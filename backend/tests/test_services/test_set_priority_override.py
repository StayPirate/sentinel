"""Single-session service integration tests for `set_priority_override()`
(backend/app/services/ticket_service.py).

Owning specifications:

- docs/features/tickets/ticket-priority.md (Persistence and Effective
  Priority; Manual Override: `set_priority_override()`; Audit; Testing
  Requirements 4 (the later clear), 5, and 6 (the override half)).
- docs/features/tickets/ticket-service.md (Transaction ownership; Caller
  category and Ticket accessibility; `set_priority_override`;
  Architectural Test Requirement 15 (single-session part) and 19).
- docs/features/tickets/ticket-mutations.md (Auto-Assignment Rule;
  `auto_assign_actor()`; Assignment Eligibility Sanitization).
- docs/features/tickets/ticket-audit-log.md (Event Type Contract:
  `priority_changed`, `assignment`, `status_change`; detail JSONB Schema
  Contract: `priority_changed`; Canonical Mutation and No-Event Matrix:
  Priority override set, change, or clear; Cross-Event Ordering; Testing
  Requirements 1-7, 18 (sanitation ordering), and 28).
- docs/features/platform/testing-strategy.md (Tier Responsibility and
  Proportionality; Service Functions; Ticket Accessibility: Locked
  mutations).

The masking of an automatic change by an override is proven at the refresh
level in `tests/test_services/test_ticket_priority_refresh.py` and through
`set_severity_manual()` in `tests/test_services/test_set_severity_manual.py`;
this module proves only the later clear of Testing Requirement 4. The
independent-session races (Testing Requirement 7, audit Testing
Requirement 23, locked-current accessibility) live in
`tests/test_services/test_set_priority_override_atomicity.py`.

Not reachable, hence not tested: the converse self-loss case of
Architectural Test Requirement 15 (an authorized mutation that itself
removes the caller's last visibility path). The canonical predicate
(docs/features/identity/rbac.md, Scope and Confidential Ticket Visibility)
depends only on the Ticket's confidentiality, the caller's scope, explicit
grants, and included-package maintainership; the override changes only
`priority_override` plus the auto-assignment consequences, so it cannot
remove any visibility path.

Expected values are transcribed from the specifications, never computed
with the module under test.
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable
from datetime import UTC, date, datetime, timedelta, timezone
from typing import Any

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import (
    PackageStatus,
    Role,
    Scope,
    Severity,
    TicketAuditEventType,
    TicketPriority,
    TicketStatus,
)
from app.core.exceptions import TicketNotFoundError, TicketNotMutableError
from app.core.identifiers import format_ticket_id
from app.models.product import Product
from app.models.ticket import Ticket
from app.models.ticket_access_grant import TicketAccessGrant
from app.models.ticket_package_product import TicketPackageProduct
from app.models.user import User
from app.services import ticket_mutations, ticket_service
from app.services.ticket_audit_log import TicketAuditLog
from app.services.ticket_convergence_registry import (
    pending_ticket_convergence_effects,
)
from app.services.ticket_mutations import set_severity_manual
from app.services.ticket_service import resolve_ticket_locator, set_priority_override
from app.services.ticket_visibility import TicketCaller
from tests.support.cvss_chain import eligibility, ticket_state
from tests.support.database import rollback_test_scope
from tests.support.ticket_mutations import (
    EVAL,
    EventRow,
    StatementRecorder,
    TicketFactory,
    TreeBuilder,
    VAUser,
    cveless,
    status_event,
    ticket_events,
    ticket_events_by_id,
    tree_for,
    unassigned_event,
)

pytest_plugins = ["tests.support.ticket_mutation_fixtures"]
"""Provides the shared `va_user` and `tree` fixtures."""

PROMOTION = status_event(TicketStatus.NEW.value, TicketStatus.ANALYSIS.value)
"""The system `New -> Analysis` event of the auto-assignment."""

AUTO: dict[Severity | None, str | None] = {
    None: None,
    Severity.CRITICAL: "P2",
    Severity.HIGH: "P3",
    Severity.MEDIUM: "P4",
}
"""ticket-priority.md, Decision Table: the `unknown` row of a CVE-less
Ticket by `severity_manual`. Fixtures keep `priority_auto` consistent."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _override_event(
    actor: User, old: str | None, new: str | None, action: str
) -> EventRow:
    """The acting-user `priority_changed` event of an override: effective
    old/new priorities, `comment` `NULL`, and the `override_action`."""
    return EventRow(
        "priority_changed", actor.id, old, new, None, {"override_action": action}
    )


def _assignment_event(actor: User) -> EventRow:
    """The acting-user auto-assignment of an unassigned Ticket."""
    return EventRow("assignment", actor.id, None, actor.username, None, None)


async def _set(
    db: AsyncSession,
    ticket_id: uuid.UUID,
    priority: TicketPriority | None,
    actor: User,
    *,
    scope: Scope = Scope.ALL,
    evaluation_date: date | None = EVAL,
) -> Ticket:
    """Call the service as an API handler would (fixed `EVAL` by default;
    `None` omits the date)."""
    return await set_priority_override(
        db,
        ticket_id=ticket_id,
        priority=priority,
        acting_user_id=actor.id,
        caller=TicketCaller.authenticated(actor.id, scope),
        evaluation_date=evaluation_date,
    )


async def _ticket(
    ticket_factory: TicketFactory,
    *,
    status: TicketStatus = TicketStatus.ANALYSIS,
    severity: Severity | None = Severity.HIGH,
    override: str | None = None,
    **overrides: Any,
) -> Ticket:
    """A CVE-less Ticket whose `priority_auto` matches its severity."""
    return await cveless(
        ticket_factory,
        status=status,
        severity=severity,
        priority_auto=AUTO[severity],
        priority_override=override,
        **overrides,
    )


class _Spy:
    """Wraps an async `ticket_service` attribute (the name imported from
    `ticket_mutations`), recording each call's arguments."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch, name: str) -> None:
        self.calls: list[tuple[tuple[Any, ...], dict[str, Any]]] = []
        original = getattr(ticket_service, name)

        async def _wrapper(*args: Any, **kwargs: Any) -> Any:
            self.calls.append((args, kwargs))
            return await original(*args, **kwargs)

        monkeypatch.setattr(ticket_service, name, _wrapper)


async def _assert_rejected(
    db: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
    error_type: type[Exception],
    *,
    ticket_id: uuid.UUID,
    priority: TicketPriority | None,
    actor: User,
    scope: Scope = Scope.ALL,
) -> None:
    """Call the service and assert the zero-side-effect contract of a
    rejected call: the expected error, no write, no assignment, no
    reconciliation, no registered convergence effect, and no event."""
    assign = _Spy(monkeypatch, "auto_assign_actor")
    reconcile = _Spy(monkeypatch, "reconcile_ticket_status")

    with StatementRecorder(db) as recorder, pytest.raises(error_type):
        await _set(db, ticket_id, priority, actor, scope=scope)

    assert recorder.writes() == []
    assert (assign.calls, reconcile.calls) == ([], [])
    assert pending_ticket_convergence_effects(db) == ()
    assert await ticket_events_by_id(db, ticket_id) == []


# ---------------------------------------------------------------------------
# TR 5: set, changed, cleared
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestEffectiveOverride:
    @pytest.mark.parametrize(
        ("severity", "old", "new", "old_effective", "new_effective", "action"),
        [
            pytest.param(Severity.HIGH, None, "P1", "P3", "P1", "set", id="set"),
            pytest.param(None, None, "P2", None, "P2", "set", id="set-auto-null"),
            pytest.param(
                Severity.HIGH, None, "P3", "P3", "P3", "set", id="set-equal-to-auto"
            ),
            pytest.param(
                Severity.HIGH, "P1", "P2", "P1", "P2", "changed", id="changed"
            ),
            pytest.param(
                Severity.HIGH, "P1", None, "P1", "P3", "cleared", id="cleared"
            ),
            pytest.param(
                Severity.HIGH,
                "P3",
                None,
                "P3",
                "P3",
                "cleared",
                id="cleared-equal-to-auto",
            ),
            pytest.param(
                None, "P2", None, "P2", None, "cleared", id="cleared-auto-null"
            ),
        ],
    )
    async def test_writes_override_and_one_effective_priority_event(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
        severity: Severity | None,
        old: str | None,
        new: str | None,
        old_effective: str | None,
        new_effective: str | None,
        action: str,
    ) -> None:
        actor = await va_user()
        ticket = await _ticket(
            ticket_factory, severity=severity, override=old, assignee_id=actor.id
        )
        refresh = _Spy(monkeypatch, "refresh_priority_auto")

        result = await _set(
            db_session,
            ticket.id,
            TicketPriority(new) if new is not None else None,
            actor,
        )

        assert result.id == ticket.id
        assert result.priority_override == new
        assert refresh.calls == []
        assert await ticket_state(db_session, ticket.id) == (
            TicketStatus.ANALYSIS,
            actor.id,
            AUTO[severity],
            new,
            severity.value if severity is not None else None,
        )
        assert await ticket_events(db_session, ticket) == [
            _override_event(actor, old_effective, new_effective, action)
        ]

    async def test_never_commits(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        actor = await va_user()
        ticket = await _ticket(ticket_factory, status=TicketStatus.NEW)

        async def forbidden() -> None:
            raise AssertionError("set_priority_override() must not commit")

        monkeypatch.setattr(db_session, "commit", forbidden)
        monkeypatch.setattr(db_session, "rollback", forbidden)

        await _set(db_session, ticket.id, TicketPriority.P1, actor)


# ---------------------------------------------------------------------------
# TR 5: same-value no-op
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestNoOp:
    @pytest.mark.parametrize(
        ("current", "requested"),
        [
            pytest.param("P2", TicketPriority.P2, id="same-value"),
            pytest.param(None, None, id="clear-without-override"),
        ],
    )
    async def test_same_value_has_no_effect(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        tree: TreeBuilder,
        monkeypatch: pytest.MonkeyPatch,
        current: str | None,
        requested: TicketPriority | None,
    ) -> None:
        actor = await va_user()
        # An unassigned `New` Ticket with a gate-satisfying tree and a VA
        # actor proves that no assignment, promotion, or reconciliation runs.
        ticket = await _ticket(
            ticket_factory, status=TicketStatus.NEW, override=current
        )
        await tree_for(TicketStatus.RESOLVED, ticket, tree)
        assign = _Spy(monkeypatch, "auto_assign_actor")
        reconcile = _Spy(monkeypatch, "reconcile_ticket_status")

        with StatementRecorder(db_session) as recorder:
            result = await _set(db_session, ticket.id, requested, actor)

        assert result.id == ticket.id
        assert (assign.calls, reconcile.calls) == ([], [])
        assert recorder.writes() == []
        assert await ticket_state(db_session, ticket.id) == (
            TicketStatus.NEW,
            None,
            "P3",
            current,
            "High",
        )
        assert await ticket_events(db_session, ticket) == []
        assert pending_ticket_convergence_effects(db_session) == ()


# ---------------------------------------------------------------------------
# TR 5: auto-assignment, promotion, and one reconciliation
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestAutoAssignment:
    @pytest.mark.parametrize(
        "final", [TicketStatus.ANALYSIS, TicketStatus.ANALYZED], ids=str
    )
    async def test_va_actor_assigns_promotes_then_reconciles_once(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        tree: TreeBuilder,
        monkeypatch: pytest.MonkeyPatch,
        final: TicketStatus,
    ) -> None:
        actor = await va_user()
        ticket = await _ticket(ticket_factory, status=TicketStatus.NEW)
        await tree_for(final, ticket, tree)
        reconcile = _Spy(monkeypatch, "reconcile_ticket_status")

        await _set(db_session, ticket.id, TicketPriority.P1, actor)

        gate = (
            [status_event(TicketStatus.ANALYSIS.value, final.value)]
            if final is not TicketStatus.ANALYSIS
            else []
        )
        assert [(args[0].id, kwargs) for args, kwargs in reconcile.calls] == [
            (ticket.id, {"evaluation_date": EVAL})
        ]
        assert await ticket_state(db_session, ticket.id) == (
            final,
            actor.id,
            "P3",
            "P1",
            "High",
        )
        assert await ticket_events(db_session, ticket) == [
            _assignment_event(actor),
            PROMOTION,
            _override_event(actor, "P3", "P1", "set"),
            *gate,
        ]

    @pytest.mark.parametrize(
        ("active", "roles"),
        [
            pytest.param(True, (Role.RESTRICTED_ANALYST,), id="restricted-analyst"),
            pytest.param(False, (Role.VULNERABILITY_ANALYST,), id="inactive-va"),
        ],
    )
    async def test_ineligible_actor_neither_assigns_nor_leaves_new(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        tree: TreeBuilder,
        monkeypatch: pytest.MonkeyPatch,
        active: bool,
        roles: tuple[Role, ...],
    ) -> None:
        actor = await va_user(active=active, roles=roles)
        ticket = await _ticket(ticket_factory, status=TicketStatus.NEW)
        await tree_for(TicketStatus.RESOLVED, ticket, tree)
        reconcile = _Spy(monkeypatch, "reconcile_ticket_status")

        await _set(db_session, ticket.id, TicketPriority.P1, actor)

        # The one reconciliation returns early for `New`, although the
        # gates are satisfied.
        assert len(reconcile.calls) == 1
        assert await ticket_state(db_session, ticket.id) == (
            TicketStatus.NEW,
            None,
            "P3",
            "P1",
            "High",
        )
        assert await ticket_events(db_session, ticket) == [
            _override_event(actor, "P3", "P1", "set")
        ]


# ---------------------------------------------------------------------------
# TR 6 (override half) and audit TR 18 (sanitation ordering)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestGateIndependence:
    async def test_override_changes_no_status_assignment_eligibility_or_access(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        ticket_access_grant_factory: Callable[..., Awaitable[TicketAccessGrant]],
        va_user: VAUser,
        tree: TreeBuilder,
    ) -> None:
        """An assigned `Analyzed` Ticket reached through an explicit grant:
        the override writes only `priority_override` and its own event."""
        owner = await va_user()
        actor = await va_user(roles=(Role.RESTRICTED_ANALYST,))
        ticket = await _ticket(
            ticket_factory,
            status=TicketStatus.ANALYZED,
            assignee_id=owner.id,
            is_confidential=True,
        )
        await tree_for(TicketStatus.ANALYZED, ticket, tree)
        await ticket_access_grant_factory(ticket_id=ticket.id, user_id=actor.id)
        caller = TicketCaller.authenticated(actor.id, Scope.NON_CONFIDENTIAL)
        before = await eligibility(db_session, ticket.id)

        with StatementRecorder(db_session) as recorder:
            await _set(
                db_session,
                ticket.id,
                TicketPriority.P1,
                actor,
                scope=Scope.NON_CONFIDENTIAL,
            )

        writes = recorder.writes()
        assert [w.split(" SET ")[0].split(" (")[0] for w in writes] == [
            "UPDATE ticket",
            "INSERT INTO ticket_audit_event",
        ]
        assert "status" not in writes[0].split(" WHERE ")[0]
        assert "assignee_id" not in writes[0].split(" WHERE ")[0]
        assert recorder.selects_from("ticket_audit_event") == []
        assert await ticket_state(db_session, ticket.id) == (
            TicketStatus.ANALYZED,
            owner.id,
            "P3",
            "P1",
            "High",
        )
        assert await eligibility(db_session, ticket.id) == before
        resolved = await resolve_ticket_locator(
            db_session, format_ticket_id(ticket.sequence_id), caller
        )
        assert resolved.id == ticket.id

    @pytest.mark.parametrize(
        "final", [TicketStatus.ANALYSIS, TicketStatus.ANALYZED], ids=str
    )
    async def test_sanitation_follows_the_override_and_precedes_final_status(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        tree: TreeBuilder,
        final: TicketStatus,
    ) -> None:
        actor = await va_user()
        inactive = await va_user(active=False)
        ticket = await _ticket(ticket_factory, assignee_id=inactive.id)
        await tree_for(final, ticket, tree)

        await _set(db_session, ticket.id, TicketPriority.P1, actor)

        gate = (
            [status_event(TicketStatus.ANALYSIS.value, final.value)]
            if final is not TicketStatus.ANALYSIS
            else []
        )
        assert await ticket_events(db_session, ticket) == [
            _override_event(actor, "P3", "P1", "set"),
            unassigned_event(inactive.username, "inactive assignee"),
            *gate,
        ]
        assert await ticket_state(db_session, ticket.id) == (
            final,
            None,
            "P3",
            "P1",
            "High",
        )


# ---------------------------------------------------------------------------
# TR 4: a later clear exposes the masked automatic value
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestMaskedAutomaticChange:
    async def test_clear_after_a_masked_refresh_exposes_the_automatic_value(
        self, db_session: AsyncSession, ticket_factory: TicketFactory, va_user: VAUser
    ) -> None:
        actor = await va_user()
        ticket = await _ticket(
            ticket_factory, severity=None, override="P1", assignee_id=actor.id
        )
        await set_severity_manual(
            db_session,
            ticket_id=ticket.id,
            severity=Severity.HIGH,
            acting_user_id=actor.id,
            caller=TicketCaller.authenticated(actor.id, Scope.ALL),
            evaluation_date=EVAL,
        )

        await _set(db_session, ticket.id, None, actor)

        assert await ticket_state(db_session, ticket.id) == (
            TicketStatus.ANALYSIS,
            actor.id,
            "P3",
            None,
            "High",
        )
        assert await ticket_events(db_session, ticket) == [
            EventRow("severity_changed", actor.id, None, "High", None, None),
            _override_event(actor, "P1", "P3", "cleared"),
        ]


# ---------------------------------------------------------------------------
# Guards with zero side effects
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestGuards:
    @pytest.mark.parametrize(
        "requested",
        [
            pytest.param(TicketPriority.P1, id="effective"),
            pytest.param(None, id="also-no-op-request"),
        ],
    )
    async def test_missing_ticket_raises_not_found(
        self,
        db_session: AsyncSession,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
        requested: TicketPriority | None,
    ) -> None:
        actor = await va_user()

        await _assert_rejected(
            db_session,
            monkeypatch,
            TicketNotFoundError,
            ticket_id=uuid.uuid7(),
            priority=requested,
            actor=actor,
        )

    @pytest.mark.parametrize(
        ("status", "requested"),
        [
            pytest.param(TicketStatus.NEW, TicketPriority.P1, id="effective"),
            pytest.param(TicketStatus.IGNORED, TicketPriority.P1, id="also-ignored"),
            pytest.param(TicketStatus.NEW, None, id="also-no-op-request"),
        ],
    )
    @pytest.mark.parametrize(
        "roles",
        [
            pytest.param((Role.RESTRICTED_ANALYST,), id="restricted-analyst"),
            # A VA origin committed after the request resolved the caller's
            # `non_confidential` scope: any auto-assignment before the denial
            # would be observable.
            pytest.param((Role.VULNERABILITY_ANALYST,), id="va-after-resolution"),
        ],
    )
    async def test_inaccessible_ticket_is_not_found_before_any_other_decision(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        ticket_access_grant_factory: Callable[..., Awaitable[TicketAccessGrant]],
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
        status: TicketStatus,
        requested: TicketPriority | None,
        roles: tuple[Role, ...],
    ) -> None:
        actor = await va_user(roles=roles)
        ticket = await _ticket(ticket_factory, status=status, is_confidential=True)
        # A non-qualifying path: another user's grant.
        await ticket_access_grant_factory(ticket_id=ticket.id)
        before = await ticket_state(db_session, ticket.id)

        await _assert_rejected(
            db_session,
            monkeypatch,
            TicketNotFoundError,
            ticket_id=ticket.id,
            priority=requested,
            actor=actor,
            scope=Scope.NON_CONFIDENTIAL,
        )

        assert await ticket_state(db_session, ticket.id) == before

    @pytest.mark.parametrize("status", [TicketStatus.IGNORED, TicketStatus.DUPLICATED])
    @pytest.mark.parametrize(
        "requested",
        [
            pytest.param(TicketPriority.P1, id="change"),
            pytest.param(TicketPriority.P2, id="same"),
        ],
    )
    async def test_manual_zone_raises_not_mutable(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
        status: TicketStatus,
        requested: TicketPriority,
    ) -> None:
        actor = await va_user()
        ticket = await _ticket(ticket_factory, status=status, override="P2")
        before = await ticket_state(db_session, ticket.id)

        await _assert_rejected(
            db_session,
            monkeypatch,
            TicketNotMutableError,
            ticket_id=ticket.id,
            priority=requested,
            actor=actor,
        )

        assert await ticket_state(db_session, ticket.id) == before

    async def test_caller_mismatch_raises_before_any_statement(
        self, db_session: AsyncSession, ticket_factory: TicketFactory, va_user: VAUser
    ) -> None:
        actor = await va_user()
        other = await va_user()
        ticket = await _ticket(ticket_factory, status=TicketStatus.NEW)

        with (
            StatementRecorder(db_session) as recorder,
            pytest.raises(ValueError, match="acting user"),
        ):
            await set_priority_override(
                db_session,
                ticket_id=ticket.id,
                priority=TicketPriority.P1,
                acting_user_id=actor.id,
                caller=TicketCaller.authenticated(other.id, Scope.ALL),
                evaluation_date=EVAL,
            )

        assert recorder.statements == []
        assert await ticket_state(db_session, ticket.id) == (
            TicketStatus.NEW,
            None,
            "P3",
            None,
            "High",
        )
        assert await ticket_events(db_session, ticket) == []


# ---------------------------------------------------------------------------
# Lock order and locked-current revalidation statement
# ---------------------------------------------------------------------------


def _bound(params: Any) -> list[Any]:
    """The bound values of one recorded statement."""
    return list(params.values() if isinstance(params, dict) else params)


@pytest.mark.integration
class TestLockOrder:
    async def test_acting_user_share_then_ticket_update_then_visibility(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        ticket_access_grant_factory: Callable[..., Awaitable[TicketAccessGrant]],
        va_user: VAUser,
    ) -> None:
        actor = await va_user(roles=(Role.RESTRICTED_ANALYST,))
        ticket = await _ticket(ticket_factory, is_confidential=True)
        await ticket_access_grant_factory(ticket_id=ticket.id, user_id=actor.id)

        with StatementRecorder(db_session) as recorder:
            await _set(
                db_session,
                ticket.id,
                TicketPriority.P1,
                actor,
                scope=Scope.NON_CONFIDENTIAL,
            )

        statements = recorder.statements

        def first(predicate: Callable[[str], bool]) -> int:
            return next(i for i, s in enumerate(statements) if predicate(s))

        user_share = first(lambda s: 'FROM "user"' in s and "FOR SHARE" in s)
        ticket_lock = first(lambda s: "FROM ticket" in s and "FOR UPDATE" in s)
        visibility = first(lambda s: "ticket_access_grant" in s)
        assert user_share < ticket_lock < visibility
        assert actor.id in _bound(recorder.parameters[user_share])
        assert "ticket_access_grant" not in statements[ticket_lock]
        assert len(recorder.row_locks()) == 2
        assert recorder.selects_from("ticket_audit_event") == []


# ---------------------------------------------------------------------------
# One evaluation date
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestEvaluationDate:
    async def test_supplied_date_reaches_reconciliation_without_the_clock(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        def clock() -> datetime:
            raise AssertionError("the supplied date must be reused")

        monkeypatch.setattr(ticket_service, "_utc_now", clock)
        monkeypatch.setattr(ticket_mutations, "_utc_now", clock)
        reconcile = _Spy(monkeypatch, "reconcile_ticket_status")
        actor = await va_user()
        ticket = await _ticket(ticket_factory, assignee_id=actor.id)
        supplied = date(2026, 1, 2)

        await _set(
            db_session, ticket.id, TicketPriority.P1, actor, evaluation_date=supplied
        )

        assert [kwargs for _, kwargs in reconcile.calls] == [
            {"evaluation_date": supplied}
        ]

    async def test_omitted_date_is_captured_once_at_entry_in_utc(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        tree: TreeBuilder,
        product_factory: Callable[..., Awaitable[Product]],
        ticket_package_product_factory: Callable[..., Awaitable[TicketPackageProduct]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        day = date(2026, 12, 31)
        instants = iter(
            [
                # 22:30 UTC on `day`, expressed with a `+02:00` offset.
                datetime(2027, 1, 1, 0, 30, tzinfo=timezone(timedelta(hours=2))),
                datetime(2027, 1, 1, 0, 0, 0, tzinfo=UTC),
            ]
        )
        calls = 0

        def clock() -> datetime:
            nonlocal calls
            calls += 1
            return next(instants)

        def forbidden_clock() -> datetime:
            raise AssertionError("the date is captured once by the service")

        actor = await va_user()
        ticket = await _ticket(ticket_factory, assignee_id=actor.id)
        # General Support ends on `day`: the AFFECTED track is actionable on
        # `day` (Analyzed) and all-EOL the next day (Resolved).
        track = await tree(ticket, status=PackageStatus.AFFECTED, products=())
        product = await product_factory(general_support_end_date=day)
        await ticket_package_product_factory(
            ticket_package_track_id=track.id, product_id=product.id
        )
        monkeypatch.setattr(ticket_service, "_utc_now", clock)
        monkeypatch.setattr(ticket_mutations, "_utc_now", forbidden_clock)
        reconcile = _Spy(monkeypatch, "reconcile_ticket_status")

        await _set(
            db_session, ticket.id, TicketPriority.P1, actor, evaluation_date=None
        )

        assert calls == 1
        assert [kwargs for _, kwargs in reconcile.calls] == [{"evaluation_date": day}]
        assert (await ticket_state(db_session, ticket.id))[0] == TicketStatus.ANALYZED


# ---------------------------------------------------------------------------
# Whole-operation rollback (TR 5; audit Testing Requirement 7)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestRollback:
    @pytest.mark.parametrize(
        "failure", ["priority-audit", "assignment-audit", "reconciliation"]
    )
    async def test_failure_rolls_back_every_effect(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        tree: TreeBuilder,
        monkeypatch: pytest.MonkeyPatch,
        failure: str,
    ) -> None:
        actor = await va_user()
        ticket = await _ticket(ticket_factory, status=TicketStatus.NEW)
        await tree_for(TicketStatus.ANALYZED, ticket, tree)
        failing_type = {
            "priority-audit": TicketAuditEventType.PRIORITY_CHANGED,
            "assignment-audit": TicketAuditEventType.ASSIGNMENT,
        }.get(failure)

        async with rollback_test_scope(db_session):
            if failing_type is not None:
                original_log = TicketAuditLog.log_event

                async def failing_log(*args: Any, **kwargs: Any) -> None:
                    if kwargs["event_type"] is failing_type:
                        raise RuntimeError("injected audit failure")
                    await original_log(*args, **kwargs)

                monkeypatch.setattr(TicketAuditLog, "log_event", failing_log)
            else:
                original_reconcile = ticket_mutations.reconcile_ticket_status

                async def failing_reconcile(*args: Any, **kwargs: Any) -> None:
                    await original_reconcile(*args, **kwargs)
                    raise RuntimeError("injected reconciliation failure")

                monkeypatch.setattr(
                    ticket_service, "reconcile_ticket_status", failing_reconcile
                )

            with pytest.raises(RuntimeError, match="injected"):
                await _set(db_session, ticket.id, TicketPriority.P1, actor)
        monkeypatch.undo()

        await db_session.refresh(ticket)
        assert await ticket_state(db_session, ticket.id) == (
            TicketStatus.NEW,
            None,
            "P3",
            None,
            "High",
        )
        assert await ticket_events(db_session, ticket) == []
        assert pending_ticket_convergence_effects(db_session) == ()
