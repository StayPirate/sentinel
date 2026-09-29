"""Single-session service integration tests for `assign_ticket()`
(backend/app/services/ticket_service.py).

Owning specifications:

- docs/features/tickets/ticket-service.md (Transaction ownership; Caller
  category and Ticket accessibility; Operability guard; Concurrency
  control; `assign_ticket`; Architectural Test Requirement 2, 3, 4
  (`assign_ticket()` path), and 15 (single-session part)).
- docs/features/tickets/tickets.md (Reassignment; Architectural
  Invariant).
- docs/features/tickets/ticket-audit-log.md (Event Type Contract:
  `assignment`, `status_change`; Canonical Mutation and No-Event Matrix:
  Direct assignment or reassignment; Cross-Event Ordering, Locking, and
  Rollback; Testing Requirements 1-7).
- docs/features/platform/testing-strategy.md (Tier Responsibility and
  Proportionality; Service Functions; User Identifier Resolution; Ticket
  Accessibility: Locked mutations).

The independent-session tests (Ticket and target-User lock serialization,
the winner/loser old value of audit Testing Requirement 23, and the
locked-current accessibility races) live in
`tests/test_services/test_assign_ticket_atomicity.py`.

Not reachable, hence not tested: the converse self-loss case of
Architectural Test Requirement 15 (an authorized mutation that itself
removes the caller's last visibility path). The canonical predicate
(docs/features/identity/rbac.md, Scope and Confidential Ticket Visibility)
depends only on the Ticket's confidentiality, the caller's scope, explicit
grants, and included-package maintainership; `assign_ticket()` changes only
`assignee_id` and the status, so it cannot remove any visibility path.

Expected values are transcribed from the specifications, never computed
with the module under test.
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable
from datetime import UTC, date, datetime, timedelta, timezone
from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import (
    PackageStatus,
    Role,
    Scope,
    TicketAuditEventType,
    TicketStatus,
)
from app.core.exceptions import (
    TicketNotFoundError,
    TicketNotMutableError,
    UserNotFoundError,
)
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
from app.services.ticket_service import (
    AssigneeInactiveError,
    AssigneeNotVAError,
    assign_ticket,
)
from app.services.ticket_visibility import TicketCaller
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
)

pytest_plugins = ["tests.support.ticket_mutation_fixtures"]
"""Provides the shared `va_user` and `tree` fixtures."""

PROMOTION = status_event(TicketStatus.NEW.value, TicketStatus.ANALYSIS.value)
"""The explicit system `New -> Analysis` event of step 9."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _assignment(actor: User, old: User | None, new: User) -> EventRow:
    """The acting-user `assignment` event (ticket-audit-log.md, Event Type
    Contract): previous and new assignee usernames, `comment` and `detail`
    `NULL`."""
    return EventRow(
        "assignment",
        actor.id,
        old.username if old is not None else None,
        new.username,
        None,
        None,
    )


async def _assign(
    db: AsyncSession,
    ticket_id: uuid.UUID,
    target: str,
    actor: User,
    *,
    scope: Scope = Scope.ALL,
    evaluation_date: date | None = EVAL,
) -> Ticket:
    """Call the service as an API handler would (fixed `EVAL` by default;
    `None` omits the date)."""
    return await assign_ticket(
        db,
        ticket_id=ticket_id,
        assignee=target,
        acting_user_id=actor.id,
        caller=TicketCaller.authenticated(actor.id, scope),
        evaluation_date=evaluation_date,
    )


async def _state(
    db: AsyncSession, ticket_id: uuid.UUID
) -> tuple[str, uuid.UUID | None] | None:
    """The persisted `(status, assignee_id)` of a Ticket, `None` if absent."""
    row = (
        await db.execute(
            select(Ticket.status, Ticket.assignee_id).where(Ticket.id == ticket_id)
        )
    ).one_or_none()
    return (row.status, row.assignee_id) if row is not None else None


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


TARGET_KINDS = ["absent", "inactive", "non-va"]
"""One target per rejected result of step 5 (the inactive-and-non-VA
precedence is proven once, by `test_ineligible_target_is_rejected_inactive_first`)."""


async def _target(kind: str, va_user: VAUser) -> str:
    """The raw UUID identifier of a target of the given kind: an active VA
    (`eligible`), no User (`absent`), or an inactive and/or non-VA User."""
    if kind == "absent":
        return str(uuid.uuid7())
    user = await va_user(
        active=not kind.startswith("inactive"),
        roles=(
            (Role.RESTRICTED_ANALYST,)
            if kind.endswith("non-va")
            else (Role.VULNERABILITY_ANALYST,)
        ),
    )
    return str(user.id)


async def _assert_rejected(
    db: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
    error_type: type[Exception],
    *,
    ticket_id: uuid.UUID,
    target: str,
    actor: User,
    scope: Scope = Scope.ALL,
) -> None:
    """Call the service and assert the zero-side-effect contract of a
    rejected call: the expected error, no write, no reconciliation, no
    registered convergence effect, the Ticket unchanged, and no event."""
    reconcile = _Spy(monkeypatch, "reconcile_ticket_status")
    before = await _state(db, ticket_id)

    with StatementRecorder(db) as recorder, pytest.raises(error_type):
        await _assign(db, ticket_id, target, actor, scope=scope)

    assert recorder.writes() == []
    assert reconcile.calls == []
    assert pending_ticket_convergence_effects(db) == ()
    assert await _state(db, ticket_id) == before
    assert await ticket_events_by_id(db, ticket_id) == []


# ---------------------------------------------------------------------------
# ATR 2 and 4: explicit New -> Analysis promotion
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestExplicitPromotion:
    async def test_new_ticket_is_promoted_by_the_assignment_not_by_reconciliation(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Step 9 creates the system `New -> Analysis` event before the one
        reconciliation, which finds the Ticket already in `Analysis` and
        (no gate being met) adds nothing. The acting user is an eligible
        VA on an unassigned Ticket: `auto_assign_actor()` is never used."""
        actor = await va_user()
        target = await va_user()
        ticket = await cveless(ticket_factory, status=TicketStatus.NEW, severity=None)
        assign = _Spy(monkeypatch, "auto_assign_actor")
        observed: list[tuple[str, list[EventRow]]] = []
        original = ticket_mutations.reconcile_ticket_status

        async def observing_reconcile(
            locked: Ticket, db: AsyncSession, **kwargs: Any
        ) -> None:
            observed.append((locked.status, await ticket_events(db, locked)))
            await original(locked, db, **kwargs)

        monkeypatch.setattr(
            ticket_service, "reconcile_ticket_status", observing_reconcile
        )

        result = await _assign(db_session, ticket.id, str(target.id), actor)

        expected = [_assignment(actor, None, target), PROMOTION]
        assert observed == [(TicketStatus.ANALYSIS, expected)]
        assert assign.calls == []
        assert result.id == ticket.id
        assert (result.status, result.assignee_id) == (
            TicketStatus.ANALYSIS,
            target.id,
        )
        assert await _state(db_session, ticket.id) == (TicketStatus.ANALYSIS, target.id)
        assert await ticket_events(db_session, ticket) == expected
        assert pending_ticket_convergence_effects(db_session) == ()

    async def test_reconciliation_promotes_further_after_the_explicit_step(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        tree: TreeBuilder,
    ) -> None:
        actor = await va_user()
        target = await va_user()
        ticket = await cveless(ticket_factory, status=TicketStatus.NEW)
        await tree_for(TicketStatus.ANALYZED, ticket, tree)

        await _assign(db_session, ticket.id, str(target.id), actor)

        assert await _state(db_session, ticket.id) == (TicketStatus.ANALYZED, target.id)
        assert await ticket_events(db_session, ticket) == [
            _assignment(actor, None, target),
            PROMOTION,
            status_event(TicketStatus.ANALYSIS.value, TicketStatus.ANALYZED.value),
        ]


# ---------------------------------------------------------------------------
# Reassignment
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestReassignment:
    @pytest.mark.parametrize(
        ("current", "gates", "expected"),
        [
            pytest.param(
                TicketStatus.ANALYSIS,
                TicketStatus.ANALYSIS,
                TicketStatus.ANALYSIS,
                id="analysis-kept",
            ),
            pytest.param(
                TicketStatus.ANALYZED,
                TicketStatus.ANALYZED,
                TicketStatus.ANALYZED,
                id="analyzed-kept",
            ),
            pytest.param(
                TicketStatus.RESOLVED,
                TicketStatus.RESOLVED,
                TicketStatus.RESOLVED,
                id="resolved-kept",
            ),
            pytest.param(
                TicketStatus.ANALYSIS,
                TicketStatus.ANALYZED,
                TicketStatus.ANALYZED,
                id="analysis-gates-met",
            ),
        ],
    )
    async def test_reassignment_records_the_previous_username_and_keeps_status(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        tree: TreeBuilder,
        current: TicketStatus,
        gates: TicketStatus,
        expected: TicketStatus,
    ) -> None:
        actor = await va_user()
        previous = await va_user()
        target = await va_user()
        ticket = await cveless(ticket_factory, status=current, assignee_id=previous.id)
        await tree_for(gates, ticket, tree)

        await _assign(db_session, ticket.id, str(target.id), actor)

        final = (
            [status_event(current.value, expected.value)]
            if expected is not current
            else []
        )
        assert await _state(db_session, ticket.id) == (expected, target.id)
        assert await ticket_events(db_session, ticket) == [
            _assignment(actor, previous, target),
            *final,
        ]


# ---------------------------------------------------------------------------
# ATR 3: idempotency
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestIdempotency:
    async def test_assigning_the_current_assignee_again_has_no_effect(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        tree: TreeBuilder,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        actor = await va_user()
        target = await va_user()
        ticket = await cveless(ticket_factory, status=TicketStatus.NEW)
        await _assign(db_session, ticket.id, str(target.id), actor)
        first = [_assignment(actor, None, target), PROMOTION]
        assert await ticket_events(db_session, ticket) == first
        # Gates met after the first call: a reconciliation on the second
        # call would move the Ticket to `Analyzed`.
        await tree_for(TicketStatus.ANALYZED, ticket, tree)
        reconcile = _Spy(monkeypatch, "reconcile_ticket_status")

        with StatementRecorder(db_session) as recorder:
            result = await _assign(db_session, ticket.id, target.username, actor)

        assert result.id == ticket.id
        assert reconcile.calls == []
        assert recorder.writes() == []
        assert await _state(db_session, ticket.id) == (TicketStatus.ANALYSIS, target.id)
        assert await ticket_events(db_session, ticket) == first
        assert pending_ticket_convergence_effects(db_session) == ()


# ---------------------------------------------------------------------------
# Target identifier forms (testing-strategy.md, User Identifier Resolution)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestTargetIdentifier:
    @pytest.mark.parametrize("form", ["uuid", "username"])
    async def test_uuid_and_username_select_the_same_target(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        form: str,
    ) -> None:
        actor = await va_user()
        target = await va_user()
        ticket = await cveless(ticket_factory, status=TicketStatus.NEW, severity=None)
        identifier = str(target.id) if form == "uuid" else target.username

        await _assign(db_session, ticket.id, identifier, actor)

        assert await _state(db_session, ticket.id) == (TicketStatus.ANALYSIS, target.id)
        assert await ticket_events(db_session, ticket) == [
            _assignment(actor, None, target),
            PROMOTION,
        ]

    @pytest.mark.parametrize("form", ["uuid", "username"])
    async def test_nonexistent_target_raises_user_not_found(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
        form: str,
    ) -> None:
        actor = await va_user()
        ticket = await cveless(ticket_factory, status=TicketStatus.NEW, severity=None)
        identifier = (
            str(uuid.uuid7()) if form == "uuid" else f"nobody.va.{uuid.uuid4().hex[:8]}"
        )

        await _assert_rejected(
            db_session,
            monkeypatch,
            UserNotFoundError,
            ticket_id=ticket.id,
            target=identifier,
            actor=actor,
        )


# ---------------------------------------------------------------------------
# Guard precedence with zero side effects
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestGuardPrecedence:
    @pytest.mark.parametrize("kind", ["eligible", *TARGET_KINDS])
    async def test_missing_ticket_is_not_found_whatever_the_target(
        self,
        db_session: AsyncSession,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
        kind: str,
    ) -> None:
        actor = await va_user()
        target = await _target(kind, va_user)

        await _assert_rejected(
            db_session,
            monkeypatch,
            TicketNotFoundError,
            ticket_id=uuid.uuid7(),
            target=target,
            actor=actor,
        )

    @pytest.mark.parametrize(
        ("status", "kind", "preassigned"),
        [
            pytest.param(TicketStatus.NEW, "eligible", False, id="eligible"),
            *[
                pytest.param(TicketStatus.NEW, kind, False, id=kind)
                for kind in TARGET_KINDS
            ],
            pytest.param(TicketStatus.IGNORED, "absent", False, id="also-ignored"),
            pytest.param(TicketStatus.ANALYSIS, "eligible", True, id="also-unchanged"),
        ],
    )
    async def test_inaccessible_ticket_is_not_found_before_any_other_decision(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
        status: TicketStatus,
        kind: str,
        preassigned: bool,
    ) -> None:
        actor = await va_user(roles=(Role.RESTRICTED_ANALYST,))
        target = await _target(kind, va_user)
        ticket = await cveless(
            ticket_factory,
            status=status,
            severity=None,
            is_confidential=True,
            assignee_id=uuid.UUID(target) if preassigned else None,
        )

        await _assert_rejected(
            db_session,
            monkeypatch,
            TicketNotFoundError,
            ticket_id=ticket.id,
            target=target,
            actor=actor,
            scope=Scope.NON_CONFIDENTIAL,
        )

    @pytest.mark.parametrize("kind", TARGET_KINDS)
    @pytest.mark.parametrize("status", [TicketStatus.IGNORED, TicketStatus.DUPLICATED])
    async def test_manual_zone_is_not_mutable_before_any_target_result(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
        status: TicketStatus,
        kind: str,
    ) -> None:
        actor = await va_user()
        ticket = await cveless(ticket_factory, status=status, severity=None)

        await _assert_rejected(
            db_session,
            monkeypatch,
            TicketNotMutableError,
            ticket_id=ticket.id,
            target=await _target(kind, va_user),
            actor=actor,
        )

    @pytest.mark.parametrize(
        ("active", "roles", "error_type"),
        [
            pytest.param(
                False,
                (Role.VULNERABILITY_ANALYST,),
                AssigneeInactiveError,
                id="inactive-va",
            ),
            pytest.param(
                False,
                (Role.RESTRICTED_ANALYST,),
                AssigneeInactiveError,
                id="inactive-precedes-non-va",
            ),
            pytest.param(False, (), AssigneeInactiveError, id="inactive-no-roles"),
            pytest.param(
                True, (Role.RESTRICTED_ANALYST,), AssigneeNotVAError, id="non-va"
            ),
            pytest.param(True, (), AssigneeNotVAError, id="no-roles"),
        ],
    )
    async def test_ineligible_target_is_rejected_inactive_first(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
        active: bool,
        roles: tuple[Role, ...],
        error_type: type[Exception],
    ) -> None:
        actor = await va_user()
        target = await va_user(active=active, roles=roles)
        ticket = await cveless(ticket_factory, status=TicketStatus.NEW, severity=None)

        await _assert_rejected(
            db_session,
            monkeypatch,
            error_type,
            ticket_id=ticket.id,
            target=str(target.id),
            actor=actor,
        )

    async def test_caller_mismatch_raises_before_any_statement(
        self, db_session: AsyncSession, ticket_factory: TicketFactory, va_user: VAUser
    ) -> None:
        actor = await va_user()
        other = await va_user()
        ticket = await cveless(ticket_factory, status=TicketStatus.NEW, severity=None)

        with (
            StatementRecorder(db_session) as recorder,
            pytest.raises(ValueError, match="acting user"),
        ):
            await assign_ticket(
                db_session,
                ticket_id=ticket.id,
                assignee=str(actor.id),
                acting_user_id=actor.id,
                caller=TicketCaller.authenticated(other.id, Scope.ALL),
                evaluation_date=EVAL,
            )

        assert recorder.statements == []
        assert await _state(db_session, ticket.id) == (TicketStatus.NEW, None)
        assert await ticket_events(db_session, ticket) == []


# ---------------------------------------------------------------------------
# Locked-current accessibility (single session)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestAccessibility:
    async def test_explicit_grant_holder_assigns_a_confidential_ticket(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        ticket_access_grant_factory: Callable[..., Awaitable[TicketAccessGrant]],
        va_user: VAUser,
    ) -> None:
        actor = await va_user(roles=(Role.RESTRICTED_ANALYST,))
        target = await va_user()
        ticket = await cveless(
            ticket_factory, status=TicketStatus.NEW, severity=None, is_confidential=True
        )
        await ticket_access_grant_factory(ticket_id=ticket.id, user_id=actor.id)

        await _assign(
            db_session, ticket.id, str(target.id), actor, scope=Scope.NON_CONFIDENTIAL
        )

        assert await _state(db_session, ticket.id) == (TicketStatus.ANALYSIS, target.id)
        assert await ticket_events(db_session, ticket) == [
            _assignment(actor, None, target),
            PROMOTION,
        ]


# ---------------------------------------------------------------------------
# Lock order and unlocked observations
# ---------------------------------------------------------------------------


def _bound(params: Any) -> list[Any]:
    """The bound values of one recorded statement."""
    return list(params.values() if isinstance(params, dict) else params)


@pytest.mark.integration
class TestLockOrder:
    async def test_target_share_then_ticket_update_then_visibility(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        ticket_access_grant_factory: Callable[..., Awaitable[TicketAccessGrant]],
        va_user: VAUser,
    ) -> None:
        """A reassignment through an explicit grant: the target User `FOR
        SHARE` and its role load precede the Ticket `FOR UPDATE`, which
        precedes the separate visibility statement. Under the Ticket lock,
        the only User reads are the unlocked previous-assignee username and
        the reconciliation's sanitation observation of the new assignee."""
        actor = await va_user(roles=(Role.RESTRICTED_ANALYST,))
        previous = await va_user()
        target = await va_user()
        ticket = await cveless(
            ticket_factory,
            severity=None,
            is_confidential=True,
            assignee_id=previous.id,
        )
        await ticket_access_grant_factory(ticket_id=ticket.id, user_id=actor.id)

        with StatementRecorder(db_session) as recorder:
            await _assign(
                db_session,
                ticket.id,
                str(target.id),
                actor,
                scope=Scope.NON_CONFIDENTIAL,
            )

        statements = recorder.statements

        def first(predicate: Callable[[str], bool]) -> int:
            return next(i for i, s in enumerate(statements) if predicate(s))

        user_share = first(lambda s: 'FROM "user"' in s and "FOR SHARE" in s)
        roles = first(lambda s: "FROM user_role" in s)
        ticket_lock = first(lambda s: "FROM ticket" in s and "FOR UPDATE" in s)
        visibility = first(lambda s: "ticket_access_grant" in s)
        assert user_share < roles < ticket_lock < visibility
        assert target.id in _bound(recorder.parameters[user_share])
        assert "ticket_access_grant" not in statements[ticket_lock]
        assert len(recorder.row_locks()) == 2

        user_reads = [
            i
            for i in range(ticket_lock + 1, len(statements))
            if 'FROM "user"' in statements[i]
        ]
        assert [i for i in user_reads if "FOR " in statements[i]] == []
        bound = [_bound(recorder.parameters[i]) for i in user_reads]
        assert len(bound) == 2
        assert bound[0] == [previous.id]
        assert target.id in bound[1]
        assert not any('"user"' in w for w in recorder.writes())
        assert recorder.selects_from("ticket_audit_event") == []
        assert await ticket_events(db_session, ticket) == [
            _assignment(actor, previous, target)
        ]


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
        target = await va_user()
        ticket = await cveless(ticket_factory, status=TicketStatus.NEW, severity=None)
        supplied = date(2026, 1, 2)

        await _assign(
            db_session, ticket.id, str(target.id), actor, evaluation_date=supplied
        )

        assert [(args[0].id, kwargs) for args, kwargs in reconcile.calls] == [
            (ticket.id, {"evaluation_date": supplied})
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
        previous = await va_user()
        target = await va_user()
        ticket = await cveless(ticket_factory, assignee_id=previous.id)
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

        await _assign(
            db_session, ticket.id, str(target.id), actor, evaluation_date=None
        )

        assert calls == 1
        assert [kwargs for _, kwargs in reconcile.calls] == [{"evaluation_date": day}]
        assert await _state(db_session, ticket.id) == (TicketStatus.ANALYZED, target.id)


# ---------------------------------------------------------------------------
# Whole-operation rollback (audit Testing Requirement 7) and no commit
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestRollback:
    @pytest.mark.parametrize(
        "failure", ["assignment-audit", "status-audit", "reconciliation"]
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
        target = await va_user()
        ticket = await cveless(ticket_factory, status=TicketStatus.NEW)
        await tree_for(TicketStatus.ANALYZED, ticket, tree)
        failing_type = {
            "assignment-audit": TicketAuditEventType.ASSIGNMENT,
            "status-audit": TicketAuditEventType.STATUS_CHANGE,
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
                await _assign(db_session, ticket.id, str(target.id), actor)
        monkeypatch.undo()

        await db_session.refresh(ticket)
        assert await _state(db_session, ticket.id) == (TicketStatus.NEW, None)
        assert await ticket_events(db_session, ticket) == []
        assert pending_ticket_convergence_effects(db_session) == ()

    async def test_never_commits(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        actor = await va_user()
        target = await va_user()
        ticket = await cveless(ticket_factory, status=TicketStatus.NEW, severity=None)

        async def forbidden() -> None:
            raise AssertionError("assign_ticket() must not commit")

        monkeypatch.setattr(db_session, "commit", forbidden)
        monkeypatch.setattr(db_session, "rollback", forbidden)

        await _assign(db_session, ticket.id, str(target.id), actor)
