"""Single-session service integration tests for `ignore_ticket()`
(backend/app/services/ticket_service.py).

Owning specifications:

- docs/features/tickets/ticket-service.md (Transaction ownership; Caller
  category and Ticket accessibility; Operability guard, including the
  ordering constraint for `ignore_ticket`; `ignore_ticket`; Service
  Exceptions; Architectural Test Requirement 4 (`ignore_ticket()` path,
  in `tests/test_services/test_new_to_analysis_promotion.py`) and 15
  (single-session part)).
- docs/features/tickets/tickets.md (Status Transitions, including the
  VA/non-VA note after the matrix; Auto-Assignment on Unassigned
  Tickets).
- docs/features/tickets/ticket-audit-log.md (Event Type Contract:
  `status_change`, `assignment`; Canonical Mutation and No-Event Matrix:
  Ignore, mark duplicate, reopen, or revert duplicate; Cross-Event
  Ordering, Locking, and Rollback; Testing Requirements 1-7).
- docs/features/platform/testing-strategy.md (Tier Responsibility and
  Proportionality; Audit Trail Testing, What to Assert).

The independent-session tests (lock serialization, the winner/loser old
value of audit Testing Requirement 23, and the locked-current
accessibility races of Architectural Test Requirement 15) are owned by a
separate atomicity module.

Not reachable, hence not tested: the converse self-loss case of
Architectural Test Requirement 15 (an authorized mutation that itself
removes the caller's last visibility path). The canonical predicate
(docs/features/identity/rbac.md, Scope and Confidential Ticket Visibility)
depends only on the Ticket's confidentiality, the caller's scope, explicit
grants, and included-package maintainership; `ignore_ticket()` changes
only the status and, through auto-assignment, `assignee_id`, so it cannot
remove any visibility path.

Expected values are transcribed from the specifications, never computed
with the module under test.
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable
from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import Role, Scope, TicketAuditEventType, TicketStatus
from app.core.exceptions import (
    InvalidTransitionError,
    TicketNotFoundError,
    TicketNotMutableError,
)
from app.models.ticket import Ticket
from app.models.ticket_access_grant import TicketAccessGrant
from app.models.ticket_audit_event import TicketAuditEvent
from app.models.user import User
from app.services import ticket_service
from app.services.ticket_audit_log import TicketAuditLog
from app.services.ticket_convergence_registry import (
    pending_ticket_convergence_effects,
)
from app.services.ticket_service import ignore_ticket
from app.services.ticket_visibility import TicketCaller
from tests.support.database import rollback_test_scope
from tests.support.ticket_mutations import (
    EventRow,
    StatementRecorder,
    TicketFactory,
    VAUser,
    status_event,
    ticket_events,
    ticket_events_by_id,
)

pytest_plugins = ["tests.support.ticket_mutation_fixtures"]
"""Provides the shared `va_user` fixture."""

PROMOTION = status_event(TicketStatus.NEW.value, TicketStatus.ANALYSIS.value)
"""The system `New -> Analysis` event of the auto-assignment."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _ignored(actor: User, old: TicketStatus) -> EventRow:
    """The acting-user manual-zone entry (ticket-audit-log.md, Event Type
    Contract: `status_change` of a direct manual transition, `comment` and
    `detail` `NULL`)."""
    return EventRow(
        "status_change", actor.id, old.value, TicketStatus.IGNORED.value, None, None
    )


def _assignment(actor: User) -> EventRow:
    """The acting-user auto-assignment of an unassigned Ticket."""
    return EventRow("assignment", actor.id, None, actor.username, None, None)


async def _ignore(
    db: AsyncSession, ticket_id: uuid.UUID, actor: User, *, scope: Scope = Scope.ALL
) -> Ticket:
    """Call the service as an API handler would."""
    return await ignore_ticket(
        db,
        ticket_id=ticket_id,
        acting_user_id=actor.id,
        caller=TicketCaller.authenticated(actor.id, scope),
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


async def _assert_rejected(
    db: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
    error_type: type[Exception],
    *,
    ticket_id: uuid.UUID,
    actor: User,
    scope: Scope = Scope.ALL,
) -> None:
    """Call the service and assert the zero-side-effect contract of a
    rejected call: the expected error, no write, no assignment, no
    reconciliation, no registered convergence effect, the Ticket
    unchanged, and no event."""
    assign = _Spy(monkeypatch, "auto_assign_actor")
    reconcile = _Spy(monkeypatch, "reconcile_ticket_status")
    before = await _state(db, ticket_id)

    with StatementRecorder(db) as recorder, pytest.raises(error_type):
        await _ignore(db, ticket_id, actor, scope=scope)

    assert recorder.writes() == []
    assert (assign.calls, reconcile.calls) == ([], [])
    assert pending_ticket_convergence_effects(db) == ()
    assert await _state(db, ticket_id) == before
    assert await ticket_events_by_id(db, ticket_id) == []


# ---------------------------------------------------------------------------
# Effective manual-zone entry
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestIgnore:
    async def test_va_actor_claims_an_unassigned_new_ticket_before_ignoring(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """tickets.md, Auto-Assignment on Unassigned Tickets: the audit
        trail records `assignment`, the system `New -> Analysis`, then the
        acting-user `Analysis -> Ignored`. The entry never reconciles,
        registers convergence, or reads audit history."""
        actor = await va_user()
        ticket = await ticket_factory(status=TicketStatus.NEW.value)
        reconcile = _Spy(monkeypatch, "reconcile_ticket_status")

        with StatementRecorder(db_session) as recorder:
            result = await _ignore(db_session, ticket.id, actor)

        assert result.id == ticket.id
        assert (result.status, result.assignee_id) == (TicketStatus.IGNORED, actor.id)
        assert await _state(db_session, ticket.id) == (TicketStatus.IGNORED, actor.id)
        assert await ticket_events(db_session, ticket) == [
            _assignment(actor),
            PROMOTION,
            _ignored(actor, TicketStatus.ANALYSIS),
        ]
        assert reconcile.calls == []
        assert pending_ticket_convergence_effects(db_session) == ()
        assert recorder.selects_from("ticket_audit_event") == []

    @pytest.mark.parametrize(
        ("active", "roles", "scope"),
        [
            pytest.param(
                True,
                (Role.RESTRICTED_ANALYST,),
                Scope.NON_CONFIDENTIAL,
                id="restricted-analyst",
            ),
            pytest.param(
                False, (Role.VULNERABILITY_ANALYST,), Scope.ALL, id="inactive-va"
            ),
        ],
    )
    async def test_ineligible_actor_ignores_a_new_ticket_directly(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        active: bool,
        roles: tuple[Role, ...],
        scope: Scope,
    ) -> None:
        """tickets.md, Status Transitions (note after the matrix): a
        non-VA actor cannot be assigned and records the direct
        `New -> Ignored`; the Ticket stays unassigned."""
        actor = await va_user(active=active, roles=roles)
        ticket = await ticket_factory(status=TicketStatus.NEW.value)

        await _ignore(db_session, ticket.id, actor, scope=scope)

        assert await _state(db_session, ticket.id) == (TicketStatus.IGNORED, None)
        assert await ticket_events(db_session, ticket) == [
            _ignored(actor, TicketStatus.NEW)
        ]

    @pytest.mark.parametrize(
        "preassigned", [False, True], ids=["unassigned", "assigned"]
    )
    async def test_analysis_ticket_is_ignored_with_auto_assignment_only_if_unassigned(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        preassigned: bool,
    ) -> None:
        """An `Analysis` Ticket has no promotion; an already-assigned
        Ticket keeps its assignee and records no `assignment`
        (rbac.md, Business Rule 12: ignore applies only the auto-assignment
        of an unassigned Ticket)."""
        actor = await va_user()
        owner = await va_user()
        ticket = await ticket_factory(
            status=TicketStatus.ANALYSIS.value,
            assignee_id=owner.id if preassigned else None,
        )

        await _ignore(db_session, ticket.id, actor)

        expected_assignee = owner.id if preassigned else actor.id
        claim = [] if preassigned else [_assignment(actor)]
        assert await _state(db_session, ticket.id) == (
            TicketStatus.IGNORED,
            expected_assignee,
        )
        assert await ticket_events(db_session, ticket) == [
            *claim,
            _ignored(actor, TicketStatus.ANALYSIS),
        ]


# ---------------------------------------------------------------------------
# Guards and their order, with zero side effects
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestGuards:
    @pytest.mark.parametrize("status", [TicketStatus.ANALYZED, TicketStatus.RESOLVED])
    async def test_gate_zone_beyond_analysis_is_an_invalid_transition(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
        status: TicketStatus,
    ) -> None:
        """An unassigned Ticket and a VA actor: a guard after the
        auto-assignment would be observable."""
        actor = await va_user()
        ticket = await ticket_factory(status=status.value)

        await _assert_rejected(
            db_session,
            monkeypatch,
            InvalidTransitionError,
            ticket_id=ticket.id,
            actor=actor,
        )

    @pytest.mark.parametrize("status", [TicketStatus.IGNORED, TicketStatus.DUPLICATED])
    async def test_manual_zone_is_not_mutable_before_the_status_check(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
        status: TicketStatus,
    ) -> None:
        """ticket-service.md, Operability guard (ordering constraint for
        `ignore_ticket`): neither status is a valid source state, yet the
        operability guard fires first with `TicketNotMutableError`."""
        actor = await va_user()
        ticket = await ticket_factory(status=status.value)

        await _assert_rejected(
            db_session,
            monkeypatch,
            TicketNotMutableError,
            ticket_id=ticket.id,
            actor=actor,
        )

    async def test_missing_ticket_is_not_found(
        self,
        db_session: AsyncSession,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        actor = await va_user()

        await _assert_rejected(
            db_session,
            monkeypatch,
            TicketNotFoundError,
            ticket_id=uuid.uuid7(),
            actor=actor,
        )

    @pytest.mark.parametrize(
        "status",
        [
            pytest.param(TicketStatus.NEW, id="ignorable"),
            pytest.param(TicketStatus.ANALYZED, id="also-invalid-transition"),
            pytest.param(TicketStatus.IGNORED, id="also-not-mutable"),
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
    ) -> None:
        """A VA origin with a request-resolved `non_confidential` scope: an
        auto-assignment before the denial would be observable. The only
        grant belongs to another user."""
        actor = await va_user()
        ticket = await ticket_factory(status=status.value, is_confidential=True)
        await ticket_access_grant_factory(ticket_id=ticket.id)

        await _assert_rejected(
            db_session,
            monkeypatch,
            TicketNotFoundError,
            ticket_id=ticket.id,
            actor=actor,
            scope=Scope.NON_CONFIDENTIAL,
        )

    async def test_caller_mismatch_raises_before_any_statement(
        self, db_session: AsyncSession, ticket_factory: TicketFactory, va_user: VAUser
    ) -> None:
        actor = await va_user()
        other = await va_user()
        ticket = await ticket_factory(status=TicketStatus.NEW.value)

        with (
            StatementRecorder(db_session) as recorder,
            pytest.raises(ValueError, match="acting user"),
        ):
            await ignore_ticket(
                db_session,
                ticket_id=ticket.id,
                acting_user_id=actor.id,
                caller=TicketCaller.authenticated(other.id, Scope.ALL),
            )

        assert recorder.statements == []
        assert await _state(db_session, ticket.id) == (TicketStatus.NEW, None)
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
        """A confidential Ticket reached through an explicit grant: the
        acting User `FOR SHARE` precedes the Ticket `FOR UPDATE`, which
        precedes the separate visibility statement."""
        actor = await va_user(roles=(Role.RESTRICTED_ANALYST,))
        ticket = await ticket_factory(
            status=TicketStatus.ANALYSIS.value, is_confidential=True
        )
        await ticket_access_grant_factory(ticket_id=ticket.id, user_id=actor.id)

        with StatementRecorder(db_session) as recorder:
            await _ignore(db_session, ticket.id, actor, scope=Scope.NON_CONFIDENTIAL)

        statements = recorder.statements

        def first(predicate: Callable[[str], bool]) -> int:
            return next(i for i, s in enumerate(statements) if predicate(s))

        user_share = first(lambda s: 'FROM "user"' in s and "FOR SHARE" in s)
        ticket_lock = first(lambda s: "FROM ticket" in s and "FOR UPDATE" in s)
        visibility = first(lambda s: "ticket_access_grant" in s)
        assert user_share < ticket_lock < visibility
        assert _bound(recorder.parameters[user_share]) == [actor.id]
        assert _bound(recorder.parameters[ticket_lock]) == [ticket.id]
        assert "ticket_access_grant" not in statements[ticket_lock]
        assert len(recorder.row_locks()) == 2
        assert await _state(db_session, ticket.id) == (TicketStatus.IGNORED, None)
        assert await ticket_events(db_session, ticket) == [
            _ignored(actor, TicketStatus.ANALYSIS)
        ]


# ---------------------------------------------------------------------------
# Whole-operation rollback (audit Testing Requirement 7) and no commit
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestRollback:
    @pytest.mark.parametrize("failure", ["audit", "flush"])
    async def test_entry_write_failure_rolls_back_assignment_status_and_events(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
        failure: str,
    ) -> None:
        """The failure is injected into the last write (the acting-user
        `Analysis -> Ignored`), after the assignment and promotion: either
        its audit validation or the flush that inserts it."""
        actor = await va_user()
        ticket = await ticket_factory(status=TicketStatus.NEW.value)
        ticket_id = ticket.id
        original_log = TicketAuditLog.log_event

        original_flush = db_session.flush
        reached = False

        async def failing_log(*args: Any, **kwargs: Any) -> None:
            nonlocal reached
            if (
                kwargs["event_type"] is TicketAuditEventType.STATUS_CHANGE
                and kwargs["new_value"] == TicketStatus.IGNORED
            ):
                reached = True
                raise RuntimeError("injected audit failure")
            await original_log(*args, **kwargs)

        async def failing_flush(*args: Any, **kwargs: Any) -> None:
            nonlocal reached
            if any(
                isinstance(o, TicketAuditEvent) and o.new_value == TicketStatus.IGNORED
                for o in db_session.new
            ):
                reached = True
                raise RuntimeError("injected flush failure")
            await original_flush(*args, **kwargs)

        async with rollback_test_scope(db_session):
            if failure == "audit":
                monkeypatch.setattr(TicketAuditLog, "log_event", failing_log)
            else:
                monkeypatch.setattr(db_session, "flush", failing_flush)
            with pytest.raises(RuntimeError, match="injected"):
                await _ignore(db_session, ticket_id, actor)
        monkeypatch.undo()

        assert reached

        assert await _state(db_session, ticket_id) == (TicketStatus.NEW, None)
        assert await ticket_events_by_id(db_session, ticket_id) == []

    async def test_never_commits(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        actor = await va_user()
        ticket = await ticket_factory(status=TicketStatus.NEW.value)

        async def forbidden() -> None:
            raise AssertionError("ignore_ticket() must not commit")

        monkeypatch.setattr(db_session, "commit", forbidden)
        monkeypatch.setattr(db_session, "rollback", forbidden)

        await _ignore(db_session, ticket.id, actor)
