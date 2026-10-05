"""Independent-session tests for `assign_ticket()`
(backend/app/services/ticket_service.py).

Owning specifications:

- docs/features/tickets/ticket-service.md (Caller category and Ticket
  accessibility; Concurrency control; `assign_ticket` Locking;
  Architectural Test Requirement 15, assignment part).
- docs/features/tickets/tickets.md (Reassignment: every assignment path
  stabilizes the prospective assignee with a User `FOR SHARE` lock before
  the Ticket lock).
- docs/features/tickets/ticket-audit-log.md (Cross-Event Ordering,
  Locking, and Rollback; Testing Requirement 23).
- docs/features/platform/testing-strategy.md (Concurrency Testing; Service
  Functions: lock serialization; Ticket Accessibility: Locked mutations).
- docs/conventions.md (Transaction and Locking: Cross-Domain Root Lock
  Order).

The single-session behavior of `assign_ticket()` is covered by
`tests/test_services/test_assign_ticket.py`; this module adds only what
needs independent sessions. The target-User lifecycle writer is simulated
by its documented `FOR NO KEY UPDATE` lock on the User row, so these tests
remain proofs of the assignment side of the lock protocol. The races of the
real `deactivate_user()` with its identity-local counterparts are covered
in `tests/test_services/test_deactivate_user_atomicity.py`; the assignment
race is not repeated there with the real writer.

Committed rows are deleted explicitly at teardown (testing-strategy.md,
Concurrency Testing). Expected values are transcribed from the
specifications, never computed with the module under test.
"""

from __future__ import annotations

import asyncio
import re
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from typing import Any

import pytest
from sqlalchemy import Select, select, update
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import Role, Scope, TicketStatus
from app.core.exceptions import TicketNotFoundError
from app.core.identifiers import format_ticket_id
from app.models.ticket import Ticket
from app.models.user import User
from app.services import ticket_service
from app.services.ticket_convergence_registry import (
    pending_ticket_convergence_effects,
)
from app.services.ticket_service import (
    AssigneeInactiveError,
    assign_ticket,
    resolve_ticket_locator,
)
from app.services.ticket_visibility import TicketCaller
from tests.support.database import assert_lock_wait
from tests.support.suse_cvss_races import (
    CommittedWorld,
    SessionStatementRecorder,
    prepare_loss,
)
from tests.support.ticket_mutations import (
    EVAL,
    EventRow,
    status_event,
    ticket_events_by_id,
)

Factory = Callable[[], Awaitable[AsyncSession]]

PROMOTION = status_event(TicketStatus.NEW.value, TicketStatus.ANALYSIS.value)
"""The explicit system `New -> Analysis` event of the assignment."""

TICKET_STATEMENT = re.compile(r"\b(?:FROM|JOIN|INTO|UPDATE) ticket\b")


@pytest.fixture
async def committed_world(db_session_factory: Factory) -> AsyncIterator[CommittedWorld]:
    world = CommittedWorld(db_session_factory, await db_session_factory())
    try:
        yield world
    finally:
        await world.cleanup()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _assignment(actor: User, old: User | None, new: User) -> EventRow:
    """The acting-user `assignment` event."""
    return EventRow(
        "assignment",
        actor.id,
        old.username if old is not None else None,
        new.username,
        None,
        None,
    )


def _start(
    world: CommittedWorld,
    session: AsyncSession,
    ticket: Ticket,
    target: str,
    actor: User,
    *,
    scope: Scope = Scope.ALL,
) -> asyncio.Task[Any]:
    """An `assign_ticket()` in `session`, tracked by the world."""
    return world.start(session, _assign(session, ticket, target, actor, scope=scope))


async def _assign(
    session: AsyncSession,
    ticket: Ticket,
    target: str,
    actor: User,
    *,
    scope: Scope = Scope.ALL,
) -> Ticket:
    return await assign_ticket(
        session,
        ticket_id=ticket.id,
        assignee=target,
        acting_user_id=actor.id,
        caller=TicketCaller.authenticated(actor.id, scope),
        evaluation_date=EVAL,
    )


class _Spy:
    """Wraps an async `ticket_service` attribute, recording the session of
    each call (independent sessions share the patched module)."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch, name: str) -> None:
        self.sessions: list[AsyncSession] = []
        original = getattr(ticket_service, name)

        async def _wrapper(*args: Any, **kwargs: Any) -> Any:
            self.sessions.append(args[1])
            return await original(*args, **kwargs)

        monkeypatch.setattr(ticket_service, name, _wrapper)


def _is_user_share(statement: str) -> bool:
    return 'FROM "user"' in statement and "FOR SHARE" in statement


def _is_ticket_lock(statement: str) -> bool:
    return TICKET_STATEMENT.search(
        statement
    ) is not None and statement.rstrip().endswith("FOR UPDATE")


async def _is_locked(probe: AsyncSession, statement: Select[Any]) -> bool:
    """Whether another transaction holds a conflicting lock on the row that
    `statement` selects (`FOR UPDATE NOWAIT`, released at once)."""
    try:
        await probe.execute(statement.with_for_update(nowait=True))
    except DBAPIError:
        await probe.rollback()
        return True
    await probe.rollback()
    return False


async def _committed(
    world: CommittedWorld, ticket: Ticket
) -> tuple[tuple[str, uuid.UUID | None], list[EventRow]]:
    """The committed `(status, assignee_id)` and events of a Ticket, read
    through a fresh independent session."""
    probe = await world.open_session()
    row = (
        await probe.execute(
            select(Ticket.status, Ticket.assignee_id).where(Ticket.id == ticket.id)
        )
    ).one()
    events = await ticket_events_by_id(probe, ticket.id)
    await probe.rollback()
    return (row.status, row.assignee_id), events


async def _hold_for_lifecycle_write(session: AsyncSession, user: User) -> None:
    """A simulated identity lifecycle writer: `FOR NO KEY UPDATE` on the
    User row (the lock of deactivation and role-origin removal), then the
    `active = false` write, left uncommitted."""
    await session.execute(
        select(User.id).where(User.id == user.id).with_for_update(key_share=True)
    )
    await session.execute(update(User).where(User.id == user.id).values(active=False))


# ---------------------------------------------------------------------------
# Ticket lock serialization (Service Functions; audit Testing Requirement 23)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestTicketLockSerialization:
    async def test_waiting_reassignment_uses_the_committed_winner_as_old_value(
        self, committed_world: CommittedWorld
    ) -> None:
        """B assigns X and holds the Ticket lock uncommitted; A's assignment
        to Y holds Y `FOR SHARE` and blocks on the Ticket lock. After B
        commits, A's event carries X as the true locked pre-state, and A
        creates no second promotion (it observes `Analysis`)."""
        actor_a = await committed_world.user(role=Role.VULNERABILITY_ANALYST)
        actor_b = await committed_world.user(role=Role.VULNERABILITY_ANALYST)
        x = await committed_world.user(role=Role.VULNERABILITY_ANALYST)
        y = await committed_world.user(role=Role.VULNERABILITY_ANALYST)
        ticket = await committed_world.ticket(cve_id=None, status=TicketStatus.NEW)
        a = await committed_world.open_session()
        b = await committed_world.open_session()
        probe = await committed_world.open_session()

        await _assign(b, ticket, str(x.id), actor_b)
        with SessionStatementRecorder(a) as recorder:
            task = _start(committed_world, a, ticket, str(y.id), actor_a)
            await assert_lock_wait(task, waiter=a, blocked_by=b)
            assert _is_user_share(recorder.statements[0])
            assert _is_ticket_lock(recorder.statements[-1])
            assert await _is_locked(probe, select(User.id).where(User.id == y.id))
            await b.commit()
            await asyncio.wait_for(task, timeout=5)
        await a.commit()

        assert await _committed(committed_world, ticket) == (
            (TicketStatus.ANALYSIS, y.id),
            [
                _assignment(actor_b, None, x),
                PROMOTION,
                _assignment(actor_a, x, y),
            ],
        )

    async def test_equal_target_loser_is_a_no_op(
        self, committed_world: CommittedWorld, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Two assignments to the same VA: the loser observes the winner's
        committed assignee under its lock and neither writes, audits, nor
        reconciles."""
        actor_a = await committed_world.user(role=Role.VULNERABILITY_ANALYST)
        actor_b = await committed_world.user(role=Role.VULNERABILITY_ANALYST)
        x = await committed_world.user(role=Role.VULNERABILITY_ANALYST)
        ticket = await committed_world.ticket(cve_id=None, status=TicketStatus.NEW)
        a = await committed_world.open_session()
        b = await committed_world.open_session()
        reconcile = _Spy(monkeypatch, "reconcile_ticket_status")

        await _assign(b, ticket, str(x.id), actor_b)
        with SessionStatementRecorder(a) as recorder:
            task = _start(committed_world, a, ticket, x.username, actor_a)
            await assert_lock_wait(task, waiter=a, blocked_by=b)
            await b.commit()
            result = await asyncio.wait_for(task, timeout=5)

        assert result.assignee_id == x.id
        assert recorder.writes() == []
        assert reconcile.sessions == [b]
        assert pending_ticket_convergence_effects(a) == ()
        await a.commit()
        assert await _committed(committed_world, ticket) == (
            (TicketStatus.ANALYSIS, x.id),
            [_assignment(actor_b, None, x), PROMOTION],
        )


# ---------------------------------------------------------------------------
# Target User FOR SHARE serialization
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestTargetUserLockSerialization:
    async def test_assignment_waits_for_a_target_lifecycle_writer(
        self, committed_world: CommittedWorld, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """B holds the target `FOR NO KEY UPDATE` and deactivates it. A
        blocks on the target `FOR SHARE` before requesting the Ticket lock,
        which an independent session can still take. After B commits, A
        decides from the locked-current row: `AssigneeInactiveError` with
        zero effects."""
        actor = await committed_world.user(role=Role.VULNERABILITY_ANALYST)
        target = await committed_world.user(role=Role.VULNERABILITY_ANALYST)
        ticket = await committed_world.ticket(cve_id=None, status=TicketStatus.NEW)
        a = await committed_world.open_session()
        b = await committed_world.open_session()
        probe = await committed_world.open_session()
        reconcile = _Spy(monkeypatch, "reconcile_ticket_status")

        await _hold_for_lifecycle_write(b, target)
        with SessionStatementRecorder(a) as recorder:
            task = _start(committed_world, a, ticket, str(target.id), actor)
            await assert_lock_wait(task, waiter=a, blocked_by=b)
            assert _is_user_share(recorder.statements[-1])
            assert not any(TICKET_STATEMENT.search(s) for s in recorder.statements)
            assert not await _is_locked(
                probe, select(Ticket.id).where(Ticket.id == ticket.id)
            )
            await b.commit()
            with pytest.raises(AssigneeInactiveError):
                await asyncio.wait_for(task, timeout=5)

        assert recorder.writes() == []
        assert reconcile.sessions == []
        assert pending_ticket_convergence_effects(a) == ()
        await a.rollback()
        assert await _committed(committed_world, ticket) == (
            (TicketStatus.NEW, None),
            [],
        )

    async def test_target_lifecycle_writer_waits_for_an_uncommitted_assignment(
        self, committed_world: CommittedWorld
    ) -> None:
        """Converse: A's uncommitted assignment holds the target `FOR SHARE`
        until its transaction ends, so B's `FOR NO KEY UPDATE` blocks until A
        commits."""
        actor = await committed_world.user(role=Role.VULNERABILITY_ANALYST)
        target = await committed_world.user(role=Role.VULNERABILITY_ANALYST)
        ticket = await committed_world.ticket(cve_id=None, status=TicketStatus.NEW)
        a = await committed_world.open_session()
        b = await committed_world.open_session()

        await _assign(a, ticket, str(target.id), actor)
        writer = committed_world.start(b, _hold_for_lifecycle_write(b, target))
        await assert_lock_wait(writer, waiter=b, blocked_by=a)
        await a.commit()
        await asyncio.wait_for(writer, timeout=5)
        await b.commit()

        assert await _committed(committed_world, ticket) == (
            (TicketStatus.ANALYSIS, target.id),
            [_assignment(actor, None, target), PROMOTION],
        )


# ---------------------------------------------------------------------------
# ATR 15: locked-current accessibility (assignment part)
# ---------------------------------------------------------------------------


LOSSES = ["confidentiality-set", "grant-revoked", "last-package-excluded"]


@pytest.mark.integration
class TestLockedCurrentAccessibilityRaces:
    """Session A passes the preliminary locator check; session B then holds
    the Ticket `FOR UPDATE` and removes A's only visibility path. A holds
    the target `FOR SHARE` (when it exists), is proven blocked on the Ticket
    lock, B commits, and A must be denied from the locked-current state
    with zero side effects, even for an absent target (testing-strategy.md,
    Ticket Accessibility: Locked mutations)."""

    @pytest.mark.parametrize("target_kind", ["eligible", "absent"])
    @pytest.mark.parametrize("loss", LOSSES)
    async def test_visibility_lost_while_waiting_for_the_lock_is_not_found(
        self,
        committed_world: CommittedWorld,
        monkeypatch: pytest.MonkeyPatch,
        loss: str,
        target_kind: str,
    ) -> None:
        user, _cve, ticket, statements = await prepare_loss(committed_world, loss)
        target = (
            str((await committed_world.user(role=Role.VULNERABILITY_ANALYST)).id)
            if target_kind == "eligible"
            else str(uuid.uuid7())
        )
        a = await committed_world.open_session()
        b = await committed_world.open_session()
        caller = TicketCaller.authenticated(user.id, Scope.NON_CONFIDENTIAL)
        assign = _Spy(monkeypatch, "auto_assign_actor")
        reconcile = _Spy(monkeypatch, "reconcile_ticket_status")

        resolved = await resolve_ticket_locator(
            a, format_ticket_id(ticket.sequence_id), caller
        )
        assert resolved.id == ticket.id
        for statement in statements:
            await b.execute(statement)
        with SessionStatementRecorder(a) as recorder:
            task = _start(
                committed_world, a, ticket, target, user, scope=Scope.NON_CONFIDENTIAL
            )
            await assert_lock_wait(task, waiter=a, blocked_by=b)
            assert _is_user_share(recorder.statements[0])
            assert _is_ticket_lock(recorder.statements[-1])
            await b.commit()
            with pytest.raises(TicketNotFoundError):
                await asyncio.wait_for(task, timeout=5)

        assert recorder.writes() == []
        assert (assign.sessions, reconcile.sessions) == ([], [])
        assert pending_ticket_convergence_effects(a) == ()
        await a.rollback()
        assert await _committed(committed_world, ticket) == (
            (TicketStatus.ANALYSIS, None),
            [],
        )
