"""Independent-session tests for the manual-zone entries `ignore_ticket()`
and `mark_as_duplicate()` (backend/app/services/ticket_service.py).

Owning specifications:

- docs/features/tickets/ticket-service.md (Caller category and Ticket
  accessibility; `ignore_ticket`; `mark_as_duplicate`: Locking,
  Constraint, Atomicity guarantee; Architectural Test Requirements 6 and
  15, manual-zone entry part).
- docs/features/tickets/ticket-mutations.md (Concurrency Control:
  Single-ticket scope, the two-phase root/dependent protocol and its
  deadlock freedom; Blocking wait).
- docs/features/tickets/ticket-audit-log.md (Cross-Event Ordering,
  Locking, and Rollback; Testing Requirements 7 and 23).
- docs/features/platform/testing-strategy.md (Concurrency Testing; Ticket
  Accessibility: Locked mutations; Tier Responsibility and
  Proportionality).
- docs/conventions.md (Transaction and Locking: Cross-Domain Root Lock
  Order).

The single-session behavior (guards and their order, events, dependent
repoint order, auto-assignment) is covered by
`tests/test_services/test_ignore_ticket.py` and
`tests/test_services/test_mark_as_duplicate.py`; this module adds only
what needs independent sessions: the `NOWAIT` dependent conflict and its
retry (ATR 6), the ordered-root serialization of opposite-direction marks,
waiting winner/loser pre-state (audit TR 23), and locked-current
accessibility races (ATR 15).

Not applicable, hence not tested here: the converse self-loss case of
ATR 15. Neither mutation changes a visibility input (confidentiality,
grants, or included-package maintainership), so neither can remove the
caller's last visibility path.

Committed rows are deleted explicitly at teardown (testing-strategy.md,
Concurrency Testing). `CommittedWorld.cleanup()` deletes every audit event
and grant before the Tickets, and removes all Tickets in one `DELETE`, so
the non-deferrable `duplicate_of_id` self-reference is checked only once
dependents and their targets are both gone. Every wait is bounded with
`asyncio.wait_for()` (over `asyncio.shield()` where the task must survive
the timeout) so a regression fails instead of hanging. Expected values are
transcribed from the specifications, never computed with the module under
test.
"""

from __future__ import annotations

import asyncio
import re
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable, Iterable
from typing import Any

import pytest
from sqlalchemy import Select, select, update
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import Role, Scope, TicketStatus
from app.core.exceptions import TicketNotFoundError, TicketNotMutableError
from app.models.ticket import Ticket
from app.models.ticket_audit_event import TicketAuditEvent
from app.models.user import User
from app.services import ticket_mutations, ticket_service
from app.services.ticket_service import (
    DuplicateConcurrentModificationError,
    DuplicateTargetIsDuplicatedError,
    assign_ticket,
    ignore_ticket,
    mark_as_duplicate,
    resolve_ticket_locator,
)
from app.services.ticket_visibility import TicketCaller
from tests.support.suse_cvss_races import (
    CommittedWorld,
    SessionStatementRecorder,
    assert_blocked,
    prepare_loss,
)
from tests.support.ticket_mutations import EVAL, EventRow, status_event

Factory = Callable[[], Awaitable[AsyncSession]]
State = tuple[str, uuid.UUID | None, uuid.UUID | None]
"""The committed `(status, duplicate_of_id, assignee_id)` of a Ticket."""

TICKET_STATEMENT = re.compile(r"\b(?:FROM|JOIN|INTO|UPDATE) ticket\b")
WAIT = 5
"""Upper bound, in seconds, of every wait that is expected to finish."""
NOWAIT_BOUND = 2
"""Upper bound, in seconds, of a call that must fail without waiting."""


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


def _sntl(ticket: Ticket) -> str:
    """The public `SNTL-{n}` identifier (tickets.md, SNTL-{n} Format)."""
    return f"SNTL-{ticket.sequence_id}"


def _entered(actor: User, old: TicketStatus, new: TicketStatus) -> EventRow:
    """The acting-user manual-zone entry `status_change`."""
    return EventRow("status_change", actor.id, old.value, new.value, None, None)


def _duplicate_set(actor: User, target: Ticket) -> EventRow:
    return EventRow("duplicate_set", actor.id, None, _sntl(target), None, None)


def _retargeted(source: Ticket, target: Ticket) -> EventRow:
    """The system `duplicate_target_changed` of one repointed dependent."""
    return EventRow(
        "duplicate_target_changed",
        None,
        _sntl(source),
        _sntl(target),
        None,
        {"triggered_by_ticket": _sntl(source)},
    )


async def _ticket(
    world: CommittedWorld,
    *,
    ticket_id: uuid.UUID | None = None,
    status: TicketStatus = TicketStatus.ANALYSIS,
    duplicate_of: Ticket | None = None,
    assignee: User | None = None,
) -> Ticket:
    """A committed CVE-less, non-confidential Ticket with a chosen UUID
    (the root lock order is the UUID order) and optional duplicate link;
    registered with the world for explicit cleanup."""
    ticket = Ticket(
        id=ticket_id or uuid.uuid7(),
        status=status.value,
        duplicate_of_id=duplicate_of.id if duplicate_of is not None else None,
        assignee_id=assignee.id if assignee is not None else None,
    )
    world.session.add(ticket)
    await world.session.flush()
    world.ticket_ids.append(ticket.id)
    await world.session.commit()
    return ticket


def _ordered_ids() -> tuple[uuid.UUID, uuid.UUID]:
    """Two fresh Ticket UUIDs in ascending order."""
    low, high = sorted((uuid.uuid4(), uuid.uuid4()))
    return low, high


async def _mark(
    db: AsyncSession,
    source: Ticket,
    target: Ticket,
    actor: User,
    *,
    scope: Scope = Scope.ALL,
) -> Ticket:
    return await mark_as_duplicate(
        db,
        ticket_id=source.id,
        duplicate_of_id=target.id,
        acting_user_id=actor.id,
        caller=TicketCaller.authenticated(actor.id, scope),
    )


async def _ignore(
    db: AsyncSession, ticket: Ticket, actor: User, *, scope: Scope = Scope.ALL
) -> Ticket:
    return await ignore_ticket(
        db,
        ticket_id=ticket.id,
        acting_user_id=actor.id,
        caller=TicketCaller.authenticated(actor.id, scope),
    )


class _AutoAssignSpy:
    """Records the session of every `auto_assign_actor(ticket, actor, db)`
    call made through `ticket_service` (independent sessions share the
    patched module)."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.sessions: list[AsyncSession] = []
        original = ticket_mutations.auto_assign_actor

        async def _wrapper(*args: Any, **kwargs: Any) -> Any:
            self.sessions.append(args[2])
            return await original(*args, **kwargs)

        monkeypatch.setattr(ticket_service, "auto_assign_actor", _wrapper)


def _is_ticket_lock(statement: str) -> bool:
    return TICKET_STATEMENT.search(
        statement
    ) is not None and statement.rstrip().endswith("FOR UPDATE")


def _is_user_share(statement: str) -> bool:
    return 'FROM "user"' in statement and "FOR SHARE" in statement


def _nowait(statements: Iterable[str]) -> list[str]:
    return [s for s in statements if "NOWAIT" in s]


def _row(ticket_id: uuid.UUID) -> Select[Any]:
    return select(Ticket.id).where(Ticket.id == ticket_id)


async def _hold(session: AsyncSession, ticket_id: uuid.UUID) -> None:
    """Take `FOR UPDATE` on one Ticket row and keep it until the session's
    transaction ends (a concurrent single-Ticket writer)."""
    await session.execute(_row(ticket_id).with_for_update())


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
    world: CommittedWorld, tickets: Iterable[Ticket]
) -> tuple[dict[uuid.UUID, State], list[tuple[uuid.UUID, EventRow]]]:
    """The committed states and audit events (global UUIDv7 insertion
    order, each with its Ticket UUID) of `tickets`, read through a fresh
    independent session."""
    ids = [t.id for t in tickets]
    probe = await world.open_session()
    rows = await probe.execute(
        select(
            Ticket.id, Ticket.status, Ticket.duplicate_of_id, Ticket.assignee_id
        ).where(Ticket.id.in_(ids))
    )
    states = {r.id: (r.status, r.duplicate_of_id, r.assignee_id) for r in rows}
    events = (
        await probe.execute(
            select(TicketAuditEvent)
            .where(TicketAuditEvent.ticket_id.in_(ids))
            .order_by(TicketAuditEvent.id)
        )
    ).scalars()
    history = [
        (
            e.ticket_id,
            EventRow(
                e.event_type, e.user_id, e.old_value, e.new_value, e.comment, e.detail
            ),
        )
        for e in events
    ]
    await probe.rollback()
    return states, history


# ---------------------------------------------------------------------------
# ATR 6: NOWAIT conflict on a dependent, then retry
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestDependentConcurrentModification:
    async def test_locked_dependent_aborts_without_effect_and_retry_succeeds(
        self, committed_world: CommittedWorld, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A points to B. S2 holds A `FOR UPDATE` (a concurrent revert).
        Marking B as a duplicate of C fails at once with
        `DuplicateConcurrentModificationError` instead of waiting; after the
        caller's rollback nothing persists. Once S2 releases A, a retry in
        a new transaction repoints A with exactly the specified events."""
        actor = await committed_world.user(role=Role.VULNERABILITY_ANALYST)
        owner = await committed_world.user(role=Role.VULNERABILITY_ANALYST)
        c = await _ticket(committed_world)
        b = await _ticket(committed_world, assignee=owner)
        a = await _ticket(
            committed_world, status=TicketStatus.DUPLICATED, duplicate_of=b
        )
        s1 = await committed_world.open_session()
        s2 = await committed_world.open_session()
        assign = _AutoAssignSpy(monkeypatch)
        before = {
            a.id: (TicketStatus.DUPLICATED, b.id, None),
            b.id: (TicketStatus.ANALYSIS, None, owner.id),
            c.id: (TicketStatus.ANALYSIS, None, None),
        }

        await _hold(s2, a.id)
        with SessionStatementRecorder(s1) as recorder:
            task = committed_world.start(s1, _mark(s1, b, c, actor))
            with pytest.raises(DuplicateConcurrentModificationError):
                await asyncio.wait_for(asyncio.shield(task), timeout=NOWAIT_BOUND)

        # The dependent lock is the failing, final statement: Phase 2 never
        # waits, and nothing was assigned or written before it.
        assert len(_nowait(recorder.statements)) == 1
        assert "NOWAIT" in recorder.statements[-1]
        assert recorder.writes() == []
        assert assign.sessions == []
        await s1.rollback()
        assert await _committed(committed_world, [a, b, c]) == (before, [])

        await s2.rollback()
        retry = await committed_world.open_session()
        await asyncio.wait_for(_mark(retry, b, c, actor), timeout=WAIT)
        await retry.commit()

        assert await _committed(committed_world, [a, b, c]) == (
            {
                a.id: (TicketStatus.DUPLICATED, c.id, None),
                b.id: (TicketStatus.DUPLICATED, c.id, owner.id),
                c.id: (TicketStatus.ANALYSIS, None, None),
            },
            [
                (b.id, _entered(actor, TicketStatus.ANALYSIS, TicketStatus.DUPLICATED)),
                (b.id, _duplicate_set(actor, c)),
                (a.id, _retargeted(b, c)),
            ],
        )


# ---------------------------------------------------------------------------
# Phase 1: ordered roots, opposite-direction marks (deadlock freedom)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestOrderedRootLocks:
    async def test_opposite_marks_serialize_on_the_lower_root_without_deadlock(
        self, committed_world: CommittedWorld
    ) -> None:
        """A holder takes only the lower-UUID row. `low -> high` and
        `high -> low` are both issued and both wait for the lower row,
        whatever their direction: neither has locked the higher row, which
        a third session can still lock `NOWAIT`. After the holder releases,
        exactly one mark wins while the other still waits for the lower row
        held by the uncommitted winner. After the winner commits, the loser
        acquires both roots, observes its target committed as `Duplicated`
        (its own source is untouched and still operable), and raises
        `DuplicateTargetIsDuplicatedError` with no event and no deadlock."""
        owner = await committed_world.user(role=Role.VULNERABILITY_ANALYST)
        actor_up = await committed_world.user(role=Role.VULNERABILITY_ANALYST)
        actor_down = await committed_world.user(role=Role.VULNERABILITY_ANALYST)
        low_id, high_id = _ordered_ids()
        low = await _ticket(committed_world, ticket_id=low_id, assignee=owner)
        high = await _ticket(committed_world, ticket_id=high_id, assignee=owner)
        holder = await committed_world.open_session()
        up = await committed_world.open_session()
        down = await committed_world.open_session()
        probe = await committed_world.open_session()

        await _hold(holder, low.id)
        with (
            SessionStatementRecorder(up) as up_recorder,
            SessionStatementRecorder(down) as down_recorder,
        ):
            up_task = committed_world.start(up, _mark(up, low, high, actor_up))
            down_task = committed_world.start(down, _mark(down, high, low, actor_down))
            await assert_blocked(up_task)
            await assert_blocked(down_task)
            for recorder in (up_recorder, down_recorder):
                assert _is_ticket_lock(recorder.statements[-1])
                assert recorder.parameters[-1][0] == low.id
            assert not await _is_locked(probe, _row(high.id))

            await holder.rollback()
            done, _pending = await asyncio.wait(
                {up_task, down_task},
                timeout=WAIT,
                return_when=asyncio.FIRST_COMPLETED,
            )
            assert len(done) == 1
            winner_task = done.pop()
            winner_task.result()
            if winner_task is up_task:
                winner, loser, loser_task = up, down, down_task
                source, target, actor = low, high, actor_up
            else:
                winner, loser, loser_task = down, up, up_task
                source, target, actor = high, low, actor_down
            await assert_blocked(loser_task)

            await winner.commit()
            with pytest.raises(DuplicateTargetIsDuplicatedError):
                await asyncio.wait_for(asyncio.shield(loser_task), timeout=WAIT)
            loser_recorder = up_recorder if loser is up else down_recorder
            assert loser_recorder.writes() == []
            await loser.rollback()

        assert await _committed(committed_world, [low, high]) == (
            {
                source.id: (TicketStatus.DUPLICATED, target.id, owner.id),
                target.id: (TicketStatus.ANALYSIS, None, owner.id),
            },
            [
                (
                    source.id,
                    _entered(actor, TicketStatus.ANALYSIS, TicketStatus.DUPLICATED),
                ),
                (source.id, _duplicate_set(actor, target)),
            ],
        )


# ---------------------------------------------------------------------------
# Waiting winner/loser pre-state (audit Testing Requirement 23)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestIgnoreLockSerialization:
    async def test_waiting_ignore_after_a_committed_ignore_is_not_mutable(
        self, committed_world: CommittedWorld
    ) -> None:
        """The loser observes the winner's committed `Ignored` under its
        lock: `TicketNotMutableError` and no event of its own."""
        owner = await committed_world.user(role=Role.VULNERABILITY_ANALYST)
        winner_actor = await committed_world.user(role=Role.VULNERABILITY_ANALYST)
        loser_actor = await committed_world.user(role=Role.VULNERABILITY_ANALYST)
        ticket = await _ticket(committed_world, assignee=owner)
        winner = await committed_world.open_session()
        loser = await committed_world.open_session()

        await _ignore(winner, ticket, winner_actor)
        with SessionStatementRecorder(loser) as recorder:
            task = committed_world.start(loser, _ignore(loser, ticket, loser_actor))
            await assert_blocked(task)
            assert _is_user_share(recorder.statements[0])
            assert _is_ticket_lock(recorder.statements[-1])
            await winner.commit()
            with pytest.raises(TicketNotMutableError):
                await asyncio.wait_for(asyncio.shield(task), timeout=WAIT)

        assert recorder.writes() == []
        await loser.rollback()
        assert await _committed(committed_world, [ticket]) == (
            {ticket.id: (TicketStatus.IGNORED, None, owner.id)},
            [
                (
                    ticket.id,
                    _entered(winner_actor, TicketStatus.ANALYSIS, TicketStatus.IGNORED),
                )
            ],
        )

    async def test_waiting_ignore_uses_the_committed_assignment_as_pre_state(
        self, committed_world: CommittedWorld
    ) -> None:
        """An unassigned `New` Ticket: alone, the VA actor's ignore would
        auto-assign and promote first. A concurrent `assign_ticket()` holds
        the Ticket and commits the assignment and `New -> Analysis`; the
        waiting ignore then neither assigns nor promotes again and records
        `Analysis -> Ignored` from the committed winner's status."""
        actor = await committed_world.user(role=Role.VULNERABILITY_ANALYST)
        assigner = await committed_world.user(role=Role.VULNERABILITY_ANALYST)
        assignee = await committed_world.user(role=Role.VULNERABILITY_ANALYST)
        ticket = await _ticket(committed_world, status=TicketStatus.NEW)
        winner = await committed_world.open_session()
        loser = await committed_world.open_session()

        await assign_ticket(
            winner,
            ticket_id=ticket.id,
            assignee=str(assignee.id),
            acting_user_id=assigner.id,
            caller=TicketCaller.authenticated(assigner.id, Scope.ALL),
            evaluation_date=EVAL,
        )
        task = committed_world.start(loser, _ignore(loser, ticket, actor))
        await assert_blocked(task)
        await winner.commit()
        await asyncio.wait_for(asyncio.shield(task), timeout=WAIT)
        await loser.commit()

        assert await _committed(committed_world, [ticket]) == (
            {ticket.id: (TicketStatus.IGNORED, None, assignee.id)},
            [
                (
                    ticket.id,
                    EventRow(
                        "assignment", assigner.id, None, assignee.username, None, None
                    ),
                ),
                (
                    ticket.id,
                    status_event(TicketStatus.NEW.value, TicketStatus.ANALYSIS.value),
                ),
                (
                    ticket.id,
                    _entered(actor, TicketStatus.ANALYSIS, TicketStatus.IGNORED),
                ),
            ],
        )


# ---------------------------------------------------------------------------
# ATR 15: locked-current accessibility (manual-zone entry part)
# ---------------------------------------------------------------------------


LOSSES = ["confidentiality-set", "grant-revoked", "last-package-excluded"]


@pytest.mark.integration
class TestLockedCurrentAccessibilityRaces:
    """The caller passes the preliminary locator check; an independent
    session then holds a root `FOR UPDATE` and removes the caller's only
    visibility path. The operation is proven blocked on that root, the
    holder commits, and the operation must be denied from the
    locked-current state with zero side effects (testing-strategy.md,
    Ticket Accessibility: Locked mutations)."""

    @pytest.mark.parametrize("loss", LOSSES)
    async def test_ignore_visibility_lost_while_waiting_is_not_found(
        self,
        committed_world: CommittedWorld,
        monkeypatch: pytest.MonkeyPatch,
        loss: str,
    ) -> None:
        user, _cve, ticket, statements = await prepare_loss(committed_world, loss)
        a = await committed_world.open_session()
        b = await committed_world.open_session()
        caller = TicketCaller.authenticated(user.id, Scope.NON_CONFIDENTIAL)
        assign = _AutoAssignSpy(monkeypatch)

        resolved = await resolve_ticket_locator(a, _sntl(ticket), caller)
        assert resolved.id == ticket.id
        for statement in statements:
            await b.execute(statement)
        with SessionStatementRecorder(a) as recorder:
            task = committed_world.start(
                a, _ignore(a, ticket, user, scope=Scope.NON_CONFIDENTIAL)
            )
            await assert_blocked(task)
            assert _is_user_share(recorder.statements[0])
            assert _is_ticket_lock(recorder.statements[-1])
            await b.commit()
            with pytest.raises(TicketNotFoundError):
                await asyncio.wait_for(asyncio.shield(task), timeout=WAIT)

        assert recorder.writes() == []
        assert assign.sessions == []
        await a.rollback()
        assert await _committed(committed_world, [ticket]) == (
            {ticket.id: (TicketStatus.ANALYSIS, None, None)},
            [],
        )

    @pytest.mark.parametrize("position", ["first", "second"])
    @pytest.mark.parametrize("role", ["source", "target"])
    async def test_mark_root_visibility_lost_while_waiting_is_not_found(
        self,
        committed_world: CommittedWorld,
        monkeypatch: pytest.MonkeyPatch,
        role: str,
        position: str,
    ) -> None:
        """The holder takes the root that loses visibility and makes it
        confidential. Its UUID position decides where the mark waits:
        as the lower UUID (`first`) the mark waits before locking any
        root, so the other root stays free; as the higher UUID (`second`)
        the mark already holds the other root, so the decision must use
        visibility read after both roots are locked, not after the first.
        Denial precedes Phase 2: no dependent lock, no repoint."""
        user = await committed_world.user(role=Role.RESTRICTED_ANALYST)
        low_id, high_id = _ordered_ids()
        lost_id, kept_id = (low_id, high_id)
        if position == "second":
            lost_id, kept_id = kept_id, lost_id
        source_id, target_id = (lost_id, kept_id)
        if role == "target":
            source_id, target_id = target_id, source_id
        source = await _ticket(committed_world, ticket_id=source_id)
        target = await _ticket(committed_world, ticket_id=target_id)
        dependent = await _ticket(
            committed_world, status=TicketStatus.DUPLICATED, duplicate_of=source
        )
        a = await committed_world.open_session()
        b = await committed_world.open_session()
        probe = await committed_world.open_session()
        caller = TicketCaller.authenticated(user.id, Scope.NON_CONFIDENTIAL)
        assign = _AutoAssignSpy(monkeypatch)

        for root in (source, target):
            resolved = await resolve_ticket_locator(a, _sntl(root), caller)
            assert resolved.id == root.id
        await _hold(b, lost_id)
        await b.execute(
            update(Ticket).where(Ticket.id == lost_id).values(is_confidential=True)
        )
        with SessionStatementRecorder(a) as recorder:
            task = committed_world.start(
                a, _mark(a, source, target, user, scope=Scope.NON_CONFIDENTIAL)
            )
            await assert_blocked(task)
            assert _is_user_share(recorder.statements[0])
            assert _is_ticket_lock(recorder.statements[-1])
            assert recorder.parameters[-1][0] == lost_id
            # The other root is held by the mark only when it comes first.
            assert await _is_locked(probe, _row(kept_id)) is (position == "second")
            await b.commit()
            with pytest.raises(TicketNotFoundError):
                await asyncio.wait_for(asyncio.shield(task), timeout=WAIT)

        assert _nowait(recorder.statements) == []
        assert recorder.writes() == []
        assert assign.sessions == []
        await a.rollback()
        assert await _committed(committed_world, [source, target, dependent]) == (
            {
                source.id: (TicketStatus.ANALYSIS, None, None),
                target.id: (TicketStatus.ANALYSIS, None, None),
                dependent.id: (TicketStatus.DUPLICATED, source.id, None),
            },
            [],
        )
