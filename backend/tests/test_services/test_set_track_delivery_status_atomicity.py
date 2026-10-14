"""Independent-session tests for `set_track_delivery_status()`
(backend/app/services/package_service.py).

Owning specifications:

- docs/features/packages/package-service.md (`set_track_delivery_status()`,
  including Concurrent outcome, the caller-owned transaction, and
  Exceptions; Concurrency Control; Architectural Test Requirement bullets
  "Delivery mutation composition" (two-step atomic advancement, caller-owned
  rollback) and "Concurrent direct mutations").
- docs/features/packages/package-model.md (Automatic Transitions: no
  intermediate state is externally committed; RELEASED is irreversible).
- docs/features/platform/testing-strategy.md (Concurrency Testing and
  Lock-Wait Observation; Service Functions (lock serialization); Audit
  Trail Testing (rollback or retry cannot synthesize an event)).

The single-session behavior is covered by
`tests/test_services/test_set_track_delivery_status.py`; this module adds
only what needs independent sessions and committed data:

- a two-step `PENDING -> IN_PROGRESS -> RELEASED` commits atomically, and a
  failure after the first step or during the flush leaves the committed
  value unchanged after the caller's rollback;
- a waiter proven blocked on the Ticket lock classifies against the
  committed winner's value: an equal target is a `no_op`, a transition is
  validated from the winner's value (never from the waiter's stale copy),
  and a change out of a committed `RELEASED` is rejected;
- after a rolled-back holder, the waiter classifies against the unchanged
  committed value.

Every committed Ticket is a CVE-less `Analysis` Ticket with one `AFFECTED`
IBS track. Committed rows are deleted explicitly at teardown by
`CommittedWorld` (testing-strategy.md, Concurrency Testing). Expected values
are transcribed from the specifications, never computed with the module
under test.
"""

from __future__ import annotations

import asyncio
import re
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable, Coroutine
from dataclasses import dataclass
from typing import Any

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import DeliveryStatus, PackageStatus, Severity, TicketStatus
from app.models.ticket_package import TicketPackage
from app.models.ticket_package_track import TicketPackageTrack
from app.services.package_service import (
    DeliveryStatusResult,
    InvalidDeliveryStatusTransition,
    MutationOutcome,
    set_track_delivery_status,
)
from tests.support.database import assert_lock_wait
from tests.support.suse_cvss_races import CommittedWorld, SessionStatementRecorder
from tests.support.ticket_mutations import ticket_events_by_id

Factory = Callable[[], Awaitable[AsyncSession]]

TICKET_STATEMENT = re.compile(r"\bFROM ticket\b")
WAIT = 5
"""Upper bound, in seconds, of every wait that is expected to finish."""

PENDING = DeliveryStatus.PENDING
IN_PROGRESS = DeliveryStatus.IN_PROGRESS
RELEASED = DeliveryStatus.RELEASED


@pytest.fixture
async def committed_world(db_session_factory: Factory) -> AsyncIterator[CommittedWorld]:
    world = CommittedWorld(db_session_factory, await db_session_factory())
    try:
        yield world
    finally:
        await world.cleanup()


@dataclass(frozen=True, slots=True)
class _Track:
    """One committed track with its declared path."""

    ticket_id: uuid.UUID
    package_id: uuid.UUID
    id: uuid.UUID


async def _committed_track(
    world: CommittedWorld, delivery: DeliveryStatus = PENDING
) -> _Track:
    """Commit the module's Ticket and track (see the module docstring)."""
    ticket = await world.ticket(
        cve_id=None, status=TicketStatus.ANALYSIS, severity_manual=Severity.HIGH
    )
    session = world.session
    package = TicketPackage(ticket_id=ticket.id, package_name="fictional-delivery")
    session.add(package)
    await session.flush()
    track = TicketPackageTrack(
        ticket_package_id=package.id,
        workflow_type="ibs",
        reference=f"Example:Codestream:{uuid.uuid4().hex[:10]}:Update",
        status=PackageStatus.AFFECTED.value,
        delivery_status=delivery.value,
    )
    session.add(track)
    await session.commit()
    return _Track(ticket.id, package.id, track.id)


def _set(
    session: AsyncSession, track: _Track, delivery: DeliveryStatus
) -> Coroutine[Any, Any, DeliveryStatusResult]:
    """The service call as the shared IBS reconciler makes it, with the
    explicit declared path, so the call issues no statement before its own
    lock."""
    return set_track_delivery_status(
        session,
        ticket_id=track.ticket_id,
        package_id=track.package_id,
        track_id=track.id,
        delivery_status=delivery,
    )


async def _committed(world: CommittedWorld, track: _Track) -> tuple[str, int]:
    """The committed delivery value and the number of committed Ticket
    events, read through a fresh independent session."""
    probe = await world.open_session()
    value = (
        await probe.execute(
            select(TicketPackageTrack.delivery_status).where(
                TicketPackageTrack.id == track.id
            )
        )
    ).scalar_one()
    events = await ticket_events_by_id(probe, track.ticket_id)
    await probe.rollback()
    return value, len(events)


async def _stale_copy(session: AsyncSession, track: _Track) -> TicketPackageTrack:
    """Load the track into `session`'s identity map before the race."""
    loaded = await session.get(TicketPackageTrack, track.id)
    assert loaded is not None
    return loaded


def _is_ticket_lock(statement: str) -> bool:
    return TICKET_STATEMENT.search(
        statement
    ) is not None and statement.rstrip().endswith("FOR UPDATE")


# ---------------------------------------------------------------------------
# Atomic composition and caller-owned rollback
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestAtomicComposition:
    """package-service.md, `set_track_delivery_status()` (participates in
    the caller-owned transaction, never commits or rolls back) and
    Architectural Test Requirement: Delivery mutation composition;
    package-model.md, Automatic Transitions (no intermediate state is
    externally committed)."""

    async def test_two_step_advancement_commits_released_only(
        self, committed_world: CommittedWorld
    ) -> None:
        track = await _committed_track(committed_world)
        session = await committed_world.open_session()

        first = await _set(session, track, IN_PROGRESS)
        assert await _committed(committed_world, track) == (PENDING.value, 0)
        second = await _set(session, track, RELEASED)
        await session.commit()

        assert (first.outcome, second.outcome) == (
            MutationOutcome.CHANGED,
            MutationOutcome.CHANGED,
        )
        assert await _committed(committed_world, track) == (RELEASED.value, 0)

    @pytest.mark.parametrize("failure", ["between-steps", "database"])
    async def test_failure_and_rollback_leave_the_committed_value(
        self,
        committed_world: CommittedWorld,
        monkeypatch: pytest.MonkeyPatch,
        failure: str,
    ) -> None:
        """`between-steps`: the caller fails after `PENDING -> IN_PROGRESS`
        and before the release step. `database`: the flush of the second
        step executes a statement PostgreSQL rejects (division by zero), so
        a genuine `DBAPIError` propagates after the first step reached the
        database. After the caller's rollback the committed value is still
        `PENDING`, and a retry commits `RELEASED` with no Ticket event."""
        track = await _committed_track(committed_world)
        session = await committed_world.open_session()

        await _set(session, track, IN_PROGRESS)
        if failure == "database":
            original_flush = session.flush

            async def flush(*args: Any, **kwargs: Any) -> None:
                await session.execute(text("SELECT 1 / 0"))
                await original_flush(*args, **kwargs)

            monkeypatch.setattr(session, "flush", flush)
            with pytest.raises(DBAPIError):
                await _set(session, track, RELEASED)
            monkeypatch.undo()
        await session.rollback()

        assert await _committed(committed_world, track) == (PENDING.value, 0)

        retry = await committed_world.open_session()
        await _set(retry, track, IN_PROGRESS)
        result = await _set(retry, track, RELEASED)
        await retry.commit()

        assert result.outcome is MutationOutcome.CHANGED
        assert await _committed(committed_world, track) == (RELEASED.value, 0)


# ---------------------------------------------------------------------------
# Concurrent calls (package-service.md, Concurrent outcome)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestConcurrentCalls:
    """package-service.md, `set_track_delivery_status()` Concurrent outcome
    (after waiting for the Ticket lock, the function uses the winner's
    committed value: `no_op` when it equals the target, otherwise the
    transition is validated from it; never a stale pre-lock old value) and
    Concurrency Control; testing-strategy.md, Lock-Wait Observation. The
    waiter holds a stale identity-map copy loaded before the race, and its
    only statement while blocked is the Ticket `FOR UPDATE`."""

    async def _race(
        self,
        world: CommittedWorld,
        track: _Track,
        *,
        winner_steps: tuple[DeliveryStatus, ...],
        waiter_target: DeliveryStatus,
        winner_commits: bool,
    ) -> tuple[asyncio.Task[DeliveryStatusResult], AsyncSession, list[str]]:
        """Let the winner apply `winner_steps` under the Ticket lock, start
        the waiter, prove it blocked on that lock with only the lock
        statement issued, then commit or roll back the winner and let the
        waiter finish. Returns the waiter's task, session, and writes."""
        winner = await world.open_session()
        waiter = await world.open_session()
        initial = (await _committed(world, track))[0]
        stale = await _stale_copy(waiter, track)
        assert stale.delivery_status == initial

        for step in winner_steps:
            await _set(winner, track, step)
        with SessionStatementRecorder(waiter) as recorder:
            task = world.start(waiter, _set(waiter, track, waiter_target))
            await assert_lock_wait(task, waiter=waiter, blocked_by=winner)
            assert len(recorder.statements) == 1
            assert _is_ticket_lock(recorder.statements[0])
            if winner_commits:
                await winner.commit()
            else:
                await winner.rollback()
            await asyncio.wait({task}, timeout=WAIT)
        assert task.done()
        return task, waiter, recorder.writes()

    async def test_equal_target_after_the_winner_is_a_no_op(
        self, committed_world: CommittedWorld
    ) -> None:
        track = await _committed_track(committed_world)

        task, _waiter, writes = await self._race(
            committed_world,
            track,
            winner_steps=(IN_PROGRESS,),
            waiter_target=IN_PROGRESS,
            winner_commits=True,
        )

        assert task.result() == DeliveryStatusResult(
            outcome=MutationOutcome.NO_OP,
            track_id=track.id,
            delivery_status=IN_PROGRESS,
        )
        assert writes == []
        assert await _committed(committed_world, track) == (IN_PROGRESS.value, 0)

    async def test_transition_is_validated_from_the_winner_value(
        self, committed_world: CommittedWorld
    ) -> None:
        """The waiter's stale copy is `PENDING`, from which `RELEASED` would
        be illegal; validated from the winner's committed `IN_PROGRESS`, it
        is the approved `IN_PROGRESS -> RELEASED`."""
        track = await _committed_track(committed_world)

        task, waiter, _writes = await self._race(
            committed_world,
            track,
            winner_steps=(IN_PROGRESS,),
            waiter_target=RELEASED,
            winner_commits=True,
        )
        result = task.result()
        await waiter.commit()

        assert (result.outcome, result.delivery_status) == (
            MutationOutcome.CHANGED,
            RELEASED,
        )
        assert await _committed(committed_world, track) == (RELEASED.value, 0)

    async def test_change_out_of_a_committed_release_is_rejected(
        self, committed_world: CommittedWorld
    ) -> None:
        """The waiter's stale copy is `IN_PROGRESS`, from which `PENDING`
        would be approved; the winner committed `IN_PROGRESS -> RELEASED`,
        so the waiter's regression is rejected with the winner's value as
        the current value and writes nothing (RELEASED is irreversible)."""
        track = await _committed_track(committed_world, IN_PROGRESS)

        task, _waiter, writes = await self._race(
            committed_world,
            track,
            winner_steps=(RELEASED,),
            waiter_target=PENDING,
            winner_commits=True,
        )

        error = task.exception()
        assert isinstance(error, InvalidDeliveryStatusTransition)
        assert (error.current, error.requested) == (RELEASED, PENDING)
        assert writes == []
        assert await _committed(committed_world, track) == (RELEASED.value, 0)

    async def test_waiter_after_a_rolled_back_holder_uses_the_committed_value(
        self, committed_world: CommittedWorld
    ) -> None:
        """The holder's uncommitted `IN_PROGRESS` is rolled back, so the
        waiter's `RELEASED` is validated from the committed `PENDING` and
        rejected as a direct `PENDING -> RELEASED`."""
        track = await _committed_track(committed_world)

        task, _waiter, writes = await self._race(
            committed_world,
            track,
            winner_steps=(IN_PROGRESS,),
            waiter_target=RELEASED,
            winner_commits=False,
        )

        error = task.exception()
        assert isinstance(error, InvalidDeliveryStatusTransition)
        assert (error.current, error.requested) == (PENDING, RELEASED)
        assert writes == []
        assert await _committed(committed_world, track) == (PENDING.value, 0)

    async def test_waiter_after_a_rolled_back_holder_changes_the_committed_value(
        self, committed_world: CommittedWorld
    ) -> None:
        track = await _committed_track(committed_world)

        task, waiter, _writes = await self._race(
            committed_world,
            track,
            winner_steps=(IN_PROGRESS,),
            waiter_target=IN_PROGRESS,
            winner_commits=False,
        )
        await waiter.commit()

        assert task.result().outcome is MutationOutcome.CHANGED
        assert await _committed(committed_world, track) == (IN_PROGRESS.value, 0)
