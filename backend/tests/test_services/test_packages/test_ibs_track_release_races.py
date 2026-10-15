"""Independent-session tests for the IBS track release reconciliation
boundary (backend/app/services/packages/ibs_track_release.py): races,
per-track failure conversion, the commit, the per-outcome hook, the
Ticket convergence drain, and consumer mode.

Owning specifications:

- docs/features/packages/ibs-track-release-detection.md (Shared
  Reconciliation Boundary: only known per-track failures become outcomes;
  `SoftTimeLimitExceeded`, `MemoryError`, and unexpected failures
  propagate; Per-Track Local Outcome: lock, reload, predecessor check,
  status re-evaluation, atomic status/event/reconciliation/checkpoint
  unit, stale `Ignored`/`Duplicated` no-op, completion after `Resolved`,
  failed changed scope, protected final-status race, rejected system
  target, flush and commit once, close, detach, and drain; commit
  exception or ambiguity terminates the invocation; broker-operational
  publication absorption; non-operational propagation without
  reclassification; Checkpoint Concurrency; Error Handling and its
  Structured Logs; Background Fetcher: Request Delay; Testing
  Requirements).
- docs/features/packages/package-service.md (`set_track_status()`
  Track-release composition; Concurrency Control; Excluded and
  Non-Actionable Records > Ticket-level operability; Architectural Test
  Requirement > Track release composition).
- docs/features/tickets/ticket-service.md (Ticket Convergence >
  Publication policies; Publication failure logging).
- docs/features/platform/testing-strategy.md (Ticket Convergence
  Publication Handoff: "IBS track and Product release detection";
  Concurrency Testing and Lock-Wait Observation; Audit Trail Testing).

Selection and the boundary body are covered by
`test_ibs_track_release.py`, whose module docstring describes the shared
setup: a `TrackWorld` with explicit teardown, `TrackUnitSessions`
replacing the boundary's `async_session_factory`, a
`task_publication.publish_task` recorder, and a real `IBSClient` over the
fake IBS API. A system `FIXED` registers a Ticket convergence effect by
itself only when it regresses a stale `Resolved` Ticket (reproduced by the
consumer-mode tests), so the drain tests wrap
`package_service.set_track_status()` to register one for its Ticket after
the real call. Concurrent changes are committed by an independent session
after every IBS request of the track's diff and before its local unit
(`before_local_unit()`), or by a holder of the Ticket lock.
"""

from __future__ import annotations

import asyncio
import re
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any, Final
from unittest.mock import AsyncMock

import pytest
from celery.exceptions import OperationalError as KombuOperationalError
from celery.exceptions import SoftTimeLimitExceeded
from sqlalchemy import delete, insert, select, update
from sqlalchemy.exc import OperationalError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from sqlalchemy.orm import Session
from structlog.testing import capture_logs

from app.core.enums import PackageStatus, TicketStatus, WorkflowType
from app.models.ticket import Ticket
from app.models.ticket_package import TicketPackage
from app.models.ticket_package_track import TicketPackageTrack
from app.models.track_release_checkpoint import TrackReleaseCheckpoint
from app.services import package_service, task_publication
from app.services.packages import ibs_track_release
from app.services.packages.ibs_track_release import (
    TrackReleaseCandidate,
    reconcile_ibs_track_releases,
)
from app.services.ticket_convergence_registry import register_ticket_convergence
from tests.support.database import assert_lock_wait
from tests.support.ibs_api import status_response, xml_response
from tests.support.ibs_keys import fictional_settings_value
from tests.support.ibs_product_release import Publish, published
from tests.support.ibs_track_release import (
    CHECKPOINT,
    CURRENT,
    FETCHER,
    NEWER,
    OTHER_CVE,
    OTHER_PROJECT,
    PACKAGE,
    PROJECT,
    SEEN_AT,
    SIBLING_PACKAGE,
    TRACK_FAILED,
    TRACK_STALE,
    WAIT,
    FakeIBS,
    Outcomes,
    Seed,
    Track,
    TrackUnitSessions,
    TrackWorld,
    before_local_unit,
    checkpoint_of,
    checkpoint_srcmd5,
    events_of,
    install_ibs,
    install_units,
    issue,
    kinds,
    logged,
    own,
    publication_failed,
    reconcile,
    register_after_fixed,
    ticket_status,
    track_failed,
    track_row,
    track_stale,
    track_status,
    unavailable,
)
from tests.support.suse_cvss_races import SessionStatementRecorder
from tests.support.ticket_mutations import EVAL, RELEASED_AT

pytestmark = pytest.mark.integration

Factory = Callable[[], Awaitable[AsyncSession]]

LATER: Final = datetime(2026, 6, 1, 12, 0, tzinfo=UTC)
"""When a concurrent handler accepted its checkpoint."""

SECRET: Final = "fictional-secret"
BROKER_FAILURE: Final = f"redis://sentinel:{SECRET}@broker.example.test:6379/1 down"
"""Fictional broker error text with credentials; never logged."""

TICKET_LOCK: Final = re.compile(r"\bFROM ticket\b.*FOR UPDATE", re.DOTALL)


@pytest.fixture(autouse=True)
def clock(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(package_service, "_utc_today", lambda: EVAL)


@pytest.fixture(autouse=True)
def publication(monkeypatch: pytest.MonkeyPatch) -> Publish:
    recorder = Publish()
    monkeypatch.setattr(task_publication, "publish_task", recorder)
    return recorder


@pytest.fixture(autouse=True)
def units(
    real_session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> TrackUnitSessions:
    return install_units(monkeypatch, real_session_factory)


@pytest.fixture(autouse=True)
def ibs(monkeypatch: pytest.MonkeyPatch) -> FakeIBS:
    return install_ibs(monkeypatch)


@pytest.fixture
async def world(db_session_factory: Factory) -> AsyncIterator[TrackWorld]:
    created = TrackWorld(db_session_factory, await db_session_factory())
    try:
        yield created
    finally:
        await created.cleanup()


async def _seeded(
    world: TrackWorld,
    count: int = 1,
    status: TicketStatus = TicketStatus.ANALYSIS,
    **kwargs: Any,
) -> list[Track]:
    """`count` committed tracks, each below its own Ticket (in `status`),
    in track-ID order."""
    seed = Seed(world.session, world)
    created = []
    for _ in range(count):
        created.append(await seed.track(await seed.ticket(status), **kwargs))
    await seed.commit()
    return sorted(created, key=lambda track: track.id)


def _by_track(entry: Any) -> str:
    return str(entry["track_id"])


def _cve(track: Track) -> str:
    assert track.cve_id is not None
    return track.cve_id


def _evidence(ibs: FakeIBS, *tracks: Track, baseline: str = "0") -> None:
    """Source info `CURRENT` for each track's package and one diff per
    package from `baseline` naming every given track's CVE."""
    packages: dict[tuple[str, str], list[str]] = {}
    for track in tracks:
        packages.setdefault((track.project, track.package_name), []).append(_cve(track))
    for (project, package), cves in packages.items():
        ibs.source(project, package, CURRENT)
        ibs.issues(project, package, baseline, CURRENT, *(issue(cve) for cve in cves))


async def _commit(world: TrackWorld, *statements: Any) -> None:
    """Commit `statements` through a fresh independent session."""
    session = await world.open_session()
    for statement in statements:
        await session.execute(statement)
    await session.commit()


def _concurrently(
    monkeypatch: pytest.MonkeyPatch, world: TrackWorld, *statements: Any
) -> None:
    """Commit `statements` once, before the first local unit's lock."""
    done = False

    async def action(_: TrackReleaseCandidate) -> None:
        nonlocal done
        if not done:
            done = True
            await _commit(world, *statements)

    before_local_unit(monkeypatch, action)


def _failing_for(
    monkeypatch: pytest.MonkeyPatch,
    track: Track,
    error: BaseException,
) -> None:
    """Make `set_track_status()` raise `error` for `track` after the real
    call flushed its status, event, and reconciliation."""
    original = package_service.set_track_status

    async def failing(db: AsyncSession, **kwargs: Any) -> Any:
        result = await original(db, **kwargs)
        if kwargs["track_id"] == track.id:
            raise error
        return result

    monkeypatch.setattr(package_service, "set_track_status", failing)


async def _releasable(world: TrackWorld, package_name: str = PACKAGE) -> Track:
    """The last open (`AFFECTED`) track of an `Analyzed` Ticket whose only
    actionable eligible Product is released: a committed `FIXED` resolves
    the Ticket (tickets.md, Gate: Analyzed -> Resolved)."""
    seed = Seed(world.session, world)
    ticket = await seed.ticket(TicketStatus.ANALYZED, assessed=True)
    track = await seed.track(
        ticket, package_name=package_name, status=PackageStatus.AFFECTED
    )
    await seed.product(track, released_at=RELEASED_AT)
    await seed.commit()
    return track


# ---------------------------------------------------------------------------
# Ticket races (Per-Track Local Outcome)
# ---------------------------------------------------------------------------


class TestTicketRaces:
    @pytest.mark.parametrize("evidence", [True, False], ids=["evidence", "no-match"])
    @pytest.mark.parametrize(
        "status", [TicketStatus.IGNORED, TicketStatus.DUPLICATED], ids=str
    )
    async def test_ticket_leaving_the_operable_states_is_a_stale_no_op(
        self,
        world: TrackWorld,
        ibs: FakeIBS,
        monkeypatch: pytest.MonkeyPatch,
        status: TicketStatus,
        evidence: bool,
    ) -> None:
        (track,) = await _seeded(world, checkpoint=CHECKPOINT)
        seed = Seed(world.session, world)
        canonical = await seed.ticket(TicketStatus.ANALYSIS, with_cve=False)
        await seed.commit()
        values: dict[str, Any] = {"status": status.value}
        if status is TicketStatus.DUPLICATED:
            values["duplicate_of_id"] = canonical.id
        ibs.source(PROJECT, PACKAGE, CURRENT)
        ibs.issues(
            PROJECT,
            PACKAGE,
            CHECKPOINT,
            CURRENT,
            issue(_cve(track) if evidence else OTHER_CVE),
        )
        _concurrently(
            monkeypatch,
            world,
            update(Ticket).where(Ticket.id == track.ticket_id).values(**values),
        )
        before = await track_row(world, track)
        hook = Outcomes()

        with capture_logs() as logs:
            outcomes = await reconcile(ibs, [track.candidate()], hook)

        assert kinds(outcomes) == {track.id: "no_op"}
        assert hook.kinds == {track.id: "no_op"}
        assert own(logs) == [track_stale(track)]
        assert await checkpoint_of(world, track) == (CHECKPOINT, SEEN_AT)
        assert await track_row(world, track) == before
        assert await events_of(world, track.ticket_id) == []
        assert await ticket_status(world, track.ticket_id) == status.value

    async def test_in_flight_track_completes_after_resolution(
        self,
        world: TrackWorld,
        ibs: FakeIBS,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Selected while `Analyzed`; the Ticket is `Resolved` before the
        lock: the factual `FIXED` still completes with its one event, and
        the gate keeps the Ticket `Resolved`."""
        track = await _releasable(world)
        _evidence(ibs, track)
        _concurrently(
            monkeypatch,
            world,
            update(Ticket)
            .where(Ticket.id == track.ticket_id)
            .values(status=TicketStatus.RESOLVED.value),
        )

        with capture_logs() as logs:
            outcomes = await reconcile(ibs, [track.candidate()])

        assert kinds(outcomes) == {track.id: "updated"}
        assert logged(logs, TRACK_STALE) == []
        assert await events_of(world, track.ticket_id) == [
            track.fixed_event(PackageStatus.AFFECTED)
        ]
        assert await ticket_status(world, track.ticket_id) == (
            TicketStatus.RESOLVED.value
        )
        assert await checkpoint_srcmd5(world, track) == CURRENT


class TestFinalStatusRace:
    @pytest.mark.parametrize(
        "final",
        [PackageStatus.NOT_AFFECTED, PackageStatus.FIXED, PackageStatus.WONT_FIX],
        ids=str,
    )
    async def test_status_becoming_final_during_io_is_a_protected_no_op(
        self,
        world: TrackWorld,
        ibs: FakeIBS,
        monkeypatch: pytest.MonkeyPatch,
        final: PackageStatus,
    ) -> None:
        """Status and timestamp stay as the concurrent decision left them;
        the examined checkpoint is accepted; no event."""
        (track,) = await _seeded(world, checkpoint=CHECKPOINT)
        _evidence(ibs, track, baseline=CHECKPOINT)
        after_decision: list[Any] = []

        async def decide(_: TrackReleaseCandidate) -> None:
            if not after_decision:
                await _commit(
                    world,
                    update(TicketPackageTrack)
                    .where(TicketPackageTrack.id == track.id)
                    .values(status=final.value),
                )
                after_decision.append(await track_row(world, track))

        before_local_unit(monkeypatch, decide)

        with capture_logs() as logs:
            outcomes = await reconcile(ibs, [track.candidate()])

        assert kinds(outcomes) == {track.id: "no_op"}
        assert own(logs) == []
        assert await track_row(world, track) == after_decision[0]
        assert await track_status(world, track) == final.value
        accepted = await checkpoint_of(world, track)
        assert accepted is not None
        assert accepted[0] == CURRENT
        assert accepted[1] > SEEN_AT
        assert await events_of(world, track.ticket_id) == []


SCOPE_CHANGES = [
    "cve-removed",
    "cve-replaced",
    "reference-changed",
    "workflow-git",
    "moved-to-other-package",
    "moved-to-other-ticket",
    "package-renamed",
    "track-hard-deleted",
    "ticket-deleted",
]


class TestScopeChanged:
    @pytest.mark.parametrize("change", SCOPE_CHANGES)
    async def test_changed_scope_fails_without_advancing(
        self,
        world: TrackWorld,
        ibs: FakeIBS,
        monkeypatch: pytest.MonkeyPatch,
        change: str,
    ) -> None:
        seed = Seed(world.session, world)
        ticket = await seed.ticket()
        track = await seed.track(ticket)
        other_cve = await seed.cve()
        # Other references: (package, reference) identifies a track.
        other_package = await seed.track(
            ticket, package_name=SIBLING_PACKAGE, project=OTHER_PROJECT
        )
        other_ticket_track = await seed.track(
            await seed.ticket(), package_name="example-other", project=OTHER_PROJECT
        )
        await seed.commit()
        _evidence(ibs, track)
        statements: dict[str, list[Any]] = {
            "cve-removed": [
                update(Ticket).where(Ticket.id == ticket.id).values(cve_id=None)
            ],
            "cve-replaced": [
                update(Ticket).where(Ticket.id == ticket.id).values(cve_id=other_cve.id)
            ],
            "reference-changed": [
                update(TicketPackageTrack)
                .where(TicketPackageTrack.id == track.id)
                .values(reference=OTHER_PROJECT)
            ],
            "workflow-git": [
                update(TicketPackageTrack)
                .where(TicketPackageTrack.id == track.id)
                .values(workflow_type=WorkflowType.GIT.value)
            ],
            "moved-to-other-package": [
                update(TicketPackageTrack)
                .where(TicketPackageTrack.id == track.id)
                .values(ticket_package_id=other_package.package_id)
            ],
            "moved-to-other-ticket": [
                update(TicketPackageTrack)
                .where(TicketPackageTrack.id == track.id)
                .values(ticket_package_id=other_ticket_track.package_id)
            ],
            "package-renamed": [
                update(TicketPackage)
                .where(TicketPackage.id == track.package_id)
                .values(package_name="example-renamed")
            ],
            "track-hard-deleted": [
                delete(TicketPackageTrack).where(TicketPackageTrack.id == track.id)
            ],
            "ticket-deleted": [
                delete(TicketPackageTrack).where(
                    TicketPackageTrack.id.in_([track.id, other_package.id])
                ),
                delete(TicketPackage).where(TicketPackage.ticket_id == ticket.id),
                delete(Ticket).where(Ticket.id == ticket.id),
            ],
        }
        _concurrently(monkeypatch, world, *statements[change])
        hook = Outcomes()

        with capture_logs() as logs:
            outcomes = await reconcile(ibs, [track.candidate()], hook)

        assert kinds(outcomes) == {track.id: "failed"}
        assert hook.kinds == {track.id: "failed"}
        assert own(logs) == [track_failed(track, "scope_changed")]
        assert await checkpoint_of(world, track) is None
        assert await events_of(world, ticket.id) == []
        assert await track_status(world, track) in (
            None,
            PackageStatus.ANALYSIS.value,
        )


# ---------------------------------------------------------------------------
# Checkpoint Concurrency
# ---------------------------------------------------------------------------


def _accept(track: Track, srcmd5: str) -> Any:
    """The statement a concurrent handler committed to accept `srcmd5`."""
    if track.checkpoint is None:
        return insert(TrackReleaseCheckpoint).values(
            ticket_package_track_id=track.id, srcmd5=srcmd5, last_seen_at=LATER
        )
    return (
        update(TrackReleaseCheckpoint)
        .where(TrackReleaseCheckpoint.ticket_package_track_id == track.id)
        .values(srcmd5=srcmd5, last_seen_at=LATER)
    )


class TestCheckpointConcurrency:
    @pytest.mark.parametrize(
        "baseline", [None, CHECKPOINT], ids=["first", "checkpoint"]
    )
    async def test_predecessor_advanced_to_the_examined_state_is_already_complete(
        self,
        world: TrackWorld,
        ibs: FakeIBS,
        units: TrackUnitSessions,
        monkeypatch: pytest.MonkeyPatch,
        baseline: str | None,
    ) -> None:
        """Another handler accepted the same `srcmd5`: a no-op whose unit
        writes nothing, so the winner's checkpoint and status stand."""
        (track,) = await _seeded(world, checkpoint=baseline)
        _evidence(ibs, track, baseline=baseline or "0")
        _concurrently(monkeypatch, world, _accept(track, CURRENT))
        unit = await world.open_session()
        units.queued.append(unit)

        with SessionStatementRecorder(unit) as recorder, capture_logs() as logs:
            outcomes = await reconcile(ibs, [track.candidate()])

        assert kinds(outcomes) == {track.id: "no_op"}
        assert recorder.writes() == []
        assert own(logs) == []
        assert await checkpoint_of(world, track) == (CURRENT, LATER)
        assert await track_status(world, track) == PackageStatus.ANALYSIS.value
        assert await events_of(world, track.ticket_id) == []

    @pytest.mark.parametrize(
        "baseline", [None, CHECKPOINT], ids=["first", "checkpoint"]
    )
    async def test_predecessor_changed_to_another_state_fails_without_overwrite(
        self,
        world: TrackWorld,
        ibs: FakeIBS,
        units: TrackUnitSessions,
        monkeypatch: pytest.MonkeyPatch,
        baseline: str | None,
    ) -> None:
        (track,) = await _seeded(world, checkpoint=baseline)
        _evidence(ibs, track, baseline=baseline or "0")
        _concurrently(monkeypatch, world, _accept(track, NEWER))
        unit = await world.open_session()
        units.queued.append(unit)

        with SessionStatementRecorder(unit) as recorder, capture_logs() as logs:
            outcomes = await reconcile(ibs, [track.candidate()])

        assert kinds(outcomes) == {track.id: "failed"}
        assert recorder.writes() == []
        assert own(logs) == [track_failed(track, "stale_checkpoint")]
        assert await checkpoint_of(world, track) == (NEWER, LATER)
        assert await track_status(world, track) == PackageStatus.ANALYSIS.value
        assert await events_of(world, track.ticket_id) == []

    async def test_concurrent_invocations_transition_once_and_never_regress(
        self,
        world: TrackWorld,
        ibs: FakeIBS,
        units: TrackUnitSessions,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Two full invocations of the same selection: the first holds the
        Ticket lock with its transition flushed; the second's unit is
        proven waiting on it, then observes the accepted state as an
        already-complete no-op. Exactly one transition and one event."""
        (track,) = await _seeded(world)
        _evidence(ibs, track)
        holder = await world.open_session()
        waiter = await world.open_session()
        units.queued.extend([holder, waiter])
        original = package_service.set_track_status
        paused = asyncio.Event()
        release = asyncio.Event()

        async def pausing(db: AsyncSession, **kwargs: Any) -> Any:
            result = await original(db, **kwargs)
            if db is holder:
                paused.set()
                await release.wait()
            return result

        monkeypatch.setattr(package_service, "set_track_status", pausing)
        first_hook = Outcomes()
        second_hook = Outcomes()

        async def invoke(hook: Outcomes) -> Any:
            async with ibs.client() as client:
                return await reconcile_ibs_track_releases(
                    [track.candidate()],
                    client=client,
                    fetcher_name=FETCHER,
                    on_outcome=hook,
                )

        first = world.start(holder, invoke(first_hook))
        await asyncio.wait_for(paused.wait(), timeout=WAIT)
        with SessionStatementRecorder(waiter) as recorder:
            second = world.start(waiter, invoke(second_hook))
            await assert_lock_wait(second, waiter=waiter, blocked_by=holder)
            assert len(recorder.statements) == 1
            assert TICKET_LOCK.search(recorder.statements[0])
            release.set()
            first_result = await asyncio.wait_for(first, timeout=WAIT)
            second_result = await asyncio.wait_for(second, timeout=WAIT)

        assert kinds(first_result) == {track.id: "updated"}
        assert kinds(second_result) == {track.id: "no_op"}
        assert first_hook.kinds == {track.id: "updated"}
        assert second_hook.kinds == {track.id: "no_op"}
        assert recorder.writes() == []
        assert units.sessions == [holder, waiter]
        assert await events_of(world, track.ticket_id) == [track.fixed_event()]
        assert await track_status(world, track) == PackageStatus.FIXED.value
        assert await checkpoint_srcmd5(world, track) == CURRENT


# ---------------------------------------------------------------------------
# Failure conversion (Shared Reconciliation Boundary)
# ---------------------------------------------------------------------------


class TestFailureConversion:
    async def test_rejected_system_target_fails_and_keeps_the_checkpoint(
        self,
        world: TrackWorld,
        ibs: FakeIBS,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The package service's real `rejected` result (here forced by
        substituting a non-`FIXED` target) is a local workflow failure."""
        (track,) = await _seeded(world, checkpoint=CHECKPOINT)
        _evidence(ibs, track, baseline=CHECKPOINT)
        original = package_service.set_track_status
        results: list[package_service.MutationOutcome] = []

        async def prohibited(db: AsyncSession, **kwargs: Any) -> Any:
            kwargs["status"] = PackageStatus.NOT_AFFECTED
            result = await original(db, **kwargs)
            results.append(result.outcome)
            return result

        monkeypatch.setattr(package_service, "set_track_status", prohibited)
        before = await track_row(world, track)

        with capture_logs() as logs:
            outcomes = await reconcile(ibs, [track.candidate()])

        assert results == [package_service.MutationOutcome.REJECTED]
        assert kinds(outcomes) == {track.id: "failed"}
        assert own(logs) == [track_failed(track, "system_target_rejected")]
        assert await checkpoint_of(world, track) == (CHECKPOINT, SEEN_AT)
        assert await track_row(world, track) == before
        assert await events_of(world, track.ticket_id) == []

    @pytest.mark.parametrize("failure", ["audit-or-reconciliation", "checkpoint-flush"])
    async def test_database_error_rolls_back_the_complete_unit_only(
        self,
        world: TrackWorld,
        ibs: FakeIBS,
        units: TrackUnitSessions,
        monkeypatch: pytest.MonkeyPatch,
        failure: str,
    ) -> None:
        """The failing unit's status, event, Ticket reconciliation
        (`Analyzed` -> `Resolved`), and checkpoint roll back together; it
        is `failed` with one bounded `database` warning; the sibling unit
        stays committed."""
        (sibling,) = await _seeded(world)
        failing = await _releasable(world, package_name=SIBLING_PACKAGE)
        _evidence(ibs, sibling, failing)
        error = OperationalError("INSERT", None, Exception(SECRET))
        if failure == "audit-or-reconciliation":
            _failing_for(monkeypatch, failing, error)
        else:

            def before_flush(session: Session) -> None:
                if any(
                    isinstance(item, TrackReleaseCheckpoint)
                    and item.ticket_package_track_id == failing.id
                    for item in (*session.new, *session.dirty)
                ):
                    raise error

            units.before_flush = before_flush
        hook = Outcomes()

        with capture_logs() as logs:
            outcomes = await reconcile(
                ibs, [sibling.candidate(), failing.candidate()], hook
            )

        assert kinds(outcomes) == {sibling.id: "updated", failing.id: "failed"}
        assert hook.kinds == kinds(outcomes)
        assert own(logs) == [track_failed(failing, "database")]
        assert SECRET not in repr(logs)
        assert await track_status(world, failing) == PackageStatus.AFFECTED.value
        assert await events_of(world, failing.ticket_id) == []
        assert await ticket_status(world, failing.ticket_id) == (
            TicketStatus.ANALYZED.value
        )
        assert await checkpoint_of(world, failing) is None
        assert await events_of(world, sibling.ticket_id) == [sibling.fixed_event()]
        assert await checkpoint_srcmd5(world, sibling) == CURRENT
        assert units.closed == units.sessions

    @pytest.mark.parametrize(
        "make_error",
        [
            pytest.param(lambda: RuntimeError("fictional bug"), id="unexpected"),
            pytest.param(SoftTimeLimitExceeded, id="soft-time-limit"),
            pytest.param(MemoryError, id="memory-error"),
        ],
    )
    async def test_non_database_exception_in_a_unit_propagates(
        self,
        world: TrackWorld,
        ibs: FakeIBS,
        units: TrackUnitSessions,
        monkeypatch: pytest.MonkeyPatch,
        make_error: Callable[[], BaseException],
    ) -> None:
        """No per-track outcome: the exception terminates the invocation
        after the failing unit rolled back; the earlier commit stays and
        the later track is never processed."""
        seed = Seed(world.session, world)
        first = await seed.track(await seed.ticket())
        second = await seed.track(await seed.ticket(), package_name=SIBLING_PACKAGE)
        third = await seed.track(await seed.ticket(), package_name="example-zz")
        await seed.commit()
        _evidence(ibs, first, second, third)
        error = make_error()
        _failing_for(monkeypatch, second, error)
        hook = Outcomes()

        with capture_logs() as logs, pytest.raises(type(error)) as raised:
            await reconcile(
                ibs, [first.candidate(), second.candidate(), third.candidate()], hook
            )

        assert raised.value is error
        assert hook.kinds == {first.id: "updated"}
        assert len(units.sessions) == 2
        assert units.closed == units.sessions
        assert logged(logs, TRACK_FAILED) == []
        assert await events_of(world, first.ticket_id) == [first.fixed_event()]
        for untouched in (second, third):
            assert await track_status(world, untouched) == PackageStatus.ANALYSIS.value
            assert await checkpoint_of(world, untouched) is None
            assert await events_of(world, untouched.ticket_id) == []


# ---------------------------------------------------------------------------
# Commit, hook, and Ticket convergence drain
# ---------------------------------------------------------------------------


async def _three(world: TrackWorld, ibs: FakeIBS) -> tuple[Track, Track, Track]:
    """Three evidence tracks of three Tickets, examined in this order
    (one diff per package, packages in name order)."""
    seed = Seed(world.session, world)
    first = await seed.track(await seed.ticket())
    second = await seed.track(await seed.ticket(), package_name=SIBLING_PACKAGE)
    third = await seed.track(await seed.ticket(), package_name="example-zz")
    await seed.commit()
    _evidence(ibs, first, second, third)
    return first, second, third


class TestCommit:
    async def test_every_unit_is_flushed_before_its_commit(
        self, world: TrackWorld, ibs: FakeIBS, units: TrackUnitSessions
    ) -> None:
        """At the start of each commit (before its own flush) the unit has
        no pending insert, update, or delete: the transition, its event,
        the reconciliation, and the checkpoint (created or advanced) were
        flushed."""
        (fixed,) = await _seeded(world)
        (advanced,) = await _seeded(
            world, package_name=SIBLING_PACKAGE, checkpoint=CHECKPOINT
        )
        _evidence(ibs, fixed)
        ibs.source(PROJECT, SIBLING_PACKAGE, CURRENT)
        ibs.issues(PROJECT, SIBLING_PACKAGE, CHECKPOINT, CURRENT, issue(OTHER_CVE))
        pending: list[tuple[int, int, int]] = []

        def before_commit(session: Session) -> None:
            pending.append((len(session.new), len(session.dirty), len(session.deleted)))

        units.before_commit = before_commit

        outcomes = await reconcile(ibs, [fixed.candidate(), advanced.candidate()])

        assert kinds(outcomes) == {fixed.id: "updated", advanced.id: "no_op"}
        assert pending == [(0, 0, 0), (0, 0, 0)]

    @pytest.mark.parametrize("ambiguous", [False, True], ids=["failed", "ambiguous"])
    async def test_commit_exception_terminates_the_invocation(
        self,
        world: TrackWorld,
        ibs: FakeIBS,
        units: TrackUnitSessions,
        publication: Publish,
        monkeypatch: pytest.MonkeyPatch,
        ambiguous: bool,
    ) -> None:
        """The second unit registered a convergence effect, then its commit
        raises (definitely failed, or after the database committed): the
        exception propagates, the hook never receives that track, its
        effect is never published, no failure is logged, the earlier
        committed track stays committed, and the third is not processed."""
        first, second, third = await _three(world, ibs)
        registered = register_after_fixed(monkeypatch)
        error = OperationalError("COMMIT", None, Exception("fictional reset"))
        if ambiguous:
            units.after_commit_error = (1, error)
        else:
            units.failing_commit = (1, error)
        hook = Outcomes()

        with capture_logs() as logs, pytest.raises(OperationalError) as raised:
            await reconcile(
                ibs, [first.candidate(), second.candidate(), third.candidate()], hook
            )

        assert raised.value is error
        assert registered == [first.ticket_id, second.ticket_id]
        assert hook.kinds == {first.id: "updated"}
        assert published(publication.calls) == [first.ticket_id]
        assert len(units.sessions) == 2
        assert units.closed == units.sessions
        assert logged(logs, TRACK_FAILED) == []
        assert await events_of(world, first.ticket_id) == [first.fixed_event()]
        if ambiguous:
            # The database outcome is the committed one; the boundary
            # cannot know it and must not report or publish it.
            assert await track_status(world, second) == PackageStatus.FIXED.value
            assert await events_of(world, second.ticket_id) == [second.fixed_event()]
        else:
            assert await track_status(world, second) == PackageStatus.ANALYSIS.value
            assert await events_of(world, second.ticket_id) == []
            assert await checkpoint_of(world, second) is None
        assert await track_status(world, third) == PackageStatus.ANALYSIS.value
        assert await checkpoint_of(world, third) is None


class TestHook:
    async def test_hook_receives_every_terminal_outcome_exactly_once(
        self,
        world: TrackWorld,
        ibs: FakeIBS,
        units: TrackUnitSessions,
    ) -> None:
        """Outcomes without a session (unchanged source, unusable package,
        failed request, invalid identity) are delivered immediately; a
        committed one after its commit and before its session closes; a
        rolled back one after its rollback."""
        seed = Seed(world.session, world)
        unchanged = await seed.track(
            await seed.ticket(), package_name="example-a", checkpoint=CURRENT
        )
        missing = await seed.track(await seed.ticket(), package_name="example-b")
        request_failed = await seed.track(await seed.ticket(), project=OTHER_PROJECT)
        invalid = await seed.track(
            await seed.ticket(), package_name="example-c", checkpoint="bad"
        )
        fixed = await seed.track(await seed.ticket(), package_name="example-d")
        no_match = await seed.track(await seed.ticket(), package_name="example-e")
        await seed.commit()
        ibs.source(PROJECT, "example-a", CURRENT)
        ibs.entries(PROJECT, "example-b")
        ibs.fail_source(OTHER_PROJECT, status_response(503))
        _evidence(ibs, fixed)
        ibs.source(PROJECT, "example-e", CURRENT)
        ibs.issues(PROJECT, "example-e", "0", CURRENT, issue(OTHER_CVE))
        events: list[str] = []
        units.events = events
        hook = Outcomes(events=events)
        tracks = [unchanged, missing, request_failed, invalid, fixed, no_match]

        outcomes = await reconcile(ibs, [t.candidate() for t in tracks], hook)

        expected = {
            unchanged.id: "no_op",
            missing.id: "failed",
            request_failed.id: "failed",
            invalid.id: "failed",
            fixed.id: "updated",
            no_match.id: "no_op",
        }
        assert kinds(outcomes) == expected
        assert len(hook.received) == len(tracks)
        assert hook.kinds == expected
        # Outcomes without a session come first (algorithm steps 1-4), each
        # once; the spec fixes no order among them.
        assert sorted(events[:4]) == sorted(
            ["hook:failed", "hook:failed", "hook:failed", "hook:no_op"]
        )
        assert events[4:] == [
            "unit",
            "commit",
            "hook:updated",
            "close",
            "unit",
            "commit",
            "hook:no_op",
            "close",
        ]


class TestDrain:
    @pytest.mark.parametrize(
        "make_error",
        [
            pytest.param(None, id="submitted"),
            pytest.param(
                lambda: KombuOperationalError(BROKER_FAILURE),
                id="acceptance-unconfirmed",
            ),
        ],
    )
    async def test_drain_follows_commit_hook_and_close_per_track(
        self,
        world: TrackWorld,
        ibs: FakeIBS,
        units: TrackUnitSessions,
        publication: Publish,
        monkeypatch: pytest.MonkeyPatch,
        make_error: Callable[[], BaseException] | None,
    ) -> None:
        """Per track: commit, the hook, the close, then exactly one root
        publication for its Ticket, before the next diff and unit. Inside
        the attempt the unit session is closed and an independent `NOWAIT`
        Ticket lock reads the committed transition. A broker operational
        error adds exactly one sanitized ERROR per effect, is absorbed,
        and leaves the outcomes unchanged."""
        first, second, _ = await _three(world, ibs)
        register_after_fixed(monkeypatch)
        events: list[str] = []
        units.events = events
        ibs.events = events
        hook = Outcomes(events=events)
        observed: list[tuple[bool, str]] = []

        async def observe(call: dict[str, Any]) -> None:
            events.append("publish")
            ticket_id = uuid.UUID(call["kwargs"]["ticket_id"])
            probe = await world.probe()
            await probe.execute(
                select(Ticket.id)
                .where(Ticket.id == ticket_id)
                .with_for_update(nowait=True)
            )
            value = (
                await probe.execute(
                    select(TicketPackageTrack.status)
                    .join(
                        TicketPackage,
                        TicketPackage.id == TicketPackageTrack.ticket_package_id,
                    )
                    .where(TicketPackage.ticket_id == ticket_id)
                )
            ).scalar_one()
            await probe.rollback()
            observed.append((units.sessions[-1] in units.closed, value))

        publication.on_call = observe
        publication.error = None if make_error is None else make_error()

        with capture_logs() as logs:
            outcomes = await reconcile(
                ibs, [first.candidate(), second.candidate()], hook
            )

        assert kinds(outcomes) == {first.id: "updated", second.id: "updated"}
        assert published(publication.calls) == [first.ticket_id, second.ticket_id]
        assert observed == [(True, PackageStatus.FIXED.value)] * 2
        assert events == [
            "http:source",
            *["http:diff", "unit", "commit", "hook:updated", "close", "publish"] * 2,
        ]
        expected = (
            []
            if make_error is None
            else [
                publication_failed(first.ticket_id),
                publication_failed(second.ticket_id),
            ]
        )
        assert [e for e in logs if e["log_level"] == "error"] == expected
        assert logged(logs, TRACK_FAILED) == []
        assert SECRET not in repr(logs)
        assert "broker.example.test" not in repr(logs)

    @pytest.mark.parametrize(
        "make_error",
        [
            pytest.param(lambda: RuntimeError("fictional bug"), id="programming-error"),
            pytest.param(SoftTimeLimitExceeded, id="soft-time-limit"),
            pytest.param(asyncio.CancelledError, id="cancelled"),
        ],
    )
    async def test_non_operational_publication_exception_propagates(
        self,
        world: TrackWorld,
        ibs: FakeIBS,
        units: TrackUnitSessions,
        publication: Publish,
        monkeypatch: pytest.MonkeyPatch,
        make_error: Callable[[], BaseException],
    ) -> None:
        """After the first commit: no rollback, no reclassification (the
        hook saw exactly one `updated`), no failure or publication-failure
        event, and the next track is not processed."""
        first, second, _ = await _three(world, ibs)
        register_after_fixed(monkeypatch)
        error = make_error()
        publication.error = error
        hook = Outcomes()

        with capture_logs() as logs, pytest.raises(type(error)) as raised:
            await reconcile(ibs, [first.candidate(), second.candidate()], hook)

        assert raised.value is error
        assert hook.kinds == {first.id: "updated"}
        assert published(publication.calls) == [first.ticket_id]
        assert len(units.sessions) == 1
        assert logged(logs, TRACK_FAILED) == []
        assert [e for e in logs if e["log_level"] == "error"] == []
        assert await events_of(world, first.ticket_id) == [first.fixed_event()]
        assert await checkpoint_srcmd5(world, first) == CURRENT
        assert await track_status(world, second) == PackageStatus.ANALYSIS.value
        assert await checkpoint_of(world, second) is None

    async def test_rolled_back_unit_publishes_nothing(
        self,
        world: TrackWorld,
        ibs: FakeIBS,
        publication: Publish,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Both units registered an effect; the first then fails with a
        database error and rolls back: only the committed second Ticket is
        published."""
        first, second, _ = await _three(world, ibs)
        registered = register_after_fixed(monkeypatch)
        _failing_for(monkeypatch, first, OperationalError("UPDATE", None, Exception()))

        outcomes = await reconcile(ibs, [first.candidate(), second.candidate()])

        assert kinds(outcomes) == {first.id: "failed", second.id: "updated"}
        assert registered == [first.ticket_id, second.ticket_id]
        assert published(publication.calls) == [second.ticket_id]


# ---------------------------------------------------------------------------
# No IBS I/O under the Ticket lock; independent siblings
# ---------------------------------------------------------------------------


class TestNoIBSRequestUnderTheTicketLock:
    async def test_every_request_happens_outside_every_unit(
        self, world: TrackWorld, ibs: FakeIBS, units: TrackUnitSessions
    ) -> None:
        """Several projects, packages, and diffs, including an unavailable
        history fallback and a failed diff: no IBS request is made between
        a unit's opening (before its Ticket lock) and its close; each diff
        is followed by the units of its tracks."""
        seed = Seed(world.session, world)
        first = await seed.track(await seed.ticket())
        fallback = await seed.track(await seed.ticket(), checkpoint=CHECKPOINT)
        incremental = await seed.track(
            await seed.ticket(), package_name=SIBLING_PACKAGE, checkpoint=CHECKPOINT
        )
        other = await seed.track(await seed.ticket(), project=OTHER_PROJECT)
        broken = await seed.track(await seed.ticket(), package_name="example-zz")
        await seed.commit()
        ibs.source(PROJECT, PACKAGE, CURRENT)
        ibs.source(PROJECT, SIBLING_PACKAGE, CURRENT)
        ibs.source(PROJECT, "example-zz", CURRENT)
        ibs.source(OTHER_PROJECT, PACKAGE, CURRENT)
        ibs.diff(
            PROJECT,
            PACKAGE,
            CHECKPOINT,
            CURRENT,
            unavailable(PROJECT, PACKAGE, CHECKPOINT),
        )
        ibs.issues(
            PROJECT, PACKAGE, "0", CURRENT, issue(_cve(first)), issue(_cve(fallback))
        )
        ibs.issues(
            PROJECT, SIBLING_PACKAGE, CHECKPOINT, CURRENT, issue(_cve(incremental))
        )
        ibs.issues(OTHER_PROJECT, PACKAGE, "0", CURRENT, issue(OTHER_CVE))
        ibs.diff(PROJECT, "example-zz", "0", CURRENT, xml_response(b"<sourcediff"))
        events: list[str] = []
        units.events = events
        ibs.events = events
        tracks = [first, fallback, incremental, other, broken]

        outcomes = await reconcile(ibs, [t.candidate() for t in tracks])

        assert kinds(outcomes) == {
            first.id: "updated",
            fallback.id: "updated",
            incremental.id: "updated",
            other.id: "no_op",
            broken.id: "failed",
        }
        inside = False
        for entry in events:
            if entry == "unit":
                assert not inside
                inside = True
            elif entry == "close":
                assert inside
                inside = False
            elif entry.startswith("http:"):
                assert not inside, events
        assert not inside
        assert events.count("unit") == 4
        assert events.count("close") == 4
        assert events[0] == "http:source"


# ---------------------------------------------------------------------------
# Request delay (Background Fetcher: Request Delay)
# ---------------------------------------------------------------------------


class TestRequestDelay:
    async def test_delay_precedes_every_later_request_and_no_unit(
        self,
        world: TrackWorld,
        ibs: FakeIBS,
        units: TrackUnitSessions,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Two projects, an unavailable-history fallback, and a failed diff:
        no wait before the first IBS request, the delay immediately before
        every later source-info and diff request (the `orev=0` fallback
        included), and never while a unit is open."""
        seed = Seed(world.session, world)
        first = await seed.track(await seed.ticket())
        fallback = await seed.track(await seed.ticket(), checkpoint=CHECKPOINT)
        other = await seed.track(await seed.ticket(), project=OTHER_PROJECT)
        broken = await seed.track(await seed.ticket(), package_name="example-zz")
        await seed.commit()
        ibs.source(PROJECT, PACKAGE, CURRENT)
        ibs.source(PROJECT, "example-zz", CURRENT)
        ibs.source(OTHER_PROJECT, PACKAGE, CURRENT)
        ibs.diff(
            PROJECT,
            PACKAGE,
            CHECKPOINT,
            CURRENT,
            unavailable(PROJECT, PACKAGE, CHECKPOINT),
        )
        ibs.issues(
            PROJECT, PACKAGE, "0", CURRENT, issue(_cve(first)), issue(_cve(fallback))
        )
        ibs.issues(OTHER_PROJECT, PACKAGE, "0", CURRENT, issue(OTHER_CVE))
        ibs.diff(PROJECT, "example-zz", "0", CURRENT, xml_response(b"<sourcediff"))
        events: list[str] = []
        delays: list[float] = []
        units.events = events
        ibs.events = events

        async def sleep(delay: float) -> None:
            delays.append(delay)
            events.append("sleep")

        monkeypatch.setattr(ibs_track_release, "asyncio", SimpleNamespace(sleep=sleep))

        outcomes = await reconcile(
            ibs,
            [t.candidate() for t in (first, fallback, other, broken)],
            request_delay=0.25,
        )

        assert kinds(outcomes) == {
            first.id: "updated",
            fallback.id: "updated",
            other.id: "no_op",
            broken.id: "failed",
        }
        requests = [entry for entry in events if entry.startswith("http:")]
        # Two source-info requests, the checkpoint diff, the fallback and
        # first-observation diff, the failed diff, and the other project's.
        assert len(requests) == 6
        assert events[0] == "http:source"
        assert delays == [0.25] * (len(requests) - 1)
        inside = False
        for position, entry in enumerate(events):
            if entry == "unit":
                inside = True
            elif entry == "close":
                inside = False
            elif entry == "sleep":
                assert not inside, events
                assert events[position + 1].startswith("http:"), events

    @pytest.mark.parametrize("delay", [None, 0.0], ids=["omitted", "zero"])
    async def test_zero_or_omitted_delay_never_waits(
        self,
        world: TrackWorld,
        ibs: FakeIBS,
        monkeypatch: pytest.MonkeyPatch,
        delay: float | None,
    ) -> None:
        seed = Seed(world.session, world)
        first = await seed.track(await seed.ticket())
        other = await seed.track(await seed.ticket(), project=OTHER_PROJECT)
        await seed.commit()
        _evidence(ibs, first, other)
        sleep = AsyncMock()
        monkeypatch.setattr(ibs_track_release, "asyncio", SimpleNamespace(sleep=sleep))

        outcomes = await reconcile(
            ibs, [first.candidate(), other.candidate()], request_delay=delay
        )

        assert kinds(outcomes) == {first.id: "updated", other.id: "updated"}
        assert len(ibs.served) == 4
        sleep.assert_not_awaited()


# ---------------------------------------------------------------------------
# Sanitized logs (XML and Response Safety; Structured Logs)
# ---------------------------------------------------------------------------


class TestSanitizedLogs:
    async def test_no_raw_response_label_or_credential_reaches_a_log(
        self, world: TrackWorld, ibs: FakeIBS
    ) -> None:
        marker = "fictional-private-marker"
        seed = Seed(world.session, world)
        fixed = await seed.track(await seed.ticket())
        forbidden = await seed.track(
            await seed.ticket(), package_name=SIBLING_PACKAGE, checkpoint=CHECKPOINT
        )
        malformed = await seed.track(await seed.ticket(), project=OTHER_PROJECT)
        await seed.commit()
        ibs.source(PROJECT, PACKAGE, CURRENT)
        ibs.source(PROJECT, SIBLING_PACKAGE, CURRENT)
        ibs.issues(
            PROJECT,
            PACKAGE,
            "0",
            CURRENT,
            issue(_cve(fixed)),
            issue(f"CVE-{marker}"),
        )
        ibs.diff(
            PROJECT,
            SIBLING_PACKAGE,
            CHECKPOINT,
            CURRENT,
            status_response(403, f"<status>{marker}</status>".encode()),
        )
        ibs.fail_source(
            OTHER_PROJECT, xml_response(f"<sourceinfolist>{marker}<".encode())
        )

        with capture_logs() as logs:
            outcomes = await reconcile(
                ibs, [fixed.candidate(), forbidden.candidate(), malformed.candidate()]
            )

        assert kinds(outcomes) == {
            fixed.id: "updated",
            forbidden.id: "failed",
            malformed.id: "failed",
        }
        assert sorted(logged(logs, TRACK_FAILED), key=_by_track) == sorted(
            [
                track_failed(forbidden, "http_status"),
                track_failed(malformed, "malformed_xml"),
            ],
            key=_by_track,
        )
        assert "<" not in repr(own(logs))
        rendered = repr(logs)
        for text in (
            marker,
            fictional_settings_value(),
            "jdoe",
            "fictional-session",
            "keyId",
        ):
            assert text not in rendered


# ---------------------------------------------------------------------------
# Consumer mode (Shared Reconciliation Boundary: Consumer mode)
# ---------------------------------------------------------------------------


async def _consumer_reconcile(
    ibs: FakeIBS, candidates: list[TrackReleaseCandidate]
) -> dict[uuid.UUID, str]:
    """One consumer-mode invocation: no fetcher name, hook, or delay."""
    async with ibs.client() as client:
        outcomes = await reconcile_ibs_track_releases(
            candidates, client=client, forbid_convergence_effects=True
        )
    return kinds(outcomes)


async def _stale_resolved(world: TrackWorld) -> tuple[Track, Track]:
    """An `Analyzed` Ticket whose `example` track is the evidence track
    (its Product released) and whose `example-libs` track stays open with
    an actionable unreleased Product, so the gate after the `FIXED` is not
    `Resolved`."""
    seed = Seed(world.session, world)
    ticket = await seed.ticket(TicketStatus.ANALYZED, assessed=True)
    fixed = await seed.track(ticket, status=PackageStatus.AFFECTED)
    await seed.product(fixed, released_at=RELEASED_AT)
    still_open = await seed.track(
        ticket, package_name=SIBLING_PACKAGE, status=PackageStatus.AFFECTED
    )
    await seed.product(still_open)
    await seed.commit()
    return fixed, still_open


def _stale_resolution(
    monkeypatch: pytest.MonkeyPatch, world: TrackWorld, ticket_id: uuid.UUID
) -> None:
    """Persist a stale `Resolved` after selection, before the local unit."""
    _concurrently(
        monkeypatch,
        world,
        update(Ticket)
        .where(Ticket.id == ticket_id)
        .values(status=TicketStatus.RESOLVED.value),
    )


def _consumer_failed(track: Track) -> dict[str, Any]:
    """`ibs_track_release_track_failed` without `fetcher_name`."""
    entry = track_failed(track, "ticket_convergence_required")
    del entry["fetcher_name"]
    return entry


class TestConsumerMode:
    async def test_unit_registering_an_effect_rolls_back_and_siblings_commit(
        self,
        world: TrackWorld,
        ibs: FakeIBS,
        publication: Publish,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Only the second Ticket's unit registers: it fails with
        `ticket_convergence_required`, keeps its status and checkpoint, and
        has no event; the siblings commit; nothing is published."""
        first, second, third = await _three(world, ibs)
        original = package_service.set_track_status
        registered: list[uuid.UUID] = []

        async def registering(db: AsyncSession, **kwargs: Any) -> Any:
            result = await original(db, **kwargs)
            if kwargs["track_id"] == second.id:
                register_ticket_convergence(db, kwargs["ticket_id"])
                registered.append(kwargs["ticket_id"])
            return result

        monkeypatch.setattr(package_service, "set_track_status", registering)

        with capture_logs() as logs:
            outcomes = await _consumer_reconcile(
                ibs, [first.candidate(), second.candidate(), third.candidate()]
            )

        assert outcomes == {
            first.id: "updated",
            second.id: "failed",
            third.id: "updated",
        }
        assert registered == [second.ticket_id]
        assert logged(logs, TRACK_FAILED) == [_consumer_failed(second)]
        assert publication.calls == []
        assert await track_status(world, second) == PackageStatus.ANALYSIS.value
        assert await checkpoint_of(world, second) is None
        assert await events_of(world, second.ticket_id) == []
        for committed in (first, third):
            assert await events_of(world, committed.ticket_id) == [
                committed.fixed_event()
            ]
            assert await checkpoint_srcmd5(world, committed) == CURRENT

    async def test_stale_resolved_regression_rolls_back_without_publication(
        self,
        world: TrackWorld,
        ibs: FakeIBS,
        publication: Publish,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Selected while `Analyzed`; a stale `Resolved` is persisted before
        the unit; the `FIXED` would regress it and register convergence:
        consumer mode rolls the unit back."""
        fixed, still_open = await _stale_resolved(world)
        _evidence(ibs, fixed)
        _stale_resolution(monkeypatch, world, fixed.ticket_id)

        with capture_logs() as logs:
            outcomes = await _consumer_reconcile(ibs, [fixed.candidate()])

        assert outcomes == {fixed.id: "failed"}
        assert logged(logs, TRACK_FAILED) == [_consumer_failed(fixed)]
        assert publication.calls == []
        assert await ticket_status(world, fixed.ticket_id) == (
            TicketStatus.RESOLVED.value
        )
        assert await track_status(world, fixed) == PackageStatus.AFFECTED.value
        assert await track_status(world, still_open) == PackageStatus.AFFECTED.value
        assert await checkpoint_of(world, fixed) is None
        assert await events_of(world, fixed.ticket_id) == []

    async def test_same_regression_commits_and_publishes_for_the_fetcher(
        self,
        world: TrackWorld,
        ibs: FakeIBS,
        publication: Publish,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Contrast: outside consumer mode the same unit commits, regresses
        the Ticket, and publishes its Ticket convergence after the commit,
        which is why the consumer must not commit it."""
        fixed, _ = await _stale_resolved(world)
        _evidence(ibs, fixed)
        _stale_resolution(monkeypatch, world, fixed.ticket_id)

        outcomes = await reconcile(ibs, [fixed.candidate()])

        assert kinds(outcomes) == {fixed.id: "updated"}
        assert published(publication.calls) == [fixed.ticket_id]
        assert await ticket_status(world, fixed.ticket_id) in (
            TicketStatus.ANALYSIS.value,
            TicketStatus.ANALYZED.value,
        )
        assert await checkpoint_srcmd5(world, fixed) == CURRENT
