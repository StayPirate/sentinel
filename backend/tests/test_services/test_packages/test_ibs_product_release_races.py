"""Independent-session tests for the IBS Product release reconciliation
boundary (backend/app/services/packages/ibs_product_release.py): races,
per-occurrence failure conversion, and the commit and Ticket convergence
drain.

Owning specifications:

- docs/features/packages/ibs-product-release-detection.md (Reconciliation
  Boundary: only known per-occurrence failures become outcomes;
  `SoftTimeLimitExceeded`, `MemoryError`, and unexpected failures
  propagate; Local mutation and concurrency: reload under the Ticket
  lock, scope revalidation, concurrent already-released no-op, stale
  `Ignored`/`Duplicated` or changed-scope no-op with one
  `ibs_product_release_occurrence_stale` warning, in-flight completion
  after `Resolved`, serialization on the Ticket lock, flush and commit
  once, close, detach, and drain; commit exception or ambiguity
  terminates the invocation; broker-operational publication absorption;
  non-operational publication propagation without reclassification;
  Irreversibility, Audit, and Observability: no event for a non-mutating
  outcome; Testing Requirements).
- docs/features/tickets/ticket-service.md (Ticket Convergence >
  Publication policies; Publication failure logging).
- docs/features/platform/testing-strategy.md (Ticket Convergence
  Publication Handoff: "IBS track and Product release detection";
  Concurrency Testing and Lock-Wait Observation; Audit Trail Testing).

Selection and the boundary body are covered by
`test_ibs_product_release.py`, whose module docstring describes the shared
setup: a `ReleaseWorld` with explicit teardown, `UnitSessions` replacing
the boundary's `async_session_factory`, a `task_publication.publish_task`
recorder, and the fake download server under `TEST_BASE_URL`. A Product
release never registers a Ticket convergence effect by itself (it only
moves a Ticket forward), so the drain tests wrap
`package_service.set_product_released_at()` to register one for the
released occurrence's Ticket after the real call. Concurrent changes are
committed by an independent session between phase 1 (all repository I/O)
and phase 2 (`between_phases()`), or by a holder of the Ticket lock.
"""

from __future__ import annotations

import asyncio
import re
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from datetime import UTC, datetime
from typing import Any, Final

import httpx
import pytest
from celery.exceptions import OperationalError as KombuOperationalError
from celery.exceptions import SoftTimeLimitExceeded
from sqlalchemy import delete, select, update
from sqlalchemy.exc import OperationalError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from sqlalchemy.orm import Session
from structlog.testing import capture_logs

from app.config import settings
from app.core.enums import PackageStatus, TicketStatus, WorkflowType
from app.models.ticket import Ticket
from app.models.ticket_package import TicketPackage
from app.models.ticket_package_product import TicketPackageProduct
from app.models.ticket_package_track import TicketPackageTrack
from app.services import package_service, task_publication
from app.services.packages.ibs_product_release import reconcile_ibs_product_releases
from tests.support.database import assert_lock_wait
from tests.support.ibs_download import TEST_BASE_URL, DownloadServer
from tests.support.ibs_product_release import (
    FETCHER,
    ISSUED_AT,
    OCCURRENCE_FAILED,
    OCCURRENCE_STALE,
    REPOSITORY,
    RUN_COMPLETED,
    SIBLING_PACKAGE,
    WAIT,
    Occurrence,
    Outcomes,
    Publish,
    ReleaseWorld,
    Seed,
    UnitSessions,
    between_phases,
    events_of,
    install_units,
    logged,
    matching,
    occurrence_failed,
    occurrence_stale,
    publication_failed,
    published,
    reconcile_from,
    register_after_release,
    released_at,
    released_events,
    repository,
    run_completed,
    summary,
    ticket_status,
)
from tests.support.suse_cvss_races import SessionStatementRecorder
from tests.support.ticket_mutations import EVAL
from tests.support.track_status import Spy

pytestmark = pytest.mark.integration

Factory = Callable[[], Awaitable[AsyncSession]]

WINNER_AT: Final = datetime(2024, 1, 2, 3, 4, 5, tzinfo=UTC)
"""A concurrent winner's committed release instant (earlier than the
advisory's, so a replacement would be visible)."""

SECRET: Final = "fictional-secret"
BROKER_FAILURE: Final = f"redis://sentinel:{SECRET}@broker.example.test:6379/1 down"
"""Fictional broker error text with credentials; never logged."""

TICKET_LOCK: Final = re.compile(r"\bFROM ticket\b.*FOR UPDATE\s*$", re.DOTALL)


@pytest.fixture(autouse=True)
def configured_base(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "ibs_download_base_url", TEST_BASE_URL)


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
) -> UnitSessions:
    return install_units(monkeypatch, real_session_factory)


@pytest.fixture
async def world(db_session_factory: Factory) -> AsyncIterator[ReleaseWorld]:
    created = ReleaseWorld(db_session_factory, await db_session_factory())
    try:
        yield created
    finally:
        await created.cleanup()


async def _seeded(
    world: ReleaseWorld,
    count: int = 1,
    status: TicketStatus = TicketStatus.ANALYSIS,
    **kwargs: Any,
) -> list[Occurrence]:
    """`count` committed occurrences, each below its own Ticket (in
    `status`) and Product, in occurrence-ID order."""
    seed = Seed(world.session, world)
    created = []
    for _ in range(count):
        ticket = await seed.ticket(status)
        created.append(await seed.occurrence(ticket, await seed.product()))
    await seed.commit()
    return sorted(created, key=lambda occurrence: occurrence.id)


def _server(*occurrences: Occurrence) -> DownloadServer:
    """`REPOSITORY` with one advisory matching every given occurrence."""
    server = DownloadServer()
    server.add(REPOSITORY, repository(matching(*(o.cve_id for o in occurrences))))
    return server


async def _commit(world: ReleaseWorld, *statements: Any) -> None:
    """Commit `statements` through a fresh independent session."""
    session = await world.open_session()
    for statement in statements:
        await session.execute(statement)
    await session.commit()


def _failing_for(
    monkeypatch: pytest.MonkeyPatch,
    occurrence: Occurrence,
    error: BaseException,
    *,
    after_call: bool = True,
) -> None:
    """Make `set_product_released_at()` raise `error` for `occurrence`,
    after (default) or instead of the real call; others are unchanged."""
    original = package_service.set_product_released_at

    async def failing(db: AsyncSession, **kwargs: Any) -> Any:
        if kwargs["ticket_package_product_id"] != occurrence.id:
            return await original(db, **kwargs)
        if after_call:
            await original(db, **kwargs)
        raise error

    monkeypatch.setattr(package_service, "set_product_released_at", failing)


# ---------------------------------------------------------------------------
# 4. Races (Local mutation and concurrency)
# ---------------------------------------------------------------------------


class TestConcurrentRelease:
    async def test_release_committed_between_phases_is_a_silent_no_op(
        self,
        world: ReleaseWorld,
        units: UnitSessions,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Another invocation committed `released_at` after this one's
        repository I/O: the locked reload sees it, the unit rolls back,
        and the service is never called; no event, no warning."""
        (occurrence,) = await _seeded(world)
        between_phases(
            monkeypatch,
            lambda: _commit(
                world,
                update(TicketPackageProduct)
                .where(TicketPackageProduct.id == occurrence.id)
                .values(released_at=WINNER_AT),
            ),
        )
        service = Spy(monkeypatch, "set_product_released_at")
        hook = Outcomes()

        with capture_logs() as logs:
            result = await reconcile_from(
                _server(occurrence), [occurrence.candidate()], hook
            )

        assert result == summary(selected=1, no_op=1)
        assert hook.kinds == [(occurrence.id, "no_op")]
        assert service.calls == []
        assert len(units.sessions) == 1
        assert logs == [run_completed(selected=1, no_op=1)]
        assert await released_at(world, occurrence) == WINNER_AT
        assert await events_of(world, occurrence.ticket_id) == []

    async def test_unit_waits_for_the_ticket_lock_and_keeps_the_winner(
        self, world: ReleaseWorld, units: UnitSessions
    ) -> None:
        """A holder locks the Ticket and sets `released_at`; the unit's
        first statement is the Ticket lock, proven waiting on the holder;
        after the holder's commit it observes the winner as a no-op."""
        (occurrence,) = await _seeded(world)
        waiter = await world.open_session()
        units.queued.append(waiter)
        holder = await world.open_session()
        await holder.execute(
            select(Ticket.id).where(Ticket.id == occurrence.ticket_id).with_for_update()
        )
        await holder.execute(
            update(TicketPackageProduct)
            .where(TicketPackageProduct.id == occurrence.id)
            .values(released_at=WINNER_AT)
        )
        hook = Outcomes()

        async with _server(occurrence).client() as client:
            with SessionStatementRecorder(waiter) as recorder, capture_logs() as logs:
                task = world.start(
                    waiter,
                    reconcile_ibs_product_releases(
                        [occurrence.candidate()],
                        client=client,
                        fetcher_name=FETCHER,
                        on_outcome=hook,
                    ),
                )
                await assert_lock_wait(task, waiter=waiter, blocked_by=holder)
                assert len(recorder.statements) == 1
                assert TICKET_LOCK.search(recorder.statements[0])
                await holder.commit()
                result = await asyncio.wait_for(task, timeout=WAIT)

        assert result == summary(selected=1, no_op=1)
        assert hook.kinds == [(occurrence.id, "no_op")]
        assert recorder.writes() == []
        assert units.sessions == [waiter]
        assert logs == [run_completed(selected=1, no_op=1)]
        assert await released_at(world, occurrence) == WINNER_AT
        assert await events_of(world, occurrence.ticket_id) == []

    async def test_unit_after_a_rolled_back_holder_releases(
        self, world: ReleaseWorld, units: UnitSessions
    ) -> None:
        (occurrence,) = await _seeded(world)
        waiter = await world.open_session()
        units.queued.append(waiter)
        holder = await world.open_session()
        await holder.execute(
            select(Ticket.id).where(Ticket.id == occurrence.ticket_id).with_for_update()
        )
        await holder.execute(
            update(TicketPackageProduct)
            .where(TicketPackageProduct.id == occurrence.id)
            .values(released_at=WINNER_AT)
        )

        async with _server(occurrence).client() as client:
            task = world.start(
                waiter,
                reconcile_ibs_product_releases(
                    [occurrence.candidate()], client=client, fetcher_name=FETCHER
                ),
            )
            await assert_lock_wait(task, waiter=waiter, blocked_by=holder)
            await holder.rollback()
            result = await asyncio.wait_for(task, timeout=WAIT)

        assert result == summary(selected=1, updated=1)
        assert await released_at(world, occurrence) == ISSUED_AT
        assert await events_of(world, occurrence.ticket_id) == [
            occurrence.released_event()
        ]


class TestInactiveTicketRaces:
    @pytest.mark.parametrize(
        "status", [TicketStatus.IGNORED, TicketStatus.DUPLICATED], ids=str
    )
    async def test_ticket_leaving_the_operable_states_is_stale(
        self,
        world: ReleaseWorld,
        monkeypatch: pytest.MonkeyPatch,
        status: TicketStatus,
    ) -> None:
        (occurrence,) = await _seeded(world)
        seed = Seed(world.session, world)
        canonical = await seed.ticket(TicketStatus.ANALYSIS, with_cve=False)
        await seed.commit()
        values: dict[str, Any] = {"status": status.value}
        if status is TicketStatus.DUPLICATED:
            values["duplicate_of_id"] = canonical.id
        between_phases(
            monkeypatch,
            lambda: _commit(
                world,
                update(Ticket)
                .where(Ticket.id == occurrence.ticket_id)
                .values(**values),
            ),
        )
        hook = Outcomes()

        with capture_logs() as logs:
            result = await reconcile_from(
                _server(occurrence), [occurrence.candidate()], hook
            )

        assert result == summary(selected=1, no_op=1)
        assert hook.kinds == [(occurrence.id, "no_op")]
        assert logs == [
            occurrence_stale(occurrence, "ticket_not_operable"),
            run_completed(selected=1, no_op=1),
        ]
        assert await released_at(world, occurrence) is None
        assert await events_of(world, occurrence.ticket_id) == []
        assert await ticket_status(world, occurrence.ticket_id) == status.value

    async def test_in_flight_occurrence_completes_after_resolution(
        self,
        world: ReleaseWorld,
        publication: Publish,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Selected while `Analyzed`; the Ticket is `Resolved` before the
        lock: the release still completes with its one event. The Ticket's
        assessed CVE and only `FIXED` track keep the gate at `Resolved`
        (tickets.md, Gate), so no status event or convergence effect
        follows."""
        seed = Seed(world.session, world)
        ticket = await seed.ticket(TicketStatus.ANALYZED, assessed=True)
        occurrence = await seed.occurrence(
            ticket, await seed.product(), track_status=PackageStatus.FIXED
        )
        await seed.commit()
        between_phases(
            monkeypatch,
            lambda: _commit(
                world,
                update(Ticket)
                .where(Ticket.id == ticket.id)
                .values(status=TicketStatus.RESOLVED.value),
            ),
        )

        with capture_logs() as logs:
            result = await reconcile_from(_server(occurrence), [occurrence.candidate()])

        assert result == summary(selected=1, updated=1)
        assert logged(logs, OCCURRENCE_STALE) == []
        assert await released_at(world, occurrence) == ISSUED_AT
        assert await events_of(world, ticket.id) == [occurrence.released_event()]
        assert await ticket_status(world, ticket.id) == TicketStatus.RESOLVED.value
        assert publication.calls == []


SCOPE_CHANGES = [
    "cve-replaced",
    "cve-removed",
    "workflow-git",
    "package-renamed",
    "product-changed",
    "occurrence-moved",
    "occurrence-deleted",
    "ticket-deleted",
]


class TestScopeChanged:
    @pytest.mark.parametrize("change", SCOPE_CHANGES)
    async def test_changed_scope_is_stale(
        self,
        world: ReleaseWorld,
        monkeypatch: pytest.MonkeyPatch,
        change: str,
    ) -> None:
        """The Ticket, CVE, package, Product, track, or workflow identity
        no longer matches the selected evidence under the lock: one
        `scope_changed` warning, no mutation, no event."""
        seed = Seed(world.session, world)
        ticket = await seed.ticket()
        occurrence = await seed.occurrence(ticket, await seed.product())
        other_cve = await seed.cve()
        other_product = await seed.product()
        other_track = await seed.occurrence(
            ticket, other_product, reference="SUSE:SLE-15-SP7:Update"
        )
        await seed.commit()
        statements: dict[str, list[Any]] = {
            "cve-replaced": [
                update(Ticket).where(Ticket.id == ticket.id).values(cve_id=other_cve.id)
            ],
            "cve-removed": [
                update(Ticket).where(Ticket.id == ticket.id).values(cve_id=None)
            ],
            "workflow-git": [
                update(TicketPackageTrack)
                .where(TicketPackageTrack.id == occurrence.track_id)
                .values(workflow_type=WorkflowType.GIT.value)
            ],
            "package-renamed": [
                update(TicketPackage)
                .where(TicketPackage.id == occurrence.package_id)
                .values(package_name="example-renamed")
            ],
            "product-changed": [
                delete(TicketPackageProduct).where(
                    TicketPackageProduct.id == other_track.id
                ),
                update(TicketPackageProduct)
                .where(TicketPackageProduct.id == occurrence.id)
                .values(product_id=other_product.id),
            ],
            "occurrence-moved": [
                delete(TicketPackageProduct).where(
                    TicketPackageProduct.id == other_track.id
                ),
                update(TicketPackageProduct)
                .where(TicketPackageProduct.id == occurrence.id)
                .values(ticket_package_track_id=other_track.track_id),
            ],
            "occurrence-deleted": [
                delete(TicketPackageProduct).where(
                    TicketPackageProduct.id == occurrence.id
                )
            ],
            "ticket-deleted": [
                delete(TicketPackageProduct).where(
                    TicketPackageProduct.id.in_([occurrence.id, other_track.id])
                ),
                delete(TicketPackageTrack).where(
                    TicketPackageTrack.ticket_package_id == occurrence.package_id
                ),
                delete(TicketPackage).where(TicketPackage.ticket_id == ticket.id),
                delete(Ticket).where(Ticket.id == ticket.id),
            ],
        }
        between_phases(monkeypatch, lambda: _commit(world, *statements[change]))
        service = Spy(monkeypatch, "set_product_released_at")
        hook = Outcomes()

        with capture_logs() as logs:
            result = await reconcile_from(
                _server(occurrence), [occurrence.candidate()], hook
            )

        assert result == summary(selected=1, no_op=1)
        assert hook.kinds == [(occurrence.id, "no_op")]
        assert service.calls == []
        assert logs == [
            occurrence_stale(occurrence, "scope_changed"),
            run_completed(selected=1, no_op=1),
        ]
        assert await released_at(world, occurrence) is None
        assert await events_of(world, ticket.id) == []


# ---------------------------------------------------------------------------
# 5. Failure conversion (Reconciliation Boundary)
# ---------------------------------------------------------------------------


class TestFailureConversion:
    async def test_database_error_fails_only_its_occurrence(
        self, world: ReleaseWorld, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The second occurrence's service call flushed its writes, then a
        `SQLAlchemyError`: its unit rolls back (no release, no event), it
        is `failed` with one bounded `database` warning naming the matched
        repository, and the siblings commit."""
        first, second, third = await _seeded(world, 3)
        _failing_for(
            monkeypatch,
            second,
            OperationalError("UPDATE ticket_package_product", None, Exception(SECRET)),
        )
        hook = Outcomes()

        with capture_logs() as logs:
            result = await reconcile_from(
                _server(first, second, third),
                [first.candidate(), second.candidate(), third.candidate()],
                hook,
            )

        assert result == summary(selected=3, updated=2, failed=1)
        assert hook.kinds == [
            (first.id, "updated"),
            (second.id, "failed"),
            (third.id, "updated"),
        ]
        assert logs == [
            occurrence_failed(second, REPOSITORY, "database"),
            run_completed(selected=3, updated=2, failed=1),
        ]
        assert SECRET not in repr(logs)
        assert await released_at(world, second) is None
        assert await events_of(world, second.ticket_id) == []
        for committed in (first, third):
            assert await released_at(world, committed) == ISSUED_AT
            assert await released_events(world, committed.ticket_id) == [
                committed.released_event()
            ]

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
        world: ReleaseWorld,
        units: UnitSessions,
        monkeypatch: pytest.MonkeyPatch,
        make_error: Callable[[], BaseException],
    ) -> None:
        """No per-occurrence outcome: the exception terminates the
        invocation after the second unit rolled back; the earlier commit
        stays and the third occurrence is never processed."""
        first, second, third = await _seeded(world, 3)
        error = make_error()
        _failing_for(monkeypatch, second, error)
        hook = Outcomes()

        with capture_logs() as logs, pytest.raises(type(error)) as raised:
            await reconcile_from(
                _server(first, second, third),
                [first.candidate(), second.candidate(), third.candidate()],
                hook,
            )

        assert raised.value is error
        assert hook.kinds == [(first.id, "updated")]
        assert len(units.sessions) == 2
        assert units.closed == units.sessions
        assert logged(logs, OCCURRENCE_FAILED) == []
        assert logged(logs, RUN_COMPLETED) == []
        assert await released_at(world, first) == ISSUED_AT
        assert await released_at(world, second) is None
        assert await events_of(world, second.ticket_id) == []
        assert await released_at(world, third) is None

    @pytest.mark.parametrize(
        "make_error",
        [
            pytest.param(SoftTimeLimitExceeded, id="soft-time-limit"),
            pytest.param(MemoryError, id="memory-error"),
        ],
    )
    async def test_signal_during_repository_io_propagates(
        self,
        world: ReleaseWorld,
        units: UnitSessions,
        make_error: Callable[[], BaseException],
    ) -> None:
        """Raised by the transport in phase 1: no unit session, no outcome,
        no occurrence or run event; nothing is persisted."""
        first, second = await _seeded(world, 2)
        error = make_error()
        server = _server(first, second)

        def interrupt(_: httpx.Request) -> httpx.Response:
            raise error

        server.script(server.repomd_url(REPOSITORY), interrupt)
        hook = Outcomes()

        with capture_logs() as logs, pytest.raises(type(error)) as raised:
            await reconcile_from(server, [first.candidate(), second.candidate()], hook)

        assert raised.value is error
        assert hook.received == []
        assert units.sessions == []
        assert logged(logs, OCCURRENCE_FAILED) == []
        assert logged(logs, RUN_COMPLETED) == []
        assert await released_at(world, first) is None


# ---------------------------------------------------------------------------
# 6. Commit and Ticket convergence drain
# ---------------------------------------------------------------------------


class TestCommitAndDrain:
    async def test_unit_is_flushed_before_its_commit(
        self, world: ReleaseWorld, units: UnitSessions
    ) -> None:
        """At the start of the commit (before its own flush) the unit has
        no pending insert, update, or delete: the release, its event, and
        the reconciliation were flushed by the service."""
        (occurrence,) = await _seeded(world)
        pending: list[tuple[int, int, int]] = []

        def before_commit(session: Session) -> None:
            pending.append((len(session.new), len(session.dirty), len(session.deleted)))

        units.before_commit = before_commit

        result = await reconcile_from(_server(occurrence), [occurrence.candidate()])

        assert result == summary(selected=1, updated=1)
        assert pending == [(0, 0, 0)]

    async def test_commit_exception_terminates_the_invocation(
        self,
        world: ReleaseWorld,
        units: UnitSessions,
        publication: Publish,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The first unit registered a convergence effect, then its commit
        fails: the exception propagates, no outcome reaches the hook,
        nothing is published or persisted, and the next occurrence is not
        processed."""
        first, second = await _seeded(world, 2)
        registered = register_after_release(monkeypatch)
        error = OperationalError("COMMIT", None, Exception("fictional reset"))
        units.failing_commit = (0, error)
        hook = Outcomes()

        with capture_logs() as logs, pytest.raises(OperationalError) as raised:
            await reconcile_from(
                _server(first, second), [first.candidate(), second.candidate()], hook
            )

        assert raised.value is error
        assert registered == [first.ticket_id]
        assert hook.received == []
        assert publication.calls == []
        assert len(units.sessions) == 1
        assert units.closed == units.sessions
        assert logged(logs, OCCURRENCE_FAILED) == []
        assert logged(logs, RUN_COMPLETED) == []
        for occurrence in (first, second):
            assert await released_at(world, occurrence) is None
            assert await events_of(world, occurrence.ticket_id) == []

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
    async def test_drain_follows_commit_close_and_hook_per_occurrence(
        self,
        world: ReleaseWorld,
        units: UnitSessions,
        publication: Publish,
        monkeypatch: pytest.MonkeyPatch,
        make_error: Callable[[], BaseException] | None,
    ) -> None:
        """Per occurrence: commit, then the hook, then exactly one root
        publication for its Ticket, before the next unit opens. Inside the
        attempt the unit session is closed and an independent `NOWAIT`
        lock of the Ticket reads the committed release. A broker
        operational error adds exactly one sanitized ERROR per effect, is
        absorbed, and leaves outcomes and counts unchanged."""
        first, second = await _seeded(world, 2)
        register_after_release(monkeypatch)
        events: list[str] = []
        units.events = events
        hook = Outcomes(events=events)
        observed: list[tuple[bool, datetime | None]] = []

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
                    select(TicketPackageProduct.released_at)
                    .join(
                        TicketPackageTrack,
                        TicketPackageTrack.id
                        == TicketPackageProduct.ticket_package_track_id,
                    )
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
            result = await reconcile_from(
                _server(first, second), [first.candidate(), second.candidate()], hook
            )

        assert result == summary(selected=2, updated=2)
        assert hook.kinds == [(first.id, "updated"), (second.id, "updated")]
        assert published(publication.calls) == [first.ticket_id, second.ticket_id]
        assert observed == [(True, ISSUED_AT), (True, ISSUED_AT)]
        # The terminal outcome precedes every awaitable post-commit action,
        # including the session close (ibs-product-release-detection.md,
        # Local mutation and concurrency).
        assert events == [*["unit", "commit", "hook:updated", "close", "publish"] * 2]
        expected = (
            []
            if make_error is None
            else [
                publication_failed(first.ticket_id),
                publication_failed(second.ticket_id),
            ]
        )
        assert [e for e in logs if e["log_level"] == "error"] == expected
        assert logged(logs, OCCURRENCE_FAILED) == []
        assert logs[-1] == run_completed(selected=2, updated=2)
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
        world: ReleaseWorld,
        units: UnitSessions,
        publication: Publish,
        monkeypatch: pytest.MonkeyPatch,
        make_error: Callable[[], BaseException],
    ) -> None:
        """After the first commit: no rollback, no reclassification (the
        hook saw exactly one `updated`), no failure or publication-failure
        event, no run event, and the next occurrence is not processed."""
        first, second = await _seeded(world, 2)
        register_after_release(monkeypatch)
        error = make_error()
        publication.error = error
        hook = Outcomes()

        with capture_logs() as logs, pytest.raises(type(error)) as raised:
            await reconcile_from(
                _server(first, second), [first.candidate(), second.candidate()], hook
            )

        assert raised.value is error
        assert hook.kinds == [(first.id, "updated")]
        assert published(publication.calls) == [first.ticket_id]
        assert len(units.sessions) == 1
        assert logged(logs, OCCURRENCE_FAILED) == []
        assert [e for e in logs if e["log_level"] == "error"] == []
        assert logged(logs, RUN_COMPLETED) == []
        assert await released_at(world, first) == ISSUED_AT
        assert await released_events(world, first.ticket_id) == [first.released_event()]
        assert await released_at(world, second) is None

    async def test_rolled_back_unit_publishes_nothing(
        self,
        world: ReleaseWorld,
        publication: Publish,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Both units registered an effect; the first then fails with a
        database error and rolls back: only the committed second Ticket is
        published."""
        first, second = await _seeded(world, 2)
        registered = register_after_release(monkeypatch)
        _failing_for(monkeypatch, first, OperationalError("UPDATE", None, Exception()))

        result = await reconcile_from(
            _server(first, second), [first.candidate(), second.candidate()]
        )

        assert result == summary(selected=2, updated=1, failed=1)
        assert registered == [first.ticket_id, second.ticket_id]
        assert published(publication.calls) == [second.ticket_id]
        assert await released_at(world, first) is None


# ---------------------------------------------------------------------------
# Sibling continuation after race outcomes (Reconciliation Boundary)
# ---------------------------------------------------------------------------


class TestSiblingContinuation:
    async def test_stale_and_concurrent_outcomes_do_not_stop_siblings(
        self, world: ReleaseWorld, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A stale occurrence and an already-released one, between two
        releasable siblings of another Ticket: every sibling commits."""
        seed = Seed(world.session, world)
        ticket = await seed.ticket()
        product = await seed.product()
        released = await seed.occurrence(ticket, product)
        sibling = await seed.occurrence(ticket, product, package_name=SIBLING_PACKAGE)
        stale, other = await _seeded(world, 2)
        await seed.commit()
        server = DownloadServer()
        server.add(
            REPOSITORY,
            repository(
                matching(
                    released.cve_id,
                    stale.cve_id,
                    other.cve_id,
                    sources=["example", SIBLING_PACKAGE],
                )
            ),
        )

        async def concurrent() -> None:
            await _commit(
                world,
                update(TicketPackageProduct)
                .where(TicketPackageProduct.id == released.id)
                .values(released_at=WINNER_AT),
                update(Ticket)
                .where(Ticket.id == stale.ticket_id)
                .values(status=TicketStatus.IGNORED.value),
            )

        between_phases(monkeypatch, concurrent)
        candidates = [o.candidate() for o in (released, sibling, stale, other)]

        with capture_logs() as logs:
            result = await reconcile_from(server, candidates)

        assert result == summary(selected=4, updated=2, no_op=2)
        assert logged(logs, OCCURRENCE_STALE) == [
            occurrence_stale(stale, "ticket_not_operable")
        ]
        assert await released_at(world, released) == WINNER_AT
        assert await released_at(world, sibling) == ISSUED_AT
        assert await released_at(world, other) == ISSUED_AT
        assert await released_events(world, ticket.id) == [sibling.released_event()]
        assert await events_of(world, stale.ticket_id) == []
