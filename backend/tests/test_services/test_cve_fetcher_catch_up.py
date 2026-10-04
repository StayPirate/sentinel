"""The default `BaseCVEFetcher.catch_up()` through the real `run_catch_up`
workflow (backend/app/services/base_cve_fetcher.py,
backend/app/tasks/fetchers.py).

Owning specifications:

- docs/features/platform/cve-fetcher-infrastructure.md (Per-CVE
  Finalization: Default `catch_up()` implementation and its Boundary
  conditions; `fetch_single` Signaling Convention; Session Lifecycle,
  Isolated status commit and Metric placement; Default catch_up
  Implementation).
- docs/features/platform/fetcher-infrastructure.md (Per-Ticket Catch-Up:
  Celery task wrapper steps 1-6, Interface contract including Post-commit
  enqueue queue routing and the `fetch_pending` exclusion; `fetch_single()`
  and `catch_up()` Lifecycle).
- docs/features/platform/testing-strategy.md (CVE Fetcher Infrastructure,
  Default catch-up; Sync Entry-Point Tests; Concurrency Testing: explicit
  cleanup of committed rows).

Two layers are exercised against real PostgreSQL:

- `run_catch_up_async`, awaited directly. The workflow's sessions
  (`app.tasks.fetchers.async_session_factory`) and the isolated status
  sessions (`app.services.base_cve_fetcher.async_session_factory`) are
  `RecordingSessions` over `real_session_factory`, sharing one ordered event
  list with the publication substitute and the drain spy
  (`tests/support/cve_catch_up.py`).
- `_run_catch_up_sync`, the synchronous Celery wrapper, from `def` tests
  with a fake bound task. Its own `asyncio.run()` uses the `NullPool`
  `cli_session_factory`; setup and observation run in separate
  `asyncio.run()` calls on the same factory.

The module-level `engine` is a fake whose `dispose` is an `AsyncMock`.
Wrapper-generic resource cleanup (HTTP client teardown, one `asyncio.run()`,
one engine disposal) does not depend on the fetcher class and is proven by
`tests/test_tasks/test_run_catch_up.py`; `TestSyncWrapper` asserts the
per-attempt event-loop and disposal counts of the default catch-up.
Committed CVE, Ticket, and `FetcherConfig` rows are deleted explicitly at
teardown (`CVESource` and references follow by cascade). Test-only fetchers
keep the inherited default `catch_up()`; their scripted `fetch_single()`
performs the per-CVE writes of one fetch: a `success` source status, an
optional Ticket convergence registration, and, last, an unflushed CVE
description change. Generic wrapper paths that do not depend on the fetcher
class (unknown fetcher, malformed UUID, missing configuration) are covered
by `tests/test_tasks/test_run_catch_up.py`.
"""

from __future__ import annotations

import asyncio
import dataclasses
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable, Iterator, MutableMapping
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import httpx
import pytest
import redis.asyncio as redis_asyncio
from celery.exceptions import SoftTimeLimitExceeded
from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from structlog.testing import capture_logs

import app.services.base_cve_fetcher as base_cve_fetcher_module
from app.core.enums import CVESourceFetchStatus, CVESourceType, TicketStatus
from app.models.cve import CVE
from app.models.ticket import Ticket
from app.services import cve_service, package_service, task_publication
from app.services.base_cve_fetcher import (
    ISOLATED_STATUS_WRITE_FAILED_EVENT,
    CVEFetchResult,
    CVENotInSource,
)
from app.services.base_fetcher import FETCHER_REGISTRY, get_catch_up_fetchers
from app.services.cve_ingest import PostIngestTasks, UpsertAction
from app.services.ticket_convergence_registry import register_ticket_convergence
from app.tasks import fetchers
from tests.support.cve_catch_up import (
    CATCH_UP,
    CONVERGE,
    RESOLVE,
    SOURCE,
    CatchUpHarness,
    CVEProbe,
    FakeEngine,
    FakeTask,
    Publications,
    RecordingSessions,
    RetryRequested,
    SourceState,
    Step,
    counters,
    define_cve_fetcher,
    delete_fetcher_rows,
    fetcher_run_count,
    install_harness,
    seed_fetcher_config,
    source_state,
)
from tests.support.suse_cvss_races import CommittedWorld

pytestmark = pytest.mark.usefixtures("isolated_fetcher_registries")

LogEntry = MutableMapping[str, Any]
SessionFactory = Callable[[], Awaitable[AsyncSession]]

_DESCRIPTION = "Example refreshed description"
_CPE = "cpe:2.3:a:example_vendor:example_product:1.0:*:*:*:*:*:*:*"
_UNRESOLVED = "Ticket references a CVE row that cannot be resolved"
_COUNTDOWNS = (5, 10, 20)


class _CommitFailureError(Exception):
    """An injected definite commit failure."""


def _http_status_error(status_code: int) -> httpx.HTTPStatusError:
    request = httpx.Request("GET", "https://cve-source.example.invalid/item")
    response = httpx.Response(status_code, request=request)
    return httpx.HTTPStatusError(
        f"HTTP {status_code}", request=request, response=response
    )


_RETRYABLE_ERRORS = [
    pytest.param(lambda: httpx.ConnectError("connection refused"), id="connect-error"),
    pytest.param(lambda: _http_status_error(503), id="http-503"),
]

_SIGNALS = [
    pytest.param(asyncio.CancelledError, id="cancelled"),
    pytest.param(SoftTimeLimitExceeded, id="soft-time-limit"),
    pytest.param(MemoryError, id="memory-error"),
]


def _events(logs: list[LogEntry], event: str) -> list[LogEntry]:
    return [entry for entry in logs if entry["event"] == event]


def _errors(logs: list[LogEntry]) -> list[LogEntry]:
    return [entry for entry in logs if entry["log_level"] == "error"]


# ---------------------------------------------------------------------------
# Scripted per-CVE writes
# ---------------------------------------------------------------------------


async def _write(
    session: AsyncSession, cve_id: str, *, register: uuid.UUID | None
) -> None:
    """One fetch's writes; the description change stays unflushed."""
    cve = (await session.execute(select(CVE).where(CVE.cve_id == cve_id))).scalar_one()
    await cve_service.record_source_status(
        session, cve.id, SOURCE, CVESourceFetchStatus.SUCCESS
    )
    if register is not None:
        register_ticket_convergence(session, register)
    cve.description = _DESCRIPTION


def _succeeds(
    *,
    register: uuid.UUID | None = None,
    post_ingest: PostIngestTasks | None = None,
) -> Step:
    async def step(cve_id: str, session: AsyncSession) -> CVEFetchResult:
        await _write(session, cve_id, register=register)
        return CVEFetchResult(action=UpsertAction.UPDATED, post_ingest=post_ingest)

    return step


def _raises(error: BaseException, *, register: uuid.UUID | None = None) -> Step:
    async def step(cve_id: str, session: AsyncSession) -> CVEFetchResult:
        await _write(session, cve_id, register=register)
        raise error

    return step


def _flush_fails(*, register: uuid.UUID | None = None) -> Step:
    """Writes, then adds a duplicate CVE row that the caller's flush rejects."""

    async def step(cve_id: str, session: AsyncSession) -> CVEFetchResult:
        await _write(session, cve_id, register=register)
        session.add(CVE(cve_id=cve_id))
        return CVEFetchResult(action=UpsertAction.UPDATED, post_ingest=None)

    return step


def _hide_cve(session: AsyncSession) -> None:
    """Make the session's `get()` resolve no `CVE` row (the foreign key
    makes an unresolvable reference impossible in PostgreSQL)."""
    real_get = session.get

    async def get(entity: Any, ident: Any, **kwargs: Any) -> Any:
        if entity is CVE:
            return None
        return await real_get(entity, ident, **kwargs)

    setattr(session, "get", get)  # noqa: B010


def _handoff(ticket_id: uuid.UUID) -> PostIngestTasks:
    return PostIngestTasks(
        ticket_id=str(ticket_id),
        cpe_matches=[],
        affected_cpes=[_CPE],
        vendor_products=[],
        resolved_packages=["example-package"],
    )


async def _description(
    factory: async_sessionmaker[AsyncSession], cve_id: uuid.UUID
) -> str | None:
    async with factory() as session:
        value: str | None = await session.scalar(
            select(CVE.description).where(CVE.id == cve_id)
        )
    return value


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
async def world(db_session_factory: SessionFactory) -> AsyncIterator[CommittedWorld]:
    created = CommittedWorld(db_session_factory, await db_session_factory())
    try:
        yield created
    finally:
        await created.cleanup()


@pytest.fixture
async def harness(
    real_session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> AsyncIterator[CatchUpHarness]:
    installed = install_harness(monkeypatch, real_session_factory)
    try:
        yield installed
    finally:
        await installed.cleanup()


@dataclass
class _Target:
    """A committed published CVE and its Ticket."""

    cve: CVE
    ticket: Ticket


async def _target(world: CommittedWorld) -> _Target:
    cve = await world.cve()
    return _Target(cve, await world.ticket(cve_id=cve.id))


# ---------------------------------------------------------------------------
# No-op Tickets and the unresolvable CVE reference
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestNoOpAndIntegrity:
    @pytest.mark.parametrize("ticket", ["missing", "cve-less"])
    async def test_missing_or_cve_less_ticket_returns_silently(
        self, world: CommittedWorld, harness: CatchUpHarness, ticket: str
    ) -> None:
        probe = await harness.fetcher()
        ticket_id = (
            uuid.uuid4()
            if ticket == "missing"
            else (await world.ticket(cve_id=None)).id
        )

        with capture_logs() as logs:
            await fetchers.run_catch_up_async(probe.name, str(ticket_id))

        assert probe.fetched == []
        assert harness.events == []
        assert harness.status.opened == []
        assert harness.published.calls == []
        assert _errors(logs) == []

    async def test_unresolvable_cve_reference_raises_before_any_fetch(
        self, world: CommittedWorld, harness: CatchUpHarness
    ) -> None:
        target = await _target(world)
        probe = await harness.fetcher()
        harness.sessions.hooks.append(_hide_cve)

        with pytest.raises(RuntimeError) as raised:
            await fetchers.run_catch_up_async(probe.name, str(target.ticket.id))

        assert str(raised.value) == _UNRESOLVED
        assert probe.fetched == []
        assert harness.events == []
        assert harness.status.opened == []
        assert harness.published.calls == []


# ---------------------------------------------------------------------------
# Success: flush, then the finalizer's sole commit and post-commit effects
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestSuccess:
    async def test_flushes_then_finalizes_and_publishes_convergence_before_handoff(
        self, world: CommittedWorld, harness: CatchUpHarness
    ) -> None:
        target = await _target(world)
        probe = await harness.fetcher()
        handoff = _handoff(target.ticket.id)
        probe.step = _succeeds(register=target.ticket.id, post_ingest=handoff)
        in_transaction: list[bool] = []

        async def before(call: dict[str, Any]) -> None:
            in_transaction.append(harness.catch_up_session.in_transaction())

        harness.published.before = before

        with capture_logs() as logs:
            await fetchers.run_catch_up_async(probe.name, str(target.ticket.id))

        assert probe.fetched == [target.cve.cve_id]
        assert harness.events == [
            "fetch_single",
            "flush",
            "commit_and_dispatch",
            "commit",
            "drain",
            f"publish:{CONVERGE}",
            f"publish:{RESOLVE}",
        ]
        # Every write was flushed before finalization started.
        assert probe.flushed_at_finalization == [True]
        assert harness.published.published(CONVERGE) == [
            {"ticket_id": str(target.ticket.id)}
        ]
        assert harness.published.published(RESOLVE) == [dataclasses.asdict(handoff)]
        assert in_transaction == [False, False]
        # Committed and visible from a fresh session.
        state = await source_state(harness.factory, target.cve.id)
        assert state is not None
        assert state.status == CVESourceFetchStatus.SUCCESS
        assert await _description(harness.factory, target.cve.id) == _DESCRIPTION
        # No FetcherRun metric, row, or isolated status.
        assert counters(probe.fetcher) == (0, 0, 0, 0)
        assert await fetcher_run_count(harness.factory, probe.name) == 0
        assert harness.status.opened == []
        assert _errors(logs) == []
        harness.engine.dispose.assert_awaited_once_with()

    async def test_finalization_error_propagates_without_rollback_or_status(
        self, world: CommittedWorld, harness: CatchUpHarness
    ) -> None:
        """`commit_and_dispatch()` runs outside the pre-commit handler: a
        post-commit serialization error escapes without a rollback or an
        isolated `failure` write and keeps the committed success."""
        target = await _target(world)
        probe = await harness.fetcher()
        probe.step = _succeeds(
            register=target.ticket.id, post_ingest=_handoff(target.ticket.id)
        )
        error = TypeError("example serialization failure")
        harness.published.errors[RESOLVE] = error

        with pytest.raises(TypeError) as raised:
            await fetchers.run_catch_up_async(probe.name, str(target.ticket.id))

        assert raised.value is error
        assert harness.events == [
            "fetch_single",
            "flush",
            "commit_and_dispatch",
            "commit",
            "drain",
            f"publish:{CONVERGE}",
            f"publish:{RESOLVE}",
        ]
        assert harness.status.opened == []
        state = await source_state(harness.factory, target.cve.id)
        assert state is not None
        assert state.status == CVESourceFetchStatus.SUCCESS
        assert await _description(harness.factory, target.cve.id) == _DESCRIPTION


# ---------------------------------------------------------------------------
# CVENotInSource, pre-finalization failures, and commit failure
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestOutcomes:
    async def test_not_in_source_rolls_back_and_commits_isolated_missing(
        self, world: CommittedWorld, harness: CatchUpHarness
    ) -> None:
        target = await _target(world)
        probe = await harness.fetcher()
        probe.step = _raises(CVENotInSource(), register=target.ticket.id)

        with capture_logs() as logs:
            await fetchers.run_catch_up_async(probe.name, str(target.ticket.id))

        assert harness.events == ["fetch_single", "rollback", "status:commit"]
        assert len(harness.status.opened) == 1
        state = await source_state(harness.factory, target.cve.id)
        assert state is not None
        assert state.status == CVESourceFetchStatus.MISSING
        assert state.first_failed_at is None
        # The fetch's uncommitted write and registration were discarded.
        assert await _description(harness.factory, target.cve.id) is None
        assert harness.published.calls == []
        # Handled inside catch_up(): never the wrapper's defensive path.
        assert _errors(logs) == []

    @pytest.mark.parametrize(
        ("make_step", "error_type", "events"),
        [
            pytest.param(
                lambda ticket: _raises(
                    ValueError("example parse failure"), register=ticket
                ),
                ValueError,
                ["fetch_single", "rollback", "status:commit"],
                id="value-error",
            ),
            pytest.param(
                lambda ticket: _raises(
                    httpx.ConnectError("connection refused"), register=ticket
                ),
                httpx.ConnectError,
                ["fetch_single", "rollback", "status:commit"],
                id="connect-error",
            ),
            pytest.param(
                lambda ticket: _flush_fails(register=ticket),
                IntegrityError,
                ["fetch_single", "flush", "rollback", "status:commit"],
                id="flush-failure",
            ),
        ],
    )
    async def test_pre_finalization_failure_rolls_back_writes_failure_and_propagates(
        self,
        world: CommittedWorld,
        harness: CatchUpHarness,
        make_step: Callable[[uuid.UUID], Step],
        error_type: type[Exception],
        events: list[str],
    ) -> None:
        target = await _target(world)
        probe = await harness.fetcher()
        probe.step = make_step(target.ticket.id)

        with pytest.raises(error_type):
            await fetchers.run_catch_up_async(probe.name, str(target.ticket.id))

        assert harness.events == events
        state = await source_state(harness.factory, target.cve.id)
        assert state is not None
        assert state.status == CVESourceFetchStatus.FAILURE
        assert state.first_failed_at == state.fetched_at
        assert await _description(harness.factory, target.cve.id) is None
        assert harness.published.calls == []

    async def test_commit_failure_propagates_without_isolated_status_or_publication(
        self, world: CommittedWorld, harness: CatchUpHarness
    ) -> None:
        target = await _target(world)
        probe = await harness.fetcher()
        probe.step = _succeeds(
            register=target.ticket.id, post_ingest=_handoff(target.ticket.id)
        )
        failure = _CommitFailureError()
        harness.sessions.failures["commit"] = failure

        with pytest.raises(_CommitFailureError) as raised:
            await fetchers.run_catch_up_async(probe.name, str(target.ticket.id))

        assert raised.value is failure
        assert harness.events == [
            "fetch_single",
            "flush",
            "commit_and_dispatch",
            "commit",
        ]
        assert harness.status.opened == []
        assert harness.published.calls == []
        assert await source_state(harness.factory, target.cve.id) is None
        assert await _description(harness.factory, target.cve.id) is None

    @pytest.mark.parametrize("make_signal", _SIGNALS)
    async def test_control_signal_propagates_without_status_handling(
        self,
        world: CommittedWorld,
        harness: CatchUpHarness,
        make_signal: Callable[[], BaseException],
    ) -> None:
        target = await _target(world)
        probe = await harness.fetcher()
        signal = make_signal()
        probe.step = _raises(signal, register=target.ticket.id)

        with pytest.raises(type(signal)) as raised:
            await fetchers.run_catch_up_async(probe.name, str(target.ticket.id))

        assert raised.value is signal
        assert harness.events == ["fetch_single"]
        assert harness.status.opened == []
        assert harness.published.calls == []
        assert await source_state(harness.factory, target.cve.id) is None


# ---------------------------------------------------------------------------
# FetcherRun and fetch_pending keys
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestResources:
    @pytest.mark.parametrize("outcome", ["success", "missing", "failure"])
    async def test_creates_no_fetcher_run_or_fetch_pending_key(
        self,
        world: CommittedWorld,
        harness: CatchUpHarness,
        redis_client: redis_asyncio.Redis,
        outcome: str,
    ) -> None:
        target = await _target(world)
        probe = await harness.fetcher()
        probe.step = {
            "success": _succeeds(),
            "missing": _raises(CVENotInSource()),
            "failure": _raises(ValueError("example parse failure")),
        }[outcome]

        if outcome == "failure":
            with pytest.raises(ValueError, match="example"):
                await fetchers.run_catch_up_async(probe.name, str(target.ticket.id))
        else:
            await fetchers.run_catch_up_async(probe.name, str(target.ticket.id))

        assert probe.fetched == [target.cve.cve_id]
        assert await fetcher_run_count(harness.factory, probe.name) == 0
        assert await redis_client.keys(f"{cve_service.FETCH_PENDING_KEY_PREFIX}*") == []


# ---------------------------------------------------------------------------
# Catch-up roster publication (fetcher-infrastructure.md, Post-commit
# enqueue; cve-fetcher-infrastructure.md, Default catch_up Implementation)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestCatchUpRoster:
    async def test_participating_cve_fetchers_are_published_with_their_queue(
        self,
        harness: CatchUpHarness,
        real_session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        """A Git-routed and a default-routed fetch-single CVE fetcher are
        each published once with their class `queue` (`None` is left to
        `publish_task()` to omit); a CVE fetcher without fetch-single is not
        a participant, so its `catch_up()` is never dispatched. The roster
        publication only enqueues: no `fetch_single()` runs."""
        FETCHER_REGISTRY.clear()
        git = define_cve_fetcher(source=CVESourceType.MITRE, fetcher_queue="git")
        default = define_cve_fetcher(source=CVESourceType.GHSA)
        unsupported = define_cve_fetcher(source=CVESourceType.KEV, supports=False)
        ticket_id = uuid.uuid7()

        assert set(get_catch_up_fetchers()) == {git.name, default.name}

        await package_service.run_ticket_convergence(
            ticket_id=ticket_id, session_factory=real_session_factory
        )

        expected = sorted(
            [(git.name, "git"), (default.name, None)], key=lambda pair: pair[0]
        )
        assert harness.published.calls == [
            {
                "task_name": CATCH_UP,
                "kwargs": {"fetcher_name": name, "ticket_id": str(ticket_id)},
                "queue": queue,
            }
            for name, queue in expected
        ]
        assert unsupported.name not in {
            call["kwargs"]["fetcher_name"] for call in harness.published.calls
        }
        assert [git.fetched, default.fetched, unsupported.fetched] == [[], [], []]


# ---------------------------------------------------------------------------
# Synchronous Celery wrapper
# ---------------------------------------------------------------------------


@dataclass
class _SyncTarget:
    cve_id: uuid.UUID
    cve: str
    ticket_id: str


@dataclass
class _SyncWorld:
    """Committed rows and substitutes of the `_run_catch_up_sync` tests.

    Every database operation of the test itself runs in its own
    `asyncio.run()` on the `NullPool` factory, as does the wrapper."""

    factory: async_sessionmaker[AsyncSession]
    sessions: RecordingSessions
    status: RecordingSessions
    published: Publications
    engine: FakeEngine
    asyncio_run: MagicMock
    cve_ids: list[uuid.UUID] = field(default_factory=list)
    ticket_ids: list[uuid.UUID] = field(default_factory=list)
    names: list[str] = field(default_factory=list)

    def target(self) -> _SyncTarget:
        async def seed() -> _SyncTarget:
            async with self.factory() as session:
                cve = CVE(cve_id=f"CVE-2099-{uuid.uuid4().int % 10**8:08d}")
                session.add(cve)
                await session.flush()
                ticket = Ticket(status=TicketStatus.ANALYSIS.value, cve_id=cve.id)
                session.add(ticket)
                await session.commit()
                return _SyncTarget(cve.id, cve.cve_id, str(ticket.id))

        target = asyncio.run(seed())
        self.cve_ids.append(target.cve_id)
        self.ticket_ids.append(uuid.UUID(target.ticket_id))
        return target

    def fetcher(self) -> CVEProbe:
        probe = define_cve_fetcher()
        self.names.append(probe.name)
        asyncio.run(seed_fetcher_config(self.factory, probe.name, enabled=True))
        return probe

    def state(self, target: _SyncTarget) -> SourceState | None:
        return asyncio.run(source_state(self.factory, target.cve_id))

    def cleanup(self) -> None:
        async def delete_rows() -> None:
            async with self.factory() as session:
                await session.execute(
                    delete(Ticket).where(Ticket.id.in_(self.ticket_ids))
                )
                await session.execute(delete(CVE).where(CVE.id.in_(self.cve_ids)))
                await session.commit()
            await delete_fetcher_rows(self.factory, self.names)

        asyncio.run(delete_rows())


@pytest.fixture
def sync_world(
    cli_session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[_SyncWorld]:
    events: list[str] = []
    created = _SyncWorld(
        factory=cli_session_factory,
        sessions=RecordingSessions(cli_session_factory, events),
        status=RecordingSessions(cli_session_factory, events, label="status:"),
        published=Publications(events),
        engine=FakeEngine(),
        asyncio_run=MagicMock(side_effect=asyncio.run),
    )
    created.sessions.install(monkeypatch, fetchers)
    created.status.install(monkeypatch, base_cve_fetcher_module)
    monkeypatch.setattr(task_publication, "publish_task", created.published)
    monkeypatch.setattr(fetchers, "engine", created.engine)
    monkeypatch.setattr(fetchers, "asyncio", SimpleNamespace(run=created.asyncio_run))
    try:
        yield created
    finally:
        created.cleanup()


@pytest.mark.integration
class TestSyncWrapper:
    def test_unresolvable_cve_reference_is_non_retryable(
        self, sync_world: _SyncWorld
    ) -> None:
        target = sync_world.target()
        probe = sync_world.fetcher()
        sync_world.sessions.hooks.append(_hide_cve)
        task = FakeTask()

        with capture_logs() as logs, pytest.raises(RuntimeError, match=_UNRESOLVED):
            fetchers._run_catch_up_sync(task, probe.name, target.ticket_id)

        task.retry.assert_not_called()
        failed = _errors(logs)
        assert [entry["event"] for entry in failed] == ["run_catch_up_failed"]
        assert failed[0]["cause"] == "RuntimeError"
        assert failed[0]["retries"] == 0
        assert probe.fetched == []
        assert sync_world.status.opened == []
        assert sync_world.asyncio_run.call_count == 1
        sync_world.engine.dispose.assert_awaited_once_with()

    @pytest.mark.parametrize("make_error", _RETRYABLE_ERRORS)
    def test_every_retryable_attempt_refreshes_failure_until_exhaustion(
        self, sync_world: _SyncWorld, make_error: Callable[[], Exception]
    ) -> None:
        """Each attempt is a fresh invocation that writes `failure` before
        its retry (5, 10, then 20 seconds); the streak start is preserved
        while `fetched_at` advances. Exhaustion emits one terminal ERROR."""
        target = sync_world.target()
        probe = sync_world.fetcher()
        errors: list[Exception] = []

        async def step(cve_id: str, session: AsyncSession) -> CVEFetchResult:
            errors.append(make_error())
            await _write(session, cve_id, register=None)
            raise errors[-1]

        probe.step = step
        states: list[SourceState | None] = []

        with capture_logs() as logs:
            for attempt, countdown in enumerate(_COUNTDOWNS):
                task = FakeTask(retries=attempt)
                with pytest.raises(RetryRequested):
                    fetchers._run_catch_up_sync(task, probe.name, target.ticket_id)
                task.retry.assert_called_once_with(exc=errors[-1], countdown=countdown)
                states.append(sync_world.state(target))
            final = FakeTask(retries=len(_COUNTDOWNS))
            with pytest.raises(type(errors[-1])) as raised:
                fetchers._run_catch_up_sync(final, probe.name, target.ticket_id)
            states.append(sync_world.state(target))

        assert raised.value is errors[-1]
        final.retry.assert_not_called()
        assert len(probe.fetched) == 4
        assert len({id(instance) for instance in probe.instances}) == 4
        written = [state for state in states if state is not None]
        assert len(written) == 4
        assert all(s.status == CVESourceFetchStatus.FAILURE for s in written)
        assert {s.first_failed_at for s in written} == {written[0].fetched_at}
        stamps = [s.fetched_at for s in written]
        assert stamps == sorted(stamps)
        assert len(set(stamps)) == 4
        failed = _events(logs, "run_catch_up_failed")
        assert len(failed) == 1
        assert failed[0]["retries"] == 3
        assert failed[0]["cause"] == type(errors[-1]).__name__
        assert sync_world.published.calls == []
        assert sync_world.asyncio_run.call_count == 4
        assert sync_world.engine.dispose.await_count == 4

    @pytest.mark.parametrize("later", ["success", "missing"])
    def test_later_attempt_overwrites_failure(
        self, sync_world: _SyncWorld, later: str
    ) -> None:
        target = sync_world.target()
        probe = sync_world.fetcher()
        first = httpx.ConnectError("connection refused")
        probe.step = _raises(first)
        task = FakeTask()

        with pytest.raises(RetryRequested):
            fetchers._run_catch_up_sync(task, probe.name, target.ticket_id)
        failed = sync_world.state(target)
        probe.step = _succeeds() if later == "success" else _raises(CVENotInSource())
        retry = FakeTask(retries=1)
        with capture_logs() as logs:
            fetchers._run_catch_up_sync(retry, probe.name, target.ticket_id)

        task.retry.assert_called_once_with(exc=first, countdown=5)
        retry.retry.assert_not_called()
        assert _errors(logs) == []
        assert failed is not None
        assert failed.status == CVESourceFetchStatus.FAILURE
        state = sync_world.state(target)
        assert state is not None
        assert state.status == (
            CVESourceFetchStatus.SUCCESS
            if later == "success"
            else CVESourceFetchStatus.MISSING
        )
        assert state.first_failed_at is None
        assert state.fetched_at > failed.fetched_at
        assert sync_world.asyncio_run.call_count == 2
        assert sync_world.engine.dispose.await_count == 2

    @pytest.mark.parametrize("make_signal", _SIGNALS)
    def test_control_signal_propagates_without_status_or_retry(
        self, sync_world: _SyncWorld, make_signal: Callable[[], BaseException]
    ) -> None:
        target = sync_world.target()
        probe = sync_world.fetcher()
        probe.step = _raises(make_signal())
        task = FakeTask()

        # `asyncio.run()` re-creates a `CancelledError` when the task ends
        # cancelled, so only the exception type is asserted.
        with capture_logs() as logs, pytest.raises(type(make_signal())):
            fetchers._run_catch_up_sync(task, probe.name, target.ticket_id)

        task.retry.assert_not_called()
        assert _events(logs, "run_catch_up_failed") == []
        assert sync_world.status.opened == []
        assert sync_world.state(target) is None
        assert sync_world.asyncio_run.call_count == 1
        sync_world.engine.dispose.assert_awaited_once_with()

    def test_failed_isolated_failure_write_keeps_original_retryable_exception(
        self, sync_world: _SyncWorld
    ) -> None:
        """An ordinary failure of the isolated `failure` write is logged once
        and suppressed; the original pre-finalization exception leaves
        `catch_up()` and reaches retry classification unchanged, and the
        previous latest source state is kept."""
        target = sync_world.target()
        probe = sync_world.fetcher()

        async def seed() -> None:
            async with sync_world.factory() as session:
                await cve_service.record_source_status(
                    session, target.cve_id, SOURCE, CVESourceFetchStatus.SUCCESS
                )
                await session.commit()

        asyncio.run(seed())
        before = sync_world.state(target)
        original = httpx.ConnectError("connection refused")
        probe.step = _raises(original)
        sync_world.status.failures["commit"] = RuntimeError(
            "example status write failure"
        )
        task = FakeTask()

        with capture_logs() as logs, pytest.raises(RetryRequested):
            fetchers._run_catch_up_sync(task, probe.name, target.ticket_id)

        task.retry.assert_called_once_with(exc=original, countdown=5)
        suppressed = _events(logs, ISOLATED_STATUS_WRITE_FAILED_EVENT)
        assert len(suppressed) == 1
        assert suppressed[0]["cve_id"] == target.cve
        assert suppressed[0]["status"] == CVESourceFetchStatus.FAILURE.value
        assert suppressed[0]["cause"] == "RuntimeError"
        assert _events(logs, "run_catch_up_failed") == []
        assert len(sync_world.status.opened) == 1
        assert before is not None
        assert sync_world.state(target) == before
