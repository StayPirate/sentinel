"""Tests for the `fetch_single_cve` task boundary
(backend/app/tasks/cve_tasks.py): `fetch_single_cve_async` and the
synchronous Celery wrapper `_fetch_single_cve_sync`.

See `docs/features/tickets/cve-service.md` (On-Demand Fetch:
fetch_single_cve — Orchestrator Behavior: one `asyncio.run()` per attempt,
exactly one `engine.dispose()` after all other cleanup on every path, no
`FetcherRun`, no stored result), `docs/features/platform/cve-fetcher-
infrastructure.md` (Retry Policy for `fetch_single`: at most three native
retries at 5, 10, and 20 seconds), `docs/features/platform/fetcher-
infrastructure.md` (Celery Integration: a task-module sub-operation outside
the fetcher registry), `docs/conventions.md` (Sync-to-Async Bridging,
Cross-Loop Pooled Connection Lifecycle), and
`docs/features/platform/testing-strategy.md` (On-Demand CVE Refetch; Sync
Entry-Point Tests) for the contract under test, with issue #799 decisions
D2 (thin wrapper, `bind=True`, explicit name, `max_retries=3`) and D7 (the
workflow returns the retry signal; the wrapper only raises `self.retry()`).

Two layers are exercised:

- the boundary with the service workflow replaced by an `AsyncMock`
  (`TestFetchSingleCveAsync`, `TestFetchSingleCveSyncWrapper`), so every
  return and exception path of the disposal and retry plumbing is
  deterministic;
- the synchronous wrapper over the real workflow
  (`TestSyncWrapperWithRealWorkflow`), in `def` tests. Its session factory
  is a `RecordingSessions` over the `NullPool` `cli_session_factory`, so no
  connection crosses event loops; setup and observation run in their own
  `asyncio.run()` calls, and Redis arrangement uses clients created on
  those loops against the worker database URL of `redis_client`.

Every test rebinds the module-level `engine` to a fake whose `dispose` is an
`AsyncMock` and defaults the session factory to one that fails when called.
The terminal matrix itself is covered by
`tests/test_services/test_fetch_single_cve_workflow.py`, and the real
two-attempt cross-loop regression by
`tests/test_tasks/test_cross_loop_engine_lifecycle.py`.
"""

from __future__ import annotations

import asyncio
import inspect
import uuid
from collections.abc import Awaitable, Callable, Iterator
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any, TypeVar
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest
import redis.asyncio as redis_asyncio
from celery.exceptions import SoftTimeLimitExceeded
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from structlog.testing import capture_logs

from app.celery_app import celery_app
from app.core.enums import CVESourceFetchStatus
from app.models.cve import CVE
from app.services import base_cve_fetcher, task_publication
from app.services.base_cve_fetcher import CVEFetchResult
from app.services.base_fetcher import FETCHER_REGISTRY
from app.services.cve_ingest import UpsertAction
from app.services.cve_service import (
    FETCH_SINGLE_CVE_TASK,
    FETCH_SINGLE_RETRY_DELAYS,
    FetchSingleRetry,
)
from app.services.fetcher_execution import FetcherConfigMissingError
from app.tasks import cve_tasks
from tests.support.cve_catch_up import (
    SOURCE,
    CVEProbe,
    FakeEngine,
    FakeTask,
    Publications,
    RecordingSessions,
    RetryRequested,
    SourceState,
    define_cve_fetcher,
    delete_fetcher_rows,
    fetcher_run_count,
    seed_fetcher_config,
    source_state,
)
from tests.support.fetch_single_cve import (
    PENDING_TTL,
    TASK,
    fictional_cve_id,
    new_token,
    pending_key,
)
from tests.support.redis import redis_url_from_client

T = TypeVar("T")

FETCHER = "fictional_nvd_fetcher"
CVE_ID = "CVE-2099-0001"
NVD = SOURCE.value
TOKEN = "Fictional_Token-0123456789abcdefghijklmnopq"
DISPOSE_FAILED = "fetch_single_cve_engine_dispose_failed"

_COUNTDOWNS = [
    pytest.param(0, 5, id="first-retry"),
    pytest.param(1, 10, id="second-retry"),
    pytest.param(2, 20, id="third-retry"),
]

_SIGNALS = [
    pytest.param(asyncio.CancelledError, id="cancelled"),
    pytest.param(SoftTimeLimitExceeded, id="soft-time-limit"),
    pytest.param(MemoryError, id="memory-error"),
]

_WORKFLOW_FAILURES = [
    pytest.param(lambda: RuntimeError("fictional failure"), id="runtime"),
    pytest.param(lambda: httpx.ConnectError("fictional refusal"), id="exhausted"),
    pytest.param(lambda: FetcherConfigMissingError("fictional"), id="config-missing"),
    *_SIGNALS,
]


def _sync(*arguments: Any, **keywords: Any) -> object:
    """The synchronous wrapper, typed to observe its runtime return value."""
    wrapper: Callable[..., object] = cve_tasks._fetch_single_cve_sync
    return wrapper(*arguments, **keywords)


def _payload() -> dict[str, object]:
    return {"fetcher_name": FETCHER, "cve_id": CVE_ID, "source": NVD, "token": TOKEN}


@pytest.fixture(autouse=True)
def fake_engine(monkeypatch: pytest.MonkeyPatch) -> FakeEngine:
    engine = FakeEngine()
    monkeypatch.setattr(cve_tasks, "engine", engine)
    return engine


@pytest.fixture(autouse=True)
def forbidden_session_factory(monkeypatch: pytest.MonkeyPatch) -> MagicMock:
    """Default session factory that fails the test when called."""
    factory = MagicMock(side_effect=AssertionError("must not open a session"))
    monkeypatch.setattr(cve_tasks, "async_session_factory", factory)
    return factory


@pytest.fixture
def workflow(monkeypatch: pytest.MonkeyPatch) -> AsyncMock:
    """Stand-in for the service workflow called by the task."""
    mock = AsyncMock(return_value=None)
    monkeypatch.setattr(cve_tasks, "run_fetch_single_cve", mock)
    return mock


@pytest.fixture
def asyncio_run_spy(monkeypatch: pytest.MonkeyPatch) -> MagicMock:
    """Replace the module's `asyncio` reference with a namespace whose
    `run` delegates to the real `asyncio.run`, counting calls."""
    spy = MagicMock(side_effect=asyncio.run)
    monkeypatch.setattr(cve_tasks, "asyncio", SimpleNamespace(run=spy))
    return spy


# ---------------------------------------------------------------------------
# Async boundary: delegation and exactly one disposal
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestFetchSingleCveAsync:
    async def test_success_delegates_payload_and_attempt_then_disposes_once(
        self,
        workflow: AsyncMock,
        fake_engine: FakeEngine,
        forbidden_session_factory: MagicMock,
    ) -> None:
        order: list[str] = []
        workflow.side_effect = lambda *args, **kwargs: order.append("workflow")
        fake_engine.dispose.side_effect = lambda: order.append("dispose")

        result = await cve_tasks.fetch_single_cve_async(
            FETCHER, CVE_ID, NVD, TOKEN, attempt=2
        )

        assert result is None
        workflow.assert_awaited_once_with(
            FETCHER,
            CVE_ID,
            NVD,
            TOKEN,
            attempt=2,
            session_factory=forbidden_session_factory,
        )
        fake_engine.dispose.assert_awaited_once_with()
        assert order == ["workflow", "dispose"]
        forbidden_session_factory.assert_not_called()

    async def test_retry_signal_is_returned_unchanged_after_one_disposal(
        self, workflow: AsyncMock, fake_engine: FakeEngine
    ) -> None:
        signal = FetchSingleRetry(countdown=10, cause=httpx.ConnectError("x"))
        workflow.return_value = signal

        result = await cve_tasks.fetch_single_cve_async(
            FETCHER, CVE_ID, NVD, TOKEN, attempt=1
        )

        assert result is signal
        fake_engine.dispose.assert_awaited_once_with()

    @pytest.mark.parametrize("make_error", _WORKFLOW_FAILURES)
    async def test_workflow_failure_propagates_after_one_disposal(
        self,
        make_error: Callable[[], BaseException],
        workflow: AsyncMock,
        fake_engine: FakeEngine,
    ) -> None:
        error = make_error()
        workflow.side_effect = error

        with capture_logs() as logs, pytest.raises(type(error)) as raised:
            await cve_tasks.fetch_single_cve_async(
                FETCHER, CVE_ID, NVD, TOKEN, attempt=0
            )

        assert raised.value is error
        fake_engine.dispose.assert_awaited_once_with()
        assert logs == []

    @pytest.mark.parametrize("returned", ["none", "retry-signal"])
    async def test_dispose_failure_after_a_normal_return_propagates(
        self, workflow: AsyncMock, fake_engine: FakeEngine, returned: str
    ) -> None:
        if returned == "retry-signal":
            workflow.return_value = FetchSingleRetry(5, httpx.ConnectError("x"))
        error = RuntimeError("fictional dispose failure")
        fake_engine.dispose.side_effect = error

        with capture_logs() as logs, pytest.raises(RuntimeError) as raised:
            await cve_tasks.fetch_single_cve_async(
                FETCHER, CVE_ID, NVD, TOKEN, attempt=0
            )

        assert raised.value is error
        fake_engine.dispose.assert_awaited_once_with()
        assert logs == []

    @pytest.mark.parametrize("make_error", _WORKFLOW_FAILURES)
    async def test_dispose_failure_does_not_mask_the_workflow_failure(
        self,
        make_error: Callable[[], BaseException],
        workflow: AsyncMock,
        fake_engine: FakeEngine,
    ) -> None:
        error = make_error()
        workflow.side_effect = error
        fake_engine.dispose.side_effect = RuntimeError("fictional dispose failure")

        with capture_logs() as logs, pytest.raises(type(error)) as raised:
            await cve_tasks.fetch_single_cve_async(
                FETCHER, CVE_ID, NVD, TOKEN, attempt=0
            )

        assert raised.value is error
        fake_engine.dispose.assert_awaited_once_with()
        assert logs == [{"event": DISPOSE_FAILED, "log_level": "warning"}]


# ---------------------------------------------------------------------------
# Synchronous wrapper: one event loop per attempt and native retry
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestFetchSingleCveSyncWrapper:
    def test_success_runs_one_event_loop_without_retry(
        self,
        workflow: AsyncMock,
        asyncio_run_spy: MagicMock,
        fake_engine: FakeEngine,
        forbidden_session_factory: MagicMock,
    ) -> None:
        task = FakeTask(retries=1)

        result = _sync(task, **_payload())

        assert result is None
        workflow.assert_awaited_once_with(
            FETCHER,
            CVE_ID,
            NVD,
            TOKEN,
            attempt=1,
            session_factory=forbidden_session_factory,
        )
        task.retry.assert_not_called()
        assert asyncio_run_spy.call_count == 1
        fake_engine.dispose.assert_awaited_once_with()

    @pytest.mark.parametrize(("retries", "countdown"), _COUNTDOWNS)
    def test_retry_signal_raises_self_retry_with_cause_and_countdown(
        self,
        retries: int,
        countdown: int,
        workflow: AsyncMock,
        asyncio_run_spy: MagicMock,
        fake_engine: FakeEngine,
    ) -> None:
        cause = httpx.ConnectError("fictional refusal")
        workflow.return_value = FetchSingleRetry(countdown=countdown, cause=cause)
        task = FakeTask(retries=retries)

        with pytest.raises(RetryRequested) as raised:
            cve_tasks._fetch_single_cve_sync(task, **_payload())

        assert raised.value is task.retry.return_value
        task.retry.assert_called_once_with(exc=cause, countdown=countdown)
        assert workflow.await_args is not None
        assert workflow.await_args.kwargs["attempt"] == retries
        assert asyncio_run_spy.call_count == 1
        fake_engine.dispose.assert_awaited_once_with()

    def test_exhausted_failure_propagates_without_retry(
        self,
        workflow: AsyncMock,
        asyncio_run_spy: MagicMock,
        fake_engine: FakeEngine,
    ) -> None:
        error = httpx.ConnectError("fictional refusal")
        workflow.side_effect = error
        task = FakeTask(retries=3)

        with pytest.raises(httpx.ConnectError) as raised:
            cve_tasks._fetch_single_cve_sync(task, **_payload())

        assert raised.value is error
        task.retry.assert_not_called()
        assert asyncio_run_spy.call_count == 1
        fake_engine.dispose.assert_awaited_once_with()

    @pytest.mark.parametrize("make_signal", _SIGNALS)
    def test_whole_run_signal_propagates_without_retry(
        self,
        make_signal: Callable[[], BaseException],
        workflow: AsyncMock,
        asyncio_run_spy: MagicMock,
        fake_engine: FakeEngine,
    ) -> None:
        signal = make_signal()
        workflow.side_effect = signal
        task = FakeTask()

        # `asyncio.run()` re-creates a `CancelledError` when the task ends
        # cancelled, so only the exception type is asserted.
        with pytest.raises(type(signal)):
            cve_tasks._fetch_single_cve_sync(task, **_payload())

        task.retry.assert_not_called()
        assert asyncio_run_spy.call_count == 1
        fake_engine.dispose.assert_awaited_once_with()

    def test_registered_task_retries_at_most_three_times(
        self, workflow: AsyncMock, fake_engine: FakeEngine
    ) -> None:
        """Through the registered bound task (eager `apply()`): a workflow
        that keeps requesting a retry is attempted with `request.retries`
        0 to 3 and then fails with the cause; no result is stored."""
        cause = httpx.ConnectError("fictional refusal")
        workflow.return_value = FetchSingleRetry(countdown=5, cause=cause)

        result = celery_app.tasks[TASK].apply(kwargs=_payload())

        assert [call.kwargs["attempt"] for call in workflow.await_args_list] == [
            0,
            1,
            2,
            3,
        ]
        assert result.failed()
        assert result.result is cause
        assert fake_engine.dispose.await_count == 4


# ---------------------------------------------------------------------------
# Synchronous wrapper over the real workflow
# ---------------------------------------------------------------------------


@dataclass
class _SyncTarget:
    cve_uuid: uuid.UUID
    cve_id: str


@dataclass
class _SyncWorld:
    """Committed rows, Redis URL, and substitutes of the real-workflow
    wrapper tests. Every operation of the test itself runs in its own
    `asyncio.run()`."""

    factory: async_sessionmaker[AsyncSession]
    redis_url: str
    sessions: RecordingSessions
    status: RecordingSessions
    published: Publications
    cve_ids: list[uuid.UUID] = field(default_factory=list)
    names: list[str] = field(default_factory=list)

    def target(self) -> _SyncTarget:
        async def seed() -> _SyncTarget:
            async with self.factory() as session:
                cve = CVE(cve_id=fictional_cve_id())
                session.add(cve)
                await session.commit()
                return _SyncTarget(cve.id, cve.cve_id)

        target = asyncio.run(seed())
        self.cve_ids.append(target.cve_uuid)
        return target

    def fetcher(self, *, enabled: bool = True) -> CVEProbe:
        probe = define_cve_fetcher(self.sessions.events)
        self.names.append(probe.name)
        asyncio.run(seed_fetcher_config(self.factory, probe.name, enabled=enabled))
        return probe

    def _redis(self, operation: Callable[[redis_asyncio.Redis], Awaitable[T]]) -> T:
        async def run() -> T:
            client = redis_asyncio.Redis.from_url(self.redis_url, decode_responses=True)
            try:
                return await operation(client)
            finally:
                await client.aclose()

        return asyncio.run(run())

    def marker(self, cve_id: str) -> str:
        token = new_token()

        async def write(client: redis_asyncio.Redis) -> None:
            assert await client.set(pending_key(cve_id), token, nx=True, ex=PENDING_TTL)

        self._redis(write)
        return token

    def marker_value(self, cve_id: str) -> str | None:
        async def read(client: redis_asyncio.Redis) -> str | None:
            value: str | None = await client.get(pending_key(cve_id))
            return value

        return self._redis(read)

    def state(self, target: _SyncTarget) -> SourceState | None:
        return asyncio.run(source_state(self.factory, target.cve_uuid))

    def run_count(self, fetcher_name: str) -> int:
        return asyncio.run(fetcher_run_count(self.factory, fetcher_name))

    def cleanup(self) -> None:
        async def delete_rows() -> None:
            async with self.factory() as session:
                await session.execute(delete(CVE).where(CVE.id.in_(self.cve_ids)))
                await session.commit()
            await delete_fetcher_rows(self.factory, self.names)

        asyncio.run(delete_rows())


@pytest.fixture
def sync_world(
    cli_session_factory: async_sessionmaker[AsyncSession],
    redis_client: redis_asyncio.Redis,
    monkeypatch: pytest.MonkeyPatch,
    isolated_fetcher_registries: None,
) -> Iterator[_SyncWorld]:
    """`redis_client` is used only for its worker-database URL and its
    redirection of the pending-marker boundary; no client object crosses
    event loops."""
    events: list[str] = []
    created = _SyncWorld(
        factory=cli_session_factory,
        redis_url=redis_url_from_client(redis_client),
        sessions=RecordingSessions(cli_session_factory, events),
        status=RecordingSessions(cli_session_factory, events, label="status:"),
        published=Publications(events),
    )
    created.sessions.install(monkeypatch, cve_tasks)
    created.status.install(monkeypatch, base_cve_fetcher)
    monkeypatch.setattr(task_publication, "publish_task", created.published)
    try:
        yield created
    finally:
        created.cleanup()


def _unchanged() -> Callable[[str, AsyncSession], Awaitable[CVEFetchResult]]:
    async def step(cve_id: str, session: AsyncSession) -> CVEFetchResult:
        assert await session.scalar(select(CVE.id).where(CVE.cve_id == cve_id))
        return CVEFetchResult(action=UpsertAction.UNCHANGED, post_ingest=None)

    return step


def _raising(
    make_error: Callable[[], BaseException], raised: list[BaseException]
) -> Callable[[str, AsyncSession], Awaitable[CVEFetchResult]]:
    async def step(cve_id: str, session: AsyncSession) -> CVEFetchResult:
        raised.append(make_error())
        raise raised[-1]

    return step


@pytest.mark.integration
class TestSyncWrapperWithRealWorkflow:
    def test_success_attempt_uses_one_event_loop_session_and_disposal(
        self,
        sync_world: _SyncWorld,
        asyncio_run_spy: MagicMock,
        fake_engine: FakeEngine,
    ) -> None:
        target = sync_world.target()
        probe = sync_world.fetcher()
        probe.step = _unchanged()
        token = sync_world.marker(target.cve_id)
        task = FakeTask()

        result = _sync(task, probe.name, target.cve_id, NVD, token)

        assert result is None
        task.retry.assert_not_called()
        assert probe.fetched == [target.cve_id]
        assert len(sync_world.sessions.opened) == 1
        assert sync_world.marker_value(target.cve_id) is None
        assert sync_world.run_count(probe.name) == 0
        assert asyncio_run_spy.call_count == 1
        fake_engine.dispose.assert_awaited_once_with()

    def test_retryable_attempts_retry_at_5_10_20_then_exhaust_with_failure(
        self,
        sync_world: _SyncWorld,
        asyncio_run_spy: MagicMock,
        fake_engine: FakeEngine,
    ) -> None:
        """Each attempt is a fresh event loop, session, and fetcher; the
        marker survives every retry and is released at exhaustion, when the
        isolated `failure` status is written within the same attempt."""
        target = sync_world.target()
        probe = sync_world.fetcher()
        errors: list[BaseException] = []
        probe.step = _raising(lambda: httpx.ConnectError("fictional refusal"), errors)
        token = sync_world.marker(target.cve_id)

        for attempt, countdown in enumerate((5, 10, 20)):
            task = FakeTask(retries=attempt)
            with pytest.raises(RetryRequested):
                cve_tasks._fetch_single_cve_sync(
                    task, probe.name, target.cve_id, NVD, token
                )
            task.retry.assert_called_once_with(exc=errors[-1], countdown=countdown)
            assert sync_world.marker_value(target.cve_id) == token
            assert sync_world.state(target) is None
        final = FakeTask(retries=3)
        with pytest.raises(httpx.ConnectError) as raised:
            cve_tasks._fetch_single_cve_sync(
                final, probe.name, target.cve_id, NVD, token
            )

        assert raised.value is errors[-1]
        final.retry.assert_not_called()
        state = sync_world.state(target)
        assert state is not None
        assert state.status == CVESourceFetchStatus.FAILURE
        assert sync_world.marker_value(target.cve_id) is None
        assert len({id(instance) for instance in probe.instances}) == 4
        assert len(sync_world.sessions.opened) == 4
        assert len(set(map(id, sync_world.sessions.opened))) == 4
        assert asyncio_run_spy.call_count == 4
        assert fake_engine.dispose.await_count == 4

    def test_disabled_fetcher_no_op_disposes_once(
        self,
        sync_world: _SyncWorld,
        asyncio_run_spy: MagicMock,
        fake_engine: FakeEngine,
    ) -> None:
        target = sync_world.target()
        probe = sync_world.fetcher(enabled=False)
        token = sync_world.marker(target.cve_id)
        task = FakeTask()

        result = _sync(task, probe.name, target.cve_id, NVD, token)

        assert result is None
        task.retry.assert_not_called()
        assert probe.fetched == []
        assert sync_world.marker_value(target.cve_id) is None
        assert asyncio_run_spy.call_count == 1
        fake_engine.dispose.assert_awaited_once_with()

    def test_malformed_payload_returns_without_session_or_retry(
        self,
        sync_world: _SyncWorld,
        asyncio_run_spy: MagicMock,
        fake_engine: FakeEngine,
    ) -> None:
        task = FakeTask()

        with capture_logs() as logs:
            result = _sync(task, FETCHER, "cve-2099-0001", NVD, TOKEN)

        assert result is None
        assert logs == [
            {
                "event": "fetch_single_cve_payload_invalid",
                "log_level": "warning",
                "invalid_fields": ["cve_id"],
            }
        ]
        task.retry.assert_not_called()
        assert sync_world.sessions.opened == []
        assert asyncio_run_spy.call_count == 1
        fake_engine.dispose.assert_awaited_once_with()

    def test_non_retryable_failure_propagates_after_one_disposal(
        self,
        sync_world: _SyncWorld,
        asyncio_run_spy: MagicMock,
        fake_engine: FakeEngine,
    ) -> None:
        target = sync_world.target()
        probe = sync_world.fetcher()
        errors: list[BaseException] = []
        probe.step = _raising(lambda: ValueError("fictional parse failure"), errors)
        token = sync_world.marker(target.cve_id)
        task = FakeTask()

        with pytest.raises(ValueError, match="fictional parse failure") as raised:
            cve_tasks._fetch_single_cve_sync(
                task, probe.name, target.cve_id, NVD, token
            )

        assert raised.value is errors[-1]
        task.retry.assert_not_called()
        state = sync_world.state(target)
        assert state is not None
        assert state.status == CVESourceFetchStatus.FAILURE
        assert sync_world.marker_value(target.cve_id) is None
        assert asyncio_run_spy.call_count == 1
        fake_engine.dispose.assert_awaited_once_with()

    @pytest.mark.parametrize("make_signal", _SIGNALS)
    def test_whole_run_signal_keeps_the_marker_and_disposes_once(
        self,
        sync_world: _SyncWorld,
        asyncio_run_spy: MagicMock,
        fake_engine: FakeEngine,
        make_signal: Callable[[], BaseException],
    ) -> None:
        target = sync_world.target()
        probe = sync_world.fetcher()
        probe.step = _raising(make_signal, [])
        token = sync_world.marker(target.cve_id)
        task = FakeTask()

        with pytest.raises(type(make_signal())):
            cve_tasks._fetch_single_cve_sync(
                task, probe.name, target.cve_id, NVD, token
            )

        task.retry.assert_not_called()
        assert sync_world.marker_value(target.cve_id) == token
        assert sync_world.status.opened == []
        assert sync_world.state(target) is None
        assert asyncio_run_spy.call_count == 1
        fake_engine.dispose.assert_awaited_once_with()


# ---------------------------------------------------------------------------
# Task registration
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestFetchSingleCveTaskRegistration:
    def test_registered_under_exact_name_with_four_payload_arguments(self) -> None:
        task = celery_app.tasks[TASK]

        assert task.name == TASK
        assert FETCH_SINGLE_CVE_TASK == TASK
        assert cve_tasks.fetch_single_cve_task.name == TASK
        assert task.run.__func__ is cve_tasks._fetch_single_cve_sync
        parameters = inspect.signature(task.run).parameters.values()
        assert [(p.name, p.kind) for p in parameters] == [
            (name, inspect.Parameter.POSITIONAL_OR_KEYWORD)
            for name in ("fetcher_name", "cve_id", "source", "token")
        ]

    def test_bound_with_three_native_retries_and_no_stored_result(self) -> None:
        task = celery_app.tasks[TASK]

        assert task.max_retries == 3
        assert FETCH_SINGLE_RETRY_DELAYS == (5, 10, 20)
        assert not getattr(task, "autoretry_for", None)
        assert task.ignore_result is True
        assert celery_app.conf.result_backend is None

    def test_is_a_sub_operation_outside_registry_and_schedule(self) -> None:
        assert TASK not in FETCHER_REGISTRY
        scheduled: dict[str, Any] = celery_app.conf.beat_schedule
        assert TASK not in {entry["task"] for entry in scheduled.values()}
