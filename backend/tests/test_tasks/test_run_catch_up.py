"""Tests for the generic `run_catch_up` Celery task
(backend/app/tasks/fetchers.py).

See `docs/features/platform/fetcher-infrastructure.md` (Per-Ticket
Catch-Up: Override-point contract, Celery task wrapper steps 1-6,
Interface contract; `fetch_single()` and `catch_up()` Lifecycle; Error
Message Sanitization — `SoftTimeLimitExceeded` handling convention),
`docs/features/platform/networking.md` (Celery Retry Classification), and
`docs/conventions.md` (Sync-to-Async Bridging, Cross-Loop Pooled
Connection Lifecycle) for the contract under test.

Two layers are exercised:

- `run_catch_up_async`, awaited directly. Paths that reach the enabled
  read use committed `FetcherConfig` rows: the workflow opens its own
  sessions through the module-level `async_session_factory` reference in
  `app.tasks.fetchers`, which the `catch_up_database` fixture redirects to
  `real_session_factory` (bound to the test engine); teardown deletes the
  committed rows explicitly.
- `_run_catch_up_sync`, the synchronous Celery wrapper, called with a fake
  bound task (`request.retries`, `retry()`). These tests are `def` (see
  testing-strategy.md, Sync Entry-Point Tests) and run the real async
  workflow inside the wrapper's own `asyncio.run()`. They stub the
  enabled read and the session factory, except the missing-configuration
  case, which uses the `NullPool` `cli_session_factory` so no connection
  crosses event loops.

Every test rebinds the module-level `engine` to a fake whose `dispose` is
an `AsyncMock` (`AsyncEngine.dispose` is read-only on the real engine),
and defaults the session factory to one that fails when called, proving
that paths without database work open no session. Test-only fetchers are
direct `BaseFetcher` subclasses with a custom `catch_up()` override,
registered under the shared `isolated_fetcher_registries` fixture. The
wrapper doubles come from `tests/support/cve_catch_up.py`. The default CVE
`catch_up()` contract is covered by
`tests/test_services/test_cve_fetcher_catch_up.py`.

The structured `celery_task_id` field comes from the task correlation
context; one test binds it and merges context variables into the
captured events.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncGenerator, Callable, MutableMapping
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import httpx
import pytest
import pytest_asyncio
import redis.asyncio as redis_asyncio
from celery.exceptions import SoftTimeLimitExceeded
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from structlog.contextvars import (
    bind_contextvars,
    merge_contextvars,
    unbind_contextvars,
)
from structlog.testing import capture_logs

import app.services.base_fetcher as base_fetcher_module
from app.models.fetcher_config import FetcherConfig
from app.models.fetcher_run import FetcherRun
from app.services.base_cve_fetcher import CVENotInSource
from app.services.base_fetcher import BaseFetcher
from app.services.fetcher_execution import FetcherConfigMissingError
from app.tasks import fetchers
from tests.support.cve_catch_up import (
    FakeEngine,
    FakeHttpClient,
    FakeTask,
    RetryRequested,
)

pytestmark = pytest.mark.usefixtures("isolated_fetcher_registries")

LogEntry = MutableMapping[str, Any]


# ---------------------------------------------------------------------------
# Test doubles and helpers
# ---------------------------------------------------------------------------


class _SessionContext:
    """Async context manager returning a fixed stand-in session."""

    def __init__(self, session: object) -> None:
        self.session = session

    async def __aenter__(self) -> object:
        return self.session

    async def __aexit__(self, *exc_info: object) -> bool:
        return False


@dataclass
class _Probe:
    """Observations of one test-only catch-up fetcher class."""

    name: str
    calls: list[tuple[str, object]] = field(default_factory=list)
    instances: list[BaseFetcher] = field(default_factory=list)
    http_clients: list[object] = field(default_factory=list)


def _define_catch_up_fetcher(
    *, raises: BaseException | None = None, use_http_client: bool = False
) -> _Probe:
    """Register a direct `BaseFetcher` subclass whose `catch_up()` records
    its call, optionally touches `self.http_client`, then optionally
    raises `raises`."""
    fetcher_name = f"test_catch_up_{uuid4().hex}"
    probe = _Probe(name=fetcher_name)

    class _CatchUpProbeFetcher(BaseFetcher):
        name = fetcher_name
        description = "Test-only catch-up probe"
        default_schedule = "0 * * * *"
        participates_in_catch_up = True

        async def execute(self, session: AsyncSession) -> None:
            return None

        async def catch_up(self, ticket_id: str, session: AsyncSession) -> None:
            probe.calls.append((ticket_id, session))
            probe.instances.append(self)
            if use_http_client:
                probe.http_clients.append(self.http_client)
            if raises is not None:
                raise raises

    return probe


def _ticket_id() -> str:
    return str(uuid4())


def _events(logs: list[LogEntry], event: str) -> list[LogEntry]:
    return [entry for entry in logs if entry["event"] == event]


def _errors(logs: list[LogEntry]) -> list[LogEntry]:
    return [entry for entry in logs if entry["log_level"] == "error"]


def _http_status_error(status_code: int) -> httpx.HTTPStatusError:
    request = httpx.Request("GET", "https://catch-up.example.invalid/item")
    response = httpx.Response(status_code, request=request)
    return httpx.HTTPStatusError(
        f"HTTP {status_code}", request=request, response=response
    )


_RETRYABLE_ERRORS = [
    pytest.param(lambda: httpx.ConnectError("connection refused"), id="connect-error"),
    pytest.param(lambda: httpx.ReadTimeout("read timed out"), id="read-timeout"),
    pytest.param(lambda: _http_status_error(503), id="http-503"),
    pytest.param(lambda: _http_status_error(429), id="http-429"),
]

_NON_RETRYABLE_ERRORS = [
    pytest.param(lambda: ValueError("unparsable payload"), id="value-error"),
    pytest.param(lambda: RuntimeError("programming error"), id="runtime-error"),
    pytest.param(lambda: _http_status_error(404), id="http-404"),
]

_INVALID_IMPLEMENTATION_ERRORS = [
    pytest.param(lambda: NotImplementedError("no catch-up"), id="not-implemented"),
    pytest.param(CVENotInSource, id="leaked-cve-not-in-source"),
]

_WHOLE_RUN_SIGNALS = [
    pytest.param(asyncio.CancelledError, id="cancelled"),
    pytest.param(SoftTimeLimitExceeded, id="soft-time-limit"),
    pytest.param(MemoryError, id="memory-error"),
]

_MALFORMED_TICKET_IDS = [
    pytest.param("not-a-uuid", id="non-uuid-string"),
    pytest.param("", id="empty-string"),
    pytest.param("SNTL-42", id="public-ticket-id"),
    pytest.param(12345, id="integer"),
    pytest.param(None, id="none"),
]


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def fake_engine(monkeypatch: pytest.MonkeyPatch) -> FakeEngine:
    engine = FakeEngine()
    monkeypatch.setattr(fetchers, "engine", engine)
    return engine


@pytest.fixture(autouse=True)
def forbidden_session_factory(monkeypatch: pytest.MonkeyPatch) -> MagicMock:
    """Default session factory that fails the test when called; fixtures
    that need database work rebind it afterwards."""
    factory = MagicMock(side_effect=AssertionError("must not open a session"))
    monkeypatch.setattr(fetchers, "async_session_factory", factory)
    return factory


@pytest.fixture
def asyncio_run_spy(monkeypatch: pytest.MonkeyPatch) -> MagicMock:
    """Replace the module's `asyncio` reference with a namespace whose
    `run` delegates to the real `asyncio.run`, counting calls."""
    spy = MagicMock(side_effect=asyncio.run)
    monkeypatch.setattr(fetchers, "asyncio", SimpleNamespace(run=spy))
    return spy


@pytest.fixture
def stub_database(monkeypatch: pytest.MonkeyPatch) -> AsyncMock:
    """No-database stand-ins for sync wrapper tests: an enabled read that
    reports `True` and a session factory yielding a stand-in session."""
    enabled_read = AsyncMock(return_value=True)
    monkeypatch.setattr(fetchers, "get_fetcher_enabled", enabled_read)
    monkeypatch.setattr(
        fetchers, "async_session_factory", lambda: _SessionContext(object())
    )
    return enabled_read


class _CatchUpDatabase:
    def __init__(self, factory: async_sessionmaker[AsyncSession]) -> None:
        self._factory = factory
        self.fetcher_names: list[str] = []

    async def seed_config(self, fetcher_name: str, *, enabled: bool) -> None:
        self.fetcher_names.append(fetcher_name)
        async with self._factory() as session:
            session.add(FetcherConfig(fetcher_name=fetcher_name, enabled=enabled))
            await session.commit()

    async def run_count(self, fetcher_name: str) -> int:
        async with self._factory() as session:
            count = await session.scalar(
                select(func.count())
                .select_from(FetcherRun)
                .where(FetcherRun.fetcher_name == fetcher_name)
            )
        return int(count or 0)


@pytest_asyncio.fixture
async def catch_up_database(
    real_session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> AsyncGenerator[_CatchUpDatabase]:
    """Redirect the workflow's session factory to the test database and
    commit `FetcherConfig` rows on request.

    Rows are real commits, not covered by the per-test savepoint
    rollback; teardown deletes every seeded row (and any `FetcherRun` a
    regression might have created for those names) in FK-safe order.
    """
    monkeypatch.setattr(fetchers, "async_session_factory", real_session_factory)
    database = _CatchUpDatabase(real_session_factory)
    try:
        yield database
    finally:
        if database.fetcher_names:
            async with real_session_factory() as session:
                await session.execute(
                    delete(FetcherRun).where(
                        FetcherRun.fetcher_name.in_(database.fetcher_names)
                    )
                )
                await session.execute(
                    delete(FetcherConfig).where(
                        FetcherConfig.fetcher_name.in_(database.fetcher_names)
                    )
                )
                await session.commit()


# ---------------------------------------------------------------------------
# Async workflow: argument validation and fetcher resolution
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestRunCatchUpAsyncWithoutDatabase:
    @pytest.mark.parametrize("ticket_id", _MALFORMED_TICKET_IDS)
    async def test_malformed_ticket_id_logs_one_error_and_raises(
        self,
        ticket_id: object,
        fake_engine: FakeEngine,
        forbidden_session_factory: MagicMock,
    ) -> None:
        probe = _define_catch_up_fetcher()

        with (
            capture_logs() as logs,
            pytest.raises(fetchers.CatchUpTicketIdError),
        ):
            await fetchers.run_catch_up_async(probe.name, cast(str, ticket_id))

        errors = _errors(logs)
        assert len(errors) == 1
        assert errors[0]["event"] == "run_catch_up_invalid_ticket_id"
        assert errors[0]["ticket_id"] == ticket_id
        assert errors[0]["fetcher_name"] == probe.name
        assert errors[0]["cause"]
        forbidden_session_factory.assert_not_called()
        assert probe.calls == []
        fake_engine.dispose.assert_awaited_once_with()

    async def test_malformed_ticket_id_is_rejected_before_fetcher_resolution(
        self, forbidden_session_factory: MagicMock
    ) -> None:
        """An unknown fetcher does not mask the caller-contract failure."""
        with (
            capture_logs() as logs,
            pytest.raises(fetchers.CatchUpTicketIdError),
        ):
            await fetchers.run_catch_up_async("ghost_catch_up_fetcher", "not-a-uuid")

        assert [entry["event"] for entry in _errors(logs)] == [
            "run_catch_up_invalid_ticket_id"
        ]
        forbidden_session_factory.assert_not_called()

    async def test_unknown_fetcher_logs_error_and_returns(
        self, fake_engine: FakeEngine, forbidden_session_factory: MagicMock
    ) -> None:
        ticket_id = _ticket_id()

        with capture_logs() as logs:
            await fetchers.run_catch_up_async("ghost_catch_up_fetcher", ticket_id)

        errors = _errors(logs)
        assert len(errors) == 1
        assert errors[0]["event"] == "run_catch_up_unknown_fetcher"
        assert errors[0]["fetcher_name"] == "ghost_catch_up_fetcher"
        assert errors[0]["ticket_id"] == ticket_id
        forbidden_session_factory.assert_not_called()
        fake_engine.dispose.assert_awaited_once_with()


@pytest.mark.integration
class TestRunCatchUpAsyncResolution:
    async def test_disabled_fetcher_logs_info_and_skips_catch_up(
        self, catch_up_database: _CatchUpDatabase, fake_engine: FakeEngine
    ) -> None:
        probe = _define_catch_up_fetcher()
        await catch_up_database.seed_config(probe.name, enabled=False)
        ticket_id = _ticket_id()

        with capture_logs() as logs:
            await fetchers.run_catch_up_async(probe.name, ticket_id)

        skipped = _events(logs, "run_catch_up_fetcher_disabled")
        assert len(skipped) == 1
        assert skipped[0]["log_level"] == "info"
        assert skipped[0]["fetcher_name"] == probe.name
        assert skipped[0]["ticket_id"] == ticket_id
        assert _errors(logs) == []
        assert probe.calls == []
        fake_engine.dispose.assert_awaited_once_with()
        assert await catch_up_database.run_count(probe.name) == 0

    async def test_missing_fetcher_config_raises_without_invoking_catch_up(
        self, catch_up_database: _CatchUpDatabase, fake_engine: FakeEngine
    ) -> None:
        probe = _define_catch_up_fetcher()

        with pytest.raises(FetcherConfigMissingError, match=probe.name):
            await fetchers.run_catch_up_async(probe.name, _ticket_id())

        assert probe.calls == []
        fake_engine.dispose.assert_awaited_once_with()
        assert await catch_up_database.run_count(probe.name) == 0

    async def test_enabled_fetcher_invokes_catch_up_once_with_session(
        self, catch_up_database: _CatchUpDatabase, fake_engine: FakeEngine
    ) -> None:
        probe = _define_catch_up_fetcher()
        await catch_up_database.seed_config(probe.name, enabled=True)
        ticket_id = _ticket_id()

        with capture_logs() as logs:
            await fetchers.run_catch_up_async(probe.name, ticket_id)

        assert len(probe.calls) == 1
        called_ticket_id, called_session = probe.calls[0]
        assert called_ticket_id == ticket_id
        assert type(called_ticket_id) is str
        assert isinstance(called_session, AsyncSession)
        assert _errors(logs) == []
        fake_engine.dispose.assert_awaited_once_with()
        assert await catch_up_database.run_count(probe.name) == 0

    async def test_success_creates_no_fetch_pending_key(
        self,
        catch_up_database: _CatchUpDatabase,
        redis_client: redis_asyncio.Redis,
    ) -> None:
        probe = _define_catch_up_fetcher()
        await catch_up_database.seed_config(probe.name, enabled=True)

        await fetchers.run_catch_up_async(probe.name, _ticket_id())

        assert len(probe.calls) == 1
        assert await redis_client.keys("fetch_pending:*") == []


# ---------------------------------------------------------------------------
# Async workflow: exceptions raised by catch_up()
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestRunCatchUpAsyncExceptions:
    @pytest.mark.parametrize("make_error", _RETRYABLE_ERRORS + _NON_RETRYABLE_ERRORS)
    async def test_ordinary_exception_propagates_unchanged(
        self,
        make_error: Callable[[], Exception],
        catch_up_database: _CatchUpDatabase,
        fake_engine: FakeEngine,
    ) -> None:
        error = make_error()
        probe = _define_catch_up_fetcher(raises=error)
        await catch_up_database.seed_config(probe.name, enabled=True)

        with pytest.raises(type(error)) as exc_info:
            await fetchers.run_catch_up_async(probe.name, _ticket_id())

        assert exc_info.value is error
        assert len(probe.calls) == 1
        fake_engine.dispose.assert_awaited_once_with()
        assert await catch_up_database.run_count(probe.name) == 0

    @pytest.mark.parametrize("make_error", _INVALID_IMPLEMENTATION_ERRORS)
    async def test_invalid_implementation_logs_error_and_returns(
        self,
        make_error: Callable[[], Exception],
        catch_up_database: _CatchUpDatabase,
        fake_engine: FakeEngine,
    ) -> None:
        error = make_error()
        probe = _define_catch_up_fetcher(raises=error)
        await catch_up_database.seed_config(probe.name, enabled=True)
        ticket_id = _ticket_id()

        with capture_logs() as logs:
            await fetchers.run_catch_up_async(probe.name, ticket_id)

        errors = _errors(logs)
        assert len(errors) == 1
        assert errors[0]["event"] == "run_catch_up_invalid_implementation"
        assert errors[0]["fetcher_name"] == probe.name
        assert errors[0]["ticket_id"] == ticket_id
        assert errors[0]["cause"] == type(error).__name__
        fake_engine.dispose.assert_awaited_once_with()

    @pytest.mark.parametrize("make_signal", _WHOLE_RUN_SIGNALS)
    async def test_whole_run_signal_propagates_unchanged(
        self,
        make_signal: Callable[[], BaseException],
        catch_up_database: _CatchUpDatabase,
        fake_engine: FakeEngine,
    ) -> None:
        signal = make_signal()
        probe = _define_catch_up_fetcher(raises=signal)
        await catch_up_database.seed_config(probe.name, enabled=True)

        with pytest.raises(type(signal)) as exc_info:
            await fetchers.run_catch_up_async(probe.name, _ticket_id())

        assert exc_info.value is signal
        fake_engine.dispose.assert_awaited_once_with()


# ---------------------------------------------------------------------------
# Async workflow: HTTP client teardown and engine disposal
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestRunCatchUpAsyncCleanup:
    async def test_http_client_closed_before_engine_disposal_on_success(
        self,
        catch_up_database: _CatchUpDatabase,
        fake_engine: FakeEngine,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        order: list[str] = []
        client = FakeHttpClient(AsyncMock(side_effect=lambda: order.append("aclose")))
        fake_engine.dispose.side_effect = lambda: order.append("dispose")
        monkeypatch.setattr(
            base_fetcher_module, "create_http_client", lambda **_: client
        )
        probe = _define_catch_up_fetcher(use_http_client=True)
        await catch_up_database.seed_config(probe.name, enabled=True)

        await fetchers.run_catch_up_async(probe.name, _ticket_id())

        assert probe.http_clients == [client]
        client.aclose.assert_awaited_once_with()
        assert probe.instances[0]._http_client is None
        assert order == ["aclose", "dispose"]

    async def test_http_client_closed_and_reset_on_exception(
        self,
        catch_up_database: _CatchUpDatabase,
        fake_engine: FakeEngine,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        client = FakeHttpClient(AsyncMock())
        monkeypatch.setattr(
            base_fetcher_module, "create_http_client", lambda **_: client
        )
        error = httpx.ConnectError("connection refused")
        probe = _define_catch_up_fetcher(raises=error, use_http_client=True)
        await catch_up_database.seed_config(probe.name, enabled=True)

        with pytest.raises(httpx.ConnectError):
            await fetchers.run_catch_up_async(probe.name, _ticket_id())

        assert probe.http_clients == [client]
        client.aclose.assert_awaited_once_with()
        assert probe.instances[0]._http_client is None
        fake_engine.dispose.assert_awaited_once_with()

    async def test_failing_http_client_close_does_not_mask_primary_exception(
        self,
        catch_up_database: _CatchUpDatabase,
        fake_engine: FakeEngine,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        client = FakeHttpClient(AsyncMock(side_effect=RuntimeError("close failed")))
        monkeypatch.setattr(
            base_fetcher_module, "create_http_client", lambda **_: client
        )
        error = ValueError("primary failure")
        probe = _define_catch_up_fetcher(raises=error, use_http_client=True)
        await catch_up_database.seed_config(probe.name, enabled=True)

        with (
            capture_logs() as logs,
            pytest.raises(ValueError, match="primary failure") as exc_info,
        ):
            await fetchers.run_catch_up_async(probe.name, _ticket_id())

        assert exc_info.value is error
        assert probe.http_clients == [client]
        client.aclose.assert_awaited_once_with()
        assert probe.instances[0]._http_client is None
        assert len(_events(logs, "fetcher_http_client_close_failed")) == 1
        fake_engine.dispose.assert_awaited_once_with()

    async def test_unused_http_client_is_never_created(
        self,
        catch_up_database: _CatchUpDatabase,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        create = MagicMock(side_effect=AssertionError("must not create a client"))
        monkeypatch.setattr(base_fetcher_module, "create_http_client", create)
        probe = _define_catch_up_fetcher()
        await catch_up_database.seed_config(probe.name, enabled=True)

        await fetchers.run_catch_up_async(probe.name, _ticket_id())

        create.assert_not_called()
        assert probe.instances[0]._http_client is None


@pytest.mark.unit
class TestRunCatchUpAsyncEngineDisposalFailure:
    async def test_dispose_failure_does_not_mask_primary_exception(
        self, fake_engine: FakeEngine
    ) -> None:
        fake_engine.dispose.side_effect = RuntimeError("dispose failed")

        with (
            capture_logs() as logs,
            pytest.raises(fetchers.CatchUpTicketIdError),
        ):
            await fetchers.run_catch_up_async("ghost_catch_up_fetcher", "not-a-uuid")

        fake_engine.dispose.assert_awaited_once_with()
        warnings = _events(logs, "run_catch_up_engine_dispose_failed")
        assert len(warnings) == 1
        assert warnings[0]["log_level"] == "warning"

    async def test_dispose_failure_on_successful_path_propagates(
        self, fake_engine: FakeEngine
    ) -> None:
        fake_engine.dispose.side_effect = RuntimeError("dispose failed")

        with pytest.raises(RuntimeError, match="dispose failed"):
            await fetchers.run_catch_up_async("ghost_catch_up_fetcher", _ticket_id())

        fake_engine.dispose.assert_awaited_once_with()


# ---------------------------------------------------------------------------
# Synchronous Celery wrapper
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestRunCatchUpSyncWrapper:
    def test_success_returns_without_retry(
        self,
        stub_database: AsyncMock,
        asyncio_run_spy: MagicMock,
        fake_engine: FakeEngine,
    ) -> None:
        probe = _define_catch_up_fetcher()
        task = FakeTask()
        ticket_id = _ticket_id()

        with capture_logs() as logs:
            fetchers._run_catch_up_sync(task, probe.name, ticket_id)

        assert [call[0] for call in probe.calls] == [ticket_id]
        stub_database.assert_awaited_once()
        task.retry.assert_not_called()
        assert _errors(logs) == []
        assert asyncio_run_spy.call_count == 1
        fake_engine.dispose.assert_awaited_once_with()

    @pytest.mark.parametrize("ticket_id", _MALFORMED_TICKET_IDS)
    def test_malformed_ticket_id_fails_without_retry_or_terminal_log(
        self,
        ticket_id: object,
        asyncio_run_spy: MagicMock,
        fake_engine: FakeEngine,
        forbidden_session_factory: MagicMock,
    ) -> None:
        probe = _define_catch_up_fetcher()
        task = FakeTask()

        with (
            capture_logs() as logs,
            pytest.raises(fetchers.CatchUpTicketIdError),
        ):
            fetchers._run_catch_up_sync(task, probe.name, cast(str, ticket_id))

        assert [entry["event"] for entry in _errors(logs)] == [
            "run_catch_up_invalid_ticket_id"
        ]
        assert _events(logs, "run_catch_up_failed") == []
        task.retry.assert_not_called()
        forbidden_session_factory.assert_not_called()
        assert probe.calls == []
        assert asyncio_run_spy.call_count == 1
        fake_engine.dispose.assert_awaited_once_with()

    def test_unknown_fetcher_returns_without_retry(
        self, asyncio_run_spy: MagicMock, fake_engine: FakeEngine
    ) -> None:
        task = FakeTask()

        with capture_logs() as logs:
            fetchers._run_catch_up_sync(task, "ghost_catch_up_fetcher", _ticket_id())

        assert [entry["event"] for entry in _errors(logs)] == [
            "run_catch_up_unknown_fetcher"
        ]
        task.retry.assert_not_called()
        assert asyncio_run_spy.call_count == 1
        fake_engine.dispose.assert_awaited_once_with()

    @pytest.mark.parametrize(
        ("retries", "countdown"),
        [
            pytest.param(0, 5, id="first-retry"),
            pytest.param(1, 10, id="second-retry"),
            pytest.param(2, 20, id="third-retry"),
        ],
    )
    @pytest.mark.parametrize("make_error", _RETRYABLE_ERRORS)
    def test_retryable_exception_retries_with_backoff(
        self,
        make_error: Callable[[], Exception],
        retries: int,
        countdown: int,
        stub_database: AsyncMock,
        asyncio_run_spy: MagicMock,
        fake_engine: FakeEngine,
    ) -> None:
        error = make_error()
        probe = _define_catch_up_fetcher(raises=error)
        task = FakeTask(retries=retries)

        with capture_logs() as logs, pytest.raises(RetryRequested):
            fetchers._run_catch_up_sync(task, probe.name, _ticket_id())

        task.retry.assert_called_once_with(exc=error, countdown=countdown)
        assert _events(logs, "run_catch_up_failed") == []
        assert len(probe.calls) == 1
        assert asyncio_run_spy.call_count == 1
        fake_engine.dispose.assert_awaited_once_with()

    @pytest.mark.parametrize("make_error", _RETRYABLE_ERRORS)
    def test_retryable_exception_after_exhaustion_fails_terminally(
        self,
        make_error: Callable[[], Exception],
        stub_database: AsyncMock,
        asyncio_run_spy: MagicMock,
        fake_engine: FakeEngine,
    ) -> None:
        error = make_error()
        probe = _define_catch_up_fetcher(raises=error)
        task = FakeTask(retries=3)
        ticket_id = _ticket_id()

        with capture_logs() as logs, pytest.raises(type(error)) as exc_info:
            fetchers._run_catch_up_sync(task, probe.name, ticket_id)

        assert exc_info.value is error
        task.retry.assert_not_called()
        failed = _events(logs, "run_catch_up_failed")
        assert len(failed) == 1
        assert failed[0]["log_level"] == "error"
        assert failed[0]["fetcher_name"] == probe.name
        assert failed[0]["ticket_id"] == ticket_id
        assert failed[0]["cause"] == type(error).__name__
        assert failed[0]["retries"] == 3
        assert asyncio_run_spy.call_count == 1
        fake_engine.dispose.assert_awaited_once_with()

    @pytest.mark.parametrize("make_error", _NON_RETRYABLE_ERRORS)
    def test_non_retryable_exception_fails_terminally_without_retry(
        self,
        make_error: Callable[[], Exception],
        stub_database: AsyncMock,
        asyncio_run_spy: MagicMock,
        fake_engine: FakeEngine,
    ) -> None:
        error = make_error()
        probe = _define_catch_up_fetcher(raises=error)
        task = FakeTask()
        ticket_id = _ticket_id()

        with capture_logs() as logs, pytest.raises(type(error)) as exc_info:
            fetchers._run_catch_up_sync(task, probe.name, ticket_id)

        assert exc_info.value is error
        task.retry.assert_not_called()
        errors = _errors(logs)
        assert len(errors) == 1
        assert errors[0]["event"] == "run_catch_up_failed"
        assert errors[0]["fetcher_name"] == probe.name
        assert errors[0]["ticket_id"] == ticket_id
        assert errors[0]["cause"] == type(error).__name__
        assert errors[0]["retries"] == 0
        # The cause is the exception class name, never the exception text.
        assert str(error) not in errors[0].values()
        assert asyncio_run_spy.call_count == 1
        fake_engine.dispose.assert_awaited_once_with()

    def test_terminal_and_malformed_errors_carry_bound_celery_task_id(
        self, stub_database: AsyncMock
    ) -> None:
        """The task-bound `celery_task_id` (bound by `task_prerun`) reaches
        both the malformed-UUID ERROR and the terminal ERROR."""
        probe = _define_catch_up_fetcher(raises=ValueError("unparsable payload"))
        celery_task_id = str(uuid4())
        bind_contextvars(celery_task_id=celery_task_id)
        try:
            with capture_logs(processors=[merge_contextvars]) as logs:
                with pytest.raises(ValueError, match="unparsable payload"):
                    fetchers._run_catch_up_sync(FakeTask(), probe.name, _ticket_id())
                with pytest.raises(fetchers.CatchUpTicketIdError):
                    fetchers._run_catch_up_sync(FakeTask(), probe.name, "not-a-uuid")
        finally:
            unbind_contextvars("celery_task_id")

        errors = _errors(logs)
        assert [entry["event"] for entry in errors] == [
            "run_catch_up_failed",
            "run_catch_up_invalid_ticket_id",
        ]
        assert all(entry["celery_task_id"] == celery_task_id for entry in errors)

    @pytest.mark.parametrize("make_error", _INVALID_IMPLEMENTATION_ERRORS)
    def test_invalid_implementation_returns_without_retry(
        self,
        make_error: Callable[[], Exception],
        stub_database: AsyncMock,
        asyncio_run_spy: MagicMock,
        fake_engine: FakeEngine,
    ) -> None:
        probe = _define_catch_up_fetcher(raises=make_error())
        task = FakeTask()

        with capture_logs() as logs:
            fetchers._run_catch_up_sync(task, probe.name, _ticket_id())

        task.retry.assert_not_called()
        assert [entry["event"] for entry in _errors(logs)] == [
            "run_catch_up_invalid_implementation"
        ]
        assert asyncio_run_spy.call_count == 1
        fake_engine.dispose.assert_awaited_once_with()

    @pytest.mark.parametrize("make_signal", _WHOLE_RUN_SIGNALS)
    def test_whole_run_signal_propagates_without_retry_or_terminal_log(
        self,
        make_signal: Callable[[], BaseException],
        stub_database: AsyncMock,
        asyncio_run_spy: MagicMock,
        fake_engine: FakeEngine,
    ) -> None:
        signal = make_signal()
        probe = _define_catch_up_fetcher(raises=signal)
        task = FakeTask()

        # `asyncio.run()` re-creates a `CancelledError` when the task ends
        # cancelled, so only the exception type is asserted.
        with capture_logs() as logs, pytest.raises(type(signal)):
            fetchers._run_catch_up_sync(task, probe.name, _ticket_id())

        task.retry.assert_not_called()
        assert _events(logs, "run_catch_up_failed") == []
        assert asyncio_run_spy.call_count == 1
        fake_engine.dispose.assert_awaited_once_with()


@pytest.mark.integration
def test_sync_missing_fetcher_config_fails_terminally_without_retry(
    cli_session_factory: async_sessionmaker[AsyncSession],
    asyncio_run_spy: MagicMock,
    fake_engine: FakeEngine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A registered fetcher without its `FetcherConfig` row is a
    non-retryable bootstrap invariant failure (fetcher-infrastructure.md,
    Celery task wrapper step 2). The real enabled read runs against the
    test database through the `NullPool` factory, inside the wrapper's own
    event loop; no row is written, so no cleanup is needed."""
    monkeypatch.setattr(fetchers, "async_session_factory", cli_session_factory)
    probe = _define_catch_up_fetcher()
    task = FakeTask()
    ticket_id = _ticket_id()

    with capture_logs() as logs, pytest.raises(FetcherConfigMissingError):
        fetchers._run_catch_up_sync(task, probe.name, ticket_id)

    task.retry.assert_not_called()
    assert probe.calls == []
    errors = _errors(logs)
    assert len(errors) == 1
    assert errors[0]["event"] == "run_catch_up_failed"
    assert errors[0]["fetcher_name"] == probe.name
    assert errors[0]["ticket_id"] == ticket_id
    assert errors[0]["cause"] == "FetcherConfigMissingError"
    assert asyncio_run_spy.call_count == 1
    fake_engine.dispose.assert_awaited_once_with()


# ---------------------------------------------------------------------------
# Task registration
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestRunCatchUpTaskRegistration:
    def test_registered_under_exact_name_with_three_retries(self) -> None:
        from app.celery_app import celery_app

        assert fetchers.run_catch_up.name == "run_catch_up"
        assert celery_app.tasks["run_catch_up"].name == "run_catch_up"
        assert fetchers.run_catch_up.max_retries == 3
        assert fetchers._CATCH_UP_RETRY_DELAYS == (5, 10, 20)
