"""Tests for the fetcher operations service
(backend/app/services/fetcher_operations.py).

See `docs/features/platform/fetcher-operations.md` (Fetcher Operations
Service, `list_fetchers`, `list_fetcher_runs`, `get_fetcher_run`,
`get_fetcher_timeline`, Disabled Period Derivation) for the contract
under test.

Pure calculation helpers (`_count_recognized_settings`) are unit tests
(no DB, no Redis). Staleness evaluation (`is_run_stale()`) is owned by
`app.services.fetcher_execution` and tested in
`test_fetcher_execution.py` — this module only tests that its own
read functions (`list_fetchers`, `list_fetcher_runs`, `get_fetcher_run`)
correctly wire a run's own `hard_time_limit_seconds` (or the live
`FetcherConfig.run_timeout` fallback) into the shared function. Every
public function performs real database reads and is tested with
`db_session`/the fetcher factory fixtures. `list_fetchers`'s RedBeat
integration uses the shared `celery_test_app` fixture
(`tests/conftest.py`) against the isolated worker Redis logical
database (see `docs/features/platform/testing-strategy.md`, Redis
Strategy).
"""

from __future__ import annotations

import asyncio
import threading
from collections.abc import AsyncGenerator, Awaitable, Callable, Generator
from datetime import UTC, datetime, timedelta
from typing import Any, cast
from unittest.mock import AsyncMock, MagicMock
from uuid import UUID, uuid4

import pytest
from celery import Celery
from celery.schedules import crontab
from pydantic import BaseModel, Field
from redbeat import RedBeatSchedulerEntry
from redbeat.schedulers import get_redis
from redis.exceptions import RedisError
from sqlalchemy import delete, select
from sqlalchemy.exc import OperationalError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

import app.services.fetcher_operations as fetcher_operations_module
from app.models.fetcher_audit_event import FetcherAuditEvent
from app.models.fetcher_config import FetcherConfig
from app.models.fetcher_run import FetcherRun
from app.models.user import User
from app.services.base_fetcher import FETCHER_REGISTRY, BaseFetcher
from app.services.fetcher_audit_log import FetcherAuditLog
from app.services.fetcher_operations import (
    FetcherAlreadyRunningError,
    FetcherBrokerUnavailableError,
    FetcherDeregisteredError,
    FetcherDisabledError,
    FetcherNotFoundError,
    FetcherRunNotFoundError,
    FetcherSettingInvalidError,
    FetcherSettingUnknownError,
    UpdateConfigPayload,
    _count_recognized_settings,
    get_fetcher_config,
    get_fetcher_run,
    get_fetcher_timeline,
    list_fetcher_audit_events,
    list_fetcher_runs,
    list_fetchers,
    trigger_fetcher,
    update_fetcher_config,
)

FetcherConfigFactory = Callable[..., Awaitable[FetcherConfig]]
FetcherRunFactory = Callable[..., Awaitable[FetcherRun]]
FetcherAuditEventFactory = Callable[..., Awaitable[FetcherAuditEvent]]
UserFactory = Callable[..., Awaitable[User]]


# ---------------------------------------------------------------------------
# Fixtures / stub fetchers
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _isolated_registry() -> Generator[None]:
    """Snapshot/restore `FETCHER_REGISTRY` around every test in this
    file — mirrors `tests/test_services/test_fetcher_schedule.py`."""
    original = dict(FETCHER_REGISTRY)
    yield
    FETCHER_REGISTRY.clear()
    FETCHER_REGISTRY.update(original)


class _SettingsModel(BaseModel):
    results_per_page: int = Field(default=100, ge=10, le=1000)


class _NoSettingsFetcherStub:
    """Minimal `FETCHER_REGISTRY` entry stub with no `Settings` model
    and no `cve_source_type` — deliberately NOT a `BaseFetcher`
    subclass (see `test_fetcher_schedule.py`, Test Independence)."""

    name = "test_ops_no_settings"
    description = "Stub fetcher without custom settings"
    default_schedule = "0 3 * * *"
    queue: str | None = None
    Settings: type[BaseModel] | None = None


class _WithSettingsFetcherStub:
    """Same rationale, with a `Settings` model and `cve_source_type`."""

    name = "test_ops_with_settings"
    description = "Stub fetcher with custom settings"
    default_schedule = "0 4 * * *"
    queue: str | None = None
    cve_source_type = "nvd"
    Settings = _SettingsModel


_NoSettingsFetcher = cast("type[BaseFetcher]", _NoSettingsFetcherStub)
_WithSettingsFetcher = cast("type[BaseFetcher]", _WithSettingsFetcherStub)


class _MultiSettingsModel(BaseModel):
    """Two fields — used only to exercise the alphabetical audit-event
    ordering of multiple `custom_settings` keys changed in one PATCH."""

    alpha_setting: int = Field(default=1, ge=0, le=100)
    zeta_setting: int = Field(default=1, ge=0, le=100)


class _MultiSettingsFetcherStub:
    name = "test_ops_multi_settings"
    description = "Stub fetcher with two custom settings"
    default_schedule = "0 6 * * *"
    queue: str | None = None
    Settings = _MultiSettingsModel


_MultiSettingsFetcher = cast("type[BaseFetcher]", _MultiSettingsFetcherStub)


def _register(*stubs: type[Any]) -> None:
    """Replace `FETCHER_REGISTRY` with exactly the given stub classes."""
    FETCHER_REGISTRY.clear()
    for stub in stubs:
        FETCHER_REGISTRY[stub.name] = stub


def _ops_log_records(caplog: pytest.LogCaptureFixture) -> list[Any]:
    """Return only the log records emitted by this module — mirrors
    the identical pattern in `test_fetcher_schedule.py`."""
    return [
        record
        for record in caplog.records
        if record.name == "app.services.fetcher_operations"
    ]


# ---------------------------------------------------------------------------
# Pure calculation unit tests
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestCountRecognizedSettings:
    def test_no_settings_model_returns_zero(self) -> None:
        assert _count_recognized_settings(_NoSettingsFetcher, {"foo": 1}) == 0

    def test_counts_only_recognized_keys(self) -> None:
        count = _count_recognized_settings(
            _WithSettingsFetcher, {"results_per_page": 50, "orphaned_key": True}
        )
        assert count == 1

    def test_empty_custom_settings_is_zero(self) -> None:
        assert _count_recognized_settings(_WithSettingsFetcher, {}) == 0


# ---------------------------------------------------------------------------
# list_fetchers
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestListFetchersMergeAndSort:
    async def test_registered_fetcher_without_config_uses_synthesized_defaults(
        self, db_session: AsyncSession, celery_test_app: Celery
    ) -> None:
        _register(_NoSettingsFetcher)

        items = await list_fetchers(
            db_session, has_manage_fetchers=False, celery_app=celery_test_app
        )

        assert len(items) == 1
        item = items[0]
        assert item.fetcher_name == _NoSettingsFetcher.name
        assert item.registered is True
        assert item.enabled is True
        assert item.effective_schedule == _NoSettingsFetcher.default_schedule
        assert item.schedule_is_override is False
        assert item.custom_settings_count == 0
        assert item.last_run is None
        assert item.next_run_at is None

    async def test_registered_fetcher_with_config_uses_stored_values(
        self,
        db_session: AsyncSession,
        celery_test_app: Celery,
        fetcher_config_factory: FetcherConfigFactory,
    ) -> None:
        _register(_WithSettingsFetcher)
        await fetcher_config_factory(
            fetcher_name=_WithSettingsFetcher.name,
            enabled=False,
            schedule_override="0 */2 * * *",
            custom_settings={"results_per_page": 250, "orphaned": True},
        )

        items = await list_fetchers(
            db_session, has_manage_fetchers=False, celery_app=celery_test_app
        )

        assert len(items) == 1
        item = items[0]
        assert item.enabled is False
        assert item.effective_schedule == "0 */2 * * *"
        assert item.schedule_is_override is True
        assert item.default_schedule == _WithSettingsFetcher.default_schedule
        assert item.cve_source_type == "nvd"
        assert item.custom_settings_count == 1  # orphaned key excluded

    async def test_deregistered_fetcher_has_null_code_fields(
        self,
        db_session: AsyncSession,
        celery_test_app: Celery,
        fetcher_config_factory: FetcherConfigFactory,
    ) -> None:
        FETCHER_REGISTRY.clear()
        config = await fetcher_config_factory(
            custom_settings={"a": 1, "b": 2},
        )

        items = await list_fetchers(
            db_session, has_manage_fetchers=False, celery_app=celery_test_app
        )

        assert len(items) == 1
        item = items[0]
        assert item.fetcher_name == config.fetcher_name
        assert item.registered is False
        assert item.description is None
        assert item.default_schedule is None
        assert item.schedule_is_override is None
        assert item.cve_source_type is None
        assert item.effective_schedule == config.schedule_override
        assert item.custom_settings_count == 2  # total key count, no schema
        assert item.next_run_at is None

    async def test_sorts_registered_and_deregistered_alphabetically(
        self,
        db_session: AsyncSession,
        celery_test_app: Celery,
        fetcher_config_factory: FetcherConfigFactory,
    ) -> None:
        _register(
            _NoSettingsFetcher, _WithSettingsFetcher
        )  # "test_ops_no_settings", "test_ops_with_settings"
        await fetcher_config_factory(fetcher_name="test_ops_aaa_deregistered")
        await fetcher_config_factory(fetcher_name="test_ops_zzz_deregistered")

        items = await list_fetchers(
            db_session, has_manage_fetchers=False, celery_app=celery_test_app
        )

        names = [item.fetcher_name for item in items]
        assert names == sorted(names)
        assert "test_ops_aaa_deregistered" in names
        assert "test_ops_zzz_deregistered" in names


@pytest.mark.integration
class TestListFetchersLastRun:
    async def test_never_run_is_null(
        self,
        db_session: AsyncSession,
        celery_test_app: Celery,
        fetcher_config_factory: FetcherConfigFactory,
    ) -> None:
        _register(_NoSettingsFetcher)
        await fetcher_config_factory(fetcher_name=_NoSettingsFetcher.name)

        items = await list_fetchers(
            db_session, has_manage_fetchers=False, celery_app=celery_test_app
        )

        assert items[0].last_run is None

    async def test_resolves_most_recent_by_started_at_desc(
        self,
        db_session: AsyncSession,
        celery_test_app: Celery,
        fetcher_config_factory: FetcherConfigFactory,
        fetcher_run_factory: FetcherRunFactory,
    ) -> None:
        _register(_NoSettingsFetcher)
        config = await fetcher_config_factory(fetcher_name=_NoSettingsFetcher.name)
        now = datetime.now(UTC)
        await fetcher_run_factory(
            fetcher_name=config.fetcher_name,
            started_at=now - timedelta(hours=2),
            status="success",
        )
        latest = await fetcher_run_factory(
            fetcher_name=config.fetcher_name,
            started_at=now - timedelta(minutes=1),
            status="success",
        )

        items = await list_fetchers(
            db_session, has_manage_fetchers=False, celery_app=celery_test_app
        )

        assert items[0].last_run is not None
        assert items[0].last_run.id == latest.id

    async def test_equal_started_at_breaks_tie_by_id_desc(
        self,
        db_session: AsyncSession,
        celery_test_app: Celery,
        fetcher_config_factory: FetcherConfigFactory,
        fetcher_run_factory: FetcherRunFactory,
    ) -> None:
        _register(_NoSettingsFetcher)
        config = await fetcher_config_factory(fetcher_name=_NoSettingsFetcher.name)
        fixed_time = datetime.now(UTC) - timedelta(hours=1)
        await fetcher_run_factory(
            fetcher_name=config.fetcher_name, started_at=fixed_time, status="success"
        )
        # uuid7 primary keys are time-ordered, so the run created second
        # has the larger id and wins the `id DESC` tiebreak.
        second = await fetcher_run_factory(
            fetcher_name=config.fetcher_name, started_at=fixed_time, status="success"
        )

        items = await list_fetchers(
            db_session, has_manage_fetchers=False, celery_app=celery_test_app
        )

        assert items[0].last_run is not None
        assert items[0].last_run.id == second.id

    async def test_running_status_has_null_finished_at_and_duration(
        self,
        db_session: AsyncSession,
        celery_test_app: Celery,
        fetcher_config_factory: FetcherConfigFactory,
        fetcher_run_factory: FetcherRunFactory,
    ) -> None:
        _register(_NoSettingsFetcher)
        config = await fetcher_config_factory(fetcher_name=_NoSettingsFetcher.name)
        await fetcher_run_factory(
            fetcher_name=config.fetcher_name,
            status="running",
            finished_at=None,
            duration_seconds=None,
        )

        items = await list_fetchers(
            db_session, has_manage_fetchers=False, celery_app=celery_test_app
        )

        last_run = items[0].last_run
        assert last_run is not None
        assert last_run.status == "running"
        assert last_run.finished_at is None
        assert last_run.duration_seconds is None

    async def test_failure_status_is_exposed_for_latest_run(
        self,
        db_session: AsyncSession,
        celery_test_app: Celery,
        fetcher_config_factory: FetcherConfigFactory,
        fetcher_run_factory: FetcherRunFactory,
    ) -> None:
        _register(_NoSettingsFetcher)
        config = await fetcher_config_factory(fetcher_name=_NoSettingsFetcher.name)
        await fetcher_run_factory(
            fetcher_name=config.fetcher_name,
            status="failure",
            error_message="sanitized failure",
        )

        items = await list_fetchers(
            db_session, has_manage_fetchers=False, celery_app=celery_test_app
        )

        last_run = items[0].last_run
        assert last_run is not None
        assert last_run.status == "failure"
        assert last_run.error_message == "sanitized failure"
        assert last_run.stale is False

    async def test_stale_reflects_run_timeout_plus_margin(
        self,
        db_session: AsyncSession,
        celery_test_app: Celery,
        fetcher_config_factory: FetcherConfigFactory,
        fetcher_run_factory: FetcherRunFactory,
    ) -> None:
        _register(_NoSettingsFetcher)
        config = await fetcher_config_factory(
            fetcher_name=_NoSettingsFetcher.name, run_timeout=60
        )
        await fetcher_run_factory(
            fetcher_name=config.fetcher_name,
            status="running",
            started_at=datetime.now(UTC) - timedelta(seconds=200),
        )

        items = await list_fetchers(
            db_session, has_manage_fetchers=False, celery_app=celery_test_app
        )

        last_run = items[0].last_run
        assert last_run is not None
        assert last_run.stale is True

    async def test_stale_uses_run_own_hard_limit_over_live_config(
        self,
        db_session: AsyncSession,
        celery_test_app: Celery,
        fetcher_config_factory: FetcherConfigFactory,
        fetcher_run_factory: FetcherRunFactory,
    ) -> None:
        """The run's own persisted `hard_time_limit_seconds` takes
        precedence over the fetcher's current (possibly since-changed)
        `FetcherConfig.run_timeout` — see
        `docs/features/platform/fetcher-infrastructure.md` (Stale Run
        Detection, Running Stale Threshold)."""
        _register(_NoSettingsFetcher)
        config = await fetcher_config_factory(
            fetcher_name=_NoSettingsFetcher.name, run_timeout=3600
        )
        await fetcher_run_factory(
            fetcher_name=config.fetcher_name,
            status="running",
            started_at=datetime.now(UTC) - timedelta(seconds=200),
            hard_time_limit_seconds=60,
        )

        items = await list_fetchers(
            db_session, has_manage_fetchers=False, celery_app=celery_test_app
        )

        last_run = items[0].last_run
        assert last_run is not None
        # 200s elapsed > own hard limit (60) + 60 margin == 120: stale,
        # even though the live config's run_timeout (3600) would not be.
        assert last_run.stale is True

    async def test_triggered_by_user_hidden_without_manage_fetchers(
        self,
        db_session: AsyncSession,
        celery_test_app: Celery,
        fetcher_config_factory: FetcherConfigFactory,
        fetcher_run_factory: FetcherRunFactory,
        user_factory: UserFactory,
    ) -> None:
        _register(_NoSettingsFetcher)
        config = await fetcher_config_factory(fetcher_name=_NoSettingsFetcher.name)
        actor = await user_factory()
        await fetcher_run_factory(
            fetcher_name=config.fetcher_name,
            triggered_by="manual",
            triggered_by_user_id=actor.id,
        )

        anonymous_items = await list_fetchers(
            db_session, has_manage_fetchers=False, celery_app=celery_test_app
        )
        privileged_items = await list_fetchers(
            db_session, has_manage_fetchers=True, celery_app=celery_test_app
        )

        assert anonymous_items[0].last_run is not None
        assert anonymous_items[0].last_run.triggered_by_user is None
        assert privileged_items[0].last_run is not None
        assert privileged_items[0].last_run.triggered_by_user is not None
        assert privileged_items[0].last_run.triggered_by_user.id == actor.id

    async def test_queued_run_is_last_run_with_null_started_at(
        self,
        db_session: AsyncSession,
        celery_test_app: Celery,
        fetcher_config_factory: FetcherConfigFactory,
        fetcher_run_factory: FetcherRunFactory,
    ) -> None:
        """A `queued` manual run (no `started_at`) is selected as
        `last_run` when it is the most recent by `created_at` — see
        `docs/features/platform/fetcher-operations.md`
        (`list_fetchers`)."""
        _register(_NoSettingsFetcher)
        config = await fetcher_config_factory(fetcher_name=_NoSettingsFetcher.name)
        now = datetime.now(UTC)
        await fetcher_run_factory(
            fetcher_name=config.fetcher_name,
            status="success",
            started_at=now - timedelta(hours=1),
        )
        queued = await fetcher_run_factory(
            fetcher_name=config.fetcher_name,
            status="queued",
            started_at=None,
            created_at=now,
        )

        items = await list_fetchers(
            db_session, has_manage_fetchers=False, celery_app=celery_test_app
        )

        last_run = items[0].last_run
        assert last_run is not None
        assert last_run.id == queued.id
        assert last_run.started_at is None
        assert last_run.finished_at is None
        assert last_run.duration_seconds is None
        assert last_run.stale is False


@pytest.mark.integration
class TestListFetchersNextRunAt:
    async def test_reads_due_at_from_existing_redbeat_entry(
        self,
        db_session: AsyncSession,
        celery_test_app: Celery,
        fetcher_config_factory: FetcherConfigFactory,
    ) -> None:
        _register(_NoSettingsFetcher)
        await fetcher_config_factory(fetcher_name=_NoSettingsFetcher.name, enabled=True)
        entry = RedBeatSchedulerEntry(
            name=_NoSettingsFetcher.name,
            task="run_fetcher",
            schedule=crontab.from_string(_NoSettingsFetcher.default_schedule),
            args=[],
            kwargs={
                "fetcher_name": _NoSettingsFetcher.name,
                "triggered_by": "schedule",
            },
            app=celery_test_app,
        )
        entry.save()
        entry.reschedule(datetime.now(UTC))
        expected_due_at = RedBeatSchedulerEntry.from_key(
            RedBeatSchedulerEntry.generate_key(
                celery_test_app, _NoSettingsFetcher.name
            ),
            app=celery_test_app,
        ).due_at

        items = await list_fetchers(
            db_session, has_manage_fetchers=False, celery_app=celery_test_app
        )

        # `due_at` is recomputed relative to wall-clock time at read time
        # (see redbeat's `RedBeatSchedulerEntry.due_at`), so two separate
        # reads a few milliseconds apart legitimately differ by a similar
        # margin — assert near-equality rather than exact equality.
        assert items[0].next_run_at is not None
        assert abs((items[0].next_run_at - expected_due_at).total_seconds()) < 5

    async def test_no_entry_is_null(
        self,
        db_session: AsyncSession,
        celery_test_app: Celery,
        fetcher_config_factory: FetcherConfigFactory,
    ) -> None:
        _register(_NoSettingsFetcher)
        await fetcher_config_factory(fetcher_name=_NoSettingsFetcher.name, enabled=True)

        items = await list_fetchers(
            db_session, has_manage_fetchers=False, celery_app=celery_test_app
        )

        assert items[0].next_run_at is None

    async def test_disabled_fetcher_is_null_even_with_leftover_entry(
        self,
        db_session: AsyncSession,
        celery_test_app: Celery,
        fetcher_config_factory: FetcherConfigFactory,
    ) -> None:
        _register(_NoSettingsFetcher)
        await fetcher_config_factory(
            fetcher_name=_NoSettingsFetcher.name, enabled=False
        )
        entry = RedBeatSchedulerEntry(
            name=_NoSettingsFetcher.name,
            task="run_fetcher",
            schedule=crontab.from_string(_NoSettingsFetcher.default_schedule),
            args=[],
            kwargs={
                "fetcher_name": _NoSettingsFetcher.name,
                "triggered_by": "schedule",
            },
            app=celery_test_app,
        )
        entry.save()

        items = await list_fetchers(
            db_session, has_manage_fetchers=False, celery_app=celery_test_app
        )

        assert items[0].next_run_at is None

    async def test_deregistered_fetcher_is_null_even_with_leftover_entry(
        self,
        db_session: AsyncSession,
        celery_test_app: Celery,
        fetcher_config_factory: FetcherConfigFactory,
    ) -> None:
        FETCHER_REGISTRY.clear()
        config = await fetcher_config_factory(
            fetcher_name="test_ops_deregistered_leftover"
        )
        entry = RedBeatSchedulerEntry(
            name=config.fetcher_name,
            task="run_fetcher",
            schedule=crontab.from_string("0 3 * * *"),
            args=[],
            kwargs={"fetcher_name": config.fetcher_name, "triggered_by": "schedule"},
            app=celery_test_app,
        )
        entry.save()

        items = await list_fetchers(
            db_session, has_manage_fetchers=False, celery_app=celery_test_app
        )

        assert items[0].next_run_at is None

    async def test_redis_error_nulls_all_fetchers_and_logs_safely(
        self,
        db_session: AsyncSession,
        celery_test_app: Celery,
        fetcher_config_factory: FetcherConfigFactory,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        _register(_NoSettingsFetcher, _WithSettingsFetcher)
        await fetcher_config_factory(fetcher_name=_NoSettingsFetcher.name, enabled=True)
        await fetcher_config_factory(
            fetcher_name=_WithSettingsFetcher.name, enabled=True
        )

        sensitive_message = (
            "Connection to redis://user:supersecret@203.0.113.5:6379 failed"
        )

        def _raise_redis_error(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
            raise RedisError(sensitive_message)

        monkeypatch.setattr(
            fetcher_operations_module, "_read_due_times", _raise_redis_error
        )

        with caplog.at_level("WARNING", logger="app.services.fetcher_operations"):
            items = await list_fetchers(
                db_session, has_manage_fetchers=False, celery_app=celery_test_app
            )

        assert all(item.next_run_at is None for item in items)
        records = _ops_log_records(caplog)
        assert len(records) == 1
        assert "fetcher_redbeat_next_run_unavailable" in caplog.text
        assert "supersecret" not in caplog.text
        assert "203.0.113.5" not in caplog.text

    async def test_redbeat_read_does_not_block_event_loop(
        self,
        db_session: AsyncSession,
        celery_test_app: Celery,
        fetcher_config_factory: FetcherConfigFactory,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Proves the synchronous RedBeat read runs in a worker thread
        (`asyncio.to_thread`), not on the event loop — a competing
        coroutine must keep making progress while the reader blocks."""
        _register(_NoSettingsFetcher)
        await fetcher_config_factory(fetcher_name=_NoSettingsFetcher.name, enabled=True)

        reader_started = threading.Event()
        release_reader = threading.Event()

        def _blocking_read(
            _celery_app: Celery, names: list[str]
        ) -> dict[str, datetime | None]:
            reader_started.set()
            release_reader.wait(timeout=5)
            return dict.fromkeys(names, None)

        monkeypatch.setattr(
            fetcher_operations_module, "_read_due_times", _blocking_read
        )

        ticks = 0

        async def _heartbeat() -> int:
            nonlocal ticks
            await asyncio.to_thread(reader_started.wait, 5)
            for _ in range(5):
                await asyncio.sleep(0.01)
                ticks += 1
            release_reader.set()
            return ticks

        heartbeat_task = asyncio.create_task(_heartbeat())
        await list_fetchers(
            db_session, has_manage_fetchers=False, celery_app=celery_test_app
        )
        heartbeat_ticks = await heartbeat_task

        assert heartbeat_ticks == 5

    def test_redbeat_client_has_bounded_socket_timeouts(
        self, celery_test_app: Celery
    ) -> None:
        """The RedBeat Redis client (the same singleton `_read_due_times`
        reads through) carries explicit socket timeouts, so a hung
        (blackholed/firewalled) connection raises `RedisError` within a
        bounded time instead of blocking the worker thread indefinitely
        — see docs/features/platform/fetcher-infrastructure.md (Redbeat
        Configuration, API endpoint failure handling)."""
        client = get_redis(celery_test_app)
        pool_kwargs = client.connection_pool.connection_kwargs
        assert pool_kwargs["socket_connect_timeout"] == 2
        assert pool_kwargs["socket_timeout"] == 2


# ---------------------------------------------------------------------------
# list_fetcher_runs
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestListFetcherRuns:
    async def test_raises_not_found_for_unknown_fetcher(
        self, db_session: AsyncSession
    ) -> None:
        with pytest.raises(FetcherNotFoundError):
            await list_fetcher_runs(
                db_session,
                fetcher_name="no_such_fetcher",
                has_manage_fetchers=False,
                page=1,
                per_page=20,
            )

    async def test_registered_without_config_returns_empty_page(
        self, db_session: AsyncSession
    ) -> None:
        _register(_NoSettingsFetcher)

        page = await list_fetcher_runs(
            db_session,
            fetcher_name=_NoSettingsFetcher.name,
            has_manage_fetchers=False,
            page=1,
            per_page=20,
        )

        assert page.items == []
        assert page.total == 0

    async def test_filters_by_exact_status(
        self,
        db_session: AsyncSession,
        fetcher_config_factory: FetcherConfigFactory,
        fetcher_run_factory: FetcherRunFactory,
    ) -> None:
        config = await fetcher_config_factory()
        await fetcher_run_factory(fetcher_name=config.fetcher_name, status="success")
        await fetcher_run_factory(fetcher_name=config.fetcher_name, status="failure")

        page = await list_fetcher_runs(
            db_session,
            fetcher_name=config.fetcher_name,
            has_manage_fetchers=False,
            page=1,
            per_page=20,
            status="failure",
        )

        assert page.total == 1
        assert page.items[0].status == "failure"

    async def test_invalid_status_returns_empty_page_not_error(
        self,
        db_session: AsyncSession,
        fetcher_config_factory: FetcherConfigFactory,
        fetcher_run_factory: FetcherRunFactory,
    ) -> None:
        config = await fetcher_config_factory()
        await fetcher_run_factory(fetcher_name=config.fetcher_name, status="success")

        page = await list_fetcher_runs(
            db_session,
            fetcher_name=config.fetcher_name,
            has_manage_fetchers=False,
            page=1,
            per_page=20,
            status="not-a-real-status",
        )

        assert page.total == 0
        assert page.items == []

    async def test_filters_by_inclusive_date_range(
        self,
        db_session: AsyncSession,
        fetcher_config_factory: FetcherConfigFactory,
        fetcher_run_factory: FetcherRunFactory,
    ) -> None:
        config = await fetcher_config_factory()
        now = datetime.now(UTC)
        in_range = await fetcher_run_factory(
            fetcher_name=config.fetcher_name, started_at=now - timedelta(days=1)
        )
        await fetcher_run_factory(
            fetcher_name=config.fetcher_name, started_at=now - timedelta(days=10)
        )

        page = await list_fetcher_runs(
            db_session,
            fetcher_name=config.fetcher_name,
            has_manage_fetchers=False,
            page=1,
            per_page=20,
            from_date=now - timedelta(days=2),
            to_date=now,
        )

        assert page.total == 1
        assert page.items[0].id == in_range.id

    async def test_pagination_reports_filtered_total_and_empty_out_of_range_page(
        self,
        db_session: AsyncSession,
        fetcher_config_factory: FetcherConfigFactory,
        fetcher_run_factory: FetcherRunFactory,
    ) -> None:
        config = await fetcher_config_factory()
        for _ in range(3):
            await fetcher_run_factory(fetcher_name=config.fetcher_name)

        page = await list_fetcher_runs(
            db_session,
            fetcher_name=config.fetcher_name,
            has_manage_fetchers=False,
            page=1,
            per_page=2,
        )
        out_of_range_page = await list_fetcher_runs(
            db_session,
            fetcher_name=config.fetcher_name,
            has_manage_fetchers=False,
            page=5,
            per_page=2,
        )

        assert page.total == 3
        assert len(page.items) == 2
        assert out_of_range_page.total == 3
        assert out_of_range_page.items == []

    async def test_orders_started_at_desc_id_desc(
        self,
        db_session: AsyncSession,
        fetcher_config_factory: FetcherConfigFactory,
        fetcher_run_factory: FetcherRunFactory,
    ) -> None:
        config = await fetcher_config_factory()
        now = datetime.now(UTC)
        older = await fetcher_run_factory(
            fetcher_name=config.fetcher_name, started_at=now - timedelta(hours=1)
        )
        newer = await fetcher_run_factory(
            fetcher_name=config.fetcher_name, started_at=now
        )

        page = await list_fetcher_runs(
            db_session,
            fetcher_name=config.fetcher_name,
            has_manage_fetchers=False,
            page=1,
            per_page=20,
        )

        assert [item.id for item in page.items] == [newer.id, older.id]

    async def test_triggered_by_user_visibility(
        self,
        db_session: AsyncSession,
        fetcher_config_factory: FetcherConfigFactory,
        fetcher_run_factory: FetcherRunFactory,
        user_factory: UserFactory,
    ) -> None:
        config = await fetcher_config_factory()
        actor = await user_factory()
        await fetcher_run_factory(
            fetcher_name=config.fetcher_name,
            triggered_by="manual",
            triggered_by_user_id=actor.id,
        )

        anonymous_page = await list_fetcher_runs(
            db_session,
            fetcher_name=config.fetcher_name,
            has_manage_fetchers=False,
            page=1,
            per_page=20,
        )
        privileged_page = await list_fetcher_runs(
            db_session,
            fetcher_name=config.fetcher_name,
            has_manage_fetchers=True,
            page=1,
            per_page=20,
        )

        assert anonymous_page.items[0].triggered_by_user is None
        assert privileged_page.items[0].triggered_by_user is not None
        assert privileged_page.items[0].triggered_by_user.id == actor.id

    async def test_stale_field_uses_fetcher_run_timeout(
        self,
        db_session: AsyncSession,
        fetcher_config_factory: FetcherConfigFactory,
        fetcher_run_factory: FetcherRunFactory,
    ) -> None:
        config = await fetcher_config_factory(run_timeout=60)
        await fetcher_run_factory(
            fetcher_name=config.fetcher_name,
            status="running",
            started_at=datetime.now(UTC) - timedelta(seconds=200),
        )

        page = await list_fetcher_runs(
            db_session,
            fetcher_name=config.fetcher_name,
            has_manage_fetchers=False,
            page=1,
            per_page=20,
        )

        assert page.items[0].stale is True

    async def test_filters_by_queued_status(
        self,
        db_session: AsyncSession,
        fetcher_config_factory: FetcherConfigFactory,
        fetcher_run_factory: FetcherRunFactory,
    ) -> None:
        config = await fetcher_config_factory()
        await fetcher_run_factory(fetcher_name=config.fetcher_name, status="success")
        queued = await fetcher_run_factory(
            fetcher_name=config.fetcher_name, status="queued", started_at=None
        )

        page = await list_fetcher_runs(
            db_session,
            fetcher_name=config.fetcher_name,
            has_manage_fetchers=False,
            page=1,
            per_page=20,
            status="queued",
        )

        assert page.total == 1
        assert page.items[0].id == queued.id
        assert page.items[0].started_at is None
        assert page.items[0].finished_at is None
        assert page.items[0].duration_seconds is None

    async def test_queued_run_ordered_and_filtered_by_created_at(
        self,
        db_session: AsyncSession,
        fetcher_config_factory: FetcherConfigFactory,
        fetcher_run_factory: FetcherRunFactory,
    ) -> None:
        """A `queued` run (no `started_at`) must still be correctly
        positioned in history by `created_at` — see
        `docs/features/platform/fetcher-operations.md`
        (`list_fetcher_runs`)."""
        config = await fetcher_config_factory()
        now = datetime.now(UTC)
        older = await fetcher_run_factory(
            fetcher_name=config.fetcher_name,
            status="success",
            started_at=now - timedelta(hours=2),
        )
        queued = await fetcher_run_factory(
            fetcher_name=config.fetcher_name,
            status="queued",
            started_at=None,
            created_at=now,
        )

        page = await list_fetcher_runs(
            db_session,
            fetcher_name=config.fetcher_name,
            has_manage_fetchers=False,
            page=1,
            per_page=20,
            from_date=now - timedelta(minutes=1),
            to_date=now + timedelta(minutes=1),
        )

        assert page.total == 1
        assert page.items[0].id == queued.id

        full_page = await list_fetcher_runs(
            db_session,
            fetcher_name=config.fetcher_name,
            has_manage_fetchers=False,
            page=1,
            per_page=20,
        )
        assert [item.id for item in full_page.items] == [queued.id, older.id]

    async def test_queued_run_is_stale_after_600_seconds(
        self,
        db_session: AsyncSession,
        fetcher_config_factory: FetcherConfigFactory,
        fetcher_run_factory: FetcherRunFactory,
    ) -> None:
        config = await fetcher_config_factory()
        await fetcher_run_factory(
            fetcher_name=config.fetcher_name,
            status="queued",
            started_at=None,
            created_at=datetime.now(UTC) - timedelta(seconds=601),
        )

        page = await list_fetcher_runs(
            db_session,
            fetcher_name=config.fetcher_name,
            has_manage_fetchers=False,
            page=1,
            per_page=20,
        )

        assert page.items[0].stale is True


# ---------------------------------------------------------------------------
# get_fetcher_run
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestGetFetcherRun:
    async def test_returns_full_detail(
        self,
        db_session: AsyncSession,
        fetcher_config_factory: FetcherConfigFactory,
        fetcher_run_factory: FetcherRunFactory,
    ) -> None:
        config = await fetcher_config_factory()
        run = await fetcher_run_factory(
            fetcher_name=config.fetcher_name,
            status="failure",
            items_succeeded=4,
            items_created=3,
            items_updated=5,
            items_failed=2,
            error_message="sanitized message",
            error_detail="raw TimeoutError detail",
            error_traceback="Traceback...",
        )

        result = await get_fetcher_run(
            db_session,
            fetcher_name=config.fetcher_name,
            run_id=run.id,
            has_manage_fetchers=False,
        )

        assert result.id == run.id
        assert result.fetcher_name == config.fetcher_name
        assert result.started_at == run.started_at
        assert result.finished_at == run.finished_at
        assert result.duration_seconds == run.duration_seconds
        assert result.status == "failure"
        assert result.items_succeeded == 4
        assert result.items_created == 3
        assert result.items_updated == 5
        assert result.items_failed == 2
        assert result.error_message == "sanitized message"
        assert result.triggered_by == run.triggered_by

    async def test_raw_diagnostics_always_populated_on_the_dataclass(
        self,
        db_session: AsyncSession,
        fetcher_config_factory: FetcherConfigFactory,
        fetcher_run_factory: FetcherRunFactory,
    ) -> None:
        """The service always returns the raw values regardless of
        `has_manage_fetchers` — visibility (absence in the HTTP
        response) is a router/schema-layer decision, per
        `fetcher_operations.get_fetcher_run` docstring."""
        config = await fetcher_config_factory()
        run = await fetcher_run_factory(
            fetcher_name=config.fetcher_name,
            status="failure",
            error_detail="raw detail",
            error_traceback="raw traceback",
        )

        result = await get_fetcher_run(
            db_session,
            fetcher_name=config.fetcher_name,
            run_id=run.id,
            has_manage_fetchers=False,
        )

        assert result.error_detail == "raw detail"
        assert result.error_traceback == "raw traceback"

    async def test_raises_not_found_for_unknown_fetcher(
        self, db_session: AsyncSession
    ) -> None:
        with pytest.raises(FetcherNotFoundError):
            await get_fetcher_run(
                db_session,
                fetcher_name="no_such_fetcher",
                run_id=uuid4(),
                has_manage_fetchers=False,
            )

    async def test_raises_run_not_found_for_nonexistent_run(
        self,
        db_session: AsyncSession,
        fetcher_config_factory: FetcherConfigFactory,
    ) -> None:
        config = await fetcher_config_factory()
        with pytest.raises(FetcherRunNotFoundError):
            await get_fetcher_run(
                db_session,
                fetcher_name=config.fetcher_name,
                run_id=uuid4(),
                has_manage_fetchers=False,
            )

    async def test_raises_run_not_found_for_run_of_different_fetcher(
        self,
        db_session: AsyncSession,
        fetcher_config_factory: FetcherConfigFactory,
        fetcher_run_factory: FetcherRunFactory,
    ) -> None:
        config_a = await fetcher_config_factory()
        config_b = await fetcher_config_factory()
        run = await fetcher_run_factory(fetcher_name=config_a.fetcher_name)

        with pytest.raises(FetcherRunNotFoundError):
            await get_fetcher_run(
                db_session,
                fetcher_name=config_b.fetcher_name,
                run_id=run.id,
                has_manage_fetchers=False,
            )

    async def test_triggered_by_user_hidden_without_manage_fetchers(
        self,
        db_session: AsyncSession,
        fetcher_config_factory: FetcherConfigFactory,
        fetcher_run_factory: FetcherRunFactory,
        user_factory: UserFactory,
    ) -> None:
        config = await fetcher_config_factory()
        actor = await user_factory()
        run = await fetcher_run_factory(
            fetcher_name=config.fetcher_name,
            triggered_by="manual",
            triggered_by_user_id=actor.id,
        )

        result = await get_fetcher_run(
            db_session,
            fetcher_name=config.fetcher_name,
            run_id=run.id,
            has_manage_fetchers=False,
        )

        assert result.triggered_by_user is None


# ---------------------------------------------------------------------------
# get_fetcher_timeline
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestGetFetcherTimelinePoints:
    async def test_orders_points_chronologically(
        self,
        db_session: AsyncSession,
        fetcher_config_factory: FetcherConfigFactory,
        fetcher_run_factory: FetcherRunFactory,
    ) -> None:
        config = await fetcher_config_factory()
        now = datetime.now(UTC)
        newer = await fetcher_run_factory(
            fetcher_name=config.fetcher_name, started_at=now - timedelta(hours=1)
        )
        older = await fetcher_run_factory(
            fetcher_name=config.fetcher_name, started_at=now - timedelta(hours=5)
        )

        timeline = await get_fetcher_timeline(
            db_session,
            fetcher_name=config.fetcher_name,
            has_manage_fetchers=False,
            from_date=now - timedelta(days=1),
            to_date=now,
        )

        assert [point.run_id for point in timeline.points] == [older.id, newer.id]

    async def test_running_point_has_null_duration(
        self,
        db_session: AsyncSession,
        fetcher_config_factory: FetcherConfigFactory,
        fetcher_run_factory: FetcherRunFactory,
    ) -> None:
        config = await fetcher_config_factory()
        now = datetime.now(UTC)
        await fetcher_run_factory(
            fetcher_name=config.fetcher_name,
            status="running",
            started_at=now,
            finished_at=None,
            duration_seconds=None,
        )

        timeline = await get_fetcher_timeline(
            db_session,
            fetcher_name=config.fetcher_name,
            has_manage_fetchers=False,
            from_date=now - timedelta(hours=1),
            to_date=now + timedelta(hours=1),
        )

        assert timeline.points[0].duration_seconds is None
        assert timeline.points[0].status == "running"

    async def test_queued_point_uses_created_at_as_timestamp(
        self,
        db_session: AsyncSession,
        fetcher_config_factory: FetcherConfigFactory,
        fetcher_run_factory: FetcherRunFactory,
    ) -> None:
        """A `queued` run has no `started_at`; the timeline point uses
        `created_at` as its `timestamp` — see
        `docs/features/platform/fetcher-operations.md`
        (`get_fetcher_timeline`)."""
        config = await fetcher_config_factory()
        now = datetime.now(UTC)
        await fetcher_run_factory(
            fetcher_name=config.fetcher_name,
            status="queued",
            started_at=None,
            created_at=now,
        )

        timeline = await get_fetcher_timeline(
            db_session,
            fetcher_name=config.fetcher_name,
            has_manage_fetchers=False,
            from_date=now - timedelta(hours=1),
            to_date=now + timedelta(hours=1),
        )

        assert len(timeline.points) == 1
        assert timeline.points[0].timestamp == now
        assert timeline.points[0].duration_seconds is None
        assert timeline.points[0].status == "queued"

    async def test_bounds_are_inclusive(
        self,
        db_session: AsyncSession,
        fetcher_config_factory: FetcherConfigFactory,
        fetcher_run_factory: FetcherRunFactory,
    ) -> None:
        config = await fetcher_config_factory()
        boundary = datetime.now(UTC)
        await fetcher_run_factory(fetcher_name=config.fetcher_name, started_at=boundary)

        timeline = await get_fetcher_timeline(
            db_session,
            fetcher_name=config.fetcher_name,
            has_manage_fetchers=False,
            from_date=boundary,
            to_date=boundary,
        )

        assert len(timeline.points) == 1

    async def test_raises_not_found_for_unknown_fetcher(
        self, db_session: AsyncSession
    ) -> None:
        now = datetime.now(UTC)
        with pytest.raises(FetcherNotFoundError):
            await get_fetcher_timeline(
                db_session,
                fetcher_name="no_such_fetcher",
                has_manage_fetchers=False,
                from_date=now - timedelta(days=1),
                to_date=now,
            )


@pytest.mark.integration
class TestDisabledPeriodDerivation:
    async def test_pairs_disabled_with_next_enabled(
        self,
        db_session: AsyncSession,
        fetcher_config_factory: FetcherConfigFactory,
        fetcher_audit_event_factory: FetcherAuditEventFactory,
    ) -> None:
        config = await fetcher_config_factory()
        now = datetime.now(UTC)
        disabled_at = now - timedelta(days=5)
        enabled_at = now - timedelta(days=3)
        await fetcher_audit_event_factory(
            fetcher_name=config.fetcher_name,
            event_type="disabled",
            created_at=disabled_at,
        )
        await fetcher_audit_event_factory(
            fetcher_name=config.fetcher_name,
            event_type="enabled",
            created_at=enabled_at,
        )

        timeline = await get_fetcher_timeline(
            db_session,
            fetcher_name=config.fetcher_name,
            has_manage_fetchers=False,
            from_date=now - timedelta(days=10),
            to_date=now,
        )

        assert len(timeline.disabled_periods) == 1
        period = timeline.disabled_periods[0]
        assert period.disabled_at == disabled_at
        assert period.enabled_at == enabled_at

    async def test_trailing_disabled_is_open_ended(
        self,
        db_session: AsyncSession,
        fetcher_config_factory: FetcherConfigFactory,
        fetcher_audit_event_factory: FetcherAuditEventFactory,
    ) -> None:
        config = await fetcher_config_factory()
        now = datetime.now(UTC)
        disabled_at = now - timedelta(days=2)
        await fetcher_audit_event_factory(
            fetcher_name=config.fetcher_name,
            event_type="disabled",
            created_at=disabled_at,
        )

        timeline = await get_fetcher_timeline(
            db_session,
            fetcher_name=config.fetcher_name,
            has_manage_fetchers=False,
            from_date=now - timedelta(days=10),
            to_date=now,
        )

        assert len(timeline.disabled_periods) == 1
        assert timeline.disabled_periods[0].enabled_at is None

    async def test_leading_orphaned_enabled_is_ignored(
        self,
        db_session: AsyncSession,
        fetcher_config_factory: FetcherConfigFactory,
        fetcher_audit_event_factory: FetcherAuditEventFactory,
    ) -> None:
        config = await fetcher_config_factory()
        now = datetime.now(UTC)
        await fetcher_audit_event_factory(
            fetcher_name=config.fetcher_name,
            event_type="enabled",
            created_at=now - timedelta(days=9),
        )

        timeline = await get_fetcher_timeline(
            db_session,
            fetcher_name=config.fetcher_name,
            has_manage_fetchers=False,
            from_date=now - timedelta(days=10),
            to_date=now,
        )

        assert timeline.disabled_periods == []

    async def test_non_state_event_is_ignored(
        self,
        db_session: AsyncSession,
        fetcher_config_factory: FetcherConfigFactory,
        fetcher_audit_event_factory: FetcherAuditEventFactory,
    ) -> None:
        config = await fetcher_config_factory()
        now = datetime.now(UTC)
        await fetcher_audit_event_factory(
            fetcher_name=config.fetcher_name,
            event_type="triggered",
            created_at=now - timedelta(days=1),
        )

        timeline = await get_fetcher_timeline(
            db_session,
            fetcher_name=config.fetcher_name,
            has_manage_fetchers=False,
            from_date=now - timedelta(days=10),
            to_date=now,
        )

        assert timeline.disabled_periods == []

    async def test_consecutive_disabled_events_use_earliest(
        self,
        db_session: AsyncSession,
        fetcher_config_factory: FetcherConfigFactory,
        fetcher_audit_event_factory: FetcherAuditEventFactory,
    ) -> None:
        config = await fetcher_config_factory()
        now = datetime.now(UTC)
        earliest = now - timedelta(days=6)
        await fetcher_audit_event_factory(
            fetcher_name=config.fetcher_name, event_type="disabled", created_at=earliest
        )
        await fetcher_audit_event_factory(
            fetcher_name=config.fetcher_name,
            event_type="disabled",
            created_at=now - timedelta(days=5),
        )
        enabled_at = now - timedelta(days=1)
        await fetcher_audit_event_factory(
            fetcher_name=config.fetcher_name,
            event_type="enabled",
            created_at=enabled_at,
        )

        timeline = await get_fetcher_timeline(
            db_session,
            fetcher_name=config.fetcher_name,
            has_manage_fetchers=False,
            from_date=now - timedelta(days=10),
            to_date=now,
        )

        assert len(timeline.disabled_periods) == 1
        assert timeline.disabled_periods[0].disabled_at == earliest

    async def test_excludes_period_entirely_outside_range(
        self,
        db_session: AsyncSession,
        fetcher_config_factory: FetcherConfigFactory,
        fetcher_audit_event_factory: FetcherAuditEventFactory,
    ) -> None:
        config = await fetcher_config_factory()
        now = datetime.now(UTC)
        await fetcher_audit_event_factory(
            fetcher_name=config.fetcher_name,
            event_type="disabled",
            created_at=now - timedelta(days=100),
        )
        await fetcher_audit_event_factory(
            fetcher_name=config.fetcher_name,
            event_type="enabled",
            created_at=now - timedelta(days=90),
        )

        timeline = await get_fetcher_timeline(
            db_session,
            fetcher_name=config.fetcher_name,
            has_manage_fetchers=False,
            from_date=now - timedelta(days=10),
            to_date=now,
        )

        assert timeline.disabled_periods == []

    async def test_includes_partial_overlap_without_clipping_timestamps(
        self,
        db_session: AsyncSession,
        fetcher_config_factory: FetcherConfigFactory,
        fetcher_audit_event_factory: FetcherAuditEventFactory,
    ) -> None:
        config = await fetcher_config_factory()
        now = datetime.now(UTC)
        disabled_at = now - timedelta(days=20)  # before the requested range
        enabled_at = now - timedelta(days=8)  # inside the requested range
        await fetcher_audit_event_factory(
            fetcher_name=config.fetcher_name,
            event_type="disabled",
            created_at=disabled_at,
        )
        await fetcher_audit_event_factory(
            fetcher_name=config.fetcher_name,
            event_type="enabled",
            created_at=enabled_at,
        )

        timeline = await get_fetcher_timeline(
            db_session,
            fetcher_name=config.fetcher_name,
            has_manage_fetchers=False,
            from_date=now - timedelta(days=10),
            to_date=now,
        )

        assert len(timeline.disabled_periods) == 1
        # Actual event timestamps are preserved, not clipped to from_date.
        assert timeline.disabled_periods[0].disabled_at == disabled_at
        assert timeline.disabled_periods[0].enabled_at == enabled_at

    async def test_actors_hidden_without_manage_fetchers(
        self,
        db_session: AsyncSession,
        fetcher_config_factory: FetcherConfigFactory,
        fetcher_audit_event_factory: FetcherAuditEventFactory,
        user_factory: UserFactory,
    ) -> None:
        config = await fetcher_config_factory()
        actor = await user_factory()
        now = datetime.now(UTC)
        await fetcher_audit_event_factory(
            fetcher_name=config.fetcher_name,
            event_type="disabled",
            created_at=now - timedelta(days=5),
            user_id=actor.id,
        )
        await fetcher_audit_event_factory(
            fetcher_name=config.fetcher_name,
            event_type="enabled",
            created_at=now - timedelta(days=3),
            user_id=actor.id,
        )

        anonymous_timeline = await get_fetcher_timeline(
            db_session,
            fetcher_name=config.fetcher_name,
            has_manage_fetchers=False,
            from_date=now - timedelta(days=10),
            to_date=now,
        )
        privileged_timeline = await get_fetcher_timeline(
            db_session,
            fetcher_name=config.fetcher_name,
            has_manage_fetchers=True,
            from_date=now - timedelta(days=10),
            to_date=now,
        )

        assert anonymous_timeline.disabled_periods[0].disabled_by is None
        assert anonymous_timeline.disabled_periods[0].enabled_by is None
        assert privileged_timeline.disabled_periods[0].disabled_by is not None
        assert privileged_timeline.disabled_periods[0].disabled_by.id == actor.id
        assert privileged_timeline.disabled_periods[0].enabled_by is not None
        assert privileged_timeline.disabled_periods[0].enabled_by.id == actor.id

    async def test_equal_created_at_pairs_correctly_via_id_ordering(
        self,
        db_session: AsyncSession,
        fetcher_config_factory: FetcherConfigFactory,
        fetcher_audit_event_factory: FetcherAuditEventFactory,
    ) -> None:
        """Ordering is `id ASC` (UUIDv7), not `created_at ASC` — proven
        by giving both events the exact same `created_at` and relying
        on `id` (generated in call order) to pair them correctly."""
        config = await fetcher_config_factory()
        now = datetime.now(UTC)
        same_time = now - timedelta(days=5)
        await fetcher_audit_event_factory(
            fetcher_name=config.fetcher_name,
            event_type="disabled",
            created_at=same_time,
        )
        await fetcher_audit_event_factory(
            fetcher_name=config.fetcher_name,
            event_type="enabled",
            created_at=same_time,
        )

        timeline = await get_fetcher_timeline(
            db_session,
            fetcher_name=config.fetcher_name,
            has_manage_fetchers=False,
            from_date=now - timedelta(days=10),
            to_date=now,
        )

        assert len(timeline.disabled_periods) == 1
        assert timeline.disabled_periods[0].disabled_at == same_time
        assert timeline.disabled_periods[0].enabled_at == same_time


@pytest.mark.integration
class TestGetFetcherConfig:
    async def test_registered_fetcher_with_override_returns_merged_config(
        self,
        db_session: AsyncSession,
        fetcher_config_factory: FetcherConfigFactory,
    ) -> None:
        _register(_WithSettingsFetcher)
        config = await fetcher_config_factory(
            fetcher_name=_WithSettingsFetcher.name,
            schedule_override="0 */2 * * *",
            custom_settings={"results_per_page": 250},
        )

        result = await get_fetcher_config(db_session, fetcher_name=config.fetcher_name)

        assert result.fetcher_name == config.fetcher_name
        assert result.enabled is True
        assert result.schedule_override == "0 */2 * * *"
        assert result.default_schedule == _WithSettingsFetcher.default_schedule
        assert result.effective_schedule == "0 */2 * * *"
        assert result.run_timeout == config.run_timeout
        assert result.request_delay == config.request_delay
        assert result.custom_settings == {"results_per_page": 250}
        assert result.updated_at == config.updated_at

    async def test_registered_fetcher_without_override_uses_default_schedule(
        self,
        db_session: AsyncSession,
        fetcher_config_factory: FetcherConfigFactory,
    ) -> None:
        _register(_NoSettingsFetcher)
        config = await fetcher_config_factory(fetcher_name=_NoSettingsFetcher.name)

        result = await get_fetcher_config(db_session, fetcher_name=config.fetcher_name)

        assert result.schedule_override is None
        assert result.effective_schedule == _NoSettingsFetcher.default_schedule

    async def test_registered_fetcher_settings_schema_matches_model(
        self,
        db_session: AsyncSession,
        fetcher_config_factory: FetcherConfigFactory,
    ) -> None:
        _register(_WithSettingsFetcher)
        config = await fetcher_config_factory(fetcher_name=_WithSettingsFetcher.name)

        result = await get_fetcher_config(db_session, fetcher_name=config.fetcher_name)

        assert result.settings_schema == _SettingsModel.model_json_schema()

    async def test_registered_fetcher_without_settings_model_schema_is_none(
        self,
        db_session: AsyncSession,
        fetcher_config_factory: FetcherConfigFactory,
    ) -> None:
        _register(_NoSettingsFetcher)
        config = await fetcher_config_factory(fetcher_name=_NoSettingsFetcher.name)

        result = await get_fetcher_config(db_session, fetcher_name=config.fetcher_name)

        assert result.settings_schema is None

    async def test_deregistered_fetcher_returns_raw_snapshot(
        self,
        db_session: AsyncSession,
        fetcher_config_factory: FetcherConfigFactory,
    ) -> None:
        FETCHER_REGISTRY.clear()
        config = await fetcher_config_factory(
            schedule_override="0 5 * * *",
            custom_settings={"orphaned_key": "raw_value"},
        )

        result = await get_fetcher_config(db_session, fetcher_name=config.fetcher_name)

        assert result.default_schedule is None
        assert result.settings_schema is None
        assert result.effective_schedule == "0 5 * * *"
        assert result.custom_settings == {"orphaned_key": "raw_value"}

    async def test_deregistered_fetcher_without_override_effective_schedule_is_none(
        self,
        db_session: AsyncSession,
        fetcher_config_factory: FetcherConfigFactory,
    ) -> None:
        FETCHER_REGISTRY.clear()
        config = await fetcher_config_factory()

        result = await get_fetcher_config(db_session, fetcher_name=config.fetcher_name)

        assert result.effective_schedule is None

    async def test_unknown_fetcher_raises_not_found(
        self, db_session: AsyncSession
    ) -> None:
        FETCHER_REGISTRY.clear()
        with pytest.raises(FetcherNotFoundError):
            await get_fetcher_config(db_session, fetcher_name="no-such-fetcher")

    async def test_registered_fetcher_without_config_row_raises_not_found(
        self, db_session: AsyncSession
    ) -> None:
        """A `FetcherConfig` row is a hard prerequisite for this
        function — unlike the Public read functions, a registered
        fetcher with no row yet (bootstrap not run) still raises,
        consistent with `trigger_fetcher`/`update_fetcher_config`."""
        _register(_NoSettingsFetcher)

        with pytest.raises(FetcherNotFoundError):
            await get_fetcher_config(db_session, fetcher_name=_NoSettingsFetcher.name)

    async def test_database_error_propagates_unchanged(
        self,
        db_session: AsyncSession,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        async def _boom(*args: Any, **kwargs: Any) -> None:
            raise OperationalError("simulated", {}, Exception("boom"))

        monkeypatch.setattr(db_session, "execute", _boom)

        with pytest.raises(OperationalError):
            await get_fetcher_config(db_session, fetcher_name="irrelevant")


# ---------------------------------------------------------------------------
# update_fetcher_config — guards
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestUpdateFetcherConfigGuards:
    async def test_unknown_fetcher_raises_not_found(
        self, db_session: AsyncSession, user_factory: UserFactory
    ) -> None:
        FETCHER_REGISTRY.clear()
        admin = await user_factory()

        with pytest.raises(FetcherNotFoundError):
            await update_fetcher_config(
                db_session,
                fetcher_name="no-such-fetcher",
                user_id=admin.id,
                payload=UpdateConfigPayload(enabled=False),
            )

    async def test_deregistered_fetcher_raises_deregistered(
        self,
        db_session: AsyncSession,
        fetcher_config_factory: FetcherConfigFactory,
        user_factory: UserFactory,
    ) -> None:
        FETCHER_REGISTRY.clear()
        config = await fetcher_config_factory()
        admin = await user_factory()

        with pytest.raises(FetcherDeregisteredError):
            await update_fetcher_config(
                db_session,
                fetcher_name=config.fetcher_name,
                user_id=admin.id,
                payload=UpdateConfigPayload(enabled=False),
            )

    async def test_registered_fetcher_without_config_row_raises_not_found(
        self,
        db_session: AsyncSession,
        user_factory: UserFactory,
    ) -> None:
        """A `FetcherConfig` row is a hard prerequisite for this
        function — a registered fetcher with no row yet (bootstrap not
        run) still raises `FetcherNotFoundError`, mirroring
        `get_fetcher_config`'s equivalent guard."""
        _register(_NoSettingsFetcher)
        admin = await user_factory()

        with pytest.raises(FetcherNotFoundError):
            await update_fetcher_config(
                db_session,
                fetcher_name=_NoSettingsFetcher.name,
                user_id=admin.id,
                payload=UpdateConfigPayload(enabled=False),
            )

    async def test_run_timeout_change_with_active_non_stale_run_raises(
        self,
        db_session: AsyncSession,
        fetcher_config_factory: FetcherConfigFactory,
        fetcher_run_factory: FetcherRunFactory,
        user_factory: UserFactory,
    ) -> None:
        _register(_NoSettingsFetcher)
        config = await fetcher_config_factory(
            fetcher_name=_NoSettingsFetcher.name, run_timeout=3600
        )
        await fetcher_run_factory(
            fetcher_name=config.fetcher_name,
            status="running",
            started_at=datetime.now(UTC),
        )
        admin = await user_factory()

        with pytest.raises(FetcherAlreadyRunningError):
            await update_fetcher_config(
                db_session,
                fetcher_name=config.fetcher_name,
                user_id=admin.id,
                payload=UpdateConfigPayload(run_timeout=1800),
            )

        await db_session.refresh(config)
        assert config.run_timeout == 3600
        events = (await db_session.execute(select(FetcherAuditEvent))).scalars().all()
        assert events == []

    async def test_run_timeout_change_with_active_non_stale_queued_run_raises(
        self,
        db_session: AsyncSession,
        fetcher_config_factory: FetcherConfigFactory,
        fetcher_run_factory: FetcherRunFactory,
        user_factory: UserFactory,
    ) -> None:
        """The Run Timeout Active Guard covers both active statuses —
        a non-stale `queued` run blocks a `run_timeout` change exactly
        like a `running` one. See
        `docs/features/platform/fetcher-infrastructure.md` (Stale Run
        Detection, "Relationship to hard time limit") for why: the
        manual run's Celery task already has its hard `time_limit`
        fixed at publication time, so lowering `run_timeout` while it
        is still `queued` could later cause the Running Stale
        Threshold (evaluated with the new, smaller value after
        adoption) to declare the still-executing process stale and
        start a second run."""
        _register(_NoSettingsFetcher)
        config = await fetcher_config_factory(
            fetcher_name=_NoSettingsFetcher.name, run_timeout=3600
        )
        queued_run = await fetcher_run_factory(
            fetcher_name=config.fetcher_name,
            status="queued",
            started_at=None,
        )
        admin = await user_factory()

        with pytest.raises(FetcherAlreadyRunningError):
            await update_fetcher_config(
                db_session,
                fetcher_name=config.fetcher_name,
                user_id=admin.id,
                payload=UpdateConfigPayload(run_timeout=1800),
            )

        await db_session.refresh(config)
        assert config.run_timeout == 3600
        await db_session.refresh(queued_run)
        assert queued_run.status == "queued"
        events = (await db_session.execute(select(FetcherAuditEvent))).scalars().all()
        assert events == []

    async def test_run_timeout_change_with_stale_queued_run_finalizes_and_proceeds(
        self,
        db_session: AsyncSession,
        fetcher_config_factory: FetcherConfigFactory,
        fetcher_run_factory: FetcherRunFactory,
        user_factory: UserFactory,
    ) -> None:
        """A `queued` run that has crossed the fixed 600-second Queued
        Stale Threshold is finalized in place (via
        `mark_queued_run_stale()`, `started_at`/`duration_seconds` left
        `NULL`) under the same lock, and the PATCH proceeds — mirroring
        the existing stale-`running` behavior."""
        _register(_NoSettingsFetcher)
        config = await fetcher_config_factory(
            fetcher_name=_NoSettingsFetcher.name, run_timeout=3600
        )
        stale_queued_run = await fetcher_run_factory(
            fetcher_name=config.fetcher_name,
            status="queued",
            started_at=None,
            created_at=datetime.now(UTC) - timedelta(seconds=601),
        )
        admin = await user_factory()

        result = await update_fetcher_config(
            db_session,
            fetcher_name=config.fetcher_name,
            user_id=admin.id,
            payload=UpdateConfigPayload(run_timeout=1800),
        )

        assert result.config.run_timeout == 1800
        await db_session.refresh(stale_queued_run)
        assert stale_queued_run.status == "failure"
        assert stale_queued_run.started_at is None
        assert stale_queued_run.duration_seconds is None
        assert stale_queued_run.error_message is not None
        assert "stale" in stale_queued_run.error_message.lower()
        # The stale-run finalization itself is silent (no audit event) —
        # exactly one audit event exists, for the actual `run_timeout`
        # config mutation.
        event = (await db_session.execute(select(FetcherAuditEvent))).scalars().one()
        assert event.event_type == "config_changed"
        assert event.old_value == "3600"
        assert event.new_value == "1800"
        assert event.detail == {"field": "run_timeout"}

    async def test_run_timeout_change_with_stale_run_finalizes_and_proceeds(
        self,
        db_session: AsyncSession,
        fetcher_config_factory: FetcherConfigFactory,
        fetcher_run_factory: FetcherRunFactory,
        user_factory: UserFactory,
    ) -> None:
        """Staleness MUST be evaluated using the current (pre-PATCH)
        `run_timeout`, never the submitted new value — see
        `docs/features/platform/fetcher-operations.md`
        (`update_fetcher_config`, Run Timeout Active Guard). The
        numbers are chosen so the two thresholds disagree: under the
        old value (60 -> threshold 120) `elapsed=150` is stale; under
        the new value (300 -> threshold 360) it would NOT be stale. A
        regression that read the wrong field would raise
        `FetcherAlreadyRunningError` here instead of finalizing and
        proceeding."""
        _register(_NoSettingsFetcher)
        config = await fetcher_config_factory(
            fetcher_name=_NoSettingsFetcher.name, run_timeout=60
        )
        stale_run = await fetcher_run_factory(
            fetcher_name=config.fetcher_name,
            status="running",
            started_at=datetime.now(UTC) - timedelta(seconds=150),
        )
        admin = await user_factory()

        result = await update_fetcher_config(
            db_session,
            fetcher_name=config.fetcher_name,
            user_id=admin.id,
            payload=UpdateConfigPayload(run_timeout=300),
        )

        assert result.config.run_timeout == 300
        await db_session.refresh(stale_run)
        assert stale_run.status == "failure"
        assert stale_run.error_message is not None
        assert "stale" in stale_run.error_message.lower()
        # The stale-run finalization itself is silent (no audit event) —
        # exactly one audit event exists, for the actual `run_timeout`
        # config mutation.
        event = (await db_session.execute(select(FetcherAuditEvent))).scalars().one()
        assert event.event_type == "config_changed"
        assert event.old_value == "60"
        assert event.new_value == "300"
        assert event.detail == {"field": "run_timeout"}

    async def test_run_timeout_change_respects_running_run_own_persisted_hard_limit(
        self,
        db_session: AsyncSession,
        fetcher_config_factory: FetcherConfigFactory,
        fetcher_run_factory: FetcherRunFactory,
        user_factory: UserFactory,
    ) -> None:
        """A `running` run dispatched under a larger persisted hard
        limit must still block the guard after `run_timeout` is
        lowered — the live config value must not override the row's
        own limit. See
        `docs/features/platform/fetcher-infrastructure.md` (Stale Run
        Detection, Running Stale Threshold): under the live config
        alone (60 -> threshold 120) the row's 200s elapsed would look
        stale, but the row's own persisted limit (3600 -> threshold
        3660) says otherwise, and that value must win."""
        _register(_NoSettingsFetcher)
        config = await fetcher_config_factory(
            fetcher_name=_NoSettingsFetcher.name, run_timeout=3600
        )
        run = await fetcher_run_factory(
            fetcher_name=config.fetcher_name,
            status="running",
            started_at=datetime.now(UTC) - timedelta(seconds=200),
            hard_time_limit_seconds=3600,
        )
        admin = await user_factory()

        with pytest.raises(FetcherAlreadyRunningError):
            await update_fetcher_config(
                db_session,
                fetcher_name=config.fetcher_name,
                user_id=admin.id,
                payload=UpdateConfigPayload(run_timeout=60),
            )

        await db_session.refresh(config)
        assert config.run_timeout == 3600
        await db_session.refresh(run)
        assert run.status == "running"
        events = (await db_session.execute(select(FetcherAuditEvent))).scalars().all()
        assert events == []

    async def test_run_timeout_unchanged_value_skips_active_run_guard(
        self,
        db_session: AsyncSession,
        fetcher_config_factory: FetcherConfigFactory,
        fetcher_run_factory: FetcherRunFactory,
        user_factory: UserFactory,
    ) -> None:
        """`run_timeout` present but equal to the current value is a
        no-op for that field — the guard does not apply, so an
        unrelated field change succeeds even with a non-stale active
        run."""
        _register(_NoSettingsFetcher)
        config = await fetcher_config_factory(
            fetcher_name=_NoSettingsFetcher.name, run_timeout=3600, request_delay=0
        )
        await fetcher_run_factory(
            fetcher_name=config.fetcher_name,
            status="running",
            started_at=datetime.now(UTC),
        )
        admin = await user_factory()

        result = await update_fetcher_config(
            db_session,
            fetcher_name=config.fetcher_name,
            user_id=admin.id,
            payload=UpdateConfigPayload(run_timeout=3600, request_delay=5.0),
        )

        assert result.config.request_delay == 5.0

    async def test_unknown_custom_setting_raises(
        self,
        db_session: AsyncSession,
        fetcher_config_factory: FetcherConfigFactory,
        user_factory: UserFactory,
    ) -> None:
        _register(_WithSettingsFetcher)
        config = await fetcher_config_factory(fetcher_name=_WithSettingsFetcher.name)
        admin = await user_factory()

        with pytest.raises(FetcherSettingUnknownError):
            await update_fetcher_config(
                db_session,
                fetcher_name=config.fetcher_name,
                user_id=admin.id,
                payload=UpdateConfigPayload(custom_settings={"nonexistent": 1}),
            )

    async def test_no_settings_model_any_key_is_unknown(
        self,
        db_session: AsyncSession,
        fetcher_config_factory: FetcherConfigFactory,
        user_factory: UserFactory,
    ) -> None:
        _register(_NoSettingsFetcher)
        config = await fetcher_config_factory(fetcher_name=_NoSettingsFetcher.name)
        admin = await user_factory()

        with pytest.raises(FetcherSettingUnknownError):
            await update_fetcher_config(
                db_session,
                fetcher_name=config.fetcher_name,
                user_id=admin.id,
                payload=UpdateConfigPayload(custom_settings={"anything": 1}),
            )

    async def test_invalid_custom_setting_value_raises(
        self,
        db_session: AsyncSession,
        fetcher_config_factory: FetcherConfigFactory,
        user_factory: UserFactory,
    ) -> None:
        _register(_WithSettingsFetcher)
        config = await fetcher_config_factory(fetcher_name=_WithSettingsFetcher.name)
        admin = await user_factory()

        with pytest.raises(FetcherSettingInvalidError):
            await update_fetcher_config(
                db_session,
                fetcher_name=config.fetcher_name,
                user_id=admin.id,
                payload=UpdateConfigPayload(custom_settings={"results_per_page": 5000}),
            )

    async def test_pre_existing_invalid_stored_value_blocks_unrelated_key_change(
        self,
        db_session: AsyncSession,
        fetcher_config_factory: FetcherConfigFactory,
        user_factory: UserFactory,
    ) -> None:
        """The merged candidate state — current stored values plus the
        submitted changes — is validated as a whole (see
        `docs/features/platform/fetcher-operations.md`,
        `update_fetcher_config`, Custom settings canonicalization). A
        previously stored value that has since become invalid (e.g.
        after a `Settings` model constraint tightening, simulated here
        by writing directly via the factory) blocks a PATCH that only
        submits a different, currently-valid key — and the exception
        message identifies the offending field even though the caller
        never submitted it."""
        _register(_MultiSettingsFetcher)
        config = await fetcher_config_factory(
            fetcher_name=_MultiSettingsFetcher.name,
            custom_settings={"alpha_setting": 500, "zeta_setting": 5},
        )
        admin = await user_factory()

        with pytest.raises(FetcherSettingInvalidError) as exc_info:
            await update_fetcher_config(
                db_session,
                fetcher_name=config.fetcher_name,
                user_id=admin.id,
                payload=UpdateConfigPayload(custom_settings={"zeta_setting": 10}),
            )

        assert "alpha_setting" in str(exc_info.value)

    async def test_unknown_key_checked_before_invalid_value(
        self,
        db_session: AsyncSession,
        fetcher_config_factory: FetcherConfigFactory,
        user_factory: UserFactory,
    ) -> None:
        _register(_WithSettingsFetcher)
        config = await fetcher_config_factory(fetcher_name=_WithSettingsFetcher.name)
        admin = await user_factory()

        with pytest.raises(FetcherSettingUnknownError):
            await update_fetcher_config(
                db_session,
                fetcher_name=config.fetcher_name,
                user_id=admin.id,
                payload=UpdateConfigPayload(
                    custom_settings={"nonexistent": 1, "results_per_page": 5000}
                ),
            )

    async def test_custom_settings_guard_failure_leaves_standard_fields_unapplied(
        self,
        db_session: AsyncSession,
        fetcher_config_factory: FetcherConfigFactory,
        user_factory: UserFactory,
    ) -> None:
        """The mutation is atomic across the whole payload: a guard
        failure on `custom_settings` (evaluated before any mutation)
        must leave an otherwise-valid standard-field change in the same
        PATCH unapplied, with no audit events created."""
        _register(_WithSettingsFetcher)
        config = await fetcher_config_factory(
            fetcher_name=_WithSettingsFetcher.name, enabled=True
        )
        original_updated_at = config.updated_at
        admin = await user_factory()

        with pytest.raises(FetcherSettingUnknownError):
            await update_fetcher_config(
                db_session,
                fetcher_name=config.fetcher_name,
                user_id=admin.id,
                payload=UpdateConfigPayload(
                    enabled=False, custom_settings={"nonexistent": 1}
                ),
            )

        await db_session.refresh(config)
        assert config.enabled is True
        assert config.updated_at == original_updated_at
        events = (await db_session.execute(select(FetcherAuditEvent))).scalars().all()
        assert events == []


# ---------------------------------------------------------------------------
# update_fetcher_config — behavior, canonicalization, audit content
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestUpdateFetcherConfigBehavior:
    async def test_disabling_creates_disabled_event_without_payload(
        self,
        db_session: AsyncSession,
        fetcher_config_factory: FetcherConfigFactory,
        user_factory: UserFactory,
    ) -> None:
        _register(_NoSettingsFetcher)
        config = await fetcher_config_factory(
            fetcher_name=_NoSettingsFetcher.name, enabled=True
        )
        admin = await user_factory()

        result = await update_fetcher_config(
            db_session,
            fetcher_name=config.fetcher_name,
            user_id=admin.id,
            payload=UpdateConfigPayload(enabled=False),
        )

        assert result.config.enabled is False
        event = (await db_session.execute(select(FetcherAuditEvent))).scalars().one()
        assert event.event_type == "disabled"
        assert event.old_value is None
        assert event.new_value is None
        assert event.detail is None
        assert event.user_id == admin.id

    async def test_enabling_creates_enabled_event(
        self,
        db_session: AsyncSession,
        fetcher_config_factory: FetcherConfigFactory,
        user_factory: UserFactory,
    ) -> None:
        _register(_NoSettingsFetcher)
        config = await fetcher_config_factory(
            fetcher_name=_NoSettingsFetcher.name, enabled=False
        )
        admin = await user_factory()

        await update_fetcher_config(
            db_session,
            fetcher_name=config.fetcher_name,
            user_id=admin.id,
            payload=UpdateConfigPayload(enabled=True),
        )

        event = (await db_session.execute(select(FetcherAuditEvent))).scalars().one()
        assert event.event_type == "enabled"

    async def test_schedule_override_change_audits_str_values(
        self,
        db_session: AsyncSession,
        fetcher_config_factory: FetcherConfigFactory,
        user_factory: UserFactory,
    ) -> None:
        _register(_NoSettingsFetcher)
        config = await fetcher_config_factory(
            fetcher_name=_NoSettingsFetcher.name, schedule_override="0 1 * * *"
        )
        admin = await user_factory()

        await update_fetcher_config(
            db_session,
            fetcher_name=config.fetcher_name,
            user_id=admin.id,
            payload=UpdateConfigPayload(schedule_override="0 2 * * *"),
        )

        event = (await db_session.execute(select(FetcherAuditEvent))).scalars().one()
        assert event.event_type == "config_changed"
        assert event.old_value == "0 1 * * *"
        assert event.new_value == "0 2 * * *"
        assert event.detail == {"field": "schedule_override"}

    async def test_schedule_override_reset_to_null(
        self,
        db_session: AsyncSession,
        fetcher_config_factory: FetcherConfigFactory,
        user_factory: UserFactory,
    ) -> None:
        _register(_NoSettingsFetcher)
        config = await fetcher_config_factory(
            fetcher_name=_NoSettingsFetcher.name, schedule_override="0 1 * * *"
        )
        admin = await user_factory()

        result = await update_fetcher_config(
            db_session,
            fetcher_name=config.fetcher_name,
            user_id=admin.id,
            payload=UpdateConfigPayload(schedule_override=None),
        )

        assert result.config.schedule_override is None
        assert result.config.effective_schedule == _NoSettingsFetcher.default_schedule
        event = (await db_session.execute(select(FetcherAuditEvent))).scalars().one()
        assert event.old_value == "0 1 * * *"
        assert event.new_value is None

    async def test_run_timeout_and_request_delay_audit_str_values(
        self,
        db_session: AsyncSession,
        fetcher_config_factory: FetcherConfigFactory,
        user_factory: UserFactory,
    ) -> None:
        _register(_NoSettingsFetcher)
        config = await fetcher_config_factory(
            fetcher_name=_NoSettingsFetcher.name, run_timeout=3600, request_delay=0
        )
        admin = await user_factory()

        await update_fetcher_config(
            db_session,
            fetcher_name=config.fetcher_name,
            user_id=admin.id,
            payload=UpdateConfigPayload(run_timeout=600, request_delay=2.0),
        )

        events = {
            e.detail["field"]: e
            for e in (
                (await db_session.execute(select(FetcherAuditEvent))).scalars().all()
            )
            if e.detail is not None
        }
        assert events["run_timeout"].old_value == "3600"
        assert events["run_timeout"].new_value == "600"
        assert events["request_delay"].old_value == "0"
        assert events["request_delay"].new_value == "2.0"

    async def test_custom_setting_new_key_audits_null_old_value(
        self,
        db_session: AsyncSession,
        fetcher_config_factory: FetcherConfigFactory,
        user_factory: UserFactory,
    ) -> None:
        _register(_WithSettingsFetcher)
        config = await fetcher_config_factory(fetcher_name=_WithSettingsFetcher.name)
        admin = await user_factory()

        result = await update_fetcher_config(
            db_session,
            fetcher_name=config.fetcher_name,
            user_id=admin.id,
            payload=UpdateConfigPayload(custom_settings={"results_per_page": 250}),
        )

        assert result.config.custom_settings == {"results_per_page": 250}
        event = (await db_session.execute(select(FetcherAuditEvent))).scalars().one()
        assert event.old_value is None
        assert event.new_value == "250"
        assert event.detail == {"field": "custom_settings", "key": "results_per_page"}

    async def test_custom_setting_reset_to_null_removes_key(
        self,
        db_session: AsyncSession,
        fetcher_config_factory: FetcherConfigFactory,
        user_factory: UserFactory,
    ) -> None:
        _register(_WithSettingsFetcher)
        config = await fetcher_config_factory(
            fetcher_name=_WithSettingsFetcher.name,
            custom_settings={"results_per_page": 250},
        )
        admin = await user_factory()

        result = await update_fetcher_config(
            db_session,
            fetcher_name=config.fetcher_name,
            user_id=admin.id,
            payload=UpdateConfigPayload(custom_settings={"results_per_page": None}),
        )

        assert result.config.custom_settings == {}
        event = (await db_session.execute(select(FetcherAuditEvent))).scalars().one()
        assert event.old_value == "250"
        assert event.new_value is None

    async def test_custom_setting_coercion_persists_canonical_value(
        self,
        db_session: AsyncSession,
        fetcher_config_factory: FetcherConfigFactory,
        user_factory: UserFactory,
    ) -> None:
        """A coercible string value (`"500"`) is validated by the
        `Settings` model and persisted/audited as its canonical integer
        form — not the raw string payload
        (`docs/features/platform/fetcher-operations.md`,
        `update_fetcher_config`, step 6, Custom settings
        canonicalization)."""
        _register(_WithSettingsFetcher)
        config = await fetcher_config_factory(fetcher_name=_WithSettingsFetcher.name)
        admin = await user_factory()

        result = await update_fetcher_config(
            db_session,
            fetcher_name=config.fetcher_name,
            user_id=admin.id,
            payload=UpdateConfigPayload(custom_settings={"results_per_page": "500"}),
        )

        assert result.config.custom_settings == {"results_per_page": 500}
        event = (await db_session.execute(select(FetcherAuditEvent))).scalars().one()
        assert event.new_value == "500"

    async def test_legacy_raw_value_is_corrected_to_canonical_type(
        self,
        db_session: AsyncSession,
        fetcher_config_factory: FetcherConfigFactory,
        user_factory: UserFactory,
    ) -> None:
        """A pre-existing stored value with the wrong JSON type (as if
        written by direct DB manipulation before canonicalization was
        enforced) is corrected to the canonical type by a PATCH that
        submits the same logical value — the type mismatch itself
        counts as an actual change (`"500" != 500`)."""
        _register(_WithSettingsFetcher)
        config = await fetcher_config_factory(
            fetcher_name=_WithSettingsFetcher.name,
            custom_settings={"results_per_page": "500"},
        )
        admin = await user_factory()

        result = await update_fetcher_config(
            db_session,
            fetcher_name=config.fetcher_name,
            user_id=admin.id,
            payload=UpdateConfigPayload(custom_settings={"results_per_page": 500}),
        )

        assert result.config.custom_settings == {"results_per_page": 500}
        event = (await db_session.execute(select(FetcherAuditEvent))).scalars().one()
        assert event.old_value == '"500"'
        assert event.new_value == "500"

    async def test_custom_setting_no_op_when_value_matches_stored(
        self,
        db_session: AsyncSession,
        fetcher_config_factory: FetcherConfigFactory,
        user_factory: UserFactory,
    ) -> None:
        _register(_WithSettingsFetcher)
        config = await fetcher_config_factory(
            fetcher_name=_WithSettingsFetcher.name,
            custom_settings={"results_per_page": 250},
        )
        admin = await user_factory()

        result = await update_fetcher_config(
            db_session,
            fetcher_name=config.fetcher_name,
            user_id=admin.id,
            payload=UpdateConfigPayload(custom_settings={"results_per_page": 250}),
        )

        assert result.propagation is None
        events = (await db_session.execute(select(FetcherAuditEvent))).scalars().all()
        assert events == []

    async def test_orphaned_and_omitted_keys_are_untouched(
        self,
        db_session: AsyncSession,
        fetcher_config_factory: FetcherConfigFactory,
        user_factory: UserFactory,
    ) -> None:
        _register(_WithSettingsFetcher)
        config = await fetcher_config_factory(
            fetcher_name=_WithSettingsFetcher.name,
            custom_settings={"results_per_page": 250, "orphaned_key": "raw"},
        )
        admin = await user_factory()

        result = await update_fetcher_config(
            db_session,
            fetcher_name=config.fetcher_name,
            user_id=admin.id,
            payload=UpdateConfigPayload(enabled=False),
        )

        assert result.config.custom_settings == {
            "results_per_page": 250,
            "orphaned_key": "raw",
        }

    async def test_full_no_op_creates_no_audit_and_leaves_updated_at_unchanged(
        self,
        db_session: AsyncSession,
        fetcher_config_factory: FetcherConfigFactory,
        user_factory: UserFactory,
    ) -> None:
        _register(_NoSettingsFetcher)
        config = await fetcher_config_factory(
            fetcher_name=_NoSettingsFetcher.name,
            enabled=True,
            run_timeout=3600,
            request_delay=1.5,
        )
        original_updated_at = config.updated_at
        admin = await user_factory()

        result = await update_fetcher_config(
            db_session,
            fetcher_name=config.fetcher_name,
            user_id=admin.id,
            payload=UpdateConfigPayload(
                enabled=True, run_timeout=3600, request_delay=1.5
            ),
        )

        assert result.propagation is None
        assert result.config.updated_at == original_updated_at
        events = (await db_session.execute(select(FetcherAuditEvent))).scalars().all()
        assert events == []

    async def test_empty_custom_settings_object_on_no_settings_fetcher_is_noop(
        self,
        db_session: AsyncSession,
        fetcher_config_factory: FetcherConfigFactory,
        user_factory: UserFactory,
    ) -> None:
        """An explicitly submitted empty `custom_settings` object
        (`{}`) is distinct from omission (`MissingType`) and from
        `null` (rejected at the schema layer) — the merge/validation
        block is skipped because there are no keys to process. For a
        fetcher with no `Settings` model, this guard also prevents an
        `AttributeError` from calling `model_validate` on `None` —
        proving the short-circuit is correct even when no settings
        class exists to validate against."""
        _register(_NoSettingsFetcher)
        config = await fetcher_config_factory(fetcher_name=_NoSettingsFetcher.name)
        original_updated_at = config.updated_at
        admin = await user_factory()

        result = await update_fetcher_config(
            db_session,
            fetcher_name=config.fetcher_name,
            user_id=admin.id,
            payload=UpdateConfigPayload(custom_settings={}),
        )

        assert result.config.updated_at == original_updated_at
        events = (await db_session.execute(select(FetcherAuditEvent))).scalars().all()
        assert events == []

    async def test_multiple_field_changes_produce_events_in_deterministic_order(
        self,
        db_session: AsyncSession,
        fetcher_config_factory: FetcherConfigFactory,
        user_factory: UserFactory,
    ) -> None:
        _register(_MultiSettingsFetcher)
        config = await fetcher_config_factory(
            fetcher_name=_MultiSettingsFetcher.name,
            enabled=True,
            schedule_override="0 1 * * *",
            run_timeout=3600,
            request_delay=0,
        )
        admin = await user_factory()

        await update_fetcher_config(
            db_session,
            fetcher_name=config.fetcher_name,
            user_id=admin.id,
            payload=UpdateConfigPayload(
                enabled=False,
                schedule_override="0 2 * * *",
                run_timeout=600,
                request_delay=3.0,
                custom_settings={"zeta_setting": 5, "alpha_setting": 9},
            ),
        )

        events = (
            (
                await db_session.execute(
                    select(FetcherAuditEvent).order_by(FetcherAuditEvent.id)
                )
            )
            .scalars()
            .all()
        )
        ordering = []
        for event in events:
            if event.detail is None:
                ordering.append(event.event_type)
            elif event.detail["field"] == "custom_settings":
                ordering.append(event.detail["key"])
            else:
                ordering.append(event.detail["field"])

        assert ordering == [
            "disabled",
            "schedule_override",
            "run_timeout",
            "request_delay",
            "alpha_setting",
            "zeta_setting",
        ]
        assert all(e.user_id == admin.id for e in events)
        assert len({e.created_at for e in events}) == 1


# ---------------------------------------------------------------------------
# update_fetcher_config — RedBeat propagation descriptor
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestUpdateFetcherConfigPropagation:
    async def test_enabled_false_produces_delete_action(
        self,
        db_session: AsyncSession,
        fetcher_config_factory: FetcherConfigFactory,
        user_factory: UserFactory,
    ) -> None:
        _register(_NoSettingsFetcher)
        config = await fetcher_config_factory(
            fetcher_name=_NoSettingsFetcher.name, enabled=True
        )
        admin = await user_factory()

        result = await update_fetcher_config(
            db_session,
            fetcher_name=config.fetcher_name,
            user_id=admin.id,
            payload=UpdateConfigPayload(enabled=False),
        )

        assert result.propagation is not None
        assert result.propagation.action == "delete"

    async def test_enabled_false_combined_with_schedule_change_still_deletes(
        self,
        db_session: AsyncSession,
        fetcher_config_factory: FetcherConfigFactory,
        user_factory: UserFactory,
    ) -> None:
        """`enabled -> false` takes precedence over any other
        schedule-affecting change in the same PATCH: the entry is
        deleted, not upserted with the new schedule/timeout — per
        `docs/features/platform/fetcher-operations.md`
        (`update_fetcher_config`, RedBeat Post-Commit Propagation)."""
        _register(_NoSettingsFetcher)
        config = await fetcher_config_factory(
            fetcher_name=_NoSettingsFetcher.name,
            enabled=True,
            schedule_override="0 9 * * *",
            run_timeout=1200,
        )
        admin = await user_factory()

        result = await update_fetcher_config(
            db_session,
            fetcher_name=config.fetcher_name,
            user_id=admin.id,
            payload=UpdateConfigPayload(
                enabled=False, schedule_override="0 11 * * *", run_timeout=1800
            ),
        )

        assert result.propagation is not None
        assert result.propagation.action == "delete"

    async def test_enabled_true_produces_upsert_with_effective_values(
        self,
        db_session: AsyncSession,
        fetcher_config_factory: FetcherConfigFactory,
        user_factory: UserFactory,
    ) -> None:
        _register(_NoSettingsFetcher)
        config = await fetcher_config_factory(
            fetcher_name=_NoSettingsFetcher.name,
            enabled=False,
            schedule_override="0 9 * * *",
            run_timeout=1200,
        )
        admin = await user_factory()

        result = await update_fetcher_config(
            db_session,
            fetcher_name=config.fetcher_name,
            user_id=admin.id,
            payload=UpdateConfigPayload(enabled=True),
        )

        assert result.propagation is not None
        assert result.propagation.action == "upsert"
        assert result.propagation.schedule_override == "0 9 * * *"
        assert result.propagation.run_timeout == 1200

    async def test_schedule_override_change_while_enabled_produces_upsert(
        self,
        db_session: AsyncSession,
        fetcher_config_factory: FetcherConfigFactory,
        user_factory: UserFactory,
    ) -> None:
        _register(_NoSettingsFetcher)
        config = await fetcher_config_factory(
            fetcher_name=_NoSettingsFetcher.name, enabled=True
        )
        admin = await user_factory()

        result = await update_fetcher_config(
            db_session,
            fetcher_name=config.fetcher_name,
            user_id=admin.id,
            payload=UpdateConfigPayload(schedule_override="0 7 * * *"),
        )

        assert result.propagation is not None
        assert result.propagation.action == "upsert"

    async def test_schedule_override_change_while_disabled_produces_no_propagation(
        self,
        db_session: AsyncSession,
        fetcher_config_factory: FetcherConfigFactory,
        user_factory: UserFactory,
    ) -> None:
        _register(_NoSettingsFetcher)
        config = await fetcher_config_factory(
            fetcher_name=_NoSettingsFetcher.name, enabled=False
        )
        admin = await user_factory()

        result = await update_fetcher_config(
            db_session,
            fetcher_name=config.fetcher_name,
            user_id=admin.id,
            payload=UpdateConfigPayload(schedule_override="0 7 * * *"),
        )

        assert result.propagation is None

    async def test_request_delay_change_alone_produces_no_propagation(
        self,
        db_session: AsyncSession,
        fetcher_config_factory: FetcherConfigFactory,
        user_factory: UserFactory,
    ) -> None:
        _register(_NoSettingsFetcher)
        config = await fetcher_config_factory(
            fetcher_name=_NoSettingsFetcher.name, enabled=True, request_delay=0
        )
        admin = await user_factory()

        result = await update_fetcher_config(
            db_session,
            fetcher_name=config.fetcher_name,
            user_id=admin.id,
            payload=UpdateConfigPayload(request_delay=9.0),
        )

        assert result.propagation is None

    async def test_custom_settings_change_alone_produces_no_propagation(
        self,
        db_session: AsyncSession,
        fetcher_config_factory: FetcherConfigFactory,
        user_factory: UserFactory,
    ) -> None:
        _register(_WithSettingsFetcher)
        config = await fetcher_config_factory(
            fetcher_name=_WithSettingsFetcher.name, enabled=True
        )
        admin = await user_factory()

        result = await update_fetcher_config(
            db_session,
            fetcher_name=config.fetcher_name,
            user_id=admin.id,
            payload=UpdateConfigPayload(custom_settings={"results_per_page": 400}),
        )

        assert result.propagation is None


# ---------------------------------------------------------------------------
# update_fetcher_config — transaction contract
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestUpdateFetcherConfigTransaction:
    async def test_does_not_commit(
        self,
        db_session: AsyncSession,
        fetcher_config_factory: FetcherConfigFactory,
        user_factory: UserFactory,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        _register(_NoSettingsFetcher)
        config = await fetcher_config_factory(
            fetcher_name=_NoSettingsFetcher.name, enabled=True
        )
        admin = await user_factory()
        commit_spy = AsyncMock(wraps=db_session.commit)
        monkeypatch.setattr(db_session, "commit", commit_spy)

        await update_fetcher_config(
            db_session,
            fetcher_name=config.fetcher_name,
            user_id=admin.id,
            payload=UpdateConfigPayload(enabled=False),
        )

        commit_spy.assert_not_called()

    async def test_flushes_within_the_caller_transaction(
        self,
        db_session: AsyncSession,
        fetcher_config_factory: FetcherConfigFactory,
        user_factory: UserFactory,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """At least one explicit flush occurs within the caller's
        transaction (never a commit/rollback). A second flush may occur
        as a side effect of the `updated_at` attribute refresh
        (`db.refresh(config, attribute_names=["updated_at"])`), whose
        own `SELECT` is itself subject to the session's default
        autoflush — the exact internal call count is not a contract."""
        _register(_NoSettingsFetcher)
        config = await fetcher_config_factory(
            fetcher_name=_NoSettingsFetcher.name, enabled=True
        )
        admin = await user_factory()
        flush_spy = AsyncMock(wraps=db_session.flush)
        monkeypatch.setattr(db_session, "flush", flush_spy)

        await update_fetcher_config(
            db_session,
            fetcher_name=config.fetcher_name,
            user_id=admin.id,
            payload=UpdateConfigPayload(enabled=False),
        )

        assert flush_spy.await_count >= 1

    async def test_rollback_removes_mutation_and_audit_together(
        self,
        db_session: AsyncSession,
        fetcher_config_factory: FetcherConfigFactory,
        user_factory: UserFactory,
    ) -> None:
        """If the caller's transaction rolls back, neither the
        `FetcherConfig` mutation nor its audit event survives — proving
        both share the same transaction."""
        _register(_NoSettingsFetcher)
        config = await fetcher_config_factory(
            fetcher_name=_NoSettingsFetcher.name, enabled=True
        )
        fetcher_name = config.fetcher_name
        admin = await user_factory()
        # Commit the base state first so the later local rollback only
        # undoes the mutation below, not the fixture-created rows.
        await db_session.commit()

        await update_fetcher_config(
            db_session,
            fetcher_name=fetcher_name,
            user_id=admin.id,
            payload=UpdateConfigPayload(enabled=False),
        )
        events = (await db_session.execute(select(FetcherAuditEvent))).scalars().all()
        assert len(events) == 1

        await db_session.rollback()

        # `config.fetcher_name` is not re-read here — `rollback()`
        # expires every attribute on every object in the session,
        # including the primary key, and an expired attribute's
        # implicit reload is a synchronous operation unsupported
        # outside a greenlet context under `AsyncSession`/asyncpg. The
        # `fetcher_name` captured above (before any commit/rollback)
        # is a plain `str`, unaffected by expiration.
        refreshed = (
            await db_session.execute(
                select(FetcherConfig).where(FetcherConfig.fetcher_name == fetcher_name)
            )
        ).scalar_one()
        assert refreshed.enabled is True
        events_after = (
            (await db_session.execute(select(FetcherAuditEvent))).scalars().all()
        )
        assert events_after == []


# ---------------------------------------------------------------------------
# update_fetcher_config — true concurrency (FetcherConfig-root lock)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestUpdateFetcherConfigConcurrency:
    """See docs/features/platform/testing-strategy.md (Concurrency
    Testing) for the canonical two-session pattern applied here."""

    async def test_concurrent_updates_serialize_on_the_config_lock(
        self,
        db_session_factory: Callable[[], Awaitable[AsyncSession]],
    ) -> None:
        # A per-test unique name: this test commits real rows (see
        # `db_session_factory`'s docstring), so a fixed registry name
        # shared with other tests in this file risks collisions with
        # leftover data from a previous failed run.
        fetcher_name = f"concurrency_cfg_{uuid4().hex[:8]}"

        class _ConcurrencyFetcherStub:
            name = fetcher_name
            description = "Concurrency test fetcher"
            default_schedule = "0 3 * * *"
            queue: str | None = None
            Settings: type[BaseModel] | None = None

        _register(cast("type[Any]", _ConcurrencyFetcherStub))
        session_a = await db_session_factory()
        session_b = await db_session_factory()

        admin = User(
            username=f"cfgadmin{uuid4().hex[:8]}",
            email=f"cfgadmin{uuid4().hex[:8]}@example.com",
            password_hash="$2b$12$" + "a" * 53,
        )
        session_a.add(admin)
        session_a.add(
            FetcherConfig(
                fetcher_name=fetcher_name,
                enabled=True,
                request_delay=0,
            )
        )
        await session_a.commit()

        # Session A acquires the FetcherConfig lock, applies its
        # mutation, and flushes — but does not commit yet, holding the
        # lock open.
        result_a = await update_fetcher_config(
            session_a,
            fetcher_name=fetcher_name,
            user_id=admin.id,
            payload=UpdateConfigPayload(request_delay=5.0),
        )
        assert result_a.config.request_delay == 5.0

        # Session B's concurrent update attempt blocks on the same
        # FetcherConfig row.
        task_b = asyncio.create_task(
            update_fetcher_config(
                session_b,
                fetcher_name=fetcher_name,
                user_id=admin.id,
                payload=UpdateConfigPayload(request_delay=9.0),
            )
        )
        with pytest.raises(TimeoutError):
            await asyncio.wait_for(asyncio.shield(task_b), timeout=0.3)

        # Releasing A's lock lets B proceed — B observes A's committed
        # value (5.0) as its "old" state, not the pre-A value (0.0).
        await session_a.commit()
        result_b = await asyncio.wait_for(task_b, timeout=5)
        await session_b.commit()

        assert result_b.config.request_delay == 9.0

        events = (
            (
                await session_a.execute(
                    select(FetcherAuditEvent)
                    .where(FetcherAuditEvent.fetcher_name == fetcher_name)
                    .order_by(FetcherAuditEvent.id)
                )
            )
            .scalars()
            .all()
        )
        assert [e.old_value for e in events] == ["0.0", "5.0"]
        assert [e.new_value for e in events] == ["5.0", "9.0"]

        # Explicit cleanup — committed rows are not covered by
        # db_session_factory's rollback-on-teardown.
        await session_a.execute(
            delete(FetcherAuditEvent).where(
                FetcherAuditEvent.fetcher_name == fetcher_name
            )
        )
        await session_a.execute(
            delete(FetcherConfig).where(FetcherConfig.fetcher_name == fetcher_name)
        )
        await session_a.execute(delete(User).where(User.id == admin.id))
        await session_a.commit()


@pytest.mark.integration
class TestListFetcherAuditEvents:
    async def test_unknown_fetcher_raises_not_found(
        self, db_session: AsyncSession
    ) -> None:
        FETCHER_REGISTRY.clear()
        with pytest.raises(FetcherNotFoundError):
            await list_fetcher_audit_events(
                db_session, fetcher_name="no-such-fetcher", page=1, per_page=20
            )

    async def test_all_invalid_event_types_still_validates_fetcher_existence(
        self, db_session: AsyncSession
    ) -> None:
        """An entirely-invalid `event_type` filter set must not mask a
        nonexistent fetcher behind an empty `200`-equivalent page — the
        existence check always runs first."""
        FETCHER_REGISTRY.clear()
        with pytest.raises(FetcherNotFoundError):
            await list_fetcher_audit_events(
                db_session,
                fetcher_name="no-such-fetcher",
                page=1,
                per_page=20,
                event_type=["not_a_real_type"],
            )

    async def test_isolates_by_fetcher_name(
        self,
        db_session: AsyncSession,
        fetcher_config_factory: FetcherConfigFactory,
        fetcher_audit_event_factory: FetcherAuditEventFactory,
    ) -> None:
        config_a = await fetcher_config_factory()
        config_b = await fetcher_config_factory()
        await fetcher_audit_event_factory(fetcher_name=config_a.fetcher_name)
        await fetcher_audit_event_factory(fetcher_name=config_b.fetcher_name)

        page = await list_fetcher_audit_events(
            db_session, fetcher_name=config_a.fetcher_name, page=1, per_page=20
        )

        assert page.total == 1
        assert page.items[0].fetcher_name == config_a.fetcher_name

    async def test_actor_is_eagerly_loaded(
        self,
        db_session: AsyncSession,
        fetcher_config_factory: FetcherConfigFactory,
        fetcher_audit_event_factory: FetcherAuditEventFactory,
        user_factory: UserFactory,
    ) -> None:
        config = await fetcher_config_factory()
        actor = await user_factory(username="eagerloadfetcheractor")
        await fetcher_audit_event_factory(
            fetcher_name=config.fetcher_name, user_id=actor.id
        )

        page = await list_fetcher_audit_events(
            db_session, fetcher_name=config.fetcher_name, page=1, per_page=20
        )

        assert page.items[0].actor is not None
        assert page.items[0].actor.username == "eagerloadfetcheractor"

    async def test_filter_by_actor_uuid(
        self,
        db_session: AsyncSession,
        fetcher_config_factory: FetcherConfigFactory,
        fetcher_audit_event_factory: FetcherAuditEventFactory,
        user_factory: UserFactory,
    ) -> None:
        config = await fetcher_config_factory()
        actor = await user_factory()
        other_actor = await user_factory()
        await fetcher_audit_event_factory(
            fetcher_name=config.fetcher_name, user_id=actor.id
        )
        await fetcher_audit_event_factory(
            fetcher_name=config.fetcher_name, user_id=other_actor.id
        )

        page = await list_fetcher_audit_events(
            db_session,
            fetcher_name=config.fetcher_name,
            page=1,
            per_page=20,
            actor=str(actor.id),
        )

        assert page.total == 1
        assert page.items[0].user_id == actor.id

    async def test_filter_by_actor_username(
        self,
        db_session: AsyncSession,
        fetcher_config_factory: FetcherConfigFactory,
        fetcher_audit_event_factory: FetcherAuditEventFactory,
        user_factory: UserFactory,
    ) -> None:
        config = await fetcher_config_factory()
        actor = await user_factory(username="filterbyusernamefetcher")
        await fetcher_audit_event_factory(
            fetcher_name=config.fetcher_name, user_id=actor.id
        )

        page = await list_fetcher_audit_events(
            db_session,
            fetcher_name=config.fetcher_name,
            page=1,
            per_page=20,
            actor="filterbyusernamefetcher",
        )

        assert page.total == 1

    async def test_unknown_actor_returns_empty_page(
        self,
        db_session: AsyncSession,
        fetcher_config_factory: FetcherConfigFactory,
        fetcher_audit_event_factory: FetcherAuditEventFactory,
    ) -> None:
        config = await fetcher_config_factory()
        await fetcher_audit_event_factory(fetcher_name=config.fetcher_name)

        page = await list_fetcher_audit_events(
            db_session,
            fetcher_name=config.fetcher_name,
            page=1,
            per_page=20,
            actor="no-such-actor",
        )

        assert page.total == 0

    async def test_system_literal_returns_empty_page(
        self,
        db_session: AsyncSession,
        fetcher_config_factory: FetcherConfigFactory,
        fetcher_audit_event_factory: FetcherAuditEventFactory,
    ) -> None:
        """Every fetcher audit event has a human actor — `"system"`
        never matches any row (`FetcherAuditLog.log_event()` enforces a
        non-null `user_id`)."""
        config = await fetcher_config_factory()
        await fetcher_audit_event_factory(fetcher_name=config.fetcher_name)

        page = await list_fetcher_audit_events(
            db_session,
            fetcher_name=config.fetcher_name,
            page=1,
            per_page=20,
            actor="system",
        )

        assert page.total == 0

    async def test_matching_event_type_is_included(
        self,
        db_session: AsyncSession,
        fetcher_config_factory: FetcherConfigFactory,
        fetcher_audit_event_factory: FetcherAuditEventFactory,
    ) -> None:
        config = await fetcher_config_factory()
        await fetcher_audit_event_factory(
            fetcher_name=config.fetcher_name, event_type="disabled"
        )

        page = await list_fetcher_audit_events(
            db_session,
            fetcher_name=config.fetcher_name,
            page=1,
            per_page=20,
            event_type=["disabled"],
        )

        assert page.total == 1

    async def test_repeatable_event_types_combine_with_or(
        self,
        db_session: AsyncSession,
        fetcher_config_factory: FetcherConfigFactory,
        fetcher_audit_event_factory: FetcherAuditEventFactory,
    ) -> None:
        config = await fetcher_config_factory()
        await fetcher_audit_event_factory(
            fetcher_name=config.fetcher_name, event_type="disabled"
        )
        await fetcher_audit_event_factory(
            fetcher_name=config.fetcher_name, event_type="enabled"
        )
        await fetcher_audit_event_factory(
            fetcher_name=config.fetcher_name, event_type="triggered"
        )

        page = await list_fetcher_audit_events(
            db_session,
            fetcher_name=config.fetcher_name,
            page=1,
            per_page=20,
            event_type=["disabled", "enabled"],
        )

        assert page.total == 2

    async def test_mixed_valid_and_invalid_event_types_keeps_valid(
        self,
        db_session: AsyncSession,
        fetcher_config_factory: FetcherConfigFactory,
        fetcher_audit_event_factory: FetcherAuditEventFactory,
    ) -> None:
        config = await fetcher_config_factory()
        await fetcher_audit_event_factory(
            fetcher_name=config.fetcher_name, event_type="disabled"
        )

        page = await list_fetcher_audit_events(
            db_session,
            fetcher_name=config.fetcher_name,
            page=1,
            per_page=20,
            event_type=["disabled", "not_a_real_type"],
        )

        assert page.total == 1

    async def test_all_invalid_event_types_returns_empty_page(
        self,
        db_session: AsyncSession,
        fetcher_config_factory: FetcherConfigFactory,
        fetcher_audit_event_factory: FetcherAuditEventFactory,
    ) -> None:
        config = await fetcher_config_factory()
        await fetcher_audit_event_factory(fetcher_name=config.fetcher_name)

        page = await list_fetcher_audit_events(
            db_session,
            fetcher_name=config.fetcher_name,
            page=1,
            per_page=20,
            event_type=["not_a_real_type"],
        )

        assert page.total == 0
        assert page.items == []

    async def test_comma_separated_value_is_treated_as_single_invalid_value(
        self,
        db_session: AsyncSession,
        fetcher_config_factory: FetcherConfigFactory,
        fetcher_audit_event_factory: FetcherAuditEventFactory,
    ) -> None:
        config = await fetcher_config_factory()
        await fetcher_audit_event_factory(
            fetcher_name=config.fetcher_name, event_type="disabled"
        )

        page = await list_fetcher_audit_events(
            db_session,
            fetcher_name=config.fetcher_name,
            page=1,
            per_page=20,
            event_type=["disabled,enabled"],
        )

        assert page.total == 0

    async def test_empty_event_type_list_applies_no_filter(
        self,
        db_session: AsyncSession,
        fetcher_config_factory: FetcherConfigFactory,
        fetcher_audit_event_factory: FetcherAuditEventFactory,
    ) -> None:
        config = await fetcher_config_factory()
        await fetcher_audit_event_factory(fetcher_name=config.fetcher_name)
        await fetcher_audit_event_factory(fetcher_name=config.fetcher_name)

        page = await list_fetcher_audit_events(
            db_session,
            fetcher_name=config.fetcher_name,
            page=1,
            per_page=20,
            event_type=[],
        )

        assert page.total == 2

    async def test_inclusive_from_and_to_date(
        self,
        db_session: AsyncSession,
        fetcher_config_factory: FetcherConfigFactory,
        fetcher_audit_event_factory: FetcherAuditEventFactory,
    ) -> None:
        config = await fetcher_config_factory()
        in_range = await fetcher_audit_event_factory(
            fetcher_name=config.fetcher_name,
            created_at=datetime(2026, 5, 13, tzinfo=UTC),
        )
        await fetcher_audit_event_factory(
            fetcher_name=config.fetcher_name,
            created_at=datetime(2026, 1, 1, tzinfo=UTC),
        )

        page = await list_fetcher_audit_events(
            db_session,
            fetcher_name=config.fetcher_name,
            page=1,
            per_page=20,
            from_date=datetime(2026, 5, 1, tzinfo=UTC),
            to_date=datetime(2026, 5, 31, tzinfo=UTC),
        )

        assert page.total == 1
        assert page.items[0].id == in_range.id

    async def test_date_only_bounds_cover_full_day(
        self,
        db_session: AsyncSession,
        fetcher_config_factory: FetcherConfigFactory,
        fetcher_audit_event_factory: FetcherAuditEventFactory,
    ) -> None:
        config = await fetcher_config_factory()
        event = await fetcher_audit_event_factory(
            fetcher_name=config.fetcher_name,
            created_at=datetime(2026, 5, 13, 23, 59, 0, tzinfo=UTC),
        )

        page = await list_fetcher_audit_events(
            db_session,
            fetcher_name=config.fetcher_name,
            page=1,
            per_page=20,
            from_date=datetime(2026, 5, 13, tzinfo=UTC).date(),
            to_date=None,
        )

        assert page.total == 1
        assert page.items[0].id == event.id

    async def test_filters_combine_with_and(
        self,
        db_session: AsyncSession,
        fetcher_config_factory: FetcherConfigFactory,
        fetcher_audit_event_factory: FetcherAuditEventFactory,
        user_factory: UserFactory,
    ) -> None:
        config = await fetcher_config_factory()
        actor = await user_factory()
        await fetcher_audit_event_factory(
            fetcher_name=config.fetcher_name, user_id=actor.id, event_type="disabled"
        )
        other_actor = await user_factory()
        await fetcher_audit_event_factory(
            fetcher_name=config.fetcher_name,
            user_id=other_actor.id,
            event_type="disabled",
        )

        page = await list_fetcher_audit_events(
            db_session,
            fetcher_name=config.fetcher_name,
            page=1,
            per_page=20,
            actor=str(actor.id),
            event_type=["disabled"],
        )

        assert page.total == 1

    async def test_reports_filtered_total(
        self,
        db_session: AsyncSession,
        fetcher_config_factory: FetcherConfigFactory,
        fetcher_audit_event_factory: FetcherAuditEventFactory,
    ) -> None:
        config = await fetcher_config_factory()
        for _ in range(3):
            await fetcher_audit_event_factory(fetcher_name=config.fetcher_name)

        page = await list_fetcher_audit_events(
            db_session,
            fetcher_name=config.fetcher_name,
            page=1,
            per_page=2,
        )

        assert page.total == 3
        assert len(page.items) == 2

    async def test_page_beyond_last_page_returns_empty_with_correct_total(
        self,
        db_session: AsyncSession,
        fetcher_config_factory: FetcherConfigFactory,
        fetcher_audit_event_factory: FetcherAuditEventFactory,
    ) -> None:
        config = await fetcher_config_factory()
        await fetcher_audit_event_factory(fetcher_name=config.fetcher_name)

        page = await list_fetcher_audit_events(
            db_session,
            fetcher_name=config.fetcher_name,
            page=2,
            per_page=20,
        )

        assert page.items == []
        assert page.total == 1

    async def test_orders_newest_first_via_id_desc(
        self,
        db_session: AsyncSession,
        fetcher_config_factory: FetcherConfigFactory,
        fetcher_audit_event_factory: FetcherAuditEventFactory,
    ) -> None:
        config = await fetcher_config_factory()
        older = await fetcher_audit_event_factory(
            fetcher_name=config.fetcher_name,
            created_at=datetime(2026, 5, 1, tzinfo=UTC),
        )
        newer = await fetcher_audit_event_factory(
            fetcher_name=config.fetcher_name,
            created_at=datetime(2026, 5, 2, tzinfo=UTC),
        )

        page = await list_fetcher_audit_events(
            db_session, fetcher_name=config.fetcher_name, page=1, per_page=20
        )

        assert [item.id for item in page.items] == [newer.id, older.id]

    async def test_equal_created_at_breaks_tie_by_id_desc(
        self,
        db_session: AsyncSession,
        fetcher_config_factory: FetcherConfigFactory,
        fetcher_audit_event_factory: FetcherAuditEventFactory,
    ) -> None:
        config = await fetcher_config_factory()
        same_time = datetime(2026, 5, 13, tzinfo=UTC)
        first = await fetcher_audit_event_factory(
            fetcher_name=config.fetcher_name, created_at=same_time
        )
        second = await fetcher_audit_event_factory(
            fetcher_name=config.fetcher_name, created_at=same_time
        )
        expected_order = sorted([first.id, second.id], reverse=True)

        page = await list_fetcher_audit_events(
            db_session, fetcher_name=config.fetcher_name, page=1, per_page=20
        )

        assert [item.id for item in page.items] == expected_order

    async def test_no_audit_event_or_mutation_created(
        self,
        db_session: AsyncSession,
        fetcher_config_factory: FetcherConfigFactory,
        fetcher_audit_event_factory: FetcherAuditEventFactory,
    ) -> None:
        config = await fetcher_config_factory()
        await fetcher_audit_event_factory(fetcher_name=config.fetcher_name)

        await list_fetcher_audit_events(
            db_session, fetcher_name=config.fetcher_name, page=1, per_page=20
        )

        rows = (await db_session.execute(select(FetcherAuditEvent))).scalars().all()
        assert len(rows) == 1

    async def test_database_error_propagates_unchanged(
        self,
        db_session: AsyncSession,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        async def _boom(*args: Any, **kwargs: Any) -> None:
            raise OperationalError("simulated", {}, Exception("boom"))

        monkeypatch.setattr(db_session, "execute", _boom)

        with pytest.raises(OperationalError):
            await list_fetcher_audit_events(
                db_session, fetcher_name="irrelevant", page=1, per_page=20
            )


# ---------------------------------------------------------------------------
# trigger_fetcher()
# ---------------------------------------------------------------------------
#
# Unlike every other function tested in this module, `trigger_fetcher()`
# manages its own sessions and commits real transactions — it cannot
# accept the savepoint-scoped `db_session` fixture (see that function's
# docstring and `docs/features/platform/fetcher-operations.md`,
# `trigger_fetcher`). Every test below therefore uses `real_session_factory`
# (a real `async_sessionmaker`, per `tests/conftest.py`) both to pass as
# `trigger_fetcher`'s `session_factory` argument and to arrange/clean up
# its own committed `FetcherConfig`/`User`/`FetcherRun` rows directly —
# the `fetcher_config_factory`/`user_factory`/`fetcher_run_factory`
# fixtures are bound to the separate, savepoint-scoped `db_session`
# connection and are therefore invisible to `trigger_fetcher`'s own
# sessions. `celery_test_app` (real Celery app, isolated test Redis) is
# used as `celery_app`; its `send_task` is monkeypatched per test to
# control the Celery publication outcome deterministically without
# depending on network I/O or a running worker.


def _stub_fetcher_class(name: str, *, queue: str | None = None) -> type[BaseFetcher]:
    """Build a per-test `FETCHER_REGISTRY`-shaped stub class with the
    given `name` — deliberately NOT a `BaseFetcher` subclass (see
    `test_fetcher_schedule.py`, Test Independence). `trigger_fetcher()`
    tests generate a unique `fetcher_name` per test (real commits, no
    savepoint isolation — see module note above), so the registry key
    must match that generated name exactly, which the shared
    `_NoSettingsFetcher`-style stubs (fixed `name`) cannot provide."""
    return cast(
        "type[BaseFetcher]",
        type(
            "_DynamicStubFetcher",
            (),
            {
                "name": name,
                "description": "Stub fetcher for trigger_fetcher() tests",
                "default_schedule": "0 3 * * *",
                "queue": queue,
                "Settings": None,
            },
        ),
    )


async def _cleanup_trigger_rows(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    fetcher_name: str,
    user_id: UUID,
) -> None:
    async with session_factory() as session:
        await session.execute(
            delete(FetcherAuditEvent).where(
                FetcherAuditEvent.fetcher_name == fetcher_name
            )
        )
        await session.execute(
            delete(FetcherRun).where(FetcherRun.fetcher_name == fetcher_name)
        )
        await session.execute(
            delete(FetcherConfig).where(FetcherConfig.fetcher_name == fetcher_name)
        )
        await session.execute(delete(User).where(User.id == user_id))
        await session.commit()


@pytest.fixture
async def trigger_env(
    real_session_factory: async_sessionmaker[AsyncSession],
) -> AsyncGenerator[tuple[str, UUID]]:
    """A real, committed, enabled `FetcherConfig` row
    (`run_timeout=3600`) and admin `User`, registered under a unique
    per-test fetcher name. Yields `(fetcher_name, user_id)`; cleans up
    explicitly on teardown (see module note above)."""
    fetcher_name = f"trigger_test_{uuid4().hex[:8]}"
    _register(_stub_fetcher_class(fetcher_name))
    async with real_session_factory() as session:
        admin = User(
            username=f"triggeradmin{uuid4().hex[:8]}",
            email=f"triggeradmin{uuid4().hex[:8]}@example.com",
            password_hash="$2b$12$" + "a" * 53,
        )
        session.add(admin)
        session.add(
            FetcherConfig(fetcher_name=fetcher_name, enabled=True, run_timeout=3600)
        )
        await session.commit()
        user_id = admin.id

    yield fetcher_name, user_id

    await _cleanup_trigger_rows(
        real_session_factory, fetcher_name=fetcher_name, user_id=user_id
    )


@pytest.mark.integration
class TestTriggerFetcherGuards:
    async def test_unregistered_and_no_config_row_raises_not_found(
        self,
        real_session_factory: async_sessionmaker[AsyncSession],
        celery_test_app: Celery,
    ) -> None:
        FETCHER_REGISTRY.clear()
        with pytest.raises(FetcherNotFoundError):
            await trigger_fetcher(
                "no-such-fetcher",
                user_id=uuid4(),
                session_factory=real_session_factory,
                celery_app=celery_test_app,
            )

    async def test_registered_but_no_config_row_raises_not_found(
        self,
        real_session_factory: async_sessionmaker[AsyncSession],
        celery_test_app: Celery,
    ) -> None:
        """A registered fetcher with no `FetcherConfig` row yet
        (bootstrap not run) is a prerequisite failure, consistent with
        `update_fetcher_config`/`get_fetcher_config`."""
        fetcher_name = f"trigger_bootstrap_{uuid4().hex[:8]}"
        _register(_stub_fetcher_class(fetcher_name))
        with pytest.raises(FetcherNotFoundError):
            await trigger_fetcher(
                fetcher_name,
                user_id=uuid4(),
                session_factory=real_session_factory,
                celery_app=celery_test_app,
            )

    async def test_deregistered_config_row_raises_deregistered(
        self,
        real_session_factory: async_sessionmaker[AsyncSession],
        celery_test_app: Celery,
    ) -> None:
        FETCHER_REGISTRY.clear()
        fetcher_name = f"trigger_deregistered_{uuid4().hex[:8]}"
        async with real_session_factory() as session:
            admin = User(
                username=f"deregadmin{uuid4().hex[:8]}",
                email=f"deregadmin{uuid4().hex[:8]}@example.com",
                password_hash="$2b$12$" + "a" * 53,
            )
            session.add(admin)
            session.add(FetcherConfig(fetcher_name=fetcher_name, enabled=True))
            await session.commit()
            user_id = admin.id

        try:
            with pytest.raises(FetcherDeregisteredError):
                await trigger_fetcher(
                    fetcher_name,
                    user_id=user_id,
                    session_factory=real_session_factory,
                    celery_app=celery_test_app,
                )
        finally:
            await _cleanup_trigger_rows(
                real_session_factory, fetcher_name=fetcher_name, user_id=user_id
            )

    async def test_disabled_fetcher_raises_disabled(
        self,
        trigger_env: tuple[str, UUID],
        real_session_factory: async_sessionmaker[AsyncSession],
        celery_test_app: Celery,
    ) -> None:
        fetcher_name, user_id = trigger_env
        async with real_session_factory() as session:
            config = await session.get(FetcherConfig, fetcher_name)
            assert config is not None
            config.enabled = False
            await session.commit()

        with pytest.raises(FetcherDisabledError):
            await trigger_fetcher(
                fetcher_name,
                user_id=user_id,
                session_factory=real_session_factory,
                celery_app=celery_test_app,
            )

    async def test_active_queued_run_raises_already_running(
        self,
        trigger_env: tuple[str, UUID],
        real_session_factory: async_sessionmaker[AsyncSession],
        celery_test_app: Celery,
    ) -> None:
        fetcher_name, user_id = trigger_env
        async with real_session_factory() as session:
            session.add(
                FetcherRun(
                    fetcher_name=fetcher_name,
                    status="queued",
                    triggered_by="manual",
                    triggered_by_user_id=user_id,
                )
            )
            await session.commit()

        with pytest.raises(FetcherAlreadyRunningError):
            await trigger_fetcher(
                fetcher_name,
                user_id=user_id,
                session_factory=real_session_factory,
                celery_app=celery_test_app,
            )

        async with real_session_factory() as session:
            runs = (
                (
                    await session.execute(
                        select(FetcherRun).where(
                            FetcherRun.fetcher_name == fetcher_name
                        )
                    )
                )
                .scalars()
                .all()
            )
        assert len(runs) == 1
        assert runs[0].status == "queued"

    async def test_active_running_run_raises_already_running(
        self,
        trigger_env: tuple[str, UUID],
        real_session_factory: async_sessionmaker[AsyncSession],
        celery_test_app: Celery,
    ) -> None:
        fetcher_name, user_id = trigger_env
        async with real_session_factory() as session:
            session.add(
                FetcherRun(
                    fetcher_name=fetcher_name,
                    status="running",
                    triggered_by="schedule",
                    started_at=datetime.now(UTC),
                    hard_time_limit_seconds=3600,
                )
            )
            await session.commit()

        with pytest.raises(FetcherAlreadyRunningError):
            await trigger_fetcher(
                fetcher_name,
                user_id=user_id,
                session_factory=real_session_factory,
                celery_app=celery_test_app,
            )


@pytest.mark.integration
class TestTriggerFetcherStaleRecovery:
    async def test_stale_queued_run_is_finalized_and_new_run_proceeds(
        self,
        trigger_env: tuple[str, UUID],
        real_session_factory: async_sessionmaker[AsyncSession],
        celery_test_app: Celery,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        fetcher_name, user_id = trigger_env
        monkeypatch.setattr(celery_test_app, "send_task", MagicMock())
        stale_created_at = datetime.now(UTC) - timedelta(seconds=601)
        async with real_session_factory() as session:
            stale_run = FetcherRun(
                fetcher_name=fetcher_name,
                status="queued",
                triggered_by="manual",
                triggered_by_user_id=user_id,
                created_at=stale_created_at,
            )
            session.add(stale_run)
            await session.commit()
            stale_run_id = stale_run.id

        result = await trigger_fetcher(
            fetcher_name,
            user_id=user_id,
            session_factory=real_session_factory,
            celery_app=celery_test_app,
        )

        assert result.run_id != stale_run_id
        async with real_session_factory() as session:
            stale_after = await session.get(FetcherRun, stale_run_id)
            assert stale_after is not None
            assert stale_after.status == "failure"
            new_run = await session.get(FetcherRun, result.run_id)
            assert new_run is not None
            assert new_run.status == "queued"

    async def test_stale_running_run_is_finalized_and_new_run_proceeds(
        self,
        trigger_env: tuple[str, UUID],
        real_session_factory: async_sessionmaker[AsyncSession],
        celery_test_app: Celery,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        fetcher_name, user_id = trigger_env
        monkeypatch.setattr(celery_test_app, "send_task", MagicMock())
        async with real_session_factory() as session:
            stale_run = FetcherRun(
                fetcher_name=fetcher_name,
                status="running",
                triggered_by="schedule",
                started_at=datetime.now(UTC) - timedelta(seconds=3661),
                hard_time_limit_seconds=3600,
            )
            session.add(stale_run)
            await session.commit()
            stale_run_id = stale_run.id

        result = await trigger_fetcher(
            fetcher_name,
            user_id=user_id,
            session_factory=real_session_factory,
            celery_app=celery_test_app,
        )

        async with real_session_factory() as session:
            stale_after = await session.get(FetcherRun, stale_run_id)
            assert stale_after is not None
            assert stale_after.status == "failure"
            new_run = await session.get(FetcherRun, result.run_id)
            assert new_run is not None
            assert new_run.status == "queued"


@pytest.mark.integration
class TestTriggerFetcherSuccess:
    async def test_creates_queued_run_and_triggered_audit_event(
        self,
        trigger_env: tuple[str, UUID],
        real_session_factory: async_sessionmaker[AsyncSession],
        celery_test_app: Celery,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        fetcher_name, user_id = trigger_env
        monkeypatch.setattr(celery_test_app, "send_task", MagicMock())

        result = await trigger_fetcher(
            fetcher_name,
            user_id=user_id,
            session_factory=real_session_factory,
            celery_app=celery_test_app,
        )

        expected_message = f"Fetcher '{fetcher_name}' has been queued for execution"
        assert result.message == expected_message
        async with real_session_factory() as session:
            run = await session.get(FetcherRun, result.run_id)
            assert run is not None
            assert run.status == "queued"
            assert run.triggered_by == "manual"
            assert run.triggered_by_user_id == user_id
            assert run.started_at is None
            assert run.finished_at is None
            assert run.duration_seconds is None

            events = (
                (
                    await session.execute(
                        select(FetcherAuditEvent).where(
                            FetcherAuditEvent.fetcher_name == fetcher_name
                        )
                    )
                )
                .scalars()
                .all()
            )
        assert len(events) == 1
        assert events[0].event_type == "triggered"
        assert events[0].user_id == user_id
        assert events[0].old_value is None
        assert events[0].new_value is None
        assert events[0].detail is None

    async def test_failure_before_commit_rolls_back_run_and_audit_event(
        self,
        trigger_env: tuple[str, UUID],
        real_session_factory: async_sessionmaker[AsyncSession],
        celery_test_app: Celery,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The `queued` `FetcherRun` and its `triggered` audit event are
        created in the same first transaction (`docs/features/platform/
        fetcher-operations.md`, `trigger_fetcher`, First Transaction,
        steps 5-7). If anything raises between the audit event's flush
        and that transaction's commit, neither the run nor the audit
        event survives, and Celery is never contacted — proving the
        two mutations share one transaction rather than being committed
        independently."""
        fetcher_name, user_id = trigger_env
        send_task_spy = MagicMock()
        monkeypatch.setattr(celery_test_app, "send_task", send_task_spy)

        original_log_event = FetcherAuditLog.log_event

        async def _log_then_fail(session: AsyncSession, **kwargs: Any) -> None:
            await original_log_event(session, **kwargs)
            raise RuntimeError("simulated failure after audit event flush")

        monkeypatch.setattr(FetcherAuditLog, "log_event", _log_then_fail)

        with pytest.raises(RuntimeError, match="simulated failure"):
            await trigger_fetcher(
                fetcher_name,
                user_id=user_id,
                session_factory=real_session_factory,
                celery_app=celery_test_app,
            )

        send_task_spy.assert_not_called()
        async with real_session_factory() as session:
            runs = (
                (
                    await session.execute(
                        select(FetcherRun).where(
                            FetcherRun.fetcher_name == fetcher_name
                        )
                    )
                )
                .scalars()
                .all()
            )
            events = (
                (
                    await session.execute(
                        select(FetcherAuditEvent).where(
                            FetcherAuditEvent.fetcher_name == fetcher_name
                        )
                    )
                )
                .scalars()
                .all()
            )
        assert runs == []
        assert events == []

    async def test_publishes_run_fetcher_with_exact_kwargs_and_options(
        self,
        trigger_env: tuple[str, UUID],
        real_session_factory: async_sessionmaker[AsyncSession],
        celery_test_app: Celery,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        fetcher_name, user_id = trigger_env
        send_task_spy = MagicMock()
        monkeypatch.setattr(celery_test_app, "send_task", send_task_spy)

        result = await trigger_fetcher(
            fetcher_name,
            user_id=user_id,
            session_factory=real_session_factory,
            celery_app=celery_test_app,
        )

        send_task_spy.assert_called_once_with(
            "run_fetcher",
            kwargs={
                "fetcher_name": fetcher_name,
                "triggered_by": "manual",
                "user_id": str(user_id),
                "run_id": str(result.run_id),
            },
            ignore_result=True,
            time_limit=3600,
            soft_time_limit=3420,
        )

    async def test_queue_option_included_when_fetcher_declares_one(
        self,
        real_session_factory: async_sessionmaker[AsyncSession],
        celery_test_app: Celery,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        fetcher_name = f"trigger_queue_{uuid4().hex[:8]}"
        _register(_stub_fetcher_class(fetcher_name, queue="git"))
        send_task_spy = MagicMock()
        monkeypatch.setattr(celery_test_app, "send_task", send_task_spy)
        async with real_session_factory() as session:
            admin = User(
                username=f"queueadmin{uuid4().hex[:8]}",
                email=f"queueadmin{uuid4().hex[:8]}@example.com",
                password_hash="$2b$12$" + "a" * 53,
            )
            session.add(admin)
            session.add(
                FetcherConfig(fetcher_name=fetcher_name, enabled=True, run_timeout=100)
            )
            await session.commit()
            user_id = admin.id

        try:
            await trigger_fetcher(
                fetcher_name,
                user_id=user_id,
                session_factory=real_session_factory,
                celery_app=celery_test_app,
            )

            assert send_task_spy.call_args.kwargs["queue"] == "git"
            assert send_task_spy.call_args.kwargs["time_limit"] == 100
            assert send_task_spy.call_args.kwargs["soft_time_limit"] == 95
            assert send_task_spy.call_args.kwargs["ignore_result"] is True
        finally:
            await _cleanup_trigger_rows(
                real_session_factory, fetcher_name=fetcher_name, user_id=user_id
            )

    async def test_not_idempotent_second_call_creates_a_second_run(
        self,
        trigger_env: tuple[str, UUID],
        real_session_factory: async_sessionmaker[AsyncSession],
        celery_test_app: Celery,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        fetcher_name, user_id = trigger_env
        monkeypatch.setattr(celery_test_app, "send_task", MagicMock())

        first = await trigger_fetcher(
            fetcher_name,
            user_id=user_id,
            session_factory=real_session_factory,
            celery_app=celery_test_app,
        )
        # Simulate the worker completing the first run so the second
        # trigger is not blocked by the Already Running guard.
        async with real_session_factory() as session:
            run = await session.get(FetcherRun, first.run_id)
            assert run is not None
            run.status = "success"
            run.started_at = datetime.now(UTC)
            run.finished_at = datetime.now(UTC)
            await session.commit()

        second = await trigger_fetcher(
            fetcher_name,
            user_id=user_id,
            session_factory=real_session_factory,
            celery_app=celery_test_app,
        )

        assert second.run_id != first.run_id
        async with real_session_factory() as session:
            events = (
                (
                    await session.execute(
                        select(FetcherAuditEvent).where(
                            FetcherAuditEvent.fetcher_name == fetcher_name
                        )
                    )
                )
                .scalars()
                .all()
            )
        assert len(events) == 2


@pytest.mark.integration
class TestTriggerFetcherBrokerFailure:
    async def test_publication_failure_finalizes_run_and_raises_broker_unavailable(
        self,
        trigger_env: tuple[str, UUID],
        real_session_factory: async_sessionmaker[AsyncSession],
        celery_test_app: Celery,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        fetcher_name, user_id = trigger_env
        sensitive_message = (
            "Error 111 connecting to redis://user:supersecret@203.0.113.5:6379"
        )

        def _raise(*_args: Any, **_kwargs: Any) -> None:
            raise ConnectionError(sensitive_message)

        monkeypatch.setattr(celery_test_app, "send_task", _raise)

        with pytest.raises(FetcherBrokerUnavailableError) as exc_info:
            await trigger_fetcher(
                fetcher_name,
                user_id=user_id,
                session_factory=real_session_factory,
                celery_app=celery_test_app,
            )

        assert "supersecret" not in str(exc_info.value)
        assert "203.0.113.5" not in str(exc_info.value)

        async with real_session_factory() as session:
            runs = (
                (
                    await session.execute(
                        select(FetcherRun).where(
                            FetcherRun.fetcher_name == fetcher_name
                        )
                    )
                )
                .scalars()
                .all()
            )
            assert len(runs) == 1
            run = runs[0]
            assert run.status == "failure"
            assert run.started_at is None
            assert run.duration_seconds is None
            assert run.error_message == (
                "Manual run could not be dispatched to the task broker"
            )
            assert run.error_detail == "ConnectionError"
            assert run.error_traceback is None
            assert "supersecret" not in (run.error_message or "")
            assert "supersecret" not in (run.error_detail or "")

            events = (
                (
                    await session.execute(
                        select(FetcherAuditEvent).where(
                            FetcherAuditEvent.fetcher_name == fetcher_name
                        )
                    )
                )
                .scalars()
                .all()
            )
        assert len(events) == 1
        assert events[0].event_type == "triggered"

    async def test_compensation_losing_the_adoption_race_still_raises_and_logs(
        self,
        trigger_env: tuple[str, UUID],
        real_session_factory: async_sessionmaker[AsyncSession],
        celery_test_app: Celery,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Ambiguous Broker Acknowledgement, outcome 2 (worker wins):
        `finalize_manual_run_as_failure()` returning `False` (a worker
        already adopted the run) is mocked directly here — the
        conditional-UPDATE race itself is proven at the
        `fetcher_execution` layer
        (`test_fetcher_execution.py::TestAcquireFetcherRunConcurrency`).
        This test verifies `trigger_fetcher()`'s own reaction to that
        outcome: it still raises `FetcherBrokerUnavailableError` and
        logs a WARNING distinguishing the lost race."""
        fetcher_name, user_id = trigger_env

        def _raise(*_args: Any, **_kwargs: Any) -> None:
            raise RuntimeError("boom")

        monkeypatch.setattr(celery_test_app, "send_task", _raise)
        monkeypatch.setattr(
            fetcher_operations_module,
            "finalize_manual_run_as_failure",
            AsyncMock(return_value=False),
        )

        with (
            caplog.at_level("WARNING", logger="app.services.fetcher_operations"),
            pytest.raises(FetcherBrokerUnavailableError),
        ):
            await trigger_fetcher(
                fetcher_name,
                user_id=user_id,
                session_factory=real_session_factory,
                celery_app=celery_test_app,
            )

        assert "fetcher_manual_trigger_compensation_lost_to_adoption" in caplog.text

    async def test_unexpected_compensation_error_propagates_uncaught(
        self,
        trigger_env: tuple[str, UUID],
        real_session_factory: async_sessionmaker[AsyncSession],
        celery_test_app: Celery,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """An unexpected failure while compensating (e.g. a database
        error distinct from the documented `ValueError` for a missing
        run) rolls back the compensation session and propagates
        uncaught — it is not swallowed or converted into
        `FetcherBrokerUnavailableError`."""
        fetcher_name, user_id = trigger_env

        def _raise_broker_error(*_args: Any, **_kwargs: Any) -> None:
            raise RuntimeError("boom")

        async def _raise_compensation_error(*_args: Any, **_kwargs: Any) -> bool:
            raise ValueError("simulated compensation failure")

        monkeypatch.setattr(celery_test_app, "send_task", _raise_broker_error)
        monkeypatch.setattr(
            fetcher_operations_module,
            "finalize_manual_run_as_failure",
            _raise_compensation_error,
        )

        with pytest.raises(ValueError, match="simulated compensation failure"):
            await trigger_fetcher(
                fetcher_name,
                user_id=user_id,
                session_factory=real_session_factory,
                celery_app=celery_test_app,
            )


@pytest.mark.integration
class TestTriggerFetcherConcurrency:
    """See docs/features/platform/testing-strategy.md (Concurrency
    Testing) for the canonical two-session pattern applied here.
    `trigger_fetcher()` manages its own sessions internally, so the
    blocking point is injected via `FetcherAuditLog.log_event` — called
    once per successful trigger, immediately before commit, i.e. while
    the `FetcherConfig` row lock is still held."""

    async def test_concurrent_triggers_serialize_on_the_config_lock(
        self,
        trigger_env: tuple[str, UUID],
        real_session_factory: async_sessionmaker[AsyncSession],
        celery_test_app: Celery,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        fetcher_name, user_id = trigger_env
        monkeypatch.setattr(celery_test_app, "send_task", MagicMock())

        hold_event = asyncio.Event()
        proceed_event = asyncio.Event()
        original_log_event = FetcherAuditLog.log_event
        call_count = 0

        async def _blocking_log_event(session: AsyncSession, **kwargs: Any) -> None:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                hold_event.set()
                await proceed_event.wait()
            await original_log_event(session, **kwargs)

        monkeypatch.setattr(FetcherAuditLog, "log_event", _blocking_log_event)

        task_a = asyncio.create_task(
            trigger_fetcher(
                fetcher_name,
                user_id=user_id,
                session_factory=real_session_factory,
                celery_app=celery_test_app,
            )
        )
        await asyncio.wait_for(hold_event.wait(), timeout=2)

        task_b = asyncio.create_task(
            trigger_fetcher(
                fetcher_name,
                user_id=user_id,
                session_factory=real_session_factory,
                celery_app=celery_test_app,
            )
        )
        with pytest.raises(TimeoutError):
            await asyncio.wait_for(asyncio.shield(task_b), timeout=0.3)

        proceed_event.set()
        result_a = await asyncio.wait_for(task_a, timeout=5)
        assert result_a.run_id is not None

        with pytest.raises(FetcherAlreadyRunningError):
            await asyncio.wait_for(task_b, timeout=5)
