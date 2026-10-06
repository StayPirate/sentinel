"""Tests for RedBeat schedule construction, upsert/delete, and startup
reconciliation (backend/app/services/fetcher_schedule.py).

See `docs/features/platform/fetcher-infrastructure.md` (Celery Beat
Schedule Synchronization) for the contract under test: effective
schedule/options resolution, the redbeat entry shape, the reconciliation
steps (write enabled, remove disabled, remove deregistered/corrupted),
idempotency, PostgreSQL authority, and fail-on-first-error semantics.

Pure calculation helpers (`_effective_schedule`, `_effective_options`)
are unit tests (no DB, no Redis). Every other function in this module
performs real redbeat/Redis I/O and is tested against the isolated
worker Redis logical database (see
`docs/features/platform/testing-strategy.md`, Redis Strategy) via the
shared `celery_test_app` fixture (`tests/conftest.py`), combined with
real PostgreSQL via `db_session`/`fetcher_config_factory`.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Generator
from datetime import UTC, datetime, timedelta
from typing import Any, cast

import pytest
from celery import Celery
from celery.schedules import crontab
from redbeat import RedBeatSchedulerEntry
from redbeat.schedulers import ensure_conf, get_redis
from redis.exceptions import RedisError
from sqlalchemy import select
from sqlalchemy.exc import OperationalError
from sqlalchemy.ext.asyncio import AsyncSession

import app.services.fetcher_schedule as fetcher_schedule_module
from app.models.fetcher_audit_event import FetcherAuditEvent
from app.models.fetcher_config import FetcherConfig
from app.services.base_fetcher import FETCHER_REGISTRY, BaseFetcher
from app.services.fetcher_schedule import (
    ReconciliationSummary,
    delete_fetcher_entry,
    propagate_config_update,
    reconcile_beat_schedule,
    upsert_fetcher_entry,
)

FetcherConfigFactory = Callable[..., Awaitable[FetcherConfig]]

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _isolated_registry() -> Generator[None]:
    """Snapshot/restore `FETCHER_REGISTRY` around every test in this file.

    Stub fetchers below are plain classes registered explicitly via
    `_register()` inside each test body — deliberately NOT `BaseFetcher`
    subclasses, since subclassing would trigger `__init_subclass__`'s
    registration at module *import* time (pytest collection), polluting
    the shared, module-level registry for the whole session before any
    test in this file runs (see
    `docs/features/platform/testing-strategy.md`, Test Independence).
    This fixture still guards against that registration leaking into
    later tests, mirroring
    `tests/test_services/test_fetcher_bootstrap.py`.
    """
    original = dict(FETCHER_REGISTRY)
    yield
    FETCHER_REGISTRY.clear()
    FETCHER_REGISTRY.update(original)


def _make_config(**overrides: object) -> FetcherConfig:
    """Build a standalone, unpersisted `FetcherConfig` for the pure
    calculation unit tests below — no session/flush involved."""
    defaults: dict[str, object] = {
        "fetcher_name": "test_schedule_fetcher",
        "enabled": True,
        "schedule_override": None,
        "run_timeout": 3600,
        "request_delay": 0.0,
        "custom_settings": {},
    }
    defaults.update(overrides)
    return FetcherConfig(**defaults)


class _NoQueueFetcherStub:
    """Minimal `FETCHER_REGISTRY` entry stub — exposes only the class
    attributes `fetcher_schedule.py` functions read. Deliberately does
    NOT subclass `BaseFetcher`: at module level, subclassing would
    trigger `__init_subclass__`'s registration at pytest collection
    time (see `_isolated_registry` above)."""

    name = "test_schedule_no_queue"
    default_schedule = "0 3 * * *"
    queue: str | None = None


class _QueuedFetcherStub:
    """Same rationale as `_NoQueueFetcherStub`, with a dedicated queue."""

    name = "test_schedule_queued"
    default_schedule = "0 3 * * *"
    queue = "git"


# Cast to `type[BaseFetcher]` so these duck-typed stubs satisfy the
# real signatures of `fetcher_schedule.py` functions — which only read
# `name`/`default_schedule`/`queue` at runtime, never construct or
# call any other `BaseFetcher` member. `cast()` performs no runtime
# wrapping; `_NoQueueFetcher is _NoQueueFetcherStub` remains `True`.
_NoQueueFetcher = cast("type[BaseFetcher]", _NoQueueFetcherStub)
_QueuedFetcher = cast("type[BaseFetcher]", _QueuedFetcherStub)


def _register(*stubs: type[Any]) -> None:
    """Replace `FETCHER_REGISTRY` with exactly the given stub classes —
    mirrors `tests/test_services/test_fetcher_bootstrap.py`."""
    FETCHER_REGISTRY.clear()
    for stub in stubs:
        FETCHER_REGISTRY[stub.name] = stub


# ---------------------------------------------------------------------------
# Pure calculation unit tests
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestEffectiveSchedule:
    def test_uses_default_schedule_when_no_override(self) -> None:
        config = _make_config(schedule_override=None)

        schedule = fetcher_schedule_module._effective_schedule(_NoQueueFetcher, config)

        assert schedule.hour == {3}
        assert schedule.minute == {0}

    def test_uses_schedule_override_when_set(self) -> None:
        config = _make_config(schedule_override="*/15 * * * *")

        schedule = fetcher_schedule_module._effective_schedule(_NoQueueFetcher, config)

        assert schedule.minute == {0, 15, 30, 45}

    def test_invalid_override_raises_value_error(self) -> None:
        config = _make_config(schedule_override="not a cron expression")

        # This message originates from Python's own tuple-unpacking
        # semantics inside `celery.schedules.crontab.from_string`
        # (splitting the cron string into 5 fields) — a core-language
        # error format, not a Celery-specific or Sentinel-specific
        # string, so it is stable across Celery versions.
        with pytest.raises(ValueError, match="not enough values to unpack"):
            fetcher_schedule_module._effective_schedule(_NoQueueFetcher, config)


@pytest.mark.unit
class TestEffectiveOptions:
    def test_time_limit_and_soft_time_limit_formulas(self) -> None:
        config = _make_config(run_timeout=100)

        options = fetcher_schedule_module._effective_options(_NoQueueFetcher, config)

        assert options["time_limit"] == 100
        assert options["soft_time_limit"] == 95

    def test_time_limit_floor_applies_below_minimum(self) -> None:
        config = _make_config(run_timeout=1)

        options = fetcher_schedule_module._effective_options(_NoQueueFetcher, config)

        assert options["time_limit"] == 5
        assert options["soft_time_limit"] == 1

    def test_queue_omitted_when_fetcher_has_no_queue(self) -> None:
        config = _make_config()

        options = fetcher_schedule_module._effective_options(_NoQueueFetcher, config)

        assert "queue" not in options

    def test_queue_included_when_fetcher_declares_one(self) -> None:
        config = _make_config()

        options = fetcher_schedule_module._effective_options(_QueuedFetcher, config)

        assert options["queue"] == "git"


# ---------------------------------------------------------------------------
# Entry construction and upsert/delete (real Redis)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestBuildEntry:
    def test_entry_has_canonical_shape(self, celery_test_app: Celery) -> None:
        config = _make_config(fetcher_name=_NoQueueFetcher.name, run_timeout=120)

        entry = fetcher_schedule_module._build_entry(
            celery_test_app, _NoQueueFetcher, config
        )

        assert entry.name == _NoQueueFetcher.name
        assert entry.task == "run_fetcher"
        assert entry.args == []
        assert entry.kwargs == {
            "fetcher_name": _NoQueueFetcher.name,
            "triggered_by": "schedule",
        }
        assert entry.enabled is True
        assert entry.options["time_limit"] == 120


@pytest.mark.integration
class TestUpsertFetcherEntry:
    def test_creates_entry_when_absent(self, celery_test_app: Celery) -> None:
        config = _make_config(fetcher_name=_NoQueueFetcher.name)

        upsert_fetcher_entry(celery_test_app, _NoQueueFetcher, config)

        key = RedBeatSchedulerEntry.generate_key(celery_test_app, _NoQueueFetcher.name)
        entry = RedBeatSchedulerEntry.from_key(key, app=celery_test_app)
        assert entry.task == "run_fetcher"
        assert entry.schedule.hour == {3}

    def test_overwrites_existing_entry(self, celery_test_app: Celery) -> None:
        config = _make_config(fetcher_name=_NoQueueFetcher.name)
        upsert_fetcher_entry(celery_test_app, _NoQueueFetcher, config)

        overridden = _make_config(
            fetcher_name=_NoQueueFetcher.name, schedule_override="*/5 * * * *"
        )
        upsert_fetcher_entry(celery_test_app, _NoQueueFetcher, overridden)

        key = RedBeatSchedulerEntry.generate_key(celery_test_app, _NoQueueFetcher.name)
        entry = RedBeatSchedulerEntry.from_key(key, app=celery_test_app)
        assert entry.schedule.minute == {0, 5, 10, 15, 20, 25, 30, 35, 40, 45, 50, 55}

    def test_reschedules_due_at_relative_to_now_not_stale_last_run(
        self, celery_test_app: Celery
    ) -> None:
        """A pre-existing entry's `last_run_at` must not leak into a
        fresh upsert — otherwise `save()` alone (which uses `HSETNX`
        for the meta hash) would silently preserve a stale `due_at`,
        risking a retroactive catch-up fire. See
        fetcher-infrastructure.md, Startup Reconciliation step 2."""
        config = _make_config(fetcher_name=_NoQueueFetcher.name)
        key = RedBeatSchedulerEntry.generate_key(celery_test_app, _NoQueueFetcher.name)
        stale_time = datetime.now(UTC) - timedelta(days=7)
        stale_entry = RedBeatSchedulerEntry(
            name=_NoQueueFetcher.name,
            task="run_fetcher",
            schedule=crontab.from_string(_NoQueueFetcher.default_schedule),
            args=[],
            kwargs={"fetcher_name": _NoQueueFetcher.name, "triggered_by": "schedule"},
            app=celery_test_app,
        )
        stale_entry.save()
        stale_entry.reschedule(last_run_at=stale_time)
        before = RedBeatSchedulerEntry.from_key(key, app=celery_test_app)
        assert before.last_run_at == stale_time

        upsert_fetcher_entry(celery_test_app, _NoQueueFetcher, config)

        after = RedBeatSchedulerEntry.from_key(key, app=celery_test_app)
        assert after.last_run_at > stale_time + timedelta(days=6)


@pytest.mark.integration
class TestDeleteFetcherEntry:
    def test_deletes_existing_entry_and_returns_true(
        self, celery_test_app: Celery
    ) -> None:
        config = _make_config(fetcher_name=_NoQueueFetcher.name)
        upsert_fetcher_entry(celery_test_app, _NoQueueFetcher, config)

        deleted = delete_fetcher_entry(celery_test_app, _NoQueueFetcher.name)

        assert deleted is True
        key = RedBeatSchedulerEntry.generate_key(celery_test_app, _NoQueueFetcher.name)
        with pytest.raises(KeyError):
            RedBeatSchedulerEntry.from_key(key, app=celery_test_app)

    def test_missing_entry_is_a_no_op_and_returns_false(
        self, celery_test_app: Celery
    ) -> None:
        deleted = delete_fetcher_entry(celery_test_app, "never_existed_fetcher")

        assert deleted is False


@pytest.mark.integration
class TestPropagateConfigUpdate:
    """See `docs/features/platform/fetcher-operations.md` (RedBeat
    Post-Commit Propagation) for the contract this function implements
    — the caller (the PATCH endpoint's post-commit callback) has
    already resolved which single `action` applies."""

    def test_delete_action_removes_the_entry(self, celery_test_app: Celery) -> None:
        _register(_NoQueueFetcher)
        config = _make_config(fetcher_name=_NoQueueFetcher.name)
        upsert_fetcher_entry(celery_test_app, _NoQueueFetcher, config)

        propagate_config_update(
            celery_test_app,
            fetcher_name=_NoQueueFetcher.name,
            action="delete",
        )

        key = RedBeatSchedulerEntry.generate_key(celery_test_app, _NoQueueFetcher.name)
        with pytest.raises(KeyError):
            RedBeatSchedulerEntry.from_key(key, app=celery_test_app)

    def test_delete_action_is_idempotent_when_no_entry_exists(
        self, celery_test_app: Celery
    ) -> None:
        _register(_NoQueueFetcher)

        propagate_config_update(
            celery_test_app,
            fetcher_name=_NoQueueFetcher.name,
            action="delete",
        )
        # No exception — delete is a no-op on a missing entry.

    def test_delete_action_before_redbeat_config_initialized_removes_the_entry(
        self, celery_test_app: Celery, uninitialized_celery_test_app: Celery
    ) -> None:
        """A disable PATCH can be the first RedBeat call of a freshly
        started API process, before anything has initialized
        `redbeat_conf`."""
        _register(_NoQueueFetcher)
        config = _make_config(fetcher_name=_NoQueueFetcher.name)
        upsert_fetcher_entry(celery_test_app, _NoQueueFetcher, config)
        assert not hasattr(uninitialized_celery_test_app, "redbeat_conf")

        propagate_config_update(
            uninitialized_celery_test_app,
            fetcher_name=_NoQueueFetcher.name,
            action="delete",
        )

        assert not _entry_exists(celery_test_app, _NoQueueFetcher.name)

    def test_upsert_action_creates_entry_using_caller_supplied_values(
        self, celery_test_app: Celery
    ) -> None:
        _register(_NoQueueFetcher)

        propagate_config_update(
            celery_test_app,
            fetcher_name=_NoQueueFetcher.name,
            action="upsert",
            schedule_override="*/5 * * * *",
            run_timeout=1200,
        )

        key = RedBeatSchedulerEntry.generate_key(celery_test_app, _NoQueueFetcher.name)
        entry = RedBeatSchedulerEntry.from_key(key, app=celery_test_app)
        assert entry.schedule.minute == {0, 5, 10, 15, 20, 25, 30, 35, 40, 45, 50, 55}
        assert entry.options["time_limit"] == 1200

    def test_upsert_action_falls_back_to_default_schedule_when_override_is_none(
        self, celery_test_app: Celery
    ) -> None:
        _register(_NoQueueFetcher)

        propagate_config_update(
            celery_test_app,
            fetcher_name=_NoQueueFetcher.name,
            action="upsert",
            schedule_override=None,
            run_timeout=3600,
        )

        key = RedBeatSchedulerEntry.generate_key(celery_test_app, _NoQueueFetcher.name)
        entry = RedBeatSchedulerEntry.from_key(key, app=celery_test_app)
        assert entry.schedule.hour == {3}

    def test_upsert_action_overwrites_existing_entry(
        self, celery_test_app: Celery
    ) -> None:
        _register(_NoQueueFetcher)
        config = _make_config(fetcher_name=_NoQueueFetcher.name)
        upsert_fetcher_entry(celery_test_app, _NoQueueFetcher, config)

        propagate_config_update(
            celery_test_app,
            fetcher_name=_NoQueueFetcher.name,
            action="upsert",
            schedule_override="*/10 * * * *",
            run_timeout=600,
        )

        key = RedBeatSchedulerEntry.generate_key(celery_test_app, _NoQueueFetcher.name)
        entry = RedBeatSchedulerEntry.from_key(key, app=celery_test_app)
        assert entry.schedule.minute == {0, 10, 20, 30, 40, 50}
        assert entry.options["time_limit"] == 600

    def test_redis_error_propagates_uncaught(
        self, celery_test_app: Celery, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _register(_NoQueueFetcher)

        def _raise(*_args: Any, **_kwargs: Any) -> None:
            raise RedisError("simulated outage")

        monkeypatch.setattr(fetcher_schedule_module, "delete_fetcher_entry", _raise)

        with pytest.raises(RedisError):
            propagate_config_update(
                celery_test_app,
                fetcher_name=_NoQueueFetcher.name,
                action="delete",
            )


# ---------------------------------------------------------------------------
# Full startup reconciliation (real Postgres + real Redis)
# ---------------------------------------------------------------------------


def _entry_exists(celery_app: Celery, name: str) -> bool:
    key = RedBeatSchedulerEntry.generate_key(celery_app, name)
    try:
        RedBeatSchedulerEntry.from_key(key, app=celery_app)
    except KeyError:
        return False
    return True


def _schedule_log_records(
    caplog: pytest.LogCaptureFixture,
) -> list[Any]:
    """Return only the log records emitted by this module.

    Scoping to `app.services.fetcher_schedule`'s own records avoids
    false positives/negatives from unrelated records propagated during
    the same test (e.g. SQLAlchemy mapper configuration logs), mirroring
    the identical pattern in `test_api_key_service.py`/`test_dependencies.py`.
    """
    return [
        record
        for record in caplog.records
        if record.name == "app.services.fetcher_schedule"
    ]


@pytest.mark.integration
class TestReconcileBeatScheduleEnabledDisabled:
    async def test_writes_entry_for_enabled_registered_fetcher(
        self,
        db_session: AsyncSession,
        celery_test_app: Celery,
        fetcher_config_factory: FetcherConfigFactory,
    ) -> None:
        _register(_NoQueueFetcher)
        await fetcher_config_factory(fetcher_name=_NoQueueFetcher.name, enabled=True)

        summary = await reconcile_beat_schedule(db_session, celery_test_app)

        assert summary.written == 1
        assert _entry_exists(celery_test_app, _NoQueueFetcher.name)

    async def test_removes_entry_for_disabled_registered_fetcher(
        self,
        db_session: AsyncSession,
        celery_test_app: Celery,
        fetcher_config_factory: FetcherConfigFactory,
    ) -> None:
        _register(_NoQueueFetcher)
        config = await fetcher_config_factory(
            fetcher_name=_NoQueueFetcher.name, enabled=True
        )
        upsert_fetcher_entry(celery_test_app, _NoQueueFetcher, config)
        assert _entry_exists(celery_test_app, _NoQueueFetcher.name)
        config.enabled = False
        await db_session.flush()

        summary = await reconcile_beat_schedule(db_session, celery_test_app)

        assert summary.disabled_removed == 1
        assert not _entry_exists(celery_test_app, _NoQueueFetcher.name)

    async def test_disabled_fetcher_with_no_existing_entry_counts_zero(
        self,
        db_session: AsyncSession,
        celery_test_app: Celery,
        fetcher_config_factory: FetcherConfigFactory,
    ) -> None:
        _register(_NoQueueFetcher)
        await fetcher_config_factory(fetcher_name=_NoQueueFetcher.name, enabled=False)

        summary = await reconcile_beat_schedule(db_session, celery_test_app)

        assert summary.disabled_removed == 0

    async def test_missing_fetcher_config_row_raises(
        self,
        db_session: AsyncSession,
        celery_test_app: Celery,
    ) -> None:
        _register(_NoQueueFetcher)
        # No FetcherConfig row created — bootstrap_fetcher_configs()
        # is assumed to have already run in the real startup sequence.

        with pytest.raises(RuntimeError, match=_NoQueueFetcher.name):
            await reconcile_beat_schedule(db_session, celery_test_app)


@pytest.mark.integration
class TestReconcileBeatScheduleDeregisteredAndMalformed:
    async def test_removes_deregistered_entry(
        self,
        db_session: AsyncSession,
        celery_test_app: Celery,
        fetcher_config_factory: FetcherConfigFactory,
    ) -> None:
        _register(_NoQueueFetcher)
        config = await fetcher_config_factory(
            fetcher_name=_NoQueueFetcher.name, enabled=True
        )
        upsert_fetcher_entry(celery_test_app, _NoQueueFetcher, config)
        # Simulate a fetcher that has since been removed from the
        # codebase: its entry remains in redbeat, but not in the
        # registry anymore.
        FETCHER_REGISTRY.clear()

        summary = await reconcile_beat_schedule(db_session, celery_test_app)

        assert summary.deregistered_removed == 1
        assert not _entry_exists(celery_test_app, _NoQueueFetcher.name)

    async def test_removes_entry_with_missing_fetcher_name_kwarg(
        self, db_session: AsyncSession, celery_test_app: Celery
    ) -> None:
        FETCHER_REGISTRY.clear()
        entry = RedBeatSchedulerEntry(
            name="corrupted_no_kwarg",
            task="run_fetcher",
            schedule=crontab.from_string(_NoQueueFetcher.default_schedule),
            args=[],
            kwargs={},
            app=celery_test_app,
        )
        entry.save()

        summary = await reconcile_beat_schedule(db_session, celery_test_app)

        assert summary.deregistered_removed == 1
        assert not _entry_exists(celery_test_app, "corrupted_no_kwarg")

    async def test_removes_entry_with_empty_fetcher_name(
        self, db_session: AsyncSession, celery_test_app: Celery
    ) -> None:
        FETCHER_REGISTRY.clear()
        entry = RedBeatSchedulerEntry(
            name="corrupted_empty_name",
            task="run_fetcher",
            schedule=crontab.from_string(_NoQueueFetcher.default_schedule),
            args=[],
            kwargs={"fetcher_name": ""},
            app=celery_test_app,
        )
        entry.save()

        summary = await reconcile_beat_schedule(db_session, celery_test_app)

        assert summary.deregistered_removed == 1
        assert not _entry_exists(celery_test_app, "corrupted_empty_name")

    async def test_removes_entry_with_none_fetcher_name(
        self, db_session: AsyncSession, celery_test_app: Celery
    ) -> None:
        FETCHER_REGISTRY.clear()
        entry = RedBeatSchedulerEntry(
            name="corrupted_none_name",
            task="run_fetcher",
            schedule=crontab.from_string(_NoQueueFetcher.default_schedule),
            args=[],
            kwargs={"fetcher_name": None},
            app=celery_test_app,
        )
        entry.save()

        summary = await reconcile_beat_schedule(db_session, celery_test_app)

        assert summary.deregistered_removed == 1
        assert not _entry_exists(celery_test_app, "corrupted_none_name")

    async def test_removes_alias_entry_whose_kwarg_does_not_match_its_own_name(
        self,
        db_session: AsyncSession,
        celery_test_app: Celery,
        fetcher_config_factory: FetcherConfigFactory,
    ) -> None:
        """An entry stored under a different Redis key name than its
        own `fetcher_name` kwarg is a non-canonical alias — Sentinel
        never creates one itself (canonical upserts always use
        `entry.name == fetcher_name`). Treated as corrupted."""
        _register(_NoQueueFetcher)
        await fetcher_config_factory(fetcher_name=_NoQueueFetcher.name, enabled=True)
        alias = RedBeatSchedulerEntry(
            name="alias_entry",
            task="run_fetcher",
            schedule=crontab.from_string(_NoQueueFetcher.default_schedule),
            args=[],
            kwargs={"fetcher_name": _NoQueueFetcher.name},
            app=celery_test_app,
        )
        alias.save()

        summary = await reconcile_beat_schedule(db_session, celery_test_app)

        assert summary.deregistered_removed == 1
        assert not _entry_exists(celery_test_app, "alias_entry")
        # The canonical entry for the still-registered, enabled fetcher
        # is unaffected by the alias's removal.
        assert _entry_exists(celery_test_app, _NoQueueFetcher.name)

    async def test_corrupted_entry_removal_logs_at_warning_level(
        self,
        db_session: AsyncSession,
        celery_test_app: Celery,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """fetcher-infrastructure.md (Reconciliation Steps, step 4):
        a corrupted entry (missing/empty/mismatched `fetcher_name`) is
        logged at WARNING — distinct from the INFO level used for a
        merely deregistered entry, since the two indicate different
        operational conditions."""
        FETCHER_REGISTRY.clear()
        entry = RedBeatSchedulerEntry(
            name="corrupted_for_log_test",
            task="run_fetcher",
            schedule=crontab.from_string(_NoQueueFetcher.default_schedule),
            args=[],
            kwargs={"fetcher_name": ""},
            app=celery_test_app,
        )
        entry.save()

        with caplog.at_level("INFO", logger="app.services.fetcher_schedule"):
            await reconcile_beat_schedule(db_session, celery_test_app)

        records = _schedule_log_records(caplog)
        matching = [
            r
            for r in records
            if r.msg.get("event") == "redbeat_corrupted_entry_removed"
        ]
        assert len(matching) == 1, records
        assert matching[0].levelname == "WARNING"

    async def test_deregistered_entry_removal_logs_at_info_level(
        self,
        db_session: AsyncSession,
        celery_test_app: Celery,
        fetcher_config_factory: FetcherConfigFactory,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """fetcher-infrastructure.md (Reconciliation Steps, step 4): a
        deregistered entry (valid, canonical `fetcher_name` no longer
        in `FETCHER_REGISTRY`) is logged at INFO — a routine, expected
        cleanup rather than a WARNING-worthy anomaly."""
        _register(_NoQueueFetcher)
        config = await fetcher_config_factory(
            fetcher_name=_NoQueueFetcher.name, enabled=True
        )
        upsert_fetcher_entry(celery_test_app, _NoQueueFetcher, config)
        FETCHER_REGISTRY.clear()

        with caplog.at_level("INFO", logger="app.services.fetcher_schedule"):
            await reconcile_beat_schedule(db_session, celery_test_app)

        records = _schedule_log_records(caplog)
        matching = [
            r
            for r in records
            if r.msg.get("event") == "redbeat_deregistered_entry_removed"
        ]
        assert len(matching) == 1, records
        assert matching[0].levelname == "INFO"

    async def test_preserves_non_run_fetcher_static_entry(
        self, db_session: AsyncSession, celery_test_app: Celery
    ) -> None:
        FETCHER_REGISTRY.clear()
        static_entry = RedBeatSchedulerEntry(
            name="cleanup_sessions",
            task="cleanup_sessions",
            schedule=crontab.from_string(_NoQueueFetcher.default_schedule),
            args=[],
            kwargs={},
            app=celery_test_app,
        )
        static_entry.save()

        await reconcile_beat_schedule(db_session, celery_test_app)

        assert _entry_exists(celery_test_app, "cleanup_sessions")
        preserved = RedBeatSchedulerEntry.from_key(
            RedBeatSchedulerEntry.generate_key(celery_test_app, "cleanup_sessions"),
            app=celery_test_app,
        )
        assert preserved.task == "cleanup_sessions"

    async def test_removes_orphaned_sorted_set_member_evicted_before_read(
        self, db_session: AsyncSession, celery_test_app: Celery
    ) -> None:
        """`_iter_all_entries` enumerates sorted-set members via
        `zrange()` and then loads each one's hash via `from_key()` —
        two separate Redis reads. If the hash is gone by the time it's
        read (its sorted-set member briefly outliving its own backing
        hash), `from_key()` raises `KeyError`. This is not a state
        Sentinel's own writes ever produce (see the function's
        docstring), but the module self-heals from it the same way
        redbeat's own due-task query does: the orphaned sorted-set
        member is removed (`zrem`) rather than left behind to be
        silently re-encountered on every future reconciliation pass.
        Simulated here by deleting only the entry's backing hash while
        leaving its sorted-set membership intact — exactly what
        `RedBeatSchedulerEntry.delete()` would never do on its own (it
        removes both atomically)."""
        FETCHER_REGISTRY.clear()
        entry = RedBeatSchedulerEntry(
            name="evicted_before_read",
            task="run_fetcher",
            schedule=crontab.from_string(_NoQueueFetcher.default_schedule),
            args=[],
            kwargs={"fetcher_name": "evicted_before_read"},
            app=celery_test_app,
        )
        entry.save()
        redis_client = get_redis(celery_test_app)
        redis_client.delete(entry.key)

        summary = await reconcile_beat_schedule(db_session, celery_test_app)

        # Not counted in the reconciliation summary — orphan cleanup
        # is a lower-level enumeration concern distinct from the three
        # fetcher-outcome counters (write/disable/deregister).
        assert summary.deregistered_removed == 0
        schedule_key = ensure_conf(celery_test_app).schedule_key
        assert redis_client.zscore(schedule_key, entry.key) is None


@pytest.mark.integration
class TestReconcileBeatScheduleIdempotency:
    async def test_two_consecutive_runs_produce_the_same_state(
        self,
        db_session: AsyncSession,
        celery_test_app: Celery,
        fetcher_config_factory: FetcherConfigFactory,
    ) -> None:
        _register(_NoQueueFetcher)
        await fetcher_config_factory(fetcher_name=_NoQueueFetcher.name, enabled=True)

        first = await reconcile_beat_schedule(db_session, celery_test_app)
        second = await reconcile_beat_schedule(db_session, celery_test_app)

        assert first == ReconciliationSummary(
            written=1, disabled_removed=0, deregistered_removed=0
        )
        assert second == ReconciliationSummary(
            written=1, disabled_removed=0, deregistered_removed=0
        )
        assert _entry_exists(celery_test_app, _NoQueueFetcher.name)


@pytest.mark.integration
class TestReconcileBeatSchedulePostgresAuthority:
    async def test_postgresql_state_overwrites_divergent_redbeat_state(
        self,
        db_session: AsyncSession,
        celery_test_app: Celery,
        fetcher_config_factory: FetcherConfigFactory,
    ) -> None:
        _register(_NoQueueFetcher)
        await fetcher_config_factory(
            fetcher_name=_NoQueueFetcher.name,
            enabled=True,
            schedule_override="0 3 * * *",
        )
        # Simulate operator-induced drift: a divergent schedule already
        # sitting in redbeat before this reconciliation runs.
        divergent = RedBeatSchedulerEntry(
            name=_NoQueueFetcher.name,
            task="run_fetcher",
            schedule=crontab.from_string("0 5 * * *"),
            args=[],
            kwargs={"fetcher_name": _NoQueueFetcher.name, "triggered_by": "schedule"},
            app=celery_test_app,
        )
        divergent.save()

        await reconcile_beat_schedule(db_session, celery_test_app)

        entry = RedBeatSchedulerEntry.from_key(
            RedBeatSchedulerEntry.generate_key(celery_test_app, _NoQueueFetcher.name),
            app=celery_test_app,
        )
        assert entry.schedule.hour == {3}


@pytest.mark.integration
class TestReconcileBeatScheduleFailFast:
    async def test_propagates_postgresql_errors(
        self,
        db_session: AsyncSession,
        celery_test_app: Celery,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        async def _boom(*args: object, **kwargs: object) -> None:
            raise OperationalError("simulated", {}, Exception("boom"))

        monkeypatch.setattr(db_session, "execute", _boom)

        with pytest.raises(OperationalError):
            await reconcile_beat_schedule(db_session, celery_test_app)

    async def test_fails_on_first_redis_error_during_write_step(
        self,
        db_session: AsyncSession,
        celery_test_app: Celery,
        fetcher_config_factory: FetcherConfigFactory,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        _register(_NoQueueFetcher, _QueuedFetcher)
        await fetcher_config_factory(fetcher_name=_NoQueueFetcher.name, enabled=True)
        await fetcher_config_factory(fetcher_name=_QueuedFetcher.name, enabled=True)

        def _raise_redis_error(self: RedBeatSchedulerEntry) -> None:
            raise RedisError("simulated write failure")

        monkeypatch.setattr(RedBeatSchedulerEntry, "save", _raise_redis_error)

        with pytest.raises(RedisError):
            await reconcile_beat_schedule(db_session, celery_test_app)

    async def test_fails_on_first_redis_error_during_cleanup_step(
        self,
        db_session: AsyncSession,
        celery_test_app: Celery,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        FETCHER_REGISTRY.clear()
        entry = RedBeatSchedulerEntry(
            name="corrupted_for_failure_test",
            task="run_fetcher",
            schedule=crontab.from_string(_NoQueueFetcher.default_schedule),
            args=[],
            kwargs={},
            app=celery_test_app,
        )
        entry.save()

        def _raise_redis_error(self: RedBeatSchedulerEntry) -> None:
            raise RedisError("simulated delete failure")

        monkeypatch.setattr(RedBeatSchedulerEntry, "delete", _raise_redis_error)

        with pytest.raises(RedisError):
            await reconcile_beat_schedule(db_session, celery_test_app)


@pytest.mark.integration
class TestReconcileBeatScheduleAuditEvents:
    async def test_creates_no_fetcher_audit_event(
        self,
        db_session: AsyncSession,
        celery_test_app: Celery,
        fetcher_config_factory: FetcherConfigFactory,
    ) -> None:
        _register(_NoQueueFetcher)
        await fetcher_config_factory(fetcher_name=_NoQueueFetcher.name, enabled=True)

        await reconcile_beat_schedule(db_session, celery_test_app)

        rows = (await db_session.execute(select(FetcherAuditEvent))).scalars().all()
        assert rows == []
