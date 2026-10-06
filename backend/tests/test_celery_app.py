"""Tests for the Celery application bootstrap (backend/app/celery_app.py).

See docs/features/platform/fetcher-infrastructure.md (Celery Integration,
Redbeat Configuration, Startup Validation) and
docs/features/platform/logging.md (Correlation IDs, Integration with
Third-Party Loggers) for the specifications exercised here.

Scope note: this module registers the static non-fetcher
`cleanup_sessions` schedule and the generic `run_fetcher` fetcher task
(see `app/tasks/fetchers.py`, tested separately in
`tests/test_tasks/test_fetchers.py`). Fetcher discovery wiring and the
worker/Beat startup handlers are tested separately in
`tests/test_tasks/test_worker_startup.py` and
`tests/test_tasks/test_beat_startup.py`. The dynamic per-fetcher
RedBeat schedule reconciliation itself
(`app/services/fetcher_schedule.py`) is tested in
`tests/test_services/test_fetcher_schedule.py`.
"""

from __future__ import annotations

import logging
import warnings
from collections.abc import Iterator

import pytest
import structlog
from celery import Celery
from celery.app.log import Logging as CeleryLogging
from celery.signals import (
    beat_init,
    celeryd_after_setup,
    setup_logging,
    task_postrun,
    task_prerun,
)
from redbeat.schedulers import ensure_conf

from app.celery_app import (
    _CORRELATION_KEYS,
    celery_app,
    create_celery_app,
    validate_celery_config,
)
from app.config import Settings
from app.core.logging import _THIRD_PARTY_LOGGERS


def _settings(**overrides: object) -> Settings:
    """Build a Settings instance bypassing env/file sources entirely,
    so tests are hermetic (mirrors the pattern in test_core/test_logging.py)."""
    defaults: dict[str, object] = {
        "jwt_secret_key": "a" * 32,
        "app_name": "sentinel-test",
        "log_level": "INFO",
        "log_format": "json",
        "celery_broker_url": "redis://localhost:6379/1",
        "celery_timezone": "UTC",
        "celery_enable_utc": True,
    }
    defaults.update(overrides)
    return Settings(_env_file=None, **defaults)  # type: ignore[arg-type]


@pytest.fixture(autouse=True)
def _reset_global_state() -> Iterator[None]:
    """Save/restore root logger, structlog contextvars, and Celery's
    internal logging-setup flag around every test.

    Sending real Celery signals (`setup_logging`, `task_prerun`,
    `task_postrun`) in these tests mutates global logging/contextvars
    state exactly as production code would. Without this fixture, that
    state would leak into other tests in the suite.

    `celery.app.log.Logging._setup` deserves special attention: despite
    being read through an instance property (`already_setup`), it is
    written as a **class** attribute
    (`celery.app.log.Logging.setup_logging_subsystem` does
    `Logging._setup = True`, not `self._setup = True`) — so it is
    shared process-wide across every `Celery` app instance, not
    per-instance. Once any test's `app.log.setup(...)` call flips it to
    `True`, every subsequent call across the whole test session
    silently no-ops (Celery's own `setup_logging_subsystem` returns
    immediately), and the `setup_logging` signal is never dispatched
    again — masking a broken receiver as a false pass. Resetting it to
    `False` before each test restores per-test independence.
    """
    root_logger = logging.getLogger()
    original_handlers = list(root_logger.handlers)
    original_level = root_logger.level
    original_third_party = {
        name: (logging.getLogger(name).level, logging.getLogger(name).propagate)
        for name in _THIRD_PARTY_LOGGERS
    }
    original_contextvars = dict(structlog.contextvars.get_contextvars())
    original_celery_log_setup = CeleryLogging._setup
    CeleryLogging._setup = False

    yield

    root_logger.handlers.clear()
    root_logger.handlers.extend(original_handlers)
    root_logger.setLevel(original_level)
    for name, (level, propagate) in original_third_party.items():
        logging.getLogger(name).setLevel(level)
        logging.getLogger(name).propagate = propagate
    structlog.contextvars.clear_contextvars()
    if original_contextvars:
        structlog.contextvars.bind_contextvars(**original_contextvars)
    CeleryLogging._setup = original_celery_log_setup


@pytest.mark.unit
class TestCreateCeleryAppDefaults:
    """Complete default configuration and broker propagation."""

    def test_broker_url_propagated_from_settings(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Celery's own `Settings.broker_url` property (celery/app/utils.py)
        # reads `os.environ["CELERY_BROKER_URL"]` unconditionally *before*
        # falling back to any value set via `.conf.update(...)` — this is
        # native Celery behavior, not something this factory controls. In
        # real deployments this never causes a divergence (our own
        # `Settings.celery_broker_url` field is populated from the very
        # same env var), but a CI job or shell that happens to export
        # `CELERY_BROKER_URL` for unrelated reasons would otherwise shadow
        # the override under test. Ensure a clean environment so this test
        # verifies propagation from `Settings`, not the ambient process env.
        monkeypatch.delenv("CELERY_BROKER_URL", raising=False)
        app = create_celery_app(
            _settings(celery_broker_url="redis://example.invalid:6380/2")
        )
        assert app.conf.broker_url == "redis://example.invalid:6380/2"

    def test_no_result_backend(self) -> None:
        app = create_celery_app(_settings())
        assert app.conf.result_backend is None

    def test_results_ignored(self) -> None:
        app = create_celery_app(_settings())
        assert app.conf.task_ignore_result is True

    def test_timezone_and_enable_utc_propagated(self) -> None:
        app = create_celery_app(_settings())
        assert app.conf.timezone == "UTC"
        assert app.conf.enable_utc is True

    def test_root_logger_not_hijacked(self) -> None:
        app = create_celery_app(_settings())
        assert app.conf.worker_hijack_root_logger is False

    def test_redbeat_scheduler_and_loop_interval(self) -> None:
        app = create_celery_app(_settings())
        assert app.conf.beat_scheduler == "redbeat.RedBeatScheduler"
        assert app.conf.beat_max_loop_interval == 60

    def test_redbeat_lock_defaults(self) -> None:
        app = create_celery_app(_settings())
        assert app.conf.redbeat_lock_key == "redbeat::lock"
        assert app.conf.redbeat_lock_timeout == 300

    def test_cleanup_sessions_static_schedule_is_sunday_at_0300_utc(self) -> None:
        app = create_celery_app(_settings())
        entry = app.conf.beat_schedule["cleanup_sessions"]

        assert entry["task"] == "cleanup_sessions"
        schedule = entry["schedule"]
        assert schedule.minute == {0}
        assert schedule.hour == {3}
        assert schedule.day_of_week == {0}

    def test_cleanup_sessions_task_is_registered_on_singleton(self) -> None:
        assert "cleanup_sessions" in celery_app.tasks

    def test_run_fetcher_task_is_registered_on_singleton(self) -> None:
        assert "run_fetcher" in celery_app.tasks


@pytest.mark.unit
class TestRedbeatRedisUrl:
    """`redbeat_redis_url` is set explicitly to the configured broker
    URL, so RedBeat follows the broker instance without relying on its
    deprecated `broker_url` fallback (see docs/features/platform/
    fetcher-infrastructure.md, Redbeat Configuration)."""

    def test_redbeat_redis_url_is_the_configured_broker_url(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # A diverging `CELERY_BROKER_URL` in the environment does not
        # change the value: the fallback this setting replaces read the
        # configured broker URL, not the environment variable.
        monkeypatch.setenv("CELERY_BROKER_URL", "redis://env.example.invalid:6379/5")
        app = create_celery_app(
            _settings(celery_broker_url="redis://example.invalid:6380/2")
        )
        assert app.conf.redbeat_redis_url == "redis://example.invalid:6380/2"

    def test_redbeat_config_initializes_without_fallback_deprecation(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        app = create_celery_app(
            _settings(celery_broker_url="redis://example.invalid:6380/2")
        )
        with (
            warnings.catch_warnings(record=True) as caught,
            caplog.at_level(logging.WARNING, logger="celery.beat"),
        ):
            warnings.simplefilter("always")
            conf = ensure_conf(app)

        assert conf.redis_url == "redis://example.invalid:6380/2"
        assert [w for w in caught if issubclass(w.category, DeprecationWarning)] == []
        assert not [r for r in caplog.records if "stop falling back" in r.getMessage()]


@pytest.mark.unit
class TestRedbeatRedisOptions:
    """`redbeat_redis_options` configures bounded socket timeouts on
    RedBeat's internal Redis client and never a `retry_period` (see
    docs/features/platform/fetcher-infrastructure.md, Redbeat
    Configuration and Runtime: Redis Data Loss)."""

    def test_socket_timeouts_configured(self) -> None:
        app = create_celery_app(_settings())
        redis_options = app.conf.get("redbeat_redis_options")
        assert redis_options is not None
        assert redis_options["socket_connect_timeout"] == 2
        assert redis_options["socket_timeout"] == 2

    def test_no_redbeat_retry_period_override(self) -> None:
        app = create_celery_app(_settings())
        redis_options = app.conf.get("redbeat_redis_options")
        assert not redis_options or "retry_period" not in redis_options


@pytest.mark.unit
class TestValidateCeleryConfigTimezoneRejection:
    """Non-UTC / disabled UTC startup rejection paths."""

    def _base_app(self) -> Celery:
        app = Celery("test")
        app.conf.update(
            timezone="UTC",
            enable_utc=True,
            redbeat_lock_key="redbeat::lock",
            redbeat_lock_timeout=300,
        )
        return app

    def test_non_utc_timezone_raises(self) -> None:
        app = self._base_app()
        app.conf.timezone = "Europe/Rome"
        with pytest.raises(RuntimeError, match="Celery timezone must be UTC"):
            validate_celery_config(app)

    def test_non_utc_timezone_message_contains_current_values(self) -> None:
        app = self._base_app()
        app.conf.timezone = "Europe/Rome"
        with pytest.raises(
            RuntimeError,
            match=r"timezone=Europe/Rome, enable_utc=True",
        ):
            validate_celery_config(app)

    def test_enable_utc_false_raises(self) -> None:
        app = self._base_app()
        app.conf.enable_utc = False
        with pytest.raises(RuntimeError, match="Celery timezone must be UTC"):
            validate_celery_config(app)

    def test_valid_utc_config_does_not_raise(self) -> None:
        app = self._base_app()
        validate_celery_config(app)


@pytest.mark.unit
class TestValidateCeleryConfigLockRejection:
    """Empty/null lock key or null/zero lock timeout startup rejection paths."""

    def _base_app(self) -> Celery:
        app = Celery("test")
        app.conf.update(
            timezone="UTC",
            enable_utc=True,
            redbeat_lock_key="redbeat::lock",
            redbeat_lock_timeout=300,
        )
        return app

    def test_none_lock_key_raises(self) -> None:
        app = self._base_app()
        app.conf.redbeat_lock_key = None
        with pytest.raises(
            RuntimeError, match="Redbeat distributed lock must be enabled"
        ):
            validate_celery_config(app)

    def test_empty_lock_key_raises(self) -> None:
        app = self._base_app()
        app.conf.redbeat_lock_key = ""
        with pytest.raises(
            RuntimeError, match="Redbeat distributed lock must be enabled"
        ):
            validate_celery_config(app)

    def test_none_lock_timeout_raises(self) -> None:
        app = self._base_app()
        app.conf.redbeat_lock_timeout = None
        with pytest.raises(
            RuntimeError, match="Redbeat distributed lock must be enabled"
        ):
            validate_celery_config(app)

    def test_zero_lock_timeout_raises(self) -> None:
        app = self._base_app()
        app.conf.redbeat_lock_timeout = 0
        with pytest.raises(
            RuntimeError, match="Redbeat distributed lock must be enabled"
        ):
            validate_celery_config(app)

    def test_lock_rejection_message_contains_current_values(self) -> None:
        app = self._base_app()
        app.conf.redbeat_lock_key = None
        app.conf.redbeat_lock_timeout = 0
        with pytest.raises(
            RuntimeError,
            match=r"redbeat_lock_key=None, redbeat_lock_timeout=0",
        ):
            validate_celery_config(app)

    def test_valid_lock_config_does_not_raise(self) -> None:
        app = self._base_app()
        validate_celery_config(app)


@pytest.mark.unit
class TestCreateCeleryAppPropagatesValidationFailure:
    """create_celery_app() itself rejects invalid settings at construction."""

    def test_non_utc_timezone_setting_raises(self) -> None:
        with pytest.raises(RuntimeError, match="Celery timezone must be UTC"):
            create_celery_app(_settings(celery_timezone="Europe/Rome"))

    def test_disabled_utc_setting_raises(self) -> None:
        with pytest.raises(RuntimeError, match="Celery timezone must be UTC"):
            create_celery_app(_settings(celery_enable_utc=False))


@pytest.mark.unit
class TestSetupLoggingSignalReplacesCeleryDefault:
    """Celery's own logging setup is fully bypassed by the connected
    `setup_logging` receiver — LOG_LEVEL remains authoritative."""

    def test_debug_log_level_survives_celery_log_setup(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        custom_settings = _settings(log_level="DEBUG")
        monkeypatch.setattr("app.celery_app.settings", custom_settings)
        app = create_celery_app(custom_settings)

        # Celery's own setup would normally force the root logger to
        # WARNING; because a setup_logging receiver is connected, its
        # internal setup_logging_subsystem branch never runs, and
        # LOG_LEVEL=DEBUG is preserved.
        app.log.setup(loglevel="WARNING")

        assert logging.getLogger().level == logging.DEBUG

    def test_info_log_level_applied_via_receiver(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        custom_settings = _settings(log_level="INFO")
        monkeypatch.setattr("app.celery_app.settings", custom_settings)
        app = create_celery_app(custom_settings)

        app.log.setup(loglevel="ERROR")

        assert logging.getLogger().level == logging.INFO

    def test_receiver_is_connected(self) -> None:
        """A setup_logging receiver must be connected at import time —
        this is what makes Celery skip its own setup branch."""
        assert setup_logging.has_listeners()


@pytest.mark.unit
class TestTaskCorrelationBinding:
    """task_prerun/task_postrun bind and reset celery_task_id."""

    def test_prerun_binds_celery_task_id(self) -> None:
        task_prerun.send(sender=None, task_id="task-abc-123")
        assert structlog.contextvars.get_contextvars()["celery_task_id"] == (
            "task-abc-123"
        )

    def test_prerun_clears_stale_request_id(self) -> None:
        structlog.contextvars.bind_contextvars(request_id="stale-request-id")
        task_prerun.send(sender=None, task_id="task-xyz")
        assert "request_id" not in structlog.contextvars.get_contextvars()

    def test_prerun_clears_stale_fetcher_run_id(self) -> None:
        structlog.contextvars.bind_contextvars(fetcher_run_id="stale-fetcher-id")
        task_prerun.send(sender=None, task_id="task-xyz")
        assert "fetcher_run_id" not in structlog.contextvars.get_contextvars()

    def test_postrun_clears_celery_task_id(self) -> None:
        task_prerun.send(sender=None, task_id="task-abc-123")
        task_postrun.send(sender=None, task_id="task-abc-123")
        assert "celery_task_id" not in structlog.contextvars.get_contextvars()

    def test_second_prerun_without_postrun_does_not_leak_previous_id(self) -> None:
        """Simulates a Celery prefork worker executing a second task after
        the first skipped task_postrun (e.g. hard time limit kill)."""
        task_prerun.send(sender=None, task_id="task-first")
        # task_postrun deliberately not sent for "task-first".
        task_prerun.send(sender=None, task_id="task-second")
        assert (
            structlog.contextvars.get_contextvars()["celery_task_id"] == "task-second"
        )

    def test_all_correlation_keys_covered_by_reset(self) -> None:
        """Documents which ContextVar names task_prerun unconditionally
        clears — see docs/features/platform/logging.md (Reset
        requirement)."""
        assert set(_CORRELATION_KEYS) == {
            "request_id",
            "celery_task_id",
            "fetcher_run_id",
        }


@pytest.mark.unit
class TestFetcherStartupWiring:
    """`app.celery_app` imports fetcher discovery and the worker/Beat
    startup handler modules, registering their signal receivers as a
    side effect of importing this module (already imported at the top
    of this test file) — see
    docs/features/platform/fetcher-infrastructure.md (Fetcher Discovery
    (Module Import), Worker Startup Handler). The receiver-specific
    contracts (ordering, orchestration, fail-fast behavior) are tested
    in tests/test_tasks/test_worker_startup.py and
    tests/test_tasks/test_beat_startup.py.
    """

    def test_static_tasks_remain_registered(self) -> None:
        """Sanity check: adding the fetcher discovery/startup imports
        does not disturb the existing task registrations."""
        assert "cleanup_sessions" in celery_app.tasks
        assert "run_fetcher" in celery_app.tasks

    def test_worker_startup_handler_is_registered(self) -> None:
        assert celeryd_after_setup.has_listeners()

    def test_beat_startup_handler_is_registered(self) -> None:
        assert beat_init.has_listeners()
