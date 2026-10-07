"""Celery application factory and bootstrap.

Constructs the single `Celery` application object shared by every
Celery-based runtime process (worker, Beat, IBS RabbitMQ consumer — see
`docs/deployment.md`, Container Images). Validates the mandatory
startup contracts defined in
`docs/features/platform/fetcher-infrastructure.md` (Startup
Validation): UTC timezone and RedBeat distributed lock enabled, both
via `validate_celery_config()`. The no-result-backend contract is
fixed by construction (`result_backend=None` is hard-coded, with no
corresponding `Settings` field to misconfigure) rather than actively
validated.

Also wires:
- Structured logging (`app.core.logging.configure_logging`) into
  Celery's own logging setup via the `setup_logging` signal, so Celery
  does not install its own handlers/levels on top of the
  structlog/stdlib pipeline (see `docs/features/platform/logging.md`,
  Integration with Third-Party Loggers).
- Task correlation binding (`celery_task_id`) via the
  `task_prerun`/`task_postrun` signals (see
  `docs/features/platform/logging.md`, Correlation IDs).
- Fetcher module discovery (`app.services.fetcher_discovery`) and the
  worker/Beat fetcher config bootstrap handlers
  (`app.tasks.worker_startup`, `app.tasks.beat_startup` — see
  `docs/features/platform/fetcher-infrastructure.md`, FetcherConfig,
  Worker Startup Handler, and Startup Reconciliation). Beat's handler
  additionally reconciles the dynamic, per-fetcher RedBeat schedule
  against `FetcherConfig` and `FETCHER_REGISTRY`
  (`app.services.fetcher_schedule.reconcile_beat_schedule`).

Also registers the static, code-authoritative `beat_schedule` entry for
the `cleanup_sessions` non-fetcher periodic task — see
`docs/features/platform/fetcher-infrastructure.md` (Non-Fetcher
Periodic Tasks). This is a fixed maintenance-task schedule declared
directly in code, distinct from the fetcher framework's
PostgreSQL-backed, admin-configurable schedules. No `FETCHER_REGISTRY`,
`FetcherConfig`, or `FetcherRun` machinery is introduced here.
"""

from __future__ import annotations

from typing import Any

import structlog
from celery import Celery
from celery.schedules import crontab
from celery.signals import setup_logging, task_postrun, task_prerun

from app.config import Settings, settings
from app.core.logging import configure_logging

# Fixed application-level tuning (not environment-configurable — see
# docs/features/platform/fetcher-infrastructure.md, Redbeat Configuration
# and docs/configuration.md, Beat Tick Interval).
_BEAT_MAX_LOOP_INTERVAL = 60
_REDBEAT_LOCK_KEY = "redbeat::lock"
# Derived as `beat_max_loop_interval * 5`, matching redbeat's own default
# derivation — see docs/features/platform/fetcher-infrastructure.md
# (Redbeat Configuration, Derived values).
_REDBEAT_LOCK_TIMEOUT = _BEAT_MAX_LOOP_INTERVAL * 5
# Bounds how long a RedBeat Redis operation can block on a hung
# (blackholed/firewalled) connection before raising `RedisError`.
# Mirrors the 2-second timeout used by the application's own Redis
# clients (`local_auth_service`, `session_service`) — see
# docs/features/platform/fetcher-infrastructure.md (Redbeat
# Configuration).
_REDBEAT_SOCKET_TIMEOUT = 2

# Static Beat schedule for non-fetcher periodic tasks (see
# docs/features/platform/fetcher-infrastructure.md, Non-Fetcher
# Periodic Tasks). Referenced by task name (string) rather than a task
# object so this dict can be set at construction time for *every*
# Celery app instance `create_celery_app()` builds (including in unit
# tests) without importing `app.tasks.session_cleanup` here — which
# would create a circular import (that module imports the `celery_app`
# singleton constructed at the bottom of this file).
_BEAT_SCHEDULE: dict[str, dict[str, Any]] = {
    "cleanup_sessions": {
        "task": "cleanup_sessions",
        "schedule": crontab(day_of_week="sun", hour=3, minute=0),
    },
}

# Correlation ContextVar names cleared unconditionally at task_prerun —
# see docs/features/platform/logging.md (Reset requirement).
_CORRELATION_KEYS = ("request_id", "celery_task_id", "fetcher_run_id")


def validate_celery_config(app: Celery) -> None:
    """Validate the mandatory startup contracts on a constructed app.

    Raises `RuntimeError` with a fatal, operator-facing message if
    either the UTC timezone contract or the redbeat distributed lock
    contract is violated. See
    `docs/features/platform/fetcher-infrastructure.md` (Startup
    Validation) for the exact conditions and message text this
    function implements verbatim.
    """
    timezone = app.conf.timezone
    enable_utc = app.conf.enable_utc
    if timezone != "UTC" or enable_utc is not True:
        msg = (
            f"FATAL: Celery timezone must be UTC. Current value: "
            f"timezone={timezone}, enable_utc={enable_utc}. All fetcher "
            f"schedules assume UTC — see docs/conventions.md."
        )
        raise RuntimeError(msg)

    lock_key = app.conf.get("redbeat_lock_key")
    lock_timeout = app.conf.get("redbeat_lock_timeout")
    if not lock_key or not lock_timeout:
        msg = (
            f"FATAL: Redbeat distributed lock must be enabled. Current "
            f"value: redbeat_lock_key={lock_key}, "
            f"redbeat_lock_timeout={lock_timeout}. The lock is required "
            f"for automatic recovery from Redis data loss — see "
            f"docs/features/platform/fetcher-infrastructure.md (Runtime: "
            f"Redis Data Loss)."
        )
        raise RuntimeError(msg)


def create_celery_app(app_settings: Settings) -> Celery:
    """Build and validate the Sentinel Celery application.

    Registers the static `beat_schedule` entry for the non-fetcher
    `cleanup_sessions` periodic task (see `_BEAT_SCHEDULE` above). The
    dynamic, per-fetcher RedBeat schedule (built from `FETCHER_REGISTRY`
    and `FetcherConfig`) is populated at Beat startup, not here — see
    `docs/features/platform/fetcher-infrastructure.md` (Celery Beat
    Schedule Synchronization, Startup Reconciliation).
    """
    app = Celery("sentinel")
    app.conf.update(
        # NOTE: Celery's own `Settings.broker_url` property (see
        # celery/app/utils.py) reads `os.environ["CELERY_BROKER_URL"]`
        # unconditionally *before* this value — native Celery behavior,
        # not overridable here. This never diverges in a real deployment
        # (`app_settings.celery_broker_url` is itself populated from that
        # same env var), so passing it explicitly keeps this value as the
        # effective source of truth in every real invocation.
        broker_url=app_settings.celery_broker_url,
        result_backend=None,
        task_ignore_result=True,
        timezone=app_settings.celery_timezone,
        enable_utc=app_settings.celery_enable_utc,
        worker_hijack_root_logger=False,
        beat_scheduler="redbeat.RedBeatScheduler",
        beat_max_loop_interval=_BEAT_MAX_LOOP_INTERVAL,
        # RedBeat stores the schedule on the broker Redis instance. Set
        # explicitly because celery-redbeat deprecates its `broker_url`
        # fallback. Taken from `Settings`, not from the `broker_url`
        # property above, because the fallback read the configured value
        # and not `CELERY_BROKER_URL` — see
        # docs/features/platform/fetcher-infrastructure.md (Redbeat
        # Configuration).
        redbeat_redis_url=app_settings.celery_broker_url,
        redbeat_lock_key=_REDBEAT_LOCK_KEY,
        redbeat_lock_timeout=_REDBEAT_LOCK_TIMEOUT,
        redbeat_redis_options={
            "socket_connect_timeout": _REDBEAT_SOCKET_TIMEOUT,
            "socket_timeout": _REDBEAT_SOCKET_TIMEOUT,
        },
        beat_schedule=_BEAT_SCHEDULE,
    )
    validate_celery_config(app)
    return app


def _install_structured_logging(**_kwargs: Any) -> None:
    """Replace Celery's own logging setup with Sentinel's pipeline.

    Connecting a receiver to `setup_logging` makes Celery skip its
    entire built-in `setup_logging_subsystem` branch (see
    `celery.app.log.Logging.setup_logging_subsystem` — it only runs
    when there are no receivers). `worker_hijack_root_logger=False`
    alone is insufficient: Celery still reconfigures the root logger's
    *level* even when hijacking is disabled, which would silently
    override `LOG_LEVEL`. See
    docs/features/platform/logging.md (Integration with Third-Party
    Loggers) for the corrected contract this receiver implements.
    """
    configure_logging(settings)


def _bind_task_correlation(task_id: str | None = None, **_kwargs: Any) -> None:
    """Bind `celery_task_id` for the duration of task execution.

    Unconditionally clears all three correlation ContextVars first —
    see docs/features/platform/logging.md (Reset requirement) — so a
    stale value from a previous task cannot leak into this one in
    reused prefork worker processes, even if `task_postrun` was skipped
    for the previous task (hard time limit kill, unhandled exception in
    the signal handler itself).
    """
    structlog.contextvars.unbind_contextvars(*_CORRELATION_KEYS)
    structlog.contextvars.bind_contextvars(celery_task_id=task_id)


def _unbind_task_correlation(**_kwargs: Any) -> None:
    """Reset `celery_task_id` at the end of task execution.

    Defense-in-depth cleanup — the unconditional clear in
    `_bind_task_correlation` is the primary guarantee (see
    docs/features/platform/logging.md, Reset requirement).
    """
    structlog.contextvars.unbind_contextvars(*_CORRELATION_KEYS)


# Connected via explicit `.connect(...)` calls (rather than the
# `@signal.connect(...)` decorator form) because `celery.signals` ships
# no type stubs (see the mypy override for `celery.*` in
# pyproject.toml): the decorator form makes mypy infer these functions
# as untyped, which strict mode rejects. Explicit connection keeps the
# handlers themselves fully typed.
setup_logging.connect(
    _install_structured_logging, dispatch_uid="sentinel.celery_app.setup_logging"
)
task_prerun.connect(
    _bind_task_correlation, dispatch_uid="sentinel.celery_app.task_prerun"
)
task_postrun.connect(
    _unbind_task_correlation, dispatch_uid="sentinel.celery_app.task_postrun"
)


celery_app = create_celery_app(settings)

# Fetcher module discovery MUST run before the worker/Beat startup
# handlers below import and call `bootstrap_fetcher_configs()`, so
# `FETCHER_REGISTRY` is fully populated by the time either handler's
# bootstrap runs — see docs/features/platform/fetcher-infrastructure.md
# (Fetcher Discovery (Module Import)).
import app.services.fetcher_discovery  # noqa: E402,F401

# Import task modules so they register (via `@celery_app.task(...)`)
# against the singleton constructed above. Must come after
# construction — these modules import `celery_app` from this module,
# which would otherwise be a circular import (this module's
# `beat_schedule` entry above references the `cleanup_sessions` task by
# name only, precisely to avoid needing this import any earlier).
# `beat_startup` and `worker_startup` do not need `celery_app` directly
# (they only connect to Celery signals) but are imported here for a
# single, discoverable startup-wiring location.
from app.tasks import (  # noqa: E402,F401
    beat_startup,
    cve_tasks,
    cvss_tasks,
    fetchers,
    package_tasks,
    session_cleanup,
    worker_startup,
)
