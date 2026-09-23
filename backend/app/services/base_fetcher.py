"""Generic BaseFetcher lifecycle, registry, and HTTP client integration.

See `docs/features/platform/fetcher-infrastructure.md` for the full
specification this module implements: the `run()` lifecycle (logging
context, per-run state reset, settings validation, cursor load, execution,
finalization, HTTP teardown, exception propagation), import-time class
validation (`__init_subclass__`), the custom Settings schema, error
message sanitization, and the BaseFetcher HTTP client integration.

Out of scope for this module (owned by later work items):
`BaseCVEFetcher`, `BaseGitFetcher`, the `run_catch_up` Celery task, and
any concrete production fetcher. The `run_fetcher` Celery task and the
atomic run acquisition protocol are implemented in
`app/tasks/fetchers.py` and `app/services/fetcher_execution.py`.
Config bootstrap (`bootstrap_fetcher_configs()`) is implemented in
`app/services/fetcher_bootstrap.py` and wired into worker/Beat startup
via `app/tasks/worker_startup.py` and `app/tasks/beat_startup.py`.
RedBeat schedule construction and startup reconciliation are
implemented in `app/services/fetcher_schedule.py`, wired into Beat
startup via `app/tasks/beat_startup.py`. These build on this module's
`FETCHER_REGISTRY`, `FetcherRunConfig`, and `BaseFetcher.run()`.
"""

from __future__ import annotations

import inspect
import json
import re
import traceback
import warnings
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import IntEnum, StrEnum
from typing import Any, ClassVar, Literal, get_args, get_origin
from uuid import UUID

import httpx
import structlog
from celery.exceptions import SoftTimeLimitExceeded
from celery.schedules import crontab
from pydantic import BaseModel, ValidationError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from structlog.contextvars import bind_contextvars, reset_contextvars

from app.core.enums import FetcherRunStatus
from app.database import async_session_factory
from app.models.fetcher_run import FetcherRun
from app.services.http_client import create_http_client

logger = structlog.get_logger(__name__)

_NAME_RE = re.compile(r"^[a-z][a-z0-9_]*$")
_SNAKE_CASE_RE = re.compile(r"^[a-z][a-z0-9_]*$")
_SCALAR_TYPES: tuple[type, ...] = (int, float, str, bool)
_MAX_REQUEST_DELAY = 300


# ---------------------------------------------------------------------------
# Runtime configuration snapshot
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FetcherRunConfig:
    """Immutable, detached runtime configuration snapshot.

    Built during the acquisition transaction (owned by the
    `run_fetcher` task wrapper — not part of this module) and passed to
    `BaseFetcher.run()`. Holds no ORM reference — safe to read after
    the acquisition transaction commits.

    Carries only the fields `execute()` actually consumes. Fetcher
    identity is available via `self.name` (not duplicated here);
    enabled state and scheduling are already resolved before the
    snapshot is built and have no bearing on an in-progress execution.

    `custom_settings` is defensively shallow-copied at construction so
    that later mutation of the source `FetcherConfig.custom_settings`
    dict cannot retroactively change an already-dispatched snapshot.
    """

    hard_time_limit_seconds: int
    request_delay: float
    custom_settings: dict[str, Any]

    def __post_init__(self) -> None:
        object.__setattr__(self, "custom_settings", dict(self.custom_settings))


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class FetcherError(Exception):
    """Base exception for fetcher infrastructure errors.

    Concrete fetchers raise this (or a subclass) from their `execute()`
    method with a sanitized public message. See
    `docs/features/platform/fetcher-infrastructure.md` (Error Message
    Sanitization).
    """


class FetcherConfigError(FetcherError):
    """Raised when stored settings fail validation at run start."""


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

FETCHER_REGISTRY: dict[str, type[BaseFetcher]] = {}


# ---------------------------------------------------------------------------
# Import-time validation helpers
# ---------------------------------------------------------------------------


def _validate_name(cls: type[BaseFetcher]) -> None:
    name = getattr(cls, "name", None)
    if not isinstance(name, str) or not _NAME_RE.match(name) or len(name) > 100:
        raise TypeError(
            f"{cls.__name__}.name must match '[a-z][a-z0-9_]*' and not exceed "
            f"100 characters, got {name!r}"
        )


def _check_name_not_duplicate(cls: type[BaseFetcher]) -> None:
    existing = FETCHER_REGISTRY.get(cls.name)
    if existing is not None and existing is not cls:
        raise TypeError(
            f"Fetcher name '{cls.name}' is already registered by "
            f"{existing.__name__}; cannot register {cls.__name__}"
        )


def _validate_description(cls: type[BaseFetcher]) -> None:
    description = getattr(cls, "description", None)
    if not isinstance(description, str) or not description.strip():
        raise TypeError(f"{cls.__name__}.description must be a non-empty string")


def _validate_schedule(cls: type[BaseFetcher]) -> None:
    schedule = getattr(cls, "default_schedule", None)
    if not isinstance(schedule, str):
        raise TypeError(f"{cls.__name__}.default_schedule must be a string")
    try:
        crontab.from_string(schedule)
    except ValueError as exc:
        raise TypeError(
            f"{cls.__name__}.default_schedule is not a valid 5-field cron "
            f"expression: {schedule!r} ({exc})"
        ) from exc


def _validate_request_delay(cls: type[BaseFetcher]) -> None:
    delay = cls.default_request_delay
    if isinstance(delay, bool) or not isinstance(delay, int | float):
        raise TypeError(f"{cls.__name__}.default_request_delay must be a number")
    if not (0 <= delay <= _MAX_REQUEST_DELAY):
        raise TypeError(
            f"{cls.__name__}.default_request_delay must be between 0 and "
            f"{_MAX_REQUEST_DELAY}, got {delay!r}"
        )


def _validate_queue(cls: type[BaseFetcher]) -> None:
    queue = cls.queue
    if queue is not None and (not isinstance(queue, str) or not queue.strip()):
        raise TypeError(f"{cls.__name__}.queue must be None or a non-empty string")


def _validate_execute_override(cls: type[BaseFetcher]) -> None:
    if cls.execute is BaseFetcher.execute:
        raise TypeError(
            f"{cls.__name__} must override execute() with a concrete implementation"
        )
    if not inspect.iscoroutinefunction(cls.execute):
        raise TypeError(f"{cls.__name__}.execute() must be an async method")


def _is_scalar_annotation(annotation: Any) -> bool:
    if annotation in _SCALAR_TYPES:
        return True
    origin = get_origin(annotation)
    if origin is Literal:
        return all(isinstance(arg, _SCALAR_TYPES) for arg in get_args(annotation))
    return isinstance(annotation, type) and issubclass(annotation, StrEnum | IntEnum)


def _validate_settings_class(cls: type[BaseFetcher]) -> None:
    settings_cls = cls.Settings
    if settings_cls is None:
        return
    if not (isinstance(settings_cls, type) and issubclass(settings_cls, BaseModel)):
        raise TypeError(
            f"{cls.__name__}.Settings must be a subclass of pydantic.BaseModel"
        )

    model_config = settings_cls.model_config
    if model_config.get("extra") != "ignore" or not model_config.get(
        "validate_default"
    ):
        raise TypeError(
            f"{cls.__name__}.Settings must set model_config = "
            "ConfigDict(extra='ignore', validate_default=True)"
        )

    for field_name, field_info in settings_cls.model_fields.items():
        if not _SNAKE_CASE_RE.match(field_name):
            raise TypeError(
                f"{cls.__name__}.Settings field {field_name!r} must be snake_case"
            )
        if field_info.is_required():
            raise TypeError(
                f"{cls.__name__}.Settings field {field_name!r} must declare a "
                "default value"
            )
        if not _is_scalar_annotation(field_info.annotation):
            raise TypeError(
                f"{cls.__name__}.Settings field {field_name!r} must use a scalar "
                "type (int, float, str, bool, Literal of scalars, StrEnum, IntEnum)"
            )

    # `validate_default=True` only validates a field's default against its
    # own constraints when Pydantic actually evaluates that default — at
    # model instantiation, not at class body execution. Instantiating with
    # no overrides here forces that check to run now, at import time,
    # rather than deferring the failure to the fetcher's first real run.
    try:
        settings_cls()
    except ValidationError as exc:
        raise TypeError(
            f"{cls.__name__}.Settings has one or more invalid default values: {exc}"
        ) from exc


def _validate_catch_up_signature(cls: type[BaseFetcher]) -> None:
    func = cls.__dict__.get("catch_up")
    if func is None:
        return
    if not inspect.iscoroutinefunction(func):
        raise TypeError(f"{cls.__name__}.catch_up() must be an async method")

    sig = inspect.signature(func)
    actual_names = list(sig.parameters.keys())
    expected_names = ["self", "ticket_id", "session"]
    if actual_names != expected_names:
        raise TypeError(
            f"{cls.__name__}.catch_up() must accept exactly "
            f"(self, ticket_id, session), got ({', '.join(actual_names)})"
        )

    hints = inspect.get_annotations(func, eval_str=True)
    if hints.get("ticket_id") is not str:
        raise TypeError(
            f"{cls.__name__}.catch_up()'s ticket_id parameter must be annotated as str"
        )
    if hints.get("session") is not AsyncSession:
        raise TypeError(
            f"{cls.__name__}.catch_up()'s session parameter must be annotated as "
            "AsyncSession"
        )
    if "return" in hints and hints["return"] is not None:
        raise TypeError(f"{cls.__name__}.catch_up() must return None")


def _validate_catch_up_participation(cls: type[BaseFetcher]) -> None:
    if cls.participates_in_catch_up and cls.catch_up is BaseFetcher.catch_up:
        raise TypeError(
            f"{cls.__name__} sets participates_in_catch_up=True but does not "
            "implement catch_up()"
        )


def _warn_catch_up_flag_mismatch(cls: type[BaseFetcher]) -> None:
    if "catch_up" in cls.__dict__ and not cls.participates_in_catch_up:
        warnings.warn(
            f"{cls.__name__} defines catch_up() but participates_in_catch_up is "
            "False — the fetcher will not receive per-ticket catch-up dispatch",
            stacklevel=3,
        )


# ---------------------------------------------------------------------------
# Error sanitization
# ---------------------------------------------------------------------------


def _sanitize_error(
    exc: BaseException, hard_time_limit_seconds: int, fetcher_name: str, processed: int
) -> tuple[str, str | None]:
    """Map an execution exception to a sanitized public/restricted pair.

    Returns `(error_message, error_detail)`. `error_message` is always
    safe for public display. `error_detail` is `None` when no
    additional restricted context is available.
    """
    if isinstance(exc, FetcherError):
        cause = exc.__cause__
        return str(exc), (str(cause) if cause is not None else None)
    if isinstance(exc, httpx.HTTPStatusError):
        status_code = exc.response.status_code
        if status_code >= 500:
            return "External service returned server error", str(exc)
        if status_code >= 400:
            return "External service rejected request", str(exc)
        return "Unexpected error", str(exc)
    if isinstance(exc, httpx.NetworkError | httpx.TimeoutException):
        return "External service unreachable", str(exc)
    if isinstance(exc, SoftTimeLimitExceeded):
        return (
            "Execution reached the soft time limit (hard limit for this "
            f"run: {hard_time_limit_seconds}s; {processed} items processed). "
            f"Review FetcherConfig.run_timeout for future runs of fetcher "
            f"'{fetcher_name}'.",
            str(exc),
        )
    return "Unexpected error", str(exc)


def _validate_metric_count(count: int) -> None:
    """Enforce the shared metric-helper `count` contract.

    `count` must be an `int` greater than or equal to zero. `bool` is
    rejected even though it is an `int` subclass. Validation happens
    before any counter mutation, so a rejected call leaves every counter
    unchanged. See `docs/features/platform/fetcher-infrastructure.md`
    (Metric helpers).
    """
    if isinstance(count, bool) or not isinstance(count, int):
        raise TypeError(
            f"metric helper count must be an int, got {type(count).__name__}"
        )
    if count < 0:
        raise ValueError(f"metric helper count must be >= 0, got {count}")


# ---------------------------------------------------------------------------
# BaseFetcher
# ---------------------------------------------------------------------------


class BaseFetcher:
    """Abstract base class for all Sentinel fetchers.

    See `docs/features/platform/fetcher-infrastructure.md` (BaseFetcher
    Base Class, Abstract Interface) for the full contract.
    """

    abstract: ClassVar[bool] = False
    name: ClassVar[str]
    description: ClassVar[str]
    default_schedule: ClassVar[str]
    default_request_delay: ClassVar[float] = 0
    queue: ClassVar[str | None] = None
    participates_in_catch_up: ClassVar[bool] = False
    http_client_options: ClassVar[dict[str, Any]] = {}
    Settings: ClassVar[type[BaseModel] | None] = None

    def __init__(self) -> None:
        self._http_client: httpx.AsyncClient | None = None
        self._succeeded = 0
        self._created = 0
        self._updated = 0
        self._failed = 0
        self._cursor: dict[str, Any] | None = None
        self._previous_cursor: dict[str, Any] | None = None
        self._settings_instance: BaseModel | None = None
        self.config: FetcherRunConfig | None = None

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        if cls.__dict__.get("abstract", False):
            return

        _validate_name(cls)
        _check_name_not_duplicate(cls)
        _validate_description(cls)
        _validate_schedule(cls)
        _validate_request_delay(cls)
        _validate_queue(cls)
        _validate_execute_override(cls)
        _validate_settings_class(cls)
        _validate_catch_up_signature(cls)
        _validate_catch_up_participation(cls)
        _warn_catch_up_flag_mismatch(cls)

        FETCHER_REGISTRY[cls.name] = cls

    # -- Abstract interface --------------------------------------------

    async def execute(self, session: AsyncSession) -> None:
        """Fetch data from the external source. MUST be overridden.

        Use `self.record_succeeded()` or `self.record_failed()` for each
        selected work unit's terminal outcome, and `self.record_created()` /
        `self.record_updated()` for durable effects.
        """
        raise NotImplementedError(f"{type(self).__name__} must implement execute()")

    async def catch_up(self, ticket_id: str, session: AsyncSession) -> None:
        """Per-ticket catch-up after reactivation. Override point.

        `BaseCVEFetcher` provides the default implementation for CVE
        fetchers. Non-CVE fetchers override with custom logic. Direct
        `BaseFetcher` subclasses that need catch-up MUST define
        `catch_up()` explicitly.
        """
        raise NotImplementedError(
            f"{type(self).__name__} does not implement catch_up()"
        )

    # -- Metrics ---------------------------------------------------------

    def record_succeeded(self, count: int = 1) -> None:
        _validate_metric_count(count)
        self._succeeded += count

    def record_failed(self, count: int = 1) -> None:
        _validate_metric_count(count)
        self._failed += count

    def record_created(self, count: int = 1) -> None:
        _validate_metric_count(count)
        self._created += count

    def record_updated(self, count: int = 1) -> None:
        _validate_metric_count(count)
        self._updated += count

    # -- Cursor ------------------------------------------------------------

    @property
    def previous_cursor(self) -> dict[str, Any] | None:
        """The cursor from the last successful or partial run.

        Loaded during `run()` phase 4 (before `execute()`). `None` if
        no prior successful/partial run exists or its cursor was NULL.
        """
        return self._previous_cursor

    # -- Custom settings -----------------------------------------------

    def get_setting(self, key: str) -> Any:
        """Resolve a custom setting value.

        Precedence: stored override (`FetcherConfig.custom_settings`)
        if present, else the `Settings` field default. Raises
        `KeyError` if no `Settings` model is declared or `key` is not
        one of its declared fields.
        """
        settings_cls = type(self).Settings
        if settings_cls is None or key not in settings_cls.model_fields:
            raise KeyError(key)
        instance = (
            self._settings_instance
            if self._settings_instance is not None
            else settings_cls()
        )
        return getattr(instance, key)

    def _build_settings_instance(
        self, custom_settings: dict[str, Any]
    ) -> BaseModel | None:
        settings_cls = type(self).Settings
        if settings_cls is None:
            return None
        return settings_cls.model_validate(custom_settings)

    # -- HTTP client -----------------------------------------------------

    @property
    def http_client(self) -> httpx.AsyncClient:
        """Pre-configured HTTP client, created lazily on first access."""
        if self._http_client is None:
            self._http_client = create_http_client(
                name=self.name, **self.http_client_options
            )
        return self._http_client

    async def _teardown_http_client(self) -> None:
        if self._http_client is not None:
            try:
                await self._http_client.aclose()
            except Exception:
                logger.warning(
                    "fetcher_http_client_close_failed", fetcher_name=self.name
                )
            self._http_client = None

    # -- Lifecycle ---------------------------------------------------------

    async def run(self, *, run_id: UUID, config: FetcherRunConfig) -> None:
        """Manage a single fetcher execution end to end.

        See `docs/features/platform/fetcher-infrastructure.md` (`run()`
        lifecycle) for the full 9-phase contract and the exception
        propagation matrix.
        """
        self.config = config
        self._succeeded = 0
        self._created = 0
        self._updated = 0
        self._failed = 0
        self._cursor = None
        self._previous_cursor = None
        self._settings_instance = None

        tokens = bind_contextvars(fetcher_run_id=str(run_id))
        execution_exc: BaseException | None = None
        try:
            execution_exc = await self._run_settings_and_execution(config)
            await self._finalize(run_id, config, execution_exc)
        finally:
            await self._teardown_http_client()
            reset_contextvars(**tokens)

        if execution_exc is not None:
            raise execution_exc

    async def _run_settings_and_execution(
        self, config: FetcherRunConfig
    ) -> BaseException | None:
        try:
            try:
                self._settings_instance = self._build_settings_instance(
                    config.custom_settings
                )
            except ValidationError as exc:
                raise FetcherConfigError(
                    f"Fetcher '{self.name}' has invalid stored settings "
                    "— update via the API"
                ) from exc

            self._previous_cursor = await self._load_previous_cursor(self.name)
        except Exception as exc:
            return exc

        async with async_session_factory() as session:
            try:
                await self.execute(session)
            except Exception as exc:
                await session.rollback()
                return exc
        return None

    async def _load_previous_cursor(self, fetcher_name: str) -> dict[str, Any] | None:
        async with async_session_factory() as session:
            result = await session.execute(
                select(FetcherRun.cursor)
                .where(
                    FetcherRun.fetcher_name == fetcher_name,
                    FetcherRun.status.in_(
                        [
                            FetcherRunStatus.SUCCESS.value,
                            FetcherRunStatus.PARTIAL.value,
                        ]
                    ),
                )
                .order_by(FetcherRun.started_at.desc())
                .limit(1)
            )
            return result.scalar_one_or_none()

    async def _finalize(
        self,
        run_id: UUID,
        config: FetcherRunConfig,
        execution_exc: BaseException | None,
    ) -> None:
        error_message: str | None = None
        error_detail: str | None = None
        error_traceback: str | None = None
        cursor_to_persist: dict[str, Any] | None = None

        if execution_exc is not None:
            status = FetcherRunStatus.FAILURE.value
            processed = self._succeeded + self._failed
            error_message, error_detail = _sanitize_error(
                execution_exc, config.hard_time_limit_seconds, self.name, processed
            )
            error_traceback = "".join(
                traceback.format_exception(
                    type(execution_exc), execution_exc, execution_exc.__traceback__
                )
            )
        elif self._failed > 0 and self._succeeded == 0:
            status = FetcherRunStatus.FAILURE.value
            error_message = f"All {self._failed} items failed"
        elif self._failed > 0:
            status = FetcherRunStatus.PARTIAL.value
        else:
            status = FetcherRunStatus.SUCCESS.value

        if (
            status
            in (
                FetcherRunStatus.SUCCESS.value,
                FetcherRunStatus.PARTIAL.value,
            )
            and self._cursor is not None
        ):
            try:
                json.dumps(self._cursor)
            except TypeError as exc:
                status = FetcherRunStatus.FAILURE.value
                error_message = "Cursor serialization failed"
                error_detail = str(exc)
                error_traceback = "".join(
                    traceback.format_exception(type(exc), exc, exc.__traceback__)
                )
            else:
                cursor_to_persist = self._cursor

        finished_at = datetime.now(UTC)

        try:
            async with async_session_factory() as session:
                run = await session.get(FetcherRun, run_id)
                if run is None:
                    raise RuntimeError(
                        f"FetcherRun {run_id} not found during finalization"
                    )
                if run.started_at is None:
                    raise RuntimeError(
                        f"FetcherRun {run_id} has no started_at during "
                        "finalization — run() must only be invoked on an "
                        "already-adopted (running) run"
                    )
                run.finished_at = finished_at
                run.duration_seconds = (finished_at - run.started_at).total_seconds()
                run.status = status
                run.items_succeeded = self._succeeded
                run.items_created = self._created
                run.items_updated = self._updated
                run.items_failed = self._failed
                run.error_message = error_message
                run.error_detail = error_detail
                run.error_traceback = error_traceback
                if cursor_to_persist is not None:
                    run.cursor = cursor_to_persist
                await session.commit()
        except Exception as finalize_exc:
            logger.critical(
                "fetcher_finalization_failed",
                fetcher_name=self.name,
                run_id=str(run_id),
                error=str(finalize_exc),
            )
            raise finalize_exc from execution_exc


# ---------------------------------------------------------------------------
# Catch-up registry accessor
# ---------------------------------------------------------------------------


def get_catch_up_fetchers() -> dict[str, type[BaseFetcher]]:
    """Return fetchers that participate in per-ticket catch-up.

    Selection is based solely on the `participates_in_catch_up` class
    attribute — not on enabled state (see
    `docs/features/platform/fetcher-infrastructure.md`, Registry
    accessor). Computed fresh from the current registry on each call.
    """
    return {
        name: cls
        for name, cls in FETCHER_REGISTRY.items()
        if cls.participates_in_catch_up
    }
