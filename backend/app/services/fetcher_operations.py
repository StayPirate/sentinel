"""Fetcher Operations Service — reads, configuration mutation, and
manual trigger orchestration.

See `docs/features/platform/fetcher-operations.md` (Fetcher Operations
Service, `list_fetchers`, `list_fetcher_runs`, `get_fetcher_run`,
`get_fetcher_timeline`, `get_fetcher_config`, `update_fetcher_config`,
`list_fetcher_audit_events`, `trigger_fetcher`, Disabled Period
Derivation) for the full specification this module implements.

The four Public read functions (`list_fetchers`, `list_fetcher_runs`,
`get_fetcher_run`, `get_fetcher_timeline`), the two capability-protected
reads (`get_fetcher_config`, `list_fetcher_audit_events`), the
capability-protected mutation (`update_fetcher_config`), and the
capability-protected manual trigger orchestration (`trigger_fetcher`)
are all implemented here.

Module-level defaults (`docs/conventions.md`, Function Specification
Completeness): every read function accepts a caller-supplied
`AsyncSession`, performs reads only, never flushes or commits, and
creates no audit events. `update_fetcher_config` and `trigger_fetcher`
are the exceptions — see each function's own docstring for its
transaction, audit, and re-invocation contract. Every function
propagates only the exceptions listed in the Service Exceptions table
below, plus standard database exceptions that surface as the global
`500 INTERNAL_ERROR` response.
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from datetime import UTC, date, datetime
from typing import Any, Literal
from uuid import UUID

import structlog
from celery import Celery
from pydantic import ValidationError
from redbeat import RedBeatSchedulerEntry
from redis.exceptions import RedisError
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from sqlalchemy.orm import selectinload

from app.core.dates import normalize_date_bound
from app.core.enums import (
    FetcherAuditEventType,
    FetcherRunStatus,
    FetcherRunTriggeredBy,
)
from app.core.exceptions import ServiceError
from app.models.fetcher_audit_event import FetcherAuditEvent
from app.models.fetcher_config import FetcherConfig
from app.models.fetcher_run import FetcherRun
from app.models.user import User
from app.services.base_fetcher import FETCHER_REGISTRY, BaseFetcher
from app.services.fetcher_audit_log import FetcherAuditLog
from app.services.fetcher_execution import (
    finalize_manual_run_as_failure,
    is_run_stale,
    mark_queued_run_stale,
    mark_run_stale,
    resolve_effective_hard_limit,
)
from app.services.fetcher_schedule import effective_task_time_limits

logger = structlog.get_logger(__name__)

# Default `run_timeout` for a registered fetcher with no `FetcherConfig`
# row yet (bootstrap not run) — mirrors `FetcherConfig.run_timeout`'s
# column default (`docs/data-model.md`, FetcherConfig).
_DEFAULT_RUN_TIMEOUT = 3600

# Sanitized, fixed detail message for a manual trigger's Celery
# publication failure — see `docs/features/platform/fetcher-operations.md`
# (`trigger_fetcher`, Publication Failure Path). Never includes the raw
# broker exception string, which routinely contains hostname, IP, port,
# a Redis URI, or credentials.
_BROKER_PUBLICATION_FAILURE_MESSAGE = (
    "Manual run could not be dispatched to the task broker"
)


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class FetcherOperationsServiceError(ServiceError):
    """Base exception for the fetcher operations service module."""


class FetcherNotFoundError(FetcherOperationsServiceError):
    """No fetcher with this name exists (not in the registry and no
    `FetcherConfig` record in the database)."""

    def __init__(self) -> None:
        super().__init__("Fetcher not found.")


class FetcherRunNotFoundError(FetcherOperationsServiceError):
    """The specified run does not exist or does not belong to the named
    fetcher."""

    def __init__(self) -> None:
        super().__init__("Fetcher run not found.")


class FetcherDeregisteredError(FetcherOperationsServiceError):
    """Fetcher exists in `FetcherConfig` but is not present in
    `FETCHER_REGISTRY` (its code was removed)."""

    def __init__(self) -> None:
        super().__init__("Fetcher is deregistered.")


class FetcherAlreadyRunningError(FetcherOperationsServiceError):
    """An active (`queued` or `running`, non-stale) run exists for this
    fetcher. Raised by both `trigger_fetcher` (a new manual trigger is
    rejected outright) and `update_fetcher_config`'s Run Timeout Active
    Guard (a `run_timeout` change is rejected while the run is active)."""

    def __init__(self) -> None:
        super().__init__("Fetcher has an active run.")


class FetcherDisabledError(FetcherOperationsServiceError):
    """`FetcherConfig.enabled` is `false` — a manual trigger is rejected
    outright (no bypass of the schedule's disabled state)."""

    def __init__(self) -> None:
        super().__init__("Fetcher is disabled.")


class FetcherBrokerUnavailableError(FetcherOperationsServiceError):
    """`trigger_fetcher`'s Celery publication (`apply_async`) raised —
    the task broker is unreachable or rejected the message. The
    pre-created `queued` `FetcherRun` is finalized as `failure` only if
    a worker had not already adopted it (see `trigger_fetcher`,
    Ambiguous Broker Acknowledgement)."""

    def __init__(self) -> None:
        super().__init__("Manual run could not be dispatched to the task broker.")


class FetcherSettingUnknownError(FetcherOperationsServiceError):
    """A submitted `custom_settings` key is not declared in the
    fetcher's `Settings` model."""

    def __init__(self, key: str) -> None:
        self.key = key
        super().__init__(f"Unknown custom setting: {key!r}")


class FetcherSettingInvalidError(FetcherOperationsServiceError):
    """The candidate merged state (current stored `custom_settings`
    values plus the submitted, non-null changes) fails the fetcher's
    `Settings` model type/range/choices validation. The invalid field
    is not necessarily one the caller submitted — see
    `docs/features/platform/fetcher-operations.md`
    (`update_fetcher_config`, Custom settings canonicalization)."""

    def __init__(self, message: str) -> None:
        super().__init__(message)


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FetcherRunSummary:
    """One run, shaped for the `List Fetchers`/`List Fetcher Runs`
    responses. `triggered_by_user` is already visibility-filtered by
    the producing function (`None` unless the caller holds
    `manage_fetchers`)."""

    id: UUID
    fetcher_name: str
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    duration_seconds: float | None
    status: str
    items_succeeded: int
    items_created: int
    items_updated: int
    items_failed: int
    error_message: str | None
    triggered_by: str
    triggered_by_user: User | None
    stale: bool


@dataclass(frozen=True)
class FetcherRunDetail(FetcherRunSummary):
    """Full run detail. `error_detail`/`error_traceback` are always the
    raw stored values here — the caller (API router) decides whether to
    surface them, based on the same `has_manage_fetchers` value it
    passed into `get_fetcher_run()`."""

    error_detail: str | None
    error_traceback: str | None


@dataclass(frozen=True)
class FetcherListItem:
    """One entry in the `List Fetchers` response."""

    fetcher_name: str
    registered: bool
    description: str | None
    enabled: bool
    effective_schedule: str | None
    schedule_is_override: bool | None
    default_schedule: str | None
    cve_source_type: str | None
    next_run_at: datetime | None
    custom_settings_count: int
    last_run: FetcherRunSummary | None


@dataclass(frozen=True)
class FetcherRunPage:
    """One page of `FetcherRunSummary` rows."""

    items: list[FetcherRunSummary]
    total: int
    page: int
    per_page: int


@dataclass(frozen=True)
class DisabledPeriod:
    """One derived disabled period. `disabled_by`/`enabled_by` are
    already visibility-filtered (`None` unless the caller holds
    `manage_fetchers`)."""

    disabled_at: datetime
    disabled_by: User | None
    enabled_at: datetime | None
    enabled_by: User | None


@dataclass(frozen=True)
class TimelinePoint:
    """One chart data point — a single `FetcherRun` record."""

    run_id: UUID
    timestamp: datetime
    duration_seconds: float | None
    items_succeeded: int
    items_created: int
    items_updated: int
    items_failed: int
    status: str


@dataclass(frozen=True)
class FetcherTimeline:
    points: list[TimelinePoint]
    disabled_periods: list[DisabledPeriod]


@dataclass(frozen=True)
class TriggerFetcherResult:
    """The outcome of a successful `trigger_fetcher()` call — the
    committed `queued` run's identifier and a human-readable
    confirmation message for the API response."""

    run_id: UUID
    message: str


@dataclass(frozen=True)
class FetcherConfigResult:
    """The merged configuration for one fetcher — persisted
    `FetcherConfig` values merged with code-defined registry metadata
    when the fetcher is registered. `default_schedule` and
    `settings_schema` are `None` for a deregistered fetcher (no code
    class to read them from)."""

    fetcher_name: str
    enabled: bool
    schedule_override: str | None
    default_schedule: str | None
    effective_schedule: str | None
    run_timeout: int
    request_delay: float
    custom_settings: dict[str, Any]
    settings_schema: dict[str, Any] | None
    updated_at: datetime


class MissingType:
    """Sentinel type for an omitted `UpdateConfigPayload` field.

    Distinguishes "field not provided" (this sentinel) from an
    explicit value — including `None` for the two fields where `None`
    is meaningful (`schedule_override` reverts to the fetcher's
    `default_schedule`; a `custom_settings` key set to `None` resets
    that key to its `Settings` field default). Conceptually mirrors
    `app.services.user_service._MissingType` (each service module
    defining its own sentinel is the established pattern — see
    `docs/features/identity/user-service.md`, `update_user()`, and
    `docs/conventions.md`'s reference to `dataclasses.MISSING`), but is
    public (no leading underscore): unlike `user_service._MissingType`,
    which is only ever referenced inside its own module, the API router
    (`app/api/v1/fetchers.py`) must reference this type directly to
    annotate the locals it builds from
    `FetcherConfigUpdateRequest.model_fields_set`.
    """

    def __repr__(self) -> str:
        return "UNSET"


UNSET: Any = MissingType()
"""Public singleton instance of `MissingType`, typed `Any` so it can be
assigned to any of `UpdateConfigPayload`'s per-field union types
without a mypy complaint at every call site."""


@dataclass(frozen=True)
class UpdateConfigPayload:
    """The set of changes requested via one `update_fetcher_config()`
    call — see `docs/features/platform/fetcher-operations.md`
    (`update_fetcher_config`, Q1). Each field defaults to `UNSET`
    (omitted — the corresponding `FetcherConfig` column is left
    untouched)."""

    enabled: bool | MissingType = UNSET
    schedule_override: str | MissingType | None = UNSET
    run_timeout: int | MissingType = UNSET
    request_delay: float | MissingType = UNSET
    custom_settings: dict[str, Any] | MissingType = UNSET


@dataclass(frozen=True)
class FetcherConfigPropagation:
    """Descriptor consumed by
    `fetcher_schedule.propagate_config_update()` after the API
    transaction dependency commits `update_fetcher_config()`'s
    mutation. Carries only primitive values — no ORM reference — so it
    remains valid across the commit boundary
    (`docs/conventions.md`, Transaction Hygiene Rules). See
    `docs/features/platform/fetcher-operations.md` (RedBeat
    Post-Commit Propagation) for the precedence
    `update_fetcher_config()` uses to decide `action`."""

    fetcher_name: str
    action: Literal["delete", "upsert"]
    schedule_override: str | None
    run_timeout: int


@dataclass(frozen=True)
class FetcherConfigMutationResult:
    """Result of `update_fetcher_config()`: the updated (or unchanged,
    for a no-op) config state, plus the post-commit RedBeat propagation
    descriptor — `None` when no schedule-affecting field actually
    changed."""

    config: FetcherConfigResult
    propagation: FetcherConfigPropagation | None


@dataclass(frozen=True)
class FetcherAuditEventPage:
    """One page of `FetcherAuditEvent` rows, with `actor` eagerly
    loaded on every item (see `list_fetcher_audit_events()`)."""

    items: list[FetcherAuditEvent]
    total: int
    page: int
    per_page: int


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _count_recognized_settings(
    fetcher_cls: type[BaseFetcher], custom_settings: dict[str, Any]
) -> int:
    """Number of `custom_settings` keys recognized by `fetcher_cls`'s
    current `Settings` schema. Orphaned keys (no longer declared) are
    excluded. `0` if the fetcher declares no `Settings` model."""
    settings_cls = fetcher_cls.Settings
    if settings_cls is None:
        return 0
    return sum(1 for key in custom_settings if key in settings_cls.model_fields)


def _build_config_result(
    config: FetcherConfig, fetcher_cls: type[BaseFetcher] | None
) -> FetcherConfigResult:
    """Merge a persisted `FetcherConfig` row with code-defined registry
    metadata — shared by `get_fetcher_config()` and
    `update_fetcher_config()` so both endpoints return an identical
    shape from a single implementation."""
    default_schedule: str | None
    effective_schedule: str | None
    settings_schema: dict[str, Any] | None

    if fetcher_cls is not None:
        default_schedule = fetcher_cls.default_schedule
        effective_schedule = config.schedule_override or default_schedule
        settings_schema = (
            fetcher_cls.Settings.model_json_schema()
            if fetcher_cls.Settings is not None
            else None
        )
    else:
        default_schedule = None
        effective_schedule = config.schedule_override
        settings_schema = None

    return FetcherConfigResult(
        fetcher_name=config.fetcher_name,
        enabled=config.enabled,
        schedule_override=config.schedule_override,
        default_schedule=default_schedule,
        effective_schedule=effective_schedule,
        run_timeout=config.run_timeout,
        request_delay=config.request_delay,
        custom_settings=config.custom_settings,
        settings_schema=settings_schema,
        updated_at=config.updated_at,
    )


def _stringify_standard_value(value: Any) -> str | None:
    """`str()` representation for a standard-field (`schedule_override`,
    `run_timeout`, `request_delay`) audit value — `None` (stored as SQL
    `NULL`) when the value itself is `None`, per
    `docs/features/platform/fetcher-operations.md` (`update_fetcher_config`,
    Audit value serialization)."""
    return None if value is None else str(value)


def _canonical_json_scalar(value: Any) -> str:
    """Canonical JSON scalar serialization for a non-null
    `custom_settings` audit value, per
    `docs/features/platform/fetcher-operations.md`
    (`update_fetcher_config`, Audit value serialization)."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _first_settings_error_message(exc: ValidationError) -> str:
    """Build a concise, user-facing message from a `Settings` model
    validation failure — one `field: message` entry per failing field,
    joined with `; `."""
    parts = [
        f"{'.'.join(str(part) for part in error['loc'])}: {error['msg']}"
        for error in exc.errors()
    ]
    return "; ".join(parts)


def _build_run_summary(
    run: FetcherRun, fallback_run_timeout: int, now: datetime, has_manage_fetchers: bool
) -> FetcherRunSummary:
    """Build a `FetcherRunSummary`, resolving `stale` via the shared
    `is_run_stale()` (`app.services.fetcher_execution`).

    `fallback_run_timeout` is the fetcher's current
    `FetcherConfig.run_timeout` (or the code-level default for an
    unbootstrapped registered fetcher) — used only when `run`'s own
    `hard_time_limit_seconds` is `NULL` (a historical row predating the
    column). See `resolve_effective_hard_limit()`.
    """
    return FetcherRunSummary(
        id=run.id,
        fetcher_name=run.fetcher_name,
        created_at=run.created_at,
        started_at=run.started_at,
        finished_at=run.finished_at,
        duration_seconds=run.duration_seconds,
        status=run.status,
        items_succeeded=run.items_succeeded,
        items_created=run.items_created,
        items_updated=run.items_updated,
        items_failed=run.items_failed,
        error_message=run.error_message,
        triggered_by=run.triggered_by,
        triggered_by_user=run.triggered_by_user if has_manage_fetchers else None,
        stale=is_run_stale(
            status=run.status,
            created_at=run.created_at,
            started_at=run.started_at,
            hard_time_limit_seconds=run.hard_time_limit_seconds,
            fallback_run_timeout=fallback_run_timeout,
            now=now,
        ),
    )


async def _ensure_fetcher_exists(db: AsyncSession, fetcher_name: str) -> None:
    """Validate that `fetcher_name` exists (registered or deregistered).

    A registered fetcher (`FETCHER_REGISTRY` membership) is always
    valid, even with no `FetcherConfig` row yet (bootstrap not run) —
    checked first since it requires no database query. Otherwise, a
    `FetcherConfig` row must exist (a deregistered fetcher whose config
    row survives its code removal). A name absent from both raises
    `FetcherNotFoundError`.

    Raises:
        FetcherNotFoundError: `fetcher_name` is neither registered nor
            has a `FetcherConfig` row.
    """
    if fetcher_name in FETCHER_REGISTRY:
        return
    result = await db.execute(
        select(FetcherConfig.fetcher_name).where(
            FetcherConfig.fetcher_name == fetcher_name
        )
    )
    if result.scalar_one_or_none() is None:
        raise FetcherNotFoundError()


async def _resolve_fallback_run_timeout(db: AsyncSession, fetcher_name: str) -> int:
    """Read `fetcher_name`'s current `FetcherConfig.run_timeout`, used
    as the stale-evaluation fallback for `running` rows whose own
    `hard_time_limit_seconds` is `NULL` (historical rows predating the
    column — see `resolve_effective_hard_limit()`).

    Assumes `fetcher_name` has already been validated to exist (see
    `_ensure_fetcher_exists`). A registered fetcher with no
    `FetcherConfig` row yet (bootstrap not run) has no live value —
    returns the code-level default (`_DEFAULT_RUN_TIMEOUT`).
    """
    result = await db.execute(
        select(FetcherConfig.run_timeout).where(
            FetcherConfig.fetcher_name == fetcher_name
        )
    )
    run_timeout = result.scalar_one_or_none()
    return run_timeout if run_timeout is not None else _DEFAULT_RUN_TIMEOUT


def _read_due_times(celery_app: Celery, names: list[str]) -> dict[str, datetime | None]:
    """Synchronous batch read of each `name`'s RedBeat `due_at`.

    Uses `RedBeatSchedulerEntry.generate_key()` + `.from_key()`
    exclusively — no raw Redis key is ever constructed (see
    `docs/conventions.md`, Redis Key Conventions). A missing entry
    (`KeyError`) yields `None` for that name only. Any `RedisError`
    propagates uncaught — the caller (`_resolve_next_run_times`)
    discards the entire partial batch and treats every requested name
    as `None` on that failure, per
    `docs/features/platform/fetcher-infrastructure.md` ("`next_run_at`
    Calculation", API endpoint failure handling).
    """
    result: dict[str, datetime | None] = {}
    for name in names:
        key = RedBeatSchedulerEntry.generate_key(celery_app, name)
        try:
            entry = RedBeatSchedulerEntry.from_key(key, app=celery_app)
        except KeyError:
            result[name] = None
            continue
        result[name] = entry.due_at
    return result


async def _resolve_next_run_times(
    celery_app: Celery, names: list[str]
) -> dict[str, datetime | None]:
    """Resolve `next_run_at` for every enabled, registered fetcher in
    `names`, offloading the synchronous RedBeat/Redis client to a
    worker thread so it never blocks the event loop.

    On any `RedisError`, logs one WARNING (no exception string, no
    Redis URL/credentials — only the exception type name) and returns
    `None` for every requested name, discarding any partial results
    already read within the same batch.
    """
    if not names:
        return {}
    try:
        return await asyncio.to_thread(_read_due_times, celery_app, names)
    except RedisError as exc:
        logger.warning(
            "fetcher_redbeat_next_run_unavailable", error_type=type(exc).__name__
        )
        return dict.fromkeys(names, None)


async def _resolve_disabled_periods(
    db: AsyncSession,
    fetcher_name: str,
    from_date: datetime,
    to_date: datetime,
    has_manage_fetchers: bool,
) -> list[DisabledPeriod]:
    """Implements Disabled Period Derivation
    (`docs/features/platform/fetcher-operations.md`): pairs each
    `disabled` event with the next `enabled` event, keeps an unpaired
    trailing `disabled` open-ended, ignores a leading orphaned
    `enabled`, and keeps only intervals intersecting
    `[from_date, to_date]` without clipping their timestamps.

    Ordered `id ASC` (fixed — no client-controlled sort). `id` is a
    UUIDv7 value, so this is equivalent to `created_at ASC` with a
    deterministic tiebreak, in a single column.
    """
    result = await db.execute(
        select(FetcherAuditEvent)
        .where(
            FetcherAuditEvent.fetcher_name == fetcher_name,
            FetcherAuditEvent.event_type.in_(
                [
                    FetcherAuditEventType.DISABLED.value,
                    FetcherAuditEventType.ENABLED.value,
                ]
            ),
        )
        .options(selectinload(FetcherAuditEvent.actor))
        .order_by(FetcherAuditEvent.id.asc())
    )
    events = list(result.scalars().all())

    intervals: list[tuple[FetcherAuditEvent, FetcherAuditEvent | None]] = []
    pending_disabled: FetcherAuditEvent | None = None
    for event in events:
        if event.event_type == FetcherAuditEventType.DISABLED.value:
            if pending_disabled is None:
                pending_disabled = event
            # else: consecutive `disabled` events — the earliest opens
            # the interval, later ones are ignored.
        elif pending_disabled is not None:
            intervals.append((pending_disabled, event))
            pending_disabled = None
        # else: orphaned `enabled` (no preceding `disabled`) — ignored.
    if pending_disabled is not None:
        intervals.append((pending_disabled, None))

    periods: list[DisabledPeriod] = []
    for disabled_event, enabled_event in intervals:
        disabled_at = disabled_event.created_at
        enabled_at = enabled_event.created_at if enabled_event is not None else None
        intersects = disabled_at <= to_date and (
            enabled_at is None or enabled_at >= from_date
        )
        if not intersects:
            continue
        periods.append(
            DisabledPeriod(
                disabled_at=disabled_at,
                disabled_by=disabled_event.actor if has_manage_fetchers else None,
                enabled_at=enabled_at,
                enabled_by=(
                    enabled_event.actor
                    if enabled_event is not None and has_manage_fetchers
                    else None
                ),
            )
        )
    return periods


# ---------------------------------------------------------------------------
# Public functions
# ---------------------------------------------------------------------------


async def list_fetchers(
    db: AsyncSession,
    *,
    has_manage_fetchers: bool,
    celery_app: Celery,
) -> list[FetcherListItem]:
    """List every fetcher — registered and deregistered — merged with
    its latest run and, for enabled registered fetchers, its next
    scheduled run time.

    See `docs/features/platform/fetcher-operations.md` (`list_fetchers`)
    for the full algorithm. Always succeeds — Redis unavailability
    degrades `next_run_at` to `null` for all fetchers rather than
    raising.
    """
    now = datetime.now(UTC)

    configs_result = await db.execute(select(FetcherConfig))
    configs_by_name = {c.fetcher_name: c for c in configs_result.scalars().all()}

    all_names = sorted(set(FETCHER_REGISTRY) | set(configs_by_name))

    last_run_result = await db.execute(
        select(FetcherRun)
        .distinct(FetcherRun.fetcher_name)
        .order_by(
            FetcherRun.fetcher_name,
            FetcherRun.created_at.desc(),
            FetcherRun.id.desc(),
        )
        .options(selectinload(FetcherRun.triggered_by_user))
    )
    last_run_by_name = {
        run.fetcher_name: run for run in last_run_result.scalars().all()
    }

    enabled_registered_names = [
        name
        for name in all_names
        if name in FETCHER_REGISTRY
        and (configs_by_name.get(name) is None or configs_by_name[name].enabled)
    ]
    next_run_by_name = await _resolve_next_run_times(
        celery_app, enabled_registered_names
    )

    items: list[FetcherListItem] = []
    for name in all_names:
        fetcher_cls = FETCHER_REGISTRY.get(name)
        config = configs_by_name.get(name)

        description: str | None
        default_schedule: str | None
        cve_source_type: str | None
        effective_schedule: str | None
        schedule_is_override: bool | None
        next_run_at: datetime | None

        if fetcher_cls is not None:
            description = fetcher_cls.description
            default_schedule = fetcher_cls.default_schedule
            cve_source_type = getattr(fetcher_cls, "cve_source_type", None)
            if config is not None:
                enabled = config.enabled
                effective_schedule = config.schedule_override or default_schedule
                schedule_is_override = config.schedule_override is not None
                custom_settings_count = _count_recognized_settings(
                    fetcher_cls, config.custom_settings
                )
                fallback_run_timeout = config.run_timeout
            else:
                enabled = True
                effective_schedule = default_schedule
                schedule_is_override = False
                custom_settings_count = 0
                fallback_run_timeout = _DEFAULT_RUN_TIMEOUT
            next_run_at = next_run_by_name.get(name) if enabled else None
        else:
            assert config is not None  # deregistered: a FetcherConfig row must exist
            description = None
            default_schedule = None
            cve_source_type = None
            enabled = config.enabled
            effective_schedule = config.schedule_override
            schedule_is_override = None
            custom_settings_count = len(config.custom_settings)
            fallback_run_timeout = config.run_timeout
            next_run_at = None

        run = last_run_by_name.get(name)
        last_run_summary = (
            _build_run_summary(run, fallback_run_timeout, now, has_manage_fetchers)
            if run is not None
            else None
        )

        items.append(
            FetcherListItem(
                fetcher_name=name,
                registered=fetcher_cls is not None,
                description=description,
                enabled=enabled,
                effective_schedule=effective_schedule,
                schedule_is_override=schedule_is_override,
                default_schedule=default_schedule,
                cve_source_type=cve_source_type,
                next_run_at=next_run_at,
                custom_settings_count=custom_settings_count,
                last_run=last_run_summary,
            )
        )
    return items


async def list_fetcher_runs(
    db: AsyncSession,
    *,
    fetcher_name: str,
    has_manage_fetchers: bool,
    page: int,
    per_page: int,
    status: str | None = None,
    from_date: date | datetime | None = None,
    to_date: date | datetime | None = None,
) -> FetcherRunPage:
    """Return one page of `FetcherRun` rows for `fetcher_name`.

    See `docs/features/platform/fetcher-operations.md`
    (`list_fetcher_runs`) for the full contract. `status`, when
    provided, is validated against `FetcherRunStatus` here (after the
    existence check) — an invalid value yields an empty page rather
    than a database query, per `docs/api-spec.md` (Enum Filter
    Validation). This mirrors the router-level `_parse_event_types`
    pattern used by other list endpoints, but is performed inside this
    function specifically so the fetcher-existence check always
    precedes it (a nonexistent fetcher must still raise
    `FetcherNotFoundError` regardless of the `status` value).

    Raises:
        FetcherNotFoundError: `fetcher_name` is neither in the registry
            nor has a `FetcherConfig` row.
    """
    await _ensure_fetcher_exists(db, fetcher_name)
    fallback_run_timeout = await _resolve_fallback_run_timeout(db, fetcher_name)

    if status is not None:
        try:
            FetcherRunStatus(status)
        except ValueError:
            return FetcherRunPage(items=[], total=0, page=page, per_page=per_page)

    filters = [FetcherRun.fetcher_name == fetcher_name]
    if status is not None:
        filters.append(FetcherRun.status == status)
    if from_date is not None:
        lower = normalize_date_bound(from_date, end_of_day=False)
        filters.append(FetcherRun.created_at >= lower)
    if to_date is not None:
        upper = normalize_date_bound(to_date, end_of_day=True)
        filters.append(FetcherRun.created_at <= upper)

    count_query = select(func.count()).select_from(FetcherRun).where(*filters)
    total = (await db.execute(count_query)).scalar_one()

    data_query = (
        select(FetcherRun)
        .where(*filters)
        .options(selectinload(FetcherRun.triggered_by_user))
        .order_by(FetcherRun.created_at.desc(), FetcherRun.id.desc())
        .offset((page - 1) * per_page)
        .limit(per_page)
    )
    runs = list((await db.execute(data_query)).scalars().all())
    now = datetime.now(UTC)
    items = [
        _build_run_summary(run, fallback_run_timeout, now, has_manage_fetchers)
        for run in runs
    ]
    return FetcherRunPage(items=items, total=total, page=page, per_page=per_page)


async def get_fetcher_run(
    db: AsyncSession,
    *,
    fetcher_name: str,
    run_id: UUID,
    has_manage_fetchers: bool,
) -> FetcherRunDetail:
    """Return full detail for one `FetcherRun`.

    `error_detail`/`error_traceback` are always populated with the raw
    stored values on the returned object — the caller (API router)
    decides whether to surface them in the HTTP response using the same
    `has_manage_fetchers` value passed in here, per
    `docs/features/platform/fetcher-operations.md` (Get Fetcher Run
    Detail, Fields: "absent from the response body", a presentation
    concern resolved at the schema/serialization layer).

    Raises:
        FetcherNotFoundError: `fetcher_name` is unknown.
        FetcherRunNotFoundError: `run_id` does not exist or belongs to
            a different fetcher.
    """
    await _ensure_fetcher_exists(db, fetcher_name)
    fallback_run_timeout = await _resolve_fallback_run_timeout(db, fetcher_name)

    result = await db.execute(
        select(FetcherRun)
        .where(FetcherRun.id == run_id, FetcherRun.fetcher_name == fetcher_name)
        .options(selectinload(FetcherRun.triggered_by_user))
    )
    run = result.scalar_one_or_none()
    if run is None:
        raise FetcherRunNotFoundError()

    now = datetime.now(UTC)
    return FetcherRunDetail(
        id=run.id,
        fetcher_name=run.fetcher_name,
        created_at=run.created_at,
        started_at=run.started_at,
        finished_at=run.finished_at,
        duration_seconds=run.duration_seconds,
        status=run.status,
        items_succeeded=run.items_succeeded,
        items_created=run.items_created,
        items_updated=run.items_updated,
        items_failed=run.items_failed,
        error_message=run.error_message,
        triggered_by=run.triggered_by,
        triggered_by_user=run.triggered_by_user if has_manage_fetchers else None,
        stale=is_run_stale(
            status=run.status,
            created_at=run.created_at,
            started_at=run.started_at,
            hard_time_limit_seconds=run.hard_time_limit_seconds,
            fallback_run_timeout=fallback_run_timeout,
            now=now,
        ),
        error_detail=run.error_detail,
        error_traceback=run.error_traceback,
    )


async def get_fetcher_timeline(
    db: AsyncSession,
    *,
    fetcher_name: str,
    has_manage_fetchers: bool,
    from_date: datetime,
    to_date: datetime,
) -> FetcherTimeline:
    """Return time-series run data and disabled periods for chart
    rendering.

    See `docs/features/platform/fetcher-operations.md`
    (`get_fetcher_timeline`, Disabled Period Derivation) for the full
    contract. `from_date`/`to_date` are already resolved (defaults
    applied, normalized to UTC) by the API layer — the
    `DATE_RANGE_TOO_WIDE` (1825-day maximum) check is also performed
    there, before this function is called.

    Raises:
        FetcherNotFoundError: `fetcher_name` is unknown.
    """
    await _ensure_fetcher_exists(db, fetcher_name)

    runs_result = await db.execute(
        select(FetcherRun)
        .where(
            FetcherRun.fetcher_name == fetcher_name,
            FetcherRun.created_at >= from_date,
            FetcherRun.created_at <= to_date,
        )
        .order_by(FetcherRun.created_at.asc(), FetcherRun.id.asc())
    )
    points = [
        TimelinePoint(
            run_id=run.id,
            timestamp=run.created_at,
            duration_seconds=run.duration_seconds,
            items_succeeded=run.items_succeeded,
            items_created=run.items_created,
            items_updated=run.items_updated,
            items_failed=run.items_failed,
            status=run.status,
        )
        for run in runs_result.scalars().all()
    ]

    disabled_periods = await _resolve_disabled_periods(
        db, fetcher_name, from_date, to_date, has_manage_fetchers
    )
    return FetcherTimeline(points=points, disabled_periods=disabled_periods)


async def get_fetcher_config(
    db: AsyncSession,
    *,
    fetcher_name: str,
) -> FetcherConfigResult:
    """Return the merged configuration for `fetcher_name`.

    See `docs/features/platform/fetcher-operations.md`
    (`get_fetcher_config`) for the full contract. Unlike the Public read
    functions above, a `FetcherConfig` row is a hard prerequisite here —
    a registered fetcher with no row yet (bootstrap not run) raises
    `FetcherNotFoundError`, consistent with `trigger_fetcher` and
    `update_fetcher_config`.

    Raises:
        FetcherNotFoundError: no `FetcherConfig` row exists for
            `fetcher_name`.
    """
    result = await db.execute(
        select(FetcherConfig).where(FetcherConfig.fetcher_name == fetcher_name)
    )
    config = result.scalar_one_or_none()
    if config is None:
        raise FetcherNotFoundError()

    fetcher_cls = FETCHER_REGISTRY.get(fetcher_name)
    return _build_config_result(config, fetcher_cls)


async def update_fetcher_config(
    db: AsyncSession,
    *,
    fetcher_name: str,
    user_id: UUID,
    payload: UpdateConfigPayload,
) -> FetcherConfigMutationResult:
    """Atomically apply `payload`'s changes to `fetcher_name`'s
    `FetcherConfig` row, audit every actually-changed field, and
    compute the RedBeat propagation the caller must perform after
    commit.

    See `docs/features/platform/fetcher-operations.md`
    (`update_fetcher_config`) for the full specification this function
    implements — this docstring summarizes it, the spec is
    authoritative.

    Q2 (guards, evaluated in this order after the row lock):
    1. `FetcherNotFoundError` — no `FetcherConfig` row for
       `fetcher_name`.
    2. `FetcherDeregisteredError` — the row exists but `fetcher_name`
       is not in `FETCHER_REGISTRY`.
    3. `FetcherAlreadyRunningError` — `payload.run_timeout` is provided,
       differs from the current value, and a non-stale active
       (`queued` or `running`) run exists (a stale one is finalized
       in-place via `fetcher_execution.mark_queued_run_stale()` or
       `mark_run_stale()`, matching the row's own status, and the PATCH
       proceeds).
    4. `FetcherSettingUnknownError` — a `payload.custom_settings` key is
       not declared in the fetcher's `Settings` model.
    5. `FetcherSettingInvalidError` — the merged candidate
       `custom_settings` state fails `Settings` model validation. The
       **entire** merged state (current stored values overlaid with
       `payload.custom_settings`) is validated, mirroring the same
       `Settings` model instantiation `BaseFetcher.run()` performs at
       the start of every run (fetcher-infrastructure.md, "Runtime
       validation of stored values") — this guarantees a PATCH never
       leaves `custom_settings` in a state that would fail at the next
       run. A pre-existing stored value that predates a `Settings`
       model constraint tightening can therefore block an otherwise
       unrelated field change until it is also corrected (explicitly,
       or via `null` reset) in the same PATCH.

    Q3 (behavior): for each of `enabled`, `schedule_override`,
    `run_timeout`, `request_delay` present in `payload` (not `UNSET`),
    compare against the current persisted value; only actually-changed
    fields are applied. For `custom_settings`, each non-null submitted
    key is validated then **canonicalized**: the persisted value, the
    no-op comparison, and the audit `new_value` all use the canonical
    value produced by the validated `Settings` model
    (`model_dump(mode="json")`) for that key — never the raw payload
    value (`docs/features/platform/fetcher-operations.md`,
    `update_fetcher_config`, step 6, Custom settings canonicalization).
    The audit `old_value` is the previously stored value, which is
    already canonical since every prior write persisted the canonical
    form. A key set to `None` is removed (reset to default). Keys
    omitted from `payload.custom_settings` and orphaned keys already
    stored are never touched. If no field actually changed, the
    function is a no-op: no mutation, no audit event, `updated_at`
    unchanged (no `UPDATE` is ever issued), and `propagation=None`.

    Q4 (audit events): one `FetcherAuditEvent` per actually-changed
    field, created via `FetcherAuditLog.log_event()`, in this order:
    `enabled` (event type `enabled`/`disabled`, no payload) →
    `schedule_override` → `run_timeout` → `request_delay` (all three:
    event type `config_changed`, `detail={"field": <name>}`,
    `old_value`/`new_value` as `str()` or `None`) → custom setting keys
    in alphabetical order (event type `config_changed`,
    `detail={"field": "custom_settings", "key": <key>}`,
    `old_value`/`new_value` as canonical JSON scalars or `None`). All
    events share this call's `user_id` and transaction timestamp.

    Q5 (re-invocation): conditionally idempotent — re-submitting a
    payload whose values already match the current persisted (and, for
    `custom_settings`, canonicalized) state is a no-op. A payload that
    still differs creates new audit events on every call.

    Q6 (exceptions): `FetcherNotFoundError`, `FetcherDeregisteredError`,
    `FetcherAlreadyRunningError`, `FetcherSettingUnknownError`,
    `FetcherSettingInvalidError`.

    Accepts a caller-supplied `AsyncSession` (caller-owned transaction):
    flushes without committing or rolling back
    (`docs/conventions.md`, Caller-Owned Service Transactions). Locks
    the `FetcherConfig` row (`SELECT ... FOR UPDATE`) as the first
    database operation (`docs/conventions.md`, Pessimistic Locking
    Pattern). Performs no network I/O — the returned
    `FetcherConfigPropagation` describes the RedBeat write the caller
    must perform strictly after commit
    (`docs/conventions.md`, Transaction Hygiene Rules).
    """
    now = datetime.now(UTC)

    result = await db.execute(
        select(FetcherConfig)
        .where(FetcherConfig.fetcher_name == fetcher_name)
        .with_for_update()
    )
    config = result.scalar_one_or_none()
    if config is None:
        raise FetcherNotFoundError()

    fetcher_cls = FETCHER_REGISTRY.get(fetcher_name)
    if fetcher_cls is None:
        raise FetcherDeregisteredError()

    enabled = payload.enabled
    schedule_override = payload.schedule_override
    run_timeout = payload.run_timeout
    request_delay = payload.request_delay
    custom_settings = payload.custom_settings

    # --- Guard 3: Run Timeout Active Guard --------------------------------
    # Covers both active statuses (`queued` and `running`), not `running`
    # alone — see docs/features/platform/fetcher-infrastructure.md
    # (Stale Run Detection, Running Stale Threshold, "Relationship to
    # hard time limit") for why a `run_timeout` change must not be
    # allowed while a manual run is still `queued`.
    if not isinstance(run_timeout, MissingType) and run_timeout != config.run_timeout:
        active_result = await db.execute(
            select(FetcherRun).where(
                FetcherRun.fetcher_name == fetcher_name,
                FetcherRun.status.in_(
                    [FetcherRunStatus.QUEUED.value, FetcherRunStatus.RUNNING.value]
                ),
            )
        )
        active_run = active_result.scalar_one_or_none()
        if active_run is not None:
            if is_run_stale(
                status=active_run.status,
                created_at=active_run.created_at,
                started_at=active_run.started_at,
                hard_time_limit_seconds=active_run.hard_time_limit_seconds,
                fallback_run_timeout=config.run_timeout,
                now=now,
            ):
                if active_run.status == FetcherRunStatus.QUEUED.value:
                    mark_queued_run_stale(
                        active_run, now=now, fetcher_name=fetcher_name
                    )
                else:
                    mark_run_stale(
                        active_run,
                        now=now,
                        hard_time_limit_seconds=resolve_effective_hard_limit(
                            active_run.hard_time_limit_seconds, config.run_timeout
                        ),
                        fetcher_name=fetcher_name,
                    )
            else:
                raise FetcherAlreadyRunningError()

    # --- Guards 4-5: custom_settings validation and canonicalization -----
    canonical_changes: dict[str, Any | None] = {}
    if not isinstance(custom_settings, MissingType):
        settings_cls = fetcher_cls.Settings
        declared_fields = settings_cls.model_fields if settings_cls is not None else {}
        for key in custom_settings:
            if key not in declared_fields:
                raise FetcherSettingUnknownError(key)

        if settings_cls is not None and custom_settings:
            candidate = dict(config.custom_settings)
            for key, value in custom_settings.items():
                if value is None:
                    candidate.pop(key, None)
                else:
                    candidate[key] = value
            try:
                validated = settings_cls.model_validate(candidate)
            except ValidationError as exc:
                raise FetcherSettingInvalidError(
                    _first_settings_error_message(exc)
                ) from exc
            dumped = validated.model_dump(mode="json")
            for key, value in custom_settings.items():
                canonical_changes[key] = None if value is None else dumped[key]

    # --- Compute diff: standard fields -------------------------------------
    changes: list[tuple[str, Any, Any]] = []
    if not isinstance(enabled, MissingType) and enabled != config.enabled:
        changes.append(("enabled", config.enabled, enabled))
    if (
        not isinstance(schedule_override, MissingType)
        and schedule_override != config.schedule_override
    ):
        changes.append(
            ("schedule_override", config.schedule_override, schedule_override)
        )
    if not isinstance(run_timeout, MissingType) and run_timeout != config.run_timeout:
        changes.append(("run_timeout", config.run_timeout, run_timeout))
    if (
        not isinstance(request_delay, MissingType)
        and request_delay != config.request_delay
    ):
        changes.append(("request_delay", config.request_delay, request_delay))

    # --- Compute diff: custom settings (alphabetical) ----------------------
    custom_changes: list[tuple[str, Any, Any]] = []
    for key in sorted(canonical_changes):
        new_value = canonical_changes[key]
        old_value = config.custom_settings.get(key)
        if new_value != old_value:
            custom_changes.append((key, old_value, new_value))

    if not changes and not custom_changes:
        return FetcherConfigMutationResult(
            config=_build_config_result(config, fetcher_cls), propagation=None
        )

    # --- Mutate -------------------------------------------------------------
    for field, _old, new in changes:
        setattr(config, field, new)

    if custom_changes:
        updated_custom = dict(config.custom_settings)
        for key, _old, new in custom_changes:
            if new is None:
                updated_custom.pop(key, None)
            else:
                updated_custom[key] = new
        config.custom_settings = updated_custom

    # --- Audit events (deterministic order) ---------------------------------
    for field, old, new in changes:
        if field == "enabled":
            await FetcherAuditLog.log_event(
                db,
                event_type=(
                    FetcherAuditEventType.ENABLED
                    if new
                    else FetcherAuditEventType.DISABLED
                ),
                fetcher_name=fetcher_name,
                user_id=user_id,
            )
        else:
            await FetcherAuditLog.log_event(
                db,
                event_type=FetcherAuditEventType.CONFIG_CHANGED,
                fetcher_name=fetcher_name,
                user_id=user_id,
                old_value=_stringify_standard_value(old),
                new_value=_stringify_standard_value(new),
                detail={"field": field},
            )
    for key, old, new in custom_changes:
        await FetcherAuditLog.log_event(
            db,
            event_type=FetcherAuditEventType.CONFIG_CHANGED,
            fetcher_name=fetcher_name,
            user_id=user_id,
            old_value=_canonical_json_scalar(old) if old is not None else None,
            new_value=_canonical_json_scalar(new) if new is not None else None,
            detail={"field": "custom_settings", "key": key},
        )

    await db.flush()
    # `updated_at` is a server-computed `onupdate=func.now()` value —
    # SQLAlchemy does not include it in `RETURNING` for an UPDATE (only
    # for INSERT), so after the flush above the in-memory attribute is
    # expired. An implicit lazy-reload of an expired attribute is
    # synchronous and unsupported under `AsyncSession`/asyncpg (raises
    # `MissingGreenlet`); refreshing it explicitly here is the async-safe
    # equivalent, and only costs a query on the branch that actually
    # mutated something.
    await db.refresh(config, attribute_names=["updated_at"])

    return FetcherConfigMutationResult(
        config=_build_config_result(config, fetcher_cls),
        propagation=_build_propagation(fetcher_name, changes, config),
    )


def _build_propagation(
    fetcher_name: str, changes: list[tuple[str, Any, Any]], config: FetcherConfig
) -> FetcherConfigPropagation | None:
    """Compute the RedBeat propagation descriptor per the precedence in
    `docs/features/platform/fetcher-operations.md` (RedBeat Post-Commit
    Propagation). `config` reflects the already-applied, not-yet-committed
    mutation — its `.enabled`/`.schedule_override`/`.run_timeout` are the
    effective post-PATCH values."""
    changed_fields = {field for field, _old, _new in changes}

    if "enabled" in changed_fields:
        if not config.enabled:
            return FetcherConfigPropagation(
                fetcher_name=fetcher_name,
                action="delete",
                schedule_override=None,
                run_timeout=0,
            )
        return FetcherConfigPropagation(
            fetcher_name=fetcher_name,
            action="upsert",
            schedule_override=config.schedule_override,
            run_timeout=config.run_timeout,
        )

    if (
        "schedule_override" in changed_fields or "run_timeout" in changed_fields
    ) and config.enabled:
        return FetcherConfigPropagation(
            fetcher_name=fetcher_name,
            action="upsert",
            schedule_override=config.schedule_override,
            run_timeout=config.run_timeout,
        )

    return None


async def list_fetcher_audit_events(
    db: AsyncSession,
    *,
    fetcher_name: str,
    page: int,
    per_page: int,
    event_type: list[str] | None = None,
    actor: str | None = None,
    from_date: date | datetime | None = None,
    to_date: date | datetime | None = None,
) -> FetcherAuditEventPage:
    """Return one page of `FetcherAuditEvent` rows for `fetcher_name`.

    See `docs/features/platform/fetcher-operations.md`
    (`list_fetcher_audit_events`) for the full contract. `event_type`,
    when provided, is validated against `FetcherAuditEventType` here —
    after the fetcher-existence check — per `docs/api-spec.md` (Enum
    Filter Validation): an invalid value is dropped from the filter
    set, and an entirely invalid set yields an empty page rather than a
    database query. This mirrors `list_fetcher_runs`'s `status`
    handling: the fetcher-existence check always precedes it, so a
    nonexistent fetcher still raises `FetcherNotFoundError` regardless
    of the `event_type` values supplied.

    `actor` and the date bounds are applied via the shared
    `FetcherAuditLog.filter_by_actor()` / `.apply_date_filters()`
    helpers (`docs/features/platform/audit-trail-infrastructure.md`):
    an unmatched UUID/username or the literal `"system"` yields an
    empty page, never an error — every fetcher audit event has a human
    actor, so `"system"` never matches.

    Raises:
        FetcherNotFoundError: `fetcher_name` is neither in the registry
            nor has a `FetcherConfig` row.
    """
    await _ensure_fetcher_exists(db, fetcher_name)

    valid_event_types: list[str] = []
    if event_type:
        for value in event_type:
            try:
                valid_event_types.append(FetcherAuditEventType(value).value)
            except ValueError:
                continue
        if not valid_event_types:
            return FetcherAuditEventPage(
                items=[], total=0, page=page, per_page=per_page
            )

    filters = [FetcherAuditEvent.fetcher_name == fetcher_name]
    if valid_event_types:
        filters.append(FetcherAuditEvent.event_type.in_(valid_event_types))

    base_query = select(FetcherAuditEvent).where(*filters)
    count_query = select(func.count()).select_from(FetcherAuditEvent).where(*filters)

    base_query = FetcherAuditLog.filter_by_actor(base_query, actor)
    count_query = FetcherAuditLog.filter_by_actor(count_query, actor)

    base_query = FetcherAuditLog.apply_date_filters(base_query, from_date, to_date)
    count_query = FetcherAuditLog.apply_date_filters(count_query, from_date, to_date)

    total = (await db.execute(count_query)).scalar_one()

    data_query = (
        base_query.options(selectinload(FetcherAuditEvent.actor))
        .order_by(FetcherAuditEvent.id.desc())
        .offset((page - 1) * per_page)
        .limit(per_page)
    )
    items = list((await db.execute(data_query)).scalars().all())
    return FetcherAuditEventPage(items=items, total=total, page=page, per_page=per_page)


async def trigger_fetcher(
    fetcher_name: str,
    *,
    user_id: UUID,
    session_factory: async_sessionmaker[AsyncSession],
    celery_app: Celery,
) -> TriggerFetcherResult:
    """Create a `queued` manual `FetcherRun`, commit it, and publish it
    to Celery.

    See `docs/features/platform/fetcher-operations.md` (`trigger_fetcher`)
    for the full specification this function implements — this
    docstring summarizes it, the spec is authoritative.

    Unlike every other function in this module, `trigger_fetcher` does
    NOT accept a caller-supplied `AsyncSession`. It is a service-owned
    orchestration boundary: it opens and commits its own short-lived
    sessions from `session_factory`, and publishes to Celery strictly
    after the first transaction commits and its `FetcherConfig` lock is
    released (`docs/conventions.md`, Transaction Hygiene Rules — no
    network I/O while a row lock is held). `celery_app` identifies the
    Celery application whose `"run_fetcher"` task is published to via
    `send_task()` (by name — not the decorated task object, which
    lives in `app.tasks` and is not importable from this layer per
    `docs/architecture.md`, Backend Layer Architecture); passed
    explicitly, mirroring `list_fetchers`, so tests can substitute an
    isolated Celery/Redis instance instead of the production singleton.
    `ignore_result=True` is passed explicitly to `send_task()` — unlike
    `apply_async()`, `send_task()` does not inherit the task's own
    `ignore_result` default, so this makes explicit at the call site
    the app-wide `task_ignore_result = True` / no-result-backend
    contract already established in
    `docs/features/platform/fetcher-infrastructure.md` (Result
    handling).

    Q2 (guards, evaluated in this order under the `FetcherConfig`
    lock):
    1. `FetcherNotFoundError` — no `FetcherConfig` row for
       `fetcher_name` (whether or not it is registered — a
       `FetcherConfig` row is a bootstrap prerequisite for triggering).
    2. `FetcherDeregisteredError` — the row exists but `fetcher_name` is
       not in `FETCHER_REGISTRY`.
    3. `FetcherDisabledError` — `FetcherConfig.enabled` is `false`.
    4. `FetcherAlreadyRunningError` — a non-stale active (`queued` or
       `running`) `FetcherRun` exists (a stale one is finalized
       in-place under the same lock, matching its own status, and the
       new run proceeds).

    Q4 (audit events): one `FetcherAuditEvent` (`triggered`, no
    payload), created in the first transaction — retained regardless of
    the Celery publication outcome.

    Q5 (re-invocation): NOT idempotent — each call creates a new
    `FetcherRun` and audit event (guards permitting).

    Q6 (exceptions): `FetcherNotFoundError`, `FetcherDeregisteredError`,
    `FetcherDisabledError`, `FetcherAlreadyRunningError`,
    `FetcherBrokerUnavailableError`.
    """
    now = datetime.now(UTC)

    async with session_factory() as session:
        try:
            result = await session.execute(
                select(FetcherConfig)
                .where(FetcherConfig.fetcher_name == fetcher_name)
                .with_for_update()
            )
            config = result.scalar_one_or_none()
            if config is None:
                raise FetcherNotFoundError()

            fetcher_cls = FETCHER_REGISTRY.get(fetcher_name)
            if fetcher_cls is None:
                raise FetcherDeregisteredError()

            if not config.enabled:
                raise FetcherDisabledError()

            active_result = await session.execute(
                select(FetcherRun).where(
                    FetcherRun.fetcher_name == fetcher_name,
                    FetcherRun.status.in_(
                        [
                            FetcherRunStatus.QUEUED.value,
                            FetcherRunStatus.RUNNING.value,
                        ]
                    ),
                )
            )
            active_run = active_result.scalar_one_or_none()
            if active_run is not None:
                if is_run_stale(
                    status=active_run.status,
                    created_at=active_run.created_at,
                    started_at=active_run.started_at,
                    hard_time_limit_seconds=active_run.hard_time_limit_seconds,
                    fallback_run_timeout=config.run_timeout,
                    now=now,
                ):
                    if active_run.status == FetcherRunStatus.QUEUED.value:
                        mark_queued_run_stale(
                            active_run, now=now, fetcher_name=fetcher_name
                        )
                    else:
                        mark_run_stale(
                            active_run,
                            now=now,
                            hard_time_limit_seconds=resolve_effective_hard_limit(
                                active_run.hard_time_limit_seconds,
                                config.run_timeout,
                            ),
                            fetcher_name=fetcher_name,
                        )
                else:
                    raise FetcherAlreadyRunningError()

            new_run = FetcherRun(
                fetcher_name=fetcher_name,
                status=FetcherRunStatus.QUEUED.value,
                triggered_by=FetcherRunTriggeredBy.MANUAL.value,
                triggered_by_user_id=user_id,
            )
            session.add(new_run)
            await session.flush()

            await FetcherAuditLog.log_event(
                session,
                event_type=FetcherAuditEventType.TRIGGERED,
                fetcher_name=fetcher_name,
                user_id=user_id,
            )

            run_id = new_run.id
            run_timeout = config.run_timeout
            queue = fetcher_cls.queue

            await session.commit()
        except Exception:
            await session.rollback()
            raise

    task_options: dict[str, Any] = dict(effective_task_time_limits(run_timeout))
    if queue is not None:
        task_options["queue"] = queue

    try:
        await asyncio.to_thread(
            celery_app.send_task,
            "run_fetcher",
            kwargs={
                "fetcher_name": fetcher_name,
                "triggered_by": FetcherRunTriggeredBy.MANUAL.value,
                "user_id": str(user_id),
                "run_id": str(run_id),
            },
            ignore_result=True,
            **task_options,
        )
    except Exception as exc:
        logger.warning(
            "fetcher_manual_trigger_publish_failed",
            fetcher_name=fetcher_name,
            run_id=str(run_id),
            error_type=type(exc).__name__,
        )
        async with session_factory() as session:
            try:
                compensation_won = await finalize_manual_run_as_failure(
                    session,
                    run_id=run_id,
                    fetcher_name=fetcher_name,
                    error_message=_BROKER_PUBLICATION_FAILURE_MESSAGE,
                    now=datetime.now(UTC),
                    error_detail=type(exc).__name__,
                    error_traceback=None,
                )
                await session.commit()
            except Exception:
                await session.rollback()
                raise
        if not compensation_won:
            # Ambiguous Broker Acknowledgement, outcome 2 (worker wins):
            # the broker actually accepted the task despite the
            # exception raised here, and a worker adopted the run
            # before this compensation attempt executed. See
            # `docs/features/platform/fetcher-operations.md`
            # (`trigger_fetcher`, Ambiguous Broker Acknowledgement).
            logger.warning(
                "fetcher_manual_trigger_compensation_lost_to_adoption",
                fetcher_name=fetcher_name,
                run_id=str(run_id),
            )
        raise FetcherBrokerUnavailableError() from exc

    return TriggerFetcherResult(
        run_id=run_id,
        message=f"Fetcher '{fetcher_name}' has been queued for execution",
    )
