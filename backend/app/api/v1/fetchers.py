"""Fetcher observation and admin config/audit-log/trigger API endpoints.

See `docs/features/platform/fetcher-operations.md` (List Fetchers, List
Fetcher Runs, Get Fetcher Run Detail, Get Fetcher Run Timeline Data,
Trigger Fetcher, Get Fetcher Config, Update Fetcher Config, Get Fetcher
Audit Log) for the authoritative endpoint contracts this module
implements. Handlers stay thin: they validate, derive
`has_manage_fetchers` from the optional principal (Public endpoints) or
require the `manage_fetchers` capability outright (admin endpoints),
delegate to `app.services.fetcher_operations`, and map the result to
the documented response — no business logic or database query lives
here. `trigger_fetcher` is the sole exception to the `DatabaseSession`
pattern used by every other handler in this module — see
`get_fetcher_trigger_session_factory` below for why.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any
from uuid import UUID

import structlog
from fastapi import APIRouter, Depends, Query, status
from redis.exceptions import RedisError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.api.dependencies import (
    AuthenticatedPrincipal,
    OptionalCurrentUser,
    require_capability,
)
from app.celery_app import celery_app
from app.core.dates import (
    normalize_date_bound,
    parse_date_range_bound,
    validate_date_range_order,
)
from app.core.enums import Capability
from app.core.errors import AppError, ErrorCode
from app.core.permissions import get_capabilities
from app.database import (
    DatabaseSession,
    async_session_factory,
    register_post_commit_callback,
)
from app.models.fetcher_audit_event import FetcherAuditEvent
from app.schemas.common import PaginationMeta, UserReference
from app.schemas.fetcher import (
    FetcherAuditEventData,
    FetcherAuditListResponse,
    FetcherAuditQuery,
    FetcherConfigData,
    FetcherConfigResponse,
    FetcherConfigUpdateRequest,
    FetcherDisabledPeriodData,
    FetcherLastRunData,
    FetcherListItemData,
    FetcherListResponse,
    FetcherRunDetailData,
    FetcherRunDetailResponse,
    FetcherRunListItemData,
    FetcherRunListQuery,
    FetcherRunListResponse,
    FetcherTimelineData,
    FetcherTimelinePointData,
    FetcherTimelineQuery,
    FetcherTimelineResponse,
    FetcherTriggerData,
    FetcherTriggerResponse,
)
from app.services import fetcher_operations, fetcher_schedule, user_service
from app.services.fetcher_operations import (
    UNSET,
    FetcherAlreadyRunningError,
    FetcherBrokerUnavailableError,
    FetcherDeregisteredError,
    FetcherDisabledError,
    FetcherListItem,
    FetcherNotFoundError,
    FetcherRunNotFoundError,
    FetcherRunSummary,
    FetcherSettingInvalidError,
    FetcherSettingUnknownError,
    FetcherTimeline,
    MissingType,
    UpdateConfigPayload,
)

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/api/v1", tags=["Fetchers"])

# Maximum allowed interval between `from_date` and `to_date` for the
# timeline endpoint (see fetcher-operations.md, Get Fetcher Run
# Timeline Data, "Date range constraint").
_TIMELINE_MAX_SECONDS = 1825 * 86400
_TIMELINE_DEFAULT_LOOKBACK = timedelta(days=7)


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


async def _resolve_has_manage_fetchers(
    db: DatabaseSession, principal: OptionalCurrentUser
) -> bool:
    """Derive `has_manage_fetchers` per fetcher-operations.md (Access
    Control, `has_manage_fetchers` derivation): `False` for an
    anonymous caller, else whether the caller's current roles grant
    `manage_fetchers`. Never produces a 401/403 on these Public
    endpoints — it only controls field-level visibility."""
    if principal is None:
        return False
    roles = await user_service.get_user_roles(db, principal.user.id)
    return Capability.MANAGE_FETCHERS in get_capabilities(roles)


def _common_run_fields(run: FetcherRunSummary) -> dict[str, Any]:
    return {
        "id": run.id,
        "created_at": run.created_at,
        "started_at": run.started_at,
        "finished_at": run.finished_at,
        "duration_seconds": run.duration_seconds,
        "status": run.status,
        "items_succeeded": run.items_succeeded,
        "items_created": run.items_created,
        "items_updated": run.items_updated,
        "items_failed": run.items_failed,
        "triggered_by": run.triggered_by,
        "triggered_by_user": (
            UserReference.model_validate(run.triggered_by_user)
            if run.triggered_by_user is not None
            else None
        ),
        "error_message": run.error_message,
        "stale": run.stale,
    }


def _serialize_run_summary(run: FetcherRunSummary) -> FetcherLastRunData:
    return FetcherLastRunData(**_common_run_fields(run))


def _serialize_run_list_item(run: FetcherRunSummary) -> FetcherRunListItemData:
    return FetcherRunListItemData(
        fetcher_name=run.fetcher_name, **_common_run_fields(run)
    )


def _serialize_list_item(item: FetcherListItem) -> FetcherListItemData:
    return FetcherListItemData(
        fetcher_name=item.fetcher_name,
        registered=item.registered,
        description=item.description,
        enabled=item.enabled,
        effective_schedule=item.effective_schedule,
        schedule_is_override=item.schedule_is_override,
        default_schedule=item.default_schedule,
        cve_source_type=item.cve_source_type,
        next_run_at=item.next_run_at,
        custom_settings_count=item.custom_settings_count,
        last_run=_serialize_run_summary(item.last_run)
        if item.last_run is not None
        else None,
    )


def _serialize_timeline(timeline: FetcherTimeline) -> FetcherTimelineData:
    return FetcherTimelineData(
        points=[
            FetcherTimelinePointData(
                run_id=point.run_id,
                timestamp=point.timestamp,
                duration_seconds=point.duration_seconds,
                items_succeeded=point.items_succeeded,
                items_created=point.items_created,
                items_updated=point.items_updated,
                items_failed=point.items_failed,
                status=point.status,
            )
            for point in timeline.points
        ],
        disabled_periods=[
            FetcherDisabledPeriodData(
                disabled_at=period.disabled_at,
                disabled_by=(
                    UserReference.model_validate(period.disabled_by)
                    if period.disabled_by is not None
                    else None
                ),
                enabled_at=period.enabled_at,
                enabled_by=(
                    UserReference.model_validate(period.enabled_by)
                    if period.enabled_by is not None
                    else None
                ),
            )
            for period in timeline.disabled_periods
        ],
    )


def _not_found(exc: Exception) -> AppError:
    return AppError(
        status_code=status.HTTP_404_NOT_FOUND,
        code=ErrorCode.FETCHER_NOT_FOUND,
        detail=str(exc),
    )


def _deregistered(exc: Exception) -> AppError:
    return AppError(
        status_code=status.HTTP_409_CONFLICT,
        code=ErrorCode.FETCHER_DEREGISTERED,
        detail=str(exc),
    )


def _already_running(exc: Exception) -> AppError:
    return AppError(
        status_code=status.HTTP_409_CONFLICT,
        code=ErrorCode.FETCHER_ALREADY_RUNNING,
        detail=str(exc),
    )


def _disabled(exc: Exception) -> AppError:
    return AppError(
        status_code=status.HTTP_409_CONFLICT,
        code=ErrorCode.FETCHER_DISABLED,
        detail=str(exc),
    )


def _broker_unavailable(exc: Exception) -> AppError:
    return AppError(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        code=ErrorCode.CELERY_UNAVAILABLE,
        detail=str(exc),
    )


def _setting_unknown(exc: FetcherSettingUnknownError) -> AppError:
    return AppError(
        status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        code=ErrorCode.FETCHER_SETTING_UNKNOWN,
        detail=str(exc),
    )


def _setting_invalid(exc: FetcherSettingInvalidError) -> AppError:
    return AppError(
        status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        code=ErrorCode.FETCHER_SETTING_INVALID,
        detail=str(exc),
    )


def _serialize_config(
    config: fetcher_operations.FetcherConfigResult,
) -> FetcherConfigData:
    return FetcherConfigData(
        fetcher_name=config.fetcher_name,
        enabled=config.enabled,
        schedule_override=config.schedule_override,
        default_schedule=config.default_schedule,
        effective_schedule=config.effective_schedule,
        run_timeout=config.run_timeout,
        request_delay=config.request_delay,
        custom_settings=config.custom_settings,
        settings_schema=config.settings_schema,
        updated_at=config.updated_at,
    )


def _serialize_audit_event(event: FetcherAuditEvent) -> FetcherAuditEventData:
    return FetcherAuditEventData(
        id=event.id,
        fetcher_name=event.fetcher_name,
        event_type=event.event_type,
        actor=UserReference.model_validate(event.actor),
        old_value=event.old_value,
        new_value=event.new_value,
        detail=event.detail,
        created_at=event.created_at,
    )


# ---------------------------------------------------------------------------
# Query parameter builders
#
# Declared as individual `Query()`-annotated parameters (rather than a
# single `Annotated[Model, Query()]` query-parameter-model field) so
# each field is visible individually to the shared query-length-limit
# dependency's route-dependant walk (`app.core.query_limits`). Mirrors
# `app/api/v1/identity_audit.py` and `app/api/v1/settings.py`.
# ---------------------------------------------------------------------------


def _fetcher_run_list_query(
    *,
    status: Annotated[
        str | None,
        Query(
            description=(
                "Filter by run status (queued, running, success, failure, partial)."
            )
        ),
    ] = None,
    from_date: Annotated[
        str | None,
        Query(
            description="ISO 8601 date/datetime; inclusive lower bound on created_at."
        ),
    ] = None,
    to_date: Annotated[
        str | None,
        Query(
            description="ISO 8601 date/datetime; inclusive upper bound on created_at."
        ),
    ] = None,
    page: Annotated[int, Query(ge=1, le=2_147_483_647, description="Page number.")] = 1,
    per_page: Annotated[
        int, Query(ge=1, le=100, description="Items per page; maximum 100.")
    ] = 20,
) -> FetcherRunListQuery:
    parsed_from = parse_date_range_bound("from_date", from_date)
    parsed_to = parse_date_range_bound("to_date", to_date)
    validate_date_range_order(parsed_from, parsed_to)
    return FetcherRunListQuery(
        status=status,
        from_date=parsed_from,
        to_date=parsed_to,
        page=page,
        per_page=per_page,
    )


def _fetcher_timeline_query(
    *,
    from_date: Annotated[
        str | None,
        Query(
            description="ISO 8601 date/datetime; inclusive lower bound. Default: -7d."
        ),
    ] = None,
    to_date: Annotated[
        str | None,
        Query(
            description="ISO 8601 date/datetime; inclusive upper bound. Default: now."
        ),
    ] = None,
) -> FetcherTimelineQuery:
    parsed_from = parse_date_range_bound("from_date", from_date)
    parsed_to = parse_date_range_bound("to_date", to_date)
    validate_date_range_order(parsed_from, parsed_to)
    return FetcherTimelineQuery(from_date=parsed_from, to_date=parsed_to)


def _fetcher_audit_query(
    *,
    event_type: Annotated[
        list[str],
        Query(
            default_factory=list,
            description="Filter by event type. Repeatable; OR semantics.",
        ),
    ],
    actor: Annotated[
        str | None,
        Query(description="Actor UUID or exact username."),
    ] = None,
    from_date: Annotated[
        str | None,
        Query(description="ISO 8601 date/datetime; inclusive lower bound."),
    ] = None,
    to_date: Annotated[
        str | None,
        Query(description="ISO 8601 date/datetime; inclusive upper bound."),
    ] = None,
    page: Annotated[int, Query(ge=1, le=2_147_483_647, description="Page number.")] = 1,
    per_page: Annotated[
        int, Query(ge=1, le=100, description="Items per page; maximum 100.")
    ] = 20,
) -> FetcherAuditQuery:
    parsed_from = parse_date_range_bound("from_date", from_date)
    parsed_to = parse_date_range_bound("to_date", to_date)
    validate_date_range_order(parsed_from, parsed_to)
    return FetcherAuditQuery(
        event_type=event_type,
        actor=actor,
        from_date=parsed_from,
        to_date=parsed_to,
        page=page,
        per_page=per_page,
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get(
    "/fetchers",
    response_model=FetcherListResponse,
    summary="List all fetchers",
    description=(
        "Returns every fetcher — registered and deregistered — merged with "
        "its latest run and, for enabled registered fetchers, its next "
        "scheduled run time. Optional authentication: anonymous callers "
        "see sanitized fields only; callers with manage_fetchers "
        "additionally see the manual-trigger actor."
    ),
)
async def list_fetchers(
    principal: OptionalCurrentUser,
    db: DatabaseSession,
) -> FetcherListResponse:
    """List all fetchers — see
    `docs/features/platform/fetcher-operations.md` (List Fetchers)."""
    has_manage_fetchers = await _resolve_has_manage_fetchers(db, principal)
    items = await fetcher_operations.list_fetchers(
        db, has_manage_fetchers=has_manage_fetchers, celery_app=celery_app
    )
    return FetcherListResponse(data=[_serialize_list_item(item) for item in items])


@router.get(
    "/fetchers/{fetcher_name}/runs",
    response_model=FetcherRunListResponse,
    summary="List fetcher run history",
    description=(
        "Returns a paginated, fixed reverse-chronological list of runs for "
        "the named fetcher. Supports filtering by status and date range."
    ),
)
async def list_fetcher_runs(
    fetcher_name: str,
    principal: OptionalCurrentUser,
    db: DatabaseSession,
    query: Annotated[FetcherRunListQuery, Depends(_fetcher_run_list_query)],
) -> FetcherRunListResponse:
    """List fetcher run history — see
    `docs/features/platform/fetcher-operations.md` (List Fetcher
    Runs)."""
    has_manage_fetchers = await _resolve_has_manage_fetchers(db, principal)
    try:
        page = await fetcher_operations.list_fetcher_runs(
            db,
            fetcher_name=fetcher_name,
            has_manage_fetchers=has_manage_fetchers,
            page=query.page,
            per_page=query.per_page,
            status=query.status,
            from_date=query.from_date,
            to_date=query.to_date,
        )
    except FetcherNotFoundError as exc:
        raise _not_found(exc) from exc
    return FetcherRunListResponse(
        data=[_serialize_run_list_item(item) for item in page.items],
        meta=PaginationMeta(total=page.total, page=page.page, per_page=page.per_page),
    )


@router.get(
    "/fetchers/{fetcher_name}/runs/{run_id}",
    response_model=FetcherRunDetailResponse,
    response_model_exclude_unset=True,
    summary="Get fetcher run detail",
    description=(
        "Returns full detail for a single run. Raw error detail and "
        "traceback are present only for callers with manage_fetchers."
    ),
)
async def get_fetcher_run(
    fetcher_name: str,
    run_id: UUID,
    principal: OptionalCurrentUser,
    db: DatabaseSession,
) -> FetcherRunDetailResponse:
    """Get fetcher run detail — see
    `docs/features/platform/fetcher-operations.md` (Get Fetcher Run
    Detail)."""
    has_manage_fetchers = await _resolve_has_manage_fetchers(db, principal)
    try:
        run = await fetcher_operations.get_fetcher_run(
            db,
            fetcher_name=fetcher_name,
            run_id=run_id,
            has_manage_fetchers=has_manage_fetchers,
        )
    except (FetcherNotFoundError, FetcherRunNotFoundError) as exc:
        raise _not_found(exc) from exc

    extra: dict[str, Any] = {}
    if has_manage_fetchers:
        extra["error_detail"] = run.error_detail
        extra["error_traceback"] = run.error_traceback
    data = FetcherRunDetailData(
        fetcher_name=run.fetcher_name, **_common_run_fields(run), **extra
    )
    return FetcherRunDetailResponse(data=data)


@router.get(
    "/fetchers/{fetcher_name}/timeline",
    response_model=FetcherTimelineResponse,
    summary="Get fetcher run timeline data",
    description=(
        "Returns time-series run data and disabled periods for chart "
        "rendering, bounded by an optional date range (maximum 1825 days)."
    ),
)
async def get_fetcher_timeline(
    fetcher_name: str,
    principal: OptionalCurrentUser,
    db: DatabaseSession,
    query: Annotated[FetcherTimelineQuery, Depends(_fetcher_timeline_query)],
) -> FetcherTimelineResponse:
    """Get fetcher run timeline data — see
    `docs/features/platform/fetcher-operations.md` (Get Fetcher Run
    Timeline Data)."""
    has_manage_fetchers = await _resolve_has_manage_fetchers(db, principal)

    now = datetime.now(UTC)
    to_date = (
        normalize_date_bound(query.to_date, end_of_day=True)
        if query.to_date is not None
        else now
    )
    from_date = (
        normalize_date_bound(query.from_date, end_of_day=False)
        if query.from_date is not None
        else now - _TIMELINE_DEFAULT_LOOKBACK
    )
    if (to_date - from_date).total_seconds() > _TIMELINE_MAX_SECONDS:
        raise AppError(
            status_code=status.HTTP_400_BAD_REQUEST,
            code=ErrorCode.DATE_RANGE_TOO_WIDE,
            detail="Date range must not exceed 1825 days.",
        )

    try:
        timeline = await fetcher_operations.get_fetcher_timeline(
            db,
            fetcher_name=fetcher_name,
            has_manage_fetchers=has_manage_fetchers,
            from_date=from_date,
            to_date=to_date,
        )
    except FetcherNotFoundError as exc:
        raise _not_found(exc) from exc
    return FetcherTimelineResponse(data=_serialize_timeline(timeline))


def get_fetcher_trigger_session_factory() -> async_sessionmaker[AsyncSession]:
    """Provide the session factory used by `trigger_fetcher()`'s
    service-owned orchestration.

    Performs no I/O — returns the production `async_session_factory`.
    `trigger_fetcher()` does not participate in the request-scoped
    `DatabaseSession` transaction: it is a service-owned orchestration
    boundary that opens and commits its own short-lived sessions across
    two independent transactions, publishing to Celery strictly between
    them with no lock held (`docs/conventions.md`, Caller-Owned Service
    Transactions: "a component that explicitly owns its sessions ...
    keeps the transaction contract defined by its owning specification";
    Transaction Hygiene Rules) — see
    `docs/features/platform/fetcher-operations.md` (`trigger_fetcher`).
    Overridable via `app.dependency_overrides` so tests can point it at
    the test database engine, mirroring `get_readiness_session_factory`
    (`app/api/health.py`) and `get_last_used_session_factory`
    (`app/api/dependencies.py`).
    """
    return async_session_factory


@router.post(
    "/fetchers/{fetcher_name}/trigger",
    response_model=FetcherTriggerResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Trigger fetcher",
    description=(
        "Enqueues a manual run of the specified fetcher. Returns the "
        "identifier of a FetcherRun already committed with status "
        "'queued'; poll GET .../runs/{run_id} for progress. Requires the "
        "manage_fetchers capability."
    ),
)
async def trigger_fetcher(
    fetcher_name: str,
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(require_capability(Capability.MANAGE_FETCHERS)),
    ],
    session_factory: Annotated[
        async_sessionmaker[AsyncSession],
        Depends(get_fetcher_trigger_session_factory),
    ],
) -> FetcherTriggerResponse:
    """Trigger fetcher — see
    `docs/features/platform/fetcher-operations.md` (Trigger Fetcher).

    Does not declare a `DatabaseSession` dependency: `trigger_fetcher()`
    manages its own sessions/transactions (see
    `get_fetcher_trigger_session_factory`)."""
    try:
        result = await fetcher_operations.trigger_fetcher(
            fetcher_name,
            user_id=principal.user.id,
            session_factory=session_factory,
            celery_app=celery_app,
        )
    except FetcherNotFoundError as exc:
        raise _not_found(exc) from exc
    except FetcherDeregisteredError as exc:
        raise _deregistered(exc) from exc
    except FetcherDisabledError as exc:
        raise _disabled(exc) from exc
    except FetcherAlreadyRunningError as exc:
        raise _already_running(exc) from exc
    except FetcherBrokerUnavailableError as exc:
        raise _broker_unavailable(exc) from exc
    return FetcherTriggerResponse(
        data=FetcherTriggerData(run_id=result.run_id, message=result.message)
    )


@router.get(
    "/fetchers/{fetcher_name}/config",
    response_model=FetcherConfigResponse,
    summary="Get fetcher config",
    description=(
        "Returns the current configuration for a fetcher, including any "
        "fetcher-specific custom settings and the generated settings "
        "schema. Requires the manage_fetchers capability."
    ),
)
async def get_fetcher_config(
    fetcher_name: str,
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(require_capability(Capability.MANAGE_FETCHERS)),
    ],
    db: DatabaseSession,
) -> FetcherConfigResponse:
    """Get fetcher config — see
    `docs/features/platform/fetcher-operations.md` (Get Fetcher
    Config)."""
    try:
        config = await fetcher_operations.get_fetcher_config(
            db, fetcher_name=fetcher_name
        )
    except FetcherNotFoundError as exc:
        raise _not_found(exc) from exc
    return FetcherConfigResponse(data=_serialize_config(config))


def _build_update_payload(body: FetcherConfigUpdateRequest) -> UpdateConfigPayload:
    """Translate `body.model_fields_set` into an `UpdateConfigPayload`
    where an omitted field maps to `UNSET` and a present field carries
    its parsed value through unchanged.

    `enabled`, `run_timeout`, and `request_delay` are asserted non-`None`
    when present: `FetcherConfigUpdateRequest`'s `_reject_null_*` field
    validators already reject an explicit `null` for these three fields
    before this function ever sees the body, so a present value is
    always the validated type — mirrors the `AdminUserUpdateRequest`
    `email` precedent (`app/api/v1/users.py`).
    """
    fields = body.model_fields_set

    enabled: bool | MissingType = UNSET
    if "enabled" in fields:
        assert body.enabled is not None
        enabled = body.enabled

    schedule_override: str | MissingType | None = UNSET
    if "schedule_override" in fields:
        schedule_override = body.schedule_override

    run_timeout: int | MissingType = UNSET
    if "run_timeout" in fields:
        assert body.run_timeout is not None
        run_timeout = body.run_timeout

    request_delay: float | MissingType = UNSET
    if "request_delay" in fields:
        assert body.request_delay is not None
        request_delay = body.request_delay

    custom_settings: dict[str, Any] | MissingType = UNSET
    if "custom_settings" in fields:
        assert body.custom_settings is not None
        custom_settings = body.custom_settings

    return UpdateConfigPayload(
        enabled=enabled,
        schedule_override=schedule_override,
        run_timeout=run_timeout,
        request_delay=request_delay,
        custom_settings=custom_settings,
    )


@router.patch(
    "/fetchers/{fetcher_name}/config",
    response_model=FetcherConfigResponse,
    summary="Update fetcher config",
    description=(
        "Partially updates a fetcher's configuration — generic fields "
        "(enabled, schedule_override, run_timeout, request_delay) and/or "
        "fetcher-specific custom settings. Only the submitted fields are "
        "changed; only actually-changed fields produce an audit event. "
        "Schedule-affecting changes are propagated to redbeat after commit "
        "on a best-effort basis. Requires the manage_fetchers capability."
    ),
)
async def update_fetcher_config(
    fetcher_name: str,
    body: FetcherConfigUpdateRequest,
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(require_capability(Capability.MANAGE_FETCHERS)),
    ],
    db: DatabaseSession,
) -> FetcherConfigResponse:
    """Update fetcher config — see
    `docs/features/platform/fetcher-operations.md` (Update Fetcher
    Config)."""
    try:
        result = await fetcher_operations.update_fetcher_config(
            db,
            fetcher_name=fetcher_name,
            user_id=principal.user.id,
            payload=_build_update_payload(body),
        )
    except FetcherNotFoundError as exc:
        raise _not_found(exc) from exc
    except FetcherDeregisteredError as exc:
        raise _deregistered(exc) from exc
    except FetcherAlreadyRunningError as exc:
        raise _already_running(exc) from exc
    except FetcherSettingUnknownError as exc:
        raise _setting_unknown(exc) from exc
    except FetcherSettingInvalidError as exc:
        raise _setting_invalid(exc) from exc

    propagation = result.propagation
    if propagation is not None:

        async def _propagate() -> None:
            try:
                await asyncio.to_thread(
                    fetcher_schedule.propagate_config_update,
                    celery_app,
                    fetcher_name=propagation.fetcher_name,
                    action=propagation.action,
                    schedule_override=propagation.schedule_override,
                    run_timeout=propagation.run_timeout,
                )
            except RedisError as exc:
                logger.warning(
                    "fetcher_config_redbeat_propagation_failed",
                    fetcher_name=propagation.fetcher_name,
                    action=propagation.action,
                    error=str(exc),
                )

        register_post_commit_callback(db, _propagate)

    return FetcherConfigResponse(data=_serialize_config(result.config))


@router.get(
    "/fetchers/{fetcher_name}/audit-log",
    response_model=FetcherAuditListResponse,
    summary="Get fetcher audit log",
    description=(
        "Returns a paginated, fixed reverse-chronological list of "
        "administrative actions on a fetcher. Supports filtering by "
        "event type, actor, and date range. Requires the manage_fetchers "
        "capability."
    ),
)
async def list_fetcher_audit_events(
    fetcher_name: str,
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(require_capability(Capability.MANAGE_FETCHERS)),
    ],
    db: DatabaseSession,
    query: Annotated[FetcherAuditQuery, Depends(_fetcher_audit_query)],
) -> FetcherAuditListResponse:
    """Get fetcher audit log — see
    `docs/features/platform/fetcher-operations.md` (Get Fetcher Audit
    Log)."""
    try:
        page = await fetcher_operations.list_fetcher_audit_events(
            db,
            fetcher_name=fetcher_name,
            page=query.page,
            per_page=query.per_page,
            event_type=query.event_type,
            actor=query.actor,
            from_date=query.from_date,
            to_date=query.to_date,
        )
    except FetcherNotFoundError as exc:
        raise _not_found(exc) from exc
    return FetcherAuditListResponse(
        data=[_serialize_audit_event(event) for event in page.items],
        meta=PaginationMeta(total=page.total, page=page.page, per_page=page.per_page),
    )
