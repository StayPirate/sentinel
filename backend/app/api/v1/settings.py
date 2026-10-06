"""System settings read and audit log endpoints, the default-CVSS impact
preview, and the manual CVSS recalculation trigger.

See `docs/features/platform/system-settings.md` (Get System Settings,
List Settings Audit Events) and
`docs/features/platform/default-cvss-version-operations.md` (Get
Default-CVSS Impact Preview, Trigger CVSS Recalculation) for the
authoritative endpoint contracts this module implements. Handlers stay
thin: they validate, delegate to `app.services.settings`,
`app.services.cvss_impact_preview`, or
`app.services.cvss_recalculation_admission`, and map the result to the
documented response — no business logic or database query lives here.
"""

from __future__ import annotations

from dataclasses import asdict
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Query

from app.api.dependencies import AuthenticatedPrincipal, require_capability
from app.core.dates import parse_date_range_bound, validate_date_range_order
from app.core.enums import Capability, SettingAuditEventType
from app.core.errors import AppError, ErrorCode
from app.database import DatabaseSession
from app.models.setting_audit_event import SettingAuditEvent
from app.schemas.common import PaginationMeta, UserReference
from app.schemas.errors import ErrorResponse
from app.schemas.settings import (
    CVSSRecalculationTriggerData,
    CVSSRecalculationTriggerResponse,
    DefaultCVSSVersionImpactData,
    DefaultCVSSVersionImpactResponse,
    SettingAuditEventData,
    SettingAuditListResponse,
    SettingAuditQuery,
    SystemSettingsData,
    SystemSettingsResponse,
)
from app.services import cvss_impact_preview, cvss_recalculation_admission
from app.services import settings as settings_service

_PREVIEW_TIMEOUT_DETAIL = "The impact preview did not complete within its deadline."

router = APIRouter(prefix="/api/v1/admin", tags=["System Settings"])


# ---------------------------------------------------------------------------
# Query parameter builder
#
# Declared as individual `Query()`-annotated parameters (rather than a
# single `Annotated[Model, Query()]` query-parameter-model field) so
# each field is visible individually to the shared query-length-limit
# dependency's route-dependant walk (`app.core.query_limits`). Mirrors
# `app/api/v1/identity_audit.py`.
# ---------------------------------------------------------------------------


def _settings_audit_query(
    *,
    event_type: Annotated[
        list[str],
        Query(
            default_factory=list,
            description="Filter by event type. Repeatable; OR semantics.",
        ),
    ],
    setting_key: Annotated[
        str | None, Query(description="Filter by exact setting key.")
    ] = None,
    actor: Annotated[
        str | None,
        Query(description="Actor UUID, exact username, or 'system'."),
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
) -> SettingAuditQuery:
    parsed_from = parse_date_range_bound("from_date", from_date)
    parsed_to = parse_date_range_bound("to_date", to_date)
    validate_date_range_order(parsed_from, parsed_to)
    return SettingAuditQuery(
        event_type=event_type,
        setting_key=setting_key,
        actor=actor,
        from_date=parsed_from,
        to_date=parsed_to,
        page=page,
        per_page=per_page,
    )


def _parse_event_types(raw: list[str]) -> tuple[bool, list[SettingAuditEventType]]:
    """Resolve the raw repeatable `event_type` query values to typed filters.

    Returns `(True, [])` when `raw` is empty (no filter applied),
    `(True, [...])` with the valid subset when at least one value is
    valid, and `(False, [])` when `raw` is non-empty but every value is
    invalid — the caller must then render an empty page without
    querying the service, per `docs/api-spec.md` (Enum Filter
    Validation).
    """
    if not raw:
        return True, []
    valid: list[SettingAuditEventType] = []
    for value in raw:
        try:
            valid.append(SettingAuditEventType(value))
        except ValueError:
            continue
    if not valid:
        return False, []
    return True, valid


def _serialize_event(event: SettingAuditEvent) -> SettingAuditEventData:
    return SettingAuditEventData(
        id=event.id,
        event_type=event.event_type,
        setting_key=event.setting_key,
        old_value=event.old_value,
        new_value=event.new_value,
        created_at=event.created_at,
        actor=UserReference.model_validate(event.actor),
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get(
    "/settings",
    response_model=SystemSettingsResponse,
    summary="Get system settings",
    description=(
        "Returns the current value of platform-wide settings. Requires "
        "the manage_settings capability."
    ),
)
async def get_system_settings(
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(require_capability(Capability.MANAGE_SETTINGS)),
    ],
    db: DatabaseSession,
) -> SystemSettingsResponse:
    """Get system settings — see
    `docs/features/platform/system-settings.md` (Get System Settings).

    A missing required `default_cvss_version` row propagates
    `RequiredSystemSettingMissingError`, which is not caught here and
    surfaces as the global `500 INTERNAL_ERROR` response — no fallback
    value is returned.
    """
    default_cvss_version = await settings_service.get_default_cvss_version(db)
    return SystemSettingsResponse(
        data=SystemSettingsData(default_cvss_version=default_cvss_version)
    )


@router.get(
    "/settings/default-cvss-version/impact",
    response_model=DefaultCVSSVersionImpactResponse,
    summary="Preview the impact of a default CVSS version change",
    description=(
        "Returns a read-only, fixed-size aggregate of the severity, Product "
        "eligibility, override-skip, and Resolved-regression effects that "
        "applying the proposed default CVSS version would have on the "
        "persisted CVE population. Advisory and non-binding; it is not a "
        "prerequisite for changing the setting. Requires the "
        "manage_settings capability."
    ),
    responses={
        503: {
            "model": ErrorResponse,
            "description": (
                "`CVSS_PREVIEW_TIMEOUT`: the preview deadline expired before "
                "a complete result was available; no partial result is "
                "returned."
            ),
        },
    },
)
async def get_default_cvss_version_impact(
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(require_capability(Capability.MANAGE_SETTINGS)),
    ],
    db: DatabaseSession,
    proposed_version: Annotated[
        Literal["3.1", "4.0"],
        Query(description="Proposed default CVSS version; exactly 3.1 or 4.0."),
    ],
) -> DefaultCVSSVersionImpactResponse:
    """Get the default-CVSS impact preview — see
    `docs/features/platform/default-cvss-version-operations.md` (Get
    Default-CVSS Impact Preview).

    `CVSSPreviewTimeoutError` maps to `503 CVSS_PREVIEW_TIMEOUT` with a
    fixed detail. A missing required setting propagates as the global
    `500 INTERNAL_ERROR`.
    """
    try:
        impact = await cvss_impact_preview.get_default_cvss_version_impact(
            db, proposed_version
        )
    except cvss_impact_preview.CVSSPreviewTimeoutError:
        raise AppError(
            status_code=503,
            code=ErrorCode.CVSS_PREVIEW_TIMEOUT,
            detail=_PREVIEW_TIMEOUT_DETAIL,
        ) from None
    return DefaultCVSSVersionImpactResponse(
        data=DefaultCVSSVersionImpactData(**asdict(impact))
    )


@router.post(
    "/settings/default-cvss-version/recalculate",
    response_model=CVSSRecalculationTriggerResponse,
    status_code=202,
    summary="Trigger the all-CVE CVSS recalculation",
    description=(
        "Admits and enqueues one complete recalculation of every persisted "
        "CVE for the currently persisted default CVSS version. Takes no "
        "request body and accepts no version. Changes no setting and "
        "creates no audit event. Repeatable: it is the explicit refresh and "
        "recovery surface after a setting change or an interrupted run. "
        "Requires the manage_settings capability."
    ),
    responses={
        409: {
            "model": ErrorResponse,
            "description": (
                "`CVSS_RECALC_ALREADY_IN_PROGRESS`: the execution fence or "
                "the admission lease is already held; nothing is published."
            ),
        },
        503: {
            "model": ErrorResponse,
            "description": (
                "`REDIS_UNAVAILABLE`: lease acquisition failed or was "
                "uncertain; nothing is published. `CELERY_UNAVAILABLE`: task "
                "publication could not be confirmed; the admission lease is "
                "retained until the task adopts it or it expires."
            ),
        },
    },
)
async def trigger_cvss_recalculation(
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(require_capability(Capability.MANAGE_SETTINGS)),
    ],
) -> CVSSRecalculationTriggerResponse:
    """Trigger CVSS recalculation — see
    `docs/features/platform/default-cvss-version-operations.md` (Trigger
    CVSS Recalculation).

    Each admission exception maps to its single status and code with a
    fixed detail. Every other exception, including a fence-release
    failure before publisher invocation, propagates to the global
    `500 INTERNAL_ERROR`.
    """
    try:
        admission = await cvss_recalculation_admission.admit_cvss_recalculation()
    except settings_service.CVSSRecalculationAlreadyInProgressError:
        raise AppError(
            status_code=409,
            code=ErrorCode.CVSS_RECALC_ALREADY_IN_PROGRESS,
            detail=settings_service.CVSS_RECALCULATION_IN_PROGRESS_MESSAGE,
        ) from None
    except cvss_recalculation_admission.CVSSRecalculationRedisUnavailableError:
        raise AppError(
            status_code=503,
            code=ErrorCode.REDIS_UNAVAILABLE,
            detail=cvss_recalculation_admission.REDIS_UNAVAILABLE_MESSAGE,
        ) from None
    except cvss_recalculation_admission.CVSSRecalculationBrokerUnavailableError:
        raise AppError(
            status_code=503,
            code=ErrorCode.CELERY_UNAVAILABLE,
            detail=cvss_recalculation_admission.BROKER_UNAVAILABLE_MESSAGE,
        ) from None
    return CVSSRecalculationTriggerResponse(
        data=CVSSRecalculationTriggerData(
            message="Recalculation batch enqueued",
            default_cvss_version=admission.target_version,
            scope="all_cves",
        )
    )


@router.get(
    "/settings/audit-log",
    response_model=SettingAuditListResponse,
    summary="List settings audit events",
    description=(
        "Returns a paginated, fixed reverse-chronological list of system "
        "setting modifications. Supports filtering by event type, setting "
        "key, actor, and date range. Requires the manage_settings "
        "capability."
    ),
)
async def list_setting_audit_events(
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(require_capability(Capability.MANAGE_SETTINGS)),
    ],
    db: DatabaseSession,
    query: Annotated[SettingAuditQuery, Depends(_settings_audit_query)],
) -> SettingAuditListResponse:
    """List settings audit events — see
    `docs/features/platform/system-settings.md` (List Settings Audit
    Events)."""
    types_valid, event_types = _parse_event_types(query.event_type)
    if not types_valid:
        return SettingAuditListResponse(
            data=[],
            meta=PaginationMeta(total=0, page=query.page, per_page=query.per_page),
        )

    page = await settings_service.list_setting_audit_events(
        db,
        event_types=event_types,
        setting_key=query.setting_key,
        actor=query.actor,
        from_date=query.from_date,
        to_date=query.to_date,
        page=query.page,
        per_page=query.per_page,
    )
    return SettingAuditListResponse(
        data=[_serialize_event(event) for event in page.items],
        meta=PaginationMeta(total=page.total, page=page.page, per_page=page.per_page),
    )
