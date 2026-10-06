"""Request/response/query schemas for the system settings read, update,
and audit log endpoints, the default-CVSS impact preview, and the manual
CVSS recalculation trigger.

See `docs/features/platform/system-settings.md` (Get System Settings,
Update System Settings, List Settings Audit Events) and
`docs/features/platform/default-cvss-version-operations.md` (Get
Default-CVSS Impact Preview, Trigger CVSS Recalculation) for the
authoritative request/response contracts these schemas implement.
"""

from __future__ import annotations

from datetime import date, datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, Field

from app.schemas.common import PaginationMeta, UserReference


class SystemSettingsData(BaseModel):
    """The settings object returned by `GET` and `PATCH
    /api/v1/admin/settings`."""

    default_cvss_version: str


class SystemSettingsResponse(BaseModel):
    """Response body for `GET` and `PATCH /api/v1/admin/settings`."""

    data: SystemSettingsData


class UpdateSystemSettingsRequest(BaseModel):
    """Request body for `PATCH /api/v1/admin/settings`.

    The single field is required (single-field PATCH, `docs/api-spec.md`
    Partial Update Semantics): a missing field, `null`, or any value other
    than exactly `"3.1"` or `"4.0"` is the global `422 VALIDATION_ERROR`.
    No preview count, high-water mark, or token is accepted.
    """

    default_cvss_version: Literal["3.1", "4.0"] = Field(
        description="New default CVSS version; exactly 3.1 or 4.0."
    )


class DefaultCVSSVersionImpactData(BaseModel):
    """The aggregate returned by
    `GET /api/v1/admin/settings/default-cvss-version/impact`.

    See `docs/features/platform/default-cvss-version-operations.md`
    (Result and Count Units); no identifier or detail collection.
    """

    observed_default_cvss_version: str
    proposed_default_cvss_version: str
    no_op: bool
    cves_evaluated: int
    cve_severity_changes: int
    product_eligibility_changes: int
    product_eligibility_override_skips: int
    resolved_ticket_regressions: int


class DefaultCVSSVersionImpactResponse(BaseModel):
    """Response body for the default-CVSS impact preview (no `meta`)."""

    data: DefaultCVSSVersionImpactData


class CVSSRecalculationTriggerData(BaseModel):
    """The body of a `202 Accepted` from
    `POST /api/v1/admin/settings/default-cvss-version/recalculate`.

    See `docs/features/platform/default-cvss-version-operations.md`
    (Trigger CVSS Recalculation); the run's task ID is never returned.
    """

    message: Literal["Recalculation batch enqueued"]
    default_cvss_version: str
    scope: Literal["all_cves"]


class CVSSRecalculationTriggerResponse(BaseModel):
    """Response body for the manual CVSS recalculation trigger."""

    data: CVSSRecalculationTriggerData


class SettingAuditQuery(BaseModel):
    """Query parameters for `GET /api/v1/admin/settings/audit-log`.

    `event_type` is intentionally `list[str]`, not
    `list[SettingAuditEventType]`: an invalid value must be silently
    ignored and produce an empty result (`docs/api-spec.md`, Enum Filter
    Validation) rather than the schema-validation `422` a typed enum
    field would raise. The route handler parses each value against
    `SettingAuditEventType` itself.

    `from_date`/`to_date` are already-parsed `date`/`datetime` values by
    the time this model is constructed — the API layer's
    `app.core.dates.parse_date_range_bound()` performs the strict ISO
    8601 parsing (and its `422` rejection) before this model sees them.
    An inverted normalized range is validated separately by
    `app.core.dates.validate_date_range_order()` (`400
    DATE_RANGE_INVERTED`).
    """

    event_type: list[str] = Field(default_factory=list)
    setting_key: str | None = None
    actor: str | None = None
    from_date: date | datetime | None = None
    to_date: date | datetime | None = None
    page: int = Field(default=1, ge=1, le=2_147_483_647)
    per_page: int = Field(default=20, ge=1, le=100)


class SettingAuditEventData(BaseModel):
    """One event in the setting audit log response
    (`system-settings.md`, List Settings Audit Events). `actor` is
    always the complete current user reference — setting audit events
    require a human actor and user rows cannot be hard-deleted, so it
    is never `null`."""

    id: UUID
    event_type: str
    setting_key: str
    old_value: str | None
    new_value: str
    created_at: datetime
    actor: UserReference


class SettingAuditListResponse(BaseModel):
    """Response body for `GET /api/v1/admin/settings/audit-log`."""

    data: list[SettingAuditEventData]
    meta: PaginationMeta
