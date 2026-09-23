"""Request/response/query schemas for the fetcher observation and
admin config/audit-log/trigger endpoints.

See `docs/features/platform/fetcher-operations.md` (List Fetchers, List
Fetcher Runs, Get Fetcher Run Detail, Get Fetcher Run Timeline Data,
Trigger Fetcher, Get Fetcher Config, Update Fetcher Config, Get Fetcher
Audit Log) for the authoritative request/response contract these
schemas implement.
"""

from __future__ import annotations

from datetime import date, datetime
from typing import Any
from uuid import UUID

from celery.schedules import crontab
from pydantic import BaseModel, Field, field_validator, model_validator

from app.schemas.common import PaginationMeta, UserReference

# ---------------------------------------------------------------------------
# Query parameters
# ---------------------------------------------------------------------------


class FetcherRunListQuery(BaseModel):
    """Query parameters for `GET /api/v1/fetchers/{fetcher_name}/runs`.

    `status` is intentionally `str | None`, not a typed
    `FetcherRunStatus`: an invalid value must be silently ignored and
    produce an empty result (`docs/api-spec.md`, Enum Filter
    Validation) rather than the schema-validation `422` a typed enum
    field would raise. The service validates the value itself, after
    the fetcher-existence check (see `fetcher_operations.list_fetcher_runs`).

    `from_date`/`to_date` are already-parsed `date`/`datetime` values by
    the time this model is constructed — the API layer's
    `app.core.dates.parse_date_range_bound()` performs the strict ISO
    8601 parsing (and its `422` rejection) before this model sees them.
    An inverted normalized range is validated separately by
    `app.core.dates.validate_date_range_order()` (`400
    DATE_RANGE_INVERTED`).
    """

    status: str | None = None
    from_date: date | datetime | None = None
    to_date: date | datetime | None = None
    page: int = Field(default=1, ge=1, le=2_147_483_647)
    per_page: int = Field(default=20, ge=1, le=100)


class FetcherTimelineQuery(BaseModel):
    """Query parameters for `GET /api/v1/fetchers/{fetcher_name}/timeline`.

    `from_date`/`to_date` are already-parsed `date`/`datetime` values
    (see `FetcherRunListQuery`). Both default to `None` here — the
    endpoint resolves the documented defaults (7 days ago / now) and
    the 1825-day maximum interval, since those require the current
    time at request time, not a static schema default.
    """

    from_date: date | datetime | None = None
    to_date: date | datetime | None = None


# ---------------------------------------------------------------------------
# List Fetchers
# ---------------------------------------------------------------------------


class FetcherLastRunData(BaseModel):
    """The `last_run` object nested in a `List Fetchers` item.

    `triggered_by_user` is a `UserReference` when `triggered_by` is
    `manual` and the caller holds `manage_fetchers`, otherwise `null`.
    `error_detail`/`error_traceback` are never included at this level
    (list response) — see `docs/features/platform/fetcher-operations.md`
    (List Fetchers, Fields)."""

    id: UUID
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    duration_seconds: float | None
    status: str
    items_succeeded: int
    items_created: int
    items_updated: int
    items_failed: int
    triggered_by: str
    triggered_by_user: UserReference | None
    error_message: str | None
    stale: bool


class FetcherListItemData(BaseModel):
    """One entry in the `GET /api/v1/fetchers` response — a registered
    or deregistered fetcher merged with its latest run and, when
    applicable, its next scheduled run time."""

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
    last_run: FetcherLastRunData | None


class FetcherListResponse(BaseModel):
    """Response body for `GET /api/v1/fetchers`. Not paginated — see
    `docs/features/platform/fetcher-operations.md` (List Fetchers,
    Pagination)."""

    data: list[FetcherListItemData]


# ---------------------------------------------------------------------------
# List Fetcher Runs / Get Fetcher Run Detail
# ---------------------------------------------------------------------------


class FetcherRunListItemData(FetcherLastRunData):
    """One entry in the `GET /api/v1/fetchers/{fetcher_name}/runs`
    response — the same shape as `FetcherLastRunData` plus
    `fetcher_name` (needed here since a run list item is not already
    nested under a fetcher-scoped object)."""

    fetcher_name: str


class FetcherRunListResponse(BaseModel):
    """Response body for `GET /api/v1/fetchers/{fetcher_name}/runs`."""

    data: list[FetcherRunListItemData]
    meta: PaginationMeta


class FetcherRunDetailData(FetcherRunListItemData):
    """The `data` object for `GET /api/v1/fetchers/{fetcher_name}/runs/{run_id}`.

    `error_detail`/`error_traceback` default to unset. The endpoint
    constructs this model without passing them for callers lacking
    `manage_fetchers` and declares `response_model_exclude_unset=True`,
    so Pydantic renders them as fully absent JSON keys — not
    `"error_detail": null` — for those callers, per
    `docs/features/platform/fetcher-operations.md` (Get Fetcher Run
    Detail, Fields). Every other field on this model is always
    explicitly set at construction time, so `exclude_unset` has no
    effect on them.
    """

    error_detail: str | None = None
    error_traceback: str | None = None


class FetcherRunDetailResponse(BaseModel):
    """Response body for `GET /api/v1/fetchers/{fetcher_name}/runs/{run_id}`."""

    data: FetcherRunDetailData


# ---------------------------------------------------------------------------
# Get Fetcher Run Timeline Data
# ---------------------------------------------------------------------------


class FetcherTimelinePointData(BaseModel):
    """One chart data point — a single `FetcherRun` record."""

    run_id: UUID
    timestamp: datetime
    duration_seconds: float | None
    items_succeeded: int
    items_created: int
    items_updated: int
    items_failed: int
    status: str


class FetcherDisabledPeriodData(BaseModel):
    """One derived disabled period. `disabled_by`/`enabled_by` are
    `UserReference` objects only when the caller holds
    `manage_fetchers`, otherwise `null` — never absent (unlike the run
    detail's raw diagnostic fields), since these are always meaningful
    as a null value regardless of capability."""

    disabled_at: datetime
    disabled_by: UserReference | None
    enabled_at: datetime | None
    enabled_by: UserReference | None


class FetcherTimelineData(BaseModel):
    points: list[FetcherTimelinePointData]
    disabled_periods: list[FetcherDisabledPeriodData]


class FetcherTimelineResponse(BaseModel):
    """Response body for `GET /api/v1/fetchers/{fetcher_name}/timeline`."""

    data: FetcherTimelineData


# ---------------------------------------------------------------------------
# Get Fetcher Config
# ---------------------------------------------------------------------------


class FetcherConfigData(BaseModel):
    """The `data` object for `GET /api/v1/fetchers/{fetcher_name}/config`.

    `default_schedule` and `settings_schema` are `null` for a
    deregistered fetcher — see `docs/features/platform/fetcher-operations.md`
    (Get Fetcher Config, Deregistered fetcher behavior)."""

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


class FetcherConfigResponse(BaseModel):
    """Response body for `GET /api/v1/fetchers/{fetcher_name}/config`."""

    data: FetcherConfigData


# ---------------------------------------------------------------------------
# Update Fetcher Config
# ---------------------------------------------------------------------------


class FetcherConfigUpdateRequest(BaseModel):
    """Request body for `PATCH /api/v1/fetchers/{fetcher_name}/config`
    (`fetcher-operations.md`, Update Fetcher Config).

    All fields are optional but at least one must be provided
    (`docs/api-spec.md`, Partial Update Semantics). The route
    distinguishes "omitted" from "explicitly provided" via
    `model_fields_set` (see `AdminUserUpdateRequest` for the same
    pattern). `enabled`, `run_timeout`, and `request_delay` are
    non-nullable in the data model — an explicit `null` for any of
    them is rejected here, before the service is called.
    `schedule_override` accepts `null` to revert to the fetcher's
    `default_schedule`. `custom_settings`, when provided, cannot itself
    be `null` (the JSONB column is non-nullable) — but an individual
    key *within* it may be `null`, resetting that key to its
    `Settings` field default (`fetcher-operations.md`,
    `update_fetcher_config`, step 6). Per-key/per-value validation
    (unknown key, invalid value) is performed by the service layer,
    which raises the dedicated `FetcherSettingUnknownError`/
    `FetcherSettingInvalidError` (422
    `FETCHER_SETTING_UNKNOWN`/`FETCHER_SETTING_INVALID`) — this schema
    only validates the group-level shape and the input-only
    constraints (`docs/features/platform/fetcher-operations.md`,
    `update_fetcher_config`, Q3 step 1) that must produce the generic
    `422 VALIDATION_ERROR`: `schedule_override` cron syntax and
    50-character storage bound (matching `FetcherConfig.schedule_override`,
    `VARCHAR(50)`), and the `run_timeout`/`request_delay` numeric bounds.
    """

    enabled: bool | None = None
    schedule_override: str | None = Field(default=None, max_length=50)
    run_timeout: int | None = Field(default=None, ge=60, le=604_800)
    request_delay: float | None = Field(default=None, ge=0, le=300)
    custom_settings: dict[str, Any] | None = None

    @field_validator("enabled", mode="before")
    @classmethod
    def _reject_null_enabled(cls, value: Any) -> Any:
        if value is None:
            raise ValueError("enabled cannot be null.")
        return value

    @field_validator("schedule_override")
    @classmethod
    def _validate_cron(cls, value: str | None) -> str | None:
        if value is not None:
            # Raises `ValueError` on an invalid 5-field cron expression —
            # the same parser redbeat uses at runtime (see
            # `docs/features/platform/fetcher-operations.md`, Update
            # Fetcher Config, Validation rules).
            crontab.from_string(value)
        return value

    @field_validator("run_timeout", mode="before")
    @classmethod
    def _reject_null_run_timeout(cls, value: Any) -> Any:
        if value is None:
            raise ValueError("run_timeout cannot be null.")
        return value

    @field_validator("request_delay", mode="before")
    @classmethod
    def _reject_null_request_delay(cls, value: Any) -> Any:
        if value is None:
            raise ValueError("request_delay cannot be null.")
        return value

    @field_validator("custom_settings", mode="before")
    @classmethod
    def _reject_null_custom_settings(cls, value: Any) -> Any:
        if value is None:
            raise ValueError(
                "custom_settings cannot be null; provide an object with the "
                "individual keys to change."
            )
        return value

    @model_validator(mode="after")
    def _require_at_least_one_field(self) -> FetcherConfigUpdateRequest:
        if not self.model_fields_set:
            raise ValueError("At least one field must be provided.")
        return self


# ---------------------------------------------------------------------------
# Get Fetcher Audit Log
# ---------------------------------------------------------------------------


class FetcherAuditQuery(BaseModel):
    """Query parameters for
    `GET /api/v1/fetchers/{fetcher_name}/audit-log`.

    `event_type` is intentionally `list[str]`, not
    `list[FetcherAuditEventType]`: an invalid value must be silently
    ignored and produce an empty result (`docs/api-spec.md`, Enum
    Filter Validation) rather than the schema-validation `422` a typed
    enum field would raise. Unlike the sibling settings/identity audit
    endpoints, this parsing happens inside
    `fetcher_operations.list_fetcher_audit_events()` itself — after the
    fetcher-existence check — not in the route handler, so that an
    entirely-invalid `event_type` set never masks a nonexistent fetcher
    behind an empty `200` response (see that function's docstring).

    `from_date`/`to_date` are already-parsed `date`/`datetime` values by
    the time this model is constructed — the API layer's
    `app.core.dates.parse_date_range_bound()` performs the strict ISO
    8601 parsing (and its `422` rejection) before this model sees them.
    An inverted normalized range is validated separately by
    `app.core.dates.validate_date_range_order()` (`400
    DATE_RANGE_INVERTED`).
    """

    event_type: list[str] = Field(default_factory=list)
    actor: str | None = None
    from_date: date | datetime | None = None
    to_date: date | datetime | None = None
    page: int = Field(default=1, ge=1, le=2_147_483_647)
    per_page: int = Field(default=20, ge=1, le=100)


class FetcherAuditEventData(BaseModel):
    """One event in the fetcher audit log response
    (`fetcher-operations.md`, Get Fetcher Audit Log). `actor` is always
    the complete current user reference — every fetcher audit event
    requires a human actor and user rows cannot be hard-deleted, so it
    is never `null`."""

    id: UUID
    fetcher_name: str
    event_type: str
    actor: UserReference
    old_value: str | None
    new_value: str | None
    detail: dict[str, Any] | None
    created_at: datetime


class FetcherAuditListResponse(BaseModel):
    """Response body for `GET /api/v1/fetchers/{fetcher_name}/audit-log`."""

    data: list[FetcherAuditEventData]
    meta: PaginationMeta


# ---------------------------------------------------------------------------
# Trigger Fetcher
# ---------------------------------------------------------------------------


class FetcherTriggerData(BaseModel):
    """The `data` object for
    `POST /api/v1/fetchers/{fetcher_name}/trigger` (`fetcher-operations.md`,
    Trigger Fetcher). `run_id` identifies a `FetcherRun` already
    committed with `status = queued` — it transitions to `running` once
    a worker adopts it."""

    run_id: UUID
    message: str


class FetcherTriggerResponse(BaseModel):
    """Response body for `POST /api/v1/fetchers/{fetcher_name}/trigger`."""

    data: FetcherTriggerData
