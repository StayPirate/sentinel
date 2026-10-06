"""System settings service.

See `docs/features/platform/system-settings.md` for the full
specification: `bootstrap_system_settings()`, `get_default_cvss_version()`,
the setting mutation `update_default_cvss_version()`, the
`SettingAuditLog` audit trail, and `list_setting_audit_events()`.

The default-CVSS impact preview, whose `CVSSPreviewTimeoutError` belongs to
this module's `SettingsServiceError` hierarchy, lives in
`app.services.cvss_impact_preview` (see
`docs/features/platform/default-cvss-version-operations.md`). The manual
recalculation admission lives in `app.services.cvss_recalculation_admission`;
it raises `CVSSRecalculationAlreadyInProgressError`, which this module owns
(system-settings.md, Service Exceptions), and defines the remaining
admission exceptions of the same hierarchy.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import date, datetime
from typing import Final, Literal

from sqlalchemy import BigInteger, Select, func, literal, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.enums import SettingAuditEventType
from app.core.exceptions import ServiceError
from app.models.setting_audit_event import SettingAuditEvent
from app.models.system_setting import SystemSetting
from app.services.base_audit_log import BaseAuditLog
from app.services.cvss import DEFAULT_CVSS_VERSIONS
from app.services.cvss_recalculation_coordination import EXECUTION_FENCE_ID

_DEFAULT_CVSS_VERSION_KEY = "default_cvss_version"
_DEFAULT_CVSS_VERSION_INITIAL_VALUE = "3.1"

CVSS_RECALCULATION_IN_PROGRESS_MESSAGE: Final = (
    "A CVSS recalculation is already in progress."
)
"""Fixed message of `CVSSRecalculationAlreadyInProgressError` and the 409
detail."""


class SettingsServiceError(ServiceError):
    """Base class for all exceptions raised by the settings service."""


class CVSSRecalculationAlreadyInProgressError(SettingsServiceError):
    """The recalculation execution fence or the admission lease is held.

    Maps to `409 CVSS_RECALC_ALREADY_IN_PROGRESS` with a fixed message
    (system-settings.md, Service Exceptions). Raised by the manual
    recalculation admission when the fence or the lease is already held,
    and by an effective setting change while the fence is held; nothing
    is admitted, published, or committed.
    """

    def __init__(self) -> None:
        super().__init__(CVSS_RECALCULATION_IN_PROGRESS_MESSAGE)


class RequiredSystemSettingMissingError(SettingsServiceError):
    """The `default_cvss_version` row is absent from `system_setting`.

    Propagates to the caller; API handlers do not catch it, so the
    framework returns the global `500 INTERNAL_ERROR` response (see
    `docs/features/platform/system-settings.md`, Service Exceptions).
    """

    def __init__(self) -> None:
        super().__init__(
            f"Required system setting '{_DEFAULT_CVSS_VERSION_KEY}' is missing."
        )


async def bootstrap_system_settings(session: AsyncSession) -> None:
    """Idempotently ensure the `default_cvss_version` baseline row exists.

    Inserts `default_cvss_version = "3.1"` with `ON CONFLICT (key) DO
    NOTHING`, then flushes so database errors surface at this boundary.
    Never commits — the caller owns the transaction. Returns `None`
    whether it inserted the row or found an existing row (including an
    administrator-selected `"4.0"` value, which is preserved). Creates
    no audit event: this is idempotent initialization, not an
    administrative setting change. Concurrent callers are safe: at
    most one inserts the row and every successful caller observes a
    completed insert or conflict before returning. Database
    availability, missing-table/schema, constraint, and flush failures
    propagate unchanged — this function does not catch, retry, or
    return partial success.
    """
    stmt = (
        pg_insert(SystemSetting)
        .values(
            key=_DEFAULT_CVSS_VERSION_KEY,
            value=_DEFAULT_CVSS_VERSION_INITIAL_VALUE,
        )
        .on_conflict_do_nothing(index_elements=["key"])
    )
    await session.execute(stmt)
    await session.flush()


def default_cvss_version_select() -> Select[str]:
    """The read-only SELECT of the persisted `default_cvss_version` value.

    Returns at most one row. `get_default_cvss_version()` executes it on
    its own; a read that must observe the setting in the same PostgreSQL
    view as other rows embeds it as an uncorrelated scalar subquery
    (`.scalar_subquery()`), which yields SQL `NULL` when the row is
    absent. Such a caller must raise `RequiredSystemSettingMissingError`
    for that `NULL`, never substitute a value. The setting key remains
    owned by this module.
    """
    return select(SystemSetting.value).where(
        SystemSetting.key == _DEFAULT_CVSS_VERSION_KEY
    )


async def get_default_cvss_version(session: AsyncSession) -> str:
    """Return the persisted `default_cvss_version` value.

    Reads the `default_cvss_version` row from `system_setting`. Raises
    `RequiredSystemSettingMissingError` if the row is absent — never
    substitutes a hardcoded or environment-derived value. Database
    availability and schema errors propagate unchanged. Performs no
    writes and creates no audit event.
    """
    result = await session.execute(default_cvss_version_select())
    value = result.scalar_one_or_none()
    if value is None:
        raise RequiredSystemSettingMissingError()
    return value


async def update_default_cvss_version(
    session: AsyncSession,
    *,
    new_version: Literal["3.1", "4.0"],
    acting_user_id: uuid.UUID,
) -> str:
    """Change `default_cvss_version` in the caller's transaction.

    See `docs/features/platform/system-settings.md` (Setting Mutation
    Service). Validates `new_version` against the closed set before any
    database access (`ValueError`), then locks the required row `FOR
    UPDATE` as the first database operation
    (`RequiredSystemSettingMissingError` when absent). The lock refreshes
    the identity map, so classification never uses a value read before
    the lock.

    A request equal to the locked-current value is a no-op: it returns
    that value with no advisory-lock request, update, or audit event.
    Otherwise the execution fence identifier is requested in
    transaction-level, non-blocking form; a definitive "not acquired"
    raises `CVSSRecalculationAlreadyInProgressError`, and a database or
    session error propagates unchanged. The row is then updated and
    exactly one `setting_changed` event is logged with the locked-current
    `old_value`, both flushed. Returns the persisted value.

    Never commits or rolls back; the transaction-level lock ends with the
    caller's transaction. Performs no Redis command, lease, publication,
    or post-commit registration.
    """
    if new_version not in DEFAULT_CVSS_VERSIONS:
        raise ValueError("new_version must be '3.1' or '4.0'")

    result = await session.execute(
        select(SystemSetting)
        .where(SystemSetting.key == _DEFAULT_CVSS_VERSION_KEY)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    setting = result.scalar_one_or_none()
    if setting is None:
        raise RequiredSystemSettingMissingError()

    current = setting.value
    if current == new_version:
        return current

    fence = await session.execute(
        select(func.pg_try_advisory_xact_lock(literal(EXECUTION_FENCE_ID, BigInteger)))
    )
    if fence.scalar_one() is not True:
        raise CVSSRecalculationAlreadyInProgressError()

    setting.value = new_version
    await SettingAuditLog.log_event(
        session,
        event_type=SettingAuditEventType.SETTING_CHANGED,
        setting_key=_DEFAULT_CVSS_VERSION_KEY,
        user_id=acting_user_id,
        old_value=current,
        new_value=new_version,
    )
    return new_version


class SettingAuditLog(BaseAuditLog):
    """Audit trail for system setting modifications.

    See `docs/features/platform/system-settings.md` (Setting Audit
    Log).
    """

    name = "setting"
    description = "System setting modifications"
    model_class = SettingAuditEvent

    @classmethod
    async def log_event(  # type: ignore[override]
        cls,
        session: AsyncSession,
        *,
        event_type: SettingAuditEventType,
        setting_key: str,
        user_id: uuid.UUID | None,
        old_value: str | None,
        new_value: str,
    ) -> None:
        """Create one `SettingAuditEvent` in the caller's transaction.

        Validates that `event_type` is a `SettingAuditEventType` member
        (this classification enum has no database CHECK constraint) and
        that `user_id` is provided — every setting change is
        human-initiated, so a missing actor raises `ValueError` before
        any database operation. The foreign key on `setting_key` and
        the NOT NULL constraint on `new_value` validate the remaining
        required fields at the database level.

        Creates exactly one event and flushes it before returning.
        Never commits or rolls back. Each invocation creates a new
        event and is therefore not idempotent — callers MUST invoke it
        only when a setting value actually changes. `ValueError` and
        all database/flush exceptions propagate to the caller.
        """
        if not isinstance(event_type, SettingAuditEventType):
            raise ValueError(
                f"event_type must be a SettingAuditEventType member, got {event_type!r}"
            )
        if user_id is None:
            raise ValueError("user_id is required for setting audit events")

        await super().log_event(
            session,
            event_type=event_type.value,
            setting_key=setting_key,
            user_id=user_id,
            old_value=old_value,
            new_value=new_value,
        )


@dataclass(frozen=True)
class SettingAuditEventPage:
    """A page of `SettingAuditEvent` rows, with `actor` eagerly loaded
    on every item (see `list_setting_audit_events()`)."""

    items: list[SettingAuditEvent]
    total: int
    page: int
    per_page: int


async def list_setting_audit_events(
    session: AsyncSession,
    *,
    event_types: list[SettingAuditEventType] | None = None,
    setting_key: str | None = None,
    actor: str | None = None,
    from_date: date | datetime | None = None,
    to_date: date | datetime | None = None,
    page: int = 1,
    per_page: int = 20,
) -> SettingAuditEventPage:
    """Return one page of `SettingAuditEvent` rows for the settings
    audit log (`docs/features/platform/system-settings.md`, List
    Settings Audit Events).

    Q1: `event_types`, when non-empty, restricts to those event types
    (OR). `setting_key`, when given, is an exact match. `actor` follows
    the shared User Identifier Resolution contract plus the reserved
    literal `"system"` for `user_id IS NULL` (see
    `BaseAuditLog.filter_by_actor()`); because every setting audit event
    has a human actor, `"system"` and any unmatched UUID/username yield
    an empty page, never an error. `from_date`/`to_date` are inclusive
    bounds, already parsed by the API layer. `page`/`per_page` have
    already passed API schema validation. All filter types combine with
    AND.

    Q3: returns `SettingAuditEventPage(items, total, page, per_page)`
    with `actor` eagerly loaded on every item, ordered `id DESC` (fixed
    — no client-controlled sort). `id` is a UUIDv7 value, so this is
    equivalent to `created_at DESC` with a deterministic tiebreak, in a
    single column. An out-of-range page returns an empty `items` list
    with the correct `total`. No row lock, mutation, or audit event is
    created.

    Q6: propagates any underlying database exception. Infallible
    otherwise.
    """
    query = select(SettingAuditEvent)
    count_query = select(func.count()).select_from(SettingAuditEvent)

    if event_types:
        type_filter = SettingAuditEvent.event_type.in_(
            [event_type.value for event_type in event_types]
        )
        query = query.where(type_filter)
        count_query = count_query.where(type_filter)

    if setting_key is not None:
        key_filter = SettingAuditEvent.setting_key == setting_key
        query = query.where(key_filter)
        count_query = count_query.where(key_filter)

    query = SettingAuditLog.filter_by_actor(query, actor)
    count_query = SettingAuditLog.filter_by_actor(count_query, actor)

    query = SettingAuditLog.apply_date_filters(query, from_date, to_date)
    count_query = SettingAuditLog.apply_date_filters(count_query, from_date, to_date)

    total = (await session.execute(count_query)).scalar_one()

    data_query = (
        query.options(selectinload(SettingAuditEvent.actor))
        .order_by(SettingAuditEvent.id.desc())
        .offset((page - 1) * per_page)
        .limit(per_page)
    )
    items = list((await session.execute(data_query)).scalars().all())
    return SettingAuditEventPage(items=items, total=total, page=page, per_page=per_page)
