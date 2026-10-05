"""Identity audit trail service.

See `docs/features/identity/identity-audit-log.md` for the full
specification: the `IdentityAuditEventType` contract (actor/target
semantics and `old_value`/`new_value`/`detail` per event type), the
`detail` JSONB Schema Contract, and the deterministic validation order
implemented by `IdentityAuditLog.log_event()`.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import date, datetime
from typing import Any, Final

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.enums import IdentityAuditEventType
from app.models.identity_audit_event import IdentityAuditEvent
from app.models.user import User
from app.services.base_audit_log import BaseAuditLog

# Imported from the leaf module rather than its `user_service` re-export:
# `user_service` imports this module, so the re-export would be a cycle.
from app.services.user_identifier import user_identifier_condition

# `old_value`/`new_value` truncation limit, in Unicode code points (not
# bytes/graphemes). Python `str` indexing already operates on code
# points, so `value[:_MAX_VALUE_CODEPOINTS]` satisfies the "no Unicode
# normalization, no ellipsis" requirement directly.
_MAX_VALUE_CODEPOINTS: Final = 512

# `detail` size limit, in UTF-8 encoded bytes of the deterministic
# serialized representation (see `_measure_detail_size`).
_MAX_DETAIL_BYTES: Final = 4096

# Per-field presence rules for the actor/target/old_value/new_value
# combination. Values are one of `_REQUIRED`, `_FORBIDDEN`, `_OPTIONAL`.
_REQUIRED: Final = "required"
_FORBIDDEN: Final = "forbidden"
_OPTIONAL: Final = "optional"

_FIELD_RULES: Final[dict[IdentityAuditEventType, dict[str, str]]] = {
    IdentityAuditEventType.USER_CREATED: {
        "user_id": _OPTIONAL,
        "target_user_id": _REQUIRED,
        "old_value": _FORBIDDEN,
        "new_value": _REQUIRED,
    },
    IdentityAuditEventType.USER_DEACTIVATED: {
        "user_id": _OPTIONAL,
        "target_user_id": _REQUIRED,
        "old_value": _REQUIRED,
        "new_value": _REQUIRED,
    },
    IdentityAuditEventType.USER_REACTIVATED: {
        "user_id": _OPTIONAL,
        "target_user_id": _REQUIRED,
        "old_value": _REQUIRED,
        "new_value": _REQUIRED,
    },
    IdentityAuditEventType.PASSWORD_RESET: {
        "user_id": _OPTIONAL,
        "target_user_id": _REQUIRED,
        "old_value": _FORBIDDEN,
        "new_value": _FORBIDDEN,
    },
    IdentityAuditEventType.ROLE_ADDED: {
        "user_id": _OPTIONAL,
        "target_user_id": _REQUIRED,
        "old_value": _FORBIDDEN,
        "new_value": _REQUIRED,
    },
    IdentityAuditEventType.ROLE_REMOVED: {
        "user_id": _OPTIONAL,
        "target_user_id": _REQUIRED,
        "old_value": _REQUIRED,
        "new_value": _FORBIDDEN,
    },
    # Intrinsically administrator-only: user_id (the actor) is required.
    # log_event() cannot verify the actor actually holds the Admin role
    # (that is an authorization concern outside this module) — it only
    # enforces that an actor is attributed.
    IdentityAuditEventType.ROLE_MAPPING_CREATED: {
        "user_id": _REQUIRED,
        "target_user_id": _FORBIDDEN,
        "old_value": _FORBIDDEN,
        "new_value": _REQUIRED,
    },
    IdentityAuditEventType.ROLE_MAPPING_DELETED: {
        "user_id": _REQUIRED,
        "target_user_id": _FORBIDDEN,
        "old_value": _REQUIRED,
        "new_value": _FORBIDDEN,
    },
    IdentityAuditEventType.USERNAME_CHANGED: {
        "user_id": _OPTIONAL,
        "target_user_id": _REQUIRED,
        "old_value": _REQUIRED,
        "new_value": _REQUIRED,
    },
    IdentityAuditEventType.API_KEY_CREATED: {
        "user_id": _REQUIRED,
        "target_user_id": _REQUIRED,
        "old_value": _FORBIDDEN,
        "new_value": _REQUIRED,
    },
    IdentityAuditEventType.API_KEY_REVOKED: {
        "user_id": _OPTIONAL,
        "target_user_id": _REQUIRED,
        "old_value": _REQUIRED,
        "new_value": _FORBIDDEN,
    },
    IdentityAuditEventType.EMAIL_CHANGED: {
        "user_id": _OPTIONAL,
        "target_user_id": _REQUIRED,
        "old_value": _REQUIRED,
        "new_value": _REQUIRED,
    },
    IdentityAuditEventType.FULL_NAME_CHANGED: {
        "user_id": _OPTIONAL,
        "target_user_id": _REQUIRED,
        "old_value": _OPTIONAL,
        "new_value": _OPTIONAL,
    },
    # Intrinsically system-only: user_id (the actor) must be NULL.
    IdentityAuditEventType.MANAGER_CHANGED: {
        "user_id": _FORBIDDEN,
        "target_user_id": _REQUIRED,
        "old_value": _OPTIONAL,
        "new_value": _OPTIONAL,
    },
}


@dataclass(frozen=True)
class _DetailSchema:
    """The `detail` JSONB schema for one `IdentityAuditEventType`.

    `required`/`optional` list the only keys accepted for the event
    type. `require_present` marks event types where `detail` itself
    must be non-NULL (`user_deactivated`, `role_mapping_created`,
    `role_mapping_deleted`, `api_key_created`, `api_key_revoked`).
    `paired` names two optional keys that must be provided together or
    not at all (`role_added`/`role_removed`'s `source`/`mapping`).
    """

    required: frozenset[str] = field(default_factory=frozenset)
    optional: frozenset[str] = field(default_factory=frozenset)
    require_present: bool = False
    paired: tuple[str, str] | None = None


# `source`-only optional schema, shared by every event type whose sole
# optional detail key is the external-sync marker.
_SOURCE_ONLY_SCHEMA: Final = _DetailSchema(optional=frozenset({"source"}))

# Event types not present in this mapping MUST have `detail = NULL`
# (`password_reset`, `manager_changed` — see the detail JSONB Schema
# Contract, "Event types not listed here MUST set detail to NULL").
_DETAIL_SCHEMAS: Final[dict[IdentityAuditEventType, _DetailSchema]] = {
    IdentityAuditEventType.USER_CREATED: _SOURCE_ONLY_SCHEMA,
    IdentityAuditEventType.USER_REACTIVATED: _SOURCE_ONLY_SCHEMA,
    IdentityAuditEventType.USERNAME_CHANGED: _SOURCE_ONLY_SCHEMA,
    IdentityAuditEventType.EMAIL_CHANGED: _SOURCE_ONLY_SCHEMA,
    IdentityAuditEventType.FULL_NAME_CHANGED: _SOURCE_ONLY_SCHEMA,
    IdentityAuditEventType.USER_DEACTIVATED: _DetailSchema(
        required=frozenset({"reason"}),
        optional=frozenset({"source"}),
        require_present=True,
    ),
    IdentityAuditEventType.ROLE_ADDED: _DetailSchema(
        optional=frozenset({"source", "mapping"}),
        paired=("source", "mapping"),
    ),
    IdentityAuditEventType.ROLE_REMOVED: _DetailSchema(
        optional=frozenset({"source", "mapping"}),
        paired=("source", "mapping"),
    ),
    IdentityAuditEventType.ROLE_MAPPING_CREATED: _DetailSchema(
        required=frozenset({"group_name", "role", "affected_users"}),
        require_present=True,
    ),
    IdentityAuditEventType.ROLE_MAPPING_DELETED: _DetailSchema(
        required=frozenset({"group_name", "role", "affected_users"}),
        require_present=True,
    ),
    IdentityAuditEventType.API_KEY_CREATED: _DetailSchema(
        required=frozenset({"key_id"}),
        require_present=True,
    ),
    IdentityAuditEventType.API_KEY_REVOKED: _DetailSchema(
        required=frozenset({"key_id"}),
        optional=frozenset({"reason"}),
        require_present=True,
    ),
}


def _validate_source(value: object) -> None:
    if value != "external_sync":
        raise ValueError("detail.source must be the literal 'external_sync'")


def _validate_string(key: str, value: object) -> None:
    if not isinstance(value, str):
        raise ValueError(f"detail.{key} must be a string")


def _validate_affected_users(value: object) -> None:
    # bool is a subclass of int in Python — explicitly excluded per the
    # detail JSONB Schema Contract ("a boolean is not an integer for
    # this contract").
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError("detail.affected_users must be a non-negative integer")


def _validate_key_id(value: object) -> None:
    if not isinstance(value, str):
        raise ValueError("detail.key_id must be a canonical UUID string")
    try:
        parsed = uuid.UUID(value)
    except ValueError as exc:
        raise ValueError("detail.key_id must be a canonical UUID string") from exc
    if str(parsed) != value:
        raise ValueError("detail.key_id must be a canonical UUID string")


_KEY_VALIDATORS: Final[dict[str, Any]] = {
    "source": _validate_source,
    "mapping": lambda value: _validate_string("mapping", value),
    "group_name": lambda value: _validate_string("group_name", value),
    "role": lambda value: _validate_string("role", value),
    "reason": lambda value: _validate_string("reason", value),
    "affected_users": _validate_affected_users,
    "key_id": _validate_key_id,
}


def _check_field_presence(
    field_name: str,
    value: object,
    rule: str,
    event_type: IdentityAuditEventType,
) -> None:
    if rule == _REQUIRED and value is None:
        raise ValueError(f"{field_name} is required for event type '{event_type}'")
    if rule == _FORBIDDEN and value is not None:
        raise ValueError(f"{field_name} must be NULL for event type '{event_type}'")


def _validate_detail(
    event_type: IdentityAuditEventType,
    detail: Mapping[str, str | int] | None,
) -> None:
    """Validate `detail` against the schema for `event_type`.

    Raises `ValueError` for: a non-mapping value, an empty mapping
    (callers must use `None` instead), an unknown key, a missing
    required key, a paired-key mismatch, a schema mismatch (an event
    type not in `_DETAIL_SCHEMAS` with non-NULL `detail`), a required
    payload that is `NULL`, or any individual key's value failing its
    type/literal validator.
    """
    schema = _DETAIL_SCHEMAS.get(event_type)
    if schema is None:
        if detail is not None:
            raise ValueError(
                f"event type '{event_type}' does not support a detail payload "
                "(must be NULL)"
            )
        return

    if detail is None:
        if schema.require_present:
            raise ValueError(f"event type '{event_type}' requires a detail payload")
        return

    if not isinstance(detail, Mapping):
        raise ValueError("detail must be a JSON object")
    if not detail:
        raise ValueError("detail must not be empty; use None instead")

    allowed_keys = schema.required | schema.optional
    unknown_keys = set(detail) - allowed_keys
    if unknown_keys:
        raise ValueError(
            f"detail contains unsupported keys for event type '{event_type}': "
            f"{sorted(unknown_keys)}"
        )
    missing_keys = schema.required - set(detail)
    if missing_keys:
        raise ValueError(
            f"detail is missing required keys for event type '{event_type}': "
            f"{sorted(missing_keys)}"
        )
    if schema.paired is not None:
        first, second = schema.paired
        if (first in detail) != (second in detail):
            raise ValueError(
                f"detail.{first} and detail.{second} must be provided together "
                f"for event type '{event_type}'"
            )

    for key, value in detail.items():
        _KEY_VALIDATORS[key](value)


def _truncate(value: str | None) -> str | None:
    """Truncate to the first 512 Unicode code points, verbatim.

    No normalization and no ellipsis (see `identity-audit-log.md`,
    Data Model — `old_value`/`new_value`). `None` remains `None`.
    """
    if value is None:
        return None
    return value[:_MAX_VALUE_CODEPOINTS]


def _measure_and_check_detail_size(detail: Mapping[str, str | int]) -> None:
    """Raise `ValueError` if the serialized `detail` exceeds 4096 bytes.

    Serialization is solely for size measurement — the persisted value
    is the original mapping, not this string (see
    `identity-audit-log.md`, `IdentityAuditLog.log_event()`, step 3).
    """
    try:
        serialized = json.dumps(
            detail,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise ValueError(f"detail failed to serialize to JSON: {exc}") from exc
    size = len(serialized.encode("utf-8"))
    if size > _MAX_DETAIL_BYTES:
        raise ValueError(
            f"detail payload of {size} bytes exceeds the {_MAX_DETAIL_BYTES} byte limit"
        )


class IdentityAuditLog(BaseAuditLog):
    """Audit trail for user lifecycle, roles, API keys, and role
    mappings. See `docs/features/identity/identity-audit-log.md`.
    """

    name = "identity"
    description = "User lifecycle, roles, API keys, and role mappings"
    model_class = IdentityAuditEvent

    @classmethod
    async def log_event(  # type: ignore[override]
        cls,
        session: AsyncSession,
        *,
        event_type: IdentityAuditEventType,
        user_id: uuid.UUID | None,
        target_user_id: uuid.UUID | None,
        old_value: str | None = None,
        new_value: str | None = None,
        detail: Mapping[str, str | int] | None = None,
    ) -> None:
        """Create one `IdentityAuditEvent` in the caller's transaction.

        Validates the event-specific required/NULL field combination
        and the `detail` schema (see `_FIELD_RULES` and
        `_DETAIL_SCHEMAS`) before any truncation or size measurement.
        Every violation raises `ValueError`; no event is inserted.
        Never commits or rolls back — flushes the pending insert
        before returning, per `BaseAuditLog.log_event()`.
        """
        if not isinstance(event_type, IdentityAuditEventType):
            raise ValueError(
                "event_type must be an IdentityAuditEventType member, got "
                f"{event_type!r}"
            )

        rules = _FIELD_RULES[event_type]
        _check_field_presence("user_id", user_id, rules["user_id"], event_type)
        _check_field_presence(
            "target_user_id", target_user_id, rules["target_user_id"], event_type
        )
        _check_field_presence("old_value", old_value, rules["old_value"], event_type)
        _check_field_presence("new_value", new_value, rules["new_value"], event_type)
        _validate_detail(event_type, detail)

        truncated_old = _truncate(old_value)
        truncated_new = _truncate(new_value)

        if detail is not None:
            _measure_and_check_detail_size(detail)

        await super().log_event(
            session,
            event_type=event_type.value,
            user_id=user_id,
            target_user_id=target_user_id,
            old_value=truncated_old,
            new_value=truncated_new,
            detail=dict(detail) if detail is not None else None,
        )


@dataclass(frozen=True)
class IdentityAuditEventPage:
    """A page of `IdentityAuditEvent` rows.

    `list_events()` (admin) eagerly loads `actor`/`target_user` on every
    item; `list_user_events()` (self-service) does not, since the
    self-service response never exposes the administrator's identity.
    """

    items: list[IdentityAuditEvent]
    total: int
    page: int
    per_page: int


async def list_events(
    session: AsyncSession,
    *,
    event_types: list[IdentityAuditEventType] | None = None,
    actor: str | None = None,
    target_user: str | None = None,
    from_date: date | datetime | None = None,
    to_date: date | datetime | None = None,
    page: int = 1,
    per_page: int = 20,
) -> IdentityAuditEventPage:
    """Return one page of identity audit events for the admin audit log.

    Q1: `event_types`, when non-empty, restricts to those event types
    (OR). `actor` follows the shared User Identifier Resolution
    contract plus the reserved literal `"system"` for `user_id IS NULL`
    (see `BaseAuditLog.filter_by_actor()`); an unmatched username or
    UUID yields an empty page, never an error. `target_user` selects
    `target_user_id` through the same single user-domain matching
    condition (`user_identifier_condition()`, see
    `docs/features/identity/user-service.md`), embedded in both the
    count and the data statement; an unmatched value yields an empty
    page. `from_date`/`to_date` are
    inclusive bounds, already parsed by the API layer.
    `page`/`per_page` have already passed API schema validation.

    Q3: returns `IdentityAuditEventPage(items, total, page, per_page)`
    with `actor` and `target_user` eagerly loaded on every item, ordered
    `id DESC` (fixed — no client-controlled sort). `id` is a UUIDv7
    value, so this is equivalent to `created_at DESC` with a
    deterministic tiebreak, in a single column. An out-of-range page
    returns an empty `items` list with the correct `total`. No row lock
    or audit event is created.

    Q6: propagates any underlying database exception. Infallible
    otherwise.
    """
    query = select(IdentityAuditEvent)
    count_query = select(func.count()).select_from(IdentityAuditEvent)

    if event_types:
        type_filter = IdentityAuditEvent.event_type.in_(
            [event_type.value for event_type in event_types]
        )
        query = query.where(type_filter)
        count_query = count_query.where(type_filter)

    query = IdentityAuditLog.filter_by_actor(query, actor)
    count_query = IdentityAuditLog.filter_by_actor(count_query, actor)

    if target_user is not None:
        # Uncorrelated and join-free, like `filter_by_actor()`: it never
        # binds to an outer `User` and never multiplies rows.
        matching_user_ids = (
            select(User.id)
            .where(user_identifier_condition(target_user))
            .correlate(None)
        )
        target_filter = IdentityAuditEvent.target_user_id.in_(matching_user_ids)
        query = query.where(target_filter)
        count_query = count_query.where(target_filter)

    query = IdentityAuditLog.apply_date_filters(query, from_date, to_date)
    count_query = IdentityAuditLog.apply_date_filters(count_query, from_date, to_date)

    total = (await session.execute(count_query)).scalar_one()

    data_query = (
        query.options(
            selectinload(IdentityAuditEvent.actor),
            selectinload(IdentityAuditEvent.target_user),
        )
        .order_by(IdentityAuditEvent.id.desc())
        .offset((page - 1) * per_page)
        .limit(per_page)
    )
    items = list((await session.execute(data_query)).scalars().all())
    return IdentityAuditEventPage(
        items=items, total=total, page=page, per_page=per_page
    )


async def list_user_events(
    session: AsyncSession,
    *,
    user_id: uuid.UUID,
    event_types: list[IdentityAuditEventType] | None = None,
    from_date: date | datetime | None = None,
    to_date: date | datetime | None = None,
    page: int = 1,
    per_page: int = 20,
) -> IdentityAuditEventPage:
    """Return one page of identity audit events targeting `user_id`, for
    the self-service audit log.

    Q1: `user_id` is the authenticated caller's own ID — this scope is
    mandatory and is not exposed as a query parameter. Other parameters
    match `list_events()`, minus `actor`/`target_user` (not available on
    this endpoint).

    Q3: returns only events where `target_user_id == user_id` (events
    with `target_user_id IS NULL` are inherently excluded by this
    condition), ordered `id DESC` (fixed). `id` is a UUIDv7 value, so
    this is equivalent to `created_at DESC` with a deterministic
    tiebreak, in a single column. An out-of-range page returns an empty
    `items` list with the correct `total`. The `actor` relationship is
    deliberately not loaded — this endpoint renders `actor` as an
    anonymized string, never the administrator's identity. No row lock
    or audit event is created.

    Q6: propagates any underlying database exception. Infallible
    otherwise.
    """
    target_filter = IdentityAuditEvent.target_user_id == user_id
    query = select(IdentityAuditEvent).where(target_filter)
    count_query = (
        select(func.count()).select_from(IdentityAuditEvent).where(target_filter)
    )

    if event_types:
        type_filter = IdentityAuditEvent.event_type.in_(
            [event_type.value for event_type in event_types]
        )
        query = query.where(type_filter)
        count_query = count_query.where(type_filter)

    query = IdentityAuditLog.apply_date_filters(query, from_date, to_date)
    count_query = IdentityAuditLog.apply_date_filters(count_query, from_date, to_date)

    total = (await session.execute(count_query)).scalar_one()

    data_query = (
        query.order_by(IdentityAuditEvent.id.desc())
        .offset((page - 1) * per_page)
        .limit(per_page)
    )
    items = list((await session.execute(data_query)).scalars().all())
    return IdentityAuditEventPage(
        items=items, total=total, page=page, per_page=per_page
    )
