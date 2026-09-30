"""API key lifecycle, query, and audit service.

See `docs/features/identity/api-key-service.md` for the authoritative
contract this module implements: actor/owner semantics, transaction
ownership, locking, status derivation, and the full operation list.
`docs/features/identity/api-key-management.md` owns the user/operator-
facing lifecycle rules (key format, name rule, derived status
precedence, anomaly warning) this module realizes.

Module-level defaults (`docs/conventions.md`, Function Specification
Completeness): every function propagates the exceptions listed in the
"Service Exceptions" table below plus whatever
`SQLAlchemyError`/generic exception the database driver raises — no
function defines a broader hierarchy than documented. Read-only
functions (`get_key_by_hash()`, `list_user_keys()`, `list_all_keys()`,
`count_non_revoked_keys()`, `list_user_keys_for_cli()`) acquire no
`FOR UPDATE` lock and create no `IdentityAuditEvent`. All functions
that evaluate derived status take one UTC `now` snapshot per
invocation (an explicit `now` parameter when the caller supplies one,
otherwise `datetime.now(UTC)`) and use it for every status calculation
in that call.

Out of scope for this module (see `docs/features/identity/api-key-service.md`,
Purpose): API endpoints, request/response schemas, endpoint
authorization, and API-key authentication validation — these remain
owned by `docs/features/identity/authentication.md`, which is the sole
caller of `update_last_used_at()` below.
"""

from __future__ import annotations

import hashlib
import re
import secrets
import string
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, cast
from uuid import UUID

import structlog
from sqlalchemy import ColumnElement, and_, func, nullslast, or_, select, update
from sqlalchemy.engine import CursorResult
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.enums import (
    ApiKeySortField,
    ApiKeyStatus,
    IdentityAuditEventType,
    SortOrder,
)
from app.core.exceptions import InactiveUserError, ServiceError, UserNotFoundError
from app.models.api_key import ApiKey
from app.models.user import User
from app.services.identity_audit_log import IdentityAuditLog

logger = structlog.get_logger(__name__)

# API Key Name Rule (api-key-management.md): trim, lowercase, 1-128
# characters, [a-z0-9._-] only.
_MAX_NAME_LENGTH = 128
_NAME_PATTERN = re.compile(r"^[a-z0-9._-]+$")

# Key Format and Visibility (api-key-management.md): `stl_ak_` plus 32
# cryptographically random alphanumeric characters.
_KEY_PREFIX = "stl_ak_"
_RANDOM_SUFFIX_LENGTH = 32
_RANDOM_ALPHABET = string.ascii_letters + string.digits
_DISPLAY_PREFIX_LENGTH = 12

# Active-Key Anomaly Warning (api-key-management.md): threshold beyond
# which the safe structured WARNING is emitted.
_ACTIVE_KEY_WARNING_THRESHOLD = 20

# Name of the partial unique index that is the concurrency authority
# for normalized-name creation races (data-model.md, ApiKey Indexes).
_UNIQUE_NAME_CONSTRAINT = "uq_api_key_user_id_name_active"


class ApiKeyServiceError(ServiceError):
    """Base for all `api_key_service`-specific exceptions."""


class ApiKeyNotFoundError(ApiKeyServiceError):
    """No key matches the given `key_id` (and optional owner restriction).

    The message is intentionally static and never includes `key_id` or
    any owner identifier — a key belonging to another owner is
    deliberately indistinguishable from a missing key (see
    `api-key-service.md`, `revoke_key()` Guard).
    """

    def __init__(self) -> None:
        super().__init__("API key not found.")


class ApiKeyNameConflictError(ApiKeyServiceError):
    """A non-revoked key already uses the normalized name for this owner.

    Raised both for the sequential pre-check and for the concurrent
    race resolved by the partial unique index (see `create_key()`).
    """

    def __init__(self) -> None:
        super().__init__("An active API key with this name already exists.")


class ApiKeyNameValidationError(ApiKeyServiceError):
    """The normalized name violates the API Key Name Rule.

    The message never includes the rejected name.
    """

    def __init__(self) -> None:
        super().__init__("API key name is invalid.")


class ApiKeyInvalidExpiryError(ApiKeyServiceError):
    """`expires_at` is not strictly later than the operation's `now`."""

    def __init__(self) -> None:
        super().__init__("API key expiration must be strictly in the future.")


@dataclass(frozen=True)
class CreatedApiKey:
    """The result of `create_key()`: the persisted `ApiKey` and the
    plaintext key as a separate transient string. The plaintext is
    never assigned to a model field and cannot be recovered by any
    later read.
    """

    api_key: ApiKey
    plaintext_key: str = field(repr=False)


@dataclass(frozen=True)
class ApiKeyPage:
    """A page of `ApiKey` rows for one owner (`list_user_keys()`)."""

    items: list[ApiKey]
    total: int
    page: int
    per_page: int


@dataclass(frozen=True)
class ApiKeyWithOwner:
    """An `ApiKey` plus the owner `User` record needed to render the
    standard `owner` User Reference Object."""

    api_key: ApiKey
    owner: User


@dataclass(frozen=True)
class ApiKeyWithOwnerPage:
    """A page of `ApiKeyWithOwner` rows across all owners
    (`list_all_keys()`)."""

    items: list[ApiKeyWithOwner]
    total: int
    page: int
    per_page: int


@dataclass(frozen=True)
class ApiKeyCliList:
    """The result of `list_user_keys_for_cli()`: every key for one user
    plus the single status snapshot the caller must reuse for every
    displayed row."""

    items: list[ApiKey]
    evaluated_at: datetime


def derive_api_key_status(api_key: ApiKey, now: datetime) -> ApiKeyStatus:
    """Derive the exclusive lifecycle status of `api_key` at `now`.

    Q1: `api_key` is the row to classify; `now` is the caller's single
    UTC snapshot for this invocation.

    Q3: precedence per `api-key-management.md` (Derived Status):
    `revoked` when `revoked_at IS NOT NULL`; otherwise `expired` when
    `expires_at IS NOT NULL AND expires_at <= now`; otherwise `active`.
    A key with `expires_at` exactly equal to `now` is expired.

    Q6: infallible — no exception is raised.
    """
    if api_key.revoked_at is not None:
        return ApiKeyStatus.REVOKED
    if api_key.expires_at is not None and api_key.expires_at <= now:
        return ApiKeyStatus.EXPIRED
    return ApiKeyStatus.ACTIVE


def _normalize_name(name: str) -> str:
    """Apply the API Key Name Rule (trim, lowercase, length, charset).

    Raises `ApiKeyNameValidationError` for a value that is empty after
    trimming, exceeds 128 characters, or contains any character outside
    `[a-z0-9._-]`.
    """
    normalized = name.strip().lower()
    if not (1 <= len(normalized) <= _MAX_NAME_LENGTH) or not _NAME_PATTERN.fullmatch(
        normalized
    ):
        raise ApiKeyNameValidationError()
    return normalized


def _generate_plaintext_key() -> str:
    """Generate `stl_ak_` plus 32 CSPRNG alphanumeric characters."""
    suffix = "".join(
        secrets.choice(_RANDOM_ALPHABET) for _ in range(_RANDOM_SUFFIX_LENGTH)
    )
    return f"{_KEY_PREFIX}{suffix}"


def _hash_key(plaintext_key: str) -> str:
    """Compute the lowercase hexadecimal SHA-256 digest of `plaintext_key`."""
    return hashlib.sha256(plaintext_key.encode("utf-8")).hexdigest()


def _is_name_conflict(exc: IntegrityError) -> bool:
    """Whether `exc` originates from the partial unique name index.

    Inspects the underlying DBAPI exception's `constraint_name`
    (populated by asyncpg for integrity constraint violations) rather
    than matching on message text, so unrelated integrity errors (the
    SHA-256 hash format check, the global `key_hash` uniqueness
    constraint, or a foreign key violation) are never misclassified as
    a name conflict. The raw `asyncpg.exceptions.PostgresError` that
    carries `constraint_name` is read through SQLAlchemy's public
    `DBAPIError.driver_exception`, which resolves the asyncpg dialect's
    emulated DBAPI wrapper.
    """
    constraint_name = getattr(exc.driver_exception, "constraint_name", None)
    return bool(constraint_name == _UNIQUE_NAME_CONSTRAINT)


def _active_predicate(now: datetime) -> ColumnElement[bool]:
    return and_(
        ApiKey.revoked_at.is_(None),
        or_(ApiKey.expires_at.is_(None), ApiKey.expires_at > now),
    )


def _expired_predicate(now: datetime) -> ColumnElement[bool]:
    return and_(
        ApiKey.revoked_at.is_(None),
        ApiKey.expires_at.isnot(None),
        ApiKey.expires_at <= now,
    )


def _revoked_predicate() -> ColumnElement[bool]:
    return ApiKey.revoked_at.isnot(None)


def _status_predicate(status: ApiKeyStatus, now: datetime) -> ColumnElement[bool]:
    if status is ApiKeyStatus.ACTIVE:
        return _active_predicate(now)
    if status is ApiKeyStatus.EXPIRED:
        return _expired_predicate(now)
    return _revoked_predicate()


def _sort_clauses(
    sort_by: ApiKeySortField, sort_order: SortOrder
) -> list[ColumnElement[Any]]:
    """Deterministic ORDER BY clauses: the requested field plus the
    primary-key tiebreaker in the same direction (`api-spec.md`,
    Sorting). `last_used_at` NULLs sort last in both directions
    (`api-key-management.md`, API); `created_at` is never NULL, so
    `nullslast()` is a no-op there.

    `sort_by=created_at` is translated to `ApiKey.id` alone: `id` is a
    UUIDv7 value, so it is monotonically time-ordered and reproduces
    `created_at` ordering while querying the primary-key index directly
    instead of the separate `created_at` column (`docs/conventions.md`,
    SQLAlchemy Conventions). The API contract is unchanged — `created_at`
    remains a valid `sort_by` value and the tiebreaker is redundant with
    the sort column itself, so it is omitted.
    """
    if sort_by is ApiKeySortField.CREATED_AT:
        return [ApiKey.id.asc()] if sort_order is SortOrder.ASC else [ApiKey.id.desc()]
    if sort_order is SortOrder.ASC:
        return [nullslast(ApiKey.last_used_at.asc()), ApiKey.id.asc()]
    return [nullslast(ApiKey.last_used_at.desc()), ApiKey.id.desc()]


async def _resolve_owner_id(session: AsyncSession, owner: str) -> UUID | None:
    """Resolve an admin list `owner` filter value to a `User.id`.

    A UUID-shaped value is used directly as the filter — a
    non-existent user ID naturally matches zero `ApiKey` rows, which is
    observably identical to an explicit "no such user" result. A
    non-UUID value is resolved via an exact, case-sensitive `username`
    lookup; `None` is returned when it matches no user, which the
    caller must render as an empty page rather than an unfiltered one.
    """
    try:
        return UUID(owner)
    except ValueError:
        pass
    result = await session.execute(select(User.id).where(User.username == owner))
    return result.scalar_one_or_none()


async def _has_conflicting_name(
    session: AsyncSession, owner_id: UUID, normalized_name: str
) -> bool:
    """Whether a non-revoked key named `normalized_name` already exists
    for `owner_id`.

    This is the sequential pre-check in `create_key()` — an early
    semantic error, not the concurrency guarantee. The partial unique
    index (`uq_api_key_user_id_name_active`) is the authority for a
    genuine concurrent race; a caller that could miss a concurrent
    insert between this check and the insert still gets a correct
    `ApiKeyNameConflictError` via the savepoint's `IntegrityError`
    translation.
    """
    result = await session.execute(
        select(ApiKey.id).where(
            ApiKey.user_id == owner_id,
            ApiKey.name == normalized_name,
            ApiKey.revoked_at.is_(None),
        )
    )
    return result.scalar_one_or_none() is not None


async def _load_key_with_owner(session: AsyncSession, key_id: UUID) -> ApiKeyWithOwner:
    """Load one `ApiKey` with its owner and nullable revoker eagerly
    populated, for API serialization after a lifecycle mutation."""
    result = await session.execute(
        select(ApiKey)
        .where(ApiKey.id == key_id)
        .options(selectinload(ApiKey.user), selectinload(ApiKey.revoking_user))
    )
    api_key = result.scalar_one()
    return ApiKeyWithOwner(api_key=api_key, owner=api_key.user)


async def create_key(
    session: AsyncSession,
    user_id: UUID,
    name: str,
    expires_at: datetime | None,
) -> CreatedApiKey:
    """Create a self-service API key for `user_id`.

    Q1: `session` is the caller's transaction; `user_id` is both owner
    and audit actor (self-service only — there is no separate actor or
    administrator creation path); `name` is the raw requested label;
    `expires_at`, when not `None`, MUST be a timezone-aware UTC
    datetime (naive-to-UTC interpretation and offset conversion are the
    API schema boundary's responsibility, per `docs/conventions.md`,
    Timestamps & Timezones — this function does not repeat that
    normalization).

    Q2 (guards, in this order): missing owner raises
    `UserNotFoundError`; inactive owner raises `InactiveUserError`;
    a name violating the API Key Name Rule raises
    `ApiKeyNameValidationError`; `expires_at <= now` raises
    `ApiKeyInvalidExpiryError`; an existing non-revoked key with the
    same normalized name raises `ApiKeyNameConflictError` (both as a
    sequential pre-check here and, when concurrently lost, via the
    partial unique index below).

    Q3: locks the owner `User` row with `SELECT ... FOR NO KEY UPDATE`
    as the first database operation and validates existence/active
    status under that lock — this serializes creation with user
    deactivation and bulk revocation, so a key cannot commit for an
    inactive user. `FOR NO KEY UPDATE` is sufficient because these
    operations never modify `User.id`; it remains compatible with the
    `FOR KEY SHARE` locks PostgreSQL acquires when validating foreign
    keys that reference `User.id`. Normalizes `name`,
    validates `expires_at`, and pre-checks the normalized name. Then
    generates `stl_ak_` plus 32 CSPRNG alphanumeric characters, computes
    its lowercase hexadecimal SHA-256 digest, and inserts the row with
    the first 12 characters as `prefix`. The insert runs inside a
    SAVEPOINT (`session.begin_nested()`) so that a concurrent same-name
    winner's `IntegrityError` on the partial unique index can be
    translated to `ApiKeyNameConflictError` without discarding any
    other pending work in the caller's transaction — the two guard
    queries above already flush that work via autoflush before the
    SAVEPOINT begins. After the insert, counts the owner's `active`
    keys (same `now` snapshot) and emits the safe
    `api_key_active_count_exceeded` WARNING when the count exceeds 20.
    Finally creates and flushes one `api_key_created`
    `IdentityAuditEvent` (actor = target = owner, `new_value` =
    normalized name, `detail = {"key_id": ...}`).

    Q4: creates exactly one `api_key_created` event, described above.

    Q5: not idempotent in general — a different available name creates
    another key. Re-invocation while the same normalized name remains
    non-revoked raises `ApiKeyNameConflictError`; concurrent same-name
    calls have the same outcome (one creation and one audit event
    total).

    Q6: propagates `UserNotFoundError`, `InactiveUserError`,
    `ApiKeyNameValidationError`, `ApiKeyInvalidExpiryError`,
    `ApiKeyNameConflictError`, and any underlying database or
    audit-service exception not translated above.
    """
    now = datetime.now(UTC)

    owner_result = await session.execute(
        select(User)
        .where(User.id == user_id)
        .with_for_update(key_share=True)
        .execution_options(populate_existing=True)
    )
    owner = owner_result.scalar_one_or_none()
    if owner is None:
        raise UserNotFoundError()
    if not owner.active:
        raise InactiveUserError()

    normalized_name = _normalize_name(name)

    if expires_at is not None and expires_at <= now:
        raise ApiKeyInvalidExpiryError()

    if await _has_conflicting_name(session, owner.id, normalized_name):
        raise ApiKeyNameConflictError()

    plaintext_key = _generate_plaintext_key()
    new_key = ApiKey(
        user_id=owner.id,
        key_hash=_hash_key(plaintext_key),
        prefix=plaintext_key[:_DISPLAY_PREFIX_LENGTH],
        name=normalized_name,
        expires_at=expires_at,
    )

    try:
        async with session.begin_nested():
            session.add(new_key)
            await session.flush()
    except IntegrityError as exc:
        if _is_name_conflict(exc):
            raise ApiKeyNameConflictError() from exc
        raise

    active_count_result = await session.execute(
        select(func.count())
        .select_from(ApiKey)
        .where(ApiKey.user_id == owner.id, _active_predicate(now))
    )
    active_count = active_count_result.scalar_one()
    if active_count > _ACTIVE_KEY_WARNING_THRESHOLD:
        logger.warning(
            "api_key_active_count_exceeded",
            user_id=str(owner.id),
            active_key_count=active_count,
            threshold=_ACTIVE_KEY_WARNING_THRESHOLD,
        )

    await IdentityAuditLog.log_event(
        session,
        event_type=IdentityAuditEventType.API_KEY_CREATED,
        user_id=owner.id,
        target_user_id=owner.id,
        new_value=normalized_name,
        detail={"key_id": str(new_key.id)},
    )

    return CreatedApiKey(api_key=new_key, plaintext_key=plaintext_key)


async def revoke_key(
    session: AsyncSession,
    key_id: UUID,
    acting_user_id: UUID | None,
    owner_user_id: UUID | None = None,
) -> ApiKeyWithOwner:
    """Revoke one API key by ID, optionally restricted to one owner.

    Q1: `key_id` identifies the key; `acting_user_id` is the audit
    actor and `revoked_by` value (a UUID for self-service/admin, `None`
    for CLI/system); `owner_user_id`, when not `None`, restricts the
    match to that owner (self-service callers pass their own ID;
    administrator and CLI callers pass `None`).

    Q2: if no row matches `key_id` and the optional owner restriction,
    raises `ApiKeyNotFoundError` — a key belonging to another owner is
    deliberately indistinguishable from a missing key.

    Q3: selects the key with `SELECT ... FOR UPDATE` (optionally
    filtered by `owner_user_id`) as the first database operation. If
    already revoked, returns the current row unchanged — `revoked_by`
    is not touched and no audit event is created. Otherwise sets
    `revoked_at` to this operation's UTC `now` and `revoked_by` to
    `acting_user_id`, flushes, and creates one `api_key_revoked` event
    (actor = `acting_user_id`, target = key owner, `old_value` =
    normalized key name, `detail = {"key_id": ...}`). In both cases,
    returns the key with its owner and nullable revoker eagerly loaded
    for API serialization.

    Q4: creates exactly one `api_key_revoked` event on the first
    effective revocation; the idempotent no-op path creates none.

    Q5: idempotent. The row lock serializes concurrent single,
    administrator, CLI, and bulk revocation of the same key — exactly
    the first transaction that observes `revoked_at IS NULL` mutates
    the key and creates one event; later or concurrent calls return the
    committed revoked state with no additional event.

    Q6: propagates `ApiKeyNotFoundError` and any underlying database or
    audit-service exception.
    """
    filters: list[ColumnElement[bool]] = [ApiKey.id == key_id]
    if owner_user_id is not None:
        filters.append(ApiKey.user_id == owner_user_id)

    result = await session.execute(
        select(ApiKey)
        .where(*filters)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    api_key = result.scalar_one_or_none()
    if api_key is None:
        raise ApiKeyNotFoundError()

    if api_key.revoked_at is None:
        now = datetime.now(UTC)
        api_key.revoked_at = now
        api_key.revoked_by = acting_user_id
        await session.flush()

        await IdentityAuditLog.log_event(
            session,
            event_type=IdentityAuditEventType.API_KEY_REVOKED,
            user_id=acting_user_id,
            target_user_id=api_key.user_id,
            old_value=api_key.name,
            detail={"key_id": str(api_key.id)},
        )

    return await _load_key_with_owner(session, api_key.id)


async def revoke_all_user_keys(
    session: AsyncSession,
    user_id: UUID,
    acting_user_id: UUID | None,
) -> int:
    """Revoke every non-revoked key for `user_id`, including expired keys.

    This is a user-deactivation side effect; it does not use the
    derived `active` status as its scope — expired-but-not-revoked keys
    are revoked too.

    Q1: `user_id` identifies the owner; `acting_user_id` is the audit
    actor and `revoked_by` value for every revoked key.

    Q2: missing user raises `UserNotFoundError`.

    Q3: locks the `User` row with `FOR NO KEY UPDATE` as the first
    database operation (`user_service.deactivate_user()` already holds
    a conflicting lock in the same transaction, so reacquisition is
    immediate). Selects every key with `revoked_at IS NULL` for that
    user, in deterministic `id` order, with `FOR UPDATE` — the user
    lock serializes concurrent bulk operations and the deterministic
    key ordering serializes each row with `revoke_key()`. Sets one
    shared `revoked_at` snapshot and
    `revoked_by = acting_user_id` on every selected key, flushes, then
    creates one `api_key_revoked` event per key (actor, target, and old
    value as in `revoke_key()`, plus
    `detail = {"key_id": ..., "reason": "user_deactivated"}`).

    Q4: creates one `api_key_revoked` event per newly revoked key; zero
    events when there are no eligible keys.

    Q5: idempotent — no matching rows returns zero and creates no
    event. Concurrent single or bulk revocations still produce one
    mutation and event per key, because every path locks the same key
    row before checking `revoked_at`.

    Q6: propagates `UserNotFoundError` and any underlying database or
    audit-service exception.
    """
    owner_result = await session.execute(
        select(User).where(User.id == user_id).with_for_update(key_share=True)
    )
    if owner_result.scalar_one_or_none() is None:
        raise UserNotFoundError()

    keys_result = await session.execute(
        select(ApiKey)
        .where(ApiKey.user_id == user_id, ApiKey.revoked_at.is_(None))
        .order_by(ApiKey.id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    keys = list(keys_result.scalars().all())
    if not keys:
        return 0

    now = datetime.now(UTC)
    for api_key in keys:
        api_key.revoked_at = now
        api_key.revoked_by = acting_user_id
    await session.flush()

    for api_key in keys:
        await IdentityAuditLog.log_event(
            session,
            event_type=IdentityAuditEventType.API_KEY_REVOKED,
            user_id=acting_user_id,
            target_user_id=api_key.user_id,
            old_value=api_key.name,
            detail={"key_id": str(api_key.id), "reason": "user_deactivated"},
        )

    return len(keys)


async def get_key_by_hash(session: AsyncSession, key_hash: str) -> ApiKey | None:
    """Return the key whose stored digest exactly matches `key_hash`.

    Q1: `key_hash` is the lowercase hexadecimal SHA-256 digest computed
    by the authentication boundary from a presented credential.

    Q3: returns the matching `ApiKey`, or `None` when no key matches.
    Performs no lock, mutation, or audit event. This read is used only
    by the authentication boundary; lifecycle validation (revocation,
    expiry) remains there — callers must not use this read as a
    substitute for `revoke_key()`.

    Q6: propagates any database exception.
    """
    result = await session.execute(select(ApiKey).where(ApiKey.key_hash == key_hash))
    return result.scalar_one_or_none()


async def list_user_keys(
    session: AsyncSession,
    user_id: UUID,
    status: ApiKeyStatus | None,
    page: int,
    per_page: int,
    sort_by: ApiKeySortField,
    sort_order: SortOrder,
    now: datetime | None = None,
) -> ApiKeyPage:
    """Return one page of `user_id`'s own API keys.

    Q1: `status`, when not `None`, restricts the result to that derived
    status. `page`/`per_page`/`sort_by`/`sort_order` have already
    passed API schema validation. `now`, when supplied, is the shared
    UTC snapshot for status filtering; otherwise this call captures its
    own `datetime.now(UTC)`.

    Q3: validates that `user_id` exists, then returns only that user's
    matching keys, ordered per `sort_by`/`sort_order` with the
    deterministic primary-key tiebreaker and `last_used_at` NULL-last
    placement. An out-of-range page returns empty `items` with the
    correct `total`. No row lock or audit event is created.

    Q6: propagates `UserNotFoundError` when `user_id` does not exist,
    and any underlying database exception.
    """
    resolved_now = now if now is not None else datetime.now(UTC)

    owner_exists = await session.execute(select(User.id).where(User.id == user_id))
    if owner_exists.scalar_one_or_none() is None:
        raise UserNotFoundError()

    filters: list[ColumnElement[bool]] = [ApiKey.user_id == user_id]
    if status is not None:
        filters.append(_status_predicate(status, resolved_now))

    total = (
        await session.execute(select(func.count()).select_from(ApiKey).where(*filters))
    ).scalar_one()

    data_query = (
        select(ApiKey)
        .where(*filters)
        .options(selectinload(ApiKey.revoking_user))
        .order_by(*_sort_clauses(sort_by, sort_order))
        .offset((page - 1) * per_page)
        .limit(per_page)
    )
    items = list((await session.execute(data_query)).scalars().all())

    return ApiKeyPage(items=items, total=total, page=page, per_page=per_page)


async def list_all_keys(
    session: AsyncSession,
    owner: str | None,
    status: ApiKeyStatus | None,
    page: int,
    per_page: int,
    sort_by: ApiKeySortField,
    sort_order: SortOrder,
    now: datetime | None = None,
) -> ApiKeyWithOwnerPage:
    """Return one page of API keys across all owners, with owner records.

    Q1: `owner`, when not `None`, is a user UUID or case-sensitive exact
    username per the shared User Identifier Resolution contract. Other
    parameters match `list_user_keys()`.

    Q3: an unknown `owner` returns an empty page with `total=0` — it is
    not an error. Otherwise applies the same status filtering, sorting,
    NULL placement, and pagination as `list_user_keys()`, across all
    owners. No row lock or audit event is created.

    Q6: propagates any underlying database exception.
    """
    resolved_now = now if now is not None else datetime.now(UTC)

    filters: list[ColumnElement[bool]] = []
    if owner is not None:
        owner_id = await _resolve_owner_id(session, owner)
        if owner_id is None:
            return ApiKeyWithOwnerPage(items=[], total=0, page=page, per_page=per_page)
        filters.append(ApiKey.user_id == owner_id)
    if status is not None:
        filters.append(_status_predicate(status, resolved_now))

    total = (
        await session.execute(select(func.count()).select_from(ApiKey).where(*filters))
    ).scalar_one()

    data_query = (
        select(ApiKey)
        .where(*filters)
        .options(selectinload(ApiKey.user), selectinload(ApiKey.revoking_user))
        .order_by(*_sort_clauses(sort_by, sort_order))
        .offset((page - 1) * per_page)
        .limit(per_page)
    )
    rows = list((await session.execute(data_query)).scalars().all())
    items = [ApiKeyWithOwner(api_key=row, owner=row.user) for row in rows]

    return ApiKeyWithOwnerPage(items=items, total=total, page=page, per_page=per_page)


async def count_non_revoked_keys(session: AsyncSession, user_id: UUID) -> int:
    """Return the number of `user_id`'s keys whose `revoked_at` is NULL.

    Q1: `user_id` is the already-resolved owner; an unknown UUID
    returns zero rather than raising, since the caller has already
    resolved the user (see `user-management.md`, deactivation preview).

    Q3: includes expired keys. No row lock or audit event is created.

    Q6: propagates any underlying database exception.
    """
    result = await session.execute(
        select(func.count())
        .select_from(ApiKey)
        .where(ApiKey.user_id == user_id, ApiKey.revoked_at.is_(None))
    )
    return result.scalar_one()


async def list_user_keys_for_cli(
    session: AsyncSession,
    username: str,
    now: datetime | None = None,
) -> ApiKeyCliList:
    """Return every key for one user, for the `api-key list` CLI command.

    Q1: `username` is trimmed and lowercased before lookup. `now`, when
    supplied, is the shared UTC snapshot; otherwise this call captures
    its own `datetime.now(UTC)`.

    Q3: resolves the user and returns all their keys ordered by `id
    DESC`. `id` is a UUIDv7 value, so this is equivalent to `created_at
    DESC` with a deterministic tiebreak, in a single column. This
    operator-only query is intentionally unpaginated. The result's
    `evaluated_at` is this call's single status snapshot — the CLI must
    not capture a different time per row. No row lock or audit event is
    created.

    Q6: propagates `UserNotFoundError` when the username does not
    resolve, and any underlying database exception.
    """
    normalized_username = username.strip().lower()
    resolved_now = now if now is not None else datetime.now(UTC)

    user_result = await session.execute(
        select(User.id).where(User.username == normalized_username)
    )
    user_id = user_result.scalar_one_or_none()
    if user_id is None:
        raise UserNotFoundError()

    data_query = (
        select(ApiKey)
        .where(ApiKey.user_id == user_id)
        .options(selectinload(ApiKey.revoking_user))
        .order_by(ApiKey.id.desc())
    )
    items = list((await session.execute(data_query)).scalars().all())

    return ApiKeyCliList(items=items, evaluated_at=resolved_now)


async def update_last_used_at(
    session: AsyncSession,
    key_id: UUID,
    used_at: datetime,
) -> bool:
    """Advance `ApiKey.last_used_at` for `key_id`, never moving it backward.

    Q1: `key_id` identifies the key; `used_at` is the authentication
    boundary's UTC snapshot for this successful validation. The
    authentication boundary calls this function at most once per
    minute per key per server instance (see `authentication.md`, API
    key validation step 5) — this function performs no debouncing
    itself.

    Q3: updates the matching row only when its current `last_used_at`
    is `NULL` or strictly earlier than `used_at`; flushes and returns
    `True` when changed. A missing row or a `used_at` that would not
    advance the stored value returns `False` and issues no write. Does
    not lock the row, does not touch any lifecycle field, and creates
    no `IdentityAuditEvent` — this is operational authentication
    metadata, not a lifecycle mutation (see `api-key-management.md`,
    Security and Audit Guarantees).

    Q5: conditionally idempotent — the same or an older `used_at`
    produces no additional write.

    Q6: propagates any underlying database exception.
    """
    result = cast(
        "CursorResult[Any]",
        await session.execute(
            update(ApiKey)
            .where(
                ApiKey.id == key_id,
                or_(ApiKey.last_used_at.is_(None), ApiKey.last_used_at < used_at),
            )
            .values(last_used_at=used_at)
        ),
    )
    await session.flush()
    return result.rowcount > 0
