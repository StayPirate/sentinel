"""Session persistence, liveness cache, invalidation, and cleanup.

See `docs/features/identity/authentication.md` (Session Management) for
the authoritative contract this module implements: session creation,
the Redis liveness cache, single/bulk invalidation, the post-commit
cache purge, and the weekly cleanup operation.

Module-level defaults (`docs/conventions.md`, Function Specification
Completeness): every function in this module propagates only
`RedisError` (caught and handled per-function as documented) and
whatever `SQLAlchemyError`/generic exception the database driver
raises — no function defines its own exception hierarchy. Only
`create_session()` acquires an explicit row lock: as its first database
operation it takes `FOR NO KEY UPDATE` on the target `User` row (the
User root lock that serializes successful login with deactivation and with
password reset — see `docs/features/identity/authentication.md`, Session
creation, and `docs/features/identity/user-service.md`, Session creation
concurrent with deactivation and with password reset).
`invalidate_session()` and
`invalidate_user_sessions()` are single, atomically-guarded conditional
`UPDATE` statements (the row lock is inherent to the `UPDATE` itself,
matching the "operational metadata touch" exemption in
`docs/conventions.md`, Pessimistic Locking Pattern); `is_session_active()`
is read-only; `cleanup_sessions()` is an unconditional bulk delete.
"""

from __future__ import annotations

import uuid
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, cast

import redis.asyncio as redis_asyncio
import structlog
from redis.exceptions import RedisError
from sqlalchemy import delete, or_, select, update
from sqlalchemy.engine import CursorResult
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.core.enums import SessionCreationReason, SessionInvalidationReason
from app.core.jwt import issue_token
from app.models.session import Session
from app.models.user import User

logger = structlog.get_logger(__name__)

_LIVENESS_KEY_PREFIX = "session_liveness:"
_LIVENESS_TTL_SECONDS = 60
_REDIS_OPERATION_TIMEOUT_SECONDS = 2

# Per-process outage-episode suppression state (authentication.md,
# Session liveness check: "The warning suppression state is per server
# process"). Module-level by design — a fresh state per API server
# process. Tests reset it directly (see docs/features/platform/
# testing-strategy.md, Test Independence).
_redis_outage_active = False


def _handle_redis_success() -> None:
    global _redis_outage_active
    _redis_outage_active = False


def _handle_redis_failure() -> None:
    global _redis_outage_active
    if not _redis_outage_active:
        _redis_outage_active = True
        logger.warning("session_redis_unavailable")


def get_session_redis_url() -> str:
    """Return the Redis URL for session-cache operations.

    Performs no I/O — returns the configured `REDIS_URL`. Extracted as
    its own function (rather than reading `settings.redis_url` inline)
    so tests can override the target instance via monkeypatching,
    consistent with the replaceable-boundary requirement in
    `docs/features/platform/testing-strategy.md` (Redis Strategy).
    """
    return settings.redis_url


def _new_redis_client() -> redis_asyncio.Redis:
    """Create a new Redis client for one session-cache operation.

    A fresh client per call, closed by the caller — mirrors
    `health_service._check_redis`'s per-check client lifecycle. Kept as
    its own function so tests can monkeypatch it to simulate
    deterministic `RedisError` failures without touching the shared
    Redis test infrastructure.
    """
    client: redis_asyncio.Redis = redis_asyncio.Redis.from_url(
        get_session_redis_url(),
        decode_responses=True,
        socket_connect_timeout=_REDIS_OPERATION_TIMEOUT_SECONDS,
        socket_timeout=_REDIS_OPERATION_TIMEOUT_SECONDS,
    )
    return client


async def _close_quietly(client: redis_asyncio.Redis) -> None:
    with suppress(RedisError):
        await client.aclose()


@dataclass(frozen=True)
class CreatedSession:
    """The result of `create_session()`: the persisted `Session`, its
    signed JWT, and the JWT's `exp` as a UTC datetime."""

    session: Session
    token: str
    token_expires_at: datetime


async def create_session(
    db: AsyncSession,
    user: User,
    reason: SessionCreationReason,
    *,
    expected_password_hash: str | None,
) -> CreatedSession | None:
    """Create a new active `Session` for `user` and issue its JWT.

    Q1: `db` is the caller's transaction; `user` identifies the target
    row only (neither its pre-lock `active` value nor its pre-lock
    `password_hash` is authoritative, and `user.id` is the only field
    read from it); `reason` is `local_login` or `sso_login` (used only
    for the operational log); `expected_password_hash` is the verified
    credential snapshot — the stored `password_hash` the caller checked
    against the supplied password — or `None` to request no password
    check (SSO).

    Q2: as its first database operation, takes `FOR NO KEY UPDATE` on the
    target `User` row and reloads the locked-current state. No pre-lock
    eligibility value on the passed object is trusted. Returns `None`
    when the locked-current row is missing, `active = false`, or
    `expected_password_hash` is not `None` and differs from the
    locked-current `password_hash` (a password reset that committed after
    the caller's verification) — no `Session`, no `last_login_at` update,
    no token, no log. This is an in-process ineligibility outcome, not an
    API error (the provider workflow maps it to its own documented login
    failure).

    Q3: for an eligible locked-current User, uses one UTC `login_at`
    snapshot for `user.last_login_at`, the persisted
    `Session.expires_at`, and the JWT `iat`/`session_deadline` claims.
    Creates a distinct active `Session` without reading, invalidating, or
    otherwise touching any existing session for the user. Flushes both
    writes, then issues the JWT from the flushed `session.id`. Emits
    `session_created` at INFO with `user_id` and `reason` — the JWT and
    session ID are never logged.

    Q4: creates no `IdentityAuditEvent` (session creation is outside
    the identity audit trail scope).

    Q5: not idempotent — every eligible invocation creates another
    independent `Session` row and JWT.

    Q6: propagates any exception from the lock/select, the flush (e.g. a
    database constraint violation), or JWT encoding; none is caught here.
    The caller rolls back both the new session and `last_login_at`
    together. Performs no Redis, bcrypt, network, or other forbidden
    work while the lock is held (`docs/conventions.md`, Transaction
    Hygiene Rules).
    """
    locked_result = await db.execute(
        select(User)
        .where(User.id == user.id)
        .with_for_update(key_share=True)
        .execution_options(populate_existing=True)
    )
    locked_user = locked_result.scalar_one_or_none()
    if (
        locked_user is None
        or not locked_user.active
        or (
            expected_password_hash is not None
            and locked_user.password_hash != expected_password_hash
        )
    ):
        return None

    login_at = datetime.now(UTC)
    session_deadline = login_at + timedelta(days=settings.session_max_lifetime_days)
    session = Session(user_id=locked_user.id, expires_at=session_deadline)
    db.add(session)
    locked_user.last_login_at = login_at
    await db.flush()

    issued = issue_token(
        user_id=locked_user.id,
        session_id=session.id,
        issued_at=login_at,
        session_deadline=session_deadline,
        jwt_expiry_hours=settings.jwt_expiry_hours,
        secret_key=settings.jwt_secret_key.get_secret_value(),
    )
    logger.info("session_created", user_id=str(locked_user.id), reason=reason.value)
    return CreatedSession(
        session=session, token=issued.token, token_expires_at=issued.token_expires_at
    )


async def is_session_active(db: AsyncSession, session_id: uuid.UUID) -> bool:
    """Check whether `session_id` is currently active.

    Q1: `session_id` is the `Session.id` to check.

    Q3: a Redis cache hit with value `"1"` returns `True` without a
    database query. A cache miss or any other cached value falls back
    to a database lookup: an absent row or `is_active = false` returns
    `False`; `is_active = true` writes the positive cache entry
    (`session_liveness:{session_id}`, value `"1"`, TTL 60s) and returns
    `True`. A `RedisError` on the read is treated as a cache miss (falls
    back to the database); a `RedisError` on the positive-cache write
    does not change the `True` result. Both cases apply the shared
    outage-episode warning rule.

    Q6: propagates any database exception (e.g. `SQLAlchemyError`) from
    the fallback query; never catches it.
    """
    key = f"{_LIVENESS_KEY_PREFIX}{session_id}"
    client = _new_redis_client()
    try:
        try:
            cached = await client.get(key)
        except RedisError:
            _handle_redis_failure()
            cached = None
        else:
            _handle_redis_success()

        if cached == "1":
            return True

        session = await db.get(Session, session_id)
        if session is None or not session.is_active:
            return False

        try:
            await client.set(key, "1", ex=_LIVENESS_TTL_SECONDS)
        except RedisError:
            _handle_redis_failure()
        else:
            _handle_redis_success()
        return True
    finally:
        await _close_quietly(client)


async def invalidate_session(db: AsyncSession, session_id: uuid.UUID) -> uuid.UUID:
    """Invalidate a single session (used by logout).

    Q1: `session_id` is the `Session.id` to invalidate.

    Q2: no guard raises — an absent or already-inactive row is a
    documented no-op (see Q3), not an error.

    Q3: sets `is_active = false` (and, via the column's `onupdate`,
    `updated_at = now()`) only for the row matching `session_id` AND
    currently `is_active = true`; a missing row or an already-inactive
    row leaves no trace and is not an error. When a row was actually
    invalidated, emits `session_invalidated` at INFO with the row's
    `user_id` and `reason = "logout"`. Always returns `session_id`
    (used by the caller for the post-commit cache purge), regardless of
    whether a row was actually changed.

    Q4: creates no `IdentityAuditEvent`.

    Q5: idempotent — re-invocation with the same `session_id` after the
    first call is a no-op (the row is already inactive).

    Q6: propagates any database exception; performs no Redis I/O.
    """
    result = await db.execute(
        update(Session)
        .where(Session.id == session_id, Session.is_active.is_(True))
        .values(is_active=False)
        .returning(Session.user_id)
    )
    row = result.scalar_one_or_none()
    await db.flush()
    if row is not None:
        logger.info("session_invalidated", user_id=str(row), reason="logout")
    return session_id


async def invalidate_user_sessions(
    db: AsyncSession, user_id: uuid.UUID, reason: SessionInvalidationReason
) -> list[uuid.UUID]:
    """Invalidate all active sessions for a user.

    Q1: `user_id` identifies the user; `reason` is `deactivation` or
    `password_reset`.

    Q2: no guard raises — a user with no active sessions is a
    documented no-op (see Q3), not an error.

    Q3: sets `is_active = false` for every row matching `user_id` AND
    currently `is_active = true`; rows already inactive are untouched.
    Emits `sessions_invalidated` at INFO with `user_id`, the number of
    changed rows, and `reason` — including when the count is zero.
    Returns the list of invalidated `Session.id` values (used by the
    caller for the post-commit cache purge).

    Q4: creates no `IdentityAuditEvent`.

    Q5: idempotent — re-invocation after the first call returns an
    empty list (no remaining active rows to invalidate).

    Q6: propagates any database exception; performs no Redis I/O.
    """
    result = await db.execute(
        update(Session)
        .where(Session.user_id == user_id, Session.is_active.is_(True))
        .values(is_active=False)
        .returning(Session.id)
    )
    session_ids = list(result.scalars().all())
    await db.flush()
    logger.info(
        "sessions_invalidated",
        user_id=str(user_id),
        count=len(session_ids),
        reason=reason.value,
    )
    return session_ids


async def purge_session_cache(session_ids: list[uuid.UUID]) -> None:
    """Post-commit, best-effort Redis purge for invalidated sessions.

    Q1: `session_ids` is the list of `Session.id` values returned by
    `invalidate_session()`/`invalidate_user_sessions()`.

    Q3: for each ID, deletes `session_liveness:{id}`. A `RedisError` on
    any single delete applies the shared outage-episode warning rule
    and does not stop the loop — every remaining ID is still attempted.
    An empty `session_ids` list performs no Redis operation at all (no
    client is even created).

    Q5: idempotent — deleting an already-absent key is a Redis no-op;
    re-invocation with the same IDs has the same (no) effect.

    Q6: never raises — every `RedisError` is caught internally; no
    other exception is expected from this Redis-only operation.
    """
    if not session_ids:
        return
    client = _new_redis_client()
    try:
        for session_id in session_ids:
            key = f"{_LIVENESS_KEY_PREFIX}{session_id}"
            try:
                await client.delete(key)
            except RedisError:
                _handle_redis_failure()
            else:
                _handle_redis_success()
    finally:
        await _close_quietly(client)


async def cleanup_sessions(db: AsyncSession, now: datetime) -> int:
    """Delete every session eligible for cleanup.

    Q1: `now` is one UTC timestamp snapshot used for the deadline
    predicate.

    Q3: deletes every row matching either predicate: `is_active =
    false` (invalidated sessions, deleted immediately — no grace
    period) or `expires_at < now` (deadline-eligible, regardless of
    active status — no buffer). Flushes and returns the number of
    deleted rows. Does not commit or roll back — the caller (the Celery
    task workflow) owns the transaction.

    Q5: idempotent — rows already deleted are simply absent from a
    subsequent invocation's result set; re-invocation with an unchanged
    `now` (or a later one) never re-deletes or errors.

    Q6: propagates any database exception; performs no Redis I/O and
    creates no `IdentityAuditEvent` (sessions are excluded from the
    identity audit trail scope).
    """
    result = cast(
        "CursorResult[Any]",
        await db.execute(
            delete(Session).where(
                or_(Session.is_active.is_(False), Session.expires_at < now)
            )
        ),
    )
    await db.flush()
    return int(result.rowcount)
