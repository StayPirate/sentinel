"""Local username/password authentication and Redis-backed lockout.

See `docs/features/identity/local-authentication.md` (Login Endpoint,
Rate Limiting / Brute-Force Protection) for the authoritative contract
this module implements: username normalization, the early guards, the
atomic lockout counter, dummy-bcrypt anti-enumeration, and delegation
to `session_service.create_session()` on success.

Module-level defaults (`docs/conventions.md`, Function Specification
Completeness): every function in this module propagates only
`RedisError` (caught and handled per-function, as documented) and
whatever `SQLAlchemyError`/generic exception the database driver
raises for the username lookup — no function defines its own exception
hierarchy. `guard_and_increment()` and `clear_login_attempts()`
acquire no `FOR UPDATE` lock (Redis-only operations).
`authenticate_local_user()` performs no eligibility re-validation of
its own beyond the single lookup, but on success delegates to
`session_service.create_session()`, which acquires the User root lock
and revalidates the locked-current active status before creating
anything (see `docs/features/identity/authentication.md`, Session
creation). A locked-current inactive outcome is mapped to the generic
invalid-credentials failure. `docs/features/identity/authentication.md`
(`get_current_user`, Credential resolution, step 5) independently
re-checks `User.active` on every subsequent authenticated request.
"""

from __future__ import annotations

import asyncio
import math
from contextlib import suppress
from dataclasses import dataclass

import redis.asyncio as redis_asyncio
import structlog
from redis.exceptions import RedisError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.core.enums import SessionCreationReason
from app.core.passwords import (
    MAX_PASSWORD_LENGTH,
    verify_dummy_password,
    verify_password,
)
from app.models.user import User
from app.services.session_service import CreatedSession, create_session

logger = structlog.get_logger(__name__)

_LOCKOUT_KEY_PREFIX = "login_attempts:"
_REDIS_OPERATION_TIMEOUT_SECONDS = 2

# `docs/conventions.md` (Username Format): the stored/normalized
# username length bound. Login step 2 rejects a normalized username
# longer than this before any database lookup or Redis counter
# creation.
_MAX_USERNAME_LENGTH = 64

# Atomically: if the counter is already at or above `max_attempts`,
# return the "Blocked" outcome (0) with the remaining PTTL in
# milliseconds, without modifying the counter or its TTL. Otherwise
# increment the counter, set/renew its TTL to `ttl_seconds`, and return
# the "Admitted" outcome (1) with the new counter value. See
# local-authentication.md (Rate Limiting, Concurrency contract): "The
# guard-and-increment is indivisible... no intermediate state is
# observable by other clients." A Lua script run server-side is the
# implementation mechanism achieving this indivisibility; the contract
# itself does not prescribe it.
_GUARD_AND_INCREMENT_SCRIPT = """
local current = tonumber(redis.call('GET', KEYS[1]) or '0')
local max_attempts = tonumber(ARGV[1])
if current >= max_attempts then
    local ttl_ms = redis.call('PTTL', KEYS[1])
    if ttl_ms < 0 then
        ttl_ms = 0
    end
    return {0, current, ttl_ms}
end
local new_value = redis.call('INCR', KEYS[1])
local ttl_seconds = tonumber(ARGV[2])
redis.call('EXPIRE', KEYS[1], ttl_seconds)
return {1, new_value, ttl_seconds * 1000}
"""


@dataclass(frozen=True)
class LockoutAdmitted:
    """The lockout gate admitted this attempt; the counter (already
    incremented, with its TTL set/renewed) has this new value."""

    attempt_count: int


@dataclass(frozen=True)
class LockoutBlocked:
    """The lockout gate rejected this attempt without verifying a
    password, incrementing the counter, or touching its TTL."""

    retry_after_seconds: int


@dataclass(frozen=True)
class LockoutUnavailable:
    """Redis is unreachable — the caller fails open (skips lockout
    enforcement entirely for this attempt; no counter data exists)."""


LockoutDecision = LockoutAdmitted | LockoutBlocked | LockoutUnavailable


def get_lockout_redis_url() -> str:
    """Return the Redis URL for login-lockout operations.

    Performs no I/O — returns the configured `REDIS_URL`. Extracted as
    its own function so tests can override the target instance via
    monkeypatching, consistent with the replaceable-boundary
    requirement in `docs/features/platform/testing-strategy.md` (Redis
    Strategy).
    """
    return settings.redis_url


def _new_redis_client() -> redis_asyncio.Redis:
    """Create a new Redis client for one lockout operation.

    A fresh client per call, closed by the caller — mirrors
    `session_service._new_redis_client()`'s per-operation client
    lifecycle. Kept as its own function so tests can monkeypatch it to
    simulate deterministic `RedisError` failures without touching the
    shared Redis test infrastructure.
    """
    client: redis_asyncio.Redis = redis_asyncio.Redis.from_url(
        get_lockout_redis_url(),
        decode_responses=True,
        socket_connect_timeout=_REDIS_OPERATION_TIMEOUT_SECONDS,
        socket_timeout=_REDIS_OPERATION_TIMEOUT_SECONDS,
    )
    return client


async def _close_quietly(client: redis_asyncio.Redis) -> None:
    with suppress(RedisError):
        await client.aclose()


async def guard_and_increment(normalized_username: str) -> LockoutDecision:
    """Atomically check-and-advance the lockout counter for a username.

    Q1: `normalized_username` is the already-trimmed, lowercased
    username (empty and overlong values are rejected by the caller
    before this function is ever invoked — see login step 2/3).

    Q3: executes the atomic guard-and-increment operation on
    `login_attempts:{normalized_username}` (see
    `_GUARD_AND_INCREMENT_SCRIPT`). Returns `LockoutBlocked` with the
    remaining TTL in seconds (rounded up, minimum 1) when the counter
    was already at or above `LOGIN_MAX_ATTEMPTS`; returns
    `LockoutAdmitted` with the new counter value otherwise. A
    `RedisError` is caught and logged at WARNING (no PII) and returns
    `LockoutUnavailable` — the fail-open outcome per
    local-authentication.md ("Redis unavailability").

    Q6: never raises — every `RedisError` is caught internally.
    """
    key = f"{_LOCKOUT_KEY_PREFIX}{normalized_username}"
    client = _new_redis_client()
    try:
        try:
            admitted, count, ttl_ms = await client.eval(  # type: ignore[misc]
                _GUARD_AND_INCREMENT_SCRIPT,
                1,
                key,
                str(settings.login_max_attempts),
                str(settings.login_lockout_minutes * 60),
            )
        except RedisError:
            logger.warning("login_lockout_redis_unavailable")
            return LockoutUnavailable()
        if admitted:
            return LockoutAdmitted(attempt_count=int(count))
        retry_after_seconds = max(1, math.ceil(int(ttl_ms) / 1000))
        return LockoutBlocked(retry_after_seconds=retry_after_seconds)
    finally:
        await _close_quietly(client)


async def clear_login_attempts(normalized_username: str) -> None:
    """Delete the lockout counter for a username (post-commit, best effort).

    Q1: `normalized_username` is the username whose counter to clear.

    Q3: deletes `login_attempts:{normalized_username}`. A `RedisError`
    is caught and logged at WARNING (no PII); the caller's already-
    committed login is never affected — see local-authentication.md
    (login step 11): "A failed counter delete may leave a residual
    counter that locks the account until TTL expiry; admin unlock and
    natural TTL expiry are the recovery paths."

    Q5: idempotent — deleting an already-absent key is a Redis no-op.

    Q6: never raises — every `RedisError` is caught internally.
    """
    key = f"{_LOCKOUT_KEY_PREFIX}{normalized_username}"
    client = _new_redis_client()
    try:
        try:
            await client.delete(key)
        except RedisError:
            logger.warning("login_lockout_clear_failed")
    finally:
        await _close_quietly(client)


@dataclass(frozen=True)
class LoginSuccess:
    """Successful local authentication.

    `normalized_username` is exposed so the caller can register the
    post-commit best-effort counter clear (see
    `docs/conventions.md`, Transaction Hygiene Rules) — mirrors how
    `session_service.invalidate_session()` returns `session_id` for the
    logout endpoint's post-commit purge.
    """

    created_session: CreatedSession
    normalized_username: str


@dataclass(frozen=True)
class LoginInvalidCredentials:
    """Generic credential failure — see local-authentication.md,
    Security Considerations: identical for every failure cause."""


@dataclass(frozen=True)
class LoginLocked:
    """The account (normalized username) is currently locked out."""

    retry_after_seconds: int


LocalLoginResult = LoginSuccess | LoginInvalidCredentials | LoginLocked


def _invalid_credentials_failure(
    user: User | None, admitted_count: int | None
) -> LoginInvalidCredentials:
    """Build the generic credential failure and emit the lockout
    transition log when this admitted attempt is the one that reached
    `LOGIN_MAX_ATTEMPTS` (see local-authentication.md, Lockout transition
    logging).

    Shared by the ordinary step-10 failure path and the
    locked-current-inactive outcome of step 11: both are lockout-accounted
    identically, and neither clears the counter. `user` is the step-5
    lookup result, so `user_id` is included only when the username
    resolved to an existing user.
    """
    if admitted_count == settings.login_max_attempts:
        log_kwargs: dict[str, str | int] = {"attempt_count": admitted_count}
        if user is not None:
            log_kwargs["user_id"] = str(user.id)
        logger.info("login_lockout_triggered", **log_kwargs)
    return LoginInvalidCredentials()


async def authenticate_local_user(
    db: AsyncSession, username: str, password: str
) -> LocalLoginResult:
    """Authenticate a local user — see local-authentication.md (Login,
    Behavior) for the full numbered flow this function implements.

    Q1: `db` is the caller's transaction (flushed but never committed
    or rolled back here — the API transaction dependency owns
    completion); `username` and `password` are the raw request field
    values.

    Q2: returns `LoginInvalidCredentials` immediately, before any
    database lookup or Redis counter creation, when: `password` exceeds
    `MAX_PASSWORD_LENGTH` (128) characters; the normalized username
    (trimmed, lowercased) exceeds 64 characters; or the normalized
    username is empty. Returns `LoginLocked` when the lockout gate
    (`guard_and_increment()`) reports `LockoutBlocked` — no password
    verification, no counter increment, no TTL change.

    Q3: on any other outcome, looks up the user by normalized username.
    An unknown username, or a known but ineligible user (inactive,
    external, or no `password_hash`), performs a dummy bcrypt
    verification (`verify_dummy_password()`) and is always a failure.
    An eligible user's password is verified with `verify_password()`
    against the stored hash (bcrypt work for both paths is offloaded
    via `asyncio.to_thread()` so it never blocks the event loop). Every
    failure returns `LoginInvalidCredentials`; when the lockout gate's
    admitted counter value equals exactly `LOGIN_MAX_ATTEMPTS`, emits
    the `login_lockout_triggered` INFO event (with `user_id` when the
    username resolved to an existing user, omitted otherwise) exactly
    once for that failure. On success, delegates to
    `session_service.create_session()`, which acquires the User root
    lock and revalidates the locked-current active state, flushes the
    new `Session` and `User.last_login_at` update, and returns
    `LoginSuccess`. If `create_session()` returns `None` (a deactivation
    committed after the step-7 pre-check), the outcome is the same
    generic `LoginInvalidCredentials` failure as step 10 — including the
    lockout transition rule — with no Session, no `last_login_at`
    update, and no successful-login counter clear.

    Q4: creates no `IdentityAuditEvent` — local login is outside the
    identity audit trail scope (see authentication.md, Session
    creation). `login_lockout_triggered` is an application log, not an
    audit event.

    Q5: not idempotent — each invocation independently advances the
    lockout counter (when the gate admits it) and, on success, creates
    another independent `Session` and JWT.

    Q6: propagates any exception from the underlying database lookup or
    from `session_service.create_session()` (e.g. a flush-time
    constraint violation or JWT encoding failure). Never raises for a
    `RedisError` — `guard_and_increment()` catches it and fails open.
    """
    if len(password) > MAX_PASSWORD_LENGTH:
        return LoginInvalidCredentials()

    normalized_username = username.strip().lower()
    if not normalized_username or len(normalized_username) > _MAX_USERNAME_LENGTH:
        return LoginInvalidCredentials()

    decision = await guard_and_increment(normalized_username)
    if isinstance(decision, LockoutBlocked):
        return LoginLocked(retry_after_seconds=decision.retry_after_seconds)
    admitted_count = (
        decision.attempt_count if isinstance(decision, LockoutAdmitted) else None
    )

    result = await db.execute(select(User).where(User.username == normalized_username))
    user = result.scalar_one_or_none()

    eligible_user: User | None = None
    stored_hash: str | None = None
    if (
        user is not None
        and user.active
        and user.external_id is None
        and user.password_hash is not None
    ):
        eligible_user = user
        stored_hash = user.password_hash

    if stored_hash is not None:
        verified = await asyncio.to_thread(verify_password, password, stored_hash)
    else:
        # Unknown username or ineligible user (inactive, external, no
        # password set): perform equivalent-cost dummy bcrypt work — see
        # local-authentication.md (login flow, steps 6-7).
        await asyncio.to_thread(verify_dummy_password, password)
        verified = False

    if not verified:
        return _invalid_credentials_failure(user, admitted_count)

    # `verified` is only ever True when `eligible_user` was set above.
    assert eligible_user is not None
    created = await create_session(db, eligible_user, SessionCreationReason.LOCAL_LOGIN)
    if created is None:
        # A deactivation committed after the step-7 pre-check: the locked
        # revalidation inside `create_session()` observed the inactive
        # current state and created no Session. This is the same generic
        # login failure as step 10 — the lockout transition is emitted
        # when this admitted attempt reached the threshold, and no
        # successful-login counter clear is registered.
        return _invalid_credentials_failure(user, admitted_count)
    return LoginSuccess(
        created_session=created, normalized_username=normalized_username
    )
