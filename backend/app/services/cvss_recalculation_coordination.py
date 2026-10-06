"""Complete-run coordination resources of the all-CVE CVSS recalculation.

See `docs/features/platform/default-cvss-version-operations.md`
(Complete-Run Coordination) for the authoritative contract this module
implements:

- the Redis admission and ownership lease `cvss_recalc_active`: its value
  codec (Coordination Resources) and its three atomic operations
  (Atomic Lease Operations);
- the PostgreSQL execution fence: its stable identifier and the
  session-level acquire and release helpers (Execution Fence); and
- the replaceable Redis URL provider (`docs/features/platform/
  testing-strategy.md`, Redis Strategy).

The lease operations perform no database access; the fence helpers perform
no Redis access. Neither writes an audit record, emits a log event, or
creates persistent state: the callers (the manual admission and the runner
task) own the coordination events and every outcome classification.

Failure model: every `RedisError`, including a timeout after the command
was sent, propagates unchanged from the lease operations. There is no
separate "uncertain" outcome: the specification gives uncertain completion
and `RedisError` the same conservative outcome, which the caller applies.
"""

from __future__ import annotations

import re
from contextlib import suppress
from dataclasses import dataclass
from enum import StrEnum
from typing import Final

import redis.asyncio as redis_asyncio
from redis.asyncio.retry import Retry
from redis.backoff import NoBackoff
from sqlalchemy import BigInteger, func, literal, select
from sqlalchemy.ext.asyncio import AsyncConnection

from app.config import settings
from app.core.enums import CVSSVersion
from app.services.cvss import DEFAULT_CVSS_VERSIONS

LEASE_KEY: Final = "cvss_recalc_active"
"""The application-owned Redis key of the admission and ownership lease."""

LEASE_TTL_SECONDS: Final = 900
"""TTL set by every successful acquisition or renewal (feature constant)."""

LEASE_RENEWAL_INTERVAL_SECONDS: Final = 60
"""Minimum interval between checkpoint renewals (feature constant)."""

LEASE_VALUE_SCHEMA: Final = "v1"
"""The lease value-schema version, the first field of every lease value."""

EXECUTION_FENCE_ID: Final = 0x534E_544C_4356_5353
"""The PostgreSQL advisory-lock key of the recalculation execution fence.

The ASCII bytes `SNTLCVSS` as a signed 64-bit integer. Stable across
releases and reserved for this feature: never change it, never reuse it
for another advisory-lock consumer, and never use a different key for the
fence. The manual admission and the runner request it at session level
through the helpers below; the effective setting mutation requests the
same key in transaction-level, non-blocking form
(`docs/features/platform/system-settings.md`, Setting Mutation Service).
"""

_REDIS_OPERATION_TIMEOUT_SECONDS = 2

_CANONICAL_UUID4 = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
)

_COMPARE_AND_RENEW_SCRIPT: Final = """
local kind = redis.call('TYPE', KEYS[1])['ok']
if kind == 'none' then
    return 0
end
if kind ~= 'string' or redis.call('GET', KEYS[1]) ~= ARGV[1] then
    return -1
end
redis.call('EXPIRE', KEYS[1], ARGV[2])
return 1
"""
"""Reset the TTL only while the key holds the complete expected value.

Returns 1 (renewed), 0 (absent), or -1 (mismatch). A key of another type
is a value that does not parse, so it matches no owner."""

_COMPARE_AND_DELETE_SCRIPT: Final = """
local kind = redis.call('TYPE', KEYS[1])['ok']
if kind == 'none' then
    return 0
end
if kind ~= 'string' or redis.call('GET', KEYS[1]) ~= ARGV[1] then
    return -1
end
redis.call('DEL', KEYS[1])
return 1
"""
"""Delete the key only while it holds the complete expected value.

Returns 1 (deleted), 0 (absent), or -1 (mismatch)."""


class LeaseAcquireOutcome(StrEnum):
    """The closed outcome set of `acquire_lease()`."""

    ACQUIRED = "acquired"
    NOT_ACQUIRED = "not_acquired"


class LeaseRenewOutcome(StrEnum):
    """The closed outcome set of `compare_and_renew_lease()`."""

    RENEWED = "renewed"
    ABSENT = "absent"
    MISMATCH = "mismatch"


class LeaseDeleteOutcome(StrEnum):
    """The closed outcome set of `compare_and_delete_lease()`."""

    DELETED = "deleted"
    ABSENT = "absent"
    MISMATCH = "mismatch"


class FenceAcquireOutcome(StrEnum):
    """The closed outcome set of `try_acquire_execution_fence()`."""

    ACQUIRED = "acquired"
    BUSY = "busy"


class FenceReleaseOutcome(StrEnum):
    """The closed outcome set of `release_execution_fence()`."""

    RELEASED = "released"
    NOT_CONFIRMED = "not_confirmed"


_RENEW_OUTCOMES: Final = {
    1: LeaseRenewOutcome.RENEWED,
    0: LeaseRenewOutcome.ABSENT,
    -1: LeaseRenewOutcome.MISMATCH,
}

_DELETE_OUTCOMES: Final = {
    1: LeaseDeleteOutcome.DELETED,
    0: LeaseDeleteOutcome.ABSENT,
    -1: LeaseDeleteOutcome.MISMATCH,
}


@dataclass(frozen=True, slots=True)
class LeaseValue:
    """A parsed lease value: the owner task ID and the run's target version."""

    task_id: str
    target_version: CVSSVersion


def is_canonical_task_id(value: object) -> bool:
    """Whether `value` is a canonical run identity.

    Canonical means the lowercase hyphenated representation of a UUID
    version 4 with the RFC 9562 variant (Run Identity). Uppercase,
    unhyphenated, braced, URN, and other-version forms are not canonical.
    """
    return isinstance(value, str) and _CANONICAL_UUID4.fullmatch(value) is not None


def _is_target_version(value: object) -> bool:
    return isinstance(value, str) and value in DEFAULT_CVSS_VERSIONS


def encode_lease_value(task_id: str, target_version: str) -> str:
    """Return the complete lease value `v1:<task_id>:<target_version>`.

    Raises `ValueError`, before any Redis command, when `task_id` is not
    canonical or `target_version` is not exactly `"3.1"` or `"4.0"`. The
    value carries no timestamp.
    """
    if not is_canonical_task_id(task_id):
        raise ValueError("lease task ID is not a canonical lowercase UUID version 4")
    if not _is_target_version(target_version):
        raise ValueError("lease target version is not '3.1' or '4.0'")
    return f"{LEASE_VALUE_SCHEMA}:{task_id}:{target_version}"


def decode_lease_value(value: object) -> LeaseValue | None:
    """Parse a stored lease value; `None` for any other shape.

    A value that does not parse matches no owner (Coordination Resources):
    a wrong schema prefix, a non-canonical task ID, an unknown target, and
    extra, missing, or empty fields all return `None`.
    """
    if not isinstance(value, str):
        return None
    fields = value.split(":")
    if len(fields) != 3:
        return None
    schema, task_id, target_version = fields
    if schema != LEASE_VALUE_SCHEMA or not is_canonical_task_id(task_id):
        return None
    if not _is_target_version(target_version):
        return None
    return LeaseValue(task_id=task_id, target_version=CVSSVersion(target_version))


def get_cvss_recalculation_redis_url() -> str:
    """Return the Redis URL of the recalculation lease.

    Performs no I/O — returns the configured `REDIS_URL`. Extracted as its
    own function so tests can redirect the lease operations, consistent
    with the replaceable-boundary requirement in
    `docs/features/platform/testing-strategy.md` (Redis Strategy).
    """
    return settings.redis_url


def new_cvss_recalculation_redis_client() -> redis_asyncio.Redis:
    """Create a Redis client for the lease operations.

    The caller creates and closes the client inside its owning event loop
    and may reuse it for several operations (for example adoption and every
    renewal checkpoint of one delivery). Socket timeouts bound every
    command; a timeout raises `RedisError` whether or not Redis applied it.

    The client never retries a command. The library default would resend a
    command whose reply timed out, and a resent acquire would then report
    `NOT_ACQUIRED` against its own write instead of propagating the
    uncertain completion as `RedisError`.
    """
    client: redis_asyncio.Redis = redis_asyncio.Redis.from_url(
        get_cvss_recalculation_redis_url(),
        decode_responses=True,
        socket_connect_timeout=_REDIS_OPERATION_TIMEOUT_SECONDS,
        socket_timeout=_REDIS_OPERATION_TIMEOUT_SECONDS,
        retry=Retry(NoBackoff(), 0),
    )
    return client


async def acquire_lease(
    client: redis_asyncio.Redis, *, task_id: str, target_version: str
) -> LeaseAcquireOutcome:
    """Acquire the lease with `SET cvss_recalc_active <value> NX EX 900`.

    Returns `ACQUIRED` when the key was absent and the complete value was
    written, or `NOT_ACQUIRED` when any key already exists (including a
    malformed value); `NOT_ACQUIRED` changes nothing, so repeating the call
    while a key exists is a safe no-op. `ValueError` for a non-canonical
    input is raised before any command. `RedisError` propagates unchanged:
    the write may have occurred, so the caller never treats it as success.
    """
    value = encode_lease_value(task_id, target_version)
    written = await client.set(LEASE_KEY, value, nx=True, ex=LEASE_TTL_SECONDS)
    if written:
        return LeaseAcquireOutcome.ACQUIRED
    return LeaseAcquireOutcome.NOT_ACQUIRED


async def compare_and_renew_lease(
    client: redis_asyncio.Redis, *, task_id: str, target_version: str
) -> LeaseRenewOutcome:
    """Atomically reset the lease TTL to 900 seconds if and only if the
    complete stored value equals `v1:<task_id>:<target_version>`.

    Returns `RENEWED`, `ABSENT` (no key), or `MISMATCH` (a different or
    malformed value). It never removes or replaces the value. `ValueError`
    for a non-canonical input is raised before any command. `RedisError`
    propagates unchanged and never confirms ownership.
    """
    value = encode_lease_value(task_id, target_version)
    result = await client.eval(  # type: ignore[misc]
        _COMPARE_AND_RENEW_SCRIPT, 1, LEASE_KEY, value, str(LEASE_TTL_SECONDS)
    )
    return _RENEW_OUTCOMES[int(result)]


async def compare_and_delete_lease(
    client: redis_asyncio.Redis, *, task_id: str, target_version: str
) -> LeaseDeleteOutcome:
    """Atomically delete the lease if and only if the complete stored value
    equals `v1:<task_id>:<target_version>`.

    Returns `DELETED`, `ABSENT`, or `MISMATCH`; `ABSENT` and `MISMATCH`
    delete nothing, so an old owner never removes a newer owner's record,
    and a repeated delete is `ABSENT`. `ValueError` for a non-canonical
    input is raised before any command. `RedisError` propagates unchanged;
    the caller records a cleanup failure and the key expires by its TTL.
    """
    value = encode_lease_value(task_id, target_version)
    result = await client.eval(  # type: ignore[misc]
        _COMPARE_AND_DELETE_SCRIPT, 1, LEASE_KEY, value
    )
    return _DELETE_OUTCOMES[int(result)]


def _require_no_transaction(connection: AsyncConnection) -> None:
    if connection.in_transaction():
        raise RuntimeError("the fenced connection already has an open transaction")


async def _invalidate_quietly(connection: AsyncConnection) -> None:
    """Invalidate `connection` so it never returns to the pool.

    A failure of the invalidation itself is suppressed: the caller is
    already propagating the original error or reporting the failed release.
    """
    with suppress(Exception):
        await connection.invalidate()


async def try_acquire_execution_fence(
    connection: AsyncConnection,
) -> FenceAcquireOutcome:
    """Request the execution fence at session level without waiting.

    `connection` is the caller's dedicated connection, with no open
    transaction (`RuntimeError` otherwise, before any statement). Runs
    `pg_try_advisory_lock` and commits the transaction that statement
    autobegins; the session-level lock survives the commit, so the helper
    returns with no open transaction on the connection.

    Returns `ACQUIRED` or `BUSY`; `BUSY` waits for nothing and holds
    nothing. A database or session error is never reported as `BUSY`: the
    connection is invalidated, because the lock may have been granted
    before the error, and the original exception propagates unchanged.

    While the fence is held, the caller MUST NOT close the connection back
    to the pool: the pool reset only rolls back, and a session-level lock
    survives it. Only `release_execution_fence()` returning `RELEASED`,
    invalidation, backend termination, or process exit releases the fence.
    """
    _require_no_transaction(connection)
    try:
        result = await connection.execute(
            select(func.pg_try_advisory_lock(literal(EXECUTION_FENCE_ID, BigInteger)))
        )
        acquired: bool = result.scalar_one()
        await connection.commit()
    except BaseException:
        await _invalidate_quietly(connection)
        raise
    if acquired:
        return FenceAcquireOutcome.ACQUIRED
    return FenceAcquireOutcome.BUSY


async def release_execution_fence(
    connection: AsyncConnection,
) -> FenceReleaseOutcome:
    """Explicitly release the execution fence held by `connection`.

    `connection` has no open transaction (`RuntimeError` otherwise, before
    any statement). Runs `pg_advisory_unlock` and commits the transaction
    that statement autobegins, so the helper returns with no open
    transaction.

    Returns `RELEASED` only when the unlock result is `true`; only then may
    the caller close the connection back to the pool. A definitive `false`
    invalidates the connection and returns `NOT_CONFIRMED`. Any exception
    during the release (a database error, a timeout, `CancelledError`)
    invalidates the connection and propagates unchanged. Invalidation
    closes the backend session, which releases the fence automatically.
    """
    _require_no_transaction(connection)
    try:
        result = await connection.execute(
            select(func.pg_advisory_unlock(literal(EXECUTION_FENCE_ID, BigInteger)))
        )
        released: bool | None = result.scalar_one()
        await connection.commit()
    except BaseException:
        await _invalidate_quietly(connection)
        raise
    if released is True:
        return FenceReleaseOutcome.RELEASED
    await _invalidate_quietly(connection)
    return FenceReleaseOutcome.NOT_CONFIRMED
