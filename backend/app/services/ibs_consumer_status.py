"""The IBS consumer heartbeat and the consumer status read.

Implements docs/features/integrations/ibs-rabbitmq-integration.md
(Monitoring and Observability > Heartbeat Storage, Consumer States; Status
API; Process Lifecycle > Startup steps 3 and 5, Reconnection status writes
and `reconnect_attempts`, Graceful Shutdown step 5; Per-Delivery
Processing > Settlement Policy counter effects):

- `HeartbeatDocument` is the one heartbeat type shared by the consumer,
  which serializes it (`to_json()`), and the status API, which validates a
  stored value into it (`parse_heartbeat()`). Construction enforces every
  schema invariant, so the consumer can never write an invalid value.
- `ConsumerStatusState` holds the process-scoped status, counters,
  `last_error`, and reconnect fields. The consumer lifecycle changes it only
  through synchronous transition methods; all its timestamps are whole UTC
  seconds from one non-decreasing reading of the clock, so the written
  ordering `process_started_at <= status_since <= heartbeat_at` always
  holds.
- `HeartbeatWriter` publishes the state from its own task: one atomic
  `SET` of the complete JSON value with a 60-second TTL, immediately after
  every change of `status`, `reconnect_attempts`, or `next_retry_seconds`,
  and otherwise every 30 seconds. The lifecycle never awaits it. A
  `RedisError` or an exceeded write bound logs one bounded WARNING and the
  loop continues; any other exception ends the writer task, which the
  consumer treats as fatal. Stopping it performs no final write.
- `get_ibs_consumer_status()` is the status API read: `disabled` without
  reading Redis when `IBS_RABBITMQ_ENABLED=false`, otherwise the
  consumer-written status of a valid fresh heartbeat, or `unreachable`.

Redis: the application-owned key `sentinel:ibs_consumer_status` through
`REDIS_URL` (`get_ibs_consumer_status_redis_url()`, the replaceable
boundary), one client per operation with 2-second connect and operation
timeouts and no command retry. No function holds a database session or
lock.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import re
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Final

import redis.asyncio as redis_asyncio
import structlog
from redis.asyncio.retry import Retry
from redis.backoff import NoBackoff
from redis.exceptions import RedisError

from app.config import settings
from app.core.enums import (
    CONSUMER_WRITTEN_IBS_CONSUMER_STATUSES,
    IBSConsumerErrorCategory,
    IBSConsumerStatus,
)
from app.services.json_decoding import decode_json

logger = structlog.get_logger(__name__)

STATUS_KEY: Final = "sentinel:ibs_consumer_status"
"""The application-owned Redis key of the heartbeat."""

HEARTBEAT_TTL_SECONDS: Final = 60
"""Expiry set by every heartbeat write."""

HEARTBEAT_REFRESH_SECONDS: Final = 30.0
"""Interval of the periodic heartbeat write."""

HEARTBEAT_FRESHNESS_SECONDS: Final = 60
"""A heartbeat whose `heartbeat_at` is older than this is `unreachable`."""

REDIS_TIMEOUT_SECONDS: Final = 2
"""Connect and operation timeout of every heartbeat Redis client."""

WRITE_TIMEOUT_SECONDS: Final = 5.0
"""Overall bound of one heartbeat write, including client closure."""

WRITER_STOP_TIMEOUT_SECONDS: Final = 5.0
"""The longest `HeartbeatWriter.stop()` waits for the cancelled writer."""

HEARTBEAT_WRITE_FAILED_EVENT: Final = "ibs_consumer_heartbeat_write_failed"

_UTC_DATETIME: Final = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|\+00:00)", re.ASCII
)
"""An RFC 3339 date-time whose offset is `Z` or `+00:00`."""


def utc_now() -> datetime:
    """The current instant in UTC (the default clock)."""
    return datetime.now(UTC)


# ---------------------------------------------------------------------------
# The heartbeat document
# ---------------------------------------------------------------------------


def _format_datetime(value: datetime) -> str:
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _is_utc(value: datetime) -> bool:
    return value.utcoffset() == timedelta(0)


def _is_count(value: object) -> bool:
    """A non-negative integer; a boolean is not an integer."""
    return type(value) is int and value >= 0


@dataclass(frozen=True, slots=True)
class HeartbeatDocument:
    """One complete heartbeat value (Heartbeat Storage schema).

    Construction raises `ValueError` unless every schema invariant holds:
    a consumer-written status; aware UTC datetimes ordered
    `process_started_at <= status_since <= heartbeat_at`; non-negative
    integer counters with `events_processed` and `processing_failed` each
    no greater than `events_relevant`, itself no greater than
    `events_received`; `next_retry_seconds` a non-negative integer or null,
    and null when `connected`; `last_error_at` null exactly when
    `last_error` is null. Error messages name no value.
    """

    status: IBSConsumerStatus
    heartbeat_at: datetime
    process_started_at: datetime
    status_since: datetime
    events_received: int
    events_relevant: int
    events_processed: int
    processing_failed: int
    reconnect_attempts: int
    next_retry_seconds: int | None
    last_error: IBSConsumerErrorCategory | None
    last_error_at: datetime | None

    def __post_init__(self) -> None:
        if self.status not in CONSUMER_WRITTEN_IBS_CONSUMER_STATUSES:
            raise ValueError("status is not consumer-written")
        timestamps = [self.heartbeat_at, self.process_started_at, self.status_since]
        if self.last_error_at is not None:
            timestamps.append(self.last_error_at)
        if not all(_is_utc(value) for value in timestamps):
            raise ValueError("a datetime is not UTC")
        if not self.process_started_at <= self.status_since <= self.heartbeat_at:
            raise ValueError("invalid timestamp ordering")
        counters = (
            self.events_received,
            self.events_relevant,
            self.events_processed,
            self.processing_failed,
            self.reconnect_attempts,
        )
        if not all(_is_count(value) for value in counters):
            raise ValueError("a counter is not a non-negative integer")
        if not (
            self.events_processed <= self.events_relevant
            and self.processing_failed <= self.events_relevant
            and self.events_relevant <= self.events_received
        ):
            raise ValueError("invalid counter invariant")
        if self.next_retry_seconds is not None and (
            not _is_count(self.next_retry_seconds)
            or self.status is IBSConsumerStatus.CONNECTED
        ):
            raise ValueError("invalid next_retry_seconds")
        if (self.last_error is None) != (self.last_error_at is None):
            raise ValueError("last_error_at does not match last_error")

    def to_json(self) -> str:
        """The compact JSON value written to Redis (whole seconds, `Z`)."""
        return json.dumps(
            {
                "status": self.status.value,
                "heartbeat_at": _format_datetime(self.heartbeat_at),
                "process_started_at": _format_datetime(self.process_started_at),
                "status_since": _format_datetime(self.status_since),
                "events_received": self.events_received,
                "events_relevant": self.events_relevant,
                "events_processed": self.events_processed,
                "processing_failed": self.processing_failed,
                "reconnect_attempts": self.reconnect_attempts,
                "next_retry_seconds": self.next_retry_seconds,
                "last_error": (
                    self.last_error.value if self.last_error is not None else None
                ),
                "last_error_at": (
                    _format_datetime(self.last_error_at)
                    if self.last_error_at is not None
                    else None
                ),
            },
            separators=(",", ":"),
        )


def _reject_constant(_: str) -> Any:
    """Reject the non-standard `NaN`, `Infinity`, and `-Infinity`."""
    raise ValueError("non-standard JSON constant")


def _parse_datetime(value: object) -> datetime:
    if not isinstance(value, str) or _UTC_DATETIME.fullmatch(value) is None:
        raise ValueError("not a UTC date-time")
    return datetime.fromisoformat(value)  # ValueError for an invalid date


def _parse_optional_datetime(value: object) -> datetime | None:
    return None if value is None else _parse_datetime(value)


def _parse_status(value: object) -> IBSConsumerStatus:
    if not isinstance(value, str):
        raise ValueError("status is not a string")
    return IBSConsumerStatus(value)


def _parse_error(value: object) -> IBSConsumerErrorCategory | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("last_error is not a string")
    return IBSConsumerErrorCategory(value)


def _document_from(members: Mapping[str, Any]) -> HeartbeatDocument:
    """Raises `KeyError` for a missing field and `ValueError` otherwise."""
    return HeartbeatDocument(
        status=_parse_status(members["status"]),
        heartbeat_at=_parse_datetime(members["heartbeat_at"]),
        process_started_at=_parse_datetime(members["process_started_at"]),
        status_since=_parse_datetime(members["status_since"]),
        events_received=members["events_received"],
        events_relevant=members["events_relevant"],
        events_processed=members["events_processed"],
        processing_failed=members["processing_failed"],
        reconnect_attempts=members["reconnect_attempts"],
        next_retry_seconds=members["next_retry_seconds"],
        last_error=_parse_error(members["last_error"]),
        last_error_at=_parse_optional_datetime(members["last_error_at"]),
    )


def parse_heartbeat(raw: bytes) -> HeartbeatDocument | None:
    """The heartbeat in a stored value, or `None` when it is invalid.

    Pure. The value must be strict UTF-8 holding exactly one RFC 8259 JSON
    object with every schema field, valid types, and the invariants of
    `HeartbeatDocument`; additional members are ignored. Freshness and
    future timestamps are judged by `evaluate_heartbeat()`.
    """
    try:
        members = decode_json(raw.decode("utf-8"), parse_constant=_reject_constant)
        if not isinstance(members, dict):
            return None
        return _document_from(members)
    except ValueError, KeyError:
        # Invalid UTF-8 or JSON (including a value the parser cannot
        # represent), an invalid or missing field, an unknown status or
        # category, or a violated invariant.
        return None


def evaluate_heartbeat(raw: bytes | None, *, now: datetime) -> HeartbeatDocument | None:
    """The valid fresh heartbeat in a stored value, or `None`.

    Pure. `None` for an absent or invalid value (`parse_heartbeat()`), any
    timestamp later than `now`, or a `heartbeat_at` more than 60 seconds
    before `now`.
    """
    if raw is None:
        return None
    document = parse_heartbeat(raw)
    if document is None:
        return None
    timestamps = [
        document.heartbeat_at,
        document.process_started_at,
        document.status_since,
    ]
    if document.last_error_at is not None:
        timestamps.append(document.last_error_at)
    if any(value > now for value in timestamps):
        return None
    if now - document.heartbeat_at > timedelta(seconds=HEARTBEAT_FRESHNESS_SECONDS):
        return None
    return document


# ---------------------------------------------------------------------------
# The process state
# ---------------------------------------------------------------------------


class ConsumerStatusState:
    """The process-scoped status, counters, `last_error`, and reconnect
    fields of one consumer process (Startup step 3).

    Starts `reconnecting` with every counter at zero; nothing resets
    afterwards. `changed` is set after every change of `status`,
    `reconnect_attempts`, or `next_retry_seconds`, which the writer
    publishes at once; counter and delivery-error updates wait for the next
    write. `last_error` and `last_error_at` keep the latest failure until a
    later one replaces them.
    """

    def __init__(self, clock: Callable[[], datetime] = utc_now) -> None:
        self._clock = clock
        self._latest = self._whole_seconds()
        self.changed = asyncio.Event()
        self.process_started_at = self._latest
        self.status = IBSConsumerStatus.RECONNECTING
        self.status_since = self._latest
        self.events_received = 0
        self.events_relevant = 0
        self.events_processed = 0
        self.processing_failed = 0
        self.reconnect_attempts = 0
        self.next_retry_seconds: int | None = None
        self.last_error: IBSConsumerErrorCategory | None = None
        self.last_error_at: datetime | None = None

    def _whole_seconds(self) -> datetime:
        return self._clock().astimezone(UTC).replace(microsecond=0)

    def _now(self) -> datetime:
        """Whole UTC seconds, never earlier than a previous reading."""
        self._latest = max(self._latest, self._whole_seconds())
        return self._latest

    def _transition(
        self,
        status: IBSConsumerStatus,
        *,
        next_retry_seconds: int | None,
        reconnect: bool = False,
    ) -> None:
        before = (self.status, self.reconnect_attempts, self.next_retry_seconds)
        if reconnect:
            self.reconnect_attempts += 1
        self.next_retry_seconds = next_retry_seconds
        if status is not self.status:
            self.status = status
            self.status_since = self._now()
        if (self.status, self.reconnect_attempts, self.next_retry_seconds) != before:
            self.changed.set()

    def _record_error(self, category: IBSConsumerErrorCategory) -> None:
        self.last_error = category
        self.last_error_at = self._now()

    def attempt_started(self, *, reconnect: bool) -> None:
        """A connection attempt starts: `reconnecting`, no wait scheduled;
        a reconnect attempt (any attempt after the initial one) counts."""
        self._transition(
            IBSConsumerStatus.RECONNECTING, next_retry_seconds=None, reconnect=reconnect
        )

    def connection_failed(self) -> None:
        """An attempt failed transiently (`rabbitmq_connection_failed`)."""
        self._record_error(IBSConsumerErrorCategory.RABBITMQ_CONNECTION_FAILED)

    def retry_scheduled(self, delay_seconds: int) -> None:
        """The wait before the next attempt starts."""
        self._transition(
            IBSConsumerStatus.RECONNECTING, next_retry_seconds=delay_seconds
        )

    def connected(self) -> None:
        """Connection, topology, and broker consumer are active."""
        self._transition(IBSConsumerStatus.CONNECTED, next_retry_seconds=None)

    def connection_lost(self) -> None:
        """The established connection, its channel, or its broker consumer
        was lost (`rabbitmq_connection_lost`)."""
        self._record_error(IBSConsumerErrorCategory.RABBITMQ_CONNECTION_LOST)
        self._transition(IBSConsumerStatus.DISCONNECTED, next_retry_seconds=None)

    def delivery_started(self) -> None:
        """The handling of one delivery begins (`events_received`)."""
        self.events_received += 1

    def delivery_succeeded(self) -> None:
        """A relevant delivery was processed or was an idempotent no-op."""
        self.events_relevant += 1
        self.events_processed += 1

    def delivery_failed(self, category: IBSConsumerErrorCategory) -> None:
        """A delivery ended in a terminal application failure."""
        self.events_relevant += 1
        self.processing_failed += 1
        self._record_error(category)

    def document(self) -> HeartbeatDocument:
        """The complete heartbeat value as of now."""
        return HeartbeatDocument(
            status=self.status,
            heartbeat_at=self._now(),
            process_started_at=self.process_started_at,
            status_since=self.status_since,
            events_received=self.events_received,
            events_relevant=self.events_relevant,
            events_processed=self.events_processed,
            processing_failed=self.processing_failed,
            reconnect_attempts=self.reconnect_attempts,
            next_retry_seconds=self.next_retry_seconds,
            last_error=self.last_error,
            last_error_at=self.last_error_at,
        )


# ---------------------------------------------------------------------------
# Redis
# ---------------------------------------------------------------------------


def get_ibs_consumer_status_redis_url() -> str:
    """Return the Redis URL of the heartbeat (`REDIS_URL`).

    Performs no I/O. Extracted so tests can redirect the heartbeat writes
    and reads (`docs/features/platform/testing-strategy.md`, Redis
    Strategy).
    """
    return settings.redis_url


def _new_redis_client() -> redis_asyncio.Redis:
    """A Redis client for one heartbeat operation, closed by the caller.

    Socket timeouts bound every command and the client never retries one,
    so a write or read never outlives its timeouts.
    """
    client: redis_asyncio.Redis = redis_asyncio.Redis.from_url(
        get_ibs_consumer_status_redis_url(),
        socket_connect_timeout=REDIS_TIMEOUT_SECONDS,
        socket_timeout=REDIS_TIMEOUT_SECONDS,
        retry=Retry(NoBackoff(), 0),
    )
    return client


async def _close_quietly(client: redis_asyncio.Redis) -> None:
    with contextlib.suppress(RedisError, TimeoutError):
        async with asyncio.timeout(REDIS_TIMEOUT_SECONDS):
            await client.aclose()


async def write_heartbeat_value(value: str) -> None:
    """`SET sentinel:ibs_consumer_status <value> EX 60`.

    Category C (Redis I/O only). Propagates `RedisError`.
    """
    client = _new_redis_client()
    try:
        await client.set(STATUS_KEY, value, ex=HEARTBEAT_TTL_SECONDS)
    finally:
        await _close_quietly(client)


HeartbeatStore = Callable[[str], Awaitable[None]]
"""Writes one complete heartbeat value (`write_heartbeat_value`)."""

Timer = Callable[[float], Awaitable[None]]


async def _sleep(seconds: float) -> None:
    await asyncio.sleep(seconds)


class HeartbeatWriter:
    """Publishes a `ConsumerStatusState` (Startup step 5).

    `start()` creates the writer task, which writes the current document,
    then waits for the first of the 30-second refresh (`timer`) and a
    state change, and repeats; a change during a write causes another write
    at once. `RedisError` and the overall write bound log one
    `ibs_consumer_heartbeat_write_failed` WARNING with the exception class
    name only. Any other exception ends the task with that exception.
    `stop()` cancels the task without a final write (Graceful Shutdown step
    5) and waits for it at most `WRITER_STOP_TIMEOUT_SECONDS`.
    """

    def __init__(
        self,
        state: ConsumerStatusState,
        *,
        store: HeartbeatStore = write_heartbeat_value,
        timer: Timer = _sleep,
    ) -> None:
        self._state = state
        self._store = store
        self._timer = timer
        self._task: asyncio.Task[None] | None = None

    def start(self) -> asyncio.Task[None]:
        """Start the writer task once; return it."""
        if self._task is None:
            self._task = asyncio.create_task(self._run())
        return self._task

    async def stop(self) -> None:
        """Stop the writer task; idempotent and bounded."""
        task = self._task
        if task is None or task.done():
            return
        task.cancel()
        await asyncio.wait({task}, timeout=WRITER_STOP_TIMEOUT_SECONDS)

    async def _run(self) -> None:
        while True:
            self._state.changed.clear()
            value = self._state.document().to_json()
            try:
                async with asyncio.timeout(WRITE_TIMEOUT_SECONDS):
                    await self._store(value)
            except (RedisError, TimeoutError) as exc:
                logger.warning(
                    HEARTBEAT_WRITE_FAILED_EVENT, error_type=type(exc).__name__
                )
            await self._wait()

    async def _wait(self) -> None:
        refresh = asyncio.ensure_future(self._timer(HEARTBEAT_REFRESH_SECONDS))
        changed = asyncio.ensure_future(self._state.changed.wait())
        try:
            await asyncio.wait({refresh, changed}, return_when=asyncio.FIRST_COMPLETED)
        finally:
            refresh.cancel()
            changed.cancel()
        if refresh.done() and not refresh.cancelled():
            refresh.result()  # A failing timer ends the writer.


# ---------------------------------------------------------------------------
# The status API read
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class IBSConsumerStatusView:
    """The observed consumer status; `heartbeat` is set exactly for a
    consumer-written status."""

    status: IBSConsumerStatus
    heartbeat: HeartbeatDocument | None = None


async def get_ibs_consumer_status() -> IBSConsumerStatusView:
    """Observe the consumer for `GET /api/v1/ibs-consumer/status`.

    Category C (read-only Redis I/O; no database access). With
    `IBS_RABBITMQ_ENABLED=false`, returns `disabled` without reading Redis,
    ignoring any stale key. Otherwise reads the key with a per-request
    client and returns the heartbeat's own status and fields when
    `evaluate_heartbeat()` accepts it against the clock read after the
    `GET`, and `unreachable` for any `RedisError`, an absent key, or an
    invalid, future, or stale value. Never raises `RedisError`.
    """
    if not settings.ibs_rabbitmq_enabled:
        return IBSConsumerStatusView(IBSConsumerStatus.DISABLED)
    client = _new_redis_client()
    try:
        raw: bytes | None = await client.get(STATUS_KEY)
    except RedisError:
        return IBSConsumerStatusView(IBSConsumerStatus.UNREACHABLE)
    finally:
        await _close_quietly(client)
    heartbeat = evaluate_heartbeat(raw, now=utc_now())
    if heartbeat is None:
        return IBSConsumerStatusView(IBSConsumerStatus.UNREACHABLE)
    return IBSConsumerStatusView(heartbeat.status, heartbeat)
