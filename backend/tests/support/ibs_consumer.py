"""Replaceable boundaries for the IBS RabbitMQ consumer lifecycle tests
(backend/app/services/ibs_event_consumer.py).

- `FakeBroker` is the `Connector`: each connection attempt pops the next
  scripted outcome (an exception to raise, `BLOCK` to wait until
  cancelled, or `CONNECT`, the default once the script is exhausted) and
  records the URL, the TLS context, and the delivery sink.
- `FakeEpoch` is one established connection: it records ACKs, the
  consumer cancellation, and the closure, and `lose()` simulates a lost
  connection, channel, or broker consumer.
- `FakeTimer` replaces every lifecycle wait (backoff and shutdown
  deadline): it records the requested seconds and returns at once, unless
  `blocking` selects the wait, which then lasts until it is cancelled or
  `release()` is called. `on_wait` runs before each wait.
- `FakeClient` stands in for the process-wide `IBSClient`.
- `Handled` replaces `handle_delivery()`: it records each call with the
  bound `ibs_event_id` and returns the scripted result, optionally after a
  gate that the test opens.
- `FakeHeartbeatStore` replaces the Redis heartbeat write: it records each
  complete value, optionally after a gate, or raises a scripted error.
- `FakeRefreshTimer` replaces the heartbeat refresh wait: it never ends on
  its own, so the writer writes only on a state change, until `fire()`
  ends the current waits as if 30 seconds had passed.
- `FakeClock` is a settable wall clock.

No real sleep, socket, broker, Redis, or database is used.
"""

from __future__ import annotations

import asyncio
import json
import ssl
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Final

import structlog

from app.core.enums import IBSConsumerErrorCategory
from app.services.ibs_event_consumer import DeliverySink
from app.services.ibs_event_decoding import (
    PACKAGE_COMMIT_ROUTING_KEY,
    DeliveryOutcome,
    DeliveryResult,
)

CONNECT: Final = "connect"
BLOCK: Final = "block"

COMMIT_BODY: Final = (
    b'{"project":"SUSE:SLE-15-SP6:Update","package":"example-pkg",'
    b'"user":"example-user","rev":"46"}'
)


@dataclass(frozen=True, slots=True)
class FakeDelivery:
    routing_key: str | None = PACKAGE_COMMIT_ROUTING_KEY
    content_type: str | None = "application/octet-stream"
    body: bytes = COMMIT_BODY


@dataclass(eq=False)
class FakeEpoch:
    events: list[str]
    lost: asyncio.Event = field(default_factory=asyncio.Event)
    loss_reason: str = "connection_lost"
    acks: list[Any] = field(default_factory=list)
    consumer_cancelled: bool = False
    closed: bool = False
    ack_error: BaseException | None = None
    close_gate: asyncio.Event | None = None
    on_close: Callable[[], None] | None = None

    def lose(self, reason: str = "connection_lost") -> None:
        if not self.lost.is_set():
            self.loss_reason = reason
            self.lost.set()

    async def ack(self, delivery: Any) -> None:
        if self.ack_error is not None:
            raise self.ack_error
        self.acks.append(delivery)
        self.events.append("ack")

    async def cancel_consumer(self) -> None:
        self.consumer_cancelled = True
        self.events.append("cancel_consumer")

    async def close(self) -> None:
        if self.on_close is not None:
            self.on_close()
        if self.close_gate is not None:
            await self.close_gate.wait()
        self.closed = True
        self.events.append("close")


@dataclass(eq=False)
class FakeBroker:
    script: list[Any] = field(default_factory=list)
    events: list[str] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    contexts: list[ssl.SSLContext] = field(default_factory=list)
    sinks: list[DeliverySink] = field(default_factory=list)
    epochs: list[FakeEpoch] = field(default_factory=list)
    connected: asyncio.Event = field(default_factory=asyncio.Event)
    attempted: asyncio.Event = field(default_factory=asyncio.Event)

    async def __call__(
        self, url: str, ssl_context: ssl.SSLContext, sink: DeliverySink
    ) -> FakeEpoch:
        self.urls.append(url)
        self.contexts.append(ssl_context)
        self.events.append("attempt")
        self.attempted.set()
        outcome = self.script.pop(0) if self.script else CONNECT
        if outcome == BLOCK:
            await asyncio.Event().wait()
        if isinstance(outcome, BaseException):
            raise outcome
        epoch = FakeEpoch(self.events)
        self.epochs.append(epoch)
        self.sinks.append(sink)
        self.events.append("connected")
        self.connected.set()
        return epoch

    def deliver(self, delivery: FakeDelivery | None = None) -> None:
        """Deliver through the latest epoch's sink."""
        self.sinks[-1](delivery if delivery is not None else FakeDelivery())

    async def wait_connected(self, count: int = 1) -> FakeEpoch:
        async with asyncio.timeout(5):
            while len(self.epochs) < count:
                self.connected.clear()
                await self.connected.wait()
        return self.epochs[count - 1]


@dataclass(eq=False)
class FakeTimer:
    calls: list[float] = field(default_factory=list)
    blocking: Callable[[float], bool] = lambda _seconds: False
    on_wait: Callable[[int, float], None] | None = None
    _waiters: list[asyncio.Future[None]] = field(default_factory=list)
    waiting: asyncio.Event = field(default_factory=asyncio.Event)

    async def __call__(self, seconds: float) -> None:
        self.calls.append(seconds)
        if self.on_wait is not None:
            self.on_wait(len(self.calls), seconds)
        if not self.blocking(seconds):
            return
        waiter: asyncio.Future[None] = asyncio.get_running_loop().create_future()
        self._waiters.append(waiter)
        self.waiting.set()
        await waiter

    def release(self) -> None:
        for waiter in self._waiters:
            if not waiter.done():
                waiter.set_result(None)


@dataclass(eq=False)
class FakeClient:
    closed: int = 0

    async def aclose(self) -> None:
        self.closed += 1


FAILED_RESULT: Final = DeliveryResult(
    DeliveryOutcome.FAILED,
    "track_failed",
    {"project": "SUSE:SLE-15-SP6:Update", "track_count": 2, "failed_track_count": 1},
    IBSConsumerErrorCategory.PACKAGE_RECONCILIATION_FAILED,
)
"""A `handle_delivery()` failure as it reaches the lifecycle."""


@dataclass(eq=False)
class FakeHeartbeatStore:
    """The heartbeat store: `values` holds every written value in order."""

    values: list[str] = field(default_factory=list)
    attempts: int = 0
    error: BaseException | None = None
    gate: asyncio.Event | None = None
    written: asyncio.Event = field(default_factory=asyncio.Event)
    events: list[str] | None = None

    async def __call__(self, value: str) -> None:
        self.attempts += 1
        if self.events is not None:
            self.events.append(f"heartbeat:{json.loads(value)['status']}")
        if self.gate is not None:
            await self.gate.wait()
        if self.error is not None:
            raise self.error
        self.values.append(value)
        self.written.set()

    @property
    def documents(self) -> list[dict[str, Any]]:
        return [json.loads(value) for value in self.values]

    @property
    def statuses(self) -> list[str]:
        """The `status` of each write, consecutive repeats collapsed."""
        collapsed: list[str] = []
        for document in self.documents:
            if not collapsed or collapsed[-1] != document["status"]:
                collapsed.append(document["status"])
        return collapsed

    @property
    def last(self) -> dict[str, Any]:
        return self.documents[-1]

    async def wait_for(
        self, predicate: Callable[[dict[str, Any]], bool]
    ) -> dict[str, Any]:
        """The first written document (from now on or earlier) that
        satisfies `predicate` (bounded)."""
        async with asyncio.timeout(5):
            while True:
                for document in self.documents:
                    if predicate(document):
                        return document
                self.written.clear()
                await self.written.wait()


@dataclass(eq=False)
class FakeRefreshTimer:
    calls: list[float] = field(default_factory=list)
    _waiters: list[asyncio.Future[None]] = field(default_factory=list)
    _fired: bool = False

    async def __call__(self, seconds: float) -> None:
        self.calls.append(seconds)
        if self._fired:
            self._fired = False
            return
        waiter: asyncio.Future[None] = asyncio.get_running_loop().create_future()
        self._waiters.append(waiter)
        await waiter

    def fire(self) -> None:
        """End the current wait, as if the refresh interval had passed; when
        no wait is pending yet, the next wait ends at once instead."""
        pending = [waiter for waiter in self._waiters if not waiter.done()]
        self._waiters.clear()
        for waiter in pending:
            waiter.set_result(None)
        self._fired = not pending


START: Final = datetime(2026, 9, 8, 14, 0, 0, 250_000, tzinfo=UTC)
"""The fictional process start of the lifecycle tests (not a whole second)."""


@dataclass(eq=False)
class FakeClock:
    now: datetime = START

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += timedelta(seconds=seconds)


@dataclass(eq=False)
class Handled:
    """A `handle_delivery()` substitute."""

    result: DeliveryResult = field(
        default_factory=lambda: DeliveryResult(
            DeliveryOutcome.PROCESSED,
            fields={"project": "SUSE:SLE-15-SP6:Update", "track_count": 1},
        )
    )
    gate: asyncio.Event | None = None
    error: BaseException | None = None
    calls: list[dict[str, Any]] = field(default_factory=list)
    started: asyncio.Event = field(default_factory=asyncio.Event)
    finished: list[str] = field(default_factory=list)
    on_call: Callable[[], None] | None = None
    events: list[str] | None = None

    async def __call__(
        self,
        routing_key: str | None,
        content_type: str | None,
        body: bytes,
        *,
        client: Any,
    ) -> DeliveryResult:
        context = structlog.contextvars.get_contextvars()
        self.calls.append(
            {
                "routing_key": routing_key,
                "body": body,
                "ibs_event_id": context.get("ibs_event_id"),
                "client": client,
            }
        )
        if self.events is not None:
            self.events.append("handle")
        self.started.set()
        if self.on_call is not None:
            self.on_call()
        if self.gate is not None:
            await self.gate.wait()
        if self.error is not None:
            raise self.error
        self.finished.append(context.get("ibs_event_id", ""))
        return self.result
