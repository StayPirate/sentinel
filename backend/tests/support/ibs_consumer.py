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

No real sleep, socket, broker, or database is used.
"""

from __future__ import annotations

import asyncio
import ssl
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Final

import structlog

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
