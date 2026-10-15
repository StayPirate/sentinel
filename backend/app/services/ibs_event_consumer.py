"""The IBS RabbitMQ consumer lifecycle (`IBSEventConsumer`).

Implements docs/features/integrations/ibs-rabbitmq-integration.md (AMQP
Contract > Connection and Topology; Per-Delivery Processing > Correlation
Scope, One-Attempt Rule, Settlement Policy, Connection Loss and Consumer
Cancellation; Process Lifecycle > Runtime Independence, Startup,
Reconnection, Fatal and Transient Failures, Graceful Shutdown; Structured
Logs) for the standalone process started by `app/ibs_consumer.py`:

- Startup verifies PostgreSQL with a bounded `SELECT 1` (failure is
  CRITICAL, exit 1), creates the one process-wide `IBSClient`, and logs
  `ibs_consumer_started` before the first connection attempt.
- Each connection epoch builds a fresh TLS context (`build_tls_context()`),
  connects with the fixed 60-second heartbeat, passively declares `pubsub`,
  declares a server-named exclusive non-durable auto-delete queue, applies
  per-consumer `prefetch_count=1`, binds the fixed routing keys, and
  consumes. Deliveries are handled one at a time in a task of their own,
  each with a fresh UUIDv7 `ibs_event_id` reset in `finally`, in one
  application attempt, and ACKed exactly once on a live channel after the
  outcome; never NACKed, rejected, or requeued.
- Connection loss, channel loss, or a broker `basic.cancel` (observed
  through aiormq's public `on_consumer_cancel_callbacks`) is a dead channel:
  the in-flight handler is cancelled and awaited, nothing is settled, the
  epoch is closed best-effort, and the consumer reconnects after the
  current backoff delay (initial delay doubled up to the cap; the first
  attempt never waits; the delay resets after a successful start).
- Fatal conditions (TLS configuration or verification, authentication
  rejection or `ACCESS_REFUSED`, a missing exchange, a topology
  precondition failure, `MemoryError`, or an exception outside a delivery's
  application processing that the lifecycle does not classify) log CRITICAL
  and exit 1 without reconnecting.
- SIGTERM/SIGINT stops new deliveries, cancels the broker consumer without
  waiting (the channel stays open for the in-flight handler), gives that
  handler at most 30 seconds, then cancels it, and exits 0 after closing the
  epoch; a backoff wait or connection attempt in progress is interrupted,
  and a repeated signal is ignored. Every closure step is bounded.

Every exit closes the `IBSClient` and disposes the database engine
best-effort. The module imports no Celery application, task module, fetcher
discovery, or concrete fetcher. Redis, the heartbeat, and the status counters
are not part of this module.
"""

from __future__ import annotations

import asyncio
import contextlib
import signal
import ssl
import uuid
from collections.abc import Awaitable, Callable, Iterator
from dataclasses import dataclass, field
from typing import Any, Final, Protocol

import aio_pika
import aiormq
import pamqp.exceptions
import structlog
from aio_pika.abc import (
    AbstractChannel,
    AbstractConnection,
    AbstractIncomingMessage,
    AbstractQueue,
)
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.config import Settings
from app.core.exceptions import TLSConfigurationError
from app.database import async_session_factory, engine
from app.services.http_client import build_tls_context
from app.services.ibs_client import IBSClient
from app.services.ibs_event_decoding import (
    BOUND_ROUTING_KEYS,
    DeliveryOutcome,
    DeliveryResult,
)
from app.services.packages.ibs_event_handlers import handle_delivery

logger = structlog.get_logger(__name__)

EXCHANGE_NAME: Final = "pubsub"
HEARTBEAT_SECONDS: Final = 60
PREFETCH_COUNT: Final = 1
CONNECTION_NAME: Final = "sentinel-ibs-consumer"
SHUTDOWN_DEADLINE_SECONDS: Final = 30.0
"""The longest the in-flight handler may run after SIGTERM/SIGINT."""

CONNECT_TIMEOUT_SECONDS: Final = 30.0
"""Bound of one connection handshake (TCP, TLS, and AMQP)."""

OPERATION_TIMEOUT_SECONDS: Final = 30.0
"""Bound of the channel open and of each topology and consume RPC."""

CLOSE_TIMEOUT_SECONDS: Final = 5.0
"""Bound of each best-effort channel, connection, or client closure."""

STARTUP_CHECK_TIMEOUT_SECONDS: Final = 10.0
"""Bound of the startup PostgreSQL `SELECT 1`."""

DISABLED_EVENT: Final = "ibs_consumer_disabled"
STARTED_EVENT: Final = "ibs_consumer_started"
STARTUP_FAILED_EVENT: Final = "ibs_consumer_startup_failed"
CONNECTED_EVENT: Final = "ibs_consumer_connected"
CONNECTION_FAILED_EVENT: Final = "ibs_consumer_connection_failed"
CONNECTION_LOST_EVENT: Final = "ibs_consumer_connection_lost"
RECONNECT_SCHEDULED_EVENT: Final = "ibs_consumer_reconnect_scheduled"
FATAL_EVENT: Final = "ibs_consumer_fatal"
DELIVERY_MALFORMED_EVENT: Final = "ibs_consumer_delivery_malformed"
DELIVERY_IRRELEVANT_EVENT: Final = "ibs_consumer_delivery_irrelevant"
DELIVERY_PROCESSED_EVENT: Final = "ibs_consumer_delivery_processed"
DELIVERY_FAILED_EVENT: Final = "ibs_consumer_delivery_failed"
DELIVERY_CANCELLED_EVENT: Final = "ibs_consumer_delivery_cancelled"
SHUTDOWN_STARTED_EVENT: Final = "ibs_consumer_shutdown_started"
SHUTDOWN_DEADLINE_EXCEEDED_EVENT: Final = "ibs_consumer_shutdown_deadline_exceeded"
STOPPED_EVENT: Final = "ibs_consumer_stopped"

POSTGRESQL_UNAVAILABLE: Final = "postgresql_unavailable"
NETWORK_ERROR: Final = "network_error"
TIMEOUT: Final = "timeout"
TLS_HANDSHAKE_FAILED: Final = "tls_handshake_failed"
AMQP_ERROR: Final = "amqp_error"
CONNECTION_LOST: Final = "connection_lost"
CHANNEL_LOST: Final = "channel_lost"
CONSUMER_CANCELLED: Final = "consumer_cancelled"
TLS_CONFIGURATION_INVALID: Final = "tls_configuration_invalid"
TLS_VERIFICATION_FAILED: Final = "tls_verification_failed"
AUTHENTICATION_REJECTED: Final = "authentication_rejected"
ACCESS_REFUSED: Final = "access_refused"
EXCHANGE_MISSING: Final = "exchange_missing"
TOPOLOGY_PRECONDITION_FAILED: Final = "topology_precondition_failed"
MEMORY_ERROR: Final = "memory_error"
UNEXPECTED_ERROR: Final = "unexpected_error"

_ACCESS_REFUSED_REPLY_CODE: Final = 403
"""`ACCESS_REFUSED`: an authorization rejection. `NOT_ALLOWED` (530) is
not fatal: RabbitMQ also uses it for refusals it lifts by itself, such as a
reached connection limit or a virtual host that is down."""

_SETTLEMENT_ERRORS: Final = (aiormq.exceptions.AMQPError, RuntimeError, OSError)
"""Errors of an ACK attempt on a channel that died after the liveness
check (aiormq raises `ChannelInvalidStateError`, a `RuntimeError`)."""

_CLOSE_ERRORS: Final = (
    aiormq.exceptions.AMQPError,
    RuntimeError,
    OSError,
    TimeoutError,
    pamqp.exceptions.PAMQPException,
)


# ---------------------------------------------------------------------------
# The AMQP boundary
# ---------------------------------------------------------------------------


class Delivery(Protocol):
    """The parts of one delivery the consumer reads."""

    @property
    def routing_key(self) -> str | None: ...

    @property
    def content_type(self) -> str | None: ...

    @property
    def body(self) -> bytes: ...


DeliverySink = Callable[[Delivery], None]


class Epoch(Protocol):
    """One established connection with its channel, queue, and consumer.

    `lost` is set, with `loss_reason`, when the connection or channel
    closes or the broker cancels the consumer. `ack()` settles one delivery
    of this epoch and raises if the channel is no longer usable.
    """

    lost: asyncio.Event
    loss_reason: str

    async def ack(self, delivery: Delivery) -> None: ...

    async def cancel_consumer(self) -> None: ...

    async def close(self) -> None: ...


Connector = Callable[[str, ssl.SSLContext, DeliverySink], Awaitable[Epoch]]
"""Connect, establish the topology, and start consuming into the sink."""

Timer = Callable[[float], Awaitable[None]]


@dataclass(frozen=True, slots=True, eq=False)
class _AmqpDelivery:
    routing_key: str | None
    content_type: str | None
    body: bytes
    message: AbstractIncomingMessage


@dataclass(eq=False)
class _AioPikaEpoch:
    """The aio-pika implementation of `Epoch` (non-robust connection)."""

    connection: AbstractConnection
    lost: asyncio.Event = field(default_factory=asyncio.Event)
    loss_reason: str = CONNECTION_LOST
    channel: AbstractChannel | None = None
    queue: AbstractQueue | None = None
    consumer_tag: str | None = None

    def lose(self, reason: str) -> None:
        if not self.lost.is_set():
            self.loss_reason = reason
            self.lost.set()

    async def ack(self, delivery: Delivery) -> None:
        if not isinstance(delivery, _AmqpDelivery):
            raise TypeError("not a delivery of this epoch")
        await delivery.message.ack()

    async def cancel_consumer(self) -> None:
        if self.queue is not None and self.consumer_tag is not None:
            # No wait for Basic.CancelOk: a slow broker must not time out
            # the RPC and close the channel the in-flight handler needs.
            await self.queue.cancel(self.consumer_tag, nowait=True)

    async def close(self) -> None:
        if self.channel is not None:
            with contextlib.suppress(*_CLOSE_ERRORS):
                async with asyncio.timeout(CLOSE_TIMEOUT_SECONDS):
                    await self.channel.close()
        with contextlib.suppress(*_CLOSE_ERRORS):
            async with asyncio.timeout(CLOSE_TIMEOUT_SECONDS):
                await self.connection.close()


async def connect_amqp(
    url: str, ssl_context: ssl.SSLContext, sink: DeliverySink
) -> Epoch:
    """Connect to `url` and establish the fixed topology and consumer.

    Category C (AMQP I/O only). Raises the library's exception for any
    failure, after closing the partial connection best-effort.
    """
    connection = await aio_pika.connect(
        url,
        ssl_context=ssl_context,
        heartbeat=HEARTBEAT_SECONDS,
        timeout=CONNECT_TIMEOUT_SECONDS,
        client_properties={"connection_name": CONNECTION_NAME},
    )
    epoch = _AioPikaEpoch(connection)
    try:
        connection.close_callbacks.add(lambda *_: epoch.lose(CONNECTION_LOST))
        async with asyncio.timeout(OPERATION_TIMEOUT_SECONDS):
            channel = await connection.channel(publisher_confirms=False)
        epoch.channel = channel
        channel.close_callbacks.add(lambda *_: epoch.lose(CHANNEL_LOST))
        underlay = await channel.get_underlay_channel()
        underlay.on_consumer_cancel_callbacks.add(
            lambda _frame: epoch.lose(CONSUMER_CANCELLED)
        )
        exchange = await channel.declare_exchange(
            EXCHANGE_NAME,
            aio_pika.ExchangeType.TOPIC,
            passive=True,
            durable=True,
            timeout=OPERATION_TIMEOUT_SECONDS,
        )
        queue = await channel.declare_queue(
            "",
            exclusive=True,
            durable=False,
            auto_delete=True,
            timeout=OPERATION_TIMEOUT_SECONDS,
        )
        epoch.queue = queue
        await channel.set_qos(
            prefetch_count=PREFETCH_COUNT,
            global_=False,
            timeout=OPERATION_TIMEOUT_SECONDS,
        )
        for routing_key in BOUND_ROUTING_KEYS:
            await queue.bind(
                exchange, routing_key=routing_key, timeout=OPERATION_TIMEOUT_SECONDS
            )

        async def on_message(message: AbstractIncomingMessage) -> None:
            sink(
                _AmqpDelivery(
                    routing_key=message.routing_key,
                    content_type=message.content_type,
                    body=message.body,
                    message=message,
                )
            )

        epoch.consumer_tag = await queue.consume(
            on_message, no_ack=False, timeout=OPERATION_TIMEOUT_SECONDS
        )
    except BaseException:
        await epoch.close()
        raise
    return epoch


# ---------------------------------------------------------------------------
# Failure classification
# ---------------------------------------------------------------------------


class FatalConsumerError(Exception):
    """A condition that ends the process with exit code 1 (no reconnect)."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def _chain(error: BaseException) -> Iterator[BaseException]:
    seen: set[int] = set()
    current: BaseException | None = error
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        yield current
        current = current.__cause__ or current.__context__


def classify_connection_error(error: BaseException) -> tuple[bool, str]:
    """`(fatal, reason_category)` of a connection or topology failure.

    Pure. aiormq wraps every transport `OSError` (DNS, TCP, TLS) in
    `AMQPConnectionError` with the original as `__cause__`, so the
    certificate-verification check walks the exception chain. Raises
    `TypeError` for an exception outside the transient and fatal classes,
    which the lifecycle then treats as unexpected (fatal).
    """
    chain = list(_chain(error))
    if any(isinstance(item, ssl.SSLCertVerificationError) for item in chain):
        return True, TLS_VERIFICATION_FAILED
    if isinstance(error, TLSConfigurationError):
        return True, TLS_CONFIGURATION_INVALID
    if isinstance(
        error,
        aiormq.exceptions.ProbableAuthenticationError
        | aiormq.exceptions.AuthenticationError,
    ):
        return True, AUTHENTICATION_REJECTED
    if isinstance(error, aiormq.exceptions.ChannelAccessRefused) or (
        isinstance(error, aiormq.exceptions.ConnectionClosed)
        and bool(error.args)
        and error.args[0] == _ACCESS_REFUSED_REPLY_CODE
    ):
        return True, ACCESS_REFUSED
    if isinstance(error, aiormq.exceptions.ChannelNotFoundEntity):
        return True, EXCHANGE_MISSING
    if isinstance(error, aiormq.exceptions.ChannelPreconditionFailed):
        return True, TOPOLOGY_PRECONDITION_FAILED
    if isinstance(error, TimeoutError):
        return False, TIMEOUT
    if any(isinstance(item, ssl.SSLError) for item in chain):
        return False, TLS_HANDSHAKE_FAILED
    if isinstance(error, aiormq.exceptions.AMQPConnectionError) and any(
        isinstance(item, OSError) for item in chain[1:]
    ):
        return False, NETWORK_ERROR
    if isinstance(
        error,
        aiormq.exceptions.AMQPError
        | aiormq.exceptions.ChannelInvalidStateError
        | pamqp.exceptions.PAMQPException,
    ):
        return False, AMQP_ERROR
    if isinstance(error, OSError):
        return False, NETWORK_ERROR
    raise TypeError("unclassified connection failure") from error


# ---------------------------------------------------------------------------
# The lifecycle
# ---------------------------------------------------------------------------


def _bound_routing_key(delivery: Delivery) -> dict[str, str]:
    """The routing key as a log field, only when it is a fixed binding."""
    key = delivery.routing_key
    return {"routing_key": key} if key in BOUND_ROUTING_KEYS and key else {}


async def _sleep(seconds: float) -> None:
    await asyncio.sleep(seconds)


async def _cancel_and_wait(task: asyncio.Future[Any]) -> None:
    """Cancel `task` and wait for its cleanup.

    Its result or exception is discarded, except a `MemoryError`, which
    propagates; so does the cancellation of the awaiting task itself.
    """
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        current = asyncio.current_task()
        if current is not None and current.cancelling():
            raise
    except MemoryError:
        raise
    except Exception:  # The outcome of an abandoned task is irrelevant.
        return


class IBSEventConsumer:
    """The standalone IBS RabbitMQ consumer process (see module docstring).

    `connect`, `client_factory`, `session_factory`, `dispose_engine`,
    `timer`, and `handle_signals` are replaceable for tests; production uses
    the defaults.
    """

    def __init__(
        self,
        settings: Settings,
        *,
        connect: Connector = connect_amqp,
        client_factory: Callable[[], IBSClient] = IBSClient,
        session_factory: async_sessionmaker[AsyncSession] = async_session_factory,
        dispose_engine: Callable[[], Awaitable[None]] = engine.dispose,
        timer: Timer = _sleep,
        handle_signals: bool = True,
    ) -> None:
        self._settings = settings
        self._connect = connect
        self._client_factory = client_factory
        self._session_factory = session_factory
        self._dispose_engine = dispose_engine
        self._timer = timer
        self._handle_signals = handle_signals
        self._shutdown = asyncio.Event()
        self._client: IBSClient | None = None

    def request_shutdown(self) -> None:
        """Start a graceful shutdown (SIGTERM/SIGINT); idempotent."""
        if not self._shutdown.is_set():
            logger.info(SHUTDOWN_STARTED_EVENT)
            self._shutdown.set()

    async def run(self) -> int:
        """Run the consumer until shutdown or a fatal condition.

        Returns the process exit code: 0 after a graceful shutdown, 1 after
        a fatal condition or a failed PostgreSQL verification. Never raises
        an `Exception`; cancellation propagates.
        """
        loop = asyncio.get_running_loop()
        signals = (signal.SIGTERM, signal.SIGINT) if self._handle_signals else ()
        for signum in signals:
            loop.add_signal_handler(signum, self.request_shutdown)
        try:
            return await self._run()
        finally:
            for signum in signals:
                loop.remove_signal_handler(signum)

    async def _run(self) -> int:
        code = 1
        try:
            try:
                await self._verify_postgresql()
            except MemoryError:
                raise
            except Exception:
                logger.critical(
                    STARTUP_FAILED_EVENT, reason_category=POSTGRESQL_UNAVAILABLE
                )
                return 1
            try:
                self._client = self._client_factory()
            except TLSConfigurationError:
                # The client builds its TLS context from SUSE_CA_CERT_PATH.
                raise FatalConsumerError(TLS_CONFIGURATION_INVALID) from None
            logger.info(STARTED_EVENT)
            await self._consume_until_shutdown()
            code = 0
        except FatalConsumerError as fatal:
            logger.critical(FATAL_EVENT, reason_category=fatal.reason)
        except MemoryError:
            logger.critical(FATAL_EVENT, reason_category=MEMORY_ERROR)
        except Exception:
            logger.critical(FATAL_EVENT, reason_category=UNEXPECTED_ERROR)
        finally:
            await self._release()
        if code == 0:
            logger.info(STOPPED_EVENT)
        return code

    async def _verify_postgresql(self) -> None:
        async with asyncio.timeout(STARTUP_CHECK_TIMEOUT_SECONDS):
            async with self._session_factory() as session:
                await session.execute(text("SELECT 1"))

    async def _release(self) -> None:
        """Close the IBS client and dispose the engine, best-effort."""
        client, self._client = self._client, None
        if client is not None:
            with contextlib.suppress(Exception):
                async with asyncio.timeout(CLOSE_TIMEOUT_SECONDS):
                    await client.aclose()
        with contextlib.suppress(Exception):
            async with asyncio.timeout(CLOSE_TIMEOUT_SECONDS):
                await self._dispose_engine()

    async def _until_shutdown(
        self, awaitable: Awaitable[Any]
    ) -> asyncio.Task[Any] | None:
        """Run `awaitable` until it finishes or shutdown is requested.

        Returns its finished task, or `None` (after cancelling and awaiting
        it) when shutdown came first.
        """
        work = asyncio.ensure_future(awaitable)
        stop = asyncio.ensure_future(self._shutdown.wait())
        try:
            await asyncio.wait({work, stop}, return_when=asyncio.FIRST_COMPLETED)
        finally:
            stop.cancel()
        if work.done():
            return work
        await _cancel_and_wait(work)
        return None

    async def _consume_until_shutdown(self) -> None:
        initial = float(self._settings.ibs_rabbitmq_reconnect_initial)
        cap = float(self._settings.ibs_rabbitmq_reconnect_max)
        delay = initial
        first = True
        while not self._shutdown.is_set():
            if not first:
                logger.info(RECONNECT_SCHEDULED_EVENT, delay_seconds=int(delay))
                waited = await self._until_shutdown(self._timer(delay))
                if waited is None or self._shutdown.is_set():
                    return
                delay = min(delay * 2, cap)
            first = False
            inbox: asyncio.Queue[Delivery] = asyncio.Queue()
            epoch = await self._open_epoch(inbox)
            if epoch is None:
                continue
            logger.info(CONNECTED_EVENT)
            delay = initial
            if not await self._consume(epoch, inbox):
                return

    async def _open_epoch(self, inbox: asyncio.Queue[Delivery]) -> Epoch | None:
        """One connection attempt; `None` after a transient failure or a
        shutdown request. Raises `FatalConsumerError` for a fatal one."""
        try:
            ssl_context = build_tls_context()
        except TLSConfigurationError:
            raise FatalConsumerError(TLS_CONFIGURATION_INVALID) from None

        def sink(delivery: Delivery) -> None:
            if not self._shutdown.is_set():
                inbox.put_nowait(delivery)

        attempt = await self._until_shutdown(
            self._connect(self._settings.ibs_rabbitmq_url, ssl_context, sink)
        )
        if attempt is None:
            return None
        error = attempt.exception()
        if error is None:
            epoch: Epoch = attempt.result()
            if self._shutdown.is_set():
                await epoch.close()
                return None
            return epoch
        if isinstance(error, MemoryError):
            raise error
        fatal, reason = classify_connection_error(error)
        if fatal:
            raise FatalConsumerError(reason)
        logger.warning(CONNECTION_FAILED_EVENT, reason_category=reason)
        return None

    async def _consume(self, epoch: Epoch, inbox: asyncio.Queue[Delivery]) -> bool:
        """Handle deliveries sequentially until the epoch is lost (returns
        `True`) or shutdown completes (returns `False`)."""
        lost = asyncio.ensure_future(epoch.lost.wait())
        stop = asyncio.ensure_future(self._shutdown.wait())
        handler: asyncio.Task[None] | None = None
        try:
            while True:
                if handler is None:
                    getter = asyncio.ensure_future(inbox.get())
                    await asyncio.wait(
                        {getter, lost, stop}, return_when=asyncio.FIRST_COMPLETED
                    )
                    if getter.done() and not lost.done() and not stop.done():
                        handler = asyncio.create_task(
                            self._handle(getter.result(), epoch)
                        )
                        continue
                    # A delivery taken together with the loss or shutdown
                    # stays unsettled.
                    await _cancel_and_wait(getter)
                else:
                    await asyncio.wait(
                        {handler, lost, stop}, return_when=asyncio.FIRST_COMPLETED
                    )
                    if handler.done():
                        finished, handler = handler, None
                        finished.result()  # MemoryError/BaseException: fatal
                        continue
                if lost.done():
                    logger.warning(
                        CONNECTION_LOST_EVENT, reason_category=epoch.loss_reason
                    )
                    if handler is not None:
                        await _cancel_and_wait(handler)
                        handler = None
                    await epoch.close()
                    return True
                await self._shut_down(epoch, handler, lost)
                handler = None
                return False
        except BaseException:
            # Best-effort cleanup on the way out (fatal, unexpected, or the
            # process task cancelled): the original exception is re-raised.
            if handler is not None:
                handler.cancel()
                with contextlib.suppress(BaseException):
                    await handler
            await epoch.close()
            raise
        finally:
            lost.cancel()
            stop.cancel()

    async def _shut_down(
        self,
        epoch: Epoch,
        handler: asyncio.Task[None] | None,
        lost: asyncio.Future[Any],
    ) -> None:
        if not lost.done():
            with contextlib.suppress(*_CLOSE_ERRORS):
                await epoch.cancel_consumer()
        if handler is not None:
            deadline = asyncio.ensure_future(self._timer(SHUTDOWN_DEADLINE_SECONDS))
            try:
                await asyncio.wait(
                    {handler, deadline, lost}, return_when=asyncio.FIRST_COMPLETED
                )
            finally:
                deadline.cancel()
            if handler.done():
                handler.result()  # MemoryError/BaseException: fatal
            else:
                if not lost.done():
                    logger.warning(SHUTDOWN_DEADLINE_EXCEEDED_EVENT)
                await _cancel_and_wait(handler)
        await epoch.close()

    async def _handle(self, delivery: Delivery, epoch: Epoch) -> None:
        """One delivery: correlation, one application attempt, the delivery
        log event, and the ACK on a live channel."""
        assert self._client is not None
        tokens = structlog.contextvars.bind_contextvars(ibs_event_id=str(uuid.uuid7()))
        try:
            try:
                result = await handle_delivery(
                    delivery.routing_key,
                    delivery.content_type,
                    delivery.body,
                    client=self._client,
                )
                _log_result(delivery, result)
                if epoch.lost.is_set():
                    return  # Dead channel: no settlement.
                try:
                    await epoch.ack(delivery)
                except _SETTLEMENT_ERRORS:
                    return  # The channel died after the check: unsettled.
            except asyncio.CancelledError:
                logger.warning(DELIVERY_CANCELLED_EVENT, **_bound_routing_key(delivery))
                raise
        finally:
            structlog.contextvars.reset_contextvars(**tokens)


def _log_result(delivery: Delivery, result: DeliveryResult) -> None:
    routing = _bound_routing_key(delivery)
    match result.outcome:
        case DeliveryOutcome.MALFORMED:
            logger.warning(
                DELIVERY_MALFORMED_EVENT,
                reason_category=result.reason_category,
                **routing,
            )
        case DeliveryOutcome.IRRELEVANT:
            logger.debug(DELIVERY_IRRELEVANT_EVENT, **routing, **result.fields)
        case DeliveryOutcome.PROCESSED:
            logger.info(DELIVERY_PROCESSED_EVENT, **routing, **result.fields)
        case DeliveryOutcome.FAILED:
            logger.error(
                DELIVERY_FAILED_EVENT,
                **routing,
                reason_category=result.reason_category,
                **result.fields,
            )
