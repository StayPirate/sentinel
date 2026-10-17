"""Tests for the real aio-pika adapter of the IBS RabbitMQ consumer
(`connect_amqp` and `_AioPikaEpoch` in
backend/app/services/ibs_event_consumer.py) against an in-process fake
AMQP 0-9-1 broker (`tests/support/amqp_server.py`).

Owning specification: docs/features/integrations/ibs-rabbitmq-integration.md
(AMQP Contract > Connection and Topology; Per-Delivery Processing >
Settlement Policy, Connection Loss and Consumer Cancellation; Process
Lifecycle > Reconnection, Fatal and Transient Failures, Graceful Shutdown;
Testing Requirements).

The adapter connects over plain TCP (`amqp://`) to 127.0.0.1, where aiormq
ignores the TLS context; the TLS transport itself is the library's and the
fixed URL scheme is enforced by `Settings`. The fake broker records every
method frame the client sends, so the tests assert the exact wire contract:
the handshake properties, the topology and its order, ACK-only settlement
(the `broker` fixture fails any test whose client sent `Basic.Nack` or
`Basic.Reject`), the broker-side `Basic.Cancel`, channel and connection
loss, the fatal and transient failure classification of the library's
real exceptions, and the fixed bounds of the handshake, every topology
operation, and the closure (withheld broker replies against patched
constants). The lifecycle itself is covered with a replaceable
connector by `test_ibs_event_consumer.py`; one end-to-end test here runs
`IBSEventConsumer` over the real adapter.

Marked `integration` because it uses loopback sockets; no database, Redis,
or external network is used.
"""

from __future__ import annotations

import asyncio
import contextlib
import gc
import ipaddress
import socket
import ssl
from collections.abc import AsyncIterator, Awaitable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

import aiormq
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from pamqp import base, commands

from app.config import Settings
from app.core.enums import IBSConsumerErrorCategory
from app.services import ibs_event_consumer
from app.services.ibs_event_consumer import (
    Delivery,
    DeliverySink,
    Epoch,
    IBSEventConsumer,
    _AioPikaEpoch,
    classify_connection_error,
    connect_amqp,
)
from app.services.ibs_event_decoding import (
    PACKAGE_COMMIT_ROUTING_KEY,
    DeliveryOutcome,
    DeliveryResult,
)
from tests.support.amqp_server import (
    WAIT_SECONDS,
    FakeAmqpServer,
    ServerConnection,
    channel_close,
)
from tests.support.ibs_consumer import (
    COMMIT_BODY,
    FakeClient,
    FakeHeartbeatStore,
    FakeRefreshTimer,
    FakeTimer,
)

pytestmark = pytest.mark.integration

_CONTENT_TYPE = "application/json"
_SETTINGS_URL = "amqps://example:example@mq.example.test"
_TOPOLOGY = [
    "Channel.Open",
    "Exchange.Declare",
    "Queue.Declare",
    "Basic.Qos",
    "Queue.Bind",
    "Queue.Bind",
    "Queue.Bind",
    "Basic.Consume",
]


def _tls_context() -> ssl.SSLContext:
    return ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)


@dataclass(eq=False)
class Sink:
    """The delivery sink: records each delivery the adapter passes on."""

    deliveries: list[Delivery] = field(default_factory=list)
    _arrived: asyncio.Event = field(default_factory=asyncio.Event)

    def __call__(self, delivery: Delivery) -> None:
        self.deliveries.append(delivery)
        self._arrived.set()

    async def wait(self, count: int = 1) -> Delivery:
        async with asyncio.timeout(WAIT_SECONDS):
            while len(self.deliveries) < count:
                self._arrived.clear()
                await self._arrived.wait()
        return self.deliveries[count - 1]


@dataclass(eq=False)
class Client:
    """Connects through the real `connect_amqp` and closes every epoch at
    teardown."""

    broker: FakeAmqpServer
    sink: Sink = field(default_factory=Sink)
    epochs: list[Epoch] = field(default_factory=list)

    async def connect(self) -> _AioPikaEpoch:
        async with asyncio.timeout(WAIT_SECONDS):
            epoch = await connect_amqp(self.broker.url, _tls_context(), self.sink)
        self.epochs.append(epoch)
        assert isinstance(epoch, _AioPikaEpoch)
        return epoch

    async def connected(self) -> tuple[_AioPikaEpoch, ServerConnection]:
        epoch = await self.connect()
        return epoch, await self.broker.connection()


@pytest.fixture(autouse=True)
async def _collect_abandoned_connections() -> AsyncIterator[None]:
    """aio-pika leaves the `Connection` of a failed `connect()` unclosed; its
    finalizer schedules `close()` on the running loop. Collect it while this
    test's loop runs, not during a later test that has no running loop."""
    yield
    gc.collect()
    for _ in range(3):
        await asyncio.sleep(0)


@pytest.fixture
async def broker() -> AsyncIterator[FakeAmqpServer]:
    async with FakeAmqpServer() as server:
        yield server
    for connection in server.connections:
        # Consume-only and ACK-only on the wire.
        assert connection.methods(commands.Basic.Publish) == []
        assert connection.methods(commands.Basic.Nack) == []
        assert connection.methods(commands.Basic.Reject) == []


@pytest.fixture
async def client(broker: FakeAmqpServer) -> AsyncIterator[Client]:
    created = Client(broker)
    yield created
    for epoch in created.epochs:
        await epoch.close()


async def _wait_lost(epoch: Epoch) -> str:
    async with asyncio.timeout(WAIT_SECONDS):
        await epoch.lost.wait()
    return epoch.loss_reason


def _deliver(connection: ServerConnection, body: bytes = COMMIT_BODY) -> int:
    return connection.deliver(
        body, routing_key=PACKAGE_COMMIT_ROUTING_KEY, content_type=_CONTENT_TYPE
    )


# ---------------------------------------------------------------------------
# Handshake
# ---------------------------------------------------------------------------


class TestHandshake:
    async def test_start_ok_announces_connection_name_and_cancel_notify(
        self, client: Client
    ) -> None:
        _, server = await client.connected()

        (start_ok,) = server.methods(commands.Connection.StartOk)
        properties = start_ok.client_properties
        assert properties["connection_name"] == "sentinel-ibs-consumer"
        capabilities = properties["capabilities"]
        assert isinstance(capabilities, dict)
        assert capabilities["consumer_cancel_notify"] is True

    async def test_tune_ok_requests_the_60_second_heartbeat(
        self, client: Client
    ) -> None:
        # The fake broker proposes 600 seconds; the client's own value wins.
        _, server = await client.connected()

        (tune_ok,) = server.methods(commands.Connection.TuneOk)
        assert tune_ok.heartbeat == 60


# ---------------------------------------------------------------------------
# Topology
# ---------------------------------------------------------------------------


class TestTopology:
    async def test_topology_is_declared_in_order_without_publisher_confirms(
        self, client: Client
    ) -> None:
        _, server = await client.connected()

        channel_methods = [frame.name for number, frame in server.received if number]
        assert channel_methods == _TOPOLOGY
        assert server.methods(commands.Confirm.Select) == []

    async def test_exchange_is_declared_passively_as_a_durable_topic(
        self, client: Client
    ) -> None:
        _, server = await client.connected()

        (declare,) = server.methods(commands.Exchange.Declare)
        assert declare.exchange == "pubsub"
        assert declare.exchange_type == "topic"
        assert declare.passive is True
        assert declare.durable is True
        assert declare.auto_delete is False
        assert declare.internal is False

    async def test_queue_is_server_named_exclusive_non_durable_auto_delete(
        self, client: Client
    ) -> None:
        _, server = await client.connected()

        (declare,) = server.methods(commands.Queue.Declare)
        assert declare.queue == ""
        assert declare.exclusive is True
        assert declare.durable is False
        assert declare.auto_delete is True
        assert declare.passive is False

    async def test_qos_is_per_consumer_prefetch_one(self, client: Client) -> None:
        _, server = await client.connected()

        (qos,) = server.methods(commands.Basic.Qos)
        assert qos.prefetch_count == 1
        assert qos.global_ is False

    async def test_server_named_queue_is_bound_to_exactly_the_three_fixed_keys(
        self, client: Client
    ) -> None:
        _, server = await client.connected()

        binds = server.methods(commands.Queue.Bind)
        assert server.queue_name is not None
        assert [bind.routing_key for bind in binds] == [
            "suse.obs.package.commit",
            "suse.obs.request.create",
            "suse.obs.request.state_change",
        ]
        for bind in binds:
            assert bind.queue == server.queue_name
            assert bind.exchange == "pubsub"
            assert bind.nowait is False
            assert bind.arguments == {}

    async def test_consumer_reads_the_server_named_queue_with_manual_ack(
        self, client: Client
    ) -> None:
        epoch, server = await client.connected()

        (consume,) = server.methods(commands.Basic.Consume)
        assert consume.queue == server.queue_name
        assert consume.no_ack is False
        assert epoch.consumer_tag == consume.consumer_tag


# ---------------------------------------------------------------------------
# Delivery and settlement
# ---------------------------------------------------------------------------


class TestDelivery:
    @pytest.mark.parametrize("content_type", [_CONTENT_TYPE, None])
    async def test_delivery_reaches_the_sink_unchanged(
        self, client: Client, content_type: str | None
    ) -> None:
        _, server = await client.connected()

        server.deliver(
            COMMIT_BODY,
            routing_key=PACKAGE_COMMIT_ROUTING_KEY,
            content_type=content_type,
        )

        delivery = await client.sink.wait()
        assert delivery.routing_key == PACKAGE_COMMIT_ROUTING_KEY
        assert delivery.content_type == content_type
        assert delivery.body == COMMIT_BODY

    async def test_ack_sends_exactly_one_basic_ack_for_the_delivery(
        self, client: Client
    ) -> None:
        epoch, server = await client.connected()
        _deliver(server, b'{"example":1}')
        tag = _deliver(server)
        await client.sink.wait(2)

        await epoch.ack(client.sink.deliveries[1])
        ack = await server.wait_for(commands.Basic.Ack)
        # Frames arrive in order: after the close, nothing else is pending.
        await epoch.close()
        await server.wait_for(commands.Connection.Close)

        assert ack.delivery_tag == tag
        assert ack.multiple is False
        assert len(server.methods(commands.Basic.Ack)) == 1

    async def test_ack_rejects_a_delivery_of_another_epoch(
        self, client: Client
    ) -> None:
        epoch = await client.connect()

        with pytest.raises(TypeError):
            await epoch.ack(cast(Delivery, object()))


# ---------------------------------------------------------------------------
# Connection loss and consumer cancellation
# ---------------------------------------------------------------------------


class TestLoss:
    async def test_broker_basic_cancel_is_consumer_cancelled_on_an_open_connection(
        self, client: Client
    ) -> None:
        epoch, server = await client.connected()

        server.cancel_consumer()

        assert await _wait_lost(epoch) == "consumer_cancelled"
        assert not epoch.connection.is_closed
        assert not server.closed.is_set()
        assert "Channel.Close" not in server.names()

    async def test_server_channel_close_is_channel_lost(self, client: Client) -> None:
        epoch, server = await client.connected()

        server.close_channel(406, "PRECONDITION_FAILED - example")

        assert await _wait_lost(epoch) == "channel_lost"
        await server.wait_for(commands.Channel.CloseOk)
        assert not epoch.connection.is_closed

    async def test_server_connection_close_is_connection_lost(
        self, client: Client
    ) -> None:
        epoch, server = await client.connected()

        server.close_connection(320, "CONNECTION_FORCED - example shutdown")

        # The connection's closing future completes before aiormq rejects
        # the channel's, so the connection callback always runs first.
        assert await _wait_lost(epoch) == "connection_lost"
        await server.wait_closed()

    async def test_abrupt_tcp_close_is_connection_lost(self, client: Client) -> None:
        epoch, server = await client.connected()

        server.abort()

        assert await _wait_lost(epoch) == "connection_lost"


# ---------------------------------------------------------------------------
# Consumer cancellation and closure by the consumer
# ---------------------------------------------------------------------------


class TestCancelAndClose:
    async def test_cancel_consumer_does_not_wait_and_keeps_the_channel_usable(
        self, broker: FakeAmqpServer, client: Client
    ) -> None:
        # The broker never answers Basic.Cancel: only nowait can return.
        broker.replies[commands.Basic.Cancel] = None
        epoch, server = await client.connected()
        tag = _deliver(server)
        delivery = await client.sink.wait()

        async with asyncio.timeout(WAIT_SECONDS):
            await epoch.cancel_consumer()
        await epoch.ack(delivery)

        cancel = await server.wait_for(commands.Basic.Cancel)
        assert cancel.nowait is True
        assert cancel.consumer_tag == epoch.consumer_tag
        ack = await server.wait_for(commands.Basic.Ack)
        assert ack.delivery_tag == tag
        assert not epoch.lost.is_set()

    async def test_close_sends_channel_close_then_connection_close(
        self, client: Client
    ) -> None:
        epoch, server = await client.connected()

        await epoch.close()

        await server.wait_closed()
        names = server.names()
        assert names.index("Channel.Close") < names.index("Connection.Close")
        assert epoch.connection.is_closed

    async def test_close_does_not_raise_when_the_server_is_gone(
        self, client: Client
    ) -> None:
        epoch, server = await client.connected()
        server.abort()
        await _wait_lost(epoch)

        async with asyncio.timeout(WAIT_SECONDS):
            await epoch.close()

        assert "Channel.Close" not in server.names()


# ---------------------------------------------------------------------------
# Fatal and transient connection failures
# ---------------------------------------------------------------------------


class TestFailures:
    @pytest.mark.parametrize(
        ("method", "reply_code", "reply_text", "error", "reason"),
        [
            pytest.param(
                commands.Exchange.Declare,
                404,
                "NOT_FOUND - no exchange 'pubsub' in vhost '/'",
                aiormq.exceptions.ChannelNotFoundEntity,
                "exchange_missing",
                id="exchange-missing",
            ),
            pytest.param(
                commands.Queue.Declare,
                406,
                "PRECONDITION_FAILED - inequivalent arg 'durable'",
                aiormq.exceptions.ChannelPreconditionFailed,
                "topology_precondition_failed",
                id="queue-precondition-failed",
            ),
            pytest.param(
                commands.Queue.Bind,
                403,
                "ACCESS_REFUSED - read access to exchange 'pubsub' refused",
                aiormq.exceptions.ChannelAccessRefused,
                "access_refused",
                id="bind-access-refused",
            ),
        ],
    )
    async def test_topology_rejection_is_fatal_and_closes_the_connection(
        self,
        broker: FakeAmqpServer,
        client: Client,
        method: type[base.Frame],
        reply_code: int,
        reply_text: str,
        error: type[Exception],
        reason: str,
    ) -> None:
        broker.replies[method] = channel_close(reply_code, reply_text, method)

        with pytest.raises(error) as raised:
            await client.connect()

        assert classify_connection_error(raised.value) == (True, reason)
        server = await broker.connection()
        await server.wait_closed()
        assert server.names()[-1] == "Connection.Close"
        assert "Basic.Consume" not in server.names()

    async def test_channel_open_failure_closes_the_partial_connection(
        self, broker: FakeAmqpServer, client: Client
    ) -> None:
        broker.replies[commands.Channel.Open] = channel_close(
            504, "CHANNEL_ERROR - example", commands.Channel.Open
        )

        with pytest.raises(aiormq.exceptions.ChannelClosed) as raised:
            await client.connect()

        assert classify_connection_error(raised.value) == (False, "amqp_error")
        server = await broker.connection()
        await server.wait_closed()
        assert server.names()[-1] == "Connection.Close"
        assert "Channel.Close" not in server.names()

    async def test_authentication_rejection_is_fatal(
        self, broker: FakeAmqpServer, client: Client
    ) -> None:
        broker.replies[commands.Connection.StartOk] = commands.Connection.Close(
            403, "ACCESS_REFUSED - Login was refused", 0, 0
        )

        with pytest.raises(aiormq.exceptions.ProbableAuthenticationError) as raised:
            await client.connect()

        assert classify_connection_error(raised.value) == (
            True,
            "authentication_rejected",
        )
        server = await broker.connection()
        await server.wait_closed()
        assert server.names() == ["Connection.StartOk"]

    async def test_refused_tcp_connection_is_a_transient_network_error(
        self,
    ) -> None:
        # A bound socket that does not listen refuses connections on its
        # port for as long as it stays open.
        with socket.socket() as unused:
            unused.bind(("127.0.0.1", 0))
            port = unused.getsockname()[1]

            with pytest.raises(aiormq.exceptions.AMQPConnectionError) as raised:
                async with asyncio.timeout(WAIT_SECONDS):
                    await connect_amqp(
                        f"amqp://example:example@127.0.0.1:{port}/",
                        _tls_context(),
                        Sink(),
                    )

        assert isinstance(raised.value.__cause__, OSError)
        assert classify_connection_error(raised.value) == (False, "network_error")


# ---------------------------------------------------------------------------
# Bounded steps (Graceful Shutdown: every connection handshake, channel open,
# topology operation, and closure step is bounded by a fixed constant)
# ---------------------------------------------------------------------------

_BOUND = 0.2
"""The patched value of each fixed bound: far below `WAIT_SECONDS`, so a
step that is not bounded by its constant fails the test's own guard."""


async def _bounded[T](awaitable: Awaitable[T]) -> asyncio.Future[T]:
    """Run `awaitable` until it finishes; fail when it outlives
    `WAIT_SECONDS` (a hang, not the step's own bound)."""
    task = asyncio.ensure_future(awaitable)
    done, _ = await asyncio.wait({task}, timeout=WAIT_SECONDS)
    if not done:
        task.cancel()
        with contextlib.suppress(BaseException):
            await task
        pytest.fail("the step was not bounded by its fixed constant")
    return task


class TestBounds:
    @pytest.mark.parametrize(
        ("method", "opened"),
        [
            pytest.param(commands.Connection.StartOk, False, id="handshake-tune"),
            pytest.param(commands.Connection.Open, False, id="handshake-open"),
            pytest.param(commands.Channel.Open, True, id="channel-open"),
            pytest.param(commands.Exchange.Declare, True, id="exchange-declare"),
            pytest.param(commands.Queue.Declare, True, id="queue-declare"),
            pytest.param(commands.Basic.Qos, True, id="qos"),
            pytest.param(commands.Queue.Bind, True, id="bind"),
            pytest.param(commands.Basic.Consume, True, id="consume"),
        ],
    )
    async def test_withheld_reply_is_bounded_and_transient(
        self,
        broker: FakeAmqpServer,
        monkeypatch: pytest.MonkeyPatch,
        method: type[base.Frame],
        opened: bool,
    ) -> None:
        """The broker never answers one handshake or topology method: the
        attempt fails with a transient `timeout` within the step's bound, and
        the partial connection is closed; after the handshake, the adapter
        closes it with `Connection.Close`."""
        monkeypatch.setattr(ibs_event_consumer, "CONNECT_TIMEOUT_SECONDS", _BOUND)
        monkeypatch.setattr(ibs_event_consumer, "OPERATION_TIMEOUT_SECONDS", _BOUND)
        broker.replies[method] = None

        attempt = await _bounded(connect_amqp(broker.url, _tls_context(), Sink()))

        error = attempt.exception()
        assert isinstance(error, TimeoutError)
        assert classify_connection_error(error) == (False, "timeout")
        server = await broker.connection()
        await server.wait_closed()
        assert len(server.methods(method)) == 1
        if opened:
            assert server.names()[-1] == "Connection.Close"

    async def test_withheld_close_replies_are_bounded(
        self, broker: FakeAmqpServer, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The broker answers neither `Channel.Close` nor `Connection.Close`:
        the channel closure, which would otherwise wait indefinitely, ends at
        its bound, the connection closure still follows (aiormq does not
        wait for `Connection.CloseOk`), and `close()` never raises."""
        monkeypatch.setattr(ibs_event_consumer, "CLOSE_TIMEOUT_SECONDS", _BOUND)
        epoch = await connect_amqp(broker.url, _tls_context(), Sink())
        server = await broker.connection()
        broker.replies[commands.Channel.Close] = None
        broker.replies[commands.Connection.Close] = None

        closing = await _bounded(epoch.close())

        assert closing.exception() is None
        await server.wait_for(commands.Connection.Close)
        assert server.names()[-2:] == ["Channel.Close", "Connection.Close"]


# ---------------------------------------------------------------------------
# TLS: the adapter's context secures the AMQPS transport
# ---------------------------------------------------------------------------


def _name(common_name: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def _fictional_pki(directory: Path, *, server_name: str) -> tuple[Path, Path, Path]:
    """A fictional CA and a server certificate for `server_name` (and, when
    it is `localhost`, 127.0.0.1); returns the CA, certificate, and key
    paths."""
    now = datetime.now(UTC)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca = (
        x509.CertificateBuilder()
        .subject_name(_name("Example Test CA"))
        .issuer_name(_name("Example Test CA"))
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(hours=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    key = ec.generate_private_key(ec.SECP256R1())
    names: list[x509.GeneralName] = [x509.DNSName(server_name)]
    if server_name == "localhost":
        names.append(x509.IPAddress(ipaddress.ip_address("127.0.0.1")))
    leaf = (
        x509.CertificateBuilder()
        .subject_name(_name(server_name))
        .issuer_name(ca.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(hours=1))
        .add_extension(x509.SubjectAlternativeName(names), critical=False)
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    ca_path = directory / "ca.pem"
    cert_path = directory / "server.pem"
    key_path = directory / "server.key"
    ca_path.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    cert_path.write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return ca_path, cert_path, key_path


def _server_context(cert: Path, key: Path) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    return context


def _trusting(ca: Path) -> ssl.SSLContext:
    """A client context like `build_tls_context()`: system CAs plus `ca`."""
    context = ssl.create_default_context()
    context.load_verify_locations(cafile=ca)
    return context


class TestTls:
    async def test_trusted_server_is_reached_through_the_given_context(
        self, tmp_path: Path
    ) -> None:
        ca, cert, key = _fictional_pki(tmp_path, server_name="localhost")

        async with FakeAmqpServer(tls=_server_context(cert, key)) as broker:
            async with asyncio.timeout(WAIT_SECONDS):
                epoch = await connect_amqp(
                    broker.tls_url("localhost"), _trusting(ca), Sink()
                )
            server = await broker.connection()
            await server.wait_for(commands.Basic.Consume)
            await epoch.close()

        assert server.methods(commands.Connection.StartOk)

    @pytest.mark.parametrize(
        ("server_name", "trusted"),
        [("localhost", False), ("mq.example.test", True)],
        ids=["untrusted-chain", "hostname-mismatch"],
    )
    async def test_certificate_verification_failure_is_fatal(
        self, tmp_path: Path, server_name: str, trusted: bool
    ) -> None:
        ca, cert, key = _fictional_pki(tmp_path, server_name=server_name)
        context = _trusting(ca) if trusted else ssl.create_default_context()

        async with FakeAmqpServer(tls=_server_context(cert, key)) as broker:
            with pytest.raises(aiormq.exceptions.AMQPConnectionError) as raised:
                async with asyncio.timeout(WAIT_SECONDS):
                    await connect_amqp(broker.tls_url("localhost"), context, Sink())

        assert isinstance(raised.value.__cause__, ssl.SSLCertVerificationError)
        assert classify_connection_error(raised.value) == (
            True,
            "tls_verification_failed",
        )


# ---------------------------------------------------------------------------
# End to end: the lifecycle over the real adapter
# ---------------------------------------------------------------------------


@dataclass(eq=False)
class _Sessions:
    """The PostgreSQL check's session factory."""

    statements: list[str] = field(default_factory=list)

    def __call__(self) -> _Sessions:
        return self

    async def __aenter__(self) -> _Sessions:
        return self

    async def __aexit__(self, *_: object) -> None:
        return None

    async def execute(self, statement: Any) -> None:
        self.statements.append(str(statement))


async def test_consumer_acks_reconnects_after_broker_cancel_and_shuts_down(
    broker: FakeAmqpServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    handled: list[tuple[str | None, str | None, bytes]] = []

    async def handle_delivery(
        routing_key: str | None,
        content_type: str | None,
        body: bytes,
        *,
        client: Any,
    ) -> DeliveryResult:
        handled.append((routing_key, content_type, body))
        return DeliveryResult(DeliveryOutcome.PROCESSED)

    monkeypatch.setattr(ibs_event_consumer, "handle_delivery", handle_delivery)
    monkeypatch.setattr(ibs_event_consumer, "build_tls_context", _tls_context)
    urls: list[str] = []

    def connect(
        url: str, ssl_context: ssl.SSLContext, sink: DeliverySink
    ) -> Awaitable[Epoch]:
        # Settings accept only amqps://; the fake broker speaks plain TCP.
        urls.append(url)
        return connect_amqp(broker.url, ssl_context, sink)

    async def dispose() -> None:
        return None

    timer = FakeTimer()
    store = FakeHeartbeatStore()
    consumer = IBSEventConsumer(
        Settings(
            _env_file=None, jwt_secret_key="a" * 32, ibs_rabbitmq_url=_SETTINGS_URL
        ),
        connect=connect,
        client_factory=cast(Any, FakeClient),
        session_factory=cast(Any, _Sessions()),
        dispose_engine=dispose,
        timer=timer,
        heartbeat_store=store,
        heartbeat_timer=FakeRefreshTimer(),
        handle_signals=False,
    )
    task = asyncio.create_task(consumer.run())
    try:
        first = await broker.connection(0)
        await first.wait_for(commands.Basic.Consume)
        tag = _deliver(first)
        ack = await first.wait_for(commands.Basic.Ack)

        first.cancel_consumer()
        second = await broker.connection(1)
        await second.wait_for(commands.Basic.Consume)
        # An ACK on the new connection proves the epoch is consuming, so
        # the shutdown below takes the consumer-cancel path.
        second_tag = _deliver(second)
        second_ack = await second.wait_for(commands.Basic.Ack)
        consumer.request_shutdown()
        async with asyncio.timeout(WAIT_SECONDS):
            code = await task
    finally:
        if not task.done():
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task

    assert code == 0
    assert ack.delivery_tag == tag
    assert second_ack.delivery_tag == second_tag
    assert handled == [(PACKAGE_COMMIT_ROUTING_KEY, _CONTENT_TYPE, COMMIT_BODY)] * 2
    assert urls == [_SETTINGS_URL, _SETTINGS_URL]
    assert timer.calls == [5.0]
    # The lost epoch was closed without a consumer cancel of its own.
    await first.wait_closed()
    assert first.methods(commands.Basic.Cancel) == []
    assert first.names()[-2:] == ["Channel.Close", "Connection.Close"]
    # Reconnection created a fresh server-named queue and bindings.
    assert second.queue_name is not None
    assert second.queue_name != first.queue_name
    assert len(second.methods(commands.Queue.Bind)) == 3
    # Graceful shutdown: nowait consumer cancel, then channel and connection.
    await second.wait_closed()
    (cancel,) = second.methods(commands.Basic.Cancel)
    assert cancel.nowait is True
    assert cancel.consumer_tag == second.consumer_tag
    assert second.names()[-3:] == ["Basic.Cancel", "Channel.Close", "Connection.Close"]
    assert len(first.methods(commands.Basic.Ack)) == 1
    assert len(second.methods(commands.Basic.Ack)) == 1
    # The heartbeat followed the real lifecycle: the broker cancel is a lost
    # connection, the reconnect is counted, and both deliveries are processed.
    assert store.statuses[:2] == ["reconnecting", "connected"]
    assert store.statuses[-1] == "connected"
    status = consumer.status
    assert (status.events_received, status.events_processed) == (2, 2)
    assert status.reconnect_attempts == 1
    assert status.last_error is IBSConsumerErrorCategory.RABBITMQ_CONNECTION_LOST
