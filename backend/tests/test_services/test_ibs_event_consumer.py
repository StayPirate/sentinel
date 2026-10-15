"""Tests for the IBS RabbitMQ consumer lifecycle
(backend/app/services/ibs_event_consumer.py) and its entry module
(backend/app/ibs_consumer.py).

Owning specification: docs/features/integrations/ibs-rabbitmq-integration.md
(Per-Delivery Processing > Correlation Scope, One-Attempt Rule, Settlement
Policy, Connection Loss and Consumer Cancellation; Process Lifecycle >
Runtime Independence, Startup, Reconnection, Fatal and Transient Failures,
Graceful Shutdown; Structured Logs; Testing Requirements), with
docs/features/platform/logging.md (IBS RabbitMQ delivery binding detail,
Reset requirement) and docs/features/platform/networking.md (a fresh TLS
context per connection attempt; missing CA warning).

The AMQP boundary is the replaceable `Connector` (`tests/support/
ibs_consumer.py`): no broker, socket, or real sleep is used, and every wait
is a `FakeTimer`. `handle_delivery()` is replaced by `Handled`, except where
the real decoding path is exercised, and the PostgreSQL check uses a fake
session factory. The real aio-pika adapter is covered by
`test_ibs_event_consumer_amqp.py`; the real-process signal handling by the
system suite.
"""

from __future__ import annotations

import asyncio
import contextlib
import contextvars
import re
import signal
import ssl
import uuid
from collections.abc import AsyncIterator, Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, cast

import aiormq
import pytest
from redis import exceptions as redis_exceptions
from structlog.contextvars import get_contextvars, merge_contextvars
from structlog.testing import capture_logs

from app.config import Settings
from app.config import settings as app_settings
from app.core.enums import IBSConsumerErrorCategory, IBSConsumerStatus
from app.core.exceptions import TLSConfigurationError
from app.services import ibs_consumer_status, ibs_event_consumer
from app.services.ibs_event_consumer import (
    SHUTDOWN_DEADLINE_SECONDS,
    IBSEventConsumer,
    classify_connection_error,
)
from app.services.ibs_event_decoding import DeliveryOutcome, DeliveryResult
from tests.support.ibs_consumer import (
    BLOCK,
    FAILED_RESULT,
    FakeBroker,
    FakeClient,
    FakeClock,
    FakeDelivery,
    FakeEpoch,
    FakeHeartbeatStore,
    FakeRefreshTimer,
    FakeTimer,
    Handled,
)

pytestmark = pytest.mark.unit

_UUID7 = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
)
_URL = "amqps://svc:mq-password-not-for-production@mq.example.test"
_WAIT = 5.0


def _settings(*, initial: int = 5, maximum: int = 300) -> Settings:
    return Settings(
        _env_file=None,
        jwt_secret_key="a" * 32,
        ibs_rabbitmq_url=_URL,
        ibs_rabbitmq_reconnect_initial=initial,
        ibs_rabbitmq_reconnect_max=maximum,
    )


@dataclass(eq=False)
class FakeSessions:
    """The PostgreSQL check's session factory."""

    error: BaseException | None = None
    hang: bool = False
    statements: list[str] = field(default_factory=list)

    def __call__(self) -> FakeSessions:
        return self

    async def __aenter__(self) -> FakeSessions:
        return self

    async def __aexit__(self, *_: object) -> None:
        return None

    async def execute(self, statement: Any) -> None:
        self.statements.append(str(statement))
        if self.hang:
            await asyncio.Event().wait()
        if self.error is not None:
            raise self.error


@dataclass(eq=False)
class Harness:
    broker: FakeBroker
    timer: FakeTimer
    client: FakeClient
    sessions: FakeSessions
    handled: Handled
    contexts: list[ssl.SSLContext]
    disposed: list[str]
    store: FakeHeartbeatStore = field(default_factory=FakeHeartbeatStore)
    refresh: FakeRefreshTimer = field(default_factory=FakeRefreshTimer)
    clock: FakeClock = field(default_factory=FakeClock)
    consumer: IBSEventConsumer | None = None
    task: asyncio.Task[int] | None = None

    def start(self, settings: Settings | None = None) -> IBSEventConsumer:
        self.consumer = IBSEventConsumer(
            settings or _settings(),
            connect=self.broker,
            client_factory=cast(Any, lambda: self.client),
            session_factory=cast(Any, self.sessions),
            dispose_engine=self._dispose,
            timer=self.timer,
            heartbeat_store=self.store,
            heartbeat_timer=self.refresh,
            clock=self.clock,
            handle_signals=False,
        )
        self.task = asyncio.create_task(self.consumer.run())
        return self.consumer

    async def _dispose(self) -> None:
        self.disposed.append("engine")

    async def stop(self) -> int:
        assert self.consumer is not None
        assert self.task is not None
        self.consumer.request_shutdown()
        return await self.result()

    async def result(self) -> int:
        assert self.task is not None
        return await asyncio.wait_for(self.task, _WAIT)


@pytest.fixture
async def harness(monkeypatch: pytest.MonkeyPatch) -> AsyncIterator[Harness]:
    contexts: list[ssl.SSLContext] = []

    def fresh_context() -> ssl.SSLContext:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        contexts.append(context)
        return context

    handled = Handled()
    monkeypatch.setattr(ibs_event_consumer, "build_tls_context", fresh_context)
    monkeypatch.setattr(ibs_event_consumer, "handle_delivery", handled)
    created = Harness(
        broker=FakeBroker(),
        timer=FakeTimer(),
        client=FakeClient(),
        sessions=FakeSessions(),
        handled=handled,
        contexts=contexts,
        disposed=[],
    )
    try:
        yield created
    finally:
        if created.task is not None and not created.task.done():
            created.task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await created.task


def _events(
    logs: Sequence[Mapping[str, Any]], prefix: str = "ibs_consumer_"
) -> list[str]:
    return [entry["event"] for entry in logs if entry["event"].startswith(prefix)]


def _entry(logs: Sequence[Mapping[str, Any]], name: str) -> Mapping[str, Any]:
    (entry,) = [entry for entry in logs if entry["event"] == name]
    return entry


async def _until(predicate: Callable[[], bool]) -> None:
    """Yield to the event loop until `predicate` holds (bounded)."""
    for _ in range(100_000):
        if predicate():
            return
        await asyncio.sleep(0)
    raise AssertionError("condition not reached")


# ---------------------------------------------------------------------------
# Startup
# ---------------------------------------------------------------------------


class TestStartup:
    async def test_postgresql_failure_is_critical_and_exits_without_connecting(
        self, harness: Harness
    ) -> None:
        harness.sessions.error = OSError("fictional refused")

        with capture_logs() as logs:
            harness.start()
            code = await harness.result()

        assert code == 1
        assert _entry(logs, "ibs_consumer_startup_failed") == {
            "event": "ibs_consumer_startup_failed",
            "log_level": "critical",
            "reason_category": "postgresql_unavailable",
        }
        assert harness.broker.urls == []
        assert harness.client.closed == 0
        assert harness.disposed == ["engine"]
        assert "fictional refused" not in repr(logs)

    async def test_postgresql_check_is_bounded(
        self, harness: Harness, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(ibs_event_consumer, "STARTUP_CHECK_TIMEOUT_SECONDS", 0.01)
        harness.sessions.hang = True

        harness.start()

        assert await harness.result() == 1
        assert harness.broker.urls == []

    async def test_started_follows_the_check_and_precedes_the_first_attempt(
        self, harness: Harness
    ) -> None:
        with capture_logs() as logs:
            harness.start()
            await _until(lambda: "ibs_consumer_connected" in _events(logs))
            code = await harness.stop()

        assert code == 0
        assert harness.sessions.statements == ["SELECT 1"]
        assert _events(logs)[:2] == ["ibs_consumer_started", "ibs_consumer_connected"]
        assert harness.broker.urls == [_URL]
        assert harness.client.closed == 1
        assert harness.disposed == ["engine"]
        assert _events(logs)[-1] == "ibs_consumer_stopped"
        assert "mq-password-not-for-production" not in repr(logs)
        assert "mq.example.test" not in repr(logs)

    # ---------------------------------------------------------------------------
    # Reconnection
    # ---------------------------------------------------------------------------

    async def test_invalid_ca_at_client_creation_is_a_fatal_tls_error(
        self, harness: Harness, monkeypatch: pytest.MonkeyPatch, tmp_path: Any
    ) -> None:
        """The real `IBSClient` builds its TLS context from a corrupt
        `SUSE_CA_CERT_PATH` before the first connection attempt."""
        corrupt = tmp_path / "corrupt.crt"
        corrupt.write_text("-----BEGIN CERTIFICATE-----\nnot base64\n")
        monkeypatch.setattr(app_settings, "suse_ca_cert_path", str(corrupt))
        consumer = IBSEventConsumer(
            _settings(),
            connect=harness.broker,
            session_factory=cast(Any, harness.sessions),
            dispose_engine=harness._dispose,
            timer=harness.timer,
            heartbeat_store=harness.store,
            heartbeat_timer=harness.refresh,
            clock=harness.clock,
            handle_signals=False,
        )

        with capture_logs() as logs:
            code = await asyncio.wait_for(consumer.run(), _WAIT)

        assert code == 1
        assert _entry(logs, "ibs_consumer_fatal")["reason_category"] == (
            "tls_configuration_invalid"
        )
        assert "ibs_consumer_started" not in _events(logs)
        assert harness.broker.urls == []
        assert harness.disposed == ["engine"]

    async def test_memory_error_in_the_check_is_fatal(self, harness: Harness) -> None:
        harness.sessions.error = MemoryError()

        with capture_logs() as logs:
            harness.start()
            code = await harness.result()

        assert code == 1
        assert _entry(logs, "ibs_consumer_fatal")["reason_category"] == "memory_error"
        assert harness.broker.urls == []

    async def test_signal_handlers_are_installed_and_removed(
        self, harness: Harness, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        loop = asyncio.get_running_loop()
        added: list[tuple[int, Any]] = []
        removed: list[int] = []
        monkeypatch.setattr(
            loop, "add_signal_handler", lambda sig, cb: added.append((sig, cb))
        )

        def remove(sig: int) -> bool:
            removed.append(sig)
            return True

        monkeypatch.setattr(loop, "remove_signal_handler", remove)
        consumer = IBSEventConsumer(
            _settings(),
            connect=harness.broker,
            client_factory=cast(Any, lambda: harness.client),
            session_factory=cast(Any, harness.sessions),
            dispose_engine=harness._dispose,
            timer=harness.timer,
            heartbeat_store=harness.store,
            heartbeat_timer=harness.refresh,
            clock=harness.clock,
        )
        task = asyncio.create_task(consumer.run())
        await harness.broker.wait_connected()

        assert [sig for sig, _ in added] == [signal.SIGTERM, signal.SIGINT]
        added[0][1]()  # The SIGTERM callback starts the graceful shutdown.
        assert await asyncio.wait_for(task, _WAIT) == 0
        assert removed == [signal.SIGTERM, signal.SIGINT]


class TestReconnection:
    async def test_delay_doubles_to_the_cap_with_a_fresh_context_per_attempt(
        self, harness: Harness
    ) -> None:
        harness.broker.script = [ConnectionRefusedError()] * 6
        harness.timer.on_wait = lambda count, _: (
            harness.consumer.request_shutdown()
            if count == 6 and harness.consumer
            else None
        )

        with capture_logs() as logs:
            harness.start(_settings(initial=5, maximum=20))
            code = await harness.result()

        assert code == 0
        assert harness.timer.calls == [5, 10, 20, 20, 20, 20]
        assert len(harness.broker.urls) == 6
        assert len({id(context) for context in harness.contexts}) == 6
        assert harness.broker.contexts == harness.contexts
        assert [e["delay_seconds"] for e in logs if "delay_seconds" in e] == [
            5,
            10,
            20,
            20,
            20,
            20,
        ]
        assert {
            e["reason_category"]
            for e in logs
            if e["event"] == "ibs_consumer_connection_failed"
        } == {"network_error"}

    async def test_first_attempt_never_waits_and_success_resets_the_delay(
        self, harness: Harness
    ) -> None:
        harness.broker.script = [OSError(), OSError()]
        harness.start()
        epoch = await harness.broker.wait_connected()
        assert harness.timer.calls == [5, 10]

        harness.broker.script = [OSError()]
        epoch.lose("connection_lost")
        await harness.broker.wait_connected(2)

        assert harness.timer.calls == [5, 10, 5, 10]
        assert epoch.closed
        assert await harness.stop() == 0

    async def test_shutdown_interrupts_the_backoff_wait(self, harness: Harness) -> None:
        harness.broker.script = [OSError()]
        harness.timer.blocking = lambda _seconds: True

        harness.start()
        async with asyncio.timeout(_WAIT):
            await harness.timer.waiting.wait()

        assert await harness.stop() == 0
        assert len(harness.broker.urls) == 1

    async def test_shutdown_interrupts_a_connection_attempt(
        self, harness: Harness
    ) -> None:
        harness.broker.script = [BLOCK]

        harness.start()
        async with asyncio.timeout(_WAIT):
            await harness.broker.attempted.wait()

        assert await harness.stop() == 0
        assert harness.broker.epochs == []


# ---------------------------------------------------------------------------
# Failure classification
# ---------------------------------------------------------------------------


def _wrapped(cause: BaseException) -> aiormq.exceptions.AMQPConnectionError:
    """How aiormq 7 reports a transport `OSError`."""
    try:
        raise aiormq.exceptions.AMQPConnectionError(*cause.args) from cause
    except aiormq.exceptions.AMQPConnectionError as error:
        return error


def _verification_failure(code: int) -> ssl.SSLCertVerificationError:
    error = ssl.SSLCertVerificationError(1, "certificate verify failed")
    error.verify_code = code
    return error


_CLASSIFIED: list[tuple[str, Callable[[], BaseException], bool, str]] = [
    (
        "untrusted-chain",
        lambda: _wrapped(_verification_failure(20)),
        True,
        "tls_verification_failed",
    ),
    (
        "hostname-mismatch",
        lambda: _wrapped(_verification_failure(62)),
        True,
        "tls_verification_failed",
    ),
    (
        "raw-verification",
        lambda: _verification_failure(62),
        True,
        "tls_verification_failed",
    ),
    (
        "tls-configuration",
        lambda: TLSConfigurationError("certs/x.crt", "bad"),
        True,
        "tls_configuration_invalid",
    ),
    (
        "login-refused",
        lambda: aiormq.exceptions.ProbableAuthenticationError("ACCESS_REFUSED"),
        True,
        "authentication_rejected",
    ),
    (
        "mechanism",
        lambda: aiormq.exceptions.AuthenticationError("AMQPLAIN", ["PLAIN"]),
        True,
        "authentication_rejected",
    ),
    (
        "channel-access",
        lambda: aiormq.exceptions.ChannelAccessRefused("ACCESS_REFUSED"),
        True,
        "access_refused",
    ),
    (
        "not-allowed",
        # RabbitMQ also refuses with NOT_ALLOWED for a reached connection
        # limit or a virtual host that is down: transient, not fatal.
        lambda: aiormq.exceptions.ConnectionNotAllowed("NOT_ALLOWED"),
        False,
        "amqp_error",
    ),
    (
        "connection-530",
        lambda: aiormq.exceptions.ConnectionClosed(530, "NOT_ALLOWED"),
        False,
        "amqp_error",
    ),
    (
        "connection-403",
        lambda: aiormq.exceptions.ConnectionClosed(403, "ACCESS_REFUSED"),
        True,
        "access_refused",
    ),
    (
        "missing-exchange",
        lambda: aiormq.exceptions.ChannelNotFoundEntity("NOT_FOUND"),
        True,
        "exchange_missing",
    ),
    (
        "precondition",
        lambda: aiormq.exceptions.ChannelPreconditionFailed("PRECONDITION_FAILED"),
        True,
        "topology_precondition_failed",
    ),
    (
        "dns",
        lambda: _wrapped(OSError(-2, "Name or service not known")),
        False,
        "network_error",
    ),
    (
        "refused",
        lambda: _wrapped(ConnectionRefusedError(111, "refused")),
        False,
        "network_error",
    ),
    ("plain-oserror", lambda: ConnectionResetError(), False, "network_error"),
    ("timeout", lambda: TimeoutError(), False, "timeout"),
    (
        "tls-handshake",
        lambda: _wrapped(ssl.SSLError(1, "handshake failure")),
        False,
        "tls_handshake_failed",
    ),
    (
        "broker-shutdown",
        lambda: aiormq.exceptions.ConnectionClosed(320, "CONNECTION_FORCED"),
        False,
        "amqp_error",
    ),
    (
        "protocol",
        lambda: aiormq.exceptions.IncompatibleProtocolError(),
        False,
        "amqp_error",
    ),
    (
        "frame",
        lambda: aiormq.exceptions.InvalidFrameError("frame"),
        False,
        "amqp_error",
    ),
    (
        "channel-closed",
        lambda: aiormq.exceptions.ChannelClosed(None, None),
        False,
        "amqp_error",
    ),
    (
        "channel-state",
        lambda: aiormq.exceptions.ChannelInvalidStateError(),
        False,
        "amqp_error",
    ),
]


class TestClassification:
    @pytest.mark.parametrize(
        ("make", "fatal", "reason"),
        [
            pytest.param(make, fatal, reason, id=name)
            for name, make, fatal, reason in _CLASSIFIED
        ],
    )
    def test_condition_is_classified(
        self, make: Callable[[], BaseException], fatal: bool, reason: str
    ) -> None:
        assert classify_connection_error(make()) == (fatal, reason)

    def test_unclassified_exception_is_rejected(self) -> None:
        with pytest.raises(TypeError):
            classify_connection_error(ValueError("fictional"))

    @pytest.mark.parametrize(
        ("make", "reason"),
        [
            pytest.param(make, reason, id=name)
            for name, make, fatal, reason in _CLASSIFIED
            if fatal and name != "tls-configuration"
        ],
    )
    async def test_fatal_condition_exits_one_without_reconnecting(
        self, harness: Harness, make: Callable[[], BaseException], reason: str
    ) -> None:
        harness.broker.script = [make()]

        with capture_logs() as logs:
            harness.start()
            code = await harness.result()

        assert code == 1
        assert _entry(logs, "ibs_consumer_fatal") == {
            "event": "ibs_consumer_fatal",
            "log_level": "critical",
            "reason_category": reason,
        }
        assert len(harness.broker.urls) == 1
        assert harness.timer.calls == []
        assert harness.client.closed == 1
        assert harness.disposed == ["engine"]

    async def test_invalid_tls_configuration_is_fatal_before_connecting(
        self, harness: Harness, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def corrupt() -> ssl.SSLContext:
            raise TLSConfigurationError(path="certs/example.crt", detail="bad")

        monkeypatch.setattr(ibs_event_consumer, "build_tls_context", corrupt)

        with capture_logs() as logs:
            harness.start()
            code = await harness.result()

        assert code == 1
        assert _entry(logs, "ibs_consumer_fatal")["reason_category"] == (
            "tls_configuration_invalid"
        )
        assert harness.broker.urls == []

    async def test_missing_ca_warns_and_connects_with_the_system_context(
        self,
        harness: Harness,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Any,
    ) -> None:
        from app.services import http_client

        monkeypatch.setattr(
            app_settings, "suse_ca_cert_path", str(tmp_path / "missing.crt")
        )
        monkeypatch.setattr(
            ibs_event_consumer, "build_tls_context", http_client.build_tls_context
        )

        with capture_logs() as logs:
            harness.start()
            await harness.broker.wait_connected()
            await harness.stop()

        assert [e["event"] for e in logs].count("suse_ca_cert_missing") == 1
        assert isinstance(harness.broker.contexts[0], ssl.SSLContext)

    async def test_unclassified_connection_exception_is_fatal(
        self, harness: Harness
    ) -> None:
        harness.broker.script = [ValueError("fictional bug")]

        with capture_logs() as logs:
            harness.start()
            code = await harness.result()

        assert code == 1
        assert _entry(logs, "ibs_consumer_fatal")["reason_category"] == (
            "unexpected_error"
        )

    async def test_memory_error_while_connecting_is_fatal(
        self, harness: Harness
    ) -> None:
        harness.broker.script = [MemoryError()]

        with capture_logs() as logs:
            harness.start()
            code = await harness.result()

        assert code == 1
        assert _entry(logs, "ibs_consumer_fatal")["reason_category"] == "memory_error"


# ---------------------------------------------------------------------------
# Deliveries
# ---------------------------------------------------------------------------


class TestDeliveries:
    async def test_deliveries_are_handled_sequentially_and_acked_once(
        self, harness: Harness
    ) -> None:
        events = harness.broker.events
        harness.handled.events = events
        gate = asyncio.Event()
        harness.handled.gate = gate
        harness.start()
        epoch = await harness.broker.wait_connected()

        first, second = FakeDelivery(body=b"{}"), FakeDelivery(body=b"[]")
        harness.broker.deliver(first)
        harness.broker.deliver(second)
        await _until(lambda: len(harness.handled.calls) == 1)
        for _ in range(10):
            await asyncio.sleep(0)
        assert len(harness.handled.calls) == 1
        assert epoch.acks == []

        gate.set()
        await _until(lambda: len(epoch.acks) == 2)

        assert epoch.acks == [first, second]
        assert [call["body"] for call in harness.handled.calls] == [b"{}", b"[]"]
        assert events[events.index("connected") :] == [
            "connected",
            "handle",
            "ack",
            "handle",
            "ack",
        ]
        assert await harness.stop() == 0

    async def test_every_delivery_binds_a_fresh_uuid7_and_resets_it(
        self, harness: Harness
    ) -> None:
        with capture_logs(processors=[merge_contextvars]) as logs:
            harness.start()
            epoch = await harness.broker.wait_connected()
            harness.broker.deliver()
            harness.broker.deliver()
            await _until(lambda: len(epoch.acks) == 2)
            epoch.lose("channel_lost")
            await harness.broker.wait_connected(2)
            await harness.stop()

        ids = [call["ibs_event_id"] for call in harness.handled.calls]
        assert len(ids) == 2
        assert all(_UUID7.fullmatch(value) for value in ids)
        assert ids[0] != ids[1]
        assert uuid.UUID(ids[0]).version == 7
        delivery_logs = [
            e for e in logs if e["event"].startswith("ibs_consumer_delivery_")
        ]
        assert [e["ibs_event_id"] for e in delivery_logs] == ids
        lifecycle = [
            e
            for e in logs
            if e["event"].startswith("ibs_consumer_")
            and not e["event"].startswith("ibs_consumer_delivery_")
        ]
        assert lifecycle
        assert all("ibs_event_id" not in e for e in lifecycle)
        assert "ibs_event_id" not in get_contextvars()

    @pytest.mark.parametrize(
        ("result", "event", "level", "fields"),
        [
            (
                DeliveryResult(
                    DeliveryOutcome.PROCESSED,
                    fields={"project": "SUSE:SLE-15-SP6:Update", "track_count": 2},
                ),
                "ibs_consumer_delivery_processed",
                "info",
                {"project": "SUSE:SLE-15-SP6:Update", "track_count": 2},
            ),
            (
                DeliveryResult(DeliveryOutcome.IRRELEVANT),
                "ibs_consumer_delivery_irrelevant",
                "debug",
                {},
            ),
            (
                DeliveryResult(
                    DeliveryOutcome.FAILED,
                    "track_failed",
                    {"track_count": 2, "failed_track_count": 1},
                    IBSConsumerErrorCategory.PACKAGE_RECONCILIATION_FAILED,
                ),
                "ibs_consumer_delivery_failed",
                "error",
                {
                    "reason_category": "track_failed",
                    "track_count": 2,
                    "failed_track_count": 1,
                },
            ),
            (
                DeliveryResult(DeliveryOutcome.MALFORMED, "invalid_json"),
                "ibs_consumer_delivery_malformed",
                "warning",
                {"reason_category": "invalid_json"},
            ),
        ],
    )
    async def test_each_outcome_logs_its_event_and_acks(
        self,
        harness: Harness,
        result: DeliveryResult,
        event: str,
        level: str,
        fields: dict[str, Any],
    ) -> None:
        harness.handled.result = result

        with capture_logs() as logs:
            harness.start()
            epoch = await harness.broker.wait_connected()
            harness.broker.deliver()
            await _until(lambda: len(epoch.acks) == 1)
            await harness.stop()

        assert _entry(logs, event) == {
            "event": event,
            "log_level": level,
            "routing_key": "suse.obs.package.commit",
            **fields,
        }
        assert "example-user" not in repr(logs)

    async def test_unbound_routing_key_is_never_logged(
        self, harness: Harness, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The real decoding path: an unbound key is malformed, ACKed once,
        and logged without its routing key or payload."""
        from app.services.packages.ibs_event_handlers import handle_delivery

        monkeypatch.setattr(ibs_event_consumer, "handle_delivery", handle_delivery)

        with capture_logs() as logs:
            harness.start()
            epoch = await harness.broker.wait_connected()
            harness.broker.deliver(
                FakeDelivery(routing_key="suse.obs.example.secret", body=b"x=1")
            )
            await _until(lambda: len(epoch.acks) == 1)
            await harness.stop()

        assert _entry(logs, "ibs_consumer_delivery_malformed") == {
            "event": "ibs_consumer_delivery_malformed",
            "log_level": "warning",
            "reason_category": "unsupported_routing_key",
        }
        assert "suse.obs.example.secret" not in repr(logs)

    @pytest.mark.parametrize(
        "reason", ["connection_lost", "channel_lost", "consumer_cancelled"]
    )
    async def test_dead_channel_cancels_the_handler_without_settlement(
        self, harness: Harness, reason: str
    ) -> None:
        harness.handled.gate = asyncio.Event()

        with capture_logs(processors=[merge_contextvars]) as logs:
            harness.start()
            first = await harness.broker.wait_connected()
            harness.broker.deliver()
            await _until(lambda: len(harness.handled.calls) == 1)
            first.lose(reason)
            second = await harness.broker.wait_connected(2)

            harness.handled.gate.set()
            harness.broker.deliver()
            await _until(lambda: len(second.acks) == 1)
            await harness.stop()

        assert first.acks == []
        assert first.closed
        assert harness.handled.finished == [harness.handled.calls[1]["ibs_event_id"]]
        cancelled = _entry(logs, "ibs_consumer_delivery_cancelled")
        assert cancelled["ibs_event_id"] == harness.handled.calls[0]["ibs_event_id"]
        assert _entry(logs, "ibs_consumer_connection_lost")["reason_category"] == reason
        assert harness.timer.calls == [5]

    async def test_loss_during_processing_prevents_the_ack(
        self, harness: Harness
    ) -> None:
        """The channel dies while the handler completes: the committed
        outcome is kept, nothing is settled."""
        harness.start()
        epoch = await harness.broker.wait_connected()
        harness.handled.on_call = lambda: epoch.lose("channel_lost")
        harness.broker.deliver()
        await harness.broker.wait_connected(2)

        assert epoch.acks == []
        assert await harness.stop() == 0

    async def test_ack_failure_on_a_closed_channel_settles_nothing(
        self, harness: Harness
    ) -> None:
        harness.start()
        epoch = await harness.broker.wait_connected()
        epoch.ack_error = aiormq.exceptions.ChannelInvalidStateError("closed")
        harness.broker.deliver()
        await _until(lambda: len(harness.handled.finished) == 1)
        epoch.lose("channel_lost")
        await harness.broker.wait_connected(2)

        assert epoch.acks == []
        assert await harness.stop() == 0

    async def test_memory_error_exits_one_without_settlement(
        self, harness: Harness
    ) -> None:
        harness.handled.error = MemoryError()

        with capture_logs() as logs:
            harness.start()
            epoch = await harness.broker.wait_connected()
            harness.broker.deliver()
            code = await harness.result()

        assert code == 1
        assert epoch.acks == []
        assert epoch.closed
        assert _entry(logs, "ibs_consumer_fatal")["reason_category"] == "memory_error"
        assert harness.client.closed == 1
        assert harness.disposed == ["engine"]

    async def test_cancelling_the_process_task_cancels_the_handler_and_closes(
        self, harness: Harness
    ) -> None:
        harness.handled.gate = asyncio.Event()
        harness.start()
        epoch = await harness.broker.wait_connected()
        harness.broker.deliver()
        await _until(lambda: len(harness.handled.calls) == 1)
        assert harness.task is not None

        harness.task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await harness.task

        assert epoch.closed
        assert epoch.acks == []
        assert harness.handled.finished == []
        assert harness.client.closed == 1


class TestCancelAndWait:
    async def test_abandoned_task_outcomes_are_discarded(self) -> None:
        async def failing() -> None:
            raise RuntimeError("fictional")

        task = asyncio.ensure_future(failing())
        await asyncio.sleep(0)

        await ibs_event_consumer._cancel_and_wait(task)

        assert task.done()

    async def test_memory_error_of_the_task_propagates(self) -> None:
        async def exhausted() -> None:
            raise MemoryError

        task = asyncio.ensure_future(exhausted())
        await asyncio.sleep(0)

        with pytest.raises(MemoryError):
            await ibs_event_consumer._cancel_and_wait(task)

    async def test_cancellation_of_the_waiter_propagates(self) -> None:
        async def stubborn() -> None:
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                await asyncio.Event().wait()

        target = asyncio.ensure_future(stubborn())
        await asyncio.sleep(0)
        waiter = asyncio.ensure_future(ibs_event_consumer._cancel_and_wait(target))
        for _ in range(3):  # The target absorbs the first cancellation.
            await asyncio.sleep(0)

        waiter.cancel()
        with pytest.raises(asyncio.CancelledError):
            await waiter
        target.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await target

    async def test_default_timer_is_an_asyncio_sleep(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        slept: list[float] = []

        async def recorded(seconds: float) -> None:
            slept.append(seconds)

        monkeypatch.setattr(asyncio, "sleep", recorded)

        await ibs_event_consumer._sleep(7.0)

        assert slept == [7.0]


# ---------------------------------------------------------------------------
# Graceful shutdown
# ---------------------------------------------------------------------------


class TestShutdown:
    async def test_in_flight_handler_completes_within_the_deadline(
        self, harness: Harness
    ) -> None:
        events = harness.broker.events
        gate = asyncio.Event()
        harness.handled.gate = gate
        harness.timer.blocking = lambda seconds: seconds == SHUTDOWN_DEADLINE_SECONDS

        with capture_logs() as logs:
            harness.start()
            epoch = await harness.broker.wait_connected()
            harness.broker.deliver()
            await _until(lambda: len(harness.handled.calls) == 1)
            assert harness.consumer is not None
            harness.consumer.request_shutdown()
            await _until(lambda: epoch.consumer_cancelled)
            harness.broker.deliver()  # Not accepted after the request.
            gate.set()
            code = await harness.result()

        assert code == 0
        assert len(epoch.acks) == 1
        assert len(harness.handled.calls) == 1
        assert events[events.index("connected") :] == [
            "connected",
            "cancel_consumer",
            "ack",
            "close",
        ]
        assert harness.timer.calls == [SHUTDOWN_DEADLINE_SECONDS]
        assert "ibs_consumer_shutdown_started" in _events(logs)
        assert _events(logs)[-1] == "ibs_consumer_stopped"
        assert "ibs_consumer_shutdown_deadline_exceeded" not in _events(logs)
        assert harness.client.closed == 1
        assert harness.disposed == ["engine"]

    async def test_deadline_expiry_cancels_the_handler_without_settlement(
        self, harness: Harness
    ) -> None:
        harness.handled.gate = asyncio.Event()

        with capture_logs() as logs:
            harness.start()
            epoch = await harness.broker.wait_connected()
            harness.broker.deliver()
            await _until(lambda: len(harness.handled.calls) == 1)
            code = await harness.stop()

        assert code == 0
        assert epoch.acks == []
        assert epoch.closed
        assert harness.timer.calls == [SHUTDOWN_DEADLINE_SECONDS]
        assert "ibs_consumer_shutdown_deadline_exceeded" in _events(logs)
        assert "ibs_consumer_delivery_cancelled" in _events(logs)

    async def test_channel_dying_during_shutdown_settles_nothing(
        self, harness: Harness
    ) -> None:
        harness.handled.gate = asyncio.Event()
        harness.timer.blocking = lambda seconds: seconds == SHUTDOWN_DEADLINE_SECONDS

        with capture_logs() as logs:
            harness.start()
            epoch = await harness.broker.wait_connected()
            harness.broker.deliver()
            await _until(lambda: len(harness.handled.calls) == 1)
            assert harness.consumer is not None
            harness.consumer.request_shutdown()
            await _until(lambda: epoch.consumer_cancelled)
            epoch.lose("connection_lost")
            code = await harness.result()

        assert code == 0
        assert epoch.acks == []
        assert epoch.closed
        assert "ibs_consumer_shutdown_deadline_exceeded" not in _events(logs)
        assert len(harness.broker.epochs) == 1

    async def test_repeated_signal_is_ignored(self, harness: Harness) -> None:
        with capture_logs() as logs:
            harness.start()
            await harness.broker.wait_connected()
            await _until(lambda: "ibs_consumer_connected" in _events(logs))
            assert harness.consumer is not None
            harness.consumer.request_shutdown()
            harness.consumer.request_shutdown()
            code = await harness.result()

        assert code == 0
        assert _events(logs).count("ibs_consumer_shutdown_started") == 1

    async def test_hanging_client_and_engine_closure_are_bounded(
        self, harness: Harness, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(ibs_event_consumer, "CLOSE_TIMEOUT_SECONDS", 0.01)

        async def hang() -> None:
            await asyncio.Event().wait()

        monkeypatch.setattr(harness.client, "aclose", hang)
        harness._dispose = hang  # type: ignore[method-assign]

        harness.start()
        await harness.broker.wait_connected()

        assert await harness.stop() == 0

    async def test_idle_shutdown_cancels_the_consumer_and_closes(
        self, harness: Harness
    ) -> None:
        with capture_logs() as logs:
            harness.start()
            epoch = await harness.broker.wait_connected()
            await _until(lambda: "ibs_consumer_connected" in _events(logs))

            assert await harness.stop() == 0
        assert epoch.consumer_cancelled
        assert epoch.closed
        assert harness.timer.calls == []


# ---------------------------------------------------------------------------
# Correlation reset (in the calling context)
# ---------------------------------------------------------------------------


class TestCorrelationReset:
    """`_handle()` resets `ibs_event_id` in `finally` for every outcome, so
    the ID cannot leak into the context that awaits it (logging.md, Reset
    requirement)."""

    @staticmethod
    def _consumer(harness: Harness) -> IBSEventConsumer:
        consumer = IBSEventConsumer(
            _settings(),
            connect=harness.broker,
            client_factory=cast(Any, lambda: harness.client),
            session_factory=cast(Any, harness.sessions),
            dispose_engine=harness._dispose,
            timer=harness.timer,
            heartbeat_store=harness.store,
            heartbeat_timer=harness.refresh,
            clock=harness.clock,
            handle_signals=False,
        )
        consumer._client = cast(Any, harness.client)
        return consumer

    @pytest.mark.parametrize(
        "result",
        [
            DeliveryResult(DeliveryOutcome.PROCESSED),
            DeliveryResult(DeliveryOutcome.MALFORMED, "invalid_json"),
            FAILED_RESULT,
        ],
        ids=lambda result: result.outcome.value,
    )
    async def test_outcome_leaves_no_correlation_behind(
        self, harness: Harness, result: DeliveryResult
    ) -> None:
        harness.handled.result = result
        epoch = FakeEpoch(harness.broker.events)

        await self._consumer(harness)._handle(FakeDelivery(), epoch)

        assert _UUID7.fullmatch(harness.handled.calls[0]["ibs_event_id"])
        assert "ibs_event_id" not in get_contextvars()
        assert len(epoch.acks) == 1

    async def test_cancellation_leaves_no_correlation_behind(
        self, harness: Harness
    ) -> None:
        """Cancelled in its own task: the task's context is inspected after
        the cancellation completes."""
        harness.handled.gate = asyncio.Event()
        epoch = FakeEpoch(harness.broker.events)
        context = contextvars.copy_context()
        handling = asyncio.get_running_loop().create_task(
            self._consumer(harness)._handle(FakeDelivery(), epoch), context=context
        )
        await _until(lambda: len(harness.handled.calls) == 1)
        assert "ibs_event_id" in context.run(get_contextvars)

        handling.cancel()
        with pytest.raises(asyncio.CancelledError):
            await handling

        assert "ibs_event_id" not in context.run(get_contextvars)
        assert epoch.acks == []

    async def test_exception_leaves_no_correlation_behind(
        self, harness: Harness
    ) -> None:
        harness.handled.error = MemoryError()
        epoch = FakeEpoch(harness.broker.events)

        with pytest.raises(MemoryError):
            await self._consumer(harness)._handle(FakeDelivery(), epoch)

        assert "ibs_event_id" not in get_contextvars()


# ---------------------------------------------------------------------------
# Heartbeat (Startup steps 3 and 5, Reconnection status writes, Settlement
# Policy counters, Graceful Shutdown step 5, Fatal and Transient Failures)
# ---------------------------------------------------------------------------

_STARTED = "2026-09-08T14:00:00Z"  # START truncated to whole seconds.


def _published(**expected: Any) -> Callable[[dict[str, Any]], bool]:
    """A predicate matching a written document by a subset of its fields."""
    return lambda document: all(document[k] == v for k, v in expected.items())


class TestHeartbeatStatus:
    async def test_reconnecting_is_written_before_the_initial_attempt(
        self, harness: Harness
    ) -> None:
        """Startup step 5 starts the writer before step 6 connects: a
        refusing or hanging broker is reported `reconnecting`."""
        harness.store.events = harness.broker.events
        harness.broker.script = [BLOCK]

        harness.start()
        async with asyncio.timeout(_WAIT):
            await harness.broker.attempted.wait()
        document = await harness.store.wait_for(_published(status="reconnecting"))

        assert harness.broker.events[:2] == ["heartbeat:reconnecting", "attempt"]
        assert document == {
            "status": "reconnecting",
            "heartbeat_at": _STARTED,
            "process_started_at": _STARTED,
            "status_since": _STARTED,
            "events_received": 0,
            "events_relevant": 0,
            "events_processed": 0,
            "processing_failed": 0,
            "reconnect_attempts": 0,
            "next_retry_seconds": None,
            "last_error": None,
            "last_error_at": None,
        }
        assert await harness.stop() == 0

    async def test_failed_attempts_record_the_wait_and_count_reconnects(
        self, harness: Harness
    ) -> None:
        harness.broker.script = [OSError(), OSError()]
        harness.timer.blocking = lambda _seconds: True
        store, clock = harness.store, harness.clock

        harness.start()
        clock.advance(3)
        first_wait = await store.wait_for(_published(next_retry_seconds=5))
        assert first_wait["status"] == "reconnecting"
        assert first_wait["status_since"] == _STARTED  # No status change.
        assert first_wait["reconnect_attempts"] == 0  # The initial attempt.
        assert first_wait["last_error"] == "rabbitmq_connection_failed"
        assert first_wait["last_error_at"] == "2026-09-08T14:00:03Z"

        clock.advance(5)
        harness.timer.release()
        second_wait = await store.wait_for(_published(next_retry_seconds=10))
        assert second_wait["reconnect_attempts"] == 1
        assert second_wait["last_error_at"] == "2026-09-08T14:00:08Z"

        clock.advance(10)
        harness.timer.release()
        connected = await store.wait_for(_published(status="connected"))

        assert connected["reconnect_attempts"] == 2
        assert connected["next_retry_seconds"] is None
        assert connected["status_since"] == "2026-09-08T14:00:18Z"
        assert connected["heartbeat_at"] == "2026-09-08T14:00:18Z"
        # A successful connection keeps the last failure.
        assert connected["last_error"] == "rabbitmq_connection_failed"
        assert connected["last_error_at"] == "2026-09-08T14:00:08Z"
        assert await harness.stop() == 0

    async def test_an_attempt_clears_the_scheduled_wait(self, harness: Harness) -> None:
        """While an attempt runs no wait is scheduled, and the reconnect
        attempt is counted when it starts."""
        harness.broker.script = [OSError(), BLOCK]

        harness.start()
        async with asyncio.timeout(_WAIT):
            await _until(lambda: len(harness.broker.urls) == 2)
        attempting = await harness.store.wait_for(_published(reconnect_attempts=1))

        assert attempting["status"] == "reconnecting"
        assert attempting["next_retry_seconds"] is None
        assert await harness.stop() == 0

    @pytest.mark.parametrize(
        "reason", ["connection_lost", "channel_lost", "consumer_cancelled"]
    )
    async def test_loss_reports_disconnected_then_reconnecting(
        self, harness: Harness, reason: str
    ) -> None:
        """A lost connection, channel, or broker consumer is reported alike:
        `disconnected` during the cleanup, then `reconnecting` with the
        scheduled wait, then `connected` again."""
        harness.timer.blocking = lambda _seconds: True
        store, clock = harness.store, harness.clock
        harness.start()
        epoch = await harness.broker.wait_connected()
        await store.wait_for(_published(status="connected"))

        clock.advance(60)
        epoch.close_gate = asyncio.Event()
        epoch.lose(reason)
        disconnected = await store.wait_for(_published(status="disconnected"))
        epoch.close_gate.set()
        waiting = await store.wait_for(_published(next_retry_seconds=5))
        harness.timer.release()
        await harness.broker.wait_connected(2)
        reconnected = await store.wait_for(
            _published(status="connected", reconnect_attempts=1)
        )

        assert disconnected["status_since"] == "2026-09-08T14:01:00Z"
        assert disconnected["last_error"] == "rabbitmq_connection_lost"
        assert disconnected["last_error_at"] == "2026-09-08T14:01:00Z"
        assert disconnected["next_retry_seconds"] is None
        assert disconnected["reconnect_attempts"] == 0
        assert waiting["status"] == "reconnecting"
        assert waiting["reconnect_attempts"] == 0  # Counted when it starts.
        assert reconnected["last_error"] == "rabbitmq_connection_lost"
        assert store.statuses == [
            "reconnecting",
            "connected",
            "disconnected",
            "reconnecting",
            "connected",
        ]
        assert await harness.stop() == 0

    async def test_refresh_rewrites_the_complete_value_every_30_seconds(
        self, harness: Harness
    ) -> None:
        store = harness.store
        harness.start()
        await harness.broker.wait_connected()
        await store.wait_for(_published(status="connected"))
        writes = len(store.values)

        harness.clock.advance(30)
        harness.refresh.fire()
        refreshed = await store.wait_for(
            _published(heartbeat_at="2026-09-08T14:00:30Z")
        )

        assert len(store.values) == writes + 1
        assert refreshed["status"] == "connected"
        assert refreshed["status_since"] == _STARTED
        assert set(harness.refresh.calls) == {30.0}
        assert await harness.stop() == 0

    async def test_counters_start_at_zero_in_every_process(
        self, harness: Harness
    ) -> None:
        harness.start()
        await harness.broker.wait_connected()
        harness.broker.deliver()
        await _until(
            lambda: harness.consumer is not None and bool(harness.handled.finished)
        )
        assert await harness.stop() == 0
        assert harness.consumer is not None
        assert harness.consumer.status.events_received == 1

        restarted = IBSEventConsumer(_settings(), clock=harness.clock)

        status = restarted.status
        assert (
            status.events_received,
            status.events_relevant,
            status.events_processed,
            status.processing_failed,
            status.reconnect_attempts,
        ) == (0, 0, 0, 0, 0)
        assert status.status is IBSConsumerStatus.RECONNECTING
        assert status.last_error is None


class TestHeartbeatCounters:
    @pytest.mark.parametrize(
        ("result", "counters", "last_error"),
        [
            (
                DeliveryResult(DeliveryOutcome.PROCESSED),
                (1, 1, 1, 0),
                None,
            ),
            (DeliveryResult(DeliveryOutcome.IRRELEVANT), (1, 0, 0, 0), None),
            (
                DeliveryResult(DeliveryOutcome.MALFORMED, "invalid_json"),
                (1, 0, 0, 0),
                None,
            ),
            (FAILED_RESULT, (1, 1, 0, 1), "package_reconciliation_failed"),
            (
                DeliveryResult(
                    DeliveryOutcome.FAILED,
                    "selection_failed",
                    error_category=IBSConsumerErrorCategory.PACKAGE_RECONCILIATION_FAILED,
                ),
                (1, 1, 0, 1),
                "package_reconciliation_failed",
            ),
        ],
        ids=[
            "processed",
            "irrelevant",
            "malformed",
            "track-failed",
            "selection-failed",
        ],
    )
    async def test_each_outcome_has_its_exact_counter_effect(
        self,
        harness: Harness,
        result: DeliveryResult,
        counters: tuple[int, int, int, int],
        last_error: str | None,
    ) -> None:
        """Processed (also an idempotent no-op) counts relevant and
        processed; irrelevant and malformed count only `events_received`;
        every terminal failure, including one before any track is selected,
        counts relevant and failed and sets `last_error`. The counters are
        published by the next write."""
        harness.handled.result = result
        harness.start()
        epoch = await harness.broker.wait_connected()
        harness.clock.advance(4)
        harness.broker.deliver()
        await _until(lambda: len(epoch.acks) == 1)

        harness.refresh.fire()
        document = await harness.store.wait_for(_published(events_received=1))

        assert (
            document["events_received"],
            document["events_relevant"],
            document["events_processed"],
            document["processing_failed"],
        ) == counters
        assert document["last_error"] == last_error
        assert document["last_error_at"] == (
            "2026-09-08T14:00:04Z" if last_error else None
        )
        assert document["status"] == "connected"
        assert await harness.stop() == 0

    async def test_real_decoding_failure_paths_count_only_received(
        self, harness: Harness, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from app.services.packages.ibs_event_handlers import handle_delivery

        monkeypatch.setattr(ibs_event_consumer, "handle_delivery", handle_delivery)
        harness.start()
        epoch = await harness.broker.wait_connected()
        harness.broker.deliver(FakeDelivery(routing_key="suse.obs.metrics"))
        harness.broker.deliver(FakeDelivery(body=b"not json"))
        await _until(lambda: len(epoch.acks) == 2)

        status = harness.consumer.status if harness.consumer else None
        assert status is not None
        assert (status.events_received, status.events_relevant) == (2, 0)
        assert status.last_error is None
        assert await harness.stop() == 0

    async def test_committed_success_is_counted_when_the_channel_died_first(
        self, harness: Harness
    ) -> None:
        harness.start()
        epoch = await harness.broker.wait_connected()
        harness.handled.on_call = lambda: epoch.lose("channel_lost")
        harness.broker.deliver()
        await harness.broker.wait_connected(2)

        assert epoch.acks == []
        assert harness.consumer is not None
        status = harness.consumer.status
        assert (status.events_received, status.events_processed) == (1, 1)
        assert status.last_error is IBSConsumerErrorCategory.RABBITMQ_CONNECTION_LOST
        assert await harness.stop() == 0

    async def test_cancelled_delivery_counts_only_received(
        self, harness: Harness
    ) -> None:
        harness.handled.gate = asyncio.Event()
        harness.start()
        epoch = await harness.broker.wait_connected()
        harness.broker.deliver()
        await _until(lambda: len(harness.handled.calls) == 1)
        epoch.lose("connection_lost")
        await harness.broker.wait_connected(2)

        assert harness.consumer is not None
        status = harness.consumer.status
        assert (status.events_received, status.events_relevant) == (1, 0)
        assert await harness.stop() == 0

    async def test_counters_and_last_error_survive_success_and_reconnects(
        self, harness: Harness
    ) -> None:
        harness.handled.result = FAILED_RESULT
        harness.start()
        epoch = await harness.broker.wait_connected()
        harness.clock.advance(2)
        harness.broker.deliver()
        await _until(lambda: len(epoch.acks) == 1)

        harness.handled.result = DeliveryResult(DeliveryOutcome.PROCESSED)
        harness.clock.advance(2)
        harness.broker.deliver()
        await _until(lambda: len(epoch.acks) == 2)
        harness.refresh.fire()
        after_success = await harness.store.wait_for(_published(events_received=2))
        assert after_success["last_error"] == "package_reconciliation_failed"
        assert after_success["last_error_at"] == "2026-09-08T14:00:02Z"

        epoch.lose("connection_lost")
        second = await harness.broker.wait_connected(2)
        second_epoch_delivery = FakeDelivery()
        harness.broker.deliver(second_epoch_delivery)
        await _until(lambda: len(second.acks) == 1)

        assert harness.consumer is not None
        status = harness.consumer.status
        assert (
            status.events_received,
            status.events_relevant,
            status.events_processed,
            status.processing_failed,
        ) == (3, 3, 2, 1)
        assert status.last_error is IBSConsumerErrorCategory.RABBITMQ_CONNECTION_LOST
        assert await harness.stop() == 0


class TestHeartbeatDegradation:
    @pytest.mark.parametrize(
        "error",
        [
            redis_exceptions.ConnectionError("fictional refused"),
            redis_exceptions.TimeoutError("fictional timeout"),
            redis_exceptions.ResponseError(
                "OOM command not allowed when used memory > 'maxmemory'."
            ),
        ],
        ids=["connection", "timeout", "oom"],
    )
    async def test_write_failure_logs_one_bounded_warning_and_changes_nothing(
        self, harness: Harness, error: Exception
    ) -> None:
        harness.store.error = error

        with capture_logs() as logs:
            harness.start()
            epoch = await harness.broker.wait_connected()
            harness.broker.deliver()
            await _until(lambda: len(epoch.acks) == 1)
            code = await harness.stop()

        assert code == 0
        failures = [
            e for e in logs if e["event"] == "ibs_consumer_heartbeat_write_failed"
        ]
        assert failures
        assert harness.store.attempts == len(failures)
        assert all(
            e
            == {
                "event": "ibs_consumer_heartbeat_write_failed",
                "log_level": "warning",
                "error_type": type(error).__name__,
            }
            for e in failures
        )
        assert "fictional" not in repr(logs)
        assert "ibs_consumer_fatal" not in _events(logs)
        assert harness.consumer is not None
        assert harness.consumer.status.events_processed == 1

    async def test_startup_succeeds_without_redis(self, harness: Harness) -> None:
        harness.store.error = redis_exceptions.ConnectionError("fictional refused")

        with capture_logs() as logs:
            harness.start()
            await harness.broker.wait_connected()

        assert "ibs_consumer_started" in _events(logs)
        assert await harness.stop() == 0

    async def test_hanging_write_is_bounded_and_delays_no_reconnect(
        self, harness: Harness, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(ibs_consumer_status, "WRITE_TIMEOUT_SECONDS", 0.01)
        harness.store.gate = asyncio.Event()  # Never opened: Redis hangs.
        harness.broker.script = [OSError(), OSError()]

        with capture_logs() as logs:
            harness.start()
            await harness.broker.wait_connected()
            await _until(lambda: "ibs_consumer_heartbeat_write_failed" in _events(logs))
            code = await harness.stop()

        assert code == 0
        assert harness.timer.calls == [5, 10]
        assert {
            e["error_type"]
            for e in logs
            if e["event"] == "ibs_consumer_heartbeat_write_failed"
        } == {"TimeoutError"}

    async def test_hanging_write_delays_no_shutdown(self, harness: Harness) -> None:
        """Shutdown step 5 cancels an in-flight write."""
        harness.start()
        await harness.broker.wait_connected()
        harness.store.gate = asyncio.Event()  # Never opened.
        harness.refresh.fire()
        await _until(lambda: harness.store.attempts >= 2)

        assert await harness.stop() == 0

    async def test_writer_that_ignores_cancellation_is_abandoned_at_its_bound(
        self, harness: Harness, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(ibs_consumer_status, "WRITER_STOP_TIMEOUT_SECONDS", 0.01)
        released = asyncio.Event()
        harness.start()
        await harness.broker.wait_connected()

        async def stubborn(value: str) -> None:
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                await released.wait()

        assert harness.consumer is not None
        harness.consumer._writer._store = stubborn
        harness.refresh.fire()
        await asyncio.sleep(0)
        try:
            assert await harness.stop() == 0
        finally:
            released.set()
            await asyncio.sleep(0)


class TestHeartbeatShutdownAndFatal:
    async def test_shutdown_stops_the_writer_before_closing_without_a_final_write(
        self, harness: Harness
    ) -> None:
        harness.start()
        epoch = await harness.broker.wait_connected()
        await harness.store.wait_for(_published(status="connected"))
        assert harness.consumer is not None
        writer = harness.consumer._writer
        observed: list[bool] = []
        epoch.on_close = lambda: observed.append(
            writer._task is not None and writer._task.done()
        )
        writes = len(harness.store.values)

        assert await harness.stop() == 0

        assert observed == [True]
        assert len(harness.store.values) == writes
        assert harness.store.last["status"] == "connected"

    async def test_writer_failure_is_fatal_and_cleans_up(
        self, harness: Harness
    ) -> None:
        harness.handled.gate = asyncio.Event()
        harness.start()
        epoch = await harness.broker.wait_connected()
        harness.broker.deliver()
        await _until(lambda: len(harness.handled.calls) == 1)

        harness.store.error = RuntimeError("fictional bug")
        with capture_logs() as logs:
            harness.refresh.fire()
            code = await harness.result()

        assert code == 1
        assert _entry(logs, "ibs_consumer_fatal")["reason_category"] == (
            "unexpected_error"
        )
        assert "ibs_consumer_stopped" not in _events(logs)
        assert epoch.acks == []
        assert epoch.closed
        assert harness.client.closed == 1
        assert harness.disposed == ["engine"]

    async def test_memory_error_in_the_writer_is_fatal(self, harness: Harness) -> None:
        harness.store.error = MemoryError()

        with capture_logs() as logs:
            harness.start()
            code = await harness.result()

        assert code == 1
        assert _entry(logs, "ibs_consumer_fatal")["reason_category"] == "memory_error"
        assert harness.disposed == ["engine"]

    async def test_heartbeat_carries_no_secret_or_identity(
        self, harness: Harness
    ) -> None:
        harness.handled.result = FAILED_RESULT
        harness.start()
        epoch = await harness.broker.wait_connected()
        harness.broker.deliver()
        await _until(lambda: len(epoch.acks) == 1)
        harness.refresh.fire()
        await harness.store.wait_for(_published(processing_failed=1))
        assert await harness.stop() == 0

        written = "".join(harness.store.values)
        for forbidden in (
            "mq-password-not-for-production",
            "mq.example.test",
            "svc",
            "SUSE:",
            "example-pkg",
            "example-user",
            "track_failed",
        ):
            assert forbidden not in written
