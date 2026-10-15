"""An in-process fake AMQP 0-9-1 broker for the IBS consumer adapter tests
(backend/app/services/ibs_event_consumer.py, `connect_amqp` and
`_AioPikaEpoch`).

`FakeAmqpServer` listens on 127.0.0.1 (an ephemeral port, plain TCP) and
speaks the server side of AMQP 0-9-1 through pamqp. Each accepted client is a
`ServerConnection` that:

- performs the handshake (Connection.Start advertising
  `consumer_cancel_notify`, `basic.nack`, `per_consumer_qos`, and
  `publisher_confirms`; Tune; OpenOk) and answers the channel, topology,
  consume, cancel, and close methods the client sends; heartbeats are
  ignored;
- records every received method frame, in order, with its channel number;
- can push frames at any time: a delivery, a broker `Basic.Cancel`, a
  `Channel.Close`, a `Connection.Close`, or an abrupt TCP close.

`FakeAmqpServer.tls`, when set, makes the listener TLS-only.
`FakeAmqpServer.replies` scripts the reply to a method type for every
connection: a `Channel.Close` or `Connection.Close` replaces the normal
reply, and `None` suppresses any reply. Every wait is bounded by
`WAIT_SECONDS`. Leaving the `async with` block aborts every client socket and
closes the listener.
"""

from __future__ import annotations

import asyncio
import secrets
import ssl
from collections.abc import Callable
from dataclasses import dataclass, field
from types import TracebackType
from typing import Final, Self

import pamqp.frame
from pamqp import base, commands
from pamqp.body import ContentBody
from pamqp.common import FieldTable
from pamqp.header import ContentHeader, ProtocolHeader
from pamqp.heartbeat import Heartbeat

WAIT_SECONDS: Final = 5.0
PROPOSED_HEARTBEAT: Final = 600
"""The server's Tune proposal, distinct from the client's own value."""

SERVER_PROPERTIES: Final[FieldTable] = {
    "product": "example-broker",
    "capabilities": {
        "consumer_cancel_notify": True,
        "basic.nack": True,
        "per_consumer_qos": True,
        "publisher_confirms": True,
    },
}

_FRAME_HEADER_SIZE: Final = 7


def channel_close(
    reply_code: int, reply_text: str, method: type[base.Frame]
) -> commands.Channel.Close:
    """A broker `Channel.Close` that names `method` as the failed one."""
    return commands.Channel.Close(
        reply_code, reply_text, method.index >> 16, method.index & 0xFFFF
    )


@dataclass(eq=False)
class ServerConnection:
    """The server side of one client connection."""

    server: FakeAmqpServer
    writer: asyncio.StreamWriter
    received: list[tuple[int, base.Frame]] = field(default_factory=list)
    closed: asyncio.Event = field(default_factory=asyncio.Event)
    queue_name: str | None = None
    consumer_tag: str | None = None
    consumer_channel: int = 0
    _delivery_tag: int = 0
    _changed: asyncio.Condition = field(default_factory=asyncio.Condition)

    def methods[F: base.Frame](self, kind: type[F]) -> list[F]:
        return [frame for _, frame in self.received if isinstance(frame, kind)]

    def names(self) -> list[str]:
        return [frame.name for _, frame in self.received]

    async def wait_for[F: base.Frame](self, kind: type[F], count: int = 1) -> F:
        """The `count`-th received method of `kind`, once it has arrived."""
        await self._wait(lambda: len(self.methods(kind)) >= count)
        return self.methods(kind)[count - 1]

    async def wait_closed(self) -> None:
        """Wait until the client has closed (or lost) the TCP connection."""
        async with asyncio.timeout(WAIT_SECONDS):
            await self.closed.wait()

    async def _wait(self, predicate: Callable[[], bool]) -> None:
        async with asyncio.timeout(WAIT_SECONDS), self._changed:
            await self._changed.wait_for(predicate)

    async def _record(self, channel: int, frame: base.Frame) -> None:
        async with self._changed:
            self.received.append((channel, frame))
            self._changed.notify_all()

    def send(
        self, channel: int, *frames: base.Frame | ContentHeader | ContentBody
    ) -> None:
        if not self.writer.is_closing():
            self.writer.write(
                b"".join(pamqp.frame.marshal(frame, channel) for frame in frames)
            )

    def deliver(
        self,
        body: bytes,
        *,
        routing_key: str,
        content_type: str | None,
        exchange: str = "pubsub",
    ) -> int:
        """Push one delivery to the consumer; returns its delivery tag."""
        assert self.consumer_tag is not None, "no consumer started"
        self._delivery_tag += 1
        self.send(
            self.consumer_channel,
            commands.Basic.Deliver(
                self.consumer_tag, self._delivery_tag, False, exchange, routing_key
            ),
            ContentHeader(
                body_size=len(body),
                properties=commands.Basic.Properties(content_type=content_type),
            ),
            ContentBody(body),
        )
        return self._delivery_tag

    def cancel_consumer(self) -> None:
        """Push a broker-side `Basic.Cancel` for the consumer tag."""
        assert self.consumer_tag is not None, "no consumer started"
        self.send(
            self.consumer_channel,
            commands.Basic.Cancel(self.consumer_tag, nowait=True),
        )

    def close_channel(self, reply_code: int, reply_text: str) -> None:
        self.send(
            self.consumer_channel,
            commands.Channel.Close(reply_code, reply_text, 0, 0),
        )

    def close_connection(self, reply_code: int, reply_text: str) -> None:
        self.send(0, commands.Connection.Close(reply_code, reply_text, 0, 0))

    def abort(self) -> None:
        """Drop the TCP connection without any AMQP close."""
        self.writer.transport.abort()

    def _reply(self, frame: base.Frame) -> base.Frame | None:
        match frame:
            case commands.Connection.StartOk():
                return commands.Connection.Tune(2047, 131072, PROPOSED_HEARTBEAT)
            case commands.Connection.Open():
                return commands.Connection.OpenOk()
            case commands.Channel.Open():
                return commands.Channel.OpenOk()
            case commands.Channel.Close():
                return commands.Channel.CloseOk()
            case commands.Connection.Close():
                return commands.Connection.CloseOk()
            case commands.Exchange.Declare(nowait=False):
                return commands.Exchange.DeclareOk()
            case commands.Queue.Declare(nowait=False):
                if not frame.queue:
                    self.queue_name = f"amq.gen-{secrets.token_hex(8)}"
                return commands.Queue.DeclareOk(self.queue_name or frame.queue, 0, 0)
            case commands.Basic.Qos():
                return commands.Basic.QosOk()
            case commands.Queue.Bind(nowait=False):
                return commands.Queue.BindOk()
            case commands.Basic.Consume(nowait=False):
                return commands.Basic.ConsumeOk(frame.consumer_tag)
            case commands.Basic.Cancel(nowait=False):
                return commands.Basic.CancelOk(frame.consumer_tag)
            case commands.Confirm.Select(nowait=False):
                return commands.Confirm.SelectOk()
        return None

    async def serve(self, reader: asyncio.StreamReader) -> None:
        try:
            await reader.readexactly(len(ProtocolHeader().marshal()))
            self.send(
                0,
                commands.Connection.Start(server_properties=SERVER_PROPERTIES),
            )
            while True:
                head = await reader.readexactly(_FRAME_HEADER_SIZE)
                _, _, size = pamqp.frame.frame_parts(head)
                assert size is not None
                rest = await reader.readexactly(size + 1)
                _, channel, frame = pamqp.frame.unmarshal(head + rest)
                if isinstance(frame, Heartbeat) or not isinstance(frame, base.Frame):
                    continue
                if isinstance(frame, commands.Basic.Consume):
                    self.consumer_tag = frame.consumer_tag
                    self.consumer_channel = channel
                await self._record(channel, frame)
                scripted = type(frame) in self.server.replies
                reply = (
                    self.server.replies[type(frame)] if scripted else self._reply(frame)
                )
                if reply is not None:
                    connection_close = isinstance(reply, commands.Connection.Close)
                    self.send(0 if connection_close else channel, reply)
                if isinstance(
                    frame, commands.Connection.Close | commands.Connection.CloseOk
                ):
                    self.writer.close()
        except asyncio.IncompleteReadError, ConnectionError:
            pass
        finally:
            self.writer.close()
            self.closed.set()
            async with self._changed:
                self._changed.notify_all()


@dataclass(eq=False)
class FakeAmqpServer:
    """The listener; use as `async with FakeAmqpServer() as server`."""

    replies: dict[type[base.Frame], base.Frame | None] = field(default_factory=dict)
    tls: ssl.SSLContext | None = None
    """A server TLS context: the listener then accepts only TLS clients."""
    connections: list[ServerConnection] = field(default_factory=list)
    _server: asyncio.Server | None = None
    _changed: asyncio.Condition = field(default_factory=asyncio.Condition)

    @property
    def port(self) -> int:
        assert self._server is not None
        port: int = self._server.sockets[0].getsockname()[1]
        return port

    @property
    def url(self) -> str:
        """A plain-TCP URL with fictional credentials."""
        return f"amqp://example:example@127.0.0.1:{self.port}/"

    async def connection(self, index: int = 0) -> ServerConnection:
        """The `index`-th accepted connection, once it exists."""
        async with asyncio.timeout(WAIT_SECONDS), self._changed:
            await self._changed.wait_for(lambda: len(self.connections) > index)
        return self.connections[index]

    async def _accept(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        connection = ServerConnection(self, writer)
        async with self._changed:
            self.connections.append(connection)
            self._changed.notify_all()
        await connection.serve(reader)

    def tls_url(self, host: str) -> str:
        """An `amqps://` URL for `host` (which must resolve to 127.0.0.1)."""
        return f"amqps://example:example@{host}:{self.port}/"

    async def __aenter__(self) -> Self:
        self._server = await asyncio.start_server(
            self._accept, "127.0.0.1", 0, ssl=self.tls
        )
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        assert self._server is not None
        for connection in self.connections:
            connection.abort()
        self._server.close()
        self._server.close_clients()
        async with asyncio.timeout(WAIT_SECONDS):
            await self._server.wait_closed()
