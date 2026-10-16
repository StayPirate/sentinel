"""Proxy routing of the shared HTTP client over real loopback sockets
(backend/app/services/http_client.py; docs/features/platform/networking.md,
Proxy Configuration).

`_LoopbackServer` listens on 127.0.0.1 and plays both a forward proxy and
an origin: it answers every request itself, recording its request line and
headers, and refuses every `CONNECT` tunnel with 403. The request target
tells the two roles apart: a request sent through a proxy carries the
absolute URL, a direct one only the path. Origins use the fictional
`.example.test` domain and are never resolved, because a proxied request
connects only to the proxy; every name resolution fails during these
tests. Retry backoff sleeps are recorded, not awaited.
"""

from __future__ import annotations

import asyncio
import base64
import gzip
import socket
from dataclasses import dataclass
from types import SimpleNamespace
from typing import Any, Final, Self
from unittest.mock import AsyncMock

import httpx
import pytest

from app.services import http_client

pytestmark = pytest.mark.integration

_PAYLOAD: Final = b'{"fictional": "payload"}'
_WAIT_SECONDS: Final = 5.0


@dataclass(frozen=True)
class _Received:
    method: str
    target: str
    headers: dict[str, str]


class _LoopbackServer:
    """A forward proxy and origin on an ephemeral 127.0.0.1 port."""

    def __init__(self) -> None:
        self.received: list[_Received] = []
        self._server: asyncio.Server | None = None

    async def __aenter__(self) -> Self:
        self._server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        assert self._server is not None
        self._server.close()
        await self._server.wait_closed()

    @property
    def address(self) -> str:
        assert self._server is not None
        host, port = self._server.sockets[0].getsockname()[:2]
        return f"{host}:{port}"

    async def _handle(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        try:
            async with asyncio.timeout(_WAIT_SECONDS):
                head = await reader.readuntil(b"\r\n\r\n")
            request_line, *header_lines = head.decode("latin-1").split("\r\n")[:-2]
            method, target, _ = request_line.split(" ")
            headers = {
                name.strip().lower(): value.strip()
                for name, value in (line.split(":", 1) for line in header_lines)
            }
            self.received.append(_Received(method, target, headers))
            if method == "CONNECT":
                writer.write(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
            else:
                body = gzip.compress(_PAYLOAD, mtime=0)
                writer.write(
                    b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n"
                    b"Content-Length: %d\r\nConnection: close\r\n\r\n"
                    % len(body)
                    + body
                )
            await writer.drain()
        finally:
            writer.close()


@pytest.fixture(autouse=True)
def _loopback_only(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fails every name resolution, so a request that bypassed the proxy
    fails without reaching the network. Connections to the loopback
    address need none."""
    original = socket.getaddrinfo

    def guarded(host: bytes | str | None, *args: Any, **kwargs: Any) -> Any:
        if host not in ("127.0.0.1", b"127.0.0.1"):
            raise OSError(f"unexpected name resolution of {host!r}")
        return original(host, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", guarded)


@pytest.fixture
def sleep(monkeypatch: pytest.MonkeyPatch) -> AsyncMock:
    """Records the shared transport's retry backoff sleeps."""
    recorded = AsyncMock()
    monkeypatch.setattr(http_client, "asyncio", SimpleNamespace(sleep=recorded))
    return recorded


class TestProxyOverSockets:
    async def test_http_request_is_forwarded_through_the_proxy(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        async with _LoopbackServer() as proxy:
            monkeypatch.setenv(
                "HTTP_PROXY", f"http://fictional-user:fictional-secret@{proxy.address}"
            )
            async with http_client.create_http_client("proxy-test") as client:
                response = await client.get("http://origin.example.test/resource")

        assert response.content == _PAYLOAD
        [received] = proxy.received
        assert received.method == "GET"
        assert received.target == "http://origin.example.test/resource"
        assert received.headers["host"] == "origin.example.test"
        assert received.headers["accept-encoding"] == "gzip, deflate"
        credentials = base64.b64encode(b"fictional-user:fictional-secret").decode()
        assert received.headers["proxy-authorization"] == f"Basic {credentials}"

    async def test_no_proxy_host_is_requested_directly(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        async with _LoopbackServer() as server:
            monkeypatch.setenv("HTTP_PROXY", f"http://{server.address}")
            monkeypatch.setenv("NO_PROXY", "127.0.0.1")
            async with http_client.create_http_client("proxy-test") as client:
                response = await client.get(f"http://{server.address}/resource")

        assert response.content == _PAYLOAD
        [received] = server.received
        assert received.target == "/resource"
        assert "proxy-authorization" not in received.headers

    async def test_refused_https_tunnel_is_retried_then_raised(
        self, monkeypatch: pytest.MonkeyPatch, sleep: AsyncMock
    ) -> None:
        async with _LoopbackServer() as proxy:
            monkeypatch.setenv("HTTPS_PROXY", f"http://{proxy.address}")
            async with http_client.create_http_client("proxy-test") as client:
                with pytest.raises(httpx.ProxyError):
                    await client.get("https://origin.example.test/resource")

        assert [(item.method, item.target) for item in proxy.received] == [
            ("CONNECT", "origin.example.test:443")
        ] * 4
        assert [call.args[0] for call in sleep.await_args_list] == [1.0, 2.0, 4.0]
