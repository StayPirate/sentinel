"""Failing substitutes at the outbound networking boundaries.

docs/features/platform/testing-strategy.md (Ticket References) requires
validation and classification tests to "install spies or failing
substitutes at outbound networking boundaries" and prove that reference
processing performs zero URL dereference, DNS resolution, probe, HTTP
request, or other outbound URL call. `OutboundGuard` implements that
mechanism once so that unit, integration, and later API tests share it.

Guarded boundaries, each replaced through `pytest.MonkeyPatch` (so every
substitute is restored at fixture teardown):

- `socket.getaddrinfo`, `socket.gethostbyname`, and the asyncio event
  loop's `getaddrinfo()` (`asyncio.base_events.BaseEventLoop`), covering
  name resolution from synchronous code, asyncio, and anyio/httpcore;
- `socket.create_connection`, `socket.socket.connect`, and
  `socket.socket.connect_ex`, covering every new TCP connection,
  including those opened by asyncio transports (`loop.sock_connect()`
  calls `socket.connect()`);
- `httpx.Client.send` and `httpx.AsyncClient.send`, so an HTTP request
  fails at the client boundary before any transport runs. These two are
  never allowed, which also means an in-process ASGI test client
  (`httpx.AsyncClient` with `ASGITransport`) cannot be used while the
  guard is installed.

A blocked call is appended to `OutboundGuard.attempts` *before*
`OutboundCallForbiddenError` is raised. The exception derives from
`AssertionError` (not `OSError`), so it is not swallowed by ordinary
network error handling; even code that catches every exception still
leaves the recorded attempt for the test's `attempts == []` assertion.

Database-backed tests talk to the test PostgreSQL server over a socket.
The design keeps them working without weakening the guard for any other
endpoint:

1. An already-open connection needs no lookup and no `connect()`; it
   keeps working regardless of fixture order. `db_session` checks out
   one pooled connection when it is set up and binds the session to it.
2. A guard may additionally allow exact database endpoints
   (`DatabaseEndpoint`): name resolution of the endpoint host for its
   port, and connections to the endpoint port on that host or on an
   address it resolved to when the guard was installed. The
   `no_outbound` fixture (`tests/support/no_outbound_fixtures.py`)
   derives the single allowed endpoint from the URL of the shared test
   engine (`_engine` in `tests/conftest.py`) and only when the requesting
   test already depends on that engine; a test without database access
   allows nothing. A Unix-domain-socket database URL is not supported:
   its connections are blocked and the test fails loudly.

Allowed database traffic is not recorded: it is test infrastructure, not
an outbound URL operation of the code under test.
"""

from __future__ import annotations

import asyncio.base_events
import socket
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any

import httpx
import pytest
from sqlalchemy.engine import URL

_DEFAULT_POSTGRES_PORT = 5432


class OutboundCallForbiddenError(AssertionError):
    """A guarded outbound boundary was called while `OutboundGuard` is active."""


@dataclass(frozen=True, slots=True)
class OutboundAttempt:
    """One blocked call: the guarded boundary and its requested target."""

    boundary: str
    target: str


@dataclass(frozen=True, slots=True)
class DatabaseEndpoint:
    """A test database host and TCP port that the guard lets through."""

    host: str
    port: int

    @classmethod
    def from_url(cls, url: URL) -> DatabaseEndpoint:
        if not url.host:
            raise ValueError("A database endpoint requires a TCP host.")
        return cls(host=url.host, port=url.port or _DEFAULT_POSTGRES_PORT)


def _text(value: object) -> str | None:
    if isinstance(value, bytes):
        return value.decode("ascii", "replace")
    if isinstance(value, str):
        return value
    return None


def _port(value: object) -> int | None:
    if isinstance(value, int):
        return value
    text = _text(value)
    if text is not None and text.isdigit():
        return int(text)
    return None


class OutboundGuard:
    """Install failing substitutes at the outbound networking boundaries.

    `allowed` lists the only database endpoints that may be resolved and
    connected; see the module docstring. Every other call is recorded in
    `attempts` and raises `OutboundCallForbiddenError`.
    """

    def __init__(self, allowed: Iterable[DatabaseEndpoint] = ()) -> None:
        self.allowed: tuple[DatabaseEndpoint, ...] = tuple(allowed)
        self.attempts: list[OutboundAttempt] = []
        self._allowed_addresses: set[tuple[str, int]] = set()

    # -- policy ---------------------------------------------------------

    def _resolve_allowed(self) -> None:
        """Record the addresses of the allowed endpoints (before patching)."""
        for endpoint in self.allowed:
            self._allowed_addresses.add((endpoint.host.lower(), endpoint.port))
            try:
                infos = socket.getaddrinfo(
                    endpoint.host, endpoint.port, type=socket.SOCK_STREAM
                )
            except OSError:
                continue
            for info in infos:
                address = info[4]
                self._allowed_addresses.add((str(address[0]).lower(), endpoint.port))

    def _lookup_allowed(self, host: object, port: object) -> bool:
        host_text = _text(host)
        if host_text is None:
            return False
        port_number = _port(port)
        return any(
            host_text.lower() == endpoint.host.lower()
            and (port is None or port_number == endpoint.port)
            for endpoint in self.allowed
        )

    def _address_allowed(self, address: object) -> bool:
        if not isinstance(address, tuple) or len(address) < 2:
            return False
        host_text = _text(address[0])
        port_number = _port(address[1])
        if host_text is None or port_number is None:
            return False
        return (host_text.lower(), port_number) in self._allowed_addresses

    def _block(self, boundary: str, target: object) -> OutboundCallForbiddenError:
        self.attempts.append(OutboundAttempt(boundary=boundary, target=repr(target)))
        return OutboundCallForbiddenError(
            f"Outbound call forbidden by the test guard: {boundary}"
        )

    # -- installation ---------------------------------------------------

    def install(self, monkeypatch: pytest.MonkeyPatch) -> OutboundGuard:
        """Replace every guarded boundary; `monkeypatch` restores them."""
        self._resolve_allowed()
        self._patch_resolution(monkeypatch)
        self._patch_connections(monkeypatch)
        self._patch_httpx(monkeypatch)
        return self

    def _patch_resolution(self, monkeypatch: pytest.MonkeyPatch) -> None:
        original_getaddrinfo = socket.getaddrinfo
        original_gethostbyname = socket.gethostbyname
        original_loop_getaddrinfo = asyncio.base_events.BaseEventLoop.getaddrinfo

        def getaddrinfo(host: Any, port: Any, *args: Any, **kwargs: Any) -> Any:
            if self._lookup_allowed(host, port):
                return original_getaddrinfo(host, port, *args, **kwargs)
            raise self._block("socket.getaddrinfo", (host, port))

        def gethostbyname(hostname: Any) -> str:
            if self._lookup_allowed(hostname, None):
                return original_gethostbyname(hostname)
            raise self._block("socket.gethostbyname", hostname)

        async def loop_getaddrinfo(
            loop: asyncio.base_events.BaseEventLoop,
            host: Any,
            port: Any,
            *args: Any,
            **kwargs: Any,
        ) -> Any:
            if self._lookup_allowed(host, port):
                return await original_loop_getaddrinfo(
                    loop, host, port, *args, **kwargs
                )
            raise self._block("asyncio.loop.getaddrinfo", (host, port))

        monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)
        monkeypatch.setattr(socket, "gethostbyname", gethostbyname)
        monkeypatch.setattr(
            asyncio.base_events.BaseEventLoop, "getaddrinfo", loop_getaddrinfo
        )

    def _patch_connections(self, monkeypatch: pytest.MonkeyPatch) -> None:
        original_create_connection = socket.create_connection
        original_connect = socket.socket.connect
        original_connect_ex = socket.socket.connect_ex

        def create_connection(address: Any, *args: Any, **kwargs: Any) -> Any:
            if self._address_allowed(address):
                return original_create_connection(address, *args, **kwargs)
            raise self._block("socket.create_connection", address)

        def connect(sock: socket.socket, address: Any) -> None:
            if self._address_allowed(address):
                return original_connect(sock, address)
            raise self._block("socket.socket.connect", address)

        def connect_ex(sock: socket.socket, address: Any) -> int:
            if self._address_allowed(address):
                return original_connect_ex(sock, address)
            raise self._block("socket.socket.connect_ex", address)

        monkeypatch.setattr(socket, "create_connection", create_connection)
        monkeypatch.setattr(socket.socket, "connect", connect)
        monkeypatch.setattr(socket.socket, "connect_ex", connect_ex)

    def _patch_httpx(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def forbidden_send(boundary: str) -> Callable[..., Any]:
            def send(client: object, request: httpx.Request, **kwargs: Any) -> Any:
                raise self._block(boundary, str(request.url.host))

            return send

        def forbidden_async_send(boundary: str) -> Callable[..., Any]:
            async def send(
                client: object, request: httpx.Request, **kwargs: Any
            ) -> Any:
                raise self._block(boundary, str(request.url.host))

            return send

        monkeypatch.setattr(httpx.Client, "send", forbidden_send("httpx.Client.send"))
        monkeypatch.setattr(
            httpx.AsyncClient, "send", forbidden_async_send("httpx.AsyncClient.send")
        )
