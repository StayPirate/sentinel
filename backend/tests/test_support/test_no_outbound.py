"""Self-tests for the outbound-call guard (tests/support/no_outbound.py).

The guard is the mechanism behind the zero-outbound-call requirement of
docs/features/platform/testing-strategy.md (Ticket References). These
tests prove that it actually fails and records name resolution,
connection, and HTTP sends to a fictional host, that it restores every
boundary afterwards, and that a database-backed test keeps working while
it is installed. Every target is fictional (`*.example.test`, the
TEST-NET-1 documentation address `192.0.2.1`); no call ever leaves the
process because the substitutes raise before the original runs.
"""

from __future__ import annotations

import asyncio
import contextlib
import socket

import httpx
import pytest
from sqlalchemy import NullPool, text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine

from tests.support.no_outbound import (
    DatabaseEndpoint,
    OutboundAttempt,
    OutboundCallForbiddenError,
    OutboundGuard,
)

pytest_plugins = ["tests.support.no_outbound_fixtures"]

_HOST = "issues.example.test"
_ADDRESS = ("192.0.2.1", 443)


@pytest.mark.unit
class TestBlockedBoundaries:
    def test_dns_lookup_fails_and_is_recorded(self, no_outbound: OutboundGuard) -> None:
        with pytest.raises(OutboundCallForbiddenError):
            socket.getaddrinfo(_HOST, 443)

        assert no_outbound.attempts == [
            OutboundAttempt("socket.getaddrinfo", repr((_HOST, 443)))
        ]

    def test_gethostbyname_fails(self, no_outbound: OutboundGuard) -> None:
        with pytest.raises(OutboundCallForbiddenError):
            socket.gethostbyname(_HOST)

        assert [a.boundary for a in no_outbound.attempts] == ["socket.gethostbyname"]

    async def test_event_loop_lookup_fails(self, no_outbound: OutboundGuard) -> None:
        with pytest.raises(OutboundCallForbiddenError):
            await asyncio.get_running_loop().getaddrinfo(_HOST, 443)

        assert [a.boundary for a in no_outbound.attempts] == [
            "asyncio.loop.getaddrinfo"
        ]

    def test_create_connection_fails(self, no_outbound: OutboundGuard) -> None:
        with pytest.raises(OutboundCallForbiddenError):
            socket.create_connection(_ADDRESS, timeout=1)

        assert [a.boundary for a in no_outbound.attempts] == [
            "socket.create_connection"
        ]

    @pytest.mark.parametrize("method", ["connect", "connect_ex"])
    def test_raw_socket_connect_fails(
        self, no_outbound: OutboundGuard, method: str
    ) -> None:
        with (
            socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock,
            pytest.raises(OutboundCallForbiddenError),
        ):
            getattr(sock, method)(_ADDRESS)

        assert no_outbound.attempts == [
            OutboundAttempt(f"socket.socket.{method}", repr(_ADDRESS))
        ]

    def test_sync_http_send_fails(self, no_outbound: OutboundGuard) -> None:
        with httpx.Client() as client, pytest.raises(OutboundCallForbiddenError):
            client.get(f"https://{_HOST}/browse/EXAMPLE-1")

        assert no_outbound.attempts == [
            OutboundAttempt("httpx.Client.send", repr(_HOST))
        ]

    async def test_async_http_send_fails(self, no_outbound: OutboundGuard) -> None:
        async with httpx.AsyncClient() as client:
            with pytest.raises(OutboundCallForbiddenError):
                await client.head(f"https://{_HOST}/browse/EXAMPLE-1")

        assert no_outbound.attempts == [
            OutboundAttempt("httpx.AsyncClient.send", repr(_HOST))
        ]

    def test_attempt_is_recorded_even_when_the_failure_is_swallowed(
        self, no_outbound: OutboundGuard
    ) -> None:
        # Simulates over-broad error handling in the code under test.
        with contextlib.suppress(Exception):
            socket.getaddrinfo(_HOST, None)

        assert len(no_outbound.attempts) == 1

    def test_failure_is_not_an_os_error(self) -> None:
        # Ordinary network error handling (`except OSError`) must not hide it.
        assert not issubclass(OutboundCallForbiddenError, OSError)
        assert issubclass(OutboundCallForbiddenError, AssertionError)

    def test_unit_test_allows_no_endpoint(self, no_outbound: OutboundGuard) -> None:
        assert no_outbound.allowed == ()


@pytest.mark.unit
class TestInstallation:
    def test_monkeypatch_undo_restores_every_boundary(self) -> None:
        originals = (
            socket.getaddrinfo,
            socket.gethostbyname,
            socket.create_connection,
            socket.socket.connect,
            socket.socket.connect_ex,
            asyncio.base_events.BaseEventLoop.getaddrinfo,
            httpx.Client.send,
            httpx.AsyncClient.send,
        )

        with pytest.MonkeyPatch.context() as monkeypatch:
            OutboundGuard().install(monkeypatch)
            assert socket.getaddrinfo is not originals[0]
            assert httpx.Client.send is not originals[6]

        assert (
            socket.getaddrinfo,
            socket.gethostbyname,
            socket.create_connection,
            socket.socket.connect,
            socket.socket.connect_ex,
            asyncio.base_events.BaseEventLoop.getaddrinfo,
            httpx.Client.send,
            httpx.AsyncClient.send,
        ) == originals

    def test_allowed_endpoint_does_not_allow_another_port_or_host(self) -> None:
        # 127.0.0.1 is resolved without DNS, so building the allowance
        # performs no lookup; nothing is connected.
        guard = OutboundGuard([DatabaseEndpoint("127.0.0.1", 55432)])
        with pytest.MonkeyPatch.context() as monkeypatch:
            guard.install(monkeypatch)
            with pytest.raises(OutboundCallForbiddenError):
                socket.create_connection(("127.0.0.1", 443))
            with pytest.raises(OutboundCallForbiddenError):
                socket.create_connection(("192.0.2.1", 55432))
            with pytest.raises(OutboundCallForbiddenError):
                socket.getaddrinfo(_HOST, 55432)

        assert [a.boundary for a in guard.attempts] == [
            "socket.create_connection",
            "socket.create_connection",
            "socket.getaddrinfo",
        ]


@pytest.mark.integration
class TestDatabaseBackedTest:
    async def test_open_session_keeps_working_and_lookups_still_fail(
        self, db_session: AsyncSession, no_outbound: OutboundGuard
    ) -> None:
        assert (await db_session.execute(text("SELECT 1"))).scalar_one() == 1

        with pytest.raises(OutboundCallForbiddenError):
            socket.getaddrinfo(_HOST, 443)
        assert [a.boundary for a in no_outbound.attempts] == ["socket.getaddrinfo"]

    async def test_new_connection_to_the_test_database_is_allowed(
        self, db_session: AsyncSession, no_outbound: OutboundGuard
    ) -> None:
        url = db_session.get_bind().engine.url
        assert no_outbound.allowed == (DatabaseEndpoint.from_url(url),)
        # NullPool forces a brand-new socket to the test database endpoint.
        fresh = create_async_engine(
            url.render_as_string(hide_password=False), poolclass=NullPool
        )
        try:
            async with fresh.connect() as connection:
                assert (await connection.execute(text("SELECT 1"))).scalar_one() == 1
        finally:
            await fresh.dispose()

        assert no_outbound.attempts == []
