"""Server-global Redis tests of the CVSS recalculation lease operations
(backend/app/services/cvss_recalculation_coordination.py).

Owning specifications:

- docs/features/platform/default-cvss-version-operations.md (Coordination
  Resources; Atomic Lease Operations);
- docs/features/platform/testing-strategy.md (All-CVE Recalculation
  Runner, Coordination server-global Redis tests; Redis Strategy, Worker
  and Test Isolation);
- docs/deployment.md (Persistence is Disabled by Design);
- issue #835 decisions T5 (dedicated container), T6 (reply-withholding
  proxy), and T7 (no client-side retry).

Every test runs against its own Redis 8 container
(`tests.support.redis.dedicated_redis_container`), so restarting,
flushing, stopping, or expiring keys never touches the shared worker
databases. The lease operations reach the container through the
replaceable URL provider `get_cvss_recalculation_redis_url()`.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Awaitable, Iterator
from contextlib import suppress
from typing import Protocol

import pytest
import redis.asyncio as redis_asyncio
from redis.exceptions import ConnectionError as RedisConnectionError
from redis.exceptions import RedisError
from redis.exceptions import TimeoutError as RedisTimeoutError

from app.services import cvss_recalculation_coordination
from app.services.cvss_recalculation_coordination import (
    LEASE_KEY,
    LEASE_TTL_SECONDS,
    LeaseAcquireOutcome,
    LeaseDeleteOutcome,
    LeaseRenewOutcome,
    acquire_lease,
    compare_and_delete_lease,
    compare_and_renew_lease,
    encode_lease_value,
)
from tests.support.redis import DedicatedRedisContainer, dedicated_redis_container

TASK_ID = "0b8f8c47-3e5d-4a21-9c6b-7d2e1f0a5b34"
TARGET = "4.0"
VALUE = f"v1:{TASK_ID}:{TARGET}"

_REPLY_DEADLINE = 5.0
_SHORT_OPERATION_TIMEOUT = 0.5


class LeaseOperation(Protocol):
    def __call__(
        self, client: redis_asyncio.Redis, *, task_id: str, target_version: str
    ) -> Awaitable[object]: ...


@pytest.fixture
def dedicated_redis(
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[DedicatedRedisContainer]:
    """A Redis 8 container for this test only, with the lease operations'
    URL provider redirected to it."""
    with dedicated_redis_container() as container:
        monkeypatch.setattr(
            cvss_recalculation_coordination,
            "get_cvss_recalculation_redis_url",
            lambda: container.url,
        )
        yield container


@pytest.fixture
async def observer(
    dedicated_redis: DedicatedRedisContainer,
) -> AsyncIterator[redis_asyncio.Redis]:
    """A direct client to the dedicated container, used only to set up and
    observe the lease outside the operations under test."""
    client = redis_asyncio.Redis.from_url(dedicated_redis.url, decode_responses=True)
    try:
        yield client
    finally:
        await client.aclose()


def _lease_client() -> redis_asyncio.Redis:
    return cvss_recalculation_coordination.new_cvss_recalculation_redis_client()


async def _wait_until_absent(client: redis_asyncio.Redis, key: str) -> None:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + _REPLY_DEADLINE
    while await client.exists(key):
        assert loop.time() < deadline, f"{key} did not expire"
        await asyncio.sleep(0.01)


@pytest.mark.integration
class TestRestartAndFlush:
    async def test_renew_after_restart_with_fresh_client_returns_absent(
        self,
        dedicated_redis: DedicatedRedisContainer,
        observer: redis_asyncio.Redis,
    ) -> None:
        client = _lease_client()
        try:
            assert (
                await acquire_lease(client, task_id=TASK_ID, target_version=TARGET)
                is LeaseAcquireOutcome.ACQUIRED
            )
        finally:
            await client.aclose()

        dedicated_redis.restart()

        assert await observer.exists(LEASE_KEY) == 0
        client = _lease_client()
        try:
            assert (
                await compare_and_renew_lease(
                    client, task_id=TASK_ID, target_version=TARGET
                )
                is LeaseRenewOutcome.ABSENT
            )
        finally:
            await client.aclose()
        assert await observer.exists(LEASE_KEY) == 0

    async def test_renew_on_client_reused_across_restart_raises_redis_error_first(
        self,
        dedicated_redis: DedicatedRedisContainer,
    ) -> None:
        """Retries are disabled (decision T7): the first command on the
        reused connection fails instead of being resent, which is the
        conservative outcome; the next command reconnects and observes the
        lost lease."""
        client = _lease_client()
        try:
            assert (
                await acquire_lease(client, task_id=TASK_ID, target_version=TARGET)
                is LeaseAcquireOutcome.ACQUIRED
            )

            dedicated_redis.restart()

            with pytest.raises(RedisConnectionError):
                await compare_and_renew_lease(
                    client, task_id=TASK_ID, target_version=TARGET
                )
            assert (
                await compare_and_renew_lease(
                    client, task_id=TASK_ID, target_version=TARGET
                )
                is LeaseRenewOutcome.ABSENT
            )
        finally:
            await client.aclose()

        fresh = _lease_client()
        try:
            assert (
                await compare_and_renew_lease(
                    fresh, task_id=TASK_ID, target_version=TARGET
                )
                is LeaseRenewOutcome.ABSENT
            )
        finally:
            await fresh.aclose()

    async def test_renew_and_delete_after_flushall_return_absent(
        self, dedicated_redis: DedicatedRedisContainer, observer: redis_asyncio.Redis
    ) -> None:
        client = _lease_client()
        try:
            assert (
                await acquire_lease(client, task_id=TASK_ID, target_version=TARGET)
                is LeaseAcquireOutcome.ACQUIRED
            )
            # Allowed only because this server is dedicated to the test.
            await observer.flushall()

            assert (
                await compare_and_renew_lease(
                    client, task_id=TASK_ID, target_version=TARGET
                )
                is LeaseRenewOutcome.ABSENT
            )
            assert (
                await compare_and_delete_lease(
                    client, task_id=TASK_ID, target_version=TARGET
                )
                is LeaseDeleteOutcome.ABSENT
            )
        finally:
            await client.aclose()
        assert await observer.exists(LEASE_KEY) == 0


@pytest.mark.integration
class TestUnavailability:
    async def test_every_operation_on_stopped_server_raises_redis_error(
        self, dedicated_redis: DedicatedRedisContainer
    ) -> None:
        dedicated_redis.stop()

        for operation in (
            acquire_lease,
            compare_and_renew_lease,
            compare_and_delete_lease,
        ):
            client = _lease_client()
            try:
                with pytest.raises(RedisError):
                    await operation(client, task_id=TASK_ID, target_version=TARGET)
            finally:
                await client.aclose()

        dedicated_redis.start()
        client = _lease_client()
        try:
            assert (
                await compare_and_renew_lease(
                    client, task_id=TASK_ID, target_version=TARGET
                )
                is LeaseRenewOutcome.ABSENT
            )
        finally:
            await client.aclose()


@pytest.mark.integration
class TestKeyExpiry:
    async def test_renew_and_delete_after_expiry_return_absent(
        self, dedicated_redis: DedicatedRedisContainer, observer: redis_asyncio.Redis
    ) -> None:
        client = _lease_client()
        try:
            assert (
                await acquire_lease(client, task_id=TASK_ID, target_version=TARGET)
                is LeaseAcquireOutcome.ACQUIRED
            )
            # Shorten the 900-second TTL instead of waiting for it.
            assert await observer.pexpire(LEASE_KEY, 5)
            await _wait_until_absent(observer, LEASE_KEY)

            assert (
                await compare_and_renew_lease(
                    client, task_id=TASK_ID, target_version=TARGET
                )
                is LeaseRenewOutcome.ABSENT
            )
            assert (
                await compare_and_delete_lease(
                    client, task_id=TASK_ID, target_version=TARGET
                )
                is LeaseDeleteOutcome.ABSENT
            )
        finally:
            await client.aclose()
        assert await observer.exists(LEASE_KEY) == 0


class _ReplyWithholdingProxy:
    """A test-only TCP proxy in front of a Redis server.

    Forwards client bytes to the server and server bytes to the client
    until `withhold_replies` is set; from then on, server bytes are read
    and discarded, so a command reaches Redis and is applied while its
    reply never reaches the client (decision T6).
    """

    def __init__(self, upstream_host: str, upstream_port: int) -> None:
        self._upstream = (upstream_host, upstream_port)
        self._server: asyncio.Server | None = None
        self._handlers: set[asyncio.Task[None]] = set()
        self.withhold_replies = False
        self.connections = 0
        self.withheld_bytes = 0

    @property
    def url(self) -> str:
        assert self._server is not None
        host, port = self._server.sockets[0].getsockname()[:2]
        return f"redis://{host}:{port}/0"

    async def start(self) -> None:
        self._server = await asyncio.start_server(self._handle, "127.0.0.1", 0)

    async def close(self) -> None:
        if self._server is not None:
            self._server.close()
        for handler in self._handlers:
            handler.cancel()
        await asyncio.gather(*self._handlers, return_exceptions=True)
        if self._server is not None:
            await self._server.wait_closed()

    async def _handle(
        self, client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter
    ) -> None:
        handler = asyncio.current_task()
        assert handler is not None
        self._handlers.add(handler)
        self.connections += 1
        writers = [client_writer]
        try:
            upstream_reader, upstream_writer = await asyncio.open_connection(
                *self._upstream
            )
            writers.append(upstream_writer)
            pumps = {
                asyncio.create_task(self._pump(client_reader, upstream_writer)),
                asyncio.create_task(
                    self._pump(upstream_reader, client_writer, replies=True)
                ),
            }
            try:
                await asyncio.wait(pumps, return_when=asyncio.FIRST_COMPLETED)
            finally:
                for pump in pumps:
                    pump.cancel()
                await asyncio.gather(*pumps, return_exceptions=True)
        finally:
            for writer in writers:
                writer.close()
                with suppress(OSError):
                    await writer.wait_closed()

    async def _pump(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        *,
        replies: bool = False,
    ) -> None:
        while data := await reader.read(65536):
            if replies and self.withhold_replies:
                self.withheld_bytes += len(data)
                continue
            writer.write(data)
            await writer.drain()


@pytest.fixture
async def proxy(
    dedicated_redis: DedicatedRedisContainer, monkeypatch: pytest.MonkeyPatch
) -> AsyncIterator[_ReplyWithholdingProxy]:
    """A reply-withholding proxy in front of the dedicated container, with
    the lease operations' URL provider and operation timeout redirected to
    it."""
    instance = _ReplyWithholdingProxy(dedicated_redis.host, dedicated_redis.port)
    await instance.start()
    monkeypatch.setattr(
        cvss_recalculation_coordination,
        "get_cvss_recalculation_redis_url",
        lambda: instance.url,
    )
    monkeypatch.setattr(
        cvss_recalculation_coordination,
        "_REDIS_OPERATION_TIMEOUT_SECONDS",
        _SHORT_OPERATION_TIMEOUT,
    )
    try:
        yield instance
    finally:
        await instance.close()


async def _time_out_after_applied(
    proxy: _ReplyWithholdingProxy, operation: LeaseOperation
) -> None:
    """Run `operation` through `proxy` with replies withheld and assert it
    raises `RedisError` after Redis replied (so after it applied the
    command), on the one connection the client opened (no resend)."""
    client = _lease_client()
    try:
        assert await client.ping()
        proxy.withhold_replies = True
        with pytest.raises(RedisTimeoutError) as excinfo:
            await operation(client, task_id=TASK_ID, target_version=TARGET)
        assert isinstance(excinfo.value, RedisError)
    finally:
        await client.aclose()

    loop = asyncio.get_running_loop()
    deadline = loop.time() + _REPLY_DEADLINE
    while proxy.withheld_bytes == 0:
        assert loop.time() < deadline, "Redis never replied to the withheld command"
        await asyncio.sleep(0.01)
    assert proxy.connections == 1


@pytest.mark.integration
class TestCommandTimeoutWithWriteApplied:
    """A timeout after Redis applied the command raises `RedisError`; the
    caller applies the conservative outcome (an acquire is never success,
    a renew never confirmed ownership, a delete never done)."""

    async def test_acquire_timeout_raises_redis_error_and_write_landed(
        self, proxy: _ReplyWithholdingProxy, observer: redis_asyncio.Redis
    ) -> None:
        await _time_out_after_applied(proxy, acquire_lease)

        assert await observer.get(LEASE_KEY) == encode_lease_value(TASK_ID, TARGET)
        assert 0 < await observer.ttl(LEASE_KEY) <= LEASE_TTL_SECONDS

    async def test_renew_timeout_raises_redis_error_and_ttl_was_reset(
        self, proxy: _ReplyWithholdingProxy, observer: redis_asyncio.Redis
    ) -> None:
        assert await observer.set(LEASE_KEY, VALUE, ex=30)

        await _time_out_after_applied(proxy, compare_and_renew_lease)

        assert await observer.get(LEASE_KEY) == VALUE
        assert await observer.ttl(LEASE_KEY) > LEASE_TTL_SECONDS - 60

    async def test_delete_timeout_raises_redis_error_and_key_was_deleted(
        self, proxy: _ReplyWithholdingProxy, observer: redis_asyncio.Redis
    ) -> None:
        assert await observer.set(LEASE_KEY, VALUE, ex=LEASE_TTL_SECONDS)

        await _time_out_after_applied(proxy, compare_and_delete_lease)

        assert await observer.exists(LEASE_KEY) == 0
