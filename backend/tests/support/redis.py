"""Shared test-only helpers for Redis-dependent tests.

See docs/features/platform/testing-strategy.md (Redis Strategy) for the
fixture contract these helpers support: `redis_url_from_client()` serves
the shared worker database, and `dedicated_redis_container()` serves the
server-global scenarios (restart, flush, unavailability) that must never
run against the shared server.
"""

from __future__ import annotations

import socket
import time
from collections.abc import Iterator
from contextlib import contextmanager
from typing import TYPE_CHECKING

import redis
import redis.asyncio as redis_asyncio
from redis.exceptions import RedisError

if TYPE_CHECKING:
    from testcontainers.community.redis import RedisContainer

_REDIS_PORT = 6379

_SERVER_COMMAND = ["redis-server", "--save", "", "--appendonly", "no"]
"""Persistence disabled, as in every deployment (docs/deployment.md,
Persistence is Disabled by Design): a restart therefore loses every key."""

_READY_DEADLINE = 30.0
_DOCKER_STOP_TIMEOUT = 10


def redis_url_from_client(client: redis_asyncio.Redis) -> str:
    """Reconstruct the connection URL for an existing async Redis client.

    Used to obtain a raw URL (e.g. for `_check_redis()`, which takes a
    URL rather than a client) from the shared `redis_client` fixture.
    """
    kwargs = client.connection_pool.connection_kwargs
    return f"redis://{kwargs['host']}:{kwargs['port']}/{kwargs.get('db', 0)}"


def unused_tcp_port() -> int:
    """A TCP port that was free when this function returned.

    The kernel picks the port for a socket bound to port 0; the socket is
    closed again, so the caller can bind the port itself (or have Docker
    bind it) shortly afterward.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("", 0))
        port: int = probe.getsockname()[1]
    return port


class DedicatedRedisContainer:
    """A running Redis 8 container that belongs to one test.

    Its host port is fixed when the container is created, so `url` stays
    valid across `restart()` and `stop()`/`start()`. Created and removed
    by `dedicated_redis_container()`.
    """

    def __init__(self, host: str, port: int, container: RedisContainer) -> None:
        self.host = host
        self.port = port
        self._container = container

    @property
    def url(self) -> str:
        """URL of logical database 0 of the container."""
        return f"redis://{self.host}:{self.port}/0"

    def restart(self) -> None:
        """Restart the server process (losing every key) and wait until it
        answers `PING` again."""
        self._container.get_wrapped_container().restart(timeout=_DOCKER_STOP_TIMEOUT)
        wait_until_redis_ready(self.url)

    def stop(self) -> None:
        """Stop the container, keeping it, so the server is unavailable."""
        self._container.get_wrapped_container().stop(timeout=_DOCKER_STOP_TIMEOUT)

    def start(self) -> None:
        """Start a stopped container again and wait until it answers
        `PING`."""
        self._container.get_wrapped_container().start()
        wait_until_redis_ready(self.url)


def wait_until_redis_ready(url: str, *, deadline: float = _READY_DEADLINE) -> None:
    """Block until the server at `url` answers `PING`, failing at a
    monotonic `deadline` (seconds)."""
    limit = time.monotonic() + deadline
    while True:
        error: RedisError | None = None
        try:
            with redis.Redis.from_url(
                url, socket_connect_timeout=1, socket_timeout=1
            ) as client:
                if client.ping():
                    return
        except RedisError as exc:
            error = exc
        if time.monotonic() >= limit:
            raise RuntimeError(
                f"dedicated Redis at {url} not ready within {deadline} s: {error}"
            ) from error
        time.sleep(0.05)


@contextmanager
def dedicated_redis_container() -> Iterator[DedicatedRedisContainer]:
    """Run a Redis 8 container dedicated to the calling test.

    For server-global scenarios only (see docs/features/platform/
    testing-strategy.md, Redis Strategy): the test may restart, flush, or
    stop this server without affecting the shared worker databases.
    Persistence is disabled, and the host port is fixed so a restart keeps
    the URL. The container is always removed on exit.
    """
    # Lazy import, as in tests/conftest.py: Docker is needed only here.
    from testcontainers.community.redis import RedisContainer

    port = unused_tcp_port()
    # renovate: depName=redis
    container = RedisContainer("redis:8")
    container.with_command(_SERVER_COMMAND).with_bind_ports(_REDIS_PORT, port)
    try:
        container.start()
        dedicated = DedicatedRedisContainer(
            container.get_container_host_ip(), port, container
        )
        wait_until_redis_ready(dedicated.url)
        yield dedicated
    finally:
        container.stop()
