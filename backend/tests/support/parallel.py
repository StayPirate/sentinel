"""Parallel (pytest-xdist) execution helpers for the test harness.

See docs/features/platform/testing-strategy.md (Parallel Execution) for the
contract: every pytest-xdist worker uses its own PostgreSQL database and its
own Redis logical database, and the controller rejects a worker count that
the test infrastructure cannot isolate or serve before any worker starts.

The helpers here are pure or perform a single read-only query, so they can be
tested directly. The pytest hook and the container provisioning that use them
live in `tests/conftest.py`.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

import pytest
from sqlalchemy import text
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import NullPool

REDIS_LOGICAL_DB_COUNT = 16
"""Logical databases offered by a default Redis server (`databases 16`)."""

ENGINE_POOL_SIZE = 5
"""Persistent connections of each worker's shared test engine (`_engine`)."""

ENGINE_MAX_OVERFLOW = 10
"""Additional transient connections the shared test engine may open."""

AUXILIARY_CONNECTIONS_PER_WORKER = 5
"""Connections a worker may hold outside the shared engine's pool: the
`NullPool` CLI-test engine, dedicated engines of cross-loop and migration
tests, and administrative `CREATE DATABASE`/`DROP DATABASE` connections."""

CONNECTIONS_PER_WORKER = (
    ENGINE_POOL_SIZE + ENGINE_MAX_OVERFLOW + AUXILIARY_CONNECTIONS_PER_WORKER
)
"""PostgreSQL connection budget reserved for each pytest worker."""

POSTGRES_MAX_IDENTIFIER_BYTES = 63
"""PostgreSQL truncates longer identifiers (`NAMEDATALEN - 1`)."""

_WORKER_ID = re.compile(r"gw(\d+)")


def worker_id() -> str | None:
    """This process's pytest-xdist worker id (`"gw0"`, `"gw1"`, ...).

    `None` when the suite runs in a single process, including the xdist
    controller, which runs no tests.
    """
    return os.environ.get("PYTEST_XDIST_WORKER") or None


def worker_number(worker: str | None) -> int:
    """The zero-based number encoded in a pytest-xdist worker id.

    A single-process run (`worker is None`) is number 0, so it maps to the
    start of every per-worker range exactly like the first worker.
    """
    if worker is None:
        return 0
    match = _WORKER_ID.fullmatch(worker)
    if match is None:
        raise ValueError(f"unexpected pytest-xdist worker id {worker!r}")
    return int(match.group(1))


def worker_database_name(base: str | None, worker: str) -> str:
    """The dedicated PostgreSQL database name of one pytest worker.

    Derived as `<base>_<worker>` (e.g. `sentinel_test_gw3`). Fails instead
    of letting PostgreSQL silently truncate a long name, because truncation
    could map two workers to the same database.
    """
    if not base:
        raise ValueError(
            "TEST_DATABASE_URL must name a database; per-worker database "
            "names are derived from it"
        )
    worker_number(worker)  # validates the id format
    name = f"{base}_{worker}"
    if len(name.encode()) > POSTGRES_MAX_IDENTIFIER_BYTES:
        raise ValueError(
            f"per-worker database name {name!r} exceeds PostgreSQL's "
            f"{POSTGRES_MAX_IDENTIFIER_BYTES}-byte identifier limit; use a "
            "shorter database name in TEST_DATABASE_URL"
        )
    return name


def worker_database_url(base_url: str, worker: str | None) -> str:
    """`base_url` retargeted at this worker's dedicated database.

    A single-process run (`worker is None`) uses `base_url` unchanged.
    """
    if worker is None:
        return base_url
    url = make_url(base_url)
    return url.set(
        database=worker_database_name(url.database, worker)
    ).render_as_string(hide_password=False)


def redis_base_index(url: str) -> int:
    """The logical database encoded in a Redis URL (0 when absent)."""
    return int(urlsplit(url).path.lstrip("/") or "0")


def redis_worker_db_index(base_index: int, worker: str | None) -> int:
    """This worker's dedicated Redis logical database index.

    Consecutive workers use consecutive databases starting at `base_index`,
    with no overlap. Raises explicitly — never silently shares a database —
    if the index meets or exceeds the number of databases the server offers.
    """
    index = base_index + worker_number(worker)
    if index >= REDIS_LOGICAL_DB_COUNT:
        raise RuntimeError(
            f"Redis test harness requires logical database {index}, but the "
            f"server only offers {REDIS_LOGICAL_DB_COUNT} (0-"
            f"{REDIS_LOGICAL_DB_COUNT - 1}). Reduce the number of parallel "
            "test workers or configure a server with more logical databases."
        )
    return index


def planned_worker_count(config: pytest.Config) -> int:
    """The number of pytest-xdist workers this run will start.

    0 when tests are not distributed: no `-n`, `-n 0`, `--pdb`, or the
    xdist plugin disabled. Counts the expanded `--tx` specifications that
    xdist itself starts (`-n N` becomes N `popen` specifications).
    """
    if getattr(config.option, "dist", "no") == "no":
        return 0
    from xdist.workermanage import parse_tx_spec_config

    return len(parse_tx_spec_config(config))


def check_redis_capacity(base_index: int, workers: int) -> None:
    """Reject a worker count that would not fit the Redis database range."""
    available = REDIS_LOGICAL_DB_COUNT - base_index
    if workers > available:
        raise pytest.UsageError(
            f"{workers} pytest workers need Redis logical databases "
            f"{base_index}-{base_index + workers - 1}, but the server offers "
            f"only 0-{REDIS_LOGICAL_DB_COUNT - 1}. Run with at most "
            f"-n {max(available, 0)}, or start TEST_REDIS_URL at a lower "
            "logical database of a range reserved for the test harness."
        )


@dataclass(frozen=True)
class PostgresCapacity:
    """Connection capacity of the PostgreSQL test server."""

    max_connections: int
    reserved_connections: int
    """`superuser_reserved_connections` plus `reserved_connections`."""
    other_clients: int
    """Client backends connected when the capacity was read, excluding the
    reading connection itself."""
    can_create_databases: bool

    @property
    def available_connections(self) -> int:
        return self.max_connections - self.reserved_connections - self.other_clients


async def read_postgres_capacity(url: str) -> PostgresCapacity:
    """Read the connection capacity and the role's database privilege."""
    engine = create_async_engine(url, poolclass=NullPool)
    try:
        async with engine.connect() as conn:
            row = (
                await conn.execute(
                    text(
                        "SELECT"
                        " current_setting('max_connections')::int,"
                        " current_setting('superuser_reserved_connections')::int"
                        " + coalesce(current_setting('reserved_connections', true),"
                        " '0')::int,"
                        " (SELECT count(*) FROM pg_stat_activity"
                        "  WHERE backend_type = 'client backend'"
                        "  AND pid <> pg_backend_pid())::int,"
                        " (SELECT rolsuper OR rolcreatedb FROM pg_roles"
                        "  WHERE rolname = current_user)"
                    )
                )
            ).one()
    finally:
        await engine.dispose()
    return PostgresCapacity(
        max_connections=row[0],
        reserved_connections=row[1],
        other_clients=row[2],
        can_create_databases=bool(row[3]),
    )


def check_postgres_capacity(workers: int, capacity: PostgresCapacity) -> None:
    """Reject a worker count the PostgreSQL test server cannot serve."""
    if not capacity.can_create_databases:
        raise pytest.UsageError(
            "Parallel test workers create a dedicated PostgreSQL database "
            "each, but the TEST_DATABASE_URL role has neither CREATEDB nor "
            "superuser. Grant CREATEDB to the test role, or run serially."
        )
    required = workers * CONNECTIONS_PER_WORKER
    available = capacity.available_connections
    if required > available:
        raise pytest.UsageError(
            f"{workers} pytest workers need up to {required} PostgreSQL "
            f"connections ({CONNECTIONS_PER_WORKER} per worker), but the test "
            f"server offers {available} (max_connections="
            f"{capacity.max_connections}, reserved="
            f"{capacity.reserved_connections}, already connected="
            f"{capacity.other_clients}). Run with at most "
            f"-n {max(available // CONNECTIONS_PER_WORKER, 0)}, or raise "
            "max_connections on the test server."
        )


def postgres_container_max_connections(workers: int) -> int:
    """`max_connections` for a harness-provisioned PostgreSQL container.

    Never below PostgreSQL's default of 100, and always enough for the
    planned workers plus PostgreSQL's default reserved connections.
    """
    return max(100, workers * CONNECTIONS_PER_WORKER + 10)
