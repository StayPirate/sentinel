"""Tests for the parallel (pytest-xdist) execution helpers of the harness."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

from tests import conftest as root_conftest
from tests.support.parallel import (
    CONNECTIONS_PER_WORKER,
    POSTGRES_MAX_IDENTIFIER_BYTES,
    REDIS_LOGICAL_DB_COUNT,
    PostgresCapacity,
    check_postgres_capacity,
    check_redis_capacity,
    planned_worker_count,
    postgres_container_max_connections,
    read_postgres_capacity,
    redis_base_index,
    redis_worker_db_index,
    worker_database_name,
    worker_database_url,
    worker_id,
    worker_number,
)

_BACKEND_DIR = Path(__file__).resolve().parents[2]


class _FakeCapture:
    def __init__(self) -> None:
        self.discarded = False

    def read_global_capture(self) -> None:
        self.discarded = True


class _FakeConfig:
    """The subset of `pytest.Config` that `planned_worker_count` and the
    root conftest's `pytest_configure` read."""

    def __init__(self, dist: str | None, tx: list[str] | None = None) -> None:
        self.option = SimpleNamespace() if dist is None else SimpleNamespace(dist=dist)
        self._tx = tx or []
        self.capture = _FakeCapture()
        self.pluginmanager = SimpleNamespace(
            getplugin=lambda name: self.capture if name == "capturemanager" else None
        )

    def getvalue(self, name: str) -> list[str]:
        assert name == "tx"
        return self._tx


def _capacity(
    *,
    max_connections: int = 100,
    reserved: int = 3,
    other_clients: int = 0,
    can_create_databases: bool = True,
) -> PostgresCapacity:
    return PostgresCapacity(
        max_connections=max_connections,
        reserved_connections=reserved,
        other_clients=other_clients,
        can_create_databases=can_create_databases,
    )


@pytest.mark.unit
class TestWorkerIdentity:
    def test_worker_id_unset_is_single_process(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("PYTEST_XDIST_WORKER", raising=False)
        assert worker_id() is None

    def test_worker_id_empty_is_single_process(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("PYTEST_XDIST_WORKER", "")
        assert worker_id() is None

    def test_worker_id_set_returns_it(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("PYTEST_XDIST_WORKER", "gw7")
        assert worker_id() == "gw7"

    @pytest.mark.parametrize(
        ("worker", "expected"), [(None, 0), ("gw0", 0), ("gw1", 1), ("gw13", 13)]
    )
    def test_worker_number_valid_id_returns_number(
        self, worker: str | None, expected: int
    ) -> None:
        assert worker_number(worker) == expected

    @pytest.mark.parametrize("worker", ["master", "gw", "gwx", "gw1a", "1", "GW1"])
    def test_worker_number_unexpected_id_raises(self, worker: str) -> None:
        with pytest.raises(ValueError, match="unexpected pytest-xdist worker id"):
            worker_number(worker)


@pytest.mark.unit
class TestWorkerDatabase:
    def test_name_appends_worker_id(self) -> None:
        assert worker_database_name("sentinel_test", "gw3") == "sentinel_test_gw3"

    @pytest.mark.parametrize("base", [None, ""])
    def test_name_without_base_database_raises(self, base: str | None) -> None:
        with pytest.raises(ValueError, match="must name a database"):
            worker_database_name(base, "gw0")

    def test_name_invalid_worker_raises(self) -> None:
        with pytest.raises(ValueError, match="unexpected pytest-xdist worker id"):
            worker_database_name("sentinel_test", "master")

    def test_name_at_identifier_limit_is_accepted(self) -> None:
        base = "d" * (POSTGRES_MAX_IDENTIFIER_BYTES - len("_gw10"))
        name = worker_database_name(base, "gw10")
        assert len(name.encode()) == POSTGRES_MAX_IDENTIFIER_BYTES

    def test_name_over_identifier_limit_raises(self) -> None:
        base = "d" * (POSTGRES_MAX_IDENTIFIER_BYTES - len("_gw10") + 1)
        with pytest.raises(ValueError, match="63-byte identifier limit"):
            worker_database_name(base, "gw10")

    def test_name_limit_counts_bytes_not_characters(self) -> None:
        # 30 two-byte characters are 60 bytes; "_gw1" makes 64.
        with pytest.raises(ValueError, match="identifier limit"):
            worker_database_name("é" * 30, "gw1")

    def test_url_single_process_is_unchanged(self) -> None:
        url = "postgresql+asyncpg://user:secret@db.example.com:5432/sentinel_test"
        assert worker_database_url(url, None) == url

    def test_url_worker_replaces_only_the_database(self) -> None:
        url = (
            "postgresql+asyncpg://user:secret@db.example.com:5432/sentinel_test"
            "?ssl=disable"
        )
        result = make_url(worker_database_url(url, "gw2"))

        assert result.database == "sentinel_test_gw2"
        assert result.password == "secret"
        assert result.host == "db.example.com"
        assert result.port == 5432
        assert dict(result.query) == {"ssl": "disable"}


@pytest.mark.unit
class TestRedisAllocation:
    @pytest.mark.parametrize(
        ("url", "expected"),
        [
            ("redis://localhost:6379/2", 2),
            ("redis://localhost:6379/", 0),
            ("redis://localhost:6379", 0),
            ("", 0),
        ],
    )
    def test_base_index_reads_url_database(self, url: str, expected: int) -> None:
        assert redis_base_index(url) == expected

    def test_worker_index_offsets_from_base(self) -> None:
        assert redis_worker_db_index(2, None) == 2
        assert redis_worker_db_index(2, "gw0") == 2
        assert redis_worker_db_index(2, "gw13") == REDIS_LOGICAL_DB_COUNT - 1

    def test_worker_index_past_server_range_raises(self) -> None:
        with pytest.raises(RuntimeError, match="requires logical database 16"):
            redis_worker_db_index(2, "gw14")

    @pytest.mark.parametrize(("base", "workers"), [(2, 14), (0, 16), (15, 1)])
    def test_capacity_within_range_is_accepted(self, base: int, workers: int) -> None:
        check_redis_capacity(base, workers)

    def test_capacity_past_range_raises_with_safe_maximum(self) -> None:
        with pytest.raises(pytest.UsageError) as raised:
            check_redis_capacity(2, 15)

        message = str(raised.value)
        assert "15 pytest workers need Redis logical databases 2-16" in message
        assert "-n 14" in message


@pytest.mark.unit
class TestPlannedWorkerCount:
    def test_without_xdist_plugin_is_zero(self) -> None:
        assert planned_worker_count(cast("pytest.Config", _FakeConfig(None))) == 0

    def test_not_distributing_is_zero(self) -> None:
        config = _FakeConfig("no", ["popen"] * 4)
        assert planned_worker_count(cast("pytest.Config", config)) == 0

    def test_numprocesses_counts_popen_specs(self) -> None:
        config = _FakeConfig("load", ["popen"] * 4)
        assert planned_worker_count(cast("pytest.Config", config)) == 4

    def test_multiplied_tx_specs_are_expanded(self) -> None:
        config = _FakeConfig("load", ["3*popen", "popen"])
        assert planned_worker_count(cast("pytest.Config", config)) == 4


@pytest.mark.unit
class TestPostgresCapacity:
    def test_available_excludes_reserved_and_connected(self) -> None:
        capacity = _capacity(max_connections=100, reserved=3, other_clients=2)
        assert capacity.available_connections == 95

    def test_role_without_createdb_raises(self) -> None:
        with pytest.raises(pytest.UsageError, match="neither CREATEDB nor superuser"):
            check_postgres_capacity(1, _capacity(can_create_databases=False))

    def test_budget_exactly_available_is_accepted(self) -> None:
        workers = 4
        capacity = _capacity(
            max_connections=workers * CONNECTIONS_PER_WORKER + 3, reserved=3
        )
        check_postgres_capacity(workers, capacity)

    def test_budget_over_available_raises_with_safe_maximum(self) -> None:
        workers = 5
        capacity = _capacity(max_connections=100, reserved=3, other_clients=1)

        with pytest.raises(pytest.UsageError) as raised:
            check_postgres_capacity(workers, capacity)

        message = str(raised.value)
        assert f"need up to {workers * CONNECTIONS_PER_WORKER} PostgreSQL" in message
        assert "offers 96" in message
        assert "max_connections=100" in message
        assert f"-n {96 // CONNECTIONS_PER_WORKER}" in message

    @pytest.mark.parametrize(
        ("workers", "expected"),
        [
            (1, 100),
            (4, 100),
            (5, 5 * CONNECTIONS_PER_WORKER + 10),
            (16, 16 * CONNECTIONS_PER_WORKER + 10),
        ],
    )
    def test_container_max_connections_covers_workers(
        self, workers: int, expected: int
    ) -> None:
        assert postgres_container_max_connections(workers) == expected
        check_postgres_capacity(
            workers, _capacity(max_connections=expected, reserved=3)
        )


@pytest.fixture
def server_url(_engine: AsyncEngine) -> str:
    """URL of the PostgreSQL test server (this worker's database)."""
    return _engine.url.render_as_string(hide_password=False)


@pytest.mark.integration
class TestReadPostgresCapacity:
    async def test_reads_server_settings_and_privilege(
        self, server_url: str, db_session: AsyncSession
    ) -> None:
        _ = await db_session.connection()  # one other client connected

        capacity = await read_postgres_capacity(server_url)

        assert capacity.max_connections > 0
        assert capacity.reserved_connections >= 0
        assert capacity.other_clients >= 1
        assert capacity.can_create_databases is True
        assert capacity.available_connections < capacity.max_connections


_CONFIGURED_DATABASE_URL = "postgresql+asyncpg://user:secret@db.example.com/sentinel"


@pytest.fixture
def configured_servers(monkeypatch: pytest.MonkeyPatch) -> None:
    """Configured test servers, so the controller starts no container."""
    monkeypatch.setenv("TEST_DATABASE_URL", _CONFIGURED_DATABASE_URL)
    monkeypatch.setenv("TEST_REDIS_URL", "redis://redis.example.com:6379/2")


def _serve_capacity(
    monkeypatch: pytest.MonkeyPatch, capacity: PostgresCapacity | Exception
) -> list[str]:
    """Replace the controller's capacity read; return the URLs it reads."""
    read: list[str] = []

    async def _read(url: str) -> PostgresCapacity:
        read.append(url)
        if isinstance(capacity, Exception):
            raise capacity
        return capacity

    monkeypatch.setattr(root_conftest, "read_postgres_capacity", _read)
    return read


@pytest.mark.unit
@pytest.mark.usefixtures("configured_servers")
class TestControllerConfigure:
    """The root conftest's `pytest_configure` in the xdist controller.

    Synchronous tests: the hook runs its capacity read with
    `asyncio.run()` (testing-strategy.md, Sync Entry-Point Tests).
    """

    def test_single_process_run_does_nothing(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        read = _serve_capacity(monkeypatch, RuntimeError("must not be read"))
        config = _FakeConfig("no")

        root_conftest.pytest_configure(cast("pytest.Config", config))

        assert read == []
        assert config.capture.discarded is False

    def test_worker_process_does_nothing(self, monkeypatch: pytest.MonkeyPatch) -> None:
        read = _serve_capacity(monkeypatch, RuntimeError("must not be read"))
        config = _FakeConfig("load", ["popen"] * 2)
        config.workerinput = {"workerid": "gw0"}  # type: ignore[attr-defined]

        root_conftest.pytest_configure(cast("pytest.Config", config))

        assert read == []

    def test_sufficient_capacity_passes_and_discards_controller_output(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        read = _serve_capacity(monkeypatch, _capacity(max_connections=100))
        config = _FakeConfig("load", ["popen"] * 4)

        root_conftest.pytest_configure(cast("pytest.Config", config))

        assert read == [_CONFIGURED_DATABASE_URL]
        assert config.capture.discarded is True

    def test_connection_budget_exceeded_raises_usage_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _serve_capacity(monkeypatch, _capacity(max_connections=100))
        config = _FakeConfig("load", ["popen"] * 5)

        with pytest.raises(pytest.UsageError, match="need up to 100 PostgreSQL"):
            root_conftest.pytest_configure(cast("pytest.Config", config))

        assert config.capture.discarded is False

    def test_role_without_createdb_raises_usage_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _serve_capacity(monkeypatch, _capacity(can_create_databases=False))
        config = _FakeConfig("load", ["popen"] * 2)

        with pytest.raises(pytest.UsageError, match="neither CREATEDB"):
            root_conftest.pytest_configure(cast("pytest.Config", config))

    def test_unreachable_server_raises_usage_error_without_password(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _serve_capacity(monkeypatch, ConnectionRefusedError("connection refused"))
        config = _FakeConfig("load", ["popen"] * 2)

        with pytest.raises(pytest.UsageError) as raised:
            root_conftest.pytest_configure(cast("pytest.Config", config))

        message = str(raised.value)
        assert "PostgreSQL test server unreachable" in message
        assert "user:***@db.example.com" in message
        assert "secret" not in message

    def test_redis_range_is_checked_before_postgres(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        read = _serve_capacity(monkeypatch, RuntimeError("must not be read"))
        config = _FakeConfig("load", ["popen"] * 15)

        with pytest.raises(pytest.UsageError, match="Redis logical databases 2-16"):
            root_conftest.pytest_configure(cast("pytest.Config", config))

        assert read == []


@pytest.mark.integration
def test_controller_rejects_workers_past_redis_range() -> None:
    """End to end: `-n` past the Redis range fails before any worker starts.

    The Redis check runs before any provisioning, so the unreachable
    TEST_DATABASE_URL is never contacted and no container is started.
    """
    env = {
        name: value
        for name, value in os.environ.items()
        if not name.startswith(("PYTEST_", "COV_CORE_"))
    }
    env["TEST_REDIS_URL"] = "redis://localhost:1/2"
    env["TEST_DATABASE_URL"] = "postgresql+asyncpg://user:secret@localhost:1/unused"

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "-p",
            "no:cacheprovider",
            "-n",
            "15",
            "--collect-only",
            "-q",
            "tests/test_health.py",
        ],
        cwd=_BACKEND_DIR,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )

    assert result.returncode == pytest.ExitCode.USAGE_ERROR, result.stderr
    assert "15 pytest workers need Redis logical databases 2-16" in result.stderr
    assert "-n 14" in result.stderr
