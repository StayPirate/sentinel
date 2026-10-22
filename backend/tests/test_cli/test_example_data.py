"""Tests for `sentinel example-data load`.

See docs/features/platform/example-dataset.md (Command, Service Exceptions)
for the authoritative contract exercised here: the fail-fast step report,
the partial-dataset warning, the exact messages, the output channels, and
the exit codes. docs/features/platform/testing-strategy.md (CLI Commands,
Example Dataset, Sync Entry-Point Tests) defines the required coverage; the
service itself is verified by `tests/test_services/test_example_dataset.py`.

Every test is a synchronous `def` that calls the real `main()`, so the exit
code is the one the shared exception mapper produces. A load commits, so
every invocation runs against its own dedicated database migrated to the
head revision (`tests/support/example_dataset.py`), injected through the
command module's `get_session_factory` as a `NullPool` factory whose engine
is disposed on its own event loop after the invocation.
"""

from __future__ import annotations

import asyncio
import os
import subprocess
import sys
from collections.abc import Awaitable, Callable, Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Final
from unittest.mock import MagicMock

import pytest
from sqlalchemy import func, select
from sqlalchemy.engine import URL
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, create_async_engine
from sqlalchemy.pool import NullPool

import app.cli.example_data as example_data_module
from app.cli import main
from app.core.exceptions import ServiceError
from app.database import register_post_commit_callback
from app.models.fetcher_config import FetcherConfig
from app.models.identity_audit_event import IdentityAuditEvent
from app.models.user import User
from app.services import settings as settings_service
from app.services import user_service
from app.services.base_fetcher import FETCHER_REGISTRY
from tests.support.example_dataset import (
    dataset_database,
    dataset_engine,
    production_registries,
    session_factory,
)

pytestmark = pytest.mark.integration

STEPS: Final = (
    "Users",
    "System settings",
    "Fetchers",
    "Product catalog",
    "CVEs and tickets",
    "Ticket work",
)
"""Steps and Transactions, in order."""

GUARD_ERROR: Final = (
    "Error: The database is not empty. The example dataset loads only into "
    "a newly created database."
)
PARTIAL_DATASET_WARNING: Final = (
    "Warning: The database holds part of the example dataset. "
    "Recreate the database before loading it again."
)
EFFECT_MESSAGE: Final = (
    "An operation of the example dataset registered a post-commit effect."
)
SERVICE_FAILURE: Final = "Fictional service failure."
OTHER_FAILURE: Final = "fictional failure"

FICTIONAL_PASSWORD_HASH: Final = "$2b$12$" + "a" * 53
"""Fictional bcrypt-shaped value; never a real hash."""

UNREACHABLE_URL: Final = "postgresql+asyncpg://sentinel:sentinel@127.0.0.1:9/none"
"""A closed local port: no PostgreSQL server listens there."""

_BACKEND_DIR: Final = Path(__file__).resolve().parents[2]


class FictionalServiceError(ServiceError):
    """A fictional service exception injected into a delegated service."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def server(_engine: AsyncEngine) -> URL:
    """The URL of the shared test engine, whose PostgreSQL server holds the
    dedicated databases."""
    return _engine.url


@pytest.fixture
def database(server: URL) -> Iterator[str]:
    """A migrated dedicated database for one test."""
    with dataset_database(server) as url:
        yield url


def _invoke_main(monkeypatch: pytest.MonkeyPatch, engine: AsyncEngine) -> int:
    """Run `sentinel example-data load` through the real `main()` against
    `engine` and return the process exit code; the engine is disposed on
    its own event loop afterwards.

    `main()` raises `SystemExit` for a mapped exception and returns on
    success, which the console script turns into exit code 0."""
    monkeypatch.setattr(
        example_data_module, "get_session_factory", lambda: session_factory(engine)
    )
    monkeypatch.setattr(sys, "argv", ["sentinel", "example-data", "load"])
    code: object = 0
    try:
        with production_registries():
            main()
    except SystemExit as exc:
        code = exc.code
    finally:
        asyncio.run(engine.dispose())
    assert isinstance(code, int)
    return code


def _load(monkeypatch: pytest.MonkeyPatch, url: str) -> int:
    return _invoke_main(monkeypatch, dataset_engine(url))


def _read[R](url: str, reader: Callable[[AsyncSession], Awaitable[R]]) -> R:
    """Run `reader` in a session of `url` on a fresh `NullPool` engine."""

    async def run() -> R:
        engine = dataset_engine(url)
        try:
            async with session_factory(engine)() as db:
                return await reader(db)
        finally:
            await engine.dispose()

    return asyncio.run(run())


async def _identity_counts(db: AsyncSession) -> tuple[int, int]:
    """The number of users and of identity audit events."""
    users = await db.scalar(select(func.count()).select_from(User))
    events = await db.scalar(select(func.count()).select_from(IdentityAuditEvent))
    return int(users or 0), int(events or 0)


def _failed_report(step: str, reason: str) -> list[str]:
    """The step report of a load that fails at `step` with `reason`."""
    index = STEPS.index(step)
    return [
        *(f"✓ {done}" for done in STEPS[:index]),
        f"✗ {step}: {reason}",
        *(
            f"— {later} not attempted (aborted due to previous error)"
            for later in STEPS[index + 1 :]
        ),
    ]


def _assert_logged_then_error(lines: list[str], error: str) -> None:
    """The mapper's catch-all logs the exception at ERROR, with its
    traceback, before printing `error` as the last stderr line
    (cli-infrastructure.md, Error Handling & Exit Code Mapping);
    `bootstrap()` routes that log to stderr."""
    assert "cli_unhandled_exception" in lines[0]
    assert lines[-1] == error
    assert [line for line in lines if line.startswith("Error: ")] == [error]


# ---------------------------------------------------------------------------
# Success
# ---------------------------------------------------------------------------


def test_load_reports_every_step_and_exits_zero(
    database: str,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    run_spy = MagicMock(side_effect=asyncio.run)
    monkeypatch.setattr(example_data_module, "asyncio", SimpleNamespace(run=run_spy))

    code = _load(monkeypatch, database)

    captured = capsys.readouterr()
    assert code == 0
    assert captured.out.splitlines() == [
        *(f"✓ {step}" for step in STEPS),
        "Loaded the example dataset.",
    ]
    assert captured.err == ""
    assert run_spy.call_count == 1
    assert _read(database, _identity_counts)[0] == 6


def test_a_fresh_process_disables_every_production_fetcher(database: str) -> None:
    """The load imports the production fetcher registry itself
    (example-dataset.md, Service: Q3). The test process has imported it
    already, so only a fresh `python -m app.cli` process, which loads no
    fetcher module before the command runs, proves that every production
    fetcher is created and disabled."""

    async def fetchers(db: AsyncSession) -> dict[str, bool]:
        rows = await db.execute(
            select(FetcherConfig.fetcher_name, FetcherConfig.enabled)
        )
        return {row.fetcher_name: row.enabled for row in rows}

    completed = subprocess.run(
        [sys.executable, "-m", "app.cli", "example-data", "load"],
        cwd=_BACKEND_DIR,
        env={**os.environ, "DATABASE_URL": database},
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.splitlines()[-1] == "Loaded the example dataset."
    with production_registries():
        production = set(FETCHER_REGISTRY)
    assert _read(database, fetchers) == dict.fromkeys(production, False)


# ---------------------------------------------------------------------------
# Guard
# ---------------------------------------------------------------------------


def test_non_empty_database_is_refused_with_exit_one(
    database: str,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    async def insert_user(db: AsyncSession) -> None:
        db.add(
            User(
                username="fgreen",
                email="frank.green@example.com",
                full_name="Frank Green",
                password_hash=FICTIONAL_PASSWORD_HASH,
            )
        )
        await db.commit()

    _read(database, insert_user)

    code = _load(monkeypatch, database)

    captured = capsys.readouterr()
    assert code == 1
    assert captured.out == ""
    assert captured.err.splitlines() == [GUARD_ERROR]
    # Nothing written: the one user remains and no identity event exists.
    assert _read(database, _identity_counts) == (1, 0)


# ---------------------------------------------------------------------------
# Failure
# ---------------------------------------------------------------------------


def _raise_service_error(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fail(*args: Any, **kwargs: Any) -> str:
        raise FictionalServiceError(SERVICE_FAILURE)

    monkeypatch.setattr(settings_service, "update_default_cvss_version", fail)


def _raise_other_exception(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fail(*args: Any, **kwargs: Any) -> str:
        raise RuntimeError(OTHER_FAILURE)

    monkeypatch.setattr(settings_service, "update_default_cvss_version", fail)


async def _no_effect() -> None:
    pass


def _register_effect(monkeypatch: pytest.MonkeyPatch) -> None:
    real = settings_service.update_default_cvss_version

    async def registering(db: AsyncSession, **kwargs: Any) -> str:
        result = await real(db, **kwargs)
        register_post_commit_callback(db, _no_effect)
        return result

    monkeypatch.setattr(settings_service, "update_default_cvss_version", registering)


@pytest.mark.parametrize(
    ("inject", "reason", "message", "expected_code"),
    [
        pytest.param(
            _raise_service_error,
            SERVICE_FAILURE,
            SERVICE_FAILURE,
            1,
            id="service-exception",
        ),
        pytest.param(
            _raise_other_exception,
            "RuntimeError",
            OTHER_FAILURE,
            2,
            id="other-exception",
        ),
        pytest.param(
            _register_effect,
            EFFECT_MESSAGE,
            EFFECT_MESSAGE,
            1,
            id="registered-effect",
        ),
    ],
)
def test_failure_after_committed_operations_warns_of_a_partial_dataset(
    database: str,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    inject: Callable[[pytest.MonkeyPatch], None],
    reason: str,
    message: str,
    expected_code: int,
) -> None:
    """The first `System settings` operation fails after the `Users` step
    committed its operations."""
    inject(monkeypatch)

    code = _load(monkeypatch, database)

    captured = capsys.readouterr()
    assert code == expected_code
    assert captured.out.splitlines() == _failed_report("System settings", reason)
    err = captured.err.splitlines()
    if expected_code == 1:
        assert err == [PARTIAL_DATASET_WARNING, f"Error: {message}"]
    else:
        assert err[0] == PARTIAL_DATASET_WARNING
        _assert_logged_then_error(err[1:], f"Error: {message}")
    # The six users of the `Users` step remain.
    assert _read(database, _identity_counts)[0] == 6


def test_failure_of_the_first_operation_reports_no_partial_dataset(
    database: str,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    async def fail(*args: Any, **kwargs: Any) -> Any:
        raise FictionalServiceError(SERVICE_FAILURE)

    monkeypatch.setattr(user_service, "create_user", fail)

    code = _load(monkeypatch, database)

    captured = capsys.readouterr()
    assert code == 1
    assert captured.out.splitlines() == _failed_report("Users", SERVICE_FAILURE)
    assert captured.err.splitlines() == [f"Error: {SERVICE_FAILURE}"]
    assert _read(database, _identity_counts) == (0, 0)


# ---------------------------------------------------------------------------
# Unreachable database
# ---------------------------------------------------------------------------


def test_unreachable_database_exits_two_before_any_step(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    engine = create_async_engine(UNREACHABLE_URL, poolclass=NullPool)

    code = _invoke_main(monkeypatch, engine)

    captured = capsys.readouterr()
    assert code == 2
    # The guard fails to connect before any step: no step report and no
    # partial-dataset warning.
    assert captured.out == ""
    err = captured.err.splitlines()
    assert not any(line.startswith("Warning: ") for line in err)
    assert err[-1].startswith("Error: ")
    _assert_logged_then_error(err, err[-1])
