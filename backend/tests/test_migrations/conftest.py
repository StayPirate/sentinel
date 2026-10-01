"""Shared Alembic test infrastructure for `tests/test_migrations/`.

Every migration test suite in this package exercises the real `alembic`
commands (`command.upgrade()`, `command.downgrade()`, `command.check()`)
against a dedicated, empty PostgreSQL database created on the same
server as the shared test harness — not against the harness's own
database (which already has every table created via
`Base.metadata.create_all()`, bypassing Alembic entirely; see
`docs/features/platform/testing-strategy.md`, Schema Setup). A
dedicated database lets each suite exercise the literal migration
files against a clean schema, mirroring a real deployment.

Per `docs/features/platform/testing-strategy.md` (Sync Entry-Point
Tests), every test function using these fixtures is synchronous (`def`,
not `async def`): `alembic.command.upgrade()` (and friends) call
`asyncio.run()` internally via `alembic/env.py`'s
`run_migrations_online()`, which would raise
`RuntimeError: asyncio.run() cannot be called when another event loop
is running` if invoked from a coroutine already running on
pytest-asyncio's event loop. The `alembic_test_database_url` fixture is
plain-sync for the same reason: it performs its own database
creation/teardown via independent `asyncio.run()` calls, entirely
outside pytest-asyncio's managed loop.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import Coroutine, Iterator
from pathlib import Path
from typing import Any

import pytest
from alembic.config import Config
from sqlalchemy.ext.asyncio import AsyncEngine

from tests.support.database import create_database, drop_database

_ALEMBIC_INI = Path(__file__).resolve().parents[2] / "alembic.ini"


def run_sync[T](coro: Coroutine[Any, Any, T]) -> T:
    """Run a coroutine to completion on a fresh event loop.

    Used for a fixture's own database creation/teardown and for schema
    inspection between `alembic` command invocations — each call is
    independent and fully completes before the next starts (no
    nesting), consistent with the Sync Entry-Point Tests convention's
    "one `asyncio.run()` call per invocation" for the entry point under
    test; this is test-infrastructure code applying the same
    discipline for clarity.
    """
    return asyncio.run(coro)


@pytest.fixture
def alembic_test_database_url(_engine: AsyncEngine) -> Iterator[str]:
    """A fresh, empty PostgreSQL database dedicated to one test's
    Alembic upgrade/downgrade cycle, created on the same server as the
    shared test harness (`_engine`) and dropped on teardown.
    """
    db_name = f"alembic_test_{uuid.uuid4().hex[:12]}"
    admin_url = _engine.url.set(database="postgres")

    run_sync(create_database(admin_url, db_name))

    yield _engine.url.set(database=db_name).render_as_string(hide_password=False)

    run_sync(drop_database(admin_url, db_name))


def isolated_alembic_config() -> Config:
    """Build an Alembic `Config` that will NOT reconfigure Python's
    stdlib `logging` module when passed to `command.upgrade()` and
    friends.

    `alembic/env.py` calls `logging.config.fileConfig(config.config_file_name)`
    whenever `config.config_file_name` is not `None`. `fileConfig()`
    defaults to `disable_existing_loggers=True`, which sets `.disabled
    = True` on every currently-registered logger NOT explicitly listed
    in `alembic.ini`'s `[loggers]` section (only `root`, `sqlalchemy`,
    `alembic`) — silently muting every `app.*` structlog-backed logger
    for the remainder of the pytest process, breaking unrelated
    `caplog`-based tests elsewhere in the suite (see
    docs/features/platform/testing-strategy.md, Test Independence).

    Forcing `file_config` to memoize its parsed `alembic.ini` content
    via one `get_main_option()` call, then clearing `config_file_name`,
    makes `env.py` skip the `fileConfig()` call entirely while leaving
    every other config lookup (`script_location`, the `sqlalchemy.url`
    override) unaffected — they read from the already-memoized
    `ConfigParser`, not from `config_file_name` directly.
    """
    cfg = Config(str(_ALEMBIC_INI))
    cfg.get_main_option("script_location")  # force file_config memoization
    cfg.config_file_name = None
    return cfg
