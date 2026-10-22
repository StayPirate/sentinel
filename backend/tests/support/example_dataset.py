"""Dedicated databases for the Example Dataset tests.

docs/features/platform/testing-strategy.md (Mandatory Test Scenarios >
Example Dataset): the dataset is verified against a dedicated database that
the test creates on the test PostgreSQL server, migrates to the head
revision with Alembic, and drops afterwards. The load commits, so it never
runs in a worker database shared with other tests, and the dedicated
database starts its Ticket identifiers at `SNTL-1`.

`dataset_database()` is synchronous: Alembic and the database DDL each run
their own `asyncio.run()`, outside pytest-asyncio's event loop (Sync
Entry-Point Tests). `session_factory()` returns a `NullPool` factory, so no
connection outlives the event loop that opened it.

`production_registries()` restricts both fetcher registries to the
production fetchers that `app.services.fetcher_discovery` registers, as in
the API process, and restores them on exit: test modules that define
fetcher classes register them in the same process-wide registries, and the
load bootstraps and disables every registered fetcher.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import Iterator
from contextlib import contextmanager

import pytest
from sqlalchemy.engine import URL
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import NullPool

from alembic import command
from app.config import settings
from app.services.base_cve_fetcher import _CVE_SOURCE_TYPE_MAP
from app.services.base_fetcher import FETCHER_REGISTRY
from tests.support.database import create_database, drop_database
from tests.test_migrations.conftest import isolated_alembic_config


@contextmanager
def production_registries() -> Iterator[None]:
    """Only the production fetchers are registered inside the context."""
    import app.services.fetcher_discovery  # noqa: F401  (production registry)

    fetchers = dict(FETCHER_REGISTRY)
    sources = dict(_CVE_SOURCE_TYPE_MAP)
    try:
        for name, fetcher in fetchers.items():
            if not fetcher.__module__.startswith("app."):
                del FETCHER_REGISTRY[name]
        for source, cve_fetcher in sources.items():
            if not cve_fetcher.__module__.startswith("app."):
                del _CVE_SOURCE_TYPE_MAP[source]
        yield
    finally:
        FETCHER_REGISTRY.clear()
        FETCHER_REGISTRY.update(fetchers)
        _CVE_SOURCE_TYPE_MAP.clear()
        _CVE_SOURCE_TYPE_MAP.update(sources)


@contextmanager
def dataset_database(server: URL) -> Iterator[str]:
    """A new database on the server of `server`, migrated to the head
    revision; yields its URL and drops it on exit."""
    name = f"example_dataset_{uuid.uuid4().hex[:12]}"
    admin = server.set(database="postgres")
    asyncio.run(create_database(admin, name))
    url = server.set(database=name).render_as_string(hide_password=False)
    try:
        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(settings, "database_url", url)
            command.upgrade(isolated_alembic_config(), "head")
        yield url
    finally:
        asyncio.run(drop_database(admin, name))


def dataset_engine(url: str) -> AsyncEngine:
    """A `NullPool` engine of the dedicated database."""
    return create_async_engine(url, poolclass=NullPool)


def session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    """A factory configured as the production `async_session_factory`."""
    return async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
