"""Alembic environment configuration for async SQLAlchemy."""

from __future__ import annotations

import asyncio
from logging.config import fileConfig

from sqlalchemy import Connection, pool
from sqlalchemy.ext.asyncio import async_engine_from_config

import app.models  # noqa: F401
from alembic import context
from app.config import settings
from app.database import Base

# Import all models here so Alembic can detect them

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

config.set_main_option("sqlalchemy.url", settings.database_url)

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode."""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection: Connection) -> None:
    """Run migrations with a connection.

    `compare_server_default=True` lets autogenerate detect
    `server_default` changes (e.g., adding `server_default=text(...)` to
    an existing column) — the default `False` would silently produce an
    empty migration for such changes, requiring the author to notice
    and hand-write the operation instead. Verified against this
    project's actual `server_default` patterns (`func.now()`,
    `text("uuidv7()")`, and literal string/boolean defaults) to produce
    no false-positive diffs.

    `alembic.ext.checkconstraint_byname` restores name-based detection
    of added/removed CHECK constraints, which Alembic 1.19.2 moved out
    of the default `alembic.autogenerate.*` set because it reports false
    positives for unnamed CHECKs. Every model CHECK is named `chk_*`
    (docs/conventions.md, Enum Storage Strategy), so it is reliable
    here. It never compares CHECK expressions: an expression change
    under an unchanged name must still be written by hand and is
    covered by the migration tests.
    """
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        compare_server_default=True,
        autogenerate_plugins=[
            "alembic.autogenerate.*",
            "alembic.ext.checkconstraint_byname",
        ],
    )

    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    """Run migrations in 'online' mode with async engine."""
    connectable = async_engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)

    await connectable.dispose()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode."""
    asyncio.run(run_async_migrations())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
