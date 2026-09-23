"""Integration tests for the fetcher-run `items_succeeded` Alembic
migration (backend/alembic/versions/*_add_items_succeeded_to_fetcher_run.py).

Verifies the migration cycle mandated by
`docs/features/platform/fetcher-infrastructure.md` (Data Model —
FetcherRun) and `docs/data-model.md` (FetcherRun): upgrade from the
previous head adds the non-null `items_succeeded` counter with a server
default of zero (no backfill/inference — existing rows of every status
read zero) and aligns the three pre-existing counters with the
documented `INTEGER NOT NULL DEFAULT 0` server default. Downgrade
removes the new column and restores the previous (default-less) shape.

See `tests/test_migrations/conftest.py` for the shared Alembic test
infrastructure (dedicated database fixture, isolated config helper)
used by every migration test suite in this package.
"""

from __future__ import annotations

from typing import Any

import pytest
from sqlalchemy import inspect, text
from sqlalchemy.ext.asyncio import create_async_engine

from alembic import command
from app.config import settings
from tests.test_migrations.conftest import isolated_alembic_config, run_sync

_PREVIOUS_HEAD = "2972274112d2"
_FETCHER_NAME = "items_succeeded_migration_test_fetcher"
_COUNTER_COLUMNS = (
    "items_succeeded",
    "items_created",
    "items_updated",
    "items_failed",
)
_EXISTING_COUNTER_COLUMNS = ("items_created", "items_updated", "items_failed")


def _normalize_default(value: str | None) -> str | None:
    """Normalize a database-reported column default expression.

    PostgreSQL may report `server_default=sa.text("0")` as `"0"` or as
    `"'0'::integer"`; both denote the integer literal zero.
    """
    if value is None:
        return None
    return value.replace("'", "").replace("::integer", "").strip()


async def _seed_pre_migration_rows(database_url: str) -> None:
    """Insert a `FetcherConfig` row and three `FetcherRun` rows
    (`queued`, `running`, `success`) using only columns valid under the
    pre-migration schema."""
    engine = create_async_engine(database_url)
    try:
        async with engine.begin() as conn:
            await conn.execute(
                text(
                    "INSERT INTO fetcher_config "
                    "(fetcher_name, enabled, run_timeout, request_delay, "
                    "custom_settings) "
                    f"VALUES ('{_FETCHER_NAME}', true, 3600, 0, '{{}}')"
                )
            )
            await conn.execute(
                text(
                    "INSERT INTO fetcher_run "
                    "(fetcher_name, status, items_created, items_updated, "
                    "items_failed, triggered_by) "
                    f"VALUES ('{_FETCHER_NAME}', 'queued', 0, 0, 0, 'manual')"
                )
            )
            await conn.execute(
                text(
                    "INSERT INTO fetcher_run "
                    "(fetcher_name, started_at, status, items_created, "
                    "items_updated, items_failed, triggered_by) "
                    f"VALUES ('{_FETCHER_NAME}', now(), 'running', "
                    "0, 0, 0, 'schedule')"
                )
            )
            await conn.execute(
                text(
                    "INSERT INTO fetcher_run "
                    "(fetcher_name, started_at, finished_at, duration_seconds, "
                    "status, items_created, items_updated, items_failed, "
                    "triggered_by) "
                    f"VALUES ('{_FETCHER_NAME}', now() - interval '1 hour', "
                    "now() - interval '55 minutes', 300, 'success', 1, 0, 0, "
                    "'schedule')"
                )
            )
    finally:
        await engine.dispose()


async def _seed_row_with_succeeded(database_url: str) -> None:
    """Insert a `success` row with a positive `items_succeeded` — only
    valid after the migration under test has run."""
    engine = create_async_engine(database_url)
    try:
        async with engine.begin() as conn:
            await conn.execute(
                text(
                    "INSERT INTO fetcher_run "
                    "(fetcher_name, started_at, finished_at, duration_seconds, "
                    "status, items_succeeded, items_created, items_updated, "
                    "items_failed, triggered_by) "
                    f"VALUES ('{_FETCHER_NAME}', now() - interval '2 hours', "
                    "now() - interval '119 minutes', 60, 'success', 7, 3, 2, 0, "
                    "'schedule')"
                )
            )
    finally:
        await engine.dispose()


async def _fetch_succeeded_values(database_url: str) -> list[int]:
    """Read `items_succeeded` for the seeded rows — only valid once the
    column exists."""
    engine = create_async_engine(database_url)
    try:
        async with engine.connect() as conn:
            result = await conn.execute(
                text(
                    "SELECT items_succeeded FROM fetcher_run "
                    f"WHERE fetcher_name = '{_FETCHER_NAME}' "
                    "ORDER BY created_at ASC"
                )
            )
            return [row[0] for row in result]
    finally:
        await engine.dispose()


async def _inspect_columns(database_url: str) -> dict[str, dict[str, Any]]:
    engine = create_async_engine(database_url)
    try:
        async with engine.connect() as conn:

            def _sync_inspect(sync_conn: Any) -> dict[str, dict[str, Any]]:
                insp = inspect(sync_conn)
                return {col["name"]: col for col in insp.get_columns("fetcher_run")}

            return await conn.run_sync(_sync_inspect)
    finally:
        await engine.dispose()


def _columns(database_url: str) -> dict[str, dict[str, Any]]:
    return run_sync(_inspect_columns(database_url))


def _succeeded_values(database_url: str) -> list[int]:
    return run_sync(_fetch_succeeded_values(database_url))


@pytest.mark.integration
class TestFetcherRunItemsSucceededMigration:
    def test_upgrade_downgrade_reupgrade_cycle(
        self,
        alembic_test_database_url: str,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(settings, "database_url", alembic_test_database_url)
        cfg = isolated_alembic_config()

        # 1. Upgrade to the previous head — the column does not exist
        # yet, and the three pre-existing counters have no server
        # default.
        command.upgrade(cfg, _PREVIOUS_HEAD)
        before = _columns(alembic_test_database_url)
        assert "items_succeeded" not in before
        for column_name in _EXISTING_COUNTER_COLUMNS:
            assert before[column_name]["nullable"] is False
            assert before[column_name]["default"] is None

        run_sync(_seed_pre_migration_rows(alembic_test_database_url))

        # 2. Upgrade to head — `items_succeeded` exists as NOT NULL with
        # a zero server default, and the three existing counters gain
        # the documented zero server default.
        command.upgrade(cfg, "head")
        after = _columns(alembic_test_database_url)
        for column_name in _COUNTER_COLUMNS:
            assert after[column_name]["nullable"] is False
            assert _normalize_default(after[column_name]["default"]) == "0"

        # No backfill/inference: every pre-existing row reads zero.
        seeded_succeeded = _succeeded_values(alembic_test_database_url)
        assert len(seeded_succeeded) == 3
        assert seeded_succeeded == [0, 0, 0]

        # A positive value is now storable.
        run_sync(_seed_row_with_succeeded(alembic_test_database_url))
        succeeded_after_insert = _succeeded_values(alembic_test_database_url)
        assert len(succeeded_after_insert) == 4
        assert succeeded_after_insert[-1] == 7

        # 3. Downgrade back to the previous head — the column is dropped
        # and the three existing counters return to their default-less
        # pre-migration shape.
        command.downgrade(cfg, _PREVIOUS_HEAD)
        downgraded = _columns(alembic_test_database_url)
        assert "items_succeeded" not in downgraded
        for column_name in _EXISTING_COUNTER_COLUMNS:
            assert downgraded[column_name]["nullable"] is False
            assert downgraded[column_name]["default"] is None

        # 4. Re-upgrade to head — idempotent: the specified shape and
        # defaults are restored; the previously populated value is gone
        # with the dropped column.
        command.upgrade(cfg, "head")
        reupgraded = _columns(alembic_test_database_url)
        for column_name in _COUNTER_COLUMNS:
            assert reupgraded[column_name]["nullable"] is False
            assert _normalize_default(reupgraded[column_name]["default"]) == "0"

        reupgraded_succeeded = _succeeded_values(alembic_test_database_url)
        assert len(reupgraded_succeeded) == 4
        assert all(value == 0 for value in reupgraded_succeeded)
