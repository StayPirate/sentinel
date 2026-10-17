"""Integration tests for the per-run hard time limit Alembic migration
(backend/alembic/versions/2972274112d2_add_hard_time_limit_to_fetcher_run.py).

Verifies the migration cycle mandated by
`docs/features/platform/fetcher-infrastructure.md` (Per-Run Hard Time
Limit): upgrade from the previous head adds a nullable
`hard_time_limit_seconds` column to `fetcher_run` with no backfill
(existing rows of every status remain `NULL`), and the column is
cleanly dropped on downgrade.

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

_PREVIOUS_HEAD = "a4f22788de31"
_REVISION = "2972274112d2"


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
                    "VALUES ('hard_limit_migration_test_fetcher', true, 3600, 0, '{}')"
                )
            )
            await conn.execute(
                text(
                    "INSERT INTO fetcher_run "
                    "(fetcher_name, status, items_created, items_updated, "
                    "items_failed, triggered_by) "
                    "VALUES ('hard_limit_migration_test_fetcher', 'queued', "
                    "0, 0, 0, 'manual')"
                )
            )
            await conn.execute(
                text(
                    "INSERT INTO fetcher_run "
                    "(fetcher_name, started_at, status, items_created, "
                    "items_updated, items_failed, triggered_by) "
                    "VALUES ('hard_limit_migration_test_fetcher', now(), "
                    "'running', 0, 0, 0, 'schedule')"
                )
            )
            await conn.execute(
                text(
                    "INSERT INTO fetcher_run "
                    "(fetcher_name, started_at, finished_at, duration_seconds, "
                    "status, items_created, items_updated, items_failed, "
                    "triggered_by) "
                    "VALUES ('hard_limit_migration_test_fetcher', "
                    "now() - interval '1 hour', now() - interval '55 minutes', "
                    "300, 'success', 1, 0, 0, 'schedule')"
                )
            )
    finally:
        await engine.dispose()


async def _seed_row_with_hard_limit(database_url: str) -> None:
    """Insert a `running` row with a populated
    `hard_time_limit_seconds` — only valid after the migration under
    test has run."""
    engine = create_async_engine(database_url)
    try:
        async with engine.begin() as conn:
            await conn.execute(
                text(
                    "INSERT INTO fetcher_run "
                    "(fetcher_name, started_at, status, hard_time_limit_seconds, "
                    "items_created, items_updated, items_failed, triggered_by) "
                    "VALUES ('hard_limit_migration_test_fetcher', now(), "
                    "'running', 1800, 0, 0, 0, 'schedule')"
                )
            )
    finally:
        await engine.dispose()


async def _fetch_statuses_only(database_url: str) -> list[str]:
    """Read only `status`, valid both before and after the migration —
    used for the pre-migration seed check, before
    `hard_time_limit_seconds` exists."""
    engine = create_async_engine(database_url)
    try:
        async with engine.connect() as conn:
            result = await conn.execute(
                text(
                    "SELECT status FROM fetcher_run "
                    "WHERE fetcher_name = 'hard_limit_migration_test_fetcher' "
                    "ORDER BY created_at ASC"
                )
            )
            return [row.status for row in result]
    finally:
        await engine.dispose()


async def _fetch_rows(database_url: str) -> list[dict[str, Any]]:
    engine = create_async_engine(database_url)
    try:
        async with engine.connect() as conn:
            result = await conn.execute(
                text(
                    "SELECT status, hard_time_limit_seconds FROM fetcher_run "
                    "WHERE fetcher_name = 'hard_limit_migration_test_fetcher' "
                    "ORDER BY created_at ASC"
                )
            )
            return [
                {"status": row.status, "hard_time_limit_seconds": row[1]}
                for row in result
            ]
    finally:
        await engine.dispose()


def _fetch(database_url: str) -> list[dict[str, Any]]:
    return run_sync(_fetch_rows(database_url))


def _fetch_statuses(database_url: str) -> list[str]:
    return run_sync(_fetch_statuses_only(database_url))


async def _inspect_fetcher_run(database_url: str) -> dict[str, dict[str, Any]]:
    engine = create_async_engine(database_url)
    try:
        async with engine.connect() as conn:

            def _sync_inspect(sync_conn: Any) -> dict[str, dict[str, Any]]:
                insp = inspect(sync_conn)
                return {col["name"]: col for col in insp.get_columns("fetcher_run")}

            return await conn.run_sync(_sync_inspect)
    finally:
        await engine.dispose()


def _inspect(database_url: str) -> dict[str, dict[str, Any]]:
    return run_sync(_inspect_fetcher_run(database_url))


@pytest.mark.integration
class TestHardTimeLimitMigration:
    def test_upgrade_downgrade_reupgrade_cycle(
        self,
        alembic_test_database_url: str,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(settings, "database_url", alembic_test_database_url)
        cfg = isolated_alembic_config()

        # 1. Upgrade to the previous head — schema state before this
        # migration: no `hard_time_limit_seconds` column.
        command.upgrade(cfg, _PREVIOUS_HEAD)
        before_columns = _inspect(alembic_test_database_url)
        assert "hard_time_limit_seconds" not in before_columns

        run_sync(_seed_pre_migration_rows(alembic_test_database_url))
        seeded_statuses = _fetch_statuses(alembic_test_database_url)
        assert len(seeded_statuses) == 3
        assert set(seeded_statuses) == {"queued", "running", "success"}

        # 2. Upgrade to the revision under test — the nullable column
        # now exists, and no backfill occurred: every pre-existing row
        # (regardless of status) has a NULL value.
        command.upgrade(cfg, _REVISION)
        after_columns = _inspect(alembic_test_database_url)
        assert "hard_time_limit_seconds" in after_columns
        assert after_columns["hard_time_limit_seconds"]["nullable"] is True

        rows_after_upgrade = _fetch(alembic_test_database_url)
        assert len(rows_after_upgrade) == 3
        assert all(row["hard_time_limit_seconds"] is None for row in rows_after_upgrade)

        # A row with a populated hard_time_limit_seconds is now valid.
        run_sync(_seed_row_with_hard_limit(alembic_test_database_url))
        rows_with_hard_limit = _fetch(alembic_test_database_url)
        assert len(rows_with_hard_limit) == 4
        new_row = next(
            r for r in rows_with_hard_limit if r["hard_time_limit_seconds"] is not None
        )
        assert new_row["hard_time_limit_seconds"] == 1800

        # 3. Downgrade back to the previous head — the column is
        # dropped entirely; no data normalization is needed since the
        # column carries no state relied upon by the older schema.
        command.downgrade(cfg, _PREVIOUS_HEAD)
        downgraded_columns = _inspect(alembic_test_database_url)
        assert "hard_time_limit_seconds" not in downgraded_columns

        # 4. Re-upgrade to the revision under test — idempotent: no
        # errors, schema facts match step 2 again (column re-added as
        # NULL for every row, including the one that previously carried
        # a value).
        command.upgrade(cfg, _REVISION)
        reupgraded_columns = _inspect(alembic_test_database_url)
        assert "hard_time_limit_seconds" in reupgraded_columns
        assert reupgraded_columns["hard_time_limit_seconds"]["nullable"] is True

        rows_after_reupgrade = _fetch(alembic_test_database_url)
        assert len(rows_after_reupgrade) == 4
        assert all(
            row["hard_time_limit_seconds"] is None for row in rows_after_reupgrade
        )
