"""Integration tests for the UUIDv7 primary key `server_default`
Alembic migration
(backend/alembic/versions/4b4f7187b541_add_uuidv7_server_default_to_primary_.py).

Verifies the migration cycle mandated by `docs/conventions.md`
(SQLAlchemy Conventions) and the issue #286 acceptance criteria: every
UUID primary key column gets `server_default=uuidv7()` after upgrade,
the default is removed on downgrade, and re-upgrade restores it
cleanly.

See `tests/test_migrations/conftest.py` for the shared Alembic test
infrastructure (dedicated database fixture, isolated config helper)
used by every migration test suite in this package.
"""

from __future__ import annotations

from typing import Any

import pytest
from sqlalchemy import inspect
from sqlalchemy.ext.asyncio import create_async_engine

from alembic import command
from app.config import settings
from tests.test_migrations.conftest import isolated_alembic_config, run_sync

_PREVIOUS_HEAD = "a43e3dc6f490"
_REVISION = "4b4f7187b541"

# Every table with a UUID primary key at the revision under test
# (`docs/data-model.md`, Notes).
_UUID_PK_TABLES: tuple[str, ...] = (
    "user",
    "api_key",
    "user_role",
    "session",
    "fetcher_run",
    "fetcher_audit_event",
    "identity_audit_event",
    "setting_audit_event",
)


async def _inspect_id_defaults(database_url: str) -> dict[str, str | None]:
    """Return each UUID PK table's `id` column `default` expression (as
    reported by the database), or `None` if no `server_default` is set."""
    engine = create_async_engine(database_url)
    try:
        async with engine.connect() as conn:

            def _sync_inspect(sync_conn: Any) -> dict[str, str | None]:
                insp = inspect(sync_conn)
                result: dict[str, str | None] = {}
                for table_name in _UUID_PK_TABLES:
                    columns = {c["name"]: c for c in insp.get_columns(table_name)}
                    result[table_name] = columns["id"]["default"]
                return result

            return await conn.run_sync(_sync_inspect)
    finally:
        await engine.dispose()


def _inspect(database_url: str) -> dict[str, str | None]:
    return run_sync(_inspect_id_defaults(database_url))


@pytest.mark.integration
class TestUuidV7PrimaryKeysMigration:
    def test_upgrade_downgrade_reupgrade_cycle(
        self,
        alembic_test_database_url: str,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(settings, "database_url", alembic_test_database_url)
        cfg = isolated_alembic_config()

        # 1. Upgrade to the previous head — every UUID PK column has no
        # server_default (Python-side `default=uuid.uuid4`/`uuid.uuid7`
        # only, per the pre-migration model state).
        command.upgrade(cfg, _PREVIOUS_HEAD)
        before = _inspect(alembic_test_database_url)
        for table_name in _UUID_PK_TABLES:
            assert before[table_name] is None, (
                f"expected no server_default on '{table_name}.id' before "
                f"the migration, got {before[table_name]!r}"
            )

        # 2. Upgrade to the revision under test — every UUID PK column
        # gets server_default=uuidv7().
        command.upgrade(cfg, _REVISION)
        after = _inspect(alembic_test_database_url)
        for table_name in _UUID_PK_TABLES:
            assert after[table_name] == "uuidv7()", (
                f"expected server_default='uuidv7()' on '{table_name}.id' "
                f"after the migration, got {after[table_name]!r}"
            )

        # 3. Downgrade back to the previous head — server_default is
        # removed from every UUID PK column (development downgrade).
        command.downgrade(cfg, _PREVIOUS_HEAD)
        downgraded = _inspect(alembic_test_database_url)
        for table_name in _UUID_PK_TABLES:
            assert downgraded[table_name] is None, (
                f"expected no server_default on '{table_name}.id' after "
                f"downgrade, got {downgraded[table_name]!r}"
            )

        # 4. Re-upgrade to the revision under test — idempotent:
        # server_default restored on every UUID PK column, no errors.
        command.upgrade(cfg, _REVISION)
        reupgraded = _inspect(alembic_test_database_url)
        for table_name in _UUID_PK_TABLES:
            assert reupgraded[table_name] == "uuidv7()", (
                f"expected server_default='uuidv7()' on '{table_name}.id' "
                f"after re-upgrade, got {reupgraded[table_name]!r}"
            )

    def test_server_side_insert_generates_uuidv7(
        self,
        alembic_test_database_url: str,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """An INSERT that omits the `id` column entirely (bypassing the
        ORM's Python-side `default=`) still gets a UUIDv7 value from the
        database — this is the migration's safety-net purpose."""
        monkeypatch.setattr(settings, "database_url", alembic_test_database_url)
        cfg = isolated_alembic_config()
        command.upgrade(cfg, _REVISION)

        async def _insert_and_fetch() -> str:
            from sqlalchemy import text

            engine = create_async_engine(alembic_test_database_url)
            try:
                async with engine.begin() as conn:
                    await conn.execute(
                        text(
                            "INSERT INTO fetcher_config "
                            "(fetcher_name, enabled, run_timeout, "
                            "request_delay, custom_settings) "
                            "VALUES ('smoke_test_fetcher', true, 60, 0.0, '{}')"
                        )
                    )
                    inserted = await conn.execute(
                        text(
                            "INSERT INTO fetcher_run "
                            "(fetcher_name, started_at, status, items_created, "
                            "items_updated, items_failed, triggered_by) "
                            "VALUES ('smoke_test_fetcher', now(), 'success', "
                            "0, 0, 0, 'manual') RETURNING id"
                        )
                    )
                    return str(inserted.scalar_one())
            finally:
                await engine.dispose()

        generated_id = run_sync(_insert_and_fetch())
        # UUIDv7 version nibble is '7' at this fixed position.
        assert generated_id[14] == "7", (
            f"expected a UUIDv7 value (version nibble '7'), got {generated_id!r}"
        )
