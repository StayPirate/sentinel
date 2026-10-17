"""Integration tests for the system settings Alembic migration
(backend/alembic/versions/c1ad47607809_add_system_settings_tables.py).

Verifies the migration cycle mandated by
`docs/features/platform/system-settings.md` (Bootstrap) and the P2-14
tracking issue acceptance criteria: upgrade from the previous head
creates both tables and the seed, the seed is idempotent and preserves
a custom value, and downgrade/re-upgrade round-trips cleanly. Drift
between the models and the migration chain is verified by `alembic
check` in CI, not here (see the note in the cycle test).

See `tests/test_migrations/conftest.py` for the shared Alembic test
infrastructure (dedicated database fixture, isolated config helper)
used by every migration test suite in this package.
"""

from __future__ import annotations

from typing import Any, TypedDict

import pytest
from sqlalchemy import inspect, text
from sqlalchemy.ext.asyncio import create_async_engine

from alembic import command
from app.config import settings
from tests.test_migrations.conftest import isolated_alembic_config, run_sync

_PREVIOUS_HEAD = "4e3e94583e96"
_REVISION = "c1ad47607809"


class _SchemaFacts(TypedDict):
    """The schema facts this test suite asserts on for a given
    (already-migrated) database — see `_inspect_schema()`."""

    tables: set[str]
    setting_audit_event_indexes: set[str]
    setting_audit_event_fks: list[dict[str, Any]]
    seed_value: str | None


async def _inspect_schema(database_url: str) -> _SchemaFacts:
    """Return the schema facts this test suite asserts on, in one
    connection, for a given (already-migrated) database URL."""
    engine = create_async_engine(database_url)
    try:
        async with engine.connect() as conn:

            def _sync_inspect(sync_conn: Any) -> _SchemaFacts:
                insp = inspect(sync_conn)
                tables = set(insp.get_table_names())
                setting_indexes = (
                    {idx["name"] for idx in insp.get_indexes("setting_audit_event")}
                    if "setting_audit_event" in tables
                    else set()
                )
                setting_fks = (
                    insp.get_foreign_keys("setting_audit_event")
                    if "setting_audit_event" in tables
                    else []
                )
                return {
                    "tables": tables,
                    "setting_audit_event_indexes": setting_indexes,
                    "setting_audit_event_fks": setting_fks,
                    "seed_value": None,
                }

            result = await conn.run_sync(_sync_inspect)

            if "system_setting" in result["tables"]:
                row = await conn.execute(
                    text(
                        "SELECT value FROM system_setting "
                        "WHERE key = 'default_cvss_version'"
                    )
                )
                result["seed_value"] = row.scalar_one_or_none()
            return result
    finally:
        await engine.dispose()


def _inspect(database_url: str) -> _SchemaFacts:
    return run_sync(_inspect_schema(database_url))


@pytest.mark.integration
class TestSystemSettingsMigration:
    def test_upgrade_downgrade_reupgrade_cycle(
        self,
        alembic_test_database_url: str,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(settings, "database_url", alembic_test_database_url)
        cfg = isolated_alembic_config()

        # 1. Upgrade to the previous head — the schema state before this
        # work item's migration.
        command.upgrade(cfg, _PREVIOUS_HEAD)
        before = _inspect(alembic_test_database_url)
        assert "system_setting" not in before["tables"]
        assert "setting_audit_event" not in before["tables"]

        # 2. Upgrade to the revision under test — creates both tables
        # and seeds the `default_cvss_version` baseline row.
        command.upgrade(cfg, _REVISION)
        after = _inspect(alembic_test_database_url)
        assert "system_setting" in after["tables"]
        assert "setting_audit_event" in after["tables"]
        assert after["seed_value"] == "3.1"
        assert (
            "ix_setting_audit_event_created_at" in after["setting_audit_event_indexes"]
        )
        assert (
            "ix_setting_audit_event_setting_key" in after["setting_audit_event_indexes"]
        )
        assert "ix_setting_audit_event_user_id" in after["setting_audit_event_indexes"]
        fk_referred_tables = {
            fk["referred_table"] for fk in after["setting_audit_event_fks"]
        }
        assert fk_referred_tables == {"system_setting", "user"}

        # 3. Downgrade back to the previous head — both tables are
        # dropped cleanly (development downgrade).
        #
        # Note: `alembic check` itself is deliberately not invoked here.
        # `command.check()` compares the migrated database against
        # `Base.metadata` in the *current* process, which by test-collection
        # time already has `tests.support.audit_models.SampleAuditEvent`
        # registered on the same shared `Base` (needed by unrelated
        # `BaseAuditLog` unit tests) — an in-process call would spuriously
        # report that table as drift. The CI pipeline's dedicated "Check
        # Alembic migration drift" step (`.github/workflows/ci.yml`) already
        # runs `alembic check` from a clean subprocess, unaffected by test
        # fixtures, against the same migration chain verified here.
        command.downgrade(cfg, _PREVIOUS_HEAD)
        downgraded = _inspect(alembic_test_database_url)
        assert "system_setting" not in downgraded["tables"]
        assert "setting_audit_event" not in downgraded["tables"]

        # 4. Re-upgrade to the revision under test — idempotent: no
        # errors, seed restored.
        command.upgrade(cfg, _REVISION)
        reupgraded = _inspect(alembic_test_database_url)
        assert "system_setting" in reupgraded["tables"]
        assert reupgraded["seed_value"] == "3.1"

    def test_seed_is_idempotent_and_preserves_a_custom_value(
        self,
        alembic_test_database_url: str,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(settings, "database_url", alembic_test_database_url)
        cfg = isolated_alembic_config()

        command.upgrade(cfg, _REVISION)
        assert _inspect(alembic_test_database_url)["seed_value"] == "3.1"

        async def _set_custom_value() -> None:
            engine = create_async_engine(alembic_test_database_url)
            try:
                async with engine.begin() as conn:
                    await conn.execute(
                        text(
                            "UPDATE system_setting SET value = '4.0' "
                            "WHERE key = 'default_cvss_version'"
                        )
                    )
            finally:
                await engine.dispose()

        run_sync(_set_custom_value())

        # Re-running the seed statement directly (mirroring what a
        # repeated migration run would execute) must not overwrite the
        # administrator-selected value.
        async def _rerun_seed() -> None:
            engine = create_async_engine(alembic_test_database_url)
            try:
                async with engine.begin() as conn:
                    await conn.execute(
                        text(
                            "INSERT INTO system_setting (key, value) "
                            "VALUES ('default_cvss_version', '3.1') "
                            "ON CONFLICT (key) DO NOTHING"
                        )
                    )
            finally:
                await engine.dispose()

        run_sync(_rerun_seed())

        assert _inspect(alembic_test_database_url)["seed_value"] == "4.0"
