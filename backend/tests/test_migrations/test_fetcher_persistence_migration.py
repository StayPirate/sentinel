"""Integration tests for the fetcher persistence and audit Alembic
migration
(backend/alembic/versions/a43e3dc6f490_add_fetcher_persistence_and_audit_tables.py).

Verifies the migration cycle mandated by
`docs/features/platform/fetcher-infrastructure.md` (Data Model) and the
P3-01 tracking issue acceptance criteria: upgrade from the previous
head, schema facts (tables, CHECK constraint, foreign keys, indexes)
match the approved data model, and downgrade/re-upgrade round-trips
cleanly. Later changes to these tables are verified by the suites of
their own revisions.

See `tests/test_migrations/conftest.py` for the shared Alembic test
infrastructure (dedicated database fixture, isolated config helper)
used by every migration test suite in this package.
"""

from __future__ import annotations

from typing import Any, TypedDict

import pytest
from sqlalchemy import inspect
from sqlalchemy.ext.asyncio import create_async_engine

from alembic import command
from app.config import settings
from tests.test_migrations.conftest import isolated_alembic_config, run_sync

_PREVIOUS_HEAD = "c1ad47607809"
_REVISION = "a43e3dc6f490"


class _SchemaFacts(TypedDict):
    """The schema facts this test suite asserts on for a given
    (already-migrated) database — see `_inspect_schema()`."""

    tables: set[str]
    fetcher_run_checks: set[str]
    fetcher_run_indexes: dict[str, dict[str, Any]]
    fetcher_run_fks: list[dict[str, Any]]
    fetcher_audit_event_indexes: dict[str, dict[str, Any]]
    fetcher_audit_event_fks: list[dict[str, Any]]


async def _inspect_schema(database_url: str) -> _SchemaFacts:
    """Return the schema facts this test suite asserts on, in one
    connection, for a given (already-migrated) database URL."""
    engine = create_async_engine(database_url)
    try:
        async with engine.connect() as conn:

            def _sync_inspect(sync_conn: Any) -> _SchemaFacts:
                insp = inspect(sync_conn)
                tables = set(insp.get_table_names())
                run_checks = (
                    {c["name"] for c in insp.get_check_constraints("fetcher_run")}
                    if "fetcher_run" in tables
                    else set()
                )
                run_indexes = (
                    {idx["name"]: idx for idx in insp.get_indexes("fetcher_run")}
                    if "fetcher_run" in tables
                    else {}
                )
                run_fks = (
                    insp.get_foreign_keys("fetcher_run")
                    if "fetcher_run" in tables
                    else []
                )
                audit_indexes = (
                    {
                        idx["name"]: idx
                        for idx in insp.get_indexes("fetcher_audit_event")
                    }
                    if "fetcher_audit_event" in tables
                    else {}
                )
                audit_fks = (
                    insp.get_foreign_keys("fetcher_audit_event")
                    if "fetcher_audit_event" in tables
                    else []
                )
                return {
                    "tables": tables,
                    "fetcher_run_checks": run_checks,
                    "fetcher_run_indexes": run_indexes,
                    "fetcher_run_fks": run_fks,
                    "fetcher_audit_event_indexes": audit_indexes,
                    "fetcher_audit_event_fks": audit_fks,
                }

            return await conn.run_sync(_sync_inspect)
    finally:
        await engine.dispose()


def _inspect(database_url: str) -> _SchemaFacts:
    return run_sync(_inspect_schema(database_url))


@pytest.mark.integration
class TestFetcherPersistenceMigration:
    def test_upgrade_downgrade_reupgrade_cycle(
        self,
        alembic_test_database_url: str,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(settings, "database_url", alembic_test_database_url)
        cfg = isolated_alembic_config()

        # 1. Upgrade to the previous head — the schema state before
        # this module's migration (`_REVISION`).
        command.upgrade(cfg, _PREVIOUS_HEAD)
        before = _inspect(alembic_test_database_url)
        assert "fetcher_config" not in before["tables"]
        assert "fetcher_run" not in before["tables"]
        assert "fetcher_audit_event" not in before["tables"]

        # 2. Upgrade to the revision under test — creates all three
        # tables with their constraints and indexes.
        command.upgrade(cfg, _REVISION)
        after = _inspect(alembic_test_database_url)
        assert "fetcher_config" in after["tables"]
        assert "fetcher_run" in after["tables"]
        assert "fetcher_audit_event" in after["tables"]

        assert "chk_fetcher_run_status_valid" in after["fetcher_run_checks"]

        assert "ix_fetcher_run_fetcher_name_started_at" in after["fetcher_run_indexes"]
        composite_index = after["fetcher_run_indexes"][
            "ix_fetcher_run_fetcher_name_started_at"
        ]
        assert composite_index["column_names"] == ["fetcher_name", "started_at"]

        run_fk_tables = {fk["referred_table"] for fk in after["fetcher_run_fks"]}
        assert run_fk_tables == {"fetcher_config", "user"}
        run_fk_by_column = {
            fk["constrained_columns"][0]: fk for fk in after["fetcher_run_fks"]
        }
        assert run_fk_by_column["fetcher_name"]["options"].get("ondelete") == (
            "RESTRICT"
        )
        assert (
            run_fk_by_column["triggered_by_user_id"]["options"].get("ondelete") is None
        )

        audit_index_names = set(after["fetcher_audit_event_indexes"])
        assert "ix_fetcher_audit_event_created_at" in audit_index_names
        assert "ix_fetcher_audit_event_user_id" in audit_index_names
        assert "ix_fetcher_audit_event_fetcher_name" in audit_index_names

        audit_fk_tables = {
            fk["referred_table"] for fk in after["fetcher_audit_event_fks"]
        }
        assert audit_fk_tables == {"fetcher_config", "user"}
        audit_fk_by_column = {
            fk["constrained_columns"][0]: fk for fk in after["fetcher_audit_event_fks"]
        }
        assert audit_fk_by_column["fetcher_name"]["options"].get("ondelete") == (
            "RESTRICT"
        )
        assert audit_fk_by_column["user_id"]["options"].get("ondelete") == "RESTRICT"

        # 3. Downgrade back to the previous head — all three tables are
        # dropped cleanly (development downgrade).
        #
        # Note: `alembic check` itself is deliberately not invoked here.
        # `command.check()` compares the migrated database against
        # `Base.metadata` in the *current* process, which by
        # test-collection time already has
        # `tests.support.audit_models.SampleAuditEvent` registered on
        # the same shared `Base` (needed by unrelated `BaseAuditLog`
        # unit tests) — an in-process call would spuriously report
        # that table as drift. The CI pipeline's dedicated "Check
        # Alembic migration drift" step (`.github/workflows/ci.yml`)
        # already runs `alembic check` from a clean subprocess,
        # unaffected by test fixtures, against the same migration
        # chain verified here.
        command.downgrade(cfg, _PREVIOUS_HEAD)
        downgraded = _inspect(alembic_test_database_url)
        assert "fetcher_config" not in downgraded["tables"]
        assert "fetcher_run" not in downgraded["tables"]
        assert "fetcher_audit_event" not in downgraded["tables"]

        # 4. Re-upgrade to the revision under test — idempotent: no
        # errors.
        command.upgrade(cfg, _REVISION)
        reupgraded = _inspect(alembic_test_database_url)
        assert "fetcher_config" in reupgraded["tables"]
        assert "fetcher_run" in reupgraded["tables"]
        assert "fetcher_audit_event" in reupgraded["tables"]
