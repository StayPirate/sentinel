"""Integration tests for the CVE root Alembic migration
(backend/alembic/versions/292b30ba95cb_add_cve_root_and_child_tables.py).

Verifies that upgrading from the previous head creates exactly the
`cve`, `cve_source`, `cve_cvss_assessment`, and `cve_external_identifier`
tables documented in `docs/data-model.md` (CVE, CVESource,
CVECVSSAssessment, CVEExternalIdentifier): columns, types, nullability,
server defaults, `ON DELETE CASCADE` foreign keys, unique keys, the single
`chk_cve_cve_state_valid` CHECK, and no further CHECK or index. Downgrade
removes the four tables and re-upgrade restores them.

`alembic check` is deliberately not invoked in-process: `command.check()`
compares against `Base.metadata` of the current process, which already
contains the test-only `tests.support.audit_models.SampleAuditEvent` table
and would report it as spurious drift. The CI "Check Alembic migration
drift" step (`.github/workflows/ci.yml`) runs `alembic check` from a clean
process against the same migration chain.

See `tests/test_migrations/conftest.py` for the shared Alembic test
infrastructure (dedicated database fixture, isolated config helper).
"""

from __future__ import annotations

from typing import Any, TypedDict

import pytest
from sqlalchemy import Dialect, inspect
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.types import DateTime, TypeEngine

from alembic import command
from app.config import settings
from tests.test_migrations.conftest import isolated_alembic_config, run_sync

_PREVIOUS_HEAD = "ace650c9f7a8"
_REVISION = "292b30ba95cb"
_CVE_TABLES = {"cve", "cve_source", "cve_cvss_assessment", "cve_external_identifier"}

_UUID_PK_DEFAULT = "uuidv7()"
_NOW_DEFAULT = "now()"

# Expected columns per table: name -> (type, nullable, server default).
# Order is the documented column order in docs/data-model.md.
_EXPECTED_COLUMNS: dict[str, list[tuple[str, str, bool, str | None]]] = {
    "cve": [
        ("id", "UUID", False, _UUID_PK_DEFAULT),
        ("cve_id", "VARCHAR(20)", False, None),
        ("title", "VARCHAR(256)", True, None),
        ("description", "TEXT", True, None),
        ("severity", "VARCHAR(20)", True, None),
        ("published_date", "TIMESTAMPTZ", True, None),
        ("modified_date", "TIMESTAMPTZ", True, None),
        ("cve_state", "VARCHAR(20)", False, "'PUBLISHED'::character varying"),
        ("date_rejected", "TIMESTAMPTZ", True, None),
        ("created_at", "TIMESTAMPTZ", False, _NOW_DEFAULT),
        ("updated_at", "TIMESTAMPTZ", False, _NOW_DEFAULT),
    ],
    "cve_source": [
        ("id", "UUID", False, _UUID_PK_DEFAULT),
        ("cve_id", "UUID", False, None),
        ("source", "VARCHAR(100)", False, None),
        ("status", "VARCHAR(20)", False, None),
        ("fetched_at", "TIMESTAMPTZ", False, None),
        ("first_failed_at", "TIMESTAMPTZ", True, None),
        ("created_at", "TIMESTAMPTZ", False, _NOW_DEFAULT),
        ("updated_at", "TIMESTAMPTZ", False, _NOW_DEFAULT),
    ],
    "cve_cvss_assessment": [
        ("id", "UUID", False, _UUID_PK_DEFAULT),
        ("cve_id", "UUID", False, None),
        ("provider_name", "VARCHAR(100)", False, None),
        ("cvss_version", "VARCHAR(10)", False, None),
        ("score", "NUMERIC(3, 1)", False, None),
        ("severity", "VARCHAR(10)", False, None),
        ("vector_string", "VARCHAR(200)", False, None),
        ("created_at", "TIMESTAMPTZ", False, _NOW_DEFAULT),
        ("updated_at", "TIMESTAMPTZ", False, _NOW_DEFAULT),
    ],
    "cve_external_identifier": [
        ("id", "UUID", False, _UUID_PK_DEFAULT),
        ("cve_id", "UUID", False, None),
        ("source", "VARCHAR(20)", False, None),
        ("identifier", "VARCHAR(100)", False, None),
        ("url", "TEXT", True, None),
        ("created_at", "TIMESTAMPTZ", False, _NOW_DEFAULT),
        ("updated_at", "TIMESTAMPTZ", False, _NOW_DEFAULT),
    ],
}

# Expected unique keys per table, as sets of column tuples.
_EXPECTED_UNIQUE_KEYS: dict[str, set[tuple[str, ...]]] = {
    "cve": {("cve_id",)},
    "cve_source": {("cve_id", "source")},
    "cve_cvss_assessment": {("cve_id", "provider_name", "cvss_version")},
    "cve_external_identifier": {("source", "identifier")},
}

_EXPECTED_NAMED_UNIQUE_CONSTRAINTS: dict[str, str] = {
    "cve_source": "uq_cve_source_cve_id_source",
    "cve_cvss_assessment": "uq_cve_cvss_assessment_cve_id_provider_name_cvss_version",
    "cve_external_identifier": "uq_cve_external_identifier_source_identifier",
}

_EXPECTED_CHECKS: dict[str, set[str]] = {
    "cve": {"chk_cve_cve_state_valid"},
    "cve_source": set(),
    "cve_cvss_assessment": set(),
    "cve_external_identifier": set(),
}

_CHILD_TABLES = ("cve_source", "cve_cvss_assessment", "cve_external_identifier")


class _TableFacts(TypedDict):
    columns: list[tuple[str, str, bool, str | None]]
    primary_key: list[str]
    foreign_keys: list[dict[str, Any]]
    unique_constraints: list[dict[str, Any]]
    checks: list[dict[str, Any]]
    standalone_indexes: list[dict[str, Any]]


class _SchemaFacts(TypedDict):
    tables: set[str]
    cve_tables: dict[str, _TableFacts]


def _describe_type(column_type: TypeEngine[Any], dialect: Dialect) -> str:
    """Render a reflected column type; `TIMESTAMPTZ` distinguishes a
    timezone-aware timestamp from a bare `TIMESTAMP`."""
    if isinstance(column_type, DateTime):
        return "TIMESTAMPTZ" if column_type.timezone else "TIMESTAMP"
    return str(column_type.compile(dialect=dialect))


async def _inspect_schema(database_url: str) -> _SchemaFacts:
    engine = create_async_engine(database_url)
    try:
        async with engine.connect() as conn:

            def _sync_inspect(sync_conn: Any) -> _SchemaFacts:
                inspector = inspect(sync_conn)
                tables = set(inspector.get_table_names())
                cve_tables: dict[str, _TableFacts] = {}
                for table in _CVE_TABLES & tables:
                    cve_tables[table] = {
                        "columns": [
                            (
                                column["name"],
                                _describe_type(column["type"], sync_conn.dialect),
                                column["nullable"],
                                column["default"],
                            )
                            for column in inspector.get_columns(table)
                        ],
                        "primary_key": inspector.get_pk_constraint(table)[
                            "constrained_columns"
                        ],
                        "foreign_keys": inspector.get_foreign_keys(table),
                        "unique_constraints": inspector.get_unique_constraints(table),
                        "checks": inspector.get_check_constraints(table),
                        # Indexes backing a unique constraint are reported
                        # with `duplicates_constraint`; anything else is a
                        # standalone index.
                        "standalone_indexes": [
                            index
                            for index in inspector.get_indexes(table)
                            if not index.get("duplicates_constraint")
                        ],
                    }
                return {"tables": tables, "cve_tables": cve_tables}

            return await conn.run_sync(_sync_inspect)
    finally:
        await engine.dispose()


def _inspect(database_url: str) -> _SchemaFacts:
    return run_sync(_inspect_schema(database_url))


def _assert_cve_schema(facts: _SchemaFacts) -> None:
    assert facts["tables"] >= _CVE_TABLES
    tables = facts["cve_tables"]

    for table, expected_columns in _EXPECTED_COLUMNS.items():
        assert tables[table]["columns"] == expected_columns, table
        assert tables[table]["primary_key"] == ["id"], table

    for table, expected_keys in _EXPECTED_UNIQUE_KEYS.items():
        actual_keys = {
            tuple(constraint["column_names"])
            for constraint in tables[table]["unique_constraints"]
        }
        assert actual_keys == expected_keys, table

    for table, name in _EXPECTED_NAMED_UNIQUE_CONSTRAINTS.items():
        names = {c["name"] for c in tables[table]["unique_constraints"]}
        assert names == {name}, table

    for table, expected_checks in _EXPECTED_CHECKS.items():
        assert {c["name"] for c in tables[table]["checks"]} == expected_checks, table

    (state_check,) = tables["cve"]["checks"]
    assert "PUBLISHED" in state_check["sqltext"]
    assert "REJECTED" in state_check["sqltext"]

    assert tables["cve"]["foreign_keys"] == []
    for table in _CHILD_TABLES:
        (foreign_key,) = tables[table]["foreign_keys"]
        assert foreign_key["constrained_columns"] == ["cve_id"], table
        assert foreign_key["referred_table"] == "cve", table
        assert foreign_key["referred_columns"] == ["id"], table
        assert foreign_key["options"].get("ondelete") == "CASCADE", table

    for table in _CVE_TABLES:
        assert tables[table]["standalone_indexes"] == [], table


@pytest.mark.integration
class TestCVERootMigration:
    def test_upgrade_downgrade_reupgrade_cycle(
        self,
        alembic_test_database_url: str,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(settings, "database_url", alembic_test_database_url)
        cfg = isolated_alembic_config()

        command.upgrade(cfg, _PREVIOUS_HEAD)
        assert _CVE_TABLES.isdisjoint(_inspect(alembic_test_database_url)["tables"])

        command.upgrade(cfg, _REVISION)
        _assert_cve_schema(_inspect(alembic_test_database_url))

        command.downgrade(cfg, _PREVIOUS_HEAD)
        downgraded = _inspect(alembic_test_database_url)
        assert _CVE_TABLES.isdisjoint(downgraded["tables"])
        assert "fetcher_run" in downgraded["tables"]

        command.upgrade(cfg, _REVISION)
        _assert_cve_schema(_inspect(alembic_test_database_url))
