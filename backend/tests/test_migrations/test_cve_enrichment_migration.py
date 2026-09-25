"""Integration tests for the CVE enrichment Alembic migration
(backend/alembic/versions/e7c553292d65_add_cve_enrichment_child_tables.py).

Verifies that upgrading from the previous head creates exactly the
`cve_affected_version`, `cve_cwe`, `cve_ssvc_assessment`, `cve_kev_entry`,
and `cve_epss_score` tables documented in `docs/data-model.md`
(CVEAffectedVersion, CVECWE, CVESSVCAssessment, CVEKEVEntry, CVEEPSSScore):
columns, types, nullability, server defaults, primary keys, the
`cve.id` foreign keys with `ON DELETE CASCADE`, the documented unique keys,
and exactly the documented indexes with no CHECK constraint (#611 decision
A3). `cve_affected_version` has no unique constraint or unique index over
its entry columns; its only index is the non-unique
`(cve_id, source_container)` scope index. The migration also adds the
non-unique `ix_cve_external_identifier_cve_id` index to the existing
`cve_external_identifier` table. Downgrade removes the tables and that
index, and re-upgrade restores them.

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

_PREVIOUS_HEAD = "702b657813b7"
_REVISION = "e7c553292d65"

_UUID_PK_DEFAULT = "uuidv7()"
_NOW_DEFAULT = "now()"

_TABLES = (
    "cve_affected_version",
    "cve_cwe",
    "cve_ssvc_assessment",
    "cve_kev_entry",
    "cve_epss_score",
)
_EXTERNAL_IDENTIFIER_INDEX = ("ix_cve_external_identifier_cve_id", ("cve_id",))

Column = tuple[str, str, bool, str | None]

_CASCADE_TO_CVE = {("cve_id", "cve", "id", "CASCADE")}


class _Expected(TypedDict):
    columns: list[Column]
    unique_constraints: set[tuple[str, tuple[str, ...]]]
    indexes: set[tuple[str, tuple[str, ...]]]


def _timestamps() -> list[Column]:
    return [
        ("created_at", "TIMESTAMPTZ", False, _NOW_DEFAULT),
        ("updated_at", "TIMESTAMPTZ", False, _NOW_DEFAULT),
    ]


_EXPECTED: dict[str, _Expected] = {
    "cve_affected_version": {
        "columns": [
            ("id", "UUID", False, _UUID_PK_DEFAULT),
            ("cve_id", "UUID", False, None),
            ("source_container", "VARCHAR(100)", False, None),
            ("vendor", "TEXT", True, None),
            ("product", "TEXT", True, None),
            ("package_url", "TEXT", True, None),
            ("collection_url", "TEXT", True, None),
            ("package_name", "TEXT", True, None),
            ("repo", "TEXT", True, None),
            ("version", "TEXT", True, None),
            ("version_type", "TEXT", True, None),
            ("version_end", "TEXT", True, None),
            ("version_end_inclusive", "BOOLEAN", True, None),
            ("program_files", "JSONB", True, None),
            ("cpe", "TEXT", True, None),
            ("ecosystem", "VARCHAR(50)", True, None),
            ("status", "VARCHAR(20)", True, None),
            ("default_status", "VARCHAR(20)", True, None),
            # `created_at` only (docs/data-model.md, Notes).
            ("created_at", "TIMESTAMPTZ", False, _NOW_DEFAULT),
        ],
        # No database entry uniqueness (docs/data-model.md, CVEAffectedVersion).
        "unique_constraints": set(),
        "indexes": {
            (
                "ix_cve_affected_version_cve_id_source_container",
                ("cve_id", "source_container"),
            ),
        },
    },
    "cve_cwe": {
        "columns": [
            ("id", "UUID", False, _UUID_PK_DEFAULT),
            ("cve_id", "UUID", False, None),
            ("cwe_id", "VARCHAR(20)", False, None),
            ("source", "VARCHAR(100)", False, None),
            *_timestamps(),
        ],
        "unique_constraints": {
            ("uq_cve_cwe_cve_id_cwe_id_source", ("cve_id", "cwe_id", "source")),
        },
        "indexes": set(),
    },
    "cve_ssvc_assessment": {
        "columns": [
            ("id", "UUID", False, _UUID_PK_DEFAULT),
            ("cve_id", "UUID", False, None),
            ("exploitation", "VARCHAR(20)", False, None),
            ("automatable", "VARCHAR(10)", False, None),
            ("technical_impact", "VARCHAR(20)", False, None),
            ("version", "VARCHAR(10)", False, None),
            ("assessed_at", "TIMESTAMPTZ", True, None),
            *_timestamps(),
        ],
        "unique_constraints": {("cve_ssvc_assessment_cve_id_key", ("cve_id",))},
        "indexes": set(),
    },
    "cve_kev_entry": {
        "columns": [
            ("id", "UUID", False, _UUID_PK_DEFAULT),
            ("cve_id", "UUID", False, None),
            ("date_added", "DATE", False, None),
            ("reference_url", "TEXT", True, None),
            *_timestamps(),
        ],
        "unique_constraints": {("cve_kev_entry_cve_id_key", ("cve_id",))},
        "indexes": set(),
    },
    "cve_epss_score": {
        "columns": [
            ("id", "UUID", False, _UUID_PK_DEFAULT),
            ("cve_id", "UUID", False, None),
            ("score", "DOUBLE PRECISION", False, None),
            ("percentile", "DOUBLE PRECISION", False, None),
            ("assessed_at", "DATE", False, None),
            *_timestamps(),
        ],
        "unique_constraints": {("cve_epss_score_cve_id_key", ("cve_id",))},
        "indexes": set(),
    },
}


class _TableFacts(TypedDict):
    columns: list[Column]
    primary_key: list[str]
    foreign_keys: list[dict[str, Any]]
    unique_constraints: list[dict[str, Any]]
    checks: list[dict[str, Any]]
    standalone_indexes: list[dict[str, Any]]


class _SchemaFacts(TypedDict):
    tables: set[str]
    enrichment: dict[str, _TableFacts]
    external_identifier_indexes: list[dict[str, Any]]


def _describe_type(column_type: TypeEngine[Any], dialect: Dialect) -> str:
    """Render a reflected column type; `TIMESTAMPTZ` distinguishes a
    timezone-aware timestamp from a bare `TIMESTAMP`."""
    if isinstance(column_type, DateTime):
        return "TIMESTAMPTZ" if column_type.timezone else "TIMESTAMP"
    return str(column_type.compile(dialect=dialect))


def _standalone_indexes(inspector: Any, table: str) -> list[dict[str, Any]]:
    """Indexes backing a unique constraint are reported with
    `duplicates_constraint`; anything else is a standalone index."""
    return [
        index
        for index in inspector.get_indexes(table)
        if not index.get("duplicates_constraint")
    ]


async def _inspect_schema(database_url: str) -> _SchemaFacts:
    engine = create_async_engine(database_url)
    try:
        async with engine.connect() as conn:

            def _sync_inspect(sync_conn: Any) -> _SchemaFacts:
                inspector = inspect(sync_conn)
                tables = set(inspector.get_table_names())
                enrichment: dict[str, _TableFacts] = {}
                for name in _TABLES:
                    if name not in tables:
                        continue
                    enrichment[name] = {
                        "columns": [
                            (
                                column["name"],
                                _describe_type(column["type"], sync_conn.dialect),
                                column["nullable"],
                                column["default"],
                            )
                            for column in inspector.get_columns(name)
                        ],
                        "primary_key": inspector.get_pk_constraint(name)[
                            "constrained_columns"
                        ],
                        "foreign_keys": inspector.get_foreign_keys(name),
                        "unique_constraints": inspector.get_unique_constraints(name),
                        "checks": inspector.get_check_constraints(name),
                        "standalone_indexes": _standalone_indexes(inspector, name),
                    }
                return {
                    "tables": tables,
                    "enrichment": enrichment,
                    "external_identifier_indexes": _standalone_indexes(
                        inspector, "cve_external_identifier"
                    ),
                }

            return await conn.run_sync(_sync_inspect)
    finally:
        await engine.dispose()


def _inspect(database_url: str) -> _SchemaFacts:
    return run_sync(_inspect_schema(database_url))


def _index_set(indexes: list[dict[str, Any]]) -> set[tuple[str, tuple[str, ...]]]:
    return {(index["name"], tuple(index["column_names"])) for index in indexes}


def _assert_non_unique_full_indexes(indexes: list[dict[str, Any]]) -> None:
    for index in indexes:
        assert index["unique"] is False, index
        assert "postgresql_where" not in index["dialect_options"], index


def _assert_upgraded_schema(facts: _SchemaFacts) -> None:
    assert set(facts["enrichment"]) == set(_TABLES)
    for name, expected in _EXPECTED.items():
        table = facts["enrichment"][name]

        assert table["columns"] == expected["columns"], name
        assert table["primary_key"] == ["id"], name

        foreign_keys = set()
        for foreign_key in table["foreign_keys"]:
            assert len(foreign_key["constrained_columns"]) == 1, foreign_key
            foreign_keys.add(
                (
                    foreign_key["constrained_columns"][0],
                    foreign_key["referred_table"],
                    foreign_key["referred_columns"][0],
                    foreign_key["options"].get("ondelete"),
                )
            )
        assert foreign_keys == _CASCADE_TO_CVE, name

        assert {
            (constraint["name"], tuple(constraint["column_names"]))
            for constraint in table["unique_constraints"]
        } == expected["unique_constraints"], name

        # No CHECK constraint is documented for any enrichment table.
        assert table["checks"] == [], name

        assert _index_set(table["standalone_indexes"]) == expected["indexes"], name
        _assert_non_unique_full_indexes(table["standalone_indexes"])

    assert _index_set(facts["external_identifier_indexes"]) == {
        _EXTERNAL_IDENTIFIER_INDEX
    }
    _assert_non_unique_full_indexes(facts["external_identifier_indexes"])


def _assert_previous_head_schema(facts: _SchemaFacts) -> None:
    assert facts["enrichment"] == {}
    assert {"cve", "cve_external_identifier"} <= facts["tables"]
    assert facts["external_identifier_indexes"] == []


@pytest.mark.integration
class TestCVEEnrichmentMigration:
    def test_upgrade_downgrade_reupgrade_cycle(
        self,
        alembic_test_database_url: str,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(settings, "database_url", alembic_test_database_url)
        cfg = isolated_alembic_config()

        command.upgrade(cfg, _PREVIOUS_HEAD)
        before = _inspect(alembic_test_database_url)
        _assert_previous_head_schema(before)

        command.upgrade(cfg, _REVISION)
        _assert_upgraded_schema(_inspect(alembic_test_database_url))

        command.downgrade(cfg, _PREVIOUS_HEAD)
        downgraded = _inspect(alembic_test_database_url)
        _assert_previous_head_schema(downgraded)
        assert downgraded["tables"] == before["tables"]

        command.upgrade(cfg, _REVISION)
        _assert_upgraded_schema(_inspect(alembic_test_database_url))
