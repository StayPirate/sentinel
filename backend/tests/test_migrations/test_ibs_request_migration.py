"""Integration tests for the IBS request and request action Alembic migration
(backend/alembic/versions/5d2a9c7e41b8_add_ibs_request_and_action_tables.py).

Verifies that upgrading from the previous head creates exactly the
`ibs_request` and `ibs_request_action` tables documented in
`docs/data-model.md` (IBSRequest, IBSRequestState Enum, IBSRequestAction,
IBSRequestActionType Enum): columns, types, nullability, server defaults,
primary keys, UNIQUE `request_number`, the `ibs_request_id` foreign key with
`ON DELETE RESTRICT`, the seven named CHECK constraints with their documented
predicates, the two type-specific unique partial identity indexes, and the
non-unique, non-partial `ix_ibs_request_action_ibs_request_id`. Downgrade
removes the tables and re-upgrade restores them.

`alembic check` does not compare CHECK expressions and the model tests run
against `Base.metadata.create_all()`, so the exact CHECK assertions below are
the only guard that the migrated expressions match the documented invariants.

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

_PREVIOUS_HEAD = "3b04d8069b1d"
_REVISION = "5d2a9c7e41b8"

_UUID_PK_DEFAULT = "uuidv7()"
_NOW_DEFAULT = "now()"

_TABLES = ("ibs_request", "ibs_request_action")

Column = tuple[str, str, bool, str | None]
# (constrained column, referred table, referred column, ON DELETE option or
# None for the PostgreSQL default NO ACTION)
ForeignKey = tuple[str, str, str, str | None]
# (name, columns, unique, partial predicate or None)
Index = tuple[str, tuple[str, ...], bool, str | None]


class _Expected(TypedDict):
    columns: list[Column]
    foreign_keys: set[ForeignKey]
    unique_keys: set[tuple[str, ...]]
    # CHECK name -> PostgreSQL's canonical rendering (pretty-printed
    # `pg_get_constraintdef`, as reflected).
    checks: dict[str, str]
    standalone_indexes: set[Index]


_EXPECTED: dict[str, _Expected] = {
    "ibs_request": {
        "columns": [
            ("id", "UUID", False, _UUID_PK_DEFAULT),
            ("request_number", "INTEGER", False, None),
            ("state", "VARCHAR(20)", False, None),
            ("superseded_by_request_number", "INTEGER", True, None),
            ("upstream_created_at", "TIMESTAMPTZ", False, None),
            ("upstream_updated_at", "TIMESTAMPTZ", False, None),
            ("created_at", "TIMESTAMPTZ", False, _NOW_DEFAULT),
            ("updated_at", "TIMESTAMPTZ", False, _NOW_DEFAULT),
        ],
        "foreign_keys": set(),
        "unique_keys": {("request_number",)},
        "checks": {
            "chk_ibs_request_request_number_positive": "request_number > 0",
            "chk_ibs_request_state_valid": (
                "state::text = ANY (ARRAY['new'::character varying, "
                "'review'::character varying, 'accepted'::character varying, "
                "'declined'::character varying, 'revoked'::character varying, "
                "'superseded'::character varying, 'deleted'::character varying]"
                "::text[])"
            ),
            "chk_ibs_request_supersession_coherence": (
                "state::text = 'superseded'::text"
                " AND superseded_by_request_number IS NOT NULL"
                " AND superseded_by_request_number > 0"
                " AND superseded_by_request_number <> request_number"
                " OR state::text <> 'superseded'::text"
                " AND superseded_by_request_number IS NULL"
            ),
        },
        # The UNIQUE `request_number` constraint covers the request-number
        # lookup; no standalone index.
        "standalone_indexes": set(),
    },
    "ibs_request_action": {
        "columns": [
            ("id", "UUID", False, _UUID_PK_DEFAULT),
            ("ibs_request_id", "UUID", False, None),
            ("action_type", "VARCHAR(32)", False, None),
            ("source_project", "VARCHAR(255)", True, None),
            ("source_package", "VARCHAR(255)", True, None),
            ("target_project", "VARCHAR(255)", True, None),
            ("target_package", "VARCHAR(255)", True, None),
            ("target_release_project", "VARCHAR(255)", True, None),
            ("logical_package", "VARCHAR(255)", False, None),
            ("codestream_name", "VARCHAR(255)", False, None),
            ("incident_number", "INTEGER", True, None),
            ("source_revision", "VARCHAR(255)", True, None),
            ("accepted_revision", "VARCHAR(255)", True, None),
            ("accepted_srcmd5", "VARCHAR(32)", True, None),
            ("accepted_xsrcmd5", "VARCHAR(32)", True, None),
            ("created_at", "TIMESTAMPTZ", False, _NOW_DEFAULT),
            ("updated_at", "TIMESTAMPTZ", False, _NOW_DEFAULT),
        ],
        "foreign_keys": {("ibs_request_id", "ibs_request", "id", "RESTRICT")},
        "unique_keys": set(),
        "checks": {
            "chk_ibs_request_action_incident_number_positive": (
                "incident_number IS NULL OR incident_number > 0"
            ),
            "chk_ibs_request_action_type_coherence": (
                "action_type::text = 'maintenance_incident'::text"
                " AND source_project IS NOT NULL"
                " AND source_package IS NOT NULL"
                " AND target_release_project IS NOT NULL"
                " AND codestream_name::text = target_release_project::text"
                " OR action_type::text = 'maintenance_release'::text"
                " AND source_project IS NOT NULL"
                " AND source_package IS NOT NULL"
                " AND target_project IS NOT NULL"
                " AND target_package IS NOT NULL"
                " AND incident_number IS NOT NULL"
                " AND codestream_name::text = target_project::text"
            ),
            "chk_ibs_request_action_accepted_srcmd5_hex": (
                "accepted_srcmd5 IS NULL"
                " OR accepted_srcmd5::text ~ '^[0-9a-f]{32}$'::text"
            ),
            "chk_ibs_request_action_accepted_xsrcmd5_hex": (
                "accepted_xsrcmd5 IS NULL"
                " OR accepted_xsrcmd5::text ~ '^[0-9a-f]{32}$'::text"
            ),
        },
        "standalone_indexes": {
            (
                "uq_ibs_request_action_maintenance_incident_identity",
                (
                    "ibs_request_id",
                    "source_project",
                    "source_package",
                    "target_release_project",
                ),
                True,
                "((action_type)::text = 'maintenance_incident'::text)",
            ),
            (
                "uq_ibs_request_action_maintenance_release_identity",
                ("ibs_request_id", "target_project", "target_package"),
                True,
                "((action_type)::text = 'maintenance_release'::text)",
            ),
            ("ix_ibs_request_action_ibs_request_id", ("ibs_request_id",), False, None),
        },
    },
}


class _TableFacts(TypedDict):
    columns: list[Column]
    primary_key: list[str]
    foreign_keys: list[dict[str, Any]]
    unique_constraints: list[dict[str, Any]]
    checks: list[dict[str, Any]]
    standalone_indexes: list[dict[str, Any]]
    index_methods: dict[str, str]


class _SchemaFacts(TypedDict):
    tables: set[str]
    catalog: dict[str, _TableFacts]


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
                catalog: dict[str, _TableFacts] = {}
                for name in _TABLES:
                    if name not in tables:
                        continue
                    indexes = inspector.get_indexes(name)
                    catalog[name] = {
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
                        # Indexes backing a unique constraint are reported
                        # with `duplicates_constraint`; anything else is a
                        # standalone index.
                        "standalone_indexes": [
                            index
                            for index in indexes
                            if not index.get("duplicates_constraint")
                        ],
                        "index_methods": {
                            index["name"]: index.get("dialect_options", {}).get(
                                "postgresql_using", "btree"
                            )
                            for index in indexes
                        },
                    }
                return {"tables": tables, "catalog": catalog}

            return await conn.run_sync(_sync_inspect)
    finally:
        await engine.dispose()


def _inspect(database_url: str) -> _SchemaFacts:
    return run_sync(_inspect_schema(database_url))


def _assert_schema(facts: _SchemaFacts) -> None:
    assert set(facts["catalog"]) == set(_TABLES)
    for name, expected in _EXPECTED.items():
        table = facts["catalog"][name]

        assert table["columns"] == expected["columns"], name
        assert table["primary_key"] == ["id"], name

        foreign_keys: set[ForeignKey] = set()
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
        assert foreign_keys == expected["foreign_keys"], name

        assert {
            tuple(constraint["column_names"])
            for constraint in table["unique_constraints"]
        } == expected["unique_keys"], name

        assert {
            check["name"]: check["sqltext"] for check in table["checks"]
        } == expected["checks"], name

        assert {
            (
                index["name"],
                tuple(index["column_names"]),
                index["unique"],
                index.get("dialect_options", {}).get("postgresql_where"),
            )
            for index in table["standalone_indexes"]
        } == expected["standalone_indexes"], name
        assert set(table["index_methods"].values()) <= {"btree"}, name


@pytest.mark.integration
class TestIBSRequestMigration:
    def test_upgrade_downgrade_reupgrade_cycle(
        self,
        alembic_test_database_url: str,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(settings, "database_url", alembic_test_database_url)
        cfg = isolated_alembic_config()

        command.upgrade(cfg, _PREVIOUS_HEAD)
        before = _inspect(alembic_test_database_url)
        assert before["catalog"] == {}

        command.upgrade(cfg, _REVISION)
        upgraded = _inspect(alembic_test_database_url)
        _assert_schema(upgraded)
        assert upgraded["tables"] == before["tables"] | set(_TABLES)

        command.downgrade(cfg, _PREVIOUS_HEAD)
        downgraded = _inspect(alembic_test_database_url)
        assert downgraded["catalog"] == {}
        assert downgraded["tables"] == before["tables"]

        command.upgrade(cfg, _REVISION)
        _assert_schema(_inspect(alembic_test_database_url))
