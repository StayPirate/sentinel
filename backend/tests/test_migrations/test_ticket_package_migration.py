"""Integration tests for the Ticket package-tree Alembic migration
(backend/alembic/versions/9e4a3d54d5cc_add_ticket_package_and_track_tables.py).

Verifies that upgrading from the previous head creates exactly the
`ticket_package` and `ticket_package_track` tables documented in
`docs/data-model.md` (TicketPackage, TicketPackageTrack): columns, types,
nullability, server defaults (`ANALYSIS` / `PENDING`), primary keys, both
foreign keys with the PostgreSQL default `NO ACTION` (#633 decision A3), both
UNIQUE constraints, the two Category A CHECK constraints accepting exactly the
`PackageStatus` and `DeliveryStatus` values, and `ix_ticket_package_package_name`
as the only standalone index (non-unique, non-partial). Downgrade removes the
tables and re-upgrade restores them.

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

import re
from typing import Any, TypedDict

import pytest
from sqlalchemy import Dialect, inspect
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.types import DateTime, TypeEngine

from alembic import command
from app.config import settings
from app.core.enums import DeliveryStatus, PackageStatus
from tests.test_migrations.conftest import isolated_alembic_config, run_sync

_PREVIOUS_HEAD = "ebb47af19347"
_REVISION = "9e4a3d54d5cc"

_UUID_PK_DEFAULT = "uuidv7()"
_NOW_DEFAULT = "now()"

_TABLES = ("ticket_package", "ticket_package_track")

Column = tuple[str, str, bool, str | None]
# (constrained column, referred table, referred column, ON DELETE option or
# None for the PostgreSQL default NO ACTION)
ForeignKey = tuple[str, str, str, str | None]
# (name, columns, unique, partial predicate or None)
Index = tuple[str, tuple[str, ...], bool, str | None]


class _Expected(TypedDict):
    columns: list[Column]
    foreign_keys: set[ForeignKey]
    unique_constraints: set[tuple[str, tuple[str, ...]]]
    checks: dict[str, set[str]]
    standalone_indexes: set[Index]


_EXPECTED: dict[str, _Expected] = {
    "ticket_package": {
        "columns": [
            ("id", "UUID", False, _UUID_PK_DEFAULT),
            ("ticket_id", "UUID", False, None),
            ("package_name", "VARCHAR(255)", False, None),
            ("deleted_at", "TIMESTAMPTZ", True, None),
            ("created_at", "TIMESTAMPTZ", False, _NOW_DEFAULT),
            ("updated_at", "TIMESTAMPTZ", False, _NOW_DEFAULT),
        ],
        "foreign_keys": {("ticket_id", "ticket", "id", None)},
        "unique_constraints": {
            (
                "uq_ticket_package_ticket_id_package_name",
                ("ticket_id", "package_name"),
            ),
        },
        "checks": {},
        "standalone_indexes": {
            ("ix_ticket_package_package_name", ("package_name",), False, None),
        },
    },
    "ticket_package_track": {
        "columns": [
            ("id", "UUID", False, _UUID_PK_DEFAULT),
            ("ticket_package_id", "UUID", False, None),
            ("workflow_type", "VARCHAR(20)", False, None),
            ("reference", "VARCHAR(255)", False, None),
            ("status", "VARCHAR(20)", False, "'ANALYSIS'::character varying"),
            (
                "delivery_status",
                "VARCHAR(20)",
                False,
                "'PENDING'::character varying",
            ),
            ("deleted_at", "TIMESTAMPTZ", True, None),
            ("created_at", "TIMESTAMPTZ", False, _NOW_DEFAULT),
            ("updated_at", "TIMESTAMPTZ", False, _NOW_DEFAULT),
        ],
        "foreign_keys": {("ticket_package_id", "ticket_package", "id", None)},
        "unique_constraints": {
            (
                "uq_ticket_package_track_ticket_package_id_reference",
                ("ticket_package_id", "reference"),
            ),
        },
        # The migration hardcodes its own literal lists, independently of
        # the model expressions, and `alembic check` does not compare CHECK
        # expressions: assert each accepted value set is exactly the enum.
        "checks": {
            "chk_ticket_package_track_status_valid": {s.value for s in PackageStatus},
            "chk_ticket_package_track_delivery_status_valid": {
                s.value for s in DeliveryStatus
            },
        },
        "standalone_indexes": set(),
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
                            for index in inspector.get_indexes(name)
                            if not index.get("duplicates_constraint")
                        ],
                    }
                return {"tables": tables, "catalog": catalog}

            return await conn.run_sync(_sync_inspect)
    finally:
        await engine.dispose()


def _inspect(database_url: str) -> _SchemaFacts:
    return run_sync(_inspect_schema(database_url))


def _assert_package_tree_schema(facts: _SchemaFacts) -> None:
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
            (constraint["name"], tuple(constraint["column_names"]))
            for constraint in table["unique_constraints"]
        } == expected["unique_constraints"], name

        checks = {check["name"]: check["sqltext"] for check in table["checks"]}
        assert set(checks) == set(expected["checks"]), name
        for check_name, accepted in expected["checks"].items():
            assert set(re.findall(r"'([^']*)'", checks[check_name])) == accepted, (
                check_name
            )

        assert {
            (
                index["name"],
                tuple(index["column_names"]),
                index["unique"],
                index.get("dialect_options", {}).get("postgresql_where"),
            )
            for index in table["standalone_indexes"]
        } == expected["standalone_indexes"], name


@pytest.mark.integration
class TestTicketPackageMigration:
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
        _assert_package_tree_schema(upgraded)
        assert upgraded["tables"] == before["tables"] | set(_TABLES)

        command.downgrade(cfg, _PREVIOUS_HEAD)
        downgraded = _inspect(alembic_test_database_url)
        assert downgraded["catalog"] == {}
        assert downgraded["tables"] == before["tables"]

        command.upgrade(cfg, _REVISION)
        _assert_package_tree_schema(_inspect(alembic_test_database_url))
