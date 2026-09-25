"""Integration tests for the Ticket satellite Alembic migration
(backend/alembic/versions/702b657813b7_add_ticket_satellite_tables.py).

Verifies that upgrading from the previous head creates exactly the
`ticket_audit_event`, `ticket_access_grant`, and `ticket_reference` tables
documented in `docs/data-model.md` (TicketAuditEvent, TicketAccessGrant,
TicketReference) and `docs/features/platform/audit-trail-infrastructure.md`
(AuditEventMixin, Indexing): columns, types, nullability, server defaults,
primary keys (including the composite grant key), foreign keys with their
documented delete rules (`RESTRICT`, `CASCADE`, or the PostgreSQL default
`NO ACTION` where none is documented, #611 decision A4), the reference
UNIQUE key, and exactly the documented indexes with no CHECK constraint
(#611 decision A3). Downgrade removes the tables and re-upgrade restores
them.

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

_PREVIOUS_HEAD = "b080b1c3810c"
_REVISION = "702b657813b7"

_UUID_PK_DEFAULT = "uuidv7()"
_NOW_DEFAULT = "now()"

_TABLES = ("ticket_audit_event", "ticket_access_grant", "ticket_reference")

Column = tuple[str, str, bool, str | None]
# (constrained column, referred table, referred column, ON DELETE option or
# None for the PostgreSQL default NO ACTION)
ForeignKey = tuple[str, str, str, str | None]


class _Expected(TypedDict):
    columns: list[Column]
    primary_key: list[str]
    foreign_keys: set[ForeignKey]
    unique_constraints: set[tuple[str, tuple[str, ...]]]
    indexes: set[tuple[str, tuple[str, ...]]]


_EXPECTED: dict[str, _Expected] = {
    "ticket_audit_event": {
        # Mixin columns first, then the domain columns.
        "columns": [
            ("id", "UUID", False, _UUID_PK_DEFAULT),
            ("created_at", "TIMESTAMPTZ", False, _NOW_DEFAULT),
            ("user_id", "UUID", True, None),
            ("ticket_id", "UUID", False, None),
            ("event_type", "VARCHAR(50)", False, None),
            ("old_value", "TEXT", True, None),
            ("new_value", "TEXT", True, None),
            ("comment", "TEXT", True, None),
            ("detail", "JSONB", True, None),
        ],
        "primary_key": ["id"],
        "foreign_keys": {
            ("ticket_id", "ticket", "id", None),
            ("user_id", "user", "id", "RESTRICT"),
        },
        "unique_constraints": set(),
        "indexes": {
            ("ix_ticket_audit_event_ticket_id", ("ticket_id",)),
            ("ix_ticket_audit_event_created_at", ("created_at",)),
            ("ix_ticket_audit_event_user_id", ("user_id",)),
        },
    },
    "ticket_access_grant": {
        "columns": [
            ("ticket_id", "UUID", False, None),
            ("user_id", "UUID", False, None),
            ("granted_by_id", "UUID", False, None),
            ("granted_at", "TIMESTAMPTZ", False, _NOW_DEFAULT),
        ],
        "primary_key": ["ticket_id", "user_id"],
        "foreign_keys": {
            ("ticket_id", "ticket", "id", "RESTRICT"),
            ("user_id", "user", "id", "RESTRICT"),
            ("granted_by_id", "user", "id", "RESTRICT"),
        },
        "unique_constraints": set(),
        "indexes": set(),
    },
    "ticket_reference": {
        "columns": [
            ("id", "UUID", False, _UUID_PK_DEFAULT),
            ("ticket_id", "UUID", False, None),
            ("url", "VARCHAR(2048)", False, None),
            ("title", "VARCHAR(500)", True, None),
            ("description", "VARCHAR(2000)", True, None),
            ("type", "VARCHAR(20)", True, None),
            ("source", "VARCHAR(100)", False, None),
            ("created_at", "TIMESTAMPTZ", False, _NOW_DEFAULT),
            ("updated_at", "TIMESTAMPTZ", False, _NOW_DEFAULT),
        ],
        "primary_key": ["id"],
        "foreign_keys": {("ticket_id", "ticket", "id", "CASCADE")},
        "unique_constraints": {
            ("uq_ticket_reference_ticket_id_url", ("ticket_id", "url")),
        },
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
    satellites: dict[str, _TableFacts]


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
                satellites: dict[str, _TableFacts] = {}
                for name in _TABLES:
                    if name not in tables:
                        continue
                    satellites[name] = {
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
                return {"tables": tables, "satellites": satellites}

            return await conn.run_sync(_sync_inspect)
    finally:
        await engine.dispose()


def _inspect(database_url: str) -> _SchemaFacts:
    return run_sync(_inspect_schema(database_url))


def _assert_satellite_schema(facts: _SchemaFacts) -> None:
    assert set(facts["satellites"]) == set(_TABLES)
    for name, expected in _EXPECTED.items():
        table = facts["satellites"][name]

        assert table["columns"] == expected["columns"], name
        assert table["primary_key"] == expected["primary_key"], name

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

        # No CHECK constraint is documented for any satellite table: every
        # enumerated column is Category B.
        assert table["checks"] == [], name

        assert {
            (index["name"], tuple(index["column_names"]))
            for index in table["standalone_indexes"]
        } == expected["indexes"], name
        for index in table["standalone_indexes"]:
            assert index["unique"] is False, index
            assert "postgresql_where" not in index["dialect_options"], index


@pytest.mark.integration
class TestTicketSatelliteMigration:
    def test_upgrade_downgrade_reupgrade_cycle(
        self,
        alembic_test_database_url: str,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(settings, "database_url", alembic_test_database_url)
        cfg = isolated_alembic_config()

        command.upgrade(cfg, _PREVIOUS_HEAD)
        before = _inspect(alembic_test_database_url)
        assert before["satellites"] == {}
        assert {"ticket", "user"} <= before["tables"]

        command.upgrade(cfg, _REVISION)
        _assert_satellite_schema(_inspect(alembic_test_database_url))

        command.downgrade(cfg, _PREVIOUS_HEAD)
        downgraded = _inspect(alembic_test_database_url)
        assert downgraded["satellites"] == {}
        assert downgraded["tables"] == before["tables"]

        command.upgrade(cfg, _REVISION)
        _assert_satellite_schema(_inspect(alembic_test_database_url))
