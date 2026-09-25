"""Integration tests for the Ticket core Alembic migration
(backend/alembic/versions/b080b1c3810c_add_ticket_table.py).

Verifies that upgrading from the previous head creates exactly the
`ticket` table documented in `docs/data-model.md` (Ticket, TicketStatus
Enum, TicketPriority Enum): columns, types, nullability, server defaults,
the `sequence_id` identity, foreign keys with the PostgreSQL default
`NO ACTION` delete rule (#611 decision A4), the unique keys, exactly the
four named CHECK constraints, and exactly the partial
`ix_ticket_duplicate_of_id` index with its `WHERE` predicate (#611
decision A3). Downgrade removes the table and re-upgrade restores it.

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
from app.core.enums import TicketStatus
from tests.test_migrations.conftest import isolated_alembic_config, run_sync

_PREVIOUS_HEAD = "292b30ba95cb"
_REVISION = "b080b1c3810c"

_UUID_PK_DEFAULT = "uuidv7()"
_NOW_DEFAULT = "now()"

# Expected columns: name -> (type, nullable, server default). The identity
# column reports no server default; its identity is asserted separately.
# Order is the model/migration column order.
_EXPECTED_COLUMNS: list[tuple[str, str, bool, str | None]] = [
    ("id", "UUID", False, _UUID_PK_DEFAULT),
    ("sequence_id", "INTEGER", False, None),
    ("cve_id", "UUID", True, None),
    ("status", "VARCHAR(20)", False, "'New'::character varying"),
    ("severity_manual", "VARCHAR(20)", True, None),
    ("priority_auto", "VARCHAR(10)", True, None),
    ("priority_override", "VARCHAR(10)", True, None),
    ("assignee_id", "UUID", True, None),
    ("duplicate_of_id", "UUID", True, None),
    ("created_at", "TIMESTAMPTZ", False, _NOW_DEFAULT),
    ("updated_at", "TIMESTAMPTZ", False, _NOW_DEFAULT),
    ("is_confidential", "BOOLEAN", False, "false"),
    ("coordinated_release_at", "TIMESTAMPTZ", True, None),
]

_EXPECTED_UNIQUE_KEYS = {("sequence_id",), ("cve_id",)}

_EXPECTED_FOREIGN_KEYS = {
    ("cve_id", "cve", "id"),
    ("assignee_id", "user", "id"),
    ("duplicate_of_id", "ticket", "id"),
}

_EXPECTED_CHECKS = {
    "chk_ticket_status_valid",
    "chk_ticket_duplicate_status_coherence",
    "chk_ticket_no_self_duplicate",
    "chk_ticket_severity_manual_cve_exclusive",
}

# PostgreSQL's canonical rendering (pretty-printed `pg_get_constraintdef`,
# as reflected) of the three documented structural CHECKs in
# docs/data-model.md (Ticket). `alembic check` does not compare CHECK
# expressions and the model tests run against `Base.metadata.create_all()`,
# so this is the only guard that the migrated expressions match the
# documented invariants.
_EXPECTED_STRUCTURAL_CHECK_SQL = {
    "chk_ticket_duplicate_status_coherence": (
        "status::text = 'Duplicated'::text AND duplicate_of_id IS NOT NULL"
        " OR status::text <> 'Duplicated'::text AND duplicate_of_id IS NULL"
    ),
    "chk_ticket_no_self_duplicate": "duplicate_of_id <> id",
    "chk_ticket_severity_manual_cve_exclusive": (
        "severity_manual IS NULL OR cve_id IS NULL"
    ),
}


class _TicketFacts(TypedDict):
    columns: list[tuple[str, str, bool, str | None]]
    identities: dict[str, dict[str, Any]]
    primary_key: list[str]
    foreign_keys: list[dict[str, Any]]
    unique_constraints: list[dict[str, Any]]
    checks: list[dict[str, Any]]
    standalone_indexes: list[dict[str, Any]]


class _SchemaFacts(TypedDict):
    tables: set[str]
    ticket: _TicketFacts | None


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
                if "ticket" not in tables:
                    return {"tables": tables, "ticket": None}
                columns = inspector.get_columns("ticket")
                return {
                    "tables": tables,
                    "ticket": {
                        "columns": [
                            (
                                column["name"],
                                _describe_type(column["type"], sync_conn.dialect),
                                column["nullable"],
                                column["default"],
                            )
                            for column in columns
                        ],
                        "identities": {
                            column["name"]: dict(column["identity"])
                            for column in columns
                            if column.get("identity")
                        },
                        "primary_key": inspector.get_pk_constraint("ticket")[
                            "constrained_columns"
                        ],
                        "foreign_keys": inspector.get_foreign_keys("ticket"),
                        "unique_constraints": inspector.get_unique_constraints(
                            "ticket"
                        ),
                        "checks": inspector.get_check_constraints("ticket"),
                        # Indexes backing a unique constraint are reported
                        # with `duplicates_constraint`; anything else is a
                        # standalone index.
                        "standalone_indexes": [
                            index
                            for index in inspector.get_indexes("ticket")
                            if not index.get("duplicates_constraint")
                        ],
                    },
                }

            return await conn.run_sync(_sync_inspect)
    finally:
        await engine.dispose()


def _inspect(database_url: str) -> _SchemaFacts:
    return run_sync(_inspect_schema(database_url))


def _assert_ticket_schema(facts: _SchemaFacts) -> None:
    ticket = facts["ticket"]
    assert ticket is not None

    assert ticket["columns"] == _EXPECTED_COLUMNS
    assert ticket["primary_key"] == ["id"]

    assert set(ticket["identities"]) == {"sequence_id"}
    identity = ticket["identities"]["sequence_id"]
    assert identity["always"] is False
    assert identity["start"] == 1
    assert identity["increment"] == 1

    assert {
        tuple(constraint["column_names"]) for constraint in ticket["unique_constraints"]
    } == _EXPECTED_UNIQUE_KEYS

    assert {
        (
            foreign_key["constrained_columns"][0],
            foreign_key["referred_table"],
            foreign_key["referred_columns"][0],
        )
        for foreign_key in ticket["foreign_keys"]
    } == _EXPECTED_FOREIGN_KEYS
    for foreign_key in ticket["foreign_keys"]:
        assert len(foreign_key["constrained_columns"]) == 1
        # No ON DELETE clause: PostgreSQL default NO ACTION (#611 A4).
        assert "ondelete" not in foreign_key["options"], foreign_key

    checks = {check["name"]: check["sqltext"] for check in ticket["checks"]}
    assert set(checks) == _EXPECTED_CHECKS
    for name, expected_sql in _EXPECTED_STRUCTURAL_CHECK_SQL.items():
        assert checks[name] == expected_sql, name

    # The migration hardcodes its own literal list, independently of the
    # model expression, and `alembic check` does not compare CHECK
    # expressions: assert the accepted value set is exactly `TicketStatus`.
    accepted_statuses = set(re.findall(r"'([^']*)'", checks["chk_ticket_status_valid"]))
    assert accepted_statuses == {status.value for status in TicketStatus}

    (index,) = ticket["standalone_indexes"]
    assert index["name"] == "ix_ticket_duplicate_of_id"
    assert index["column_names"] == ["duplicate_of_id"]
    assert index["unique"] is False
    assert index["dialect_options"]["postgresql_where"] == (
        "(duplicate_of_id IS NOT NULL)"
    )


@pytest.mark.integration
class TestTicketCoreMigration:
    def test_upgrade_downgrade_reupgrade_cycle(
        self,
        alembic_test_database_url: str,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(settings, "database_url", alembic_test_database_url)
        cfg = isolated_alembic_config()

        command.upgrade(cfg, _PREVIOUS_HEAD)
        assert "ticket" not in _inspect(alembic_test_database_url)["tables"]

        command.upgrade(cfg, _REVISION)
        _assert_ticket_schema(_inspect(alembic_test_database_url))

        command.downgrade(cfg, _PREVIOUS_HEAD)
        downgraded = _inspect(alembic_test_database_url)
        assert "ticket" not in downgraded["tables"]
        assert {"cve", "user"} <= downgraded["tables"]

        command.upgrade(cfg, _REVISION)
        _assert_ticket_schema(_inspect(alembic_test_database_url))
