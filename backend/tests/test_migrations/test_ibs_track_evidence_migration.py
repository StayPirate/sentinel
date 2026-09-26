"""Integration tests for the IBS track evidence Alembic migration
(backend/alembic/versions/
fe641477a7c6_add_track_release_checkpoint_and_action_track_tables.py).

Verifies that upgrading from the previous head creates exactly the
`track_release_checkpoint` and `ibs_request_action_track` tables documented
in `docs/data-model.md` (TrackReleaseCheckpoint, IBSRequestActionTrack):
columns, types, nullability, server defaults (`last_seen_at` and
`created_at` default to `now()`), primary keys, every foreign key with
`ON DELETE RESTRICT`, the UNIQUE `ticket_package_track_id` of the checkpoint,
the track-leading UNIQUE `(ticket_package_track_id, ibs_request_action_id)`,
no CHECK constraint (#633 decision A2), and the non-unique, non-partial
`ix_ibs_request_action_track_ibs_request_action_id` as the only standalone
index. Downgrade removes the tables and re-upgrade restores them.

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

_PREVIOUS_HEAD = "5d2a9c7e41b8"
_REVISION = "fe641477a7c6"

_UUID_PK_DEFAULT = "uuidv7()"
_NOW_DEFAULT = "now()"

_TABLES = ("track_release_checkpoint", "ibs_request_action_track")

Column = tuple[str, str, bool, str | None]
# (constrained column, referred table, referred column, ON DELETE option)
ForeignKey = tuple[str, str, str, str | None]
# (name, ordered columns)
UniqueKey = tuple[str, tuple[str, ...]]
# (name, columns, unique, partial predicate or None)
Index = tuple[str, tuple[str, ...], bool, str | None]


class _Expected(TypedDict):
    columns: list[Column]
    foreign_keys: set[ForeignKey]
    unique_keys: set[UniqueKey]
    standalone_indexes: set[Index]


_EXPECTED: dict[str, _Expected] = {
    "track_release_checkpoint": {
        "columns": [
            ("id", "UUID", False, _UUID_PK_DEFAULT),
            ("ticket_package_track_id", "UUID", False, None),
            ("srcmd5", "VARCHAR(32)", False, None),
            ("last_seen_at", "TIMESTAMPTZ", False, _NOW_DEFAULT),
        ],
        "foreign_keys": {
            ("ticket_package_track_id", "ticket_package_track", "id", "RESTRICT")
        },
        "unique_keys": {
            (
                "track_release_checkpoint_ticket_package_track_id_key",
                ("ticket_package_track_id",),
            )
        },
        # UNIQUE `ticket_package_track_id` covers the track-keyed lookup.
        "standalone_indexes": set(),
    },
    "ibs_request_action_track": {
        "columns": [
            ("id", "UUID", False, _UUID_PK_DEFAULT),
            ("ibs_request_action_id", "UUID", False, None),
            ("ticket_package_track_id", "UUID", False, None),
            ("created_at", "TIMESTAMPTZ", False, _NOW_DEFAULT),
        ],
        "foreign_keys": {
            ("ibs_request_action_id", "ibs_request_action", "id", "RESTRICT"),
            ("ticket_package_track_id", "ticket_package_track", "id", "RESTRICT"),
        },
        "unique_keys": {
            (
                "uq_ibs_request_action_track_track_id_action_id",
                ("ticket_package_track_id", "ibs_request_action_id"),
            )
        },
        "standalone_indexes": {
            (
                "ix_ibs_request_action_track_ibs_request_action_id",
                ("ibs_request_action_id",),
                False,
                None,
            )
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
            (constraint["name"], tuple(constraint["column_names"]))
            for constraint in table["unique_constraints"]
        } == expected["unique_keys"], name

        assert table["checks"] == [], name

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
class TestIBSTrackEvidenceMigration:
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
