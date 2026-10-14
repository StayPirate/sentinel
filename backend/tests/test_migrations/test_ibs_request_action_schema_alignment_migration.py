"""Integration tests for the IBS request action schema alignment Alembic
migration (backend/alembic/versions/
6636db334eb1_align_ibs_request_action_with_retained_.py).

Verifies that upgrading from the previous head aligns `ibs_request_action`
with `docs/data-model.md` (IBSRequestAction): `source_revision`,
`accepted_xsrcmd5`, and `chk_ibs_request_action_accepted_xsrcmd5_hex` are
dropped (user decision C1 on #942), and the non-unique, non-partial
`ix_ibs_request_action_logical_package_codestream_name` B-tree index on
`(logical_package, codestream_name)` is added. Every other column, the
foreign key, the remaining CHECK predicates, and the existing indexes are
unchanged, and an existing row survives with its remaining values. Downgrade
restores the previous shape (both nullable columns with their types, the
CHECK with its predicate, no new index) and re-upgrade succeeds.

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

import uuid
from typing import Any, TypedDict

import pytest
from sqlalchemy import Dialect, inspect, text
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.types import DateTime, TypeEngine

from alembic import command
from app.config import settings
from tests.test_migrations.conftest import isolated_alembic_config, run_sync

_PREVIOUS_HEAD = "fe641477a7c6"
_REVISION = "6636db334eb1"

_TABLE = "ibs_request_action"
_UUID_PK_DEFAULT = "uuidv7()"
_NOW_DEFAULT = "now()"

Column = tuple[str, str, bool, str | None]
# (name, columns, unique, partial predicate or None)
Index = tuple[str, tuple[str, ...], bool, str | None]

_DROPPED_COLUMNS: list[Column] = [
    ("source_revision", "VARCHAR(255)", True, None),
    ("accepted_xsrcmd5", "VARCHAR(32)", True, None),
]

_KEPT_COLUMNS: list[Column] = [
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
    ("accepted_revision", "VARCHAR(255)", True, None),
    ("accepted_srcmd5", "VARCHAR(32)", True, None),
    ("created_at", "TIMESTAMPTZ", False, _NOW_DEFAULT),
    ("updated_at", "TIMESTAMPTZ", False, _NOW_DEFAULT),
]

_XSRCMD5_CHECK = "chk_ibs_request_action_accepted_xsrcmd5_hex"

# CHECK name -> PostgreSQL's canonical rendering (pretty-printed
# `pg_get_constraintdef`, as reflected).
_KEPT_CHECKS = {
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
        "accepted_srcmd5 IS NULL OR accepted_srcmd5::text ~ '^[0-9a-f]{32}$'::text"
    ),
}
_DROPPED_CHECK = {
    _XSRCMD5_CHECK: (
        "accepted_xsrcmd5 IS NULL OR accepted_xsrcmd5::text ~ '^[0-9a-f]{32}$'::text"
    )
}

_KEPT_INDEXES: set[Index] = {
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
}
_NEW_INDEX: Index = (
    "ix_ibs_request_action_logical_package_codestream_name",
    ("logical_package", "codestream_name"),
    False,
    None,
)

_FOREIGN_KEY = ("ibs_request_id", "ibs_request", "id", "RESTRICT")

_CODESTREAM = "Example:Codestream:One:Update"
_CHECKSUM = "0123456789abcdef0123456789abcdef"


class _TableFacts(TypedDict):
    columns: list[Column]
    primary_key: list[str]
    foreign_keys: set[tuple[str, str, str, str | None]]
    unique_constraints: list[dict[str, Any]]
    checks: dict[str, str]
    standalone_indexes: set[Index]
    index_methods: set[str]


def _describe_type(column_type: TypeEngine[Any], dialect: Dialect) -> str:
    """Render a reflected column type; `TIMESTAMPTZ` distinguishes a
    timezone-aware timestamp from a bare `TIMESTAMP`."""
    if isinstance(column_type, DateTime):
        return "TIMESTAMPTZ" if column_type.timezone else "TIMESTAMP"
    return str(column_type.compile(dialect=dialect))


async def _inspect_table(database_url: str) -> _TableFacts:
    engine = create_async_engine(database_url)
    try:
        async with engine.connect() as conn:

            def _sync_inspect(sync_conn: Any) -> _TableFacts:
                inspector = inspect(sync_conn)
                indexes = inspector.get_indexes(_TABLE)
                return {
                    "columns": [
                        (
                            column["name"],
                            _describe_type(column["type"], sync_conn.dialect),
                            column["nullable"],
                            column["default"],
                        )
                        for column in inspector.get_columns(_TABLE)
                    ],
                    "primary_key": inspector.get_pk_constraint(_TABLE)[
                        "constrained_columns"
                    ],
                    "foreign_keys": {
                        (
                            foreign_key["constrained_columns"][0],
                            foreign_key["referred_table"],
                            foreign_key["referred_columns"][0],
                            foreign_key["options"].get("ondelete"),
                        )
                        for foreign_key in inspector.get_foreign_keys(_TABLE)
                    },
                    "unique_constraints": inspector.get_unique_constraints(_TABLE),
                    "checks": {
                        check["name"]: check["sqltext"]
                        for check in inspector.get_check_constraints(_TABLE)
                    },
                    # Indexes backing a unique constraint are reported with
                    # `duplicates_constraint`; anything else is standalone.
                    "standalone_indexes": {
                        (
                            index["name"],
                            tuple(index["column_names"]),
                            index["unique"],
                            index.get("dialect_options", {}).get("postgresql_where"),
                        )
                        for index in indexes
                        if not index.get("duplicates_constraint")
                    },
                    "index_methods": {
                        index.get("dialect_options", {}).get(
                            "postgresql_using", "btree"
                        )
                        for index in indexes
                    },
                }

            return await conn.run_sync(_sync_inspect)
    finally:
        await engine.dispose()


def _inspect(database_url: str) -> _TableFacts:
    return run_sync(_inspect_table(database_url))


def _assert_unchanged_parts(facts: _TableFacts) -> None:
    assert facts["primary_key"] == ["id"]
    assert facts["foreign_keys"] == {_FOREIGN_KEY}
    assert facts["unique_constraints"] == []
    assert facts["index_methods"] == {"btree"}


def _assert_previous_shape(facts: _TableFacts, *, exact_order: bool) -> None:
    """The shape at `_PREVIOUS_HEAD`. After a downgrade the restored columns
    follow the kept ones, so only the original creation has their order."""
    _assert_unchanged_parts(facts)
    if exact_order:
        assert facts["columns"] == [
            *_KEPT_COLUMNS[:11],
            _DROPPED_COLUMNS[0],
            *_KEPT_COLUMNS[11:13],
            _DROPPED_COLUMNS[1],
            *_KEPT_COLUMNS[13:],
        ]
    else:
        assert facts["columns"] == [*_KEPT_COLUMNS, *_DROPPED_COLUMNS]
    assert facts["checks"] == {**_KEPT_CHECKS, **_DROPPED_CHECK}
    assert facts["standalone_indexes"] == _KEPT_INDEXES


def _assert_upgraded(facts: _TableFacts) -> None:
    _assert_unchanged_parts(facts)
    assert facts["columns"] == _KEPT_COLUMNS
    assert facts["checks"] == _KEPT_CHECKS
    assert facts["standalone_indexes"] == _KEPT_INDEXES | {_NEW_INDEX}


async def _execute(database_url: str, statement: str, **parameters: Any) -> list[Any]:
    engine = create_async_engine(database_url)
    try:
        async with engine.begin() as conn:
            result = await conn.execute(text(statement), parameters)
            return list(result.all()) if result.returns_rows else []
    finally:
        await engine.dispose()


def _seed_release_action(database_url: str) -> uuid.UUID:
    """One accepted release action carrying both columns to be dropped."""
    (request_id,) = run_sync(
        _execute(
            database_url,
            "INSERT INTO ibs_request (request_number, state, upstream_created_at,"
            " upstream_updated_at) VALUES (410001, 'accepted', now(), now())"
            " RETURNING id",
        )
    )[0]
    (action_id,) = run_sync(
        _execute(
            database_url,
            "INSERT INTO ibs_request_action (ibs_request_id, action_type,"
            " source_project, source_package, target_project, target_package,"
            " logical_package, codestream_name, incident_number, source_revision,"
            " accepted_revision, accepted_srcmd5, accepted_xsrcmd5)"
            " VALUES (:request_id, 'maintenance_release', 'SUSE:Maintenance:45001',"
            " 'example-pkg.SUSE_Codestream', :codestream, 'example-pkg.45001',"
            " 'example-pkg', :codestream, 45001, :checksum, '4', :checksum,"
            " :checksum) RETURNING id",
            request_id=request_id,
            codestream=_CODESTREAM,
            checksum=_CHECKSUM,
        )
    )[0]
    return uuid.UUID(str(action_id))


@pytest.mark.integration
class TestIBSRequestActionSchemaAlignmentMigration:
    def test_upgrade_downgrade_reupgrade_cycle(
        self,
        alembic_test_database_url: str,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(settings, "database_url", alembic_test_database_url)
        cfg = isolated_alembic_config()

        command.upgrade(cfg, _PREVIOUS_HEAD)
        _assert_previous_shape(_inspect(alembic_test_database_url), exact_order=True)

        command.upgrade(cfg, _REVISION)
        _assert_upgraded(_inspect(alembic_test_database_url))

        command.downgrade(cfg, _PREVIOUS_HEAD)
        _assert_previous_shape(_inspect(alembic_test_database_url), exact_order=False)

        command.upgrade(cfg, _REVISION)
        _assert_upgraded(_inspect(alembic_test_database_url))

    def test_existing_row_survives_with_its_remaining_values(
        self,
        alembic_test_database_url: str,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Dropping the two columns keeps every other value of an existing
        row; the restored columns are empty after a downgrade, and the
        restored CHECK accepts that row."""
        monkeypatch.setattr(settings, "database_url", alembic_test_database_url)
        cfg = isolated_alembic_config()
        command.upgrade(cfg, _PREVIOUS_HEAD)
        action_id = _seed_release_action(alembic_test_database_url)
        kept = (
            "SELECT action_type, source_project, source_package, target_project,"
            " target_package, logical_package, codestream_name, incident_number,"
            " accepted_revision, accepted_srcmd5 FROM ibs_request_action"
            " WHERE id = :id"
        )
        before = run_sync(_execute(alembic_test_database_url, kept, id=action_id))

        command.upgrade(cfg, _REVISION)
        assert run_sync(_execute(alembic_test_database_url, kept, id=action_id)) == (
            before
        )

        command.downgrade(cfg, _PREVIOUS_HEAD)
        assert run_sync(_execute(alembic_test_database_url, kept, id=action_id)) == (
            before
        )
        assert run_sync(
            _execute(
                alembic_test_database_url,
                "SELECT source_revision, accepted_xsrcmd5 FROM ibs_request_action"
                " WHERE id = :id",
                id=action_id,
            )
        ) == [(None, None)]
