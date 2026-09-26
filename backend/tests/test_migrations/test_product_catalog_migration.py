"""Integration tests for the Product catalog Alembic migration
(backend/alembic/versions/ebb47af19347_add_product_catalog_tables.py).

Verifies that upgrading from the previous head creates exactly the `product`
and `product_repository` tables documented in `docs/data-model.md` (Product,
ProductRepository): columns, types (including `NUMERIC(3,1)` and `DATE`),
nullability, server defaults (none on `catalog_last_seen_at`), primary keys,
the `product_repository.product_id` foreign key with the PostgreSQL default
`NO ACTION` (#633 decision A3), UNIQUE `cpe`, UNIQUE `(product_id,
repo_name)`, and no CHECK constraint or standalone index (#633 decision A2).
Downgrade removes the tables and re-upgrade restores them.

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

_PREVIOUS_HEAD = "b3996908657f"
_REVISION = "ebb47af19347"

_UUID_PK_DEFAULT = "uuidv7()"
_NOW_DEFAULT = "now()"

_TABLES = ("product", "product_repository")

Column = tuple[str, str, bool, str | None]
# (constrained column, referred table, referred column, ON DELETE option or
# None for the PostgreSQL default NO ACTION)
ForeignKey = tuple[str, str, str, str | None]


class _Expected(TypedDict):
    columns: list[Column]
    foreign_keys: set[ForeignKey]
    unique_constraints: set[tuple[str, tuple[str, ...]]]


_EXPECTED: dict[str, _Expected] = {
    "product": {
        "columns": [
            ("id", "UUID", False, _UUID_PK_DEFAULT),
            ("name", "VARCHAR(100)", False, None),
            ("version", "VARCHAR(50)", False, None),
            ("display_name", "VARCHAR(255)", False, None),
            ("cpe", "VARCHAR(255)", False, None),
            ("cvss_threshold", "NUMERIC(3, 1)", True, None),
            ("first_customer_ship_date", "DATE", True, None),
            ("general_support_end_date", "DATE", True, None),
            ("extended_support_end_date", "DATE", True, None),
            ("reactive_support_end_date", "DATE", True, None),
            ("catalog_last_seen_at", "TIMESTAMPTZ", False, None),
            ("created_at", "TIMESTAMPTZ", False, _NOW_DEFAULT),
            ("updated_at", "TIMESTAMPTZ", False, _NOW_DEFAULT),
        ],
        "foreign_keys": set(),
        "unique_constraints": {("product_cpe_key", ("cpe",))},
    },
    "product_repository": {
        "columns": [
            ("id", "UUID", False, _UUID_PK_DEFAULT),
            ("product_id", "UUID", False, None),
            ("repo_name", "VARCHAR(255)", False, None),
            ("catalog_last_seen_at", "TIMESTAMPTZ", False, None),
            ("created_at", "TIMESTAMPTZ", False, _NOW_DEFAULT),
            ("updated_at", "TIMESTAMPTZ", False, _NOW_DEFAULT),
        ],
        "foreign_keys": {("product_id", "product", "id", None)},
        "unique_constraints": {
            (
                "uq_product_repository_product_id_repo_name",
                ("product_id", "repo_name"),
            ),
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


def _assert_catalog_schema(facts: _SchemaFacts) -> None:
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

        # No CHECK constraint (e.g. on the `cvss_threshold` range) and no
        # standalone index (e.g. on `catalog_last_seen_at`) is documented.
        assert table["checks"] == [], name
        assert table["standalone_indexes"] == [], name


@pytest.mark.integration
class TestProductCatalogMigration:
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
        _assert_catalog_schema(upgraded)
        assert upgraded["tables"] == before["tables"] | set(_TABLES)

        command.downgrade(cfg, _PREVIOUS_HEAD)
        downgraded = _inspect(alembic_test_database_url)
        assert downgraded["catalog"] == {}
        assert downgraded["tables"] == before["tables"]

        command.upgrade(cfg, _REVISION)
        _assert_catalog_schema(_inspect(alembic_test_database_url))
