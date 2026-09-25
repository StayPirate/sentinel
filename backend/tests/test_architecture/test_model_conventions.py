"""Structural tests over SQLAlchemy model conventions.

Verifies invariants declared in `docs/conventions.md` (SQLAlchemy
Conventions, Enum Storage Strategy) and
`docs/features/platform/testing-strategy.md` (Structural Tests) across
every table registered in `Base.metadata`.

Scope note: CHECK constraint naming and `created_at`/`updated_at`
presence are deliberately NOT verified here, even though both are
model-level invariants. `docs/data-model.md` (Notes) already documents
a growing, per-table exception list for `created_at`/`updated_at`
(append-only and auto-created tables); mirroring that list here would
require hand-keeping a second copy in sync, since this module must not
parse `data-model.md`. CHECK constraint naming has only two instances
project-wide, one of which (`chk_user_auth_exclusive`) is a legitimate
exception to the enum-check pattern — a case better served by human
review in each rare PR that adds one than by a hard-coded rule (see
issue #58 for the full rationale). The invariants below apply
universally, with small, explicit per-table exception lists for the
primary key type invariant (see `_NON_UUID_PRIMARY_KEY_TABLES`) and the
UUIDv7 generation invariant (see `_NON_UUIDV7_PRIMARY_KEY_TABLES`), which
is what makes them good structural-test candidates.

Only the mechanical part of the foreign-key access-path indexing criterion
in `docs/data-model.md` (Notes) is verified here: every `ON DELETE CASCADE`
foreign key is covered by a leading key. Whether another foreign key's
parent rows can be deleted, or whether a documented query needs an index,
requires judgement and is checked by `@data-model-reviewer`.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence

import pytest
from sqlalchemy import (
    Column,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    MetaData,
    Table,
    UniqueConstraint,
    text,
)
from sqlalchemy import Enum as SAEnum
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql.schema import CallableColumnDefault, DefaultClause
from sqlalchemy.types import DateTime

import app.models  # noqa: F401 — import populates Base.metadata as a side effect
from app.database import Base


def _mapped_tables() -> Iterable[Table]:
    """Every table registered on the shared declarative Base."""
    return Base.metadata.tables.values()


# Explicit, per-table exception list for the UUID primary key invariant
# below. `docs/data-model.md` (Notes) documents these as deliberate
# exceptions: a natural business identifier makes a more meaningful
# primary key than a surrogate UUID for small, key-value-shaped
# configuration tables. Maps table name -> the set of primary key
# column names allowed to be non-UUID on that table. A table not
# listed here still requires every primary key column to be UUID.
_NON_UUID_PRIMARY_KEY_TABLES: dict[str, frozenset[str]] = {
    "system_setting": frozenset({"key"}),
    "fetcher_config": frozenset({"fetcher_name"}),
}

# Explicit, per-table exception list for the UUIDv7 generation invariant
# only. `docs/data-model.md` (Notes) documents `TicketAccessGrant` as a
# composite primary key `(ticket_id, user_id)`: both columns are UUID
# foreign keys to existing rows, so they must never generate a UUID of
# their own. They remain subject to the UUID type invariant above. Maps
# table name -> the set of UUID primary key column names exempt from the
# `uuid.uuid7`/`uuidv7()` default requirement.
_NON_UUIDV7_PRIMARY_KEY_TABLES: dict[str, frozenset[str]] = {
    "ticket_access_grant": frozenset({"ticket_id", "user_id"}),
}


@pytest.mark.unit
class TestPrimaryKeyExceptionListsAreCurrent:
    """Every exception entry names an existing primary key column, so a
    renamed or removed table cannot leave a stale exemption behind."""

    @pytest.mark.parametrize(
        "exceptions",
        [_NON_UUID_PRIMARY_KEY_TABLES, _NON_UUIDV7_PRIMARY_KEY_TABLES],
        ids=["non_uuid", "non_uuidv7"],
    )
    def test_every_entry_matches_a_primary_key_column(
        self, exceptions: dict[str, frozenset[str]]
    ) -> None:
        tables = Base.metadata.tables
        for table_name, column_names in exceptions.items():
            assert table_name in tables, f"Unknown table '{table_name}'"
            pk_names = {column.name for column in tables[table_name].primary_key}
            assert column_names <= pk_names, (
                f"Table '{table_name}': {sorted(column_names - pk_names)} "
                "are not primary key columns"
            )

    def test_composite_foreign_key_exception_columns_are_uuid(self) -> None:
        # The UUIDv7 exemption must not hide a non-UUID key: the type
        # invariant still applies to these columns.
        tables = Base.metadata.tables
        for table_name, column_names in _NON_UUIDV7_PRIMARY_KEY_TABLES.items():
            for column_name in column_names:
                column = tables[table_name].columns[column_name]
                assert isinstance(column.type, UUID)
                assert column.foreign_keys, (
                    f"'{table_name}.{column_name}' is exempt from UUIDv7 "
                    "generation but is not a foreign key"
                )


@pytest.mark.unit
class TestPrimaryKeyType:
    """Every mapped table uses a UUID primary key, except the small,
    explicit set of natural-key tables in `_NON_UUID_PRIMARY_KEY_TABLES`.

    See `docs/conventions.md` (SQLAlchemy Conventions): "Use UUID
    primary keys," and `docs/data-model.md` (Notes) for the documented
    per-table exceptions.
    """

    def test_every_table_has_a_uuid_primary_key(self) -> None:
        violations: list[str] = []
        for table in _mapped_tables():
            pk_columns = list(table.primary_key.columns)
            if not pk_columns:
                violations.append(f"Table '{table.name}' has no primary key")
                continue
            allowed_non_uuid = _NON_UUID_PRIMARY_KEY_TABLES.get(table.name, frozenset())
            for column in pk_columns:
                if column.name in allowed_non_uuid:
                    continue
                if not isinstance(column.type, UUID):
                    violations.append(
                        f"Table '{table.name}' primary key column "
                        f"'{column.name}' is not a UUID type "
                        f"(got {type(column.type).__name__})"
                    )
        assert not violations, "\n".join(violations)


@pytest.mark.unit
class TestUuidPrimaryKeyIsUuidV7:
    """Every UUID primary key column uses UUIDv7, not UUIDv4, on both
    sides of the generation contract.

    See `docs/conventions.md` (SQLAlchemy Conventions): "Use UUIDv7
    primary keys... Never use `uuid.uuid4` for primary keys." Applies
    to the same tables covered by `TestPrimaryKeyType` (natural-key
    tables in `_NON_UUID_PRIMARY_KEY_TABLES` are skipped — they have no
    UUID column to check — and so are the composite foreign-key primary
    key columns in `_NON_UUIDV7_PRIMARY_KEY_TABLES`, which reference
    existing rows instead of generating an identifier).
    """

    def test_every_uuid_primary_key_has_uuid7_default_and_server_default(
        self,
    ) -> None:
        violations: list[str] = []
        for table in _mapped_tables():
            allowed_non_uuid = _NON_UUID_PRIMARY_KEY_TABLES.get(table.name, frozenset())
            allowed_non_uuidv7 = _NON_UUIDV7_PRIMARY_KEY_TABLES.get(
                table.name, frozenset()
            )
            for column in table.primary_key.columns:
                if column.name in allowed_non_uuid or not isinstance(column.type, UUID):
                    continue
                if column.name in allowed_non_uuidv7:
                    continue

                default = column.default
                if (
                    not isinstance(default, CallableColumnDefault)
                    or getattr(default.arg, "__module__", None) != "uuid"
                    or getattr(default.arg, "__qualname__", None) != "uuid7"
                ):
                    violations.append(
                        f"Table '{table.name}' primary key column "
                        f"'{column.name}' does not declare "
                        "default=uuid.uuid7"
                    )

                server_default = column.server_default
                if (
                    not isinstance(server_default, DefaultClause)
                    or str(server_default.arg) != "uuidv7()"
                ):
                    violations.append(
                        f"Table '{table.name}' primary key column "
                        f"'{column.name}' does not declare "
                        'server_default=text("uuidv7()")'
                    )
        assert not violations, "\n".join(violations)


@pytest.mark.unit
class TestDateTimeColumnsAreTimezoneAware:
    """Every DateTime column is timezone-aware.

    See `docs/conventions.md` (Timestamps & Timezones): "Never use bare
    TIMESTAMP (without time zone) — naive timestamps are ambiguous and
    a source of bugs in multi-timezone environments."
    """

    def test_every_datetime_column_declares_timezone_true(self) -> None:
        violations: list[str] = []
        for table in _mapped_tables():
            for column in table.columns:
                if (
                    isinstance(column.type, DateTime)
                    and column.type.timezone is not True
                ):
                    violations.append(
                        f"Table '{table.name}' column '{column.name}' "
                        "uses DateTime without timezone=True "
                        "(produces a naive TIMESTAMP column)"
                    )
        assert not violations, "\n".join(violations)


@pytest.mark.unit
class TestNoPostgresEnumTypes:
    """No column uses a native SQL ENUM type.

    See `docs/conventions.md` (Enum Storage Strategy): "Sentinel does
    not use PostgreSQL ENUM types (CREATE TYPE ... AS ENUM). All
    enumerated columns use VARCHAR(N)."

    `sqlalchemy.dialects.postgresql.ENUM` is a subclass of
    `sqlalchemy.Enum`, so a single `isinstance` check against the
    generic type catches both the emulated and the PostgreSQL-native
    variant.
    """

    def test_no_column_uses_a_native_enum_type(self) -> None:
        violations: list[str] = []
        for table in _mapped_tables():
            for column in table.columns:
                if isinstance(column.type, SAEnum):
                    violations.append(
                        f"Table '{table.name}' column '{column.name}' uses "
                        "a native ENUM type (forbidden — use VARCHAR(N) "
                        "with a CHECK constraint or a Python StrEnum instead, "
                        "per the Enum Storage Strategy)"
                    )
        assert not violations, "\n".join(violations)


def _leading_key_column_lists(table: Table) -> list[list[str]]:
    """Ordered column-name lists of every key that can serve a lookup on
    its leading columns: the primary key, each unique constraint (including
    `unique=True` columns), and each non-partial index. An index stops at
    its first non-column expression, since a functional expression cannot
    serve a plain column lookup."""
    keys: list[list[str]] = [[column.name for column in table.primary_key.columns]]
    keys.extend(
        [column.name for column in constraint.columns]
        for constraint in table.constraints
        if isinstance(constraint, UniqueConstraint)
    )
    for index in table.indexes:
        if index.dialect_options["postgresql"]["where"] is not None:
            continue
        leading: list[str] = []
        for expression in index.expressions:
            if not isinstance(expression, Column):
                break
            leading.append(expression.name)
        keys.append(leading)
    return keys


def _is_covered(fk_columns: Sequence[str], keys: Iterable[list[str]]) -> bool:
    """True when some key's leading columns are exactly the FK columns,
    in any order."""
    width = len(fk_columns)
    return any(
        len(key) >= width and set(key[:width]) == set(fk_columns) for key in keys
    )


def _cascade_foreign_key_coverage_violations(tables: Iterable[Table]) -> list[str]:
    violations: list[str] = []
    for table in tables:
        keys = _leading_key_column_lists(table)
        for constraint in table.foreign_key_constraints:
            if (constraint.ondelete or "").upper() != "CASCADE":
                continue
            fk_columns = [column.name for column in constraint.columns]
            if not _is_covered(fk_columns, keys):
                violations.append(
                    f"Table '{table.name}' ON DELETE CASCADE foreign key "
                    f"{fk_columns} is not the leading column set of its "
                    "primary key, a unique constraint, or a non-partial index"
                )
    return violations


@pytest.mark.unit
class TestCascadeForeignKeysAreIndexed:
    """Every `ON DELETE CASCADE` foreign key leads the primary key, a unique
    constraint, or a non-partial index, so a parent delete does not scan
    the child table.

    See `docs/data-model.md` (Notes): "The child side of an `ON DELETE
    CASCADE` foreign key is always covered by a primary key, a unique
    constraint, or a non-partial index." There is deliberately no exception
    list.
    """

    def test_every_cascade_foreign_key_is_covered(self) -> None:
        violations = _cascade_foreign_key_coverage_violations(_mapped_tables())
        assert not violations, "\n".join(violations)


def _synthetic_child(*extra: Index | UniqueConstraint) -> Table:
    """A child table with a CASCADE FK `parent_id` on fresh metadata;
    `extra` adds the indexes or constraints under test."""
    metadata = MetaData()
    Table("parent", metadata, Column("id", UUID, primary_key=True))
    return Table(
        "child",
        metadata,
        Column("id", UUID, primary_key=True),
        Column("parent_id", UUID, ForeignKey("parent.id", ondelete="CASCADE")),
        Column("other", UUID),
        *extra,
    )


@pytest.mark.unit
class TestCascadeForeignKeyCoverageDetection:
    """The coverage check itself: it accepts every documented kind of
    covering key and rejects keys that cannot serve the FK lookup."""

    def test_uncovered_foreign_key_is_reported(self) -> None:
        violations = _cascade_foreign_key_coverage_violations([_synthetic_child()])
        assert len(violations) == 1
        assert "'child'" in violations[0]
        assert "['parent_id']" in violations[0]

    def test_non_leading_index_column_is_reported(self) -> None:
        table = _synthetic_child(Index("ix_child_other_parent", "other", "parent_id"))
        assert _cascade_foreign_key_coverage_violations([table])

    def test_non_leading_unique_constraint_column_is_reported(self) -> None:
        table = _synthetic_child(UniqueConstraint("other", "parent_id"))
        assert _cascade_foreign_key_coverage_violations([table])

    def test_partial_index_is_not_coverage(self) -> None:
        table = _synthetic_child(
            Index(
                "ix_child_parent_partial",
                "parent_id",
                postgresql_where=text("other IS NOT NULL"),
            )
        )
        assert _cascade_foreign_key_coverage_violations([table])

    def test_functional_index_expression_is_not_coverage(self) -> None:
        table = _synthetic_child(
            Index("ix_child_parent_text", text("(parent_id::text)"))
        )
        assert _cascade_foreign_key_coverage_violations([table])

    @pytest.mark.parametrize(
        "covering_key",
        [
            Index("ix_child_parent_id", "parent_id"),
            Index("ix_child_parent_other", "parent_id", "other"),
            UniqueConstraint("parent_id", "other"),
        ],
        ids=["single_column_index", "composite_index", "unique_constraint"],
    )
    def test_leading_key_is_coverage(
        self, covering_key: Index | UniqueConstraint
    ) -> None:
        table = _synthetic_child(covering_key)
        assert _cascade_foreign_key_coverage_violations([table]) == []

    def test_leading_primary_key_column_is_coverage(self) -> None:
        metadata = MetaData()
        Table("parent", metadata, Column("id", UUID, primary_key=True))
        table = Table(
            "child",
            metadata,
            Column(
                "parent_id",
                UUID,
                ForeignKey("parent.id", ondelete="CASCADE"),
                primary_key=True,
            ),
            Column("other", UUID, primary_key=True),
        )
        assert _cascade_foreign_key_coverage_violations([table]) == []

    def test_unique_column_is_coverage(self) -> None:
        metadata = MetaData()
        Table("parent", metadata, Column("id", UUID, primary_key=True))
        table = Table(
            "child",
            metadata,
            Column("id", UUID, primary_key=True),
            Column(
                "parent_id",
                UUID,
                ForeignKey("parent.id", ondelete="CASCADE"),
                unique=True,
            ),
        )
        assert _cascade_foreign_key_coverage_violations([table]) == []

    def test_composite_foreign_key_is_covered_in_any_leading_order(self) -> None:
        metadata = MetaData()
        Table(
            "parent",
            metadata,
            Column("a", UUID, primary_key=True),
            Column("b", UUID, primary_key=True),
        )
        covered = Table(
            "child",
            metadata,
            Column("id", UUID, primary_key=True),
            Column("a", UUID),
            Column("b", UUID),
            Column("other", UUID),
            ForeignKeyConstraint(
                ["a", "b"], ["parent.a", "parent.b"], ondelete="CASCADE"
            ),
            Index("ix_child_b_a_other", "b", "a", "other"),
        )
        assert _cascade_foreign_key_coverage_violations([covered]) == []

        uncovered = Table(
            "child_partial_prefix",
            metadata,
            Column("id", UUID, primary_key=True),
            Column("a", UUID),
            Column("b", UUID),
            Column("other", UUID),
            ForeignKeyConstraint(
                ["a", "b"], ["parent.a", "parent.b"], ondelete="CASCADE"
            ),
            Index("ix_child_partial_prefix_a_other_b", "a", "other", "b"),
        )
        assert _cascade_foreign_key_coverage_violations([uncovered])

    @pytest.mark.parametrize("ondelete", [None, "RESTRICT", "SET NULL", "NO ACTION"])
    def test_non_cascade_foreign_key_is_ignored(self, ondelete: str | None) -> None:
        metadata = MetaData()
        Table("parent", metadata, Column("id", UUID, primary_key=True))
        table = Table(
            "child",
            metadata,
            Column("id", UUID, primary_key=True),
            Column("parent_id", UUID, ForeignKey("parent.id", ondelete=ondelete)),
        )
        assert _cascade_foreign_key_coverage_violations([table]) == []
