"""Integration tests for the TicketPackage model
(backend/app/models/ticket_package.py).

See docs/data-model.md (TicketPackage) and
docs/features/packages/package-model.md (Data Model, Exclusion and
Actionability). Only the persistence contract is covered here; package-tree
creation, exclusion and restoration, actionability, and package queries are
`package_service` behavior. Deletion protection of the package against its
tracks is covered in `test_ticket_package_track.py`.
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import CheckConstraint, UniqueConstraint, delete, insert, text
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.ticket import Ticket
from app.models.ticket_package import TicketPackage

TicketFactory = Callable[..., Awaitable[Ticket]]
TicketPackageFactory = Callable[..., Awaitable[TicketPackage]]

_DOCUMENTED_COLUMNS = {
    "id",
    "ticket_id",
    "package_name",
    "deleted_at",
    "created_at",
    "updated_at",
}


@pytest.mark.integration
class TestTicketPackageCreation:
    async def test_create_with_defaults(
        self, ticket_package_factory: TicketPackageFactory
    ) -> None:
        package = await ticket_package_factory()

        assert package.id.version == 7
        assert package.ticket_id is not None
        assert package.package_name.startswith("example-package-")
        assert package.deleted_at is None
        assert package.created_at is not None
        assert package.updated_at is not None

    async def test_create_with_every_column(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        ticket_package_factory: TicketPackageFactory,
    ) -> None:
        ticket = await ticket_factory()
        excluded_at = datetime(2026, 9, 1, 1, 0, tzinfo=UTC)
        package = await ticket_package_factory(
            ticket_id=ticket.id,
            package_name="example-libfoo",
            deleted_at=excluded_at,
        )
        package_id = package.id
        db_session.expunge(package)

        reloaded = await db_session.get(TicketPackage, package_id)
        assert reloaded is not None
        assert reloaded.ticket_id == ticket.id
        assert reloaded.package_name == "example-libfoo"
        assert reloaded.deleted_at == excluded_at

    async def test_raw_insert_applies_server_defaults(
        self, db_session: AsyncSession, ticket_factory: TicketFactory
    ) -> None:
        """A raw SQL INSERT bypasses every Python-side default, so the
        `uuidv7()` and `now()` server defaults must supply the columns."""
        ticket = await ticket_factory()
        result = await db_session.execute(
            text(
                "INSERT INTO ticket_package (ticket_id, package_name) "
                "VALUES (:ticket_id, 'example-raw') "
                "RETURNING id, deleted_at, created_at, updated_at"
            ),
            {"ticket_id": ticket.id},
        )
        row = result.one()
        assert isinstance(row.id, uuid.UUID)
        assert row.id.version == 7
        assert row.deleted_at is None
        assert row.created_at.tzinfo is not None
        assert row.updated_at == row.created_at


@pytest.mark.unit
class TestTicketPackageSchemaShape:
    """Exactly the documented columns, constraints, and index (#633
    decision A2): no persisted actionability column, no CHECK constraint,
    and only `ix_ticket_package_package_name`."""

    def test_columns_match_documented_set(self) -> None:
        assert set(TicketPackage.__table__.columns.keys()) == _DOCUMENTED_COLUMNS

    def test_unique_constraint(self) -> None:
        table = TicketPackage.metadata.tables["ticket_package"]
        uniques = {
            (constraint.name, tuple(column.name for column in constraint.columns))
            for constraint in table.constraints
            if isinstance(constraint, UniqueConstraint)
        }
        assert uniques == {
            (
                "uq_ticket_package_ticket_id_package_name",
                ("ticket_id", "package_name"),
            )
        }

    def test_no_check_constraint(self) -> None:
        table = TicketPackage.metadata.tables["ticket_package"]
        assert not [c for c in table.constraints if isinstance(c, CheckConstraint)]

    def test_exact_index_set(self) -> None:
        """`ix_ticket_package_package_name`: non-unique, non-partial B-tree
        on `package_name` (docs/data-model.md, TicketPackage, Indexes)."""
        (index,) = TicketPackage.metadata.tables["ticket_package"].indexes
        assert index.name == "ix_ticket_package_package_name"
        assert [column.name for column in index.columns] == ["package_name"]
        assert index.unique is False
        assert index.dialect_options["postgresql"]["where"] is None
        # No `postgresql_using`: PostgreSQL's default B-tree access method.
        assert not index.dialect_options["postgresql"]["using"]


@pytest.mark.integration
class TestTicketPackageColumnLengths:
    async def test_documented_maximum_accepted(
        self, ticket_package_factory: TicketPackageFactory
    ) -> None:
        package = await ticket_package_factory(package_name="a" * 255)
        assert len(package.package_name) == 255

    async def test_value_over_documented_maximum_rejected(
        self, ticket_package_factory: TicketPackageFactory
    ) -> None:
        # asyncpg surfaces the truncation as a generic DBAPIError.
        with pytest.raises(DBAPIError, match="value too long"):
            await ticket_package_factory(package_name="a" * 256)


@pytest.mark.integration
class TestTicketPackageUniqueness:
    async def test_same_package_name_on_same_ticket_rejected(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        ticket_package_factory: TicketPackageFactory,
    ) -> None:
        ticket = await ticket_factory()
        await ticket_package_factory(ticket_id=ticket.id, package_name="example-dup")
        db_session.add(TicketPackage(ticket_id=ticket.id, package_name="example-dup"))
        with pytest.raises(
            IntegrityError, match="uq_ticket_package_ticket_id_package_name"
        ):
            await db_session.flush()

    async def test_directly_excluded_package_still_occupies_the_name(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        ticket_package_factory: TicketPackageFactory,
    ) -> None:
        """The UNIQUE constraint is not partial: a soft-deleted package
        still owns its name within the Ticket."""
        ticket = await ticket_factory()
        await ticket_package_factory(
            ticket_id=ticket.id,
            package_name="example-dup",
            deleted_at=datetime.now(UTC),
        )
        db_session.add(TicketPackage(ticket_id=ticket.id, package_name="example-dup"))
        with pytest.raises(
            IntegrityError, match="uq_ticket_package_ticket_id_package_name"
        ):
            await db_session.flush()

    async def test_same_package_name_on_different_tickets_accepted(
        self, ticket_package_factory: TicketPackageFactory
    ) -> None:
        first = await ticket_package_factory(package_name="example-shared")
        second = await ticket_package_factory(package_name="example-shared")
        assert first.ticket_id != second.ticket_id

    async def test_different_package_names_on_same_ticket_accepted(
        self,
        ticket_factory: TicketFactory,
        ticket_package_factory: TicketPackageFactory,
    ) -> None:
        ticket = await ticket_factory()
        await ticket_package_factory(ticket_id=ticket.id, package_name="example-a")
        await ticket_package_factory(ticket_id=ticket.id, package_name="example-b")


@pytest.mark.integration
class TestTicketPackageNotNullConstraints:
    @pytest.mark.parametrize(
        "column", ["ticket_id", "package_name", "created_at", "updated_at"]
    )
    async def test_explicit_null_rejected(
        self, db_session: AsyncSession, ticket_factory: TicketFactory, column: str
    ) -> None:
        """A Core INSERT with an explicit NULL bypasses the ORM, which
        would otherwise omit a `None` server-defaulted column."""
        ticket = await ticket_factory()
        values: dict[str, object] = {
            "ticket_id": ticket.id,
            "package_name": "example-null",
            column: None,
        }
        with pytest.raises(IntegrityError, match="not-null"):
            await db_session.execute(insert(TicketPackage).values(values))

    async def test_deleted_at_accepts_null(
        self, db_session: AsyncSession, ticket_package_factory: TicketPackageFactory
    ) -> None:
        package = await ticket_package_factory(deleted_at=datetime.now(UTC))
        package.deleted_at = None
        await db_session.flush()
        await db_session.refresh(package)
        assert package.deleted_at is None


@pytest.mark.integration
class TestTicketPackageForeignKey:
    async def test_nonexistent_ticket_rejected(self, db_session: AsyncSession) -> None:
        db_session.add(
            TicketPackage(ticket_id=uuid.uuid7(), package_name="example-orphan")
        )
        with pytest.raises(IntegrityError, match="ticket_package_ticket_id_fkey"):
            await db_session.flush()

    def test_foreign_key_uses_default_no_action(self) -> None:
        """No ON DELETE action is documented: the PostgreSQL default
        NO ACTION applies (#633 decision A3)."""
        (fk,) = TicketPackage.__table__.c.ticket_id.foreign_keys
        assert fk.target_fullname == "ticket.id"
        assert fk.ondelete is None


@pytest.mark.integration
class TestTicketDeleteRejectedWhilePackagesExist:
    """Tickets are never deleted and the package tree is soft-deleted. The
    FK uses the PostgreSQL default NO ACTION (#633 decision A3) and
    `Ticket.packages` uses `passive_deletes="all"`, so deleting a Ticket
    with packages fails on the FK instead of the ORM nulling the package's
    `ticket_id` first."""

    async def test_orm_delete_with_loaded_packages_raises(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        ticket_package_factory: TicketPackageFactory,
    ) -> None:
        ticket = await ticket_factory()
        await ticket_package_factory(ticket_id=ticket.id)
        await db_session.refresh(ticket, ["packages"])
        assert len(ticket.packages) == 1

        await db_session.delete(ticket)
        with pytest.raises(IntegrityError, match="ticket_package_ticket_id_fkey"):
            await db_session.flush()

    async def test_database_delete_raises(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        ticket_package_factory: TicketPackageFactory,
    ) -> None:
        ticket = await ticket_factory()
        await ticket_package_factory(ticket_id=ticket.id)
        ticket_id = ticket.id
        db_session.expunge_all()

        with pytest.raises(IntegrityError, match="ticket_package_ticket_id_fkey"):
            await db_session.execute(delete(Ticket).where(Ticket.id == ticket_id))


@pytest.mark.integration
class TestTicketPackageRelationships:
    async def test_ticket_packages_round_trip(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        ticket_package_factory: TicketPackageFactory,
    ) -> None:
        ticket = await ticket_factory()
        first = await ticket_package_factory(ticket_id=ticket.id)
        second = await ticket_package_factory(ticket_id=ticket.id)
        await ticket_package_factory()

        await db_session.refresh(first, ["ticket"])
        await db_session.refresh(ticket, ["packages"])

        assert first.ticket is ticket
        assert {p.id for p in ticket.packages} == {first.id, second.id}


@pytest.mark.integration
class TestTicketPackageTimestamps:
    async def test_timestamps_are_timezone_aware(
        self, db_session: AsyncSession, ticket_package_factory: TicketPackageFactory
    ) -> None:
        package = await ticket_package_factory(deleted_at=datetime.now(UTC))
        await db_session.refresh(package)
        assert package.created_at.tzinfo is not None
        assert package.updated_at.tzinfo is not None
        assert package.deleted_at is not None
        assert package.deleted_at.tzinfo is not None

    async def test_updated_at_advances_on_update(
        self, db_session: AsyncSession, ticket_package_factory: TicketPackageFactory
    ) -> None:
        """Backdating pattern (docs/features/platform/testing-strategy.md,
        `server_default=func.now()` and `onupdate=func.now()` Testing)."""
        package = await ticket_package_factory()
        backdated = datetime.now(UTC) - timedelta(days=7)
        package.updated_at = backdated
        await db_session.flush()
        await db_session.refresh(package)
        assert package.updated_at == backdated

        package.deleted_at = datetime.now(UTC)
        await db_session.flush()
        await db_session.refresh(package)

        assert package.updated_at > backdated

    async def test_created_at_unchanged_on_update(
        self, db_session: AsyncSession, ticket_package_factory: TicketPackageFactory
    ) -> None:
        package = await ticket_package_factory()
        backdated = datetime.now(UTC) - timedelta(days=7)
        package.created_at = backdated
        await db_session.flush()

        package.deleted_at = datetime.now(UTC)
        await db_session.flush()
        await db_session.refresh(package)

        assert package.created_at == backdated
