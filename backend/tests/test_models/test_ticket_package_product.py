"""Integration tests for the TicketPackageProduct model
(backend/app/models/ticket_package_product.py).

See docs/data-model.md (TicketPackageProduct) and
docs/features/packages/package-model.md (Data Model, Package Eligibility >
Override Model, Exclusion and Actionability). Only the persistence contract is
covered here; eligibility computation, override set and clear,
recalculation, release confirmation, exclusion and restoration, and
actionability are `package_service` behavior.
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import CheckConstraint, UniqueConstraint, delete, insert, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.product import Product
from app.models.ticket_package_product import TicketPackageProduct
from app.models.ticket_package_track import TicketPackageTrack

ProductFactory = Callable[..., Awaitable[Product]]
TicketPackageTrackFactory = Callable[..., Awaitable[TicketPackageTrack]]
TicketPackageProductFactory = Callable[..., Awaitable[TicketPackageProduct]]

_DOCUMENTED_COLUMNS = {
    "id",
    "ticket_package_track_id",
    "product_id",
    "eligible",
    "is_eligible_override",
    "released_at",
    "deleted_at",
    "created_at",
    "updated_at",
}

_UNIQUE = "uq_ticket_package_product_ticket_package_track_id_product_id"
_TRACK_FK = "ticket_package_product_ticket_package_track_id_fkey"
_PRODUCT_FK = "ticket_package_product_product_id_fkey"


@pytest.mark.integration
class TestTicketPackageProductCreation:
    async def test_create_with_defaults(
        self, ticket_package_product_factory: TicketPackageProductFactory
    ) -> None:
        occurrence = await ticket_package_product_factory()

        assert occurrence.id.version == 7
        assert occurrence.ticket_package_track_id is not None
        assert occurrence.product_id is not None
        assert occurrence.eligible is True
        assert occurrence.is_eligible_override is False
        assert occurrence.released_at is None
        assert occurrence.deleted_at is None
        assert occurrence.created_at is not None
        assert occurrence.updated_at is not None

    async def test_create_with_every_column(
        self,
        db_session: AsyncSession,
        product_factory: ProductFactory,
        ticket_package_track_factory: TicketPackageTrackFactory,
        ticket_package_product_factory: TicketPackageProductFactory,
    ) -> None:
        track = await ticket_package_track_factory()
        product = await product_factory()
        released_at = datetime(2026, 9, 1, 8, 30, tzinfo=UTC)
        excluded_at = datetime(2026, 9, 2, 1, 0, tzinfo=UTC)
        occurrence = await ticket_package_product_factory(
            ticket_package_track_id=track.id,
            product_id=product.id,
            eligible=False,
            is_eligible_override=True,
            released_at=released_at,
            deleted_at=excluded_at,
        )
        occurrence_id = occurrence.id
        db_session.expunge(occurrence)

        reloaded = await db_session.get(TicketPackageProduct, occurrence_id)
        assert reloaded is not None
        assert reloaded.ticket_package_track_id == track.id
        assert reloaded.product_id == product.id
        assert reloaded.eligible is False
        assert reloaded.is_eligible_override is True
        assert reloaded.released_at == released_at
        assert reloaded.deleted_at == excluded_at

    async def test_raw_insert_applies_server_defaults(
        self,
        db_session: AsyncSession,
        product_factory: ProductFactory,
        ticket_package_track_factory: TicketPackageTrackFactory,
    ) -> None:
        """A raw SQL INSERT bypasses every Python-side default, so the
        database must supply `id`, `eligible` (`true`), `is_eligible_override`
        (`false`), and the timestamps."""
        track = await ticket_package_track_factory()
        product = await product_factory()
        result = await db_session.execute(
            text(
                "INSERT INTO ticket_package_product "
                "(ticket_package_track_id, product_id) "
                "VALUES (:track_id, :product_id) "
                "RETURNING id, eligible, is_eligible_override, released_at, "
                "deleted_at, created_at, updated_at"
            ),
            {"track_id": track.id, "product_id": product.id},
        )
        row = result.one()
        assert isinstance(row.id, uuid.UUID)
        assert row.id.version == 7
        assert row.eligible is True
        assert row.is_eligible_override is False
        assert row.released_at is None
        assert row.deleted_at is None
        assert row.created_at.tzinfo is not None
        assert row.updated_at == row.created_at


@pytest.mark.unit
class TestTicketPackageProductSchemaShape:
    """Exactly the documented columns, constraints, and index (#633
    decision A2): no persisted actionability, lifecycle-phase, or
    `non_actionable_reason` column, no CHECK constraint, and only
    `ix_ticket_package_product_product_id`."""

    def test_columns_match_documented_set(self) -> None:
        assert set(TicketPackageProduct.__table__.columns.keys()) == _DOCUMENTED_COLUMNS

    def test_unique_constraint(self) -> None:
        table = TicketPackageProduct.metadata.tables["ticket_package_product"]
        uniques = {
            (constraint.name, tuple(column.name for column in constraint.columns))
            for constraint in table.constraints
            if isinstance(constraint, UniqueConstraint)
        }
        assert uniques == {(_UNIQUE, ("ticket_package_track_id", "product_id"))}

    def test_no_check_constraint(self) -> None:
        table = TicketPackageProduct.metadata.tables["ticket_package_product"]
        assert not [c for c in table.constraints if isinstance(c, CheckConstraint)]

    def test_exact_index_set(self) -> None:
        """`ix_ticket_package_product_product_id`: non-unique, non-partial
        B-tree on `product_id` (docs/data-model.md, TicketPackageProduct,
        Indexes). The UNIQUE constraint covers the track access path."""
        table = TicketPackageProduct.metadata.tables["ticket_package_product"]
        (index,) = table.indexes
        assert index.name == "ix_ticket_package_product_product_id"
        assert [column.name for column in index.columns] == ["product_id"]
        assert index.unique is False
        assert index.dialect_options["postgresql"]["where"] is None
        # No `postgresql_using`: PostgreSQL's default B-tree access method.
        assert not index.dialect_options["postgresql"]["using"]

    @pytest.mark.parametrize(
        ("column", "python_default", "server_default"),
        [("eligible", True, "true"), ("is_eligible_override", False, "false")],
    )
    def test_python_and_server_defaults(
        self, column: str, python_default: bool, server_default: str
    ) -> None:
        table_column = TicketPackageProduct.__table__.c[column]
        assert table_column.default is not None
        assert table_column.default.arg is python_default
        assert table_column.server_default is not None
        assert str(table_column.server_default.arg) == server_default

    @pytest.mark.parametrize(
        ("column", "target"),
        [
            ("ticket_package_track_id", "ticket_package_track.id"),
            ("product_id", "product.id"),
        ],
    )
    def test_foreign_keys_use_default_no_action(self, column: str, target: str) -> None:
        """No ON DELETE action is documented: the PostgreSQL default
        NO ACTION applies (#633 decision A3)."""
        (fk,) = TicketPackageProduct.__table__.c[column].foreign_keys
        assert fk.target_fullname == target
        assert fk.ondelete is None


@pytest.mark.integration
class TestTicketPackageProductUniqueness:
    async def test_same_product_on_same_track_rejected(
        self,
        db_session: AsyncSession,
        ticket_package_product_factory: TicketPackageProductFactory,
    ) -> None:
        occurrence = await ticket_package_product_factory()
        db_session.add(
            TicketPackageProduct(
                ticket_package_track_id=occurrence.ticket_package_track_id,
                product_id=occurrence.product_id,
            )
        )
        with pytest.raises(IntegrityError, match=_UNIQUE):
            await db_session.flush()

    async def test_directly_excluded_occurrence_still_occupies_the_product(
        self,
        db_session: AsyncSession,
        ticket_package_product_factory: TicketPackageProductFactory,
    ) -> None:
        """The UNIQUE constraint is not partial: a soft-deleted occurrence
        still owns its Product within the track."""
        occurrence = await ticket_package_product_factory(deleted_at=datetime.now(UTC))
        db_session.add(
            TicketPackageProduct(
                ticket_package_track_id=occurrence.ticket_package_track_id,
                product_id=occurrence.product_id,
            )
        )
        with pytest.raises(IntegrityError, match=_UNIQUE):
            await db_session.flush()

    async def test_same_product_on_different_tracks_accepted(
        self,
        product_factory: ProductFactory,
        ticket_package_product_factory: TicketPackageProductFactory,
    ) -> None:
        product = await product_factory()
        first = await ticket_package_product_factory(product_id=product.id)
        second = await ticket_package_product_factory(product_id=product.id)
        assert first.ticket_package_track_id != second.ticket_package_track_id

    async def test_different_products_on_same_track_accepted(
        self,
        ticket_package_track_factory: TicketPackageTrackFactory,
        ticket_package_product_factory: TicketPackageProductFactory,
    ) -> None:
        track = await ticket_package_track_factory()
        first = await ticket_package_product_factory(ticket_package_track_id=track.id)
        second = await ticket_package_product_factory(ticket_package_track_id=track.id)
        assert first.product_id != second.product_id


@pytest.mark.integration
class TestTicketPackageProductNotNullConstraints:
    @pytest.mark.parametrize(
        "column",
        [
            "ticket_package_track_id",
            "product_id",
            "eligible",
            "is_eligible_override",
            "created_at",
            "updated_at",
        ],
    )
    async def test_explicit_null_rejected(
        self,
        db_session: AsyncSession,
        product_factory: ProductFactory,
        ticket_package_track_factory: TicketPackageTrackFactory,
        column: str,
    ) -> None:
        """A Core INSERT with an explicit NULL bypasses the ORM, which
        would otherwise omit a `None` server-defaulted column."""
        track = await ticket_package_track_factory()
        product = await product_factory()
        values: dict[str, object] = {
            "ticket_package_track_id": track.id,
            "product_id": product.id,
            column: None,
        }
        with pytest.raises(IntegrityError, match="not-null"):
            await db_session.execute(insert(TicketPackageProduct).values(values))

    @pytest.mark.parametrize("column", ["released_at", "deleted_at"])
    async def test_nullable_timestamp_accepts_null(
        self,
        db_session: AsyncSession,
        ticket_package_product_factory: TicketPackageProductFactory,
        column: str,
    ) -> None:
        occurrence = await ticket_package_product_factory(**{column: datetime.now(UTC)})
        setattr(occurrence, column, None)
        await db_session.flush()
        await db_session.refresh(occurrence)
        assert getattr(occurrence, column) is None


@pytest.mark.integration
class TestTicketPackageProductForeignKeys:
    @pytest.mark.parametrize(
        ("column", "constraint"),
        [("ticket_package_track_id", _TRACK_FK), ("product_id", _PRODUCT_FK)],
    )
    async def test_nonexistent_reference_rejected(
        self,
        db_session: AsyncSession,
        product_factory: ProductFactory,
        ticket_package_track_factory: TicketPackageTrackFactory,
        column: str,
        constraint: str,
    ) -> None:
        track = await ticket_package_track_factory()
        product = await product_factory()
        values: dict[str, uuid.UUID] = {
            "ticket_package_track_id": track.id,
            "product_id": product.id,
            column: uuid.uuid7(),
        }
        db_session.add(TicketPackageProduct(**values))
        with pytest.raises(IntegrityError, match=constraint):
            await db_session.flush()


@pytest.mark.integration
class TestParentDeleteRejectedWhileOccurrencesExist:
    """Tracks are soft-deleted and Products are retained. Both FKs use the
    PostgreSQL default NO ACTION (#633 decision A3), and
    `TicketPackageTrack.products` and `Product.ticket_package_products` use
    `passive_deletes="all"`, so deleting a parent with occurrences fails on
    the FK instead of the ORM nulling the occurrence's FK first. The ORM
    tests load the collection before deleting, which is when the ORM would
    otherwise do so."""

    async def test_orm_track_delete_with_loaded_products_raises(
        self,
        db_session: AsyncSession,
        ticket_package_product_factory: TicketPackageProductFactory,
    ) -> None:
        occurrence = await ticket_package_product_factory()
        track = await db_session.get(
            TicketPackageTrack, occurrence.ticket_package_track_id
        )
        assert track is not None
        await db_session.refresh(track, ["products"])
        assert len(track.products) == 1

        await db_session.delete(track)
        with pytest.raises(IntegrityError, match=_TRACK_FK):
            await db_session.flush()

    async def test_orm_product_delete_with_loaded_occurrences_raises(
        self,
        db_session: AsyncSession,
        ticket_package_product_factory: TicketPackageProductFactory,
    ) -> None:
        occurrence = await ticket_package_product_factory()
        product = await db_session.get(Product, occurrence.product_id)
        assert product is not None
        await db_session.refresh(product, ["ticket_package_products"])
        assert len(product.ticket_package_products) == 1

        await db_session.delete(product)
        with pytest.raises(IntegrityError, match=_PRODUCT_FK):
            await db_session.flush()

    async def test_database_track_delete_raises(
        self,
        db_session: AsyncSession,
        ticket_package_product_factory: TicketPackageProductFactory,
    ) -> None:
        occurrence = await ticket_package_product_factory()
        track_id = occurrence.ticket_package_track_id
        db_session.expunge_all()

        with pytest.raises(IntegrityError, match=_TRACK_FK):
            await db_session.execute(
                delete(TicketPackageTrack).where(TicketPackageTrack.id == track_id)
            )

    async def test_database_product_delete_raises(
        self,
        db_session: AsyncSession,
        ticket_package_product_factory: TicketPackageProductFactory,
    ) -> None:
        occurrence = await ticket_package_product_factory()
        product_id = occurrence.product_id
        db_session.expunge_all()

        with pytest.raises(IntegrityError, match=_PRODUCT_FK):
            await db_session.execute(delete(Product).where(Product.id == product_id))


@pytest.mark.integration
class TestTicketPackageProductRelationships:
    async def test_track_products_round_trip(
        self,
        db_session: AsyncSession,
        ticket_package_track_factory: TicketPackageTrackFactory,
        ticket_package_product_factory: TicketPackageProductFactory,
    ) -> None:
        track = await ticket_package_track_factory()
        first = await ticket_package_product_factory(ticket_package_track_id=track.id)
        second = await ticket_package_product_factory(ticket_package_track_id=track.id)
        await ticket_package_product_factory()

        await db_session.refresh(first, ["ticket_package_track"])
        await db_session.refresh(track, ["products"])

        assert first.ticket_package_track is track
        assert {p.id for p in track.products} == {first.id, second.id}

    async def test_product_occurrences_round_trip(
        self,
        db_session: AsyncSession,
        product_factory: ProductFactory,
        ticket_package_product_factory: TicketPackageProductFactory,
    ) -> None:
        product = await product_factory()
        first = await ticket_package_product_factory(product_id=product.id)
        second = await ticket_package_product_factory(product_id=product.id)
        await ticket_package_product_factory()

        await db_session.refresh(first, ["product"])
        await db_session.refresh(product, ["ticket_package_products"])

        assert first.product is product
        assert {p.id for p in product.ticket_package_products} == {
            first.id,
            second.id,
        }


@pytest.mark.integration
class TestTicketPackageProductTimestamps:
    async def test_timestamps_are_timezone_aware(
        self,
        db_session: AsyncSession,
        ticket_package_product_factory: TicketPackageProductFactory,
    ) -> None:
        now = datetime.now(UTC)
        occurrence = await ticket_package_product_factory(
            released_at=now, deleted_at=now
        )
        await db_session.refresh(occurrence)
        assert occurrence.created_at.tzinfo is not None
        assert occurrence.updated_at.tzinfo is not None
        assert occurrence.released_at is not None
        assert occurrence.released_at.tzinfo is not None
        assert occurrence.deleted_at is not None
        assert occurrence.deleted_at.tzinfo is not None

    async def test_updated_at_advances_on_update(
        self,
        db_session: AsyncSession,
        ticket_package_product_factory: TicketPackageProductFactory,
    ) -> None:
        """Backdating pattern (docs/features/platform/testing-strategy.md,
        `server_default=func.now()` and `onupdate=func.now()` Testing)."""
        occurrence = await ticket_package_product_factory()
        backdated = datetime.now(UTC) - timedelta(days=7)
        occurrence.updated_at = backdated
        await db_session.flush()
        await db_session.refresh(occurrence)
        assert occurrence.updated_at == backdated

        occurrence.eligible = False
        await db_session.flush()
        await db_session.refresh(occurrence)

        assert occurrence.updated_at > backdated

    async def test_created_at_unchanged_on_update(
        self,
        db_session: AsyncSession,
        ticket_package_product_factory: TicketPackageProductFactory,
    ) -> None:
        occurrence = await ticket_package_product_factory()
        backdated = datetime.now(UTC) - timedelta(days=7)
        occurrence.created_at = backdated
        await db_session.flush()

        occurrence.is_eligible_override = True
        await db_session.flush()
        await db_session.refresh(occurrence)

        assert occurrence.created_at == backdated
