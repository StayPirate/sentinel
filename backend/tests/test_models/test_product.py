"""Integration tests for the Product model (backend/app/models/product.py).

See docs/data-model.md (Product) and docs/features/packages/product-catalog.md
(Data Model, Product Lifecycle Phases). Only the persistence contract is
covered here; SMELT and AIMAAS synchronization, catalog readiness, and the
lifecycle SQL expression (tests/test_services/test_product_service.py) are
service behavior.
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable
from datetime import UTC, date, datetime, timedelta
from decimal import Decimal

import pytest
from sqlalchemy import CheckConstraint, delete, insert, text
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.product import Product
from app.models.product_repository import ProductRepository

ProductFactory = Callable[..., Awaitable[Product]]
ProductRepositoryFactory = Callable[..., Awaitable[ProductRepository]]

# Documented VARCHAR lengths (docs/data-model.md, Product).
_COLUMN_LENGTHS = {
    "name": 100,
    "version": 50,
    "display_name": 255,
    "cpe": 255,
}

_LIFECYCLE_DATE_COLUMNS = (
    "first_customer_ship_date",
    "general_support_end_date",
    "extended_support_end_date",
    "reactive_support_end_date",
)

_DOCUMENTED_COLUMNS = {
    "id",
    "name",
    "version",
    "display_name",
    "cpe",
    "cvss_threshold",
    *_LIFECYCLE_DATE_COLUMNS,
    "catalog_last_seen_at",
    "created_at",
    "updated_at",
}


def _valid_values(**overrides: object) -> dict[str, object]:
    values: dict[str, object] = {
        "name": "Example Product",
        "version": "1",
        "display_name": "EP 1",
        "cpe": "cpe:/o:example:product:core",
        "catalog_last_seen_at": datetime.now(UTC),
    }
    values.update(overrides)
    return values


@pytest.mark.integration
class TestProductCreation:
    async def test_create_with_defaults(self, product_factory: ProductFactory) -> None:
        product = await product_factory()

        assert product.id.version == 7
        assert product.cpe.startswith("cpe:/o:example:product:")
        assert product.cvss_threshold is None
        for column in _LIFECYCLE_DATE_COLUMNS:
            assert getattr(product, column) is None
        assert product.catalog_last_seen_at.tzinfo is not None
        assert product.created_at is not None
        assert product.updated_at is not None

    async def test_create_with_every_column(
        self, db_session: AsyncSession, product_factory: ProductFactory
    ) -> None:
        seen_at = datetime(2026, 9, 1, 1, 0, tzinfo=UTC)
        product = await product_factory(
            name="Example Server",
            version="15 SP9",
            display_name="Example Server 15 SP9",
            cpe="cpe:/o:example:server:15:sp9",
            cvss_threshold=Decimal("7.0"),
            first_customer_ship_date=date(2024, 1, 15),
            general_support_end_date=date(2026, 6, 30),
            extended_support_end_date=date(2029, 6, 30),
            reactive_support_end_date=date(2031, 6, 30),
            catalog_last_seen_at=seen_at,
        )
        product_id = product.id
        db_session.expunge(product)

        reloaded = await db_session.get(Product, product_id)
        assert reloaded is not None
        assert reloaded.name == "Example Server"
        assert reloaded.version == "15 SP9"
        assert reloaded.display_name == "Example Server 15 SP9"
        assert reloaded.cpe == "cpe:/o:example:server:15:sp9"
        assert reloaded.cvss_threshold == Decimal("7.0")
        assert reloaded.first_customer_ship_date == date(2024, 1, 15)
        assert reloaded.general_support_end_date == date(2026, 6, 30)
        assert reloaded.extended_support_end_date == date(2029, 6, 30)
        assert reloaded.reactive_support_end_date == date(2031, 6, 30)
        assert reloaded.catalog_last_seen_at == seen_at

    async def test_raw_insert_applies_server_defaults(
        self, db_session: AsyncSession
    ) -> None:
        """A raw SQL INSERT bypasses every Python-side default, so the
        `uuidv7()` and `now()` server defaults must supply the columns."""
        result = await db_session.execute(
            text(
                "INSERT INTO product "
                "(name, version, display_name, cpe, catalog_last_seen_at) "
                "VALUES ('Raw', '1', 'Raw 1', 'cpe:/o:example:raw:1', now()) "
                "RETURNING id, created_at, updated_at"
            )
        )
        row = result.one()
        assert isinstance(row.id, uuid.UUID)
        assert row.id.version == 7
        assert row.created_at.tzinfo is not None
        assert row.updated_at == row.created_at


@pytest.mark.unit
class TestProductSchemaShape:
    """Exactly the documented columns and constraints (#633 decisions A2):
    no lifecycle-phase or catalog-presence column, no CHECK constraint, and
    no standalone index (including none on `catalog_last_seen_at`)."""

    def test_columns_match_documented_set(self) -> None:
        assert set(Product.__table__.columns.keys()) == _DOCUMENTED_COLUMNS

    def test_no_check_constraint_or_standalone_index(self) -> None:
        table = Product.metadata.tables["product"]
        assert not [c for c in table.constraints if isinstance(c, CheckConstraint)]
        assert table.indexes == set()

    def test_catalog_last_seen_at_has_no_default(self) -> None:
        column = Product.__table__.c.catalog_last_seen_at
        assert column.default is None
        assert column.server_default is None


@pytest.mark.integration
class TestProductColumnLengths:
    @pytest.mark.parametrize(("column", "length"), list(_COLUMN_LENGTHS.items()))
    async def test_documented_maximum_accepted(
        self, product_factory: ProductFactory, column: str, length: int
    ) -> None:
        product = await product_factory(**{column: "a" * length})
        assert len(getattr(product, column)) == length

    @pytest.mark.parametrize(("column", "length"), list(_COLUMN_LENGTHS.items()))
    async def test_value_over_documented_maximum_rejected(
        self, product_factory: ProductFactory, column: str, length: int
    ) -> None:
        # asyncpg surfaces the truncation as a generic DBAPIError.
        with pytest.raises(DBAPIError, match="value too long"):
            await product_factory(**{column: "a" * (length + 1)})


@pytest.mark.integration
class TestProductCpeUniqueness:
    async def test_duplicate_cpe_rejected(
        self, db_session: AsyncSession, product_factory: ProductFactory
    ) -> None:
        await product_factory(cpe="cpe:/o:example:dup:1")
        db_session.add(Product(**_valid_values(cpe="cpe:/o:example:dup:1")))
        with pytest.raises(IntegrityError, match="product_cpe_key"):
            await db_session.flush()

    async def test_descriptive_fields_are_not_identity(
        self, product_factory: ProductFactory
    ) -> None:
        """`name`, `version`, and `display_name` carry no identity
        constraint; only `cpe` is unique."""
        first = await product_factory(name="Same", version="1", display_name="Same")
        second = await product_factory(name="Same", version="1", display_name="Same")
        assert first.cpe != second.cpe

    async def test_database_compares_stored_cpe_exactly(
        self, product_factory: ProductFactory
    ) -> None:
        """Source values are preserved exactly: the UNIQUE constraint
        compares the stored value, so case variants are distinct rows."""
        await product_factory(cpe="cpe:/o:example:case:1")
        await product_factory(cpe="cpe:/o:EXAMPLE:case:1")


@pytest.mark.integration
class TestProductNotNullConstraints:
    @pytest.mark.parametrize(
        "column",
        [
            "name",
            "version",
            "display_name",
            "cpe",
            "catalog_last_seen_at",
            "created_at",
            "updated_at",
        ],
    )
    async def test_explicit_null_rejected(
        self, db_session: AsyncSession, column: str
    ) -> None:
        """A Core INSERT with an explicit NULL bypasses the ORM, which
        would otherwise omit a `None` server-defaulted column."""
        with pytest.raises(IntegrityError, match="not-null"):
            await db_session.execute(
                insert(Product).values(_valid_values(**{column: None}))
            )

    async def test_omitted_catalog_last_seen_at_rejected(
        self, db_session: AsyncSession
    ) -> None:
        """`catalog_last_seen_at` has no default: omitting it fails."""
        values = _valid_values()
        del values["catalog_last_seen_at"]
        db_session.add(Product(**values))
        with pytest.raises(IntegrityError, match="catalog_last_seen_at"):
            await db_session.flush()

    @pytest.mark.parametrize("column", ["cvss_threshold", *_LIFECYCLE_DATE_COLUMNS])
    async def test_optional_columns_accept_null(
        self, db_session: AsyncSession, product_factory: ProductFactory, column: str
    ) -> None:
        value: object = (
            Decimal("5.0") if column == "cvss_threshold" else date(2027, 1, 1)
        )
        product = await product_factory(**{column: value})
        setattr(product, column, None)
        await db_session.flush()
        await db_session.refresh(product)
        assert getattr(product, column) is None


@pytest.mark.integration
class TestProductCvssThreshold:
    """`cvss_threshold` is `DECIMAL(3,1)` (docs/data-model.md, Product)."""

    @pytest.mark.parametrize("threshold", ["0.0", "0.1", "5.5", "9.9", "10.0"])
    async def test_one_decimal_value_round_trips_as_decimal(
        self, db_session: AsyncSession, product_factory: ProductFactory, threshold: str
    ) -> None:
        product = await product_factory(cvss_threshold=Decimal(threshold))
        await db_session.refresh(product)

        assert isinstance(product.cvss_threshold, Decimal)
        assert product.cvss_threshold == Decimal(threshold)
        assert str(product.cvss_threshold) == threshold

    async def test_value_is_stored_at_one_decimal_place(
        self, db_session: AsyncSession, product_factory: ProductFactory
    ) -> None:
        product = await product_factory(cvss_threshold=Decimal("7.25"))
        await db_session.refresh(product)
        assert str(product.cvss_threshold) == "7.3"

    async def test_value_beyond_precision_rejected(
        self, product_factory: ProductFactory
    ) -> None:
        with pytest.raises(DBAPIError, match="numeric field overflow"):
            await product_factory(cvss_threshold=Decimal("100.0"))


@pytest.mark.integration
class TestProductLifecycleDates:
    @pytest.mark.parametrize("column", _LIFECYCLE_DATE_COLUMNS)
    async def test_date_round_trips_as_calendar_date(
        self, db_session: AsyncSession, product_factory: ProductFactory, column: str
    ) -> None:
        product = await product_factory(**{column: date(2030, 2, 28)})
        await db_session.refresh(product)
        value = getattr(product, column)
        assert type(value) is date
        assert value == date(2030, 2, 28)


@pytest.mark.integration
class TestProductNoDeletionPropagation:
    """Products and repository associations are retained
    (docs/features/packages/product-catalog.md, Data Model). The FK uses the
    PostgreSQL default NO ACTION (#633 decision A3) and
    `Product.repositories` uses `passive_deletes="all"`, so deleting a
    referenced Product fails on the FK instead of the ORM nulling the
    association's `product_id` first."""

    async def test_orm_delete_with_loaded_repositories_raises(
        self,
        db_session: AsyncSession,
        product_factory: ProductFactory,
        product_repository_factory: ProductRepositoryFactory,
    ) -> None:
        product = await product_factory()
        await product_repository_factory(product_id=product.id)
        await db_session.refresh(product, ["repositories"])
        assert len(product.repositories) == 1

        await db_session.delete(product)
        with pytest.raises(IntegrityError, match="product_repository_product_id_fkey"):
            await db_session.flush()

    async def test_database_delete_raises(
        self,
        db_session: AsyncSession,
        product_factory: ProductFactory,
        product_repository_factory: ProductRepositoryFactory,
    ) -> None:
        product = await product_factory()
        await product_repository_factory(product_id=product.id)
        product_id = product.id
        db_session.expunge_all()

        with pytest.raises(IntegrityError, match="product_repository_product_id_fkey"):
            await db_session.execute(delete(Product).where(Product.id == product_id))


@pytest.mark.integration
class TestProductTimestamps:
    async def test_timestamps_are_timezone_aware(
        self, db_session: AsyncSession, product_factory: ProductFactory
    ) -> None:
        product = await product_factory()
        await db_session.refresh(product)
        assert product.created_at.tzinfo is not None
        assert product.updated_at.tzinfo is not None
        assert product.catalog_last_seen_at.tzinfo is not None

    async def test_updated_at_advances_on_update(
        self, db_session: AsyncSession, product_factory: ProductFactory
    ) -> None:
        """Backdating pattern (docs/features/platform/testing-strategy.md,
        `server_default=func.now()` and `onupdate=func.now()` Testing):
        `now()` is fixed for the test transaction, so the column is
        backdated explicitly before the mutation."""
        product = await product_factory()
        backdated = datetime.now(UTC) - timedelta(days=7)
        product.updated_at = backdated
        await db_session.flush()
        await db_session.refresh(product)
        assert product.updated_at == backdated

        product.display_name = "Renamed"
        await db_session.flush()
        await db_session.refresh(product)

        assert product.updated_at > backdated

    async def test_created_at_unchanged_on_update(
        self, db_session: AsyncSession, product_factory: ProductFactory
    ) -> None:
        product = await product_factory()
        backdated = datetime.now(UTC) - timedelta(days=7)
        product.created_at = backdated
        await db_session.flush()

        product.display_name = "Renamed"
        await db_session.flush()
        await db_session.refresh(product)

        assert product.created_at == backdated
