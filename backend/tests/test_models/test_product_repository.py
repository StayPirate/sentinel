"""Integration tests for the ProductRepository model
(backend/app/models/product_repository.py).

See docs/data-model.md (ProductRepository) and
docs/features/packages/product-catalog.md (Data Model, ProductRepository).
Only the persistence contract is covered here; catalog synchronization and
current/historical traversal are service behavior. Deletion protection of
the referenced Product is covered in `test_product.py`.
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import CheckConstraint, insert, text
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.product import Product
from app.models.product_repository import ProductRepository

ProductFactory = Callable[..., Awaitable[Product]]
ProductRepositoryFactory = Callable[..., Awaitable[ProductRepository]]


@pytest.mark.integration
class TestProductRepositoryCreation:
    async def test_create_with_defaults(
        self, product_repository_factory: ProductRepositoryFactory
    ) -> None:
        association = await product_repository_factory()

        assert association.id.version == 7
        assert association.product_id is not None
        assert association.repo_name.startswith("Example:Updates:")
        assert association.catalog_last_seen_at.tzinfo is not None
        assert association.created_at is not None
        assert association.updated_at is not None

    async def test_create_with_every_column(
        self,
        db_session: AsyncSession,
        product_factory: ProductFactory,
        product_repository_factory: ProductRepositoryFactory,
    ) -> None:
        product = await product_factory()
        seen_at = datetime(2026, 9, 1, 1, 0, tzinfo=UTC)
        association = await product_repository_factory(
            product_id=product.id,
            repo_name="Example:Updates:Server:15-SP9:x86_64",
            catalog_last_seen_at=seen_at,
        )
        association_id = association.id
        db_session.expunge(association)

        reloaded = await db_session.get(ProductRepository, association_id)
        assert reloaded is not None
        assert reloaded.product_id == product.id
        assert reloaded.repo_name == "Example:Updates:Server:15-SP9:x86_64"
        assert reloaded.catalog_last_seen_at == seen_at

    async def test_raw_insert_applies_server_defaults(
        self, db_session: AsyncSession, product_factory: ProductFactory
    ) -> None:
        """A raw SQL INSERT bypasses every Python-side default, so the
        `uuidv7()` and `now()` server defaults must supply the columns."""
        product = await product_factory()
        result = await db_session.execute(
            text(
                "INSERT INTO product_repository "
                "(product_id, repo_name, catalog_last_seen_at) "
                "VALUES (:product_id, 'Example:Raw', now()) "
                "RETURNING id, created_at, updated_at"
            ),
            {"product_id": product.id},
        )
        row = result.one()
        assert isinstance(row.id, uuid.UUID)
        assert row.id.version == 7
        assert row.created_at.tzinfo is not None
        assert row.updated_at == row.created_at


@pytest.mark.unit
class TestProductRepositorySchemaShape:
    """No undocumented CHECK constraint or standalone index (#633 decision
    A2); the `(product_id, repo_name)` UNIQUE constraint covers the
    `product_id` access path."""

    def test_no_check_constraint_or_standalone_index(self) -> None:
        table = ProductRepository.metadata.tables["product_repository"]
        assert not [c for c in table.constraints if isinstance(c, CheckConstraint)]
        assert table.indexes == set()

    def test_catalog_last_seen_at_has_no_default(self) -> None:
        column = ProductRepository.__table__.c.catalog_last_seen_at
        assert column.default is None
        assert column.server_default is None


@pytest.mark.integration
class TestProductRepositoryColumnLengths:
    async def test_documented_maximum_accepted(
        self, product_repository_factory: ProductRepositoryFactory
    ) -> None:
        association = await product_repository_factory(repo_name="a" * 255)
        assert len(association.repo_name) == 255

    async def test_value_over_documented_maximum_rejected(
        self, product_repository_factory: ProductRepositoryFactory
    ) -> None:
        # asyncpg surfaces the truncation as a generic DBAPIError.
        with pytest.raises(DBAPIError, match="value too long"):
            await product_repository_factory(repo_name="a" * 256)


@pytest.mark.integration
class TestProductRepositoryUniqueness:
    async def test_duplicate_association_rejected(
        self,
        db_session: AsyncSession,
        product_factory: ProductFactory,
        product_repository_factory: ProductRepositoryFactory,
    ) -> None:
        product = await product_factory()
        await product_repository_factory(product_id=product.id, repo_name="Example:A")
        db_session.add(
            ProductRepository(
                product_id=product.id,
                repo_name="Example:A",
                catalog_last_seen_at=datetime.now(UTC),
            )
        )
        with pytest.raises(
            IntegrityError, match="uq_product_repository_product_id_repo_name"
        ):
            await db_session.flush()

    async def test_same_repo_name_on_different_products_accepted(
        self, product_repository_factory: ProductRepositoryFactory
    ) -> None:
        """Repository names are not globally unique."""
        first = await product_repository_factory(repo_name="Example:Shared")
        second = await product_repository_factory(repo_name="Example:Shared")
        assert first.product_id != second.product_id

    async def test_different_repo_names_on_same_product_accepted(
        self,
        product_factory: ProductFactory,
        product_repository_factory: ProductRepositoryFactory,
    ) -> None:
        product = await product_factory()
        await product_repository_factory(product_id=product.id, repo_name="Example:A")
        await product_repository_factory(product_id=product.id, repo_name="Example:B")

    async def test_database_compares_stored_repo_name_exactly(
        self,
        product_factory: ProductFactory,
        product_repository_factory: ProductRepositoryFactory,
    ) -> None:
        """Source values are preserved exactly: case variants are distinct
        associations at the model layer."""
        product = await product_factory()
        await product_repository_factory(product_id=product.id, repo_name="Example:A")
        await product_repository_factory(product_id=product.id, repo_name="EXAMPLE:A")


@pytest.mark.integration
class TestProductRepositoryNotNullConstraints:
    @pytest.mark.parametrize(
        "column",
        ["product_id", "repo_name", "catalog_last_seen_at", "created_at", "updated_at"],
    )
    async def test_explicit_null_rejected(
        self, db_session: AsyncSession, product_factory: ProductFactory, column: str
    ) -> None:
        """A Core INSERT with an explicit NULL bypasses the ORM, which
        would otherwise omit a `None` server-defaulted column."""
        product = await product_factory()
        values: dict[str, object] = {
            "product_id": product.id,
            "repo_name": "Example:Null",
            "catalog_last_seen_at": datetime.now(UTC),
            column: None,
        }
        with pytest.raises(IntegrityError, match="not-null"):
            await db_session.execute(insert(ProductRepository).values(values))

    async def test_omitted_catalog_last_seen_at_rejected(
        self, db_session: AsyncSession, product_factory: ProductFactory
    ) -> None:
        """`catalog_last_seen_at` has no default: omitting it fails."""
        product = await product_factory()
        db_session.add(ProductRepository(product_id=product.id, repo_name="Example:A"))
        with pytest.raises(IntegrityError, match="catalog_last_seen_at"):
            await db_session.flush()


@pytest.mark.integration
class TestProductRepositoryForeignKey:
    async def test_nonexistent_product_rejected(self, db_session: AsyncSession) -> None:
        db_session.add(
            ProductRepository(
                product_id=uuid.uuid7(),
                repo_name="Example:Orphan",
                catalog_last_seen_at=datetime.now(UTC),
            )
        )
        with pytest.raises(IntegrityError, match="product_repository_product_id_fkey"):
            await db_session.flush()

    def test_foreign_key_uses_default_no_action(self) -> None:
        """No ON DELETE action is documented: the PostgreSQL default
        NO ACTION applies (#633 decision A3)."""
        (fk,) = ProductRepository.__table__.c.product_id.foreign_keys
        assert fk.target_fullname == "product.id"
        assert fk.ondelete is None


@pytest.mark.integration
class TestProductRepositoryRelationships:
    async def test_product_repositories_round_trip(
        self,
        db_session: AsyncSession,
        product_factory: ProductFactory,
        product_repository_factory: ProductRepositoryFactory,
    ) -> None:
        product = await product_factory()
        first = await product_repository_factory(product_id=product.id)
        second = await product_repository_factory(product_id=product.id)
        await product_repository_factory()

        await db_session.refresh(first, ["product"])
        await db_session.refresh(product, ["repositories"])

        assert first.product is product
        assert {r.id for r in product.repositories} == {first.id, second.id}


@pytest.mark.integration
class TestProductRepositoryTimestamps:
    async def test_timestamps_are_timezone_aware(
        self,
        db_session: AsyncSession,
        product_repository_factory: ProductRepositoryFactory,
    ) -> None:
        association = await product_repository_factory()
        await db_session.refresh(association)
        assert association.created_at.tzinfo is not None
        assert association.updated_at.tzinfo is not None
        assert association.catalog_last_seen_at.tzinfo is not None

    async def test_updated_at_advances_on_update(
        self,
        db_session: AsyncSession,
        product_repository_factory: ProductRepositoryFactory,
    ) -> None:
        """Backdating pattern (docs/features/platform/testing-strategy.md,
        `server_default=func.now()` and `onupdate=func.now()` Testing)."""
        association = await product_repository_factory()
        backdated = datetime.now(UTC) - timedelta(days=7)
        association.updated_at = backdated
        await db_session.flush()
        await db_session.refresh(association)
        assert association.updated_at == backdated

        association.catalog_last_seen_at = datetime.now(UTC)
        await db_session.flush()
        await db_session.refresh(association)

        assert association.updated_at > backdated
