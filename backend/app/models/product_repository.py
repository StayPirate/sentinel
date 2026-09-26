"""ProductRepository model — a SMELT repository project of one Product.

See `docs/data-model.md` (ProductRepository) and
`docs/features/packages/product-catalog.md` (Data Model, ProductRepository)
for the full specification. This module implements only the persistence
association; catalog synchronization and current/historical traversal for
release detection belong to the Product and release-detection services.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, String, UniqueConstraint, func, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base

if TYPE_CHECKING:
    from app.models.product import Product


class ProductRepository(Base):
    """One SMELT repository project name associated with one Product.

    Repository names are not globally unique; an association is unique by
    `(product_id, repo_name)`, which also covers the `product_id` access
    path. `catalog_last_seen_at` is the shared timestamp of the latest
    complete SMELT snapshot that observed the association; an association
    is current when it equals the latest snapshot timestamp and historical
    otherwise. Associations are retained, never deleted. The FK uses the
    PostgreSQL default `NO ACTION` (#633 decision A3).
    """

    __tablename__ = "product_repository"
    __table_args__ = (
        UniqueConstraint(
            "product_id",
            "repo_name",
            name="uq_product_repository_product_id_repo_name",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid7,
        server_default=text("uuidv7()"),
    )
    product_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("product.id"), nullable=False
    )
    repo_name: Mapped[str] = mapped_column(String(255), nullable=False)
    catalog_last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )

    product: Mapped[Product] = relationship("Product", back_populates="repositories")
