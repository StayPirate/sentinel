"""Product model — one SUSE Product of the local catalog.

See `docs/data-model.md` (Product) and
`docs/features/packages/product-catalog.md` (Data Model, Product Lifecycle
Phases) for the full specification. This module implements only the
persistence root; SMELT catalog synchronization, AIMAAS lifecycle and
threshold synchronization, catalog readiness, and Product queries belong to
the Product services.
"""

from __future__ import annotations

import uuid
from datetime import date, datetime
from decimal import Decimal
from typing import TYPE_CHECKING

from sqlalchemy import Date, DateTime, Numeric, String, func, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base

if TYPE_CHECKING:
    from app.models.product_repository import ProductRepository
    from app.models.ticket_package_product import TicketPackageProduct


class Product(Base):
    """A SUSE Product identified by its canonical CPE.

    `cpe` is the canonical identity and the exact SMELT/AIMAAS join key;
    `name`, `version`, and `display_name` are descriptive SMELT attributes
    with no identity constraint. `cvss_threshold` is the AIMAAS threshold
    (`NULL` means the implicit threshold of 0). The four lifecycle date
    columns are the AIMAAS projections consumed by the Lifecycle Evaluator;
    the lifecycle phase and catalog presence are derived at read time and
    never persisted. `catalog_last_seen_at` is the shared timestamp of the
    latest complete SMELT snapshot that observed the Product and has no
    default: the Product sync always assigns it. Products are retained,
    never deleted.
    """

    __tablename__ = "product"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid7,
        server_default=text("uuidv7()"),
    )
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    version: Mapped[str] = mapped_column(String(50), nullable=False)
    display_name: Mapped[str] = mapped_column(String(255), nullable=False)
    cpe: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    cvss_threshold: Mapped[Decimal | None] = mapped_column(Numeric(3, 1), nullable=True)
    first_customer_ship_date: Mapped[date | None] = mapped_column(Date, nullable=True)
    general_support_end_date: Mapped[date | None] = mapped_column(Date, nullable=True)
    extended_support_end_date: Mapped[date | None] = mapped_column(Date, nullable=True)
    reactive_support_end_date: Mapped[date | None] = mapped_column(Date, nullable=True)
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

    # passive_deletes="all": Products and their repository associations are
    # retained (docs/features/packages/product-catalog.md, Data Model).
    # Without it SQLAlchemy would try to null the NOT NULL `product_id` of
    # loaded associations before deleting the Product; the database FK
    # (default NO ACTION) must reject the delete instead.
    repositories: Mapped[list[ProductRepository]] = relationship(
        "ProductRepository",
        back_populates="product",
        passive_deletes="all",
    )
    # passive_deletes="all": Products are retained. Without it SQLAlchemy
    # would try to null the NOT NULL `product_id` of loaded Ticket package
    # occurrences before deleting the Product; the database FK (default
    # NO ACTION) must reject the delete instead.
    ticket_package_products: Mapped[list[TicketPackageProduct]] = relationship(
        "TicketPackageProduct",
        back_populates="product",
        passive_deletes="all",
    )
