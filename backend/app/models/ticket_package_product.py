"""TicketPackageProduct model — one Product occurrence below one package track.

See `docs/data-model.md` (TicketPackageProduct) and
`docs/features/packages/package-model.md` (Data Model, Axis 2: Eligibility,
Package Eligibility > Override Model, Exclusion and Actionability) for the full
specification. This module implements only the persistence record;
eligibility computation, override set and clear, recalculation, release
confirmation, exclusion and restoration, and actionability belong to
`package_service` (and, for the narrow CVSS-chain exception, to
`ticket_mutations`).
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    UniqueConstraint,
    false,
    func,
    text,
    true,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base

if TYPE_CHECKING:
    from app.models.product import Product
    from app.models.ticket_package_track import TicketPackageTrack


class TicketPackageProduct(Base):
    """The eligibility and release confirmation of one Product in one track.

    A Product occurs at most once per track by `(ticket_package_track_id,
    product_id)`, which also covers the `ticket_package_track_id` access
    path; `ix_ticket_package_product_product_id` serves the Product-keyed
    occurrence selections. `eligible` is the effective eligibility (new
    records default to `true`); `is_eligible_override` (default `false`)
    marks a manual eligibility that automatic workflows do not modify.
    `released_at` is the authoritative advisory-issued time, `NULL` until
    Product release detection confirms an exact match. `deleted_at` is the
    direct manual-exclusion marker; current actionability and lifecycle phase
    are derived at read time and never persisted. Both FKs use the PostgreSQL
    default `NO ACTION` (#633 decision A3): tracks are soft-deleted and
    Products are retained.
    """

    __tablename__ = "ticket_package_product"
    __table_args__ = (
        UniqueConstraint(
            "ticket_package_track_id",
            "product_id",
            name="uq_ticket_package_product_ticket_package_track_id_product_id",
        ),
        # Non-unique, non-partial (docs/data-model.md, TicketPackageProduct,
        # Indexes).
        Index("ix_ticket_package_product_product_id", "product_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid7,
        server_default=text("uuidv7()"),
    )
    ticket_package_track_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("ticket_package_track.id"), nullable=False
    )
    product_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("product.id"), nullable=False
    )
    eligible: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default=true()
    )
    is_eligible_override: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=false()
    )
    released_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    deleted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
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

    ticket_package_track: Mapped[TicketPackageTrack] = relationship(
        "TicketPackageTrack", back_populates="products"
    )
    product: Mapped[Product] = relationship(
        "Product", back_populates="ticket_package_products"
    )
