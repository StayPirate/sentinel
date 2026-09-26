"""TicketPackage model — one source package anchored within one Ticket.

See `docs/data-model.md` (TicketPackage) and
`docs/features/packages/package-model.md` (Data Model, Exclusion and
Actionability) for the full specification. This module implements only the
persistence root of the package tree; package-tree creation, exclusion and
restoration, reconciliation, actionability, and package queries belong to
`package_service`.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import (
    DateTime,
    ForeignKey,
    Index,
    String,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base

if TYPE_CHECKING:
    from app.models.ticket import Ticket
    from app.models.ticket_package_track import TicketPackageTrack


class TicketPackage(Base):
    """A source package within one Ticket, grouping its tracks.

    A package name is unique per Ticket by `(ticket_id, package_name)`, which
    also covers the `ticket_id` access path; `ix_ticket_package_package_name`
    serves the cross-Ticket lookups by package name. `deleted_at` is the
    direct manual-exclusion marker (`NULL` = not directly excluded) and is
    written only by authorized user exclusion/restore operations. Current
    actionability is derived at read time and never persisted. Package
    records are soft-deleted, never hard-deleted; the FK uses the PostgreSQL
    default `NO ACTION` (#633 decision A3).
    """

    __tablename__ = "ticket_package"
    __table_args__ = (
        UniqueConstraint(
            "ticket_id",
            "package_name",
            name="uq_ticket_package_ticket_id_package_name",
        ),
        # Non-unique, non-partial (docs/data-model.md, TicketPackage, Indexes).
        Index("ix_ticket_package_package_name", "package_name"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid7,
        server_default=text("uuidv7()"),
    )
    ticket_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("ticket.id"), nullable=False
    )
    package_name: Mapped[str] = mapped_column(String(255), nullable=False)
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

    ticket: Mapped[Ticket] = relationship("Ticket", back_populates="packages")
    # passive_deletes="all": the package tree is soft-deleted, never
    # hard-deleted. Without it SQLAlchemy would try to null the NOT NULL
    # `ticket_package_id` of loaded tracks before deleting the package; the
    # database FK (default NO ACTION) must reject the delete instead.
    tracks: Mapped[list[TicketPackageTrack]] = relationship(
        "TicketPackageTrack",
        back_populates="ticket_package",
        passive_deletes="all",
    )
