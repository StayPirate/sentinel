"""TicketReference model — curated external links of a Ticket.

See `docs/data-model.md` (TicketReference, ReferenceType Enum) and
`docs/features/tickets/ticket-references.md` (Data Model) for the full
specification. This module implements only the persistence root; URL
validation and normalization, type classification, automatic upsert, and
manual mutation belong to the reference services.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import (
    DateTime,
    ForeignKey,
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


class TicketReference(Base):
    """An external link associated with a Ticket.

    `id` is the public locator of this nested sub-resource. `url` holds the
    service-normalized value, and `(ticket_id, url)` is the final database
    backstop for concurrent writers. `type` stores a `ReferenceType` value
    (Category B, no CHECK constraint) or `NULL` when uncategorized.
    `source` is a stable fetcher name or exactly `manual`.
    """

    __tablename__ = "ticket_reference"
    __table_args__ = (
        UniqueConstraint("ticket_id", "url", name="uq_ticket_reference_ticket_id_url"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid7,
        server_default=text("uuidv7()"),
    )
    ticket_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("ticket.id", ondelete="CASCADE"),
        nullable=False,
    )
    url: Mapped[str] = mapped_column(String(2048), nullable=False)
    title: Mapped[str | None] = mapped_column(String(500), nullable=True)
    description: Mapped[str | None] = mapped_column(String(2000), nullable=True)
    type: Mapped[str | None] = mapped_column(String(20), nullable=True)
    source: Mapped[str] = mapped_column(String(100), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )

    ticket: Mapped[Ticket] = relationship("Ticket", back_populates="references")
