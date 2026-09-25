"""TicketAccessGrant model — explicit access to a confidential Ticket.

See `docs/data-model.md` (TicketAccessGrant, Notes) and
`docs/features/tickets/tickets.md` (Confidential Tickets) for the full
specification. This module implements only the persistence root; grant
creation, revocation, declassification deletion, and the canonical
visibility predicate belong to the ticket services.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base

if TYPE_CHECKING:
    from app.models.ticket import Ticket
    from app.models.user import User


class TicketAccessGrant(Base):
    """One manual grant of explicit access to one user on one Ticket.

    Composite primary key `(ticket_id, user_id)`: both columns reference
    existing rows, so neither generates a UUID (the documented exception
    to the UUIDv7 primary key convention, `docs/data-model.md`, Notes).
    Every FK uses `ON DELETE RESTRICT` because Tickets are never deleted
    and users are deactivated, not deleted. `granted_at` replaces
    `created_at` for this write-once record; there is no `updated_at`.
    """

    __tablename__ = "ticket_access_grant"

    ticket_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("ticket.id", ondelete="RESTRICT"),
        primary_key=True,
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("user.id", ondelete="RESTRICT"),
        primary_key=True,
    )
    granted_by_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("user.id", ondelete="RESTRICT"),
        nullable=False,
    )
    granted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    ticket: Mapped[Ticket] = relationship("Ticket", back_populates="access_grants")
    # Read-only convenience relationships for the current target and
    # granting user profiles (tickets.md, TicketAccessGrantResponse).
    # Deliberately unidirectional and `viewonly=True`: User gets no reverse
    # collection, and grants are managed only through their own columns.
    user: Mapped[User] = relationship("User", foreign_keys=[user_id], viewonly=True)
    granted_by: Mapped[User] = relationship(
        "User", foreign_keys=[granted_by_id], viewonly=True
    )
