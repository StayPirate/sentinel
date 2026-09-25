"""TicketAuditEvent model — audit trail for semantic Ticket events.

See `docs/data-model.md` (TicketAuditEvent, TicketAuditEventType Enum),
`docs/features/platform/audit-trail-infrastructure.md` (AuditEventMixin,
Indexing, Immutability), and `docs/features/tickets/ticket-audit-log.md`
(Event Type Contract) for the full specification. This module implements
only the persistence root; the `TicketAuditLog` service subclass owns the
typed `log_event()` contract, including `event_type`, `comment`, and
`detail` validation.
"""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING, Any

from sqlalchemy import ForeignKey, Index, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base
from app.models.mixins import AuditEventMixin

if TYPE_CHECKING:
    from app.models.ticket import Ticket
    from app.models.user import User


class TicketAuditEvent(Base, AuditEventMixin):
    """One semantic Ticket event required by the canonical mutation matrix.

    Inherits `id`, `created_at`, and the nullable actor `user_id` (with
    their indexes) from `AuditEventMixin`; append-only, so there is no
    `updated_at`. `event_type` stores a `TicketAuditEventType` value
    (Category B, no CHECK constraint). `ticket_id` is the mandatory
    parent-scope filter of every Ticket audit query and is indexed. Its
    FK has no ON DELETE action (PostgreSQL `NO ACTION`): Tickets are never
    deleted, so deleting a Ticket with events fails loudly.
    """

    __tablename__ = "ticket_audit_event"
    __table_args__ = (Index("ix_ticket_audit_event_ticket_id", "ticket_id"),)

    ticket_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("ticket.id"), nullable=False
    )
    event_type: Mapped[str] = mapped_column(String(50), nullable=False)
    old_value: Mapped[str | None] = mapped_column(Text, nullable=True)
    new_value: Mapped[str | None] = mapped_column(Text, nullable=True)
    comment: Mapped[str | None] = mapped_column(Text, nullable=True)
    detail: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)

    ticket: Mapped[Ticket] = relationship("Ticket", back_populates="audit_events")
    # Read-only convenience relationship resolving the current actor
    # profile at read time (audit-trail-infrastructure.md, Human-Readable
    # Subjects). Deliberately unidirectional and `viewonly=True`, like the
    # other audit trails: this model is append-only and User gets no
    # reverse collection.
    actor: Mapped[User | None] = relationship(
        "User", foreign_keys="TicketAuditEvent.user_id", viewonly=True
    )
