"""Response schemas for the Ticket audit log endpoint.

See `docs/features/tickets/ticket-audit-log.md` (API > List Ticket
Events) for the authoritative response contract these schemas implement.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field

from app.schemas.common import PaginationMeta, UserReference


class TicketAuditEventData(BaseModel):
    """One Ticket audit event.

    `ticket_id` is the parent's canonical `SNTL-{n}` identity; the
    internal Ticket UUID is never exposed (`docs/api-spec.md`, Ticket
    Identifier Resolution). `id` is the event's own UUID. `actor` is the
    complete current User reference, or `null` for a system event.
    """

    id: UUID
    ticket_id: str = Field(
        description="Canonical Ticket identity (`SNTL-{n}`).",
        examples=["SNTL-42"],
    )
    event_type: str
    old_value: str | None
    new_value: str | None
    comment: str | None
    detail: dict[str, Any] | None
    created_at: datetime
    actor: UserReference | None


class TicketAuditListResponse(BaseModel):
    """Response body for `GET /api/v1/tickets/{ticket_id}/audit-log`."""

    data: list[TicketAuditEventData]
    meta: PaginationMeta
