"""Response schemas for the standard API error envelope.

See `docs/api-spec.md` (Response Format) for the authoritative error
body contract. Used only for OpenAPI documentation (`responses={...}`)
— API handlers raise `app.core.errors.AppError`, whose exception
handler (registered in `app.main`) builds the actual JSON body; these
schemas never construct a response themselves.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class ErrorResponse(BaseModel):
    """The standard `{"code": ..., "detail": ...}` error body."""

    code: str
    detail: str


class TicketCVEConflictErrorResponse(ErrorResponse):
    """The `409 TICKET_CVE_CONFLICT` body: the standard envelope plus the
    conflicting Ticket's identity (`docs/api-spec.md`, Response Format;
    `docs/features/tickets/tickets.md`, CVE Resolution Behavior)."""

    existing_ticket_id: str = Field(
        description=(
            "Canonical identity (`SNTL-{n}`) of the Ticket already associated "
            "with the CVE. Only for `TICKET_CVE_CONFLICT`; it is returned even "
            "when that Ticket is otherwise inaccessible, and following it "
            "applies ordinary accessibility (identifier only, no Ticket "
            "content)."
        ),
        examples=["SNTL-42"],
    )
