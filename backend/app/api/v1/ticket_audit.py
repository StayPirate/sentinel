"""Ticket audit log endpoint.

See `docs/features/tickets/ticket-audit-log.md` (API > List Ticket
Events) for the authoritative endpoint contract. The handler stays thin:
it validates transport input, delegates the protected read to
`ticket_audit_log.list_ticket_events()`, and maps the result or the
shared `TicketNotFoundError` to HTTP. No business logic or database
query lives here.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query

from app.api.dependencies import (
    AuthenticatedTicketCaller,
    TicketIdPath,
    require_accessible_ticket,
    ticket_not_found_error,
)
from app.core.dates import parse_date_range_bound, validate_date_range_order
from app.core.enums import TicketAuditEventType
from app.core.exceptions import TicketNotFoundError
from app.database import DatabaseSession
from app.schemas.common import PaginationMeta, UserReference
from app.schemas.errors import ErrorResponse
from app.schemas.ticket_audit import TicketAuditEventData, TicketAuditListResponse
from app.services import ticket_audit_log
from app.services.ticket_audit_log import TicketEventItem
from app.services.ticket_service import ResolvedTicket

router = APIRouter(prefix="/api/v1", tags=["Ticket Audit Log"])


def parse_event_types(raw: list[str]) -> list[TicketAuditEventType] | None:
    """Resolve the raw repeatable `event_type` values to the typed filter.

    Returns `None` when the parameter was not supplied (no filter), or
    the valid members otherwise. Invalid values are silently dropped, so
    an all-invalid filter yields an empty list, which the service turns
    into an empty page only after the parent Ticket is proven accessible
    (`docs/api-spec.md`, Enum Filter Validation).
    """
    if not raw:
        return None
    valid: list[TicketAuditEventType] = []
    for value in raw:
        try:
            valid.append(TicketAuditEventType(value))
        except ValueError:
            continue
    return valid


def _serialize_event(event: TicketEventItem) -> TicketAuditEventData:
    return TicketAuditEventData(
        id=event.id,
        ticket_id=event.ticket_id,
        event_type=event.event_type,
        old_value=event.old_value,
        new_value=event.new_value,
        comment=event.comment,
        detail=event.detail,
        created_at=event.created_at,
        actor=(
            UserReference(
                id=event.actor.id,
                username=event.actor.username,
                full_name=event.actor.full_name,
                active=event.actor.active,
            )
            if event.actor is not None
            else None
        ),
    )


@router.get(
    "/tickets/{ticket_id}/audit-log",
    response_model=TicketAuditListResponse,
    summary="List Ticket audit events",
    description=(
        "Returns a paginated list of audit events for one Ticket, in fixed "
        "reverse-chronological order (created_at DESC, id DESC). Supports "
        "filtering by event type (repeatable), actor, text search, and "
        "inclusive date range. The Ticket is identified by its canonical "
        "SNTL-{n} identity. Requires authentication (JWT session or API "
        "key)."
    ),
    responses={
        404: {
            "model": ErrorResponse,
            "description": (
                "Ticket identifier is malformed, does not exist, or identifies "
                "a Ticket inaccessible to the caller."
            ),
        },
    },
)
async def list_ticket_events(
    ticket_id: TicketIdPath,
    db: DatabaseSession,
    caller: AuthenticatedTicketCaller,
    _ticket: Annotated[ResolvedTicket, Depends(require_accessible_ticket)],
    event_type: Annotated[
        list[str],
        Query(
            default_factory=list,
            description=(
                "Filter by event type. Repeatable; OR semantics. Invalid "
                "values are ignored."
            ),
        ),
    ],
    actor: Annotated[
        str | None,
        Query(description="Actor user UUID, exact username, or 'system'."),
    ] = None,
    search: Annotated[
        str | None,
        Query(
            description=(
                "Case-insensitive literal substring search across comment, "
                "old_value, new_value, and detail."
            )
        ),
    ] = None,
    from_date: Annotated[
        str | None,
        Query(description="ISO 8601 date/datetime; inclusive lower bound."),
    ] = None,
    to_date: Annotated[
        str | None,
        Query(description="ISO 8601 date/datetime; inclusive upper bound."),
    ] = None,
    page: Annotated[int, Query(ge=1, le=2_147_483_647, description="Page number.")] = 1,
    per_page: Annotated[
        int, Query(ge=1, le=100, description="Items per page; maximum 100.")
    ] = 20,
) -> TicketAuditListResponse:
    """List Ticket events — see `docs/features/tickets/ticket-audit-log.md`
    (List Ticket Events).

    `_ticket` runs the shared `require_accessible_ticket` boundary before
    the handler; the service re-applies Ticket visibility inside the one
    statement that selects the events and total, so the response never
    relies on that preliminary decision.
    """
    parsed_from = parse_date_range_bound("from_date", from_date)
    parsed_to = parse_date_range_bound("to_date", to_date)
    validate_date_range_order(parsed_from, parsed_to)
    try:
        result = await ticket_audit_log.list_ticket_events(
            db,
            ticket_id=ticket_id,
            caller=caller,
            event_types=parse_event_types(event_type),
            actor=actor,
            search=search,
            from_date=parsed_from,
            to_date=parsed_to,
            page=page,
            per_page=per_page,
        )
    except TicketNotFoundError:
        raise ticket_not_found_error() from None
    return TicketAuditListResponse(
        data=[_serialize_event(event) for event in result.items],
        meta=PaginationMeta(
            total=result.total, page=result.page, per_page=result.per_page
        ),
    )
