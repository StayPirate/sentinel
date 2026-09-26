"""Ticket reads, lifecycle operations, and cross-domain Ticket compositions.

See `docs/features/tickets/ticket-service.md` for the full
specification. This module currently implements the consumer-facing
Ticket locator resolution (Ticket Query Operations > Ticket locator
resolution); the remaining query and lifecycle operations are added by
their owning work items.

Every operation accepts the caller's `AsyncSession` and never commits or
rolls back; database exceptions propagate unchanged (Transaction
ownership).
"""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import TicketNotFoundError
from app.core.identifiers import parse_ticket_id
from app.models.ticket import Ticket
from app.services.ticket_visibility import TicketCaller, ticket_visibility_condition


@dataclass(frozen=True, slots=True)
class ResolvedTicket:
    """An accessible Ticket selected by its public `SNTL-{n}` locator.

    `id` is the internal Ticket UUID, usable only as an internal service
    locator; it is never a consumer response field. `sequence_id` is the
    `n` of the public identifier.
    """

    id: UUID
    sequence_id: int


async def resolve_ticket_locator(
    db: AsyncSession, ticket_id: str, caller: TicketCaller
) -> ResolvedTicket:
    """Resolve a consumer `SNTL-{n}` locator to an accessible Ticket.

    Category B read (ticket-service.md, Ticket locator resolution;
    api-spec.md, Ticket Identifier Resolution).

    Q1: `ticket_id` is the raw consumer locator (a path value);
    `caller` is the request-resolved caller information.

    Q3: parses the value with `core.identifiers.parse_ticket_id()` (no
    trimming or normalization), then selects the Ticket by
    `Ticket.sequence_id` in one statement constrained by the canonical
    visibility predicate. Creates no event, acquires no lock, and never
    commits or rolls back.

    Q4: returns the selected Ticket's internal UUID and sequence number.
    This is a preliminary decision only: it never authorizes a later
    unconstrained query. Reads re-apply visibility in the selection that
    returns data, and mutations revalidate against locked-current state.

    Q6: raises `TicketNotFoundError` when the locator is malformed
    (including a Ticket UUID), no Ticket has that sequence number, or the
    Ticket is inaccessible to `caller` — without distinguishing the
    causes. Malformed input performs no database query. Database
    exceptions propagate unchanged.
    """
    sequence_id = parse_ticket_id(ticket_id)
    if sequence_id is None:
        raise TicketNotFoundError()
    row = (
        await db.execute(
            select(Ticket.id, Ticket.sequence_id).where(
                Ticket.sequence_id == sequence_id,
                ticket_visibility_condition(caller),
            )
        )
    ).one_or_none()
    if row is None:
        raise TicketNotFoundError()
    return ResolvedTicket(id=row.id, sequence_id=row.sequence_id)
