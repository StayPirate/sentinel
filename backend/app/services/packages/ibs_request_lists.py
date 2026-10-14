"""Ticket-scoped IBS submission and release request lists.

See `docs/features/packages/ibs-submission-tracking.md` (Public API,
Common Query Rules, List Submission Requests, List Release Requests,
Security and Privacy) for the authoritative contract and
`docs/features/identity/rbac.md` (Scope and Confidential Ticket
Visibility) for the canonical predicate applied here.

`list_submission_requests()` and `list_release_requests()` share one
statement builder. Each executes exactly one SQL statement, so the parent
accessibility decision, the candidate set, its total, and the page come
from one PostgreSQL snapshot:

1. the parent Ticket, selected by `sequence_id` under
   `ticket_visibility_condition()`;
2. the distinct `IBSRequestAction.id` values correlated through
   `IBSRequestActionTrack` to a track of a package of that Ticket. Package
   and track exclusion, affectedness, actionability, and Ticket status are
   deliberately absent: persisted history is returned regardless;
3. the list's action type and the client filters, combined with AND;
4. the total of that candidate set and the requested page, ordered by the
   parent request's selected upstream timestamp, then `IBSRequestAction.id`,
   both in the requested direction;
5. the projection of each action with its parent request.

A malformed locator (including a Ticket UUID), a missing Ticket, and an
inaccessible Ticket raise `TicketNotFoundError`, never an empty page. Both
reads are Category B: they acquire no lock, write or flush nothing, create
no audit event, and perform no external, Redis, or broker I/O. Database
exceptions propagate unchanged.

The projection never selects authors, actors, comments, descriptions, raw
source or target fields, acceptinfo, or local row timestamps. The request
and incident links use the fixed IBS web origin; they are never derived
from `IBS_API_URL`.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Final

from sqlalchemy import ColumnElement, false, func, select, true
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import (
    IBSRequestActionType,
    IBSRequestSortField,
    IBSRequestState,
    SortOrder,
)
from app.core.exceptions import TicketNotFoundError
from app.core.identifiers import parse_ticket_id
from app.models.ibs_request import IBSRequest
from app.models.ibs_request_action import IBSRequestAction
from app.models.ibs_request_action_track import IBSRequestActionTrack
from app.models.ticket import Ticket
from app.models.ticket_package import TicketPackage
from app.models.ticket_package_track import TicketPackageTrack
from app.services.ticket_visibility import TicketCaller, ticket_visibility_condition

IBS_WEB_ORIGIN: Final = "https://build.suse.de"
"""Fixed IBS web origin of the request and incident links."""

MAX_PER_PAGE: Final = 100
"""Largest accepted `per_page` (docs/api-spec.md, Pagination)."""

INCIDENT_NUMBER_MAX: Final = 2_147_483_647
"""Largest accepted `incident_number` filter, the PostgreSQL `INTEGER`
maximum (ibs-submission-tracking.md, List Release Requests)."""


@dataclass(frozen=True, slots=True)
class IBSRequestActionItem:
    """One correlated request action with its parent request.

    `package_name` is the action's validated logical package. On the
    release list `incident_number` and `incident_url` are never `None`
    (the `maintenance_release` structural CHECK requires the incident).
    """

    id: uuid.UUID
    action_type: IBSRequestActionType
    request_number: int
    state: IBSRequestState
    superseded_by_request_number: int | None
    package_name: str
    codestream_name: str
    incident_number: int | None
    ibs_url: str
    incident_url: str | None
    upstream_created_at: datetime
    upstream_updated_at: datetime


@dataclass(frozen=True, slots=True)
class IBSRequestActionPage:
    """One page of correlated actions and the total of the candidate set."""

    items: tuple[IBSRequestActionItem, ...]
    total: int
    page: int
    per_page: int


def request_url(request_number: int) -> str:
    """The IBS web link of a request (ibs-submission-tracking.md, Public
    API: `ibs_url`)."""
    return f"{IBS_WEB_ORIGIN}/request/show/{request_number}"


def incident_url(incident_number: int) -> str:
    """The IBS web link of an incident project, reconstructed as
    `SUSE:Maintenance:{incident_number}` (ibs-submission-tracking.md,
    Public API: `incident_url`)."""
    return f"{IBS_WEB_ORIGIN}/project/show/SUSE:Maintenance:{incident_number}"


async def list_submission_requests(
    db: AsyncSession,
    *,
    ticket_id: str,
    caller: TicketCaller,
    package_name: str | None = None,
    codestream_name: str | None = None,
    state: IBSRequestState | None = None,
    state_was_supplied: bool = False,
    sort_by: IBSRequestSortField = IBSRequestSortField.UPSTREAM_UPDATED_AT,
    sort_order: SortOrder = SortOrder.DESC,
    page: int = 1,
    per_page: int = 20,
) -> IBSRequestActionPage:
    """List the distinct correlated `maintenance_incident` actions of one
    accessible Ticket (ibs-submission-tracking.md, List Submission
    Requests).

    Q1: `ticket_id` is the public `SNTL-{n}` locator and `caller` the
    request-resolved caller (anonymous allowed). `package_name` and
    `codestream_name` are exact, case-sensitive filters on the action's
    logical package and codestream. `state` is an exact parent request
    state; `state_was_supplied = True` with `state = None` represents a
    supplied value that is not a valid `IBSRequestState`, which matches no
    action. `page` is positive and `per_page` is 1-100.

    Q3: the one-statement read described in the module docstring.

    Q6: `TicketNotFoundError` for a malformed, missing, or inaccessible
    Ticket, before any filter outcome. `ValueError` before any query for
    `page < 1` or `per_page` outside 1-100. Database errors propagate.
    """
    return await _list_actions(
        db,
        action_type=IBSRequestActionType.MAINTENANCE_INCIDENT,
        ticket_id=ticket_id,
        caller=caller,
        package_name=package_name,
        codestream_name=codestream_name,
        state=state,
        state_was_supplied=state_was_supplied,
        incident_number=None,
        sort_by=sort_by,
        sort_order=sort_order,
        page=page,
        per_page=per_page,
    )


async def list_release_requests(
    db: AsyncSession,
    *,
    ticket_id: str,
    caller: TicketCaller,
    package_name: str | None = None,
    codestream_name: str | None = None,
    state: IBSRequestState | None = None,
    state_was_supplied: bool = False,
    incident_number: int | None = None,
    sort_by: IBSRequestSortField = IBSRequestSortField.UPSTREAM_UPDATED_AT,
    sort_order: SortOrder = SortOrder.DESC,
    page: int = 1,
    per_page: int = 20,
) -> IBSRequestActionPage:
    """List the distinct correlated `maintenance_release` actions of one
    accessible Ticket (ibs-submission-tracking.md, List Release Requests).

    Release actions are selected only through their direct
    `IBSRequestActionTrack` correlation, never inferred from request-level
    incident equality.

    Q1: as `list_submission_requests()`, plus `incident_number`, an exact
    incident filter within 1-`INCIDENT_NUMBER_MAX`.

    Q3: the one-statement read described in the module docstring.

    Q6: as `list_submission_requests()`; additionally `ValueError` before
    any query for an `incident_number` outside 1-`INCIDENT_NUMBER_MAX`.
    """
    if incident_number is not None and not 1 <= incident_number <= INCIDENT_NUMBER_MAX:
        raise ValueError(f"incident_number must be between 1 and {INCIDENT_NUMBER_MAX}")
    return await _list_actions(
        db,
        action_type=IBSRequestActionType.MAINTENANCE_RELEASE,
        ticket_id=ticket_id,
        caller=caller,
        package_name=package_name,
        codestream_name=codestream_name,
        state=state,
        state_was_supplied=state_was_supplied,
        incident_number=incident_number,
        sort_by=sort_by,
        sort_order=sort_order,
        page=page,
        per_page=per_page,
    )


async def _list_actions(
    db: AsyncSession,
    *,
    action_type: IBSRequestActionType,
    ticket_id: str,
    caller: TicketCaller,
    package_name: str | None,
    codestream_name: str | None,
    state: IBSRequestState | None,
    state_was_supplied: bool,
    incident_number: int | None,
    sort_by: IBSRequestSortField,
    sort_order: SortOrder,
    page: int,
    per_page: int,
) -> IBSRequestActionPage:
    if page < 1:
        raise ValueError("page must be at least 1")
    if not 1 <= per_page <= MAX_PER_PAGE:
        raise ValueError(f"per_page must be between 1 and {MAX_PER_PAGE}")
    sequence_id = parse_ticket_id(ticket_id)
    if sequence_id is None:
        raise TicketNotFoundError()

    parent = (
        select(Ticket.id.label("ticket_id"))
        .where(Ticket.sequence_id == sequence_id, ticket_visibility_condition(caller))
        .cte("parent")
    )
    # Every correlated action of the visible parent once, however many of
    # its tracks the action correlates to (Common Query Rules).
    correlated = (
        select(IBSRequestActionTrack.ibs_request_action_id.label("action_id"))
        .join(
            TicketPackageTrack,
            TicketPackageTrack.id == IBSRequestActionTrack.ticket_package_track_id,
        )
        .join(TicketPackage, TicketPackage.id == TicketPackageTrack.ticket_package_id)
        .join(parent, parent.c.ticket_id == TicketPackage.ticket_id)
        .distinct()
        .cte("correlated")
    )

    conditions: list[ColumnElement[bool]] = [
        IBSRequestAction.action_type == action_type.value
    ]
    if package_name is not None:
        conditions.append(IBSRequestAction.logical_package == package_name)
    if codestream_name is not None:
        conditions.append(IBSRequestAction.codestream_name == codestream_name)
    if state is not None:
        conditions.append(IBSRequest.state == state.value)
    elif state_was_supplied:
        conditions.append(false())
    if incident_number is not None:
        conditions.append(IBSRequestAction.incident_number == incident_number)

    filtered = (
        select(
            IBSRequestAction.id,
            IBSRequestAction.logical_package,
            IBSRequestAction.codestream_name,
            IBSRequestAction.incident_number,
            IBSRequest.request_number,
            IBSRequest.state,
            IBSRequest.superseded_by_request_number,
            IBSRequest.upstream_created_at,
            IBSRequest.upstream_updated_at,
        )
        .select_from(correlated)
        .join(IBSRequestAction, IBSRequestAction.id == correlated.c.action_id)
        .join(IBSRequest, IBSRequest.id == IBSRequestAction.ibs_request_id)
        .where(*conditions)
        .cte("filtered")
    )

    total = select(func.count().label("total")).select_from(filtered).cte("total")
    # The sort-field values are the parent request's upstream timestamp
    # column names; both columns are NOT NULL.
    ascending = sort_order is SortOrder.ASC
    page_rows = (
        select(filtered)
        .order_by(
            *_ordering(filtered.c[sort_by.value], filtered.c.id, ascending=ascending)
        )
        .limit(per_page)
        .offset((page - 1) * per_page)
        .cte("page")
    )
    statement = (
        select(
            total.c.total,
            page_rows.c.id.label("action_id"),
            page_rows.c.logical_package,
            page_rows.c.codestream_name,
            page_rows.c.incident_number,
            page_rows.c.request_number,
            page_rows.c.state,
            page_rows.c.superseded_by_request_number,
            page_rows.c.upstream_created_at,
            page_rows.c.upstream_updated_at,
        )
        .select_from(parent)
        .join(total, true())
        .outerjoin(page_rows, true())
        .order_by(
            *_ordering(page_rows.c[sort_by.value], page_rows.c.id, ascending=ascending)
        )
    )

    # The read neither flushes the caller's pending state (autoflush is
    # suspended) nor writes anything itself.
    with db.no_autoflush:
        rows = (await db.execute(statement)).all()
    if not rows:
        raise TicketNotFoundError()

    items = tuple(
        IBSRequestActionItem(
            id=row.action_id,
            action_type=action_type,
            request_number=row.request_number,
            state=IBSRequestState(row.state),
            superseded_by_request_number=row.superseded_by_request_number,
            package_name=row.logical_package,
            codestream_name=row.codestream_name,
            incident_number=row.incident_number,
            ibs_url=request_url(row.request_number),
            incident_url=(
                incident_url(row.incident_number)
                if row.incident_number is not None
                else None
            ),
            upstream_created_at=row.upstream_created_at,
            upstream_updated_at=row.upstream_updated_at,
        )
        for row in rows
        if row.action_id is not None
    )
    return IBSRequestActionPage(
        items=items, total=rows[0].total, page=page, per_page=per_page
    )


def _ordering(
    primary: ColumnElement[datetime],
    tie_breaker: ColumnElement[uuid.UUID],
    *,
    ascending: bool,
) -> tuple[ColumnElement[datetime], ColumnElement[uuid.UUID]]:
    """The primary key, then the action ID, both in the same direction
    (docs/api-spec.md, Deterministic Pagination Ordering)."""
    if ascending:
        return primary.asc(), tie_breaker.asc()
    return primary.desc(), tie_breaker.desc()
