"""Ticket IBS submission and release request list endpoints.

See `docs/features/packages/ibs-submission-tracking.md` (Public API, Common
Query Rules, List Submission Requests, List Release Requests) for the
authoritative endpoint contracts.

Both reads follow `docs/api-spec.md` (Authorization Chain Evaluation
Order, flow 1): optional authentication resolves the caller once, and the
service selects the accessible parent Ticket, the distinct correlated
actions, their total, and the page in one visibility-constrained
statement, so there is no preliminary accessibility dependency. Handlers
stay thin: they resolve the transport input, delegate to
`ibs_request_lists`, and map the result or the shared
`TicketNotFoundError` to HTTP. No business logic or database query lives
here.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Annotated, Final

from fastapi import APIRouter, Depends, Query

from app.api.dependencies import (
    OptionalTicketCaller,
    TicketIdPath,
    ticket_not_found_error,
)
from app.core.enums import IBSRequestSortField, IBSRequestState, SortOrder
from app.core.exceptions import TicketNotFoundError
from app.database import DatabaseSession
from app.schemas.common import PaginationMeta
from app.schemas.errors import ErrorResponse
from app.schemas.ibs_request import (
    ReleaseRequestItem,
    ReleaseRequestListResponse,
    SubmissionRequestItem,
    SubmissionRequestListResponse,
)
from app.services.packages import ibs_request_lists
from app.services.packages.ibs_request_lists import IBSRequestActionItem

router = APIRouter(prefix="/api/v1", tags=["IBS Submission Tracking"])

# Wire value -> filter member (`docs/api-spec.md`, Enum Filter Validation).
_STATE_FILTER: Final[Mapping[str, IBSRequestState]] = {
    member.value: member for member in IBSRequestState
}

_TICKET_NOT_FOUND_DESCRIPTION: Final = (
    "`TICKET_NOT_FOUND`: Ticket identifier is malformed, does not exist, or "
    "identifies a Ticket inaccessible to the caller."
)

_LIST_DESCRIPTION_SUFFIX: Final = (
    " Each item is one distinct action, however many tracks of the Ticket it "
    "is correlated to. Persisted history is returned regardless of the "
    "Ticket status and of package or track exclusion, affectedness, or "
    "actionability. Filters combine with AND; an invalid `state` returns an "
    "empty page. Sorted by the selected upstream timestamp of the request "
    "(default `upstream_updated_at`, `desc`). The Ticket is identified by its "
    "canonical SNTL-{n} identity. Public; optional authentication determines "
    "access to confidential Tickets."
)


@dataclass(frozen=True, slots=True)
class _RequestListQuery:
    """The validated query parameters shared by both lists."""

    package_name: str | None
    codestream_name: str | None
    state: str | None
    sort_by: IBSRequestSortField
    sort_order: SortOrder
    page: int
    per_page: int


def _request_list_query(
    *,
    package_name: Annotated[
        str | None,
        Query(description="Exact, case-sensitive logical package of the action."),
    ] = None,
    codestream_name: Annotated[
        str | None,
        Query(description="Exact, case-sensitive IBS codestream of the action."),
    ] = None,
    state: Annotated[
        str | None,
        Query(
            description=(
                "Exact current request state: `new`, `review`, `accepted`, "
                "`declined`, `revoked`, `superseded`, or `deleted`. Any other "
                "value matches no action."
            )
        ),
    ] = None,
    sort_by: Annotated[
        IBSRequestSortField,
        Query(
            description=(
                "Sort field (default `upstream_updated_at`): the request's "
                "`upstream_created_at` or `upstream_updated_at`."
            )
        ),
    ] = IBSRequestSortField.UPSTREAM_UPDATED_AT,
    sort_order: Annotated[
        SortOrder, Query(description="`asc` or `desc` (default `desc`).")
    ] = SortOrder.DESC,
    page: Annotated[int, Query(ge=1, le=2_147_483_647, description="Page number.")] = 1,
    per_page: Annotated[
        int, Query(ge=1, le=100, description="Items per page; maximum 100.")
    ] = 20,
) -> _RequestListQuery:
    """Collect the query parameters shared by both lists.

    Declared as individual `Query()` parameters so each one is visible to
    the shared query-length-limit and inadmissible-character dependencies.
    Invalid pagination, `sort_by`, and `sort_order` values fail their
    declared types and constraints with the global `422 VALIDATION_ERROR`;
    an invalid `state` is resolved by the handler as a supplied filter
    that matches nothing.
    """
    return _RequestListQuery(
        package_name=package_name,
        codestream_name=codestream_name,
        state=state,
        sort_by=sort_by,
        sort_order=sort_order,
        page=page,
        per_page=per_page,
    )


RequestListQuery = Annotated[_RequestListQuery, Depends(_request_list_query)]


def _state_filter(raw: str | None) -> IBSRequestState | None:
    """The valid state member, or `None` when absent or invalid; the caller
    passes `state_was_supplied` separately so the service still applies
    parent accessibility before returning the empty page."""
    return None if raw is None else _STATE_FILTER.get(raw)


def _item_fields(item: IBSRequestActionItem) -> dict[str, object]:
    return {
        "id": item.id,
        "action_type": item.action_type.value,
        "request_number": item.request_number,
        "state": item.state.value,
        "superseded_by_request_number": item.superseded_by_request_number,
        "package_name": item.package_name,
        "codestream_name": item.codestream_name,
        "incident_number": item.incident_number,
        "ibs_url": item.ibs_url,
        "incident_url": item.incident_url,
        "upstream_created_at": item.upstream_created_at,
        "upstream_updated_at": item.upstream_updated_at,
    }


@router.get(
    "/tickets/{ticket_id}/submission-requests",
    response_model=SubmissionRequestListResponse,
    summary="List submission requests",
    description=(
        "Returns the paginated IBS submission request (`maintenance_incident`) "
        "actions correlated to the Ticket's package tracks." + _LIST_DESCRIPTION_SUFFIX
    ),
    responses={
        404: {"model": ErrorResponse, "description": _TICKET_NOT_FOUND_DESCRIPTION}
    },
)
async def list_submission_requests(
    ticket_id: TicketIdPath,
    db: DatabaseSession,
    caller: OptionalTicketCaller,
    query: RequestListQuery,
) -> SubmissionRequestListResponse:
    """List Submission Requests — see
    `docs/features/packages/ibs-submission-tracking.md` (List Submission
    Requests)."""
    try:
        result = await ibs_request_lists.list_submission_requests(
            db,
            ticket_id=ticket_id,
            caller=caller,
            package_name=query.package_name,
            codestream_name=query.codestream_name,
            state=_state_filter(query.state),
            state_was_supplied=query.state is not None,
            sort_by=query.sort_by,
            sort_order=query.sort_order,
            page=query.page,
            per_page=query.per_page,
        )
    except TicketNotFoundError:
        raise ticket_not_found_error() from None
    return SubmissionRequestListResponse(
        data=[
            SubmissionRequestItem.model_validate(_item_fields(item))
            for item in result.items
        ],
        meta=PaginationMeta(
            total=result.total, page=result.page, per_page=result.per_page
        ),
    )


@router.get(
    "/tickets/{ticket_id}/release-requests",
    response_model=ReleaseRequestListResponse,
    summary="List release requests",
    description=(
        "Returns the paginated IBS release request (`maintenance_release`) "
        "actions directly correlated to the Ticket's package tracks; they are "
        "never inferred from request-level incident equality. Also filterable "
        "by exact `incident_number`." + _LIST_DESCRIPTION_SUFFIX
    ),
    responses={
        404: {"model": ErrorResponse, "description": _TICKET_NOT_FOUND_DESCRIPTION}
    },
)
async def list_release_requests(
    ticket_id: TicketIdPath,
    db: DatabaseSession,
    caller: OptionalTicketCaller,
    query: RequestListQuery,
    incident_number: Annotated[
        int | None,
        Query(
            ge=1,
            le=2_147_483_647,
            description=(
                "Exact maintenance incident number: a positive integer of at "
                "most 2147483647."
            ),
        ),
    ] = None,
) -> ReleaseRequestListResponse:
    """List Release Requests — see
    `docs/features/packages/ibs-submission-tracking.md` (List Release
    Requests)."""
    try:
        result = await ibs_request_lists.list_release_requests(
            db,
            ticket_id=ticket_id,
            caller=caller,
            package_name=query.package_name,
            codestream_name=query.codestream_name,
            state=_state_filter(query.state),
            state_was_supplied=query.state is not None,
            incident_number=incident_number,
            sort_by=query.sort_by,
            sort_order=query.sort_order,
            page=query.page,
            per_page=query.per_page,
        )
    except TicketNotFoundError:
        raise ticket_not_found_error() from None
    return ReleaseRequestListResponse(
        data=[
            ReleaseRequestItem.model_validate(_item_fields(item))
            for item in result.items
        ],
        meta=PaginationMeta(
            total=result.total, page=result.page, per_page=result.per_page
        ),
    )
