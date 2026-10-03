"""Maintainer workbench endpoints.

See `docs/features/packages/maintainer.md` (API Endpoints > Pending
Packages, In-Progress Packages, Completed Packages, Package Details for
Ticket) for the authoritative endpoint contracts.
Handlers stay thin: they authenticate the caller (no capability is
required), capture the request's single evaluation instant and its UTC
date (`docs/features/tickets/ticket-deadlines.md`, Evaluation Instant),
delegate the protected read to `package_service`, and map results and
`TicketNotFoundError` to HTTP. No business logic or database query lives
here.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, date, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import (
    AuthenticatedTicketCaller,
    TicketIdPath,
    ticket_not_found_error,
)
from app.core.enums import MaintainerWorkSortField, SortOrder
from app.core.exceptions import TicketNotFoundError
from app.database import DatabaseSession
from app.schemas.common import PaginationMeta
from app.schemas.errors import ErrorResponse
from app.schemas.maintainer import (
    MaintainerTicketWork,
    MaintainerTicketWorkResponse,
    MaintainerWorkItem,
    MaintainerWorkListResponse,
)
from app.services import package_service
from app.services.packages.maintainer_workbench import (
    MaintainerWorkItem as WorkItemProjection,
)
from app.services.packages.maintainer_workbench import MaintainerWorkPage
from app.services.ticket_visibility import TicketCaller

router = APIRouter(prefix="/api/v1", tags=["Maintainer Operations"])

type _ListOperation = Callable[..., Awaitable[MaintainerWorkPage]]


def _utc_now() -> datetime:
    """The current instant in UTC (patched by controlled-clock tests)."""
    return datetime.now(UTC)


def _lower(value: str | None) -> str | None:
    return value.lower() if value is not None else None


def _serialize_item(item: WorkItemProjection) -> MaintainerWorkItem:
    return MaintainerWorkItem.model_validate(
        {
            "package_name": item.package_name,
            "ticket_id": item.ticket_id,
            "cve_id": item.cve_id,
            "severity": _lower(item.severity),
            "workflow_type": item.workflow_type.lower(),
            "reference": item.reference,
            "status": item.status.lower(),
            "delivery_status": item.delivery_status.lower(),
            "submission_due_at": item.submission_due_at,
            "submission_milestone": _lower(item.submission_milestone),
        }
    )


@dataclass(frozen=True, slots=True)
class _WorkbenchListQuery:
    """The validated shared global-list query parameters."""

    package: str | None
    sort_by: MaintainerWorkSortField
    sort_order: SortOrder
    page: int
    per_page: int


def _workbench_list_query(
    *,
    package: Annotated[
        str | None,
        Query(
            description=(
                "Exact, case-sensitive match on the package name: no trimming, "
                "aliasing, substring matching, or case normalization."
            )
        ),
    ] = None,
    sort_by: Annotated[
        MaintainerWorkSortField,
        Query(
            description=(
                "Sort field (default `severity`): `severity` (semantic ordering; "
                "see Sorting), `package` (Unicode code-point order), or "
                "`submission_due_at` (the track's submission due date). An "
                "unresolved severity and a null due date sort last in both "
                "directions."
            )
        ),
    ] = MaintainerWorkSortField.SEVERITY,
    sort_order: Annotated[
        SortOrder, Query(description="`asc` or `desc` (default `desc`).")
    ] = SortOrder.DESC,
    page: Annotated[int, Query(ge=1, le=2_147_483_647, description="Page number.")] = 1,
    per_page: Annotated[
        int, Query(ge=1, le=100, description="Items per page; maximum 100.")
    ] = 20,
) -> _WorkbenchListQuery:
    """Collect the shared global-list query parameters.

    Declared as individual `Query()` parameters so each one is visible to
    the shared query-length-limit dependency (`app.core.query_limits`).
    Invalid pagination, `sort_by`, and `sort_order` values fail their
    declared types and constraints with the global `422 VALIDATION_ERROR`.
    """
    return _WorkbenchListQuery(
        package=package,
        sort_by=sort_by,
        sort_order=sort_order,
        page=page,
        per_page=per_page,
    )


WorkbenchListQuery = Annotated[_WorkbenchListQuery, Depends(_workbench_list_query)]


def _evaluation() -> tuple[datetime, date]:
    """Capture the response's one evaluation instant and its UTC date."""
    evaluation_instant = _utc_now()
    return evaluation_instant, evaluation_instant.astimezone(UTC).date()


async def _list_work(
    operation: _ListOperation,
    db: AsyncSession,
    caller: TicketCaller,
    query: _WorkbenchListQuery,
) -> MaintainerWorkListResponse:
    evaluation_instant, evaluation_date = _evaluation()
    result = await operation(
        db,
        caller=caller,
        evaluation_date=evaluation_date,
        evaluation_instant=evaluation_instant,
        package=query.package,
        sort_by=query.sort_by,
        sort_order=query.sort_order,
        page=query.page,
        per_page=query.per_page,
    )
    return MaintainerWorkListResponse(
        data=[_serialize_item(item) for item in result.items],
        meta=PaginationMeta(
            total=result.total, page=result.page, per_page=result.per_page
        ),
    )


_LIST_DESCRIPTION_SUFFIX = (
    " Each item is one exact package track whose Ticket is visible to the "
    "caller and whose included package the caller maintains. Supports an "
    "exact `package` filter, sorting, and pagination. Authenticated; no "
    "capability is required."
)


@router.get(
    "/my/packages/pending",
    response_model=MaintainerWorkListResponse,
    summary="List my pending packages",
    description=(
        "Returns the caller's pending tracks: Ticket in `analysis` or "
        "`analyzed`, track actionable and `affected` with delivery `pending`, "
        "and at least one actionable eligible Product." + _LIST_DESCRIPTION_SUFFIX
    ),
)
async def list_pending_packages(
    db: DatabaseSession,
    caller: AuthenticatedTicketCaller,
    query: WorkbenchListQuery,
) -> MaintainerWorkListResponse:
    """Pending Packages — see `docs/features/packages/maintainer.md`
    (Pending Packages)."""
    return await _list_work(
        package_service.list_maintainer_pending_work, db, caller, query
    )


@router.get(
    "/my/packages/in-progress",
    response_model=MaintainerWorkListResponse,
    summary="List my in-progress packages",
    description=(
        "Returns the caller's in-progress tracks: Ticket in `analysis` or "
        "`analyzed`, track actionable and `affected` or `fixed` with delivery "
        "`in_progress`, and at least one actionable eligible Product."
        + _LIST_DESCRIPTION_SUFFIX
    ),
)
async def list_in_progress_packages(
    db: DatabaseSession,
    caller: AuthenticatedTicketCaller,
    query: WorkbenchListQuery,
) -> MaintainerWorkListResponse:
    """In-Progress Packages — see `docs/features/packages/maintainer.md`
    (In-Progress Packages)."""
    return await _list_work(
        package_service.list_maintainer_in_progress_work, db, caller, query
    )


@router.get(
    "/my/packages/completed",
    response_model=MaintainerWorkListResponse,
    summary="List my completed packages",
    description=(
        "Returns the caller's completed tracks: Ticket in `analysis`, "
        "`analyzed`, or `resolved`, track actionable with delivery `released`."
        + _LIST_DESCRIPTION_SUFFIX
    ),
)
async def list_completed_packages(
    db: DatabaseSession,
    caller: AuthenticatedTicketCaller,
    query: WorkbenchListQuery,
) -> MaintainerWorkListResponse:
    """Completed Packages — see `docs/features/packages/maintainer.md`
    (Completed Packages)."""
    return await _list_work(
        package_service.list_maintainer_completed_work, db, caller, query
    )


@router.get(
    "/my/packages/tickets/{ticket_id}",
    response_model=MaintainerTicketWorkResponse,
    summary="Get my package work for a Ticket",
    description=(
        "Returns every track of one Ticket that the caller maintains and that "
        "satisfies a workbench classification, partitioned into `pending`, "
        "`in_progress`, and `completed`. Fixed order: `package_name`, then "
        "`reference`, in ascending Unicode code-point order. Unpaginated (the "
        "track set of one Ticket is bounded). All three arrays are empty when "
        "the caller has no qualifying work on an accessible Ticket. The Ticket "
        "is identified by its canonical SNTL-{n} identity. Authenticated; no "
        "capability is required."
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
async def get_ticket_package_work(
    ticket_id: TicketIdPath,
    db: DatabaseSession,
    caller: AuthenticatedTicketCaller,
) -> MaintainerTicketWorkResponse:
    """Package Details for Ticket — see `docs/features/packages/maintainer.md`
    (Package Details for Ticket).

    The service applies Ticket visibility in the same statement that
    selects the classified tracks, so no separate preliminary
    accessibility query is needed.
    """
    evaluation_instant, evaluation_date = _evaluation()
    try:
        work = await package_service.get_maintainer_ticket_work(
            db,
            ticket_id=ticket_id,
            caller=caller,
            evaluation_date=evaluation_date,
            evaluation_instant=evaluation_instant,
        )
    except TicketNotFoundError:
        raise ticket_not_found_error() from None
    return MaintainerTicketWorkResponse(
        data=MaintainerTicketWork(
            pending=[_serialize_item(item) for item in work.pending],
            in_progress=[_serialize_item(item) for item in work.in_progress],
            completed=[_serialize_item(item) for item in work.completed],
        )
    )
