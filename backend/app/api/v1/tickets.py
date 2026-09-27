"""Ticket endpoints.

See `docs/features/tickets/tickets.md` (API Endpoints > List Tickets and
Get Ticket, Response Schemas > TicketSummary and TicketDetail) for the
authoritative endpoint contracts.
Handlers stay thin: they supply caller information to `ticket_service`,
map its outcomes to HTTP, and serialize its semantic projection. The
service owns SNTL resolution, visibility-constrained selection, and the
single evaluation instant; no business logic or database query lives
here.

`serialize_ticket_detail()` is the one `TicketDetail` serializer, shared
by every endpoint that returns a Ticket detail, so responses cannot
drift. It never captures a date or instant.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Annotated, Final

from fastapi import APIRouter, Depends, Query

from app.api.dependencies import (
    OptionalTicketCaller,
    TicketIdPath,
    ticket_not_found_error,
)
from app.api.v1.ticket_packages import serialize_package
from app.core.enums import (
    MilestonePhase,
    Severity,
    SortOrder,
    TicketPriority,
    TicketSortField,
    TicketStatus,
)
from app.core.exceptions import TicketNotFoundError
from app.database import DatabaseSession
from app.schemas.common import PaginationMeta, UserReference
from app.schemas.cve import (
    CVEDetail,
    CVEEPSSResponse,
    CVEExternalIdentifierResponse,
    CVEKEVResponse,
    CVESSVCResponse,
    CVESummary,
    CVEWeaknessResponse,
)
from app.schemas.errors import ErrorResponse
from app.schemas.ticket import (
    TicketDetail,
    TicketDetailResponse,
    TicketListQuery,
    TicketListResponse,
    TicketSummary,
)
from app.services import ticket_service
from app.services.ticket_service import (
    CVEDetailProjection,
    TicketDetailProjection,
    TicketSummaryProjection,
)

router = APIRouter(prefix="/api/v1", tags=["Tickets"])

# Lowercase wire value -> domain filter member (tickets.md, Response
# Schemas: enum serialization; List Tickets). `unresolved` maps to `None`,
# the SQL `NULL` member of the nullable severity and priority filters.
_STATUS_FILTER: Final[Mapping[str, TicketStatus]] = {
    member.value.lower(): member for member in TicketStatus
}
_SEVERITY_FILTER: Final[Mapping[str, Severity | None]] = {
    **{member.value.lower(): member for member in Severity},
    "unresolved": None,
}
_PRIORITY_FILTER: Final[Mapping[str, TicketPriority | None]] = {
    **{member.value.lower(): member for member in TicketPriority},
    "unresolved": None,
}
_OVERDUE_FILTER: Final[Mapping[str, MilestonePhase]] = {
    member.value: member for member in MilestonePhase
}


def _parse_repeatable[T](raw: list[str], members: Mapping[str, T]) -> list[T] | None:
    """Resolve raw repeatable enum filter values to domain members.

    Returns `None` when the parameter was not supplied (no filter), or
    the valid members otherwise. Invalid values, including
    comma-separated lists, are silently dropped, so an all-invalid
    filter yields an empty list, which the service turns into an empty
    page (`docs/api-spec.md`, Enum Filter Validation).
    """
    if not raw:
        return None
    return [members[value] for value in raw if value in members]


def _ticket_list_query(
    *,
    search: Annotated[
        str | None,
        Query(
            description=(
                "Free-text search; a Ticket matches if any field matches. SNTL "
                "identifier: prefix of the numeric part (optional `SNTL-` "
                "prefix, case-insensitive). CVE ID: case-insensitive prefix "
                "(`CVE-` optional for a year-number term such as `2024-1234`). "
                "Included package names: case-insensitive substring. External "
                "identifiers (e.g. GHSA IDs): case-insensitive prefix. Outer "
                "whitespace is trimmed; `%`, `_`, and backslash are literal."
            )
        ),
    ] = None,
    status_filter: Annotated[
        list[str],
        Query(
            alias="status",
            default_factory=list,
            description=(
                "Filter by Ticket status: `new`, `analysis`, `analyzed`, "
                "`resolved`, `ignored`, `duplicated`. Repeatable; OR semantics. "
                "Invalid values are ignored."
            ),
        ),
    ],
    assignee: Annotated[
        str | None,
        Query(
            description=(
                "Filter by assignee: user UUID, exact username, or `none` for "
                "unassigned Tickets. An unknown user yields an empty page."
            )
        ),
    ] = None,
    severity: Annotated[
        list[str],
        Query(
            default_factory=list,
            description=(
                "Filter by resolved severity: `critical`, `high`, `medium`, "
                "`low`, `none` (CVSS score 0.0), `unresolved` (no severity). "
                "Repeatable; OR semantics. Invalid values are ignored."
            ),
        ),
    ],
    priority: Annotated[
        list[str],
        Query(
            default_factory=list,
            description=(
                "Filter by effective priority: `p1`, `p2`, `p3`, `p4`, "
                "`unresolved` (not yet prioritizable). Repeatable; OR "
                "semantics. Invalid values are ignored."
            ),
        ),
    ],
    overdue: Annotated[
        list[str],
        Query(
            default_factory=list,
            description=(
                "Filter by past-due, uncompleted milestones: `triage` (Ticket "
                "`new` or `analysis` past its triage due date, VA decision), "
                "`submission` (maintainer submission request), `um` (UM "
                "release request), `qa` (QA testing and publication): at least "
                "one track has that milestone overdue. Repeatable; OR "
                "semantics. Invalid values are ignored."
            ),
        ),
    ],
    maintainer: Annotated[
        str | None,
        Query(
            description=(
                "Filter by maintainer of at least one included package: user "
                "UUID or exact username. An unknown user yields an empty page."
            )
        ),
    ] = None,
    page: Annotated[int, Query(ge=1, le=2_147_483_647, description="Page number.")] = 1,
    per_page: Annotated[
        int, Query(ge=1, le=100, description="Items per page; maximum 100.")
    ] = 20,
    sort_by: Annotated[
        TicketSortField,
        Query(
            description=(
                "Sort field (default `created_at`): `created_at`, `updated_at`, "
                "`severity`, `priority`, and `status` (semantic ordering), "
                "`ticket_id` (numeric), or a Ticket-level due date "
                "(`triage_due_at`, `submission_due_at`, `um_due_at`, "
                "`qa_due_at`, `release_due_at`). `null` values sort last in "
                "both directions."
            )
        ),
    ] = TicketSortField.CREATED_AT,
    sort_order: Annotated[
        SortOrder, Query(description="`asc` or `desc` (default `desc`).")
    ] = SortOrder.DESC,
) -> TicketListQuery:
    """Collect the List Tickets query parameters.

    Declared as individual `Query()` parameters so each one is visible to
    the shared query-length-limit dependency (`app.core.query_limits`).
    `status` uses an alias only to keep the Python name distinct.
    """
    return TicketListQuery(
        search=search,
        status=status_filter,
        assignee=assignee,
        severity=severity,
        priority=priority,
        overdue=overdue,
        maintainer=maintainer,
        page=page,
        per_page=per_page,
        sort_by=sort_by,
        sort_order=sort_order,
    )


def _lower(value: str | None) -> str | None:
    return value.lower() if value is not None else None


def serialize_cve_detail(cve: CVEDetailProjection) -> CVEDetail:
    """Map the expanded CVE projection to its `CVEDetail` schema."""
    return CVEDetail.model_validate(
        {
            "cve_id": cve.cve_id,
            "title": cve.title,
            "description": cve.description,
            "published_date": cve.published_date,
            "modified_date": cve.modified_date,
            "cve_state": cve.cve_state.lower(),
            "date_rejected": cve.date_rejected,
            "severity": _lower(cve.severity),
            "external_identifiers": [
                CVEExternalIdentifierResponse(
                    source=item.source.lower(),
                    identifier=item.identifier,
                    url=item.url,
                )
                for item in cve.external_identifiers
            ],
            "kev": (
                CVEKEVResponse(
                    date_added=cve.kev.date_added,
                    reference_url=cve.kev.reference_url,
                )
                if cve.kev is not None
                else None
            ),
            "epss": (
                CVEEPSSResponse(
                    score=cve.epss.score,
                    percentile=cve.epss.percentile,
                    assessed_at=cve.epss.assessed_at,
                )
                if cve.epss is not None
                else None
            ),
            "ssvc": (
                CVESSVCResponse(
                    exploitation=cve.ssvc.exploitation,
                    automatable=cve.ssvc.automatable,
                    technical_impact=cve.ssvc.technical_impact,
                    version=cve.ssvc.version,
                    assessed_at=cve.ssvc.assessed_at,
                )
                if cve.ssvc is not None
                else None
            ),
            "cwes": [
                CVEWeaknessResponse(cwe_id=cwe.cwe_id, sources=list(cwe.sources))
                for cwe in cve.cwes
            ],
        }
    )


def serialize_ticket_summary(summary: TicketSummaryProjection) -> TicketSummary:
    """Map a Ticket summary projection to its `TicketSummary` schema.

    Lowercases every enumerated value and expands the Ticket-level due
    dates (all `null` when no SLA applies).
    """
    due = summary.due_dates
    cve = summary.cve
    return TicketSummary.model_validate(
        {
            "ticket_id": summary.ticket_id,
            "status": summary.status.lower(),
            "severity": _lower(summary.severity),
            "priority": _lower(summary.priority),
            "assignee": (
                UserReference.model_validate(summary.assignee)
                if summary.assignee is not None
                else None
            ),
            "cve": (
                CVESummary(
                    cve_id=cve.cve_id, title=cve.title, description=cve.description
                )
                if cve is not None
                else None
            ),
            "duplicate_of_ticket_id": summary.duplicate_of_ticket_id,
            "is_confidential": summary.is_confidential,
            "coordinated_release_at": summary.coordinated_release_at,
            "triage_due_at": due.triage if due is not None else None,
            "submission_due_at": due.submission if due is not None else None,
            "um_due_at": due.um if due is not None else None,
            "qa_due_at": due.qa if due is not None else None,
            "release_due_at": due.release if due is not None else None,
            "package_names": list(summary.package_names),
            "created_at": summary.created_at,
            "updated_at": summary.updated_at,
        }
    )


def serialize_ticket_detail(detail: TicketDetailProjection) -> TicketDetail:
    """Map a Ticket detail projection to its `TicketDetail` schema.

    Lowercases every enumerated value, expands the Ticket-level due dates
    (all `null` when no SLA applies), and reuses the package-tree
    serializer for `packages`.
    """
    due = detail.due_dates
    return TicketDetail.model_validate(
        {
            "ticket_id": detail.ticket_id,
            "status": detail.status.lower(),
            "severity": _lower(detail.severity),
            "priority": _lower(detail.priority),
            "priority_automatic": _lower(detail.priority_automatic),
            "priority_override": _lower(detail.priority_override),
            "assignee": (
                UserReference.model_validate(detail.assignee)
                if detail.assignee is not None
                else None
            ),
            "cve": serialize_cve_detail(detail.cve) if detail.cve is not None else None,
            "duplicate_of_ticket_id": detail.duplicate_of_ticket_id,
            "is_confidential": detail.is_confidential,
            "coordinated_release_at": detail.coordinated_release_at,
            "triage_due_at": due.triage if due is not None else None,
            "submission_due_at": due.submission if due is not None else None,
            "um_due_at": due.um if due is not None else None,
            "qa_due_at": due.qa if due is not None else None,
            "release_due_at": due.release if due is not None else None,
            "packages": [serialize_package(p) for p in detail.packages],
            "created_at": detail.created_at,
            "updated_at": detail.updated_at,
        }
    )


@router.get(
    "/tickets",
    response_model=TicketListResponse,
    summary="List Tickets",
    description=(
        "Returns a paginated list of the Tickets visible to the caller, with "
        "multi-field search, repeatable status, severity, priority, and overdue "
        "filters, assignee and maintainer filters, and sorting. Visibility is "
        "applied before every filter, sort, count, and page. Public; optional "
        "authentication determines access to confidential Tickets."
    ),
)
async def list_tickets(
    db: DatabaseSession,
    caller: OptionalTicketCaller,
    query: Annotated[TicketListQuery, Depends(_ticket_list_query)],
) -> TicketListResponse:
    """List Tickets — see `docs/features/tickets/tickets.md` (List
    Tickets).

    The service captures the single evaluation instant and returns rows
    and total from one visibility-constrained statement.
    """
    result = await ticket_service.list_tickets(
        db,
        caller=caller,
        search=query.search,
        status=_parse_repeatable(query.status, _STATUS_FILTER),
        assignee=query.assignee,
        severity=_parse_repeatable(query.severity, _SEVERITY_FILTER),
        priority=_parse_repeatable(query.priority, _PRIORITY_FILTER),
        overdue=_parse_repeatable(query.overdue, _OVERDUE_FILTER),
        maintainer=query.maintainer,
        sort_by=query.sort_by,
        sort_order=query.sort_order,
        page=query.page,
        per_page=query.per_page,
    )
    return TicketListResponse(
        data=[serialize_ticket_summary(item) for item in result.items],
        meta=PaginationMeta(
            total=result.total, page=result.page, per_page=result.per_page
        ),
    )


@router.get(
    "/tickets/{ticket_id}",
    response_model=TicketDetailResponse,
    summary="Get Ticket",
    description=(
        "Returns one Ticket by its canonical SNTL-{n} identity: root fields, "
        "resolved severity, effective, automatic, and override priority, "
        "Ticket-level due dates, the current assignee, expanded CVE evidence "
        "(KEV, EPSS, SSVC, CWE, external identifiers; CVSS assessments are "
        "available from their own sub-resource), the duplicate target's "
        "identifier only, and the complete package tree. Maintainer "
        "identities are not included. Public; optional authentication "
        "determines access to confidential Tickets."
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
async def get_ticket(
    ticket_id: TicketIdPath,
    db: DatabaseSession,
    caller: OptionalTicketCaller,
) -> TicketDetailResponse:
    """Get Ticket — see `docs/features/tickets/tickets.md` (Get Ticket).

    The service captures the response's single evaluation instant and
    applies Ticket visibility in the same statement that selects the
    complete detail, so no separate preliminary accessibility query is
    needed.
    """
    try:
        detail = await ticket_service.get_ticket_detail(
            db, ticket_id=ticket_id, caller=caller
        )
    except TicketNotFoundError:
        raise ticket_not_found_error() from None
    return TicketDetailResponse(data=serialize_ticket_detail(detail))
