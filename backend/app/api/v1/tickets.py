"""Ticket endpoints.

See `docs/features/tickets/tickets.md` (API Endpoints > List Tickets and
Get Ticket, Response Schemas > TicketSummary and TicketDetail) for the
authoritative endpoint contracts, Create Ticket for manual creation
(`docs/features/tickets/ticket-service.md`, `create_ticket`), Associate
CVE for the later association (`associate_cve`), Assign Ticket
(`assign_ticket`), Set Priority Override
(`docs/features/tickets/ticket-priority.md`, `set_priority_override()`),
Ignore Ticket (`ignore_ticket`), Mark Ticket as Duplicate
(`mark_as_duplicate`), Reopen Ticket (`reopen_from_ignored`), Revert
Duplicate Status (`revert_duplicate`), Set Confidentiality
(`set_confidentiality`), Set Coordinated Release Date
(`set_coordinated_release_date`), Access Grant Management
(`grant_access`, `revoke_access`, `list_access_grants`), and Set Severity
Manual for the manual-severity mutation (`docs/features/tickets/ticket-mutations.md`,
`set_severity_manual()`).
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
from datetime import UTC, datetime
from typing import Annotated, Final

from fastapi import APIRouter, Depends, Path, Query, Response, status

from app.api.dependencies import (
    AuthenticatedPrincipal,
    AuthenticatedTicketCaller,
    CallerRoles,
    OptionalTicketCaller,
    TicketIdPath,
    cve_invalid_format_error,
    insufficient_permission_error,
    require_accessible_ticket,
    require_capability,
    ticket_cve_already_set_error,
    ticket_cve_conflict_error,
    ticket_not_found_error,
    ticket_not_mutable_error,
    user_not_found_error,
)
from app.api.v1.cves import serialize_cve_detail
from app.api.v1.ticket_packages import serialize_package
from app.core.enums import (
    Capability,
    MilestonePhase,
    Severity,
    SortOrder,
    TicketPriority,
    TicketSortField,
    TicketStatus,
)
from app.core.errors import AppError, ErrorCode
from app.core.exceptions import (
    InactiveUserError,
    InvalidTransitionError,
    SeverityDerivedError,
    TicketNotFoundError,
    TicketNotMutableError,
    UserNotFoundError,
)
from app.core.identifiers import is_valid_cve_id
from app.core.permissions import get_capabilities
from app.database import DatabaseSession
from app.schemas.common import PaginationMeta, UserReference
from app.schemas.cve import (
    CVESummary,
)
from app.schemas.errors import ErrorResponse, TicketCVEConflictErrorResponse
from app.schemas.ticket import (
    TicketAccessGrantDataResponse,
    TicketAccessGrantListResponse,
    TicketAccessGrantRequest,
    TicketAccessGrantResponse,
    TicketAssigneeUpdateRequest,
    TicketAssociateCVERequest,
    TicketConfidentialityUpdateRequest,
    TicketCoordinatedReleaseDateUpdateRequest,
    TicketCreateRequest,
    TicketDetail,
    TicketDetailResponse,
    TicketDuplicateRequest,
    TicketListQuery,
    TicketListResponse,
    TicketPriorityUpdateRequest,
    TicketSeverityUpdateRequest,
    TicketSummary,
)
from app.services import ticket_mutations, ticket_service
from app.services.cve_service import CVEIdFormatError
from app.services.ticket_service import (
    AccessGrantAction,
    AssigneeInactiveError,
    AssigneeNotVAError,
    DuplicateConcurrentModificationError,
    DuplicateTargetIsDuplicatedError,
    ResolvedTicket,
    SelfDuplicateError,
    TicketCreationSource,
    TicketCVEAlreadySetError,
    TicketCVEConflictError,
    TicketDetailProjection,
    TicketNotConfidentialError,
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
# Lowercase request-body label -> domain severity (tickets.md, Set Severity
# Manual). JSON `null` is handled separately as "clear".
_SEVERITY_INPUT: Final[Mapping[str, Severity]] = {
    member.value.lower(): member for member in Severity
}
# Lowercase request-body level -> domain priority (tickets.md, Set Priority
# Override). JSON `null` is handled separately as "clear".
_PRIORITY_INPUT: Final[Mapping[str, TicketPriority]] = {
    member.value.lower(): member for member in TicketPriority
}


def _utc_now() -> datetime:
    """The current instant in UTC (patched by controlled-clock tests)."""
    return datetime.now(UTC)


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


def _severity_derived_error() -> AppError:
    return AppError(
        status_code=status.HTTP_409_CONFLICT,
        code=ErrorCode.TICKET_SEVERITY_DERIVED,
        detail="Ticket severity is derived from CVSS assessments.",
    )


@router.post(
    "/tickets",
    status_code=status.HTTP_201_CREATED,
    response_model=TicketDetailResponse,
    summary="Create Ticket",
    description=(
        "Creates a Ticket manually, optionally associated with a CVE (an "
        "unknown CVE is created as a placeholder record), with an initial "
        "manual severity (only without a CVE), as confidential, and with an "
        "initial Coordinated Release Date (only when confidential). An active "
        "vulnerability analyst creator is assigned and the Ticket starts in "
        "`analysis`; otherwise it starts `new` and unassigned. Returns the "
        "created Ticket detail. Requires `create_ticket`; supplying "
        "`is_confidential` (`true` or `false`) additionally requires "
        "`manage_confidentiality`."
    ),
    responses={
        409: {
            "model": TicketCVEConflictErrorResponse | ErrorResponse,
            "description": (
                "`TICKET_CVE_CONFLICT`: the CVE is already associated with "
                "another Ticket, identified by `existing_ticket_id` "
                "(`SNTL-{n}`). `TICKET_SEVERITY_DERIVED`: both `cve_id` and "
                "`severity` were provided (that body has no "
                "`existing_ticket_id`)."
            ),
        },
        422: {
            "model": ErrorResponse,
            "description": (
                "`CVE_INVALID_FORMAT`: `cve_id` does not match "
                "`^CVE-[0-9]{4}-[0-9]{4,}$` or exceeds 20 characters. "
                "`VALIDATION_ERROR`: the body is invalid, including a "
                "`coordinated_release_at` without `is_confidential: true`."
            ),
        },
    },
)
async def create_ticket(
    body: TicketCreateRequest,
    db: DatabaseSession,
    principal: Annotated[
        AuthenticatedPrincipal, Depends(require_capability(Capability.CREATE_TICKET))
    ],
    roles: CallerRoles,
) -> TicketDetailResponse:
    """Create Ticket — see `docs/features/tickets/tickets.md` (Create
    Ticket).

    Order (`docs/api-spec.md`, Authorization Chain Evaluation Order):
    authentication, then `create_ticket` before any lookup, then body
    validation, then the presence-based field-level
    `manage_confidentiality` check from the same per-request role load
    (`docs/features/identity/rbac.md`, Endpoint Permission Map † and
    Business Rule 13), then the `CVE_INVALID_FORMAT` pre-validation, with
    no database work before the service call. The handler captures the
    one UTC date reused by the `TicketDetail` assembled from the
    transaction-owned new Ticket (`docs/features/tickets/ticket-service.md`,
    `get_ticket_detail()`).
    """
    if (
        "is_confidential" in body.model_fields_set
        and Capability.MANAGE_CONFIDENTIALITY not in get_capabilities(roles)
    ):
        raise insufficient_permission_error()
    if body.cve_id is not None and not is_valid_cve_id(body.cve_id):
        raise cve_invalid_format_error()
    evaluation_date = _utc_now().date()
    try:
        ticket = await ticket_service.create_ticket(
            db,
            acting_user_id=principal.user.id,
            cve_id=body.cve_id,
            severity_manual=(
                _SEVERITY_INPUT[body.severity] if body.severity is not None else None
            ),
            is_confidential=body.is_confidential,
            coordinated_release_at=body.coordinated_release_at,
            source=TicketCreationSource.MANUAL,
        )
    except SeverityDerivedError:
        raise _severity_derived_error() from None
    except TicketCVEConflictError as exc:
        raise ticket_cve_conflict_error(exc.existing_ticket_id) from None
    except CVEIdFormatError:
        raise cve_invalid_format_error() from None
    detail = await ticket_service.assemble_ticket_detail(
        db, ticket_id=ticket.id, evaluation_date=evaluation_date
    )
    return TicketDetailResponse(data=serialize_ticket_detail(detail))


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


@router.patch(
    "/tickets/{ticket_id}/severity",
    response_model=TicketDetailResponse,
    summary="Set Severity Manual",
    description=(
        "Sets or clears the manual severity of a Ticket without a CVE. A "
        "lowercase label (`critical`, `high`, `medium`, `low`, `none`) sets "
        "it; JSON `null` clears it (unresolved). An unassigned Ticket is "
        "auto-assigned to an active vulnerability analyst, the automatic "
        "priority is refreshed, and the Ticket status is re-evaluated. "
        "Returns the post-mutation Ticket detail. Requires `triage_ticket`."
    ),
    responses={
        404: {
            "model": ErrorResponse,
            "description": (
                "`TICKET_NOT_FOUND`: Ticket identifier is malformed, does not "
                "exist, or identifies a Ticket inaccessible to the caller."
            ),
        },
        409: {
            "model": ErrorResponse,
            "description": (
                "`TICKET_SEVERITY_DERIVED`: the Ticket has an associated CVE, so "
                "its severity is derived from CVSS. `TICKET_NOT_MUTABLE`: the "
                "Ticket is Ignored or Duplicated."
            ),
        },
    },
)
async def set_ticket_severity(
    ticket_id: TicketIdPath,
    body: TicketSeverityUpdateRequest,
    db: DatabaseSession,
    principal: Annotated[
        AuthenticatedPrincipal, Depends(require_capability(Capability.TRIAGE_TICKET))
    ],
    caller: AuthenticatedTicketCaller,
    ticket: Annotated[ResolvedTicket, Depends(require_accessible_ticket)],
) -> TicketDetailResponse:
    """Set Severity Manual — see `docs/features/tickets/tickets.md`.

    Authorization follows `docs/api-spec.md` (Authorization Chain
    Evaluation Order, flow 3): authentication, then `triage_ticket`
    before any Ticket lookup, then the delegated preliminary SNTL
    resolution. The capability decision and the caller's scope share one
    role load per request. `set_severity_manual()` revalidates
    accessibility from locked-current state; the handler captures the
    one workflow `evaluation_date`, reused by reconciliation and by the
    `TicketDetail` assembled from the locked post-state inside the same
    transaction (`docs/features/tickets/ticket-service.md`,
    `get_ticket_detail()`).
    """
    evaluation_date = _utc_now().date()
    severity = _SEVERITY_INPUT[body.severity] if body.severity is not None else None
    try:
        await ticket_mutations.set_severity_manual(
            db,
            ticket_id=ticket.id,
            severity=severity,
            acting_user_id=principal.user.id,
            caller=caller,
            evaluation_date=evaluation_date,
        )
    except TicketNotFoundError:
        raise ticket_not_found_error() from None
    except TicketNotMutableError:
        raise ticket_not_mutable_error() from None
    except SeverityDerivedError:
        raise _severity_derived_error() from None
    detail = await ticket_service.assemble_ticket_detail(
        db, ticket_id=ticket.id, evaluation_date=evaluation_date
    )
    return TicketDetailResponse(data=serialize_ticket_detail(detail))


@router.post(
    "/tickets/{ticket_id}/associate-cve",
    response_model=TicketDetailResponse,
    summary="Associate CVE",
    description=(
        "Associates a CVE with a Ticket that has none (an unknown CVE is "
        "created as a placeholder record). Clears the manual severity, which "
        "the CVE's CVSS-derived severity replaces; recalculates the automatic "
        "Product eligibility and the automatic priority from the CVE's "
        "current assessments and evidence; and re-evaluates the Ticket status, "
        "which may regress. An unassigned Ticket is auto-assigned to an "
        "active vulnerability analyst caller. Returns the post-mutation "
        "Ticket detail. Requires `triage_ticket`."
    ),
    responses={
        400: {
            "model": ErrorResponse,
            "description": (
                "`TICKET_CVE_ALREADY_SET`: the Ticket already has a CVE associated."
            ),
        },
        404: {
            "model": ErrorResponse,
            "description": (
                "`TICKET_NOT_FOUND`: Ticket identifier is malformed, does not "
                "exist, or identifies a Ticket inaccessible to the caller."
            ),
        },
        409: {
            "model": TicketCVEConflictErrorResponse | ErrorResponse,
            "description": (
                "`TICKET_CVE_CONFLICT`: the CVE is already associated with "
                "another Ticket, identified by `existing_ticket_id` "
                "(`SNTL-{n}`). `TICKET_NOT_MUTABLE`: the Ticket is Ignored or "
                "Duplicated (that body has no `existing_ticket_id`)."
            ),
        },
        422: {
            "model": ErrorResponse,
            "description": (
                "`CVE_INVALID_FORMAT`: `cve_id` does not match "
                "`^CVE-[0-9]{4}-[0-9]{4,}$` or exceeds 20 characters. "
                "`VALIDATION_ERROR`: `cve_id` is missing, `null`, or not a "
                "string."
            ),
        },
    },
)
async def associate_ticket_cve(
    ticket_id: TicketIdPath,
    body: TicketAssociateCVERequest,
    db: DatabaseSession,
    principal: Annotated[
        AuthenticatedPrincipal, Depends(require_capability(Capability.TRIAGE_TICKET))
    ],
    caller: AuthenticatedTicketCaller,
    ticket: Annotated[ResolvedTicket, Depends(require_accessible_ticket)],
) -> TicketDetailResponse:
    """Associate CVE — see `docs/features/tickets/tickets.md` (Associate
    CVE).

    Authorization follows `docs/api-spec.md` (Authorization Chain
    Evaluation Order, flow 3): authentication, then `triage_ticket`
    before any Ticket lookup, then the delegated preliminary SNTL
    resolution and body validation, then the `CVE_INVALID_FORMAT`
    pre-validation with no database work. `associate_cve()` revalidates
    accessibility from locked-current state after the User and CVE locks.
    The handler captures the one workflow `evaluation_date`, reused by the
    CVSS chain, the reconciliation, and the `TicketDetail` assembled from
    the locked post-state inside the same transaction
    (`docs/features/tickets/ticket-service.md`, `get_ticket_detail()`).
    """
    if not is_valid_cve_id(body.cve_id):
        raise cve_invalid_format_error()
    evaluation_date = _utc_now().date()
    try:
        await ticket_service.associate_cve(
            db,
            ticket_id=ticket.id,
            cve_id=body.cve_id,
            acting_user_id=principal.user.id,
            caller=caller,
            evaluation_date=evaluation_date,
        )
    except TicketNotFoundError:
        raise ticket_not_found_error() from None
    except TicketNotMutableError:
        raise ticket_not_mutable_error() from None
    except TicketCVEAlreadySetError:
        raise ticket_cve_already_set_error() from None
    except TicketCVEConflictError as exc:
        raise ticket_cve_conflict_error(exc.existing_ticket_id) from None
    except CVEIdFormatError:
        raise cve_invalid_format_error() from None
    detail = await ticket_service.assemble_ticket_detail(
        db, ticket_id=ticket.id, evaluation_date=evaluation_date
    )
    return TicketDetailResponse(data=serialize_ticket_detail(detail))


def _assignee_not_va_error() -> AppError:
    return AppError(
        status_code=status.HTTP_400_BAD_REQUEST,
        code=ErrorCode.TICKET_ASSIGNEE_NOT_VA,
        detail="Assignee must hold the vulnerability_analyst role.",
    )


def _assignee_inactive_error() -> AppError:
    return AppError(
        status_code=status.HTTP_409_CONFLICT,
        code=ErrorCode.TICKET_ASSIGNEE_INACTIVE,
        detail="Assignee is inactive.",
    )


@router.patch(
    "/tickets/{ticket_id}/priority",
    response_model=TicketDetailResponse,
    summary="Set Priority Override",
    description=(
        "Sets, changes, or clears the manual priority override. A lowercase "
        "level (`p1`-`p4`) sets it; JSON `null` clears it, returning the Ticket "
        "to its automatic priority (`priority_automatic`). The override is "
        "sticky: automatic refresh never changes it. An unchanged request is an "
        "idempotent success. An effective change auto-assigns an unassigned "
        "Ticket to an active vulnerability analyst caller and re-evaluates the "
        "Ticket status. Returns the post-mutation Ticket detail. Requires "
        "`triage_ticket`."
    ),
    responses={
        404: {
            "model": ErrorResponse,
            "description": (
                "`TICKET_NOT_FOUND`: Ticket identifier is malformed, does not "
                "exist, or identifies a Ticket inaccessible to the caller."
            ),
        },
        409: {
            "model": ErrorResponse,
            "description": (
                "`TICKET_NOT_MUTABLE`: the Ticket is Ignored or Duplicated."
            ),
        },
    },
)
async def set_ticket_priority(
    ticket_id: TicketIdPath,
    body: TicketPriorityUpdateRequest,
    db: DatabaseSession,
    principal: Annotated[
        AuthenticatedPrincipal, Depends(require_capability(Capability.TRIAGE_TICKET))
    ],
    caller: AuthenticatedTicketCaller,
    ticket: Annotated[ResolvedTicket, Depends(require_accessible_ticket)],
) -> TicketDetailResponse:
    """Set Priority Override — see `docs/features/tickets/tickets.md`.

    Authorization follows `docs/api-spec.md` (Authorization Chain
    Evaluation Order, flow 3): authentication, then `triage_ticket`
    before any Ticket lookup, then the delegated preliminary SNTL
    resolution and body validation. `set_priority_override()` revalidates
    accessibility from locked-current state; the handler captures the one
    workflow `evaluation_date`, reused by reconciliation and by the
    `TicketDetail` assembled from the locked post-state inside the same
    transaction (`docs/features/tickets/ticket-service.md`,
    `get_ticket_detail()`).
    """
    evaluation_date = _utc_now().date()
    priority = _PRIORITY_INPUT[body.priority] if body.priority is not None else None
    try:
        await ticket_service.set_priority_override(
            db,
            ticket_id=ticket.id,
            priority=priority,
            acting_user_id=principal.user.id,
            caller=caller,
            evaluation_date=evaluation_date,
        )
    except TicketNotFoundError:
        raise ticket_not_found_error() from None
    except TicketNotMutableError:
        raise ticket_not_mutable_error() from None
    detail = await ticket_service.assemble_ticket_detail(
        db, ticket_id=ticket.id, evaluation_date=evaluation_date
    )
    return TicketDetailResponse(data=serialize_ticket_detail(detail))


@router.patch(
    "/tickets/{ticket_id}/assignee",
    response_model=TicketDetailResponse,
    summary="Assign Ticket",
    description=(
        "Assigns or reassigns a Ticket to an active vulnerability analyst, "
        "identified by UUID or exact username. A Ticket cannot be unassigned "
        "through the API. Reassigning to the current assignee is an idempotent "
        "success. A `new` Ticket moves to `analysis`, and the Ticket status is "
        "re-evaluated. Returns the post-mutation Ticket detail. Requires "
        "`triage_ticket`."
    ),
    responses={
        400: {
            "model": ErrorResponse,
            "description": (
                "`TICKET_ASSIGNEE_NOT_VA`: the target user does not hold the "
                "`vulnerability_analyst` role."
            ),
        },
        404: {
            "model": ErrorResponse,
            "description": (
                "`TICKET_NOT_FOUND`: Ticket identifier is malformed, does not "
                "exist, or identifies a Ticket inaccessible to the caller. "
                "`USER_NOT_FOUND`: no user matches `user_id` (reported only for "
                "an accessible, mutable Ticket)."
            ),
        },
        409: {
            "model": ErrorResponse,
            "description": (
                "`TICKET_ASSIGNEE_INACTIVE`: the target user is inactive. "
                "`TICKET_NOT_MUTABLE`: the Ticket is Ignored or Duplicated."
            ),
        },
    },
)
async def assign_ticket(
    ticket_id: TicketIdPath,
    body: TicketAssigneeUpdateRequest,
    db: DatabaseSession,
    principal: Annotated[
        AuthenticatedPrincipal, Depends(require_capability(Capability.TRIAGE_TICKET))
    ],
    caller: AuthenticatedTicketCaller,
    ticket: Annotated[ResolvedTicket, Depends(require_accessible_ticket)],
) -> TicketDetailResponse:
    """Assign Ticket — see `docs/features/tickets/tickets.md`.

    Authorization follows `docs/api-spec.md` (Authorization Chain
    Evaluation Order, flow 3): authentication, then `triage_ticket`
    before any Ticket lookup, then the delegated preliminary SNTL
    resolution and body validation. The UUID-or-username `user_id` is
    passed unchanged: `assign_ticket()` resolves and locks the target
    before the Ticket but reports its absence only after locked-current
    Ticket accessibility and operability. The handler captures the one
    workflow `evaluation_date`, reused by reconciliation and by the
    `TicketDetail` assembled from the locked post-state inside the same
    transaction (`docs/features/tickets/ticket-service.md`,
    `get_ticket_detail()`).
    """
    evaluation_date = _utc_now().date()
    try:
        await ticket_service.assign_ticket(
            db,
            ticket_id=ticket.id,
            assignee=body.user_id,
            acting_user_id=principal.user.id,
            caller=caller,
            evaluation_date=evaluation_date,
        )
    except TicketNotFoundError:
        raise ticket_not_found_error() from None
    except TicketNotMutableError:
        raise ticket_not_mutable_error() from None
    except UserNotFoundError:
        raise user_not_found_error() from None
    except AssigneeInactiveError:
        raise _assignee_inactive_error() from None
    except AssigneeNotVAError:
        raise _assignee_not_va_error() from None
    detail = await ticket_service.assemble_ticket_detail(
        db, ticket_id=ticket.id, evaluation_date=evaluation_date
    )
    return TicketDetailResponse(data=serialize_ticket_detail(detail))


def _invalid_transition_error() -> AppError:
    return AppError(
        status_code=status.HTTP_409_CONFLICT,
        code=ErrorCode.TICKET_INVALID_TRANSITION,
        detail="Ticket status transition is not allowed.",
    )


def _self_duplicate_error() -> AppError:
    return AppError(
        status_code=status.HTTP_400_BAD_REQUEST,
        code=ErrorCode.TICKET_SELF_DUPLICATE,
        detail="Ticket cannot be marked as a duplicate of itself.",
    )


def _duplicate_target_duplicated_error() -> AppError:
    return AppError(
        status_code=status.HTTP_409_CONFLICT,
        code=ErrorCode.TICKET_DUPLICATE_TARGET_DUPLICATED,
        detail="Duplicate target is itself a duplicate.",
    )


def _duplicate_concurrent_modification_error() -> AppError:
    return AppError(
        status_code=status.HTTP_409_CONFLICT,
        code=ErrorCode.TICKET_DUPLICATE_CONCURRENT_MODIFICATION,
        detail="A duplicate dependent is being modified concurrently.",
    )


@router.post(
    "/tickets/{ticket_id}/ignore",
    response_model=TicketDetailResponse,
    summary="Ignore Ticket",
    description=(
        "Moves a `new` or `analysis` Ticket to `ignored` (manual zone). No "
        "request body. An unassigned Ticket is first auto-assigned to an "
        "active vulnerability analyst caller, which records `new` -> "
        "`analysis` before the transition. Returns the post-mutation Ticket "
        "detail. Requires `triage_ticket`."
    ),
    responses={
        404: {
            "model": ErrorResponse,
            "description": (
                "`TICKET_NOT_FOUND`: Ticket identifier is malformed, does not "
                "exist, or identifies a Ticket inaccessible to the caller."
            ),
        },
        409: {
            "model": ErrorResponse,
            "description": (
                "`TICKET_INVALID_TRANSITION`: the Ticket is `analyzed` or "
                "`resolved`. `TICKET_NOT_MUTABLE`: the Ticket is already "
                "Ignored or Duplicated."
            ),
        },
    },
)
async def ignore_ticket(
    ticket_id: TicketIdPath,
    db: DatabaseSession,
    principal: Annotated[
        AuthenticatedPrincipal, Depends(require_capability(Capability.TRIAGE_TICKET))
    ],
    caller: AuthenticatedTicketCaller,
    ticket: Annotated[ResolvedTicket, Depends(require_accessible_ticket)],
) -> TicketDetailResponse:
    """Ignore Ticket — see `docs/features/tickets/tickets.md`.

    Authorization follows `docs/api-spec.md` (Authorization Chain
    Evaluation Order, flow 3): authentication, then `triage_ticket`
    before any Ticket lookup, then the delegated preliminary SNTL
    resolution. `ignore_ticket()` revalidates accessibility from
    locked-current state and does not reconcile, so the handler captures
    one UTC date at workflow entry solely for the `TicketDetail`
    assembled from the locked post-state inside the same transaction
    (`docs/features/tickets/ticket-service.md`, `get_ticket_detail()`).
    """
    evaluation_date = _utc_now().date()
    try:
        await ticket_service.ignore_ticket(
            db,
            ticket_id=ticket.id,
            acting_user_id=principal.user.id,
            caller=caller,
        )
    except TicketNotFoundError:
        raise ticket_not_found_error() from None
    except TicketNotMutableError:
        raise ticket_not_mutable_error() from None
    except InvalidTransitionError:
        raise _invalid_transition_error() from None
    detail = await ticket_service.assemble_ticket_detail(
        db, ticket_id=ticket.id, evaluation_date=evaluation_date
    )
    return TicketDetailResponse(data=serialize_ticket_detail(detail))


@router.post(
    "/tickets/{ticket_id}/duplicate",
    response_model=TicketDetailResponse,
    summary="Mark Ticket as Duplicate",
    description=(
        "Marks a Ticket as a duplicate of another Ticket, identified by "
        "`duplicate_of_ticket_id` (`SNTL-{n}`), which must not itself be "
        "Duplicated. Tickets currently marked as duplicates of this Ticket are "
        "atomically repointed to the new target. An unassigned Ticket is first "
        "auto-assigned to an active vulnerability analyst caller. Returns the "
        "post-mutation Ticket detail. Requires `triage_ticket`."
    ),
    responses={
        400: {
            "model": ErrorResponse,
            "description": (
                "`TICKET_SELF_DUPLICATE`: source and target are the same Ticket."
            ),
        },
        404: {
            "model": ErrorResponse,
            "description": (
                "`TICKET_NOT_FOUND`: the path Ticket identifier is malformed, "
                "does not exist, or identifies a Ticket inaccessible to the "
                "caller, or the well-formed `duplicate_of_ticket_id` does not "
                "exist or is inaccessible."
            ),
        },
        409: {
            "model": ErrorResponse,
            "description": (
                "`TICKET_DUPLICATE_TARGET_DUPLICATED`: the target is itself "
                "Duplicated (use its target instead). "
                "`TICKET_DUPLICATE_CONCURRENT_MODIFICATION`: a Ticket that "
                "duplicates this Ticket is locked by a concurrent operation; "
                "re-read and retry. `TICKET_NOT_MUTABLE`: the Ticket is Ignored "
                "or Duplicated."
            ),
        },
        422: {
            "model": ErrorResponse,
            "description": (
                "`VALIDATION_ERROR`: `duplicate_of_ticket_id` is missing, "
                "`null`, not a string, or not a canonical `SNTL-{n}` identifier."
            ),
        },
    },
)
async def mark_ticket_as_duplicate(
    ticket_id: TicketIdPath,
    body: TicketDuplicateRequest,
    db: DatabaseSession,
    principal: Annotated[
        AuthenticatedPrincipal, Depends(require_capability(Capability.TRIAGE_TICKET))
    ],
    caller: AuthenticatedTicketCaller,
    ticket: Annotated[ResolvedTicket, Depends(require_accessible_ticket)],
) -> TicketDetailResponse:
    """Mark Ticket as Duplicate — see `docs/features/tickets/tickets.md`.

    Authorization follows `docs/api-spec.md` (Authorization Chain
    Evaluation Order, flow 3, multi-root): authentication, then
    `triage_ticket` before any Ticket lookup, then the delegated
    preliminary SNTL resolution of the path and Pydantic validation of
    the body. The target is resolved through the same visibility-
    constrained service resolution (`docs/api-spec.md`, Ticket Identifier
    Resolution: request-body Ticket field) only to obtain its internal
    UUID; `mark_as_duplicate()` revalidates both roots from
    locked-current state. It does not reconcile, so the handler captures
    one UTC date at workflow entry solely for the `TicketDetail`
    assembled from the locked source inside the same transaction
    (`docs/features/tickets/ticket-service.md`, `get_ticket_detail()`).
    """
    evaluation_date = _utc_now().date()
    try:
        target = await ticket_service.resolve_ticket_locator(
            db, body.duplicate_of_ticket_id, caller
        )
        await ticket_service.mark_as_duplicate(
            db,
            ticket_id=ticket.id,
            duplicate_of_id=target.id,
            acting_user_id=principal.user.id,
            caller=caller,
        )
    except TicketNotFoundError:
        raise ticket_not_found_error() from None
    except TicketNotMutableError:
        raise ticket_not_mutable_error() from None
    except DuplicateTargetIsDuplicatedError:
        raise _duplicate_target_duplicated_error() from None
    except SelfDuplicateError:
        raise _self_duplicate_error() from None
    except DuplicateConcurrentModificationError:
        raise _duplicate_concurrent_modification_error() from None
    detail = await ticket_service.assemble_ticket_detail(
        db, ticket_id=ticket.id, evaluation_date=evaluation_date
    )
    return TicketDetailResponse(data=serialize_ticket_detail(detail))


@router.post(
    "/tickets/{ticket_id}/reopen",
    response_model=TicketDetailResponse,
    summary="Reopen Ticket",
    description=(
        "Reopens an `ignored` Ticket. No request body. An active vulnerability "
        "analyst caller becomes the assignee, replacing any current assignee; "
        "otherwise the current assignee is kept. Automatic Product eligibility "
        "is re-evaluated from current data, and the Ticket status is evaluated "
        "from its gates (`analysis`, `analyzed`, or `resolved`). Returns the "
        "post-mutation Ticket detail. Requires `triage_ticket`."
    ),
    responses={
        404: {
            "model": ErrorResponse,
            "description": (
                "`TICKET_NOT_FOUND`: Ticket identifier is malformed, does not "
                "exist, or identifies a Ticket inaccessible to the caller."
            ),
        },
        409: {
            "model": ErrorResponse,
            "description": (
                "`TICKET_INVALID_TRANSITION`: the Ticket is not `ignored`."
            ),
        },
    },
)
async def reopen_ticket(
    ticket_id: TicketIdPath,
    db: DatabaseSession,
    principal: Annotated[
        AuthenticatedPrincipal, Depends(require_capability(Capability.TRIAGE_TICKET))
    ],
    caller: AuthenticatedTicketCaller,
    ticket: Annotated[ResolvedTicket, Depends(require_accessible_ticket)],
) -> TicketDetailResponse:
    """Reopen Ticket — see `docs/features/tickets/tickets.md`.

    Authorization follows `docs/api-spec.md` (Authorization Chain
    Evaluation Order, flow 3): authentication, then `triage_ticket`
    before any Ticket lookup, then the delegated preliminary SNTL
    resolution. `reopen_from_ignored()` revalidates accessibility from
    locked-current state; it is the dedicated manual-zone exit and never
    produces `TICKET_NOT_MUTABLE`. The handler captures the one workflow
    `evaluation_date`, reused by the eligibility convergence, the final
    reconciliation, and the `TicketDetail` assembled from the locked
    post-state inside the same transaction
    (`docs/features/tickets/ticket-service.md`, `get_ticket_detail()`).
    """
    evaluation_date = _utc_now().date()
    try:
        await ticket_service.reopen_from_ignored(
            db,
            ticket_id=ticket.id,
            acting_user_id=principal.user.id,
            caller=caller,
            evaluation_date=evaluation_date,
        )
    except TicketNotFoundError:
        raise ticket_not_found_error() from None
    except InvalidTransitionError:
        raise _invalid_transition_error() from None
    detail = await ticket_service.assemble_ticket_detail(
        db, ticket_id=ticket.id, evaluation_date=evaluation_date
    )
    return TicketDetailResponse(data=serialize_ticket_detail(detail))


@router.post(
    "/tickets/{ticket_id}/revert-duplicate",
    response_model=TicketDetailResponse,
    summary="Revert Duplicate Status",
    description=(
        "Reverts a `duplicated` Ticket into the gate zone and clears its "
        "duplicate link. No request body. Tickets previously repointed away "
        "from this Ticket keep their current target. An active vulnerability "
        "analyst caller becomes the assignee, replacing any current assignee; "
        "otherwise the current assignee is kept. Automatic Product eligibility "
        "is re-evaluated from current data, and the Ticket status is evaluated "
        "from its gates (`analysis`, `analyzed`, or `resolved`). Returns the "
        "post-mutation Ticket detail. Requires `triage_ticket`."
    ),
    responses={
        404: {
            "model": ErrorResponse,
            "description": (
                "`TICKET_NOT_FOUND`: Ticket identifier is malformed, does not "
                "exist, or identifies a Ticket inaccessible to the caller."
            ),
        },
        409: {
            "model": ErrorResponse,
            "description": (
                "`TICKET_INVALID_TRANSITION`: the Ticket is not `duplicated`."
            ),
        },
    },
)
async def revert_ticket_duplicate(
    ticket_id: TicketIdPath,
    db: DatabaseSession,
    principal: Annotated[
        AuthenticatedPrincipal, Depends(require_capability(Capability.TRIAGE_TICKET))
    ],
    caller: AuthenticatedTicketCaller,
    ticket: Annotated[ResolvedTicket, Depends(require_accessible_ticket)],
) -> TicketDetailResponse:
    """Revert Duplicate Status — see `docs/features/tickets/tickets.md`.

    Authorization follows `docs/api-spec.md` (Authorization Chain
    Evaluation Order, flow 3): authentication, then `triage_ticket`
    before any Ticket lookup, then the delegated preliminary SNTL
    resolution. `revert_duplicate()` revalidates accessibility from
    locked-current state; it is the dedicated manual-zone exit and never
    produces `TICKET_NOT_MUTABLE`. The handler captures the one workflow
    `evaluation_date`, reused by the eligibility convergence, the final
    reconciliation, and the `TicketDetail` assembled from the locked
    post-state inside the same transaction
    (`docs/features/tickets/ticket-service.md`, `get_ticket_detail()`).
    """
    evaluation_date = _utc_now().date()
    try:
        await ticket_service.revert_duplicate(
            db,
            ticket_id=ticket.id,
            acting_user_id=principal.user.id,
            caller=caller,
            evaluation_date=evaluation_date,
        )
    except TicketNotFoundError:
        raise ticket_not_found_error() from None
    except InvalidTransitionError:
        raise _invalid_transition_error() from None
    detail = await ticket_service.assemble_ticket_detail(
        db, ticket_id=ticket.id, evaluation_date=evaluation_date
    )
    return TicketDetailResponse(data=serialize_ticket_detail(detail))


def _ticket_not_confidential_error() -> AppError:
    return AppError(
        status_code=status.HTTP_409_CONFLICT,
        code=ErrorCode.TICKET_NOT_CONFIDENTIAL,
        detail="Operation requires a confidential Ticket.",
    )


@router.patch(
    "/tickets/{ticket_id}/confidentiality",
    response_model=TicketDetailResponse,
    summary="Set Confidentiality",
    description=(
        "Sets whether a Ticket is confidential. Valid in every Ticket status, "
        "including `ignored` and `duplicated`; it never assigns the Ticket or "
        "changes its status. Making a confidential Ticket non-confidential "
        "deletes every explicit access grant; making it confidential again "
        "does not recreate them. Package-maintainer visibility and the "
        "Coordinated Release Date are unchanged. An unchanged request is an "
        "idempotent success. Returns the post-mutation Ticket detail. Requires "
        "`manage_confidentiality`."
    ),
    responses={
        404: {
            "model": ErrorResponse,
            "description": (
                "`TICKET_NOT_FOUND`: Ticket identifier is malformed, does not "
                "exist, or identifies a Ticket inaccessible to the caller."
            ),
        },
    },
)
async def set_ticket_confidentiality(
    ticket_id: TicketIdPath,
    body: TicketConfidentialityUpdateRequest,
    db: DatabaseSession,
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(require_capability(Capability.MANAGE_CONFIDENTIALITY)),
    ],
    caller: AuthenticatedTicketCaller,
    ticket: Annotated[ResolvedTicket, Depends(require_accessible_ticket)],
) -> TicketDetailResponse:
    """Set Confidentiality — see `docs/features/tickets/tickets.md`.

    Authorization follows `docs/api-spec.md` (Authorization Chain
    Evaluation Order, flow 3): authentication, then
    `manage_confidentiality` before any Ticket lookup, then the delegated
    preliminary SNTL resolution and body validation.
    `set_confidentiality()` revalidates accessibility from locked-current
    state; it is a visibility-only opt-out from `ensure_ticket_operable()`
    and never produces `TICKET_NOT_MUTABLE`. It takes no evaluation date,
    so the handler captures one UTC date at workflow entry solely for the
    `TicketDetail` assembled from the locked post-state inside the same
    transaction (`docs/features/tickets/ticket-service.md`,
    `get_ticket_detail()`).
    """
    evaluation_date = _utc_now().date()
    try:
        await ticket_service.set_confidentiality(
            db,
            ticket_id=ticket.id,
            is_confidential=body.is_confidential,
            acting_user_id=principal.user.id,
            caller=caller,
        )
    except TicketNotFoundError:
        raise ticket_not_found_error() from None
    detail = await ticket_service.assemble_ticket_detail(
        db, ticket_id=ticket.id, evaluation_date=evaluation_date
    )
    return TicketDetailResponse(data=serialize_ticket_detail(detail))


@router.patch(
    "/tickets/{ticket_id}/coordinated-release-date",
    response_model=TicketDetailResponse,
    summary="Set Coordinated Release Date",
    description=(
        "Sets, changes, or clears the Coordinated Release Date (embargo "
        "publication instant) of a confidential Ticket. An ISO 8601 date-time "
        "sets or replaces it (a value without a UTC offset is interpreted as "
        "UTC; past instants are accepted); JSON `null` clears it. Valid in "
        "every Ticket status, including `ignored` and `duplicated`; it never "
        "assigns the Ticket or changes its status. An unchanged request (the "
        "same instant, or `null` when none is set) is an idempotent success. "
        "Returns the post-mutation Ticket detail. Requires "
        "`manage_confidentiality`."
    ),
    responses={
        404: {
            "model": ErrorResponse,
            "description": (
                "`TICKET_NOT_FOUND`: Ticket identifier is malformed, does not "
                "exist, or identifies a Ticket inaccessible to the caller."
            ),
        },
        409: {
            "model": ErrorResponse,
            "description": (
                "`TICKET_NOT_CONFIDENTIAL`: the Ticket is not confidential "
                "(including a declassified Ticket that retains its date)."
            ),
        },
    },
)
async def set_ticket_coordinated_release_date(
    ticket_id: TicketIdPath,
    body: TicketCoordinatedReleaseDateUpdateRequest,
    db: DatabaseSession,
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(require_capability(Capability.MANAGE_CONFIDENTIALITY)),
    ],
    caller: AuthenticatedTicketCaller,
    ticket: Annotated[ResolvedTicket, Depends(require_accessible_ticket)],
) -> TicketDetailResponse:
    """Set Coordinated Release Date — see `docs/features/tickets/tickets.md`.

    Authorization follows `docs/api-spec.md` (Authorization Chain
    Evaluation Order, flow 3): authentication, then
    `manage_confidentiality` before any Ticket lookup, then the delegated
    preliminary SNTL resolution and body validation (the body value is
    already UTC). `set_coordinated_release_date()` revalidates
    accessibility from locked-current state before its confidentiality
    guard; it is an embargo-metadata opt-out from
    `ensure_ticket_operable()` and never produces `TICKET_NOT_MUTABLE`. It
    takes no evaluation date, so the handler captures one UTC date at
    workflow entry solely for the `TicketDetail` assembled from the locked
    post-state inside the same transaction
    (`docs/features/tickets/ticket-service.md`, `get_ticket_detail()`).
    """
    evaluation_date = _utc_now().date()
    try:
        await ticket_service.set_coordinated_release_date(
            db,
            ticket_id=ticket.id,
            coordinated_release_at=body.coordinated_release_at,
            acting_user_id=principal.user.id,
            caller=caller,
        )
    except TicketNotFoundError:
        raise ticket_not_found_error() from None
    except TicketNotConfidentialError:
        raise _ticket_not_confidential_error() from None
    detail = await ticket_service.assemble_ticket_detail(
        db, ticket_id=ticket.id, evaluation_date=evaluation_date
    )
    return TicketDetailResponse(data=serialize_ticket_detail(detail))


# ---------------------------------------------------------------------------
# Access Grant Management (tickets.md, List Access Grants, Grant Access,
# Revoke Access)
# ---------------------------------------------------------------------------

AccessGrantUserPath = Annotated[
    str,
    Path(
        description="Target user: UUID or exact username.",
        examples=["jdoe"],
    ),
]
"""The `{user}` path parameter of Revoke Access.

Deliberately an unconstrained string (tickets.md, Revoke Access): the
UUID-or-username value is passed unchanged to `revoke_access()`, which
reports an unknown user only after locked-current Ticket accessibility
and the confidentiality guard. The only exception is a value containing
U+0000, which the app-wide `reject_nul_in_request_input` dependency
rejects with `422` first (`docs/api-spec.md`, NUL Characters in Request
Input).
"""


def _user_inactive_error() -> AppError:
    return AppError(
        status_code=status.HTTP_409_CONFLICT,
        code=ErrorCode.USER_INACTIVE,
        detail="User is inactive.",
    )


def serialize_access_grant(
    grant: ticket_service.AccessGrantProjection,
) -> TicketAccessGrantResponse:
    """Build `TicketAccessGrantResponse`, shared by the list and grant
    endpoints so both item shapes are identical."""
    return TicketAccessGrantResponse(
        user=UserReference(
            id=grant.user.id,
            username=grant.user.username,
            full_name=grant.user.full_name,
            active=grant.user.active,
        ),
        granted_at=grant.granted_at,
        granted_by=UserReference(
            id=grant.granted_by.id,
            username=grant.granted_by.username,
            full_name=grant.granted_by.full_name,
            active=grant.granted_by.active,
        ),
    )


_TICKET_NOT_FOUND_DESCRIPTION: Final = (
    "`TICKET_NOT_FOUND`: Ticket identifier is malformed, does not exist, or "
    "identifies a Ticket inaccessible to the caller."
)


@router.get(
    "/tickets/{ticket_id}/access",
    response_model=TicketAccessGrantListResponse,
    summary="List Access Grants",
    description=(
        "Lists every user holding an explicit access grant on a confidential "
        "Ticket, with the current profiles of the user and of the grantor "
        "(deactivated users are included with `active = false`). Unpaginated: "
        "grants per Ticket are a bounded dataset, so the response has no "
        "`meta` object. The order is fixed, `granted_at` ascending then user "
        "UUID ascending, and not client-configurable: supplied `sort_by` or "
        "`sort_order` values are ignored. "
        "Requires `manage_confidentiality`."
    ),
    responses={
        404: {"model": ErrorResponse, "description": _TICKET_NOT_FOUND_DESCRIPTION},
        409: {
            "model": ErrorResponse,
            "description": "`TICKET_NOT_CONFIDENTIAL`: the Ticket is not confidential.",
        },
    },
)
async def list_ticket_access_grants(
    ticket_id: TicketIdPath,
    db: DatabaseSession,
    _principal: Annotated[
        AuthenticatedPrincipal,
        Depends(require_capability(Capability.MANAGE_CONFIDENTIALITY)),
    ],
    caller: AuthenticatedTicketCaller,
    ticket: Annotated[ResolvedTicket, Depends(require_accessible_ticket)],
) -> TicketAccessGrantListResponse:
    """List Access Grants — see `docs/features/tickets/tickets.md`.

    Authorization follows `docs/api-spec.md` (Authorization Chain
    Evaluation Order, flow 2): authentication, then
    `manage_confidentiality` before any Ticket lookup, then the delegated
    preliminary SNTL resolution. `list_access_grants()` re-applies Ticket
    visibility in the one statement that selects the parent and its
    grants, so the response never relies on that preliminary decision.
    """
    try:
        grants = await ticket_service.list_access_grants(
            db, ticket_id=ticket.id, caller=caller
        )
    except TicketNotFoundError:
        raise ticket_not_found_error() from None
    except TicketNotConfidentialError:
        raise _ticket_not_confidential_error() from None
    return TicketAccessGrantListResponse(
        data=[serialize_access_grant(grant) for grant in grants]
    )


@router.post(
    "/tickets/{ticket_id}/access",
    status_code=status.HTTP_201_CREATED,
    response_model=TicketAccessGrantDataResponse,
    summary="Grant Access",
    description=(
        "Grants a user, identified by UUID or exact username, explicit access "
        "to a confidential Ticket. Returns 201 with the new grant; when the "
        "grant already exists, returns 200 with the existing grant (original "
        "`granted_by` and `granted_at`), even when its user is now inactive. "
        "Valid in every Ticket status, including `ignored` and `duplicated`; "
        "it never assigns the Ticket or changes its status. Requires "
        "`manage_confidentiality`."
    ),
    responses={
        200: {
            "model": TicketAccessGrantDataResponse,
            "description": "The grant already exists; no change was made.",
        },
        404: {
            "model": ErrorResponse,
            "description": (
                f"{_TICKET_NOT_FOUND_DESCRIPTION} `USER_NOT_FOUND`: no user "
                "matches `user` (reported only for an accessible confidential "
                "Ticket)."
            ),
        },
        409: {
            "model": ErrorResponse,
            "description": (
                "`TICKET_NOT_CONFIDENTIAL`: the Ticket is not confidential "
                "(reported whether or not the user exists). `USER_INACTIVE`: the "
                "user is inactive and holds no grant on the Ticket."
            ),
        },
    },
)
async def grant_ticket_access(
    ticket_id: TicketIdPath,
    body: TicketAccessGrantRequest,
    response: Response,
    db: DatabaseSession,
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(require_capability(Capability.MANAGE_CONFIDENTIALITY)),
    ],
    caller: AuthenticatedTicketCaller,
    ticket: Annotated[ResolvedTicket, Depends(require_accessible_ticket)],
) -> TicketAccessGrantDataResponse:
    """Grant Access — see `docs/features/tickets/tickets.md`.

    Authorization follows `docs/api-spec.md` (Authorization Chain
    Evaluation Order, flow 3): authentication, then
    `manage_confidentiality` before any Ticket lookup, then the delegated
    preliminary SNTL resolution and body validation. The UUID-or-username
    `user` is passed unchanged: `grant_access()` locks the target before
    the Ticket but reports its absence only after locked-current
    accessibility and the confidentiality guard. The status code comes
    only from the service's serialized action (`created` → 201,
    `already_exists` → 200), never from an unlocked pre-read.
    """
    try:
        result = await ticket_service.grant_access(
            db,
            ticket_id=ticket.id,
            target_user=body.user,
            acting_user_id=principal.user.id,
            caller=caller,
        )
    except TicketNotFoundError:
        raise ticket_not_found_error() from None
    except TicketNotConfidentialError:
        raise _ticket_not_confidential_error() from None
    except UserNotFoundError:
        raise user_not_found_error() from None
    except InactiveUserError:
        raise _user_inactive_error() from None
    if result.action is AccessGrantAction.ALREADY_EXISTS:
        response.status_code = status.HTTP_200_OK
    return TicketAccessGrantDataResponse(data=serialize_access_grant(result.projection))


@router.delete(
    "/tickets/{ticket_id}/access/{user}",
    status_code=status.HTTP_204_NO_CONTENT,
    response_class=Response,
    summary="Revoke Access",
    description=(
        "Revokes the explicit access grant of a user, identified by UUID or "
        "exact username, on a confidential Ticket. Revoking from an inactive "
        "user is valid. When no grant exists, the request is an idempotent "
        "success. Valid in every Ticket status, including `ignored` and "
        "`duplicated`; it never assigns the Ticket or changes its status. "
        "Requires `manage_confidentiality`."
    ),
    responses={
        404: {
            "model": ErrorResponse,
            "description": (
                f"{_TICKET_NOT_FOUND_DESCRIPTION} `USER_NOT_FOUND`: no user "
                "matches `user` (reported only for an accessible confidential "
                "Ticket)."
            ),
        },
        409: {
            "model": ErrorResponse,
            "description": (
                "`TICKET_NOT_CONFIDENTIAL`: the Ticket is not confidential "
                "(reported whether or not the user exists)."
            ),
        },
    },
)
async def revoke_ticket_access(
    ticket_id: TicketIdPath,
    user: AccessGrantUserPath,
    db: DatabaseSession,
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(require_capability(Capability.MANAGE_CONFIDENTIALITY)),
    ],
    caller: AuthenticatedTicketCaller,
    ticket: Annotated[ResolvedTicket, Depends(require_accessible_ticket)],
) -> Response:
    """Revoke Access — see `docs/features/tickets/tickets.md`.

    Authorization follows `docs/api-spec.md` (Authorization Chain
    Evaluation Order, flow 3), as Grant Access. The `{user}` path value
    is passed unchanged to `revoke_access()`; both an effective revoke and
    an absent-grant no-op return 204 with an empty body.
    """
    try:
        await ticket_service.revoke_access(
            db,
            ticket_id=ticket.id,
            target_user=user,
            acting_user_id=principal.user.id,
            caller=caller,
        )
    except TicketNotFoundError:
        raise ticket_not_found_error() from None
    except TicketNotConfidentialError:
        raise _ticket_not_confidential_error() from None
    except UserNotFoundError:
        raise user_not_found_error() from None
    return Response(status_code=status.HTTP_204_NO_CONTENT)
