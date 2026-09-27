"""Response schemas for Tickets.

See `docs/features/tickets/tickets.md` (Response Schemas > TicketSummary
and TicketDetail, Endpoint -> Schema Mapping, List Tickets) for the
authoritative contract,
`docs/features/tickets/ticket-priority.md` (API Surface) for the priority
fields, and `docs/features/tickets/ticket-deadlines.md` (Actors and
Phases, Due Dates, API Surface) for the due-date semantics these OpenAPI
descriptions convey to external consumers.

A Ticket is identified only by its canonical `SNTL-{n}` identity
(`ticket_id`); a duplicate target only by `duplicate_of_ticket_id`. The
internal Ticket UUID is never serialized (`docs/api-spec.md`, Ticket
Identifier Resolution). Every enumerated value is serialized in
lowercase.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

from app.core.enums import SortOrder, TicketSortField
from app.schemas.common import PaginationMeta, SeverityValue, UserReference
from app.schemas.cve import CVEDetail, CVESummary
from app.schemas.package import PackageDetail

type TicketStatusValue = Literal[
    "new", "analysis", "analyzed", "resolved", "ignored", "duplicated"
]
type TicketPriorityValue = Literal["p1", "p2", "p3", "p4"]

# Field descriptions shared by `TicketSummary` and `TicketDetail`, so the
# two representations cannot drift (docs/features/tickets/tickets.md,
# Response Schemas; docs/features/tickets/ticket-deadlines.md, Actors and
# Phases: the phases and actors are defined for external consumers).
_TICKET_ID_DESCRIPTION = "Canonical Ticket identity (`SNTL-{n}`)."
_STATUS_DESCRIPTION = (
    "Ticket status: `new`, `analysis`, `analyzed`, `resolved`, `ignored`, or "
    "`duplicated`."
)
_SEVERITY_DESCRIPTION = (
    "Resolved severity (the CVE severity for a Ticket with a CVE, otherwise "
    "the manual severity): `critical`, `high`, `medium`, `low`, or `none` "
    "(CVSS score 0.0, informational), or `null` when unresolved (no CVSS "
    "data and no manual severity set). `none` is distinct from `null`."
)
_PRIORITY_DESCRIPTION = (
    "Effective priority: `priority_override` when set, otherwise "
    "`priority_automatic`. `p1`-`p4`, or `null` when not yet prioritizable."
)
_ASSIGNEE_DESCRIPTION = "Assigned Vulnerability Analyst, or `null` if unassigned."
_DUPLICATE_OF_DESCRIPTION = (
    "Canonical identity (`SNTL-{n}`) of the Ticket this Ticket duplicates, or "
    "`null`. Only the identifier is exposed: following it applies ordinary "
    "accessibility and may return `404 TICKET_NOT_FOUND`."
)
_IS_CONFIDENTIAL_DESCRIPTION = "Whether the Ticket is confidential."
_TRIAGE_DUE_DESCRIPTION = (
    "Due date (UTC) of the triage milestone, in which the VA (Vulnerability "
    "Analyst) decides affectedness; `null` when no SLA applies (Ticket "
    "`ignored` or `duplicated`, or severity `none`)."
)
_SUBMISSION_DUE_DESCRIPTION = (
    "Due date (UTC) of the submission milestone, in which the maintainer "
    "prepares the fix and submits it to IBS (submission request, SR)."
)
_UM_DUE_DESCRIPTION = (
    "Due date (UTC) of the UM milestone, in which the UM (SUSE maintenance "
    "update team) prepares the maintenance update and creates the release "
    "request (RR)."
)
_QA_DUE_DESCRIPTION = (
    "Due date (UTC) of the QA milestone, in which QA (quality assurance) "
    "tests the maintenance update before publication; currently equal to "
    "`release_due_at`."
)
_RELEASE_DUE_DESCRIPTION = (
    "Final deadline (UTC) by which the update must be released; currently "
    "equal to `qa_due_at`."
)
_CREATED_AT_DESCRIPTION = "Creation timestamp (UTC)."
_UPDATED_AT_DESCRIPTION = "Last modification timestamp (UTC)."


class TicketSummary(BaseModel):
    """Compact Ticket representation returned by the list endpoint.

    Provides enough information for table views without the package
    tree: `package_names` replaces it with the included package names.
    """

    ticket_id: str = Field(description=_TICKET_ID_DESCRIPTION, examples=["SNTL-42"])
    status: TicketStatusValue = Field(description=_STATUS_DESCRIPTION)
    severity: SeverityValue | None = Field(description=_SEVERITY_DESCRIPTION)
    priority: TicketPriorityValue | None = Field(description=_PRIORITY_DESCRIPTION)
    assignee: UserReference | None = Field(description=_ASSIGNEE_DESCRIPTION)
    cve: CVESummary | None = Field(
        description="Summary of the associated CVE, or `null` if no CVE."
    )
    duplicate_of_ticket_id: str | None = Field(
        description=_DUPLICATE_OF_DESCRIPTION, examples=["SNTL-7"]
    )
    is_confidential: bool = Field(description=_IS_CONFIDENTIAL_DESCRIPTION)
    coordinated_release_at: datetime | None = Field(
        description=(
            "Coordinated Release Date (embargo publication instant, UTC), or "
            "`null` when none is set. A retained value on a non-confidential "
            "Ticket is historical and inert."
        )
    )
    triage_due_at: datetime | None = Field(description=_TRIAGE_DUE_DESCRIPTION)
    submission_due_at: datetime | None = Field(description=_SUBMISSION_DUE_DESCRIPTION)
    um_due_at: datetime | None = Field(description=_UM_DUE_DESCRIPTION)
    qa_due_at: datetime | None = Field(description=_QA_DUE_DESCRIPTION)
    release_due_at: datetime | None = Field(description=_RELEASE_DUE_DESCRIPTION)
    package_names: list[str] = Field(
        description=(
            "Exact-deduplicated names of the directly included packages, "
            "ordered by ascending Unicode code point. Product lifecycle "
            "actionability does not remove an included package name."
        ),
        examples=[["curl", "openssl-3"]],
    )
    created_at: datetime = Field(description=_CREATED_AT_DESCRIPTION)
    updated_at: datetime = Field(description=_UPDATED_AT_DESCRIPTION)


class TicketListResponse(BaseModel):
    """Response body for `GET /api/v1/tickets` (paginated)."""

    data: list[TicketSummary]
    meta: PaginationMeta


class TicketListQuery(BaseModel):
    """Query parameters for `GET /api/v1/tickets` (tickets.md, List
    Tickets).

    The repeatable enum filters (`status`, `severity`, `priority`,
    `overdue`) are intentionally raw `list[str]`: an invalid value is
    silently dropped rather than rejected (`docs/api-spec.md`, Enum
    Filter Validation), and an empty list means the filter was omitted.
    `sort_by` and `sort_order` are typed, so an invalid value is the
    global `422 VALIDATION_ERROR` (Sort Parameter Validation). String
    parameters share the global 500-character limit.
    """

    search: str | None = None
    status: list[str] = Field(default_factory=list)
    assignee: str | None = None
    severity: list[str] = Field(default_factory=list)
    priority: list[str] = Field(default_factory=list)
    overdue: list[str] = Field(default_factory=list)
    maintainer: str | None = None
    page: int = Field(default=1, ge=1, le=2_147_483_647)
    per_page: int = Field(default=20, ge=1, le=100)
    sort_by: TicketSortField = TicketSortField.CREATED_AT
    sort_order: SortOrder = SortOrder.DESC


class TicketDetail(BaseModel):
    """Full Ticket representation for the detail endpoint and every
    mutation endpoint returning a Ticket.

    Replaces the compact `package_names` of list views with the complete
    package tree and uses expanded CVE data. Maintainer identities are
    never exposed.
    """

    ticket_id: str = Field(description=_TICKET_ID_DESCRIPTION, examples=["SNTL-42"])
    status: TicketStatusValue = Field(description=_STATUS_DESCRIPTION)
    severity: SeverityValue | None = Field(description=_SEVERITY_DESCRIPTION)
    priority: TicketPriorityValue | None = Field(description=_PRIORITY_DESCRIPTION)
    priority_automatic: TicketPriorityValue | None = Field(
        description=(
            "System-derived priority: `p1`-`p4`, or `null` when not yet prioritizable."
        )
    )
    priority_override: TicketPriorityValue | None = Field(
        description=(
            "Manual priority override: `p1`-`p4`, or `null` when no override is set."
        )
    )
    assignee: UserReference | None = Field(description=_ASSIGNEE_DESCRIPTION)
    cve: CVEDetail | None = Field(
        description="Expanded data of the associated CVE, or `null` if no CVE."
    )
    duplicate_of_ticket_id: str | None = Field(
        description=_DUPLICATE_OF_DESCRIPTION, examples=["SNTL-7"]
    )
    is_confidential: bool = Field(description=_IS_CONFIDENTIAL_DESCRIPTION)
    coordinated_release_at: datetime | None = Field(
        description=(
            "Coordinated Release Date (embargo publication instant, UTC), or "
            "`null` when none is set."
        )
    )
    triage_due_at: datetime | None = Field(description=_TRIAGE_DUE_DESCRIPTION)
    submission_due_at: datetime | None = Field(description=_SUBMISSION_DUE_DESCRIPTION)
    um_due_at: datetime | None = Field(description=_UM_DUE_DESCRIPTION)
    qa_due_at: datetime | None = Field(description=_QA_DUE_DESCRIPTION)
    release_due_at: datetime | None = Field(description=_RELEASE_DUE_DESCRIPTION)
    packages: list[PackageDetail] = Field(
        description=(
            "Complete package/track/Product tree, including excluded and "
            "non-actionable records, ordered by `package_name` (Unicode code "
            "point). Maintainer identities are not exposed."
        )
    )
    created_at: datetime = Field(description=_CREATED_AT_DESCRIPTION)
    updated_at: datetime = Field(description=_UPDATED_AT_DESCRIPTION)


class TicketDetailResponse(BaseModel):
    """Response body for `GET /api/v1/tickets/{ticket_id}`."""

    data: TicketDetail
