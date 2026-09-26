"""Response schemas for Tickets.

See `docs/features/tickets/tickets.md` (Response Schemas > TicketDetail,
Endpoint -> Schema Mapping) for the authoritative contract,
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

from app.schemas.common import SeverityValue, UserReference
from app.schemas.cve import CVEDetail
from app.schemas.package import PackageDetail

type TicketStatusValue = Literal[
    "new", "analysis", "analyzed", "resolved", "ignored", "duplicated"
]
type TicketPriorityValue = Literal["p1", "p2", "p3", "p4"]


class TicketDetail(BaseModel):
    """Full Ticket representation for the detail endpoint and every
    mutation endpoint returning a Ticket.

    Replaces the compact `package_names` of list views with the complete
    package tree and uses expanded CVE data. Maintainer identities are
    never exposed.
    """

    ticket_id: str = Field(
        description="Canonical Ticket identity (`SNTL-{n}`).", examples=["SNTL-42"]
    )
    status: TicketStatusValue = Field(
        description=(
            "Ticket status: `new`, `analysis`, `analyzed`, `resolved`, "
            "`ignored`, or `duplicated`."
        )
    )
    severity: SeverityValue | None = Field(
        description=(
            "Resolved severity (the CVE severity for a Ticket with a CVE, "
            "otherwise the manual severity): `critical`, `high`, `medium`, "
            "`low`, or `none` (CVSS score 0.0, informational), or `null` "
            "when unresolved (no CVSS data and no manual severity set). "
            "`none` is distinct from `null`."
        )
    )
    priority: TicketPriorityValue | None = Field(
        description=(
            "Effective priority: `priority_override` when set, otherwise "
            "`priority_automatic`. `p1`-`p4`, or `null` when not yet "
            "prioritizable."
        )
    )
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
    assignee: UserReference | None = Field(
        description="Assigned Vulnerability Analyst, or `null` if unassigned."
    )
    cve: CVEDetail | None = Field(
        description="Expanded data of the associated CVE, or `null` if no CVE."
    )
    duplicate_of_ticket_id: str | None = Field(
        description=(
            "Canonical identity (`SNTL-{n}`) of the Ticket this Ticket "
            "duplicates, or `null`. Only the identifier is exposed: following "
            "it applies ordinary accessibility and may return "
            "`404 TICKET_NOT_FOUND`."
        ),
        examples=["SNTL-7"],
    )
    is_confidential: bool = Field(description="Whether the Ticket is confidential.")
    coordinated_release_at: datetime | None = Field(
        description=(
            "Coordinated Release Date (embargo publication instant, UTC), or "
            "`null` when none is set."
        )
    )
    triage_due_at: datetime | None = Field(
        description=(
            "Due date (UTC) of the triage milestone, in which the VA "
            "(Vulnerability Analyst) decides affectedness; `null` when no SLA "
            "applies (Ticket `ignored` or `duplicated`, or severity `none`)."
        )
    )
    submission_due_at: datetime | None = Field(
        description=(
            "Due date (UTC) of the submission milestone, in which the "
            "maintainer prepares the fix and submits it to IBS (submission "
            "request, SR)."
        )
    )
    um_due_at: datetime | None = Field(
        description=(
            "Due date (UTC) of the UM milestone, in which the UM (SUSE "
            "maintenance update team) prepares the maintenance update and "
            "creates the release request (RR)."
        )
    )
    qa_due_at: datetime | None = Field(
        description=(
            "Due date (UTC) of the QA milestone, in which QA (quality "
            "assurance) tests the maintenance update before publication; "
            "currently equal to `release_due_at`."
        )
    )
    release_due_at: datetime | None = Field(
        description=(
            "Final deadline (UTC) by which the update must be released; "
            "currently equal to `qa_due_at`."
        )
    )
    packages: list[PackageDetail] = Field(
        description=(
            "Complete package/track/Product tree, including excluded and "
            "non-actionable records, ordered by `package_name` (Unicode code "
            "point). Maintainer identities are not exposed."
        )
    )
    created_at: datetime = Field(description="Creation timestamp (UTC).")
    updated_at: datetime = Field(description="Last modification timestamp (UTC).")


class TicketDetailResponse(BaseModel):
    """Response body for `GET /api/v1/tickets/{ticket_id}`."""

    data: TicketDetail
