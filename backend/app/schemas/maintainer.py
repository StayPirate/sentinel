"""Response schemas for the maintainer workbench.

See `docs/features/packages/maintainer.md` (Workbench Row and Privacy
Contract, Shared Global-List Query Contract, API Endpoints) for the
authoritative contracts and `docs/features/tickets/ticket-deadlines.md`
(Actors and Phases, Track Milestones, API Surface) for the submission
deadline semantics these OpenAPI descriptions convey to external
consumers.

Every enumerated value is serialized in lowercase. `ticket_id` is the
only Ticket identity; no Ticket UUID, track UUID, maintainer identity,
personal identifier, group, or SMELT data is exposed.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

from app.schemas.common import PaginationMeta, SeverityValue
from app.schemas.package import (
    DeliveryStatusValue,
    MilestoneStatusValue,
    PackageStatusValue,
    WorkflowTypeValue,
)


class MaintainerWorkItem(BaseModel):
    """One workbench item: one exact package track maintained by the caller.

    The submission phase is the maintainer's share of the remediation SLA:
    the maintainer prepares the fix and submits it to IBS (submission
    request, SR). A submission milestone `pending` is unrelated to
    `delivery_status = pending`.
    """

    package_name: str = Field(description="Source package name.")
    ticket_id: str = Field(
        description="Canonical Ticket identity (`SNTL-{n}`).",
        examples=["SNTL-42"],
    )
    cve_id: str | None = Field(
        description="Associated CVE identifier; `null` for a Ticket without a CVE."
    )
    severity: SeverityValue | None = Field(
        description=(
            "Resolved Ticket severity: `critical`, `high`, `medium`, `low`, or "
            "`none`; `null` when not yet resolved."
        )
    )
    workflow_type: WorkflowTypeValue = Field(
        description="Delivery workflow of the track: `ibs` or `git`."
    )
    reference: str = Field(
        description="IBS codestream project or Git branch reference of the track."
    )
    status: PackageStatusValue = Field(
        description=(
            "Affectedness of the track: `analysis`, `affected`, "
            "`not_affected`, `fixed`, or `wont_fix`."
        )
    )
    delivery_status: DeliveryStatusValue = Field(
        description=(
            "Delivery pipeline status of the track: `pending`, `in_progress`, "
            "or `released`. Unrelated to a submission milestone `pending`."
        )
    )
    submission_due_at: datetime | None = Field(
        description=(
            "Due date (UTC) of the submission milestone of this track: the "
            "date by which the maintainer, who prepares the fix and submits it "
            "to IBS (submission request, SR), should complete the submission "
            "phase of the remediation SLA. `null` when no SLA applies."
        )
    )
    submission_milestone: MilestoneStatusValue | None = Field(
        description=(
            "Status of the maintainer submission milestone of this track: "
            "`done` (submitted: delivery is `in_progress` or `released`, or a "
            "later phase is completed), `pending` (not completed and its due "
            "date is not past), `overdue` (not completed and its due date is "
            "past), `not_applicable` (the phase does not apply to this track), "
            "or `null` (no SLA applies, or Sentinel cannot observe the phase, "
            "such as a Git track or a Ticket without a CVE). A milestone "
            "`pending` is unrelated to `delivery_status = pending`."
        )
    )


class MaintainerWorkListResponse(BaseModel):
    """A paginated workbench global list."""

    data: list[MaintainerWorkItem]
    meta: PaginationMeta


class MaintainerTicketWork(BaseModel):
    """The caller's classified work on one Ticket.

    Each array is ordered by `package_name`, then `reference` (ascending
    Unicode code point); an item appears in at most one array. All three
    arrays are empty when the caller has no qualifying work on the Ticket.
    """

    pending: list[MaintainerWorkItem] = Field(
        description="Tracks with an affected, not yet delivered fix."
    )
    in_progress: list[MaintainerWorkItem] = Field(
        description="Tracks whose delivery is in progress."
    )
    completed: list[MaintainerWorkItem] = Field(
        description="Tracks whose delivery is released."
    )


class MaintainerTicketWorkResponse(BaseModel):
    """The per-Ticket workbench response (unpaginated)."""

    data: MaintainerTicketWork
