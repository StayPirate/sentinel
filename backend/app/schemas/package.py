"""Response schemas for the Ticket package tree.

See `docs/features/tickets/tickets.md` (Response Schemas > ProductDetail,
TrackDetail, TrackMilestones, PackageDetail) for the authoritative
contracts, `docs/features/packages/package-model.md` (Derived
Actionability, Delivery Relevance Indicator, List Ticket Packages), and
`docs/features/tickets/ticket-deadlines.md` (Actors and Phases, Track
Milestones, API Surface) for the field semantics these OpenAPI
descriptions convey to external consumers.

Every enumerated value is serialized in lowercase. Package-tree UUIDs are
public nested-resource locators; the internal Ticket and catalog Product
UUIDs are never serialized (`docs/api-spec.md`, Product Identifier
Resolution).
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, Field

type PackageStatusValue = Literal[
    "analysis", "affected", "not_affected", "fixed", "wont_fix"
]
type DeliveryStatusValue = Literal["pending", "in_progress", "released"]
type WorkflowTypeValue = Literal["ibs", "git"]
type LifecyclePhaseValue = Literal[
    "pre_release", "general_support", "extended_support", "reactive_support", "eol"
]
type ProductReasonValue = Literal[
    "package_excluded", "track_excluded", "product_excluded", "eol"
]
type TrackReasonValue = Literal[
    "package_excluded", "track_excluded", "no_actionable_products"
]
type PackageReasonValue = Literal["package_excluded", "no_actionable_tracks"]
type MilestoneStatusValue = Literal["done", "pending", "overdue", "not_applicable"]
type CurrentPhaseValue = Literal["triage", "submission", "um", "qa", "done"]

_MILESTONE_VALUES = (
    "`done` (completed), `pending` (not completed and its due date is not "
    "past), `overdue` (not completed and its due date is past), "
    "`not_applicable` (the phase does not apply to this track), or `null` "
    "(no SLA applies, or Sentinel cannot observe the phase for this track, "
    "such as a Git track or a Ticket without a CVE). A milestone `pending` "
    "is unrelated to `delivery_status = pending`."
)


class ProductDetail(BaseModel):
    """One Product occurrence within a track."""

    id: UUID = Field(description="TicketPackageProduct occurrence identifier.")
    product_cpe: str = Field(
        description="Canonical public identity (CPE) of the related catalog Product."
    )
    product_name: str = Field(description="Product display name.")
    eligible: bool = Field(
        description="Whether this Product receives the fix (effective eligibility)."
    )
    is_eligible_override: bool = Field(
        description="`true` if an authorized acting user manually set eligibility."
    )
    released_at: datetime | None = Field(
        description=(
            "Issued time (UTC) of the validated stable security advisory that "
            "established the Product release; `null` until confirmed."
        )
    )
    lifecycle_phase: LifecyclePhaseValue | None = Field(
        description=(
            "Current Product lifecycle phase for the response's UTC evaluation "
            "date; `null` when lifecycle data is unavailable."
        )
    )
    deleted_at: datetime | None = Field(
        description=(
            "Direct manual-exclusion timestamp of this occurrence only; "
            "`null` when not directly excluded. Use `actionable` for current "
            "participation."
        )
    )
    actionable: bool = Field(
        description=(
            "Whether the Product currently participates in operational "
            "decisions: no manual exclusion at package, track, or Product "
            "level, and not end-of-life."
        )
    )
    non_actionable_reason: ProductReasonValue | None = Field(
        description=(
            "First applicable reason in the order `package_excluded`, "
            "`track_excluded`, `product_excluded`, `eol`; `null` when "
            "actionable."
        )
    )


class TrackMilestones(BaseModel):
    """Milestone status per phase of one track.

    Each member is one of: done, pending, overdue, not_applicable, or
    null. A milestone `pending` is unrelated to `delivery_status = pending`.
    """

    triage: MilestoneStatusValue | None = Field(
        description=(
            "Triage phase: the VA (Vulnerability Analyst) decides the "
            "affectedness of the track. " + _MILESTONE_VALUES
        )
    )
    submission: MilestoneStatusValue | None = Field(
        description=(
            "Submission phase: the maintainer prepares the fix and submits "
            "it to IBS as a submission request (SR). " + _MILESTONE_VALUES
        )
    )
    um: MilestoneStatusValue | None = Field(
        description=(
            "UM phase: the UM (SUSE maintenance update team) prepares the "
            "maintenance update and creates the release request (RR). "
            + _MILESTONE_VALUES
        )
    )
    qa: MilestoneStatusValue | None = Field(
        description=(
            "QA phase: QA (quality assurance) tests the maintenance update, "
            "which is then published to every actionable eligible Product. "
            + _MILESTONE_VALUES
        )
    )


class TrackDetail(BaseModel):
    """One track (IBS codestream or Git branch) within a package."""

    id: UUID = Field(description="TicketPackageTrack identifier.")
    workflow_type: WorkflowTypeValue = Field(description="`ibs` or `git`.")
    reference: str = Field(description="Codestream project name or branch reference.")
    status: PackageStatusValue = Field(
        description=(
            "Affectedness of the track: `analysis`, `affected`, "
            "`not_affected`, `fixed`, or `wont_fix`."
        )
    )
    delivery_status: DeliveryStatusValue = Field(
        description=(
            "Delivery pipeline status: `pending`, `in_progress`, or "
            "`released`. `pending` is the system default: it does not imply "
            "that a fix is expected, does not prove that no submission "
            "request exists, and does not establish that synchronization "
            "succeeded. Use `delivery_relevant` to decide whether this value "
            "is operationally significant."
        )
    )
    delivery_relevant: bool = Field(
        description=(
            "Computed: `true` when the affectedness is `analysis` or "
            "`affected`, or `delivery_status` is not `pending`. When `false`, "
            "consumers should not display `delivery_status` or make decisions "
            "based on it."
        )
    )
    products: list[ProductDetail] = Field(
        description=(
            "Product occurrences under this track, including excluded and "
            "non-actionable ones, ordered by `product_cpe` (Unicode code point)."
        )
    )
    deleted_at: datetime | None = Field(
        description=(
            "Direct manual-exclusion timestamp of this track only; `null` when "
            "not directly excluded."
        )
    )
    actionable: bool = Field(
        description=(
            "Whether the track is not manually excluded (directly or through "
            "its package) and has at least one actionable Product."
        )
    )
    non_actionable_reason: TrackReasonValue | None = Field(
        description=(
            "First applicable reason in the order `package_excluded`, "
            "`track_excluded`, `no_actionable_products`; `null` when actionable."
        )
    )
    triage_due_at: datetime | None = Field(
        description=(
            "Due date (UTC) of the VA (Vulnerability Analyst) triage "
            "milestone for this track; `null` when no SLA applies (Ticket "
            "`ignored` or `duplicated`, or severity `none`)."
        )
    )
    submission_due_at: datetime | None = Field(
        description="Due date (UTC) of the maintainer submission (SR) milestone."
    )
    um_due_at: datetime | None = Field(
        description=(
            "Due date (UTC) of the UM (SUSE maintenance update team) "
            "release-request (RR) milestone."
        )
    )
    qa_due_at: datetime | None = Field(
        description=(
            "Due date (UTC) of the QA (quality assurance) milestone; currently "
            "equal to `release_due_at`."
        )
    )
    release_due_at: datetime | None = Field(
        description=(
            "Final deadline (UTC) by which the update must be released; "
            "currently equal to `qa_due_at`."
        )
    )
    milestones: TrackMilestones = Field(
        description="Per-phase milestone status of this track."
    )
    current_phase: CurrentPhaseValue | None = Field(
        description=(
            "First phase not yet completed, in the order `triage` (VA), "
            "`submission` (maintainer), `um` (UM), `qa` (QA); `done` when "
            "every applicable phase is completed; `null` when no SLA applies "
            "or an unobservable (`null`) phase is reached before any pending "
            "or overdue phase. `pending` and `overdue` are never phases."
        )
    )


class PackageDetail(BaseModel):
    """One source package within a Ticket, with its complete track tree.

    Maintainer identities are never exposed.
    """

    id: UUID = Field(description="TicketPackage identifier.")
    package_name: str = Field(description="Source package name.")
    tracks: list[TrackDetail] = Field(
        description=(
            "Tracks of this package, including excluded and non-actionable "
            "ones, ordered by `reference` (Unicode code point)."
        )
    )
    deleted_at: datetime | None = Field(
        description=(
            "Direct manual-exclusion timestamp of this package; `null` when "
            "not directly excluded."
        )
    )
    actionable: bool = Field(
        description=(
            "Whether the package is not manually excluded and has at least "
            "one actionable track."
        )
    )
    non_actionable_reason: PackageReasonValue | None = Field(
        description=(
            "First applicable reason in the order `package_excluded`, "
            "`no_actionable_tracks`; `null` when actionable."
        )
    )


class TicketPackageListResponse(BaseModel):
    """Response body for `GET /api/v1/tickets/{ticket_id}/packages`.

    Unpaginated: the package count per Ticket is bounded.
    """

    data: list[PackageDetail]
