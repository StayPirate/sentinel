"""Request and response schemas for the Ticket package tree.

See `docs/features/tickets/tickets.md` (Response Schemas > ProductDetail,
TrackDetail, TrackMilestones, PackageDetail) for the authoritative
contracts, `docs/features/packages/package-model.md` (Derived
Actionability, Delivery Relevance Indicator, List Ticket Packages,
Change Track Status, Override Product Eligibility, Soft-Delete and Restore
Package, Track, and Product, Search Packages Across Tickets), and
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
from typing import Literal, Self
from uuid import UUID

from pydantic import BaseModel, Field, model_validator

from app.core.enums import PackageSortField, SortOrder
from app.schemas.common import PaginationMeta, SeverityValue, TicketStatusValue

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

# Consumer-facing guidance required on every response schema exposing the
# two fields (package-model.md, Delivery Relevance Indicator).
_DELIVERY_STATUS_DESCRIPTION = (
    "Delivery pipeline status: `pending`, `in_progress`, or `released`. "
    "`pending` is the system default: it does not imply that a fix is "
    "expected, does not prove that no submission request exists, and does "
    "not establish that synchronization succeeded. Use `delivery_relevant` to "
    "decide whether this value is operationally significant."
)
_DELIVERY_RELEVANT_DESCRIPTION = (
    "Computed: `true` when the affectedness is `analysis` or `affected`, or "
    "`delivery_status` is not `pending`. When `false`, consumers should not "
    "display `delivery_status` or make decisions based on it."
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
        description=_DELIVERY_STATUS_DESCRIPTION
    )
    delivery_relevant: bool = Field(description=_DELIVERY_RELEVANT_DESCRIPTION)
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


class TrackStatusUpdateRequest(BaseModel):
    """Request body of `PATCH .../packages/{package_id}/tracks/{track_id}`.

    See `docs/features/packages/package-model.md` (Change Track Status).
    The single field is required and non-nullable; an omitted field,
    `null`, a non-string, or any value outside the five lowercase
    affectedness labels fails with the global `422 VALIDATION_ERROR`.
    """

    status: PackageStatusValue = Field(
        description=(
            "New affectedness status: `analysis`, `affected`, `not_affected`, "
            "`fixed`, or `wont_fix`. `fixed` accepts `admin_ticket_ops` (any "
            "Ticket) or `manage_packages` (only a Ticket without a CVE); every "
            "other value requires `manage_packages`. Required."
        ),
        examples=["affected"],
    )


class TrackStatusProduct(BaseModel):
    """One Product occurrence of a track-status mutation response."""

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
    lifecycle_phase: LifecyclePhaseValue | None = Field(
        description=(
            "Product lifecycle phase for the mutation's UTC evaluation date; "
            "`null` when lifecycle data is unavailable."
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


class TrackStatusTrack(BaseModel):
    """The locked-current track returned by a track-status mutation."""

    ticket_id: str = Field(description="Canonical Ticket identity (`SNTL-{n}`).")
    package_name: str = Field(description="Source package name.")
    reference: str = Field(description="Codestream project name or branch reference.")
    status: PackageStatusValue = Field(
        description=(
            "Current affectedness of the track: `analysis`, `affected`, "
            "`not_affected`, `fixed`, or `wont_fix`."
        )
    )
    delivery_status: DeliveryStatusValue = Field(
        description=_DELIVERY_STATUS_DESCRIPTION
    )
    delivery_relevant: bool = Field(description=_DELIVERY_RELEVANT_DESCRIPTION)
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
    products: list[TrackStatusProduct] = Field(
        description=(
            "Every Product occurrence of the track, including excluded and "
            "non-actionable ones, ordered by `product_cpe` (Unicode code point)."
        )
    )


class TrackStatusResponse(BaseModel):
    """Response body of `PATCH .../packages/{package_id}/tracks/{track_id}`."""

    data: TrackStatusTrack


class ProductEligibilityUpdateRequest(BaseModel):
    """Request body of `PATCH .../products/{ticket_package_product_id}`.

    See `docs/features/packages/package-model.md` (Override Product
    Eligibility). The single field is required and nullable
    (`docs/api-spec.md`, Partial Update Semantics: single-field PATCH): a
    JSON boolean sets or changes the override, while JSON `null` resets
    the Product to automatic calculation. An omitted field or any value
    other than a JSON boolean or `null` (`docs/api-spec.md`, JSON Request
    Body Scalar Types) fails with the global `422 VALIDATION_ERROR`.
    """

    eligible: bool | None = Field(
        strict=True,
        description=(
            "Eligibility override: `true` or `false` sets or changes the manual "
            "override; JSON `null` removes it and immediately recalculates "
            "eligibility automatically (CVSS threshold and lifecycle phase). "
            "Required."
        ),
        examples=[False, None],
    )


class ProductEligibilityProduct(BaseModel):
    """The locked-current Product occurrence returned by an eligibility override."""

    ticket_id: str = Field(description="Canonical Ticket identity (`SNTL-{n}`).")
    package_name: str = Field(description="Parent source package name.")
    reference: str = Field(
        description="Parent track reference (codestream project name or branch)."
    )
    id: UUID = Field(description="TicketPackageProduct occurrence identifier.")
    product_cpe: str = Field(
        description="Canonical public identity (CPE) of the related catalog Product."
    )
    product_name: str = Field(description="Product display name.")
    eligible: bool = Field(
        description="Whether this Product receives the fix (effective eligibility)."
    )
    is_eligible_override: bool = Field(
        description=(
            "`true` if an authorized acting user manually set eligibility; "
            "`false` when eligibility is calculated automatically."
        )
    )
    lifecycle_phase: LifecyclePhaseValue | None = Field(
        description=(
            "Product lifecycle phase for the mutation's UTC evaluation date; "
            "`null` when lifecycle data is unavailable."
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


class ProductEligibilityResponse(BaseModel):
    """Response body of `PATCH .../products/{ticket_package_product_id}`."""

    data: ProductEligibilityProduct


# Exclusion and restoration (package-model.md, Soft-Delete and Restore Package,
# Track, and Product). One schema per level, shared by exclude and restore.


class PackageExclusionPackage(BaseModel):
    """The locked-current package returned by a package exclude or restore."""

    package_name: str = Field(description="Source package name.")
    actionable: bool = Field(
        description=(
            "Whether the package is not manually excluded and has at least "
            "one actionable track, on the mutation's UTC evaluation date."
        )
    )
    non_actionable_reason: PackageReasonValue | None = Field(
        description=(
            "First applicable reason in the order `package_excluded`, "
            "`no_actionable_tracks`; `null` when actionable."
        )
    )


class PackageExclusionResponse(BaseModel):
    """Response body of `POST .../packages/{package_id}/exclude|restore`."""

    data: PackageExclusionPackage


class TrackExclusionTrack(BaseModel):
    """The locked-current track returned by a track exclude or restore."""

    reference: str = Field(
        description="Track reference (codestream project name or branch)."
    )
    actionable: bool = Field(
        description=(
            "Whether the track is not manually excluded (directly or through "
            "its package) and has at least one actionable Product, on the "
            "mutation's UTC evaluation date."
        )
    )
    non_actionable_reason: TrackReasonValue | None = Field(
        description=(
            "First applicable reason in the order `package_excluded`, "
            "`track_excluded`, `no_actionable_products`; `null` when actionable."
        )
    )


class TrackExclusionResponse(BaseModel):
    """Response body of `POST .../tracks/{track_id}/exclude|restore`."""

    data: TrackExclusionTrack


class ProductExclusionProduct(BaseModel):
    """The locked-current Product occurrence returned by an exclude or restore."""

    id: UUID = Field(description="TicketPackageProduct occurrence identifier.")
    product_cpe: str = Field(
        description="Canonical public identity (CPE) of the related catalog Product."
    )
    product_name: str = Field(description="Product display name.")
    actionable: bool = Field(
        description=(
            "Whether the Product currently participates in operational "
            "decisions: no manual exclusion at package, track, or Product "
            "level, and not end-of-life on the mutation's UTC evaluation date."
        )
    )
    non_actionable_reason: ProductReasonValue | None = Field(
        description=(
            "First applicable reason in the order `package_excluded`, "
            "`track_excluded`, `product_excluded`, `eol`; `null` when "
            "actionable."
        )
    )


class ProductExclusionResponse(BaseModel):
    """Response body of `POST .../products/{id}/exclude|restore` (occurrence id)."""

    data: ProductExclusionProduct


# Cross-Ticket package search (package-model.md, Search Packages Across
# Tickets; Response Schema: PackageListItem).


class PackageSearchQuery(BaseModel):
    """Query parameters of `GET /api/v1/packages`.

    `ticket_status` is intentionally a raw `list[str]`: an invalid value is
    silently dropped rather than rejected (`docs/api-spec.md`, Enum Filter
    Validation), and an empty list means the filter was omitted.
    `sort_by` and `sort_order` are typed, so an invalid value is the
    global `422 VALIDATION_ERROR` (Sort Parameter Validation). String
    parameters share the global 500-character limit, applied to the raw
    values before this model is built.

    `search` and `name` are mutually exclusive. `search` counts as
    present only when it is non-empty after trimming outer whitespace; the
    value itself is passed through unchanged, and the service performs the
    one effective trim.
    """

    search: str | None = None
    name: str | None = None
    ticket_status: list[str] = Field(default_factory=list)
    sort_by: PackageSortField = PackageSortField.CREATED_AT
    sort_order: SortOrder = SortOrder.DESC
    page: int = Field(default=1, ge=1, le=2_147_483_647)
    per_page: int = Field(default=20, ge=1, le=100)

    @model_validator(mode="after")
    def _search_and_name_are_exclusive(self) -> Self:
        if self.name is not None and self.search is not None and self.search.strip():
            raise ValueError("search and name are mutually exclusive.")
        return self


class TicketPackageRef(BaseModel):
    """Lightweight reference to the Ticket of a package occurrence."""

    ticket_id: str = Field(
        description="Canonical Ticket identity (`SNTL-{n}`).", examples=["SNTL-123"]
    )
    status: TicketStatusValue = Field(
        description=(
            "Current Ticket status: `new`, `analysis`, `analyzed`, `resolved`, "
            "`ignored`, or `duplicated`."
        )
    )
    severity: SeverityValue | None = Field(
        description=(
            "Resolved Ticket severity (the CVE severity for a Ticket with a "
            "CVE, otherwise the manual severity): `critical`, `high`, "
            "`medium`, `low`, or `none` (CVSS score 0.0, informational), or "
            "`null` when unresolved. `none` is distinct from `null`."
        )
    )


class TrackSummary(BaseModel):
    """Counts of the package's actionable tracks by affectedness status.

    Only actionable tracks are counted, on the same UTC evaluation date as
    the package filtering and pagination of the response.
    """

    total: int = Field(description="Total actionable tracks.")
    affected: int = Field(description="Actionable tracks with status `affected`.")
    fixed: int = Field(description="Actionable tracks with status `fixed`.")
    not_affected: int = Field(
        description="Actionable tracks with status `not_affected`."
    )
    wont_fix: int = Field(description="Actionable tracks with status `wont_fix`.")
    analysis: int = Field(description="Actionable tracks with status `analysis`.")


class PackageListItem(BaseModel):
    """One actionable package occurrence: one `(package_name, Ticket)` pair."""

    id: UUID = Field(description="TicketPackage identifier.")
    package_name: str = Field(description="Source package name.")
    ticket: TicketPackageRef = Field(description="The Ticket tracking the package.")
    track_summary: TrackSummary = Field(
        description="Actionable track counts of the package within this Ticket."
    )
    created_at: datetime = Field(
        description="When the package was added to the Ticket (UTC)."
    )
    updated_at: datetime = Field(
        description="Last modification of the package occurrence (UTC)."
    )


class PackageListResponse(BaseModel):
    """Response body of `GET /api/v1/packages` (paginated)."""

    data: list[PackageListItem]
    meta: PaginationMeta
