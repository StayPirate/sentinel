"""Schemas for compact and expanded CVE data and the CVE read endpoints.

See `docs/features/tickets/tickets.md` (Response Schemas > Shared
Sub-Schemas: CVESummary, CVEDetail, CVEKEVResponse, CVEEPSSResponse,
CVESSVCResponse, CVEWeaknessResponse, CVEExternalIdentifierResponse) for
the shared contracts, `docs/features/tickets/cve-tracking.md` (List CVEs:
CVEListItem; Get CVE: CVEResourceDetail; Get CVE Affected Versions:
CVEAffectedVersionGroup, CVEAffectedVersionEntry), and
`docs/features/tickets/cve-service.md` (Global CVE Source Listing) for
the endpoint schemas, and (CVE Source Status) for the per-CVE source
status. `CVEDetail` exposes persisted evidence only:
it never contains a CVE priority (`docs/features/tickets/ticket-priority.md`)
or inline CVSS assessments, which remain in their dedicated sub-resource.

Every enumerated value is serialized in lowercase.
"""

from __future__ import annotations

from datetime import date, datetime
from typing import Literal

from pydantic import BaseModel, Field

from app.core.enums import CVESortField, CVESourceSortField, SortOrder
from app.schemas.common import PaginationMeta, SeverityValue

type CveStateValue = Literal["published", "rejected"]
type CVESourceStatusValue = Literal["success", "failure", "missing"]
type CVESourceDerivedStatusValue = Literal[
    "success", "failure", "missing", "pending", "not_attempted"
]


class CVEKEVResponse(BaseModel):
    """The CISA Known Exploited Vulnerabilities catalog entry of a CVE."""

    date_added: date = Field(description="Date the CVE was added to the KEV catalog.")
    reference_url: str | None = Field(description="KEV catalog entry URL.")


class CVEEPSSResponse(BaseModel):
    """The latest persisted FIRST EPSS snapshot of a CVE."""

    score: float = Field(description="EPSS probability (0.0-1.0).")
    percentile: float = Field(description="EPSS percentile rank (0.0-1.0).")
    assessed_at: date = Field(
        description=(
            "EPSS assessment date. EPSS refreshes only for active Tickets, so "
            "consumers use this date to indicate staleness."
        )
    )


class CVESSVCResponse(BaseModel):
    """The persisted CISA SSVC decision points of a CVE."""

    exploitation: str = Field(
        description="SSVC exploitation decision point: `none`, `poc`, or `active`."
    )
    automatable: str = Field(
        description="SSVC automatable decision point: `no` or `yes`."
    )
    technical_impact: str = Field(
        description="SSVC technical impact decision point: `partial` or `total`."
    )
    version: str = Field(description="SSVC version (e.g. `2.0.3`).")
    assessed_at: datetime | None = Field(
        description="When the assessment was performed (UTC)."
    )


class CVEWeaknessResponse(BaseModel):
    """One distinct CWE classification of a CVE."""

    cwe_id: str = Field(description="CWE identifier (e.g. `CWE-79`).")
    sources: list[str] = Field(
        description=(
            "Every persisted provider that assigned this CWE, "
            "exact-deduplicated and ordered by ascending Unicode code point."
        )
    )


class CVEExternalIdentifierResponse(BaseModel):
    """One external vulnerability identifier from another naming authority."""

    source: str = Field(
        description="Naming authority, serialized in lowercase (e.g. `ghsa`)."
    )
    identifier: str = Field(description="External identifier (e.g. a GHSA-ID).")
    url: str | None = Field(description="Direct link to the advisory page.")


class CVESummary(BaseModel):
    """Compact CVE representation for list views."""

    cve_id: str = Field(description="CVE identifier (e.g. `CVE-2024-1234`).")
    title: str | None = Field(
        description=(
            "Brief summary from the CNA (at most 256 characters); `null` if "
            "not provided by the CNA."
        )
    )
    description: str | None = Field(description="Vulnerability description.")


class CVEDetail(BaseModel):
    """Expanded CVE representation for detail views.

    Contains persisted evidence only: no CVE priority and no inline CVSS
    assessments.
    """

    cve_id: str = Field(description="CVE identifier (e.g. `CVE-2024-1234`).")
    title: str | None = Field(
        description=(
            "Brief summary from the CNA (at most 256 characters); `null` if "
            "not provided by the CNA."
        )
    )
    description: str | None = Field(description="Vulnerability description.")
    published_date: datetime | None = Field(description="Date published (UTC).")
    modified_date: datetime | None = Field(description="Date last modified (UTC).")
    cve_state: CveStateValue = Field(
        description="CVE record state: `published` or `rejected`."
    )
    date_rejected: datetime | None = Field(
        description=(
            "When the CVE was rejected (UTC); `null` if `cve_state` is `published`."
        )
    )
    severity: SeverityValue | None = Field(
        description=(
            "Unified CVE severity: `critical`, `high`, `medium`, `low`, or "
            "`none` (CVSS score 0.0, informational), or `null` when "
            "unresolved (no CVSS data). `none` is distinct from `null`."
        )
    )
    external_identifiers: list[CVEExternalIdentifierResponse] = Field(
        description=(
            "External identifiers from other naming authorities, ordered by "
            "source, then identifier, in ascending Unicode code-point order."
        )
    )
    kev: CVEKEVResponse | None = Field(
        description="CISA KEV catalog entry, or `null` when the CVE has none."
    )
    epss: CVEEPSSResponse | None = Field(
        description="Latest persisted FIRST EPSS snapshot, or `null` when none exists."
    )
    ssvc: CVESSVCResponse | None = Field(
        description="Persisted CISA SSVC decision points, or `null` when none exist."
    )
    cwes: list[CVEWeaknessResponse] = Field(
        description=(
            "CWE classifications grouped by CWE identifier and ordered by "
            "ascending Unicode code point of `cwe_id`; empty when none exist."
        )
    )


# ---------------------------------------------------------------------------
# CVE read endpoints
# ---------------------------------------------------------------------------


class CVEAssociatedTicket(BaseModel):
    """The public identity of the Ticket associated with a CVE."""

    ticket_id: str = Field(
        description="Canonical Ticket identity (`SNTL-{n}`).", examples=["SNTL-42"]
    )


class CVEListItem(BaseModel):
    """One accessible CVE in `GET /api/v1/cves` (cve-tracking.md, List
    CVEs > Response Schema)."""

    cve_id: str = Field(description="CVE identifier (e.g. `CVE-2024-1234`).")
    title: str | None = Field(
        description=(
            "Brief summary from the CNA (at most 256 characters); `null` if "
            "not provided by the CNA."
        )
    )
    description: str | None = Field(description="Vulnerability description.")
    severity: SeverityValue | None = Field(
        description=(
            "Resolved severity from the CVSS resolution cascade: `critical`, "
            "`high`, `medium`, `low`, or `none` (CVSS score 0.0), or `null` "
            "when no CVSS assessment is available (unresolved)."
        )
    )
    cve_state: CveStateValue = Field(description="`published` or `rejected`.")
    published_date: datetime | None = Field(description="CVE publication date (UTC).")
    ticket: CVEAssociatedTicket | None = Field(
        description="Associated Ticket, if any; `null` for a ticketless CVE."
    )
    created_at: datetime = Field(description="Record creation timestamp (UTC).")
    updated_at: datetime = Field(description="Last modification timestamp (UTC).")


class CVEListResponse(BaseModel):
    """Response body for `GET /api/v1/cves` (paginated)."""

    data: list[CVEListItem]
    meta: PaginationMeta


class CVEResourceDetail(CVEDetail):
    """`GET /api/v1/cves/{cve_id}` (cve-tracking.md, Get CVE): every field
    of `CVEDetail` plus the associated Ticket's identity. Evidence only:
    no CVE priority and no inline CVSS assessments."""

    ticket: CVEAssociatedTicket | None = Field(
        description="Associated Ticket, if any; `null` for a ticketless CVE."
    )


class CVEResourceDetailResponse(BaseModel):
    """Response body for `GET /api/v1/cves/{cve_id}`."""

    data: CVEResourceDetail


class CVEAffectedVersionEntry(BaseModel):
    """The persisted content of one affected-version entry, as stored by
    ingestion (cve-tracking.md, Get CVE Affected Versions >
    CVEAffectedVersionEntry; field meanings in `docs/data-model.md`,
    CVEAffectedVersion). Values are not case- or format-normalized; the
    internal row identifier and creation time are deliberately absent."""

    vendor: str | None = Field(description="Vendor name.")
    product: str | None = Field(description="Product or package name.")
    package_url: str | None = Field(
        description="Package URL (PURL); an unvalidated upstream string."
    )
    collection_url: str | None = Field(
        description=(
            "Package registry URL; an unvalidated upstream string, not "
            "guaranteed to be `http` or `https`."
        )
    )
    package_name: str | None = Field(description="Source or registry package name.")
    repo: str | None = Field(
        description=(
            "Source code repository URL; an unvalidated upstream string, not "
            "guaranteed to be `http` or `https`."
        )
    )
    version: str | None = Field(
        description=(
            "Single version or range start; for `version_type = git`, the "
            "introducing commit."
        )
    )
    version_type: str | None = Field(
        description=(
            "Version scheme recorded by ingestion (e.g. `semver`, `git`, "
            "`exact`, `custom`), or `null` when none is recorded."
        )
    )
    version_end: str | None = Field(
        description=(
            "Range end; for `version_type = git`, the closing commit, whose "
            "inclusivity `version_end_inclusive` gives."
        )
    )
    version_end_inclusive: bool | None = Field(
        description=(
            "`true` when `version_end` is inclusive, `false` when exclusive, "
            "`null` without a range end."
        )
    )
    program_files: list[str] | None = Field(description="Affected source files.")
    cpe: str | None = Field(description="CPE supplied with the entry.")
    ecosystem: str | None = Field(description="OSSF canonical ecosystem identifier.")
    status: str | None = Field(
        description=(
            "Upstream version-level status (known values `affected`, "
            "`unaffected`, `unknown`), stored without validation."
        )
    )
    default_status: str | None = Field(
        description=(
            "Upstream entry-level baseline status, same value set as `status`."
        )
    )


class CVEAffectedVersionGroup(BaseModel):
    """The entries of one provenance scope (cve-tracking.md, Get CVE
    Affected Versions > CVEAffectedVersionGroup)."""

    source_container: str = Field(
        description="Provenance scope (e.g. `cna`, `adp:CISA-ADP`, `ghsa`, `osv`)."
    )
    entries: list[CVEAffectedVersionEntry] = Field(
        description=(
            "The scope's entries, never empty, ordered by `vendor`, `product`, "
            "`package_name`, `ecosystem`, `repo`, `version_type`, `version`, "
            "then `version_end`, each by ascending Unicode code point with "
            "absent values last."
        )
    )


class CVEAffectedVersionsResponse(BaseModel):
    """Response body for `GET /api/v1/cves/{cve_id}/affected-versions`
    (unpaginated, groups in ascending `source_container` code-point
    order)."""

    data: list[CVEAffectedVersionGroup]


class CVESourceListItem(BaseModel):
    """One persisted latest-state CVE source record in
    `GET /api/v1/cve-sources` (cve-service.md, Global CVE Source Listing >
    Response). The internal record UUID is deliberately absent."""

    cve_id: str = Field(
        description="CVE identifier (CVE-ID string, e.g. `CVE-2025-1234`)."
    )
    source: str = Field(
        description=(
            "CVE source type identifier (e.g. `nvd`, `mitre`, `kernel`), "
            "whether currently registered or historically persisted."
        )
    )
    status: CVESourceStatusValue = Field(
        description="Persisted fetch status: `success`, `failure`, or `missing`."
    )
    fetched_at: datetime = Field(
        description=(
            "Database wall-clock instant of the latest serialized status "
            "mutation (UTC)."
        )
    )
    first_failed_at: datetime | None = Field(
        description=(
            "When the current failure streak began (UTC); `null` when the "
            "record is not in a failure streak."
        )
    )
    created_at: datetime = Field(description="Record creation timestamp (UTC).")
    updated_at: datetime = Field(description="Record last update timestamp (UTC).")


class CVESourceListResponse(BaseModel):
    """Response body for `GET /api/v1/cve-sources` (paginated)."""

    data: list[CVESourceListItem]
    meta: PaginationMeta


class CVESourceStatusItem(BaseModel):
    """One source entry of `GET /api/v1/cves/{cve_id}/sources`
    (cve-service.md, CVE Source Status > Response schema)."""

    source: str = Field(
        description=(
            "CVE source type identifier (e.g. `nvd`, `kev`), currently "
            "registered or historically persisted for this CVE."
        )
    )
    status: CVESourceDerivedStatusValue = Field(
        description=(
            "Derived status: `success`, `failure`, `missing`, `pending` (an "
            "on-demand fetch is in flight for an enabled registered source), "
            "or `not_attempted` (no completed attempt is recorded)."
        )
    )
    fetched_at: datetime | None = Field(
        description=(
            "Timestamp of the last completed fetch attempt (UTC); for KEV "
            "`success`, the latest persisted KEV-evidence change. `null` "
            "when no attempt has completed."
        )
    )
    first_failed_at: datetime | None = Field(
        description=(
            "When the current failure streak began (UTC); `null` when the "
            "record is not in a failure streak. Kept while `pending`."
        )
    )
    registered: bool = Field(description="Whether the source is currently registered.")
    refetchable: bool = Field(
        description="Whether on-demand refetch is supported for the source."
    )
    enabled: bool = Field(
        description=(
            "Current effective enabled state of a registered source; "
            "independent from `refetchable`. `false` for historical sources."
        )
    )


class CVESourceStatusResponse(BaseModel):
    """Response body for `GET /api/v1/cves/{cve_id}/sources` (unpaginated,
    fixed ascending `source` code-point order)."""

    data: list[CVESourceStatusItem]


class CVERefetchResult(BaseModel):
    """The dispatch result of `POST /api/v1/cves/{cve_id}/refetch`
    (cve-tracking.md, Re-fetch Endpoint; cve-service.md,
    `FetchDispatchResult`). The four arrays are disjoint and each is in
    ascending canonical source code-point order."""

    sources_enqueued: list[str] = Field(
        description=(
            "Sources whose single-CVE fetch publication returned without raising."
        )
    )
    sources_already_pending: list[str] = Field(
        description=(
            "Sources with an on-demand fetch already pending; no new "
            "publication was attempted."
        )
    )
    sources_disabled: list[str] = Field(
        description=(
            "Registered refetchable sources skipped because they are "
            "disabled (broadcast only)."
        )
    )
    sources_failed: list[str] = Field(
        description=(
            "Sources whose publication attempt raised; broker acceptance is "
            "unconfirmed, not certainly rejected."
        )
    )


class CVERefetchResponse(BaseModel):
    """Response body for `POST /api/v1/cves/{cve_id}/refetch` (202)."""

    data: CVERefetchResult


class CVEListQuery(BaseModel):
    """Query parameters of `GET /api/v1/cves` (cve-tracking.md, List CVEs >
    Query Parameters).

    `cve_state` and the repeatable `severity` are intentionally raw
    strings: an invalid value yields an empty page rather than an error
    (`docs/api-spec.md`, Enum Filter Validation); `severity is None` means
    omitted. The date bounds are already parsed, checked for inversion,
    and normalized to UTC. `sort_by` and `sort_order` are typed, so an
    invalid value is the global `422 VALIDATION_ERROR`.
    """

    search: str | None = None
    cve_state: str | None = None
    severity: list[str] | None = None
    has_ticket: bool | None = None
    from_date: datetime | None = None
    to_date: datetime | None = None
    page: int = Field(default=1, ge=1, le=2_147_483_647)
    per_page: int = Field(default=20, ge=1, le=100)
    sort_by: CVESortField = CVESortField.PUBLISHED_DATE
    sort_order: SortOrder = SortOrder.DESC


class CVESourceListQuery(BaseModel):
    """Query parameters of `GET /api/v1/cve-sources` (cve-service.md,
    Global CVE Source Listing > Query Parameters).

    `source` is already grammar-bounded; `status` stays a raw string so an
    invalid value yields an empty page. The date bounds are parsed,
    checked for inversion, and normalized to UTC.
    """

    source: str | None = None
    status: str | None = None
    stalled: bool | None = None
    from_date: datetime | None = None
    to_date: datetime | None = None
    page: int = Field(default=1, ge=1, le=2_147_483_647)
    per_page: int = Field(default=20, ge=1, le=100)
    sort_by: CVESourceSortField = CVESourceSortField.FETCHED_AT
    sort_order: SortOrder = SortOrder.DESC
