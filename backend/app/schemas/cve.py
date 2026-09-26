"""Response schemas for expanded CVE data.

See `docs/features/tickets/tickets.md` (Response Schemas > Shared
Sub-Schemas: CVEDetail, CVEKEVResponse, CVEEPSSResponse,
CVESSVCResponse, CVEWeaknessResponse, CVEExternalIdentifierResponse) for
the authoritative contracts. `CVEDetail` exposes persisted evidence only:
it never contains a CVE priority (`docs/features/tickets/ticket-priority.md`)
or inline CVSS assessments, which remain in their dedicated sub-resource.

Every enumerated value is serialized in lowercase.
"""

from __future__ import annotations

from datetime import date, datetime
from typing import Literal

from pydantic import BaseModel, Field

from app.schemas.common import SeverityValue

type CveStateValue = Literal["published", "rejected"]


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
