"""Response schemas for CVSS assessments.

See `docs/features/tickets/cvss-scoring.md` (API Endpoints: Shared
Assessment Item, Get CVSS Assessments for a CVE; Accepted Base Vectors:
per-version Base metrics and API wire values) for the authoritative
contracts.

`CVSSAssessmentItem` is the one shared assessment item schema: the GET
composite and the SUSE upsert response serialize exactly this schema. It
is a union discriminated by `cvss_version`, so each version carries only
its own `metrics` shape and never fields of another version or an untyped
abbreviation map. Metric and severity values are the lowercase wire values
of the Category B enums in `app.core.enums`, which the pure parser also
produces, so the wire vocabulary has one definition.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

from pydantic import BaseModel, Field

from app.core.enums import (
    CVSS2AccessComplexity,
    CVSS2AccessVector,
    CVSS2Authentication,
    CVSS2Impact,
    CVSS3Scope,
    CVSS3UserInteraction,
    CVSS4AttackRequirements,
    CVSS4UserInteraction,
    CVSSAssessmentSeverity,
    CVSSAttackComplexity,
    CVSSAttackVector,
    CVSSImpact,
    CVSSPrivilegesRequired,
    EligibilitySource,
)
from app.schemas.common import SeverityValue

type CVSSVersionValue = Literal["2.0", "3.0", "3.1", "4.0"]
type DefaultCVSSVersionValue = Literal["3.1", "4.0"]


class CVSS2Metrics(BaseModel):
    """Expanded CVSS v2.0 Base metrics."""

    access_vector: CVSS2AccessVector
    access_complexity: CVSS2AccessComplexity
    authentication: CVSS2Authentication
    confidentiality_impact: CVSS2Impact
    integrity_impact: CVSS2Impact
    availability_impact: CVSS2Impact


class CVSS3Metrics(BaseModel):
    """Expanded CVSS v3.0 and v3.1 Base metrics (shared shape)."""

    attack_vector: CVSSAttackVector
    attack_complexity: CVSSAttackComplexity
    privileges_required: CVSSPrivilegesRequired
    user_interaction: CVSS3UserInteraction
    scope: CVSS3Scope
    confidentiality_impact: CVSSImpact
    integrity_impact: CVSSImpact
    availability_impact: CVSSImpact


class CVSS4Metrics(BaseModel):
    """Expanded CVSS v4.0 Base metrics."""

    attack_vector: CVSSAttackVector
    attack_complexity: CVSSAttackComplexity
    attack_requirements: CVSS4AttackRequirements
    privileges_required: CVSSPrivilegesRequired
    user_interaction: CVSS4UserInteraction
    vulnerable_system_confidentiality: CVSSImpact
    vulnerable_system_integrity: CVSSImpact
    vulnerable_system_availability: CVSSImpact
    subsequent_system_confidentiality: CVSSImpact
    subsequent_system_integrity: CVSSImpact
    subsequent_system_availability: CVSSImpact


class _CVSSAssessmentBase(BaseModel):
    """Field order of the shared item; subclasses narrow the version pair."""

    id: UUID = Field(description="Assessment identifier.")
    provider_name: str = Field(description="Canonical persisted provider name.")
    cvss_version: CVSSVersionValue = Field(description="Exact vector version.")
    score: float = Field(description="Calculated Base score (0.0-10.0).")
    severity: CVSSAssessmentSeverity = Field(
        description=(
            "Version-specific assessment severity (v2.0: low, medium, high; "
            "v3.0, v3.1, v4.0: none through critical). Not the unified CVE "
            "severity."
        )
    )
    vector_string: str = Field(description="Canonical complete Base vector.")
    metrics: CVSS2Metrics | CVSS3Metrics | CVSS4Metrics = Field(
        description="Base metrics expanded from the vector for its version."
    )
    created_at: datetime = Field(description="Creation timestamp (UTC).")
    updated_at: datetime = Field(description="Last-update timestamp (UTC).")


class CVSS20Assessment(_CVSSAssessmentBase):
    """A CVSS v2.0 assessment."""

    cvss_version: Literal["2.0"]
    metrics: CVSS2Metrics


class CVSS30Assessment(_CVSSAssessmentBase):
    """A CVSS v3.0 assessment."""

    cvss_version: Literal["3.0"]
    metrics: CVSS3Metrics


class CVSS31Assessment(_CVSSAssessmentBase):
    """A CVSS v3.1 assessment."""

    cvss_version: Literal["3.1"]
    metrics: CVSS3Metrics


class CVSS40Assessment(_CVSSAssessmentBase):
    """A CVSS v4.0 assessment."""

    cvss_version: Literal["4.0"]
    metrics: CVSS4Metrics


type CVSSAssessmentItem = Annotated[
    CVSS20Assessment | CVSS30Assessment | CVSS31Assessment | CVSS40Assessment,
    Field(discriminator="cvss_version"),
]
"""The shared assessment item, discriminated by `cvss_version`."""


class CVSSSeverityResult(BaseModel):
    """The Severity Resolution Cascade winner of a CVE."""

    score: float = Field(description="Winning assessment's Base score.")
    version: CVSSVersionValue = Field(description="Winning assessment's version.")
    provider: str = Field(description="Winning assessment's canonical provider.")
    label: SeverityValue = Field(
        description="Unified severity calculated from the score."
    )


class CVSSEligibilityResult(BaseModel):
    """The Eligibility Score Resolution result of a CVE."""

    score: float = Field(
        description="SUSE default-version score, or 10.0 as the fallback."
    )
    source: EligibilitySource = Field(description="`suse` or `fallback`.")


class CVECVSSAssessments(BaseModel):
    """The bounded CVSS composite of one CVE."""

    assessments: list[CVSSAssessmentItem] = Field(
        description=(
            "Complete assessment set, ordered by version 4.0, 3.1, 3.0, 2.0, "
            "then provider name by Unicode code point."
        )
    )
    default_cvss_version: DefaultCVSSVersionValue = Field(
        description="The configured default CVSS version observed by this read."
    )
    severity: CVSSSeverityResult | None = Field(
        description="Severity Resolution result, or null without assessments."
    )
    eligibility: CVSSEligibilityResult = Field(
        description="Eligibility Score Resolution result; always present."
    )


class CVECVSSAssessmentsResponse(BaseModel):
    """`GET /api/v1/cves/{cve_id}/cvss` response envelope."""

    data: CVECVSSAssessments
