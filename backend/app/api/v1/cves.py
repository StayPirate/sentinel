"""CVE endpoints.

See `docs/features/tickets/cvss-scoring.md` (Get CVSS Assessments for a
CVE, Shared Assessment Item) for the authoritative endpoint contract, and
`docs/api-spec.md` (CVE Identifier Resolution, CVE Accessibility Check)
for the shared `{cve_id}` path behavior.

Handlers stay thin: they supply the request-resolved caller information to
`cve_service`, map `CVENotFoundError` to the one identical
`404 CVE_NOT_FOUND`, and serialize the semantic projection. The service
owns CVE-ID resolution and the accessibility-constrained selection; no
business logic or database query lives here.

`serialize_cvss_assessment()` is the one shared assessment-item
serializer, so every endpoint that returns an assessment item serializes
the same schema.
"""

from __future__ import annotations

from dataclasses import fields

from fastapi import APIRouter
from pydantic import TypeAdapter

from app.api.dependencies import CVEIdPath, OptionalTicketCaller, cve_not_found_error
from app.core.exceptions import CVENotFoundError
from app.database import DatabaseSession
from app.schemas.cvss import (
    CVECVSSAssessments,
    CVECVSSAssessmentsResponse,
    CVSSAssessmentItem,
)
from app.schemas.errors import ErrorResponse
from app.services import cve_service
from app.services.cve_service import CVSSAssessmentProjection

router = APIRouter(prefix="/api/v1", tags=["CVEs"])

_ASSESSMENT_ITEM: TypeAdapter[CVSSAssessmentItem] = TypeAdapter(CVSSAssessmentItem)


def serialize_cvss_assessment(
    assessment: CVSSAssessmentProjection,
) -> CVSSAssessmentItem:
    """Project one assessment onto the version-discriminated item schema."""
    metrics = assessment.metrics
    return _ASSESSMENT_ITEM.validate_python(
        {
            "id": assessment.id,
            "provider_name": assessment.provider_name,
            "cvss_version": assessment.cvss_version.value,
            "score": float(assessment.score),
            "severity": assessment.severity,
            "vector_string": assessment.vector_string,
            "metrics": {
                field.name: getattr(metrics, field.name) for field in fields(metrics)
            },
            "created_at": assessment.created_at,
            "updated_at": assessment.updated_at,
        }
    )


def serialize_cve_cvss_assessments(
    result: cve_service.CVECVSSAssessments,
) -> CVECVSSAssessments:
    """Project the service composite onto the response schema.

    Enum values become their lowercase wire values; the unified severity
    label is the lowercase form of the PascalCase domain `Severity`.
    """
    severity = result.severity
    return CVECVSSAssessments.model_validate(
        {
            "assessments": [
                serialize_cvss_assessment(item) for item in result.assessments
            ],
            "default_cvss_version": result.default_cvss_version.value,
            "severity": (
                None
                if severity is None
                else {
                    "score": float(severity.score),
                    "version": severity.version.value,
                    "provider": severity.provider,
                    "label": severity.label.value.lower(),
                }
            ),
            "eligibility": {
                "score": float(result.eligibility.score),
                "source": result.eligibility.source,
            },
        }
    )


@router.get(
    "/cves/{cve_id}/cvss",
    response_model=CVECVSSAssessmentsResponse,
    summary="Get CVSS assessments for a CVE",
    description=(
        "Returns the complete CVSS assessment set of one CVE, identified by "
        "its CVE-ID, in canonical order (version 4.0, 3.1, 3.0, 2.0, then "
        "provider name), together with the configured default CVSS version, "
        "the resolved severity (null without assessments), and the "
        "eligibility score. Not paginated and not sortable: the set is "
        "bounded and has one canonical order. Public; optional "
        "authentication determines access to CVEs associated with "
        "confidential Tickets."
    ),
    responses={
        404: {
            "model": ErrorResponse,
            "description": (
                "CVE-ID is malformed, does not exist, or identifies a CVE "
                "associated with a Ticket inaccessible to the caller."
            ),
        },
    },
)
async def get_cve_cvss_assessments(
    cve_id: CVEIdPath,
    db: DatabaseSession,
    caller: OptionalTicketCaller,
) -> CVECVSSAssessmentsResponse:
    """Get CVSS Assessments for a CVE — see
    `docs/features/tickets/cvss-scoring.md`.

    The service applies CVE accessibility in the same statement that selects
    the complete composite, so no preliminary accessibility query is needed.
    """
    try:
        result = await cve_service.get_cvss_assessments(
            db, cve_id=cve_id, caller=caller
        )
    except CVENotFoundError:
        raise cve_not_found_error() from None
    return CVECVSSAssessmentsResponse(data=serialize_cve_cvss_assessments(result))
