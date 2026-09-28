"""CVE endpoints.

See `docs/features/tickets/cvss-scoring.md` (Get CVSS Assessments for a
CVE, Set or Update SUSE CVSS Assessment, Delete SUSE CVSS Assessment,
Shared Assessment Item) for the authoritative endpoint contracts, and
`docs/api-spec.md` (CVE Identifier Resolution, CVE Accessibility Check,
Authorization Chain Evaluation Order) for the shared `{cve_id}` path
behavior.

Handlers stay thin: they supply the request-resolved caller information to
`cve_service` or `ticket_mutations`, map service exceptions to their HTTP
responses (`CVENotFoundError` to the one identical `404 CVE_NOT_FOUND`),
and serialize the semantic projection. The services own CVE-ID
resolution, the accessibility-constrained selection, and the locked
mutation; no business logic or database query lives here.

`serialize_cvss_assessment()` is the one shared assessment-item
serializer, so every endpoint that returns an assessment item serializes
the same schema.
"""

from __future__ import annotations

from dataclasses import fields
from typing import Annotated

from fastapi import APIRouter, Depends, Path, Response, status
from pydantic import TypeAdapter

from app.api.dependencies import (
    AuthenticatedPrincipal,
    AuthenticatedTicketCaller,
    CVEIdPath,
    OptionalTicketCaller,
    cve_not_found_error,
    require_accessible_cve,
    require_capability,
    ticket_not_mutable_error,
)
from app.core.enums import Capability
from app.core.errors import AppError, ErrorCode
from app.core.exceptions import CVENotFoundError, TicketNotMutableError
from app.database import DatabaseSession
from app.schemas.cvss import (
    CVECVSSAssessments,
    CVECVSSAssessmentsResponse,
    CVSSAssessmentItem,
    CVSSAssessmentResponse,
    SUSECVSSAssessmentRequest,
)
from app.schemas.errors import ErrorResponse
from app.services import cve_service, ticket_mutations
from app.services.cve_service import CVSSAssessmentProjection, ResolvedCVE
from app.services.cvss import SUSE_PROVIDER_NAME
from app.services.ticket_mutations import (
    CVSSAssessmentAction,
    CVSSAssessmentNotFoundError,
    CVSSMutationCaller,
    InvalidCVSSVectorError,
)

router = APIRouter(prefix="/api/v1", tags=["CVEs"])

_ASSESSMENT_ITEM: TypeAdapter[CVSSAssessmentItem] = TypeAdapter(CVSSAssessmentItem)

CVSSVersionPath = Annotated[
    str,
    Path(
        description=(
            "CVSS version of the SUSE assessment: `2.0`, `3.0`, `3.1`, or `4.0`."
        ),
        examples=["3.1"],
    ),
]
"""The `{cvss_version}` path parameter.

Deliberately an unconstrained string: an unrecognized value must produce
`404 CVSS_ASSESSMENT_NOT_FOUND`, not the `422` an enum would return
(`docs/features/tickets/cvss-scoring.md`, Delete SUSE CVSS Assessment).
"""


def _cvss_assessment_not_found_error() -> AppError:
    """Create the 404 for an unrecognized version or an absent SUSE
    assessment (ticket-mutations.md, Service Exceptions)."""
    return AppError(
        status_code=status.HTTP_404_NOT_FOUND,
        code=ErrorCode.CVSS_ASSESSMENT_NOT_FOUND,
        detail="CVSS assessment not found.",
    )


async def require_accepted_cvss_version(cvss_version: CVSSVersionPath) -> str:
    """Reject an unrecognized `{cvss_version}` before any CVE resolution.

    See `docs/features/tickets/cvss-scoring.md` (Delete SUSE CVSS
    Assessment): the version check is input-only and precedes CVE-ID
    resolution, so the endpoint declares this dependency after its
    capability check and before `require_accessible_cve`. It performs no
    query and delegates the accepted-version rule to `ticket_mutations`.
    """
    try:
        ticket_mutations.require_accepted_cvss_version(cvss_version)
    except CVSSAssessmentNotFoundError:
        raise _cvss_assessment_not_found_error() from None
    return cvss_version


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


@router.post(
    "/cves/{cve_id}/cvss/suse",
    response_model=CVSSAssessmentResponse,
    summary="Set or update the SUSE CVSS assessment",
    description=(
        "Creates or updates the internal SUSE assessment of one CVE for the "
        "version derived from the submitted CVSS Base vector. Returns 201 "
        "only when this request created the assessment, and 200 for an "
        "update or an equivalent (unchanged) vector. The CVE severity is "
        "re-resolved; for a CVE with a Ticket, an unassigned Ticket is "
        "auto-assigned to an active vulnerability analyst, automatic Product "
        "eligibility and priority are refreshed, and the Ticket status is "
        "re-evaluated. Requires `manage_cvss`."
    ),
    responses={
        201: {
            "model": CVSSAssessmentResponse,
            "description": "The SUSE assessment was created by this request.",
        },
        404: {
            "model": ErrorResponse,
            "description": (
                "`CVE_NOT_FOUND`: CVE-ID is malformed, does not exist, or "
                "identifies a CVE associated with a Ticket inaccessible to the "
                "caller."
            ),
        },
        409: {
            "model": ErrorResponse,
            "description": (
                "`TICKET_NOT_MUTABLE`: the CVE's Ticket is Ignored or Duplicated."
            ),
        },
        422: {
            "model": ErrorResponse,
            "description": (
                "`CVSS_INVALID_VECTOR`: the string passes the schema checks but "
                "violates the accepted Base-vector contract. `VALIDATION_ERROR`: "
                "the body fails schema validation."
            ),
        },
    },
)
async def upsert_suse_cvss_assessment(
    body: SUSECVSSAssessmentRequest,
    response: Response,
    db: DatabaseSession,
    principal: Annotated[
        AuthenticatedPrincipal, Depends(require_capability(Capability.MANAGE_CVSS))
    ],
    caller: AuthenticatedTicketCaller,
    cve: Annotated[ResolvedCVE, Depends(require_accessible_cve)],
) -> CVSSAssessmentResponse:
    """Set or Update SUSE CVSS Assessment — see
    `docs/features/tickets/cvss-scoring.md`.

    Authorization follows `docs/api-spec.md` (Authorization Chain
    Evaluation Order, flow 3): authentication, then `manage_cvss` before
    any CVE lookup, then the delegated preliminary CVE resolution. The
    capability decision and the caller's scope share one role load per
    request. `upsert_cvss_assessment()` revalidates CVE accessibility from
    its locked-current roots; the HTTP status comes only from its
    serialized action.
    """
    try:
        result = await ticket_mutations.upsert_cvss_assessment(
            db,
            cve_id=cve.id,
            provider=SUSE_PROVIDER_NAME,
            vector_string=body.vector_string,
            caller=CVSSMutationCaller.MANUAL_SUSE,
            acting_user_id=principal.user.id,
            ticket_caller=caller,
        )
    except CVENotFoundError:
        raise cve_not_found_error() from None
    except TicketNotMutableError:
        raise ticket_not_mutable_error() from None
    except InvalidCVSSVectorError:
        raise AppError(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            code=ErrorCode.CVSS_INVALID_VECTOR,
            detail="Invalid CVSS vector.",
        ) from None
    if result.action is CVSSAssessmentAction.CREATED:
        response.status_code = status.HTTP_201_CREATED
    assert result.assessment is not None  # created, updated, or unchanged
    projection = cve_service.project_cvss_assessment(cve.cve_id, result.assessment)
    return CVSSAssessmentResponse(data=serialize_cvss_assessment(projection))


@router.delete(
    "/cves/{cve_id}/cvss/suse/{cvss_version}",
    status_code=status.HTTP_204_NO_CONTENT,
    response_class=Response,
    summary="Delete the SUSE CVSS assessment",
    description=(
        "Deletes the internal SUSE assessment of one CVE for one CVSS version "
        "(`2.0`, `3.0`, `3.1`, or `4.0`). The CVE severity is re-resolved; for "
        "a CVE with a Ticket, an unassigned Ticket is auto-assigned to an "
        "active vulnerability analyst, automatic Product eligibility and "
        "priority are refreshed, and the Ticket status is re-evaluated "
        "(deleting the last SUSE assessment reopens the analysis). Requires "
        "`manage_cvss`."
    ),
    responses={
        404: {
            "model": ErrorResponse,
            "description": (
                "`CVSS_ASSESSMENT_NOT_FOUND`: the version is not recognized "
                "(checked before the CVE-ID), or the CVE has no SUSE assessment "
                "for it. `CVE_NOT_FOUND`: CVE-ID is malformed, does not exist, "
                "or identifies a CVE associated with a Ticket inaccessible to "
                "the caller."
            ),
        },
        409: {
            "model": ErrorResponse,
            "description": (
                "`TICKET_NOT_MUTABLE`: the CVE's Ticket is Ignored or Duplicated."
            ),
        },
    },
)
async def delete_suse_cvss_assessment(
    db: DatabaseSession,
    principal: Annotated[
        AuthenticatedPrincipal, Depends(require_capability(Capability.MANAGE_CVSS))
    ],
    cvss_version: Annotated[str, Depends(require_accepted_cvss_version)],
    caller: AuthenticatedTicketCaller,
    cve: Annotated[ResolvedCVE, Depends(require_accessible_cve)],
) -> Response:
    """Delete SUSE CVSS Assessment — see
    `docs/features/tickets/cvss-scoring.md`.

    Authorization follows `docs/api-spec.md` (Authorization Chain
    Evaluation Order, flow 3). The dependency order is significant:
    authentication, then `manage_cvss` before any lookup, then the
    input-only version check, then the delegated preliminary CVE
    resolution. `delete_cvss_assessment()` revalidates CVE accessibility
    from its locked-current roots; the response comes only from its
    serialized action (`deleted` → 204, `not_found` → 404).
    """
    try:
        result = await ticket_mutations.delete_cvss_assessment(
            db,
            cve_id=cve.id,
            provider=SUSE_PROVIDER_NAME,
            cvss_version=cvss_version,
            caller=CVSSMutationCaller.MANUAL_SUSE,
            acting_user_id=principal.user.id,
            ticket_caller=caller,
        )
    except CVENotFoundError:
        raise cve_not_found_error() from None
    except TicketNotMutableError:
        raise ticket_not_mutable_error() from None
    except CVSSAssessmentNotFoundError:
        raise _cvss_assessment_not_found_error() from None
    if result.action is CVSSAssessmentAction.NOT_FOUND:
        raise _cvss_assessment_not_found_error()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
