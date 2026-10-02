"""CVE endpoints.

See `docs/features/tickets/cve-tracking.md` (List CVEs, Get CVE),
`docs/features/tickets/cve-service.md` (Service Read Contracts; Global
CVE Source Listing), and `docs/features/tickets/cvss-scoring.md` (Get
CVSS Assessments for a CVE, Set or Update SUSE CVSS Assessment, Delete
SUSE CVSS Assessment, Shared Assessment Item) for the authoritative
endpoint contracts, and `docs/api-spec.md` (CVE Identifier Resolution,
CVE Accessibility Check, Authorization Chain Evaluation Order) for the
shared `{cve_id}` path behavior.

Handlers stay thin: they supply the request-resolved caller information to
`cve_service` or `ticket_mutations`, map service exceptions to their HTTP
responses (`CVENotFoundError` to the one identical `404 CVE_NOT_FOUND`),
and serialize the semantic projection. The services own CVE-ID
resolution, the accessibility-constrained selection, and the locked
mutation; no business logic or database query lives here.

`serialize_cvss_assessment()` is the one shared assessment-item
serializer, so every endpoint that returns an assessment item serializes
the same schema. `serialize_cve_detail()` is likewise the one `CVEDetail`
serializer, shared by `GET /cves/{cve_id}` and `TicketDetail.cve`.

`GET /cve-sources` lives here because it lists CVE-source records; it is
the intentional identifier-only exception to CVE accessibility and
therefore resolves no caller.
"""

from __future__ import annotations

from dataclasses import fields
from datetime import datetime
from typing import Annotated, Final

from fastapi import APIRouter, Depends, Path, Query, Response, status
from pydantic import TypeAdapter

from app.api.dependencies import (
    AuthenticatedPrincipal,
    AuthenticatedTicketCaller,
    CVEIdPath,
    OptionalCurrentUser,
    OptionalTicketCaller,
    cve_not_found_error,
    require_accessible_cve,
    require_capability,
    ticket_not_mutable_error,
)
from app.core.dates import (
    normalize_date_bound,
    parse_date_range_bound,
    validate_date_range_order,
)
from app.core.enums import Capability, CVESortField, CVESourceSortField, SortOrder
from app.core.errors import AppError, ErrorCode
from app.core.exceptions import CVENotFoundError, TicketNotMutableError
from app.database import DatabaseSession
from app.schemas.common import PaginationMeta
from app.schemas.cve import (
    CVEAssociatedTicket,
    CVEDetail,
    CVEEPSSResponse,
    CVEExternalIdentifierResponse,
    CVEKEVResponse,
    CVEListItem,
    CVEListQuery,
    CVEListResponse,
    CVEResourceDetail,
    CVEResourceDetailResponse,
    CVESourceListItem,
    CVESourceListQuery,
    CVESourceListResponse,
    CVESSVCResponse,
    CVEWeaknessResponse,
)
from app.schemas.cvss import (
    CVECVSSAssessments,
    CVECVSSAssessmentsResponse,
    CVSSAssessmentItem,
    CVSSAssessmentResponse,
    SUSECVSSAssessmentRequest,
)
from app.schemas.errors import ErrorResponse
from app.services import cve_service, ticket_mutations
from app.services.cve_projection import CVEDetailProjection
from app.services.cve_service import (
    CVEDetailResult,
    CVEListItemProjection,
    CVESourceListItemProjection,
    CVSSAssessmentProjection,
    ResolvedCVE,
)
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


_SOURCE_PATTERN: Final = r"^[a-z][a-z0-9_]*$"
"""Grammar of a persisted CVE source identifier (`CVESourceType` values;
cve-service.md, Global CVE Source Listing > Query Parameters)."""
_SOURCE_MAX_LENGTH: Final = 100


def _lower(value: str | None) -> str | None:
    return value.lower() if value is not None else None


def _date_bounds(
    from_date: str | None, to_date: str | None
) -> tuple[datetime | None, datetime | None]:
    """Parse, check, and UTC-normalize an inclusive `from_date`/`to_date`
    pair (`docs/api-spec.md`, Date Range Interpretation): a malformed
    value is `422 VALIDATION_ERROR` and an inverted range `400
    DATE_RANGE_INVERTED`."""
    parsed_from = parse_date_range_bound("from_date", from_date)
    parsed_to = parse_date_range_bound("to_date", to_date)
    validate_date_range_order(parsed_from, parsed_to)
    return (
        normalize_date_bound(parsed_from, end_of_day=False)
        if parsed_from is not None
        else None,
        normalize_date_bound(parsed_to, end_of_day=True)
        if parsed_to is not None
        else None,
    )


def _ticket(ticket_id: str | None) -> CVEAssociatedTicket | None:
    return CVEAssociatedTicket(ticket_id=ticket_id) if ticket_id is not None else None


def serialize_cve_detail(cve: CVEDetailProjection) -> CVEDetail:
    """Map the expanded CVE projection to its `CVEDetail` schema."""
    return CVEDetail.model_validate(
        {
            "cve_id": cve.cve_id,
            "title": cve.title,
            "description": cve.description,
            "published_date": cve.published_date,
            "modified_date": cve.modified_date,
            "cve_state": cve.cve_state.lower(),
            "date_rejected": cve.date_rejected,
            "severity": _lower(cve.severity),
            "external_identifiers": [
                CVEExternalIdentifierResponse(
                    source=item.source.lower(),
                    identifier=item.identifier,
                    url=item.url,
                )
                for item in cve.external_identifiers
            ],
            "kev": (
                CVEKEVResponse(
                    date_added=cve.kev.date_added,
                    reference_url=cve.kev.reference_url,
                )
                if cve.kev is not None
                else None
            ),
            "epss": (
                CVEEPSSResponse(
                    score=cve.epss.score,
                    percentile=cve.epss.percentile,
                    assessed_at=cve.epss.assessed_at,
                )
                if cve.epss is not None
                else None
            ),
            "ssvc": (
                CVESSVCResponse(
                    exploitation=cve.ssvc.exploitation,
                    automatable=cve.ssvc.automatable,
                    technical_impact=cve.ssvc.technical_impact,
                    version=cve.ssvc.version,
                    assessed_at=cve.ssvc.assessed_at,
                )
                if cve.ssvc is not None
                else None
            ),
            "cwes": [
                CVEWeaknessResponse(cwe_id=cwe.cwe_id, sources=list(cwe.sources))
                for cwe in cve.cwes
            ],
        }
    )


def serialize_cve_list_item(item: CVEListItemProjection) -> CVEListItem:
    """Map a CVE list projection to its `CVEListItem` schema (lowercase
    enumerated values)."""
    return CVEListItem.model_validate(
        {
            "cve_id": item.cve_id,
            "title": item.title,
            "description": item.description,
            "severity": _lower(item.severity),
            "cve_state": item.cve_state.lower(),
            "published_date": item.published_date,
            "ticket": _ticket(item.ticket_id),
            "created_at": item.created_at,
            "updated_at": item.updated_at,
        }
    )


def serialize_cve_resource_detail(result: CVEDetailResult) -> CVEResourceDetail:
    """Map the CVE detail result to `CVEResourceDetail`: the shared
    `CVEDetail` fields plus the associated Ticket identity."""
    return CVEResourceDetail.model_validate(
        {
            **serialize_cve_detail(result.cve).model_dump(),
            "ticket": _ticket(result.ticket_id),
        }
    )


def serialize_cve_source_list_item(
    item: CVESourceListItemProjection,
) -> CVESourceListItem:
    """Map a persisted CVE-source projection to its `CVESourceListItem`."""
    return CVESourceListItem.model_validate(
        {
            "cve_id": item.cve_id,
            "source": item.source,
            "status": item.status.value,
            "fetched_at": item.fetched_at,
            "first_failed_at": item.first_failed_at,
            "created_at": item.created_at,
            "updated_at": item.updated_at,
        }
    )


def _cve_list_query(
    *,
    search: Annotated[
        str | None,
        Query(
            description=(
                "Free-text search. Outer whitespace is trimmed; a "
                "whitespace-only value is ignored. CVE ID: case-insensitive "
                "prefix; title and description: case-insensitive substring. "
                "`%`, `_`, and backslash are literal."
            )
        ),
    ] = None,
    cve_state: Annotated[
        str | None,
        Query(
            description=(
                "Filter by CVE state: `published` or `rejected`. Any other "
                "value yields an empty page."
            )
        ),
    ] = None,
    severity: Annotated[
        list[str],
        Query(
            default_factory=list,
            description=(
                "Filter by resolved severity: `critical`, `high`, `medium`, "
                "`low`, `none` (CVSS score 0.0), `unresolved` (no CVSS "
                "assessment). Repeatable; OR semantics. Invalid values are "
                "ignored; only invalid values yield an empty page."
            ),
        ),
    ],
    has_ticket: Annotated[
        bool | None,
        Query(
            description=(
                "`true`: only CVEs with an associated Ticket; `false`: only "
                "CVEs without a Ticket."
            )
        ),
    ] = None,
    from_date: Annotated[
        str | None,
        Query(
            description=(
                "ISO 8601 date/datetime; inclusive lower bound on "
                "`published_date`. CVEs without a publication date are excluded."
            )
        ),
    ] = None,
    to_date: Annotated[
        str | None,
        Query(
            description=(
                "ISO 8601 date/datetime; inclusive upper bound on "
                "`published_date`. CVEs without a publication date are excluded."
            )
        ),
    ] = None,
    page: Annotated[int, Query(ge=1, le=2_147_483_647, description="Page number.")] = 1,
    per_page: Annotated[
        int, Query(ge=1, le=100, description="Items per page; maximum 100.")
    ] = 20,
    sort_by: Annotated[
        CVESortField,
        Query(
            description=(
                "Sort field (default `published_date`): `cve_id` (Unicode "
                "code-point lexical order), `published_date`, `severity` "
                "(semantic ordering), or `created_at`. `null` values sort "
                "last in both directions."
            )
        ),
    ] = CVESortField.PUBLISHED_DATE,
    sort_order: Annotated[
        SortOrder, Query(description="`asc` or `desc` (default `desc`).")
    ] = SortOrder.DESC,
) -> CVEListQuery:
    """Collect the List CVEs query parameters.

    Declared as individual `Query()` parameters so each one is visible to
    the shared query-length-limit dependency (`app.core.query_limits`).
    """
    parsed_from, parsed_to = _date_bounds(from_date, to_date)
    return CVEListQuery(
        search=search,
        cve_state=cve_state,
        severity=severity or None,
        has_ticket=has_ticket,
        from_date=parsed_from,
        to_date=parsed_to,
        page=page,
        per_page=per_page,
        sort_by=sort_by,
        sort_order=sort_order,
    )


def _cve_source_list_query(
    *,
    source: Annotated[
        str | None,
        Query(
            pattern=_SOURCE_PATTERN,
            max_length=_SOURCE_MAX_LENGTH,
            description=(
                "Filter by one exact persisted source identifier (e.g. "
                "`nvd`), currently registered or historical. Must match "
                "`^[a-z][a-z0-9_]*$` and be at most 100 characters; an "
                "absent well-formed value yields an empty page."
            ),
        ),
    ] = None,
    status_filter: Annotated[
        str | None,
        Query(
            alias="status",
            description=(
                "Filter by persisted fetch status: `success`, `failure`, or "
                "`missing`. Any other value yields an empty page."
            ),
        ),
    ] = None,
    stalled: Annotated[
        bool | None,
        Query(
            description=(
                "`true`: only stalled records (`failure` whose streak began "
                "more than 30 days ago); `false`: every record except stalled "
                "ones. `false` does not imply retryable."
            )
        ),
    ] = None,
    from_date: Annotated[
        str | None,
        Query(
            description="ISO 8601 date/datetime; inclusive lower bound on fetched_at."
        ),
    ] = None,
    to_date: Annotated[
        str | None,
        Query(
            description="ISO 8601 date/datetime; inclusive upper bound on fetched_at."
        ),
    ] = None,
    page: Annotated[int, Query(ge=1, le=2_147_483_647, description="Page number.")] = 1,
    per_page: Annotated[
        int, Query(ge=1, le=100, description="Items per page; maximum 100.")
    ] = 20,
    sort_by: Annotated[
        CVESourceSortField,
        Query(
            description=(
                "Sort field (default `fetched_at`): `fetched_at`, "
                "`first_failed_at`, `source`, or `status` (the latter two in "
                "Unicode code-point lexical order). `null` values sort last "
                "in both directions."
            )
        ),
    ] = CVESourceSortField.FETCHED_AT,
    sort_order: Annotated[
        SortOrder, Query(description="`asc` or `desc` (default `desc`).")
    ] = SortOrder.DESC,
) -> CVESourceListQuery:
    """Collect the Global CVE Source Listing query parameters.

    Individual `Query()` parameters, as for the CVE list; `status` uses
    an alias only to keep the Python name distinct from FastAPI's
    `status` module.
    """
    parsed_from, parsed_to = _date_bounds(from_date, to_date)
    return CVESourceListQuery(
        source=source,
        status=status_filter,
        stalled=stalled,
        from_date=parsed_from,
        to_date=parsed_to,
        page=page,
        per_page=per_page,
        sort_by=sort_by,
        sort_order=sort_order,
    )


@router.get(
    "/cves",
    response_model=CVEListResponse,
    summary="List CVEs",
    description=(
        "Returns a paginated list of the CVEs accessible to the caller, with "
        "free-text search, state, repeatable severity, Ticket-presence, and "
        "publication-date filters, and sorting. A CVE without a Ticket is "
        "always listed; a CVE with a Ticket is listed only when that Ticket "
        "is visible to the caller. Public; optional authentication "
        "determines access to CVEs associated with confidential Tickets."
    ),
)
async def list_cves(
    db: DatabaseSession,
    caller: OptionalTicketCaller,
    query: Annotated[CVEListQuery, Depends(_cve_list_query)],
) -> CVEListResponse:
    """List CVEs — see `docs/features/tickets/cve-tracking.md` (List CVEs).

    The service applies CVE accessibility inside its single list
    statement; rows and total come from one observation.
    """
    result = await cve_service.list_cves(
        db,
        caller,
        search=query.search,
        cve_state=query.cve_state,
        severity=query.severity,
        has_ticket=query.has_ticket,
        from_date=query.from_date,
        to_date=query.to_date,
        page=query.page,
        per_page=query.per_page,
        sort_by=query.sort_by,
        sort_order=query.sort_order,
    )
    return CVEListResponse(
        data=[serialize_cve_list_item(item) for item in result.items],
        meta=PaginationMeta(
            total=result.total, page=result.page, per_page=result.per_page
        ),
    )


@router.get(
    "/cves/{cve_id}",
    response_model=CVEResourceDetailResponse,
    summary="Get CVE",
    description=(
        "Returns one CVE, identified by its CVE-ID, with its persisted "
        "exploitation (KEV, EPSS, SSVC) and weakness (CWE) evidence, its "
        "external identifiers, and the associated Ticket identity. Evidence "
        "only: no priority and no CVSS assessments (see `/cvss`). Public; "
        "optional authentication determines access to CVEs associated with "
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
async def get_cve(
    cve_id: CVEIdPath,
    db: DatabaseSession,
    caller: OptionalTicketCaller,
) -> CVEResourceDetailResponse:
    """Get CVE — see `docs/features/tickets/cve-tracking.md` (Get CVE).

    The service applies CVE accessibility in the same statement that
    selects the complete detail, so no preliminary query is needed.
    """
    try:
        result = await cve_service.get_cve_detail(db, caller, cve_id)
    except CVENotFoundError:
        raise cve_not_found_error() from None
    return CVEResourceDetailResponse(data=serialize_cve_resource_detail(result))


@router.get(
    "/cve-sources",
    response_model=CVESourceListResponse,
    summary="List persisted CVE source records",
    description=(
        "Returns a paginated global listing of the persisted latest-state "
        "CVE source records (CVE-ID, source, persisted status, timestamps), "
        "filterable by source, status, stalled state, and fetch time. Enables "
        "drill-down from fetcher runs; the result is a latest-state "
        "approximation and can differ from a run's failure count. Exposes "
        "public CVE IDs and operational metadata only, so no Ticket "
        "visibility is applied. Public; optional authentication."
    ),
)
async def list_cve_sources(
    db: DatabaseSession,
    principal: OptionalCurrentUser,
    query: Annotated[CVESourceListQuery, Depends(_cve_source_list_query)],
) -> CVESourceListResponse:
    """Global CVE Source Listing — see `docs/features/tickets/cve-service.md`.

    `principal` processes optional authentication (sliding session
    refresh, 401 for an invalid selected credential); the listing itself
    does not vary by caller.
    """
    del principal
    result = await cve_service.list_cve_sources(
        db,
        source=query.source,
        status=query.status,
        stalled=query.stalled,
        from_date=query.from_date,
        to_date=query.to_date,
        page=query.page,
        per_page=query.per_page,
        sort_by=query.sort_by,
        sort_order=query.sort_order,
    )
    return CVESourceListResponse(
        data=[serialize_cve_source_list_item(item) for item in result.items],
        meta=PaginationMeta(
            total=result.total, page=result.page, per_page=result.per_page
        ),
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
