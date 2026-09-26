"""Ticket endpoints.

See `docs/features/tickets/tickets.md` (API Endpoints > Get Ticket,
Response Schemas > TicketDetail) for the authoritative endpoint contract.
Handlers stay thin: they supply caller information to `ticket_service`,
map its outcomes to HTTP, and serialize its semantic projection. The
service owns SNTL resolution, visibility-constrained selection, and the
single evaluation instant; no business logic or database query lives
here.

`serialize_ticket_detail()` is the one `TicketDetail` serializer, shared
by every endpoint that returns a Ticket detail, so responses cannot
drift. It never captures a date or instant.
"""

from __future__ import annotations

from fastapi import APIRouter

from app.api.dependencies import (
    OptionalTicketCaller,
    TicketIdPath,
    ticket_not_found_error,
)
from app.api.v1.ticket_packages import serialize_package
from app.core.exceptions import TicketNotFoundError
from app.database import DatabaseSession
from app.schemas.common import UserReference
from app.schemas.cve import (
    CVEDetail,
    CVEEPSSResponse,
    CVEExternalIdentifierResponse,
    CVEKEVResponse,
    CVESSVCResponse,
    CVEWeaknessResponse,
)
from app.schemas.errors import ErrorResponse
from app.schemas.ticket import TicketDetail, TicketDetailResponse
from app.services import ticket_service
from app.services.ticket_service import CVEDetailProjection, TicketDetailProjection

router = APIRouter(prefix="/api/v1", tags=["Tickets"])


def _lower(value: str | None) -> str | None:
    return value.lower() if value is not None else None


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


def serialize_ticket_detail(detail: TicketDetailProjection) -> TicketDetail:
    """Map a Ticket detail projection to its `TicketDetail` schema.

    Lowercases every enumerated value, expands the Ticket-level due dates
    (all `null` when no SLA applies), and reuses the package-tree
    serializer for `packages`.
    """
    due = detail.due_dates
    return TicketDetail.model_validate(
        {
            "ticket_id": detail.ticket_id,
            "status": detail.status.lower(),
            "severity": _lower(detail.severity),
            "priority": _lower(detail.priority),
            "priority_automatic": _lower(detail.priority_automatic),
            "priority_override": _lower(detail.priority_override),
            "assignee": (
                UserReference.model_validate(detail.assignee)
                if detail.assignee is not None
                else None
            ),
            "cve": serialize_cve_detail(detail.cve) if detail.cve is not None else None,
            "duplicate_of_ticket_id": detail.duplicate_of_ticket_id,
            "is_confidential": detail.is_confidential,
            "coordinated_release_at": detail.coordinated_release_at,
            "triage_due_at": due.triage if due is not None else None,
            "submission_due_at": due.submission if due is not None else None,
            "um_due_at": due.um if due is not None else None,
            "qa_due_at": due.qa if due is not None else None,
            "release_due_at": due.release if due is not None else None,
            "packages": [serialize_package(p) for p in detail.packages],
            "created_at": detail.created_at,
            "updated_at": detail.updated_at,
        }
    )


@router.get(
    "/tickets/{ticket_id}",
    response_model=TicketDetailResponse,
    summary="Get Ticket",
    description=(
        "Returns one Ticket by its canonical SNTL-{n} identity: root fields, "
        "resolved severity, effective, automatic, and override priority, "
        "Ticket-level due dates, the current assignee, expanded CVE evidence "
        "(KEV, EPSS, SSVC, CWE, external identifiers; CVSS assessments are "
        "available from their own sub-resource), the duplicate target's "
        "identifier only, and the complete package tree. Maintainer "
        "identities are not included. Public; optional authentication "
        "determines access to confidential Tickets."
    ),
    responses={
        404: {
            "model": ErrorResponse,
            "description": (
                "Ticket identifier is malformed, does not exist, or identifies "
                "a Ticket inaccessible to the caller."
            ),
        },
    },
)
async def get_ticket(
    ticket_id: TicketIdPath,
    db: DatabaseSession,
    caller: OptionalTicketCaller,
) -> TicketDetailResponse:
    """Get Ticket — see `docs/features/tickets/tickets.md` (Get Ticket).

    The service captures the response's single evaluation instant and
    applies Ticket visibility in the same statement that selects the
    complete detail, so no separate preliminary accessibility query is
    needed.
    """
    try:
        detail = await ticket_service.get_ticket_detail(
            db, ticket_id=ticket_id, caller=caller
        )
    except TicketNotFoundError:
        raise ticket_not_found_error() from None
    return TicketDetailResponse(data=serialize_ticket_detail(detail))
