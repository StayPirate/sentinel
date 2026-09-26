"""Ticket package-tree endpoint.

See `docs/features/packages/package-model.md` (API Endpoints > List Ticket
Packages) for the authoritative endpoint contract. The handler stays
thin: it captures the response's single evaluation instant and derives
its UTC evaluation date (`docs/features/tickets/ticket-deadlines.md`,
Evaluation Instant), delegates the protected read to
`package_service.get_ticket_packages()`, and maps the result or the
shared `TicketNotFoundError` to HTTP. No business logic or database query
lives here.
"""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter

from app.api.dependencies import (
    OptionalTicketCaller,
    TicketIdPath,
    ticket_not_found_error,
)
from app.core.exceptions import TicketNotFoundError
from app.database import DatabaseSession
from app.schemas.errors import ErrorResponse
from app.schemas.package import (
    PackageDetail,
    ProductDetail,
    TicketPackageListResponse,
    TrackDetail,
    TrackMilestones,
)
from app.services import package_service
from app.services.package_service import (
    PackageProjection,
    ProductProjection,
    TrackProjection,
)

router = APIRouter(prefix="/api/v1", tags=["Ticket Packages"])


def _utc_now() -> datetime:
    """The current instant in UTC (patched by controlled-clock tests)."""
    return datetime.now(UTC)


def _lower(value: str | None) -> str | None:
    return value.lower() if value is not None else None


def _serialize_product(product: ProductProjection) -> ProductDetail:
    return ProductDetail.model_validate(
        {
            "id": product.id,
            "product_cpe": product.product_cpe,
            "product_name": product.product_name,
            "eligible": product.eligible,
            "is_eligible_override": product.is_eligible_override,
            "released_at": product.released_at,
            "lifecycle_phase": _lower(product.lifecycle_phase),
            "deleted_at": product.deleted_at,
            "actionable": product.actionable,
            "non_actionable_reason": _lower(product.non_actionable_reason),
        }
    )


def _serialize_track(track: TrackProjection) -> TrackDetail:
    due = track.due_dates
    milestones = track.milestones
    return TrackDetail.model_validate(
        {
            "id": track.id,
            "workflow_type": track.workflow_type.lower(),
            "reference": track.reference,
            "status": track.status.lower(),
            "delivery_status": track.delivery_status.lower(),
            "delivery_relevant": track.delivery_relevant,
            "products": [_serialize_product(p) for p in track.products],
            "deleted_at": track.deleted_at,
            "actionable": track.actionable,
            "non_actionable_reason": _lower(track.non_actionable_reason),
            "triage_due_at": due.triage if due is not None else None,
            "submission_due_at": due.submission if due is not None else None,
            "um_due_at": due.um if due is not None else None,
            "qa_due_at": due.qa if due is not None else None,
            "release_due_at": due.release if due is not None else None,
            "milestones": TrackMilestones.model_validate(
                {
                    "triage": _lower(milestones.triage),
                    "submission": _lower(milestones.submission),
                    "um": _lower(milestones.um),
                    "qa": _lower(milestones.qa),
                }
            ),
            "current_phase": _lower(milestones.current_phase),
        }
    )


def serialize_package(package: PackageProjection) -> PackageDetail:
    """Map one package-tree projection to its `PackageDetail` schema.

    Shared by every response embedding the package tree
    (`TicketDetail.packages` reuses the same schema).
    """
    return PackageDetail.model_validate(
        {
            "id": package.id,
            "package_name": package.package_name,
            "tracks": [_serialize_track(t) for t in package.tracks],
            "deleted_at": package.deleted_at,
            "actionable": package.actionable,
            "non_actionable_reason": _lower(package.non_actionable_reason),
        }
    )


@router.get(
    "/tickets/{ticket_id}/packages",
    response_model=TicketPackageListResponse,
    summary="List Ticket packages",
    description=(
        "Returns the complete package tree of one Ticket: every package, "
        "track, and Product occurrence, including manually excluded and "
        "lifecycle-non-actionable records, with direct exclusion timestamps, "
        "derived actionability, per-track due dates, milestones, and current "
        "phase. Fixed order: packages by name, tracks by reference, and "
        "Products by CPE, each in ascending Unicode code-point order. "
        "Unpaginated (the package count per Ticket is bounded). The Ticket is "
        "identified by its canonical SNTL-{n} identity. Public; optional "
        "authentication determines access to confidential Tickets."
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
async def list_ticket_packages(
    ticket_id: TicketIdPath,
    db: DatabaseSession,
    caller: OptionalTicketCaller,
) -> TicketPackageListResponse:
    """List Ticket packages — see `docs/features/packages/package-model.md`
    (List Ticket Packages).

    Captures one evaluation instant for the complete response and uses
    its UTC calendar date as the read's `evaluation_date`. The service
    applies Ticket visibility in the same statement that selects the
    tree, so no separate preliminary accessibility query is needed.
    """
    evaluation_instant = _utc_now()
    try:
        packages = await package_service.get_ticket_packages(
            db,
            ticket_id=ticket_id,
            caller=caller,
            evaluation_date=evaluation_instant.astimezone(UTC).date(),
            evaluation_instant=evaluation_instant,
        )
    except TicketNotFoundError:
        raise ticket_not_found_error() from None
    return TicketPackageListResponse(data=[serialize_package(p) for p in packages])
