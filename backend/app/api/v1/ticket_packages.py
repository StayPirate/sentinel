"""Ticket package-tree endpoints.

See `docs/features/packages/package-model.md` (API Endpoints > List Ticket
Packages, Change Track Status) for the authoritative endpoint contracts.
Handlers stay thin: they capture the request's single evaluation instant
or date (`docs/features/tickets/ticket-deadlines.md`, Evaluation Instant;
package-model.md, Derived Actionability), delegate the protected read or
locked mutation to `package_service`, and map results and service
exceptions to HTTP. No business logic or database query lives here.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Path

from app.api.dependencies import (
    AuthenticatedPrincipal,
    AuthenticatedTicketCaller,
    CallerRoles,
    OptionalTicketCaller,
    TicketIdPath,
    insufficient_permission_error,
    require_accessible_ticket,
    require_any_capability,
    resource_not_found_error,
    ticket_not_found_error,
    ticket_not_mutable_error,
)
from app.core.enums import Capability, PackageStatus
from app.core.exceptions import TicketNotFoundError, TicketNotMutableError
from app.core.permissions import get_capabilities
from app.database import DatabaseSession
from app.schemas.errors import ErrorResponse
from app.schemas.package import (
    PackageDetail,
    ProductDetail,
    TicketPackageListResponse,
    TrackDetail,
    TrackMilestones,
    TrackStatusProduct,
    TrackStatusResponse,
    TrackStatusTrack,
    TrackStatusUpdateRequest,
)
from app.services import package_service
from app.services.package_service import (
    PackageNotFoundError,
    PackageProjection,
    ProductProjection,
    TrackFixedStatusRestrictedError,
    TrackNotFoundError,
    TrackProjection,
    TrackStatusProjection,
)
from app.services.ticket_service import ResolvedTicket

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


# ---------------------------------------------------------------------------
# Change Track Status
# ---------------------------------------------------------------------------

PackageIdPath = Annotated[
    UUID, Path(description="TicketPackage occurrence identifier (UUID).")
]
TrackIdPath = Annotated[
    UUID, Path(description="TicketPackageTrack occurrence identifier (UUID).")
]

_require_track_status_capability = require_any_capability(
    Capability.ADMIN_TICKET_OPS, Capability.MANAGE_PACKAGES
)


@dataclass(frozen=True, slots=True)
class _TrackStatusChange:
    """A validated track-status request that passed every capability check."""

    principal: AuthenticatedPrincipal
    package_id: UUID
    track_id: UUID
    status: PackageStatus
    force: bool


@dataclass(frozen=True, slots=True)
class _ResolvedTrackStatusChange:
    """An authorized track-status request with its preliminary Ticket."""

    change: _TrackStatusChange
    ticket: ResolvedTicket


async def _authorize_track_status_change(
    principal: Annotated[
        AuthenticatedPrincipal, Depends(_require_track_status_capability)
    ],
    roles: CallerRoles,
    body: TrackStatusUpdateRequest,
    package_id: PackageIdPath,
    track_id: TrackIdPath,
) -> _TrackStatusChange:
    """Apply the value-dependent capability check (package-model.md,
    Change Track Status †; `docs/api-spec.md`, alternative capabilities).

    FastAPI resolves the capability union first (generic 403 for a caller
    holding neither alternative), then validates the body and nested
    path UUIDs (422, which skips this function), and only then runs this
    check: a non-`fixed` target requires `manage_packages` and otherwise
    returns the same generic 403. None of these steps loads a resource.
    `force` is derived from the once-resolved roles: it marks a `fixed`
    request by an `admin_ticket_ops` holder (unrestricted `FIXED`).
    """
    capabilities = get_capabilities(roles)
    status = PackageStatus(body.status.upper())
    if (
        status is not PackageStatus.FIXED
        and Capability.MANAGE_PACKAGES not in capabilities
    ):
        raise insufficient_permission_error()
    return _TrackStatusChange(
        principal=principal,
        package_id=package_id,
        track_id=track_id,
        status=status,
        force=status is PackageStatus.FIXED
        and Capability.ADMIN_TICKET_OPS in capabilities,
    )


async def _resolve_track_status_change(
    change: Annotated[_TrackStatusChange, Depends(_authorize_track_status_change)],
    ticket_id: TicketIdPath,
    db: DatabaseSession,
    caller: AuthenticatedTicketCaller,
) -> _ResolvedTrackStatusChange:
    """Run the preliminary Ticket accessibility role after authorization.

    Depends on the authorized change, so a capability or validation
    failure always precedes the `require_accessible_ticket` resolution
    (`404 TICKET_NOT_FOUND`). The resolution is invoked here rather than
    declared as a sibling dependency so that FastAPI cannot run it when
    the body fails validation.
    """
    ticket = await require_accessible_ticket(ticket_id, db, caller)
    return _ResolvedTrackStatusChange(change=change, ticket=ticket)


def _serialize_track_status(track: TrackStatusProjection) -> TrackStatusTrack:
    return TrackStatusTrack.model_validate(
        {
            "ticket_id": track.ticket_id,
            "package_name": track.package_name,
            "reference": track.reference,
            "status": track.status.lower(),
            "delivery_status": track.delivery_status.lower(),
            "delivery_relevant": track.delivery_relevant,
            "actionable": track.actionable,
            "non_actionable_reason": _lower(track.non_actionable_reason),
            "products": [
                TrackStatusProduct.model_validate(
                    {
                        "id": product.id,
                        "product_cpe": product.product_cpe,
                        "product_name": product.product_name,
                        "eligible": product.eligible,
                        "is_eligible_override": product.is_eligible_override,
                        "lifecycle_phase": _lower(product.lifecycle_phase),
                        "actionable": product.actionable,
                        "non_actionable_reason": _lower(product.non_actionable_reason),
                    }
                )
                for product in track.products
            ],
        }
    )


@router.patch(
    "/tickets/{ticket_id}/packages/{package_id}/tracks/{track_id}",
    response_model=TrackStatusResponse,
    summary="Change Track Status",
    description=(
        "Changes the affectedness status of one track. An effective change "
        "records a `track_status_changed` event, auto-assigns an unassigned "
        "Ticket to an active vulnerability analyst, and re-evaluates the "
        "Ticket status; an unchanged status returns the current track with "
        "no side effect. `fixed` requires `admin_ticket_ops` (any Ticket) or "
        "`manage_packages` (only a Ticket without a CVE); every other status "
        "requires `manage_packages`. Returns the track and all its Products "
        "with their current eligibility and actionability."
    ),
    responses={
        404: {
            "model": ErrorResponse,
            "description": (
                "`TICKET_NOT_FOUND`: Ticket identifier is malformed, does not "
                "exist, or identifies a Ticket inaccessible to the caller. "
                "`RESOURCE_NOT_FOUND`: the package or track does not exist "
                "under the declared Ticket and package."
            ),
        },
        409: {
            "model": ErrorResponse,
            "description": "`TICKET_NOT_MUTABLE`: the Ticket is Ignored or Duplicated.",
        },
    },
)
async def change_track_status(
    resolved: Annotated[
        _ResolvedTrackStatusChange, Depends(_resolve_track_status_change)
    ],
    db: DatabaseSession,
    caller: AuthenticatedTicketCaller,
) -> TrackStatusResponse:
    """Change Track Status — see `docs/features/packages/package-model.md`.

    Authorization follows `docs/api-spec.md` (Authorization Chain
    Evaluation Order, flow 3, alternative capabilities) through the
    dependency chain above. The handler captures the one workflow UTC
    date, shared by the service's reconciliation and its locked-current
    track projection; `set_track_status()` revalidates accessibility,
    operability, nested ownership, and the CVE-less `FIXED` restriction
    under the Ticket lock.
    """
    change = resolved.change
    evaluation_date = _utc_now().date()
    try:
        result = await package_service.set_track_status(
            db,
            ticket_id=resolved.ticket.id,
            package_id=change.package_id,
            track_id=change.track_id,
            status=change.status,
            acting_user_id=change.principal.user.id,
            caller=caller,
            force=change.force,
            evaluation_date=evaluation_date,
        )
    except TicketNotFoundError:
        raise ticket_not_found_error() from None
    except TicketNotMutableError:
        raise ticket_not_mutable_error() from None
    except PackageNotFoundError, TrackNotFoundError:
        raise resource_not_found_error() from None
    except TrackFixedStatusRestrictedError:
        raise insufficient_permission_error() from None
    return TrackStatusResponse(data=_serialize_track_status(result.track))
