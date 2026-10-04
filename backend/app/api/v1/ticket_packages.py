"""Ticket package-tree endpoints.

See `docs/features/packages/package-model.md` (API Endpoints > Add Package
to Ticket, List Ticket Packages, Search Packages Across Tickets, Change
Track Status, Override Product Eligibility, Soft-Delete and Restore
Package, Track, and Product) for the authoritative endpoint contracts.
Handlers stay thin: they capture the request's single evaluation instant
or date (`docs/features/tickets/ticket-deadlines.md`, Evaluation Instant;
package-model.md, Derived Actionability), delegate the protected read or
locked mutation to `package_service`, and map results and service
exceptions to HTTP. No business logic or database query lives here.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Awaitable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Annotated, Any, Final
from uuid import UUID

import httpx
from fastapi import APIRouter, Depends, Path, Query
from fastapi import status as http_status
from fastapi.exceptions import RequestValidationError
from pydantic import ValidationError

from app.api.dependencies import (
    AuthenticatedPrincipal,
    AuthenticatedTicketCaller,
    CallerRoles,
    OptionalTicketCaller,
    TicketIdPath,
    insufficient_permission_error,
    require_accessible_ticket,
    require_any_capability,
    require_capability,
    resource_not_found_error,
    ticket_not_found_error,
    ticket_not_mutable_error,
)
from app.core.enums import (
    Capability,
    PackageSortField,
    PackageStatus,
    SortOrder,
    TicketStatus,
)
from app.core.errors import AppError, ErrorCode
from app.core.exceptions import TicketNotFoundError, TicketNotMutableError
from app.core.permissions import get_capabilities
from app.database import DatabaseSession
from app.schemas.common import PaginationMeta
from app.schemas.errors import ErrorResponse
from app.schemas.package import (
    PackageAdditionRequest,
    PackageAdditionResponse,
    PackageAdditionResult,
    PackageDetail,
    PackageExclusionPackage,
    PackageExclusionResponse,
    PackageListItem,
    PackageListResponse,
    PackageSearchQuery,
    ProductDetail,
    ProductEligibilityProduct,
    ProductEligibilityResponse,
    ProductEligibilityUpdateRequest,
    ProductExclusionProduct,
    ProductExclusionResponse,
    TicketPackageListResponse,
    TicketPackageRef,
    TrackDetail,
    TrackExclusionResponse,
    TrackExclusionTrack,
    TrackMilestones,
    TrackStatusProduct,
    TrackStatusResponse,
    TrackStatusTrack,
    TrackStatusUpdateRequest,
    TrackSummary,
)
from app.services import package_service
from app.services.http_client import create_http_client
from app.services.package_service import (
    PackageAlreadyExcludedError,
    PackageMarkerProjection,
    PackageNotExcludedError,
    PackageNotFoundError,
    PackageNotFoundInSmeltError,
    PackageProjection,
    PackageSearchItem,
    PackageTargetsUnresolvedError,
    ProductCatalogNotReadyError,
    ProductEligibilityProjection,
    ProductMarkerProjection,
    ProductNotFoundError,
    ProductProjection,
    SmeltUnavailableError,
    TrackFixedStatusRestrictedError,
    TrackMarkerProjection,
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
# Search Packages Across Tickets
# ---------------------------------------------------------------------------

# Lowercase wire value -> domain filter member (tickets.md, Response
# Schemas: enum serialization; package-model.md, Query Parameters).
_TICKET_STATUS_FILTER: Final[Mapping[str, TicketStatus]] = {
    member.value.lower(): member for member in TicketStatus
}


def _ticket_status_filter(raw: list[str]) -> list[TicketStatus] | None:
    """Resolve the raw repeatable `ticket_status` values.

    Returns `None` when the parameter was not supplied (no filter), or
    the valid members otherwise. Invalid values, including
    comma-separated lists, are silently dropped, so an all-invalid
    filter yields an empty list, which the service turns into an empty
    page (`docs/api-spec.md`, Enum Filter Validation).
    """
    if not raw:
        return None
    members = _TICKET_STATUS_FILTER
    return [members[value] for value in raw if value in members]


def _package_search_query(
    *,
    search: Annotated[
        str | None,
        Query(
            description=(
                "Case-insensitive substring match on the package name. Outer "
                "whitespace is trimmed once; an empty result means no search "
                "filter. `%`, `_`, and backslash are literal characters. "
                "Mutually exclusive with `name`."
            )
        ),
    ] = None,
    name: Annotated[
        str | None,
        Query(
            description=(
                "Exact, case-sensitive match on the package name. Mutually "
                "exclusive with a non-empty `search`."
            )
        ),
    ] = None,
    ticket_status: Annotated[
        list[str],
        Query(
            default_factory=list,
            description=(
                "Ticket statuses to include: `new`, `analysis`, `analyzed`, "
                "`resolved`, `ignored`, `duplicated`. Repeatable; OR semantics. "
                "Invalid values are ignored; if all values are invalid, the "
                "result is empty. Default: all statuses."
            ),
        ),
    ],
    sort_by: Annotated[
        PackageSortField,
        Query(
            description=(
                "Sort field (default `created_at`): `package_name` (Unicode "
                "code-point order) or `created_at` (when the package was added "
                "to the Ticket)."
            )
        ),
    ] = PackageSortField.CREATED_AT,
    sort_order: Annotated[
        SortOrder, Query(description="`asc` or `desc` (default `desc`).")
    ] = SortOrder.DESC,
    page: Annotated[int, Query(ge=1, le=2_147_483_647, description="Page number.")] = 1,
    per_page: Annotated[
        int, Query(ge=1, le=100, description="Items per page; maximum 100.")
    ] = 20,
) -> PackageSearchQuery:
    """Collect and validate the Search Packages query parameters.

    Declared as individual `Query()` parameters so each one is visible to
    the shared query-length-limit dependency (`app.core.query_limits`).
    The `search`/`name` exclusivity is a cross-field rule of
    `PackageSearchQuery`; its failure is re-raised as the global
    `422 VALIDATION_ERROR`.
    """
    try:
        return PackageSearchQuery(
            search=search,
            name=name,
            ticket_status=ticket_status,
            sort_by=sort_by,
            sort_order=sort_order,
            page=page,
            per_page=per_page,
        )
    except ValidationError as exc:
        raise RequestValidationError(
            [
                {
                    "loc": ("query", *error["loc"]),
                    "msg": error["msg"],
                    "type": error["type"],
                }
                for error in exc.errors()
            ]
        ) from None


def _serialize_search_item(item: PackageSearchItem) -> PackageListItem:
    ticket = item.ticket
    summary = item.track_summary
    return PackageListItem.model_validate(
        {
            "id": item.id,
            "package_name": item.package_name,
            "ticket": TicketPackageRef.model_validate(
                {
                    "ticket_id": ticket.ticket_id,
                    "status": ticket.status.lower(),
                    "severity": _lower(ticket.severity),
                }
            ),
            "track_summary": TrackSummary.model_validate(
                {
                    "total": summary.total,
                    "affected": summary.affected,
                    "fixed": summary.fixed,
                    "not_affected": summary.not_affected,
                    "wont_fix": summary.wont_fix,
                    "analysis": summary.analysis,
                }
            ),
            "created_at": item.created_at,
            "updated_at": item.updated_at,
        }
    )


@router.get(
    "/packages",
    response_model=PackageListResponse,
    summary="Search packages across Tickets",
    description=(
        "Returns a paginated list of actionable package occurrences across the "
        "Tickets visible to the caller; each item is one (package name, Ticket) "
        "pair. Non-actionable packages (directly excluded, or without an "
        "actionable track) are always omitted. Supports a literal substring "
        "`search` or an exact `name`, a repeatable `ticket_status` filter, and "
        "sorting. Visibility is applied before every filter, sort, count, page, "
        "and track aggregate. Public; optional authentication determines access "
        "to confidential Tickets."
    ),
)
async def search_packages(
    db: DatabaseSession,
    caller: OptionalTicketCaller,
    query: Annotated[PackageSearchQuery, Depends(_package_search_query)],
) -> PackageListResponse:
    """Search Packages Across Tickets — see
    `docs/features/packages/package-model.md` (Search Packages Across
    Tickets).

    Captures one UTC evaluation date for the complete response; the
    service applies visibility, actionability, filters, the total, and
    the track aggregates from one statement.
    """
    result = await package_service.search_packages(
        db,
        caller=caller,
        evaluation_date=_utc_now().astimezone(UTC).date(),
        search=query.search,
        name=query.name,
        ticket_status=_ticket_status_filter(query.ticket_status),
        sort_by=query.sort_by,
        sort_order=query.sort_order,
        page=query.page,
        per_page=query.per_page,
    )
    return PackageListResponse(
        data=[_serialize_search_item(item) for item in result.items],
        meta=PaginationMeta(
            total=result.total, page=result.page, per_page=result.per_page
        ),
    )


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


# ---------------------------------------------------------------------------
# Override Product Eligibility
# ---------------------------------------------------------------------------

ProductOccurrenceIdPath = Annotated[
    UUID,
    Path(
        description=(
            "TicketPackageProduct occurrence identifier (UUID), as returned in "
            "`products[].id`; never the catalog Product identifier."
        )
    ),
]


def _serialize_product_eligibility(
    product: ProductEligibilityProjection,
) -> ProductEligibilityProduct:
    return ProductEligibilityProduct.model_validate(
        {
            "ticket_id": product.ticket_id,
            "package_name": product.package_name,
            "reference": product.reference,
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


@router.patch(
    "/tickets/{ticket_id}/packages/{package_id}/tracks/{track_id}"
    "/products/{ticket_package_product_id}",
    response_model=ProductEligibilityResponse,
    summary="Override Product Eligibility",
    description=(
        "Sets, changes, or clears the eligibility override of one Product "
        "occurrence. `eligible: true` or `false` sets or changes the manual "
        "override; `eligible: null` removes it and immediately recalculates "
        "eligibility from the current CVSS threshold and lifecycle rules "
        "(the SUSE assessment of the default CVSS version, otherwise the 10.0 "
        "fallback, including for a Ticket without a CVE). An effective change "
        "records a `product_eligibility_changed` event, auto-assigns an "
        "unassigned Ticket to an active vulnerability analyst, and "
        "re-evaluates the Ticket status; an unchanged request returns the "
        "current Product with no side effect. Excluded and end-of-life "
        "Products remain editable. Requires `manage_packages`. Returns the "
        "Product with its current eligibility and actionability."
    ),
    responses={
        404: {
            "model": ErrorResponse,
            "description": (
                "`TICKET_NOT_FOUND`: Ticket identifier is malformed, does not "
                "exist, or identifies a Ticket inaccessible to the caller. "
                "`RESOURCE_NOT_FOUND`: the package, track, or Product occurrence "
                "does not exist under the declared Ticket, package, and track."
            ),
        },
        409: {
            "model": ErrorResponse,
            "description": "`TICKET_NOT_MUTABLE`: the Ticket is Ignored or Duplicated.",
        },
    },
)
async def override_product_eligibility(
    body: ProductEligibilityUpdateRequest,
    package_id: PackageIdPath,
    track_id: TrackIdPath,
    ticket_package_product_id: ProductOccurrenceIdPath,
    db: DatabaseSession,
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(require_capability(Capability.MANAGE_PACKAGES)),
    ],
    caller: AuthenticatedTicketCaller,
    ticket: Annotated[ResolvedTicket, Depends(require_accessible_ticket)],
) -> ProductEligibilityResponse:
    """Override Product Eligibility — see
    `docs/features/packages/package-model.md`.

    Authorization follows `docs/api-spec.md` (Authorization Chain
    Evaluation Order, flow 3): authentication, then `manage_packages`
    before any lookup, then the delegated preliminary SNTL resolution
    and request validation. The handler captures the one workflow UTC
    date, shared by the service's lifecycle evaluation, reconciliation,
    and locked-current Product projection; `set_product_eligibility()`
    revalidates accessibility, operability, and nested ownership under
    the Ticket lock.
    """
    evaluation_date = _utc_now().date()
    try:
        result = await package_service.set_product_eligibility(
            db,
            ticket_id=ticket.id,
            package_id=package_id,
            track_id=track_id,
            ticket_package_product_id=ticket_package_product_id,
            eligible=body.eligible,
            acting_user_id=principal.user.id,
            caller=caller,
            evaluation_date=evaluation_date,
        )
    except TicketNotFoundError:
        raise ticket_not_found_error() from None
    except TicketNotMutableError:
        raise ticket_not_mutable_error() from None
    except PackageNotFoundError, TrackNotFoundError, ProductNotFoundError:
        raise resource_not_found_error() from None
    return ProductEligibilityResponse(
        data=_serialize_product_eligibility(result.product)
    )


# ---------------------------------------------------------------------------
# Exclusion and restoration (Soft-Delete / Restore Package, Track, Product)
# ---------------------------------------------------------------------------


def package_already_excluded_error() -> AppError:
    """Create the 409 for an exclusion of an already directly excluded record.

    See package-model.md (Soft-Delete Package, Track, and Product) and
    package-service.md (Service Exceptions, `PackageAlreadyExcludedError`).
    """
    return AppError(
        status_code=http_status.HTTP_409_CONFLICT,
        code=ErrorCode.PACKAGE_ALREADY_EXCLUDED,
        detail="Record is already excluded.",
    )


def package_not_excluded_error() -> AppError:
    """Create the 422 for a restoration of a record not directly excluded.

    See package-model.md (Restore Package, Track, and Product) and
    package-service.md (Service Exceptions, `PackageNotExcludedError`).
    """
    return AppError(
        status_code=http_status.HTTP_422_UNPROCESSABLE_CONTENT,
        code=ErrorCode.PACKAGE_NOT_EXCLUDED,
        detail="Record is not directly excluded.",
    )


async def _run_marker_change[R](change: Awaitable[R]) -> R:
    """Await one exclusion or restoration and map its service exceptions."""
    try:
        return await change
    except TicketNotFoundError:
        raise ticket_not_found_error() from None
    except TicketNotMutableError:
        raise ticket_not_mutable_error() from None
    except PackageNotFoundError, TrackNotFoundError, ProductNotFoundError:
        raise resource_not_found_error() from None
    except PackageAlreadyExcludedError:
        raise package_already_excluded_error() from None
    except PackageNotExcludedError:
        raise package_not_excluded_error() from None


def _serialize_package_marker(
    package: PackageMarkerProjection,
) -> PackageExclusionResponse:
    return PackageExclusionResponse(
        data=PackageExclusionPackage.model_validate(
            {
                "package_name": package.package_name,
                "actionable": package.actionable,
                "non_actionable_reason": _lower(package.non_actionable_reason),
            }
        )
    )


def _serialize_track_marker(track: TrackMarkerProjection) -> TrackExclusionResponse:
    return TrackExclusionResponse(
        data=TrackExclusionTrack.model_validate(
            {
                "reference": track.reference,
                "actionable": track.actionable,
                "non_actionable_reason": _lower(track.non_actionable_reason),
            }
        )
    )


def _serialize_product_marker(
    product: ProductMarkerProjection,
) -> ProductExclusionResponse:
    return ProductExclusionResponse(
        data=ProductExclusionProduct.model_validate(
            {
                "id": product.id,
                "product_cpe": product.product_cpe,
                "product_name": product.product_name,
                "actionable": product.actionable,
                "non_actionable_reason": _lower(product.non_actionable_reason),
            }
        )
    )


_TICKET_NOT_FOUND_DESCRIPTION = (
    "`TICKET_NOT_FOUND`: Ticket identifier is malformed, does not exist, or "
    "identifies a Ticket inaccessible to the caller."
)
_NOT_MUTABLE_RESPONSE: dict[str, Any] = {
    "model": ErrorResponse,
    "description": "`TICKET_NOT_MUTABLE`: the Ticket is Ignored or Duplicated.",
}


def _exclude_responses(level: str, path: str) -> dict[int | str, dict[str, Any]]:
    return {
        404: {
            "model": ErrorResponse,
            "description": (
                f"{_TICKET_NOT_FOUND_DESCRIPTION} `RESOURCE_NOT_FOUND`: the {path} "
                "does not exist under the declared path."
            ),
        },
        409: {
            "model": ErrorResponse,
            "description": (
                f"`PACKAGE_ALREADY_EXCLUDED`: the {level} is already directly "
                "excluded. `TICKET_NOT_MUTABLE`: the Ticket is Ignored or "
                "Duplicated."
            ),
        },
    }


def _restore_responses(level: str, path: str) -> dict[int | str, dict[str, Any]]:
    return {
        404: {
            "model": ErrorResponse,
            "description": (
                f"{_TICKET_NOT_FOUND_DESCRIPTION} `RESOURCE_NOT_FOUND`: the {path} "
                "does not exist under the declared path."
            ),
        },
        409: _NOT_MUTABLE_RESPONSE,
        422: {
            "model": ErrorResponse,
            "description": (
                f"`PACKAGE_NOT_EXCLUDED`: the {level} is not directly excluded "
                "(an exclusion inherited from an ancestor does not count). "
                "`VALIDATION_ERROR`: a nested identifier is not a UUID."
            ),
        },
    }


ManagePackagesPrincipal = Annotated[
    AuthenticatedPrincipal, Depends(require_capability(Capability.MANAGE_PACKAGES))
]
AccessibleTicket = Annotated[ResolvedTicket, Depends(require_accessible_ticket)]

_SHARED_BEHAVIOR = (
    "Requires `manage_packages`. Changes only this record's direct marker: "
    "ancestors and descendants are never modified. Records one audit event, "
    "auto-assigns an unassigned Ticket to an active vulnerability analyst, and "
    "re-evaluates the Ticket status. The response reports current "
    "actionability, which may remain `false` because of an ancestor exclusion, "
    "end-of-life, or the descendant set."
)


@router.post(
    "/tickets/{ticket_id}/packages/{package_id}/exclude",
    response_model=PackageExclusionResponse,
    summary="Soft-Delete Package from Ticket",
    description=(
        "Directly excludes one package. Its tracks and Products become "
        "effectively excluded without being modified. Excluding the caller's "
        "last included maintained package may remove the caller's access to a "
        f"confidential Ticket after this request. {_SHARED_BEHAVIOR}"
    ),
    responses=_exclude_responses("package", "package"),
)
async def exclude_package(
    package_id: PackageIdPath,
    db: DatabaseSession,
    principal: ManagePackagesPrincipal,
    caller: AuthenticatedTicketCaller,
    ticket: AccessibleTicket,
) -> PackageExclusionResponse:
    """Soft-Delete Package from Ticket — see
    `docs/features/packages/package-model.md`.

    Authorization follows `docs/api-spec.md` (Authorization Chain
    Evaluation Order, flow 3). The handler captures the one workflow UTC
    date shared by reconciliation and the locked-current projection; the
    service revalidates accessibility, operability, nested ownership, and
    the direct-marker guard under the Ticket lock.
    """
    result = await _run_marker_change(
        package_service.soft_delete_ticket_package(
            db,
            ticket_id=ticket.id,
            package_id=package_id,
            acting_user_id=principal.user.id,
            caller=caller,
            evaluation_date=_utc_now().date(),
        )
    )
    return _serialize_package_marker(result.target)


@router.post(
    "/tickets/{ticket_id}/packages/{package_id}/restore",
    response_model=PackageExclusionResponse,
    summary="Restore Package",
    description=(
        "Restores one directly excluded package. Child markers are not "
        "modified, so the package may remain non-actionable "
        "(`no_actionable_tracks`). Restoring a maintained package reactivates "
        f"maintainer visibility. {_SHARED_BEHAVIOR}"
    ),
    responses=_restore_responses("package", "package"),
)
async def restore_package(
    package_id: PackageIdPath,
    db: DatabaseSession,
    principal: ManagePackagesPrincipal,
    caller: AuthenticatedTicketCaller,
    ticket: AccessibleTicket,
) -> PackageExclusionResponse:
    """Restore Package — see `docs/features/packages/package-model.md`."""
    result = await _run_marker_change(
        package_service.restore_ticket_package(
            db,
            ticket_id=ticket.id,
            package_id=package_id,
            acting_user_id=principal.user.id,
            caller=caller,
            evaluation_date=_utc_now().date(),
        )
    )
    return _serialize_package_marker(result.target)


@router.post(
    "/tickets/{ticket_id}/packages/{package_id}/tracks/{track_id}/exclude",
    response_model=TrackExclusionResponse,
    summary="Soft-Delete Track",
    description=(
        "Directly excludes one track, also beneath an excluded package (the "
        "response reason is then `package_excluded`). Its Products become "
        f"effectively excluded without being modified. {_SHARED_BEHAVIOR}"
    ),
    responses=_exclude_responses("track", "package or track"),
)
async def exclude_track(
    package_id: PackageIdPath,
    track_id: TrackIdPath,
    db: DatabaseSession,
    principal: ManagePackagesPrincipal,
    caller: AuthenticatedTicketCaller,
    ticket: AccessibleTicket,
) -> TrackExclusionResponse:
    """Soft-Delete Track — see `docs/features/packages/package-model.md`."""
    result = await _run_marker_change(
        package_service.soft_delete_ticket_package_track(
            db,
            ticket_id=ticket.id,
            package_id=package_id,
            track_id=track_id,
            acting_user_id=principal.user.id,
            caller=caller,
            evaluation_date=_utc_now().date(),
        )
    )
    return _serialize_track_marker(result.target)


@router.post(
    "/tickets/{ticket_id}/packages/{package_id}/tracks/{track_id}/restore",
    response_model=TrackExclusionResponse,
    summary="Restore Track",
    description=(
        "Restores one directly excluded track. Product markers are not "
        "modified, so the track may remain non-actionable "
        f"(`no_actionable_products`). {_SHARED_BEHAVIOR}"
    ),
    responses=_restore_responses("track", "package or track"),
)
async def restore_track(
    package_id: PackageIdPath,
    track_id: TrackIdPath,
    db: DatabaseSession,
    principal: ManagePackagesPrincipal,
    caller: AuthenticatedTicketCaller,
    ticket: AccessibleTicket,
) -> TrackExclusionResponse:
    """Restore Track — see `docs/features/packages/package-model.md`."""
    result = await _run_marker_change(
        package_service.restore_ticket_package_track(
            db,
            ticket_id=ticket.id,
            package_id=package_id,
            track_id=track_id,
            acting_user_id=principal.user.id,
            caller=caller,
            evaluation_date=_utc_now().date(),
        )
    )
    return _serialize_track_marker(result.target)


@router.post(
    "/tickets/{ticket_id}/packages/{package_id}/tracks/{track_id}"
    "/products/{ticket_package_product_id}/exclude",
    response_model=ProductExclusionResponse,
    summary="Soft-Delete Product",
    description=(
        "Directly excludes one Product occurrence, also beneath an excluded "
        "package or track and while the Product is end-of-life (ancestor "
        "reasons take precedence over `product_excluded`, which takes "
        f"precedence over `eol`). {_SHARED_BEHAVIOR}"
    ),
    responses=_exclude_responses("Product", "package, track, or Product occurrence"),
)
async def exclude_product(
    package_id: PackageIdPath,
    track_id: TrackIdPath,
    ticket_package_product_id: ProductOccurrenceIdPath,
    db: DatabaseSession,
    principal: ManagePackagesPrincipal,
    caller: AuthenticatedTicketCaller,
    ticket: AccessibleTicket,
) -> ProductExclusionResponse:
    """Soft-Delete Product — see `docs/features/packages/package-model.md`."""
    result = await _run_marker_change(
        package_service.soft_delete_ticket_package_product(
            db,
            ticket_id=ticket.id,
            package_id=package_id,
            track_id=track_id,
            ticket_package_product_id=ticket_package_product_id,
            acting_user_id=principal.user.id,
            caller=caller,
            evaluation_date=_utc_now().date(),
        )
    )
    return _serialize_product_marker(result.target)


@router.post(
    "/tickets/{ticket_id}/packages/{package_id}/tracks/{track_id}"
    "/products/{ticket_package_product_id}/restore",
    response_model=ProductExclusionResponse,
    summary="Restore Product",
    description=(
        "Restores one directly excluded Product occurrence. No ancestor or "
        "lifecycle pre-check applies, so the Product may remain non-actionable "
        f"(for example `eol`). {_SHARED_BEHAVIOR}"
    ),
    responses=_restore_responses("Product", "package, track, or Product occurrence"),
)
async def restore_product(
    package_id: PackageIdPath,
    track_id: TrackIdPath,
    ticket_package_product_id: ProductOccurrenceIdPath,
    db: DatabaseSession,
    principal: ManagePackagesPrincipal,
    caller: AuthenticatedTicketCaller,
    ticket: AccessibleTicket,
) -> ProductExclusionResponse:
    """Restore Product — see `docs/features/packages/package-model.md`."""
    result = await _run_marker_change(
        package_service.restore_ticket_package_product(
            db,
            ticket_id=ticket.id,
            package_id=package_id,
            track_id=track_id,
            ticket_package_product_id=ticket_package_product_id,
            acting_user_id=principal.user.id,
            caller=caller,
            evaluation_date=_utc_now().date(),
        )
    )
    return _serialize_product_marker(result.target)


# ---------------------------------------------------------------------------
# Add Package to Ticket
# ---------------------------------------------------------------------------


async def get_package_addition_http_client() -> AsyncIterator[httpx.AsyncClient]:
    """Provide the request's one shared-factory SMELT HTTP client.

    `add_package_to_ticket()` performs both SMELT requests of the request
    with this client (`docs/features/platform/networking.md`, Shared HTTP
    Client, Non-Fetcher Components). `function`-scoped so the client is
    closed before the response is transmitted. Overridable via
    `app.dependency_overrides` so tests can serve SMELT in-process.
    """
    async with create_http_client(package_service.HTTP_CLIENT_NAME) as client:
        yield client


PackageAdditionHttpClient = Annotated[
    httpx.AsyncClient, Depends(get_package_addition_http_client, scope="function")
]


def _package_addition_error(status_code: int, code: ErrorCode, detail: str) -> AppError:
    return AppError(status_code=status_code, code=code, detail=detail)


@router.post(
    "/tickets/{ticket_id}/packages",
    status_code=http_status.HTTP_201_CREATED,
    response_model=PackageAdditionResponse,
    summary="Add Package to Ticket",
    description=(
        "Adds a source package to a Ticket. Sentinel resolves every currently "
        "maintained track and Product of the package through SMELT, matches "
        "the Products against the current Product catalog snapshot, acquires "
        "package-wide maintainership, and creates the missing package, track, "
        "and Product records. Existing records, included or excluded, are "
        "skipped, so a repeated request is safe and reports zero created "
        "records. An effective addition records a `package_added` event, "
        "auto-assigns an unassigned Ticket to an active vulnerability "
        "analyst, and re-evaluates the Ticket status. Requires "
        "`manage_packages`. Error rows are not ordered by status: the "
        "endpoint applies, in order, Ticket accessibility, SMELT "
        "availability, catalog readiness, package-not-found, "
        "target resolution, then the locked Ticket checks (accessibility, "
        "`TICKET_NOT_MUTABLE`, `PACKAGE_ALREADY_EXCLUDED`)."
    ),
    responses={
        404: {
            "model": ErrorResponse,
            "description": _TICKET_NOT_FOUND_DESCRIPTION,
        },
        409: {
            "model": ErrorResponse,
            "description": (
                "`PACKAGE_ALREADY_EXCLUDED`: the package exists on this Ticket "
                "but is directly excluded; use the restore endpoint. "
                "`TICKET_NOT_MUTABLE`: the Ticket is Ignored or Duplicated."
            ),
        },
        422: {
            "model": ErrorResponse,
            "description": (
                "`PACKAGE_NOT_FOUND_IN_SMELT`: SMELT maintains no codestream "
                "for the package. `PACKAGE_TARGETS_UNRESOLVED`: SMELT returned "
                "codestreams, but no target of a supported codestream matches a "
                "Product of the current catalog snapshot. `VALIDATION_ERROR`: "
                "the request body is invalid."
            ),
        },
        503: {
            "model": ErrorResponse,
            "description": (
                "`SMELT_UNAVAILABLE`: SMELT did not produce a valid successful "
                "response. `PRODUCT_CATALOG_NOT_READY`: no complete SMELT "
                "Product catalog snapshot has been published yet."
            ),
        },
    },
)
async def add_ticket_package(
    body: PackageAdditionRequest,
    db: DatabaseSession,
    principal: ManagePackagesPrincipal,
    caller: AuthenticatedTicketCaller,
    ticket: AccessibleTicket,
    http_client: PackageAdditionHttpClient,
) -> PackageAdditionResponse:
    """Add Package to Ticket — see `docs/features/packages/package-model.md`.

    Authorization follows `docs/api-spec.md` (Authorization Chain
    Evaluation Order, flow 4): authentication, then `manage_packages`
    before any lookup, then the delegated preliminary SNTL resolution.
    The service repeats the lock-free preliminary check before the SMELT
    I/O and re-evaluates accessibility under the Ticket lock afterwards.
    The handler passes the authenticated actor and caller with public-add
    semantics and performs no package lookup; a `Resolved` regression it
    causes is published after commit by the API convergence drain.
    """
    try:
        result = await package_service.add_package_to_ticket(
            db,
            ticket_id=ticket.id,
            package_name=body.package_name,
            acting_user_id=principal.user.id,
            caller=caller,
            http_client=http_client,
        )
    except TicketNotFoundError:
        raise ticket_not_found_error() from None
    except TicketNotMutableError:
        raise ticket_not_mutable_error() from None
    except PackageAlreadyExcludedError:
        raise _package_addition_error(
            http_status.HTTP_409_CONFLICT,
            ErrorCode.PACKAGE_ALREADY_EXCLUDED,
            "Package is excluded from this Ticket; restore it instead.",
        ) from None
    except PackageNotFoundInSmeltError:
        raise _package_addition_error(
            http_status.HTTP_422_UNPROCESSABLE_CONTENT,
            ErrorCode.PACKAGE_NOT_FOUND_IN_SMELT,
            "Package not found in SMELT.",
        ) from None
    except PackageTargetsUnresolvedError:
        raise _package_addition_error(
            http_status.HTTP_422_UNPROCESSABLE_CONTENT,
            ErrorCode.PACKAGE_TARGETS_UNRESOLVED,
            "No package target resolves to a current catalog Product.",
        ) from None
    except ProductCatalogNotReadyError:
        raise _package_addition_error(
            http_status.HTTP_503_SERVICE_UNAVAILABLE,
            ErrorCode.PRODUCT_CATALOG_NOT_READY,
            "Product catalog is not ready.",
        ) from None
    except SmeltUnavailableError:
        raise _package_addition_error(
            http_status.HTTP_503_SERVICE_UNAVAILABLE,
            ErrorCode.SMELT_UNAVAILABLE,
            "SMELT is unavailable.",
        ) from None
    return PackageAdditionResponse(
        data=PackageAdditionResult(
            package_name=body.package_name,
            tracks_created=result.tracks_created,
            tracks_skipped=result.tracks_skipped,
            products_created=result.products_created,
            products_skipped=result.products_skipped,
        )
    )
