"""Ticket reference endpoints.

See `docs/features/tickets/ticket-references.md` (API Endpoints > List
References, Add Reference, Update Reference, Delete Reference) for the
authoritative endpoint contracts.

Handlers stay thin. The read delegates its single visibility-constrained
selection to `reference_service` (`docs/api-spec.md`, Authorization
Chain Evaluation Order, flow 1). Each mutation checks `manage_references`
before any resource lookup and lets the service lock the Ticket and
revalidate accessibility under the lock (flow 3), so there is no
preliminary accessibility dependency. The mutations are explicit
manual-zone exceptions and never produce `TICKET_NOT_MUTABLE`.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Annotated, Final
from uuid import UUID

from fastapi import APIRouter, Depends, Path, Query, Response, status

from app.api.dependencies import (
    AuthenticatedPrincipal,
    AuthenticatedTicketCaller,
    OptionalTicketCaller,
    TicketIdPath,
    require_capability,
    resource_not_found_error,
    ticket_not_found_error,
)
from app.core.enums import Capability, ReferenceType
from app.core.errors import AppError, ErrorCode
from app.core.exceptions import TicketNotFoundError
from app.database import DatabaseSession
from app.schemas.errors import ErrorResponse
from app.schemas.ticket_reference import (
    TicketReferenceCreate,
    TicketReferenceDataResponse,
    TicketReferenceListResponse,
    TicketReferenceResponse,
    TicketReferenceUpdate,
)
from app.services import reference_service
from app.services.reference_service import (
    UNSET,
    ManualReferenceCreateInput,
    ManualReferenceUpdateInput,
    ReferenceConflictError,
    ReferenceNotEditableError,
    ReferenceNotFoundError,
    TicketReferenceProjection,
)

router = APIRouter(prefix="/api/v1", tags=["Ticket References"])

ReferenceIdPath = Annotated[
    UUID, Path(description="Reference identifier, resolved under its path Ticket.")
]

ManageReferencesPrincipal = Annotated[
    AuthenticatedPrincipal, Depends(require_capability(Capability.MANAGE_REFERENCES))
]

# Wire value -> filter member (`docs/api-spec.md`, Enum Filter Validation).
_TYPE_FILTER: Final[Mapping[str, ReferenceType]] = {
    member.value: member for member in ReferenceType
}

_TICKET_NOT_FOUND_DESCRIPTION: Final = (
    "`TICKET_NOT_FOUND`: Ticket identifier is malformed, does not exist, or "
    "identifies a Ticket inaccessible to the caller."
)
_REFERENCE_NOT_FOUND_DESCRIPTION: Final = (
    "`RESOURCE_NOT_FOUND`: the reference does not exist under this Ticket."
)
_NOT_EDITABLE_DESCRIPTION: Final = (
    "`RESOURCE_NOT_EDITABLE`: the reference is automatic (owned by a CVE fetcher)."
)
_CONFLICT_DESCRIPTION: Final = (
    "`RESOURCE_CONFLICT`: another reference already uses the normalized URL on "
    "this Ticket."
)
_MANUAL_ZONE_NOTE: Final = (
    "Valid in every Ticket status, including `ignored` and `duplicated`; it never "
    "assigns the Ticket, changes its status, or re-evaluates its workflow. "
    "Requires `manage_references`."
)


def resource_not_editable_error() -> AppError:
    """`409 RESOURCE_NOT_EDITABLE` (ticket-references.md, Service Exceptions)."""
    return AppError(
        status_code=status.HTTP_409_CONFLICT,
        code=ErrorCode.RESOURCE_NOT_EDITABLE,
        detail="Reference is not editable.",
    )


def resource_conflict_error() -> AppError:
    """`409 RESOURCE_CONFLICT` (ticket-references.md, Service Exceptions)."""
    return AppError(
        status_code=status.HTTP_409_CONFLICT,
        code=ErrorCode.RESOURCE_CONFLICT,
        detail="Another reference already uses this URL on the Ticket.",
    )


def serialize_reference(
    projection: TicketReferenceProjection,
) -> TicketReferenceResponse:
    """Map a service projection to `TicketReferenceResponse`."""
    return TicketReferenceResponse(
        id=projection.id,
        ticket_id=projection.ticket_id,
        url=projection.url,
        title=projection.title,
        description=projection.description,
        type=None if projection.type is None else projection.type.value,
        source=projection.source,
        created_at=projection.created_at,
        updated_at=projection.updated_at,
    )


@router.get(
    "/tickets/{ticket_id}/references",
    response_model=TicketReferenceListResponse,
    summary="List References",
    description=(
        "Returns every automatic and manual reference of a Ticket visible to the "
        "caller, unpaginated, ordered by type (`advisory`, `patch`, `issue`, "
        "`article`, uncategorized), then creation time, then identifier. "
        "`source` and `type` filters combine with AND; an invalid `type` value "
        "returns an empty list for an accessible Ticket. Anonymous callers see "
        "references of non-confidential Tickets only."
    ),
    responses={
        404: {"model": ErrorResponse, "description": _TICKET_NOT_FOUND_DESCRIPTION}
    },
)
async def list_references(
    ticket_id: TicketIdPath,
    db: DatabaseSession,
    caller: OptionalTicketCaller,
    source: Annotated[
        str | None,
        Query(description="Exact, case-sensitive source (`manual` or a fetcher name)."),
    ] = None,
    reference_type: Annotated[
        str | None,
        Query(
            alias="type",
            description=(
                "One of `advisory`, `patch`, `issue`, or `article`. Any other value "
                "matches no reference."
            ),
        ),
    ] = None,
) -> TicketReferenceListResponse:
    """List References — see `docs/features/tickets/ticket-references.md`.

    An invalid `type` is removed at this boundary and signalled as
    `type_was_supplied` with no value, so the service still applies parent
    accessibility before returning the empty list.
    """
    try:
        references = await reference_service.list_references(
            db,
            ticket_id,
            caller,
            source=source,
            type=None if reference_type is None else _TYPE_FILTER.get(reference_type),
            type_was_supplied=reference_type is not None,
        )
    except TicketNotFoundError:
        raise ticket_not_found_error() from None
    return TicketReferenceListResponse(
        data=[serialize_reference(reference) for reference in references]
    )


@router.post(
    "/tickets/{ticket_id}/references",
    status_code=status.HTTP_201_CREATED,
    response_model=TicketReferenceDataResponse,
    summary="Add Reference",
    description=(
        "Creates one manual reference. The URL is validated and normalized "
        "without being dereferenced; an omitted `type` is classified from the "
        f"normalized URL. {_MANUAL_ZONE_NOTE}"
    ),
    responses={
        404: {"model": ErrorResponse, "description": _TICKET_NOT_FOUND_DESCRIPTION},
        409: {"model": ErrorResponse, "description": _CONFLICT_DESCRIPTION},
    },
)
async def add_reference(
    ticket_id: TicketIdPath,
    body: TicketReferenceCreate,
    db: DatabaseSession,
    principal: ManageReferencesPrincipal,
    caller: AuthenticatedTicketCaller,
) -> TicketReferenceDataResponse:
    """Add Reference — see `docs/features/tickets/ticket-references.md`."""
    supplied = body.model_fields_set
    input_ = ManualReferenceCreateInput(
        url=body.url,
        title=body.title,
        description=body.description,
        type=(
            UNSET
            if "type" not in supplied
            else (None if body.type is None else ReferenceType(body.type))
        ),
    )
    try:
        projection = await reference_service.create_reference(
            db, ticket_id, caller, input_
        )
    except TicketNotFoundError:
        raise ticket_not_found_error() from None
    except ReferenceConflictError:
        raise resource_conflict_error() from None
    return TicketReferenceDataResponse(data=serialize_reference(projection))


@router.patch(
    "/tickets/{ticket_id}/references/{reference_id}",
    response_model=TicketReferenceDataResponse,
    summary="Update Reference",
    description=(
        "Partially updates one manual reference: omitted fields are preserved "
        "and `null` clears `title`, `description`, or `type`. Changing `url` "
        "without `type` keeps the current type. A request equivalent to the "
        "current state returns it unchanged without recording an event. "
        f"{_MANUAL_ZONE_NOTE}"
    ),
    responses={
        404: {
            "model": ErrorResponse,
            "description": (
                f"{_TICKET_NOT_FOUND_DESCRIPTION} {_REFERENCE_NOT_FOUND_DESCRIPTION}"
            ),
        },
        409: {
            "model": ErrorResponse,
            "description": f"{_NOT_EDITABLE_DESCRIPTION} {_CONFLICT_DESCRIPTION}",
        },
    },
)
async def update_reference(
    ticket_id: TicketIdPath,
    reference_id: ReferenceIdPath,
    body: TicketReferenceUpdate,
    db: DatabaseSession,
    principal: ManageReferencesPrincipal,
    caller: AuthenticatedTicketCaller,
) -> TicketReferenceDataResponse:
    """Update Reference — see `docs/features/tickets/ticket-references.md`."""
    supplied = body.model_fields_set
    input_ = ManualReferenceUpdateInput(
        url=body.url if "url" in supplied and body.url is not None else UNSET,
        title=body.title if "title" in supplied else UNSET,
        description=body.description if "description" in supplied else UNSET,
        type=(
            UNSET
            if "type" not in supplied
            else (None if body.type is None else ReferenceType(body.type))
        ),
    )
    try:
        projection = await reference_service.update_reference(
            db, ticket_id, reference_id, caller, input_
        )
    except TicketNotFoundError:
        raise ticket_not_found_error() from None
    except ReferenceNotFoundError:
        raise resource_not_found_error() from None
    except ReferenceNotEditableError:
        raise resource_not_editable_error() from None
    except ReferenceConflictError:
        raise resource_conflict_error() from None
    return TicketReferenceDataResponse(data=serialize_reference(projection))


@router.delete(
    "/tickets/{ticket_id}/references/{reference_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    response_class=Response,
    summary="Delete Reference",
    description=f"Deletes one manual reference. {_MANUAL_ZONE_NOTE}",
    responses={
        404: {
            "model": ErrorResponse,
            "description": (
                f"{_TICKET_NOT_FOUND_DESCRIPTION} {_REFERENCE_NOT_FOUND_DESCRIPTION}"
            ),
        },
        409: {"model": ErrorResponse, "description": _NOT_EDITABLE_DESCRIPTION},
    },
)
async def delete_reference(
    ticket_id: TicketIdPath,
    reference_id: ReferenceIdPath,
    db: DatabaseSession,
    principal: ManageReferencesPrincipal,
    caller: AuthenticatedTicketCaller,
) -> Response:
    """Delete Reference — see `docs/features/tickets/ticket-references.md`."""
    try:
        await reference_service.delete_reference(db, ticket_id, reference_id, caller)
    except TicketNotFoundError:
        raise ticket_not_found_error() from None
    except ReferenceNotFoundError:
        raise resource_not_found_error() from None
    except ReferenceNotEditableError:
        raise resource_not_editable_error() from None
    return Response(status_code=status.HTTP_204_NO_CONTENT)
