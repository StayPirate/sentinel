"""Request and response schemas for Ticket references.

See `docs/features/tickets/ticket-references.md` (API Schemas:
TicketReferenceCreate, TicketReferenceUpdate, TicketReferenceResponse;
URL Boundary) and `docs/api-spec.md` (Partial Update Semantics) for the
authoritative contracts.

Pydantic owns transport shape, nullability, enum membership, and the
declared string lengths; URLs are validated through the shared Core URL
boundary. The handler distinguishes an omitted field from an explicit
`null` through `model_fields_set`; `reference_service` reruns every
domain check for every caller.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any, Literal, Self
from uuid import UUID

from pydantic import (
    BaseModel,
    Field,
    WithJsonSchema,
    field_validator,
    model_validator,
)

from app.core.reference_urls import MAX_REFERENCE_URL_LENGTH, normalize_reference_url

type ReferenceTypeValue = Literal["advisory", "patch", "issue", "article"]
"""Lowercase wire values of `ReferenceType`; JSON `null` is uncategorized."""

_URL_DESCRIPTION = (
    "Absolute `http` or `https` URL with a valid host and no user information "
    "or control characters, at most 2048 characters before and after "
    "normalization. Stored normalized: scheme and host lowercased, `http` "
    "upgraded to `https`, and only an otherwise empty root path slash removed. "
    "Never dereferenced."
)
_TITLE_DESCRIPTION = (
    "Human-readable label: 1-500 characters, not whitespace-only, not trimmed."
)
_DESCRIPTION_DESCRIPTION = (
    "Editorial context: 1-2000 characters, not whitespace-only, not trimmed."
)


def _validate_url(value: str) -> str:
    # The Core boundary raises a `ValueError` whose message never contains
    # the submitted value. The raw value is kept: the service normalizes it.
    normalize_reference_url(value)
    return value


def _reject_whitespace_only(value: str | None) -> str | None:
    if value is not None and not value.strip():
        raise ValueError("Value must not be whitespace-only.")
    return value


class TicketReferenceCreate(BaseModel):
    """Request body of `POST /api/v1/tickets/{ticket_id}/references`.

    `url` is required and non-nullable. Omitted or `null` `title` and
    `description` persist as `NULL`. An omitted `type` requests
    URL-pattern classification; an explicit `null` stores uncategorized.
    """

    url: str = Field(
        max_length=MAX_REFERENCE_URL_LENGTH,
        description=_URL_DESCRIPTION,
        examples=["https://issues.example.test/tickets/12345"],
    )
    title: str | None = Field(
        default=None,
        min_length=1,
        max_length=500,
        description=f"{_TITLE_DESCRIPTION} Omitted or `null` stores no title.",
    )
    description: str | None = Field(
        default=None,
        min_length=1,
        max_length=2000,
        description=(
            f"{_DESCRIPTION_DESCRIPTION} Omitted or `null` stores no description."
        ),
    )
    type: ReferenceTypeValue | None = Field(
        default=None,
        description=(
            "`advisory`, `patch`, `issue`, or `article`. Omitted: classified from "
            "the normalized URL, or uncategorized when no pattern matches. "
            "`null`: stored uncategorized without classification."
        ),
    )

    _check_url = field_validator("url")(_validate_url)
    _check_text = field_validator("title", "description")(_reject_whitespace_only)


class TicketReferenceUpdate(BaseModel):
    """Request body of `PATCH .../references/{reference_id}`.

    Partial update (`docs/api-spec.md`, Partial Update Semantics): an
    omitted field preserves the current value; `null` clears `title`,
    `description`, or `type`; `url` rejects `null`. An empty object is
    rejected. Changing `url` without `type` preserves the current type.
    """

    # `None` is only the internal "omitted" default: explicit JSON `null` is
    # rejected below, so the published schema is a plain string.
    url: Annotated[
        str | None,
        WithJsonSchema({"type": "string", "maxLength": MAX_REFERENCE_URL_LENGTH}),
    ] = Field(
        default=None,
        max_length=MAX_REFERENCE_URL_LENGTH,
        description=f"{_URL_DESCRIPTION} Omitted preserves; `null` is invalid.",
    )
    title: str | None = Field(
        default=None,
        min_length=1,
        max_length=500,
        description=f"{_TITLE_DESCRIPTION} Omitted preserves; `null` clears.",
    )
    description: str | None = Field(
        default=None,
        min_length=1,
        max_length=2000,
        description=f"{_DESCRIPTION_DESCRIPTION} Omitted preserves; `null` clears.",
    )
    type: ReferenceTypeValue | None = Field(
        default=None,
        description=(
            "`advisory`, `patch`, `issue`, or `article`. Omitted preserves (also "
            "when `url` changes); `null` clears to uncategorized."
        ),
    )

    @field_validator("url", mode="before")
    @classmethod
    def _reject_null_url(cls, value: Any) -> Any:
        if value is None:
            raise ValueError("url cannot be null.")
        return value

    @field_validator("url")
    @classmethod
    def _check_url(cls, value: str | None) -> str | None:
        return None if value is None else _validate_url(value)

    _check_text = field_validator("title", "description")(_reject_whitespace_only)

    @model_validator(mode="after")
    def _require_at_least_one_field(self) -> Self:
        if not self.model_fields_set:
            raise ValueError("At least one field must be provided.")
        return self


class TicketReferenceResponse(BaseModel):
    """One persisted Ticket reference (`TicketReferenceResponse`)."""

    id: UUID = Field(description="Reference identifier.")
    ticket_id: str = Field(description="Canonical Ticket identity (`SNTL-{n}`).")
    url: str = Field(description="Normalized persisted URL.")
    title: str | None = Field(description="Human-readable label, or `null`.")
    description: str | None = Field(description="Editorial context, or `null`.")
    type: ReferenceTypeValue | None = Field(
        description=(
            "`advisory`, `patch`, `issue`, `article`, or `null` (uncategorized)."
        )
    )
    source: str = Field(
        description=(
            "`manual` for consumer-managed references; otherwise the stable name "
            "of the CVE fetcher that owns the reference (not editable)."
        )
    )
    created_at: datetime = Field(description="Creation time (UTC).")
    updated_at: datetime = Field(description="Last effective update time (UTC).")


class TicketReferenceDataResponse(BaseModel):
    """Response body of `POST` and `PATCH` on Ticket references."""

    data: TicketReferenceResponse


class TicketReferenceListResponse(BaseModel):
    """Response body of `GET /api/v1/tickets/{ticket_id}/references`.

    Unpaginated: references are a small Ticket-scoped collection.
    """

    data: list[TicketReferenceResponse]
