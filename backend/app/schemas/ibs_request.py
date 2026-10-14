"""Response schemas for the Ticket submission and release request lists.

See `docs/features/packages/ibs-submission-tracking.md` (List Submission
Requests, List Release Requests) for the authoritative item schemas. Each
item is one distinct correlated IBS request action with its parent
request. No author, actor, comment, description, raw source or target
field, acceptinfo, RabbitMQ metadata, or local row timestamp is exposed.
Timestamps are UTC.
"""

from __future__ import annotations

from datetime import datetime
from typing import Final, Literal
from uuid import UUID

from pydantic import BaseModel, Field

from app.schemas.common import PaginationMeta

type IBSRequestStateValue = Literal[
    "new", "review", "accepted", "declined", "revoked", "superseded", "deleted"
]
"""Wire values of `IBSRequestState`: the exact current IBS request state."""

_ID: Final = "Local identifier of the request action; the stable identity of this item."
_REQUEST_NUMBER: Final = "Public IBS request number."
_STATE: Final = (
    "Exact current state of the IBS request: `new`, `review`, `accepted`, "
    "`declined`, `revoked`, `superseded`, or `deleted`."
)
_SUPERSEDED_BY: Final = (
    "Request number of the successor when `state` is `superseded`; otherwise `null`."
)
_PACKAGE_NAME: Final = "Logical source package of the action."
_IBS_URL: Final = "IBS web link of the request."
_UPSTREAM_CREATED_AT: Final = "Time (UTC) IBS created the request."
_UPSTREAM_UPDATED_AT: Final = "Time (UTC) of the current IBS request state."


class SubmissionRequestItem(BaseModel):
    """One correlated submission (`maintenance_incident`) action."""

    id: UUID = Field(description=_ID)
    action_type: Literal["maintenance_incident"] = Field(
        description="Action classification: always `maintenance_incident`."
    )
    request_number: int = Field(description=_REQUEST_NUMBER, examples=[410001])
    state: IBSRequestStateValue = Field(description=_STATE)
    superseded_by_request_number: int | None = Field(description=_SUPERSEDED_BY)
    package_name: str = Field(description=_PACKAGE_NAME)
    codestream_name: str = Field(
        description="IBS codestream (track reference) the submission targets.",
        examples=["SUSE:SLE-15-SP6:Update"],
    )
    incident_number: int | None = Field(
        description=(
            "Maintenance incident the submission created or updated; `null` "
            "until IBS establishes it."
        ),
        examples=[45001],
    )
    ibs_url: str = Field(description=_IBS_URL)
    incident_url: str | None = Field(
        description="IBS web link of the incident project; `null` without an incident."
    )
    upstream_created_at: datetime = Field(description=_UPSTREAM_CREATED_AT)
    upstream_updated_at: datetime = Field(description=_UPSTREAM_UPDATED_AT)


class ReleaseRequestItem(BaseModel):
    """One correlated release (`maintenance_release`) action."""

    id: UUID = Field(description=_ID)
    action_type: Literal["maintenance_release"] = Field(
        description="Action classification: always `maintenance_release`."
    )
    request_number: int = Field(description=_REQUEST_NUMBER, examples=[410101])
    state: IBSRequestStateValue = Field(description=_STATE)
    superseded_by_request_number: int | None = Field(description=_SUPERSEDED_BY)
    package_name: str = Field(description=_PACKAGE_NAME)
    codestream_name: str = Field(
        description="IBS codestream the release targets.",
        examples=["SUSE:SLE-15-SP6:Update"],
    )
    incident_number: int = Field(
        description="Maintenance incident the release delivers.", examples=[45001]
    )
    ibs_url: str = Field(description=_IBS_URL)
    incident_url: str = Field(description="IBS web link of the incident project.")
    upstream_created_at: datetime = Field(description=_UPSTREAM_CREATED_AT)
    upstream_updated_at: datetime = Field(description=_UPSTREAM_UPDATED_AT)


class SubmissionRequestListResponse(BaseModel):
    """Response body for `GET /api/v1/tickets/{ticket_id}/submission-requests`."""

    data: list[SubmissionRequestItem]
    meta: PaginationMeta


class ReleaseRequestListResponse(BaseModel):
    """Response body for `GET /api/v1/tickets/{ticket_id}/release-requests`."""

    data: list[ReleaseRequestItem]
    meta: PaginationMeta
