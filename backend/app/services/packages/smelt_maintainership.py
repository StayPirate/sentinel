"""Validated retrieval of SMELT package maintainership emails.

Implements docs/features/packages/package-maintainership.md (SMELT
Contract; Email Extraction; Security and Privacy) as the external phase of
`add_package_to_ticket()` step 7 (docs/features/packages/package-service.md):
one anonymous, non-paginated GET of
`experimental/v2/packages/{package_name}/maintainership` built from the
validated `SMELT_API_URL`, with no query, no codestream filter, and no
redirect following.

The response is validated whole with strict models before any email is
read, so a malformed consumed structure never yields a partial grant. The
result is the lowercase, globally deduplicated set of non-null direct-user
and group-member emails. Every missing or invalid result is converted into
an empty set plus exactly one PII-free
`package_maintainership_acquisition_unavailable` WARNING whose category
follows one deterministic precedence (first matching row wins):

1. `transport`: no HTTP response after the shared transport retries;
2. `http_status`: any status other than 200 and 404 (body not read);
3. `package_missing`: 404 with a valid JSend error envelope;
4. `envelope`: 404 with any other body;
5. `envelope`: 200 with invalid JSON, a non-object body, or a JSend
   `status` other than `success`;
6. `schema`: 200 `success` with a malformed consumed structure.

Only those failure classes are caught; programming errors, cancellation,
`SoftTimeLimitExceeded`, and `MemoryError` propagate. The helper performs
network I/O only: it opens no database session and acquires no lock
(§ Module invariant: I/O-then-Lock pattern), so callers must not hold a
Ticket lock or an open transaction while awaiting it.
"""

from __future__ import annotations

import json
from typing import Any, Literal
from urllib.parse import quote
from uuid import UUID

import httpx
import structlog
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from app.config import settings
from app.core.external_strings import NulFreeStr
from app.services.http_client import INFRA_FAILURE_TYPES

logger = structlog.get_logger(__name__)

ACQUISITION_UNAVAILABLE_EVENT = "package_maintainership_acquisition_unavailable"

MaintainershipFailureCategory = Literal[
    "transport", "http_status", "package_missing", "envelope", "schema"
]

_NOT_A_PATH_SEGMENT = frozenset({"", ".", ".."})
_CREDENTIAL_HEADERS = ("authorization", "cookie")


class _Person(BaseModel):
    """A direct user or group member; only `email` is consumed.

    An `email` containing U+0000 is a schema failure (External String
    Admissibility): the normalized email is a `User.email` query parameter.
    """

    model_config = ConfigDict(strict=True, extra="ignore", frozen=True)

    email: NulFreeStr | None = None


class _Group(BaseModel):
    """A maintainer group; only `members` is traversed."""

    model_config = ConfigDict(strict=True, extra="ignore", frozen=True)

    members: list[_Person] = Field(default_factory=list)


class _Entry(BaseModel):
    """One maintainership entry; the codestream is checked as an object only."""

    model_config = ConfigDict(strict=True, extra="ignore", frozen=True)

    codestream: dict[str, Any]
    users: list[_Person]
    groups: list[_Group]


class _SuccessEnvelope(BaseModel):
    """The `data` of a JSend success envelope (`status` checked before)."""

    model_config = ConfigDict(strict=True, extra="ignore", frozen=True)

    data: list[_Entry]


class _UnavailableError(Exception):
    """Internal signal: the result is invalid for one bounded category."""

    def __init__(
        self,
        category: MaintainershipFailureCategory,
        *,
        status_code: int | None = None,
        error_type: str | None = None,
    ) -> None:
        super().__init__(category)
        self.category = category
        self.status_code = status_code
        self.error_type = error_type


def maintainership_url(api_url: str, package_name: str) -> str:
    """Return the maintainership URL for a canonical `SMELT_API_URL`.

    The package name is percent-encoded into exactly one path segment.
    A name that cannot form one segment (empty, `.`, or `..`, which HTTP
    path normalization would remove) is a caller-contract violation and
    raises `ValueError`.
    """
    if package_name in _NOT_A_PATH_SEGMENT:
        msg = "package_name cannot form a single URL path segment"
        raise ValueError(msg)
    encoded = quote(package_name, safe="")
    return f"{api_url}/experimental/v2/packages/{encoded}/maintainership"


async def fetch_package_maintainer_emails(
    client: httpx.AsyncClient, *, ticket_id: UUID, package_name: str
) -> frozenset[str]:
    """Return the validated maintainer emails of `package_name` from SMELT.

    `client` is the caller's shared HTTP client (one lifetime per
    orchestrating invocation); `ticket_id` is the internal Ticket UUID,
    used only as log context. Returns the lowercase, globally deduplicated
    set of non-null `users[].email` and `groups[].members[].email` values.
    A valid response without such emails returns an empty set silently;
    every missing or invalid result returns an empty set after one
    sanitized warning.
    """
    url = maintainership_url(settings.smelt_api_url, package_name)
    try:
        envelope = await _fetch_envelope(client, url)
    except _UnavailableError as unavailable:
        _warn(unavailable, ticket_id=ticket_id, package_name=package_name)
        return frozenset()
    return frozenset(
        person.email.lower()
        for entry in envelope.data
        for person in (
            *entry.users,
            *(member for group in entry.groups for member in group.members),
        )
        if person.email is not None
    )


async def _fetch_envelope(client: httpx.AsyncClient, url: str) -> _SuccessEnvelope:
    """Request `url` and return the validated success envelope.

    The request is anonymous and never follows a redirect, whatever the
    injected client's defaults: client authentication is disabled and any
    default credential or cookie header is removed.
    """
    request = client.build_request("GET", url)
    for header in _CREDENTIAL_HEADERS:
        request.headers.pop(header, None)
    try:
        response = await client.send(
            request, auth=None, stream=True, follow_redirects=False
        )
    except INFRA_FAILURE_TYPES as exc:
        raise _UnavailableError("transport", error_type=type(exc).__name__) from None
    try:
        status_code = response.status_code
        if status_code not in (200, 404):
            raise _UnavailableError("http_status", status_code=status_code)
        body = await _read_json(response)
    finally:
        await response.aclose()

    if status_code == 404:
        if _is_jsend_error(body):
            raise _UnavailableError("package_missing", status_code=status_code)
        raise _UnavailableError("envelope", status_code=status_code)

    if not isinstance(body, dict) or body.get("status") != "success":
        raise _UnavailableError("envelope", status_code=status_code)
    try:
        return _SuccessEnvelope.model_validate(body)
    except ValidationError:
        # Raised from None: the validation error renders input values.
        raise _UnavailableError("schema", status_code=status_code) from None


async def _read_json(response: httpx.Response) -> Any:
    """Read and decode a 200 or 404 body; undecodable bodies are `envelope`."""
    status_code = response.status_code
    try:
        content = await response.aread()
    except INFRA_FAILURE_TYPES as exc:
        raise _UnavailableError(
            "transport", status_code=status_code, error_type=type(exc).__name__
        ) from None
    except httpx.DecodingError as exc:
        raise _UnavailableError(
            "envelope", status_code=status_code, error_type=type(exc).__name__
        ) from None
    try:
        return json.loads(content)
    except (ValueError, RecursionError) as exc:
        # ValueError covers JSONDecodeError and UnicodeDecodeError;
        # RecursionError covers pathologically nested untrusted JSON.
        raise _UnavailableError(
            "envelope", status_code=status_code, error_type=type(exc).__name__
        ) from None


def _is_jsend_error(body: Any) -> bool:
    return (
        isinstance(body, dict)
        and body.get("status") == "error"
        and isinstance(body.get("data"), str)
    )


def _warn(
    unavailable: _UnavailableError, *, ticket_id: UUID, package_name: str
) -> None:
    fields: dict[str, Any] = {
        "ticket_id": str(ticket_id),
        "package_name": package_name,
        "category": unavailable.category,
    }
    if unavailable.status_code is not None:
        fields["status_code"] = unavailable.status_code
    if unavailable.error_type is not None:
        fields["error_type"] = unavailable.error_type
    logger.warning(ACQUISITION_UNAVAILABLE_EVENT, **fields)
