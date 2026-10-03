"""Validated retrieval of a package's SMELT maintained codestreams.

Implements docs/features/packages/package-model.md (SMELT Query for
Package Resolution: Envelope and error handling, Entry validation,
Consumed fields, Single authoritative representation, Processing step 1)
as the external phase of `add_package_to_ticket()` steps 2-3
(docs/features/packages/package-service.md): one anonymous,
non-paginated GET of
`experimental/v2/maintained/{package_name}?include_reactive_ltss=true`
built from the validated `SMELT_API_URL`, with no redirect following. The
paginated maintained sweep operation is never used.

The body of an HTTP 200 or 404 response is parsed and the complete
response is validated before any result is returned:

- only the JSend `status` values `success` and `error` are recognized,
  and only HTTP 200 with `success` and HTTP 404 with a valid `error`
  envelope (string `data`) are valid pairings;
- HTTP 200 `success` with an empty `data` and a valid HTTP 404 are
  *package not found*;
- every entry of a non-empty `data` needs a `codestream` object with a
  non-empty `name` of at most 255 characters, unique across the response,
  and a declared `type`; every `SLFO` and `SLE_15` entry needs a non-empty
  `targets` array whose `product.cpe` values are non-empty strings;
- `SLFO_IBS` and `UNKNOWN` entries are skipped without validating their
  targets, with one WARNING each once the response is accepted.

Any other outcome raises `MaintainedPackageUnavailableError`, which the
caller maps to `SmeltUnavailableError`. Catalog readiness, CPE matching,
and the public error mapping belong to the caller. Every validated
supported record is returned as received: Sentinel applies no
channel/compose deduplication and does not consume `product_definition`.

Only the specified failure classes are converted; programming errors,
cancellation, `SoftTimeLimitExceeded`, and `MemoryError` propagate. The
helper performs network I/O only: it opens no database session and
acquires no lock (package-service.md, Module invariant: I/O-then-Lock
pattern), so callers must not hold a Ticket lock or an open transaction
while awaiting it.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Annotated, Any, Final, Literal
from urllib.parse import quote

import httpx
import structlog
from pydantic import BaseModel, ConfigDict, Field, TypeAdapter, ValidationError

from app.config import settings
from app.core.enums import WorkflowType
from app.services.http_client import INFRA_FAILURE_TYPES

logger = structlog.get_logger(__name__)

UNSUPPORTED_PROCESS_EVENT: Final = "package_codestream_maintenance_process_unsupported"
UNKNOWN_PROCESS_EVENT: Final = "package_codestream_maintenance_process_unknown"

REFERENCE_MAX_LENGTH: Final = 255
"""The persisted `TicketPackageTrack.reference` column length."""

MaintainedUnavailableCategory = Literal[
    "transport", "http_status", "envelope", "schema"
]

_WORKFLOW_TYPES: Final = {"SLFO": WorkflowType.GIT, "SLE_15": WorkflowType.IBS}
_NOT_A_PATH_SEGMENT = frozenset({"", ".", ".."})
_CREDENTIAL_HEADERS = ("authorization", "cookie")


@dataclass(frozen=True, slots=True)
class MaintainedTarget:
    """One Product target; `friendly_name` is `None` when absent or empty."""

    cpe: str
    friendly_name: str | None

    @property
    def log_label(self) -> str:
        """The friendly name for log messages, falling back to the CPE."""
        return self.friendly_name or self.cpe


@dataclass(frozen=True, slots=True)
class MaintainedCodestream:
    """One supported codestream with its mapped workflow and targets."""

    name: str
    workflow_type: WorkflowType
    targets: tuple[MaintainedTarget, ...]


@dataclass(frozen=True, slots=True)
class MaintainedPackage:
    """The validated supported codestreams of a package, in response order.

    Empty when every returned codestream was skipped as unsupported or
    unclassified; that is not *package not found*.
    """

    codestreams: tuple[MaintainedCodestream, ...]


@dataclass(frozen=True, slots=True)
class MaintainedPackageNotFound:
    """SMELT does not maintain the package in any codestream."""


class MaintainedPackageUnavailableError(Exception):
    """SMELT did not produce a valid expected response.

    Carries only a bounded `category`, the HTTP `status_code` when a
    response exists, and the converted exception's class name; never a
    response body, URL, or raw exception text.
    """

    def __init__(
        self,
        category: MaintainedUnavailableCategory,
        *,
        status_code: int | None = None,
        error_type: str | None = None,
    ) -> None:
        super().__init__(category)
        self.category = category
        self.status_code = status_code
        self.error_type = error_type


class _Codestream(BaseModel):
    """The validated codestream identity; `url` is not consumed."""

    model_config = ConfigDict(strict=True, extra="ignore", frozen=True)

    name: str = Field(min_length=1, max_length=REFERENCE_MAX_LENGTH)
    type: Literal["SLFO", "SLFO_IBS", "SLE_15", "UNKNOWN"]


class _Entry(BaseModel):
    """One grouped entry; `targets` is validated only for supported types."""

    model_config = ConfigDict(strict=True, extra="ignore", frozen=True)

    codestream: _Codestream
    targets: Any = None


class _Product(BaseModel):
    """A target Product; `friendly_name` is read leniently afterwards."""

    model_config = ConfigDict(strict=True, extra="ignore", frozen=True)

    cpe: str = Field(min_length=1)
    friendly_name: Any = None


class _Target(BaseModel):
    model_config = ConfigDict(strict=True, extra="ignore", frozen=True)

    product: _Product


class _SuccessData(BaseModel):
    """The `data` of a JSend success envelope (`status` checked before)."""

    model_config = ConfigDict(strict=True, extra="ignore", frozen=True)

    data: list[_Entry]


_SUPPORTED_TARGETS: TypeAdapter[list[_Target]] = TypeAdapter(
    Annotated[list[_Target], Field(min_length=1)]
)


def maintained_package_url(api_url: str, package_name: str) -> str:
    """Return the maintained-package URL for a canonical `SMELT_API_URL`.

    The package name is percent-encoded into exactly one case-preserving
    path segment. A name that cannot form one segment (empty, `.`, or
    `..`, which HTTP path normalization would remove) is a caller-contract
    violation and raises `ValueError`.
    """
    if package_name in _NOT_A_PATH_SEGMENT:
        msg = "package_name cannot form a single URL path segment"
        raise ValueError(msg)
    encoded = quote(package_name, safe="")
    return f"{api_url}/experimental/v2/maintained/{encoded}?include_reactive_ltss=true"


async def fetch_maintained_package(
    client: httpx.AsyncClient, *, package_name: str
) -> MaintainedPackage | MaintainedPackageNotFound:
    """Return the validated SMELT maintained codestreams of `package_name`.

    `client` is the caller's shared HTTP client (one lifetime per
    orchestrating invocation). Raises `MaintainedPackageUnavailableError`
    when SMELT did not produce a valid expected response, and `ValueError`
    before any request when `package_name` cannot form one path segment.
    """
    url = maintained_package_url(settings.smelt_api_url, package_name)
    status_code, body = await _fetch_body(client, url)
    if status_code == 404:
        if _is_jsend_error(body):
            return MaintainedPackageNotFound()
        raise MaintainedPackageUnavailableError("envelope", status_code=status_code)
    if not isinstance(body, dict) or body.get("status") != "success":
        raise MaintainedPackageUnavailableError("envelope", status_code=status_code)
    try:
        entries = _SuccessData.model_validate(body).data
    except ValidationError:
        # Raised from None: the validation error renders input values.
        raise MaintainedPackageUnavailableError(
            "schema", status_code=status_code
        ) from None
    if not entries:
        return MaintainedPackageNotFound()
    codestreams = _validate_entries(entries, status_code=status_code)
    _warn_skipped(entries, package_name=package_name)
    return MaintainedPackage(codestreams=codestreams)


async def _fetch_body(client: httpx.AsyncClient, url: str) -> tuple[int, Any]:
    """Request `url` and return the status code and decoded 200/404 body.

    The request is anonymous and never follows a redirect, whatever the
    injected client's defaults: client authentication is disabled and any
    default credential or cookie header is removed. Any status other than
    200 and 404 is unavailable without reading the body.
    """
    request = client.build_request("GET", url)
    for header in _CREDENTIAL_HEADERS:
        request.headers.pop(header, None)
    try:
        response = await client.send(
            request, auth=None, stream=True, follow_redirects=False
        )
    except INFRA_FAILURE_TYPES as exc:
        raise MaintainedPackageUnavailableError(
            "transport", error_type=type(exc).__name__
        ) from None
    try:
        status_code = response.status_code
        if status_code not in (200, 404):
            raise MaintainedPackageUnavailableError(
                "http_status", status_code=status_code
            )
        body = await _read_json(response)
    finally:
        await response.aclose()
    return status_code, body


async def _read_json(response: httpx.Response) -> Any:
    """Read and decode a 200 or 404 body; undecodable bodies are `envelope`."""
    status_code = response.status_code
    try:
        content = await response.aread()
    except INFRA_FAILURE_TYPES as exc:
        raise MaintainedPackageUnavailableError(
            "transport", status_code=status_code, error_type=type(exc).__name__
        ) from None
    except httpx.DecodingError as exc:
        raise MaintainedPackageUnavailableError(
            "envelope", status_code=status_code, error_type=type(exc).__name__
        ) from None
    try:
        return json.loads(content)
    except (ValueError, RecursionError) as exc:
        # ValueError covers JSONDecodeError and UnicodeDecodeError;
        # RecursionError covers pathologically nested untrusted JSON.
        raise MaintainedPackageUnavailableError(
            "envelope", status_code=status_code, error_type=type(exc).__name__
        ) from None


def _is_jsend_error(body: Any) -> bool:
    return (
        isinstance(body, dict)
        and body.get("status") == "error"
        and isinstance(body.get("data"), str)
    )


def _validate_entries(
    entries: list[_Entry], *, status_code: int
) -> tuple[MaintainedCodestream, ...]:
    """Validate the whole response and map its supported codestreams.

    Codestream names are unique across every entry, including skipped
    ones; any violation rejects the complete response.
    """
    names = [entry.codestream.name for entry in entries]
    if len(set(names)) != len(names):
        raise MaintainedPackageUnavailableError("schema", status_code=status_code)
    codestreams: list[MaintainedCodestream] = []
    for entry in entries:
        workflow_type = _WORKFLOW_TYPES.get(entry.codestream.type)
        if workflow_type is None:
            continue
        try:
            targets = _SUPPORTED_TARGETS.validate_python(entry.targets, strict=True)
        except ValidationError:
            raise MaintainedPackageUnavailableError(
                "schema", status_code=status_code
            ) from None
        codestreams.append(
            MaintainedCodestream(
                name=entry.codestream.name,
                workflow_type=workflow_type,
                targets=tuple(
                    MaintainedTarget(
                        cpe=target.product.cpe,
                        friendly_name=_friendly_name(target.product.friendly_name),
                    )
                    for target in targets
                ),
            )
        )
    return tuple(codestreams)


def _friendly_name(value: Any) -> str | None:
    """A non-empty string, or `None`; the field never rejects a response."""
    return value if isinstance(value, str) and value else None


def _warn_skipped(entries: list[_Entry], *, package_name: str) -> None:
    """Emit one WARNING per skipped codestream of an accepted response."""
    for entry in entries:
        codestream = entry.codestream
        if codestream.type == "SLFO_IBS":
            logger.warning(
                UNSUPPORTED_PROCESS_EVENT,
                package_name=package_name,
                codestream=codestream.name,
                maintenance_process_type=codestream.type,
            )
        elif codestream.type == "UNKNOWN":
            logger.warning(
                UNKNOWN_PROCESS_EVENT,
                package_name=package_name,
                codestream=codestream.name,
            )
