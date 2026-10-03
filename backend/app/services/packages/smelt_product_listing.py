"""Validated retrieval of the SMELT `v1/basic/products/` Product listing.

Implements docs/features/packages/product-catalog.md (SMELT Integration >
Origin, Authentication, and Pagination): every page request is built from
the configured HTTPS API prefix with the fixed `page_size` and an explicit
`page`, pages are fetched sequentially and exactly once, `next`/`previous`
are parsed only as consistency metadata (never used as a request
destination), and redirects are never followed. Any transport, HTTP,
pagination, or response-schema failure raises `FetcherError` with the
sanitized messages of § Fetcher: `sync_smelt_products` > Error Handling.

The helper performs network I/O only; callers must not hold an open
database transaction while awaiting it (§ Product Sync, steps 1 and 7).
Logs identify the failed page and category, never the response payload.
"""

from __future__ import annotations

import asyncio
import re
from collections import Counter
from dataclasses import dataclass
from typing import Any, NoReturn
from urllib.parse import parse_qsl, urlsplit

import httpx
import structlog
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from app.services.base_fetcher import FetcherError

logger = structlog.get_logger(__name__)

PRODUCTS_ENDPOINT_PATH = "v1/basic/products/"
PAGE_SIZE = 100

CONNECTION_FAILED_MESSAGE = "Failed to connect to SMELT"
TIMEOUT_MESSAGE = "SMELT request timed out"
INVALID_RESPONSE_MESSAGE = "SMELT returned invalid Product catalog response"

_METADATA_SCHEMES = frozenset({"http", "https"})
_PAGE_VALUE = re.compile(r"[1-9][0-9]*")
_PAGE_PARAMETER = "page"
_PAGE_SIZE_PARAMETER = "page_size"


@dataclass(frozen=True, slots=True)
class SmeltProductListing:
    """The complete, pagination-validated Product listing.

    `results` holds every collected row in page order, unvalidated beyond
    being JSON objects; complete-snapshot validation belongs to the
    caller (§ Product Sync, step 2).
    """

    count: int
    results: list[dict[str, Any]]


@dataclass(frozen=True, slots=True)
class _Origin:
    """The configured origin and the expected endpoint path."""

    hostname: str
    port: int | None
    path: str


class _ProductListingPage(BaseModel):
    """One `v1/basic/products/` page envelope (unknown fields ignored)."""

    model_config = ConfigDict(strict=True, extra="ignore", frozen=True)

    count: int = Field(ge=0)
    total_pages: int = Field(ge=1)
    next: str | None
    previous: str | None
    results: list[dict[str, Any]]


class InvalidProductListingError(Exception):
    """A pagination or response-schema violation on one page.

    The message names the page and the violated rule only; it never
    contains response content, hosts, or URLs.
    """


def products_endpoint_url(api_url: str) -> str:
    """Return the Product listing URL for a canonical `SMELT_API_URL`."""
    return f"{api_url}/{PRODUCTS_ENDPOINT_PATH}"


def _origin(api_url: str) -> _Origin:
    parsed = urlsplit(products_endpoint_url(api_url))
    return _Origin(
        hostname=(parsed.hostname or "").lower(),
        port=parsed.port,
        path=parsed.path,
    )


async def fetch_product_listing(
    client: httpx.AsyncClient, *, api_url: str, request_delay: float
) -> SmeltProductListing:
    """Retrieve and pagination-validate the complete Product listing.

    `api_url` is the validated, canonical `SMELT_API_URL`; `request_delay`
    is the run's configured delay in seconds, applied between page
    requests. Raises `FetcherError` with a sanitized message on any
    failure; no partial listing is ever returned.
    """
    url = products_endpoint_url(api_url)
    origin = _origin(api_url)
    count: int | None = None
    total_pages: int | None = None
    results: list[dict[str, Any]] = []

    page = 1
    while True:
        if page > 1 and request_delay > 0:
            await asyncio.sleep(request_delay)
        data = await _get_page(client, url, page)
        try:
            envelope = _parse_page(data, page)
            if count is None or total_pages is None:
                count, total_pages = envelope.count, envelope.total_pages
            elif (envelope.count, envelope.total_pages) != (count, total_pages):
                _invalid(page, "count or total_pages changed during retrieval")
            _check_page(envelope, page, total_pages, origin)
            # Every non-final page is non-empty, so this also bounds the
            # number of requests by `count`.
            if len(results) + len(envelope.results) > count:
                _invalid(page, "more results than count")
        except InvalidProductListingError as exc:
            _log_invalid(page, exc)
            raise FetcherError(INVALID_RESPONSE_MESSAGE) from exc
        results.extend(envelope.results)
        if page == total_pages:
            break
        page += 1

    if len(results) != count:
        mismatch = InvalidProductListingError(
            f"collected {len(results)} results but count is {count}"
        )
        _log_invalid(page, mismatch)
        raise FetcherError(INVALID_RESPONSE_MESSAGE) from mismatch
    return SmeltProductListing(count=count, results=results)


async def _get_page(client: httpx.AsyncClient, url: str, page: int) -> Any:
    """Request one page and return its decoded JSON body."""
    try:
        response = await client.get(
            url, params={_PAGE_SIZE_PARAMETER: PAGE_SIZE, _PAGE_PARAMETER: page}
        )
    except httpx.TimeoutException as exc:
        logger.warning(
            "smelt_product_catalog_request_failed", page=page, category="timeout"
        )
        raise FetcherError(TIMEOUT_MESSAGE) from exc
    except httpx.DecodingError:
        invalid = InvalidProductListingError(f"page {page}: undecodable body")
        _log_invalid(page, invalid)
        raise FetcherError(INVALID_RESPONSE_MESSAGE) from invalid
    except httpx.RequestError as exc:
        logger.warning(
            "smelt_product_catalog_request_failed", page=page, category="connection"
        )
        raise FetcherError(CONNECTION_FAILED_MESSAGE) from exc

    try:
        response.raise_for_status()
    except httpx.HTTPStatusError as exc:
        status_code = response.status_code
        logger.warning(
            "smelt_product_catalog_request_failed",
            page=page,
            category="http_status",
            status_code=status_code,
        )
        raise FetcherError(f"SMELT returned HTTP {status_code}") from exc

    try:
        return response.json()
    except ValueError:
        invalid = InvalidProductListingError(f"page {page}: body is not valid JSON")
        _log_invalid(page, invalid)
        raise FetcherError(INVALID_RESPONSE_MESSAGE) from invalid


def _parse_page(data: Any, page: int) -> _ProductListingPage:
    try:
        return _ProductListingPage.model_validate(data)
    except ValidationError as exc:
        fields = sorted(
            {str(error["loc"][0]) for error in exc.errors() if error["loc"]}
        )
        detail = ", ".join(fields) if fields else "envelope"
        # Raised from None: the validation error renders input values.
        raise InvalidProductListingError(
            f"page {page}: invalid response schema ({detail})"
        ) from None


def _check_page(
    envelope: _ProductListingPage, page: int, total_pages: int, origin: _Origin
) -> None:
    """Apply pagination rules 3 and 4 to one parsed page."""
    if page == 1:
        if envelope.previous is not None:
            _invalid(page, "previous must be null on page 1")
    else:
        if envelope.previous is None:
            _invalid(page, "previous must not be null after page 1")
        previous_page = _metadata_page(envelope.previous, origin, page, "previous")
        if (previous_page or "1") != str(page - 1):
            _invalid(page, "previous does not designate the adjacent page")

    if page < total_pages:
        if not envelope.results:
            _invalid(page, "non-final page has no results")
        if envelope.next is None:
            _invalid(page, "next must not be null on a non-final page")
        if _metadata_page(envelope.next, origin, page, "next") != str(page + 1):
            _invalid(page, "next does not designate the adjacent page")
    elif envelope.next is not None:
        _invalid(page, "next must be null on the final page")


def _metadata_page(url: str, origin: _Origin, page: int, field: str) -> str | None:
    """Validate one continuation URL; return its page value, or None if omitted.

    The value is a canonical decimal (no sign or leading zero), so callers
    compare it with the expected page number as a string; it is never
    converted to an integer.
    """
    if any(character.isspace() or not character.isprintable() for character in url):
        _invalid(page, f"{field} is malformed")
    if "#" in url:
        _invalid(page, f"{field} has a fragment")
    try:
        parsed = urlsplit(url)
        hostname = parsed.hostname
        port = parsed.port
        user_information = parsed.username is not None or parsed.password is not None
    except ValueError:
        _invalid(page, f"{field} is malformed")
    if port is None and parsed.netloc.endswith(":"):
        _invalid(page, f"{field} is malformed")
    if user_information or "@" in parsed.netloc:
        _invalid(page, f"{field} has user information")
    if parsed.scheme not in _METADATA_SCHEMES or hostname != origin.hostname:
        _invalid(page, f"{field} has a different origin")
    if port != origin.port:
        _invalid(page, f"{field} has a different port")
    if parsed.path != origin.path:
        _invalid(page, f"{field} has a different path")

    try:
        parameters = parse_qsl(
            parsed.query, keep_blank_values=True, strict_parsing=True
        )
    except ValueError:
        _invalid(page, f"{field} has a malformed query")
    names = Counter(name for name, _ in parameters)
    if any(total > 1 for total in names.values()):
        _invalid(page, f"{field} has a duplicate query parameter")
    if set(names) - {_PAGE_PARAMETER, _PAGE_SIZE_PARAMETER}:
        _invalid(page, f"{field} has an unknown query parameter")
    values = dict(parameters)
    if values.get(_PAGE_SIZE_PARAMETER) != str(PAGE_SIZE):
        _invalid(page, f"{field} does not carry the fixed page size")
    if _PAGE_PARAMETER not in values:
        return None
    if _PAGE_VALUE.fullmatch(values[_PAGE_PARAMETER]) is None:
        _invalid(page, f"{field} has a malformed page value")
    return values[_PAGE_PARAMETER]


def _invalid(page: int, rule: str) -> NoReturn:
    raise InvalidProductListingError(f"page {page}: {rule}")


def _log_invalid(page: int, exc: InvalidProductListingError) -> None:
    logger.warning(
        "smelt_product_catalog_response_invalid", page=page, category=str(exc)
    )
