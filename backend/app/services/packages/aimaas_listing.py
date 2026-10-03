"""Validated retrieval of one paginated AIMAAS entity collection.

Implements docs/features/packages/product-catalog.md (AIMAAS Integration >
Origin, Authentication, and Pagination): pages are requested sequentially
from page 1 with the explicit `size=100`, every request is built from the
configured HTTPS API prefix and the known endpoint path, redirects are
never followed, and the configured `request_delay` is applied between page
requests. Every page must report the requested `page` and `size` and the
same `total` and `pages`; non-final pages hold exactly `size` items, the
final page `total - (pages - 1) * size`, and the collected count equals
`total`. `pages = 0` with an empty first page is the complete empty
collection.

Any transport, HTTP, pagination, or envelope failure raises `FetcherError`
with the sanitized AIMAAS messages; the invalid-response message belongs
to the consuming fetcher and is supplied by it. Items are returned as JSON
objects without inspecting their fields: each consumer validates only the
fields it consumes.

The helper performs network I/O only; callers must not hold an open
database transaction while awaiting it. Logs identify the collection, the
failed page, and the violated rule, never the response payload.
"""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, NoReturn

import httpx
import structlog
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from app.services.base_fetcher import FetcherError

logger = structlog.get_logger(__name__)

PRODUCTS_ENDPOINT_PATH = "entity/products"
PAGE_SIZE = 100

CONNECTION_FAILED_MESSAGE = "Failed to connect to AIMAAS"
TIMEOUT_MESSAGE = "AIMAAS request timed out"

_PAGE_PARAMETER = "page"
_SIZE_PARAMETER = "size"


@dataclass(frozen=True, slots=True)
class AimaasListing:
    """The complete, pagination-validated collection.

    `items` holds every collected entry in page order, unvalidated beyond
    being JSON objects.
    """

    total: int
    items: list[dict[str, Any]]


class _ListingPage(BaseModel):
    """One AIMAAS page envelope (unknown fields ignored)."""

    model_config = ConfigDict(strict=True, extra="ignore", frozen=True)

    items: list[dict[str, Any]]
    total: int = Field(ge=0)
    page: int
    size: int
    pages: int = Field(ge=0)


class InvalidAimaasListingError(Exception):
    """A pagination or envelope violation on one page.

    The message names the page and the violated rule only; it never
    contains response content, hosts, or URLs.
    """


def endpoint_url(api_url: str, path: str) -> str:
    """Return the endpoint URL for a canonical `AIMAAS_API_URL`."""
    return f"{api_url}/{path}"


async def fetch_aimaas_products(
    client: httpx.AsyncClient,
    *,
    api_url: str,
    request_delay: float,
    invalid_message: str,
) -> AimaasListing:
    """Retrieve the complete default AIMAAS Product list with `all_fields=true`.

    Deleted entries are excluded by the upstream default (no `all` or
    `deleted_only` parameter).
    """
    return await fetch_aimaas_listing(
        client,
        api_url=api_url,
        path=PRODUCTS_ENDPOINT_PATH,
        query={"all_fields": "true"},
        collection="products",
        request_delay=request_delay,
        invalid_message=invalid_message,
    )


async def fetch_aimaas_listing(
    client: httpx.AsyncClient,
    *,
    api_url: str,
    path: str,
    query: Mapping[str, str],
    collection: str,
    request_delay: float,
    invalid_message: str,
) -> AimaasListing:
    """Retrieve and pagination-validate one complete AIMAAS collection.

    `api_url` is the validated, canonical `AIMAAS_API_URL`; `path` the
    endpoint path below it; `query` the immutable endpoint-specific query
    parameters sent with every page; `collection` the label identifying
    this retrieval in logs; `request_delay` the run's configured delay in
    seconds, applied between page requests; `invalid_message` the
    consumer's sanitized `FetcherError` message for an invalid pagination
    or response schema. No partial listing is ever returned.
    """
    url = endpoint_url(api_url, path)
    total: int | None = None
    pages: int | None = None
    items: list[dict[str, Any]] = []

    page = 1
    while True:
        if page > 1 and request_delay > 0:
            await asyncio.sleep(request_delay)
        data = await _get_page(client, url, query, page, collection, invalid_message)
        try:
            envelope = _parse_page(data, page)
            if total is None or pages is None:
                total, pages = envelope.total, envelope.pages
            _check_page(envelope, page, total, pages)
        except InvalidAimaasListingError as exc:
            _log_invalid(collection, page, exc)
            raise FetcherError(invalid_message) from exc
        items.extend(envelope.items)
        if page >= pages:
            break
        page += 1

    # `pages - 1` full pages plus the checked final-page count, or the
    # empty collection, sum to exactly `total`: the collected-count
    # invariant holds by construction.
    return AimaasListing(total=total, items=items)


async def _get_page(
    client: httpx.AsyncClient,
    url: str,
    query: Mapping[str, str],
    page: int,
    collection: str,
    invalid_message: str,
) -> Any:
    """Request one page and return its decoded JSON body."""
    params = {**query, _SIZE_PARAMETER: str(PAGE_SIZE), _PAGE_PARAMETER: str(page)}
    try:
        response = await client.get(url, params=params)
    except httpx.TimeoutException as exc:
        _log_request_failed(collection, page, "timeout")
        raise FetcherError(TIMEOUT_MESSAGE) from exc
    except httpx.DecodingError:
        invalid = InvalidAimaasListingError(f"page {page}: undecodable body")
        _log_invalid(collection, page, invalid)
        raise FetcherError(invalid_message) from invalid
    except httpx.RequestError as exc:
        _log_request_failed(collection, page, "connection")
        raise FetcherError(CONNECTION_FAILED_MESSAGE) from exc

    try:
        response.raise_for_status()
    except httpx.HTTPStatusError as exc:
        status_code = response.status_code
        _log_request_failed(collection, page, "http_status", status_code=status_code)
        raise FetcherError(f"AIMAAS returned HTTP {status_code}") from exc

    try:
        return response.json()
    except ValueError:
        invalid = InvalidAimaasListingError(f"page {page}: body is not valid JSON")
        _log_invalid(collection, page, invalid)
        raise FetcherError(invalid_message) from invalid


def _parse_page(data: Any, page: int) -> _ListingPage:
    try:
        return _ListingPage.model_validate(data)
    except ValidationError as exc:
        fields = sorted(
            {str(error["loc"][0]) for error in exc.errors() if error["loc"]}
        )
        detail = ", ".join(fields) if fields else "envelope"
        # Raised from None: the validation error renders input values.
        raise InvalidAimaasListingError(
            f"page {page}: invalid response schema ({detail})"
        ) from None


def _check_page(envelope: _ListingPage, page: int, total: int, pages: int) -> None:
    """Apply the pagination invariants to one parsed page."""
    if envelope.page != page:
        _invalid(page, "page does not echo the requested page")
    if envelope.size != PAGE_SIZE:
        _invalid(page, "size does not echo the requested page size")
    if (envelope.total, envelope.pages) != (total, pages):
        _invalid(page, "total or pages changed during retrieval")

    if pages == 0:
        # Page 1 is already beyond `pages`: the complete empty collection.
        if total != 0:
            _invalid(page, "pages is 0 but total is not")
        expected = 0
    else:
        final_count = total - (pages - 1) * PAGE_SIZE
        # Only `pages = 1` may describe an empty collection with a final page.
        if not (0 < final_count <= PAGE_SIZE or (pages == 1 and total == 0)):
            _invalid(page, "total and pages are inconsistent")
        expected = PAGE_SIZE if page < pages else final_count
    if len(envelope.items) != expected:
        _invalid(page, f"expected {expected} items, received {len(envelope.items)}")


def _invalid(page: int, rule: str) -> NoReturn:
    raise InvalidAimaasListingError(f"page {page}: {rule}")


def _log_request_failed(
    collection: str, page: int, category: str, **extra: int
) -> None:
    logger.warning(
        "aimaas_request_failed",
        collection=collection,
        page=page,
        category=category,
        **extra,
    )


def _log_invalid(collection: str, page: int, exc: InvalidAimaasListingError) -> None:
    logger.warning(
        "aimaas_response_invalid",
        collection=collection,
        page=page,
        category=str(exc),
    )
