"""Shared SMELT Product listing fixtures and a fake SMELT server.

The files under `backend/tests/fixtures/smelt/` are live
`v1/basic/products/` pages (first, middle, and final) captured from the
default `SMELT_API_URL` with `page_size=100`, stored as served. They
contain Product catalog data only; no personal identifier was present
(docs/conventions.md, External Integration Contract Verification).

`SmeltServer` is an in-process `httpx.MockTransport` handler that serves
a paginated `v1/basic/products/` listing in the verified live
serialization (docs/features/packages/product-catalog.md, SMELT
Integration > Origin, Authentication, and Pagination): fixed page size
100, constant `count` and `total_pages`, continuation metadata with the
known `http` scheme defect, and `previous` on page 2 omitting `page`. Tests
mutate `pages` to build negative cases, register raw `responses` (status
codes, undecodable bodies, transport errors), and inspect `requests`.

Consumers: `tests/test_services/test_packages/test_smelt_product_listing.py`,
`test_smelt_product_listing_contract.py`, and `test_sync_smelt_products.py`.
All values are fictional (`smelt.example.test`, `cpe:/o:example:...`).
"""

from __future__ import annotations

import copy
import json
import math
from collections.abc import Callable, Iterable, Mapping
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs

import httpx

FIXTURE_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "smelt"

# Page numbers of the captured live pages.
FIXTURE_PAGES = (1, 2, 6)

SMELT_TEST_API_URL = "https://smelt.example.test/api"
"""A fictional, validated `SMELT_API_URL` (no port)."""

SMELT_TEST_ENDPOINT = f"{SMELT_TEST_API_URL}/v1/basic/products/"
"""The Product listing request URL for `SMELT_TEST_API_URL`."""

SMELT_TEST_METADATA_BASE = "http://smelt.example.test/api/v1/basic/products/"
"""Continuation-metadata base in the live serialization (`http` scheme)."""

PAGE_SIZE = 100


def load_products_page(page: int) -> dict[str, Any]:
    """Return one captured live Product listing page as parsed JSON."""
    path = FIXTURE_DIR / f"products_page_{page}.json"
    data: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    return data


def product_row(index: int, **overrides: Any) -> dict[str, Any]:
    """One fictional SMELT Product row with every upstream field.

    The ignored fields (`id`, `end_of_life`, `changed`, `details`) are
    present as served upstream; `overrides` replaces or adds any key.
    """
    row: dict[str, Any] = {
        "name": f"Example-Product-{index}",
        "id": 1000 + index,
        "friendly_name": f"Example Product {index}",
        "version": f"{index}",
        "cpe": f"cpe:/o:example:product-{index}:1",
        "end_of_life": None,
        "changed": "2026-09-01T03:00:00.000000Z",
        "repos": [
            f"EXAMPLE:Products:Product{index}:1:x86_64",
            f"EXAMPLE:Updates:Product{index}:1:x86_64",
        ],
        "details": [],
    }
    row.update(overrides)
    return row


def metadata_url(base: str, page: int) -> str:
    """A continuation URL in the live serialization; page 1 omits `page`."""
    if page == 1:
        return f"{base}?page_size={PAGE_SIZE}"
    return f"{base}?page={page}&page_size={PAGE_SIZE}"


def paginate(
    rows: list[dict[str, Any]], *, metadata_base: str = SMELT_TEST_METADATA_BASE
) -> dict[int, dict[str, Any]]:
    """Split `rows` into a valid page sequence keyed by page number."""
    total_pages = max(1, math.ceil(len(rows) / PAGE_SIZE))
    pages: dict[int, dict[str, Any]] = {}
    for page in range(1, total_pages + 1):
        start = (page - 1) * PAGE_SIZE
        pages[page] = {
            "count": len(rows),
            "total_pages": total_pages,
            "next": (
                metadata_url(metadata_base, page + 1) if page < total_pages else None
            ),
            "previous": metadata_url(metadata_base, page - 1) if page > 1 else None,
            "results": copy.deepcopy(rows[start : start + PAGE_SIZE]),
        }
    return pages


def make_rows(total: int, *, start: int = 1) -> list[dict[str, Any]]:
    """`total` distinct fictional Product rows numbered from `start`."""
    return [product_row(index) for index in range(start, start + total)]


Responder = Callable[[httpx.Request], httpx.Response]


class SmeltServer:
    """A fake SMELT `v1/basic/products/` endpoint for `httpx.MockTransport`.

    `pages` maps a page number to the JSON body served for it (any JSON
    value, mutable by tests); `responses` maps a page number to a callable
    that returns a raw response or raises a transport error instead. A
    request for an unknown page is answered with HTTP 404. Every request
    is recorded in `requests`; when `events` is supplied, `("http", url)`
    is also appended to it so a test can order requests against other
    recorded events.
    """

    def __init__(
        self,
        pages: Mapping[int, Any],
        *,
        events: list[tuple[str, str]] | None = None,
    ) -> None:
        self.pages: dict[int, Any] = dict(pages)
        self.responses: dict[int, Responder] = {}
        self.requests: list[httpx.Request] = []
        self.events = events

    @classmethod
    def for_rows(
        cls,
        product_rows: Iterable[dict[str, Any]],
        *,
        metadata_base: str = SMELT_TEST_METADATA_BASE,
        events: list[tuple[str, str]] | None = None,
    ) -> SmeltServer:
        """Serve `product_rows` as a valid paginated listing."""
        return cls(
            paginate(list(product_rows), metadata_base=metadata_base), events=events
        )

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self.events is not None:
            self.events.append(("http", str(request.url)))
        page = _requested_page(request)
        if page in self.responses:
            return self.responses[page](request)
        if page not in self.pages:
            return httpx.Response(404, json={"detail": "Invalid page."})
        return httpx.Response(200, json=self.pages[page])

    def client(self) -> httpx.AsyncClient:
        """A client whose transport is this server (redirects not followed)."""
        return httpx.AsyncClient(transport=httpx.MockTransport(self.handler))

    @property
    def requested_urls(self) -> list[str]:
        return [str(request.url) for request in self.requests]

    @property
    def requested_pages(self) -> list[int | None]:
        return [_requested_page(request) for request in self.requests]


def _requested_page(request: httpx.Request) -> int | None:
    values = parse_qs(request.url.query.decode("ascii")).get("page")
    if not values or not values[0].isdigit():
        return None
    return int(values[0])
