"""Shared AIMAAS Product and CVSS threshold fixtures and a fake AIMAAS server.

The files under `backend/tests/fixtures/aimaas/` are live pages captured
from the default `AIMAAS_API_URL` on 2026-10-03 and stored as served plus a
trailing newline:

- `products_page_{1..6}.json`: `entity/products?all_fields=true&size=100`,
  the complete Product list (pages 1-5) and one page beyond `pages` (6);
- `thresholds_page_{1,2}.json`: `entity/cvss-threshold?size=100`, the
  complete threshold list (page 1) and one page beyond `pages` (2).

They contain Product lifecycle and threshold data only; no personal
identifier was present (docs/conventions.md, External Integration Contract
Verification).

`AimaasServer` is an in-process `httpx.MockTransport` handler that serves a
paginated AIMAAS collection in the verified live envelope
(docs/features/packages/product-catalog.md, AIMAAS Integration > Origin,
Authentication, and Pagination): `{items, total, page, size, pages}` with
1-based pages, `page` and `size` echoing the request, and `{items: []}`
with correct metadata for a page beyond `pages`. Tests mutate `pages` to
build negative cases, register raw `responses` (status codes, undecodable
bodies, transport errors), and inspect `requests`.

`AimaasRouter` serves several such endpoints from one client, routed by
the request URL without its query: `sync_aimaas_thresholds` reads both the
Product list and the CVSS threshold list through one HTTP client.

All values built here are fictional (`aimaas.example.test`,
`cpe:/o:example:...`).
"""

from __future__ import annotations

import copy
import json
import math
from collections.abc import Callable, Iterable, Mapping
from pathlib import Path
from typing import Any

import httpx

FIXTURE_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "aimaas"

# Representative captured Product list pages: first, middle, final, and
# beyond `pages` (6).
FIXTURE_PAGES = (1, 3, 5, 6)

# Every captured Product list page: the complete collection (1-5) and the
# page beyond `pages` (6).
PRODUCT_LIST_PAGES = (1, 2, 3, 4, 5, 6)

# Every captured threshold list page: the complete collection (1) and the
# page beyond `pages` (2).
THRESHOLD_FIXTURE_PAGES = (1, 2)

AIMAAS_TEST_API_URL = "https://aimaas.example.test/api"
"""A fictional, validated `AIMAAS_API_URL` (no port)."""

AIMAAS_TEST_PRODUCTS_ENDPOINT = f"{AIMAAS_TEST_API_URL}/entity/products"
"""The Product list request URL for `AIMAAS_TEST_API_URL`."""

AIMAAS_TEST_THRESHOLDS_ENDPOINT = f"{AIMAAS_TEST_API_URL}/entity/cvss-threshold"
"""The CVSS threshold list request URL for `AIMAAS_TEST_API_URL`."""

PAGE_SIZE = 100


def load_products_page(page: int) -> dict[str, Any]:
    """Return one captured live Product list page as parsed JSON."""
    return _load(f"products_page_{page}.json")


def load_thresholds_page(page: int) -> dict[str, Any]:
    """Return one captured live CVSS threshold list page as parsed JSON."""
    return _load(f"thresholds_page_{page}.json")


def _load(name: str) -> dict[str, Any]:
    data: dict[str, Any] = json.loads((FIXTURE_DIR / name).read_text("utf-8"))
    return data


def product_item(index: int, **overrides: Any) -> dict[str, Any]:
    """One fictional AIMAAS Product entry with every live field.

    The default lifecycle dates form a complete consistent chain; the
    ignored fields are present as served upstream. `overrides` replaces or
    adds any key.
    """
    item: dict[str, Any] = {
        "slug": f"example-product-{index}",
        "name": f"Example Product {index}",
        "id": index,
        "deleted": False,
        "version": f"{index}",
        "fcs": "2024-01-15",
        "end_of_gs": "2027-06-30",
        "end_of_ltss": "2030-06-30",
        "end_of_reactive_ltss": "2032-06-30",
        "tracked_in_bz": None,
        "beta_release": None,
        "end_of_lts_core": None,
        "cpe": f"cpe:/o:example:product-{index}:1",
        "end_of_espos": None,
    }
    item.update(overrides)
    return item


def make_items(total: int, *, start: int = 1) -> list[dict[str, Any]]:
    """`total` distinct fictional Product entries numbered from `start`."""
    return [product_item(index) for index in range(start, start + total)]


def threshold_item(
    index: int, *, product: int, threshold: Any = 7.0, **overrides: Any
) -> dict[str, Any]:
    """One fictional AIMAAS CVSS threshold entry with every live field.

    `product` is the AIMAAS Product ID the threshold applies to; the
    ignored fields are present as served upstream. `overrides` replaces or
    adds any key.
    """
    item: dict[str, Any] = {
        "slug": f"example-threshold-{index}",
        "name": f"Example Threshold {index}",
        "id": 10_000 + index,
        "deleted": False,
        "product": product,
        "threshold": threshold,
    }
    item.update(overrides)
    return item


def paginate(items: list[dict[str, Any]]) -> dict[int, dict[str, Any]]:
    """Split `items` into a valid page sequence keyed by page number.

    An empty collection is served as `pages = 0` (page 1 is then beyond
    `pages`), the envelope AIMAAS returns for an empty result.
    """
    total_pages = math.ceil(len(items) / PAGE_SIZE)
    return {
        page: page_body(items, page, total_pages)
        for page in range(1, max(total_pages, 1) + 1)
    }


def page_body(
    items: list[dict[str, Any]], page: int, total_pages: int
) -> dict[str, Any]:
    """One page envelope of `items` for `page` (empty beyond `total_pages`)."""
    start = (page - 1) * PAGE_SIZE
    return {
        "items": copy.deepcopy(items[start : start + PAGE_SIZE]),
        "total": len(items),
        "page": page,
        "size": PAGE_SIZE,
        "pages": total_pages,
    }


Responder = Callable[[httpx.Request], httpx.Response]


class AimaasServer:
    """A fake AIMAAS paginated list endpoint for `httpx.MockTransport`.

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
    def for_items(
        cls,
        items: Iterable[dict[str, Any]],
        *,
        events: list[tuple[str, str]] | None = None,
    ) -> AimaasServer:
        """Serve `items` as a valid paginated collection."""
        return cls(paginate(list(items)), events=events)

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self.events is not None:
            self.events.append(("http", str(request.url)))
        page = _requested_page(request)
        if page in self.responses:
            return self.responses[page](request)
        if page not in self.pages:
            return httpx.Response(404, json={"detail": "Not Found"})
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


class AimaasRouter:
    """Several fake AIMAAS endpoints behind one `httpx.MockTransport`.

    `routes` maps an endpoint URL without query (for example
    `AIMAAS_TEST_THRESHOLDS_ENDPOINT`) to the `AimaasServer` answering it;
    a request for any other URL is answered with HTTP 404. Every request is
    recorded in `requests`; when `events` is supplied, `("http", url)` is
    also appended to it, so the routed servers need no `events` of their
    own.
    """

    def __init__(
        self,
        routes: Mapping[str, AimaasServer],
        *,
        events: list[tuple[str, str]] | None = None,
    ) -> None:
        self.routes: dict[str, AimaasServer] = dict(routes)
        self.requests: list[httpx.Request] = []
        self.events = events

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self.events is not None:
            self.events.append(("http", str(request.url)))
        server = self.routes.get(str(request.url.copy_with(query=None)))
        if server is None:
            return httpx.Response(404, json={"detail": "Not Found"})
        return server.handler(request)

    def client(self) -> httpx.AsyncClient:
        """A client whose transport is this router (redirects not followed)."""
        return httpx.AsyncClient(transport=httpx.MockTransport(self.handler))

    @property
    def requested_urls(self) -> list[str]:
        return [str(request.url) for request in self.requests]


def threshold_sync_router(
    products: Iterable[dict[str, Any]],
    thresholds: Iterable[dict[str, Any]],
    *,
    events: list[tuple[str, str]] | None = None,
) -> AimaasRouter:
    """Serve `products` as the Product list and `thresholds` as the CVSS
    threshold list of `AIMAAS_TEST_API_URL`, each a valid paginated
    collection."""
    return AimaasRouter(
        {
            AIMAAS_TEST_PRODUCTS_ENDPOINT: AimaasServer.for_items(products),
            AIMAAS_TEST_THRESHOLDS_ENDPOINT: AimaasServer.for_items(thresholds),
        },
        events=events,
    )


def _requested_page(request: httpx.Request) -> int | None:
    value = request.url.params.get("page")
    if value is None or not value.isdigit():
        return None
    return int(value)
