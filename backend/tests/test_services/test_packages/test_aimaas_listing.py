"""Tests for the validated AIMAAS paginated-collection retrieval.

Contract under test: docs/features/packages/product-catalog.md (AIMAAS
Integration > Origin, Authentication, and Pagination: sequential 1-based
pages with explicit `size=100`, the pagination validation invariants, and
the empty-collection rules; Product Lifecycle Sync, endpoint suffix and
query parameters; Deleted Flag Semantics, no `all` or `deleted_only`
parameter; Fetcher: `sync_aimaas_lifecycle` > Error Handling, sanitized
messages and payload-free logs) and docs/features/platform/
fetcher-infrastructure.md (Error Message Sanitization: chained
`FetcherError`, no host or URL in the public message).

Every test serves a fictional collection through `httpx.MockTransport`
(`tests/support/aimaas.py`); no network and no database are used.
"""

from __future__ import annotations

from collections.abc import Callable
from types import SimpleNamespace
from typing import Any, Final

import httpx
import pytest
from structlog.testing import capture_logs

from app.services.base_fetcher import FetcherError
from app.services.packages import aimaas_listing
from app.services.packages.aimaas_listing import (
    CONNECTION_FAILED_MESSAGE,
    PAGE_SIZE,
    PRODUCTS_ENDPOINT_PATH,
    TIMEOUT_MESSAGE,
    AimaasListing,
    InvalidAimaasListingError,
    endpoint_url,
    fetch_aimaas_listing,
    fetch_aimaas_products,
)
from tests.support.aimaas import (
    AIMAAS_TEST_API_URL,
    AIMAAS_TEST_PRODUCTS_ENDPOINT,
    AimaasServer,
    make_items,
    product_item,
)

INVALID: Final = "Example consumer invalid response message"
MARKER: Final = "Example-Confidential-Aimaas-Value"

Mutator = Callable[[dict[int, Any]], None]


async def _fetch(
    server: AimaasServer, *, delay: float = 0, api_url: str = AIMAAS_TEST_API_URL
) -> AimaasListing:
    async with server.client() as client:
        return await fetch_aimaas_products(
            client, api_url=api_url, request_delay=delay, invalid_message=INVALID
        )


async def _fetch_failing(server: AimaasServer) -> FetcherError:
    with pytest.raises(FetcherError) as raised:
        await _fetch(server)
    return raised.value


async def _fetch_invalid(server: AimaasServer) -> InvalidAimaasListingError:
    """Assert the consumer's invalid-response failure; return its cause."""
    error = await _fetch_failing(server)
    assert str(error) == INVALID
    cause = error.__cause__
    assert isinstance(cause, InvalidAimaasListingError)
    return cause


def _three_pages() -> AimaasServer:
    """250 items: pages of 100, 100, and 50."""
    return AimaasServer.for_items(make_items(250))


def _empty_page(pages: int) -> dict[str, Any]:
    return {"items": [], "total": 0, "page": 1, "size": PAGE_SIZE, "pages": pages}


def _set(page: int, field: str, value: Any) -> Mutator:
    def mutate(pages: dict[int, Any]) -> None:
        pages[page][field] = value

    return mutate


def _set_all(field: str, value: Any) -> Mutator:
    def mutate(pages: dict[int, Any]) -> None:
        for body in pages.values():
            body[field] = value

    return mutate


def _delete(page: int, field: str) -> Mutator:
    def mutate(pages: dict[int, Any]) -> None:
        del pages[page][field]

    return mutate


def _replace(page: int, body: Any) -> Mutator:
    def mutate(pages: dict[int, Any]) -> None:
        pages[page] = body

    return mutate


def _resize(page: int, count: int) -> Mutator:
    """Serve `count` items on `page` (fictional items, metadata unchanged)."""

    def mutate(pages: dict[int, Any]) -> None:
        pages[page]["items"] = make_items(count, start=10_000)

    return mutate


def _set_item(page: int, value: Any) -> Mutator:
    def mutate(pages: dict[int, Any]) -> None:
        pages[page]["items"][0] = value

    return mutate


# ---------------------------------------------------------------------------
# Accepted collections
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestRetrieval:
    async def test_multi_page_collection_returns_every_item_in_page_order(
        self,
    ) -> None:
        items = make_items(250)
        server = AimaasServer.for_items(items)

        listing = await _fetch(server)

        assert listing == AimaasListing(total=250, items=items)
        assert server.requested_pages == [1, 2, 3]

    async def test_single_page_collection(self) -> None:
        items = make_items(7)
        server = AimaasServer.for_items(items)

        listing = await _fetch(server)

        assert listing == AimaasListing(total=7, items=items)
        assert server.requested_pages == [1]

    async def test_exactly_one_full_page_requests_no_further_page(self) -> None:
        items = make_items(100)
        server = AimaasServer.for_items(items)

        listing = await _fetch(server)

        assert listing == AimaasListing(total=100, items=items)
        assert server.pages[1]["pages"] == 1
        assert server.requested_pages == [1]

    async def test_exact_multiple_of_page_size_requests_no_extra_page(self) -> None:
        server = AimaasServer.for_items(make_items(200))

        listing = await _fetch(server)

        assert listing.total == 200
        assert len(listing.items) == 200
        assert server.requested_pages == [1, 2]

    async def test_zero_pages_with_empty_first_page_is_the_empty_collection(
        self,
    ) -> None:
        server = AimaasServer({1: _empty_page(0), 2: _empty_page(0)})

        listing = await _fetch(server)

        assert listing == AimaasListing(total=0, items=[])
        assert server.requested_pages == [1]

    async def test_one_page_with_zero_total_and_empty_first_page_is_accepted(
        self,
    ) -> None:
        server = AimaasServer({1: _empty_page(1), 2: _empty_page(1)})

        listing = await _fetch(server)

        assert listing == AimaasListing(total=0, items=[])
        assert server.requested_pages == [1]

    async def test_items_are_returned_without_inspecting_their_fields(self) -> None:
        items = [{"unexpected": [1, None]}, {}, product_item(3, cpe=None, fcs=7)]
        server = AimaasServer.for_items(items)

        listing = await _fetch(server)

        assert listing.items == items

    async def test_unknown_envelope_fields_are_ignored(self) -> None:
        server = _three_pages()
        for body in server.pages.values():
            body["links"] = {"next": MARKER}

        listing = await _fetch(server)

        assert listing.total == 250


# ---------------------------------------------------------------------------
# Request construction
# ---------------------------------------------------------------------------


def _expected_product_requests(pages: int) -> list[str]:
    return [
        f"{AIMAAS_TEST_PRODUCTS_ENDPOINT}?all_fields=true&size=100&page={page}"
        for page in range(1, pages + 1)
    ]


@pytest.mark.unit
class TestRequests:
    async def test_product_requests_carry_exactly_the_documented_query(
        self,
    ) -> None:
        server = _three_pages()

        await _fetch(server)

        assert server.requested_urls == _expected_product_requests(3)
        for page, request in enumerate(server.requests, start=1):
            assert request.method == "GET"
            assert request.url.scheme == "https"
            assert request.url.host == "aimaas.example.test"
            assert request.url.port is None
            assert request.url.path == "/api/entity/products"
            assert request.url.params.multi_items() == [
                ("all_fields", "true"),
                ("size", "100"),
                ("page", str(page)),
            ]

    async def test_product_requests_never_include_deleted_records(self) -> None:
        server = _three_pages()

        await _fetch(server)

        for request in server.requests:
            assert "all" not in request.url.params
            assert "deleted_only" not in request.url.params

    async def test_requests_send_no_credentials(self) -> None:
        server = _three_pages()

        await _fetch(server)

        for request in server.requests:
            assert "authorization" not in request.headers
            assert "cookie" not in request.headers

    async def test_configured_non_default_port_is_used(self) -> None:
        api_url = "https://aimaas.example.test:8443/api"
        server = AimaasServer.for_items(make_items(5))

        await _fetch(server, api_url=api_url)

        assert server.requested_urls == [
            f"{api_url}/entity/products?all_fields=true&size=100&page=1"
        ]

    async def test_generic_listing_sends_the_supplied_path_and_query(self) -> None:
        server = AimaasServer.for_items(make_items(150))

        async with server.client() as client:
            listing = await fetch_aimaas_listing(
                client,
                api_url=AIMAAS_TEST_API_URL,
                path="entity/example-collection",
                query={"example_filter": "yes"},
                collection="example",
                request_delay=0,
                invalid_message=INVALID,
            )

        assert listing.total == 150
        assert server.requested_urls == [
            f"{AIMAAS_TEST_API_URL}/entity/example-collection"
            f"?example_filter=yes&size=100&page={page}"
            for page in (1, 2)
        ]

    async def test_pages_are_requested_once_and_never_beyond_pages(self) -> None:
        server = _three_pages()
        server.pages[4] = {**server.pages[3], "page": 4, "items": []}

        await _fetch(server)

        assert server.requested_pages == [1, 2, 3]

    def test_endpoint_url_joins_prefix_and_path(self) -> None:
        assert endpoint_url(AIMAAS_TEST_API_URL, "entity/products") == (
            "https://aimaas.example.test/api/entity/products"
        )
        assert PRODUCTS_ENDPOINT_PATH == "entity/products"
        assert PAGE_SIZE == 100


@pytest.mark.unit
class TestRequestDelay:
    @staticmethod
    def _record_sleeps(
        monkeypatch: pytest.MonkeyPatch, events: list[tuple[str, str]]
    ) -> None:
        async def sleep(delay: float) -> None:
            events.append(("sleep", repr(delay)))

        monkeypatch.setattr(aimaas_listing, "asyncio", SimpleNamespace(sleep=sleep))

    async def test_delay_is_awaited_between_page_requests_only(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        events: list[tuple[str, str]] = []
        self._record_sleeps(monkeypatch, events)
        server = AimaasServer.for_items(make_items(250), events=events)

        await _fetch(server, delay=0.5)

        first, second, third = _expected_product_requests(3)
        assert events == [
            ("http", first),
            ("sleep", "0.5"),
            ("http", second),
            ("sleep", "0.5"),
            ("http", third),
        ]

    async def test_single_page_never_sleeps(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        events: list[tuple[str, str]] = []
        self._record_sleeps(monkeypatch, events)

        await _fetch(AimaasServer.for_items(make_items(5), events=events), delay=2.0)

        assert [kind for kind, _ in events] == ["http"]

    async def test_zero_delay_never_sleeps(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        events: list[tuple[str, str]] = []
        self._record_sleeps(monkeypatch, events)

        await _fetch(AimaasServer.for_items(make_items(250), events=events), delay=0)

        assert [kind for kind, _ in events] == ["http", "http", "http"]


# ---------------------------------------------------------------------------
# Pagination and envelope rejections
# ---------------------------------------------------------------------------

# (id, mutation, page whose validation fails)
_REJECTIONS: Final[list[tuple[str, Mutator, int]]] = [
    # Constant metadata across pages.
    ("total-changes", _set(2, "total", 251), 2),
    ("pages-changes", _set(2, "pages", 4), 2),
    ("total-and-pages-change", _set_all("total", 350), 1),
    # Echo of the requested page and size.
    ("size-differs-on-page-1", _set(1, "size", 50), 1),
    ("size-differs-on-later-page", _set(2, "size", 99), 2),
    ("page-not-echoed-on-page-1", _set(1, "page", 2), 1),
    ("page-not-echoed-on-later-page", _set(2, "page", 3), 2),
    ("page-zero-reported", _set(1, "page", 0), 1),
    # Page item counts.
    ("non-final-page-short", _resize(1, 99), 1),
    ("non-final-page-long", _resize(2, 101), 2),
    ("non-final-page-empty", _resize(2, 0), 2),
    ("final-page-too-few", _resize(3, 49), 3),
    ("final-page-too-many", _resize(3, 51), 3),
    ("final-page-empty", _resize(3, 0), 3),
    # Envelope schema.
    ("top-level-list", _replace(1, []), 1),
    ("top-level-string", _replace(1, "items"), 1),
    ("top-level-null", _replace(1, None), 1),
    ("top-level-number", _replace(1, 250), 1),
    ("later-page-not-an-object", _replace(2, []), 2),
    ("missing-items", _delete(1, "items"), 1),
    ("missing-total", _delete(1, "total"), 1),
    ("missing-page", _delete(1, "page"), 1),
    ("missing-size", _delete(1, "size"), 1),
    ("missing-pages", _delete(1, "pages"), 1),
    ("missing-field-on-later-page", _delete(3, "total"), 3),
    ("string-total", _set(1, "total", "250"), 1),
    ("string-pages", _set(1, "pages", "3"), 1),
    ("string-page", _set(1, "page", "1"), 1),
    ("string-size", _set(1, "size", "100"), 1),
    ("float-total", _set(1, "total", 250.0), 1),
    ("float-pages", _set(1, "pages", 3.0), 1),
    ("float-size", _set(1, "size", 100.0), 1),
    ("boolean-total", _set(1, "total", True), 1),
    ("boolean-page", _set(1, "page", True), 1),
    ("boolean-pages", _set(1, "pages", True), 1),
    ("null-total", _set(1, "total", None), 1),
    ("negative-total", _set(1, "total", -1), 1),
    ("negative-pages", _set(1, "pages", -1), 1),
    ("object-items", _set(1, "items", {}), 1),
    ("string-items", _set(1, "items", "items"), 1),
    ("null-items", _set(1, "items", None), 1),
    ("string-item", _set_item(2, "item"), 2),
    ("integer-item", _set_item(1, 5), 1),
    ("null-item", _set_item(1, None), 1),
    ("array-item", _set_item(3, []), 3),
]


@pytest.mark.unit
class TestPaginationRejected:
    @pytest.mark.parametrize(
        ("mutate", "failed_page"),
        [case[1:] for case in _REJECTIONS],
        ids=[case[0] for case in _REJECTIONS],
    )
    async def test_violation_rejects_and_stops_at_the_failed_page(
        self, mutate: Mutator, failed_page: int
    ) -> None:
        server = _three_pages()
        mutate(server.pages)

        cause = await _fetch_invalid(server)

        assert str(cause).startswith(f"page {failed_page}: ")
        assert server.requested_pages == list(range(1, failed_page + 1))

    @pytest.mark.parametrize(
        ("total", "pages"),
        [(50, 3), (500, 2), (100, 2), (0, 2), (101, 1)],
        ids=[
            "total-50-pages-3",
            "total-500-pages-2",
            "empty-final-page",
            "zero-total-two-pages",
            "total-101-pages-1",
        ],
    )
    async def test_inconsistent_total_and_pages_are_rejected_on_page_1(
        self, total: int, pages: int
    ) -> None:
        server = AimaasServer(
            {
                page: {
                    "items": make_items(PAGE_SIZE) if total else [],
                    "total": total,
                    "page": page,
                    "size": PAGE_SIZE,
                    "pages": pages,
                }
                for page in (1, 2, 3)
            }
        )

        cause = await _fetch_invalid(server)

        assert str(cause) == "page 1: total and pages are inconsistent"
        assert server.requested_pages == [1]

    async def test_zero_pages_with_nonzero_total_is_rejected(self) -> None:
        server = AimaasServer({1: {**_empty_page(0), "total": 5}})

        cause = await _fetch_invalid(server)

        assert str(cause) == "page 1: pages is 0 but total is not"
        assert server.requested_pages == [1]

    async def test_zero_pages_with_items_on_page_1_is_rejected(self) -> None:
        server = AimaasServer({1: {**_empty_page(0), "items": make_items(1)}})

        cause = await _fetch_invalid(server)

        assert str(cause) == "page 1: expected 0 items, received 1"

    async def test_one_page_with_zero_total_but_items_is_rejected(self) -> None:
        server = AimaasServer({1: {**_empty_page(1), "items": make_items(2)}})

        cause = await _fetch_invalid(server)

        assert str(cause) == "page 1: expected 0 items, received 2"

    async def test_rule_messages_name_the_page_and_rule(self) -> None:
        cases: list[tuple[Mutator, str]] = [
            (_set(2, "page", 3), "page 2: page does not echo the requested page"),
            (_set(1, "size", 50), "page 1: size does not echo the requested page size"),
            (_set(2, "total", 251), "page 2: total or pages changed during retrieval"),
            (_resize(3, 49), "page 3: expected 50 items, received 49"),
            (_resize(1, 101), "page 1: expected 100 items, received 101"),
            (_delete(1, "size"), "page 1: invalid response schema (size)"),
            (
                _set_item(2, MARKER),
                "page 2: invalid response schema (items)",
            ),
            (_replace(1, [MARKER]), "page 1: invalid response schema (envelope)"),
        ]
        for mutate, message in cases:
            server = _three_pages()
            mutate(server.pages)

            assert str(await _fetch_invalid(server)) == message

    async def test_schema_error_lists_every_invalid_field_once(self) -> None:
        server = _three_pages()
        server.pages[1].update({"total": "x", "pages": "y", "items": [1, 2]})

        cause = await _fetch_invalid(server)

        assert str(cause) == "page 1: invalid response schema (items, pages, total)"

    async def test_schema_error_suppresses_the_rendering_validation_error(
        self,
    ) -> None:
        server = _three_pages()
        server.pages[1]["total"] = MARKER

        cause = await _fetch_invalid(server)

        assert cause.__cause__ is None
        assert cause.__suppress_context__ is True

    async def test_top_level_json_null_is_rejected(self) -> None:
        server = _three_pages()
        server.responses[1] = lambda request: httpx.Response(200, content=b"null")

        cause = await _fetch_invalid(server)

        assert str(cause) == "page 1: invalid response schema (envelope)"

    async def test_non_json_body_is_rejected(self) -> None:
        server = _three_pages()
        server.responses[2] = lambda request: httpx.Response(
            200, content=b"<html>maintenance</html>"
        )

        cause = await _fetch_invalid(server)

        assert str(cause) == "page 2: body is not valid JSON"
        assert server.requested_pages == [1, 2]

    async def test_undecodable_body_is_an_invalid_response(self) -> None:
        server = _three_pages()
        server.responses[1] = lambda request: httpx.Response(
            200,
            headers={"content-encoding": "gzip"},
            stream=httpx.ByteStream(b"not gzip at all"),
        )

        cause = await _fetch_invalid(server)

        assert str(cause) == "page 1: undecodable body"
        assert server.requested_pages == [1]


# ---------------------------------------------------------------------------
# Transport and HTTP failures
# ---------------------------------------------------------------------------


def _raise(error: type[httpx.TransportError]) -> Callable[[httpx.Request], Any]:
    def respond(request: httpx.Request) -> httpx.Response:
        raise error("example failure to aimaas.example.test", request=request)

    return respond


@pytest.mark.unit
class TestTransportFailures:
    @pytest.mark.parametrize("status_code", [404, 500, 503, 422])
    async def test_non_success_status_raises_http_status_message(
        self, status_code: int
    ) -> None:
        server = _three_pages()
        server.responses[1] = lambda request: httpx.Response(status_code)

        error = await _fetch_failing(server)

        assert str(error) == f"AIMAAS returned HTTP {status_code}"
        assert isinstance(error.__cause__, httpx.HTTPStatusError)
        assert server.requested_pages == [1]

    @pytest.mark.parametrize("status_code", [301, 302])
    async def test_redirect_is_not_followed(self, status_code: int) -> None:
        server = _three_pages()
        server.responses[1] = lambda request: httpx.Response(
            status_code, headers={"Location": "https://other.example.test/elsewhere"}
        )

        error = await _fetch_failing(server)

        assert str(error) == f"AIMAAS returned HTTP {status_code}"
        assert isinstance(error.__cause__, httpx.HTTPStatusError)
        assert len(server.requests) == 1

    @pytest.mark.parametrize(
        ("error", "message"),
        [
            (httpx.ConnectError, CONNECTION_FAILED_MESSAGE),
            (httpx.ReadError, CONNECTION_FAILED_MESSAGE),
            (httpx.RemoteProtocolError, CONNECTION_FAILED_MESSAGE),
            (httpx.ReadTimeout, TIMEOUT_MESSAGE),
            (httpx.ConnectTimeout, TIMEOUT_MESSAGE),
            (httpx.PoolTimeout, TIMEOUT_MESSAGE),
        ],
        ids=lambda value: value if isinstance(value, str) else value.__name__,
    )
    async def test_transport_error_on_later_page_raises_sanitized_message(
        self, error: type[httpx.TransportError], message: str
    ) -> None:
        server = _three_pages()
        server.responses[2] = _raise(error)

        raised = await _fetch_failing(server)

        assert str(raised) == message
        assert isinstance(raised.__cause__, error)
        assert server.requested_pages == [1, 2]
        assert "aimaas.example.test" not in str(raised)

    def test_sanitized_messages_are_the_specified_values(self) -> None:
        assert CONNECTION_FAILED_MESSAGE == "Failed to connect to AIMAAS"
        assert TIMEOUT_MESSAGE == "AIMAAS request timed out"

    async def test_http_failure_on_later_page_stops_further_requests(self) -> None:
        server = AimaasServer.for_items(make_items(350))
        server.responses[2] = lambda request: httpx.Response(500)

        with pytest.raises(FetcherError, match=r"^AIMAAS returned HTTP 500$"):
            await _fetch(server)

        assert server.requested_pages == [1, 2]

    async def test_missing_later_page_is_an_http_failure(self) -> None:
        server = _three_pages()
        del server.pages[3]

        error = await _fetch_failing(server)

        assert str(error) == "AIMAAS returned HTTP 404"
        assert server.requested_pages == [1, 2, 3]


# ---------------------------------------------------------------------------
# Logs (Error Handling: failed page and category, no payload)
# ---------------------------------------------------------------------------


def _marked_server() -> AimaasServer:
    return AimaasServer.for_items(
        [
            product_item(index, name=MARKER, slug=MARKER, cpe=f"{MARKER}-{index}")
            for index in range(1, 251)
        ]
    )


def _assert_payload_free(logs: list[Any], error: FetcherError) -> None:
    assert MARKER not in repr(logs)
    assert MARKER not in str(error)
    assert MARKER not in str(error.__cause__)
    assert "aimaas.example.test" not in repr(logs)


@pytest.mark.unit
class TestFailureLogs:
    async def test_invalid_item_log_names_collection_page_and_category(
        self,
    ) -> None:
        server = _marked_server()
        server.pages[2]["items"][0] = MARKER

        with capture_logs() as logs:
            error = await _fetch_failing(server)

        assert logs == [
            {
                "event": "aimaas_response_invalid",
                "log_level": "warning",
                "collection": "products",
                "page": 2,
                "category": "page 2: invalid response schema (items)",
            }
        ]
        _assert_payload_free(logs, error)

    async def test_invalid_metadata_value_is_not_logged(self) -> None:
        server = _marked_server()
        server.pages[1]["total"] = MARKER

        with capture_logs() as logs:
            error = await _fetch_failing(server)

        (entry,) = logs
        assert entry["category"] == "page 1: invalid response schema (total)"
        _assert_payload_free(logs, error)

    async def test_pagination_rule_log_names_the_rule(self) -> None:
        server = _marked_server()
        server.pages[3]["items"].append(product_item(9999, name=MARKER))

        with capture_logs() as logs:
            error = await _fetch_failing(server)

        assert logs == [
            {
                "event": "aimaas_response_invalid",
                "log_level": "warning",
                "collection": "products",
                "page": 3,
                "category": "page 3: expected 50 items, received 51",
            }
        ]
        _assert_payload_free(logs, error)

    async def test_http_status_log_names_page_category_and_status(self) -> None:
        server = _marked_server()
        server.responses[2] = lambda request: httpx.Response(
            500, json={"detail": MARKER}
        )

        with capture_logs() as logs:
            error = await _fetch_failing(server)

        assert logs == [
            {
                "event": "aimaas_request_failed",
                "log_level": "warning",
                "collection": "products",
                "page": 2,
                "category": "http_status",
                "status_code": 500,
            }
        ]
        _assert_payload_free(logs, error)

    @pytest.mark.parametrize(
        ("error", "category"),
        [(httpx.ConnectError, "connection"), (httpx.ReadTimeout, "timeout")],
    )
    async def test_transport_log_names_page_and_category(
        self, error: type[httpx.TransportError], category: str
    ) -> None:
        server = _marked_server()
        server.responses[3] = _raise(error)

        with capture_logs() as logs:
            raised = await _fetch_failing(server)

        assert logs == [
            {
                "event": "aimaas_request_failed",
                "log_level": "warning",
                "collection": "products",
                "page": 3,
                "category": category,
            }
        ]
        _assert_payload_free(logs, raised)

    async def test_non_json_body_log_contains_no_body(self) -> None:
        server = _marked_server()
        server.responses[1] = lambda request: httpx.Response(
            200, content=MARKER.encode()
        )

        with capture_logs() as logs:
            error = await _fetch_failing(server)

        (entry,) = logs
        assert entry["event"] == "aimaas_response_invalid"
        assert (entry["collection"], entry["page"]) == ("products", 1)
        assert entry["category"] == "page 1: body is not valid JSON"
        _assert_payload_free(logs, error)

    async def test_undecodable_body_log_contains_no_body(self) -> None:
        server = _marked_server()
        server.responses[2] = lambda request: httpx.Response(
            200,
            headers={"content-encoding": "gzip"},
            stream=httpx.ByteStream(MARKER.encode()),
        )

        with capture_logs() as logs:
            error = await _fetch_failing(server)

        (entry,) = logs
        assert (entry["collection"], entry["page"]) == ("products", 2)
        assert entry["category"] == "page 2: undecodable body"
        _assert_payload_free(logs, error)

    async def test_generic_listing_logs_its_collection_label(self) -> None:
        server = AimaasServer.for_items(make_items(3))
        server.responses[1] = lambda request: httpx.Response(503)

        async with server.client() as client:
            with capture_logs() as logs, pytest.raises(FetcherError):
                await fetch_aimaas_listing(
                    client,
                    api_url=AIMAAS_TEST_API_URL,
                    path="entity/example-collection",
                    query={},
                    collection="example-collection",
                    request_delay=0,
                    invalid_message=INVALID,
                )

        (entry,) = logs
        assert entry["collection"] == "example-collection"

    async def test_successful_retrieval_logs_nothing(self) -> None:
        with capture_logs() as logs:
            await _fetch(_marked_server())

        assert logs == []
