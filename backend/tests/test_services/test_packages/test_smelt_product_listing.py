"""Tests for the validated SMELT Product listing retrieval.

Contract under test: docs/features/packages/product-catalog.md (SMELT
Integration > Origin, Authentication, and Pagination, rules 1-4; Fetcher:
`sync_smelt_products` > Error Handling, sanitized messages and payload-free
logs) and docs/features/platform/fetcher-infrastructure.md (Error Message
Sanitization: chained `FetcherError`, no host or URL in the public
message). The transport mapping and the response-schema boundary follow
the #763 implementation decisions D2 and D3: an undecodable or non-JSON
body, the envelope, the continuation metadata, the page sequence, and a
non-object result element are an invalid response.

Every test serves a fictional listing through `httpx.MockTransport`
(`tests/support/smelt.py`); no network and no database are used.
"""

from __future__ import annotations

from collections.abc import Callable
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
from structlog.testing import capture_logs

from app.services.base_fetcher import FetcherError
from app.services.packages import smelt_product_listing
from app.services.packages.smelt_product_listing import (
    InvalidProductListingError,
    SmeltProductListing,
    fetch_product_listing,
)
from tests.support.smelt import (
    SMELT_TEST_API_URL,
    SMELT_TEST_ENDPOINT,
    SMELT_TEST_METADATA_BASE,
    SmeltServer,
    make_rows,
)

INVALID = "SMELT returned invalid Product catalog response"
PORT_API_URL = "https://smelt.example.test:8443/api"

Mutator = Callable[[dict[int, Any]], None]


def _meta(query: str, base: str = SMELT_TEST_METADATA_BASE) -> str:
    return f"{base}?{query}"


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


def _set_result(page: int, value: Any) -> Mutator:
    def mutate(pages: dict[int, Any]) -> None:
        pages[page]["results"][0] = value

    return mutate


async def _fetch(
    server: SmeltServer, *, api_url: str = SMELT_TEST_API_URL, delay: float = 0
) -> SmeltProductListing:
    async with server.client() as client:
        return await fetch_product_listing(client, api_url=api_url, request_delay=delay)


async def _fetch_invalid(
    server: SmeltServer, *, api_url: str = SMELT_TEST_API_URL
) -> FetcherError:
    with pytest.raises(FetcherError) as raised:
        await _fetch(server, api_url=api_url)
    error = raised.value
    assert str(error) == INVALID
    assert isinstance(error.__cause__, InvalidProductListingError)
    return error


def _three_pages(**kwargs: Any) -> SmeltServer:
    """250 rows: pages of 100, 100, and 50."""
    return SmeltServer.for_rows(make_rows(250), **kwargs)


def _expected_requests(pages: int, api_url: str = SMELT_TEST_API_URL) -> list[str]:
    endpoint = f"{api_url}/v1/basic/products/"
    return [f"{endpoint}?page_size=100&page={page}" for page in range(1, pages + 1)]


# ---------------------------------------------------------------------------
# Happy path and request construction (rule 1, rule 4)
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestRetrieval:
    async def test_single_page_listing_returns_every_row_and_count(self) -> None:
        product_rows = make_rows(3)
        server = SmeltServer.for_rows(product_rows)

        listing = await _fetch(server)

        assert listing == SmeltProductListing(count=3, results=product_rows)
        assert server.requested_pages == [1]

    async def test_multi_page_listing_returns_rows_in_page_order(self) -> None:
        product_rows = make_rows(250)
        server = SmeltServer.for_rows(product_rows)

        listing = await _fetch(server)

        assert listing.count == 250
        assert listing.results == product_rows
        assert server.requested_pages == [1, 2, 3]

    async def test_exact_multiple_of_page_size_requests_no_extra_page(self) -> None:
        server = SmeltServer.for_rows(make_rows(200))

        listing = await _fetch(server)

        assert listing.count == 200
        assert server.requested_pages == [1, 2]

    async def test_empty_listing_with_one_empty_final_page_is_accepted(self) -> None:
        """An empty final page is valid at the pagination layer; `count = 0`
        is rejected by complete-snapshot validation instead (D3)."""
        server = SmeltServer.for_rows([])

        listing = await _fetch(server)

        assert listing == SmeltProductListing(count=0, results=[])

    async def test_requests_use_configured_https_origin_and_explicit_page(
        self,
    ) -> None:
        server = _three_pages()

        await _fetch(server)

        assert server.requested_urls == _expected_requests(3)
        for request in server.requests:
            assert request.method == "GET"
            assert request.url.scheme == "https"
            assert request.url.host == "smelt.example.test"
            assert request.url.port is None
            assert request.url.path == "/api/v1/basic/products/"
            assert [name for name, _ in request.url.params.multi_items()] == [
                "page_size",
                "page",
            ]

    async def test_requests_never_target_the_continuation_metadata(self) -> None:
        server = _three_pages()
        metadata = {
            body[field]
            for body in server.pages.values()
            for field in ("next", "previous")
            if body[field] is not None
        }

        await _fetch(server)

        assert metadata
        assert metadata.isdisjoint(server.requested_urls)
        assert all(url.startswith(SMELT_TEST_ENDPOINT) for url in server.requested_urls)

    async def test_requests_send_no_credentials(self) -> None:
        server = _three_pages()

        await _fetch(server)

        for request in server.requests:
            assert "authorization" not in request.headers
            assert "cookie" not in request.headers

    async def test_configured_non_default_port_is_used_in_requests(self) -> None:
        server = _three_pages(
            metadata_base="http://smelt.example.test:8443/api/v1/basic/products/"
        )

        await _fetch(server, api_url=PORT_API_URL)

        assert server.requested_urls == _expected_requests(3, PORT_API_URL)


@pytest.mark.unit
class TestRequestDelay:
    @staticmethod
    def _record_sleeps(
        monkeypatch: pytest.MonkeyPatch, events: list[tuple[str, str]]
    ) -> None:
        async def sleep(delay: float) -> None:
            events.append(("sleep", repr(delay)))

        monkeypatch.setattr(
            smelt_product_listing, "asyncio", SimpleNamespace(sleep=sleep)
        )

    async def test_delay_is_awaited_between_page_requests_only(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        events: list[tuple[str, str]] = []
        self._record_sleeps(monkeypatch, events)
        server = SmeltServer.for_rows(make_rows(250), events=events)

        await _fetch(server, delay=0.5)

        first, second, third = _expected_requests(3)
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

        await _fetch(SmeltServer.for_rows(make_rows(5), events=events), delay=2.0)

        assert [kind for kind, _ in events] == ["http"]

    async def test_zero_delay_never_sleeps(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        events: list[tuple[str, str]] = []
        self._record_sleeps(monkeypatch, events)

        await _fetch(SmeltServer.for_rows(make_rows(250), events=events), delay=0)

        assert [kind for kind, _ in events] == ["http", "http", "http"]


# ---------------------------------------------------------------------------
# Continuation metadata (rule 3): accepting cases
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestMetadataAccepted:
    @pytest.mark.parametrize(
        "metadata_base",
        [
            SMELT_TEST_METADATA_BASE,
            "https://smelt.example.test/api/v1/basic/products/",
        ],
        ids=["http-scheme-defect", "https"],
    )
    async def test_metadata_scheme_http_or_https_is_accepted(
        self, metadata_base: str
    ) -> None:
        listing = await _fetch(_three_pages(metadata_base=metadata_base))

        assert listing.count == 250

    @pytest.mark.parametrize(
        "metadata_base",
        [
            "http://smelt.example.test:8443/api/v1/basic/products/",
            "https://smelt.example.test:8443/api/v1/basic/products/",
        ],
        ids=["http", "https"],
    )
    async def test_explicit_setting_port_matched_by_metadata_is_accepted(
        self, metadata_base: str
    ) -> None:
        listing = await _fetch(
            _three_pages(metadata_base=metadata_base), api_url=PORT_API_URL
        )

        assert listing.count == 250

    @pytest.mark.parametrize(
        "mutate",
        [
            _set(2, "previous", _meta("page=1&page_size=100")),
            _set(2, "previous", _meta("page_size=100")),
            _set(1, "next", _meta("page_size=100&page=2")),
        ],
        ids=[
            "explicit-page-1-in-previous",
            "omitted-page-in-previous-on-page-2",
            "parameter-order-free",
        ],
    )
    async def test_equivalent_metadata_serializations_are_accepted(
        self, mutate: Mutator
    ) -> None:
        server = _three_pages()
        mutate(server.pages)

        listing = await _fetch(server)

        assert listing.count == 250


# ---------------------------------------------------------------------------
# Continuation metadata (rule 3) and envelope (rule 2): rejecting cases
# ---------------------------------------------------------------------------

_NEXT_2 = "page=2&page_size=100"
_HOST = "smelt.example.test"
_PATH = "/api/v1/basic/products/"


def _url(authority: str = f"http://{_HOST}", path: str = _PATH) -> str:
    """A page-2 `next` URL with the given authority and path."""
    return f"{authority}{path}?{_NEXT_2}"


_METADATA_REJECTIONS: list[tuple[str, Mutator]] = [
    ("ftp-scheme", _set(1, "next", _url(f"ftp://{_HOST}"))),
    ("relative-url", _set(1, "next", _url(""))),
    (
        "explicit-443-when-setting-omits-port",
        _set(1, "next", _url(f"https://{_HOST}:443")),
    ),
    (
        "explicit-80-when-setting-omits-port",
        _set(1, "next", _url(f"http://{_HOST}:80")),
    ),
    (
        "explicit-8443-when-setting-omits-port",
        _set(1, "next", _url(f"https://{_HOST}:8443")),
    ),
    ("empty-port", _set(1, "next", _url(f"http://{_HOST}:"))),
    ("out-of-range-port", _set(1, "next", _url(f"http://{_HOST}:99999"))),
    ("different-host", _set(1, "next", _url("http://other.example.test"))),
    ("different-path", _set(1, "next", _url(path="/api/v2/basic/products/"))),
    (
        "path-without-trailing-slash",
        _set(1, "next", _url(path="/api/v1/basic/products")),
    ),
    ("user-information", _set(1, "next", _url(f"http://operator@{_HOST}"))),
    ("user-and-password", _set(1, "next", _url(f"http://operator:example@{_HOST}"))),
    ("empty-user-information", _set(1, "next", _url(f"http://@{_HOST}"))),
    ("fragment", _set(1, "next", _meta(f"{_NEXT_2}#results"))),
    ("whitespace", _set(1, "next", _meta(f"{_NEXT_2} "))),
    ("control-character", _set(1, "next", _meta(f"{_NEXT_2}\x00"))),
    ("duplicate-page-size", _set(1, "next", _meta(f"{_NEXT_2}&page_size=100"))),
    ("duplicate-page", _set(1, "next", _meta(f"page=2&{_NEXT_2}"))),
    ("unknown-parameter", _set(1, "next", _meta(f"{_NEXT_2}&format=json"))),
    ("missing-page-size", _set(1, "next", _meta("page=2"))),
    ("wrong-page-size", _set(1, "next", _meta("page=2&page_size=50"))),
    ("blank-page-size", _set(1, "next", _meta("page=2&page_size="))),
    ("next-without-page", _set(1, "next", _meta("page_size=100"))),
    ("malformed-query-empty-field", _set(1, "next", _meta("page=2&&page_size=100"))),
    ("malformed-query-no-equals", _set(1, "next", _meta("page&page_size=100"))),
    ("page-zero", _set(1, "next", _meta("page=0&page_size=100"))),
    ("page-leading-zero", _set(1, "next", _meta("page=02&page_size=100"))),
    ("page-negative", _set(1, "next", _meta("page=-1&page_size=100"))),
    ("page-plus-sign", _set(1, "next", _meta("page=%2B2&page_size=100"))),
    ("page-decimal", _set(1, "next", _meta("page=2.0&page_size=100"))),
    ("page-non-numeric", _set(1, "next", _meta("page=abc&page_size=100"))),
    ("page-empty", _set(1, "next", _meta("page=&page_size=100"))),
    ("page-oversized", _set(1, "next", _meta(f"page={'9' * 5000}&page_size=100"))),
    ("next-without-query", _set(1, "next", SMELT_TEST_METADATA_BASE)),
    ("next-with-empty-query", _set(1, "next", f"{SMELT_TEST_METADATA_BASE}?")),
    ("non-adjacent-next", _set(1, "next", _meta("page=3&page_size=100"))),
    ("next-designating-same-page", _set(2, "next", _meta("page=2&page_size=100"))),
    ("non-adjacent-previous", _set(3, "previous", _meta("page=1&page_size=100"))),
    ("omitted-page-in-previous-on-page-3", _set(3, "previous", _meta("page_size=100"))),
    ("previous-on-page-1", _set(1, "previous", _meta("page_size=100"))),
    ("previous-null-on-page-2", _set(2, "previous", None)),
    ("previous-null-on-final-page", _set(3, "previous", None)),
    ("next-null-on-page-1", _set(1, "next", None)),
    ("next-null-on-page-2", _set(2, "next", None)),
    ("next-on-final-page", _set(3, "next", _meta("page=4&page_size=100"))),
    ("previous-different-host", _set(2, "previous", _url("http://other.example.test"))),
]

_ENVELOPE_REJECTIONS: list[tuple[str, Mutator]] = [
    ("count-changes", _set(2, "count", 251)),
    ("total-pages-changes", _set(2, "total_pages", 4)),
    ("empty-non-final-page", _set(2, "results", [])),
    ("negative-count", _set(1, "count", -1)),
    ("zero-total-pages", _set(1, "total_pages", 0)),
    ("string-count", _set(1, "count", "250")),
    ("float-count", _set(1, "count", 250.0)),
    ("boolean-count", _set(1, "count", True)),
    ("null-count", _set(1, "count", None)),
    ("null-total-pages", _set(1, "total_pages", None)),
    ("string-total-pages", _set(1, "total_pages", "3")),
    ("boolean-total-pages", _set(1, "total_pages", True)),
    ("non-string-next", _set(1, "next", 2)),
    ("non-string-previous", _set(2, "previous", ["page=1"])),
    ("object-results", _set(1, "results", {})),
    ("null-results", _set(1, "results", None)),
    ("string-result-element", _set_result(1, "row")),
    ("integer-result-element", _set_result(1, 5)),
    ("null-result-element", _set_result(1, None)),
    ("array-result-element", _set_result(1, [])),
    ("missing-count", _delete(1, "count")),
    ("missing-total-pages", _delete(1, "total_pages")),
    ("missing-next", _delete(1, "next")),
    ("missing-previous", _delete(1, "previous")),
    ("missing-results", _delete(1, "results")),
    ("missing-null-next-on-final-page", _delete(3, "next")),
    ("top-level-array", _replace(1, [])),
    ("top-level-string", _replace(1, "count")),
    ("top-level-number", _replace(1, 250)),
    ("later-page-not-an-object", _replace(2, [])),
]


@pytest.mark.unit
class TestMetadataRejected:
    @pytest.mark.parametrize(
        "mutate",
        [case for _, case in _METADATA_REJECTIONS],
        ids=[name for name, _ in _METADATA_REJECTIONS],
    )
    async def test_invalid_continuation_metadata_rejects_the_listing(
        self, mutate: Mutator
    ) -> None:
        server = _three_pages()
        mutate(server.pages)

        error = await _fetch_invalid(server)

        assert "smelt.example.test" not in str(error)

    @pytest.mark.parametrize(
        "metadata_base",
        [
            "http://smelt.example.test/api/v1/basic/products/",
            "https://smelt.example.test/api/v1/basic/products/",
            "https://smelt.example.test:9443/api/v1/basic/products/",
            "https://smelt.example.test:443/api/v1/basic/products/",
        ],
        ids=["http-port-omitted", "https-port-omitted", "other-port", "port-443"],
    )
    async def test_explicit_setting_port_not_matched_by_metadata_is_rejected(
        self, metadata_base: str
    ) -> None:
        server = _three_pages(metadata_base=metadata_base)

        await _fetch_invalid(server, api_url=PORT_API_URL)

        assert server.requested_pages == [1]


@pytest.mark.unit
class TestEnvelopeRejected:
    @pytest.mark.parametrize(
        "mutate",
        [case for _, case in _ENVELOPE_REJECTIONS],
        ids=[name for name, _ in _ENVELOPE_REJECTIONS],
    )
    async def test_invalid_envelope_or_page_sequence_rejects_the_listing(
        self, mutate: Mutator
    ) -> None:
        server = _three_pages()
        mutate(server.pages)

        await _fetch_invalid(server)

    async def test_fewer_collected_results_than_count_is_rejected(self) -> None:
        server = _three_pages()
        _set_all("count", 251)(server.pages)

        await _fetch_invalid(server)

        assert server.requested_pages == [1, 2, 3]

    async def test_more_collected_results_than_count_is_rejected(self) -> None:
        server = _three_pages()
        _set_all("count", 249)(server.pages)

        await _fetch_invalid(server)

        assert server.requested_pages == [1, 2, 3]

    async def test_excess_results_stop_retrieval_before_the_final_page(self) -> None:
        server = _three_pages()
        _set_all("count", 150)(server.pages)

        await _fetch_invalid(server)

        assert server.requested_pages == [1, 2]

    async def test_top_level_json_null_is_rejected(self) -> None:
        server = _three_pages()
        server.responses[1] = lambda request: httpx.Response(200, content=b"null")

        error = await _fetch_invalid(server)

        assert "envelope" in str(error.__cause__)

    async def test_non_json_body_is_rejected(self) -> None:
        server = _three_pages()
        server.responses[2] = lambda request: httpx.Response(
            200, content=b"<html>maintenance</html>"
        )

        await _fetch_invalid(server)

    async def test_undecodable_body_is_an_invalid_response(self) -> None:
        """`httpx.DecodingError` maps to the invalid-response message (D2),
        not to a connection failure."""
        server = _three_pages()
        server.responses[1] = lambda request: httpx.Response(
            200,
            headers={"content-encoding": "gzip"},
            stream=httpx.ByteStream(b"not gzip at all"),
        )

        error = await _fetch_invalid(server)

        assert "undecodable" in str(error.__cause__)

    async def test_invalid_page_stops_further_requests(self) -> None:
        server = SmeltServer.for_rows(make_rows(350))
        server.pages[3]["count"] = 351

        await _fetch_invalid(server)

        assert server.requested_pages == [1, 2, 3]


# ---------------------------------------------------------------------------
# Transport and HTTP failures (Error Handling, D2)
# ---------------------------------------------------------------------------


def _raise(error: type[httpx.TransportError]) -> Callable[[httpx.Request], Any]:
    def respond(request: httpx.Request) -> httpx.Response:
        raise error("example failure to smelt.example.test", request=request)

    return respond


@pytest.mark.unit
class TestTransportFailures:
    @pytest.mark.parametrize("status_code", [404, 500, 503, 401])
    async def test_non_success_status_raises_http_status_message(
        self, status_code: int
    ) -> None:
        server = _three_pages()
        server.responses[1] = lambda request: httpx.Response(status_code)

        with pytest.raises(FetcherError) as raised:
            await _fetch(server)

        assert str(raised.value) == f"SMELT returned HTTP {status_code}"
        assert isinstance(raised.value.__cause__, httpx.HTTPStatusError)

    async def test_redirect_is_not_followed(self) -> None:
        server = _three_pages()
        server.responses[1] = lambda request: httpx.Response(
            302, headers={"Location": "https://other.example.test/elsewhere"}
        )

        with pytest.raises(FetcherError) as raised:
            await _fetch(server)

        assert str(raised.value) == "SMELT returned HTTP 302"
        assert isinstance(raised.value.__cause__, httpx.HTTPStatusError)
        assert len(server.requests) == 1

    @pytest.mark.parametrize(
        ("error", "message"),
        [
            (httpx.ConnectError, "Failed to connect to SMELT"),
            (httpx.ReadError, "Failed to connect to SMELT"),
            (httpx.RemoteProtocolError, "Failed to connect to SMELT"),
            (httpx.ReadTimeout, "SMELT request timed out"),
            (httpx.ConnectTimeout, "SMELT request timed out"),
            (httpx.PoolTimeout, "SMELT request timed out"),
        ],
        ids=lambda value: value if isinstance(value, str) else value.__name__,
    )
    async def test_transport_error_raises_sanitized_chained_message(
        self, error: type[httpx.TransportError], message: str
    ) -> None:
        server = _three_pages()
        server.responses[2] = _raise(error)

        with pytest.raises(FetcherError) as raised:
            await _fetch(server)

        assert str(raised.value) == message
        assert isinstance(raised.value.__cause__, error)
        assert server.requested_pages == [1, 2]

    async def test_failure_on_page_three_of_four_stops_further_requests(
        self,
    ) -> None:
        server = SmeltServer.for_rows(make_rows(350))
        server.responses[3] = lambda request: httpx.Response(500)

        with pytest.raises(FetcherError, match=r"^SMELT returned HTTP 500$"):
            await _fetch(server)

        assert server.requested_pages == [1, 2, 3]


# ---------------------------------------------------------------------------
# Logs (Error Handling: failed page and category, no payload)
# ---------------------------------------------------------------------------

_MARKER = "Example-Confidential-Row-Value"


def _marked_server() -> SmeltServer:
    server = SmeltServer.for_rows(
        [
            {**row, "name": _MARKER, "friendly_name": _MARKER, "repos": [_MARKER]}
            for row in make_rows(250)
        ]
    )
    return server


@pytest.mark.unit
class TestFailureLogs:
    async def test_invalid_page_log_names_page_and_category_without_payload(
        self,
    ) -> None:
        server = _marked_server()
        server.pages[2]["results"][0] = _MARKER

        with capture_logs() as logs, pytest.raises(FetcherError):
            await _fetch(server)

        (entry,) = [
            log
            for log in logs
            if log["event"] == "smelt_product_catalog_response_invalid"
        ]
        assert entry["page"] == 2
        assert entry["log_level"] == "warning"
        assert entry["category"].startswith("page 2: invalid response schema")
        assert _MARKER not in repr(logs)

    async def test_metadata_rule_log_names_the_violated_rule(self) -> None:
        server = _marked_server()
        server.pages[1]["next"] = _meta(f"{_NEXT_2}&{_MARKER}=1")

        with capture_logs() as logs, pytest.raises(FetcherError):
            await _fetch(server)

        (entry,) = logs
        assert entry["event"] == "smelt_product_catalog_response_invalid"
        assert entry["page"] == 1
        assert entry["category"] == "page 1: next has an unknown query parameter"
        assert _MARKER not in repr(logs)
        assert "smelt.example.test" not in repr(logs)

    async def test_count_mismatch_log_names_the_final_page(self) -> None:
        server = _marked_server()
        _set_all("count", 251)(server.pages)

        with capture_logs() as logs, pytest.raises(FetcherError):
            await _fetch(server)

        (entry,) = logs
        assert entry["page"] == 3
        assert entry["category"] == "collected 250 results but count is 251"

    async def test_http_status_log_names_page_category_and_status(self) -> None:
        server = _marked_server()
        server.responses[2] = lambda request: httpx.Response(
            500, json={"detail": _MARKER}
        )

        with capture_logs() as logs, pytest.raises(FetcherError):
            await _fetch(server)

        assert logs == [
            {
                "event": "smelt_product_catalog_request_failed",
                "log_level": "warning",
                "page": 2,
                "category": "http_status",
                "status_code": 500,
            }
        ]

    @pytest.mark.parametrize(
        ("error", "category"),
        [(httpx.ConnectError, "connection"), (httpx.ReadTimeout, "timeout")],
    )
    async def test_transport_log_names_page_and_category(
        self, error: type[httpx.TransportError], category: str
    ) -> None:
        server = _marked_server()
        server.responses[3] = _raise(error)

        with capture_logs() as logs, pytest.raises(FetcherError):
            await _fetch(server)

        assert logs == [
            {
                "event": "smelt_product_catalog_request_failed",
                "log_level": "warning",
                "page": 3,
                "category": category,
            }
        ]

    async def test_non_json_body_log_contains_no_body(self) -> None:
        server = _marked_server()
        server.responses[1] = lambda request: httpx.Response(
            200, content=_MARKER.encode()
        )

        with capture_logs() as logs, pytest.raises(FetcherError):
            await _fetch(server)

        (entry,) = logs
        assert entry["page"] == 1
        assert entry["category"] == "page 1: body is not valid JSON"
        assert _MARKER not in repr(logs)

    async def test_successful_retrieval_logs_nothing(self) -> None:
        with capture_logs() as logs:
            await _fetch(_marked_server())

        assert logs == []
