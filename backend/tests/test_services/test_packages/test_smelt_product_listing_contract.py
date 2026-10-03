"""Contract tests for the SMELT `v1/basic/products/` listing.

Contract under test: docs/features/packages/product-catalog.md (SMELT
Integration, Origin, Authentication, and Pagination; Product Sync,
"Response fields used") and docs/data-sources.md (SMELT, Contract
characteristics), verified against sanitized live pages captured from
the default `SMELT_API_URL` (docs/conventions.md, External Integration
Contract Verification). Every field Sentinel consumes is asserted for
name, type, nullability, and the continuation-metadata URL form.

The parser-backed tests at the end serve the captured pages through
`fetch_product_listing()` and `validate_snapshot()` to prove that the
live serialization (the `http` metadata scheme and the omitted `page` in
page 2's `previous`) and the live rows are accepted as specified.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest

from app.services.packages.smelt_product_listing import (
    SmeltProductListing,
    fetch_product_listing,
)
from app.services.packages.sync_smelt_products import (
    CatalogProduct,
    validate_snapshot,
)
from tests.support.smelt import FIXTURE_PAGES, SmeltServer, load_products_page

_TOTAL_PAGES = 6
_PAGE_SIZE = "100"


def _metadata_page(url: str) -> int:
    """Return the page number a continuation URL designates (omitted = 1)."""
    query = parse_qs(urlsplit(url).query, keep_blank_values=True)
    return int(query["page"][0]) if "page" in query else 1


@pytest.mark.unit
class TestEnvelope:
    @pytest.mark.parametrize("page", FIXTURE_PAGES)
    def test_page_has_the_paginated_envelope(self, page: int) -> None:
        data = load_products_page(page)

        assert {"count", "total_pages", "next", "previous", "results"} <= set(data)
        assert type(data["count"]) is int
        assert data["count"] > 0
        assert type(data["total_pages"]) is int
        assert data["total_pages"] == _TOTAL_PAGES
        assert isinstance(data["results"], list)

    def test_count_and_total_pages_are_constant_across_pages(self) -> None:
        pages = [load_products_page(page) for page in FIXTURE_PAGES]

        assert len({data["count"] for data in pages}) == 1
        assert len({data["total_pages"] for data in pages}) == 1

    def test_non_final_pages_are_full_and_final_page_holds_the_remainder(
        self,
    ) -> None:
        count = load_products_page(1)["count"]

        assert len(load_products_page(1)["results"]) == int(_PAGE_SIZE)
        assert len(load_products_page(2)["results"]) == int(_PAGE_SIZE)
        assert len(load_products_page(6)["results"]) == count - 5 * int(_PAGE_SIZE)


@pytest.mark.unit
class TestContinuationMetadata:
    def test_first_page_has_null_previous_and_next_page_two(self) -> None:
        data = load_products_page(1)

        assert data["previous"] is None
        assert isinstance(data["next"], str)
        assert _metadata_page(data["next"]) == 2

    def test_final_page_has_null_next(self) -> None:
        data = load_products_page(6)

        assert data["next"] is None
        assert isinstance(data["previous"], str)
        assert _metadata_page(data["previous"]) == 5

    def test_previous_of_page_two_omits_the_page_parameter(self) -> None:
        previous = load_products_page(2)["previous"]

        assert isinstance(previous, str)
        assert parse_qs(urlsplit(previous).query) == {"page_size": [_PAGE_SIZE]}

    @pytest.mark.parametrize(
        ("page", "field"),
        [(1, "next"), (2, "next"), (2, "previous"), (6, "previous")],
    )
    def test_metadata_uses_the_known_http_scheme_defect_and_expected_shape(
        self, page: int, field: str
    ) -> None:
        url = load_products_page(page)[field]
        parsed = urlsplit(url)
        query = parse_qs(parsed.query, keep_blank_values=True)

        assert parsed.scheme == "http"
        assert parsed.hostname == "smelt.suse.de"
        assert parsed.port is None
        assert parsed.username is None
        assert parsed.path == "/api/v1/basic/products/"
        assert parsed.fragment == ""
        assert set(query) <= {"page", "page_size"}
        assert query["page_size"] == [_PAGE_SIZE]
        assert all(len(values) == 1 for values in query.values())


def _all_rows() -> list[dict[str, Any]]:
    return [
        row for page in FIXTURE_PAGES for row in load_products_page(page)["results"]
    ]


@pytest.mark.unit
class TestConsumedRowFields:
    @pytest.mark.parametrize("field", ["name", "version", "cpe", "friendly_name"])
    def test_descriptive_fields_are_non_empty_strings(self, field: str) -> None:
        for row in _all_rows():
            assert isinstance(row[field], str)
            assert row[field] != ""

    def test_repos_are_non_empty_arrays_of_non_empty_strings(self) -> None:
        for row in _all_rows():
            assert isinstance(row["repos"], list)
            assert row["repos"]
            assert all(isinstance(repo, str) and repo for repo in row["repos"])

    def test_cpes_are_unique_and_repositories_are_not_repeated_within_a_product(
        self,
    ) -> None:
        rows = _all_rows()

        assert len({row["cpe"] for row in rows}) == len(rows)
        for row in rows:
            assert len(set(row["repos"])) == len(row["repos"])

    def test_a_repository_may_be_shared_by_several_products(self) -> None:
        owners: dict[str, int] = {}
        for row in _all_rows():
            for repo in row["repos"]:
                owners[repo] = owners.get(repo, 0) + 1

        assert any(total > 1 for total in owners.values())

    def test_ignored_fields_are_present_upstream(self) -> None:
        for row in _all_rows():
            assert {"id", "end_of_life", "changed", "details"} <= set(row)


# ---------------------------------------------------------------------------
# Parser-backed contract: the live serialization is accepted
# ---------------------------------------------------------------------------

_LIVE_API_URL = "https://smelt.suse.de/api"


def _live_listing_server() -> SmeltServer:
    """Serve the captured pages verbatim at pages 1, 2, and 6.

    Pages 3-5 were not captured; they repeat page 2's rows with
    continuation metadata rewritten in the captured serialization (the
    metadata base of page 1's `next`, explicit `page` first).
    """
    pages: dict[int, Any] = {page: load_products_page(page) for page in FIXTURE_PAGES}
    base = load_products_page(1)["next"].split("?", 1)[0]
    for page in (3, 4, 5):
        pages[page] = {
            **load_products_page(2),
            "next": f"{base}?page={page + 1}&page_size={_PAGE_SIZE}",
            "previous": f"{base}?page={page - 1}&page_size={_PAGE_SIZE}",
        }
    return SmeltServer(pages)


@pytest.mark.unit
class TestLiveSerializationAccepted:
    async def test_live_pages_pass_pagination_validation(self) -> None:
        server = _live_listing_server()

        async with server.client() as client:
            listing = await fetch_product_listing(
                client, api_url=_LIVE_API_URL, request_delay=0
            )

        assert listing.count == load_products_page(1)["count"] == 556
        assert len(listing.results) == 556
        assert server.requested_pages == [1, 2, 3, 4, 5, 6]
        assert listing.results[:100] == load_products_page(1)["results"]
        assert listing.results[100:200] == load_products_page(2)["results"]
        assert listing.results[500:] == load_products_page(6)["results"]
        assert all(
            url.startswith(f"{_LIVE_API_URL}/v1/basic/products/?")
            for url in server.requested_urls
        )

    def test_live_rows_pass_complete_snapshot_validation_unchanged(self) -> None:
        rows = _all_rows()

        products = validate_snapshot(SmeltProductListing(count=len(rows), results=rows))

        assert products == [
            CatalogProduct(
                cpe=row["cpe"],
                name=row["name"],
                version=row["version"],
                display_name=row["friendly_name"],
                repos=tuple(row["repos"]),
            )
            for row in rows
        ]
