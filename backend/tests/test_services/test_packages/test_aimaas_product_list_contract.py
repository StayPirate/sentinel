"""Contract tests for the AIMAAS `entity/products?all_fields=true` list.

Contract under test: docs/features/packages/product-catalog.md (AIMAAS
Integration > Origin, Authentication, and Pagination; Deleted Flag
Semantics; Product Lifecycle Sync, consumed and ignored fields, matching)
and docs/data-sources.md (AIMAAS), verified against live pages captured
from the default `AIMAAS_API_URL` with `size=100` (docs/conventions.md,
External Integration Contract Verification). Every field Sentinel consumes
is asserted for name, JSON type, nullability, and date representation.

The parser-backed tests at the end serve the captured pages through
`fetch_aimaas_products()` and parse the captured items with
`parse_lifecycle_entries()` and `validate_lifecycle_entries()` to prove
that the live envelope and the live items are accepted as specified and
projected with the documented field mapping.
"""

from __future__ import annotations

import re
from datetime import date
from typing import Any, Final

import pytest

from app.services.packages.aimaas_listing import fetch_aimaas_products
from app.services.packages.sync_aimaas_lifecycle import (
    LifecycleDates,
    parse_lifecycle_entries,
    validate_lifecycle_entries,
)
from app.services.product_lifecycle import LifecycleDateViolation
from tests.support.aimaas import (
    AIMAAS_TEST_API_URL,
    FIXTURE_PAGES,
    PAGE_SIZE,
    PRODUCT_LIST_PAGES,
    AimaasServer,
    load_products_page,
)

_TOTAL: Final = 475
_PAGES: Final = 5
_DATE_FIELDS: Final = (
    "fcs",
    "end_of_gs",
    "end_of_ltss",
    "end_of_espos",
    "end_of_reactive_ltss",
)
_IGNORED_FIELDS: Final = (
    "slug",
    "name",
    "id",
    "deleted",
    "version",
    "tracked_in_bz",
    "end_of_lts_core",
    "beta_release",
)
_ISO_DATE: Final = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")


def _all_items() -> list[dict[str, Any]]:
    return [
        item for page in FIXTURE_PAGES for item in load_products_page(page)["items"]
    ]


@pytest.mark.unit
class TestEnvelope:
    @pytest.mark.parametrize("page", FIXTURE_PAGES)
    def test_page_has_the_paginated_envelope(self, page: int) -> None:
        data = load_products_page(page)

        assert set(data) == {"items", "total", "page", "size", "pages"}
        for field in ("total", "page", "size", "pages"):
            assert type(data[field]) is int
        assert isinstance(data["items"], list)
        assert all(isinstance(item, dict) for item in data["items"])

    @pytest.mark.parametrize("page", FIXTURE_PAGES)
    def test_page_and_size_echo_the_request(self, page: int) -> None:
        data = load_products_page(page)

        assert data["page"] == page
        assert data["size"] == PAGE_SIZE

    def test_total_and_pages_are_constant_across_pages(self) -> None:
        pages = [load_products_page(page) for page in FIXTURE_PAGES]

        assert {data["total"] for data in pages} == {_TOTAL}
        assert {data["pages"] for data in pages} == {_PAGES}

    def test_non_final_pages_are_full_and_final_page_holds_the_remainder(
        self,
    ) -> None:
        assert len(load_products_page(1)["items"]) == PAGE_SIZE
        assert len(load_products_page(3)["items"]) == PAGE_SIZE
        assert len(load_products_page(_PAGES)["items"]) == (
            _TOTAL - (_PAGES - 1) * PAGE_SIZE
        )

    def test_page_beyond_pages_is_empty_with_correct_metadata(self) -> None:
        data = load_products_page(_PAGES + 1)

        assert data["items"] == []
        assert (data["total"], data["pages"]) == (_TOTAL, _PAGES)


@pytest.mark.unit
class TestConsumedItemFields:
    def test_cpe_is_a_non_empty_string(self) -> None:
        for item in _all_items():
            assert isinstance(item["cpe"], str)
            assert item["cpe"] != ""

    def test_cpes_are_unique(self) -> None:
        items = _all_items()

        assert len({item["cpe"] for item in items}) == len(items)

    @pytest.mark.parametrize("field", _DATE_FIELDS)
    def test_date_fields_are_present_iso_dates_or_null(self, field: str) -> None:
        for item in _all_items():
            value = item[field]
            if value is not None:
                assert isinstance(value, str)
                assert _ISO_DATE.fullmatch(value)
                date.fromisoformat(value)

    @pytest.mark.parametrize("field", _DATE_FIELDS)
    def test_every_date_field_has_both_values_and_nulls_live(self, field: str) -> None:
        values = [item[field] for item in _all_items()]

        assert any(value is None for value in values)
        assert any(value is not None for value in values)

    def test_default_list_contains_no_deleted_entries(self) -> None:
        assert all(item["deleted"] is False for item in _all_items())

    def test_items_contain_only_consumed_and_ignored_fields(self) -> None:
        for item in _all_items():
            assert set(item) == {"cpe", *_DATE_FIELDS, *_IGNORED_FIELDS}


# ---------------------------------------------------------------------------
# Parser-backed contract: the live envelope and items are accepted
# ---------------------------------------------------------------------------

_INVALID: Final = "AIMAAS returned invalid Product lifecycle response"

# The one captured item whose dates violate a Lifecycle Evaluator rule: an
# `end_of_ltss` without `end_of_gs` (verified from the captured fixtures).
_INCONSISTENT_CAPTURED_CPE: Final = "cpe:/o:suse:sles-ltss-core:12:sp5"


def _live_listing_server() -> AimaasServer:
    """Serve every captured Product list page verbatim."""
    return AimaasServer({page: load_products_page(page) for page in PRODUCT_LIST_PAGES})


def _optional_date(value: str | None) -> date | None:
    return None if value is None else date.fromisoformat(value)


def _expected_projection(item: dict[str, Any]) -> LifecycleDates:
    """The documented field mapping, transcribed from the raw JSON."""
    ltss, espos = item["end_of_ltss"], item["end_of_espos"]
    extended: date | None
    if ltss is not None and espos is not None:
        extended = max(date.fromisoformat(ltss), date.fromisoformat(espos))
    else:
        extended = _optional_date(ltss if ltss is not None else espos)
    return LifecycleDates(
        first_customer_ship_date=_optional_date(item["fcs"]),
        general_support_end_date=_optional_date(item["end_of_gs"]),
        extended_support_end_date=extended,
        reactive_support_end_date=_optional_date(item["end_of_reactive_ltss"]),
    )


@pytest.mark.unit
class TestLiveSerializationAccepted:
    async def test_live_pages_pass_pagination_validation(self) -> None:
        server = _live_listing_server()

        async with server.client() as client:
            listing = await fetch_aimaas_products(
                client,
                api_url=AIMAAS_TEST_API_URL,
                request_delay=0,
                invalid_message=_INVALID,
            )

        assert listing.total == _TOTAL
        assert len(listing.items) == _TOTAL
        assert server.requested_pages == [1, 2, 3, 4, 5]
        assert listing.items == [
            item
            for page in PRODUCT_LIST_PAGES
            for item in load_products_page(page)["items"]
        ]

    def test_live_items_parse_with_the_documented_field_mapping(self) -> None:
        items = _all_items()

        entries = parse_lifecycle_entries(items)

        assert len(entries) == len(items)
        for item, entry in zip(items, entries, strict=True):
            assert entry.cpe is not None
            assert entry.cpe == item["cpe"]
            assert entry.dates == _expected_projection(item)

    def test_live_items_pass_complete_response_validation(self) -> None:
        items = _all_items()

        projections = validate_lifecycle_entries(parse_lifecycle_entries(items))

        assert projections == {
            item["cpe"]: _expected_projection(item) for item in items
        }

    def test_live_items_map_both_extended_sources(self) -> None:
        """The captured data exercises `end_of_ltss` and `end_of_espos` as
        the extended-support source."""
        entries = {entry.cpe: entry for entry in parse_lifecycle_entries(_all_items())}
        sources = {
            field
            for item in _all_items()
            for field in ("end_of_ltss", "end_of_espos")
            if item[field] is not None
            and entries[item["cpe"]].dates.extended_support_end_date
            == date.fromisoformat(item[field])
        }

        assert sources == {"end_of_ltss", "end_of_espos"}

    def test_only_the_known_inconsistent_live_item_reports_violations(self) -> None:
        projections = validate_lifecycle_entries(parse_lifecycle_entries(_all_items()))

        inconsistent = {
            cpe: dates.violations()
            for cpe, dates in projections.items()
            if dates.violations()
        }

        assert inconsistent == {
            _INCONSISTENT_CAPTURED_CPE: (
                LifecycleDateViolation.MISSING_GENERAL_SUPPORT_END_DATE,
            )
        }
