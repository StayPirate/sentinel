"""Contract tests for the AIMAAS `entity/products?all_fields=true` list.

Contract under test: docs/features/packages/product-catalog.md (AIMAAS
Integration > Origin, Authentication, and Pagination; Deleted Flag
Semantics; Product Lifecycle Sync, consumed and ignored fields, matching)
and docs/data-sources.md (AIMAAS), verified against live pages captured
from the default `AIMAAS_API_URL` with `size=100` (docs/conventions.md,
External Integration Contract Verification). Every field Sentinel consumes
is asserted for name, JSON type, nullability, and date representation.
"""

from __future__ import annotations

import re
from datetime import date
from typing import Any, Final

import pytest

from tests.support.aimaas import FIXTURE_PAGES, PAGE_SIZE, load_products_page

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

    def test_ignored_fields_are_present_upstream(self) -> None:
        for item in _all_items():
            assert set(_IGNORED_FIELDS) <= set(item)

    def test_items_contain_only_consumed_and_ignored_fields(self) -> None:
        for item in _all_items():
            assert set(item) == {"cpe", *_DATE_FIELDS, *_IGNORED_FIELDS}
