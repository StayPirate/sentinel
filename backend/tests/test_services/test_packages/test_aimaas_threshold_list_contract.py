"""Contract tests for the AIMAAS `entity/cvss-threshold` list and its join.

Contract under test: docs/features/packages/product-catalog.md (AIMAAS
Integration > Origin, Authentication, and Pagination; Deleted Flag
Semantics; CVSS Threshold Sync, consumed and ignored fields, consumed-field
schema, CPE resolution through the in-memory join) and docs/data-sources.md
(AIMAAS), verified against live pages captured from the default
`AIMAAS_API_URL` with `size=100` (docs/conventions.md, External Integration
Contract Verification). Every field Sentinel consumes is asserted for name,
JSON type, nullability, and range: the threshold envelope, `product`,
`threshold`, and the Product list `id` and `cpe` used by the join.
"""

from __future__ import annotations

import math
from decimal import Decimal
from typing import Any, Final

import pytest

from tests.support.aimaas import (
    PAGE_SIZE,
    PRODUCT_LIST_PAGES,
    THRESHOLD_FIXTURE_PAGES,
    load_products_page,
    load_thresholds_page,
)

_TOTAL: Final = 24
_PAGES: Final = 1
_PRODUCT_TOTAL: Final = 475
_CONSUMED_FIELDS: Final = ("product", "threshold")
_IGNORED_FIELDS: Final = ("slug", "name", "id", "deleted")

# The one captured threshold whose AIMAAS Product ID is absent from the
# complete default Product list (verified from the captured fixtures).
_UNRESOLVED_CAPTURED_PRODUCT_ID: Final = 216


def _thresholds() -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = load_thresholds_page(1)["items"]
    return items


def _products() -> list[dict[str, Any]]:
    return [
        item
        for page in PRODUCT_LIST_PAGES
        for item in load_products_page(page)["items"]
    ]


@pytest.mark.unit
class TestThresholdEnvelope:
    @pytest.mark.parametrize("page", THRESHOLD_FIXTURE_PAGES)
    def test_page_has_the_paginated_envelope(self, page: int) -> None:
        data = load_thresholds_page(page)

        assert set(data) == {"items", "total", "page", "size", "pages"}
        for field in ("total", "page", "size", "pages"):
            assert type(data[field]) is int
        assert isinstance(data["items"], list)
        assert all(isinstance(item, dict) for item in data["items"])

    @pytest.mark.parametrize("page", THRESHOLD_FIXTURE_PAGES)
    def test_page_and_size_echo_the_request(self, page: int) -> None:
        data = load_thresholds_page(page)

        assert data["page"] == page
        assert data["size"] == PAGE_SIZE

    def test_total_and_pages_are_constant_across_pages(self) -> None:
        pages = [load_thresholds_page(page) for page in THRESHOLD_FIXTURE_PAGES]

        assert {data["total"] for data in pages} == {_TOTAL}
        assert {data["pages"] for data in pages} == {_PAGES}

    def test_single_final_page_holds_the_complete_collection(self) -> None:
        assert len(_thresholds()) == _TOTAL - (_PAGES - 1) * PAGE_SIZE

    def test_page_beyond_pages_is_empty_with_correct_metadata(self) -> None:
        data = load_thresholds_page(_PAGES + 1)

        assert data["items"] == []
        assert (data["total"], data["pages"]) == (_TOTAL, _PAGES)


@pytest.mark.unit
class TestThresholdItemFields:
    def test_items_contain_only_consumed_and_ignored_fields(self) -> None:
        for item in _thresholds():
            assert set(item) == {*_CONSUMED_FIELDS, *_IGNORED_FIELDS}

    def test_product_is_an_integer(self) -> None:
        for item in _thresholds():
            assert type(item["product"]) is int

    def test_product_ids_are_unique(self) -> None:
        products = [item["product"] for item in _thresholds()]

        assert len(set(products)) == len(products)

    def test_threshold_is_a_json_number(self) -> None:
        for item in _thresholds():
            assert type(item["threshold"]) in (int, float)
            assert math.isfinite(item["threshold"])

    def test_threshold_is_representable_at_one_decimal_within_range(self) -> None:
        for item in _thresholds():
            value = Decimal(repr(item["threshold"]))

            assert Decimal("0.0") <= value <= Decimal("10.0")
            assert value == value.quantize(Decimal("0.1"))

    def test_default_list_contains_no_deleted_entries(self) -> None:
        assert all(item["deleted"] is False for item in _thresholds())


@pytest.mark.unit
class TestProductListJoinFields:
    def test_complete_product_list_is_captured(self) -> None:
        pages = [load_products_page(page) for page in PRODUCT_LIST_PAGES]

        assert {data["total"] for data in pages} == {_PRODUCT_TOTAL}
        assert len(_products()) == _PRODUCT_TOTAL

    def test_product_id_is_a_unique_integer(self) -> None:
        ids = [item["id"] for item in _products()]

        assert all(type(value) is int for value in ids)
        assert len(set(ids)) == len(ids)

    def test_product_cpe_is_a_unique_non_empty_string(self) -> None:
        cpes = [item["cpe"] for item in _products()]

        assert all(isinstance(cpe, str) and cpe for cpe in cpes)
        assert len(set(cpes)) == len(cpes)

    def test_every_threshold_but_one_resolves_through_the_product_list(
        self,
    ) -> None:
        ids = {item["id"] for item in _products()}

        unresolved = [
            item["product"] for item in _thresholds() if item["product"] not in ids
        ]

        assert unresolved == [_UNRESOLVED_CAPTURED_PRODUCT_ID]

    def test_resolved_thresholds_map_to_distinct_cpes(self) -> None:
        cpe_by_id = {item["id"]: item["cpe"] for item in _products()}

        resolved = [
            cpe_by_id[item["product"]]
            for item in _thresholds()
            if item["product"] in cpe_by_id
        ]

        assert len(resolved) == _TOTAL - 1
        assert len(set(resolved)) == len(resolved)
