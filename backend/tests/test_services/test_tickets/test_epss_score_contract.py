"""Contract tests for the FIRST.org EPSS single-CVE endpoint.

Contract under test: docs/features/tickets/cve-sync-epss.md (Algorithm,
Field Mapping, Explicitly Ignored Fields, Error Handling) and
docs/data-sources.md (EPSS), verified against live responses captured
anonymously on 2026-10-06 through Sentinel's production HTTP client
(`create_http_client(name="sync_epss_scores")`, its standard User-Agent;
docs/conventions.md, External Integration Contract Verification). Every
consumed field is asserted for name, nesting, type, and encoding through
a strict test-local typed model; the production parser does not exist
yet.

Live verification on 2026-10-06 (`GET /data/v1/epss?cve={CVE-ID}`):

- 24 requests: 20 scored public CVE-IDs published 1999-2026 and 4
  syntactically valid CVE-IDs that EPSS does not score. Every response was
  HTTP 200 `application/json; charset=utf-8`, and none redirected.
- The root is always an object with exactly `status`, `status-code`,
  `version`, `access`, `total`, `offset`, `limit`, and `data`. `total`
  equals the length of `data`.
- Every scored response has exactly one `data[]` entry with exactly
  `cve`, `epss`, `percentile`, and `date`, all strings. `cve` echoes the
  queried CVE-ID; `epss` and `percentile` are unsigned decimals with nine
  fractional digits in [0, 1] (one percentile was exactly
  `"1.000000000"`); `date` is `YYYY-MM-DD` and identical across all
  responses of the day. No `time-series` member was present.
- Every unscored response has `total: 0` and `data: []`.

Not observable live, and therefore covered by the fetcher unit tests only:
more than one `data[]` entry; a missing, `null`, or non-string consumed
field; a sign, exponent, whitespace, `NaN`, or out-of-range value; an
invalid calendar date; a non-object root or missing `data`; a non-JSON
body; non-200 statuses; and U+0000 in any string.
"""

from __future__ import annotations

import math
import re
from datetime import date
from typing import Any, TypedDict

import pytest
from pydantic import TypeAdapter, ValidationError

from app.services.cve_ingest import EPSSEntry
from tests.support.epss import (
    ALL_FIXTURES,
    SCORED_FIXTURES,
    UNSCORED_FIXTURE,
    load_fixture,
    load_raw_fixture,
)

_DECIMAL = re.compile(r"[0-9]+(\.[0-9]+)?")
_DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
_FIXTURE_CVE_IDS = {
    "scored": "CVE-2024-6387",
    "scored_percentile_one": "CVE-2021-44228",
    "scored_low": "CVE-2026-0001",
}
_ENVELOPE_KEYS = frozenset(
    {"status", "status-code", "version", "access", "total", "offset", "limit", "data"}
)
"""`data` plus every envelope field of § Explicitly Ignored Fields."""
_ENTRY_KEYS = frozenset({"cve", "epss", "percentile", "date"})


class _Entry(TypedDict):
    epss: str
    percentile: str
    date: str


class _Response(TypedDict):
    """The consumed fields as observed live. Unconsumed fields are ignored."""

    data: list[_Entry]


_RESPONSE = TypeAdapter(_Response)


def _validated(body: Any) -> _Response:
    return _RESPONSE.validate_python(body, strict=True)


def _strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [s for key, item in value.items() for s in (key, *_strings(item))]
    if isinstance(value, list):
        return [s for item in value for s in _strings(item)]
    return []


@pytest.mark.unit
class TestTypedResponse:
    @pytest.mark.parametrize("name", ALL_FIXTURES)
    def test_root_is_an_object_with_the_documented_members(self, name: str) -> None:
        body = load_fixture(name)

        assert isinstance(body, dict)
        assert set(body) == _ENVELOPE_KEYS

    @pytest.mark.parametrize("name", ALL_FIXTURES)
    def test_consumed_fields_validate_strictly_without_coercion(
        self, name: str
    ) -> None:
        validated = _validated(load_fixture(name))

        assert len(validated["data"]) <= 1

    @pytest.mark.parametrize(
        "entry",
        [
            {"epss": 0.5, "percentile": "0.5", "date": "2026-10-06"},
            {"epss": "0.5", "percentile": None, "date": "2026-10-06"},
            {"epss": "0.5", "percentile": "0.5"},
        ],
        ids=["number-score", "null-percentile", "missing-date"],
    )
    def test_typed_model_rejects_a_mistyped_or_missing_consumed_field(
        self, entry: dict[str, Any]
    ) -> None:
        with pytest.raises(ValidationError):
            _validated({"data": [entry]})

    @pytest.mark.parametrize("name", ALL_FIXTURES)
    def test_no_string_contains_nul(self, name: str) -> None:
        assert all("\x00" not in s for s in _strings(load_fixture(name)))


@pytest.mark.unit
class TestScoredEntry:
    @pytest.mark.parametrize("name", SCORED_FIXTURES)
    def test_data_holds_exactly_one_entry_and_total_matches(self, name: str) -> None:
        body = load_fixture(name)

        assert len(body["data"]) == 1
        assert body["total"] == 1

    @pytest.mark.parametrize("name", SCORED_FIXTURES)
    def test_entry_has_exactly_the_mapped_and_redundant_members(
        self, name: str
    ) -> None:
        entry = load_fixture(name)["data"][0]

        assert set(entry) == _ENTRY_KEYS
        assert "time-series" not in entry

    @pytest.mark.parametrize("name", SCORED_FIXTURES)
    def test_cve_member_echoes_the_queried_cve_id(self, name: str) -> None:
        assert load_fixture(name)["data"][0]["cve"] == _FIXTURE_CVE_IDS[name]

    @pytest.mark.parametrize("name", SCORED_FIXTURES)
    @pytest.mark.parametrize("field", ["epss", "percentile"])
    def test_score_fields_are_unsigned_decimals_within_the_unit_interval(
        self, name: str, field: str
    ) -> None:
        value = load_fixture(name)["data"][0][field]

        assert isinstance(value, str)
        assert _DECIMAL.fullmatch(value)
        assert 0.0 <= float(value) <= 1.0
        assert math.isfinite(float(value))

    @pytest.mark.parametrize("name", SCORED_FIXTURES)
    def test_date_is_an_iso_calendar_date(self, name: str) -> None:
        value = load_fixture(name)["data"][0]["date"]

        assert _DATE.fullmatch(value)
        assert date.fromisoformat(value).isoformat() == value

    def test_date_is_a_batch_level_value_shared_by_every_entry(self) -> None:
        dates = {load_fixture(name)["data"][0]["date"] for name in SCORED_FIXTURES}

        assert len(dates) == 1

    def test_percentile_upper_bound_is_published_inclusively(self) -> None:
        entry = load_fixture("scored_percentile_one")["data"][0]

        assert entry["percentile"] == "1.000000000"

    @pytest.mark.parametrize("name", SCORED_FIXTURES)
    def test_converted_entry_satisfies_the_epss_entry_contract(self, name: str) -> None:
        entry = load_fixture(name)["data"][0]

        converted = EPSSEntry.model_validate(
            {
                "score": entry["epss"],
                "percentile": entry["percentile"],
                "assessed_at": entry["date"],
            }
        )

        assert converted.score == float(entry["epss"])
        assert converted.percentile == float(entry["percentile"])
        assert converted.assessed_at == date.fromisoformat(entry["date"])


@pytest.mark.unit
class TestUnscoredResponse:
    def test_unscored_cve_id_has_an_empty_data_array(self) -> None:
        body = load_fixture(UNSCORED_FIXTURE)

        assert body["data"] == []
        assert body["total"] == 0

    def test_unscored_body_is_stored_as_served(self) -> None:
        raw = load_raw_fixture(UNSCORED_FIXTURE)

        assert raw.endswith(b'"data":[]}\n')


@pytest.mark.unit
class TestIgnoredEnvelope:
    """§ Explicitly Ignored Fields: the envelope members are present but
    never consumed; their observed values document the API version."""

    @pytest.mark.parametrize("name", ALL_FIXTURES)
    def test_envelope_reports_the_public_v1_api(self, name: str) -> None:
        body = load_fixture(name)

        assert body["status"] == "OK"
        assert body["status-code"] == 200
        assert body["version"] == "1.0"
        assert body["access"] == "public"
        assert body["offset"] == 0
