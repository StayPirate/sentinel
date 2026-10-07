"""Contract tests for the CISA KEV catalog feed.

Contract under test: docs/features/tickets/cve-sync-kev.md (Algorithm,
Field Mapping, Explicitly Ignored Fields, Error Handling) and
docs/data-sources.md (CISA KEV (Known Exploited Vulnerabilities)),
verified against the live catalog downloaded anonymously on 2026-10-07
without following redirects (docs/conventions.md, External Integration
Contract Verification). Every consumed field is asserted for name,
nesting, type, and encoding through a strict test-local typed model,
independent of the production parser.

Live verification on 2026-10-07 (`GET` of the documented URL):

- HTTP 200 with no redirect, `application/json`, 1,767,828 bytes,
  `catalogVersion` `2026.10.04`.
- The root is an object with exactly `title`, `catalogVersion`,
  `dateReleased`, `count`, and `vulnerabilities`; `count` (1,734) equals
  the length of `vulnerabilities`.
- Every entry has exactly the same 12 members: `cveID`, `vendorProject`,
  `product`, `vulnerabilityName`, `dateAdded`, `shortDescription`,
  `requiredAction`, `dueDate`, `knownRansomwareCampaignUse`, `notes`,
  `cwes`, and `forensicTriage`.
- Every `cveID` is a canonical, unique CVE-ID; every `dateAdded` is a
  `YYYY-MM-DD` string; `cwes` is always a list of strings matching
  `^CWE-[1-9][0-9]*$` (175 empty, 107 with more than one item);
  `forensicTriage` is `"Yes"` (75) or `"No"` (1,659).

Not observable live, and therefore covered by the parser and fetcher
tests only: a non-object root; a missing or non-list `vulnerabilities`; an
absent or non-integer `count` or one that differs from the list length;
an entry that is not an object; an absent, non-string, or non-canonical
`cveID`; an absent, non-string, or invalid `dateAdded`; a `null`, absent,
or non-list `cwes` and non-string or non-canonical `cwes` items; non-200
statuses; a non-JSON body; and U+0000 in any string.
"""

from __future__ import annotations

import re
from datetime import date
from typing import Any, TypedDict

import pytest
from pydantic import TypeAdapter, ValidationError

from app.core.identifiers import is_valid_cve_id
from app.services.cve_ingest import CWEEntry, KEVEntry
from tests.support.cisa_kev import (
    FIXTURE_CVE_IDS,
    load_catalog,
    load_raw_catalog,
    reference_url,
)

_TOP_LEVEL_KEYS = (
    "title",
    "catalogVersion",
    "dateReleased",
    "count",
    "vulnerabilities",
)
"""`vulnerabilities` and `count` plus the feed-level ignored fields, in
live order."""

_ENTRY_KEYS = frozenset(
    {
        "cveID",
        "dateAdded",
        "cwes",
        "vendorProject",
        "product",
        "vulnerabilityName",
        "shortDescription",
        "requiredAction",
        "dueDate",
        "knownRansomwareCampaignUse",
        "notes",
        "forensicTriage",
    }
)
"""The consumed members plus every per-entry field of § Explicitly
Ignored Fields."""

_IGNORED_ENTRY_KEYS = _ENTRY_KEYS - {"cveID", "dateAdded", "cwes"}

_DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
_CWE = re.compile(r"CWE-[1-9][0-9]*")


class _Entry(TypedDict):
    cveID: str
    dateAdded: str
    cwes: list[str]


class _Catalog(TypedDict):
    """The consumed fields as observed live. Unconsumed fields are ignored."""

    count: int
    vulnerabilities: list[_Entry]


_CATALOG = TypeAdapter(_Catalog)


def _validated(body: Any) -> _Catalog:
    return _CATALOG.validate_python(body, strict=True)


def _strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [s for key, item in value.items() for s in (key, *_strings(item))]
    if isinstance(value, list):
        return [s for item in value for s in _strings(item)]
    return []


def _entries() -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = load_catalog()["vulnerabilities"]
    return entries


@pytest.mark.unit
class TestTypedCatalog:
    def test_root_is_an_object_with_the_documented_members_in_order(self) -> None:
        body = load_catalog()

        assert isinstance(body, dict)
        assert tuple(body) == _TOP_LEVEL_KEYS

    def test_consumed_fields_validate_strictly_without_coercion(self) -> None:
        validated = _validated(load_catalog())

        assert len(validated["vulnerabilities"]) == len(FIXTURE_CVE_IDS)

    def test_count_equals_the_list_length(self) -> None:
        body = load_catalog()

        assert isinstance(body["count"], int)
        assert body["count"] == len(body["vulnerabilities"])

    @pytest.mark.parametrize(
        "entry",
        [
            {"cveID": "CVE-2026-0001", "dateAdded": 20261001, "cwes": []},
            {"cveID": None, "dateAdded": "2026-10-01", "cwes": []},
            {"cveID": "CVE-2026-0001", "dateAdded": "2026-10-01", "cwes": "CWE-79"},
            {"cveID": "CVE-2026-0001", "cwes": []},
        ],
        ids=["number-date", "null-cve-id", "string-cwes", "missing-date"],
    )
    def test_typed_model_rejects_a_mistyped_or_missing_consumed_field(
        self, entry: dict[str, Any]
    ) -> None:
        with pytest.raises(ValidationError):
            _validated({"count": 1, "vulnerabilities": [entry]})

    def test_no_string_contains_nul(self) -> None:
        assert all("\x00" not in s for s in _strings(load_catalog()))

    def test_fixture_is_minified_with_ascii_escapes_and_one_trailing_newline(
        self,
    ) -> None:
        raw = load_raw_catalog()

        assert raw.endswith(b"}\n")
        assert raw.count(b"\n") == 1
        assert raw.isascii()


@pytest.mark.unit
class TestEntries:
    def test_fixture_entries_are_the_documented_ones_in_catalog_order(self) -> None:
        assert tuple(entry["cveID"] for entry in _entries()) == FIXTURE_CVE_IDS

    @pytest.mark.parametrize("index", range(len(FIXTURE_CVE_IDS)))
    def test_entry_has_exactly_the_mapped_and_ignored_members(self, index: int) -> None:
        assert set(_entries()[index]) == _ENTRY_KEYS

    @pytest.mark.parametrize("index", range(len(FIXTURE_CVE_IDS)))
    def test_cve_id_is_canonical(self, index: int) -> None:
        assert is_valid_cve_id(_entries()[index]["cveID"])

    def test_cve_ids_are_unique(self) -> None:
        cve_ids = [entry["cveID"] for entry in _entries()]

        assert len(set(cve_ids)) == len(cve_ids)

    @pytest.mark.parametrize("index", range(len(FIXTURE_CVE_IDS)))
    def test_date_added_is_an_iso_calendar_date(self, index: int) -> None:
        value = _entries()[index]["dateAdded"]

        assert isinstance(value, str)
        assert _DATE.fullmatch(value)
        assert date.fromisoformat(value).isoformat() == value

    @pytest.mark.parametrize("index", range(len(FIXTURE_CVE_IDS)))
    def test_cwes_is_a_list_of_canonical_cwe_ids(self, index: int) -> None:
        cwes = _entries()[index]["cwes"]

        assert isinstance(cwes, list)
        assert all(isinstance(cwe, str) and _CWE.fullmatch(cwe) for cwe in cwes)

    def test_cwes_cover_single_multiple_and_empty_lists(self) -> None:
        lengths = {len(entry["cwes"]) for entry in _entries()}

        assert 0 in lengths
        assert 1 in lengths
        assert any(length > 1 for length in lengths)

    def test_forensic_triage_takes_both_observed_values(self) -> None:
        assert {entry["forensicTriage"] for entry in _entries()} == {"Yes", "No"}

    @pytest.mark.parametrize("index", range(len(FIXTURE_CVE_IDS)))
    def test_ignored_members_are_strings(self, index: int) -> None:
        entry = _entries()[index]

        assert all(isinstance(entry[key], str) for key in _IGNORED_ENTRY_KEYS)


@pytest.mark.unit
class TestTargetContracts:
    @pytest.mark.parametrize("index", range(len(FIXTURE_CVE_IDS)))
    def test_entry_converts_to_the_kev_entry_contract(self, index: int) -> None:
        entry = _entries()[index]

        converted = KEVEntry(
            date_added=entry["dateAdded"],
            reference_url=reference_url(entry["cveID"]),
        )

        assert converted.date_added == date.fromisoformat(entry["dateAdded"])
        assert converted.reference_url == reference_url(entry["cveID"])

    @pytest.mark.parametrize("index", range(len(FIXTURE_CVE_IDS)))
    def test_cwes_convert_to_the_cwe_entry_contract(self, index: int) -> None:
        for cwe in _entries()[index]["cwes"]:
            assert CWEEntry(cwe_id=cwe, source="CISA KEV").cwe_id == cwe

    def test_constructed_reference_url_fits_the_kev_entry_bound(self) -> None:
        longest = max(FIXTURE_CVE_IDS, key=len)

        assert len(reference_url(longest)) <= 2048
