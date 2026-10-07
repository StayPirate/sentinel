"""Unit tests for the pure CISA KEV catalog parser
(backend/app/services/tickets/cisa_kev_catalog.py).

Owning specifications:

- docs/features/tickets/cve-sync-kev.md (Algorithm steps 2, 3a, and 3d;
  Field Mapping; Error Handling, External String Admissibility).
- docs/features/tickets/cve-service.md (CVEIngestPayload Schema: the
  `KEVEntry` and `CWEEntry` contracts).
- docs/features/platform/testing-strategy.md (External String
  Admissibility).

The parser performs no HTTP, database, or logging work, so these tests use
no database or Redis. The fixture catalog of `tests/support/cisa_kev.py`
supplies the live-shaped entries; every other value is fictional.
"""

from __future__ import annotations

from datetime import date
from typing import Any, Final

import pytest

from app.services.cve_ingest import CWEEntry, KEVEntry
from app.services.tickets.cisa_kev_catalog import (
    CWE_SOURCE,
    InvalidCwesError,
    InvalidDateAddedError,
    KevCatalog,
    KevCatalogStructureError,
    KevEnrichment,
    entry_cve_id,
    extract,
    parse_catalog,
)
from tests.support.cisa_kev import (
    FIXTURE_CVE_IDS,
    catalog_of,
    entry_for,
    fixture_entry,
    load_catalog,
    reference_url,
)

CVE_ID: Final = "CVE-2099-48001"
URL: Final = reference_url(CVE_ID)
SECRET_TEXT: Final = "Reported by Alice Example <alice.example@example.invalid>"
"""A feed value that must never reach an exception message."""

ABSENT: Final = object()
"""Marks a member removed from the entry."""


def _entry(**members: Any) -> dict[str, Any]:
    """A live-shaped entry for `CVE_ID`; `ABSENT` removes a member."""
    entry = entry_for(CVE_ID)
    for key, value in members.items():
        if value is ABSENT:
            del entry[key]
        else:
            entry[key] = value
    return entry


def _cwes(*cwe_ids: str) -> list[CWEEntry]:
    return [CWEEntry(cwe_id=cwe_id, source="CISA KEV") for cwe_id in cwe_ids]


# ---------------------------------------------------------------------------
# parse_catalog(): catalog structure (Algorithm step 2)
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestParseCatalog:
    def test_fixture_catalog_keeps_count_and_raw_entries_in_order(self) -> None:
        document = load_catalog()

        catalog = parse_catalog(document)

        assert catalog == KevCatalog(count=5, entries=document["vulnerabilities"])
        assert catalog.entries is document["vulnerabilities"]
        assert [entry["cveID"] for entry in catalog.entries] == list(FIXTURE_CVE_IDS)

    @pytest.mark.parametrize(
        "document",
        [[], [load_catalog()], "catalog", "", 5, 5.0, True, None],
        ids=[
            "empty_list",
            "list",
            "string",
            "empty_string",
            "int",
            "float",
            "bool",
            "null",
        ],
    )
    def test_non_object_root_is_an_unexpected_structure(self, document: Any) -> None:
        with pytest.raises(KevCatalogStructureError) as raised:
            parse_catalog(document)

        assert str(raised.value) == "CISA KEV catalog has unexpected structure"

    @pytest.mark.parametrize(
        "vulnerabilities",
        [ABSENT, None, {}, {"cveID": CVE_ID}, "[]", 0, True],
        ids=["missing", "null", "empty_object", "object", "string", "int", "bool"],
    )
    def test_missing_or_non_list_vulnerabilities_is_an_unexpected_structure(
        self, vulnerabilities: Any
    ) -> None:
        document = load_catalog()
        if vulnerabilities is ABSENT:
            del document["vulnerabilities"]
        else:
            document["vulnerabilities"] = vulnerabilities

        with pytest.raises(KevCatalogStructureError):
            parse_catalog(document)

    @pytest.mark.parametrize(
        "count",
        [ABSENT, "5", 5.0, True, False, None, [5], {"count": 5}],
        ids=["absent", "string", "float", "true", "false", "null", "list", "object"],
    )
    def test_absent_or_non_integer_count_is_none(self, count: Any) -> None:
        document = load_catalog()
        if count is ABSENT:
            del document["count"]
        else:
            document["count"] = count

        catalog = parse_catalog(document)

        assert catalog.count is None
        assert len(catalog.entries) == len(FIXTURE_CVE_IDS)

    @pytest.mark.parametrize("count", [0, 5, 7, -1, 10**12])
    def test_integer_count_is_kept_even_when_it_mismatches(self, count: int) -> None:
        document = load_catalog()
        document["count"] = count

        catalog = parse_catalog(document)

        assert catalog.count == count
        assert len(catalog.entries) == len(FIXTURE_CVE_IDS)

    def test_empty_vulnerabilities_is_a_valid_catalog(self) -> None:
        catalog = parse_catalog(catalog_of())

        assert catalog == KevCatalog(count=0, entries=[])

    def test_entries_are_not_validated_or_copied(self) -> None:
        # Entry validation belongs to the per-entry boundary.
        entries: list[object] = [None, "x", 7, [], {"cveID": SECRET_TEXT}]

        catalog = parse_catalog({"vulnerabilities": entries})

        assert catalog.count is None
        assert catalog.entries is entries

    def test_unconsumed_members_are_ignored(self) -> None:
        catalog = parse_catalog(
            {"title": SECRET_TEXT, "vulnerabilities": [], "extra": SECRET_TEXT}
        )

        assert catalog == KevCatalog(count=None, entries=[])


# ---------------------------------------------------------------------------
# entry_cve_id(): the raw cveID (Algorithm step 3a)
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestEntryCveId:
    @pytest.mark.parametrize(
        "entry",
        [None, CVE_ID, 7, [CVE_ID], [{"cveID": CVE_ID}]],
        ids=["null", "string", "int", "list", "list_of_object"],
    )
    def test_non_object_entry_is_none(self, entry: Any) -> None:
        assert entry_cve_id(entry) is None

    def test_missing_cve_id_is_none(self) -> None:
        assert entry_cve_id(_entry(cveID=ABSENT)) is None

    @pytest.mark.parametrize(
        "value",
        [CVE_ID, "cve-2099-48001", "CVE-2099-1", f"{CVE_ID}\x00", "", 48001, None],
        ids=["canonical", "lowercase", "short", "nul", "empty", "int", "null"],
    )
    def test_raw_value_is_returned_unvalidated(self, value: Any) -> None:
        assert entry_cve_id(_entry(cveID=value)) == value

    @pytest.mark.parametrize("cve_id", FIXTURE_CVE_IDS)
    def test_fixture_entry_cve_id(self, cve_id: str) -> None:
        assert entry_cve_id(fixture_entry(cve_id)) == cve_id


# ---------------------------------------------------------------------------
# extract(): the KEV and CWE conversion (Algorithm step 3d; Field Mapping)
# ---------------------------------------------------------------------------

FIXTURE_MAPPING: Final = {
    "CVE-2026-88779": (date(2026, 10, 4), ("CWE-119",)),
    "CVE-2026-81963": (date(2026, 9, 8), ("CWE-59", "CWE-284")),
    "CVE-2015-3246": (date(2026, 8, 26), ()),
    "CVE-2026-20316": (date(2026, 7, 29), ("CWE-259",)),
    "CVE-2026-104286": (date(2026, 10, 1), ("CWE-22", "CWE-158")),
}
"""The expected conversion of every fixture entry, written out by hand."""


@pytest.mark.unit
class TestExtractFixture:
    def test_mapping_covers_every_fixture_entry(self) -> None:
        assert tuple(FIXTURE_MAPPING) == FIXTURE_CVE_IDS

    @pytest.mark.parametrize("cve_id", FIXTURE_CVE_IDS)
    def test_fixture_entry_maps_to_the_exact_kev_and_cwe_entries(
        self, cve_id: str
    ) -> None:
        date_added, cwe_ids = FIXTURE_MAPPING[cve_id]
        url = reference_url(cve_id)

        enrichment = extract(fixture_entry(cve_id), reference_url=url)

        assert enrichment == KevEnrichment(
            kev_entry=KEVEntry(date_added=date_added, reference_url=url),
            cwe_classifications=_cwes(*cwe_ids),
            skipped_cwes=0,
        )
        assert enrichment.kev_entry.reference_url == (
            "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
            f"?field_cve={cve_id}"
        )
        assert all(cwe.source == "CISA KEV" for cwe in enrichment.cwe_classifications)

    def test_reference_url_is_taken_verbatim(self) -> None:
        url = "https://kev.example.invalid/entry"

        enrichment = extract(_entry(), reference_url=url)

        assert enrichment.kev_entry.reference_url == url

    def test_cwe_source_constant(self) -> None:
        assert CWE_SOURCE == "CISA KEV"

    def test_unconsumed_members_do_not_affect_the_result(self) -> None:
        entry = _entry(cwes=["CWE-79"])
        for key in ("vendorProject", "shortDescription", "notes", "forensicTriage"):
            entry[key] = SECRET_TEXT
        entry["unexpectedMember"] = {"nested": SECRET_TEXT}

        assert extract(entry, reference_url=URL) == extract(
            _entry(cwes=["CWE-79"]), reference_url=URL
        )


@pytest.mark.unit
class TestExtractCwes:
    def test_identical_ids_collapse_in_first_occurrence_order(self) -> None:
        entry = _entry(cwes=["CWE-284", "CWE-59", "CWE-284", "CWE-59", "CWE-7"])

        enrichment = extract(entry, reference_url=URL)

        assert enrichment.cwe_classifications == _cwes("CWE-284", "CWE-59", "CWE-7")
        assert enrichment.skipped_cwes == 0

    @pytest.mark.parametrize(
        "cwes", [ABSENT, None, []], ids=["absent", "null", "empty"]
    )
    def test_absent_null_or_empty_cwes_supply_nothing(self, cwes: Any) -> None:
        enrichment = extract(_entry(cwes=cwes), reference_url=URL)

        assert enrichment.cwe_classifications == []
        assert enrichment.skipped_cwes == 0
        assert enrichment.kev_entry == KEVEntry(
            date_added=date(2026, 10, 1), reference_url=URL
        )

    @pytest.mark.parametrize(
        "cwes",
        ["CWE-79", "", {"cweID": "CWE-79"}, {}, 79, 0, True, 7.9],
        ids=[
            "string",
            "empty_string",
            "object",
            "empty_object",
            "int",
            "zero",
            "bool",
            "float",
        ],
    )
    def test_non_list_cwes_is_invalid(self, cwes: Any) -> None:
        with pytest.raises(InvalidCwesError) as raised:
            extract(_entry(cwes=cwes), reference_url=URL)

        assert str(raised.value) == "CISA KEV entry has a non-list cwes"

    @pytest.mark.parametrize(
        "item",
        [
            79,
            None,
            True,
            7.9,
            ["CWE-79"],
            {"cweID": "CWE-79"},
            "CWE-0",
            "CWE-079",
            "cwe-79",
            "CWE-79 ",
            " CWE-79",
            "CWE-79\n",
            "CWE79",
            "CWE-",
            "",
            "CWE-12345678901234567",
            "NVD-CWE-Other",
            "NVD-CWE-noinfo",
            "CWE-79\x00",
            "\x00",
            SECRET_TEXT,
        ],
        ids=[
            "int",
            "null",
            "bool",
            "float",
            "list",
            "object",
            "zero",
            "leading_zero",
            "lowercase",
            "trailing_space",
            "leading_space",
            "trailing_newline",
            "no_dash",
            "no_number",
            "empty",
            "over_long",
            "nvd_other",
            "nvd_noinfo",
            "nul_suffix",
            "nul_only",
            "free_text",
        ],
    )
    def test_invalid_item_is_skipped_and_counted(self, item: Any) -> None:
        entry = _entry(cwes=["CWE-79", item, "CWE-352"])

        enrichment = extract(entry, reference_url=URL)

        assert enrichment.cwe_classifications == _cwes("CWE-79", "CWE-352")
        assert enrichment.skipped_cwes == 1

    def test_longest_admissible_cwe_id_is_kept(self) -> None:
        # `CWEEntry.cwe_id` is bounded at 20 characters.
        cwe_id = "CWE-1234567890123456"
        assert len(cwe_id) == 20

        enrichment = extract(_entry(cwes=[cwe_id]), reference_url=URL)

        assert enrichment.cwe_classifications == _cwes(cwe_id)

    def test_every_rejected_item_counts_once_including_duplicates(self) -> None:
        entry = _entry(cwes=["cwe-1", "cwe-1", None, "CWE-1", "CWE-0", "CWE-1"])

        enrichment = extract(entry, reference_url=URL)

        assert enrichment.cwe_classifications == _cwes("CWE-1")
        assert enrichment.skipped_cwes == 4

    def test_only_invalid_items_yield_no_classification(self) -> None:
        enrichment = extract(_entry(cwes=["CWE-0", 7]), reference_url=URL)

        assert enrichment.cwe_classifications == []
        assert enrichment.skipped_cwes == 2


@pytest.mark.unit
class TestExtractDateAdded:
    @pytest.mark.parametrize(
        "value",
        ["2026-10-01", "2000-02-29", "0001-01-01", "9999-12-31"],
    )
    def test_iso_calendar_date_is_accepted(self, value: str) -> None:
        enrichment = extract(_entry(dateAdded=value), reference_url=URL)

        assert enrichment.kev_entry.date_added == date.fromisoformat(value)

    @pytest.mark.parametrize(
        "value",
        [
            ABSENT,
            None,
            20261001,
            2026.1,
            True,
            ["2026-10-01"],
            {"date": "2026-10-01"},
            "",
            "2026-1-01",
            "2026-10-1",
            "26-10-01",
            "20261001",
            "2026/10/01",
            "2026-02-30",
            "2026-13-01",
            "2026-00-10",
            "0000-01-01",
            "2026-10-01T00:00:00",
            "2026-10-01Z",
            " 2026-10-01",
            "2026-10-01 ",
            "2026-10-01\n",
            "\uff12\uff10\uff12\uff16-10-01",
            "2026-10-01\x00",
            "\x002026-10-01",
            SECRET_TEXT,
        ],
        ids=[
            "missing",
            "null",
            "int",
            "float",
            "bool",
            "list",
            "object",
            "empty",
            "one_digit_month",
            "one_digit_day",
            "two_digit_year",
            "basic_format",
            "slashes",
            "february_30",
            "month_13",
            "month_0",
            "year_0",
            "datetime",
            "zulu_suffix",
            "leading_space",
            "trailing_space",
            "trailing_newline",
            "fullwidth_digits",
            "nul_suffix",
            "nul_prefix",
            "free_text",
        ],
    )
    def test_invalid_date_added_is_rejected(self, value: Any) -> None:
        with pytest.raises(InvalidDateAddedError) as raised:
            extract(_entry(dateAdded=value), reference_url=URL)

        assert str(raised.value) == "CISA KEV entry has an invalid dateAdded"
        assert raised.value.__cause__ is None

    def test_date_is_validated_before_cwes(self) -> None:
        with pytest.raises(InvalidDateAddedError):
            extract(_entry(dateAdded=None, cwes="CWE-79"), reference_url=URL)


# ---------------------------------------------------------------------------
# Exception messages carry no input value
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestExceptionPrivacy:
    @pytest.mark.parametrize(
        ("call", "error"),
        [
            (lambda: parse_catalog([SECRET_TEXT]), KevCatalogStructureError),
            (
                lambda: parse_catalog({"vulnerabilities": SECRET_TEXT}),
                KevCatalogStructureError,
            ),
            (
                lambda: extract(_entry(dateAdded=SECRET_TEXT), reference_url=URL),
                InvalidDateAddedError,
            ),
            (
                lambda: extract(_entry(dateAdded="2026-02-30"), reference_url=URL),
                InvalidDateAddedError,
            ),
            (
                lambda: extract(_entry(cwes=SECRET_TEXT), reference_url=URL),
                InvalidCwesError,
            ),
        ],
        ids=["root", "vulnerabilities", "date_text", "date_calendar", "cwes"],
    )
    def test_message_and_args_omit_the_value(
        self, call: Any, error: type[Exception]
    ) -> None:
        with pytest.raises(error) as raised:
            call()

        rendered = f"{raised.value!s} {raised.value!r} {raised.value.args!r}"
        assert SECRET_TEXT not in rendered
        assert "Alice" not in rendered
        assert "2026-02-30" not in rendered
        assert raised.value.__cause__ is None
        assert raised.value.__suppress_context__ or raised.value.__context__ is None

    @pytest.mark.parametrize(
        "error", [KevCatalogStructureError, InvalidDateAddedError, InvalidCwesError]
    )
    def test_errors_are_value_errors(self, error: type[Exception]) -> None:
        assert issubclass(error, ValueError)
