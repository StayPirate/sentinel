"""Unit tests for the Red Hat CVE record models and extraction
(backend/app/services/tickets/redhat_cve_record.py).

Contract under test: docs/features/tickets/cve-sync-redhat.md (Algorithm
steps 2-9, Field Mapping, Response Validation including External String
Admissibility, Explicitly Ignored Fields, and the extractable-data
determination of Error Handling). The fetcher logs the candidate skip
events and ingests the result; those parts are tested in
`test_sync_redhat_cves.py`.

Records are the sanitized live fixtures of `tests/support/redhat.py` or
minimal fictional objects. No database, HTTP, or log is involved.
"""

from __future__ import annotations

from typing import Any, Final

import pytest
from pydantic import ValidationError

from app.services import cve_service
from app.services.cvss import validate_cvss_vector
from app.services.tickets import redhat_cve_record
from app.services.tickets.redhat_cve_record import (
    BugzillaLink,
    RedhatCVERecord,
    RedhatExtraction,
    extract,
    parse_response,
)
from tests.support.redhat import CVE_SUCCESS_FIXTURES, load_cve_fixture

V31: Final = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
V31_REORDERED: Final = "CVSS:3.1/C:H/I:H/A:H/AV:N/AC:L/PR:N/UI:N/S:U"
V2: Final = "AV:N/AC:L/Au:N/C:P/I:P/A:P"
NON_BASE_V31: Final = V31 + "/E:P"
URL_1: Final = "https://advisory.example.invalid/upstream/1"
URL_2: Final = "https://advisory.example.invalid/upstream/2"
BUGZILLA_URL: Final = "https://bugzilla.example.invalid/show_bug.cgi?id=1"
SECRET_INPUT: Final = "Example-Secret-Input-Value"


def _extract(**fields: Any) -> RedhatExtraction:
    return extract(parse_response(fields))


def _nothing(**overrides: Any) -> dict[str, Any]:
    return {
        "cvss_vectors": (),
        "cwe_id": None,
        "reference_urls": (),
        "bugzilla": None,
        "package_names": (),
        "skipped": (),
        **overrides,
    }


class ParserSpy:
    """Records every vector passed to the canonical parser."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    def __call__(self, vector: str) -> Any:
        self.calls.append(vector)
        return validate_cvss_vector(vector)


@pytest.fixture
def parser(monkeypatch: pytest.MonkeyPatch) -> ParserSpy:
    spy = ParserSpy()
    monkeypatch.setattr(redhat_cve_record, "validate_cvss_vector", spy)
    return spy


# ---------------------------------------------------------------------------
# Response validation
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestResponseValidation:
    @pytest.mark.parametrize("name", CVE_SUCCESS_FIXTURES)
    def test_live_fixtures_validate(self, name: str) -> None:
        record = parse_response(load_cve_fixture(name))

        assert isinstance(record, RedhatCVERecord)

    def test_unconsumed_fields_of_any_type_are_ignored(self) -> None:
        record = parse_response(
            {
                "threat_severity": 7,
                "affected_release": "not-a-list",
                "cvss3": {"cvss3_base_score": [], "status": None},
                "bugzilla": {"id": {}, "url": BUGZILLA_URL},
                "package_state": [{"fix_state": 1, "package_name": "example"}],
            }
        )

        assert record.cvss3 is not None
        assert record.cvss3.cvss3_scoring_vector is None
        assert extract(record).package_names == ("example",)

    @pytest.mark.parametrize(
        "body",
        [[], "text", 7, None, True],
        ids=["array", "string", "int", "null", "bool"],
    )
    def test_non_object_root_is_a_schema_mismatch(self, body: Any) -> None:
        with pytest.raises(ValidationError):
            parse_response(body)

    @pytest.mark.parametrize(
        ("field", "value"),
        [
            ("cvss3", "CVSS:3.1/AV:N"),
            ("cvss3", {"cvss3_scoring_vector": 3.1}),
            ("cvss", ["AV:N"]),
            ("cvss", {"cvss_scoring_vector": {"vector": V2}}),
            ("cwe", 200),
            ("cwe", ["CWE-200"]),
            ("references", URL_1),
            ("references", [URL_1, 7]),
            ("bugzilla", BUGZILLA_URL),
            ("bugzilla", {"url": 1}),
            ("bugzilla", {"url": BUGZILLA_URL, "description": ["text"]}),
            ("package_state", {"package_name": "example"}),
            ("package_state", ["example"]),
            ("package_state", [{"package_name": 7}]),
        ],
    )
    def test_consumed_field_of_another_json_type_is_a_schema_mismatch(
        self, field: str, value: Any
    ) -> None:
        with pytest.raises(ValidationError):
            parse_response({**load_cve_fixture("cve_full_v3"), field: value})

    @pytest.mark.parametrize(
        "field", ["cvss3", "cvss", "cwe", "references", "bugzilla", "package_state"]
    )
    def test_null_consumed_field_is_not_observed(self, field: str) -> None:
        body = {**load_cve_fixture("cve_full_v3"), field: None}

        assert getattr(parse_response(body), field) is None

    @pytest.mark.parametrize(
        "body",
        [
            {"cwe": [SECRET_INPUT]},
            {"references": [SECRET_INPUT, 1]},
            {"bugzilla": {"url": [SECRET_INPUT]}},
            {"package_state": [{"package_name": {"name": SECRET_INPUT}}]},
        ],
    )
    def test_validation_error_never_renders_the_input(
        self, body: dict[str, Any]
    ) -> None:
        with pytest.raises(ValidationError) as raised:
            parse_response(body)

        assert SECRET_INPUT not in str(raised.value)
        assert SECRET_INPUT not in repr(raised.value)

    def test_strings_are_not_coerced(self) -> None:
        with pytest.raises(ValidationError):
            parse_response({"package_state": [{"package_name": b"example"}]})


# ---------------------------------------------------------------------------
# CVSS (steps 2-5)
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestCvss:
    def test_v3_only(self) -> None:
        extraction = extract(parse_response(load_cve_fixture("cve_full_v3")))

        assert extraction.cvss_vectors == (
            "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
        )

    def test_v2_only(self) -> None:
        extraction = extract(parse_response(load_cve_fixture("cve_v2_only")))

        assert extraction.cvss_vectors == ("AV:N/AC:L/Au:N/C:P/I:N/A:N",)

    def test_v3_and_v2_coexist_v3_first(self) -> None:
        extraction = extract(parse_response(load_cve_fixture("cve_v2_v3")))

        assert extraction.cvss_vectors == (
            "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
            "AV:L/AC:M/Au:N/C:C/I:C/A:C",
        )

    def test_neither(self, parser: ParserSpy) -> None:
        extraction = extract(parse_response(load_cve_fixture("cve_no_cvss")))

        assert extraction.cvss_vectors == ()
        assert extraction.skipped == ()
        assert parser.calls == []

    def test_canonical_parser_output_is_used(self) -> None:
        extraction = _extract(cvss3={"cvss3_scoring_vector": f" {V31_REORDERED} "})

        assert extraction.cvss_vectors == (V31,)

    @pytest.mark.parametrize("vector", [None, "", " ", "\t\n "])
    def test_null_empty_or_whitespace_vector_is_absent_without_parser_call(
        self, vector: str | None, parser: ParserSpy
    ) -> None:
        extraction = _extract(
            cvss3={"cvss3_scoring_vector": vector},
            cvss={"cvss_scoring_vector": vector},
        )

        assert extraction == RedhatExtraction(**_nothing())
        assert parser.calls == []

    def test_object_without_vector_key_is_absent(self, parser: ParserSpy) -> None:
        extraction = _extract(cvss3={"status": "draft"}, cvss={})

        assert extraction.cvss_vectors == ()
        assert extraction.skipped == ()
        assert parser.calls == []

    @pytest.mark.parametrize("status", ["draft", "verified", "unknown", None])
    def test_status_is_not_evaluated(self, status: str | None) -> None:
        extraction = _extract(
            cvss3={"cvss3_scoring_vector": V31, "status": status},
            cvss={"cvss_scoring_vector": V2, "status": status},
        )

        assert extraction.cvss_vectors == (V31, V2)

    def test_base_score_is_not_read(self) -> None:
        extraction = _extract(
            cvss3={"cvss3_scoring_vector": V31, "cvss3_base_score": "0.1"}
        )

        assert extraction.cvss_vectors == (V31,)

    @pytest.mark.parametrize(
        "vector",
        [
            "CVSS:3.1/AV:N",
            NON_BASE_V31,
            "CVSS:9.9/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "cvss:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "not a vector",
        ],
        ids=["incomplete", "non_base", "unknown_prefix", "wrong_case", "garbage"],
    )
    def test_rejected_vector_is_skipped_once_and_other_data_continues(
        self, vector: str, parser: ParserSpy
    ) -> None:
        extraction = _extract(
            cvss3={"cvss3_scoring_vector": vector},
            cvss={"cvss_scoring_vector": V2},
            cwe="CWE-79",
        )

        assert extraction.cvss_vectors == (V2,)
        assert extraction.cwe_id == "CWE-79"
        assert extraction.skipped == ("invalid_vector",)
        assert parser.calls == [vector, V2]

    def test_both_vectors_rejected_skip_twice(self) -> None:
        extraction = _extract(
            cvss3={"cvss3_scoring_vector": "CVSS:3.1/AV:N"},
            cvss={"cvss_scoring_vector": "AV:N"},
        )

        assert extraction.cvss_vectors == ()
        assert extraction.skipped == ("invalid_vector", "invalid_vector")

    def test_vector_longer_than_200_characters_is_rejected_without_parser_call(
        self, parser: ParserSpy
    ) -> None:
        # Valid after trimming, but the received value exceeds the bound.
        padded = V31 + " " * (201 - len(V31))
        assert len(padded) == 201

        extraction = _extract(cvss3={"cvss3_scoring_vector": padded})

        assert extraction.cvss_vectors == ()
        assert extraction.skipped == ("invalid_vector",)
        assert parser.calls == []

    def test_vector_of_exactly_200_characters_reaches_the_parser(
        self, parser: ParserSpy
    ) -> None:
        padded = V31 + " " * (200 - len(V31))

        extraction = _extract(cvss3={"cvss3_scoring_vector": padded})

        assert extraction.cvss_vectors == (V31,)
        assert parser.calls == [padded]

    def test_bound_equals_the_ingestion_received_length_bound(self) -> None:
        assert redhat_cve_record.VECTOR_MAX_LENGTH == cve_service.CVSS_VECTOR_MAX_LENGTH

    @pytest.mark.parametrize("position", ["start", "middle", "end"])
    def test_vector_containing_nul_is_an_invalid_vector(self, position: str) -> None:
        vector = {
            "start": "\x00" + V31,
            "middle": V31.replace("/C:H", "/C:\x00H"),
            "end": V31 + "\x00",
        }[position]

        extraction = _extract(cvss3={"cvss3_scoring_vector": vector})

        assert extraction.cvss_vectors == ()
        assert extraction.skipped == ("invalid_vector",)

    def test_only_an_invalid_vector_is_no_extractable_data(self) -> None:
        extraction = _extract(cvss3={"cvss3_scoring_vector": "CVSS:3.1/AV:N"})

        assert not extraction.has_extractable_data


# ---------------------------------------------------------------------------
# CWE (step 6)
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestCwe:
    @pytest.mark.parametrize("cwe", ["CWE-1", "CWE-200", "CWE-1395"])
    def test_valid_identifier_is_kept(self, cwe: str) -> None:
        extraction = _extract(cwe=cwe)

        assert extraction.cwe_id == cwe
        assert extraction.skipped == ()
        assert extraction.has_extractable_data

    def test_absent_cwe_is_not_observed(self) -> None:
        extraction = _extract()

        assert extraction.cwe_id is None
        assert extraction.skipped == ()

    @pytest.mark.parametrize(
        "cwe",
        [
            "CWE-200->CWE-284",
            "CWE-200, CWE-284",
            "(CWE-200|CWE-284)",
            "CWE-0",
            "CWE-020",
            "cwe-200",
            "CWE-200\n",
            " CWE-200",
            "",
            "   ",
            "CWE-" + "1" * 17,
            "CWE-\x00200",
            "CWE-200\x00",
        ],
        ids=[
            "chain",
            "list",
            "alternatives",
            "zero",
            "leading_zero",
            "lowercase",
            "trailing_newline",
            "leading_space",
            "empty",
            "whitespace",
            "over_long",
            "nul_middle",
            "nul_end",
        ],
    )
    def test_invalid_value_is_skipped_and_other_data_continues(self, cwe: str) -> None:
        extraction = _extract(cwe=cwe, references=[URL_1])

        assert extraction.cwe_id is None
        assert extraction.skipped == ("invalid_cwe",)
        assert extraction.reference_urls == (URL_1,)

    def test_only_an_invalid_cwe_is_no_extractable_data(self) -> None:
        assert not _extract(cwe="CWE-200->CWE-284").has_extractable_data

    def test_skip_reasons_follow_algorithm_order(self) -> None:
        extraction = _extract(
            cwe="CWE-200->CWE-284",
            cvss={"cvss_scoring_vector": "AV:N"},
            cvss3={"cvss3_scoring_vector": "CVSS:3.1/AV:N"},
        )

        assert extraction.skipped == ("invalid_vector", "invalid_vector", "invalid_cwe")


# ---------------------------------------------------------------------------
# References (step 7) and Bugzilla (step 8)
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestReferences:
    def test_live_element_is_split_into_lines_in_order(self) -> None:
        extraction = extract(parse_response(load_cve_fixture("cve_full_v3")))

        assert extraction.reference_urls == (
            "https://www.cve.org/CVERecord?id=CVE-2024-6387",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-6387",
            "https://advisory.example.invalid/upstream/1",
            "https://advisory.example.invalid/upstream/2",
            "https://advisory.example.invalid/upstream/3",
        )

    def test_elements_and_lines_keep_their_order(self) -> None:
        extraction = _extract(references=[f"{URL_2}\n{URL_1}", URL_1, URL_2])

        assert extraction.reference_urls == (URL_2, URL_1, URL_1, URL_2)

    @pytest.mark.parametrize(
        "element",
        [
            f"{URL_1}\n\n{URL_2}",
            f"\n{URL_1}\n{URL_2}\n",
            f"{URL_1}\n \t \n{URL_2}\n\n",
            f"{URL_1}\r\n{URL_2}\r\n",
            f"{URL_1}\r\n\r\n{URL_2}",
        ],
        ids=["blank_line", "edge_newlines", "whitespace_line", "crlf", "crlf_blank"],
    )
    def test_blank_lines_are_dropped_and_crlf_is_one_break(self, element: str) -> None:
        extraction = _extract(references=[element])

        assert extraction.reference_urls == (URL_1, URL_2)

    @pytest.mark.parametrize(
        ("element", "expected"),
        [
            (f" {URL_1} ", f" {URL_1} "),
            (f"{URL_1}\r", f"{URL_1}\r"),
            (f"{URL_1}\rx\n{URL_2}", f"{URL_1}\rx"),
            (f"{URL_1}\r\r\n{URL_2}", f"{URL_1}\r"),
        ],
        ids=["surrounding_space", "lone_trailing_cr", "inner_cr", "double_cr"],
    )
    def test_other_lines_are_kept_verbatim(self, element: str, expected: str) -> None:
        extraction = _extract(references=[element])

        assert extraction.reference_urls[0] == expected

    @pytest.mark.parametrize("references", [[], [""], ["\n \n"], ["\r\n"]])
    def test_no_non_blank_line_is_no_extractable_data(
        self, references: list[str]
    ) -> None:
        extraction = _extract(references=references)

        assert extraction.reference_urls == ()
        assert not extraction.has_extractable_data

    def test_one_non_blank_line_is_extractable_data(self) -> None:
        assert _extract(references=["\n", "x"]).has_extractable_data

    def test_line_containing_nul_is_kept_for_the_url_boundary(self) -> None:
        extraction = _extract(references=[f"{URL_1}\x00"])

        assert extraction.reference_urls == (f"{URL_1}\x00",)


@pytest.mark.unit
class TestBugzilla:
    def test_live_link_carries_url_and_description(self) -> None:
        extraction = extract(parse_response(load_cve_fixture("cve_no_cvss")))

        assert extraction.bugzilla == BugzillaLink(
            url="https://bugzilla.redhat.com/show_bug.cgi?id=1617825",
            title="security flaw",
        )

    def test_missing_description_gives_no_title(self) -> None:
        extraction = _extract(bugzilla={"url": BUGZILLA_URL})

        assert extraction.bugzilla == BugzillaLink(url=BUGZILLA_URL, title=None)

    @pytest.mark.parametrize("url", [None, "", " ", "\n"])
    def test_empty_url_is_skipped_and_not_extractable(self, url: str | None) -> None:
        extraction = _extract(bugzilla={"url": url, "description": "Fictional flaw"})

        assert extraction.bugzilla is None
        assert not extraction.has_extractable_data

    def test_object_without_url_is_skipped(self) -> None:
        assert _extract(bugzilla={"description": "Fictional flaw"}).bugzilla is None

    def test_url_is_kept_verbatim(self) -> None:
        extraction = _extract(bugzilla={"url": f" {BUGZILLA_URL}\x00"})

        assert extraction.bugzilla == BugzillaLink(
            url=f" {BUGZILLA_URL}\x00", title=None
        )

    def test_bugzilla_alone_is_extractable_data(self) -> None:
        assert _extract(bugzilla={"url": BUGZILLA_URL}).has_extractable_data


# ---------------------------------------------------------------------------
# Packages (step 9)
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestPackages:
    def test_live_names_are_filtered_and_deduplicated(self) -> None:
        extraction = extract(parse_response(load_cve_fixture("cve_full_v3")))

        assert extraction.package_names == ("openssh",)

    def test_duplicates_are_removed_in_first_seen_order(self) -> None:
        extraction = extract(parse_response(load_cve_fixture("cve_v2_only")))

        assert extraction.package_names == ("openssl", "openssl097a", "openssl098e")

    def test_null_blank_and_slash_names_are_dropped(self) -> None:
        extraction = _extract(
            package_state=[
                {"package_name": None},
                {"package_name": ""},
                {"package_name": "  "},
                {},
                {"package_name": "example/container"},
                {"package_name": "/"},
                {"package_name": "example-b"},
                {"package_name": "example-a"},
                {"package_name": "example-b"},
            ]
        )

        assert extraction.package_names == ("example-b", "example-a")

    def test_kept_names_are_unmodified(self) -> None:
        extraction = _extract(package_state=[{"package_name": " Example:1 "}])

        assert extraction.package_names == (" Example:1 ",)

    def test_all_names_filtered_is_no_extractable_data(self) -> None:
        extraction = _extract(
            package_state=[{"package_name": None}, {"package_name": "a/b"}]
        )

        assert extraction.package_names == ()
        assert not extraction.has_extractable_data

    def test_affected_release_is_never_consumed(self) -> None:
        extraction = _extract(
            affected_release=[{"package": "example-0:1.0-1.el9"}],
            package_state=[{"package_name": "example"}],
        )

        assert extraction.package_names == ("example",)


# ---------------------------------------------------------------------------
# Extractable data
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestExtractableData:
    def test_empty_object_has_no_extractable_data(self) -> None:
        extraction = _extract()

        assert extraction == RedhatExtraction(**_nothing())
        assert not extraction.has_extractable_data

    def test_only_unconsumed_fields_have_no_extractable_data(self) -> None:
        extraction = _extract(
            name="CVE-2099-0001",
            threat_severity="Important",
            details=["Fictional details."],
            affected_release=[{"package": "example-0:1.0-1.el9"}],
        )

        assert not extraction.has_extractable_data

    def test_all_rejected_values_have_no_extractable_data(self) -> None:
        extraction = _extract(
            cvss3={"cvss3_scoring_vector": NON_BASE_V31},
            cvss={"cvss_scoring_vector": " "},
            cwe="CWE-1, CWE-2",
            references=["\n"],
            bugzilla={"url": ""},
            package_state=[{"package_name": "a/b"}],
        )

        assert not extraction.has_extractable_data
        assert extraction.skipped == ("invalid_vector", "invalid_cwe")

    @pytest.mark.parametrize(
        "fields",
        [
            {"cvss3": {"cvss3_scoring_vector": V31}},
            {"cvss": {"cvss_scoring_vector": V2}},
            {"cwe": "CWE-79"},
            {"references": [URL_1]},
            {"bugzilla": {"url": BUGZILLA_URL}},
            {"package_state": [{"package_name": "example"}]},
        ],
        ids=["v3", "v2", "cwe", "references", "bugzilla", "packages"],
    )
    def test_each_data_type_alone_is_extractable(self, fields: dict[str, Any]) -> None:
        assert _extract(**fields).has_extractable_data

    @pytest.mark.parametrize("name", CVE_SUCCESS_FIXTURES)
    def test_every_live_fixture_has_extractable_data(self, name: str) -> None:
        assert extract(parse_response(load_cve_fixture(name))).has_extractable_data
