"""Unit tests for the GitHub Advisory Database record model and extraction
(backend/app/services/tickets/ghsa_advisory_record.py).

Contract under test: docs/features/tickets/cve-sync-ghsa.md (Field Mapping
including the global presence rule, CVSS, CWE, external identifiers,
affected versions, ecosystem normalization, package-name candidates,
references, and explicitly ignored fields; Version range parsing rules;
Response Validation including External String Admissibility) and the payload
rejections of docs/features/tickets/cve-service.md (CVEIngestPayload Schema,
Canonical Payload Duplicate Handling). The fetcher owns the requests, the
CVE-ID gate, the WARNINGs, and the ingestion; those parts are tested with
the fetcher.

Advisories are the sanitized live fixtures of `tests/support/ghsa.py` or
minimal fictional objects. No database, HTTP, or log is involved.
"""

from __future__ import annotations

import copy
from datetime import UTC, datetime, timedelta
from typing import Any, Final

import pytest
from pydantic import ValidationError

from app.core.enums import CVEExternalIdentifierSource, ReferenceType
from app.services.cve_ingest import (
    AffectedVersionEntry,
    AffectedVersionOperation,
    AffectedVersionScopeOperation,
    CVEIngestPayload,
    CVSSAssessmentEntry,
    CWEEntry,
    ExternalIdentifierEntry,
)
from app.services.reference_service import AutomaticReferenceInput
from app.services.tickets.ghsa_advisory_record import (
    ECOSYSTEMS,
    GhsaAdvisory,
    GhsaExtraction,
    VersionRange,
    element_cve_id,
    extract,
    normalize_ecosystem,
    parse_advisory,
    parse_version_range,
)
from tests.support.ghsa import (
    ADVISORY_FIXTURES,
    FIXTURE_CVE_IDS,
    SINGLE_REVIEWED_CVE_ID,
    SINGLE_REVIEWED_FIXTURE,
    load_advisory_fixture,
    load_list_fixture,
)

GHSA_ID: Final = "GHSA-xxxx-yyyy-zzzz"
HTML_URL: Final = f"https://github.com/advisories/{GHSA_ID}"
REPO: Final = "https://git.example.invalid/example/project"
URL_1: Final = "https://advisory.example.invalid/upstream/1"
URL_2: Final = "https://advisory.example.invalid/upstream/2"
V31: Final = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
V40: Final = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
SECRET_INPUT: Final = "Example-Secret-Input-Value"
CREDIT_LOGIN: Final = "example-researcher"
"""The fictional credited login of every sanitized fixture."""

ALL_FIXTURES: Final = (*ADVISORY_FIXTURES, SINGLE_REVIEWED_FIXTURE)

type Bounds = tuple[str | None, str | None, bool | None]


def _single_reviewed() -> dict[str, Any]:
    advisory: dict[str, Any] = load_list_fixture(SINGLE_REVIEWED_FIXTURE)[0]
    return advisory


def _fixture(name: str) -> dict[str, Any]:
    if name == SINGLE_REVIEWED_FIXTURE:
        return _single_reviewed()
    return load_advisory_fixture(name)


def _advisory(**fields: Any) -> dict[str, Any]:
    """A minimal advisory object with the two required fields."""
    return {"ghsa_id": GHSA_ID, "html_url": HTML_URL, **fields}


def _extract(**fields: Any) -> GhsaExtraction:
    return extract(parse_advisory(_advisory(**fields)))


def _vulnerability(
    name: str | None = "example-package",
    ecosystem: str = "npm",
    version_range: str | None = "< 2.0",
) -> dict[str, Any]:
    return {
        "package": {"ecosystem": ecosystem, "name": name},
        "vulnerable_version_range": version_range,
    }


def _entries(extraction: GhsaExtraction) -> list[AffectedVersionEntry]:
    (operation,) = extraction.payload.affected_version_operations or []
    assert operation.source_container == "ghsa"
    assert operation.operation is AffectedVersionOperation.REPLACE
    assert operation.entries is not None
    return operation.entries


def _bounds(entries: list[AffectedVersionEntry]) -> list[Bounds]:
    return [(e.version, e.version_end, e.version_end_inclusive) for e in entries]


def _bounds_of(range_: VersionRange | None) -> Bounds | None:
    if range_ is None:
        return None
    return (range_.version, range_.version_end, range_.version_end_inclusive)


def _iso(value: str) -> datetime:
    return datetime.fromisoformat(value)


# ---------------------------------------------------------------------------
# Response validation
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestResponseValidation:
    @pytest.mark.parametrize("name", ALL_FIXTURES)
    def test_live_advisories_validate(self, name: str) -> None:
        assert isinstance(parse_advisory(_fixture(name)), GhsaAdvisory)

    def test_minimal_advisory_validates(self) -> None:
        advisory = parse_advisory(_advisory())

        assert advisory.ghsa_id == GHSA_ID
        assert advisory.html_url == HTML_URL
        assert advisory.model_fields_set == {"ghsa_id", "html_url"}

    @pytest.mark.parametrize("field", ["ghsa_id", "html_url"])
    def test_required_field_absent_is_a_schema_mismatch(self, field: str) -> None:
        body = _advisory()
        del body[field]

        with pytest.raises(ValidationError):
            parse_advisory(body)

    @pytest.mark.parametrize("field", ["ghsa_id", "html_url"])
    def test_required_field_null_is_a_schema_mismatch(self, field: str) -> None:
        with pytest.raises(ValidationError):
            parse_advisory(_advisory(**{field: None}))

    @pytest.mark.parametrize(
        "body",
        [[], [_advisory()], "text", 7, None, True],
        ids=["empty_array", "array", "string", "int", "null", "bool"],
    )
    def test_non_object_root_is_a_schema_mismatch(self, body: Any) -> None:
        with pytest.raises(ValidationError):
            parse_advisory(body)

    @pytest.mark.parametrize(
        "fields",
        [
            {"ghsa_id": 1},
            {"html_url": ["x"]},
            {"summary": 1},
            {"summary": True},
            {"description": {}},
            {"source_code_location": 1},
            {"references": URL_1},
            {"references": [1]},
            {"references": [None]},
            {"references": {}},
            {"cwes": ["CWE-79"]},
            {"cwes": [{"cwe_id": 79}]},
            {"cwes": [{"name": "Example"}]},
            {"cwes": {}},
            {"cvss_severities": []},
            {"cvss_severities": {"cvss_v3": V31}},
            {"cvss_severities": {"cvss_v3": {"vector_string": 1}}},
            {"cvss_severities": {"cvss_v4": {"vector_string": 1}}},
            {"cvss_severities": {"cvss_v4": {"vector_string": [V40]}}},
            {"vulnerabilities": {}},
            {"vulnerabilities": [1]},
            {"vulnerabilities": [None]},
            {"vulnerabilities": [{"package": "example"}]},
            {"vulnerabilities": [{"package": {"ecosystem": 1}}]},
            {"vulnerabilities": [{"package": {"ecosystem": "npm", "name": 1}}]},
            {"vulnerabilities": [{"vulnerable_version_range": 1}]},
            {"vulnerabilities": [{"vulnerable_version_range": ["< 1"]}]},
        ],
        ids=[
            "ghsa_id_int",
            "html_url_list",
            "summary_int",
            "summary_bool",
            "description_object",
            "source_code_location_int",
            "references_string",
            "references_int_item",
            "references_null_item",
            "references_object",
            "cwes_strings",
            "cwe_id_int",
            "cwe_id_absent",
            "cwes_object",
            "cvss_severities_array",
            "cvss_v3_string",
            "cvss_v3_vector_int",
            "cvss_v4_vector_int",
            "cvss_v4_vector_list",
            "vulnerabilities_object",
            "vulnerabilities_int_item",
            "vulnerabilities_null_item",
            "package_string",
            "package_ecosystem_int",
            "package_name_int",
            "range_int",
            "range_list",
        ],
    )
    def test_consumed_field_of_another_json_type_is_a_schema_mismatch(
        self, fields: dict[str, Any]
    ) -> None:
        with pytest.raises(ValidationError):
            parse_advisory(_advisory(**fields))

    @pytest.mark.parametrize("field", ["published_at", "updated_at"])
    @pytest.mark.parametrize(
        "value",
        [
            1_700_000_000,
            1.5,
            True,
            ["2024-06-19T15:04:41Z"],
            "2024-06-19",
            "2024-06-19T15:04:41",
            "not a date-time",
            "",
            "2024-06-19T15:04:41Z\x00",
            "\x002024-06-19T15:04:41Z",
            "2024-06-19\x0015:04:41Z",
            "2024-06-19T15:04:41\x00Z",
            "2024-06-19T15:04:41+00:00\x00",
            "\x00",
            "2024-13-19T15:04:41Z",
        ],
        ids=[
            "int",
            "float",
            "bool",
            "list",
            "date_only",
            "naive",
            "text",
            "empty",
            "trailing_nul",
            "leading_nul",
            "nul_separator",
            "nul_before_zone",
            "nul_after_offset",
            "only_nul",
            "invalid_month",
        ],
    )
    def test_invalid_date_time_is_a_schema_mismatch(
        self, field: str, value: Any
    ) -> None:
        with pytest.raises(ValidationError):
            parse_advisory(_advisory(**{field: value}))

    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            ("2024-06-19T15:04:41Z", datetime(2024, 6, 19, 15, 4, 41, tzinfo=UTC)),
            (
                "2024-06-19T17:04:41+02:00",
                datetime(2024, 6, 19, 15, 4, 41, tzinfo=UTC),
            ),
            (
                "2024-06-19T15:04:41.250Z",
                datetime(2024, 6, 19, 15, 4, 41, 250000, tzinfo=UTC),
            ),
        ],
        ids=["zulu", "offset", "fraction"],
    )
    def test_date_time_with_an_offset_is_an_aware_instant(
        self, value: str, expected: datetime
    ) -> None:
        advisory = parse_advisory(_advisory(published_at=value, updated_at=value))

        assert advisory.published_at == expected
        assert advisory.updated_at == expected
        assert advisory.published_at is not None
        assert advisory.published_at.utcoffset() is not None

    @pytest.mark.parametrize(
        "field",
        [
            "source_code_location",
            "references",
            "cwes",
            "cvss_severities",
            "vulnerabilities",
        ],
    )
    def test_null_non_global_field_is_absent(self, field: str) -> None:
        assert getattr(parse_advisory(_advisory(**{field: None})), field) is None

    def test_null_nested_fields_are_absent(self) -> None:
        advisory = parse_advisory(
            _advisory(
                cvss_severities={"cvss_v3": None, "cvss_v4": {"vector_string": None}},
                vulnerabilities=[
                    {"package": None, "vulnerable_version_range": None},
                    {"package": {"ecosystem": "npm", "name": None}},
                ],
            )
        )

        assert advisory.cvss_severities is not None
        assert advisory.cvss_severities.cvss_v3 is None
        assert advisory.cvss_severities.cvss_v4 is not None
        assert advisory.cvss_severities.cvss_v4.vector_string is None
        assert advisory.vulnerabilities is not None
        assert advisory.vulnerabilities[0].package is None
        assert advisory.vulnerabilities[1].package is not None
        assert advisory.vulnerabilities[1].package.name is None

    @pytest.mark.parametrize(
        "body",
        [
            _advisory(summary=[SECRET_INPUT]),
            _advisory(published_at=SECRET_INPUT),
            _advisory(updated_at=f"2024-06-19T{SECRET_INPUT}"),
            _advisory(references=SECRET_INPUT),
            _advisory(references=[SECRET_INPUT, 1]),
            _advisory(cwes=[SECRET_INPUT]),
            _advisory(cvss_severities={"cvss_v3": SECRET_INPUT}),
            _advisory(vulnerabilities=[{"package": {"ecosystem": [SECRET_INPUT]}}]),
            _advisory(vulnerabilities={SECRET_INPUT: SECRET_INPUT}),
            {"ghsa_id": None, "html_url": SECRET_INPUT, "summary": 1},
            SECRET_INPUT,
            [SECRET_INPUT],
        ],
        ids=[
            "summary_list",
            "unparseable_published_at",
            "unparseable_updated_at",
            "references_string",
            "references_items",
            "cwes_strings",
            "cvss_v3_string",
            "ecosystem_list",
            "vulnerabilities_object",
            "required_null",
            "string_root",
            "array_root",
        ],
    )
    def test_validation_error_never_renders_the_input(self, body: Any) -> None:
        with pytest.raises(ValidationError) as raised:
            parse_advisory(body)

        assert SECRET_INPUT not in str(raised.value)
        assert SECRET_INPUT not in repr(raised.value)

    def test_unconsumed_fields_of_any_type_are_not_validated(self) -> None:
        advisory = parse_advisory(
            _advisory(
                cve_id=1,
                severity=[],
                cvss="x",
                epss=7,
                identifiers="GHSA",
                credits=None,
                cwes=[{"cwe_id": "CWE-79", "name": 1}],
                cvss_severities={"cvss_v3": {"vector_string": V31, "score": "high"}},
                vulnerabilities=[
                    {
                        "package": {"ecosystem": "npm", "name": "x", "purl": 1},
                        "first_patched_version": {"identifier": 1},
                        "vulnerable_functions": 3,
                    }
                ],
            )
        )

        assert isinstance(advisory, GhsaAdvisory)


# ---------------------------------------------------------------------------
# element_cve_id (Algorithm steps 6.d.i-ii input)
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestElementCveId:
    @pytest.mark.parametrize(
        ("element", "expected"),
        [
            ({"cve_id": "CVE-2099-0001"}, "CVE-2099-0001"),
            ({"cve_id": "not-a-cve"}, "not-a-cve"),
            ({"cve_id": 7}, 7),
            ({"cve_id": None}, None),
            ({}, None),
            ([{"cve_id": "CVE-2099-0001"}], None),
            ("CVE-2099-0001", None),
            (None, None),
            (7, None),
        ],
        ids=[
            "string",
            "malformed_string",
            "int",
            "null",
            "absent",
            "array",
            "string_element",
            "null_element",
            "int_element",
        ],
    )
    def test_raw_cve_id_is_returned_unvalidated(
        self, element: object, expected: object
    ) -> None:
        assert element_cve_id(element) == expected

    @pytest.mark.parametrize("name", ADVISORY_FIXTURES)
    def test_live_advisory_cve_id(self, name: str) -> None:
        assert element_cve_id(load_advisory_fixture(name)) == FIXTURE_CVE_IDS[name]

    def test_live_single_query_cve_id(self) -> None:
        assert element_cve_id(_single_reviewed()) == SINGLE_REVIEWED_CVE_ID


# ---------------------------------------------------------------------------
# Global CVE fields
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestGlobalFields:
    def test_present_globals_are_mapped(self) -> None:
        payload = _extract(
            summary="Fictional summary.",
            description="Fictional **markdown** description.",
            published_at="2024-06-19T15:04:41Z",
            updated_at="2026-09-24T16:45:27+02:00",
        ).payload

        assert payload.title == "Fictional summary."
        assert payload.description == "Fictional **markdown** description."
        assert payload.published_date == datetime(2024, 6, 19, 15, 4, 41, tzinfo=UTC)
        assert payload.modified_date == datetime(2026, 9, 24, 14, 45, 27, tzinfo=UTC)
        assert payload.modified_date is not None
        assert payload.modified_date.utcoffset() == timedelta(0)

    def test_absent_globals_are_omitted(self) -> None:
        payload = _extract().payload

        assert {
            "title",
            "description",
            "published_date",
            "modified_date",
        }.isdisjoint(payload.model_fields_set)

    @pytest.mark.parametrize(
        ("source", "target"),
        [
            ("summary", "title"),
            ("description", "description"),
            ("published_at", "published_date"),
            ("updated_at", "modified_date"),
        ],
    )
    def test_explicit_null_global_is_present_as_none(
        self, source: str, target: str
    ) -> None:
        payload = _extract(**{source: None}).payload

        assert target in payload.model_fields_set
        assert getattr(payload, target) is None
        assert payload.model_fields_set & {
            "title",
            "description",
            "published_date",
            "modified_date",
        } == {target}

    def test_empty_strings_are_values(self) -> None:
        payload = _extract(summary="", description="").payload

        assert payload.title == ""
        assert payload.description == ""

    @pytest.mark.parametrize(
        ("length", "stored"), [(255, 255), (256, 256), (257, 256), (1024, 256)]
    )
    def test_summary_truncation(self, length: int, stored: int) -> None:
        summary = "".join(chr(ord("a") + i % 26) for i in range(length))

        payload = _extract(summary=summary).payload

        assert payload.title == summary[:stored]

    @pytest.mark.parametrize(
        ("length", "stored"), [(65535, 65535), (65536, 65535), (70000, 65535)]
    )
    def test_description_truncation(self, length: int, stored: int) -> None:
        description = "d" * (length - 1) + "e"

        payload = _extract(description=description).payload

        assert payload.description == description[:stored]
        assert payload.description is not None
        assert len(payload.description) == stored

    def test_truncation_precedes_validation(self) -> None:
        """A U+0000 only in the truncated tail never reaches the payload."""
        payload = _extract(
            summary="s" * 256 + "\x00", description="d" * 65535 + "\x00"
        ).payload

        assert payload.title == "s" * 256
        assert payload.description == "d" * 65535

    @pytest.mark.parametrize("name", ALL_FIXTURES)
    def test_cve_state_and_date_rejected_are_never_set(self, name: str) -> None:
        body = {**_fixture(name), "cve_state": "REJECTED", "date_rejected": "x"}

        payload = extract(parse_advisory(body)).payload

        assert "cve_state" not in payload.model_fields_set
        assert "date_rejected" not in payload.model_fields_set
        assert payload.cve_state is None
        assert payload.date_rejected is None

    def test_minimal_advisory_carries_only_the_external_identifier(self) -> None:
        extraction = _extract()

        assert extraction.payload.model_fields_set == {"external_identifiers"}
        assert extraction.upstream_references == []
        assert extraction.skipped_cwes == 0
        assert extraction.unrecognized_ranges == 0


# ---------------------------------------------------------------------------
# External identifier and references
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestExternalIdentifierAndReferences:
    def test_external_identifier_is_the_ghsa_id_and_html_url(self) -> None:
        payload = _extract().payload

        assert payload.external_identifiers == [
            ExternalIdentifierEntry(
                source=CVEExternalIdentifierSource.GHSA,
                identifier=GHSA_ID,
                url=HTML_URL,
            )
        ]

    def test_source_candidate_precedes_upstream_candidates_in_order(self) -> None:
        extraction = _extract(references=[URL_2, URL_1, URL_2, HTML_URL])

        assert extraction.source_reference == AutomaticReferenceInput(
            url=HTML_URL,
            title="GitHub Advisory",
            explicit_type=ReferenceType.ADVISORY,
        )
        assert extraction.upstream_references == [
            AutomaticReferenceInput(url=URL_2),
            AutomaticReferenceInput(url=URL_1),
            AutomaticReferenceInput(url=URL_2),
            AutomaticReferenceInput(url=HTML_URL),
        ]
        assert all(
            c.title is None and c.explicit_type is None and c.upstream_tags is None
            for c in extraction.upstream_references
        )

    @pytest.mark.parametrize(
        "fields",
        [{}, {"references": None}, {"references": []}],
        ids=["absent", "null", "empty"],
    )
    def test_no_references_give_no_upstream_candidates(
        self, fields: dict[str, Any]
    ) -> None:
        extraction = _extract(**fields)

        assert extraction.upstream_references == []
        assert extraction.source_reference.url == HTML_URL

    @pytest.mark.parametrize("url", [f"{URL_1}\x00", " not a url ", ""])
    def test_upstream_url_is_passed_as_received(self, url: str) -> None:
        """`reference_service` owns URL rejection (U+0000 is skipped there as
        `control_character`), never the advisory."""
        extraction = _extract(references=[url, URL_2])

        assert extraction.upstream_references == [
            AutomaticReferenceInput(url=url),
            AutomaticReferenceInput(url=URL_2),
        ]

    @pytest.mark.parametrize("name", ALL_FIXTURES)
    def test_live_references(self, name: str) -> None:
        body = _fixture(name)

        extraction = extract(parse_advisory(body))

        assert extraction.source_reference == AutomaticReferenceInput(
            url=body["html_url"],
            title="GitHub Advisory",
            explicit_type=ReferenceType.ADVISORY,
        )
        assert extraction.upstream_references == [
            AutomaticReferenceInput(url=url) for url in body["references"]
        ]
        assert extraction.payload.external_identifiers == [
            ExternalIdentifierEntry(
                source=CVEExternalIdentifierSource.GHSA,
                identifier=body["ghsa_id"],
                url=body["html_url"],
            )
        ]


# ---------------------------------------------------------------------------
# CVSS assessments
# ---------------------------------------------------------------------------


def _candidate(vector: str) -> CVSSAssessmentEntry:
    return CVSSAssessmentEntry(provider_name="GitHub", vector_string=vector)


@pytest.mark.unit
class TestCvssCandidates:
    @pytest.mark.parametrize(
        ("severities", "expected"),
        [
            ({"cvss_v3": {"vector_string": V31}}, [V31]),
            ({"cvss_v4": {"vector_string": V40}}, [V40]),
            (
                {"cvss_v3": {"vector_string": V31}, "cvss_v4": {"vector_string": V40}},
                [V31, V40],
            ),
            (
                {"cvss_v4": {"vector_string": V40}, "cvss_v3": {"vector_string": V31}},
                [V31, V40],
            ),
            ({"cvss_v3": {"vector_string": V40}}, [V40]),
            ({"cvss_v3": {"vector_string": "not a vector"}}, ["not a vector"]),
            ({"cvss_v4": {"vector_string": V40 + "/E:P"}}, [V40 + "/E:P"]),
            ({"cvss_v3": {"vector_string": V31 + "\x00"}}, [V31 + "\x00"]),
            ({"cvss_v3": {"vector_string": " "}}, [" "]),
        ],
        ids=[
            "v3_only",
            "v4_only",
            "both",
            "both_reversed_keys",
            "v4_vector_in_v3_slot",
            "malformed",
            "non_base",
            "nul",
            "blank",
        ],
    )
    def test_non_empty_vectors_are_passed_unchanged(
        self, severities: dict[str, Any], expected: list[str]
    ) -> None:
        payload = _extract(cvss_severities=severities).payload

        assert payload.cvss_assessments == [_candidate(v) for v in expected]

    @pytest.mark.parametrize(
        "fields",
        [
            {},
            {"cvss_severities": None},
            {"cvss_severities": {}},
            {"cvss_severities": {"cvss_v3": None, "cvss_v4": None}},
            {"cvss_severities": {"cvss_v3": {}, "cvss_v4": {}}},
            {
                "cvss_severities": {
                    "cvss_v3": {"vector_string": None},
                    "cvss_v4": {"vector_string": None},
                }
            },
            {
                "cvss_severities": {
                    "cvss_v3": {"vector_string": ""},
                    "cvss_v4": {"vector_string": ""},
                }
            },
        ],
        ids=[
            "absent",
            "null",
            "empty_object",
            "null_versions",
            "absent_vectors",
            "null_vectors",
            "empty_vectors",
        ],
    )
    def test_no_candidate_omits_cvss_assessments(self, fields: dict[str, Any]) -> None:
        payload = _extract(**fields).payload

        assert "cvss_assessments" not in payload.model_fields_set
        assert payload.cvss_assessments is None

    def test_one_null_vector_does_not_drop_the_other(self) -> None:
        payload = _extract(
            cvss_severities={
                "cvss_v3": {"vector_string": None, "score": 0.0},
                "cvss_v4": {"vector_string": V40, "score": 9.9},
            }
        ).payload

        assert payload.cvss_assessments == [_candidate(V40)]

    @pytest.mark.parametrize(
        ("name", "expected"),
        [
            (
                "advisory_v3_v4",
                [
                    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L",
                    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N",
                ],
            ),
            (
                "advisory_v4_non_base",
                [
                    "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:L/VI:H/VA:N/SC:N/SI:N/SA:N/E:P",
                ],
            ),
            (
                "advisory_v3_v4_non_base_ranges",
                [
                    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    "CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N"
                    "/RE:M/U:Red",
                ],
            ),
            (
                "advisory_erlang",
                [
                    "CVSS:4.0/AV:L/AC:L/AT:P/PR:N/UI:N/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N",
                ],
            ),
            (
                SINGLE_REVIEWED_FIXTURE,
                ["CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:H"],
            ),
        ],
    )
    def test_live_vectors_are_passed_unparsed(
        self, name: str, expected: list[str]
    ) -> None:
        payload = extract(parse_advisory(_fixture(name))).payload

        assert payload.cvss_assessments == [_candidate(v) for v in expected]

    @pytest.mark.parametrize("name", ALL_FIXTURES)
    def test_live_candidates_follow_the_non_null_vectors(self, name: str) -> None:
        body = _fixture(name)
        severities = body["cvss_severities"]
        expected = [
            severities[key]["vector_string"]
            for key in ("cvss_v3", "cvss_v4")
            if severities[key]["vector_string"]
        ]

        payload = extract(parse_advisory(body)).payload

        assert payload.cvss_assessments == [_candidate(v) for v in expected]


# ---------------------------------------------------------------------------
# CWE classifications
# ---------------------------------------------------------------------------


def _cwes(*ids: str) -> list[dict[str, str]]:
    return [{"cwe_id": cwe_id, "name": "Example weakness"} for cwe_id in ids]


@pytest.mark.unit
class TestCweCandidates:
    def test_valid_cwes_are_kept_in_order(self) -> None:
        extraction = _extract(cwes=_cwes("CWE-79", "CWE-20", "CWE-79"))

        assert extraction.payload.cwe_classifications == [
            CWEEntry(cwe_id="CWE-79", source="GitHub"),
            CWEEntry(cwe_id="CWE-20", source="GitHub"),
            CWEEntry(cwe_id="CWE-79", source="GitHub"),
        ]
        assert extraction.skipped_cwes == 0

    def test_twenty_character_cwe_is_kept(self) -> None:
        cwe_id = "CWE-" + "1" * 16
        assert len(cwe_id) == 20

        extraction = _extract(cwes=_cwes(cwe_id))

        assert extraction.payload.cwe_classifications == [
            CWEEntry(cwe_id=cwe_id, source="GitHub")
        ]

    @pytest.mark.parametrize(
        "cwe_id",
        [
            "CWE-0",
            "CWE-079",
            "NVD-CWE-Other",
            "NVD-CWE-noinfo",
            "cwe-79",
            "CWE-",
            "CWE79",
            "",
            " CWE-79",
            "CWE-79 ",
            "CWE-79\n",
            "CWE-\u0667\u0669",
            "CWE-79\x00",
            "\x00",
            "CWE-" + "1" * 17,
        ],
        ids=[
            "zero",
            "leading_zero",
            "nvd_other",
            "nvd_noinfo",
            "lowercase",
            "no_number",
            "no_hyphen",
            "empty",
            "leading_space",
            "trailing_space",
            "trailing_newline",
            "non_ascii_digits",
            "nul",
            "only_nul",
            "over_long",
        ],
    )
    def test_invalid_cwe_is_skipped_and_counted(self, cwe_id: str) -> None:
        extraction = _extract(cwes=_cwes("CWE-20", cwe_id, "CWE-79"))

        assert extraction.payload.cwe_classifications == [
            CWEEntry(cwe_id="CWE-20", source="GitHub"),
            CWEEntry(cwe_id="CWE-79", source="GitHub"),
        ]
        assert extraction.skipped_cwes == 1

    @pytest.mark.parametrize(
        ("fields", "skipped"),
        [
            ({}, 0),
            ({"cwes": None}, 0),
            ({"cwes": []}, 0),
            ({"cwes": _cwes("CWE-0", "NVD-CWE-Other", "cwe-79")}, 3),
        ],
        ids=["absent", "null", "empty", "only_invalid"],
    )
    def test_no_valid_cwe_omits_cwe_classifications(
        self, fields: dict[str, Any], skipped: int
    ) -> None:
        extraction = _extract(**fields)

        assert "cwe_classifications" not in extraction.payload.model_fields_set
        assert extraction.skipped_cwes == skipped

    @pytest.mark.parametrize("name", ALL_FIXTURES)
    def test_live_cwes(self, name: str) -> None:
        body = _fixture(name)

        extraction = extract(parse_advisory(body))

        assert extraction.payload.cwe_classifications == [
            CWEEntry(cwe_id=cwe["cwe_id"], source="GitHub") for cwe in body["cwes"]
        ]
        assert extraction.skipped_cwes == 0


# ---------------------------------------------------------------------------
# Version range parsing rules
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestParseVersionRange:
    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            # Base patterns
            ("< 1.2.3", (None, "1.2.3", False)),
            ("<= 1.2.3", (None, "1.2.3", True)),
            (">= 1.0, < 2.0", ("1.0", "2.0", False)),
            (">= 1.0, <= 2.0", ("1.0", "2.0", True)),
            ("= 1.5.0", ("1.5.0", "1.5.0", True)),
            ("> 1.0, < 2.0", ("1.0", "2.0", False)),
            ("> 1.0, <= 2.0", ("1.0", "2.0", True)),
            # No upper bound
            (">= 1.0", ("1.0", None, None)),
            ("> 1.0", ("1.0", None, None)),
            # Variable whitespace
            (">=1.0,<2.0", ("1.0", "2.0", False)),
            ("  >=   1.0  ,   <  2.0  ", ("1.0", "2.0", False)),
            ("\t>= 1.0,\t<= 2.0\n", ("1.0", "2.0", True)),
            ("<1.2.3", (None, "1.2.3", False)),
            ("=1.5.0", ("1.5.0", "1.5.0", True)),
            # Non-semver opaque strings
            (">= 2.0-beta9, < 2.3.1", ("2.0-beta9", "2.3.1", False)),
            ("= 0.40.0-preview.2", ("0.40.0-preview.2", "0.40.0-preview.2", True)),
            ("< 4.0.0-canary.34", (None, "4.0.0-canary.34", False)),
            ("< v1.0 final", (None, "v1.0 final", False)),
            (">= 1:2.3~rc1", ("1:2.3~rc1", None, None)),
        ],
        ids=[
            "lt",
            "le",
            "ge_lt",
            "ge_le",
            "eq",
            "gt_lt",
            "gt_le",
            "ge_only",
            "gt_only",
            "no_whitespace",
            "extra_whitespace",
            "tabs_and_newline",
            "lt_no_space",
            "eq_no_space",
            "pre_release",
            "eq_pre_release",
            "canary",
            "internal_space",
            "epoch_and_tilde",
        ],
    )
    def test_recognized_range(self, value: str, expected: Bounds) -> None:
        assert _bounds_of(parse_version_range(value)) == expected

    @pytest.mark.parametrize("value", [None, "", " ", "\t\n"])
    def test_null_empty_or_blank_range_has_no_bounds(self, value: str | None) -> None:
        assert parse_version_range(value) == VersionRange()
        assert _bounds_of(parse_version_range(value)) == (None, None, None)

    @pytest.mark.parametrize(
        "value",
        [
            "< 1.0, < 2.0",
            "<= 1.0, < 2.0",
            "< 2.0, >= 1.0",
            ">= 1.0, >= 2.0",
            "= 1.0, < 2.0",
            ">= 1.0, = 2.0",
            ">= 1.0, < 2.0, < 3.0",
            ">= 1.0, < 2.0, >= 3.0",
            "~1.0",
            "^1.0",
            "!= 1.0",
            "== 1.0",
            "=> 1.0",
            "=< 1.0",
            ">=, < 2",
            ">= 1.0, <",
            ">=",
            "<",
            ">==1",
            "<<1",
            ">= >1",
            "< =1",
            "1.0",
            "1.0 - 2.0",
            ">= 1.0,",
            ", < 2.0",
            "< 1<2",
            ">= 1.0 < 2.0",
            ">= 1.0; < 2.0",
        ],
        ids=[
            "two_uppers",
            "two_uppers_mixed",
            "reversed_order",
            "two_lowers",
            "eq_with_upper",
            "lower_with_eq",
            "three_constraints",
            "three_constraints_lower_last",
            "tilde",
            "caret",
            "not_equal",
            "double_equal",
            "reversed_ge",
            "reversed_le",
            "empty_lower_operand",
            "empty_upper_operand",
            "lone_ge",
            "lone_lt",
            "operand_starts_with_equal",
            "operand_starts_with_lt",
            "operand_starts_with_gt",
            "operand_starts_with_equal_after_space",
            "no_operator",
            "hyphen_range",
            "trailing_comma",
            "leading_comma",
            "inner_operator_character",
            "two_constraints_without_comma",
            "semicolon_separator",
        ],
    )
    def test_unrecognized_range(self, value: str) -> None:
        assert parse_version_range(value) is None


# ---------------------------------------------------------------------------
# Affected versions and package-name candidates
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAffectedVersions:
    @pytest.mark.parametrize(
        "fields", [{}, {"vulnerabilities": None}], ids=["absent", "null"]
    )
    def test_absent_or_null_vulnerabilities_emit_no_operation(
        self, fields: dict[str, Any]
    ) -> None:
        payload = _extract(source_code_location=REPO, **fields).payload

        assert "affected_version_operations" not in payload.model_fields_set
        assert "resolved_packages" not in payload.model_fields_set

    def test_empty_vulnerabilities_emit_an_empty_replacement(self) -> None:
        payload = _extract(source_code_location=REPO, vulnerabilities=[]).payload

        assert payload.affected_version_operations == [
            AffectedVersionScopeOperation(
                source_container="ghsa",
                operation=AffectedVersionOperation.REPLACE,
                entries=[],
            )
        ]
        assert "resolved_packages" not in payload.model_fields_set

    def test_entries_are_a_complete_replacement_in_input_order(self) -> None:
        extraction = _extract(
            source_code_location=REPO,
            vulnerabilities=[
                _vulnerability("example-b", "pip", ">= 1.0, < 2.0"),
                _vulnerability("example-a", "maven", "<= 3.0"),
                _vulnerability("example-b", "pip", "= 2.5"),
            ],
        )

        assert extraction.payload.affected_version_operations == [
            AffectedVersionScopeOperation(
                source_container="ghsa",
                operation=AffectedVersionOperation.REPLACE,
                entries=[
                    AffectedVersionEntry(
                        product="example-b",
                        package_name="example-b",
                        version="1.0",
                        version_end="2.0",
                        version_end_inclusive=False,
                        repo=REPO,
                        ecosystem="PyPI",
                    ),
                    AffectedVersionEntry(
                        product="example-a",
                        package_name="example-a",
                        version_end="3.0",
                        version_end_inclusive=True,
                        repo=REPO,
                        ecosystem="Maven",
                    ),
                    AffectedVersionEntry(
                        product="example-b",
                        package_name="example-b",
                        version="2.5",
                        version_end="2.5",
                        version_end_inclusive=True,
                        repo=REPO,
                        ecosystem="PyPI",
                    ),
                ],
            )
        ]
        assert extraction.payload.resolved_packages == ["example-b", "example-a"]
        assert extraction.unrecognized_ranges == 0

    def test_unmapped_entry_fields_are_null(self) -> None:
        (entry,) = _entries(_extract(vulnerabilities=[_vulnerability()]))

        assert entry.vendor is None
        assert entry.package_url is None
        assert entry.collection_url is None
        assert entry.cpe is None
        assert entry.program_files is None
        assert entry.version_type is None
        assert entry.status is None
        assert entry.default_status is None

    @pytest.mark.parametrize(
        "vulnerability",
        [
            {"package": None, "vulnerable_version_range": "< 2.0"},
            {"vulnerable_version_range": "< 2.0"},
        ],
        ids=["null_package", "absent_package"],
    )
    def test_entry_without_package_is_kept_without_coordinates(
        self, vulnerability: dict[str, Any]
    ) -> None:
        extraction = _extract(
            source_code_location=REPO, vulnerabilities=[vulnerability]
        )

        assert _entries(extraction) == [
            AffectedVersionEntry(
                version_end="2.0", version_end_inclusive=False, repo=REPO
            )
        ]
        assert "resolved_packages" not in extraction.payload.model_fields_set

    @pytest.mark.parametrize(
        "package",
        [{"ecosystem": "go", "name": None}, {"ecosystem": "go"}],
        ids=["null_name", "absent_name"],
    )
    def test_entry_without_name_keeps_the_ecosystem(
        self, package: dict[str, Any]
    ) -> None:
        extraction = _extract(
            vulnerabilities=[{"package": package, "vulnerable_version_range": "< 2"}]
        )

        assert _entries(extraction) == [
            AffectedVersionEntry(
                version_end="2", version_end_inclusive=False, ecosystem="Go"
            )
        ]
        assert "resolved_packages" not in extraction.payload.model_fields_set

    @pytest.mark.parametrize(
        ("fields", "expected"),
        [
            ({"source_code_location": REPO}, REPO),
            ({"source_code_location": ""}, None),
            ({"source_code_location": None}, None),
            ({}, None),
        ],
        ids=["value", "empty", "null", "absent"],
    )
    def test_repo_is_the_advisory_source_code_location(
        self, fields: dict[str, Any], expected: str | None
    ) -> None:
        entries = _entries(
            _extract(
                vulnerabilities=[
                    _vulnerability("example-a"),
                    _vulnerability("example-b"),
                ],
                **fields,
            )
        )

        assert [e.repo for e in entries] == [expected, expected]

    @pytest.mark.parametrize(
        "version_range",
        [None, "", "   "],
        ids=["null", "empty", "blank"],
    )
    def test_entry_without_range_has_null_bounds(
        self, version_range: str | None
    ) -> None:
        extraction = _extract(
            vulnerabilities=[_vulnerability(version_range=version_range)]
        )

        assert _bounds(_entries(extraction)) == [(None, None, None)]
        assert extraction.unrecognized_ranges == 0

    def test_absent_range_has_null_bounds(self) -> None:
        extraction = _extract(
            vulnerabilities=[{"package": {"ecosystem": "npm", "name": "example"}}]
        )

        assert _bounds(_entries(extraction)) == [(None, None, None)]
        assert extraction.unrecognized_ranges == 0

    def test_unrecognized_range_keeps_the_entry_and_is_counted(self) -> None:
        extraction = _extract(
            vulnerabilities=[
                _vulnerability("example-a", version_range="~1.0"),
                _vulnerability("example-b", version_range=">= 1.0, < 2.0"),
                _vulnerability("example-c", version_range="< 1.0, < 2.0"),
            ]
        )

        entries = _entries(extraction)

        assert [
            (e.package_name, *b) for e, b in zip(entries, _bounds(entries), strict=True)
        ] == [
            ("example-a", None, None, None),
            ("example-b", "1.0", "2.0", False),
            ("example-c", None, None, None),
        ]
        assert extraction.unrecognized_ranges == 2
        assert extraction.payload.resolved_packages == [
            "example-a",
            "example-b",
            "example-c",
        ]

    def test_u0000_in_an_unrecognized_range_is_not_a_bound(self) -> None:
        extraction = _extract(vulnerabilities=[_vulnerability(version_range="~1\x00")])

        assert _bounds(_entries(extraction)) == [(None, None, None)]
        assert extraction.unrecognized_ranges == 1

    def test_identical_entries_are_admissible(self) -> None:
        extraction = _extract(
            vulnerabilities=[_vulnerability(), _vulnerability(), _vulnerability()]
        )

        assert len(_entries(extraction)) == 3
        assert extraction.payload.resolved_packages == ["example-package"]

    def test_same_key_entries_with_differing_content_reject_the_payload(self) -> None:
        """`< 2.0` and `<= 2.0` share the entry conflict key and differ only
        in `version_end_inclusive` (cve-service.md, Canonical Payload
        Duplicate Handling)."""
        with pytest.raises(ValidationError):
            _extract(
                vulnerabilities=[
                    _vulnerability(version_range="< 2.0"),
                    _vulnerability(version_range="<= 2.0"),
                ]
            )


@pytest.mark.unit
class TestEcosystemNormalization:
    @pytest.mark.parametrize(
        ("github", "expected"),
        [
            ("pip", "PyPI"),
            ("go", "Go"),
            ("rust", "crates.io"),
            ("npm", "npm"),
            ("maven", "Maven"),
            ("nuget", "NuGet"),
            ("composer", "Packagist"),
            ("rubygems", "RubyGems"),
            ("pub", "Pub"),
            ("erlang", "Hex"),
            ("actions", "GitHub Actions"),
            ("swift", "SwiftURL"),
            ("other", None),
        ],
    )
    def test_documented_mapping(self, github: str, expected: str | None) -> None:
        assert normalize_ecosystem(github) == expected
        (entry,) = _entries(
            _extract(vulnerabilities=[_vulnerability(ecosystem=github)])
        )
        assert entry.ecosystem == expected

    def test_mapping_covers_exactly_the_documented_values(self) -> None:
        assert set(ECOSYSTEMS) == {
            "rubygems",
            "npm",
            "pip",
            "maven",
            "nuget",
            "composer",
            "go",
            "rust",
            "erlang",
            "actions",
            "pub",
            "other",
            "swift",
        }

    @pytest.mark.parametrize("value", ["conda", "PIP", "Npm", "", "E" * 50])
    def test_unmapped_value_is_stored_as_received(self, value: str) -> None:
        assert normalize_ecosystem(value) == value
        (entry,) = _entries(_extract(vulnerabilities=[_vulnerability(ecosystem=value)]))
        assert entry.ecosystem == value


@pytest.mark.unit
class TestPackageNames:
    def test_names_are_deduplicated_in_first_occurrence_order(self) -> None:
        extraction = _extract(
            vulnerabilities=[
                _vulnerability("example-b", version_range="< 1"),
                {"package": None},
                _vulnerability(None, version_range="< 2"),
                _vulnerability("", version_range="< 3"),
                _vulnerability("   ", version_range="< 4"),
                _vulnerability("example-a", version_range="< 5"),
                _vulnerability("example-b", version_range="< 6"),
                _vulnerability("Example-B", version_range="< 7"),
                _vulnerability(" example-a", version_range="< 8"),
                _vulnerability("example-b", "pip", version_range="< 9"),
            ]
        )

        assert extraction.payload.resolved_packages == [
            "example-b",
            "example-a",
            "Example-B",
            " example-a",
        ]
        assert len(_entries(extraction)) == 10

    def test_only_discarded_names_omit_resolved_packages(self) -> None:
        extraction = _extract(
            vulnerabilities=[
                {"package": None},
                _vulnerability(None, version_range="< 2"),
                _vulnerability("", version_range="< 3"),
                _vulnerability(" \t", version_range="< 4"),
            ]
        )

        assert len(_entries(extraction)) == 4
        assert "resolved_packages" not in extraction.payload.model_fields_set

    def test_entry_product_keeps_an_empty_name(self) -> None:
        """Only the candidate list discards blank names; the display entry
        keeps the received value."""
        (entry,) = _entries(_extract(vulnerabilities=[_vulnerability("  ")]))

        assert entry.product == "  "
        assert entry.package_name == "  "


# ---------------------------------------------------------------------------
# Explicitly ignored fields
# ---------------------------------------------------------------------------


IGNORED_TOP_LEVEL: Final[dict[str, Any]] = {
    "credits": [{"user": {"login": SECRET_INPUT}, "type": SECRET_INPUT}],
    "severity": 5,
    "cvss": {"vector_string": V40, "score": "x"},
    "epss": SECRET_INPUT,
    "identifiers": [{"type": "GHSA", "value": SECRET_INPUT}],
    "comments": "many",
    "withdrawn_at": 1,
    "nvd_published_at": [],
    "github_reviewed_at": {},
    "url": 1,
    "repository_advisory_url": SECRET_INPUT,
    "type": "unreviewed",
    "cve_id": SECRET_INPUT,
}


@pytest.mark.unit
class TestIgnoredFields:
    @pytest.mark.parametrize("name", ALL_FIXTURES)
    def test_ignored_fields_never_influence_the_extraction(self, name: str) -> None:
        body = _fixture(name)
        baseline = extract(parse_advisory(body))
        mutated = copy.deepcopy(body)
        mutated.update(IGNORED_TOP_LEVEL)
        for version in ("cvss_v3", "cvss_v4"):
            mutated["cvss_severities"][version]["score"] = SECRET_INPUT
        for cwe in mutated["cwes"]:
            cwe["name"] = SECRET_INPUT
        for vulnerability in mutated["vulnerabilities"]:
            vulnerability["vulnerable_functions"] = SECRET_INPUT
            vulnerability["first_patched_version"] = {"identifier": SECRET_INPUT}
            vulnerability["package"]["purl"] = SECRET_INPUT

        extraction = extract(parse_advisory(mutated))

        assert extraction == baseline
        assert extraction.payload.model_fields_set == (
            baseline.payload.model_fields_set
        )
        assert SECRET_INPUT not in extraction.payload.model_dump_json()
        assert SECRET_INPUT not in repr(extraction)

    @pytest.mark.parametrize("name", ALL_FIXTURES)
    def test_ignored_fields_may_be_absent(self, name: str) -> None:
        body = _fixture(name)
        stripped = {k: v for k, v in body.items() if k not in IGNORED_TOP_LEVEL}

        assert extract(parse_advisory(stripped)) == extract(parse_advisory(body))

    @pytest.mark.parametrize("name", ALL_FIXTURES)
    def test_live_credits_never_reach_the_extraction(self, name: str) -> None:
        body = _fixture(name)
        assert CREDIT_LOGIN in str(body["credits"])

        extraction = extract(parse_advisory(body))

        assert CREDIT_LOGIN not in extraction.payload.model_dump_json()
        candidates = [extraction.source_reference, *extraction.upstream_references]
        assert all(CREDIT_LOGIN not in str(c.url) for c in candidates)
        assert CREDIT_LOGIN not in repr(extraction)

    def test_legacy_cvss_is_not_a_candidate(self) -> None:
        payload = _extract(cvss={"vector_string": V31, "score": 9.8}).payload

        assert "cvss_assessments" not in payload.model_fields_set

    def test_nvd_published_at_is_not_the_published_date(self) -> None:
        payload = _extract(nvd_published_at="2024-06-19T15:04:41Z").payload

        assert "published_date" not in payload.model_fields_set


# ---------------------------------------------------------------------------
# External String Admissibility and payload bounds
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAdmissibility:
    """U+0000 and over-length values pass `parse_advisory()` and are rejected
    by the payload validation in `extract()` (an advisory-level failure,
    before any write)."""

    @pytest.mark.parametrize(
        "fields",
        [
            {"summary": "Fictional\x00 summary"},
            {"summary": "\x00"},
            {"description": "Fictional description\x00"},
            {"ghsa_id": f"{GHSA_ID}\x00"},
            {"html_url": f"\x00{HTML_URL}"},
            {"source_code_location": f"{REPO}\x00", "vulnerabilities": [{}]},
            {"vulnerabilities": [_vulnerability(name="example\x00")]},
            {"vulnerabilities": [_vulnerability(ecosystem="conda\x00")]},
            {"vulnerabilities": [_vulnerability(ecosystem="pip\x00")]},
            {"vulnerabilities": [_vulnerability(version_range="< 2.0\x00")]},
            {"vulnerabilities": [_vulnerability(version_range=">= \x001, < 2")]},
            {"vulnerabilities": [_vulnerability(version_range="= 1.\x00")]},
        ],
        ids=[
            "summary",
            "summary_only_nul",
            "description",
            "ghsa_id",
            "html_url",
            "source_code_location",
            "package_name",
            "unmapped_ecosystem",
            "near_mapped_ecosystem",
            "upper_bound",
            "lower_bound",
            "exact_bound",
        ],
    )
    def test_u0000_rejects_the_advisory(self, fields: dict[str, Any]) -> None:
        advisory = parse_advisory(_advisory(**fields))

        with pytest.raises(ValidationError) as raised:
            extract(advisory)

        assert "\x00" not in str(raised.value)

    def test_u0000_in_a_cwe_is_skipped(self) -> None:
        extraction = _extract(cwes=_cwes("CWE-79\x00", "CWE-20"))

        assert extraction.payload.cwe_classifications == [
            CWEEntry(cwe_id="CWE-20", source="GitHub")
        ]
        assert extraction.skipped_cwes == 1

    def test_u0000_in_a_vector_is_passed_to_upsert_cve(self) -> None:
        payload = _extract(
            cvss_severities={
                "cvss_v3": {"vector_string": V31 + "\x00"},
                "cvss_v4": {"vector_string": V40},
            }
        ).payload

        assert payload.cvss_assessments == [
            _candidate(V31 + "\x00"),
            _candidate(V40),
        ]

    def test_u0000_in_a_reference_is_passed_to_reference_service(self) -> None:
        extraction = _extract(references=[f"{URL_1}\x00"])

        assert extraction.upstream_references == [
            AutomaticReferenceInput(url=f"{URL_1}\x00")
        ]

    @pytest.mark.parametrize(
        ("fields", "value"),
        [
            ({"ghsa_id": "G" * 100}, "G" * 100),
            ({"html_url": "https://e.invalid/" + "a" * 2030}, None),
            ({"source_code_location": "https://e.invalid/" + "a" * 2030}, None),
            ({"package_name": "n" * 2048}, None),
            ({"ecosystem": "E" * 50}, None),
        ],
        ids=[
            "ghsa_id",
            "html_url",
            "source_code_location",
            "package_name",
            "unmapped_ecosystem",
        ],
    )
    def test_value_of_exactly_the_maximum_is_admissible(
        self, fields: dict[str, Any], value: str | None
    ) -> None:
        extraction = _extract(**_bounded_fields(fields))

        payload = extraction.payload
        (identifier,) = payload.external_identifiers or []
        (entry,) = _entries(extraction)
        if "ghsa_id" in fields:
            assert identifier.identifier == value
        if "html_url" in fields:
            assert len(fields["html_url"]) == 2048
            assert identifier.url == fields["html_url"]
            assert extraction.source_reference.url == fields["html_url"]
        if "source_code_location" in fields:
            assert len(fields["source_code_location"]) == 2048
            assert entry.repo == fields["source_code_location"]
        if "package_name" in fields:
            assert entry.package_name == fields["package_name"]
            assert entry.product == fields["package_name"]
        if "ecosystem" in fields:
            assert entry.ecosystem == fields["ecosystem"]

    @pytest.mark.parametrize(
        "fields",
        [
            {"ghsa_id": "G" * 101},
            {"html_url": "https://e.invalid/" + "a" * 2031},
            {"source_code_location": "https://e.invalid/" + "a" * 2031},
            {"package_name": "n" * 2049},
            {"ecosystem": "E" * 51},
        ],
        ids=[
            "ghsa_id",
            "html_url",
            "source_code_location",
            "package_name",
            "unmapped_ecosystem",
        ],
    )
    def test_over_long_value_rejects_the_advisory(self, fields: dict[str, Any]) -> None:
        advisory = parse_advisory(_advisory(**_bounded_fields(fields)))

        with pytest.raises(ValidationError):
            extract(advisory)

    def test_unbounded_version_and_product_are_admissible(self) -> None:
        bound = "1." + "0" * 5000
        (entry,) = _entries(
            _extract(vulnerabilities=[_vulnerability(version_range=f">= {bound}")])
        )

        assert entry.version == bound

    def test_payload_validation_error_never_renders_the_input(self) -> None:
        advisory = parse_advisory(
            _advisory(summary=f"{SECRET_INPUT}\x00", ghsa_id=SECRET_INPUT * 10)
        )

        with pytest.raises(ValidationError) as raised:
            extract(advisory)

        assert SECRET_INPUT not in str(raised.value)
        assert SECRET_INPUT not in repr(raised.value)


def _bounded_fields(fields: dict[str, Any]) -> dict[str, Any]:
    """Advisory fields for one bound check: package-level values go into a
    single vulnerability entry; every advisory carries one entry."""
    advisory = {k: v for k, v in fields.items() if k in GhsaAdvisory.model_fields}
    name = fields.get("package_name", "example-package")
    ecosystem = fields.get("ecosystem", "npm")
    advisory["vulnerabilities"] = [_vulnerability(name, ecosystem)]
    return advisory


# ---------------------------------------------------------------------------
# Live fixtures
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestLiveFixtures:
    @pytest.mark.parametrize("name", ALL_FIXTURES)
    def test_every_fixture_extracts_per_the_field_mapping(self, name: str) -> None:
        body = _fixture(name)

        extraction = extract(parse_advisory(body))

        payload = extraction.payload
        assert isinstance(payload, CVEIngestPayload)
        assert payload.title == body["summary"]
        assert payload.description == body["description"]
        assert payload.published_date == _iso(body["published_at"])
        assert payload.modified_date == _iso(body["updated_at"])
        entries = _entries(extraction)
        assert len(entries) == len(body["vulnerabilities"])
        assert [(e.product, e.package_name, e.ecosystem, e.repo) for e in entries] == [
            (
                v["package"]["name"],
                v["package"]["name"],
                ECOSYSTEMS[v["package"]["ecosystem"]],
                body["source_code_location"] or None,
            )
            for v in body["vulnerabilities"]
        ]
        assert [
            _bounds_of(parse_version_range(v["vulnerable_version_range"]))
            for v in body["vulnerabilities"]
        ] == _bounds(entries)
        assert payload.resolved_packages == list(
            dict.fromkeys(v["package"]["name"] for v in body["vulnerabilities"])
        )
        assert extraction.unrecognized_ranges == 0
        assert extraction.skipped_cwes == 0

    def test_erlang_is_hex(self) -> None:
        entries = _entries(
            extract(parse_advisory(load_advisory_fixture("advisory_erlang")))
        )

        assert [(e.package_name, e.ecosystem) for e in entries] == [("ash", "Hex")]
        assert _bounds(entries) == [("3.0.0", "3.29.3", False)]

    def test_empty_source_location_gives_no_repo(self) -> None:
        body = load_advisory_fixture("advisory_empty_source_location")
        assert body["source_code_location"] == ""

        entries = _entries(extract(parse_advisory(body)))

        assert entries
        assert all(e.repo is None for e in entries)

    def test_gt_range_keeps_the_lower_bound_with_an_exclusive_end(self) -> None:
        entries = _entries(
            extract(parse_advisory(load_advisory_fixture("advisory_gt_range")))
        )

        assert _bounds(entries) == [
            ("3.0.0", "3.90.0", False),
            ("4.0.0-canary.0", "4.0.0-canary.34", False),
        ]

    def test_inclusive_exact_and_repeated_package_ranges(self) -> None:
        extraction = extract(
            parse_advisory(load_advisory_fixture("advisory_v3_v4_non_base_ranges"))
        )

        entries = _entries(extraction)

        assert [
            (e.package_name, *b) for e, b in zip(entries, _bounds(entries), strict=True)
        ] == [
            ("org.bouncycastle:bcprov-jdk14", "1.59", "1.80.1", True),
            ("org.bouncycastle:bcprov-jdk18on", "1.59", "1.80.1", True),
            ("org.bouncycastle:bcprov-jdk18on", "1.81.0", "1.81.0", True),
            ("org.bouncycastle:bcprov-jdk18on", "1.82", "1.83", True),
            ("org.bouncycastle:bcprov-jdk15on", None, "1.7.0", True),
        ]
        assert {e.ecosystem for e in entries} == {"Maven"}
        assert extraction.payload.resolved_packages == [
            "org.bouncycastle:bcprov-jdk14",
            "org.bouncycastle:bcprov-jdk18on",
            "org.bouncycastle:bcprov-jdk15on",
        ]

    def test_multi_ecosystem_advisory(self) -> None:
        extraction = extract(
            parse_advisory(load_advisory_fixture("advisory_multi_ecosystem"))
        )

        entries = _entries(extraction)

        assert [
            (e.ecosystem, *b) for e, b in zip(entries, _bounds(entries), strict=True)
        ] == [
            ("npm", None, "0.39.1", False),
            ("npm", "0.40.0-preview.2", "0.40.0-preview.2", True),
            ("GitHub Actions", None, "0.1.22", False),
        ]
        assert extraction.payload.resolved_packages == [
            "@google/gemini-cli",
            "google-github-actions/run-gemini-cli",
        ]

    def test_single_query_advisory_keeps_the_opaque_beta_bound(self) -> None:
        entries = _entries(extract(parse_advisory(_single_reviewed())))

        assert ("2.0-beta9", "2.3.1", False) in _bounds(entries)
        assert {e.repo for e in entries} == {"https://github.com/apache/logging-log4j2"}
