"""Unit tests for the Linux Kernel CNA record mapping
(backend/app/services/tickets/kernel_cve_record.py).

Contract under test: docs/features/tickets/cve-sync-kernel.md (Algorithm
steps 1 path pattern, 2b-2d and 2f-2g; Rejection Handling state derivation;
CVE JSON Field Mapping: fields to extract, presence rules, explicitly ignored
fields, CVE-ID handling and cross-validation, CVSS deduplication,
`provider_name = "Linux"`, the `cna` scope, External String Admissibility),
the parser delegation of docs/features/platform/cve-record-parser.md (Caller
Pattern; What Remains Source-Specific), and the candidate order of
docs/features/platform/cve-fetcher-infrastructure.md (Automatic Reference
Caller Contract). `SyncKernelCves` owns the delta, the ingestion, and the
per-item failure outcome; those parts are tested with the fetcher.

Records are the sanitized live fixtures of `tests/support/kernel.py` or
minimal fictional objects. No database, Git, or log is involved.
"""

from __future__ import annotations

import copy
import json
from typing import Any, Final

import pytest
from pydantic import ValidationError

from app.core.enums import CveState, ReferenceType
from app.services import cve_record_parser
from app.services.cve_ingest import (
    AffectedVersionEntry,
    AffectedVersionOperation,
    AffectedVersionScopeOperation,
    CVEIngestPayload,
    CVSSAssessmentEntry,
)
from app.services.reference_service import AutomaticReferenceInput
from app.services.tickets.kernel_cve_record import (
    PROVIDER_NAME,
    RECORD_PATH_PATTERN,
    RESOLVED_PACKAGE,
    SOURCE_CONTAINER,
    SOURCE_REFERENCE_TITLE,
    KernelRecord,
    KernelRecordDecodeError,
    KernelRecordError,
    KernelRecordPathError,
    KernelRecordStateError,
    map_record,
)
from tests.support.kernel import (
    ALL_RECORDS,
    load_raw_record,
    load_record,
    record_path,
)
from tests.support.module_imports import APP_ROOT, forbidden_imports, imported_modules

pytestmark = pytest.mark.unit

CVE_ID: Final = "CVE-2026-0001"
PUBLISHED_PATH: Final = f"cve/published/2026/{CVE_ID}.json"
REJECTED_PATH: Final = f"cve/rejected/2026/{CVE_ID}.json"
VULNS_TREE: Final = "https://git.kernel.org/pub/scm/linux/security/vulns.git/tree"
V31: Final = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
V31_NON_BASE: Final = "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N/E:U/RL:O/RC:C"
V31_NON_BASE_REDUCED: Final = "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N"
V40: Final = "CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
V40_NON_BASE: Final = (
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:L/VI:N/VA:N/SC:L/SI:N/SA:N/RE:M/U:Clear"
)
V40_NON_BASE_REDUCED: Final = (
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:L/VI:N/VA:N/SC:L/SI:N/SA:N"
)
URL_1: Final = (
    "https://git.kernel.org/stable/c/0000000000000000000000000000000000000001"
)
URL_2: Final = "https://advisory.example.invalid/upstream/2"
NUL: Final = "\x00"

_KERNEL_FIELDS: Final = frozenset(
    {
        "cve_state",
        "title",
        "description",
        "cvss_assessments",
        "affected_version_operations",
        "resolved_packages",
    }
)
"""Every payload field the kernel mapping may set (§ CVE JSON Field Mapping;
dates are never set)."""


def _affected_element(**overrides: Any) -> dict[str, Any]:
    element: dict[str, Any] = {
        "product": "Linux",
        "vendor": "Linux",
        "defaultStatus": "unaffected",
        "repo": "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git",
        "programFiles": ["fs/example/file.c"],
        "versions": [
            {
                "version": "6.18.1",
                "lessThan": "6.18.5",
                "status": "affected",
                "versionType": "semver",
            },
            {
                "version": "6.19",
                "lessThanOrEqual": "6.19.*",
                "status": "unaffected",
                "versionType": "semver",
            },
        ],
    }
    element.update(overrides)
    return element


def _record(**cna: Any) -> dict[str, Any]:
    """A minimal fictional published 5.1.1 record; `cna` replaces members."""
    container: dict[str, Any] = {
        "providerMetadata": {"orgId": "f4215fc3-5b6b-47ff-a258-f7189bd81038"},
        "descriptions": [{"lang": "en", "value": "Fictional description."}],
        "affected": [_affected_element()],
        "references": [{"url": URL_1}],
        "title": "example: fictional title",
    }
    container.update(cna)
    return {
        "containers": {"cna": container},
        "cveMetadata": {
            "assignerOrgId": "f4215fc3-5b6b-47ff-a258-f7189bd81038",
            "cveId": CVE_ID,
            "state": "PUBLISHED",
        },
        "dataType": "CVE_RECORD",
        "dataVersion": "5.1.1",
    }


def _without(record: dict[str, Any], key: str) -> dict[str, Any]:
    del record["containers"]["cna"][key]
    return record


def _map(record: object, path: str = PUBLISHED_PATH) -> KernelRecord:
    return map_record(path, json.dumps(record).encode())


def _payload(record: object, path: str = PUBLISHED_PATH) -> CVEIngestPayload:
    return _map(record, path).payload


def _cna_entries(payload: CVEIngestPayload) -> list[AffectedVersionEntry]:
    operations = payload.affected_version_operations or []
    assert len(operations) == 1
    assert operations[0].source_container == SOURCE_CONTAINER
    assert operations[0].operation is AffectedVersionOperation.REPLACE
    return list(operations[0].entries or [])


# ---------------------------------------------------------------------------
# Path
# ---------------------------------------------------------------------------


class TestPath:
    @pytest.mark.parametrize(
        ("path", "state", "year"),
        [
            ("cve/published/2026/CVE-2026-0001.json", "published", "2026"),
            ("cve/rejected/2019/CVE-2019-25161.json", "rejected", "2019"),
            ("cve/published/2024/CVE-2024-123456.json", "published", "2024"),
        ],
    )
    def test_record_path_is_accepted(self, path: str, state: str, year: str) -> None:
        cve_id = path.rsplit("/", 1)[1].removesuffix(".json")
        record = _record()
        record["cveMetadata"]["cveId"] = cve_id

        result = _map(record, path)

        assert result.cve_id == cve_id
        assert result.source_reference.url == (
            f"{VULNS_TREE}/cve/{state}/{year}/{cve_id}.json"
        )

    @pytest.mark.parametrize(
        "path",
        [
            "cve/testing/published/2021/CVE-2021-47181.json",
            "cve/reserved/2026/CVE-2026-0001.json",
            "cve/returned/2026/CVE-2026-0001.json",
            "cve/published/2026/CVE-2026-0001",
            "cve/published/2026/CVE-2026-0001.sha1",
            "cve/published/2026/CVE-2026-0001.json.orig",
            "cve/published/2026/CVE-2026-0001.JSON",
            "cve/Published/2026/CVE-2026-0001.json",
            "cve/published/2025/CVE-2026-0001.json",
            "cve/published/2026/CVE-2026-001.json",
            "cve/published/2026/cve-2026-0001.json",
            "cve/published/2026/CVE-2026-0000000000001.json",
            "cve/published/\uff12\uff10\uff12\uff16/CVE-\uff12\uff10\uff12\uff16-0001.json",
            "cve/published/2026/CVE-2026-0001.json\n",
            "/cve/published/2026/CVE-2026-0001.json",
            "./cve/published/2026/CVE-2026-0001.json",
            "cve/published/2026/x/CVE-2026-0001.json",
            "cve/CVE_JSON_5.1.1_schema.json",
            "cve/published/2026/CVE-2026-\udcff.json",
            "",
        ],
    )
    def test_path_outside_the_record_pattern_fails(self, path: str) -> None:
        with pytest.raises(KernelRecordPathError):
            _map(_record(), path)

    def test_path_is_checked_before_the_content(self) -> None:
        with pytest.raises(KernelRecordPathError):
            map_record("cve/published/2026/CVE-2026-0001.sha1", b"\xff")

    def test_pattern_captures_the_directory_year_and_cve_id(self) -> None:
        match = RECORD_PATH_PATTERN.fullmatch(PUBLISHED_PATH)

        assert match is not None
        assert (match["state"], match["year"], match["cve_id"]) == (
            "published",
            "2026",
            CVE_ID,
        )


# ---------------------------------------------------------------------------
# Content decoding
# ---------------------------------------------------------------------------


class TestDecode:
    @pytest.mark.parametrize(
        "content",
        [
            b"",
            b"\xff\xfe{}",
            b'{"title": "\xe9"}',
            b"\xef\xbb\xbf{}",
            "{}".encode("utf-16"),
            b"{",
            b'{"a": 1,}',
            b"[]",
            b'"CVE-2026-0001"',
            b"null",
            b"42",
            b"[" * 100_000 + b"]" * 100_000,
            b'{"n": ' + b"9" * 5000 + b"}",
        ],
        ids=[
            "empty",
            "non-utf-8",
            "latin-1-byte",
            "utf-8-bom",
            "utf-16",
            "truncated",
            "trailing-comma",
            "array-root",
            "string-root",
            "null-root",
            "number-root",
            "deep-nesting",
            "oversized-integer",
        ],
    )
    def test_undecodable_content_fails(self, content: bytes) -> None:
        with pytest.raises(KernelRecordDecodeError):
            map_record(PUBLISHED_PATH, content)

    def test_error_message_and_cause_carry_no_content(self) -> None:
        secret = b'{"title": "Example-Secret-Input-Value"'

        with pytest.raises(KernelRecordDecodeError) as caught:
            map_record(PUBLISHED_PATH, secret)

        assert "Example-Secret" not in str(caught.value)
        assert caught.value.__cause__ is None
        assert caught.value.__suppress_context__

    def test_errors_are_value_errors_with_fixed_messages(self) -> None:
        errors = [
            KernelRecordPathError(),
            KernelRecordDecodeError(),
            KernelRecordStateError(),
        ]

        assert all(isinstance(e, KernelRecordError) for e in errors)
        assert all(isinstance(e, ValueError) for e in errors)
        assert len({str(e) for e in errors}) == 3


# ---------------------------------------------------------------------------
# State (Rejection Handling)
# ---------------------------------------------------------------------------


class TestState:
    def test_published_path_uses_the_json_state(self) -> None:
        assert _payload(_record()).cve_state is CveState.PUBLISHED

    def test_published_path_with_json_rejected_state_is_rejected(self) -> None:
        record = _record()
        record["cveMetadata"]["state"] = "REJECTED"

        assert _payload(record).cve_state is CveState.REJECTED

    @pytest.mark.parametrize(
        "state",
        ["RESERVED", "published", "", " PUBLISHED", None, 1, ["PUBLISHED"]],
    )
    def test_published_path_with_unrecognized_state_fails(self, state: Any) -> None:
        record = _record()
        record["cveMetadata"]["state"] = state

        with pytest.raises(KernelRecordStateError):
            _map(record)

    def test_published_path_without_state_fails(self) -> None:
        record = _record()
        del record["cveMetadata"]["state"]

        with pytest.raises(KernelRecordStateError):
            _map(record)

    @pytest.mark.parametrize("metadata", [None, "PUBLISHED", [], {}])
    def test_published_path_with_unusable_metadata_fails(self, metadata: Any) -> None:
        record = _record()
        record["cveMetadata"] = metadata

        with pytest.raises(KernelRecordStateError):
            _map(record)

    @pytest.mark.parametrize("state", ["PUBLISHED", "REJECTED", "RESERVED", None])
    def test_rejected_path_is_rejected_regardless_of_the_json(self, state: Any) -> None:
        record = _record()
        record["cveMetadata"]["state"] = state

        assert _payload(record, REJECTED_PATH).cve_state is CveState.REJECTED

    @pytest.mark.parametrize("metadata", [None, "x", {}])
    def test_rejected_path_without_usable_metadata_is_rejected(
        self, metadata: Any
    ) -> None:
        record = _record()
        record["cveMetadata"] = metadata

        assert _payload(record, REJECTED_PATH).cve_state is CveState.REJECTED

    @pytest.mark.parametrize("name", ALL_RECORDS)
    def test_live_record_state_follows_its_directory(self, name: str) -> None:
        path = record_path(name)
        expected = (
            CveState.REJECTED
            if path.startswith("cve/rejected/")
            else CveState.PUBLISHED
        )

        assert map_record(path, load_raw_record(name)).payload.cve_state is expected


# ---------------------------------------------------------------------------
# CVE-ID
# ---------------------------------------------------------------------------


class TestCveId:
    @pytest.mark.parametrize(
        "metadata",
        [
            {"cveId": CVE_ID, "state": "PUBLISHED"},
            {"cveID": CVE_ID, "state": "PUBLISHED"},
            {"state": "PUBLISHED"},
            {"cveId": "CVE-2026-9999", "state": "PUBLISHED"},
            {"cveID": "cve-2026-0001", "state": "PUBLISHED"},
            {"cveId": 2026, "state": "PUBLISHED"},
        ],
        ids=["cveId", "legacy-cveID", "absent", "mismatch", "case", "non-string"],
    )
    def test_file_name_id_is_authoritative(self, metadata: dict[str, Any]) -> None:
        record = _record()
        record["cveMetadata"] = metadata

        result = _map(record)

        assert result.cve_id == CVE_ID
        assert result.source_reference.url == f"{VULNS_TREE}/{PUBLISHED_PATH}"

    def test_mismatch_never_reaches_the_payload_or_references(self) -> None:
        record = _record()
        record["cveMetadata"]["cveId"] = "CVE-2026-9999"

        result = _map(record)

        assert "CVE-2026-9999" not in repr(result)

    @pytest.mark.parametrize("name", ALL_RECORDS)
    def test_live_record_id_is_its_file_name(self, name: str) -> None:
        path = record_path(name)

        result = map_record(path, load_raw_record(name))

        assert result.cve_id == path.rsplit("/", 1)[1].removesuffix(".json")


# ---------------------------------------------------------------------------
# Global fields
# ---------------------------------------------------------------------------


class TestGlobalFields:
    def test_title_and_description_are_mapped(self) -> None:
        payload = _payload(_record())

        assert payload.title == "example: fictional title"
        assert payload.description == "Fictional description."

    def test_title_is_truncated_to_256_characters(self) -> None:
        payload = _payload(_record(title="t" * 300))

        assert payload.title == "t" * 256

    def test_absent_title_and_descriptions_are_omitted(self) -> None:
        record = _without(_without(_record(), "title"), "descriptions")

        payload = _payload(record)

        assert {"title", "description"}.isdisjoint(payload.model_fields_set)

    def test_null_title_and_descriptions_are_explicit_clears(self) -> None:
        payload = _payload(_record(title=None, descriptions=None))

        assert {"title", "description"} <= payload.model_fields_set
        assert payload.title is None
        assert payload.description is None

    @pytest.mark.parametrize("title", [1, True, ["t"], {"t": "t"}])
    def test_non_string_title_is_omitted(self, title: Any) -> None:
        assert "title" not in _payload(_record(title=title)).model_fields_set

    @pytest.mark.parametrize(
        "descriptions",
        [
            [],
            [{"lang": "en"}],
            [{"lang": "en", "value": None}],
            [{"lang": "en", "value": 1}],
            ["Fictional description."],
            {"lang": "en", "value": "Fictional description."},
            "Fictional description.",
        ],
    )
    def test_descriptions_without_a_string_value_are_omitted(
        self, descriptions: Any
    ) -> None:
        payload = _payload(_record(descriptions=descriptions))

        assert "description" not in payload.model_fields_set

    def test_english_description_is_selected(self) -> None:
        descriptions = [
            {"lang": "de", "value": "Fiktive Beschreibung."},
            {"lang": "en-US", "value": "Fictional description."},
        ]

        assert _payload(_record(descriptions=descriptions)).description == (
            "Fictional description."
        )

    def test_dates_are_never_read(self) -> None:
        record = _record()
        record["cveMetadata"].update(
            {
                "datePublished": "2026-01-01T00:00:00.000Z",
                "dateUpdated": "2026-01-02T00:00:00.000Z",
                "dateRejected": "2026-01-03T00:00:00.000Z",
            }
        )

        for path in (PUBLISHED_PATH, REJECTED_PATH):
            fields = _payload(record, path).model_fields_set
            assert {"published_date", "modified_date", "date_rejected"}.isdisjoint(
                fields
            )

    @pytest.mark.parametrize(
        "containers", [None, [], "cna", {}, {"cna": None}, {"cna": []}, {"cna": "x"}]
    )
    def test_unusable_cna_is_an_empty_container(self, containers: Any) -> None:
        record = _record()
        record["containers"] = containers

        result = _map(record)

        assert result.payload.model_fields_set == {"cve_state", "resolved_packages"}
        assert result.upstream_references == ()

    def test_absent_containers_is_an_empty_container(self) -> None:
        record = _record()
        del record["containers"]

        payload = _payload(record)

        assert payload.model_fields_set == {"cve_state", "resolved_packages"}

    @pytest.mark.parametrize("path", [PUBLISHED_PATH, REJECTED_PATH])
    def test_resolved_packages_is_kernel_source(self, path: str) -> None:
        assert _payload(_record(), path).resolved_packages == [RESOLVED_PACKAGE]
        assert RESOLVED_PACKAGE == "kernel-source"


# ---------------------------------------------------------------------------
# CVSS
# ---------------------------------------------------------------------------


class TestCvss:
    def test_provider_is_linux(self) -> None:
        assert PROVIDER_NAME == "Linux"

    @pytest.mark.parametrize(
        ("metrics", "expected"),
        [
            ([{"cvssV3_1": {"vectorString": V31}}], [V31]),
            ([{"cvssV4_0": {"vectorString": V40}}], [V40]),
            (
                [
                    {"cvssV3_1": {"vectorString": V31}},
                    {"cvssV4_0": {"vectorString": V40}},
                ],
                [V40, V31],
            ),
            ([{"cvssV3_1": {"vectorString": V31_NON_BASE}}], [V31_NON_BASE_REDUCED]),
            ([{"cvssV4_0": {"vectorString": V40_NON_BASE}}], [V40_NON_BASE_REDUCED]),
        ],
        ids=["v3.1", "v4.0", "v3.1-and-v4.0", "v3.1-non-base", "v4.0-non-base"],
    )
    def test_vectors_are_linux_candidates_reduced_to_base(
        self, metrics: list[dict[str, Any]], expected: list[str]
    ) -> None:
        cvss = _payload(_record(metrics=metrics)).cvss_assessments

        assert cvss is not None
        assert {c.vector_string for c in cvss} == set(expected)
        assert len(cvss) == len(expected)
        assert {c.provider_name for c in cvss} == {"Linux"}

    def test_mapping_delegates_to_the_parser(self) -> None:
        metrics = [
            {"cvssV3_1": {"vectorString": V31}},
            {"cvssV3_1": {"vectorString": V31_NON_BASE}},
            {"cvssV4_0": {"vectorString": "CVSS:4.0/AV:X"}},
        ]

        assert _payload(_record(metrics=metrics)).cvss_assessments == (
            cve_record_parser.parse_cvss_assessments(metrics, "Linux")
        )

    @pytest.mark.parametrize(
        "metrics",
        [None, [], "x", [{"cvssV3_1": {"vectorString": "CVSS:3.1/AV:X"}}]],
        ids=["null", "empty", "non-array", "invalid-vector"],
    )
    def test_no_valid_vector_sets_no_cvss_field(self, metrics: Any) -> None:
        payload = _payload(_record(metrics=metrics))

        assert "cvss_assessments" not in payload.model_fields_set

    def test_absent_metrics_sets_no_cvss_field(self) -> None:
        assert "cvss_assessments" not in _payload(_record()).model_fields_set

    @pytest.mark.parametrize("name", ["published_cvss_v3_1", "rejected_cvss_v3_1"])
    def test_live_cvss_v3_1_is_a_linux_candidate(self, name: str) -> None:
        record = load_record(name)
        vector = record["containers"]["cna"]["metrics"][0]["cvssV3_1"]["vectorString"]

        payload = map_record(record_path(name), load_raw_record(name)).payload

        assert payload.cvss_assessments == [
            CVSSAssessmentEntry(provider_name="Linux", vector_string=vector)
        ]


# ---------------------------------------------------------------------------
# Affected versions (`cna` scope)
# ---------------------------------------------------------------------------


class TestAffected:
    def test_non_empty_affected_replaces_the_cna_scope(self) -> None:
        affected = [_affected_element()]

        entries = _cna_entries(_payload(_record(affected=affected)))

        assert entries == cve_record_parser.parse_affected_versions(affected)
        assert [e.version for e in entries] == ["6.18.1", "6.19"]
        assert {tuple(e.program_files or ()) for e in entries} == {
            ("fs/example/file.c",)
        }

    def test_empty_affected_replaces_the_cna_scope_with_nothing(self) -> None:
        assert _cna_entries(_payload(_record(affected=[]))) == []

    @pytest.mark.parametrize("affected", [None, {}, "Linux", 1])
    def test_null_or_non_array_affected_emits_no_operation(self, affected: Any) -> None:
        payload = _payload(_record(affected=affected))

        assert "affected_version_operations" not in payload.model_fields_set

    def test_absent_affected_emits_no_operation(self) -> None:
        payload = _payload(_without(_record(), "affected"))

        assert "affected_version_operations" not in payload.model_fields_set

    def test_unparseable_element_leaves_a_reduced_replace(self) -> None:
        affected = [_affected_element(), _affected_element(vendor=1)]

        entries = _cna_entries(_payload(_record(affected=affected)))

        assert len(entries) == 2

    def test_live_duplicate_elements_without_versions_collapse(self) -> None:
        name = "rejected_without_references"

        payload = map_record(record_path(name), load_raw_record(name)).payload

        assert len(_cna_entries(payload)) == 1

    @pytest.mark.parametrize("name", ALL_RECORDS)
    def test_live_affected_is_the_parsed_cna_snapshot(self, name: str) -> None:
        affected = load_record(name)["containers"]["cna"]["affected"]

        payload = map_record(record_path(name), load_raw_record(name)).payload

        assert payload.affected_version_operations == [
            AffectedVersionScopeOperation(
                source_container="cna",
                operation=AffectedVersionOperation.REPLACE,
                entries=cve_record_parser.parse_affected_versions(affected),
            )
        ]


# ---------------------------------------------------------------------------
# Ignored fields
# ---------------------------------------------------------------------------


class TestIgnoredFields:
    def test_ignored_fields_never_reach_the_payload(self) -> None:
        record = _record(
            cpeApplicability=[
                {
                    "nodes": [
                        {
                            "operator": "OR",
                            "negate": False,
                            "cpeMatch": [
                                {
                                    "vulnerable": True,
                                    "criteria": (
                                        "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*"
                                    ),
                                }
                            ],
                        }
                    ]
                }
            ],
            x_generator={"engine": "bippy-1.2.0"},
            problemTypes=[
                {"descriptions": [{"type": "CWE", "cweId": "CWE-416", "lang": "en"}]}
            ],
        )
        record["containers"]["adp"] = [
            {
                "providerMetadata": {"orgId": "x", "shortName": "CISA-ADP"},
                "metrics": [{"cvssV3_1": {"vectorString": V31}}],
            }
        ]

        payload = _payload(record)

        assert payload.model_fields_set <= _KERNEL_FIELDS
        assert payload.cvss_assessments is None
        assert payload.cwe_classifications is None
        assert payload.cpe_matches is None

    def test_problem_types_record_maps_normally(self) -> None:
        name = "vulns_rejected_5_1_problem_types"

        payload = map_record(record_path(name), load_raw_record(name)).payload

        assert payload.cve_state is CveState.REJECTED
        assert "cwe_classifications" not in payload.model_fields_set

    @pytest.mark.parametrize("name", ALL_RECORDS)
    def test_live_payload_sets_only_kernel_fields(self, name: str) -> None:
        payload = map_record(record_path(name), load_raw_record(name)).payload

        assert {"cve_state", "resolved_packages", "affected_version_operations"} <= (
            payload.model_fields_set
        )
        assert payload.model_fields_set <= _KERNEL_FIELDS


# ---------------------------------------------------------------------------
# References
# ---------------------------------------------------------------------------


class TestReferences:
    @pytest.mark.parametrize(
        ("path", "state"), [(PUBLISHED_PATH, "published"), (REJECTED_PATH, "rejected")]
    )
    def test_source_candidate_is_the_vulns_tree_advisory(
        self, path: str, state: str
    ) -> None:
        source = _map(_record(), path).source_reference

        assert source == AutomaticReferenceInput(
            url=f"{VULNS_TREE}/cve/{state}/2026/{CVE_ID}.json",
            title="Linux Kernel CNA",
            explicit_type=ReferenceType.ADVISORY,
        )
        assert SOURCE_REFERENCE_TITLE == "Linux Kernel CNA"

    def test_upstream_candidates_are_url_only_in_array_order(self) -> None:
        references = [
            {"url": URL_2, "name": "Fictional reference", "tags": ["patch"]},
            {"url": URL_1},
        ]

        upstream = _map(_record(references=references)).upstream_references

        assert upstream == (
            AutomaticReferenceInput(url=URL_2),
            AutomaticReferenceInput(url=URL_1),
        )

    def test_duplicate_urls_are_passed_through(self) -> None:
        references = [{"url": URL_1}, {"url": URL_1}]

        upstream = _map(_record(references=references)).upstream_references

        assert upstream == (AutomaticReferenceInput(url=URL_1),) * 2

    @pytest.mark.parametrize(
        ("element", "url"),
        [
            ("https://advisory.example.invalid/upstream/3", None),
            (None, None),
            (["x"], None),
            ({}, None),
            ({"url": None}, None),
            ({"url": 1}, 1),
            ({"url": ""}, ""),
        ],
        ids=["string", "null", "array", "no-url", "null-url", "int-url", "empty-url"],
    )
    def test_each_element_is_one_candidate_validated_by_the_service(
        self, element: Any, url: object
    ) -> None:
        upstream = _map(
            _record(references=[element, {"url": URL_1}])
        ).upstream_references

        assert upstream == (
            AutomaticReferenceInput(url=url),
            AutomaticReferenceInput(url=URL_1),
        )

    @pytest.mark.parametrize("references", [None, {}, "x", []])
    def test_null_non_array_or_empty_references_yield_none(
        self, references: Any
    ) -> None:
        result = _map(_record(references=references))

        assert result.upstream_references == ()
        assert result.source_reference.url == f"{VULNS_TREE}/{PUBLISHED_PATH}"

    def test_absent_references_yield_only_the_source_candidate(self) -> None:
        result = _map(_without(_record(), "references"))

        assert result.upstream_references == ()

    def test_live_references_keep_their_order(self) -> None:
        name = "published_external_references"
        urls = [r["url"] for r in load_record(name)["containers"]["cna"]["references"]]

        result = map_record(record_path(name), load_raw_record(name))

        assert result.upstream_references == tuple(
            AutomaticReferenceInput(url=url) for url in urls
        )
        assert len(urls) == 9

    def test_live_record_without_references_has_only_the_source(self) -> None:
        name = "rejected_without_references"

        result = map_record(record_path(name), load_raw_record(name))

        assert result.upstream_references == ()
        assert result.source_reference.url == (
            f"{VULNS_TREE}/cve/rejected/2024/CVE-2024-26701.json"
        )


# ---------------------------------------------------------------------------
# External String Admissibility
# ---------------------------------------------------------------------------


class TestExternalStringAdmissibility:
    @pytest.mark.parametrize(
        "cna",
        [
            {"title": f"example{NUL}"},
            {"title": "t" * 300 + NUL},
            {"descriptions": [{"lang": "en", "value": f"Fictional{NUL}"}]},
        ],
        ids=["title", "title-after-bound", "description"],
    )
    def test_global_string_fails_payload_construction(
        self, cna: dict[str, Any]
    ) -> None:
        with pytest.raises(ValidationError) as caught:
            _map(_record(**cna))

        assert NUL not in str(caught.value)

    def test_unselected_description_is_not_consumed(self) -> None:
        descriptions = [
            {"lang": "en", "value": "Fictional description."},
            {"lang": "de", "value": f"Fiktiv{NUL}"},
        ]

        assert _payload(_record(descriptions=descriptions)).description == (
            "Fictional description."
        )

    @pytest.mark.parametrize(
        ("element_field", "version_field"),
        [
            ("vendor", None),
            ("product", None),
            ("repo", None),
            ("defaultStatus", None),
            ("programFiles", None),
            ("packageName", None),
            (None, "version"),
            (None, "versionType"),
            (None, "lessThan"),
            (None, "lessThanOrEqual"),
            (None, "status"),
        ],
    )
    def test_affected_value_skips_its_entry_and_keeps_siblings(
        self, element_field: str | None, version_field: str | None
    ) -> None:
        poisoned = _affected_element(product="Linux-poisoned")
        if element_field == "programFiles":
            poisoned["programFiles"] = ["fs/example/file.c", f"fs/{NUL}.c"]
        elif element_field is not None:
            poisoned[element_field] = f"x{NUL}"
        else:
            assert version_field is not None
            for version in poisoned["versions"]:
                if version_field == "lessThanOrEqual":
                    # `lessThan` wins over `lessThanOrEqual` when both exist.
                    version.pop("lessThan", None)
                version[version_field] = f"x{NUL}"
        affected = [_affected_element(), poisoned]

        entries = _cna_entries(_payload(_record(affected=affected)))

        assert {e.product for e in entries} == {"Linux"}
        assert len(entries) == 2

    def test_vector_skips_its_candidate(self) -> None:
        metrics = [
            {"cvssV4_0": {"vectorString": V40 + NUL}},
            {"cvssV3_1": {"vectorString": V31}},
        ]

        cvss = _payload(_record(metrics=metrics)).cvss_assessments

        assert cvss == [CVSSAssessmentEntry(provider_name="Linux", vector_string=V31)]

    def test_reference_url_is_left_to_the_reference_service(self) -> None:
        url = f"{URL_1}{NUL}"

        upstream = _map(_record(references=[{"url": url}])).upstream_references

        assert upstream == (AutomaticReferenceInput(url=url),)

    def test_published_state_is_unrecognized(self) -> None:
        record = _record()
        record["cveMetadata"]["state"] = f"PUBLISHED{NUL}"

        with pytest.raises(KernelRecordStateError):
            _map(record)

    @pytest.mark.parametrize(
        "mutate",
        [
            lambda r: r["cveMetadata"].update(cveId=f"{CVE_ID}{NUL}"),
            lambda r: r["cveMetadata"].update(assignerOrgId=NUL),
            lambda r: r["cveMetadata"].update(datePublished=NUL),
            lambda r: r["containers"]["cna"].update(x_generator={"engine": NUL}),
            lambda r: r["containers"]["cna"].update(cpeApplicability=[{"n": NUL}]),
            lambda r: r["containers"]["cna"].update(
                problemTypes=[{"descriptions": [{"description": NUL}]}]
            ),
            lambda r: r["containers"]["cna"]["providerMetadata"].update(orgId=NUL),
        ],
        ids=[
            "cve-id",
            "assigner-org-id",
            "date-published",
            "x-generator",
            "cpe-applicability",
            "problem-types",
            "provider-org-id",
        ],
    )
    def test_unconsumed_or_compared_only_value_has_no_effect(self, mutate: Any) -> None:
        record = _record()
        mutate(record)

        assert _map(record) == _map(_record())


# ---------------------------------------------------------------------------
# Live records, purity, and module boundary
# ---------------------------------------------------------------------------


class TestLiveRecords:
    def test_published_record_maps_completely(self) -> None:
        name = "published_cvss_v3_1"
        cna = load_record(name)["containers"]["cna"]

        result = map_record(record_path(name), load_raw_record(name))

        assert result.cve_id == "CVE-2026-43070"
        assert result.payload.cve_state is CveState.PUBLISHED
        assert result.payload.title == cna["title"]
        assert result.payload.description == cna["descriptions"][0]["value"]
        assert result.payload.resolved_packages == ["kernel-source"]
        assert len(_cna_entries(result.payload)) == 5
        assert [r.url for r in result.upstream_references] == [
            r["url"] for r in cna["references"]
        ]

    def test_record_without_title_omits_it(self) -> None:
        name = "vulns_rejected_5_1_problem_types"

        payload = map_record(record_path(name), load_raw_record(name)).payload

        assert "title" not in payload.model_fields_set
        assert payload.description is not None


class TestPurity:
    @pytest.mark.parametrize("name", ALL_RECORDS)
    def test_repeated_calls_yield_equal_results(self, name: str) -> None:
        path, content = record_path(name), load_raw_record(name)

        first = map_record(path, content)
        map_record(PUBLISHED_PATH, json.dumps(_record()).encode())

        assert map_record(path, content) == first

    def test_result_is_immutable(self) -> None:
        result = _map(_record())

        with pytest.raises(AttributeError):
            result.cve_id = "CVE-2026-9999"  # type: ignore[misc]
        assert isinstance(result.upstream_references, tuple)

    def test_input_record_is_not_mutated(self) -> None:
        record = _record()
        snapshot = copy.deepcopy(record)

        _map(record)

        assert record == snapshot


_MODULE: Final = APP_ROOT / "services" / "tickets" / "kernel_cve_record.py"


class TestModuleBoundary:
    def test_imports_include_no_logging_database_settings_or_io(self) -> None:
        modules = imported_modules(_MODULE, "app.services.tickets")

        assert forbidden_imports(modules) == set()
        assert not {
            m
            for m in modules
            if m.split(".")[0] in {"structlog", "subprocess", "sys", "io", "asyncio"}
            or m in {"app.core.logging", "app.services.git_operations"}
        }

    def test_application_imports_are_core_parser_payload_and_reference_input(
        self,
    ) -> None:
        modules = imported_modules(_MODULE, "app.services.tickets")

        assert {m for m in modules if m.startswith("app.")} == {
            "app.core.enums",
            "app.core.identifiers",
            "app.services.cve_record_parser",
            "app.services.cve_ingest",
            "app.services.reference_service",
        }

    def test_module_defines_no_coroutine(self) -> None:
        source = _MODULE.read_text(encoding="utf-8")

        assert "async def" not in source
        assert "await " not in source
