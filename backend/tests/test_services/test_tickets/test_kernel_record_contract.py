"""Contract tests for the Linux Kernel CNA `vulns.git` source facts.

Contract under test: docs/features/tickets/cve-sync-kernel.md (Algorithm
step 1 file layout, Rejection Handling, CVE JSON Field Mapping: the key
differences from `cvelistV5`, the fields to extract, the explicitly ignored
fields, CVE-ID field name handling, `provider_name` derivation) and
docs/data-sources.md (Linux Kernel CVE Feed: Repository Structure), verified
against the sanitized live capture documented in `tests/support/kernel.py`.

Only source-specific facts are asserted here. The CVE Record 5.x field
shapes of kernel records (types, nullability, bounds, U+0000) are owned and
asserted by `tests/test_services/test_cve_record_contract.py` for the
parser's `vulns_*` fixtures; this module applies its strict test-local model
of the kernel-specific shape to those and to the records added here.

Facts recorded in `tests/support/kernel.py` rather than asserted from a
fixture: the default branch (`master`), the server ignoring `--filter`, the
record counts and frequencies of the full scan, and the documentation-only
source reference URL form. Not observable live, and therefore covered by the
mapping unit tests only: a `null` or mistyped global field, an unrecognized
state under `published/`, a JSON CVE-ID that mismatches its file name, a
`cvssV4_0` or non-Base vector, a non-object reference element, U+0000 in any
string, and undecodable content.
"""

from __future__ import annotations

import re
from pathlib import PurePosixPath
from typing import Any, Literal
from urllib.parse import urlsplit

import pytest
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from app.services.cvss import validate_cvss_vector
from tests.support.cve_record import VULNS_FIXTURES
from tests.support.kernel import (
    ALL_RECORDS,
    KERNEL_ORG_ID,
    RECORD_SOURCES,
    load_raw_record,
    load_record,
    record_path,
    repository_paths,
)

pytestmark = pytest.mark.unit

_RECORD_PATH = re.compile(
    r"cve/(published|rejected)/(?P<year>[0-9]{4})/CVE-(?P=year)-[0-9]{4,}\.json"
)
"""cve-sync-kernel.md Algorithm step 1, matched from the start of the
repository path (test-local; independent of the production pattern)."""

_SIBLING_SUFFIXES = frozenset(
    {"", ".sha1", ".mbox", ".dyad", ".vulnerable", ".reference", ".cvss", ".message"}
)
_REJECTED_ONLY_SUFFIXES = frozenset({".mbox.rejected"})
_CVE_FILE = re.compile(r"(CVE-[0-9]{4}-[0-9]+)(.*)")
_REJECTED_RECORDS = tuple(
    name for name in ALL_RECORDS if record_path(name).startswith("cve/rejected/")
)
_WITHOUT_TITLE = "vulns_rejected_5_1_problem_types"
_WITHOUT_REFERENCES = "rejected_without_references"
_LEGACY_CVE_ID = frozenset({"vulns_rejected_5_0_legacy_cve_id", _WITHOUT_REFERENCES})
_FICTIONAL_DESCRIPTION_PREFIX = (
    "In the Linux kernel, the following vulnerability has been resolved:\n\n"
    "example: fictional subject of "
)
_FICTIONAL_TITLE_PREFIX = "example: fictional title of "
_FICTIONAL_UPSTREAM = re.compile(r"https://advisory\.example\.invalid/upstream/[0-9]+")
_KERNEL_STABLE_PATHS = ("/stable/c/", "/pub/scm/linux/kernel/git/stable/")
_KEPT_HOSTS = frozenset({"syzkaller.appspot.com"})
_EMAIL = re.compile(rb"[A-Za-z0-9._%+-]+@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)")


# ---------------------------------------------------------------------------
# Strict test-local model of the kernel-specific record shape
# ---------------------------------------------------------------------------


class _Strict(BaseModel):
    """No coercion; an optional field is optional by absence only and is
    never `null` when present (as observed live)."""

    model_config = ConfigDict(strict=True, extra="ignore", frozen=True)

    @model_validator(mode="before")
    @classmethod
    def _reject_present_null(cls, data: Any) -> Any:
        if isinstance(data, dict):
            for name, field in cls.model_fields.items():
                key = field.alias or name
                if key in data and data[key] is None:
                    raise ValueError(f"{key} is present and null")
        return data


class _Closed(_Strict):
    """A member whose complete key set is asserted."""

    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)


class _CveMetadata(_Closed):
    """No date, short name, or other key exists in kernel metadata."""

    assigner_org_id: Literal["f4215fc3-5b6b-47ff-a258-f7189bd81038"] = Field(
        alias="assignerOrgId"
    )
    cve_id: str | None = Field(None, alias="cveId")
    legacy_cve_id: str | None = Field(None, alias="cveID")
    state: Literal["PUBLISHED"]
    requester_user_id: str | None = Field(None, alias="requesterUserId")
    serial: int | str | None = None

    @model_validator(mode="after")
    def _one_cve_id(self) -> _CveMetadata:
        if (self.cve_id is None) == (self.legacy_cve_id is None):
            raise ValueError("exactly one of cveId and cveID")
        return self


class _ProviderMetadata(_Closed):
    org_id: Literal["f4215fc3-5b6b-47ff-a258-f7189bd81038"] = Field(alias="orgId")


class _Description(_Strict):
    lang: Literal["en"]
    value: str


class _CvssV31(_Strict):
    version: Literal["3.1"]
    vector_string: str = Field(alias="vectorString")


class _Metric(_Closed):
    cvss_v3_1: _CvssV31 = Field(alias="cvssV3_1")
    scenarios: list[dict[str, Any]] | None = None


class _Reference(_Closed):
    url: str


class _Affected(_Strict):
    vendor: Literal["Linux"]
    product: str
    program_files: list[str] | None = Field(None, alias="programFiles")


class _Cna(_Strict):
    provider_metadata: _ProviderMetadata = Field(alias="providerMetadata")
    title: str | None = None
    descriptions: list[_Description] = Field(min_length=1, max_length=1)
    affected: list[_Affected] = Field(min_length=1)
    metrics: list[_Metric] | None = None
    references: list[_Reference] | None = None
    problem_types: list[dict[str, Any]] | None = Field(None, alias="problemTypes")


class _Containers(_Closed):
    """CNA-only: no `adp` container."""

    cna: _Cna


class _KernelRecord(_Closed):
    containers: _Containers
    cve_metadata: _CveMetadata = Field(alias="cveMetadata")
    data_type: Literal["CVE_RECORD"] = Field(alias="dataType")
    data_version: Literal["5.0", "5.1", "5.1.1"] = Field(alias="dataVersion")


def _record(name: str) -> _KernelRecord:
    return _KernelRecord.model_validate(load_record(name))


def _cna(name: str) -> _Cna:
    return _record(name).containers.cna


def _strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [s for key, item in value.items() for s in (key, *_strings(item))]
    if isinstance(value, list):
        return [s for item in value for s in _strings(item)]
    return []


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestRepositoryLayout:
    def test_record_pattern_selects_only_published_and_rejected_json(self) -> None:
        selected = {p for p in repository_paths() if _RECORD_PATH.fullmatch(p)}

        assert selected == {
            p
            for p in repository_paths()
            if p.startswith(("cve/published/", "cve/rejected/")) and p.endswith(".json")
        }
        assert set(RECORD_SOURCES.values()) <= selected

    @pytest.mark.parametrize(
        "path", ["cve/CVE_JSON_5.0_schema.json", "cve/CVE_JSON_5.1.1_schema.json"]
    )
    def test_schema_json_outside_the_processed_directories_exists(
        self, path: str
    ) -> None:
        assert path in repository_paths()
        assert _RECORD_PATH.fullmatch(path) is None

    def test_testing_tree_holds_record_paths_only_an_anchored_match_excludes(
        self,
    ) -> None:
        path = "cve/testing/published/2021/CVE-2021-47181.json"

        assert path in repository_paths()
        # The same file directly under `cve/` would be a record path.
        assert _RECORD_PATH.fullmatch("cve/" + path.removeprefix("cve/testing/"))
        assert _RECORD_PATH.fullmatch(path) is None

    def test_processed_directories_hold_the_documented_sibling_types(self) -> None:
        suffixes: dict[str, set[str]] = {"published": set(), "rejected": set()}
        for path in repository_paths():
            parts = PurePosixPath(path).parts
            match = _CVE_FILE.fullmatch(parts[-1])
            if len(parts) == 4 and parts[1] in suffixes and match is not None:
                suffixes[parts[1]].add(match.group(2))

        assert suffixes["published"] == _SIBLING_SUFFIXES | {".json"}
        assert suffixes["rejected"] >= (
            {"", ".json", ".sha1", ".mbox", ".dyad"} | _REJECTED_ONLY_SUFFIXES
        )
        assert suffixes["rejected"] <= (
            _SIBLING_SUFFIXES | _REJECTED_ONLY_SUFFIXES | {".json"}
        )

    @pytest.mark.parametrize("directory", ["reserved", "returned", "review"])
    def test_unprocessed_directories_hold_no_json(self, directory: str) -> None:
        paths = [p for p in repository_paths() if p.startswith(f"cve/{directory}/")]

        assert paths
        assert not [p for p in paths if p.endswith(".json")]

    def test_reserved_directory_nests_one_level_deeper(self) -> None:
        assert "cve/reserved/2026/x/CVE-2026-100000" in repository_paths()

    @pytest.mark.parametrize("name", ALL_RECORDS)
    def test_year_directory_is_the_cve_id_year(self, name: str) -> None:
        assert _RECORD_PATH.fullmatch(record_path(name)) is not None


class TestTypedRecord:
    @pytest.mark.parametrize("name", ALL_RECORDS)
    def test_record_has_the_kernel_shape(self, name: str) -> None:
        _record(name)

    @pytest.mark.parametrize(
        ("path", "value"),
        [
            (("cveMetadata", "datePublished"), "2026-01-01T00:00:00.000Z"),
            (("cveMetadata", "dateRejected"), "2026-01-01T00:00:00.000Z"),
            (("cveMetadata", "assignerShortName"), "Linux"),
            (("cveMetadata", "state"), "REJECTED"),
            (("containers", "adp"), []),
            (("containers", "cna", "providerMetadata", "shortName"), "Linux"),
            (("containers", "cna", "title"), None),
            (("containers", "cna", "references", 0, "tags"), ["patch"]),
            (("containers", "cna", "metrics", 0, "cvssV4_0"), {}),
        ],
    )
    def test_typed_model_rejects_a_non_kernel_shape(
        self, path: tuple[str | int, ...], value: Any
    ) -> None:
        """Guards the strictness the source-fact assertions rely on."""
        data = load_record("published_cvss_v3_1")
        target: Any = data
        for key in path[:-1]:
            target = target[key]
        target[path[-1]] = value

        with pytest.raises(ValidationError):
            _KernelRecord.model_validate(data)


class TestMetadata:
    @pytest.mark.parametrize("name", ALL_RECORDS)
    def test_json_cve_id_matches_the_file_name(self, name: str) -> None:
        md = _record(name).cve_metadata

        assert (md.cve_id or md.legacy_cve_id) == PurePosixPath(record_path(name)).stem

    def test_legacy_cve_id_key_occurs_only_in_5_0_records(self) -> None:
        legacy = {n for n in ALL_RECORDS if _record(n).cve_metadata.legacy_cve_id}

        assert legacy == _LEGACY_CVE_ID
        assert {_record(n).data_version for n in legacy} == {"5.0"}

    @pytest.mark.parametrize("name", _REJECTED_RECORDS)
    def test_rejected_directory_record_says_published(self, name: str) -> None:
        assert _record(name).cve_metadata.state == "PUBLISHED"

    def test_rejected_fixture_inventory_is_complete(self) -> None:
        assert set(_REJECTED_RECORDS) == {
            "rejected_cvss_v3_1",
            _WITHOUT_REFERENCES,
            *(n for n in VULNS_FIXTURES if n.startswith("vulns_rejected_")),
        }

    @pytest.mark.parametrize("name", ALL_RECORDS)
    def test_provider_has_no_short_name(self, name: str) -> None:
        cna = load_record(name)["containers"]["cna"]

        assert cna["providerMetadata"] == {"orgId": KERNEL_ORG_ID}


class TestCnaContent:
    def test_title_is_absent_only_in_the_legacy_problem_types_record(self) -> None:
        assert {n for n in ALL_RECORDS if _cna(n).title is None} == {_WITHOUT_TITLE}

    def test_metrics_hold_only_strict_base_cvss_v3_1(self) -> None:
        with_metrics = [n for n in ALL_RECORDS if _cna(n).metrics is not None]

        assert {"published_cvss_v3_1", "rejected_cvss_v3_1"} <= set(with_metrics)
        for name in with_metrics:
            for metric in _cna(name).metrics or ():
                vector = metric.cvss_v3_1.vector_string
                assert validate_cvss_vector(vector).canonical_vector == vector

    def test_records_without_metrics_are_captured(self) -> None:
        assert _cna("published_without_metrics").metrics is None
        assert _cna(_WITHOUT_REFERENCES).metrics is None

    def test_problem_types_occur_only_in_one_record_without_a_cwe(self) -> None:
        carrying = {n for n in ALL_RECORDS if _cna(n).problem_types is not None}

        assert carrying == {_WITHOUT_TITLE}
        problem_types = _cna(_WITHOUT_TITLE).problem_types or []
        descriptions = [d for p in problem_types for d in p["descriptions"]]
        assert descriptions
        assert all("cweId" not in d and "type" not in d for d in descriptions)

    def test_references_are_absent_only_in_one_rejected_record(self) -> None:
        assert {n for n in ALL_RECORDS if _cna(n).references is None} == {
            _WITHOUT_REFERENCES
        }

    def test_references_include_hosts_other_than_git_kernel_org(self) -> None:
        hosts = [
            urlsplit(r.url).hostname
            for r in _cna("published_external_references").references or ()
        ]

        assert len(hosts) == 9
        assert {h for h in hosts if h != "git.kernel.org"} == {
            "syzkaller.appspot.com",
            "advisory.example.invalid",
        }

    def test_affected_elements_without_versions_are_captured(self) -> None:
        affected = load_record(_WITHOUT_REFERENCES)["containers"]["cna"]["affected"]

        assert len(affected) == 2
        assert affected[0] == affected[1]
        assert "versions" not in affected[0]

    @pytest.mark.parametrize("name", list(RECORD_SOURCES))
    def test_ignored_fields_are_present(self, name: str) -> None:
        record = load_record(name)
        cna = record["containers"]["cna"]

        assert "x_generator" in cna
        assert record["cveMetadata"]["assignerOrgId"] == KERNEL_ORG_ID
        if name != _WITHOUT_REFERENCES:
            assert "cpeApplicability" in cna


class TestSanitization:
    @pytest.mark.parametrize("name", list(RECORD_SOURCES))
    def test_fixture_retains_no_real_email(self, name: str) -> None:
        for match in _EMAIL.finditer(load_raw_record(name)):
            assert match.group(1) == b"example.invalid"

    @pytest.mark.parametrize("name", list(RECORD_SOURCES))
    def test_free_text_is_fictional(self, name: str) -> None:
        cna = load_record(name)["containers"]["cna"]

        assert cna["title"].startswith(_FICTIONAL_TITLE_PREFIX)
        for description in cna["descriptions"]:
            assert description["value"].startswith(_FICTIONAL_DESCRIPTION_PREFIX)
        for metric in cna.get("metrics", []):
            for scenario in metric.get("scenarios", []):
                assert scenario["value"] == "Fictional scenario."

    @pytest.mark.parametrize("name", list(RECORD_SOURCES))
    def test_urls_are_kept_organisation_locations_or_fictional(self, name: str) -> None:
        urls = [
            s
            for s in _strings(load_record(name))
            if s.startswith(("http://", "https://"))
        ]

        for url in urls:
            parts = urlsplit(url)
            if parts.hostname == "git.kernel.org":
                assert parts.path.startswith(_KERNEL_STABLE_PATHS), url
            elif parts.hostname == "advisory.example.invalid":
                assert _FICTIONAL_UPSTREAM.fullmatch(url), url
            else:
                assert parts.hostname in _KEPT_HOSTS, url

    def test_review_file_names_are_fictional(self) -> None:
        review = [p for p in repository_paths() if p.startswith("cve/review/")]

        assert review
        assert all(p.endswith("-example") for p in review)
