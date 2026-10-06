"""Contract tests for the Red Hat Security Data per-CVE endpoint.

Contract under test: docs/features/tickets/cve-sync-redhat.md (Algorithm,
Field Mapping, Response Validation, Explicitly Ignored Fields, Error
Handling) and docs/data-sources.md (Red Hat Security Data), verified
against sanitized live responses captured anonymously on 2026-10-06
through Sentinel's production HTTP client
(`create_http_client(name="sync_redhat_cves")`, its standard User-Agent;
docs/conventions.md, External Integration Contract Verification). Every
consumed field is asserted for name, nesting, type, and nullability
through a strict test-local typed model; the production parser does not
exist yet.

Live verification on 2026-10-06:

- 146 per-CVE requests: 144 HTTP 200 across publication years 2005-2026
  and 2 HTTP 404 for nonexistent CVE-IDs. Every response was
  `application/json` and none redirected (`Location` absent). A request
  with a non-Sentinel default library User-Agent (`Python-urllib`) is
  answered with an HTML 403 by the CDN; Sentinel's User-Agent is accepted.
- The root is always a JSON object. `cvss3` (59 records) is an object
  `{cvss3_base_score, cvss3_scoring_vector, status}` and `cvss` (75) an
  object `{cvss_base_score, cvss_scoring_vector, status}`, each scoring
  vector a string. `cwe` (84) is always a string holding one `CWE-<n>`.
  `references` is always an array of exactly one string whose URLs are
  separated by `\\n` only: no `\\r`, trailing newline, or blank line was
  observed. `bugzilla` is always an object `{description, id, url}` with a
  non-empty string `url`. `package_state` is an array of objects
  `{product_name, fix_state, package_name, cpe}`, sometimes with `impact`;
  `package_name` is a string, contains `/` for container images, and
  duplicate names are common. `cvss4` was never present.
- All 133 sampled per-CVE vectors, and all 27,354 v3 vectors among the
  30,000 most recent records of the list endpoint `GET /cve.json`, are
  accepted by `app.services.cvss.validate_cvss_vector` as pure Base
  vectors (CVSS v2.0, `CVSS:3.0/`, and `CVSS:3.1/`).

Not observable live, and therefore covered by the fetcher unit tests only:
null, empty, or whitespace-only vectors; invalid or non-Base vectors; CWE
chains or lists; blank or CRLF reference lines and trailing newlines; an
empty Bugzilla URL; null or blank package names; `cvss4`; a non-object
root; and U+0000 in any string.
"""

from __future__ import annotations

import json
import re
from typing import Any, NotRequired, TypedDict
from urllib.parse import urlsplit

import pytest
from pydantic import TypeAdapter, ValidationError

from app.core.enums import CVSSVersion
from app.services.cvss import validate_cvss_vector
from tests.support.redhat import (
    CVE_SUCCESS_FIXTURES,
    NOT_FOUND_FIXTURE,
    load_cve_fixture,
    load_raw_fixture,
)

# Algorithm step 6.
_CWE_PATTERN = re.compile(r"^CWE-[1-9][0-9]*$")
_V3_VERSIONS = frozenset({CVSSVersion.V3_0, CVSSVersion.V3_1})
_KEPT_REFERENCE_HOSTS = frozenset({"www.cve.org", "nvd.nist.gov", "www.cisa.gov"})
_FICTIONAL_REFERENCE_HOST = "advisory.example.invalid"
_FICTIONAL_TEXT = "Fictional "
_FICTIONAL_ACKNOWLEDGEMENT = "Example Researcher (Example Org)"


class _CVSS3(TypedDict):
    cvss3_scoring_vector: str


class _CVSS(TypedDict):
    cvss_scoring_vector: str


class _Bugzilla(TypedDict):
    url: str
    description: str


class _PackageState(TypedDict):
    package_name: str


class _CVEResponse(TypedDict):
    """The consumed fields as observed live: optional by absence, never
    `null` when present. Unconsumed fields are ignored."""

    cvss3: NotRequired[_CVSS3]
    cvss: NotRequired[_CVSS]
    cwe: NotRequired[str]
    references: NotRequired[list[str]]
    bugzilla: NotRequired[_Bugzilla]
    package_state: NotRequired[list[_PackageState]]


_RESPONSE = TypeAdapter(_CVEResponse)


def _validated(body: Any) -> _CVEResponse:
    return _RESPONSE.validate_python(body, strict=True)


def _project(raw: Any, validated: Any) -> Any:
    """`raw` restricted to the keys the typed model consumes."""
    if isinstance(validated, dict):
        return {key: _project(raw[key], value) for key, value in validated.items()}
    if isinstance(validated, list):
        return [_project(r, v) for r, v in zip(raw, validated, strict=True)]
    return raw


def _fixtures_with(key: str) -> list[str]:
    return [name for name in CVE_SUCCESS_FIXTURES if key in load_cve_fixture(name)]


def _reference_lines(name: str) -> list[str]:
    references = _validated(load_cve_fixture(name)).get("references", [])
    return [line for element in references for line in element.split("\n")]


def _package_names(name: str) -> list[str]:
    package_state = _validated(load_cve_fixture(name)).get("package_state", [])
    return [entry["package_name"] for entry in package_state]


def _strings(value: Any) -> list[str]:
    if isinstance(value, dict):
        return [s for item in value.values() for s in _strings(item)]
    if isinstance(value, list):
        return [s for item in value for s in _strings(item)]
    return [value] if isinstance(value, str) else []


@pytest.mark.unit
class TestTypedResponse:
    @pytest.mark.parametrize("name", CVE_SUCCESS_FIXTURES)
    def test_root_is_a_json_object(self, name: str) -> None:
        assert isinstance(json.loads(load_raw_fixture(name)), dict)

    @pytest.mark.parametrize("name", CVE_SUCCESS_FIXTURES)
    def test_consumed_fields_validate_strictly_without_coercion(
        self, name: str
    ) -> None:
        body = load_cve_fixture(name)

        validated = _validated(body)

        assert validated == _project(body, validated)

    @pytest.mark.parametrize(
        ("key", "value"),
        [
            ("cvss3", {"cvss3_scoring_vector": None}),
            ("cvss", {"cvss_scoring_vector": 7}),
            ("cwe", None),
            ("references", "https://advisory.example.invalid/upstream/1"),
            ("bugzilla", {"url": None, "description": "Fictional flaw"}),
            ("package_state", [{"package_name": None}]),
        ],
    )
    def test_typed_model_rejects_a_null_or_mistyped_consumed_field(
        self, key: str, value: Any
    ) -> None:
        """Guards the strictness the fixture assertions rely on."""
        with pytest.raises(ValidationError):
            _validated({**load_cve_fixture("cve_full_v3"), key: value})

    @pytest.mark.parametrize("name", CVE_SUCCESS_FIXTURES)
    def test_no_string_contains_nul_or_carriage_return(self, name: str) -> None:
        for value in _strings(load_cve_fixture(name)):
            assert "\x00" not in value
            assert "\r" not in value


@pytest.mark.unit
class TestCVSSShape:
    @pytest.mark.parametrize("name", _fixtures_with("cvss3"))
    def test_v3_vector_is_an_accepted_v3_base_vector(self, name: str) -> None:
        vector = _validated(load_cve_fixture(name))["cvss3"]["cvss3_scoring_vector"]

        assert validate_cvss_vector(vector).version in _V3_VERSIONS

    @pytest.mark.parametrize("name", _fixtures_with("cvss"))
    def test_v2_vector_is_an_accepted_v2_base_vector(self, name: str) -> None:
        vector = _validated(load_cve_fixture(name))["cvss"]["cvss_scoring_vector"]

        assert validate_cvss_vector(vector).version is CVSSVersion.V2_0

    @pytest.mark.parametrize("name", CVE_SUCCESS_FIXTURES)
    def test_no_cvss4_field_is_published(self, name: str) -> None:
        assert "cvss4" not in load_cve_fixture(name)


@pytest.mark.unit
class TestCWEShape:
    @pytest.mark.parametrize("name", _fixtures_with("cwe"))
    def test_cwe_is_one_identifier_matching_the_step_6_pattern(self, name: str) -> None:
        assert _CWE_PATTERN.fullmatch(_validated(load_cve_fixture(name))["cwe"])


@pytest.mark.unit
class TestReferencesShape:
    @pytest.mark.parametrize("name", CVE_SUCCESS_FIXTURES)
    def test_references_is_an_array_of_one_string(self, name: str) -> None:
        assert len(_validated(load_cve_fixture(name))["references"]) == 1

    @pytest.mark.parametrize("name", CVE_SUCCESS_FIXTURES)
    def test_lines_split_on_newline_are_absolute_http_urls(self, name: str) -> None:
        for line in _reference_lines(name):
            assert "\r" not in line
            assert line.strip() == line
            parts = urlsplit(line)
            assert parts.scheme in {"http", "https"}
            assert parts.netloc

    @pytest.mark.parametrize("name", CVE_SUCCESS_FIXTURES)
    def test_element_carries_several_newline_separated_urls(self, name: str) -> None:
        assert len(_reference_lines(name)) > 1


@pytest.mark.unit
class TestBugzillaShape:
    @pytest.mark.parametrize("name", CVE_SUCCESS_FIXTURES)
    def test_bugzilla_url_and_description_are_non_empty_strings(
        self, name: str
    ) -> None:
        bugzilla = _validated(load_cve_fixture(name))["bugzilla"]

        assert bugzilla["url"].strip()
        assert bugzilla["description"].strip()
        assert urlsplit(bugzilla["url"]).scheme == "https"


@pytest.mark.unit
class TestPackageStateShape:
    @pytest.mark.parametrize("name", _fixtures_with("package_state"))
    def test_package_names_are_non_blank_strings(self, name: str) -> None:
        names = _package_names(name)

        assert names
        assert all(package_name.strip() for package_name in names)


@pytest.mark.unit
class TestUnconsumedFields:
    """The fields of § Explicitly Ignored Fields appear as served, so the
    parser must tolerate them."""

    @pytest.mark.parametrize("name", CVE_SUCCESS_FIXTURES)
    def test_root_unconsumed_fields_are_present(self, name: str) -> None:
        body = load_cve_fixture(name)

        assert {
            "name",
            "threat_severity",
            "public_date",
            "details",
            "affected_release",
            "csaw",
        } <= set(body)
        assert "id" in body["bugzilla"]

    @pytest.mark.parametrize("name", _fixtures_with("cvss3"))
    def test_cvss3_score_and_status_are_present(self, name: str) -> None:
        cvss3 = load_cve_fixture(name)["cvss3"]

        assert {"cvss3_base_score", "status"} <= set(cvss3)

    @pytest.mark.parametrize("name", _fixtures_with("cvss"))
    def test_cvss_score_and_status_are_present(self, name: str) -> None:
        cvss = load_cve_fixture(name)["cvss"]

        assert {"cvss_base_score", "status"} <= set(cvss)

    @pytest.mark.parametrize("name", _fixtures_with("package_state"))
    def test_package_state_unconsumed_fields_are_present(self, name: str) -> None:
        for entry in load_cve_fixture(name)["package_state"]:
            assert {"product_name", "fix_state", "cpe"} <= set(entry)

    def test_statement_acknowledgement_and_mitigation_occur(self) -> None:
        body = load_cve_fixture("cve_full_v3")

        assert {"statement", "acknowledgement", "mitigation"} <= set(body)


@pytest.mark.unit
class TestFixtureCoverage:
    """The captured set exercises every observable consumed variant."""

    def test_v3_only_v2_only_both_and_neither_are_captured(self) -> None:
        variants = {
            name: ("cvss3" in body, "cvss" in body)
            for name in CVE_SUCCESS_FIXTURES
            for body in [load_cve_fixture(name)]
        }

        assert variants == {
            "cve_full_v3": (True, False),
            "cve_v2_v3": (True, True),
            "cve_v2_only": (False, True),
            "cve_no_cvss": (False, False),
        }

    def test_both_v3_prefixes_are_captured(self) -> None:
        versions = {
            validate_cvss_vector(
                load_cve_fixture(name)["cvss3"]["cvss3_scoring_vector"]
            ).version
            for name in _fixtures_with("cvss3")
        }

        assert versions == _V3_VERSIONS

    def test_cwe_present_and_absent_are_captured(self) -> None:
        assert set(_fixtures_with("cwe")) == {"cve_full_v3", "cve_v2_only"}

    def test_package_state_absent_is_captured(self) -> None:
        assert "cve_no_cvss" not in _fixtures_with("package_state")

    def test_container_path_package_name_is_captured(self) -> None:
        assert any("/" in name for name in _package_names("cve_full_v3"))

    @pytest.mark.parametrize("name", ["cve_full_v3", "cve_v2_only"])
    def test_duplicate_package_names_are_captured(self, name: str) -> None:
        names = _package_names(name)

        assert len(set(names)) < len(names)

    def test_kept_and_fictional_reference_hosts_are_captured(self) -> None:
        hosts = {
            urlsplit(line).hostname
            for name in CVE_SUCCESS_FIXTURES
            for line in _reference_lines(name)
        }

        assert hosts == {*_KEPT_REFERENCE_HOSTS, _FICTIONAL_REFERENCE_HOST}


@pytest.mark.unit
class TestNotFoundBody:
    def test_not_found_body_is_a_json_string_literal(self) -> None:
        body = json.loads(load_raw_fixture(NOT_FOUND_FIXTURE))

        assert body == '{"message":"Not Found"}'


@pytest.mark.unit
class TestSanitization:
    @pytest.mark.parametrize("name", [*CVE_SUCCESS_FIXTURES, NOT_FOUND_FIXTURE])
    def test_fixture_retains_no_email(self, name: str) -> None:
        assert b"@" not in load_raw_fixture(name)

    @pytest.mark.parametrize("name", CVE_SUCCESS_FIXTURES)
    def test_reference_hosts_are_kept_or_fictional(self, name: str) -> None:
        for line in _reference_lines(name):
            host = urlsplit(line).hostname
            assert host in _KEPT_REFERENCE_HOSTS | {_FICTIONAL_REFERENCE_HOST}
            if host == _FICTIONAL_REFERENCE_HOST:
                assert re.fullmatch(
                    r"https://advisory\.example\.invalid/upstream/[0-9]+", line
                )

    @pytest.mark.parametrize("name", CVE_SUCCESS_FIXTURES)
    def test_free_text_is_fictional(self, name: str) -> None:
        body = load_cve_fixture(name)
        free_text = [
            *body["details"],
            *([body["statement"]] if "statement" in body else []),
            *([body["mitigation"]["value"]] if "mitigation" in body else []),
        ]

        assert free_text
        assert all(text.startswith(_FICTIONAL_TEXT) for text in free_text)
        if "acknowledgement" in body:
            assert _FICTIONAL_ACKNOWLEDGEMENT in body["acknowledgement"]
