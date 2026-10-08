"""Contract tests for the GitHub Advisory Database REST API.

Contract under test: docs/features/tickets/cve-sync-ghsa.md (Algorithm,
`fetch_single(cve_id)`, Field Mapping, Explicitly ignored fields, Version
range parsing rules, Response Validation, Error Handling) and
docs/data-sources.md (GHSA), verified against sanitized live responses
captured anonymously on 2026-10-08 with Python `urllib` requests
(`User-Agent: sentinel-contract-probe`, `Accept: application/vnd.github+json`,
`X-GitHub-Api-Version: 2022-11-28`; docs/conventions.md, External
Integration Contract Verification). Every consumed field is asserted for
name, nesting, type, and nullability through a strict test-local typed
model; no production parser exists yet, and the model is independent of
the one it will define.

Live verification on 2026-10-08 (18 anonymous requests in total):

- Six consecutive pages of the periodic query
  `?type=reviewed&is_withdrawn=false&modified=>=2026-09-23T22:00:34Z&sort=updated&direction=asc&per_page=100`,
  100 advisories each (600 advisories). Every response was HTTP 200
  `application/json; charset=utf-8`. Page 1 carried a `Link` header with
  only `rel="next"`; later pages added a `rel="prev"` link with `before=`.
  On a multi-page result the last page still carries a `Link` header with
  only `rel="prev"` (verified live on 2026-10-08 by an independent
  re-verification: 4 pages of 100/100/100/4 advisories for
  `modified=>=2026-10-05T00:00:00Z`), and a single-page response carries
  none. The next URL is always
  `https://api.github.com/advisories` with the original filters re-encoded
  and an opaque `after=` cursor.
- Every advisory has all of `ghsa_id`, `cve_id`, `url`, `html_url`,
  `summary`, `description`, `type`, `severity`, `repository_advisory_url`,
  `source_code_location`, `identifiers`, `references`, `published_at`,
  `updated_at`, `github_reviewed_at`, `nvd_published_at`, `withdrawn_at`,
  `vulnerabilities`, `cvss_severities`, `cwes`, `credits`, `comments`, and
  `cvss`; `epss` is present in 446.
- `cve_id` is null in 82 advisories and otherwise a canonical CVE-ID; no
  CVE-ID occurs twice. `html_url` is always
  `https://github.com/advisories/{ghsa_id}`, and it is also listed in
  `references` of all 600. `updated_at` is ascending. All dates have the
  form `YYYY-MM-DDTHH:MM:SSZ`.
- `summary` is at most 187 characters and `description` at most 22,275;
  neither is ever null. `source_code_location` is the empty string in 2
  advisories and otherwise a URL. `references` is an array of strings (at
  most 36). `cwes` holds objects `{cwe_id, name}`, every `cwe_id` a valid
  `CWE-<n>`. `comments` is an integer.
- 1030 `vulnerabilities[]` entries, all with a `package` object
  `{ecosystem, name}`, a string `vulnerable_version_range`, a string or
  null `first_patched_version` (83 null), and a `vulnerable_functions`
  list. Range shapes: `>=, <` 372, `<` 313, `<=` 181, `>=, <=` 144, `=` 18,
  `>, <` 2; none unrecognized. Ecosystems: npm 373, maven 216, pip 189,
  go 84, nuget 75, composer 54, rust 25, swift 5, erlang 4, rubygems 4,
  actions 1. GitHub documents the enumeration rubygems, npm, pip, maven,
  nuget, composer, go, rust, erlang, actions, pub, other, and swift.
- `cvss_severities` is always an object `{cvss_v3, cvss_v4}` whose members
  are objects `{vector_string, score}`; `vector_string` is null when
  unset. Prefixes: `CVSS:3.1` 447, `CVSS:3.0` 5, `CVSS:4.0` 197. 0 of the
  452 v3 vectors and 9 of the 197 v4 vectors carry non-Base metrics
  (`E:P` six times, `RE:M` twice, `U:Red`, `U:Amber`, `S:P`, `AU:Y`,
  `R:U`, `V:C`, and `X` values); 5 of those 9 advisories have no v3
  vector.
- No string contains U+0000. No two affected-version entries collide on
  the conflict key `(product/package_name, version, version_end,
  ecosystem, repo)`.
- `?cve_id=` single queries: a reviewed advisory (CVE-2021-44228) returns a
  list of one advisory with that `cve_id`, whose v3 vector carries the
  Temporal metric `E:H`; an unknown, a withdrawn-only, and an
  unreviewed-only CVE-ID each return `[]`. A fictional bearer token is
  answered with HTTP 401 `{"message":"Bad credentials",...}`.

Documentation-only (not observed live): the authenticated quota and the
HTTP 403 secondary rate limit.

Not observable live, and therefore covered by the parser and fetcher unit
tests only: a null, absent, or empty `vulnerabilities`; a null `package` or
package `name`; a null or empty range; an unrecognized range or a single
lower bound; the `other` and `pub` ecosystems; an invalid CWE; an invalid
`cve_id` or a null one other than the observed null; a non-array root;
U+0000 in any string; and over-length values.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timedelta
from typing import Annotated, Any, TypedDict
from urllib.parse import parse_qs, urlsplit

import pytest
from pydantic import Field, TypeAdapter, ValidationError

from app.core.enums import CVSSVersion
from app.services.cvss import validate_cvss_vector, validate_external_cvss_vector
from app.services.ticket_mutations_errors import InvalidCVSSVectorError
from tests.support.ghsa import (
    ADVISORY_FIXTURES,
    AUTH_401_FIXTURE,
    FIXTURE_CVE_IDS,
    LIVE_NEXT_LINK,
    LIVE_NEXT_PREV_LINK,
    SINGLE_EMPTY_FIXTURE,
    SINGLE_REVIEWED_CVE_ID,
    SINGLE_REVIEWED_FIXTURE,
    load_advisory_fixture,
    load_list_fixture,
    load_raw_fixture,
)

_ALL_FIXTURES = (
    *ADVISORY_FIXTURES,
    SINGLE_REVIEWED_FIXTURE,
    SINGLE_EMPTY_FIXTURE,
    AUTH_401_FIXTURE,
)
_GHSA_ID = re.compile(r"GHSA(-[23456789cfghjmpqrvwx]{4}){3}")
_CVE_ID = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}")
# Field Mapping, CWE classifications.
_CWE_PATTERN = re.compile(r"^CWE-[1-9][0-9]*$")
_DATE_TIME = r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"
_GITHUB_ECOSYSTEMS = frozenset(
    {
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
)
"""GitHub's documented ecosystem enumeration (Field Mapping)."""
_RANGE_CONSTRAINT = re.compile(r"(>=|<=|>|<|=)\s*(.*)")
_RECOGNIZED_RANGE_SHAPES = frozenset(
    {
        ("<",),
        ("<=",),
        (">=", "<"),
        (">=", "<="),
        ("=",),
        (">", "<"),
        (">=",),
        (">",),
    }
)
"""The base patterns and a single lower bound (Version range parsing
rules)."""
_V3_BASE_METRICS = frozenset({"AV", "AC", "PR", "UI", "S", "C", "I", "A"})
_V4_BASE_METRICS = frozenset(
    {"AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA"}
)
_V3_VERSIONS = frozenset({CVSSVersion.V3_0, CVSSVersion.V3_1})
_NON_BASE_V4_FIXTURES = ("advisory_v4_non_base", "advisory_v3_v4_non_base_ranges")
_TOP_LEVEL_KEYS = frozenset(
    {
        "ghsa_id",
        "cve_id",
        "url",
        "html_url",
        "summary",
        "description",
        "type",
        "severity",
        "repository_advisory_url",
        "source_code_location",
        "identifiers",
        "references",
        "published_at",
        "updated_at",
        "github_reviewed_at",
        "nvd_published_at",
        "withdrawn_at",
        "vulnerabilities",
        "cvss_severities",
        "cwes",
        "credits",
        "comments",
        "cvss",
    }
)
"""The keys of every live advisory; `epss` is additionally optional."""
_FILTERS = {
    "type": ["reviewed"],
    "is_withdrawn": ["false"],
    "modified": [">=2026-09-23T22:00:34Z"],
    "sort": ["updated"],
    "direction": ["asc"],
    "per_page": ["100"],
}
"""The periodic query filters of the live capture (Algorithm step 5)."""

_FICTIONAL_DESCRIPTION_BODY = (
    "\n\n### Impact\n\nFictional impact statement.\n\n### Patches\n\n"
    "Fictional patch note."
)
"""The fixed fictional text following the first sentence of every
sanitized `description`."""
_FICTIONAL_LOGIN = "example-researcher"
_FICTIONAL_USER_ID = 1000
_FICTIONAL_NODE_ID = "U_exampleNode0001"
_FICTIONAL_UPSTREAM = re.compile(r"https://advisory\.example\.invalid/upstream/[0-9]+")
_FICTIONAL_HOSTS = frozenset({"advisory.example.invalid", "github.example.invalid"})
_KEPT_HOSTS = frozenset(
    {
        "nvd.nist.gov",
        "logging.apache.org",
        "access.redhat.com",
        "osv.dev",
        "cna.erlef.org",
        "www.vulncheck.com",
    }
)
"""Advisory-database, vendor, and project hosts whose URLs are retained."""
_KEPT_GITHUB_OWNERS = frozenset(
    {
        "advisories",
        "apache",
        "ash-project",
        "bcgit",
        "gitpython-developers",
        "google-github-actions",
        "payloadcms",
        "pyca",
        "pypa",
        "socketio",
    }
)
"""`github.com` path owners (organisations and the advisory database) whose
URLs are retained."""
_EMAIL = re.compile(rb"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+")

type _DateTime = Annotated[str, Field(pattern=_DATE_TIME)]


class _Package(TypedDict):
    ecosystem: str
    name: str | None


class _Vulnerability(TypedDict):
    package: _Package
    vulnerable_version_range: str | None


class _Vector(TypedDict):
    vector_string: str | None


class _CvssSeverities(TypedDict):
    cvss_v3: _Vector
    cvss_v4: _Vector


class _Cwe(TypedDict):
    cwe_id: str


class _Advisory(TypedDict):
    """The consumed fields (Response Validation) as observed live: always
    present, `null` only where the type allows it. Unconsumed fields are
    ignored."""

    ghsa_id: str
    cve_id: str | None
    html_url: str
    summary: str
    description: str | None
    published_at: _DateTime
    updated_at: _DateTime
    source_code_location: str | None
    references: list[str]
    cwes: list[_Cwe]
    cvss_severities: _CvssSeverities
    vulnerabilities: list[_Vulnerability]


_ADVISORY = TypeAdapter(_Advisory)
_ADVISORY_LIST = TypeAdapter(list[_Advisory])


def _validated(body: Any) -> _Advisory:
    return _ADVISORY.validate_python(body, strict=True)


def _project(raw: Any, validated: Any) -> Any:
    """`raw` restricted to the keys the typed model consumes."""
    if isinstance(validated, dict):
        return {key: _project(raw[key], value) for key, value in validated.items()}
    if isinstance(validated, list):
        return [_project(r, v) for r, v in zip(raw, validated, strict=True)]
    return raw


def _single_advisory() -> dict[str, Any]:
    advisory: dict[str, Any] = load_list_fixture(SINGLE_REVIEWED_FIXTURE)[0]
    return advisory


_ADVISORY_NAMES = (*ADVISORY_FIXTURES, SINGLE_REVIEWED_FIXTURE)


def _advisory(name: str) -> dict[str, Any]:
    if name == SINGLE_REVIEWED_FIXTURE:
        return _single_advisory()
    return load_advisory_fixture(name)


def _vector(name: str, version: str) -> str | None:
    return _validated(_advisory(name))["cvss_severities"][
        "cvss_v3" if version == "v3" else "cvss_v4"
    ]["vector_string"]


def _fixtures_with_vector(version: str) -> list[str]:
    return [name for name in _ADVISORY_NAMES if _vector(name, version) is not None]


def _metric_keys(vector: str) -> set[str]:
    return {part.split(":")[0] for part in vector.split("/")[1:]}


def _base_tokens(vector: str, base: frozenset[str]) -> str:
    """The prefix and the Base tokens of a FIRST-ordered vector."""
    prefix, *tokens = vector.split("/")
    return "/".join([prefix, *(t for t in tokens if t.split(":")[0] in base)])


def _ranges(name: str) -> list[str]:
    return [
        entry["vulnerable_version_range"]
        for entry in _validated(_advisory(name))["vulnerabilities"]
        if entry["vulnerable_version_range"] is not None
    ]


def _range_shape(value: str) -> tuple[str, ...] | None:
    """The operator sequence of a recognized range, or `None`."""
    operators: list[str] = []
    for part in value.split(","):
        match = _RANGE_CONSTRAINT.fullmatch(part.strip())
        if match is None or not match.group(2).strip():
            return None
        operators.append(match.group(1))
    shape = tuple(operators)
    return shape if shape in _RECOGNIZED_RANGE_SHAPES else None


def _strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [s for key, item in value.items() for s in (key, *_strings(item))]
    if isinstance(value, list):
        return [s for item in value for s in _strings(item)]
    return []


def _urls(value: Any) -> list[str]:
    return [s for s in _strings(value) if s.startswith(("http://", "https://"))]


def _links(header: str) -> dict[str, str]:
    """`rel` → URL of an RFC 8288 `Link` header value."""
    return {
        rel: url for url, rel in re.findall(r'<([^>]*)>\s*;\s*rel="([^"]*)"', header)
    }


@pytest.mark.unit
class TestTypedAdvisory:
    @pytest.mark.parametrize("name", ADVISORY_FIXTURES)
    def test_advisory_fixture_is_a_json_object(self, name: str) -> None:
        assert isinstance(json.loads(load_raw_fixture(name)), dict)

    @pytest.mark.parametrize("name", _ADVISORY_NAMES)
    def test_consumed_fields_validate_strictly_without_coercion(
        self, name: str
    ) -> None:
        body = _advisory(name)

        validated = _validated(body)

        assert validated == _project(body, validated)

    @pytest.mark.parametrize(
        ("key", "value"),
        [
            ("ghsa_id", None),
            ("html_url", None),
            ("cve_id", 2021),
            ("summary", None),
            ("published_at", "2026-10-08"),
            ("updated_at", "2026-10-08T00:00:00+00:00"),
            ("source_code_location", 1),
            ("references", "https://advisory.example.invalid/upstream/1"),
            ("references", [None]),
            ("cwes", [{"cwe_id": 20}]),
            ("cvss_severities", {"cvss_v3": {"vector_string": None}}),
            (
                "cvss_severities",
                {"cvss_v3": {"vector_string": 7}, "cvss_v4": {"vector_string": None}},
            ),
            ("vulnerabilities", None),
            (
                "vulnerabilities",
                [{"package": None, "vulnerable_version_range": "< 1.0"}],
            ),
            (
                "vulnerabilities",
                [
                    {
                        "package": {"ecosystem": None, "name": "example"},
                        "vulnerable_version_range": "< 1.0",
                    }
                ],
            ),
            (
                "vulnerabilities",
                [
                    {
                        "package": {"ecosystem": "npm", "name": "example"},
                        "vulnerable_version_range": 1,
                    }
                ],
            ),
        ],
    )
    def test_typed_model_rejects_a_null_or_mistyped_consumed_field(
        self, key: str, value: Any
    ) -> None:
        """Guards the strictness the fixture assertions rely on."""
        with pytest.raises(ValidationError):
            _validated({**load_advisory_fixture("advisory_v3_v4"), key: value})

    @pytest.mark.parametrize("name", _ADVISORY_NAMES)
    def test_every_live_top_level_key_is_present(self, name: str) -> None:
        keys = set(_advisory(name))

        assert keys - {"epss"} == _TOP_LEVEL_KEYS

    @pytest.mark.parametrize("name", _ADVISORY_NAMES)
    def test_no_string_contains_nul(self, name: str) -> None:
        assert all("\x00" not in s for s in _strings(_advisory(name)))

    @pytest.mark.parametrize("name", _ADVISORY_NAMES)
    def test_dates_parse_as_utc_date_times(self, name: str) -> None:
        advisory = _validated(_advisory(name))

        for value in (advisory["published_at"], advisory["updated_at"]):
            assert datetime.fromisoformat(value).utcoffset() == timedelta(0)


@pytest.mark.unit
class TestIdentifiers:
    @pytest.mark.parametrize("name", _ADVISORY_NAMES)
    def test_ghsa_id_matches_the_ghsa_id_pattern(self, name: str) -> None:
        assert _GHSA_ID.fullmatch(_validated(_advisory(name))["ghsa_id"])

    @pytest.mark.parametrize("name", _ADVISORY_NAMES)
    def test_html_url_is_the_advisory_page_of_the_ghsa_id(self, name: str) -> None:
        advisory = _validated(_advisory(name))

        assert advisory["html_url"] == (
            f"https://github.com/advisories/{advisory['ghsa_id']}"
        )

    @pytest.mark.parametrize("name", ADVISORY_FIXTURES)
    def test_cve_id_is_the_recorded_canonical_cve_id_or_null(self, name: str) -> None:
        cve_id = _validated(load_advisory_fixture(name))["cve_id"]

        assert cve_id == FIXTURE_CVE_IDS[name]
        assert cve_id is None or _CVE_ID.fullmatch(cve_id)

    @pytest.mark.parametrize("name", _ADVISORY_NAMES)
    def test_identifiers_repeat_the_ghsa_id_and_the_cve_id(self, name: str) -> None:
        """`.identifiers[]` is ignored because it is redundant with the
        dedicated top-level fields (Explicitly ignored fields)."""
        advisory = _advisory(name)
        expected = [{"value": advisory["ghsa_id"], "type": "GHSA"}]
        if advisory["cve_id"] is not None:
            expected.append({"value": advisory["cve_id"], "type": "CVE"})

        assert advisory["identifiers"] == expected


@pytest.mark.unit
class TestCVSSShape:
    @pytest.mark.parametrize("name", _ADVISORY_NAMES)
    def test_vector_string_prefix_matches_its_member(self, name: str) -> None:
        v3 = _vector(name, "v3")
        v4 = _vector(name, "v4")

        assert v3 is None or v3.startswith(("CVSS:3.0/", "CVSS:3.1/"))
        assert v4 is None or v4.startswith("CVSS:4.0/")

    @pytest.mark.parametrize(
        "name", [n for n in _fixtures_with_vector("v3") if n in ADVISORY_FIXTURES]
    )
    def test_page_v3_vector_is_an_accepted_base_vector(self, name: str) -> None:
        vector = _vector(name, "v3")
        assert vector is not None

        assert _metric_keys(vector) == _V3_BASE_METRICS
        assert validate_cvss_vector(vector).version in _V3_VERSIONS

    @pytest.mark.parametrize(
        "name", ["advisory_v3_v4", "advisory_erlang", "advisory_gt_range"]
    )
    def test_base_v4_vector_is_accepted(self, name: str) -> None:
        vector = _vector(name, "v4")
        assert vector is not None

        assert _metric_keys(vector) == _V4_BASE_METRICS
        assert validate_cvss_vector(vector).version is CVSSVersion.V4_0

    @pytest.mark.parametrize("name", _NON_BASE_V4_FIXTURES)
    def test_non_base_v4_vector_reduces_to_its_base_vector(self, name: str) -> None:
        """Field Mapping, CVSS assessments: the External Base Reduction of
        cvss-scoring.md keeps the Base vector; the strict parser rejects it."""
        vector = _vector(name, "v4")
        assert vector is not None

        assert _metric_keys(vector) > _V4_BASE_METRICS
        assert validate_external_cvss_vector(vector).canonical_vector == (
            _base_tokens(vector, _V4_BASE_METRICS)
        )
        with pytest.raises(InvalidCVSSVectorError):
            validate_cvss_vector(vector)

    def test_single_query_v3_vector_with_a_temporal_metric_reduces_to_base(
        self,
    ) -> None:
        vector = _vector(SINGLE_REVIEWED_FIXTURE, "v3")
        assert vector is not None

        assert _metric_keys(vector) == _V3_BASE_METRICS | {"E"}
        parsed = validate_external_cvss_vector(vector)
        assert parsed.version is CVSSVersion.V3_1
        assert parsed.canonical_vector == _base_tokens(vector, _V3_BASE_METRICS)
        with pytest.raises(InvalidCVSSVectorError):
            validate_cvss_vector(vector)

    def test_v3_only_v4_only_and_both_vectors_are_captured(self) -> None:
        variants = {
            name: (_vector(name, "v3") is not None, _vector(name, "v4") is not None)
            for name in _ADVISORY_NAMES
        }

        assert variants == {
            "advisory_v3_v4": (True, True),
            "advisory_v4_non_base": (False, True),
            "advisory_v3_v4_non_base_ranges": (True, True),
            "advisory_null_cve_id": (True, False),
            "advisory_erlang": (False, True),
            "advisory_multi_ecosystem": (True, False),
            "advisory_empty_source_location": (True, False),
            "advisory_gt_range": (False, True),
            SINGLE_REVIEWED_FIXTURE: (True, False),
        }


@pytest.mark.unit
class TestCWEShape:
    @pytest.mark.parametrize("name", _ADVISORY_NAMES)
    def test_every_cwe_id_matches_the_validation_pattern(self, name: str) -> None:
        cwes = _validated(_advisory(name))["cwes"]

        assert cwes
        assert all(_CWE_PATTERN.fullmatch(cwe["cwe_id"]) for cwe in cwes)

    @pytest.mark.parametrize("name", _ADVISORY_NAMES)
    def test_cwe_objects_carry_an_unconsumed_name(self, name: str) -> None:
        for cwe in _advisory(name)["cwes"]:
            assert set(cwe) == {"cwe_id", "name"}


@pytest.mark.unit
class TestVulnerabilitiesShape:
    @pytest.mark.parametrize("name", _ADVISORY_NAMES)
    def test_ecosystems_are_within_the_documented_enumeration(self, name: str) -> None:
        for entry in _validated(_advisory(name))["vulnerabilities"]:
            assert entry["package"]["ecosystem"] in _GITHUB_ECOSYSTEMS

    @pytest.mark.parametrize("name", _ADVISORY_NAMES)
    def test_package_names_are_non_blank_strings(self, name: str) -> None:
        entries = _validated(_advisory(name))["vulnerabilities"]

        assert entries
        for entry in entries:
            package_name = entry["package"]["name"]
            assert package_name is not None
            assert package_name.strip() == package_name != ""

    @pytest.mark.parametrize("name", _ADVISORY_NAMES)
    def test_every_range_is_a_recognized_shape(self, name: str) -> None:
        entries = _validated(_advisory(name))["vulnerabilities"]

        for entry in entries:
            range_ = entry["vulnerable_version_range"]
            assert range_ is not None
            assert _range_shape(range_) is not None

    def test_every_base_pattern_is_captured(self) -> None:
        shapes = {
            _range_shape(range_) for name in _ADVISORY_NAMES for range_ in _ranges(name)
        }

        assert shapes == {
            ("<",),
            ("<=",),
            (">=", "<"),
            (">=", "<="),
            ("=",),
            (">", "<"),
        }

    def test_required_ranges_of_the_maven_fixture_are_captured(self) -> None:
        shapes = {_range_shape(r) for r in _ranges("advisory_v3_v4_non_base_ranges")}

        assert {("=",), ("<=",), (">=", "<=")} <= shapes

    def test_strict_lower_bound_ranges_are_captured(self) -> None:
        assert _ranges("advisory_gt_range") == [
            "> 3.0.0, < 3.90.0",
            "> 4.0.0-canary.0, < 4.0.0-canary.34",
        ]

    def test_non_semver_bound_is_captured(self) -> None:
        assert ">= 2.0-beta9, < 2.3.1" in _ranges(SINGLE_REVIEWED_FIXTURE)

    def test_ecosystems_of_the_capture_are_represented(self) -> None:
        ecosystems = {
            entry["package"]["ecosystem"]
            for name in _ADVISORY_NAMES
            for entry in _validated(_advisory(name))["vulnerabilities"]
        }

        assert ecosystems == {"npm", "pip", "maven", "erlang", "actions"}

    def test_two_ecosystems_in_one_advisory_are_captured(self) -> None:
        entries = _validated(load_advisory_fixture("advisory_multi_ecosystem"))[
            "vulnerabilities"
        ]

        assert [entry["package"]["ecosystem"] for entry in entries] == [
            "npm",
            "npm",
            "actions",
        ]

    @pytest.mark.parametrize(
        "name", ["advisory_v3_v4", "advisory_v3_v4_non_base_ranges"]
    )
    def test_repeated_package_names_are_captured(self, name: str) -> None:
        names = [
            entry["package"]["name"]
            for entry in _validated(load_advisory_fixture(name))["vulnerabilities"]
        ]

        assert len(set(names)) < len(names)

    @pytest.mark.parametrize("name", _ADVISORY_NAMES)
    def test_unconsumed_entry_fields_are_present(self, name: str) -> None:
        for entry in _advisory(name)["vulnerabilities"]:
            assert set(entry) == {
                "package",
                "vulnerable_version_range",
                "first_patched_version",
                "vulnerable_functions",
            }
            assert isinstance(entry["vulnerable_functions"], list)
            assert entry["first_patched_version"] is None or isinstance(
                entry["first_patched_version"], str
            )

    def test_null_first_patched_version_is_captured(self) -> None:
        entries = load_advisory_fixture("advisory_v3_v4_non_base_ranges")[
            "vulnerabilities"
        ]

        assert any(entry["first_patched_version"] is None for entry in entries)


@pytest.mark.unit
class TestSourceCodeLocation:
    def test_empty_source_code_location_is_captured(self) -> None:
        advisory = _validated(load_advisory_fixture("advisory_empty_source_location"))

        assert advisory["source_code_location"] == ""

    @pytest.mark.parametrize(
        "name",
        [n for n in _ADVISORY_NAMES if n != "advisory_empty_source_location"],
    )
    def test_source_code_location_is_an_absolute_https_url(self, name: str) -> None:
        location = _validated(_advisory(name))["source_code_location"]
        assert location is not None

        parts = urlsplit(location)
        assert parts.scheme == "https"
        assert parts.netloc


@pytest.mark.unit
class TestReferencesShape:
    @pytest.mark.parametrize("name", _ADVISORY_NAMES)
    def test_references_are_absolute_http_urls(self, name: str) -> None:
        references = _validated(_advisory(name))["references"]

        assert references
        for reference in references:
            parts = urlsplit(reference)
            assert parts.scheme in {"http", "https"}
            assert parts.netloc

    @pytest.mark.parametrize("name", _ADVISORY_NAMES)
    def test_html_url_is_also_listed_in_references(self, name: str) -> None:
        advisory = _validated(_advisory(name))

        assert advisory["html_url"] in advisory["references"]


@pytest.mark.unit
class TestSingleQuery:
    def test_reviewed_query_returns_one_advisory_for_the_cve_id(self) -> None:
        advisories = _ADVISORY_LIST.validate_python(
            load_list_fixture(SINGLE_REVIEWED_FIXTURE), strict=True
        )

        assert len(advisories) == 1
        assert advisories[0]["cve_id"] == SINGLE_REVIEWED_CVE_ID

    def test_query_without_a_match_returns_an_empty_array_as_served(self) -> None:
        assert load_raw_fixture(SINGLE_EMPTY_FIXTURE) == b"[]"


@pytest.mark.unit
class TestAuthFailureBody:
    def test_bad_credentials_body_is_stored_as_served(self) -> None:
        raw = load_raw_fixture(AUTH_401_FIXTURE)

        assert raw == (
            b'{\r\n  "message": "Bad credentials",\r\n'
            b'  "documentation_url": "https://docs.github.com/rest",\r\n'
            b'  "status": "401"\r\n}'
        )

    def test_bad_credentials_body_is_an_object_with_a_string_status(self) -> None:
        assert json.loads(load_raw_fixture(AUTH_401_FIXTURE)) == {
            "message": "Bad credentials",
            "documentation_url": "https://docs.github.com/rest",
            "status": "401",
        }


@pytest.mark.unit
class TestPaginationLink:
    """Algorithm step 6.e: the live next URL passes the next-URL check and
    keeps the original filters."""

    @pytest.mark.parametrize("header", [LIVE_NEXT_LINK, LIVE_NEXT_PREV_LINK])
    def test_next_url_passes_the_next_url_check(self, header: str) -> None:
        parts = urlsplit(_links(header)["next"])

        assert parts.scheme == "https"
        assert parts.hostname == "api.github.com"
        assert parts.netloc == "api.github.com"
        assert parts.port is None
        assert parts.username is None
        assert parts.password is None
        assert parts.fragment == ""
        assert parts.path == "/advisories"

    @pytest.mark.parametrize("header", [LIVE_NEXT_LINK, LIVE_NEXT_PREV_LINK])
    def test_next_url_preserves_the_filters_and_adds_an_after_cursor(
        self, header: str
    ) -> None:
        query = parse_qs(urlsplit(_links(header)["next"]).query, strict_parsing=True)

        assert {key: query[key] for key in _FILTERS} == _FILTERS
        assert set(query) == {*_FILTERS, "after"}
        assert len(query["after"]) == 1

    def test_first_page_link_has_only_a_next_relation(self) -> None:
        assert set(_links(LIVE_NEXT_LINK)) == {"next"}

    def test_later_page_link_adds_a_prev_relation_with_a_before_cursor(
        self,
    ) -> None:
        links = _links(LIVE_NEXT_PREV_LINK)
        query = parse_qs(urlsplit(links["prev"]).query)

        assert set(links) == {"next", "prev"}
        assert "before" in query
        assert "after" not in query


@pytest.mark.unit
class TestUnconsumedFields:
    """The fields of § Explicitly ignored fields appear as served, so the
    parser must tolerate them."""

    @pytest.mark.parametrize("name", _ADVISORY_NAMES)
    def test_ignored_fields_have_their_live_types(self, name: str) -> None:
        advisory = _advisory(name)

        assert advisory["type"] == "reviewed"
        assert isinstance(advisory["severity"], str)
        assert isinstance(advisory["comments"], int)
        assert advisory["withdrawn_at"] is None
        assert set(advisory["cvss"]) == {"vector_string", "score"}
        for member in advisory["cvss_severities"].values():
            assert set(member) == {"vector_string", "score"}
        assert isinstance(advisory["credits"], list)

    def test_epss_present_and_absent_are_captured(self) -> None:
        with_epss = {name for name in _ADVISORY_NAMES if "epss" in _advisory(name)}

        assert set(_ADVISORY_NAMES) - with_epss == {
            "advisory_null_cve_id",
            "advisory_gt_range",
        }

    def test_null_repository_advisory_url_is_captured(self) -> None:
        advisory = load_advisory_fixture("advisory_v3_v4_non_base_ranges")

        assert advisory["repository_advisory_url"] is None


@pytest.mark.unit
class TestSanitization:
    @pytest.mark.parametrize("name", _ALL_FIXTURES)
    def test_fixture_retains_no_email(self, name: str) -> None:
        assert _EMAIL.search(load_raw_fixture(name)) is None

    @pytest.mark.parametrize("name", _ADVISORY_NAMES)
    def test_free_text_is_fictional(self, name: str) -> None:
        advisory = _advisory(name)
        ghsa_id = advisory["ghsa_id"]

        assert advisory["summary"] == f"Fictional summary of {ghsa_id}."
        assert advisory["description"] == (
            f"Fictional description of {ghsa_id}.{_FICTIONAL_DESCRIPTION_BODY}"
        )

    @pytest.mark.parametrize("name", _ADVISORY_NAMES)
    def test_credits_are_one_fictional_user(self, name: str) -> None:
        credits = _advisory(name)["credits"]

        assert len(credits) == 1
        user = credits[0]["user"]
        assert user["login"] == _FICTIONAL_LOGIN
        assert user["id"] == _FICTIONAL_USER_ID
        assert user["node_id"] == _FICTIONAL_NODE_ID
        urls = _urls(credits)
        assert urls
        assert all(urlsplit(url).hostname == "github.example.invalid" for url in urls)

    @pytest.mark.parametrize("name", _ADVISORY_NAMES)
    def test_urls_are_kept_organisation_locations_or_fictional(self, name: str) -> None:
        for url in _urls(_advisory(name)):
            parts = urlsplit(url)
            host = parts.hostname
            segments = parts.path.split("/")
            if host == "github.com":
                assert segments[1] in _KEPT_GITHUB_OWNERS
            elif host == "api.github.com":
                owner = segments[2] if segments[1] == "repos" else segments[1]
                assert owner in _KEPT_GITHUB_OWNERS
            elif host == "advisory.example.invalid":
                assert _FICTIONAL_UPSTREAM.fullmatch(url)
            else:
                assert host in _KEPT_HOSTS | _FICTIONAL_HOSTS

    def test_replaced_references_are_captured(self) -> None:
        replaced = [
            reference
            for name in _ADVISORY_NAMES
            for reference in _advisory(name)["references"]
            if _FICTIONAL_UPSTREAM.fullmatch(reference)
        ]

        assert len(replaced) == 3
