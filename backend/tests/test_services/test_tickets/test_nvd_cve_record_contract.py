"""Contract tests for the NVD CVE API 2.0 and Source API.

Contract under test: docs/features/tickets/cve-sync-nvd.md (Algorithm step
4.c page envelope; Field Mapping: Global CVE fields and Required fields,
Optional member validation, Candidate skip event, Source identity, CVSS
metrics, CWE / weaknesses, CPE configurations, References, Explicitly
ignored fields, External String Admissibility; NVD Source API Caching;
`fetch_single(cve_id)`) and docs/data-sources.md (NVD), verified against the
sanitized live responses of `services.nvd.nist.gov/rest/json/cves/2.0` and
`/rest/json/source/2.0` captured anonymously on 2026-10-10
(docs/conventions.md, External Integration Contract Verification). Every
consumed field is asserted for name, nesting, type, and nullability through
a strict test-local typed model; no production mapping exists yet, and the
model is independent of the one `app/services/tickets/nvd_cve_record.py`
will define.

Live verification on 2026-10-10 (37 anonymous HTTP 200 requests over
33,114 distinct records and one Source API response; the full evidence,
counts, and trimming rules are recorded in `tests/support/nvd.py`):

- Every page envelope carries the integers `totalResults`,
  `resultsPerPage`, and `startIndex`, `format` `NVD_CVE`, `version` `2.0`,
  a millisecond `timestamp`, and the array `vulnerabilities`; an unknown
  CVE-ID returns `totalResults` 0 and an empty array.
- Every element is `{"cve": {...}}` with string `id`, `published`,
  `lastModified` (millisecond form, no offset), and `vulnStatus` (seven
  values), exactly one English description, an object `metrics`, and an
  array `references`. Rejected records carry empty `metrics` and
  `references` and no `weaknesses`, `configurations`, or `affected`.
- Metric and weakness entries name their provider in `source`; CNA entries
  may be `Primary` and NVD's own entries `Secondary`, so `type` does not
  identify NVD (Source identity). Every vector prefix matches its array,
  the External Base Reduction accepts every vector, and every v4.0 vector
  carries non-Base metrics. No source appears twice in one metric array.
- Weakness values are `CWE-<n>`, `NVD-CWE-noinfo`, or `NVD-CWE-Other`;
  every reference tag is listed in ticket-references.md § CVE Source Tag
  Mapping. Configurations hold `OR` nodes with `negate` `false`, `AND`
  configurations pair vulnerable firmware with platform hardware, and no
  configuration carries `negate`.
- The Source API lists 514 sources in one page; names are trimmed, at most
  80 characters, and `nvd@nist.gov` is the only identifier of `NIST`.
- No string contains U+0000.

The typed model also declares `metrics.*[].type`, `weaknesses[].type`, and
`references[].source`, which the mapping does not read (Explicitly ignored
fields), because the Source identity and sanitization assertions below rely
on their observed shape; `operator`, version-range, and every other
unconsumed member are only observed, not modelled.

Documentation-only (not observed live), and therefore covered by the
mapping unit tests (test_nvd_cve_record.py) only: `negate = true` on a node
or configuration; nested nodes; `configurations` `null` or `[]`; an absent,
`null`, or malformed `matchCriteriaId`; a non-boolean `vulnerable`; an
invalid `criteria`; an unknown `vulnStatus`; timestamps with an offset;
absent or wrongly typed required global fields; wrongly typed optional
members; a Source API body other than the observed envelope; malformed
source entries; blank source names; and U+0000 anywhere.
"""

from __future__ import annotations

import json
import re
from copy import deepcopy
from datetime import datetime
from typing import Annotated, Any, Final, Literal, NotRequired, TypedDict

import pytest
from pydantic import Field, TypeAdapter, ValidationError

from app.core.enums import CVSSVersion
from app.core.identifiers import is_valid_cve_id
from app.services.cvss import validate_cvss_vector, validate_external_cvss_vector
from app.services.ticket_mutations_errors import InvalidCVSSVectorError
from tests.support.nvd import (
    CISA_ADP_SOURCE_IDENTIFIER,
    FIXTURE_DIR,
    NVD_SOURCE_IDENTIFIER,
    PAGE_EMPTY,
    PAGE_FIXTURES,
    PAGE_REJECTED,
    RECORD_CVE_IDS,
    RECORD_FIXTURES,
    SINGLE_LOG4SHELL,
    SINGLE_PLATFORM_ALSO_VULNERABLE,
    SOURCE_PAGE,
    all_records,
    load_json_fixture,
    load_raw_fixture,
    load_record,
)

_ALL_FIXTURES: Final = (*RECORD_FIXTURES, *PAGE_FIXTURES, SOURCE_PAGE)
_CVE_FIXTURES: Final = (*RECORD_FIXTURES, *PAGE_FIXTURES)
_SINGLE_QUERIES: Final = {
    SINGLE_LOG4SHELL: "CVE-2021-44228",
    SINGLE_PLATFORM_ALSO_VULNERABLE: "CVE-2026-50355",
}
"""Single-record page fixture → the requested `cveId` (`fetch_single`)."""

_TIMESTAMP: Final = r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}$"
"""The observed millisecond form without an offset (NVD Date Format)."""
_VULN_STATUSES: Final = frozenset(
    {
        "Analyzed",
        "Awaiting Analysis",
        "Deferred",
        "Modified",
        "Received",
        "Rejected",
        "Undergoing Analysis",
    }
)
_CVSS_ARRAY_VERSIONS: Final = {
    "cvssMetricV2": CVSSVersion.V2_0,
    "cvssMetricV30": CVSSVersion.V3_0,
    "cvssMetricV31": CVSSVersion.V3_1,
    "cvssMetricV40": CVSSVersion.V4_0,
}
"""CVSS metrics extraction rule 1: the four arrays in iteration order."""
_CVSS_ARRAY_PREFIXES: Final = {
    "cvssMetricV30": "CVSS:3.0/",
    "cvssMetricV31": "CVSS:3.1/",
    "cvssMetricV40": "CVSS:4.0/",
}
_V4_BASE_METRICS: Final = frozenset(
    {"AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA"}
)
_V4_NON_BASE_FIXTURE: Final = "record_awaiting_v40_non_base"
# CWE / weaknesses, extraction rule 3.
_CWE_PATTERN: Final = re.compile(r"^CWE-[1-9][0-9]*$")
_CWE_PLACEHOLDERS: Final = frozenset({"NVD-CWE-noinfo", "NVD-CWE-Other"})
_NVD_REFERENCE_TAGS: Final = frozenset(
    {
        "Patch",
        "Vendor Advisory",
        "Third Party Advisory",
        "US Government Resource",
        "VDB Entry",
        "Issue Tracking",
        "Exploit",
        "Mailing List",
        "Release Notes",
        "Technical Description",
        "Mitigation",
        "Press/Media Coverage",
        "Tool Signature",
        "Broken Link",
        "Not Applicable",
        "Permissions Required",
        "URL Repurposed",
        "Product",
    }
)
"""The NVD column of ticket-references.md § CVE Source Tag Mapping
(test-local copy)."""
_CRITERIA_MAX_LENGTH: Final = 2048
_UPPERCASE_UUID: Final = re.compile(
    r"[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}"
)
_CONFIGURATION_KEYS: Final = frozenset({"operator", "nodes"})
_NODE_KEYS: Final = frozenset({"operator", "negate", "cpeMatch"})
_CPE_MATCH_KEYS: Final = frozenset(
    {
        "vulnerable",
        "criteria",
        "matchCriteriaId",
        "versionStartIncluding",
        "versionStartExcluding",
        "versionEndIncluding",
        "versionEndExcluding",
    }
)
_RANGE_KEYS: Final = _CPE_MATCH_KEYS - {"vulnerable", "criteria", "matchCriteriaId"}
_FIRMWARE_ON_HARDWARE_FIXTURES: Final = (
    "record_analyzed_full",
    "record_firmware_hardware",
    "record_multiple_configurations",
    SINGLE_LOG4SHELL,
)
_PLATFORM_ALSO_VULNERABLE_CRITERIA: Final = (
    "cpe:2.3:o:microsoft:windows_server_2012:-:*:*:*:*:*:*:*"
)
_WITHOUT_CONFIGURATIONS: Final = frozenset(
    {
        "record_awaiting_v30",
        "record_awaiting_v40_non_base",
        "record_reserved_suse",
        "record_deferred_without_metrics",
        "record_received",
        PAGE_REJECTED,
    }
)
_SSVC_FIXTURES: Final = (
    "record_analyzed_full",
    "record_awaiting_v30",
    "record_awaiting_v40_non_base",
    SINGLE_LOG4SHELL,
)
_CISA_MEMBERS: Final = frozenset(
    {"cisaExploitAdd", "cisaActionDue", "cisaRequiredAction", "cisaVulnerabilityName"}
)
_SOURCE_NAME_MAX_LENGTH: Final = 100
"""The `CWEEntry` source bound (CWE / weaknesses, extraction rule 5)."""

_EMAIL: Final = re.compile(rb"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+")
_FICTIONAL_DOMAIN: Final = b"@example.com"
_FICTIONAL_CONTACT: Final = re.compile(r"contact-[a-z0-9-]+@example\.com")
_FICTIONAL_UNKNOWN: Final = re.compile(rb"unknown-[0-9]+@example\.com")
_FICTIONAL_UPSTREAM: Final = re.compile(
    r"https://advisory\.example\.invalid/upstream/[0-9]+"
)

type _Timestamp = Annotated[str, Field(pattern=_TIMESTAMP)]
type _NonNegative = Annotated[int, Field(ge=0)]
type _VulnStatus = Literal[
    "Analyzed",
    "Awaiting Analysis",
    "Deferred",
    "Modified",
    "Received",
    "Rejected",
    "Undergoing Analysis",
]
type _EntryType = Literal["Primary", "Secondary"]


class _Description(TypedDict):
    lang: str
    value: str


class _CvssData(TypedDict):
    vectorString: str


class _Metric(TypedDict):
    source: str
    type: _EntryType
    cvssData: _CvssData


class _Metrics(TypedDict):
    cvssMetricV2: NotRequired[list[_Metric]]
    cvssMetricV30: NotRequired[list[_Metric]]
    cvssMetricV31: NotRequired[list[_Metric]]
    cvssMetricV40: NotRequired[list[_Metric]]


class _Weakness(TypedDict):
    source: str
    type: _EntryType
    description: list[_Description]


class _Reference(TypedDict):
    url: str
    source: str
    tags: NotRequired[list[str]]


class _CpeMatch(TypedDict):
    vulnerable: bool
    criteria: str
    matchCriteriaId: str


class _Node(TypedDict):
    negate: bool
    cpeMatch: list[_CpeMatch]


class _Configuration(TypedDict):
    negate: NotRequired[bool]
    nodes: list[_Node]


class _Cve(TypedDict):
    """The consumed fields as observed live: optional by absence, never
    `null` when present. Unconsumed members are ignored."""

    id: str
    published: _Timestamp
    lastModified: _Timestamp
    vulnStatus: _VulnStatus
    descriptions: list[_Description]
    metrics: _Metrics
    weaknesses: NotRequired[list[_Weakness]]
    references: list[_Reference]
    configurations: NotRequired[list[_Configuration]]


class _Element(TypedDict):
    cve: _Cve


class _Page(TypedDict):
    """The consumed envelope members (Algorithm step 4.c)."""

    totalResults: _NonNegative
    vulnerabilities: list[_Element]


class _Source(TypedDict):
    name: str
    sourceIdentifiers: list[str]


class _SourcePage(TypedDict):
    """The consumed Source API members (NVD Source API Caching)."""

    totalResults: int
    resultsPerPage: int
    sources: list[_Source]


_ELEMENT = TypeAdapter(_Element)
_PAGE = TypeAdapter(_Page)
_SOURCE_PAGE = TypeAdapter(_SourcePage)
_ABSENT: Final = object()


def _validated(element: Any) -> _Element:
    return _ELEMENT.validate_python(element, strict=True)


def _validated_page(body: Any) -> _Page:
    return _PAGE.validate_python(body, strict=True)


def _validated_source_page(body: Any) -> _SourcePage:
    return _SOURCE_PAGE.validate_python(body, strict=True)


def _project(raw: Any, validated: Any) -> Any:
    """`raw` restricted to the keys the typed model consumes."""
    if isinstance(validated, dict):
        return {key: _project(raw[key], value) for key, value in validated.items()}
    if isinstance(validated, list):
        return [_project(r, v) for r, v in zip(raw, validated, strict=True)]
    return raw


def _mutated(body: Any, path: tuple[str | int, ...], value: Any) -> Any:
    """A deep copy of `body` whose member at `path` is `value`, or removed
    when `value` is `_ABSENT`."""
    copy = deepcopy(body)
    target = copy
    for key in path[:-1]:
        target = target[key]
    if value is _ABSENT:
        del target[path[-1]]
    else:
        target[path[-1]] = value
    return copy


def _cve(name: str) -> _Cve:
    return _validated(load_record(name))["cve"]


def _metric_arrays(cve: _Cve) -> dict[str, list[_Metric]]:
    metrics = cve["metrics"]
    return {
        "cvssMetricV2": metrics.get("cvssMetricV2", []),
        "cvssMetricV30": metrics.get("cvssMetricV30", []),
        "cvssMetricV31": metrics.get("cvssMetricV31", []),
        "cvssMetricV40": metrics.get("cvssMetricV40", []),
    }


def _metrics(cve: _Cve) -> list[tuple[str, _Metric]]:
    return [
        (array, metric)
        for array, metrics in _metric_arrays(cve).items()
        for metric in metrics
    ]


def _cpe_matches(cve: _Cve) -> list[_CpeMatch]:
    return [
        match
        for configuration in cve.get("configurations", [])
        for node in configuration["nodes"]
        for match in node["cpeMatch"]
    ]


def _raw_configurations(element: dict[str, Any]) -> list[dict[str, Any]]:
    configurations: list[dict[str, Any]] = element["cve"].get("configurations", [])
    return configurations


def _cpe_part(criteria: str) -> str:
    return criteria.split(":")[2]


def _is_firmware_on_hardware(configuration: dict[str, Any]) -> bool:
    """An `AND` configuration of a vulnerable `o` node and a platform `h`
    node."""
    if configuration.get("operator") != "AND":
        return False
    nodes = configuration["nodes"]
    if len(nodes) != 2:
        return False
    vulnerable, platform = (node["cpeMatch"] for node in nodes)
    return all(
        m["vulnerable"] is True and _cpe_part(m["criteria"]) == "o" for m in vulnerable
    ) and all(
        m["vulnerable"] is False and _cpe_part(m["criteria"]) == "h" for m in platform
    )


def _source_cache() -> dict[str, str]:
    """The cache construction of NVD Source API Caching (test-local)."""
    page = _validated_source_page(load_json_fixture(SOURCE_PAGE))
    return {
        identifier: source["name"].strip()
        for source in page["sources"]
        for identifier in source["sourceIdentifiers"]
    }


def _metric_keys(vector: str) -> set[str]:
    return {part.split(":")[0] for part in vector.split("/")[1:]}


def _strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [s for key, item in value.items() for s in (key, *_strings(item))]
    if isinstance(value, list):
        return [s for item in value for s in _strings(item)]
    return []


_RECORDS: Final = all_records()
_RECORD_PARAMS: Final = [
    pytest.param(name, element, id=f"{name}:{element['cve']['id']}")
    for name, element in _RECORDS
]


@pytest.mark.unit
class TestPageEnvelope:
    @pytest.mark.parametrize("name", PAGE_FIXTURES)
    def test_page_body_is_a_json_object(self, name: str) -> None:
        assert isinstance(json.loads(load_raw_fixture(name)), dict)

    @pytest.mark.parametrize("name", PAGE_FIXTURES)
    def test_consumed_envelope_validates_strictly_without_coercion(
        self, name: str
    ) -> None:
        body = load_json_fixture(name)

        validated = _validated_page(body)

        assert validated == _project(body, validated)

    @pytest.mark.parametrize("name", PAGE_FIXTURES)
    def test_unconsumed_envelope_members_have_their_live_shape(self, name: str) -> None:
        """Algorithm step 4.c: not validated by the mapping; recorded here."""
        body = load_json_fixture(name)

        assert type(body["resultsPerPage"]) is int
        assert type(body["startIndex"]) is int
        assert body["format"] == "NVD_CVE"
        assert body["version"] == "2.0"
        assert re.fullmatch(_TIMESTAMP, body["timestamp"])

    def test_unknown_cve_id_returns_zero_results_as_served(self) -> None:
        page = _validated_page(load_json_fixture(PAGE_EMPTY))

        assert page["totalResults"] == 0
        assert page["vulnerabilities"] == []
        assert load_raw_fixture(PAGE_EMPTY) == (
            b'{"resultsPerPage":0,"startIndex":0,"totalResults":0,'
            b'"format":"NVD_CVE","version":"2.0",'
            b'"timestamp":"2026-10-10T17:14:44.130","vulnerabilities":[]}'
        )

    @pytest.mark.parametrize(("name", "cve_id"), sorted(_SINGLE_QUERIES.items()))
    def test_single_query_returns_one_element_for_the_cve_id(
        self, name: str, cve_id: str
    ) -> None:
        page = _validated_page(load_json_fixture(name))

        assert page["totalResults"] == 1
        assert len(page["vulnerabilities"]) == 1
        assert page["vulnerabilities"][0]["cve"]["id"] == cve_id

    def test_rejected_page_carries_only_the_rejected_shape(self) -> None:
        body = load_json_fixture(PAGE_REJECTED)
        page = _validated_page(body)

        assert page["totalResults"] == 12
        assert len(page["vulnerabilities"]) == 12
        for element in body["vulnerabilities"]:
            cve = element["cve"]
            assert cve["vulnStatus"] == "Rejected"
            assert cve["metrics"] == {}
            assert cve["references"] == []
            assert {"configurations", "weaknesses", "affected"}.isdisjoint(cve)


@pytest.mark.unit
class TestTypedRecord:
    @pytest.mark.parametrize(("name", "element"), _RECORD_PARAMS)
    def test_consumed_fields_validate_strictly_without_coercion(
        self, name: str, element: dict[str, Any]
    ) -> None:
        validated = _validated(element)

        assert validated == _project(element, validated)

    @pytest.mark.parametrize("name", RECORD_FIXTURES)
    def test_record_id_is_the_recorded_cve_id(self, name: str) -> None:
        assert _cve(name)["id"] == RECORD_CVE_IDS[name]

    @pytest.mark.parametrize(("name", "element"), _RECORD_PARAMS)
    def test_id_is_a_canonical_cve_id(self, name: str, element: dict[str, Any]) -> None:
        assert is_valid_cve_id(_validated(element)["cve"]["id"])

    @pytest.mark.parametrize(("name", "element"), _RECORD_PARAMS)
    def test_timestamps_parse_without_an_offset(
        self, name: str, element: dict[str, Any]
    ) -> None:
        """Required fields: a timestamp without an offset is UTC."""
        cve = _validated(element)["cve"]

        for value in (cve["published"], cve["lastModified"]):
            assert datetime.fromisoformat(value).tzinfo is None

    @pytest.mark.parametrize(("name", "element"), _RECORD_PARAMS)
    def test_record_has_exactly_one_english_description(
        self, name: str, element: dict[str, Any]
    ) -> None:
        descriptions = _validated(element)["cve"]["descriptions"]

        assert [d["lang"] for d in descriptions].count("en") == 1

    def test_every_observed_vuln_status_is_captured(self) -> None:
        statuses = {_validated(element)["cve"]["vulnStatus"] for _, element in _RECORDS}

        assert statuses == _VULN_STATUSES

    def test_spanish_descriptions_are_captured(self) -> None:
        langs = {
            d["lang"]
            for _, element in _RECORDS
            for d in _validated(element)["cve"]["descriptions"]
        }

        assert langs == {"en", "es"}


@pytest.mark.unit
class TestStrictModels:
    """Guards the strictness the fixture assertions rely on."""

    @pytest.mark.parametrize(
        ("path", "value"),
        [
            pytest.param(("cve",), [], id="cve-array"),
            pytest.param(("cve", "id"), _ABSENT, id="id-absent"),
            pytest.param(("cve", "id"), 2025, id="id-int"),
            pytest.param(("cve", "published"), 20260408, id="published-int"),
            pytest.param(("cve", "published"), None, id="published-null"),
            pytest.param(
                ("cve", "published"),
                "2026-04-08T18:24:51.257+00:00",
                id="published-offset",
            ),
            pytest.param(
                ("cve", "lastModified"), "2026-07-25", id="last-modified-date"
            ),
            pytest.param(("cve", "vulnStatus"), None, id="vuln-status-null"),
            pytest.param(
                ("cve", "vulnStatus"), "Fictional State", id="vuln-status-new"
            ),
            pytest.param(
                ("cve", "descriptions"), "Fictional description.", id="descriptions-str"
            ),
            pytest.param(
                ("cve", "descriptions", 0, "value"), None, id="description-value-null"
            ),
            pytest.param(("cve", "metrics"), None, id="metrics-null"),
            pytest.param(
                ("cve", "metrics", "cvssMetricV31"), {}, id="metric-array-object"
            ),
            pytest.param(
                ("cve", "metrics", "cvssMetricV31", 0, "cvssData", "vectorString"),
                7,
                id="vector-int",
            ),
            pytest.param(
                ("cve", "metrics", "cvssMetricV31", 0, "cvssData"),
                None,
                id="cvss-data-null",
            ),
            pytest.param(
                ("cve", "metrics", "cvssMetricV31", 0, "source"),
                None,
                id="metric-source-null",
            ),
            pytest.param(
                ("cve", "metrics", "cvssMetricV31", 0, "type"),
                "Tertiary",
                id="metric-type-unknown",
            ),
            pytest.param(
                ("cve", "weaknesses", 0, "description"), None, id="weakness-null"
            ),
            pytest.param(
                ("cve", "weaknesses", 0, "description", 0, "value"),
                787,
                id="weakness-value-int",
            ),
            pytest.param(("cve", "references"), None, id="references-null"),
            pytest.param(("cve", "references", 0, "url"), None, id="url-null"),
            pytest.param(("cve", "references", 0, "tags"), "Exploit", id="tags-str"),
            pytest.param(("cve", "configurations"), None, id="configurations-null"),
            pytest.param(
                ("cve", "configurations", 0, "negate"), "false", id="config-negate-str"
            ),
            pytest.param(
                ("cve", "configurations", 0, "nodes", 0, "negate"),
                None,
                id="node-negate-null",
            ),
            pytest.param(
                ("cve", "configurations", 0, "nodes", 0, "cpeMatch", 0, "vulnerable"),
                1,
                id="vulnerable-int",
            ),
            pytest.param(
                ("cve", "configurations", 0, "nodes", 0, "cpeMatch", 0, "criteria"),
                None,
                id="criteria-null",
            ),
            pytest.param(
                (
                    "cve",
                    "configurations",
                    0,
                    "nodes",
                    0,
                    "cpeMatch",
                    0,
                    "matchCriteriaId",
                ),
                None,
                id="match-criteria-id-null",
            ),
        ],
    )
    def test_record_model_rejects_a_null_or_mistyped_consumed_field(
        self, path: tuple[str | int, ...], value: Any
    ) -> None:
        with pytest.raises(ValidationError):
            _validated(_mutated(load_record("record_analyzed_full"), path, value))

    @pytest.mark.parametrize(
        ("path", "value"),
        [
            pytest.param(("totalResults",), "1", id="total-str"),
            pytest.param(("totalResults",), True, id="total-bool"),
            pytest.param(("totalResults",), -1, id="total-negative"),
            pytest.param(("totalResults",), _ABSENT, id="total-absent"),
            pytest.param(("vulnerabilities",), None, id="vulnerabilities-null"),
            pytest.param(("vulnerabilities",), {}, id="vulnerabilities-object"),
        ],
    )
    def test_page_model_rejects_a_wrong_envelope(
        self, path: tuple[str | int, ...], value: Any
    ) -> None:
        with pytest.raises(ValidationError):
            _validated_page(_mutated(load_json_fixture(SINGLE_LOG4SHELL), path, value))

    def test_page_model_rejects_a_non_object_body(self) -> None:
        with pytest.raises(ValidationError):
            _validated_page([])

    @pytest.mark.parametrize(
        ("path", "value"),
        [
            pytest.param(("totalResults",), "514", id="total-str"),
            pytest.param(("resultsPerPage",), None, id="per-page-null"),
            pytest.param(("sources",), {}, id="sources-object"),
            pytest.param(("sources", 0, "name"), None, id="name-null"),
            pytest.param(
                ("sources", 0, "sourceIdentifiers"),
                "mitre-1@example.com",
                id="identifiers-str",
            ),
            pytest.param(
                ("sources", 0, "sourceIdentifiers"), [None], id="identifier-null"
            ),
        ],
    )
    def test_source_model_rejects_a_wrong_shape(
        self, path: tuple[str | int, ...], value: Any
    ) -> None:
        with pytest.raises(ValidationError):
            _validated_source_page(
                _mutated(load_json_fixture(SOURCE_PAGE), path, value)
            )


@pytest.mark.unit
class TestCVSSMetrics:
    @pytest.mark.parametrize(("name", "element"), _RECORD_PARAMS)
    def test_vector_prefix_matches_its_array(
        self, name: str, element: dict[str, Any]
    ) -> None:
        for array, metric in _metrics(_validated(element)["cve"]):
            vector = metric["cvssData"]["vectorString"]
            prefix = _CVSS_ARRAY_PREFIXES.get(array)
            if prefix is None:
                assert not vector.startswith("CVSS:")
            else:
                assert vector.startswith(prefix)

    @pytest.mark.parametrize(("name", "element"), _RECORD_PARAMS)
    def test_external_base_reduction_accepts_every_vector(
        self, name: str, element: dict[str, Any]
    ) -> None:
        for array, metric in _metrics(_validated(element)["cve"]):
            parsed = validate_external_cvss_vector(metric["cvssData"]["vectorString"])

            assert parsed.version is _CVSS_ARRAY_VERSIONS[array]

    def test_non_base_v4_vector_reduces_to_its_base_vector(self) -> None:
        """CVSS metrics rule 4: the External Base Reduction keeps the Base
        vector; the strict parser rejects the received one."""
        ((array, metric),) = _metrics(_cve(_V4_NON_BASE_FIXTURE))
        vector = metric["cvssData"]["vectorString"]

        canonical = validate_external_cvss_vector(vector).canonical_vector

        assert array == "cvssMetricV40"
        assert canonical != vector
        assert _metric_keys(vector) > _V4_BASE_METRICS
        assert _metric_keys(canonical) == _V4_BASE_METRICS
        assert len(canonical.split("/")) - 1 == len(_V4_BASE_METRICS)
        with pytest.raises(InvalidCVSSVectorError):
            validate_cvss_vector(vector)

    def test_every_metric_array_is_captured(self) -> None:
        arrays = {
            array
            for _, element in _RECORDS
            for array, _ in _metrics(_validated(element)["cve"])
        }

        assert arrays == set(_CVSS_ARRAY_VERSIONS)

    @pytest.mark.parametrize(("name", "element"), _RECORD_PARAMS)
    def test_no_source_appears_twice_in_one_array(
        self, name: str, element: dict[str, Any]
    ) -> None:
        for metrics in _metric_arrays(_validated(element)["cve"]).values():
            sources = [metric["source"] for metric in metrics]
            assert len(sources) == len(set(sources))

    @pytest.mark.parametrize(
        "name", ["record_deferred_without_metrics", "record_received"]
    )
    def test_empty_metrics_object_is_captured(self, name: str) -> None:
        cve = load_record(name)["cve"]

        assert cve["metrics"] == {}
        assert "weaknesses" not in cve

    def test_unconsumed_cvss_data_members_are_present(self) -> None:
        metrics = load_record("record_analyzed_full")["cve"]["metrics"]
        metric = metrics["cvssMetricV31"][0]

        assert {"version", "baseScore", "baseSeverity"} <= set(metric["cvssData"])
        assert {"exploitabilityScore", "impactScore"} <= set(metric)


@pytest.mark.unit
class TestWeaknesses:
    @pytest.mark.parametrize(("name", "element"), _RECORD_PARAMS)
    def test_weakness_values_are_cwe_ids_or_placeholders(
        self, name: str, element: dict[str, Any]
    ) -> None:
        for weakness in _validated(element)["cve"].get("weaknesses", []):
            for description in weakness["description"]:
                value = description["value"]
                assert _CWE_PATTERN.fullmatch(value) or value in _CWE_PLACEHOLDERS

    @pytest.mark.parametrize(
        ("name", "placeholder"),
        [
            ("record_modified_v2", "NVD-CWE-Other"),
            ("record_cwe_placeholder", "NVD-CWE-noinfo"),
        ],
    )
    def test_placeholder_weakness_is_captured(
        self, name: str, placeholder: str
    ) -> None:
        values = [
            description["value"]
            for weakness in _cve(name).get("weaknesses", [])
            for description in weakness["description"]
        ]

        assert placeholder in values


@pytest.mark.unit
class TestReferences:
    @pytest.mark.parametrize(("name", "element"), _RECORD_PARAMS)
    def test_every_tag_is_in_the_nvd_tag_mapping(
        self, name: str, element: dict[str, Any]
    ) -> None:
        for reference in _validated(element)["cve"]["references"]:
            assert set(reference.get("tags", [])) <= _NVD_REFERENCE_TAGS

    def test_tagged_and_untagged_references_are_captured(self) -> None:
        references = [
            reference
            for _, element in _RECORDS
            for reference in _validated(element)["cve"]["references"]
        ]

        assert any("tags" in reference for reference in references)
        assert any("tags" not in reference for reference in references)


@pytest.mark.unit
class TestSourceIdentity:
    def test_cna_primary_and_nvd_secondary_cvss_are_captured(self) -> None:
        metrics = _metric_arrays(_cve("record_cna_primary_cvss"))

        assert any(
            any(
                m["type"] == "Primary" and m["source"] != NVD_SOURCE_IDENTIFIER
                for m in array
            )
            and any(
                m["type"] == "Secondary" and m["source"] == NVD_SOURCE_IDENTIFIER
                for m in array
            )
            for array in metrics.values()
        )

    def test_cna_primary_and_nvd_secondary_weaknesses_are_captured(self) -> None:
        weaknesses = _cve("record_cna_primary_cwe").get("weaknesses", [])

        assert any(
            w["type"] == "Primary" and w["source"] != NVD_SOURCE_IDENTIFIER
            for w in weaknesses
        )
        assert any(
            w["type"] == "Secondary" and w["source"] == NVD_SOURCE_IDENTIFIER
            for w in weaknesses
        )

    def test_single_query_nvd_weakness_is_secondary(self) -> None:
        weaknesses = _cve(SINGLE_LOG4SHELL).get("weaknesses", [])

        assert [
            w["type"] for w in weaknesses if w["source"] == NVD_SOURCE_IDENTIFIER
        ] == ["Secondary"]

    @pytest.mark.parametrize(("name", "element"), _RECORD_PARAMS)
    def test_every_non_nvd_source_resolves_through_the_source_api(
        self, name: str, element: dict[str, Any]
    ) -> None:
        cache = _source_cache()
        cve = _validated(element)["cve"]
        sources = [metric["source"] for _, metric in _metrics(cve)] + [
            weakness["source"] for weakness in cve.get("weaknesses", [])
        ]

        for source in sources:
            assert source == NVD_SOURCE_IDENTIFIER or source in cache

    def test_reserved_provider_source_resolves_to_suse(self) -> None:
        cache = _source_cache()
        cve = _cve("record_reserved_suse")
        sources = {metric["source"] for _, metric in _metrics(cve)} | {
            weakness["source"] for weakness in cve.get("weaknesses", [])
        }

        assert sources
        for source in sources:
            assert cache[source].strip().casefold() == "suse"


@pytest.mark.unit
class TestCpeConfigurations:
    @pytest.mark.parametrize(("name", "element"), _RECORD_PARAMS)
    def test_criteria_are_admissible_cpe_strings(
        self, name: str, element: dict[str, Any]
    ) -> None:
        for match in _cpe_matches(_validated(element)["cve"]):
            criteria = match["criteria"]
            assert criteria.startswith("cpe:2.3:")
            assert len(criteria) <= _CRITERIA_MAX_LENGTH
            assert "\x00" not in criteria
            criteria.encode("utf-8")

    @pytest.mark.parametrize(("name", "element"), _RECORD_PARAMS)
    def test_match_criteria_ids_are_uppercase_uuids(
        self, name: str, element: dict[str, Any]
    ) -> None:
        for match in _cpe_matches(_validated(element)["cve"]):
            assert _UPPERCASE_UUID.fullmatch(match["matchCriteriaId"])

    @pytest.mark.parametrize(("name", "element"), _RECORD_PARAMS)
    def test_no_level_is_negated(self, name: str, element: dict[str, Any]) -> None:
        for configuration in _validated(element)["cve"].get("configurations", []):
            assert "negate" not in configuration
            for node in configuration["nodes"]:
                assert node["negate"] is False

    @pytest.mark.parametrize(("name", "element"), _RECORD_PARAMS)
    def test_levels_carry_no_nested_or_unknown_member(
        self, name: str, element: dict[str, Any]
    ) -> None:
        for configuration in _raw_configurations(element):
            assert set(configuration) <= _CONFIGURATION_KEYS
            for node in configuration["nodes"]:
                assert set(node) == _NODE_KEYS
                for match in node["cpeMatch"]:
                    assert set(match) <= _CPE_MATCH_KEYS

    @pytest.mark.parametrize(("name", "element"), _RECORD_PARAMS)
    def test_observed_operators_are_and_configurations_and_or_nodes(
        self, name: str, element: dict[str, Any]
    ) -> None:
        for configuration in _raw_configurations(element):
            assert configuration.get("operator", "AND") == "AND"
            for node in configuration["nodes"]:
                assert node["operator"] == "OR"

    @pytest.mark.parametrize("name", _FIRMWARE_ON_HARDWARE_FIXTURES)
    def test_firmware_on_hardware_and_configuration_is_captured(
        self, name: str
    ) -> None:
        assert any(
            _is_firmware_on_hardware(configuration)
            for configuration in _raw_configurations(load_record(name))
        )

    def test_two_firmware_on_hardware_configurations_are_captured(self) -> None:
        configurations = _raw_configurations(
            load_record("record_multiple_configurations")
        )

        assert len(configurations) == 2
        assert all(_is_firmware_on_hardware(c) for c in configurations)

    def test_platform_criteria_is_also_vulnerable_elsewhere(self) -> None:
        matches = _cpe_matches(_cve(SINGLE_PLATFORM_ALSO_VULNERABLE))

        assert sorted(
            m["vulnerable"]
            for m in matches
            if m["criteria"] == _PLATFORM_ALSO_VULNERABLE_CRITERIA
        ) == [False, True]

    def test_one_criteria_repeats_with_different_version_ranges(self) -> None:
        ranges: dict[str, list[tuple[tuple[str, Any], ...]]] = {}
        for configuration in _raw_configurations(load_record(SINGLE_LOG4SHELL)):
            for node in configuration["nodes"]:
                for match in node["cpeMatch"]:
                    ranges.setdefault(match["criteria"], []).append(
                        tuple(sorted((k, match[k]) for k in _RANGE_KEYS & set(match)))
                    )

        assert any(
            len(found) > 1 and len(set(found)) == len(found)
            for found in ranges.values()
        )

    def test_escaped_criteria_is_captured(self) -> None:
        criteria = [
            m["criteria"] for m in _cpe_matches(_cve("record_escaped_criteria"))
        ]

        assert any("\\/" in value for value in criteria)

    def test_records_without_configurations_are_the_recorded_ones(self) -> None:
        without = {
            name for name, element in _RECORDS if "configurations" not in element["cve"]
        }
        with_configurations = {
            name for name, element in _RECORDS if "configurations" in element["cve"]
        }

        assert without == _WITHOUT_CONFIGURATIONS
        assert with_configurations.isdisjoint(_WITHOUT_CONFIGURATIONS)


@pytest.mark.unit
class TestIgnoredMembers:
    """The members of § Explicitly ignored fields appear as served, so the
    mapping must tolerate them."""

    @pytest.mark.parametrize(("name", "element"), _RECORD_PARAMS)
    def test_source_identifier_and_cve_tags_are_present(
        self, name: str, element: dict[str, Any]
    ) -> None:
        cve = element["cve"]

        assert isinstance(cve["sourceIdentifier"], str)
        assert isinstance(cve["cveTags"], list)

    @pytest.mark.parametrize(("name", "element"), _RECORD_PARAMS)
    def test_affected_is_present_on_every_non_rejected_record(
        self, name: str, element: dict[str, Any]
    ) -> None:
        cve = element["cve"]

        assert ("affected" in cve) is (cve["vulnStatus"] != "Rejected")

    @pytest.mark.parametrize("name", _SSVC_FIXTURES)
    def test_ssvc_metrics_member_is_present(self, name: str) -> None:
        assert isinstance(load_record(name)["cve"]["metrics"]["ssvcV203"], list)

    def test_cisa_members_are_present_on_the_single_query(self) -> None:
        assert set(load_record(SINGLE_LOG4SHELL)["cve"]) >= _CISA_MEMBERS

    def test_cve_tags_with_a_tag_are_captured(self) -> None:
        tags = load_record("record_cna_primary_cvss")["cve"]["cveTags"]

        assert tags[0]["tags"] == ["exclusively-hosted-service"]


@pytest.mark.unit
class TestSourceApi:
    def test_source_body_is_a_json_object(self) -> None:
        assert isinstance(json.loads(load_raw_fixture(SOURCE_PAGE)), dict)

    def test_consumed_fields_validate_strictly_without_coercion(self) -> None:
        body = load_json_fixture(SOURCE_PAGE)

        validated = _validated_source_page(body)

        assert validated == _project(body, validated)

    def test_unconsumed_envelope_members_have_their_live_shape(self) -> None:
        body = load_json_fixture(SOURCE_PAGE)

        assert body["format"] == "NVD_SOURCE"
        assert body["version"] == "2.0"
        assert body["startIndex"] == 0
        assert re.fullmatch(_TIMESTAMP, body["timestamp"])

    def test_single_page_guard_is_not_triggered(self) -> None:
        page = _validated_source_page(load_json_fixture(SOURCE_PAGE))

        assert page["totalResults"] == page["resultsPerPage"]

    def test_names_are_trimmed_bounded_and_non_blank(self) -> None:
        for source in _validated_source_page(load_json_fixture(SOURCE_PAGE))["sources"]:
            name = source["name"]
            assert name
            assert name == name.strip()
            assert len(name) <= _SOURCE_NAME_MAX_LENGTH

    def test_nvd_identifier_is_the_only_identifier_of_nist(self) -> None:
        sources = _validated_source_page(load_json_fixture(SOURCE_PAGE))["sources"]

        assert [s["sourceIdentifiers"] for s in sources if s["name"] == "NIST"] == [
            [NVD_SOURCE_IDENTIFIER]
        ]
        assert [
            s["name"]
            for s in sources
            if NVD_SOURCE_IDENTIFIER in s["sourceIdentifiers"]
        ] == ["NIST"]

    def test_reserved_suse_source_exists(self) -> None:
        sources = _validated_source_page(load_json_fixture(SOURCE_PAGE))["sources"]

        assert "SUSE" in {source["name"] for source in sources}

    def test_cisa_adp_identifier_resolves_to_cisa_adp(self) -> None:
        assert _source_cache()[CISA_ADP_SOURCE_IDENTIFIER] == "CISA-ADP"

    def test_source_with_several_identifiers_is_captured(self) -> None:
        sources = _validated_source_page(load_json_fixture(SOURCE_PAGE))["sources"]

        assert any(len(source["sourceIdentifiers"]) > 1 for source in sources)


@pytest.mark.unit
class TestSanitization:
    def test_fixture_directory_holds_exactly_the_declared_fixtures(self) -> None:
        assert {path.name for path in FIXTURE_DIR.iterdir()} == {
            f"{name}.json" for name in _ALL_FIXTURES
        }

    @pytest.mark.parametrize("name", _ALL_FIXTURES)
    def test_emails_are_nvd_or_fictional(self, name: str) -> None:
        for match in _EMAIL.finditer(load_raw_fixture(name)):
            email = match.group(0)
            assert email == NVD_SOURCE_IDENTIFIER.encode() or email.endswith(
                _FICTIONAL_DOMAIN
            )

    def test_contact_emails_are_fictional(self) -> None:
        for source in load_json_fixture(SOURCE_PAGE)["sources"]:
            assert _FICTIONAL_CONTACT.fullmatch(source["contactEmail"])

    @pytest.mark.parametrize("name", _CVE_FIXTURES)
    def test_record_emails_are_nvd_known_sources_or_unknown(self, name: str) -> None:
        known = {identifier.encode() for identifier in _source_cache()}

        for match in _EMAIL.finditer(load_raw_fixture(name)):
            email = match.group(0)
            assert (
                email == NVD_SOURCE_IDENTIFIER.encode()
                or email in known
                or _FICTIONAL_UNKNOWN.fullmatch(email)
            )

    @pytest.mark.parametrize(("name", "element"), _RECORD_PARAMS)
    def test_descriptions_are_fictional(
        self, name: str, element: dict[str, Any]
    ) -> None:
        cve = element["cve"]
        cve_id = cve["id"]
        english = (
            f"Rejected reason: fictional rejection note for {cve_id}."
            if cve["vulnStatus"] == "Rejected"
            else f"Fictional description of {cve_id}."
        )
        expected = {"en": english, "es": f"Descripción ficticia de {cve_id}."}

        for description in cve["descriptions"]:
            assert description["value"] == expected[description["lang"]]

    @pytest.mark.parametrize(("name", "element"), _RECORD_PARAMS)
    def test_reference_urls_are_fictional(
        self, name: str, element: dict[str, Any]
    ) -> None:
        for reference in element["cve"]["references"]:
            assert _FICTIONAL_UPSTREAM.fullmatch(reference["url"])

    @pytest.mark.parametrize("name", _ALL_FIXTURES)
    def test_no_fixture_contains_nul(self, name: str) -> None:
        raw = load_raw_fixture(name)

        assert b"\\u0000" not in raw
        assert b"\x00" not in raw
        assert all("\x00" not in s for s in _strings(json.loads(raw)))
