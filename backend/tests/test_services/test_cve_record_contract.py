"""Contract tests for CVE Record Format 5.x as served by `cvelistV5` and
the kernel `vulns.git`.

Contract under test: docs/features/platform/cve-record-parser.md (Input
Validation, External String Admissibility, every parser function, What
Remains Source-Specific, Schema Version Handling) and the payload bounds of
`app/services/cve_ingest.py` (`AffectedVersionEntry`, `CWEEntry`,
`SSVCEntry`, `KEVEntry`, `CVEIngestPayload.title`), verified against
sanitized live records (docs/conventions.md, External Integration Contract
Verification; captures documented in `tests/support/cve_record.py`). Every
consumed field is asserted for name, nesting, type, and nullability through
a strict test-local typed model; no production parser exists yet, and the
model is independent of the one it will define.

Live verification on 2026-10-08, full scans of both repositories:

- `vulns.git` (`master` `e65245d833add2ba0bda9658cba6581a4ad7a71b`): all
  17,644 records under `cve/published/` and `cve/rejected/`. `dataVersion`
  5.1.1 in 17,352, 5.0 in 291, 5.1 in 1. `cveId` in 17,353 and the legacy
  `cveID` in the other 291, all of them 5.0. `state` is always PUBLISHED,
  also in the 317 files under `rejected/`. No record has `datePublished`,
  `dateUpdated`, `dateRejected`, `providerMetadata.shortName`, or `adp`.
  `descriptions` is always one `en` entry; `title` is present in 17,643.
  `metrics` (6,427 records) holds only `cvssV3_1`, every vector a strict
  Base vector. `problemTypes` occurs in 1 record, whose description has
  neither `type` nor `cweId`. `versionType` is one of `semver`, `git`,
  `original_commit_for_fix`, `custom` (absent in 17,282 versions); version
  `status` and `defaultStatus` are `affected` or `unaffected`; 19 elements
  have no `versions`.
- `cvelistV5` (release `cve_2026-10-08_1400Z`): all 402,861 records under
  `cves/`. `dataVersion` 5.1 in 259,039, 5.2 in 129,764, 5.0 in 14,058 (all
  with `rejectedReasons`); always `cveId`, matching the file name. `state`
  PUBLISHED in 384,424 and REJECTED in 18,437. `dateUpdated` is always
  `YYYY-MM-DDTHH:MM:SS.fffZ`; so is `datePublished`, except 2 without offset
  or fraction and 6,283 absent; `dateRejected` is present in 18,436 (one
  REJECTED record has none). Description languages: `en`, `en-US`, `en` and
  `de`, `en` and `es` (always an English entry). `versionType` is an open
  set (`custom`, `semver`, `git`, `rpm`, `original_commit_for_fix`,
  `maven`, ...; at most 128 characters). Version `status` is `affected`,
  `unaffected`, or `unknown`; `defaultStatus` likewise. 161,346 elements
  have an `n/a` vendor or product; 144,340 have both and no package
  coordinate; 925 have neither vendor nor product but `packageName` and
  `collectionURL`. Versions: `n/a` 154,582; the other placeholder versions
  `-` 2,242, uppercase `N/A` 1,265, and `NA` 69, and the vendor `N/A` 29,
  are not sentinels under the specification and are stored as received. 204
  `cpes` arrays are empty; no `versions` array is.
- `cvelistV5` vectors: every `cvssV2_0`, `cvssV3_0`, `cvssV3_1`, and
  `cvssV4_0` `vectorString` is a string and either a strict Base vector or
  reduced by `validate_external_cvss_vector` (v2.0 9,229, v3.0 11,554,
  v3.1 20,057, v4.0 11,909 reduced; none rejected). Keys coexist in one
  `metrics` entry (`cvssV4_0` with `cvssV3_1` 584 times, ...), and the same
  key repeats within one `metrics` array (`cvssV4_0` in 68 records,
  `cvssV3_1` in 62).
- CISA-ADP: 195,907 containers; 195,906 carry exactly one `other.type`
  `ssvc` entry and one (CVE-2013-3735) has `metrics` without one. The
  `options` are always the single-key objects `Exploitation`,
  `Automatable`, `Technical Impact`, `version` always `2.0.3`, `timestamp`
  always `YYYY-MM-DDTHH:MM:SS.ffffffZ` (190,257) or `...+00:00` (5,649).
  `kev` occurs at most once per container (1,734), `dateAdded` always
  `YYYY-MM-DD`, `reference` always a string of at most 87 characters.
- `cweId` is always a string matching `^CWE-[1-9][0-9]*$` (at most 8
  characters). Problem-type `type` values include `CWE`, `cwe` (1,515 with a
  `cweId`), `text`, and absent (3,418 with a `cweId`). ADP short names: `CVE`,
  `CISA-ADP`, `siemens-SADP`, `redhat-SADP`. The CNA short name is absent in
  12 records. `title` is at most 256 characters, a description at most
  3,998.
- No string in either repository contains U+0000, and no consumed string
  exceeds its payload bound (`versionType` reaches exactly 128).

Every consumed field was observed live in at least one repository; none is
documentation-only.

Not observable live, and therefore covered by the parser unit tests only:
U+0000 in any string; over-bound values; a `null`, non-string, or
non-list value of a consumed field; an empty-string vendor, product, or
version; both `lessThan` and `lessThanOrEqual` on one version; an empty
`versions` array; a description list without an English entry; a JSON
CVE-ID that mismatches its file name; an invalid `cweId`; an invalid SSVC
enum value; an incomplete SSVC or one without `timestamp`; more than one
SSVC or KEV entry in a CISA-ADP container; a KEV `dateAdded` date-time; a
vector rejected by the External Base Reduction; and an unrecognized state
such as RESERVED.
"""

from __future__ import annotations

import copy
import re
from datetime import date, datetime, timedelta
from typing import Any, Literal, Self
from urllib.parse import urlsplit

import pytest
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from app.core.enums import (
    CVSSVersion,
    SSVCAutomatable,
    SSVCExploitation,
    SSVCTechnicalImpact,
)
from app.services.cve_ingest import (
    AffectedVersionEntry,
    CVEIngestPayload,
    CWEEntry,
    KEVEntry,
    SSVCEntry,
)
from app.services.cvss import (
    EXTERNAL_VECTOR_MAX_LENGTH,
    validate_cvss_vector,
    validate_external_cvss_vector,
)
from app.services.ticket_mutations_errors import InvalidCVSSVectorError
from tests.support.cve_record import (
    ALL_FIXTURES,
    CVELISTV5_FIXTURES,
    FIXTURE_SOURCES,
    VULNS_FIXTURES,
    load_fixture,
    load_raw_fixture,
    source_cve_id,
)

pytestmark = pytest.mark.unit

# parse_cwe_classifications step 2.
_CWE_PATTERN = re.compile(r"^CWE-[1-9][0-9]*$")
_MILLISECOND_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")
_MICROSECOND_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$")
_OFFSET_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\+00:00$")
_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_CVSS_KEYS: dict[str, CVSSVersion] = {
    "cvssV4_0": CVSSVersion.V4_0,
    "cvssV3_1": CVSSVersion.V3_1,
    "cvssV3_0": CVSSVersion.V3_0,
    "cvssV2_0": CVSSVersion.V2_0,
}
"""The vector keys in `parse_cvss_assessments` traversal order."""
_SSVC_KEYS = ["Exploitation", "Automatable", "Technical Impact"]
_ADP_SHORT_NAMES = frozenset({"CVE", "CISA-ADP", "siemens-SADP", "redhat-SADP"})
_KERNEL_VERSION_TYPES = frozenset(
    {"semver", "git", "original_commit_for_fix", "custom"}
)
_STATUSES = frozenset({"affected", "unaffected", "unknown"})

_REJECTED_FIXTURES = {
    "cvelistv5_5_0_rejected_legacy": True,
    "cvelistv5_5_2_rejected": True,
    "cvelistv5_5_1_rejected_without_date_rejected": False,
}
"""REJECTED `cvelistV5` fixtures → whether `dateRejected` is present."""
_NAIVE_FIXTURE = "cvelistv5_naive_date_published"
_KERNEL_REJECTED_DIRECTORY = (
    "vulns_rejected_5_0_legacy_cve_id",
    "vulns_rejected_5_1_problem_types",
)

_NON_BASE_VECTORS = {
    ("cvelistv5_v4_supplemental_non_base", "cvssV4_0"): (
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:L/VI:N/VA:N/SC:L/SI:N/SA:N/RE:M/U:Clear",
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:L/VI:N/VA:N/SC:L/SI:N/SA:N",
    ),
    ("cvelistv5_v3_1_non_base_en_us_kev", "cvssV3_1"): (
        "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N/E:U/RL:O/RC:C",
        "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N",
    ),
    ("cvelistv5_v3_0_non_base_unordered", "cvssV3_0"): (
        "CVSS:3.0/AV:P/C:L/I:L/S:U/AC:L/A:L/UI:N/PR:N/RL:O/RC:C/E:U",
        "CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L",
    ),
    ("cvelistv5_empty_cpes", "cvssV3_1"): (
        "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:L/A:N/E:P/RL:U/RC:C",
        "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:L/A:N",
    ),
    ("cvelistv5_all_cvss_keys_non_base", "cvssV4_0"): (
        "CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N/E:X",
        "CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N",
    ),
    ("cvelistv5_all_cvss_keys_non_base", "cvssV3_1"): (
        "CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L/E:X/RL:O/RC:C",
        "CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L",
    ),
    ("cvelistv5_all_cvss_keys_non_base", "cvssV3_0"): (
        "CVSS:3.0/AV:A/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L/E:X/RL:O/RC:C",
        "CVSS:3.0/AV:A/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L",
    ),
    ("cvelistv5_all_cvss_keys_non_base", "cvssV2_0"): (
        "AV:A/AC:M/Au:S/C:P/I:P/A:P/E:ND/RL:OF/RC:C",
        "AV:A/AC:M/Au:S/C:P/I:P/A:P",
    ),
}
"""(fixture, key) → (received vector, canonical Base vector of the External
Base Reduction) for every non-Base vector of the fixture set."""

_FICTIONAL_DESCRIPTION_PREFIXES = (
    "Fictional description of ",
    "Fictional ADP description of ",
    "Fiktive Beschreibung von ",
    "In the Linux kernel, the following vulnerability has been resolved:\n\n"
    "example: fictional subject of ",
)
_FICTIONAL_TITLE_PREFIXES = ("Fictional title of ", "example: fictional title of ")
_KEPT_ADP_TITLES = frozenset({"CISA ADP Vulnrichment", "CVE Program Container"})
_FICTIONAL_UPSTREAM = re.compile(r"https://advisory\.example\.invalid/upstream/[0-9]+")
_FICTIONAL_HOSTS = frozenset({"advisory.example.invalid", "github.example.invalid"})
_KEPT_HOSTS = frozenset(
    {
        "access.redhat.com",
        "blog.exodusintel.com",
        "blogs.technet.com",
        "bugzilla.redhat.com",
        "cpan.org",
        "docs.microsoft.com",
        "docs.suitecrm.com",
        "exchange.xforce.ibmcloud.com",
        "fortiguard.com",
        "git.kernel.org",
        "msrc.microsoft.com",
        "pkg.go.dev",
        "portal.microfocus.com",
        "rt.cpan.org",
        "sec.cloudapps.cisco.com",
        "security.access.redhat.com",
        "vuldb.com",
        "www.binarly.io",
        "www.cisa.gov",
        "www.cve.org",
        "www.debian.org",
        "www.ibm.com",
        "www.jenkins.io",
        "www.jetbrains.com",
        "www.kernel.org",
        "www.redhat.com",
        "www.securityfocus.com",
        "www.securitytracker.com",
        "www.virustotal.com",
        "www.vulncheck.com",
        "www.zerodayinitiative.com",
    }
)
"""Organisation, vendor, project, and advisory-database hosts whose URLs are
retained."""
_KEPT_GITHUB_OWNERS = frozenset(
    {"cpan-authors", "SuiteCRM", "temporalio", "tukaani-project"}
)
"""`github.com` path owners (project organisations) whose URLs are retained."""
_KERNEL_STABLE_PATHS = ("/stable/c/", "/pub/scm/linux/kernel/git/stable/")
_FICTIONAL_EMAIL_DOMAINS = frozenset({b"example.invalid", b"example.com"})
_EMAIL = re.compile(rb"[A-Za-z0-9._%+-]+@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)")


# ---------------------------------------------------------------------------
# Strict test-local typed model of the consumed CVE Record fields
# ---------------------------------------------------------------------------


class _Consumed(BaseModel):
    """No coercion; an optional field is optional by absence only and is
    never `null` when present (as observed live). Unconsumed fields are
    ignored."""

    model_config = ConfigDict(strict=True, extra="ignore", frozen=True)

    @model_validator(mode="before")
    @classmethod
    def _reject_present_null(cls, data: Any) -> Any:
        if isinstance(data, dict):
            for name, field in cls.model_fields.items():
                key = field.alias or name
                if key in data and data[key] is None:
                    raise ValueError(f"{key} is null")
        return data


class _CveMetadata(_Consumed):
    cve_id: str | None = Field(None, alias="cveId")
    legacy_cve_id: str | None = Field(None, alias="cveID")
    state: Literal["PUBLISHED", "REJECTED"]
    date_published: str | None = Field(None, alias="datePublished")
    date_updated: str | None = Field(None, alias="dateUpdated")
    date_rejected: str | None = Field(None, alias="dateRejected")

    @model_validator(mode="after")
    def _one_cve_id_key(self) -> Self:
        if (self.cve_id is None) == (self.legacy_cve_id is None):
            raise ValueError("exactly one of cveId and cveID is expected")
        return self


class _Description(_Consumed):
    lang: str
    value: str


class _ProviderMetadata(_Consumed):
    short_name: str | None = Field(None, alias="shortName")


class _Version(_Consumed):
    version: str
    status: str
    version_type: str | None = Field(None, alias="versionType")
    less_than: str | None = Field(None, alias="lessThan")
    less_than_or_equal: str | None = Field(None, alias="lessThanOrEqual")


class _Affected(_Consumed):
    vendor: str | None = None
    product: str | None = None
    repo: str | None = None
    package_url: str | None = Field(None, alias="packageURL")
    collection_url: str | None = Field(None, alias="collectionURL")
    package_name: str | None = Field(None, alias="packageName")
    default_status: str | None = Field(None, alias="defaultStatus")
    cpes: list[str] | None = None
    program_files: list[str] | None = Field(None, alias="programFiles")
    versions: list[_Version] | None = None


class _Vector(_Consumed):
    vector_string: str = Field(alias="vectorString")


class _Other(_Consumed):
    type: str
    content: dict[str, Any]


class _Metric(_Consumed):
    cvss_v4_0: _Vector | None = Field(None, alias="cvssV4_0")
    cvss_v3_1: _Vector | None = Field(None, alias="cvssV3_1")
    cvss_v3_0: _Vector | None = Field(None, alias="cvssV3_0")
    cvss_v2_0: _Vector | None = Field(None, alias="cvssV2_0")
    other: _Other | None = None

    def vectors(self) -> list[tuple[str, str]]:
        """(key, vectorString) of each present CVSS key, in traversal order."""
        present = {
            "cvssV4_0": self.cvss_v4_0,
            "cvssV3_1": self.cvss_v3_1,
            "cvssV3_0": self.cvss_v3_0,
            "cvssV2_0": self.cvss_v2_0,
        }
        return [(k, v.vector_string) for k, v in present.items() if v is not None]


class _ProblemTypeDescription(_Consumed):
    type: str | None = None
    cwe_id: str | None = Field(None, alias="cweId")


class _ProblemType(_Consumed):
    descriptions: list[_ProblemTypeDescription]


class _Cna(_Consumed):
    provider_metadata: _ProviderMetadata = Field(alias="providerMetadata")
    title: str | None = None
    descriptions: list[_Description] | None = None
    affected: list[_Affected] | None = None
    metrics: list[_Metric] | None = None
    problem_types: list[_ProblemType] | None = Field(None, alias="problemTypes")


class _Adp(_Consumed):
    provider_metadata: _ProviderMetadata = Field(alias="providerMetadata")
    affected: list[_Affected] | None = None
    metrics: list[_Metric] | None = None
    problem_types: list[_ProblemType] | None = Field(None, alias="problemTypes")


class _Containers(_Consumed):
    cna: _Cna
    adp: list[_Adp] | None = None


class _Record(_Consumed):
    data_version: Literal["5.0", "5.1", "5.1.1", "5.2"] = Field(alias="dataVersion")
    cve_metadata: _CveMetadata = Field(alias="cveMetadata")
    containers: _Containers


class _SSVCContent(_Consumed):
    """`other.content` of a CISA-ADP `ssvc` entry (parse_ssvc_assessment)."""

    options: list[dict[str, str]]
    version: str
    timestamp: str


class _KEVContent(_Consumed):
    """`other.content` of a CISA-ADP `kev` entry (parse_kev_data)."""

    date_added: str = Field(alias="dateAdded")
    reference: str


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _record(name: str) -> _Record:
    return _Record.model_validate(load_fixture(name))


def _project(raw: Any, validated: Any) -> Any:
    """`raw` restricted to the keys the typed model consumes."""
    if isinstance(validated, dict):
        return {key: _project(raw[key], value) for key, value in validated.items()}
    if isinstance(validated, list):
        return [_project(r, v) for r, v in zip(raw, validated, strict=True)]
    return raw


def _with(name: str, path: tuple[str | int, ...], value: Any) -> dict[str, Any]:
    """A deep copy of fixture `name` with the member at `path` set to
    `value`."""
    record = copy.deepcopy(load_fixture(name))
    target: Any = record
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    return record


def _cve_id(record: _Record) -> str:
    cve_id = record.cve_metadata.cve_id or record.cve_metadata.legacy_cve_id
    assert cve_id is not None
    return cve_id


def _containers(record: _Record) -> list[_Cna | _Adp]:
    return [record.containers.cna, *(record.containers.adp or [])]


def _affected(name: str) -> list[_Affected]:
    return [e for c in _containers(_record(name)) for e in c.affected or []]


def _versions(name: str) -> list[_Version]:
    return [v for e in _affected(name) for v in e.versions or []]


def _vectors(name: str) -> list[tuple[str, str]]:
    """(key, vectorString) of every CVSS vector of every container."""
    return [
        vector
        for c in _containers(_record(name))
        for m in c.metrics or []
        for vector in m.vectors()
    ]


def _other_entries(container: _Cna | _Adp, type_: str) -> list[_Other]:
    return [
        m.other
        for m in container.metrics or []
        if m.other is not None and m.other.type == type_
    ]


def _cisa_adp(name: str) -> _Adp | None:
    matches = [
        adp
        for adp in _record(name).containers.adp or []
        if adp.provider_metadata.short_name == "CISA-ADP"
    ]
    assert len(matches) <= 1
    return matches[0] if matches else None


def _cisa_adp_fixtures() -> list[str]:
    return [name for name in ALL_FIXTURES if _cisa_adp(name) is not None]


def _problem_type_descriptions(name: str) -> list[_ProblemTypeDescription]:
    return [
        d
        for c in _containers(_record(name))
        for p in c.problem_types or []
        for d in p.descriptions
    ]


def _max_length(model: type[BaseModel], field: str) -> int | None:
    for metadata in model.model_fields[field].metadata:
        max_length = getattr(metadata, "max_length", None)
        if max_length is not None:
            assert isinstance(max_length, int)
            return max_length
    return None


def _consumed_strings(record: _Record) -> list[tuple[str, str, int | None]]:
    """(label, value, payload bound or None) of every consumed string."""
    found: list[tuple[str, str, int | None]] = []

    def add(label: str, value: str | None, bound: int | None) -> None:
        if value is not None:
            found.append((label, value, bound))

    def entry(field: str) -> int | None:
        return _max_length(AffectedVersionEntry, field)

    md = record.cve_metadata
    for label, value in (
        ("cveId", md.cve_id),
        ("cveID", md.legacy_cve_id),
        ("state", md.state),
        ("datePublished", md.date_published),
        ("dateUpdated", md.date_updated),
        ("dateRejected", md.date_rejected),
    ):
        add(label, value, None)
    cna = record.containers.cna
    add("title", cna.title, _max_length(CVEIngestPayload, "title"))
    for d in cna.descriptions or []:
        add("descriptions[].value", d.value, None)
    for c in _containers(record):
        add("providerMetadata.shortName", c.provider_metadata.short_name, None)
        for e in c.affected or []:
            add("vendor", e.vendor, entry("vendor"))
            add("product", e.product, entry("product"))
            add("repo", e.repo, entry("repo"))
            add("packageURL", e.package_url, entry("package_url"))
            add("collectionURL", e.collection_url, entry("collection_url"))
            add("packageName", e.package_name, entry("package_name"))
            add("defaultStatus", e.default_status, entry("default_status"))
            for cpe in e.cpes or []:
                add("cpes[]", cpe, entry("cpe"))
            for path in e.program_files or []:
                add("programFiles[]", path, None)
            for v in e.versions or []:
                add("version", v.version, entry("version"))
                add("versionType", v.version_type, entry("version_type"))
                add("lessThan", v.less_than, entry("version_end"))
                add("lessThanOrEqual", v.less_than_or_equal, entry("version_end"))
                add("status", v.status, entry("status"))
        for m in c.metrics or []:
            for _, vector in m.vectors():
                add("vectorString", vector, EXTERNAL_VECTOR_MAX_LENGTH)
        for p in c.problem_types or []:
            for problem in p.descriptions:
                add("cweId", problem.cwe_id, _max_length(CWEEntry, "cwe_id"))
        if isinstance(c, _Adp) and c.provider_metadata.short_name == "CISA-ADP":
            for ssvc in _other_entries(c, "ssvc"):
                content = _SSVCContent.model_validate(ssvc.content)
                for option in content.options:
                    for value in option.values():
                        add("ssvc options[]", value, None)
                add("ssvc version", content.version, _max_length(SSVCEntry, "version"))
                add("ssvc timestamp", content.timestamp, None)
            for kev in _other_entries(c, "kev"):
                kev_content = _KEVContent.model_validate(kev.content)
                add("kev dateAdded", kev_content.date_added, None)
                add(
                    "kev reference",
                    kev_content.reference,
                    _max_length(KEVEntry, "reference_url"),
                )
    return found


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


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestTypedRecord:
    @pytest.mark.parametrize("name", ALL_FIXTURES)
    def test_consumed_fields_validate_strictly_without_coercion(
        self, name: str
    ) -> None:
        raw = load_fixture(name)

        dumped = _Record.model_validate(raw).model_dump(
            by_alias=True, exclude_unset=True
        )

        assert dumped == _project(raw, dumped)

    @pytest.mark.parametrize(
        ("path", "value"),
        [
            (("dataVersion",), "5.3"),
            (("cveMetadata", "cveId"), 2026),
            (("cveMetadata", "state"), None),
            (("cveMetadata", "state"), "RESERVED"),
            (("cveMetadata", "datePublished"), None),
            (("containers", "cna", "providerMetadata", "shortName"), None),
            (("containers", "cna", "title"), None),
            (("containers", "cna", "descriptions"), "Fictional"),
            (("containers", "cna", "descriptions", 0, "value"), None),
            (("containers", "cna", "affected", 0, "vendor"), 1),
            (("containers", "cna", "affected", 0, "programFiles"), "comments.go"),
            (("containers", "cna", "affected", 0, "programFiles"), [1]),
            (("containers", "cna", "affected", 1, "cpes"), "cpe:2.3:a:x:y"),
            (("containers", "cna", "affected", 0, "versions"), None),
            (("containers", "cna", "affected", 0, "versions", 0, "lessThan"), None),
            (("containers", "cna", "affected", 0, "versions", 0, "status"), None),
            (("containers", "cna", "metrics", 0, "cvssV4_0", "vectorString"), None),
            (("containers", "cna", "problemTypes", 0, "descriptions", 0, "cweId"), 129),
            (("containers", "adp", 0, "providerMetadata"), None),
            (("containers", "adp", 0, "metrics", 0, "other", "content"), []),
        ],
    )
    def test_typed_model_rejects_a_null_or_mistyped_consumed_field(
        self, path: tuple[str | int, ...], value: Any
    ) -> None:
        """Guards the strictness the fixture assertions rely on."""
        with pytest.raises(ValidationError):
            _Record.model_validate(_with("cvelistv5_repeated_cvss_v4", path, value))

    @pytest.mark.parametrize(
        "metadata",
        [
            {"state": "PUBLISHED"},
            {
                "cveId": "CVE-2026-16651",
                "cveID": "CVE-2026-16651",
                "state": "PUBLISHED",
            },
        ],
    )
    def test_typed_model_requires_exactly_one_cve_id_key(
        self, metadata: dict[str, Any]
    ) -> None:
        with pytest.raises(ValidationError):
            _CveMetadata.model_validate(metadata)


class TestSchemaVersions:
    def test_cvelistv5_fixtures_cover_its_data_versions(self) -> None:
        versions = {_record(name).data_version for name in CVELISTV5_FIXTURES}

        assert versions == {"5.0", "5.1", "5.2"}

    def test_vulns_fixtures_cover_its_data_versions(self) -> None:
        versions = {_record(name).data_version for name in VULNS_FIXTURES}

        assert versions == {"5.0", "5.1", "5.1.1"}


class TestCveMetadata:
    @pytest.mark.parametrize("name", ALL_FIXTURES)
    def test_json_cve_id_matches_the_source_file_name(self, name: str) -> None:
        assert _cve_id(_record(name)) == source_cve_id(name)

    def test_legacy_cve_id_key_occurs_only_in_the_kernel_5_0_record(self) -> None:
        legacy = {
            name
            for name in ALL_FIXTURES
            if _record(name).cve_metadata.legacy_cve_id is not None
        }

        assert legacy == {"vulns_rejected_5_0_legacy_cve_id"}
        assert _record("vulns_rejected_5_0_legacy_cve_id").data_version == "5.0"

    @pytest.mark.parametrize("name", VULNS_FIXTURES)
    def test_kernel_record_has_no_dates_short_name_or_adp(self, name: str) -> None:
        record = _record(name)
        md = record.cve_metadata

        assert md.date_published is None
        assert md.date_updated is None
        assert md.date_rejected is None
        assert record.containers.cna.provider_metadata.short_name is None
        assert record.containers.adp is None

    @pytest.mark.parametrize("name", _KERNEL_REJECTED_DIRECTORY)
    def test_kernel_record_in_rejected_directory_says_published(
        self, name: str
    ) -> None:
        """What Remains Source-Specific: the kernel fetcher overrides the
        JSON state with REJECTED from the directory."""
        assert FIXTURE_SOURCES[name].startswith("cve/rejected/")
        assert _record(name).cve_metadata.state == "PUBLISHED"

    @pytest.mark.parametrize("name", VULNS_FIXTURES)
    def test_kernel_state_is_always_published(self, name: str) -> None:
        assert _record(name).cve_metadata.state == "PUBLISHED"

    @pytest.mark.parametrize(
        ("name", "has_date_rejected"), list(_REJECTED_FIXTURES.items())
    )
    def test_rejected_record_carries_date_rejected_or_not(
        self, name: str, has_date_rejected: bool
    ) -> None:
        md = _record(name).cve_metadata

        assert md.state == "REJECTED"
        assert (md.date_rejected is not None) is has_date_rejected

    @pytest.mark.parametrize("name", list(_REJECTED_FIXTURES))
    def test_rejected_record_has_only_rejected_reasons(self, name: str) -> None:
        """Schema Version Handling: `rejectedReasons` instead of `affected`
        and `metrics`."""
        containers = load_fixture(name)["containers"]

        assert set(containers) == {"cna"}
        assert set(containers["cna"]) == {"providerMetadata", "rejectedReasons"}

    def test_legacy_5_0_record_is_rejected(self) -> None:
        assert _record("cvelistv5_5_0_rejected_legacy").data_version == "5.0"

    @pytest.mark.parametrize(
        "name",
        [n for n in ALL_FIXTURES if _record(n).cve_metadata.state == "PUBLISHED"],
    )
    def test_published_record_has_no_date_rejected(self, name: str) -> None:
        assert _record(name).cve_metadata.date_rejected is None

    def test_rejected_record_without_date_published_is_captured(self) -> None:
        assert _record("cvelistv5_5_2_rejected").cve_metadata.date_published is None


class TestDates:
    @pytest.mark.parametrize(
        "name", [n for n in CVELISTV5_FIXTURES if n != _NAIVE_FIXTURE]
    )
    def test_cvelistv5_dates_are_millisecond_utc_date_times(self, name: str) -> None:
        md = _record(name).cve_metadata
        dates = [md.date_published, md.date_updated, md.date_rejected]
        present = [value for value in dates if value is not None]

        assert md.date_updated is not None
        for value in present:
            assert _MILLISECOND_UTC.fullmatch(value)
            assert datetime.fromisoformat(value).utcoffset() == timedelta(0)

    def test_date_published_without_offset_or_fraction_is_captured(self) -> None:
        md = _record(_NAIVE_FIXTURE).cve_metadata

        assert md.date_published == "2022-09-05T09:50:10"
        assert datetime.fromisoformat(md.date_published).tzinfo is None
        assert md.date_updated == "2024-08-03T10:54:03.893Z"


class TestDescriptionsAndTitle:
    def test_description_languages_of_the_capture_are_represented(self) -> None:
        languages = {
            tuple(d.lang for d in _record(name).containers.cna.descriptions or [])
            for name in ALL_FIXTURES
        }

        assert languages == {(), ("en",), ("en-US",), ("en", "de")}

    @pytest.mark.parametrize(
        "name",
        [n for n in ALL_FIXTURES if _record(n).cve_metadata.state == "PUBLISHED"],
    )
    def test_published_record_has_an_english_description(self, name: str) -> None:
        descriptions = _record(name).containers.cna.descriptions

        assert descriptions
        assert any(d.lang.startswith("en") for d in descriptions)

    @pytest.mark.parametrize("name", VULNS_FIXTURES)
    def test_kernel_record_has_exactly_one_en_description(self, name: str) -> None:
        descriptions = _record(name).containers.cna.descriptions

        assert descriptions is not None
        assert [d.lang for d in descriptions] == ["en"]

    @pytest.mark.parametrize(
        "name", ["cvelistv5_5_2_package_only_affected", "cvelistv5_lowercase_cwe_type"]
    )
    def test_crlf_description_is_captured(self, name: str) -> None:
        descriptions = _record(name).containers.cna.descriptions

        assert descriptions is not None
        assert "\r\n" in descriptions[0].value

    def test_kernel_record_without_title_is_captured(self) -> None:
        assert _record("vulns_rejected_5_1_problem_types").containers.cna.title is None

    def test_cvelistv5_record_without_title_is_captured(self) -> None:
        assert _record("cvelistv5_kev_ssvc_offset_n_a").containers.cna.title is None


class TestProviderMetadata:
    @pytest.mark.parametrize("name", CVELISTV5_FIXTURES)
    def test_cvelistv5_cna_short_name_is_a_non_empty_string(self, name: str) -> None:
        assert _record(name).containers.cna.provider_metadata.short_name

    def test_adp_short_names_are_within_the_observed_set(self) -> None:
        short_names = {
            adp.provider_metadata.short_name
            for name in ALL_FIXTURES
            for adp in _record(name).containers.adp or []
        }

        assert short_names == {"CVE", "CISA-ADP", "redhat-SADP"}
        assert short_names <= _ADP_SHORT_NAMES


class TestAffected:
    @pytest.mark.parametrize(
        "name",
        ["cvelistv5_5_2_package_only_affected", "cvelistv5_package_url_package_only"],
    )
    def test_package_only_element_has_no_vendor_or_product(self, name: str) -> None:
        elements = [
            e for e in _affected(name) if e.vendor is None and e.product is None
        ]

        assert len(elements) == 1
        assert elements[0].package_name
        assert elements[0].collection_url

    def test_package_url_on_a_package_only_element_is_captured(self) -> None:
        element = _affected("cvelistv5_package_url_package_only")[0]

        assert element.vendor is None
        assert element.package_url == "pkg:cpan/HTML-FormHandler"

    def test_package_url_with_vendor_and_product_is_captured(self) -> None:
        element = _affected("cvelistv5_package_url_vendor")[0]

        assert (element.vendor, element.product) == ("SuiteCRM", "SuiteCRM")
        assert element.package_url == "pkg:github/SuiteCRM/SuiteCRM"

    def test_n_a_vendor_product_and_version_are_captured(self) -> None:
        element = _affected("cvelistv5_kev_ssvc_offset_n_a")[0]

        assert (element.vendor, element.product) == ("n/a", "n/a")
        assert element.versions is not None
        assert [v.version for v in element.versions] == ["n/a"]
        assert element.package_name is None
        assert element.cpes is None

    @pytest.mark.parametrize(
        "name", ["cvelistv5_v3_1_non_base_en_us_kev", "cvelistv5_lowercase_cwe_type"]
    )
    def test_uppercase_n_a_version_is_captured(self, name: str) -> None:
        assert "N/A" in {v.version for v in _versions(name)}

    def test_empty_cpes_array_is_captured(self) -> None:
        assert _affected("cvelistv5_empty_cpes")[0].cpes == []

    @pytest.mark.parametrize(
        "name",
        [
            "cvelistv5_5_2_package_only_affected",
            "cvelistv5_program_files_adp_affected",
            "vulns_published_affected_without_versions",
        ],
    )
    def test_element_without_versions_is_captured(self, name: str) -> None:
        assert any(e.versions is None for e in _affected(name))

    @pytest.mark.parametrize("name", ALL_FIXTURES)
    def test_present_versions_array_is_never_empty(self, name: str) -> None:
        for element in _affected(name):
            assert element.versions is None or element.versions

    @pytest.mark.parametrize("name", ALL_FIXTURES)
    def test_no_version_has_both_upper_bounds(self, name: str) -> None:
        for version in _versions(name):
            assert version.less_than is None or version.less_than_or_equal is None

    def test_less_than_and_less_than_or_equal_are_both_captured(self) -> None:
        versions = [v for name in ALL_FIXTURES for v in _versions(name)]

        assert any(v.less_than is not None for v in versions)
        assert any(v.less_than_or_equal is not None for v in versions)

    @pytest.mark.parametrize(
        "name",
        [
            "cvelistv5_package_url_package_only",
            "cvelistv5_program_files_adp_affected",
            "cvelistv5_repeated_cvss_v4",
            "vulns_published_5_1_1",
            "vulns_published_affected_without_versions",
        ],
    )
    def test_program_files_is_a_non_empty_list_of_paths(self, name: str) -> None:
        program_files = [e.program_files for e in _affected(name) if e.program_files]

        assert program_files
        for paths in program_files:
            assert all(path and not path.startswith("/") for path in paths)

    @pytest.mark.parametrize("name", ALL_FIXTURES)
    def test_statuses_are_known_values(self, name: str) -> None:
        for element in _affected(name):
            assert element.default_status is None or element.default_status in _STATUSES
        for version in _versions(name):
            assert version.status in _STATUSES

    def test_every_status_and_default_status_value_is_captured(self) -> None:
        statuses = {v.status for name in ALL_FIXTURES for v in _versions(name)}
        default_statuses = {
            e.default_status for name in ALL_FIXTURES for e in _affected(name)
        }

        assert statuses == _STATUSES
        assert default_statuses == {*_STATUSES, None}

    @pytest.mark.parametrize("name", VULNS_FIXTURES)
    def test_kernel_version_types_are_within_the_observed_set(self, name: str) -> None:
        for version in _versions(name):
            assert (
                version.version_type is None
                or version.version_type in _KERNEL_VERSION_TYPES
            )

    def test_every_kernel_version_type_is_captured(self) -> None:
        types = {v.version_type for name in VULNS_FIXTURES for v in _versions(name)}

        assert types == {*_KERNEL_VERSION_TYPES, None}

    def test_open_set_version_type_is_captured(self) -> None:
        assert "rpm" in {
            v.version_type for v in _versions("cvelistv5_program_files_adp_affected")
        }

    def test_adp_affected_elements_are_captured(self) -> None:
        sadp = [
            adp
            for adp in _record("cvelistv5_program_files_adp_affected").containers.adp
            or []
            if adp.provider_metadata.short_name == "redhat-SADP"
        ]

        assert len(sadp) == 1
        assert sadp[0].affected is not None
        assert len(sadp[0].affected) == 3
        assert all(e.cpes and e.package_name for e in sadp[0].affected)


class TestCVSS:
    def test_all_four_strict_base_keys_are_captured(self) -> None:
        assert [key for key, _ in _vectors("cvelistv5_all_cvss_keys_en_de")] == list(
            _CVSS_KEYS
        )

    def test_all_four_non_base_keys_are_captured(self) -> None:
        assert [key for key, _ in _vectors("cvelistv5_all_cvss_keys_non_base")] == list(
            _CVSS_KEYS
        )

    def test_keys_coexist_in_one_metrics_entry(self) -> None:
        metrics = _record("cvelistv5_coexisting_cvss_keys").containers.cna.metrics

        assert metrics is not None
        assert len(metrics) == 1
        assert [key for key, _ in metrics[0].vectors()] == ["cvssV4_0", "cvssV3_1"]

    def test_same_key_repeats_within_one_metrics_array(self) -> None:
        metrics = _record("cvelistv5_repeated_cvss_v4").containers.cna.metrics

        assert metrics is not None
        assert [key for m in metrics for key, _ in m.vectors()] == [
            "cvssV4_0",
            "cvssV4_0",
        ]

    def test_adp_cvss_v4_vector_is_captured(self) -> None:
        adp = _cisa_adp("cvelistv5_adp_cvss_v4")

        assert adp is not None
        assert "cvssV4_0" in {k for m in adp.metrics or [] for k, _ in m.vectors()}

    @pytest.mark.parametrize(
        ("name", "key", "received", "canonical"),
        [(n, k, r, c) for (n, k), (r, c) in _NON_BASE_VECTORS.items()],
    )
    def test_non_base_vector_reduces_to_its_canonical_base_vector(
        self, name: str, key: str, received: str, canonical: str
    ) -> None:
        """parse_cvss_assessments step 3: the External Base Reduction keeps
        the Base vector; the strict parser rejects the received vector."""
        assert (key, received) in _vectors(name)
        with pytest.raises(InvalidCVSSVectorError):
            validate_cvss_vector(received)

        parsed = validate_external_cvss_vector(received)

        assert parsed.canonical_vector == canonical
        assert parsed.version is _CVSS_KEYS[key]

    @pytest.mark.parametrize("name", ALL_FIXTURES)
    def test_every_other_vector_is_a_strict_base_vector_of_its_key(
        self, name: str
    ) -> None:
        for key, vector in _vectors(name):
            if (name, key) in _NON_BASE_VECTORS:
                continue
            parsed = validate_cvss_vector(vector)
            assert parsed.version is _CVSS_KEYS[key]
            assert validate_external_cvss_vector(vector) == parsed

    def test_every_non_base_vector_is_listed(self) -> None:
        non_base: set[tuple[str, str]] = set()
        for name in ALL_FIXTURES:
            for key, vector in _vectors(name):
                try:
                    validate_cvss_vector(vector)
                except InvalidCVSSVectorError:
                    non_base.add((name, key))

        assert non_base == set(_NON_BASE_VECTORS)

    @pytest.mark.parametrize("name", ALL_FIXTURES)
    def test_other_metrics_carry_no_vector(self, name: str) -> None:
        for container in _containers(_record(name)):
            for metric in container.metrics or []:
                assert metric.other is None or metric.vectors() == []

    def test_other_types_of_the_capture_are_represented(self) -> None:
        types = {
            m.other.type
            for name in ALL_FIXTURES
            for c in _containers(_record(name))
            for m in c.metrics or []
            if m.other is not None
        }

        assert types == {"ssvc", "kev", "Red Hat severity rating"}

    @pytest.mark.parametrize(
        "name",
        ["cvelistv5_5_2_package_only_affected", "cvelistv5_program_files_adp_affected"],
    )
    def test_red_hat_severity_is_a_vectorless_other_metric(self, name: str) -> None:
        severities = [
            other
            for c in _containers(_record(name))
            for other in _other_entries(c, "Red Hat severity rating")
        ]

        assert len(severities) == 1
        assert set(severities[0].content) == {"value", "namespace"}

    @pytest.mark.parametrize("name", VULNS_FIXTURES)
    def test_kernel_metrics_hold_only_cvss_v3_1(self, name: str) -> None:
        for key, _ in _vectors(name):
            assert key == "cvssV3_1"

    def test_kernel_cvss_v3_1_is_captured(self) -> None:
        assert [k for k, _ in _vectors("vulns_published_5_1_1")] == ["cvssV3_1"]


class TestSSVC:
    @pytest.mark.parametrize("name", _cisa_adp_fixtures())
    def test_cisa_adp_container_has_exactly_one_ssvc_entry(self, name: str) -> None:
        adp = _cisa_adp(name)
        assert adp is not None

        assert len(_other_entries(adp, "ssvc")) == 1

    @pytest.mark.parametrize("name", _cisa_adp_fixtures())
    def test_ssvc_content_has_the_consumed_shape(self, name: str) -> None:
        adp = _cisa_adp(name)
        assert adp is not None
        content = _SSVCContent.model_validate(_other_entries(adp, "ssvc")[0].content)

        assert all(len(option) == 1 for option in content.options)
        assert [key for option in content.options for key in option] == _SSVC_KEYS
        values = {k: v for option in content.options for k, v in option.items()}
        assert values["Exploitation"] in {m.value for m in SSVCExploitation}
        assert values["Automatable"] in {m.value for m in SSVCAutomatable}
        assert values["Technical Impact"] in {m.value for m in SSVCTechnicalImpact}
        assert content.version == "2.0.3"
        assert datetime.fromisoformat(content.timestamp).utcoffset() == timedelta(0)

    def test_both_ssvc_timestamp_forms_are_captured(self) -> None:
        timestamps: list[str] = []
        for name in _cisa_adp_fixtures():
            adp = _cisa_adp(name)
            assert adp is not None
            ssvc = _other_entries(adp, "ssvc")[0]
            timestamps.append(_SSVCContent.model_validate(ssvc.content).timestamp)

        assert all(
            _MICROSECOND_UTC.fullmatch(t) or _OFFSET_UTC.fullmatch(t)
            for t in timestamps
        )
        assert any(_OFFSET_UTC.fullmatch(t) for t in timestamps)
        assert any(_MICROSECOND_UTC.fullmatch(t) for t in timestamps)

    def test_every_exploitation_value_is_captured(self) -> None:
        exploitation: set[str] = set()
        for name in _cisa_adp_fixtures():
            adp = _cisa_adp(name)
            assert adp is not None
            content = _SSVCContent.model_validate(
                _other_entries(adp, "ssvc")[0].content
            )
            exploitation.add(content.options[0]["Exploitation"])

        assert exploitation == {member.value for member in SSVCExploitation}


class TestKEV:
    @pytest.mark.parametrize("name", _cisa_adp_fixtures())
    def test_cisa_adp_container_has_at_most_one_kev_entry(self, name: str) -> None:
        adp = _cisa_adp(name)
        assert adp is not None

        assert len(_other_entries(adp, "kev")) <= 1

    @pytest.mark.parametrize(
        ("name", "date_added"),
        [
            ("cvelistv5_kev_ssvc_offset_n_a", "2022-03-15"),
            ("cvelistv5_v3_1_non_base_en_us_kev", "2022-01-10"),
        ],
    )
    def test_kev_content_is_a_date_and_a_reference_string(
        self, name: str, date_added: str
    ) -> None:
        adp = _cisa_adp(name)
        assert adp is not None
        (kev,) = _other_entries(adp, "kev")
        content = _KEVContent.model_validate(kev.content)

        assert content.date_added == date_added
        assert _DATE.fullmatch(content.date_added)
        assert date.fromisoformat(content.date_added).isoformat() == date_added
        assert urlsplit(content.reference).scheme == "https"
        assert source_cve_id(name) in content.reference


class TestProblemTypes:
    @pytest.mark.parametrize("name", ALL_FIXTURES)
    def test_every_cwe_id_matches_the_validation_pattern(self, name: str) -> None:
        for description in _problem_type_descriptions(name):
            cwe_id = description.cwe_id
            assert cwe_id is None or _CWE_PATTERN.fullmatch(cwe_id)

    def test_type_values_of_the_capture_are_represented(self) -> None:
        types = {
            d.type for name in ALL_FIXTURES for d in _problem_type_descriptions(name)
        }

        assert types == {"CWE", "cwe", "text", None}

    def test_lowercase_cwe_type_carries_a_cwe_id(self) -> None:
        (description,) = _problem_type_descriptions("cvelistv5_lowercase_cwe_type")

        assert (description.type, description.cwe_id) == ("cwe", "CWE-79")

    def test_cwe_id_without_type_is_captured(self) -> None:
        (description,) = _problem_type_descriptions("cvelistv5_cwe_id_without_type")

        assert (description.type, description.cwe_id) == (None, "CWE-611")

    @pytest.mark.parametrize(
        "name", ["vulns_rejected_5_1_problem_types", "cvelistv5_coexisting_cvss_keys"]
    )
    def test_description_without_type_or_cwe_id_is_captured(self, name: str) -> None:
        cna = _record(name).containers.cna

        assert cna.problem_types is not None
        (description,) = [d for p in cna.problem_types for d in p.descriptions]
        assert (description.type, description.cwe_id) == (None, None)

    @pytest.mark.parametrize("name", ALL_FIXTURES)
    def test_text_type_carries_no_cwe_id(self, name: str) -> None:
        for description in _problem_type_descriptions(name):
            assert description.type != "text" or description.cwe_id is None

    def test_kernel_problem_types_occur_only_in_the_5_1_record(self) -> None:
        with_problem_types = {
            name
            for name in VULNS_FIXTURES
            if _record(name).containers.cna.problem_types is not None
        }

        assert with_problem_types == {"vulns_rejected_5_1_problem_types"}


class TestExternalStringAdmissibility:
    @pytest.mark.parametrize("name", ALL_FIXTURES)
    def test_every_consumed_string_is_nul_free_and_within_its_bound(
        self, name: str
    ) -> None:
        strings = _consumed_strings(_record(name))

        assert strings
        for label, value, bound in strings:
            assert "\x00" not in value, label
            assert bound is None or len(value) <= bound, label

    def test_bounded_payload_fields_are_checked(self) -> None:
        bounded = {
            label
            for name in ALL_FIXTURES
            for label, _, bound in _consumed_strings(_record(name))
            if bound is not None
        }

        assert bounded == {
            "title",
            "vendor",
            "repo",
            "packageURL",
            "collectionURL",
            "packageName",
            "defaultStatus",
            "cpes[]",
            "versionType",
            "status",
            "vectorString",
            "cweId",
            "ssvc version",
            "kev reference",
        }


class TestSanitization:
    @pytest.mark.parametrize("name", ALL_FIXTURES)
    def test_fixture_retains_no_real_email(self, name: str) -> None:
        for match in _EMAIL.finditer(load_raw_fixture(name)):
            assert match.group(1) in _FICTIONAL_EMAIL_DOMAINS

    @pytest.mark.parametrize("name", ALL_FIXTURES)
    def test_free_text_is_fictional(self, name: str) -> None:
        containers = load_fixture(name)["containers"]
        cna = containers["cna"]
        adps = containers.get("adp", [])

        for container in [cna, *adps]:
            for description in container.get("descriptions", []):
                assert description["value"].startswith(_FICTIONAL_DESCRIPTION_PREFIXES)
            for reason in container.get("rejectedReasons", []):
                assert reason["value"].startswith("Fictional rejection reason for ")
            for credit in container.get("credits", []):
                assert credit["value"] == "Example Researcher"
        if "title" in cna:
            assert cna["title"].startswith(_FICTIONAL_TITLE_PREFIXES)
        for adp in adps:
            title = adp.get("title")
            assert (
                title is None
                or title in _KEPT_ADP_TITLES
                or title.startswith(_FICTIONAL_TITLE_PREFIXES)
            )

    @pytest.mark.parametrize("name", ALL_FIXTURES)
    def test_urls_are_kept_organisation_locations_or_fictional(self, name: str) -> None:
        for url in _urls(load_fixture(name)):
            parts = urlsplit(url)
            host = parts.hostname
            if host == "github.com":
                assert parts.path.split("/")[1] in _KEPT_GITHUB_OWNERS, url
            elif host == "git.kernel.org":
                assert parts.path.startswith(_KERNEL_STABLE_PATHS), url
            elif host == "advisory.example.invalid":
                assert _FICTIONAL_UPSTREAM.fullmatch(url), url
            else:
                assert host in _KEPT_HOSTS | _FICTIONAL_HOSTS, url

    def test_replaced_references_are_captured(self) -> None:
        replaced = {
            url
            for name in ALL_FIXTURES
            for url in _urls(load_fixture(name))
            if _FICTIONAL_UPSTREAM.fullmatch(url)
        }

        assert len(replaced) == 12
