"""Pure, source-agnostic parsing of CVE Record Format 5.x structures.

Implements docs/features/platform/cve-record-parser.md (Design Principles,
Module-Level Defaults, Input Validation, External String Admissibility,
Functions, Schema Version Handling). The functions turn deserialized
CVE JSON 5.x values from `cvelistV5`, `vulns.git`, or any other CVE Record
source into `CVEIngestPayload` sub-structures (`app/services/cve_ingest.py`).

Every function is a Category B function: no I/O, no logging, no database,
and no exception escapes. The input is untrusted, so every consumed value
is checked for its JSON type. A wrong-typed argument yields the empty
result; an unparseable entry, including one the payload model rejects for a
bound, pattern, enum, or U+0000, is skipped while its siblings survive.
There is no `dataVersion` branching: parsing follows the actual structure.

Callers own presence: whether a scoped affected-version operation exists,
whether a global field is omitted or explicitly null, and every log line.
"""

from __future__ import annotations

import re
from collections.abc import Iterator, Mapping
from datetime import UTC, date, datetime
from typing import Any, Final

from pydantic import ValidationError

from app.core.enums import (
    CveState,
    CVSSVersion,
    SSVCAutomatable,
    SSVCExploitation,
    SSVCTechnicalImpact,
)
from app.core.external_strings import contains_nul
from app.services.cve_ingest import (
    AffectedVersionEntry,
    CVSSAssessmentEntry,
    CWEEntry,
    KEVEntry,
    SSVCEntry,
    affected_version_key,
)
from app.services.cvss import is_reserved_provider_name, validate_external_cvss_vector
from app.services.ticket_mutations_errors import InvalidCVSSVectorError

TITLE_MAX_LENGTH: Final = 256
"""`parse_title` truncation bound (the `CVEIngestPayload.title` bound)."""

CVSS_VECTOR_KEYS: Final[tuple[str, ...]] = (
    "cvssV4_0",
    "cvssV3_1",
    "cvssV3_0",
    "cvssV2_0",
)
"""The `metrics[]` keys inspected by `parse_cvss_assessments`, in order."""

_SENTINELS: Final = frozenset({"n/a", ""})
"""Values of `vendor`, `product`, and `version` normalized to `None`."""

_PACKAGE_COORDINATES: Final[tuple[str, ...]] = (
    "package_name",
    "package_url",
    "collection_url",
    "repo",
    "cpe",
)
"""Parsed fields that keep an entry whose `vendor` and `product` are
sentinels when one of them is a non-empty string."""

_CWE_PATTERN: Final = re.compile(r"CWE-[1-9][0-9]*")
_CWE_MAX_LENGTH: Final = 20

_SSVC_EXPLOITATION: Final = "Exploitation"
_SSVC_AUTOMATABLE: Final = "Automatable"
_SSVC_TECHNICAL_IMPACT: Final = "Technical Impact"
_SSVC_DECISION_POINTS: Final = (
    _SSVC_EXPLOITATION,
    _SSVC_AUTOMATABLE,
    _SSVC_TECHNICAL_IMPACT,
)

_DATE_LENGTH: Final = len("YYYY-MM-DD")


class _UnparseableError(Exception):
    """A consumed field has another JSON type; its element is skipped."""


# ---------------------------------------------------------------------------
# Typed field access (Input Validation)
# ---------------------------------------------------------------------------


def _objects(value: object) -> Iterator[Mapping[str, Any]]:
    """The object elements of a JSON array; anything else yields nothing."""
    if isinstance(value, list):
        for element in value:
            if isinstance(element, dict):
                yield element


def _optional_str(element: Mapping[str, Any], key: str) -> str | None:
    """An absent or `null` field is `None`; a non-string is unparseable."""
    value = element.get(key)
    if value is None or isinstance(value, str):
        return value
    raise _UnparseableError


def _sentinel_normalized(value: str | None) -> str | None:
    return None if value is None or value in _SENTINELS else value


def _first_cpe(element: Mapping[str, Any]) -> str | None:
    cpes = element.get("cpes")
    if cpes is None:
        return None
    if not isinstance(cpes, list):
        raise _UnparseableError
    if not cpes:
        return None
    first = cpes[0]
    if not isinstance(first, str):
        raise _UnparseableError
    return first


def _program_files(element: Mapping[str, Any]) -> list[str] | None:
    files = element.get("programFiles")
    if files is None:
        return None
    if not isinstance(files, list) or not all(isinstance(f, str) for f in files):
        raise _UnparseableError
    return files


def _parse_datetime(value: object) -> datetime | None:
    """An ISO 8601 date-time as aware UTC; a value without an offset is UTC.

    Anything else, including a date without a time of day, is `None`.
    """
    if not isinstance(value, str) or contains_nul(value) or "T" not in value:
        # `fromisoformat` accepts U+0000 as the date/time separator.
        return None
    try:
        parsed = datetime.fromisoformat(value)
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=UTC)
        return parsed.astimezone(UTC)
    except ValueError, OverflowError:
        return None


def _parse_date(value: object) -> date | None:
    """An ISO 8601 date, or the date portion of a date-time as written."""
    if not isinstance(value, str) or contains_nul(value):
        return None
    try:
        if len(value) == _DATE_LENGTH:
            return date.fromisoformat(value)
        if "T" not in value:
            return None
        return datetime.fromisoformat(value).date()
    except ValueError:
        return None


def _last_other_content(metrics: object, other_type: str) -> object:
    """`other.content` of the last `metrics[]` entry whose `other.type`
    equals `other_type`; `None` when there is none."""
    content: object = None
    for metric in _objects(metrics):
        other = metric.get("other")
        if isinstance(other, dict) and other.get("type") == other_type:
            content = other.get("content")
    return content


# ---------------------------------------------------------------------------
# Affected versions
# ---------------------------------------------------------------------------


def parse_affected_versions(affected: object) -> list[AffectedVersionEntry]:
    """Typed entries of one `affected[]` array (§ `parse_affected_versions`).

    Duplicates by the affected-version entry conflict key keep the last
    occurrence. An unparseable element or version, and every entry the
    `AffectedVersionEntry` model rejects, is skipped.
    """
    by_key: dict[tuple[Any, ...], AffectedVersionEntry] = {}
    for element in _objects(affected):
        try:
            entries = _element_entries(element)
        except _UnparseableError:
            continue
        for entry in entries:
            key = affected_version_key(entry)
            by_key.pop(key, None)
            by_key[key] = entry
    return list(by_key.values())


def _element_entries(element: Mapping[str, Any]) -> list[AffectedVersionEntry]:
    """The entries of one `affected[]` element (steps 1-5)."""
    vendor = _sentinel_normalized(_optional_str(element, "vendor"))
    product = _sentinel_normalized(_optional_str(element, "product"))
    common: dict[str, Any] = {
        "vendor": vendor,
        "product": product,
        "repo": _optional_str(element, "repo"),
        "package_url": _optional_str(element, "packageURL"),
        "collection_url": _optional_str(element, "collectionURL"),
        "package_name": _optional_str(element, "packageName"),
        "default_status": _optional_str(element, "defaultStatus"),
        "cpe": _first_cpe(element),
        "program_files": _program_files(element),
    }
    if (
        vendor is None
        and product is None
        and not any(common[field] for field in _PACKAGE_COORDINATES)
    ):
        return []
    versions = element.get("versions")
    if versions is None or versions == []:
        entry = _entry(common)
        return [] if entry is None else [entry]
    if not isinstance(versions, list):
        raise _UnparseableError
    entries: list[AffectedVersionEntry] = []
    for version in _objects(versions):
        try:
            fields = _version_fields(version)
        except _UnparseableError:
            continue
        entry = _entry(common | fields)
        if entry is not None:
            entries.append(entry)
    return entries


def _version_fields(version: Mapping[str, Any]) -> dict[str, Any]:
    """The per-version fields of one `versions[]` element (step 5)."""
    less_than = _optional_str(version, "lessThan")
    less_than_or_equal = _optional_str(version, "lessThanOrEqual")
    if less_than is not None:
        version_end, inclusive = less_than, False
    elif less_than_or_equal is not None:
        version_end, inclusive = less_than_or_equal, True
    else:
        version_end, inclusive = None, None
    return {
        "version": _sentinel_normalized(_optional_str(version, "version")),
        "version_type": _optional_str(version, "versionType"),
        "version_end": version_end,
        "version_end_inclusive": inclusive,
        "status": _optional_str(version, "status"),
    }


def _entry(fields: dict[str, Any]) -> AffectedVersionEntry | None:
    try:
        return AffectedVersionEntry(**fields)
    except ValidationError:
        return None


# ---------------------------------------------------------------------------
# CVSS assessments
# ---------------------------------------------------------------------------


def parse_cvss_assessments(
    metrics: object, provider_name: str
) -> list[CVSSAssessmentEntry]:
    """Vector-only candidates of one `metrics[]` array
    (§ `parse_cvss_assessments`).

    A reserved `SUSE` provider (after trim and case-fold) yields `[]`. Every
    `vectorString` goes through the External Base Reduction; a rejected one
    is skipped, and the last accepted candidate per derived version wins.
    The provider is stamped trimmed and otherwise unvalidated: `upsert_cve()`
    classifies an invalid one as `invalid_provider`. A caller may derive the
    provider from upstream JSON, so a non-string one also yields `[]`.
    """
    if not isinstance(provider_name, str) or is_reserved_provider_name(provider_name):
        return []
    provider = provider_name.strip()
    by_version: dict[CVSSVersion, CVSSAssessmentEntry] = {}
    for metric in _objects(metrics):
        for key in CVSS_VECTOR_KEYS:
            cvss = metric.get(key)
            vector = cvss.get("vectorString") if isinstance(cvss, dict) else None
            if not isinstance(vector, str):
                continue
            try:
                parsed = validate_external_cvss_vector(vector)
            except InvalidCVSSVectorError:
                continue
            by_version.pop(parsed.version, None)
            by_version[parsed.version] = CVSSAssessmentEntry(
                provider_name=provider, vector_string=parsed.canonical_vector
            )
    return list(by_version.values())


# ---------------------------------------------------------------------------
# CWE classifications
# ---------------------------------------------------------------------------


def parse_cwe_classifications(problem_types: object, source: str) -> list[CWEEntry]:
    """CWE entries of one `problemTypes[]` array
    (§ `parse_cwe_classifications`), first occurrence per `cwe_id`."""
    by_id: dict[str, CWEEntry] = {}
    for problem_type in _objects(problem_types):
        for description in _objects(problem_type.get("descriptions")):
            entry = _cwe_entry(description, source)
            if entry is not None:
                by_id.setdefault(entry.cwe_id, entry)
    return list(by_id.values())


def _cwe_entry(description: Mapping[str, Any], source: str) -> CWEEntry | None:
    kind = description.get("type")
    cwe_id = description.get("cweId")
    is_cwe = isinstance(kind, str) and kind.casefold() == "cwe"
    if not (is_cwe or cwe_id is not None):
        return None
    if (
        not isinstance(cwe_id, str)
        or len(cwe_id) > _CWE_MAX_LENGTH
        or _CWE_PATTERN.fullmatch(cwe_id) is None
    ):
        return None
    try:
        return CWEEntry(cwe_id=cwe_id, source=source)
    except ValidationError:
        return None


# ---------------------------------------------------------------------------
# Description, title, CVE-ID
# ---------------------------------------------------------------------------


def parse_description(descriptions: object) -> str | None:
    """The first English `descriptions[].value`, else the first one
    (§ `parse_description`). Only string values are considered; the value is
    returned unvalidated."""
    values: list[tuple[object, str]] = [
        (description.get("lang"), value)
        for description in _objects(descriptions)
        if isinstance(value := description.get("value"), str)
    ]
    for lang, value in values:
        if isinstance(lang, str) and lang.startswith("en"):
            return value
    return values[0][1] if values else None


def parse_title(cna: object) -> str | None:
    """`cna.title` truncated to 256 characters, unvalidated (§ `parse_title`)."""
    title = cna.get("title") if isinstance(cna, dict) else None
    return title[:TITLE_MAX_LENGTH] if isinstance(title, str) else None


def validate_cve_id(filename_id: str, json_metadata: object) -> str:
    """The authoritative CVE-ID (§ `validate_cve_id`).

    The JSON `cveId` (or legacy `cveID`) is only cross-checked against the
    file name, and the file name is authoritative on a match, a mismatch,
    and an absent JSON value alike, so the result is always `filename_id`.
    The comparison has no observable effect: this module never logs, and
    each caller's specification owns any reaction to a mismatch.
    """
    return filename_id


# ---------------------------------------------------------------------------
# CISA-ADP SSVC and KEV
# ---------------------------------------------------------------------------


def parse_ssvc_assessment(metrics: object) -> SSVCEntry | None:
    """The last `ssvc` assessment of a CISA-ADP `metrics[]` array
    (§ `parse_ssvc_assessment`).

    `None` when it is incomplete, carries a value outside its enum or the
    `version` bound, or has a present but unparseable `timestamp`.
    """
    content = _last_other_content(metrics, "ssvc")
    if not isinstance(content, dict):
        return None
    options: dict[str, object] = {}
    for option in _objects(content.get("options")):
        for point in _SSVC_DECISION_POINTS:
            if point in option:
                options.setdefault(point, option[point])
    version = content.get("version")
    if version is None or version == "":
        return None
    timestamp = content.get("timestamp")
    assessed_at = None if timestamp is None else _parse_datetime(timestamp)
    if timestamp is not None and assessed_at is None:
        return None
    try:
        return SSVCEntry(
            exploitation=_ssvc_value(SSVCExploitation, options),
            automatable=_ssvc_value(SSVCAutomatable, options),
            technical_impact=_ssvc_value(SSVCTechnicalImpact, options),
            version=version,
            assessed_at=assessed_at,
        )
    except ValueError:  # Includes `pydantic.ValidationError`.
        return None


def _ssvc_value[E: (SSVCExploitation, SSVCAutomatable, SSVCTechnicalImpact)](
    enum: type[E], options: Mapping[str, object]
) -> E:
    """The exact enum member of one decision point; `ValueError` when the
    point is missing or its value is not a member."""
    point = {
        SSVCExploitation: _SSVC_EXPLOITATION,
        SSVCAutomatable: _SSVC_AUTOMATABLE,
        SSVCTechnicalImpact: _SSVC_TECHNICAL_IMPACT,
    }[enum]
    value = options.get(point)
    if not isinstance(value, str):
        raise ValueError(point)
    return enum(value)


def parse_kev_data(metrics: object) -> KEVEntry | None:
    """The last `kev` entry of a CISA-ADP `metrics[]` array
    (§ `parse_kev_data`).

    `None` when `dateAdded` is absent or unparseable, or when a present
    `reference` is not a string within its bound or contains U+0000.
    """
    content = _last_other_content(metrics, "kev")
    if not isinstance(content, dict):
        return None
    date_added = _parse_date(content.get("dateAdded"))
    if date_added is None:
        return None
    try:
        return KEVEntry(date_added=date_added, reference_url=content.get("reference"))
    except ValidationError:
        return None


# ---------------------------------------------------------------------------
# Metadata
# ---------------------------------------------------------------------------


def extract_cve_state(json_metadata: object) -> CveState | None:
    """`cveMetadata.state` when it is a `CveState` member, else `None`
    (§ `extract_cve_state`)."""
    state = json_metadata.get("state") if isinstance(json_metadata, dict) else None
    if not isinstance(state, str):
        return None
    try:
        return CveState(state)
    except ValueError:
        return None


def extract_dates(
    json_metadata: object,
) -> tuple[datetime | None, datetime | None, datetime | None]:
    """`(datePublished, dateUpdated, dateRejected)` as aware UTC datetimes,
    each `None` when absent or unparseable (§ `extract_dates`)."""
    if not isinstance(json_metadata, dict):
        return None, None, None
    return (
        _parse_datetime(json_metadata.get("datePublished")),
        _parse_datetime(json_metadata.get("dateUpdated")),
        _parse_datetime(json_metadata.get("dateRejected")),
    )
