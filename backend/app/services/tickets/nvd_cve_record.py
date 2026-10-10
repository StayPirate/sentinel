"""Typed envelopes and pure mapping of NVD CVE API 2.0 records.

Implements docs/features/tickets/cve-sync-nvd.md (Algorithm step 4.c page
envelope; Field Mapping: Global CVE fields, Optional member validation,
Candidate skip event, Source identity, CVSS metrics, CWE / weaknesses, CPE
configurations, References, Explicitly ignored fields, CVSS deduplication
rules, External String Admissibility; NVD Source API Caching) for one CVE API
response body, one `vulnerabilities[]` element, and one Source API response
body. The module performs no HTTP, database, or logging work; `SyncNvdCves`
owns the requests, the per-item failure outcome, the ingestion, and the
WARNING events built from the facts reported here.

Bodies are decoded as strict UTF-8 with the standard-library JSON decoder,
which keeps an unpaired surrogate escape as a string value so that it reaches
the outcome of its own field (for example `invalid_cpe_match`); Pydantic's
JSON mode would reject the whole body. The envelopes are then validated by
strict models of their consumed members.

`parse_page()` raises `NvdPageError` for an unparseable page response.
`map_vulnerability()` raises `NvdRecordIdError` for an `.id` string that is
not a valid CVE-ID, `NvdRecordStructureError` for a structurally
non-processable record, and the payload's `pydantic.ValidationError` for a
description containing U+0000 (cve-service.md, CVEIngestPayload Schema).
Every other invalid unit is skipped and reported as a closed skip reason. No
message renders the input.
"""

from __future__ import annotations

import json
import re
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from types import MappingProxyType
from typing import Any, Final, Literal, TypeGuard

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from app.core.enums import CveState, ReferenceType
from app.core.external_strings import contains_nul
from app.core.identifiers import is_valid_cve_id
from app.services.cve_ingest import (
    CPEMatchEntry,
    CVEIngestPayload,
    CVSSAssessmentEntry,
    CWEEntry,
)
from app.services.cvss import is_reserved_provider_name, validate_external_cvss_vector
from app.services.reference_service import AutomaticReferenceInput
from app.services.ticket_mutations_errors import InvalidCVSSVectorError

NVD_SOURCE_IDENTIFIER: Final = "nvd@nist.gov"
"""NVD's own source identifier (Source identity)."""

NVD_PROVIDER_NAME: Final = "NVD"
"""The CVSS provider and CWE source of NVD's own entries."""

SOURCE_REFERENCE_TITLE: Final = "NVD"

SOURCE_REFERENCE_URL_PATTERN: Final = "https://nvd.nist.gov/vuln/detail/{cve_id}"
"""The fetcher's `source_reference_url_pattern` (single `{cve_id}`)."""

CVSS_METRIC_ARRAYS: Final = (
    "cvssMetricV2",
    "cvssMetricV30",
    "cvssMetricV31",
    "cvssMetricV40",
)
"""The CVSS metric arrays in iteration order (CVSS metrics rule 1)."""

CPE_CRITERIA_MAX_LENGTH: Final = 2048
"""The `CPEMatchEntry.criteria` bound in code points."""

type SkipReason = Literal[
    "invalid_description",
    "invalid_cvss_metric",
    "invalid_vector",
    "missing_source",
    "unresolved_source",
    "reserved_provider",
    "invalid_cwe",
    "invalid_reference",
    "invalid_cpe_configuration",
    "invalid_cpe_match",
]
"""The closed reasons of the candidate skip event (Candidate skip event)."""

INVALID_DESCRIPTION: Final = "invalid_description"
INVALID_CVSS_METRIC: Final = "invalid_cvss_metric"
INVALID_VECTOR: Final = "invalid_vector"
MISSING_SOURCE: Final = "missing_source"
UNRESOLVED_SOURCE: Final = "unresolved_source"
RESERVED_PROVIDER: Final = "reserved_provider"
INVALID_CWE: Final = "invalid_cwe"
INVALID_REFERENCE: Final = "invalid_reference"
INVALID_CPE_CONFIGURATION: Final = "invalid_cpe_configuration"
INVALID_CPE_MATCH: Final = "invalid_cpe_match"

_VULN_STATUS_STATES: Final[Mapping[str, CveState]] = MappingProxyType(
    {
        "Received": CveState.PUBLISHED,
        "Awaiting Analysis": CveState.PUBLISHED,
        "Undergoing Analysis": CveState.PUBLISHED,
        "Analyzed": CveState.PUBLISHED,
        "Modified": CveState.PUBLISHED,
        "Deferred": CveState.PUBLISHED,
        "Rejected": CveState.REJECTED,
    }
)
"""`vulnStatus` → `CVEState` mapping; any other value maps to `PUBLISHED`."""

_DATE_TIME_FORM: Final = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}"
    r"(?::[0-9]{2}(?:\.[0-9]+)?)?(?:Z|[+-][0-9]{2}:[0-9]{2})?"
)
"""The extended-format date-time of Required fields; apply with `fullmatch`."""
_CWE_PATTERN: Final = re.compile(r"CWE-[1-9][0-9]*")
_UUID_FORM: Final = re.compile(
    r"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}"
)
_ENGLISH: Final = "en"

_STRICT: Final = ConfigDict(
    strict=True, extra="ignore", frozen=True, hide_input_in_errors=True
)


class NvdPageError(ValueError):
    """A CVE API body that is not a page envelope; a page-level failure."""

    def __init__(self) -> None:
        super().__init__("NVD response is not a CVE API page")


class NvdRecordError(ValueError):
    """A `vulnerabilities[]` element that cannot be mapped; a per-item
    failure."""


class NvdRecordStructureError(NvdRecordError):
    """The element, its `cve` member, or a required field is unusable."""

    def __init__(self) -> None:
        super().__init__("NVD record is structurally non-processable")


class NvdRecordIdError(NvdRecordError):
    """The `.id` string is not a valid CVE-ID."""

    def __init__(self) -> None:
        super().__init__("NVD record id is not a valid CVE-ID")


class _SkippedUnitError(Exception):
    """An invalid unit, skipped under its closed reason."""

    def __init__(self, reason: SkipReason) -> None:
        super().__init__(reason)
        self.reason: SkipReason = reason


class _CvePage(BaseModel):
    """The consumed members of a CVE API page (Algorithm step 4.c)."""

    model_config = _STRICT

    total_results: int = Field(alias="totalResults", ge=0)
    vulnerabilities: list[Any]


class _SourcePage(BaseModel):
    """The consumed members of a Source API body (NVD Source API Caching)."""

    model_config = _STRICT

    total_results: int = Field(alias="totalResults")
    results_per_page: int = Field(alias="resultsPerPage")
    sources: list[Any]


@dataclass(frozen=True, slots=True)
class NvdCvePage:
    """One CVE API page: the result count and the raw elements, each mapped
    under its own per-item boundary."""

    total_results: int
    vulnerabilities: tuple[object, ...]


@dataclass(frozen=True, slots=True)
class NvdSourceCache:
    """The Source API cache and the facts of its construction.

    `names` maps a source identifier to its trimmed display name; it is
    `None` in degraded mode (unparseable body or envelope). The fetcher logs
    the degraded-mode WARNING, the bounded count WARNING when
    `malformed_entries` is positive, and the pagination-guard WARNING when
    `incomplete` is true.
    """

    names: Mapping[str, str] | None
    malformed_entries: int
    incomplete: bool


@dataclass(frozen=True, slots=True)
class CpeSelection:
    """The selected CPE package candidates and the skip reasons of invalid
    units (CPE configurations).

    `matches` is `None` when `configurations` is absent, `null`, or not an
    array, and otherwise one entry per selected occurrence, possibly none.
    """

    matches: tuple[CPEMatchEntry, ...] | None
    skip_reasons: frozenset[SkipReason]


@dataclass(frozen=True, slots=True)
class NvdCveRecord:
    """Everything one `vulnerabilities[]` element contributes, built before
    any write.

    `skip_reasons` holds each reason with at least one skipped unit, for one
    candidate skip event per reason; `unrecognized_vuln_status` asks for the
    bounded unknown-`vulnStatus` event.
    """

    cve_id: str
    payload: CVEIngestPayload
    source_reference: AutomaticReferenceInput
    upstream_references: tuple[AutomaticReferenceInput, ...]
    skip_reasons: frozenset[SkipReason]
    unrecognized_vuln_status: bool


def parse_page(content: bytes) -> NvdCvePage:
    """Validate one CVE API response body (Algorithm step 4.c).

    The body must be a JSON object with a non-negative integer
    `totalResults` and an array `vulnerabilities`; anything else raises
    `NvdPageError`.
    """
    try:
        page = _CvePage.model_validate(_decode(content))
    except ValidationError:
        raise NvdPageError from None
    return NvdCvePage(
        total_results=page.total_results,
        vulnerabilities=tuple(page.vulnerabilities),
    )


def build_source_cache(content: bytes) -> NvdSourceCache:
    """Build the `source_identifier → display_name` cache from one Source API
    HTTP 200 body (NVD Source API Caching).

    An unparseable body or envelope yields degraded mode; a malformed entry
    is skipped and counted, and a later entry wins for a repeated
    identifier.
    """
    try:
        page = _SourcePage.model_validate(_decode(content))
    except NvdPageError, ValidationError:
        return NvdSourceCache(names=None, malformed_entries=0, incomplete=False)
    names: dict[str, str] = {}
    malformed = 0
    for entry in page.sources:
        parsed = _source_entry(entry)
        if parsed is None:
            malformed += 1
            continue
        name, identifiers = parsed
        for identifier in identifiers:
            names[identifier] = name
    return NvdSourceCache(
        names=MappingProxyType(names),
        malformed_entries=malformed,
        incomplete=page.total_results > page.results_per_page,
    )


def element_cve_id(element: object) -> str | None:
    """The `.id` of an element when it is a valid CVE-ID, else `None`."""
    cve = element.get("cve") if isinstance(element, dict) else None
    cve_id = cve.get("id") if isinstance(cve, dict) else None
    if isinstance(cve_id, str) and is_valid_cve_id(cve_id):
        return cve_id
    return None


def map_vulnerability(
    element: object, source_names: Mapping[str, str] | None
) -> NvdCveRecord:
    """Map one `vulnerabilities[]` element (Field Mapping).

    `source_names` is the Source API cache, or `None` in degraded mode.
    Raises `NvdRecordIdError`, `NvdRecordStructureError`, or the payload's
    `pydantic.ValidationError`.
    """
    cve = element.get("cve") if isinstance(element, dict) else None
    if not isinstance(cve, dict):
        raise NvdRecordStructureError
    cve_id = cve.get("id")
    if not isinstance(cve_id, str):
        raise NvdRecordStructureError
    if not is_valid_cve_id(cve_id):
        raise NvdRecordIdError
    published = _timestamp(cve.get("published"))
    modified = _timestamp(cve.get("lastModified"))
    vuln_status = cve.get("vulnStatus")
    if not isinstance(vuln_status, str):
        raise NvdRecordStructureError
    cve_state = _VULN_STATUS_STATES.get(vuln_status)

    reasons: set[SkipReason] = set()
    fields: dict[str, object] = {
        "published_date": published,
        "modified_date": modified,
        "cve_state": CveState.PUBLISHED if cve_state is None else cve_state,
    }
    description = _description(cve.get("descriptions"), reasons)
    if description is not None:
        fields["description"] = description
    cvss = _cvss_candidates(cve.get("metrics"), source_names, reasons)
    if cvss:
        fields["cvss_assessments"] = cvss
    cwes = _cwe_candidates(cve.get("weaknesses"), source_names, reasons)
    if cwes:
        fields["cwe_classifications"] = cwes
    selection = select_cpe_matches(cve.get("configurations"))
    reasons |= selection.skip_reasons
    if selection.matches is not None:
        fields["cpe_matches"] = list(selection.matches)
    upstream_references = _upstream_references(cve.get("references"), reasons)

    return NvdCveRecord(
        cve_id=cve_id,
        payload=CVEIngestPayload.model_validate(fields),
        source_reference=AutomaticReferenceInput(
            url=SOURCE_REFERENCE_URL_PATTERN.format(cve_id=cve_id),
            title=SOURCE_REFERENCE_TITLE,
            explicit_type=ReferenceType.ADVISORY,
        ),
        upstream_references=upstream_references,
        skip_reasons=frozenset(reasons),
        unrecognized_vuln_status=cve_state is None,
    )


def select_cpe_matches(configurations: object) -> CpeSelection:
    """§ CPE configurations: the `vulnerable = true` entries beneath no
    negated node or configuration, with every invalid unit skipped together
    with everything beneath it."""
    if configurations is None:
        return CpeSelection(matches=None, skip_reasons=frozenset())
    if not isinstance(configurations, list):
        return CpeSelection(
            matches=None, skip_reasons=frozenset({INVALID_CPE_CONFIGURATION})
        )
    matches: list[CPEMatchEntry] = []
    reasons: set[SkipReason] = set()
    for configuration in configurations:
        try:
            nodes = _unnegated_members(configuration, "nodes")
        except _SkippedUnitError as skip:
            reasons.add(skip.reason)
            continue
        for node in nodes:
            try:
                entries = _unnegated_members(node, "cpeMatch")
            except _SkippedUnitError as skip:
                reasons.add(skip.reason)
                continue
            for entry in entries:
                try:
                    match = _cpe_match(entry)
                except _SkippedUnitError as skip:
                    reasons.add(skip.reason)
                    continue
                if match is not None:
                    matches.append(match)
    return CpeSelection(matches=tuple(matches), skip_reasons=frozenset(reasons))


def _decode(content: bytes) -> object:
    """Strict UTF-8 JSON; raises `NvdPageError` when it does not decode."""
    try:
        return json.loads(content.decode("utf-8"))
    except ValueError, RecursionError:
        # `UnicodeDecodeError` and `JSONDecodeError` are `ValueError`s; the
        # latter keeps the document, so the cause is not chained.
        raise NvdPageError from None


def _source_entry(entry: object) -> tuple[str, list[str]] | None:
    """A source entry's trimmed name and identifiers, `None` when
    malformed."""
    if not isinstance(entry, dict):
        return None
    name = entry.get("name")
    identifiers = entry.get("sourceIdentifiers")
    if not isinstance(name, str) or not name.strip():
        return None
    if not isinstance(identifiers, list) or not all(
        isinstance(identifier, str) for identifier in identifiers
    ):
        return None
    return name.strip(), identifiers


def _timestamp(value: object) -> datetime:
    """An ISO 8601 extended-format date-time, as aware UTC."""
    if not isinstance(value, str) or _DATE_TIME_FORM.fullmatch(value) is None:
        raise NvdRecordStructureError
    try:
        parsed = datetime.fromisoformat(value)
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=UTC)
        return parsed.astimezone(UTC)
    except ValueError, OverflowError:
        # The `fromisoformat` message quotes the input; an offset can move
        # the instant outside the representable UTC range.
        raise NvdRecordStructureError from None


def _is_text_entry(entry: object) -> TypeGuard[dict[str, Any]]:
    """A description entry: an object with string `lang` and `value`."""
    return (
        isinstance(entry, dict)
        and isinstance(entry.get("lang"), str)
        and isinstance(entry.get("value"), str)
    )


def _description(descriptions: object, reasons: set[SkipReason]) -> str | None:
    """The first valid English description; `None` when there is none."""
    if descriptions is None:
        return None
    if not isinstance(descriptions, list):
        reasons.add(INVALID_DESCRIPTION)
        return None
    selected: str | None = None
    for entry in descriptions:
        if not _is_text_entry(entry):
            reasons.add(INVALID_DESCRIPTION)
            continue
        if selected is None and entry["lang"] == _ENGLISH:
            selected = entry["value"]
    return selected


def _provider(source: str | None, source_names: Mapping[str, str] | None) -> str:
    """§ Source identity: the provider of an entry's `.source`; raises
    `_SkippedUnitError` for a missing or unresolved source."""
    if not source:
        raise _SkippedUnitError(MISSING_SOURCE)
    if source == NVD_SOURCE_IDENTIFIER:
        return NVD_PROVIDER_NAME
    name = None if source_names is None else source_names.get(source)
    if name is None:
        raise _SkippedUnitError(UNRESOLVED_SOURCE)
    return name.strip()


def _cvss_candidates(
    metrics: object,
    source_names: Mapping[str, str] | None,
    reasons: set[SkipReason],
) -> list[CVSSAssessmentEntry]:
    """§ CVSS metrics: the accepted entries of the four arrays, the last
    valid one per `source` within an array."""
    if metrics is None:
        return []
    if not isinstance(metrics, dict):
        reasons.add(INVALID_CVSS_METRIC)
        return []
    candidates: list[CVSSAssessmentEntry] = []
    for array_name in CVSS_METRIC_ARRAYS:
        entries = metrics.get(array_name)
        if entries is None:
            continue
        if not isinstance(entries, list):
            reasons.add(INVALID_CVSS_METRIC)
            continue
        accepted: dict[str, CVSSAssessmentEntry] = {}
        for entry in entries:
            try:
                source, candidate = _cvss_candidate(entry, source_names)
            except _SkippedUnitError as skip:
                reasons.add(skip.reason)
                continue
            accepted.pop(source, None)
            accepted[source] = candidate
        candidates.extend(accepted.values())
    return candidates


def _cvss_candidate(
    entry: object, source_names: Mapping[str, str] | None
) -> tuple[str, CVSSAssessmentEntry]:
    """One metric entry checked shape → provider → vector (CVSS metrics
    rules 2-4); raises `_SkippedUnitError` with the first failed check."""
    if not isinstance(entry, dict):
        raise _SkippedUnitError(INVALID_CVSS_METRIC)
    source = entry.get("source")
    cvss_data = entry.get("cvssData")
    if source is not None and not isinstance(source, str):
        raise _SkippedUnitError(INVALID_CVSS_METRIC)
    if cvss_data is not None and not isinstance(cvss_data, dict):
        raise _SkippedUnitError(INVALID_CVSS_METRIC)
    provider = _provider(source, source_names)
    if is_reserved_provider_name(provider):
        raise _SkippedUnitError(RESERVED_PROVIDER)
    vector = None if cvss_data is None else cvss_data.get("vectorString")
    if not isinstance(vector, str) or not vector:
        raise _SkippedUnitError(INVALID_VECTOR)
    try:
        canonical = validate_external_cvss_vector(vector).canonical_vector
    except InvalidCVSSVectorError:
        raise _SkippedUnitError(INVALID_VECTOR) from None
    key = source or ""  # `_provider()` rejected a missing source.
    return key, CVSSAssessmentEntry(provider_name=provider, vector_string=canonical)


def _cwe_candidates(
    weaknesses: object,
    source_names: Mapping[str, str] | None,
    reasons: set[SkipReason],
) -> list[CWEEntry]:
    """§ CWE / weaknesses: the valid candidates, identical ones collapsed."""
    if weaknesses is None:
        return []
    if not isinstance(weaknesses, list):
        reasons.add(INVALID_CWE)
        return []
    candidates: list[CWEEntry] = []
    for weakness in weaknesses:
        try:
            candidates.extend(_weakness_candidates(weakness, source_names, reasons))
        except _SkippedUnitError as skip:
            reasons.add(skip.reason)
    return list(dict.fromkeys(candidates))


def _weakness_candidates(
    weakness: object,
    source_names: Mapping[str, str] | None,
    reasons: set[SkipReason],
) -> list[CWEEntry]:
    """The CWE candidates of one weakness entry; raises `_SkippedUnitError` for an
    invalid entry or source."""
    if not isinstance(weakness, dict):
        raise _SkippedUnitError(INVALID_CWE)
    source = weakness.get("source")
    descriptions = weakness.get("description")
    if source is not None and not isinstance(source, str):
        raise _SkippedUnitError(INVALID_CWE)
    if descriptions is not None and not isinstance(descriptions, list):
        raise _SkippedUnitError(INVALID_CWE)
    values: list[str] = []
    for entry in descriptions or ():
        if not _is_text_entry(entry):
            reasons.add(INVALID_CWE)
            continue
        if entry["lang"] == _ENGLISH and _CWE_PATTERN.fullmatch(entry["value"]):
            values.append(entry["value"])
    if not values:
        return []
    cwe_source = _provider(source, source_names)
    candidates: list[CWEEntry] = []
    for value in values:
        try:
            candidates.append(CWEEntry(cwe_id=value, source=cwe_source))
        except ValidationError:
            reasons.add(INVALID_CWE)
    return candidates


def _unnegated_members(level: object, key: str) -> Sequence[object]:
    """The `key` array of a configuration or node, empty when the level is
    negated; raises `_SkippedUnitError` for an invalid level."""
    if not isinstance(level, dict):
        raise _SkippedUnitError(INVALID_CPE_CONFIGURATION)
    negate = level.get("negate")
    if negate is not None and not isinstance(negate, bool):
        raise _SkippedUnitError(INVALID_CPE_CONFIGURATION)
    if negate:
        return ()
    members = level.get(key)
    if not isinstance(members, list):
        raise _SkippedUnitError(INVALID_CPE_CONFIGURATION)
    return members


def _cpe_match(entry: object) -> CPEMatchEntry | None:
    """A selected entry, `None` for an excluded one; raises `_SkippedUnitError` for an
    invalid entry."""
    if not isinstance(entry, dict):
        raise _SkippedUnitError(INVALID_CPE_MATCH)
    vulnerable = entry.get("vulnerable")
    if not isinstance(vulnerable, bool):
        raise _SkippedUnitError(INVALID_CPE_MATCH)
    if not vulnerable:
        return None
    criteria = entry.get("criteria")
    if (
        not isinstance(criteria, str)
        or len(criteria) > CPE_CRITERIA_MAX_LENGTH
        or contains_nul(criteria)
        or not _encodable(criteria)
    ):
        raise _SkippedUnitError(INVALID_CPE_MATCH)
    match_criteria_id = entry.get("matchCriteriaId")
    if match_criteria_id is None:
        return CPEMatchEntry(criteria=criteria, vulnerable=True)
    if not isinstance(match_criteria_id, str) or not _UUID_FORM.fullmatch(
        match_criteria_id
    ):
        raise _SkippedUnitError(INVALID_CPE_MATCH)
    return CPEMatchEntry(
        criteria=criteria,
        vulnerable=True,
        match_criteria_id=uuid.UUID(match_criteria_id),
    )


def _encodable(value: str) -> bool:
    """Whether `value` has a UTF-8 encoding (no unpaired surrogate)."""
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def _upstream_references(
    references: object, reasons: set[SkipReason]
) -> tuple[AutomaticReferenceInput, ...]:
    """§ References: one candidate per `references[]` element, in array
    order, with its URL and string tags."""
    if references is None:
        return ()
    if not isinstance(references, list):
        reasons.add(INVALID_REFERENCE)
        return ()
    return tuple(_reference(element) for element in references)


def _reference(element: object) -> AutomaticReferenceInput:
    """A non-object element yields a `None` URL, which `reference_service`
    skips as `url_not_string`."""
    if not isinstance(element, dict):
        return AutomaticReferenceInput(url=None)
    tags = element.get("tags")
    upstream_tags: Sequence[str] | None = (
        tuple(t for t in tags if isinstance(t, str)) if isinstance(tags, list) else None
    )
    return AutomaticReferenceInput(url=element.get("url"), upstream_tags=upstream_tags)
