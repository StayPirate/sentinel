"""Typed model and pure extraction of GitHub Advisory Database advisories.

Implements docs/features/tickets/cve-sync-ghsa.md (Field Mapping, Version
range parsing rules, Response Validation, Post-Ingest Package Candidates)
for one advisory object of a `GET /advisories` HTTP 200 array. The module
performs no HTTP, database, or logging work; `SyncGhsaAdvisories`
(`sync_ghsa_advisories.py`) owns the requests, the CVE-ID gate, the
WARNINGs, and the ingestion.

`parse_advisory()` validates only the consumed fields, strictly and without
coercion. A consumed field of another JSON type, a required field that is
absent or `null`, an unparseable or naive date-time, and a non-object root
raise `pydantic.ValidationError`, whose message never renders the input.

`extract()` builds the `CVEIngestPayload` and the reference candidates.
The payload's own validation rejects U+0000 and over-length values
(cve-service.md, CVEIngestPayload Schema); that `pydantic.ValidationError`
propagates as a per-advisory failure. CVSS vectors are passed unparsed:
`upsert_cve()` owns canonical acceptance through the External Base
Reduction and its bounded `invalid_vector` warning.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Annotated, Final

from pydantic import BaseModel, BeforeValidator, ConfigDict

from app.core.enums import CVEExternalIdentifierSource, ReferenceType
from app.core.external_strings import contains_nul
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

PROVIDER_NAME: Final = "GitHub"
"""The CVSS provider and CWE source of every GHSA candidate."""

SOURCE_CONTAINER: Final = "ghsa"
"""The stable `source_container` of the GHSA affected-version scope."""

SOURCE_REFERENCE_TITLE: Final = "GitHub Advisory"

TITLE_MAX_LENGTH: Final = 256
DESCRIPTION_MAX_LENGTH: Final = 65535

_CWE_PATTERN: Final = re.compile(r"CWE-[1-9][0-9]*")
_CWE_MAX_LENGTH: Final = 20

ECOSYSTEMS: Final[Mapping[str, str | None]] = {
    "pip": "PyPI",
    "go": "Go",
    "rust": "crates.io",
    "npm": "npm",
    "maven": "Maven",
    "nuget": "NuGet",
    "composer": "Packagist",
    "rubygems": "RubyGems",
    "pub": "Pub",
    "erlang": "Hex",
    "actions": "GitHub Actions",
    "swift": "SwiftURL",
    "other": None,
}
"""§ Ecosystem normalization: GitHub value → OSSF canonical value (`None`
for `other`). A value outside the mapping is stored as received."""

_LOWER_OPERATORS: Final = frozenset({">=", ">"})
_UPPER_OPERATORS: Final[Mapping[str, bool]] = {"<": False, "<=": True}
_CONSTRAINT: Final = re.compile(r"(<=|>=|<|>|=)\s*([^\s<>=](?:[^<>=]*[^\s<>=])?)")


def _iso_datetime(value: object) -> datetime:
    """An ISO 8601 date-time string with a UTC offset; anything else,
    including a date-time without an offset, is a schema mismatch."""
    if not isinstance(value, str):
        raise ValueError("date-time must be a string")
    if contains_nul(value):
        # `fromisoformat` ignores a trailing U+0000 and accepts it as the
        # date/time separator.
        raise ValueError("date-time must not contain U+0000")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        # The `fromisoformat` message quotes the input.
        raise ValueError("date-time is not ISO 8601") from None
    if parsed.tzinfo is None:
        raise ValueError("date-time without a UTC offset")
    return parsed


type IsoDateTime = Annotated[datetime, BeforeValidator(_iso_datetime)]
"""An ISO 8601 date-time string with an offset (`Z` live), parsed to an
aware `datetime`."""


class _Model(BaseModel):
    model_config = ConfigDict(
        strict=True, extra="ignore", frozen=True, hide_input_in_errors=True
    )


class GhsaPackage(_Model):
    ecosystem: str
    name: str | None = None


class GhsaVulnerability(_Model):
    package: GhsaPackage | None = None
    vulnerable_version_range: str | None = None


class GhsaCvss(_Model):
    vector_string: str | None = None


class GhsaCvssSeverities(_Model):
    cvss_v3: GhsaCvss | None = None
    cvss_v4: GhsaCvss | None = None


class GhsaCwe(_Model):
    cwe_id: str


class GhsaAdvisory(_Model):
    """The consumed fields of one advisory (§ Response Validation).

    `model_fields_set` records which presence-sensitive globals (`summary`,
    `description`, `published_at`, `updated_at`) the advisory carried.
    """

    ghsa_id: str
    html_url: str
    summary: str | None = None
    description: str | None = None
    published_at: IsoDateTime | None = None
    updated_at: IsoDateTime | None = None
    source_code_location: str | None = None
    references: list[str] | None = None
    cwes: list[GhsaCwe] | None = None
    cvss_severities: GhsaCvssSeverities | None = None
    vulnerabilities: list[GhsaVulnerability] | None = None


def element_cve_id(element: object) -> object:
    """The raw `cve_id` of a page element (`None` when absent or `null`,
    or when the element is not an object); the caller applies the CVE-ID
    gate and format check (Algorithm steps 6.d.i-ii)."""
    if isinstance(element, dict):
        return element.get("cve_id")
    return None


def parse_advisory(element: object) -> GhsaAdvisory:
    """Validate one advisory object; raises `pydantic.ValidationError`."""
    return GhsaAdvisory.model_validate(element)


@dataclass(frozen=True, slots=True)
class VersionRange:
    """The `CVEAffectedVersion` bounds of one `vulnerable_version_range`."""

    version: str | None = None
    version_end: str | None = None
    version_end_inclusive: bool | None = None


def parse_version_range(value: str | None) -> VersionRange | None:
    """§ Version range parsing rules; `None` for an unrecognized format.

    A `null`, empty, or blank range is recognized and has no bounds.
    Otherwise the range, split on `,` with each constraint trimmed, must be
    one constraint (`<`, `<=`, `=`, `>=`, `>`) or a lower bound (`>=`,
    `>`) followed by an upper bound (`<`, `<=`), each with a non-empty
    operand that contains no `<`, `>`, or `=`.
    """
    if value is None or not value.strip():
        return VersionRange()
    constraints: list[tuple[str, str]] = []
    for part in value.split(","):
        match = _CONSTRAINT.fullmatch(part.strip())
        if match is None:
            return None
        constraints.append((match.group(1), match.group(2)))
    match constraints:
        case [("=", operand)]:
            return VersionRange(operand, operand, True)
        case [(operator, operand)] if operator in _LOWER_OPERATORS:
            return VersionRange(version=operand)
        case [(operator, operand)] if operator in _UPPER_OPERATORS:
            return VersionRange(None, operand, _UPPER_OPERATORS[operator])
        case [(lower, start), (upper, end)] if (
            lower in _LOWER_OPERATORS and upper in _UPPER_OPERATORS
        ):
            return VersionRange(start, end, _UPPER_OPERATORS[upper])
    return None


def normalize_ecosystem(value: str) -> str | None:
    """§ Ecosystem normalization."""
    return ECOSYSTEMS.get(value, value)


@dataclass(frozen=True, slots=True)
class GhsaExtraction:
    """Everything one advisory contributes, built before any write.

    `skipped_cwes` and `unrecognized_ranges` count the values that the
    fetcher reports with one bounded WARNING each.
    """

    payload: CVEIngestPayload
    source_reference: AutomaticReferenceInput
    upstream_references: list[AutomaticReferenceInput]
    skipped_cwes: int
    unrecognized_ranges: int


def extract(advisory: GhsaAdvisory) -> GhsaExtraction:
    """§ Field Mapping for one validated advisory.

    Raises `pydantic.ValidationError` when the payload rejects a value
    (U+0000, over-length, or a conflicting same-key duplicate).
    """
    fields: dict[str, object] = _global_fields(advisory)
    cvss = _cvss_candidates(advisory.cvss_severities)
    if cvss:
        fields["cvss_assessments"] = cvss
    cwes, skipped_cwes = _cwe_candidates(advisory.cwes or ())
    if cwes:
        fields["cwe_classifications"] = cwes
    fields["external_identifiers"] = [
        ExternalIdentifierEntry(
            source=CVEExternalIdentifierSource.GHSA,
            identifier=advisory.ghsa_id,
            url=advisory.html_url,
        )
    ]
    unrecognized_ranges = 0
    vulnerabilities = advisory.vulnerabilities
    if vulnerabilities is not None:
        entries: list[AffectedVersionEntry] = []
        for vulnerability in vulnerabilities:
            version_range = parse_version_range(vulnerability.vulnerable_version_range)
            if version_range is None:
                unrecognized_ranges += 1
                version_range = VersionRange()
            entries.append(
                _affected_entry(
                    vulnerability, version_range, advisory.source_code_location
                )
            )
        fields["affected_version_operations"] = [
            AffectedVersionScopeOperation(
                source_container=SOURCE_CONTAINER,
                operation=AffectedVersionOperation.REPLACE,
                entries=entries,
            )
        ]
        names = package_names(vulnerabilities)
        if names:
            fields["resolved_packages"] = names
    return GhsaExtraction(
        payload=CVEIngestPayload.model_validate(fields),
        source_reference=AutomaticReferenceInput(
            url=advisory.html_url,
            title=SOURCE_REFERENCE_TITLE,
            explicit_type=ReferenceType.ADVISORY,
        ),
        upstream_references=[
            AutomaticReferenceInput(url=url) for url in advisory.references or ()
        ],
        skipped_cwes=skipped_cwes,
        unrecognized_ranges=unrecognized_ranges,
    )


def _global_fields(advisory: GhsaAdvisory) -> dict[str, object]:
    """Presence-sensitive globals: an absent key is omitted, an explicit
    `null` passes as `None`, and text is truncated to its bound."""
    present = advisory.model_fields_set
    fields: dict[str, object] = {}
    if "summary" in present:
        summary = advisory.summary
        fields["title"] = None if summary is None else summary[:TITLE_MAX_LENGTH]
    if "description" in present:
        description = advisory.description
        fields["description"] = (
            None if description is None else description[:DESCRIPTION_MAX_LENGTH]
        )
    if "published_at" in present:
        fields["published_date"] = advisory.published_at
    if "updated_at" in present:
        fields["modified_date"] = advisory.updated_at
    return fields


def _cvss_candidates(
    severities: GhsaCvssSeverities | None,
) -> list[CVSSAssessmentEntry]:
    """0-2 vector-only candidates gated on a non-null, non-empty vector."""
    if severities is None:
        return []
    return [
        CVSSAssessmentEntry(provider_name=PROVIDER_NAME, vector_string=vector)
        for cvss in (severities.cvss_v3, severities.cvss_v4)
        if cvss is not None and (vector := cvss.vector_string)
    ]


def _cwe_candidates(
    cwes: Sequence[GhsaCwe],
) -> tuple[list[CWEEntry], int]:
    """The valid CWEs and the number of skipped ones."""
    valid: list[CWEEntry] = []
    skipped = 0
    for cwe in cwes:
        if len(cwe.cwe_id) <= _CWE_MAX_LENGTH and _CWE_PATTERN.fullmatch(cwe.cwe_id):
            valid.append(CWEEntry(cwe_id=cwe.cwe_id, source=PROVIDER_NAME))
        else:
            skipped += 1
    return valid, skipped


def _affected_entry(
    vulnerability: GhsaVulnerability,
    version_range: VersionRange,
    source_code_location: str | None,
) -> AffectedVersionEntry:
    """One `ghsa` entry (§ Affected versions); an empty
    `source_code_location` is NULL."""
    package = vulnerability.package
    name = package.name if package is not None else None
    return AffectedVersionEntry(
        product=name,
        package_name=name,
        version=version_range.version,
        version_end=version_range.version_end,
        version_end_inclusive=version_range.version_end_inclusive,
        repo=source_code_location or None,
        ecosystem=normalize_ecosystem(package.ecosystem) if package else None,
    )


def package_names(vulnerabilities: list[GhsaVulnerability]) -> list[str]:
    """§ Post-Ingest Package Candidates: `package.name` values in order,
    deduplicated, with null, empty, and whitespace-only values discarded."""
    names: dict[str, None] = {}
    for vulnerability in vulnerabilities:
        package = vulnerability.package
        if package is not None and package.name and package.name.strip():
            names.setdefault(package.name, None)
    return list(names)
