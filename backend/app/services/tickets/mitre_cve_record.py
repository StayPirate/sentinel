"""Pure mapping of one MITRE `cvelistV5` record file.

Implements docs/features/tickets/cve-sync-mitre.md (Algorithm step 2,
mapping only; CVE JSON 5.x Field Path Mapping: global fields, CNA fields and
the CNA defensive guard, ADP fields and the ADP defensive guard, CISA-ADP
SSVC, KEV, and CWE, scoped affected-version operations, CVE-ID
cross-validation, additive child retention, caller WARNING fields, External
String Admissibility) for one `cves/YEAR/NNNxxx/CVE-YEAR-SEQ.json` file. The
module performs no Git, database, or logging work; `SyncMitreCves` owns the
delta, `upsert_cve()`, `upsert_references()`, the per-item failure outcome,
and the WARNING events built from the facts reported here.

`map_record()` delegates the CVE Record 5.x field parsing to
`cve_record_parser` and builds the `CVEIngestPayload`, the ordered
reference candidates, and the bounded facts of skipped data. Every failure
is a per-item failure: a `MitreRecordError` subclass for a path, content,
state, rejection date, or duplicate that cannot be mapped, or the payload's
`pydantic.ValidationError` for a `title` or description containing U+0000
(cve-service.md, CVEIngestPayload Schema). No message renders the input.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final, Literal

from app.core.enums import CveState, ReferenceType
from app.core.external_strings import contains_nul
from app.core.identifiers import is_valid_cve_id
from app.services.cve_ingest import (
    AffectedVersionContent,
    AffectedVersionEntry,
    AffectedVersionOperation,
    AffectedVersionScopeOperation,
    CVEIngestPayload,
    CVSSAssessmentEntry,
    CWEEntry,
    KEVEntry,
    SSVCEntry,
    affected_version_content,
)
from app.services.cve_record_parser import (
    extract_cve_state,
    extract_dates,
    parse_affected_versions,
    parse_cvss_assessments,
    parse_cwe_classifications,
    parse_description,
    parse_kev_data,
    parse_ssvc_assessment,
    parse_title,
    validate_cve_id,
)
from app.services.reference_service import AutomaticReferenceInput

CISA_ADP_ORG_ID: Final = "134c704f-9b21-4f2e-91b3-4a467353bcc0"
"""The `providerMetadata.orgId` that identifies the CISA-ADP container."""

CISA_ADP_CWE_SOURCE: Final = "adp:CISA-ADP"
"""The CWE `source` of CISA-ADP classifications."""

CNA_SOURCE_CONTAINER: Final = "cna"
"""The CNA affected-version scope shared with `sync_kernel_cves`."""

ADP_SCOPE_PREFIX: Final = "adp:"
"""Prefix of every ADP affected-version scope and CVSS provider."""

SOURCE_REFERENCE_TITLE: Final = "MITRE"

SOURCE_REFERENCE_URL_PATTERN: Final = "https://cve.org/CVERecord?id={cve_id}"
"""The fetcher's `source_reference_url_pattern` (single `{cve_id}`)."""

RECORD_PATH_PATTERN: Final = re.compile(
    r"cves/[0-9]{4}/[0-9]+xxx/(?P<cve_id>CVE-[0-9]{4}-[0-9]{4,})\.json"
)
"""A record path relative to the repository root (Algorithm step 1); apply
with `fullmatch`. Purely structural: bucket and year are not cross-checked."""

CNA_GUARD_REASON: Final = "cna_short_name_missing"

type SsvcField = Literal["Exploitation", "Automatable", "Technical Impact", "version"]
type SsvcSkipReason = Literal["incomplete", "invalid_value"]

SSVC_FIELDS: Final[tuple[SsvcField, ...]] = (
    "Exploitation",
    "Automatable",
    "Technical Impact",
    "version",
)
"""The SSVC fields a skip can report missing, in reporting order."""

_SCOPE_MAX_LENGTH: Final = 100
"""`AffectedVersionScopeOperation.source_container` and the persisted CVSS
provider bound."""

_DECISION_POINTS: Final[tuple[SsvcField, ...]] = SSVC_FIELDS[:3]

_UUID_SHAPE: Final = re.compile(
    r"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}"
)

_NO_ENTRY: Final = object()


class MitreRecordError(ValueError):
    """A record file that cannot be mapped; a per-item failure."""


class MitreRecordPathError(MitreRecordError):
    def __init__(self) -> None:
        super().__init__("path is not a cvelistV5 CVE record path")


class MitreRecordDecodeError(MitreRecordError):
    def __init__(self) -> None:
        super().__init__("record content is not a UTF-8 JSON object")


class MitreRecordStateError(MitreRecordError):
    def __init__(self) -> None:
        super().__init__("record has no recognized state")


class MitreRecordRejectionDateError(MitreRecordError):
    def __init__(self) -> None:
        super().__init__("published record carries a rejection date")


class MitreRecordConflictError(MitreRecordError):
    def __init__(self) -> None:
        super().__init__("record carries conflicting duplicate ADP data")


@dataclass(frozen=True, slots=True)
class SkippedAdp:
    """One ADP entry skipped by the ADP defensive guard."""

    org_id: str | None
    """The received `providerMetadata.orgId` when UUID-shaped, else `None`."""


@dataclass(frozen=True, slots=True)
class CnaGuard:
    """The CNA defensive guard skipped the CNA CVSS and CWE."""

    org_id: str | None
    """The received `providerMetadata.orgId` when UUID-shaped, else `None`."""

    reason: Literal["cna_short_name_missing"] = CNA_GUARD_REASON


@dataclass(frozen=True, slots=True)
class SsvcSkip:
    """A CISA-ADP `ssvc` entry `parse_ssvc_assessment()` could not use."""

    reason: SsvcSkipReason
    missing_fields: tuple[SsvcField, ...]
    """Empty unless `reason` is `incomplete`; in `SSVC_FIELDS` order."""


@dataclass(frozen=True, slots=True)
class MitreRecord:
    """Everything one record contributes, built before any write.

    `cve_id` is the authoritative file-name CVE-ID; `source_reference` and
    `upstream_references` are the `upsert_references()` candidates in
    processing order. `skipped_adps`, `cna_guard`, and `ssvc_skips` are the
    bounded facts of the caller WARNINGs (cve-sync-mitre.md, Caller WARNING
    fields).
    """

    cve_id: str
    payload: CVEIngestPayload
    source_reference: AutomaticReferenceInput
    upstream_references: tuple[AutomaticReferenceInput, ...]
    skipped_adps: tuple[SkippedAdp, ...]
    cna_guard: CnaGuard | None
    ssvc_skips: tuple[SsvcSkip, ...]


@dataclass(frozen=True, slots=True)
class _AdpContribution:
    """The payload data of one valid ADP entry."""

    scope: str
    affected: tuple[AffectedVersionEntry, ...] | None
    cvss: tuple[CVSSAssessmentEntry, ...]
    cwe: tuple[CWEEntry, ...]
    ssvc: SSVCEntry | None
    kev: KEVEntry | None

    def identity(self) -> tuple[object, ...]:
        """The normalized content compared between duplicate scopes."""
        affected: frozenset[AffectedVersionContent] | None = (
            None
            if self.affected is None
            else frozenset(affected_version_content(e) for e in self.affected)
        )
        return (
            affected,
            frozenset((c.provider_name, c.vector_string) for c in self.cvss),
            frozenset((c.cwe_id, c.source) for c in self.cwe),
            self.ssvc,
            self.kev,
        )


def map_record(path: str, content: bytes) -> MitreRecord:
    """Map one record file at its repository `path` (Algorithm step 2).

    Raises a `MitreRecordError` subclass or the payload's
    `pydantic.ValidationError`.
    """
    match = RECORD_PATH_PATTERN.fullmatch(path)
    if match is None or not is_valid_cve_id(match["cve_id"]):
        raise MitreRecordPathError
    record = _decode(content)
    metadata = record.get("cveMetadata")
    cve_id = validate_cve_id(match["cve_id"], metadata)
    cve_state = extract_cve_state(metadata)
    if cve_state is None or not isinstance(metadata, dict):
        raise MitreRecordStateError

    containers = record.get("containers")
    if not isinstance(containers, dict):
        containers = {}
    cna = containers.get("cna")
    if not isinstance(cna, dict):
        cna = {}

    fields = _global_fields(cve_state, metadata, cna)
    cvss: list[CVSSAssessmentEntry] = []
    cwe: list[CWEEntry] = []
    operations: list[AffectedVersionScopeOperation] = []

    cna_affected = cna.get("affected")
    if isinstance(cna_affected, list):
        operations.append(_replace(CNA_SOURCE_CONTAINER, cna_affected))
    cna_guard: CnaGuard | None = None
    short_name = _short_name(cna.get("providerMetadata"))
    if short_name is None:
        cna_guard = CnaGuard(org_id=_org_id(cna.get("providerMetadata")))
    else:
        cvss.extend(parse_cvss_assessments(cna.get("metrics"), short_name))
        cwe.extend(
            parse_cwe_classifications(cna.get("problemTypes"), f"cna:{short_name}")
        )

    contributions, skipped_adps, ssvc_skips = _adp_contributions(containers.get("adp"))
    ssvc = _single({c.ssvc for c in contributions} - {None})
    kev = _single({c.kev for c in contributions} - {None})
    for contribution in contributions:
        if contribution.affected is not None:
            operations.append(
                AffectedVersionScopeOperation(
                    source_container=contribution.scope,
                    operation=AffectedVersionOperation.REPLACE,
                    entries=list(contribution.affected),
                )
            )
        cvss.extend(contribution.cvss)
        cwe.extend(contribution.cwe)

    if cvss:
        fields["cvss_assessments"] = cvss
    if cwe:
        fields["cwe_classifications"] = list(dict.fromkeys(cwe))
    if operations:
        fields["affected_version_operations"] = operations
    if ssvc is not None:
        fields["ssvc_assessment"] = ssvc
    if kev is not None:
        fields["kev_data"] = kev

    return MitreRecord(
        cve_id=cve_id,
        payload=CVEIngestPayload.model_validate(fields),
        source_reference=AutomaticReferenceInput(
            url=SOURCE_REFERENCE_URL_PATTERN.format(cve_id=cve_id),
            title=SOURCE_REFERENCE_TITLE,
            explicit_type=ReferenceType.ADVISORY,
        ),
        upstream_references=_upstream_references(cna.get("references")),
        skipped_adps=skipped_adps,
        cna_guard=cna_guard,
        ssvc_skips=ssvc_skips,
    )


def _decode(content: bytes) -> dict[str, Any]:
    """Strict UTF-8 JSON whose root is an object."""
    try:
        record = json.loads(content.decode("utf-8"))
    except ValueError, RecursionError:
        # `UnicodeDecodeError` and `JSONDecodeError` are `ValueError`s; the
        # latter keeps the document, so the cause is not chained.
        raise MitreRecordDecodeError from None
    if not isinstance(record, dict):
        raise MitreRecordDecodeError
    return record


def _global_fields(
    cve_state: CveState, metadata: Mapping[str, Any], cna: Mapping[str, Any]
) -> dict[str, object]:
    """§ Global CVE fields and the CNA `title`/`descriptions` presence: an
    absent key is omitted, a literal `null` is an explicit clear, and an
    unparseable value is omitted."""
    if cve_state is CveState.PUBLISHED and metadata.get("dateRejected") is not None:
        raise MitreRecordRejectionDateError
    fields: dict[str, object] = {"cve_state": cve_state}
    published, modified, rejected = extract_dates(metadata)
    dates = [
        ("published_date", "datePublished", published),
        ("modified_date", "dateUpdated", modified),
    ]
    if cve_state is CveState.REJECTED:
        # For PUBLISHED the service invariant clears any stored date.
        dates.append(("date_rejected", "dateRejected", rejected))
    for name, key, parsed in dates:
        if key in metadata and (metadata[key] is None or parsed is not None):
            fields[name] = parsed
    if "title" in cna:
        title = cna["title"]
        if title is None:
            fields["title"] = None
        elif isinstance(title, str):
            fields["title"] = parse_title(cna)
    if "descriptions" in cna:
        descriptions = cna["descriptions"]
        description = parse_description(descriptions)
        if descriptions is None:
            fields["description"] = None
        elif description is not None:
            fields["description"] = description
    return fields


def _adp_contributions(
    adps: object,
) -> tuple[list[_AdpContribution], tuple[SkippedAdp, ...], tuple[SsvcSkip, ...]]:
    """The valid ADP contributions with duplicate scopes collapsed, the
    skipped entries, and the SSVC skips of every CISA-ADP container."""
    if not isinstance(adps, list):
        return [], (), ()
    by_scope: dict[str, _AdpContribution] = {}
    skipped: list[SkippedAdp] = []
    ssvc_skips: list[SsvcSkip] = []
    for adp in adps:
        metadata = adp.get("providerMetadata") if isinstance(adp, dict) else None
        name = _short_name(metadata)
        scope = None if name is None else f"{ADP_SCOPE_PREFIX}{name}"
        if (
            not isinstance(adp, dict)
            or not isinstance(metadata, dict)
            or scope is None
            or not _admissible_scope(scope)
        ):
            skipped.append(SkippedAdp(org_id=_org_id(metadata)))
            continue
        cisa = metadata.get("orgId") == CISA_ADP_ORG_ID
        contribution = _contribution(scope, adp, cisa)
        if cisa and contribution.ssvc is None:
            skip = _ssvc_skip(adp.get("metrics"))
            if skip is not None:
                ssvc_skips.append(skip)
        existing = by_scope.get(scope)
        if existing is None:
            by_scope[scope] = contribution
        elif existing.identity() != contribution.identity():
            raise MitreRecordConflictError
    return list(by_scope.values()), tuple(skipped), tuple(ssvc_skips)


def _contribution(scope: str, adp: Mapping[str, Any], cisa: bool) -> _AdpContribution:
    affected = adp.get("affected")
    metrics = adp.get("metrics")
    return _AdpContribution(
        scope=scope,
        affected=(
            tuple(parse_affected_versions(affected))
            if isinstance(affected, list)
            else None
        ),
        cvss=tuple(parse_cvss_assessments(metrics, scope)),
        cwe=(
            tuple(
                parse_cwe_classifications(adp.get("problemTypes"), CISA_ADP_CWE_SOURCE)
            )
            if cisa
            else ()
        ),
        ssvc=parse_ssvc_assessment(metrics) if cisa else None,
        kev=parse_kev_data(metrics) if cisa else None,
    )


def _ssvc_skip(metrics: object) -> SsvcSkip | None:
    """The skip of the last `ssvc` entry `parse_ssvc_assessment()` rejected;
    `None` when the container has no `ssvc` entry. Call only after the parser
    returned `None`."""
    content: object = _NO_ENTRY
    if isinstance(metrics, list):
        for metric in metrics:
            other = metric.get("other") if isinstance(metric, dict) else None
            if isinstance(other, dict) and other.get("type") == "ssvc":
                content = other.get("content")
    if content is _NO_ENTRY:
        return None
    values: dict[str, object] = {}
    if isinstance(content, dict):
        options = content.get("options")
        if isinstance(options, list):
            for option in options:
                if isinstance(option, dict):
                    for point in _DECISION_POINTS:
                        if point in option:
                            values.setdefault(point, option[point])
        values["version"] = content.get("version")
    missing = tuple(
        field
        for field in SSVC_FIELDS
        if values.get(field) is None or values[field] == ""
    )
    return SsvcSkip(
        reason="incomplete" if missing else "invalid_value", missing_fields=missing
    )


def _replace(scope: str, affected: list[Any]) -> AffectedVersionScopeOperation:
    return AffectedVersionScopeOperation(
        source_container=scope,
        operation=AffectedVersionOperation.REPLACE,
        entries=parse_affected_versions(affected),
    )


def _short_name(provider_metadata: object) -> str | None:
    """The trimmed `shortName`; `None` when absent, not a string, or empty."""
    if not isinstance(provider_metadata, dict):
        return None
    short_name = provider_metadata.get("shortName")
    if not isinstance(short_name, str) or not short_name.strip():
        return None
    return short_name.strip()


def _admissible_scope(scope: str) -> bool:
    """A malformed ADP identity cannot form a valid scope or provider."""
    return len(scope) <= _SCOPE_MAX_LENGTH and not contains_nul(scope)


def _org_id(provider_metadata: object) -> str | None:
    """The received `orgId` when it is a UUID-shaped string, else `None`."""
    org_id = (
        provider_metadata.get("orgId") if isinstance(provider_metadata, dict) else None
    )
    if isinstance(org_id, str) and _UUID_SHAPE.fullmatch(org_id):
        return org_id
    return None


def _single[T](values: set[T]) -> T | None:
    """The one distinct value, `None` for none; differing values conflict."""
    if len(values) > 1:
        raise MitreRecordConflictError
    return next(iter(values), None)


def _upstream_references(references: object) -> tuple[AutomaticReferenceInput, ...]:
    """One candidate per `references[]` element, in array order, with its URL
    and string tags.

    A non-object element yields a `None` URL, which `reference_service`
    skips as `url_not_string`; a non-array value yields none.
    """
    if not isinstance(references, list):
        return ()
    return tuple(_reference(element) for element in references)


def _reference(element: object) -> AutomaticReferenceInput:
    if not isinstance(element, dict):
        return AutomaticReferenceInput(url=None)
    tags = element.get("tags")
    upstream_tags: Sequence[str] | None = (
        tuple(t for t in tags if isinstance(t, str)) if isinstance(tags, list) else None
    )
    return AutomaticReferenceInput(url=element.get("url"), upstream_tags=upstream_tags)
