"""Pure mapping of one Linux Kernel CNA `vulns.git` record file.

Implements docs/features/tickets/cve-sync-kernel.md (Algorithm steps 2b-2d
and 2f-2g, Rejection Handling, CVE JSON Field Mapping, External String
Admissibility) for one `cve/{published,rejected}/YEAR/CVE-YEAR-ID.json`
file. The module performs no Git, database, or logging work;
`SyncKernelCves` owns the delta, `upsert_cve()`, `upsert_references()`, and
the per-item failure outcome.

`map_record()` derives `cve_state` from the directory, delegates the CVE
Record 5.x field parsing to `cve_record_parser`, and builds the
`CVEIngestPayload` and the ordered reference candidates. Every failure is
a per-item failure: a `KernelRecordError` subclass for a path, content, or
state that cannot be mapped, or the payload's `pydantic.ValidationError`
for a `title` or description containing U+0000 (cve-service.md,
CVEIngestPayload Schema). Neither message renders the input.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Final

from app.core.enums import CveState, ReferenceType
from app.core.identifiers import is_valid_cve_id
from app.services.cve_ingest import (
    AffectedVersionOperation,
    AffectedVersionScopeOperation,
    CVEIngestPayload,
)
from app.services.cve_record_parser import (
    extract_cve_state,
    parse_affected_versions,
    parse_cvss_assessments,
    parse_description,
    parse_title,
    validate_cve_id,
)
from app.services.reference_service import AutomaticReferenceInput

PROVIDER_NAME: Final = "Linux"
"""The hardcoded CVSS provider (`providerMetadata.shortName` is absent)."""

RESOLVED_PACKAGE: Final = "kernel-source"
"""The SUSE source package of every kernel CVE."""

SOURCE_CONTAINER: Final = "cna"
"""The affected-version scope shared with `sync_mitre_cves`."""

SOURCE_REFERENCE_TITLE: Final = "Linux Kernel CNA"

SOURCE_REFERENCE_URL_TEMPLATE: Final = (
    "https://git.kernel.org/pub/scm/linux/security/vulns.git/tree/"
    "cve/{state}/{year}/{cve_id}.json"
)
"""Algorithm step 2f; `{state}` is the directory the file was found in."""

RECORD_PATH_PATTERN: Final = re.compile(
    r"cve/(?P<state>published|rejected)/(?P<year>[0-9]{4})/"
    r"(?P<cve_id>CVE-(?P=year)-[0-9]{4,})\.json"
)
"""A record path relative to the repository root (Algorithm step 1); apply
with `fullmatch` so `cve/testing/...` and sibling files never match."""

_REJECTED_DIRECTORY: Final = "rejected"


class KernelRecordError(ValueError):
    """A record file that cannot be mapped; a per-item failure."""


class KernelRecordPathError(KernelRecordError):
    def __init__(self) -> None:
        super().__init__("path is not a vulns.git CVE record path")


class KernelRecordDecodeError(KernelRecordError):
    def __init__(self) -> None:
        super().__init__("record content is not a UTF-8 JSON object")


class KernelRecordStateError(KernelRecordError):
    def __init__(self) -> None:
        super().__init__("published record has no recognized state")


@dataclass(frozen=True, slots=True)
class KernelRecord:
    """Everything one record contributes, built before any write.

    `cve_id` is the authoritative file-name CVE-ID; `source_reference` and
    `upstream_references` are the `upsert_references()` candidates in
    processing order (Algorithm step 2g).
    """

    cve_id: str
    payload: CVEIngestPayload
    source_reference: AutomaticReferenceInput
    upstream_references: tuple[AutomaticReferenceInput, ...]


def map_record(path: str, content: bytes) -> KernelRecord:
    """Map one record file at its repository `path` (Algorithm steps
    2b-2d, 2f-2g).

    Raises `KernelRecordPathError`, `KernelRecordDecodeError`,
    `KernelRecordStateError`, or the payload's `pydantic.ValidationError`.
    """
    match = RECORD_PATH_PATTERN.fullmatch(path)
    if match is None or not is_valid_cve_id(match["cve_id"]):
        raise KernelRecordPathError
    directory, year = match["state"], match["year"]
    record = _decode(content)
    metadata = record.get("cveMetadata")
    cve_id = validate_cve_id(match["cve_id"], metadata)

    cve_state = (
        CveState.REJECTED
        if directory == _REJECTED_DIRECTORY
        else extract_cve_state(metadata)
    )
    if cve_state is None:
        raise KernelRecordStateError

    containers = record.get("containers")
    cna = containers.get("cna") if isinstance(containers, dict) else None
    if not isinstance(cna, dict):
        cna = {}

    payload = CVEIngestPayload.model_validate(_payload_fields(cve_state, cna))
    return KernelRecord(
        cve_id=cve_id,
        payload=payload,
        source_reference=AutomaticReferenceInput(
            url=SOURCE_REFERENCE_URL_TEMPLATE.format(
                state=directory, year=year, cve_id=cve_id
            ),
            title=SOURCE_REFERENCE_TITLE,
            explicit_type=ReferenceType.ADVISORY,
        ),
        upstream_references=_upstream_references(cna.get("references")),
    )


def _decode(content: bytes) -> dict[str, Any]:
    """Strict UTF-8 JSON whose root is an object."""
    try:
        record = json.loads(content.decode("utf-8"))
    except ValueError, RecursionError:
        # `UnicodeDecodeError` and `JSONDecodeError` are `ValueError`s; the
        # latter keeps the document, so the cause is not chained.
        raise KernelRecordDecodeError from None
    if not isinstance(record, dict):
        raise KernelRecordDecodeError
    return record


def _payload_fields(cve_state: CveState, cna: Mapping[str, Any]) -> dict[str, object]:
    """§ CVE JSON Field Mapping. Dates are never read; an absent global is
    omitted and a literal `null` is an explicit clear."""
    fields: dict[str, object] = {
        "cve_state": cve_state,
        "resolved_packages": [RESOLVED_PACKAGE],
    }
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
    cvss = parse_cvss_assessments(cna.get("metrics"), PROVIDER_NAME)
    if cvss:
        fields["cvss_assessments"] = cvss
    affected = cna.get("affected")
    if isinstance(affected, list):
        fields["affected_version_operations"] = [
            AffectedVersionScopeOperation(
                source_container=SOURCE_CONTAINER,
                operation=AffectedVersionOperation.REPLACE,
                entries=parse_affected_versions(affected),
            )
        ]
    return fields


def _upstream_references(references: object) -> tuple[AutomaticReferenceInput, ...]:
    """One URL-only candidate per `references[]` element, in array order.

    A non-object element yields a `None` URL, which `reference_service`
    skips as `url_not_string`; a non-array value yields none.
    """
    if not isinstance(references, list):
        return ()
    return tuple(
        AutomaticReferenceInput(
            url=element.get("url") if isinstance(element, dict) else None
        )
        for element in references
    )
