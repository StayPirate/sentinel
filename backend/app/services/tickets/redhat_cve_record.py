"""Typed models and pure extraction of one Red Hat Security Data CVE record.

Implements docs/features/tickets/cve-sync-redhat.md (Algorithm steps 2-9,
Field Mapping, Response Validation) for the body of one
`GET /hydra/rest/securitydata/cve/{CVE-ID}.json` HTTP 200 response. The
module performs no HTTP, database, or logging work; `SyncRedhatCves`
(`sync_redhat_cves.py`) owns the request, the candidate skip events, and
the ingestion.

`parse_response()` validates only the consumed fields, strictly and
without coercion; a consumed field of another JSON type, or a non-object
root, raises `pydantic.ValidationError`, whose message never renders the
input. `extract()` then applies each field's own gate, so a value counts
as extractable data only when it passes that gate.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Final

from pydantic import BaseModel, ConfigDict

from app.services.cvss import validate_cvss_vector
from app.services.ticket_mutations_errors import InvalidCVSSVectorError

PROVIDER_NAME: Final = "Red Hat"
"""The constant CVSS provider and CWE source of every Red Hat value."""

VECTOR_MAX_LENGTH: Final = 200
"""Received-length bound of a vector, checked before any parser call
(cve-service.md, Phase 1 > CVSS assessment ingestion)."""

INVALID_VECTOR_REASON: Final = "invalid_vector"
INVALID_CWE_REASON: Final = "invalid_cwe"

_CWE_PATTERN: Final = re.compile(r"CWE-[1-9][0-9]*")
"""Algorithm step 6, applied with `fullmatch` (`^CWE-[1-9][0-9]*$`)."""

_CWE_MAX_LENGTH: Final = 20
"""`CWEEntry.cwe_id` bound: a longer matching identifier is an invalid CWE
value rather than a payload failure that would discard the other data."""


class _ConsumedFields(BaseModel):
    """Strict, unknown-field-ignoring shape of consumed fields only."""

    model_config = ConfigDict(
        strict=True, extra="ignore", frozen=True, hide_input_in_errors=True
    )


class RedhatCvss3(_ConsumedFields):
    cvss3_scoring_vector: str | None = None


class RedhatCvss(_ConsumedFields):
    cvss_scoring_vector: str | None = None


class RedhatBugzilla(_ConsumedFields):
    url: str | None = None
    description: str | None = None


class RedhatPackageState(_ConsumedFields):
    package_name: str | None = None


class RedhatCVERecord(_ConsumedFields):
    """The consumed fields of the response root object (§ Response
    Validation). An absent or `null` field is not observed."""

    cvss3: RedhatCvss3 | None = None
    cvss: RedhatCvss | None = None
    cwe: str | None = None
    references: list[str] | None = None
    bugzilla: RedhatBugzilla | None = None
    package_state: list[RedhatPackageState] | None = None


@dataclass(frozen=True, slots=True)
class BugzillaLink:
    url: str
    title: str | None


@dataclass(frozen=True, slots=True)
class RedhatExtraction:
    """The values of one record that passed their own gates.

    `cvss_vectors` holds canonical vectors (v3 before v2); `skipped` holds
    one closed reason per rejected vector or CWE, in algorithm order.
    """

    cvss_vectors: tuple[str, ...]
    cwe_id: str | None
    reference_urls: tuple[str, ...]
    bugzilla: BugzillaLink | None
    package_names: tuple[str, ...]
    skipped: tuple[str, ...]

    @property
    def has_extractable_data(self) -> bool:
        """Whether any value passed its gate (§ Error Handling). The
        synthetic source reference never counts."""
        return bool(
            self.cvss_vectors
            or self.cwe_id is not None
            or self.reference_urls
            or self.bugzilla is not None
            or self.package_names
        )


def parse_response(data: object) -> RedhatCVERecord:
    """Validate a decoded response body (§ Response Validation).

    Raises `pydantic.ValidationError` for a non-object root or a consumed
    field of another JSON type; unconsumed fields are not validated.
    """
    return RedhatCVERecord.model_validate(data)


def extract(record: RedhatCVERecord) -> RedhatExtraction:
    """Apply Algorithm steps 2-9 to one validated record."""
    skipped: list[str] = []
    vectors: list[str] = []
    for vector in (
        record.cvss3.cvss3_scoring_vector if record.cvss3 is not None else None,
        record.cvss.cvss_scoring_vector if record.cvss is not None else None,
    ):
        if vector is None or not vector.strip():
            continue
        canonical = _canonical_vector(vector)
        if canonical is None:
            skipped.append(INVALID_VECTOR_REASON)
        else:
            vectors.append(canonical)

    cwe_id: str | None = None
    if record.cwe is not None:
        if _is_valid_cwe(record.cwe):
            cwe_id = record.cwe
        else:
            skipped.append(INVALID_CWE_REASON)

    return RedhatExtraction(
        cvss_vectors=tuple(vectors),
        cwe_id=cwe_id,
        reference_urls=tuple(_reference_lines(record.references or ())),
        bugzilla=_bugzilla_link(record.bugzilla),
        package_names=tuple(_package_names(record.package_state or ())),
        skipped=tuple(skipped),
    )


def _canonical_vector(vector: str) -> str | None:
    """The canonical parser's output, or `None` for a rejected vector."""
    if len(vector) > VECTOR_MAX_LENGTH:
        return None
    try:
        return validate_cvss_vector(vector).canonical_vector
    except InvalidCVSSVectorError:
        return None


def _is_valid_cwe(value: str) -> bool:
    return len(value) <= _CWE_MAX_LENGTH and _CWE_PATTERN.fullmatch(value) is not None


def _reference_lines(elements: Sequence[str]) -> list[str]:
    """Step 7: split each element on `\\n`, a `\\r\\n` pair being one break.

    Only the `\\r` of a `\\r\\n` pair is removed; any other `\\r` stays for
    the URL boundary to reject. Empty and whitespace-only lines are
    dropped; every other line is kept verbatim, in element and line order.
    """
    lines: list[str] = []
    for element in elements:
        segments = element.split("\n")
        for position, segment in enumerate(segments):
            if position < len(segments) - 1 and segment.endswith("\r"):
                segment = segment[:-1]
            if segment.strip():
                lines.append(segment)
    return lines


def _bugzilla_link(bugzilla: RedhatBugzilla | None) -> BugzillaLink | None:
    """Step 8. A whitespace-only `url` is treated as empty: it cannot be a
    reference URL and is not counted as extractable data."""
    if bugzilla is None or bugzilla.url is None or not bugzilla.url.strip():
        return None
    return BugzillaLink(url=bugzilla.url, title=bugzilla.description)


def _package_names(package_state: Sequence[RedhatPackageState]) -> list[str]:
    """Step 9: drop `null`, empty, whitespace-only, and `/`-containing
    names, then deduplicate in first-seen order. Kept names are unmodified."""
    names: dict[str, None] = {}
    for entry in package_state:
        name = entry.package_name
        if name is None or not name.strip() or "/" in name:
            continue
        names.setdefault(name, None)
    return list(names)
