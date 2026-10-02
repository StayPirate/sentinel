"""Source-neutral CVE ingestion values: the payload, result, and handoff.

See `docs/features/tickets/cve-service.md` (CVEIngestPayload Schema;
Canonical Payload Duplicate Handling; Affected-Version Snapshot
Operations; UpsertResult; PostIngestTasks). These are service-layer
values consumed and produced by `cve_service.upsert_cve()` and
`cve_service.build_post_ingest_tasks()`. They live under `app/services/`
rather than `app/schemas/` because a Service may not import a Schema
(`docs/architecture.md`, Backend Layer Architecture); "Pydantic schema"
in the specification names the model kind, not the layer.

Every payload model is frozen, forbids unknown fields, and hides input
values in validation errors, so a rejected payload cannot leak upstream
content into a log. Construction raises `pydantic.ValidationError` for
the canonical model-validation failures: explicit-null `cve_state`, an
explicit `PUBLISHED` with a non-null `date_rejected`, malformed
affected-version operation shapes, and conflicting same-key child
content whose canonical key is available here (CWE, external
identifiers, affected-version operations and entries). Conflicting CVSS
candidates are detected by `upsert_cve()`, which owns their
canonicalization. Naive datetimes are interpreted as UTC and every
datetime is normalized to aware UTC.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, date, datetime
from enum import StrEnum
from typing import Annotated, Any, Final, Self, TypedDict

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, model_validator

from app.core.enums import (
    CVEExternalIdentifierSource,
    CveState,
    SSVCAutomatable,
    SSVCExploitation,
    SSVCTechnicalImpact,
)
from app.models.cve import CVE
from app.models.ticket import Ticket


def _to_utc(value: datetime) -> datetime:
    """A naive value is UTC; an aware value is converted to UTC."""
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


type UTCDateTime = Annotated[datetime, AfterValidator(_to_utc)]
"""A payload instant, always aware UTC after validation."""

_PAYLOAD_CONFIG: Final = ConfigDict(
    extra="forbid", frozen=True, hide_input_in_errors=True
)


class _PayloadModel(BaseModel):
    model_config = _PAYLOAD_CONFIG


class CVSSAssessmentEntry(_PayloadModel):
    """Untrusted vector-only candidate from an external provider.

    Both fields accept any object: an individually invalid candidate is
    skipped by `upsert_cve()` without invalidating valid siblings.
    """

    provider_name: object
    vector_string: object


class CWEEntry(_PayloadModel):
    cwe_id: str = Field(pattern=r"^CWE-[1-9][0-9]*$", max_length=20)
    source: str = Field(max_length=100)


class AffectedVersionEntry(_PayloadModel):
    """One entry of a CVE JSON 5.x `affected[].versions[]` array."""

    vendor: str | None = Field(None, max_length=512)
    product: str | None = None
    package_url: str | None = Field(None, max_length=2048)
    collection_url: str | None = Field(None, max_length=2048)
    package_name: str | None = Field(None, max_length=2048)
    repo: str | None = Field(None, max_length=2048)
    version: str | None = None
    version_type: str | None = Field(None, max_length=128)
    version_end: str | None = None
    version_end_inclusive: bool | None = None
    program_files: list[str] | None = None
    cpe: str | None = Field(None, max_length=2048)
    ecosystem: str | None = Field(None, max_length=50)
    status: str | None = Field(None, max_length=20)
    default_status: str | None = Field(None, max_length=20)


class AffectedVersionOperation(StrEnum):
    """Snapshot operation of one affected-version scope (not persisted)."""

    REPLACE = "replace"
    REMOVE = "remove"


class AffectedVersionScopeOperation(_PayloadModel):
    """Authoritative operation for one stable affected-version scope.

    `replace` requires `entries` (which may be empty); `remove` forbids
    them, including an empty list.
    """

    source_container: str = Field(max_length=100)
    operation: AffectedVersionOperation
    entries: list[AffectedVersionEntry] | None = None

    @model_validator(mode="after")
    def _check_shape(self) -> Self:
        replace = self.operation is AffectedVersionOperation.REPLACE
        if replace and self.entries is None:
            raise ValueError("A replace operation requires entries.")
        if not replace and self.entries is not None:
            raise ValueError("A remove operation must not supply entries.")
        return self


class SSVCEntry(_PayloadModel):
    exploitation: SSVCExploitation
    automatable: SSVCAutomatable
    technical_impact: SSVCTechnicalImpact
    version: str = Field(max_length=10)
    assessed_at: UTCDateTime | None = None


class KEVEntry(_PayloadModel):
    date_added: date
    reference_url: str | None = Field(None, max_length=2048)


class EPSSEntry(_PayloadModel):
    score: float = Field(ge=0.0, le=1.0)
    percentile: float = Field(ge=0.0, le=1.0)
    assessed_at: date


class CPEMatchEntry(_PayloadModel):
    """NVD CPE package candidate; transported, never persisted."""

    criteria: str = Field(max_length=2048)
    vulnerable: bool
    match_criteria_id: uuid.UUID | None = None


class ExternalIdentifierEntry(_PayloadModel):
    source: CVEExternalIdentifierSource
    identifier: str = Field(max_length=100)
    url: str | None = Field(None, max_length=2048)


# ---------------------------------------------------------------------------
# Canonical child normalization (cve-service.md, Canonical Payload Duplicate
# Handling; Affected-Version Snapshot Operations)
# ---------------------------------------------------------------------------

AFFECTED_VERSION_FIELDS: Final[tuple[str, ...]] = (
    "vendor",
    "product",
    "package_url",
    "collection_url",
    "package_name",
    "repo",
    "version",
    "version_type",
    "version_end",
    "version_end_inclusive",
    "program_files",
    "cpe",
    "ecosystem",
    "status",
    "default_status",
)
"""Every persisted `CVEAffectedVersion` entry column, in content order."""

type AffectedVersionContent = tuple[Any, ...]
"""The complete persisted content of one entry, in `AFFECTED_VERSION_FIELDS`
order, with `program_files` as a tuple so the value is hashable."""


def affected_version_content(values: Any) -> AffectedVersionContent:
    """The hashable persisted content of an entry or a stored row."""
    content = []
    for name in AFFECTED_VERSION_FIELDS:
        value = getattr(values, name)
        if name == "program_files" and value is not None:
            value = tuple(value)
        content.append(value)
    return tuple(content)


def _affected_version_key(entry: AffectedVersionEntry) -> tuple[Any, ...]:
    """The entry conflict key: absent `vendor`/`product` differ from an empty
    string, absent `version_type`/`version`/`version_end`/`package_name`
    equal one."""
    return (
        entry.vendor,
        entry.product,
        entry.version_type or "",
        entry.version or "",
        entry.version_end or "",
        entry.package_name or "",
    )


@dataclass(frozen=True, slots=True)
class NormalizedScopeOperation:
    """One validated affected-version scope operation.

    `entries` is `None` for `remove` and otherwise the deduplicated
    complete snapshot in first-occurrence order.
    """

    source_container: str
    operation: AffectedVersionOperation
    entries: tuple[AffectedVersionEntry, ...] | None

    def content(self) -> frozenset[AffectedVersionContent]:
        """The snapshot as a set of entry contents (empty for `remove`)."""
        return frozenset(affected_version_content(e) for e in self.entries or ())


_AFFECTED_VERSION_KEY_FIELDS: Final = frozenset(
    {"vendor", "product", "version_type", "version", "version_end", "package_name"}
)


def _affected_version_semantic_content(entry: AffectedVersionEntry) -> tuple[Any, ...]:
    """The persisted fields outside the entry conflict key, which decide
    whether two same-key entries are identical or contradictory."""
    return tuple(
        value
        for name, value in zip(
            AFFECTED_VERSION_FIELDS, affected_version_content(entry), strict=True
        )
        if name not in _AFFECTED_VERSION_KEY_FIELDS
    )


def _normalized_entries(
    entries: Sequence[AffectedVersionEntry],
) -> tuple[AffectedVersionEntry, ...]:
    """Same-key entries with identical semantic content collapse to the first
    occurrence; differing semantic content is contradictory."""
    by_key: dict[tuple[Any, ...], tuple[Any, ...]] = {}
    unique: list[AffectedVersionEntry] = []
    for entry in entries:
        key = _affected_version_key(entry)
        content = _affected_version_semantic_content(entry)
        existing = by_key.get(key)
        if existing is None:
            by_key[key] = content
            unique.append(entry)
        elif existing != content:
            raise ValueError(
                "Affected-version entries share one conflict key with differing"
                " content."
            )
    return tuple(unique)


def normalize_affected_version_operations(
    operations: Sequence[AffectedVersionScopeOperation] | None,
) -> tuple[NormalizedScopeOperation, ...]:
    """The validated operations, at most one per scope, ordered by
    `source_container` code point.

    Identical entries and identical duplicate operations collapse.
    Raises `ValueError` for same-key entries with differing content or
    differing operations for one scope.
    """
    by_scope: dict[str, NormalizedScopeOperation] = {}
    for operation in operations or ():
        entries = operation.entries
        normalized_entries = None if entries is None else _normalized_entries(entries)
        normalized = NormalizedScopeOperation(
            source_container=operation.source_container,
            operation=operation.operation,
            entries=normalized_entries,
        )
        existing = by_scope.get(operation.source_container)
        if existing is None:
            by_scope[operation.source_container] = normalized
        elif (
            existing.operation is not normalized.operation
            or existing.content() != normalized.content()
        ):
            raise ValueError("Differing operations target one affected-version scope.")
    return tuple(by_scope[scope] for scope in sorted(by_scope))


def normalize_cwe_classifications(
    entries: Sequence[CWEEntry] | None,
) -> tuple[tuple[str, str], ...]:
    """Unique `(cwe_id, source)` keys in code-point order. The key is the
    complete content, so same-key entries are always identical."""
    return tuple(sorted({(entry.cwe_id, entry.source) for entry in entries or ()}))


def normalize_external_identifiers(
    entries: Sequence[ExternalIdentifierEntry] | None,
) -> tuple[ExternalIdentifierEntry, ...]:
    """Unique `(source, identifier)` entries in code-point key order.

    Raises `ValueError` when one key carries differing `url` content.
    """
    by_key: dict[tuple[str, str], ExternalIdentifierEntry] = {}
    for entry in entries or ():
        key = (entry.source.value, entry.identifier)
        existing = by_key.get(key)
        if existing is None:
            by_key[key] = entry
        elif existing.url != entry.url:
            raise ValueError(
                "External identifiers share one (source, identifier) key with"
                " differing content."
            )
    return tuple(by_key[key] for key in sorted(by_key))


class CVEIngestPayload(_PayloadModel):
    """Canonical structure for CVE data flowing into `cve_service`.

    All fields optional; fetchers populate only what their source provides.
    `model_fields_set` is the authority for global-field presence.
    """

    title: str | None = Field(None, max_length=256)
    description: str | None = None
    published_date: UTCDateTime | None = None
    modified_date: UTCDateTime | None = None
    cve_state: CveState | None = None
    date_rejected: UTCDateTime | None = None

    cvss_assessments: list[CVSSAssessmentEntry] | None = None
    cwe_classifications: list[CWEEntry] | None = None
    affected_version_operations: list[AffectedVersionScopeOperation] | None = None
    external_identifiers: list[ExternalIdentifierEntry] | None = None
    ssvc_assessment: SSVCEntry | None = None
    kev_data: KEVEntry | None = None
    epss_score: EPSSEntry | None = None

    cpe_matches: list[CPEMatchEntry] | None = None
    resolved_packages: list[str] | None = None

    @model_validator(mode="after")
    def _check_invariants(self) -> Self:
        if "cve_state" in self.model_fields_set and self.cve_state is None:
            raise ValueError("cve_state must not be explicitly null.")
        if self.cve_state is CveState.PUBLISHED and self.date_rejected is not None:
            raise ValueError("A PUBLISHED cve_state cannot carry date_rejected.")
        normalize_affected_version_operations(self.affected_version_operations)
        normalize_external_identifiers(self.external_identifiers)
        return self


# ---------------------------------------------------------------------------
# Result and post-ingest handoff (cve-service.md, UpsertResult;
# PostIngestTasks)
# ---------------------------------------------------------------------------


class UpsertAction(StrEnum):
    """Effective CVE-owned persistence outcome of one `upsert_cve()` call."""

    CREATED = "created"
    UPDATED = "updated"
    UNCHANGED = "unchanged"


class UpsertResult(BaseModel):
    """Transaction-local result of `upsert_cve()`.

    `ticket` is always present. `action` excludes source status, Ticket
    creation, priority, references, delegated audit, and post-ingest work.
    """

    model_config = ConfigDict(arbitrary_types_allowed=True, frozen=True)

    cve: CVE
    ticket: Ticket
    action: UpsertAction


class SerializedCPEMatch(TypedDict):
    criteria: str
    vulnerable: bool
    match_criteria_id: str | None


@dataclass(frozen=True)
class PostIngestTasks:
    """Pure, JSON-serializable package-candidate handoff.

    Every value is a candidate requiring later package-domain validation.
    """

    ticket_id: str
    cpe_matches: list[SerializedCPEMatch]
    affected_cpes: list[str]
    vendor_products: list[list[str]]
    resolved_packages: list[str]
