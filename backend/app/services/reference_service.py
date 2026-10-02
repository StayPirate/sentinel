"""Ticket references: classification, automatic ingestion, manual operations.

See `docs/features/tickets/ticket-references.md` for the full
specification. This module implements the trusted automatic ingestion
boundary (`upsert_references()` with deterministic candidate
preparation, the CVE Source Tag Mapping, automatic rejection logging,
and the database merge rules), the manual consumer functions
(`create_reference()`, `update_reference()`, `delete_reference()`,
`list_references()`), their exception hierarchy, and URL-pattern type
classification (`classify_reference_url()`). Automatic and manual inputs
share the Core URL boundary (`app.core.reference_urls`).

Every function accepts the caller's `AsyncSession` and never commits or
rolls back; database exceptions propagate unchanged. No function
performs network I/O: URL validation and classification are lexical
(Security and Privacy).

Manual mutations are explicit opt-outs from `ensure_ticket_operable()`
(Manual-Zone Exception): they lock the parent Ticket as their
serialization root, but never assign a user, reconcile gates, change
Ticket status, exit the manual zone, or register Ticket convergence.
Automatic ingestion acquires no Ticket lock and creates no Ticket audit
event; it runs inside the caller's per-CVE transaction.
"""

from __future__ import annotations

import re
import uuid
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Final

import structlog
from sqlalchemy import ColumnElement, and_, case, false, func, or_, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import ReferenceType, TicketAuditEventType
from app.core.exceptions import ServiceError, TicketNotFoundError
from app.core.identifiers import format_ticket_id, is_valid_cve_id, parse_ticket_id
from app.core.reference_urls import ReferenceUrlError, normalize_reference_url
from app.models.ticket import Ticket
from app.models.ticket_reference import TicketReference
from app.services.ticket_audit_log import TicketAuditLog
from app.services.ticket_mutations import lock_accessible_ticket_by_locator
from app.services.ticket_visibility import TicketCaller, ticket_visibility_condition

logger = structlog.get_logger(__name__)

MANUAL_SOURCE: Final = "manual"
"""The reserved `TicketReference.source` of consumer-managed references."""

SOURCE_MAX_LENGTH: Final = 100
"""Maximum automatic source length (`VARCHAR(100)`)."""

TITLE_MAX_LENGTH: Final = 500
"""Maximum title length (`VARCHAR(500)`)."""

DESCRIPTION_MAX_LENGTH: Final = 2000
"""Maximum description length (`VARCHAR(2000)`)."""

INVALID_METADATA_REASON: Final = "invalid_metadata"
"""Automatic rejection reason for an invalid title or explicit type.

The other reasons of the closed vocabulary (Automatic Rejection Logging)
are the `ReferenceUrlRejection` values of the Core URL boundary.
"""

_UNIQUE_URL_CONSTRAINT: Final = "uq_ticket_reference_ticket_id_url"


class Unset(Enum):
    """Sentinel type of an omitted semantic input field."""

    UNSET = "UNSET"


UNSET: Final = Unset.UNSET
"""An omitted field, distinct from an explicit `None` (Semantic Types)."""


# ---------------------------------------------------------------------------
# Semantic types (ticket-references.md, Semantic Types)
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class AutomaticReferenceInput:
    """One automatic candidate (`AutomaticReferenceInput`).

    An in-memory transfer contract from a CVE fetcher. `url` is typed as
    `object` because the value is untrusted: `None`, non-string, and
    malformed values are skipped with a bounded rejection log rather than
    failing the call. `upstream_tags` are used only for classification and
    never persisted. `explicit_type` has the highest classification
    priority; `None` means no explicit hint.
    """

    url: object
    title: str | None = None
    upstream_tags: Sequence[str] | None = None
    explicit_type: ReferenceType | None = None


@dataclass(frozen=True, slots=True)
class ManualReferenceCreateInput:
    """Manual create input (`ManualReferenceCreateInput`).

    Omitted `title` and `description` persist as `NULL`. An omitted
    `type` (`UNSET`) requests URL-pattern classification; an explicit
    `None` stores `NULL` without classification.
    """

    url: str
    title: str | None = None
    description: str | None = None
    type: ReferenceType | Unset | None = UNSET


@dataclass(frozen=True, slots=True)
class ManualReferenceUpdateInput:
    """Manual partial-update input (`ManualReferenceUpdateInput`).

    `UNSET` preserves the current value; `None` clears a nullable field.
    `url` cannot be `None`, and at least one field must be supplied.
    """

    url: str | Unset = UNSET
    title: str | Unset | None = UNSET
    description: str | Unset | None = UNSET
    type: ReferenceType | Unset | None = UNSET


@dataclass(frozen=True, slots=True)
class TicketReferenceProjection:
    """Persisted reference shape (`TicketReferenceProjection`).

    `ticket_id` is the canonical `SNTL-{n}` identity; `url` is always the
    persisted normalized value.
    """

    id: uuid.UUID
    ticket_id: str
    url: str
    title: str | None
    description: str | None
    type: ReferenceType | None
    source: str
    created_at: datetime
    updated_at: datetime


# ---------------------------------------------------------------------------
# Service exceptions (ticket-references.md, Service Exceptions)
# ---------------------------------------------------------------------------


class ReferenceServiceError(ServiceError):
    """Base class for all exceptions owned by `reference_service`.

    The shared `TicketNotFoundError` inherits from `ServiceError`
    directly; API handlers catch it explicitly (docs/conventions.md,
    Service Exception Conventions).
    """


class ReferenceNotFoundError(ReferenceServiceError):
    """The reference does not exist under the accessible parent Ticket.

    Maps to `404 RESOURCE_NOT_FOUND`. A reference UUID belonging to
    another Ticket is indistinguishable from an unknown UUID.
    """

    def __init__(self) -> None:
        super().__init__("Reference not found.")


class ReferenceNotEditableError(ReferenceServiceError):
    """A consumer attempts to update or delete an automatic reference.

    Maps to `409 RESOURCE_NOT_EDITABLE`.
    """

    def __init__(self) -> None:
        super().__init__("Reference is not editable.")


class ReferenceConflictError(ReferenceServiceError):
    """Another reference already owns the normalized URL on the Ticket.

    Maps to `409 RESOURCE_CONFLICT`.
    """

    def __init__(self) -> None:
        super().__init__("Another reference already uses this URL on the Ticket.")


# ---------------------------------------------------------------------------
# URL-pattern classification (ticket-references.md, URL Pattern Mapping)
# ---------------------------------------------------------------------------

_URL_PATTERN_TABLE: Final[tuple[tuple[str, ReferenceType], ...]] = (
    ("github.com/*/commit/*", ReferenceType.PATCH),
    ("github.com/*/pull/*", ReferenceType.PATCH),
    ("gitlab.com/*/commit/*", ReferenceType.PATCH),
    ("gitlab.com/*/-/merge_requests/*", ReferenceType.PATCH),
    ("git.kernel.org/*/commit/*", ReferenceType.PATCH),
    ("github.com/advisories/GHSA-*", ReferenceType.ADVISORY),
    ("github.com/*/security/advisories/*", ReferenceType.ADVISORY),
    ("nvd.nist.gov/vuln/detail/*", ReferenceType.ADVISORY),
    ("cve.org/CVERecord*", ReferenceType.ADVISORY),
    ("access.redhat.com/security/cve/*", ReferenceType.ADVISORY),
    ("access.redhat.com/errata/*", ReferenceType.ADVISORY),
    ("ubuntu.com/security/CVE-*", ReferenceType.ADVISORY),
    ("www.debian.org/security/*", ReferenceType.ADVISORY),
    ("security.gentoo.org/*", ReferenceType.ADVISORY),
    ("www.oracle.com/security-alerts/*", ReferenceType.ADVISORY),
    ("security.netapp.com/advisory/*", ReferenceType.ADVISORY),
    ("www.zerodayinitiative.com/advisories/*", ReferenceType.ADVISORY),
    ("msrc.microsoft.com/*", ReferenceType.ADVISORY),
    ("support.apple.com/*", ReferenceType.ADVISORY),
    ("www.mozilla.org/*/security/advisories/*", ReferenceType.ADVISORY),
    ("errata.almalinux.org/*", ReferenceType.ADVISORY),
    ("bugzilla.suse.com/*", ReferenceType.ISSUE),
    ("bugzilla.redhat.com/*", ReferenceType.ISSUE),
    ("bugs.launchpad.net/*", ReferenceType.ISSUE),
    ("savannah.gnu.org/bugs/*", ReferenceType.ISSUE),
    ("sourceware.org/bugzilla/*", ReferenceType.ISSUE),
    ("lists.fedoraproject.org/*", ReferenceType.ARTICLE),
    ("www.openwall.com/lists/*", ReferenceType.ARTICLE),
    ("seclists.org/*", ReferenceType.ARTICLE),
    ("www.exploit-db.com/*", ReferenceType.ARTICLE),
    ("lists.apache.org/*", ReferenceType.ARTICLE),
)


def _compile_url_pattern(pattern: str) -> re.Pattern[str]:
    # `*` matches any run of characters, including `/`; every other
    # character is literal. Matching is case-insensitive (the table and
    # the matched `host + path` are compared without case).
    regex = ".*".join(re.escape(part) for part in pattern.split("*"))
    return re.compile(regex, re.IGNORECASE | re.DOTALL)


_URL_PATTERNS: Final[tuple[tuple[re.Pattern[str], ReferenceType], ...]] = tuple(
    (_compile_url_pattern(pattern), reference_type)
    for pattern, reference_type in _URL_PATTERN_TABLE
)

_NORMALIZED_PREFIX: Final = "https://"


def classify_reference_url(normalized_url: str) -> ReferenceType | None:
    """Classify a normalized reference URL by the URL Pattern Mapping.

    `normalized_url` must be the output of `normalize_reference_url()`.
    Each pattern is matched against the URL's host (without port) and
    path, case-insensitively; the query and fragment never participate.
    The empty root path of a normalized URL is matched as `/`. The first
    matching row of the table wins; an unmatched URL returns `None`
    (uncategorized). Pure: no outbound operation.
    """
    if not normalized_url.startswith(_NORMALIZED_PREFIX):
        raise ValueError("classify_reference_url() requires a normalized URL.")
    rest = normalized_url[len(_NORMALIZED_PREFIX) :]
    authority_end = len(rest)
    for delimiter in "/?#":
        index = rest.find(delimiter)
        if index != -1:
            authority_end = min(authority_end, index)
    authority = rest[:authority_end]
    host = authority if authority.startswith("[") else authority.partition(":")[0]
    path = re.split(r"[?#]", rest[authority_end:], maxsplit=1)[0] or "/"
    subject = host + path
    for pattern, reference_type in _URL_PATTERNS:
        if pattern.fullmatch(subject) is not None:
            return reference_type
    return None


# ---------------------------------------------------------------------------
# Tag classification (ticket-references.md, CVE Source Tag Mapping)
# ---------------------------------------------------------------------------

_TAG_TABLE: Final[tuple[tuple[str | None, str | None, ReferenceType | None], ...]] = (
    # (NVD tag, MITRE tag, type); `None` in a tag column means "no form".
    ("Patch", "patch", ReferenceType.PATCH),
    ("Vendor Advisory", "vendor-advisory", ReferenceType.ADVISORY),
    ("Third Party Advisory", "third-party-advisory", ReferenceType.ADVISORY),
    ("US Government Resource", "government-resource", ReferenceType.ADVISORY),
    ("VDB Entry", "vdb-entry", ReferenceType.ADVISORY),
    ("Issue Tracking", "issue-tracking", ReferenceType.ISSUE),
    ("Exploit", "exploit", ReferenceType.ARTICLE),
    ("Mailing List", "mailing-list", ReferenceType.ARTICLE),
    ("Release Notes", "release-notes", ReferenceType.ARTICLE),
    ("Technical Description", "technical-description", ReferenceType.ARTICLE),
    ("Mitigation", "mitigation", ReferenceType.ARTICLE),
    ("Press/Media Coverage", "media-coverage", ReferenceType.ARTICLE),
    ("Tool Signature", "signature", ReferenceType.ARTICLE),
    ("Broken Link", "broken-link", None),
    ("Not Applicable", "not-applicable", None),
    ("Permissions Required", "permissions-required", None),
    ("URL Repurposed", None, None),
    ("Product", "product", None),
    (None, "customer-entitlement", None),
    (None, "related", None),
)

# Recognized tags that map to a type. Tags mapped to `NULL` are omitted:
# they never prevent a later tag or URL-pattern classification.
_TAG_TYPES: Final[dict[str, ReferenceType]] = {
    tag: reference_type
    for nvd_tag, mitre_tag, reference_type in _TAG_TABLE
    if reference_type is not None
    for tag in (nvd_tag, mitre_tag)
    if tag is not None
}

_TAG_TYPE_PRIORITY: Final[tuple[ReferenceType, ...]] = (
    ReferenceType.PATCH,
    ReferenceType.ADVISORY,
    ReferenceType.ISSUE,
    ReferenceType.ARTICLE,
)


def classify_reference_tags(tags: Sequence[object] | None) -> ReferenceType | None:
    """Classify upstream reference tags by the CVE Source Tag Mapping.

    Tags match exactly one of the listed NVD Title Case or MITRE
    kebab-case forms. Unknown tags, non-string tags, and tags mapped to
    `NULL` are ignored. When the recognized tags map to different types,
    priority is `patch`, `advisory`, `issue`, then `article`. Returns
    `None` when no tag maps to a type. Pure: no outbound operation.
    """
    if not tags:
        return None
    found = {_TAG_TYPES.get(tag) for tag in tags if isinstance(tag, str)}
    for reference_type in _TAG_TYPE_PRIORITY:
        if reference_type in found:
            return reference_type
    return None


# ---------------------------------------------------------------------------
# Input-only validation (ticket-references.md, URL Normalization)
# ---------------------------------------------------------------------------


def _require_authenticated(caller: TicketCaller) -> uuid.UUID:
    if caller.user_id is None:
        raise ValueError("Manual reference mutations require an authenticated caller.")
    return caller.user_id


def _validate_text(value: object, *, field: str, max_length: int) -> str | None:
    """Validate a nullable title or description; never trims."""
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"Reference {field} must be a string or null.")
    if not 1 <= len(value) <= max_length:
        raise ValueError(
            f"Reference {field} must be between 1 and {max_length} characters."
        )
    if not value.strip():
        raise ValueError(f"Reference {field} must not be whitespace-only.")
    return value


def _validate_type(value: object) -> ReferenceType | None:
    if value is None or isinstance(value, ReferenceType):
        return value
    raise ValueError("Reference type must be a ReferenceType or null.")


# ---------------------------------------------------------------------------
# Persistence helpers
# ---------------------------------------------------------------------------


def _is_url_conflict(exc: IntegrityError) -> bool:
    """Whether `exc` is exactly the `(ticket_id, url)` uniqueness violation."""
    constraint_name = getattr(exc.driver_exception, "constraint_name", None)
    return bool(constraint_name == _UNIQUE_URL_CONSTRAINT)


async def _write_reference(session: AsyncSession, stage: Callable[[], None]) -> None:
    """Stage and flush one reference write inside a savepoint.

    The Ticket lock already decides conflicts between writers that lock
    the Ticket. A writer that does not hold the Ticket lock can still own
    the normalized URL first; only that exact uniqueness violation becomes
    `ReferenceConflictError`, and rolling back to the savepoint keeps the
    caller's transaction usable. Every other integrity error propagates
    unchanged.

    `stage` adds or modifies the row only after the savepoint exists:
    `begin_nested()` flushes already pending changes before it creates
    the savepoint, so a write staged earlier would run outside it.
    """
    try:
        async with session.begin_nested():
            stage()
            await session.flush()
    except IntegrityError as exc:
        if _is_url_conflict(exc):
            raise ReferenceConflictError() from exc
        raise


async def _url_owned_by_other(
    session: AsyncSession,
    *,
    ticket_id: uuid.UUID,
    url: str,
    exclude_id: uuid.UUID | None = None,
) -> bool:
    statement = select(TicketReference.id).where(
        TicketReference.ticket_id == ticket_id, TicketReference.url == url
    )
    if exclude_id is not None:
        statement = statement.where(TicketReference.id != exclude_id)
    return (await session.execute(statement.limit(1))).first() is not None


async def _load_editable_reference(
    session: AsyncSession, *, ticket_id: uuid.UUID, reference_id: uuid.UUID
) -> TicketReference:
    """Resolve the reference under its locked parent and require `manual`."""
    reference = (
        await session.execute(
            select(TicketReference)
            .where(
                TicketReference.id == reference_id,
                TicketReference.ticket_id == ticket_id,
            )
            .execution_options(populate_existing=True)
        )
    ).scalar_one_or_none()
    if reference is None:
        raise ReferenceNotFoundError()
    if reference.source != MANUAL_SOURCE:
        raise ReferenceNotEditableError()
    return reference


def _reference_type(value: str | None) -> ReferenceType | None:
    return None if value is None else ReferenceType(value)


async def _project(
    session: AsyncSession, reference: TicketReference, *, sequence_id: int
) -> TicketReferenceProjection:
    # Server-generated timestamps are expired by the flush; reload the
    # persisted row so the projection reflects the stored state.
    await session.refresh(reference)
    return TicketReferenceProjection(
        id=reference.id,
        ticket_id=format_ticket_id(sequence_id),
        url=reference.url,
        title=reference.title,
        description=reference.description,
        type=_reference_type(reference.type),
        source=reference.source,
        created_at=reference.created_at,
        updated_at=reference.updated_at,
    )


# ---------------------------------------------------------------------------
# Automatic ingestion (ticket-references.md, Automatic Ingestion)
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class _PreparedCandidate:
    """A validated, classified, coalesced automatic candidate."""

    url: str
    title: str | None
    type: ReferenceType | None


def _prepare_candidate(
    candidate: AutomaticReferenceInput, *, cve_id: str, source: str
) -> _PreparedCandidate | None:
    """Validate and classify one candidate; log and return `None` if invalid."""
    try:
        url = normalize_reference_url(candidate.url)
    except ReferenceUrlError as exc:
        _log_rejection(cve_id=cve_id, source=source, reason=exc.reason.value)
        return None
    try:
        title = _validate_text(
            candidate.title, field="title", max_length=TITLE_MAX_LENGTH
        )
        explicit_type = _validate_type(candidate.explicit_type)
    except ValueError:
        _log_rejection(cve_id=cve_id, source=source, reason=INVALID_METADATA_REASON)
        return None
    reference_type = (
        explicit_type
        or classify_reference_tags(candidate.upstream_tags)
        or classify_reference_url(url)
    )
    return _PreparedCandidate(url=url, title=title, type=reference_type)


def _log_rejection(*, cve_id: str, source: str, reason: str) -> None:
    # Only the bounded context: never the URL, title, or exception text
    # (Automatic Rejection Logging).
    logger.warning(
        "automatic_reference_rejected", cve_id=cve_id, source=source, reason=reason
    )


def _prepare_candidates(
    source_reference: AutomaticReferenceInput | None,
    upstream_references: Sequence[AutomaticReferenceInput],
    *,
    cve_id: str,
    source: str,
) -> list[_PreparedCandidate]:
    """Deterministic Candidate Preparation steps 1-4.

    The source candidate comes first, followed by the upstream candidates
    in their original order. Invalid candidates are logged and removed
    without reordering the others. Same-URL candidates coalesce into the
    first one, which keeps its position and every non-NULL field; later
    duplicates only fill its missing `title` or `type`.
    """
    ordered = ([] if source_reference is None else [source_reference]) + list(
        upstream_references
    )
    prepared: dict[str, _PreparedCandidate] = {}
    for candidate in ordered:
        current = _prepare_candidate(candidate, cve_id=cve_id, source=source)
        if current is None:
            continue
        first = prepared.get(current.url)
        if first is None:
            prepared[current.url] = current
            continue
        if first.title is None:
            first.title = current.title
        if first.type is None:
            first.type = current.type
    return list(prepared.values())


async def _merge_candidate(
    session: AsyncSession,
    *,
    ticket_id: uuid.UUID,
    source: str,
    candidate: _PreparedCandidate,
) -> None:
    """Apply one prepared candidate by the Database Merge Rules.

    One `INSERT ... ON CONFLICT DO UPDATE` resolves the current serialized
    row for `(ticket_id, url)` atomically, including against concurrent
    inserts and deletes, so no unique violation aborts the caller's
    transaction:

    - no row: insert with the automatic `source` and `description = NULL`;
    - same automatic source: non-NULL candidate fields replace current
      values;
    - different automatic source: candidate fields fill only `NULL`
      current fields;
    - manual row: untouched (excluded by the `WHERE`).

    `source` and `description` of an existing row never change. The
    `WHERE` also skips updates that change nothing, so `updated_at`
    (written explicitly: ORM `onupdate` does not apply to `ON CONFLICT`)
    advances only on an effective update.
    """
    candidate_type = None if candidate.type is None else candidate.type.value
    same_source = TicketReference.source == source
    new_title = case(
        (same_source, func.coalesce(candidate.title, TicketReference.title)),
        else_=func.coalesce(TicketReference.title, candidate.title),
    )
    new_type = case(
        (same_source, func.coalesce(candidate_type, TicketReference.type)),
        else_=func.coalesce(TicketReference.type, candidate_type),
    )
    statement = (
        pg_insert(TicketReference)
        .values(
            ticket_id=ticket_id,
            url=candidate.url,
            title=candidate.title,
            description=None,
            type=candidate_type,
            source=source,
        )
        .on_conflict_do_update(
            constraint=_UNIQUE_URL_CONSTRAINT,
            set_={"title": new_title, "type": new_type, "updated_at": func.now()},
            where=and_(
                TicketReference.source != MANUAL_SOURCE,
                or_(
                    new_title.is_distinct_from(TicketReference.title),
                    new_type.is_distinct_from(TicketReference.type),
                ),
            ),
        )
    )
    await session.execute(statement)


async def upsert_references(
    session: AsyncSession,
    ticket_id: uuid.UUID,
    cve_id: str,
    source: str,
    source_reference: AutomaticReferenceInput | None,
    upstream_references: Sequence[AutomaticReferenceInput],
) -> None:
    """Persist the automatic references of one CVE ingestion.

    Category A trusted system mutation (ticket-references.md,
    `upsert_references()`; Automatic Ingestion).

    Q1: `ticket_id` is the internal UUID of the Ticket established by the
    CVE ingestion workflow; `cve_id` is the canonical CVE ID, used only for
    rejection logging; `source` is the calling fetcher's stable
    `BaseFetcher.name`; `source_reference` is the optional source
    candidate; `upstream_references` are the upstream candidates in their
    original order.

    Q2: the source and CVE-ID contract checks run before any persistent
    work. Every candidate is then prepared (validated, classified, and
    coalesced) before any database comparison; an invalid candidate logs
    one WARNING with only the CVE ID, source, and closed reason and is
    skipped. Prepared candidates are merged in order by the Database
    Merge Rules, one atomic conflict-aware statement each. No Ticket lock
    is acquired (the caller may already hold it), no parent lookup is
    performed, no stale row is deleted, and no Ticket audit event is
    created. Re-invocation with the same candidates is a no-op once every
    fill opportunity is satisfied.

    Q4: always `None`. With no valid candidate, nothing is written.

    Q6: `ValueError` for a `source` that is not a non-empty string of at
    most 100 characters different from `manual`, or for a non-canonical
    `cve_id`, before persistent work. Unexpected database errors
    (including the foreign-key violation for an absent Ticket),
    cancellation, and programming errors propagate unchanged; the caller
    rolls back the complete per-CVE transaction.
    """
    if (
        not isinstance(source, str)
        or not 1 <= len(source) <= SOURCE_MAX_LENGTH
        or source == MANUAL_SOURCE
    ):
        raise ValueError(
            "Automatic reference source must be a fetcher name of 1 to "
            f"{SOURCE_MAX_LENGTH} characters other than '{MANUAL_SOURCE}'."
        )
    if not is_valid_cve_id(cve_id):
        raise ValueError("Automatic reference cve_id must be a canonical CVE ID.")

    candidates = _prepare_candidates(
        source_reference, upstream_references, cve_id=cve_id, source=source
    )
    for candidate in candidates:
        await _merge_candidate(
            session, ticket_id=ticket_id, source=source, candidate=candidate
        )


# ---------------------------------------------------------------------------
# Manual mutations (ticket-references.md, Service Layer)
# ---------------------------------------------------------------------------


async def create_reference(
    session: AsyncSession,
    ticket_id: str,
    caller: TicketCaller,
    input: ManualReferenceCreateInput,
) -> TicketReferenceProjection:
    """Create one manual reference on an accessible Ticket.

    Category A consumer mutation (ticket-references.md,
    `create_reference()`; Manual Mutation Ordering).

    Q1: `ticket_id` is the public `SNTL-{n}` locator; `caller` is the
    request-resolved caller, which must be authenticated (its user is the
    audit actor); `input` is the semantic create input.

    Q2: input-only validation (caller, URL normalization, title,
    description, type) precedes any database access. The Ticket is then
    locked `FOR UPDATE` as the first persistent read, followed by
    locked-current accessibility and the normalized-URL conflict check.
    The type is the explicit supplied value (including `None`) or, when
    omitted, the URL-pattern classification. The row is inserted with
    `source = manual` and exactly one `reference_added` event (acting
    user, `old_value = NULL`, `new_value` = normalized URL, `comment` and
    `detail` `NULL`); both are flushed. No operability check, assignment,
    reconciliation, or convergence registration.

    Q4: returns the persisted projection.

    Q6: `ValueError` for an anonymous caller or invalid semantic input
    (before database access); `TicketNotFoundError` for a malformed,
    missing, or inaccessible Ticket; `ReferenceConflictError` when any
    reference (manual or automatic) owns the normalized URL. Audit
    validation and database errors propagate.
    """
    actor_id = _require_authenticated(caller)
    url = normalize_reference_url(input.url)
    title = _validate_text(input.title, field="title", max_length=TITLE_MAX_LENGTH)
    description = _validate_text(
        input.description, field="description", max_length=DESCRIPTION_MAX_LENGTH
    )
    reference_type = (
        classify_reference_url(url)
        if isinstance(input.type, Unset)
        else _validate_type(input.type)
    )

    ticket = await lock_accessible_ticket_by_locator(session, ticket_id, caller)
    if await _url_owned_by_other(session, ticket_id=ticket.id, url=url):
        raise ReferenceConflictError()

    reference = TicketReference(
        ticket_id=ticket.id,
        url=url,
        title=title,
        description=description,
        type=None if reference_type is None else reference_type.value,
        source=MANUAL_SOURCE,
    )
    await _write_reference(session, lambda: session.add(reference))
    await TicketAuditLog.log_event(
        session,
        ticket_id=ticket.id,
        event_type=TicketAuditEventType.REFERENCE_ADDED,
        user_id=actor_id,
        new_value=url,
    )
    await session.flush()
    return await _project(session, reference, sequence_id=ticket.sequence_id)


async def update_reference(
    session: AsyncSession,
    ticket_id: str,
    reference_id: uuid.UUID,
    caller: TicketCaller,
    input: ManualReferenceUpdateInput,
) -> TicketReferenceProjection:
    """Apply a partial update to one manual reference.

    Category A consumer mutation (ticket-references.md,
    `update_reference()`; Manual Mutation Ordering).

    Q1: `ticket_id` is the public `SNTL-{n}` locator; `reference_id` is
    the nested reference UUID; `caller` must be authenticated; `input`
    preserves supplied-field information.

    Q2: input-only validation precedes database access. Under the Ticket
    lock, in order: locked-current accessibility; scoped lookup of
    `(ticket, reference_id)`; `source = manual`; a conflict for a supplied
    URL owned by another reference; comparison with locked-current
    values. A supplied URL without a supplied type preserves the type. If
    every supplied value equals the current value, nothing is written
    and `updated_at` is unchanged. Otherwise the row is updated and one
    event per changed field is emitted in the order
    `reference_url_changed` (`detail = NULL`), `reference_type_changed`,
    `reference_title_changed`, `reference_description_changed` (each with
    `detail = {"url": <post-update URL>}`), all with the acting user and
    `comment = NULL`, and flushed.

    Q4: returns the persisted projection (current state for a no-op).

    Q6: `ValueError` for an anonymous caller or invalid semantic input;
    `TicketNotFoundError`; `ReferenceNotFoundError` for a missing or
    wrong-parent reference; `ReferenceNotEditableError` for an automatic
    reference; `ReferenceConflictError`. Audit validation and database
    errors propagate.
    """
    actor_id = _require_authenticated(caller)
    if all(
        isinstance(value, Unset)
        for value in (input.url, input.title, input.description, input.type)
    ):
        raise ValueError("At least one field must be provided.")
    if input.url is None:
        raise ValueError("Reference url cannot be null.")
    url = UNSET if isinstance(input.url, Unset) else normalize_reference_url(input.url)
    title = (
        UNSET
        if isinstance(input.title, Unset)
        else _validate_text(input.title, field="title", max_length=TITLE_MAX_LENGTH)
    )
    description = (
        UNSET
        if isinstance(input.description, Unset)
        else _validate_text(
            input.description,
            field="description",
            max_length=DESCRIPTION_MAX_LENGTH,
        )
    )
    reference_type = (
        UNSET if isinstance(input.type, Unset) else _validate_type(input.type)
    )

    ticket = await lock_accessible_ticket_by_locator(session, ticket_id, caller)
    reference = await _load_editable_reference(
        session, ticket_id=ticket.id, reference_id=reference_id
    )
    if (
        not isinstance(url, Unset)
        and url != reference.url
        and await _url_owned_by_other(
            session, ticket_id=ticket.id, url=url, exclude_id=reference.id
        )
    ):
        raise ReferenceConflictError()

    old_url = reference.url
    old_type = reference.type
    old_title = reference.title
    old_description = reference.description
    new_type = (
        old_type
        if isinstance(reference_type, Unset)
        else (None if reference_type is None else reference_type.value)
    )
    new_url = old_url if isinstance(url, Unset) else url
    new_title = old_title if isinstance(title, Unset) else title
    new_description = old_description if isinstance(description, Unset) else description
    changes: list[tuple[TicketAuditEventType, str | None, str | None]] = [
        (event_type, old, new)
        for event_type, old, new in (
            (TicketAuditEventType.REFERENCE_URL_CHANGED, old_url, new_url),
            (TicketAuditEventType.REFERENCE_TYPE_CHANGED, old_type, new_type),
            (TicketAuditEventType.REFERENCE_TITLE_CHANGED, old_title, new_title),
            (
                TicketAuditEventType.REFERENCE_DESCRIPTION_CHANGED,
                old_description,
                new_description,
            ),
        )
        if old != new
    ]
    if not changes:
        return await _project(session, reference, sequence_id=ticket.sequence_id)

    def stage() -> None:
        reference.url = new_url
        reference.type = new_type
        reference.title = new_title
        reference.description = new_description

    await _write_reference(session, stage)
    for event_type, old_value, new_value in changes:
        await TicketAuditLog.log_event(
            session,
            ticket_id=ticket.id,
            event_type=event_type,
            user_id=actor_id,
            old_value=old_value,
            new_value=new_value,
            detail=(
                None
                if event_type is TicketAuditEventType.REFERENCE_URL_CHANGED
                else {"url": new_url}
            ),
        )
    await session.flush()
    return await _project(session, reference, sequence_id=ticket.sequence_id)


async def delete_reference(
    session: AsyncSession,
    ticket_id: str,
    reference_id: uuid.UUID,
    caller: TicketCaller,
) -> None:
    """Delete one manual reference.

    Category A consumer mutation (ticket-references.md,
    `delete_reference()`; Manual Mutation Ordering).

    Q2: after the caller check, under the Ticket lock, in order:
    locked-current accessibility, scoped `(ticket, reference_id)` lookup,
    and `source = manual`. The row is deleted and exactly one
    `reference_deleted` event (acting user, `old_value` = normalized URL,
    `new_value`, `comment`, and `detail` `NULL`) is flushed with it.

    Q6: `ValueError` for an anonymous caller; `TicketNotFoundError`;
    `ReferenceNotFoundError` (including after a committed delete);
    `ReferenceNotEditableError`. Audit validation and database errors
    propagate.
    """
    actor_id = _require_authenticated(caller)
    ticket = await lock_accessible_ticket_by_locator(session, ticket_id, caller)
    reference = await _load_editable_reference(
        session, ticket_id=ticket.id, reference_id=reference_id
    )
    url = reference.url
    await session.delete(reference)
    await session.flush()
    await TicketAuditLog.log_event(
        session,
        ticket_id=ticket.id,
        event_type=TicketAuditEventType.REFERENCE_DELETED,
        user_id=actor_id,
        old_value=url,
    )
    await session.flush()


# ---------------------------------------------------------------------------
# Read (ticket-references.md, `list_references()`)
# ---------------------------------------------------------------------------

_TYPE_PRIORITY: Final = case(
    {
        ReferenceType.ADVISORY.value: 0,
        ReferenceType.PATCH.value: 1,
        ReferenceType.ISSUE.value: 2,
        ReferenceType.ARTICLE.value: 3,
    },
    value=TicketReference.type,
    else_=4,
)


async def list_references(
    session: AsyncSession,
    ticket_id: str,
    caller: TicketCaller,
    source: str | None,
    type: ReferenceType | None,
    type_was_supplied: bool,
) -> list[TicketReferenceProjection]:
    """List every visible reference of one accessible Ticket.

    Category B read (ticket-references.md, `list_references()`).

    Q1: `ticket_id` is the public `SNTL-{n}` locator; `caller` is the
    request-resolved caller (anonymous allowed); `source` is an optional
    exact, case-sensitive source; `type` an optional valid type;
    `type_was_supplied = True` with `type = None` represents a supplied
    value that was not a valid `ReferenceType`.

    Q3: one SQL statement selects the parent Ticket under the canonical
    visibility predicate, LEFT JOINed to its references with the filters
    (combined with AND) in the join condition, so parent accessibility
    and the returned rows come from one PostgreSQL snapshot. Ordered by
    type priority (`advisory`, `patch`, `issue`, `article`, `NULL`), then
    `created_at`, then `id`, ascending. No pagination, lock, flush, or
    event.

    Q4: the complete list; empty only for an accessible Ticket (including
    when an invalid `type` was supplied).

    Q6: `TicketNotFoundError` for a malformed, missing, or inaccessible
    Ticket, before any filter outcome. Database errors propagate.
    """
    sequence_id = parse_ticket_id(ticket_id)
    if sequence_id is None:
        raise TicketNotFoundError()

    join_conditions: list[ColumnElement[bool]] = [
        TicketReference.ticket_id == Ticket.id
    ]
    if type is not None:
        join_conditions.append(TicketReference.type == type.value)
    elif type_was_supplied:
        join_conditions.append(false())
    if source is not None:
        join_conditions.append(TicketReference.source == source)

    # The read neither flushes the caller's pending state (autoflush is
    # suspended) nor writes anything itself.
    with session.no_autoflush:
        rows = (
            await session.execute(
                select(
                    Ticket.sequence_id,
                    TicketReference.id,
                    TicketReference.url,
                    TicketReference.title,
                    TicketReference.description,
                    TicketReference.type,
                    TicketReference.source,
                    TicketReference.created_at,
                    TicketReference.updated_at,
                )
                .select_from(Ticket)
                .outerjoin(TicketReference, and_(*join_conditions))
                .where(
                    Ticket.sequence_id == sequence_id,
                    ticket_visibility_condition(caller),
                )
                .order_by(
                    _TYPE_PRIORITY, TicketReference.created_at, TicketReference.id
                )
            )
        ).all()
    if not rows:
        raise TicketNotFoundError()
    public_ticket_id = format_ticket_id(sequence_id)
    return [
        TicketReferenceProjection(
            id=row.id,
            ticket_id=public_ticket_id,
            url=row.url,
            title=row.title,
            description=row.description,
            type=_reference_type(row.type),
            source=row.source,
            created_at=row.created_at,
            updated_at=row.updated_at,
        )
        for row in rows
        if row.id is not None
    ]
