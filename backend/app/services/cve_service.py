"""CVE service: CVE identifier resolution, accessibility-constrained reads,
and the placeholder-CVE data guarantee.

See `docs/features/tickets/cve-service.md` (Ownership; CVE Read and
Accessibility Boundary; On-Demand Fetch: `ensure_cve_exists()`; CVE Upsert
Serialization; Caller Validation Responsibility; Service Read Contracts;
Exceptions) for the module contract, and
`docs/features/tickets/cvss-scoring.md` (Get CVSS Assessments for a CVE)
for the CVSS read implemented here. `list_cves()`, `get_cve_detail()`, and
`list_cve_sources()` implement the CVE List, CVE Detail, and Global CVE
Source Listing read contracts; the CVE detail shares the `CVEDetail`
projection of `cve_projection` with the Ticket detail, so this module
never imports `ticket_service`. `resolve_cve_locator()` is the
preliminary `{cve_id}` resolution of the CVE mutation paths, whose locked
mutation in `ticket_mutations` makes the authoritative accessibility
decision; `ticket_mutations` never imports this module.

CVE accessibility is a projection of the one canonical Ticket visibility
predicate (`docs/features/identity/rbac.md`, Scope and Confidential Ticket
Visibility): a CVE without an associated Ticket is visible, and a CVE with
an associated Ticket is visible exactly when that Ticket is visible to the
caller. The projection composes `ticket_visibility_condition()` and never
defines a second predicate. It constrains the same database selection that
supplies the response, so no preliminary access decision ever authorizes a
later unconstrained query.

Reads are Category B: they create no row or audit event, acquire no lock,
never flush, commit, or roll back, and perform no network or Redis I/O.
Each read selects its rows (and any total) in one SQL statement, so they
derive from one coherent PostgreSQL observation. Unexpected
database and programming exceptions propagate unchanged. Results are
semantic service values, not Pydantic schemas.

`ensure_cve_exists()` is the pure placeholder-CVE data guarantee: it may
create one `CVE` row and, in its lock-aware form, acquire the CVE root lock
for the calling Ticket workflow, but it never commits or rolls back and
performs no registry, Redis, task, or external I/O.
"""

from __future__ import annotations

import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from decimal import Decimal
from typing import Any, Final

import structlog
from sqlalchemy import ColumnElement, Row, and_, false, func, or_, select, true
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import (
    CVESortField,
    CVESourceFetchStatus,
    CVESourceSortField,
    CveState,
    CVSSAssessmentSeverity,
    CVSSVersion,
    Severity,
    SortOrder,
)
from app.core.exceptions import CVENotFoundError, ServiceError
from app.core.identifiers import format_ticket_id, is_valid_cve_id
from app.models.cve import CVE
from app.models.cve_cvss_assessment import CVECVSSAssessment
from app.models.cve_source import CVESource
from app.models.ticket import Ticket
from app.services.cve_projection import (
    CODE_POINT_COLLATION,
    CVEDetailProjection,
    cve_detail_columns,
    cve_detail_from_row,
    join_cve_evidence,
)
from app.services.cvss import (
    CVSSBaseMetrics,
    EligibilityResolution,
    ParsedCVSSVector,
    SeverityResolution,
    resolve_eligibility_score,
    resolve_severity_score,
    validate_cvss_vector,
)
from app.services.settings import (
    RequiredSystemSettingMissingError,
    default_cvss_version_select,
)
from app.services.sql_patterns import LIKE_ESCAPE, escape_like
from app.services.ticket_mutations_errors import InvalidCVSSVectorError
from app.services.ticket_severity import severity_rank_expression
from app.services.ticket_visibility import TicketCaller, ticket_visibility_condition

logger = structlog.get_logger(__name__)

# Canonical list order of the bounded assessment set: version
# 4.0 > 3.1 > 3.0 > 2.0 (cvss-scoring.md, Get CVSS Assessments for a CVE).
_LIST_VERSION_RANK: Final[Mapping[CVSSVersion, int]] = {
    CVSSVersion.V4_0: 0,
    CVSSVersion.V3_1: 1,
    CVSSVersion.V3_0: 2,
    CVSSVersion.V2_0: 3,
}


class CVEServiceError(ServiceError):
    """Base of the module-owned operational `cve_service` exceptions
    (cve-service.md, Exceptions). The shared `CVENotFoundError` does not
    inherit from it."""


class CVEIdFormatError(CVEServiceError):
    """A CVE-ID reaching a service boundary is malformed.

    Raised when the value does not match `^CVE-[0-9]{4}-[0-9]{4,}$` or
    exceeds 20 characters (`core.identifiers.is_valid_cve_id()`). It is a
    defense-in-depth backstop: callers pre-validate and map request-body
    input to `422 CVE_INVALID_FORMAT` themselves (cve-service.md, Caller
    Validation Responsibility). The message is static and never includes
    the rejected value.
    """

    def __init__(self) -> None:
        super().__init__("CVE identifier format is invalid.")


class CVSSAssessmentIntegrityError(RuntimeError):
    """A persisted `CVECVSSAssessment` row violates its vector-derived unit.

    `docs/data-model.md` (CVECVSSAssessment, Notes) requires `cvss_version`,
    `score`, `severity`, and the canonical `vector_string` to be one
    consistent vector-derived unit written only through the shared parser.
    A row that breaks that invariant is corrupt data, not a caller error:
    it is not a `ServiceError`, is never mapped to a domain error code, and
    therefore surfaces as the global `500 INTERNAL_ERROR`. The message is
    static; the identifying details go to the structured ERROR log emitted
    before raising.
    """

    def __init__(self) -> None:
        super().__init__(
            "A persisted CVSS assessment violates its vector-derived unit."
        )


@dataclass(frozen=True, slots=True)
class CVSSAssessmentProjection:
    """One persisted assessment with its metrics expanded from the vector."""

    id: uuid.UUID
    provider_name: str
    cvss_version: CVSSVersion
    score: Decimal
    severity: CVSSAssessmentSeverity
    vector_string: str
    metrics: CVSSBaseMetrics
    created_at: datetime
    updated_at: datetime


@dataclass(frozen=True, slots=True)
class CVECVSSAssessments:
    """The bounded CVSS composite of one accessible CVE.

    `assessments` is the complete set in canonical list order.
    `default_cvss_version` is the setting observed in the same database
    view; `severity` (absent for an empty set) and `eligibility` are the
    pure resolutions of the complete set under that version.
    """

    assessments: tuple[CVSSAssessmentProjection, ...]
    default_cvss_version: CVSSVersion
    severity: SeverityResolution | None
    eligibility: EligibilityResolution


def _cve_accessibility_condition(caller: TicketCaller) -> ColumnElement[bool]:
    """CVE accessibility for a statement that outer-joins the CVE's Ticket.

    The enclosing statement must select from `CVE` outer-joined to `Ticket`
    on `Ticket.cve_id = CVE.id` (unique, so at most one Ticket). No joined
    Ticket means a ticketless, public CVE; otherwise the canonical Ticket
    predicate decides. For an anonymous caller that predicate evaluates no
    grant or maintainer branch.
    """
    return or_(Ticket.id.is_(None), ticket_visibility_condition(caller))


type _StoredAssessment = Row[Any] | CVECVSSAssessment
"""A persisted assessment: a row of the one-statement read (the assessment
`id` labeled `id`) or a `CVECVSSAssessment` instance."""


@dataclass(frozen=True, slots=True)
class ResolvedCVE:
    """An accessible CVE selected by its public CVE-ID.

    `id` is the internal CVE UUID, usable only as an internal service
    locator; it is never a consumer response field.
    """

    id: uuid.UUID
    cve_id: str


def _mismatched_fields(
    row: _StoredAssessment, parsed: ParsedCVSSVector | None
) -> list[str]:
    """Names of stored columns that disagree with the re-parsed vector."""
    if parsed is None:
        return ["vector_string"]
    mismatched = []
    if parsed.canonical_vector != row.vector_string:
        mismatched.append("vector_string")
    if parsed.version.value != row.cvss_version:
        mismatched.append("cvss_version")
    if parsed.score != row.score:
        mismatched.append("score")
    if parsed.severity.value != row.severity:
        mismatched.append("severity")
    return mismatched


def _project_assessment(
    cve_id: str, row: _StoredAssessment
) -> CVSSAssessmentProjection:
    """Expand one persisted row, verifying its vector-derived unit.

    The stored vector must parse through the shared parser and already be
    canonical, and the stored version, score, and severity must equal the
    values derived from it. Any disagreement is logged at ERROR with the
    identifiers an operator needs to repair the row (never the vector
    content) and raises `CVSSAssessmentIntegrityError`.
    """
    try:
        parsed: ParsedCVSSVector | None = validate_cvss_vector(row.vector_string)
    except InvalidCVSSVectorError:
        parsed = None
    mismatched = _mismatched_fields(row, parsed)
    if parsed is None or mismatched:
        logger.error(
            "cvss_assessment_integrity_violation",
            cve_id=cve_id,
            assessment_id=str(row.id),
            fields=mismatched,
        )
        raise CVSSAssessmentIntegrityError()
    return CVSSAssessmentProjection(
        id=row.id,
        provider_name=row.provider_name,
        cvss_version=parsed.version,
        score=parsed.score,
        severity=parsed.severity,
        vector_string=parsed.canonical_vector,
        metrics=parsed.metrics,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


def _list_order(assessment: CVSSAssessmentProjection) -> tuple[int, str]:
    """Version rank, then provider by Unicode code point (Python `str` order)."""
    return (_LIST_VERSION_RANK[assessment.cvss_version], assessment.provider_name)


async def get_cvss_assessments(
    db: AsyncSession,
    *,
    cve_id: str,
    caller: TicketCaller,
) -> CVECVSSAssessments:
    """Read the CVSS composite of one accessible CVE.

    See `docs/features/tickets/cvss-scoring.md` (Get CVSS Assessments for a
    CVE). `cve_id` is the raw `{cve_id}` path value; `caller` is the
    request-resolved caller information.

    1. A value rejected by `core.identifiers.is_valid_cve_id()` raises
       `CVENotFoundError` without any query. Lookup is otherwise by the
       unique `CVE.cve_id`; the internal CVE UUID is never accepted.
    2. One statement selects the CVE, its outer-joined Ticket constrained by
       the CVE accessibility projection, every assessment row, and the
       `default_cvss_version` setting as a scalar subquery, so all of them
       come from one coherent PostgreSQL view. No row means the CVE is
       missing or inaccessible: `CVENotFoundError`.
    3. An accessible CVE whose setting row is absent raises
       `RequiredSystemSettingMissingError`.
    4. Each row is verified and expanded (`_project_assessment()`); the set
       is ordered by version `4.0 > 3.1 > 3.0 > 2.0`, then provider name by
       Unicode code point, independent of database collation.
    5. Severity and eligibility are the pure resolutions of the complete,
       unfiltered set under the observed default version.

    Raises:
        CVENotFoundError: Malformed, missing, or inaccessible CVE.
        RequiredSystemSettingMissingError: The setting row is absent.
        CVSSAssessmentIntegrityError: A persisted row violates its
            vector-derived unit.
        ValueError: The persisted setting is not `3.1` or `4.0`.
    """
    if not is_valid_cve_id(cve_id):
        raise CVENotFoundError()

    statement = (
        select(
            default_cvss_version_select()
            .scalar_subquery()
            .label("default_cvss_version"),
            CVECVSSAssessment.id,
            CVECVSSAssessment.provider_name,
            CVECVSSAssessment.cvss_version,
            CVECVSSAssessment.score,
            CVECVSSAssessment.severity,
            CVECVSSAssessment.vector_string,
            CVECVSSAssessment.created_at,
            CVECVSSAssessment.updated_at,
        )
        .select_from(CVE)
        .outerjoin(Ticket, Ticket.cve_id == CVE.id)
        .outerjoin(CVECVSSAssessment, CVECVSSAssessment.cve_id == CVE.id)
        .where(CVE.cve_id == cve_id, _cve_accessibility_condition(caller))
    )
    rows: Sequence[Row[Any]] = (await db.execute(statement)).all()
    if not rows:
        raise CVENotFoundError()

    default_cvss_version: str | None = rows[0].default_cvss_version
    if default_cvss_version is None:
        raise RequiredSystemSettingMissingError()

    assessments = sorted(
        (_project_assessment(cve_id, row) for row in rows if row.id is not None),
        key=_list_order,
    )
    severity = resolve_severity_score(assessments, default_cvss_version)
    eligibility = resolve_eligibility_score(assessments, default_cvss_version)
    return CVECVSSAssessments(
        assessments=tuple(assessments),
        default_cvss_version=CVSSVersion(default_cvss_version),
        severity=severity,
        eligibility=eligibility,
    )


def project_cvss_assessment(
    cve_id: str, assessment: CVECVSSAssessment
) -> CVSSAssessmentProjection:
    """Project one persisted assessment for the shared assessment item.

    See `docs/features/tickets/cvss-scoring.md` (Shared Assessment Item):
    GET and POST serialize exactly the same item, so a mutation response
    uses the same projection and vector-derived-unit verification as
    `get_cvss_assessments()`. `cve_id` is the public CVE-ID, used only to
    identify the row in the integrity-violation log.

    Category B: pure; performs no database operation. The caller supplies
    an assessment whose columns, including the server-generated
    timestamps, are loaded.

    Raises:
        CVSSAssessmentIntegrityError: The row violates its vector-derived
            unit.
    """
    return _project_assessment(cve_id, assessment)


async def resolve_cve_locator(
    db: AsyncSession, cve_id: str, caller: TicketCaller
) -> ResolvedCVE:
    """Resolve a consumer `{cve_id}` path value to an accessible CVE.

    The preliminary CVE accessibility decision of an authenticated CVE
    mutation path — the thin `require_accessible_cve` boundary role of
    `docs/api-spec.md` (CVE Accessibility Check; CVE Identifier
    Resolution). Category B read (cve-service.md, CVE Read and
    Accessibility Boundary).

    Q1: `cve_id` is the raw path value; `caller` is the request-resolved
    caller information.

    Q3: a value rejected by `core.identifiers.is_valid_cve_id()` performs
    no query. Otherwise one statement selects the CVE by the unique
    `CVE.cve_id`, outer-joined to its Ticket and constrained by the CVE
    accessibility projection of the canonical Ticket predicate. Creates no
    row or event, acquires no lock, and never flushes, commits, or rolls
    back.

    Q4: returns the internal CVE UUID and the CVE-ID. This is a
    preliminary decision only: it never authorizes a later unconstrained
    query. The locked mutation that follows re-evaluates accessibility
    from its locked-current roots, and that decision is authoritative.

    Q6: raises `CVENotFoundError` for a malformed, missing, or
    inaccessible CVE without distinguishing the causes. Database
    exceptions propagate unchanged.
    """
    if not is_valid_cve_id(cve_id):
        raise CVENotFoundError()
    row = (
        await db.execute(
            select(CVE.id, CVE.cve_id)
            .select_from(CVE)
            .outerjoin(Ticket, Ticket.cve_id == CVE.id)
            .where(CVE.cve_id == cve_id, _cve_accessibility_condition(caller))
        )
    ).one_or_none()
    if row is None:
        raise CVENotFoundError()
    return ResolvedCVE(id=row.id, cve_id=row.cve_id)


async def ensure_cve_exists(
    db: AsyncSession, cve_id: str, *, lock: bool = False
) -> CVE:
    """Ensure a CVE row exists, creating a placeholder when needed.

    Category A data guarantee (cve-service.md, On-Demand Fetch:
    `ensure_cve_exists()`, Placeholder Records, Concurrency; CVE Upsert
    Serialization, New CVE).

    Q1: `cve_id` is the CVE-ID string, expected to be pre-validated by the
    caller. `lock=True` is the lock-aware form used by Ticket workflows
    that hold the CVE as a root (`ticket_service.create_ticket()`, and
    `associate_cve()`): it must be called before any Ticket lock, after
    the optional acting-User lock (`docs/conventions.md`, Cross-Domain
    Root Lock Order).

    Q2: runs in the caller-owned transaction, which must be READ
    COMMITTED (the application default), so a waiting statement observes
    a concurrent transaction's committed winner row.

    Q3: (1) validates the format before any database operation. (2) Reads
    the row by the unique `CVE.cve_id`; with `lock=True` this read is
    itself the `SELECT ... FOR NO KEY UPDATE` and the first persistent
    read.
    (3) If absent, inserts a placeholder with only `cve_id` set (every
    other column takes its model or database default, including
    `cve_state = PUBLISHED`; no `CVESource` row) through `INSERT ... ON CONFLICT
    (cve_id) DO NOTHING`. PostgreSQL waits for a concurrent uncommitted
    inserter of the same key: if it commits, this call inserts nothing
    and (4) reads, and with `lock=True` locks, the committed winner; if
    it rolls back, this call becomes the insert winner. No unique
    violation is raised, so the caller's transaction and unrelated work
    stay usable and no savepoint is needed. A newly inserted row is owned
    by the transaction and is therefore already its locked root. Creates
    no audit event and never commits or rolls back; performs no registry,
    Redis, task, or external I/O.

    Q4: returns the serialized winner row — the existing row unchanged,
    the placeholder this call inserted, or a concurrent creator's
    committed row — refreshed from the database.

    Q6: raises `CVEIdFormatError` before any database operation for a
    malformed, over-length, or non-string value. Database exceptions
    propagate unchanged.
    """
    if not is_valid_cve_id(cve_id):
        raise CVEIdFormatError()

    statement = (
        select(CVE)
        .where(CVE.cve_id == cve_id)
        .execution_options(populate_existing=True)
    )
    if lock:
        # `FOR NO KEY UPDATE` (Cross-Domain Root Lock Order): serializes
        # every CVE-root holder while a referencing Ticket's foreign-key
        # `FOR KEY SHARE` stays compatible.
        statement = statement.with_for_update(key_share=True)

    existing = (await db.execute(statement)).scalar_one_or_none()
    if existing is not None:
        return existing

    # Inserter or loser, the winner row is then read (and locked) below.
    await db.execute(
        pg_insert(CVE)
        .values(cve_id=cve_id)
        .on_conflict_do_nothing(index_elements=[CVE.cve_id])
    )
    return (await db.execute(statement)).scalar_one()


# ---------------------------------------------------------------------------
# Service read contracts: CVE list, CVE detail, global CVE-source listing
# (cve-service.md, Service Read Contracts)
# ---------------------------------------------------------------------------

MAX_PER_PAGE: Final = 100

_STALLED_AFTER: Final = timedelta(days=30)
"""Failure-streak age beyond which a persisted `failure` row is stalled
(`docs/data-model.md`, CVESource, Derived predicate "stalled")."""

# Documented lowercase wire value -> stored value (cve-tracking.md, List
# CVEs, Query Parameters). `unresolved` is the SQL `NULL` severity.
_CVE_STATE_FILTER: Final[Mapping[str, str]] = {
    member.value.lower(): member.value for member in CveState
}
_SEVERITY_FILTER: Final[Mapping[str, str | None]] = {
    **{member.value.lower(): member.value for member in Severity},
    "unresolved": None,
}
_SOURCE_STATUS_FILTER: Final[frozenset[str]] = frozenset(
    member.value for member in CVESourceFetchStatus
)


@dataclass(frozen=True, slots=True)
class CVEListItemProjection:
    """The semantic projection represented by `CVEListItem`.

    `severity` is the CVE-owned unified severity (`None` is unresolved).
    `ticket_id` is the associated Ticket's public `SNTL-{n}` identity, or
    `None` for a ticketless CVE; the internal UUIDs are never part of it.
    """

    cve_id: str
    title: str | None
    description: str | None
    severity: Severity | None
    cve_state: CveState
    published_date: datetime | None
    ticket_id: str | None
    created_at: datetime
    updated_at: datetime


@dataclass(frozen=True, slots=True)
class CVEListResult:
    """One page of accessible CVEs and the unpaginated total, both derived
    from one PostgreSQL observation."""

    items: tuple[CVEListItemProjection, ...]
    total: int
    page: int
    per_page: int


@dataclass(frozen=True, slots=True)
class CVEDetailResult:
    """The semantic projection represented by `CVEResourceDetail`: the
    shared `CVEDetail` projection plus the associated Ticket's public
    `SNTL-{n}` identity, or `None`."""

    cve: CVEDetailProjection
    ticket_id: str | None


@dataclass(frozen=True, slots=True)
class CVESourceListItemProjection:
    """One persisted `CVESource` latest-state row of the global listing.

    `cve_id` is the public CVE-ID string; `CVESource.id`, the CVE UUID,
    and every Ticket attribute are deliberately absent.
    """

    cve_id: str
    source: str
    status: CVESourceFetchStatus
    fetched_at: datetime
    first_failed_at: datetime | None
    created_at: datetime
    updated_at: datetime


@dataclass(frozen=True, slots=True)
class CVESourceListResult:
    """One page of persisted CVE-source rows and the unpaginated total,
    both derived from one PostgreSQL observation."""

    items: tuple[CVESourceListItemProjection, ...]
    total: int
    page: int
    per_page: int


def _validate_page(page: int, per_page: int) -> None:
    """Reject an out-of-contract page before any query (the API already
    enforces the bounds as `422 VALIDATION_ERROR`)."""
    if page < 1:
        raise ValueError("page must be at least 1")
    if not 1 <= per_page <= MAX_PER_PAGE:
        raise ValueError(f"per_page must be between 1 and {MAX_PER_PAGE}")


def _ordered(
    sort_key: ColumnElement[Any], row_id: ColumnElement[Any], sort_order: SortOrder
) -> tuple[ColumnElement[Any], ColumnElement[Any]]:
    """Primary order with `NULL` last in both directions, then the internal
    primary-key tie-breaker in the same direction."""
    if sort_order is SortOrder.ASC:
        return sort_key.asc().nulls_last(), row_id.asc()
    return sort_key.desc().nulls_last(), row_id.desc()


def _sntl(sequence_id: int | None) -> str | None:
    return format_ticket_id(sequence_id) if sequence_id is not None else None


def _cve_search_condition(term: str) -> ColumnElement[bool]:
    """CVE-ID case-insensitive prefix, or title/description case-insensitive
    substring, for a normalized non-empty term; `%`, `_`, and backslash
    match literally."""
    escaped = escape_like(term)
    return or_(
        CVE.cve_id.ilike(f"{escaped}%", escape=LIKE_ESCAPE),
        CVE.title.ilike(f"%{escaped}%", escape=LIKE_ESCAPE),
        CVE.description.ilike(f"%{escaped}%", escape=LIKE_ESCAPE),
    )


def _cve_severity_condition(values: Sequence[str]) -> ColumnElement[bool]:
    """OR over the valid supplied severity wire values; `unresolved`
    matches SQL `NULL`. No valid value matches nothing."""
    valid = [_SEVERITY_FILTER[value] for value in values if value in _SEVERITY_FILTER]
    stored = sorted({value for value in valid if value is not None})
    branches: list[ColumnElement[bool]] = []
    if stored:
        branches.append(CVE.severity.in_(stored))
    if None in valid:
        branches.append(CVE.severity.is_(None))
    return or_(*branches) if branches else false()


def _cve_sort_key(sort_by: CVESortField) -> ColumnElement[Any]:
    match sort_by:
        case CVESortField.CVE_ID:
            return CVE.cve_id.collate(CODE_POINT_COLLATION)
        case CVESortField.PUBLISHED_DATE:
            return CVE.published_date.expression
        case CVESortField.SEVERITY:
            return severity_rank_expression(CVE.severity.expression)
        case CVESortField.CREATED_AT:
            return CVE.created_at.expression


async def list_cves(
    db: AsyncSession,
    caller: TicketCaller,
    *,
    search: str | None,
    cve_state: str | None,
    severity: Sequence[str] | None,
    has_ticket: bool | None,
    from_date: datetime | None,
    to_date: datetime | None,
    page: int,
    per_page: int,
    sort_by: CVESortField,
    sort_order: SortOrder,
) -> CVEListResult:
    """List the accessible CVEs matching the filters, one page at a time.

    Category B read (cve-service.md, Service Read Contracts > CVE List;
    cve-tracking.md, List CVEs).

    Q1: `caller` is the request-resolved caller information
    (`ANONYMOUS_CALLER` for an anonymous request). `search` is the raw
    free-text input. `cve_state` and each `severity` entry are raw wire
    values; `None` means omitted and an empty `severity` sequence means
    supplied with no value. `from_date`/`to_date` are UTC-normalized
    inclusive bounds over `published_date`. `page` is positive and
    `per_page` is 1-100.

    Q3: in one SQL statement, and therefore one PostgreSQL observation
    (a CTE chain: filtered CVEs, their total, the requested page, then
    the page rows with their associated Ticket's `sequence_id`):
    1. selects CVEs outer-joined to their at most one Ticket under the
       CVE accessibility projection of the canonical Ticket predicate,
       so inaccessible associated CVEs are absent from rows and total;
    2. trims `search` once; a non-empty term matches the CVE-ID as a
       case-insensitive prefix or the title or description as a
       case-insensitive substring, with `%`, `_`, and backslash literal;
    3. applies `cve_state` (an undocumented value matches nothing),
       severity (valid values OR-combined; `none` is the resolved
       `None` label, `unresolved` SQL `NULL`; no valid value matches
       nothing), `has_ticket`, and the inclusive date bounds (a `NULL`
       `published_date` satisfies neither bound), AND-combined;
    4. never multiplies a CVE row: the Ticket join is unique by
       `Ticket.cve_id` and no child relation is joined;
    5. orders by `cve_id` (code point), `published_date`, `created_at`,
       or the semantic severity rank, `NULL` last in both directions,
       then by `CVE.id` in the same direction;
    6. counts after accessibility and every filter, before paging.
    Creates no row or event, acquires no lock, and never flushes,
    commits, or rolls back.

    Q4: returns the page items, the total, and the echoed `page` and
    `per_page`. A page beyond the last is empty with the correct total.

    Q6: raises `ValueError` before any query for `page < 1` or
    `per_page` outside 1-100; no domain exception. Database exceptions
    propagate unchanged.
    """
    _validate_page(page, per_page)

    conditions: list[ColumnElement[bool]] = [_cve_accessibility_condition(caller)]
    normalized_search = search.strip() if search is not None else ""
    if normalized_search:
        conditions.append(_cve_search_condition(normalized_search))
    if cve_state is not None:
        stored_state = _CVE_STATE_FILTER.get(cve_state)
        conditions.append(
            CVE.cve_state == stored_state if stored_state is not None else false()
        )
    if severity is not None:
        conditions.append(_cve_severity_condition(severity))
    if has_ticket is not None:
        conditions.append(Ticket.id.is_not(None) if has_ticket else Ticket.id.is_(None))
    if from_date is not None:
        conditions.append(CVE.published_date >= from_date)
    if to_date is not None:
        conditions.append(CVE.published_date <= to_date)

    filtered = (
        select(CVE.id.label("id"), _cve_sort_key(sort_by).label("sort_key"))
        .select_from(CVE)
        .outerjoin(Ticket, Ticket.cve_id == CVE.id)
        .where(*conditions)
        .cte("filtered")
    )
    total = select(func.count().label("total")).select_from(filtered).cte("total")
    page_rows = (
        select(filtered)
        .order_by(*_ordered(filtered.c.sort_key, filtered.c.id, sort_order))
        .limit(per_page)
        .offset((page - 1) * per_page)
        .cte("page")
    )
    statement = (
        select(
            total.c.total,
            CVE.id.label("cve_pk"),
            CVE.cve_id,
            CVE.title,
            CVE.description,
            CVE.severity,
            CVE.cve_state,
            CVE.published_date,
            CVE.created_at,
            CVE.updated_at,
            Ticket.sequence_id.label("ticket_sequence_id"),
        )
        .select_from(total)
        .outerjoin(page_rows, true())
        .outerjoin(CVE, CVE.id == page_rows.c.id)
        .outerjoin(Ticket, Ticket.cve_id == CVE.id)
        .order_by(*_ordered(page_rows.c.sort_key, page_rows.c.id, sort_order))
    )
    rows = (await db.execute(statement)).all()
    return CVEListResult(
        items=tuple(
            CVEListItemProjection(
                cve_id=row.cve_id,
                title=row.title,
                description=row.description,
                severity=Severity(row.severity) if row.severity is not None else None,
                cve_state=CveState(row.cve_state),
                published_date=row.published_date,
                ticket_id=_sntl(row.ticket_sequence_id),
                created_at=row.created_at,
                updated_at=row.updated_at,
            )
            for row in rows
            if row.cve_pk is not None
        ),
        total=rows[0].total,
        page=page,
        per_page=per_page,
    )


async def get_cve_detail(
    db: AsyncSession, caller: TicketCaller, cve_id: str
) -> CVEDetailResult:
    """Return the detail of one accessible CVE.

    Category B read (cve-service.md, Service Read Contracts > CVE Detail;
    cve-tracking.md, Get CVE). Performs the `require_accessible_cve`
    boundary role of `GET /api/v1/cves/{cve_id}` directly in its
    selection.

    Q1: `cve_id` is the raw path value; `caller` is the request-resolved
    caller information.

    Q3: (1) a value rejected by `core.identifiers.is_valid_cve_id()` runs
    no query. (2) One SQL statement, and therefore one PostgreSQL
    observation, selects the CVE by the unique `CVE.cve_id`, outer-joined
    to its at most one Ticket and constrained by the CVE accessibility
    projection of the canonical Ticket predicate, together with the
    shared `CVEDetail` evidence (severity, ordered external identifiers,
    KEV, EPSS, SSVC, grouped CWEs) and the Ticket's `sequence_id`.
    (3) Projects the shared `CVEDetailProjection` and the `SNTL-{n}`
    identity; never the internal UUIDs, protected Ticket content, a
    priority, or CVSS assessments. Creates no row or event, acquires no
    lock, and never flushes, commits, or rolls back.

    Q4: returns the `CVEDetailResult`.

    Q6: raises `CVENotFoundError` for a malformed, missing, or
    inaccessible CVE without distinguishing the causes. Database
    exceptions propagate unchanged.
    """
    if not is_valid_cve_id(cve_id):
        raise CVENotFoundError()
    statement = join_cve_evidence(
        select(
            *cve_detail_columns(),
            Ticket.sequence_id.label("ticket_sequence_id"),
        )
        .select_from(CVE)
        .outerjoin(Ticket, Ticket.cve_id == CVE.id)
    ).where(CVE.cve_id == cve_id, _cve_accessibility_condition(caller))
    row = (await db.execute(statement)).one_or_none()
    cve = cve_detail_from_row(row) if row is not None else None
    if row is None or cve is None:
        raise CVENotFoundError()
    return CVEDetailResult(cve=cve, ticket_id=_sntl(row.ticket_sequence_id))


def _stalled_condition() -> ColumnElement[bool]:
    """The stalled predicate at the statement's database instant `now()`.

    `first_failed_at IS NOT NULL` keeps the predicate two-valued, so its
    negation (`stalled=false`) returns every non-stalled row.
    """
    return and_(
        CVESource.status == CVESourceFetchStatus.FAILURE.value,
        CVESource.first_failed_at.is_not(None),
        CVESource.first_failed_at < func.now() - _STALLED_AFTER,
    )


def _source_sort_key(sort_by: CVESourceSortField) -> ColumnElement[Any]:
    match sort_by:
        case CVESourceSortField.FETCHED_AT:
            return CVESource.fetched_at.expression
        case CVESourceSortField.FIRST_FAILED_AT:
            return CVESource.first_failed_at.expression
        case CVESourceSortField.SOURCE:
            return CVESource.source.collate(CODE_POINT_COLLATION)
        case CVESourceSortField.STATUS:
            return CVESource.status.collate(CODE_POINT_COLLATION)


async def list_cve_sources(
    db: AsyncSession,
    *,
    source: str | None,
    status: str | None,
    stalled: bool | None,
    from_date: datetime | None,
    to_date: datetime | None,
    page: int,
    per_page: int,
    sort_by: CVESourceSortField,
    sort_order: SortOrder,
) -> CVESourceListResult:
    """List persisted `CVESource` latest-state rows, one page at a time.

    Category B read (cve-service.md, Global CVE Source Listing > Service
    contract). The intentional identifier-only exception to CVE
    accessibility: no caller, no Ticket visibility join.

    Q1: `source` is an exact, grammar-bounded persisted source
    identifier; `status` a raw persisted-status value; `stalled` the
    stalled-predicate filter; `from_date`/`to_date` UTC-normalized
    inclusive bounds over `fetched_at`; `page` positive and `per_page`
    1-100.

    Q3: in one SQL statement, and therefore one PostgreSQL observation
    whose `now()` is the single observation instant for the stalled
    boundary, the page, and the total:
    1. selects one row per `CVESource` with no Ticket join;
    2. applies `source` (exact; a well-formed absent value matches
       nothing), `status` (a value outside `success`/`failure`/`missing`
       matches nothing), `stalled` (`true` keeps only `failure` rows whose
       streak began more than 30 days before `now()`, `false` excludes
       exactly those rows), and the inclusive `fetched_at` bounds,
       AND-combined;
    3. orders by `source` or `status` (code point), `fetched_at`, or
       `first_failed_at` (`NULL` last in both directions), then by the
       internal `CVESource.id` in the same direction;
    4. counts after every filter, before paging;
    5. resolves `CVESource.cve_id` to the public `CVE.cve_id`.
    Creates no row or event, acquires no lock, and never flushes,
    commits, or rolls back.

    Q4: returns the page items (never `CVESource.id`, any Ticket UUID,
    CVE content, user identity, or raw error), the total, and the echoed
    `page` and `per_page`. A page beyond the last is empty with the
    correct total.

    Q6: raises `ValueError` before any query for `page < 1` or
    `per_page` outside 1-100; no domain exception. Database exceptions
    propagate unchanged.
    """
    _validate_page(page, per_page)

    conditions: list[ColumnElement[bool]] = []
    if source is not None:
        conditions.append(CVESource.source == source)
    if status is not None:
        conditions.append(
            CVESource.status == status if status in _SOURCE_STATUS_FILTER else false()
        )
    if stalled is not None:
        conditions.append(_stalled_condition() if stalled else ~_stalled_condition())
    if from_date is not None:
        conditions.append(CVESource.fetched_at >= from_date)
    if to_date is not None:
        conditions.append(CVESource.fetched_at <= to_date)

    filtered = (
        select(CVESource.id.label("id"), _source_sort_key(sort_by).label("sort_key"))
        .where(*conditions)
        .cte("filtered")
    )
    total = select(func.count().label("total")).select_from(filtered).cte("total")
    page_rows = (
        select(filtered)
        .order_by(*_ordered(filtered.c.sort_key, filtered.c.id, sort_order))
        .limit(per_page)
        .offset((page - 1) * per_page)
        .cte("page")
    )
    statement = (
        select(
            total.c.total,
            CVESource.id.label("source_pk"),
            CVE.cve_id,
            CVESource.source,
            CVESource.status,
            CVESource.fetched_at,
            CVESource.first_failed_at,
            CVESource.created_at,
            CVESource.updated_at,
        )
        .select_from(total)
        .outerjoin(page_rows, true())
        .outerjoin(CVESource, CVESource.id == page_rows.c.id)
        .outerjoin(CVE, CVE.id == CVESource.cve_id)
        .order_by(*_ordered(page_rows.c.sort_key, page_rows.c.id, sort_order))
    )
    rows = (await db.execute(statement)).all()
    return CVESourceListResult(
        items=tuple(
            CVESourceListItemProjection(
                cve_id=row.cve_id,
                source=row.source,
                status=CVESourceFetchStatus(row.status),
                fetched_at=row.fetched_at,
                first_failed_at=row.first_failed_at,
                created_at=row.created_at,
                updated_at=row.updated_at,
            )
            for row in rows
            if row.source_pk is not None
        ),
        total=rows[0].total,
        page=page,
        per_page=per_page,
    )
