"""CVE service: CVE identifier resolution, accessibility-constrained reads,
and the placeholder-CVE data guarantee.

See `docs/features/tickets/cve-service.md` (Ownership; CVE Read and
Accessibility Boundary; On-Demand Fetch: `ensure_cve_exists()`; CVE Upsert
Serialization; Caller Validation Responsibility; Service Read Contracts;
Exceptions) for the module contract, and
`docs/features/tickets/cvss-scoring.md` (Get CVSS Assessments for a CVE)
for the CVSS read implemented here. `resolve_cve_locator()` is the
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
never flush, commit, or roll back, and perform no network I/O. Unexpected
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
from datetime import datetime
from decimal import Decimal
from typing import Any, Final

import structlog
from sqlalchemy import ColumnElement, Row, or_, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import CVSSAssessmentSeverity, CVSSVersion
from app.core.exceptions import CVENotFoundError, ServiceError
from app.core.identifiers import is_valid_cve_id
from app.models.cve import CVE
from app.models.cve_cvss_assessment import CVECVSSAssessment
from app.models.ticket import Ticket
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
from app.services.ticket_mutations_errors import InvalidCVSSVectorError
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
    itself the `SELECT ... FOR UPDATE` and the first persistent read.
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
        statement = statement.with_for_update()

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
