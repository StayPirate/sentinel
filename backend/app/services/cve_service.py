"""CVE service: CVE identifier resolution, accessibility-constrained reads,
the placeholder-CVE data guarantee, and source-neutral CVE ingestion.

See `docs/features/tickets/cve-service.md` (Ownership; CVE Read and
Accessibility Boundary; Primary Entry Point: `upsert_cve()`; On-Demand
Fetch: `ensure_cve_exists()`; CVE Upsert Serialization; Caller Validation
Responsibility; Service Read Contracts; Exceptions) for the module
contract, and `docs/features/tickets/cvss-scoring.md` (Get CVSS
Assessments for a CVE) for the CVSS read implemented here. `list_cves()`,
`get_cve_detail()`, and `list_cve_sources()` implement the CVE List, CVE
Detail, and Global CVE Source Listing read contracts; the CVE detail
shares the `CVEDetail` projection of `cve_projection` with the Ticket
detail. `resolve_cve_locator()` is the preliminary `{cve_id}` resolution
of the CVE mutation paths, whose locked mutation in `ticket_mutations`
makes the authoritative accessibility decision; `ticket_mutations` never
imports this module.

`upsert_cve()`, `record_source_status()`, and `build_post_ingest_tasks()`
implement source-neutral ingestion. `upsert_cve()` composes
`ticket_service` (Ticket creation and lifecycle) and `ticket_mutations`
(trusted-external CVSS batch, automatic priority). `ticket_service` also
imports this module (`ensure_cve_exists()`), so each side imports only
the other's module object and dereferences it at call time; neither uses
the other while being imported.

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
derive from one coherent PostgreSQL observation. `get_cve_source_status()`
is a deliberate exception to the caller-owned session: it opens and
closes its own short-lived read session, then performs one best-effort
read-only Redis pending-overlay lookup after that session is closed
(cve-service.md, CVE Source Status; Transaction Ownership). Unexpected
database and programming exceptions propagate unchanged. Results are
semantic service values, not Pydantic schemas.

`ensure_cve_exists()` is the pure placeholder-CVE data guarantee: it may
create one `CVE` row and, in its lock-aware form, acquire the CVE root lock
for the calling Ticket workflow, but it never commits or rolls back and
performs no registry, Redis, task, or external I/O.

On-demand single-CVE fetch has two parts here (cve-service.md, Fetch
Orchestration: `trigger_on_demand_fetch()`; On-Demand Fetch:
fetch_single_cve). `trigger_on_demand_fetch()` is the database-free
publication: it writes the `fetch_pending:{cve_id}:{source}` token marker
and publishes `fetch_single_cve` through `task_publication`.
`run_fetch_single_cve()` is the second service-owned orchestration boundary
(cve-service.md, Transaction Ownership): it owns the one session of a task
attempt, renews and owner-releases the marker, and finalizes through
`BaseCVEFetcher.commit_and_dispatch()`. The thin Celery wrapper and the
engine disposal live in `app.tasks.cve_tasks`.

The transactional preparation locks the CVE then its optional Ticket,
validates registry capability and enabled state, and projects the
primitive dispatch values. `prepare_freshness_refresh()` runs it inside
the caller-owned transaction of a manual create-with-CVE or CVE
association and registers the publication as a post-commit effect.
`refetch_cve()` is the third service-owned orchestration boundary: it
runs the preparation in its own short transaction, commits and closes it,
then publishes with no transaction or lock open.
"""

from __future__ import annotations

import re
import secrets
import uuid
from asyncio import CancelledError
from collections.abc import Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, date, datetime
from decimal import Decimal
from enum import StrEnum
from typing import Any, Final, cast

import redis.asyncio as redis_asyncio
import structlog
from celery.exceptions import SoftTimeLimitExceeded
from pydantic import ValidationError
from pydantic_core import PydanticCustomError
from redis.exceptions import RedisError
from sqlalchemy import (
    ColumnElement,
    Row,
    Select,
    and_,
    delete,
    false,
    func,
    literal,
    or_,
    select,
    true,
)
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.config import settings
from app.core.enums import (
    CVESortField,
    CVESourceDerivedStatus,
    CVESourceFetchStatus,
    CVESourceSortField,
    CVESourceType,
    CveState,
    CVSSAssessmentSeverity,
    CVSSVersion,
    FetcherRunStatus,
    Severity,
    SortOrder,
    TicketStatus,
)
from app.core.exceptions import CVENotFoundError, ServiceError
from app.core.identifiers import format_ticket_id, is_valid_cve_id
from app.database import register_post_commit_callback
from app.models.cve import CVE
from app.models.cve_affected_version import CVEAffectedVersion
from app.models.cve_cvss_assessment import CVECVSSAssessment
from app.models.cve_cwe import CVECWE
from app.models.cve_epss_score import CVEEPSSScore
from app.models.cve_external_identifier import CVEExternalIdentifier
from app.models.cve_kev_entry import CVEKEVEntry
from app.models.cve_source import CVESource
from app.models.cve_ssvc_assessment import CVESSVCAssessment
from app.models.fetcher_config import FetcherConfig
from app.models.fetcher_run import FetcherRun
from app.models.ticket import Ticket
from app.services import (
    base_cve_fetcher,
    task_publication,
    ticket_mutations,
    ticket_service,
)
from app.services.base_fetcher import FETCHER_REGISTRY
from app.services.cve_ingest import (
    AFFECTED_VERSION_FIELDS,
    AffectedVersionOperation,
    CVEIngestPayload,
    NormalizedScopeOperation,
    PostIngestTasks,
    SerializedCPEMatch,
    UpsertAction,
    UpsertResult,
    affected_version_content,
    is_post_ingest_package_name_candidate,
    normalize_affected_version_operations,
    normalize_cwe_classifications,
    normalize_external_identifiers,
)
from app.services.cve_projection import (
    CODE_POINT_COLLATION,
    CVEDetailProjection,
    cve_detail_columns,
    cve_detail_from_row,
    join_cve_evidence,
)
from app.services.cvss import (
    CVSS_VERSION_RANK,
    CVSSBaseMetrics,
    EligibilityResolution,
    ParsedCVSSVector,
    SeverityResolution,
    resolve_eligibility_score,
    resolve_severity_score,
    validate_cvss_vector,
)
from app.services.fetcher_execution import (
    FetcherConfigMissingError,
    get_fetcher_enabled,
)
from app.services.http_client import is_retryable_condition
from app.services.settings import (
    RequiredSystemSettingMissingError,
    default_cvss_version_select,
)
from app.services.sql_patterns import LIKE_ESCAPE, escape_like
from app.services.ticket_mutations import (
    ParsedExternalCVSSAssessment,
    is_valid_external_provider_name,
)
from app.services.ticket_mutations_errors import InvalidCVSSVectorError
from app.services.ticket_severity import severity_rank_expression
from app.services.ticket_visibility import TicketCaller, ticket_visibility_condition

logger = structlog.get_logger(__name__)


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


class CVEInvalidSourceError(CVEServiceError):
    """The explicitly requested refetch source is not a registered CVE
    source with `supports_fetch_single = True` (unknown, deregistered, or
    not refetchable). Mapped to `422 CVE_INVALID_SOURCE`. The message is
    static and never includes the rejected value."""

    def __init__(self) -> None:
        super().__init__("The requested source does not support single-CVE fetch.")


class CVESourceDisabledError(CVEServiceError):
    """The explicitly requested registered refetchable source is disabled.
    Mapped to `409 FETCHER_DISABLED`."""

    def __init__(self) -> None:
        super().__init__("The requested source is disabled.")


class CVEFetchFailedError(CVEServiceError):
    """Broadcast refetch preparation found no registered enabled source
    that supports single-CVE fetch, including an empty fetch-single
    registry. Mapped to `503 CVE_FETCH_FAILED`."""

    def __init__(self) -> None:
        super().__init__("No enabled source supports single-CVE fetch.")


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
    """Version precedence, then provider by Unicode code point (Python `str`
    order)."""
    return (CVSS_VERSION_RANK[assessment.cvss_version], assessment.provider_name)


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
    cve, _ = await _obtain_cve(db, cve_id, lock=lock)
    return cve


async def _obtain_cve(db: AsyncSession, cve_id: str, *, lock: bool) -> tuple[CVE, bool]:
    """The shared conflict-safe CVE create-or-obtain protocol (cve-service.md,
    CVE Upsert Serialization, New CVE).

    Reads the row by the unique `CVE.cve_id` (with `lock`, the read is the
    `FOR NO KEY UPDATE` root lock). If absent, inserts a placeholder through
    `INSERT ... ON CONFLICT (cve_id) DO NOTHING RETURNING id`: PostgreSQL
    waits for a concurrent uncommitted inserter of the same key, so this
    call either becomes the insert winner (also when that inserter rolls
    back) or inserts nothing and obtains the committed winner. No unique
    violation is raised and the caller transaction stays usable. Returns the
    row and whether this call inserted it.
    """
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
        return existing, False

    # Inserter or loser, the winner row is then read (and locked) below.
    inserted = (
        await db.execute(
            pg_insert(CVE)
            .values(cve_id=cve_id)
            .on_conflict_do_nothing(index_elements=[CVE.cve_id])
            .returning(CVE.id)
        )
    ).scalar_one_or_none()
    return (await db.execute(statement)).scalar_one(), inserted is not None


# ---------------------------------------------------------------------------
# Service read contracts: CVE list, CVE detail, global CVE-source listing
# (cve-service.md, Service Read Contracts)
# ---------------------------------------------------------------------------

MAX_PER_PAGE: Final = 100

_STALLED_AFTER_HOURS: Final = 30 * 24
"""Failure-streak age (30 days) beyond which a persisted `failure` row is
stalled (`docs/data-model.md`, CVESource, Derived predicate "stalled").
Applied as a fixed-length `make_interval(hours => 720)`, so the boundary
does not depend on the database session time zone (a `'30 days'`
interval would follow calendar days across a daylight-saving change)."""

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
    """The primary sort expression for `sort_by` on `CVE`."""
    keys: Mapping[CVESortField, ColumnElement[Any]] = {
        CVESortField.CVE_ID: CVE.cve_id.collate(CODE_POINT_COLLATION),
        CVESortField.PUBLISHED_DATE: CVE.published_date.expression,
        CVESortField.SEVERITY: severity_rank_expression(CVE.severity.expression),
        CVESortField.CREATED_AT: CVE.created_at.expression,
    }
    return keys[sort_by]


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
        CVESource.first_failed_at
        < func.now() - func.make_interval(0, 0, 0, 0, _STALLED_AFTER_HOURS),
    )


def _source_sort_key(sort_by: CVESourceSortField) -> ColumnElement[Any]:
    """The primary sort expression for `sort_by` on `CVESource`."""
    keys: Mapping[CVESourceSortField, ColumnElement[Any]] = {
        CVESourceSortField.FETCHED_AT: CVESource.fetched_at.expression,
        CVESourceSortField.FIRST_FAILED_AT: CVESource.first_failed_at.expression,
        CVESourceSortField.SOURCE: CVESource.source.collate(CODE_POINT_COLLATION),
        CVESourceSortField.STATUS: CVESource.status.collate(CODE_POINT_COLLATION),
    }
    return keys[sort_by]


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


# ---------------------------------------------------------------------------
# Per-CVE source status (cve-service.md, CVE Source Status)
# ---------------------------------------------------------------------------

KEV_FETCHER_NAME: Final = "sync_cisa_kev"
"""Stable fetcher name of the KEV source, whose latest fully successful
run proves KEV absence (cve-service.md, KEV status derivation)."""

FETCH_PENDING_KEY_PREFIX: Final = "fetch_pending:"
"""Prefix of the on-demand pending marker key
`fetch_pending:{cve_id}:{source}` (cve-service.md, Database-Free
Publication). `trigger_on_demand_fetch()` writes it, the `fetch_single_cve`
workflow renews and owner-releases it, and the source-status overlay
reads it, all through `_new_redis_client()`."""

_PENDING_REDIS_TIMEOUT_SECONDS: Final = 2


def get_fetch_pending_redis_url() -> str:
    """Return the Redis URL of the pending-marker overlay.

    Performs no I/O. A function rather than an inline read so tests can
    redirect it (testing-strategy.md, Redis Strategy).
    """
    return settings.redis_url


def _new_redis_client() -> redis_asyncio.Redis:
    """A fresh Redis client for one overlay lookup, closed by the caller.

    Kept as its own function so tests can substitute a client that raises
    `RedisError` deterministically.
    """
    client: redis_asyncio.Redis = redis_asyncio.Redis.from_url(
        get_fetch_pending_redis_url(),
        decode_responses=True,
        socket_connect_timeout=_PENDING_REDIS_TIMEOUT_SECONDS,
        socket_timeout=_PENDING_REDIS_TIMEOUT_SECONDS,
    )
    return client


def fetch_pending_key(cve_id: str, source: str) -> str:
    """The pending-marker key of one canonical CVE-ID and source value."""
    return f"{FETCH_PENDING_KEY_PREFIX}{cve_id}:{source}"


@dataclass(frozen=True, slots=True)
class CVESourceStatusEntry:
    """One roster entry of the per-CVE source status."""

    source: str
    status: CVESourceDerivedStatus
    fetched_at: datetime | None
    first_failed_at: datetime | None
    registered: bool
    refetchable: bool
    enabled: bool


@dataclass(frozen=True, slots=True)
class CVESourceStatusResult:
    """The complete, unpaginated roster in ascending `source` code-point
    order."""

    entries: tuple[CVESourceStatusEntry, ...]


@dataclass(frozen=True, slots=True)
class _PersistedSourceStatus:
    status: CVESourceFetchStatus
    fetched_at: datetime
    first_failed_at: datetime | None


@dataclass(frozen=True, slots=True)
class _DurableSourceProjection:
    """The complete durable input of the status read, materialized from
    one PostgreSQL observation."""

    cve_created_at: datetime
    persisted: Mapping[str, _PersistedSourceStatus]
    config_names: frozenset[str]
    disabled_names: frozenset[str]
    kev_updated_at: datetime | None
    kev_run_finished_at: datetime | None


def _durable_source_status_statement(cve_id: str, caller: TicketCaller) -> Select[Any]:
    """One statement: the accessible CVE with one row per `CVESource` row
    (or one row without a source), each carrying the same scalar
    `FetcherConfig`, `CVEKEVEntry`, and KEV-run inputs."""
    config_names = select(func.array_agg(FetcherConfig.fetcher_name)).scalar_subquery()
    disabled_names = select(
        func.array_agg(FetcherConfig.fetcher_name).filter(
            FetcherConfig.enabled.is_(false())
        )
    ).scalar_subquery()
    kev_run_finished_at = (
        select(FetcherRun.finished_at)
        .where(
            FetcherRun.fetcher_name == KEV_FETCHER_NAME,
            FetcherRun.status == FetcherRunStatus.SUCCESS.value,
        )
        .order_by(FetcherRun.finished_at.desc().nulls_last(), FetcherRun.id.desc())
        .limit(1)
        .scalar_subquery()
    )
    return (
        select(
            CVE.created_at.label("cve_created_at"),
            config_names.label("config_names"),
            disabled_names.label("disabled_names"),
            CVEKEVEntry.updated_at.label("kev_updated_at"),
            kev_run_finished_at.label("kev_run_finished_at"),
            CVESource.source.label("source"),
            CVESource.status.label("status"),
            CVESource.fetched_at.label("fetched_at"),
            CVESource.first_failed_at.label("first_failed_at"),
        )
        .select_from(CVE)
        .outerjoin(Ticket, Ticket.cve_id == CVE.id)
        .outerjoin(CVEKEVEntry, CVEKEVEntry.cve_id == CVE.id)
        .outerjoin(CVESource, CVESource.cve_id == CVE.id)
        .where(CVE.cve_id == cve_id, _cve_accessibility_condition(caller))
    )


async def _read_durable_source_projection(
    session_factory: async_sessionmaker[AsyncSession],
    cve_id: str,
    caller: TicketCaller,
) -> _DurableSourceProjection:
    """Materialize the durable projection in one short-lived service-owned
    read transaction, closed before this function returns."""
    async with session_factory() as session:
        rows = (
            await session.execute(_durable_source_status_statement(cve_id, caller))
        ).all()
    if not rows:
        raise CVENotFoundError()
    first = rows[0]
    return _DurableSourceProjection(
        cve_created_at=first.cve_created_at,
        persisted={
            row.source: _PersistedSourceStatus(
                status=CVESourceFetchStatus(row.status),
                fetched_at=row.fetched_at,
                first_failed_at=row.first_failed_at,
            )
            for row in rows
            if row.source is not None
        },
        config_names=frozenset(first.config_names or ()),
        disabled_names=frozenset(first.disabled_names or ()),
        kev_updated_at=first.kev_updated_at,
        kev_run_finished_at=first.kev_run_finished_at,
    )


async def _load_pending_sources(cve_id: str, sources: Sequence[str]) -> frozenset[str]:
    """The aggregate best-effort pending overlay: the subset of `sources`
    whose marker exists, from one `MGET`.

    No Redis I/O for an empty `sources`. A `RedisError` discards the
    complete overlay (an empty result), so a response never mixes overlay
    observations with durable fallbacks.
    """
    if not sources:
        return frozenset()
    client = _new_redis_client()
    try:
        values = await client.mget([fetch_pending_key(cve_id, s) for s in sources])
    except RedisError as exc:
        logger.warning(
            "cve_source_pending_overlay_unavailable",
            cve_id=cve_id,
            error_type=type(exc).__name__,
        )
        return frozenset()
    finally:
        with suppress(RedisError):
            await client.aclose()
    return frozenset(
        source
        for source, value in zip(sources, values, strict=True)
        if value is not None
    )


def _kev_entry(
    projection: _DurableSourceProjection, *, refetchable: bool, enabled: bool
) -> CVESourceStatusEntry:
    """KEV status from `CVEKEVEntry` presence and the latest fully
    successful `sync_cisa_kev` run; independent of `enabled`."""
    status = CVESourceDerivedStatus.NOT_ATTEMPTED
    fetched_at: datetime | None = None
    if projection.kev_updated_at is not None:
        status = CVESourceDerivedStatus.SUCCESS
        fetched_at = projection.kev_updated_at
    elif (
        projection.kev_run_finished_at is not None
        and projection.kev_run_finished_at >= projection.cve_created_at
    ):
        status = CVESourceDerivedStatus.MISSING
        fetched_at = projection.kev_run_finished_at
    return CVESourceStatusEntry(
        source=CVESourceType.KEV.value,
        status=status,
        fetched_at=fetched_at,
        first_failed_at=None,
        registered=True,
        refetchable=refetchable,
        enabled=enabled,
    )


def _durable_entry(
    source: str,
    persisted: _PersistedSourceStatus | None,
    *,
    pending: bool,
    registered: bool,
    refetchable: bool,
    enabled: bool,
) -> CVESourceStatusEntry:
    """A non-KEV entry: `pending` over any durable status (keeping the last
    completed timestamps), otherwise the persisted status or
    `not_attempted`."""
    if pending:
        status = CVESourceDerivedStatus.PENDING
    elif persisted is not None:
        status = CVESourceDerivedStatus(persisted.status.value)
    else:
        status = CVESourceDerivedStatus.NOT_ATTEMPTED
    return CVESourceStatusEntry(
        source=source,
        status=status,
        fetched_at=persisted.fetched_at if persisted is not None else None,
        first_failed_at=persisted.first_failed_at if persisted is not None else None,
        registered=registered,
        refetchable=refetchable,
        enabled=enabled,
    )


async def get_cve_source_status(
    cve_id: str,
    caller: TicketCaller,
    *,
    session_factory: async_sessionmaker[AsyncSession],
) -> CVESourceStatusResult:
    """Report the fetch status of every CVE source for one accessible CVE.

    Category B read with a service-owned session (cve-service.md, CVE
    Source Status; Transaction Ownership).

    Q1: `cve_id` is the raw path value; `caller` is the request-resolved
    caller information (`ANONYMOUS_CALLER` for an anonymous request);
    `session_factory` opens the one short-lived read session.

    Q3 (Resolution algorithm):
    1. a value rejected by `core.identifiers.is_valid_cve_id()` runs no
       query. One SQL statement, and therefore one PostgreSQL observation,
       selects the CVE under the CVE accessibility projection of the
       canonical Ticket predicate together with its `CVESource` rows, the
       `FetcherConfig` names and disabled names, `CVEKEVEntry.updated_at`,
       and the latest successful `sync_cisa_kev` run (`finished_at DESC,
       id DESC`). The session closes before any registry or Redis access;
    2. loads the in-memory registry (`get_all_cve_source_types()`);
    3. `enabled` is the materialized `FetcherConfig.enabled` of the
       source's fetcher, `true` when the row is absent; `refetchable` is
       exactly `supports_fetch_single`;
    4. the roster is every registered source plus every persisted source
       value that is not registered (historical), each exactly once;
    5. one aggregate `MGET` of the pending markers of the registered,
       enabled, non-KEV sources (none when that set is empty); KEV derives
       from its data table; a registered enabled non-KEV source with a
       marker is `pending` over its durable status, keeping the last
       completed timestamps; disabled and historical sources never
       receive the overlay; historical sources report
       `registered`/`refetchable`/`enabled` as `false`;
    6. orders the roster by `source` in ascending code-point order.
    Creates no row or event, acquires no lock, never flushes or commits.

    Q4: returns the complete ordered roster.

    Q6: raises `CVENotFoundError` for a malformed, missing, or
    inaccessible CVE without distinguishing the causes. A `RedisError`
    never escapes: it discards the complete overlay and the durable view
    is returned. Database exceptions propagate unchanged.
    """
    if not is_valid_cve_id(cve_id):
        raise CVENotFoundError()
    projection = await _read_durable_source_projection(session_factory, cve_id, caller)

    registry = base_cve_fetcher.get_all_cve_source_types()
    enabled = {
        source: (
            cls.name not in projection.disabled_names
            if cls.name in projection.config_names
            else True
        )
        for source, cls in registry.items()
    }
    overlay_sources = sorted(
        source
        for source in registry
        if enabled[source] and source != CVESourceType.KEV.value
    )
    pending = await _load_pending_sources(cve_id, overlay_sources)

    entries: list[CVESourceStatusEntry] = []
    for source in sorted(registry.keys() | projection.persisted.keys()):
        fetcher_cls = registry.get(source)
        if fetcher_cls is None:
            entries.append(
                _durable_entry(
                    source,
                    projection.persisted[source],
                    pending=False,
                    registered=False,
                    refetchable=False,
                    enabled=False,
                )
            )
        elif source == CVESourceType.KEV.value:
            entries.append(
                _kev_entry(
                    projection,
                    refetchable=fetcher_cls.supports_fetch_single,
                    enabled=enabled[source],
                )
            )
        else:
            entries.append(
                _durable_entry(
                    source,
                    projection.persisted.get(source),
                    pending=source in pending,
                    registered=True,
                    refetchable=fetcher_cls.supports_fetch_single,
                    enabled=enabled[source],
                )
            )
    return CVESourceStatusResult(entries=tuple(entries))


# ---------------------------------------------------------------------------
# Source-neutral CVE ingestion (cve-service.md, Primary Entry Point:
# `upsert_cve()`; CVESource Management; Complete `upsert_cve()` Composition;
# Concurrency; PostIngestTasks)
# ---------------------------------------------------------------------------

CVSS_VECTOR_MAX_LENGTH: Final = 200
"""Defensive received-length bound of an external CVSS vector candidate
(cve-service.md, Phase 1 > CVSS assessment ingestion); equal to the API
received-length limit of cvss-scoring.md (Input Rules, rule 1)."""

INVALID_PROVIDER_REASON: Final = "invalid_provider"
INVALID_VECTOR_REASON: Final = "invalid_vector"

_NULLABLE_GLOBAL_FIELDS: Final[tuple[str, ...]] = (
    "title",
    "description",
    "published_date",
    "modified_date",
)


def _utc_now() -> datetime:
    """The current instant; the single injection point of `upsert_cve()`'s
    `evaluation_date`."""
    return datetime.now(UTC)


async def record_source_status(
    session: AsyncSession,
    cve_id: uuid.UUID,
    source: CVESourceType,
    status: CVESourceFetchStatus,
) -> None:
    """Create or update the latest `CVESource` state of `(cve_id, source)`.

    Category A mutation, the single `CVESource` writer (cve-service.md,
    CVESource Management).

    Q1: `cve_id` is the CVE UUID primary key; `source` and `status` are
    Enum members (raw strings are programming errors).

    Q2: runs in the caller-owned transaction; the upsert's conflict
    handling serializes every writer of the same key on its row.

    Q3: one `INSERT ... ON CONFLICT (cve_id, source) DO UPDATE` whose
    single `clock_timestamp()` instant (database wall clock, not
    transaction start) becomes `fetched_at` and, when a failure starts a
    new streak, `first_failed_at`. A failure preserves an existing
    `first_failed_at`; success and missing clear it. The latest serialized
    write wins; no history row is created and no unique violation can
    abort the caller transaction. Never commits or rolls back.

    Q6: raises `ValueError` for a non-UUID `cve_id` or a non-Enum `source`
    or `status`. A missing CVE raises the foreign-key `IntegrityError`.
    """
    if not isinstance(cve_id, uuid.UUID):
        raise ValueError("record_source_status() requires the CVE UUID.")
    if not isinstance(source, CVESourceType):
        raise ValueError("source must be a CVESourceType member.")
    if not isinstance(status, CVESourceFetchStatus):
        raise ValueError("status must be a CVESourceFetchStatus member.")

    failure = status is CVESourceFetchStatus.FAILURE
    instant = select(func.clock_timestamp().label("ts")).subquery()
    row = select(
        literal(cve_id, CVESource.cve_id.type),
        literal(source.value, CVESource.source.type),
        literal(status.value, CVESource.status.type),
        instant.c.ts,
        instant.c.ts if failure else literal(None, CVESource.first_failed_at.type),
    )
    statement = pg_insert(CVESource).from_select(
        [
            CVESource.cve_id,
            CVESource.source,
            CVESource.status,
            CVESource.fetched_at,
            CVESource.first_failed_at,
        ],
        row,
        include_defaults=False,
    )
    excluded = statement.excluded
    statement = statement.on_conflict_do_update(
        index_elements=[CVESource.cve_id, CVESource.source],
        set_={
            "status": excluded.status,
            "fetched_at": excluded.fetched_at,
            "first_failed_at": (
                func.coalesce(CVESource.first_failed_at, excluded.fetched_at)
                if failure
                else None
            ),
            "updated_at": func.now(),
        },
    )
    await session.execute(statement)


def _canonical_cvss_candidates(
    cve_id: str, source: CVESourceType, payload: CVEIngestPayload
) -> list[ParsedExternalCVSSAssessment]:
    """Step 2: classify, parse, and group every CVSS candidate.

    In input order, provider before vector: an invalid provider is
    `invalid_provider`; a non-string vector, one over
    `CVSS_VECTOR_MAX_LENGTH` received characters, or one the parser
    rejects is `invalid_vector`. Each skip emits one WARNING carrying only
    the CVE ID, source value, zero-based ordinal, and reason. Valid
    candidates are grouped by `(provider, derived version)`: identical
    canonical vectors collapse; differing ones reject the complete payload
    with `pydantic.ValidationError` (no provider or vector in the error).
    """
    accepted: dict[tuple[str, CVSSVersion], ParsedExternalCVSSAssessment] = {}
    conflict: int | None = None
    for ordinal, entry in enumerate(payload.cvss_assessments or ()):
        provider = entry.provider_name
        vector = entry.vector_string
        parsed: ParsedCVSSVector | None = None
        reason = INVALID_VECTOR_REASON
        if not isinstance(provider, str) or not is_valid_external_provider_name(
            provider
        ):
            reason = INVALID_PROVIDER_REASON
        elif isinstance(vector, str) and len(vector) <= CVSS_VECTOR_MAX_LENGTH:
            try:
                parsed = validate_cvss_vector(vector)
            except InvalidCVSSVectorError:
                parsed = None
        if parsed is None or not isinstance(provider, str):
            logger.warning(
                "cve_cvss_candidate_skipped",
                cve_id=cve_id,
                source=source.value,
                ordinal=ordinal,
                reason=reason,
            )
            continue
        key = (provider, parsed.version)
        existing = accepted.get(key)
        if existing is None:
            accepted[key] = ParsedExternalCVSSAssessment(
                provider=provider, parsed=parsed
            )
        elif existing.parsed.canonical_vector != parsed.canonical_vector:
            conflict = ordinal if conflict is None else conflict
    if conflict is not None:
        raise ValidationError.from_exception_data(
            "CVEIngestPayload",
            [
                {
                    "type": PydanticCustomError(
                        "cvss_assessment_conflict",
                        "Contradictory canonical CVSS assessments share one"
                        " (provider, version) key.",
                    ),
                    "loc": ("cvss_assessments", conflict),
                    "input": None,
                }
            ],
        )
    return list(accepted.values())


def _assign(cve: CVE, name: str, value: object) -> bool:
    """Set one global field when the value differs; whether it changed."""
    if getattr(cve, name) == value:
        return False
    setattr(cve, name, value)
    return True


def _merge_global_fields(cve: CVE, payload: CVEIngestPayload) -> bool:
    """Step 4 global merge (cve-service.md, Merge Strategy).

    Presence (`model_fields_set`) decides: omitted preserves, explicit
    `null` clears, a value sets or replaces, an equal value is a no-op. A
    resulting `PUBLISHED` always clears `date_rejected`; for `REJECTED` an
    omitted date is preserved.
    """
    supplied = payload.model_fields_set
    changed = False
    for name in _NULLABLE_GLOBAL_FIELDS:
        if name in supplied:
            changed |= _assign(cve, name, getattr(payload, name))
    if payload.cve_state is not None:
        changed |= _assign(cve, "cve_state", payload.cve_state.value)
    if cve.cve_state == CveState.PUBLISHED:
        changed |= _assign(cve, "date_rejected", None)
    elif "date_rejected" in supplied:
        changed |= _assign(cve, "date_rejected", payload.date_rejected)
    return changed


async def _upsert_one_to_one(
    db: AsyncSession, model: Any, cve_id: uuid.UUID, values: Mapping[str, object]
) -> bool:
    """Create or update a 1:1 child keyed by `cve_id`; equal content is a
    no-op that does not touch `updated_at`. Whether a row changed."""
    statement = pg_insert(model).values(cve_id=cve_id, **values)
    excluded = statement.excluded
    upsert = statement.on_conflict_do_update(
        index_elements=[model.cve_id],
        set_={**{name: excluded[name] for name in values}, "updated_at": func.now()},
        where=or_(
            *(getattr(model, name).is_distinct_from(excluded[name]) for name in values)
        ),
    ).returning(model.id)
    return (await db.execute(upsert)).scalar_one_or_none() is not None


async def _apply_affected_version_operation(
    db: AsyncSession, cve_id: uuid.UUID, operation: NormalizedScopeOperation
) -> bool:
    """Apply one scope operation; whether the scope's row set changed.

    The complete current set is compared with the snapshot before any
    physical change, so an equal replacement, a repeated empty
    replacement, or removal of an absent scope is a no-op.
    """
    scope = and_(
        CVEAffectedVersion.cve_id == cve_id,
        CVEAffectedVersion.source_container == operation.source_container,
    )
    columns = [getattr(CVEAffectedVersion, name) for name in AFFECTED_VERSION_FIELDS]
    current = [
        affected_version_content(row)
        for row in (await db.execute(select(*columns).where(scope))).all()
    ]
    desired = operation.content()
    if len(current) == len(set(current)) and set(current) == desired:
        return False
    await db.execute(
        delete(CVEAffectedVersion)
        .where(scope)
        .execution_options(synchronize_session=False)
    )
    if operation.operation is AffectedVersionOperation.REPLACE and operation.entries:
        await db.execute(
            pg_insert(CVEAffectedVersion).values(
                [
                    {
                        "cve_id": cve_id,
                        "source_container": operation.source_container,
                        **{n: getattr(entry, n) for n in AFFECTED_VERSION_FIELDS},
                    }
                    for entry in operation.entries
                ]
            )
        )
    return True


async def _persist_children(
    db: AsyncSession, cve_id: uuid.UUID, payload: CVEIngestPayload
) -> bool:
    """Step 4 child persistence (cve-service.md, Child Persistence Matrix);
    whether any non-CVSS child changed effectively. Omitted, null, and
    empty additive input retains every row."""
    changed = False

    cwe_keys = normalize_cwe_classifications(payload.cwe_classifications)
    if cwe_keys:
        inserted = (
            await db.execute(
                pg_insert(CVECWE)
                .values(
                    [
                        {"cve_id": cve_id, "cwe_id": cwe_id, "source": source}
                        for cwe_id, source in cwe_keys
                    ]
                )
                .on_conflict_do_nothing(
                    index_elements=[CVECWE.cve_id, CVECWE.cwe_id, CVECWE.source]
                )
                .returning(CVECWE.id)
            )
        ).all()
        changed |= bool(inserted)

    identifiers = normalize_external_identifiers(payload.external_identifiers)
    if identifiers:
        statement = pg_insert(CVEExternalIdentifier).values(
            [
                {
                    "cve_id": cve_id,
                    "source": entry.source.value,
                    "identifier": entry.identifier,
                    "url": entry.url,
                }
                for entry in identifiers
            ]
        )
        excluded = statement.excluded
        written = (
            await db.execute(
                statement.on_conflict_do_update(
                    index_elements=[
                        CVEExternalIdentifier.source,
                        CVEExternalIdentifier.identifier,
                    ],
                    set_={
                        "cve_id": excluded.cve_id,
                        "url": excluded.url,
                        "updated_at": func.now(),
                    },
                    where=or_(
                        CVEExternalIdentifier.cve_id.is_distinct_from(excluded.cve_id),
                        CVEExternalIdentifier.url.is_distinct_from(excluded.url),
                    ),
                ).returning(CVEExternalIdentifier.id)
            )
        ).all()
        changed |= bool(written)

    if payload.ssvc_assessment is not None:
        ssvc = payload.ssvc_assessment
        changed |= await _upsert_one_to_one(
            db,
            CVESSVCAssessment,
            cve_id,
            {
                "exploitation": ssvc.exploitation.value,
                "automatable": ssvc.automatable.value,
                "technical_impact": ssvc.technical_impact.value,
                "version": ssvc.version,
                "assessed_at": ssvc.assessed_at,
            },
        )
    if payload.kev_data is not None:
        changed |= await _upsert_one_to_one(
            db,
            CVEKEVEntry,
            cve_id,
            {
                "date_added": payload.kev_data.date_added,
                "reference_url": payload.kev_data.reference_url,
            },
        )
    if payload.epss_score is not None:
        epss = payload.epss_score
        changed |= await _upsert_one_to_one(
            db,
            CVEEPSSScore,
            cve_id,
            {
                "score": epss.score,
                "percentile": epss.percentile,
                "assessed_at": epss.assessed_at,
            },
        )

    for operation in normalize_affected_version_operations(
        payload.affected_version_operations
    ):
        changed |= await _apply_affected_version_operation(db, cve_id, operation)
    return changed


async def _lock_ticket_of(db: AsyncSession, cve: CVE) -> Ticket | None:
    """The unique Ticket associated with the locked `cve`, `FOR UPDATE`."""
    return (
        await db.execute(
            select(Ticket)
            .where(Ticket.cve_id == cve.id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
    ).scalar_one_or_none()


async def upsert_cve(
    db: AsyncSession,
    cve_id: str,
    source: CVESourceType,
    cve_data: CVEIngestPayload,
) -> UpsertResult:
    """Central source-neutral entry point for all CVE data.

    Category A trusted system composition (cve-service.md, Primary Entry
    Point: `upsert_cve()`; Complete `upsert_cve()` Composition steps 1-9;
    Concurrency; Transaction Boundaries, Phase 1). Callers are CVE fetchers
    and the on-demand fetch path; never an API, CLI, or consumer boundary.

    Q1: `cve_id` is a pre-validated canonical CVE-ID; `source` is the
    fetcher's `CVESourceType` member; `cve_data` is a constructed
    `CVEIngestPayload` (its model validators have run).

    Q2: the caller owns the per-CVE transaction and commits once after its
    automatic-reference work. Locks, in order and retained until the
    transaction ends: the CVE `FOR NO KEY UPDATE`, then its unique Ticket
    `FOR UPDATE` (delegates re-lock both as same-transaction no-ops). No
    User root.

    Q3: (1) format guard, source and payload type checks, then one UTC
    `evaluation_date`; (2) CVSS candidates parsed, skipped with one
    sanitized warning each, and grouped (contradictory duplicates reject
    the payload); (3) the conflict-safe CVE create-or-lock, preserving the
    locked pre-merge `cve_state`; (4) presence-sensitive global merge and
    child persistence, flushed; (5) the unique Ticket loaded `FOR UPDATE`
    or created through `ticket_service.create_ticket()` (ingestion
    source); (6) `ticket_mutations.upsert_external_cvss_batch()` with the
    valid candidates and the captured date, then one
    `refresh_priority_auto()`; (7) exactly one lifecycle decision: the
    rejection boundary for `PUBLISHED -> REJECTED` or a newly created
    Ticket whose CVE is `REJECTED`; for `REJECTED -> PUBLISHED`, the system
    `reopen_from_ignored()` form only when the locked Ticket is still the
    CVE's association and `Ignored`; otherwise nothing; (8)
    `record_source_status(SUCCESS)`; (9) flush. No HTTP, Redis, Celery,
    DNS, or package work; never commits or rolls back.

    Q4: `UpsertResult` with the CVE, the Ticket, and `created` (this call
    won the CVE insert), `updated` (an effective global, child, or CVSS
    change), or `unchanged`.

    Q5: re-invocation derives every outcome from locked-current state;
    equal data creates no row or Ticket event (source status may advance
    its timestamp).

    Q6: before any database operation, `CVEIdFormatError` for a malformed
    `cve_id`, `ValueError` for a non-Enum `source` or a non-payload
    `cve_data`, and `pydantic.ValidationError` for contradictory CVSS
    duplicates. `RequiredSystemSettingMissingError`,
    `TicketCVEConflictError` (invariant failure), and database, audit,
    flush, cancellation, and programming exceptions from the delegates
    propagate; the caller rolls back the complete per-CVE transaction.
    """
    if not is_valid_cve_id(cve_id):
        raise CVEIdFormatError()
    if not isinstance(source, CVESourceType):
        raise ValueError("source must be a CVESourceType member.")
    if not isinstance(cve_data, CVEIngestPayload):
        raise ValueError("cve_data must be a CVEIngestPayload.")
    evaluation_date: date = _utc_now().date()

    candidates = _canonical_cvss_candidates(cve_id, source, cve_data)

    cve, created = await _obtain_cve(db, cve_id, lock=True)
    previous_state = cve.cve_state

    changed = _merge_global_fields(cve, cve_data)
    resulting_state = cve.cve_state
    changed |= await _persist_children(db, cve.id, cve_data)
    await db.flush()

    ticket = await _lock_ticket_of(db, cve)
    ticket_created = ticket is None
    if ticket is None:
        ticket = await ticket_service.create_ticket(
            db,
            acting_user_id=None,
            cve_id=cve.cve_id,
            source=ticket_service.TicketCreationSource.CVE_INGESTION,
            ingestion_source=source,
        )

    batch = await ticket_mutations.upsert_external_cvss_batch(
        db, cve_id=cve.id, assessments=candidates, evaluation_date=evaluation_date
    )
    changed |= batch.effective
    await ticket_mutations.refresh_priority_auto(db, ticket=ticket)

    if resulting_state == CveState.REJECTED and (
        previous_state == CveState.PUBLISHED or ticket_created
    ):
        await ticket_service.ignore_new_for_rejected_cve(
            db, cve_id=cve.id, ticket=ticket
        )
    elif (
        previous_state == CveState.REJECTED
        and resulting_state == CveState.PUBLISHED
        and ticket.cve_id == cve.id
        and ticket.status == TicketStatus.IGNORED
    ):
        ticket = await ticket_service.reopen_from_ignored_as_system(
            db, ticket_id=ticket.id, evaluation_date=evaluation_date
        )

    await record_source_status(db, cve.id, source, CVESourceFetchStatus.SUCCESS)
    await db.flush()

    if created:
        action = UpsertAction.CREATED
    elif changed:
        action = UpsertAction.UPDATED
    else:
        action = UpsertAction.UNCHANGED
    return UpsertResult(cve=cve, ticket=ticket, action=action)


def build_post_ingest_tasks(
    result: UpsertResult,
    payload: CVEIngestPayload,
) -> PostIngestTasks | None:
    """Extract the pure post-commit package-candidate handoff.

    Category C pure helper (cve-service.md, `build_post_ingest_tasks()`):
    no database, mapping, Redis, Celery, or network access and no domain
    exception. CPE matches, affected-version CPEs and vendor/product pairs
    of `replace` entries, and filtered package names (direct
    `resolved_packages` and `replace` entry `package_name` values) are
    exact-deduplicated and emitted in ascending Unicode code-point order;
    CPE matches order by criteria, `vulnerable` (false first), then
    `match_criteria_id` with `None` first. Returns `None` when every
    collection is empty.
    """
    cpe_matches = sorted(
        {
            (
                match.criteria,
                match.vulnerable,
                None if (mcid := match.match_criteria_id) is None else str(mcid),
            )
            for match in payload.cpe_matches or ()
        },
        key=lambda m: (m[0], m[1], m[2] is not None, m[2] or ""),
    )
    entries = [
        entry
        for operation in payload.affected_version_operations or ()
        if operation.operation is AffectedVersionOperation.REPLACE
        for entry in operation.entries or ()
    ]
    affected_cpes = sorted({e.cpe for e in entries if e.cpe is not None})
    vendor_products = sorted(
        {
            (e.vendor, e.product)
            for e in entries
            if e.vendor is not None and e.product is not None
        }
    )
    resolved_packages = sorted(
        {
            name
            for name in [
                *(payload.resolved_packages or ()),
                *(e.package_name for e in entries if e.package_name is not None),
            ]
            if is_post_ingest_package_name_candidate(name)
        }
    )
    if not (cpe_matches or affected_cpes or vendor_products or resolved_packages):
        return None
    return PostIngestTasks(
        ticket_id=str(result.ticket.id),
        cpe_matches=[
            SerializedCPEMatch(
                criteria=criteria, vulnerable=vulnerable, match_criteria_id=mcid
            )
            for criteria, vulnerable, mcid in cpe_matches
        ],
        affected_cpes=affected_cpes,
        vendor_products=[[vendor, product] for vendor, product in vendor_products],
        resolved_packages=resolved_packages,
    )


# ---------------------------------------------------------------------------
# On-demand single-CVE fetch (cve-service.md, Fetch Orchestration:
# `trigger_on_demand_fetch()`; On-Demand Fetch: fetch_single_cve)
# ---------------------------------------------------------------------------

FETCH_SINGLE_CVE_TASK: Final = "fetch_single_cve"
"""Explicit registered name of the on-demand single-CVE Celery task."""

FETCH_PENDING_TTL_SECONDS: Final = 600
"""Fixed TTL of the pending marker, set by the writer and every renewal."""

FETCH_SINGLE_RETRY_DELAYS: Final[tuple[int, ...]] = (5, 10, 20)
"""Countdown in seconds before retry 1, 2, and 3 (at most three retries)."""

MARKER_UNAVAILABLE_EVENT: Final = "fetch_pending_marker_unavailable"
"""WARNING: the marker `SET` raised `RedisError`; publication fails open."""

MARKER_OPERATION_FAILED_EVENT: Final = "fetch_pending_marker_operation_failed"
"""WARNING: a best-effort owner renewal or release raised `RedisError`."""

PAYLOAD_INVALID_EVENT: Final = "fetch_single_cve_payload_invalid"
UNKNOWN_FETCHER_EVENT: Final = "fetch_single_cve_unknown_fetcher"
TARGET_MISMATCH_EVENT: Final = "fetch_single_cve_target_mismatch"
CONFIG_MISSING_EVENT: Final = "fetch_single_cve_config_missing"
FETCHER_DISABLED_EVENT: Final = "fetch_single_cve_fetcher_disabled"
CVE_MISSING_EVENT: Final = "fetch_single_cve_cve_missing"
RETRY_SCHEDULED_EVENT: Final = "fetch_single_cve_retry_scheduled"
COMPLETED_EVENT: Final = "fetch_single_cve_completed"
FAILED_EVENT: Final = "fetch_single_cve_failed"

_TOKEN_BYTES: Final = 32
_TOKEN_PATTERN: Final = re.compile(r"[A-Za-z0-9_-]{43}")
_FETCHER_NAME_PATTERN: Final = re.compile(r"[a-z][a-z0-9_]*")
_FETCHER_NAME_MAX_LENGTH: Final = 100
_CVE_SOURCE_VALUES: Final = frozenset(member.value for member in CVESourceType)
_CONTROL_SIGNALS: Final = (CancelledError, SoftTimeLimitExceeded, MemoryError)

_COMPARE_AND_EXPIRE_SCRIPT: Final = """
if redis.call('GET', KEYS[1]) == ARGV[1] then
    return redis.call('EXPIRE', KEYS[1], ARGV[2])
end
return 0
"""
"""Owner renewal: reset the TTL only while the marker holds the token."""

_COMPARE_AND_DELETE_SCRIPT: Final = """
if redis.call('GET', KEYS[1]) == ARGV[1] then
    return redis.call('DEL', KEYS[1])
end
return 0
"""
"""Owner release: delete the marker only while it holds the token."""


@dataclass(frozen=True, slots=True)
class FetchDispatchResult:
    """Outcome of one database-free on-demand publication.

    A service-layer value, not a response schema. Each list holds canonical
    `CVESourceType` values in ascending code-point order; the four lists
    are disjoint and their union is the complete prepared broadcast set
    (cve-service.md, `FetchDispatchResult`).
    """

    sources_enqueued: list[str]
    sources_already_pending: list[str]
    sources_disabled: list[str]
    sources_failed: list[str]


@dataclass(frozen=True, slots=True)
class FetchSingleRetry:
    """Retry signal of one `fetch_single_cve` attempt.

    The synchronous wrapper raises `self.retry()` with `countdown` and
    `cause`; the workflow has already rolled back and renewed the marker.
    """

    countdown: int
    cause: Exception


def _new_marker_token() -> str:
    """A cryptographically unpredictable pending-marker ownership token."""
    return secrets.token_urlsafe(_TOKEN_BYTES)


async def trigger_on_demand_fetch(
    cve_id: str,
    dispatch_sources: Sequence[tuple[str, str, str | None]],
    disabled_sources: Sequence[str] = (),
) -> FetchDispatchResult:
    """Publish prepared single-CVE tasks after the owning commit.

    Category C (Redis and broker I/O only; no database access or
    configuration re-read). Callers invoke it with no transaction or row
    lock open.

    Q1: `cve_id` is the canonical CVE-ID; each `dispatch_sources` tuple is
    `(fetcher_name, canonical source, queue or None)` of one enabled
    fetch-single source prepared by the transactional preparation;
    `disabled_sources` holds the canonical sources that preparation found
    registered and refetchable but disabled.

    Q2: a malformed or overlength `cve_id` raises `CVEIdFormatError`, and a
    source repeated within or across both inputs raises `ValueError`, each
    before any Redis or Celery I/O.

    Q3: for each prepared source in code-point order, creates a fresh
    token and attempts `SET fetch_pending:{cve_id}:{source} <token> NX EX
    600`. An existing key adds the source to `sources_already_pending`
    without publication. A `RedisError` logs one bounded WARNING and
    publishes without a marker (fail open). Otherwise publishes
    `fetch_single_cve` with `fetcher_name`, `cve_id`, `source`, and
    `token`, passing `queue` only when non-`None`; a normal return adds the
    source to `sources_enqueued`. Every prepared source is processed.

    Q4: the `FetchDispatchResult`, including `disabled_sources` as
    `sources_disabled`.

    Q5: safe to re-invoke: a current marker coalesces the source, and
    fail-open duplicate tasks are serialized by `upsert_cve()`.

    Q6: any publication `Exception` is ambiguous broker acceptance: the
    source goes to `sources_failed` and its owned marker is retained for
    task cleanup or TTL expiry. Cancellation, `SoftTimeLimitExceeded`, and
    `MemoryError` propagate.
    """
    if not is_valid_cve_id(cve_id):
        raise CVEIdFormatError()
    prepared = sorted(dispatch_sources, key=lambda entry: entry[1])
    all_sources = [source for _, source, _ in prepared] + list(disabled_sources)
    if len(set(all_sources)) != len(all_sources):
        raise ValueError("on-demand dispatch sources must be distinct")

    enqueued: list[str] = []
    already_pending: list[str] = []
    failed: list[str] = []
    client: redis_asyncio.Redis | None = None
    try:
        for fetcher_name, source, queue in prepared:
            token = _new_marker_token()
            if client is None:
                client = _new_redis_client()
            try:
                acquired = await client.set(
                    fetch_pending_key(cve_id, source),
                    token,
                    nx=True,
                    ex=FETCH_PENDING_TTL_SECONDS,
                )
            except RedisError as exc:
                logger.warning(
                    MARKER_UNAVAILABLE_EVENT,
                    cve_id=cve_id,
                    source=source,
                    fetcher_name=fetcher_name,
                    cause=type(exc).__name__,
                )
                acquired = True
            if not acquired:
                already_pending.append(source)
                continue
            try:
                await task_publication.publish_task(
                    FETCH_SINGLE_CVE_TASK,
                    kwargs={
                        "fetcher_name": fetcher_name,
                        "cve_id": cve_id,
                        "source": source,
                        "token": token,
                    },
                    queue=queue,
                )
            except _CONTROL_SIGNALS:
                raise
            except Exception:
                failed.append(source)
            else:
                enqueued.append(source)
    finally:
        if client is not None:
            with suppress(RedisError):
                await client.aclose()
    return FetchDispatchResult(
        sources_enqueued=enqueued,
        sources_already_pending=already_pending,
        sources_disabled=sorted(disabled_sources),
        sources_failed=failed,
    )


class _PendingMarker:
    """Owner-side access to one `fetch_pending` marker of a task attempt.

    Renewal and release are atomic compare-by-token scripts that never
    recreate an absent key, so an old task cannot extend or delete a newer
    owner's marker. Both are best effort: a `RedisError` logs one bounded
    WARNING and never alters database or retry classification.
    """

    def __init__(self, cve_id: str, source: str, token: str) -> None:
        self._cve_id = cve_id
        self._source = source
        self._token = token
        self._client: redis_asyncio.Redis | None = None

    async def renew(self) -> None:
        await self._run(
            _COMPARE_AND_EXPIRE_SCRIPT, "renew", str(FETCH_PENDING_TTL_SECONDS)
        )

    async def release(self) -> None:
        await self._run(_COMPARE_AND_DELETE_SCRIPT, "release")

    async def aclose(self) -> None:
        if self._client is not None:
            with suppress(RedisError):
                await self._client.aclose()
            self._client = None

    async def _run(self, script: str, operation: str, *args: str) -> None:
        if self._client is None:
            self._client = _new_redis_client()
        try:
            await self._client.eval(  # type: ignore[misc]
                script,
                1,
                fetch_pending_key(self._cve_id, self._source),
                self._token,
                *args,
            )
        except RedisError as exc:
            logger.warning(
                MARKER_OPERATION_FAILED_EVENT,
                operation=operation,
                cve_id=self._cve_id,
                source=self._source,
                cause=type(exc).__name__,
            )


def _invalid_payload_fields(
    fetcher_name: object, cve_id: object, source: object, token: object
) -> list[str]:
    """Names (never values) of the payload fields lacking their publication
    format, in a fixed order."""
    invalid: list[str] = []
    if not (
        isinstance(fetcher_name, str)
        and len(fetcher_name) <= _FETCHER_NAME_MAX_LENGTH
        and _FETCHER_NAME_PATTERN.fullmatch(fetcher_name)
    ):
        invalid.append("fetcher_name")
    if not is_valid_cve_id(cve_id):
        invalid.append("cve_id")
    if not (isinstance(source, str) and source in _CVE_SOURCE_VALUES):
        invalid.append("source")
    if not (isinstance(token, str) and _TOKEN_PATTERN.fullmatch(token)):
        invalid.append("token")
    return invalid


async def run_fetch_single_cve(
    fetcher_name: object,
    cve_id: object,
    source: object,
    token: object,
    *,
    attempt: int,
    session_factory: async_sessionmaker[AsyncSession],
) -> FetchSingleRetry | None:
    """Run one `fetch_single_cve` attempt.

    Category A service-owned orchestration (cve-service.md, Transaction
    Ownership): one fresh fetcher instance and one session from
    `session_factory`; `commit_and_dispatch()` is the sole commit of the
    fetched data. Creates no `FetcherRun`, audit event, or durable task
    state. The caller disposes the engine after this function returns.

    Q1: the four untrusted task-payload values and the zero-based Celery
    `attempt` index (`request.retries`).

    Q2: a malformed payload logs one WARNING naming only the malformed
    fields and returns `None` without fetch, status write, or retry; the
    marker is owner-released only when `cve_id`, `source`, and `token` are
    all well-formed.

    Q3: renews the marker by token, then applies the terminal matrix of
    cve-service.md (On-Demand Fetch: fetch_single_cve): unknown target,
    source mismatch or non-capable target, disabled meanwhile, and missing
    CVE are bounded outcomes that never invoke the fetcher; otherwise
    `fetch_single()`, flush, and `commit_and_dispatch()` outside the
    pre-finalization handler. `CVENotInSource` writes an isolated
    `missing` status. Every terminal outcome owner-releases the marker. The
    fetcher's HTTP client is closed on every path.

    Q4: `FetchSingleRetry` when a retryable pre-finalization exception
    occurs within the retry budget (after rollback and owner renewal);
    otherwise `None`.

    Q5: each attempt is independent; ingestion is idempotent through
    `upsert_cve()`.

    Q6: `FetcherConfigMissingError` (bootstrap invariant) propagates.
    After retry exhaustion, or immediately for a non-retryable exception,
    the pre-finalization exception propagates after an isolated `failure`
    status attempt. A commit or post-commit finalization exception
    propagates without isolated status. Each of these emits one
    `fetch_single_cve_failed` ERROR after owner release. Cancellation,
    `SoftTimeLimitExceeded`, and `MemoryError` propagate without marker
    cleanup (the TTL is the backstop).
    """
    invalid = _invalid_payload_fields(fetcher_name, cve_id, source, token)
    if invalid:
        logger.warning(PAYLOAD_INVALID_EVENT, invalid_fields=invalid)
        if not {"cve_id", "source", "token"}.intersection(invalid):
            orphan = _PendingMarker(str(cve_id), str(source), str(token))
            try:
                await orphan.release()
            finally:
                await orphan.aclose()
        return None
    # Every field is a well-formed string from here on.
    fetcher_name, cve_id = cast(str, fetcher_name), cast(str, cve_id)
    source, token = cast(str, source), cast(str, token)

    marker = _PendingMarker(cve_id, source, token)
    fetchers: list[base_cve_fetcher.BaseCVEFetcher] = []
    try:
        await marker.renew()
        return await _fetch_single_attempt(
            fetcher_name,
            cve_id,
            source,
            marker,
            attempt=attempt,
            session_factory=session_factory,
            fetchers=fetchers,
        )
    finally:
        for fetcher in fetchers:
            await fetcher._teardown_http_client()
        await marker.aclose()


def _resolve_fetch_single_target(
    fetcher_name: str, source: str
) -> tuple[str, type[base_cve_fetcher.BaseCVEFetcher] | None]:
    """The registered fetch-single class serving `source`, or a closed
    reason (`unknown_fetcher` / `target_mismatch`) and `None`."""
    fetcher_cls = FETCHER_REGISTRY.get(fetcher_name)
    if fetcher_cls is None:
        return "unknown_fetcher", None
    if not (
        issubclass(fetcher_cls, base_cve_fetcher.BaseCVEFetcher)
        and fetcher_cls.supports_fetch_single
        and fetcher_cls.cve_source_type.value == source
    ):
        return "target_mismatch", None
    return "ok", fetcher_cls


async def _fetch_single_attempt(
    fetcher_name: str,
    cve_id: str,
    source: str,
    marker: _PendingMarker,
    *,
    attempt: int,
    session_factory: async_sessionmaker[AsyncSession],
    fetchers: list[base_cve_fetcher.BaseCVEFetcher],
) -> FetchSingleRetry | None:
    """The terminal matrix of one well-formed attempt (see
    `run_fetch_single_cve`). Every created fetcher is appended to
    `fetchers` so the caller owns its HTTP teardown."""
    context = {"fetcher_name": fetcher_name, "cve_id": cve_id, "source": source}
    reason, fetcher_cls = _resolve_fetch_single_target(fetcher_name, source)
    if fetcher_cls is None:
        logger.error(
            UNKNOWN_FETCHER_EVENT
            if reason == "unknown_fetcher"
            else TARGET_MISMATCH_EVENT,
            **context,
        )
        await marker.release()
        return None

    fetcher = fetcher_cls()
    fetchers.append(fetcher)
    async with session_factory() as session:
        skip: str | None = None
        try:
            if not await get_fetcher_enabled(session, fetcher_name):
                skip = FETCHER_DISABLED_EVENT
            elif (
                await session.scalar(select(CVE.id).where(CVE.cve_id == cve_id))
            ) is None:
                skip = CVE_MISSING_EVENT
            # End the read-only precheck transaction before external I/O.
            await session.rollback()
            if skip is None:
                result = await fetcher.fetch_single(cve_id, session)
                await session.flush()
        except _CONTROL_SIGNALS:
            raise
        except FetcherConfigMissingError:
            logger.error(CONFIG_MISSING_EVENT, **context)
            await marker.release()
            raise
        except base_cve_fetcher.CVENotInSource:
            await session.rollback()
            await fetcher._isolated_status_commit(cve_id, CVESourceFetchStatus.MISSING)
            await marker.release()
            logger.info(COMPLETED_EVENT, outcome="missing", **context)
            return None
        except Exception as exc:
            await session.rollback()
            if is_retryable_condition(exc) and attempt < len(FETCH_SINGLE_RETRY_DELAYS):
                countdown = FETCH_SINGLE_RETRY_DELAYS[attempt]
                await marker.renew()
                logger.warning(
                    RETRY_SCHEDULED_EVENT,
                    cause=type(exc).__name__,
                    retries=attempt,
                    countdown=countdown,
                    **context,
                )
                return FetchSingleRetry(countdown=countdown, cause=exc)
            await fetcher._isolated_status_commit(cve_id, CVESourceFetchStatus.FAILURE)
            await marker.release()
            logger.error(
                FAILED_EVENT,
                stage="pre_finalization",
                cause=type(exc).__name__,
                retries=attempt,
                **context,
            )
            raise

        if skip is not None:
            if skip == FETCHER_DISABLED_EVENT:
                logger.info(skip, **context)
            else:
                logger.warning(skip, **context)
            await marker.release()
            return None

        try:
            await fetcher.commit_and_dispatch(session, result)
        except _CONTROL_SIGNALS:
            raise
        except Exception as exc:
            await marker.release()
            logger.error(
                FAILED_EVENT,
                stage="finalization",
                cause=type(exc).__name__,
                retries=attempt,
                **context,
            )
            raise
    await marker.release()
    logger.info(COMPLETED_EVENT, outcome=result.action.value, **context)
    return None


# ---------------------------------------------------------------------------
# Transactional preparation and the manual refetch orchestration
# (cve-service.md, Fetch Orchestration: `trigger_on_demand_fetch()` >
# Transactional Preparation, Callers and Ordering; Transaction Ownership)
# ---------------------------------------------------------------------------

NO_ELIGIBLE_SOURCE_EVENT: Final = "cve_fetch_no_eligible_source"
"""INFO: an automatic freshness preparation found no enabled refetchable
source, so no publication was registered."""

PUBLICATION_UNCONFIRMED_EVENT: Final = "cve_fetch_publication_unconfirmed"
"""WARNING: at least one on-demand publication attempt raised; broker
acceptance of those sources is unconfirmed."""


class OnDemandFetchTrigger(StrEnum):
    """The workflow that prepared an on-demand fetch, carried by its logs."""

    REFETCH = "refetch"
    TICKET_CREATE = "ticket_create"
    CVE_ASSOCIATE = "cve_associate"


class _PreparationMode(StrEnum):
    """The two modes of the one preparation boundary.

    `CONSUMER` is the manual refetch: it evaluates CVE accessibility from
    the locked-current roots. `AUTOMATIC` is the create/associate freshness
    refresh: its caller already holds both roots and made its own
    locked-current decision (or created the Ticket), so the roots are
    re-locked without a second accessibility evaluation.
    """

    CONSUMER = "consumer"
    AUTOMATIC = "automatic"


type DispatchSource = tuple[str, str, str | None]
"""One prepared enabled source: `(fetcher name, canonical source, queue)`."""


@dataclass(frozen=True, slots=True)
class _PreparedFetch:
    """The primitive values handed to database-free publication.

    Both tuples are in ascending canonical-source code-point order. An empty
    `dispatch_sources` is the no-eligible-source outcome.
    """

    cve_id: str
    dispatch_sources: tuple[DispatchSource, ...]
    disabled_sources: tuple[str, ...]


async def _prepare_on_demand_fetch(
    db: AsyncSession,
    cve_id: str,
    *,
    mode: _PreparationMode,
    source: str | None = None,
    caller: TicketCaller | None = None,
) -> _PreparedFetch:
    """The transactional preparation boundary of an on-demand fetch.

    Runs in the session it receives and never commits or rolls back; it
    creates no row or audit event and never calls `ensure_ticket_operable()`.

    (1) Input-only CVE-ID format guard. (2) Locks the CVE `FOR NO KEY
    UPDATE`, then its optional associated Ticket `FOR UPDATE` (a
    same-transaction no-op for the automatic callers). Only key columns are
    selected, so caller-loaded ORM state is never refreshed. (3) `CONSUMER`
    only: evaluates CVE accessibility for `caller` in a separate statement
    after both locks. (4) Only then reads the fetch-single registry and the
    `FetcherConfig` rows of the applicable fetchers. (5) Classifies the
    explicit `source` or the broadcast roster. (6) Projects the enabled
    sources in canonical-source order.

    Raises `CVEIdFormatError` (malformed), `CVENotFoundError` (missing, or
    inaccessible in `CONSUMER` mode), `CVEInvalidSourceError` (explicit
    source not registered as refetchable), `CVESourceDisabledError`
    (explicit source disabled), and `FetcherConfigMissingError` (bootstrap
    invariant). Database exceptions propagate unchanged.
    """
    if (mode is _PreparationMode.CONSUMER) != (caller is not None):
        raise ValueError("a caller is required exactly for consumer preparation")
    if mode is _PreparationMode.AUTOMATIC and source is not None:
        raise ValueError("automatic preparation always broadcasts")
    if not is_valid_cve_id(cve_id):
        raise CVEIdFormatError()

    cve_pk = (
        await db.execute(
            select(CVE.id).where(CVE.cve_id == cve_id).with_for_update(key_share=True)
        )
    ).scalar_one_or_none()
    if cve_pk is None:
        raise CVENotFoundError()
    ticket_pk = (
        await db.execute(
            select(Ticket.id).where(Ticket.cve_id == cve_pk).with_for_update()
        )
    ).scalar_one_or_none()
    if caller is not None and ticket_pk is not None:
        accessible = (
            await db.execute(
                select(ticket_visibility_condition(caller))
                .select_from(Ticket)
                .where(Ticket.id == ticket_pk)
            )
        ).scalar_one()
        if not accessible:
            raise CVENotFoundError()

    registry = base_cve_fetcher.get_fetch_single_fetchers()
    if source is not None:
        if source not in registry:
            raise CVEInvalidSourceError()
        registry = {source: registry[source]}
    enabled_by_name = await _fetcher_enabled_states(
        db, [fetcher_cls.name for fetcher_cls in registry.values()]
    )

    dispatch: list[DispatchSource] = []
    disabled: list[str] = []
    for canonical_source in sorted(registry):
        fetcher_cls = registry[canonical_source]
        if enabled_by_name[fetcher_cls.name]:
            dispatch.append((fetcher_cls.name, canonical_source, fetcher_cls.queue))
        else:
            disabled.append(canonical_source)
    if source is not None and disabled:
        raise CVESourceDisabledError()
    return _PreparedFetch(
        cve_id=cve_id,
        dispatch_sources=tuple(dispatch),
        disabled_sources=tuple(disabled),
    )


async def _fetcher_enabled_states(
    db: AsyncSession, fetcher_names: Sequence[str]
) -> dict[str, bool]:
    """`FetcherConfig.enabled` of every named registered fetcher, from one
    statement. A missing row raises `FetcherConfigMissingError`."""
    if not fetcher_names:
        return {}
    rows = (
        await db.execute(
            select(FetcherConfig.fetcher_name, FetcherConfig.enabled).where(
                FetcherConfig.fetcher_name.in_(fetcher_names)
            )
        )
    ).all()
    states = {row.fetcher_name: row.enabled for row in rows}
    for fetcher_name in sorted(fetcher_names):
        if fetcher_name not in states:
            raise FetcherConfigMissingError(
                f"No FetcherConfig row for registered fetcher '{fetcher_name}'"
            )
    return states


async def _publish_prepared(
    prepared: _PreparedFetch, trigger: OnDemandFetchTrigger
) -> FetchDispatchResult:
    """Database-free publication of prepared values, logging a non-empty
    `sources_failed` once (canonical CVE-ID and sources only)."""
    result = await trigger_on_demand_fetch(
        prepared.cve_id, prepared.dispatch_sources, prepared.disabled_sources
    )
    if result.sources_failed:
        logger.warning(
            PUBLICATION_UNCONFIRMED_EVENT,
            cve_id=prepared.cve_id,
            sources_failed=result.sources_failed,
            trigger=trigger.value,
        )
    return result


async def refetch_cve(
    *,
    cve_id: str,
    source: str | None,
    caller: TicketCaller,
    session_factory: async_sessionmaker[AsyncSession],
) -> FetchDispatchResult:
    """Manually refetch one CVE from one or every refetchable source.

    Service-owned orchestration boundary of `POST
    /api/v1/cves/{cve_id}/refetch` (cve-service.md, Callers and Ordering;
    Transaction Ownership; cve-tracking.md, Re-fetch Endpoint). Dispatch
    only: creates no audit event, changes no CVE, Ticket, source status, or
    configuration, and never calls `ensure_ticket_operable()`.

    Q1: `cve_id` is the raw path value; `source` the optional raw query
    value; `caller` the request-resolved caller information;
    `session_factory` opens the one short preparation session.

    Q2: the API has authenticated the caller and verified `triage_ticket`
    before any lookup. The preparation transaction locks the CVE, then the
    optional Ticket, and performs no network I/O while holding them.

    Q3: (1) a malformed `cve_id` is not found before any I/O. (2) Runs the
    consumer preparation in one session, commits, and closes it, releasing
    the locks. (3) With no transaction or lock open, publishes through
    `trigger_on_demand_fetch()` and logs a non-empty `sources_failed` once.
    Registers no post-commit callback.

    Q4: the `FetchDispatchResult`. Mapping an all-unconfirmed result to
    `503 CELERY_UNAVAILABLE` is the endpoint's response contract.

    Q5: safe to repeat; the pending marker coalesces current work.

    Q6: `CVENotFoundError` (malformed, missing, inaccessible),
    `CVEInvalidSourceError`, `CVESourceDisabledError`, and
    `CVEFetchFailedError` (no enabled refetchable broadcast source), each
    with zero Redis and Celery I/O. `FetcherConfigMissingError`, database,
    and commit exceptions propagate with no publication.
    """
    if not is_valid_cve_id(cve_id):
        raise CVENotFoundError()
    async with session_factory() as session:
        prepared = await _prepare_on_demand_fetch(
            session,
            cve_id,
            mode=_PreparationMode.CONSUMER,
            source=source,
            caller=caller,
        )
        if not prepared.dispatch_sources:
            raise CVEFetchFailedError()
        await session.commit()
    return await _publish_prepared(prepared, OnDemandFetchTrigger.REFETCH)


async def prepare_freshness_refresh(
    db: AsyncSession, *, cve_id: str, trigger: OnDemandFetchTrigger
) -> None:
    """Prepare and register the all-source freshness refresh of a manual
    create-with-CVE or CVE association.

    Category A step of `ticket_service.create_ticket()` (step 11) and
    `associate_cve()` (step 14), called last, after every creation,
    association, CVSS, Product, reconciliation, and audit write
    (cve-service.md, Transactional Preparation, Callers and Ordering).

    Q1: `cve_id` is the canonical CVE-ID of the CVE root the caller holds;
    `trigger` names the calling workflow for the logs.

    Q2: runs in the caller-owned API transaction, which already holds the
    CVE `FOR NO KEY UPDATE` and the Ticket `FOR UPDATE`; the re-locks are
    same-transaction no-ops and accessibility is not re-evaluated. Never
    commits, rolls back, or performs network I/O.

    Q3: on the no-eligible-source outcome (empty fetch-single registry or
    every source disabled) logs one `cve_fetch_no_eligible_source` INFO and
    registers nothing. Otherwise registers one database-free effect through
    `register_post_commit_callback()`; `get_db()` runs it only after its
    commit, and never after a rollback.

    Q6: `FetcherConfigMissingError` and database exceptions propagate and
    roll back the caller's mutation. After commit, publication failure is
    best effort: the effect logs a non-empty `sources_failed` once.
    """
    if trigger is OnDemandFetchTrigger.REFETCH:
        raise ValueError("the refetch trigger uses refetch_cve()")
    prepared = await _prepare_on_demand_fetch(
        db, cve_id, mode=_PreparationMode.AUTOMATIC
    )
    if not prepared.dispatch_sources:
        logger.info(NO_ELIGIBLE_SOURCE_EVENT, cve_id=cve_id, trigger=trigger.value)
        return

    async def _publish() -> None:
        await _publish_prepared(prepared, trigger)

    register_post_commit_callback(db, _publish)
