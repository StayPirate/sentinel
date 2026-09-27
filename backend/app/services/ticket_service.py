"""Ticket reads, lifecycle operations, and cross-domain Ticket compositions.

See `docs/features/tickets/ticket-service.md` for the full
specification. This module currently implements the consumer-facing
Ticket locator resolution (Ticket Query Operations > Ticket locator
resolution), the Ticket list (`list_tickets()`), and the Ticket detail
read in its consumer and mutation-assembly modes (Ticket Query
Operations > `get_ticket_detail()`); the lifecycle operations are added
by their owning work items.

Every operation accepts the caller's `AsyncSession` and never commits or
rolls back; database exceptions propagate unchanged (Transaction
ownership).

Ticket detail. Both modes run one SQL statement, and therefore observe
one PostgreSQL snapshot, that selects the Ticket root, its resolved
severity and priority fields, the current assignee, the expanded CVE with
its KEV, EPSS, SSVC, CWE, and external-identifier evidence, the duplicate
target's `sequence_id`, and the package-owned complete tree
(`package_service.ticket_package_tree_column()`). The consumer mode
(`get_ticket_detail()`) constrains that statement by the canonical
visibility predicate; the mutation-assembly mode
(`assemble_ticket_detail()`) selects the caller's transaction-owned or
locked Ticket by internal UUID and applies no second visibility decision.
Both return the same semantic projection; no Pydantic type enters this
layer.

Ticket list. `list_tickets()` also runs one SQL statement (a CTE chain:
visible and filtered Tickets, their total, the requested page, then the
page's one-to-one assignee, CVE, and duplicate target plus the included
package names), so rows, total, resolved users, severity, sorting, and
pagination derive from one PostgreSQL observation. Due dates, milestone
statuses, and resolved severity come from the shared SQL expressions of
`ticket_deadline_expressions` and `ticket_severity`; User filters use the
user-domain matching condition of `user_service`.
"""

from __future__ import annotations

import re
from collections.abc import Collection, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, date, datetime
from enum import StrEnum
from typing import Any, Final
from uuid import UUID

from sqlalchemy import (
    ColumnElement,
    DateTime,
    Select,
    SQLColumnExpression,
    String,
    and_,
    case,
    cast,
    exists,
    false,
    func,
    literal,
    literal_column,
    or_,
    select,
    true,
    type_coerce,
)
from sqlalchemy.dialects.postgresql import JSON, aggregate_order_by
from sqlalchemy.engine import Row
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import aliased

from app.core.enums import (
    CveState,
    MilestonePhase,
    MilestoneStatus,
    Severity,
    SortOrder,
    TicketPriority,
    TicketSortField,
    TicketStatus,
)
from app.core.exceptions import TicketNotFoundError
from app.core.identifiers import format_ticket_id, parse_ticket_id
from app.models.cve import CVE
from app.models.cve_cwe import CVECWE
from app.models.cve_epss_score import CVEEPSSScore
from app.models.cve_external_identifier import CVEExternalIdentifier
from app.models.cve_kev_entry import CVEKEVEntry
from app.models.cve_ssvc_assessment import CVESSVCAssessment
from app.models.ticket import Ticket
from app.models.ticket_package import TicketPackage
from app.models.ticket_package_maintainer import TicketPackageMaintainer
from app.models.ticket_package_track import TicketPackageTrack
from app.models.user import User
from app.services import package_service
from app.services.package_service import PackageProjection
from app.services.ticket_deadline_expressions import (
    TicketDueDateExpressions,
    ticket_due_date_expressions,
    track_milestone_status_expression,
)
from app.services.ticket_deadlines import DueDates, compute_due_dates
from app.services.ticket_severity import resolved_severity_expression
from app.services.ticket_visibility import TicketCaller, ticket_visibility_condition
from app.services.user_service import user_identifier_condition

_EMPTY_JSON_ARRAY: Final[ColumnElement[Any]] = literal_column("'[]'::json")
_CODE_POINT_COLLATION: Final = "C"

_ASSIGNEE = aliased(User, name="detail_assignee")
_DUPLICATE_TARGET = aliased(Ticket, name="detail_duplicate_target")


@dataclass(frozen=True, slots=True)
class ResolvedTicket:
    """An accessible Ticket selected by its public `SNTL-{n}` locator.

    `id` is the internal Ticket UUID, usable only as an internal service
    locator; it is never a consumer response field. `sequence_id` is the
    `n` of the public identifier.
    """

    id: UUID
    sequence_id: int


# ---------------------------------------------------------------------------
# Ticket detail semantic projection
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class TicketUserProjection:
    """The current profile of a referenced User (api-spec.md, User
    References in Responses): selected from the current `User` row, never
    a historical snapshot."""

    id: UUID
    username: str
    full_name: str | None
    active: bool


@dataclass(frozen=True, slots=True)
class CVEKEVProjection:
    """The persisted CISA KEV catalog entry of a CVE."""

    date_added: date
    reference_url: str | None


@dataclass(frozen=True, slots=True)
class CVEEPSSProjection:
    """The latest persisted FIRST EPSS snapshot of a CVE."""

    score: float
    percentile: float
    assessed_at: date


@dataclass(frozen=True, slots=True)
class CVESSVCProjection:
    """The persisted CISA SSVC decision points of a CVE (stored labels)."""

    exploitation: str
    automatable: str
    technical_impact: str
    version: str
    assessed_at: datetime | None


@dataclass(frozen=True, slots=True)
class CVEWeaknessProjection:
    """One distinct CWE of a CVE with every provider that assigned it,
    exact-deduplicated and in ascending Unicode code-point order."""

    cwe_id: str
    sources: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class CVEExternalIdentifierProjection:
    """One external vulnerability identifier of a CVE.

    `source` is the stored `CVEExternalIdentifierSource` value (for
    example `"GHSA"`); the wire format lowercases it.
    """

    source: str
    identifier: str
    url: str | None


@dataclass(frozen=True, slots=True)
class CVEDetailProjection:
    """The expanded current CVE of a Ticket (`CVEDetail`).

    `severity` is the CVE-owned unified severity (`None` is SQL `NULL`,
    unresolved; `Severity.NONE` is the resolved `None` label).
    `external_identifiers` are ordered by source, identifier, then
    `CVEExternalIdentifier.id`; `cwes` by `cwe_id`, all in ascending
    Unicode code-point order. CVSS assessments are never inline.
    """

    cve_id: str
    title: str | None
    description: str | None
    published_date: datetime | None
    modified_date: datetime | None
    cve_state: CveState
    date_rejected: datetime | None
    severity: Severity | None
    external_identifiers: tuple[CVEExternalIdentifierProjection, ...]
    kev: CVEKEVProjection | None
    epss: CVEEPSSProjection | None
    ssvc: CVESSVCProjection | None
    cwes: tuple[CVEWeaknessProjection, ...]


@dataclass(frozen=True, slots=True)
class TicketDetailProjection:
    """The semantic projection represented by `TicketDetail`.

    `ticket_id` is the public `SNTL-{n}` identity; the internal Ticket
    UUID is deliberately absent. `severity` is the resolved severity
    (tickets.md, Severity Resolution). `priority` is the effective
    priority `COALESCE(priority_override, priority_automatic)`.
    `due_dates` is `None` when no SLA applies (every Ticket-level due
    date is then `null`). `duplicate_of_ticket_id` is the direct target's
    `SNTL-{n}` identity only. `packages` is the package-owned complete
    tree for the same evaluation date and instant.
    """

    ticket_id: str
    status: TicketStatus
    severity: Severity | None
    priority: TicketPriority | None
    priority_automatic: TicketPriority | None
    priority_override: TicketPriority | None
    assignee: TicketUserProjection | None
    cve: CVEDetailProjection | None
    duplicate_of_ticket_id: str | None
    is_confidential: bool
    coordinated_release_at: datetime | None
    due_dates: DueDates | None
    packages: tuple[PackageProjection, ...]
    created_at: datetime
    updated_at: datetime


# ---------------------------------------------------------------------------
# Ticket list semantic projection
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class CVESummaryProjection:
    """The compact current CVE of a Ticket (`CVESummary`)."""

    cve_id: str
    title: str | None
    description: str | None


@dataclass(frozen=True, slots=True)
class TicketSummaryProjection:
    """The semantic projection represented by `TicketSummary`.

    `ticket_id` is the public `SNTL-{n}` identity; the internal Ticket
    UUID is deliberately absent. `severity` is the resolved severity and
    `priority` the effective priority, the same values the list filtered
    and sorted by. `due_dates` is `None` when no SLA applies.
    `package_names` are the directly included package names in ascending
    Unicode code-point order.
    """

    ticket_id: str
    status: TicketStatus
    severity: Severity | None
    priority: TicketPriority | None
    assignee: TicketUserProjection | None
    cve: CVESummaryProjection | None
    duplicate_of_ticket_id: str | None
    is_confidential: bool
    coordinated_release_at: datetime | None
    due_dates: DueDates | None
    package_names: tuple[str, ...]
    created_at: datetime
    updated_at: datetime


@dataclass(frozen=True, slots=True)
class TicketPage:
    """One page of Ticket summaries and the total of visible, filtered
    Tickets (computed before page slicing)."""

    items: tuple[TicketSummaryProjection, ...]
    total: int
    page: int
    per_page: int


# ---------------------------------------------------------------------------
# Clock
# ---------------------------------------------------------------------------


def _utc_now() -> datetime:
    """The current instant in UTC (patched by controlled-clock tests)."""
    return datetime.now(UTC)


# ---------------------------------------------------------------------------
# Ticket detail statement
# ---------------------------------------------------------------------------


def _key(name: str) -> ColumnElement[str]:
    """An inline JSON object key (a SQL literal, not a bound parameter)."""
    return literal_column(f"'{name}'")


def _json_array(
    element: ColumnElement[Any], *order_by: SQLColumnExpression[Any]
) -> ColumnElement[Any]:
    """`COALESCE(json_agg(element ORDER BY ...), '[]')`."""
    return func.coalesce(
        func.json_agg(aggregate_order_by(element, *order_by)), _EMPTY_JSON_ARRAY
    )


def _cwe_assignments_column() -> ColumnElement[Any]:
    """Every `(cwe_id, source)` pair of the enclosing CVE as a JSON array,
    ordered by `cwe_id` then `source` in code-point order; `[]` when none
    exist (grouped into `CVEWeaknessProjection` values by `_cwes()`)."""
    pairs = (
        select(
            _json_array(
                func.json_build_array(CVECWE.cwe_id, CVECWE.source),
                CVECWE.cwe_id.collate(_CODE_POINT_COLLATION),
                CVECWE.source.collate(_CODE_POINT_COLLATION),
            )
        )
        .where(CVECWE.cve_id == CVE.id)
        .correlate_except(CVECWE)
        .scalar_subquery()
    )
    return type_coerce(pairs, JSON)


def _external_identifiers_column() -> ColumnElement[Any]:
    """External identifiers of the enclosing CVE as a JSON array, ordered by
    source, identifier (code point), then `CVEExternalIdentifier.id`."""
    identifier = func.json_build_object(
        _key("source"),
        CVEExternalIdentifier.source,
        _key("identifier"),
        CVEExternalIdentifier.identifier,
        _key("url"),
        CVEExternalIdentifier.url,
    )
    identifiers = (
        select(
            _json_array(
                identifier,
                CVEExternalIdentifier.source.collate(_CODE_POINT_COLLATION),
                CVEExternalIdentifier.identifier.collate(_CODE_POINT_COLLATION),
                CVEExternalIdentifier.id,
            )
        )
        .where(CVEExternalIdentifier.cve_id == CVE.id)
        .correlate_except(CVEExternalIdentifier)
        .scalar_subquery()
    )
    return type_coerce(identifiers, JSON)


def _detail_statement(evaluation_date: date) -> Select[Any]:
    """The single detail statement rooted at `Ticket`, without a filter.

    Every joined relation is at most one row per Ticket (`User.id`,
    `Ticket.id`, and `CVE.id` are keys; KEV, EPSS, and SSVC are unique by
    `cve_id`), and every collection is a correlated scalar subquery, so
    the statement yields exactly one row per selected Ticket. The
    duplicate target contributes only its `sequence_id`. The caller adds
    the `WHERE` clause that owns the Ticket selection.
    """
    tree = package_service.ticket_package_tree_column(Ticket.id, evaluation_date)
    return (
        select(
            Ticket.sequence_id.label("sequence_id"),
            Ticket.priority_auto.label("priority_automatic"),
            Ticket.priority_override.label("priority_override"),
            func.coalesce(Ticket.priority_override, Ticket.priority_auto).label(
                "priority"
            ),
            Ticket.is_confidential.label("is_confidential"),
            Ticket.coordinated_release_at.label("coordinated_release_at"),
            Ticket.updated_at.label("updated_at"),
            _ASSIGNEE.id.label("assignee_id"),
            _ASSIGNEE.username.label("assignee_username"),
            _ASSIGNEE.full_name.label("assignee_full_name"),
            _ASSIGNEE.active.label("assignee_active"),
            _DUPLICATE_TARGET.sequence_id.label("duplicate_sequence_id"),
            CVE.id.label("cve_pk"),
            CVE.cve_id.label("cve_id"),
            CVE.title.label("cve_title"),
            CVE.description.label("cve_description"),
            CVE.published_date.label("cve_published_date"),
            CVE.modified_date.label("cve_modified_date"),
            CVE.cve_state.label("cve_state"),
            CVE.date_rejected.label("cve_date_rejected"),
            CVE.severity.label("cve_severity"),
            CVEKEVEntry.id.label("kev_pk"),
            CVEKEVEntry.date_added.label("kev_date_added"),
            CVEKEVEntry.reference_url.label("kev_reference_url"),
            CVEEPSSScore.id.label("epss_pk"),
            CVEEPSSScore.score.label("epss_score"),
            CVEEPSSScore.percentile.label("epss_percentile"),
            CVEEPSSScore.assessed_at.label("epss_assessed_at"),
            CVESSVCAssessment.id.label("ssvc_pk"),
            CVESSVCAssessment.exploitation.label("ssvc_exploitation"),
            CVESSVCAssessment.automatable.label("ssvc_automatable"),
            CVESSVCAssessment.technical_impact.label("ssvc_technical_impact"),
            CVESSVCAssessment.version.label("ssvc_version"),
            CVESSVCAssessment.assessed_at.label("ssvc_assessed_at"),
            _cwe_assignments_column().label("cve_cwe_assignments"),
            _external_identifiers_column().label("cve_external_identifiers"),
            *package_service.ticket_tree_context_columns(),
            tree.label("packages"),
        )
        .select_from(Ticket)
        .outerjoin(_ASSIGNEE, _ASSIGNEE.id == Ticket.assignee_id)
        .outerjoin(_DUPLICATE_TARGET, _DUPLICATE_TARGET.id == Ticket.duplicate_of_id)
        .outerjoin(CVE, CVE.id == Ticket.cve_id)
        .outerjoin(CVEKEVEntry, CVEKEVEntry.cve_id == CVE.id)
        .outerjoin(CVEEPSSScore, CVEEPSSScore.cve_id == CVE.id)
        .outerjoin(CVESSVCAssessment, CVESSVCAssessment.cve_id == CVE.id)
    )


# ---------------------------------------------------------------------------
# Ticket detail assembly
# ---------------------------------------------------------------------------


def _priority(value: str | None) -> TicketPriority | None:
    return TicketPriority(value) if value is not None else None


def _cwes(assignments: Sequence[Sequence[str]]) -> tuple[CVEWeaknessProjection, ...]:
    """Group ordered `(cwe_id, source)` pairs by CWE, exact-deduplicating
    the sources while keeping their code-point order."""
    grouped: dict[str, dict[str, None]] = {}
    for cwe_id, source in assignments:
        grouped.setdefault(cwe_id, {})[source] = None
    return tuple(
        CVEWeaknessProjection(cwe_id=cwe_id, sources=tuple(sources))
        for cwe_id, sources in grouped.items()
    )


def _external_identifiers(
    raw: Sequence[Mapping[str, Any]],
) -> tuple[CVEExternalIdentifierProjection, ...]:
    return tuple(
        CVEExternalIdentifierProjection(
            source=item["source"], identifier=item["identifier"], url=item["url"]
        )
        for item in raw
    )


def _cve(row: Row[Any]) -> CVEDetailProjection | None:
    if row.cve_pk is None:
        return None
    return CVEDetailProjection(
        cve_id=row.cve_id,
        title=row.cve_title,
        description=row.cve_description,
        published_date=row.cve_published_date,
        modified_date=row.cve_modified_date,
        cve_state=CveState(row.cve_state),
        date_rejected=row.cve_date_rejected,
        severity=Severity(row.cve_severity) if row.cve_severity is not None else None,
        external_identifiers=_external_identifiers(row.cve_external_identifiers),
        kev=(
            CVEKEVProjection(
                date_added=row.kev_date_added, reference_url=row.kev_reference_url
            )
            if row.kev_pk is not None
            else None
        ),
        epss=(
            CVEEPSSProjection(
                score=row.epss_score,
                percentile=row.epss_percentile,
                assessed_at=row.epss_assessed_at,
            )
            if row.epss_pk is not None
            else None
        ),
        ssvc=(
            CVESSVCProjection(
                exploitation=row.ssvc_exploitation,
                automatable=row.ssvc_automatable,
                technical_impact=row.ssvc_technical_impact,
                version=row.ssvc_version,
                assessed_at=row.ssvc_assessed_at,
            )
            if row.ssvc_pk is not None
            else None
        ),
        cwes=_cwes(row.cve_cwe_assignments),
    )


def _project(row: Row[Any], *, evaluation_instant: datetime) -> TicketDetailProjection:
    """Assemble the projection from one `_detail_statement()` row.

    The Ticket-level due dates and the per-track dates share the same
    Ticket context (resolved severity, status, `created_at`) selected in
    the row. Pure.
    """
    context = package_service.ticket_tree_context_from_row(row)
    assignee = (
        TicketUserProjection(
            id=row.assignee_id,
            username=row.assignee_username,
            full_name=row.assignee_full_name,
            active=row.assignee_active,
        )
        if row.assignee_id is not None
        else None
    )
    duplicate_sequence_id: int | None = row.duplicate_sequence_id
    return TicketDetailProjection(
        ticket_id=format_ticket_id(row.sequence_id),
        status=context.status,
        severity=context.severity,
        priority=_priority(row.priority),
        priority_automatic=_priority(row.priority_automatic),
        priority_override=_priority(row.priority_override),
        assignee=assignee,
        cve=_cve(row),
        duplicate_of_ticket_id=(
            format_ticket_id(duplicate_sequence_id)
            if duplicate_sequence_id is not None
            else None
        ),
        is_confidential=row.is_confidential,
        coordinated_release_at=row.coordinated_release_at,
        due_dates=compute_due_dates(
            created_at=context.created_at,
            severity=context.severity,
            ticket_status=context.status,
        ),
        packages=package_service.assemble_ticket_packages(
            row.packages, ticket=context, evaluation_instant=evaluation_instant
        ),
        created_at=context.created_at,
        updated_at=row.updated_at,
    )


# ---------------------------------------------------------------------------
# Query operations
# ---------------------------------------------------------------------------


async def resolve_ticket_locator(
    db: AsyncSession, ticket_id: str, caller: TicketCaller
) -> ResolvedTicket:
    """Resolve a consumer `SNTL-{n}` locator to an accessible Ticket.

    Category B read (ticket-service.md, Ticket locator resolution;
    api-spec.md, Ticket Identifier Resolution).

    Q1: `ticket_id` is the raw consumer locator (a path value);
    `caller` is the request-resolved caller information.

    Q3: parses the value with `core.identifiers.parse_ticket_id()` (no
    trimming or normalization), then selects the Ticket by
    `Ticket.sequence_id` in one statement constrained by the canonical
    visibility predicate. Creates no event, acquires no lock, and never
    commits or rolls back.

    Q4: returns the selected Ticket's internal UUID and sequence number.
    This is a preliminary decision only: it never authorizes a later
    unconstrained query. Reads re-apply visibility in the selection that
    returns data, and mutations revalidate against locked-current state.

    Q6: raises `TicketNotFoundError` when the locator is malformed
    (including a Ticket UUID), no Ticket has that sequence number, or the
    Ticket is inaccessible to `caller` — without distinguishing the
    causes. Malformed input performs no database query. Database
    exceptions propagate unchanged.
    """
    sequence_id = parse_ticket_id(ticket_id)
    if sequence_id is None:
        raise TicketNotFoundError()
    row = (
        await db.execute(
            select(Ticket.id, Ticket.sequence_id).where(
                Ticket.sequence_id == sequence_id,
                ticket_visibility_condition(caller),
            )
        )
    ).one_or_none()
    if row is None:
        raise TicketNotFoundError()
    return ResolvedTicket(id=row.id, sequence_id=row.sequence_id)


async def get_ticket_detail(
    db: AsyncSession, *, ticket_id: str, caller: TicketCaller
) -> TicketDetailProjection:
    """Return the detail of one accessible Ticket (consumer mode).

    Category B read (ticket-service.md, Ticket Query Operations >
    `get_ticket_detail()`; tickets.md, TicketDetail and Get Ticket).

    Q1: `ticket_id` is the raw public `SNTL-{n}` locator; `caller` is the
    request-resolved caller information.

    Q3: captures one UTC evaluation instant exactly once at entry and
    uses its UTC calendar date as the read's `evaluation_date`
    (ticket-deadlines.md, Evaluation Instant); a read-only request
    accepts no separately selected date. Parses the locator without
    normalization, then, in one SQL statement and therefore one
    PostgreSQL snapshot, selects the Ticket by `sequence_id` under the
    canonical visibility predicate together with every component of the
    detail: root fields, resolved severity, effective, automatic, and
    override priority, the current assignee, the expanded CVE with its
    KEV, EPSS, SSVC, grouped CWE, and ordered external-identifier
    evidence (no inline CVSS), the duplicate target's `sequence_id` only
    (no chain following, no target content, no second protected lookup),
    and the package-owned complete tree for that date. Ticket-level due
    dates come from `compute_due_dates()`; per-track milestones compare
    against the same instant. Maintainer identities are neither loaded
    nor projected. Creates no event, acquires no lock, and never commits
    or rolls back.

    Q4: returns the `TicketDetailProjection`.

    Q6: raises `TicketNotFoundError` when the locator is malformed
    (including a Ticket UUID; no query is run), no Ticket has that
    sequence number, or the Ticket is inaccessible to `caller` — without
    distinguishing the causes. Database exceptions propagate unchanged.
    """
    evaluation_instant = _utc_now()
    sequence_id = parse_ticket_id(ticket_id)
    if sequence_id is None:
        raise TicketNotFoundError()
    statement = _detail_statement(evaluation_instant.astimezone(UTC).date()).where(
        Ticket.sequence_id == sequence_id, ticket_visibility_condition(caller)
    )
    row = (await db.execute(statement)).one_or_none()
    if row is None:
        raise TicketNotFoundError()
    return _project(row, evaluation_instant=evaluation_instant)


async def assemble_ticket_detail(
    db: AsyncSession, *, ticket_id: UUID, evaluation_date: date
) -> TicketDetailProjection:
    """Return the post-mutation detail of a Ticket (mutation-assembly mode).

    Category B read (ticket-service.md, Ticket Query Operations >
    `get_ticket_detail()`, mutation assembly) used by every mutation that
    returns `TicketDetail`, inside its caller-owned transaction after the
    mutation has produced the post-state.

    Q1: `ticket_id` is the internal UUID of the transaction-owned new
    Ticket (creation) or of the mutation's locked Ticket whose
    locked-pre-state authorization already succeeded; it is never a
    consumer locator. `evaluation_date` is the workflow's existing UTC
    date, reused for lifecycle and actionability and never recaptured.

    Q3: captures the evaluation instant at projection entry for milestone
    comparisons (ticket-deadlines.md, Evaluation Instant), so a
    projection crossing UTC midnight after the workflow date was captured
    keeps the workflow date for actionability and compares milestones
    against the later instant. Runs the same single detail statement as
    `get_ticket_detail()`, selected by `Ticket.id` in the caller's
    session (observing its flushed, uncommitted post-state) and without
    the visibility predicate: a mutation that removes the actor's final
    visibility path still returns its post-mutation detail. Creates no
    event, acquires no lock, and never commits or rolls back.

    Q4: returns the `TicketDetailProjection`.

    Q6: raises `sqlalchemy.exc.NoResultFound` when no Ticket has that UUID
    — an invariant violation of the calling workflow, which then rolls
    back its mutation and audit events. Database exceptions propagate
    unchanged.
    """
    evaluation_instant = _utc_now()
    statement = _detail_statement(evaluation_date).where(Ticket.id == ticket_id)
    row = (await db.execute(statement)).one()
    return _project(row, evaluation_instant=evaluation_instant)


# ---------------------------------------------------------------------------
# Ticket list
# ---------------------------------------------------------------------------

MAX_PER_PAGE: Final = 100
ASSIGNEE_NONE: Final = "none"
"""The literal `assignee` filter value selecting unassigned Tickets; it is
handled before User resolution (docs/api-spec.md, User Identifier
Resolution)."""

_LIKE_ESCAPE: Final = "\\"
_SNTL_PREFIX: Final = "sntl-"
_CVE_PREFIX: Final = "CVE-"
_DIGITS: Final = re.compile(r"[0-9]+")
_YEAR_NUMBER: Final = re.compile(r"[0-9]{4}-[0-9]+")

_TRIAGE_OPEN_STATUSES: Final = (TicketStatus.NEW.value, TicketStatus.ANALYSIS.value)

# Semantic ranks (docs/api-spec.md, Semantic Sort Fields). SQL `NULL` is
# not ranked, so it sorts last under Nullable Sort Field Ordering.
_SEVERITY_RANK: Final[dict[str, int]] = {
    Severity.NONE.value: 0,
    Severity.LOW.value: 1,
    Severity.MEDIUM.value: 2,
    Severity.HIGH.value: 3,
    Severity.CRITICAL.value: 4,
}
_PRIORITY_RANK: Final[dict[str, int]] = {
    TicketPriority.P4.value: 0,
    TicketPriority.P3.value: 1,
    TicketPriority.P2.value: 2,
    TicketPriority.P1.value: 3,
}
_STATUS_RANK: Final[dict[str, int]] = {
    TicketStatus.NEW.value: 0,
    TicketStatus.ANALYSIS.value: 1,
    TicketStatus.ANALYZED.value: 2,
    TicketStatus.RESOLVED.value: 3,
    TicketStatus.IGNORED.value: 4,
    TicketStatus.DUPLICATED.value: 5,
}

_LIST_ASSIGNEE = aliased(User, name="list_assignee")
_LIST_DUPLICATE_TARGET = aliased(Ticket, name="list_duplicate_target")


def _escape_like(term: str) -> str:
    """Escape `term` so `%`, `_`, and backslash match literally under
    `ESCAPE '\\'` (backslash first, so added escapes are not doubled)."""
    return (
        term.replace(_LIKE_ESCAPE, _LIKE_ESCAPE * 2)
        .replace("%", f"{_LIKE_ESCAPE}%")
        .replace("_", f"{_LIKE_ESCAPE}_")
    )


def _sequence_prefix(term: str) -> str | None:
    """The digits searched in the SNTL identifier field, or `None` when
    the field does not apply (tickets.md, Search): an optional
    case-insensitive `SNTL-` prefix followed by one or more ASCII
    digits."""
    head = term[: len(_SNTL_PREFIX)]
    remainder = (
        term[len(_SNTL_PREFIX) :]
        if head.isascii() and head.lower() == _SNTL_PREFIX
        else term
    )
    return remainder if _DIGITS.fullmatch(remainder) else None


def _cve_prefix(term: str) -> str:
    """The CVE-ID prefix searched for `term`: a year-number term (four
    ASCII digits, a hyphen, one or more ASCII digits) is searched as if
    prefixed by `CVE-`; any other term as given (tickets.md, Search)."""
    return f"{_CVE_PREFIX}{term}" if _YEAR_NUMBER.fullmatch(term) else term


def _search_condition(term: str) -> ColumnElement[bool]:
    """The multi-field OR search condition on `Ticket` for a normalized,
    non-empty term. Every one-to-many field uses existence semantics, so
    the condition never multiplies Ticket rows."""
    escaped = _escape_like(term)
    branches: list[ColumnElement[bool]] = []
    digits = _sequence_prefix(term)
    if digits is not None:
        branches.append(cast(Ticket.sequence_id, String).like(f"{digits}%"))
    branches.append(
        exists(
            select(CVE.id).where(
                CVE.id == Ticket.cve_id,
                CVE.cve_id.ilike(f"{_escape_like(_cve_prefix(term))}%", escape="\\"),
            )
        ).correlate(Ticket)
    )
    branches.append(
        exists(
            select(TicketPackage.id).where(
                TicketPackage.ticket_id == Ticket.id,
                TicketPackage.deleted_at.is_(None),
                TicketPackage.package_name.ilike(f"%{escaped}%", escape="\\"),
            )
        ).correlate(Ticket)
    )
    branches.append(
        exists(
            select(CVEExternalIdentifier.id).where(
                CVEExternalIdentifier.cve_id == Ticket.cve_id,
                CVEExternalIdentifier.identifier.ilike(f"{escaped}%", escape="\\"),
            )
        ).correlate(Ticket)
    )
    return or_(*branches)


def _nullable_member_condition(
    expression: ColumnElement[str | None], members: Collection[StrEnum | None]
) -> ColumnElement[bool]:
    """OR over enum members of a nullable expression; a `None` member
    matches SQL `NULL` (the `unresolved` filter value). A supplied but
    empty collection matches nothing."""
    values = sorted({member.value for member in members if member is not None})
    branches: list[ColumnElement[bool]] = []
    if values:
        branches.append(expression.in_(values))
    if None in members:
        branches.append(expression.is_(None))
    return or_(*branches) if branches else false()


def _overdue_condition(
    phases: Collection[MilestonePhase],
    *,
    due: TicketDueDateExpressions,
    evaluation_date: date,
    evaluation_instant: datetime,
) -> ColumnElement[bool]:
    """The Ticket-level `overdue` filter (ticket-deadlines.md,
    Ticket-Level Overdue Filter), OR over `phases`: `triage` is past due
    for a `New` or `Analysis` Ticket; a later phase matches when at least
    one track of the Ticket has that milestone `overdue` (existence
    semantics over aliased package and track)."""
    instant = literal(evaluation_instant, DateTime(timezone=True))
    branches: list[ColumnElement[bool]] = []
    for phase in MilestonePhase:
        if phase not in phases:
            continue
        if phase is MilestonePhase.TRIAGE:
            branches.append(
                and_(Ticket.status.in_(_TRIAGE_OPEN_STATUSES), due.triage < instant)
            )
            continue
        package = aliased(TicketPackage)
        track = aliased(TicketPackageTrack)
        milestone = track_milestone_status_expression(
            phase,
            evaluation_date=evaluation_date,
            evaluation_instant=evaluation_instant,
            ticket=Ticket,
            package=package,
            track=track,
            due_dates=due,
        )
        branches.append(
            exists(
                select(track.id)
                .join(package, package.id == track.ticket_package_id)
                .where(
                    package.ticket_id == Ticket.id,
                    milestone == MilestoneStatus.OVERDUE.value,
                )
            ).correlate(Ticket)
        )
    return or_(*branches) if branches else false()


def _user_filter_ids(identifier: str) -> Select[tuple[UUID]]:
    """The `User.id` matching a UUID-or-username filter value (at most
    one), resolved inside the list statement through the user-domain
    matching rules."""
    return select(User.id).where(user_identifier_condition(identifier))


def _sort_key(
    sort_by: TicketSortField,
    *,
    severity: ColumnElement[str | None],
    priority: ColumnElement[str | None],
    due: TicketDueDateExpressions,
) -> ColumnElement[Any]:
    """The primary sort expression for `sort_by` on `Ticket`."""
    match sort_by:
        case TicketSortField.CREATED_AT:
            return Ticket.created_at.expression
        case TicketSortField.UPDATED_AT:
            return Ticket.updated_at.expression
        case TicketSortField.TICKET_ID:
            return Ticket.sequence_id.expression
        case TicketSortField.SEVERITY:
            return case(_SEVERITY_RANK, value=severity)
        case TicketSortField.PRIORITY:
            return case(_PRIORITY_RANK, value=priority)
        case TicketSortField.STATUS:
            return case(_STATUS_RANK, value=Ticket.status)
        case TicketSortField.TRIAGE_DUE_AT:
            return due.triage
        case TicketSortField.SUBMISSION_DUE_AT:
            return due.submission
        case TicketSortField.UM_DUE_AT:
            return due.um
        case TicketSortField.QA_DUE_AT:
            return due.qa
        case TicketSortField.RELEASE_DUE_AT:
            return due.release


def _ordered(
    sort_key: ColumnElement[Any], ticket_id: ColumnElement[Any], sort_order: SortOrder
) -> tuple[ColumnElement[Any], ColumnElement[Any]]:
    """Primary order with `NULL` last in both directions, then the internal
    `Ticket.id` tie-breaker in the same direction."""
    if sort_order is SortOrder.ASC:
        return sort_key.asc().nulls_last(), ticket_id.asc()
    return sort_key.desc().nulls_last(), ticket_id.desc()


def _summary(row: Row[Any]) -> TicketSummaryProjection:
    """Assemble one summary from a list-statement row. Pure."""
    status = TicketStatus(row.status)
    severity = Severity(row.severity) if row.severity is not None else None
    duplicate_sequence_id: int | None = row.duplicate_sequence_id
    return TicketSummaryProjection(
        ticket_id=format_ticket_id(row.sequence_id),
        status=status,
        severity=severity,
        priority=_priority(row.priority),
        assignee=(
            TicketUserProjection(
                id=row.assignee_id,
                username=row.assignee_username,
                full_name=row.assignee_full_name,
                active=row.assignee_active,
            )
            if row.assignee_id is not None
            else None
        ),
        cve=(
            CVESummaryProjection(
                cve_id=row.cve_id,
                title=row.cve_title,
                description=row.cve_description,
            )
            if row.cve_id is not None
            else None
        ),
        duplicate_of_ticket_id=(
            format_ticket_id(duplicate_sequence_id)
            if duplicate_sequence_id is not None
            else None
        ),
        is_confidential=row.is_confidential,
        coordinated_release_at=row.coordinated_release_at,
        due_dates=_due_dates(row),
        package_names=tuple(row.package_names or ()),
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


def _due_dates(row: Row[Any]) -> DueDates | None:
    """The row's SQL-derived Ticket-level due dates; all five are `NULL`
    together exactly when no SLA applies."""
    if row.triage_due_at is None:
        return None
    return DueDates(
        triage=row.triage_due_at,
        submission=row.submission_due_at,
        um=row.um_due_at,
        qa=row.qa_due_at,
        release=row.release_due_at,
    )


async def list_tickets(
    db: AsyncSession,
    *,
    caller: TicketCaller,
    search: str | None = None,
    status: Collection[TicketStatus] | None = None,
    assignee: str | None = None,
    severity: Collection[Severity | None] | None = None,
    priority: Collection[TicketPriority | None] | None = None,
    overdue: Collection[MilestonePhase] | None = None,
    maintainer: str | None = None,
    sort_by: TicketSortField = TicketSortField.CREATED_AT,
    sort_order: SortOrder = SortOrder.DESC,
    page: int = 1,
    per_page: int = 20,
) -> TicketPage:
    """List the visible Tickets matching the filters, one page at a time.

    Category B read (ticket-service.md, Ticket Query Operations >
    `list_tickets()`; tickets.md, Search, TicketSummary, List Tickets).

    Q1: `caller` is the request-resolved caller information. `search` is
    the raw multi-field search. For each repeatable filter (`status`,
    `severity`, `priority`, `overdue`), `None` means omitted (no filter)
    and a collection holds the valid supplied members, so an empty
    collection (every supplied value was invalid) matches nothing. A
    `None` member of `severity` or `priority` is the `unresolved` value
    (SQL `NULL`). `assignee` is a User UUID, exact username, or the
    literal `none`; `maintainer` a User UUID or exact username. `page`
    is positive and `per_page` is 1-100.

    Q3: captures one UTC evaluation instant and derives the read
    `evaluation_date` from its UTC date. Then, in one SQL statement and
    therefore one PostgreSQL snapshot:
    1. selects the Tickets satisfying the canonical visibility predicate
       (anonymous callers evaluate no grant or maintainer branch);
    2. trims `search` once and, when non-empty, matches it by the
       field-specific OR rules of tickets.md (Search) with `%`, `_`, and
       backslash literal: SNTL numeric prefix, case-insensitive CVE-ID
       prefix, included package-name substring, and case-insensitive
       external-identifier prefix;
    3. applies the supplied filters with AND semantics and OR within a
       repeatable filter; `assignee=none` selects unassigned Tickets
       before any User resolution; an unknown assignee or maintainer
       matches nothing; maintainer matching uses an included package;
    4. resolves severity once per Ticket through the canonical cascade,
       the effective priority as `COALESCE(priority_override,
       priority_auto)`, and the five due dates through
       `ticket_due_date_expressions()`; filters, the sort key, and the
       projection use these same expressions; `overdue` applies the
       Ticket-level rules at the one instant with existence semantics;
    5. never multiplies a Ticket row: every one-to-many relation is an
       existence check or a correlated aggregate;
    6. projects `package_names` from directly included packages in
       ascending Unicode code-point order (unique per Ticket by
       `(ticket_id, package_name)`);
    7. orders by the requested key with `NULL` last in both directions
       (semantic ranks for status, severity, and priority; numeric
       `sequence_id` for `ticket_id`), then by `Ticket.id` in the same
       direction;
    8. counts after visibility and every filter, before page slicing.
    Creates no event, acquires no lock, and never commits or rolls back.

    Q4: returns the page items, the total, and the echoed `page` and
    `per_page`. A page beyond the last is empty with the correct total.

    Q6: raises `ValueError` before any query for `page < 1` or
    `per_page` outside 1-100. Database exceptions propagate unchanged.
    """
    if page < 1:
        raise ValueError("page must be at least 1")
    if not 1 <= per_page <= MAX_PER_PAGE:
        raise ValueError(f"per_page must be between 1 and {MAX_PER_PAGE}")
    evaluation_instant = _utc_now()
    evaluation_date = evaluation_instant.astimezone(UTC).date()

    resolved_severity = resolved_severity_expression()
    effective_priority: ColumnElement[str | None] = func.coalesce(
        Ticket.priority_override, Ticket.priority_auto
    )
    due = ticket_due_date_expressions(severity=resolved_severity)

    conditions: list[ColumnElement[bool]] = [ticket_visibility_condition(caller)]
    normalized_search = search.strip() if search is not None else ""
    if normalized_search:
        conditions.append(_search_condition(normalized_search))
    if status is not None:
        values = sorted({member.value for member in status})
        conditions.append(Ticket.status.in_(values) if values else false())
    if severity is not None:
        conditions.append(_nullable_member_condition(resolved_severity, severity))
    if priority is not None:
        conditions.append(_nullable_member_condition(effective_priority, priority))
    if overdue is not None:
        conditions.append(
            _overdue_condition(
                overdue,
                due=due,
                evaluation_date=evaluation_date,
                evaluation_instant=evaluation_instant,
            )
        )
    if assignee is not None:
        conditions.append(
            Ticket.assignee_id.is_(None)
            if assignee == ASSIGNEE_NONE
            else Ticket.assignee_id.in_(_user_filter_ids(assignee))
        )
    if maintainer is not None:
        conditions.append(
            exists(
                select(TicketPackageMaintainer.id)
                .join(
                    TicketPackage,
                    TicketPackage.id == TicketPackageMaintainer.ticket_package_id,
                )
                .where(
                    TicketPackage.ticket_id == Ticket.id,
                    TicketPackage.deleted_at.is_(None),
                    TicketPackageMaintainer.user_id.in_(_user_filter_ids(maintainer)),
                )
            ).correlate(Ticket)
        )

    # Only the identity and sort key are materialized for every candidate;
    # the display projections (resolved severity, priority, due dates) are
    # evaluated for the page rows alone, in the same statement.
    filtered = (
        select(
            Ticket.id.label("id"),
            _sort_key(
                sort_by,
                severity=resolved_severity,
                priority=effective_priority,
                due=due,
            ).label("sort_key"),
        )
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
    package_names = (
        select(
            func.array_agg(
                aggregate_order_by(
                    TicketPackage.package_name,
                    TicketPackage.package_name.collate(_CODE_POINT_COLLATION),
                )
            )
        )
        .where(
            TicketPackage.ticket_id == Ticket.id,
            TicketPackage.deleted_at.is_(None),
        )
        .scalar_subquery()
    )
    statement = (
        select(
            total.c.total,
            Ticket.id.label("ticket_pk"),
            Ticket.sequence_id,
            Ticket.status,
            resolved_severity.label("severity"),
            effective_priority.label("priority"),
            Ticket.is_confidential,
            Ticket.coordinated_release_at,
            Ticket.created_at,
            Ticket.updated_at,
            due.triage.label("triage_due_at"),
            due.submission.label("submission_due_at"),
            due.um.label("um_due_at"),
            due.qa.label("qa_due_at"),
            due.release.label("release_due_at"),
            _LIST_ASSIGNEE.id.label("assignee_id"),
            _LIST_ASSIGNEE.username.label("assignee_username"),
            _LIST_ASSIGNEE.full_name.label("assignee_full_name"),
            _LIST_ASSIGNEE.active.label("assignee_active"),
            _LIST_DUPLICATE_TARGET.sequence_id.label("duplicate_sequence_id"),
            CVE.cve_id.label("cve_id"),
            CVE.title.label("cve_title"),
            CVE.description.label("cve_description"),
            package_names.label("package_names"),
        )
        .select_from(total)
        .outerjoin(page_rows, true())
        .outerjoin(Ticket, Ticket.id == page_rows.c.id)
        .outerjoin(_LIST_ASSIGNEE, _LIST_ASSIGNEE.id == Ticket.assignee_id)
        .outerjoin(
            _LIST_DUPLICATE_TARGET,
            _LIST_DUPLICATE_TARGET.id == Ticket.duplicate_of_id,
        )
        .outerjoin(CVE, CVE.id == Ticket.cve_id)
        .order_by(*_ordered(page_rows.c.sort_key, page_rows.c.id, sort_order))
    )
    rows = (await db.execute(statement)).all()
    return TicketPage(
        items=tuple(_summary(row) for row in rows if row.ticket_pk is not None),
        total=rows[0].total,
        page=page,
        per_page=per_page,
    )
