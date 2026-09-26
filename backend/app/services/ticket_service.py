"""Ticket reads, lifecycle operations, and cross-domain Ticket compositions.

See `docs/features/tickets/ticket-service.md` for the full
specification. This module currently implements the consumer-facing
Ticket locator resolution (Ticket Query Operations > Ticket locator
resolution) and the Ticket detail read in its consumer and
mutation-assembly modes (Ticket Query Operations > `get_ticket_detail()`);
the remaining query and lifecycle operations are added by their owning
work items.

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
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, date, datetime
from typing import Any, Final
from uuid import UUID

from sqlalchemy import (
    ColumnElement,
    Select,
    SQLColumnExpression,
    func,
    literal_column,
    select,
    type_coerce,
)
from sqlalchemy.dialects.postgresql import JSON, aggregate_order_by
from sqlalchemy.engine import Row
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import aliased

from app.core.enums import CveState, Severity, TicketPriority, TicketStatus
from app.core.exceptions import TicketNotFoundError
from app.core.identifiers import format_ticket_id, parse_ticket_id
from app.models.cve import CVE
from app.models.cve_cwe import CVECWE
from app.models.cve_epss_score import CVEEPSSScore
from app.models.cve_external_identifier import CVEExternalIdentifier
from app.models.cve_kev_entry import CVEKEVEntry
from app.models.cve_ssvc_assessment import CVESSVCAssessment
from app.models.ticket import Ticket
from app.models.user import User
from app.services import package_service
from app.services.package_service import PackageProjection
from app.services.ticket_deadlines import DueDates, compute_due_dates
from app.services.ticket_visibility import TicketCaller, ticket_visibility_condition

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
