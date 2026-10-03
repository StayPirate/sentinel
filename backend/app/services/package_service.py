"""Package-centric operations: package-tree queries, eligibility, and mutations.

See `docs/features/packages/package-service.md` for the full
specification. This module currently implements the package-tree query
(Query Operations > `get_ticket_packages()`) in its standalone consumer
mode and its composed mode, the synchronous manual-zone-exit
eligibility convergence (`converge_manual_zone_exit_eligibility()`),
which `ticket_service` composes with an already locked Ticket, the
Product-originated system recalculation
(`recalculate_product_eligibility_for_ticket()`), the lifecycle
actionability reconciliation
(`reconcile_lifecycle_actionability_for_ticket()`), and the
package mutation foundation (`PackageServiceError` hierarchy, the
explicit system invocation context, the locked semantic-locator loader
at the package, track, and Product levels) with the mutations
`set_track_status()`, `set_product_eligibility()`, and the six direct
exclusion and restoration operations (`soft_delete_ticket_package[_track|
_product]()`, `restore_ticket_package[_track|_product]()`), the
cross-Ticket package search (`search_packages()`), and the four
maintainer workbench queries (`list_maintainer_pending_work()`,
`list_maintainer_in_progress_work()`, `list_maintainer_completed_work()`,
`get_maintainer_ticket_work()`, built by the leaf module
`app.services.packages.maintainer_workbench`), and the package-record
creation boundary `add_package_records()` with its additive maintainer
association; the remaining mutation and
orchestration operations are added by their owning work items. This module
never imports `ticket_service`; it consumes the `ticket_mutations`
primitives, which never import it back.

Every operation accepts the caller's `AsyncSession` and never commits or
rolls back; database exceptions propagate unchanged (Transaction
ownership).

Composed mode. The complete tree is exposed as one correlated scalar
column (`ticket_package_tree_column()`) that aggregates packages, tracks,
and Products as nested JSON for a Ticket id column of the enclosing
statement, plus `assemble_ticket_packages()`, which turns that value into
the typed projection. A composing read (`ticket_service.get_ticket_detail()`)
adds the column to its own single, already visibility-constrained or
mutation-owned statement, so the tree is observed in the same database
snapshot as the rest of its response. The internal Ticket UUID is only an
internal correlation key and never an API locator.

Search. `search_packages()` runs one SQL statement (a CTE chain: the
visible, actionable, filtered package occurrences, their total, the
requested page, then the page's actionable-track aggregate), so items,
total, and `track_summary` derive from one PostgreSQL observation and one
`evaluation_date`. Each maintainer workbench query likewise runs one
statement, so its rows and total, or its Ticket selection and three
collections, come from one observation.
"""

from __future__ import annotations

import uuid
from collections.abc import Collection, Mapping, Sequence
from collections.abc import Set as AbstractSet
from dataclasses import dataclass
from datetime import UTC, date, datetime
from enum import Enum, StrEnum
from typing import Any, Final, Literal, get_args

import structlog
from sqlalchemy import (
    ColumnElement,
    SQLColumnExpression,
    and_,
    false,
    func,
    literal_column,
    select,
    true,
    type_coerce,
)
from sqlalchemy.dialects.postgresql import JSON, aggregate_order_by
from sqlalchemy.engine import Row
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import aliased
from sqlalchemy.orm.util import AliasedClass

from app.core.enums import (
    DeliveryStatus,
    LifecyclePhase,
    MaintainerWorkSortField,
    NonActionableReason,
    PackageSortField,
    PackageStatus,
    Severity,
    SortOrder,
    TicketAuditEventType,
    TicketStatus,
    WorkflowType,
)
from app.core.exceptions import ServiceError, TicketNotFoundError
from app.core.identifiers import format_ticket_id, parse_ticket_id
from app.models.cve_cvss_assessment import CVECVSSAssessment
from app.models.product import Product
from app.models.ticket import Ticket
from app.models.ticket_package import TicketPackage
from app.models.ticket_package_maintainer import TicketPackageMaintainer
from app.models.ticket_package_product import TicketPackageProduct
from app.models.ticket_package_track import TicketPackageTrack
from app.models.user import User
from app.services import settings as settings_service
from app.services.cvss import EligibilityResolution, resolve_eligibility_score
from app.services.package_actionability import (
    is_delivery_relevant,
    package_actionable_expression,
    package_non_actionable_reason,
    product_actionable_expression,
    product_non_actionable_reason,
    track_actionable_expression,
    track_non_actionable_reason,
)
from app.services.packages.maintainer_workbench import (
    MaintainerTicketWork,
    MaintainerWorkItem,
    MaintainerWorkPage,
    WorkbenchClassification,
    global_list_statement,
    item_from_row,
    ticket_work_statement,
)
from app.services.product_eligibility import evaluate_product_eligibility
from app.services.product_service import lifecycle_phase_expression
from app.services.sql_patterns import LIKE_ESCAPE, escape_like
from app.services.ticket_audit_log import (
    PACKAGE_ADDED_AUTOMATIC_COMMENTS,
    TicketAuditLog,
)
from app.services.ticket_deadline_expressions import active_release_request_exists
from app.services.ticket_deadlines import (
    DueDates,
    TrackMilestones,
    compute_due_dates,
    resolve_track_milestones,
)
from app.services.ticket_mutations import (
    auto_assign_actor,
    ensure_ticket_operable,
    lock_accessible_ticket,
    reconcile_ticket_status,
    stabilize_acting_user,
)
from app.services.ticket_severity import resolved_severity_expression
from app.services.ticket_visibility import TicketCaller, ticket_visibility_condition

logger = structlog.get_logger(__name__)

_EMPTY_JSON_ARRAY: Final[ColumnElement[Any]] = literal_column("'[]'::json")
_CODE_POINT_COLLATION: Final = "C"


# ---------------------------------------------------------------------------
# Semantic projection
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ProductProjection:
    """One `TicketPackageProduct` occurrence of the tree (`ProductDetail`).

    `id` is the occurrence UUID; `product_cpe` and `product_name` come
    from the related catalog Product (`Product.cpe`, `Product.display_name`).
    `lifecycle_phase` is evaluated for the response's `evaluation_date`.
    """

    id: uuid.UUID
    product_cpe: str
    product_name: str
    eligible: bool
    is_eligible_override: bool
    released_at: datetime | None
    lifecycle_phase: LifecyclePhase | None
    deleted_at: datetime | None
    actionable: bool
    non_actionable_reason: NonActionableReason | None


@dataclass(frozen=True, slots=True)
class TrackProjection:
    """One `TicketPackageTrack` of the tree (`TrackDetail`).

    `due_dates` is `None` when no SLA applies (every due-date field is
    then `null`); with one SLA for every Product the dates equal the
    Ticket's. `milestones` carries the four member statuses and
    `current_phase`.
    """

    id: uuid.UUID
    workflow_type: WorkflowType
    reference: str
    status: PackageStatus
    delivery_status: DeliveryStatus
    delivery_relevant: bool
    deleted_at: datetime | None
    actionable: bool
    non_actionable_reason: NonActionableReason | None
    due_dates: DueDates | None
    milestones: TrackMilestones
    products: tuple[ProductProjection, ...]


@dataclass(frozen=True, slots=True)
class PackageProjection:
    """One `TicketPackage` of the tree (`PackageDetail`)."""

    id: uuid.UUID
    package_name: str
    deleted_at: datetime | None
    actionable: bool
    non_actionable_reason: NonActionableReason | None
    tracks: tuple[TrackProjection, ...]


@dataclass(frozen=True, slots=True)
class TicketTreeContext:
    """The Ticket inputs of the per-track deadline projection.

    `severity` is the resolved severity (`None` is SQL `NULL`,
    unresolved; `Severity.NONE` is the resolved `None` label).
    """

    created_at: datetime
    status: TicketStatus
    has_cve: bool
    severity: Severity | None


# ---------------------------------------------------------------------------
# Composable SQL
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


def _products_json(evaluation_date: date) -> ColumnElement[Any]:
    """Products of the enclosing track, ordered by CPE code point then id."""
    product = func.json_build_object(
        _key("id"),
        TicketPackageProduct.id,
        _key("product_cpe"),
        Product.cpe,
        _key("product_name"),
        Product.display_name,
        _key("eligible"),
        TicketPackageProduct.eligible,
        _key("is_eligible_override"),
        TicketPackageProduct.is_eligible_override,
        _key("released_at"),
        TicketPackageProduct.released_at,
        _key("lifecycle_phase"),
        lifecycle_phase_expression(evaluation_date, Product),
        _key("deleted_at"),
        TicketPackageProduct.deleted_at,
        _key("actionable"),
        product_actionable_expression(evaluation_date),
    )
    return (
        select(
            _json_array(
                product,
                Product.cpe.collate(_CODE_POINT_COLLATION),
                TicketPackageProduct.id,
            )
        )
        .select_from(TicketPackageProduct)
        .join(Product, Product.id == TicketPackageProduct.product_id)
        .where(TicketPackageProduct.ticket_package_track_id == TicketPackageTrack.id)
        .correlate_except(TicketPackageProduct, Product)
        .scalar_subquery()
    )


def _tracks_json(evaluation_date: date) -> ColumnElement[Any]:
    """Tracks of the enclosing package, ordered by reference code point then id."""
    track = func.json_build_object(
        _key("id"),
        TicketPackageTrack.id,
        _key("workflow_type"),
        TicketPackageTrack.workflow_type,
        _key("reference"),
        TicketPackageTrack.reference,
        _key("status"),
        TicketPackageTrack.status,
        _key("delivery_status"),
        TicketPackageTrack.delivery_status,
        _key("deleted_at"),
        TicketPackageTrack.deleted_at,
        _key("actionable"),
        track_actionable_expression(evaluation_date),
        _key("has_active_release_request"),
        active_release_request_exists(),
        _key("products"),
        _products_json(evaluation_date),
    )
    return (
        select(
            _json_array(
                track,
                TicketPackageTrack.reference.collate(_CODE_POINT_COLLATION),
                TicketPackageTrack.id,
            )
        )
        .where(TicketPackageTrack.ticket_package_id == TicketPackage.id)
        .correlate_except(TicketPackageTrack)
        .scalar_subquery()
    )


def ticket_package_tree_column(
    ticket_id: SQLColumnExpression[uuid.UUID], evaluation_date: date
) -> ColumnElement[Any]:
    """Build the complete package tree of one Ticket as a JSON column.

    `ticket_id` is the internal Ticket UUID column of the enclosing
    statement (for example `Ticket.id`); the column is a correlated
    scalar subquery on it, so it is evaluated in the enclosing
    statement's snapshot and adds exactly one value per enclosing row.
    It never applies Ticket visibility: the enclosing statement owns the
    protected (or mutation-owned) selection of the Ticket row.

    The value is a JSON array of every `TicketPackage` of the Ticket,
    including directly or effectively excluded and lifecycle-non-actionable
    records, each with its tracks and Product occurrences, ordered by
    `package_name`, `reference`, and `Product.cpe` in ascending Unicode
    code-point order (`COLLATE "C"`) with the occurrence UUID as the final
    tie-breaker. Every level carries its direct `deleted_at` and the SQL
    `actionable` value for `evaluation_date`; Products carry their
    lifecycle phase on that date; tracks carry the correlated `um`
    release-request evidence. Maintainer identities are never selected.

    Pass the result to `assemble_ticket_packages()`. Building the column
    performs no I/O and raises no exception.
    """
    package = func.json_build_object(
        _key("id"),
        TicketPackage.id,
        _key("package_name"),
        TicketPackage.package_name,
        _key("deleted_at"),
        TicketPackage.deleted_at,
        _key("actionable"),
        package_actionable_expression(evaluation_date),
        _key("tracks"),
        _tracks_json(evaluation_date),
    )
    tree = (
        select(
            _json_array(
                package,
                TicketPackage.package_name.collate(_CODE_POINT_COLLATION),
                TicketPackage.id,
            )
        )
        .where(TicketPackage.ticket_id == ticket_id)
        .correlate_except(TicketPackage)
        .scalar_subquery()
    )
    return type_coerce(tree, JSON)


def ticket_tree_context_columns(
    ticket: type[Ticket] | AliasedClass[Ticket] = Ticket,
) -> tuple[ColumnElement[Any], ...]:
    """The labeled Ticket columns read by `ticket_tree_context_from_row()`.

    Selects `created_at`, `status`, CVE presence, and the resolved
    severity (`resolved_severity_expression()`) of `ticket`.
    """
    return (
        ticket.created_at.label("tree_ticket_created_at"),
        ticket.status.label("tree_ticket_status"),
        ticket.cve_id.is_not(None).label("tree_ticket_has_cve"),
        resolved_severity_expression(ticket).label("tree_ticket_severity"),
    )


def ticket_tree_context_from_row(row: Row[Any]) -> TicketTreeContext:
    """Build the Ticket context from a row selecting `ticket_tree_context_columns()`."""
    severity = row.tree_ticket_severity
    return TicketTreeContext(
        created_at=row.tree_ticket_created_at,
        status=TicketStatus(row.tree_ticket_status),
        has_cve=row.tree_ticket_has_cve,
        severity=Severity(severity) if severity is not None else None,
    )


# ---------------------------------------------------------------------------
# Assembly
# ---------------------------------------------------------------------------


def _timestamp(value: str | None) -> datetime | None:
    """Parse a PostgreSQL JSON `timestamptz` value as an aware UTC datetime."""
    return None if value is None else datetime.fromisoformat(value).astimezone(UTC)


def _assemble_product(
    raw: Mapping[str, Any], *, package_excluded: bool, track_excluded: bool
) -> ProductProjection:
    deleted_at = _timestamp(raw["deleted_at"])
    phase = raw["lifecycle_phase"]
    lifecycle_phase = LifecyclePhase(phase) if phase is not None else None
    return ProductProjection(
        id=uuid.UUID(raw["id"]),
        product_cpe=raw["product_cpe"],
        product_name=raw["product_name"],
        eligible=raw["eligible"],
        is_eligible_override=raw["is_eligible_override"],
        released_at=_timestamp(raw["released_at"]),
        lifecycle_phase=lifecycle_phase,
        deleted_at=deleted_at,
        actionable=raw["actionable"],
        non_actionable_reason=product_non_actionable_reason(
            package_excluded=package_excluded,
            track_excluded=track_excluded,
            product_excluded=deleted_at is not None,
            lifecycle_phase=lifecycle_phase,
        ),
    )


def _assemble_track(
    raw: Mapping[str, Any],
    *,
    package_excluded: bool,
    ticket: TicketTreeContext,
    due_dates: DueDates | None,
    evaluation_instant: datetime,
) -> TrackProjection:
    deleted_at = _timestamp(raw["deleted_at"])
    track_excluded = deleted_at is not None
    products = tuple(
        _assemble_product(
            product, package_excluded=package_excluded, track_excluded=track_excluded
        )
        for product in raw["products"]
    )
    workflow_type = WorkflowType(raw["workflow_type"])
    status = PackageStatus(raw["status"])
    delivery_status = DeliveryStatus(raw["delivery_status"])
    actionable: bool = raw["actionable"]
    actionable_eligible = [p for p in products if p.actionable and p.eligible]
    milestones = resolve_track_milestones(
        due_dates=due_dates,
        ticket_has_cve=ticket.has_cve,
        workflow_type=workflow_type,
        track_status=status,
        track_actionable=actionable,
        has_actionable_eligible_product=bool(actionable_eligible),
        all_actionable_eligible_released=all(
            p.released_at is not None for p in actionable_eligible
        ),
        delivery_status=delivery_status,
        has_active_release_request=raw["has_active_release_request"],
        evaluation_instant=evaluation_instant,
    )
    return TrackProjection(
        id=uuid.UUID(raw["id"]),
        workflow_type=workflow_type,
        reference=raw["reference"],
        status=status,
        delivery_status=delivery_status,
        delivery_relevant=is_delivery_relevant(status, delivery_status),
        deleted_at=deleted_at,
        actionable=actionable,
        non_actionable_reason=track_non_actionable_reason(
            package_excluded=package_excluded,
            track_excluded=track_excluded,
            has_actionable_product=any(p.actionable for p in products),
        ),
        due_dates=due_dates,
        milestones=milestones,
        products=products,
    )


def assemble_ticket_packages(
    raw_tree: Sequence[Mapping[str, Any]],
    *,
    ticket: TicketTreeContext,
    evaluation_instant: datetime,
) -> tuple[PackageProjection, ...]:
    """Turn a `ticket_package_tree_column()` value into the typed projection.

    `raw_tree` is the decoded JSON value, already in canonical order;
    `ticket` the Ticket inputs selected in the same statement;
    `evaluation_instant` the one timezone-aware instant of the response
    (package-service.md, `get_ticket_packages()` step 4).

    Keeps the SQL `actionable` value of every level and derives:
    `non_actionable_reason` by the canonical first-applicable precedence;
    `delivery_relevant`; the Ticket's five due dates through
    `compute_due_dates()` (identical for every track); and each track's
    `milestones` and `current_phase` through `resolve_track_milestones()`
    from its affectedness, delivery, actionability, actionable eligible
    Products and their `released_at`, and the correlated `um` RR evidence.
    Pure: performs no I/O and persists nothing.

    Raises:
        ValueError: `evaluation_instant` or `ticket.created_at` is naive.
    """
    if evaluation_instant.utcoffset() is None:
        raise ValueError("evaluation_instant must be a timezone-aware datetime.")
    due_dates = compute_due_dates(
        created_at=ticket.created_at,
        severity=ticket.severity,
        ticket_status=ticket.status,
    )
    packages: list[PackageProjection] = []
    for raw in raw_tree:
        deleted_at = _timestamp(raw["deleted_at"])
        package_excluded = deleted_at is not None
        tracks = tuple(
            _assemble_track(
                track,
                package_excluded=package_excluded,
                ticket=ticket,
                due_dates=due_dates,
                evaluation_instant=evaluation_instant,
            )
            for track in raw["tracks"]
        )
        packages.append(
            PackageProjection(
                id=uuid.UUID(raw["id"]),
                package_name=raw["package_name"],
                deleted_at=deleted_at,
                actionable=raw["actionable"],
                non_actionable_reason=package_non_actionable_reason(
                    package_excluded=package_excluded,
                    has_actionable_track=any(t.actionable for t in tracks),
                ),
                tracks=tracks,
            )
        )
    return tuple(packages)


# ---------------------------------------------------------------------------
# Query operations
# ---------------------------------------------------------------------------


async def get_ticket_packages(
    db: AsyncSession,
    *,
    ticket_id: str,
    caller: TicketCaller,
    evaluation_date: date,
    evaluation_instant: datetime,
) -> tuple[PackageProjection, ...]:
    """Return the complete package tree of one accessible Ticket.

    Category B read (package-service.md, Query Operations >
    `get_ticket_packages()`, standalone consumer mode).

    Q1: `ticket_id` is the public `SNTL-{n}` locator and `caller` the
    request-resolved caller information. `evaluation_date` is the one UTC
    date used for lifecycle and actionability; `evaluation_instant` the
    one timezone-aware instant used for milestone comparisons, from which
    the read request derived that date.

    Q3: in one SQL statement, and therefore one PostgreSQL snapshot,
    selects the Ticket by `sequence_id` under the canonical visibility
    predicate together with its resolved severity, status, `created_at`,
    CVE presence, and complete tree (`ticket_package_tree_column()`),
    then assembles the projection (`assemble_ticket_packages()`). All
    packages, tracks, and Products are included, including excluded and
    non-actionable ones. Maintainer identities are neither loaded nor
    projected. Creates no event, acquires no lock, and never commits or
    rolls back.

    Q4: returns the packages in ascending code-point order of
    `package_name` (then UUID), each with its tracks and Products in the
    same canonical order. A Ticket without packages returns an empty
    tuple.

    Q6: raises `TicketNotFoundError` for a malformed locator (including a
    Ticket UUID; no query is run), a missing Ticket, or an inaccessible
    Ticket, without distinguishing the causes. Raises `ValueError` before
    any query when `evaluation_instant` is naive. Database exceptions
    propagate unchanged.
    """
    if evaluation_instant.utcoffset() is None:
        raise ValueError("evaluation_instant must be a timezone-aware datetime.")
    sequence_id = parse_ticket_id(ticket_id)
    if sequence_id is None:
        raise TicketNotFoundError()
    statement = select(
        *ticket_tree_context_columns(),
        ticket_package_tree_column(Ticket.id, evaluation_date).label("packages"),
    ).where(Ticket.sequence_id == sequence_id, ticket_visibility_condition(caller))
    row = (await db.execute(statement)).one_or_none()
    if row is None:
        raise TicketNotFoundError()
    return assemble_ticket_packages(
        row.packages,
        ticket=ticket_tree_context_from_row(row),
        evaluation_instant=evaluation_instant,
    )


# ---------------------------------------------------------------------------
# Cross-Ticket package search (package-service.md, Query Operations >
# `search_packages()`; package-model.md, Search Packages Across Tickets)
# ---------------------------------------------------------------------------

MAX_PER_PAGE: Final = 100
"""Largest accepted `per_page` (docs/api-spec.md, Pagination)."""


@dataclass(frozen=True, slots=True)
class TicketPackageRefProjection:
    """The lightweight parent-Ticket reference of a search item
    (`TicketPackageRef`).

    `ticket_id` is the canonical `SNTL-{n}` identity; the internal Ticket
    UUID is never part of the projection. `severity` is the resolved
    severity (tickets.md, Severity Resolution): `None` is SQL `NULL`
    (unresolved), while `Severity.NONE` is the resolved `None` label.
    """

    ticket_id: str
    status: TicketStatus
    severity: Severity | None


@dataclass(frozen=True, slots=True)
class TrackSummaryProjection:
    """Counts of the actionable tracks of one package occurrence by
    affectedness status (`TrackSummary`); `total` is their sum."""

    total: int
    affected: int
    fixed: int
    not_affected: int
    wont_fix: int
    analysis: int


@dataclass(frozen=True, slots=True)
class PackageSearchItem:
    """One actionable, caller-visible `TicketPackage` occurrence
    (`PackageListItem`).

    `id` is the `TicketPackage` UUID (a public nested-resource locator);
    `created_at` and `updated_at` are the `TicketPackage` timestamps.
    """

    id: uuid.UUID
    package_name: str
    ticket: TicketPackageRefProjection
    track_summary: TrackSummaryProjection
    created_at: datetime
    updated_at: datetime


@dataclass(frozen=True, slots=True)
class PackageSearchPage:
    """One page of search items and the total of the visible candidates."""

    items: tuple[PackageSearchItem, ...]
    total: int
    page: int
    per_page: int


# Ordered (field, status) pairs of the `TrackSummary` aggregate.
_TRACK_SUMMARY_STATUSES: Final = (
    ("affected", PackageStatus.AFFECTED),
    ("fixed", PackageStatus.FIXED),
    ("not_affected", PackageStatus.NOT_AFFECTED),
    ("wont_fix", PackageStatus.WONT_FIX),
    ("analysis", PackageStatus.ANALYSIS),
)


def _search_order(
    sort_key: ColumnElement[Any],
    package_id: ColumnElement[Any],
    *,
    sort_by: PackageSortField,
    sort_order: SortOrder,
) -> tuple[ColumnElement[Any], ColumnElement[Any]]:
    """Primary order on `sort_key`, then the internal `TicketPackage.id`
    tie-breaker in the same direction. `package_name` compares by Unicode
    code point (`COLLATE "C"`) regardless of the database collation."""
    key = (
        sort_key.collate(_CODE_POINT_COLLATION)
        if sort_by is PackageSortField.PACKAGE_NAME
        else sort_key
    )
    if sort_order is SortOrder.ASC:
        return key.asc(), package_id.asc()
    return key.desc(), package_id.desc()


def _search_item(row: Row[Any]) -> PackageSearchItem:
    """Assemble one search item from a search-statement row. Pure."""
    return PackageSearchItem(
        id=row.package_pk,
        package_name=row.package_name,
        ticket=TicketPackageRefProjection(
            ticket_id=format_ticket_id(row.sequence_id),
            status=TicketStatus(row.ticket_status),
            severity=Severity(row.severity) if row.severity is not None else None,
        ),
        track_summary=TrackSummaryProjection(
            total=row.summary_total,
            affected=row.summary_affected,
            fixed=row.summary_fixed,
            not_affected=row.summary_not_affected,
            wont_fix=row.summary_wont_fix,
            analysis=row.summary_analysis,
        ),
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


async def search_packages(
    db: AsyncSession,
    *,
    caller: TicketCaller,
    evaluation_date: date,
    search: str | None = None,
    name: str | None = None,
    ticket_status: Collection[TicketStatus] | None = None,
    sort_by: PackageSortField = PackageSortField.CREATED_AT,
    sort_order: SortOrder = SortOrder.DESC,
    page: int = 1,
    per_page: int = 20,
) -> PackageSearchPage:
    """Search the actionable package occurrences of the visible Tickets.

    Category B read (package-service.md, Query Operations >
    `search_packages()`; package-model.md, Search Packages Across
    Tickets).

    Q1: `caller` is the request-resolved caller information and
    `evaluation_date` the one UTC date of the request. `search` is the
    raw substring term (the transport schema has already enforced its
    exclusivity with `name`); `name` the exact package name.
    `ticket_status` is `None` when omitted (no filter) or the valid
    supplied members, so an empty collection (every supplied value was
    invalid) matches nothing. `page` is positive and `per_page` is 1-100.

    Q3: in one SQL statement, and therefore one PostgreSQL snapshot:
    1. selects the `TicketPackage` occurrences joined to their Ticket
       under the canonical visibility predicate (anonymous callers
       evaluate no grant or maintainer branch);
    2. keeps only actionable packages
       (`package_actionable_expression(evaluation_date)`);
    3. applies `ticket_status` (OR within the filter); trims `search`
       once and, when non-empty, matches it as a case-insensitive
       substring with `%`, `_`, and backslash literal; applies `name` as
       a case-sensitive exact match; all filters combine with AND;
    4. orders by `package_name` in Unicode code-point order or by
       `TicketPackage.created_at`, then by `TicketPackage.id` in the same
       direction;
    5. counts the candidates before page slicing;
    6. aggregates, for the page rows only and in the same statement,
       the actionable tracks on the same `evaluation_date` by status
       (`track_summary`), so database work does not grow with page size
       or result cardinality;
    7. projects the canonical Ticket identity, status, and resolved
       severity (`resolved_severity_expression()`).
    Creates no event, acquires no lock, and never commits or rolls back.

    Q4: returns the page items, the total, and the echoed `page` and
    `per_page`. An empty candidate set or a page beyond the last returns
    no items with the correct total.

    Q6: raises `ValueError` before any query for `page < 1` or
    `per_page` outside 1-100. Database exceptions propagate unchanged.
    """
    if page < 1:
        raise ValueError("page must be at least 1")
    if not 1 <= per_page <= MAX_PER_PAGE:
        raise ValueError(f"per_page must be between 1 and {MAX_PER_PAGE}")

    conditions: list[ColumnElement[bool]] = [
        ticket_visibility_condition(caller),
        package_actionable_expression(evaluation_date),
    ]
    if ticket_status is not None:
        values = sorted({member.value for member in ticket_status})
        conditions.append(Ticket.status.in_(values) if values else false())
    normalized_search = search.strip() if search is not None else ""
    if normalized_search:
        conditions.append(
            TicketPackage.package_name.ilike(
                f"%{escape_like(normalized_search)}%", escape=LIKE_ESCAPE
            )
        )
    if name is not None:
        conditions.append(TicketPackage.package_name == name)

    sort_column: ColumnElement[Any] = (
        TicketPackage.package_name.expression
        if sort_by is PackageSortField.PACKAGE_NAME
        else TicketPackage.created_at.expression
    )
    filtered = (
        select(TicketPackage.id.label("id"), sort_column.label("sort_key"))
        .join(Ticket, Ticket.id == TicketPackage.ticket_id)
        .where(*conditions)
        .cte("filtered")
    )
    total = select(func.count().label("total")).select_from(filtered).cte("total")
    page_rows = (
        select(filtered)
        .order_by(
            *_search_order(
                filtered.c.sort_key,
                filtered.c.id,
                sort_by=sort_by,
                sort_order=sort_order,
            )
        )
        .limit(per_page)
        .offset((page - 1) * per_page)
        .cte("page")
    )
    summary_package = aliased(TicketPackage)
    summary_track = aliased(TicketPackageTrack)
    summary = (
        select(
            summary_track.ticket_package_id.label("package_id"),
            func.count().label("total"),
            *(
                func.count().filter(summary_track.status == status.value).label(field)
                for field, status in _TRACK_SUMMARY_STATUSES
            ),
        )
        .join(summary_package, summary_package.id == summary_track.ticket_package_id)
        .where(
            summary_track.ticket_package_id.in_(select(page_rows.c.id)),
            track_actionable_expression(
                evaluation_date, package=summary_package, track=summary_track
            ),
        )
        .group_by(summary_track.ticket_package_id)
        .cte("summary")
    )
    statement = (
        select(
            total.c.total,
            TicketPackage.id.label("package_pk"),
            TicketPackage.package_name,
            TicketPackage.created_at,
            TicketPackage.updated_at,
            Ticket.sequence_id,
            Ticket.status.label("ticket_status"),
            resolved_severity_expression().label("severity"),
            func.coalesce(summary.c.total, 0).label("summary_total"),
            *(
                func.coalesce(summary.c[field], 0).label(f"summary_{field}")
                for field, _ in _TRACK_SUMMARY_STATUSES
            ),
        )
        .select_from(total)
        .outerjoin(page_rows, true())
        .outerjoin(TicketPackage, TicketPackage.id == page_rows.c.id)
        .outerjoin(Ticket, Ticket.id == TicketPackage.ticket_id)
        .outerjoin(summary, summary.c.package_id == page_rows.c.id)
        .order_by(
            *_search_order(
                page_rows.c.sort_key,
                page_rows.c.id,
                sort_by=sort_by,
                sort_order=sort_order,
            )
        )
    )
    rows = (await db.execute(statement)).all()
    return PackageSearchPage(
        items=tuple(_search_item(row) for row in rows if row.package_pk is not None),
        total=rows[0].total,
        page=page,
        per_page=per_page,
    )


# ---------------------------------------------------------------------------
# Maintainer workbench queries (package-service.md, Query Operations >
# Maintainer workbench queries; maintainer.md)
# ---------------------------------------------------------------------------


def _workbench_caller_user_id(
    caller: TicketCaller, evaluation_instant: datetime
) -> uuid.UUID:
    """Validate the workbench caller contract and return the owner ID.

    The workbench owner is the authenticated caller; an anonymous caller
    and a naive evaluation instant are caller-contract violations.
    """
    if caller.user_id is None:
        raise ValueError("The maintainer workbench requires an authenticated caller.")
    if evaluation_instant.utcoffset() is None:
        raise ValueError("evaluation_instant must be a timezone-aware datetime.")
    return caller.user_id


async def _list_maintainer_work(
    db: AsyncSession,
    classification: WorkbenchClassification,
    *,
    caller: TicketCaller,
    evaluation_date: date,
    evaluation_instant: datetime,
    package: str | None,
    sort_by: MaintainerWorkSortField,
    sort_order: SortOrder,
    page: int,
    per_page: int,
) -> MaintainerWorkPage:
    caller_user_id = _workbench_caller_user_id(caller, evaluation_instant)
    if page < 1:
        raise ValueError("page must be at least 1")
    if not 1 <= per_page <= MAX_PER_PAGE:
        raise ValueError(f"per_page must be between 1 and {MAX_PER_PAGE}")
    statement = global_list_statement(
        classification,
        caller=caller,
        caller_user_id=caller_user_id,
        evaluation_date=evaluation_date,
        evaluation_instant=evaluation_instant,
        package=package,
        sort_by=sort_by,
        sort_order=sort_order,
        page=page,
        per_page=per_page,
    )
    rows = (await db.execute(statement)).all()
    return MaintainerWorkPage(
        items=tuple(item_from_row(row) for row in rows if row.track_pk is not None),
        total=rows[0].total,
        page=page,
        per_page=per_page,
    )


async def list_maintainer_pending_work(
    db: AsyncSession,
    *,
    caller: TicketCaller,
    evaluation_date: date,
    evaluation_instant: datetime,
    package: str | None = None,
    sort_by: MaintainerWorkSortField = MaintainerWorkSortField.SEVERITY,
    sort_order: SortOrder = SortOrder.DESC,
    page: int = 1,
    per_page: int = 20,
) -> MaintainerWorkPage:
    """List the caller's pending workbench tracks.

    Category B read (package-service.md, Maintainer workbench queries;
    maintainer.md, Pending, Shared Global-List Query Contract).

    Q1: `caller` is the request-resolved authenticated caller: its
    `user_id` is the workbench owner and its effective scope feeds the
    canonical visibility predicate. `evaluation_date` is the one UTC date
    of the response, for classification; `evaluation_instant` the one
    timezone-aware instant from which it was derived, for the submission
    milestone. `package` is an optional case-sensitive exact package
    name; `page` is positive and `per_page` is 1-100.

    Q3: in one SQL statement, and therefore one PostgreSQL observation,
    selects one row per exact `TicketPackageTrack` whose Ticket is
    visible to the caller, whose included parent package has a
    maintainer association for the caller, and which is pending: Ticket
    `Analysis` or `Analyzed`, actionable track, affectedness `AFFECTED`,
    delivery `PENDING`, and at least one actionable Product with
    persisted `eligible = true` (existence semantics, no fan-out). Applies
    `package` with AND, orders by semantic severity, code-point package
    name, or submission due date (`NULL` last in both directions) and
    then the track UUID in the same direction, counts the candidates,
    slices the page, and projects the ten item fields. Acquires no lock,
    writes nothing, creates no event, performs no external or Redis I/O,
    enqueues no task, and never commits or rolls back.

    Q4: returns the page items, the total, and the echoed `page` and
    `per_page`; an empty candidate set or a page beyond the last returns
    no items with the correct total.

    Q6: raises `ValueError` before any query for an anonymous caller, a
    naive `evaluation_instant`, `page < 1`, or `per_page` outside 1-100.
    Database exceptions propagate unchanged.
    """
    return await _list_maintainer_work(
        db,
        WorkbenchClassification.PENDING,
        caller=caller,
        evaluation_date=evaluation_date,
        evaluation_instant=evaluation_instant,
        package=package,
        sort_by=sort_by,
        sort_order=sort_order,
        page=page,
        per_page=per_page,
    )


async def list_maintainer_in_progress_work(
    db: AsyncSession,
    *,
    caller: TicketCaller,
    evaluation_date: date,
    evaluation_instant: datetime,
    package: str | None = None,
    sort_by: MaintainerWorkSortField = MaintainerWorkSortField.SEVERITY,
    sort_order: SortOrder = SortOrder.DESC,
    page: int = 1,
    per_page: int = 20,
) -> MaintainerWorkPage:
    """List the caller's in-progress workbench tracks.

    Identical to `list_maintainer_pending_work()` except for the
    classification (maintainer.md, In Progress): Ticket `Analysis` or
    `Analyzed`, actionable track, affectedness `AFFECTED` or `FIXED`,
    delivery `IN_PROGRESS`, and at least one actionable Product with
    persisted `eligible = true`.
    """
    return await _list_maintainer_work(
        db,
        WorkbenchClassification.IN_PROGRESS,
        caller=caller,
        evaluation_date=evaluation_date,
        evaluation_instant=evaluation_instant,
        package=package,
        sort_by=sort_by,
        sort_order=sort_order,
        page=page,
        per_page=per_page,
    )


async def list_maintainer_completed_work(
    db: AsyncSession,
    *,
    caller: TicketCaller,
    evaluation_date: date,
    evaluation_instant: datetime,
    package: str | None = None,
    sort_by: MaintainerWorkSortField = MaintainerWorkSortField.SEVERITY,
    sort_order: SortOrder = SortOrder.DESC,
    page: int = 1,
    per_page: int = 20,
) -> MaintainerWorkPage:
    """List the caller's completed workbench tracks.

    Identical to `list_maintainer_pending_work()` except for the
    classification (maintainer.md, Completed): Ticket `Analysis`,
    `Analyzed`, or `Resolved`, actionable track, and delivery `RELEASED`,
    with no eligible-Product requirement.
    """
    return await _list_maintainer_work(
        db,
        WorkbenchClassification.COMPLETED,
        caller=caller,
        evaluation_date=evaluation_date,
        evaluation_instant=evaluation_instant,
        package=package,
        sort_by=sort_by,
        sort_order=sort_order,
        page=page,
        per_page=per_page,
    )


async def get_maintainer_ticket_work(
    db: AsyncSession,
    *,
    ticket_id: str,
    caller: TicketCaller,
    evaluation_date: date,
    evaluation_instant: datetime,
) -> MaintainerTicketWork:
    """Return the caller's classified work on one accessible Ticket.

    Category B read (package-service.md, Maintainer workbench queries;
    maintainer.md, Package Details for Ticket).

    Q1: `ticket_id` is the public `SNTL-{n}` locator; `caller`,
    `evaluation_date`, and `evaluation_instant` are as in
    `list_maintainer_pending_work()`.

    Q3: parses the locator with the canonical SNTL parser, then in one
    SQL statement, and therefore one PostgreSQL observation, selects the
    Ticket under the canonical visibility predicate together with its
    caller-owned tracks that satisfy one of the three classifications on
    `evaluation_date`, each projected once. Ownership and classification
    are evaluated only for the selected accessible Ticket. Partitions the
    items by classification, each collection in ascending code-point
    order of `package_name`, then `reference`, then the internal track
    UUID. Acquires no lock, writes nothing, creates no event, performs no
    external or Redis I/O, enqueues no task, and never commits or rolls
    back.

    Q4: returns the three collections; all three are empty when the
    accessible Ticket has no qualifying caller work, whatever the cause.

    Q6: raises `TicketNotFoundError` for a malformed locator (including a
    lowercase, padded, or UUID value; no query is run), a missing Ticket,
    or an inaccessible Ticket, without distinguishing the causes. Raises
    `ValueError` before any query for an anonymous caller or a naive
    `evaluation_instant`. Database exceptions propagate unchanged.
    """
    caller_user_id = _workbench_caller_user_id(caller, evaluation_instant)
    sequence_id = parse_ticket_id(ticket_id)
    if sequence_id is None:
        raise TicketNotFoundError()
    statement = ticket_work_statement(
        sequence_id=sequence_id,
        caller=caller,
        caller_user_id=caller_user_id,
        evaluation_date=evaluation_date,
        evaluation_instant=evaluation_instant,
    )
    rows = (await db.execute(statement)).all()
    if not rows:
        raise TicketNotFoundError()
    collections: dict[WorkbenchClassification, list[MaintainerWorkItem]] = {
        classification: [] for classification in WorkbenchClassification
    }
    for row in rows:
        if row.track_pk is not None:
            classification = WorkbenchClassification(row.classification)
            collections[classification].append(item_from_row(row))
    return MaintainerTicketWork(
        pending=tuple(collections[WorkbenchClassification.PENDING]),
        in_progress=tuple(collections[WorkbenchClassification.IN_PROGRESS]),
        completed=tuple(collections[WorkbenchClassification.COMPLETED]),
    )


# ---------------------------------------------------------------------------
# Synchronous manual-zone-exit eligibility convergence
# ---------------------------------------------------------------------------

_REACTIVATION_REASON: Final = "reactivation"


@dataclass(frozen=True, slots=True)
class ManualZoneExitEligibilityResult:
    """Occurrence counts of one manual-zone-exit eligibility convergence."""

    examined: int
    override_skipped: int
    changed: int


@dataclass(frozen=True, slots=True)
class _RecalculationCounts:
    """Occurrence counts of one automatic eligibility recalculation loop."""

    examined: int
    override_skipped: int
    changed: int


def _eligibility_value(eligible: bool) -> str:
    """The `product_eligibility_changed` old/new value (`true`/`false`)."""
    return "true" if eligible else "false"


async def _current_eligibility_score(
    db: AsyncSession, ticket: Ticket
) -> EligibilityResolution:
    """Resolve the Ticket's current Eligibility Score Resolution.

    Reads the current persisted `default_cvss_version` and, for a
    CVE-associated Ticket, the complete assessment set of its CVE
    (current committed state, refreshing identity-map copies, without a
    CVE lock), then applies `resolve_eligibility_score()`: the canonical
    SUSE score at the default version, otherwise the `10.0` fallback,
    including for a CVE-less Ticket.

    Raises `RequiredSystemSettingMissingError` when the setting is absent
    and `ValueError` for an invalid default version or assessment set.
    """
    default_cvss_version = await settings_service.get_default_cvss_version(db)
    assessments: Sequence[CVECVSSAssessment] = ()
    if ticket.cve_id is not None:
        assessments = (
            (
                await db.execute(
                    select(CVECVSSAssessment)
                    .where(CVECVSSAssessment.cve_id == ticket.cve_id)
                    .execution_options(populate_existing=True)
                )
            )
            .scalars()
            .all()
        )
    return resolve_eligibility_score(assessments, default_cvss_version)


async def converge_manual_zone_exit_eligibility(
    db: AsyncSession,
    *,
    ticket: Ticket,
    evaluation_date: date,
) -> ManualZoneExitEligibilityResult:
    """Converge every automatic Product occurrence of an exiting Ticket.

    Category A composable boundary (package-service.md, Synchronous
    manual-zone-exit eligibility convergence; package-model.md, Ticket
    Convergence phase 1). Invoked only by
    `ticket_service._complete_manual_zone_exit()`.

    Q1: `ticket` is the Ticket the `ticket_service` exit workflow already
    locked `FOR UPDATE`, validated in its exact `Ignored` or `Duplicated`
    source state, and set to the intermediate `Analysis` floor.
    `evaluation_date` is the workflow's one UTC date.

    Q2: the caller owns the transaction and holds the Ticket lock (plus,
    for a consumer exit, the acting User `FOR SHARE`). Acquires no lock:
    it never reacquires the Ticket lock and never locks the CVE; the CVE
    assessments are current committed state read without a lock.

    Q3: (1) reads the current persisted `default_cvss_version` and, for a
    CVE-associated Ticket, the complete assessment set, and resolves the
    Eligibility Score Resolution (the `10.0` fallback without a SUSE
    default-version assessment, including a CVE-less Ticket). (2) Reloads,
    in one statement ordered by `TicketPackageProduct.id`, every Product
    occurrence of the Ticket, including directly or effectively excluded
    and EOL occurrences, with its override marker, `eligible`, Product
    threshold, lifecycle phase on `evaluation_date`, and the event-time
    subject (track reference, package name, Product display name and
    CPE). (3) Applies the shared pure evaluator, skips every override
    without change or event, and updates only booleans that differ, each
    with one system `product_eligibility_changed` (`reason =
    reactivation`, `comment NULL`, no `override_action`). (4) Flushes.
    Never assigns, reconciles, writes `CVE.severity`, restores exclusion,
    creates package descendants, reads audit history, commits, rolls
    back, or performs network, Redis, or Celery I/O. Re-invocation with
    the same date and inputs is a no-op.

    Q4: returns the examined, override-skipped, and changed counts.

    Q6: raises `ValueError` before any database operation when the Ticket
    is not at the `Analysis` floor (a manual-zone Ticket is never passed
    directly). `RequiredSystemSettingMissingError`, `ValueError` from an
    invalid default version or assessment set, and audit, database, and
    flush exceptions propagate and roll back the caller's complete
    manual-zone-exit transaction.
    """
    if ticket.status != TicketStatus.ANALYSIS:
        raise ValueError(
            "the manual-zone exit must set the Analysis floor before converging."
        )

    counts = await _recalculate_automatic_eligibility(
        db,
        ticket=ticket,
        evaluation_date=evaluation_date,
        reason=_REACTIVATION_REASON,
    )
    await db.flush()
    return ManualZoneExitEligibilityResult(
        examined=counts.examined,
        override_skipped=counts.override_skipped,
        changed=counts.changed,
    )


async def _recalculate_automatic_eligibility(
    db: AsyncSession,
    *,
    ticket: Ticket,
    evaluation_date: date,
    reason: str,
    catalog_product_id: uuid.UUID | None = None,
) -> _RecalculationCounts:
    """Recalculate the automatic Product occurrences of one locked Ticket.

    The one load → evaluate → update → audit loop shared by the manual-zone
    exit convergence and `recalculate_product_eligibility_for_ticket()`.
    The caller holds the Ticket lock and owns the transaction.

    Resolves the Ticket's current Eligibility Score Resolution, then
    reloads, in one statement ordered by `TicketPackageProduct.id`, every
    Product occurrence of the Ticket (only those of `catalog_product_id`
    when supplied), including directly or effectively excluded and EOL
    occurrences under every track status, with its override marker,
    `eligible`, Product threshold, lifecycle phase on `evaluation_date`,
    and the event-time subject. Applies the shared pure evaluator, skips
    every override without change or event, and updates only booleans that
    differ, each with one system `product_eligibility_changed` (`reason`,
    `comment NULL`, no `override_action`). Does not flush, assign,
    reconcile, commit, or roll back.

    Returns the examined (including override-skipped), override-skipped,
    and changed occurrence counts.
    """
    eligibility = await _current_eligibility_score(db, ticket)

    occurrence = TicketPackageProduct
    statement = (
        select(
            occurrence,
            TicketPackageTrack.reference,
            TicketPackage.package_name,
            Product.display_name,
            Product.cpe,
            Product.cvss_threshold,
            lifecycle_phase_expression(evaluation_date).label("lifecycle"),
        )
        .join(
            TicketPackageTrack,
            TicketPackageTrack.id == occurrence.ticket_package_track_id,
        )
        .join(TicketPackage, TicketPackage.id == TicketPackageTrack.ticket_package_id)
        .join(Product, Product.id == occurrence.product_id)
        .where(TicketPackage.ticket_id == ticket.id)
        .order_by(occurrence.id)
        .execution_options(populate_existing=True)
    )
    if catalog_product_id is not None:
        statement = statement.where(occurrence.product_id == catalog_product_id)
    rows = (await db.execute(statement)).all()

    override_skipped = 0
    changed = 0
    for row in rows:
        product_occurrence: TicketPackageProduct = row[0]
        new_eligible = evaluate_product_eligibility(
            is_eligible_override=product_occurrence.is_eligible_override,
            lifecycle_phase=(
                LifecyclePhase(row.lifecycle) if row.lifecycle is not None else None
            ),
            cvss_threshold=row.cvss_threshold,
            eligibility_score=eligibility,
        ).automatic_eligible
        if new_eligible is None:
            override_skipped += 1
            continue
        old_eligible = product_occurrence.eligible
        if new_eligible == old_eligible:
            continue
        product_occurrence.eligible = new_eligible
        changed += 1
        await TicketAuditLog.log_event(
            db,
            ticket_id=ticket.id,
            event_type=TicketAuditEventType.PRODUCT_ELIGIBILITY_CHANGED,
            user_id=None,
            old_value=_eligibility_value(old_eligible),
            new_value=_eligibility_value(new_eligible),
            detail={
                "track": row.reference,
                "package": row.package_name,
                "product_name": row.display_name,
                "product_cpe": row.cpe,
                "reason": reason,
            },
        )
    return _RecalculationCounts(
        examined=len(rows), override_skipped=override_skipped, changed=changed
    )


# ---------------------------------------------------------------------------
# Service exceptions (package-service.md, Service Exceptions)
# ---------------------------------------------------------------------------


class PackageServiceError(ServiceError):
    """Base class for all exceptions owned by `package_service`.

    Shared exceptions (`TicketNotFoundError`, `TicketNotMutableError`)
    inherit from `ServiceError` directly; API handlers catch them
    explicitly (docs/conventions.md, Service Exception Conventions).
    """


class PackageNotFoundError(PackageServiceError):
    """The package ID does not exist under the declared Ticket path.

    Maps to `404 RESOURCE_NOT_FOUND`. The static message never reveals
    whether the occurrence exists under another path.
    """

    def __init__(self) -> None:
        super().__init__("Package not found.")


class TrackNotFoundError(PackageServiceError):
    """The track ID does not exist under the declared Ticket/package path.

    Maps to `404 RESOURCE_NOT_FOUND`. The static message never reveals
    whether the occurrence exists under another path.
    """

    def __init__(self) -> None:
        super().__init__("Track not found.")


class ProductNotFoundError(PackageServiceError):
    """The Product occurrence or catalog Product does not exist.

    On consumer paths the identifier is a `TicketPackageProduct.id` under
    the declared Ticket/package/track path; it maps to `404
    RESOURCE_NOT_FOUND`, and the static message never reveals whether the
    occurrence exists under another path. The system-internal
    `recalculate_product_eligibility_for_ticket()` also raises it when its
    catalog `Product.id` does not exist; that path has no HTTP mapping.
    """

    def __init__(self) -> None:
        super().__init__("Product not found.")


class PackageAlreadyExcludedError(PackageServiceError):
    """The targeted package-tree record is already directly excluded.

    Raised by `soft_delete_ticket_package[_track|_product]()` when the
    locked target's own `deleted_at` marker is already set, and by
    `add_package_records()` outside re-resolution mode when the existing
    package occurrence is directly excluded. Maps to `409
    PACKAGE_ALREADY_EXCLUDED`.
    """

    def __init__(self) -> None:
        super().__init__("Record is already excluded.")


class PackageNotExcludedError(PackageServiceError):
    """The targeted package-tree record is not directly excluded.

    Raised by `restore_ticket_package[_track|_product]()` when the locked
    target's own `deleted_at` marker is NULL, even if the record is
    effectively excluded through an ancestor. Maps to `422
    PACKAGE_NOT_EXCLUDED`.
    """

    def __init__(self) -> None:
        super().__init__("Record is not directly excluded.")


class TrackFixedStatusRestrictedError(PackageServiceError):
    """The user-attributed affectedness target violates caller authority.

    Raised when the admin force marker is used for a non-`FIXED` target,
    or `FIXED` is requested with only `manage_packages` while the
    locked-current Ticket has a CVE. Maps to the generic `403
    AUTH_INSUFFICIENT_PERMISSION`, which discloses no condition.
    """

    def __init__(self) -> None:
        super().__init__("Track status change not permitted.")


# ---------------------------------------------------------------------------
# Invocation context and semantic outcomes (package-service.md, Consumer
# caller context and Ticket accessibility; Semantic locators)
# ---------------------------------------------------------------------------


class SystemInvocation(Enum):
    """Explicit trusted internal invocation of a mutation boundary.

    Passed instead of a `TicketCaller` by system workflows (for example
    IBS track release detection). A missing consumer context is never
    interpreted as system authority: a boundary that serves both caller
    kinds requires one of the two values explicitly.
    """

    SYSTEM = "system"


SYSTEM_INVOCATION: Final = SystemInvocation.SYSTEM
"""The single system invocation context value."""


class MutationOutcome(StrEnum):
    """Semantic outcome of a direct set/update package mutation.

    `REJECTED` is reserved for a prohibited system target of
    `set_track_status()`. Never persisted or serialized.
    """

    CHANGED = "changed"
    NO_OP = "no_op"
    REJECTED = "rejected"


_FINAL_STATUSES: Final = frozenset(
    {PackageStatus.NOT_AFFECTED, PackageStatus.FIXED, PackageStatus.WONT_FIX}
)


def _resolve_actor(
    acting_user_id: uuid.UUID | None, caller: TicketCaller | SystemInvocation
) -> bool:
    """Validate the actor/context pairing; return whether the call is system.

    Raises `ValueError` when a system context carries an actor, when a
    consumer context has no actor, or when the consumer caller does not
    identify the acting user.
    """
    if isinstance(caller, SystemInvocation):
        if acting_user_id is not None:
            raise ValueError("a system invocation has no acting user.")
        return True
    if acting_user_id is None or caller.user_id != acting_user_id:
        raise ValueError("caller must identify the acting user.")
    return False


def _require_consumer_actor(
    acting_user_id: uuid.UUID | None, caller: TicketCaller
) -> uuid.UUID:
    """Validate a user-attributed-only boundary's actor before any I/O.

    Raises `ValueError` when the actor is null, `caller` is not a
    consumer `TicketCaller`, or the caller does not identify the actor.
    Returns the validated acting user UUID.
    """
    if (
        acting_user_id is None
        or not isinstance(caller, TicketCaller)
        or caller.user_id != acting_user_id
    ):
        raise ValueError("caller must identify a non-null acting user.")
    return acting_user_id


async def _lock_system_ticket(db: AsyncSession, ticket_id: uuid.UUID) -> Ticket:
    """Lock the declared Ticket `FOR UPDATE` for a system invocation.

    Applies no consumer visibility. Raises `TicketNotFoundError` when no
    Ticket has `ticket_id`.
    """
    ticket = (
        await db.execute(
            select(Ticket)
            .where(Ticket.id == ticket_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
    ).scalar_one_or_none()
    if ticket is None:
        raise TicketNotFoundError()
    return ticket


async def _load_locked_package(
    db: AsyncSession, *, ticket_id: uuid.UUID, package_id: uuid.UUID
) -> TicketPackage:
    """Reload and validate the declared Ticket/package chain.

    Called only while the caller holds the Ticket `FOR UPDATE` lock and
    after locked-current accessibility (package-service.md, Semantic
    locators and locked ownership validation). One statement selects the
    package under the declared Ticket, including a directly excluded
    one, and refreshes any identity-map copy.

    Raises `PackageNotFoundError` when the package is missing or belongs
    to another Ticket, without revealing or touching that occurrence.
    """
    package = (
        await db.execute(
            select(TicketPackage)
            .where(TicketPackage.id == package_id, TicketPackage.ticket_id == ticket_id)
            .execution_options(populate_existing=True)
        )
    ).scalar_one_or_none()
    if package is None:
        raise PackageNotFoundError()
    return package


async def _load_locked_track(
    db: AsyncSession,
    *,
    ticket_id: uuid.UUID,
    package_id: uuid.UUID,
    track_id: uuid.UUID,
) -> tuple[TicketPackage, TicketPackageTrack]:
    """Reload and validate the declared Ticket/package/track chain.

    Called only while the caller holds the Ticket `FOR UPDATE` lock and
    after locked-current accessibility (package-service.md, Semantic
    locators and locked ownership validation). One statement selects the
    package under the declared Ticket and, through an outer join, the
    track under that package; directly or effectively excluded records
    are included. Identity-map copies are refreshed so the returned rows
    are the committed-current state observed under the lock.

    Raises `PackageNotFoundError` when the package is missing or belongs
    to another Ticket, and `TrackNotFoundError` when the track is missing
    or belongs to another package. Neither reveals nor touches an
    occurrence under another path.
    """
    row = (
        await db.execute(
            select(TicketPackage, TicketPackageTrack)
            .outerjoin(
                TicketPackageTrack,
                and_(
                    TicketPackageTrack.ticket_package_id == TicketPackage.id,
                    TicketPackageTrack.id == track_id,
                ),
            )
            .where(TicketPackage.id == package_id, TicketPackage.ticket_id == ticket_id)
            .execution_options(populate_existing=True)
        )
    ).one_or_none()
    if row is None:
        raise PackageNotFoundError()
    package, track = row
    if track is None:
        raise TrackNotFoundError()
    return package, track


@dataclass(frozen=True, slots=True)
class _LockedProductPath:
    """The declared Ticket/package/track/Product path reloaded under lock.

    `product` is the related catalog Product (threshold, display name,
    CPE); `lifecycle_phase` is its phase on the operation's
    `evaluation_date` (`None` when lifecycle data is unavailable).
    """

    package: TicketPackage
    track: TicketPackageTrack
    occurrence: TicketPackageProduct
    product: Product
    lifecycle_phase: LifecyclePhase | None


async def _load_locked_product(
    db: AsyncSession,
    *,
    ticket_id: uuid.UUID,
    package_id: uuid.UUID,
    track_id: uuid.UUID,
    ticket_package_product_id: uuid.UUID,
    evaluation_date: date,
) -> _LockedProductPath:
    """Reload and validate the declared Ticket/package/track/Product chain.

    Called only while the caller holds the Ticket `FOR UPDATE` lock and
    after locked-current accessibility (package-service.md, Semantic
    locators and locked ownership validation). One statement selects the
    package under the declared Ticket and, through outer joins, the track
    under that package, the `TicketPackageProduct` occurrence under that
    track, and its catalog Product with the lifecycle phase on
    `evaluation_date`. Directly or effectively excluded and EOL records
    are included. `ticket_package_product_id` is matched only against the
    occurrence identifier, never the catalog `Product.id`. Identity-map
    copies are refreshed so the returned rows are the committed-current
    state observed under the lock.

    Raises `PackageNotFoundError`, `TrackNotFoundError`, or
    `ProductNotFoundError` for the first missing or mismatched level.
    None of them reveals or touches an occurrence under another path.
    """
    row = (
        await db.execute(
            select(
                TicketPackage,
                TicketPackageTrack,
                TicketPackageProduct,
                Product,
                lifecycle_phase_expression(evaluation_date, Product).label(
                    "lifecycle_phase"
                ),
            )
            .outerjoin(
                TicketPackageTrack,
                and_(
                    TicketPackageTrack.ticket_package_id == TicketPackage.id,
                    TicketPackageTrack.id == track_id,
                ),
            )
            .outerjoin(
                TicketPackageProduct,
                and_(
                    TicketPackageProduct.ticket_package_track_id
                    == TicketPackageTrack.id,
                    TicketPackageProduct.id == ticket_package_product_id,
                ),
            )
            .outerjoin(Product, Product.id == TicketPackageProduct.product_id)
            .where(TicketPackage.id == package_id, TicketPackage.ticket_id == ticket_id)
            .execution_options(populate_existing=True)
        )
    ).one_or_none()
    if row is None:
        raise PackageNotFoundError()
    package, track, occurrence, product, phase = row
    if track is None:
        raise TrackNotFoundError()
    if occurrence is None:
        raise ProductNotFoundError()
    return _LockedProductPath(
        package=package,
        track=track,
        occurrence=occurrence,
        product=product,
        lifecycle_phase=LifecyclePhase(phase) if phase is not None else None,
    )


# ---------------------------------------------------------------------------
# Track projection (package-model.md, Change Track Status response)
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class TrackStatusProjection:
    """The locked-current track of a track-status mutation result.

    `ticket_id` is the canonical `SNTL-{n}` identity; `products` are every
    Product occurrence of the track in canonical order (`product_cpe`
    code point, then occurrence UUID), each with its lifecycle phase,
    eligibility, override marker, and actionability on the shared
    `evaluation_date`.
    """

    ticket_id: str
    package_name: str
    reference: str
    status: PackageStatus
    delivery_status: DeliveryStatus
    delivery_relevant: bool
    actionable: bool
    non_actionable_reason: NonActionableReason | None
    products: tuple[ProductProjection, ...]


@dataclass(frozen=True, slots=True)
class TrackStatusResult:
    """Result of `set_track_status()`.

    `outcome` is `changed`, `no_op`, or `rejected`; `track` is projected
    from state observed under the Ticket lock with `evaluation_date`, the
    one UTC date also used by reconciliation.
    """

    outcome: MutationOutcome
    track: TrackStatusProjection
    evaluation_date: date


async def _project_track(
    db: AsyncSession,
    *,
    ticket: Ticket,
    track_id: uuid.UUID,
    evaluation_date: date,
) -> TrackStatusProjection:
    """Project one track and its Products under the held Ticket lock.

    One statement reads the track, its package name and markers, the SQL
    track actionability, and the canonical Product JSON of the package
    tree read, all for `evaluation_date`; reasons are derived by the
    canonical precedence. Performs no write.
    """
    row = (
        await db.execute(
            select(
                TicketPackage.package_name,
                TicketPackage.deleted_at.label("package_deleted_at"),
                TicketPackageTrack.reference,
                TicketPackageTrack.status,
                TicketPackageTrack.delivery_status,
                TicketPackageTrack.deleted_at.label("track_deleted_at"),
                track_actionable_expression(evaluation_date).label("actionable"),
                type_coerce(_products_json(evaluation_date), JSON).label("products"),
            )
            .select_from(TicketPackageTrack)
            .join(
                TicketPackage, TicketPackage.id == TicketPackageTrack.ticket_package_id
            )
            .where(TicketPackageTrack.id == track_id)
        )
    ).one()
    package_excluded = row.package_deleted_at is not None
    track_excluded = row.track_deleted_at is not None
    products = tuple(
        _assemble_product(
            product, package_excluded=package_excluded, track_excluded=track_excluded
        )
        for product in row.products
    )
    status = PackageStatus(row.status)
    delivery_status = DeliveryStatus(row.delivery_status)
    return TrackStatusProjection(
        ticket_id=format_ticket_id(ticket.sequence_id),
        package_name=row.package_name,
        reference=row.reference,
        status=status,
        delivery_status=delivery_status,
        delivery_relevant=is_delivery_relevant(status, delivery_status),
        actionable=row.actionable,
        non_actionable_reason=track_non_actionable_reason(
            package_excluded=package_excluded,
            track_excluded=track_excluded,
            has_actionable_product=any(p.actionable for p in products),
        ),
        products=products,
    )


# ---------------------------------------------------------------------------
# Track affectedness (package-service.md, `set_track_status()`)
# ---------------------------------------------------------------------------


def _utc_today() -> date:
    """The current UTC date (patched by controlled-clock tests)."""
    return datetime.now(UTC).date()


async def set_track_status(
    db: AsyncSession,
    *,
    ticket_id: uuid.UUID,
    package_id: uuid.UUID,
    track_id: uuid.UUID,
    status: PackageStatus,
    acting_user_id: uuid.UUID | None,
    caller: TicketCaller | SystemInvocation,
    force: bool = False,
    evaluation_date: date | None = None,
) -> TrackStatusResult:
    """Set the affectedness status of one `TicketPackageTrack`.

    Category A mutation (package-service.md, `set_track_status()`;
    package-model.md, Status Behavior, Manual Transitions, Automatic
    Transitions).

    Q1: `ticket_id`, `package_id`, `track_id` are the declared semantic
    locator (internal UUIDs; the API resolves `SNTL-{n}` first). A
    user-attributed call passes the authenticated `acting_user_id` and
    the request-resolved `caller` identifying it; a system call passes
    `acting_user_id=None` and `caller=SYSTEM_INVOCATION`. `force` is the
    caller-verified `admin_ticket_ops` marker (ignored for a system
    call). `evaluation_date` is the one UTC date shared by reconciliation
    and the result projection; captured once at entry when omitted.

    Q2: the caller owns the transaction and has verified capabilities
    (`admin_ticket_ops OR manage_packages`, and `manage_packages` for a
    non-`FIXED` target). Locks: a user-attributed call takes the acting
    User `FOR SHARE` (`stabilize_acting_user()`) then the Ticket `FOR
    UPDATE`; a system call takes only the Ticket lock.

    Q3: (2) consumer locked-current accessibility; (3)
    `ensure_ticket_operable()`; (4) locked path reload; (5-6) authority:
    user `FIXED` with `force` is unrestricted, user `FIXED` without
    `force` requires locked `cve_id IS NULL`, a user non-`FIXED` target
    requires `force=False`, and a system call accepts only `FIXED` (any
    other system target logs one sanitized warning and returns
    `rejected`); (7) an unchanged target returns `no_op`; (8) a system
    `FIXED` on a final state returns the protected `no_op`; (9)
    `auto_assign_actor()` for an effective user change only; (10) writes
    the status, creates one `track_status_changed` (locked old value,
    requested new value, `detail = {track, package}`, acting user or
    `NULL`), then calls `reconcile_ticket_status()` once with the shared
    date; (11) flushes. Excluded and EOL tracks remain mutable. No-op and
    rejected outcomes create no assignment, audit event, reconciliation,
    or convergence registration. Never commits, reads audit history, or
    performs external I/O.

    Q4: returns the outcome, the locked-current track projection, and the
    shared `evaluation_date`.

    Q6: raises `ValueError` before any database operation for an
    inconsistent actor/context pairing. Raises `TicketNotFoundError` for
    a missing or (consumer) inaccessible Ticket before any other
    decision, `TicketNotMutableError` for `Ignored`/`Duplicated`,
    `PackageNotFoundError` / `TrackNotFoundError` for a missing or
    mismatched path level, and `TrackFixedStatusRestrictedError` for a
    prohibited user target, all without side effects. `UserNotFoundError`
    (an invariant violation), audit, database, flush, and reconciliation
    exceptions propagate and roll back the caller's transaction.
    """
    is_system = _resolve_actor(acting_user_id, caller)
    if evaluation_date is None:
        evaluation_date = _utc_today()

    if isinstance(caller, SystemInvocation):
        acting_user = None
        ticket = await _lock_system_ticket(db, ticket_id)
    else:
        assert acting_user_id is not None  # guaranteed by _resolve_actor
        acting_user = await stabilize_acting_user(db, acting_user_id)
        ticket = await lock_accessible_ticket(db, ticket_id, caller)
    ensure_ticket_operable(ticket)
    package, track = await _load_locked_track(
        db, ticket_id=ticket.id, package_id=package_id, track_id=track_id
    )

    if is_system:
        if status is not PackageStatus.FIXED:
            logger.warning(
                "track_status_system_target_rejected",
                ticket_id=str(ticket.id),
                package_id=str(package_id),
                track_id=str(track_id),
                requested_status=status.value,
            )
            return await _track_status_result(
                db, MutationOutcome.REJECTED, ticket, track_id, evaluation_date
            )
    elif status is PackageStatus.FIXED:
        if not force and ticket.cve_id is not None:
            raise TrackFixedStatusRestrictedError()
    elif force:
        raise TrackFixedStatusRestrictedError()

    old_status = PackageStatus(track.status)
    if old_status is status or (is_system and old_status in _FINAL_STATUSES):
        return await _track_status_result(
            db, MutationOutcome.NO_OP, ticket, track_id, evaluation_date
        )

    if acting_user is not None:
        await auto_assign_actor(ticket, acting_user, db)
    track.status = status.value
    await TicketAuditLog.log_event(
        db,
        ticket_id=ticket.id,
        event_type=TicketAuditEventType.TRACK_STATUS_CHANGED,
        user_id=acting_user_id,
        old_value=old_status.value,
        new_value=status.value,
        detail={"track": track.reference, "package": package.package_name},
    )
    await reconcile_ticket_status(ticket, db, evaluation_date=evaluation_date)
    await db.flush()
    return await _track_status_result(
        db, MutationOutcome.CHANGED, ticket, track_id, evaluation_date
    )


async def _track_status_result(
    db: AsyncSession,
    outcome: MutationOutcome,
    ticket: Ticket,
    track_id: uuid.UUID,
    evaluation_date: date,
) -> TrackStatusResult:
    return TrackStatusResult(
        outcome=outcome,
        track=await _project_track(
            db, ticket=ticket, track_id=track_id, evaluation_date=evaluation_date
        ),
        evaluation_date=evaluation_date,
    )


# ---------------------------------------------------------------------------
# Product eligibility override (package-service.md, `set_product_eligibility()`;
# package-model.md, Override Product Eligibility response)
# ---------------------------------------------------------------------------

_VA_OVERRIDE_REASON: Final = "va_override"


class OverrideAction(StrEnum):
    """The `override_action` of an authorized-user eligibility event.

    `SET`: automatic management becomes a manual override (including a
    metadata-only set with an unchanged boolean). `CHANGED`: an existing
    override changes value. `CLEARED`: the override is removed.
    """

    SET = "set"
    CHANGED = "changed"
    CLEARED = "cleared"


@dataclass(frozen=True, slots=True)
class ProductEligibilityProjection:
    """The locked-current Product occurrence of an eligibility result.

    `ticket_id` is the canonical `SNTL-{n}` identity; `package_name` and
    `reference` identify the parent package and track; `id` is the
    `TicketPackageProduct` occurrence UUID. `lifecycle_phase`,
    `actionable`, and `non_actionable_reason` use the shared
    `evaluation_date`.
    """

    ticket_id: str
    package_name: str
    reference: str
    id: uuid.UUID
    product_cpe: str
    product_name: str
    eligible: bool
    is_eligible_override: bool
    lifecycle_phase: LifecyclePhase | None
    actionable: bool
    non_actionable_reason: NonActionableReason | None


@dataclass(frozen=True, slots=True)
class ProductEligibilityResult:
    """Result of `set_product_eligibility()`.

    `outcome` is `changed` or `no_op`; `product` is projected from state
    observed under the Ticket lock with `evaluation_date`, the one UTC
    date also used by lifecycle evaluation and reconciliation.
    """

    outcome: MutationOutcome
    product: ProductEligibilityProjection
    evaluation_date: date


async def _project_product(
    db: AsyncSession,
    *,
    ticket: Ticket,
    ticket_package_product_id: uuid.UUID,
    evaluation_date: date,
) -> ProductEligibilityProjection:
    """Project one Product occurrence under the held Ticket lock.

    One statement reads the occurrence, its catalog Product, the parent
    track and package with their direct markers, the lifecycle phase, and
    the SQL Product actionability, all for `evaluation_date`; the reason
    is derived by the canonical precedence. Performs no write.
    """
    row = (
        await db.execute(
            select(
                TicketPackage.package_name,
                TicketPackage.deleted_at.label("package_deleted_at"),
                TicketPackageTrack.reference,
                TicketPackageTrack.deleted_at.label("track_deleted_at"),
                TicketPackageProduct.id,
                TicketPackageProduct.eligible,
                TicketPackageProduct.is_eligible_override,
                TicketPackageProduct.deleted_at.label("product_deleted_at"),
                Product.cpe,
                Product.display_name,
                lifecycle_phase_expression(evaluation_date, Product).label(
                    "lifecycle_phase"
                ),
                product_actionable_expression(evaluation_date).label("actionable"),
            )
            .select_from(TicketPackageProduct)
            .join(
                TicketPackageTrack,
                TicketPackageTrack.id == TicketPackageProduct.ticket_package_track_id,
            )
            .join(
                TicketPackage, TicketPackage.id == TicketPackageTrack.ticket_package_id
            )
            .join(Product, Product.id == TicketPackageProduct.product_id)
            .where(TicketPackageProduct.id == ticket_package_product_id)
        )
    ).one()
    phase = row.lifecycle_phase
    lifecycle_phase = LifecyclePhase(phase) if phase is not None else None
    return ProductEligibilityProjection(
        ticket_id=format_ticket_id(ticket.sequence_id),
        package_name=row.package_name,
        reference=row.reference,
        id=row.id,
        product_cpe=row.cpe,
        product_name=row.display_name,
        eligible=row.eligible,
        is_eligible_override=row.is_eligible_override,
        lifecycle_phase=lifecycle_phase,
        actionable=row.actionable,
        non_actionable_reason=product_non_actionable_reason(
            package_excluded=row.package_deleted_at is not None,
            track_excluded=row.track_deleted_at is not None,
            product_excluded=row.product_deleted_at is not None,
            lifecycle_phase=lifecycle_phase,
        ),
    )


async def set_product_eligibility(
    db: AsyncSession,
    *,
    ticket_id: uuid.UUID,
    package_id: uuid.UUID,
    track_id: uuid.UUID,
    ticket_package_product_id: uuid.UUID,
    eligible: bool | None,
    acting_user_id: uuid.UUID,
    caller: TicketCaller,
    evaluation_date: date | None = None,
) -> ProductEligibilityResult:
    """Set, change, or clear the eligibility override of one occurrence.

    Category A mutation (package-service.md, `set_product_eligibility()`;
    package-model.md, Authorized-User Overrides Product Eligibility,
    Override Model, Override Product Eligibility).

    Q1: `ticket_id`, `package_id`, `track_id`, `ticket_package_product_id`
    are the declared semantic locator (internal UUIDs; the API resolves
    `SNTL-{n}` first; the last is a `TicketPackageProduct.id`, never a
    catalog `Product.id`). `eligible` is the override value, or `None` to
    reset to automatic calculation. `acting_user_id` is the authenticated
    user and `caller` the request-resolved caller identifying it; there is
    no system form. `evaluation_date` is the one UTC date shared by
    lifecycle evaluation, eligibility, reconciliation, and the result
    projection; captured once at entry when omitted.

    Q2: the caller owns the transaction and has verified
    `manage_packages`. Locks: the acting User `FOR SHARE`
    (`stabilize_acting_user()`), then the Ticket `FOR UPDATE`. CVE
    assessments are read as current committed state without a CVE lock.

    Q3: (2) locked-current accessibility; (3) `ensure_ticket_operable()`;
    (4) locked path reload. Override (`eligible` is a bool): (5) `no_op`
    when the locked value equals `eligible` and the marker is already
    `true`; (6) `auto_assign_actor()`; (7-8) sets the value and the
    marker; (9) one acting-user `product_eligibility_changed` with the
    event-time Product subject, `reason = va_override`, and
    `override_action = set` (from automatic management, even with an
    unchanged boolean) or `changed` (an override value change); (10)
    `reconcile_ticket_status()` once; (11) flushes. Reset (`None`): (5)
    `no_op` when the marker is already `false`; (6) `auto_assign_actor()`;
    (7) clears the marker; (8-9) recalculates `eligible` with the shared
    pure evaluator from the current `default_cvss_version`, assessment
    set (the `10.0` fallback without a SUSE default-version assessment,
    including a CVE-less Ticket), Product threshold, and lifecycle phase;
    (10) one event with `override_action = cleared` and truthful old/new
    values, which may be equal; (11) reconciles once; (12) flushes.
    Excluded and EOL occurrences remain mutable; affectedness, delivery,
    `released_at`, and exclusion markers are never changed. No-op
    outcomes create no assignment, audit event, reconciliation, or
    convergence registration. Never commits, reads audit history, or
    performs external I/O.

    Q4: returns the outcome, the locked-current Product projection, and
    the shared `evaluation_date`.

    Q6: raises `ValueError` before any database operation when the actor
    is null or `caller` is not a consumer caller identifying it. Raises
    `TicketNotFoundError` for a missing or inaccessible Ticket before any
    other decision, `TicketNotMutableError` for `Ignored`/`Duplicated`,
    and `PackageNotFoundError` / `TrackNotFoundError` /
    `ProductNotFoundError` for a missing or mismatched path level, all
    without side effects. `UserNotFoundError` (an invariant violation),
    settings, eligibility-resolution, audit, database, flush, and
    reconciliation exceptions propagate and roll back the caller's
    transaction.
    """
    _require_consumer_actor(acting_user_id, caller)
    if evaluation_date is None:
        evaluation_date = _utc_today()

    acting_user = await stabilize_acting_user(db, acting_user_id)
    ticket = await lock_accessible_ticket(db, ticket_id, caller)
    ensure_ticket_operable(ticket)
    path = await _load_locked_product(
        db,
        ticket_id=ticket.id,
        package_id=package_id,
        track_id=track_id,
        ticket_package_product_id=ticket_package_product_id,
        evaluation_date=evaluation_date,
    )
    occurrence = path.occurrence
    old_eligible = occurrence.eligible
    was_override = occurrence.is_eligible_override

    if eligible is None:
        if not was_override:
            return await _product_eligibility_result(
                db, MutationOutcome.NO_OP, ticket, occurrence.id, evaluation_date
            )
        action = OverrideAction.CLEARED
    else:
        if was_override and old_eligible == eligible:
            return await _product_eligibility_result(
                db, MutationOutcome.NO_OP, ticket, occurrence.id, evaluation_date
            )
        action = OverrideAction.CHANGED if was_override else OverrideAction.SET

    await auto_assign_actor(ticket, acting_user, db)
    if eligible is None:
        occurrence.is_eligible_override = False
        automatic = evaluate_product_eligibility(
            is_eligible_override=False,
            lifecycle_phase=path.lifecycle_phase,
            cvss_threshold=path.product.cvss_threshold,
            eligibility_score=await _current_eligibility_score(db, ticket),
        ).automatic_eligible
        assert automatic is not None  # an automatic record always has a value
        new_eligible = automatic
    else:
        occurrence.is_eligible_override = True
        new_eligible = eligible
    occurrence.eligible = new_eligible
    await TicketAuditLog.log_event(
        db,
        ticket_id=ticket.id,
        event_type=TicketAuditEventType.PRODUCT_ELIGIBILITY_CHANGED,
        user_id=acting_user_id,
        old_value=_eligibility_value(old_eligible),
        new_value=_eligibility_value(new_eligible),
        detail={
            "track": path.track.reference,
            "package": path.package.package_name,
            "product_name": path.product.display_name,
            "product_cpe": path.product.cpe,
            "reason": _VA_OVERRIDE_REASON,
            "override_action": action.value,
        },
    )
    await reconcile_ticket_status(ticket, db, evaluation_date=evaluation_date)
    await db.flush()
    return await _product_eligibility_result(
        db, MutationOutcome.CHANGED, ticket, occurrence.id, evaluation_date
    )


async def _product_eligibility_result(
    db: AsyncSession,
    outcome: MutationOutcome,
    ticket: Ticket,
    ticket_package_product_id: uuid.UUID,
    evaluation_date: date,
) -> ProductEligibilityResult:
    return ProductEligibilityResult(
        outcome=outcome,
        product=await _project_product(
            db,
            ticket=ticket,
            ticket_package_product_id=ticket_package_product_id,
            evaluation_date=evaluation_date,
        ),
        evaluation_date=evaluation_date,
    )


# ---------------------------------------------------------------------------
# Product-originated eligibility recalculation (package-service.md,
# `recalculate_product_eligibility_for_ticket()`)
# ---------------------------------------------------------------------------

ProductRecalculationReason = Literal["threshold", "reactive_ltss"]
"""System trigger recorded in Product-originated eligibility events."""

PRODUCT_RECALCULATION_REASONS: Final[frozenset[str]] = frozenset(
    get_args(ProductRecalculationReason)
)

_MANUAL_ZONE: Final = frozenset({TicketStatus.IGNORED, TicketStatus.DUPLICATED})


@dataclass(frozen=True, slots=True)
class ProductEligibilityRecalculationResult:
    """Outcome of one Product-originated recalculation in one Ticket.

    `examined` counts every occurrence of the catalog Product in the Ticket,
    including `override_skipped`; `changed` the occurrences whose `eligible`
    value was updated. A Ticket found in the manual zone has
    `manual_zone_skipped = True` and zero counts.
    """

    examined: int
    override_skipped: int
    changed: int
    manual_zone_skipped: bool


async def recalculate_product_eligibility_for_ticket(
    db: AsyncSession,
    ticket_id: uuid.UUID,
    catalog_product_id: uuid.UUID,
    reason: ProductRecalculationReason,
    evaluation_date: date | None = None,
) -> ProductEligibilityRecalculationResult:
    """Recalculate one catalog Product's automatic eligibility in one Ticket.

    Category A system mutation boundary (package-service.md,
    `recalculate_product_eligibility_for_ticket()`;
    product-lifecycle-transitions.md, Sub-task:
    `re_evaluate_product_eligibility`). Used after an AIMAAS threshold
    change (`reason = "threshold"`) or a Reactive Support lifecycle change
    (`reason = "reactive_ltss"`).

    Q1: `catalog_product_id` is the internal catalog `Product.id`, never a
    `TicketPackageProduct.id`. `evaluation_date` is the caller's UTC date;
    when omitted, one UTC date is captured at entry. No threshold,
    lifecycle phase, score, or expected result is supplied by the caller.

    Q2: validates `reason` before any database operation. Acquires `FOR
    UPDATE` on the Ticket as the first database operation (no User lock,
    no CVE lock). An `Ignored` or `Duplicated` Ticket returns a manual-zone
    skip result; otherwise `ensure_ticket_operable()` applies and the
    catalog Product must exist.

    Q3: recalculates every occurrence of the Product in the Ticket,
    including directly or effectively excluded and EOL occurrences under
    every track status, from the current persisted `default_cvss_version`,
    assessment set, threshold, and lifecycle dates with the shared pure
    evaluator; skips manual overrides; updates differing values in
    ascending `TicketPackageProduct.id` order with one system
    `product_eligibility_changed` each (`user_id`/`comment` NULL, event-time
    Product subject, `reason`); when at least one value changed, calls
    `reconcile_ticket_status()` exactly once with the same
    `evaluation_date`; flushes. Never assigns, never creates or clears an
    override, never commits or rolls back.

    Q4: returns the examined, override-skipped, and changed counts and
    whether the Ticket was skipped in the manual zone.

    Q5: deterministic and idempotent: a converged Ticket is a no-op without
    event or reconciliation.

    Q6: `ValueError` for an unsupported `reason` (caller contract);
    `TicketNotFoundError` for a missing Ticket; `ProductNotFoundError` for a
    missing catalog Product. Settings, database, eligibility-resolution,
    audit, and reconciliation exceptions propagate and roll back the
    caller's whole Ticket transaction.
    """
    if reason not in PRODUCT_RECALCULATION_REASONS:
        raise ValueError(f"unsupported eligibility recalculation reason: {reason!r}")
    if evaluation_date is None:
        evaluation_date = _utc_today()

    ticket = await _lock_system_ticket(db, ticket_id)
    if ticket.status in _MANUAL_ZONE:
        return ProductEligibilityRecalculationResult(
            examined=0, override_skipped=0, changed=0, manual_zone_skipped=True
        )
    ensure_ticket_operable(ticket)

    product_exists = (
        await db.execute(select(Product.id).where(Product.id == catalog_product_id))
    ).scalar_one_or_none()
    if product_exists is None:
        raise ProductNotFoundError()

    counts = await _recalculate_automatic_eligibility(
        db,
        ticket=ticket,
        evaluation_date=evaluation_date,
        reason=reason,
        catalog_product_id=catalog_product_id,
    )
    if counts.changed:
        await reconcile_ticket_status(ticket, db, evaluation_date=evaluation_date)
    await db.flush()
    return ProductEligibilityRecalculationResult(
        examined=counts.examined,
        override_skipped=counts.override_skipped,
        changed=counts.changed,
        manual_zone_skipped=False,
    )


# ---------------------------------------------------------------------------
# Lifecycle actionability reconciliation (package-service.md,
# `reconcile_lifecycle_actionability_for_ticket()`)
# ---------------------------------------------------------------------------

_LIFECYCLE_SKIPPED_STATUSES: Final = frozenset(
    {TicketStatus.NEW, TicketStatus.IGNORED, TicketStatus.DUPLICATED}
)


@dataclass(frozen=True, slots=True)
class LifecycleReconciliationResult:
    """Outcome of one lifecycle actionability reconciliation.

    `previous_status` is the locked-current status before reconciliation and
    `current_status` the status after it; `changed` is true exactly when
    they differ. A `New`, `Ignored`, or `Duplicated` Ticket has
    `skipped = True` and an unchanged status.
    """

    previous_status: TicketStatus
    current_status: TicketStatus
    changed: bool
    skipped: bool


async def reconcile_lifecycle_actionability_for_ticket(
    db: AsyncSession,
    ticket_id: uuid.UUID,
    evaluation_date: date,
) -> LifecycleReconciliationResult:
    """Reconcile one gate-zone Ticket against current derived actionability.

    Category A system mutation boundary (package-service.md,
    `reconcile_lifecycle_actionability_for_ticket()`;
    product-lifecycle-transitions.md, Algorithm step 4 and Catch-Up). Used
    after Product lifecycle data or the UTC date may have changed derived
    actionability; neither the lifecycle phase nor actionability is
    persisted.

    Q1: `evaluation_date` is the caller's UTC date for its complete
    lifecycle evaluation run.

    Q2: acquires `FOR UPDATE` on the Ticket as the first database
    operation (no User or CVE lock). `New`, `Ignored`, and `Duplicated`
    return a skipped result (defensive race guard).

    Q3: calls `reconcile_ticket_status()` exactly once with
    `evaluation_date`, then flushes. The delegated reconciliation creates
    the ordinary system `status_change` when the status changes and
    registers Ticket convergence for a `Resolved` regression. Never
    assigns, never creates a separate audit event, and never writes
    exclusion markers, eligibility, affectedness, or delivery state; never
    commits or rolls back.

    Q4: returns the previous and current status and whether it changed.

    Q5: deterministic and idempotent for the supplied date and current
    persisted data: a converged Ticket is a no-op.

    Q6: `TicketNotFoundError` for a missing Ticket; database, audit, and
    reconciliation exceptions propagate and roll back the caller's
    transaction.
    """
    ticket = await _lock_system_ticket(db, ticket_id)
    previous = TicketStatus(ticket.status)
    if previous in _LIFECYCLE_SKIPPED_STATUSES:
        return LifecycleReconciliationResult(
            previous_status=previous,
            current_status=previous,
            changed=False,
            skipped=True,
        )

    await reconcile_ticket_status(ticket, db, evaluation_date=evaluation_date)
    await db.flush()
    current = TicketStatus(ticket.status)
    return LifecycleReconciliationResult(
        previous_status=previous,
        current_status=current,
        changed=current is not previous,
        skipped=False,
    )


# ---------------------------------------------------------------------------
# Package-record creation (package-service.md, `add_package_records()`;
# package-maintainership.md, Acquisition Workflow > Locked mutation)
# ---------------------------------------------------------------------------

PackageAddedComment = Literal[
    "CVE package resolution", "Product catalog backfill", "Ticket convergence"
]
"""Closed system context recorded as the `package_added` comment."""

_ACTIVE_STATUSES: Final = frozenset(
    {TicketStatus.NEW, TicketStatus.ANALYSIS, TicketStatus.ANALYZED}
)


@dataclass(frozen=True, slots=True)
class ResolvedTrackData:
    """One fully validated and locally resolved track of a package.

    `reference` is the unique SMELT codestream name, already validated
    against the persisted track-reference constraints; `workflow_type` is
    already mapped from the authoritative maintenance process type;
    `catalog_product_ids` are the distinct internal IDs of existing local
    Products resolved by exact CPE under this codestream (a tuple, so a
    duplicate remains a detectable caller-contract violation).
    """

    reference: str
    workflow_type: WorkflowType
    catalog_product_ids: tuple[uuid.UUID, ...]


class PackageRecordsOutcome(StrEnum):
    """Semantic outcome of `add_package_records()`. Never persisted."""

    PACKAGE_TREE_CHANGED = "package_tree_changed"
    PACKAGE_TREE_NO_OP = "package_tree_no_op"
    MAINTAINER_ONLY = "maintainer_only"
    ACTIVE_TICKET_ONLY_SKIPPED = "active_ticket_only_skipped"


@dataclass(frozen=True, slots=True)
class CreatedTrack:
    """A track newly created by one invocation, with its persisted
    `workflow_type` (the post-commit IBS catch-up signal)."""

    track_id: uuid.UUID
    reference: str
    workflow_type: WorkflowType


@dataclass(frozen=True, slots=True)
class PackageRecordsResult:
    """Result of `add_package_records()`, derived from state under the lock.

    The counts cover the supplied tracks and Product IDs: a skip is an
    existing record (active or soft-deleted), including one committed by a
    concurrent winner. Maintainer additions change no count and add no
    field. An `active_ticket_only` skip examines nothing and has zero
    counts. `created_tracks` lists only the newly created tracks.
    """

    outcome: PackageRecordsOutcome
    tracks_created: int
    tracks_skipped: int
    products_created: int
    products_skipped: int
    created_tracks: tuple[CreatedTrack, ...]


@dataclass(slots=True)
class _TrackPlan:
    """One supplied track resolved against the locked package tree."""

    data: ResolvedTrackData
    existing_track_id: uuid.UUID | None
    missing_product_ids: list[uuid.UUID]


def _validate_package_records_input(
    acting_user_id: uuid.UUID | None,
    caller: TicketCaller | SystemInvocation,
    tracks: Sequence[ResolvedTrackData],
    audit_comment: str | None,
) -> None:
    """Reject a caller-contract violation before any database operation."""
    is_system = _resolve_actor(acting_user_id, caller)
    if not tracks:
        raise ValueError("tracks must not be empty.")
    references: set[str] = set()
    for track in tracks:
        if not track.catalog_product_ids:
            raise ValueError("a track must resolve at least one Product.")
        if len(set(track.catalog_product_ids)) != len(track.catalog_product_ids):
            raise ValueError("a track's catalog Product IDs must be distinct.")
        if track.reference in references:
            raise ValueError("track references must be distinct.")
        references.add(track.reference)
    if audit_comment is not None and (
        audit_comment not in PACKAGE_ADDED_AUTOMATIC_COMMENTS
    ):
        raise ValueError(f"unsupported package_added comment: {audit_comment!r}")
    if is_system and audit_comment is None:
        raise ValueError("a system invocation requires its canonical comment.")
    if not is_system and audit_comment is not None:
        raise ValueError("a user-attributed invocation has no audit comment.")


async def add_package_records(
    db: AsyncSession,
    *,
    ticket_id: uuid.UUID,
    package_name: str,
    tracks: Sequence[ResolvedTrackData],
    maintainer_emails: AbstractSet[str],
    acting_user_id: uuid.UUID | None,
    caller: TicketCaller | SystemInvocation,
    audit_comment: PackageAddedComment | None = None,
    active_ticket_only: bool = False,
    allow_excluded_reresolution: bool = False,
) -> PackageRecordsResult:
    """Create the missing package-tree records and maintainer associations.

    Category A mutation (package-service.md, `add_package_records()`,
    Record Creation Logic, Concurrency Control; package-maintainership.md,
    Acquisition Workflow > Locked mutation, Audit event; package-model.md,
    Adding Packages to a Ticket). The locked boundary delegated to by
    `add_package_to_ticket()` after all external I/O.

    Q1: `tracks` are the fully validated, locally resolved targets and
    `maintainer_emails` the validated, lowercase, globally deduplicated
    individual emails (empty when none). A user-attributed call passes
    the acting user's `acting_user_id`, the consumer `caller` identifying
    it, and `audit_comment=None`; a system call passes
    `acting_user_id=None`, `caller=SYSTEM_INVOCATION`, and its canonical
    `audit_comment`. `active_ticket_only` skips an inactive locked Ticket;
    `allow_excluded_reresolution` is the Ticket convergence mode.

    Q2: the caller owns the transaction and has completed all external
    I/O. Locks: a user-attributed call takes the acting User `FOR SHARE`
    (`stabilize_acting_user()`) then the Ticket `FOR UPDATE`; a system
    call takes only the Ticket lock. One UTC `evaluation_date` is captured
    at entry.

    Q3: (1) consumer locked-current accessibility; (2) an
    `active_ticket_only` call on a Ticket that is not `New`, `Analysis`,
    or `Analyzed` returns `active_ticket_only_skipped`; (3)
    `ensure_ticket_operable()`; (4) the existing package occurrence is
    reloaded under the lock and, outside re-resolution mode, a directly
    excluded one raises `PackageAlreadyExcludedError`; (5) the missing
    tracks, Product occurrences, and associations are determined under
    the lock (matching Users: exact `User.email` in `maintainer_emails`
    with `active` true, ordered by `User.id`, an unlocked observation);
    (6) nothing missing returns `package_tree_no_op`; (7) when a
    package-tree record is missing, `auto_assign_actor()`; (8) creates the
    package, new tracks (`ANALYSIS`/`PENDING`), and missing Product
    occurrences with creation eligibility from the shared evaluator
    (current threshold, lifecycle phase on `evaluation_date`, and the
    Ticket's Eligibility Score Resolution loaded once); existing records,
    including soft-deleted ones, are skipped unchanged and no marker is
    set or cleared; (9) inserts each missing association in ascending
    `User.id` order with one system `package_maintainer_added`
    (`new_value` the event-time username, `detail = {package}`); (10)
    when the package tree changed, one `package_added` (acting user and
    `NULL` comment, or system and `audit_comment`) and exactly one
    `reconcile_ticket_status()` with `evaluation_date`; a maintainer-only
    mutation assigns and reconciles nothing; (11) flushes. Never commits,
    reads audit history, logs a personal identifier, or performs network,
    Redis, or broker I/O; the only post-commit effect is a convergence
    registration made by the delegated reconciliation.

    Q4: returns the semantic outcome, the creation and skip counts, and
    the newly created tracks with their persisted `workflow_type`.

    Q5: idempotent: with unchanged inputs and state a repeat call is a
    `package_tree_no_op` without any write or event. Same-Ticket calls
    serialize on the Ticket lock and report a concurrent winner's rows as
    skips.

    Q6: raises `ValueError` before any database operation for an
    inconsistent actor/context pairing, empty `tracks`, a track without
    Products, duplicate Products within a track, a duplicate `reference`,
    or an `audit_comment` outside the closed set or inconsistent with the
    actor, and under the lock for a catalog Product that does not exist.
    Raises `TicketNotFoundError` for a missing or (consumer) inaccessible
    Ticket and `TicketNotMutableError` for a manual-zone Ticket before any
    other decision, and `PackageAlreadyExcludedError` before any effect.
    Settings, eligibility-resolution, database (including a unique
    violation), audit, flush, and reconciliation exceptions propagate and
    roll back the caller's complete transaction.
    """
    _validate_package_records_input(acting_user_id, caller, tracks, audit_comment)
    evaluation_date = _utc_today()

    if isinstance(caller, SystemInvocation):
        acting_user = None
        ticket = await _lock_system_ticket(db, ticket_id)
    else:
        assert acting_user_id is not None  # guaranteed by the validation
        acting_user = await stabilize_acting_user(db, acting_user_id)
        ticket = await lock_accessible_ticket(db, ticket_id, caller)

    if active_ticket_only and ticket.status not in _ACTIVE_STATUSES:
        return PackageRecordsResult(
            outcome=PackageRecordsOutcome.ACTIVE_TICKET_ONLY_SKIPPED,
            tracks_created=0,
            tracks_skipped=0,
            products_created=0,
            products_skipped=0,
            created_tracks=(),
        )
    ensure_ticket_operable(ticket)

    package = (
        await db.execute(
            select(TicketPackage)
            .where(
                TicketPackage.ticket_id == ticket.id,
                TicketPackage.package_name == package_name,
            )
            .execution_options(populate_existing=True)
        )
    ).scalar_one_or_none()
    if (
        package is not None
        and package.deleted_at is not None
        and not allow_excluded_reresolution
    ):
        raise PackageAlreadyExcludedError()

    existing_tracks: dict[str, uuid.UUID] = {}
    existing_products: set[tuple[uuid.UUID, uuid.UUID]] = set()
    existing_maintainers: set[uuid.UUID] = set()
    if package is not None:
        track_rows = await db.execute(
            select(
                TicketPackageTrack.id,
                TicketPackageTrack.reference,
                TicketPackageProduct.product_id,
            )
            .outerjoin(
                TicketPackageProduct,
                TicketPackageProduct.ticket_package_track_id == TicketPackageTrack.id,
            )
            .where(
                TicketPackageTrack.ticket_package_id == package.id,
                TicketPackageTrack.reference.in_([t.reference for t in tracks]),
            )
        )
        for track_id, reference, product_id in track_rows:
            existing_tracks[reference] = track_id
            if product_id is not None:
                existing_products.add((track_id, product_id))
        existing_maintainers = set(
            (
                await db.execute(
                    select(TicketPackageMaintainer.user_id).where(
                        TicketPackageMaintainer.ticket_package_id == package.id
                    )
                )
            )
            .scalars()
            .all()
        )

    new_maintainers: list[tuple[uuid.UUID, str]] = []
    if maintainer_emails:
        matches = await db.execute(
            select(User.id, User.username)
            .where(User.email.in_(sorted(maintainer_emails)), User.active.is_(True))
            .order_by(User.id)
        )
        new_maintainers = [
            (user_id, username)
            for user_id, username in matches
            if user_id not in existing_maintainers
        ]

    plans: list[_TrackPlan] = []
    tracks_skipped = 0
    products_skipped = 0
    for data in tracks:
        existing_track_id = existing_tracks.get(data.reference)
        if existing_track_id is None:
            missing = list(data.catalog_product_ids)
        else:
            tracks_skipped += 1
            missing = [
                product_id
                for product_id in data.catalog_product_ids
                if (existing_track_id, product_id) not in existing_products
            ]
            products_skipped += len(data.catalog_product_ids) - len(missing)
        plans.append(_TrackPlan(data, existing_track_id, missing))

    tree_changed = package is None or any(
        plan.existing_track_id is None or plan.missing_product_ids for plan in plans
    )
    if not tree_changed and not new_maintainers:
        return PackageRecordsResult(
            outcome=PackageRecordsOutcome.PACKAGE_TREE_NO_OP,
            tracks_created=0,
            tracks_skipped=tracks_skipped,
            products_created=0,
            products_skipped=products_skipped,
            created_tracks=(),
        )

    created_tracks: list[CreatedTrack] = []
    products_created = 0
    if tree_changed:
        await auto_assign_actor(ticket, acting_user, db)
        if package is None:
            package = TicketPackage(ticket_id=ticket.id, package_name=package_name)
            db.add(package)
            await db.flush()
        created_tracks, products_created = await _create_package_tree(
            db,
            ticket=ticket,
            package=package,
            plans=plans,
            evaluation_date=evaluation_date,
        )

    assert package is not None  # a maintainer-only outcome found the package
    for user_id, username in new_maintainers:
        db.add(TicketPackageMaintainer(ticket_package_id=package.id, user_id=user_id))
        await TicketAuditLog.log_event(
            db,
            ticket_id=ticket.id,
            event_type=TicketAuditEventType.PACKAGE_MAINTAINER_ADDED,
            user_id=None,
            new_value=username,
            detail={"package": package.package_name},
        )

    if tree_changed:
        await TicketAuditLog.log_event(
            db,
            ticket_id=ticket.id,
            event_type=TicketAuditEventType.PACKAGE_ADDED,
            user_id=acting_user_id,
            new_value=package.package_name,
            comment=audit_comment,
        )
        await reconcile_ticket_status(ticket, db, evaluation_date=evaluation_date)
    await db.flush()
    return PackageRecordsResult(
        outcome=(
            PackageRecordsOutcome.PACKAGE_TREE_CHANGED
            if tree_changed
            else PackageRecordsOutcome.MAINTAINER_ONLY
        ),
        tracks_created=len(created_tracks),
        tracks_skipped=tracks_skipped,
        products_created=products_created,
        products_skipped=products_skipped,
        created_tracks=tuple(created_tracks),
    )


async def _create_package_tree(
    db: AsyncSession,
    *,
    ticket: Ticket,
    package: TicketPackage,
    plans: Sequence[_TrackPlan],
    evaluation_date: date,
) -> tuple[list[CreatedTrack], int]:
    """Insert the planned new tracks and missing Product occurrences.

    New tracks start at `ANALYSIS`/`PENDING`. Each new occurrence gets its
    creation eligibility from the shared pure evaluator over the current
    Product threshold, the lifecycle phase on `evaluation_date`, and the
    Ticket's Eligibility Score Resolution, loaded once (package-service.md,
    Record Creation Logic). Returns the created tracks and the number of
    created occurrences. Raises `ValueError` for an unknown catalog
    Product.
    """
    targets: list[tuple[_TrackPlan, TicketPackageTrack | None]] = []
    for plan in plans:
        track = None
        if plan.existing_track_id is None:
            track = TicketPackageTrack(
                ticket_package_id=package.id,
                workflow_type=plan.data.workflow_type.value,
                reference=plan.data.reference,
                status=PackageStatus.ANALYSIS.value,
                delivery_status=DeliveryStatus.PENDING.value,
            )
            db.add(track)
        targets.append((plan, track))
    await db.flush()

    created_tracks: list[CreatedTrack] = []
    occurrences: list[tuple[uuid.UUID, uuid.UUID]] = []
    for plan, track in targets:
        if track is None:
            assert plan.existing_track_id is not None
            track_id = plan.existing_track_id
        else:
            track_id = track.id
            created_tracks.append(
                CreatedTrack(track.id, track.reference, plan.data.workflow_type)
            )
        occurrences.extend((track_id, p) for p in plan.missing_product_ids)

    eligibility = await _current_eligibility_score(db, ticket)
    product_ids = {product_id for _, product_id in occurrences}
    inputs = {
        row.id: row
        for row in await db.execute(
            select(
                Product.id,
                Product.cvss_threshold,
                lifecycle_phase_expression(evaluation_date).label("lifecycle"),
            ).where(Product.id.in_(product_ids))
        )
    }
    for track_id, product_id in occurrences:
        product = inputs.get(product_id)
        if product is None:
            raise ValueError("a resolved catalog Product does not exist.")
        eligible = evaluate_product_eligibility(
            is_eligible_override=False,
            lifecycle_phase=(
                LifecyclePhase(product.lifecycle)
                if product.lifecycle is not None
                else None
            ),
            cvss_threshold=product.cvss_threshold,
            eligibility_score=eligibility,
        ).automatic_eligible
        assert eligible is not None  # no override on a new occurrence
        db.add(
            TicketPackageProduct(
                ticket_package_track_id=track_id,
                product_id=product_id,
                eligible=eligible,
                is_eligible_override=False,
            )
        )
    await db.flush()
    return created_tracks, len(occurrences)


# ---------------------------------------------------------------------------
# Exclusion and restoration (package-service.md, Exclusion and restoration
# operations; package-model.md, Exclusion and Actionability, Soft-Delete and
# Restore Package, Track, and Product responses)
# ---------------------------------------------------------------------------


class _MarkerLevel(Enum):
    """The package-tree level whose direct `deleted_at` marker changes."""

    PACKAGE = "package"
    TRACK = "track"
    PRODUCT = "product"


class _MarkerDirection(Enum):
    """Exclusion sets the direct marker; restoration clears it."""

    EXCLUDE = "exclude"
    RESTORE = "restore"


_MARKER_EVENTS: Final[
    Mapping[tuple[_MarkerLevel, _MarkerDirection], TicketAuditEventType]
] = {
    (_MarkerLevel.PACKAGE, _MarkerDirection.EXCLUDE): (
        TicketAuditEventType.PACKAGE_EXCLUDED
    ),
    (_MarkerLevel.TRACK, _MarkerDirection.EXCLUDE): TicketAuditEventType.TRACK_EXCLUDED,
    (_MarkerLevel.PRODUCT, _MarkerDirection.EXCLUDE): (
        TicketAuditEventType.PRODUCT_EXCLUDED
    ),
    (_MarkerLevel.PACKAGE, _MarkerDirection.RESTORE): (
        TicketAuditEventType.PACKAGE_RESTORED
    ),
    (_MarkerLevel.TRACK, _MarkerDirection.RESTORE): TicketAuditEventType.TRACK_RESTORED,
    (_MarkerLevel.PRODUCT, _MarkerDirection.RESTORE): (
        TicketAuditEventType.PRODUCT_RESTORED
    ),
}


@dataclass(frozen=True, slots=True)
class PackageMarkerProjection:
    """The locked-current package of an exclusion or restoration result.

    `actionable` and `non_actionable_reason` (`package_excluded`, then
    `no_actionable_tracks`) use the shared `evaluation_date`.
    """

    package_name: str
    actionable: bool
    non_actionable_reason: NonActionableReason | None


@dataclass(frozen=True, slots=True)
class TrackMarkerProjection:
    """The locked-current track of an exclusion or restoration result.

    `reference` is the track reference; `actionable` and
    `non_actionable_reason` (`package_excluded`, `track_excluded`, then
    `no_actionable_products`) use the shared `evaluation_date`.
    """

    reference: str
    actionable: bool
    non_actionable_reason: NonActionableReason | None


@dataclass(frozen=True, slots=True)
class ProductMarkerProjection:
    """The locked-current Product occurrence of an exclusion or restoration.

    `id` is the `TicketPackageProduct` occurrence UUID; `product_cpe` and
    `product_name` come from the related catalog Product. `actionable`
    and `non_actionable_reason` (`package_excluded`, `track_excluded`,
    `product_excluded`, then `eol`) use the shared `evaluation_date`.
    """

    id: uuid.UUID
    product_cpe: str
    product_name: str
    actionable: bool
    non_actionable_reason: NonActionableReason | None


@dataclass(frozen=True, slots=True)
class MarkerChangeResult[P]:
    """Result of one effective direct-marker exclusion or restoration.

    `target` is the targeted record projected from state observed under
    the Ticket lock after the flush; `evaluation_date` is the one UTC
    date also used by Ticket reconciliation. There is no outcome field:
    a repeated call fails on the direct-marker guard instead of
    returning a no-op.
    """

    target: P
    evaluation_date: date


def _marker_now() -> datetime:
    """The current UTC instant set on an exclusion marker (patched by tests)."""
    return datetime.now(UTC)


async def _change_direct_marker(
    db: AsyncSession,
    *,
    level: _MarkerLevel,
    direction: _MarkerDirection,
    ticket_id: uuid.UUID,
    package_id: uuid.UUID,
    track_id: uuid.UUID | None,
    ticket_package_product_id: uuid.UUID | None,
    acting_user_id: uuid.UUID,
    caller: TicketCaller,
    evaluation_date: date | None,
) -> tuple[Ticket, date]:
    """Apply the shared Category A direct-marker contract.

    package-service.md, Exclusion and restoration operations, steps 1-9
    (the public function projects the result, step 10):

    1. validate the actor before any database operation (`ValueError`);
    2. resolve one `evaluation_date`, stabilize the acting User `FOR
       SHARE`, then lock the declared Ticket `FOR UPDATE`;
    3. locked-current accessibility (`TicketNotFoundError`);
    4. `ensure_ticket_operable()` (`TicketNotMutableError`);
    5. reload the declared path for `level` under the lock
       (`PackageNotFoundError` / `TrackNotFoundError` /
       `ProductNotFoundError`);
    6. inspect only the target's direct marker: exclusion of a set
       marker raises `PackageAlreadyExcludedError`, restoration of a NULL
       marker raises `PackageNotExcludedError`, before any effect;
    7. `auto_assign_actor()`;
    8. set the target marker to the current UTC instant, or clear it;
       ancestor and descendant markers and every other dimension stay
       unchanged;
    9. one acting-user event with the exact level payload (package
       name, track reference with `{track, package}`, or Product display
       name with the event-time Product subject; `comment = NULL`), then
       one `reconcile_ticket_status()` with the shared date, then flush.

    No ancestor, descendant, EOL, or child-existence condition is a
    guard. Returns the locked Ticket and the shared `evaluation_date`.
    Audit, reconciliation, database, and flush failures propagate and
    roll back the caller's transaction. Never commits, reads audit
    history, or performs external I/O.
    """
    actor_id = _require_consumer_actor(acting_user_id, caller)
    if evaluation_date is None:
        evaluation_date = _utc_today()

    acting_user = await stabilize_acting_user(db, actor_id)
    ticket = await lock_accessible_ticket(db, ticket_id, caller)
    ensure_ticket_operable(ticket)

    target: TicketPackage | TicketPackageTrack | TicketPackageProduct
    detail: dict[str, str] | None
    match level:
        case _MarkerLevel.PACKAGE:
            package = await _load_locked_package(
                db, ticket_id=ticket.id, package_id=package_id
            )
            target, subject, detail = package, package.package_name, None
        case _MarkerLevel.TRACK:
            assert track_id is not None  # guaranteed by the public functions
            package, track = await _load_locked_track(
                db, ticket_id=ticket.id, package_id=package_id, track_id=track_id
            )
            target, subject = track, track.reference
            detail = {"track": track.reference, "package": package.package_name}
        case _:
            assert level is _MarkerLevel.PRODUCT
            assert track_id is not None  # guaranteed by the public functions
            assert ticket_package_product_id is not None
            path = await _load_locked_product(
                db,
                ticket_id=ticket.id,
                package_id=package_id,
                track_id=track_id,
                ticket_package_product_id=ticket_package_product_id,
                evaluation_date=evaluation_date,
            )
            target, subject = path.occurrence, path.product.display_name
            detail = {
                "track": path.track.reference,
                "package": path.package.package_name,
                "product_name": path.product.display_name,
                "product_cpe": path.product.cpe,
            }

    directly_excluded = target.deleted_at is not None
    if direction is _MarkerDirection.EXCLUDE:
        if directly_excluded:
            raise PackageAlreadyExcludedError()
    elif not directly_excluded:
        raise PackageNotExcludedError()

    await auto_assign_actor(ticket, acting_user, db)
    if direction is _MarkerDirection.EXCLUDE:
        target.deleted_at = _marker_now()
        old_value, new_value = subject, None
    else:
        target.deleted_at = None
        old_value, new_value = None, subject
    await TicketAuditLog.log_event(
        db,
        ticket_id=ticket.id,
        event_type=_MARKER_EVENTS[level, direction],
        user_id=actor_id,
        old_value=old_value,
        new_value=new_value,
        detail=detail,
    )
    await reconcile_ticket_status(ticket, db, evaluation_date=evaluation_date)
    await db.flush()
    return ticket, evaluation_date


async def _project_marker_package(
    db: AsyncSession, *, package_id: uuid.UUID, evaluation_date: date
) -> PackageMarkerProjection:
    """Project one package under the held Ticket lock (one statement).

    When the direct marker is NULL, SQL package actionability equals the
    existence of an actionable track, so it feeds the canonical reason
    precedence directly; with the marker set, `package_excluded` wins.
    """
    row = (
        await db.execute(
            select(
                TicketPackage.package_name,
                TicketPackage.deleted_at,
                package_actionable_expression(evaluation_date).label("actionable"),
            ).where(TicketPackage.id == package_id)
        )
    ).one()
    return PackageMarkerProjection(
        package_name=row.package_name,
        actionable=row.actionable,
        non_actionable_reason=package_non_actionable_reason(
            package_excluded=row.deleted_at is not None,
            has_actionable_track=row.actionable,
        ),
    )


async def _project_marker_track(
    db: AsyncSession, *, track_id: uuid.UUID, evaluation_date: date
) -> TrackMarkerProjection:
    """Project one track under the held Ticket lock (one statement).

    When both direct markers are NULL, SQL track actionability equals
    the existence of an actionable Product, so it feeds the canonical
    reason precedence directly; otherwise an exclusion reason wins.
    """
    row = (
        await db.execute(
            select(
                TicketPackage.deleted_at.label("package_deleted_at"),
                TicketPackageTrack.reference,
                TicketPackageTrack.deleted_at.label("track_deleted_at"),
                track_actionable_expression(evaluation_date).label("actionable"),
            )
            .select_from(TicketPackageTrack)
            .join(
                TicketPackage, TicketPackage.id == TicketPackageTrack.ticket_package_id
            )
            .where(TicketPackageTrack.id == track_id)
        )
    ).one()
    return TrackMarkerProjection(
        reference=row.reference,
        actionable=row.actionable,
        non_actionable_reason=track_non_actionable_reason(
            package_excluded=row.package_deleted_at is not None,
            track_excluded=row.track_deleted_at is not None,
            has_actionable_product=row.actionable,
        ),
    )


async def _project_marker_product(
    db: AsyncSession,
    *,
    ticket: Ticket,
    ticket_package_product_id: uuid.UUID,
    evaluation_date: date,
) -> ProductMarkerProjection:
    """Project one Product occurrence under the held Ticket lock.

    Reuses the one-statement occurrence projection of the eligibility
    override and keeps only the exclusion response fields.
    """
    product = await _project_product(
        db,
        ticket=ticket,
        ticket_package_product_id=ticket_package_product_id,
        evaluation_date=evaluation_date,
    )
    return ProductMarkerProjection(
        id=product.id,
        product_cpe=product.product_cpe,
        product_name=product.product_name,
        actionable=product.actionable,
        non_actionable_reason=product.non_actionable_reason,
    )


async def _change_package_marker(
    db: AsyncSession,
    direction: _MarkerDirection,
    *,
    ticket_id: uuid.UUID,
    package_id: uuid.UUID,
    acting_user_id: uuid.UUID,
    caller: TicketCaller,
    evaluation_date: date | None,
) -> MarkerChangeResult[PackageMarkerProjection]:
    _, resolved_date = await _change_direct_marker(
        db,
        level=_MarkerLevel.PACKAGE,
        direction=direction,
        ticket_id=ticket_id,
        package_id=package_id,
        track_id=None,
        ticket_package_product_id=None,
        acting_user_id=acting_user_id,
        caller=caller,
        evaluation_date=evaluation_date,
    )
    return MarkerChangeResult(
        target=await _project_marker_package(
            db, package_id=package_id, evaluation_date=resolved_date
        ),
        evaluation_date=resolved_date,
    )


async def _change_track_marker(
    db: AsyncSession,
    direction: _MarkerDirection,
    *,
    ticket_id: uuid.UUID,
    package_id: uuid.UUID,
    track_id: uuid.UUID,
    acting_user_id: uuid.UUID,
    caller: TicketCaller,
    evaluation_date: date | None,
) -> MarkerChangeResult[TrackMarkerProjection]:
    _, resolved_date = await _change_direct_marker(
        db,
        level=_MarkerLevel.TRACK,
        direction=direction,
        ticket_id=ticket_id,
        package_id=package_id,
        track_id=track_id,
        ticket_package_product_id=None,
        acting_user_id=acting_user_id,
        caller=caller,
        evaluation_date=evaluation_date,
    )
    return MarkerChangeResult(
        target=await _project_marker_track(
            db, track_id=track_id, evaluation_date=resolved_date
        ),
        evaluation_date=resolved_date,
    )


async def _change_product_marker(
    db: AsyncSession,
    direction: _MarkerDirection,
    *,
    ticket_id: uuid.UUID,
    package_id: uuid.UUID,
    track_id: uuid.UUID,
    ticket_package_product_id: uuid.UUID,
    acting_user_id: uuid.UUID,
    caller: TicketCaller,
    evaluation_date: date | None,
) -> MarkerChangeResult[ProductMarkerProjection]:
    ticket, resolved_date = await _change_direct_marker(
        db,
        level=_MarkerLevel.PRODUCT,
        direction=direction,
        ticket_id=ticket_id,
        package_id=package_id,
        track_id=track_id,
        ticket_package_product_id=ticket_package_product_id,
        acting_user_id=acting_user_id,
        caller=caller,
        evaluation_date=evaluation_date,
    )
    return MarkerChangeResult(
        target=await _project_marker_product(
            db,
            ticket=ticket,
            ticket_package_product_id=ticket_package_product_id,
            evaluation_date=resolved_date,
        ),
        evaluation_date=resolved_date,
    )


async def soft_delete_ticket_package(
    db: AsyncSession,
    *,
    ticket_id: uuid.UUID,
    package_id: uuid.UUID,
    acting_user_id: uuid.UUID,
    caller: TicketCaller,
    evaluation_date: date | None = None,
) -> MarkerChangeResult[PackageMarkerProjection]:
    """Directly exclude one `TicketPackage` (sets only its `deleted_at`).

    Category A mutation under the shared contract of package-service.md
    (Exclusion and restoration operations); see `_change_direct_marker()`
    for the complete ordered behavior.

    Q1: `ticket_id` and `package_id` are the declared semantic locator
    (internal UUIDs; the API resolves `SNTL-{n}` first). `acting_user_id`
    is the authenticated user and `caller` the request-resolved caller
    identifying it; there is no system form. `evaluation_date` is the one
    UTC date shared by reconciliation and the projection; captured once
    at entry when omitted.

    Q2: the caller owns the transaction and has verified
    `manage_packages`. Locks: acting User `FOR SHARE`, then Ticket `FOR
    UPDATE`.

    Q3-Q5: a NULL direct marker is set to the current UTC instant, with
    one `package_excluded` event (`old_value` = package name), optional
    assignment, and one reconciliation. Tracks and Products keep their
    markers and become effectively excluded. Excluding the caller's last
    qualifying maintained package may remove its visibility; the call
    still succeeds (authorized on the locked pre-state).

    Q4: returns the locked-current package projection and the date.

    Q6: `ValueError` before any database operation for a null or
    mismatched actor; `TicketNotFoundError`, `TicketNotMutableError`,
    `PackageNotFoundError`, and `PackageAlreadyExcludedError` without
    side effects; audit, database, flush, and reconciliation failures
    propagate.
    """
    return await _change_package_marker(
        db,
        _MarkerDirection.EXCLUDE,
        ticket_id=ticket_id,
        package_id=package_id,
        acting_user_id=acting_user_id,
        caller=caller,
        evaluation_date=evaluation_date,
    )


async def restore_ticket_package(
    db: AsyncSession,
    *,
    ticket_id: uuid.UUID,
    package_id: uuid.UUID,
    acting_user_id: uuid.UUID,
    caller: TicketCaller,
    evaluation_date: date | None = None,
) -> MarkerChangeResult[PackageMarkerProjection]:
    """Restore one directly excluded `TicketPackage` (clears its marker).

    Same contract, parameters, locks, and exceptions as
    `soft_delete_ticket_package()`, except that the guard requires a set
    direct marker (`PackageNotExcludedError` otherwise) and the event is
    `package_restored` (`new_value` = package name). Child markers are
    not modified; the package may remain non-actionable
    (`no_actionable_tracks`). Restoring a maintained package reactivates
    the retained maintainer visibility without external I/O.
    """
    return await _change_package_marker(
        db,
        _MarkerDirection.RESTORE,
        ticket_id=ticket_id,
        package_id=package_id,
        acting_user_id=acting_user_id,
        caller=caller,
        evaluation_date=evaluation_date,
    )


async def soft_delete_ticket_package_track(
    db: AsyncSession,
    *,
    ticket_id: uuid.UUID,
    package_id: uuid.UUID,
    track_id: uuid.UUID,
    acting_user_id: uuid.UUID,
    caller: TicketCaller,
    evaluation_date: date | None = None,
) -> MarkerChangeResult[TrackMarkerProjection]:
    """Directly exclude one `TicketPackageTrack` (sets only its marker).

    Same contract as `soft_delete_ticket_package()` with the
    Ticket/package/track locator (`TrackNotFoundError` for a missing or
    mismatched track). The event is `track_excluded` (`old_value` = track
    reference, `detail = {track, package}`). Valid beneath an excluded
    package; Product markers are not modified and maintainer visibility
    is unaffected.
    """
    return await _change_track_marker(
        db,
        _MarkerDirection.EXCLUDE,
        ticket_id=ticket_id,
        package_id=package_id,
        track_id=track_id,
        acting_user_id=acting_user_id,
        caller=caller,
        evaluation_date=evaluation_date,
    )


async def restore_ticket_package_track(
    db: AsyncSession,
    *,
    ticket_id: uuid.UUID,
    package_id: uuid.UUID,
    track_id: uuid.UUID,
    acting_user_id: uuid.UUID,
    caller: TicketCaller,
    evaluation_date: date | None = None,
) -> MarkerChangeResult[TrackMarkerProjection]:
    """Restore one directly excluded `TicketPackageTrack`.

    Same contract as `soft_delete_ticket_package_track()` with the
    restore guard (`PackageNotExcludedError`) and the `track_restored`
    event (`new_value` = track reference, `detail = {track, package}`).
    Valid beneath an excluded package; the track may remain
    non-actionable.
    """
    return await _change_track_marker(
        db,
        _MarkerDirection.RESTORE,
        ticket_id=ticket_id,
        package_id=package_id,
        track_id=track_id,
        acting_user_id=acting_user_id,
        caller=caller,
        evaluation_date=evaluation_date,
    )


async def soft_delete_ticket_package_product(
    db: AsyncSession,
    *,
    ticket_id: uuid.UUID,
    package_id: uuid.UUID,
    track_id: uuid.UUID,
    ticket_package_product_id: uuid.UUID,
    acting_user_id: uuid.UUID,
    caller: TicketCaller,
    evaluation_date: date | None = None,
) -> MarkerChangeResult[ProductMarkerProjection]:
    """Directly exclude one `TicketPackageProduct` occurrence.

    Same contract as `soft_delete_ticket_package()` with the complete
    Ticket/package/track/occurrence locator (`ProductNotFoundError` for a
    missing or mismatched occurrence; a catalog `Product.id` never
    resolves). The event is `product_excluded` (`old_value` =
    `Product.display_name`, `detail` = event-time `{track, package,
    product_name, product_cpe}`). Valid beneath an excluded ancestor and
    on an EOL Product.
    """
    return await _change_product_marker(
        db,
        _MarkerDirection.EXCLUDE,
        ticket_id=ticket_id,
        package_id=package_id,
        track_id=track_id,
        ticket_package_product_id=ticket_package_product_id,
        acting_user_id=acting_user_id,
        caller=caller,
        evaluation_date=evaluation_date,
    )


async def restore_ticket_package_product(
    db: AsyncSession,
    *,
    ticket_id: uuid.UUID,
    package_id: uuid.UUID,
    track_id: uuid.UUID,
    ticket_package_product_id: uuid.UUID,
    acting_user_id: uuid.UUID,
    caller: TicketCaller,
    evaluation_date: date | None = None,
) -> MarkerChangeResult[ProductMarkerProjection]:
    """Restore one directly excluded `TicketPackageProduct` occurrence.

    Same contract as `soft_delete_ticket_package_product()` with the
    restore guard (`PackageNotExcludedError`) and the `product_restored`
    event (`new_value` = `Product.display_name`). No ancestor or
    lifecycle pre-check; the Product may remain non-actionable (for
    example `eol`).
    """
    return await _change_product_marker(
        db,
        _MarkerDirection.RESTORE,
        ticket_id=ticket_id,
        package_id=package_id,
        track_id=track_id,
        ticket_package_product_id=ticket_package_product_id,
        acting_user_id=acting_user_id,
        caller=caller,
        evaluation_date=evaluation_date,
    )
