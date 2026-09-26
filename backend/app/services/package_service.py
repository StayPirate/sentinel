"""Package-centric operations: package-tree queries.

See `docs/features/packages/package-service.md` for the full
specification. This module currently implements the package-tree query
(Query Operations > `get_ticket_packages()`) in its standalone consumer
mode and its composed mode; mutation, orchestration, and search
operations are added by their owning work items.

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
"""

from __future__ import annotations

import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, date, datetime
from typing import Any, Final

from sqlalchemy import (
    ColumnElement,
    SQLColumnExpression,
    exists,
    func,
    literal_column,
    select,
    type_coerce,
)
from sqlalchemy.dialects.postgresql import JSON, aggregate_order_by
from sqlalchemy.engine import Row
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm.util import AliasedClass

from app.core.enums import (
    DeliveryStatus,
    IBSRequestActionType,
    IBSRequestState,
    LifecyclePhase,
    NonActionableReason,
    PackageStatus,
    Severity,
    TicketStatus,
    WorkflowType,
)
from app.core.exceptions import TicketNotFoundError
from app.core.identifiers import parse_ticket_id
from app.models.ibs_request import IBSRequest
from app.models.ibs_request_action import IBSRequestAction
from app.models.ibs_request_action_track import IBSRequestActionTrack
from app.models.product import Product
from app.models.ticket import Ticket
from app.models.ticket_package import TicketPackage
from app.models.ticket_package_product import TicketPackageProduct
from app.models.ticket_package_track import TicketPackageTrack
from app.services.package_actionability import (
    is_delivery_relevant,
    package_actionable_expression,
    package_non_actionable_reason,
    product_actionable_expression,
    product_non_actionable_reason,
    track_actionable_expression,
    track_non_actionable_reason,
)
from app.services.product_service import lifecycle_phase_expression
from app.services.ticket_deadlines import (
    DueDates,
    TrackMilestones,
    compute_due_dates,
    resolve_track_milestones,
)
from app.services.ticket_severity import resolved_severity_expression
from app.services.ticket_visibility import TicketCaller, ticket_visibility_condition

ACTIVE_RELEASE_REQUEST_STATES: Final = frozenset(
    {IBSRequestState.NEW, IBSRequestState.REVIEW, IBSRequestState.ACCEPTED}
)
"""`IBSRequest.state` values whose correlated `maintenance_release` action
is `um` completion evidence (ticket-deadlines.md, Completion Evidence)."""

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


def _has_active_release_request() -> ColumnElement[bool]:
    """Correlated `um` RR evidence of the enclosing `TicketPackageTrack`."""
    return exists(
        select(IBSRequestActionTrack.id)
        .join(
            IBSRequestAction,
            IBSRequestAction.id == IBSRequestActionTrack.ibs_request_action_id,
        )
        .join(IBSRequest, IBSRequest.id == IBSRequestAction.ibs_request_id)
        .where(
            IBSRequestActionTrack.ticket_package_track_id == TicketPackageTrack.id,
            IBSRequestAction.action_type
            == IBSRequestActionType.MAINTENANCE_RELEASE.value,
            IBSRequest.state.in_(
                sorted(state.value for state in ACTIVE_RELEASE_REQUEST_STATES)
            ),
        )
        .correlate_except(IBSRequestActionTrack, IBSRequestAction, IBSRequest)
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
        _has_active_release_request(),
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
