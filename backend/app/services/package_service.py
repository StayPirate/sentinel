"""Package-centric operations: package-tree queries, eligibility, and mutations.

See `docs/features/packages/package-service.md` for the full
specification. This module currently implements the package-tree query
(Query Operations > `get_ticket_packages()`) in its standalone consumer
mode and its composed mode, the synchronous manual-zone-exit
eligibility convergence (`converge_manual_zone_exit_eligibility()`),
which `ticket_service` composes with an already locked Ticket, and the
package mutation foundation (`PackageServiceError` hierarchy, the
explicit system invocation context, the locked semantic-locator loader)
with its first mutation, `set_track_status()`; the remaining mutation,
orchestration, and search operations are added by their owning work
items. This module never imports `ticket_service`; it consumes the
`ticket_mutations` primitives, which never import it back.

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
from enum import Enum, StrEnum
from typing import Any, Final

import structlog
from sqlalchemy import (
    ColumnElement,
    SQLColumnExpression,
    and_,
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
    LifecyclePhase,
    NonActionableReason,
    PackageStatus,
    Severity,
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
from app.models.ticket_package_product import TicketPackageProduct
from app.models.ticket_package_track import TicketPackageTrack
from app.services import settings as settings_service
from app.services.cvss import resolve_eligibility_score
from app.services.package_actionability import (
    is_delivery_relevant,
    package_actionable_expression,
    package_non_actionable_reason,
    product_actionable_expression,
    product_non_actionable_reason,
    track_actionable_expression,
    track_non_actionable_reason,
)
from app.services.product_eligibility import evaluate_product_eligibility
from app.services.product_service import lifecycle_phase_expression
from app.services.ticket_audit_log import TicketAuditLog
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
# Synchronous manual-zone-exit eligibility convergence
# ---------------------------------------------------------------------------

_REACTIVATION_REASON: Final = "reactivation"


@dataclass(frozen=True, slots=True)
class ManualZoneExitEligibilityResult:
    """Occurrence counts of one manual-zone-exit eligibility convergence."""

    examined: int
    override_skipped: int
    changed: int


def _eligibility_value(eligible: bool) -> str:
    """The `product_eligibility_changed` old/new value (`true`/`false`)."""
    return "true" if eligible else "false"


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

    default_cvss_version = await settings_service.get_default_cvss_version(db)
    assessments: Sequence[CVECVSSAssessment] = ()
    if ticket.cve_id is not None:
        assessments = (
            (
                await db.execute(
                    select(CVECVSSAssessment).where(
                        CVECVSSAssessment.cve_id == ticket.cve_id
                    )
                )
            )
            .scalars()
            .all()
        )
    eligibility = resolve_eligibility_score(assessments, default_cvss_version)

    occurrence = TicketPackageProduct
    rows = (
        await db.execute(
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
            .join(
                TicketPackage, TicketPackage.id == TicketPackageTrack.ticket_package_id
            )
            .join(Product, Product.id == occurrence.product_id)
            .where(TicketPackage.ticket_id == ticket.id)
            .order_by(occurrence.id)
            .execution_options(populate_existing=True)
        )
    ).all()

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
                "reason": _REACTIVATION_REASON,
            },
        )
    await db.flush()
    return ManualZoneExitEligibilityResult(
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
