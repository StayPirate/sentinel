"""Maintainer workbench candidate set, classification, and projection.

Shared statement builder of the four `package_service` maintainer
workbench queries (`docs/features/packages/package-service.md`, Maintainer
workbench queries). `docs/features/packages/maintainer.md` owns the
contract: ownership, the workbench row and privacy contract, the three
classifications, the global-list query contract, and the per-Ticket
aggregate.

One candidate row is one exact `TicketPackageTrack`. Every candidate
independently satisfies:

1. the canonical Ticket visibility predicate
   (`ticket_visibility_condition()`) on the row's Ticket; and
2. caller ownership: a `TicketPackageMaintainer` association of the
   caller on the row's own parent `TicketPackage`, whose
   `deleted_at IS NULL`.

Classification uses the canonical actionability expressions of
`app.services.package_actionability` with one UTC `evaluation_date`.
Ownership and the actionable-eligible-Product check use existence
semantics, so neither maintainer associations nor Products can fan out a
track row or inflate a count. Combining affectedness, eligibility,
actionability, and delivery here is the read-only workbench presentation
gate (`docs/features/packages/package-model.md`, Three Orthogonal
Dimensions); nothing is derived or mutated.

The projection is exactly the ten workbench item fields. The submission
deadline fields reuse the SQL twins of the deadline pure functions
(`app.services.ticket_deadline_expressions`) with the response's one
evaluation instant. Maintainer identities, Ticket UUIDs, and SMELT data
are never selected into an item.

Every builder is Category B: it performs no I/O, write, audit, or lock.
This module imports only Models, Core, and leaf service modules, so
`package_service` composes it without a dependency cycle; the caller
executes each statement once, so rows, totals, and per-Ticket
collections come from one PostgreSQL observation.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import date, datetime
from enum import StrEnum
from typing import Any, Final

from sqlalchemy import (
    ColumnElement,
    Select,
    and_,
    case,
    exists,
    func,
    literal,
    null,
    select,
    true,
)
from sqlalchemy.engine import Row
from sqlalchemy.orm import aliased

from app.core.enums import (
    DeliveryStatus,
    MaintainerWorkSortField,
    MilestonePhase,
    MilestoneStatus,
    PackageStatus,
    Severity,
    SortOrder,
    TicketStatus,
    WorkflowType,
)
from app.core.identifiers import format_ticket_id
from app.models.cve import CVE
from app.models.product import Product
from app.models.ticket import Ticket
from app.models.ticket_package import TicketPackage
from app.models.ticket_package_maintainer import TicketPackageMaintainer
from app.models.ticket_package_product import TicketPackageProduct
from app.models.ticket_package_track import TicketPackageTrack
from app.services.package_actionability import (
    product_actionable_expression,
    track_actionable_expression,
)
from app.services.ticket_deadline_expressions import (
    ticket_due_date_expressions,
    track_milestone_status_expression,
)
from app.services.ticket_severity import (
    resolved_severity_expression,
    severity_rank_expression,
)
from app.services.ticket_visibility import TicketCaller, ticket_visibility_condition

_CODE_POINT_COLLATION: Final = "C"


class WorkbenchClassification(StrEnum):
    """The three workbench classifications (maintainer.md, Classification).

    Internal classification only: never persisted and not an API value.
    """

    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"


# Ticket statuses admitted to each classification (maintainer.md, Ticket
# Status and Workflow Boundaries): pending and in-progress rows require an
# active gate-zone Ticket; `Resolved` contributes completed rows only.
_ACTIVE_GATE_ZONE_STATUSES: Final = (
    TicketStatus.ANALYSIS.value,
    TicketStatus.ANALYZED.value,
)
_COMPLETED_STATUSES: Final = (*_ACTIVE_GATE_ZONE_STATUSES, TicketStatus.RESOLVED.value)
_IN_PROGRESS_AFFECTEDNESS: Final = (
    PackageStatus.AFFECTED.value,
    PackageStatus.FIXED.value,
)


# ---------------------------------------------------------------------------
# Semantic results
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class MaintainerWorkItem:
    """One workbench item: one exact caller-owned `TicketPackageTrack`.

    `ticket_id` is the canonical `SNTL-{n}` identity; the internal Ticket
    and track UUIDs are never part of the item. `severity` is the resolved
    Ticket severity (`None` is SQL `NULL`, unresolved; `Severity.NONE` is
    the resolved `None` label). `submission_due_at` and
    `submission_milestone` are the track's submission deadline and
    milestone status (ticket-deadlines.md), `None` when no SLA applies or
    the phase is unobservable.
    """

    package_name: str
    ticket_id: str
    cve_id: str | None
    severity: Severity | None
    workflow_type: WorkflowType
    reference: str
    status: PackageStatus
    delivery_status: DeliveryStatus
    submission_due_at: datetime | None
    submission_milestone: MilestoneStatus | None


@dataclass(frozen=True, slots=True)
class MaintainerWorkPage:
    """One page of a workbench global list and the total of its candidates."""

    items: tuple[MaintainerWorkItem, ...]
    total: int
    page: int
    per_page: int


@dataclass(frozen=True, slots=True)
class MaintainerTicketWork:
    """The caller's classified work on one accessible Ticket.

    Each collection is in ascending code-point order of `package_name`,
    then `reference`, then the internal track UUID. An item appears in at
    most one collection.
    """

    pending: tuple[MaintainerWorkItem, ...]
    in_progress: tuple[MaintainerWorkItem, ...]
    completed: tuple[MaintainerWorkItem, ...]


# ---------------------------------------------------------------------------
# Candidate predicates
# ---------------------------------------------------------------------------


def caller_owns_package_condition(caller_user_id: uuid.UUID) -> ColumnElement[bool]:
    """Build the caller-ownership predicate on the enclosing `TicketPackage`.

    True exactly when the package is included (`deleted_at IS NULL`) and
    has a persisted `TicketPackageMaintainer` association for
    `caller_user_id` (maintainer.md, User Identification and Ownership).
    The association check uses existence semantics, so several
    associations never multiply the enclosing row. Raises no exception.
    """
    has_association = exists(
        select(TicketPackageMaintainer.id).where(
            TicketPackageMaintainer.ticket_package_id == TicketPackage.id,
            TicketPackageMaintainer.user_id == caller_user_id,
        )
    ).correlate(TicketPackage)
    return and_(TicketPackage.deleted_at.is_(None), has_association)


def _has_actionable_eligible_product(evaluation_date: date) -> ColumnElement[bool]:
    """At least one actionable Product occurrence below the enclosing track
    has persisted `eligible = true`, by existence semantics."""
    occurrence = aliased(TicketPackageProduct)
    catalog = aliased(Product)
    return exists(
        select(occurrence.id)
        .join(catalog, catalog.id == occurrence.product_id)
        .where(
            occurrence.ticket_package_track_id == TicketPackageTrack.id,
            occurrence.eligible.is_(True),
            product_actionable_expression(
                evaluation_date, product=occurrence, catalog_product=catalog
            ),
        )
        .correlate_except(occurrence, catalog)
    )


def classification_condition(
    classification: WorkbenchClassification, evaluation_date: date
) -> ColumnElement[bool]:
    """Build the exact classification predicate of the enclosing track.

    The enclosing statement joins `TicketPackageTrack`, its parent
    `TicketPackage`, and that package's `Ticket`. Implements
    maintainer.md (Pending, In Progress, Completed) with the canonical
    track actionability on `evaluation_date`. Completed requires no
    eligible Product. Raises no exception.
    """
    track = TicketPackageTrack
    actionable = track_actionable_expression(evaluation_date)
    if classification is WorkbenchClassification.COMPLETED:
        return and_(
            Ticket.status.in_(_COMPLETED_STATUSES),
            track.delivery_status == DeliveryStatus.RELEASED.value,
            actionable,
        )
    if classification is WorkbenchClassification.PENDING:
        affectedness = track.status == PackageStatus.AFFECTED.value
        delivery = DeliveryStatus.PENDING
    else:
        affectedness = track.status.in_(_IN_PROGRESS_AFFECTEDNESS)
        delivery = DeliveryStatus.IN_PROGRESS
    return and_(
        Ticket.status.in_(_ACTIVE_GATE_ZONE_STATUSES),
        affectedness,
        track.delivery_status == delivery.value,
        actionable,
        _has_actionable_eligible_product(evaluation_date),
    )


def classification_expression(evaluation_date: date) -> ColumnElement[str | None]:
    """Build the classification of the enclosing track as a value.

    Yields the `WorkbenchClassification` value whose predicate holds, or
    NULL when the track satisfies none. The predicates are mutually
    exclusive because each requires a distinct persisted delivery status.
    """
    expression: ColumnElement[str | None] = case(
        *(
            (
                classification_condition(classification, evaluation_date),
                literal(classification.value),
            )
            for classification in WorkbenchClassification
        ),
        else_=null(),
    )
    return expression


# ---------------------------------------------------------------------------
# Projection
# ---------------------------------------------------------------------------


def _cve_identifier() -> ColumnElement[str | None]:
    """The associated CVE identifier of the enclosing `Ticket`, or NULL."""
    return (
        select(CVE.cve_id)
        .where(CVE.id == Ticket.cve_id)
        .correlate(Ticket)
        .scalar_subquery()
    )


def _track_columns(
    *, evaluation_date: date, evaluation_instant: datetime
) -> tuple[ColumnElement[Any], ...]:
    """The track-level item columns, labeled for `item_from_row()`.

    `submission_milestone` is the `submission` milestone status of the
    enclosing track on the response's one instant (ticket-deadlines.md,
    Track Milestones).
    """
    due = ticket_due_date_expressions(severity=resolved_severity_expression())
    return (
        TicketPackage.package_name.label("package_name"),
        TicketPackageTrack.workflow_type.label("workflow_type"),
        TicketPackageTrack.reference.label("reference"),
        TicketPackageTrack.status.label("track_status"),
        TicketPackageTrack.delivery_status.label("delivery_status"),
        track_milestone_status_expression(
            MilestonePhase.SUBMISSION,
            evaluation_date=evaluation_date,
            evaluation_instant=evaluation_instant,
            due_dates=due,
        ).label("submission_milestone"),
    )


def _ticket_columns() -> tuple[ColumnElement[Any], ...]:
    """The Ticket-level item columns, labeled for `item_from_row()`.

    Severity is resolved once and reused by the submission due date.
    """
    severity = resolved_severity_expression()
    due = ticket_due_date_expressions(severity=severity)
    return (
        Ticket.sequence_id.label("sequence_id"),
        _cve_identifier().label("cve_id"),
        severity.label("severity"),
        due.submission.label("submission_due_at"),
    )


def item_from_row(row: Row[Any]) -> MaintainerWorkItem:
    """Assemble one workbench item from a workbench statement row. Pure."""
    return MaintainerWorkItem(
        package_name=row.package_name,
        ticket_id=format_ticket_id(row.sequence_id),
        cve_id=row.cve_id,
        severity=Severity(row.severity) if row.severity is not None else None,
        workflow_type=WorkflowType(row.workflow_type),
        reference=row.reference,
        status=PackageStatus(row.track_status),
        delivery_status=DeliveryStatus(row.delivery_status),
        submission_due_at=row.submission_due_at,
        submission_milestone=(
            MilestoneStatus(row.submission_milestone)
            if row.submission_milestone is not None
            else None
        ),
    )


# ---------------------------------------------------------------------------
# Statements
# ---------------------------------------------------------------------------


def _sort_key(sort_by: MaintainerWorkSortField) -> ColumnElement[Any]:
    """The primary sort key of the enclosing track row."""
    if sort_by is MaintainerWorkSortField.SEVERITY:
        return severity_rank_expression(resolved_severity_expression())
    if sort_by is MaintainerWorkSortField.PACKAGE:
        return TicketPackage.package_name.expression
    return ticket_due_date_expressions().submission


def _ordered(
    sort_key: ColumnElement[Any],
    track_id: ColumnElement[Any],
    *,
    sort_by: MaintainerWorkSortField,
    sort_order: SortOrder,
) -> tuple[ColumnElement[Any], ColumnElement[Any]]:
    """Primary order with `NULL` last in both directions, then the internal
    `TicketPackageTrack.id` tie-breaker in the same direction. `package`
    compares by Unicode code point (`COLLATE "C"`)."""
    key = (
        sort_key.collate(_CODE_POINT_COLLATION)
        if sort_by is MaintainerWorkSortField.PACKAGE
        else sort_key
    )
    if sort_order is SortOrder.ASC:
        return key.asc().nulls_last(), track_id.asc()
    return key.desc().nulls_last(), track_id.desc()


def global_list_statement(
    classification: WorkbenchClassification,
    *,
    caller: TicketCaller,
    caller_user_id: uuid.UUID,
    evaluation_date: date,
    evaluation_instant: datetime,
    package: str | None,
    sort_by: MaintainerWorkSortField,
    sort_order: SortOrder,
    page: int,
    per_page: int,
) -> Select[Any]:
    """Build the one statement of a workbench global list.

    A CTE chain over one candidate set: the visible, caller-owned,
    classification-qualified tracks with their sort key (`filtered`),
    their count (`total`), and the requested slice (`page`). The final
    select starts from `total` and outer-joins the slice, so it always
    returns at least one row carrying the total, and a row with a NULL
    `track_pk` stands for an empty page. `package` is a case-sensitive
    exact match composed with AND. Raises no exception.
    """
    conditions: list[ColumnElement[bool]] = [
        ticket_visibility_condition(caller),
        caller_owns_package_condition(caller_user_id),
        classification_condition(classification, evaluation_date),
    ]
    if package is not None:
        conditions.append(TicketPackage.package_name == package)
    filtered = (
        select(
            TicketPackageTrack.id.label("id"),
            _sort_key(sort_by).label("sort_key"),
        )
        .join(TicketPackage, TicketPackage.id == TicketPackageTrack.ticket_package_id)
        .join(Ticket, Ticket.id == TicketPackage.ticket_id)
        .where(*conditions)
        .cte("filtered")
    )
    total = select(func.count().label("total")).select_from(filtered).cte("total")
    page_rows = (
        select(filtered)
        .order_by(
            *_ordered(
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
    return (
        select(
            total.c.total,
            TicketPackageTrack.id.label("track_pk"),
            *_ticket_columns(),
            *_track_columns(
                evaluation_date=evaluation_date,
                evaluation_instant=evaluation_instant,
            ),
        )
        .select_from(total)
        .outerjoin(page_rows, true())
        .outerjoin(TicketPackageTrack, TicketPackageTrack.id == page_rows.c.id)
        .outerjoin(
            TicketPackage, TicketPackage.id == TicketPackageTrack.ticket_package_id
        )
        .outerjoin(Ticket, Ticket.id == TicketPackage.ticket_id)
        .order_by(
            *_ordered(
                page_rows.c.sort_key,
                page_rows.c.id,
                sort_by=sort_by,
                sort_order=sort_order,
            )
        )
    )


def ticket_work_statement(
    *,
    sequence_id: int,
    caller: TicketCaller,
    caller_user_id: uuid.UUID,
    evaluation_date: date,
    evaluation_instant: datetime,
) -> Select[Any]:
    """Build the one statement of the per-Ticket workbench aggregate.

    Selects the Ticket by `sequence_id` under the canonical visibility
    predicate and, through a lateral outer join correlated to that
    selected Ticket only, its caller-owned classified tracks with their
    classification. No row means a missing or inaccessible Ticket; one
    row with a NULL `track_pk` means an accessible Ticket without
    qualifying caller work. Rows are in ascending code-point order of
    `package_name`, then `reference`, then track UUID. Raises no
    exception.
    """
    classification = classification_expression(evaluation_date)
    work = (
        select(
            TicketPackageTrack.id.label("track_pk"),
            classification.label("classification"),
            *_track_columns(
                evaluation_date=evaluation_date,
                evaluation_instant=evaluation_instant,
            ),
        )
        .join(TicketPackage, TicketPackage.id == TicketPackageTrack.ticket_package_id)
        .where(
            TicketPackage.ticket_id == Ticket.id,
            caller_owns_package_condition(caller_user_id),
            classification.is_not(None),
        )
        .correlate(Ticket)
        .lateral("work")
    )
    return (
        select(*_ticket_columns(), *work.c)
        .select_from(Ticket)
        .outerjoin(work, true())
        .where(Ticket.sequence_id == sequence_id, ticket_visibility_condition(caller))
        .order_by(
            work.c.package_name.collate(_CODE_POINT_COLLATION).asc(),
            work.c.reference.collate(_CODE_POINT_COLLATION).asc(),
            work.c.track_pk.asc(),
        )
    )
