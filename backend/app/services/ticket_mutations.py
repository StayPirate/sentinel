"""Ticket mutation primitives shared by every Ticket-mutating service.

Implements, from `docs/features/tickets/ticket-mutations.md`:

- `ensure_ticket_operable()` — the manual-zone mutability guard;
- `stabilize_acting_user()` — the acting-User stabilization that every
  assignment-capable path performs before its CVE or Ticket lock
  (Concurrency Control > Extension to non-module operations;
  `docs/conventions.md`, Cross-Domain Root Lock Order);
- `auto_assign_actor()` — the Auto-Assignment Rule;
- `reconcile_ticket_status()` — the sole gate-zone status authority,
  including assignment-eligibility sanitation, the `previous_status`
  semantics, and transaction-local Ticket convergence registration.

The gates are exactly those of `docs/features/tickets/tickets.md` (Gate:
Analysis → Analyzed, Gate: Analyzed → Resolved) over the canonical
actionability expressions of `docs/features/packages/package-model.md`
(Derived Actionability, Gate Participation): the gates only observe
affectedness, eligibility, release, exclusion, and lifecycle and never
derive or persist any of them.

Transaction ownership: every function participates in the caller-owned
transaction. Nothing here commits or rolls back; audit events are created
through `TicketAuditLog.log_event()` and flushed in the same transaction.

Authorization: the module performs no capability check. API callers apply
`require_capability()` first; consumer operations revalidate Ticket
accessibility from locked-current roots before calling these primitives.

Dependency direction: this module never imports `package_service` or
`ticket_service` (ticket-mutations.md, Relationship with other modules);
both of them import these primitives. It re-exports the leaf
`ticket_mutations_errors` hierarchy.
"""

from __future__ import annotations

from datetime import UTC, date, datetime
from typing import Final
from uuid import UUID

import structlog
from sqlalchemy import ColumnElement, and_, exists, not_, or_, select
from sqlalchemy import inspect as sa_inspect
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import aliased, selectinload

from app.core.enums import (
    CVSSVersion,
    PackageStatus,
    Role,
    TicketAuditEventType,
    TicketStatus,
)
from app.core.exceptions import TicketNotMutableError, UserNotFoundError
from app.models.cve_cvss_assessment import CVECVSSAssessment
from app.models.product import Product
from app.models.ticket import Ticket
from app.models.ticket_package import TicketPackage
from app.models.ticket_package_product import TicketPackageProduct
from app.models.ticket_package_track import TicketPackageTrack
from app.models.user import User
from app.models.user_role import UserRole
from app.services.cvss import SUSE_PROVIDER_NAME
from app.services.package_actionability import (
    product_actionable_expression,
    track_actionable_expression,
)
from app.services.ticket_audit_log import TicketAuditLog
from app.services.ticket_convergence_registry import register_ticket_convergence
from app.services.ticket_mutations_errors import (
    InvalidCVSSVectorError,
    TicketMutationsError,
)
from app.services.ticket_severity import resolved_severity_expression

__all__ = [
    "INACTIVE_ASSIGNEE_REASON",
    "VA_ROLE_REMOVED_REASON",
    "InvalidCVSSVectorError",
    "TicketMutationsError",
    "TicketNotMutableError",
    "auto_assign_actor",
    "ensure_ticket_operable",
    "reconcile_ticket_status",
    "stabilize_acting_user",
]

logger = structlog.get_logger(__name__)

INACTIVE_ASSIGNEE_REASON: Final = "inactive assignee"
"""Sanitation reason for an inactive assignee (ticket-audit-log.md,
Canonical Automatic Comment Vocabulary); takes precedence."""

VA_ROLE_REMOVED_REASON: Final = "vulnerability_analyst role removed"
"""Sanitation reason for an active assignee without any VA origin."""

_MANUAL_ZONE: Final = frozenset({TicketStatus.IGNORED, TicketStatus.DUPLICATED})
_SANITIZED_RESULTS: Final = frozenset({TicketStatus.ANALYSIS, TicketStatus.ANALYZED})
_ACCEPTED_CVSS_VERSIONS: Final = tuple(version.value for version in CVSSVersion)


def _utc_now() -> datetime:
    """The current instant in UTC (patched by controlled-clock tests)."""
    return datetime.now(UTC)


# ---------------------------------------------------------------------------
# Mutability guard
# ---------------------------------------------------------------------------


def ensure_ticket_operable(ticket: Ticket) -> None:
    """Reject mutations on manual-zone inactive Tickets.

    Category B guard (ticket-mutations.md, `ensure_ticket_operable()`;
    tickets.md, Mutability Guard).

    Q1: `ticket` is already loaded by the caller with `SELECT ... FOR
    UPDATE`, after locked-current accessibility revalidation.

    Q3: inspects only the in-memory `ticket.status`; performs no database
    operation.

    Q4: returns `None` when the Ticket is operable.

    Q6: raises `TicketNotMutableError` exactly when the status is
    `Ignored` or `Duplicated`.
    """
    if ticket.status in _MANUAL_ZONE:
        raise TicketNotMutableError()


# ---------------------------------------------------------------------------
# Acting-User stabilization and auto-assignment
# ---------------------------------------------------------------------------


async def stabilize_acting_user(db: AsyncSession, user_id: UUID) -> User:
    """Lock the acting User `FOR SHARE` and load its current eligibility.

    Category A (acquires a row lock).

    Q1: `db` is the caller-owned session; `user_id` is the authenticated
    acting user's UUID. System callers have no acting User and never call
    this function.

    Q2: the caller invokes it before acquiring any CVE or Ticket lock
    (`docs/conventions.md`, Cross-Domain Root Lock Order) and retains the
    lock through the assignment decision and the Ticket mutation (until
    its transaction ends).

    Q3: selects the `User` row with `FOR SHARE`, refreshing any identity-
    map copy, then loads its current `UserRole` origins while holding that
    lock. `FOR SHARE` conflicts with the `FOR NO KEY UPDATE` taken by
    deactivation and role-origin removal, so `active` and the VA origins
    stay stable until the transaction ends. Creates no event.

    Q4: returns the locked `User` with `active`, `username`, and `roles`
    loaded; `auto_assign_actor()` reads them without any further query.

    Q6: raises `UserNotFoundError` when no User has `user_id` (an
    invariant violation for an authenticated caller). Database exceptions
    propagate unchanged.
    """
    statement = (
        select(User)
        .where(User.id == user_id)
        .options(selectinload(User.roles))
        .with_for_update(read=True)
        .execution_options(populate_existing=True)
    )
    user = (await db.execute(statement)).scalar_one_or_none()
    if user is None:
        raise UserNotFoundError()
    return user


def _is_stabilized_vulnerability_analyst(user: User) -> bool:
    """Whether the stabilized `user` currently holds any VA origin.

    Reads the roles loaded by `stabilize_acting_user()`; raises
    `ValueError` if they are not loaded, because loading them here would
    be a User query under the Ticket lock.
    """
    if "roles" in sa_inspect(user).unloaded:
        raise ValueError(
            "acting_user must be stabilized with stabilize_acting_user() "
            "before the Ticket lock."
        )
    return any(role.role == Role.VULNERABILITY_ANALYST for role in user.roles)


async def auto_assign_actor(
    ticket: Ticket,
    acting_user: User | None,
    db: AsyncSession,
    force: bool = False,
) -> bool:
    """Assign `ticket` to the acting user if that user is an active VA.

    Category A (ticket-mutations.md, Auto-Assignment Rule and
    `auto_assign_actor()`).

    Q1: `ticket` is locked `FOR UPDATE` by the caller; `acting_user` is
    the User returned by `stabilize_acting_user()` before the Ticket lock,
    or `None` for a system action. `force=True` is reserved for the
    `ticket_service` manual-zone exits (`reopen_from_ignored`,
    `revert_duplicate`); every other caller must pass `False`.

    Q2: the caller holds the acting User `FOR SHARE` lock and the Ticket
    `FOR UPDATE` lock.

    Q3: in order — a system actor, an already-assigned Ticket (unless
    `force`), an inactive locked User or one without any current VA
    origin, and an unchanged assignee return `False` with no effect.
    Otherwise sets `assignee_id`, creates one `assignment` event
    attributed to the acting user (`old_value` the previous assignee's
    event-time username or `NULL`, `new_value` the acting username,
    `comment NULL`), and, when the Ticket is `New`, sets `Analysis` and
    creates the system `status_change` `New → Analysis`. The acting
    User's eligibility is read from the stabilized instance without any
    query. The only other read is, for `force=True` replacing a different
    assignee, one unlocked observation of that previous assignee's
    username for `old_value`. Never calls `reconcile_ticket_status()`; the
    caller must reconcile after completing its mutations.

    Q4: returns `True` when the assignment was applied, otherwise `False`.

    Q6: raises `ValueError` when `acting_user` was not stabilized (roles
    not loaded). Audit validation and database exceptions propagate and
    roll back the caller's transaction.
    """
    if acting_user is None:
        return False
    if not force and ticket.assignee_id is not None:
        return False
    if not acting_user.active or not _is_stabilized_vulnerability_analyst(acting_user):
        return False
    if ticket.assignee_id == acting_user.id:
        return False

    previous_username: str | None = None
    if ticket.assignee_id is not None:
        previous_username = (
            await db.execute(select(User.username).where(User.id == ticket.assignee_id))
        ).scalar_one()

    ticket.assignee_id = acting_user.id
    await TicketAuditLog.log_event(
        db,
        ticket_id=ticket.id,
        event_type=TicketAuditEventType.ASSIGNMENT,
        user_id=acting_user.id,
        old_value=previous_username,
        new_value=acting_user.username,
    )
    if ticket.status == TicketStatus.NEW:
        ticket.status = TicketStatus.ANALYSIS.value
        await TicketAuditLog.log_event(
            db,
            ticket_id=ticket.id,
            event_type=TicketAuditEventType.STATUS_CHANGE,
            user_id=None,
            old_value=TicketStatus.NEW.value,
            new_value=TicketStatus.ANALYSIS.value,
        )
    return True


# ---------------------------------------------------------------------------
# Gate predicates (tickets.md, Gate: Analysis → Analyzed / Analyzed → Resolved)
# ---------------------------------------------------------------------------


def _has_manually_included_track(ticket_id: UUID) -> ColumnElement[bool]:
    """`|M| >= 1`: a track whose own and package markers are both NULL."""
    return exists(
        select(TicketPackageTrack.id)
        .join(TicketPackage, TicketPackage.id == TicketPackageTrack.ticket_package_id)
        .where(
            TicketPackage.ticket_id == ticket_id,
            TicketPackage.deleted_at.is_(None),
            TicketPackageTrack.deleted_at.is_(None),
        )
    )


def _actionable_track_condition(
    ticket_id: UUID, evaluation_date: date
) -> ColumnElement[bool]:
    """Select the Ticket's actionable tracks `A` (`TicketPackageTrack` joined
    to its `TicketPackage`)."""
    return and_(
        TicketPackage.ticket_id == ticket_id,
        track_actionable_expression(evaluation_date),
    )


def _has_actionable_analysis_track(
    ticket_id: UUID, evaluation_date: date
) -> ColumnElement[bool]:
    """Some track in `A` has affectedness `ANALYSIS`."""
    return exists(
        select(TicketPackageTrack.id)
        .join(TicketPackage, TicketPackage.id == TicketPackageTrack.ticket_package_id)
        .where(
            _actionable_track_condition(ticket_id, evaluation_date),
            TicketPackageTrack.status == PackageStatus.ANALYSIS.value,
        )
    )


def _has_canonical_suse_assessment() -> ColumnElement[bool]:
    """A canonical `SUSE` assessment of the Ticket's CVE in an accepted version."""
    return exists(
        select(CVECVSSAssessment.id).where(
            CVECVSSAssessment.cve_id == Ticket.cve_id,
            CVECVSSAssessment.provider_name == SUSE_PROVIDER_NAME,
            CVECVSSAssessment.cvss_version.in_(_ACCEPTED_CVSS_VERSIONS),
        )
    ).correlate(Ticket)


def _has_incomplete_actionable_track(
    ticket_id: UUID, evaluation_date: date
) -> ColumnElement[bool]:
    """Some track in `A` is not resolution-complete.

    A track `t` is resolution-complete when (a) its status is
    `NOT_AFFECTED` or `WONT_FIX`; (b) it is `FIXED` and the Ticket has no
    CVE or every Product in `AEP(t)` has `released_at`; or (c) it is
    `AFFECTED` and `AEP(t)` is empty. `AEP(t)` is the set of actionable
    Products of `t` whose persisted `eligible` is true.
    """
    track = TicketPackageTrack
    occurrence = aliased(TicketPackageProduct)
    catalog = aliased(Product)

    def _aep(*conditions: ColumnElement[bool]) -> ColumnElement[bool]:
        return exists(
            select(occurrence.id)
            .join(catalog, catalog.id == occurrence.product_id)
            .where(
                occurrence.ticket_package_track_id == track.id,
                occurrence.eligible.is_(True),
                product_actionable_expression(
                    evaluation_date, product=occurrence, catalog_product=catalog
                ),
                *conditions,
            )
            .correlate_except(occurrence, catalog)
        )

    resolution_complete = or_(
        track.status.in_(
            (PackageStatus.NOT_AFFECTED.value, PackageStatus.WONT_FIX.value)
        ),
        and_(
            track.status == PackageStatus.FIXED.value,
            or_(
                Ticket.cve_id.is_(None),
                not_(_aep(occurrence.released_at.is_(None))),
            ),
        ),
        and_(track.status == PackageStatus.AFFECTED.value, not_(_aep())),
    )
    return exists(
        select(track.id)
        .join(TicketPackage, TicketPackage.id == track.ticket_package_id)
        .where(
            _actionable_track_condition(ticket_id, evaluation_date),
            not_(resolution_complete),
        )
        .correlate(Ticket)
    )


async def _evaluate_gate_status(
    db: AsyncSession, ticket_id: UUID, evaluation_date: date
) -> TicketStatus:
    """Evaluate the highest valid gate-zone status in one SQL statement.

    Every clause uses the same `evaluation_date`; nothing is persisted.
    """
    analyzed = and_(
        _has_manually_included_track(ticket_id),
        not_(_has_actionable_analysis_track(ticket_id, evaluation_date)),
        resolved_severity_expression(Ticket).is_not(None),
        or_(Ticket.cve_id.is_(None), _has_canonical_suse_assessment()),
    ).label("analyzed")
    resolution_complete = not_(
        _has_incomplete_actionable_track(ticket_id, evaluation_date)
    ).label("resolution_complete")
    row = (
        await db.execute(
            select(analyzed, resolution_complete).where(Ticket.id == ticket_id)
        )
    ).one()
    if not row.analyzed:
        return TicketStatus.ANALYSIS
    if row.resolution_complete:
        return TicketStatus.RESOLVED
    return TicketStatus.ANALYZED


# ---------------------------------------------------------------------------
# Status reconciliation
# ---------------------------------------------------------------------------


async def _sanitize_assignment(db: AsyncSession, ticket: Ticket) -> None:
    """Assignment Eligibility Sanitization (ticket-mutations.md).

    A fresh, unlocked observation of the current assignee's `active`
    value and VA origins; audit history is never read.
    """
    if ticket.assignee_id is None:
        return
    has_va_origin = exists(
        select(UserRole.id).where(
            UserRole.user_id == User.id,
            UserRole.role == Role.VULNERABILITY_ANALYST.value,
        )
    ).correlate(User)
    assignee = (
        await db.execute(
            select(
                User.id, User.username, User.active, has_va_origin.label("va")
            ).where(User.id == ticket.assignee_id)
        )
    ).one()
    if not assignee.active:
        reason = INACTIVE_ASSIGNEE_REASON
    elif not assignee.va:
        reason = VA_ROLE_REMOVED_REASON
    else:
        return

    ticket.assignee_id = None
    await TicketAuditLog.log_event(
        db,
        ticket_id=ticket.id,
        event_type=TicketAuditEventType.ASSIGNMENT,
        user_id=None,
        old_value=assignee.username,
        new_value=None,
        comment=f"Unassigned from {assignee.username}: {reason}",
    )
    logger.warning(
        "ticket_assignee_sanitized",
        ticket_id=str(ticket.id),
        user_id=str(assignee.id),
        reason=reason,
    )


def _registers_convergence(
    effective_previous: TicketStatus, new_status: TicketStatus
) -> bool:
    """Step 5: a manual-zone exit or a `Resolved` regression."""
    if effective_previous in _MANUAL_ZONE:
        return True
    return (
        effective_previous is TicketStatus.RESOLVED and new_status in _SANITIZED_RESULTS
    )


async def reconcile_ticket_status(
    ticket: Ticket,
    db: AsyncSession,
    previous_status: TicketStatus | None = None,
    evaluation_date: date | None = None,
) -> None:
    """Reconcile the Ticket's status and assignment with current reality.

    Category A (ticket-mutations.md, `reconcile_ticket_status()`;
    tickets.md, Automatic Status Evaluation). A service-internal
    primitive: owning mutation services call it after their effective
    gate-relevant mutations; entry points never call it directly.

    Q1: `ticket` is locked `FOR UPDATE` by the caller (a workflow that
    also owns a CVE lock acquired it first). `previous_status`, when
    supplied by a manual-zone exit, is the preserved source status used
    as the status event's `old_value` and for convergence registration.
    `evaluation_date` is the workflow's UTC date; when omitted, one UTC
    date is captured at entry.

    Q2: acquires no lock and never acquires or re-acquires a CVE lock; it
    only reads `CVE.severity` and assessments under the caller's locks.

    Q3: (1) a `New` Ticket returns immediately, logging a warning when it
    has an assignee. (2) In one SQL statement for one `evaluation_date`,
    evaluates the Analyzed predicate (at least one manually included
    track; no actionable `ANALYSIS` track; resolved severity not NULL;
    for a Ticket with a CVE, a canonical `SUSE` assessment in an accepted
    version) and universal resolution completeness over actionable
    tracks; the result is `Resolved`, `Analyzed`, or the `Analysis`
    floor. (3) For an `Analysis` or `Analyzed` result, clears an
    inactive or non-VA assignee with one system `assignment` event
    (`Unassigned from {username}: {reason}`, `inactive assignee`
    preferred) and a warning log; a `Resolved` result retains the
    assignee. (4) When the result differs from the current status, or
    `previous_status` is supplied and differs from the result, sets the
    status and creates one system `status_change` whose `old_value` is
    `previous_status` or the current status. (5) Independently of (4),
    registers one transaction-local Ticket convergence effect when the
    effective previous status (`previous_status`, else the status at
    entry) is `Ignored` or `Duplicated`, or is `Resolved` and the result
    is `Analysis` or `Analyzed`. Never persists lifecycle or
    actionability, never publishes, and never commits.

    Q4: returns `None`; the outcome is the Ticket's in-memory and flushed
    state.

    Q6: raises `ValueError` when the Ticket is still `Ignored` or
    `Duplicated` (the function never operates on the manual zone).
    Audit validation and database exceptions propagate and roll back the
    caller's transaction.
    """
    current = TicketStatus(ticket.status)
    if current is TicketStatus.NEW:
        if ticket.assignee_id is not None:
            logger.warning(
                "ticket_new_status_with_assignee",
                ticket_id=str(ticket.id),
                assignee_id=str(ticket.assignee_id),
            )
        return
    if current in _MANUAL_ZONE:
        raise ValueError(
            "reconcile_ticket_status() never operates on a manual-zone Ticket."
        )

    if evaluation_date is None:
        evaluation_date = _utc_now().date()
    effective_previous = previous_status if previous_status is not None else current

    new_status = await _evaluate_gate_status(db, ticket.id, evaluation_date)

    if new_status in _SANITIZED_RESULTS:
        await _sanitize_assignment(db, ticket)

    if new_status is not current or (
        previous_status is not None and previous_status is not new_status
    ):
        old_value = effective_previous.value
        ticket.status = new_status.value
        await TicketAuditLog.log_event(
            db,
            ticket_id=ticket.id,
            event_type=TicketAuditEventType.STATUS_CHANGE,
            user_id=None,
            old_value=old_value,
            new_value=new_status.value,
        )

    if _registers_convergence(effective_previous, new_status):
        register_ticket_convergence(db, ticket.id)
