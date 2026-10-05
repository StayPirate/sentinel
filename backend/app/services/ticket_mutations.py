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
  semantics, and transaction-local Ticket convergence registration;
- `refresh_priority_auto()` — the only writer of `Ticket.priority_auto`
  (`docs/features/tickets/ticket-priority.md`, Automatic Refresh);
- `set_severity_manual()` — the manual-severity gate-relevant mutation;
- `recalculate_cvss_chain()` — CVE-owned severity recalculation in
  association and default-version modes, with the shared immediate
  Product propagation helper (the narrow atomic-CVSS-chain exception that
  updates system-managed Product eligibility inline through the
  package-model-owned pure evaluator);
- `upsert_cvss_assessment()` and `delete_cvss_assessment()` — the manual
  SUSE assessment create/update and delete, each with its atomic CVSS
  chain (CVSS Mutation Authority and Result, CVSS Status Matrix,
  `upsert_cvss_assessment()`, `delete_cvss_assessment()`);
- `upsert_external_cvss_batch()` — the system-only trusted-external
  assessment batch of one CVE ingestion payload, with its provider guard
  `is_valid_external_provider_name()` (`upsert_external_cvss_batch()`,
  CVSS Status Matrix, trusted external batch column).

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

Dependency direction: this module never imports `package_service`,
`ticket_service`, or `cve_service` (ticket-mutations.md, Relationship with
other modules; cve-service.md, Relationship with other modules); they
import these primitives. The CVSS mutations therefore perform their own
authoritative locked-current CVE accessibility check. It re-exports the
leaf `ticket_mutations_errors` hierarchy.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, date, datetime
from decimal import Decimal
from enum import Enum, StrEnum
from typing import Final, Literal
from uuid import UUID

import structlog
from sqlalchemy import ColumnElement, and_, case, exists, not_, or_, select
from sqlalchemy import inspect as sa_inspect
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import aliased, selectinload

from app.core.enums import (
    CVSSVersion,
    LifecyclePhase,
    PackageStatus,
    Role,
    Severity,
    TicketAuditEventType,
    TicketStatus,
)
from app.core.exceptions import (
    CVENotFoundError,
    SeverityDerivedError,
    TicketNotFoundError,
    TicketNotMutableError,
    UserNotFoundError,
)
from app.core.external_strings import contains_nul
from app.core.identifiers import parse_ticket_id
from app.models.cve import CVE
from app.models.cve_cvss_assessment import CVECVSSAssessment
from app.models.cve_epss_score import CVEEPSSScore
from app.models.cve_kev_entry import CVEKEVEntry
from app.models.cve_ssvc_assessment import CVESSVCAssessment
from app.models.product import Product
from app.models.ticket import Ticket
from app.models.ticket_package import TicketPackage
from app.models.ticket_package_product import TicketPackageProduct
from app.models.ticket_package_track import TicketPackageTrack
from app.models.user import User
from app.models.user_role import UserRole
from app.services import settings as settings_service
from app.services.cvss import (
    CVSS_VERSION_RANK,
    SUSE_PROVIDER_NAME,
    EligibilityResolution,
    ParsedCVSSVector,
    SeverityResolution,
    is_reserved_provider_name,
    resolve_eligibility_score,
    resolve_severity_score,
    validate_cvss_vector,
)
from app.services.package_actionability import (
    product_actionable_expression,
    track_actionable_expression,
)
from app.services.product_eligibility import evaluate_product_eligibility
from app.services.product_service import lifecycle_phase_expression
from app.services.ticket_audit_log import TicketAuditLog
from app.services.ticket_convergence_registry import register_ticket_convergence
from app.services.ticket_mutations_errors import (
    CVSSAssessmentNotFoundError,
    InvalidCVSSVectorError,
    TicketMutationsError,
)
from app.services.ticket_priority import classify_exploitation, resolve_priority
from app.services.ticket_severity import resolved_severity_expression
from app.services.ticket_visibility import TicketCaller, ticket_visibility_condition

__all__ = [
    "EXTERNAL_PROVIDER_MAX_LENGTH",
    "INACTIVE_ASSIGNEE_REASON",
    "VA_ROLE_REMOVED_REASON",
    "CVSSAssessmentAction",
    "CVSSAssessmentMutationResult",
    "CVSSAssessmentNotFoundError",
    "CVSSChainClassification",
    "CVSSChainMode",
    "CVSSChainResult",
    "CVSSMutationCaller",
    "CVSSPropagation",
    "ExternalCVSSAssessmentOutcome",
    "ExternalCVSSBatchResult",
    "InvalidCVSSVectorError",
    "ParsedExternalCVSSAssessment",
    "ProductPropagationSummary",
    "TicketMutationsError",
    "TicketNotMutableError",
    "auto_assign_actor",
    "delete_cvss_assessment",
    "ensure_ticket_operable",
    "gate_status_expression",
    "is_stabilized_vulnerability_analyst",
    "is_valid_external_provider_name",
    "recalculate_cvss_chain",
    "reconcile_ticket_status",
    "refresh_priority_auto",
    "require_accepted_cvss_version",
    "set_severity_manual",
    "stabilize_acting_user",
    "upsert_cvss_assessment",
    "upsert_external_cvss_batch",
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


def is_stabilized_vulnerability_analyst(user: User) -> bool:
    """Whether the stabilized `user` currently holds any VA origin.

    Category C (pure; no database operation). Shared by
    `auto_assign_actor()` and the initial-status decision of
    `ticket_service.create_ticket()`, which reads the creator's
    eligibility from the same locked row without emitting the
    auto-assignment events.

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
    if not acting_user.active or not is_stabilized_vulnerability_analyst(acting_user):
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
#
# Every predicate is correlated to the enclosing statement's `Ticket`, so the
# same gate SQL serves `reconcile_ticket_status()` (one Ticket) and set-based
# gate-mismatch discovery (`gate_status_expression()`).
# ---------------------------------------------------------------------------


def _has_manually_included_track() -> ColumnElement[bool]:
    """`|M| >= 1`: a track whose own and package markers are both NULL."""
    return exists(
        select(TicketPackageTrack.id)
        .join(TicketPackage, TicketPackage.id == TicketPackageTrack.ticket_package_id)
        .where(
            TicketPackage.ticket_id == Ticket.id,
            TicketPackage.deleted_at.is_(None),
            TicketPackageTrack.deleted_at.is_(None),
        )
        .correlate(Ticket)
    )


def _actionable_track_condition(evaluation_date: date) -> ColumnElement[bool]:
    """Select the Ticket's actionable tracks `A` (`TicketPackageTrack` joined
    to its `TicketPackage`)."""
    return and_(
        TicketPackage.ticket_id == Ticket.id,
        track_actionable_expression(evaluation_date),
    )


def _has_actionable_analysis_track(evaluation_date: date) -> ColumnElement[bool]:
    """Some track in `A` has affectedness `ANALYSIS`."""
    return exists(
        select(TicketPackageTrack.id)
        .join(TicketPackage, TicketPackage.id == TicketPackageTrack.ticket_package_id)
        .where(
            _actionable_track_condition(evaluation_date),
            TicketPackageTrack.status == PackageStatus.ANALYSIS.value,
        )
        .correlate(Ticket)
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


def _has_incomplete_actionable_track(evaluation_date: date) -> ColumnElement[bool]:
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
            _actionable_track_condition(evaluation_date),
            not_(resolution_complete),
        )
        .correlate(Ticket)
    )


def gate_status_expression(evaluation_date: date) -> ColumnElement[str]:
    """Build the highest valid gate-zone status of the enclosing `Ticket`.

    Category B (expression builder; no I/O). The one SQL form of the gates
    evaluated by `reconcile_ticket_status()` step 2 (tickets.md, Gate:
    Analysis → Analyzed, Gate: Analyzed → Resolved; package-model.md, Gate
    Participation), correlated to the `Ticket` of the enclosing statement
    so a set-based gate-mismatch query applies exactly the reconciliation
    gates (implementation roadmap umbrella #761, H7). Its read-only twin
    over supplied inputs is `ticket_gate_projection.project_gate_status()`;
    both must agree (shared matrix: `tests/support/gate_matrix.py`).

    Q1: `evaluation_date` is the one UTC date used by every lifecycle and
    actionability predicate.

    Q4: evaluates to the `TicketStatus` value `Resolved` (Analyzed and
    resolution-complete), `Analyzed`, or the `Analysis` floor; never `New`
    or a manual-zone status. Status, assignee, and audit history are not
    inputs.
    """
    analyzed = and_(
        _has_manually_included_track(),
        not_(_has_actionable_analysis_track(evaluation_date)),
        resolved_severity_expression(Ticket).is_not(None),
        or_(Ticket.cve_id.is_(None), _has_canonical_suse_assessment()),
    )
    resolution_complete = not_(_has_incomplete_actionable_track(evaluation_date))
    return case(
        (not_(analyzed), TicketStatus.ANALYSIS.value),
        (resolution_complete, TicketStatus.RESOLVED.value),
        else_=TicketStatus.ANALYZED.value,
    )


async def _evaluate_gate_status(
    db: AsyncSession, ticket_id: UUID, evaluation_date: date
) -> TicketStatus:
    """Evaluate the highest valid gate-zone status in one SQL statement.

    Every clause uses the same `evaluation_date`; nothing is persisted.
    """
    status = (
        await db.execute(
            select(gate_status_expression(evaluation_date)).where(
                Ticket.id == ticket_id
            )
        )
    ).scalar_one()
    return TicketStatus(status)


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


# ---------------------------------------------------------------------------
# Automatic priority (ticket-priority.md, Automatic Refresh)
# ---------------------------------------------------------------------------


async def refresh_priority_auto(db: AsyncSession, *, ticket: Ticket) -> bool:
    """Recompute and persist the Ticket's automatic priority.

    Category A primitive (`docs/features/tickets/ticket-priority.md`,
    `refresh_priority_auto()`; ticket-mutations.md, Utility Functions). The
    only writer of `Ticket.priority_auto`.

    Q1: `ticket` is the caller's locked Ticket instance (or a Ticket
    inserted in the current transaction).

    Q2: trusted preconditions, not rediscovered: the caller holds the
    Ticket `FOR UPDATE` and, for a CVE-associated Ticket, the preceding CVE
    root lock. Acquires no lock, performs no accessibility check, and does
    not call `ensure_ticket_operable()`: it applies in every Ticket status.

    Q3: (1) reads the resolved severity from locked-current state —
    `CVE.severity` when `cve_id` is set, otherwise `severity_manual`; the
    CVE read observes the enclosing transaction's writes (autoflush).
    (2) For a CVE-associated Ticket, reads in the same statement whether a
    `CVEKEVEntry` exists, the SSVC `exploitation`, and the EPSS
    `percentile`; a CVE-less Ticket uses no evidence. (3) Computes
    `resolve_priority(severity, classify_exploitation(...))`. (4) An
    unchanged result returns `False` with no write or event. (5) Otherwise
    persists the new `priority_auto`, and (6) creates one system
    `priority_changed` event with the old and new effective priorities
    (`COALESCE(priority_override, priority_auto)`), `comment` and `detail`
    `NULL`, only when the effective priority changed; an override that
    masks the change creates no event. (7) Flushes. Never assigns,
    reconciles, changes status, registers convergence, reads audit
    history, or performs network, Redis, or Celery I/O.

    Q4: returns `True` exactly when this call changed `priority_auto`.

    Q6: raises nothing of its own. Database, audit, and flush exceptions
    propagate unchanged and roll back the caller's complete transaction.
    """
    kev_listed = False
    ssvc_exploitation: str | None = None
    epss_percentile: float | None = None
    if ticket.cve_id is not None:
        row = (
            await db.execute(
                select(
                    CVE.severity,
                    exists().where(CVEKEVEntry.cve_id == CVE.id),
                    select(CVESSVCAssessment.exploitation)
                    .where(CVESSVCAssessment.cve_id == CVE.id)
                    .scalar_subquery(),
                    select(CVEEPSSScore.percentile)
                    .where(CVEEPSSScore.cve_id == CVE.id)
                    .scalar_subquery(),
                ).where(CVE.id == ticket.cve_id)
            )
        ).one()
        severity_value, kev_listed, ssvc_exploitation, epss_percentile = row
    else:
        severity_value = ticket.severity_manual

    severity = Severity(severity_value) if severity_value is not None else None
    resolved = resolve_priority(
        severity,
        classify_exploitation(
            kev_listed=kev_listed,
            ssvc_exploitation=ssvc_exploitation,
            epss_percentile=epss_percentile,
        ),
    )
    new_auto = resolved.value if resolved is not None else None
    if new_auto == ticket.priority_auto:
        return False

    override = ticket.priority_override
    old_effective = override if override is not None else ticket.priority_auto
    ticket.priority_auto = new_auto
    new_effective = override if override is not None else new_auto
    if new_effective != old_effective:
        await TicketAuditLog.log_event(
            db,
            ticket_id=ticket.id,
            event_type=TicketAuditEventType.PRIORITY_CHANGED,
            user_id=None,
            old_value=old_effective,
            new_value=new_effective,
        )
    await db.flush()
    return True


# ---------------------------------------------------------------------------
# Manual severity (ticket-mutations.md, `set_severity_manual()`)
# ---------------------------------------------------------------------------


async def lock_accessible_ticket(
    db: AsyncSession, ticket_id: UUID, caller: TicketCaller
) -> Ticket:
    """Lock the Ticket `FOR UPDATE` and revalidate consumer accessibility.

    The accessibility decision is a separate statement issued after the
    lock is granted, so it observes the confidentiality, explicit grants,
    and included-package maintainership committed while this transaction
    waited for the lock (`docs/api-spec.md`, Authorization Chain
    Evaluation Order, flow 3). Missing and inaccessible Tickets both raise
    the one `TicketNotFoundError`. Shared by `set_severity_manual()` and
    the `ticket_service` consumer mutations that lock one Ticket as their
    own root (for example `associate_cve()` and `ignore_ticket()`); the
    caller has already taken any
    earlier root in the global User, CVE, Ticket order.
    """
    return await _lock_ticket_and_check_access(db, Ticket.id == ticket_id, caller)


async def lock_accessible_ticket_by_locator(
    db: AsyncSession, ticket_id: str, caller: TicketCaller
) -> Ticket:
    """Lock the Ticket named by its public `SNTL-{n}` locator.

    Same contract as `lock_accessible_ticket()` for a mutation whose
    service boundary receives the public locator (for example the manual
    reference mutations, ticket-references.md, Manual Mutation Ordering):
    the `FOR UPDATE` selection by `sequence_id` is the first persistent
    read, and accessibility is decided by a separate statement after the
    lock is granted. A malformed locator raises `TicketNotFoundError`
    before any database access; missing and inaccessible Tickets raise
    the same exception.
    """
    sequence_id = parse_ticket_id(ticket_id)
    if sequence_id is None:
        raise TicketNotFoundError()
    return await _lock_ticket_and_check_access(
        db, Ticket.sequence_id == sequence_id, caller
    )


async def _lock_ticket_and_check_access(
    db: AsyncSession, locator: ColumnElement[bool], caller: TicketCaller
) -> Ticket:
    ticket = (
        await db.execute(
            select(Ticket)
            .where(locator)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
    ).scalar_one_or_none()
    if ticket is None:
        raise TicketNotFoundError()
    accessible = (
        await db.execute(
            select(ticket_visibility_condition(caller))
            .select_from(Ticket)
            .where(Ticket.id == ticket.id)
        )
    ).scalar_one()
    if not accessible:
        raise TicketNotFoundError()
    return ticket


async def set_severity_manual(
    db: AsyncSession,
    *,
    ticket_id: UUID,
    severity: Severity | None,
    acting_user_id: UUID,
    caller: TicketCaller,
    evaluation_date: date | None = None,
) -> Ticket:
    """Set or clear the manual severity of a CVE-less Ticket.

    Category A consumer mutation (ticket-mutations.md,
    `set_severity_manual()`; tickets.md, Set Severity Manual).

    Q1: `ticket_id` is the internal Ticket UUID (the API resolves the
    public `SNTL-{n}` locator first). `severity` is the requested label, or
    `None` to clear `severity_manual` (SQL `NULL`, distinct from the
    `Severity.NONE` label). `acting_user_id` is the authenticated acting
    user; `caller` is the request-resolved caller information whose
    `user_id` must equal `acting_user_id`. `evaluation_date` is the
    workflow's UTC date shared with any `TicketDetail` response; one UTC
    date is captured at entry when omitted.

    Q2: the caller has verified `triage_ticket` and owns the transaction.
    Locks, in order: the acting User `FOR SHARE`
    (`stabilize_acting_user()`), then the Ticket `FOR UPDATE`.

    Q3: (2) revalidates accessibility from locked-current state with the
    canonical visibility predicate; (3) `ensure_ticket_operable()`;
    (4) rejects a CVE-associated Ticket; (5) an unchanged value is a no-op
    with no assignment, write, event, or reconciliation; (6)
    `auto_assign_actor()` with the stabilized User; (7) writes
    `severity_manual`; (8) creates one `severity_changed` event attributed
    to the acting user (old/new PascalCase labels or `NULL`), then calls
    `refresh_priority_auto()`; (9) calls `reconcile_ticket_status()` once
    with the one `evaluation_date`. Never commits.

    Q4: returns the locked Ticket in its post-mutation state.

    Q6: raises `ValueError` before any database operation when `caller`
    does not identify `acting_user_id` (an internal contract violation);
    `TicketNotFoundError` for a missing or inaccessible Ticket, before any
    other decision; `TicketNotMutableError` for `Ignored` or `Duplicated`;
    `SeverityDerivedError` when `cve_id IS NOT NULL`. `UserNotFoundError`
    (an invariant violation for an authenticated caller), audit, database,
    flush, and reconciliation exceptions propagate and roll back the
    caller's complete transaction.
    """
    if caller.user_id != acting_user_id:
        raise ValueError("caller must identify the acting user.")
    if evaluation_date is None:
        evaluation_date = _utc_now().date()

    acting_user = await stabilize_acting_user(db, acting_user_id)
    ticket = await lock_accessible_ticket(db, ticket_id, caller)
    ensure_ticket_operable(ticket)
    if ticket.cve_id is not None:
        raise SeverityDerivedError()

    new_value = severity.value if severity is not None else None
    old_value = ticket.severity_manual
    if new_value == old_value:
        return ticket

    await auto_assign_actor(ticket, acting_user, db)
    ticket.severity_manual = new_value
    await TicketAuditLog.log_event(
        db,
        ticket_id=ticket.id,
        event_type=TicketAuditEventType.SEVERITY_CHANGED,
        user_id=acting_user.id,
        old_value=old_value,
        new_value=new_value,
    )
    await refresh_priority_auto(db, ticket=ticket)
    await reconcile_ticket_status(ticket, db, evaluation_date=evaluation_date)
    return ticket


# ---------------------------------------------------------------------------
# CVSS chain recalculation (ticket-mutations.md, `recalculate_cvss_chain()`)
# ---------------------------------------------------------------------------


class CVSSChainMode(StrEnum):
    """Semantic invocation mode of `recalculate_cvss_chain()`.

    Service-internal; neither persisted nor serialized. `ASSOCIATION` is
    the `ticket_service.associate_cve()` composition; `DEFAULT_VERSION` is
    one unit of the all-CVE default-version recalculation.
    """

    ASSOCIATION = "association"
    DEFAULT_VERSION = "default_version"


class CVSSPropagation(StrEnum):
    """Ticket-scoped propagation disposition of a CVSS chain.

    The vocabulary of ticket-mutations.md (CVSS Mutation Authority and
    Result); service-internal, neither persisted nor serialized.
    """

    IMMEDIATE = "immediate"
    DEFERRED_UNTIL_REACTIVATION = "deferred_until_reactivation"
    NOT_APPLICABLE = "not_applicable"
    NONE = "none"


class CVSSChainClassification(StrEnum):
    """Runner-facing classification of one `recalculate_cvss_chain()` unit."""

    CHANGED = "changed"
    UNCHANGED = "unchanged"
    MISSING = "missing"


@dataclass(frozen=True, slots=True)
class ProductPropagationSummary:
    """Occurrence counts of one immediate Product propagation (all zero
    when propagation was not applied)."""

    examined: int = 0
    override_skipped: int = 0
    changed: int = 0


@dataclass(frozen=True, slots=True)
class CVSSChainResult:
    """Transaction-local result of `recalculate_cvss_chain()`.

    Valid inside the caller-owned transaction only; it is not evidence of
    durability until that transaction commits. `severity_resolution` is
    `None` for an empty assessment set or a `missing` unit;
    `eligibility_resolution` is `None` only for `missing`.
    `severity_changed` compares the mode's applicable old value (the
    supplied pre-association manual severity in association mode, the old
    `CVE.severity` in default-version mode) with the new CVE severity.
    """

    mode: CVSSChainMode
    classification: CVSSChainClassification
    severity_resolution: SeverityResolution | None
    eligibility_resolution: EligibilityResolution | None
    propagation: CVSSPropagation
    products: ProductPropagationSummary
    severity_changed: bool
    reconciled: bool
    evaluation_date: date


class _Unset(Enum):
    """Marker distinguishing an omitted argument from an explicit `None`."""

    UNSET = "unset"


_UNSET: Final = _Unset.UNSET
_GATE_ZONE: Final = frozenset(
    {TicketStatus.ANALYSIS, TicketStatus.ANALYZED, TicketStatus.RESOLVED}
)


def _eligibility_value(eligible: bool) -> str:
    """The `product_eligibility_changed` old/new value (`true`/`false`)."""
    return "true" if eligible else "false"


async def _propagate_automatic_product_eligibility(
    db: AsyncSession,
    *,
    ticket: Ticket,
    eligibility: EligibilityResolution,
    evaluation_date: date,
) -> ProductPropagationSummary:
    """Immediate automatic Product propagation of the atomic CVSS chain.

    The sole narrow exception that lets `ticket_mutations` write
    system-managed `TicketPackageProduct.eligible` inline
    (ticket-mutations.md, Contract; package-model.md, Override Model).
    Shared by `recalculate_cvss_chain()` and the manual SUSE assessment
    mutations; never imports `package_service`.

    Q1: `ticket` is the chain's Ticket; `eligibility` is the Eligibility
    Score Resolution of the Ticket's current complete assessment set at
    the chain's default version (or the fallback); `evaluation_date` is
    the chain's one UTC date.

    Q2: the caller holds the CVE `FOR NO KEY UPDATE` then Ticket
    `FOR UPDATE` roots (and, for manual work, the acting User before
    them). Acquires no lock.

    Q3: reloads, in one statement ordered by `TicketPackageProduct.id`,
    every Product occurrence of the Ticket — including directly or
    effectively excluded, EOL, and unaffected occurrences — with its
    current override marker, `eligible`, Product threshold, lifecycle
    phase on `evaluation_date`, and the event-time subject (track
    reference, package name, Product display name and CPE). Applies the
    shared pure evaluator; skips overrides; updates only booleans that
    change and creates one system `product_eligibility_changed` per change
    (`reason = cvss`, `comment NULL`). Never touches the override marker
    or any other package state.

    Q4: returns the examined, override-skipped, and changed counts.

    Q6: raises nothing of its own; audit, database, and flush exceptions
    propagate and roll back the caller's complete transaction.
    """
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
        outcome = evaluate_product_eligibility(
            is_eligible_override=product_occurrence.is_eligible_override,
            lifecycle_phase=(
                LifecyclePhase(row.lifecycle) if row.lifecycle is not None else None
            ),
            cvss_threshold=row.cvss_threshold,
            eligibility_score=eligibility,
        )
        new_eligible = outcome.automatic_eligible
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
                "reason": "cvss",
            },
        )
    return ProductPropagationSummary(
        examined=len(rows), override_skipped=override_skipped, changed=changed
    )


def _propagation_for(mode: CVSSChainMode, ticket: Ticket | None) -> CVSSPropagation:
    """Propagation disposition of an existing CVE (ticket-mutations.md,
    `recalculate_cvss_chain()` step 7)."""
    if ticket is None:
        return CVSSPropagation.NOT_APPLICABLE
    if mode is CVSSChainMode.DEFAULT_VERSION and ticket.status in _MANUAL_ZONE:
        return CVSSPropagation.DEFERRED_UNTIL_REACTIVATION
    return CVSSPropagation.IMMEDIATE


async def _lock_cve(db: AsyncSession, cve_id: UUID) -> CVE | None:
    """Lock the CVE root `FOR NO KEY UPDATE`, refreshing any identity-map
    copy; `None` when no CVE has `cve_id` (`docs/conventions.md`,
    Cross-Domain Root Lock Order)."""
    return (
        await db.execute(
            select(CVE)
            .where(CVE.id == cve_id)
            .with_for_update(key_share=True)
            .execution_options(populate_existing=True)
        )
    ).scalar_one_or_none()


async def _lock_associated_ticket(db: AsyncSession, cve: CVE) -> Ticket | None:
    """Lock the Ticket associated with the already locked `cve` `FOR UPDATE`,
    so a concurrent association composes in the CVE then Ticket order;
    `None` for a ticketless CVE."""
    return (
        await db.execute(
            select(Ticket)
            .where(Ticket.cve_id == cve.id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
    ).scalar_one_or_none()


async def recalculate_cvss_chain(
    db: AsyncSession,
    *,
    cve_id: UUID,
    mode: CVSSChainMode,
    association_previous_severity: Severity | Literal[_Unset.UNSET] | None = _UNSET,
    default_cvss_version: str | None = None,
    evaluation_date: date | None = None,
) -> CVSSChainResult:
    """Recalculate CVE-owned severity and its mode-specific consequences.

    Category A system/composition primitive (ticket-mutations.md,
    `recalculate_cvss_chain()`; CVSS Status Matrix, default-version
    paragraph). Never creates, updates, or deletes an assessment and never
    changes an override.

    Q1: `cve_id` is the internal CVE UUID. `mode` selects the composition.
    `association_previous_severity` is required in association mode (the
    Ticket's pre-association `severity_manual`, including `None`) and must
    be omitted in default-version mode. `default_cvss_version`, when
    given, is used for both resolutions instead of the setting (the M4
    runner passes its target version). `evaluation_date` is the one UTC
    date for lifecycle, eligibility, actionability, reconciliation, and
    the result; captured once at entry when omitted.

    Q2: the caller owns the transaction. Takes the CVE `FOR NO KEY
    UPDATE` as the first persistent read, then the associated Ticket
    `FOR UPDATE` (in association mode both are same-transaction re-locks
    of the roots `associate_cve()` already holds). Performs no
    accessibility check and does not call `ensure_ticket_operable()`.

    Q3: (1) default-version mode with no CVE row returns `missing` with no
    other read or effect. (2) Reads `default_cvss_version` once (unless
    supplied) and the complete assessment set; resolves severity and
    eligibility with the pure `cvss` resolutions. (3) Persists a changed
    `CVE.severity`; when a Ticket exists and the applicable old and new
    values differ, creates one system `severity_changed`. (4) Association
    mode: immediate Product propagation, then `refresh_priority_auto()`;
    no assignment and no reconciliation (the caller reconciles once).
    Default-version mode by locked Ticket status: ticketless — severity
    only; `New` — Product propagation and priority, no reconciliation;
    `Analysis`/`Analyzed`/`Resolved` — Product propagation, priority, and
    exactly one final `reconcile_ticket_status()` when severity or a
    Product value changed (a `Resolved` regression registers its normal
    convergence effect there); `Ignored`/`Duplicated` — severity and its
    direct event plus priority only. No state assigns or exits the manual
    zone. (5) Flushes. Never commits, publishes, or performs network,
    Redis, or Celery I/O.

    Q4: returns `CVSSChainResult`. `changed` when the unit contains a
    durable semantic mutation or required event (changed `CVE.severity`,
    `severity_changed`, Product change, changed `priority_auto` including
    one masked by an override, and any sanitation or status change of the
    reconciliation that only a gate-input change triggers); otherwise
    `unchanged`; `missing` only in default-version mode.

    Q6: raises `ValueError` before any database operation for a mode and
    `association_previous_severity` mismatch, and in association mode for
    a missing CVE or associated Ticket (caller contract violations).
    `RequiredSystemSettingMissingError`, `ValueError` from an invalid
    default version or assessment set, and audit, database, flush, and
    reconciliation exceptions propagate and roll back the caller's
    complete transaction.
    """
    association = mode is CVSSChainMode.ASSOCIATION
    if association and association_previous_severity is _UNSET:
        raise ValueError("association mode requires association_previous_severity.")
    if not association and association_previous_severity is not _UNSET:
        raise ValueError(
            "association_previous_severity is only valid in association mode."
        )
    if evaluation_date is None:
        evaluation_date = _utc_now().date()

    cve = await _lock_cve(db, cve_id)
    if cve is None:
        if association:
            raise ValueError("association mode requires the locked CVE to exist.")
        return CVSSChainResult(
            mode=mode,
            classification=CVSSChainClassification.MISSING,
            severity_resolution=None,
            eligibility_resolution=None,
            propagation=CVSSPropagation.NONE,
            products=ProductPropagationSummary(),
            severity_changed=False,
            reconciled=False,
            evaluation_date=evaluation_date,
        )
    ticket = await _lock_associated_ticket(db, cve)
    if association and ticket is None:
        raise ValueError("association mode requires the associated Ticket.")

    if default_cvss_version is None:
        default_cvss_version = await settings_service.get_default_cvss_version(db)
    assessments = (
        (
            await db.execute(
                select(CVECVSSAssessment).where(CVECVSSAssessment.cve_id == cve.id)
            )
        )
        .scalars()
        .all()
    )
    severity_resolution = resolve_severity_score(assessments, default_cvss_version)
    eligibility_resolution = resolve_eligibility_score(
        assessments, default_cvss_version
    )

    new_severity = (
        severity_resolution.label.value if severity_resolution is not None else None
    )
    old_cve_severity = cve.severity
    cve_severity_written = new_severity != old_cve_severity
    if cve_severity_written:
        cve.severity = new_severity
    if isinstance(association_previous_severity, Severity):
        old_effective: str | None = association_previous_severity.value
    elif association:
        old_effective = None
    else:
        old_effective = old_cve_severity
    severity_changed = old_effective != new_severity
    if ticket is not None and severity_changed:
        await TicketAuditLog.log_event(
            db,
            ticket_id=ticket.id,
            event_type=TicketAuditEventType.SEVERITY_CHANGED,
            user_id=None,
            old_value=old_effective,
            new_value=new_severity,
        )

    propagation = _propagation_for(mode, ticket)
    products = ProductPropagationSummary()
    priority_changed = False
    reconciled = False
    if ticket is not None:
        if propagation is CVSSPropagation.IMMEDIATE:
            products = await _propagate_automatic_product_eligibility(
                db,
                ticket=ticket,
                eligibility=eligibility_resolution,
                evaluation_date=evaluation_date,
            )
        priority_changed = await refresh_priority_auto(db, ticket=ticket)
        if (
            not association
            and ticket.status in _GATE_ZONE
            and (severity_changed or products.changed > 0)
        ):
            await reconcile_ticket_status(ticket, db, evaluation_date=evaluation_date)
            reconciled = True
    await db.flush()

    effective = (
        cve_severity_written
        or (ticket is not None and severity_changed)
        or products.changed > 0
        or priority_changed
    )
    return CVSSChainResult(
        mode=mode,
        classification=(
            CVSSChainClassification.CHANGED
            if effective
            else CVSSChainClassification.UNCHANGED
        ),
        severity_resolution=severity_resolution,
        eligibility_resolution=eligibility_resolution,
        propagation=propagation,
        products=products,
        severity_changed=severity_changed,
        reconciled=reconciled,
        evaluation_date=evaluation_date,
    )


# ---------------------------------------------------------------------------
# Manual SUSE CVSS assessment (ticket-mutations.md, CVSS Mutation Authority
# and Result; CVSS Status Matrix; `upsert_cvss_assessment()`;
# `delete_cvss_assessment()`)
# ---------------------------------------------------------------------------


class CVSSMutationCaller(StrEnum):
    """Caller authority of a single-assessment CVSS mutation.

    Service-internal; neither persisted nor serialized. `MANUAL_SUSE` is
    the only category: an authorized consumer operation on the internal
    SUSE assessment. Trusted external ingestion uses its own system-only
    batch boundary; authority is never inferred from the acting user.
    """

    MANUAL_SUSE = "manual_suse"


class CVSSAssessmentAction(StrEnum):
    """Serialized action of a CVSS assessment mutation, classified after
    the roots are locked (service-internal)."""

    CREATED = "created"
    UPDATED = "updated"
    UNCHANGED = "unchanged"
    DELETED = "deleted"
    NOT_FOUND = "not_found"


@dataclass(frozen=True, slots=True)
class CVSSAssessmentMutationResult:
    """Transaction-local result of a manual SUSE assessment mutation.

    Valid inside the caller-owned transaction only; it is not evidence of
    durability until that transaction commits. `assessment` is the
    locked-current persisted assessment with its server timestamps loaded
    after `created`, `updated`, or `unchanged`; the deleted assessment
    snapshot (its columns as loaded before the delete) after `deleted`;
    and `None` for `not_found`. `severity_resolution` is `None` only for
    an empty set (never after a create or update). `severity_changed`
    compares the old and new unified `CVE.severity`. `products` holds the
    counts of an applied immediate propagation (all zero otherwise);
    `assigned` and `reconciled` summarize the Ticket-scoped chain.
    """

    assessment: CVECVSSAssessment | None
    action: CVSSAssessmentAction
    severity_resolution: SeverityResolution | None
    severity_changed: bool
    eligibility_resolution: EligibilityResolution
    propagation: CVSSPropagation
    products: ProductPropagationSummary
    assigned: bool
    reconciled: bool
    evaluation_date: date


def _canonical_assessment_value(
    provider: str, version: str, vector: str, score: Decimal
) -> str:
    """The canonical `cvss_assessment_changed` old/new value
    (ticket-audit-log.md, Event Type Contract)."""
    return f"{provider} v{version} {vector} ({score:.1f})"


async def _lock_accessible_cve_roots(
    db: AsyncSession, cve_id: UUID, caller: TicketCaller
) -> tuple[CVE, Ticket | None]:
    """Lock the CVE then its associated Ticket and revalidate accessibility.

    The CVE `FOR NO KEY UPDATE` is taken first (`docs/conventions.md`,
    Cross-Domain Root Lock Order: a referencing Ticket's foreign-key
    `FOR KEY SHARE` stays compatible); the Ticket currently associated
    with the locked CVE is then locked `FOR UPDATE`, so a concurrent
    association composes in the global CVE then Ticket order. The
    accessibility decision is a separate statement issued after both
    locks are granted, so it observes the confidentiality, grants,
    included-package maintainership, and association committed while this
    transaction waited (`docs/api-spec.md`, Authorization Chain
    Evaluation Order, flow 3). A ticketless CVE is accessible. A missing
    CVE and an inaccessible associated Ticket both raise the one shared
    `CVENotFoundError`, never a Ticket error.
    """
    cve = await _lock_cve(db, cve_id)
    if cve is None:
        raise CVENotFoundError()
    ticket = await _lock_associated_ticket(db, cve)
    if ticket is not None:
        accessible = (
            await db.execute(
                select(ticket_visibility_condition(caller))
                .select_from(Ticket)
                .where(Ticket.id == ticket.id)
            )
        ).scalar_one()
        if not accessible:
            raise CVENotFoundError()
    return cve, ticket


def require_accepted_cvss_version(cvss_version: str) -> CVSSVersion:
    """Validate a received CVSS version for the SUSE assessment deletion.

    Category C (pure; input-only). See ticket-mutations.md
    (`delete_cvss_assessment()` step 1, Service Exceptions) and
    cvss-scoring.md (Delete SUSE CVSS Assessment): exactly `2.0`, `3.0`,
    `3.1`, or `4.0` is accepted, with no trimming or other normalization.
    The API applies it before CVE-ID resolution, so an unrecognized value
    is never distinguishable by `{cve_id}`.

    Raises:
        CVSSAssessmentNotFoundError: `cvss_version` is not accepted.
    """
    if cvss_version not in _ACCEPTED_CVSS_VERSIONS:
        raise CVSSAssessmentNotFoundError()
    return CVSSVersion(cvss_version)


def _has_suse_assessment(assessments: list[CVECVSSAssessment]) -> bool:
    """Whether a canonical `SUSE` assessment exists in an accepted version
    (the CVSS Workflow Gate input)."""
    return any(
        a.provider_name == SUSE_PROVIDER_NAME
        and a.cvss_version in _ACCEPTED_CVSS_VERSIONS
        for a in assessments
    )


async def upsert_cvss_assessment(
    db: AsyncSession,
    *,
    cve_id: UUID,
    provider: str,
    vector_string: str,
    caller: CVSSMutationCaller,
    acting_user_id: UUID,
    ticket_caller: TicketCaller,
    default_cvss_version: str | None = None,
    evaluation_date: date | None = None,
) -> CVSSAssessmentMutationResult:
    """Create or update the manual SUSE assessment of a CVE.

    Category A consumer mutation (ticket-mutations.md,
    `upsert_cvss_assessment()`, CVSS Mutation Authority and Result, CVSS
    Status Matrix; cvss-scoring.md, Assessment Persistence and Ticket
    Status, Serialization and Concurrent Outcomes).

    Q1: `cve_id` is the internal CVE UUID (the API resolves the public
    CVE-ID first). `provider` must be the reserved SUSE provider in any
    case or outer-whitespace variant; it is stored as `SUSE`.
    `vector_string` is the received vector. `caller` must be
    `MANUAL_SUSE`. `acting_user_id` is the authenticated acting user;
    `ticket_caller` is the request-resolved caller information whose
    `user_id` must equal `acting_user_id`. `default_cvss_version`, when
    given, is used for both resolutions instead of the setting.
    `evaluation_date` is the workflow's one UTC date; captured once at
    entry when omitted.

    Q2: the caller has verified `manage_cvss` and owns the transaction.
    Locks, in order: the acting User `FOR SHARE`
    (`stabilize_acting_user()`), the CVE `FOR NO KEY UPDATE`, then the
    Ticket associated with the locked CVE `FOR UPDATE`.

    Q3: (1) validates authority and parses the vector from input only.
    (2) Locks the roots and (3) revalidates CVE accessibility from the
    locked-current Ticket before any other read. (4) Rejects an `Ignored`
    or `Duplicated` Ticket. (5) Reads `default_cvss_version` once unless
    supplied. (6) Loads the assessments under the CVE lock and classifies
    `created`, `updated`, or `unchanged` by comparing canonical vectors.
    `unchanged` returns the current resolutions with no write, assignment,
    event, propagation, priority refresh, or reconciliation. (7) An
    effective mutation persists the vector-derived unit and the
    re-resolved `CVE.severity` (assigned even when equal). (8) With a
    Ticket: `auto_assign_actor()` with the stabilized User; the
    acting-user `cvss_assessment_changed`; a system `severity_changed`
    when the unified severity changed; immediate automatic Product
    propagation (`reason = cvss`); `refresh_priority_auto()`; and exactly
    one `reconcile_ticket_status()` with the one `evaluation_date` when
    the Ticket is now in the gate zone and the severity, a Product value,
    or canonical-SUSE presence changed, or the assignment moved `New`
    into `Analysis`. A ticketless CVE maintains CVE-owned state only.
    (9) Flushes and loads the assessment's server timestamps. Never
    commits, publishes, or performs network, Redis, or Celery I/O.

    Q4: returns `CVSSAssessmentMutationResult`. Propagation is
    `not_applicable` for a ticketless CVE, `immediate` for an effective
    mutation with a Ticket, and `none` for `unchanged`.

    Q5: a repeated call with an equivalent vector is `unchanged`.

    Q6: raises `ValueError` before any database operation for a
    non-`MANUAL_SUSE` caller, a missing actor, a non-reserved provider,
    or a `ticket_caller` that does not identify `acting_user_id`;
    `InvalidCVSSVectorError` before any database operation for a vector
    violating the accepted Base-vector contract; `CVENotFoundError` for a
    missing or inaccessible CVE, before any other decision;
    `TicketNotMutableError` for an `Ignored` or `Duplicated` Ticket.
    `RequiredSystemSettingMissingError`, `UserNotFoundError` (an
    invariant violation for an authenticated caller), and audit,
    database, eligibility, flush, and reconciliation exceptions propagate
    and roll back the caller's complete transaction.
    """
    if caller is not CVSSMutationCaller.MANUAL_SUSE:
        raise ValueError("upsert_cvss_assessment() requires MANUAL_SUSE authority.")
    if acting_user_id is None:
        raise ValueError("MANUAL_SUSE authority requires an acting user.")
    if not is_reserved_provider_name(provider):
        raise ValueError("MANUAL_SUSE authority may only mutate the SUSE provider.")
    if ticket_caller.user_id != acting_user_id:
        raise ValueError("ticket_caller must identify the acting user.")
    parsed = validate_cvss_vector(vector_string)
    if evaluation_date is None:
        evaluation_date = _utc_now().date()

    acting_user = await stabilize_acting_user(db, acting_user_id)
    cve, ticket = await _lock_accessible_cve_roots(db, cve_id, ticket_caller)
    if ticket is not None:
        ensure_ticket_operable(ticket)
    if default_cvss_version is None:
        default_cvss_version = await settings_service.get_default_cvss_version(db)
    assessments = list(
        (
            await db.execute(
                select(CVECVSSAssessment)
                .where(CVECVSSAssessment.cve_id == cve.id)
                .execution_options(populate_existing=True)
            )
        ).scalars()
    )
    version = parsed.version.value
    existing = next(
        (
            a
            for a in assessments
            if a.provider_name == SUSE_PROVIDER_NAME and a.cvss_version == version
        ),
        None,
    )

    if existing is not None and existing.vector_string == parsed.canonical_vector:
        return CVSSAssessmentMutationResult(
            assessment=existing,
            action=CVSSAssessmentAction.UNCHANGED,
            severity_resolution=resolve_severity_score(
                assessments, default_cvss_version
            ),
            severity_changed=False,
            eligibility_resolution=resolve_eligibility_score(
                assessments, default_cvss_version
            ),
            propagation=CVSSPropagation.NONE,
            products=ProductPropagationSummary(),
            assigned=False,
            reconciled=False,
            evaluation_date=evaluation_date,
        )

    suse_present_before = _has_suse_assessment(assessments)
    if existing is None:
        action = CVSSAssessmentAction.CREATED
        old_value: str | None = None
        assessment = CVECVSSAssessment(
            cve_id=cve.id,
            provider_name=SUSE_PROVIDER_NAME,
            cvss_version=version,
            score=parsed.score,
            severity=parsed.severity.value,
            vector_string=parsed.canonical_vector,
        )
        db.add(assessment)
        assessments.append(assessment)
    else:
        action = CVSSAssessmentAction.UPDATED
        old_value = _canonical_assessment_value(
            existing.provider_name,
            existing.cvss_version,
            existing.vector_string,
            existing.score,
        )
        assessment = existing
        assessment.score = parsed.score
        assessment.severity = parsed.severity.value
        assessment.vector_string = parsed.canonical_vector
    new_value = _canonical_assessment_value(
        SUSE_PROVIDER_NAME, version, parsed.canonical_vector, parsed.score
    )

    severity_resolution = resolve_severity_score(assessments, default_cvss_version)
    eligibility_resolution = resolve_eligibility_score(
        assessments, default_cvss_version
    )
    new_severity = (
        severity_resolution.label.value if severity_resolution is not None else None
    )
    old_severity = cve.severity
    severity_changed = old_severity != new_severity
    cve.severity = new_severity
    await db.flush()

    assigned = False
    reconciled = False
    products = ProductPropagationSummary()
    propagation = CVSSPropagation.NOT_APPLICABLE
    if ticket is not None:
        propagation = CVSSPropagation.IMMEDIATE
        was_new = ticket.status == TicketStatus.NEW
        assigned = await auto_assign_actor(ticket, acting_user, db)
        promoted = was_new and ticket.status == TicketStatus.ANALYSIS
        await TicketAuditLog.log_event(
            db,
            ticket_id=ticket.id,
            event_type=TicketAuditEventType.CVSS_ASSESSMENT_CHANGED,
            user_id=acting_user.id,
            old_value=old_value,
            new_value=new_value,
        )
        if severity_changed:
            await TicketAuditLog.log_event(
                db,
                ticket_id=ticket.id,
                event_type=TicketAuditEventType.SEVERITY_CHANGED,
                user_id=None,
                old_value=old_severity,
                new_value=new_severity,
            )
        products = await _propagate_automatic_product_eligibility(
            db,
            ticket=ticket,
            eligibility=eligibility_resolution,
            evaluation_date=evaluation_date,
        )
        await refresh_priority_auto(db, ticket=ticket)
        gate_input_changed = (
            severity_changed
            or products.changed > 0
            or suse_present_before != _has_suse_assessment(assessments)
        )
        if ticket.status in _GATE_ZONE and (gate_input_changed or promoted):
            await reconcile_ticket_status(ticket, db, evaluation_date=evaluation_date)
            reconciled = True
    await db.flush()
    await db.refresh(assessment, ["created_at", "updated_at"])

    return CVSSAssessmentMutationResult(
        assessment=assessment,
        action=action,
        severity_resolution=severity_resolution,
        severity_changed=severity_changed,
        eligibility_resolution=eligibility_resolution,
        propagation=propagation,
        products=products,
        assigned=assigned,
        reconciled=reconciled,
        evaluation_date=evaluation_date,
    )


async def delete_cvss_assessment(
    db: AsyncSession,
    *,
    cve_id: UUID,
    provider: str,
    cvss_version: str,
    caller: CVSSMutationCaller,
    acting_user_id: UUID,
    ticket_caller: TicketCaller,
    default_cvss_version: str | None = None,
    evaluation_date: date | None = None,
) -> CVSSAssessmentMutationResult:
    """Delete the manual SUSE assessment of a CVE for one version.

    Category A consumer mutation (ticket-mutations.md,
    `delete_cvss_assessment()`, CVSS Mutation Authority and Result, CVSS
    Status Matrix; cvss-scoring.md, Assessment Persistence and Ticket
    Status, Serialization and Concurrent Outcomes, Delete SUSE CVSS
    Assessment). Hard delete addressed by the natural key.

    Q1: `cve_id` is the internal CVE UUID (the API resolves the public
    CVE-ID first). `provider` must be the reserved SUSE provider in any
    case or outer-whitespace variant. `cvss_version` is the received
    version, accepted exactly as `2.0`, `3.0`, `3.1`, or `4.0`. `caller`
    must be `MANUAL_SUSE`. `acting_user_id` is the authenticated acting
    user; `ticket_caller` is the request-resolved caller information
    whose `user_id` must equal `acting_user_id`. `default_cvss_version`,
    when given, is used for both resolutions instead of the setting.
    `evaluation_date` is the workflow's one UTC date; captured once at
    entry when omitted.

    Q2: the caller has verified `manage_cvss` and owns the transaction.
    Locks, in order: the acting User `FOR SHARE`
    (`stabilize_acting_user()`), the CVE `FOR NO KEY UPDATE`, then the
    Ticket associated with the locked CVE `FOR UPDATE`.

    Q3: (1) validates authority and the version from input only. (2)
    Locks the roots and (3) revalidates CVE accessibility from the
    locked-current Ticket before any other decision. (4) Rejects an
    `Ignored` or `Duplicated` Ticket. (5) Reads `default_cvss_version`
    once unless supplied. (6) Loads the assessments under the CVE lock;
    without a canonical SUSE assessment for the version, returns
    `not_found` with the current resolutions and no write, assignment,
    event, propagation, priority refresh, or reconciliation. (7) Deletes
    the assessment and persists the re-resolved `CVE.severity`, `NULL`
    when no assessment remains (assigned even when equal). (8) With a
    Ticket: `auto_assign_actor()` with the stabilized User; the
    acting-user `cvss_assessment_changed` (old value = the canonical
    snapshot, new value `NULL`); a system `severity_changed` when the
    unified severity changed; immediate automatic Product propagation
    (`reason = cvss`); `refresh_priority_auto()`; and exactly one
    `reconcile_ticket_status()` with the one `evaluation_date` when the
    Ticket is now in the gate zone and the severity, a Product value, or
    canonical-SUSE presence changed, or the assignment moved `New` into
    `Analysis`. A ticketless CVE maintains CVE-owned state only. (9)
    Flushes. Never commits, publishes, or performs network, Redis, or
    Celery I/O.

    Q4: returns `CVSSAssessmentMutationResult` with `deleted` (the
    deleted snapshot) or `not_found` (`assessment = None`). Propagation
    is `not_applicable` for a ticketless CVE, `immediate` for a delete
    with a Ticket, and `none` for `not_found`.

    Q5: a repeated call after an effective delete is `not_found`.

    Q6: raises `ValueError` before any database operation for a
    non-`MANUAL_SUSE` caller, a missing actor, a non-reserved provider,
    or a `ticket_caller` that does not identify `acting_user_id`;
    `CVSSAssessmentNotFoundError` before any database operation for an
    unaccepted version; `CVENotFoundError` for a missing or inaccessible
    CVE, before any other decision; `TicketNotMutableError` for an
    `Ignored` or `Duplicated` Ticket. `RequiredSystemSettingMissingError`,
    `UserNotFoundError` (an invariant violation for an authenticated
    caller), and audit, database, eligibility, flush, and reconciliation
    exceptions propagate and roll back the caller's complete transaction.
    """
    if caller is not CVSSMutationCaller.MANUAL_SUSE:
        raise ValueError("delete_cvss_assessment() requires MANUAL_SUSE authority.")
    if acting_user_id is None:
        raise ValueError("MANUAL_SUSE authority requires an acting user.")
    if not is_reserved_provider_name(provider):
        raise ValueError("MANUAL_SUSE authority may only delete the SUSE provider.")
    if ticket_caller.user_id != acting_user_id:
        raise ValueError("ticket_caller must identify the acting user.")
    version = require_accepted_cvss_version(cvss_version).value
    if evaluation_date is None:
        evaluation_date = _utc_now().date()

    acting_user = await stabilize_acting_user(db, acting_user_id)
    cve, ticket = await _lock_accessible_cve_roots(db, cve_id, ticket_caller)
    if ticket is not None:
        ensure_ticket_operable(ticket)
    if default_cvss_version is None:
        default_cvss_version = await settings_service.get_default_cvss_version(db)
    assessments = list(
        (
            await db.execute(
                select(CVECVSSAssessment)
                .where(CVECVSSAssessment.cve_id == cve.id)
                .execution_options(populate_existing=True)
            )
        ).scalars()
    )
    existing = next(
        (
            a
            for a in assessments
            if a.provider_name == SUSE_PROVIDER_NAME and a.cvss_version == version
        ),
        None,
    )

    if existing is None:
        return CVSSAssessmentMutationResult(
            assessment=None,
            action=CVSSAssessmentAction.NOT_FOUND,
            severity_resolution=resolve_severity_score(
                assessments, default_cvss_version
            ),
            severity_changed=False,
            eligibility_resolution=resolve_eligibility_score(
                assessments, default_cvss_version
            ),
            propagation=CVSSPropagation.NONE,
            products=ProductPropagationSummary(),
            assigned=False,
            reconciled=False,
            evaluation_date=evaluation_date,
        )

    suse_present_before = _has_suse_assessment(assessments)
    old_value = _canonical_assessment_value(
        existing.provider_name,
        existing.cvss_version,
        existing.vector_string,
        existing.score,
    )
    await db.delete(existing)
    assessments.remove(existing)

    severity_resolution = resolve_severity_score(assessments, default_cvss_version)
    eligibility_resolution = resolve_eligibility_score(
        assessments, default_cvss_version
    )
    new_severity = (
        severity_resolution.label.value if severity_resolution is not None else None
    )
    old_severity = cve.severity
    severity_changed = old_severity != new_severity
    cve.severity = new_severity
    await db.flush()

    assigned = False
    reconciled = False
    products = ProductPropagationSummary()
    propagation = CVSSPropagation.NOT_APPLICABLE
    if ticket is not None:
        propagation = CVSSPropagation.IMMEDIATE
        was_new = ticket.status == TicketStatus.NEW
        assigned = await auto_assign_actor(ticket, acting_user, db)
        promoted = was_new and ticket.status == TicketStatus.ANALYSIS
        await TicketAuditLog.log_event(
            db,
            ticket_id=ticket.id,
            event_type=TicketAuditEventType.CVSS_ASSESSMENT_CHANGED,
            user_id=acting_user.id,
            old_value=old_value,
            new_value=None,
        )
        if severity_changed:
            await TicketAuditLog.log_event(
                db,
                ticket_id=ticket.id,
                event_type=TicketAuditEventType.SEVERITY_CHANGED,
                user_id=None,
                old_value=old_severity,
                new_value=new_severity,
            )
        products = await _propagate_automatic_product_eligibility(
            db,
            ticket=ticket,
            eligibility=eligibility_resolution,
            evaluation_date=evaluation_date,
        )
        await refresh_priority_auto(db, ticket=ticket)
        gate_input_changed = (
            severity_changed
            or products.changed > 0
            or suse_present_before != _has_suse_assessment(assessments)
        )
        if ticket.status in _GATE_ZONE and (gate_input_changed or promoted):
            await reconcile_ticket_status(ticket, db, evaluation_date=evaluation_date)
            reconciled = True
    await db.flush()

    return CVSSAssessmentMutationResult(
        assessment=existing,
        action=CVSSAssessmentAction.DELETED,
        severity_resolution=severity_resolution,
        severity_changed=severity_changed,
        eligibility_resolution=eligibility_resolution,
        propagation=propagation,
        products=products,
        assigned=assigned,
        reconciled=reconciled,
        evaluation_date=evaluation_date,
    )


# ---------------------------------------------------------------------------
# Trusted-external CVSS batch (ticket-mutations.md,
# `upsert_external_cvss_batch()`; CVSS Status Matrix, trusted external
# batch column)
# ---------------------------------------------------------------------------


EXTERNAL_PROVIDER_MAX_LENGTH: Final = 100
"""The persisted `CVECVSSAssessment.provider_name` limit (`VARCHAR(100)`)."""


def is_valid_external_provider_name(provider: object) -> bool:
    """Whether `provider` may identify a trusted-external assessment.

    Category C (pure; input-only). The batch provider guard
    (ticket-mutations.md, `upsert_external_cvss_batch()` > Guards;
    cvss-scoring.md, Provider Identity and Authority): a string that is
    non-empty after outer trim, at most 100 characters as received, free
    of U+0000 (External String Admissibility), and not equivalent to the
    reserved `SUSE` after outer trim and Unicode case-folding. Shared with
    the ingestion-side `invalid_provider` skip so the skip and the batch
    guard cannot diverge.
    """
    return (
        isinstance(provider, str)
        and bool(provider.strip())
        and len(provider) <= EXTERNAL_PROVIDER_MAX_LENGTH
        and not contains_nul(provider)
        and not is_reserved_provider_name(provider)
    )


@dataclass(frozen=True, slots=True)
class ParsedExternalCVSSAssessment:
    """One valid trusted-external candidate of an ingestion payload.

    Service-internal semantic type, neither a Pydantic schema nor a
    persisted entity. `provider` is the source's canonical non-reserved
    provider name; `parsed` is the immutable stable result of
    `cvss.validate_cvss_vector()` and the only CVSS authority.
    """

    provider: str
    parsed: ParsedCVSSVector


@dataclass(frozen=True, slots=True)
class ExternalCVSSAssessmentOutcome:
    """The serialized action of one batch candidate."""

    provider: str
    version: CVSSVersion
    action: CVSSAssessmentAction


@dataclass(frozen=True, slots=True)
class ExternalCVSSBatchResult:
    """Transaction-local result of `upsert_external_cvss_batch()`.

    Valid inside the caller-owned transaction only; it is not evidence of
    durability until that transaction commits. `actions` holds one
    `created`, `updated`, or `unchanged` outcome per candidate in canonical
    order. Both resolutions are those of the final complete assessment set
    and are `None` only for an empty batch (`severity_resolution` is also
    `None` for an empty set). `propagation` is `none` without an effective
    candidate, otherwise `not_applicable` (ticketless), `immediate`, or
    `deferred_until_reactivation` per the status matrix. `products` holds
    the counts of an applied immediate pass (all zero otherwise).
    """

    actions: tuple[ExternalCVSSAssessmentOutcome, ...]
    severity_resolution: SeverityResolution | None
    eligibility_resolution: EligibilityResolution | None
    propagation: CVSSPropagation
    products: ProductPropagationSummary
    severity_changed: bool
    reconciled: bool
    evaluation_date: date

    @property
    def effective(self) -> bool:
        """Whether any candidate was created or updated (an effective CVSS
        child change for `UpsertResult.action`)."""
        return any(
            outcome.action is not CVSSAssessmentAction.UNCHANGED
            for outcome in self.actions
        )


def _validated_batch(
    cve_id: object, assessments: object, evaluation_date: object
) -> list[ParsedExternalCVSSAssessment]:
    """The input-only guards of the batch, in canonical order.

    Raises `ValueError` for a missing or non-UUID `cve_id`, a missing or
    non-`date` `evaluation_date`, a non-sequence, an item that is not a
    `ParsedExternalCVSSAssessment`, an invalid provider, a parsed result
    that is not exactly the stable parse of its own canonical vector, or a
    duplicate `(provider, version)` key.
    """
    if not isinstance(evaluation_date, date) or isinstance(evaluation_date, datetime):
        raise ValueError("upsert_external_cvss_batch() requires an evaluation_date.")
    if not isinstance(cve_id, UUID):
        raise ValueError("upsert_external_cvss_batch() requires the CVE UUID.")
    if not isinstance(assessments, Sequence) or isinstance(assessments, str | bytes):
        raise ValueError("assessments must be a sequence of parsed candidates.")

    keys: set[tuple[str, CVSSVersion]] = set()
    candidates: list[ParsedExternalCVSSAssessment] = []
    for item in assessments:
        if not isinstance(item, ParsedExternalCVSSAssessment):
            raise ValueError("Every candidate must be a ParsedExternalCVSSAssessment.")
        if not is_valid_external_provider_name(item.provider):
            raise ValueError(
                "Candidate provider is empty, overlength, NUL-containing, or reserved."
            )
        parsed = item.parsed
        if not isinstance(parsed, ParsedCVSSVector) or not isinstance(
            parsed.canonical_vector, str
        ):
            raise ValueError("Candidate parsed result is malformed.")
        try:
            reparsed = validate_cvss_vector(parsed.canonical_vector)
        except InvalidCVSSVectorError:
            raise ValueError("Candidate parsed result is malformed.") from None
        if reparsed != parsed:
            raise ValueError("Candidate parsed result is malformed.")
        key = (item.provider, parsed.version)
        if key in keys:
            raise ValueError("Duplicate canonical (provider, version) candidate.")
        keys.add(key)
        candidates.append(item)
    candidates.sort(key=lambda c: (CVSS_VERSION_RANK[c.parsed.version], c.provider))
    return candidates


async def upsert_external_cvss_batch(
    db: AsyncSession,
    *,
    cve_id: UUID,
    assessments: Sequence[ParsedExternalCVSSAssessment],
    evaluation_date: date,
) -> ExternalCVSSBatchResult:
    """Apply one payload's trusted-external assessments as one atomic batch.

    System-only Category A boundary (ticket-mutations.md,
    `upsert_external_cvss_batch()`, CVSS Status Matrix; cvss-scoring.md,
    Provider Identity and Authority, Assessment Persistence and Ticket
    Status). Its only caller is `cve_service.upsert_cve()`; it is never an
    API, task, CLI, or fetcher boundary and never assigns.

    Q1: `cve_id` is the internal CVE UUID. `assessments` is the complete
    valid canonical candidate set of one payload (individually invalid
    candidates are skipped by the caller first); every provider is
    non-reserved. `evaluation_date` is the caller's one UTC date and is
    required; it is never replaced.

    Q2: the caller owns the transaction. Locks, as the first persistent
    reads: the CVE `FOR NO KEY UPDATE`, then its associated Ticket `FOR
    UPDATE` when one exists (same-transaction no-ops under `upsert_cve()`,
    which already holds both). No User lock, no accessibility check, and
    no `ensure_ticket_operable()`.

    Q3: (1) orders candidates by version `4.0`, `3.1`, `3.0`, `2.0`, then
    provider by Unicode code point; an empty batch returns here with no
    lock, query, or effect. (2) Locks the roots. (3) Reads
    `default_cvss_version` once. (4) Classifies each candidate against the
    locked-current natural-key row by canonical vector and persists every
    effective vector-derived unit; (5) with a Ticket, one system
    `cvss_assessment_changed` per effective candidate in canonical order.
    An all-unchanged batch stops here with no further write or event.
    (6) Resolves the final complete set once, persists `CVE.severity` once,
    and with a Ticket appends at most one system `severity_changed`. (7)
    For `New`, `Analysis`, `Analyzed`, and `Resolved`, one immediate
    automatic Product pass (`reason = cvss`, override skips, occurrence-ID
    order); `Ignored` and `Duplicated` defer it; then, with a Ticket,
    `refresh_priority_auto()` in every status. (8) For a gate-zone Ticket,
    at most one `reconcile_ticket_status()` when severity or a Product
    value changed. (9) Flushes. Never commits, rolls back, assigns, exits
    a manual zone, publishes, or performs network, Redis, or Celery I/O.

    Q4: returns `ExternalCVSSBatchResult`.

    Q5: re-invocation with equal canonical candidates returns only
    `unchanged` actions with no write or event.

    Q6: raises `ValueError` before any database operation for a missing
    `evaluation_date` or CVE UUID, a malformed candidate or parsed result,
    an empty, overlength, U+0000-containing, or reserved provider, or a
    duplicate canonical key; and after the lock lookup for a CVE that does not exist.
    `RequiredSystemSettingMissingError`, and settings, database, audit,
    eligibility, flush, reconciliation, cancellation, and programming
    exceptions propagate unchanged and roll back the caller's complete
    per-CVE transaction.
    """
    candidates = _validated_batch(cve_id, assessments, evaluation_date)
    if not candidates:
        return ExternalCVSSBatchResult(
            actions=(),
            severity_resolution=None,
            eligibility_resolution=None,
            propagation=CVSSPropagation.NONE,
            products=ProductPropagationSummary(),
            severity_changed=False,
            reconciled=False,
            evaluation_date=evaluation_date,
        )

    cve = await _lock_cve(db, cve_id)
    if cve is None:
        raise ValueError("upsert_external_cvss_batch() requires an existing CVE.")
    ticket = await _lock_associated_ticket(db, cve)
    default_cvss_version = await settings_service.get_default_cvss_version(db)
    current = list(
        (
            await db.execute(
                select(CVECVSSAssessment)
                .where(CVECVSSAssessment.cve_id == cve.id)
                .execution_options(populate_existing=True)
            )
        ).scalars()
    )
    by_key = {(a.provider_name, a.cvss_version): a for a in current}

    outcomes: list[ExternalCVSSAssessmentOutcome] = []
    changes: list[tuple[str | None, str]] = []
    for candidate in candidates:
        parsed = candidate.parsed
        version = parsed.version.value
        existing = by_key.get((candidate.provider, version))
        if existing is not None and existing.vector_string == parsed.canonical_vector:
            action = CVSSAssessmentAction.UNCHANGED
        elif existing is None:
            action = CVSSAssessmentAction.CREATED
            assessment = CVECVSSAssessment(
                cve_id=cve.id,
                provider_name=candidate.provider,
                cvss_version=version,
                score=parsed.score,
                severity=parsed.severity.value,
                vector_string=parsed.canonical_vector,
            )
            db.add(assessment)
            current.append(assessment)
            changes.append((None, _external_value(candidate)))
        else:
            action = CVSSAssessmentAction.UPDATED
            old_value = _canonical_assessment_value(
                existing.provider_name,
                existing.cvss_version,
                existing.vector_string,
                existing.score,
            )
            existing.score = parsed.score
            existing.severity = parsed.severity.value
            existing.vector_string = parsed.canonical_vector
            changes.append((old_value, _external_value(candidate)))
        outcomes.append(
            ExternalCVSSAssessmentOutcome(
                provider=candidate.provider, version=parsed.version, action=action
            )
        )

    severity_resolution = resolve_severity_score(current, default_cvss_version)
    eligibility_resolution = resolve_eligibility_score(current, default_cvss_version)
    if not changes:
        return ExternalCVSSBatchResult(
            actions=tuple(outcomes),
            severity_resolution=severity_resolution,
            eligibility_resolution=eligibility_resolution,
            propagation=CVSSPropagation.NONE,
            products=ProductPropagationSummary(),
            severity_changed=False,
            reconciled=False,
            evaluation_date=evaluation_date,
        )

    if ticket is not None:
        for old_assessment, new_assessment in changes:
            await TicketAuditLog.log_event(
                db,
                ticket_id=ticket.id,
                event_type=TicketAuditEventType.CVSS_ASSESSMENT_CHANGED,
                user_id=None,
                old_value=old_assessment,
                new_value=new_assessment,
            )

    new_severity = (
        severity_resolution.label.value if severity_resolution is not None else None
    )
    old_severity = cve.severity
    severity_changed = old_severity != new_severity
    cve.severity = new_severity
    await db.flush()

    products = ProductPropagationSummary()
    reconciled = False
    if ticket is None:
        propagation = CVSSPropagation.NOT_APPLICABLE
    else:
        if severity_changed:
            await TicketAuditLog.log_event(
                db,
                ticket_id=ticket.id,
                event_type=TicketAuditEventType.SEVERITY_CHANGED,
                user_id=None,
                old_value=old_severity,
                new_value=new_severity,
            )
        if ticket.status in _MANUAL_ZONE:
            propagation = CVSSPropagation.DEFERRED_UNTIL_REACTIVATION
        else:
            propagation = CVSSPropagation.IMMEDIATE
            products = await _propagate_automatic_product_eligibility(
                db,
                ticket=ticket,
                eligibility=eligibility_resolution,
                evaluation_date=evaluation_date,
            )
        await refresh_priority_auto(db, ticket=ticket)
        if ticket.status in _GATE_ZONE and (severity_changed or products.changed > 0):
            await reconcile_ticket_status(ticket, db, evaluation_date=evaluation_date)
            reconciled = True
    await db.flush()

    return ExternalCVSSBatchResult(
        actions=tuple(outcomes),
        severity_resolution=severity_resolution,
        eligibility_resolution=eligibility_resolution,
        propagation=propagation,
        products=products,
        severity_changed=severity_changed,
        reconciled=reconciled,
        evaluation_date=evaluation_date,
    )


def _external_value(candidate: ParsedExternalCVSSAssessment) -> str:
    """The canonical `cvss_assessment_changed` value of a candidate."""
    parsed = candidate.parsed
    return _canonical_assessment_value(
        candidate.provider,
        parsed.version.value,
        parsed.canonical_vector,
        parsed.score,
    )
