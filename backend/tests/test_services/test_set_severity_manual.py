"""Service integration tests for `set_severity_manual()`
(backend/app/services/ticket_mutations.py).

Owning specifications:

- docs/features/tickets/ticket-mutations.md (Transaction ownership;
  Authorization responsibility; Concurrency Control;
  `ensure_ticket_operable()`; Gate-Relevant Mutation Operations;
  `set_severity_manual()`; Auto-Assignment Rule; Architectural Test
  Requirement: manual severity on a CVE-less Ticket, Locked-current
  consumer accessibility, Automatic priority; Service Exceptions).
- docs/features/tickets/ticket-priority.md (Automatic Refresh: Refresh
  Points — Manual severity; Testing Requirement 3).
- docs/features/tickets/ticket-audit-log.md (Event Type Contract:
  `severity_changed`, `priority_changed`, `assignment`, `status_change`;
  ordering rules; Canonical Mutation and No-Event Matrix: Manual severity;
  Cross-Event Ordering; Testing Requirements 1-7, 12, 23, 24, 28).
- docs/features/tickets/tickets.md (Severity Resolution; Mutability Guard;
  Tickets Without CVE).
- docs/features/tickets/ticket-deadlines.md (Testing Requirement 3: the
  `created_at` start is immutable across a severity change).
- docs/features/identity/rbac.md (Scope and Confidential Ticket
  Visibility).
- docs/features/platform/testing-strategy.md (Concurrency Testing; Ticket
  Accessibility: Locked mutations; Audit Trail Testing).

Expected values are transcribed from the specifications, never computed
with the module under test.
"""

from __future__ import annotations

import asyncio
import contextlib
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from datetime import UTC, date, datetime
from typing import Any

import pytest
from sqlalchemy import Delete, Update, delete, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import (
    PackageStatus,
    Role,
    Scope,
    Severity,
    TicketAuditEventType,
    TicketStatus,
)
from app.core.exceptions import (
    SeverityDerivedError,
    TicketNotFoundError,
    TicketNotMutableError,
)
from app.core.identifiers import format_ticket_id
from app.models.cve import CVE
from app.models.product import Product
from app.models.ticket import Ticket
from app.models.ticket_access_grant import TicketAccessGrant
from app.models.ticket_audit_event import TicketAuditEvent
from app.models.ticket_package import TicketPackage
from app.models.ticket_package_maintainer import TicketPackageMaintainer
from app.models.ticket_package_product import TicketPackageProduct
from app.models.ticket_package_track import TicketPackageTrack
from app.models.user import User
from app.models.user_role import UserRole
from app.services import ticket_mutations
from app.services.ticket_audit_log import TicketAuditLog
from app.services.ticket_convergence_registry import (
    TicketConvergenceEffect,
    pending_ticket_convergence_effects,
)
from app.services.ticket_mutations import set_severity_manual
from app.services.ticket_service import resolve_ticket_locator
from app.services.ticket_visibility import TicketCaller
from tests.support.database import assert_lock_wait, rollback_test_scope
from tests.support.ticket_mutations import (
    EVAL,
    EventRow,
    StatementRecorder,
    TicketFactory,
    TreeBuilder,
    VAUser,
    cveless,
    ticket_events,
    ticket_events_by_id,
    tree_for,
    unassigned_event,
)

pytest_plugins = ["tests.support.ticket_mutation_fixtures"]
"""Provides the shared `va_user` and `tree` fixtures."""

CVEFactory = Callable[..., Awaitable[CVE]]

CREATED_AT = datetime(2026, 3, 10, 14, 37, 21, 123456, tzinfo=UTC)
"""A fixed Ticket start with a non-midnight time of day."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _severity_event(actor: User, old: str | None, new: str | None) -> EventRow:
    """The acting-user `severity_changed` event of `set_severity_manual()`."""
    return EventRow("severity_changed", actor.id, old, new, None, None)


def _priority_event(old: str | None, new: str | None) -> EventRow:
    """The system `priority_changed` event of the automatic refresh."""
    return EventRow("priority_changed", None, old, new, None, None)


def _assignment_event(actor: User) -> EventRow:
    """The acting-user auto-assignment of an unassigned Ticket."""
    return EventRow("assignment", actor.id, None, actor.username, None, None)


def _status_event(old: TicketStatus, new: TicketStatus) -> EventRow:
    return EventRow("status_change", None, old.value, new.value, None, None)


def _label(severity: Severity | None) -> str | None:
    """The stored PascalCase label, or SQL `NULL`."""
    return severity.value if severity is not None else None


async def _set(
    db: AsyncSession,
    ticket_id: uuid.UUID,
    severity: Severity | None,
    actor: User,
    *,
    scope: Scope = Scope.ALL,
) -> Ticket:
    """Call the service as an API handler would, with the fixed `EVAL`."""
    return await set_severity_manual(
        db,
        ticket_id=ticket_id,
        severity=severity,
        acting_user_id=actor.id,
        caller=TicketCaller.authenticated(actor.id, scope),
        evaluation_date=EVAL,
    )


async def _state(
    db: AsyncSession, ticket_id: uuid.UUID
) -> tuple[str | None, str, uuid.UUID | None, str | None, str | None]:
    """The persisted `(severity_manual, status, assignee_id, priority_auto,
    priority_override)` of a Ticket."""
    row = (
        await db.execute(
            select(
                Ticket.severity_manual,
                Ticket.status,
                Ticket.assignee_id,
                Ticket.priority_auto,
                Ticket.priority_override,
            ).where(Ticket.id == ticket_id)
        )
    ).one()
    return (
        row.severity_manual,
        row.status,
        row.assignee_id,
        row.priority_auto,
        row.priority_override,
    )


class _CallCounter:
    """Wraps a `ticket_mutations` module function, recording each call."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch, name: str) -> None:
        self.calls: list[dict[str, Any]] = []
        original = getattr(ticket_mutations, name)

        async def _wrapper(*args: Any, **kwargs: Any) -> Any:
            self.calls.append(kwargs)
            return await original(*args, **kwargs)

        monkeypatch.setattr(ticket_mutations, name, _wrapper)


# ---------------------------------------------------------------------------
# Effective set, change, and clear
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestEffectiveMutation:
    @pytest.mark.parametrize(
        ("old", "old_auto", "new", "new_auto"),
        [
            pytest.param(None, None, Severity.HIGH, "P3", id="set"),
            pytest.param(Severity.HIGH, "P3", Severity.LOW, "P4", id="changed"),
            pytest.param(Severity.LOW, "P4", None, None, id="cleared"),
            pytest.param(None, None, Severity.NONE, "P4", id="none-label-set"),
            pytest.param(Severity.NONE, "P4", None, None, id="none-label-cleared"),
        ],
    )
    async def test_writes_severity_then_events_severity_and_priority(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        old: Severity | None,
        old_auto: str | None,
        new: Severity | None,
        new_auto: str | None,
    ) -> None:
        actor = await va_user()
        ticket = await cveless(
            ticket_factory, severity=old, assignee_id=actor.id, priority_auto=old_auto
        )

        result = await _set(db_session, ticket.id, new, actor)

        assert result.id == ticket.id
        assert result.severity_manual == _label(new)
        assert await _state(db_session, ticket.id) == (
            _label(new),
            TicketStatus.ANALYSIS,
            actor.id,
            new_auto,
            None,
        )
        assert await ticket_events(db_session, ticket) == [
            _severity_event(actor, _label(old), _label(new)),
            _priority_event(old_auto, new_auto),
        ]

    async def test_unchanged_effective_priority_adds_no_priority_event(
        self, db_session: AsyncSession, ticket_factory: TicketFactory, va_user: VAUser
    ) -> None:
        actor = await va_user()
        ticket = await cveless(
            ticket_factory,
            severity=Severity.MEDIUM,
            assignee_id=actor.id,
            priority_auto="P4",
        )

        await _set(db_session, ticket.id, Severity.LOW, actor)

        assert (await _state(db_session, ticket.id))[3] == "P4"
        assert await ticket_events(db_session, ticket) == [
            _severity_event(actor, "Medium", "Low")
        ]

    async def test_override_masks_the_automatic_priority_change(
        self, db_session: AsyncSession, ticket_factory: TicketFactory, va_user: VAUser
    ) -> None:
        actor = await va_user()
        ticket = await cveless(
            ticket_factory,
            severity=None,
            assignee_id=actor.id,
            priority_override="P1",
        )

        await _set(db_session, ticket.id, Severity.HIGH, actor)

        assert (await _state(db_session, ticket.id))[3:] == ("P3", "P1")
        assert await ticket_events(db_session, ticket) == [
            _severity_event(actor, None, "High")
        ]

    async def test_created_at_is_unchanged_by_a_severity_change(
        self, db_session: AsyncSession, ticket_factory: TicketFactory, va_user: VAUser
    ) -> None:
        actor = await va_user()
        ticket = await cveless(
            ticket_factory,
            severity=Severity.LOW,
            assignee_id=actor.id,
            created_at=CREATED_AT,
        )

        await _set(db_session, ticket.id, Severity.CRITICAL, actor)

        created_at = (
            await db_session.execute(
                select(Ticket.created_at).where(Ticket.id == ticket.id)
            )
        ).scalar_one()
        assert created_at == CREATED_AT

    async def test_never_commits(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        actor = await va_user()
        ticket = await cveless(ticket_factory, severity=None, assignee_id=actor.id)

        async def forbidden() -> None:
            raise AssertionError("set_severity_manual() must not commit")

        monkeypatch.setattr(db_session, "commit", forbidden)
        monkeypatch.setattr(db_session, "rollback", forbidden)

        await _set(db_session, ticket.id, Severity.HIGH, actor)


# ---------------------------------------------------------------------------
# Same-value no-op
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestNoOp:
    @pytest.mark.parametrize(
        "severity",
        [
            pytest.param(Severity.HIGH, id="label"),
            pytest.param(Severity.NONE, id="none-label"),
            pytest.param(None, id="null"),
        ],
    )
    async def test_same_value_has_no_effect(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        tree: TreeBuilder,
        monkeypatch: pytest.MonkeyPatch,
        severity: Severity | None,
    ) -> None:
        actor = await va_user()
        # A deliberately stale `priority_auto` proves no refresh runs, and an
        # unassigned `New` Ticket with a gate-satisfying tree proves no
        # assignment, promotion, or reconciliation runs.
        ticket = await cveless(
            ticket_factory,
            status=TicketStatus.NEW,
            severity=severity,
            priority_auto="P1",
        )
        await tree(ticket, status=PackageStatus.NOT_AFFECTED)
        assign = _CallCounter(monkeypatch, "auto_assign_actor")
        refresh = _CallCounter(monkeypatch, "refresh_priority_auto")
        reconcile = _CallCounter(monkeypatch, "reconcile_ticket_status")

        with StatementRecorder(db_session) as recorder:
            result = await _set(db_session, ticket.id, severity, actor)

        assert result.id == ticket.id
        assert (assign.calls, refresh.calls, reconcile.calls) == ([], [], [])
        assert recorder.writes() == []
        assert await _state(db_session, ticket.id) == (
            _label(severity),
            TicketStatus.NEW,
            None,
            "P1",
            None,
        )
        assert await ticket_events(db_session, ticket) == []
        assert pending_ticket_convergence_effects(db_session) == ()


# ---------------------------------------------------------------------------
# Rejections: derived severity, manual zone, missing, contract violation
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestRejections:
    @pytest.mark.parametrize(
        "requested",
        [
            pytest.param(Severity.HIGH, id="set"),
            pytest.param(None, id="clear-equals-null-severity-manual"),
        ],
    )
    async def test_cve_ticket_raises_severity_derived(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_factory: CVEFactory,
        va_user: VAUser,
        requested: Severity | None,
    ) -> None:
        """The derived-severity precondition precedes the no-op decision:
        even `None`, equal to the CVE Ticket's NULL `severity_manual`, is
        rejected."""
        actor = await va_user()
        cve = await cve_factory(severity=Severity.LOW.value)
        ticket = await ticket_factory(
            status=TicketStatus.NEW.value, cve_id=cve.id, priority_auto="P4"
        )

        with (
            StatementRecorder(db_session) as recorder,
            pytest.raises(SeverityDerivedError),
        ):
            await _set(db_session, ticket.id, requested, actor)

        assert recorder.writes() == []
        assert await _state(db_session, ticket.id) == (
            None,
            TicketStatus.NEW,
            None,
            "P4",
            None,
        )
        assert await ticket_events(db_session, ticket) == []

    @pytest.mark.parametrize("status", [TicketStatus.IGNORED, TicketStatus.DUPLICATED])
    @pytest.mark.parametrize(
        "requested",
        [
            pytest.param(Severity.HIGH, id="change"),
            pytest.param(Severity.LOW, id="same"),
        ],
    )
    async def test_manual_zone_raises_not_mutable(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        status: TicketStatus,
        requested: Severity,
    ) -> None:
        actor = await va_user()
        ticket = await cveless(
            ticket_factory, status=status, severity=Severity.LOW, priority_auto="P4"
        )

        with (
            StatementRecorder(db_session) as recorder,
            pytest.raises(TicketNotMutableError),
        ):
            await _set(db_session, ticket.id, requested, actor)

        assert recorder.writes() == []
        assert await _state(db_session, ticket.id) == (
            "Low",
            status,
            None,
            "P4",
            None,
        )
        assert await ticket_events(db_session, ticket) == []

    async def test_operability_precedes_derived_severity(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_factory: CVEFactory,
        va_user: VAUser,
    ) -> None:
        actor = await va_user()
        cve = await cve_factory(severity=Severity.HIGH.value)
        ticket = await ticket_factory(status=TicketStatus.IGNORED.value, cve_id=cve.id)

        with pytest.raises(TicketNotMutableError):
            await _set(db_session, ticket.id, Severity.LOW, actor)

        assert await ticket_events(db_session, ticket) == []

    async def test_missing_ticket_raises_not_found(
        self, db_session: AsyncSession, va_user: VAUser
    ) -> None:
        actor = await va_user()

        with (
            StatementRecorder(db_session) as recorder,
            pytest.raises(TicketNotFoundError),
        ):
            await _set(db_session, uuid.uuid7(), Severity.HIGH, actor)

        assert recorder.writes() == []

    async def test_caller_mismatch_raises_before_any_statement(
        self, db_session: AsyncSession, ticket_factory: TicketFactory, va_user: VAUser
    ) -> None:
        actor = await va_user()
        other = await va_user()
        ticket = await cveless(ticket_factory, status=TicketStatus.NEW, severity=None)

        with (
            StatementRecorder(db_session) as recorder,
            pytest.raises(ValueError, match="acting user"),
        ):
            await set_severity_manual(
                db_session,
                ticket_id=ticket.id,
                severity=Severity.HIGH,
                acting_user_id=actor.id,
                caller=TicketCaller.authenticated(other.id, Scope.ALL),
                evaluation_date=EVAL,
            )

        assert recorder.statements == []
        assert await _state(db_session, ticket.id) == (
            None,
            TicketStatus.NEW,
            None,
            None,
            None,
        )
        assert await ticket_events(db_session, ticket) == []


# ---------------------------------------------------------------------------
# Locked-current consumer accessibility (single session)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestAccessibility:
    @pytest.mark.parametrize(
        ("status", "with_cve", "severity", "requested"),
        [
            pytest.param(TicketStatus.NEW, False, None, Severity.HIGH, id="effective"),
            pytest.param(
                TicketStatus.IGNORED, False, None, Severity.HIGH, id="also-ignored"
            ),
            pytest.param(TicketStatus.NEW, True, None, Severity.HIGH, id="also-cve"),
            pytest.param(
                TicketStatus.NEW,
                False,
                Severity.HIGH,
                Severity.HIGH,
                id="also-unchanged",
            ),
        ],
    )
    @pytest.mark.parametrize(
        "roles",
        [
            pytest.param((Role.RESTRICTED_ANALYST,), id="restricted-analyst"),
            # A VA origin committed after the request resolved the caller's
            # `non_confidential` scope: the stabilized User is VA-eligible,
            # so any assignment before the denial would be observable.
            pytest.param((Role.VULNERABILITY_ANALYST,), id="va-after-resolution"),
        ],
    )
    async def test_inaccessible_ticket_is_not_found_before_any_decision(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_factory: CVEFactory,
        ticket_access_grant_factory: Callable[..., Awaitable[TicketAccessGrant]],
        ticket_package_factory: Callable[..., Awaitable[TicketPackage]],
        ticket_package_maintainer_factory: Callable[
            ..., Awaitable[TicketPackageMaintainer]
        ],
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
        status: TicketStatus,
        with_cve: bool,
        severity: Severity | None,
        requested: Severity,
        roles: tuple[Role, ...],
    ) -> None:
        actor = await va_user(roles=roles)
        cve_id = (await cve_factory()).id if with_cve else None
        ticket = await ticket_factory(
            status=status.value,
            is_confidential=True,
            cve_id=cve_id,
            severity_manual=_label(severity),
        )
        # Non-qualifying paths: another user's grant and maintainership, and
        # the caller's maintainership of an excluded package.
        await ticket_access_grant_factory(ticket_id=ticket.id)
        await ticket_package_maintainer_factory(
            ticket_package_id=(await ticket_package_factory(ticket_id=ticket.id)).id
        )
        excluded = await ticket_package_factory(
            ticket_id=ticket.id, deleted_at=datetime.now(UTC)
        )
        await ticket_package_maintainer_factory(
            ticket_package_id=excluded.id, user_id=actor.id
        )
        assign = _CallCounter(monkeypatch, "auto_assign_actor")
        reconcile = _CallCounter(monkeypatch, "reconcile_ticket_status")

        with (
            StatementRecorder(db_session) as recorder,
            pytest.raises(TicketNotFoundError),
        ):
            await _set(
                db_session, ticket.id, requested, actor, scope=Scope.NON_CONFIDENTIAL
            )

        assert (assign.calls, reconcile.calls) == ([], [])
        assert recorder.writes() == []
        assert await _state(db_session, ticket.id) == (
            _label(severity),
            status,
            None,
            None,
            None,
        )
        assert await ticket_events(db_session, ticket) == []
        assert pending_ticket_convergence_effects(db_session) == ()

    async def test_accessible_through_explicit_grant(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        ticket_access_grant_factory: Callable[..., Awaitable[TicketAccessGrant]],
        va_user: VAUser,
    ) -> None:
        actor = await va_user(roles=(Role.RESTRICTED_ANALYST,))
        ticket = await cveless(ticket_factory, severity=None, is_confidential=True)
        await ticket_access_grant_factory(ticket_id=ticket.id, user_id=actor.id)

        await _set(
            db_session, ticket.id, Severity.HIGH, actor, scope=Scope.NON_CONFIDENTIAL
        )

        assert await _state(db_session, ticket.id) == (
            "High",
            TicketStatus.ANALYSIS,
            None,
            "P3",
            None,
        )
        assert await ticket_events(db_session, ticket) == [
            _severity_event(actor, None, "High"),
            _priority_event(None, "P3"),
        ]

    async def test_scope_all_sees_a_confidential_ticket_and_assigns(
        self, db_session: AsyncSession, ticket_factory: TicketFactory, va_user: VAUser
    ) -> None:
        actor = await va_user()
        ticket = await cveless(ticket_factory, severity=None, is_confidential=True)

        await _set(db_session, ticket.id, Severity.HIGH, actor, scope=Scope.ALL)

        assert await ticket_events(db_session, ticket) == [
            _assignment_event(actor),
            _severity_event(actor, None, "High"),
            _priority_event(None, "P3"),
        ]


# ---------------------------------------------------------------------------
# Auto-assignment, sanitation, and exact event order
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestAssignmentAndEventOrder:
    async def test_va_actor_assigns_promotes_and_reaches_the_final_gate(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        tree: TreeBuilder,
    ) -> None:
        actor = await va_user()
        ticket = await cveless(ticket_factory, status=TicketStatus.NEW, severity=None)
        await tree_for(TicketStatus.ANALYZED, ticket, tree)

        await _set(db_session, ticket.id, Severity.HIGH, actor)

        assert await _state(db_session, ticket.id) == (
            "High",
            TicketStatus.ANALYZED,
            actor.id,
            "P3",
            None,
        )
        assert await ticket_events(db_session, ticket) == [
            _assignment_event(actor),
            _status_event(TicketStatus.NEW, TicketStatus.ANALYSIS),
            _severity_event(actor, None, "High"),
            _priority_event(None, "P3"),
            _status_event(TicketStatus.ANALYSIS, TicketStatus.ANALYZED),
        ]
        assert pending_ticket_convergence_effects(db_session) == ()

    @pytest.mark.parametrize(
        ("active", "roles", "reason"),
        [
            pytest.param(
                False, (Role.VULNERABILITY_ANALYST,), "inactive assignee", id="inactive"
            ),
            pytest.param(
                True,
                (Role.RESTRICTED_ANALYST,),
                "vulnerability_analyst role removed",
                id="active-without-va",
            ),
        ],
    )
    @pytest.mark.parametrize("result", [TicketStatus.ANALYSIS, TicketStatus.ANALYZED])
    async def test_sanitation_follows_priority_and_precedes_final_status(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        tree: TreeBuilder,
        active: bool,
        roles: tuple[Role, ...],
        reason: str,
        result: TicketStatus,
    ) -> None:
        actor = await va_user()
        assignee = await va_user(active=active, roles=roles)
        ticket = await cveless(ticket_factory, severity=None, assignee_id=assignee.id)
        await tree_for(result, ticket, tree)

        await _set(db_session, ticket.id, Severity.HIGH, actor)

        final = (
            [_status_event(TicketStatus.ANALYSIS, result)]
            if result is not TicketStatus.ANALYSIS
            else []
        )
        assert await ticket_events(db_session, ticket) == [
            _severity_event(actor, None, "High"),
            _priority_event(None, "P3"),
            unassigned_event(assignee.username, reason),
            *final,
        ]
        assert await _state(db_session, ticket.id) == (
            "High",
            result,
            None,
            "P3",
            None,
        )

    @pytest.mark.parametrize(
        ("active", "roles"),
        [
            pytest.param(True, (Role.RESTRICTED_ANALYST,), id="restricted-analyst"),
        ],
    )
    async def test_ineligible_actor_neither_assigns_nor_leaves_new(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        tree: TreeBuilder,
        active: bool,
        roles: tuple[Role, ...],
    ) -> None:
        actor = await va_user(active=active, roles=roles)
        ticket = await cveless(ticket_factory, status=TicketStatus.NEW, severity=None)
        await tree_for(TicketStatus.RESOLVED, ticket, tree)

        await _set(db_session, ticket.id, Severity.HIGH, actor)

        # Reconciliation skips `New`, even though the gates are satisfied.
        assert await _state(db_session, ticket.id) == (
            "High",
            TicketStatus.NEW,
            None,
            "P3",
            None,
        )
        assert await ticket_events(db_session, ticket) == [
            _severity_event(actor, None, "High"),
            _priority_event(None, "P3"),
        ]
        assert pending_ticket_convergence_effects(db_session) == ()


# ---------------------------------------------------------------------------
# Gate transitions and convergence registration
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestGateTransitions:
    @pytest.mark.parametrize(
        ("current", "old", "new", "tree_result", "expected"),
        [
            pytest.param(
                TicketStatus.ANALYSIS,
                None,
                Severity.HIGH,
                TicketStatus.ANALYZED,
                TicketStatus.ANALYZED,
                id="forward-to-analyzed",
            ),
            pytest.param(
                TicketStatus.ANALYSIS,
                None,
                Severity.NONE,
                TicketStatus.RESOLVED,
                TicketStatus.RESOLVED,
                id="forward-to-resolved",
            ),
            pytest.param(
                TicketStatus.ANALYZED,
                Severity.HIGH,
                None,
                TicketStatus.ANALYZED,
                TicketStatus.ANALYSIS,
                id="backward-analyzed-to-analysis",
            ),
            pytest.param(
                TicketStatus.RESOLVED,
                Severity.HIGH,
                Severity.LOW,
                TicketStatus.RESOLVED,
                TicketStatus.RESOLVED,
                id="resolved-unchanged",
            ),
        ],
    )
    async def test_transition_registers_no_convergence(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        tree: TreeBuilder,
        current: TicketStatus,
        old: Severity | None,
        new: Severity | None,
        tree_result: TicketStatus,
        expected: TicketStatus,
    ) -> None:
        actor = await va_user()
        ticket = await cveless(
            ticket_factory, status=current, severity=old, assignee_id=actor.id
        )
        await tree_for(tree_result, ticket, tree)

        await _set(db_session, ticket.id, new, actor)

        assert (await _state(db_session, ticket.id))[1] == expected
        events = await ticket_events(db_session, ticket)
        assert events[0] == _severity_event(actor, _label(old), _label(new))
        if expected is current:
            assert [
                e.event_type for e in events if e.event_type == "status_change"
            ] == []
        else:
            assert events[-1] == _status_event(current, expected)
        assert pending_ticket_convergence_effects(db_session) == ()

    async def test_resolved_regression_registers_one_convergence_effect(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        tree: TreeBuilder,
    ) -> None:
        actor = await va_user()
        ticket = await cveless(
            ticket_factory,
            status=TicketStatus.RESOLVED,
            severity=Severity.HIGH,
            assignee_id=actor.id,
            priority_auto="P3",
        )
        await tree_for(TicketStatus.RESOLVED, ticket, tree)

        await _set(db_session, ticket.id, None, actor)

        assert await _state(db_session, ticket.id) == (
            None,
            TicketStatus.ANALYSIS,
            actor.id,
            None,
            None,
        )
        assert await ticket_events(db_session, ticket) == [
            _severity_event(actor, "High", None),
            _priority_event("P3", None),
            _status_event(TicketStatus.RESOLVED, TicketStatus.ANALYSIS),
        ]
        assert pending_ticket_convergence_effects(db_session) == (
            TicketConvergenceEffect(ticket.id),
        )


# ---------------------------------------------------------------------------
# One evaluation date
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestEvaluationDate:
    async def test_supplied_date_reaches_reconciliation_without_the_clock(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        def clock() -> datetime:
            raise AssertionError("the supplied date must be reused")

        monkeypatch.setattr(ticket_mutations, "_utc_now", clock)
        reconcile = _CallCounter(monkeypatch, "reconcile_ticket_status")
        actor = await va_user()
        ticket = await cveless(ticket_factory, severity=None, assignee_id=actor.id)
        supplied = date(2026, 1, 2)

        await set_severity_manual(
            db_session,
            ticket_id=ticket.id,
            severity=Severity.HIGH,
            acting_user_id=actor.id,
            caller=TicketCaller.authenticated(actor.id, Scope.ALL),
            evaluation_date=supplied,
        )

        assert reconcile.calls == [{"evaluation_date": supplied}]

    async def test_omitted_date_is_captured_once_at_entry(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        tree: TreeBuilder,
        product_factory: Callable[..., Awaitable[Product]],
        ticket_package_product_factory: Callable[..., Awaitable[TicketPackageProduct]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        day = date(2026, 12, 31)
        instants = iter(
            [
                datetime(2026, 12, 31, 23, 59, 59, 999999, tzinfo=UTC),
                datetime(2027, 1, 1, 0, 0, 0, tzinfo=UTC),
            ]
        )
        calls = 0

        def clock() -> datetime:
            nonlocal calls
            calls += 1
            return next(instants)

        actor = await va_user()
        ticket = await cveless(ticket_factory, severity=None, assignee_id=actor.id)
        # General Support ends on `day`: the AFFECTED track is actionable on
        # `day` (Analyzed) and all-EOL the next day (Resolved).
        track = await tree(ticket, status=PackageStatus.AFFECTED, products=())
        product = await product_factory(general_support_end_date=day)
        await ticket_package_product_factory(
            ticket_package_track_id=track.id, product_id=product.id
        )
        monkeypatch.setattr(ticket_mutations, "_utc_now", clock)
        reconcile = _CallCounter(monkeypatch, "reconcile_ticket_status")

        await set_severity_manual(
            db_session,
            ticket_id=ticket.id,
            severity=Severity.HIGH,
            acting_user_id=actor.id,
            caller=TicketCaller.authenticated(actor.id, Scope.ALL),
        )

        assert calls == 1
        assert reconcile.calls == [{"evaluation_date": day}]
        assert (await _state(db_session, ticket.id))[1] == TicketStatus.ANALYZED


# ---------------------------------------------------------------------------
# Lock order and locked-current revalidation statement
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestLockOrder:
    async def test_user_share_then_ticket_update_then_visibility(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        ticket_access_grant_factory: Callable[..., Awaitable[TicketAccessGrant]],
        va_user: VAUser,
    ) -> None:
        actor = await va_user(roles=(Role.RESTRICTED_ANALYST,))
        ticket = await cveless(ticket_factory, severity=None, is_confidential=True)
        await ticket_access_grant_factory(ticket_id=ticket.id, user_id=actor.id)

        with StatementRecorder(db_session) as recorder:
            await _set(
                db_session,
                ticket.id,
                Severity.HIGH,
                actor,
                scope=Scope.NON_CONFIDENTIAL,
            )

        statements = recorder.statements

        def first(predicate: Callable[[str], bool]) -> int:
            return next(i for i, s in enumerate(statements) if predicate(s))

        user_share = first(lambda s: 'FROM "user"' in s and "FOR SHARE" in s)
        ticket_lock = first(lambda s: "FROM ticket" in s and "FOR UPDATE" in s)
        visibility = first(lambda s: "ticket_access_grant" in s)
        assert user_share < ticket_lock < visibility
        # The accessibility decision is a separate statement issued after
        # the lock is granted, not a predicate of the locking statement.
        assert "ticket_access_grant" not in statements[ticket_lock]
        assert "is_confidential" not in statements[ticket_lock].split("WHERE")[-1]
        assert len(recorder.row_locks()) == 2
        assert recorder.selects_from("ticket_audit_event") == []


# ---------------------------------------------------------------------------
# Whole-operation rollback (audit Testing Requirements 7 and 24)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestRollback:
    @pytest.mark.parametrize(
        "failure", ["severity-audit", "refresh-flush", "reconciliation"]
    )
    async def test_failure_rolls_back_every_effect(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        tree: TreeBuilder,
        monkeypatch: pytest.MonkeyPatch,
        failure: str,
    ) -> None:
        actor = await va_user()
        ticket = await cveless(ticket_factory, status=TicketStatus.NEW, severity=None)
        await tree_for(TicketStatus.ANALYZED, ticket, tree)
        flushes_in_refresh = 0

        async with rollback_test_scope(db_session):
            if failure == "severity-audit":
                original_log = TicketAuditLog.log_event

                async def failing_log(*args: Any, **kwargs: Any) -> None:
                    if kwargs["event_type"] is TicketAuditEventType.SEVERITY_CHANGED:
                        raise RuntimeError("injected audit failure")
                    await original_log(*args, **kwargs)

                monkeypatch.setattr(TicketAuditLog, "log_event", failing_log)
            elif failure == "refresh-flush":
                original_refresh = ticket_mutations.refresh_priority_auto
                original_flush = db_session.flush
                inside = False

                async def tracking_refresh(db: AsyncSession, *, ticket: Ticket) -> bool:
                    nonlocal inside
                    inside = True
                    try:
                        return await original_refresh(db, ticket=ticket)
                    finally:
                        inside = False

                async def failing_flush(*args: Any, **kwargs: Any) -> None:
                    nonlocal flushes_in_refresh
                    if inside:
                        flushes_in_refresh += 1
                        # The first flush inside the refresh inserts the
                        # `priority_changed` event; fail its final flush.
                        if flushes_in_refresh == 2:
                            raise RuntimeError("injected flush failure")
                    await original_flush(*args, **kwargs)

                monkeypatch.setattr(
                    ticket_mutations, "refresh_priority_auto", tracking_refresh
                )
                monkeypatch.setattr(db_session, "flush", failing_flush)
            else:
                original_reconcile = ticket_mutations.reconcile_ticket_status

                async def failing_reconcile(*args: Any, **kwargs: Any) -> None:
                    await original_reconcile(*args, **kwargs)
                    raise RuntimeError("injected reconciliation failure")

                monkeypatch.setattr(
                    ticket_mutations, "reconcile_ticket_status", failing_reconcile
                )

            with pytest.raises(RuntimeError, match="injected"):
                await _set(db_session, ticket.id, Severity.HIGH, actor)
        monkeypatch.undo()

        if failure == "refresh-flush":
            assert flushes_in_refresh == 2
        await db_session.refresh(ticket)
        assert await _state(db_session, ticket.id) == (
            None,
            TicketStatus.NEW,
            None,
            None,
            None,
        )
        assert await ticket_events(db_session, ticket) == []
        assert pending_ticket_convergence_effects(db_session) == ()


# ---------------------------------------------------------------------------
# Locked-current accessibility races (independent sessions)
# ---------------------------------------------------------------------------


class _CommittedWorld:
    """Committed setup rows for independent-session tests, deleted
    explicitly at teardown (testing-strategy.md, Concurrency Testing).

    The world also owns the racing sessions and tasks of a test, so that
    teardown releases their row locks before deleting: a failed assertion
    must fail the test, never leave the cleanup waiting on a lock held by
    an open transaction.
    """

    def __init__(
        self, factory: Callable[[], Awaitable[AsyncSession]], session: AsyncSession
    ) -> None:
        self._factory = factory
        self.session = session
        self.ticket_ids: list[uuid.UUID] = []
        self.user_ids: list[uuid.UUID] = []
        self._sessions: list[AsyncSession] = []
        self._tasks: list[tuple[AsyncSession, asyncio.Task[Any]]] = []

    async def open_session(self) -> AsyncSession:
        """An independent session released before the cleanup."""
        session = await self._factory()
        self._sessions.append(session)
        return session

    def track(self, session: AsyncSession, task: asyncio.Task[Ticket]) -> None:
        self._tasks.append((session, task))

    async def _release(self) -> None:
        busy = {id(s) for s, task in self._tasks if not task.done()}
        for session in self._sessions:
            if id(session) not in busy:
                with contextlib.suppress(Exception):
                    await session.rollback()
        for session, task in self._tasks:
            if not task.done():
                try:
                    await asyncio.wait_for(task, timeout=5)
                except Exception, asyncio.CancelledError:
                    task.cancel()
            with contextlib.suppress(Exception, asyncio.CancelledError):
                await task
            with contextlib.suppress(Exception):
                await session.rollback()

    async def user(self, *, role: Role) -> User:
        prefix = "alice.ra" if role is Role.RESTRICTED_ANALYST else "bob.va"
        suffix = uuid.uuid4().hex[:10]
        user = User(
            username=f"{prefix}.{suffix}",
            email=f"{prefix}.{suffix}@example.com",
            password_hash="$2b$12$" + "r" * 53,
        )
        self.session.add(user)
        await self.session.flush()
        self.user_ids.append(user.id)
        self.session.add(UserRole(user_id=user.id, role=role.value))
        await self.session.commit()
        return user

    async def ticket(self, *, is_confidential: bool) -> Ticket:
        ticket = Ticket(
            status=TicketStatus.ANALYSIS.value, is_confidential=is_confidential
        )
        self.session.add(ticket)
        await self.session.flush()
        self.ticket_ids.append(ticket.id)
        await self.session.commit()
        return ticket

    async def grant(self, ticket: Ticket, user: User, granter: User) -> None:
        self.session.add(
            TicketAccessGrant(
                ticket_id=ticket.id, user_id=user.id, granted_by_id=granter.id
            )
        )
        await self.session.commit()

    async def maintained_package(
        self, ticket: Ticket, maintainer: User, name: str
    ) -> TicketPackage:
        package = TicketPackage(ticket_id=ticket.id, package_name=name)
        self.session.add(package)
        await self.session.flush()
        self.session.add(
            TicketPackageMaintainer(ticket_package_id=package.id, user_id=maintainer.id)
        )
        await self.session.commit()
        return package

    async def cleanup(self) -> None:
        await self._release()
        await self.session.rollback()
        packages = select(TicketPackage.id).where(
            TicketPackage.ticket_id.in_(self.ticket_ids)
        )
        for statement in (
            delete(TicketAuditEvent).where(
                TicketAuditEvent.ticket_id.in_(self.ticket_ids)
            ),
            delete(TicketPackageTrack).where(
                TicketPackageTrack.ticket_package_id.in_(packages)
            ),
            delete(TicketPackageMaintainer).where(
                TicketPackageMaintainer.ticket_package_id.in_(packages)
            ),
            delete(TicketPackage).where(TicketPackage.ticket_id.in_(self.ticket_ids)),
            delete(TicketAccessGrant).where(
                TicketAccessGrant.ticket_id.in_(self.ticket_ids)
            ),
            delete(Ticket).where(Ticket.id.in_(self.ticket_ids)),
            delete(UserRole).where(UserRole.user_id.in_(self.user_ids)),
            delete(User).where(User.id.in_(self.user_ids)),
        ):
            await self.session.execute(statement)
        await self.session.commit()


@pytest.fixture
async def committed_world(
    db_session_factory: Callable[[], Awaitable[AsyncSession]],
) -> AsyncIterator[_CommittedWorld]:
    world = _CommittedWorld(db_session_factory, await db_session_factory())
    try:
        yield world
    finally:
        await world.cleanup()


VISIBILITY_LOSSES = ["confidentiality-set", "grant-revoked", "last-package-excluded"]


async def _prepare_loss(
    world: _CommittedWorld, loss: str
) -> tuple[User, Ticket, Update | Delete]:
    """Commit a Ticket visible to a `restricted_analyst` caller through
    exactly one path, and return the statement that removes that path."""
    user = await world.user(role=Role.RESTRICTED_ANALYST)
    if loss == "confidentiality-set":
        ticket = await world.ticket(is_confidential=False)
        return (
            user,
            ticket,
            update(Ticket).where(Ticket.id == ticket.id).values(is_confidential=True),
        )
    ticket = await world.ticket(is_confidential=True)
    if loss == "grant-revoked":
        granter = await world.user(role=Role.VULNERABILITY_ANALYST)
        await world.grant(ticket, user, granter)
        return (
            user,
            ticket,
            delete(TicketAccessGrant).where(
                TicketAccessGrant.ticket_id == ticket.id,
                TicketAccessGrant.user_id == user.id,
            ),
        )
    package = await world.maintained_package(ticket, user, "fictional-race-a")
    return (
        user,
        ticket,
        update(TicketPackage)
        .where(TicketPackage.id == package.id)
        .values(deleted_at=datetime.now(UTC)),
    )


async def _lock_and_apply(
    session: AsyncSession, ticket: Ticket, change: Update | Delete
) -> None:
    await session.execute(
        select(Ticket.id).where(Ticket.id == ticket.id).with_for_update()
    )
    await session.execute(change)


def _start(
    world: _CommittedWorld, session: AsyncSession, ticket: Ticket, user: User
) -> asyncio.Task[Ticket]:
    task = asyncio.create_task(
        set_severity_manual(
            session,
            ticket_id=ticket.id,
            severity=Severity.HIGH,
            acting_user_id=user.id,
            caller=TicketCaller.authenticated(user.id, Scope.NON_CONFIDENTIAL),
            evaluation_date=EVAL,
        )
    )
    world.track(session, task)
    return task


async def _assert_untouched(world: _CommittedWorld, ticket: Ticket) -> None:
    fresh = await world.open_session()
    assert await _state(fresh, ticket.id) == (
        None,
        TicketStatus.ANALYSIS,
        None,
        None,
        None,
    )
    assert await ticket_events_by_id(fresh, ticket.id) == []
    total = (
        await fresh.execute(
            select(func.count())
            .select_from(TicketAuditEvent)
            .where(TicketAuditEvent.ticket_id == ticket.id)
        )
    ).scalar_one()
    assert total == 0
    await fresh.rollback()


@pytest.mark.integration
class TestLockedCurrentAccessibilityRaces:
    """Session A passes the preliminary locator check; session B then
    holds the Ticket `FOR UPDATE` and removes A's only visibility path. A's
    mutation is proven blocked on the Ticket lock, B commits, and A must be
    denied from the locked-current state with zero side effects
    (testing-strategy.md, Ticket Accessibility: Locked mutations)."""

    @pytest.mark.parametrize("loss", VISIBILITY_LOSSES)
    async def test_visibility_lost_while_waiting_for_the_lock_is_denied(
        self,
        committed_world: _CommittedWorld,
        monkeypatch: pytest.MonkeyPatch,
        loss: str,
    ) -> None:
        user, ticket, change = await _prepare_loss(committed_world, loss)
        a = await committed_world.open_session()
        b = await committed_world.open_session()
        caller = TicketCaller.authenticated(user.id, Scope.NON_CONFIDENTIAL)
        assign = _CallCounter(monkeypatch, "auto_assign_actor")
        reconcile = _CallCounter(monkeypatch, "reconcile_ticket_status")

        resolved = await resolve_ticket_locator(
            a, format_ticket_id(ticket.sequence_id), caller
        )
        assert resolved.id == ticket.id
        await _lock_and_apply(b, ticket, change)
        task = _start(committed_world, a, ticket, user)
        await assert_lock_wait(task, waiter=a, blocked_by=b)
        await b.commit()

        with pytest.raises(TicketNotFoundError):
            await asyncio.wait_for(task, timeout=5)

        assert (assign.calls, reconcile.calls) == ([], [])
        assert pending_ticket_convergence_effects(a) == ()
        await a.rollback()
        await _assert_untouched(committed_world, ticket)

    async def test_remaining_included_package_keeps_access_after_the_wait(
        self, committed_world: _CommittedWorld
    ) -> None:
        """Converse: excluding one of two included maintained packages does
        not remove visibility, so A succeeds once B commits."""
        user = await committed_world.user(role=Role.RESTRICTED_ANALYST)
        ticket = await committed_world.ticket(is_confidential=True)
        first = await committed_world.maintained_package(
            ticket, user, "fictional-race-a"
        )
        await committed_world.maintained_package(ticket, user, "fictional-race-b")
        a = await committed_world.open_session()
        b = await committed_world.open_session()

        await _lock_and_apply(
            b,
            ticket,
            update(TicketPackage)
            .where(TicketPackage.id == first.id)
            .values(deleted_at=datetime.now(UTC)),
        )
        task = _start(committed_world, a, ticket, user)
        await assert_lock_wait(task, waiter=a, blocked_by=b)
        await b.commit()

        result = await asyncio.wait_for(task, timeout=5)

        assert result.severity_manual == "High"
        assert await _state(a, ticket.id) == (
            "High",
            TicketStatus.ANALYSIS,
            None,
            "P3",
            None,
        )
        assert await ticket_events_by_id(a, ticket.id) == [
            _severity_event(user, None, "High"),
            _priority_event(None, "P3"),
        ]
        await a.rollback()

    async def test_status_committed_while_waiting_is_the_locked_current_state(
        self, committed_world: _CommittedWorld, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Operability is decided from locked-current state: A already holds
        a stale identity-map copy of the Ticket (`Analysis`) when B, holding
        the lock, moves it to `Ignored` without touching visibility. After
        B commits, A must observe `Ignored` under its lock and be rejected
        with zero side effects."""
        user = await committed_world.user(role=Role.RESTRICTED_ANALYST)
        ticket = await committed_world.ticket(is_confidential=False)
        a = await committed_world.open_session()
        b = await committed_world.open_session()
        assign = _CallCounter(monkeypatch, "auto_assign_actor")
        reconcile = _CallCounter(monkeypatch, "reconcile_ticket_status")

        stale = await a.get(Ticket, ticket.id)
        assert stale is not None
        assert stale.status == TicketStatus.ANALYSIS.value
        await _lock_and_apply(
            b,
            ticket,
            update(Ticket)
            .where(Ticket.id == ticket.id)
            .values(status=TicketStatus.IGNORED.value),
        )
        task = _start(committed_world, a, ticket, user)
        await assert_lock_wait(task, waiter=a, blocked_by=b)
        await b.commit()

        with pytest.raises(TicketNotMutableError):
            await asyncio.wait_for(task, timeout=5)

        assert (assign.calls, reconcile.calls) == ([], [])
        await a.rollback()
        fresh = await committed_world.open_session()
        assert await _state(fresh, ticket.id) == (
            None,
            TicketStatus.IGNORED,
            None,
            None,
            None,
        )
        assert await ticket_events_by_id(fresh, ticket.id) == []
        await fresh.rollback()
