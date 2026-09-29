"""Single-session service tests for `associate_cve()`
(backend/app/services/ticket_service.py).

Owning specifications:

- docs/features/tickets/ticket-service.md (Acting user convention; Caller
  category and Ticket accessibility; Operability guard; Concurrency
  control; `associate_cve`; Service Exceptions; Architectural Test
  Requirement 1, 9 (single-session part), 15 (single-session part), 19).
- docs/features/tickets/ticket-mutations.md (`recalculate_cvss_chain()`:
  association mode; `reconcile_ticket_status()`; Architectural Test
  Requirement: Composed workflows, Complete atomic chain).
- docs/features/tickets/ticket-audit-log.md (Event Type Contract:
  `cve_associated`, `severity_changed`, `product_eligibility_changed`,
  `priority_changed`, `assignment`, `status_change`; Canonical Mutation
  and No-Event Matrix: CVE association; Cross-Event Ordering; detail JSONB
  Schema Contract; Testing Requirements 1-6, 8, 10, 16, 17, 20, 23, 28;
  the rollback requirements 7 and 24 are proven in
  `tests/test_services/test_associate_cve_atomicity.py`).
- docs/features/tickets/ticket-priority.md (Refresh Points: CVE
  association; Testing Requirement 3).
- docs/features/tickets/ticket-deadlines.md (Due Dates: Formula; SLA Tier;
  Testing Requirement 3, CVE association).
- docs/features/packages/package-model.md (Axis 2: Eligibility; Override
  Model).
- docs/features/platform/testing-strategy.md (Ticket Accessibility; Audit
  Trail Testing; Concurrency Testing).

The independent-session races (CVSS mutation, locked-current visibility
changes) are not part of this module. Step 14 of the specification (the
CVE freshness refresh) is not implemented and is neither tested nor
expected here.

Expected values are transcribed from the specifications, never computed
with the module under test.
"""

from __future__ import annotations

import json
import re
import socket
import uuid
from collections.abc import Awaitable, Callable
from datetime import UTC, date, datetime, timedelta, timezone
from decimal import Decimal
from types import ModuleType
from typing import Any

import httpx
import pytest
from celery import Celery
from celery.app.task import Task
from redis.asyncio import Redis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import (
    PackageStatus,
    Role,
    Scope,
    Severity,
    TicketAuditEventType,
    TicketStatus,
)
from app.core.exceptions import TicketNotFoundError, TicketNotMutableError
from app.core.identifiers import format_ticket_id
from app.models.cve import CVE
from app.models.product import Product
from app.models.system_setting import SystemSetting
from app.models.ticket import Ticket
from app.models.ticket_access_grant import TicketAccessGrant
from app.models.ticket_package import TicketPackage
from app.models.ticket_package_maintainer import TicketPackageMaintainer
from app.models.ticket_package_product import TicketPackageProduct
from app.models.ticket_package_track import TicketPackageTrack
from app.models.user import User
from app.services import ticket_mutations, ticket_service
from app.services.cve_service import CVEIdFormatError
from app.services.ticket_audit_log import list_ticket_events
from app.services.ticket_convergence_registry import (
    TicketConvergenceEffect,
    pending_ticket_convergence_effects,
)
from app.services.ticket_deadline_expressions import ticket_due_date_expressions
from app.services.ticket_mutations import CVSSChainMode
from app.services.ticket_service import (
    TicketCVEAlreadySetError,
    TicketCVEConflictError,
    associate_cve,
)
from app.services.ticket_visibility import TicketCaller
from tests.support.cvss_chain import (
    DEFAULT_VERSION,
    Assessment,
    CVEBuilder,
    cve_severity,
    eligibility,
    label,
    priority_event,
    product_event,
    severity_event,
    subjects,
)
from tests.support.database import rollback_test_scope
from tests.support.ticket_mutations import (
    AFTER_EVAL,
    EVAL,
    EventRow,
    Prod,
    StatementRecorder,
    TicketFactory,
    TreeBuilder,
    VAUser,
    cveless,
    status_event,
    ticket_events,
    ticket_events_by_id,
    tree_for,
    unassigned_event,
)

pytest_plugins = ["tests.support.ticket_mutation_fixtures"]
"""Provides the shared `va_user`, `tree`, and `cve_with` fixtures."""

Factory = Callable[..., Awaitable[Any]]

CREATED_AT = datetime(2026, 3, 10, 14, 37, 21, 123456, tzinfo=UTC)
"""A fixed Ticket start with a non-midnight time of day."""

NEW_CVE_ID = "CVE-2099-0201"
"""A CVE-ID with no row: association inserts a placeholder."""

SUSE_CRITICAL = Assessment("9.8")
"""A canonical SUSE assessment at the default version: `Critical`, `P2`."""

SUSE_HIGH = Assessment("7.5")
"""A canonical SUSE assessment at the default version: `High`, `P3`."""

T99 = Decimal("9.9")
"""A Product threshold above 9.8 and below the 10.0 fallback."""

CVE_STATEMENT = re.compile(r"\b(?:FROM|JOIN|INTO|UPDATE) cve\b")
TICKET_STATEMENT = re.compile(r"\b(?:FROM|JOIN|INTO|UPDATE) ticket\b")

UUID_TEXT = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)

TIER_OFFSETS_DAYS: dict[int, tuple[int, int, int, int, int]] = {
    30: (3, 18, 21, 30, 30),
    90: (9, 54, 63, 90, 90),
    180: (18, 108, 126, 180, 180),
}
"""ticket-deadlines.md, Due Dates: Formula. `(triage, submission, um, qa,
release)` offsets in days from `created_at`, per SLA tier."""


@pytest.fixture(autouse=True)
async def default_setting(
    system_setting_factory: Callable[..., Awaitable[SystemSetting]],
) -> SystemSetting:
    """The persisted `default_cvss_version` (the test schema has none)."""
    return await system_setting_factory(
        key="default_cvss_version", value=DEFAULT_VERSION
    )


@pytest.fixture
def no_external_io(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fail on any new socket, HTTP, Redis, or Celery operation (the test
    database connection is already established)."""

    def forbidden(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("associate_cve() must perform no external I/O")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(httpx.AsyncClient, "send", forbidden)
    monkeypatch.setattr(httpx.Client, "send", forbidden)
    monkeypatch.setattr(Redis, "execute_command", forbidden)
    monkeypatch.setattr(Celery, "send_task", forbidden)
    monkeypatch.setattr(Task, "apply_async", forbidden)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _Spy:
    """Wraps an async module function, recording each call's arguments."""

    def __init__(
        self, monkeypatch: pytest.MonkeyPatch, module: ModuleType, name: str
    ) -> None:
        self.calls: list[dict[str, Any]] = []
        original = getattr(module, name)

        async def _wrapper(*args: Any, **kwargs: Any) -> Any:
            self.calls.append(kwargs)
            return await original(*args, **kwargs)

        monkeypatch.setattr(module, name, _wrapper)


async def _associate(
    db: AsyncSession,
    ticket_id: uuid.UUID,
    cve_id: str,
    actor: User,
    *,
    scope: Scope = Scope.ALL,
    evaluation_date: date | None = EVAL,
) -> Ticket:
    """Call the service as an API handler would (fixed `EVAL` by default;
    `None` omits the date)."""
    return await associate_cve(
        db,
        ticket_id=ticket_id,
        cve_id=cve_id,
        acting_user_id=actor.id,
        caller=TicketCaller.authenticated(actor.id, scope),
        evaluation_date=evaluation_date,
    )


async def _state(
    db: AsyncSession, ticket_id: uuid.UUID
) -> tuple[str, uuid.UUID | None, uuid.UUID | None, str | None, str | None, str | None]:
    """The persisted `(status, assignee_id, cve_id, severity_manual,
    priority_auto, priority_override)` of a Ticket."""
    row = (
        await db.execute(
            select(
                Ticket.status,
                Ticket.assignee_id,
                Ticket.cve_id,
                Ticket.severity_manual,
                Ticket.priority_auto,
                Ticket.priority_override,
            ).where(Ticket.id == ticket_id)
        )
    ).one()
    return (
        row.status,
        row.assignee_id,
        row.cve_id,
        row.severity_manual,
        row.priority_auto,
        row.priority_override,
    )


async def _cve_row(db: AsyncSession, cve_id: str) -> CVE | None:
    return (
        await db.execute(
            select(CVE)
            .where(CVE.cve_id == cve_id)
            .execution_options(populate_existing=True)
        )
    ).scalar_one_or_none()


async def _world(
    db: AsyncSession, ticket_id: uuid.UUID, *, with_cves: bool = True
) -> tuple[Any, ...]:
    """Everything a rejected call must leave unchanged: the Ticket row, its
    events and Product eligibility, and (optionally) every CVE row."""
    ticket = (
        await db.execute(
            select(
                Ticket.status,
                Ticket.assignee_id,
                Ticket.cve_id,
                Ticket.severity_manual,
                Ticket.priority_auto,
                Ticket.priority_override,
                Ticket.created_at,
            ).where(Ticket.id == ticket_id)
        )
    ).one_or_none()
    cves = (
        (
            await db.execute(
                select(CVE.cve_id, CVE.severity, CVE.cve_state).order_by(CVE.cve_id)
            )
        ).all()
        if with_cves
        else []
    )
    return (
        tuple(ticket) if ticket is not None else None,
        await ticket_events_by_id(db, ticket_id),
        await eligibility(db, ticket_id),
        [tuple(row) for row in cves],
    )


def _assoc_event(actor: User, cve_id: str) -> EventRow:
    """The acting-user `cve_associated` event."""
    return EventRow("cve_associated", actor.id, None, cve_id, None, None)


def _assignment_event(actor: User) -> EventRow:
    """The acting-user auto-assignment of an unassigned Ticket."""
    return EventRow("assignment", actor.id, None, actor.username, None, None)


def _first(statements: list[str], predicate: Callable[[str], bool]) -> int:
    return next(i for i, s in enumerate(statements) if predicate(s))


def _is_user_share(statement: str) -> bool:
    return 'FROM "user"' in statement and "FOR SHARE" in statement


def _root_order(statements: list[str]) -> tuple[int, int, int]:
    """Indexes of the acting-User `FOR SHARE`, the first statement touching
    the CVE, and the first statement touching the Ticket."""
    return (
        _first(statements, _is_user_share),
        _first(statements, lambda s: CVE_STATEMENT.search(s) is not None),
        _first(statements, lambda s: TICKET_STATEMENT.search(s) is not None),
    )


class _Denial:
    """The outcome of a rejected call."""

    def __init__(self, error: Any, statements: list[str]) -> None:
        self.error = error
        self.statements = statements


async def _denied(
    db: AsyncSession,
    error_type: type[Exception],
    *,
    ticket_id: uuid.UUID,
    cve_id: str,
    actor: User,
    scope: Scope = Scope.ALL,
) -> _Denial:
    """Call the service inside a rolled-back scope (the caller owns the
    transaction: a placeholder CVE this call inserted is rolled back with
    it) and assert the zero-side-effect contract of a rejected call: no
    event, no assignment, no registered convergence effect, and every
    Ticket, Product, and CVE row unchanged, including no surviving
    placeholder CVE."""
    before = await _world(db, ticket_id)
    async with rollback_test_scope(db):
        with StatementRecorder(db) as recorder, pytest.raises(error_type) as raised:
            await _associate(db, ticket_id, cve_id, actor, scope=scope)
        assert pending_ticket_convergence_effects(db) == ()
        statements = list(recorder.statements)
        # Before the caller's rollback: nothing but a placeholder CVE was
        # written, so no assignment, event, or Ticket write preceded the
        # rejection.
        writes = [
            w
            for w in recorder.writes()
            if not w.startswith(("SAVEPOINT", "RELEASE SAVEPOINT", "ROLLBACK"))
        ]
        assert all(w.startswith("INSERT INTO cve ") for w in writes), writes
        assert len(writes) <= 1
        assert (await _world(db, ticket_id, with_cves=False))[:3] == before[:3]
    assert await _world(db, ticket_id) == before
    return _Denial(raised.value, statements)


# ---------------------------------------------------------------------------
# ATR 1: CVE association causes status regression
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestStatusRegression:
    @pytest.mark.parametrize("cve_kind", ["existing-empty", "placeholder"])
    async def test_empty_assessment_set_regresses_analyzed_to_analysis(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_with: CVEBuilder,
        va_user: VAUser,
        tree: TreeBuilder,
        cve_kind: str,
    ) -> None:
        actor = await va_user()
        ticket = await cveless(
            ticket_factory,
            status=TicketStatus.ANALYZED,
            severity=Severity.HIGH,
            assignee_id=actor.id,
            priority_auto="P3",
        )
        # The first occurrence is ineligible with a threshold of exactly
        # 10.0: only the 10.0 fallback score makes it eligible.
        await tree(
            ticket,
            status=PackageStatus.AFFECTED,
            products=(
                Prod(eligible=False, threshold=Decimal("10.0")),
                Prod(eligible=True),
            ),
        )
        if cve_kind == "existing-empty":
            cve_id = (await cve_with(severity=None)).cve_id
        else:
            cve_id = NEW_CVE_ID
        subject = (await subjects(db_session, ticket.id))[0]

        result = await _associate(db_session, ticket.id, cve_id, actor)

        cve = await _cve_row(db_session, cve_id)
        assert cve is not None
        assert cve.severity is None
        assert result.id == ticket.id
        assert await _state(db_session, ticket.id) == (
            TicketStatus.ANALYSIS,
            actor.id,
            cve.id,
            None,
            None,
            None,
        )
        assert await eligibility(db_session, ticket.id) == [(True, False)] * 2
        assert await ticket_events(db_session, ticket) == [
            _assoc_event(actor, cve_id),
            severity_event("High", None),
            product_event(subject, False, True),
            priority_event("P3", None),
            status_event("Analyzed", "Analysis"),
        ]
        # An Analyzed regression is not a convergence trigger.
        assert pending_ticket_convergence_effects(db_session) == ()


# ---------------------------------------------------------------------------
# Composed workflow (ticket-mutations.md, Composed workflows)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestComposedWorkflow:
    async def test_pre_existing_assessments_products_and_one_reconciliation(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_with: CVEBuilder,
        va_user: VAUser,
        product_factory: Callable[..., Awaitable[Product]],
        ticket_package_factory: Callable[..., Awaitable[TicketPackage]],
        ticket_package_track_factory: Callable[..., Awaitable[TicketPackageTrack]],
        ticket_package_product_factory: Callable[..., Awaitable[TicketPackageProduct]],
        monkeypatch: pytest.MonkeyPatch,
        no_external_io: None,
    ) -> None:
        actor = await va_user()
        # A stale persisted severity: the chain recomputes it from the
        # committed assessments.
        cve = await cve_with(SUSE_CRITICAL, severity=Severity.LOW)
        ticket = await ticket_factory(
            status=TicketStatus.NEW.value,
            severity_manual=Severity.MEDIUM.value,
            priority_auto="P4",
        )
        alpha = await ticket_package_factory(
            ticket_id=ticket.id, package_name="fictional-alpha"
        )
        beta = await ticket_package_factory(
            ticket_id=ticket.id, package_name="fictional-beta"
        )
        alpha_update = await ticket_package_track_factory(
            ticket_package_id=alpha.id,
            reference="Example:Alpha:Update",
            status=PackageStatus.AFFECTED.value,
        )
        beta_update = await ticket_package_track_factory(
            ticket_package_id=beta.id,
            reference="Example:Beta:Update",
            status=PackageStatus.AFFECTED.value,
        )
        beta_next = await ticket_package_track_factory(
            ticket_package_id=beta.id,
            reference="Example:Beta:Next",
            status=PackageStatus.AFFECTED.value,
        )
        ids = sorted(uuid.uuid7() for _ in range(5))
        # Creation order differs from occurrence-ID order across tracks and
        # packages. `(id, track, n, eligible, override, threshold)`.
        placements = [
            (ids[3], beta_next, 1, False, False, None),  # -> true, event
            (ids[0], beta_update, 2, True, False, T99),  # -> false, event
            (ids[4], alpha_update, 3, False, True, None),  # override skip
            (ids[1], alpha_update, 4, True, False, None),  # unchanged
            (ids[2], alpha_update, 5, True, True, T99),  # override skip
        ]
        for occurrence_id, track, n, eligible, override, threshold in placements:
            product = await product_factory(
                name=f"fictional-short-{n}",
                display_name=f"Fictional Server {n}",
                cpe=f"cpe:/o:example:fictional_server:{n}",
                general_support_end_date=AFTER_EVAL,
                cvss_threshold=threshold,
            )
            await ticket_package_product_factory(
                id=occurrence_id,
                ticket_package_track_id=track.id,
                product_id=product.id,
                eligible=eligible,
                is_eligible_override=override,
            )
        chain = _Spy(monkeypatch, ticket_service, "recalculate_cvss_chain")
        reconcile = _Spy(monkeypatch, ticket_service, "reconcile_ticket_status")
        assign = _Spy(monkeypatch, ticket_service, "auto_assign_actor")
        inner_reconcile = _Spy(monkeypatch, ticket_mutations, "reconcile_ticket_status")
        inner_assign = _Spy(monkeypatch, ticket_mutations, "auto_assign_actor")

        await _associate(db_session, ticket.id, cve.cve_id, actor)

        def subject(track: str, package: str, n: int) -> dict[str, str]:
            return {
                "track": track,
                "package": package,
                "product_name": f"Fictional Server {n}",
                "product_cpe": f"cpe:/o:example:fictional_server:{n}",
                "reason": "cvss",
            }

        assert await cve_severity(db_session, cve.id) == "Critical"
        # In ascending occurrence-ID order; overrides keep both fields.
        assert await eligibility(db_session, ticket.id) == [
            (False, False),
            (True, False),
            (True, True),
            (True, False),
            (False, True),
        ]
        assert await ticket_events(db_session, ticket) == [
            _assignment_event(actor),
            status_event("New", "Analysis"),
            _assoc_event(actor, cve.cve_id),
            severity_event("Medium", "Critical"),
            product_event(
                subject("Example:Beta:Update", "fictional-beta", 2), True, False
            ),
            product_event(
                subject("Example:Beta:Next", "fictional-beta", 1), False, True
            ),
            priority_event("P4", "P2"),
            status_event("Analysis", "Analyzed"),
        ]
        assert chain.calls == [
            {
                "cve_id": cve.id,
                "mode": CVSSChainMode.ASSOCIATION,
                "association_previous_severity": Severity.MEDIUM,
                "evaluation_date": EVAL,
            }
        ]
        # One assignment step and one final reconciliation, both owned by
        # the service; the chain performs neither.
        assert len(assign.calls) == 1
        assert len(reconcile.calls) == 1
        assert reconcile.calls[0] == {"evaluation_date": EVAL}
        assert (inner_assign.calls, inner_reconcile.calls) == ([], [])
        assert pending_ticket_convergence_effects(db_session) == ()

    async def test_no_second_assignment_for_an_assigned_ticket(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_with: CVEBuilder,
        va_user: VAUser,
    ) -> None:
        actor = await va_user()
        owner = await va_user()
        cve = await cve_with(SUSE_HIGH, severity=None)
        ticket = await cveless(
            ticket_factory, severity=Severity.HIGH, assignee_id=owner.id
        )

        await _associate(db_session, ticket.id, cve.cve_id, actor)

        assert (await _state(db_session, ticket.id))[1] == owner.id
        events = await ticket_events(db_session, ticket)
        assert [e.event_type for e in events if e.event_type == "assignment"] == []


# ---------------------------------------------------------------------------
# Severity-source handover (system `severity_changed`)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestSeverityHandover:
    @pytest.mark.parametrize(
        ("manual", "assessments", "derived", "priorities"),
        [
            pytest.param(
                None, (SUSE_CRITICAL,), "Critical", (None, "P2"), id="null-to-label"
            ),
            pytest.param(Severity.HIGH, (), None, ("P3", None), id="label-to-null"),
            pytest.param(
                Severity.LOW, (SUSE_HIGH,), "High", ("P4", "P3"), id="differing"
            ),
            pytest.param(
                Severity.MEDIUM,
                (SUSE_CRITICAL,),
                "Critical",
                ("P4", "P2"),
                id="differing-medium-critical",
            ),
            pytest.param(
                Severity.NONE, (), None, ("P4", None), id="none-label-to-null"
            ),
            pytest.param(
                Severity.HIGH, (SUSE_HIGH,), "High", ("P3", "P3"), id="equal-high"
            ),
            pytest.param(
                Severity.CRITICAL,
                (SUSE_CRITICAL,),
                "Critical",
                ("P2", "P2"),
                id="equal-critical",
            ),
            pytest.param(
                Severity.NONE,
                (Assessment("0.0"),),
                "None",
                ("P4", "P4"),
                id="equal-none-label",
            ),
            pytest.param(None, (), None, (None, None), id="null-to-null"),
        ],
    )
    async def test_handover_event_is_system_attributed_and_only_when_changed(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_with: CVEBuilder,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
        manual: Severity | None,
        assessments: tuple[Assessment, ...],
        derived: str | None,
        priorities: tuple[str | None, str | None],
    ) -> None:
        old_priority, new_priority = priorities
        actor = await va_user()
        cve = await cve_with(*assessments, severity=None)
        ticket = await cveless(
            ticket_factory,
            severity=manual,
            assignee_id=actor.id,
            priority_auto=old_priority,
        )
        chain = _Spy(monkeypatch, ticket_service, "recalculate_cvss_chain")

        await _associate(db_session, ticket.id, cve.cve_id, actor)

        assert chain.calls[0]["association_previous_severity"] == manual
        assert await cve_severity(db_session, cve.id) == derived
        expected = [_assoc_event(actor, cve.cve_id)]
        if label(manual) != derived:
            # `user_id` NULL: derived, although the actor initiated it.
            expected.append(severity_event(label(manual), derived))
        if old_priority != new_priority:
            expected.append(priority_event(old_priority, new_priority))
        assert await ticket_events(db_session, ticket) == expected
        assert await _state(db_session, ticket.id) == (
            TicketStatus.ANALYSIS,
            actor.id,
            cve.id,
            None,
            new_priority,
            None,
        )


# ---------------------------------------------------------------------------
# Event order, assignment, sanitation, and automatic priority
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestEventOrder:
    @pytest.mark.parametrize("status", [TicketStatus.NEW, TicketStatus.ANALYSIS])
    async def test_assignment_and_promotion_precede_the_association(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_with: CVEBuilder,
        va_user: VAUser,
        status: TicketStatus,
    ) -> None:
        actor = await va_user()
        cve = await cve_with(SUSE_CRITICAL, severity=None)
        ticket = await cveless(
            ticket_factory, status=status, severity=Severity.MEDIUM, priority_auto="P4"
        )

        await _associate(db_session, ticket.id, cve.cve_id, actor)

        promotion = (
            [status_event("New", "Analysis")] if status is TicketStatus.NEW else []
        )
        assert await ticket_events(db_session, ticket) == [
            _assignment_event(actor),
            *promotion,
            _assoc_event(actor, cve.cve_id),
            severity_event("Medium", "Critical"),
            priority_event("P4", "P2"),
        ]
        assert await _state(db_session, ticket.id) == (
            TicketStatus.ANALYSIS,
            actor.id,
            cve.id,
            None,
            "P2",
            None,
        )

    @pytest.mark.parametrize(
        ("active", "roles"),
        [
            pytest.param(True, (Role.RESTRICTED_ANALYST,), id="restricted-analyst"),
            pytest.param(False, (Role.VULNERABILITY_ANALYST,), id="inactive-va"),
            pytest.param(True, (), id="no-role"),
        ],
    )
    async def test_ineligible_actor_associates_without_assignment_and_new_stays_new(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_with: CVEBuilder,
        va_user: VAUser,
        tree: TreeBuilder,
        active: bool,
        roles: tuple[Role, ...],
    ) -> None:
        actor = await va_user(active=active, roles=roles)
        cve = await cve_with(SUSE_CRITICAL, severity=None)
        ticket = await cveless(ticket_factory, status=TicketStatus.NEW, severity=None)
        # The gates would be satisfied, but reconciliation skips `New`.
        await tree_for(TicketStatus.RESOLVED, ticket, tree)

        await _associate(db_session, ticket.id, cve.cve_id, actor)

        assert await _state(db_session, ticket.id) == (
            TicketStatus.NEW,
            None,
            cve.id,
            None,
            "P2",
            None,
        )
        assert await ticket_events(db_session, ticket) == [
            _assoc_event(actor, cve.cve_id),
            severity_event(None, "Critical"),
            priority_event(None, "P2"),
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
        cve_with: CVEBuilder,
        va_user: VAUser,
        tree: TreeBuilder,
        active: bool,
        roles: tuple[Role, ...],
        reason: str,
        result: TicketStatus,
    ) -> None:
        actor = await va_user()
        assignee = await va_user(active=active, roles=roles)
        cve = await cve_with(SUSE_CRITICAL, severity=None)
        ticket = await cveless(ticket_factory, severity=None, assignee_id=assignee.id)
        track_status = (
            PackageStatus.ANALYSIS
            if result is TicketStatus.ANALYSIS
            else PackageStatus.AFFECTED
        )
        # An ineligible occurrence the association makes eligible: its
        # event precedes the priority, the sanitation, and the final status.
        await tree(ticket, status=track_status, products=(Prod(eligible=False),))
        subject = (await subjects(db_session, ticket.id))[0]

        await _associate(db_session, ticket.id, cve.cve_id, actor)

        final = (
            [status_event("Analysis", result.value)]
            if result is not TicketStatus.ANALYSIS
            else []
        )
        assert await ticket_events(db_session, ticket) == [
            _assoc_event(actor, cve.cve_id),
            severity_event(None, "Critical"),
            product_event(subject, False, True),
            priority_event(None, "P2"),
            unassigned_event(assignee.username, reason),
            *final,
        ]
        # The already-assigned Ticket is never re-assigned to the actor.
        assert (await _state(db_session, ticket.id))[1] is None

    @pytest.mark.parametrize(
        ("status", "track_status", "actor_kind", "final_status"),
        [
            pytest.param(
                TicketStatus.NEW,
                PackageStatus.NOT_AFFECTED,
                "restricted",
                TicketStatus.NEW,
                id="new",
            ),
            pytest.param(
                TicketStatus.ANALYSIS,
                PackageStatus.ANALYSIS,
                "va",
                TicketStatus.ANALYSIS,
                id="analysis",
            ),
            pytest.param(
                TicketStatus.ANALYZED,
                PackageStatus.AFFECTED,
                "va",
                TicketStatus.ANALYZED,
                id="analyzed",
            ),
            pytest.param(
                TicketStatus.RESOLVED,
                PackageStatus.NOT_AFFECTED,
                "va",
                TicketStatus.RESOLVED,
                id="resolved",
            ),
        ],
    )
    async def test_priority_refresh_follows_product_events_in_every_operable_status(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_with: CVEBuilder,
        va_user: VAUser,
        tree: TreeBuilder,
        status: TicketStatus,
        track_status: PackageStatus,
        actor_kind: str,
        final_status: TicketStatus,
    ) -> None:
        actor = await va_user(
            roles=(Role.RESTRICTED_ANALYST,)
            if actor_kind == "restricted"
            else (Role.VULNERABILITY_ANALYST,)
        )
        owner = None if status is TicketStatus.NEW else await va_user()
        cve = await cve_with(SUSE_CRITICAL, severity=None)
        ticket = await cveless(
            ticket_factory,
            status=status,
            severity=Severity.HIGH,
            assignee_id=owner.id if owner is not None else None,
            priority_auto="P3",
        )
        await tree(ticket, status=track_status, products=(Prod(eligible=False),))
        subject = (await subjects(db_session, ticket.id))[0]

        await _associate(db_session, ticket.id, cve.cve_id, actor)

        # Automatic `High` + unknown exploitation = P3; `Critical` = P2.
        assert await _state(db_session, ticket.id) == (
            final_status,
            owner.id if owner is not None else None,
            cve.id,
            None,
            "P2",
            None,
        )
        assert await ticket_events(db_session, ticket) == [
            _assoc_event(actor, cve.cve_id),
            severity_event("High", "Critical"),
            product_event(subject, False, True),
            priority_event("P3", "P2"),
        ]

    async def test_override_masks_the_automatic_priority_change(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_with: CVEBuilder,
        va_user: VAUser,
    ) -> None:
        actor = await va_user()
        cve = await cve_with(SUSE_CRITICAL, severity=None)
        ticket = await cveless(
            ticket_factory,
            severity=Severity.HIGH,
            assignee_id=actor.id,
            priority_auto="P3",
            priority_override="P1",
        )

        await _associate(db_session, ticket.id, cve.cve_id, actor)

        # `priority_auto` changed (P3 -> P2) behind the override: no event.
        assert (await _state(db_session, ticket.id))[4:] == ("P2", "P1")
        assert await ticket_events(db_session, ticket) == [
            _assoc_event(actor, cve.cve_id),
            severity_event("High", "Critical"),
        ]

    async def test_exploitation_evidence_of_the_new_cve_reaches_the_priority(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_with: CVEBuilder,
        cve_kev_entry_factory: Factory,
        va_user: VAUser,
    ) -> None:
        actor = await va_user()
        cve = await cve_with(SUSE_HIGH, severity=None)
        await cve_kev_entry_factory(cve_id=cve.id)
        ticket = await cveless(
            ticket_factory,
            severity=Severity.HIGH,
            assignee_id=actor.id,
            priority_auto="P3",
        )

        await _associate(db_session, ticket.id, cve.cve_id, actor)

        # `kev` is P1 for every severity (ticket-priority.md, Decision Table).
        assert (await _state(db_session, ticket.id))[4] == "P1"
        assert await ticket_events(db_session, ticket) == [
            _assoc_event(actor, cve.cve_id),
            priority_event("P3", "P1"),
        ]


# ---------------------------------------------------------------------------
# Product event detail (audit Testing Requirements 6, 8, 10)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestProductEventDetail:
    async def test_detail_keys_snapshot_values_and_search(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_with: CVEBuilder,
        va_user: VAUser,
        product_factory: Callable[..., Awaitable[Product]],
        ticket_package_factory: Callable[..., Awaitable[TicketPackage]],
        ticket_package_track_factory: Callable[..., Awaitable[TicketPackageTrack]],
        ticket_package_product_factory: Callable[..., Awaitable[TicketPackageProduct]],
    ) -> None:
        actor = await va_user()
        cve = await cve_with(SUSE_CRITICAL, severity=None)
        ticket = await cveless(
            ticket_factory, severity=Severity.HIGH, assignee_id=actor.id
        )
        package = await ticket_package_factory(
            ticket_id=ticket.id, package_name="fictional-alpha"
        )
        track = await ticket_package_track_factory(
            ticket_package_id=package.id,
            reference="Example:Alpha:Update",
            status=PackageStatus.AFFECTED.value,
        )
        product = await product_factory(
            name="fictional-short-9",
            display_name="Fictional Server 9",
            cpe="cpe:/o:example:fictional_server:9",
            general_support_end_date=AFTER_EVAL,
        )
        occurrence = await ticket_package_product_factory(
            ticket_package_track_id=track.id, product_id=product.id, eligible=False
        )
        overridden = await product_factory(general_support_end_date=AFTER_EVAL)
        await ticket_package_product_factory(
            ticket_package_track_id=track.id,
            product_id=overridden.id,
            eligible=False,
            is_eligible_override=True,
        )

        await _associate(db_session, ticket.id, cve.cve_id, actor)

        events = [
            e
            for e in await ticket_events(db_session, ticket)
            if e.event_type == "product_eligibility_changed"
        ]
        assert events == [
            EventRow(
                "product_eligibility_changed",
                None,
                "false",
                "true",
                None,
                {
                    "track": "Example:Alpha:Update",
                    "package": "fictional-alpha",
                    "product_name": "Fictional Server 9",
                    "product_cpe": "cpe:/o:example:fictional_server:9",
                    "reason": "cvss",
                },
            )
        ]
        detail = events[0].detail
        assert set(detail) == {
            "track",
            "package",
            "product_name",
            "product_cpe",
            "reason",
        }
        assert "override_action" not in detail
        # `Product.display_name`, never the short `Product.name`.
        assert "fictional-short-9" not in json.dumps(detail)
        # No internal Product or occurrence identifier anywhere.
        text = json.dumps(detail)
        assert str(product.id) not in text
        assert str(occurrence.id) not in text
        assert UUID_TEXT.search(text) is None

        sequence = await db_session.scalar(
            select(Ticket.sequence_id).where(Ticket.id == ticket.id)
        )
        assert sequence is not None
        caller = TicketCaller.authenticated(actor.id, Scope.ALL)

        async def found(term: str) -> int:
            page = await list_ticket_events(
                db_session,
                ticket_id=format_ticket_id(sequence),
                caller=caller,
                search=term,
            )
            return page.total

        assert await found("Fictional Server 9") == 1
        assert await found("cpe:/o:example:fictional_server:9") == 1
        assert await found("fictional-short-9") == 0


# ---------------------------------------------------------------------------
# Guards: every rejection has zero side effects
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestGuards:
    @pytest.mark.parametrize("cve_kind", ["existing", "placeholder"])
    async def test_missing_ticket_raises_not_found_after_locking_the_cve(
        self,
        db_session: AsyncSession,
        cve_with: CVEBuilder,
        va_user: VAUser,
        cve_kind: str,
    ) -> None:
        actor = await va_user()
        cve_id = (
            (await cve_with(severity=None)).cve_id
            if cve_kind == "existing"
            else NEW_CVE_ID
        )

        denial = await _denied(
            db_session,
            TicketNotFoundError,
            ticket_id=uuid.uuid7(),
            cve_id=cve_id,
            actor=actor,
        )

        user_lock, cve_lock, ticket_lock = _root_order(denial.statements)
        assert user_lock < cve_lock < ticket_lock

    @pytest.mark.parametrize("cve_kind", ["existing", "placeholder"])
    @pytest.mark.parametrize(
        "roles",
        [
            pytest.param((Role.RESTRICTED_ANALYST,), id="restricted-analyst"),
            # A VA origin committed after the request resolved the caller's
            # `non_confidential` scope: an assignment before the denial would
            # be observable.
            pytest.param((Role.VULNERABILITY_ANALYST,), id="va-after-resolution"),
        ],
    )
    async def test_inaccessible_ticket_raises_not_found_after_locking_the_cve(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_with: CVEBuilder,
        ticket_access_grant_factory: Callable[..., Awaitable[TicketAccessGrant]],
        ticket_package_factory: Callable[..., Awaitable[TicketPackage]],
        ticket_package_maintainer_factory: Callable[
            ..., Awaitable[TicketPackageMaintainer]
        ],
        va_user: VAUser,
        tree: TreeBuilder,
        roles: tuple[Role, ...],
        cve_kind: str,
    ) -> None:
        actor = await va_user(roles=roles)
        cve_id = (
            (await cve_with(severity=None)).cve_id
            if cve_kind == "existing"
            else NEW_CVE_ID
        )
        ticket = await cveless(
            ticket_factory,
            status=TicketStatus.RESOLVED,
            severity=Severity.HIGH,
            is_confidential=True,
        )
        await tree_for(TicketStatus.RESOLVED, ticket, tree)
        # Non-qualifying paths: another user's grant and maintainership,
        # and the caller's maintainership of an excluded package.
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

        denial = await _denied(
            db_session,
            TicketNotFoundError,
            ticket_id=ticket.id,
            cve_id=cve_id,
            actor=actor,
            scope=Scope.NON_CONFIDENTIAL,
        )

        user_lock, cve_lock, ticket_lock = _root_order(denial.statements)
        assert user_lock < cve_lock < ticket_lock

    @pytest.mark.parametrize(
        "state",
        [
            pytest.param(TicketStatus.IGNORED, id="ignored"),
            pytest.param(TicketStatus.DUPLICATED, id="duplicated"),
            pytest.param(TicketStatus.ANALYSIS, id="with-cve"),
        ],
    )
    async def test_accessibility_precedes_every_other_ticket_decision(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_with: CVEBuilder,
        va_user: VAUser,
        state: TicketStatus,
    ) -> None:
        actor = await va_user(roles=(Role.RESTRICTED_ANALYST,))
        other = await cve_with(severity=None)
        own = await cve_with(severity=None)
        overrides: dict[str, Any] = {"status": state.value, "is_confidential": True}
        if state is TicketStatus.ANALYSIS:
            overrides["cve_id"] = own.id
        ticket = await ticket_factory(**overrides)

        await _denied(
            db_session,
            TicketNotFoundError,
            ticket_id=ticket.id,
            cve_id=other.cve_id,
            actor=actor,
            scope=Scope.NON_CONFIDENTIAL,
        )

    @pytest.mark.parametrize("cve_kind", ["existing", "placeholder"])
    @pytest.mark.parametrize("status", [TicketStatus.IGNORED, TicketStatus.DUPLICATED])
    async def test_manual_zone_ticket_raises_not_mutable(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_with: CVEBuilder,
        va_user: VAUser,
        status: TicketStatus,
        cve_kind: str,
    ) -> None:
        actor = await va_user()
        cve_id = (
            (await cve_with(severity=None)).cve_id
            if cve_kind == "existing"
            else NEW_CVE_ID
        )
        ticket = await cveless(
            ticket_factory, status=status, severity=Severity.LOW, priority_auto="P4"
        )

        await _denied(
            db_session,
            TicketNotMutableError,
            ticket_id=ticket.id,
            cve_id=cve_id,
            actor=actor,
        )

    async def test_operability_precedes_the_already_set_check(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_with: CVEBuilder,
        va_user: VAUser,
    ) -> None:
        actor = await va_user()
        own = await cve_with(severity=None)
        ticket = await ticket_factory(status=TicketStatus.IGNORED.value, cve_id=own.id)

        await _denied(
            db_session,
            TicketNotMutableError,
            ticket_id=ticket.id,
            cve_id=own.cve_id,
            actor=actor,
        )

    @pytest.mark.parametrize(
        "requested",
        [
            pytest.param("same", id="equals-the-current-cve"),
            pytest.param("other-existing", id="differs-existing"),
            pytest.param("other-new", id="differs-placeholder"),
            pytest.param("associated-elsewhere", id="precedes-the-conflict-check"),
        ],
    )
    async def test_ticket_with_a_cve_raises_already_set(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_with: CVEBuilder,
        va_user: VAUser,
        requested: str,
    ) -> None:
        # An unassigned `New` Ticket and a VA actor: an assignment before
        # the rejection would be observable.
        actor = await va_user()
        own = await cve_with(severity=Severity.LOW)
        ticket = await ticket_factory(
            status=TicketStatus.NEW.value, cve_id=own.id, priority_auto="P4"
        )
        if requested == "same":
            cve_id = own.cve_id
        elif requested == "other-existing":
            cve_id = (await cve_with(severity=None)).cve_id
        elif requested == "other-new":
            cve_id = NEW_CVE_ID
        else:
            elsewhere = await cve_with(severity=None)
            await ticket_factory(cve_id=elsewhere.id)
            cve_id = elsewhere.cve_id

        denial = await _denied(
            db_session,
            TicketCVEAlreadySetError,
            ticket_id=ticket.id,
            cve_id=cve_id,
            actor=actor,
        )

        assert isinstance(denial.error, TicketCVEAlreadySetError)
        assert not isinstance(denial.error, TicketCVEConflictError)

    @pytest.mark.parametrize(
        "confidential", [False, True], ids=["public", "confidential"]
    )
    @pytest.mark.parametrize(
        ("roles", "scope"),
        [
            pytest.param((Role.VULNERABILITY_ANALYST,), Scope.ALL, id="va"),
            pytest.param(
                (Role.RESTRICTED_ANALYST,), Scope.NON_CONFIDENTIAL, id="restricted"
            ),
        ],
    )
    async def test_cve_of_another_ticket_raises_conflict_with_its_identifier(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_with: CVEBuilder,
        va_user: VAUser,
        confidential: bool,
        roles: tuple[Role, ...],
        scope: Scope,
    ) -> None:
        """The conflicting Ticket may be confidential and inaccessible to
        the caller; its identifier is still returned."""
        actor = await va_user(roles=roles)
        cve = await cve_with(severity=Severity.LOW)
        existing = await ticket_factory(cve_id=cve.id, is_confidential=confidential)
        existing_id = existing.id
        sequence = await db_session.scalar(
            select(Ticket.sequence_id).where(Ticket.id == existing.id)
        )
        assert sequence is not None
        # An unassigned `New` Ticket: an assignment before the rejection
        # would be observable.
        ticket = await ticket_factory(status=TicketStatus.NEW.value)

        denial = await _denied(
            db_session,
            TicketCVEConflictError,
            ticket_id=ticket.id,
            cve_id=cve.cve_id,
            actor=actor,
            scope=scope,
        )

        assert isinstance(denial.error, TicketCVEConflictError)
        assert denial.error.existing_ticket_id == format_ticket_id(sequence)
        assert format_ticket_id(sequence) not in str(denial.error)
        # The conflicting Ticket itself is untouched.
        assert await ticket_events_by_id(db_session, existing_id) == []

    async def test_caller_mismatch_raises_value_error_before_any_statement(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_with: CVEBuilder,
        va_user: VAUser,
    ) -> None:
        actor = await va_user()
        other = await va_user()
        cve = await cve_with(severity=None)
        ticket = await cveless(ticket_factory, status=TicketStatus.NEW, severity=None)
        before = await _world(db_session, ticket.id)

        with (
            StatementRecorder(db_session) as recorder,
            pytest.raises(ValueError, match="acting user"),
        ):
            await associate_cve(
                db_session,
                ticket_id=ticket.id,
                cve_id=cve.cve_id,
                acting_user_id=actor.id,
                caller=TicketCaller.authenticated(other.id, Scope.ALL),
                evaluation_date=EVAL,
            )

        assert recorder.statements == []
        assert await _world(db_session, ticket.id) == before

    @pytest.mark.parametrize(
        "malformed",
        [
            "",
            "cve-2099-0001",
            "CVE-99-0001",
            "CVE-2099-123",
            "CVE-2099-0001 ",
            " CVE-2099-0001",
            "CVE-2099-0001; DROP TABLE cve",
            "CVE-2099-" + "1" * 20,
        ],
    )
    async def test_malformed_cve_id_raises_before_any_statement(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        malformed: str,
    ) -> None:
        actor = await va_user()
        ticket = await cveless(ticket_factory, status=TicketStatus.NEW, severity=None)
        before = await _world(db_session, ticket.id)

        with StatementRecorder(db_session) as recorder, pytest.raises(CVEIdFormatError):
            await _associate(db_session, ticket.id, malformed, actor)

        assert recorder.statements == []
        assert await _world(db_session, ticket.id) == before


# ---------------------------------------------------------------------------
# Locked-current accessibility (positive paths, single session)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestAccessibleAssociation:
    async def test_explicit_grant_holder_associates_without_assignment(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_with: CVEBuilder,
        ticket_access_grant_factory: Callable[..., Awaitable[TicketAccessGrant]],
        va_user: VAUser,
    ) -> None:
        actor = await va_user(roles=(Role.RESTRICTED_ANALYST,))
        cve = await cve_with(SUSE_HIGH, severity=None)
        ticket = await cveless(
            ticket_factory,
            status=TicketStatus.NEW,
            severity=None,
            is_confidential=True,
        )
        await ticket_access_grant_factory(ticket_id=ticket.id, user_id=actor.id)

        await _associate(
            db_session,
            ticket.id,
            cve.cve_id,
            actor,
            scope=Scope.NON_CONFIDENTIAL,
        )

        assert await ticket_events(db_session, ticket) == [
            _assoc_event(actor, cve.cve_id),
            severity_event(None, "High"),
            priority_event(None, "P3"),
        ]

    async def test_included_package_maintainer_associates(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_with: CVEBuilder,
        ticket_package_factory: Callable[..., Awaitable[TicketPackage]],
        ticket_package_maintainer_factory: Callable[
            ..., Awaitable[TicketPackageMaintainer]
        ],
        va_user: VAUser,
    ) -> None:
        actor = await va_user(roles=(Role.RESTRICTED_ANALYST,))
        cve = await cve_with(SUSE_HIGH, severity=None)
        ticket = await cveless(
            ticket_factory,
            status=TicketStatus.NEW,
            severity=None,
            is_confidential=True,
        )
        package = await ticket_package_factory(ticket_id=ticket.id)
        await ticket_package_maintainer_factory(
            ticket_package_id=package.id, user_id=actor.id
        )

        await _associate(
            db_session,
            ticket.id,
            cve.cve_id,
            actor,
            scope=Scope.NON_CONFIDENTIAL,
        )

        assert (await _state(db_session, ticket.id))[2] == cve.id

    async def test_scope_all_sees_a_confidential_ticket_and_assigns(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_with: CVEBuilder,
        va_user: VAUser,
    ) -> None:
        actor = await va_user()
        cve = await cve_with(SUSE_HIGH, severity=None)
        ticket = await cveless(
            ticket_factory,
            status=TicketStatus.NEW,
            severity=None,
            is_confidential=True,
        )

        await _associate(db_session, ticket.id, cve.cve_id, actor)

        assert await ticket_events(db_session, ticket) == [
            _assignment_event(actor),
            status_event("New", "Analysis"),
            _assoc_event(actor, cve.cve_id),
            severity_event(None, "High"),
            priority_event(None, "P3"),
        ]


# ---------------------------------------------------------------------------
# Already-REJECTED CVE: ordinary association only
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestRejectedCVE:
    @pytest.mark.parametrize("kind", ["active-va", "restricted-analyst"])
    async def test_rejected_cve_gets_no_automatic_rejection_effect(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_with: CVEBuilder,
        cve_factory: Factory,
        cve_cvss_assessment_factory: Factory,
        va_user: VAUser,
        kind: str,
    ) -> None:
        assigned = kind == "active-va"
        actor = await va_user(
            roles=(
                (Role.VULNERABILITY_ANALYST,)
                if assigned
                else (Role.RESTRICTED_ANALYST,)
            )
        )
        cve: CVE = await cve_factory(
            cve_state="REJECTED",
            date_rejected=datetime(2099, 3, 4, tzinfo=UTC),
            severity=None,
        )
        await cve_cvss_assessment_factory(
            cve_id=cve.id,
            provider_name="SUSE",
            cvss_version="3.1",
            score=Decimal("7.5"),
        )
        ticket = await ticket_factory(status=TicketStatus.NEW.value)

        await _associate(db_session, ticket.id, cve.cve_id, actor)

        events = await ticket_events(db_session, ticket)
        promotion = (
            [_assignment_event(actor), status_event("New", "Analysis")]
            if assigned
            else []
        )
        assert events == [
            *promotion,
            _assoc_event(actor, cve.cve_id),
            severity_event(None, "High"),
            priority_event(None, "P3"),
        ]
        assert all(e.comment != "CVE rejected" for e in events)
        assert all(e.new_value != "Ignored" for e in events)
        assert (await _state(db_session, ticket.id))[0] == (
            TicketStatus.ANALYSIS if assigned else TicketStatus.NEW
        )
        refreshed = await _cve_row(db_session, cve.cve_id)
        assert refreshed is not None
        assert refreshed.cve_state == "REJECTED"


# ---------------------------------------------------------------------------
# Transaction-local convergence registration
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestConvergenceRegistration:
    async def test_resolved_regression_to_analysis_registers_one_effect(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_with: CVEBuilder,
        va_user: VAUser,
        tree: TreeBuilder,
    ) -> None:
        actor = await va_user()
        cve = await cve_with(severity=None)
        ticket = await cveless(
            ticket_factory,
            status=TicketStatus.RESOLVED,
            severity=Severity.HIGH,
            assignee_id=actor.id,
            priority_auto="P3",
        )
        await tree_for(TicketStatus.RESOLVED, ticket, tree)

        await _associate(db_session, ticket.id, cve.cve_id, actor)

        assert await ticket_events(db_session, ticket) == [
            _assoc_event(actor, cve.cve_id),
            severity_event("High", None),
            priority_event("P3", None),
            status_event("Resolved", "Analysis"),
        ]
        assert pending_ticket_convergence_effects(db_session) == (
            TicketConvergenceEffect(ticket.id),
        )

    async def test_resolved_regression_to_analyzed_registers_one_effect(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_with: CVEBuilder,
        va_user: VAUser,
        tree: TreeBuilder,
    ) -> None:
        actor = await va_user()
        cve = await cve_with(SUSE_CRITICAL, severity=None)
        ticket = await cveless(
            ticket_factory,
            status=TicketStatus.RESOLVED,
            severity=Severity.HIGH,
            assignee_id=actor.id,
            priority_auto="P3",
        )
        # No eligible Product: the tree is resolution-complete until the
        # association makes the occurrence eligible.
        await tree(
            ticket, status=PackageStatus.AFFECTED, products=(Prod(eligible=False),)
        )

        await _associate(db_session, ticket.id, cve.cve_id, actor)

        events = await ticket_events(db_session, ticket)
        assert events[-1] == status_event("Resolved", "Analyzed")
        assert pending_ticket_convergence_effects(db_session) == (
            TicketConvergenceEffect(ticket.id),
        )

    async def test_resolved_that_stays_resolved_registers_nothing(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_with: CVEBuilder,
        va_user: VAUser,
        tree: TreeBuilder,
    ) -> None:
        actor = await va_user()
        cve = await cve_with(SUSE_HIGH, severity=None)
        ticket = await cveless(
            ticket_factory,
            status=TicketStatus.RESOLVED,
            severity=Severity.HIGH,
            assignee_id=actor.id,
            priority_auto="P3",
        )
        await tree_for(TicketStatus.RESOLVED, ticket, tree)

        await _associate(db_session, ticket.id, cve.cve_id, actor)

        assert (await _state(db_session, ticket.id))[0] == TicketStatus.RESOLVED
        assert await ticket_events(db_session, ticket) == [
            _assoc_event(actor, cve.cve_id)
        ]
        assert pending_ticket_convergence_effects(db_session) == ()


# ---------------------------------------------------------------------------
# created_at immutability and Ticket-level due dates
# ---------------------------------------------------------------------------


async def _due_dates(
    db: AsyncSession, ticket_id: uuid.UUID
) -> tuple[datetime | None, ...]:
    """The five Ticket-level due dates through the read path's SQL
    expressions (the resolved severity cascade)."""
    due = ticket_due_date_expressions()
    row = (
        await db.execute(
            select(due.triage, due.submission, due.um, due.qa, due.release).where(
                Ticket.id == ticket_id
            )
        )
    ).one()
    return tuple(row)


def _expected_due(tier: int | None) -> tuple[datetime | None, ...]:
    if tier is None:
        return (None,) * 5
    return tuple(CREATED_AT + timedelta(days=d) for d in TIER_OFFSETS_DAYS[tier])


@pytest.mark.integration
class TestDeadlines:
    @pytest.mark.parametrize(
        ("manual", "assessments", "before", "after"),
        [
            pytest.param(
                Severity.MEDIUM, (SUSE_CRITICAL,), 90, 30, id="medium-critical"
            ),
            pytest.param(
                Severity.CRITICAL, (Assessment("3.9"),), 30, 180, id="critical-low"
            ),
            pytest.param(Severity.LOW, (), 180, 30, id="low-to-unresolved"),
            pytest.param(Severity.NONE, (SUSE_CRITICAL,), None, 30, id="none-label"),
            pytest.param(
                Severity.HIGH, (Assessment("0.0"),), 30, None, id="to-none-label"
            ),
        ],
    )
    async def test_created_at_is_immutable_and_the_tier_follows_the_cve_severity(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_with: CVEBuilder,
        va_user: VAUser,
        manual: Severity,
        assessments: tuple[Assessment, ...],
        before: int | None,
        after: int | None,
    ) -> None:
        actor = await va_user()
        cve = await cve_with(*assessments, severity=None)
        ticket = await cveless(
            ticket_factory,
            severity=manual,
            assignee_id=actor.id,
            created_at=CREATED_AT,
        )
        assert await _due_dates(db_session, ticket.id) == _expected_due(before)

        await _associate(db_session, ticket.id, cve.cve_id, actor)

        created_at = (
            await db_session.execute(
                select(Ticket.created_at).where(Ticket.id == ticket.id)
            )
        ).scalar_one()
        assert created_at == CREATED_AT
        assert await _due_dates(db_session, ticket.id) == _expected_due(after)


# ---------------------------------------------------------------------------
# Lock order and statement shape
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestLockOrder:
    async def test_existing_cve_user_share_then_cve_update_then_ticket_update(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_with: CVEBuilder,
        va_user: VAUser,
        no_external_io: None,
    ) -> None:
        actor = await va_user()
        cve = await cve_with(SUSE_HIGH, severity=None)
        ticket = await cveless(ticket_factory, status=TicketStatus.NEW, severity=None)

        with StatementRecorder(db_session) as recorder:
            await _associate(db_session, ticket.id, cve.cve_id, actor)

        statements = recorder.statements
        user_lock, cve_lock, ticket_lock = _root_order(statements)
        # The acting User lock is the first statement of the operation.
        assert user_lock == 0
        # The first CVE statement is the resolution SELECT ... FOR UPDATE:
        # no unlocked CVE read precedes it, and no Ticket statement does.
        assert statements[cve_lock].lstrip().startswith("SELECT")
        assert statements[cve_lock].rstrip().endswith("FOR UPDATE")
        assert "FROM cve " in statements[cve_lock]
        assert user_lock < cve_lock < ticket_lock
        assert statements[ticket_lock].lstrip().startswith("SELECT")
        assert statements[ticket_lock].rstrip().endswith("FOR UPDATE")
        assert not any(s.startswith("INSERT INTO cve ") for s in statements)
        # The first three row locks are the documented roots, in order.
        locks = recorder.row_locks()
        assert _is_user_share(locks[0])
        assert locks[1] == statements[cve_lock]
        assert locks[2] == statements[ticket_lock]
        assert recorder.selects_from("ticket_audit_event") == []

    async def test_placeholder_is_inserted_with_on_conflict_before_the_ticket_lock(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        no_external_io: None,
    ) -> None:
        actor = await va_user()
        ticket = await cveless(ticket_factory, status=TicketStatus.NEW, severity=None)

        with StatementRecorder(db_session) as recorder:
            await _associate(db_session, ticket.id, NEW_CVE_ID, actor)

        statements = recorder.statements
        user_lock, first_cve, ticket_lock = _root_order(statements)
        cve_statements = [
            i for i, s in enumerate(statements) if CVE_STATEMENT.search(s)
        ]
        first, placeholder, relock = (statements[i] for i in cve_statements[:3])
        assert user_lock == 0
        assert first.lstrip().startswith("SELECT")
        assert first.rstrip().endswith("FOR UPDATE")
        assert placeholder.startswith("INSERT INTO cve ")
        assert "ON CONFLICT (cve_id) DO NOTHING" in placeholder
        assert relock.rstrip().endswith("FOR UPDATE")
        assert user_lock < first_cve < cve_statements[1] < cve_statements[2]
        assert cve_statements[2] < ticket_lock
        assert statements[ticket_lock].rstrip().endswith("FOR UPDATE")

    async def test_ticket_visibility_is_a_separate_statement_after_the_lock(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_with: CVEBuilder,
        ticket_access_grant_factory: Callable[..., Awaitable[TicketAccessGrant]],
        va_user: VAUser,
    ) -> None:
        actor = await va_user(roles=(Role.RESTRICTED_ANALYST,))
        cve = await cve_with(SUSE_HIGH, severity=None)
        ticket = await cveless(ticket_factory, severity=None, is_confidential=True)
        await ticket_access_grant_factory(ticket_id=ticket.id, user_id=actor.id)

        with StatementRecorder(db_session) as recorder:
            await _associate(
                db_session,
                ticket.id,
                cve.cve_id,
                actor,
                scope=Scope.NON_CONFIDENTIAL,
            )

        statements = recorder.statements
        ticket_lock = _first(
            statements,
            lambda s: "FROM ticket" in s and s.rstrip().endswith("FOR UPDATE"),
        )
        visibility = _first(statements, lambda s: "ticket_access_grant" in s)
        assert ticket_lock < visibility
        assert "ticket_access_grant" not in statements[ticket_lock]
        assert "is_confidential" not in statements[ticket_lock].split("WHERE")[-1]


# ---------------------------------------------------------------------------
# One evaluation date
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestEvaluationDate:
    @pytest.mark.parametrize(
        ("offset_days", "product_event_expected", "final"),
        [
            # On `EVAL` the Product is in Reactive Support: ineligible; the
            # only Product is then not eligible and the track is complete.
            pytest.param(0, True, TicketStatus.RESOLVED, id="reactive-support"),
            # 100 days earlier General Support has not ended: eligible
            # (unchanged), so the track is incomplete.
            pytest.param(-100, False, TicketStatus.ANALYZED, id="general-support"),
            # 400 days later every lifecycle date has passed: EOL, so the
            # track is not actionable and nothing is incomplete.
            pytest.param(400, False, TicketStatus.RESOLVED, id="end-of-life"),
        ],
    )
    async def test_supplied_date_drives_lifecycle_and_reconciliation(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_with: CVEBuilder,
        va_user: VAUser,
        tree: TreeBuilder,
        monkeypatch: pytest.MonkeyPatch,
        offset_days: int,
        product_event_expected: bool,
        final: TicketStatus,
    ) -> None:
        clock_calls = 0

        def other_current_date() -> datetime:
            nonlocal clock_calls
            clock_calls += 1
            return datetime(2031, 5, 5, 12, 0, tzinfo=UTC)

        def forbidden_clock() -> datetime:
            raise AssertionError("the supplied date must be reused")

        monkeypatch.setattr(ticket_service, "_utc_now", other_current_date)
        monkeypatch.setattr(ticket_mutations, "_utc_now", forbidden_clock)
        chain = _Spy(monkeypatch, ticket_service, "recalculate_cvss_chain")
        reconcile = _Spy(monkeypatch, ticket_service, "reconcile_ticket_status")
        actor = await va_user()
        cve = await cve_with(SUSE_CRITICAL, severity=None)
        ticket = await cveless(
            ticket_factory,
            severity=Severity.HIGH,
            assignee_id=actor.id,
            priority_auto="P3",
        )
        await tree(
            ticket,
            status=PackageStatus.AFFECTED,
            products=(Prod(eligible=True, reactive=True),),
        )
        subject = (await subjects(db_session, ticket.id))[0]
        supplied = EVAL + timedelta(days=offset_days)

        await _associate(
            db_session, ticket.id, cve.cve_id, actor, evaluation_date=supplied
        )

        assert clock_calls == 0
        assert chain.calls[0]["evaluation_date"] == supplied
        assert reconcile.calls == [{"evaluation_date": supplied}]
        product = (
            [product_event(subject, True, False)] if product_event_expected else []
        )
        assert await ticket_events(db_session, ticket) == [
            _assoc_event(actor, cve.cve_id),
            severity_event("High", "Critical"),
            *product,
            priority_event("P3", "P2"),
            status_event("Analysis", final.value),
        ]

    async def test_omitted_date_is_captured_once_at_entry_in_utc(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_with: CVEBuilder,
        va_user: VAUser,
        tree: TreeBuilder,
        product_factory: Callable[..., Awaitable[Product]],
        ticket_package_product_factory: Callable[..., Awaitable[TicketPackageProduct]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        day = date(2026, 12, 31)
        instants = iter(
            [
                # 22:30 UTC on `day`, expressed with a `+02:00` offset.
                datetime(2027, 1, 1, 0, 30, tzinfo=timezone(timedelta(hours=2))),
                datetime(2027, 1, 1, 0, 0, 0, tzinfo=UTC),
            ]
        )
        calls = 0

        def clock() -> datetime:
            nonlocal calls
            calls += 1
            return next(instants)

        def forbidden_clock() -> datetime:
            raise AssertionError("the date is captured once by the service")

        actor = await va_user()
        cve = await cve_with(SUSE_CRITICAL, severity=None)
        ticket = await cveless(
            ticket_factory,
            severity=None,
            assignee_id=actor.id,
        )
        # General Support ends on `day`: the AFFECTED track is actionable on
        # `day` (Analyzed) and all-EOL the next day (Resolved).
        track = await tree(ticket, status=PackageStatus.AFFECTED, products=())
        product = await product_factory(general_support_end_date=day)
        await ticket_package_product_factory(
            ticket_package_track_id=track.id, product_id=product.id
        )
        monkeypatch.setattr(ticket_service, "_utc_now", clock)
        monkeypatch.setattr(ticket_mutations, "_utc_now", forbidden_clock)
        chain = _Spy(monkeypatch, ticket_service, "recalculate_cvss_chain")
        reconcile = _Spy(monkeypatch, ticket_service, "reconcile_ticket_status")

        await _associate(db_session, ticket.id, cve.cve_id, actor, evaluation_date=None)

        assert calls == 1
        assert chain.calls[0]["evaluation_date"] == day
        assert reconcile.calls == [{"evaluation_date": day}]
        assert (await _state(db_session, ticket.id))[0] == TicketStatus.ANALYZED


# ---------------------------------------------------------------------------
# Persisted contract of the association itself
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestPersistedContract:
    async def test_event_fields_cleared_manual_severity_and_returned_ticket(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_with: CVEBuilder,
        va_user: VAUser,
    ) -> None:
        actor = await va_user()
        cve = await cve_with(SUSE_HIGH, severity=None)
        ticket = await cveless(
            ticket_factory, severity=Severity.LOW, assignee_id=actor.id
        )

        result = await _associate(db_session, ticket.id, cve.cve_id, actor)

        assert result.id == ticket.id
        assert (result.cve_id, result.severity_manual) == (cve.id, None)
        assert (await _state(db_session, ticket.id))[2:4] == (cve.id, None)
        (event,) = [
            e
            for e in await ticket_events(db_session, ticket)
            if e.event_type == TicketAuditEventType.CVE_ASSOCIATED.value
        ]
        assert event == EventRow(
            "cve_associated", actor.id, None, cve.cve_id, None, None
        )

    async def test_new_cve_placeholder_is_created_and_associated(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
    ) -> None:
        actor = await va_user()
        ticket = await cveless(ticket_factory, severity=None, assignee_id=actor.id)
        assert await _cve_row(db_session, NEW_CVE_ID) is None

        await _associate(db_session, ticket.id, NEW_CVE_ID, actor)

        cve = await _cve_row(db_session, NEW_CVE_ID)
        assert cve is not None
        assert (cve.cve_state, cve.severity, cve.title) == ("PUBLISHED", None, None)
        assert (await _state(db_session, ticket.id))[2] == cve.id
        assert await ticket_events(db_session, ticket) == [
            _assoc_event(actor, NEW_CVE_ID)
        ]

    async def test_never_commits_or_rolls_back(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_with: CVEBuilder,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        actor = await va_user()
        cve = await cve_with(SUSE_HIGH, severity=None)
        ticket = await cveless(ticket_factory, severity=None, assignee_id=actor.id)

        async def forbidden() -> None:
            raise AssertionError("associate_cve() must not end the transaction")

        monkeypatch.setattr(db_session, "commit", forbidden)
        monkeypatch.setattr(db_session, "rollback", forbidden)

        await _associate(db_session, ticket.id, cve.cve_id, actor)
