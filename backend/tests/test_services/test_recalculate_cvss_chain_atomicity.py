"""Service integration tests for `recalculate_cvss_chain()`
(backend/app/services/ticket_mutations.py, CVSS chain recalculation):
runner-facing classification, idempotency, whole-chain rollback, the one
evaluation date, and lock order and serialization.

The eligibility formula, association mode, and the default-version state
matrix are in test_recalculate_cvss_chain.py.

Owning specifications:

- docs/features/tickets/ticket-mutations.md (`recalculate_cvss_chain()`:
  Behavior 1-7, Runner-facing classification, Idempotency; CVSS Mutation
  Authority and Result: rollback of the complete chain; Architectural Test
  Requirement: Complete atomic chain, Automatic priority).
- docs/features/tickets/ticket-priority.md (Testing Requirements 3 and 8,
  unit level: a unit whose only mutation is `priority_auto`, including one
  masked by an override, classifies `changed`).
- docs/features/tickets/ticket-audit-log.md (Canonical Mutation and
  No-Event Matrix: Default-version severity/eligibility chain; Testing
  Requirements 7, 12, 24, 28).
- docs/features/platform/testing-strategy.md (Rollback Within a Test;
  Concurrency Testing; Service Functions: lock serialization).
- docs/conventions.md (Transaction and Locking: CVE then Ticket).

Expected values are transcribed from the specifications, never computed
with the module under test.
"""

from __future__ import annotations

import asyncio
import contextlib
import re
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from datetime import UTC, date, datetime, timedelta
from decimal import Decimal
from typing import Any

import pytest
from sqlalchemy import delete, select, text, update
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import PackageStatus, Severity, TicketStatus
from app.models.cve import CVE
from app.models.cve_cvss_assessment import CVECVSSAssessment
from app.models.cve_kev_entry import CVEKEVEntry
from app.models.product import Product
from app.models.system_setting import SystemSetting
from app.models.ticket import Ticket
from app.models.ticket_audit_event import TicketAuditEvent
from app.models.ticket_package_product import TicketPackageProduct
from app.services import settings as settings_service
from app.services import ticket_mutations
from app.services.product_eligibility import evaluate_product_eligibility
from app.services.settings import RequiredSystemSettingMissingError
from app.services.ticket_audit_log import TicketAuditLog
from app.services.ticket_convergence_registry import (
    pending_ticket_convergence_effects,
)
from app.services.ticket_mutations import (
    CVSSChainClassification,
    CVSSChainMode,
    CVSSChainResult,
    CVSSPropagation,
    ProductPropagationSummary,
)
from tests.support.cvss_chain import (
    DEFAULT_VERSION,
    Assessment,
    CallCounter,
    CVEBuilder,
    assessment_snapshot,
    associate,
    cve_severity,
    eligibility,
    priority_event,
    product_event,
    run_chain,
    severity_event,
    severity_resolution,
    subjects,
    suse_eligibility,
    ticket_state,
    total_ticket_events,
)
from tests.support.database import assert_lock_wait, rollback_test_scope
from tests.support.ticket_mutations import (
    EVAL,
    Prod,
    StatementRecorder,
    TicketFactory,
    TreeBuilder,
    VAUser,
    status_event,
    ticket_events,
    ticket_events_by_id,
    unassigned_event,
)

pytest_plugins = ["tests.support.ticket_mutation_fixtures"]
"""Provides the shared `va_user`, `tree`, and `cve_with` fixtures."""

DEFAULT = CVSSChainMode.DEFAULT_VERSION
CHANGED = CVSSChainClassification.CHANGED
UNCHANGED = CVSSChainClassification.UNCHANGED
MISSING = CVSSChainClassification.MISSING

SUSE_CRITICAL = Assessment("9.8")
SUSE_HIGH = Assessment("7.5")
T9 = Decimal("9.0")

ALL_STATUSES = tuple(TicketStatus)
GATE_ZONE = (TicketStatus.ANALYSIS, TicketStatus.ANALYZED, TicketStatus.RESOLVED)
MANUAL_ZONE = (TicketStatus.IGNORED, TicketStatus.DUPLICATED)


@pytest.fixture(autouse=True)
async def default_setting(
    system_setting_factory: Callable[..., Awaitable[SystemSetting]],
) -> SystemSetting:
    """The persisted `default_cvss_version` (the test schema has none)."""
    return await system_setting_factory(
        key="default_cvss_version", value=DEFAULT_VERSION
    )


def _is_write_to(table: str, statement: str) -> bool:
    head = statement.lstrip().upper()
    return head.startswith(
        (f"UPDATE {table.upper()} ", f"INSERT INTO {table.upper()} ")
    ) or head.startswith(f"DELETE FROM {table.upper()} ")


def _sql_dates(recorder: StatementRecorder) -> set[date]:
    """Every pure `date` bound in the recorded statements."""
    return {
        value
        for params in recorder.parameters
        for value in (params.values() if isinstance(params, dict) else params)
        if isinstance(value, date) and not isinstance(value, datetime)
    }


def _propagation_for(status: TicketStatus | None) -> CVSSPropagation:
    """Step 7 of the specification, transcribed."""
    if status is None:
        return CVSSPropagation.NOT_APPLICABLE
    if status in MANUAL_ZONE:
        return CVSSPropagation.DEFERRED_UNTIL_REACTIVATION
    return CVSSPropagation.IMMEDIATE


# ---------------------------------------------------------------------------
# Runner-facing classification
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestClassification:
    @pytest.mark.parametrize("status", ALL_STATUSES)
    @pytest.mark.parametrize(
        ("override", "events"),
        [
            pytest.param(None, [priority_event("P3", "P1")], id="effective"),
            pytest.param("P2", [], id="masked-by-override"),
        ],
    )
    async def test_priority_auto_change_alone_is_changed(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_with: CVEBuilder,
        cve_kev_entry_factory: Callable[..., Awaitable[CVEKEVEntry]],
        monkeypatch: pytest.MonkeyPatch,
        status: TicketStatus,
        override: str | None,
        events: list[Any],
    ) -> None:
        """A KEV entry added out of band is the only changed input
        (ticket-priority.md, Testing Requirement 8, unit level)."""
        cve = await cve_with(SUSE_HIGH, severity=Severity.HIGH)
        await cve_kev_entry_factory(cve_id=cve.id)
        ticket = await ticket_factory(
            status=status.value,
            cve_id=cve.id,
            priority_auto="P3",
            priority_override=override,
        )
        reconcile = CallCounter(monkeypatch, "reconcile_ticket_status")

        with StatementRecorder(db_session) as recorder:
            result = await run_chain(db_session, cve.id)

        assert result == CVSSChainResult(
            mode=DEFAULT,
            classification=CHANGED,
            severity_resolution=severity_resolution("7.5", Severity.HIGH),
            eligibility_resolution=suse_eligibility("7.5"),
            propagation=_propagation_for(status),
            products=ProductPropagationSummary(),
            severity_changed=False,
            reconciled=False,
            evaluation_date=EVAL,
        )
        assert reconcile.calls == []
        assert [s for s in recorder.writes() if _is_write_to("ticket", s)] != []
        assert await ticket_state(db_session, ticket.id) == (
            status,
            None,
            "P1",
            override,
            None,
        )
        assert await ticket_events(db_session, ticket) == events

    async def test_sanitation_and_status_come_only_with_a_gate_input_change(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_with: CVEBuilder,
        tree: TreeBuilder,
        va_user: VAUser,
    ) -> None:
        """Converged severity, Products, and priority: the stale status and
        ineligible assignee are left for the next gate-relevant mutation.
        After a gate input changes, the same unit sanitizes, transitions,
        and classifies `changed`."""
        assignee = await va_user(active=False)
        cve = await cve_with(SUSE_HIGH, severity=Severity.HIGH)
        ticket = await ticket_factory(
            status=TicketStatus.ANALYSIS.value,
            cve_id=cve.id,
            priority_auto="P3",
            assignee_id=assignee.id,
        )
        await tree(ticket, status=PackageStatus.AFFECTED, products=(Prod(),))

        converged = await run_chain(db_session, cve.id)

        assert (converged.classification, converged.reconciled) == (UNCHANGED, False)
        assert await ticket_events(db_session, ticket) == []

        await db_session.execute(
            update(CVE).where(CVE.id == cve.id).values(severity=Severity.LOW.value)
        )
        changed = await run_chain(db_session, cve.id)

        assert (changed.classification, changed.reconciled) == (CHANGED, True)
        assert await ticket_state(db_session, ticket.id) == (
            TicketStatus.ANALYZED,
            None,
            "P3",
            None,
            None,
        )
        assert await ticket_events(db_session, ticket) == [
            severity_event("Low", "High"),
            unassigned_event(assignee.username, "inactive assignee"),
            status_event(TicketStatus.ANALYSIS, TicketStatus.ANALYZED),
        ]

    @pytest.mark.parametrize("status", [None, *ALL_STATUSES])
    async def test_converged_unit_is_unchanged_without_write_or_event(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_with: CVEBuilder,
        tree: TreeBuilder,
        monkeypatch: pytest.MonkeyPatch,
        status: TicketStatus | None,
    ) -> None:
        cve = await cve_with(SUSE_HIGH, severity=Severity.HIGH)
        ticket = None
        if status is not None:
            ticket = await ticket_factory(
                status=status.value, cve_id=cve.id, priority_auto="P3"
            )
            await tree(
                ticket,
                products=(
                    Prod(eligible=True),
                    Prod(eligible=False, threshold=T9),
                    Prod(eligible=True, threshold=T9, override=True),
                ),
            )
        reconcile = CallCounter(monkeypatch, "reconcile_ticket_status")

        with StatementRecorder(db_session) as recorder:
            result = await run_chain(db_session, cve.id)

        immediate = _propagation_for(status) is CVSSPropagation.IMMEDIATE
        assert result == CVSSChainResult(
            mode=DEFAULT,
            classification=UNCHANGED,
            severity_resolution=severity_resolution("7.5", Severity.HIGH),
            eligibility_resolution=suse_eligibility("7.5"),
            propagation=_propagation_for(status),
            products=(
                ProductPropagationSummary(3, 1, 0)
                if immediate
                else ProductPropagationSummary()
            ),
            severity_changed=False,
            reconciled=False,
            evaluation_date=EVAL,
        )
        assert recorder.writes() == []
        assert reconcile.calls == []
        assert await total_ticket_events(db_session) == 0

    @pytest.mark.parametrize("absence", ["never-existed", "deleted-in-transaction"])
    async def test_missing_cve_is_missing_without_any_effect(
        self,
        db_session: AsyncSession,
        cve_with: CVEBuilder,
        monkeypatch: pytest.MonkeyPatch,
        absence: str,
    ) -> None:
        if absence == "never-existed":
            cve_id = uuid.uuid7()
        else:
            cve = await cve_with(SUSE_HIGH, severity=Severity.LOW)
            cve_id = cve.id
            await db_session.delete(cve)
            await db_session.flush()

        async def forbidden(_db: AsyncSession) -> str:
            raise AssertionError("a missing unit reads no setting")

        monkeypatch.setattr(settings_service, "get_default_cvss_version", forbidden)
        refresh = CallCounter(monkeypatch, "refresh_priority_auto")
        reconcile = CallCounter(monkeypatch, "reconcile_ticket_status")

        with StatementRecorder(db_session) as recorder:
            result = await run_chain(db_session, cve_id)

        assert result == CVSSChainResult(
            mode=DEFAULT,
            classification=MISSING,
            severity_resolution=None,
            eligibility_resolution=None,
            propagation=CVSSPropagation.NONE,
            products=ProductPropagationSummary(),
            severity_changed=False,
            reconciled=False,
            evaluation_date=EVAL,
        )
        assert len(recorder.statements) == 1
        assert recorder.writes() == []
        assert (refresh.calls, reconcile.calls) == ([], [])
        assert await total_ticket_events(db_session) == 0


# ---------------------------------------------------------------------------
# Idempotency; assessments and overrides are never modified
# ---------------------------------------------------------------------------


async def _stale_gate_zone_ticket(
    ticket_factory: TicketFactory,
    cve_with: CVEBuilder,
    tree: TreeBuilder,
    *,
    assignee_id: uuid.UUID | None = None,
    products: int = 1,
) -> tuple[CVE, Ticket]:
    """An `Analysis` Ticket whose severity (`Medium` → `Critical`), Products
    (`false` → `true`), and priority (`P4` → `P2`) are stale, with an
    AFFECTED track whose gate result is `Analyzed`."""
    cve = await cve_with(
        SUSE_CRITICAL, Assessment("5.0", "NVD"), severity=Severity.MEDIUM
    )
    ticket = await ticket_factory(
        status=TicketStatus.ANALYSIS.value,
        cve_id=cve.id,
        priority_auto="P4",
        assignee_id=assignee_id,
    )
    await tree(
        ticket,
        status=PackageStatus.AFFECTED,
        products=(
            *(Prod(eligible=False, threshold=T9) for _ in range(products)),
            Prod(eligible=False, override=True),
        ),
    )
    return cve, ticket


@pytest.mark.integration
class TestIdempotency:
    async def test_second_invocation_is_unchanged_without_write_or_event(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_with: CVEBuilder,
        tree: TreeBuilder,
    ) -> None:
        cve, ticket = await _stale_gate_zone_ticket(ticket_factory, cve_with, tree)
        first = await run_chain(db_session, cve.id)
        assert first.classification is CHANGED
        events = await ticket_events(db_session, ticket)
        assert len(events) == 4

        with StatementRecorder(db_session) as recorder:
            second = await run_chain(db_session, cve.id)

        assert second == CVSSChainResult(
            mode=DEFAULT,
            classification=UNCHANGED,
            severity_resolution=severity_resolution("9.8", Severity.CRITICAL),
            eligibility_resolution=suse_eligibility("9.8"),
            propagation=CVSSPropagation.IMMEDIATE,
            products=ProductPropagationSummary(2, 1, 0),
            severity_changed=False,
            reconciled=False,
            evaluation_date=EVAL,
        )
        assert recorder.writes() == []
        assert await ticket_events(db_session, ticket) == events

    @pytest.mark.parametrize(
        "status", [TicketStatus.NEW, *GATE_ZONE, *MANUAL_ZONE, "association"]
    )
    async def test_never_modifies_assessments_or_override_markers(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_with: CVEBuilder,
        tree: TreeBuilder,
        status: TicketStatus | str,
    ) -> None:
        cve = await cve_with(
            SUSE_CRITICAL,
            Assessment("2.0", version="4.0"),
            Assessment("5.0", provider="NVD"),
            severity=Severity.LOW,
        )
        ticket_status = (
            TicketStatus.ANALYSIS if status == "association" else TicketStatus(status)
        )
        ticket = await ticket_factory(
            status=ticket_status.value,
            **(
                {"severity_manual": Severity.LOW.value}
                if status == "association"
                else {"cve_id": cve.id}
            ),
        )
        await tree(
            ticket,
            status=PackageStatus.FIXED,
            products=(
                Prod(eligible=False, override=True),
                Prod(eligible=True, override=True, threshold=Decimal("9.9")),
                Prod(eligible=False, threshold=T9),
            ),
        )
        before = await assessment_snapshot(db_session, cve.id)
        kwargs: dict[str, Any] = {}
        if status == "association":
            await associate(db_session, ticket, cve)
            kwargs = {
                "mode": CVSSChainMode.ASSOCIATION,
                "association_previous_severity": Severity.LOW,
            }

        with StatementRecorder(db_session) as recorder:
            first = await run_chain(db_session, cve.id, **kwargs)
            second = await run_chain(
                db_session,
                cve.id,
                **(
                    {**kwargs, "association_previous_severity": Severity.CRITICAL}
                    if kwargs
                    else {}
                ),
            )

        assert first.classification is CHANGED
        assert second.classification is UNCHANGED
        assert await assessment_snapshot(db_session, cve.id) == before
        overrides = [o for _, o in await eligibility(db_session, ticket.id)]
        assert overrides == [True, True, False]
        assert [s for s in recorder.writes() if "cve_cvss_assessment" in s] == []
        assert [s for s in recorder.writes() if "is_eligible_override" in s] == []


# ---------------------------------------------------------------------------
# Whole-chain rollback (audit Testing Requirements 7 and 24)
# ---------------------------------------------------------------------------


FAILURES = ["settings", "database", "eligibility", "audit", "flush", "reconciliation"]


@pytest.mark.integration
class TestRollback:
    @pytest.mark.parametrize("failure", FAILURES)
    async def test_failure_rolls_back_the_complete_chain(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_with: CVEBuilder,
        tree: TreeBuilder,
        va_user: VAUser,
        default_setting: SystemSetting,
        monkeypatch: pytest.MonkeyPatch,
        failure: str,
    ) -> None:
        assignee = await va_user(active=False)
        cve, ticket = await _stale_gate_zone_ticket(
            ticket_factory, cve_with, tree, assignee_id=assignee.id, products=2
        )
        cve_id, ticket_id, assignee_id = cve.id, ticket.id, assignee.id
        expected_error: type[BaseException] = RuntimeError
        progress: dict[str, int] = {"audit": 0, "evaluations": 0}

        async with rollback_test_scope(db_session):
            if failure == "settings":
                await db_session.delete(default_setting)
                await db_session.flush()
                expected_error = RequiredSystemSettingMissingError
            elif failure == "database":
                original_refresh = ticket_mutations.refresh_priority_auto

                async def failing_refresh(db: AsyncSession, *, ticket: Ticket) -> bool:
                    await original_refresh(db, ticket=ticket)
                    await db.execute(text("SELECT 1 / 0"))
                    raise AssertionError("unreachable")  # pragma: no cover

                monkeypatch.setattr(
                    ticket_mutations, "refresh_priority_auto", failing_refresh
                )
                expected_error = DBAPIError
            elif failure == "eligibility":

                def failing_evaluate(**kwargs: Any) -> Any:
                    progress["evaluations"] += 1
                    if progress["evaluations"] == 2:
                        raise RuntimeError("injected eligibility failure")
                    return evaluate_product_eligibility(**kwargs)

                monkeypatch.setattr(
                    ticket_mutations, "evaluate_product_eligibility", failing_evaluate
                )
            elif failure == "audit":
                original_log = TicketAuditLog.log_event

                async def failing_log(*args: Any, **kwargs: Any) -> None:
                    progress["audit"] += 1
                    # Severity, two Products, then fail the priority event.
                    if progress["audit"] == 4:
                        raise RuntimeError("injected audit failure")
                    await original_log(*args, **kwargs)

                monkeypatch.setattr(TicketAuditLog, "log_event", failing_log)
            elif failure == "flush":
                original_reconcile = ticket_mutations.reconcile_ticket_status
                original_flush = db_session.flush
                reconciled = False

                async def tracking_reconcile(*args: Any, **kwargs: Any) -> None:
                    nonlocal reconciled
                    await original_reconcile(*args, **kwargs)
                    reconciled = True

                async def failing_flush(*args: Any, **kwargs: Any) -> None:
                    if reconciled:
                        raise RuntimeError("injected flush failure")
                    await original_flush(*args, **kwargs)

                monkeypatch.setattr(
                    ticket_mutations, "reconcile_ticket_status", tracking_reconcile
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

            with pytest.raises(expected_error):
                await run_chain(db_session, cve_id)
        monkeypatch.undo()

        if failure == "eligibility":
            assert progress["evaluations"] == 2
        if failure == "audit":
            assert progress["audit"] == 4
        assert await cve_severity(db_session, cve_id) == "Medium"
        assert await eligibility(db_session, ticket_id) == [
            (False, False),
            (False, False),
            (False, True),
        ]
        assert await ticket_state(db_session, ticket_id) == (
            TicketStatus.ANALYSIS,
            assignee_id,
            "P4",
            None,
            None,
        )
        assert await ticket_events_by_id(db_session, ticket_id) == []
        assert pending_ticket_convergence_effects(db_session) == ()

    async def test_unfailed_scenario_mutates_everything_the_failures_roll_back(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_with: CVEBuilder,
        tree: TreeBuilder,
        va_user: VAUser,
    ) -> None:
        """Control for the rollback matrix: without an injected failure the
        same scenario changes every asserted value."""
        assignee = await va_user(active=False)
        cve, ticket = await _stale_gate_zone_ticket(
            ticket_factory, cve_with, tree, assignee_id=assignee.id, products=2
        )

        await run_chain(db_session, cve.id)

        assert await cve_severity(db_session, cve.id) == "Critical"
        assert await eligibility(db_session, ticket.id) == [
            (True, False),
            (True, False),
            (False, True),
        ]
        assert await ticket_state(db_session, ticket.id) == (
            TicketStatus.ANALYZED,
            None,
            "P2",
            None,
            None,
        )
        detail = await subjects(db_session, ticket.id)
        assert await ticket_events(db_session, ticket) == [
            severity_event("Medium", "Critical"),
            product_event(detail[0], False, True),
            product_event(detail[1], False, True),
            priority_event("P4", "P2"),
            unassigned_event(assignee.username, "inactive assignee"),
            status_event(TicketStatus.ANALYSIS, TicketStatus.ANALYZED),
        ]


# ---------------------------------------------------------------------------
# One evaluation date
# ---------------------------------------------------------------------------


BOUNDARY = date(2026, 6, 15)
"""The first day of the boundary Product's Reactive Support."""


@pytest.mark.integration
class TestEvaluationDate:
    @pytest.mark.parametrize(
        ("supplied", "reactive"),
        [
            pytest.param(BOUNDARY, True, id="reactive-on-the-supplied-date"),
            pytest.param(BOUNDARY - timedelta(days=1), False, id="day-before"),
        ],
    )
    async def test_supplied_date_drives_lifecycle_reconciliation_and_result(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_with: CVEBuilder,
        tree: TreeBuilder,
        product_factory: Callable[..., Awaitable[Product]],
        ticket_package_product_factory: Callable[..., Awaitable[TicketPackageProduct]],
        monkeypatch: pytest.MonkeyPatch,
        supplied: date,
        reactive: bool,
    ) -> None:
        def clock() -> datetime:
            raise AssertionError("the supplied date must be reused")

        monkeypatch.setattr(ticket_mutations, "_utc_now", clock)
        cve = await cve_with(SUSE_CRITICAL, severity=Severity.CRITICAL)
        ticket = await ticket_factory(
            status=TicketStatus.ANALYSIS.value, cve_id=cve.id, priority_auto="P2"
        )
        track = await tree(ticket, status=PackageStatus.AFFECTED, products=())
        product = await product_factory(
            general_support_end_date=BOUNDARY - timedelta(days=60),
            extended_support_end_date=BOUNDARY - timedelta(days=1),
            reactive_support_end_date=BOUNDARY + timedelta(days=60),
        )
        await ticket_package_product_factory(
            ticket_package_track_id=track.id, product_id=product.id, eligible=True
        )
        reconcile = CallCounter(monkeypatch, "reconcile_ticket_status")

        with StatementRecorder(db_session) as recorder:
            result = await run_chain(db_session, cve.id, evaluation_date=supplied)

        assert result.evaluation_date == supplied
        assert _sql_dates(recorder) == {supplied}
        detail = await subjects(db_session, ticket.id)
        if reactive:
            # Reactive Support on the date: ineligible, so the AFFECTED
            # track has no actionable eligible Product and resolves.
            assert result.classification is CHANGED
            assert reconcile.calls == [{"evaluation_date": supplied}]
            assert await eligibility(db_session, ticket.id) == [(False, False)]
            assert await ticket_events(db_session, ticket) == [
                product_event(detail[0], True, False),
                status_event(TicketStatus.ANALYSIS, TicketStatus.RESOLVED),
            ]
        else:
            assert result.classification is UNCHANGED
            assert reconcile.calls == []
            assert await eligibility(db_session, ticket.id) == [(True, False)]
            assert await ticket_events(db_session, ticket) == []

    async def test_omitted_date_is_captured_once_across_a_utc_midnight(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_with: CVEBuilder,
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

        cve = await cve_with(SUSE_CRITICAL, severity=Severity.MEDIUM)
        ticket = await ticket_factory(
            status=TicketStatus.ANALYSIS.value, cve_id=cve.id, priority_auto="P2"
        )
        # Extended support ends on `day`: eligible on `day` (Analyzed gate
        # result), Reactive Support and ineligible the next day (Resolved).
        track = await tree(ticket, status=PackageStatus.AFFECTED, products=())
        product = await product_factory(
            general_support_end_date=day - timedelta(days=60),
            extended_support_end_date=day,
            reactive_support_end_date=day + timedelta(days=60),
        )
        await ticket_package_product_factory(
            ticket_package_track_id=track.id, product_id=product.id, eligible=True
        )
        monkeypatch.setattr(ticket_mutations, "_utc_now", clock)
        reconcile = CallCounter(monkeypatch, "reconcile_ticket_status")

        with StatementRecorder(db_session) as recorder:
            result = await run_chain(db_session, cve.id, evaluation_date=None)

        assert calls == 1
        assert result.evaluation_date == day
        assert reconcile.calls == [{"evaluation_date": day}]
        assert _sql_dates(recorder) == {day}
        assert await eligibility(db_session, ticket.id) == [(True, False)]
        assert (await ticket_state(db_session, ticket.id))[0] == TicketStatus.ANALYZED
        assert await ticket_events(db_session, ticket) == [
            severity_event("Medium", "Critical"),
            status_event(TicketStatus.ANALYSIS, TicketStatus.ANALYZED),
        ]

    async def test_omitted_date_of_a_missing_unit_is_captured_once(
        self, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        calls = 0

        def clock() -> datetime:
            nonlocal calls
            calls += 1
            return datetime(2026, 12, 31, 23, 59, 59, tzinfo=UTC)

        monkeypatch.setattr(ticket_mutations, "_utc_now", clock)

        result = await run_chain(db_session, uuid.uuid7(), evaluation_date=None)

        assert (calls, result.evaluation_date) == (1, date(2026, 12, 31))


# ---------------------------------------------------------------------------
# Lock order and serialization
# ---------------------------------------------------------------------------


_CVE_TABLE = re.compile(r"FROM cve\b")


@pytest.mark.integration
class TestLockOrder:
    async def test_cve_then_ticket_are_locked_before_any_other_read(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_with: CVEBuilder,
        tree: TreeBuilder,
    ) -> None:
        cve, ticket = await _stale_gate_zone_ticket(ticket_factory, cve_with, tree)

        with StatementRecorder(db_session) as recorder:
            await run_chain(db_session, cve.id)

        statements = recorder.statements
        assert _CVE_TABLE.search(statements[0])
        assert "FOR NO KEY UPDATE" in statements[0]
        assert "FROM ticket" in statements[1]
        assert "FOR UPDATE" in statements[1]
        assert "ticket.cve_id" in statements[1]
        setting = next(
            i for i, s in enumerate(statements) if "FROM system_setting" in s
        )
        assert setting == 2
        assert len(recorder.row_locks()) == 2
        assert recorder.selects_from("ticket_audit_event") == []
        assert (await ticket_state(db_session, ticket.id))[0] == TicketStatus.ANALYZED


class _CommittedWorld:
    """Committed rows for the independent-session test, deleted explicitly
    at teardown (testing-strategy.md, Concurrency Testing)."""

    def __init__(
        self, factory: Callable[[], Awaitable[AsyncSession]], session: AsyncSession
    ) -> None:
        self._factory = factory
        self.session = session
        self.cve_ids: list[uuid.UUID] = []
        self.ticket_ids: list[uuid.UUID] = []
        self._sessions: list[AsyncSession] = []
        self._tasks: list[asyncio.Task[Any]] = []

    async def open_session(self) -> AsyncSession:
        session = await self._factory()
        self._sessions.append(session)
        return session

    def track(self, task: asyncio.Task[Any]) -> None:
        self._tasks.append(task)

    async def cve_with_ticket(self) -> tuple[uuid.UUID, uuid.UUID]:
        cve = CVE(cve_id=f"CVE-2099-{uuid.uuid4().int % 10**8:08d}")
        self.session.add(cve)
        await self.session.flush()
        self.cve_ids.append(cve.id)
        ticket = Ticket(status=TicketStatus.ANALYSIS.value, cve_id=cve.id)
        self.session.add(ticket)
        await self.session.flush()
        self.ticket_ids.append(ticket.id)
        await self.session.commit()
        return cve.id, ticket.id

    async def cleanup(self) -> None:
        for session in self._sessions:
            with contextlib.suppress(Exception):
                await session.rollback()
        for task in self._tasks:
            if not task.done():
                task.cancel()
            with contextlib.suppress(Exception, asyncio.CancelledError):
                await task
        await self.session.rollback()
        for statement in (
            delete(TicketAuditEvent).where(
                TicketAuditEvent.ticket_id.in_(self.ticket_ids)
            ),
            delete(Ticket).where(Ticket.id.in_(self.ticket_ids)),
            delete(CVECVSSAssessment).where(CVECVSSAssessment.cve_id.in_(self.cve_ids)),
            delete(CVE).where(CVE.id.in_(self.cve_ids)),
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


@pytest.mark.integration
class TestLockSerialization:
    async def test_waits_for_the_cve_lock_and_recalculates_from_the_winner(
        self, committed_world: _CommittedWorld
    ) -> None:
        """Session B holds the CVE `FOR NO KEY UPDATE` (the CVE root mode)
        and adds the first SUSE assessment; A's recalculation blocks on the
        CVE lock and, after B commits, derives severity and priority from
        B's committed set."""
        cve_id, ticket_id = await committed_world.cve_with_ticket()
        a = await committed_world.open_session()
        b = await committed_world.open_session()
        await b.execute(
            select(CVE.id).where(CVE.id == cve_id).with_for_update(key_share=True)
        )
        b.add(
            CVECVSSAssessment(
                cve_id=cve_id,
                provider_name="SUSE",
                cvss_version="3.1",
                score=Decimal("9.8"),
                severity="critical",
                vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            )
        )
        await b.flush()

        task = asyncio.create_task(
            run_chain(a, cve_id, default_cvss_version=DEFAULT_VERSION)
        )
        committed_world.track(task)
        await assert_lock_wait(task, waiter=a, blocked_by=b)
        await b.commit()

        result = await asyncio.wait_for(task, timeout=5)

        assert result.classification is CHANGED
        assert result.severity_resolution == severity_resolution(
            "9.8", Severity.CRITICAL
        )
        assert result.reconciled is True
        assert await ticket_events_by_id(a, ticket_id) == [
            severity_event(None, "Critical"),
            priority_event(None, "P2"),
        ]
        await a.rollback()
