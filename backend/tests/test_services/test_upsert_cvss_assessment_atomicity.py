"""Atomicity, evaluation-date, and independent-session tests for
`upsert_cvss_assessment()` (backend/app/services/ticket_mutations.py).

Owning specifications:

- docs/features/tickets/ticket-mutations.md (CVSS Mutation Authority and
  Result: rollback of the complete chain; `upsert_cvss_assessment()`;
  Service Exceptions: `RequiredSystemSettingMissingError`; Architectural
  Test Requirement: complete atomic chain, serialized outcomes,
  independent-session races (default-version/CVSS), locked-current
  consumer accessibility).
- docs/features/tickets/cvss-scoring.md (Serialization and Concurrent
  Outcomes; Required Tests > Persistence and API Tests: two-session lock
  tests and manual API concurrency tests).
- docs/features/tickets/ticket-audit-log.md (Testing Requirements 7, 16,
  23, 24).
- docs/features/platform/testing-strategy.md (Concurrency Testing; Ticket
  Accessibility: Locked mutations).

The cross-path races against CVE ingestion and two external batches are
deferred to M3.1 (#669 Deferred). The CVSS/reactivation, association/CVSS,
and CVSS/override races live in test_manual_zone_exit_atomicity.py,
test_associate_cve_atomicity.py, and
test_set_product_eligibility_atomicity.py. Expected values are transcribed
from the specifications.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Awaitable, Callable
from datetime import UTC, date, datetime, timedelta
from decimal import Decimal
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import (
    PackageStatus,
    Role,
    Scope,
    Severity,
    TicketAuditEventType,
    TicketStatus,
)
from app.core.exceptions import CVENotFoundError
from app.models.cve import CVE
from app.models.system_setting import SystemSetting
from app.models.ticket import Ticket
from app.models.user import User
from app.services import cve_service, ticket_mutations
from app.services.settings import RequiredSystemSettingMissingError
from app.services.ticket_audit_log import TicketAuditLog
from app.services.ticket_convergence_registry import (
    pending_ticket_convergence_effects,
)
from app.services.ticket_mutations import (
    CVSSAssessmentAction,
    CVSSAssessmentMutationResult,
    CVSSChainClassification,
    CVSSChainMode,
    recalculate_cvss_chain,
)
from app.services.ticket_visibility import TicketCaller
from tests.support.cvss_chain import (
    CallCounter,
    cve_severity,
    eligibility,
    priority_event,
    product_event,
    severity_event,
    ticket_state,
)
from tests.support.database import assert_lock_wait, rollback_test_scope
from tests.support.suse_cvss import (
    V31_CRITICAL,
    V31_MEDIUM,
    V40_CRITICAL,
    assignment_event,
    cvss_event,
    persisted_assessments,
    upsert,
)
from tests.support.suse_cvss_races import (
    VISIBILITY_LOSSES,
    CommittedWorld,
    prepare_loss,
)
from tests.support.ticket_mutations import (
    EVAL,
    Prod,
    StatementRecorder,
    TicketFactory,
    TreeBuilder,
    VAUser,
    status_event,
    ticket_events_by_id,
)

pytest_plugins = ["tests.support.ticket_mutation_fixtures"]
"""Provides the shared `va_user` and `tree` fixtures."""

Factory = Callable[..., Awaitable[Any]]


@pytest.fixture
async def default_setting(system_setting_factory: Factory) -> SystemSetting:
    """The persisted `default_cvss_version` (the test schema has none)."""
    setting: SystemSetting = await system_setting_factory(
        key="default_cvss_version", value="3.1"
    )
    return setting


def _sql_dates(recorder: StatementRecorder) -> set[date]:
    """Every pure `date` bound in the recorded statements."""
    return {
        value
        for params in recorder.parameters
        for value in (params.values() if isinstance(params, dict) else params)
        if isinstance(value, date) and not isinstance(value, datetime)
    }


# ---------------------------------------------------------------------------
# Whole-chain rollback (audit Testing Requirements 7 and 24)
# ---------------------------------------------------------------------------


FAILURES = ["settings", "database", "eligibility", "audit", "flush", "reconciliation"]


@pytest.mark.integration
class TestRollback:
    async def _scenario(
        self,
        db: AsyncSession,
        ticket_factory: TicketFactory,
        cve_factory: Factory,
        tree: TreeBuilder,
        va_user: VAUser,
    ) -> tuple[User, CVE, Ticket]:
        """An unassigned `New` Ticket whose effective chain assigns,
        promotes, writes the assessment and severity, changes a Product,
        refreshes priority, and reaches `Analyzed`."""
        actor = await va_user()
        cve: CVE = await cve_factory()
        ticket = await ticket_factory(status=TicketStatus.NEW.value, cve_id=cve.id)
        await tree(
            ticket,
            status=PackageStatus.AFFECTED,
            products=(Prod(eligible=False, threshold=Decimal("7.0")),),
        )
        return actor, cve, ticket

    @pytest.mark.parametrize("failure", FAILURES)
    async def test_failure_rolls_back_the_complete_chain(
        self,
        db_session: AsyncSession,
        default_setting: SystemSetting,
        ticket_factory: TicketFactory,
        cve_factory: Factory,
        tree: TreeBuilder,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
        failure: str,
    ) -> None:
        actor, cve, ticket = await self._scenario(
            db_session, ticket_factory, cve_factory, tree, va_user
        )
        cve_id, ticket_id = cve.id, ticket.id
        expected_error: type[BaseException] = RuntimeError
        reached = False

        async with rollback_test_scope(db_session):
            if failure == "settings":
                await db_session.delete(default_setting)
                await db_session.flush()
                expected_error = RequiredSystemSettingMissingError
            elif failure == "database":
                original_refresh = ticket_mutations.refresh_priority_auto

                async def failing_refresh(db: AsyncSession, *, ticket: Ticket) -> bool:
                    nonlocal reached
                    reached = await original_refresh(db, ticket=ticket)
                    await db.execute(text("SELECT 1 / 0"))
                    raise AssertionError("unreachable")  # pragma: no cover

                monkeypatch.setattr(
                    ticket_mutations, "refresh_priority_auto", failing_refresh
                )
                expected_error = DBAPIError
            elif failure == "eligibility":

                def failing_evaluate(**kwargs: Any) -> Any:
                    nonlocal reached
                    reached = True
                    raise RuntimeError("injected eligibility failure")

                monkeypatch.setattr(
                    ticket_mutations, "evaluate_product_eligibility", failing_evaluate
                )
            elif failure == "audit":
                original_log = TicketAuditLog.log_event

                async def failing_log(*args: Any, **kwargs: Any) -> None:
                    nonlocal reached
                    if kwargs["event_type"] is TicketAuditEventType.PRIORITY_CHANGED:
                        reached = True
                        raise RuntimeError("injected audit failure")
                    await original_log(*args, **kwargs)

                monkeypatch.setattr(TicketAuditLog, "log_event", failing_log)
            elif failure == "flush":
                original_reconcile = ticket_mutations.reconcile_ticket_status
                original_flush = db_session.flush

                async def tracking_reconcile(*args: Any, **kwargs: Any) -> None:
                    nonlocal reached
                    await original_reconcile(*args, **kwargs)
                    reached = True

                async def failing_flush(*args: Any, **kwargs: Any) -> None:
                    if reached:
                        raise RuntimeError("injected flush failure")
                    await original_flush(*args, **kwargs)

                monkeypatch.setattr(
                    ticket_mutations, "reconcile_ticket_status", tracking_reconcile
                )
                monkeypatch.setattr(db_session, "flush", failing_flush)
            else:
                original_reconcile = ticket_mutations.reconcile_ticket_status

                async def failing_reconcile(*args: Any, **kwargs: Any) -> None:
                    nonlocal reached
                    await original_reconcile(*args, **kwargs)
                    reached = True
                    raise RuntimeError("injected reconciliation failure")

                monkeypatch.setattr(
                    ticket_mutations, "reconcile_ticket_status", failing_reconcile
                )

            with pytest.raises(expected_error):
                await upsert(db_session, cve_id, V31_CRITICAL.canonical, actor)
        monkeypatch.undo()

        assert reached is (failure != "settings")
        assert await persisted_assessments(db_session, cve_id) == []
        assert await cve_severity(db_session, cve_id) is None
        assert await eligibility(db_session, ticket_id) == [(False, False)]
        assert await ticket_state(db_session, ticket_id) == (
            TicketStatus.NEW,
            None,
            None,
            None,
            None,
        )
        assert await ticket_events_by_id(db_session, ticket_id) == []
        assert pending_ticket_convergence_effects(db_session) == ()

    async def test_unfailed_scenario_mutates_everything_the_failures_roll_back(
        self,
        db_session: AsyncSession,
        default_setting: SystemSetting,
        ticket_factory: TicketFactory,
        cve_factory: Factory,
        tree: TreeBuilder,
        va_user: VAUser,
    ) -> None:
        """Control for the rollback matrix: without an injected failure the
        same scenario changes every asserted value."""
        actor, cve, ticket = await self._scenario(
            db_session, ticket_factory, cve_factory, tree, va_user
        )

        await upsert(db_session, cve.id, V31_CRITICAL.canonical, actor)

        assert len(await persisted_assessments(db_session, cve.id)) == 1
        assert await cve_severity(db_session, cve.id) == "Critical"
        assert await eligibility(db_session, ticket.id) == [(True, False)]
        assert await ticket_state(db_session, ticket.id) == (
            TicketStatus.ANALYZED,
            actor.id,
            "P2",
            None,
            None,
        )
        assert [
            e.event_type for e in await ticket_events_by_id(db_session, ticket.id)
        ] == [
            "assignment",
            "status_change",
            "cvss_assessment_changed",
            "severity_changed",
            "product_eligibility_changed",
            "priority_changed",
            "status_change",
        ]


# ---------------------------------------------------------------------------
# One evaluation date
# ---------------------------------------------------------------------------


@pytest.mark.integration
@pytest.mark.usefixtures("default_setting")
class TestEvaluationDate:
    async def test_supplied_date_is_reused_without_the_clock(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_factory: Factory,
        tree: TreeBuilder,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        def clock() -> datetime:
            raise AssertionError("the supplied date must be reused")

        monkeypatch.setattr(ticket_mutations, "_utc_now", clock)
        reconcile = CallCounter(monkeypatch, "reconcile_ticket_status")
        actor = await va_user()
        cve: CVE = await cve_factory()
        ticket = await ticket_factory(
            status=TicketStatus.ANALYSIS.value, cve_id=cve.id, assignee_id=actor.id
        )
        await tree(ticket, status=PackageStatus.AFFECTED)
        supplied = date(2026, 1, 2)

        with StatementRecorder(db_session) as recorder:
            result = await upsert(
                db_session,
                cve.id,
                V31_CRITICAL.canonical,
                actor,
                evaluation_date=supplied,
            )

        assert result.evaluation_date == supplied
        assert reconcile.calls == [{"evaluation_date": supplied}]
        assert _sql_dates(recorder) == {supplied}

    async def test_omitted_date_is_captured_once_across_a_utc_midnight(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_factory: Factory,
        tree: TreeBuilder,
        product_factory: Factory,
        ticket_package_product_factory: Factory,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Extended support ends on `day`: the Product is eligible on `day`
        and in Reactive Support (ineligible) the next day."""
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
        cve: CVE = await cve_factory()
        ticket = await ticket_factory(
            status=TicketStatus.ANALYSIS.value, cve_id=cve.id, assignee_id=actor.id
        )
        track = await tree(ticket, status=PackageStatus.AFFECTED, products=())
        product = await product_factory(
            general_support_end_date=day - timedelta(days=60),
            extended_support_end_date=day,
            reactive_support_end_date=day + timedelta(days=60),
        )
        await ticket_package_product_factory(
            ticket_package_track_id=track.id, product_id=product.id, eligible=False
        )
        monkeypatch.setattr(ticket_mutations, "_utc_now", clock)
        reconcile = CallCounter(monkeypatch, "reconcile_ticket_status")

        with StatementRecorder(db_session) as recorder:
            result = await upsert(
                db_session, cve.id, V31_CRITICAL.canonical, actor, evaluation_date=None
            )

        assert calls == 1
        assert result.evaluation_date == day
        assert reconcile.calls == [{"evaluation_date": day}]
        assert _sql_dates(recorder) == {day}
        assert await eligibility(db_session, ticket.id) == [(True, False)]
        assert (await ticket_state(db_session, ticket.id))[0] == TicketStatus.ANALYZED


# ---------------------------------------------------------------------------
# Independent sessions
# ---------------------------------------------------------------------------


@pytest.fixture
async def committed_world(
    db_session_factory: Callable[[], Awaitable[AsyncSession]],
) -> AsyncIterator[CommittedWorld]:
    world = CommittedWorld(db_session_factory, await db_session_factory())
    try:
        yield world
    finally:
        await world.cleanup()


def _upsert_task(
    world: CommittedWorld,
    session: AsyncSession,
    cve: CVE,
    vector: str,
    actor: User,
    *,
    scope: Scope = Scope.ALL,
) -> asyncio.Task[CVSSAssessmentMutationResult]:
    """An upsert in `session`; the default version is passed explicitly
    because the committed test schema has no setting row."""
    return world.start(
        session,
        upsert(session, cve.id, vector, actor, scope=scope, default_cvss_version="3.1"),
    )


@pytest.mark.integration
class TestSerializedOutcomes:
    async def test_waiting_equal_upsert_is_unchanged(
        self, committed_world: CommittedWorld
    ) -> None:
        owner = await committed_world.user(role=Role.VULNERABILITY_ANALYST)
        actor = await committed_world.user(role=Role.VULNERABILITY_ANALYST)
        cve = await committed_world.cve()
        ticket = await committed_world.ticket(cve_id=cve.id, assignee_id=owner.id)
        a = await committed_world.open_session()
        b = await committed_world.open_session()

        winner = await upsert(
            b, cve.id, V31_CRITICAL.canonical, owner, default_cvss_version="3.1"
        )
        task = _upsert_task(committed_world, a, cve, V31_CRITICAL.canonical, actor)
        await assert_lock_wait(task, waiter=a, blocked_by=b)
        await b.commit()

        loser = await asyncio.wait_for(task, timeout=5)

        assert winner.action is CVSSAssessmentAction.CREATED
        assert loser.action is CVSSAssessmentAction.UNCHANGED
        assert loser.assessment is not None
        assert winner.assessment is not None
        assert loser.assessment.id == winner.assessment.id
        assert await ticket_events_by_id(a, ticket.id) == [
            cvss_event(owner, None, V31_CRITICAL),
            severity_event(None, "Critical"),
            priority_event(None, "P2"),
        ]
        await a.rollback()

    async def test_waiting_differing_upsert_updates_from_the_winner(
        self, committed_world: CommittedWorld
    ) -> None:
        owner = await committed_world.user(role=Role.VULNERABILITY_ANALYST)
        actor = await committed_world.user(role=Role.VULNERABILITY_ANALYST)
        cve = await committed_world.cve()
        ticket = await committed_world.ticket(cve_id=cve.id, assignee_id=owner.id)
        a = await committed_world.open_session()
        b = await committed_world.open_session()

        await upsert(b, cve.id, V31_MEDIUM.canonical, owner, default_cvss_version="3.1")
        task = _upsert_task(committed_world, a, cve, V31_CRITICAL.canonical, actor)
        await assert_lock_wait(task, waiter=a, blocked_by=b)
        await b.commit()

        result = await asyncio.wait_for(task, timeout=5)

        assert result.action is CVSSAssessmentAction.UPDATED
        assert result.severity_changed is True
        assert await ticket_events_by_id(a, ticket.id) == [
            cvss_event(owner, None, V31_MEDIUM),
            severity_event(None, "Medium"),
            priority_event(None, "P4"),
            cvss_event(actor, V31_MEDIUM, V31_CRITICAL),
            severity_event("Medium", "Critical"),
            priority_event("P4", "P2"),
        ]
        await a.rollback()

    async def test_first_upsert_on_an_unassigned_ticket_assigns_once(
        self, committed_world: CommittedWorld
    ) -> None:
        """Two VA actors race on an unassigned Ticket: only the serialized
        winner assigns; the waiter sees the locked-current assignee."""
        first = await committed_world.user(role=Role.VULNERABILITY_ANALYST)
        second = await committed_world.user(role=Role.VULNERABILITY_ANALYST)
        cve = await committed_world.cve()
        ticket = await committed_world.ticket(cve_id=cve.id)
        a = await committed_world.open_session()
        b = await committed_world.open_session()

        await upsert(b, cve.id, V31_MEDIUM.canonical, first, default_cvss_version="3.1")
        task = _upsert_task(committed_world, a, cve, V31_CRITICAL.canonical, second)
        await assert_lock_wait(task, waiter=a, blocked_by=b)
        await b.commit()

        result = await asyncio.wait_for(task, timeout=5)

        assert result.assigned is False
        events = await ticket_events_by_id(a, ticket.id)
        assert [e for e in events if e.event_type == "assignment"] == [
            assignment_event(first)
        ]
        await a.rollback()


@pytest.mark.integration
class TestDefaultVersionRace:
    """`recalculate_cvss_chain()` in default-version mode (the M4 runner's
    unit) and a manual SUSE upsert serialize on the CVE root; each
    recomputes from the winner's committed state and never duplicates a
    Product event or the final reconciliation."""

    async def _world(
        self, world: CommittedWorld
    ) -> tuple[User, CVE, Ticket, dict[str, str]]:
        owner = await world.user(role=Role.VULNERABILITY_ANALYST)
        cve = await world.cve(V31_CRITICAL, severity=Severity.CRITICAL)
        ticket = await world.ticket(
            cve_id=cve.id, assignee_id=owner.id, priority_auto="P2"
        )
        # Converged under default 3.1: 9.8 < 9.9.
        detail = await world.affected_product(
            ticket, threshold=Decimal("9.9"), eligible=False
        )
        return owner, cve, ticket, detail

    async def test_runner_first_then_the_waiting_upsert(
        self, committed_world: CommittedWorld
    ) -> None:
        owner, cve, ticket, detail = await self._world(committed_world)
        a = await committed_world.open_session()
        b = await committed_world.open_session()

        runner = await recalculate_cvss_chain(
            b,
            cve_id=cve.id,
            mode=CVSSChainMode.DEFAULT_VERSION,
            default_cvss_version="4.0",
            evaluation_date=EVAL,
        )
        task = committed_world.start(
            a,
            upsert(
                a, cve.id, V40_CRITICAL.canonical, owner, default_cvss_version="4.0"
            ),
        )
        await assert_lock_wait(task, waiter=a, blocked_by=b)
        await b.commit()

        result = await asyncio.wait_for(task, timeout=5)

        assert (runner.products.changed, runner.reconciled) == (1, True)
        assert result.products.changed == 1
        assert result.reconciled is True
        assert await ticket_events_by_id(a, ticket.id) == [
            product_event(detail, False, True),
            status_event(TicketStatus.ANALYSIS.value, TicketStatus.ANALYZED.value),
            cvss_event(owner, None, V40_CRITICAL),
            product_event(detail, True, False),
            status_event(TicketStatus.ANALYZED.value, TicketStatus.RESOLVED.value),
        ]
        await a.rollback()

    async def test_upsert_first_then_the_waiting_runner(
        self, committed_world: CommittedWorld
    ) -> None:
        owner, cve, ticket, _ = await self._world(committed_world)
        a = await committed_world.open_session()
        b = await committed_world.open_session()

        created = await upsert(
            a, cve.id, V40_CRITICAL.canonical, owner, default_cvss_version="4.0"
        )
        task = committed_world.start(
            b,
            recalculate_cvss_chain(
                b,
                cve_id=cve.id,
                mode=CVSSChainMode.DEFAULT_VERSION,
                default_cvss_version="4.0",
                evaluation_date=EVAL,
            ),
        )
        await assert_lock_wait(task, waiter=b, blocked_by=a)
        await a.commit()

        runner = await asyncio.wait_for(task, timeout=5)

        assert (created.products.changed, created.reconciled) == (0, False)
        assert runner.classification is CVSSChainClassification.UNCHANGED
        assert (runner.products.changed, runner.reconciled) == (0, False)
        assert await ticket_events_by_id(b, ticket.id) == [
            cvss_event(owner, None, V40_CRITICAL)
        ]
        await b.rollback()


# ---------------------------------------------------------------------------
# Locked-current CVE accessibility races
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestLockedCurrentAccessibilityRaces:
    """Session A passes the preliminary locator check; session B removes
    A's only visibility path, either while A waits for a root lock or
    before A starts. A must be denied from the locked-current state with
    zero side effects (testing-strategy.md, Ticket Accessibility: Locked
    mutations; cvss-scoring.md, Serialization and Concurrent Outcomes)."""

    @pytest.mark.parametrize("timing", ["while-waiting", "after-preliminary"])
    @pytest.mark.parametrize("loss", VISIBILITY_LOSSES)
    async def test_visibility_lost_before_the_lock_is_cve_not_found(
        self,
        committed_world: CommittedWorld,
        monkeypatch: pytest.MonkeyPatch,
        loss: str,
        timing: str,
    ) -> None:
        user, cve, ticket, statements = await prepare_loss(committed_world, loss)
        a = await committed_world.open_session()
        b = await committed_world.open_session()
        caller = TicketCaller.authenticated(user.id, Scope.NON_CONFIDENTIAL)
        assign = CallCounter(monkeypatch, "auto_assign_actor")
        reconcile = CallCounter(monkeypatch, "reconcile_ticket_status")
        propagate = CallCounter(monkeypatch, "_propagate_automatic_product_eligibility")

        resolved = await cve_service.resolve_cve_locator(a, cve.cve_id, caller)
        assert resolved.id == cve.id
        for statement in statements:
            await b.execute(statement)
        if timing == "while-waiting":
            task = _upsert_task(
                committed_world,
                a,
                cve,
                V31_CRITICAL.canonical,
                user,
                scope=Scope.NON_CONFIDENTIAL,
            )
            await assert_lock_wait(task, waiter=a, blocked_by=b)
            await b.commit()
        else:
            await b.commit()
            task = _upsert_task(
                committed_world,
                a,
                cve,
                V31_CRITICAL.canonical,
                user,
                scope=Scope.NON_CONFIDENTIAL,
            )

        with pytest.raises(CVENotFoundError):
            await asyncio.wait_for(task, timeout=5)

        assert (assign.calls, reconcile.calls, propagate.calls) == ([], [], [])
        assert pending_ticket_convergence_effects(a) == ()
        await a.rollback()
        fresh = await committed_world.open_session()
        assert await persisted_assessments(fresh, cve.id) == []
        assert await cve_severity(fresh, cve.id) is None
        assert await ticket_events_by_id(fresh, ticket.id) == []
        assert await ticket_state(fresh, ticket.id) == (
            TicketStatus.ANALYSIS,
            None,
            None,
            None,
            None,
        )
        await fresh.rollback()
