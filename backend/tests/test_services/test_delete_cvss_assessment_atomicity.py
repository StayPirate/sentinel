"""Atomicity, evaluation-date, and independent-session tests for
`delete_cvss_assessment()` (backend/app/services/ticket_mutations.py).

Owning specifications:

- docs/features/tickets/ticket-mutations.md (CVSS Mutation Authority and
  Result: rollback of the complete chain; `delete_cvss_assessment()`;
  Service Exceptions: `RequiredSystemSettingMissingError`; Architectural
  Test Requirement: complete atomic chain, serialized outcomes
  (delete/not-found and upsert/delete races), locked-current consumer
  accessibility).
- docs/features/tickets/cvss-scoring.md (Serialization and Concurrent
  Outcomes: "a waiting delete after another delete is `not_found`";
  Required Tests > Persistence and API Tests: two-session lock tests and
  manual API concurrency tests).
- docs/features/tickets/ticket-audit-log.md (Canonical Mutation and
  No-Event Matrix: concurrent-loser and rolled-back outcomes; Cross-Event
  Ordering, Locking, and Rollback).
- docs/features/platform/testing-strategy.md (Concurrency Testing; Ticket
  Accessibility: Locked mutations; Audit Trail Testing).

Expected values are transcribed from the specifications.
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
    CVSSPropagation,
)
from app.services.ticket_visibility import TicketCaller
from tests.support.cvss_chain import (
    FALLBACK,
    CallCounter,
    cve_severity,
    eligibility,
    priority_event,
    severity_event,
    severity_resolution,
    ticket_state,
)
from tests.support.database import rollback_test_scope
from tests.support.suse_cvss import (
    V31_CRITICAL,
    V31_MEDIUM,
    V40_CRITICAL,
    Vector,
    cvss_delete_event,
    cvss_event,
    delete_assessment,
    persisted_assessments,
    unit,
    upsert,
)
from tests.support.suse_cvss_races import (
    VISIBILITY_LOSSES,
    CommittedWorld,
    assert_blocked,
    prepare_loss,
)
from tests.support.ticket_mutations import (
    Prod,
    StatementRecorder,
    TicketFactory,
    TreeBuilder,
    VAUser,
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
# Whole-chain rollback
# ---------------------------------------------------------------------------


FAILURES = ["settings", "database", "eligibility", "audit", "flush", "reconciliation"]


@pytest.mark.integration
class TestRollback:
    async def _scenario(
        self,
        ticket_factory: TicketFactory,
        cve_factory: Factory,
        cve_cvss_assessment_factory: Factory,
        tree: TreeBuilder,
        va_user: VAUser,
    ) -> tuple[User, CVE, Ticket]:
        """An unassigned `New` Ticket whose effective delete assigns,
        promotes, deletes the default-version SUSE assessment, changes the
        severity (`Medium` to the SUSE v4.0 `Critical`) and a Product (the
        `10.0` fallback), refreshes priority, and reaches `Analyzed`."""
        actor = await va_user()
        cve: CVE = await cve_factory(severity=Severity.MEDIUM.value)
        for vector in (V31_MEDIUM, V40_CRITICAL):
            await cve_cvss_assessment_factory(
                cve_id=cve.id, provider_name="SUSE", **vector.columns()
            )
        ticket = await ticket_factory(
            status=TicketStatus.NEW.value, cve_id=cve.id, priority_auto="P4"
        )
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
        cve_cvss_assessment_factory: Factory,
        tree: TreeBuilder,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
        failure: str,
    ) -> None:
        actor, cve, ticket = await self._scenario(
            ticket_factory, cve_factory, cve_cvss_assessment_factory, tree, va_user
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
                await delete_assessment(db_session, cve_id, "3.1", actor)
        monkeypatch.undo()

        assert reached is (failure != "settings")
        assert await persisted_assessments(db_session, cve_id) == [
            unit("SUSE", V31_MEDIUM),
            unit("SUSE", V40_CRITICAL),
        ]
        assert await cve_severity(db_session, cve_id) == "Medium"
        assert await eligibility(db_session, ticket_id) == [(False, False)]
        assert await ticket_state(db_session, ticket_id) == (
            TicketStatus.NEW,
            None,
            "P4",
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
        cve_cvss_assessment_factory: Factory,
        tree: TreeBuilder,
        va_user: VAUser,
    ) -> None:
        """Control for the rollback matrix: without an injected failure the
        same scenario changes every asserted value."""
        actor, cve, ticket = await self._scenario(
            ticket_factory, cve_factory, cve_cvss_assessment_factory, tree, va_user
        )

        await delete_assessment(db_session, cve.id, "3.1", actor)

        assert await persisted_assessments(db_session, cve.id) == [
            unit("SUSE", V40_CRITICAL)
        ]
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
        cve_cvss_assessment_factory: Factory,
        tree: TreeBuilder,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        def clock() -> datetime:
            raise AssertionError("the supplied date must be reused")

        monkeypatch.setattr(ticket_mutations, "_utc_now", clock)
        reconcile = CallCounter(monkeypatch, "reconcile_ticket_status")
        actor = await va_user()
        cve: CVE = await cve_factory(severity=Severity.CRITICAL.value)
        await cve_cvss_assessment_factory(
            cve_id=cve.id, provider_name="SUSE", **V31_CRITICAL.columns()
        )
        ticket = await ticket_factory(
            status=TicketStatus.ANALYSIS.value, cve_id=cve.id, assignee_id=actor.id
        )
        await tree(ticket, status=PackageStatus.AFFECTED)
        supplied = date(2026, 1, 2)

        with StatementRecorder(db_session) as recorder:
            result = await delete_assessment(
                db_session, cve.id, "3.1", actor, evaluation_date=supplied
            )

        assert result.evaluation_date == supplied
        assert reconcile.calls == [{"evaluation_date": supplied}]
        assert _sql_dates(recorder) == {supplied}

    async def test_omitted_date_is_captured_once_across_a_utc_midnight(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_factory: Factory,
        cve_cvss_assessment_factory: Factory,
        tree: TreeBuilder,
        product_factory: Factory,
        ticket_package_product_factory: Factory,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Extended support ends on `day`: the stale automatic Product is
        eligible on `day` and in Reactive Support (ineligible) the next
        day. Deleting the non-default SUSE v4.0 assessment re-evaluates
        it."""
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
        cve: CVE = await cve_factory(severity=Severity.CRITICAL.value)
        for vector in (V31_CRITICAL, V40_CRITICAL):
            await cve_cvss_assessment_factory(
                cve_id=cve.id, provider_name="SUSE", **vector.columns()
            )
        ticket = await ticket_factory(
            status=TicketStatus.ANALYSIS.value,
            cve_id=cve.id,
            assignee_id=actor.id,
            priority_auto="P2",
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
            result = await delete_assessment(
                db_session, cve.id, "4.0", actor, evaluation_date=None
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


def _delete_task(
    world: CommittedWorld,
    session: AsyncSession,
    cve: CVE,
    version: str,
    actor: User,
    *,
    scope: Scope = Scope.ALL,
) -> asyncio.Task[CVSSAssessmentMutationResult]:
    """A delete in `session`; the default version is passed explicitly
    because the committed test schema has no setting row."""
    return world.start(
        session,
        delete_assessment(
            session, cve.id, version, actor, scope=scope, default_cvss_version="3.1"
        ),
    )


async def _world(
    world: CommittedWorld, *assessments: Vector, severity: Severity | None
) -> tuple[User, User, CVE, Ticket]:
    """Two VA users and an `Analysis` Ticket assigned to the first, with a
    `priority_auto` consistent with `severity`."""
    owner = await world.user(role=Role.VULNERABILITY_ANALYST)
    actor = await world.user(role=Role.VULNERABILITY_ANALYST)
    cve = await world.cve(*assessments, severity=severity)
    priority = {None: None, Severity.MEDIUM: "P4", Severity.CRITICAL: "P2"}[severity]
    ticket = await world.ticket(
        cve_id=cve.id, assignee_id=owner.id, priority_auto=priority
    )
    return owner, actor, cve, ticket


@pytest.mark.integration
class TestSerializedOutcomes:
    async def test_waiting_delete_after_a_delete_is_not_found(
        self, committed_world: CommittedWorld
    ) -> None:
        owner, actor, cve, ticket = await _world(
            committed_world, V31_CRITICAL, severity=Severity.CRITICAL
        )
        a = await committed_world.open_session()
        b = await committed_world.open_session()

        winner = await delete_assessment(
            b, cve.id, "3.1", owner, default_cvss_version="3.1"
        )
        task = _delete_task(committed_world, a, cve, "3.1", actor)
        await assert_blocked(task)
        await b.commit()

        loser = await asyncio.wait_for(task, timeout=5)

        assert winner.action is CVSSAssessmentAction.DELETED
        assert loser.action is CVSSAssessmentAction.NOT_FOUND
        assert loser.assessment is None
        assert loser.propagation is CVSSPropagation.NONE
        assert loser.severity_resolution is None
        assert loser.eligibility_resolution == FALLBACK
        assert (loser.assigned, loser.reconciled) == (False, False)
        assert await ticket_events_by_id(a, ticket.id) == [
            cvss_delete_event(owner, V31_CRITICAL),
            severity_event("Critical", None),
            priority_event("P2", None),
        ]
        await a.rollback()

    async def test_waiting_upsert_after_a_delete_creates(
        self, committed_world: CommittedWorld
    ) -> None:
        owner, actor, cve, ticket = await _world(
            committed_world, V31_MEDIUM, severity=Severity.MEDIUM
        )
        a = await committed_world.open_session()
        b = await committed_world.open_session()

        await delete_assessment(b, cve.id, "3.1", owner, default_cvss_version="3.1")
        task = committed_world.start(
            a,
            upsert(
                a, cve.id, V31_CRITICAL.canonical, actor, default_cvss_version="3.1"
            ),
        )
        await assert_blocked(task)
        await b.commit()

        result = await asyncio.wait_for(task, timeout=5)

        assert result.action is CVSSAssessmentAction.CREATED
        assert result.propagation is CVSSPropagation.IMMEDIATE
        assert result.severity_changed is True
        assert await ticket_events_by_id(a, ticket.id) == [
            cvss_delete_event(owner, V31_MEDIUM),
            severity_event("Medium", None),
            priority_event("P4", None),
            cvss_event(actor, None, V31_CRITICAL),
            severity_event(None, "Critical"),
            priority_event(None, "P2"),
        ]
        await a.rollback()

    async def test_waiting_delete_after_an_update_deletes_the_updated_row(
        self, committed_world: CommittedWorld
    ) -> None:
        owner, actor, cve, ticket = await _world(
            committed_world, V31_MEDIUM, severity=Severity.MEDIUM
        )
        a = await committed_world.open_session()
        b = await committed_world.open_session()

        await upsert(
            b, cve.id, V31_CRITICAL.canonical, owner, default_cvss_version="3.1"
        )
        task = _delete_task(committed_world, a, cve, "3.1", actor)
        await assert_blocked(task)
        await b.commit()

        result = await asyncio.wait_for(task, timeout=5)

        assert result.action is CVSSAssessmentAction.DELETED
        assert result.assessment is not None
        assert result.assessment.vector_string == V31_CRITICAL.canonical
        assert result.propagation is CVSSPropagation.IMMEDIATE
        assert (result.severity_resolution, result.severity_changed) == (None, True)
        assert await ticket_events_by_id(a, ticket.id) == [
            cvss_event(owner, V31_MEDIUM, V31_CRITICAL),
            severity_event("Medium", "Critical"),
            priority_event("P4", "P2"),
            cvss_delete_event(actor, V31_CRITICAL),
            severity_event("Critical", None),
            priority_event("P2", None),
        ]
        await a.rollback()

    async def test_waiting_delete_after_a_create_deletes_the_created_row(
        self, committed_world: CommittedWorld
    ) -> None:
        """An unlocked pre-read would have classified `not_found`."""
        owner, actor, cve, ticket = await _world(committed_world, severity=None)
        a = await committed_world.open_session()
        b = await committed_world.open_session()

        await upsert(
            b, cve.id, V31_CRITICAL.canonical, owner, default_cvss_version="3.1"
        )
        task = _delete_task(committed_world, a, cve, "3.1", actor)
        await assert_blocked(task)
        await b.commit()

        result = await asyncio.wait_for(task, timeout=5)

        assert result.action is CVSSAssessmentAction.DELETED
        assert await ticket_events_by_id(a, ticket.id) == [
            cvss_event(owner, None, V31_CRITICAL),
            severity_event(None, "Critical"),
            priority_event(None, "P2"),
            cvss_delete_event(actor, V31_CRITICAL),
            severity_event("Critical", None),
            priority_event("P2", None),
        ]
        await a.rollback()

    async def test_waiting_upsert_after_a_delete_of_another_version(
        self, committed_world: CommittedWorld
    ) -> None:
        """The waiting upsert classifies from the winner's remaining set:
        its SUSE v3.1 row still exists, so an equal vector is `unchanged`,
        and its result resolves without the deleted v4.0 row."""
        owner, actor, cve, ticket = await _world(
            committed_world, V31_MEDIUM, V40_CRITICAL, severity=Severity.MEDIUM
        )
        a = await committed_world.open_session()
        b = await committed_world.open_session()

        await delete_assessment(b, cve.id, "4.0", owner, default_cvss_version="3.1")
        task = committed_world.start(
            a,
            upsert(a, cve.id, V31_MEDIUM.canonical, actor, default_cvss_version="3.1"),
        )
        await assert_blocked(task)
        await b.commit()

        result = await asyncio.wait_for(task, timeout=5)

        assert result.action is CVSSAssessmentAction.UNCHANGED
        assert result.severity_resolution == severity_resolution("4.8", Severity.MEDIUM)
        assert await persisted_assessments(a, cve.id) == [unit("SUSE", V31_MEDIUM)]
        assert await ticket_events_by_id(a, ticket.id) == [
            cvss_delete_event(owner, V40_CRITICAL)
        ]
        await a.rollback()

    async def test_first_delete_on_an_unassigned_ticket_assigns_once(
        self, committed_world: CommittedWorld
    ) -> None:
        """Two VA actors race to delete different versions on an unassigned
        Ticket: only the serialized winner assigns."""
        first = await committed_world.user(role=Role.VULNERABILITY_ANALYST)
        second = await committed_world.user(role=Role.VULNERABILITY_ANALYST)
        cve = await committed_world.cve(
            V31_CRITICAL, V40_CRITICAL, severity=Severity.CRITICAL
        )
        ticket = await committed_world.ticket(cve_id=cve.id, priority_auto="P2")
        a = await committed_world.open_session()
        b = await committed_world.open_session()

        winner = await delete_assessment(
            b, cve.id, "4.0", first, default_cvss_version="3.1"
        )
        task = _delete_task(committed_world, a, cve, "3.1", second)
        await assert_blocked(task)
        await b.commit()

        result = await asyncio.wait_for(task, timeout=5)

        assert (winner.assigned, result.assigned) == (True, False)
        events = await ticket_events_by_id(a, ticket.id)
        assert [e.user_id for e in events if e.event_type == "assignment"] == [first.id]
        await a.rollback()


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
        user, cve, ticket, statements = await prepare_loss(
            committed_world, loss, V31_CRITICAL, severity=Severity.CRITICAL
        )
        a = await committed_world.open_session()
        b = await committed_world.open_session()
        caller = TicketCaller.authenticated(user.id, Scope.NON_CONFIDENTIAL)
        assign = CallCounter(monkeypatch, "auto_assign_actor")
        reconcile = CallCounter(monkeypatch, "reconcile_ticket_status")
        propagate = CallCounter(monkeypatch, "_propagate_automatic_product_eligibility")
        refresh = CallCounter(monkeypatch, "refresh_priority_auto")

        resolved = await cve_service.resolve_cve_locator(a, cve.cve_id, caller)
        assert resolved.id == cve.id
        for statement in statements:
            await b.execute(statement)
        if timing == "while-waiting":
            task = _delete_task(
                committed_world, a, cve, "3.1", user, scope=Scope.NON_CONFIDENTIAL
            )
            await assert_blocked(task)
            await b.commit()
        else:
            await b.commit()
            task = _delete_task(
                committed_world, a, cve, "3.1", user, scope=Scope.NON_CONFIDENTIAL
            )

        with pytest.raises(CVENotFoundError):
            await asyncio.wait_for(task, timeout=5)

        assert (assign.calls, reconcile.calls, propagate.calls, refresh.calls) == (
            [],
            [],
            [],
            [],
        )
        assert pending_ticket_convergence_effects(a) == ()
        await a.rollback()
        fresh = await committed_world.open_session()
        assert await persisted_assessments(fresh, cve.id) == [
            unit("SUSE", V31_CRITICAL)
        ]
        assert await cve_severity(fresh, cve.id) == "Critical"
        assert await ticket_events_by_id(fresh, ticket.id) == []
        assert await ticket_state(fresh, ticket.id) == (
            TicketStatus.ANALYSIS,
            None,
            None,
            None,
            None,
        )
        await fresh.rollback()
