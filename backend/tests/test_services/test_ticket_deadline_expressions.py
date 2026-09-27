"""Tests for the Ticket due-date and track milestone SQL expressions
(backend/app/services/ticket_deadline_expressions.py).

Owning specification: `docs/features/tickets/ticket-deadlines.md`
(SLA Tier, Phase Shares, Due Dates, Evaluation Instant, Track Milestones,
Read Ownership and Query Integration; Testing Requirements 1-5 on the SQL
side, 10, and 11), with the resolved-severity cascade of
`docs/features/tickets/tickets.md` (Severity Resolution) and the
actionability predicates of `docs/features/packages/package-model.md`
(Derived Actionability).

Requirement 10 (SQL/pure equivalence) is driven by the shared matrix
`tests/support/deadline_matrix.py`: every case is persisted as real
Ticket, CVE, package, track, Product, and IBS request evidence rows
(`tests/support/deadline_persistence.py`), evaluated by the SQL
expressions in PostgreSQL, and compared with both the independently
transcribed expectation and the pure functions.
"""

from __future__ import annotations

import dataclasses
import inspect
from collections.abc import Sequence
from datetime import UTC, date, datetime, timedelta
from typing import Any, cast

import pytest
from sqlalchemy import ColumnElement, event, exists, func, literal, select, text
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import aliased

import tests.test_services.test_package_service as tree_tests
import tests.test_services.test_ticket_deadlines as pure_tests
from app.core.enums import (
    DeliveryStatus,
    IBSRequestActionType,
    IBSRequestState,
    MilestonePhase,
    MilestoneStatus,
    PackageStatus,
    Severity,
    TicketStatus,
)
from app.models.ticket import Ticket
from app.models.ticket_audit_event import TicketAuditEvent
from app.models.ticket_package import TicketPackage
from app.models.ticket_package_track import TicketPackageTrack
from app.services import ticket_deadline_expressions
from app.services.ticket_deadline_expressions import (
    TicketDueDateExpressions,
    active_release_request_exists,
    sla_days_expression,
    ticket_due_date_expressions,
    track_milestone_status_expression,
)
from app.services.ticket_deadlines import (
    ACTIVE_RELEASE_REQUEST_STATES,
    compute_due_dates,
    resolve_track_milestones,
)
from tests.support.deadline_matrix import (
    ACTIVE_RELEASE_REQUEST_STATES as MATRIX_ACTIVE_STATES,
)
from tests.support.deadline_matrix import (
    AFTER_ALL_DUE,
    AT_TRIAGE_DUE,
    BEFORE_ANY_DUE,
    CREATED_AT,
    DEADLINE_CASES,
    EXPECTATION_FIELDS,
    INCIDENT,
    RELEASE,
    DeadlineCase,
    ProductEvidence,
    RequestEvidence,
)
from tests.support.deadline_persistence import (
    PERSISTED_INPUT_FIELDS,
    DeadlineWorld,
    PersistedCase,
)
from tests.support.module_imports import APP_ROOT, imported_modules

LATER_PHASES = (MilestonePhase.SUBMISSION, MilestonePhase.UM, MilestonePhase.QA)
SQL_STATUS_VALUES = {*MilestoneStatus, None}

D = MilestoneStatus.DONE
P = MilestoneStatus.PENDING
O = MilestoneStatus.OVERDUE  # noqa: E741 - mirrors the specification value
NA = MilestoneStatus.NOT_APPLICABLE


@pytest.fixture
def deadline_world(request: pytest.FixtureRequest) -> DeadlineWorld:
    return DeadlineWorld.from_request(request)


def _evaluation_date(instant: datetime) -> date:
    """The read's `evaluation_date`: the UTC date of its instant."""
    return instant.astimezone(UTC).date()


def _statuses(
    instant: datetime,
    *,
    evaluation_date: date | None = None,
    ticket: Any = Ticket,
    package: Any = TicketPackage,
    track: Any = TicketPackageTrack,
    due_dates: TicketDueDateExpressions | None = None,
) -> list[ColumnElement[str | None]]:
    return [
        track_milestone_status_expression(
            phase,
            evaluation_date=evaluation_date or _evaluation_date(instant),
            evaluation_instant=instant,
            ticket=ticket,
            package=package,
            track=track,
            due_dates=due_dates,
        )
        for phase in LATER_PHASES
    ]


def _track_scope(statement: Any) -> Any:
    return (
        statement.select_from(TicketPackageTrack)
        .join(TicketPackage, TicketPackage.id == TicketPackageTrack.ticket_package_id)
        .join(Ticket, Ticket.id == TicketPackage.ticket_id)
    )


async def _sql_values(
    db: AsyncSession, persisted: PersistedCase, instant: datetime
) -> tuple[tuple[datetime | None, ...], tuple[MilestoneStatus | None, ...]]:
    """Five due dates and three later milestone statuses, in one statement."""
    due = ticket_due_date_expressions()
    statement = _track_scope(
        select(
            due.triage,
            due.submission,
            due.um,
            due.qa,
            due.release,
            *_statuses(instant, due_dates=due),
        )
    ).where(TicketPackageTrack.id == persisted.track.id)
    row = (await db.execute(statement)).one()
    statuses = tuple(None if v is None else MilestoneStatus(v) for v in row[5:])
    return tuple(row[:5]), statuses


def _pure_values(
    case: DeadlineCase,
) -> tuple[tuple[datetime, ...] | None, tuple[MilestoneStatus | None, ...]]:
    due = compute_due_dates(**case.due_dates_kwargs())
    milestones = resolve_track_milestones(due_dates=due, **case.milestone_kwargs())
    due_tuple = (
        None
        if due is None
        else (due.triage, due.submission, due.um, due.qa, due.release)
    )
    return due_tuple, tuple(milestones.status_of(phase) for phase in LATER_PHASES)


def _parametrized_cases(function: Any) -> Sequence[Any]:
    (mark,) = [m for m in function.pytestmark if m.name == "parametrize"]
    cases: Sequence[Any] = mark.args[1]
    return cases


# ---------------------------------------------------------------------------
# SQL/pure parity over the shared matrix (Requirement 10)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestSqlPureParity:
    @pytest.mark.parametrize("case", DEADLINE_CASES, ids=lambda case: case.id)
    async def test_sql_equals_expectation_and_pure_functions(
        self,
        db_session: AsyncSession,
        deadline_world: DeadlineWorld,
        case: DeadlineCase,
    ) -> None:
        persisted = await deadline_world.build(case)

        sql_due, sql_statuses = await _sql_values(
            db_session, persisted, case.evaluation_instant
        )
        pure_due, pure_statuses = _pure_values(case)

        expected_due = case.expected_due_dates()
        assert sql_due == (expected_due or (None,) * 5)
        assert pure_due == expected_due
        assert sql_statuses == case.expected_statuses[1:] == pure_statuses


@pytest.mark.unit
class TestSharedMatrixStructure:
    def test_every_matrix_consumer_iterates_the_same_case_tuple(self) -> None:
        """A case added to the shared matrix is exercised by the pure
        functions, the package-tree projection, and the SQL expressions."""
        consumers = (
            pure_tests.TestComputeDueDatesMatrix.test_matrix_due_dates,
            pure_tests.TestResolveTrackMilestonesMatrix.test_matrix_milestones,
            tree_tests.TestTrackMilestones.test_milestones_current_phase_and_due_dates,
            TestSqlPureParity.test_sql_equals_expectation_and_pure_functions,
        )

        for consumer in consumers:
            assert _parametrized_cases(consumer) is DEADLINE_CASES

    def test_persistence_builder_consumes_every_input_field(self) -> None:
        inputs = {f.name for f in dataclasses.fields(DeadlineCase)} - EXPECTATION_FIELDS

        assert inputs == PERSISTED_INPUT_FIELDS | {"evaluation_instant"}

    def test_matrix_active_states_match_the_specification_constant(self) -> None:
        assert MATRIX_ACTIVE_STATES == ACTIVE_RELEASE_REQUEST_STATES

    def test_matrix_covers_every_required_evidence_dimension(self) -> None:
        cases = DEADLINE_CASES
        correlated_rr_states = {
            r.state
            for c in cases
            for r in c.requests
            if r.action_type is RELEASE and r.correlated
        }

        assert {c.severity for c in cases} == {*Severity, None}
        assert {c.ticket_has_cve for c in cases} == {True, False}
        assert {c.track_status for c in cases} == set(PackageStatus)
        assert {c.delivery_status for c in cases} == set(DeliveryStatus)
        assert correlated_rr_states == set(IBSRequestState)
        assert any(not r.correlated for c in cases for r in c.requests)
        assert any(
            c.requests and all(r.action_type is INCIDENT for r in c.requests)
            for c in cases
        )
        assert any(c.package_excluded for c in cases)
        assert any(c.track_excluded for c in cases)
        assert any(c.products and all(p.eol for p in c.products) for c in cases)
        assert any(
            {p.released for p in c.products if p.eligible and not p.excluded}
            == {True, False}
            for c in cases
        )
        assert {TicketStatus.IGNORED, TicketStatus.DUPLICATED} <= {
            c.ticket_status for c in cases
        }
        assert {s for c in cases for s in c.expected_statuses[1:]} == (
            SQL_STATUS_VALUES
        )

    def test_matrix_contains_the_equal_instant_boundary_for_later_phases(
        self,
    ) -> None:
        """At least one case evaluates a later phase exactly at its due
        date and expects `pending`."""
        boundary: list[MilestoneStatus | None] = []
        for case in DEADLINE_CASES:
            due = case.expected_due_dates()
            if due is not None and case.evaluation_instant in due[1:4]:
                phase_index = due.index(case.evaluation_instant)
                boundary.append(case.expected_statuses[phase_index])

        assert boundary
        assert set(boundary) == {P}


# ---------------------------------------------------------------------------
# Due-date expressions
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestDueDateExpressions:
    async def test_offsets_ignore_session_time_zone_and_daylight_saving(
        self,
        db_session: AsyncSession,
        ticket_factory: Any,
    ) -> None:
        """Every offset is exact elapsed seconds: a session `TimeZone`
        with a daylight-saving transition inside the window (Europe
        switches on 2026-03-29) does not shift a due date by an hour."""
        created_at = datetime(2026, 3, 20, 12, 30, 15, 654321, tzinfo=UTC)
        ticket: Ticket = await ticket_factory(
            severity_manual=Severity.MEDIUM.value, created_at=created_at
        )
        await db_session.execute(text("SET LOCAL TIME ZONE 'Europe/Berlin'"))
        due = ticket_due_date_expressions()

        row = (
            await db_session.execute(
                select(due.triage, due.submission, due.um, due.qa, due.release).where(
                    Ticket.id == ticket.id
                )
            )
        ).one()

        assert tuple(row) == tuple(
            created_at + timedelta(days=days) for days in (9, 54, 63, 90, 90)
        )

    async def test_supplied_severity_expression_is_used_instead_of_resolving(
        self,
        db_session: AsyncSession,
        ticket_factory: Any,
    ) -> None:
        """A caller that already resolved severity once passes it in."""
        ticket: Ticket = await ticket_factory(
            severity_manual=Severity.HIGH.value, created_at=CREATED_AT
        )
        low = cast(ColumnElement[str | None], literal(Severity.LOW.value))

        row = (
            await db_session.execute(
                select(
                    sla_days_expression(severity=low),
                    ticket_due_date_expressions(severity=low).release,
                    sla_days_expression(),
                ).where(Ticket.id == ticket.id)
            )
        ).one()

        assert tuple(row) == (180, CREATED_AT + timedelta(days=180), 30)

    async def test_due_dates_filter_and_sort_in_sql_with_null_last(
        self,
        db_session: AsyncSession,
        ticket_factory: Any,
    ) -> None:
        """Due-date expressions are usable in `WHERE` and `ORDER BY`; manual
        zone and `None` severity yield NULL, sorted last."""
        high = await ticket_factory(
            severity_manual=Severity.HIGH.value, created_at=CREATED_AT
        )
        low = await ticket_factory(
            severity_manual=Severity.LOW.value, created_at=CREATED_AT
        )
        none_label = await ticket_factory(
            severity_manual=Severity.NONE.value, created_at=CREATED_AT
        )
        ignored = await ticket_factory(
            status=TicketStatus.IGNORED.value, created_at=CREATED_AT
        )
        ids = [high.id, low.id, none_label.id, ignored.id]
        triage = ticket_due_date_expressions().triage

        ordered = (
            await db_session.scalars(
                select(Ticket.id)
                .where(Ticket.id.in_(ids))
                .order_by(triage.desc().nulls_last(), Ticket.id)
            )
        ).all()
        past = (
            await db_session.scalars(
                select(Ticket.id).where(
                    Ticket.id.in_(ids),
                    triage < literal(AFTER_ALL_DUE),
                )
            )
        ).all()

        assert ordered[:2] == [low.id, high.id]
        assert set(ordered[2:]) == {none_label.id, ignored.id}
        assert set(past) == {high.id, low.id}

    def test_for_phase_returns_each_member(self) -> None:
        due = ticket_due_date_expressions()

        assert [due.for_phase(phase) for phase in MilestonePhase] == [
            due.triage,
            due.submission,
            due.um,
            due.qa,
        ]


# ---------------------------------------------------------------------------
# Milestone status expressions
# ---------------------------------------------------------------------------


class _Recorder:
    def __init__(self, db: AsyncSession) -> None:
        bind = db.bind
        assert bind is not None
        self._engine = bind.engine.sync_engine
        self.statements: list[str] = []

    def _record(self, *args: Any) -> None:
        self.statements.append(args[2])

    def __enter__(self) -> _Recorder:
        event.listen(self._engine, "before_cursor_execute", self._record)
        return self

    def __exit__(self, *exc: object) -> None:
        event.remove(self._engine, "before_cursor_execute", self._record)


def _overdue_case(package_name: str) -> DeadlineCase:
    return DeadlineCase(
        id=package_name,
        expected_offsets_days=None,
        expected_statuses=(D, O, O, O),
        expected_current_phase=None,
        products=(ProductEvidence(), ProductEvidence()),
        evaluation_instant=AFTER_ALL_DUE,
    )


@pytest.mark.integration
class TestMilestoneFilteringAndCounting:
    async def test_counted_selection_does_not_duplicate_a_ticket(
        self,
        db_session: AsyncSession,
        deadline_world: DeadlineWorld,
    ) -> None:
        """A Ticket with three overdue tracks, each with two actionable
        eligible Products and an inactive RR, is counted once; the filter
        runs in SQL through aliases with existence semantics."""
        first = await deadline_world.build(_overdue_case("a"))
        for name in ("b", "c"):
            case = dataclasses.replace(
                _overdue_case(name),
                requests=(RequestEvidence(state=IBSRequestState.DECLINED),),
            )
            await deadline_world.build(case, ticket=first.ticket)
        done = await deadline_world.build(
            dataclasses.replace(
                _overdue_case("done"), delivery_status=DeliveryStatus.IN_PROGRESS
            )
        )
        track = aliased(TicketPackageTrack)
        package = aliased(TicketPackage)
        (submission, _, _) = _statuses(
            AFTER_ALL_DUE, package=package, track=track, ticket=Ticket
        )
        has_overdue = exists(
            select(track.id)
            .join(package, package.id == track.ticket_package_id)
            .where(
                package.ticket_id == Ticket.id,
                submission == MilestoneStatus.OVERDUE.value,
            )
            .correlate(Ticket)
        )
        scope = Ticket.id.in_([first.ticket.id, done.ticket.id])

        count = await db_session.scalar(
            select(func.count()).select_from(Ticket).where(scope, has_overdue)
        )
        ids = (
            await db_session.scalars(select(Ticket.id).where(scope, has_overdue))
        ).all()
        track_count = await db_session.scalar(
            select(func.count())
            .select_from(track)
            .join(package, package.id == track.ticket_package_id)
            .join(Ticket, Ticket.id == package.ticket_id)
            .where(scope, submission == MilestoneStatus.OVERDUE.value)
        )

        assert count == 1
        assert ids == [first.ticket.id]
        assert track_count == 3

    async def test_actionability_uses_the_supplied_date_and_comparison_the_instant(
        self,
        db_session: AsyncSession,
        deadline_world: DeadlineWorld,
    ) -> None:
        """A Product whose General Support ends on the evaluation date is
        actionable that day and `eol` the next; the instant alone drives
        the past-due comparison."""
        persisted = await deadline_world.build(
            DeadlineCase(
                id="lifecycle",
                expected_offsets_days=None,
                expected_statuses=(D, O, O, O),
                expected_current_phase=None,
                products=(),
            )
        )
        gs_end = date(2026, 3, 11)
        product = await deadline_world.factory("product_factory")(
            general_support_end_date=gs_end
        )
        await deadline_world.factory("ticket_package_product_factory")(
            ticket_package_track_id=persisted.track.id, product_id=product.id
        )

        async def statuses(evaluation_date: date) -> tuple[Any, ...]:
            statement = _track_scope(
                select(*_statuses(AFTER_ALL_DUE, evaluation_date=evaluation_date))
            ).where(TicketPackageTrack.id == persisted.track.id)
            return tuple((await db_session.execute(statement)).one())

        assert await statuses(gs_end) == (O.value, O.value, O.value)
        assert await statuses(date(2026, 3, 12)) == (NA.value, NA.value, NA.value)

    async def test_release_request_evidence_is_scoped_to_the_given_track(
        self,
        db_session: AsyncSession,
        deadline_world: DeadlineWorld,
    ) -> None:
        with_rr = await deadline_world.build(
            dataclasses.replace(_overdue_case("rr"), requests=(RequestEvidence(),))
        )
        sibling = await deadline_world.build(
            _overdue_case("sibling"), ticket=with_rr.ticket
        )
        track = aliased(TicketPackageTrack)

        result = await db_session.execute(
            select(track.id, active_release_request_exists(track=track)).where(
                track.id.in_([with_rr.track.id, sibling.track.id])
            )
        )
        rows = {row[0]: row[1] for row in result}

        assert rows == {with_rr.track.id: True, sibling.track.id: False}

    async def test_evaluation_writes_no_row_and_creates_no_event(
        self,
        db_session: AsyncSession,
        deadline_world: DeadlineWorld,
    ) -> None:
        """Requirement 11: the expressions only read; nothing is persisted,
        no audit event is created, and the evaluated rows are unchanged."""
        persisted = await deadline_world.build(
            dataclasses.replace(
                _overdue_case("side_effects"), requests=(RequestEvidence(),)
            )
        )
        snapshot = _track_scope(
            select(
                Ticket.status,
                Ticket.updated_at,
                Ticket.priority_auto,
                Ticket.assignee_id,
                TicketPackageTrack.status,
                TicketPackageTrack.delivery_status,
                TicketPackageTrack.updated_at,
            )
        ).where(TicketPackageTrack.id == persisted.track.id)
        before = (await db_session.execute(snapshot)).one()

        with _Recorder(db_session) as recorder:
            await _sql_values(db_session, persisted, AFTER_ALL_DUE)

        after = (await db_session.execute(snapshot)).one()
        events = await db_session.scalar(
            select(func.count()).select_from(TicketAuditEvent)
        )
        assert after == before
        assert events == 0
        assert not db_session.new
        assert not db_session.dirty
        assert [s.lstrip()[:6].upper() for s in recorder.statements] == ["SELECT"]


@pytest.mark.unit
class TestMilestoneExpressionGuards:
    def test_naive_instant_is_rejected_for_every_phase(self) -> None:
        for phase in LATER_PHASES:
            with pytest.raises(ValueError, match="evaluation_instant"):
                track_milestone_status_expression(
                    phase,
                    evaluation_date=BEFORE_ANY_DUE.date(),
                    evaluation_instant=BEFORE_ANY_DUE.replace(tzinfo=None),
                )

    def test_triage_has_no_track_expression(self) -> None:
        with pytest.raises(ValueError, match="submission, um, and qa"):
            track_milestone_status_expression(
                MilestonePhase.TRIAGE,
                evaluation_date=AT_TRIAGE_DUE.date(),
                evaluation_instant=AT_TRIAGE_DUE,
            )

    def test_release_request_evidence_matches_action_type_and_states(self) -> None:
        compiled = str(
            select(active_release_request_exists()).compile(
                compile_kwargs={"literal_binds": True}
            )
        )

        assert f"'{IBSRequestActionType.MAINTENANCE_RELEASE.value}'" in compiled
        for state in IBSRequestState:
            assert (f"'{state.value}'" in compiled) is (
                state in ACTIVE_RELEASE_REQUEST_STATES
            )


# ---------------------------------------------------------------------------
# Module boundary
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestModuleBoundary:
    def test_imports_only_leaf_services(self) -> None:
        """Importable by `ticket_service` and `package_service` without a
        cycle: it imports neither, nor the audit trail or any I/O layer."""
        modules = imported_modules(
            APP_ROOT / "services" / "ticket_deadline_expressions.py", "app.services"
        )

        assert {m for m in modules if m.startswith("app.services")} == {
            "app.services.package_actionability",
            "app.services.ticket_deadlines",
            "app.services.ticket_severity",
        }
        assert not {
            m
            for m in modules
            if m.startswith(("app.api", "app.schemas", "app.tasks", "app.cli"))
            or m in {"app.config", "app.database"}
        }

    def test_builders_are_synchronous(self) -> None:
        for function in (
            sla_days_expression,
            ticket_due_date_expressions,
            track_milestone_status_expression,
            active_release_request_exists,
        ):
            assert not inspect.iscoroutinefunction(function)
        assert not any(
            inspect.iscoroutinefunction(member)
            for _, member in inspect.getmembers(
                ticket_deadline_expressions, inspect.isfunction
            )
        )
