"""Single-session service integration tests for the lifecycle actionability
reconciliation `package_service.reconcile_lifecycle_actionability_for_ticket()`
(backend/app/services/package_service.py).

Owning specifications:

- docs/features/packages/package-service.md
  (`reconcile_lifecycle_actionability_for_ticket()`; Concurrency Control;
  Excluded and Non-Actionable Records; Architectural Test Requirement:
  Derived actionability).
- docs/features/packages/package-model.md (Exclusion and Actionability:
  Manual Exclusion Markers reason precedence, Derived Actionability with
  one UTC `evaluation_date`, Gate Participation, Restore, Ticket Events for
  Exclusion).
- docs/features/packages/product-lifecycle-transitions.md (Lifecycle
  Authority and Effects; Algorithm step 4; TicketAuditEvent Records).
- docs/features/tickets/ticket-mutations.md (`reconcile_ticket_status()`
  steps 4-5; Transaction-Local Ticket Convergence Registration).
- docs/features/tickets/ticket-audit-log.md (Event Type Contract:
  `status_change`; Canonical Mutation and No-Event Matrix row "EOL
  entry/exit or derived actionability change"; Testing Requirements 1-7,
  12, 14, 24, 25).
- docs/features/platform/testing-strategy.md (Service Functions; Audit
  Trail Testing; Rollback Within a Test).

Independent-session lock serialization (audit Testing Requirement 23) and
the discard of a committed transaction's convergence effect are covered by
`tests/test_services/test_reconcile_lifecycle_actionability_atomicity.py`;
the candidate-discovery parity by
`tests/test_services/test_lifecycle_gate_parity.py`.

Every Ticket is CVE-less with `severity_manual = High` and unassigned
unless a test states otherwise. A "boundary" Product's General Support
ends on `EVAL`: it is actionable on `EVAL` and EOL from `NEXT_DAY`
(product-catalog.md, Lifecycle Evaluator). Expected values are transcribed
from the specifications, never computed with the module under test.
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import (
    CVSSVersion,
    NonActionableReason,
    PackageStatus,
    Severity,
    TicketStatus,
)
from app.core.exceptions import TicketNotFoundError
from app.models.cve import CVE
from app.models.cve_cvss_assessment import CVECVSSAssessment
from app.models.product import Product
from app.models.ticket import Ticket
from app.models.ticket_package import TicketPackage
from app.models.ticket_package_product import TicketPackageProduct
from app.models.ticket_package_track import TicketPackageTrack
from app.services import package_service, ticket_mutations
from app.services.package_service import (
    LifecycleReconciliationResult,
    reconcile_lifecycle_actionability_for_ticket,
)
from app.services.packages import evaluate_lifecycle_transitions
from app.services.packages.evaluate_lifecycle_transitions import (
    find_lifecycle_gate_mismatches,
)
from app.services.ticket_audit_log import TicketAuditLog
from app.services.ticket_convergence_registry import (
    TicketConvergenceEffect,
    pending_ticket_convergence_effects,
)
from tests.support.database import rollback_test_scope
from tests.support.package_exclusion import State, observed
from tests.support.ticket_mutations import (
    AFTER_EVAL,
    BEFORE_EVAL,
    EVAL,
    StatementRecorder,
    TicketFactory,
    TreeBuilder,
    VAUser,
    cveless,
    status_event,
    ticket_events,
    ticket_events_by_id,
    tree_for,
)
from tests.support.track_status import Spy, ticket_state

pytest_plugins = ["tests.support.ticket_mutation_fixtures"]
"""Provides the shared `va_user` and `tree` fixtures."""

ProductFactory = Callable[..., Awaitable[Product]]
OccurrenceFactory = Callable[..., Awaitable[TicketPackageProduct]]

NEXT_DAY = EVAL + timedelta(days=1)
"""The first EOL day of a boundary Product."""

ANALYSIS = TicketStatus.ANALYSIS
ANALYZED = TicketStatus.ANALYZED
RESOLVED = TicketStatus.RESOLVED
GATE_ZONE = (ANALYSIS, ANALYZED, RESOLVED)

EXCLUSION_EVENTS = frozenset(
    f"{level}_{action}"
    for level in ("package", "track", "product")
    for action in ("excluded", "restored")
)
"""Every package-tree exclusion and restoration event type."""

ACTIONABLE: State = (True, None)


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _Target:
    """One target path: its catalog Product and Product occurrence."""

    product: Product
    occurrence: TicketPackageProduct


PathBuilder = Callable[..., Awaitable[_Target]]


@pytest.fixture
def path(
    tree: TreeBuilder,
    product_factory: ProductFactory,
    ticket_package_product_factory: OccurrenceFactory,
) -> PathBuilder:
    """One package with one track of `status` and one eligible occurrence
    of a catalog Product whose General Support ends on `support_end`, with
    the given direct markers."""

    async def _create(
        ticket: Ticket,
        *,
        status: PackageStatus,
        support_end: date,
        package_excluded: bool = False,
        track_excluded: bool = False,
        product_excluded: bool = False,
    ) -> _Target:
        track = await tree(
            ticket,
            status=status,
            products=(),
            package_excluded=package_excluded,
            track_excluded=track_excluded,
        )
        product = await product_factory(general_support_end_date=support_end)
        occurrence = await ticket_package_product_factory(
            ticket_package_track_id=track.id,
            product_id=product.id,
            eligible=True,
            deleted_at=datetime.now(UTC) if product_excluded else None,
        )
        return _Target(product, occurrence)

    return _create


def _result(
    previous: TicketStatus, current: TicketStatus, *, skipped: bool = False
) -> LifecycleReconciliationResult:
    return LifecycleReconciliationResult(
        previous_status=previous,
        current_status=current,
        changed=previous is not current,
        skipped=skipped,
    )


async def _reconcile(
    db: AsyncSession, ticket_id: uuid.UUID, evaluation_date: date = EVAL
) -> LifecycleReconciliationResult:
    return await reconcile_lifecycle_actionability_for_ticket(
        db, ticket_id, evaluation_date
    )


async def _correct_support_end(
    db: AsyncSession, product: Product, support_end: date
) -> None:
    """An AIMAAS lifecycle correction of the catalog Product."""
    await db.execute(
        update(Product)
        .where(Product.id == product.id)
        .values(general_support_end_date=support_end)
    )


def _is_ticket_lock(statement: str) -> bool:
    return "FROM ticket " in statement and statement.rstrip().endswith("FOR UPDATE")


def _write_targets(recorder: StatementRecorder) -> list[str]:
    """The sorted `INSERT INTO <table>` / `UPDATE <table>` of every write."""
    targets = []
    for statement in recorder.writes():
        words = statement.split()
        targets.append(" ".join(words[:3] if words[0] == "INSERT" else words[:2]))
    return sorted(targets)


STATUS_WRITES = ["INSERT INTO ticket_audit_event", "UPDATE ticket"]
"""The only writes of an effective call: the status and its event."""


def _bound_dates(recorder: StatementRecorder) -> set[date]:
    """Every `date` (not `datetime`) parameter bound to a statement."""
    return {
        value
        for params in recorder.parameters
        for value in (params.values() if isinstance(params, dict) else params)
        if isinstance(value, date) and not isinstance(value, datetime)
    }


async def _persisted_status(db: AsyncSession, ticket_id: uuid.UUID) -> str:
    return (
        await db.execute(select(Ticket.status).where(Ticket.id == ticket_id))
    ).scalar_one()


async def _other_dimensions(db: AsyncSession, ticket_id: uuid.UUID) -> list[Any]:
    """Every marker, affectedness, delivery, eligibility, override, and
    release value of the Ticket's package tree, in occurrence-ID order."""
    rows = await db.execute(
        select(
            TicketPackage.deleted_at,
            TicketPackageTrack.status,
            TicketPackageTrack.delivery_status,
            TicketPackageTrack.deleted_at,
            TicketPackageProduct.eligible,
            TicketPackageProduct.is_eligible_override,
            TicketPackageProduct.released_at,
            TicketPackageProduct.deleted_at,
        )
        .join(
            TicketPackageTrack,
            TicketPackageTrack.ticket_package_id == TicketPackage.id,
        )
        .join(
            TicketPackageProduct,
            TicketPackageProduct.ticket_package_track_id == TicketPackageTrack.id,
        )
        .where(TicketPackage.ticket_id == ticket_id)
        .order_by(TicketPackageProduct.id)
    )
    return [tuple(row) for row in rows]


def _forbid_clocks(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fail any attempt to capture the current date: the supplied
    `evaluation_date` alone governs."""

    def clock() -> datetime:
        raise AssertionError("the supplied evaluation date must be reused")

    monkeypatch.setattr(ticket_mutations, "_utc_now", clock)
    monkeypatch.setattr(package_service, "_utc_today", clock)
    monkeypatch.setattr(evaluate_lifecycle_transitions, "_utc_today", clock)


# ---------------------------------------------------------------------------
# Guards (package-service.md, Preconditions and guards; Behavior steps 1-2)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestGuards:
    @pytest.mark.parametrize(
        "status",
        [TicketStatus.NEW, TicketStatus.IGNORED, TicketStatus.DUPLICATED],
        ids=str,
    )
    async def test_non_gate_zone_ticket_is_skipped_without_effects(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        tree: TreeBuilder,
        monkeypatch: pytest.MonkeyPatch,
        status: TicketStatus,
    ) -> None:
        """The tree would gate `Resolved`; the locked-current status skips
        it with no reconciliation, write, event, assignment, or
        registration."""
        ticket = await cveless(ticket_factory, status=status)
        await tree_for(RESOLVED, ticket, tree)
        reconcile = Spy(monkeypatch, "reconcile_ticket_status")
        assign = Spy(monkeypatch, "auto_assign_actor")

        with StatementRecorder(db_session) as recorder:
            result = await _reconcile(db_session, ticket.id)

        assert result == _result(status, status, skipped=True)
        (statement,) = recorder.statements
        assert _is_ticket_lock(statement)
        assert (reconcile.calls, assign.calls) == ([], [])
        assert pending_ticket_convergence_effects(db_session) == ()
        assert await ticket_state(db_session, ticket) == (status, None)
        assert await ticket_events(db_session, ticket) == []

    async def test_missing_ticket_raises_ticket_not_found(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        await cveless(ticket_factory)
        reconcile = Spy(monkeypatch, "reconcile_ticket_status")

        with (
            StatementRecorder(db_session) as recorder,
            pytest.raises(TicketNotFoundError),
        ):
            await _reconcile(db_session, uuid.uuid4())

        (statement,) = recorder.statements
        assert _is_ticket_lock(statement)
        assert reconcile.calls == []

    async def test_ticket_lock_is_the_first_statement_and_the_only_row_lock(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        tree: TreeBuilder,
        va_user: VAUser,
        cve_factory: Callable[..., Awaitable[CVE]],
        cve_cvss_assessment_factory: Callable[..., Awaitable[CVECVSSAssessment]],
    ) -> None:
        """Behavior step 1 and the no-event matrix ("Ticket lock only for
        reconciliation"): no CVE or User lock, even for an assigned
        CVE-associated Ticket whose reconciliation observes the assignee."""
        cve = await cve_factory(severity=Severity.HIGH.value)
        await cve_cvss_assessment_factory(
            cve_id=cve.id, provider_name="SUSE", cvss_version=CVSSVersion.V3_1.value
        )
        assignee = await va_user()
        ticket = await ticket_factory(
            status=RESOLVED.value, cve_id=cve.id, assignee_id=assignee.id
        )
        await tree_for(ANALYZED, ticket, tree)

        with StatementRecorder(db_session) as recorder:
            result = await _reconcile(db_session, ticket.id)

        assert result == _result(RESOLVED, ANALYZED)
        assert _is_ticket_lock(recorder.statements[0])
        assert recorder.row_locks() == [recorder.statements[0]]
        assert await ticket_state(db_session, ticket) == (ANALYZED, assignee.id)


# ---------------------------------------------------------------------------
# Reconciliation (Behavior steps 3-4; Idempotency)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestReconciliation:
    @pytest.mark.parametrize(
        ("current", "target"),
        [(current, target) for current in GATE_ZONE for target in GATE_ZONE],
        ids=lambda status: str(status),
    )
    async def test_result_reports_the_previous_and_current_status(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        tree: TreeBuilder,
        current: TicketStatus,
        target: TicketStatus,
    ) -> None:
        """Every gate-zone status against every gate result: a change
        creates exactly one system `status_change` (`comment` and `detail`
        `NULL`); a converged Ticket is a no-op without any write."""
        ticket = await cveless(ticket_factory, status=current)
        await tree_for(target, ticket, tree)

        with StatementRecorder(db_session) as recorder:
            result = await _reconcile(db_session, ticket.id)

        assert result == _result(current, target)
        assert await _persisted_status(db_session, ticket.id) == target
        if current is target:
            assert recorder.writes() == []
            assert await ticket_events(db_session, ticket) == []
        else:
            assert _write_targets(recorder) == STATUS_WRITES
            assert await ticket_events(db_session, ticket) == [
                status_event(current.value, target.value)
            ]

    async def test_delegates_exactly_one_reconciliation_then_flushes(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        path: PathBuilder,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Behavior steps 3-4: one `reconcile_ticket_status()` on the
        locked Ticket and session with the supplied date (no
        `previous_status`), then the boundary's own flush."""
        ticket = await cveless(ticket_factory, status=ANALYZED)
        await path(ticket, status=PackageStatus.AFFECTED, support_end=EVAL)
        calls: list[tuple[str, tuple[Any, ...], dict[str, Any]]] = []
        original_reconcile = ticket_mutations.reconcile_ticket_status
        original_flush = db_session.flush

        async def reconcile(*args: Any, **kwargs: Any) -> None:
            calls.append(("reconcile", args, kwargs))
            await original_reconcile(*args, **kwargs)

        async def flush(*args: Any, **kwargs: Any) -> None:
            calls.append(("flush", args, kwargs))
            await original_flush(*args, **kwargs)

        monkeypatch.setattr(package_service, "reconcile_ticket_status", reconcile)
        monkeypatch.setattr(db_session, "flush", flush)
        result = await _reconcile(db_session, ticket.id, NEXT_DAY)
        monkeypatch.undo()

        assert result == _result(ANALYZED, RESOLVED)
        (delegated,) = [call for call in calls if call[0] == "reconcile"]
        _, (locked, session), kwargs = delegated
        assert (locked.id, session, kwargs) == (
            ticket.id,
            db_session,
            {"evaluation_date": NEXT_DAY},
        )
        assert calls[-1][0] == "flush"

    async def test_reinvocation_is_a_no_op(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        path: PathBuilder,
    ) -> None:
        """Idempotency: a repeated call for the same date after the status
        has converged produces no write and no second event."""
        ticket = await cveless(ticket_factory, status=ANALYZED)
        await path(ticket, status=PackageStatus.AFFECTED, support_end=EVAL)

        first = await _reconcile(db_session, ticket.id, NEXT_DAY)
        with StatementRecorder(db_session) as recorder:
            second = await _reconcile(db_session, ticket.id, NEXT_DAY)

        assert (first, second) == (
            _result(ANALYZED, RESOLVED),
            _result(RESOLVED, RESOLVED),
        )
        assert recorder.writes() == []
        assert await ticket_events(db_session, ticket) == [
            status_event(ANALYZED.value, RESOLVED.value)
        ]

    async def test_never_commits_or_rolls_back(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        path: PathBuilder,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Behavior step 4: the caller owns the transaction; its rollback
        discards the status change and its event."""
        ticket = await cveless(ticket_factory, status=ANALYZED)
        await path(ticket, status=PackageStatus.AFFECTED, support_end=EVAL)
        ticket_id = ticket.id

        async def forbidden(*args: Any, **kwargs: Any) -> None:
            raise AssertionError("the service must not end the transaction")

        async with rollback_test_scope(db_session):
            monkeypatch.setattr(db_session, "commit", forbidden)
            monkeypatch.setattr(db_session, "rollback", forbidden)
            result = await _reconcile(db_session, ticket_id, NEXT_DAY)
            monkeypatch.undo()
            assert result == _result(ANALYZED, RESOLVED)
            assert db_session.in_transaction()

        assert await _persisted_status(db_session, ticket_id) == ANALYZED
        assert await ticket_events_by_id(db_session, ticket_id) == []


# ---------------------------------------------------------------------------
# Convergence registration (ticket-mutations.md, step 5)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestConvergenceRegistration:
    @pytest.mark.parametrize(
        ("track_status", "regressed"),
        [
            pytest.param(PackageStatus.AFFECTED, ANALYZED, id="to-analyzed"),
            pytest.param(PackageStatus.ANALYSIS, ANALYSIS, id="to-analysis"),
        ],
    )
    async def test_resolved_regression_registers_exactly_one_effect(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        path: PathBuilder,
        track_status: PackageStatus,
        regressed: TicketStatus,
    ) -> None:
        """A Product leaves EOL through a lifecycle correction: the
        `Resolved` Ticket regresses and one transaction-local effect is
        registered; re-invocation adds none."""
        ticket = await cveless(ticket_factory, status=RESOLVED)
        target = await path(ticket, status=track_status, support_end=BEFORE_EVAL)
        assert await _reconcile(db_session, ticket.id) == _result(RESOLVED, RESOLVED)
        assert pending_ticket_convergence_effects(db_session) == ()

        await _correct_support_end(db_session, target.product, AFTER_EVAL)
        first = await _reconcile(db_session, ticket.id)
        second = await _reconcile(db_session, ticket.id)

        assert (first, second) == (
            _result(RESOLVED, regressed),
            _result(regressed, regressed),
        )
        assert pending_ticket_convergence_effects(db_session) == (
            TicketConvergenceEffect(ticket.id),
        )
        assert await ticket_events(db_session, ticket) == [
            status_event(RESOLVED.value, regressed.value)
        ]


# ---------------------------------------------------------------------------
# Derived actionability (package-service.md, Architectural Test Requirement)
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _Transition:
    """One EOL entry or exit of the target Product.

    The Ticket starts converged at `initial` for `EVAL` with the target
    Product's General Support ending on `support_end`. `correction`, when
    set, is the corrected General Support end applied before the measured
    call on `evaluation_date`."""

    initial: TicketStatus
    support_end: date
    correction: date | None
    evaluation_date: date
    expected: TicketStatus
    target_state: tuple[State, State, State]
    registers: bool


NO_ACTIONABLE_EOL: tuple[State, State, State] = (
    (False, NonActionableReason.NO_ACTIONABLE_TRACKS),
    (False, NonActionableReason.NO_ACTIONABLE_PRODUCTS),
    (False, NonActionableReason.EOL),
)

TRANSITIONS = [
    pytest.param(
        _Transition(ANALYZED, EVAL, None, NEXT_DAY, RESOLVED, NO_ACTIONABLE_EOL, False),
        id="eol-entry-by-date",
    ),
    pytest.param(
        _Transition(
            ANALYZED, AFTER_EVAL, BEFORE_EVAL, EVAL, RESOLVED, NO_ACTIONABLE_EOL, False
        ),
        id="eol-entry-by-correction",
    ),
    pytest.param(
        _Transition(
            RESOLVED,
            BEFORE_EVAL,
            AFTER_EVAL,
            EVAL,
            ANALYZED,
            (ACTIONABLE, ACTIONABLE, ACTIONABLE),
            True,
        ),
        id="eol-exit-by-correction",
    ),
]


@pytest.mark.integration
class TestDerivedActionability:
    @pytest.mark.parametrize("transition", TRANSITIONS)
    async def test_eol_entry_and_exit_change_only_the_ticket_status(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        tree: TreeBuilder,
        path: PathBuilder,
        monkeypatch: pytest.MonkeyPatch,
        transition: _Transition,
    ) -> None:
        """An unassigned Ticket with a final in-support "pin" track and an
        `AFFECTED` target track whose eligible Product enters or leaves
        EOL. The status changes through reconciliation with exactly one
        system `status_change`; there is no package-tree exclusion or
        restoration event (audit Testing Requirements 12 and 14), no
        assignment, no audit-history read, and no write beyond the status
        and its event: markers, affectedness, delivery, eligibility,
        override, and release values are unchanged. The target's derived
        parent actionability and reasons follow the supplied date."""
        ticket = await cveless(ticket_factory, status=transition.initial)
        await tree(ticket, status=PackageStatus.NOT_AFFECTED)
        target = await path(
            ticket, status=PackageStatus.AFFECTED, support_end=transition.support_end
        )
        initial = transition.initial
        assert await _reconcile(db_session, ticket.id) == _result(initial, initial)
        if transition.correction is not None:
            await _correct_support_end(
                db_session, target.product, transition.correction
            )
        before = await _other_dimensions(db_session, ticket.id)
        assign = Spy(monkeypatch, "auto_assign_actor")

        with StatementRecorder(db_session) as recorder:
            result = await _reconcile(db_session, ticket.id, transition.evaluation_date)

        assert result == _result(initial, transition.expected)
        events = await ticket_events(db_session, ticket)
        assert events == [status_event(initial.value, transition.expected.value)]
        assert EXCLUSION_EVENTS.isdisjoint(e.event_type for e in events)
        assert _write_targets(recorder) == STATUS_WRITES
        assert recorder.selects_from("ticket_audit_event") == []
        assert assign.calls == []
        assert await ticket_state(db_session, ticket) == (transition.expected, None)
        assert await _other_dimensions(db_session, ticket.id) == before
        assert (
            await observed(db_session, target.occurrence, transition.evaluation_date)
            == transition.target_state
        )
        expected_effects = (
            (TicketConvergenceEffect(ticket.id),) if transition.registers else ()
        )
        assert pending_ticket_convergence_effects(db_session) == expected_effects

    @pytest.mark.parametrize(
        ("marker", "initial", "after", "states"),
        [
            pytest.param(
                None,
                ANALYZED,
                RESOLVED,
                ((ACTIONABLE, ACTIONABLE, ACTIONABLE), NO_ACTIONABLE_EOL),
                id="no-marker",
            ),
            pytest.param(
                "product",
                RESOLVED,
                RESOLVED,
                (
                    (
                        (False, NonActionableReason.NO_ACTIONABLE_TRACKS),
                        (False, NonActionableReason.NO_ACTIONABLE_PRODUCTS),
                        (False, NonActionableReason.PRODUCT_EXCLUDED),
                    ),
                )
                * 2,
                id="product-marker",
            ),
            pytest.param(
                "track",
                RESOLVED,
                RESOLVED,
                (
                    (
                        (False, NonActionableReason.NO_ACTIONABLE_TRACKS),
                        (False, NonActionableReason.TRACK_EXCLUDED),
                        (False, NonActionableReason.TRACK_EXCLUDED),
                    ),
                )
                * 2,
                id="track-marker",
            ),
            pytest.param(
                "package",
                RESOLVED,
                RESOLVED,
                (((False, NonActionableReason.PACKAGE_EXCLUDED),) * 3,) * 2,
                id="package-marker",
            ),
        ],
    )
    async def test_eol_entry_keeps_reason_precedence_and_parent_actionability(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        tree: TreeBuilder,
        path: PathBuilder,
        marker: str | None,
        initial: TicketStatus,
        after: TicketStatus,
        states: tuple[tuple[State, State, State], ...],
    ) -> None:
        """package-model.md, Manual Exclusion Markers and Derived
        Actionability: the boundary Product of an `AFFECTED` target track
        enters EOL on `NEXT_DAY` beside a final "pin" track. With a manual
        marker the marker reason keeps precedence over `eol` on both dates
        and the gate result is unchanged (no event); only the all-clear
        path becomes `eol`, which makes its track and package
        non-actionable and resolves the Ticket. `states` lists the target
        `(package, track, Product)` state on `EVAL` and on `NEXT_DAY`."""
        ticket = await cveless(ticket_factory, status=initial)
        await tree(ticket, status=PackageStatus.NOT_AFFECTED)
        target = await path(
            ticket,
            status=PackageStatus.AFFECTED,
            support_end=EVAL,
            package_excluded=marker == "package",
            track_excluded=marker == "track",
            product_excluded=marker == "product",
        )
        assert await _reconcile(db_session, ticket.id) == _result(initial, initial)
        before = await _other_dimensions(db_session, ticket.id)

        result = await _reconcile(db_session, ticket.id, NEXT_DAY)

        assert result == _result(initial, after)
        assert await ticket_events(db_session, ticket) == (
            [status_event(initial.value, after.value)] if initial is not after else []
        )
        assert await _other_dimensions(db_session, ticket.id) == before
        assert (
            await observed(db_session, target.occurrence, EVAL),
            await observed(db_session, target.occurrence, NEXT_DAY),
        ) == states

    async def test_one_supplied_date_across_discovery_reconciliation_and_result(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        path: PathBuilder,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A run that crosses midnight UTC: the boundary Product enters EOL
        on `NEXT_DAY`. With every clock forbidden, a run supplying `EVAL`
        neither selects nor changes the Ticket, while a run supplying
        `NEXT_DAY` selects it, reconciles it with only that date bound to
        every statement, and returns the status for that date."""
        ticket = await cveless(ticket_factory, status=ANALYZED)
        target = await path(ticket, status=PackageStatus.AFFECTED, support_end=EVAL)
        _forbid_clocks(monkeypatch)

        assert (
            await find_lifecycle_gate_mismatches(db_session, evaluation_date=EVAL) == []
        )
        assert await _reconcile(db_session, ticket.id, EVAL) == _result(
            ANALYZED, ANALYZED
        )
        candidates = await find_lifecycle_gate_mismatches(
            db_session, evaluation_date=NEXT_DAY
        )
        with StatementRecorder(db_session) as recorder:
            result = await _reconcile(db_session, ticket.id, NEXT_DAY)

        assert list(candidates) == [ticket.id]
        assert result == _result(ANALYZED, RESOLVED)
        assert _bound_dates(recorder) == {NEXT_DAY}
        assert await ticket_events(db_session, ticket) == [
            status_event(ANALYZED.value, RESOLVED.value)
        ]
        assert await observed(db_session, target.occurrence, NEXT_DAY) == (
            NO_ACTIONABLE_EOL
        )
        assert (
            await find_lifecycle_gate_mismatches(db_session, evaluation_date=NEXT_DAY)
            == []
        )


# ---------------------------------------------------------------------------
# Rollback (ticket-audit-log.md, Testing Requirements 7 and 24)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestRollback:
    @pytest.mark.parametrize("failure", ["audit", "final-flush"])
    async def test_failure_propagates_and_rollback_discards_every_effect(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        tree: TreeBuilder,
        monkeypatch: pytest.MonkeyPatch,
        failure: str,
    ) -> None:
        """A `Resolved` regression whose `status_change` insertion
        (`audit`) or whose boundary flush after the delegated
        reconciliation (`final-flush`) fails: the exception propagates,
        and the caller's rollback leaves the status, the events, and the
        pending effects at their pre-call state."""
        ticket = await cveless(ticket_factory, status=RESOLVED)
        await tree_for(ANALYZED, ticket, tree)
        ticket_id = ticket.id
        original_reconcile = ticket_mutations.reconcile_ticket_status
        original_flush = db_session.flush
        reconciled = False

        async def reconcile(*args: Any, **kwargs: Any) -> None:
            nonlocal reconciled
            await original_reconcile(*args, **kwargs)
            reconciled = True

        async def failing_log(*args: Any, **kwargs: Any) -> None:
            raise RuntimeError("injected audit failure")

        async def flush(*args: Any, **kwargs: Any) -> None:
            if reconciled:
                raise RuntimeError("injected flush failure")
            await original_flush(*args, **kwargs)

        async with rollback_test_scope(db_session):
            monkeypatch.setattr(package_service, "reconcile_ticket_status", reconcile)
            if failure == "audit":
                monkeypatch.setattr(TicketAuditLog, "log_event", failing_log)
            else:
                monkeypatch.setattr(db_session, "flush", flush)
            with pytest.raises(RuntimeError, match="injected"):
                await _reconcile(db_session, ticket_id)
            monkeypatch.undo()
            assert reconciled is (failure == "final-flush")

        assert await _persisted_status(db_session, ticket_id) == RESOLVED
        assert await ticket_events_by_id(db_session, ticket_id) == []
        assert pending_ticket_convergence_effects(db_session) == ()
