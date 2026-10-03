"""Gate parity of the lifecycle gate-mismatch candidate discovery.

Covers `find_lifecycle_gate_mismatches()` and
`lifecycle_gate_mismatch_condition()`
(backend/app/services/packages/evaluate_lifecycle_transitions.py) and the
public gate builder `ticket_mutations.gate_status_expression()`
(backend/app/services/ticket_mutations.py).

Owning specifications:

- docs/features/packages/product-lifecycle-transitions.md (Algorithm step
  4: candidate discovery selects the `Analysis`, `Analyzed`, and
  `Resolved` Tickets whose persisted status differs from the current gate
  predicates, with the same SQL actionability expressions as
  reconciliation and one `evaluation_date`; `New`, `Ignored`, and
  `Duplicated` are never selected; Lifecycle Authority and Effects: a
  missing or inconsistent lifecycle never makes a Product EOL).
- docs/features/tickets/ticket-mutations.md (`reconcile_ticket_status()`
  step 2: one SQL statement for one `evaluation_date`).
- docs/features/packages/package-model.md (Derived Actionability; Gate
  Participation).
- docs/features/packages/product-catalog.md (Lifecycle Evaluator: an
  inconsistent date set has a `NULL` phase).
- docs/features/platform/testing-strategy.md (Service Functions, "Ticket
  gate and convergence changes additionally require").

The gate matrix seeds one Ticket per tree shape and persisted status in one
test transaction. Every Ticket's expected gate result is transcribed from
the specifications for each evaluation date, never computed with the
module under test; the parity tests then compare the set-based candidate
query, the public gate expression, and the per-Ticket reconciliation path
with that expectation and with each other. Single-Ticket gate formulas
are covered by `tests/test_services/test_ticket_mutations.py`.
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import date, datetime, timedelta
from enum import StrEnum

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import CVSSVersion, PackageStatus, Severity, TicketStatus
from app.models.cve import CVE
from app.models.cve_cvss_assessment import CVECVSSAssessment
from app.models.product import Product
from app.models.ticket import Ticket
from app.models.ticket_package_product import TicketPackageProduct
from app.services import ticket_mutations
from app.services.packages import evaluate_lifecycle_transitions
from app.services.packages.evaluate_lifecycle_transitions import (
    find_lifecycle_gate_mismatches,
)
from app.services.ticket_convergence_registry import (
    pending_ticket_convergence_effects,
)
from app.services.ticket_mutations import (
    gate_status_expression,
    reconcile_ticket_status,
)
from tests.support.ticket_mutations import (
    BEFORE_EVAL,
    EVAL,
    Prod,
    StatementRecorder,
    TicketFactory,
    TreeBuilder,
    cveless,
    lock_ticket,
    ticket_events,
)

pytest_plugins = ["tests.support.ticket_mutation_fixtures"]
"""Provides the shared `tree` fixture."""

ProductFactory = Callable[..., Awaitable[Product]]
OccurrenceFactory = Callable[..., Awaitable[TicketPackageProduct]]
CVEFactory = Callable[..., Awaitable[CVE]]
AssessmentFactory = Callable[..., Awaitable[CVECVSSAssessment]]

NEXT_DAY = EVAL + timedelta(days=1)
"""The first EOL day of a boundary Product, whose General Support ends on
`EVAL` (product-catalog.md, Lifecycle Evaluator: the end date is
inclusive)."""

DATES = pytest.mark.parametrize(
    "evaluation_date",
    [pytest.param(EVAL, id="eval"), pytest.param(NEXT_DAY, id="next-day")],
)

ANALYSIS = TicketStatus.ANALYSIS
ANALYZED = TicketStatus.ANALYZED
RESOLVED = TicketStatus.RESOLVED

GATE_ZONE = (ANALYSIS, ANALYZED, RESOLVED)
OUTSIDE_GATE_ZONE = (TicketStatus.NEW, TicketStatus.IGNORED, TicketStatus.DUPLICATED)


# ---------------------------------------------------------------------------
# Gate matrix
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _Kit:
    """The factories a tree shape uses."""

    tree: TreeBuilder
    product_factory: ProductFactory
    occurrence_factory: OccurrenceFactory

    async def occurrence(
        self,
        ticket: Ticket,
        *,
        status: PackageStatus,
        eligible: bool = True,
        override: bool = False,
        **dates: date,
    ) -> None:
        """One track of `status` with one Product occurrence whose catalog
        Product has exactly the given lifecycle dates."""
        track = await self.tree(ticket, status=status, products=())
        product = await self.product_factory(**dates)
        await self.occurrence_factory(
            ticket_package_track_id=track.id,
            product_id=product.id,
            eligible=eligible,
            is_eligible_override=override,
        )


Builder = Callable[[_Kit, Ticket], Awaitable[None]]


async def _empty(kit: _Kit, ticket: Ticket) -> None:
    """No package tree: no manually included track."""


async def _all_eol(kit: _Kit, ticket: Ticket) -> None:
    await kit.tree(ticket, status=PackageStatus.ANALYSIS, products=(Prod(eol=True),))
    await kit.tree(ticket, status=PackageStatus.AFFECTED, products=(Prod(eol=True),))


async def _missing_lifecycle(kit: _Kit, ticket: Ticket) -> None:
    await kit.tree(
        ticket, status=PackageStatus.AFFECTED, products=(Prod(lifecycle=False),)
    )


async def _inconsistent_lifecycle(kit: _Kit, ticket: Ticket) -> None:
    # Both ends precede `EVAL`, but General Support ends after Extended
    # Support: the set is inconsistent, so the phase is NULL, never EOL.
    await kit.occurrence(
        ticket,
        status=PackageStatus.AFFECTED,
        general_support_end_date=BEFORE_EVAL,
        extended_support_end_date=BEFORE_EVAL - timedelta(days=10),
    )


async def _excluded_descendants(kit: _Kit, ticket: Ticket) -> None:
    await kit.tree(ticket, status=PackageStatus.ANALYSIS, track_excluded=True)
    await kit.tree(ticket, status=PackageStatus.ANALYSIS, package_excluded=True)
    await kit.tree(
        ticket, status=PackageStatus.AFFECTED, products=(Prod(excluded=True),)
    )
    await kit.tree(ticket, status=PackageStatus.NOT_AFFECTED)


async def _only_excluded_package(kit: _Kit, ticket: Ticket) -> None:
    await kit.tree(ticket, status=PackageStatus.NOT_AFFECTED, package_excluded=True)


async def _overrides_false(kit: _Kit, ticket: Ticket) -> None:
    await kit.tree(
        ticket,
        status=PackageStatus.AFFECTED,
        products=(Prod(eligible=False, override=True), Prod(eligible=False)),
    )


async def _override_true_boundary(kit: _Kit, ticket: Ticket) -> None:
    await kit.occurrence(
        ticket,
        status=PackageStatus.AFFECTED,
        override=True,
        general_support_end_date=EVAL,
    )


async def _fixed_unreleased(kit: _Kit, ticket: Ticket) -> None:
    await kit.tree(ticket, status=PackageStatus.FIXED, products=(Prod(),))


async def _boundary_affected(kit: _Kit, ticket: Ticket) -> None:
    await kit.occurrence(
        ticket, status=PackageStatus.AFFECTED, general_support_end_date=EVAL
    )


async def _boundary_analysis(kit: _Kit, ticket: Ticket) -> None:
    await kit.occurrence(
        ticket, status=PackageStatus.ANALYSIS, general_support_end_date=EVAL
    )
    await kit.tree(ticket, status=PackageStatus.NOT_AFFECTED)


async def _final_decision(kit: _Kit, ticket: Ticket) -> None:
    await kit.tree(ticket, status=PackageStatus.NOT_AFFECTED)


class Kind(StrEnum):
    """How the matrix Ticket is created."""

    CVELESS = "cveless"
    """CVE-less with `severity_manual = High`."""
    CVELESS_NO_SEVERITY = "cveless-no-severity"
    """CVE-less with SQL `NULL` severity."""
    CVE_SUSE = "cve-suse"
    """A `High` CVE with a canonical SUSE v3.1 assessment."""
    CVE_EXTERNAL = "cve-external"
    """A `High` CVE with only an external assessment."""


@dataclass(frozen=True, slots=True)
class Shape:
    """One tree shape and its expected gate result per evaluation date."""

    id: str
    build: Builder
    on_eval: TicketStatus
    on_next_day: TicketStatus
    kind: Kind = Kind.CVELESS

    def expected(self, evaluation_date: date) -> TicketStatus:
        return self.on_eval if evaluation_date == EVAL else self.on_next_day


SHAPES: tuple[Shape, ...] = (
    # M is empty: the Analysis floor.
    Shape("empty-tree", _empty, ANALYSIS, ANALYSIS),
    # M non-empty, A empty: Analyzed and vacuously resolution-complete.
    Shape("all-eol", _all_eol, RESOLVED, RESOLVED),
    # A NULL phase is actionable: the AFFECTED track keeps an eligible
    # actionable unreleased Product (clause c fails).
    Shape("missing-lifecycle", _missing_lifecycle, ANALYZED, ANALYZED),
    Shape("inconsistent-lifecycle", _inconsistent_lifecycle, ANALYZED, ANALYZED),
    # Excluded ANALYSIS track and package do not block; the AFFECTED track
    # whose only Product is excluded counts for M only; the NOT_AFFECTED
    # track is complete.
    Shape("excluded-descendants", _excluded_descendants, RESOLVED, RESOLVED),
    Shape("only-excluded-package", _only_excluded_package, ANALYSIS, ANALYSIS),
    # Override-false Products leave the eligible set empty (clause c).
    Shape("overrides-false", _overrides_false, RESOLVED, RESOLVED),
    # An override-true Product stays eligible but not actionable once EOL.
    Shape("override-true-boundary", _override_true_boundary, ANALYZED, RESOLVED),
    # CVE-less FIXED ignores release (clause b); with a CVE it requires it.
    Shape("cveless-fixed", _fixed_unreleased, RESOLVED, RESOLVED),
    Shape("cve-fixed-unreleased", _fixed_unreleased, ANALYZED, ANALYZED, Kind.CVE_SUSE),
    # The boundary Product enters EOL on NEXT_DAY (forward correction on
    # NEXT_DAY; reverse correction of a Resolved Ticket on EVAL).
    Shape("boundary-affected", _boundary_affected, ANALYZED, RESOLVED),
    Shape("boundary-analysis", _boundary_analysis, ANALYSIS, RESOLVED),
    # Non-lifecycle Analyzed inputs.
    Shape(
        "no-severity",
        _final_decision,
        ANALYSIS,
        ANALYSIS,
        Kind.CVELESS_NO_SEVERITY,
    ),
    Shape("cve-external-only", _final_decision, ANALYSIS, ANALYSIS, Kind.CVE_EXTERNAL),
    Shape("cve-suse-final", _final_decision, RESOLVED, RESOLVED, Kind.CVE_SUSE),
)


@dataclass(frozen=True, slots=True)
class Seeded:
    """One matrix Ticket: its shape and persisted status."""

    ticket: Ticket
    shape: Shape
    status: TicketStatus

    @property
    def id(self) -> uuid.UUID:
        return self.ticket.id


Seeder = Callable[..., Awaitable[list[Seeded]]]


@pytest.fixture
def seed(
    tree: TreeBuilder,
    product_factory: ProductFactory,
    ticket_package_product_factory: OccurrenceFactory,
    ticket_factory: TicketFactory,
    cve_factory: CVEFactory,
    cve_cvss_assessment_factory: AssessmentFactory,
) -> Seeder:
    """Seed one Ticket per shape and persisted status (default: every
    gate-zone status and every status outside the gate zone)."""
    kit = _Kit(tree, product_factory, ticket_package_product_factory)

    async def _ticket(kind: Kind, status: TicketStatus) -> Ticket:
        if kind == Kind.CVELESS:
            return await cveless(ticket_factory, status=status)
        if kind == Kind.CVELESS_NO_SEVERITY:
            return await cveless(ticket_factory, status=status, severity=None)
        cve = await cve_factory(severity=Severity.HIGH.value)
        await cve_cvss_assessment_factory(
            cve_id=cve.id,
            provider_name="SUSE" if kind == Kind.CVE_SUSE else "NVD",
            cvss_version=CVSSVersion.V3_1.value,
        )
        return await ticket_factory(status=status.value, cve_id=cve.id)

    async def _seed(
        shapes: tuple[Shape, ...] = SHAPES,
        statuses: tuple[TicketStatus, ...] = GATE_ZONE + OUTSIDE_GATE_ZONE,
    ) -> list[Seeded]:
        seeded = []
        for shape in shapes:
            for status in statuses:
                ticket = await _ticket(shape.kind, status)
                await shape.build(kit, ticket)
                seeded.append(Seeded(ticket, shape, status))
        return seeded

    return _seed


def _mismatched(seeded: list[Seeded], evaluation_date: date) -> list[uuid.UUID]:
    """The expected candidates in ascending ID order: gate-zone Tickets
    whose persisted status differs from the transcribed gate result."""
    return sorted(
        s.id
        for s in seeded
        if s.status in GATE_ZONE and s.status is not s.shape.expected(evaluation_date)
    )


# ---------------------------------------------------------------------------
# Candidate discovery versus reconciliation
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestGateParity:
    @DATES
    async def test_candidates_are_exactly_the_tickets_reconciliation_changes(
        self, db_session: AsyncSession, seed: Seeder, evaluation_date: date
    ) -> None:
        """product-lifecycle-transitions.md, Algorithm step 4 (issue #766
        decision D2): over the gate matrix, the candidate set equals the
        set of Tickets whose `reconcile_ticket_status()` with the same date
        changes status, and both equal the transcribed mismatches."""
        seeded = await seed()
        expected = _mismatched(seeded, evaluation_date)
        assert 0 < len(expected) < len(seeded)

        candidates = await find_lifecycle_gate_mismatches(
            db_session, evaluation_date=evaluation_date
        )

        assert list(candidates) == expected
        changed = []
        for item in seeded:
            if item.status not in GATE_ZONE:
                continue
            ticket = await lock_ticket(db_session, item.ticket)
            await reconcile_ticket_status(
                ticket, db_session, evaluation_date=evaluation_date
            )
            assert ticket.status == item.shape.expected(evaluation_date), item
            if ticket.status != item.status:
                changed.append(item.id)
        assert sorted(changed) == expected
        # Once reconciled, the same date selects nothing.
        assert (
            await find_lifecycle_gate_mismatches(
                db_session, evaluation_date=evaluation_date
            )
            == []
        )

    async def test_new_ignored_and_duplicated_are_never_selected(
        self, db_session: AsyncSession, seed: Seeder
    ) -> None:
        """Algorithm step 4: `New` is never selected because gates do not
        apply before first assignment, and the manual zone only leaves
        through its explicit exits, even when their trees gate otherwise
        on every date."""
        boundary = next(s for s in SHAPES if s.id == "boundary-analysis")
        final = next(s for s in SHAPES if s.id == "cve-suse-final")
        outside = await seed((boundary, final), OUTSIDE_GATE_ZONE)
        (control,) = await seed((final,), (ANALYSIS,))

        for evaluation_date in (EVAL, NEXT_DAY):
            candidates = await find_lifecycle_gate_mismatches(
                db_session, evaluation_date=evaluation_date
            )
            assert list(candidates) == [control.id]
        for item in outside:
            persisted = (
                await db_session.execute(
                    select(Ticket.status).where(Ticket.id == item.id)
                )
            ).scalar_one()
            assert persisted == item.status


# ---------------------------------------------------------------------------
# Public gate expression versus the per-Ticket evaluation
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestGateExpressionParity:
    @DATES
    async def test_expression_equals_the_per_ticket_evaluation(
        self, db_session: AsyncSession, seed: Seeder, evaluation_date: date
    ) -> None:
        """`gate_status_expression()` evaluated for every matrix Ticket in
        one set-based statement equals `_evaluate_gate_status()` (the path
        of `reconcile_ticket_status()` step 2) and the transcribed gate
        result. Status is not an input, so Tickets outside the gate zone
        evaluate like the others. The per-Ticket evaluation is still one
        SQL statement."""
        seeded = await seed()
        result = await db_session.execute(
            select(Ticket.id, gate_status_expression(evaluation_date)).where(
                Ticket.id.in_([s.id for s in seeded])
            )
        )
        rows: dict[uuid.UUID, str] = dict(result.all())

        assert len(rows) == len(seeded)
        for item in seeded:
            with StatementRecorder(db_session) as recorder:
                evaluated = await ticket_mutations._evaluate_gate_status(
                    db_session, item.id, evaluation_date
                )
            assert len(recorder.statements) == 1
            expected = item.shape.expected(evaluation_date)
            assert (TicketStatus(rows[item.id]), evaluated) == (expected, expected), (
                item
            )


# ---------------------------------------------------------------------------
# Read-only discovery and the supplied date
# ---------------------------------------------------------------------------


def _forbid_clocks(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fail any attempt to capture the current date: the supplied
    `evaluation_date` alone governs."""

    def clock() -> datetime:
        raise AssertionError("the supplied evaluation date must be reused")

    monkeypatch.setattr(ticket_mutations, "_utc_now", clock)
    monkeypatch.setattr(evaluate_lifecycle_transitions, "_utc_today", clock)


def _bound_dates(recorder: StatementRecorder) -> set[date]:
    """Every `date` (not `datetime`) parameter bound to a statement."""
    return {
        value
        for params in recorder.parameters
        for value in (params.values() if isinstance(params, dict) else params)
        if isinstance(value, date) and not isinstance(value, datetime)
    }


@pytest.mark.integration
class TestReadOnlyDiscovery:
    async def test_discovery_is_one_select_without_lock_write_or_event(
        self, db_session: AsyncSession, seed: Seeder
    ) -> None:
        """Category B: one read-only statement; no lock, write, audit read
        or event, status change, or convergence registration, even for a
        `Resolved` regression candidate."""
        boundary = next(s for s in SHAPES if s.id == "boundary-affected")
        seeded = await seed((boundary,), GATE_ZONE)

        with StatementRecorder(db_session) as recorder:
            candidates = await find_lifecycle_gate_mismatches(
                db_session, evaluation_date=EVAL
            )

        (resolved,) = [s for s in seeded if s.status is RESOLVED]
        (analysis,) = [s for s in seeded if s.status is ANALYSIS]
        assert list(candidates) == sorted([resolved.id, analysis.id])
        (statement,) = recorder.statements
        assert statement.lstrip().upper().startswith("SELECT")
        assert recorder.row_locks() == []
        assert "ticket_audit_event" not in statement
        assert pending_ticket_convergence_effects(db_session) == ()
        for item in seeded:
            persisted = (
                await db_session.execute(
                    select(Ticket.status).where(Ticket.id == item.id)
                )
            ).scalar_one()
            assert persisted == item.status
            assert await ticket_events(db_session, item.ticket) == []

    async def test_supplied_date_alone_decides_a_midnight_boundary_mismatch(
        self,
        db_session: AsyncSession,
        seed: Seeder,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The boundary Product's EOL begins on `NEXT_DAY`: an `Analyzed`
        Ticket is a mismatch only when the supplied date is `NEXT_DAY`,
        whatever the clock says, and every bound date is the supplied
        one."""
        boundary = next(s for s in SHAPES if s.id == "boundary-affected")
        (item,) = await seed((boundary,), (ANALYZED,))
        _forbid_clocks(monkeypatch)

        for evaluation_date, expected in ((EVAL, []), (NEXT_DAY, [item.id])):
            with StatementRecorder(db_session) as recorder:
                candidates = await find_lifecycle_gate_mismatches(
                    db_session, evaluation_date=evaluation_date
                )
            assert list(candidates) == expected
            assert _bound_dates(recorder) == {evaluation_date}
