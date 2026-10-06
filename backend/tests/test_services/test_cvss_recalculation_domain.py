"""Domain-matrix tests of the all-CVE default-version recalculation
workflow `run_cvss_derived_state_recalculation()`
(backend/app/services/cvss_recalculation.py), exercised through the runner
rather than the chain.

Owning specifications:

- docs/features/platform/default-cvss-version-operations.md (All-CVE
  Recalculation Runner: Per-CVE Transactional Unit, Outcome
  Classification; Scope and Ownership: no assessment change and no
  remediation action);
- docs/features/tickets/ticket-mutations.md (`recalculate_cvss_chain()`,
  default-version mode and Runner-facing classification; CVSS Status
  Matrix, default-version paragraph; `reconcile_ticket_status()` steps 3-5,
  Assignment Eligibility Sanitization, Transaction-Local Ticket Convergence
  Registration);
- docs/features/tickets/ticket-audit-log.md (Canonical Mutation and
  No-Event Matrix: Default-version severity/eligibility chain; Automatic
  priority refresh);
- docs/features/tickets/ticket-priority.md (Refresh Points, default-version
  row; Audit; Testing Requirement 8);
- docs/features/tickets/tickets.md (Gate: Analysis → Analyzed; Gate:
  Analyzed → Resolved; Gate Input and Reconciliation Ownership);
- docs/features/packages/package-model.md (Axis 2: Eligibility, rule 1
  override preservation);
- docs/features/tickets/cvss-scoring.md (Severity Resolution Cascade;
  Eligibility Score Resolution);
- docs/features/platform/testing-strategy.md (All-CVE Recalculation
  Runner: Domain matrix, Idempotency and recovery; Audit Trail Testing).

The shared stale scenario follows the chain tests: the CVE's persisted
severity is `Medium` while its SUSE 3.1 assessment (9.8) derives `Critical`
at the run target 3.1; the Ticket's `priority_auto` is the stale `P4`
(`Critical` with unknown exploitation is `P2`); and the automatic
occurrence with threshold 9.0 is still `false` (9.8 meets it). Expected
values are transcribed from the specifications.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from datetime import date
from decimal import Decimal
from typing import Any

import pytest
import redis.asyncio as redis_asyncio
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

from app.core.enums import PackageStatus, Role, Severity, TicketStatus
from app.models.cve import CVE
from app.models.cve_kev_entry import CVEKEVEntry
from app.models.ticket import Ticket
from app.models.ticket_package import TicketPackage
from app.models.ticket_package_product import TicketPackageProduct
from app.models.ticket_package_track import TicketPackageTrack
from app.models.user import User
from tests.support.cvss_chain import (
    Assessment,
    CallCounter,
    assessment_snapshot,
    cve_severity,
    eligibility,
    priority_event,
    product_event,
    severity_event,
    subjects,
    ticket_state,
    total_ticket_events,
)
from tests.support.cvss_recalculation import (
    RecalculationHarness,
    capture_events,
    completed_run,
    recalculation_harness,
    runner_events,
)
from tests.support.ticket_mutations import (
    EVAL,
    EventRow,
    Prod,
    status_event,
    ticket_events_by_id,
    unassigned_event,
)

pytestmark = pytest.mark.integration

SUSE_31_CRITICAL = Assessment("9.8")
SUSE_31_HIGH = Assessment("7.5")
T9 = Decimal("9.0")
T99 = Decimal("9.9")

INACTIVE = "inactive assignee"
ROLE_REMOVED = "vulnerability_analyst role removed"
"""The exact sanitation reasons (ticket-mutations.md, Assignment
Eligibility Sanitization)."""

ONE_RECONCILIATION = [{"evaluation_date": EVAL}]
"""One final `reconcile_ticket_status()` call with the unit's date."""

CHAIN_EVENT_TYPES = {
    "severity_changed",
    "product_eligibility_changed",
    "priority_changed",
    "status_change",
}
"""The event types of the "Default-version severity/eligibility chain"
row (ticket-audit-log.md); an assigned Ticket may add sanitation."""


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
async def h(
    _engine: AsyncEngine,
    redis_client: redis_asyncio.Redis,
    monkeypatch: pytest.MonkeyPatch,
) -> AsyncIterator[RecalculationHarness]:
    async with recalculation_harness(_engine.url, redis_client, monkeypatch) as harness:
        yield harness


@pytest.fixture
def reconcile(monkeypatch: pytest.MonkeyPatch) -> CallCounter:
    return CallCounter(monkeypatch, "reconcile_ticket_status")


# ---------------------------------------------------------------------------
# Committed population
# ---------------------------------------------------------------------------


async def _write(h: RecalculationHarness, statement: Any) -> None:
    await h.world.session.execute(statement)
    await h.world.session.commit()


async def _ticket(
    h: RecalculationHarness,
    cve: CVE,
    status: TicketStatus,
    *,
    priority_auto: str | None = "P4",
    priority_override: str | None = None,
    assignee: User | None = None,
) -> Ticket:
    """A committed Ticket of `cve` in `status`; a `Duplicated` Ticket points
    at a fresh CVE-less Ticket, which the runner never visits."""
    ticket = await h.world.ticket(
        cve_id=cve.id,
        status=TicketStatus.ANALYSIS if status is TicketStatus.DUPLICATED else status,
        priority_auto=priority_auto,
        assignee_id=assignee.id if assignee is not None else None,
    )
    values: dict[str, Any] = {}
    if status is TicketStatus.DUPLICATED:
        target = await h.world.ticket(cve_id=None)
        values.update(status=status.value, duplicate_of_id=target.id)
    if priority_override is not None:
        values["priority_override"] = priority_override
    if values:
        await _write(h, update(Ticket).where(Ticket.id == ticket.id).values(**values))
    return ticket


async def _stale(
    h: RecalculationHarness,
    status: TicketStatus,
    track_status: PackageStatus,
    *,
    assignee: User | None = None,
    products: tuple[Prod, ...] = (Prod(eligible=False, threshold=T9),),
) -> tuple[CVE, Ticket]:
    """The shared stale scenario for a Ticket in `status` with one track."""
    cve = await h.world.scored_cve(SUSE_31_CRITICAL, severity=Severity.MEDIUM)
    ticket = await _ticket(h, cve, status, assignee=assignee)
    await h.world.track(ticket, status=track_status, products=products)
    return cve, ticket


async def _kev(h: RecalculationHarness, cve: CVE) -> None:
    """A KEV entry added out of band (cascades with its CVE)."""
    h.world.session.add(CVEKEVEntry(cve_id=cve.id, date_added=date(2026, 9, 1)))
    await h.world.session.commit()


# ---------------------------------------------------------------------------
# Readers
# ---------------------------------------------------------------------------


async def _events(h: RecalculationHarness, ticket: Ticket) -> list[EventRow]:
    return await h.world.read(lambda db: ticket_events_by_id(db, ticket.id))


async def _state(h: RecalculationHarness, ticket: Ticket) -> tuple[Any, ...]:
    return await h.world.read(lambda db: ticket_state(db, ticket.id))


async def _eligibility(
    h: RecalculationHarness, ticket: Ticket
) -> list[tuple[bool, bool]]:
    return await h.world.read(lambda db: eligibility(db, ticket.id))


async def _subjects(h: RecalculationHarness, ticket: Ticket) -> list[dict[str, str]]:
    return await h.world.read(lambda db: subjects(db, ticket.id))


async def _severity(h: RecalculationHarness, cve: CVE) -> str | None:
    return await h.world.read(lambda db: cve_severity(db, cve.id))


async def _assessments(h: RecalculationHarness, cve: CVE) -> list[tuple[Any, ...]]:
    return await h.world.read(lambda db: assessment_snapshot(db, cve.id))


async def _package_state(
    h: RecalculationHarness, ticket: Ticket
) -> list[tuple[Any, ...]]:
    """Every package-tree column a remediation action could change: package
    and track markers, affectedness, delivery, and each occurrence's
    override marker, release, and marker (everything except the automatic
    `eligible`)."""

    async def _read(db: AsyncSession) -> list[tuple[Any, ...]]:
        rows = await db.execute(
            select(
                TicketPackage.deleted_at,
                TicketPackageTrack.status,
                TicketPackageTrack.delivery_status,
                TicketPackageTrack.deleted_at,
                TicketPackageProduct.is_eligible_override,
                TicketPackageProduct.released_at,
                TicketPackageProduct.deleted_at,
            )
            .select_from(TicketPackageProduct)
            .join(
                TicketPackageTrack,
                TicketPackageTrack.id == TicketPackageProduct.ticket_package_track_id,
            )
            .join(
                TicketPackage, TicketPackage.id == TicketPackageTrack.ticket_package_id
            )
            .where(TicketPackage.ticket_id == ticket.id)
            .order_by(TicketPackageProduct.id)
        )
        return [tuple(row) for row in rows]

    return await h.world.read(_read)


def _record_publications(
    h: RecalculationHarness,
) -> list[tuple[str, str]]:
    """Make the substituted publisher record, per publication, the Ticket's
    committed status as an independent connection observes it while the
    Ticket is lockable without waiting: the unit committed and released
    its locks before the drain."""
    observed: list[tuple[str, str]] = []

    async def _on_call(ticket_id: str) -> None:
        status = (
            await h.observer.execute(
                select(Ticket.status)
                .where(Ticket.id == uuid.UUID(ticket_id))
                .with_for_update(nowait=True)
            )
        ).scalar_one()
        observed.append((ticket_id, status))

    h.published.on_call = _on_call
    return observed


# ---------------------------------------------------------------------------
# Ticketless CVEs
# ---------------------------------------------------------------------------


class TestTicketless:
    async def test_ticketless_cves_receive_severity_only(
        self, h: RecalculationHarness, reconcile: CallCounter
    ) -> None:
        stale = await h.world.scored_cve(SUSE_31_CRITICAL, severity=Severity.MEDIUM)
        converged = await h.world.scored_cve(
            SUSE_31_CRITICAL, severity=Severity.CRITICAL
        )
        events_before = await h.world.read(total_ticket_events)
        task_id = await h.admit()

        with capture_events() as logs:
            await h.run(task_id)

        assert runner_events(logs) == completed_run(
            task_id, converged.id, changed=1, unchanged=1
        )
        assert await _severity(h, stale) == "Critical"
        assert await _severity(h, converged) == "Critical"
        assert await h.world.read(total_ticket_events) == events_before
        assert reconcile.calls == []
        assert h.published.calls == []


# ---------------------------------------------------------------------------
# New
# ---------------------------------------------------------------------------


class TestNew:
    async def test_new_ticket_receives_eligibility_and_priority_without_reconciling(
        self, h: RecalculationHarness, reconcile: CallCounter
    ) -> None:
        """A `NOT_AFFECTED` tree would resolve the Ticket if it were
        reconciled; `New` stays outside gate reconciliation."""
        cve, ticket = await _stale(h, TicketStatus.NEW, PackageStatus.NOT_AFFECTED)
        task_id = await h.admit()

        with capture_events() as logs:
            await h.run(task_id)

        assert runner_events(logs) == completed_run(task_id, cve.id, changed=1)
        detail = await _subjects(h, ticket)
        assert await _events(h, ticket) == [
            severity_event("Medium", "Critical"),
            product_event(detail[0], False, True),
            priority_event("P4", "P2"),
        ]
        assert await _state(h, ticket) == (TicketStatus.NEW, None, "P2", None, None)
        assert await _eligibility(h, ticket) == [(True, False)]
        assert reconcile.calls == []
        assert h.published.calls == []


# ---------------------------------------------------------------------------
# Gate zone
# ---------------------------------------------------------------------------


_GATE_TRANSITIONS = [
    pytest.param(
        TicketStatus.ANALYSIS,
        PackageStatus.AFFECTED,
        TicketStatus.ANALYZED,
        id="analysis-to-analyzed",
    ),
    pytest.param(
        TicketStatus.ANALYZED,
        PackageStatus.NOT_AFFECTED,
        TicketStatus.RESOLVED,
        id="analyzed-to-resolved",
    ),
    pytest.param(
        TicketStatus.RESOLVED,
        PackageStatus.FIXED,
        TicketStatus.ANALYZED,
        id="resolved-regresses-to-analyzed",
    ),
]


class TestGateZone:
    @pytest.mark.parametrize(("status", "track_status", "expected"), _GATE_TRANSITIONS)
    async def test_gate_input_change_reconciles_exactly_once(
        self,
        h: RecalculationHarness,
        reconcile: CallCounter,
        status: TicketStatus,
        track_status: PackageStatus,
        expected: TicketStatus,
    ) -> None:
        """Severity and Product changes are gate inputs: one final
        reconciliation after every chain event. A `Resolved` regression
        (its FIXED track's newly eligible Product is unreleased) registers
        one convergence effect, drained once after the unit committed and
        released its locks; no other transition registers one. The active
        VA assignee is retained."""
        owner = await h.world.analyst()
        cve, ticket = await _stale(h, status, track_status, assignee=owner)
        published = _record_publications(h)
        task_id = await h.admit()

        with capture_events() as logs:
            await h.run(task_id)

        assert runner_events(logs) == completed_run(task_id, cve.id, changed=1)
        detail = await _subjects(h, ticket)
        assert await _events(h, ticket) == [
            severity_event("Medium", "Critical"),
            product_event(detail[0], False, True),
            priority_event("P4", "P2"),
            status_event(status, expected),
        ]
        assert await _state(h, ticket) == (expected, owner.id, "P2", None, None)
        assert await _eligibility(h, ticket) == [(True, False)]
        assert reconcile.calls == ONE_RECONCILIATION
        regression = status is TicketStatus.RESOLVED
        assert published == ([(str(ticket.id), expected)] if regression else [])
        assert h.published.calls == ([str(ticket.id)] if regression else [])

    async def test_resolved_regression_to_analysis_registers_and_drains_one_effect(
        self, h: RecalculationHarness, reconcile: CallCounter
    ) -> None:
        """Every assessment disappeared out of band while the persisted
        severity still says `High`: severity becomes SQL `NULL`, so the
        Analyzed predicate fails and the `Resolved` Ticket regresses to the
        `Analysis` floor. The Product stays eligible under the 10.0
        fallback and threshold `NULL`."""
        owner = await h.world.analyst()
        cve = await h.world.scored_cve(severity=Severity.HIGH)
        ticket = await _ticket(
            h, cve, TicketStatus.RESOLVED, priority_auto="P3", assignee=owner
        )
        await h.world.track(
            ticket, status=PackageStatus.NOT_AFFECTED, products=(Prod(),)
        )
        published = _record_publications(h)
        task_id = await h.admit()

        with capture_events() as logs:
            await h.run(task_id)

        assert runner_events(logs) == completed_run(task_id, cve.id, changed=1)
        assert await _severity(h, cve) is None
        assert await _events(h, ticket) == [
            severity_event("High", None),
            priority_event("P3", None),
            status_event(TicketStatus.RESOLVED, TicketStatus.ANALYSIS),
        ]
        assert await _state(h, ticket) == (
            TicketStatus.ANALYSIS,
            owner.id,
            None,
            None,
            None,
        )
        assert await _eligibility(h, ticket) == [(True, False)]
        assert reconcile.calls == ONE_RECONCILIATION
        assert published == [(str(ticket.id), TicketStatus.ANALYSIS)]
        assert h.published.calls == [str(ticket.id)]

    @pytest.mark.parametrize(
        ("status", "track_status"),
        [
            pytest.param(
                TicketStatus.ANALYSIS,
                PackageStatus.AFFECTED,
                id="analysis-gate-analyzed",
            ),
            pytest.param(
                TicketStatus.ANALYZED,
                PackageStatus.NOT_AFFECTED,
                id="analyzed-gate-resolved",
            ),
            pytest.param(
                TicketStatus.RESOLVED,
                PackageStatus.ANALYSIS,
                id="resolved-gate-analysis",
            ),
        ],
    )
    @pytest.mark.parametrize("priority", ["P2", "P4"], ids=["converged", "stale"])
    async def test_no_gate_input_change_never_reconciles(
        self,
        h: RecalculationHarness,
        reconcile: CallCounter,
        status: TicketStatus,
        track_status: PackageStatus,
        priority: str,
    ) -> None:
        """Severity and the Product are converged while the persisted status
        disagrees with the gates and the assignee is inactive. Priority is
        not a gate input: neither the converged unit nor a priority-only
        change reconciles, so the status and the ineligible assignee stay
        for the next gate-relevant mutation."""
        assignee = await h.world.analyst(active=False)
        cve = await h.world.scored_cve(SUSE_31_CRITICAL, severity=Severity.CRITICAL)
        ticket = await _ticket(
            h, cve, status, priority_auto=priority, assignee=assignee
        )
        await h.world.track(
            ticket,
            status=track_status,
            products=(Prod(eligible=True, threshold=T9),),
        )
        task_id = await h.admit()

        with capture_events() as logs:
            await h.run(task_id)

        stale = priority == "P4"
        assert runner_events(logs) == completed_run(
            task_id, cve.id, changed=int(stale), unchanged=int(not stale)
        )
        assert await _events(h, ticket) == (
            [priority_event("P4", "P2")] if stale else []
        )
        assert await _state(h, ticket) == (status, assignee.id, "P2", None, None)
        assert await _eligibility(h, ticket) == [(True, False)]
        assert reconcile.calls == []
        assert h.published.calls == []


# ---------------------------------------------------------------------------
# Assignment eligibility sanitation
# ---------------------------------------------------------------------------


class TestSanitation:
    @pytest.mark.parametrize(
        ("ineligibility", "track_status", "expected", "reason"),
        [
            pytest.param(
                "inactive",
                PackageStatus.AFFECTED,
                TicketStatus.ANALYZED,
                INACTIVE,
                id="inactive-analyzed",
            ),
            pytest.param(
                "role-removed",
                PackageStatus.AFFECTED,
                TicketStatus.ANALYZED,
                ROLE_REMOVED,
                id="role-removed-analyzed",
            ),
            pytest.param(
                "inactive",
                PackageStatus.NOT_AFFECTED,
                TicketStatus.RESOLVED,
                None,
                id="inactive-resolved-retained",
            ),
        ],
    )
    async def test_reconciliation_sanitizes_an_ineligible_assignee(
        self,
        h: RecalculationHarness,
        ineligibility: str,
        track_status: PackageStatus,
        expected: TicketStatus,
        reason: str | None,
    ) -> None:
        """The reconciliation that the gate-input change triggers clears an
        inactive or non-VA assignee for an `Analysis` or `Analyzed` result,
        with one system `assignment` event after the priority event and
        before the final `status_change`; a `Resolved` result retains the
        assignee without an event."""
        if ineligibility == "inactive":
            assignee = await h.world.analyst(active=False)
        else:
            assignee = await h.world.user(role=Role.RESTRICTED_ANALYST)
        cve, ticket = await _stale(
            h, TicketStatus.ANALYSIS, track_status, assignee=assignee
        )
        task_id = await h.admit()

        with capture_events() as logs:
            await h.run(task_id)

        assert runner_events(logs) == completed_run(task_id, cve.id, changed=1)
        detail = await _subjects(h, ticket)
        sanitation = (
            [unassigned_event(assignee.username, reason)] if reason is not None else []
        )
        assert await _events(h, ticket) == [
            severity_event("Medium", "Critical"),
            product_event(detail[0], False, True),
            priority_event("P4", "P2"),
            *sanitation,
            status_event(TicketStatus.ANALYSIS, expected),
        ]
        retained = assignee.id if reason is None else None
        assert await _state(h, ticket) == (expected, retained, "P2", None, None)
        assert h.published.calls == []


# ---------------------------------------------------------------------------
# Manual zone
# ---------------------------------------------------------------------------


class TestManualZone:
    @pytest.mark.parametrize("status", [TicketStatus.IGNORED, TicketStatus.DUPLICATED])
    async def test_manual_zone_receives_severity_and_priority_only(
        self,
        h: RecalculationHarness,
        reconcile: CallCounter,
        status: TicketStatus,
    ) -> None:
        """No Product propagation, sanitation, reconciliation, manual-zone
        exit, or convergence registration, although the tree would resolve
        and the assignee is inactive."""
        assignee = await h.world.analyst(active=False)
        cve, ticket = await _stale(
            h, status, PackageStatus.NOT_AFFECTED, assignee=assignee
        )
        task_id = await h.admit()

        with capture_events() as logs:
            await h.run(task_id)

        assert runner_events(logs) == completed_run(task_id, cve.id, changed=1)
        assert await _severity(h, cve) == "Critical"
        assert await _events(h, ticket) == [
            severity_event("Medium", "Critical"),
            priority_event("P4", "P2"),
        ]
        assert await _state(h, ticket) == (status, assignee.id, "P2", None, None)
        assert await _eligibility(h, ticket) == [(False, False)]
        assert reconcile.calls == []
        assert h.published.calls == []


# ---------------------------------------------------------------------------
# Overrides
# ---------------------------------------------------------------------------


class TestOverrides:
    async def test_manual_eligibility_overrides_are_preserved(
        self, h: RecalculationHarness
    ) -> None:
        """Two overridden occurrences whose automatic value would flip keep
        both fields and create no event; only the automatic sibling
        changes."""
        cve, ticket = await _stale(
            h,
            TicketStatus.ANALYSIS,
            PackageStatus.AFFECTED,
            products=(
                Prod(eligible=False, override=True, threshold=T9),
                Prod(eligible=True, override=True, threshold=T99),
                Prod(eligible=False, threshold=T9),
            ),
        )
        task_id = await h.admit()

        with capture_events() as logs:
            await h.run(task_id)

        assert runner_events(logs) == completed_run(task_id, cve.id, changed=1)
        assert await _eligibility(h, ticket) == [
            (False, True),
            (True, True),
            (True, False),
        ]
        detail = await _subjects(h, ticket)
        assert await _events(h, ticket) == [
            severity_event("Medium", "Critical"),
            product_event(detail[2], False, True),
            priority_event("P4", "P2"),
            status_event(TicketStatus.ANALYSIS, TicketStatus.ANALYZED),
        ]


# ---------------------------------------------------------------------------
# Whole population: no side effect, idempotent rerun
# ---------------------------------------------------------------------------


class TestPopulation:
    async def test_every_state_without_side_effects_then_an_unchanged_rerun(
        self, h: RecalculationHarness
    ) -> None:
        """One CVE per state of the matrix, every Ticket unassigned. The run
        mutates no assessment, assigns nobody, exits no manual zone, and
        applies no remediation (package-tree state other than automatic
        `eligible` is unchanged); every event belongs to the chain row. A
        second complete run classifies every unit `unchanged`, adds no
        event, and publishes nothing new."""
        ticketless = await h.world.scored_cve(
            SUSE_31_CRITICAL, severity=Severity.MEDIUM
        )
        population = [
            await _stale(h, status, track_status)
            for status, track_status in (
                (TicketStatus.NEW, PackageStatus.NOT_AFFECTED),
                (TicketStatus.ANALYSIS, PackageStatus.AFFECTED),
                (TicketStatus.ANALYZED, PackageStatus.NOT_AFFECTED),
                (TicketStatus.RESOLVED, PackageStatus.FIXED),
                (TicketStatus.IGNORED, PackageStatus.NOT_AFFECTED),
                (TicketStatus.DUPLICATED, PackageStatus.NOT_AFFECTED),
            )
        ]
        cves = [ticketless, *(cve for cve, _ in population)]
        tickets = [ticket for _, ticket in population]
        watermark = max(cve.id for cve in cves)
        assessments = [await _assessments(h, cve) for cve in cves]
        packages = [await _package_state(h, ticket) for ticket in tickets]
        first = await h.admit()

        with capture_events() as logs:
            await h.run(first)

        assert runner_events(logs) == completed_run(first, watermark, changed=7)
        statuses = [(await _state(h, ticket))[0] for ticket in tickets]
        assert statuses == [
            TicketStatus.NEW,
            TicketStatus.ANALYZED,
            TicketStatus.RESOLVED,
            TicketStatus.ANALYZED,
            TicketStatus.IGNORED,
            TicketStatus.DUPLICATED,
        ]
        assert [(await _state(h, ticket))[1] for ticket in tickets] == [None] * 6
        events = [await _events(h, ticket) for ticket in tickets]
        assert {e.event_type for per in events for e in per} <= CHAIN_EVENT_TYPES
        assert all(e.user_id is None for per in events for e in per)
        resolved = tickets[3]
        assert h.published.calls == [str(resolved.id)]

        rerun = await h.admit()
        with capture_events() as logs:
            await h.run(rerun)

        assert runner_events(logs) == completed_run(rerun, watermark, unchanged=7)
        assert [await _events(h, ticket) for ticket in tickets] == events
        assert [(await _state(h, ticket))[0] for ticket in tickets] == statuses
        assert h.published.calls == [str(resolved.id)]
        assert [await _assessments(h, cve) for cve in cves] == assessments
        assert [await _package_state(h, ticket) for ticket in tickets] == packages


# ---------------------------------------------------------------------------
# ticket-priority.md Testing Requirement 8 at runner level
# ---------------------------------------------------------------------------


class TestPriorityOnlyUnits:
    @pytest.mark.parametrize("status", list(TicketStatus))
    async def test_priority_auto_only_units_count_changed(
        self, h: RecalculationHarness, status: TicketStatus
    ) -> None:
        """A KEV entry added out of band is the only changed input of two
        otherwise converged units (`High` from SUSE 7.5, `P3`): `P1` for
        both. The effective change emits one system `priority_changed`;
        the change masked by the `P2` override persists `priority_auto`
        without an event. Both units count `changed`; the converged
        ticketless unit counts `unchanged`."""
        effective = await h.world.scored_cve(SUSE_31_HIGH, severity=Severity.HIGH)
        masked = await h.world.scored_cve(SUSE_31_HIGH, severity=Severity.HIGH)
        converged = await h.world.scored_cve(SUSE_31_HIGH, severity=Severity.HIGH)
        for cve in (effective, masked):
            await _kev(h, cve)
        effective_ticket = await _ticket(h, effective, status, priority_auto="P3")
        masked_ticket = await _ticket(
            h, masked, status, priority_auto="P3", priority_override="P2"
        )
        task_id = await h.admit()

        with capture_events() as logs:
            await h.run(task_id)

        assert runner_events(logs) == completed_run(
            task_id, converged.id, changed=2, unchanged=1
        )
        assert await _events(h, effective_ticket) == [priority_event("P3", "P1")]
        assert await _events(h, masked_ticket) == []
        assert await _state(h, effective_ticket) == (status, None, "P1", None, None)
        assert await _state(h, masked_ticket) == (status, None, "P1", "P2", None)
        assert [await _severity(h, cve) for cve in (effective, masked, converged)] == [
            "High"
        ] * 3
        assert h.published.calls == []
