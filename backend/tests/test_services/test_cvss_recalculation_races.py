"""Concurrency and race tests of the all-CVE default-version recalculation
workflow `run_cvss_derived_state_recalculation()`
(backend/app/services/cvss_recalculation.py).

Owning specifications:

- docs/features/platform/default-cvss-version-operations.md (All-CVE
  Recalculation Runner: Concurrent-Change Semantics, Per-CVE Transactional
  Unit, Outcome Classification);
- docs/features/tickets/ticket-mutations.md (`recalculate_cvss_chain()`,
  default-version mode and Runner-facing classification; CVSS Status
  Matrix, default-version paragraph; Concurrency Control);
- docs/features/tickets/ticket-audit-log.md (Canonical Mutation and
  No-Event Matrix: Default-version severity/eligibility chain);
- docs/features/platform/testing-strategy.md (All-CVE Recalculation
  Runner: Concurrency and races; Concurrency Testing and Lock-Wait
  Observation; Audit Trail Testing).

Every race commits its data on independent connections and deletes it
explicitly (tests/support/cvss_recalculation.py). An independent holder
transaction takes the documented root of the concurrent change (the CVE
`FOR NO KEY UPDATE` and then the Ticket for CVE-rooted changes, the Ticket
alone for Ticket-rooted ones) and applies the change; the delivery is then
started, `assert_lock_wait()` proves on the fenced connection's backend PID
that its unit waits on the holder, and only then does the holder commit.
The page has already been read by then, so every assertion distinguishes
the committed winner from the page-observed state. The holder writes only
the raced input, not the derived state its real owning workflow would also
maintain, so that the unit alone derives the outcome.

Expected values are transcribed from the specifications.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import AsyncIterator
from contextlib import suppress
from decimal import Decimal
from typing import Any

import pytest
import redis.asyncio as redis_asyncio
from sqlalchemy import Update, delete, select, update
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

from app.core.enums import PackageStatus, Severity, TicketStatus
from app.models.cve import CVE
from app.models.cve_cvss_assessment import CVECVSSAssessment
from app.models.product import Product
from app.models.ticket import Ticket
from app.models.ticket_package import TicketPackage
from app.models.ticket_package_product import TicketPackageProduct
from app.models.ticket_package_track import TicketPackageTrack
from tests.support.cvss_chain import (
    Assessment,
    associate,
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
    ChainSpy,
    RecalculationHarness,
    capture_events,
    completed_run,
    recalculation_harness,
    runner_events,
)
from tests.support.database import assert_lock_wait
from tests.support.ticket_mutations import (
    REACTIVE_END,
    REACTIVE_EXTENDED_END,
    REACTIVE_GS_END,
    EventRow,
    Prod,
    status_event,
    ticket_events_by_id,
)

pytestmark = pytest.mark.integration

SUSE_31_CRITICAL = Assessment("9.8")
"""The canonical SUSE 3.1 assessment: `Critical` and eligibility score 9.8
when 3.1 is the default."""

NVD_31_MEDIUM = Assessment("5.0", provider="NVD")
"""A non-SUSE 3.1 assessment: `Medium`; eligibility falls back to 10.0."""

T9 = Decimal("9.0")
T99 = Decimal("9.9")

_RUN_TIMEOUT = 10.0


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
def chain(monkeypatch: pytest.MonkeyPatch) -> ChainSpy:
    return ChainSpy(monkeypatch)


# ---------------------------------------------------------------------------
# Holder roots, the raced delivery, and readers
# ---------------------------------------------------------------------------


async def _lock_cve(holder: AsyncSession, cve_id: uuid.UUID) -> None:
    """The CVE root `FOR NO KEY UPDATE`, as a CVSS or association writer
    takes it first."""
    await holder.execute(
        select(CVE.id).where(CVE.id == cve_id).with_for_update(key_share=True)
    )


async def _lock_ticket(holder: AsyncSession, ticket_id: uuid.UUID) -> None:
    """The Ticket root `FOR UPDATE`."""
    await holder.execute(
        select(Ticket.id).where(Ticket.id == ticket_id).with_for_update()
    )


async def _run_against(
    h: RecalculationHarness, holder: AsyncSession, task_id: str
) -> object:
    """Start the delivery, prove that its unit waits on a lock `holder`
    holds, commit `holder`, and return what the delivery returned.

    The waiter session is a non-transactional view over the fenced
    connection, used only to read its backend PID. On a failed proof the
    holder is rolled back so that the delivery can finish before the
    harness tears down."""
    waiter = AsyncSession(bind=h.connection)
    run = asyncio.create_task(h.run(task_id))
    try:
        await assert_lock_wait(run, waiter=waiter, blocked_by=holder)
        await holder.commit()
        return await asyncio.wait_for(asyncio.shield(run), timeout=_RUN_TIMEOUT)
    finally:
        if not run.done():
            await holder.rollback()
            with suppress(BaseException):
                await asyncio.wait_for(run, timeout=_RUN_TIMEOUT)
        await waiter.close()


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


async def _severity(h: RecalculationHarness, cve_id: uuid.UUID) -> str | None:
    return await h.world.read(lambda db: cve_severity(db, cve_id))


async def _occurrence_ids(h: RecalculationHarness, ticket: Ticket) -> list[uuid.UUID]:
    """The Ticket's Product occurrence IDs in ascending order."""

    async def _read(db: AsyncSession) -> list[uuid.UUID]:
        rows = await db.execute(
            select(TicketPackageProduct.id)
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
        return list(rows.scalars())

    return await h.world.read(_read)


async def _assessments(
    h: RecalculationHarness, cve_id: uuid.UUID
) -> list[tuple[str, str, Decimal]]:
    async def _read(db: AsyncSession) -> list[tuple[str, str, Decimal]]:
        rows = await db.execute(
            select(
                CVECVSSAssessment.provider_name,
                CVECVSSAssessment.cvss_version,
                CVECVSSAssessment.score,
            )
            .where(CVECVSSAssessment.cve_id == cve_id)
            .order_by(CVECVSSAssessment.provider_name)
        )
        return [(row[0], row[1], row[2]) for row in rows]

    return await h.world.read(_read)


# ---------------------------------------------------------------------------
# Concurrent CVE deletion
# ---------------------------------------------------------------------------


class TestDeletedCandidate:
    async def test_cve_deleted_by_the_lock_holder_is_skipped_without_audit(
        self, h: RecalculationHarness, chain: ChainSpy
    ) -> None:
        """The holder deletes the CVE while holding its row: the page has
        enumerated it, its unit waits on the deletion, and the locked
        lookup after the commit finds no row. The unit is `skipped` (not
        `failed`), creates no audit event, and the run continues."""
        deleted = await h.world.scored_cve(SUSE_31_CRITICAL, severity=Severity.MEDIUM)
        sibling = await h.world.scored_cve(SUSE_31_CRITICAL, severity=Severity.LOW)
        events_before = await h.world.read(total_ticket_events)
        holder = await h.world.open_session()
        await holder.execute(delete(CVE).where(CVE.id == deleted.id))
        task_id = await h.admit()

        with capture_events() as logs:
            result = await _run_against(h, holder, task_id)

        assert result is None
        assert runner_events(logs) == completed_run(
            task_id, sibling.id, changed=1, skipped=1
        )
        assert chain.cve_ids == [deleted.id, sibling.id]
        assert await h.world.cve_count() == 1
        assert await _severity(h, sibling.id) == "Critical"
        assert await h.world.read(total_ticket_events) == events_before
        assert h.published.calls == []


# ---------------------------------------------------------------------------
# Concurrent association and disassociation
# ---------------------------------------------------------------------------


class TestAssociation:
    async def test_concurrent_association_applies_the_newly_associated_ticket(
        self, h: RecalculationHarness
    ) -> None:
        """The holder associates a CVE-less `Analyzed` Ticket under the CVE
        then Ticket roots (`associate_cve()` order); the page observed a
        ticketless CVE. The unit applies the committed association:
        severity, Product, priority, and the final gate event on the new
        Ticket."""
        cve = await h.world.scored_cve(SUSE_31_CRITICAL, severity=Severity.MEDIUM)
        ticket = await h.world.ticket(
            cve_id=None,
            status=TicketStatus.ANALYZED,
            severity_manual=Severity.MEDIUM,
            priority_auto="P4",
        )
        # Eligible under the CVE-less 10.0 fallback; 9.8 is below 9.9.
        await h.world.track(
            ticket,
            status=PackageStatus.AFFECTED,
            products=(Prod(eligible=True, threshold=T99),),
        )
        holder = await h.world.open_session()
        await associate(holder, ticket, cve)
        task_id = await h.admit()

        with capture_events() as logs:
            await _run_against(h, holder, task_id)

        assert runner_events(logs) == completed_run(task_id, cve.id, changed=1)
        detail = await _subjects(h, ticket)
        assert await _events(h, ticket) == [
            severity_event("Medium", "Critical"),
            product_event(detail[0], True, False),
            priority_event("P4", "P2"),
            status_event(TicketStatus.ANALYZED, TicketStatus.RESOLVED),
        ]
        assert await _state(h, ticket) == (
            TicketStatus.RESOLVED,
            None,
            "P2",
            None,
            None,
        )
        assert await _eligibility(h, ticket) == [(False, False)]
        assert await _severity(h, cve.id) == "Critical"
        assert h.published.calls == []

    async def test_concurrent_disassociation_leaves_the_former_ticket_untouched(
        self, h: RecalculationHarness
    ) -> None:
        """The holder detaches the CVE's Ticket under the CVE then Ticket
        roots; the page observed an associated CVE. The unit finds no
        Ticket: it maintains CVE severity only and creates no event."""
        cve = await h.world.scored_cve(SUSE_31_CRITICAL, severity=Severity.MEDIUM)
        ticket = await h.world.ticket(
            cve_id=cve.id, status=TicketStatus.ANALYZED, priority_auto="P4"
        )
        await h.world.track(
            ticket,
            status=PackageStatus.AFFECTED,
            products=(Prod(eligible=False, threshold=T9),),
        )
        holder = await h.world.open_session()
        await _lock_cve(holder, cve.id)
        await _lock_ticket(holder, ticket.id)
        await holder.execute(
            update(Ticket).where(Ticket.id == ticket.id).values(cve_id=None)
        )
        task_id = await h.admit()

        with capture_events() as logs:
            await _run_against(h, holder, task_id)

        assert runner_events(logs) == completed_run(task_id, cve.id, changed=1)
        assert await _severity(h, cve.id) == "Critical"
        assert await _events(h, ticket) == []
        assert await _state(h, ticket) == (
            TicketStatus.ANALYZED,
            None,
            "P4",
            None,
            None,
        )
        assert await _eligibility(h, ticket) == [(False, False)]
        assert h.published.calls == []


# ---------------------------------------------------------------------------
# Concurrent Ticket status change
# ---------------------------------------------------------------------------


_STATUS_CHANGES = [
    pytest.param(
        TicketStatus.ANALYSIS,
        TicketStatus.IGNORED,
        [False],
        TicketStatus.IGNORED,
        id="into-the-manual-zone",
    ),
    pytest.param(
        TicketStatus.IGNORED,
        TicketStatus.ANALYSIS,
        [True],
        TicketStatus.ANALYZED,
        id="into-the-gate-zone",
    ),
]


class TestTicketStatusChange:
    @pytest.mark.parametrize(
        ("seeded", "committed", "eligible", "final"), _STATUS_CHANGES
    )
    async def test_unit_applies_the_committed_ticket_status(
        self,
        h: RecalculationHarness,
        seeded: TicketStatus,
        committed: TicketStatus,
        eligible: list[bool],
        final: TicketStatus,
    ) -> None:
        """The holder changes the status under the Ticket root; the unit
        holds the CVE and waits for the Ticket. A Ticket moved to `Ignored`
        receives severity and priority only (no Product propagation or
        reconciliation); a Ticket moved to `Analysis` receives Product
        propagation and one reconciliation. Neither direction registers a
        convergence effect: the unit is no manual-zone exit."""
        cve = await h.world.scored_cve(SUSE_31_CRITICAL, severity=Severity.MEDIUM)
        ticket = await h.world.ticket(cve_id=cve.id, status=seeded, priority_auto="P4")
        await h.world.track(
            ticket,
            status=PackageStatus.AFFECTED,
            products=(Prod(eligible=False, threshold=T9),),
        )
        holder = await h.world.open_session()
        await _lock_ticket(holder, ticket.id)
        await holder.execute(
            update(Ticket).where(Ticket.id == ticket.id).values(status=committed.value)
        )
        task_id = await h.admit()

        with capture_events() as logs:
            await _run_against(h, holder, task_id)

        assert runner_events(logs) == completed_run(task_id, cve.id, changed=1)
        detail = await _subjects(h, ticket)
        gate_zone = committed is TicketStatus.ANALYSIS
        assert await _events(h, ticket) == [
            severity_event("Medium", "Critical"),
            *([product_event(detail[0], False, True)] if gate_zone else []),
            priority_event("P4", "P2"),
            *([status_event(committed, final)] if gate_zone else []),
        ]
        assert await _state(h, ticket) == (final, None, "P2", None, None)
        assert await _eligibility(h, ticket) == [(value, False) for value in eligible]
        assert h.published.calls == []


# ---------------------------------------------------------------------------
# Concurrent CVSS assessment write
# ---------------------------------------------------------------------------


class TestAssessmentWrite:
    async def test_unit_resolves_from_the_committed_assessment_set(
        self, h: RecalculationHarness
    ) -> None:
        """The holder adds the first SUSE assessment under the CVE root, as
        `upsert_cvss_assessment()` does. Before it, the CVE, Ticket, and
        Product were converged (NVD `Medium`, 10.0 fallback eligibility,
        `P4`, `Analysis` without SUSE); the unit derives everything from the
        committed set: `Critical`, score 9.8 below threshold 9.9, `P2`, and
        `Resolved` once the SUSE gate holds and no eligible Product
        remains."""
        cve = await h.world.scored_cve(NVD_31_MEDIUM, severity=Severity.MEDIUM)
        ticket = await h.world.ticket(
            cve_id=cve.id, status=TicketStatus.ANALYSIS, priority_auto="P4"
        )
        await h.world.track(
            ticket,
            status=PackageStatus.AFFECTED,
            products=(Prod(eligible=True, threshold=T99),),
        )
        holder = await h.world.open_session()
        await _lock_cve(holder, cve.id)
        holder.add(
            CVECVSSAssessment(
                cve_id=cve.id,
                provider_name="SUSE",
                cvss_version="3.1",
                score=Decimal("9.8"),
                severity="critical",
                vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            )
        )
        await holder.flush()
        task_id = await h.admit()

        with capture_events() as logs:
            await _run_against(h, holder, task_id)

        assert runner_events(logs) == completed_run(task_id, cve.id, changed=1)
        assert await _severity(h, cve.id) == "Critical"
        detail = await _subjects(h, ticket)
        assert await _events(h, ticket) == [
            severity_event("Medium", "Critical"),
            product_event(detail[0], True, False),
            priority_event("P4", "P2"),
            status_event(TicketStatus.ANALYSIS, TicketStatus.RESOLVED),
        ]
        assert await _state(h, ticket) == (
            TicketStatus.RESOLVED,
            None,
            "P2",
            None,
            None,
        )
        assert await _eligibility(h, ticket) == [(False, False)]
        assert await _assessments(h, cve.id) == [
            ("NVD", "3.1", Decimal("5.0")),
            ("SUSE", "3.1", Decimal("9.8")),
        ]


# ---------------------------------------------------------------------------
# Concurrent override change
# ---------------------------------------------------------------------------


class TestOverrideChange:
    async def test_committed_override_is_preserved_and_skipped(
        self, h: RecalculationHarness
    ) -> None:
        """The holder pins the first occurrence `eligible = false` with an
        override under the Ticket root (the direct override's root); the
        unit holds the CVE and waits for the Ticket. Propagation skips the
        committed override without an event and still flips the automatic
        sibling, so the Ticket reconciles to `Analyzed`."""
        cve = await h.world.scored_cve(SUSE_31_CRITICAL, severity=Severity.MEDIUM)
        ticket = await h.world.ticket(
            cve_id=cve.id, status=TicketStatus.ANALYSIS, priority_auto="P4"
        )
        await h.world.track(
            ticket,
            status=PackageStatus.AFFECTED,
            products=(
                Prod(eligible=False, threshold=T9),
                Prod(eligible=False, threshold=T9),
            ),
        )
        pinned, _ = await _occurrence_ids(h, ticket)
        holder = await h.world.open_session()
        await _lock_ticket(holder, ticket.id)
        await holder.execute(
            update(TicketPackageProduct)
            .where(TicketPackageProduct.id == pinned)
            .values(is_eligible_override=True)
        )
        task_id = await h.admit()

        with capture_events() as logs:
            await _run_against(h, holder, task_id)

        assert runner_events(logs) == completed_run(task_id, cve.id, changed=1)
        assert await _eligibility(h, ticket) == [(False, True), (True, False)]
        detail = await _subjects(h, ticket)
        assert await _events(h, ticket) == [
            severity_event("Medium", "Critical"),
            product_event(detail[1], False, True),
            priority_event("P4", "P2"),
            status_event(TicketStatus.ANALYSIS, TicketStatus.ANALYZED),
        ]
        assert await _state(h, ticket) == (
            TicketStatus.ANALYZED,
            None,
            "P2",
            None,
            None,
        )


# ---------------------------------------------------------------------------
# Concurrent threshold or lifecycle change
# ---------------------------------------------------------------------------


def _product_change(change: str, product_id: uuid.UUID) -> Update:
    """A threshold raised above the 9.8 eligibility score, or lifecycle
    dates that place the Product in Reactive Support on `EVAL`."""
    statement = update(Product).where(Product.id == product_id)
    if change == "threshold":
        return statement.values(cvss_threshold=T99)
    return statement.values(
        general_support_end_date=REACTIVE_GS_END,
        extended_support_end_date=REACTIVE_EXTENDED_END,
        reactive_support_end_date=REACTIVE_END,
    )


class TestProductInputChange:
    @pytest.mark.parametrize("change", ["threshold", "lifecycle"])
    @pytest.mark.parametrize("ordering", ["ticket-lock", "after-page-before-unit"])
    async def test_eligibility_reflects_the_committed_product_input(
        self,
        h: RecalculationHarness,
        chain: ChainSpy,
        change: str,
        ordering: str,
    ) -> None:
        """Before the change everything is converged (`Critical`, score 9.8
        over threshold 9.0 in General Support, `P2`, `Analyzed`), so the
        page-observed state would classify `unchanged`. The committed
        change makes the automatic occurrence ineligible, and the one
        reconciliation resolves the `AFFECTED` track.

        The chain locks neither the `Product` row nor any other catalog
        row: it reloads thresholds and lifecycle dates after its CVE and
        Ticket roots. A threshold or lifecycle writer therefore cannot be
        serialized on a row the unit requests. `ticket-lock` commits the
        change from a transaction that also holds the Ticket root (the root
        of the package-domain recalculation that follows a catalog change),
        so `assert_lock_wait()` proves that the unit had begun its locked
        processing before the commit. `after-page-before-unit` commits the
        change with no root at all, through the chain spy's `before` hook,
        after the page read and before the unit's first lock request."""
        cve = await h.world.scored_cve(SUSE_31_CRITICAL, severity=Severity.CRITICAL)
        ticket = await h.world.ticket(
            cve_id=cve.id, status=TicketStatus.ANALYZED, priority_auto="P2"
        )
        await h.world.track(
            ticket,
            status=PackageStatus.AFFECTED,
            products=(Prod(eligible=True, threshold=T9),),
        )
        statement = _product_change(change, h.world.product_ids[-1])
        task_id = await h.admit()

        with capture_events() as logs:
            if ordering == "ticket-lock":
                holder = await h.world.open_session()
                await _lock_ticket(holder, ticket.id)
                await holder.execute(statement)
                await _run_against(h, holder, task_id)
            else:

                async def _commit_change(_index: int) -> None:
                    await h.world.session.execute(statement)
                    await h.world.session.commit()

                chain.before[0] = _commit_change
                await h.run(task_id)

        assert runner_events(logs) == completed_run(task_id, cve.id, changed=1)
        detail = await _subjects(h, ticket)
        assert await _events(h, ticket) == [
            product_event(detail[0], True, False),
            status_event(TicketStatus.ANALYZED, TicketStatus.RESOLVED),
        ]
        assert await _state(h, ticket) == (
            TicketStatus.RESOLVED,
            None,
            "P2",
            None,
            None,
        )
        assert await _eligibility(h, ticket) == [(False, False)]
        assert await _severity(h, cve.id) == "Critical"
