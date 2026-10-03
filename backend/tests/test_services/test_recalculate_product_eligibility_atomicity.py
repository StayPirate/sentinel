"""Independent-session tests for
`package_service.recalculate_product_eligibility_for_ticket()`
(backend/app/services/package_service.py).

Owning specifications:

- docs/features/packages/package-service.md
  (`recalculate_product_eligibility_for_ticket()`: step 1, the Ticket
  `FOR UPDATE` as the first database operation; step 2, the manual-zone
  skip; Idempotency; `set_product_eligibility()`, "After a concurrent
  winner commits, the waiting caller determines override action and audit
  old/new values from the reloaded locked state"; Concurrency Control;
  Architectural Test Requirement: Automatic Product eligibility
  recalculation and Concurrent direct mutations).
- docs/features/tickets/ticket-service.md (`ignore_ticket`: acting User
  `FOR SHARE`, then the Ticket `FOR UPDATE`).
- docs/features/tickets/ticket-audit-log.md (Canonical Mutation and No-Event
  Matrix: "Product eligibility or override ownership change", system
  `package_service` uses the Ticket root; Testing Requirements 20 and 23).
- docs/features/platform/testing-strategy.md (Concurrency Testing,
  Lock-Wait Observation; Service Functions: lock serialization).

The single-session behavior is covered by
`tests/test_services/test_recalculate_product_eligibility.py`; this module
adds only what needs independent sessions: recalculation/recalculation,
recalculation/override set and clear in both orders, and
recalculation/`ignore_ticket()` in both orders.

Every race serializes a winner that keeps its Ticket lock in an open
transaction and a waiter proven blocked on that lock (`assert_lock_wait`).
Each waiter first loads a stale identity-map copy of the contested
occurrence, so its result must come from the reloaded locked-current state.
The world is an assigned (active VA) `Analysis` Ticket of a CVE with one
SUSE v3.1 medium assessment (4.8) and a `Medium` severity, whose
occurrences sit on `ANALYSIS` tracks: reconciliation keeps the `Analysis`
floor without sanitation, so only the raced events appear. The catalog
Product threshold is 9.0 unless a test states otherwise: 4.8 is below it,
so the automatic value is `false` (package-model.md, Axis 2: Eligibility,
rules 3-5), while each occurrence is seeded `true` as computed under an
earlier threshold. Committed rows, including the `default_cvss_version`
setting the test schema lacks, are deleted explicitly at teardown.
Expected values are transcribed from the specifications, never computed
with the module under test.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable, Coroutine
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any

import pytest
from sqlalchemy import delete, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import PackageStatus, Role, Scope, Severity, TicketStatus
from app.models.product import Product
from app.models.system_setting import SystemSetting
from app.models.ticket import Ticket
from app.models.ticket_package import TicketPackage
from app.models.ticket_package_product import TicketPackageProduct
from app.models.ticket_package_track import TicketPackageTrack
from app.models.user import User
from app.services.package_service import (
    MutationOutcome,
    ProductEligibilityRecalculationResult,
    ProductEligibilityResult,
    recalculate_product_eligibility_for_ticket,
    set_product_eligibility,
)
from app.services.ticket_service import ignore_ticket
from app.services.ticket_visibility import TicketCaller
from tests.support.cvss_chain import DEFAULT_VERSION, eligibility, ticket_state
from tests.support.database import assert_lock_wait
from tests.support.suse_cvss import V31_MEDIUM
from tests.support.suse_cvss_races import CommittedWorld, SessionStatementRecorder
from tests.support.ticket_mutations import (
    AFTER_EVAL,
    EVAL,
    EventRow,
    ticket_events_by_id,
)
from tests.support.track_status import Spy

Factory = Callable[[], Awaitable[AsyncSession]]

WAIT = 5
"""Upper bound, in seconds, of every wait that is expected to finish."""

THRESHOLD = Decimal("9.0")
"""The catalog Product threshold (see the module docstring)."""

ANALYSIS = TicketStatus.ANALYSIS.value
IGNORED = TicketStatus.IGNORED.value


# ---------------------------------------------------------------------------
# Committed world
# ---------------------------------------------------------------------------


@pytest.fixture
async def world(db_session_factory: Factory) -> AsyncIterator[CommittedWorld]:
    """A `CommittedWorld` that also owns the committed `default_cvss_version`
    setting (the test schema has none), which every recalculation reads."""
    created = CommittedWorld(db_session_factory, await db_session_factory())
    owns_setting = False
    try:
        if await created.session.get(SystemSetting, "default_cvss_version") is None:
            created.session.add(
                SystemSetting(key="default_cvss_version", value=DEFAULT_VERSION)
            )
            owns_setting = True
        await created.session.commit()
        yield created
    finally:
        await created.cleanup()
        if owns_setting:
            await created.session.execute(
                delete(SystemSetting).where(SystemSetting.key == "default_cvss_version")
            )
            await created.session.commit()


@dataclass(frozen=True, slots=True)
class _Occurrence:
    """One committed Product occurrence with its declared path and its
    event-time Product subject (ticket-audit-log.md, detail JSONB Schema
    Contract: `product_eligibility_changed`)."""

    ticket_id: uuid.UUID
    package_id: uuid.UUID
    track_id: uuid.UUID
    id: uuid.UUID
    subject: dict[str, str]


async def _ticket(world: CommittedWorld) -> tuple[User, Ticket]:
    """The assigned `Analysis` Ticket of the module docstring and its
    assignee, also the acting VA of every racing user mutation."""
    actor = await world.user(role=Role.VULNERABILITY_ANALYST)
    cve = await world.cve(V31_MEDIUM, severity=Severity.MEDIUM)
    ticket = await world.ticket(
        cve_id=cve.id, status=TicketStatus.ANALYSIS, assignee_id=actor.id
    )
    return actor, ticket


async def _product(world: CommittedWorld, threshold: Decimal = THRESHOLD) -> Product:
    """A committed catalog Product in General Support on `EVAL`."""
    suffix = uuid.uuid4().hex[:10]
    product = Product(
        name=f"Example Product {suffix}",
        version="1",
        display_name=f"EP {suffix}",
        cpe=f"cpe:/o:example:product:{suffix}",
        catalog_last_seen_at=datetime.now(UTC),
        cvss_threshold=threshold,
        general_support_end_date=AFTER_EVAL,
    )
    world.session.add(product)
    await world.session.flush()
    world.product_ids.append(product.id)
    await world.session.commit()
    return product


async def _occurrence(
    world: CommittedWorld,
    ticket: Ticket,
    product: Product,
    *,
    eligible: bool,
    override: bool = False,
    occurrence_id: uuid.UUID | None = None,
) -> _Occurrence:
    """Commit one occurrence of `product` on a fresh `ANALYSIS` track of a
    fresh package of the Ticket."""
    session = world.session
    suffix = uuid.uuid4().hex[:10]
    package = TicketPackage(ticket_id=ticket.id, package_name=f"fictional-{suffix}")
    session.add(package)
    await session.flush()
    track = TicketPackageTrack(
        ticket_package_id=package.id,
        workflow_type="ibs",
        reference=f"Example:Codestream:{suffix}:Update",
        status=PackageStatus.ANALYSIS.value,
    )
    session.add(track)
    await session.flush()
    occurrence = TicketPackageProduct(
        ticket_package_track_id=track.id,
        product_id=product.id,
        eligible=eligible,
        is_eligible_override=override,
    )
    if occurrence_id is not None:
        occurrence.id = occurrence_id
    session.add(occurrence)
    await session.commit()
    return _Occurrence(
        ticket.id,
        package.id,
        track.id,
        occurrence.id,
        {
            "track": track.reference,
            "package": package.package_name,
            "product_name": product.display_name,
            "product_cpe": product.cpe,
        },
    )


# ---------------------------------------------------------------------------
# Calls, expected events, and committed state
# ---------------------------------------------------------------------------


def _recalculate(
    session: AsyncSession, ticket: Ticket, product: Product
) -> Coroutine[Any, Any, ProductEligibilityRecalculationResult]:
    """The per-Ticket threshold sub-task call."""
    return recalculate_product_eligibility_for_ticket(
        session,
        ticket_id=ticket.id,
        catalog_product_id=product.id,
        reason="threshold",
        evaluation_date=EVAL,
    )


def _override(
    session: AsyncSession, occurrence: _Occurrence, eligible: bool | None, actor: User
) -> Coroutine[Any, Any, ProductEligibilityResult]:
    """The override set (`bool`) or clear (`None`) as the API makes it."""
    return set_product_eligibility(
        session,
        ticket_id=occurrence.ticket_id,
        package_id=occurrence.package_id,
        track_id=occurrence.track_id,
        ticket_package_product_id=occurrence.id,
        eligible=eligible,
        acting_user_id=actor.id,
        caller=TicketCaller.authenticated(actor.id, Scope.ALL),
        evaluation_date=EVAL,
    )


def _ignore(
    session: AsyncSession, ticket: Ticket, actor: User
) -> Coroutine[Any, Any, Ticket]:
    return ignore_ticket(
        session,
        ticket_id=ticket.id,
        acting_user_id=actor.id,
        caller=TicketCaller.authenticated(actor.id, Scope.ALL),
    )


def _result(
    examined: int, skipped: int, changed: int, *, manual_zone: bool = False
) -> ProductEligibilityRecalculationResult:
    return ProductEligibilityRecalculationResult(
        examined=examined,
        override_skipped=skipped,
        changed=changed,
        manual_zone_skipped=manual_zone,
    )


def _value(eligible: bool) -> str:
    return "true" if eligible else "false"


def _threshold_event(occurrence: _Occurrence, old: bool, new: bool) -> EventRow:
    """The system `product_eligibility_changed` of this boundary."""
    return EventRow(
        "product_eligibility_changed",
        None,
        _value(old),
        _value(new),
        None,
        {**occurrence.subject, "reason": "threshold"},
    )


def _override_event(
    occurrence: _Occurrence, actor: User, old: bool, new: bool, action: str
) -> EventRow:
    """The acting-user `product_eligibility_changed` with `va_override`."""
    return EventRow(
        "product_eligibility_changed",
        actor.id,
        _value(old),
        _value(new),
        None,
        {**occurrence.subject, "reason": "va_override", "override_action": action},
    )


def _ignored_event(actor: User) -> EventRow:
    """The acting-user manual-zone entry `status_change`."""
    return EventRow("status_change", actor.id, ANALYSIS, IGNORED, None, None)


def _sessions(spy: Spy) -> list[Any]:
    """The session argument of each `reconcile_ticket_status(ticket, db,
    ...)` call."""
    return [args[1] for args, _kwargs in spy.calls]


def _is_ticket_lock(statement: str) -> bool:
    return "FROM ticket " in statement and statement.rstrip().endswith("FOR UPDATE")


def _is_user_share(statement: str) -> bool:
    return 'FROM "user"' in statement and statement.rstrip().endswith("FOR SHARE")


async def _stale_copy(
    session: AsyncSession, occurrence: _Occurrence
) -> tuple[bool, bool]:
    """Load the waiter's identity-map copy of the occurrence before the race."""
    stale = await session.get(TicketPackageProduct, occurrence.id)
    assert stale is not None
    return stale.eligible, stale.is_eligible_override


@dataclass(frozen=True, slots=True)
class _Committed:
    """The committed Ticket `(status, assignee_id, priority_auto,
    priority_override, severity_manual)`, the `(eligible,
    is_eligible_override)` of its occurrences in occurrence-ID order, and
    its audit events."""

    ticket: tuple[Any, ...]
    occurrences: list[tuple[bool, bool]]
    events: list[EventRow]


async def _committed(world: CommittedWorld, ticket: Ticket) -> _Committed:
    """The committed state, read through a fresh independent session."""
    probe = await world.open_session()
    committed = _Committed(
        await ticket_state(probe, ticket.id),
        await eligibility(probe, ticket.id),
        await ticket_events_by_id(probe, ticket.id),
    )
    await probe.rollback()
    return committed


# ---------------------------------------------------------------------------
# Recalculation/recalculation (Idempotency; audit Testing Requirement 23)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestRecalculationSerialization:
    async def test_waiting_recalculation_is_a_locked_current_no_op(
        self, world: CommittedWorld, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Two sub-task deliveries for one Ticket. A changes the stale
        `true` to `false` and keeps its transaction open: nothing is
        committed yet. B, holding a stale `true` copy, issues the Ticket
        lock as its first statement and is proven blocked on it. After A
        commits, B reloads the converged occurrence: no write, no second
        event, and no reconciliation."""
        actor, ticket = await _ticket(world)
        product = await _product(world)
        occurrence = await _occurrence(world, ticket, product, eligible=True)
        a = await world.open_session()
        b = await world.open_session()
        assert await _stale_copy(b, occurrence) == (True, False)
        reconcile = Spy(monkeypatch, "reconcile_ticket_status")
        before = (ANALYSIS, actor.id, None, None, None)

        first = await _recalculate(a, ticket, product)
        # The service never commits: the change is invisible to others.
        assert await _committed(world, ticket) == _Committed(
            before, [(True, False)], []
        )
        with SessionStatementRecorder(b) as recorder:
            task = world.start(b, _recalculate(b, ticket, product))
            await assert_lock_wait(task, waiter=b, blocked_by=a)
            assert len(recorder.statements) == 1
            assert _is_ticket_lock(recorder.statements[0])
            await a.commit()
            second = await asyncio.wait_for(task, timeout=WAIT)
        await b.commit()

        assert (first, second) == (_result(1, 0, 1), _result(1, 0, 0))
        assert recorder.writes() == []
        assert _sessions(reconcile) == [a]
        assert await _committed(world, ticket) == _Committed(
            before,
            [(False, False)],
            [_threshold_event(occurrence, True, False)],
        )


# ---------------------------------------------------------------------------
# Recalculation/override (set_product_eligibility(), Idempotency paragraph;
# ATR Concurrent direct mutations; audit Testing Requirement 23)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestRecalculationAndOverride:
    async def test_waiting_override_set_uses_the_recalculated_old_value(
        self, world: CommittedWorld, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A recalculates the stale `true` to `false`. B's override `true`,
        blocked on the Ticket lock with a stale `true` copy, then records
        `set` with the winner-current old value `false`."""
        actor, ticket = await _ticket(world)
        product = await _product(world)
        occurrence = await _occurrence(world, ticket, product, eligible=True)
        a = await world.open_session()
        b = await world.open_session()
        assert await _stale_copy(b, occurrence) == (True, False)
        reconcile = Spy(monkeypatch, "reconcile_ticket_status")

        first = await _recalculate(a, ticket, product)
        with SessionStatementRecorder(b) as recorder:
            task = world.start(b, _override(b, occurrence, True, actor))
            await assert_lock_wait(task, waiter=b, blocked_by=a)
            assert _is_user_share(recorder.statements[0])
            assert _is_ticket_lock(recorder.statements[-1])
            await a.commit()
            result = await asyncio.wait_for(task, timeout=WAIT)
        await b.commit()

        assert first == _result(1, 0, 1)
        assert result.outcome is MutationOutcome.CHANGED
        assert (result.product.eligible, result.product.is_eligible_override) == (
            True,
            True,
        )
        assert _sessions(reconcile) == [a, b]
        assert await _committed(world, ticket) == _Committed(
            (ANALYSIS, actor.id, None, None, None),
            [(True, True)],
            [
                _threshold_event(occurrence, True, False),
                _override_event(occurrence, actor, False, True, "set"),
            ],
        )

    async def test_waiting_recalculation_skips_the_committed_override(
        self, world: CommittedWorld, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A sets an override `true` on the stale automatic `true` (a
        metadata-only `set`). B, blocked on the Ticket lock with the stale
        automatic copy, then observes the override: it is skipped without
        write, event, or reconciliation (package-model.md, rule 1)."""
        actor, ticket = await _ticket(world)
        product = await _product(world)
        occurrence = await _occurrence(world, ticket, product, eligible=True)
        a = await world.open_session()
        b = await world.open_session()
        assert await _stale_copy(b, occurrence) == (True, False)
        reconcile = Spy(monkeypatch, "reconcile_ticket_status")

        first = await _override(a, occurrence, True, actor)
        with SessionStatementRecorder(b) as recorder:
            task = world.start(b, _recalculate(b, ticket, product))
            await assert_lock_wait(task, waiter=b, blocked_by=a)
            assert len(recorder.statements) == 1
            assert _is_ticket_lock(recorder.statements[0])
            await a.commit()
            second = await asyncio.wait_for(task, timeout=WAIT)
        await b.commit()

        assert first.outcome is MutationOutcome.CHANGED
        assert second == _result(1, 1, 0)
        assert recorder.writes() == []
        assert _sessions(reconcile) == [a]
        assert await _committed(world, ticket) == _Committed(
            (ANALYSIS, actor.id, None, None, None),
            [(True, True)],
            [_override_event(occurrence, actor, True, True, "set")],
        )

    async def test_waiting_override_clear_recalculates_after_the_winner(
        self, world: CommittedWorld, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Two occurrences of the Product: a stale automatic `true` and an
        override `true`. A recalculates the automatic one to `false` and
        skips the override. B's clear of the override, blocked on the
        Ticket lock, then clears it to the current automatic `false` with
        the truthful old value `true`."""
        actor, ticket = await _ticket(world)
        product = await _product(world)
        low, high = sorted(uuid.uuid4() for _ in range(2))
        automatic = await _occurrence(
            world, ticket, product, eligible=True, occurrence_id=low
        )
        overridden = await _occurrence(
            world, ticket, product, eligible=True, override=True, occurrence_id=high
        )
        a = await world.open_session()
        b = await world.open_session()
        assert await _stale_copy(b, overridden) == (True, True)
        reconcile = Spy(monkeypatch, "reconcile_ticket_status")

        first = await _recalculate(a, ticket, product)
        task = world.start(b, _override(b, overridden, None, actor))
        await assert_lock_wait(task, waiter=b, blocked_by=a)
        await a.commit()
        result = await asyncio.wait_for(task, timeout=WAIT)
        await b.commit()

        assert first == _result(2, 1, 1)
        assert result.outcome is MutationOutcome.CHANGED
        assert (result.product.eligible, result.product.is_eligible_override) == (
            False,
            False,
        )
        assert _sessions(reconcile) == [a, b]
        assert await _committed(world, ticket) == _Committed(
            (ANALYSIS, actor.id, None, None, None),
            [(False, False), (False, False)],
            [
                _threshold_event(automatic, True, False),
                _override_event(overridden, actor, True, False, "cleared"),
            ],
        )

    async def test_waiting_recalculation_updates_the_cleared_occurrence(
        self, world: CommittedWorld, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An override `false` under a 4.0 threshold. A clears it, so it is
        recalculated to `true` (4.8 >= 4.0). While A holds the Ticket lock,
        the threshold synchronization commits 9.0 for the catalog Product
        (it takes no Ticket lock). B's recalculation, blocked on the Ticket
        lock with a stale override copy, then updates the now automatic
        occurrence from the current threshold with the truthful old value
        `true` (package-service.md, "Later CVSS, default-version,
        threshold, lifecycle, or Ticket convergence workflows may update
        it")."""
        actor, ticket = await _ticket(world)
        product = await _product(world, Decimal("4.0"))
        occurrence = await _occurrence(
            world, ticket, product, eligible=False, override=True
        )
        a = await world.open_session()
        b = await world.open_session()
        assert await _stale_copy(b, occurrence) == (False, True)
        reconcile = Spy(monkeypatch, "reconcile_ticket_status")

        first = await _override(a, occurrence, None, actor)
        await asyncio.wait_for(
            world.session.execute(
                update(Product)
                .where(Product.id == product.id)
                .values(cvss_threshold=THRESHOLD)
            ),
            timeout=WAIT,
        )
        await world.session.commit()
        task = world.start(b, _recalculate(b, ticket, product))
        await assert_lock_wait(task, waiter=b, blocked_by=a)
        await a.commit()
        second = await asyncio.wait_for(task, timeout=WAIT)
        await b.commit()

        assert first.outcome is MutationOutcome.CHANGED
        assert (first.product.eligible, first.product.is_eligible_override) == (
            True,
            False,
        )
        assert second == _result(1, 0, 1)
        assert _sessions(reconcile) == [a, b]
        assert await _committed(world, ticket) == _Committed(
            (ANALYSIS, actor.id, None, None, None),
            [(False, False)],
            [
                _override_event(occurrence, actor, False, True, "cleared"),
                _threshold_event(occurrence, True, False),
            ],
        )


# ---------------------------------------------------------------------------
# Recalculation/manual-zone entry (package-service.md, step 2; audit
# Testing Requirement 23)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestRecalculationAndIgnore:
    async def test_waiting_recalculation_after_a_committed_ignore_is_skipped(
        self, world: CommittedWorld, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The Ticket entered `Ignored` after candidate selection: the
        recalculation, blocked on the Ticket lock, observes the committed
        `Ignored` and returns the manual-zone skip result without
        `TicketNotMutableError`, write, event, or reconciliation. The
        stale occurrence keeps its value."""
        actor, ticket = await _ticket(world)
        product = await _product(world)
        await _occurrence(world, ticket, product, eligible=True)
        a = await world.open_session()
        b = await world.open_session()
        reconcile = Spy(monkeypatch, "reconcile_ticket_status")

        await _ignore(a, ticket, actor)
        with SessionStatementRecorder(b) as recorder:
            task = world.start(b, _recalculate(b, ticket, product))
            await assert_lock_wait(task, waiter=b, blocked_by=a)
            await a.commit()
            result = await asyncio.wait_for(task, timeout=WAIT)
        await b.commit()

        assert result == _result(0, 0, 0, manual_zone=True)
        assert len(recorder.statements) == 1
        assert _is_ticket_lock(recorder.statements[0])
        assert reconcile.calls == []
        assert await _committed(world, ticket) == _Committed(
            (IGNORED, actor.id, None, None, None),
            [(True, False)],
            [_ignored_event(actor)],
        )

    async def test_waiting_ignore_proceeds_after_a_committed_recalculation(
        self, world: CommittedWorld, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The recalculation wins and leaves the Ticket at `Analysis`; the
        ignore, which takes its acting User `FOR SHARE` and is proven
        blocked on the Ticket lock, then records `Analysis -> Ignored`
        after the committed Product event."""
        actor, ticket = await _ticket(world)
        product = await _product(world)
        occurrence = await _occurrence(world, ticket, product, eligible=True)
        a = await world.open_session()
        b = await world.open_session()
        reconcile = Spy(monkeypatch, "reconcile_ticket_status")

        first = await _recalculate(a, ticket, product)
        with SessionStatementRecorder(b) as recorder:
            task = world.start(b, _ignore(b, ticket, actor))
            await assert_lock_wait(task, waiter=b, blocked_by=a)
            assert _is_user_share(recorder.statements[0])
            assert _is_ticket_lock(recorder.statements[-1])
            await a.commit()
            ignored = await asyncio.wait_for(task, timeout=WAIT)
        await b.commit()

        assert first == _result(1, 0, 1)
        assert ignored.status == IGNORED
        assert _sessions(reconcile) == [a]
        assert await _committed(world, ticket) == _Committed(
            (IGNORED, actor.id, None, None, None),
            [(False, False)],
            [_threshold_event(occurrence, True, False), _ignored_event(actor)],
        )
