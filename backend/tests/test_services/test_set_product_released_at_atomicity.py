"""Independent-session tests for `set_product_released_at()`
(backend/app/services/package_service.py).

Owning specifications:

- docs/features/packages/package-service.md (`set_product_released_at()`,
  including Idempotency, Irreversibility, Product-release composition, and
  Exceptions; Concurrency Control ("Product release detection likewise
  serializes concurrent first writes under the Ticket lock");
  Architectural Test Requirement bullets "Product release composition" and
  "Concurrent direct mutations").
- docs/features/tickets/ticket-audit-log.md (Rules: `product_released` only
  for an effective NULL-to-timestamp change, none for a concurrent no-op;
  Cross-Event Ordering, Locking, and Rollback; Testing Requirement 7).
- docs/features/tickets/tickets.md (Gate: Analyzed -> Resolved, clause
  (b)).
- docs/features/platform/testing-strategy.md (Concurrency Testing and
  Lock-Wait Observation; Audit Trail Testing (rollback or retry cannot
  synthesize an event); Service Functions (lock serialization)).

The single-session behavior is covered by
`tests/test_services/test_set_product_released_at.py`; this module adds
only what needs independent sessions and committed data:

- an effective release, its one event, and the Ticket reconciliation commit
  atomically; audit, reconciliation, and database failures propagate and
  the caller's rollback leaves none of them, after which a retry commits
  exactly one event;
- a waiter proven blocked on the Ticket lock observes the committed
  winner's timestamp and returns `no_op` without a write, event, or
  reconciliation; after a rolled-back holder it releases with its own
  instant;
- a repeated sequential call after commit is a `no_op`.

Every committed Ticket is a CVE-associated `Analyzed` Ticket (CVE severity
Critical, one SUSE v3.1 assessment) with one `FIXED` track whose only
Product is eligible, in support on `EVAL`, and unreleased, so an effective
release resolves it (tickets.md, clause (b)). The service's UTC evaluation
date is pinned to `EVAL`. Committed rows are deleted explicitly at teardown
by `CommittedWorld` (testing-strategy.md, Concurrency Testing). Expected
values are transcribed from the specifications, never computed with the
module under test.
"""

from __future__ import annotations

import asyncio
import re
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable, Coroutine
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import (
    PackageStatus,
    Severity,
    TicketAuditEventType,
    TicketStatus,
)
from app.models.product import Product
from app.models.ticket import Ticket
from app.models.ticket_package import TicketPackage
from app.models.ticket_package_product import TicketPackageProduct
from app.models.ticket_package_track import TicketPackageTrack
from app.services import package_service, ticket_mutations
from app.services.package_service import (
    MutationOutcome,
    ProductReleasedResult,
    set_product_released_at,
)
from app.services.ticket_audit_log import TicketAuditLog
from app.services.ticket_convergence_registry import (
    pending_ticket_convergence_effects,
)
from tests.support.database import assert_lock_wait
from tests.support.suse_cvss import V31_CRITICAL
from tests.support.suse_cvss_races import CommittedWorld, SessionStatementRecorder
from tests.support.ticket_mutations import (
    AFTER_EVAL,
    EVAL,
    EventRow,
    status_event,
    ticket_events_by_id,
)
from tests.support.track_status import Spy

Factory = Callable[[], Awaitable[AsyncSession]]

TICKET_STATEMENT = re.compile(r"\b(?:FROM|JOIN|INTO|UPDATE) ticket\b")
WAIT = 5
"""Upper bound, in seconds, of every wait that is expected to finish."""

PACKAGE_NAME = "fictional-release-race"
ADVISORY = "SUSE-SU-2024:0815-1"
OTHER_ADVISORY = "SUSE-SU-2024:0816-1"
"""Fictional validated advisory identifiers."""

ISSUED = datetime(2024, 3, 1, 12, 0, tzinfo=UTC)
ISSUED_Z = "2024-03-01T12:00:00Z"
LATER = datetime(2024, 3, 2, 8, 30, tzinfo=UTC)
LATER_Z = "2024-03-02T08:30:00Z"

ANALYZED = TicketStatus.ANALYZED.value
RESOLVED = TicketStatus.RESOLVED.value
RESOLUTION = status_event(ANALYZED, RESOLVED)


@pytest.fixture(autouse=True)
def controlled_clock(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pin the service's one UTC evaluation date to `EVAL`."""
    monkeypatch.setattr(package_service, "_utc_today", lambda: EVAL)


@pytest.fixture
async def committed_world(db_session_factory: Factory) -> AsyncIterator[CommittedWorld]:
    world = CommittedWorld(db_session_factory, await db_session_factory())
    try:
        yield world
    finally:
        await world.cleanup()


# ---------------------------------------------------------------------------
# Committed world
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _Occurrence:
    """One committed Product occurrence with its declared path and its
    event-time Product subject (ticket-audit-log.md, detail JSONB Schema
    Contract: `product_released`)."""

    ticket_id: uuid.UUID
    package_id: uuid.UUID
    track_id: uuid.UUID
    id: uuid.UUID
    subject: dict[str, str]


async def _analyzed_ticket(world: CommittedWorld) -> tuple[Ticket, _Occurrence]:
    """Commit the module's `Analyzed` Ticket and its one unreleased
    occurrence (see the module docstring). Rows are owned by the world."""
    cve = await world.cve(V31_CRITICAL, severity=Severity.CRITICAL)
    ticket = await world.ticket(cve_id=cve.id, status=TicketStatus.ANALYZED)
    session = world.session
    package = TicketPackage(ticket_id=ticket.id, package_name=PACKAGE_NAME)
    suffix = uuid.uuid4().hex[:10]
    product = Product(
        name=f"Example Product {suffix}",
        version="1",
        display_name=f"EP {suffix}",
        cpe=f"cpe:/o:example:product:{suffix}",
        catalog_last_seen_at=datetime.now(UTC),
        general_support_end_date=AFTER_EVAL,
    )
    session.add_all([package, product])
    await session.flush()
    world.product_ids.append(product.id)
    track = TicketPackageTrack(
        ticket_package_id=package.id,
        workflow_type="ibs",
        reference=f"Example:Codestream:{suffix}:Update",
        status=PackageStatus.FIXED.value,
    )
    session.add(track)
    await session.flush()
    occurrence = TicketPackageProduct(
        ticket_package_track_id=track.id, product_id=product.id, eligible=True
    )
    session.add(occurrence)
    await session.commit()
    return ticket, _Occurrence(
        ticket.id,
        package.id,
        track.id,
        occurrence.id,
        {
            "track": track.reference,
            "package": PACKAGE_NAME,
            "product_name": product.display_name,
            "product_cpe": product.cpe,
        },
    )


# ---------------------------------------------------------------------------
# Calls, expected events, and committed state
# ---------------------------------------------------------------------------


def _release(
    session: AsyncSession,
    occurrence: _Occurrence,
    released_at: datetime = ISSUED,
    advisory_id: str = ADVISORY,
) -> Coroutine[Any, Any, ProductReleasedResult]:
    """The service call as the release detector makes it, with the explicit
    declared path, so the call issues no statement before its own lock."""
    return set_product_released_at(
        session,
        ticket_id=occurrence.ticket_id,
        package_id=occurrence.package_id,
        track_id=occurrence.track_id,
        ticket_package_product_id=occurrence.id,
        released_at=released_at,
        advisory_id=advisory_id,
    )


def _released_event(
    occurrence: _Occurrence, new_value: str = ISSUED_Z, advisory_id: str = ADVISORY
) -> EventRow:
    """The system `product_released` event of `occurrence`."""
    return EventRow(
        "product_released",
        None,
        None,
        new_value,
        None,
        {**occurrence.subject, "advisory_id": advisory_id},
    )


@dataclass(frozen=True, slots=True)
class _Committed:
    """The committed occurrence `released_at`, Ticket `(status,
    assignee_id)`, and Ticket audit events."""

    released_at: datetime | None
    ticket: tuple[str, uuid.UUID | None]
    events: list[EventRow]


async def _committed(world: CommittedWorld, occurrence: _Occurrence) -> _Committed:
    """The committed state, read through a fresh independent session."""
    probe = await world.open_session()
    released_at = (
        await probe.execute(
            select(TicketPackageProduct.released_at).where(
                TicketPackageProduct.id == occurrence.id
            )
        )
    ).scalar_one()
    row = (
        await probe.execute(
            select(Ticket.status, Ticket.assignee_id).where(
                Ticket.id == occurrence.ticket_id
            )
        )
    ).one()
    events = await ticket_events_by_id(probe, occurrence.ticket_id)
    await probe.rollback()
    return _Committed(released_at, (row.status, row.assignee_id), events)


UNRELEASED = _Committed(None, (ANALYZED, None), [])
"""The committed state of a module Ticket before any release."""


def _sessions(spy: Spy, position: int) -> list[Any]:
    """The session argument of each recorded call."""
    return [args[position] for args, _kwargs in spy.calls]


def _is_ticket_lock(statement: str) -> bool:
    return TICKET_STATEMENT.search(
        statement
    ) is not None and statement.rstrip().endswith("FOR UPDATE")


# ---------------------------------------------------------------------------
# Atomic composition and caller-owned rollback
# ---------------------------------------------------------------------------

FAILURES = ["audit", "reconcile-before", "reconcile-after", "database"]
"""`audit`: `TicketAuditLog.log_event()` raises for `product_released`
after the occurrence change. `reconcile-before`: reconciliation raises
before evaluating the gate. `reconcile-after`: reconciliation applies
`Analyzed -> Resolved` with its event, then raises. `database`: the final
flush, after reconciliation, executes a statement PostgreSQL rejects
(division by zero), so a genuine `DBAPIError` aborts the transaction
after every write reached the database."""


@pytest.mark.integration
class TestAtomicComposition:
    """package-service.md, Architectural Test Requirement: Product release
    composition (an effective release timestamp, its one service-owned
    event, and Ticket reconciliation commit atomically; local failure rolls
    back all three) and `set_product_released_at()` Exceptions;
    ticket-audit-log.md, Testing Requirement 7."""

    async def test_effective_release_commits_with_its_event_and_status(
        self, committed_world: CommittedWorld
    ) -> None:
        _ticket, occurrence = await _analyzed_ticket(committed_world)
        session = await committed_world.open_session()

        result = await _release(session, occurrence)
        await session.commit()

        assert (result.outcome, result.released_at) == (
            MutationOutcome.CHANGED,
            ISSUED,
        )
        assert await _committed(committed_world, occurrence) == _Committed(
            ISSUED, (RESOLVED, None), [_released_event(occurrence), RESOLUTION]
        )

    @pytest.mark.parametrize("failure", FAILURES)
    async def test_failure_propagates_and_the_rollback_leaves_no_effect(
        self,
        committed_world: CommittedWorld,
        monkeypatch: pytest.MonkeyPatch,
        failure: str,
    ) -> None:
        """After the caller's rollback nothing of the release is committed;
        a retry in a fresh transaction then commits exactly one event, so
        neither the failure nor the retry synthesizes a second one
        (testing-strategy.md, Audit Trail Testing)."""
        _ticket, occurrence = await _analyzed_ticket(committed_world)
        session = await committed_world.open_session()
        original_reconcile = ticket_mutations.reconcile_ticket_status
        reconciled = False

        async def reconcile(*args: Any, **kwargs: Any) -> None:
            nonlocal reconciled
            if failure == "reconcile-before":
                raise RuntimeError("injected reconciliation failure")
            await original_reconcile(*args, **kwargs)
            reconciled = True
            if failure == "reconcile-after":
                raise RuntimeError("injected reconciliation failure")

        original_log = TicketAuditLog.log_event

        async def log_event(*args: Any, **kwargs: Any) -> None:
            if kwargs["event_type"] is TicketAuditEventType.PRODUCT_RELEASED:
                raise RuntimeError("injected audit failure")
            await original_log(*args, **kwargs)

        original_flush = session.flush

        async def flush(*args: Any, **kwargs: Any) -> None:
            if reconciled:
                await session.execute(text("SELECT 1 / 0"))
            await original_flush(*args, **kwargs)

        monkeypatch.setattr(package_service, "reconcile_ticket_status", reconcile)
        if failure == "audit":
            # The class object `package_service` references by name.
            monkeypatch.setattr(TicketAuditLog, "log_event", log_event)
        elif failure == "database":
            monkeypatch.setattr(session, "flush", flush)
        expected_error: type[Exception] = (
            DBAPIError if failure == "database" else RuntimeError
        )

        with pytest.raises(expected_error):
            await _release(session, occurrence)
        if failure in ("reconcile-after", "database"):
            assert reconciled is True
        await session.rollback()
        monkeypatch.undo()
        monkeypatch.setattr(package_service, "_utc_today", lambda: EVAL)

        assert await _committed(committed_world, occurrence) == UNRELEASED

        retry = await committed_world.open_session()
        result = await _release(retry, occurrence)
        await retry.commit()

        assert result.outcome is MutationOutcome.CHANGED
        assert await _committed(committed_world, occurrence) == _Committed(
            ISSUED, (RESOLVED, None), [_released_event(occurrence), RESOLUTION]
        )


# ---------------------------------------------------------------------------
# Concurrent and repeated release (package-service.md, Concurrency Control)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestConcurrentRelease:
    """package-service.md, Concurrency Control and `set_product_released_at()`
    Q5 and Product-release composition: concurrent first writes serialize
    on the Ticket lock; a later caller observes the first committed value
    as an irreversible `no_op` and does not replace it, reconcile, or
    create another event. The system call takes no lock other than the
    Ticket `FOR UPDATE` as its first statement; the waiter holds a stale
    identity-map copy of the unreleased occurrence."""

    async def test_waiter_observes_the_committed_winner_as_a_no_op(
        self, committed_world: CommittedWorld, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _ticket, occurrence = await _analyzed_ticket(committed_world)
        winner = await committed_world.open_session()
        waiter = await committed_world.open_session()
        stale = await waiter.get(TicketPackageProduct, occurrence.id)
        assert stale is not None
        assert stale.released_at is None
        assign = Spy(monkeypatch, "auto_assign_actor")
        reconcile = Spy(monkeypatch, "reconcile_ticket_status")

        first = await _release(winner, occurrence, ISSUED)
        with SessionStatementRecorder(waiter) as recorder:
            task = committed_world.start(
                waiter, _release(waiter, occurrence, LATER, OTHER_ADVISORY)
            )
            await assert_lock_wait(task, waiter=waiter, blocked_by=winner)
            assert len(recorder.statements) == 1
            assert _is_ticket_lock(recorder.statements[0])
            await winner.commit()
            result = await asyncio.wait_for(task, timeout=WAIT)

        assert first.outcome is MutationOutcome.CHANGED
        assert (result.outcome, result.ticket_package_product_id) == (
            MutationOutcome.NO_OP,
            occurrence.id,
        )
        assert result.released_at == ISSUED
        assert recorder.writes() == []
        assert assign.calls == []
        # `reconcile_ticket_status(ticket, db, ...)`.
        assert _sessions(reconcile, 1) == [winner]
        assert pending_ticket_convergence_effects(waiter) == ()
        await waiter.commit()
        assert await _committed(committed_world, occurrence) == _Committed(
            ISSUED, (RESOLVED, None), [_released_event(occurrence), RESOLUTION]
        )

    async def test_waiter_after_a_rolled_back_holder_releases_its_own_instant(
        self, committed_world: CommittedWorld, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The holder's uncommitted release is rolled back, so the waiter
        reloads an unreleased occurrence under the lock and performs the
        one effective release with its own instant and advisory."""
        _ticket, occurrence = await _analyzed_ticket(committed_world)
        holder = await committed_world.open_session()
        waiter = await committed_world.open_session()
        reconcile = Spy(monkeypatch, "reconcile_ticket_status")

        await _release(holder, occurrence, ISSUED)
        task = committed_world.start(
            waiter, _release(waiter, occurrence, LATER, OTHER_ADVISORY)
        )
        await assert_lock_wait(task, waiter=waiter, blocked_by=holder)
        await holder.rollback()
        result = await asyncio.wait_for(task, timeout=WAIT)
        await waiter.commit()

        assert (result.outcome, result.released_at) == (MutationOutcome.CHANGED, LATER)
        assert _sessions(reconcile, 1) == [holder, waiter]
        assert await _committed(committed_world, occurrence) == _Committed(
            LATER,
            (RESOLVED, None),
            [_released_event(occurrence, LATER_Z, OTHER_ADVISORY), RESOLUTION],
        )

    async def test_repeated_call_after_commit_is_a_no_op(
        self, committed_world: CommittedWorld, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _ticket, occurrence = await _analyzed_ticket(committed_world)
        first_session = await committed_world.open_session()
        await _release(first_session, occurrence, ISSUED)
        await first_session.commit()
        reconcile = Spy(monkeypatch, "reconcile_ticket_status")
        second_session = await committed_world.open_session()

        with SessionStatementRecorder(second_session) as recorder:
            result = await _release(
                second_session, occurrence, ISSUED - timedelta(days=1), OTHER_ADVISORY
            )
        await second_session.commit()

        assert (result.outcome, result.released_at) == (MutationOutcome.NO_OP, ISSUED)
        assert recorder.writes() == []
        assert reconcile.calls == []
        assert await _committed(committed_world, occurrence) == _Committed(
            ISSUED, (RESOLVED, None), [_released_event(occurrence), RESOLUTION]
        )
