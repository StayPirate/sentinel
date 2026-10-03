"""Independent-session tests for
`package_service.reconcile_lifecycle_actionability_for_ticket()`
(backend/app/services/package_service.py).

Owning specifications:

- docs/features/packages/package-service.md
  (`reconcile_lifecycle_actionability_for_ticket()`: step 1, the Ticket
  `FOR UPDATE` as the first database operation; Concurrency Control;
  `soft_delete_ticket_package_track()`).
- docs/features/packages/product-lifecycle-transitions.md (Algorithm step
  5: a concurrent mutation is serialized by the Ticket row lock and the
  service reevaluates current persisted state after acquiring it).
- docs/features/tickets/ticket-mutations.md (Concurrency Control;
  Transaction-Local Ticket Convergence Registration step 3: the effects of
  an ended transaction are discarded; consumption does not exist yet).
- docs/features/tickets/ticket-audit-log.md (Testing Requirement 23: every
  event uses the true locked pre-state).
- docs/features/platform/testing-strategy.md (Concurrency Testing,
  Lock-Wait Observation; Service Functions: lock serialization).

The single-session behavior is covered by
`tests/test_services/test_reconcile_lifecycle_actionability.py`; this
module adds only what needs independent sessions: the lifecycle
reconciliation racing a track exclusion in both orders.

Every race serializes a winner that keeps its Ticket lock in an open
transaction and a waiter proven blocked on that lock (`assert_lock_wait`).
Each waiter first loads a stale identity-map copy of the Ticket, so its
result and its `status_change` old value must come from the reloaded
locked-current state. Each Ticket is CVE-less with `severity_manual =
High` and assigned to the acting active vulnerability analyst, so neither
auto-assignment nor assignment sanitation adds an event. A boundary
Product's General Support ends on `EVAL` (EOL from `NEXT_DAY`). Committed
rows are deleted explicitly at teardown by `CommittedWorld`. Expected
values are transcribed from the specifications, never computed with the
module under test.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable, Coroutine
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import (
    NonActionableReason,
    PackageStatus,
    Role,
    Scope,
    Severity,
    TicketStatus,
)
from app.models.product import Product
from app.models.ticket import Ticket
from app.models.ticket_package import TicketPackage
from app.models.ticket_package_product import TicketPackageProduct
from app.models.ticket_package_track import TicketPackageTrack
from app.models.user import User
from app.services.package_service import (
    LifecycleReconciliationResult,
    MarkerChangeResult,
    TrackMarkerProjection,
    reconcile_lifecycle_actionability_for_ticket,
    soft_delete_ticket_package_track,
)
from app.services.ticket_convergence_registry import (
    TicketConvergenceEffect,
    pending_ticket_convergence_effects,
)
from app.services.ticket_visibility import TicketCaller
from tests.support.database import assert_lock_wait
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

WAIT = 5
"""Upper bound, in seconds, of every wait that is expected to finish."""

NEXT_DAY = EVAL + timedelta(days=1)
"""The first EOL day of a boundary Product."""

ANALYSIS = TicketStatus.ANALYSIS
ANALYZED = TicketStatus.ANALYZED
RESOLVED = TicketStatus.RESOLVED


# ---------------------------------------------------------------------------
# Committed world
# ---------------------------------------------------------------------------


@pytest.fixture
async def world(db_session_factory: Factory) -> AsyncIterator[CommittedWorld]:
    created = CommittedWorld(db_session_factory, await db_session_factory())
    try:
        yield created
    finally:
        await created.cleanup()


@dataclass(frozen=True, slots=True)
class _Path:
    """One committed package with one track and one Product occurrence."""

    ticket_id: uuid.UUID
    package_id: uuid.UUID
    track_id: uuid.UUID
    reference: str
    package_name: str


async def _ticket(world: CommittedWorld, status: TicketStatus) -> tuple[User, Ticket]:
    """The acting active VA and a committed CVE-less `High` Ticket of
    `status` assigned to it."""
    actor = await world.user(role=Role.VULNERABILITY_ANALYST)
    ticket = await world.ticket(
        cve_id=None,
        status=status,
        assignee_id=actor.id,
        severity_manual=Severity.HIGH,
    )
    return actor, ticket


async def _path(
    world: CommittedWorld,
    ticket: Ticket,
    *,
    status: PackageStatus,
    support_end: date,
) -> _Path:
    """Commit one package with one track of `status` and one eligible
    occurrence of a catalog Product whose General Support ends on
    `support_end`."""
    session = world.session
    suffix = uuid.uuid4().hex[:10]
    package = TicketPackage(ticket_id=ticket.id, package_name=f"fictional-{suffix}")
    product = Product(
        name=f"Example Product {suffix}",
        version="1",
        display_name=f"EP {suffix}",
        cpe=f"cpe:/o:example:product:{suffix}",
        catalog_last_seen_at=datetime.now(UTC),
        general_support_end_date=support_end,
    )
    session.add_all([package, product])
    await session.flush()
    world.product_ids.append(product.id)
    track = TicketPackageTrack(
        ticket_package_id=package.id,
        workflow_type="ibs",
        reference=f"Example:Codestream:{suffix}:Update",
        status=status.value,
    )
    session.add(track)
    await session.flush()
    session.add(
        TicketPackageProduct(
            ticket_package_track_id=track.id, product_id=product.id, eligible=True
        )
    )
    await session.commit()
    return _Path(ticket.id, package.id, track.id, track.reference, package.package_name)


# ---------------------------------------------------------------------------
# Calls, expected events, and committed state
# ---------------------------------------------------------------------------


def _reconcile(
    session: AsyncSession, ticket: Ticket, evaluation_date: date
) -> Coroutine[Any, Any, LifecycleReconciliationResult]:
    """The per-Ticket unit call of the lifecycle evaluator."""
    return reconcile_lifecycle_actionability_for_ticket(
        session, ticket.id, evaluation_date
    )


def _exclude(
    session: AsyncSession, path: _Path, actor: User
) -> Coroutine[Any, Any, MarkerChangeResult[TrackMarkerProjection]]:
    """The track exclusion as the API makes it, on `EVAL`."""
    return soft_delete_ticket_package_track(
        session,
        ticket_id=path.ticket_id,
        package_id=path.package_id,
        track_id=path.track_id,
        acting_user_id=actor.id,
        caller=TicketCaller.authenticated(actor.id, Scope.ALL),
        evaluation_date=EVAL,
    )


def _result(
    previous: TicketStatus, current: TicketStatus
) -> LifecycleReconciliationResult:
    return LifecycleReconciliationResult(
        previous_status=previous,
        current_status=current,
        changed=previous is not current,
        skipped=False,
    )


def _track_excluded(path: _Path, actor: User) -> EventRow:
    """The acting-user `track_excluded` event (ticket-audit-log.md, Event
    Type Contract and detail JSONB Schema Contract)."""
    return EventRow(
        "track_excluded",
        actor.id,
        path.reference,
        None,
        None,
        {"track": path.reference, "package": path.package_name},
    )


def _sessions(spy: Spy) -> list[Any]:
    """The session argument of each `reconcile_ticket_status(ticket, db,
    ...)` call."""
    return [args[1] for args, _kwargs in spy.calls]


def _is_ticket_lock(statement: str) -> bool:
    return "FROM ticket " in statement and statement.rstrip().endswith("FOR UPDATE")


def _is_user_share(statement: str) -> bool:
    return 'FROM "user"' in statement and statement.rstrip().endswith("FOR SHARE")


async def _stale_copy(session: AsyncSession, ticket: Ticket) -> Ticket:
    """Load the waiter's identity-map copy of the Ticket before the race."""
    stale = await session.get(Ticket, ticket.id)
    assert stale is not None
    return stale


async def _committed(
    world: CommittedWorld, ticket: Ticket
) -> tuple[tuple[str, uuid.UUID | None], list[EventRow]]:
    """The committed Ticket `(status, assignee_id)` and its audit events,
    read through a fresh independent session."""
    probe = await world.open_session()
    row = (
        await probe.execute(
            select(Ticket.status, Ticket.assignee_id).where(Ticket.id == ticket.id)
        )
    ).one()
    events = await ticket_events_by_id(probe, ticket.id)
    await probe.rollback()
    return (row.status, row.assignee_id), events


# ---------------------------------------------------------------------------
# Lifecycle reconciliation racing a track exclusion
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestTrackExclusionRace:
    async def test_waiting_reconciliation_uses_the_committed_exclusion(
        self, world: CommittedWorld, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An `Analysis` Ticket with an actionable `ANALYSIS` blocker track
        and an `AFFECTED` track whose eligible boundary Product is
        actionable on `EVAL`. A excludes the blocker on `EVAL` (its own
        reconciliation reaches `Analyzed`) and keeps its transaction open.
        B, the lifecycle unit of a run on `NEXT_DAY` holding a stale
        `Analysis` copy, issues the Ticket lock as its first statement and
        is proven blocked on it. After A commits, B reconciles the
        committed state: with the blocker excluded and the boundary
        Product EOL, the Ticket resolves from the winner's `Analyzed`
        (without the exclusion it would have stayed `Analysis`)."""
        actor, ticket = await _ticket(world, ANALYSIS)
        blocker = await _path(
            world, ticket, status=PackageStatus.ANALYSIS, support_end=AFTER_EVAL
        )
        await _path(world, ticket, status=PackageStatus.AFFECTED, support_end=EVAL)
        exclusion = await world.open_session()
        lifecycle = await world.open_session()
        stale = await _stale_copy(lifecycle, ticket)
        assert stale.status == ANALYSIS
        reconcile = Spy(monkeypatch, "reconcile_ticket_status")

        await _exclude(exclusion, blocker, actor)
        with SessionStatementRecorder(lifecycle) as recorder:
            task = world.start(lifecycle, _reconcile(lifecycle, ticket, NEXT_DAY))
            await assert_lock_wait(task, waiter=lifecycle, blocked_by=exclusion)
            (statement,) = recorder.statements
            assert _is_ticket_lock(statement)
            await exclusion.commit()
            result = await asyncio.wait_for(task, timeout=WAIT)
        await lifecycle.commit()

        assert result == _result(ANALYZED, RESOLVED)
        assert stale.status == RESOLVED
        assert _sessions(reconcile) == [exclusion, lifecycle]
        assert await _committed(world, ticket) == (
            (RESOLVED, actor.id),
            [
                _track_excluded(blocker, actor),
                status_event(ANALYSIS.value, ANALYZED.value),
                status_event(ANALYZED.value, RESOLVED.value),
            ],
        )

    async def test_waiting_exclusion_uses_the_committed_reconciliation(
        self, world: CommittedWorld, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A `Resolved` Ticket with a final "pin" track and an `AFFECTED`
        track whose eligible Product has left EOL. A, the lifecycle unit on
        `EVAL`, regresses the Ticket to `Analyzed`, registers one
        convergence effect, and keeps its transaction open. B excludes the
        `AFFECTED` track while holding a stale `Resolved` copy: it takes
        its acting User `FOR SHARE` and is proven blocked on the Ticket
        lock. After A commits, A's effect is discarded (no consumer
        exists yet) and B's reconciliation resolves the Ticket from the
        winner's `Analyzed`, never from the stale `Resolved`."""
        actor, ticket = await _ticket(world, RESOLVED)
        await _path(
            world, ticket, status=PackageStatus.NOT_AFFECTED, support_end=AFTER_EVAL
        )
        target = await _path(
            world, ticket, status=PackageStatus.AFFECTED, support_end=AFTER_EVAL
        )
        lifecycle = await world.open_session()
        exclusion = await world.open_session()
        stale = await _stale_copy(exclusion, ticket)
        assert stale.status == RESOLVED
        reconcile = Spy(monkeypatch, "reconcile_ticket_status")

        result = await _reconcile(lifecycle, ticket, EVAL)
        assert pending_ticket_convergence_effects(lifecycle) == (
            TicketConvergenceEffect(ticket.id),
        )
        with SessionStatementRecorder(exclusion) as recorder:
            task = world.start(exclusion, _exclude(exclusion, target, actor))
            await assert_lock_wait(task, waiter=exclusion, blocked_by=lifecycle)
            assert _is_user_share(recorder.statements[0])
            assert _is_ticket_lock(recorder.statements[-1])
            await lifecycle.commit()
            excluded = await asyncio.wait_for(task, timeout=WAIT)
        await exclusion.commit()

        assert result == _result(RESOLVED, ANALYZED)
        assert lifecycle.info == {}
        assert pending_ticket_convergence_effects(lifecycle) == ()
        assert (excluded.target.actionable, excluded.target.non_actionable_reason) == (
            False,
            NonActionableReason.TRACK_EXCLUDED,
        )
        # The stale copy stays referenced until the waiter has decided.
        assert stale.id == ticket.id
        assert _sessions(reconcile) == [lifecycle, exclusion]
        assert await _committed(world, ticket) == (
            (RESOLVED, actor.id),
            [
                status_event(RESOLVED.value, ANALYZED.value),
                _track_excluded(target, actor),
                status_event(ANALYZED.value, RESOLVED.value),
            ],
        )
