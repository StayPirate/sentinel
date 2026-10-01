"""Independent-session tests for `set_track_status()`
(backend/app/services/package_service.py).

Owning specifications:

- docs/features/packages/package-service.md (`set_track_status()`;
  Concurrency Control; Architectural Test Requirement bullets "Atomic
  consumer accessibility", mutation part, and "Concurrent direct
  mutations", track-status part).
- docs/features/tickets/ticket-audit-log.md (Testing Requirement 23).
- docs/features/identity/rbac.md (Scope; Scope and Confidential Ticket
  Visibility).
- docs/features/platform/testing-strategy.md (Concurrency Testing; Ticket
  Accessibility: Locked mutations).
- docs/conventions.md (Transaction and Locking: Cross-Domain Root Lock
  Order).

The single-session behavior of `set_track_status()` is covered by
`tests/test_services/test_set_track_status.py` and
`tests/test_services/test_set_track_status_scope.py`; this module adds only
what needs independent sessions:

- locked-current accessibility races for a `non_confidential` caller,
  including otherwise-no-op, wrong-package, and `Ignored` requests;
- same-track winner/loser serialization with truthful audit old values and
  a single auto-assignment;
- a same-target waiter that is a true no-op;
- a system `FIXED` waiter that observes a user-committed final state;
- the acting-User `FOR SHARE` lock preceding the Ticket lock, and the
  system form taking no User lock.

Every race serializes a winner that keeps its locks in an open transaction
and a waiter proven blocked (`assert_lock_wait`) on a named lock. The
identity lifecycle writer is simulated by its documented `FOR NO KEY
UPDATE` lock on the User row. Committed rows are deleted explicitly at
teardown by `CommittedWorld` (testing-strategy.md, Concurrency Testing).
Expected values are transcribed from the specifications, never computed
with the module under test.
"""

from __future__ import annotations

import asyncio
import re
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import pytest
from sqlalchemy import Select, select, update
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import PackageStatus, Role, Scope, Severity, TicketStatus
from app.core.exceptions import TicketNotFoundError
from app.core.identifiers import format_ticket_id
from app.models.product import Product
from app.models.ticket import Ticket
from app.models.ticket_package import TicketPackage
from app.models.ticket_package_product import TicketPackageProduct
from app.models.ticket_package_track import TicketPackageTrack
from app.models.user import User
from app.services.package_service import MutationOutcome, TrackStatusResult
from app.services.ticket_convergence_registry import (
    pending_ticket_convergence_effects,
)
from app.services.ticket_service import resolve_ticket_locator
from app.services.ticket_visibility import TicketCaller
from tests.support.database import assert_lock_wait
from tests.support.suse_cvss_races import (
    CommittedWorld,
    SessionStatementRecorder,
    prepare_loss,
)
from tests.support.ticket_mutations import (
    AFTER_EVAL,
    EventRow,
    status_event,
    ticket_events_by_id,
)
from tests.support.track_status import Spy, set_status

Factory = Callable[[], Awaitable[AsyncSession]]

TICKET_STATEMENT = re.compile(r"\b(?:FROM|JOIN|INTO|UPDATE) ticket\b")
USER_STATEMENT = re.compile(r'\b(?:FROM|JOIN|UPDATE) "user"')
WAIT = 5
PACKAGE_NAME = "fictional-track-race"


@pytest.fixture
async def committed_world(db_session_factory: Factory) -> AsyncIterator[CommittedWorld]:
    world = CommittedWorld(db_session_factory, await db_session_factory())
    try:
        yield world
    finally:
        await world.cleanup()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _Committed:
    """The committed track status, Ticket `(status, assignee_id)`, and
    Ticket audit events."""

    track_status: str
    ticket: tuple[str, uuid.UUID | None]
    events: list[EventRow]


async def _add_track(
    world: CommittedWorld,
    ticket: Ticket,
    *,
    status: PackageStatus = PackageStatus.ANALYSIS,
) -> TicketPackageTrack:
    """Commit one track with one eligible in-support Product occurrence
    under the Ticket's existing package, or under a new `PACKAGE_NAME`
    package when the Ticket has none. Rows are owned by the world."""
    session = world.session
    package_id = (
        await session.execute(
            select(TicketPackage.id).where(TicketPackage.ticket_id == ticket.id)
        )
    ).scalar_one_or_none()
    if package_id is None:
        package = TicketPackage(ticket_id=ticket.id, package_name=PACKAGE_NAME)
        session.add(package)
        await session.flush()
        package_id = package.id
    suffix = uuid.uuid4().hex[:10]
    product = Product(
        name=f"Example Product {suffix}",
        version="1",
        display_name=f"EP {suffix}",
        cpe=f"cpe:/o:example:product:{suffix}",
        catalog_last_seen_at=datetime.now(UTC),
        general_support_end_date=AFTER_EVAL,
    )
    track = TicketPackageTrack(
        ticket_package_id=package_id,
        workflow_type="ibs",
        reference=f"Example:Codestream:{suffix}:Update",
        status=status.value,
    )
    session.add_all([product, track])
    await session.flush()
    world.product_ids.append(product.id)
    session.add(
        TicketPackageProduct(
            ticket_package_track_id=track.id, product_id=product.id, eligible=True
        )
    )
    await session.commit()
    return track


async def _open_ticket(
    world: CommittedWorld, *, assignee: User | None = None
) -> tuple[Ticket, TicketPackageTrack]:
    """A committed CVE-less `High` `Analysis` Ticket with one `ANALYSIS`
    track and one eligible in-support Product: its gate result follows the
    track status (tickets.md gates; `AFFECTED` gives `Analyzed`, a final
    status gives `Resolved`)."""
    ticket = await world.ticket(
        cve_id=None,
        severity_manual=Severity.HIGH,
        assignee_id=assignee.id if assignee else None,
    )
    return ticket, await _add_track(world, ticket)


def _track_event(
    track: TicketPackageTrack,
    actor: User | None,
    old: PackageStatus,
    new: PackageStatus,
) -> EventRow:
    """The `track_status_changed` event of a `PACKAGE_NAME` track."""
    return EventRow(
        "track_status_changed",
        actor.id if actor else None,
        old.value,
        new.value,
        None,
        {"track": track.reference, "package": PACKAGE_NAME},
    )


def _assignment(actor: User) -> EventRow:
    """The acting-user auto-assignment of an unassigned Ticket."""
    return EventRow("assignment", actor.id, None, actor.username, None, None)


def _gate(old: TicketStatus, new: TicketStatus) -> EventRow:
    return status_event(old.value, new.value)


def _start(
    world: CommittedWorld,
    session: AsyncSession,
    track: TicketPackageTrack,
    target: PackageStatus,
    actor: User | None,
    *,
    ticket: Ticket,
    package_id: uuid.UUID | None = None,
    scope: Scope = Scope.ALL,
) -> asyncio.Task[TrackStatusResult]:
    """A `set_track_status()` in `session` (system when `actor` is `None`),
    tracked by the world. The Ticket locator is explicit, so the call
    issues no statement before its own locks."""
    return world.start(
        session,
        set_status(
            session,
            track,
            target,
            actor,
            ticket_id=ticket.id,
            package_id=package_id,
            scope=scope,
        ),
    )


def _sessions(spy: Spy, position: int) -> list[Any]:
    """The session argument of each recorded call."""
    return [args[position] for args, _kwargs in spy.calls]


def _is_user_share(statement: str) -> bool:
    return USER_STATEMENT.search(statement) is not None and statement.rstrip().endswith(
        "FOR SHARE"
    )


def _is_ticket_lock(statement: str) -> bool:
    return TICKET_STATEMENT.search(
        statement
    ) is not None and statement.rstrip().endswith("FOR UPDATE")


async def _is_locked(probe: AsyncSession, statement: Select[Any]) -> bool:
    """Whether another transaction holds a conflicting lock on the row that
    `statement` selects (`FOR UPDATE NOWAIT`, released at once)."""
    try:
        await probe.execute(statement.with_for_update(nowait=True))
    except DBAPIError:
        await probe.rollback()
        return True
    await probe.rollback()
    return False


async def _committed(
    world: CommittedWorld, ticket: Ticket, track: TicketPackageTrack
) -> _Committed:
    """The committed state of a Ticket and one of its tracks, read through
    a fresh independent session."""
    probe = await world.open_session()
    track_status = (
        await probe.execute(
            select(TicketPackageTrack.status).where(TicketPackageTrack.id == track.id)
        )
    ).scalar_one()
    row = (
        await probe.execute(
            select(Ticket.status, Ticket.assignee_id).where(Ticket.id == ticket.id)
        )
    ).one()
    events = await ticket_events_by_id(probe, ticket.id)
    await probe.rollback()
    return _Committed(track_status, (row.status, row.assignee_id), events)


async def _hold_user(session: AsyncSession, user: User) -> None:
    """A simulated identity lifecycle writer's `FOR NO KEY UPDATE` lock on
    the User row (the lock of deactivation and role-origin removal)."""
    await session.execute(
        select(User.id).where(User.id == user.id).with_for_update(key_share=True)
    )


# ---------------------------------------------------------------------------
# Atomic consumer accessibility (mutation part): locked-current state
# ---------------------------------------------------------------------------


LOSSES = ["confidentiality-set", "grant-revoked", "last-package-excluded"]
"""The Ticket-scoped visibility losses of testing-strategy.md, Locked
mutations. `association-changed` is a CVE-path loss: this operation is
Ticket-scoped and the Ticket predicate does not depend on its CVE."""

REQUESTS = ["effective", "no-op", "wrong-package", "ignored"]
"""`effective`: `ANALYSIS -> AFFECTED`; `no-op`: `ANALYSIS -> ANALYSIS`;
`wrong-package`: an effective target under a nonexistent package;
`ignored`: B also makes the Ticket `Ignored` with the visibility loss."""


@pytest.mark.integration
class TestLockedCurrentAccessibilityRaces:
    """A `restricted_analyst` caller with effective scope `non_confidential`
    passes the preliminary locator check through exactly one visibility
    path. Session B then holds the Ticket `FOR UPDATE` and removes that
    path. A takes its acting User `FOR SHARE`, is proven blocked on the
    Ticket lock, B commits, and A must raise `TicketNotFoundError` from the
    locked-current state with zero side effects. No-op, nested-ownership,
    and operability decisions never precede the denial (testing-strategy.md,
    Ticket Accessibility: Locked mutations; package-service.md,
    `set_track_status()` steps 2-4 and 7)."""

    @pytest.mark.parametrize("request_kind", REQUESTS)
    @pytest.mark.parametrize("loss", LOSSES)
    async def test_visibility_lost_while_waiting_for_the_lock_is_not_found(
        self,
        committed_world: CommittedWorld,
        monkeypatch: pytest.MonkeyPatch,
        loss: str,
        request_kind: str,
    ) -> None:
        user, _cve, ticket, statements = await prepare_loss(committed_world, loss)
        # Under the maintained package for `last-package-excluded`: an
        # excluded track remains mutable, so only the denial can stop it.
        track = await _add_track(committed_world, ticket)
        target = (
            PackageStatus.ANALYSIS
            if request_kind == "no-op"
            else PackageStatus.AFFECTED
        )
        package_id = uuid.uuid7() if request_kind == "wrong-package" else None
        final_status = TicketStatus.ANALYSIS
        if request_kind == "ignored":
            final_status = TicketStatus.IGNORED
            statements.append(
                update(Ticket)
                .where(Ticket.id == ticket.id)
                .values(status=TicketStatus.IGNORED.value)
            )
        a = await committed_world.open_session()
        b = await committed_world.open_session()
        caller = TicketCaller.authenticated(user.id, Scope.NON_CONFIDENTIAL)
        assign = Spy(monkeypatch, "auto_assign_actor")
        reconcile = Spy(monkeypatch, "reconcile_ticket_status")

        resolved = await resolve_ticket_locator(
            a, format_ticket_id(ticket.sequence_id), caller
        )
        assert resolved.id == ticket.id
        for statement in statements:
            await b.execute(statement)
        with SessionStatementRecorder(a) as recorder:
            task = _start(
                committed_world,
                a,
                track,
                target,
                user,
                ticket=ticket,
                package_id=package_id,
                scope=Scope.NON_CONFIDENTIAL,
            )
            await assert_lock_wait(task, waiter=a, blocked_by=b)
            assert _is_user_share(recorder.statements[0])
            assert _is_ticket_lock(recorder.statements[-1])
            await b.commit()
            with pytest.raises(TicketNotFoundError):
                await asyncio.wait_for(task, timeout=WAIT)

        assert recorder.writes() == []
        assert (assign.calls, reconcile.calls) == ([], [])
        assert pending_ticket_convergence_effects(a) == ()
        await a.rollback()
        assert await _committed(committed_world, ticket, track) == _Committed(
            PackageStatus.ANALYSIS.value, (final_status.value, None), []
        )


# ---------------------------------------------------------------------------
# Concurrent direct mutations (track-status part; audit Testing Requirement 23)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestSameTrackSerialization:
    """Two active VAs change the same track of an unassigned Ticket. The
    winner holds the Ticket lock uncommitted; the waiter holds its acting
    User `FOR SHARE` and a stale identity-map copy of the track, and is
    proven blocked on the Ticket lock. After the winner commits, the waiter
    decides from the winner-committed state (package-service.md,
    Concurrency Control and `set_track_status()` steps 7 and 9-10)."""

    async def test_waiter_uses_the_committed_winner_value_as_old_value(
        self, committed_world: CommittedWorld
    ) -> None:
        winner_actor = await committed_world.user(role=Role.VULNERABILITY_ANALYST)
        waiter_actor = await committed_world.user(role=Role.VULNERABILITY_ANALYST)
        ticket, track = await _open_ticket(committed_world)
        winner = await committed_world.open_session()
        waiter = await committed_world.open_session()
        stale = await waiter.get(TicketPackageTrack, track.id)
        assert stale is not None
        assert stale.status == PackageStatus.ANALYSIS.value

        await set_status(winner, track, PackageStatus.AFFECTED, winner_actor)
        with SessionStatementRecorder(waiter) as recorder:
            task = _start(
                committed_world,
                waiter,
                track,
                PackageStatus.NOT_AFFECTED,
                waiter_actor,
                ticket=ticket,
            )
            await assert_lock_wait(task, waiter=waiter, blocked_by=winner)
            assert _is_user_share(recorder.statements[0])
            assert _is_ticket_lock(recorder.statements[-1])
            await winner.commit()
            result = await asyncio.wait_for(task, timeout=WAIT)
        await waiter.commit()

        assert result.outcome is MutationOutcome.CHANGED
        assert result.track.status is PackageStatus.NOT_AFFECTED
        # The waiter observes the winner's assignee and does not reassign.
        assert await _committed(committed_world, ticket, track) == _Committed(
            PackageStatus.NOT_AFFECTED.value,
            (TicketStatus.RESOLVED.value, winner_actor.id),
            [
                _assignment(winner_actor),
                _track_event(
                    track, winner_actor, PackageStatus.ANALYSIS, PackageStatus.AFFECTED
                ),
                _gate(TicketStatus.ANALYSIS, TicketStatus.ANALYZED),
                _track_event(
                    track,
                    waiter_actor,
                    PackageStatus.AFFECTED,
                    PackageStatus.NOT_AFFECTED,
                ),
                _gate(TicketStatus.ANALYZED, TicketStatus.RESOLVED),
            ],
        )

    async def test_same_target_waiter_is_a_no_op(
        self, committed_world: CommittedWorld, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        winner_actor = await committed_world.user(role=Role.VULNERABILITY_ANALYST)
        waiter_actor = await committed_world.user(role=Role.VULNERABILITY_ANALYST)
        ticket, track = await _open_ticket(committed_world)
        winner = await committed_world.open_session()
        waiter = await committed_world.open_session()
        stale = await waiter.get(TicketPackageTrack, track.id)
        assert stale is not None
        assert stale.status == PackageStatus.ANALYSIS.value
        assign = Spy(monkeypatch, "auto_assign_actor")
        reconcile = Spy(monkeypatch, "reconcile_ticket_status")

        await set_status(winner, track, PackageStatus.AFFECTED, winner_actor)
        with SessionStatementRecorder(waiter) as recorder:
            task = _start(
                committed_world,
                waiter,
                track,
                PackageStatus.AFFECTED,
                waiter_actor,
                ticket=ticket,
            )
            await assert_lock_wait(task, waiter=waiter, blocked_by=winner)
            assert _is_ticket_lock(recorder.statements[-1])
            await winner.commit()
            result = await asyncio.wait_for(task, timeout=WAIT)

        assert result.outcome is MutationOutcome.NO_OP
        assert result.track.status is PackageStatus.AFFECTED
        assert recorder.writes() == []
        # `auto_assign_actor(ticket, acting_user, db)`,
        # `reconcile_ticket_status(ticket, db, ...)`.
        assert _sessions(assign, 2) == [winner]
        assert _sessions(reconcile, 1) == [winner]
        assert pending_ticket_convergence_effects(waiter) == ()
        await waiter.commit()
        assert await _committed(committed_world, ticket, track) == _Committed(
            PackageStatus.AFFECTED.value,
            (TicketStatus.ANALYZED.value, winner_actor.id),
            [
                _assignment(winner_actor),
                _track_event(
                    track, winner_actor, PackageStatus.ANALYSIS, PackageStatus.AFFECTED
                ),
                _gate(TicketStatus.ANALYSIS, TicketStatus.ANALYZED),
            ],
        )


@pytest.mark.integration
class TestSystemAgainstUserFinalState:
    async def test_system_fixed_waiter_observes_the_committed_final_state(
        self, committed_world: CommittedWorld, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A user sets `NOT_AFFECTED` and holds the Ticket lock; a system
        `FIXED` request, which takes no User lock, is proven blocked on the
        Ticket lock. After the user commits, the system request observes the
        final state and returns the protected `no_op` with no write, event,
        or reconciliation (package-service.md, `set_track_status()` step 8
        and Automatic authority)."""
        actor = await committed_world.user(role=Role.VULNERABILITY_ANALYST)
        ticket, track = await _open_ticket(committed_world)
        winner = await committed_world.open_session()
        system = await committed_world.open_session()
        stale = await system.get(TicketPackageTrack, track.id)
        assert stale is not None
        assert stale.status == PackageStatus.ANALYSIS.value
        reconcile = Spy(monkeypatch, "reconcile_ticket_status")

        await set_status(winner, track, PackageStatus.NOT_AFFECTED, actor)
        with SessionStatementRecorder(system) as recorder:
            task = _start(
                committed_world, system, track, PackageStatus.FIXED, None, ticket=ticket
            )
            await assert_lock_wait(task, waiter=system, blocked_by=winner)
            assert len(recorder.statements) == 1
            assert _is_ticket_lock(recorder.statements[0])
            await winner.commit()
            result = await asyncio.wait_for(task, timeout=WAIT)

        assert result.outcome is MutationOutcome.NO_OP
        assert result.track.status is PackageStatus.NOT_AFFECTED
        assert recorder.writes() == []
        assert _sessions(reconcile, 1) == [winner]
        assert pending_ticket_convergence_effects(system) == ()
        await system.commit()
        assert await _committed(committed_world, ticket, track) == _Committed(
            PackageStatus.NOT_AFFECTED.value,
            (TicketStatus.RESOLVED.value, actor.id),
            [
                _assignment(actor),
                _track_event(
                    track, actor, PackageStatus.ANALYSIS, PackageStatus.NOT_AFFECTED
                ),
                _gate(TicketStatus.ANALYSIS, TicketStatus.RESOLVED),
            ],
        )


# ---------------------------------------------------------------------------
# Lock order: acting User `FOR SHARE` before the Ticket `FOR UPDATE`
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestActingUserLockOrder:
    """package-service.md, `set_track_status()` step 1 and Concurrency
    Control; conventions.md, Cross-Domain Root Lock Order."""

    @pytest.mark.parametrize("release", ["rollback", "deactivation-committed"])
    async def test_user_call_waits_for_a_lifecycle_writer_before_the_ticket_lock(
        self, committed_world: CommittedWorld, release: str
    ) -> None:
        """B holds the acting User `FOR NO KEY UPDATE`. A blocks on its
        `FOR SHARE` before requesting the Ticket lock, which an independent
        session can still take with `NOWAIT`. After B releases, A proceeds
        and decides auto-assignment from the locked-current User: a rolled
        back writer leaves an active VA that is assigned; a committed
        deactivation changes the track without assignment (package-service.md,
        Auto-Assignment Rule)."""
        actor = await committed_world.user(role=Role.VULNERABILITY_ANALYST)
        ticket, track = await _open_ticket(committed_world)
        a = await committed_world.open_session()
        b = await committed_world.open_session()
        probe = await committed_world.open_session()

        await _hold_user(b, actor)
        with SessionStatementRecorder(a) as recorder:
            task = _start(
                committed_world, a, track, PackageStatus.AFFECTED, actor, ticket=ticket
            )
            await assert_lock_wait(task, waiter=a, blocked_by=b)
            assert _is_user_share(recorder.statements[-1])
            assert not any(TICKET_STATEMENT.search(s) for s in recorder.statements)
            assert not await _is_locked(
                probe, select(Ticket.id).where(Ticket.id == ticket.id)
            )
            if release == "rollback":
                await b.rollback()
            else:
                await b.execute(
                    update(User).where(User.id == actor.id).values(active=False)
                )
                await b.commit()
            result = await asyncio.wait_for(task, timeout=WAIT)
        assert _is_ticket_lock(
            next(s for s in recorder.statements if TICKET_STATEMENT.search(s))
        )
        await a.commit()

        assert result.outcome is MutationOutcome.CHANGED
        assigned = release == "rollback"
        assert await _committed(committed_world, ticket, track) == _Committed(
            PackageStatus.AFFECTED.value,
            (TicketStatus.ANALYZED.value, actor.id if assigned else None),
            [
                *([_assignment(actor)] if assigned else []),
                _track_event(
                    track, actor, PackageStatus.ANALYSIS, PackageStatus.AFFECTED
                ),
                _gate(TicketStatus.ANALYSIS, TicketStatus.ANALYZED),
            ],
        )

    async def test_system_call_takes_no_user_lock(
        self, committed_world: CommittedWorld
    ) -> None:
        """B holds the Ticket assignee's User `FOR NO KEY UPDATE`; a system
        `FIXED` call begins with the Ticket lock, takes no User lock, and
        completes while B still holds the User row."""
        assignee = await committed_world.user(role=Role.VULNERABILITY_ANALYST)
        ticket, track = await _open_ticket(committed_world, assignee=assignee)
        system = await committed_world.open_session()
        b = await committed_world.open_session()
        probe = await committed_world.open_session()

        await _hold_user(b, assignee)
        with SessionStatementRecorder(system) as recorder:
            task = _start(
                committed_world, system, track, PackageStatus.FIXED, None, ticket=ticket
            )
            result = await asyncio.wait_for(task, timeout=WAIT)
        assert await _is_locked(probe, select(User.id).where(User.id == assignee.id))
        await system.commit()
        await b.rollback()

        assert result.outcome is MutationOutcome.CHANGED
        assert _is_ticket_lock(recorder.statements[0])
        assert [s for s in recorder.row_locks() if not _is_ticket_lock(s)] == []
        assert await _committed(committed_world, ticket, track) == _Committed(
            PackageStatus.FIXED.value,
            (TicketStatus.RESOLVED.value, assignee.id),
            [
                _track_event(track, None, PackageStatus.ANALYSIS, PackageStatus.FIXED),
                _gate(TicketStatus.ANALYSIS, TicketStatus.RESOLVED),
            ],
        )
