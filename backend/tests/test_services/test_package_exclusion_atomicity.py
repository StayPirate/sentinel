"""Independent-session tests for the package-tree exclusion and restoration
operations (backend/app/services/package_service.py:
`soft_delete_ticket_package[_track|_product]()` and
`restore_ticket_package[_track|_product]()`), part D.

Owning specifications:

- docs/features/packages/package-service.md (Exclusion and restoration
  operations, including "Re-invocation and concurrency"; Consumer caller
  context and Ticket accessibility; Concurrency Control; Auto-Assignment
  Rule; Architectural Test Requirement bullets "Atomic consumer
  accessibility" (mutation part) and "Concurrent direct mutations").
- docs/features/tickets/ticket-audit-log.md (Testing Requirement 23: every
  event uses the true locked pre-state; a loser creates no event).
- docs/features/identity/rbac.md (Scope and Confidential Ticket
  Visibility).
- docs/api-spec.md (Authorization Chain Evaluation Order, flow 3).
- docs/features/platform/testing-strategy.md (Concurrency Testing; Ticket
  Accessibility: Locked mutations).
- docs/conventions.md (Transaction and Locking: Cross-Domain Root Lock
  Order).

The single-session behavior is covered by
`tests/test_services/test_package_exclusion.py`,
`tests/test_services/test_package_exclusion_scope.py`, and
`tests/test_services/test_package_exclusion_visibility.py`; this module adds
only what needs independent sessions:

- exclude/exclude and restore/restore winner and loser at every level;
- exclude/restore in both orders at every level, each guard applied to the
  committed-current state observed after the lock;
- concurrent ancestor/descendant exclusions;
- locked-current accessibility losses for a `non_confidential` caller,
  for exclusion and restoration, with nested-ownership, operability, and
  direct-marker decisions that never precede the denial;
- the acting-User `FOR SHARE` lock preceding the Ticket lock.

The public-add and internal re-resolution races of Concurrency Control are
out of scope (the orchestration operations are not implemented by this
change).

Every race serializes a winner that keeps its locks in an open transaction
and a waiter proven blocked (`assert_blocked`) on the Ticket lock, whose
statements show the acting User `FOR SHARE` first and the Ticket `FOR
UPDATE` last. The waiter holds a stale identity-map copy of its target path
loaded before the winner's change. Each Ticket is CVE-less with
`severity_manual = High` and carries an untouched actionable `ANALYSIS`
"pin" path, so it stays in `Analysis` and creates no gate event; each
target track carries one eligible Product in General Support on `EVAL`.
Committed rows are deleted explicitly at teardown by `CommittedWorld`
(testing-strategy.md, Concurrency Testing). Expected values are
transcribed from the specifications, never computed with the module under
test.
"""

from __future__ import annotations

import asyncio
import re
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass
from typing import Any

import pytest
from sqlalchemy import Select, select, update
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import NonActionableReason, Role, Scope, Severity, TicketStatus
from app.core.exceptions import TicketNotFoundError
from app.core.identifiers import format_ticket_id
from app.models.ticket import Ticket
from app.models.ticket_package import TicketPackage
from app.models.ticket_package_product import TicketPackageProduct
from app.models.ticket_package_track import TicketPackageTrack
from app.models.user import User
from app.services.package_service import (
    MarkerChangeResult,
    PackageAlreadyExcludedError,
    PackageNotExcludedError,
)
from app.services.ticket_convergence_registry import (
    pending_ticket_convergence_effects,
)
from app.services.ticket_service import resolve_ticket_locator
from app.services.ticket_visibility import TicketCaller
from tests.support.package_exclusion import (
    LEVELS,
    MARKER_NOW,
    CommittedPath,
    Direction,
    Level,
    Markers,
    committed_path,
    markers_by_id,
    patch_marker_now,
    path_call,
    path_event,
    with_target,
)
from tests.support.suse_cvss import assignment_event
from tests.support.suse_cvss_races import (
    CommittedWorld,
    SessionStatementRecorder,
    assert_blocked,
    prepare_loss,
)
from tests.support.ticket_mutations import EventRow, ticket_events_by_id
from tests.support.track_status import Spy

Factory = Callable[[], Awaitable[AsyncSession]]

TICKET_STATEMENT = re.compile(r"\b(?:FROM|JOIN|INTO|UPDATE) ticket\b")
USER_STATEMENT = re.compile(r'\b(?:FROM|JOIN|UPDATE) "user"')
WAIT = 5
"""Upper bound, in seconds, of every wait that is expected to finish."""

ANALYSIS = TicketStatus.ANALYSIS.value

OWN_REASON = {
    Level.PACKAGE: NonActionableReason.PACKAGE_EXCLUDED,
    Level.TRACK: NonActionableReason.TRACK_EXCLUDED,
    Level.PRODUCT: NonActionableReason.PRODUCT_EXCLUDED,
}
"""The reason of a record whose own direct marker is its only exclusion
(package-model.md, Derived Actionability)."""


@pytest.fixture
async def committed_world(db_session_factory: Factory) -> AsyncIterator[CommittedWorld]:
    world = CommittedWorld(db_session_factory, await db_session_factory())
    try:
        yield world
    finally:
        await world.cleanup()


@pytest.fixture(autouse=True)
def _marker_clock(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every exclusion, in every session, sets its marker to `MARKER_NOW`."""
    patch_marker_now(monkeypatch)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _Op:
    """One direct-marker call on a committed path."""

    level: Level
    direction: Direction
    path: CommittedPath
    actor: User


@dataclass(frozen=True, slots=True)
class _Committed:
    """The committed Ticket `(status, assignee_id)`, the direct markers of
    the target path, and the Ticket audit events."""

    ticket: tuple[str, uuid.UUID | None]
    markers: Markers
    events: list[EventRow]


async def _pinned(world: CommittedWorld, *, assignee: User | None = None) -> Ticket:
    """A committed CVE-less High `Analysis` Ticket with the pin path."""
    ticket = await world.ticket(
        cve_id=None,
        severity_manual=Severity.HIGH,
        assignee_id=assignee.id if assignee else None,
    )
    await committed_path(world, ticket)
    return ticket


async def _target(
    world: CommittedWorld,
    ticket: Ticket,
    *,
    seeded: tuple[Level, ...] = (),
    package_id: uuid.UUID | None = None,
) -> CommittedPath:
    """A committed target path whose `seeded` direct markers are set."""
    return await committed_path(
        world,
        ticket,
        package_id=package_id,
        package_excluded=Level.PACKAGE in seeded,
        track_excluded=Level.TRACK in seeded,
        product_excluded=Level.PRODUCT in seeded,
    )


async def _committed(
    world: CommittedWorld, ticket: Ticket, path: CommittedPath
) -> _Committed:
    """The committed state, read through a fresh independent session."""
    probe = await world.open_session()
    row = (
        await probe.execute(
            select(Ticket.status, Ticket.assignee_id).where(Ticket.id == ticket.id)
        )
    ).one()
    committed = _Committed(
        (row.status, row.assignee_id),
        await markers_by_id(probe, path.id),
        await ticket_events_by_id(probe, ticket.id),
    )
    await probe.rollback()
    return committed


Stale = tuple[TicketPackage, TicketPackageTrack, TicketPackageProduct]
"""Strong references to identity-map copies: the session's identity map is
weak, so an unreferenced copy would be reloaded rather than stale."""


async def _load_stale(session: AsyncSession, path: CommittedPath) -> Stale:
    """Load the path's package, track, and occurrence into the session's
    identity map, before any concurrent change."""
    package = await session.get(TicketPackage, path.package_id)
    track = await session.get(TicketPackageTrack, path.track_id)
    occurrence = await session.get(TicketPackageProduct, path.id)
    assert package is not None
    assert track is not None
    assert occurrence is not None
    return package, track, occurrence


def _stale_markers(stale: Stale) -> Markers:
    """The direct markers of the copies as loaded before the race."""
    package, track, occurrence = stale
    return package.deleted_at, track.deleted_at, occurrence.deleted_at


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


async def _hold_user(session: AsyncSession, user: User) -> None:
    """A simulated identity lifecycle writer's `FOR NO KEY UPDATE` lock on
    the User row (the lock of deactivation and role-origin removal)."""
    await session.execute(
        select(User.id).where(User.id == user.id).with_for_update(key_share=True)
    )


@dataclass
class _Race:
    """The outcome of one serialized winner/waiter race."""

    winner: AsyncSession
    waiter: AsyncSession
    winner_result: MarkerChangeResult[Any]
    waiter_result: MarkerChangeResult[Any] | None
    recorder: SessionStatementRecorder
    stale: Markers
    """The waiter's markers as loaded into its identity map pre-race."""


async def _race(
    world: CommittedWorld,
    first: _Op,
    second: _Op,
    *,
    error: type[Exception] | None = None,
) -> _Race:
    """`first` runs and keeps the Ticket lock uncommitted; `second`, holding
    a stale identity-map copy of its path, takes its acting User `FOR
    SHARE` and is proven blocked on the Ticket lock. `first` commits, then
    `second` completes (or raises `error`); `second` is left uncommitted."""
    winner = await world.open_session()
    waiter = await world.open_session()
    stale = await _load_stale(waiter, second.path)
    stale_markers = _stale_markers(stale)

    winner_result = await path_call(
        winner, first.level, first.direction, first.path, first.actor
    )
    recorder = SessionStatementRecorder(waiter)
    waiter_result: MarkerChangeResult[Any] | None = None
    with recorder:
        task = world.start(
            waiter,
            path_call(
                waiter, second.level, second.direction, second.path, second.actor
            ),
        )
        await assert_blocked(task)
        assert _is_user_share(recorder.statements[0])
        assert _is_ticket_lock(recorder.statements[-1])
        await winner.commit()
        if error is None:
            waiter_result = await asyncio.wait_for(task, timeout=WAIT)
        else:
            with pytest.raises(error):
                await asyncio.wait_for(task, timeout=WAIT)
    # The copies stay referenced until the waiter has decided.
    assert len(stale) == 3
    return _Race(winner, waiter, winner_result, waiter_result, recorder, stale_markers)


# ---------------------------------------------------------------------------
# Same-direction races (package-service.md, Re-invocation and concurrency)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestSameDirectionSerialization:
    """Two active VAs request the same direction on the same target of an
    unassigned Ticket: exclude/exclude has one success followed by
    `PackageAlreadyExcludedError`; restore/restore has one success followed
    by `PackageNotExcludedError`. The waiter's stale copy would pass the
    guard; its locked reload fails it before assignment, so it writes
    nothing, creates no event, does not assign, reconcile, or register a
    convergence effect (ticket-audit-log.md, Testing Requirement 23)."""

    @LEVELS
    @pytest.mark.parametrize("direction", list(Direction), ids=str)
    async def test_waiter_fails_on_the_direct_marker_guard(
        self,
        committed_world: CommittedWorld,
        monkeypatch: pytest.MonkeyPatch,
        level: Level,
        direction: Direction,
    ) -> None:
        world = committed_world
        winner_actor = await world.user(role=Role.VULNERABILITY_ANALYST)
        waiter_actor = await world.user(role=Role.VULNERABILITY_ANALYST)
        ticket = await _pinned(world)
        restore = direction is Direction.RESTORE
        path = await _target(world, ticket, seeded=(level,) if restore else ())
        before = await markers_by_id(world.session, path.id)
        assign = Spy(monkeypatch, "auto_assign_actor")
        reconcile = Spy(monkeypatch, "reconcile_ticket_status")

        race = await _race(
            world,
            _Op(level, direction, path, winner_actor),
            _Op(level, direction, path, waiter_actor),
            error=PackageNotExcludedError if restore else PackageAlreadyExcludedError,
        )

        assert race.stale == before
        assert race.recorder.writes() == []
        # `auto_assign_actor(ticket, acting_user, db)`,
        # `reconcile_ticket_status(ticket, db, ...)`.
        assert _sessions(assign, 2) == [race.winner]
        assert _sessions(reconcile, 1) == [race.winner]
        assert pending_ticket_convergence_effects(race.waiter) == ()
        await race.waiter.rollback()
        assert await _committed(world, ticket, path) == _Committed(
            (ANALYSIS, winner_actor.id),
            with_target(before, level, None if restore else MARKER_NOW),
            [
                assignment_event(winner_actor),
                path_event(level, direction, path, winner_actor),
            ],
        )


# ---------------------------------------------------------------------------
# Opposite-direction races
# ---------------------------------------------------------------------------

ORDERS = pytest.mark.parametrize(
    "first",
    [Direction.EXCLUDE, Direction.RESTORE],
    ids=["exclude-then-restore", "restore-then-exclude"],
)


@pytest.mark.integration
class TestOppositeDirections:
    """package-service.md, Re-invocation and concurrency: exclude/restore
    has no global priority; each caller applies its guard to the
    committed-current state observed after acquiring the lock.

    `exclude-then-restore`: the target starts clear. The waiter's stale
    copy is clear, so its restore guard would fail on the pre-lock state;
    after the winner's exclusion commits, the restore succeeds with
    `new_value` = the subject. `restore-then-exclude`: the target starts
    excluded, so the waiter's exclusion would fail on its stale copy; after
    the winner's restore commits, it succeeds with `old_value` = the
    subject. Each event reflects its own true locked pre-state; the waiter
    finds the winner as assignee and does not assign again."""

    @LEVELS
    @ORDERS
    async def test_waiter_applies_its_guard_to_the_committed_winner_state(
        self,
        committed_world: CommittedWorld,
        monkeypatch: pytest.MonkeyPatch,
        level: Level,
        first: Direction,
    ) -> None:
        world = committed_world
        winner_actor = await world.user(role=Role.VULNERABILITY_ANALYST)
        waiter_actor = await world.user(role=Role.VULNERABILITY_ANALYST)
        ticket = await _pinned(world)
        second = Direction.RESTORE if first is Direction.EXCLUDE else Direction.EXCLUDE
        path = await _target(
            world, ticket, seeded=(level,) if first is Direction.RESTORE else ()
        )
        before = await markers_by_id(world.session, path.id)
        reconcile = Spy(monkeypatch, "reconcile_ticket_status")

        race = await _race(
            world,
            _Op(level, first, path, winner_actor),
            _Op(level, second, path, waiter_actor),
        )
        await race.waiter.commit()

        assert race.stale == before
        assert race.waiter_result is not None
        final_excluded = second is Direction.EXCLUDE
        assert (
            race.waiter_result.target.actionable,
            race.waiter_result.target.non_actionable_reason,
        ) == ((False, OWN_REASON[level]) if final_excluded else (True, None))
        assert _sessions(reconcile, 1) == [race.winner, race.waiter]
        assert await _committed(world, ticket, path) == _Committed(
            (ANALYSIS, winner_actor.id),
            with_target(before, level, MARKER_NOW if final_excluded else None),
            [
                assignment_event(winner_actor),
                path_event(level, first, path, winner_actor),
                path_event(level, second, path, waiter_actor),
            ],
        )


# ---------------------------------------------------------------------------
# Ancestor/descendant independence
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestAncestorDescendantIndependence:
    """package-service.md, Re-invocation and concurrency: ancestor and
    descendant calls may both succeed because each changes an independent
    direct marker; Exclusion and restoration operations: no ancestor
    exclusion is a guard. The calls serialize on the Ticket lock; the
    waiter's result reports the ancestor reason (package-model.md, Derived
    Actionability precedence)."""

    @pytest.mark.parametrize(
        ("winner_level", "waiter_level"),
        [
            (Level.PACKAGE, Level.TRACK),
            (Level.PACKAGE, Level.PRODUCT),
            (Level.TRACK, Level.PRODUCT),
            (Level.PRODUCT, Level.PACKAGE),
        ],
        ids=lambda level: str(level),
    )
    async def test_both_exclusions_succeed_and_set_both_markers(
        self,
        committed_world: CommittedWorld,
        monkeypatch: pytest.MonkeyPatch,
        winner_level: Level,
        waiter_level: Level,
    ) -> None:
        world = committed_world
        winner_actor = await world.user(role=Role.VULNERABILITY_ANALYST)
        waiter_actor = await world.user(role=Role.VULNERABILITY_ANALYST)
        ticket = await _pinned(world)
        path = await _target(world, ticket)
        reconcile = Spy(monkeypatch, "reconcile_ticket_status")

        race = await _race(
            world,
            _Op(winner_level, Direction.EXCLUDE, path, winner_actor),
            _Op(waiter_level, Direction.EXCLUDE, path, waiter_actor),
        )
        await race.waiter.commit()

        levels = {winner_level, waiter_level}
        ancestor = Level.PACKAGE if Level.PACKAGE in levels else Level.TRACK
        assert race.waiter_result is not None
        assert (
            race.waiter_result.target.actionable,
            race.waiter_result.target.non_actionable_reason,
        ) == (False, OWN_REASON[ancestor])
        assert _sessions(reconcile, 1) == [race.winner, race.waiter]
        expected_markers = with_target(
            with_target((None, None, None), winner_level, MARKER_NOW),
            waiter_level,
            MARKER_NOW,
        )
        assert await _committed(world, ticket, path) == _Committed(
            (ANALYSIS, winner_actor.id),
            expected_markers,
            [
                assignment_event(winner_actor),
                path_event(winner_level, Direction.EXCLUDE, path, winner_actor),
                path_event(waiter_level, Direction.EXCLUDE, path, waiter_actor),
            ],
        )


# ---------------------------------------------------------------------------
# Atomic consumer accessibility (mutation part): locked-current state
# ---------------------------------------------------------------------------

LOSSES = ["confidentiality-set", "grant-revoked", "last-package-excluded"]
"""The Ticket-scoped visibility losses of testing-strategy.md, Locked
mutations. `association-changed` is a CVE-path loss: these operations are
Ticket-scoped and the Ticket predicate does not depend on its CVE."""

REQUESTS = ["effective", "guard-violation", "wrong-path", "ignored"]
"""`effective`: a request that would succeed if accessible;
`guard-violation`: the opposite target marker (would be
`PackageAlreadyExcludedError` / `PackageNotExcludedError`); `wrong-path`:
an unknown target identifier (would be `TrackNotFoundError` /
`ProductNotFoundError` / `PackageNotFoundError`); `ignored`: B also makes
the Ticket `Ignored` with the visibility loss (would be
`TicketNotMutableError`)."""


async def _existing_package(world: CommittedWorld, ticket: Ticket) -> uuid.UUID | None:
    """The Ticket's maintained package created by `prepare_loss()`, if any."""
    return (
        await world.session.execute(
            select(TicketPackage.id).where(TicketPackage.ticket_id == ticket.id)
        )
    ).scalar_one_or_none()


async def _assert_denied(
    world: CommittedWorld,
    monkeypatch: pytest.MonkeyPatch,
    *,
    user: User,
    ticket: Ticket,
    statements: list[Any],
    level: Level,
    direction: Direction,
    path: CommittedPath,
    overrides: dict[str, uuid.UUID],
) -> None:
    """Session A passes the preliminary locator check; session B holds the
    Ticket `FOR UPDATE` while applying the loss `statements`; A takes its
    acting User `FOR SHARE` and is proven blocked on the Ticket lock; B
    commits; A must raise `TicketNotFoundError` with zero domain writes,
    assignment, reconciliation, or convergence registration."""
    a = await world.open_session()
    b = await world.open_session()
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
        task = world.start(
            a,
            path_call(
                a,
                level,
                direction,
                path,
                user,
                scope=Scope.NON_CONFIDENTIAL,
                **overrides,
            ),
        )
        await assert_blocked(task)
        assert _is_user_share(recorder.statements[0])
        assert _is_ticket_lock(recorder.statements[-1])
        await b.commit()
        with pytest.raises(TicketNotFoundError):
            await asyncio.wait_for(task, timeout=WAIT)

    assert recorder.writes() == []
    assert (assign.calls, reconcile.calls) == ([], [])
    assert pending_ticket_convergence_effects(a) == ()
    await a.rollback()


@pytest.mark.integration
class TestLockedCurrentAccessibilityRaces:
    """A `restricted_analyst` caller with effective scope `non_confidential`
    passes the preliminary locator check through exactly one visibility
    path; session B then removes that path while holding the Ticket lock.
    A, blocked on the Ticket lock, must raise `TicketNotFoundError` from
    the locked-current state with zero side effects after B commits.
    Operability, nested ownership, and the direct-marker guard never
    precede the denial (testing-strategy.md, Ticket Accessibility: Locked
    mutations; package-service.md, Exclusion and restoration operations
    steps 2-6; api-spec.md, flow 3)."""

    @pytest.mark.parametrize("request_kind", REQUESTS)
    @pytest.mark.parametrize("direction", list(Direction), ids=str)
    @pytest.mark.parametrize("loss", LOSSES)
    async def test_track_operation_after_visibility_loss_is_not_found(
        self,
        committed_world: CommittedWorld,
        monkeypatch: pytest.MonkeyPatch,
        loss: str,
        direction: Direction,
        request_kind: str,
    ) -> None:
        """The track-level request matrix. For `last-package-excluded` the
        target track lies under the maintained package: an exclusion or
        restore beneath an excluded package is valid, so only the denial
        stops it."""
        world = committed_world
        user, _cve, ticket, statements = await prepare_loss(world, loss)
        seeded = (direction is Direction.RESTORE) != (request_kind == "guard-violation")
        path = await _target(
            world,
            ticket,
            seeded=(Level.TRACK,) if seeded else (),
            package_id=await _existing_package(world, ticket),
        )
        overrides = {"track_id": uuid.uuid7()} if request_kind == "wrong-path" else {}
        status = ANALYSIS
        if request_kind == "ignored":
            status = TicketStatus.IGNORED.value
            statements.append(
                update(Ticket)
                .where(Ticket.id == ticket.id)
                .values(status=TicketStatus.IGNORED.value)
            )
        before = await markers_by_id(world.session, path.id)

        await _assert_denied(
            world,
            monkeypatch,
            user=user,
            ticket=ticket,
            statements=statements,
            level=Level.TRACK,
            direction=direction,
            path=path,
            overrides=overrides,
        )

        committed = await _committed(world, ticket, path)
        assert (committed.ticket, committed.events) == ((status, None), [])
        assert committed.markers[1:] == before[1:]
        assert (committed.markers[0] is not None) is (loss == "last-package-excluded")

    @pytest.mark.parametrize("direction", list(Direction), ids=str)
    @pytest.mark.parametrize(
        ("level", "loss"),
        [
            (Level.PACKAGE, "confidentiality-set"),
            (Level.PACKAGE, "grant-revoked"),
            (Level.PACKAGE, "last-package-excluded"),
            (Level.PRODUCT, "confidentiality-set"),
            (Level.PRODUCT, "grant-revoked"),
            (Level.PRODUCT, "last-package-excluded"),
        ],
        ids=lambda value: str(value),
    )
    async def test_package_and_product_operations_after_visibility_loss(
        self,
        committed_world: CommittedWorld,
        monkeypatch: pytest.MonkeyPatch,
        level: Level,
        loss: str,
        direction: Direction,
    ) -> None:
        """Package and Product requests that would be effective without the
        loss (a restore targets a directly excluded record). For
        `last-package-excluded` the target lies under, or at package level
        is, the maintained package. At package level that package cannot be
        excluded before the preliminary check, so the loss itself supplies
        the target state: B's exclusion makes A's exclusion a would-be
        `PackageAlreadyExcludedError` and A's restore a would-be effective
        restore of the caller's own last package; the denial wins in both."""
        world = committed_world
        user, _cve, ticket, statements = await prepare_loss(world, loss)
        own_package = level is Level.PACKAGE and loss == "last-package-excluded"
        seeded = direction is Direction.RESTORE and not own_package
        path = await _target(
            world,
            ticket,
            seeded=(level,) if seeded else (),
            package_id=await _existing_package(world, ticket),
        )
        before = await markers_by_id(world.session, path.id)

        await _assert_denied(
            world,
            monkeypatch,
            user=user,
            ticket=ticket,
            statements=statements,
            level=level,
            direction=direction,
            path=path,
            overrides={},
        )

        committed = await _committed(world, ticket, path)
        assert (committed.ticket, committed.events) == ((ANALYSIS, None), [])
        assert committed.markers[1:] == before[1:]
        if loss == "last-package-excluded":
            assert before[0] is None
            assert committed.markers[0] is not None
        else:
            assert committed.markers[0] == before[0]


# ---------------------------------------------------------------------------
# Lock order: acting User `FOR SHARE` before the Ticket `FOR UPDATE`
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestActingUserLockOrder:
    """package-service.md, Exclusion and restoration operations step 2,
    Auto-Assignment Rule, and Concurrency Control; conventions.md,
    Cross-Domain Root Lock Order."""

    @pytest.mark.parametrize("direction", list(Direction), ids=str)
    @pytest.mark.parametrize("release", ["rollback", "deactivation-committed"])
    async def test_call_waits_for_a_lifecycle_writer_before_the_ticket_lock(
        self,
        committed_world: CommittedWorld,
        release: str,
        direction: Direction,
    ) -> None:
        """B holds the acting User `FOR NO KEY UPDATE`. A blocks on its
        `FOR SHARE` before requesting the Ticket lock, which an independent
        session can still take with `NOWAIT`. After B releases, A proceeds
        and decides auto-assignment from the locked-current User: a rolled
        back writer leaves an active VA that is assigned; a committed
        deactivation changes the marker without assignment."""
        world = committed_world
        actor = await world.user(role=Role.VULNERABILITY_ANALYST)
        ticket = await _pinned(world)
        restore = direction is Direction.RESTORE
        path = await _target(world, ticket, seeded=(Level.PACKAGE,) if restore else ())
        before = await markers_by_id(world.session, path.id)
        a = await world.open_session()
        b = await world.open_session()
        probe = await world.open_session()

        await _hold_user(b, actor)
        with SessionStatementRecorder(a) as recorder:
            task = world.start(a, path_call(a, Level.PACKAGE, direction, path, actor))
            await assert_blocked(task)
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
            await asyncio.wait_for(task, timeout=WAIT)
        assert _is_ticket_lock(
            next(s for s in recorder.statements if TICKET_STATEMENT.search(s))
        )
        await a.commit()

        assigned = release == "rollback"
        assert await _committed(world, ticket, path) == _Committed(
            (ANALYSIS, actor.id if assigned else None),
            with_target(before, Level.PACKAGE, None if restore else MARKER_NOW),
            [
                *([assignment_event(actor)] if assigned else []),
                path_event(Level.PACKAGE, direction, path, actor),
            ],
        )
