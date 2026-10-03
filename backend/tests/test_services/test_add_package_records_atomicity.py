"""Independent-session tests for the package-record creation boundary
`package_service.add_package_records()`
(backend/app/services/package_service.py), part C: races.

Owning specifications:

- docs/features/packages/package-service.md (`add_package_records()` step
  1, step 2, step 3, step 6, Concurrent outcomes; Consumer caller context
  and Ticket accessibility; Auto-Assignment Rule; Concurrency Control,
  including the public-add and internal re-resolution outcomes;
  Architectural Test Requirement bullets "Atomic consumer accessibility"
  (consumer-mutation part), "Concurrent direct mutations" (public add and
  internal re-resolution racing with exclusion or restore), "Package
  creation concurrency and result truth", and "Maintainership
  acquisition" (locked-mutation part)).
- docs/features/packages/package-maintainership.md (Acquisition Workflow >
  Locked mutation: the acting-User root, the unlocked maintainer
  observation, serialization; Confidential Ticket Visibility: locked-current
  authority; Testing Requirements: concurrent invocations and the
  `active_ticket_only` race skip).
- docs/features/tickets/ticket-audit-log.md (Testing Requirement 23: every
  event uses the true locked pre-state; a loser creates no event).
- docs/features/platform/testing-strategy.md (Concurrency Testing,
  Lock-Wait Observation; Ticket Accessibility: Locked mutations).
- docs/conventions.md (Transaction and Locking: Cross-Domain Root Lock
  Order).

The single-session behavior is covered by
`tests/test_services/test_add_package_records.py` and
`tests/test_services/test_add_package_records_scope.py`; this module adds
only what needs independent sessions:

- two same-Ticket calls serialized on the Ticket lock, with a waiter that
  reports the winner's rows as skips, a package-tree no-op, a
  maintainer-only mutation, or a remaining partial creation;
- the acting-User `FOR SHARE` root before the Ticket lock, and no User root
  for a system call or for the maintainer observation;
- an `active_ticket_only` skip after a committed status change;
- public and re-resolution calls racing with the package, track, and
  Product exclusion and restoration operations;
- locked-current accessibility losses for a `non_confidential` caller,
  including when its own email is supplied as a maintainer email.

Every race serializes a holder that keeps the Ticket lock in an open
transaction and a waiter proven blocked on it (`assert_lock_wait`), whose
statements show the acting User `FOR SHARE` first (none for a system call)
and the Ticket `FOR UPDATE` last. One accessibility case instead pauses
the call on an `asyncio.Event` before its first root lock. Unless a test
states otherwise, each Ticket is an unassigned CVE-less `Analysis` Ticket
with `severity_manual = High` and an untouched actionable `ANALYSIS` "pin"
package, so it stays in `Analysis` and creates no gate event; every
catalog Product is in General Support on the controlled service date
`EVAL` with a `NULL` threshold, so a created occurrence is eligible (the
`10.0` fallback score). Committed rows, including the `default_cvss_version`
setting the test schema lacks, are deleted explicitly at teardown
(testing-strategy.md, Concurrency Testing). Expected values are
transcribed from the specifications, never computed with the module under
test.
"""

from __future__ import annotations

import asyncio
import dataclasses
import re
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable, Coroutine
from datetime import datetime
from typing import Any

import pytest
from sqlalchemy import Select, delete, select, update
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import Role, Scope, Severity, TicketStatus, WorkflowType
from app.core.exceptions import TicketNotFoundError
from app.models.product import Product
from app.models.system_setting import SystemSetting
from app.models.ticket import Ticket
from app.models.ticket_package import TicketPackage
from app.models.ticket_package_product import TicketPackageProduct
from app.models.user import User
from app.services import package_service
from app.services.package_service import (
    CreatedTrack,
    PackageAddedComment,
    PackageAlreadyExcludedError,
    PackageRecordsOutcome,
    PackageRecordsResult,
    ResolvedTrackData,
)
from app.services.ticket_convergence_registry import (
    pending_ticket_convergence_effects,
)
from app.services.ticket_mutations import stabilize_acting_user
from tests.support.cvss_chain import DEFAULT_VERSION
from tests.support.database import assert_lock_wait
from tests.support.package_exclusion import (
    MARKER_NOW,
    SEEDED_AT,
    CommittedPath,
    Direction,
    Level,
    committed_path,
    markers_by_id,
    patch_marker_now,
    path_call,
    path_event,
    with_target,
)
from tests.support.package_records import (
    NEW_TRACK,
    SKIPPED,
    OccurrenceState,
    TrackState,
    Tree,
    add_records,
    catalog_product,
    changed,
    maintainer_event,
    maintainers,
    new_occurrence,
    outcome,
    package_added_event,
    package_tree,
    target,
    ticket_row,
    track_ids,
    tree_rows,
)
from tests.support.suse_cvss import assignment_event
from tests.support.suse_cvss_races import (
    CommittedWorld,
    SessionStatementRecorder,
    prepare_loss,
)
from tests.support.ticket_mutations import (
    EVAL,
    EventRow,
    StatementRecorder,
    ticket_events_by_id,
)
from tests.support.track_status import Spy

Factory = Callable[[], Awaitable[AsyncSession]]

TICKET_STATEMENT = re.compile(r"\b(?:FROM|JOIN|INTO|UPDATE) ticket\b")
USER_STATEMENT = re.compile(r'\b(?:FROM|JOIN|UPDATE) "user"')
ROW_LOCKS = ("FOR UPDATE", "FOR SHARE", "FOR NO KEY UPDATE", "FOR KEY SHARE")
WAIT = 5
"""Upper bound, in seconds, of every wait that is expected to finish."""

ANALYSIS = TicketStatus.ANALYSIS.value
IBS_REF = "Fictional:Product:15-SP7:Update"
GIT_REF = "fictional/slfo-1.1"
CVE_RESOLUTION: PackageAddedComment = "CVE package resolution"
CONVERGENCE: PackageAddedComment = "Ticket convergence"

UNDECIDED = (
    "ticket_package.package_name =",
    "FROM ticket_package_track",
    "FROM ticket_package_product",
    '"user".email IN',
)
"""Statement fragments of the package lookup (excluded-package guard), the
locked tree reload (no-op and idempotency classification), and the
maintainer match: none may precede a locked accessibility denial."""

CONTEXTS = pytest.mark.parametrize("context", ["user", "system"])


@pytest.fixture
async def world(db_session_factory: Factory) -> AsyncIterator[CommittedWorld]:
    """A `CommittedWorld` that also owns the committed `default_cvss_version`
    setting (the test schema has none), which every creation reads."""
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


@pytest.fixture(autouse=True)
def _clocks(monkeypatch: pytest.MonkeyPatch) -> None:
    """In every session, the service's UTC date is `EVAL` and an exclusion
    sets its marker to `MARKER_NOW`."""
    monkeypatch.setattr(package_service, "_utc_today", lambda: EVAL)
    patch_marker_now(monkeypatch)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _name() -> str:
    return f"fictional-librace-{uuid.uuid4().hex[:10]}"


async def _ticket(world: CommittedWorld) -> Ticket:
    """The committed unassigned pinned Ticket of the module docstring."""
    ticket = await world.ticket(cve_id=None, severity_manual=Severity.HIGH)
    await committed_path(world, ticket)
    return ticket


async def _product(world: CommittedWorld) -> Product:
    """A committed catalog Product owned by the world."""
    product = await catalog_product(world.session)
    world.product_ids.append(product.id)
    await world.session.commit()
    return product


async def _product_of(world: CommittedWorld, path: CommittedPath) -> uuid.UUID:
    """The catalog Product of a committed path's occurrence."""
    product_id = (
        await world.session.execute(
            select(TicketPackageProduct.product_id).where(
                TicketPackageProduct.id == path.id
            )
        )
    ).scalar_one()
    await world.session.commit()
    return product_id


def _path_tree(
    path: CommittedPath,
    *,
    package: datetime | None,
    track: datetime | None,
    product: datetime | None,
    product_id: uuid.UUID,
) -> Tree:
    """The tree of a committed path (an `ibs` `ANALYSIS`/`PENDING` track
    with one eligible unreleased occurrence) with the given direct
    markers."""
    reference = path.subject["track"]
    return Tree(
        package,
        {reference: TrackState("ibs", "ANALYSIS", "PENDING", track)},
        {(reference, product_id): OccurrenceState(True, False, None, product)},
    )


@dataclasses.dataclass(frozen=True, slots=True)
class _State:
    """The committed Ticket `(status, assignee_id)`, its audit events, the
    tree of one package, and every maintainer association of the Ticket."""

    ticket: tuple[str, uuid.UUID | None]
    events: list[EventRow]
    tree: Tree | None
    maintainers: list[tuple[str, uuid.UUID]]


async def _committed(
    world: CommittedWorld, ticket_id: uuid.UUID, package_name: str
) -> _State:
    """The committed state, read through a fresh independent session."""
    probe = await world.open_session()
    state = _State(
        await ticket_row(probe, ticket_id),
        await ticket_events_by_id(probe, ticket_id),
        await package_tree(probe, ticket_id, package_name),
        await maintainers(probe, ticket_id),
    )
    await probe.rollback()
    return state


async def _track_ids(
    world: CommittedWorld, ticket_id: uuid.UUID, package_name: str
) -> dict[str, uuid.UUID]:
    probe = await world.open_session()
    ids = await track_ids(probe, ticket_id, package_name)
    await probe.rollback()
    return ids


def _sessions(spy: Spy, position: int) -> list[Any]:
    """The session argument of each recorded call."""
    return [args[position] for args, _kwargs in spy.calls]


def _is_user_share(statement: str) -> bool:
    return USER_STATEMENT.search(statement) is not None and statement.rstrip().endswith(
        "FOR SHARE"
    )


def _is_user_lock(statement: str) -> bool:
    return USER_STATEMENT.search(statement) is not None and any(
        lock in statement for lock in ROW_LOCKS
    )


def _is_ticket_lock(statement: str) -> bool:
    return TICKET_STATEMENT.search(
        statement
    ) is not None and statement.rstrip().endswith("FOR UPDATE")


def _assert_blocked_at_ticket_root(statements: list[str], *, user_root: bool) -> None:
    """The waiter's statements so far: the Ticket `FOR UPDATE` it waits on
    is the last; a user-attributed call took its acting User `FOR SHARE`
    first and touched no Ticket before; a system call issued nothing else."""
    assert _is_ticket_lock(statements[-1])
    if user_root:
        assert _is_user_share(statements[0])
        assert not any(TICKET_STATEMENT.search(s) for s in statements[:-1])
    else:
        assert len(statements) == 1


async def _hold_user(session: AsyncSession, user: User) -> None:
    """A simulated identity lifecycle writer's `FOR NO KEY UPDATE` lock on
    the User row (the lock of deactivation and role-origin removal)."""
    await session.execute(
        select(User.id).where(User.id == user.id).with_for_update(key_share=True)
    )


async def _hold_ticket(session: AsyncSession, ticket_id: uuid.UUID) -> None:
    await session.execute(
        select(Ticket.id).where(Ticket.id == ticket_id).with_for_update()
    )


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


async def _behind(
    world: CommittedWorld,
    holder: AsyncSession,
    waiter: AsyncSession,
    call: Coroutine[Any, Any, PackageRecordsResult],
    *,
    user_root: bool,
    error: type[Exception] | None = None,
) -> tuple[PackageRecordsResult | None, SessionStatementRecorder]:
    """Start `call` on `waiter`, prove it blocked on the Ticket lock that
    `holder` keeps uncommitted, commit `holder`, then await `call` (or its
    `error`). The waiter's transaction is left open."""
    recorder = SessionStatementRecorder(waiter)
    result: PackageRecordsResult | None = None
    with recorder:
        task = world.start(waiter, call)
        await assert_lock_wait(task, waiter=waiter, blocked_by=holder)
        _assert_blocked_at_ticket_root(recorder.statements, user_root=user_root)
        await holder.commit()
        if error is None:
            result = await asyncio.wait_for(task, timeout=WAIT)
        else:
            with pytest.raises(error):
                await asyncio.wait_for(task, timeout=WAIT)
    return result, recorder


# ---------------------------------------------------------------------------
# Serialization and result truth (package-service.md, Concurrent outcomes;
# Architectural Test Requirement: Package creation concurrency and result
# truth)
# ---------------------------------------------------------------------------

SERIALIZED = ["no-op", "maintainer-only", "partial"]
"""The waiter's input against the winner's `IBS_REF: {P1}` with maintainer
M1. `no-op`: the same tree and M1. `maintainer-only`: the same tree with
M1 and the extra M2. `partial`: `IBS_REF: {P1, P2}` plus a new Git track
`GIT_REF: {P3}`, with M1."""


@pytest.mark.integration
class TestSerializedCreation:
    """Two same-Ticket calls serialize on the Ticket lock. The winner
    creates the missing rows and assigns the unassigned Ticket; the waiter
    reloads the committed winner state and reports its rows truthfully as
    skips. Only rows and associations it actually creates contribute its
    events, assignment attempt, reconciliation, counts, and new-track
    signal; no row or event is duplicated (ticket-audit-log.md, Testing
    Requirement 23)."""

    @CONTEXTS
    @pytest.mark.parametrize("case", SERIALIZED)
    async def test_waiter_reports_the_winner_rows_truthfully(
        self,
        world: CommittedWorld,
        monkeypatch: pytest.MonkeyPatch,
        case: str,
        context: str,
    ) -> None:
        winner_actor = await world.user(role=Role.VULNERABILITY_ANALYST)
        waiter_actor = (
            await world.user(role=Role.VULNERABILITY_ANALYST)
            if context == "user"
            else None
        )
        m1 = await world.user(role=Role.RESTRICTED_ANALYST)
        m2 = await world.user(role=Role.RESTRICTED_ANALYST)
        ticket = await _ticket(world)
        p1, p2, p3 = [await _product(world) for _ in range(3)]
        pkg = _name()
        winner_tracks = [target(IBS_REF, p1)]
        waiter_tracks, waiter_emails = {
            "no-op": (winner_tracks, {m1.email}),
            "maintainer-only": (winner_tracks, {m1.email, m2.email}),
            "partial": (
                [
                    target(IBS_REF, p1, p2),
                    target(GIT_REF, p3, workflow=WorkflowType.GIT),
                ],
                {m1.email},
            ),
        }[case]
        assign = Spy(monkeypatch, "auto_assign_actor")
        reconcile = Spy(monkeypatch, "reconcile_ticket_status")
        winner = await world.open_session()
        waiter = await world.open_session()

        winner_result = await add_records(
            winner, ticket.id, pkg, winner_tracks, actor=winner_actor, emails={m1.email}
        )
        waiter_result, recorder = await _behind(
            world,
            winner,
            waiter,
            add_records(
                waiter,
                ticket.id,
                pkg,
                waiter_tracks,
                actor=waiter_actor,
                emails=waiter_emails,
                comment=CVE_RESOLUTION,
            ),
            user_root=waiter_actor is not None,
        )
        assert pending_ticket_convergence_effects(waiter) == ()
        await waiter.commit()

        ids = await _track_ids(world, ticket.id, pkg)
        assert outcome(winner_result) == changed(1, 0, 1, 0)
        assert winner_result.created_tracks == (
            CreatedTrack(ids[IBS_REF], IBS_REF, WorkflowType.IBS),
        )
        assert waiter_result is not None
        partial = case == "partial"
        if case == "no-op":
            assert outcome(waiter_result) == (
                PackageRecordsOutcome.PACKAGE_TREE_NO_OP,
                0,
                1,
                0,
                1,
            )
            assert recorder.writes() == []
        elif case == "maintainer-only":
            assert outcome(waiter_result) == (
                PackageRecordsOutcome.MAINTAINER_ONLY,
                0,
                1,
                0,
                1,
            )
            # Only the association and its event: no tree or Ticket write.
            writes = recorder.writes()
            assert writes
            assert all(
                re.match(
                    r"\s*INSERT INTO (ticket_package_maintainer|ticket_audit_event)", s
                )
                for s in writes
            )
        else:
            assert outcome(waiter_result) == changed(1, 1, 2, 1)
        assert waiter_result.created_tracks == (
            (CreatedTrack(ids[GIT_REF], GIT_REF, WorkflowType.GIT),) if partial else ()
        )
        # `auto_assign_actor(ticket, acting_user, db)`,
        # `reconcile_ticket_status(ticket, db, ...)`: only a tree change.
        expected_sessions = [winner, waiter] if partial else [winner]
        assert _sessions(assign, 2) == expected_sessions
        assert _sessions(reconcile, 1) == expected_sessions

        occurrences = {(IBS_REF, p1.id): new_occurrence(True)}
        tracks = {IBS_REF: NEW_TRACK[WorkflowType.IBS]}
        if partial:
            occurrences |= {
                (IBS_REF, p2.id): new_occurrence(True),
                (GIT_REF, p3.id): new_occurrence(True),
            }
            tracks[GIT_REF] = NEW_TRACK[WorkflowType.GIT]
        waiter_events = {
            "no-op": [],
            "maintainer-only": [maintainer_event(pkg, m2)],
            "partial": [package_added_event(pkg, waiter_actor, CVE_RESOLUTION)],
        }[case]
        assert await _committed(world, ticket.id, pkg) == _State(
            (ANALYSIS, winner_actor.id),
            [
                assignment_event(winner_actor),
                maintainer_event(pkg, m1),
                package_added_event(pkg, winner_actor),
                *waiter_events,
            ],
            Tree(None, tracks, occurrences),
            sorted(
                [(pkg, m1.id)] + ([(pkg, m2.id)] if case == "maintainer-only" else [])
            ),
        )


# ---------------------------------------------------------------------------
# Root lock order (package-service.md, step 1 and Concurrency Control;
# package-maintainership.md, Locked mutation; conventions.md, Cross-Domain
# Root Lock Order)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestRootLockOrder:
    @pytest.mark.parametrize("release", ["rollback", "deactivation-committed"])
    async def test_user_call_waits_for_a_lifecycle_writer_before_the_ticket_lock(
        self, world: CommittedWorld, release: str
    ) -> None:
        """B holds the acting User `FOR NO KEY UPDATE`. A blocks on its
        `FOR SHARE` before requesting the Ticket lock, which an independent
        session can still take with `NOWAIT`. After B releases, A creates
        the tree and decides auto-assignment from the locked-current User:
        a rolled-back writer leaves an active VA that is assigned; after a
        committed deactivation the creation proceeds without assignment."""
        actor = await world.user(role=Role.VULNERABILITY_ANALYST)
        ticket = await _ticket(world)
        product = await _product(world)
        pkg = _name()
        a = await world.open_session()
        b = await world.open_session()
        probe = await world.open_session()

        await _hold_user(b, actor)
        with SessionStatementRecorder(a) as recorder:
            task = world.start(
                a,
                add_records(a, ticket.id, pkg, [target(IBS_REF, product)], actor=actor),
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

        assigned = release == "rollback"
        assert outcome(result) == changed(1, 0, 1, 0)
        state = await _committed(world, ticket.id, pkg)
        assert (state.ticket, state.events) == (
            (ANALYSIS, actor.id if assigned else None),
            [
                *([assignment_event(actor)] if assigned else []),
                package_added_event(pkg, actor),
            ],
        )

    @CONTEXTS
    async def test_maintainer_observation_and_system_call_take_no_user_lock(
        self, world: CommittedWorld, context: str
    ) -> None:
        """The maintainer User query is an unlocked current-state
        observation, not a User root: a lifecycle writer holding the
        matching maintainer's User `FOR NO KEY UPDATE` does not block the
        call, which associates that User. A system call takes no User lock
        at all and starts with the Ticket lock; a user-attributed call locks
        only its acting User."""
        actor = (
            await world.user(role=Role.VULNERABILITY_ANALYST)
            if context == "user"
            else None
        )
        maintainer = await world.user(role=Role.RESTRICTED_ANALYST)
        ticket = await _ticket(world)
        product = await _product(world)
        pkg = _name()
        writer = await world.open_session()
        a = await world.open_session()

        await _hold_user(writer, maintainer)
        with SessionStatementRecorder(a) as recorder:
            result = await asyncio.wait_for(
                add_records(
                    a,
                    ticket.id,
                    pkg,
                    [target(IBS_REF, product)],
                    actor=actor,
                    emails={maintainer.email},
                ),
                timeout=WAIT,
            )
        await a.commit()
        await writer.rollback()

        user_locks = [s for s in recorder.statements if _is_user_lock(s)]
        if actor is None:
            assert user_locks == []
            assert _is_ticket_lock(recorder.statements[0])
        else:
            assert user_locks == [recorder.statements[0]]
            assert _is_user_share(recorder.statements[0])
        assert outcome(result) == changed(1, 0, 1, 0)
        assert (await _committed(world, ticket.id, pkg)).maintainers == [
            (pkg, maintainer.id)
        ]


# ---------------------------------------------------------------------------
# `active_ticket_only` after a committed status change (package-service.md
# step 3; package-maintainership.md, Locked mutation step 2)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestActiveTicketOnlyRace:
    @pytest.mark.parametrize(
        "status",
        [TicketStatus.RESOLVED, TicketStatus.IGNORED, TicketStatus.DUPLICATED],
        ids=str,
    )
    async def test_waiter_skips_after_a_committed_status_change(
        self,
        world: CommittedWorld,
        monkeypatch: pytest.MonkeyPatch,
        status: TicketStatus,
    ) -> None:
        """A changes the active Ticket's status under its Ticket lock. The
        Product catalog backfill call (`active_ticket_only`), which would
        create a tree and an association, waits, then observes the
        committed inactive status and returns the skip: it examines nothing
        after the lock and has zero writes, events, assignment,
        reconciliation, convergence registration, records, or
        associations."""
        maintainer = await world.user(role=Role.RESTRICTED_ANALYST)
        ticket = await _ticket(world)
        duplicate_of = (
            await world.ticket(cve_id=None)
            if status is TicketStatus.DUPLICATED
            else None
        )
        product = await _product(world)
        pkg = _name()
        assign = Spy(monkeypatch, "auto_assign_actor")
        reconcile = Spy(monkeypatch, "reconcile_ticket_status")
        holder = await world.open_session()
        waiter = await world.open_session()

        await _hold_ticket(holder, ticket.id)
        await holder.execute(
            update(Ticket)
            .where(Ticket.id == ticket.id)
            .values(
                status=status.value,
                duplicate_of_id=duplicate_of.id if duplicate_of else None,
            )
        )
        result, recorder = await _behind(
            world,
            holder,
            waiter,
            add_records(
                waiter,
                ticket.id,
                pkg,
                [target(IBS_REF, product)],
                emails={maintainer.email},
                comment="Product catalog backfill",
                active_ticket_only=True,
            ),
            user_root=False,
        )

        assert result == SKIPPED
        assert len(recorder.statements) == 1
        assert (assign.calls, reconcile.calls) == ([], [])
        assert pending_ticket_convergence_effects(waiter) == ()
        await waiter.rollback()
        assert await _committed(world, ticket.id, pkg) == _State(
            (status.value, None), [], None, []
        )


# ---------------------------------------------------------------------------
# Public add and internal re-resolution racing with exclusion or restore
# (package-service.md, Concurrency Control; Architectural Test
# Requirement: Concurrent direct mutations)
# ---------------------------------------------------------------------------

KINDS = ["no-op", "maintainer-only", "tree"]
"""The adding call's input on the committed path `T1: {P1}`. `no-op`: the
same tree, no email. `maintainer-only`: the same tree with maintainer M.
`tree`: `T1: {P1, P2}` plus a new Git track `GIT_REF: {P3}`, with M."""


def _input(
    kind: str, path: CommittedPath, p1: uuid.UUID, p2: Product, p3: Product, m: User
) -> tuple[list[ResolvedTrackData], set[str]]:
    reference = path.subject["track"]
    if kind == "tree":
        return (
            [
                target(reference, p1, p2),
                target(GIT_REF, p3, workflow=WorkflowType.GIT),
            ],
            {m.email},
        )
    return [target(reference, p1)], ({m.email} if kind == "maintainer-only" else set())


@dataclasses.dataclass(frozen=True, slots=True)
class _MarkerWorld:
    """A pinned unassigned Ticket with the target path, its exclusion or
    restoration actor A, the adding actor B (`None` for a system call),
    the maintainer M, and the extra catalog Products."""

    ticket: Ticket
    path: CommittedPath
    p1: uuid.UUID
    p2: Product
    p3: Product
    actor_a: User
    actor_b: User | None
    m: User


async def _marker_world(
    world: CommittedWorld, *, seeded: Level | None = None, system: bool = False
) -> _MarkerWorld:
    actor_a = await world.user(role=Role.VULNERABILITY_ANALYST)
    actor_b = None if system else await world.user(role=Role.VULNERABILITY_ANALYST)
    m = await world.user(role=Role.RESTRICTED_ANALYST)
    ticket = await _ticket(world)
    path = await committed_path(
        world,
        ticket,
        package_excluded=seeded is Level.PACKAGE,
        track_excluded=seeded is Level.TRACK,
        product_excluded=seeded is Level.PRODUCT,
    )
    return _MarkerWorld(
        ticket,
        path,
        await _product_of(world, path),
        await _product(world),
        await _product(world),
        actor_a,
        actor_b,
        m,
    )


def _tree_events(
    kind: str, w: _MarkerWorld, comment: PackageAddedComment = CVE_RESOLUTION
) -> list[EventRow]:
    """The adding call's own events (no assignment: A already assigned)."""
    pkg = w.path.subject["package"]
    return {
        "no-op": [],
        "maintainer-only": [maintainer_event(pkg, w.m)],
        "tree": [
            maintainer_event(pkg, w.m),
            package_added_event(pkg, w.actor_b, comment),
        ],
    }[kind]


def _with_new_rows(tree: Tree, kind: str, w: _MarkerWorld) -> Tree:
    """`tree` plus the rows that the `tree` input creates."""
    if kind != "tree":
        return tree
    reference = w.path.subject["track"]
    return Tree(
        tree.deleted_at,
        tree.tracks | {GIT_REF: NEW_TRACK[WorkflowType.GIT]},
        tree.occurrences
        | {
            (reference, w.p2.id): new_occurrence(True),
            (GIT_REF, w.p3.id): new_occurrence(True),
        },
    )


EXPECTED_OUTCOME = {
    "no-op": (PackageRecordsOutcome.PACKAGE_TREE_NO_OP, 0, 1, 0, 1),
    "maintainer-only": (PackageRecordsOutcome.MAINTAINER_ONLY, 0, 1, 0, 1),
    "tree": changed(1, 1, 2, 1),
}


@pytest.mark.integration
class TestPublicAddRacingWithMarkers:
    """A, an active VA, changes a direct marker through the M2.4 operation
    and keeps the Ticket lock; B, the public-mode add
    (`allow_excluded_reresolution = False`), waits. A assigns the Ticket
    and commits; B decides from the committed marker during its own
    serialized turn."""

    @CONTEXTS
    @pytest.mark.parametrize("kind", KINDS)
    async def test_add_after_a_committed_package_exclusion_is_rejected(
        self,
        world: CommittedWorld,
        monkeypatch: pytest.MonkeyPatch,
        kind: str,
        context: str,
    ) -> None:
        """B raises `PackageAlreadyExcludedError` before any local mutation,
        even when it would add a maintainer or complete the tree: no write,
        record, association, event, assignment, reconciliation, or
        convergence registration."""
        w = await _marker_world(world, system=context == "system")
        pkg = w.path.subject["package"]
        tracks, emails = _input(kind, w.path, w.p1, w.p2, w.p3, w.m)
        assign = Spy(monkeypatch, "auto_assign_actor")
        reconcile = Spy(monkeypatch, "reconcile_ticket_status")
        holder = await world.open_session()
        waiter = await world.open_session()

        await path_call(holder, Level.PACKAGE, Direction.EXCLUDE, w.path, w.actor_a)
        _, recorder = await _behind(
            world,
            holder,
            waiter,
            add_records(
                waiter, w.ticket.id, pkg, tracks, actor=w.actor_b, emails=emails
            ),
            user_root=w.actor_b is not None,
            error=PackageAlreadyExcludedError,
        )

        assert recorder.writes() == []
        assert _sessions(assign, 2) == [holder]
        assert _sessions(reconcile, 1) == [holder]
        assert pending_ticket_convergence_effects(waiter) == ()
        await waiter.rollback()
        assert await _committed(world, w.ticket.id, pkg) == _State(
            (ANALYSIS, w.actor_a.id),
            [
                assignment_event(w.actor_a),
                path_event(Level.PACKAGE, Direction.EXCLUDE, w.path, w.actor_a),
            ],
            _path_tree(
                w.path, package=MARKER_NOW, track=None, product=None, product_id=w.p1
            ),
            [],
        )

    @CONTEXTS
    @pytest.mark.parametrize("kind", KINDS)
    async def test_add_after_a_committed_package_restore_proceeds(
        self,
        world: CommittedWorld,
        monkeypatch: pytest.MonkeyPatch,
        kind: str,
        context: str,
    ) -> None:
        """The package starts directly excluded, so B would be rejected
        before the lock; after A's restore commits the guard no longer
        applies and B reaches its locked no-op, maintainer-only, or
        package-tree outcome."""
        w = await _marker_world(world, seeded=Level.PACKAGE, system=context == "system")
        pkg = w.path.subject["package"]
        tracks, emails = _input(kind, w.path, w.p1, w.p2, w.p3, w.m)
        reconcile = Spy(monkeypatch, "reconcile_ticket_status")
        holder = await world.open_session()
        waiter = await world.open_session()

        await path_call(holder, Level.PACKAGE, Direction.RESTORE, w.path, w.actor_a)
        result, _ = await _behind(
            world,
            holder,
            waiter,
            add_records(
                waiter, w.ticket.id, pkg, tracks, actor=w.actor_b, emails=emails
            ),
            user_root=w.actor_b is not None,
        )
        await waiter.commit()

        assert result is not None
        assert outcome(result) == EXPECTED_OUTCOME[kind]
        assert _sessions(reconcile, 1) == (
            [holder, waiter] if kind == "tree" else [holder]
        )
        assert await _committed(world, w.ticket.id, pkg) == _State(
            (ANALYSIS, w.actor_a.id),
            [
                assignment_event(w.actor_a),
                path_event(Level.PACKAGE, Direction.RESTORE, w.path, w.actor_a),
                *_tree_events(kind, w),
            ],
            _with_new_rows(
                _path_tree(
                    w.path, package=None, track=None, product=None, product_id=w.p1
                ),
                kind,
                w,
            ),
            [(pkg, w.m.id)] if kind != "no-op" else [],
        )

    @pytest.mark.parametrize("direction", list(Direction), ids=str)
    @pytest.mark.parametrize("level", [Level.TRACK, Level.PRODUCT], ids=str)
    async def test_add_racing_with_a_track_or_product_marker_proceeds(
        self,
        world: CommittedWorld,
        level: Level,
        direction: Direction,
    ) -> None:
        """Only the package's direct marker is a guard. After a committed
        track or Product exclusion or restore, B completes the tree and
        adds M: the existing (possibly excluded) track and occurrence are
        skips, the new occurrence beneath an excluded track is created
        with `deleted_at = NULL`, and A's marker is left as committed."""
        restore = direction is Direction.RESTORE
        w = await _marker_world(world, seeded=level if restore else None)
        pkg = w.path.subject["package"]
        tracks, emails = _input("tree", w.path, w.p1, w.p2, w.p3, w.m)
        holder = await world.open_session()
        waiter = await world.open_session()

        await path_call(holder, level, direction, w.path, w.actor_a)
        result, _ = await _behind(
            world,
            holder,
            waiter,
            add_records(
                waiter, w.ticket.id, pkg, tracks, actor=w.actor_b, emails=emails
            ),
            user_root=True,
        )
        await waiter.commit()

        assert result is not None
        assert outcome(result) == changed(1, 1, 2, 1)
        marker = None if restore else MARKER_NOW
        expected = with_target((None, None, None), level, marker)
        probe = await world.open_session()
        assert await markers_by_id(probe, w.path.id) == expected
        await probe.rollback()
        assert await _committed(world, w.ticket.id, pkg) == _State(
            (ANALYSIS, w.actor_a.id),
            [
                assignment_event(w.actor_a),
                path_event(level, direction, w.path, w.actor_a),
                *_tree_events("tree", w),
            ],
            _with_new_rows(
                _path_tree(
                    w.path,
                    package=None,
                    track=expected[1],
                    product=expected[2],
                    product_id=w.p1,
                ),
                "tree",
                w,
            ),
            [(pkg, w.m.id)],
        )


@pytest.mark.integration
class TestReresolutionBeneathAnExclusion:
    @pytest.mark.parametrize("kind", ["descendants", "maintainer-only"])
    async def test_reresolution_after_a_committed_package_exclusion(
        self,
        world: CommittedWorld,
        monkeypatch: pytest.MonkeyPatch,
        kind: str,
    ) -> None:
        """The package holds `T1: {P1 excluded}` and an excluded track
        `T0: {P0}`. After A's package exclusion commits, the Ticket
        convergence call (`allow_excluded_reresolution = True`) proceeds:
        `descendants` creates the missing `P2` under `T1` and the new
        `GIT_REF: {P3}` plus M's association; `maintainer-only` adds only
        M. Neither clears or sets any package, track, or Product marker,
        and the events carry the system actor and the exact comment."""
        w = await _marker_world(world, seeded=Level.PRODUCT, system=True)
        pkg = w.path.subject["package"]
        sibling = await committed_path(
            world, w.ticket, package_id=w.path.package_id, track_excluded=True
        )
        p0 = await _product_of(world, sibling)
        t1, t0 = w.path.subject["track"], sibling.subject["track"]
        tracks = [target(t1, w.p1), target(t0, p0)]
        if kind == "descendants":
            tracks = [
                target(t1, w.p1, w.p2),
                target(t0, p0),
                target(GIT_REF, w.p3, workflow=WorkflowType.GIT),
            ]
        reconcile = Spy(monkeypatch, "reconcile_ticket_status")
        holder = await world.open_session()
        waiter = await world.open_session()

        await path_call(holder, Level.PACKAGE, Direction.EXCLUDE, w.path, w.actor_a)
        result, _ = await _behind(
            world,
            holder,
            waiter,
            add_records(
                waiter,
                w.ticket.id,
                pkg,
                tracks,
                emails={w.m.email},
                comment=CONVERGENCE,
                reresolution=True,
            ),
            user_root=False,
        )
        await waiter.commit()

        descendants = kind == "descendants"
        assert result is not None
        if descendants:
            assert outcome(result) == changed(1, 2, 2, 2)
            ids = await _track_ids(world, w.ticket.id, pkg)
            assert result.created_tracks == (
                CreatedTrack(ids[GIT_REF], GIT_REF, WorkflowType.GIT),
            )
        else:
            assert outcome(result) == (
                PackageRecordsOutcome.MAINTAINER_ONLY,
                0,
                2,
                0,
                2,
            )
        assert _sessions(reconcile, 1) == (
            [holder, waiter] if descendants else [holder]
        )
        probe = await world.open_session()
        assert await markers_by_id(probe, w.path.id) == (MARKER_NOW, None, SEEDED_AT)
        assert await markers_by_id(probe, sibling.id) == (MARKER_NOW, SEEDED_AT, None)
        await probe.rollback()
        tracks_state = {
            t1: TrackState("ibs", "ANALYSIS", "PENDING", None),
            t0: TrackState("ibs", "ANALYSIS", "PENDING", SEEDED_AT),
        }
        occurrences = {
            (t1, w.p1): OccurrenceState(True, False, None, SEEDED_AT),
            (t0, p0): OccurrenceState(True, False, None, None),
        }
        if descendants:
            tracks_state[GIT_REF] = NEW_TRACK[WorkflowType.GIT]
            occurrences |= {
                (t1, w.p2.id): new_occurrence(True),
                (GIT_REF, w.p3.id): new_occurrence(True),
            }
        assert await _committed(world, w.ticket.id, pkg) == _State(
            (ANALYSIS, w.actor_a.id),
            [
                assignment_event(w.actor_a),
                path_event(Level.PACKAGE, Direction.EXCLUDE, w.path, w.actor_a),
                maintainer_event(pkg, w.m),
                *([package_added_event(pkg, None, CONVERGENCE)] if descendants else []),
            ],
            Tree(MARKER_NOW, tracks_state, occurrences),
            [(pkg, w.m.id)],
        )


# ---------------------------------------------------------------------------
# Atomic consumer accessibility (consumer-mutation part): locked-current
# state (testing-strategy.md, Ticket Accessibility: Locked mutations)
# ---------------------------------------------------------------------------

LOSSES = ["confidentiality-set", "grant-revoked", "last-package-excluded"]
"""The Ticket-scoped visibility losses of testing-strategy.md, Locked
mutations (`association-changed` is a CVE-scoped loss)."""

REQUESTS = [
    "would-create",
    "existing-tree",
    "existing-tree-own-email",
    "ignored",
    "active-ticket-only-resolved",
]
"""A's request, each of which would otherwise reach a different decision.
`would-create`: a new package tree with A's own email (a package-tree
change that would make A its maintainer). `existing-tree`: exactly a
committed tree, no email (a package-tree no-op; for
`last-package-excluded` the tree lies under the excluded maintained
package, a would-be `PackageAlreadyExcludedError`). `existing-tree-own-
email`: the same with A's own email (a would-be maintainer-only mutation,
or the excluded-package guard). `ignored`: B also makes the Ticket
`Ignored` (a would-be `TicketNotMutableError`) for a `would-create` input.
`active-ticket-only-resolved`: B also makes the Ticket `Resolved` and A
passes `active_ticket_only` (a would-be skip)."""


async def _existing_package(world: CommittedWorld, ticket: Ticket) -> uuid.UUID | None:
    """The Ticket's maintained package created by `prepare_loss()`, if any."""
    package_id = (
        await world.session.execute(
            select(TicketPackage.id).where(TicketPackage.ticket_id == ticket.id)
        )
    ).scalar_one_or_none()
    await world.session.commit()
    return package_id


async def _protected_state(
    world: CommittedWorld, ticket_id: uuid.UUID
) -> tuple[Any, ...]:
    """The committed assignee, events, maintainer associations, and every
    package-tree row with the package markers left out (B's
    `last-package-excluded` loss sets one)."""
    probe = await world.open_session()
    _status, assignee = await ticket_row(probe, ticket_id)
    rows = [
        r[:3] if r[0] == "package" else r for r in await tree_rows(probe, ticket_id)
    ]
    state = (
        assignee,
        await ticket_events_by_id(probe, ticket_id),
        rows,
        await maintainers(probe, ticket_id),
    )
    await probe.rollback()
    return state


def _assert_denied_without_effects(
    recorder: StatementRecorder,
    session: AsyncSession,
    assign: Spy,
    reconcile: Spy,
) -> None:
    """Zero domain write, assignment, reconciliation, and convergence
    registration, and no excluded-package, no-op, idempotency, or
    maintainer-match read before the denial."""
    assert recorder.writes() == []
    assert (assign.calls, reconcile.calls) == ([], [])
    assert pending_ticket_convergence_effects(session) == ()
    assert [s for s in recorder.statements if any(p in s for p in UNDECIDED)] == []


@pytest.mark.integration
class TestLockedCurrentAccessibilityRaces:
    """A `restricted_analyst` caller (effective scope `non_confidential`)
    can access the Ticket through exactly one path; session B removes that
    path. A then acquires the Ticket lock and must raise
    `TicketNotFoundError` from the locked-current state with zero side
    effects, even when its own email is a supplied maintainer email
    (fetched but unpersisted maintainer data cannot authorize), and before
    any operability, `active_ticket_only`, excluded-package, no-op, or
    idempotency decision (package-service.md, step 2; Consumer caller
    context and Ticket accessibility; package-maintainership.md,
    Confidential Ticket Visibility)."""

    @pytest.mark.parametrize("request_kind", REQUESTS)
    @pytest.mark.parametrize("loss", LOSSES)
    async def test_add_blocked_behind_the_visibility_loss_is_not_found(
        self,
        world: CommittedWorld,
        monkeypatch: pytest.MonkeyPatch,
        loss: str,
        request_kind: str,
    ) -> None:
        """B applies the loss while holding the Ticket `FOR UPDATE`; A takes
        its acting User `FOR SHARE` and is proven blocked on the Ticket
        lock; B commits."""
        user, _cve, ticket, statements = await prepare_loss(world, loss)
        if request_kind.startswith("existing-tree"):
            path = await committed_path(
                world, ticket, package_id=await _existing_package(world, ticket)
            )
            pkg = path.subject["package"]
            tracks = [target(path.subject["track"], await _product_of(world, path))]
        else:
            pkg = _name()
            tracks = [target(IBS_REF, await _product(world))]
        emails = set() if request_kind == "existing-tree" else {user.email}
        status = {
            "ignored": TicketStatus.IGNORED,
            "active-ticket-only-resolved": TicketStatus.RESOLVED,
        }.get(request_kind, TicketStatus.ANALYSIS)
        if status is not TicketStatus.ANALYSIS:
            statements.append(
                update(Ticket).where(Ticket.id == ticket.id).values(status=status.value)
            )
        before = await _protected_state(world, ticket.id)
        assign = Spy(monkeypatch, "auto_assign_actor")
        reconcile = Spy(monkeypatch, "reconcile_ticket_status")
        a = await world.open_session()
        b = await world.open_session()

        for statement in statements:
            await b.execute(statement)
        with SessionStatementRecorder(a) as recorder:
            task = world.start(
                a,
                add_records(
                    a,
                    ticket.id,
                    pkg,
                    tracks,
                    actor=user,
                    emails=emails,
                    scope=Scope.NON_CONFIDENTIAL,
                    active_ticket_only=request_kind == "active-ticket-only-resolved",
                ),
            )
            await assert_lock_wait(task, waiter=a, blocked_by=b)
            _assert_blocked_at_ticket_root(recorder.statements, user_root=True)
            await b.commit()
            with pytest.raises(TicketNotFoundError):
                await asyncio.wait_for(task, timeout=WAIT)

        _assert_denied_without_effects(recorder, a, assign, reconcile)
        await a.rollback()
        assert await _protected_state(world, ticket.id) == before
        state = await _committed(world, ticket.id, pkg)
        assert state.ticket == (status.value, None)
        assert state.events == []
        if loss == "last-package-excluded":
            assert state.maintainers == [("fictional-race-a", user.id)]

    @pytest.mark.parametrize("loss", LOSSES)
    async def test_add_paused_before_its_first_root_lock_is_not_found(
        self,
        world: CommittedWorld,
        monkeypatch: pytest.MonkeyPatch,
        loss: str,
    ) -> None:
        """A is paused on an `asyncio.Event` immediately before its first
        root lock (the acting-User stabilization), having issued no
        statement; B applies and commits the loss; A then takes the User
        and Ticket locks and is denied, with its own email supplied for a
        would-be package-tree change."""
        user, _cve, ticket, statements = await prepare_loss(world, loss)
        product = await _product(world)
        pkg = _name()
        arrived = asyncio.Event()
        release = asyncio.Event()

        async def paused(db: AsyncSession, user_id: uuid.UUID) -> User:
            arrived.set()
            await release.wait()
            return await stabilize_acting_user(db, user_id)

        monkeypatch.setattr(package_service, "stabilize_acting_user", paused)
        before = await _protected_state(world, ticket.id)
        assign = Spy(monkeypatch, "auto_assign_actor")
        reconcile = Spy(monkeypatch, "reconcile_ticket_status")
        a = await world.open_session()
        b = await world.open_session()

        try:
            with SessionStatementRecorder(a) as recorder:
                task = world.start(
                    a,
                    add_records(
                        a,
                        ticket.id,
                        pkg,
                        [target(IBS_REF, product)],
                        actor=user,
                        emails={user.email},
                        scope=Scope.NON_CONFIDENTIAL,
                    ),
                )
                await asyncio.wait_for(arrived.wait(), timeout=WAIT)
                assert recorder.statements == []
                for statement in statements:
                    await b.execute(statement)
                await b.commit()
                release.set()
                with pytest.raises(TicketNotFoundError):
                    await asyncio.wait_for(task, timeout=WAIT)
        finally:
            release.set()

        assert _is_user_share(recorder.statements[0])
        assert _is_ticket_lock(
            next(s for s in recorder.statements if TICKET_STATEMENT.search(s))
        )
        _assert_denied_without_effects(recorder, a, assign, reconcile)
        await a.rollback()
        assert await _protected_state(world, ticket.id) == before
        state = await _committed(world, ticket.id, pkg)
        assert (state.ticket, state.events, state.tree) == ((ANALYSIS, None), [], None)
