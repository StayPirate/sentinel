"""Independent-session tests for `update_roles()`
(backend/app/services/user_service.py).

Owning specifications:

- docs/features/identity/user-service.md (`update_roles()`, Concurrency;
  Concurrency Considerations: Concurrent role modification from multiple
  entry points, Concurrent role removal and deactivation).
- docs/features/tickets/ticket-audit-log.md (Canonical Automatic Comment
  Vocabulary; Testing Requirement 23).
- docs/features/platform/testing-strategy.md (Concurrency Testing,
  Lock-Wait Observation; User Lifecycle and Management: concurrent removal
  of the final vulnerability-analyst role sources, Manual role mutation
  concurrency).

The single-session behavior of `update_roles()` is covered by
`tests/test_services/test_update_roles.py`; this module adds only what
needs independent sessions. Each race holds the winner's uncommitted
`update_roles()` in session A, proves that the loser in session B waits on
A's User lock, commits A, and lets B classify from the locked-current
state. The Ticket lock phase of the final VA-origin loss is proven the
other way round: a concurrent Ticket writer in session B holds one
candidate, and the removal in session A waits on it and revalidates the
locked-current row. The races against assignment-capable paths and against
deactivation are covered elsewhere.

Committed rows are deleted explicitly at teardown (testing-strategy.md,
Concurrency Testing). Expected values are transcribed from the
specifications, never computed with the module under test.
"""

from __future__ import annotations

import asyncio
import re
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass

import pytest
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import Role, TicketStatus
from app.models.ticket import Ticket
from app.models.user import User
from app.models.user_role import UserRole
from app.services.user_service import RoleUpdateResult
from tests.support.database import assert_lock_wait
from tests.support.identity_lifecycle_races import (
    MANUAL,
    VA_ROLE_REMOVED,
    IdentityEventRow,
    IdentityWorld,
    add_roles,
    identity_events,
    origins,
    remove_roles,
    role_added,
    role_removed,
)
from tests.support.suse_cvss_races import SessionStatementRecorder
from tests.support.ticket_mutations import (
    EventRow,
    ticket_events_by_id,
    unassigned_event,
)

Factory = Callable[[], Awaitable[AsyncSession]]
Mutation = Callable[[AsyncSession], Awaitable[RoleUpdateResult]]

# Stored `UserRole.role` values (docs/data-model.md, Role Enum).
_ADMIN = "Admin"
_VA = "Vulnerability Analyst"
_RA = "Restricted Analyst"

TICKET_STATEMENT = re.compile(r"\b(?:FROM|JOIN|INTO|UPDATE) ticket\b")
TICKET_LOCK = re.compile(r"\bFROM ticket\b.*\bFOR UPDATE\s*$", re.DOTALL)


@pytest.fixture
async def identity_world(db_session_factory: Factory) -> AsyncIterator[IdentityWorld]:
    world = IdentityWorld(db_session_factory, await db_session_factory())
    try:
        yield world
    finally:
        await world.cleanup()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _is_user_lock(statement: str) -> bool:
    return 'FROM "user"' in statement and "FOR NO KEY UPDATE" in statement


def _is_ticket_lock(statement: str) -> bool:
    return bool(TICKET_LOCK.search(statement))


def _touches_ticket(statements: list[str]) -> bool:
    return any(TICKET_STATEMENT.search(s) for s in statements)


@dataclass(frozen=True, slots=True)
class _Race:
    winner: RoleUpdateResult
    loser: RoleUpdateResult
    loser_statements: list[str]
    loser_writes: list[str]


async def _race(world: IdentityWorld, winner: Mutation, loser: Mutation) -> _Race:
    """Run `winner` uncommitted in session A, start `loser` in session B,
    prove that B waits on A with the User lock as its only statement so far
    (`update_roles()` step 2: the first persistent access), commit A, then
    let B finish and commit."""
    a = await world.open_session()
    b = await world.open_session()

    winner_result = await winner(a)
    with SessionStatementRecorder(b) as recorder:
        task = world.start(b, loser(b))
        await assert_lock_wait(task, waiter=b, blocked_by=a)
        waiting = list(recorder.statements)
        assert len(waiting) == 1
        assert _is_user_lock(waiting[0])
        await a.commit()
        loser_result = await asyncio.wait_for(task, timeout=5)
    await b.commit()
    return _Race(
        winner_result, loser_result, list(recorder.statements), recorder.writes()
    )


@dataclass(frozen=True, slots=True)
class _Committed:
    origins: set[tuple[str, str]]
    identity: list[IdentityEventRow]
    tickets: dict[uuid.UUID, tuple[str, uuid.UUID | None]]
    ticket_events: dict[uuid.UUID, list[EventRow]]


async def _committed(
    world: IdentityWorld, user: User, tickets: tuple[Ticket, ...] = ()
) -> _Committed:
    """The committed origins and Identity events of `user`, and the
    committed `(status, assignee_id)` and events of each Ticket, read
    through a fresh independent session."""
    probe = await world.open_session()
    rows = (
        await probe.execute(
            select(Ticket.id, Ticket.status, Ticket.assignee_id).where(
                Ticket.id.in_([t.id for t in tickets])
            )
        )
    ).all()
    committed = _Committed(
        origins=await origins(probe, user.id),
        identity=await identity_events(probe, user.id),
        tickets={row.id: (row.status, row.assignee_id) for row in rows},
        ticket_events={t.id: await ticket_events_by_id(probe, t.id) for t in tickets},
    )
    await probe.rollback()
    return committed


async def _assigned_ticket(
    world: IdentityWorld, user: User, status: TicketStatus = TicketStatus.ANALYSIS
) -> Ticket:
    return await world.ticket(cve_id=None, assignee_id=user.id, status=status)


async def _assigned_ticket_with_id(
    world: IdentityWorld, ticket_id: uuid.UUID, user: User
) -> Ticket:
    """A committed CVE-less `Analysis` Ticket with a chosen UUID, assigned to
    `user` and registered for teardown like `CommittedWorld.ticket()`."""
    ticket = Ticket(
        id=ticket_id,
        status=TicketStatus.ANALYSIS.value,
        cve_id=None,
        assignee_id=user.id,
    )
    world.session.add(ticket)
    await world.session.flush()
    world.ticket_ids.append(ticket.id)
    await world.session.commit()
    return ticket


def _actor(world: IdentityWorld) -> Awaitable[User]:
    return world.identity_user(prefix="alice.admin")


# ---------------------------------------------------------------------------
# Duplicate additions and removals
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestDuplicateMutations:
    """user-service.md, `update_roles()` Concurrency: the loser waits on the
    User lock, observes the winner's committed state, and is a no-op before
    any INSERT or DELETE (ticket-audit-log.md, Testing Requirement 23)."""

    async def test_duplicate_additions_insert_one_row_and_one_event(
        self, identity_world: IdentityWorld
    ) -> None:
        actor_a = await _actor(identity_world)
        actor_b = await _actor(identity_world)
        target = await identity_world.identity_user()

        race = await _race(
            identity_world,
            lambda s: add_roles(s, target, [Role.ADMIN], actor_a),
            lambda s: add_roles(s, target, [Role.ADMIN], actor_b),
        )

        assert (race.winner.added_roles, race.winner.removed_roles) == (
            [Role.ADMIN],
            [],
        )
        assert (race.loser.added_roles, race.loser.removed_roles) == ([], [])
        assert race.loser_writes == []
        probe = await identity_world.open_session()
        assigned_by = (
            await probe.execute(
                select(UserRole.assigned_by).where(UserRole.user_id == target.id)
            )
        ).scalar_one()
        await probe.rollback()
        assert assigned_by == actor_a.id
        committed = await _committed(identity_world, target)
        assert committed.origins == {(_ADMIN, MANUAL)}
        assert committed.identity == [role_added(actor_a, target, "admin")]

    async def test_duplicate_removals_delete_once_with_one_event(
        self, identity_world: IdentityWorld
    ) -> None:
        actor_a = await _actor(identity_world)
        actor_b = await _actor(identity_world)
        target = await identity_world.identity_user(manual=[Role.RESTRICTED_ANALYST])

        race = await _race(
            identity_world,
            lambda s: remove_roles(s, target, [Role.RESTRICTED_ANALYST], actor_a),
            lambda s: remove_roles(s, target, [Role.RESTRICTED_ANALYST], actor_b),
        )

        assert (race.winner.added_roles, race.winner.removed_roles) == (
            [],
            [Role.RESTRICTED_ANALYST],
        )
        assert (race.loser.added_roles, race.loser.removed_roles) == ([], [])
        assert race.loser_writes == []
        committed = await _committed(identity_world, target)
        assert committed.origins == set()
        assert committed.identity == [
            role_removed(actor_a, target, "restricted_analyst")
        ]


# ---------------------------------------------------------------------------
# Concurrent add and remove of the same role
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestConcurrentAddAndRemove:
    """testing-strategy.md, Manual role mutation concurrency: each
    transaction classifies its own effect from locked-current state, giving
    one effective mutation and event, or two in sequence when the add
    commits first; the final state matches the last committed
    transaction."""

    @pytest.mark.parametrize(
        ("initially_present", "first", "expected"),
        [
            # Absent role, add commits first: the add inserts, the waiting
            # remove observes the committed row and deletes it.
            (False, "add", ("inserted", "deleted", set(), ["added", "removed"])),
            # Absent role, remove commits first: the remove is a no-op, the
            # waiting add inserts.
            (False, "remove", ("none", "inserted", {(_RA, MANUAL)}, ["added"])),
            # Present role, add commits first: the add is a no-op, the
            # waiting remove deletes.
            (True, "add", ("none", "deleted", set(), ["removed"])),
            # Present role, remove commits first: the remove deletes, the
            # waiting add re-inserts.
            (
                True,
                "remove",
                ("deleted", "inserted", {(_RA, MANUAL)}, ["removed", "added"]),
            ),
        ],
        ids=[
            "absent-add-first",
            "absent-remove-first",
            "present-add-first",
            "present-remove-first",
        ],
    )
    async def test_lock_order_decides_the_final_state(
        self,
        identity_world: IdentityWorld,
        initially_present: bool,
        first: str,
        expected: tuple[str, str, set[tuple[str, str]], list[str]],
    ) -> None:
        winner_effect, loser_effect, final_origins, event_kinds = expected
        adder = await _actor(identity_world)
        remover = await _actor(identity_world)
        target = await identity_world.identity_user(
            manual=[Role.RESTRICTED_ANALYST] if initially_present else []
        )

        def add(s: AsyncSession) -> Awaitable[RoleUpdateResult]:
            return add_roles(s, target, [Role.RESTRICTED_ANALYST], adder)

        def remove(s: AsyncSession) -> Awaitable[RoleUpdateResult]:
            return remove_roles(s, target, [Role.RESTRICTED_ANALYST], remover)

        if first == "add":
            race = await _race(identity_world, add, remove)
        else:
            race = await _race(identity_world, remove, add)

        effects = {
            "none": ([], []),
            "inserted": ([Role.RESTRICTED_ANALYST], []),
            "deleted": ([], [Role.RESTRICTED_ANALYST]),
        }
        assert (race.winner.added_roles, race.winner.removed_roles) == effects[
            winner_effect
        ]
        assert (race.loser.added_roles, race.loser.removed_roles) == effects[
            loser_effect
        ]
        events = {
            "added": role_added(adder, target, "restricted_analyst"),
            "removed": role_removed(remover, target, "restricted_analyst"),
        }
        committed = await _committed(identity_world, target)
        assert committed.origins == final_origins
        assert committed.identity == [events[kind] for kind in event_kinds]


# ---------------------------------------------------------------------------
# Different roles of the same User; Admins removing each other
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestIndependentEffects:
    @pytest.mark.parametrize("first", ["add-admin", "remove-ra"])
    async def test_different_roles_of_one_user_serialize_and_both_apply(
        self, identity_world: IdentityWorld, first: str
    ) -> None:
        """user-service.md, `update_roles()` Concurrency: requests touching
        different roles of the same User serialize on the User lock; both
        effects apply and the events follow commit order."""
        actor_a = await _actor(identity_world)
        actor_b = await _actor(identity_world)
        target = await identity_world.identity_user(manual=[Role.RESTRICTED_ANALYST])

        def add(s: AsyncSession) -> Awaitable[RoleUpdateResult]:
            return add_roles(s, target, [Role.ADMIN], actor_a)

        def remove(s: AsyncSession) -> Awaitable[RoleUpdateResult]:
            return remove_roles(s, target, [Role.RESTRICTED_ANALYST], actor_b)

        added = role_added(actor_a, target, "admin")
        removed = role_removed(actor_b, target, "restricted_analyst")
        if first == "add-admin":
            race = await _race(identity_world, add, remove)
            adding, removing, order = race.winner, race.loser, [added, removed]
        else:
            race = await _race(identity_world, remove, add)
            adding, removing, order = race.loser, race.winner, [removed, added]

        assert (adding.added_roles, adding.removed_roles) == ([Role.ADMIN], [])
        assert (removing.added_roles, removing.removed_roles) == (
            [],
            [Role.RESTRICTED_ANALYST],
        )
        committed = await _committed(identity_world, target)
        assert committed.origins == {(_ADMIN, MANUAL)}
        assert committed.identity == order

    async def test_two_admins_removing_each_other_both_succeed(
        self, identity_world: IdentityWorld
    ) -> None:
        """user-service.md, `update_roles()` Business Rule 2 and
        testing-strategy.md, Manual role mutation concurrency: the self-Admin
        guard applies only when actor and target are the same User, so both
        removals succeed and can leave zero Admins. The requests lock
        different Users and need not serialize: each completes while the
        other is still uncommitted."""
        first = await identity_world.identity_user(
            manual=[Role.ADMIN], prefix="alice.admin"
        )
        second = await identity_world.identity_user(
            manual=[Role.ADMIN], prefix="carol.admin"
        )
        a = await identity_world.open_session()
        b = await identity_world.open_session()

        by_first = await asyncio.wait_for(
            remove_roles(a, second, [Role.ADMIN], first), timeout=5
        )
        by_second = await asyncio.wait_for(
            remove_roles(b, first, [Role.ADMIN], second), timeout=5
        )
        await a.commit()
        await b.commit()

        assert by_first.removed_roles == [Role.ADMIN]
        assert by_second.removed_roles == [Role.ADMIN]
        committed_first = await _committed(identity_world, first)
        committed_second = await _committed(identity_world, second)
        assert committed_first.origins == set()
        assert committed_second.origins == set()
        assert committed_first.identity == [role_removed(second, first, "admin")]
        assert committed_second.identity == [role_removed(first, second, "admin")]


# ---------------------------------------------------------------------------
# Final vulnerability_analyst origin loss
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestFinalVaOriginLoss:
    async def test_concurrent_final_va_removals_unassign_and_audit_once(
        self, identity_world: IdentityWorld
    ) -> None:
        """testing-strategy.md, User Lifecycle and Management: concurrent
        removal of the final vulnerability-analyst role sources serializes
        the remaining-role check; unassignment and audit happen exactly
        once, and the loser issues no Ticket statement."""
        actor_a = await _actor(identity_world)
        actor_b = await _actor(identity_world)
        target = await identity_world.identity_user(manual=[Role.VULNERABILITY_ANALYST])
        analysis = await _assigned_ticket(identity_world, target)
        analyzed = await _assigned_ticket(identity_world, target, TicketStatus.ANALYZED)

        race = await _race(
            identity_world,
            lambda s: remove_roles(s, target, [Role.VULNERABILITY_ANALYST], actor_a),
            lambda s: remove_roles(s, target, [Role.VULNERABILITY_ANALYST], actor_b),
        )

        assert race.winner.removed_roles == [Role.VULNERABILITY_ANALYST]
        assert (race.loser.added_roles, race.loser.removed_roles) == ([], [])
        assert race.loser_writes == []
        assert not _touches_ticket(race.loser_statements)
        committed = await _committed(identity_world, target, (analysis, analyzed))
        assert committed.origins == set()
        assert committed.identity == [
            role_removed(actor_a, target, "vulnerability_analyst")
        ]
        assert committed.tickets == {
            analysis.id: (TicketStatus.ANALYSIS, None),
            analyzed.id: (TicketStatus.ANALYZED, None),
        }
        unassigned = unassigned_event(target.username, VA_ROLE_REMOVED)
        assert committed.ticket_events == {
            analysis.id: [unassigned],
            analyzed.id: [unassigned],
        }

    async def test_removal_first_then_addition_keeps_the_ticket_cleared(
        self, identity_world: IdentityWorld
    ) -> None:
        """user-service.md, Concurrent role modification from multiple
        entry points: the removal commits first and clears the Ticket once;
        the waiting addition re-adds the manual VA row and restores no
        assignment."""
        remover = await _actor(identity_world)
        adder = await _actor(identity_world)
        target = await identity_world.identity_user(manual=[Role.VULNERABILITY_ANALYST])
        ticket = await _assigned_ticket(identity_world, target)

        race = await _race(
            identity_world,
            lambda s: remove_roles(s, target, [Role.VULNERABILITY_ANALYST], remover),
            lambda s: add_roles(s, target, [Role.VULNERABILITY_ANALYST], adder),
        )

        assert race.winner.removed_roles == [Role.VULNERABILITY_ANALYST]
        assert (race.loser.added_roles, race.loser.removed_roles) == (
            [Role.VULNERABILITY_ANALYST],
            [],
        )
        assert not _touches_ticket(race.loser_statements)
        committed = await _committed(identity_world, target, (ticket,))
        assert committed.origins == {(_VA, MANUAL)}
        assert committed.identity == [
            role_removed(remover, target, "vulnerability_analyst"),
            role_added(adder, target, "vulnerability_analyst"),
        ]
        assert committed.tickets == {ticket.id: (TicketStatus.ANALYSIS, None)}
        assert committed.ticket_events == {
            ticket.id: [unassigned_event(target.username, VA_ROLE_REMOVED)]
        }

    async def test_addition_first_then_removal_clears_the_ticket_once(
        self, identity_world: IdentityWorld
    ) -> None:
        """Converse lock order: the addition observes the present manual VA
        row and is a no-op; the waiting removal then removes the final VA
        origin and clears the Ticket once."""
        adder = await _actor(identity_world)
        remover = await _actor(identity_world)
        target = await identity_world.identity_user(manual=[Role.VULNERABILITY_ANALYST])
        ticket = await _assigned_ticket(identity_world, target)

        race = await _race(
            identity_world,
            lambda s: add_roles(s, target, [Role.VULNERABILITY_ANALYST], adder),
            lambda s: remove_roles(s, target, [Role.VULNERABILITY_ANALYST], remover),
        )

        assert (race.winner.added_roles, race.winner.removed_roles) == ([], [])
        assert race.loser.removed_roles == [Role.VULNERABILITY_ANALYST]
        committed = await _committed(identity_world, target, (ticket,))
        assert committed.origins == set()
        assert committed.identity == [
            role_removed(remover, target, "vulnerability_analyst")
        ]
        assert committed.tickets == {ticket.id: (TicketStatus.ANALYSIS, None)}
        assert committed.ticket_events == {
            ticket.id: [unassigned_event(target.username, VA_ROLE_REMOVED)]
        }


# ---------------------------------------------------------------------------
# Ticket lock phase of the final VA-origin loss
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestTicketLockRevalidation:
    """user-service.md, Concurrent role removal and deactivation: the final
    VA-origin loss locks the User, then the candidate Tickets in ascending
    UUID order, and revalidates each from its locked-current row; a
    candidate changed by a concurrent writer gets no clear and no event
    (testing-strategy.md, User Lifecycle and Management: stale candidates,
    reassignment winners)."""

    @pytest.mark.parametrize("change", ["reassigned", "resolved", "cleared"])
    async def test_waits_on_the_ticket_lock_and_revalidates_the_locked_row(
        self, identity_world: IdentityWorld, change: str
    ) -> None:
        admin = await _actor(identity_world)
        target = await identity_world.identity_user(manual=[Role.VULNERABILITY_ANALYST])
        other_va = await identity_world.identity_user(
            manual=[Role.VULNERABILITY_ANALYST], prefix="carol.va"
        )
        # Session B holds the first candidate in UUID order, so A blocks on
        # it before locking the second.
        held_id, other_id = sorted(uuid.uuid4() for _ in range(2))
        held = await _assigned_ticket_with_id(identity_world, held_id, target)
        other = await _assigned_ticket_with_id(identity_world, other_id, target)
        changes: dict[str, tuple[dict[str, object], tuple[str, uuid.UUID | None]]] = {
            "reassigned": (
                {"assignee_id": other_va.id},
                (TicketStatus.ANALYSIS, other_va.id),
            ),
            "resolved": (
                {"status": TicketStatus.RESOLVED.value},
                (TicketStatus.RESOLVED, target.id),
            ),
            # A concurrent sanitation clear.
            "cleared": ({"assignee_id": None}, (TicketStatus.ANALYSIS, None)),
        }
        values, held_state = changes[change]
        a = await identity_world.open_session()
        b = await identity_world.open_session()

        await b.execute(select(Ticket.id).where(Ticket.id == held_id).with_for_update())
        await b.execute(update(Ticket).where(Ticket.id == held_id).values(**values))
        with SessionStatementRecorder(a) as recorder:
            task = identity_world.start(
                a, remove_roles(a, target, [Role.VULNERABILITY_ANALYST], admin)
            )
            await assert_lock_wait(task, waiter=a, blocked_by=b)
            waiting = list(recorder.statements)
            await b.commit()
            result = await asyncio.wait_for(task, timeout=5)
        await a.commit()

        assert _is_user_lock(waiting[0])
        assert _is_ticket_lock(waiting[-1])
        assert result.removed_roles == [Role.VULNERABILITY_ANALYST]
        committed = await _committed(identity_world, target, (held, other))
        assert committed.origins == set()
        assert committed.identity == [
            role_removed(admin, target, "vulnerability_analyst")
        ]
        assert committed.tickets == {
            held_id: held_state,
            other_id: (TicketStatus.ANALYSIS, None),
        }
        assert committed.ticket_events == {
            held_id: [],
            other_id: [unassigned_event(target.username, VA_ROLE_REMOVED)],
        }


# ---------------------------------------------------------------------------
# UNIQUE backstop
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestUniqueBackstop:
    async def test_violation_from_a_non_conforming_writer_rolls_back_everything(
        self, identity_world: IdentityWorld
    ) -> None:
        """user-service.md, `update_roles()` Concurrency and Exceptions: a
        writer W inserts a `_manual` row without the User lock (its FK check
        takes only `FOR KEY SHARE`, which does not conflict with
        `FOR NO KEY UPDATE`). A, holding an earlier effective mutation of
        another User in the same transaction, locks the target, cannot see
        W's uncommitted row, classifies the role as missing, and waits on
        the UNIQUE index. After W commits, the violation propagates as a
        database error instead of a no-op, and A's rollback leaves nothing
        of its transaction."""
        actor = await _actor(identity_world)
        other = await identity_world.identity_user(prefix="carol.ra")
        target = await identity_world.identity_user()
        w = await identity_world.open_session()
        a = await identity_world.open_session()

        w.add(UserRole(user_id=target.id, role=_RA, group_name=MANUAL))
        await w.flush()
        earlier = await add_roles(a, other, [Role.RESTRICTED_ANALYST], actor)
        assert earlier.added_roles == [Role.RESTRICTED_ANALYST]
        with SessionStatementRecorder(a) as recorder:
            task = identity_world.start(
                a, add_roles(a, target, [Role.RESTRICTED_ANALYST], actor)
            )
            await assert_lock_wait(task, waiter=a, blocked_by=w)
            assert _is_user_lock(recorder.statements[0])
            assert (
                recorder.statements[-1]
                .lstrip()
                .upper()
                .startswith("INSERT INTO USER_ROLE")
            )
            await w.commit()
            with pytest.raises(IntegrityError) as raised:
                await asyncio.wait_for(task, timeout=5)

        driver_exception = raised.value.driver_exception
        assert getattr(driver_exception, "sqlstate", None) == "23505"
        assert (
            getattr(driver_exception, "constraint_name", None)
            == "uq_user_role_user_role_group"
        )
        await a.rollback()
        probe = await identity_world.open_session()
        assigned_by = (
            await probe.execute(
                select(UserRole.assigned_by).where(UserRole.user_id == target.id)
            )
        ).scalar_one()
        await probe.rollback()
        assert assigned_by is None
        committed_target = await _committed(identity_world, target)
        committed_other = await _committed(identity_world, other)
        assert committed_target.origins == {(_RA, MANUAL)}
        assert committed_target.identity == []
        assert committed_other.origins == set()
        assert committed_other.identity == []
