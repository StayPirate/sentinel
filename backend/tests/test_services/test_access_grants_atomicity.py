"""Independent-session tests for `grant_access()`, `revoke_access()`, and
`list_access_grants()` (backend/app/services/ticket_service.py).

Owning specifications:

- docs/features/tickets/ticket-service.md (Caller category and Ticket
  accessibility; Concurrency control; `set_confidentiality`, Concurrency
  and result; `grant_access`, Concurrency; `revoke_access`, Concurrency;
  `list_access_grants`; Architectural Test Requirements 8, 14 (race
  parts), 15 (grant part), and 16 (visibility lost before selection)).
- docs/features/identity/user-service.md (`update_user()`;
  `reactivate_user()`; Access grant concurrent with user lifecycle or
  rename).
- docs/features/tickets/ticket-audit-log.md (Event Type Contract:
  `access_grant_added`, `access_grant_removed`, `confidentiality_changed`;
  Testing Requirement 23).
- docs/features/platform/testing-strategy.md (Concurrency Testing; Ticket
  Accessibility: Single, nested, and assembled reads, Locked mutations, and
  the race list of Confidentiality and explicit access grants).

The single-session behavior (exact events, precedence, lock order, no-ops,
rollback, listing projection and order) is covered by
`tests/test_services/test_access_grants.py`; this module adds only what
needs independent sessions:

- grant/grant (ATR 8): one `created`, one `already_exists` carrying the
  winner's provenance, one row and one event; the waiter reaches no unique
  violation, so its transaction stays usable;
- grant then revoke, no-op revoke then grant, and revoke/revoke;
- confidentiality/grant and confidentiality/revoke in both orders;
- reactivation/grant in both orders, with the real
  `user_service.reactivate_user()`;
- rename/grant and rename/revoke in both orders, with the real
  `user_service.update_user()`, including a waiter that identified the
  target by its pre-rename username;
- locked-current accessibility races (ATR 15) for grant and revoke,
  including otherwise-no-op requests and an absent target;
- the listing: visibility lost after the preliminary locator resolution
  (ATR 16), and the acquisition direction.

Every race serializes a winner that keeps its locks in an open transaction
and a waiter proven blocked (`assert_blocked`) on a named lock: the target
User `FOR NO KEY UPDATE` when the winner holds that User (another grant or
revoke of the same target, a reactivation, or a rename, which lock it `FOR
UPDATE`), or the Ticket `FOR UPDATE` when the winner holds only the Ticket
(`set_confidentiality()`, or an accessibility-loss writer). A lifecycle or
rename waiter is proven blocked on its own User `FOR UPDATE`. Waiters hold
stale identity-map copies of the Ticket (and, for the lifecycle races, of
the target User), so their results prove classification from the state
observed after the winner commits.

Not applicable or deferred, hence not tested here:

- the deactivation/grant race: `user_service.deactivate_user()` does not
  exist yet; it is deferred to M4.1;
- the `association-changed` visibility loss of
  `tests.support.suse_cvss_races.VISIBILITY_LOSSES`: it is a CVE-path loss
  (testing-strategy.md, Locked mutations: "changing the CVE-to-Ticket
  association for a CVE-scoped operation"); every operation here is
  Ticket-scoped and the canonical predicate of a Ticket does not depend on
  its CVE association;
- the converse self-loss case of ATR 15 needs no second session and is
  covered single-session by `test_access_grants.py::TestSelfLoss`;
- confidentiality/confidentiality, owned by
  `tests/test_services/test_confidentiality_atomicity.py`.

Committed rows, including the `IdentityAuditEvent` rows of the real
lifecycle and rename writers, are deleted explicitly at teardown
(testing-strategy.md, Concurrency Testing). Every wait is bounded so a
regression fails instead of hanging. Expected values are transcribed from
the specifications, never computed with the module under test.
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
from sqlalchemy import delete, func, insert, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import Role, Scope
from app.core.exceptions import (
    InactiveUserError,
    TicketNotFoundError,
    UserNotFoundError,
)
from app.core.identifiers import format_ticket_id
from app.models.identity_audit_event import IdentityAuditEvent
from app.models.ticket import Ticket
from app.models.ticket_access_grant import TicketAccessGrant
from app.models.user import User
from app.services.ticket_convergence_registry import (
    pending_ticket_convergence_effects,
)
from app.services.ticket_service import (
    AccessGrantAction,
    AccessGrantProjection,
    TicketNotConfidentialError,
    TicketUserProjection,
    grant_access,
    list_access_grants,
    resolve_ticket_locator,
    revoke_access,
    set_confidentiality,
)
from app.services.ticket_visibility import TicketCaller
from app.services.user_service import reactivate_user, update_user
from tests.support.suse_cvss_races import (
    CommittedWorld,
    SessionStatementRecorder,
    assert_blocked,
    prepare_loss,
)
from tests.support.ticket_mutations import (
    EventRow,
    StatementRecorder,
    ticket_events_by_id,
)

Factory = Callable[[], Awaitable[AsyncSession]]
Call = Callable[[AsyncSession], Awaitable[Any]]
GrantRow = tuple[uuid.UUID, uuid.UUID, datetime]
"""A persisted grant as `(user_id, granted_by_id, granted_at)`."""
Committed = tuple[bool, list[GrantRow], list[EventRow]]
"""The committed `is_confidential`, grants in `user_id` order, and audit
events of a Ticket."""

PAST = datetime(2026, 3, 15, 10, 30, tzinfo=UTC)
"""The original grant time of every pre-existing grant."""
EARLIER = datetime(2026, 2, 1, 9, 0, tzinfo=UTC)

TICKET_STATEMENT = re.compile(r"\b(?:FROM|JOIN|INTO|UPDATE) ticket\b")
WAIT = 5
"""Upper bound, in seconds, of every wait that is expected to finish."""

TARGET = "target"
"""The target User `FOR NO KEY UPDATE` of a grant or revoke."""
USER = "user"
"""The User `FOR UPDATE` of `reactivate_user()` and `update_user()`."""
TICKET = "ticket"
"""The Ticket `FOR UPDATE`."""


# ---------------------------------------------------------------------------
# Committed world and helpers
# ---------------------------------------------------------------------------


class _World(CommittedWorld):
    """`CommittedWorld` whose cleanup also deletes the `IdentityAuditEvent`
    rows committed by `reactivate_user()` and `update_user()`: they
    reference the world's Users (`ON DELETE RESTRICT`), and the shared
    cleanup does not know them."""

    async def cleanup(self) -> None:
        await self._release()
        await self.session.rollback()
        await self.session.execute(
            delete(IdentityAuditEvent).where(
                or_(
                    IdentityAuditEvent.target_user_id.in_(self.user_ids),
                    IdentityAuditEvent.user_id.in_(self.user_ids),
                )
            )
        )
        await self.session.commit()
        await super().cleanup()


@pytest.fixture
async def world(db_session_factory: Factory) -> AsyncIterator[CommittedWorld]:
    created = _World(db_session_factory, await db_session_factory())
    try:
        yield created
    finally:
        await created.cleanup()


@pytest.fixture
async def probe(world: CommittedWorld) -> AsyncSession:
    """An independent session that only observes committed state."""
    return await world.open_session()


async def _analyst(world: CommittedWorld) -> User:
    """A committed acting user (`vulnerability_analyst`, scope `all`)."""
    return await world.user(role=Role.VULNERABILITY_ANALYST)


async def _person(world: CommittedWorld, *, active: bool = True) -> User:
    """A committed prospective grant target (`restricted_analyst`)."""
    user = await world.user(role=Role.RESTRICTED_ANALYST)
    if not active:
        # The committed pre-state of an earlier deactivation.
        await world.session.execute(
            update(User).where(User.id == user.id).values(active=False)
        )
        await world.session.commit()
    return user


async def _grant_row(
    world: CommittedWorld, ticket: Ticket, user: User, granter: User
) -> None:
    """A committed pre-existing grant with the original time `PAST`."""
    await world.session.execute(
        insert(TicketAccessGrant).values(
            ticket_id=ticket.id,
            user_id=user.id,
            granted_by_id=granter.id,
            granted_at=PAST,
        )
    )
    await world.session.commit()


def _caller(actor: User, scope: Scope) -> TicketCaller:
    return TicketCaller.authenticated(actor.id, scope)


def _granting(
    ticket: Ticket, target: str, actor: User, *, scope: Scope = Scope.ALL
) -> Call:
    def call(db: AsyncSession) -> Awaitable[Any]:
        return grant_access(
            db,
            ticket_id=ticket.id,
            target_user=target,
            acting_user_id=actor.id,
            caller=_caller(actor, scope),
        )

    return call


def _revoking(
    ticket: Ticket, target: str, actor: User, *, scope: Scope = Scope.ALL
) -> Call:
    def call(db: AsyncSession) -> Awaitable[Any]:
        return revoke_access(
            db,
            ticket_id=ticket.id,
            target_user=target,
            acting_user_id=actor.id,
            caller=_caller(actor, scope),
        )

    return call


def _operation(
    op: str, ticket: Ticket, target: str, actor: User, *, scope: Scope = Scope.ALL
) -> Call:
    build = _granting if op == "grant" else _revoking
    return build(ticket, target, actor, scope=scope)


def _declassifying(ticket: Ticket, actor: User) -> Call:
    def call(db: AsyncSession) -> Awaitable[Any]:
        return set_confidentiality(
            db,
            ticket_id=ticket.id,
            is_confidential=False,
            acting_user_id=actor.id,
            caller=_caller(actor, Scope.ALL),
        )

    return call


def _reactivating(user: User, actor: User) -> Call:
    def call(db: AsyncSession) -> Awaitable[Any]:
        return reactivate_user(db, user.id, acting_user_id=actor.id)

    return call


def _renaming(user: User, username: str, actor: User) -> Call:
    def call(db: AsyncSession) -> Awaitable[Any]:
        return update_user(db, user.id, acting_user_id=actor.id, username=username)

    return call


def _rejected(call: Call, error: type[Exception]) -> Call:
    """`call`, which must raise `error` without any write statement."""

    async def wrapped(db: AsyncSession) -> None:
        with SessionStatementRecorder(db) as recorder, pytest.raises(error):
            await call(db)
        assert recorder.writes() == []

    return wrapped


def _added(actor: User, username: str) -> EventRow:
    """The acting-user `access_grant_added` (ticket-audit-log.md, Event
    Type Contract): `new_value` the target username, all else `NULL`."""
    return EventRow("access_grant_added", actor.id, None, username, None, None)


def _removed(actor: User, username: str) -> EventRow:
    """The acting-user `access_grant_removed`: `old_value` the target
    username, all else `NULL`."""
    return EventRow("access_grant_removed", actor.id, username, None, None, None)


def _declassified(actor: User) -> EventRow:
    """The acting-user `confidentiality_changed` from `"true"` to
    `"false"`."""
    return EventRow("confidentiality_changed", actor.id, "true", "false", None, None)


def _lock_kind(statement: str) -> str:
    text = statement.rstrip()
    if 'FROM "user"' in text and text.endswith("FOR NO KEY UPDATE"):
        return TARGET
    if 'FROM "user"' in text and text.endswith("FOR UPDATE"):
        return USER
    if TICKET_STATEMENT.search(text) is not None and text.endswith("FOR UPDATE"):
        return TICKET
    return statement


def _locks(recorder: StatementRecorder) -> list[str]:
    """The kinds of the recorded row locks, in acquisition order."""
    return [_lock_kind(s) for s in recorder.row_locks()]


async def _now(db: AsyncSession) -> datetime:
    """PostgreSQL `now()`: the transaction timestamp that the
    `granted_at` server default of a grant created in this transaction
    receives (issue #694, D6)."""
    return (await db.execute(select(func.now()))).scalar_one()


async def _committed(probe: AsyncSession, ticket: Ticket) -> Committed:
    confidential = (
        await probe.execute(
            select(Ticket.is_confidential).where(Ticket.id == ticket.id)
        )
    ).scalar_one()
    grants = [
        (row.user_id, row.granted_by_id, row.granted_at)
        for row in await probe.execute(
            select(
                TicketAccessGrant.user_id,
                TicketAccessGrant.granted_by_id,
                TicketAccessGrant.granted_at,
            )
            .where(TicketAccessGrant.ticket_id == ticket.id)
            .order_by(TicketAccessGrant.user_id)
        )
    ]
    events = await ticket_events_by_id(probe, ticket.id)
    await probe.rollback()
    return confidential, grants, events


async def _identity(
    probe: AsyncSession, user: User
) -> tuple[str, list[tuple[str, uuid.UUID | None, str | None, str | None]]]:
    """The committed username of `user` and its identity events."""
    username = (
        await probe.execute(select(User.username).where(User.id == user.id))
    ).scalar_one()
    events = [
        (e.event_type, e.user_id, e.old_value, e.new_value)
        for e in (
            await probe.execute(
                select(IdentityAuditEvent)
                .where(IdentityAuditEvent.target_user_id == user.id)
                .order_by(IdentityAuditEvent.id)
            )
        ).scalars()
    ]
    await probe.rollback()
    return username, events


@dataclass(frozen=True, slots=True)
class _Race:
    """The outcome of `_serialize()`: both transaction timestamps, the
    winner's return value, and the waiter's session (transaction still
    open), recorder, and finished task."""

    winner_now: datetime
    waiter_now: datetime
    winner_result: Any
    waiter: AsyncSession
    recorder: StatementRecorder
    task: asyncio.Task[Any]


async def _serialize(
    world: CommittedWorld,
    ticket: Ticket,
    first: Call,
    then: Call,
    *,
    blocked_on: list[str],
    stale: User | None = None,
    release: str = "commit",
) -> _Race:
    """Run `first` in a winner session that keeps its locks, start `then`
    in a waiter session holding stale copies of the Ticket (and of
    `stale`), and prove the waiter blocked: its statements so far are
    exactly the row locks `blocked_on`, the last being the one it waits
    for. Then end the winner (`release`: `commit`, or `rollback` after a
    rejected winner, as the API transaction dependency would) and wait,
    bounded, for the waiter to finish."""
    winner = await world.open_session()
    waiter = await world.open_session()
    winner_now = await _now(winner)
    waiter_now = await _now(waiter)
    assert await waiter.get(Ticket, ticket.id) is not None
    if stale is not None:
        assert await waiter.get(User, stale.id) is not None

    winner_result = await first(winner)
    with SessionStatementRecorder(waiter) as recorder:
        task: asyncio.Task[Any] = world.start(waiter, then(waiter))
        await assert_blocked(task)
        assert [_lock_kind(s) for s in recorder.statements] == blocked_on
        if release == "commit":
            await winner.commit()
        else:
            await winner.rollback()
        done, _pending = await asyncio.wait({task}, timeout=WAIT)
        assert task in done
    return _Race(winner_now, waiter_now, winner_result, waiter, recorder, task)


# ---------------------------------------------------------------------------
# Grant and revoke of one target (ATR 8; `revoke_access`, Concurrency)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestGrantRevokeRaces:
    """Both operations lock the same target User first, so the waiter is
    blocked on that `FOR NO KEY UPDATE` before requesting the Ticket."""

    async def test_concurrent_identical_grants_create_one_grant(
        self, world: CommittedWorld, probe: AsyncSession
    ) -> None:
        """ATR 8 and testing-strategy.md (grant/grant, unique-key
        backstop): the waiter, which identifies the same target by its
        username, returns the winner-current row as `already_exists` with
        the winner's provenance, issues no write (so no unique violation is
        reached), and its transaction remains usable."""
        first_actor = await _analyst(world)
        second_actor = await _analyst(world)
        target = await _person(world)
        ticket = await world.ticket(cve_id=None, is_confidential=True)

        race = await _serialize(
            world,
            ticket,
            _granting(ticket, str(target.id), first_actor),
            _granting(ticket, target.username, second_actor),
            blocked_on=[TARGET],
        )

        assert race.winner_result.action is AccessGrantAction.CREATED
        result = race.task.result()
        assert result.action is AccessGrantAction.ALREADY_EXISTS
        assert (
            result.grant.user_id,
            result.grant.granted_by_id,
            result.grant.granted_at,
        ) == (target.id, first_actor.id, race.winner_now)
        assert result.projection.granted_by.id == first_actor.id
        assert result.projection.granted_at == race.winner_now
        assert race.recorder.writes() == []
        assert _locks(race.recorder) == [TARGET, TICKET]
        # The transaction is not aborted: a further statement and the
        # commit succeed.
        count = (
            await race.waiter.execute(
                select(func.count())
                .select_from(TicketAccessGrant)
                .where(TicketAccessGrant.ticket_id == ticket.id)
            )
        ).scalar_one()
        assert count == 1
        await race.waiter.commit()
        assert await _committed(probe, ticket) == (
            True,
            [(target.id, first_actor.id, race.winner_now)],
            [_added(first_actor, target.username)],
        )

    async def test_grant_then_revoke_leaves_no_grant(
        self, world: CommittedWorld, probe: AsyncSession
    ) -> None:
        granter = await _analyst(world)
        revoker = await _analyst(world)
        target = await _person(world)
        ticket = await world.ticket(cve_id=None, is_confidential=True)

        race = await _serialize(
            world,
            ticket,
            _granting(ticket, str(target.id), granter),
            _revoking(ticket, str(target.id), revoker),
            blocked_on=[TARGET],
        )

        assert race.task.result() is None
        assert _locks(race.recorder) == [TARGET, TICKET]
        await race.waiter.commit()
        assert await _committed(probe, ticket) == (
            True,
            [],
            [_added(granter, target.username), _removed(revoker, target.username)],
        )

    async def test_no_op_revoke_then_grant_leaves_the_new_grant(
        self, world: CommittedWorld, probe: AsyncSession
    ) -> None:
        revoker = await _analyst(world)
        granter = await _analyst(world)
        target = await _person(world)
        ticket = await world.ticket(cve_id=None, is_confidential=True)

        race = await _serialize(
            world,
            ticket,
            _revoking(ticket, str(target.id), revoker),
            _granting(ticket, str(target.id), granter),
            blocked_on=[TARGET],
        )

        assert race.winner_result is None
        assert race.task.result().action is AccessGrantAction.CREATED
        await race.waiter.commit()
        assert await _committed(probe, ticket) == (
            True,
            [(target.id, granter.id, race.waiter_now)],
            [_added(granter, target.username)],
        )

    async def test_second_revoke_is_a_no_op(
        self, world: CommittedWorld, probe: AsyncSession
    ) -> None:
        """The waiter observes the committed deletion: no write and no
        second event (audit Testing Requirement 23)."""
        granter = await _analyst(world)
        first_actor = await _analyst(world)
        second_actor = await _analyst(world)
        target = await _person(world)
        ticket = await world.ticket(cve_id=None, is_confidential=True)
        await _grant_row(world, ticket, target, granter)

        race = await _serialize(
            world,
            ticket,
            _revoking(ticket, str(target.id), first_actor),
            _revoking(ticket, target.username, second_actor),
            blocked_on=[TARGET],
        )

        assert race.task.result() is None
        assert race.recorder.writes() == []
        await race.waiter.commit()
        assert await _committed(probe, ticket) == (
            True,
            [],
            [_removed(first_actor, target.username)],
        )


# ---------------------------------------------------------------------------
# Confidentiality/grant and confidentiality/revoke (`set_confidentiality`,
# Concurrency and result)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestConfidentialityRaces:
    """A confidential Ticket with a pre-existing bystander grant. A grant or
    revoke waiter locks its target User, then blocks on the Ticket held by
    the declassification; a declassification waiter blocks on the Ticket
    held by the grant or revoke winner."""

    @pytest.mark.parametrize("previously_granted", [False, True], ids=["new", "held"])
    async def test_declassification_first_rejects_the_waiting_grant(
        self, world: CommittedWorld, probe: AsyncSession, previously_granted: bool
    ) -> None:
        """`held`: the target's grant, which would have been
        `already_exists` before the lock, was deleted by the committed
        declassification; the waiter returns no stale result."""
        granter = await _analyst(world)
        declassifier = await _analyst(world)
        bystander = await _person(world)
        target = await _person(world)
        ticket = await world.ticket(cve_id=None, is_confidential=True)
        await _grant_row(world, ticket, bystander, granter)
        if previously_granted:
            await _grant_row(world, ticket, target, granter)

        race = await _serialize(
            world,
            ticket,
            _declassifying(ticket, declassifier),
            _granting(ticket, str(target.id), granter),
            blocked_on=[TARGET, TICKET],
        )

        with pytest.raises(TicketNotConfidentialError):
            race.task.result()
        assert race.recorder.writes() == []
        await race.waiter.rollback()
        assert await _committed(probe, ticket) == (
            False,
            [],
            [_declassified(declassifier)],
        )

    async def test_grant_first_precedes_the_declassification_that_deletes_it(
        self, world: CommittedWorld, probe: AsyncSession
    ) -> None:
        granter = await _analyst(world)
        declassifier = await _analyst(world)
        bystander = await _person(world)
        target = await _person(world)
        ticket = await world.ticket(cve_id=None, is_confidential=True)
        await _grant_row(world, ticket, bystander, granter)

        race = await _serialize(
            world,
            ticket,
            _granting(ticket, str(target.id), granter),
            _declassifying(ticket, declassifier),
            blocked_on=[TICKET],
        )

        assert race.winner_result.action is AccessGrantAction.CREATED
        assert race.task.result().is_confidential is False
        await race.waiter.commit()
        assert await _committed(probe, ticket) == (
            False,
            [],
            [_added(granter, target.username), _declassified(declassifier)],
        )

    async def test_declassification_first_rejects_the_waiting_revoke(
        self, world: CommittedWorld, probe: AsyncSession
    ) -> None:
        """The declassification already deleted the target's grant without
        an `access_grant_removed`; the waiter adds nothing."""
        granter = await _analyst(world)
        declassifier = await _analyst(world)
        revoker = await _analyst(world)
        bystander = await _person(world)
        target = await _person(world)
        ticket = await world.ticket(cve_id=None, is_confidential=True)
        await _grant_row(world, ticket, bystander, granter)
        await _grant_row(world, ticket, target, granter)

        race = await _serialize(
            world,
            ticket,
            _declassifying(ticket, declassifier),
            _revoking(ticket, str(target.id), revoker),
            blocked_on=[TARGET, TICKET],
        )

        with pytest.raises(TicketNotConfidentialError):
            race.task.result()
        assert race.recorder.writes() == []
        await race.waiter.rollback()
        assert await _committed(probe, ticket) == (
            False,
            [],
            [_declassified(declassifier)],
        )

    async def test_revoke_first_precedes_the_declassification(
        self, world: CommittedWorld, probe: AsyncSession
    ) -> None:
        granter = await _analyst(world)
        revoker = await _analyst(world)
        declassifier = await _analyst(world)
        bystander = await _person(world)
        target = await _person(world)
        ticket = await world.ticket(cve_id=None, is_confidential=True)
        await _grant_row(world, ticket, bystander, granter)
        await _grant_row(world, ticket, target, granter)

        race = await _serialize(
            world,
            ticket,
            _revoking(ticket, str(target.id), revoker),
            _declassifying(ticket, declassifier),
            blocked_on=[TICKET],
        )

        assert race.task.result().is_confidential is False
        await race.waiter.commit()
        assert await _committed(probe, ticket) == (
            False,
            [],
            [_removed(revoker, target.username), _declassified(declassifier)],
        )


# ---------------------------------------------------------------------------
# Reactivation/grant (`grant_access`, Concurrency; user-service.md, Access
# grant concurrent with user lifecycle or rename)
# ---------------------------------------------------------------------------


REACTIVATED = ("user_reactivated", "inactive", "active")
"""The `user_reactivated` event type and old/new values."""


@pytest.mark.integration
class TestReactivationRaces:
    """An inactive target without a grant on a confidential Ticket."""

    async def test_reactivation_first_permits_creation(
        self, world: CommittedWorld, probe: AsyncSession
    ) -> None:
        """The waiter holds a stale inactive copy of the target and blocks
        on its `FOR NO KEY UPDATE`; it decides from the reactivated row.
        Reactivation creates no Ticket event."""
        admin = await _analyst(world)
        granter = await _analyst(world)
        target = await _person(world, active=False)
        ticket = await world.ticket(cve_id=None, is_confidential=True)

        race = await _serialize(
            world,
            ticket,
            _reactivating(target, admin),
            _granting(ticket, str(target.id), granter),
            blocked_on=[TARGET],
            stale=target,
        )

        assert race.winner_result.reactivated is True
        result = race.task.result()
        assert result.action is AccessGrantAction.CREATED
        assert result.projection.user.active is True
        await race.waiter.commit()
        assert await _committed(probe, ticket) == (
            True,
            [(target.id, granter.id, race.waiter_now)],
            [_added(granter, target.username)],
        )
        event_type, old, new = REACTIVATED
        assert await _identity(probe, target) == (
            target.username,
            [(event_type, admin.id, old, new)],
        )

    async def test_inactive_observation_first_is_not_retroactively_changed(
        self, world: CommittedWorld, probe: AsyncSession
    ) -> None:
        """The grant observes the inactive target under its lock and is
        rejected; the reactivation waits on the User `FOR UPDATE` until
        the rejected transaction ends, then commits without creating any
        grant or Ticket event."""
        admin = await _analyst(world)
        granter = await _analyst(world)
        target = await _person(world, active=False)
        ticket = await world.ticket(cve_id=None, is_confidential=True)

        race = await _serialize(
            world,
            ticket,
            _rejected(_granting(ticket, str(target.id), granter), InactiveUserError),
            _reactivating(target, admin),
            blocked_on=[USER],
            release="rollback",
        )

        assert race.task.result().reactivated is True
        await race.waiter.commit()
        assert await _committed(probe, ticket) == (True, [], [])
        event_type, old, new = REACTIVATED
        assert await _identity(probe, target) == (
            target.username,
            [(event_type, admin.id, old, new)],
        )


# ---------------------------------------------------------------------------
# Rename/grant and rename/revoke (`grant_access` and `revoke_access`,
# Concurrency; user-service.md, Access grant concurrent with user
# lifecycle or rename)
# ---------------------------------------------------------------------------


def _new_username() -> str:
    """A fictional, valid, unique post-rename username."""
    return f"carol.renamed.{uuid.uuid4().hex[:10]}"


@pytest.mark.integration
@pytest.mark.parametrize("op", ["grant", "revoke"])
class TestRenameRaces:
    """A confidential Ticket; for `revoke` the target holds a pre-existing
    grant. The event username and the target identity always come from one
    stabilized User state."""

    async def test_rename_first_waiter_by_uuid_uses_the_new_username(
        self, world: CommittedWorld, probe: AsyncSession, op: str
    ) -> None:
        admin = await _analyst(world)
        granter = await _analyst(world)
        actor = await _analyst(world)
        target = await _person(world)
        old_name, new_name = target.username, _new_username()
        ticket = await world.ticket(cve_id=None, is_confidential=True)
        if op == "revoke":
            await _grant_row(world, ticket, target, granter)

        race = await _serialize(
            world,
            ticket,
            _renaming(target, new_name, admin),
            _operation(op, ticket, str(target.id), actor),
            blocked_on=[TARGET],
            stale=target,
        )

        assert race.winner_result.changed_fields == ["username"]
        if op == "grant":
            assert race.task.result().projection.user.username == new_name
            expected = (
                [(target.id, actor.id, race.waiter_now)],
                [_added(actor, new_name)],
            )
        else:
            expected = ([], [_removed(actor, new_name)])
        await race.waiter.commit()
        assert await _committed(probe, ticket) == (True, *expected)
        assert await _identity(probe, target) == (
            new_name,
            [("username_changed", admin.id, old_name, new_name)],
        )

    async def test_rename_first_waiter_by_old_username_is_user_not_found(
        self, world: CommittedWorld, probe: AsyncSession, op: str
    ) -> None:
        """The waiter blocks on the row its old username matched; after the
        rename commits, the locked-current row no longer matches, so the
        target is absent. `UserNotFoundError` is raised only after the
        Ticket lock and accessibility check, with no effect."""
        admin = await _analyst(world)
        granter = await _analyst(world)
        actor = await _analyst(world)
        target = await _person(world)
        old_name, new_name = target.username, _new_username()
        ticket = await world.ticket(cve_id=None, is_confidential=True)
        if op == "revoke":
            await _grant_row(world, ticket, target, granter)

        race = await _serialize(
            world,
            ticket,
            _renaming(target, new_name, admin),
            _operation(op, ticket, old_name, actor),
            blocked_on=[TARGET],
        )

        with pytest.raises(UserNotFoundError):
            race.task.result()
        assert _locks(race.recorder) == [TARGET, TICKET]
        assert race.recorder.writes() == []
        await race.waiter.rollback()
        grants = [(target.id, granter.id, PAST)] if op == "revoke" else []
        assert await _committed(probe, ticket) == (True, grants, [])
        assert await _identity(probe, target) == (
            new_name,
            [("username_changed", admin.id, old_name, new_name)],
        )

    async def test_operation_first_uses_the_old_username_then_rename_commits(
        self, world: CommittedWorld, probe: AsyncSession, op: str
    ) -> None:
        """The operation identifies the target by its current username and
        keeps it locked; the rename waits on the User `FOR UPDATE` and
        commits afterwards, leaving the event with the old username."""
        admin = await _analyst(world)
        granter = await _analyst(world)
        actor = await _analyst(world)
        target = await _person(world)
        old_name, new_name = target.username, _new_username()
        ticket = await world.ticket(cve_id=None, is_confidential=True)
        if op == "revoke":
            await _grant_row(world, ticket, target, granter)

        race = await _serialize(
            world,
            ticket,
            _operation(op, ticket, old_name, actor),
            _renaming(target, new_name, admin),
            blocked_on=[USER],
            stale=target,
        )

        assert race.task.result().changed_fields == ["username"]
        if op == "grant":
            assert race.winner_result.projection.user.username == old_name
            expected = (
                [(target.id, actor.id, race.winner_now)],
                [_added(actor, old_name)],
            )
        else:
            expected = ([], [_removed(actor, old_name)])
        await race.waiter.commit()
        assert await _committed(probe, ticket) == (True, *expected)
        assert await _identity(probe, target) == (
            new_name,
            [("username_changed", admin.id, old_name, new_name)],
        )


# ---------------------------------------------------------------------------
# ATR 15: locked-current accessibility (grant part)
# ---------------------------------------------------------------------------


LOSSES = ["confidentiality-set", "grant-revoked", "last-package-excluded"]
"""The Ticket-path visibility losses (`association-changed` is CVE-path
only; see the module docstring)."""

TARGET_KINDS = ["effective", "otherwise-no-op", "absent"]
"""`effective` would create or delete a grant; `otherwise-no-op` would
return `already_exists` or be a revoke no-op; `absent` would raise
`UserNotFoundError`."""


@pytest.mark.integration
class TestLockedCurrentAccessibilityRaces:
    """The `restricted_analyst` caller (scope `non_confidential`) passes the
    preliminary locator check through exactly one visibility path; an
    independent session then holds the Ticket `FOR UPDATE`, removes that
    path, and grants a bystander. The operation locks its target User (or
    preserves its absence), is proven blocked on the Ticket, the holder
    commits, and the operation must be denied from the locked-current state
    with zero side effects and without disclosing the target result
    (testing-strategy.md, Ticket Accessibility: Locked mutations; Every
    grant mutation proves Ticket accessibility is authoritative)."""

    @pytest.mark.parametrize("target_kind", TARGET_KINDS)
    @pytest.mark.parametrize("loss", LOSSES)
    @pytest.mark.parametrize("op", ["grant", "revoke"])
    async def test_visibility_lost_while_waiting_is_not_found(
        self,
        world: CommittedWorld,
        probe: AsyncSession,
        op: str,
        loss: str,
        target_kind: str,
    ) -> None:
        user, _cve, ticket, statements = await prepare_loss(world, loss)
        granter = await _analyst(world)
        bystander = await _person(world)
        ungranted = await _person(world)
        statements = [
            *statements,
            insert(TicketAccessGrant).values(
                ticket_id=ticket.id,
                user_id=bystander.id,
                granted_by_id=granter.id,
                granted_at=PAST,
            ),
        ]
        holder = {"grant": ungranted, "revoke": bystander}[op]
        other = {"grant": bystander, "revoke": ungranted}[op]
        target = {
            "effective": str(holder.id),
            "otherwise-no-op": str(other.id),
            "absent": str(uuid.uuid7()),
        }[target_kind]
        call = _operation(op, ticket, target, user, scope=Scope.NON_CONFIDENTIAL)
        caller = _caller(user, Scope.NON_CONFIDENTIAL)
        locator = format_ticket_id(ticket.sequence_id)
        a = await world.open_session()
        b = await world.open_session()

        resolved = await resolve_ticket_locator(a, locator, caller)
        assert resolved.id == ticket.id
        for statement in statements:
            await b.execute(statement)
        with SessionStatementRecorder(a) as recorder:
            task = world.start(a, call(a))
            await assert_blocked(task)
            assert [_lock_kind(s) for s in recorder.statements] == [TARGET, TICKET]
            await b.commit()
            with pytest.raises(TicketNotFoundError):
                await asyncio.wait_for(asyncio.shield(task), timeout=WAIT)

        # The premise: the committed loss really removed the caller's access.
        with pytest.raises(TicketNotFoundError):
            await resolve_ticket_locator(probe, locator, caller)
        await probe.rollback()

        # Nothing happened before the denial, not even a registration.
        assert recorder.writes() == []
        assert _locks(recorder) == [TARGET, TICKET]
        assert pending_ticket_convergence_effects(a) == ()
        await a.rollback()
        assert await _committed(probe, ticket) == (
            True,
            [(bystander.id, granter.id, PAST)],
            [],
        )


# ---------------------------------------------------------------------------
# ATR 16: the listing after the preliminary resolution (testing-strategy.md,
# Single, nested, and assembled reads)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestListingVisibilityRaces:
    @pytest.mark.parametrize("loss", LOSSES)
    async def test_visibility_lost_after_resolution_is_not_found(
        self, world: CommittedWorld, probe: AsyncSession, loss: str
    ) -> None:
        """The caller resolves the locator through its only path; an
        independent session removes that path and grants a bystander in
        one commit. The subsequent listing in the caller's session raises
        `TicketNotFoundError` and never returns the bystander row."""
        user, _cve, ticket, statements = await prepare_loss(world, loss)
        granter = await _analyst(world)
        bystander = await _person(world)
        caller = _caller(user, Scope.NON_CONFIDENTIAL)
        a = await world.open_session()
        b = await world.open_session()

        resolved = await resolve_ticket_locator(
            a, format_ticket_id(ticket.sequence_id), caller
        )
        for statement in [
            *statements,
            insert(TicketAccessGrant).values(
                ticket_id=ticket.id,
                user_id=bystander.id,
                granted_by_id=granter.id,
                granted_at=PAST,
            ),
        ]:
            await b.execute(statement)
        await b.commit()

        with pytest.raises(TicketNotFoundError):
            await asyncio.wait_for(
                list_access_grants(a, ticket_id=resolved.id, caller=caller),
                timeout=WAIT,
            )
        await a.rollback()

    async def test_access_acquired_before_selection_returns_the_complete_list(
        self, world: CommittedWorld
    ) -> None:
        """Acquisition direction. Through the API the preliminary locator
        resolution already returns 404 to a caller without access, so the
        request never reaches the listing; at the service boundary, an
        independent session commits the caller's grant and a second grant
        together, and the one-statement listing in the caller's session
        returns the complete post-acquisition set, never a partial one."""
        granter = await _analyst(world)
        user = await _person(world)
        other = await _person(world)
        ticket = await world.ticket(cve_id=None, is_confidential=True)
        caller = _caller(user, Scope.NON_CONFIDENTIAL)
        a = await world.open_session()
        b = await world.open_session()

        with pytest.raises(TicketNotFoundError):
            await resolve_ticket_locator(
                a, format_ticket_id(ticket.sequence_id), caller
            )
        for grantee, granted_at in ((user, EARLIER), (other, PAST)):
            await b.execute(
                insert(TicketAccessGrant).values(
                    ticket_id=ticket.id,
                    user_id=grantee.id,
                    granted_by_id=granter.id,
                    granted_at=granted_at,
                )
            )
        await b.commit()

        listed = await asyncio.wait_for(
            list_access_grants(a, ticket_id=ticket.id, caller=caller), timeout=WAIT
        )

        def profile(person: User) -> TicketUserProjection:
            return TicketUserProjection(
                id=person.id, username=person.username, full_name=None, active=True
            )

        assert listed == [
            AccessGrantProjection(
                user=profile(user), granted_at=EARLIER, granted_by=profile(granter)
            ),
            AccessGrantProjection(
                user=profile(other), granted_at=PAST, granted_by=profile(granter)
            ),
        ]
        await a.rollback()
