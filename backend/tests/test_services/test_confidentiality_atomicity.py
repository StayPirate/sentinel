"""Independent-session tests for `set_confidentiality()` and
`set_coordinated_release_date()` (backend/app/services/ticket_service.py).

Owning specifications:

- docs/features/tickets/ticket-service.md (Caller category and Ticket
  accessibility; `set_confidentiality`, Concurrency and result;
  `set_coordinated_release_date`, Concurrency; Architectural Test
  Requirements 15, confidentiality and Coordinated Release Date parts, and
  20, the independent-session races with declassification and with another
  CRD change).
- docs/features/tickets/ticket-audit-log.md (Event Type Contract:
  `confidentiality_changed` and `coordinated_release_changed`; Testing
  Requirement 23).
- docs/features/platform/testing-strategy.md (Concurrency Testing; Ticket
  Accessibility: Locked mutations, and Confidentiality and explicit access
  grants: the confidentiality/confidentiality race and the
  CRD/declassification race of the Coordinated Release Date bullet).

The single-session behavior (exact events, no-ops, grant deletion,
rollback, statuses, the offset-equal no-op) is covered by
`tests/test_services/test_confidentiality.py` and
`tests/test_services/test_coordinated_release_date.py`; this module adds
only what needs independent sessions:

- confidentiality/confidentiality: a same-value waiter is a no-op that
  touches no grant, and opposing effective toggles each create one event
  with their true locked old value in commit order;
- CRD/declassification in both serialization orders: declassification
  first rejects the waiting CRD change with `TicketNotConfidentialError`
  (also for a request that would otherwise be a no-op or a clear); a CRD
  change first is retained by the waiting declassification;
- CRD/CRD: two changes create one event each in serialization order, the
  second with the first's new value as its old value; a waiter requesting
  the winner's instant is a no-op (audit TR 23);
- locked-current accessibility races (ATR 15) for both operations. The
  denial must precede no-op classification and the confidentiality guard:
  the no-op requests would otherwise succeed without effect, and for the
  `confidentiality-set` loss the preliminary (non-confidential) state would
  have produced `TicketNotConfidentialError` for the CRD request while the
  locked-current (confidential) state would, without the accessibility
  check, let it proceed.

In every race the winner holds the Ticket `FOR UPDATE` in its open
transaction; the waiter holds a stale identity-map copy of the Ticket, is
proven blocked on its only row lock (the Ticket `FOR UPDATE`: neither
operation locks a User), and classifies from the state it observes after
the winner commits.

Not applicable, hence not tested here:

- the `association-changed` visibility loss of
  `tests.support.suse_cvss_races.VISIBILITY_LOSSES`. It is a CVE-path loss
  (testing-strategy.md, Locked mutations: "changing the CVE-to-Ticket
  association for a CVE-scoped operation"); both operations are
  Ticket-scoped and the canonical predicate of a Ticket does not depend on
  its CVE association;
- the converse self-loss case of ATR 15 as a race. It needs no second
  session: the only self-loss either operation can produce is a
  `non_confidential`-scope caller classifying a non-confidential Ticket it
  sees only through the non-confidential branch, covered single-session in
  `tests/test_services/test_confidentiality.py`. Through the API it is
  unreachable, because `manage_confidentiality` implies scope `all` under
  the predefined roles; declassification only widens visibility, and the
  CRD is not a visibility input;
- races with `grant_access()` and `revoke_access()`, owned by the
  access-grant work item.

Committed rows are deleted explicitly at teardown (testing-strategy.md,
Concurrency Testing). Every wait is bounded so a regression fails instead
of hanging. Expected values are transcribed from the specifications, never
computed with the module under test.
"""

from __future__ import annotations

import asyncio
import re
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from datetime import UTC, datetime, timedelta, timezone
from typing import Any

import pytest
from sqlalchemy import insert, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import Role, Scope, TicketStatus
from app.core.exceptions import TicketNotFoundError
from app.core.identifiers import format_ticket_id
from app.models.ticket import Ticket
from app.models.ticket_access_grant import TicketAccessGrant
from app.models.user import User
from app.services.ticket_convergence_registry import (
    pending_ticket_convergence_effects,
)
from app.services.ticket_service import (
    TicketNotConfidentialError,
    resolve_ticket_locator,
    set_confidentiality,
    set_coordinated_release_date,
)
from app.services.ticket_visibility import TicketCaller
from tests.support.database import assert_lock_wait
from tests.support.suse_cvss_races import (
    CommittedWorld,
    SessionStatementRecorder,
    prepare_loss,
)
from tests.support.ticket_mutations import (
    EventRow,
    StatementRecorder,
    ticket_events_by_id,
)

Factory = Callable[[], Awaitable[AsyncSession]]
Call = Callable[[AsyncSession], Awaitable[Ticket]]
Committed = tuple[tuple[bool, datetime | None], list[uuid.UUID], list[EventRow]]
"""The committed `(is_confidential, coordinated_release_at)`, grant user
IDs in UUID order, and audit events of a Ticket."""

CRD_0 = datetime(2026, 10, 1, 8, 0, tzinfo=UTC)
CRD_1 = datetime(2026, 10, 15, 12, 0, tzinfo=UTC)
CRD_1_PLUS_2 = datetime(2026, 10, 15, 14, 0, tzinfo=timezone(timedelta(hours=2)))
"""The instant `CRD_1` supplied with a `+02:00` offset."""
CRD_2 = datetime(2026, 11, 2, 9, 30, tzinfo=UTC)

ISO_0 = "2026-10-01T08:00:00Z"
ISO_1 = "2026-10-15T12:00:00Z"
ISO_2 = "2026-11-02T09:30:00Z"
"""The UTC ISO 8601 `coordinated_release_changed` values of the instants."""

TICKET_STATEMENT = re.compile(r"\b(?:FROM|JOIN|INTO|UPDATE) ticket\b")
WAIT = 5
"""Upper bound, in seconds, of every wait that is expected to finish."""


# ---------------------------------------------------------------------------
# Committed world and helpers
# ---------------------------------------------------------------------------


@pytest.fixture
async def world(db_session_factory: Factory) -> AsyncIterator[CommittedWorld]:
    created = CommittedWorld(db_session_factory, await db_session_factory())
    try:
        yield created
    finally:
        await created.cleanup()


@pytest.fixture
async def probe(world: CommittedWorld) -> AsyncSession:
    """An independent session that only observes committed state."""
    return await world.open_session()


async def _ticket(
    world: CommittedWorld, *, confidential: bool, crd: datetime | None = None
) -> Ticket:
    """A committed CVE-less `Analysis` Ticket registered for cleanup."""
    ticket = Ticket(
        status=TicketStatus.ANALYSIS.value,
        is_confidential=confidential,
        coordinated_release_at=crd,
    )
    world.session.add(ticket)
    await world.session.flush()
    world.ticket_ids.append(ticket.id)
    await world.session.commit()
    return ticket


async def _grants(world: CommittedWorld, ticket: Ticket, count: int) -> None:
    """`count` committed grants to distinct restricted analysts."""
    granter = await world.user(role=Role.VULNERABILITY_ANALYST)
    for _ in range(count):
        await world.grant(
            ticket, await world.user(role=Role.RESTRICTED_ANALYST), granter
        )


def _confidentiality(
    ticket: Ticket, value: bool, actor: User, *, scope: Scope = Scope.ALL
) -> Call:
    def call(db: AsyncSession) -> Awaitable[Ticket]:
        return set_confidentiality(
            db,
            ticket_id=ticket.id,
            is_confidential=value,
            acting_user_id=actor.id,
            caller=TicketCaller.authenticated(actor.id, scope),
        )

    return call


def _crd(
    ticket: Ticket, value: datetime | None, actor: User, *, scope: Scope = Scope.ALL
) -> Call:
    def call(db: AsyncSession) -> Awaitable[Ticket]:
        return set_coordinated_release_date(
            db,
            ticket_id=ticket.id,
            coordinated_release_at=value,
            acting_user_id=actor.id,
            caller=TicketCaller.authenticated(actor.id, scope),
        )

    return call


def _conf_event(actor: User, old: str, new: str) -> EventRow:
    """The acting-user `confidentiality_changed` (`"true"`/`"false"`)."""
    return EventRow("confidentiality_changed", actor.id, old, new, None, None)


def _crd_event(actor: User, old: str | None, new: str | None) -> EventRow:
    """The acting-user `coordinated_release_changed` (UTC ISO 8601)."""
    return EventRow("coordinated_release_changed", actor.id, old, new, None, None)


def _is_ticket_lock(statement: str) -> bool:
    return TICKET_STATEMENT.search(
        statement
    ) is not None and statement.rstrip().endswith("FOR UPDATE")


def _grant_statements(recorder: StatementRecorder) -> list[str]:
    return [s for s in recorder.statements if "ticket_access_grant" in s]


async def _committed(probe: AsyncSession, ticket: Ticket) -> Committed:
    row = (
        await probe.execute(
            select(Ticket.is_confidential, Ticket.coordinated_release_at).where(
                Ticket.id == ticket.id
            )
        )
    ).one()
    grants = list(
        (
            await probe.execute(
                select(TicketAccessGrant.user_id)
                .where(TicketAccessGrant.ticket_id == ticket.id)
                .order_by(TicketAccessGrant.user_id)
            )
        ).scalars()
    )
    events = await ticket_events_by_id(probe, ticket.id)
    await probe.rollback()
    return (row.is_confidential, row.coordinated_release_at), grants, events


async def _serialize(
    world: CommittedWorld, ticket: Ticket, first: Call, then: Call
) -> tuple[AsyncSession, StatementRecorder, asyncio.Task[Ticket]]:
    """Run `first` in a winner session that keeps its Ticket lock, start
    `then` in a waiter session holding a stale copy of the Ticket, prove the
    waiter blocked by the winner (`assert_lock_wait`) on the Ticket `FOR
    UPDATE` as its first and only statement, commit the winner, and wait
    for the waiter to finish.

    Returns the waiter session (transaction still open), its recorder, and
    its finished task."""
    winner = await world.open_session()
    waiter = await world.open_session()
    stale = await waiter.get(Ticket, ticket.id)
    assert stale is not None

    await first(winner)
    with SessionStatementRecorder(waiter) as recorder:
        task: asyncio.Task[Ticket] = world.start(waiter, then(waiter))
        await assert_lock_wait(task, waiter=waiter, blocked_by=winner)
        assert len(recorder.statements) == 1
        assert _is_ticket_lock(recorder.statements[0])
        await winner.commit()
        done, _pending = await asyncio.wait({task}, timeout=WAIT)
        assert task in done
    # The Ticket `FOR UPDATE` is the waiter's only row lock (no User lock).
    assert recorder.row_locks() == [recorder.statements[0]]
    return waiter, recorder, task


# ---------------------------------------------------------------------------
# confidentiality/confidentiality (ticket-service.md, Concurrency and result)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestConfidentialityRaces:
    @pytest.mark.parametrize(
        ("start", "grants", "old", "new"),
        [
            pytest.param(True, 2, "true", "false", id="both-declassify"),
            pytest.param(False, 0, "false", "true", id="both-classify"),
        ],
    )
    async def test_same_value_waiter_is_a_no_op(
        self,
        world: CommittedWorld,
        probe: AsyncSession,
        start: bool,
        grants: int,
        old: str,
        new: str,
    ) -> None:
        """Both callers request `not start`; the waiter observes the
        winner's committed value under its lock: no write, no grant
        statement, no event, and it returns the locked-current Ticket."""
        first_actor = await world.user(role=Role.VULNERABILITY_ANALYST)
        second_actor = await world.user(role=Role.VULNERABILITY_ANALYST)
        ticket = await _ticket(world, confidential=start, crd=CRD_0)
        await _grants(world, ticket, grants)

        waiter, recorder, task = await _serialize(
            world,
            ticket,
            _confidentiality(ticket, not start, first_actor),
            _confidentiality(ticket, not start, second_actor),
        )

        result = task.result()
        assert (result.is_confidential, result.coordinated_release_at) == (
            not start,
            CRD_0,
        )
        assert recorder.writes() == []
        assert _grant_statements(recorder) == []
        await waiter.commit()
        assert await _committed(probe, ticket) == (
            (not start, CRD_0),
            [],
            [_conf_event(first_actor, old, new)],
        )

    @pytest.mark.parametrize(
        ("start", "grants", "first_events"),
        [
            pytest.param(True, 2, ("true", "false"), id="declassify-then-classify"),
            pytest.param(False, 0, ("false", "true"), id="classify-then-declassify"),
        ],
    )
    async def test_opposing_changes_use_their_locked_old_values(
        self,
        world: CommittedWorld,
        probe: AsyncSession,
        start: bool,
        grants: int,
        first_events: tuple[str, str],
    ) -> None:
        """The winner toggles away from `start`, the waiter back to it:
        two events in commit order, the waiter's old value being the
        winner's new value, and no grant recreated by reclassification."""
        first_actor = await world.user(role=Role.VULNERABILITY_ANALYST)
        second_actor = await world.user(role=Role.VULNERABILITY_ANALYST)
        ticket = await _ticket(world, confidential=start)
        await _grants(world, ticket, grants)

        waiter, recorder, task = await _serialize(
            world,
            ticket,
            _confidentiality(ticket, not start, first_actor),
            _confidentiality(ticket, start, second_actor),
        )

        assert task.result().is_confidential is start
        waiter_grants = _grant_statements(recorder)
        if start:
            # The waiter's `false` to `true` performs no grant query.
            assert waiter_grants == []
        else:
            # The waiter's `true` to `false` deletes the then-current grants.
            assert len(waiter_grants) == 1
            assert (
                waiter_grants[0].lstrip().startswith("DELETE FROM ticket_access_grant")
            )
        await waiter.commit()
        old, new = first_events
        assert await _committed(probe, ticket) == (
            (start, None),
            [],
            [_conf_event(first_actor, old, new), _conf_event(second_actor, new, old)],
        )


# ---------------------------------------------------------------------------
# CRD/declassification, both orders (ticket-service.md,
# `set_coordinated_release_date`, Concurrency)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestCoordinatedReleaseAndDeclassificationRaces:
    """A confidential Ticket with the CRD `CRD_0` and two grants."""

    @pytest.mark.parametrize(
        "requested",
        [
            pytest.param(CRD_1, id="change"),
            pytest.param(None, id="clear"),
            pytest.param(CRD_0, id="otherwise-no-op"),
        ],
    )
    async def test_declassification_first_rejects_the_waiting_crd_change(
        self,
        world: CommittedWorld,
        probe: AsyncSession,
        requested: datetime | None,
    ) -> None:
        """`otherwise-no-op`: the confidentiality guard precedes the no-op
        classification of an equal instant."""
        declassifier = await world.user(role=Role.VULNERABILITY_ANALYST)
        crd_actor = await world.user(role=Role.VULNERABILITY_ANALYST)
        ticket = await _ticket(world, confidential=True, crd=CRD_0)
        await _grants(world, ticket, 2)

        waiter, recorder, task = await _serialize(
            world,
            ticket,
            _confidentiality(ticket, False, declassifier),
            _crd(ticket, requested, crd_actor),
        )

        with pytest.raises(TicketNotConfidentialError):
            task.result()
        assert recorder.writes() == []
        await waiter.rollback()
        assert await _committed(probe, ticket) == (
            (False, CRD_0),
            [],
            [_conf_event(declassifier, "true", "false")],
        )

    async def test_crd_change_first_is_retained_by_the_waiting_declassification(
        self, world: CommittedWorld, probe: AsyncSession
    ) -> None:
        crd_actor = await world.user(role=Role.VULNERABILITY_ANALYST)
        declassifier = await world.user(role=Role.VULNERABILITY_ANALYST)
        ticket = await _ticket(world, confidential=True, crd=CRD_0)
        await _grants(world, ticket, 2)

        waiter, _recorder, task = await _serialize(
            world,
            ticket,
            _crd(ticket, CRD_1, crd_actor),
            _confidentiality(ticket, False, declassifier),
        )

        result = task.result()
        assert (result.is_confidential, result.coordinated_release_at) == (
            False,
            CRD_1,
        )
        await waiter.commit()
        assert await _committed(probe, ticket) == (
            (False, CRD_1),
            [],
            [
                _crd_event(crd_actor, ISO_0, ISO_1),
                _conf_event(declassifier, "true", "false"),
            ],
        )


# ---------------------------------------------------------------------------
# CRD/CRD (ticket-service.md, `set_coordinated_release_date`, Concurrency;
# audit Testing Requirement 23)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestCoordinatedReleaseRaces:
    @pytest.mark.parametrize(
        ("start", "first", "second", "values"),
        [
            pytest.param(
                None, CRD_1, CRD_2, (None, ISO_1, ISO_2), id="set-then-change"
            ),
            pytest.param(
                CRD_0, CRD_1, None, (ISO_0, ISO_1, None), id="change-then-clear"
            ),
        ],
    )
    async def test_two_changes_serialize_with_locked_old_values(
        self,
        world: CommittedWorld,
        probe: AsyncSession,
        start: datetime | None,
        first: datetime,
        second: datetime | None,
        values: tuple[str | None, str, str | None],
    ) -> None:
        first_actor = await world.user(role=Role.VULNERABILITY_ANALYST)
        second_actor = await world.user(role=Role.VULNERABILITY_ANALYST)
        ticket = await _ticket(world, confidential=True, crd=start)

        waiter, _recorder, task = await _serialize(
            world,
            ticket,
            _crd(ticket, first, first_actor),
            _crd(ticket, second, second_actor),
        )

        assert task.result().coordinated_release_at == second
        await waiter.commit()
        old, middle, new = values
        assert await _committed(probe, ticket) == (
            (True, second),
            [],
            [
                _crd_event(first_actor, old, middle),
                _crd_event(second_actor, middle, new),
            ],
        )

    @pytest.mark.parametrize(
        "requested",
        [
            pytest.param(CRD_1, id="same-instant"),
            pytest.param(CRD_1_PLUS_2, id="same-instant-other-offset"),
        ],
    )
    async def test_waiter_requesting_the_winner_value_is_a_no_op(
        self, world: CommittedWorld, probe: AsyncSession, requested: datetime
    ) -> None:
        first_actor = await world.user(role=Role.VULNERABILITY_ANALYST)
        second_actor = await world.user(role=Role.VULNERABILITY_ANALYST)
        ticket = await _ticket(world, confidential=True, crd=CRD_0)

        waiter, recorder, task = await _serialize(
            world,
            ticket,
            _crd(ticket, CRD_1, first_actor),
            _crd(ticket, requested, second_actor),
        )

        assert task.result().coordinated_release_at == CRD_1
        assert recorder.writes() == []
        await waiter.commit()
        assert await _committed(probe, ticket) == (
            (True, CRD_1),
            [],
            [_crd_event(first_actor, ISO_0, ISO_1)],
        )


# ---------------------------------------------------------------------------
# ATR 15: locked-current accessibility (confidentiality and CRD parts)
# ---------------------------------------------------------------------------


LOSSES = ["confidentiality-set", "grant-revoked", "last-package-excluded"]
"""The Ticket-path visibility losses (`association-changed` is CVE-path
only; see the module docstring)."""

REQUESTS: dict[tuple[str, str], Any] = {
    ("confidentiality", "effective"): False,
    ("confidentiality", "otherwise-no-op"): True,
    ("crd", "effective"): CRD_1,
    ("crd", "otherwise-no-op"): None,
}
"""The requested value per operation and kind. Every loss leaves the
Ticket confidential with no CRD, so `True` and `None` would be no-ops and
`False` would delete the bystander grant."""


@pytest.mark.integration
class TestLockedCurrentAccessibilityRaces:
    """The `restricted_analyst` caller passes the preliminary locator check
    through exactly one visibility path; an independent session then holds
    the Ticket `FOR UPDATE`, removes that path, and grants a bystander. The
    operation is proven blocked on the Ticket, the holder commits, and the
    operation must be denied from the locked-current state with zero side
    effects (testing-strategy.md, Ticket Accessibility: Locked mutations)."""

    @pytest.mark.parametrize("kind", ["effective", "otherwise-no-op"])
    @pytest.mark.parametrize("loss", LOSSES)
    @pytest.mark.parametrize("operation", ["confidentiality", "crd"])
    async def test_visibility_lost_while_waiting_is_not_found(
        self,
        world: CommittedWorld,
        probe: AsyncSession,
        operation: str,
        loss: str,
        kind: str,
    ) -> None:
        user, _cve, ticket, statements = await prepare_loss(world, loss)
        granter = await world.user(role=Role.VULNERABILITY_ANALYST)
        bystander = await world.user(role=Role.RESTRICTED_ANALYST)
        statements = [
            *statements,
            insert(TicketAccessGrant).values(
                ticket_id=ticket.id, user_id=bystander.id, granted_by_id=granter.id
            ),
        ]
        requested = REQUESTS[(operation, kind)]
        build = _confidentiality if operation == "confidentiality" else _crd
        call = build(ticket, requested, user, scope=Scope.NON_CONFIDENTIAL)
        caller = TicketCaller.authenticated(user.id, Scope.NON_CONFIDENTIAL)
        locator = format_ticket_id(ticket.sequence_id)
        a = await world.open_session()
        b = await world.open_session()

        resolved = await resolve_ticket_locator(a, locator, caller)
        assert resolved.id == ticket.id
        for statement in statements:
            await b.execute(statement)
        with SessionStatementRecorder(a) as recorder:
            task = world.start(a, call(a))
            await assert_lock_wait(task, waiter=a, blocked_by=b)
            assert len(recorder.statements) == 1
            assert _is_ticket_lock(recorder.statements[0])
            await b.commit()
            with pytest.raises(TicketNotFoundError):
                await asyncio.wait_for(asyncio.shield(task), timeout=WAIT)

        # The premise: the committed loss really removed the caller's access.
        with pytest.raises(TicketNotFoundError):
            await resolve_ticket_locator(probe, locator, caller)
        await probe.rollback()

        # Nothing happened before the denial, not even a registration.
        assert recorder.writes() == []
        assert recorder.row_locks() == [recorder.statements[0]]
        assert pending_ticket_convergence_effects(a) == ()
        await a.rollback()
        assert await _committed(probe, ticket) == ((True, None), [bystander.id], [])
