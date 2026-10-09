"""Independent-session tests for the explicit operator Ticket convergence
dispatch `ticket_service.dispatch_ticket_convergence()`
(backend/app/services/ticket_service.py).

Owning specifications:

- docs/features/tickets/ticket-service.md (Ticket Convergence > Publication
  policies, explicit operator rerun; Publication failure logging;
  `dispatch_ticket_convergence()`; Architectural Test Requirements 12 and
  15, convergence dispatch part).
- docs/features/tickets/tickets.md (Rerun Ticket Convergence: behavior and
  ordering, no audit event, repeated and concurrent requests).
- docs/features/tickets/ticket-audit-log.md (the rerun creates no event).
- docs/features/platform/testing-strategy.md (Ticket Convergence
  Publication Handoff > explicit operator rerun, Control signals and
  security; Ticket Accessibility > Locked mutations; Concurrency Testing).

The dispatch owns one short session from its `session_factory`, so every
test commits its rows through `db_session_factory` sessions and deletes
them explicitly at teardown. The broker publication call
(`task_publication.publish_task`) is substituted by a recorder whose hook
runs at the publication boundary: there an independent session acquires
the Ticket `FOR UPDATE NOWAIT`, proving that the dispatch committed,
closed its session, and released the lock before the attempt. A waiter is
proven blocked with `assert_lock_wait`; every other wait is bounded.

The HTTP mapping (202, 404, 409, 503) is covered by
`tests/test_api/test_ticket_convergence_rerun.py`; the shared publisher
boundary by `tests/test_services/test_ticket_convergence_publication.py`.
Expected values are transcribed from the specifications, never computed
with the module under test.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, cast

import pytest
from celery.exceptions import OperationalError as BrokerOperationalError
from sqlalchemy import func, select, update
from sqlalchemy.exc import OperationalError as DatabaseOperationalError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from structlog.testing import capture_logs

from app.core.enums import Role, Scope, TicketStatus
from app.core.exceptions import InvalidTransitionError, TicketNotFoundError
from app.models.ticket import Ticket
from app.models.ticket_audit_event import TicketAuditEvent
from app.models.user import User
from app.services import task_publication
from app.services.ticket_convergence_registry import (
    detach_ticket_convergence_effects,
    pending_ticket_convergence_effects,
)
from app.services.ticket_service import (
    TicketConvergenceDispatchError,
    dispatch_ticket_convergence,
    resolve_ticket_locator,
)
from app.services.ticket_visibility import TicketCaller
from tests.support.database import assert_lock_wait
from tests.support.suse_cvss_races import (
    CommittedWorld,
    SessionStatementRecorder,
    prepare_loss,
)

Factory = Callable[[], Awaitable[AsyncSession]]

DISPATCH_FAILED_MESSAGE = (
    "Ticket convergence could not be dispatched to the task broker"
)
"""tickets.md, Rerun Ticket Convergence, step 5 (the fixed detail)."""

BROKER_URL = "amqp://sentinel-user:fictional-secret@broker.example.test:5672//"
"""A fictional credential-bearing broker URL carried by the injected error."""

PORT_DIGITS_TICKET_ID = uuid.UUID("01a11fd4-3f1a-7239-a342-fd8d567209f6")
"""A UUIDv7 whose hexadecimal digits contain the broker port `5672`."""

WAIT = 5
"""Upper bound, in seconds, of every wait that is expected to finish."""

ACCEPTED = [TicketStatus.ANALYSIS, TicketStatus.ANALYZED, TicketStatus.RESOLVED]
REJECTED = [TicketStatus.NEW, TicketStatus.IGNORED, TicketStatus.DUPLICATED]


# ---------------------------------------------------------------------------
# Committed world, session factory, and publication recorder
# ---------------------------------------------------------------------------


class _World(CommittedWorld):
    probe: AsyncSession
    """Independent session observing committed state and probing locks."""

    async def status_ticket(self, status: TicketStatus, **columns: Any) -> Ticket:
        """A committed CVE-less Ticket in `status` (a `Duplicated` one is
        linked to a committed `Analysis` target)."""
        if status is TicketStatus.DUPLICATED:
            target = await self.ticket(cve_id=None)
            columns["duplicate_of_id"] = target.id
        ticket = Ticket(status=status.value, **columns)
        self.session.add(ticket)
        await self.session.flush()
        self.ticket_ids.append(ticket.id)
        await self.session.commit()
        return ticket


@pytest.fixture
async def world(db_session_factory: Factory) -> AsyncIterator[_World]:
    created = _World(db_session_factory, await db_session_factory())
    try:
        created.probe = await created.open_session()
        yield created
    finally:
        await created.cleanup()


class _Sessions:
    """The dispatch's `session_factory`: hands out pre-opened independent
    sessions in order (their backend PIDs are known before the dispatch
    starts) and records each session's close."""

    def __init__(self, *sessions: AsyncSession) -> None:
        self._pending = list(sessions)
        self.handed: list[AsyncSession] = []
        self.closed: list[AsyncSession] = []

    def __call__(self) -> AsyncSession:
        session = self._pending.pop(0)
        close = session.close

        async def _recording_close() -> None:
            await close()
            self.closed.append(session)

        session.close = _recording_close  # type: ignore[method-assign]
        self.handed.append(session)
        return session

    @property
    def factory(self) -> async_sessionmaker[AsyncSession]:
        return cast(async_sessionmaker[AsyncSession], self)


@dataclass
class _Publish:
    """Substitute for `task_publication.publish_task` recording each call."""

    error: BaseException | None = None
    calls: list[dict[str, Any]] = field(default_factory=list)
    on_call: Callable[[dict[str, Any]], Awaitable[None]] | None = None

    async def __call__(self, task_name: str, **options: Any) -> None:
        call = {"task_name": task_name, **options}
        self.calls.append(call)
        if self.on_call is not None:
            await self.on_call(call)
        if self.error is not None:
            raise self.error


@pytest.fixture
def publish(monkeypatch: pytest.MonkeyPatch) -> _Publish:
    recorder = _Publish()
    monkeypatch.setattr(task_publication, "publish_task", recorder)
    return recorder


def _caller(user: User, scope: Scope = Scope.ALL) -> TicketCaller:
    return TicketCaller.authenticated(user.id, scope)


def _sntl(ticket: Ticket) -> str:
    return f"SNTL-{ticket.sequence_id}"


async def _row(db: AsyncSession, ticket_id: uuid.UUID) -> dict[str, Any]:
    """Every persisted Ticket column, including `updated_at`."""
    row = (
        await db.execute(select(Ticket.__table__).where(Ticket.id == ticket_id))
    ).one()
    await db.rollback()
    return dict(row._mapping)


async def _event_count(db: AsyncSession, ticket_id: uuid.UUID) -> int:
    count: int = (
        await db.execute(
            select(func.count(TicketAuditEvent.id)).where(
                TicketAuditEvent.ticket_id == ticket_id
            )
        )
    ).scalar_one()
    await db.rollback()
    return count


async def _lock_nowait(probe: AsyncSession, ticket_id: uuid.UUID) -> str:
    """Acquire and release the Ticket lock without waiting; fails with a
    lock-not-available error when another transaction holds it."""
    status: str = (
        await probe.execute(
            select(Ticket.status)
            .where(Ticket.id == ticket_id)
            .with_for_update(nowait=True)
        )
    ).scalar_one()
    await probe.rollback()
    return status


def _assert_no_owner_state(session: AsyncSession) -> None:
    """The dispatch registered no post-commit callback and no convergence
    effect, and its session is closed (nothing left in its identity map)."""
    assert "post_commit_callbacks" not in session.info
    assert pending_ticket_convergence_effects(session) == ()
    assert detach_ticket_convergence_effects(session) == ()
    assert not session.in_transaction()
    assert len(session.identity_map) == 0


def _published(publish: _Publish, ticket_id: uuid.UUID) -> dict[str, Any]:
    """The single root convergence publication for `ticket_id`."""
    [call] = publish.calls
    assert call["task_name"] == "run_ticket_convergence"
    assert call["kwargs"] == {"ticket_id": str(ticket_id)}
    assert set(call) == {"task_name", "kwargs", "task_id"}
    return call


# ---------------------------------------------------------------------------
# Acceptance and status eligibility (ATR 12)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestDispatchAccepted:
    @pytest.mark.parametrize("status", ACCEPTED, ids=lambda s: s.value)
    async def test_eligible_status_publishes_after_commit_close_and_lock_release(
        self,
        world: _World,
        publish: _Publish,
        status: TicketStatus,
    ) -> None:
        """The Ticket lock is the first statement; the dispatch writes
        nothing, commits and closes its session, and only then publishes:
        inside the publisher an independent session takes the Ticket lock
        `NOWAIT`. The returned ID is the published root task UUID (v7)."""
        actor = await world.user(role=Role.VULNERABILITY_ANALYST)
        ticket = await world.status_ticket(status, severity_manual="High")
        before = await _row(world.probe, ticket.id)
        session = await world.open_session()
        sessions = _Sessions(session)
        observed: list[tuple[str, bool, bool]] = []

        async def _at_publication(call: dict[str, Any]) -> None:
            locked = await _lock_nowait(world.probe, ticket.id)
            observed.append(
                (locked, session.in_transaction(), session in sessions.closed)
            )

        publish.on_call = _at_publication

        with SessionStatementRecorder(session) as recorder:
            task_id = await dispatch_ticket_convergence(
                ticket_id=ticket.id,
                caller=_caller(actor),
                session_factory=sessions.factory,
            )

        call = _published(publish, ticket.id)
        assert call["task_id"] == task_id
        assert str(uuid.UUID(task_id)) == task_id
        assert uuid.UUID(task_id).version == 7
        assert observed == [(status.value, False, True)]
        first = recorder.statements[0]
        assert "FROM ticket" in first
        assert "FOR UPDATE" in first
        assert recorder.writes() == []
        assert sessions.handed == sessions.closed == [session]
        _assert_no_owner_state(session)
        assert await _row(world.probe, ticket.id) == before
        assert await _event_count(world.probe, ticket.id) == 0

    @pytest.mark.parametrize("status", REJECTED, ids=lambda s: s.value)
    async def test_ineligible_status_is_an_invalid_transition_without_publication(
        self,
        world: _World,
        publish: _Publish,
        status: TicketStatus,
    ) -> None:
        actor = await world.user(role=Role.VULNERABILITY_ANALYST)
        ticket = await world.status_ticket(status)
        before = await _row(world.probe, ticket.id)
        session = await world.open_session()
        sessions = _Sessions(session)

        with pytest.raises(InvalidTransitionError):
            await dispatch_ticket_convergence(
                ticket_id=ticket.id,
                caller=_caller(actor),
                session_factory=sessions.factory,
            )

        assert publish.calls == []
        assert sessions.closed == [session]
        _assert_no_owner_state(session)
        assert await _lock_nowait(world.probe, ticket.id) == status.value
        assert await _row(world.probe, ticket.id) == before
        assert await _event_count(world.probe, ticket.id) == 0

    async def test_missing_ticket_is_not_found_without_publication(
        self, world: _World, publish: _Publish
    ) -> None:
        actor = await world.user(role=Role.VULNERABILITY_ANALYST)
        session = await world.open_session()
        sessions = _Sessions(session)

        with pytest.raises(TicketNotFoundError):
            await dispatch_ticket_convergence(
                ticket_id=uuid.uuid7(),
                caller=_caller(actor),
                session_factory=sessions.factory,
            )

        assert publish.calls == []
        assert sessions.closed == [session]
        _assert_no_owner_state(session)

    async def test_repeated_dispatch_publishes_each_time_with_distinct_task_ids(
        self, world: _World, publish: _Publish
    ) -> None:
        """Not idempotent by design: every accepted call publishes another
        complete workflow (tickets.md, repeated requests)."""
        actor = await world.user(role=Role.VULNERABILITY_ANALYST)
        ticket = await world.status_ticket(TicketStatus.ANALYSIS)
        first, second = await world.open_session(), await world.open_session()
        sessions = _Sessions(first, second)

        returned = [
            await dispatch_ticket_convergence(
                ticket_id=ticket.id,
                caller=_caller(actor),
                session_factory=sessions.factory,
            )
            for _ in range(2)
        ]

        assert [call["kwargs"] for call in publish.calls] == [
            {"ticket_id": str(ticket.id)}
        ] * 2
        assert [call["task_id"] for call in publish.calls] == returned
        assert len(set(returned)) == 2
        assert sessions.closed == [first, second]
        assert await _event_count(world.probe, ticket.id) == 0

    async def test_concurrent_dispatches_serialize_on_the_lock_and_both_publish(
        self, world: _World, publish: _Publish
    ) -> None:
        """Two dispatches wait on a Ticket lock held by an independent
        session; after it ends, both pass the locked check and each
        publishes its own task (no coalescing, no conflict)."""
        actor = await world.user(role=Role.VULNERABILITY_ANALYST)
        ticket = await world.status_ticket(TicketStatus.RESOLVED)
        holder = await world.open_session()
        first, second = await world.open_session(), await world.open_session()
        sessions = _Sessions(first, second)
        await holder.execute(
            select(Ticket.id).where(Ticket.id == ticket.id).with_for_update()
        )

        def _dispatch() -> Awaitable[str]:
            return dispatch_ticket_convergence(
                ticket_id=ticket.id,
                caller=_caller(actor),
                session_factory=sessions.factory,
            )

        one = world.start(first, _dispatch())
        await assert_lock_wait(one, waiter=first, blocked_by=holder)
        two = world.start(second, _dispatch())
        await assert_lock_wait(two, waiter=second, blocked_by=(holder, first))
        assert publish.calls == []
        await holder.commit()
        returned = await asyncio.wait_for(asyncio.gather(one, two), timeout=WAIT)

        assert sorted(call["task_id"] for call in publish.calls) == sorted(returned)
        assert len(set(returned)) == 2
        assert [call["kwargs"] for call in publish.calls] == [
            {"ticket_id": str(ticket.id)}
        ] * 2
        assert sorted(map(id, sessions.closed)) == sorted([id(first), id(second)])
        assert await _event_count(world.probe, ticket.id) == 0


# ---------------------------------------------------------------------------
# Publication outcomes (acceptance_unconfirmed and propagation)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestDispatchPublicationOutcomes:
    async def test_broker_operational_error_raises_the_fixed_dispatch_error(
        self, world: _World, publish: _Publish
    ) -> None:
        """`acceptance_unconfirmed`: exactly one sanitized
        `ticket_convergence_dispatch_failed` ERROR with only `ticket_id` and
        the closed cause; the raised error carries the fixed message and no
        trace of the broker exception. The committed Ticket is unchanged.
        The Ticket ID contains the broker port digits, proving that the
        no-leak check ignores the logged `ticket_id` value."""
        actor = await world.user(role=Role.VULNERABILITY_ANALYST)
        ticket = await world.status_ticket(
            TicketStatus.ANALYZED, id=PORT_DIGITS_TICKET_ID
        )
        before = await _row(world.probe, ticket.id)
        session = await world.open_session()
        sessions = _Sessions(session)
        publish.error = BrokerOperationalError(f"{BROKER_URL} connection refused")

        with capture_logs() as logs, pytest.raises(TicketConvergenceDispatchError) as e:
            await dispatch_ticket_convergence(
                ticket_id=ticket.id,
                caller=_caller(actor),
                session_factory=sessions.factory,
            )

        assert len(publish.calls) == 1
        assert str(e.value) == DISPATCH_FAILED_MESSAGE
        assert e.value.__cause__ is None
        assert e.value.__suppress_context__ is True
        assert logs == [
            {
                "event": "ticket_convergence_dispatch_failed",
                "log_level": "error",
                "ticket_id": str(ticket.id),
                "cause": "broker_operational_error",
            }
        ]
        # The `ticket_id` value is asserted exactly above; it is removed
        # here because hexadecimal UUID digits may contain "5672".
        rendered = repr(logs).replace(str(ticket.id), "") + str(e.value)
        for fragment in ("fictional-secret", "broker.example.test", "5672", "amqp"):
            assert fragment not in rendered
        assert sessions.closed == [session]
        _assert_no_owner_state(session)
        assert await _row(world.probe, ticket.id) == before
        assert await _event_count(world.probe, ticket.id) == 0

    @pytest.mark.parametrize(
        "error",
        [RuntimeError("programming error"), asyncio.CancelledError()],
        ids=lambda e: type(e).__name__,
    )
    async def test_non_operational_exception_propagates_unchanged_without_log(
        self, world: _World, publish: _Publish, error: BaseException
    ) -> None:
        actor = await world.user(role=Role.VULNERABILITY_ANALYST)
        ticket = await world.status_ticket(TicketStatus.ANALYSIS)
        session = await world.open_session()
        sessions = _Sessions(session)
        publish.error = error

        with capture_logs() as logs, pytest.raises(type(error)) as raised:
            await dispatch_ticket_convergence(
                ticket_id=ticket.id,
                caller=_caller(actor),
                session_factory=sessions.factory,
            )

        assert raised.value is error
        assert not isinstance(raised.value, TicketConvergenceDispatchError)
        assert len(publish.calls) == 1
        assert logs == []
        assert sessions.closed == [session]
        assert await _event_count(world.probe, ticket.id) == 0

    @pytest.mark.parametrize(
        "committed", [False, True], ids=["failed-commit", "ambiguous-commit"]
    )
    async def test_commit_exception_propagates_without_publication(
        self,
        world: _World,
        publish: _Publish,
        committed: bool,
    ) -> None:
        """A definitely failed commit, and a commit whose outcome is
        ambiguous (the database committed, then the call raised), both
        propagate unchanged with no publication attempt; the session is
        closed and the Ticket lock released."""
        actor = await world.user(role=Role.VULNERABILITY_ANALYST)
        ticket = await world.status_ticket(TicketStatus.ANALYSIS)
        session = await world.open_session()
        sessions = _Sessions(session)
        failure = DatabaseOperationalError(
            "COMMIT", {}, Exception("server closed the connection")
        )
        real_commit = session.commit

        async def _failing_commit() -> None:
            if committed:
                await real_commit()
            raise failure

        session.commit = _failing_commit  # type: ignore[method-assign]

        with capture_logs() as logs, pytest.raises(DatabaseOperationalError) as e:
            await dispatch_ticket_convergence(
                ticket_id=ticket.id,
                caller=_caller(actor),
                session_factory=sessions.factory,
            )

        assert e.value is failure
        assert publish.calls == []
        assert logs == []
        assert sessions.closed == [session]
        assert await _lock_nowait(world.probe, ticket.id) == TicketStatus.ANALYSIS
        assert await _event_count(world.probe, ticket.id) == 0


# ---------------------------------------------------------------------------
# Locked-current accessibility races (ATR 15, convergence dispatch part)
# ---------------------------------------------------------------------------


LOSSES = ["confidentiality-set", "grant-revoked", "last-package-excluded"]
"""The Ticket-path visibility losses (testing-strategy.md, Locked
mutations); the CVE-to-Ticket association loss applies to CVE-scoped
operations only."""


@pytest.mark.integration
class TestLockedCurrentAccessibilityRaces:
    """A `restricted_analyst` caller passes the preliminary locator check
    (the API's `require_accessible_ticket`) through exactly one visibility
    path. An independent session then holds the Ticket `FOR UPDATE` and
    removes that path; the dispatch is proven blocked on the Ticket, the
    holder commits, and the dispatch must be denied from the locked-current
    state with no publication, write, event, callback, or effect."""

    @pytest.mark.parametrize(
        "moved", [False, True], ids=["eligible-status", "also-moved-out"]
    )
    @pytest.mark.parametrize("loss", LOSSES)
    async def test_visibility_lost_while_waiting_is_not_found(
        self,
        world: _World,
        publish: _Publish,
        loss: str,
        moved: bool,
    ) -> None:
        """`also-moved-out`: the same committed change also moves the
        Ticket to `Ignored`, so the status guard would raise
        `InvalidTransitionError`; the denial must precede it."""
        user, _cve, ticket, statements = await prepare_loss(world, loss)
        if moved:
            statements = [
                *statements,
                update(Ticket)
                .where(Ticket.id == ticket.id)
                .values(status=TicketStatus.IGNORED.value),
            ]
        caller = TicketCaller.authenticated(user.id, Scope.NON_CONFIDENTIAL)
        a = await world.open_session()
        b = await world.open_session()
        sessions = _Sessions(a)

        resolved = await resolve_ticket_locator(world.probe, _sntl(ticket), caller)
        assert resolved.id == ticket.id
        await world.probe.rollback()
        for statement in statements:
            await b.execute(statement)
        with SessionStatementRecorder(a) as recorder:
            task = world.start(
                a,
                dispatch_ticket_convergence(
                    ticket_id=ticket.id, caller=caller, session_factory=sessions.factory
                ),
            )
            await assert_lock_wait(task, waiter=a, blocked_by=b)
            first = recorder.statements[0]
            assert "FROM ticket" in first
            assert "FOR UPDATE" in first
            await b.commit()
            with pytest.raises(TicketNotFoundError):
                await asyncio.wait_for(asyncio.shield(task), timeout=WAIT)

        # The premise: the committed loss really removed the caller's access.
        with pytest.raises(TicketNotFoundError):
            await resolve_ticket_locator(world.probe, _sntl(ticket), caller)
        await world.probe.rollback()

        assert publish.calls == []
        assert recorder.writes() == []
        assert sessions.closed == [a]
        _assert_no_owner_state(a)
        expected = TicketStatus.IGNORED if moved else TicketStatus.ANALYSIS
        assert await _lock_nowait(world.probe, ticket.id) == expected.value
        assert await _event_count(world.probe, ticket.id) == 0

    async def test_authorized_caller_dispatches_from_the_locked_current_state(
        self, world: _World, publish: _Publish
    ) -> None:
        """Control for the races: the same `restricted_analyst` caller,
        authorized only through the grant, waits on the same lock while
        the holder commits an unrelated change, and is accepted."""
        user, _cve, ticket, statements = await prepare_loss(world, "grant-revoked")
        caller = TicketCaller.authenticated(user.id, Scope.NON_CONFIDENTIAL)
        a = await world.open_session()
        b = await world.open_session()
        sessions = _Sessions(a)

        await b.execute(statements[0])
        await b.execute(
            update(Ticket)
            .where(Ticket.id == ticket.id)
            .values(coordinated_release_at=datetime(2099, 1, 1, tzinfo=UTC))
        )
        task = world.start(
            a,
            dispatch_ticket_convergence(
                ticket_id=ticket.id, caller=caller, session_factory=sessions.factory
            ),
        )
        await assert_lock_wait(task, waiter=a, blocked_by=b)
        await b.commit()
        task_id = await asyncio.wait_for(asyncio.shield(task), timeout=WAIT)

        assert _published(publish, ticket.id)["task_id"] == task_id
        assert sessions.closed == [a]
