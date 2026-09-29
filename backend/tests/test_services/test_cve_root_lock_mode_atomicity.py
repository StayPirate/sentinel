"""Independent-session tests for the CVE root lock mode (issue #703).

Owning specifications:

- docs/conventions.md (Transaction and Locking: Cross-Domain Root Lock
  Order — the CVE root is acquired with `FOR NO KEY UPDATE`, so the
  foreign-key `FOR KEY SHARE` of a referencing Ticket row stays
  compatible while CVE-root holders still serialize).
- docs/features/tickets/ticket-mutations.md (Concurrency Control;
  `upsert_cvss_assessment()`; `delete_cvss_assessment()`; Architectural
  Test Requirement: serialized outcomes, independent-session races).
- docs/features/tickets/ticket-service.md (`ignore_ticket`;
  `assign_ticket`; Concurrency control).
- docs/features/platform/testing-strategy.md (Concurrency Testing).

Regression: PostgreSQL re-runs the `ticket.cve_id -> cve.id` foreign-key
check (`SELECT 1 FROM cve ... FOR KEY SHARE`) when a transaction UPDATEs
a Ticket row it already updated. A Ticket-first mutation that writes the
Ticket twice (auto- or explicit assignment, then the status) therefore
needs `FOR KEY SHARE` on the associated CVE while holding the Ticket. A
manual CVSS mutation holding the CVE and waiting for the Ticket used to
deadlock with it when the CVE root was `FOR UPDATE`.

The Ticket-first session is paused deterministically right after its
first audit event, whose flush writes the first Ticket UPDATE, by
wrapping `TicketAuditLog.log_event` with an `asyncio.Event`. Committed
rows are deleted explicitly at teardown (`CommittedWorld.cleanup()`).
Every wait is bounded so a regression fails instead of hanging. Expected
values are transcribed from the specifications.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from typing import Any

import pytest
from sqlalchemy import Select, select
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import Role, Scope, Severity, TicketStatus
from app.core.exceptions import TicketNotMutableError
from app.models.cve import CVE
from app.models.ticket import Ticket
from app.models.user import User
from app.services.ticket_audit_log import TicketAuditLog
from app.services.ticket_mutations import (
    CVSSAssessmentAction,
    CVSSAssessmentMutationResult,
)
from app.services.ticket_service import assign_ticket, ignore_ticket
from app.services.ticket_visibility import TicketCaller
from tests.support.cvss_chain import cve_severity, priority_event, severity_event
from tests.support.suse_cvss import (
    V31_CRITICAL,
    V31_MEDIUM,
    assignment_event,
    cvss_event,
    delete_assessment,
    persisted_assessments,
    unit,
    upsert,
)
from tests.support.suse_cvss_races import (
    CommittedWorld,
    SessionStatementRecorder,
    assert_blocked,
)
from tests.support.ticket_mutations import (
    EVAL,
    EventRow,
    status_event,
    ticket_events_by_id,
)

Factory = Callable[[], Awaitable[AsyncSession]]
WAIT = 5
"""Upper bound, in seconds, of every wait that is expected to finish."""


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


class _PauseAfterFirstAuditEvent:
    """Pauses `session`'s workflow right after its first Ticket audit event
    returns, i.e. after the flush that wrote its first Ticket UPDATE, while
    it holds the Ticket lock. Other sessions pass through unchanged."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch, session: AsyncSession) -> None:
        self.paused = asyncio.Event()
        self.resume = asyncio.Event()
        original = TicketAuditLog.log_event

        async def _wrapper(db: AsyncSession, *args: Any, **kwargs: Any) -> None:
            await original(db, *args, **kwargs)
            if db is session and not self.paused.is_set():
                self.paused.set()
                await self.resume.wait()

        monkeypatch.setattr(TicketAuditLog, "log_event", _wrapper)


def _cve_row(cve: CVE) -> Select[Any]:
    return select(CVE.id).where(CVE.id == cve.id)


async def _is_locked(probe: AsyncSession, statement: Select[Any]) -> bool:
    """Whether another transaction holds a lock on the selected row that
    conflicts with `FOR UPDATE NOWAIT` (released at once)."""
    try:
        await probe.execute(statement.with_for_update(nowait=True))
    except DBAPIError:
        await probe.rollback()
        return True
    await probe.rollback()
    return False


def _is_ticket_update(statement: str) -> bool:
    return statement.lstrip().startswith("UPDATE ticket ")


async def _race_ticket_first_against_cvss(
    world: CommittedWorld,
    monkeypatch: pytest.MonkeyPatch,
    cve: CVE,
    ticket_first: Callable[[AsyncSession], Awaitable[Ticket]],
    cvss: Callable[[AsyncSession], Awaitable[CVSSAssessmentMutationResult]],
) -> tuple[AsyncSession, asyncio.Task[CVSSAssessmentMutationResult]]:
    """Drive the regression interleaving and return the CVSS session and
    task, still waiting for the Ticket after the Ticket-first session
    committed.

    1. A (Ticket-first) holds the Ticket and has written it once.
    2. B (CVSS) holds the CVE root and waits for the Ticket.
    3. A writes the Ticket again (the foreign-key `FOR KEY SHARE` on the
       CVE) and completes while B still holds the CVE; A commits.
    """
    a = await world.open_session()
    b = await world.open_session()
    probe = await world.open_session()
    pause = _PauseAfterFirstAuditEvent(monkeypatch, a)

    with SessionStatementRecorder(a) as recorder:
        first = world.start(a, ticket_first(a))
        await asyncio.wait_for(pause.paused.wait(), timeout=WAIT)
        assert len([s for s in recorder.statements if _is_ticket_update(s)]) == 1
        assert await _is_locked(probe, _cve_row(cve)) is False

        second = world.start(b, cvss(b))
        await assert_blocked(second)
        assert await _is_locked(probe, _cve_row(cve)) is True

        pause.resume.set()
        await asyncio.wait_for(first, timeout=WAIT)

    assert len([s for s in recorder.statements if _is_ticket_update(s)]) >= 2
    assert not second.done()
    assert await _is_locked(probe, _cve_row(cve)) is True
    await a.commit()
    return b, second


async def _ticket_state(
    reader: AsyncSession, ticket_id: uuid.UUID
) -> tuple[str, uuid.UUID | None]:
    """The committed `(status, assignee_id)` of a Ticket, read by a separate
    session so the world's committed instances stay loaded."""
    row = (
        await reader.execute(
            select(Ticket.status, Ticket.assignee_id).where(Ticket.id == ticket_id)
        )
    ).one()
    return row.status, row.assignee_id


def _explicit_assignment_event(actor: User, target: User) -> EventRow:
    return EventRow("assignment", actor.id, None, target.username, None, None)


def _ignored_event(actor: User) -> EventRow:
    return EventRow("status_change", actor.id, "Analysis", "Ignored", None, None)


# ---------------------------------------------------------------------------
# Ticket-first mutation against a manual CVSS mutation
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestTicketFirstMutationAgainstCVSSMutation:
    @pytest.mark.parametrize("operation", ["upsert", "delete"])
    async def test_ignore_completes_while_the_cvss_mutation_holds_the_cve(
        self,
        committed_world: CommittedWorld,
        monkeypatch: pytest.MonkeyPatch,
        operation: str,
    ) -> None:
        """A VA ignores a `New` unassigned Ticket (auto-assignment, then
        `New -> Analysis`, then `Ignored`: several Ticket UPDATEs) while a
        manual CVSS mutation waits for the Ticket under the CVE root. The
        ignore commits without a deadlock; the waiter then observes the
        committed `Ignored` and is rejected with no effect."""
        ignorer = await committed_world.user(role=Role.VULNERABILITY_ANALYST)
        scorer = await committed_world.user(role=Role.VULNERABILITY_ANALYST)
        cve = await committed_world.cve(V31_CRITICAL, severity=Severity.CRITICAL)
        ticket = await committed_world.ticket(cve_id=cve.id, status=TicketStatus.NEW)

        async def _ignore(db: AsyncSession) -> Ticket:
            return await ignore_ticket(
                db,
                ticket_id=ticket.id,
                acting_user_id=ignorer.id,
                caller=TicketCaller.authenticated(ignorer.id, Scope.ALL),
            )

        async def _cvss(db: AsyncSession) -> CVSSAssessmentMutationResult:
            if operation == "upsert":
                return await upsert(
                    db, cve.id, V31_MEDIUM.canonical, scorer, default_cvss_version="3.1"
                )
            return await delete_assessment(
                db, cve.id, "3.1", scorer, default_cvss_version="3.1"
            )

        _, waiter = await _race_ticket_first_against_cvss(
            committed_world, monkeypatch, cve, _ignore, _cvss
        )

        with pytest.raises(TicketNotMutableError):
            await asyncio.wait_for(waiter, timeout=WAIT)

        reader = await committed_world.open_session()
        assert await _ticket_state(reader, ticket.id) == (
            TicketStatus.IGNORED.value,
            ignorer.id,
        )
        assert await ticket_events_by_id(reader, ticket.id) == [
            assignment_event(ignorer),
            status_event("New", "Analysis"),
            _ignored_event(ignorer),
        ]
        assert await persisted_assessments(reader, cve.id) == [
            unit("SUSE", V31_CRITICAL)
        ]
        assert await cve_severity(reader, cve.id) == "Critical"

    async def test_assign_completes_then_the_waiting_upsert_applies_from_the_winner(
        self, committed_world: CommittedWorld, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An explicit assignment of a `New` Ticket (assignee, then
        `New -> Analysis`) commits while a manual upsert waits for the
        Ticket under the CVE root; the upsert then applies from the
        committed winner without a second assignment."""
        assigner = await committed_world.user(role=Role.VULNERABILITY_ANALYST)
        target = await committed_world.user(role=Role.VULNERABILITY_ANALYST)
        scorer = await committed_world.user(role=Role.VULNERABILITY_ANALYST)
        cve = await committed_world.cve()
        ticket = await committed_world.ticket(cve_id=cve.id, status=TicketStatus.NEW)

        async def _assign(db: AsyncSession) -> Ticket:
            return await assign_ticket(
                db,
                ticket_id=ticket.id,
                assignee=target.username,
                acting_user_id=assigner.id,
                caller=TicketCaller.authenticated(assigner.id, Scope.ALL),
                evaluation_date=EVAL,
            )

        async def _upsert(db: AsyncSession) -> CVSSAssessmentMutationResult:
            return await upsert(
                db, cve.id, V31_CRITICAL.canonical, scorer, default_cvss_version="3.1"
            )

        b, waiter = await _race_ticket_first_against_cvss(
            committed_world, monkeypatch, cve, _assign, _upsert
        )

        result = await asyncio.wait_for(waiter, timeout=WAIT)
        await b.commit()

        assert result.action is CVSSAssessmentAction.CREATED
        assert result.assigned is False
        reader = await committed_world.open_session()
        assert await _ticket_state(reader, ticket.id) == (
            TicketStatus.ANALYSIS.value,
            target.id,
        )
        assert await ticket_events_by_id(reader, ticket.id) == [
            _explicit_assignment_event(assigner, target),
            status_event("New", "Analysis"),
            cvss_event(scorer, None, V31_CRITICAL),
            severity_event(None, "Critical"),
            priority_event(None, "P2"),
        ]


# ---------------------------------------------------------------------------
# CVE-root holders still serialize
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestCVERootSerialization:
    async def test_waiting_upsert_on_a_ticketless_cve_updates_from_the_winner(
        self, committed_world: CommittedWorld
    ) -> None:
        """Without an associated Ticket the CVE root is the only shared
        lock: a second manual upsert waits until the first commits and then
        classifies from the committed winner."""
        first = await committed_world.user(role=Role.VULNERABILITY_ANALYST)
        second = await committed_world.user(role=Role.VULNERABILITY_ANALYST)
        cve = await committed_world.cve()
        a = await committed_world.open_session()
        b = await committed_world.open_session()

        winner = await upsert(
            b, cve.id, V31_MEDIUM.canonical, first, default_cvss_version="3.1"
        )
        task = committed_world.start(
            a,
            upsert(
                a, cve.id, V31_CRITICAL.canonical, second, default_cvss_version="3.1"
            ),
        )
        await assert_blocked(task)
        await b.commit()

        loser = await asyncio.wait_for(task, timeout=WAIT)

        assert winner.action is CVSSAssessmentAction.CREATED
        assert loser.action is CVSSAssessmentAction.UPDATED
        assert loser.assessment is not None
        assert winner.assessment is not None
        assert loser.assessment.id == winner.assessment.id
        assert loser.severity_changed is True
        await a.rollback()
