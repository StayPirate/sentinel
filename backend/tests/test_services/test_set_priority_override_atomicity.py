"""Independent-session tests for `set_priority_override()`
(backend/app/services/ticket_service.py).

Owning specifications:

- docs/features/tickets/ticket-priority.md (Automatic Refresh; Manual
  Override: `set_priority_override()`; Audit; Testing Requirement 7).
- docs/features/tickets/ticket-service.md (Caller category and Ticket
  accessibility; Concurrency control; `set_priority_override`;
  Architectural Test Requirement 15, override part).
- docs/features/tickets/ticket-mutations.md (Concurrency Control;
  `set_severity_manual()`; `upsert_cvss_assessment()`).
- docs/features/tickets/ticket-audit-log.md (Event Type Contract:
  `priority_changed`; Cross-Event Ordering, Locking, and Rollback; Testing
  Requirements 23 and 28).
- docs/features/platform/testing-strategy.md (Concurrency Testing; Service
  Functions: lock serialization; Ticket Accessibility: Locked mutations).
- docs/conventions.md (Transaction and Locking: Cross-Domain Root Lock
  Order).

The single-session behavior of `set_priority_override()` is covered by
`tests/test_services/test_set_priority_override.py`; this module adds only
what needs independent sessions. Committed rows are deleted explicitly at
teardown (testing-strategy.md, Concurrency Testing). Expected values are
transcribed from the specifications, never computed with the module under
test.
"""

from __future__ import annotations

import asyncio
import re
from collections.abc import AsyncIterator, Awaitable, Callable
from typing import Any

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import Role, Scope, Severity, TicketPriority, TicketStatus
from app.core.exceptions import TicketNotFoundError
from app.core.identifiers import format_ticket_id
from app.models.cve import CVE
from app.models.ticket import Ticket
from app.models.user import User
from app.services import ticket_service
from app.services.ticket_convergence_registry import (
    pending_ticket_convergence_effects,
)
from app.services.ticket_mutations import set_severity_manual
from app.services.ticket_service import resolve_ticket_locator, set_priority_override
from app.services.ticket_visibility import TicketCaller
from tests.support.cvss_chain import priority_event, severity_event, ticket_state
from tests.support.suse_cvss import V31_CRITICAL, cvss_event, upsert
from tests.support.suse_cvss_races import (
    CommittedWorld,
    SessionStatementRecorder,
    assert_blocked,
    prepare_loss,
)
from tests.support.ticket_mutations import EVAL, EventRow, ticket_events_by_id

Factory = Callable[[], Awaitable[AsyncSession]]

TICKET_STATEMENT = re.compile(r"\b(?:FROM|JOIN|INTO|UPDATE) ticket\b")


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


def _override_event(
    actor: User, old: str | None, new: str | None, action: str
) -> EventRow:
    """The acting-user `priority_changed` event of an override."""
    return EventRow(
        "priority_changed", actor.id, old, new, None, {"override_action": action}
    )


def _manual_severity_event(actor: User, new: str) -> EventRow:
    """The acting-user `severity_changed` event of `set_severity_manual()`
    from SQL `NULL`."""
    return EventRow("severity_changed", actor.id, None, new, None, None)


async def _override(
    session: AsyncSession,
    ticket: Ticket,
    priority: TicketPriority | None,
    actor: User,
    *,
    scope: Scope = Scope.ALL,
) -> Ticket:
    return await set_priority_override(
        session,
        ticket_id=ticket.id,
        priority=priority,
        acting_user_id=actor.id,
        caller=TicketCaller.authenticated(actor.id, scope),
        evaluation_date=EVAL,
    )


async def _severity(session: AsyncSession, ticket: Ticket, actor: User) -> Ticket:
    """`set_severity_manual()` to `High` (automatic priority `P3`)."""
    return await set_severity_manual(
        session,
        ticket_id=ticket.id,
        severity=Severity.HIGH,
        acting_user_id=actor.id,
        caller=TicketCaller.authenticated(actor.id, Scope.ALL),
        evaluation_date=EVAL,
    )


async def _suse(session: AsyncSession, cve: CVE, actor: User) -> Any:
    """A manual SUSE 9.8 upsert (`Critical`, automatic priority `P2`); the
    committed test schema has no `default_cvss_version` row."""
    return await upsert(
        session, cve.id, V31_CRITICAL.canonical, actor, default_cvss_version="3.1"
    )


class _Spy:
    """Wraps an async `ticket_service` attribute, recording the session of
    each call (independent sessions share the patched module)."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch, name: str) -> None:
        self.sessions: list[AsyncSession] = []
        original = getattr(ticket_service, name)
        # `reconcile_ticket_status(ticket, db, ...)`,
        # `auto_assign_actor(ticket, acting_user, db)`.
        position = 1 if name == "reconcile_ticket_status" else 2

        async def _wrapper(*args: Any, **kwargs: Any) -> Any:
            self.sessions.append(args[position])
            return await original(*args, **kwargs)

        monkeypatch.setattr(ticket_service, name, _wrapper)


def _is_ticket_lock(statement: str) -> bool:
    return TICKET_STATEMENT.search(
        statement
    ) is not None and statement.rstrip().endswith("FOR UPDATE")


async def _committed(
    world: CommittedWorld, ticket: Ticket
) -> tuple[tuple[Any, ...], list[EventRow]]:
    """The committed `ticket_state()` and events of a Ticket, read through a
    fresh independent session."""
    probe = await world.open_session()
    state = await ticket_state(probe, ticket.id)
    events = await ticket_events_by_id(probe, ticket.id)
    await probe.rollback()
    return state, events


# ---------------------------------------------------------------------------
# TR 7: override against an automatic refresh, both orderings
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestOverrideAndManualSeverityRace:
    """A CVE-less Ticket assigned to its owner, with no severity and no
    priority. The refresh of `set_severity_manual()` moves `priority_auto`
    from `NULL` to `P3`; the override sets `P1`."""

    async def test_severity_first_the_override_uses_the_committed_refresh(
        self, committed_world: CommittedWorld
    ) -> None:
        owner = await committed_world.user(role=Role.VULNERABILITY_ANALYST)
        overrider = await committed_world.user(role=Role.VULNERABILITY_ANALYST)
        ticket = await committed_world.ticket(cve_id=None, assignee_id=owner.id)
        a = await committed_world.open_session()
        b = await committed_world.open_session()
        # A holds a stale identity-map copy from before the refresh.
        stale = await a.get(Ticket, ticket.id)
        assert stale is not None
        assert stale.priority_auto is None

        await _severity(b, ticket, owner)
        with SessionStatementRecorder(a) as recorder:
            task = committed_world.start(
                a, _override(a, ticket, TicketPriority.P1, overrider)
            )
            await assert_blocked(task)
            assert _is_ticket_lock(recorder.statements[-1])
            await b.commit()
            await asyncio.wait_for(task, timeout=5)
        await a.commit()

        assert await _committed(committed_world, ticket) == (
            (TicketStatus.ANALYSIS, owner.id, "P3", "P1", "High"),
            [
                _manual_severity_event(owner, "High"),
                priority_event(None, "P3"),
                _override_event(overrider, "P3", "P1", "set"),
            ],
        )

    async def test_override_first_the_refresh_is_masked_without_event(
        self, committed_world: CommittedWorld
    ) -> None:
        owner = await committed_world.user(role=Role.VULNERABILITY_ANALYST)
        overrider = await committed_world.user(role=Role.VULNERABILITY_ANALYST)
        ticket = await committed_world.ticket(cve_id=None, assignee_id=owner.id)
        a = await committed_world.open_session()
        b = await committed_world.open_session()

        await _override(b, ticket, TicketPriority.P1, overrider)
        with SessionStatementRecorder(a) as recorder:
            task = committed_world.start(a, _severity(a, ticket, owner))
            await assert_blocked(task)
            assert _is_ticket_lock(recorder.statements[-1])
            await b.commit()
            await asyncio.wait_for(task, timeout=5)
        await a.commit()

        assert await _committed(committed_world, ticket) == (
            (TicketStatus.ANALYSIS, owner.id, "P3", "P1", "High"),
            [
                _override_event(overrider, None, "P1", "set"),
                _manual_severity_event(owner, "High"),
            ],
        )


@pytest.mark.integration
class TestOverrideAndManualSUSERace:
    """A CVE-associated Ticket assigned to its owner, on a CVE without
    assessments or severity. The manual SUSE 9.8 upsert (User, CVE, then
    Ticket) moves `priority_auto` from `NULL` to `P2`; the override (User,
    then Ticket) sets `P1`."""

    async def test_upsert_first_the_override_uses_the_committed_refresh(
        self, committed_world: CommittedWorld
    ) -> None:
        owner = await committed_world.user(role=Role.VULNERABILITY_ANALYST)
        overrider = await committed_world.user(role=Role.VULNERABILITY_ANALYST)
        cve = await committed_world.cve()
        ticket = await committed_world.ticket(cve_id=cve.id, assignee_id=owner.id)
        a = await committed_world.open_session()
        b = await committed_world.open_session()

        await _suse(b, cve, owner)
        with SessionStatementRecorder(a) as recorder:
            task = committed_world.start(
                a, _override(a, ticket, TicketPriority.P1, overrider)
            )
            await assert_blocked(task)
            assert _is_ticket_lock(recorder.statements[-1])
            await b.commit()
            await asyncio.wait_for(task, timeout=5)
        await a.commit()

        assert await _committed(committed_world, ticket) == (
            (TicketStatus.ANALYSIS, owner.id, "P2", "P1", None),
            [
                cvss_event(owner, None, V31_CRITICAL),
                severity_event(None, "Critical"),
                priority_event(None, "P2"),
                _override_event(overrider, "P2", "P1", "set"),
            ],
        )

    async def test_override_first_the_refresh_is_masked_without_event(
        self, committed_world: CommittedWorld
    ) -> None:
        owner = await committed_world.user(role=Role.VULNERABILITY_ANALYST)
        overrider = await committed_world.user(role=Role.VULNERABILITY_ANALYST)
        cve = await committed_world.cve()
        ticket = await committed_world.ticket(cve_id=cve.id, assignee_id=owner.id)
        a = await committed_world.open_session()
        b = await committed_world.open_session()

        await _override(b, ticket, TicketPriority.P1, overrider)
        with SessionStatementRecorder(a) as recorder:
            task = committed_world.start(a, _suse(a, cve, owner))
            await assert_blocked(task)
            # The upsert holds its CVE root and waits for the Ticket.
            assert _is_ticket_lock(recorder.statements[-1])
            await b.commit()
            await asyncio.wait_for(task, timeout=5)
        await a.commit()

        assert await _committed(committed_world, ticket) == (
            (TicketStatus.ANALYSIS, owner.id, "P2", "P1", None),
            [
                _override_event(overrider, None, "P1", "set"),
                cvss_event(owner, None, V31_CRITICAL),
                severity_event(None, "Critical"),
            ],
        )


# ---------------------------------------------------------------------------
# Override against override (audit Testing Requirement 23)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestOverrideWinnerAndLoser:
    async def test_equal_value_loser_is_a_no_op(
        self, committed_world: CommittedWorld, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        owner = await committed_world.user(role=Role.VULNERABILITY_ANALYST)
        first = await committed_world.user(role=Role.VULNERABILITY_ANALYST)
        second = await committed_world.user(role=Role.VULNERABILITY_ANALYST)
        ticket = await committed_world.ticket(
            cve_id=None,
            assignee_id=owner.id,
            severity_manual=Severity.HIGH,
            priority_auto="P3",
        )
        a = await committed_world.open_session()
        b = await committed_world.open_session()
        reconcile = _Spy(monkeypatch, "reconcile_ticket_status")

        await _override(b, ticket, TicketPriority.P1, first)
        with SessionStatementRecorder(a) as recorder:
            task = committed_world.start(
                a, _override(a, ticket, TicketPriority.P1, second)
            )
            await assert_blocked(task)
            await b.commit()
            result = await asyncio.wait_for(task, timeout=5)

        assert result.priority_override == "P1"
        assert recorder.writes() == []
        assert reconcile.sessions == [b]
        assert pending_ticket_convergence_effects(a) == ()
        await a.commit()
        assert await _committed(committed_world, ticket) == (
            (TicketStatus.ANALYSIS, owner.id, "P3", "P1", "High"),
            [_override_event(first, "P3", "P1", "set")],
        )

    async def test_differing_loser_changes_from_the_winner_value(
        self, committed_world: CommittedWorld
    ) -> None:
        owner = await committed_world.user(role=Role.VULNERABILITY_ANALYST)
        first = await committed_world.user(role=Role.VULNERABILITY_ANALYST)
        second = await committed_world.user(role=Role.VULNERABILITY_ANALYST)
        ticket = await committed_world.ticket(
            cve_id=None,
            assignee_id=owner.id,
            severity_manual=Severity.HIGH,
            priority_auto="P3",
        )
        a = await committed_world.open_session()
        b = await committed_world.open_session()

        await _override(b, ticket, TicketPriority.P1, first)
        task = committed_world.start(a, _override(a, ticket, TicketPriority.P2, second))
        await assert_blocked(task)
        await b.commit()
        await asyncio.wait_for(task, timeout=5)
        await a.commit()

        assert await _committed(committed_world, ticket) == (
            (TicketStatus.ANALYSIS, owner.id, "P3", "P2", "High"),
            [
                _override_event(first, "P3", "P1", "set"),
                _override_event(second, "P1", "P2", "changed"),
            ],
        )


# ---------------------------------------------------------------------------
# ATR 15: locked-current accessibility (override part)
# ---------------------------------------------------------------------------


LOSSES = ["confidentiality-set", "grant-revoked", "last-package-excluded"]


@pytest.mark.integration
class TestLockedCurrentAccessibilityRaces:
    """Session A passes the preliminary locator check; session B then holds
    the Ticket `FOR UPDATE` and removes A's only visibility path. A is
    proven blocked on the Ticket lock, B commits, and A must be denied from
    the locked-current state with zero side effects, even for a request
    that would otherwise be the no-op (testing-strategy.md, Ticket
    Accessibility: Locked mutations)."""

    @pytest.mark.parametrize(
        "requested",
        [
            pytest.param(TicketPriority.P1, id="effective"),
            pytest.param(None, id="also-no-op-request"),
        ],
    )
    @pytest.mark.parametrize("loss", LOSSES)
    async def test_visibility_lost_while_waiting_for_the_lock_is_not_found(
        self,
        committed_world: CommittedWorld,
        monkeypatch: pytest.MonkeyPatch,
        loss: str,
        requested: TicketPriority | None,
    ) -> None:
        user, _cve, ticket, statements = await prepare_loss(committed_world, loss)
        a = await committed_world.open_session()
        b = await committed_world.open_session()
        caller = TicketCaller.authenticated(user.id, Scope.NON_CONFIDENTIAL)
        assign = _Spy(monkeypatch, "auto_assign_actor")
        reconcile = _Spy(monkeypatch, "reconcile_ticket_status")

        resolved = await resolve_ticket_locator(
            a, format_ticket_id(ticket.sequence_id), caller
        )
        assert resolved.id == ticket.id
        for statement in statements:
            await b.execute(statement)
        with SessionStatementRecorder(a) as recorder:
            task = committed_world.start(
                a,
                _override(a, ticket, requested, user, scope=Scope.NON_CONFIDENTIAL),
            )
            await assert_blocked(task)
            assert _is_ticket_lock(recorder.statements[-1])
            await b.commit()
            with pytest.raises(TicketNotFoundError):
                await asyncio.wait_for(task, timeout=5)

        assert recorder.writes() == []
        assert (assign.sessions, reconcile.sessions) == ([], [])
        assert pending_ticket_convergence_effects(a) == ()
        await a.rollback()
        state, events = await _committed(committed_world, ticket)
        assert state[:4] == (TicketStatus.ANALYSIS, None, None, None)
        assert events == []
