"""Service integration tests for `ignore_new_for_rejected_cve()`
(backend/app/services/ticket_service.py).

Owning specifications:

- docs/features/tickets/ticket-service.md (`ignore_new_for_rejected_cve()`;
  Architectural Test Requirement 13 (the exact `CVE rejected` comment) and
  17 (System CVE rejection boundary), except the rejected-orphan creation
  order, which needs `cve_service.upsert_cve()` creating the Ticket).
- docs/features/tickets/cve-tracking.md (CVE Rejection Handling >
  Rejection handling, status table).
- docs/features/tickets/ticket-audit-log.md (Event Type Contract:
  `status_change`; Canonical Automatic Comment Vocabulary: `CVE
  rejected`; Canonical Mutation and No-Event Matrix row "CVE association
  and rejection/revert"; Cross-Event Ordering, Locking, and Rollback;
  Testing Requirements 1-7, 25).
- docs/features/tickets/ticket-priority.md (Refresh Points: the CVE
  rejection lifecycle step changes no priority input).
- docs/features/platform/testing-strategy.md (Audit Trail Testing;
  Rollback Within a Test).
- Decision D9 of issue #749 (`cve_id=None` is an association violation).

The tests take the CVE-then-Ticket locks themselves, as `upsert_cve()`
does before invoking the boundary. Expected values are transcribed from
the specifications, never computed with the module under test.
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable
from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import TicketAuditEventType, TicketStatus
from app.models.cve import CVE
from app.models.ticket import Ticket
from app.models.ticket_audit_event import TicketAuditEvent
from app.services import ticket_service
from app.services.ticket_audit_log import TicketAuditLog
from app.services.ticket_convergence_registry import (
    pending_ticket_convergence_effects,
)
from app.services.ticket_service import ignore_new_for_rejected_cve
from tests.support.cvss_chain import ticket_state
from tests.support.database import rollback_test_scope
from tests.support.ticket_mutations import (
    EventRow,
    StatementRecorder,
    TicketFactory,
    VAUser,
    lock_ticket,
    ticket_events,
    ticket_events_by_id,
)

pytest_plugins = ["tests.support.ticket_mutation_fixtures"]
"""Provides the shared `va_user` fixture."""

Factory = Callable[..., Awaitable[Any]]

REJECTED = EventRow(
    "status_change",
    None,
    TicketStatus.NEW.value,
    TicketStatus.IGNORED.value,
    "CVE rejected",
    None,
)
"""The exact system rejection event (cve-tracking.md, Rejection handling;
ticket-audit-log.md, Canonical Automatic Comment Vocabulary)."""

OTHER_STATUSES = (
    TicketStatus.ANALYSIS,
    TicketStatus.ANALYZED,
    TicketStatus.RESOLVED,
    TicketStatus.IGNORED,
    TicketStatus.DUPLICATED,
)


async def _lock_roots(db: AsyncSession, cve_id: uuid.UUID, ticket: Ticket) -> Ticket:
    """Acquire the CVE root then the associated Ticket, as `upsert_cve()`
    holds them before invoking the boundary."""
    await db.execute(
        select(CVE.id).where(CVE.id == cve_id).with_for_update(key_share=True)
    )
    return await lock_ticket(db, ticket)


class _Spy:
    """Wraps an async `ticket_service` attribute, recording each call."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch, name: str) -> None:
        self.calls: list[tuple[tuple[Any, ...], dict[str, Any]]] = []
        original = getattr(ticket_service, name)

        async def _wrapper(*args: Any, **kwargs: Any) -> Any:
            self.calls.append((args, kwargs))
            return await original(*args, **kwargs)

        monkeypatch.setattr(ticket_service, name, _wrapper)


def _spies(monkeypatch: pytest.MonkeyPatch) -> list[_Spy]:
    """Spies on every Ticket consequence the boundary must never compose."""
    return [
        _Spy(monkeypatch, name)
        for name in (
            "auto_assign_actor",
            "reconcile_ticket_status",
            "refresh_priority_auto",
            "recalculate_cvss_chain",
        )
    ]


def _statement_kinds(statements: list[str]) -> list[str]:
    """The leading verb and target of each statement, sorted."""
    return sorted(" ".join(s.split()[:3]) for s in statements)


# ---------------------------------------------------------------------------
# Status table (cve-tracking.md, Rejection handling)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestStatusTable:
    async def test_new_becomes_ignored_with_the_exact_system_event(
        self,
        db_session: AsyncSession,
        cve_factory: Factory,
        ticket_factory: TicketFactory,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A stale `priority_auto` (`P4` for a `Critical` CVE) proves that no
        priority refresh runs. The boundary issues only the Ticket update
        and the event insert: no lock, no read, no audit-history query."""
        cve = await cve_factory(severity="Critical")
        ticket = await ticket_factory(
            status=TicketStatus.NEW.value, cve_id=cve.id, priority_auto="P4"
        )
        locked = await _lock_roots(db_session, cve.id, ticket)
        spies = _spies(monkeypatch)

        with StatementRecorder(db_session) as recorder:
            result = await ignore_new_for_rejected_cve(
                db_session, cve_id=cve.id, ticket=locked
            )

        assert result is locked
        assert result.status == TicketStatus.IGNORED
        assert _statement_kinds(recorder.statements) == [
            "INSERT INTO ticket_audit_event",
            "UPDATE ticket SET",
        ]
        assert recorder.row_locks() == []
        assert recorder.selects_from("ticket_audit_event") == []
        assert [spy.calls for spy in spies] == [[], [], [], []]
        assert await ticket_state(db_session, ticket.id) == (
            TicketStatus.IGNORED,
            None,
            "P4",
            None,
            None,
        )
        assert await ticket_events(db_session, ticket) == [REJECTED]
        assert pending_ticket_convergence_effects(db_session) == ()

    @pytest.mark.parametrize("status", OTHER_STATUSES)
    async def test_every_other_status_is_a_no_op(
        self,
        db_session: AsyncSession,
        cve_factory: Factory,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
        status: TicketStatus,
    ) -> None:
        """An inactive assignee and a stale `priority_auto` would change if
        any sanitation or refresh ran."""
        inactive = await va_user(active=False)
        cve = await cve_factory(severity="Critical")
        ticket = await ticket_factory(
            status=status.value,
            cve_id=cve.id,
            assignee_id=inactive.id,
            priority_auto="P4",
        )
        locked = await _lock_roots(db_session, cve.id, ticket)
        spies = _spies(monkeypatch)

        with StatementRecorder(db_session) as recorder:
            result = await ignore_new_for_rejected_cve(
                db_session, cve_id=cve.id, ticket=locked
            )

        assert result is locked
        assert result.status == status
        assert recorder.statements == []
        assert [spy.calls for spy in spies] == [[], [], [], []]
        assert await ticket_state(db_session, ticket.id) == (
            status,
            inactive.id,
            "P4",
            None,
            None,
        )
        assert await ticket_events(db_session, ticket) == []
        assert pending_ticket_convergence_effects(db_session) == ()

    async def test_reinvocation_after_the_transition_is_a_no_op(
        self,
        db_session: AsyncSession,
        cve_factory: Factory,
        ticket_factory: TicketFactory,
    ) -> None:
        cve = await cve_factory()
        ticket = await ticket_factory(status=TicketStatus.NEW.value, cve_id=cve.id)
        locked = await _lock_roots(db_session, cve.id, ticket)

        await ignore_new_for_rejected_cve(db_session, cve_id=cve.id, ticket=locked)
        with StatementRecorder(db_session) as recorder:
            again = await ignore_new_for_rejected_cve(
                db_session, cve_id=cve.id, ticket=locked
            )

        assert again.status == TicketStatus.IGNORED
        assert recorder.statements == []
        assert await ticket_events(db_session, ticket) == [REJECTED]

    async def test_assignee_is_preserved_without_sanitation(
        self,
        db_session: AsyncSession,
        cve_factory: Factory,
        ticket_factory: TicketFactory,
        va_user: VAUser,
    ) -> None:
        """Rejection never assigns, unassigns, or sanitizes: an inactive
        assignee of the `New` Ticket is retained."""
        inactive = await va_user(active=False)
        cve = await cve_factory()
        ticket = await ticket_factory(
            status=TicketStatus.NEW.value, cve_id=cve.id, assignee_id=inactive.id
        )
        locked = await _lock_roots(db_session, cve.id, ticket)

        await ignore_new_for_rejected_cve(db_session, cve_id=cve.id, ticket=locked)

        assert await ticket_state(db_session, ticket.id) == (
            TicketStatus.IGNORED,
            inactive.id,
            None,
            None,
            None,
        )
        assert await ticket_events(db_session, ticket) == [REJECTED]


# ---------------------------------------------------------------------------
# Association violations (Q6; D9)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestAssociationViolation:
    @pytest.mark.parametrize("status", [TicketStatus.NEW, TicketStatus.ANALYSIS])
    @pytest.mark.parametrize(
        "violation",
        [
            "another-cve",
            "cveless-ticket-with-none",
            "cveless-ticket-with-a-cve",
            "none-with-associated-ticket",
        ],
    )
    async def test_raises_value_error_before_any_statement(
        self,
        db_session: AsyncSession,
        cve_factory: Factory,
        ticket_factory: TicketFactory,
        violation: str,
        status: TicketStatus,
    ) -> None:
        """The check precedes the status classification: a non-`New`
        Ticket raises too."""
        cve = await cve_factory()
        other = await cve_factory()
        if violation.startswith("cveless"):
            ticket = await ticket_factory(status=status.value, severity_manual="High")
        else:
            ticket = await ticket_factory(status=status.value, cve_id=cve.id)
        cve_id: Any = {
            "another-cve": other.id,
            "cveless-ticket-with-none": None,
            "cveless-ticket-with-a-cve": cve.id,
            "none-with-associated-ticket": None,
        }[violation]

        with (
            StatementRecorder(db_session) as recorder,
            pytest.raises(ValueError, match="unique association"),
        ):
            await ignore_new_for_rejected_cve(db_session, cve_id=cve_id, ticket=ticket)

        assert recorder.statements == []
        assert ticket.status == status
        assert (await ticket_state(db_session, ticket.id))[0] == status
        assert await ticket_events(db_session, ticket) == []


# ---------------------------------------------------------------------------
# Rollback and transaction ownership
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestRollback:
    @pytest.mark.parametrize("failure", ["audit", "flush"])
    async def test_failure_propagates_and_rolls_back_status_and_event(
        self,
        db_session: AsyncSession,
        cve_factory: Factory,
        ticket_factory: TicketFactory,
        monkeypatch: pytest.MonkeyPatch,
        failure: str,
    ) -> None:
        cve = await cve_factory()
        ticket = await ticket_factory(status=TicketStatus.NEW.value, cve_id=cve.id)
        cve_id, ticket_id = cve.id, ticket.id
        original_flush = db_session.flush
        reached = False

        async def failing_log(*args: Any, **kwargs: Any) -> None:
            nonlocal reached
            assert kwargs["event_type"] is TicketAuditEventType.STATUS_CHANGE
            reached = True
            raise RuntimeError("injected audit failure")

        async def failing_flush(*args: Any, **kwargs: Any) -> None:
            nonlocal reached
            if any(
                isinstance(o, TicketAuditEvent) and o.comment == "CVE rejected"
                for o in db_session.new
            ):
                reached = True
                raise RuntimeError("injected flush failure")
            await original_flush(*args, **kwargs)

        async with rollback_test_scope(db_session):
            locked = await _lock_roots(db_session, cve_id, ticket)
            if failure == "audit":
                monkeypatch.setattr(TicketAuditLog, "log_event", failing_log)
            else:
                monkeypatch.setattr(db_session, "flush", failing_flush)
            with pytest.raises(RuntimeError, match="injected"):
                await ignore_new_for_rejected_cve(
                    db_session, cve_id=cve_id, ticket=locked
                )
        monkeypatch.undo()

        assert reached
        status = (
            await db_session.execute(
                select(Ticket.status)
                .where(Ticket.id == ticket_id)
                .execution_options(populate_existing=True)
            )
        ).scalar_one()
        assert status == TicketStatus.NEW
        assert await ticket_events_by_id(db_session, ticket_id) == []

    async def test_never_commits_or_rolls_back(
        self,
        db_session: AsyncSession,
        cve_factory: Factory,
        ticket_factory: TicketFactory,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        cve = await cve_factory()
        ticket = await ticket_factory(status=TicketStatus.NEW.value, cve_id=cve.id)
        locked = await _lock_roots(db_session, cve.id, ticket)

        async def forbidden() -> None:
            raise AssertionError("the boundary must not end the transaction")

        monkeypatch.setattr(db_session, "commit", forbidden)
        monkeypatch.setattr(db_session, "rollback", forbidden)

        result = await ignore_new_for_rejected_cve(
            db_session, cve_id=cve.id, ticket=locked
        )

        assert result.status == TicketStatus.IGNORED
