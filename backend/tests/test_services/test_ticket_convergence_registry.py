"""Transaction-local Ticket convergence registration lifecycle.

Owning specifications:

- docs/features/tickets/ticket-mutations.md (Transaction-Local Ticket
  Convergence Registration, steps 1-3: registration, deduplication and
  order, discard).
- docs/features/platform/testing-strategy.md (Ticket Convergence
  Publication Handoff > Transaction-local lifecycle): registration carries
  only the Ticket UUID and performs no query or I/O; rollback, a failed
  commit, and pre-commit cancellation discard; a reused session starts its
  next transaction empty. These tests use real PostgreSQL with independent
  sessions and deterministic ordering.

Consumption (owner detach, publisher, publication policies) does not exist
yet: every effect is discarded when its transaction ends, including after a
successful commit, and nothing is ever published (roadmap dispatch D1).
"""

from __future__ import annotations

import asyncio
import dataclasses
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from typing import Any

import pytest
from sqlalchemy import delete, event, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session

from app.core.enums import Severity, TicketStatus
from app.models.ticket import Ticket
from app.models.ticket_audit_event import TicketAuditEvent
from app.services.ticket_convergence_registry import (
    TicketConvergenceEffect,
    _discard_on_transaction_end,
    pending_ticket_convergence_effects,
    register_ticket_convergence,
)
from app.services.ticket_mutations import reconcile_ticket_status

SessionFactory = Callable[[], Awaitable[AsyncSession]]


# ---------------------------------------------------------------------------
# Registration primitive
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestEffect:
    def test_effect_carries_only_the_ticket_uuid(self) -> None:
        ticket_id = uuid.uuid7()
        effect = TicketConvergenceEffect(ticket_id)

        assert [f.name for f in dataclasses.fields(effect)] == ["ticket_id"]
        assert effect.ticket_id == ticket_id
        with pytest.raises(dataclasses.FrozenInstanceError):
            effect.ticket_id = uuid.uuid7()  # type: ignore[misc]


@pytest.mark.integration
class TestRegistration:
    async def test_registration_requires_a_transaction(
        self, db_session_factory: SessionFactory
    ) -> None:
        session = await db_session_factory()

        with pytest.raises(ValueError, match="transaction"):
            register_ticket_convergence(session, uuid.uuid7())

    async def test_deduplicates_and_keeps_first_registration_order_without_io(
        self, db_session_factory: SessionFactory
    ) -> None:
        session = await db_session_factory()
        await session.execute(select(1))
        first, second = uuid.uuid7(), uuid.uuid7()
        engine = session.get_bind().engine
        statements: list[str] = []

        def record(*args: Any) -> None:
            statements.append(args[2])

        event.listen(engine, "before_cursor_execute", record)
        try:
            register_ticket_convergence(session, second)
            register_ticket_convergence(session, first)
            register_ticket_convergence(session, second)
        finally:
            event.remove(engine, "before_cursor_execute", record)

        assert statements == []
        assert pending_ticket_convergence_effects(session) == (
            TicketConvergenceEffect(second),
            TicketConvergenceEffect(first),
        )
        await session.rollback()

    async def test_no_transaction_reads_empty(
        self, db_session_factory: SessionFactory
    ) -> None:
        session = await db_session_factory()

        assert pending_ticket_convergence_effects(session) == ()


# ---------------------------------------------------------------------------
# Transaction lifecycle through reconcile_ticket_status()
# ---------------------------------------------------------------------------


@dataclasses.dataclass
class _World:
    setup: AsyncSession
    ticket_ids: list[uuid.UUID] = dataclasses.field(default_factory=list)

    async def ticket(self) -> uuid.UUID:
        ticket = Ticket(
            status=TicketStatus.ANALYSIS.value,
            severity_manual=Severity.HIGH.value,
        )
        self.setup.add(ticket)
        await self.setup.commit()
        self.ticket_ids.append(ticket.id)
        return ticket.id

    async def status(self, ticket_id: uuid.UUID) -> str:
        await self.setup.rollback()
        return (
            await self.setup.execute(
                select(Ticket.status).where(Ticket.id == ticket_id)
            )
        ).scalar_one()

    async def event_count(self, ticket_id: uuid.UUID) -> int:
        await self.setup.rollback()
        rows = await self.setup.execute(
            select(TicketAuditEvent.id).where(TicketAuditEvent.ticket_id == ticket_id)
        )
        return len(rows.all())

    async def cleanup(self) -> None:
        await self.setup.rollback()
        await self.setup.execute(
            delete(TicketAuditEvent).where(
                TicketAuditEvent.ticket_id.in_(self.ticket_ids)
            )
        )
        await self.setup.execute(delete(Ticket).where(Ticket.id.in_(self.ticket_ids)))
        await self.setup.commit()


@pytest.fixture
async def world(db_session_factory: SessionFactory) -> AsyncIterator[_World]:
    committed = _World(await db_session_factory())
    try:
        yield committed
    finally:
        await committed.cleanup()


async def _exit_manual_zone(session: AsyncSession, ticket_id: uuid.UUID) -> None:
    """Lock the Ticket and reconcile a manual-zone exit (registers)."""
    ticket = (
        await session.execute(
            select(Ticket).where(Ticket.id == ticket_id).with_for_update()
        )
    ).scalar_one()
    await reconcile_ticket_status(ticket, session, previous_status=TicketStatus.IGNORED)


@pytest.mark.integration
class TestTransactionLifecycle:
    async def test_successful_commit_discards_without_publication(
        self, world: _World, db_session_factory: SessionFactory
    ) -> None:
        ticket_id = await world.ticket()
        owner = await db_session_factory()
        await _exit_manual_zone(owner, ticket_id)
        assert pending_ticket_convergence_effects(owner) == (
            TicketConvergenceEffect(ticket_id),
        )

        await owner.commit()

        # No effect survives and nothing (e.g. a post-commit callback) was
        # registered for publication.
        assert owner.info == {}
        await owner.execute(select(1))
        assert pending_ticket_convergence_effects(owner) == ()
        await owner.rollback()
        assert await world.event_count(ticket_id) == 1

    async def test_rollback_discards_and_next_transaction_starts_empty(
        self, world: _World, db_session_factory: SessionFactory
    ) -> None:
        ticket_id = await world.ticket()
        owner = await db_session_factory()
        await _exit_manual_zone(owner, ticket_id)

        await owner.rollback()

        assert pending_ticket_convergence_effects(owner) == ()
        other_id = uuid.uuid7()
        await owner.execute(select(1))
        register_ticket_convergence(owner, other_id)
        assert pending_ticket_convergence_effects(owner) == (
            TicketConvergenceEffect(other_id),
        )
        await owner.rollback()
        assert await world.event_count(ticket_id) == 0

    async def test_failed_commit_discards(
        self, world: _World, db_session_factory: SessionFactory
    ) -> None:
        ticket_id = await world.ticket()
        owner = await db_session_factory()
        await _exit_manual_zone(owner, ticket_id)
        owner.add(Ticket(status="NotAStatus"))

        with pytest.raises(IntegrityError):
            await owner.commit()
        await owner.rollback()

        assert pending_ticket_convergence_effects(owner) == ()
        assert owner.info == {}
        assert await world.event_count(ticket_id) == 0

    async def test_pre_commit_cancellation_discards(
        self, world: _World, db_session_factory: SessionFactory
    ) -> None:
        ticket_id = await world.ticket()
        owner = await db_session_factory()
        registered = asyncio.Event()

        async def owner_workflow() -> None:
            async with owner:
                await _exit_manual_zone(owner, ticket_id)
                registered.set()
                await asyncio.Event().wait()
                await owner.commit()  # pragma: no cover - never reached

        task = asyncio.create_task(owner_workflow())
        await asyncio.wait_for(registered.wait(), timeout=5)
        assert pending_ticket_convergence_effects(owner) == (
            TicketConvergenceEffect(ticket_id),
        )
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

        assert owner.info == {}
        assert pending_ticket_convergence_effects(owner) == ()
        assert await world.status(ticket_id) == TicketStatus.ANALYSIS
        assert await world.event_count(ticket_id) == 0

    async def test_binding_is_to_the_transaction_not_the_session(
        self, db_session_factory: SessionFactory
    ) -> None:
        """Even if the end-of-transaction discard never ran, a later
        transaction of the same reused session inherits nothing."""
        owner = await db_session_factory()
        stale, fresh = uuid.uuid7(), uuid.uuid7()
        event.remove(Session, "after_transaction_end", _discard_on_transaction_end)
        try:
            await owner.execute(select(1))
            register_ticket_convergence(owner, stale)
            await owner.commit()
            assert owner.info != {}

            await owner.execute(select(1))
            assert pending_ticket_convergence_effects(owner) == ()
            register_ticket_convergence(owner, fresh)
            assert pending_ticket_convergence_effects(owner) == (
                TicketConvergenceEffect(fresh),
            )
        finally:
            event.listen(Session, "after_transaction_end", _discard_on_transaction_end)
            await owner.rollback()

    async def test_concurrent_transactions_have_independent_registries(
        self, world: _World, db_session_factory: SessionFactory
    ) -> None:
        first_id = await world.ticket()
        second_id = await world.ticket()
        first = await db_session_factory()
        second = await db_session_factory()

        await _exit_manual_zone(first, first_id)
        await _exit_manual_zone(second, second_id)

        assert pending_ticket_convergence_effects(first) == (
            TicketConvergenceEffect(first_id),
        )
        assert pending_ticket_convergence_effects(second) == (
            TicketConvergenceEffect(second_id),
        )
        await first.rollback()
        assert pending_ticket_convergence_effects(second) == (
            TicketConvergenceEffect(second_id),
        )
        await second.rollback()
