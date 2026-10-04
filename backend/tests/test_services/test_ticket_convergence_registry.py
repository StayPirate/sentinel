"""Transaction-local Ticket convergence registration lifecycle.

Owning specifications:

- docs/features/tickets/ticket-mutations.md (Transaction-Local Ticket
  Convergence Registration, steps 1-5: registration, deduplication and
  order, discard, detach and consume, interruption gap).
- docs/features/platform/testing-strategy.md (Ticket Convergence
  Publication Handoff > Transaction-local lifecycle): registration carries
  only the Ticket UUID and performs no query or I/O; rollback, a failed or
  ambiguous commit, and pre-commit cancellation leave nothing to detach;
  a successful commit leaves the complete sequence detachable exactly
  once; a reused session neither replays nor inherits an effect. These
  tests use real PostgreSQL with independent sessions and deterministic
  ordering. The publication policies built on the detach are covered in
  `test_ticket_convergence_publication.py`.
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
    _drop_undetached_on_new_transaction,
    _finish_on_transaction_end,
    detach_ticket_convergence_effects,
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
    async def test_successful_commit_detaches_complete_sequence_once(
        self, world: _World, db_session_factory: SessionFactory
    ) -> None:
        first_id = await world.ticket()
        second_id = await world.ticket()
        owner = await db_session_factory()
        await _exit_manual_zone(owner, second_id)
        await _exit_manual_zone(owner, first_id)
        await _exit_manual_zone(owner, second_id)
        assert pending_ticket_convergence_effects(owner) == (
            TicketConvergenceEffect(second_id),
            TicketConvergenceEffect(first_id),
        )

        await owner.commit()

        assert detach_ticket_convergence_effects(owner) == (
            TicketConvergenceEffect(second_id),
            TicketConvergenceEffect(first_id),
        )
        # Consumed exactly once: nothing is left to replay.
        assert detach_ticket_convergence_effects(owner) == ()
        assert owner.info == {}
        await owner.execute(select(1))
        assert pending_ticket_convergence_effects(owner) == ()
        await owner.rollback()
        assert detach_ticket_convergence_effects(owner) == ()
        assert await world.event_count(first_id) == 1

    async def test_detach_after_session_close(
        self, world: _World, db_session_factory: SessionFactory
    ) -> None:
        ticket_id = await world.ticket()
        owner = await db_session_factory()
        async with owner:
            await _exit_manual_zone(owner, ticket_id)
            await owner.commit()

        assert detach_ticket_convergence_effects(owner) == (
            TicketConvergenceEffect(ticket_id),
        )

    async def test_detach_performs_no_database_io(
        self, world: _World, db_session_factory: SessionFactory
    ) -> None:
        ticket_id = await world.ticket()
        owner = await db_session_factory()
        await _exit_manual_zone(owner, ticket_id)
        await owner.commit()
        engine = owner.get_bind().engine
        statements: list[str] = []

        def record(*args: Any) -> None:
            statements.append(args[2])

        event.listen(engine, "before_cursor_execute", record)
        try:
            effects = detach_ticket_convergence_effects(owner)
        finally:
            event.remove(engine, "before_cursor_execute", record)

        assert effects == (TicketConvergenceEffect(ticket_id),)
        assert statements == []

    async def test_commit_without_registration_detaches_nothing(
        self, db_session_factory: SessionFactory
    ) -> None:
        owner = await db_session_factory()
        await owner.execute(select(1))
        await owner.commit()

        assert detach_ticket_convergence_effects(owner) == ()
        assert owner.info == {}

    async def test_next_transaction_never_inherits_an_undetached_sequence(
        self, world: _World, db_session_factory: SessionFactory
    ) -> None:
        stale_id = await world.ticket()
        owner = await db_session_factory()
        await _exit_manual_zone(owner, stale_id)
        await owner.commit()

        # The owner never drained; a new transaction begins on the session.
        await owner.execute(select(1))
        fresh = uuid.uuid7()
        register_ticket_convergence(owner, fresh)
        await owner.commit()

        assert detach_ticket_convergence_effects(owner) == (
            TicketConvergenceEffect(fresh),
        )

    async def test_rollback_discards_and_next_transaction_starts_empty(
        self, world: _World, db_session_factory: SessionFactory
    ) -> None:
        ticket_id = await world.ticket()
        owner = await db_session_factory()
        await _exit_manual_zone(owner, ticket_id)

        await owner.rollback()

        assert detach_ticket_convergence_effects(owner) == ()
        assert pending_ticket_convergence_effects(owner) == ()
        other_id = uuid.uuid7()
        await owner.execute(select(1))
        register_ticket_convergence(owner, other_id)
        assert pending_ticket_convergence_effects(owner) == (
            TicketConvergenceEffect(other_id),
        )
        await owner.rollback()
        assert detach_ticket_convergence_effects(owner) == ()
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

        assert detach_ticket_convergence_effects(owner) == ()
        assert owner.info == {}
        assert await world.event_count(ticket_id) == 0

    async def test_ambiguous_commit_outcome_discards(
        self, world: _World, db_session_factory: SessionFactory
    ) -> None:
        """An exception raised at the connection's COMMIT boundary leaves
        the outcome unknown to the owner: nothing becomes detachable."""
        ticket_id = await world.ticket()
        owner = await db_session_factory()
        await _exit_manual_zone(owner, ticket_id)
        connection = await owner.connection()

        def fail_commit(conn: Any) -> None:
            raise ConnectionResetError("commit outcome unknown")

        event.listen(connection.sync_connection, "commit", fail_commit)
        try:
            with pytest.raises(ConnectionResetError):
                await owner.commit()
        finally:
            event.remove(connection.sync_connection, "commit", fail_commit)
        # The owner terminates: the connection with the unknown outcome is
        # discarded (its server-side transaction ends with it).
        await connection.invalidate()
        await owner.close()

        assert detach_ticket_convergence_effects(owner) == ()
        assert owner.info == {}

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
        assert detach_ticket_convergence_effects(owner) == ()
        assert await world.status(ticket_id) == TicketStatus.ANALYSIS
        assert await world.event_count(ticket_id) == 0

    async def test_savepoint_boundaries_do_not_decide(
        self, db_session_factory: SessionFactory
    ) -> None:
        owner = await db_session_factory()
        kept, released = uuid.uuid7(), uuid.uuid7()
        await owner.execute(select(1))

        savepoint = await owner.begin_nested()
        register_ticket_convergence(owner, kept)
        await savepoint.rollback()
        savepoint = await owner.begin_nested()
        register_ticket_convergence(owner, released)
        await savepoint.commit()

        # A savepoint release is not the owner's commit.
        assert detach_ticket_convergence_effects(owner) == ()
        await owner.commit()
        assert detach_ticket_convergence_effects(owner) == (
            TicketConvergenceEffect(kept),
            TicketConvergenceEffect(released),
        )

    async def test_binding_is_to_the_transaction_not_the_session(
        self, db_session_factory: SessionFactory
    ) -> None:
        """Even if neither end-of-transaction listener ran, a later
        transaction of the same reused session inherits nothing."""
        owner = await db_session_factory()
        stale, fresh = uuid.uuid7(), uuid.uuid7()
        event.remove(Session, "after_transaction_end", _finish_on_transaction_end)
        event.remove(
            Session, "after_transaction_create", _drop_undetached_on_new_transaction
        )
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
            event.listen(Session, "after_transaction_end", _finish_on_transaction_end)
            event.listen(
                Session,
                "after_transaction_create",
                _drop_undetached_on_new_transaction,
            )
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
        await second.commit()
        assert detach_ticket_convergence_effects(first) == ()
        assert detach_ticket_convergence_effects(second) == (
            TicketConvergenceEffect(second_id),
        )
