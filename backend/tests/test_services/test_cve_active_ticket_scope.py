"""Tests for `cve_service.get_active_ticket_cve_ids()`.

Owning specifications: docs/features/platform/cve-fetcher-infrastructure.md
(Session Lifecycle for API-based CVE Fetchers); the Scope of
docs/features/tickets/cve-sync-redhat.md, cve-sync-epss.md, and
cve-sync-osv.md; docs/features/tickets/tickets.md (Status Categories);
docs/features/platform/testing-strategy.md (Service Functions;
Concurrency Testing).

`Ticket.cve_id` is UNIQUE, so one CVE is referenced by at most one Ticket
and no CVE can carry both an active and an inactive Ticket. Every
`db_session` test starts from empty CVE and Ticket tables (per-test
rollback). The lock test commits its rows through independent sessions
and deletes them explicitly.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from typing import Any

import pytest
from sqlalchemy import Select, delete, event, select
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import TicketStatus
from app.models.cve import CVE
from app.models.ticket import Ticket
from app.services.cve_service import get_active_ticket_cve_ids

Factory = Callable[..., Awaitable[Any]]
SessionFactory = Callable[[], Awaitable[AsyncSession]]

ACTIVE = (TicketStatus.NEW, TicketStatus.ANALYSIS, TicketStatus.ANALYZED)
INACTIVE = (TicketStatus.RESOLVED, TicketStatus.IGNORED, TicketStatus.DUPLICATED)
ROW_LOCKS = ("FOR UPDATE", "FOR NO KEY UPDATE", "FOR SHARE", "FOR KEY SHARE")


async def _cve_with_ticket(
    cve_factory: Factory, ticket_factory: Factory, status: TicketStatus, **cve: Any
) -> CVE:
    created: CVE = await cve_factory(**cve)
    await ticket_factory(cve_id=created.id, status=status.value)
    return created


@pytest.mark.integration
class TestScope:
    @pytest.mark.parametrize("status", ACTIVE)
    async def test_cve_of_an_active_ticket_is_selected(
        self,
        db_session: AsyncSession,
        cve_factory: Factory,
        ticket_factory: Factory,
        status: TicketStatus,
    ) -> None:
        cve = await _cve_with_ticket(cve_factory, ticket_factory, status)

        assert await get_active_ticket_cve_ids(db_session) == [cve.cve_id]

    @pytest.mark.parametrize("status", INACTIVE)
    async def test_cve_of_an_inactive_ticket_is_excluded(
        self,
        db_session: AsyncSession,
        cve_factory: Factory,
        ticket_factory: Factory,
        status: TicketStatus,
    ) -> None:
        await _cve_with_ticket(cve_factory, ticket_factory, status)

        assert await get_active_ticket_cve_ids(db_session) == []

    async def test_cve_less_active_tickets_and_ticketless_cves_are_excluded(
        self,
        db_session: AsyncSession,
        cve_factory: Factory,
        ticket_factory: Factory,
    ) -> None:
        for status in ACTIVE:
            await ticket_factory(status=status.value)
        await cve_factory()

        assert await get_active_ticket_cve_ids(db_session) == []

    async def test_empty_database_returns_an_empty_list(
        self, db_session: AsyncSession
    ) -> None:
        assert await get_active_ticket_cve_ids(db_session) == []

    async def test_mixed_scope_is_each_active_cve_once_in_code_point_order(
        self,
        db_session: AsyncSession,
        cve_factory: Factory,
        ticket_factory: Factory,
    ) -> None:
        """Insertion order differs from the result order, and the numeric
        order of the sequence parts differs from the code point order."""
        for cve_id, status in (
            ("CVE-2099-9999", TicketStatus.ANALYZED),
            ("CVE-2099-100000", TicketStatus.NEW),
            ("CVE-2099-20000", TicketStatus.RESOLVED),
            ("CVE-2099-10000", TicketStatus.ANALYSIS),
            ("CVE-2098-99999", TicketStatus.NEW),
            ("CVE-2099-30000", TicketStatus.IGNORED),
        ):
            await _cve_with_ticket(cve_factory, ticket_factory, status, cve_id=cve_id)
        await cve_factory(cve_id="CVE-2099-1000")

        assert await get_active_ticket_cve_ids(db_session) == [
            "CVE-2098-99999",
            "CVE-2099-10000",
            "CVE-2099-100000",
            "CVE-2099-9999",
        ]


@pytest.mark.integration
class TestReadOnly:
    async def test_one_lock_free_select_leaves_the_session_untouched(
        self,
        db_session: AsyncSession,
        cve_factory: Factory,
        ticket_factory: Factory,
    ) -> None:
        """A pending active Ticket is neither flushed nor observed, and the
        caller-owned transaction stays open."""
        cve = await _cve_with_ticket(cve_factory, ticket_factory, TicketStatus.NEW)
        pending_cve: CVE = await cve_factory()
        pending = Ticket(cve_id=pending_cve.id)
        db_session.add(pending)
        statements: list[str] = []
        engine = db_session.get_bind().engine

        def record(*args: Any) -> None:
            statements.append(args[2])

        event.listen(engine, "before_cursor_execute", record)
        try:
            result = await get_active_ticket_cve_ids(db_session)
        finally:
            event.remove(engine, "before_cursor_execute", record)

        assert result == [cve.cve_id]
        (statement,) = statements
        assert statement.lstrip().upper().startswith("SELECT")
        for row_lock in ROW_LOCKS:
            assert row_lock not in statement.upper()
        assert list(db_session.new) == [pending]
        assert not db_session.dirty
        assert not db_session.deleted
        assert db_session.in_transaction()


class _CommittedScope:
    """One active Ticket and its CVE committed through an independent
    session and deleted at teardown (testing-strategy.md, Concurrency
    Testing: committed data is not rolled back by the fixture)."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.cve_ids: list[uuid.UUID] = []
        self.ticket_ids: list[uuid.UUID] = []

    async def active_ticket(self) -> tuple[CVE, Ticket]:
        cve = CVE(cve_id=f"CVE-2099-{uuid.uuid4().int % 10**9:09d}")
        self.session.add(cve)
        await self.session.flush()
        self.cve_ids.append(cve.id)
        ticket = Ticket(cve_id=cve.id, status=TicketStatus.ANALYSIS.value)
        self.session.add(ticket)
        await self.session.flush()
        self.ticket_ids.append(ticket.id)
        await self.session.commit()
        return cve, ticket

    async def cleanup(self) -> None:
        await self.session.rollback()
        await self.session.execute(delete(Ticket).where(Ticket.id.in_(self.ticket_ids)))
        await self.session.execute(delete(CVE).where(CVE.id.in_(self.cve_ids)))
        await self.session.commit()


@pytest.fixture
async def committed_scope(
    db_session_factory: SessionFactory,
) -> AsyncIterator[_CommittedScope]:
    scope = _CommittedScope(await db_session_factory())
    try:
        yield scope
    finally:
        await scope.cleanup()


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


@pytest.mark.integration
class TestNoRowLock:
    async def test_open_reading_transaction_holds_no_ticket_or_cve_lock(
        self,
        committed_scope: _CommittedScope,
        db_session_factory: SessionFactory,
    ) -> None:
        cve, ticket = await committed_scope.active_ticket()
        reader = await db_session_factory()
        probe = await db_session_factory()

        try:
            assert cve.cve_id in await get_active_ticket_cve_ids(reader)

            assert reader.in_transaction()
            assert not await _is_locked(
                probe, select(Ticket.id).where(Ticket.id == ticket.id)
            )
            assert not await _is_locked(probe, select(CVE.id).where(CVE.id == cve.id))
        finally:
            # Release any lock before the committed rows are deleted.
            await reader.rollback()
