"""Tests for the Ticket service (backend/app/services/ticket_service.py).

See docs/features/tickets/ticket-service.md (Ticket Query Operations >
Ticket locator resolution) and docs/api-spec.md (Ticket Identifier
Resolution) for the contract under test: SNTL-only parsing without
normalization, lookup by `Ticket.sequence_id`, the canonical visibility
predicate, and one indistinguishable `TicketNotFoundError` for every
denial cause.
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable
from typing import Any
from unittest.mock import AsyncMock

import pytest
from sqlalchemy.exc import OperationalError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import Scope
from app.core.exceptions import ServiceError, TicketNotFoundError
from app.core.identifiers import format_ticket_id
from app.models.ticket import Ticket
from app.services.ticket_service import ResolvedTicket, resolve_ticket_locator
from app.services.ticket_visibility import ANONYMOUS_CALLER, TicketCaller

Factory = Callable[..., Awaitable[Any]]

MALFORMED_LOCATORS = [
    "sntl-1",
    "Sntl-1",
    " SNTL-1",
    "SNTL-1 ",
    "SNTL-1\n",
    "SNTL-0",
    "SNTL-01",
    "SNTL-0042",
    "SNTL-+1",
    "SNTL--1",
    "SNTL-",
    "SNTL-2147483648",
    "SNTL-99999999999999999999",
    "1",
    "",
    "SNTL-1/audit-log",
    "018f0e2a-7b1c-7cde-8f00-000000000001",
]


@pytest.mark.unit
class TestTicketNotFoundError:
    def test_is_a_shared_service_error(self) -> None:
        assert issubclass(TicketNotFoundError, ServiceError)

    def test_message_is_static(self) -> None:
        assert str(TicketNotFoundError()) == "Ticket not found."


@pytest.mark.unit
class TestMalformedLocatorPerformsNoQuery:
    @pytest.mark.parametrize("locator", MALFORMED_LOCATORS)
    async def test_malformed_locator_raises_without_database_access(
        self, locator: str
    ) -> None:
        db = AsyncMock(spec=AsyncSession)

        with pytest.raises(TicketNotFoundError):
            await resolve_ticket_locator(db, locator, ANONYMOUS_CALLER)

        db.execute.assert_not_awaited()


@pytest.mark.integration
class TestResolveTicketLocator:
    async def test_visible_ticket_resolves_to_internal_identity(
        self, db_session: AsyncSession, ticket_factory: Factory
    ) -> None:
        ticket: Ticket = await ticket_factory()

        resolved = await resolve_ticket_locator(
            db_session, format_ticket_id(ticket.sequence_id), ANONYMOUS_CALLER
        )

        assert resolved == ResolvedTicket(id=ticket.id, sequence_id=ticket.sequence_id)

    async def test_ticket_uuid_is_not_a_locator(
        self, db_session: AsyncSession, ticket_factory: Factory
    ) -> None:
        ticket: Ticket = await ticket_factory()

        with pytest.raises(TicketNotFoundError):
            await resolve_ticket_locator(db_session, str(ticket.id), ANONYMOUS_CALLER)

    async def test_well_formed_missing_locator_is_not_found(
        self, db_session: AsyncSession
    ) -> None:
        with pytest.raises(TicketNotFoundError):
            await resolve_ticket_locator(
                db_session, "SNTL-2147483647", ANONYMOUS_CALLER
            )

    async def test_inaccessible_ticket_is_not_found(
        self, db_session: AsyncSession, ticket_factory: Factory, user_factory: Factory
    ) -> None:
        ticket: Ticket = await ticket_factory(is_confidential=True)
        user = await user_factory()
        locator = format_ticket_id(ticket.sequence_id)

        for caller in (
            ANONYMOUS_CALLER,
            TicketCaller.authenticated(user.id, Scope.NON_CONFIDENTIAL),
        ):
            with pytest.raises(TicketNotFoundError):
                await resolve_ticket_locator(db_session, locator, caller)

    async def test_accessible_confidential_ticket_resolves(
        self,
        db_session: AsyncSession,
        ticket_factory: Factory,
        user_factory: Factory,
        ticket_access_grant_factory: Factory,
    ) -> None:
        ticket: Ticket = await ticket_factory(is_confidential=True)
        user = await user_factory()
        await ticket_access_grant_factory(ticket_id=ticket.id, user_id=user.id)
        locator = format_ticket_id(ticket.sequence_id)

        for caller in (
            TicketCaller.authenticated(user.id, Scope.NON_CONFIDENTIAL),
            TicketCaller.authenticated(uuid.uuid4(), Scope.ALL),
        ):
            resolved = await resolve_ticket_locator(db_session, locator, caller)
            assert resolved.id == ticket.id

    async def test_every_denial_cause_raises_the_same_exception(
        self, db_session: AsyncSession, ticket_factory: Factory
    ) -> None:
        confidential: Ticket = await ticket_factory(is_confidential=True)
        causes = [
            "sntl-1",
            str(confidential.id),
            "SNTL-2147483647",
            format_ticket_id(confidential.sequence_id),
        ]
        messages = set()
        for locator in causes:
            with pytest.raises(TicketNotFoundError) as excinfo:
                await resolve_ticket_locator(db_session, locator, ANONYMOUS_CALLER)
            assert type(excinfo.value) is TicketNotFoundError
            messages.add(str(excinfo.value))
        assert messages == {"Ticket not found."}

    async def test_database_error_propagates(self) -> None:
        db = AsyncMock(spec=AsyncSession)
        failure = OperationalError("SELECT 1", {}, Exception("connection lost"))
        db.execute.side_effect = failure

        with pytest.raises(OperationalError) as excinfo:
            await resolve_ticket_locator(db, "SNTL-1", ANONYMOUS_CALLER)

        assert excinfo.value is failure
