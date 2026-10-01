"""Integration tests for `lock_accessible_ticket_by_locator()`
(backend/app/services/ticket_mutations.py).

The manual reference mutations receive the public `SNTL-{n}` locator and
lock the parent Ticket as their serialization root before any nested
state is disclosed (docs/features/tickets/ticket-references.md, Manual
Mutation Ordering; Security and Privacy). The locator grammar is
docs/api-spec.md (Ticket Identifier Resolution), the accessibility
decision is the canonical predicate of docs/features/identity/rbac.md
(Scope and Confidential Ticket Visibility), and the lock-then-revalidate
order is docs/api-spec.md (Authorization Chain Evaluation Order, flow 3).
The accessibility cases follow docs/features/platform/testing-strategy.md
(Ticket References: anonymous, `non_confidential` scope, scope `all`,
explicit grant, included-package maintainership, and loss of a path).

Malformed locators never reach the database; missing and inaccessible
Tickets raise the one shared `TicketNotFoundError`.
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Any

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import Scope
from app.core.exceptions import TicketNotFoundError
from app.core.identifiers import format_ticket_id
from app.models.ticket import Ticket
from app.models.ticket_package import TicketPackage
from app.models.user import User
from app.services.ticket_mutations import lock_accessible_ticket_by_locator
from app.services.ticket_visibility import ANONYMOUS_CALLER, TicketCaller
from tests.support.ticket_api import INVALID_LOCATORS, MAX_SEQUENCE
from tests.support.ticket_mutations import StatementRecorder

Factory = Callable[..., Awaitable[Any]]

_MALFORMED: list[tuple[str, Callable[[Ticket], str]]] = [
    *(case for case in INVALID_LOCATORS if case[0] != "well-formed-missing"),
    ("random-uuid", lambda _t: str(uuid.uuid4())),
    ("prefixed-uuid", lambda t: f"SNTL-{t.id}"),
    ("zero", lambda _t: "SNTL-0"),
    ("empty", lambda _t: ""),
    ("prefix-only", lambda _t: "SNTL-"),
    ("bare-number", lambda t: str(t.sequence_id)),
    ("leading-space", lambda t: f" SNTL-{t.sequence_id}"),
    ("trailing-newline", lambda t: f"SNTL-{t.sequence_id}\n"),
]
"""Locators the SNTL grammar rejects, each built against an existing
Ticket so a lookup by any column could have found it."""


def _restricted(user: User) -> TicketCaller:
    return TicketCaller.authenticated(user.id, Scope.NON_CONFIDENTIAL)


async def _lock(
    db: AsyncSession, ticket: Ticket, caller: TicketCaller
) -> tuple[Ticket, StatementRecorder]:
    with StatementRecorder(db) as recorder:
        locked = await lock_accessible_ticket_by_locator(
            db, format_ticket_id(ticket.sequence_id), caller
        )
    return locked, recorder


async def _denied(
    db: AsyncSession, ticket: Ticket, caller: TicketCaller
) -> StatementRecorder:
    with StatementRecorder(db) as recorder, pytest.raises(TicketNotFoundError):
        await lock_accessible_ticket_by_locator(
            db, format_ticket_id(ticket.sequence_id), caller
        )
    return recorder


def _assert_lock_statement(statement: str) -> None:
    """The Ticket row lock selected by `sequence_id`."""
    assert statement.lstrip().upper().startswith("SELECT")
    assert "FROM ticket" in statement
    assert "ticket.sequence_id =" in statement
    assert statement.rstrip().endswith("FOR UPDATE")


def _assert_visibility_statement(statement: str) -> None:
    """The separate, non-locking accessibility statement for the Ticket."""
    assert statement.lstrip().upper().startswith("SELECT")
    assert "FROM ticket" in statement
    assert "ticket.id =" in statement
    assert "FOR UPDATE" not in statement


@pytest.mark.integration
class TestMalformedLocator:
    @pytest.mark.parametrize(
        "build", [build for _, build in _MALFORMED], ids=[n for n, _ in _MALFORMED]
    )
    async def test_raises_not_found_without_any_statement(
        self,
        db_session: AsyncSession,
        ticket_factory: Factory,
        build: Callable[[Ticket], str],
    ) -> None:
        ticket = await ticket_factory()
        user_id = uuid.uuid4()

        with StatementRecorder(db_session) as recorder:
            for caller in (
                ANONYMOUS_CALLER,
                TicketCaller.authenticated(user_id, Scope.ALL),
            ):
                with pytest.raises(TicketNotFoundError):
                    await lock_accessible_ticket_by_locator(
                        db_session, build(ticket), caller
                    )

        assert recorder.statements == []


@pytest.mark.integration
class TestMissingTicket:
    async def test_well_formed_missing_locator_raises_not_found_after_one_lock(
        self, db_session: AsyncSession, ticket_factory: Factory
    ) -> None:
        # Another Ticket exists (and opens the test savepoint), so only the
        # function's own statements are recorded.
        await ticket_factory()

        with (
            StatementRecorder(db_session) as recorder,
            pytest.raises(TicketNotFoundError),
        ):
            await lock_accessible_ticket_by_locator(
                db_session,
                format_ticket_id(MAX_SEQUENCE),
                TicketCaller.authenticated(uuid.uuid4(), Scope.ALL),
            )

        # No visibility statement follows a failed lock lookup.
        assert len(recorder.statements) == 1
        _assert_lock_statement(recorder.statements[0])
        assert recorder.parameters[0] == (MAX_SEQUENCE,)


@pytest.mark.integration
class TestInaccessibleTicket:
    async def test_confidential_ticket_denied_to_non_confidential_scope(
        self, db_session: AsyncSession, ticket_factory: Factory, user_factory: Factory
    ) -> None:
        ticket = await ticket_factory(is_confidential=True)
        user = await user_factory()

        recorder = await _denied(db_session, ticket, _restricted(user))

        assert len(recorder.statements) == 2
        _assert_lock_statement(recorder.statements[0])
        _assert_visibility_statement(recorder.statements[1])

    async def test_confidential_ticket_denied_to_anonymous_caller(
        self,
        db_session: AsyncSession,
        ticket_factory: Factory,
        ticket_access_grant_factory: Factory,
        ticket_package_factory: Factory,
        ticket_package_maintainer_factory: Factory,
    ) -> None:
        ticket = await ticket_factory(is_confidential=True)
        await ticket_access_grant_factory(ticket_id=ticket.id)
        package = await ticket_package_factory(ticket_id=ticket.id)
        await ticket_package_maintainer_factory(ticket_package_id=package.id)

        recorder = await _denied(db_session, ticket, ANONYMOUS_CALLER)

        assert len(recorder.statements) == 2
        _assert_lock_statement(recorder.statements[0])
        _assert_visibility_statement(recorder.statements[1])

    async def test_grant_for_another_user_does_not_grant_access(
        self,
        db_session: AsyncSession,
        ticket_factory: Factory,
        user_factory: Factory,
        ticket_access_grant_factory: Factory,
    ) -> None:
        ticket = await ticket_factory(is_confidential=True)
        await ticket_access_grant_factory(ticket_id=ticket.id)
        user = await user_factory()

        await _denied(db_session, ticket, _restricted(user))

    async def test_maintainer_of_an_excluded_package_loses_access(
        self,
        db_session: AsyncSession,
        ticket_factory: Factory,
        user_factory: Factory,
        ticket_package_factory: Factory,
        ticket_package_maintainer_factory: Factory,
    ) -> None:
        ticket = await ticket_factory(is_confidential=True)
        user = await user_factory()
        package: TicketPackage = await ticket_package_factory(
            ticket_id=ticket.id, deleted_at=datetime.now(UTC)
        )
        await ticket_package_maintainer_factory(
            ticket_package_id=package.id, user_id=user.id
        )

        await _denied(db_session, ticket, _restricted(user))


@pytest.mark.integration
class TestAccessibleTicket:
    async def test_non_confidential_ticket_is_locked_for_anonymous_caller(
        self, db_session: AsyncSession, ticket_factory: Factory
    ) -> None:
        ticket = await ticket_factory(is_confidential=False)

        locked, recorder = await _lock(db_session, ticket, ANONYMOUS_CALLER)

        assert locked.id == ticket.id
        assert len(recorder.statements) == 2
        _assert_lock_statement(recorder.statements[0])
        _assert_visibility_statement(recorder.statements[1])

    async def test_scope_all_locks_a_confidential_ticket(
        self, db_session: AsyncSession, ticket_factory: Factory, user_factory: Factory
    ) -> None:
        ticket = await ticket_factory(is_confidential=True)
        user = await user_factory()

        locked, recorder = await _lock(
            db_session, ticket, TicketCaller.authenticated(user.id, Scope.ALL)
        )

        assert locked.id == ticket.id
        assert locked.sequence_id == ticket.sequence_id
        _assert_lock_statement(recorder.statements[0])
        _assert_visibility_statement(recorder.statements[1])

    async def test_explicit_grant_locks_a_confidential_ticket(
        self,
        db_session: AsyncSession,
        ticket_factory: Factory,
        user_factory: Factory,
        ticket_access_grant_factory: Factory,
    ) -> None:
        ticket = await ticket_factory(is_confidential=True)
        user = await user_factory()
        await ticket_access_grant_factory(ticket_id=ticket.id, user_id=user.id)

        locked, recorder = await _lock(db_session, ticket, _restricted(user))

        assert locked.id == ticket.id
        assert len(recorder.statements) == 2
        _assert_lock_statement(recorder.statements[0])
        _assert_visibility_statement(recorder.statements[1])
        assert "ticket_access_grant" in recorder.statements[1]

    async def test_included_package_maintainer_locks_a_confidential_ticket(
        self,
        db_session: AsyncSession,
        ticket_factory: Factory,
        user_factory: Factory,
        ticket_package_factory: Factory,
        ticket_package_maintainer_factory: Factory,
    ) -> None:
        ticket = await ticket_factory(is_confidential=True)
        user = await user_factory()
        package = await ticket_package_factory(ticket_id=ticket.id)
        await ticket_package_maintainer_factory(
            ticket_package_id=package.id, user_id=user.id
        )

        locked, recorder = await _lock(db_session, ticket, _restricted(user))

        assert locked.id == ticket.id
        _assert_lock_statement(recorder.statements[0])
        _assert_visibility_statement(recorder.statements[1])
        assert "ticket_package_maintainer" in recorder.statements[1]

    async def test_locks_only_the_named_ticket(
        self, db_session: AsyncSession, ticket_factory: Factory
    ) -> None:
        other = await ticket_factory()
        ticket = await ticket_factory()

        locked, recorder = await _lock(db_session, ticket, ANONYMOUS_CALLER)

        assert locked.id == ticket.id != other.id
        assert len(recorder.row_locks()) == 1
        assert recorder.parameters[0] == (ticket.sequence_id,)
