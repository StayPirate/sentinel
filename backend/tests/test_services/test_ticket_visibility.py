"""Tests for the canonical Ticket visibility predicate
(backend/app/services/ticket_visibility.py).

See docs/features/identity/rbac.md (Scope and Confidential Ticket
Visibility) for the predicate under test and
docs/features/platform/testing-strategy.md (Ticket Accessibility >
Canonical predicate) for the matrix these integration tests implement
against real PostgreSQL. The predicate's consumers (the SNTL resolver and
the Ticket audit read) are tested in their own modules.
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable
from dataclasses import FrozenInstanceError
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.engine import Dialect
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import DeliveryStatus, PackageStatus, Role, Scope, TicketStatus
from app.core.permissions import get_effective_scope
from app.models.ticket import Ticket
from app.models.ticket_package import TicketPackage
from app.models.user import User
from app.services.ticket_visibility import (
    ANONYMOUS_CALLER,
    TicketCaller,
    ticket_visibility_condition,
)

Factory = Callable[..., Awaitable[Any]]


async def _is_visible(db: AsyncSession, caller: TicketCaller, ticket: Ticket) -> bool:
    """Evaluate the predicate for one Ticket in PostgreSQL."""
    result = await db.execute(
        select(Ticket.id).where(
            Ticket.id == ticket.id, ticket_visibility_condition(caller)
        )
    )
    return result.scalar_one_or_none() is not None


def _restricted(user: User) -> TicketCaller:
    return TicketCaller.authenticated(user.id, Scope.NON_CONFIDENTIAL)


def _compiled(caller: TicketCaller, dialect: Dialect) -> str:
    return str(ticket_visibility_condition(caller).compile(dialect=dialect))


@pytest.mark.unit
class TestTicketCaller:
    def test_anonymous_caller_has_no_identity_or_scope(self) -> None:
        assert ANONYMOUS_CALLER.user_id is None
        assert ANONYMOUS_CALLER.scope is None
        assert ANONYMOUS_CALLER.is_anonymous is True

    def test_authenticated_caller_carries_user_and_scope(self) -> None:
        user_id = uuid.uuid4()
        caller = TicketCaller.authenticated(user_id, Scope.ALL)
        assert caller.user_id == user_id
        assert caller.scope is Scope.ALL
        assert caller.is_anonymous is False

    @pytest.mark.parametrize(
        "kwargs",
        [{"user_id": uuid.uuid4()}, {"scope": Scope.ALL}],
        ids=["user-without-scope", "scope-without-user"],
    )
    def test_partial_caller_is_rejected(self, kwargs: dict[str, Any]) -> None:
        with pytest.raises(ValueError, match="both user_id and scope"):
            TicketCaller(**kwargs)

    def test_is_frozen(self) -> None:
        caller = TicketCaller.authenticated(uuid.uuid4(), Scope.ALL)
        with pytest.raises(FrozenInstanceError):
            caller.scope = Scope.NON_CONFIDENTIAL  # type: ignore[misc]


@pytest.mark.integration
class TestPredicateShape:
    """Compiled with the PostgreSQL dialect of the test session."""

    def test_anonymous_predicate_is_only_the_non_confidential_branch(
        self, db_session: AsyncSession
    ) -> None:
        sql = _compiled(ANONYMOUS_CALLER, db_session.get_bind().dialect)
        assert "is_confidential IS false" in sql
        assert "EXISTS" not in sql
        assert "ticket_access_grant" not in sql
        assert "ticket_package_maintainer" not in sql

    def test_scope_all_predicate_needs_no_relationship_lookup(
        self, db_session: AsyncSession
    ) -> None:
        sql = _compiled(
            TicketCaller.authenticated(uuid.uuid4(), Scope.ALL),
            db_session.get_bind().dialect,
        )
        assert "EXISTS" not in sql

    def test_restricted_predicate_is_correlated_to_ticket(
        self, db_session: AsyncSession
    ) -> None:
        caller = TicketCaller.authenticated(uuid.uuid4(), Scope.NON_CONFIDENTIAL)
        sql = str(
            select(Ticket.id)
            .where(ticket_visibility_condition(caller))
            .compile(dialect=db_session.get_bind().dialect)
        )
        assert sql.count("EXISTS") == 2
        assert "ticket_access_grant.ticket_id = ticket.id" in sql
        assert "ticket_package.ticket_id = ticket.id" in sql
        assert "ticket_package.deleted_at IS NULL" in sql
        # Correlated: only the outer statement selects FROM `ticket`; the
        # subqueries reference the enclosing row instead of scanning it.
        from_clauses = [
            line.split()[1] for line in sql.splitlines() if line.startswith("FROM ")
        ]
        assert from_clauses == [
            "ticket",
            "ticket_access_grant",
            "ticket_package_maintainer",
        ]


@pytest.mark.integration
class TestCanonicalPredicate:
    async def test_non_confidential_ticket_is_visible_to_every_caller(
        self, db_session: AsyncSession, ticket_factory: Factory, user_factory: Factory
    ) -> None:
        ticket = await ticket_factory(is_confidential=False)
        user = await user_factory()
        for caller in (
            ANONYMOUS_CALLER,
            _restricted(user),
            TicketCaller.authenticated(user.id, Scope.ALL),
        ):
            assert await _is_visible(db_session, caller, ticket)

    async def test_anonymous_caller_never_sees_a_confidential_ticket(
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

        assert not await _is_visible(db_session, ANONYMOUS_CALLER, ticket)

    async def test_scope_all_sees_confidential_without_grant_or_maintainer(
        self, db_session: AsyncSession, ticket_factory: Factory, user_factory: Factory
    ) -> None:
        ticket = await ticket_factory(is_confidential=True)
        user = await user_factory()

        assert await _is_visible(
            db_session, TicketCaller.authenticated(user.id, Scope.ALL), ticket
        )
        assert not await _is_visible(db_session, _restricted(user), ticket)

    async def test_explicit_grant_exposes_only_the_granted_ticket(
        self,
        db_session: AsyncSession,
        ticket_factory: Factory,
        user_factory: Factory,
        ticket_access_grant_factory: Factory,
    ) -> None:
        granted = await ticket_factory(is_confidential=True)
        other = await ticket_factory(is_confidential=True)
        user = await user_factory()
        someone_else = await user_factory()
        await ticket_access_grant_factory(ticket_id=granted.id, user_id=user.id)
        await ticket_access_grant_factory(ticket_id=other.id, user_id=someone_else.id)

        assert await _is_visible(db_session, _restricted(user), granted)
        assert not await _is_visible(db_session, _restricted(user), other)

    async def test_included_package_maintainer_sees_the_ticket(
        self,
        db_session: AsyncSession,
        ticket_factory: Factory,
        user_factory: Factory,
        ticket_package_factory: Factory,
        ticket_package_maintainer_factory: Factory,
    ) -> None:
        ticket = await ticket_factory(is_confidential=True)
        other_ticket = await ticket_factory(is_confidential=True)
        user = await user_factory()
        package = await ticket_package_factory(ticket_id=ticket.id)
        await ticket_package_maintainer_factory(
            ticket_package_id=package.id, user_id=user.id
        )
        other_package = await ticket_package_factory(ticket_id=other_ticket.id)
        await ticket_package_maintainer_factory(ticket_package_id=other_package.id)

        assert await _is_visible(db_session, _restricted(user), ticket)
        assert not await _is_visible(db_session, _restricted(user), other_ticket)

    async def test_package_exclusion_removes_and_restore_reactivates_access(
        self,
        db_session: AsyncSession,
        ticket_factory: Factory,
        user_factory: Factory,
        ticket_package_factory: Factory,
        ticket_package_maintainer_factory: Factory,
    ) -> None:
        ticket = await ticket_factory(is_confidential=True)
        user = await user_factory()
        package: TicketPackage = await ticket_package_factory(ticket_id=ticket.id)
        await ticket_package_maintainer_factory(
            ticket_package_id=package.id, user_id=user.id
        )

        package.deleted_at = datetime.now(UTC)
        await db_session.flush()
        assert not await _is_visible(db_session, _restricted(user), ticket)

        package.deleted_at = None
        await db_session.flush()
        assert await _is_visible(db_session, _restricted(user), ticket)

    async def test_multiple_qualifying_packages_lose_access_only_after_the_last(
        self,
        db_session: AsyncSession,
        ticket_factory: Factory,
        user_factory: Factory,
        ticket_package_factory: Factory,
        ticket_package_maintainer_factory: Factory,
    ) -> None:
        ticket = await ticket_factory(is_confidential=True)
        user = await user_factory()
        first: TicketPackage = await ticket_package_factory(ticket_id=ticket.id)
        second: TicketPackage = await ticket_package_factory(ticket_id=ticket.id)
        for package in (first, second):
            await ticket_package_maintainer_factory(
                ticket_package_id=package.id, user_id=user.id
            )

        first.deleted_at = datetime.now(UTC)
        await db_session.flush()
        assert await _is_visible(db_session, _restricted(user), ticket)

        second.deleted_at = datetime.now(UTC)
        await db_session.flush()
        assert not await _is_visible(db_session, _restricted(user), ticket)

    async def test_track_and_product_exclusion_keep_maintainer_visibility(
        self,
        db_session: AsyncSession,
        ticket_factory: Factory,
        user_factory: Factory,
        ticket_package_factory: Factory,
        ticket_package_track_factory: Factory,
        ticket_package_product_factory: Factory,
        ticket_package_maintainer_factory: Factory,
    ) -> None:
        ticket = await ticket_factory(is_confidential=True)
        user = await user_factory()
        package = await ticket_package_factory(ticket_id=ticket.id)
        await ticket_package_maintainer_factory(
            ticket_package_id=package.id, user_id=user.id
        )
        excluded_at = datetime.now(UTC)
        track = await ticket_package_track_factory(
            ticket_package_id=package.id, deleted_at=excluded_at
        )
        await ticket_package_product_factory(
            ticket_package_track_id=track.id, deleted_at=excluded_at
        )

        assert await _is_visible(db_session, _restricted(user), ticket)

    @pytest.mark.parametrize("status", list(TicketStatus))
    async def test_package_and_ticket_state_do_not_change_visibility(
        self,
        status: TicketStatus,
        db_session: AsyncSession,
        ticket_factory: Factory,
        user_factory: Factory,
        product_factory: Factory,
        ticket_package_factory: Factory,
        ticket_package_track_factory: Factory,
        ticket_package_product_factory: Factory,
        ticket_package_maintainer_factory: Factory,
    ) -> None:
        """Ticket status, affectedness, delivery, eligibility, Product
        release, and Product EOL leave the maintainer branch intact."""
        ticket = await ticket_factory(is_confidential=True, status=status.value)
        user = await user_factory()
        package = await ticket_package_factory(ticket_id=ticket.id)
        await ticket_package_maintainer_factory(
            ticket_package_id=package.id, user_id=user.id
        )
        track = await ticket_package_track_factory(
            ticket_package_id=package.id,
            status=PackageStatus.NOT_AFFECTED.value,
            delivery_status=DeliveryStatus.RELEASED.value,
        )
        eol_product = await product_factory(
            general_support_end_date=datetime.now(UTC).date() - timedelta(days=400),
            extended_support_end_date=datetime.now(UTC).date() - timedelta(days=200),
            reactive_support_end_date=datetime.now(UTC).date() - timedelta(days=100),
        )
        await ticket_package_product_factory(
            ticket_package_track_id=track.id,
            product_id=eol_product.id,
            eligible=False,
            released_at=datetime.now(UTC),
        )

        assert await _is_visible(db_session, _restricted(user), ticket)

    async def test_user_without_roles_gains_visibility_only_per_ticket(
        self,
        db_session: AsyncSession,
        ticket_factory: Factory,
        user_factory: Factory,
        ticket_access_grant_factory: Factory,
        ticket_package_factory: Factory,
        ticket_package_maintainer_factory: Factory,
    ) -> None:
        user = await user_factory()
        caller = TicketCaller.authenticated(user.id, get_effective_scope([]))
        granted = await ticket_factory(is_confidential=True)
        maintained = await ticket_factory(is_confidential=True)
        hidden = await ticket_factory(is_confidential=True)
        await ticket_access_grant_factory(ticket_id=granted.id, user_id=user.id)
        package = await ticket_package_factory(ticket_id=maintained.id)
        await ticket_package_maintainer_factory(
            ticket_package_id=package.id, user_id=user.id
        )

        assert caller.scope is Scope.NON_CONFIDENTIAL
        assert await _is_visible(db_session, caller, granted)
        assert await _is_visible(db_session, caller, maintained)
        assert not await _is_visible(db_session, caller, hidden)

    @pytest.mark.parametrize(
        ("roles", "expected"),
        [
            ([Role.RESTRICTED_ANALYST], False),
            ([Role.VULNERABILITY_ANALYST], True),
            ([Role.ADMIN], True),
            ([Role.RESTRICTED_ANALYST, Role.VULNERABILITY_ANALYST], True),
        ],
    )
    async def test_role_scope_drives_the_scope_branch(
        self,
        roles: list[Role],
        expected: bool,
        db_session: AsyncSession,
        ticket_factory: Factory,
        user_factory: Factory,
    ) -> None:
        ticket = await ticket_factory(is_confidential=True)
        user = await user_factory()
        caller = TicketCaller.authenticated(user.id, get_effective_scope(roles))

        assert await _is_visible(db_session, caller, ticket) is expected
