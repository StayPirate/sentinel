"""Integration tests for the TicketAccessGrant model
(backend/app/models/ticket_access_grant.py).

See docs/data-model.md (TicketAccessGrant, Notes) and
docs/features/tickets/tickets.md (Confidential Tickets). Only the
persistence contract is covered here; grant and revoke idempotency,
declassification deletion, and the visibility predicate are service
behavior.
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import insert, inspect, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.ticket import Ticket
from app.models.ticket_access_grant import TicketAccessGrant
from app.models.user import User

TicketFactory = Callable[..., Awaitable[Ticket]]
UserFactory = Callable[..., Awaitable[User]]
TicketAccessGrantFactory = Callable[..., Awaitable[TicketAccessGrant]]


@pytest.mark.integration
class TestTicketAccessGrantCreation:
    async def test_create_with_defaults(
        self,
        db_session: AsyncSession,
        ticket_access_grant_factory: TicketAccessGrantFactory,
    ) -> None:
        grant = await ticket_access_grant_factory()

        assert grant.ticket_id is not None
        assert grant.user_id is not None
        assert grant.granted_by_id is not None
        assert grant.granted_by_id != grant.user_id
        assert grant.granted_at is not None
        assert grant.granted_at.tzinfo is not None
        ticket = await db_session.get(Ticket, grant.ticket_id)
        assert ticket is not None
        assert ticket.is_confidential is True

    async def test_explicit_granted_at_round_trip(
        self,
        db_session: AsyncSession,
        ticket_access_grant_factory: TicketAccessGrantFactory,
    ) -> None:
        granted_at = datetime(2025, 3, 15, 10, 30, tzinfo=UTC)
        grant = await ticket_access_grant_factory(granted_at=granted_at)
        key = (grant.ticket_id, grant.user_id)
        db_session.expunge(grant)

        reloaded = await db_session.get(TicketAccessGrant, key)
        assert reloaded is not None
        assert reloaded.granted_at == granted_at

    async def test_database_assigns_granted_at(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        user_factory: UserFactory,
    ) -> None:
        """`granted_at` has a `now()` server default and no Python default."""
        ticket = await ticket_factory(is_confidential=True)
        user = await user_factory()
        granter = await user_factory()
        result = await db_session.execute(
            insert(TicketAccessGrant)
            .values(ticket_id=ticket.id, user_id=user.id, granted_by_id=granter.id)
            .returning(TicketAccessGrant.granted_at)
        )
        granted_at = result.scalar_one()
        assert granted_at.tzinfo is not None
        assert abs(granted_at - datetime.now(UTC)) < timedelta(hours=1)

    async def test_granting_user_may_be_the_target_user(
        self,
        ticket_access_grant_factory: TicketAccessGrantFactory,
        user_factory: UserFactory,
    ) -> None:
        """No CHECK distinguishes the two users (#611 decision A3)."""
        user = await user_factory()
        grant = await ticket_access_grant_factory(
            user_id=user.id, granted_by_id=user.id
        )
        assert grant.user_id == grant.granted_by_id

    async def test_non_confidential_ticket_not_enforced_by_database(
        self,
        ticket_access_grant_factory: TicketAccessGrantFactory,
        ticket_factory: TicketFactory,
    ) -> None:
        """Grant preconditions are service-enforced (tickets.md, Access
        Grant Management); the schema documents no such constraint."""
        ticket = await ticket_factory(is_confidential=False)
        grant = await ticket_access_grant_factory(ticket_id=ticket.id)
        assert grant.ticket_id == ticket.id


@pytest.mark.unit
class TestTicketAccessGrantMetadata:
    def test_composite_primary_key(self) -> None:
        pk_names = [c.name for c in TicketAccessGrant.__table__.primary_key]
        assert pk_names == ["ticket_id", "user_id"]

    def test_no_generic_timestamp_columns(self) -> None:
        """`granted_at` replaces `created_at`; there is no `updated_at`
        (docs/data-model.md, Notes)."""
        columns = set(TicketAccessGrant.__table__.columns.keys())
        assert columns == {"ticket_id", "user_id", "granted_by_id", "granted_at"}

    def test_primary_key_columns_generate_no_identifier(self) -> None:
        for name in ("ticket_id", "user_id"):
            column = TicketAccessGrant.__table__.c[name]
            assert column.default is None
            assert column.server_default is None

    @pytest.mark.parametrize(
        ("column", "target"),
        [
            ("ticket_id", "ticket.id"),
            ("user_id", "user.id"),
            ("granted_by_id", "user.id"),
        ],
    )
    def test_every_foreign_key_uses_ondelete_restrict(
        self, column: str, target: str
    ) -> None:
        (fk,) = TicketAccessGrant.__table__.c[column].foreign_keys
        assert fk.target_fullname == target
        assert fk.ondelete == "RESTRICT"

    @pytest.mark.parametrize("name", ["user", "granted_by"])
    def test_user_relationships_are_view_only(self, name: str) -> None:
        relationship = inspect(TicketAccessGrant).relationships[name]
        assert relationship.viewonly is True
        assert relationship.back_populates is None

    def test_user_has_no_reverse_grant_collection(self) -> None:
        assert not any(
            rel.mapper.class_ is TicketAccessGrant
            for rel in inspect(User).relationships
        )


@pytest.mark.integration
class TestTicketAccessGrantPrimaryKey:
    async def test_duplicate_grant_rejected(
        self,
        db_session: AsyncSession,
        ticket_access_grant_factory: TicketAccessGrantFactory,
        user_factory: UserFactory,
    ) -> None:
        grant = await ticket_access_grant_factory()
        other_granter = await user_factory()
        # Expunge so the identity map does not intercept the duplicate key
        # before the database primary key rejects it.
        db_session.expunge(grant)
        db_session.add(
            TicketAccessGrant(
                ticket_id=grant.ticket_id,
                user_id=grant.user_id,
                granted_by_id=other_granter.id,
            )
        )
        with pytest.raises(IntegrityError, match="ticket_access_grant_pkey"):
            await db_session.flush()

    async def test_same_user_on_different_tickets_accepted(
        self,
        ticket_access_grant_factory: TicketAccessGrantFactory,
        user_factory: UserFactory,
    ) -> None:
        user = await user_factory()
        first = await ticket_access_grant_factory(user_id=user.id)
        second = await ticket_access_grant_factory(user_id=user.id)
        assert first.ticket_id != second.ticket_id

    async def test_different_users_on_same_ticket_accepted(
        self,
        db_session: AsyncSession,
        ticket_access_grant_factory: TicketAccessGrantFactory,
        ticket_factory: TicketFactory,
    ) -> None:
        ticket = await ticket_factory(is_confidential=True)
        await ticket_access_grant_factory(ticket_id=ticket.id)
        await ticket_access_grant_factory(ticket_id=ticket.id)

        result = await db_session.execute(
            select(TicketAccessGrant).where(TicketAccessGrant.ticket_id == ticket.id)
        )
        assert len(result.scalars().all()) == 2


@pytest.mark.integration
class TestTicketAccessGrantNotNullConstraints:
    @pytest.mark.parametrize(
        "column", ["ticket_id", "user_id", "granted_by_id", "granted_at"]
    )
    async def test_explicit_null_rejected(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        user_factory: UserFactory,
        column: str,
    ) -> None:
        """A Core INSERT with an explicit NULL bypasses the ORM, which
        refuses a NULL primary key and omits a `None` server-defaulted
        column."""
        ticket = await ticket_factory(is_confidential=True)
        user = await user_factory()
        granter = await user_factory()
        values: dict[str, object] = {
            "ticket_id": ticket.id,
            "user_id": user.id,
            "granted_by_id": granter.id,
            column: None,
        }
        with pytest.raises(IntegrityError, match="not-null"):
            await db_session.execute(insert(TicketAccessGrant).values(values))


@pytest.mark.integration
class TestTicketAccessGrantForeignKeys:
    @pytest.mark.parametrize(
        ("column", "constraint"),
        [
            ("ticket_id", "ticket_access_grant_ticket_id_fkey"),
            ("user_id", "ticket_access_grant_user_id_fkey"),
            ("granted_by_id", "ticket_access_grant_granted_by_id_fkey"),
        ],
    )
    async def test_nonexistent_reference_rejected(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        user_factory: UserFactory,
        column: str,
        constraint: str,
    ) -> None:
        ticket = await ticket_factory(is_confidential=True)
        user = await user_factory()
        granter = await user_factory()
        values: dict[str, uuid.UUID] = {
            "ticket_id": ticket.id,
            "user_id": user.id,
            "granted_by_id": granter.id,
            column: uuid.uuid7(),
        }
        db_session.add(TicketAccessGrant(**values))
        with pytest.raises(IntegrityError, match=constraint):
            await db_session.flush()


@pytest.mark.integration
class TestTicketAccessGrantRestrictOnDelete:
    """Tickets are never deleted and users are deactivated, not deleted
    (docs/data-model.md, TicketAccessGrant note), so every referenced-row
    delete fails on its RESTRICT FK. `Ticket.access_grants` uses
    `passive_deletes="all"`, so the ORM never tries to blank the grant's
    primary key first; the Ticket test loads the collection before
    deleting, which is when the ORM would otherwise do so."""

    async def test_deleting_ticket_with_grant_raises(
        self,
        db_session: AsyncSession,
        ticket_access_grant_factory: TicketAccessGrantFactory,
    ) -> None:
        grant = await ticket_access_grant_factory()
        ticket = await db_session.get(Ticket, grant.ticket_id)
        assert ticket is not None
        await db_session.refresh(ticket, ["access_grants"])

        await db_session.delete(ticket)
        with pytest.raises(IntegrityError, match="ticket_access_grant_ticket_id_fkey"):
            await db_session.flush()

    async def test_deleting_target_user_raises(
        self,
        db_session: AsyncSession,
        ticket_access_grant_factory: TicketAccessGrantFactory,
        user_factory: UserFactory,
    ) -> None:
        user = await user_factory()
        await ticket_access_grant_factory(user_id=user.id)

        await db_session.delete(user)
        with pytest.raises(IntegrityError, match="ticket_access_grant_user_id_fkey"):
            await db_session.flush()

    async def test_deleting_granting_user_raises(
        self,
        db_session: AsyncSession,
        ticket_access_grant_factory: TicketAccessGrantFactory,
        user_factory: UserFactory,
    ) -> None:
        granter = await user_factory()
        await ticket_access_grant_factory(granted_by_id=granter.id)

        await db_session.delete(granter)
        with pytest.raises(
            IntegrityError, match="ticket_access_grant_granted_by_id_fkey"
        ):
            await db_session.flush()

    async def test_deleting_grant_row_accepted(
        self,
        db_session: AsyncSession,
        ticket_access_grant_factory: TicketAccessGrantFactory,
    ) -> None:
        """Declassification hard-deletes grant rows (tickets.md,
        Confidential Tickets); the schema permits it."""
        grant = await ticket_access_grant_factory()
        key = (grant.ticket_id, grant.user_id)

        await db_session.delete(grant)
        await db_session.flush()

        assert await db_session.get(TicketAccessGrant, key) is None


@pytest.mark.integration
class TestTicketAccessGrantRelationships:
    async def test_ticket_access_grants_round_trip(
        self,
        db_session: AsyncSession,
        ticket_access_grant_factory: TicketAccessGrantFactory,
        ticket_factory: TicketFactory,
    ) -> None:
        ticket = await ticket_factory(is_confidential=True)
        first = await ticket_access_grant_factory(ticket_id=ticket.id)
        second = await ticket_access_grant_factory(ticket_id=ticket.id)
        await ticket_access_grant_factory()

        await db_session.refresh(first, ["ticket"])
        await db_session.refresh(ticket, ["access_grants"])

        assert first.ticket is ticket
        assert {g.user_id for g in ticket.access_grants} == {
            first.user_id,
            second.user_id,
        }

    async def test_user_relationships_resolve_distinct_users(
        self,
        db_session: AsyncSession,
        ticket_access_grant_factory: TicketAccessGrantFactory,
        user_factory: UserFactory,
    ) -> None:
        user = await user_factory()
        granter = await user_factory()
        grant = await ticket_access_grant_factory(
            user_id=user.id, granted_by_id=granter.id
        )

        await db_session.refresh(grant, ["user", "granted_by"])

        assert grant.user is user
        assert grant.granted_by is granter
