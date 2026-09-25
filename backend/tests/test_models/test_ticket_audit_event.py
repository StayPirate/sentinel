"""Integration tests for the TicketAuditEvent model
(backend/app/models/ticket_audit_event.py).

See docs/data-model.md (TicketAuditEvent, TicketAuditEventType Enum),
docs/features/platform/audit-trail-infrastructure.md (AuditEventMixin,
Indexing, Immutability), and docs/features/tickets/ticket-audit-log.md
(Event Type Contract). Only the persistence contract is covered here; the
typed `TicketAuditLog.log_event()` validation of `event_type`, `comment`,
and `detail` is service behavior.
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable

import pytest
from sqlalchemy import insert, inspect, select, text
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import TicketAuditEventType
from app.models.mixins import AuditEventMixin
from app.models.ticket import Ticket
from app.models.ticket_audit_event import TicketAuditEvent
from app.models.user import User

TicketFactory = Callable[..., Awaitable[Ticket]]
UserFactory = Callable[..., Awaitable[User]]
TicketAuditEventFactory = Callable[..., Awaitable[TicketAuditEvent]]


@pytest.mark.integration
class TestTicketAuditEventCreation:
    async def test_create_with_defaults(
        self, ticket_audit_event_factory: TicketAuditEventFactory
    ) -> None:
        event = await ticket_audit_event_factory()

        assert event.id.version == 7
        assert event.ticket_id is not None
        assert event.event_type == "ticket_created"
        assert event.user_id is None
        assert event.old_value is None
        assert event.new_value is None
        assert event.comment is None
        assert event.detail is None
        assert event.created_at is not None
        assert event.created_at.tzinfo is not None

    async def test_create_with_every_column(
        self,
        db_session: AsyncSession,
        ticket_audit_event_factory: TicketAuditEventFactory,
        ticket_factory: TicketFactory,
        user_factory: UserFactory,
    ) -> None:
        ticket = await ticket_factory()
        actor = await user_factory()
        detail = {"triggered_by_ticket": "SNTL-7"}

        event = await ticket_audit_event_factory(
            ticket_id=ticket.id,
            user_id=actor.id,
            event_type=TicketAuditEventType.DUPLICATE_TARGET_CHANGED.value,
            old_value="SNTL-5",
            new_value="SNTL-6",
            comment="Fictional system-generated description",
            detail=detail,
        )
        event_id = event.id
        db_session.expunge(event)

        reloaded = await db_session.get(TicketAuditEvent, event_id)
        assert reloaded is not None
        assert reloaded.ticket_id == ticket.id
        assert reloaded.user_id == actor.id
        assert reloaded.event_type == "duplicate_target_changed"
        assert reloaded.old_value == "SNTL-5"
        assert reloaded.new_value == "SNTL-6"
        assert reloaded.comment == "Fictional system-generated description"
        assert reloaded.detail == detail

    async def test_detail_nested_jsonb_round_trip(
        self,
        db_session: AsyncSession,
        ticket_audit_event_factory: TicketAuditEventFactory,
    ) -> None:
        detail = {
            "product": {"name": "Fictional Linux 1", "cpe": "cpe:/o:example:linux:1"},
            "track": "fictional-track",
            "package": "fictional-package",
            "reason": "threshold",
        }
        event = await ticket_audit_event_factory(detail=detail)
        event_id = event.id
        db_session.expunge(event)

        reloaded = await db_session.get(TicketAuditEvent, event_id)
        assert reloaded is not None
        assert reloaded.detail == detail

    async def test_raw_insert_applies_server_defaults(
        self, db_session: AsyncSession, ticket_factory: TicketFactory
    ) -> None:
        """A raw SQL INSERT bypasses every Python-side default (a Core
        `insert()` would still apply `uuid.uuid7`), so the `uuidv7()` and
        `now()` server defaults must supply both columns."""
        ticket = await ticket_factory()
        result = await db_session.execute(
            text(
                "INSERT INTO ticket_audit_event (ticket_id, event_type) "
                "VALUES (:ticket_id, 'ticket_created') RETURNING id, created_at"
            ),
            {"ticket_id": ticket.id},
        )
        row = result.one()
        assert isinstance(row.id, uuid.UUID)
        assert row.id.version == 7
        assert row.created_at.tzinfo is not None

    @pytest.mark.parametrize("event_type", list(TicketAuditEventType))
    async def test_every_event_type_accepted(
        self,
        ticket_audit_event_factory: TicketAuditEventFactory,
        event_type: TicketAuditEventType,
    ) -> None:
        event = await ticket_audit_event_factory(event_type=event_type.value)
        assert event.event_type == event_type.value

    async def test_arbitrary_event_type_accepted_at_model_layer(
        self, ticket_audit_event_factory: TicketAuditEventFactory
    ) -> None:
        """Category B: no CHECK constraint; `TicketAuditLog` validates."""
        event = await ticket_audit_event_factory(event_type="not_a_ticket_event")
        assert event.event_type == "not_a_ticket_event"

    async def test_event_type_over_column_length_rejected(
        self, ticket_audit_event_factory: TicketAuditEventFactory
    ) -> None:
        """`event_type` is VARCHAR(50) (docs/data-model.md)."""
        await ticket_audit_event_factory(event_type="a" * 50)
        # asyncpg surfaces the truncation as a generic DBAPIError.
        with pytest.raises(DBAPIError, match="value too long"):
            await ticket_audit_event_factory(event_type="a" * 51)

    async def test_multiple_events_per_ticket_accepted(
        self,
        db_session: AsyncSession,
        ticket_audit_event_factory: TicketAuditEventFactory,
        ticket_factory: TicketFactory,
    ) -> None:
        ticket = await ticket_factory()
        for _ in range(3):
            await ticket_audit_event_factory(
                ticket_id=ticket.id, event_type="status_change"
            )

        result = await db_session.execute(
            select(TicketAuditEvent).where(TicketAuditEvent.ticket_id == ticket.id)
        )
        assert len(result.scalars().all()) == 3


@pytest.mark.unit
class TestTicketAuditEventMetadata:
    """Structural assertions over SQLAlchemy metadata."""

    def test_no_updated_at_column(self) -> None:
        """Append-only (docs/data-model.md, Notes)."""
        assert "updated_at" not in TicketAuditEvent.__table__.columns

    def test_inherits_audit_event_mixin(self) -> None:
        assert issubclass(TicketAuditEvent, AuditEventMixin)

    def test_registered_in_audit_event_mixin_subclasses(self) -> None:
        """Registration is what puts the model under the audit
        immutability structural test."""
        assert TicketAuditEvent in AuditEventMixin.__subclasses__()

    def test_table_name_follows_audit_naming(self) -> None:
        assert TicketAuditEvent.__tablename__ == "ticket_audit_event"

    def test_user_id_foreign_key_uses_ondelete_restrict(self) -> None:
        (fk,) = TicketAuditEvent.__table__.c.user_id.foreign_keys
        assert fk.ondelete == "RESTRICT"

    def test_ticket_id_foreign_key_has_no_ondelete_action(self) -> None:
        """docs/data-model.md specifies no ON DELETE action (#611 decision
        A4: the PostgreSQL default NO ACTION applies)."""
        (fk,) = TicketAuditEvent.__table__.c.ticket_id.foreign_keys
        assert fk.target_fullname == "ticket.id"
        assert fk.ondelete is None

    def test_actor_is_view_only_and_user_has_no_reverse_collection(self) -> None:
        relationship = inspect(TicketAuditEvent).relationships["actor"]
        assert relationship.viewonly is True
        assert relationship.back_populates is None
        assert not any(
            rel.mapper.class_ is TicketAuditEvent for rel in inspect(User).relationships
        )


@pytest.mark.integration
class TestTicketAuditEventNotNullConstraints:
    @pytest.mark.parametrize("column", ["event_type", "created_at"])
    async def test_explicit_null_rejected(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        column: str,
    ) -> None:
        """A Core INSERT with an explicit NULL bypasses the ORM, which
        would otherwise omit a `None` server-defaulted column."""
        ticket = await ticket_factory()
        values: dict[str, object] = {
            "ticket_id": ticket.id,
            "event_type": "ticket_created",
            column: None,
        }
        with pytest.raises(IntegrityError, match="not-null"):
            await db_session.execute(insert(TicketAuditEvent).values(values))

    async def test_missing_ticket_id_rejected(self, db_session: AsyncSession) -> None:
        db_session.add(TicketAuditEvent(event_type="ticket_created"))
        with pytest.raises(IntegrityError, match="not-null"):
            await db_session.flush()


@pytest.mark.integration
class TestTicketAuditEventForeignKeys:
    async def test_nonexistent_ticket_rejected(self, db_session: AsyncSession) -> None:
        db_session.add(
            TicketAuditEvent(ticket_id=uuid.uuid7(), event_type="ticket_created")
        )
        with pytest.raises(IntegrityError, match="ticket_audit_event_ticket_id_fkey"):
            await db_session.flush()

    async def test_nonexistent_actor_rejected(
        self, db_session: AsyncSession, ticket_factory: TicketFactory
    ) -> None:
        ticket = await ticket_factory()
        db_session.add(
            TicketAuditEvent(
                ticket_id=ticket.id,
                user_id=uuid.uuid7(),
                event_type="ticket_created",
            )
        )
        with pytest.raises(IntegrityError, match="ticket_audit_event_user_id_fkey"):
            await db_session.flush()


@pytest.mark.integration
class TestTicketAuditEventNoDeletionPropagation:
    """Audit history survives: deleting the Ticket or the actor fails on
    the audit FK. `Ticket.audit_events` uses `passive_deletes="all"`, so
    the ORM never nulls `ticket_id` first; each test loads the collection
    before deleting, which is when the ORM would otherwise emit that
    UPDATE."""

    async def test_deleting_ticket_with_events_raises(
        self,
        db_session: AsyncSession,
        ticket_audit_event_factory: TicketAuditEventFactory,
        ticket_factory: TicketFactory,
    ) -> None:
        ticket = await ticket_factory()
        await ticket_audit_event_factory(ticket_id=ticket.id)
        await db_session.refresh(ticket, ["audit_events"])

        await db_session.delete(ticket)
        with pytest.raises(IntegrityError, match="ticket_audit_event_ticket_id_fkey"):
            await db_session.flush()

    async def test_deleting_actor_raises(
        self,
        db_session: AsyncSession,
        ticket_audit_event_factory: TicketAuditEventFactory,
        user_factory: UserFactory,
    ) -> None:
        actor = await user_factory()
        await ticket_audit_event_factory(user_id=actor.id)

        await db_session.delete(actor)
        with pytest.raises(IntegrityError, match="ticket_audit_event_user_id_fkey"):
            await db_session.flush()


@pytest.mark.integration
class TestTicketAuditEventRelationships:
    async def test_ticket_audit_events_round_trip(
        self,
        db_session: AsyncSession,
        ticket_audit_event_factory: TicketAuditEventFactory,
        ticket_factory: TicketFactory,
    ) -> None:
        ticket = await ticket_factory()
        first = await ticket_audit_event_factory(ticket_id=ticket.id)
        second = await ticket_audit_event_factory(
            ticket_id=ticket.id, event_type="status_change"
        )
        await ticket_audit_event_factory()

        await db_session.refresh(first, ["ticket"])
        await db_session.refresh(ticket, ["audit_events"])

        assert first.ticket is ticket
        assert {e.id for e in ticket.audit_events} == {first.id, second.id}

    async def test_actor_relationship(
        self,
        db_session: AsyncSession,
        ticket_audit_event_factory: TicketAuditEventFactory,
        user_factory: UserFactory,
    ) -> None:
        actor = await user_factory()
        event = await ticket_audit_event_factory(user_id=actor.id)
        await db_session.refresh(event, ["actor"])
        assert event.actor is actor

    async def test_actor_none_for_system_event(
        self,
        db_session: AsyncSession,
        ticket_audit_event_factory: TicketAuditEventFactory,
    ) -> None:
        event = await ticket_audit_event_factory()
        await db_session.refresh(event, ["actor"])
        assert event.actor is None


@pytest.mark.integration
class TestTicketAuditEventIndexes:
    """docs/data-model.md (TicketAuditEvent, Indexes) and
    audit-trail-infrastructure.md (Indexing): the `ticket_id` scope index
    plus the inherited `created_at` and `user_id` indexes, and nothing
    else (#611 decision A3)."""

    async def test_exact_index_set(self, db_session: AsyncSession) -> None:
        conn = await db_session.connection()
        indexes = await conn.run_sync(
            lambda sync_conn: inspect(sync_conn).get_indexes("ticket_audit_event")
        )
        assert {(idx["name"], tuple(idx["column_names"])) for idx in indexes} == {
            ("ix_ticket_audit_event_ticket_id", ("ticket_id",)),
            ("ix_ticket_audit_event_created_at", ("created_at",)),
            ("ix_ticket_audit_event_user_id", ("user_id",)),
        }
        assert all(not idx["unique"] for idx in indexes)
