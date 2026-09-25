"""Integration tests for the TicketReference model
(backend/app/models/ticket_reference.py).

See docs/data-model.md (TicketReference, ReferenceType Enum) and
docs/features/tickets/ticket-references.md (Data Model). Only the
persistence contract is covered here; URL validation and normalization,
type classification, source rules, and upsert are service behavior.
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import delete, func, insert, select, text
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import ReferenceType
from app.models.ticket import Ticket
from app.models.ticket_reference import TicketReference

TicketFactory = Callable[..., Awaitable[Ticket]]
TicketReferenceFactory = Callable[..., Awaitable[TicketReference]]

# Documented VARCHAR lengths (docs/data-model.md, TicketReference).
_COLUMN_LENGTHS = {
    "url": 2048,
    "title": 500,
    "description": 2000,
    "type": 20,
    "source": 100,
}


async def _count_references(session: AsyncSession, ticket_id: uuid.UUID) -> int:
    result = await session.execute(
        select(func.count())
        .select_from(TicketReference)
        .where(TicketReference.ticket_id == ticket_id)
    )
    return result.scalar_one()


@pytest.mark.integration
class TestTicketReferenceCreation:
    async def test_create_with_defaults(
        self, ticket_reference_factory: TicketReferenceFactory
    ) -> None:
        reference = await ticket_reference_factory()

        assert reference.id.version == 7
        assert reference.ticket_id is not None
        assert reference.url.startswith("https://advisories.example.com/ref-")
        assert reference.source == "manual"
        assert reference.title is None
        assert reference.description is None
        assert reference.type is None
        assert reference.created_at is not None
        assert reference.updated_at is not None

    async def test_create_with_every_column(
        self,
        db_session: AsyncSession,
        ticket_reference_factory: TicketReferenceFactory,
        ticket_factory: TicketFactory,
    ) -> None:
        ticket = await ticket_factory()
        reference = await ticket_reference_factory(
            ticket_id=ticket.id,
            url="https://git.example.com/fictional/project/commit/abc123",
            title="Fictional fix commit",
            description="Fixes the fictional overflow",
            type=ReferenceType.PATCH.value,
            source="sync_nvd_cves",
        )
        reference_id = reference.id
        db_session.expunge(reference)

        reloaded = await db_session.get(TicketReference, reference_id)
        assert reloaded is not None
        assert reloaded.ticket_id == ticket.id
        assert reloaded.url == "https://git.example.com/fictional/project/commit/abc123"
        assert reloaded.title == "Fictional fix commit"
        assert reloaded.description == "Fixes the fictional overflow"
        assert reloaded.type == "patch"
        assert reloaded.source == "sync_nvd_cves"

    async def test_raw_insert_applies_server_defaults(
        self, db_session: AsyncSession, ticket_factory: TicketFactory
    ) -> None:
        """A raw SQL INSERT bypasses every Python-side default (a Core
        `insert()` would still apply `uuid.uuid7`), so the `uuidv7()` and
        `now()` server defaults must supply the columns."""
        ticket = await ticket_factory()
        result = await db_session.execute(
            text(
                "INSERT INTO ticket_reference (ticket_id, url, source) "
                "VALUES (:ticket_id, 'https://advisories.example.com/raw', "
                "'manual') RETURNING id, created_at, updated_at"
            ),
            {"ticket_id": ticket.id},
        )
        row = result.one()
        assert isinstance(row.id, uuid.UUID)
        assert row.id.version == 7
        assert row.created_at.tzinfo is not None
        assert row.updated_at == row.created_at

    @pytest.mark.parametrize("reference_type", list(ReferenceType))
    async def test_every_reference_type_accepted(
        self,
        ticket_reference_factory: TicketReferenceFactory,
        reference_type: ReferenceType,
    ) -> None:
        reference = await ticket_reference_factory(type=reference_type.value)
        assert reference.type == reference_type.value

    async def test_arbitrary_type_accepted_at_model_layer(
        self, ticket_reference_factory: TicketReferenceFactory
    ) -> None:
        """Category B: no CHECK constraint; the reference services
        validate against `ReferenceType`."""
        reference = await ticket_reference_factory(type="uncategorized")
        assert reference.type == "uncategorized"


@pytest.mark.integration
class TestTicketReferenceColumnLengths:
    @pytest.mark.parametrize(("column", "length"), list(_COLUMN_LENGTHS.items()))
    async def test_documented_maximum_accepted(
        self,
        ticket_reference_factory: TicketReferenceFactory,
        column: str,
        length: int,
    ) -> None:
        reference = await ticket_reference_factory(**{column: "a" * length})
        assert len(getattr(reference, column)) == length

    @pytest.mark.parametrize(("column", "length"), list(_COLUMN_LENGTHS.items()))
    async def test_value_over_documented_maximum_rejected(
        self,
        ticket_reference_factory: TicketReferenceFactory,
        column: str,
        length: int,
    ) -> None:
        # asyncpg surfaces the truncation as a generic DBAPIError.
        with pytest.raises(DBAPIError, match="value too long"):
            await ticket_reference_factory(**{column: "a" * (length + 1)})


@pytest.mark.integration
class TestTicketReferenceUniqueness:
    async def test_same_url_on_same_ticket_rejected(
        self,
        db_session: AsyncSession,
        ticket_reference_factory: TicketReferenceFactory,
        ticket_factory: TicketFactory,
    ) -> None:
        ticket = await ticket_factory()
        url = "https://advisories.example.com/dup"
        await ticket_reference_factory(ticket_id=ticket.id, url=url)
        db_session.add(
            TicketReference(ticket_id=ticket.id, url=url, source="sync_osv_cves")
        )
        with pytest.raises(IntegrityError, match="uq_ticket_reference_ticket_id_url"):
            await db_session.flush()

    async def test_same_url_on_different_tickets_accepted(
        self, ticket_reference_factory: TicketReferenceFactory
    ) -> None:
        url = "https://advisories.example.com/shared"
        first = await ticket_reference_factory(url=url)
        second = await ticket_reference_factory(url=url)
        assert first.ticket_id != second.ticket_id

    async def test_database_compares_stored_url_exactly(
        self,
        ticket_reference_factory: TicketReferenceFactory,
        ticket_factory: TicketFactory,
    ) -> None:
        """Normalization is a service contract: the UNIQUE constraint
        compares the stored value, so un-normalized variants are distinct
        rows at the model layer."""
        ticket = await ticket_factory()
        await ticket_reference_factory(
            ticket_id=ticket.id, url="https://advisories.example.com/x"
        )
        await ticket_reference_factory(
            ticket_id=ticket.id, url="https://ADVISORIES.example.com/x"
        )


@pytest.mark.integration
class TestTicketReferenceNotNullConstraints:
    @pytest.mark.parametrize(
        "column", ["ticket_id", "url", "source", "created_at", "updated_at"]
    )
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
            "url": "https://advisories.example.com/null",
            "source": "manual",
            column: None,
        }
        with pytest.raises(IntegrityError, match="not-null"):
            await db_session.execute(insert(TicketReference).values(values))

    @pytest.mark.parametrize("column", ["title", "description", "type"])
    async def test_optional_columns_accept_null(
        self,
        db_session: AsyncSession,
        ticket_reference_factory: TicketReferenceFactory,
        column: str,
    ) -> None:
        reference = await ticket_reference_factory(**{column: "x"})
        setattr(reference, column, None)
        await db_session.flush()
        await db_session.refresh(reference)
        assert getattr(reference, column) is None


@pytest.mark.integration
class TestTicketReferenceForeignKey:
    async def test_nonexistent_ticket_rejected(self, db_session: AsyncSession) -> None:
        db_session.add(
            TicketReference(
                ticket_id=uuid.uuid7(),
                url="https://advisories.example.com/orphan",
                source="manual",
            )
        )
        with pytest.raises(IntegrityError, match="ticket_reference_ticket_id_fkey"):
            await db_session.flush()

    def test_foreign_key_uses_ondelete_cascade(self) -> None:
        (fk,) = TicketReference.__table__.c.ticket_id.foreign_keys
        assert fk.target_fullname == "ticket.id"
        assert fk.ondelete == "CASCADE"


@pytest.mark.integration
class TestTicketReferenceCascadeOnTicketDelete:
    """`FK(ticket.id) ON DELETE CASCADE`: references are owned children.
    Tickets are never deleted in practice, but the documented schema
    behavior is verified both through the database and through the ORM."""

    async def test_database_delete_cascades(
        self,
        db_session: AsyncSession,
        ticket_reference_factory: TicketReferenceFactory,
        ticket_factory: TicketFactory,
    ) -> None:
        ticket = await ticket_factory()
        other = await ticket_reference_factory()
        await ticket_reference_factory(ticket_id=ticket.id)
        await ticket_reference_factory(ticket_id=ticket.id)
        ticket_id = ticket.id
        db_session.expunge_all()

        await db_session.execute(delete(Ticket).where(Ticket.id == ticket_id))

        assert await _count_references(db_session, ticket_id) == 0
        assert await _count_references(db_session, other.ticket_id) == 1

    async def test_orm_delete_with_loaded_references_cascades(
        self,
        db_session: AsyncSession,
        ticket_reference_factory: TicketReferenceFactory,
        ticket_factory: TicketFactory,
    ) -> None:
        ticket = await ticket_factory()
        await ticket_reference_factory(ticket_id=ticket.id)
        await ticket_reference_factory(ticket_id=ticket.id)
        ticket_id = ticket.id
        await db_session.refresh(ticket, ["references"])
        assert len(ticket.references) == 2

        await db_session.delete(ticket)
        await db_session.flush()

        assert await _count_references(db_session, ticket_id) == 0

    async def test_orm_delete_with_unloaded_references_cascades(
        self,
        db_session: AsyncSession,
        ticket_reference_factory: TicketReferenceFactory,
        ticket_factory: TicketFactory,
    ) -> None:
        ticket = await ticket_factory()
        await ticket_reference_factory(ticket_id=ticket.id)
        ticket_id = ticket.id
        db_session.expunge_all()
        reloaded = await db_session.get(Ticket, ticket_id)
        assert reloaded is not None

        await db_session.delete(reloaded)
        await db_session.flush()

        assert await _count_references(db_session, ticket_id) == 0


@pytest.mark.integration
class TestTicketReferenceRelationships:
    async def test_ticket_references_round_trip(
        self,
        db_session: AsyncSession,
        ticket_reference_factory: TicketReferenceFactory,
        ticket_factory: TicketFactory,
    ) -> None:
        ticket = await ticket_factory()
        first = await ticket_reference_factory(ticket_id=ticket.id)
        second = await ticket_reference_factory(ticket_id=ticket.id)
        await ticket_reference_factory()

        await db_session.refresh(first, ["ticket"])
        await db_session.refresh(ticket, ["references"])

        assert first.ticket is ticket
        assert {r.id for r in ticket.references} == {first.id, second.id}


@pytest.mark.integration
class TestTicketReferenceTimestamps:
    async def test_timestamps_are_timezone_aware(
        self,
        db_session: AsyncSession,
        ticket_reference_factory: TicketReferenceFactory,
    ) -> None:
        reference = await ticket_reference_factory()
        await db_session.refresh(reference)
        assert reference.created_at.tzinfo is not None
        assert reference.updated_at.tzinfo is not None

    async def test_updated_at_advances_on_update(
        self,
        db_session: AsyncSession,
        ticket_reference_factory: TicketReferenceFactory,
    ) -> None:
        """Backdating pattern (docs/features/platform/testing-strategy.md,
        `server_default=func.now()` and `onupdate=func.now()` Testing):
        `now()` is fixed for the test transaction, so the column is
        backdated explicitly before the mutation."""
        reference = await ticket_reference_factory()
        backdated = datetime.now(UTC) - timedelta(days=7)
        reference.updated_at = backdated
        await db_session.flush()
        await db_session.refresh(reference)
        assert reference.updated_at == backdated

        reference.title = "Fictional updated title"
        await db_session.flush()
        await db_session.refresh(reference)

        assert reference.updated_at > backdated

    async def test_created_at_unchanged_on_update(
        self,
        db_session: AsyncSession,
        ticket_reference_factory: TicketReferenceFactory,
    ) -> None:
        reference = await ticket_reference_factory()
        backdated = datetime.now(UTC) - timedelta(days=7)
        reference.created_at = backdated
        await db_session.flush()

        reference.type = ReferenceType.ADVISORY.value
        await db_session.flush()
        await db_session.refresh(reference)

        assert reference.created_at == backdated
