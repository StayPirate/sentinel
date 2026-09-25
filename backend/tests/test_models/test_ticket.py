"""Integration tests for the Ticket model (backend/app/models/ticket.py).

See docs/data-model.md (Ticket, TicketStatus Enum, TicketPriority Enum),
docs/features/tickets/tickets.md (SNTL-{n} Format, Confidential Tickets,
Coordinated Release Date), docs/features/tickets/ticket-priority.md
(Persistence and Effective Priority), and
docs/features/tickets/cvss-scoring.md (Unified CVE Severity) for the full
specification. Only the persistence contract is covered here; lifecycle,
duplicate locking, priority refresh, and CRD rules are service behavior.
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import Severity, TicketPriority, TicketStatus
from app.models.cve import CVE
from app.models.ticket import Ticket
from app.models.user import User

TicketFactory = Callable[..., Awaitable[Ticket]]
CVEFactory = Callable[..., Awaitable[CVE]]
UserFactory = Callable[..., Awaitable[User]]

_NON_DUPLICATED_STATUSES = [s for s in TicketStatus if s != TicketStatus.DUPLICATED]


@pytest.mark.integration
class TestTicketCreation:
    async def test_create_with_defaults(self, ticket_factory: TicketFactory) -> None:
        ticket = await ticket_factory()

        assert ticket.id.version == 7
        assert isinstance(ticket.sequence_id, int)
        assert ticket.sequence_id >= 1
        assert ticket.status == TicketStatus.NEW
        assert ticket.is_confidential is False
        assert ticket.cve_id is None
        assert ticket.severity_manual is None
        assert ticket.priority_auto is None
        assert ticket.priority_override is None
        assert ticket.assignee_id is None
        assert ticket.duplicate_of_id is None
        assert ticket.coordinated_release_at is None
        assert ticket.created_at is not None
        assert ticket.updated_at is not None

    async def test_create_with_every_column(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_factory: CVEFactory,
        user_factory: UserFactory,
    ) -> None:
        cve = await cve_factory()
        assignee = await user_factory()
        crd = datetime(2099, 6, 1, 12, 0, tzinfo=UTC)
        ticket = await ticket_factory(
            cve_id=cve.id,
            status=TicketStatus.ANALYZED.value,
            priority_auto=TicketPriority.P2.value,
            priority_override=TicketPriority.P1.value,
            assignee_id=assignee.id,
            is_confidential=True,
            coordinated_release_at=crd,
        )
        await db_session.refresh(ticket)

        assert ticket.cve_id == cve.id
        assert ticket.status == "Analyzed"
        assert ticket.priority_auto == "P2"
        assert ticket.priority_override == "P1"
        assert ticket.assignee_id == assignee.id
        assert ticket.is_confidential is True
        assert ticket.coordinated_release_at == crd

    async def test_raw_insert_applies_server_defaults(
        self, db_session: AsyncSession
    ) -> None:
        """An INSERT that bypasses the ORM still gets a UUIDv7 `id`, an
        identity `sequence_id`, `status = 'New'`, `is_confidential =
        false`, and both timestamps from the PostgreSQL-side defaults
        (docs/data-model.md, Ticket)."""
        result = await db_session.execute(
            text(
                "INSERT INTO ticket DEFAULT VALUES RETURNING id, sequence_id, "
                "status, is_confidential, created_at, updated_at"
            )
        )
        row = result.one()

        assert isinstance(row.id, uuid.UUID)
        assert row.id.version == 7
        assert isinstance(row.sequence_id, int)
        assert row.sequence_id >= 1
        assert row.status == "New"
        assert row.is_confidential is False
        assert row.created_at is not None
        assert row.updated_at is not None


@pytest.mark.integration
class TestTicketSequenceId:
    """`sequence_id` is a database-assigned, unique auto-increment integer
    exposed as `SNTL-{n}` (docs/features/tickets/tickets.md, SNTL-{n}
    Format)."""

    async def test_assigned_by_database_and_increasing(
        self, ticket_factory: TicketFactory
    ) -> None:
        first = await ticket_factory()
        second = await ticket_factory()
        third = await ticket_factory()

        assert first.sequence_id < second.sequence_id < third.sequence_id

    async def test_duplicate_sequence_id_rejected(
        self, db_session: AsyncSession, ticket_factory: TicketFactory
    ) -> None:
        existing = await ticket_factory()
        db_session.add(Ticket(sequence_id=existing.sequence_id))
        with pytest.raises(IntegrityError, match="ticket_sequence_id_key"):
            await db_session.flush()


@pytest.mark.integration
class TestTicketNotNullConstraints:
    @pytest.mark.parametrize(
        "column",
        [
            "sequence_id",
            "status",
            "is_confidential",
            "created_at",
            "updated_at",
        ],
    )
    async def test_explicit_null_rejected(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        column: str,
    ) -> None:
        """A raw UPDATE bypasses the ORM and server defaults, proving the
        database itself rejects NULL for each NOT NULL column."""
        ticket = await ticket_factory()
        with pytest.raises(IntegrityError, match="not-null"):
            await db_session.execute(
                text(f"UPDATE ticket SET {column} = NULL WHERE id = :id"),
                {"id": ticket.id},
            )


@pytest.mark.integration
class TestTicketCveAssociation:
    """`cve_id` is an optional, UNIQUE FK to `cve.id` (0..1:0..1)."""

    async def test_second_ticket_for_same_cve_rejected(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_factory: CVEFactory,
    ) -> None:
        cve = await cve_factory()
        await ticket_factory(cve_id=cve.id)
        db_session.add(Ticket(cve_id=cve.id))
        with pytest.raises(IntegrityError, match="ticket_cve_id_key"):
            await db_session.flush()

    async def test_multiple_tickets_without_cve_accepted(
        self, db_session: AsyncSession, ticket_factory: TicketFactory
    ) -> None:
        first = await ticket_factory()
        second = await ticket_factory()

        result = await db_session.execute(
            text("SELECT count(*) FROM ticket WHERE cve_id IS NULL AND id IN (:a, :b)"),
            {"a": first.id, "b": second.id},
        )
        assert result.scalar_one() == 2


@pytest.mark.integration
class TestTicketForeignKeys:
    @pytest.mark.parametrize(
        ("column", "constraint"),
        [
            ("cve_id", "ticket_cve_id_fkey"),
            ("assignee_id", "ticket_assignee_id_fkey"),
            ("duplicate_of_id", "ticket_duplicate_of_id_fkey"),
        ],
    )
    async def test_nonexistent_reference_rejected(
        self, db_session: AsyncSession, column: str, constraint: str
    ) -> None:
        overrides: dict[str, object] = {column: uuid.uuid7()}
        if column == "duplicate_of_id":
            overrides["status"] = TicketStatus.DUPLICATED.value
        db_session.add(Ticket(**overrides))
        with pytest.raises(IntegrityError, match=constraint):
            await db_session.flush()


@pytest.mark.integration
class TestTicketNoDeletionPropagation:
    """Tickets are never deleted and never silently detached
    (docs/data-model.md, Ticket, Deletion policy). The referenced-side
    relationships use `passive_deletes="all"`, so deleting a referenced
    row fails on the Ticket FK (default NO ACTION) instead of the ORM
    nulling the Ticket column first. Each test loads the collection before
    deleting, which is when the ORM would otherwise emit that UPDATE."""

    async def test_deleting_associated_cve_raises(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_factory: CVEFactory,
    ) -> None:
        cve = await cve_factory()
        await ticket_factory(cve_id=cve.id)
        await db_session.refresh(cve, ["ticket"])

        await db_session.delete(cve)
        with pytest.raises(IntegrityError, match="ticket_cve_id_fkey"):
            await db_session.flush()

    async def test_deleting_assignee_raises(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        user_factory: UserFactory,
    ) -> None:
        assignee = await user_factory()
        await ticket_factory(assignee_id=assignee.id)
        await db_session.refresh(assignee, ["assigned_tickets"])

        await db_session.delete(assignee)
        with pytest.raises(IntegrityError, match="ticket_assignee_id_fkey"):
            await db_session.flush()

    async def test_deleting_duplicate_target_raises(
        self, db_session: AsyncSession, ticket_factory: TicketFactory
    ) -> None:
        target = await ticket_factory()
        await ticket_factory(duplicate_of_id=target.id)
        await db_session.refresh(target, ["duplicates"])

        await db_session.delete(target)
        with pytest.raises(IntegrityError, match="ticket_duplicate_of_id_fkey"):
            await db_session.flush()


@pytest.mark.integration
class TestTicketStatusCheckConstraint:
    """`status` is Category A, protected by `chk_ticket_status_valid`
    (docs/data-model.md, TicketStatus Enum)."""

    @pytest.mark.parametrize("status", list(TicketStatus), ids=lambda s: s.name)
    async def test_every_member_accepted(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        status: TicketStatus,
    ) -> None:
        ticket = await ticket_factory(status=status.value)
        await db_session.refresh(ticket)
        assert ticket.status == status.value

    @pytest.mark.parametrize("value", ["Open", "new", "NEW", ""])
    async def test_invalid_value_rejected_on_insert(
        self, db_session: AsyncSession, value: str
    ) -> None:
        db_session.add(Ticket(status=value))
        with pytest.raises(IntegrityError, match="chk_ticket_status_valid"):
            await db_session.flush()

    async def test_invalid_value_rejected_on_update(
        self, db_session: AsyncSession, ticket_factory: TicketFactory
    ) -> None:
        ticket = await ticket_factory()
        with pytest.raises(IntegrityError, match="chk_ticket_status_valid"):
            await db_session.execute(
                text("UPDATE ticket SET status = 'Closed' WHERE id = :id"),
                {"id": ticket.id},
            )


@pytest.mark.integration
class TestTicketDuplicateConstraints:
    """`chk_ticket_duplicate_status_coherence` and
    `chk_ticket_no_self_duplicate` (docs/data-model.md, Ticket)."""

    async def test_duplicated_with_target_accepted(
        self, db_session: AsyncSession, ticket_factory: TicketFactory
    ) -> None:
        target = await ticket_factory()
        duplicate = await ticket_factory(
            status=TicketStatus.DUPLICATED.value, duplicate_of_id=target.id
        )
        await db_session.refresh(duplicate)

        assert duplicate.status == "Duplicated"
        assert duplicate.duplicate_of_id == target.id

    async def test_duplicated_without_target_rejected(
        self, db_session: AsyncSession
    ) -> None:
        db_session.add(Ticket(status=TicketStatus.DUPLICATED.value))
        with pytest.raises(
            IntegrityError, match="chk_ticket_duplicate_status_coherence"
        ):
            await db_session.flush()

    @pytest.mark.parametrize("status", _NON_DUPLICATED_STATUSES, ids=lambda s: s.name)
    async def test_non_duplicated_with_target_rejected(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        status: TicketStatus,
    ) -> None:
        target = await ticket_factory()
        db_session.add(Ticket(status=status.value, duplicate_of_id=target.id))
        with pytest.raises(
            IntegrityError, match="chk_ticket_duplicate_status_coherence"
        ):
            await db_session.flush()

    async def test_leaving_duplicated_without_clearing_target_rejected(
        self, db_session: AsyncSession, ticket_factory: TicketFactory
    ) -> None:
        duplicate = await ticket_factory(status=TicketStatus.DUPLICATED.value)
        with pytest.raises(
            IntegrityError, match="chk_ticket_duplicate_status_coherence"
        ):
            await db_session.execute(
                text("UPDATE ticket SET status = 'Analysis' WHERE id = :id"),
                {"id": duplicate.id},
            )

    async def test_self_duplicate_rejected(
        self, db_session: AsyncSession, ticket_factory: TicketFactory
    ) -> None:
        ticket = await ticket_factory()
        with pytest.raises(IntegrityError, match="chk_ticket_no_self_duplicate"):
            await db_session.execute(
                text(
                    "UPDATE ticket SET status = 'Duplicated', duplicate_of_id = id "
                    "WHERE id = :id"
                ),
                {"id": ticket.id},
            )

    async def test_target_status_not_enforced_by_database(
        self, db_session: AsyncSession, ticket_factory: TicketFactory
    ) -> None:
        """ "Always references a non-Duplicated ticket" is enforced by the
        `mark_as_duplicate` locking protocol, not by a database constraint
        (docs/data-model.md, Ticket; #611 decision A3)."""
        duplicated_target = await ticket_factory(status=TicketStatus.DUPLICATED.value)
        chained = await ticket_factory(duplicate_of_id=duplicated_target.id)
        await db_session.refresh(chained)

        assert chained.duplicate_of_id == duplicated_target.id


@pytest.mark.integration
class TestTicketSeverityManual:
    """`severity_manual` is a Category B column mutually exclusive with
    `cve_id` (`chk_ticket_severity_manual_cve_exclusive`)."""

    @pytest.mark.parametrize("label", list(Severity), ids=lambda s: s.name)
    async def test_every_label_accepted_without_cve(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        label: Severity,
    ) -> None:
        ticket = await ticket_factory(severity_manual=label.value)
        await db_session.refresh(ticket)
        assert ticket.severity_manual == label.value

    async def test_arbitrary_value_accepted_at_model_layer(
        self, db_session: AsyncSession, ticket_factory: TicketFactory
    ) -> None:
        ticket = await ticket_factory(severity_manual="Moderate")
        await db_session.refresh(ticket)
        assert ticket.severity_manual == "Moderate"

    async def test_none_label_is_distinct_from_null(
        self, db_session: AsyncSession, ticket_factory: TicketFactory
    ) -> None:
        resolved = await ticket_factory(severity_manual=Severity.NONE.value)
        unresolved = await ticket_factory()

        result = await db_session.execute(
            text(
                "SELECT id FROM ticket WHERE severity_manual IS NULL AND id IN (:a, :b)"
            ),
            {"a": resolved.id, "b": unresolved.id},
        )
        assert result.scalars().all() == [unresolved.id]

    async def test_severity_manual_with_cve_rejected_on_insert(
        self, db_session: AsyncSession, cve_factory: CVEFactory
    ) -> None:
        cve = await cve_factory()
        db_session.add(Ticket(cve_id=cve.id, severity_manual=Severity.HIGH.value))
        with pytest.raises(
            IntegrityError, match="chk_ticket_severity_manual_cve_exclusive"
        ):
            await db_session.flush()

    async def test_associating_cve_while_severity_manual_set_rejected(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_factory: CVEFactory,
    ) -> None:
        cve = await cve_factory()
        ticket = await ticket_factory(severity_manual=Severity.LOW.value)
        with pytest.raises(
            IntegrityError, match="chk_ticket_severity_manual_cve_exclusive"
        ):
            await db_session.execute(
                text("UPDATE ticket SET cve_id = :cve_id WHERE id = :id"),
                {"cve_id": cve.id, "id": ticket.id},
            )


@pytest.mark.integration
class TestTicketPriorityColumns:
    """`priority_auto` and `priority_override` are independent Category B
    `TicketPriority` columns; `NULL` is not a level (docs/data-model.md,
    TicketPriority Enum)."""

    @pytest.mark.parametrize("level", list(TicketPriority), ids=lambda p: p.name)
    async def test_every_level_accepted_in_both_columns(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        level: TicketPriority,
    ) -> None:
        ticket = await ticket_factory(
            priority_auto=level.value, priority_override=level.value
        )
        await db_session.refresh(ticket)
        assert ticket.priority_auto == level.value
        assert ticket.priority_override == level.value

    async def test_override_without_auto_accepted(
        self, db_session: AsyncSession, ticket_factory: TicketFactory
    ) -> None:
        ticket = await ticket_factory(priority_override=TicketPriority.P4.value)
        await db_session.refresh(ticket)
        assert ticket.priority_auto is None
        assert ticket.priority_override == "P4"

    async def test_arbitrary_value_accepted_at_model_layer(
        self, db_session: AsyncSession, ticket_factory: TicketFactory
    ) -> None:
        ticket = await ticket_factory(priority_auto="P9", priority_override="p1")
        await db_session.refresh(ticket)
        assert ticket.priority_auto == "P9"
        assert ticket.priority_override == "p1"


@pytest.mark.integration
class TestTicketConfidentiality:
    async def test_crd_on_non_confidential_ticket_not_enforced_by_database(
        self, db_session: AsyncSession, ticket_factory: TicketFactory
    ) -> None:
        """The CRD is writable only while confidential, but that rule is
        service-enforced and the value is retained after declassification
        (docs/data-model.md, Ticket), so the database accepts it."""
        crd = datetime(2099, 1, 1, tzinfo=UTC)
        ticket = await ticket_factory(is_confidential=False, coordinated_release_at=crd)
        await db_session.refresh(ticket)
        assert ticket.coordinated_release_at == crd


@pytest.mark.integration
class TestTicketIndexes:
    """docs/data-model.md (Ticket, Indexes): exactly the partial
    `duplicate_of_id` index and the non-partial `assignee_id` index, beyond
    the primary key and unique keys (#611 decision A3)."""

    async def test_exact_standalone_index_set(self, db_session: AsyncSession) -> None:
        result = await db_session.execute(
            text(
                "SELECT i.relname AS name, ix.indisunique AS is_unique "
                "FROM pg_index ix "
                "JOIN pg_class i ON i.oid = ix.indexrelid "
                "JOIN pg_class t ON t.oid = ix.indrelid "
                "LEFT JOIN pg_constraint c ON c.conindid = ix.indexrelid "
                "WHERE t.relname = 'ticket' AND c.oid IS NULL"
            )
        )
        rows = result.all()
        assert {row.name for row in rows} == {
            "ix_ticket_duplicate_of_id",
            "ix_ticket_assignee_id",
        }
        assert all(not row.is_unique for row in rows)

    async def test_assignee_index_is_non_partial_btree(
        self, db_session: AsyncSession
    ) -> None:
        result = await db_session.execute(
            text(
                "SELECT indexdef FROM pg_indexes "
                "WHERE tablename = 'ticket' AND indexname = 'ix_ticket_assignee_id'"
            )
        )
        (row,) = result.all()
        assert "USING btree (assignee_id)" in row.indexdef
        assert "UNIQUE" not in row.indexdef
        assert "WHERE" not in row.indexdef

    async def test_partial_duplicate_of_index_present(
        self, db_session: AsyncSession
    ) -> None:
        result = await db_session.execute(
            text(
                "SELECT indexname, indexdef FROM pg_indexes "
                "WHERE tablename = 'ticket' AND indexname = 'ix_ticket_duplicate_of_id'"
            )
        )
        (row,) = result.all()
        assert "(duplicate_of_id)" in row.indexdef
        assert "WHERE (duplicate_of_id IS NOT NULL)" in row.indexdef


@pytest.mark.integration
class TestTicketRelationships:
    async def test_cve_ticket_one_to_one_round_trip(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_factory: CVEFactory,
    ) -> None:
        cve = await cve_factory()
        ticket = await ticket_factory(cve_id=cve.id)

        await db_session.refresh(ticket, ["cve"])
        await db_session.refresh(cve, ["ticket"])

        assert ticket.cve is cve
        assert cve.ticket is ticket

    async def test_cve_without_ticket_has_none(
        self, db_session: AsyncSession, cve_factory: CVEFactory
    ) -> None:
        cve = await cve_factory()
        await db_session.refresh(cve, ["ticket"])
        assert cve.ticket is None

    async def test_associating_through_relationship_sets_cve_id(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_factory: CVEFactory,
    ) -> None:
        cve = await cve_factory()
        ticket = await ticket_factory()
        await db_session.refresh(ticket, ["cve"])

        ticket.cve = cve
        await db_session.flush()
        await db_session.refresh(ticket)

        assert ticket.cve_id == cve.id

    async def test_assignee_relationship_both_directions(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        user_factory: UserFactory,
    ) -> None:
        assignee = await user_factory()
        first = await ticket_factory(assignee_id=assignee.id)
        second = await ticket_factory(assignee_id=assignee.id)
        await ticket_factory()

        await db_session.refresh(first, ["assignee"])
        await db_session.refresh(assignee, ["assigned_tickets"])

        assert first.assignee is assignee
        assert {t.id for t in assignee.assigned_tickets} == {first.id, second.id}

    async def test_duplicate_relationship_both_directions(
        self, db_session: AsyncSession, ticket_factory: TicketFactory
    ) -> None:
        target = await ticket_factory()
        first = await ticket_factory(duplicate_of_id=target.id)
        second = await ticket_factory(duplicate_of_id=target.id)

        await db_session.refresh(first, ["duplicate_of"])
        await db_session.refresh(target, ["duplicates", "duplicate_of"])

        assert first.duplicate_of is target
        assert target.duplicate_of is None
        assert {t.id for t in target.duplicates} == {first.id, second.id}


@pytest.mark.integration
class TestTicketTimestamps:
    async def test_timestamps_are_timezone_aware(
        self, db_session: AsyncSession, ticket_factory: TicketFactory
    ) -> None:
        ticket = await ticket_factory(
            is_confidential=True,
            coordinated_release_at=datetime(2099, 1, 1, tzinfo=UTC),
        )
        await db_session.refresh(ticket)

        for value in (
            ticket.created_at,
            ticket.updated_at,
            ticket.coordinated_release_at,
        ):
            assert value is not None
            assert value.tzinfo is not None

    async def test_updated_at_advances_on_update(
        self, db_session: AsyncSession, ticket_factory: TicketFactory
    ) -> None:
        """Backdating pattern (docs/features/platform/testing-strategy.md,
        `server_default=func.now()` and `onupdate=func.now()` Testing):
        `now()` is fixed for the test transaction, so the column is
        backdated explicitly before the mutation."""
        ticket = await ticket_factory()
        backdated = datetime.now(UTC) - timedelta(days=7)
        ticket.updated_at = backdated
        await db_session.flush()
        await db_session.refresh(ticket)
        assert ticket.updated_at == backdated

        ticket.status = TicketStatus.ANALYSIS.value
        await db_session.flush()
        await db_session.refresh(ticket)

        assert ticket.updated_at > backdated

    async def test_created_at_unchanged_on_update(
        self, db_session: AsyncSession, ticket_factory: TicketFactory
    ) -> None:
        ticket = await ticket_factory()
        backdated = datetime.now(UTC) - timedelta(days=7)
        ticket.created_at = backdated
        await db_session.flush()

        ticket.is_confidential = True
        await db_session.flush()
        await db_session.refresh(ticket)

        assert ticket.created_at == backdated


@pytest.mark.integration
class TestTicketFactory:
    async def test_duplicate_of_override_defaults_status_to_duplicated(
        self, ticket_factory: TicketFactory
    ) -> None:
        target = await ticket_factory()
        duplicate = await ticket_factory(duplicate_of_id=target.id)
        assert duplicate.status == TicketStatus.DUPLICATED

    async def test_duplicated_status_override_creates_target(
        self, db_session: AsyncSession, ticket_factory: TicketFactory
    ) -> None:
        duplicate = await ticket_factory(status=TicketStatus.DUPLICATED.value)
        assert duplicate.duplicate_of_id is not None
        target = await db_session.get(Ticket, duplicate.duplicate_of_id)
        assert target is not None
        assert target.status == TicketStatus.NEW
