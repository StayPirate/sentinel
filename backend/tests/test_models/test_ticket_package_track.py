"""Integration tests for the TicketPackageTrack model
(backend/app/models/ticket_package_track.py).

See docs/data-model.md (TicketPackageTrack, PackageStatus Enum,
DeliveryStatus Enum, WorkflowType Enum) and
docs/features/packages/package-model.md (Data Model, Three Orthogonal
Dimensions, Exclusion and Actionability). Only the persistence contract is
covered here; affectedness and delivery transitions, exclusion and
restoration, and actionability are `package_service` behavior.
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import CheckConstraint, UniqueConstraint, delete, insert, text
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import DeliveryStatus, PackageStatus, WorkflowType
from app.models.ticket_package import TicketPackage
from app.models.ticket_package_track import TicketPackageTrack

TicketPackageFactory = Callable[..., Awaitable[TicketPackage]]
TicketPackageTrackFactory = Callable[..., Awaitable[TicketPackageTrack]]

_DOCUMENTED_COLUMNS = {
    "id",
    "ticket_package_id",
    "workflow_type",
    "reference",
    "status",
    "delivery_status",
    "deleted_at",
    "created_at",
    "updated_at",
}

# Documented VARCHAR lengths (docs/data-model.md, TicketPackageTrack).
# `status` and `delivery_status` are bounded more tightly by their CHECKs.
_COLUMN_LENGTHS = {
    "workflow_type": 20,
    "reference": 255,
}

_STATUS_CHECK = "chk_ticket_package_track_status_valid"
_DELIVERY_STATUS_CHECK = "chk_ticket_package_track_delivery_status_valid"


@pytest.mark.integration
class TestTicketPackageTrackCreation:
    async def test_create_with_defaults(
        self, ticket_package_track_factory: TicketPackageTrackFactory
    ) -> None:
        track = await ticket_package_track_factory()

        assert track.id.version == 7
        assert track.ticket_package_id is not None
        assert track.workflow_type == "ibs"
        assert track.reference.startswith("Example:Codestream:")
        assert track.status == PackageStatus.ANALYSIS.value
        assert track.delivery_status == DeliveryStatus.PENDING.value
        assert track.deleted_at is None
        assert track.created_at is not None
        assert track.updated_at is not None

    async def test_create_with_every_column(
        self,
        db_session: AsyncSession,
        ticket_package_factory: TicketPackageFactory,
        ticket_package_track_factory: TicketPackageTrackFactory,
    ) -> None:
        package = await ticket_package_factory()
        excluded_at = datetime(2026, 9, 1, 1, 0, tzinfo=UTC)
        track = await ticket_package_track_factory(
            ticket_package_id=package.id,
            workflow_type=WorkflowType.GIT.value,
            reference="example-main",
            status=PackageStatus.AFFECTED.value,
            delivery_status=DeliveryStatus.IN_PROGRESS.value,
            deleted_at=excluded_at,
        )
        track_id = track.id
        db_session.expunge(track)

        reloaded = await db_session.get(TicketPackageTrack, track_id)
        assert reloaded is not None
        assert reloaded.ticket_package_id == package.id
        assert reloaded.workflow_type == "git"
        assert reloaded.reference == "example-main"
        assert reloaded.status == "AFFECTED"
        assert reloaded.delivery_status == "IN_PROGRESS"
        assert reloaded.deleted_at == excluded_at

    async def test_raw_insert_applies_server_defaults(
        self, db_session: AsyncSession, ticket_package_factory: TicketPackageFactory
    ) -> None:
        """A raw SQL INSERT bypasses every Python-side default, so the
        database must supply `id`, `status` (`ANALYSIS`), `delivery_status`
        (`PENDING`), and the timestamps."""
        package = await ticket_package_factory()
        result = await db_session.execute(
            text(
                "INSERT INTO ticket_package_track "
                "(ticket_package_id, workflow_type, reference) "
                "VALUES (:package_id, 'ibs', 'Example:Raw:Update') "
                "RETURNING id, status, delivery_status, deleted_at, "
                "created_at, updated_at"
            ),
            {"package_id": package.id},
        )
        row = result.one()
        assert isinstance(row.id, uuid.UUID)
        assert row.id.version == 7
        assert row.status == "ANALYSIS"
        assert row.delivery_status == "PENDING"
        assert row.deleted_at is None
        assert row.created_at.tzinfo is not None
        assert row.updated_at == row.created_at


@pytest.mark.unit
class TestTicketPackageTrackSchemaShape:
    """Exactly the documented columns and constraints (#633 decision A2):
    no persisted actionability or lifecycle column, only the two
    enum-validation CHECKs (none on Category B `workflow_type`), and no
    standalone index."""

    def test_columns_match_documented_set(self) -> None:
        assert set(TicketPackageTrack.__table__.columns.keys()) == _DOCUMENTED_COLUMNS

    def test_unique_constraint(self) -> None:
        table = TicketPackageTrack.metadata.tables["ticket_package_track"]
        uniques = {
            (constraint.name, tuple(column.name for column in constraint.columns))
            for constraint in table.constraints
            if isinstance(constraint, UniqueConstraint)
        }
        assert uniques == {
            (
                "uq_ticket_package_track_ticket_package_id_reference",
                ("ticket_package_id", "reference"),
            )
        }

    def test_exact_check_constraint_set(self) -> None:
        table = TicketPackageTrack.metadata.tables["ticket_package_track"]
        checks = {c.name for c in table.constraints if isinstance(c, CheckConstraint)}
        assert checks == {_STATUS_CHECK, _DELIVERY_STATUS_CHECK}

    def test_no_standalone_index(self) -> None:
        """The `(ticket_package_id, reference)` UNIQUE constraint covers the
        `ticket_package_id` access path."""
        table = TicketPackageTrack.metadata.tables["ticket_package_track"]
        assert table.indexes == set()

    @pytest.mark.parametrize(
        ("column", "expected"),
        [("status", "ANALYSIS"), ("delivery_status", "PENDING")],
    )
    def test_python_and_server_defaults(self, column: str, expected: str) -> None:
        table_column = TicketPackageTrack.__table__.c[column]
        assert table_column.default is not None
        assert table_column.default.arg == expected
        assert table_column.server_default is not None
        assert table_column.server_default.arg == expected


@pytest.mark.integration
class TestTicketPackageTrackColumnLengths:
    @pytest.mark.parametrize(("column", "length"), list(_COLUMN_LENGTHS.items()))
    async def test_documented_maximum_accepted(
        self,
        ticket_package_track_factory: TicketPackageTrackFactory,
        column: str,
        length: int,
    ) -> None:
        track = await ticket_package_track_factory(**{column: "a" * length})
        assert len(getattr(track, column)) == length

    @pytest.mark.parametrize(("column", "length"), list(_COLUMN_LENGTHS.items()))
    async def test_value_over_documented_maximum_rejected(
        self,
        ticket_package_track_factory: TicketPackageTrackFactory,
        column: str,
        length: int,
    ) -> None:
        # asyncpg surfaces the truncation as a generic DBAPIError.
        with pytest.raises(DBAPIError, match="value too long"):
            await ticket_package_track_factory(**{column: "a" * (length + 1)})


@pytest.mark.integration
class TestTicketPackageTrackUniqueness:
    async def test_same_reference_on_same_package_rejected(
        self,
        db_session: AsyncSession,
        ticket_package_factory: TicketPackageFactory,
        ticket_package_track_factory: TicketPackageTrackFactory,
    ) -> None:
        package = await ticket_package_factory()
        await ticket_package_track_factory(
            ticket_package_id=package.id, reference="Example:Dup:Update"
        )
        db_session.add(
            TicketPackageTrack(
                ticket_package_id=package.id,
                workflow_type="ibs",
                reference="Example:Dup:Update",
            )
        )
        with pytest.raises(
            IntegrityError, match="uq_ticket_package_track_ticket_package_id_reference"
        ):
            await db_session.flush()

    async def test_same_reference_with_other_workflow_type_rejected(
        self,
        db_session: AsyncSession,
        ticket_package_factory: TicketPackageFactory,
        ticket_package_track_factory: TicketPackageTrackFactory,
    ) -> None:
        """The track identity is `reference` alone within the package;
        `workflow_type` is not part of the key."""
        package = await ticket_package_factory()
        await ticket_package_track_factory(
            ticket_package_id=package.id, workflow_type="ibs", reference="example-x"
        )
        db_session.add(
            TicketPackageTrack(
                ticket_package_id=package.id, workflow_type="git", reference="example-x"
            )
        )
        with pytest.raises(
            IntegrityError, match="uq_ticket_package_track_ticket_package_id_reference"
        ):
            await db_session.flush()

    async def test_same_reference_on_different_packages_accepted(
        self, ticket_package_track_factory: TicketPackageTrackFactory
    ) -> None:
        first = await ticket_package_track_factory(reference="Example:Shared:Update")
        second = await ticket_package_track_factory(reference="Example:Shared:Update")
        assert first.ticket_package_id != second.ticket_package_id

    async def test_different_references_on_same_package_accepted(
        self,
        ticket_package_factory: TicketPackageFactory,
        ticket_package_track_factory: TicketPackageTrackFactory,
    ) -> None:
        package = await ticket_package_factory()
        await ticket_package_track_factory(
            ticket_package_id=package.id, reference="Example:A:Update"
        )
        await ticket_package_track_factory(
            ticket_package_id=package.id, reference="Example:B:Update"
        )


@pytest.mark.integration
class TestTicketPackageTrackNotNullConstraints:
    @pytest.mark.parametrize(
        "column",
        [
            "ticket_package_id",
            "workflow_type",
            "reference",
            "status",
            "delivery_status",
            "created_at",
            "updated_at",
        ],
    )
    async def test_explicit_null_rejected(
        self,
        db_session: AsyncSession,
        ticket_package_factory: TicketPackageFactory,
        column: str,
    ) -> None:
        """A Core INSERT with an explicit NULL bypasses the ORM, which
        would otherwise omit a `None` server-defaulted column."""
        package = await ticket_package_factory()
        values: dict[str, object] = {
            "ticket_package_id": package.id,
            "workflow_type": "ibs",
            "reference": "Example:Null:Update",
            column: None,
        }
        with pytest.raises(IntegrityError, match="not-null"):
            await db_session.execute(insert(TicketPackageTrack).values(values))

    async def test_deleted_at_accepts_null(
        self,
        db_session: AsyncSession,
        ticket_package_track_factory: TicketPackageTrackFactory,
    ) -> None:
        track = await ticket_package_track_factory(deleted_at=datetime.now(UTC))
        track.deleted_at = None
        await db_session.flush()
        await db_session.refresh(track)
        assert track.deleted_at is None


@pytest.mark.integration
class TestTicketPackageTrackStatusCheckConstraint:
    """`status` is Category A, protected by
    `chk_ticket_package_track_status_valid` (docs/data-model.md,
    PackageStatus Enum)."""

    @pytest.mark.parametrize("status", list(PackageStatus), ids=lambda s: s.name)
    async def test_every_member_accepted(
        self,
        db_session: AsyncSession,
        ticket_package_track_factory: TicketPackageTrackFactory,
        status: PackageStatus,
    ) -> None:
        track = await ticket_package_track_factory(status=status.value)
        await db_session.refresh(track)
        assert track.status == status.value

    @pytest.mark.parametrize(
        "value", ["analysis", "Analysis", "RESOLVED", "PENDING", ""]
    )
    async def test_invalid_value_rejected_on_insert(
        self,
        ticket_package_track_factory: TicketPackageTrackFactory,
        value: str,
    ) -> None:
        with pytest.raises(IntegrityError, match=_STATUS_CHECK):
            await ticket_package_track_factory(status=value)

    async def test_invalid_value_rejected_on_update(
        self,
        db_session: AsyncSession,
        ticket_package_track_factory: TicketPackageTrackFactory,
    ) -> None:
        track = await ticket_package_track_factory()
        with pytest.raises(IntegrityError, match=_STATUS_CHECK):
            await db_session.execute(
                text(
                    "UPDATE ticket_package_track SET status = 'CLOSED' WHERE id = :id"
                ),
                {"id": track.id},
            )


@pytest.mark.integration
class TestTicketPackageTrackDeliveryStatusCheckConstraint:
    """`delivery_status` is Category A, protected by
    `chk_ticket_package_track_delivery_status_valid` (docs/data-model.md,
    DeliveryStatus Enum)."""

    @pytest.mark.parametrize("status", list(DeliveryStatus), ids=lambda s: s.name)
    async def test_every_member_accepted(
        self,
        db_session: AsyncSession,
        ticket_package_track_factory: TicketPackageTrackFactory,
        status: DeliveryStatus,
    ) -> None:
        track = await ticket_package_track_factory(delivery_status=status.value)
        await db_session.refresh(track)
        assert track.delivery_status == status.value

    @pytest.mark.parametrize(
        "value", ["pending", "Pending", "DELIVERED", "ANALYSIS", ""]
    )
    async def test_invalid_value_rejected_on_insert(
        self,
        ticket_package_track_factory: TicketPackageTrackFactory,
        value: str,
    ) -> None:
        with pytest.raises(IntegrityError, match=_DELIVERY_STATUS_CHECK):
            await ticket_package_track_factory(delivery_status=value)

    async def test_invalid_value_rejected_on_update(
        self,
        db_session: AsyncSession,
        ticket_package_track_factory: TicketPackageTrackFactory,
    ) -> None:
        track = await ticket_package_track_factory()
        with pytest.raises(IntegrityError, match=_DELIVERY_STATUS_CHECK):
            await db_session.execute(
                text(
                    "UPDATE ticket_package_track SET delivery_status = 'SHIPPED' "
                    "WHERE id = :id"
                ),
                {"id": track.id},
            )


@pytest.mark.integration
class TestTicketPackageTrackWorkflowType:
    """`workflow_type` is Category B: no CHECK constraint; the writing
    service validates against `WorkflowType` (docs/data-model.md,
    WorkflowType Enum)."""

    @pytest.mark.parametrize("workflow_type", list(WorkflowType), ids=lambda w: w.name)
    async def test_every_member_accepted(
        self,
        ticket_package_track_factory: TicketPackageTrackFactory,
        workflow_type: WorkflowType,
    ) -> None:
        track = await ticket_package_track_factory(workflow_type=workflow_type.value)
        assert track.workflow_type == workflow_type.value

    async def test_arbitrary_value_accepted_at_model_layer(
        self,
        db_session: AsyncSession,
        ticket_package_track_factory: TicketPackageTrackFactory,
    ) -> None:
        track = await ticket_package_track_factory(workflow_type="uncategorized")
        await db_session.refresh(track)
        assert track.workflow_type == "uncategorized"


@pytest.mark.integration
class TestTicketPackageTrackForeignKey:
    async def test_nonexistent_package_rejected(self, db_session: AsyncSession) -> None:
        db_session.add(
            TicketPackageTrack(
                ticket_package_id=uuid.uuid7(),
                workflow_type="ibs",
                reference="Example:Orphan:Update",
            )
        )
        with pytest.raises(
            IntegrityError, match="ticket_package_track_ticket_package_id_fkey"
        ):
            await db_session.flush()

    def test_foreign_key_uses_default_no_action(self) -> None:
        """No ON DELETE action is documented: the PostgreSQL default
        NO ACTION applies (#633 decision A3)."""
        (fk,) = TicketPackageTrack.__table__.c.ticket_package_id.foreign_keys
        assert fk.target_fullname == "ticket_package.id"
        assert fk.ondelete is None


@pytest.mark.integration
class TestTicketPackageDeleteRejectedWhileTracksExist:
    """The package tree is soft-deleted, never hard-deleted. The FK uses the
    PostgreSQL default NO ACTION (#633 decision A3) and
    `TicketPackage.tracks` uses `passive_deletes="all"`, so deleting a
    package with tracks fails on the FK instead of the ORM nulling the
    track's `ticket_package_id` first."""

    async def test_orm_delete_with_loaded_tracks_raises(
        self,
        db_session: AsyncSession,
        ticket_package_factory: TicketPackageFactory,
        ticket_package_track_factory: TicketPackageTrackFactory,
    ) -> None:
        package = await ticket_package_factory()
        await ticket_package_track_factory(ticket_package_id=package.id)
        await db_session.refresh(package, ["tracks"])
        assert len(package.tracks) == 1

        await db_session.delete(package)
        with pytest.raises(
            IntegrityError, match="ticket_package_track_ticket_package_id_fkey"
        ):
            await db_session.flush()

    async def test_database_delete_raises(
        self,
        db_session: AsyncSession,
        ticket_package_factory: TicketPackageFactory,
        ticket_package_track_factory: TicketPackageTrackFactory,
    ) -> None:
        package = await ticket_package_factory()
        await ticket_package_track_factory(ticket_package_id=package.id)
        package_id = package.id
        db_session.expunge_all()

        with pytest.raises(
            IntegrityError, match="ticket_package_track_ticket_package_id_fkey"
        ):
            await db_session.execute(
                delete(TicketPackage).where(TicketPackage.id == package_id)
            )


@pytest.mark.integration
class TestTicketPackageTrackRelationships:
    async def test_package_tracks_round_trip(
        self,
        db_session: AsyncSession,
        ticket_package_factory: TicketPackageFactory,
        ticket_package_track_factory: TicketPackageTrackFactory,
    ) -> None:
        package = await ticket_package_factory()
        first = await ticket_package_track_factory(ticket_package_id=package.id)
        second = await ticket_package_track_factory(ticket_package_id=package.id)
        await ticket_package_track_factory()

        await db_session.refresh(first, ["ticket_package"])
        await db_session.refresh(package, ["tracks"])

        assert first.ticket_package is package
        assert {t.id for t in package.tracks} == {first.id, second.id}


@pytest.mark.integration
class TestTicketPackageTrackTimestamps:
    async def test_timestamps_are_timezone_aware(
        self,
        db_session: AsyncSession,
        ticket_package_track_factory: TicketPackageTrackFactory,
    ) -> None:
        track = await ticket_package_track_factory(deleted_at=datetime.now(UTC))
        await db_session.refresh(track)
        assert track.created_at.tzinfo is not None
        assert track.updated_at.tzinfo is not None
        assert track.deleted_at is not None
        assert track.deleted_at.tzinfo is not None

    async def test_updated_at_advances_on_update(
        self,
        db_session: AsyncSession,
        ticket_package_track_factory: TicketPackageTrackFactory,
    ) -> None:
        """Backdating pattern (docs/features/platform/testing-strategy.md,
        `server_default=func.now()` and `onupdate=func.now()` Testing)."""
        track = await ticket_package_track_factory()
        backdated = datetime.now(UTC) - timedelta(days=7)
        track.updated_at = backdated
        await db_session.flush()
        await db_session.refresh(track)
        assert track.updated_at == backdated

        track.status = PackageStatus.AFFECTED.value
        await db_session.flush()
        await db_session.refresh(track)

        assert track.updated_at > backdated

    async def test_created_at_unchanged_on_update(
        self,
        db_session: AsyncSession,
        ticket_package_track_factory: TicketPackageTrackFactory,
    ) -> None:
        track = await ticket_package_track_factory()
        backdated = datetime.now(UTC) - timedelta(days=7)
        track.created_at = backdated
        await db_session.flush()

        track.delivery_status = DeliveryStatus.IN_PROGRESS.value
        await db_session.flush()
        await db_session.refresh(track)

        assert track.created_at == backdated
