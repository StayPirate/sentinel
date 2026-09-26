"""Integration tests for the TrackReleaseCheckpoint model
(backend/app/models/track_release_checkpoint.py).

See docs/data-model.md (TrackReleaseCheckpoint, TicketPackageTrack, Notes:
timestamp exceptions) and docs/features/packages/ibs-track-release-detection.md
(Track Release Checkpoint). Only the persisted state is covered here;
predecessor validation, conditional advancement, first observation, and the
unavailable-history fallback are IBS track release detection behavior.
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import (
    CheckConstraint,
    UniqueConstraint,
    delete,
    func,
    insert,
    inspect,
    select,
    text,
)
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import RelationshipProperty

from app.models.ticket_package_track import TicketPackageTrack
from app.models.track_release_checkpoint import TrackReleaseCheckpoint

TicketPackageTrackFactory = Callable[..., Awaitable[TicketPackageTrack]]
TrackReleaseCheckpointFactory = Callable[..., Awaitable[TrackReleaseCheckpoint]]

# `last_seen_at` instead of `created_at`/`updated_at` (docs/data-model.md,
# Notes: timestamp exceptions).
_DOCUMENTED_COLUMNS = {"id", "ticket_package_track_id", "srcmd5", "last_seen_at"}

_UNIQUE = "track_release_checkpoint_ticket_package_track_id_key"
_TRACK_FK = "track_release_checkpoint_ticket_package_track_id_fkey"

_SRCMD5 = "0123456789abcdef0123456789abcdef"
_NEXT_SRCMD5 = "fedcba9876543210fedcba9876543210"


async def _backdate_track(
    db_session: AsyncSession, track: TicketPackageTrack
) -> datetime:
    """Backdating pattern (docs/features/platform/testing-strategy.md,
    `server_default=func.now()` and `onupdate=func.now()` Testing): a
    track row update would replace this value with the transaction time."""
    backdated = datetime.now(UTC) - timedelta(days=7)
    track.updated_at = backdated
    await db_session.flush()
    await db_session.refresh(track)
    assert track.updated_at == backdated
    return backdated


@pytest.mark.integration
class TestTrackReleaseCheckpointCreation:
    async def test_create_with_defaults(
        self, track_release_checkpoint_factory: TrackReleaseCheckpointFactory
    ) -> None:
        checkpoint = await track_release_checkpoint_factory()

        assert checkpoint.id.version == 7
        assert checkpoint.ticket_package_track_id is not None
        assert len(checkpoint.srcmd5) == 32
        assert checkpoint.last_seen_at is not None

    async def test_create_with_explicit_values(
        self,
        db_session: AsyncSession,
        ticket_package_track_factory: TicketPackageTrackFactory,
        track_release_checkpoint_factory: TrackReleaseCheckpointFactory,
    ) -> None:
        track = await ticket_package_track_factory()
        seen_at = datetime(2026, 9, 3, 10, 15, tzinfo=UTC)
        checkpoint = await track_release_checkpoint_factory(
            ticket_package_track_id=track.id, srcmd5=_SRCMD5, last_seen_at=seen_at
        )
        checkpoint_id = checkpoint.id
        db_session.expunge(checkpoint)

        reloaded = await db_session.get(TrackReleaseCheckpoint, checkpoint_id)
        assert reloaded is not None
        assert reloaded.ticket_package_track_id == track.id
        assert reloaded.srcmd5 == _SRCMD5
        assert reloaded.last_seen_at == seen_at

    async def test_raw_insert_applies_server_defaults(
        self,
        db_session: AsyncSession,
        ticket_package_track_factory: TicketPackageTrackFactory,
    ) -> None:
        """A raw SQL INSERT bypasses every Python-side default, so the
        database must supply `id` and `last_seen_at`."""
        track = await ticket_package_track_factory()
        result = await db_session.execute(
            text(
                "INSERT INTO track_release_checkpoint "
                "(ticket_package_track_id, srcmd5) VALUES (:track_id, :srcmd5) "
                "RETURNING id, last_seen_at, now() AS transaction_time"
            ),
            {"track_id": track.id, "srcmd5": _SRCMD5},
        )
        row = result.one()
        assert isinstance(row.id, uuid.UUID)
        assert row.id.version == 7
        assert row.last_seen_at.tzinfo is not None
        assert row.last_seen_at == row.transaction_time

    async def test_omitted_last_seen_at_uses_database_default(
        self,
        db_session: AsyncSession,
        track_release_checkpoint_factory: TrackReleaseCheckpointFactory,
    ) -> None:
        checkpoint = await track_release_checkpoint_factory()
        await db_session.refresh(checkpoint)
        transaction_time = (await db_session.execute(select(func.now()))).scalar_one()
        assert checkpoint.last_seen_at == transaction_time


@pytest.mark.unit
class TestTrackReleaseCheckpointSchemaShape:
    """Exactly the documented columns, constraints, and index set (#633
    decision A2): `last_seen_at` only, no `srcmd5` format CHECK, and no
    standalone index (UNIQUE `ticket_package_track_id` covers the
    track-keyed lookup)."""

    def test_columns_match_documented_set(self) -> None:
        assert (
            set(TrackReleaseCheckpoint.__table__.columns.keys()) == _DOCUMENTED_COLUMNS
        )

    def test_every_column_is_not_null(self) -> None:
        assert not [
            c.name for c in TrackReleaseCheckpoint.__table__.columns if c.nullable
        ]

    def test_unique_constraint(self) -> None:
        table = TrackReleaseCheckpoint.metadata.tables["track_release_checkpoint"]
        uniques = [
            tuple(column.name for column in constraint.columns)
            for constraint in table.constraints
            if isinstance(constraint, UniqueConstraint)
        ]
        assert uniques == [("ticket_package_track_id",)]

    def test_no_check_constraint(self) -> None:
        table = TrackReleaseCheckpoint.metadata.tables["track_release_checkpoint"]
        assert not [c for c in table.constraints if isinstance(c, CheckConstraint)]

    def test_no_standalone_index(self) -> None:
        table = TrackReleaseCheckpoint.metadata.tables["track_release_checkpoint"]
        assert not table.indexes

    def test_srcmd5_has_no_default(self) -> None:
        column = TrackReleaseCheckpoint.__table__.c.srcmd5
        assert column.default is None
        assert column.server_default is None

    def test_last_seen_at_has_server_default_only(self) -> None:
        """`DEFAULT` is documented; the release detector sets the value
        explicitly when it accepts a new checkpoint, so there is no
        Python-side default and no `onupdate`."""
        column = TrackReleaseCheckpoint.__table__.c.last_seen_at
        assert column.server_default is not None
        assert column.default is None
        assert column.onupdate is None
        assert column.server_onupdate is None

    def test_foreign_key_uses_ondelete_restrict(self) -> None:
        (fk,) = TrackReleaseCheckpoint.__table__.c.ticket_package_track_id.foreign_keys
        assert fk.target_fullname == "ticket_package_track.id"
        assert fk.ondelete == "RESTRICT"

    @pytest.mark.parametrize(
        ("owner", "name", "target", "reverse", "uselist"),
        [
            (
                TicketPackageTrack,
                "release_checkpoint",
                TrackReleaseCheckpoint,
                "ticket_package_track",
                False,
            ),
            (
                TrackReleaseCheckpoint,
                "ticket_package_track",
                TicketPackageTrack,
                "release_checkpoint",
                False,
            ),
        ],
    )
    def test_one_to_one_back_populates(
        self, owner: type, name: str, target: type, reverse: str, uselist: bool
    ) -> None:
        relationship: RelationshipProperty[Any] = inspect(owner).relationships[name]
        assert relationship.mapper.class_ is target
        assert relationship.back_populates == reverse
        assert relationship.uselist is uselist

    def test_track_release_checkpoint_uses_passive_deletes_all(self) -> None:
        """The ORM never nulls or deletes a checkpoint; the RESTRICT FK
        rejects a track delete instead."""
        relationship = TicketPackageTrack.release_checkpoint.property
        assert relationship.passive_deletes == "all"
        assert not relationship.cascade.delete


@pytest.mark.integration
class TestTrackReleaseCheckpointDatabaseIndexes:
    async def test_only_the_unique_constraint_index_exists(
        self, db_session: AsyncSession
    ) -> None:
        result = await db_session.execute(
            text(
                "SELECT indexname, indexdef FROM pg_indexes "
                "WHERE tablename = 'track_release_checkpoint' "
                "AND indexname <> 'track_release_checkpoint_pkey'"
            )
        )
        definitions = dict(result.tuples().all())
        assert set(definitions) == {_UNIQUE}
        assert definitions[_UNIQUE].startswith("CREATE UNIQUE INDEX")
        assert definitions[_UNIQUE].endswith("USING btree (ticket_package_track_id)")


@pytest.mark.integration
class TestTrackReleaseCheckpointUniqueness:
    async def test_second_checkpoint_for_same_track_rejected(
        self,
        db_session: AsyncSession,
        track_release_checkpoint_factory: TrackReleaseCheckpointFactory,
    ) -> None:
        checkpoint = await track_release_checkpoint_factory()
        db_session.add(
            TrackReleaseCheckpoint(
                ticket_package_track_id=checkpoint.ticket_package_track_id,
                srcmd5=_NEXT_SRCMD5,
            )
        )
        with pytest.raises(IntegrityError, match=_UNIQUE):
            await db_session.flush()

    async def test_same_srcmd5_on_different_tracks_accepted(
        self,
        track_release_checkpoint_factory: TrackReleaseCheckpointFactory,
    ) -> None:
        """A checkpoint belongs to one track, not to a global source state."""
        first = await track_release_checkpoint_factory(srcmd5=_SRCMD5)
        second = await track_release_checkpoint_factory(srcmd5=_SRCMD5)
        assert first.ticket_package_track_id != second.ticket_package_track_id


@pytest.mark.integration
class TestTrackReleaseCheckpointColumnLength:
    async def test_srcmd5_accepts_32_characters(
        self, track_release_checkpoint_factory: TrackReleaseCheckpointFactory
    ) -> None:
        checkpoint = await track_release_checkpoint_factory(srcmd5="a" * 32)
        assert checkpoint.srcmd5 == "a" * 32

    async def test_srcmd5_rejects_33_characters(
        self, track_release_checkpoint_factory: TrackReleaseCheckpointFactory
    ) -> None:
        with pytest.raises(DBAPIError, match="value too long"):
            await track_release_checkpoint_factory(srcmd5="a" * 33)


@pytest.mark.integration
class TestTrackReleaseCheckpointNotNullConstraints:
    @pytest.mark.parametrize(
        "column", ["ticket_package_track_id", "srcmd5", "last_seen_at"]
    )
    async def test_explicit_null_rejected(
        self,
        db_session: AsyncSession,
        ticket_package_track_factory: TicketPackageTrackFactory,
        column: str,
    ) -> None:
        """A Core INSERT with an explicit NULL bypasses the ORM, which
        would otherwise omit a `None` server-defaulted column."""
        track = await ticket_package_track_factory()
        values: dict[str, object] = {
            "ticket_package_track_id": track.id,
            "srcmd5": _SRCMD5,
            column: None,
        }
        with pytest.raises(IntegrityError, match="not-null"):
            await db_session.execute(insert(TrackReleaseCheckpoint).values(values))


@pytest.mark.integration
class TestTrackReleaseCheckpointForeignKey:
    async def test_nonexistent_track_rejected(self, db_session: AsyncSession) -> None:
        db_session.add(
            TrackReleaseCheckpoint(ticket_package_track_id=uuid.uuid7(), srcmd5=_SRCMD5)
        )
        with pytest.raises(IntegrityError, match=_TRACK_FK):
            await db_session.flush()


@pytest.mark.integration
class TestTrackDeleteRestrictedWhileCheckpointExists:
    """Tracks are soft-deleted only (docs/data-model.md,
    TrackReleaseCheckpoint). The FK uses `ON DELETE RESTRICT` and
    `TicketPackageTrack.release_checkpoint` uses `passive_deletes="all"`, so
    deleting a track with a checkpoint fails on the FK instead of the ORM
    nulling the checkpoint's `ticket_package_track_id` first."""

    async def test_orm_delete_with_loaded_checkpoint_raises(
        self,
        db_session: AsyncSession,
        track_release_checkpoint_factory: TrackReleaseCheckpointFactory,
    ) -> None:
        checkpoint = await track_release_checkpoint_factory()
        track = await db_session.get(
            TicketPackageTrack, checkpoint.ticket_package_track_id
        )
        assert track is not None
        await db_session.refresh(track, ["release_checkpoint"])
        assert track.release_checkpoint is checkpoint

        await db_session.delete(track)
        with pytest.raises(IntegrityError, match=_TRACK_FK):
            await db_session.flush()

    async def test_database_delete_raises(
        self,
        db_session: AsyncSession,
        track_release_checkpoint_factory: TrackReleaseCheckpointFactory,
    ) -> None:
        checkpoint = await track_release_checkpoint_factory()
        track_id = checkpoint.ticket_package_track_id
        db_session.expunge_all()

        with pytest.raises(IntegrityError, match=_TRACK_FK):
            await db_session.execute(
                delete(TicketPackageTrack).where(TicketPackageTrack.id == track_id)
            )


@pytest.mark.integration
class TestTrackReleaseCheckpointRelationship:
    async def test_track_without_checkpoint_loads_none(
        self,
        db_session: AsyncSession,
        ticket_package_track_factory: TicketPackageTrackFactory,
    ) -> None:
        track = await ticket_package_track_factory()
        await db_session.refresh(track, ["release_checkpoint"])
        assert track.release_checkpoint is None

    async def test_track_and_checkpoint_round_trip(
        self,
        db_session: AsyncSession,
        track_release_checkpoint_factory: TrackReleaseCheckpointFactory,
    ) -> None:
        checkpoint = await track_release_checkpoint_factory()
        await track_release_checkpoint_factory()
        track = await db_session.get(
            TicketPackageTrack, checkpoint.ticket_package_track_id
        )
        assert track is not None

        await db_session.refresh(track, ["release_checkpoint"])
        await db_session.refresh(checkpoint, ["ticket_package_track"])

        assert track.release_checkpoint is checkpoint
        assert checkpoint.ticket_package_track is track

    async def test_assignment_through_track_persists_checkpoint(
        self,
        db_session: AsyncSession,
        ticket_package_track_factory: TicketPackageTrackFactory,
    ) -> None:
        track = await ticket_package_track_factory()
        await db_session.refresh(track, ["release_checkpoint"])

        track.release_checkpoint = TrackReleaseCheckpoint(srcmd5=_SRCMD5)
        await db_session.flush()

        stored = (
            await db_session.execute(
                select(TrackReleaseCheckpoint).where(
                    TrackReleaseCheckpoint.ticket_package_track_id == track.id
                )
            )
        ).scalar_one()
        assert stored.srcmd5 == _SRCMD5


@pytest.mark.integration
class TestTrackReleaseCheckpointTimestamps:
    async def test_last_seen_at_is_timezone_aware(
        self,
        db_session: AsyncSession,
        track_release_checkpoint_factory: TrackReleaseCheckpointFactory,
    ) -> None:
        checkpoint = await track_release_checkpoint_factory()
        await db_session.refresh(checkpoint)
        assert checkpoint.last_seen_at.tzinfo is not None
        assert not hasattr(checkpoint, "created_at")
        assert not hasattr(checkpoint, "updated_at")

    async def test_advancement_persists_explicit_last_seen_at(
        self,
        db_session: AsyncSession,
        track_release_checkpoint_factory: TrackReleaseCheckpointFactory,
    ) -> None:
        checkpoint = await track_release_checkpoint_factory(
            srcmd5=_SRCMD5, last_seen_at=datetime(2026, 9, 3, 10, 0, tzinfo=UTC)
        )
        accepted_at = datetime(2026, 9, 4, 11, 30, tzinfo=UTC)

        checkpoint.srcmd5 = _NEXT_SRCMD5
        checkpoint.last_seen_at = accepted_at
        await db_session.flush()
        await db_session.refresh(checkpoint)

        assert checkpoint.srcmd5 == _NEXT_SRCMD5
        assert checkpoint.last_seen_at == accepted_at

    async def test_last_seen_at_not_rewritten_implicitly(
        self,
        db_session: AsyncSession,
        track_release_checkpoint_factory: TrackReleaseCheckpointFactory,
    ) -> None:
        """No `onupdate`: an update that does not set `last_seen_at` keeps
        the backdated value instead of the transaction time."""
        checkpoint = await track_release_checkpoint_factory(srcmd5=_SRCMD5)
        backdated = datetime.now(UTC) - timedelta(days=7)
        checkpoint.last_seen_at = backdated
        await db_session.flush()

        checkpoint.srcmd5 = _NEXT_SRCMD5
        await db_session.flush()
        await db_session.refresh(checkpoint)

        assert checkpoint.last_seen_at == backdated


@pytest.mark.integration
class TestCheckpointLeavesTrackUpdatedAtUnchanged:
    """Checkpoint creation or advancement does not update
    `TicketPackageTrack.updated_at` (docs/data-model.md, TicketPackageTrack
    and TrackReleaseCheckpoint)."""

    async def test_direct_creation(
        self,
        db_session: AsyncSession,
        ticket_package_track_factory: TicketPackageTrackFactory,
        track_release_checkpoint_factory: TrackReleaseCheckpointFactory,
    ) -> None:
        track = await ticket_package_track_factory()
        backdated = await _backdate_track(db_session, track)

        await track_release_checkpoint_factory(ticket_package_track_id=track.id)
        await db_session.refresh(track)

        assert track.updated_at == backdated

    async def test_creation_through_track_relationship(
        self,
        db_session: AsyncSession,
        ticket_package_track_factory: TicketPackageTrackFactory,
    ) -> None:
        track = await ticket_package_track_factory()
        backdated = await _backdate_track(db_session, track)
        await db_session.refresh(track, ["release_checkpoint"])

        track.release_checkpoint = TrackReleaseCheckpoint(srcmd5=_SRCMD5)
        await db_session.flush()
        await db_session.refresh(track)

        assert track.updated_at == backdated

    async def test_advancement(
        self,
        db_session: AsyncSession,
        ticket_package_track_factory: TicketPackageTrackFactory,
        track_release_checkpoint_factory: TrackReleaseCheckpointFactory,
    ) -> None:
        track = await ticket_package_track_factory()
        checkpoint = await track_release_checkpoint_factory(
            ticket_package_track_id=track.id, srcmd5=_SRCMD5
        )
        backdated = await _backdate_track(db_session, track)

        checkpoint.srcmd5 = _NEXT_SRCMD5
        checkpoint.last_seen_at = datetime.now(UTC)
        await db_session.flush()
        await db_session.refresh(track)

        assert track.updated_at == backdated
