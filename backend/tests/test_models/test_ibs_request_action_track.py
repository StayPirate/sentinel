"""Integration tests for the IBSRequestActionTrack model
(backend/app/models/ibs_request_action_track.py).

See docs/data-model.md (IBSRequestActionTrack, IBS Request Evidence
Retention, Notes: timestamp exceptions) and
docs/features/packages/ibs-submission-tracking.md (Data Model >
IBSRequestActionTrack, Retention and Deletion, RabbitMQ Request Wake-Ups
step 4). Only the persistence contract is covered here; the correlation
upsert and delivery derivation are IBS submission tracking behavior.
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Any

import pytest
from sqlalchemy import (
    CheckConstraint,
    UniqueConstraint,
    delete,
    insert,
    inspect,
    text,
)
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import RelationshipProperty

from app.core.enums import IBSRequestActionType, IBSRequestState
from app.models.ibs_request import IBSRequest
from app.models.ibs_request_action import IBSRequestAction
from app.models.ibs_request_action_track import IBSRequestActionTrack
from app.models.ticket_package import TicketPackage
from app.models.ticket_package_track import TicketPackageTrack

IBSRequestActionFactory = Callable[..., Awaitable[IBSRequestAction]]
IBSRequestActionTrackFactory = Callable[..., Awaitable[IBSRequestActionTrack]]
TicketPackageTrackFactory = Callable[..., Awaitable[TicketPackageTrack]]

# No `updated_at` (docs/data-model.md, Notes: timestamp exceptions).
_DOCUMENTED_COLUMNS = {
    "id",
    "ibs_request_action_id",
    "ticket_package_track_id",
    "created_at",
}

_UNIQUE = "uq_ibs_request_action_track_track_id_action_id"
_ACTION_INDEX = "ix_ibs_request_action_track_ibs_request_action_id"
_ACTION_FK = "ibs_request_action_track_ibs_request_action_id_fkey"
_TRACK_FK = "ibs_request_action_track_ticket_package_track_id_fkey"


@pytest.mark.integration
class TestIBSRequestActionTrackCreation:
    async def test_create_with_defaults(
        self, ibs_request_action_track_factory: IBSRequestActionTrackFactory
    ) -> None:
        link = await ibs_request_action_track_factory()

        assert link.id.version == 7
        assert link.ibs_request_action_id is not None
        assert link.ticket_package_track_id is not None
        assert link.created_at is not None

    async def test_create_with_explicit_references(
        self,
        db_session: AsyncSession,
        ibs_request_action_factory: IBSRequestActionFactory,
        ticket_package_track_factory: TicketPackageTrackFactory,
        ibs_request_action_track_factory: IBSRequestActionTrackFactory,
    ) -> None:
        action = await ibs_request_action_factory()
        track = await ticket_package_track_factory()
        link = await ibs_request_action_track_factory(
            ibs_request_action_id=action.id, ticket_package_track_id=track.id
        )
        link_id = link.id
        db_session.expunge(link)

        reloaded = await db_session.get(IBSRequestActionTrack, link_id)
        assert reloaded is not None
        assert reloaded.ibs_request_action_id == action.id
        assert reloaded.ticket_package_track_id == track.id

    async def test_raw_insert_applies_server_defaults(
        self,
        db_session: AsyncSession,
        ibs_request_action_factory: IBSRequestActionFactory,
        ticket_package_track_factory: TicketPackageTrackFactory,
    ) -> None:
        """A raw SQL INSERT bypasses every Python-side default, so the
        database must supply `id` and `created_at`."""
        action = await ibs_request_action_factory()
        track = await ticket_package_track_factory()
        result = await db_session.execute(
            text(
                "INSERT INTO ibs_request_action_track "
                "(ibs_request_action_id, ticket_package_track_id) "
                "VALUES (:action_id, :track_id) RETURNING id, created_at"
            ),
            {"action_id": action.id, "track_id": track.id},
        )
        row = result.one()
        assert isinstance(row.id, uuid.UUID)
        assert row.id.version == 7
        assert row.created_at.tzinfo is not None


@pytest.mark.unit
class TestIBSRequestActionTrackSchemaShape:
    """Exactly the documented columns, constraints, and index (#633 decision
    A2): `created_at` only, the track-leading UNIQUE pair, no CHECK
    constraint, and only `ix_ibs_request_action_track_ibs_request_action_id`."""

    def test_columns_match_documented_set(self) -> None:
        assert (
            set(IBSRequestActionTrack.__table__.columns.keys()) == _DOCUMENTED_COLUMNS
        )

    def test_every_column_is_not_null(self) -> None:
        assert not [
            c.name for c in IBSRequestActionTrack.__table__.columns if c.nullable
        ]

    def test_unique_constraint_is_track_leading(self) -> None:
        table = IBSRequestActionTrack.metadata.tables["ibs_request_action_track"]
        uniques = {
            (constraint.name, tuple(column.name for column in constraint.columns))
            for constraint in table.constraints
            if isinstance(constraint, UniqueConstraint)
        }
        assert uniques == {
            (_UNIQUE, ("ticket_package_track_id", "ibs_request_action_id"))
        }

    def test_no_check_constraint(self) -> None:
        table = IBSRequestActionTrack.metadata.tables["ibs_request_action_track"]
        assert not [c for c in table.constraints if isinstance(c, CheckConstraint)]

    def test_exact_index_set(self) -> None:
        """Non-unique, non-partial B-tree on `ibs_request_action_id`
        (docs/data-model.md, IBSRequestActionTrack, Indexes)."""
        (index,) = IBSRequestActionTrack.metadata.tables[
            "ibs_request_action_track"
        ].indexes
        assert index.name == _ACTION_INDEX
        assert [column.name for column in index.columns] == ["ibs_request_action_id"]
        assert index.unique is False
        assert index.dialect_options["postgresql"]["where"] is None
        # No `postgresql_using`: PostgreSQL's default B-tree access method.
        assert not index.dialect_options["postgresql"]["using"]

    @pytest.mark.parametrize(
        ("column", "target"),
        [
            ("ibs_request_action_id", "ibs_request_action.id"),
            ("ticket_package_track_id", "ticket_package_track.id"),
        ],
    )
    def test_foreign_keys_use_ondelete_restrict(self, column: str, target: str) -> None:
        (fk,) = IBSRequestActionTrack.__table__.c[column].foreign_keys
        assert fk.target_fullname == target
        assert fk.ondelete == "RESTRICT"

    @pytest.mark.parametrize(
        ("owner", "name", "target", "reverse"),
        [
            (
                IBSRequestAction,
                "track_links",
                IBSRequestActionTrack,
                "ibs_request_action",
            ),
            (
                IBSRequestActionTrack,
                "ibs_request_action",
                IBSRequestAction,
                "track_links",
            ),
        ],
    )
    def test_bidirectional_back_populates(
        self, owner: type, name: str, target: type, reverse: str
    ) -> None:
        relationship: RelationshipProperty[Any] = inspect(owner).relationships[name]
        assert relationship.mapper.class_ is target
        assert relationship.back_populates == reverse

    def test_action_track_links_use_passive_deletes_all(self) -> None:
        """The ORM never nulls or deletes retained correlations; the
        RESTRICT FK rejects an action delete instead."""
        relationship = IBSRequestAction.track_links.property
        assert relationship.passive_deletes == "all"
        assert not relationship.cascade.delete

    def test_only_the_documented_relationship_is_mapped(self) -> None:
        """Only the action ↔ correlation pair is documented
        (docs/data-model.md, IBSRequestActionTrack); the track side is
        reached through the FK column."""
        assert set(inspect(IBSRequestActionTrack).relationships.keys()) == {
            "ibs_request_action"
        }
        assert not [
            rel
            for rel in inspect(TicketPackageTrack).relationships
            if rel.mapper.class_ is IBSRequestActionTrack
        ]


@pytest.mark.integration
class TestIBSRequestActionTrackDatabaseIndexes:
    async def test_index_definitions(self, db_session: AsyncSession) -> None:
        result = await db_session.execute(
            text(
                "SELECT indexname, indexdef FROM pg_indexes "
                "WHERE tablename = 'ibs_request_action_track' "
                "AND indexname <> 'ibs_request_action_track_pkey'"
            )
        )
        definitions = dict(result.tuples().all())
        assert set(definitions) == {_UNIQUE, _ACTION_INDEX}
        assert definitions[_UNIQUE].startswith("CREATE UNIQUE INDEX")
        assert definitions[_UNIQUE].endswith(
            "USING btree (ticket_package_track_id, ibs_request_action_id)"
        )
        assert definitions[_ACTION_INDEX].startswith("CREATE INDEX")
        assert definitions[_ACTION_INDEX].endswith(
            "USING btree (ibs_request_action_id)"
        )


@pytest.mark.integration
class TestIBSRequestActionTrackUniqueness:
    async def test_duplicate_pair_rejected(
        self,
        db_session: AsyncSession,
        ibs_request_action_track_factory: IBSRequestActionTrackFactory,
    ) -> None:
        link = await ibs_request_action_track_factory()
        db_session.add(
            IBSRequestActionTrack(
                ibs_request_action_id=link.ibs_request_action_id,
                ticket_package_track_id=link.ticket_package_track_id,
            )
        )
        with pytest.raises(IntegrityError, match=_UNIQUE):
            await db_session.flush()

    async def test_update_into_existing_pair_rejected(
        self,
        db_session: AsyncSession,
        ticket_package_track_factory: TicketPackageTrackFactory,
        ibs_request_action_track_factory: IBSRequestActionTrackFactory,
    ) -> None:
        track = await ticket_package_track_factory()
        first = await ibs_request_action_track_factory(ticket_package_track_id=track.id)
        second = await ibs_request_action_track_factory(
            ticket_package_track_id=track.id
        )

        second.ibs_request_action_id = first.ibs_request_action_id
        with pytest.raises(IntegrityError, match=_UNIQUE):
            await db_session.flush()

    async def test_one_action_correlates_to_several_tracks(
        self,
        ibs_request_action_factory: IBSRequestActionFactory,
        ibs_request_action_track_factory: IBSRequestActionTrackFactory,
    ) -> None:
        """One action diff can name several CVEs, packages, or codestreams."""
        action = await ibs_request_action_factory()
        first = await ibs_request_action_track_factory(ibs_request_action_id=action.id)
        second = await ibs_request_action_track_factory(ibs_request_action_id=action.id)
        assert first.ticket_package_track_id != second.ticket_package_track_id

    async def test_several_actions_correlate_to_one_track(
        self,
        ibs_request_action_factory: IBSRequestActionFactory,
        ticket_package_track_factory: TicketPackageTrackFactory,
        ibs_request_action_track_factory: IBSRequestActionTrackFactory,
    ) -> None:
        """A track can be correlated to submission and release actions of
        different requests."""
        track = await ticket_package_track_factory()
        submission = await ibs_request_action_factory()
        release = await ibs_request_action_factory(
            action_type=IBSRequestActionType.MAINTENANCE_RELEASE.value
        )
        for action in (submission, release):
            await ibs_request_action_track_factory(
                ibs_request_action_id=action.id, ticket_package_track_id=track.id
            )


@pytest.mark.integration
class TestIBSRequestActionTrackNotNullConstraints:
    @pytest.mark.parametrize(
        "column", ["ibs_request_action_id", "ticket_package_track_id", "created_at"]
    )
    async def test_explicit_null_rejected(
        self,
        db_session: AsyncSession,
        ibs_request_action_factory: IBSRequestActionFactory,
        ticket_package_track_factory: TicketPackageTrackFactory,
        column: str,
    ) -> None:
        """A Core INSERT with an explicit NULL bypasses the ORM, which
        would otherwise omit a `None` server-defaulted column."""
        action = await ibs_request_action_factory()
        track = await ticket_package_track_factory()
        values: dict[str, object] = {
            "ibs_request_action_id": action.id,
            "ticket_package_track_id": track.id,
            column: None,
        }
        with pytest.raises(IntegrityError, match="not-null"):
            await db_session.execute(insert(IBSRequestActionTrack).values(values))


@pytest.mark.integration
class TestIBSRequestActionTrackForeignKeys:
    @pytest.mark.parametrize(
        ("column", "constraint"),
        [("ibs_request_action_id", _ACTION_FK), ("ticket_package_track_id", _TRACK_FK)],
    )
    async def test_nonexistent_reference_rejected(
        self,
        db_session: AsyncSession,
        ibs_request_action_factory: IBSRequestActionFactory,
        ticket_package_track_factory: TicketPackageTrackFactory,
        column: str,
        constraint: str,
    ) -> None:
        action = await ibs_request_action_factory()
        track = await ticket_package_track_factory()
        values: dict[str, uuid.UUID] = {
            "ibs_request_action_id": action.id,
            "ticket_package_track_id": track.id,
            column: uuid.uuid7(),
        }
        db_session.add(IBSRequestActionTrack(**values))
        with pytest.raises(IntegrityError, match=constraint):
            await db_session.flush()


@pytest.mark.integration
class TestIBSRequestActionTrackRestrictOnDelete:
    """Correlations are factual evidence retained indefinitely
    (docs/data-model.md, IBS Request Evidence Retention): deleting a
    referenced action or track fails on its RESTRICT FK."""

    async def test_orm_action_delete_with_loaded_links_raises(
        self,
        db_session: AsyncSession,
        ibs_request_action_track_factory: IBSRequestActionTrackFactory,
    ) -> None:
        link = await ibs_request_action_track_factory()
        action = await db_session.get(IBSRequestAction, link.ibs_request_action_id)
        assert action is not None
        await db_session.refresh(action, ["track_links"])
        assert action.track_links == [link]

        await db_session.delete(action)
        with pytest.raises(IntegrityError, match=_ACTION_FK):
            await db_session.flush()

    async def test_orm_track_delete_raises(
        self,
        db_session: AsyncSession,
        ibs_request_action_track_factory: IBSRequestActionTrackFactory,
    ) -> None:
        link = await ibs_request_action_track_factory()
        track = await db_session.get(TicketPackageTrack, link.ticket_package_track_id)
        assert track is not None

        await db_session.delete(track)
        with pytest.raises(IntegrityError, match=_TRACK_FK):
            await db_session.flush()

    async def test_database_action_delete_raises(
        self,
        db_session: AsyncSession,
        ibs_request_action_track_factory: IBSRequestActionTrackFactory,
    ) -> None:
        link = await ibs_request_action_track_factory()
        action_id = link.ibs_request_action_id
        db_session.expunge_all()

        with pytest.raises(IntegrityError, match=_ACTION_FK):
            await db_session.execute(
                delete(IBSRequestAction).where(IBSRequestAction.id == action_id)
            )

    async def test_database_track_delete_raises(
        self,
        db_session: AsyncSession,
        ibs_request_action_track_factory: IBSRequestActionTrackFactory,
    ) -> None:
        link = await ibs_request_action_track_factory()
        track_id = link.ticket_package_track_id
        db_session.expunge_all()

        with pytest.raises(IntegrityError, match=_TRACK_FK):
            await db_session.execute(
                delete(TicketPackageTrack).where(TicketPackageTrack.id == track_id)
            )


@pytest.mark.integration
class TestIBSRequestActionTrackRelationships:
    async def test_action_track_links_round_trip(
        self,
        db_session: AsyncSession,
        ibs_request_action_factory: IBSRequestActionFactory,
        ibs_request_action_track_factory: IBSRequestActionTrackFactory,
    ) -> None:
        action = await ibs_request_action_factory()
        first = await ibs_request_action_track_factory(ibs_request_action_id=action.id)
        second = await ibs_request_action_track_factory(ibs_request_action_id=action.id)
        await ibs_request_action_track_factory()

        await db_session.refresh(action, ["track_links"])
        await db_session.refresh(first, ["ibs_request_action"])

        assert {link.id for link in action.track_links} == {first.id, second.id}
        assert first.ibs_request_action is action

    async def test_link_retained_for_excluded_track_and_deleted_request(
        self,
        db_session: AsyncSession,
        ibs_request_action_track_factory: IBSRequestActionTrackFactory,
    ) -> None:
        """Package-tree soft deletion and an upstream `deleted` request state
        never remove correlations (docs/data-model.md, IBS Request Evidence
        Retention); the persisted relationship is not filtered by either."""
        link = await ibs_request_action_track_factory()
        action = await db_session.get(IBSRequestAction, link.ibs_request_action_id)
        track = await db_session.get(TicketPackageTrack, link.ticket_package_track_id)
        assert action is not None
        assert track is not None
        request = await db_session.get(IBSRequest, action.ibs_request_id)
        package = await db_session.get(TicketPackage, track.ticket_package_id)
        assert request is not None
        assert package is not None
        now = datetime.now(UTC)
        track.deleted_at = now
        package.deleted_at = now
        request.state = IBSRequestState.DELETED.value
        await db_session.flush()

        await db_session.refresh(action, ["track_links"])

        assert [candidate.id for candidate in action.track_links] == [link.id]


@pytest.mark.integration
class TestIBSRequestActionTrackTimestamps:
    async def test_created_at_is_timezone_aware(
        self,
        db_session: AsyncSession,
        ibs_request_action_track_factory: IBSRequestActionTrackFactory,
    ) -> None:
        link = await ibs_request_action_track_factory()
        await db_session.refresh(link)
        assert link.created_at.tzinfo is not None
        assert not hasattr(link, "updated_at")
