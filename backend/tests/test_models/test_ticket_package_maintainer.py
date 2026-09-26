"""Integration tests for the TicketPackageMaintainer model
(backend/app/models/ticket_package_maintainer.py).

See docs/data-model.md (TicketPackageMaintainer, Notes) and
docs/features/packages/package-maintainership.md (Domain Semantics, Data
Model). Only the persistence contract is covered here; SMELT maintainership
acquisition, its audit event, confidential visibility, the Ticket
`maintainer` filter, and workbench queries are service behavior.
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
    func,
    insert,
    inspect,
    select,
    text,
)
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import RelationshipProperty

from app.models.ticket_package import TicketPackage
from app.models.ticket_package_maintainer import TicketPackageMaintainer
from app.models.user import User

TicketPackageFactory = Callable[..., Awaitable[TicketPackage]]
TicketPackageMaintainerFactory = Callable[..., Awaitable[TicketPackageMaintainer]]
UserFactory = Callable[..., Awaitable[User]]

# No `updated_at` (docs/data-model.md, Notes: timestamp exceptions).
_DOCUMENTED_COLUMNS = {"id", "ticket_package_id", "user_id", "created_at"}

_UNIQUE = "uq_ticket_package_maintainer_ticket_package_id_user_id"
_PACKAGE_FK = "ticket_package_maintainer_ticket_package_id_fkey"
_USER_FK = "ticket_package_maintainer_user_id_fkey"


async def _association_count(db_session: AsyncSession) -> int:
    return (
        await db_session.execute(
            select(func.count()).select_from(TicketPackageMaintainer)
        )
    ).scalar_one()


@pytest.mark.integration
class TestTicketPackageMaintainerCreation:
    async def test_create_with_defaults(
        self, ticket_package_maintainer_factory: TicketPackageMaintainerFactory
    ) -> None:
        association = await ticket_package_maintainer_factory()

        assert association.id.version == 7
        assert association.ticket_package_id is not None
        assert association.user_id is not None
        assert association.created_at is not None

    async def test_create_with_explicit_references(
        self,
        db_session: AsyncSession,
        ticket_package_factory: TicketPackageFactory,
        user_factory: UserFactory,
        ticket_package_maintainer_factory: TicketPackageMaintainerFactory,
    ) -> None:
        package = await ticket_package_factory()
        user = await user_factory()
        association = await ticket_package_maintainer_factory(
            ticket_package_id=package.id, user_id=user.id
        )
        association_id = association.id
        db_session.expunge(association)

        reloaded = await db_session.get(TicketPackageMaintainer, association_id)
        assert reloaded is not None
        assert reloaded.ticket_package_id == package.id
        assert reloaded.user_id == user.id

    async def test_raw_insert_applies_server_defaults(
        self,
        db_session: AsyncSession,
        ticket_package_factory: TicketPackageFactory,
        user_factory: UserFactory,
    ) -> None:
        """A raw SQL INSERT bypasses every Python-side default, so the
        database must supply `id` and `created_at`."""
        package = await ticket_package_factory()
        user = await user_factory()
        result = await db_session.execute(
            text(
                "INSERT INTO ticket_package_maintainer "
                "(ticket_package_id, user_id) VALUES (:package_id, :user_id) "
                "RETURNING id, created_at"
            ),
            {"package_id": package.id, "user_id": user.id},
        )
        row = result.one()
        assert isinstance(row.id, uuid.UUID)
        assert row.id.version == 7
        assert row.created_at.tzinfo is not None


@pytest.mark.unit
class TestTicketPackageMaintainerSchemaShape:
    """Exactly the documented columns, constraints, and index (#633
    decision A2): `created_at` only, no CHECK constraint, and only
    `ix_ticket_package_maintainer_user_id`."""

    def test_columns_match_documented_set(self) -> None:
        assert (
            set(TicketPackageMaintainer.__table__.columns.keys()) == _DOCUMENTED_COLUMNS
        )

    def test_unique_constraint(self) -> None:
        table = TicketPackageMaintainer.metadata.tables["ticket_package_maintainer"]
        uniques = {
            (constraint.name, tuple(column.name for column in constraint.columns))
            for constraint in table.constraints
            if isinstance(constraint, UniqueConstraint)
        }
        assert uniques == {(_UNIQUE, ("ticket_package_id", "user_id"))}

    def test_no_check_constraint(self) -> None:
        table = TicketPackageMaintainer.metadata.tables["ticket_package_maintainer"]
        assert not [c for c in table.constraints if isinstance(c, CheckConstraint)]

    def test_exact_index_set(self) -> None:
        """`ix_ticket_package_maintainer_user_id`: non-unique, non-partial
        B-tree on `user_id` (docs/data-model.md, TicketPackageMaintainer,
        Indexes). The UNIQUE constraint covers package-first acquisition."""
        (index,) = TicketPackageMaintainer.metadata.tables[
            "ticket_package_maintainer"
        ].indexes
        assert index.name == "ix_ticket_package_maintainer_user_id"
        assert [column.name for column in index.columns] == ["user_id"]
        assert index.unique is False
        assert index.dialect_options["postgresql"]["where"] is None
        # No `postgresql_using`: PostgreSQL's default B-tree access method.
        assert not index.dialect_options["postgresql"]["using"]

    @pytest.mark.parametrize(
        ("column", "target"),
        [("ticket_package_id", "ticket_package.id"), ("user_id", "user.id")],
    )
    def test_foreign_keys_use_ondelete_restrict(self, column: str, target: str) -> None:
        (fk,) = TicketPackageMaintainer.__table__.c[column].foreign_keys
        assert fk.target_fullname == target
        assert fk.ondelete == "RESTRICT"


@pytest.mark.unit
class TestMaintainershipRelationshipShape:
    """`TicketPackage.maintainers` ↔ `User.maintained_packages` are explicit
    `back_populates` relationships (docs/data-model.md,
    TicketPackageMaintainer). They are view-only many-to-many collections
    through the association table, so associations are created only by
    inserting `TicketPackageMaintainer` rows."""

    @pytest.mark.parametrize(
        ("owner", "name", "target", "reverse"),
        [
            (TicketPackage, "maintainers", User, "maintained_packages"),
            (User, "maintained_packages", TicketPackage, "maintainers"),
        ],
    )
    def test_view_only_many_to_many(
        self, owner: type, name: str, target: type, reverse: str
    ) -> None:
        relationship: RelationshipProperty[Any] = inspect(owner).relationships[name]
        assert relationship.mapper.class_ is target
        assert relationship.back_populates == reverse
        assert relationship.viewonly is True
        assert relationship.secondary is TicketPackageMaintainer.__table__

    def test_association_declares_no_relationship(self) -> None:
        assert not inspect(TicketPackageMaintainer).relationships


@pytest.mark.integration
class TestTicketPackageMaintainerUniqueness:
    async def test_same_user_on_same_package_rejected(
        self,
        db_session: AsyncSession,
        ticket_package_maintainer_factory: TicketPackageMaintainerFactory,
    ) -> None:
        association = await ticket_package_maintainer_factory()
        db_session.add(
            TicketPackageMaintainer(
                ticket_package_id=association.ticket_package_id,
                user_id=association.user_id,
            )
        )
        with pytest.raises(IntegrityError, match=_UNIQUE):
            await db_session.flush()

    async def test_same_user_on_different_packages_accepted(
        self,
        user_factory: UserFactory,
        ticket_package_maintainer_factory: TicketPackageMaintainerFactory,
    ) -> None:
        user = await user_factory()
        first = await ticket_package_maintainer_factory(user_id=user.id)
        second = await ticket_package_maintainer_factory(user_id=user.id)
        assert first.ticket_package_id != second.ticket_package_id

    async def test_different_users_on_same_package_accepted(
        self,
        ticket_package_factory: TicketPackageFactory,
        ticket_package_maintainer_factory: TicketPackageMaintainerFactory,
    ) -> None:
        package = await ticket_package_factory()
        first = await ticket_package_maintainer_factory(ticket_package_id=package.id)
        second = await ticket_package_maintainer_factory(ticket_package_id=package.id)
        assert first.user_id != second.user_id


@pytest.mark.integration
class TestTicketPackageMaintainerNotNullConstraints:
    @pytest.mark.parametrize("column", ["ticket_package_id", "user_id", "created_at"])
    async def test_explicit_null_rejected(
        self,
        db_session: AsyncSession,
        ticket_package_factory: TicketPackageFactory,
        user_factory: UserFactory,
        column: str,
    ) -> None:
        """A Core INSERT with an explicit NULL bypasses the ORM, which
        would otherwise omit a `None` server-defaulted column."""
        package = await ticket_package_factory()
        user = await user_factory()
        values: dict[str, object] = {
            "ticket_package_id": package.id,
            "user_id": user.id,
            column: None,
        }
        with pytest.raises(IntegrityError, match="not-null"):
            await db_session.execute(insert(TicketPackageMaintainer).values(values))


@pytest.mark.integration
class TestTicketPackageMaintainerForeignKeys:
    @pytest.mark.parametrize(
        ("column", "constraint"),
        [("ticket_package_id", _PACKAGE_FK), ("user_id", _USER_FK)],
    )
    async def test_nonexistent_reference_rejected(
        self,
        db_session: AsyncSession,
        ticket_package_factory: TicketPackageFactory,
        user_factory: UserFactory,
        column: str,
        constraint: str,
    ) -> None:
        package = await ticket_package_factory()
        user = await user_factory()
        values: dict[str, uuid.UUID] = {
            "ticket_package_id": package.id,
            "user_id": user.id,
            column: uuid.uuid7(),
        }
        db_session.add(TicketPackageMaintainer(**values))
        with pytest.raises(IntegrityError, match=constraint):
            await db_session.flush()


@pytest.mark.integration
class TestTicketPackageMaintainerRestrictOnDelete:
    """Package occurrences are soft-deleted and users are deactivated, not
    deleted (docs/data-model.md, TicketPackageMaintainer), so every
    referenced-row delete fails on its RESTRICT FK. The view-only
    collections never delete or null association rows, so the ORM tests load
    them before deleting to prove the database still rejects the delete."""

    async def test_orm_package_delete_with_loaded_maintainers_raises(
        self,
        db_session: AsyncSession,
        ticket_package_maintainer_factory: TicketPackageMaintainerFactory,
    ) -> None:
        association = await ticket_package_maintainer_factory()
        package = await db_session.get(TicketPackage, association.ticket_package_id)
        assert package is not None
        await db_session.refresh(package, ["maintainers"])
        assert len(package.maintainers) == 1

        await db_session.delete(package)
        with pytest.raises(IntegrityError, match=_PACKAGE_FK):
            await db_session.flush()

    async def test_orm_user_delete_with_loaded_packages_raises(
        self,
        db_session: AsyncSession,
        ticket_package_maintainer_factory: TicketPackageMaintainerFactory,
    ) -> None:
        association = await ticket_package_maintainer_factory()
        user = await db_session.get(User, association.user_id)
        assert user is not None
        await db_session.refresh(user, ["maintained_packages"])
        assert len(user.maintained_packages) == 1

        await db_session.delete(user)
        with pytest.raises(IntegrityError, match=_USER_FK):
            await db_session.flush()

    async def test_database_package_delete_raises(
        self,
        db_session: AsyncSession,
        ticket_package_maintainer_factory: TicketPackageMaintainerFactory,
    ) -> None:
        association = await ticket_package_maintainer_factory()
        package_id = association.ticket_package_id
        db_session.expunge_all()

        with pytest.raises(IntegrityError, match=_PACKAGE_FK):
            await db_session.execute(
                delete(TicketPackage).where(TicketPackage.id == package_id)
            )

    async def test_database_user_delete_raises(
        self,
        db_session: AsyncSession,
        ticket_package_maintainer_factory: TicketPackageMaintainerFactory,
    ) -> None:
        association = await ticket_package_maintainer_factory()
        user_id = association.user_id
        db_session.expunge_all()

        with pytest.raises(IntegrityError, match=_USER_FK):
            await db_session.execute(delete(User).where(User.id == user_id))


@pytest.mark.integration
class TestMaintainershipRelationships:
    async def test_package_maintainers_and_user_packages_round_trip(
        self,
        db_session: AsyncSession,
        ticket_package_factory: TicketPackageFactory,
        user_factory: UserFactory,
        ticket_package_maintainer_factory: TicketPackageMaintainerFactory,
    ) -> None:
        package = await ticket_package_factory()
        other_package = await ticket_package_factory()
        first_user = await user_factory()
        second_user = await user_factory()
        await ticket_package_maintainer_factory(
            ticket_package_id=package.id, user_id=first_user.id
        )
        await ticket_package_maintainer_factory(
            ticket_package_id=package.id, user_id=second_user.id
        )
        await ticket_package_maintainer_factory(
            ticket_package_id=other_package.id, user_id=first_user.id
        )
        await ticket_package_maintainer_factory()

        await db_session.refresh(package, ["maintainers"])
        await db_session.refresh(first_user, ["maintained_packages"])

        assert {u.id for u in package.maintainers} == {first_user.id, second_user.id}
        assert {p.id for p in first_user.maintained_packages} == {
            package.id,
            other_package.id,
        }

    async def test_association_retained_for_excluded_package_and_inactive_user(
        self,
        db_session: AsyncSession,
        ticket_package_maintainer_factory: TicketPackageMaintainerFactory,
    ) -> None:
        """Package exclusion and user deactivation never delete an
        association (package-maintainership.md, Add-only acquisition); the
        persisted relationship is not filtered by either marker."""
        association = await ticket_package_maintainer_factory()
        package = await db_session.get(TicketPackage, association.ticket_package_id)
        user = await db_session.get(User, association.user_id)
        assert package is not None
        assert user is not None
        package.deleted_at = datetime.now(UTC)
        user.active = False
        await db_session.flush()

        await db_session.refresh(package, ["maintainers"])
        await db_session.refresh(user, ["maintained_packages"])

        assert [u.id for u in package.maintainers] == [user.id]
        assert [p.id for p in user.maintained_packages] == [package.id]

    async def test_collection_changes_are_not_persisted(
        self,
        db_session: AsyncSession,
        ticket_package_factory: TicketPackageFactory,
        user_factory: UserFactory,
        ticket_package_maintainer_factory: TicketPackageMaintainerFactory,
    ) -> None:
        """The view-only collections cannot add or remove associations:
        only inserting a `TicketPackageMaintainer` row creates one."""
        package = await ticket_package_factory()
        maintainer = await user_factory()
        await ticket_package_maintainer_factory(
            ticket_package_id=package.id, user_id=maintainer.id
        )
        newcomer = await user_factory()
        await db_session.refresh(package, ["maintainers"])

        package.maintainers.remove(maintainer)
        package.maintainers.append(newcomer)
        await db_session.flush()

        assert await _association_count(db_session) == 1
        await db_session.refresh(package, ["maintainers"])
        assert [u.id for u in package.maintainers] == [maintainer.id]


@pytest.mark.integration
class TestTicketPackageMaintainerTimestamps:
    async def test_created_at_is_timezone_aware(
        self,
        db_session: AsyncSession,
        ticket_package_maintainer_factory: TicketPackageMaintainerFactory,
    ) -> None:
        association = await ticket_package_maintainer_factory()
        await db_session.refresh(association)
        assert association.created_at.tzinfo is not None
        assert not hasattr(association, "updated_at")
