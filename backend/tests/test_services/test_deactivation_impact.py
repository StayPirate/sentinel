"""Tests for `get_deactivation_impact()`
(backend/app/services/user_service.py).

See docs/features/identity/user-service.md (`get_deactivation_impact()`
including Guard and no-op ordering, Query ownership, Advisory consistency,
Side effects and audit, Re-invocation, and Exceptions; External Active Status
Ownership; `deactivate_user()` for the previewed action) and
docs/features/identity/user-management.md (Get Deactivation Impact, Advisory
semantics) for the contract under test, and
docs/features/platform/testing-strategy.md (User Lifecycle and Management:
"Deactivation preview service"; Ticket Accessibility: Confidentiality and
explicit access grants; API Key Management; Concurrency Testing) for the
mandatory scenarios. The route and CLI composition are covered by their own
modules.

Independent-session tests commit their rows through `IdentityWorld`, which
deletes them explicitly at teardown (testing-strategy.md, Concurrency
Testing). Expected values are transcribed from the specifications; nothing
here computes an expectation with the module under test.
"""

from __future__ import annotations

import dataclasses
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock

import pytest
import redis.asyncio as redis_asyncio
from sqlalchemy import func, select
from sqlalchemy.exc import OperationalError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import Role, TicketStatus
from app.core.exceptions import UserNotFoundError
from app.models.api_key import ApiKey
from app.models.identity_audit_event import IdentityAuditEvent
from app.models.session import Session
from app.models.ticket import Ticket
from app.models.ticket_access_grant import TicketAccessGrant
from app.models.ticket_audit_event import TicketAuditEvent
from app.models.ticket_package import TicketPackage
from app.models.ticket_package_maintainer import TicketPackageMaintainer
from app.models.user import User
from app.models.user_role import UserRole
from app.services import local_auth_service, session_service, user_service
from app.services.user_service import (
    DeactivationImpact,
    ExternalUserStatusReadOnlyError,
    SelfDeactivationError,
    UserServiceError,
    deactivate_user,
    get_deactivation_impact,
)
from tests.support.identity_lifecycle_races import (
    EXTERNAL_GROUP,
    MANUAL,
    IdentityWorld,
    deactivate,
)
from tests.support.suse_cvss_races import SessionStatementRecorder
from tests.support.ticket_mutations import StatementRecorder

UserFactory = Callable[..., Awaitable[User]]
UserRoleFactory = Callable[..., Awaitable[UserRole]]
ApiKeyFactory = Callable[..., Awaitable[ApiKey]]
SessionFactory = Callable[..., Awaitable[Session]]
TicketFactory = Callable[..., Awaitable[Ticket]]
Factory = Callable[[], Awaitable[AsyncSession]]

_REASON = "fictional offboarding"
# Stored `UserRole.role` values (docs/data-model.md, Role Enum).
_ADMIN = "Admin"
_VA = "Vulnerability Analyst"

# user-service.md, `get_deactivation_impact()` Guard and no-op ordering step 2.
_ZEROED = DeactivationImpact(
    already_inactive=True,
    is_last_active_admin=False,
    api_keys_count=0,
    sessions_count=0,
    tickets_count=0,
)


class _InjectedError(Exception):
    """A deterministic failure injected into one observation."""


@dataclass(frozen=True)
class _World:
    """The persisted fixture state of one preview scenario."""

    actor_id: uuid.UUID
    target_id: uuid.UUID
    other_id: uuid.UUID


@pytest.fixture
async def world(
    user_factory: UserFactory,
    user_role_factory: UserRoleFactory,
    api_key_factory: ApiKeyFactory,
    session_factory: SessionFactory,
    ticket_factory: TicketFactory,
) -> _World:
    """An active local target holding the only Admin role, with every
    in-scope and out-of-scope resource kind of the previewed action."""
    actor = await user_factory(username="alice.operator")
    target = await user_factory(username="bob.va")
    other = await user_factory(username="carol.va")
    await user_role_factory(user_id=target.id, role=_ADMIN)
    await user_role_factory(user_id=target.id, role=_VA)
    await user_role_factory(user_id=other.id, role=_VA)

    now = datetime.now(UTC)
    await api_key_factory(user_id=target.id, name="bob-laptop")
    await api_key_factory(
        user_id=target.id, name="bob-ci-expired", expires_at=now - timedelta(days=1)
    )
    await api_key_factory(
        user_id=target.id,
        name="bob-old",
        revoked_at=now - timedelta(days=2),
        revoked_by=actor.id,
    )
    await api_key_factory(user_id=other.id, name="carol-laptop")

    await session_factory(user_id=target.id)
    await session_factory(user_id=target.id)
    await session_factory(user_id=target.id, is_active=False)
    await session_factory(user_id=other.id)

    for status in ("New", "Analysis", "Analyzed", "Resolved", "Ignored", "Duplicated"):
        await ticket_factory(status=status, assignee_id=target.id)
    await ticket_factory(status=TicketStatus.ANALYSIS.value)
    await ticket_factory(status=TicketStatus.ANALYSIS.value, assignee_id=other.id)

    return _World(actor_id=actor.id, target_id=target.id, other_id=other.id)


# The `world` target: two non-revoked keys (one expired), two active
# Sessions, and its `New`, `Analysis`, and `Analyzed` Tickets.
_WORLD_IMPACT = DeactivationImpact(
    already_inactive=False,
    is_last_active_admin=True,
    api_keys_count=2,
    sessions_count=2,
    tickets_count=3,
)


@pytest.fixture
def forbid_key_count(monkeypatch: pytest.MonkeyPatch) -> AsyncMock:
    """Replace the delegated API-key count with a spy that fails if awaited."""
    spy = AsyncMock(side_effect=AssertionError("must not count API keys"))
    monkeypatch.setattr(user_service, "count_non_revoked_keys", spy)
    return spy


async def _audit_counts(db: AsyncSession) -> tuple[int, int]:
    """`(IdentityAuditEvent rows, TicketAuditEvent rows)` in the database."""
    identity = await db.execute(select(func.count()).select_from(IdentityAuditEvent))
    tickets = await db.execute(select(func.count()).select_from(TicketAuditEvent))
    return identity.scalar_one(), tickets.scalar_one()


# ---------------------------------------------------------------------------
# Guard and no-op ordering
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestGuardPrecedence:
    @pytest.mark.parametrize("system", [False, True], ids=["admin", "system"])
    async def test_unknown_user_raises_not_found(
        self,
        db_session: AsyncSession,
        user_factory: UserFactory,
        forbid_key_count: AsyncMock,
        system: bool,
    ) -> None:
        """Step 1: an unknown target raises `UserNotFoundError`."""
        actor = await user_factory(username="alice.operator")

        with pytest.raises(UserNotFoundError):
            await get_deactivation_impact(
                db_session, uuid.uuid4(), acting_user_id=None if system else actor.id
            )

        forbid_key_count.assert_not_awaited()

    @pytest.mark.parametrize(
        ("external", "actor"),
        [
            (False, "admin"),
            (False, None),
            (False, "self"),
            (True, "admin"),
            (True, None),
            (True, "self"),
        ],
        ids=[
            "local-admin",
            "local-system",
            "local-self",
            "external-admin",
            "external-system",
            "external-self",
        ],
    )
    async def test_already_inactive_target_is_zeroed_before_any_guard(
        self,
        db_session: AsyncSession,
        user_factory: UserFactory,
        user_role_factory: UserRoleFactory,
        api_key_factory: ApiKeyFactory,
        session_factory: SessionFactory,
        ticket_factory: TicketFactory,
        forbid_key_count: AsyncMock,
        external: bool,
        actor: str | None,
    ) -> None:
        """Step 2 and External Active Status Ownership: an already-inactive
        target, local or external and whatever the actor, returns the
        zeroed result without the external and self guards and without
        accessing its leftover keys, Sessions, Tickets, or Admin role: the
        target read is the only statement."""
        operator = await user_factory(username="alice.operator")
        overrides: dict[str, Any] = {"external_id": uuid.uuid4()} if external else {}
        target = await user_factory(username="bob.va", active=False, **overrides)
        await user_role_factory(user_id=target.id, role=_ADMIN)
        await api_key_factory(user_id=target.id, name="bob-leftover")
        await session_factory(user_id=target.id)
        await ticket_factory(status=TicketStatus.ANALYSIS.value, assignee_id=target.id)
        acting = {"admin": operator.id, "self": target.id, None: None}[actor]

        with StatementRecorder(db_session) as recorder:
            impact = await get_deactivation_impact(
                db_session, target.id, acting_user_id=acting
            )

        assert impact == _ZEROED
        forbid_key_count.assert_not_awaited()
        assert len(recorder.statements) == 1
        assert 'FROM "user"' in recorder.statements[0]

    @pytest.mark.parametrize(
        ("external", "self_target", "error"),
        [
            (True, False, ExternalUserStatusReadOnlyError),
            (True, True, ExternalUserStatusReadOnlyError),
            (False, True, SelfDeactivationError),
        ],
        ids=["external", "external-self", "local-self"],
    )
    async def test_active_rejected_target_is_not_observed(
        self,
        db_session: AsyncSession,
        user_factory: UserFactory,
        api_key_factory: ApiKeyFactory,
        forbid_key_count: AsyncMock,
        external: bool,
        self_target: bool,
        error: type[UserServiceError],
    ) -> None:
        """Steps 3-4: an active external target with an actor UUID raises
        `ExternalUserStatusReadOnlyError`, also when it is the actor itself
        (the external guard precedes the self guard); an active local
        self-target raises `SelfDeactivationError`. No resource is read."""
        operator = await user_factory(username="alice.operator")
        overrides: dict[str, Any] = {"external_id": uuid.uuid4()} if external else {}
        target = await user_factory(username="bob.va", **overrides)
        await api_key_factory(user_id=target.id, name="bob-laptop")
        acting = target.id if self_target else operator.id

        with StatementRecorder(db_session) as recorder, pytest.raises(error):
            await get_deactivation_impact(db_session, target.id, acting_user_id=acting)

        forbid_key_count.assert_not_awaited()
        assert len(recorder.statements) == 1


@pytest.mark.unit
class TestDeactivationImpactShape:
    def test_exactly_the_five_documented_fields(self) -> None:
        """user-service.md, `get_deactivation_impact()` Result: no grant or
        maintainership field exists (user-management.md, Get Deactivation
        Impact)."""
        assert [f.name for f in dataclasses.fields(DeactivationImpact)] == [
            "already_inactive",
            "is_last_active_admin",
            "api_keys_count",
            "sessions_count",
            "tickets_count",
        ]


# ---------------------------------------------------------------------------
# Observations
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestObservations:
    async def test_counts_follow_the_action_predicates(
        self, db_session: AsyncSession, world: _World
    ) -> None:
        """Non-revoked keys including the expired one, active Sessions, and
        `New`/`Analysis`/`Analyzed` assigned Tickets; revoked keys, inactive
        Sessions, preserved inactive-status Tickets, unassigned Tickets, and
        other Users' resources are excluded."""
        impact = await get_deactivation_impact(
            db_session, world.target_id, acting_user_id=world.actor_id
        )

        assert impact == _WORLD_IMPACT

    async def test_target_without_resources_reports_zero_counts(
        self, db_session: AsyncSession, user_factory: UserFactory
    ) -> None:
        operator = await user_factory(username="alice.operator")
        target = await user_factory(username="bob.va")

        impact = await get_deactivation_impact(
            db_session, target.id, acting_user_id=operator.id
        )

        assert impact == DeactivationImpact(
            already_inactive=False,
            is_last_active_admin=False,
            api_keys_count=0,
            sessions_count=0,
            tickets_count=0,
        )

    @pytest.mark.parametrize("external", [False, True], ids=["local", "external"])
    async def test_system_caller_observes_without_external_or_self_guard(
        self,
        db_session: AsyncSession,
        user_factory: UserFactory,
        api_key_factory: ApiKeyFactory,
        session_factory: SessionFactory,
        ticket_factory: TicketFactory,
        external: bool,
    ) -> None:
        """Steps 3-4 with `acting_user_id = None`: both guards are
        inapplicable, so an active external target is observed too."""
        overrides: dict[str, Any] = {"external_id": uuid.uuid4()} if external else {}
        target = await user_factory(username="bob.va", **overrides)
        await api_key_factory(user_id=target.id, name="bob-laptop")
        await session_factory(user_id=target.id)
        await ticket_factory(status=TicketStatus.NEW.value, assignee_id=target.id)

        impact = await get_deactivation_impact(
            db_session, target.id, acting_user_id=None
        )

        assert impact == DeactivationImpact(
            already_inactive=False,
            is_last_active_admin=False,
            api_keys_count=1,
            sessions_count=1,
            tickets_count=1,
        )

    @pytest.mark.parametrize(
        ("target_origins", "others", "expected"),
        [
            ([(_ADMIN, MANUAL)], [(True, [(_VA, MANUAL)])], True),
            ([(_ADMIN, EXTERNAL_GROUP)], [], True),
            ([(_ADMIN, MANUAL), (_ADMIN, EXTERNAL_GROUP)], [], True),
            ([(_VA, MANUAL)], [], False),
            ([(_VA, MANUAL)], [(True, [(_ADMIN, MANUAL)])], False),
            ([(_ADMIN, MANUAL)], [(True, [(_ADMIN, MANUAL)])], False),
            ([(_ADMIN, MANUAL)], [(True, [(_ADMIN, EXTERNAL_GROUP)])], False),
            ([(_ADMIN, MANUAL)], [(False, [(_ADMIN, MANUAL)])], True),
        ],
        ids=[
            "sole-manual-admin",
            "sole-external-origin-admin",
            "sole-admin-through-two-origins",
            "no-admin-anywhere",
            "target-not-admin",
            "other-active-manual-admin",
            "other-active-external-origin-admin",
            "only-other-admin-inactive",
        ],
    )
    async def test_last_active_admin_across_origins(
        self,
        db_session: AsyncSession,
        user_factory: UserFactory,
        user_role_factory: UserRoleFactory,
        target_origins: list[tuple[str, str]],
        others: list[tuple[bool, list[tuple[str, str]]]],
        expected: bool,
    ) -> None:
        """`is_last_active_admin` is true exactly when the active target
        holds Admin through any origin and no other active User holds Admin
        through any origin."""
        target = await user_factory(username="bob.va")
        for role, group_name in target_origins:
            await user_role_factory(user_id=target.id, role=role, group_name=group_name)
        for index, (active, origins) in enumerate(others):
            other = await user_factory(username=f"carol.other{index}", active=active)
            for role, group_name in origins:
                await user_role_factory(
                    user_id=other.id, role=role, group_name=group_name
                )

        impact = await get_deactivation_impact(
            db_session, target.id, acting_user_id=None
        )

        assert impact == DeactivationImpact(
            already_inactive=False,
            is_last_active_admin=expected,
            api_keys_count=0,
            sessions_count=0,
            tickets_count=0,
        )

    async def test_grants_and_maintainers_are_neither_counted_nor_observed(
        self,
        db_session: AsyncSession,
        world: _World,
        ticket_factory: TicketFactory,
        ticket_access_grant_factory: Callable[..., Awaitable[TicketAccessGrant]],
        ticket_package_factory: Callable[..., Awaitable[TicketPackage]],
        ticket_package_maintainer_factory: Callable[
            ..., Awaitable[TicketPackageMaintainer]
        ],
    ) -> None:
        """Query ownership: deactivation retains explicit grants and
        maintainer rows, so the preview neither counts nor reads them
        (testing-strategy.md, Confidentiality and explicit access grants)."""
        confidential = await ticket_factory(is_confidential=True)
        await ticket_access_grant_factory(
            ticket_id=confidential.id,
            user_id=world.target_id,
            granted_by_id=world.actor_id,
        )
        package = await ticket_package_factory(ticket_id=(await ticket_factory()).id)
        await ticket_package_maintainer_factory(
            ticket_package_id=package.id, user_id=world.target_id
        )

        with StatementRecorder(db_session) as recorder:
            impact = await get_deactivation_impact(
                db_session, world.target_id, acting_user_id=world.actor_id
            )

        assert impact == _WORLD_IMPACT
        assert recorder.statements
        assert not [
            s
            for s in recorder.statements
            if "ticket_access_grant" in s or "ticket_package_maintainer" in s
        ]


# ---------------------------------------------------------------------------
# Advisory consistency, side effects, and re-invocation
# ---------------------------------------------------------------------------


@pytest.fixture
async def identity_world(db_session_factory: Factory) -> AsyncIterator[IdentityWorld]:
    world = IdentityWorld(db_session_factory, await db_session_factory())
    try:
        yield world
    finally:
        await world.cleanup()


async def _commit_resources(world: IdentityWorld, user: User, name: str) -> None:
    """Commit one non-revoked key, one active Session, and one assigned
    `Analysis` Ticket of `user`."""
    # Fictional 64-character hex digest, never a real key hash.
    digest = uuid.uuid4().hex * 2
    world.session.add(
        ApiKey(
            user_id=user.id, key_hash=digest, prefix=f"stl_ak_{digest[:5]}", name=name
        )
    )
    world.session.add(
        Session(user_id=user.id, expires_at=datetime.now(UTC) + timedelta(days=30))
    )
    await world.session.commit()
    await world.ticket(cve_id=None, assignee_id=user.id)


@pytest.mark.integration
class TestAdvisory:
    async def test_no_mutation_audit_event_or_redis_operation(
        self,
        db_session: AsyncSession,
        world: _World,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Side effects and audit, Advisory consistency: no write, row lock,
        pending ORM change, transaction control, audit event, or Redis
        client; nothing is reserved or recorded."""
        audit_before = await _audit_counts(db_session)

        def _no_redis(*args: object, **kwargs: object) -> None:
            raise AssertionError("must not create a Redis client")

        commit_spy = AsyncMock(side_effect=AssertionError("must not commit"))
        rollback_spy = AsyncMock(side_effect=AssertionError("must not roll back"))
        monkeypatch.setattr(db_session, "commit", commit_spy)
        monkeypatch.setattr(db_session, "rollback", rollback_spy)
        monkeypatch.setattr(session_service, "_new_redis_client", _no_redis)
        monkeypatch.setattr(local_auth_service, "_new_redis_client", _no_redis)
        monkeypatch.setattr(redis_asyncio.Redis, "from_url", _no_redis)

        with StatementRecorder(db_session) as recorder:
            impact = await get_deactivation_impact(
                db_session, world.target_id, acting_user_id=world.actor_id
            )

        assert impact == _WORLD_IMPACT
        assert recorder.writes() == []
        assert recorder.row_locks() == []
        assert not db_session.new
        assert not db_session.dirty
        assert not db_session.deleted
        commit_spy.assert_not_called()
        rollback_spy.assert_not_called()
        assert await _audit_counts(db_session) == audit_before

    async def test_resource_created_after_the_preview_is_still_deactivated(
        self,
        db_session: AsyncSession,
        user_factory: UserFactory,
        api_key_factory: ApiKeyFactory,
        session_factory: SessionFactory,
        ticket_factory: TicketFactory,
    ) -> None:
        """Advisory consistency: `deactivate_user()` independently affects
        every in-scope resource present when it executes, including those
        created after the preview; a repeated preview observes the result."""
        target = await user_factory(username="bob.va")
        await api_key_factory(user_id=target.id, name="bob-laptop")
        first = await session_factory(user_id=target.id)
        await ticket_factory(status=TicketStatus.ANALYSIS.value, assignee_id=target.id)

        before = await get_deactivation_impact(
            db_session, target.id, acting_user_id=None
        )
        assert before == DeactivationImpact(
            already_inactive=False,
            is_last_active_admin=False,
            api_keys_count=1,
            sessions_count=1,
            tickets_count=1,
        )

        await api_key_factory(user_id=target.id, name="bob-late")
        second = await session_factory(user_id=target.id)
        await ticket_factory(status=TicketStatus.NEW.value, assignee_id=target.id)

        result = await deactivate_user(
            db_session, target.id, acting_user_id=None, reason=_REASON
        )

        assert result.deactivated is True
        assert sorted(result.invalidated_session_ids) == sorted([first.id, second.id])
        revoked = await db_session.execute(
            select(ApiKey.revoked_at).where(ApiKey.user_id == target.id)
        )
        assert [at is not None for at in revoked.scalars()] == [True, True]
        assigned = await db_session.execute(
            select(func.count())
            .select_from(Ticket)
            .where(Ticket.assignee_id == target.id)
        )
        assert assigned.scalar_one() == 0
        assert (
            await get_deactivation_impact(db_session, target.id, acting_user_id=None)
            == _ZEROED
        )

    async def test_holds_no_row_lock(self, identity_world: IdentityWorld) -> None:
        """Advisory consistency: while the preview's transaction is still
        open, an independent session acquires `FOR UPDATE NOWAIT` on the
        target User and on its assigned Ticket."""
        target = await identity_world.identity_user(manual=[Role.ADMIN])
        ticket = await identity_world.ticket(cve_id=None, assignee_id=target.id)
        preview = await identity_world.open_session()
        probe = await identity_world.open_session()

        with SessionStatementRecorder(preview) as recorder:
            impact = await get_deactivation_impact(
                preview, target.id, acting_user_id=None
            )

        assert impact.tickets_count == 1
        assert preview.in_transaction()
        assert recorder.row_locks() == []
        locked_user = await probe.execute(
            select(User.id).where(User.id == target.id).with_for_update(nowait=True)
        )
        assert locked_user.scalar_one() == target.id
        locked_ticket = await probe.execute(
            select(Ticket.id).where(Ticket.id == ticket.id).with_for_update(nowait=True)
        )
        assert locked_ticket.scalar_one() == ticket.id
        await probe.rollback()
        await preview.rollback()

    async def test_repeated_invocation_observes_committed_changes(
        self, identity_world: IdentityWorld
    ) -> None:
        """Re-invocation: each call in the same open session observes the
        state committed by independent sessions since the previous call,
        including a committed deactivation of the already-loaded target."""
        target = await identity_world.identity_user(manual=[Role.VULNERABILITY_ANALYST])
        preview = await identity_world.open_session()

        first = await get_deactivation_impact(preview, target.id, acting_user_id=None)

        await _commit_resources(identity_world, target, "bob-laptop")
        second = await get_deactivation_impact(preview, target.id, acting_user_id=None)

        writer = await identity_world.open_session()
        deactivation = await deactivate(writer, target, _REASON)
        await writer.commit()
        third = await get_deactivation_impact(preview, target.id, acting_user_id=None)
        await preview.rollback()

        assert first == DeactivationImpact(
            already_inactive=False,
            is_last_active_admin=False,
            api_keys_count=0,
            sessions_count=0,
            tickets_count=0,
        )
        assert second == DeactivationImpact(
            already_inactive=False,
            is_last_active_admin=False,
            api_keys_count=1,
            sessions_count=1,
            tickets_count=1,
        )
        assert deactivation.deactivated is True
        assert third == _ZEROED


# ---------------------------------------------------------------------------
# Error propagation
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestErrorPropagation:
    async def test_key_count_exception_escapes_unchanged(
        self,
        db_session: AsyncSession,
        world: _World,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Query ownership and Exceptions: the API-key count is delegated to
        `count_non_revoked_keys()`, whose exception propagates unchanged."""
        audit_before = await _audit_counts(db_session)
        error = _InjectedError("fictional key count failure")
        spy = AsyncMock(side_effect=error)
        monkeypatch.setattr(user_service, "count_non_revoked_keys", spy)

        with pytest.raises(_InjectedError) as raised:
            await get_deactivation_impact(
                db_session, world.target_id, acting_user_id=world.actor_id
            )

        assert raised.value is error
        spy.assert_awaited_once_with(db_session, world.target_id)
        assert await _audit_counts(db_session) == audit_before

    async def test_database_error_escapes_unchanged(
        self,
        db_session: AsyncSession,
        world: _World,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Exceptions: a database error of the Session observation
        propagates unchanged."""
        audit_before = await _audit_counts(db_session)
        error = OperationalError(
            "SELECT count(*) FROM session", {}, Exception("fictional connection loss")
        )
        original = db_session.execute
        failed: list[bool] = []

        async def _execute(statement: Any, *args: Any, **kwargs: Any) -> Any:
            if Session.__table__ in statement.get_final_froms():
                failed.append(True)
                raise error
            return await original(statement, *args, **kwargs)

        monkeypatch.setattr(db_session, "execute", _execute)

        with pytest.raises(OperationalError) as raised:
            await get_deactivation_impact(
                db_session, world.target_id, acting_user_id=world.actor_id
            )

        monkeypatch.undo()
        assert raised.value is error
        assert failed == [True]
        assert await _audit_counts(db_session) == audit_before
