"""Single-session tests for `deactivate_user()`
(backend/app/services/user_service.py).

See docs/features/identity/user-service.md (`deactivate_user()` including
Audit attribution, Mutation Result Types, External Active Status Ownership,
Inactive User Management Principle — Deactivation and management,
`reactivate_user()` — Explicitly NOT restored, Transactionality, Service
Exceptions) for the contract under test;
docs/features/identity/api-key-service.md (`revoke_all_user_keys()`) and
docs/features/identity/authentication.md (Session invalidation, Deactivation
ordering) for the delegated steps; docs/features/identity/identity-audit-log.md
(IdentityAuditEventType Enum, detail JSONB Schema Contract, Testing
Requirements) and docs/features/tickets/ticket-audit-log.md (Canonical
Automatic Comment Vocabulary, Canonical Mutation and No-Event Matrix, Testing
Requirements 12 and 19) for the exact events; and
docs/features/platform/testing-strategy.md (User Lifecycle and Management,
"Transactions and audit" and "Deactivation action"; Audit Trail Testing) for
the mandatory scenarios. Independent-session concurrency and the post-commit
purge workflow are covered elsewhere.

Expected values are transcribed from the specifications; nothing here
computes an expectation with the module under test.
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock

import pytest
import redis.asyncio as redis_asyncio
from sqlalchemy import event, inspect, select, update
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Mapper

from app.core.enums import IdentityAuditEventType, TicketStatus
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
from app.services.identity_audit_log import IdentityAuditLog
from app.services.session_service import invalidate_user_sessions
from app.services.ticket_audit_log import TicketAuditLog
from app.services.user_service import (
    ExternalUserStatusReadOnlyError,
    SelfDeactivationError,
    UserServiceError,
    deactivate_user,
    reactivate_user,
)
from tests.support.database import rollback_test_scope
from tests.support.ticket_mutations import StatementRecorder

UserFactory = Callable[..., Awaitable[User]]
UserRoleFactory = Callable[..., Awaitable[UserRole]]
ApiKeyFactory = Callable[..., Awaitable[ApiKey]]
SessionFactory = Callable[..., Awaitable[Session]]
TicketFactory = Callable[..., Awaitable[Ticket]]

_REASON = "fictional offboarding"
# ticket-audit-log.md, Canonical Automatic Comment Vocabulary (System
# unassignment) with the canonical reason `user deactivated`.
_DEACTIVATION_COMMENT = "Unassigned from bob.va: user deactivated"
# Stored `UserRole.role` value (docs/data-model.md, Role Enum).
_VA = "Vulnerability Analyst"


class _InjectedError(Exception):
    """A deterministic failure injected into one composed step."""


def _ordered_ids(count: int) -> list[uuid.UUID]:
    """`count` fresh UUIDs in ascending order."""
    return sorted(uuid.uuid4() for _ in range(count))


def _bound(params: Any) -> list[Any]:
    """The bound values of one recorded statement."""
    return list(params.values() if isinstance(params, dict) else params)


@dataclass(frozen=True)
class _World:
    """The persisted fixture state of one deactivation scenario."""

    admin_id: uuid.UUID
    target_id: uuid.UUID
    manager_id: uuid.UUID
    other_id: uuid.UUID
    # The target's non-revoked keys, ascending: [expired, unexpired].
    key_ids: list[uuid.UUID]
    revoked_key_id: uuid.UUID
    revoked_key_at: datetime
    other_key_id: uuid.UUID
    active_session_ids: set[uuid.UUID]
    inactive_session_id: uuid.UUID
    other_session_id: uuid.UUID
    # Ascending: Analyzed, Resolved, New, Ignored, Analysis, Duplicated.
    ticket_ids: list[uuid.UUID]
    other_ticket_id: uuid.UUID

    @property
    def all_ticket_ids(self) -> list[uuid.UUID]:
        return [*self.ticket_ids, self.other_ticket_id]

    @property
    def all_session_ids(self) -> list[uuid.UUID]:
        return [
            *self.active_session_ids,
            self.inactive_session_id,
            self.other_session_id,
        ]


@pytest.fixture
async def world(
    user_factory: UserFactory,
    user_role_factory: UserRoleFactory,
    api_key_factory: ApiKeyFactory,
    session_factory: SessionFactory,
    ticket_factory: TicketFactory,
) -> _World:
    admin = await user_factory(username="alice.admin")
    manager = await user_factory(username="dave.manager")
    target = await user_factory(username="bob.va", manager_id=manager.id)
    other = await user_factory(username="carol.va")
    await user_role_factory(user_id=target.id, role=_VA)

    now = datetime.now(UTC)
    key_ids = _ordered_ids(2)
    # Created out of id order so that creation order cannot pass for the
    # documented `id` order.
    await api_key_factory(id=key_ids[1], user_id=target.id, name="bob-laptop")
    await api_key_factory(
        id=key_ids[0],
        user_id=target.id,
        name="bob-ci-expired",
        expires_at=now - timedelta(days=1),
    )
    revoked_at = now - timedelta(days=2)
    revoked = await api_key_factory(
        user_id=target.id,
        name="bob-old",
        revoked_at=revoked_at,
        revoked_by=admin.id,
    )
    other_key = await api_key_factory(user_id=other.id, name="carol-laptop")

    first_session = await session_factory(user_id=target.id)
    second_session = await session_factory(user_id=target.id)
    inactive_session = await session_factory(user_id=target.id, is_active=False)
    other_session = await session_factory(user_id=other.id)

    ticket_ids = _ordered_ids(6)
    statuses = [
        TicketStatus.ANALYZED,
        TicketStatus.RESOLVED,
        TicketStatus.NEW,
        TicketStatus.IGNORED,
        TicketStatus.ANALYSIS,
        TicketStatus.DUPLICATED,
    ]
    for index in reversed(range(6)):
        await ticket_factory(
            id=ticket_ids[index], status=statuses[index].value, assignee_id=target.id
        )
    other_ticket = await ticket_factory(
        status=TicketStatus.ANALYSIS.value, assignee_id=other.id
    )

    return _World(
        admin_id=admin.id,
        target_id=target.id,
        manager_id=manager.id,
        other_id=other.id,
        key_ids=key_ids,
        revoked_key_id=revoked.id,
        revoked_key_at=revoked_at,
        other_key_id=other_key.id,
        active_session_ids={first_session.id, second_session.id},
        inactive_session_id=inactive_session.id,
        other_session_id=other_session.id,
        ticket_ids=ticket_ids,
        other_ticket_id=other_ticket.id,
    )


async def _active(db: AsyncSession, user_id: uuid.UUID) -> bool:
    return bool(
        (await db.execute(select(User.active).where(User.id == user_id))).scalar_one()
    )


async def _keys(
    db: AsyncSession, user_ids: list[uuid.UUID]
) -> dict[uuid.UUID, tuple[datetime | None, uuid.UUID | None]]:
    """Current `(revoked_at, revoked_by)` of every key of the Users."""
    rows = await db.execute(
        select(ApiKey.id, ApiKey.revoked_at, ApiKey.revoked_by).where(
            ApiKey.user_id.in_(user_ids)
        )
    )
    return {row.id: (row.revoked_at, row.revoked_by) for row in rows}


async def _sessions(db: AsyncSession, ids: list[uuid.UUID]) -> dict[uuid.UUID, bool]:
    rows = await db.execute(
        select(Session.id, Session.is_active).where(Session.id.in_(ids))
    )
    return {row.id: row.is_active for row in rows}


async def _states(
    db: AsyncSession, ids: list[uuid.UUID]
) -> dict[uuid.UUID, tuple[str, uuid.UUID | None]]:
    rows = await db.execute(
        select(Ticket.id, Ticket.status, Ticket.assignee_id).where(Ticket.id.in_(ids))
    )
    return {row.id: (row.status, row.assignee_id) for row in rows}


IdentityEventRow = tuple[
    str, uuid.UUID | None, uuid.UUID | None, str | None, str | None, Any
]
"""`(event_type, user_id, target_user_id, old_value, new_value, detail)`."""


async def _identity_events(
    db: AsyncSession, target_user_id: uuid.UUID
) -> list[IdentityEventRow]:
    """Every IdentityAuditEvent of the target, in insertion (UUIDv7) order."""
    rows = (
        await db.execute(
            select(IdentityAuditEvent)
            .where(IdentityAuditEvent.target_user_id == target_user_id)
            .order_by(IdentityAuditEvent.id)
        )
    ).scalars()
    return [
        (r.event_type, r.user_id, r.target_user_id, r.old_value, r.new_value, r.detail)
        for r in rows
    ]


TicketEventRow = tuple[
    uuid.UUID, str, uuid.UUID | None, str | None, str | None, str | None, Any
]
"""`(ticket_id, event_type, user_id, old_value, new_value, comment, detail)`."""


async def _ticket_events(
    db: AsyncSession, ids: list[uuid.UUID]
) -> list[TicketEventRow]:
    rows = (
        await db.execute(
            select(TicketAuditEvent)
            .where(TicketAuditEvent.ticket_id.in_(ids))
            .order_by(TicketAuditEvent.id)
        )
    ).scalars()
    return [
        (
            r.ticket_id,
            r.event_type,
            r.user_id,
            r.old_value,
            r.new_value,
            r.comment,
            r.detail,
        )
        for r in rows
    ]


def _revoked_event(
    actor: uuid.UUID | None, target: uuid.UUID, name: str, key_id: uuid.UUID
) -> IdentityEventRow:
    """identity-audit-log.md, `api_key_revoked` (bulk revocation during
    deactivation) and api-key-service.md, `revoke_all_user_keys()` step 4."""
    return (
        "api_key_revoked",
        actor,
        target,
        name,
        None,
        {"key_id": str(key_id), "reason": "user_deactivated"},
    )


def _deactivated_event(
    actor: uuid.UUID | None, target: uuid.UUID, detail: dict[str, str]
) -> IdentityEventRow:
    """user-service.md, `deactivate_user()` step 5."""
    return ("user_deactivated", actor, target, "active", "inactive", detail)


def _clear_event(ticket_id: uuid.UUID) -> TicketEventRow:
    """user-service.md, Private Helpers, `_unassign_active_tickets()` step 4."""
    return (ticket_id, "assignment", None, "bob.va", None, _DEACTIVATION_COMMENT, None)


async def _snapshot(db: AsyncSession, w: _World) -> tuple[Any, ...]:
    """Every state a deactivation could change, read from the database."""
    return (
        await _active(db, w.target_id),
        await _keys(db, [w.target_id, w.other_id]),
        await _sessions(db, w.all_session_ids),
        await _states(db, w.all_ticket_ids),
        await _identity_events(db, w.target_id),
        await _ticket_events(db, w.all_ticket_ids),
    )


# ---------------------------------------------------------------------------
# Effective deactivation
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestDeactivateUserEffective:
    async def test_result_and_profile(
        self, db_session: AsyncSession, world: _World
    ) -> None:
        """user-service.md, Mutation Result Types and `deactivate_user()`
        step 6: `deactivated = true` and the profile with roles and manager
        loaded."""
        result = await deactivate_user(
            db_session, world.target_id, acting_user_id=world.admin_id, reason=_REASON
        )

        assert result.deactivated is True
        assert result.user.id == world.target_id
        assert result.user.active is False
        unloaded = inspect(result.user).unloaded
        assert "roles" not in unloaded
        assert "manager" not in unloaded
        assert [(r.role, r.group_name) for r in result.user.roles] == [(_VA, "_manual")]
        assert result.user.manager is not None
        assert result.user.manager.id == world.manager_id
        assert await _active(db_session, world.target_id) is False

    async def test_invalidates_exactly_the_targets_active_sessions(
        self, db_session: AsyncSession, world: _World
    ) -> None:
        """user-service.md, `deactivate_user()` step 2 and authentication.md,
        `invalidate_user_sessions()`."""
        result = await deactivate_user(
            db_session, world.target_id, acting_user_id=world.admin_id, reason=_REASON
        )

        assert len(result.invalidated_session_ids) == 2
        assert set(result.invalidated_session_ids) == world.active_session_ids
        expected = dict.fromkeys(world.active_session_ids, False)
        expected[world.inactive_session_id] = False
        expected[world.other_session_id] = True
        assert await _sessions(db_session, world.all_session_ids) == expected

    async def test_revokes_every_non_revoked_key_including_expired(
        self, db_session: AsyncSession, world: _World
    ) -> None:
        """user-service.md, `deactivate_user()` step 1 and api-key-service.md,
        `revoke_all_user_keys()`: one shared `revoked_at`, `revoked_by` is
        the actor; an already-revoked key and another User's key are
        untouched."""
        await deactivate_user(
            db_session, world.target_id, acting_user_id=world.admin_id, reason=_REASON
        )

        keys = await _keys(db_session, [world.target_id, world.other_id])
        expired_at, expired_by = keys[world.key_ids[0]]
        unexpired_at, unexpired_by = keys[world.key_ids[1]]
        assert expired_at is not None
        assert expired_at == unexpired_at
        assert expired_by == unexpired_by == world.admin_id
        assert keys[world.revoked_key_id] == (world.revoked_key_at, world.admin_id)
        assert keys[world.other_key_id] == (None, None)

    async def test_clears_only_active_status_assignments(
        self, db_session: AsyncSession, world: _World
    ) -> None:
        """user-service.md, `deactivate_user()` step 4 and Private Helpers:
        one system `assignment` event per cleared Ticket in ascending UUID
        order, status unchanged; the caller's reason never reaches a Ticket
        comment."""
        ids = world.ticket_ids

        await deactivate_user(
            db_session, world.target_id, acting_user_id=world.admin_id, reason=_REASON
        )

        assert await _states(db_session, world.all_ticket_ids) == {
            ids[0]: ("Analyzed", None),
            ids[1]: ("Resolved", world.target_id),
            ids[2]: ("New", None),
            ids[3]: ("Ignored", world.target_id),
            ids[4]: ("Analysis", None),
            ids[5]: ("Duplicated", world.target_id),
            world.other_ticket_id: ("Analysis", world.other_id),
        }
        events = await _ticket_events(db_session, world.all_ticket_ids)
        assert events == [
            _clear_event(ids[0]),
            _clear_event(ids[2]),
            _clear_event(ids[4]),
        ]
        assert all(_REASON not in (row[5] or "") for row in events)

    async def test_identity_events(
        self, db_session: AsyncSession, world: _World
    ) -> None:
        """identity-audit-log.md, `api_key_revoked` and `user_deactivated`:
        one revocation event per newly revoked key in key `id` order, none
        for the already-revoked key, then exactly one `user_deactivated`."""
        await deactivate_user(
            db_session, world.target_id, acting_user_id=world.admin_id, reason=_REASON
        )

        actor, target = world.admin_id, world.target_id
        assert await _identity_events(db_session, target) == [
            _revoked_event(actor, target, "bob-ci-expired", world.key_ids[0]),
            _revoked_event(actor, target, "bob-laptop", world.key_ids[1]),
            _deactivated_event(actor, target, {"reason": _REASON}),
        ]
        assert await _identity_events(db_session, world.other_id) == []

    async def test_composite_audit_insertion_order(
        self, db_session: AsyncSession, world: _World
    ) -> None:
        """user-service.md, `deactivate_user()` composite insertion order:
        `api_key_revoked` events, then Ticket `assignment` events, then
        `user_deactivated`. Both trails use process-monotonic UUIDv7 ids
        assigned at each event's own flush, so the merged id order is the
        insertion order across the two tables."""
        await deactivate_user(
            db_session, world.target_id, acting_user_id=world.admin_id, reason=_REASON
        )

        identity = await db_session.execute(
            select(
                IdentityAuditEvent.id,
                IdentityAuditEvent.event_type,
                IdentityAuditEvent.old_value,
            ).where(IdentityAuditEvent.target_user_id == world.target_id)
        )
        tickets = await db_session.execute(
            select(TicketAuditEvent.id, TicketAuditEvent.ticket_id).where(
                TicketAuditEvent.ticket_id.in_(world.all_ticket_ids)
            )
        )
        merged: list[tuple[uuid.UUID, tuple[str, object]]] = [
            (row.id, (row.event_type, row.old_value)) for row in identity
        ] + [(row.id, ("assignment", row.ticket_id)) for row in tickets]
        ids = world.ticket_ids

        assert [label for _, label in sorted(merged)] == [
            ("api_key_revoked", "bob-ci-expired"),
            ("api_key_revoked", "bob-laptop"),
            ("assignment", ids[0]),
            ("assignment", ids[2]),
            ("assignment", ids[4]),
            ("user_deactivated", "active"),
        ]

    async def test_target_without_resources_creates_only_user_deactivated(
        self, db_session: AsyncSession, user_factory: UserFactory
    ) -> None:
        admin = await user_factory(username="alice.admin")
        target = await user_factory(username="bob.va")

        result = await deactivate_user(
            db_session, target.id, acting_user_id=admin.id, reason=_REASON
        )

        assert result.deactivated is True
        assert result.invalidated_session_ids == []
        assert await _identity_events(db_session, target.id) == [
            _deactivated_event(admin.id, target.id, {"reason": _REASON})
        ]


# ---------------------------------------------------------------------------
# Guard and no-op ordering
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestDeactivateUserGuards:
    async def test_unknown_user_raises_not_found_without_writes(
        self, db_session: AsyncSession, user_factory: UserFactory
    ) -> None:
        # Existing setup starts the test savepoint before recording.
        admin = await user_factory(username="alice.admin")
        missing = uuid.uuid4()

        with (
            StatementRecorder(db_session) as recorder,
            pytest.raises(UserNotFoundError),
        ):
            await deactivate_user(
                db_session, missing, acting_user_id=admin.id, reason=_REASON
            )

        assert recorder.writes() == []
        assert await _identity_events(db_session, missing) == []

    @pytest.mark.parametrize(
        ("external", "actor"),
        [
            (False, "admin"),
            (False, None),
            (True, "admin"),
            (True, None),
            (False, "self"),
        ],
        ids=[
            "local-admin",
            "local-system",
            "external-admin",
            "external-system",
            "local-self",
        ],
    )
    async def test_already_inactive_target_is_a_no_op_before_any_guard(
        self,
        db_session: AsyncSession,
        user_factory: UserFactory,
        api_key_factory: ApiKeyFactory,
        session_factory: SessionFactory,
        ticket_factory: TicketFactory,
        external: bool,
        actor: str | None,
    ) -> None:
        """user-service.md, `deactivate_user()` Guard and no-op ordering
        step 2: an already-inactive target, local or external, is a no-op
        evaluated before the external and self guards, whose leftover
        state is untouched."""
        admin = await user_factory(username="alice.admin")
        manager = await user_factory(username="dave.manager")
        overrides: dict[str, Any] = {"external_id": uuid.uuid4()} if external else {}
        target = await user_factory(
            username="bob.va", active=False, manager_id=manager.id, **overrides
        )
        key = await api_key_factory(user_id=target.id, name="bob-leftover")
        session = await session_factory(user_id=target.id)
        ticket = await ticket_factory(
            status=TicketStatus.ANALYSIS.value, assignee_id=target.id
        )
        acting = {"admin": admin.id, "self": target.id, None: None}[actor]

        with StatementRecorder(db_session) as recorder:
            result = await deactivate_user(
                db_session, target.id, acting_user_id=acting, reason=_REASON
            )

        assert result.deactivated is False
        assert result.invalidated_session_ids == []
        assert result.user.id == target.id
        assert result.user.active is False
        unloaded = inspect(result.user).unloaded
        assert "roles" not in unloaded
        assert "manager" not in unloaded
        assert recorder.writes() == []
        assert await _keys(db_session, [target.id]) == {key.id: (None, None)}
        assert await _sessions(db_session, [session.id]) == {session.id: True}
        assert await _states(db_session, [ticket.id]) == {
            ticket.id: ("Analysis", target.id)
        }
        assert await _identity_events(db_session, target.id) == []
        assert await _ticket_events(db_session, [ticket.id]) == []

    @pytest.mark.parametrize(
        ("external", "self_target", "error"),
        [
            (True, False, ExternalUserStatusReadOnlyError),
            (True, True, ExternalUserStatusReadOnlyError),
            (False, True, SelfDeactivationError),
        ],
        ids=["external", "external-self", "local-self"],
    )
    async def test_rejected_active_target_has_no_effect(
        self,
        db_session: AsyncSession,
        user_factory: UserFactory,
        api_key_factory: ApiKeyFactory,
        session_factory: SessionFactory,
        ticket_factory: TicketFactory,
        external: bool,
        self_target: bool,
        error: type[UserServiceError],
    ) -> None:
        """user-service.md, `deactivate_user()` Guard and no-op ordering
        steps 3-4: the external guard precedes the self guard, and a
        rejection performs no mutation and creates no event."""
        admin = await user_factory(username="alice.admin")
        overrides: dict[str, Any] = {"external_id": uuid.uuid4()} if external else {}
        target = await user_factory(username="bob.va", **overrides)
        key = await api_key_factory(user_id=target.id, name="bob-laptop")
        session = await session_factory(user_id=target.id)
        ticket = await ticket_factory(
            status=TicketStatus.ANALYSIS.value, assignee_id=target.id
        )
        acting = target.id if self_target else admin.id

        with StatementRecorder(db_session) as recorder, pytest.raises(error):
            await deactivate_user(
                db_session, target.id, acting_user_id=acting, reason=_REASON
            )

        assert recorder.writes() == []
        assert await _active(db_session, target.id) is True
        assert await _keys(db_session, [target.id]) == {key.id: (None, None)}
        assert await _sessions(db_session, [session.id]) == {session.id: True}
        assert await _states(db_session, [ticket.id]) == {
            ticket.id: ("Analysis", target.id)
        }
        assert await _identity_events(db_session, target.id) == []
        assert await _ticket_events(db_session, [ticket.id]) == []

    async def test_guards_use_the_locked_current_row_not_a_stale_read(
        self, db_session: AsyncSession, user_factory: UserFactory
    ) -> None:
        """user-service.md, `deactivate_user()`: no pre-read is
        authoritative. The identity map still holds `active = True` while
        the row is already inactive; the locked-current row decides."""
        admin = await user_factory(username="alice.admin")
        target = await user_factory(username="bob.va")
        await db_session.execute(
            update(User)
            .where(User.id == target.id)
            .values(active=False)
            .execution_options(synchronize_session=False)
        )
        assert target.active is True

        result = await deactivate_user(
            db_session, target.id, acting_user_id=admin.id, reason=_REASON
        )

        assert result.deactivated is False
        assert result.invalidated_session_ids == []
        assert result.user.active is False
        assert await _identity_events(db_session, target.id) == []

    async def test_first_database_statement_is_the_user_lock(
        self, db_session: AsyncSession, world: _World
    ) -> None:
        """user-service.md, `deactivate_user()`: `FOR NO KEY UPDATE` on the
        target User is the first database operation."""
        with StatementRecorder(db_session) as recorder:
            await deactivate_user(
                db_session,
                world.target_id,
                acting_user_id=world.admin_id,
                reason=_REASON,
            )

        first = recorder.statements[0]
        assert 'FROM "user"' in first
        assert "FOR NO KEY UPDATE" in first
        assert _bound(recorder.parameters[0]) == [world.target_id]


@pytest.mark.unit
class TestSelfDeactivationError:
    def test_self_deactivation_error_carries_fixed_message(self) -> None:
        """user-service.md, Service Exceptions: `SelfDeactivationError`
        inherits `UserServiceError`; its message never echoes input."""
        error = SelfDeactivationError()
        assert isinstance(error, UserServiceError)
        assert str(error) == "Cannot deactivate your own account."


# ---------------------------------------------------------------------------
# Audit attribution
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestDeactivateUserAttribution:
    @pytest.mark.parametrize(
        ("external", "system", "reason", "detail"),
        [
            (False, False, _REASON, {"reason": _REASON}),
            (False, True, _REASON, {"reason": _REASON}),
            (
                True,
                True,
                "external_sync_missing",
                {"reason": "external_sync_missing", "source": "external_sync"},
            ),
            (
                False,
                True,
                "external_sync_missing",
                {"reason": "external_sync_missing"},
            ),
        ],
        ids=[
            "actor-local",
            "system-local",
            "system-external",
            "reason-never-derives-source",
        ],
    )
    async def test_detail_source_derives_from_actor_and_target_only(
        self,
        db_session: AsyncSession,
        user_factory: UserFactory,
        api_key_factory: ApiKeyFactory,
        ticket_factory: TicketFactory,
        external: bool,
        system: bool,
        reason: str,
        detail: dict[str, str],
    ) -> None:
        """user-service.md, `deactivate_user()` Audit attribution: `source =
        "external_sync"` exactly for actor NULL with an external target.
        The actor is threaded into `revoked_by` and every Identity event,
        while the Ticket comment keeps the canonical reason. An actor NULL
        is never a self-target, so the self guard cannot apply."""
        admin = await user_factory(username="alice.admin")
        overrides: dict[str, Any] = {"external_id": uuid.uuid4()} if external else {}
        target = await user_factory(username="bob.va", **overrides)
        key = await api_key_factory(user_id=target.id, name="bob-laptop")
        ticket = await ticket_factory(
            status=TicketStatus.ANALYSIS.value, assignee_id=target.id
        )
        actor = None if system else admin.id

        result = await deactivate_user(
            db_session, target.id, acting_user_id=actor, reason=reason
        )

        assert result.deactivated is True
        revoked_at, revoked_by = (await _keys(db_session, [target.id]))[key.id]
        assert revoked_at is not None
        assert revoked_by == actor
        assert await _identity_events(db_session, target.id) == [
            _revoked_event(actor, target.id, "bob-laptop", key.id),
            _deactivated_event(actor, target.id, detail),
        ]
        assert await _ticket_events(db_session, [ticket.id]) == [
            _clear_event(ticket.id)
        ]


# ---------------------------------------------------------------------------
# Rollback of every composed step
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestDeactivateUserRollback:
    """testing-strategy.md, User Lifecycle and Management: `deactivate_user`
    rollback leaves no partial User, API-key, Session, Ticket,
    TicketAuditEvent, or IdentityAuditEvent mutation when any composed step
    fails. Each test fails one step after earlier steps have flushed, lets
    the exception escape the caller-owned scope, and compares the complete
    state with the pre-call snapshot."""

    async def _assert_full_rollback(
        self, db: AsyncSession, w: _World, before: tuple[Any, ...]
    ) -> None:
        assert before[0] is True
        assert before[4] == []
        assert before[5] == []
        assert await _snapshot(db, w) == before

    async def _run(self, db: AsyncSession, w: _World) -> None:
        with pytest.raises(_InjectedError):
            async with rollback_test_scope(db):
                await deactivate_user(
                    db, w.target_id, acting_user_id=w.admin_id, reason=_REASON
                )

    async def test_api_key_revocation_audit_failure(
        self,
        db_session: AsyncSession,
        world: _World,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        before = await _snapshot(db_session, world)
        original = IdentityAuditLog.log_event
        revocations = 0

        async def _fail_second_revocation(*args: Any, **kwargs: Any) -> None:
            # The keys are flushed and the first event is inserted before
            # the second event fails.
            nonlocal revocations
            if kwargs["event_type"] is IdentityAuditEventType.API_KEY_REVOKED:
                revocations += 1
                if revocations == 2:
                    raise _InjectedError
            await original(*args, **kwargs)

        monkeypatch.setattr(IdentityAuditLog, "log_event", _fail_second_revocation)

        await self._run(db_session, world)

        assert revocations == 2
        await self._assert_full_rollback(db_session, world, before)

    async def test_session_invalidation_failure(
        self,
        db_session: AsyncSession,
        world: _World,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        before = await _snapshot(db_session, world)
        invalidated: list[uuid.UUID] = []

        async def _fail_after_invalidating(
            *args: Any, **kwargs: Any
        ) -> list[uuid.UUID]:
            invalidated.extend(await invalidate_user_sessions(*args, **kwargs))
            raise _InjectedError

        monkeypatch.setattr(
            user_service, "invalidate_user_sessions", _fail_after_invalidating
        )

        await self._run(db_session, world)

        assert set(invalidated) == world.active_session_ids
        await self._assert_full_rollback(db_session, world, before)

    async def test_user_active_write_failure(
        self, db_session: AsyncSession, world: _World
    ) -> None:
        """The flush of the pending `User.active` change fails; it is the
        autoflush before the first Ticket query, after the keys and Sessions
        were written."""
        before = await _snapshot(db_session, world)
        attempts: list[bool] = []

        def _fail_active_write(
            mapper: Mapper[User], connection: Connection, target: User
        ) -> None:
            if target.id == world.target_id:
                attempts.append(inspect(target).attrs.active.history.has_changes())
                raise _InjectedError

        event.listen(User, "before_update", _fail_active_write)
        try:
            await self._run(db_session, world)
        finally:
            event.remove(User, "before_update", _fail_active_write)

        assert attempts == [True]
        await self._assert_full_rollback(db_session, world, before)

    async def test_ticket_audit_failure(
        self,
        db_session: AsyncSession,
        world: _World,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        before = await _snapshot(db_session, world)
        original = TicketAuditLog.log_event
        calls = 0

        async def _fail_second(*args: Any, **kwargs: Any) -> None:
            # The first Ticket clear and its event succeed; the second
            # event fails, so a partial batch exists when it propagates.
            nonlocal calls
            calls += 1
            if calls == 2:
                raise _InjectedError
            await original(*args, **kwargs)

        monkeypatch.setattr(TicketAuditLog, "log_event", _fail_second)

        await self._run(db_session, world)

        assert calls == 2
        await self._assert_full_rollback(db_session, world, before)

    async def test_user_deactivated_insertion_failure(
        self,
        db_session: AsyncSession,
        world: _World,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        before = await _snapshot(db_session, world)
        original = IdentityAuditLog.log_event
        reached: list[IdentityAuditEventType] = []

        async def _fail_user_deactivated(*args: Any, **kwargs: Any) -> None:
            reached.append(kwargs["event_type"])
            if kwargs["event_type"] is IdentityAuditEventType.USER_DEACTIVATED:
                raise _InjectedError
            await original(*args, **kwargs)

        monkeypatch.setattr(IdentityAuditLog, "log_event", _fail_user_deactivated)

        await self._run(db_session, world)

        assert reached[-1] is IdentityAuditEventType.USER_DEACTIVATED
        await self._assert_full_rollback(db_session, world, before)

    async def test_final_flush_failure(
        self,
        db_session: AsyncSession,
        world: _World,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The flush after `user_deactivated` was inserted fails, with every
        mutation and event already written."""
        before = await _snapshot(db_session, world)
        original_log = IdentityAuditLog.log_event
        original_flush = db_session.flush
        armed = False
        failed = False

        async def _arm_after_user_deactivated(*args: Any, **kwargs: Any) -> None:
            nonlocal armed
            await original_log(*args, **kwargs)
            if kwargs["event_type"] is IdentityAuditEventType.USER_DEACTIVATED:
                armed = True

        async def _flush(*args: Any, **kwargs: Any) -> None:
            nonlocal armed, failed
            if armed:
                armed = False
                failed = True
                raise _InjectedError
            await original_flush(*args, **kwargs)

        monkeypatch.setattr(IdentityAuditLog, "log_event", _arm_after_user_deactivated)
        monkeypatch.setattr(db_session, "flush", _flush)

        await self._run(db_session, world)

        assert failed is True
        await self._assert_full_rollback(db_session, world, before)


# ---------------------------------------------------------------------------
# Transaction ownership and re-invocation
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestDeactivateUserTransactionality:
    async def test_flushes_without_commit_rollback_or_redis_io(
        self,
        db_session: AsyncSession,
        world: _World,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """user-service.md, Transaction Ownership and `deactivate_user()`
        post-commit phase: the service flushes, never commits or rolls
        back, and performs no Redis I/O."""
        commit_spy = AsyncMock(side_effect=AssertionError("must not commit"))
        rollback_spy = AsyncMock(side_effect=AssertionError("must not roll back"))
        redis_spy = AsyncMock(side_effect=AssertionError("must not purge"))

        def _no_redis(*args: object, **kwargs: object) -> None:
            raise AssertionError("must not create a Redis client")

        monkeypatch.setattr(db_session, "commit", commit_spy)
        monkeypatch.setattr(db_session, "rollback", rollback_spy)
        monkeypatch.setattr(session_service, "purge_session_cache", redis_spy)
        monkeypatch.setattr(session_service, "_new_redis_client", _no_redis)
        monkeypatch.setattr(local_auth_service, "_new_redis_client", _no_redis)
        monkeypatch.setattr(redis_asyncio.Redis, "from_url", _no_redis)

        result = await deactivate_user(
            db_session, world.target_id, acting_user_id=world.admin_id, reason=_REASON
        )

        assert result.deactivated is True
        commit_spy.assert_not_called()
        rollback_spy.assert_not_called()
        redis_spy.assert_not_called()
        assert not db_session.new
        assert not db_session.dirty
        assert not db_session.deleted
        assert len(await _identity_events(db_session, world.target_id)) == 3
        assert len(await _ticket_events(db_session, world.all_ticket_ids)) == 3

    async def test_repeated_invocation_is_a_no_op(
        self, db_session: AsyncSession, world: _World
    ) -> None:
        """user-service.md, `deactivate_user()` Re-invocation."""
        await deactivate_user(
            db_session, world.target_id, acting_user_id=world.admin_id, reason=_REASON
        )
        after_first = await _snapshot(db_session, world)

        with StatementRecorder(db_session) as recorder:
            again = await deactivate_user(
                db_session,
                world.target_id,
                acting_user_id=world.admin_id,
                reason=_REASON,
            )

        assert again.deactivated is False
        assert again.invalidated_session_ids == []
        assert recorder.writes() == []
        assert await _snapshot(db_session, world) == after_first


# ---------------------------------------------------------------------------
# Retained relationships and reactivation
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestDeactivateUserRetention:
    async def test_grants_and_maintainers_survive_and_reactivation_restores_nothing(
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
        """user-service.md, Inactive User Management Principle — Deactivation
        and management, `deactivate_user()` database phase, and
        `reactivate_user()` — Explicitly NOT restored; ticket-audit-log.md,
        Canonical Mutation and No-Event Matrix ("User deactivation or
        reactivation with retained Ticket grants") and Testing Requirement
        12."""
        confidential = await ticket_factory(is_confidential=True)
        await ticket_access_grant_factory(
            ticket_id=confidential.id,
            user_id=world.target_id,
            granted_by_id=world.admin_id,
        )
        maintained = await ticket_factory()
        package = await ticket_package_factory(ticket_id=maintained.id)
        await ticket_package_maintainer_factory(
            ticket_package_id=package.id, user_id=world.target_id
        )
        relationship_tickets = [confidential.id, maintained.id]
        no_event_types = (
            "access_grant_added",
            "access_grant_removed",
            "package_maintainer_added",
        )

        async def _retained() -> tuple[list[Any], list[Any]]:
            grants = await db_session.execute(
                select(
                    TicketAccessGrant.ticket_id,
                    TicketAccessGrant.user_id,
                    TicketAccessGrant.granted_by_id,
                    TicketAccessGrant.granted_at,
                ).where(TicketAccessGrant.user_id == world.target_id)
            )
            maintainers = await db_session.execute(
                select(
                    TicketPackageMaintainer.id,
                    TicketPackageMaintainer.ticket_package_id,
                    TicketPackageMaintainer.user_id,
                    TicketPackageMaintainer.created_at,
                ).where(TicketPackageMaintainer.user_id == world.target_id)
            )
            return [tuple(r) for r in grants], [tuple(r) for r in maintainers]

        async def _relationship_events() -> list[str]:
            rows = await db_session.execute(
                select(TicketAuditEvent.event_type).where(
                    TicketAuditEvent.event_type.in_(no_event_types)
                )
            )
            return list(rows.scalars())

        retained = await _retained()
        assert len(retained[0]) == 1
        assert len(retained[1]) == 1
        assert await _relationship_events() == []

        await deactivate_user(
            db_session, world.target_id, acting_user_id=world.admin_id, reason=_REASON
        )

        assert await _retained() == retained
        assert await _relationship_events() == []
        assert await _ticket_events(db_session, relationship_tickets) == []
        after_deactivation = await _snapshot(db_session, world)

        reactivated = await reactivate_user(
            db_session, world.target_id, acting_user_id=None
        )

        assert reactivated.reactivated is True
        assert await _active(db_session, world.target_id) is True
        # Keys stay revoked, Sessions inactive, and cleared assignments NULL.
        _, keys, sessions, states, identity, tickets = after_deactivation
        assert await _keys(db_session, [world.target_id, world.other_id]) == keys
        assert all(
            keys[key_id][0] is not None
            for key_id in (*world.key_ids, world.revoked_key_id)
        )
        assert await _sessions(db_session, world.all_session_ids) == sessions
        assert await _states(db_session, world.all_ticket_ids) == states
        assert await _ticket_events(db_session, world.all_ticket_ids) == tickets
        assert await _identity_events(db_session, world.target_id) == [
            *identity,
            ("user_reactivated", None, world.target_id, "inactive", "active", None),
        ]
        assert await _retained() == retained
        assert await _relationship_events() == []
        assert await _ticket_events(db_session, relationship_tickets) == []
