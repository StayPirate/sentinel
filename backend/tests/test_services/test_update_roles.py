"""Single-session tests for `update_roles()`
(backend/app/services/user_service.py).

See docs/features/identity/user-service.md (`update_roles()`, Mutation Result
Types, Transactionality, Service Exceptions) for the contract under test;
docs/features/identity/identity-audit-log.md (Service Contract, Manual role
mutation events; Testing Requirements 1-5) and
docs/features/tickets/ticket-audit-log.md (Canonical Automatic Comment
Vocabulary) for the exact events; and docs/features/platform/testing-strategy.md
(User Lifecycle and Management, Manual role mutation service) for the
mandatory scenarios. Independent-session concurrency is covered elsewhere.

Expected values are transcribed from the specifications; nothing here
computes an expectation with the module under test.
"""

from __future__ import annotations

import re
import uuid
from collections.abc import Awaitable, Callable
from typing import Any
from unittest.mock import AsyncMock

import pytest
from sqlalchemy import inspect, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import Role, TicketStatus
from app.core.exceptions import UserNotFoundError
from app.models.identity_audit_event import IdentityAuditEvent
from app.models.ticket import Ticket
from app.models.ticket_audit_event import TicketAuditEvent
from app.models.user import User
from app.models.user_role import UserRole
from app.services.identity_audit_log import IdentityAuditLog
from app.services.ticket_audit_log import TicketAuditLog
from app.services.user_service import (
    SelfRoleRemovalError,
    UserServiceError,
    update_roles,
)
from tests.support.database import rollback_test_scope
from tests.support.ticket_mutations import StatementRecorder

UserFactory = Callable[..., Awaitable[User]]
UserRoleFactory = Callable[..., Awaitable[UserRole]]
TicketFactory = Callable[..., Awaitable[Ticket]]

_MANUAL = "_manual"
_EXTERNAL_GROUP = "Example Security Group"
# Stored `UserRole.role` values (docs/data-model.md, Role Enum).
_ADMIN = "Admin"
_VA = "Vulnerability Analyst"
_RA = "Restricted Analyst"
_ROLE_LOSS_COMMENT = "Unassigned from bob.va: vulnerability_analyst role removed"
_TICKET_STATEMENT = re.compile(r"\b(?:FROM|JOIN|INTO|UPDATE) ticket\b")


def _ordered_ids(count: int) -> list[uuid.UUID]:
    """`count` fresh Ticket UUIDs in ascending order."""
    return sorted(uuid.uuid4() for _ in range(count))


def _bound(params: Any) -> list[Any]:
    """The bound values of one recorded statement."""
    return list(params.values() if isinstance(params, dict) else params)


def _stored_roles(params: Any) -> list[str]:
    """The stored role values among one statement's bound parameters."""
    return [value for value in _bound(params) if value in (_ADMIN, _VA, _RA)]


async def _origins(db: AsyncSession, user_id: uuid.UUID) -> set[tuple[str, str]]:
    """Every `(role, group_name)` origin of the User, read from the database."""
    rows = await db.execute(
        select(UserRole.role, UserRole.group_name).where(UserRole.user_id == user_id)
    )
    return {(row.role, row.group_name) for row in rows}


async def _identity_events(
    db: AsyncSession, target_user_id: uuid.UUID
) -> list[tuple[str, uuid.UUID | None, uuid.UUID | None, str | None, str | None, Any]]:
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


def _added(
    actor: uuid.UUID | None, target: uuid.UUID, role: str
) -> tuple[str, uuid.UUID | None, uuid.UUID, None, str, None]:
    """identity-audit-log.md, Manual role mutation events: `role_added`."""
    return ("role_added", actor, target, None, role, None)


def _removed(
    actor: uuid.UUID | None, target: uuid.UUID, role: str
) -> tuple[str, uuid.UUID | None, uuid.UUID, str, None, None]:
    """identity-audit-log.md, Manual role mutation events: `role_removed`."""
    return ("role_removed", actor, target, role, None, None)


async def _states(
    db: AsyncSession, ids: list[uuid.UUID]
) -> dict[uuid.UUID, tuple[str, uuid.UUID | None]]:
    rows = await db.execute(
        select(Ticket.id, Ticket.status, Ticket.assignee_id).where(Ticket.id.in_(ids))
    )
    return {row.id: (row.status, row.assignee_id) for row in rows}


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


def _role_loss_event(
    ticket_id: uuid.UUID,
) -> tuple[uuid.UUID, str, None, str, None, str, None]:
    """ticket-audit-log.md, Canonical Automatic Comment Vocabulary (System
    unassignment) with reason `vulnerability_analyst role removed`."""
    return (ticket_id, "assignment", None, "bob.va", None, _ROLE_LOSS_COMMENT, None)


async def _manual_row(db: AsyncSession, user_id: uuid.UUID, role: str) -> UserRole:
    return (
        await db.execute(
            select(UserRole).where(
                UserRole.user_id == user_id,
                UserRole.role == role,
                UserRole.group_name == _MANUAL,
            )
        )
    ).scalar_one()


# ---------------------------------------------------------------------------
# Effective mutations and their Identity events
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestUpdateRolesEffectiveMutation:
    @pytest.mark.parametrize(
        ("role", "stored", "wire"),
        [
            (Role.ADMIN, _ADMIN, "admin"),
            (Role.VULNERABILITY_ANALYST, _VA, "vulnerability_analyst"),
            (Role.RESTRICTED_ANALYST, _RA, "restricted_analyst"),
        ],
        ids=["admin", "vulnerability-analyst", "restricted-analyst"],
    )
    async def test_effective_addition_inserts_manual_row_and_role_added(
        self,
        db_session: AsyncSession,
        user_factory: UserFactory,
        role: Role,
        stored: str,
        wire: str,
    ) -> None:
        """user-service.md, `update_roles()` Business Rule 1 and step 8."""
        admin = await user_factory(username="alice.admin")
        target = await user_factory(username="bob.va")

        result = await update_roles(
            db_session, target.id, add=[role], acting_user_id=admin.id
        )

        assert result.added_roles == [role]
        assert result.removed_roles == []
        row = await _manual_row(db_session, target.id, stored)
        assert row.assigned_by == admin.id
        assert await _origins(db_session, target.id) == {(stored, _MANUAL)}
        assert await _identity_events(db_session, target.id) == [
            _added(admin.id, target.id, wire)
        ]

    @pytest.mark.parametrize(
        ("role", "stored", "wire"),
        [
            (Role.ADMIN, _ADMIN, "admin"),
            (Role.VULNERABILITY_ANALYST, _VA, "vulnerability_analyst"),
            (Role.RESTRICTED_ANALYST, _RA, "restricted_analyst"),
        ],
        ids=["admin", "vulnerability-analyst", "restricted-analyst"],
    )
    async def test_effective_removal_deletes_manual_row_and_role_removed(
        self,
        db_session: AsyncSession,
        user_factory: UserFactory,
        user_role_factory: UserRoleFactory,
        role: Role,
        stored: str,
        wire: str,
    ) -> None:
        admin = await user_factory(username="alice.admin")
        target = await user_factory(username="bob.va")
        await user_role_factory(user_id=target.id, role=stored)

        result = await update_roles(
            db_session, target.id, remove=[role], acting_user_id=admin.id
        )

        assert result.added_roles == []
        assert result.removed_roles == [role]
        assert await _origins(db_session, target.id) == set()
        assert await _identity_events(db_session, target.id) == [
            _removed(admin.id, target.id, wire)
        ]

    async def test_system_actor_records_null_actor_and_assigned_by(
        self,
        db_session: AsyncSession,
        user_factory: UserFactory,
        user_role_factory: UserRoleFactory,
    ) -> None:
        """user-service.md, Acting user convention: CLI/system callers pass
        `None`, recorded as the NULL event actor and `assigned_by`."""
        target = await user_factory(username="bob.va")
        await user_role_factory(user_id=target.id, role=_RA)

        result = await update_roles(
            db_session,
            target.id,
            add=[Role.ADMIN],
            remove=[Role.RESTRICTED_ANALYST],
            acting_user_id=None,
        )

        assert result.added_roles == [Role.ADMIN]
        assert result.removed_roles == [Role.RESTRICTED_ANALYST]
        row = await _manual_row(db_session, target.id, _ADMIN)
        assert row.assigned_by is None
        assert await _identity_events(db_session, target.id) == [
            _added(None, target.id, "admin"),
            _removed(None, target.id, "restricted_analyst"),
        ]

    async def test_inactive_target_behaves_like_an_active_one(
        self,
        db_session: AsyncSession,
        user_factory: UserFactory,
        user_role_factory: UserRoleFactory,
        ticket_factory: TicketFactory,
    ) -> None:
        """user-service.md, Concurrency Considerations, Role modification
        during deactivation: no active-status check."""
        admin = await user_factory(username="alice.admin")
        target = await user_factory(username="bob.va", active=False)
        await user_role_factory(user_id=target.id, role=_VA)
        ticket = await ticket_factory(
            status=TicketStatus.ANALYSIS.value, assignee_id=target.id
        )

        result = await update_roles(
            db_session,
            target.id,
            add=[Role.ADMIN],
            remove=[Role.VULNERABILITY_ANALYST],
            acting_user_id=admin.id,
        )

        assert result.added_roles == [Role.ADMIN]
        assert result.removed_roles == [Role.VULNERABILITY_ANALYST]
        assert result.user.active is False
        assert await _origins(db_session, target.id) == {(_ADMIN, _MANUAL)}
        assert await _identity_events(db_session, target.id) == [
            _added(admin.id, target.id, "admin"),
            _removed(admin.id, target.id, "vulnerability_analyst"),
        ]
        assert await _states(db_session, [ticket.id]) == {ticket.id: ("Analysis", None)}
        assert await _ticket_events(db_session, [ticket.id]) == [
            _role_loss_event(ticket.id)
        ]


# ---------------------------------------------------------------------------
# Normalization, idempotency, and the empty request
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestUpdateRolesNormalization:
    async def test_duplicate_additions_create_one_row_and_one_event(
        self, db_session: AsyncSession, user_factory: UserFactory
    ) -> None:
        target = await user_factory(username="bob.va")

        result = await update_roles(
            db_session,
            target.id,
            add=[Role.ADMIN, Role.ADMIN],
            acting_user_id=None,
        )

        assert result.added_roles == [Role.ADMIN]
        assert await _origins(db_session, target.id) == {(_ADMIN, _MANUAL)}
        assert await _identity_events(db_session, target.id) == [
            _added(None, target.id, "admin")
        ]

    async def test_duplicate_removals_delete_once_and_create_one_event(
        self,
        db_session: AsyncSession,
        user_factory: UserFactory,
        user_role_factory: UserRoleFactory,
    ) -> None:
        target = await user_factory(username="bob.va")
        await user_role_factory(user_id=target.id, role=_RA)

        result = await update_roles(
            db_session,
            target.id,
            remove=[Role.RESTRICTED_ANALYST, Role.RESTRICTED_ANALYST],
            acting_user_id=None,
        )

        assert result.removed_roles == [Role.RESTRICTED_ANALYST]
        assert await _identity_events(db_session, target.id) == [
            _removed(None, target.id, "restricted_analyst")
        ]

    async def test_fully_cancelled_request_is_a_lockless_no_op(
        self,
        db_session: AsyncSession,
        user_factory: UserFactory,
        user_role_factory: UserRoleFactory,
    ) -> None:
        """user-service.md, `update_roles()` Business Rule 4 and step 1:
        the intersection is cancelled before any persistent access, so a
        request with nothing left acquires no lock and writes nothing."""
        target = await user_factory(username="bob.va")
        await user_role_factory(user_id=target.id, role=_ADMIN)

        with StatementRecorder(db_session) as recorder:
            result = await update_roles(
                db_session,
                target.id,
                add=[Role.ADMIN, Role.RESTRICTED_ANALYST],
                remove=[Role.RESTRICTED_ANALYST, Role.ADMIN],
                acting_user_id=None,
            )

        assert recorder.row_locks() == []
        assert recorder.writes() == []
        assert result.added_roles == []
        assert result.removed_roles == []
        assert await _origins(db_session, target.id) == {(_ADMIN, _MANUAL)}
        assert await _identity_events(db_session, target.id) == []

    async def test_partial_overlap_applies_only_the_uncancelled_roles(
        self,
        db_session: AsyncSession,
        user_factory: UserFactory,
        user_role_factory: UserRoleFactory,
    ) -> None:
        target = await user_factory(username="bob.va")
        await user_role_factory(user_id=target.id, role=_RA)

        result = await update_roles(
            db_session,
            target.id,
            add=[Role.ADMIN, Role.RESTRICTED_ANALYST],
            remove=[Role.RESTRICTED_ANALYST],
            acting_user_id=None,
        )

        assert result.added_roles == [Role.ADMIN]
        assert result.removed_roles == []
        assert await _origins(db_session, target.id) == {
            (_ADMIN, _MANUAL),
            (_RA, _MANUAL),
        }
        assert await _identity_events(db_session, target.id) == [
            _added(None, target.id, "admin")
        ]

    async def test_present_addition_and_missing_removal_are_no_ops(
        self,
        db_session: AsyncSession,
        user_factory: UserFactory,
        user_role_factory: UserRoleFactory,
    ) -> None:
        """user-service.md, `update_roles()` Business Rule 3."""
        admin = await user_factory(username="alice.admin")
        target = await user_factory(username="bob.va")
        await user_role_factory(user_id=target.id, role=_ADMIN)

        with StatementRecorder(db_session) as recorder:
            result = await update_roles(
                db_session,
                target.id,
                add=[Role.ADMIN],
                remove=[Role.VULNERABILITY_ANALYST],
                acting_user_id=admin.id,
            )

        assert recorder.writes() == []
        assert result.added_roles == []
        assert result.removed_roles == []
        assert await _origins(db_session, target.id) == {(_ADMIN, _MANUAL)}
        assert await _identity_events(db_session, target.id) == []

    async def test_repeated_invocation_is_an_idempotent_no_op(
        self,
        db_session: AsyncSession,
        user_factory: UserFactory,
        user_role_factory: UserRoleFactory,
        ticket_factory: TicketFactory,
    ) -> None:
        """user-service.md, `update_roles()` Re-invocation."""
        target = await user_factory(username="bob.va")
        await user_role_factory(user_id=target.id, role=_VA)
        ticket = await ticket_factory(
            status=TicketStatus.ANALYSIS.value, assignee_id=target.id
        )
        await update_roles(
            db_session,
            target.id,
            add=[Role.ADMIN],
            remove=[Role.VULNERABILITY_ANALYST],
            acting_user_id=None,
        )

        again = await update_roles(
            db_session,
            target.id,
            add=[Role.ADMIN],
            remove=[Role.VULNERABILITY_ANALYST],
            acting_user_id=None,
        )

        assert again.added_roles == []
        assert again.removed_roles == []
        assert await _origins(db_session, target.id) == {(_ADMIN, _MANUAL)}
        assert len(await _identity_events(db_session, target.id)) == 2
        assert await _ticket_events(db_session, [ticket.id]) == [
            _role_loss_event(ticket.id)
        ]

    @pytest.mark.parametrize(
        ("add", "remove"),
        [(None, None), ([], []), ([], None)],
        ids=["none", "empty-lists", "mixed"],
    )
    async def test_empty_request_returns_profile_without_lock_or_write(
        self,
        db_session: AsyncSession,
        user_factory: UserFactory,
        user_role_factory: UserRoleFactory,
        add: list[Role] | None,
        remove: list[Role] | None,
    ) -> None:
        manager = await user_factory(username="dave.manager")
        target = await user_factory(username="bob.va", manager_id=manager.id)
        await user_role_factory(user_id=target.id, role=_RA)

        with StatementRecorder(db_session) as recorder:
            result = await update_roles(
                db_session, target.id, add=add, remove=remove, acting_user_id=None
            )

        assert recorder.row_locks() == []
        assert recorder.writes() == []
        assert result.added_roles == []
        assert result.removed_roles == []
        assert result.user.id == target.id
        unloaded = inspect(result.user).unloaded
        assert "roles" not in unloaded
        assert "manager" not in unloaded
        assert [(r.role, r.group_name) for r in result.user.roles] == [(_RA, _MANUAL)]
        assert result.user.manager is not None
        assert result.user.manager.id == manager.id
        assert await _identity_events(db_session, target.id) == []

    async def test_empty_request_for_unknown_user_raises_not_found(
        self, db_session: AsyncSession, user_factory: UserFactory
    ) -> None:
        # Existing setup starts the test savepoint before recording.
        await user_factory(username="alice.admin")
        missing = uuid.uuid4()

        with (
            StatementRecorder(db_session) as recorder,
            pytest.raises(UserNotFoundError),
        ):
            await update_roles(db_session, missing, acting_user_id=None)

        assert recorder.row_locks() == []
        assert recorder.writes() == []
        assert await _identity_events(db_session, missing) == []

    async def test_non_empty_request_for_unknown_user_raises_not_found(
        self, db_session: AsyncSession, user_factory: UserFactory
    ) -> None:
        # Existing setup starts the test savepoint before recording.
        await user_factory(username="alice.admin")
        missing = uuid.uuid4()

        with (
            StatementRecorder(db_session) as recorder,
            pytest.raises(UserNotFoundError),
        ):
            await update_roles(
                db_session, missing, add=[Role.ADMIN], acting_user_id=None
            )

        assert recorder.writes() == []
        assert await _identity_events(db_session, missing) == []


# ---------------------------------------------------------------------------
# Locking, statement order, and event order
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestUpdateRolesOrdering:
    async def test_first_persistent_access_is_the_user_lock(
        self,
        db_session: AsyncSession,
        user_factory: UserFactory,
    ) -> None:
        """user-service.md, `update_roles()` step 2."""
        target = await user_factory(username="bob.va")

        with StatementRecorder(db_session) as recorder:
            await update_roles(
                db_session, target.id, add=[Role.ADMIN], acting_user_id=None
            )

        first = recorder.statements[0]
        assert 'FROM "user"' in first
        assert "FOR NO KEY UPDATE" in first
        assert _bound(recorder.parameters[0]) == [target.id]
        assert [s for s in recorder.row_locks() if 'FROM "user"' in s] == [first]

    async def test_added_events_precede_removed_events_in_wire_order(
        self,
        db_session: AsyncSession,
        user_factory: UserFactory,
        user_role_factory: UserRoleFactory,
    ) -> None:
        """user-service.md, `update_roles()` steps 5, 6, 8, and 10: INSERTs,
        DELETEs, `role_added` events, `role_removed` events, and the result
        lists each follow ascending wire-format order, whatever the input
        order."""
        admin = await user_factory(username="alice.admin")
        target = await user_factory(username="bob.va")
        await user_role_factory(user_id=target.id, role=_VA)
        await user_role_factory(user_id=target.id, role=_RA)

        with StatementRecorder(db_session) as recorder:
            first = await update_roles(
                db_session,
                target.id,
                add=[Role.ADMIN],
                remove=[Role.VULNERABILITY_ANALYST, Role.RESTRICTED_ANALYST],
                acting_user_id=admin.id,
            )

        assert first.added_roles == [Role.ADMIN]
        assert first.removed_roles == [
            Role.RESTRICTED_ANALYST,
            Role.VULNERABILITY_ANALYST,
        ]
        deletes = [
            i
            for i, s in enumerate(recorder.statements)
            if s.lstrip().upper().startswith("DELETE FROM USER_ROLE")
        ]
        assert [
            role for i in deletes for role in _stored_roles(recorder.parameters[i])
        ] == [_RA, _VA]

        with StatementRecorder(db_session) as recorder:
            second = await update_roles(
                db_session,
                target.id,
                add=[Role.VULNERABILITY_ANALYST, Role.RESTRICTED_ANALYST],
                remove=[Role.ADMIN],
                acting_user_id=admin.id,
            )

        assert second.added_roles == [
            Role.RESTRICTED_ANALYST,
            Role.VULNERABILITY_ANALYST,
        ]
        assert second.removed_roles == [Role.ADMIN]
        inserts = [
            i
            for i, s in enumerate(recorder.statements)
            if s.lstrip().upper().startswith("INSERT INTO USER_ROLE")
        ]
        assert [
            role for i in inserts for role in _stored_roles(recorder.parameters[i])
        ] == [_RA, _VA]

        assert await _identity_events(db_session, target.id) == [
            _added(admin.id, target.id, "admin"),
            _removed(admin.id, target.id, "restricted_analyst"),
            _removed(admin.id, target.id, "vulnerability_analyst"),
            _added(admin.id, target.id, "restricted_analyst"),
            _added(admin.id, target.id, "vulnerability_analyst"),
            _removed(admin.id, target.id, "admin"),
        ]

    async def test_inserts_precede_deletes(
        self,
        db_session: AsyncSession,
        user_factory: UserFactory,
        user_role_factory: UserRoleFactory,
    ) -> None:
        """user-service.md, `update_roles()` steps 5-6."""
        target = await user_factory(username="bob.va")
        await user_role_factory(user_id=target.id, role=_ADMIN)

        with StatementRecorder(db_session) as recorder:
            await update_roles(
                db_session,
                target.id,
                add=[Role.RESTRICTED_ANALYST],
                remove=[Role.ADMIN],
                acting_user_id=None,
            )

        statements = [s.lstrip().upper() for s in recorder.statements]
        insert = next(
            i for i, s in enumerate(statements) if s.startswith("INSERT INTO USER_ROLE")
        )
        delete = next(
            i for i, s in enumerate(statements) if s.startswith("DELETE FROM USER_ROLE")
        )
        assert insert < delete

    async def test_final_va_loss_clears_tickets_after_the_role_delete(
        self,
        db_session: AsyncSession,
        user_factory: UserFactory,
        user_role_factory: UserRoleFactory,
        ticket_factory: TicketFactory,
    ) -> None:
        """user-service.md, `update_roles()` step 7, Ordering invariant: the
        remaining-origin check and every Ticket lock and clear follow the
        `_manual` VA DELETE."""
        target = await user_factory(username="bob.va")
        await user_role_factory(user_id=target.id, role=_VA)
        ticket = await ticket_factory(
            status=TicketStatus.ANALYSIS.value, assignee_id=target.id
        )

        with StatementRecorder(db_session) as recorder:
            await update_roles(
                db_session,
                target.id,
                remove=[Role.VULNERABILITY_ANALYST],
                acting_user_id=None,
            )

        statements = [s.lstrip().upper() for s in recorder.statements]
        delete = next(
            i for i, s in enumerate(statements) if s.startswith("DELETE FROM USER_ROLE")
        )
        ticket_lock = next(
            i
            for i, s in enumerate(statements)
            if "FROM TICKET " in f"{s} " and "FOR UPDATE" in s
        )
        ticket_update = next(
            i for i, s in enumerate(statements) if s.startswith("UPDATE TICKET ")
        )
        assert delete < ticket_lock < ticket_update
        assert await _states(db_session, [ticket.id]) == {ticket.id: ("Analysis", None)}


# ---------------------------------------------------------------------------
# Role origins: external rows are observed only
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestUpdateRolesExternalOrigins:
    async def test_manual_add_alongside_external_origin_is_reported(
        self,
        db_session: AsyncSession,
        user_factory: UserFactory,
        user_role_factory: UserRoleFactory,
    ) -> None:
        """user-service.md, `update_roles()` Business Rule 1 and step 10."""
        target = await user_factory(username="bob.va")
        external = await user_role_factory(
            user_id=target.id, role=_ADMIN, group_name=_EXTERNAL_GROUP
        )
        external_id = external.id

        result = await update_roles(
            db_session, target.id, add=[Role.ADMIN], acting_user_id=None
        )

        assert result.added_roles == [Role.ADMIN]
        assert await _origins(db_session, target.id) == {
            (_ADMIN, _EXTERNAL_GROUP),
            (_ADMIN, _MANUAL),
        }
        external_row = (
            await db_session.execute(
                select(UserRole.id, UserRole.assigned_by).where(
                    UserRole.user_id == target.id,
                    UserRole.group_name == _EXTERNAL_GROUP,
                )
            )
        ).one()
        assert external_row.id == external_id
        assert await _identity_events(db_session, target.id) == [
            _added(None, target.id, "admin")
        ]

    async def test_manual_remove_alongside_external_origin_keeps_external_row(
        self,
        db_session: AsyncSession,
        user_factory: UserFactory,
        user_role_factory: UserRoleFactory,
    ) -> None:
        target = await user_factory(username="bob.va")
        await user_role_factory(user_id=target.id, role=_RA)
        await user_role_factory(user_id=target.id, role=_RA, group_name=_EXTERNAL_GROUP)

        result = await update_roles(
            db_session,
            target.id,
            remove=[Role.RESTRICTED_ANALYST],
            acting_user_id=None,
        )

        assert result.removed_roles == [Role.RESTRICTED_ANALYST]
        assert await _origins(db_session, target.id) == {(_RA, _EXTERNAL_GROUP)}
        assert await _identity_events(db_session, target.id) == [
            _removed(None, target.id, "restricted_analyst")
        ]

    async def test_removal_without_manual_row_never_touches_external_row(
        self,
        db_session: AsyncSession,
        user_factory: UserFactory,
        user_role_factory: UserRoleFactory,
    ) -> None:
        target = await user_factory(username="bob.va")
        await user_role_factory(user_id=target.id, role=_RA, group_name=_EXTERNAL_GROUP)

        with StatementRecorder(db_session) as recorder:
            result = await update_roles(
                db_session,
                target.id,
                remove=[Role.RESTRICTED_ANALYST],
                acting_user_id=None,
            )

        assert recorder.writes() == []
        assert result.removed_roles == []
        assert await _origins(db_session, target.id) == {(_RA, _EXTERNAL_GROUP)}
        assert await _identity_events(db_session, target.id) == []


# ---------------------------------------------------------------------------
# Final vulnerability_analyst origin loss
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestUpdateRolesVaOriginLoss:
    async def test_manual_va_removal_with_external_va_changes_no_ticket(
        self,
        db_session: AsyncSession,
        user_factory: UserFactory,
        user_role_factory: UserRoleFactory,
        ticket_factory: TicketFactory,
    ) -> None:
        """user-service.md, `update_roles()` step 7 and TicketAuditEvent: a
        manual deletion whose role remains effective through an external
        origin changes no Ticket."""
        target = await user_factory(username="bob.va")
        await user_role_factory(user_id=target.id, role=_VA)
        await user_role_factory(user_id=target.id, role=_VA, group_name=_EXTERNAL_GROUP)
        ticket = await ticket_factory(
            status=TicketStatus.ANALYSIS.value, assignee_id=target.id
        )

        result = await update_roles(
            db_session,
            target.id,
            remove=[Role.VULNERABILITY_ANALYST],
            acting_user_id=None,
        )

        assert result.removed_roles == [Role.VULNERABILITY_ANALYST]
        assert await _origins(db_session, target.id) == {(_VA, _EXTERNAL_GROUP)}
        assert await _states(db_session, [ticket.id]) == {
            ticket.id: ("Analysis", target.id)
        }
        assert await _ticket_events(db_session, [ticket.id]) == []

    @pytest.mark.parametrize(
        ("role", "stored"),
        [(Role.ADMIN, _ADMIN), (Role.RESTRICTED_ANALYST, _RA)],
        ids=["admin", "restricted_analyst"],
    )
    async def test_non_va_removal_issues_no_ticket_statement(
        self,
        db_session: AsyncSession,
        user_factory: UserFactory,
        user_role_factory: UserRoleFactory,
        ticket_factory: TicketFactory,
        role: Role,
        stored: str,
    ) -> None:
        """user-service.md, `update_roles()` step 7: only an effective
        `vulnerability_analyst` deletion reaches the role-loss helper, so
        removing another manual role from an assigned VA touches no
        Ticket."""
        admin = await user_factory(username="alice.admin")
        target = await user_factory(username="bob.va")
        await user_role_factory(user_id=target.id, role=_VA)
        await user_role_factory(user_id=target.id, role=stored)
        ticket = await ticket_factory(
            status=TicketStatus.ANALYSIS.value, assignee_id=target.id
        )

        with StatementRecorder(db_session) as recorder:
            result = await update_roles(
                db_session, target.id, remove=[role], acting_user_id=admin.id
            )

        assert result.removed_roles == [role]
        assert not any(_TICKET_STATEMENT.search(s) for s in recorder.statements)
        assert await _origins(db_session, target.id) == {(_VA, _MANUAL)}
        assert await _states(db_session, [ticket.id]) == {
            ticket.id: ("Analysis", target.id)
        }
        assert await _ticket_events(db_session, [ticket.id]) == []

    async def test_final_va_removal_unassigns_only_active_status_tickets(
        self,
        db_session: AsyncSession,
        user_factory: UserFactory,
        user_role_factory: UserRoleFactory,
        ticket_factory: TicketFactory,
    ) -> None:
        """user-service.md, `update_roles()` TicketAuditEvent: one system
        `assignment` per unassigned active Ticket with reason
        `vulnerability_analyst role removed`, in Ticket UUID order."""
        admin = await user_factory(username="alice.admin")
        target = await user_factory(username="bob.va")
        await user_role_factory(user_id=target.id, role=_VA)
        ids = _ordered_ids(6)
        statuses = {
            ids[0]: TicketStatus.ANALYZED,
            ids[1]: TicketStatus.RESOLVED,
            ids[2]: TicketStatus.NEW,
            ids[3]: TicketStatus.IGNORED,
            ids[4]: TicketStatus.ANALYSIS,
            ids[5]: TicketStatus.DUPLICATED,
        }
        for ticket_id in reversed(ids):
            await ticket_factory(
                id=ticket_id, status=statuses[ticket_id].value, assignee_id=target.id
            )

        await update_roles(
            db_session,
            target.id,
            remove=[Role.VULNERABILITY_ANALYST],
            acting_user_id=admin.id,
        )

        assert await _states(db_session, ids) == {
            ids[0]: ("Analyzed", None),
            ids[1]: ("Resolved", target.id),
            ids[2]: ("New", None),
            ids[3]: ("Ignored", target.id),
            ids[4]: ("Analysis", None),
            ids[5]: ("Duplicated", target.id),
        }
        assert await _ticket_events(db_session, ids) == [
            _role_loss_event(ids[0]),
            _role_loss_event(ids[2]),
            _role_loss_event(ids[4]),
        ]

    async def test_manual_addition_after_final_loss_restores_no_assignment(
        self,
        db_session: AsyncSession,
        user_factory: UserFactory,
        user_role_factory: UserRoleFactory,
        ticket_factory: TicketFactory,
    ) -> None:
        """testing-strategy.md, Manual role mutation concurrency: a manual
        role addition after a final VA-origin loss does not restore any
        previously cleared assignment (single-session form)."""
        target = await user_factory(username="bob.va")
        await user_role_factory(user_id=target.id, role=_VA)
        ticket = await ticket_factory(
            status=TicketStatus.ANALYSIS.value, assignee_id=target.id
        )
        await update_roles(
            db_session,
            target.id,
            remove=[Role.VULNERABILITY_ANALYST],
            acting_user_id=None,
        )

        result = await update_roles(
            db_session,
            target.id,
            add=[Role.VULNERABILITY_ANALYST],
            acting_user_id=None,
        )

        assert result.added_roles == [Role.VULNERABILITY_ANALYST]
        assert await _states(db_session, [ticket.id]) == {ticket.id: ("Analysis", None)}
        assert await _ticket_events(db_session, [ticket.id]) == [
            _role_loss_event(ticket.id)
        ]


# ---------------------------------------------------------------------------
# Self-Admin guard
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestUpdateRolesSelfAdminGuard:
    @pytest.mark.parametrize(
        "external_admin", [False, True], ids=["no-admin", "external-admin-only"]
    )
    async def test_self_removal_of_missing_manual_admin_is_a_no_op(
        self,
        db_session: AsyncSession,
        user_factory: UserFactory,
        user_role_factory: UserRoleFactory,
        external_admin: bool,
    ) -> None:
        """user-service.md, `update_roles()` Business Rule 2: removing a
        missing manual Admin row is an idempotent no-op and is permitted."""
        actor = await user_factory(username="alice.admin")
        if external_admin:
            await user_role_factory(
                user_id=actor.id, role=_ADMIN, group_name=_EXTERNAL_GROUP
            )

        result = await update_roles(
            db_session, actor.id, remove=[Role.ADMIN], acting_user_id=actor.id
        )

        assert result.removed_roles == []
        expected = {(_ADMIN, _EXTERNAL_GROUP)} if external_admin else set()
        assert await _origins(db_session, actor.id) == expected
        assert await _identity_events(db_session, actor.id) == []

    async def test_self_removal_with_another_admin_origin_succeeds(
        self,
        db_session: AsyncSession,
        user_factory: UserFactory,
        user_role_factory: UserRoleFactory,
    ) -> None:
        actor = await user_factory(username="alice.admin")
        await user_role_factory(user_id=actor.id, role=_ADMIN)
        await user_role_factory(
            user_id=actor.id, role=_ADMIN, group_name=_EXTERNAL_GROUP
        )

        result = await update_roles(
            db_session, actor.id, remove=[Role.ADMIN], acting_user_id=actor.id
        )

        assert result.removed_roles == [Role.ADMIN]
        assert await _origins(db_session, actor.id) == {(_ADMIN, _EXTERNAL_GROUP)}
        assert await _identity_events(db_session, actor.id) == [
            _removed(actor.id, actor.id, "admin")
        ]

    async def test_self_removal_of_final_admin_origin_raises_before_any_effect(
        self,
        db_session: AsyncSession,
        user_factory: UserFactory,
        user_role_factory: UserRoleFactory,
        ticket_factory: TicketFactory,
    ) -> None:
        """user-service.md, `update_roles()` Business Rule 2 and step 4: the
        rejection precedes every `UserRole` write, audit event, and Ticket
        mutation — including the addition and the final VA loss requested
        together."""
        actor = await user_factory(username="bob.va")
        await user_role_factory(user_id=actor.id, role=_ADMIN)
        await user_role_factory(user_id=actor.id, role=_VA)
        ticket = await ticket_factory(
            status=TicketStatus.ANALYSIS.value, assignee_id=actor.id
        )

        with (
            StatementRecorder(db_session) as recorder,
            pytest.raises(SelfRoleRemovalError),
        ):
            await update_roles(
                db_session,
                actor.id,
                add=[Role.RESTRICTED_ANALYST],
                remove=[Role.ADMIN, Role.VULNERABILITY_ANALYST],
                acting_user_id=actor.id,
            )

        assert recorder.writes() == []
        assert await _origins(db_session, actor.id) == {
            (_ADMIN, _MANUAL),
            (_VA, _MANUAL),
        }
        assert await _identity_events(db_session, actor.id) == []
        assert await _states(db_session, [ticket.id]) == {
            ticket.id: ("Analysis", actor.id)
        }
        assert await _ticket_events(db_session, [ticket.id]) == []

    async def test_system_actor_may_remove_the_final_admin_origin(
        self,
        db_session: AsyncSession,
        user_factory: UserFactory,
        user_role_factory: UserRoleFactory,
    ) -> None:
        target = await user_factory(username="alice.admin")
        await user_role_factory(user_id=target.id, role=_ADMIN)

        result = await update_roles(
            db_session, target.id, remove=[Role.ADMIN], acting_user_id=None
        )

        assert result.removed_roles == [Role.ADMIN]
        assert await _origins(db_session, target.id) == set()
        assert await _identity_events(db_session, target.id) == [
            _removed(None, target.id, "admin")
        ]

    async def test_another_actor_may_remove_the_final_admin_origin(
        self,
        db_session: AsyncSession,
        user_factory: UserFactory,
        user_role_factory: UserRoleFactory,
    ) -> None:
        """user-service.md, `update_roles()` Business Rule 2: the guard
        applies only when actor and target are the same User."""
        actor = await user_factory(username="alice.admin")
        target = await user_factory(username="carol.admin")
        await user_role_factory(user_id=target.id, role=_ADMIN)

        result = await update_roles(
            db_session, target.id, remove=[Role.ADMIN], acting_user_id=actor.id
        )

        assert result.removed_roles == [Role.ADMIN]
        assert await _identity_events(db_session, target.id) == [
            _removed(actor.id, target.id, "admin")
        ]


@pytest.mark.unit
class TestSelfRoleRemovalError:
    def test_self_role_removal_error_carries_fixed_message(self) -> None:
        """user-service.md, Service Exceptions: `SelfRoleRemovalError`
        inherits `UserServiceError`; its message is the fixed sanitized
        detail."""
        error = SelfRoleRemovalError()
        assert isinstance(error, UserServiceError)
        assert str(error) == "Cannot remove your own final admin role."


# ---------------------------------------------------------------------------
# Transactionality and result shape
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestUpdateRolesTransactionality:
    async def test_flushes_without_commit_or_rollback(
        self,
        db_session: AsyncSession,
        user_factory: UserFactory,
        user_role_factory: UserRoleFactory,
        ticket_factory: TicketFactory,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        target = await user_factory(username="bob.va")
        await user_role_factory(user_id=target.id, role=_VA)
        ticket = await ticket_factory(
            status=TicketStatus.ANALYSIS.value, assignee_id=target.id
        )
        commit_spy = AsyncMock(side_effect=AssertionError("must not commit"))
        rollback_spy = AsyncMock(side_effect=AssertionError("must not roll back"))
        monkeypatch.setattr(db_session, "commit", commit_spy)
        monkeypatch.setattr(db_session, "rollback", rollback_spy)

        await update_roles(
            db_session,
            target.id,
            add=[Role.ADMIN],
            remove=[Role.VULNERABILITY_ANALYST],
            acting_user_id=None,
        )

        commit_spy.assert_not_called()
        rollback_spy.assert_not_called()
        assert not db_session.new
        assert not db_session.dirty
        assert not db_session.deleted
        assert await _origins(db_session, target.id) == {(_ADMIN, _MANUAL)}
        assert len(await _identity_events(db_session, target.id)) == 2
        assert len(await _ticket_events(db_session, [ticket.id])) == 1

    async def test_caller_rollback_removes_rows_and_events_of_both_trails(
        self,
        db_session: AsyncSession,
        user_factory: UserFactory,
        user_role_factory: UserRoleFactory,
        ticket_factory: TicketFactory,
    ) -> None:
        """identity-audit-log.md, Testing Requirement 5 and user-service.md,
        Transactionality: rows, Identity events, Ticket clears, and Ticket
        events commit or roll back as one unit."""
        target = await user_factory(username="bob.va")
        target_id = target.id
        await user_role_factory(user_id=target_id, role=_VA)
        ticket = await ticket_factory(
            status=TicketStatus.ANALYSIS.value, assignee_id=target_id
        )
        ticket_id = ticket.id

        async with rollback_test_scope(db_session):
            await update_roles(
                db_session,
                target_id,
                add=[Role.ADMIN],
                remove=[Role.VULNERABILITY_ANALYST],
                acting_user_id=None,
            )

        assert await _origins(db_session, target_id) == {(_VA, _MANUAL)}
        assert await _identity_events(db_session, target_id) == []
        assert await _states(db_session, [ticket_id]) == {
            ticket_id: ("Analysis", target_id)
        }
        assert await _ticket_events(db_session, [ticket_id]) == []

    async def test_identity_audit_failure_rolls_back_everything(
        self,
        db_session: AsyncSession,
        user_factory: UserFactory,
        user_role_factory: UserRoleFactory,
        ticket_factory: TicketFactory,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        target = await user_factory(username="bob.va")
        target_id = target.id
        await user_role_factory(user_id=target_id, role=_VA)
        ticket = await ticket_factory(
            status=TicketStatus.ANALYZED.value, assignee_id=target_id
        )
        ticket_id = ticket.id

        async def _boom(*args: object, **kwargs: object) -> None:
            raise ValueError("simulated identity audit failure")

        monkeypatch.setattr(IdentityAuditLog, "log_event", _boom)

        with pytest.raises(ValueError, match="simulated identity audit failure"):
            async with rollback_test_scope(db_session):
                await update_roles(
                    db_session,
                    target_id,
                    add=[Role.ADMIN],
                    remove=[Role.VULNERABILITY_ANALYST],
                    acting_user_id=None,
                )

        assert await _origins(db_session, target_id) == {(_VA, _MANUAL)}
        assert await _identity_events(db_session, target_id) == []
        assert await _states(db_session, [ticket_id]) == {
            ticket_id: ("Analyzed", target_id)
        }
        assert await _ticket_events(db_session, [ticket_id]) == []

    async def test_ticket_audit_failure_rolls_back_both_domains(
        self,
        db_session: AsyncSession,
        user_factory: UserFactory,
        user_role_factory: UserRoleFactory,
        ticket_factory: TicketFactory,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        target = await user_factory(username="bob.va")
        target_id = target.id
        await user_role_factory(user_id=target_id, role=_VA)
        first_id, second_id = _ordered_ids(2)
        for ticket_id in (first_id, second_id):
            await ticket_factory(
                id=ticket_id, status=TicketStatus.ANALYSIS.value, assignee_id=target_id
            )
        calls = 0
        original = TicketAuditLog.log_event

        async def _fail_second(*args: Any, **kwargs: Any) -> None:
            # The first Ticket clear and its event succeed; the second
            # event fails, so a partial batch exists when it propagates.
            nonlocal calls
            calls += 1
            if calls == 2:
                raise ValueError("simulated ticket audit failure")
            await original(*args, **kwargs)

        monkeypatch.setattr(TicketAuditLog, "log_event", _fail_second)

        with pytest.raises(ValueError, match="simulated ticket audit failure"):
            async with rollback_test_scope(db_session):
                await update_roles(
                    db_session,
                    target_id,
                    add=[Role.ADMIN],
                    remove=[Role.VULNERABILITY_ANALYST],
                    acting_user_id=None,
                )

        assert calls == 2
        assert await _origins(db_session, target_id) == {(_VA, _MANUAL)}
        assert await _identity_events(db_session, target_id) == []
        ids = [first_id, second_id]
        assert await _states(db_session, ids) == {
            first_id: ("Analysis", target_id),
            second_id: ("Analysis", target_id),
        }
        assert await _ticket_events(db_session, ids) == []

    async def test_result_user_has_roles_and_manager_loaded_post_mutation(
        self,
        db_session: AsyncSession,
        user_factory: UserFactory,
        user_role_factory: UserRoleFactory,
    ) -> None:
        """user-service.md, Mutation Result Types: the returned User has
        roles and manager loaded and reflects the post-mutation origins."""
        manager = await user_factory(username="dave.manager")
        target = await user_factory(username="bob.va", manager_id=manager.id)
        await user_role_factory(user_id=target.id, role=_RA)
        await user_role_factory(
            user_id=target.id, role=_ADMIN, group_name=_EXTERNAL_GROUP
        )
        # Load the stale collection into the identity map first.
        await db_session.refresh(target, ["roles"])

        result = await update_roles(
            db_session,
            target.id,
            add=[Role.VULNERABILITY_ANALYST],
            remove=[Role.RESTRICTED_ANALYST],
            acting_user_id=None,
        )

        unloaded = inspect(result.user).unloaded
        assert "roles" not in unloaded
        assert "manager" not in unloaded
        assert {(r.role, r.group_name) for r in result.user.roles} == {
            (_ADMIN, _EXTERNAL_GROUP),
            (_VA, _MANUAL),
        }
        assert result.user.manager is not None
        assert result.user.manager.id == manager.id
