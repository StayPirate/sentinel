"""Shared independent-session infrastructure for the identity lifecycle race
tests (manual role mutation in `test_update_roles_atomicity.py`, and the
lifecycle-writer race matrices built on it).

`IdentityWorld` extends `CommittedWorld` with Users whose role origins are
chosen per origin, and deletes the Identity audit events that the real
lifecycle writers commit before its own teardown, which their
`ON DELETE RESTRICT` foreign keys to `user` would otherwise block
(testing-strategy.md, Concurrency Testing). `origins()` and
`identity_events()` read the role origins and the Identity trail of one
target User. `add_roles()` and
`remove_roles()` run the real `update_roles()` in one racing session, so a
consumer can use the real final VA-origin loss as its lifecycle writer.

Expected values in the consumers are transcribed from the specifications;
nothing here computes an expectation with the module under test.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterable, Sequence
from typing import Any

from sqlalchemy import delete, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import Role
from app.models.identity_audit_event import IdentityAuditEvent
from app.models.user import User
from app.models.user_role import UserRole
from app.services.user_service import RoleUpdateResult, update_roles
from tests.support.suse_cvss_races import CommittedWorld

MANUAL = "_manual"
"""The `group_name` of a manual role origin (rbac.md, Role Origins and
Coexistence)."""

EXTERNAL_GROUP = "Example Security Group"
"""A fictional external role-origin `group_name`."""

VA_ROLE_REMOVED = "vulnerability_analyst role removed"
"""The unassignment reason of a manual final VA-origin loss
(ticket-audit-log.md, Canonical Automatic Comment Vocabulary)."""

IdentityEventRow = tuple[
    str, uuid.UUID | None, uuid.UUID | None, str | None, str | None, Any
]
"""`(event_type, user_id, target_user_id, old_value, new_value, detail)`."""


class IdentityWorld(CommittedWorld):
    """A `CommittedWorld` whose Users may carry manual and external role
    origins, and whose teardown also deletes the committed Identity audit
    events that reference its Users."""

    async def identity_user(
        self,
        *,
        manual: Iterable[Role] = (),
        external: Iterable[Role] = (),
        active: bool = True,
        prefix: str = "bob.va",
    ) -> User:
        """A committed User with one `_manual` origin per role in `manual`
        and one `EXTERNAL_GROUP` origin per role in `external` (none when
        both are empty). The username is `<prefix>.<hex>`, unique per call."""
        suffix = uuid.uuid4().hex[:10]
        user = User(
            username=f"{prefix}.{suffix}",
            email=f"{prefix}.{suffix}@example.com",
            password_hash="$2b$12$" + "r" * 53,
            active=active,
        )
        self.session.add(user)
        await self.session.flush()
        self.user_ids.append(user.id)
        for role in manual:
            self.session.add(UserRole(user_id=user.id, role=role.value))
        for role in external:
            self.session.add(
                UserRole(user_id=user.id, role=role.value, group_name=EXTERNAL_GROUP)
            )
        await self.session.commit()
        return user

    async def add_origin(
        self, user: User, role: Role, *, group_name: str = MANUAL
    ) -> None:
        """Commit one more role origin of `user`."""
        self.session.add(
            UserRole(user_id=user.id, role=role.value, group_name=group_name)
        )
        await self.session.commit()

    async def cleanup(self) -> None:
        # Release the racing sessions first: an uncommitted lifecycle writer
        # may still hold the User or Ticket rows that teardown deletes.
        await self._release()
        await self.session.rollback()
        await self.session.execute(
            delete(IdentityAuditEvent).where(
                or_(
                    IdentityAuditEvent.target_user_id.in_(self.user_ids),
                    IdentityAuditEvent.user_id.in_(self.user_ids),
                )
            )
        )
        await self.session.commit()
        await super().cleanup()


async def origins(session: AsyncSession, user_id: uuid.UUID) -> set[tuple[str, str]]:
    """Every `(stored role, group_name)` origin of the User."""
    rows = await session.execute(
        select(UserRole.role, UserRole.group_name).where(UserRole.user_id == user_id)
    )
    return {(row.role, row.group_name) for row in rows}


async def identity_events(
    session: AsyncSession, user_id: uuid.UUID
) -> list[IdentityEventRow]:
    """The Identity audit events targeting `user_id`, in insertion (UUIDv7
    `id`) order."""
    rows = (
        await session.execute(
            select(IdentityAuditEvent)
            .where(IdentityAuditEvent.target_user_id == user_id)
            .order_by(IdentityAuditEvent.id)
        )
    ).scalars()
    return [
        (r.event_type, r.user_id, r.target_user_id, r.old_value, r.new_value, r.detail)
        for r in rows
    ]


def role_added(actor: User | None, target: User, wire: str) -> IdentityEventRow:
    """identity-audit-log.md, Manual role mutation events: `role_added`."""
    return (
        "role_added",
        actor.id if actor is not None else None,
        target.id,
        None,
        wire,
        None,
    )


def role_removed(actor: User | None, target: User, wire: str) -> IdentityEventRow:
    """identity-audit-log.md, Manual role mutation events: `role_removed`."""
    return (
        "role_removed",
        actor.id if actor is not None else None,
        target.id,
        wire,
        None,
        None,
    )


async def add_roles(
    session: AsyncSession,
    user: User,
    roles: Sequence[Role],
    actor: User | None = None,
) -> RoleUpdateResult:
    """The real `update_roles(add=roles)` for `user` in `session`, left
    uncommitted."""
    return await update_roles(
        session,
        user.id,
        add=list(roles),
        acting_user_id=actor.id if actor is not None else None,
    )


async def remove_roles(
    session: AsyncSession,
    user: User,
    roles: Sequence[Role],
    actor: User | None = None,
) -> RoleUpdateResult:
    """The real `update_roles(remove=roles)` for `user` in `session`, left
    uncommitted; removing the final VA origin is the real final VA-origin
    loss lifecycle writer."""
    return await update_roles(
        session,
        user.id,
        remove=list(roles),
        acting_user_id=actor.id if actor is not None else None,
    )
