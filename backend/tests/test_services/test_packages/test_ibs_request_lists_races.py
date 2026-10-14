"""Independent-session races for the Ticket-scoped IBS request lists
(backend/app/services/packages/ibs_request_lists.py).

Owning specifications:

- docs/features/packages/ibs-submission-tracking.md (Public API: the
  canonical visibility predicate is part of the same database result used
  for deduplication, counting, pagination, and projection, and a
  preliminary check cannot authorize a later unconstrained action query;
  Security and Privacy bullet 1).
- docs/features/platform/testing-strategy.md (Ticket Accessibility: List
  and count reads; Single, nested, and assembled reads; Database Strategy
  > Concurrency Testing).
- docs/features/identity/rbac.md (Optional Principal to Caller Context:
  the caller is resolved once per request).

Every scenario commits its rows through an independent session
(`_CommittedWorld`) and deletes them at teardown in FK-safe order, then
proves nothing it created remains. Session R performs the preliminary
`resolve_ticket_locator()`, session W commits a change, and R then
performs the protected selection. The steps run in a fixed order on
independent connections, so the interleaving is deterministic without
sleeps. Each outcome must be either the complete response of one coherent
view or `TicketNotFoundError`.
"""

from __future__ import annotations

import itertools
import secrets
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import pytest
from sqlalchemy import delete, func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import IBSRequestActionType, Role, Scope
from app.core.exceptions import TicketNotFoundError
from app.core.identifiers import format_ticket_id
from app.core.permissions import get_effective_scope
from app.models.ibs_request import IBSRequest
from app.models.ibs_request_action import IBSRequestAction
from app.models.ibs_request_action_track import IBSRequestActionTrack
from app.models.ticket import Ticket
from app.models.ticket_access_grant import TicketAccessGrant
from app.models.ticket_package import TicketPackage
from app.models.ticket_package_maintainer import TicketPackageMaintainer
from app.models.ticket_package_product import TicketPackageProduct
from app.models.ticket_package_track import TicketPackageTrack
from app.models.user import User
from app.models.user_role import UserRole
from app.services import user_service
from app.services.packages.ibs_request_lists import (
    IBSRequestActionPage,
    list_release_requests,
    list_submission_requests,
)
from app.services.ticket_service import resolve_ticket_locator
from app.services.ticket_visibility import ANONYMOUS_CALLER, TicketCaller

_SessionFactory = Callable[[], Awaitable[AsyncSession]]
_Lister = Callable[..., Awaitable[IBSRequestActionPage]]

_SR = IBSRequestActionType.MAINTENANCE_INCIDENT
_RR = IBSRequestActionType.MAINTENANCE_RELEASE
_UPSTREAM_TIME = datetime(2026, 8, 10, 9, 15, tzinfo=UTC)


@dataclass(frozen=True, slots=True)
class _Kind:
    """One of the two list operations and the action type it returns."""

    lister: _Lister
    action_type: IBSRequestActionType


_KINDS = [
    pytest.param(_Kind(list_submission_requests, _SR), id="submission"),
    pytest.param(_Kind(list_release_requests, _RR), id="release"),
]


def _sntl(ticket: Ticket) -> str:
    return format_ticket_id(ticket.sequence_id)


def _restricted(user: User) -> TicketCaller:
    return TicketCaller.authenticated(user.id, Scope.NON_CONFIDENTIAL)


async def _list(
    kind: _Kind, db: AsyncSession, ticket: Ticket, caller: TicketCaller
) -> IBSRequestActionPage:
    return await kind.lister(db, ticket_id=_sntl(ticket), caller=caller, per_page=100)


async def _commit(session: AsyncSession, *statements: Any) -> None:
    for statement in statements:
        await session.execute(statement)
    await session.commit()


class _CommittedWorld:
    """Commits fixture rows through an independent session and deletes
    them at teardown in FK-safe order (testing-strategy.md, Concurrency
    Testing: committed data is not rolled back by the fixture)."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.user_ids: list[uuid.UUID] = []
        self.ticket_ids: list[uuid.UUID] = []
        self.package_ids: list[uuid.UUID] = []
        self.track_ids: list[uuid.UUID] = []
        self.request_ids: list[uuid.UUID] = []
        self.action_ids: list[uuid.UUID] = []
        # Random per world rather than fixed: committed rows left by an
        # interrupted earlier run against the same database cannot collide.
        self._numbers = itertools.count(400_000_000 + secrets.randbelow(10**9))
        self._names = itertools.count(1)

    async def user(self, *, role: Role | None = None) -> User:
        suffix = f"{next(self._names)}.{uuid.uuid4().hex[:8]}"
        user = User(
            username=f"fictional.race{suffix}",
            email=f"race{suffix}@example.com",
            password_hash="$2b$12$" + "a" * 53,
        )
        self.session.add(user)
        await self.session.flush()
        self.user_ids.append(user.id)
        if role is not None:
            self.session.add(UserRole(user_id=user.id, role=role.value))
        await self.session.commit()
        return user

    async def ticket(self, *, is_confidential: bool) -> Ticket:
        ticket = Ticket(is_confidential=is_confidential)
        self.session.add(ticket)
        await self.session.flush()
        self.ticket_ids.append(ticket.id)
        await self.session.commit()
        return ticket

    async def package(self, ticket: Ticket) -> TicketPackage:
        package = TicketPackage(
            ticket_id=ticket.id,
            package_name=f"example-race-package-{next(self._names)}",
        )
        self.session.add(package)
        await self.session.flush()
        self.package_ids.append(package.id)
        await self.session.commit()
        return package

    async def track(self, package: TicketPackage) -> TicketPackageTrack:
        track = TicketPackageTrack(
            ticket_package_id=package.id,
            workflow_type="ibs",
            reference=f"Example:Race:{next(self._names)}:Update",
        )
        self.session.add(track)
        await self.session.flush()
        self.track_ids.append(track.id)
        await self.session.commit()
        return track

    async def maintainer(self, package: TicketPackage, user: User) -> None:
        self.session.add(
            TicketPackageMaintainer(ticket_package_id=package.id, user_id=user.id)
        )
        await self.session.commit()

    async def grant(self, ticket: Ticket, user: User, granter: User) -> None:
        self.session.add(
            TicketAccessGrant(
                ticket_id=ticket.id, user_id=user.id, granted_by_id=granter.id
            )
        )
        await self.session.commit()

    async def action(
        self,
        action_type: IBSRequestActionType,
        track: TicketPackageTrack,
        *,
        session: AsyncSession | None = None,
    ) -> IBSRequestAction:
        """Commit one request, one action of `action_type`, and its
        correlation to `track`, through `session` (default: the world's
        own). The rows are recorded for cleanup either way."""
        db = session or self.session
        number = next(self._numbers)
        codestream = f"Example:Race:{number}:Update"
        request = IBSRequest(
            request_number=number,
            state="review",
            upstream_created_at=_UPSTREAM_TIME,
            upstream_updated_at=_UPSTREAM_TIME,
        )
        db.add(request)
        await db.flush()
        self.request_ids.append(request.id)
        fields: dict[str, Any]
        if action_type is _RR:
            fields = {
                "source_project": f"SUSE:Maintenance:{number % 100_000 + 1}",
                "source_package": "example-pkg.Example_Race",
                "target_project": codestream,
                "target_package": "example-pkg",
                "incident_number": number % 100_000 + 1,
            }
        else:
            fields = {
                "source_project": "Example:Devel:Race",
                "source_package": "example-pkg",
                "target_release_project": codestream,
            }
        action = IBSRequestAction(
            ibs_request_id=request.id,
            action_type=action_type.value,
            logical_package="example-pkg",
            codestream_name=codestream,
            **fields,
        )
        db.add(action)
        await db.flush()
        self.action_ids.append(action.id)
        db.add(
            IBSRequestActionTrack(
                ibs_request_action_id=action.id, ticket_package_track_id=track.id
            )
        )
        await db.commit()
        return action

    def _statements(self) -> list[Any]:
        return [
            delete(IBSRequestActionTrack).where(
                or_(
                    IBSRequestActionTrack.ibs_request_action_id.in_(self.action_ids),
                    IBSRequestActionTrack.ticket_package_track_id.in_(self.track_ids),
                )
            ),
            delete(IBSRequestAction).where(IBSRequestAction.id.in_(self.action_ids)),
            delete(IBSRequest).where(IBSRequest.id.in_(self.request_ids)),
            delete(TicketPackageMaintainer).where(
                TicketPackageMaintainer.ticket_package_id.in_(self.package_ids)
            ),
            delete(TicketPackageProduct).where(
                TicketPackageProduct.ticket_package_track_id.in_(self.track_ids)
            ),
            delete(TicketPackageTrack).where(TicketPackageTrack.id.in_(self.track_ids)),
            delete(TicketPackage).where(TicketPackage.id.in_(self.package_ids)),
            delete(TicketAccessGrant).where(
                TicketAccessGrant.ticket_id.in_(self.ticket_ids)
            ),
            delete(Ticket).where(Ticket.id.in_(self.ticket_ids)),
            delete(UserRole).where(UserRole.user_id.in_(self.user_ids)),
            delete(User).where(User.id.in_(self.user_ids)),
        ]

    async def cleanup(self) -> None:
        await self.session.rollback()
        for statement in self._statements():
            await self.session.execute(statement)
        await self.session.commit()

    async def remaining(self) -> dict[str, int]:
        """The count of every recorded row still present, per table."""
        checks = {
            "ibs_request_action_track": select(func.count())
            .select_from(IBSRequestActionTrack)
            .where(
                or_(
                    IBSRequestActionTrack.ibs_request_action_id.in_(self.action_ids),
                    IBSRequestActionTrack.ticket_package_track_id.in_(self.track_ids),
                )
            ),
            "ibs_request_action": select(func.count()).where(
                IBSRequestAction.id.in_(self.action_ids)
            ),
            "ibs_request": select(func.count()).where(
                IBSRequest.id.in_(self.request_ids)
            ),
            "ticket_package_track": select(func.count()).where(
                TicketPackageTrack.id.in_(self.track_ids)
            ),
            "ticket_package": select(func.count()).where(
                TicketPackage.id.in_(self.package_ids)
            ),
            "ticket_access_grant": select(func.count()).where(
                TicketAccessGrant.ticket_id.in_(self.ticket_ids)
            ),
            "ticket": select(func.count()).where(Ticket.id.in_(self.ticket_ids)),
            "user": select(func.count()).where(User.id.in_(self.user_ids)),
        }
        counts = {
            table: (await self.session.execute(query)).scalar_one()
            for table, query in checks.items()
        }
        await self.session.rollback()
        return counts


@pytest.fixture
async def committed_world(
    db_session_factory: _SessionFactory,
) -> AsyncIterator[_CommittedWorld]:
    world = _CommittedWorld(await db_session_factory())
    try:
        yield world
    finally:
        await world.cleanup()
        assert set((await world.remaining()).values()) <= {0}


async def _visible_world(
    world: _CommittedWorld,
    kind: _Kind,
    *,
    is_confidential: bool,
    actions: int = 2,
) -> tuple[Ticket, TicketPackage, set[uuid.UUID]]:
    """One Ticket with one package, one track, and `actions` correlated
    actions of the list's type, plus one of the other type that must
    never appear."""
    ticket = await world.ticket(is_confidential=is_confidential)
    package = await world.package(ticket)
    track = await world.track(package)
    ids = {(await world.action(kind.action_type, track)).id for _ in range(actions)}
    await world.action(_RR if kind.action_type is _SR else _SR, track)
    return ticket, package, ids


def _assert_complete(page: IBSRequestActionPage, expected: set[uuid.UUID]) -> None:
    """The response of one coherent view: every expected item, each once,
    and the matching total."""
    assert len(page.items) == len(expected)
    assert {item.id for item in page.items} == expected
    assert page.total == len(expected)


@pytest.mark.integration
@pytest.mark.parametrize("kind", _KINDS)
class TestListRaces:
    """An implementation that listed actions without re-applying
    visibility after the preliminary decision would return rows and fail
    the loss cases."""

    async def test_confidentiality_set_after_preliminary_resolution(
        self,
        kind: _Kind,
        committed_world: _CommittedWorld,
        db_session_factory: _SessionFactory,
    ) -> None:
        user = await committed_world.user()
        ticket, _, _ = await _visible_world(
            committed_world, kind, is_confidential=False
        )
        reader = await db_session_factory()
        writer = await db_session_factory()
        caller = _restricted(user)

        await resolve_ticket_locator(reader, _sntl(ticket), caller)
        await _commit(
            writer,
            update(Ticket).where(Ticket.id == ticket.id).values(is_confidential=True),
        )

        with pytest.raises(TicketNotFoundError):
            await _list(kind, reader, ticket, caller)

    async def test_grant_revoked_after_preliminary_resolution(
        self,
        kind: _Kind,
        committed_world: _CommittedWorld,
        db_session_factory: _SessionFactory,
    ) -> None:
        user = await committed_world.user()
        granter = await committed_world.user()
        ticket, _, _ = await _visible_world(committed_world, kind, is_confidential=True)
        await committed_world.grant(ticket, user, granter)
        reader = await db_session_factory()
        writer = await db_session_factory()
        caller = _restricted(user)

        await resolve_ticket_locator(reader, _sntl(ticket), caller)
        await _commit(
            writer,
            delete(TicketAccessGrant).where(
                TicketAccessGrant.ticket_id == ticket.id,
                TicketAccessGrant.user_id == user.id,
            ),
        )

        with pytest.raises(TicketNotFoundError):
            await _list(kind, reader, ticket, caller)

    async def test_last_maintained_package_excluded_after_preliminary_resolution(
        self,
        kind: _Kind,
        committed_world: _CommittedWorld,
        db_session_factory: _SessionFactory,
    ) -> None:
        """The correlated track sits under the maintained package: its
        history survives the exclusion, but the caller's visibility does
        not."""
        user = await committed_world.user()
        ticket, package, _ = await _visible_world(
            committed_world, kind, is_confidential=True
        )
        await committed_world.maintainer(package, user)
        reader = await db_session_factory()
        writer = await db_session_factory()
        caller = _restricted(user)

        await resolve_ticket_locator(reader, _sntl(ticket), caller)
        await _commit(
            writer,
            update(TicketPackage)
            .where(TicketPackage.id == package.id)
            .values(deleted_at=datetime.now(UTC)),
        )

        with pytest.raises(TicketNotFoundError):
            await _list(kind, reader, ticket, caller)

    async def test_grant_added_after_a_denial_is_observed_whole(
        self,
        kind: _Kind,
        committed_world: _CommittedWorld,
        db_session_factory: _SessionFactory,
    ) -> None:
        user = await committed_world.user()
        granter = await committed_world.user()
        ticket, _, expected = await _visible_world(
            committed_world, kind, is_confidential=True
        )
        reader = await db_session_factory()
        writer = await db_session_factory()
        caller = _restricted(user)

        with pytest.raises(TicketNotFoundError):
            await resolve_ticket_locator(reader, _sntl(ticket), caller)
        writer.add(
            TicketAccessGrant(
                ticket_id=ticket.id, user_id=user.id, granted_by_id=granter.id
            )
        )
        await writer.commit()

        _assert_complete(await _list(kind, reader, ticket, caller), expected)

    async def test_confidentiality_removed_after_a_denial_is_observed_whole(
        self,
        kind: _Kind,
        committed_world: _CommittedWorld,
        db_session_factory: _SessionFactory,
    ) -> None:
        ticket, _, expected = await _visible_world(
            committed_world, kind, is_confidential=True
        )
        reader = await db_session_factory()
        writer = await db_session_factory()

        with pytest.raises(TicketNotFoundError):
            await resolve_ticket_locator(reader, _sntl(ticket), ANONYMOUS_CALLER)
        await _commit(
            writer,
            update(Ticket).where(Ticket.id == ticket.id).values(is_confidential=False),
        )

        _assert_complete(await _list(kind, reader, ticket, ANONYMOUS_CALLER), expected)

    async def test_count_and_page_come_from_one_view(
        self,
        kind: _Kind,
        committed_world: _CommittedWorld,
        db_session_factory: _SessionFactory,
    ) -> None:
        """Actions and correlations committed between two reads are
        observed whole by the later read, in its items and total alike.
        Page/total coherence within one read follows from the single
        statement proven in `test_ibs_request_lists.py`."""
        ticket, package, initial = await _visible_world(
            committed_world, kind, is_confidential=False
        )
        reader = await db_session_factory()
        writer = await db_session_factory()

        before = await _list(kind, reader, ticket, ANONYMOUS_CALLER)
        await resolve_ticket_locator(reader, _sntl(ticket), ANONYMOUS_CALLER)
        track = await committed_world.track(package)
        added = {
            (await committed_world.action(kind.action_type, track, session=writer)).id
            for _ in range(3)
        }
        after = await _list(kind, reader, ticket, ANONYMOUS_CALLER)

        _assert_complete(before, initial)
        _assert_complete(after, initial | added)

    async def test_concurrent_role_change_does_not_alter_the_resolved_caller(
        self,
        kind: _Kind,
        committed_world: _CommittedWorld,
        db_session_factory: _SessionFactory,
    ) -> None:
        """The caller's scope is resolved once per request; a committed
        role removal applies to the next resolution, not to the in-flight
        request (rbac.md, Optional Principal to Caller Context)."""
        user = await committed_world.user(role=Role.VULNERABILITY_ANALYST)
        ticket, _, expected = await _visible_world(
            committed_world, kind, is_confidential=True
        )
        reader = await db_session_factory()
        writer = await db_session_factory()
        in_flight = TicketCaller.authenticated(
            user.id,
            get_effective_scope(await user_service.get_user_roles(reader, user.id)),
        )

        await _commit(writer, delete(UserRole).where(UserRole.user_id == user.id))
        result = await _list(kind, reader, ticket, in_flight)
        next_request = TicketCaller.authenticated(
            user.id,
            get_effective_scope(await user_service.get_user_roles(reader, user.id)),
        )

        assert in_flight.scope is Scope.ALL
        _assert_complete(result, expected)
        assert next_request.scope is Scope.NON_CONFIDENTIAL
        with pytest.raises(TicketNotFoundError):
            await _list(kind, reader, ticket, next_request)
