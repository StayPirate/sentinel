"""Independent-session tests for the cross-Ticket package search
(`package_service.search_packages()`).

Owning specifications:

- docs/features/packages/package-service.md (Query Operations >
  `search_packages()`; Consumer caller context and Ticket accessibility;
  Architectural Test Requirement bullet "Atomic consumer accessibility":
  read queries constrain package items, totals, pages, and aggregates in
  the same database result).
- docs/features/identity/rbac.md (Scope and Confidential Ticket
  Visibility).
- docs/features/platform/testing-strategy.md (Concurrency Testing; Ticket
  Accessibility > List and count reads: at least one independent-session
  race per query shape that changes confidentiality, revokes the caller's
  grant, or excludes the caller's last qualifying package after a
  preliminary resolution point; Single, nested, and assembled reads:
  acquisition of visibility and the request-resolved caller; Parallel
  Execution).

The single-session behavior is covered by
`tests/test_services/test_package_search.py`.

Session R searches once (the access decision a split implementation would
reuse), session W commits a visibility change, and R searches again on the
same connection inside the same open transaction. Under PostgreSQL's
default `READ COMMITTED` isolation the second search observes W's commit:
it must return no row from a Ticket that became invisible, and its total
must agree with its items. Every Ticket is CVE-less in `Analysis`; each
package path carries one track with one eligible Product in General
Support on `EVAL`. Names are unique per test (a random token generated in
the test body), and committed rows are deleted explicitly at teardown by
`CommittedWorld` (testing-strategy.md, Concurrency Testing).
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator, Awaitable, Callable

import pytest
from sqlalchemy import delete, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql import Executable

from app.core.enums import PackageStatus, Role, Scope, Severity
from app.core.identifiers import format_ticket_id
from app.models.ticket import Ticket
from app.models.ticket_access_grant import TicketAccessGrant
from app.models.ticket_package import TicketPackage
from app.models.ticket_package_track import TicketPackageTrack
from app.models.user import User
from app.models.user_role import UserRole
from app.services.package_service import (
    PackageSearchPage,
    TrackSummaryProjection,
    search_packages,
)
from app.services.ticket_visibility import TicketCaller
from tests.support.package_exclusion import (
    CommittedPath,
    Direction,
    Level,
    add_maintainer,
    committed_path,
    markers_by_id,
    path_call,
)
from tests.support.suse_cvss_races import CommittedWorld
from tests.support.ticket_mutations import EVAL

Factory = Callable[[], Awaitable[AsyncSession]]

_FICTIONAL_HASH = "$2b$12$" + "s" * 53
"""A fictional bcrypt-shaped value, never a real hash."""


@pytest.fixture
async def committed_world(db_session_factory: Factory) -> AsyncIterator[CommittedWorld]:
    world = CommittedWorld(db_session_factory, await db_session_factory())
    try:
        yield world
    finally:
        await world.cleanup()


async def _user(world: CommittedWorld, role: Role | None = None) -> User:
    """Commit an active local user with a fictional identity (and `role`)."""
    suffix = uuid.uuid4().hex[:10]
    user = User(
        username=f"fictional.search.{suffix}",
        email=f"fictional.search.{suffix}@example.com",
        password_hash=_FICTIONAL_HASH,
    )
    world.session.add(user)
    await world.session.flush()
    world.user_ids.append(user.id)
    if role is not None:
        world.session.add(UserRole(user_id=user.id, role=role.value))
    await world.session.commit()
    return user


async def _package(world: CommittedWorld, ticket: Ticket, name: str) -> CommittedPath:
    """Commit an actionable package named `name` (one track, one eligible
    Product in General Support on `EVAL`)."""
    package = TicketPackage(ticket_id=ticket.id, package_name=name)
    world.session.add(package)
    await world.session.commit()
    return await committed_path(world, ticket, package_id=package.id)


async def _search(
    reader: AsyncSession, caller: TicketCaller, token: str
) -> PackageSearchPage:
    """One search restricted to the test's own packages."""
    return await search_packages(
        reader, caller=caller, evaluation_date=EVAL, search=token
    )


def _names(page: PackageSearchPage) -> set[str]:
    return {item.package_name for item in page.items}


def _sntl(ticket: Ticket) -> str:
    return format_ticket_id(ticket.sequence_id)


async def _commit(session: AsyncSession, *statements: Executable) -> None:
    for statement in statements:
        await session.execute(statement)
    await session.commit()


@pytest.mark.integration
class TestSearchRaces:
    async def test_confidentiality_set_between_searches(
        self, committed_world: CommittedWorld
    ) -> None:
        world = committed_world
        token = f"fictional-search-{uuid.uuid4().hex[:12]}"
        user = await _user(world)
        hidden = await world.ticket(cve_id=None)
        await _package(world, hidden, f"{token}-a")
        public = await world.ticket(cve_id=None)
        await _package(world, public, f"{token}-b")
        reader = await world.open_session()
        writer = await world.open_session()
        caller = TicketCaller.authenticated(user.id, Scope.NON_CONFIDENTIAL)

        assert (await _search(reader, caller, token)).total == 2
        await _commit(
            writer,
            update(Ticket).where(Ticket.id == hidden.id).values(is_confidential=True),
        )
        after = await _search(reader, caller, token)

        assert after.total == len(after.items) == 1
        assert _names(after) == {f"{token}-b"}
        assert _sntl(hidden) not in {item.ticket.ticket_id for item in after.items}

    async def test_grant_revoked_between_searches(
        self, committed_world: CommittedWorld
    ) -> None:
        world = committed_world
        token = f"fictional-search-{uuid.uuid4().hex[:12]}"
        user = await _user(world)
        granter = await _user(world, Role.VULNERABILITY_ANALYST)
        ticket = await world.ticket(cve_id=None, is_confidential=True)
        await _package(world, ticket, f"{token}-a")
        await world.grant(ticket, user, granter)
        reader = await world.open_session()
        writer = await world.open_session()
        caller = TicketCaller.authenticated(user.id, Scope.NON_CONFIDENTIAL)

        assert _names(await _search(reader, caller, token)) == {f"{token}-a"}
        await _commit(
            writer,
            delete(TicketAccessGrant).where(TicketAccessGrant.ticket_id == ticket.id),
        )

        assert await _search(reader, caller, token) == PackageSearchPage(
            items=(), total=0, page=1, per_page=20
        )

    async def test_last_maintained_package_excluded_between_searches(
        self, committed_world: CommittedWorld
    ) -> None:
        """W excludes the caller's only maintained package A through the
        real exclusion operation, as an authorized actor, and commits. The
        confidential Ticket also has an actionable package B that the
        caller does not maintain: B disappears too, proving the loss of
        Ticket visibility rather than only A's non-actionability."""
        world = committed_world
        token = f"fictional-search-{uuid.uuid4().hex[:12]}"
        user = await _user(world)
        actor = await _user(world, Role.VULNERABILITY_ANALYST)
        ticket = await world.ticket(
            cve_id=None, is_confidential=True, severity_manual=Severity.HIGH
        )
        maintained = await _package(world, ticket, f"{token}-a")
        await add_maintainer(world, maintained.package_id, user)
        await _package(world, ticket, f"{token}-b")
        reader = await world.open_session()
        writer = await world.open_session()
        caller = TicketCaller.authenticated(user.id, Scope.NON_CONFIDENTIAL)
        all_scope = TicketCaller.authenticated(actor.id, Scope.ALL)

        assert _names(await _search(reader, caller, token)) == {
            f"{token}-a",
            f"{token}-b",
        }
        await path_call(writer, Level.PACKAGE, Direction.EXCLUDE, maintained, actor)
        await writer.commit()
        after = await _search(reader, caller, token)

        assert after == PackageSearchPage(items=(), total=0, page=1, per_page=20)
        probe = await world.open_session()
        package_marker, _, _ = await markers_by_id(probe, maintained.id)
        assert package_marker is not None
        assert _names(await _search(probe, all_scope, token)) == {f"{token}-b"}

    async def test_visibility_acquired_between_searches_is_observed_whole(
        self, committed_world: CommittedWorld
    ) -> None:
        """A grant committed together with a severity and an affectedness
        change is observed as one snapshot: the newly visible item carries
        the new severity and track summary."""
        world = committed_world
        token = f"fictional-search-{uuid.uuid4().hex[:12]}"
        user = await _user(world)
        granter = await _user(world, Role.VULNERABILITY_ANALYST)
        ticket = await world.ticket(cve_id=None, is_confidential=True)
        path = await _package(world, ticket, f"{token}-a")
        reader = await world.open_session()
        writer = await world.open_session()
        caller = TicketCaller.authenticated(user.id, Scope.NON_CONFIDENTIAL)

        assert (await _search(reader, caller, token)).total == 0
        writer.add(
            TicketAccessGrant(
                ticket_id=ticket.id, user_id=user.id, granted_by_id=granter.id
            )
        )
        await _commit(
            writer,
            update(Ticket)
            .where(Ticket.id == ticket.id)
            .values(severity_manual=Severity.HIGH.value),
            update(TicketPackageTrack)
            .where(TicketPackageTrack.id == path.track_id)
            .values(status=PackageStatus.AFFECTED.value),
        )
        after = await _search(reader, caller, token)

        assert after.total == 1
        (item,) = after.items
        assert item.id == path.package_id
        assert item.ticket.ticket_id == _sntl(ticket)
        assert item.ticket.severity is Severity.HIGH
        assert item.track_summary == TrackSummaryProjection(
            total=1, affected=1, fixed=0, not_affected=0, wont_fix=0, analysis=0
        )

    async def test_concurrent_role_change_does_not_alter_the_resolved_caller(
        self, committed_world: CommittedWorld
    ) -> None:
        """The service consumes the request-resolved scope: a role removal
        committed during the request does not narrow its visibility; the
        next request's newly resolved caller is narrowed."""
        world = committed_world
        token = f"fictional-search-{uuid.uuid4().hex[:12]}"
        user = await _user(world, Role.VULNERABILITY_ANALYST)
        ticket = await world.ticket(cve_id=None, is_confidential=True)
        await _package(world, ticket, f"{token}-a")
        reader = await world.open_session()
        writer = await world.open_session()
        in_flight = TicketCaller.authenticated(user.id, Scope.ALL)

        await _commit(writer, delete(UserRole).where(UserRole.user_id == user.id))
        page = await _search(reader, in_flight, token)

        assert [item.ticket.ticket_id for item in page.items] == [_sntl(ticket)]
        assert page.total == 1
        next_request = TicketCaller.authenticated(user.id, Scope.NON_CONFIDENTIAL)
        assert (await _search(reader, next_request, token)).total == 0
