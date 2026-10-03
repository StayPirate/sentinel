"""Independent-session races of the maintainer workbench queries.

Owning specifications:

- docs/features/packages/maintainer.md (Consistency, Side Effects, and
  Performance): each list or per-Ticket result is assembled from one
  coherent PostgreSQL observation.
- docs/features/packages/package-service.md (Maintainer workbench
  queries; Consumer caller context and Ticket accessibility).
- docs/features/platform/testing-strategy.md (Maintainer Workbench >
  Per-Ticket response and concurrency; Ticket Accessibility > List and
  count reads, Single, nested, and assembled reads).

Session R performs a first read, session W then commits one atomic change
that alters several protected facts at once, and R reads again. The steps
run in a fixed order on independent connections, so the interleaving is
deterministic. Each read is one statement, so R observes the change
entirely or not at all: rows, totals, and per-Ticket collections never
combine the pre-change access decision with post-change content.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Awaitable, Callable
from typing import Any

import pytest
from sqlalchemy import delete, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import DeliveryStatus, Severity
from app.core.exceptions import TicketNotFoundError
from app.core.identifiers import format_ticket_id
from app.models.ticket import Ticket
from app.models.ticket_access_grant import TicketAccessGrant
from app.models.ticket_package import TicketPackage
from app.models.ticket_package_product import TicketPackageProduct
from app.models.ticket_package_track import TicketPackageTrack
from app.services.package_service import (
    get_maintainer_ticket_work,
    list_maintainer_in_progress_work,
    list_maintainer_pending_work,
)
from app.services.packages.maintainer_workbench import (
    MaintainerTicketWork,
    MaintainerWorkPage,
)
from app.services.ticket_visibility import TicketCaller
from tests.support.maintainer_workbench import (
    EVAL,
    EXCLUDED_AT,
    INSTANT,
    WorkbenchSeed,
    owner_caller,
)

SessionFactory = Callable[[], Awaitable[AsyncSession]]

EMPTY = MaintainerTicketWork(pending=(), in_progress=(), completed=())


@pytest.fixture
async def world(db_session_factory: SessionFactory) -> AsyncIterator[WorkbenchSeed]:
    seed = WorkbenchSeed(await db_session_factory())
    try:
        yield seed
    finally:
        await seed.cleanup()


async def _commit(session: AsyncSession, *statements: Any) -> None:
    for statement in statements:
        await session.execute(statement)
    await session.commit()


async def _pending(session: AsyncSession, caller: TicketCaller) -> MaintainerWorkPage:
    return await list_maintainer_pending_work(
        session, caller=caller, evaluation_date=EVAL, evaluation_instant=INSTANT
    )


async def _in_progress(
    session: AsyncSession, caller: TicketCaller
) -> MaintainerWorkPage:
    return await list_maintainer_in_progress_work(
        session, caller=caller, evaluation_date=EVAL, evaluation_instant=INSTANT
    )


async def _ticket_work(
    session: AsyncSession, ticket: Ticket, caller: TicketCaller
) -> MaintainerTicketWork:
    return await get_maintainer_ticket_work(
        session,
        ticket_id=format_ticket_id(ticket.sequence_id),
        caller=caller,
        evaluation_date=EVAL,
        evaluation_instant=INSTANT,
    )


def _summary(page: MaintainerWorkPage) -> tuple[int, list[str]]:
    return page.total, [item.reference for item in page.items]


@pytest.mark.integration
class TestWorkbenchRaces:
    async def test_confidentiality_set_hides_a_ticket_seen_without_ownership(
        self, world: WorkbenchSeed, db_session_factory: SessionFactory
    ) -> None:
        """The caller sees the non-confidential Ticket (empty collections:
        the work belongs to another maintainer); W makes it confidential and
        changes the other maintainer's track at once. R then gets 404, never
        a result built from the stale access decision."""
        caller_user = await world.user()
        other = await world.user()
        ticket = await world.ticket(confidential=False)
        track = await world.work(other, ticket=ticket)
        await world.session.commit()
        reader = await db_session_factory()
        writer = await db_session_factory()
        caller = owner_caller(caller_user)

        assert await _ticket_work(reader, ticket, caller) == EMPTY
        await _commit(
            writer,
            update(Ticket).where(Ticket.id == ticket.id).values(is_confidential=True),
            update(TicketPackageTrack)
            .where(TicketPackageTrack.id == track.id)
            .values(delivery_status=DeliveryStatus.IN_PROGRESS.value),
        )

        with pytest.raises(TicketNotFoundError):
            await _ticket_work(reader, ticket, caller)
        assert _summary(await _in_progress(reader, caller)) == (0, [])

    async def test_confidentiality_set_keeps_owned_rows_through_maintainership(
        self, world: WorkbenchSeed, db_session_factory: SessionFactory
    ) -> None:
        """An owned row is also visible through the maintainer branch, so
        confidentiality alone never removes it; the atomic severity change
        committed with it is observed in the same read."""
        owner = await world.user()
        ticket = await world.ticket(confidential=False, cve=False)
        track = await world.work(owner, ticket=ticket)
        await world.session.commit()
        reader = await db_session_factory()
        writer = await db_session_factory()
        caller = owner_caller(owner)

        (before,) = (await _pending(reader, caller)).items
        await _commit(
            writer,
            update(Ticket)
            .where(Ticket.id == ticket.id)
            .values(is_confidential=True, severity_manual=Severity.LOW.value),
        )
        page = await _pending(reader, caller)

        assert before.severity is Severity.HIGH
        assert _summary(page) == (1, [track.reference])
        assert page.items[0].severity is Severity.LOW

    async def test_final_grant_revoked(
        self, world: WorkbenchSeed, db_session_factory: SessionFactory
    ) -> None:
        caller_user = await world.user()
        other = await world.user()
        ticket = await world.ticket(confidential=True)
        await world.work(other, ticket=ticket)
        await world.grant(ticket, caller_user, other)
        await world.session.commit()
        reader = await db_session_factory()
        writer = await db_session_factory()
        caller = owner_caller(caller_user)

        assert await _ticket_work(reader, ticket, caller) == EMPTY
        await _commit(
            writer,
            delete(TicketAccessGrant).where(TicketAccessGrant.ticket_id == ticket.id),
        )

        with pytest.raises(TicketNotFoundError):
            await _ticket_work(reader, ticket, caller)

    async def test_final_maintained_package_excluded_with_a_track_change(
        self, world: WorkbenchSeed, db_session_factory: SessionFactory
    ) -> None:
        """W atomically excludes the caller's only package (removing both
        ownership and the maintainer visibility branch) and moves its track
        to `in_progress`: R must expose neither the pending row nor the
        post-change in-progress row, and the per-Ticket read is 404."""
        owner = await world.user()
        ticket = await world.ticket(confidential=True)
        track = await world.work(owner, ticket=ticket)
        await world.session.commit()
        reader = await db_session_factory()
        writer = await db_session_factory()
        caller = owner_caller(owner)

        assert _summary(await _pending(reader, caller)) == (1, [track.reference])
        assert len((await _ticket_work(reader, ticket, caller)).pending) == 1
        await _commit(
            writer,
            update(TicketPackage)
            .where(TicketPackage.id == track.ticket_package_id)
            .values(deleted_at=EXCLUDED_AT),
            update(TicketPackageTrack)
            .where(TicketPackageTrack.id == track.id)
            .values(delivery_status=DeliveryStatus.IN_PROGRESS.value),
        )

        assert _summary(await _pending(reader, caller)) == (0, [])
        assert _summary(await _in_progress(reader, caller)) == (0, [])
        with pytest.raises(TicketNotFoundError):
            await _ticket_work(reader, ticket, caller)

    async def test_one_of_two_tickets_lost_while_the_other_changes(
        self, world: WorkbenchSeed, db_session_factory: SessionFactory
    ) -> None:
        """Rows and total of one list come from one observation: after W
        excludes the package of Ticket A and adds a track under Ticket B in
        one commit, R sees exactly B's two rows with total 2."""
        owner = await world.user()
        lost = await world.work(owner, confidential=True, name="fictional-a")
        kept = await world.work(owner, confidential=True, name="fictional-b")
        await world.session.commit()
        reader = await db_session_factory()
        writer = WorkbenchSeed(await db_session_factory())
        caller = owner_caller(owner)

        assert _summary(await _pending(reader, caller))[0] == 2
        await writer.session.execute(
            update(TicketPackage)
            .where(TicketPackage.id == lost.ticket_package_id)
            .values(deleted_at=EXCLUDED_AT)
        )
        kept_package = await writer.session.get(TicketPackage, kept.ticket_package_id)
        assert kept_package is not None
        added = await writer.track(kept_package)
        await writer.session.commit()
        world.product_ids.extend(writer.product_ids)

        total, references = _summary(await _pending(reader, caller))
        assert total == 2
        assert sorted(references) == sorted([kept.reference, added.reference])

    async def test_qualifying_package_restored_with_a_track_change(
        self, world: WorkbenchSeed, db_session_factory: SessionFactory
    ) -> None:
        """Acquisition: before the restore R gets 404; after W restores the
        package and moves its track to `in_progress` in one commit, R sees
        the complete post-change state."""
        owner = await world.user()
        ticket = await world.ticket(confidential=True)
        track = await world.work(owner, ticket=ticket)
        await world.session.execute(
            update(TicketPackage)
            .where(TicketPackage.id == track.ticket_package_id)
            .values(deleted_at=EXCLUDED_AT)
        )
        await world.session.commit()
        reader = await db_session_factory()
        writer = await db_session_factory()
        caller = owner_caller(owner)

        with pytest.raises(TicketNotFoundError):
            await _ticket_work(reader, ticket, caller)
        await _commit(
            writer,
            update(TicketPackage)
            .where(TicketPackage.id == track.ticket_package_id)
            .values(deleted_at=None),
            update(TicketPackageTrack)
            .where(TicketPackageTrack.id == track.id)
            .values(delivery_status=DeliveryStatus.IN_PROGRESS.value),
        )

        work = await _ticket_work(reader, ticket, caller)
        assert (len(work.pending), len(work.in_progress)) == (0, 1)
        assert _summary(await _in_progress(reader, caller)) == (1, [track.reference])
        assert _summary(await _pending(reader, caller)) == (0, [])

    @pytest.mark.parametrize("change", ["ineligible", "excluded"])
    async def test_final_qualifying_product_loses_eligibility_or_actionability(
        self,
        world: WorkbenchSeed,
        db_session_factory: SessionFactory,
        change: str,
    ) -> None:
        owner = await world.user()
        ticket = await world.ticket(confidential=True)
        track = await world.work(owner, ticket=ticket)
        await world.session.commit()
        reader = await db_session_factory()
        writer = await db_session_factory()
        caller = owner_caller(owner)

        assert _summary(await _pending(reader, caller)) == (1, [track.reference])
        values: dict[str, Any] = (
            {"eligible": False}
            if change == "ineligible"
            else {"deleted_at": EXCLUDED_AT}
        )
        await _commit(
            writer,
            update(TicketPackageProduct)
            .where(TicketPackageProduct.ticket_package_track_id == track.id)
            .values(**values),
        )

        assert _summary(await _pending(reader, caller)) == (0, [])
        assert await _ticket_work(reader, ticket, caller) == EMPTY
