"""Independent-session and whole-transaction tests for `ensure_cve_exists()`
(backend/app/services/cve_service.py) and `create_ticket()`
(backend/app/services/ticket_service.py).

Owning specifications:

- docs/features/tickets/cve-service.md (On-Demand Fetch:
  `ensure_cve_exists()` — Concurrency; CVE Upsert Serialization > New CVE
  and Ticket creation winner).
- docs/features/tickets/ticket-service.md (Concurrency control: creation
  paragraph; `create_ticket` — Concurrency: CVE uniqueness, Locking;
  Architectural Test Requirement 7).
- docs/features/tickets/ticket-audit-log.md (Cross-Event Ordering, Locking,
  and Rollback; Testing Requirements 7 and 23).
- docs/features/platform/testing-strategy.md (Concurrency Testing; Audit
  Trail Testing; On-Demand CVE Refetch).
- docs/features/tickets/cve-service.md (Fetch Orchestration: Transactional
  Preparation, Callers and Ordering), for the freshness registration that
  the ATR 7 race re-asserts with an enabled refetchable source.

Committed rows are deleted explicitly at teardown (testing-strategy.md,
Concurrency Testing). Expected values are transcribed from the
specifications.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from datetime import UTC, datetime
from typing import Any

import pytest
from sqlalchemy import Select, delete, false, func, or_, select, text
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import CVESourceType, Role, Severity, TicketAuditEventType
from app.models.cve import CVE
from app.models.fetcher_config import FetcherConfig
from app.models.ticket import Ticket
from app.models.ticket_audit_event import TicketAuditEvent
from app.models.user import User
from app.services import ticket_mutations, ticket_service
from app.services.cve_service import ensure_cve_exists
from app.services.ticket_audit_log import TicketAuditLog
from app.services.ticket_service import (
    TicketCreationSource,
    TicketCVEConflictError,
    create_ticket,
)
from tests.support.cve_catch_up import define_cve_fetcher
from tests.support.cve_source_status import clear_fetcher_registries
from tests.support.database import assert_lock_wait
from tests.support.suse_cvss_races import CommittedWorld
from tests.support.ticket_creation import creation_events
from tests.support.ticket_mutations import StatementRecorder, ticket_events_by_id

CRD = datetime(2026, 10, 6, 14, 0, tzinfo=UTC)
CRD_VALUE = "2026-10-06T14:00:00Z"


class _CreationWorld(CommittedWorld):
    """A `CommittedWorld` that also deletes the CVEs and Tickets created by
    the code under test, found by CVE-ID string and by committed-user
    reference, so that a failing assertion cannot leak rows."""

    def __init__(
        self, factory: Callable[[], Awaitable[AsyncSession]], session: AsyncSession
    ) -> None:
        super().__init__(factory, session)
        self.cve_id_strings: list[str] = []
        self.fetcher_names: list[str] = []

    def new_cve_id(self) -> str:
        cve_id = f"CVE-2099-{uuid.uuid4().int % 10**8:08d}"
        self.cve_id_strings.append(cve_id)
        return cve_id

    async def refetchable_source(self) -> None:
        """Exactly one registered refetchable CVE fetcher with a committed
        enabled `FetcherConfig` row, so a manual create-with-CVE registers
        its freshness effect (ticket-service.md, `create_ticket` step 11).
        The test isolates the registries."""
        clear_fetcher_registries()
        name = define_cve_fetcher(source=CVESourceType.NVD).name
        self.fetcher_names.append(name)
        self.session.add(FetcherConfig(fetcher_name=name, enabled=True))
        await self.session.commit()

    async def cleanup(self) -> None:
        await self._release()
        await self.session.rollback()
        cve_ids = (
            await self.session.scalars(
                select(CVE.id).where(CVE.cve_id.in_(self.cve_id_strings))
            )
        ).all()
        self.cve_ids.extend(cve_ids)
        ticket_ids = (
            await self.session.scalars(
                select(Ticket.id).where(
                    or_(
                        Ticket.cve_id.in_(self.cve_ids),
                        Ticket.assignee_id.in_(self.user_ids),
                        Ticket.id.in_(
                            select(TicketAuditEvent.ticket_id).where(
                                TicketAuditEvent.user_id.in_(self.user_ids)
                            )
                        ),
                    )
                )
            )
        ).all()
        self.ticket_ids.extend(set(ticket_ids) - set(self.ticket_ids))
        await self.session.rollback()
        try:
            await super().cleanup()
        finally:
            await self.session.execute(
                delete(FetcherConfig).where(
                    FetcherConfig.fetcher_name.in_(self.fetcher_names)
                )
            )
            await self.session.commit()


@pytest.fixture
async def world(
    db_session_factory: Callable[[], Awaitable[AsyncSession]],
) -> AsyncIterator[_CreationWorld]:
    created = _CreationWorld(db_session_factory, await db_session_factory())
    try:
        yield created
    finally:
        await created.cleanup()


def _freshness_effects(session: AsyncSession) -> int:
    """The number of post-commit callbacks registered on `session`; only
    the freshness preparation registers one in these service calls."""
    return len(session.info.get("post_commit_callbacks", []))


async def _manual(db: AsyncSession, creator: User, **kwargs: Any) -> Ticket:
    return await create_ticket(
        db,
        acting_user_id=creator.id,
        source=TicketCreationSource.MANUAL,
        **kwargs,
    )


async def _cve_rows(db: AsyncSession, cve_id: str) -> list[uuid.UUID]:
    rows = await db.scalars(select(CVE.id).where(CVE.cve_id == cve_id))
    result = list(rows.all())
    await db.commit()
    return result


async def _tickets_for(db: AsyncSession, cve_id: str) -> list[uuid.UUID]:
    rows = await db.scalars(
        select(Ticket.id).join(CVE, Ticket.cve_id == CVE.id).where(CVE.cve_id == cve_id)
    )
    result = list(rows.all())
    await db.commit()
    return result


async def _sntl(db: AsyncSession, ticket_id: uuid.UUID) -> str:
    sequence = await db.scalar(select(Ticket.sequence_id).where(Ticket.id == ticket_id))
    await db.commit()
    return f"SNTL-{sequence}"


async def _lock_nowait(session: AsyncSession, cve_id: uuid.UUID) -> None:
    await session.execute(
        select(CVE.id).where(CVE.id == cve_id).with_for_update(nowait=True)
    )


# ---------------------------------------------------------------------------
# ensure_cve_exists: conflict-aware creation
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestEnsureRace:
    @pytest.mark.parametrize("lock", [False, True], ids=["plain", "locked"])
    async def test_racing_callers_obtain_the_one_winner_row(
        self, world: _CreationWorld, lock: bool
    ) -> None:
        cve_id = world.new_cve_id()
        a = await world.open_session()
        b = await world.open_session()

        winner = await ensure_cve_exists(a, cve_id, lock=lock)
        task = world.start(b, ensure_cve_exists(b, cve_id, lock=lock))
        await assert_lock_wait(task, waiter=b, blocked_by=a)
        await a.commit()
        loser = await asyncio.wait_for(task, timeout=5)

        assert loser.id == winner.id
        assert loser.cve_id == cve_id
        assert await b.scalar(text("SELECT 1")) == 1
        await b.commit()
        assert await a.scalar(text("SELECT 1")) == 1
        await a.commit()
        assert await _cve_rows(world.session, cve_id) == [winner.id]

    @pytest.mark.parametrize("lock", [False, True], ids=["plain", "locked"])
    async def test_rolled_back_first_inserter_lets_the_waiter_create(
        self, world: _CreationWorld, lock: bool
    ) -> None:
        cve_id = world.new_cve_id()
        a = await world.open_session()
        b = await world.open_session()

        apparent = (await ensure_cve_exists(a, cve_id, lock=lock)).id
        task = world.start(b, ensure_cve_exists(b, cve_id, lock=lock))
        await assert_lock_wait(task, waiter=b, blocked_by=a)
        await a.rollback()
        created = await asyncio.wait_for(task, timeout=5)

        assert created.id != apparent
        assert created.cve_id == cve_id
        await b.commit()
        assert await _cve_rows(world.session, cve_id) == [created.id]

    async def test_locked_conflict_loser_holds_the_winner_lock(
        self, world: _CreationWorld
    ) -> None:
        cve_id = world.new_cve_id()
        a = await world.open_session()
        b = await world.open_session()
        c = await world.open_session()

        winner = await ensure_cve_exists(a, cve_id, lock=True)
        task = world.start(b, ensure_cve_exists(b, cve_id, lock=True))
        await assert_lock_wait(task, waiter=b, blocked_by=a)
        await a.commit()
        loser = await asyncio.wait_for(task, timeout=5)
        assert loser.id == winner.id

        with pytest.raises(DBAPIError):
            await _lock_nowait(c, winner.id)
        await c.rollback()

        await b.rollback()
        await _lock_nowait(c, winner.id)
        await c.rollback()

    async def test_plain_conflict_loser_holds_no_lock(
        self, world: _CreationWorld
    ) -> None:
        cve_id = world.new_cve_id()
        a = await world.open_session()
        b = await world.open_session()
        c = await world.open_session()

        winner = await ensure_cve_exists(a, cve_id)
        task = world.start(b, ensure_cve_exists(b, cve_id))
        await assert_lock_wait(task, waiter=b, blocked_by=a)
        await a.commit()
        await asyncio.wait_for(task, timeout=5)

        await _lock_nowait(c, winner.id)
        await c.rollback()
        await b.rollback()

    async def test_locked_resolution_of_an_existing_row_holds_its_lock(
        self, world: _CreationWorld
    ) -> None:
        cve = await world.cve()
        b = await world.open_session()
        c = await world.open_session()

        await ensure_cve_exists(b, cve.cve_id, lock=True)

        with pytest.raises(DBAPIError):
            await _lock_nowait(c, cve.id)
        await c.rollback()
        await b.rollback()


# ---------------------------------------------------------------------------
# create_ticket: serialization on the User and CVE roots
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestCreationRace:
    @pytest.mark.parametrize(
        ("existing", "refetchable"),
        [
            pytest.param(True, False, id="existing-cve"),
            pytest.param(False, False, id="placeholder"),
            pytest.param(False, True, id="placeholder-refetchable"),
        ],
    )
    @pytest.mark.usefixtures("isolated_fetcher_registries")
    async def test_second_creator_waits_then_observes_the_committed_association(
        self, world: _CreationWorld, existing: bool, refetchable: bool
    ) -> None:
        """ATR 7: one Ticket, one success, one `TicketCVEConflictError`
        carrying the winner's identifier. With an enabled refetchable source
        the winner registers exactly one freshness effect and the loser none
        (ticket-service.md, `create_ticket` step 11)."""
        if refetchable:
            await world.refetchable_source()
        first = await world.user(role=Role.VULNERABILITY_ANALYST)
        second = await world.user(role=Role.RESTRICTED_ANALYST)
        cve_id = (await world.cve()).cve_id if existing else world.new_cve_id()
        a = await world.open_session()
        b = await world.open_session()

        winner = await _manual(a, first, cve_id=cve_id)
        world.ticket_ids.append(winner.id)
        task = world.start(b, _manual(b, second, cve_id=cve_id))
        await assert_lock_wait(task, waiter=b, blocked_by=a)
        await a.commit()

        with pytest.raises(TicketCVEConflictError) as raised:
            await asyncio.wait_for(task, timeout=5)
        await b.rollback()

        assert _freshness_effects(a) == (1 if refetchable else 0)
        assert _freshness_effects(b) == 0
        assert raised.value.existing_ticket_id == await _sntl(world.session, winner.id)
        assert await _tickets_for(world.session, cve_id) == [winner.id]
        assert len(await _cve_rows(world.session, cve_id)) == 1
        events = await ticket_events_by_id(world.session, winner.id)
        await world.session.commit()
        assert events == creation_events(
            creator_id=first.id, assignee_username=first.username, cve_id=cve_id
        )

    @pytest.mark.parametrize(
        "existing", [True, False], ids=["existing-cve", "placeholder"]
    )
    async def test_rolled_back_first_creator_lets_the_waiter_create(
        self, world: _CreationWorld, existing: bool
    ) -> None:
        first = await world.user(role=Role.VULNERABILITY_ANALYST)
        second = await world.user(role=Role.RESTRICTED_ANALYST)
        cve_id = (await world.cve()).cve_id if existing else world.new_cve_id()
        a = await world.open_session()
        b = await world.open_session()

        await _manual(a, first, cve_id=cve_id)
        task = world.start(b, _manual(b, second, cve_id=cve_id))
        await assert_lock_wait(task, waiter=b, blocked_by=a)
        await a.rollback()
        created = await asyncio.wait_for(task, timeout=5)
        world.ticket_ids.append(created.id)
        await b.commit()

        assert await _tickets_for(world.session, cve_id) == [created.id]
        events = await ticket_events_by_id(world.session, created.id)
        await world.session.commit()
        assert events == creation_events(creator_id=second.id, cve_id=cve_id)

    async def test_creator_lock_blocks_deactivation_until_commit(
        self, world: _CreationWorld
    ) -> None:
        creator = await world.user(role=Role.VULNERABILITY_ANALYST)
        a = await world.open_session()
        b = await world.open_session()

        ticket = await _manual(a, creator)
        world.ticket_ids.append(ticket.id)
        task = world.start(
            b,
            b.execute(
                select(User.id)
                .where(User.id == creator.id)
                .with_for_update(key_share=True)
            ),
        )
        await assert_lock_wait(task, waiter=b, blocked_by=a)
        await a.commit()
        await asyncio.wait_for(task, timeout=5)
        await b.rollback()

    async def test_unique_backstop_violation_escapes_untranslated(
        self, world: _CreationWorld, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The association read is forced to observe nothing (an injected
        invariant violation), so the INSERT hits `Ticket.cve_id UNIQUE`.
        The `IntegrityError` escapes as-is and no statement follows it."""
        creator = await world.user(role=Role.VULNERABILITY_ANALYST)
        cve = await world.cve()
        existing = await world.ticket(cve_id=cve.id)
        session = await world.open_session()
        original_execute = session.execute
        suppressed = 0

        async def execute(statement: Any, *args: Any, **kwargs: Any) -> Any:
            nonlocal suppressed
            if (
                isinstance(statement, Select)
                and [c.key for c in statement.selected_columns] == ["sequence_id"]
                and Ticket.__table__ in statement.get_final_froms()
            ):
                suppressed += 1
                statement = statement.where(false())
            return await original_execute(statement, *args, **kwargs)

        monkeypatch.setattr(session, "execute", execute)

        with (
            StatementRecorder(session) as recorder,
            pytest.raises(IntegrityError) as raised,
        ):
            await _manual(session, creator, cve_id=cve.cve_id)
        monkeypatch.undo()
        await session.rollback()

        assert suppressed == 1
        assert not isinstance(raised.value, TicketCVEConflictError)
        assert "cve_id" in str(raised.value.orig)
        assert recorder.statements[-1].startswith("INSERT INTO ticket ")
        assert await _tickets_for(world.session, cve.cve_id) == [existing.id]


# ---------------------------------------------------------------------------
# Whole-transaction rollback
# ---------------------------------------------------------------------------


FAILURES = [
    pytest.param("audit", "ticket_created", "placeholder", id="audit-ticket-created"),
    pytest.param("audit", "assignment", "placeholder", id="audit-assignment"),
    pytest.param("audit", "severity_changed", "cve-less", id="audit-severity"),
    pytest.param("audit", "coordinated_release_changed", "placeholder", id="audit-crd"),
    pytest.param("audit", "cve_associated", "placeholder", id="audit-cve-associated"),
    pytest.param("audit", "priority_changed", "cve-less", id="audit-priority"),
    pytest.param("flush", "ticket", "placeholder", id="flush-ticket-insert"),
    pytest.param("flush", "cve_associated", "placeholder", id="flush-event-insert"),
    pytest.param("refresh", None, "cve-less", id="priority-refresh"),
]
"""`(failure, position, scenario)`. The `cve-less` scenario records
`ticket_created`, `assignment`, `severity_changed`,
`coordinated_release_changed`, and `priority_changed`; the `placeholder`
scenario records `ticket_created`, `assignment`,
`coordinated_release_changed`, and `cve_associated` for a new CVE."""


async def _committed_counts(db: AsyncSession) -> tuple[int, int, int]:
    counts = (
        await db.execute(
            select(
                select(func.count()).select_from(Ticket).scalar_subquery(),
                select(func.count()).select_from(TicketAuditEvent).scalar_subquery(),
                select(func.count()).select_from(CVE).scalar_subquery(),
            )
        )
    ).one()
    await db.commit()
    return (counts[0], counts[1], counts[2])


async def _create_scenario(
    session: AsyncSession, creator: User, scenario: str, cve_id: str
) -> Ticket:
    if scenario == "cve-less":
        return await _manual(
            session,
            creator,
            severity_manual=Severity.HIGH,
            is_confidential=True,
            coordinated_release_at=CRD,
        )
    return await _manual(
        session,
        creator,
        cve_id=cve_id,
        is_confidential=True,
        coordinated_release_at=CRD,
    )


@pytest.mark.integration
class TestRollback:
    @pytest.mark.parametrize(("failure", "position", "scenario"), FAILURES)
    async def test_failure_rolls_back_ticket_placeholder_and_events(
        self,
        world: _CreationWorld,
        monkeypatch: pytest.MonkeyPatch,
        failure: str,
        position: str | None,
        scenario: str,
    ) -> None:
        creator = await world.user(role=Role.VULNERABILITY_ANALYST)
        cve_id = world.new_cve_id()
        session = await world.open_session()
        before = await _committed_counts(world.session)
        reached = False

        if failure == "audit":
            original_log = TicketAuditLog.log_event

            async def failing_log(*args: Any, **kwargs: Any) -> None:
                nonlocal reached
                if kwargs["event_type"] is TicketAuditEventType(str(position)):
                    reached = True
                    raise RuntimeError("injected audit failure")
                await original_log(*args, **kwargs)

            monkeypatch.setattr(TicketAuditLog, "log_event", failing_log)
        elif failure == "flush":
            original_flush = session.flush

            def pending(session_new: Any) -> bool:
                if position == "ticket":
                    return any(isinstance(o, Ticket) for o in session_new)
                return any(
                    isinstance(o, TicketAuditEvent) and o.event_type == position
                    for o in session_new
                )

            async def failing_flush(*args: Any, **kwargs: Any) -> None:
                nonlocal reached
                if pending(session.new):
                    reached = True
                    raise RuntimeError("injected flush failure")
                await original_flush(*args, **kwargs)

            monkeypatch.setattr(session, "flush", failing_flush)
        else:
            original_refresh = ticket_mutations.refresh_priority_auto

            async def failing_refresh(db: AsyncSession, *, ticket: Ticket) -> bool:
                nonlocal reached
                reached = await original_refresh(db, ticket=ticket)
                raise RuntimeError("injected priority refresh failure")

            monkeypatch.setattr(
                ticket_service, "refresh_priority_auto", failing_refresh
            )

        with pytest.raises(RuntimeError, match="injected"):
            await _create_scenario(session, creator, scenario, cve_id)
        monkeypatch.undo()
        await session.rollback()

        assert reached is True
        assert await _committed_counts(world.session) == before
        assert await _cve_rows(world.session, cve_id) == []
        creator_events = await world.session.scalar(
            select(func.count())
            .select_from(TicketAuditEvent)
            .where(TicketAuditEvent.user_id == creator.id)
        )
        await world.session.commit()
        assert creator_events == 0

    @pytest.mark.parametrize("scenario", ["cve-less", "placeholder"])
    async def test_unfailed_scenario_commits_everything_the_failures_roll_back(
        self, world: _CreationWorld, scenario: str
    ) -> None:
        """Control for the rollback matrix: without an injected failure the
        same scenario persists the Ticket, the placeholder, and every event."""
        creator = await world.user(role=Role.VULNERABILITY_ANALYST)
        cve_id = world.new_cve_id()
        session = await world.open_session()
        before = await _committed_counts(world.session)

        ticket = await _create_scenario(session, creator, scenario, cve_id)
        world.ticket_ids.append(ticket.id)
        await session.commit()

        events = await ticket_events_by_id(world.session, ticket.id)
        await world.session.commit()
        if scenario == "cve-less":
            expected = creation_events(
                creator_id=creator.id,
                assignee_username=creator.username,
                severity="High",
                coordinated_release=CRD_VALUE,
                priority="P3",
            )
            assert await _cve_rows(world.session, cve_id) == []
        else:
            expected = creation_events(
                creator_id=creator.id,
                assignee_username=creator.username,
                coordinated_release=CRD_VALUE,
                cve_id=cve_id,
            )
            assert len(await _cve_rows(world.session, cve_id)) == 1
        assert events == expected
        after = await _committed_counts(world.session)
        assert after[0] == before[0] + 1
        assert after[1] == before[1] + len(expected)
        assert after[2] == before[2] + (scenario == "placeholder")
