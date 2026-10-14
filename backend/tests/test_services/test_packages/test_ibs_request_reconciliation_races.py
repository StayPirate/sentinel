"""Independent-session tests for the shared IBS request reconciliation
(backend/app/services/packages/ibs_request_reconciliation.py): the
stale-negative guard, the Ticket lock, the cross-Ticket request lock and
insert order, overlapping invocations, and whole-scope atomicity.

Owning specifications:

- docs/features/packages/ibs-submission-tracking.md (Shared Authoritative
  Reconciliation > Algorithm steps 1 and 4-10 and the concurrency
  paragraphs: the step-1 snapshot, conditional request upserts, a stale
  request observation, equal-time conflicting content, uniqueness conflicts
  resolved by reload, the stale-negative guard; Delivery Derivation:
  `RELEASED` reloaded under the lock keeps delivery; Testing Requirements:
  stale-negative concurrency with independent sessions, atomic commit and
  rollback).
- docs/features/packages/package-model.md (Delivery status regression;
  RELEASED is irreversible).
- docs/conventions.md (Transaction and Locking: Pessimistic Locking
  Pattern, Cross-Domain Root Lock Order, Transaction Hygiene Rules).
- docs/features/platform/testing-strategy.md (Concurrency Testing and
  Lock-Wait Observation).

Concurrent writers are independent `db_session_factory` sessions. A change
"during the scan" is committed by `before_lock()`, after every IBS request
of the scope and before its unit takes the Ticket lock; a lock holder is
started there and the scope's unit is proven waiting on it with
`assert_lock_wait()`. The boundary's sessions come from `UnitSessions`
over `real_session_factory`, or from queued `db_session_factory` sessions
when a test needs their backend PIDs (the first session the boundary opens
is the step-1 snapshot session, then one unit per complete scope).
"""

from __future__ import annotations

import asyncio
import re
from collections.abc import AsyncIterator, Awaitable, Callable
from datetime import UTC, datetime
from typing import Any, Final

import pytest
from sqlalchemy import delete, insert, select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from sqlalchemy.orm import Session
from structlog.testing import capture_logs

from app.core.enums import DeliveryStatus, IBSRequestActionType, IBSRequestState
from app.models.ibs_request import IBSRequest
from app.models.ibs_request_action import IBSRequestAction
from app.models.ibs_request_action_track import IBSRequestActionTrack
from app.models.ticket import Ticket
from app.models.ticket_package_track import TicketPackageTrack
from app.services import package_service
from app.services.packages import ibs_request_reconciliation
from app.services.packages.ibs_request_observation import IBSRequestScope
from app.services.packages.ibs_request_reconciliation import reconcile_ibs_requests
from tests.support.database import assert_lock_wait
from tests.support.ibs_product_release import UnitSessions
from tests.support.ibs_request_reconciliation import (
    CREATED_AT,
    SCOPE_FAILED,
    WHEN_AT,
    Action,
    FakeRequests,
    Outcomes,
    RequestSeed,
    RequestWorld,
    before_lock,
    cve_issue,
    delivery_of,
    evidence_of,
    install_fake_requests,
    install_request_units,
    kinds,
    reconcile,
    request_rows,
    submission,
    unique_package,
)
from tests.support.ibs_track_release import events_of, logged
from tests.support.suse_cvss_races import SessionStatementRecorder

pytestmark = pytest.mark.integration

Factory = Callable[[], Awaitable[AsyncSession]]

WAIT: Final = 5
"""Upper bound, in seconds, of every wait expected to finish."""
LATER: Final = datetime(2026, 10, 2, 8, 0, tzinfo=UTC)
LATER_WHEN: Final = "2026-10-02T08:00:00"
EVEN_LATER: Final = datetime(2026, 10, 3, 8, 0, tzinfo=UTC)

PENDING: Final = DeliveryStatus.PENDING
IN_PROGRESS: Final = DeliveryStatus.IN_PROGRESS
RELEASED: Final = DeliveryStatus.RELEASED
REVIEW: Final = IBSRequestState.REVIEW
DECLINED: Final = IBSRequestState.DECLINED
ACCEPTED: Final = IBSRequestState.ACCEPTED

TICKET_LOCK: Final = re.compile(r"\bFROM ticket\b.*FOR UPDATE", re.DOTALL)
REQUEST_STATEMENT: Final = re.compile(r"\bibs_request\b(?!_action)")
ACTION_WRITE: Final = re.compile(r"^\s*(INSERT INTO|UPDATE) ibs_request_action\b")


@pytest.fixture(autouse=True)
def fake(monkeypatch: pytest.MonkeyPatch) -> FakeRequests:
    return install_fake_requests(monkeypatch)


@pytest.fixture(autouse=True)
def units(
    real_session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> UnitSessions:
    return install_request_units(monkeypatch, real_session_factory)


@pytest.fixture
async def world(db_session_factory: Factory) -> AsyncIterator[RequestWorld]:
    created = RequestWorld(db_session_factory, await db_session_factory())
    try:
        yield created
    finally:
        await created.cleanup()


@pytest.fixture
def delivery_calls(monkeypatch: pytest.MonkeyPatch) -> list[DeliveryStatus]:
    """Records every requested delivery value of the real mutation."""
    calls: list[DeliveryStatus] = []
    original = package_service.set_track_delivery_status

    async def recording(db: AsyncSession, **kwargs: Any) -> Any:
        calls.append(kwargs["delivery_status"])
        return await original(db, **kwargs)

    monkeypatch.setattr(package_service, "set_track_delivery_status", recording)
    return calls


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _commit(world: RequestWorld, *statements: Any) -> None:
    """Commit `statements` through a fresh independent session."""
    session = await world.open_session()
    for statement in statements:
        await session.execute(statement)
    await session.commit()


def _once(
    monkeypatch: pytest.MonkeyPatch,
    action: Callable[[IBSRequestScope], Awaitable[None]],
    *,
    track_id: Any = None,
) -> None:
    """Run `action` once, before the lock of the first scope (or of the
    scope of `track_id`)."""
    done = False

    async def guarded(target: IBSRequestScope) -> None:
        nonlocal done
        if not done and (track_id is None or target.track_id == track_id):
            done = True
            await action(target)

    before_lock(monkeypatch, guarded)


async def _correlated_review(
    seed: RequestSeed, *scopes: IBSRequestScope, number: int | None = None
) -> tuple[int, Action]:
    """One retained open SR of the scopes' package correlated to each
    scope's track."""
    number = number or seed.world.number()
    action = submission(scopes[0].package_name, number)
    await seed.evidence(number, REVIEW, action, tracks=scopes)
    return number, action


async def _negative_scope(
    world: RequestWorld, fake: FakeRequests, *, delivery: DeliveryStatus = IN_PROGRESS
) -> tuple[IBSRequestScope, int]:
    """A track in `delivery` correlated to one retained open SR that IBS
    now reports declined: a complete negative observation."""
    seed = RequestSeed(world)
    scope = await seed.track(
        await seed.ticket(), package=unique_package(), delivery=delivery
    )
    number, action = await _correlated_review(seed, scope)
    await seed.commit()
    fake.request(number, DECLINED, action, when=LATER_WHEN)
    fake.quiet(scope.package_name)
    return scope, number


async def _uncorrelated(world: RequestWorld, package: str) -> tuple[int, Any]:
    """Commit one retained open SR of `package` correlated to nothing;
    returns its number and action ID."""
    seed = RequestSeed(world)
    number = world.number()
    action_id = await seed.evidence(number, REVIEW, submission(package, number))
    await seed.commit()
    return number, action_id


# ---------------------------------------------------------------------------
# Stale-negative guard (Algorithm steps 1 and 8)
# ---------------------------------------------------------------------------


class TestStaleNegativeGuard:
    async def test_without_concurrent_change_the_negative_regresses(
        self,
        world: RequestWorld,
        fake: FakeRequests,
        delivery_calls: list[DeliveryStatus],
    ) -> None:
        """The control case of this class."""
        scope, _ = await _negative_scope(world, fake)

        outcomes = await reconcile(fake, [scope])

        assert kinds(outcomes) == {scope.track_id: "updated"}
        assert delivery_calls == [PENDING]
        assert await delivery_of(await world.probe(), scope.track_id) == PENDING

    async def test_row_added_during_the_scan_blocks_the_regression_only(
        self,
        world: RequestWorld,
        fake: FakeRequests,
        monkeypatch: pytest.MonkeyPatch,
        delivery_calls: list[DeliveryStatus],
    ) -> None:
        """Another writer commits an open SR of the same package and
        codestream during the scan: the negative does not regress, and the
        unobserved row is not positive evidence either."""
        scope, number = await _negative_scope(world, fake)
        added = world.number()

        async def add(_: IBSRequestScope) -> None:
            session = await world.open_session()
            seed = RequestSeed(world)
            seed.session = session
            await seed.evidence(added, REVIEW, submission(scope.package_name, added))
            await session.commit()

        _once(monkeypatch, add)

        outcomes = await reconcile(fake, [scope])

        assert kinds(outcomes) == {scope.track_id: "updated"}
        assert delivery_calls == []
        probe = await world.probe()
        assert await delivery_of(probe, scope.track_id) == IN_PROGRESS
        assert [
            row.request_number for row in await evidence_of(probe, scope.track_id)
        ] == [number]
        assert (await request_rows(probe, [number]))[number][0] == DECLINED.value

    async def test_row_restamped_during_the_scan_blocks_the_regression(
        self,
        world: RequestWorld,
        fake: FakeRequests,
        monkeypatch: pytest.MonkeyPatch,
        delivery_calls: list[DeliveryStatus],
    ) -> None:
        scope, _ = await _negative_scope(world, fake)
        other, _ = await _uncorrelated(world, scope.package_name)

        async def restamp(_: IBSRequestScope) -> None:
            await _commit(
                world,
                update(IBSRequest)
                .where(IBSRequest.request_number == other)
                .values(state=REVIEW.value),
            )

        _once(monkeypatch, restamp)

        outcomes = await reconcile(fake, [scope])

        assert kinds(outcomes) == {scope.track_id: "updated"}
        assert delivery_calls == []
        assert await delivery_of(await world.probe(), scope.track_id) == IN_PROGRESS

    async def test_row_removed_during_the_scan_blocks_the_regression(
        self,
        world: RequestWorld,
        fake: FakeRequests,
        monkeypatch: pytest.MonkeyPatch,
        delivery_calls: list[DeliveryStatus],
    ) -> None:
        scope, _ = await _negative_scope(world, fake)
        other, action_id = await _uncorrelated(world, scope.package_name)

        async def remove(_: IBSRequestScope) -> None:
            await _commit(
                world,
                delete(IBSRequestAction).where(IBSRequestAction.id == action_id),
                delete(IBSRequest).where(IBSRequest.request_number == other),
            )

        _once(monkeypatch, remove)

        outcomes = await reconcile(fake, [scope])

        assert kinds(outcomes) == {scope.track_id: "updated"}
        assert delivery_calls == []
        assert await delivery_of(await world.probe(), scope.track_id) == IN_PROGRESS

    async def test_writer_begun_before_step_1_and_committed_during_the_scan(
        self,
        world: RequestWorld,
        fake: FakeRequests,
        monkeypatch: pytest.MonkeyPatch,
        delivery_calls: list[DeliveryStatus],
    ) -> None:
        """The writer's rows carry its transaction start time, earlier than
        this scope's own writes, so a timestamp bound would miss them; they
        were absent from the step-1 snapshot, so the guard still blocks the
        regression."""
        scope, number = await _negative_scope(world, fake)
        writer = await world.open_session()
        seed = RequestSeed(world)
        seed.session = writer
        added = world.number()
        await seed.evidence(added, REVIEW, submission(scope.package_name, added))

        async def commit_writer(_: IBSRequestScope) -> None:
            await writer.commit()

        _once(monkeypatch, commit_writer)

        outcomes = await reconcile(fake, [scope])

        assert kinds(outcomes) == {scope.track_id: "updated"}
        assert delivery_calls == []
        probe = await world.probe()
        assert await delivery_of(probe, scope.track_id) == IN_PROGRESS
        rows = await request_rows(probe, [number, added])
        assert rows[added][4] < rows[number][4]

    async def test_delivery_changed_during_the_scan_blocks_the_regression(
        self,
        world: RequestWorld,
        fake: FakeRequests,
        monkeypatch: pytest.MonkeyPatch,
        delivery_calls: list[DeliveryStatus],
    ) -> None:
        """A `PENDING` baseline becomes `IN_PROGRESS` through another
        writer's positive work during the scan; this scope's negative never
        overwrites it, and the writer's correlation survives."""
        scope, number = await _negative_scope(world, fake, delivery=PENDING)
        other, action_id = await _uncorrelated(world, scope.package_name)

        async def positive_work(_: IBSRequestScope) -> None:
            await _commit(
                world,
                insert(IBSRequestActionTrack).values(
                    ibs_request_action_id=action_id,
                    ticket_package_track_id=scope.track_id,
                ),
                update(TicketPackageTrack)
                .where(TicketPackageTrack.id == scope.track_id)
                .values(delivery_status=IN_PROGRESS.value),
            )

        _once(monkeypatch, positive_work)

        outcomes = await reconcile(fake, [scope])

        assert kinds(outcomes) == {scope.track_id: "updated"}
        assert delivery_calls == []
        probe = await world.probe()
        assert await delivery_of(probe, scope.track_id) == IN_PROGRESS
        assert {
            row.request_number for row in await evidence_of(probe, scope.track_id)
        } == {
            number,
            other,
        }

    async def test_evidence_reused_by_a_later_scope_never_regresses_it(
        self,
        world: RequestWorld,
        fake: FakeRequests,
        monkeypatch: pytest.MonkeyPatch,
        delivery_calls: list[DeliveryStatus],
    ) -> None:
        """Two Tickets share one retained SR that IBS now reports declined.
        The second scope reuses the detail the first scope fetched, but rows
        committed after the invocation's step-1 snapshot (the first scope's
        refresh of the shared request and a writer's correlation to the
        second track) differ from its snapshot, so only the first scope
        regresses."""
        seed = RequestSeed(world)
        package = unique_package()
        first = await seed.track(
            await seed.ticket(), package=package, delivery=IN_PROGRESS
        )
        second = await seed.track(
            await seed.ticket(), package=package, delivery=IN_PROGRESS
        )
        first, second = sorted([first, second], key=lambda s: s.track_id)
        number, action = await _correlated_review(seed, first, second)
        await seed.commit()
        other, other_action = await _uncorrelated(world, package)
        fake.request(number, DECLINED, action, when=LATER_WHEN)
        fake.quiet(package)

        async def correlate(_: IBSRequestScope) -> None:
            await _commit(
                world,
                insert(IBSRequestActionTrack).values(
                    ibs_request_action_id=other_action,
                    ticket_package_track_id=second.track_id,
                ),
            )

        _once(monkeypatch, correlate, track_id=first.track_id)

        outcomes = await reconcile(fake, [first, second])

        assert kinds(outcomes) == {first.track_id: "updated", second.track_id: "no_op"}
        probe = await world.probe()
        assert await delivery_of(probe, first.track_id) == PENDING
        assert await delivery_of(probe, second.track_id) == IN_PROGRESS
        assert delivery_calls == [PENDING]
        assert other in {
            row.request_number for row in await evidence_of(probe, second.track_id)
        }


# ---------------------------------------------------------------------------
# The Ticket lock (Algorithm steps 4-5 and 9)
# ---------------------------------------------------------------------------


class TestTicketLock:
    async def test_unit_waits_for_the_ticket_and_keeps_a_winner_released(
        self,
        world: RequestWorld,
        fake: FakeRequests,
        units: UnitSessions,
        monkeypatch: pytest.MonkeyPatch,
        delivery_calls: list[DeliveryStatus],
    ) -> None:
        """A positive scope waits for a concurrent holder of the Ticket lock
        that proves the release; under the lock it reloads `RELEASED`,
        commits its evidence, and requests no transition."""
        seed = RequestSeed(world)
        scope = await seed.track(await seed.ticket(), package=unique_package())
        await seed.commit()
        number = world.number()
        action = submission(scope.package_name, number)
        fake.request(number, REVIEW, action)
        fake.action_diff(
            number,
            action,
            cve_issue(scope.cve_id),
            codestream_package=scope.package_name,
        )
        fake.quiet(scope.package_name, open_submissions=[number])
        holder = await world.open_session()
        waiter = await world.open_session()
        units.queued.extend([await world.open_session(), waiter])
        locked = asyncio.Event()

        async def hold(target: IBSRequestScope) -> None:
            await holder.execute(
                select(Ticket.id).where(Ticket.id == target.ticket_id).with_for_update()
            )
            await holder.execute(
                update(TicketPackageTrack)
                .where(TicketPackageTrack.id == target.track_id)
                .values(delivery_status=RELEASED.value)
            )
            locked.set()

        _once(monkeypatch, hold)
        hook = Outcomes()

        with SessionStatementRecorder(waiter) as recorder:
            task = world.start(waiter, reconcile(fake, [scope], hook))
            await asyncio.wait_for(locked.wait(), timeout=WAIT)
            await assert_lock_wait(task, waiter=waiter, blocked_by=holder)
            assert len(recorder.statements) == 1
            assert TICKET_LOCK.search(recorder.statements[0])
            assert hook.received == []
            await holder.commit()
            outcomes = await asyncio.wait_for(task, timeout=WAIT)

        assert kinds(outcomes) == {scope.track_id: "created"}
        assert delivery_calls == []
        probe = await world.probe()
        assert await delivery_of(probe, scope.track_id) == RELEASED
        assert [
            row.request_number for row in await evidence_of(probe, scope.track_id)
        ] == [number]
        assert await events_of(world, scope.ticket_id) == []


# ---------------------------------------------------------------------------
# Request locks and inserts across Tickets (Algorithm steps 6-7)
# ---------------------------------------------------------------------------


class TestRequestConcurrency:
    async def test_an_older_point_fetch_waits_and_never_replaces_newer_truth(
        self,
        world: RequestWorld,
        fake: FakeRequests,
        units: UnitSessions,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Another Ticket's scope holds the shared request with a newer
        observation; this scope waits on the request row, then fails as a
        stale request observation without any write."""
        seed = RequestSeed(world)
        scope = await seed.track(await seed.ticket(), package=unique_package())
        number, action = await _correlated_review(seed, scope)
        await seed.commit()
        fake.request(number, REVIEW, action)
        fake.quiet(scope.package_name)
        holder = await world.open_session()
        waiter = await world.open_session()
        units.queued.extend([await world.open_session(), waiter])
        locked = asyncio.Event()

        async def hold(_: IBSRequestScope) -> None:
            await holder.execute(
                select(IBSRequest.id)
                .where(IBSRequest.request_number == number)
                .with_for_update(key_share=True)
            )
            await holder.execute(
                update(IBSRequest)
                .where(IBSRequest.request_number == number)
                .values(state=DECLINED.value, upstream_updated_at=LATER)
            )
            locked.set()

        _once(monkeypatch, hold)

        with capture_logs() as logs:
            task = world.start(waiter, reconcile(fake, [scope]))
            await asyncio.wait_for(locked.wait(), timeout=WAIT)
            await assert_lock_wait(task, waiter=waiter, blocked_by=holder)
            await holder.commit()
            outcomes = await asyncio.wait_for(task, timeout=WAIT)

        assert kinds(outcomes) == {scope.track_id: "failed"}
        [entry] = logged(logs, SCOPE_FAILED)
        assert entry["reason_category"] == "stale_request_observation"
        assert entry["request_number"] == number
        rows = await request_rows(await world.probe(), [number])
        assert rows[number][:2] == (DECLINED.value, None)
        assert rows[number][3] == LATER

    @pytest.mark.parametrize(
        ("state", "kind"),
        [(REVIEW, "created"), (DECLINED, "failed")],
        ids=["identical", "conflicting"],
    )
    async def test_concurrently_inserted_request_is_resolved_by_reload(
        self,
        world: RequestWorld,
        fake: FakeRequests,
        units: UnitSessions,
        monkeypatch: pytest.MonkeyPatch,
        state: IBSRequestState,
        kind: str,
    ) -> None:
        """Another writer inserts the same new request number first: this
        scope's insert waits on it, inserts nothing, reloads the winner, and
        applies the equal-time rule (identical content is idempotent,
        conflicting content fails)."""
        seed = RequestSeed(world)
        scope = await seed.track(await seed.ticket(), package=unique_package())
        await seed.commit()
        number = world.number()
        action = submission(scope.package_name, number)
        fake.request(number, REVIEW, action)
        fake.action_diff(
            number,
            action,
            cve_issue(scope.cve_id),
            codestream_package=scope.package_name,
        )
        fake.quiet(scope.package_name, open_submissions=[number])
        holder = await world.open_session()
        waiter = await world.open_session()
        units.queued.extend([await world.open_session(), waiter])
        inserted = asyncio.Event()

        async def insert_first(_: IBSRequestScope) -> None:
            await holder.execute(
                insert(IBSRequest).values(
                    request_number=number,
                    state=state.value,
                    upstream_created_at=CREATED_AT,
                    upstream_updated_at=WHEN_AT,
                )
            )
            inserted.set()

        _once(monkeypatch, insert_first)

        task = world.start(waiter, reconcile(fake, [scope]))
        await asyncio.wait_for(inserted.wait(), timeout=WAIT)
        await assert_lock_wait(task, waiter=waiter, blocked_by=holder)
        winner = await holder.scalar(
            select(IBSRequest.id).where(IBSRequest.request_number == number)
        )
        await holder.commit()
        outcomes = await asyncio.wait_for(task, timeout=WAIT)

        assert kinds(outcomes) == {scope.track_id: kind}
        probe = await world.probe()
        stored = (
            await probe.execute(
                select(IBSRequest.id, IBSRequest.state).where(
                    IBSRequest.request_number == number
                )
            )
        ).all()
        await probe.rollback()
        assert stored == [(winner, state.value)]
        correlated = await evidence_of(probe, scope.track_id)
        expected = [number] if kind == "created" else []
        assert [row.request_number for row in correlated] == expected
        expected_delivery = IN_PROGRESS if kind == "created" else PENDING
        assert await delivery_of(probe, scope.track_id) == expected_delivery

    async def test_requests_are_locked_and_inserted_in_one_ascending_sequence(
        self,
        world: RequestWorld,
        fake: FakeRequests,
        units: UnitSessions,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A retained request (lower number) and a new one (higher number):
        while another writer holds the lower one, this scope waits on it and
        has not yet inserted the higher one or written any action; then it
        processes requests in ascending order, actions after every request,
        correlations last."""
        seed = RequestSeed(world)
        scope = await seed.track(await seed.ticket(), package=unique_package())
        lower, lower_action = await _correlated_review(seed, scope)
        await seed.commit()
        higher = lower + 1
        world.numbers().add(higher)
        higher_action = submission(scope.package_name, higher)
        fake.request(lower, REVIEW, lower_action)
        fake.request(higher, REVIEW, higher_action)
        fake.action_diff(
            higher,
            higher_action,
            cve_issue(scope.cve_id),
            codestream_package=scope.package_name,
        )
        fake.quiet(scope.package_name, open_submissions=[higher])
        holder = await world.open_session()
        waiter = await world.open_session()
        units.queued.extend([await world.open_session(), waiter])
        locked = asyncio.Event()

        async def hold(_: IBSRequestScope) -> None:
            await holder.execute(
                select(IBSRequest.id)
                .where(IBSRequest.request_number == lower)
                .with_for_update(key_share=True)
            )
            locked.set()

        _once(monkeypatch, hold)

        with SessionStatementRecorder(waiter) as recorder:
            task = world.start(waiter, reconcile(fake, [scope]))
            await asyncio.wait_for(locked.wait(), timeout=WAIT)
            await assert_lock_wait(task, waiter=waiter, blocked_by=holder)
            probe = await world.probe()
            assert await request_rows(probe, [higher]) == {}
            assert not any(ACTION_WRITE.search(s) for s in recorder.statements)
            await holder.rollback()
            outcomes = await asyncio.wait_for(task, timeout=WAIT)

        assert kinds(outcomes) == {scope.track_id: "created"}
        statements = recorder.statements
        assert TICKET_LOCK.search(statements[0])
        request_positions = [
            index
            for index, statement in enumerate(statements)
            if REQUEST_STATEMENT.search(statement.split("WHERE")[0])
            and (
                "FOR NO KEY UPDATE" in statement
                or statement.lstrip().startswith(("INSERT", "UPDATE"))
            )
        ]
        action_positions = [
            index
            for index, statement in enumerate(statements)
            if ACTION_WRITE.search(statement)
        ]
        correlation_positions = [
            index
            for index, statement in enumerate(statements)
            if statement.lstrip().startswith("INSERT INTO ibs_request_action_track")
        ]
        assert request_positions
        assert action_positions
        assert correlation_positions
        assert max(request_positions) < min(action_positions)
        assert max(action_positions) < min(correlation_positions)
        assert [
            row.request_number for row in await evidence_of(probe, scope.track_id)
        ] == [lower, higher]

    async def test_overlapping_invocations_of_two_tickets_serialize_without_deadlock(
        self,
        world: RequestWorld,
        fake: FakeRequests,
        units: UnitSessions,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Two Tickets' scopes share an existing request and a new one. The
        first holds both request rows (the new one inserted) before its
        action writes; the second waits on the shared existing request,
        then finds both requests and the new action committed and only
        adds its own correlations."""
        seed = RequestSeed(world)
        package = unique_package()
        cve_one = f"CVE-2099-{world.number() % 10**8:08d}"
        cve_two = f"CVE-2099-{world.number() % 10**8:08d}"
        first = await seed.track(await seed.ticket(cve_id=cve_one), package=package)
        second = await seed.track(await seed.ticket(cve_id=cve_two), package=package)
        existing, existing_action = await _correlated_review(seed, first, second)
        await seed.commit()
        new = existing + 1
        world.numbers().add(new)
        new_action = submission(package, new)
        fake.request(existing, REVIEW, existing_action)
        fake.request(new, REVIEW, new_action)
        fake.action_diff(
            new,
            new_action,
            cve_issue(cve_one),
            cve_issue(cve_two),
            codestream_package=package,
        )
        fake.quiet(package, open_submissions=[new])
        first_unit = await world.open_session()
        second_unit = await world.open_session()
        units.queued.extend(
            [
                await world.open_session(),
                first_unit,
                await world.open_session(),
                second_unit,
            ]
        )
        original = ibs_request_reconciliation._lock_actions
        paused = asyncio.Event()
        release = asyncio.Event()

        async def pausing(db: AsyncSession, request_ids: Any) -> Any:
            if db is first_unit:
                paused.set()
                await release.wait()
            return await original(db, request_ids)

        monkeypatch.setattr(ibs_request_reconciliation, "_lock_actions", pausing)

        async def invoke(target: IBSRequestScope) -> Any:
            async with fake.client() as client:
                return await reconcile_ibs_requests([target], client=client)

        one = world.start(first_unit, invoke(first))
        await asyncio.wait_for(paused.wait(), timeout=WAIT)
        two = world.start(second_unit, invoke(second))
        await assert_lock_wait(two, waiter=second_unit, blocked_by=first_unit)
        release.set()
        first_outcomes = await asyncio.wait_for(one, timeout=WAIT)
        second_outcomes = await asyncio.wait_for(two, timeout=WAIT)

        assert kinds(first_outcomes) == {first.track_id: "created"}
        assert kinds(second_outcomes) == {second.track_id: "created"}
        probe = await world.probe()
        for target in (first, second):
            assert [
                row.request_number for row in await evidence_of(probe, target.track_id)
            ] == [existing, new]
            assert await delivery_of(probe, target.track_id) == IN_PROGRESS
        actions = await probe.scalar(
            select(IBSRequestAction.id)
            .join(IBSRequest, IBSRequest.id == IBSRequestAction.ibs_request_id)
            .where(
                IBSRequest.request_number == new,
                IBSRequestAction.action_type
                == IBSRequestActionType.MAINTENANCE_INCIDENT.value,
            )
        )
        await probe.rollback()
        assert actions is not None


# ---------------------------------------------------------------------------
# Whole-scope atomicity (Algorithm step 10)
# ---------------------------------------------------------------------------


class TestScopeAtomicity:
    async def test_a_conflict_after_earlier_writes_rolls_back_the_whole_scope(
        self,
        world: RequestWorld,
        fake: FakeRequests,
        units: UnitSessions,
    ) -> None:
        """The lower request is updated first; the higher one then carries
        conflicting equal-time content: nothing of the scope is committed."""
        seed = RequestSeed(world)
        scope = await seed.track(
            await seed.ticket(), package=unique_package(), delivery=IN_PROGRESS
        )
        lower, lower_action = await _correlated_review(seed, scope)
        higher = lower + 1
        await _correlated_review(seed, scope, number=higher)
        await seed.commit()
        higher_action = submission(scope.package_name, higher)
        fake.request(lower, DECLINED, lower_action, when=LATER_WHEN)
        fake.request(higher, DECLINED, higher_action)
        fake.quiet(scope.package_name)
        unit = await world.open_session()
        units.queued.extend([await world.open_session(), unit])

        with SessionStatementRecorder(unit) as recorder, capture_logs() as logs:
            outcomes = await reconcile(fake, [scope])

        assert kinds(outcomes) == {scope.track_id: "failed"}
        assert any(
            statement.lstrip().startswith("UPDATE ibs_request ")
            for statement in recorder.statements
        )
        [entry] = logged(logs, SCOPE_FAILED)
        assert entry["reason_category"] == "conflicting_observation"
        assert entry["request_number"] == higher
        probe = await world.probe()
        rows = await request_rows(probe, [lower, higher])
        assert rows[lower][0] == REVIEW.value
        assert rows[lower][3] == WHEN_AT
        assert await delivery_of(probe, scope.track_id) == IN_PROGRESS

    async def test_every_write_is_flushed_before_the_commit(
        self,
        world: RequestWorld,
        fake: FakeRequests,
        units: UnitSessions,
    ) -> None:
        scope, _ = await _negative_scope(world, fake)
        pending: list[bool] = []

        def check(session: Session) -> None:
            pending.append(bool(session.new or session.dirty or session.deleted))

        units.before_commit = check

        outcomes = await reconcile(fake, [scope])

        assert kinds(outcomes) == {scope.track_id: "updated"}
        assert pending == [False]
