"""Concurrency tests of the setting mutation `update_default_cvss_version()`
(backend/app/services/settings.py) on independent sessions and connections.

Owning specifications:

- docs/features/platform/system-settings.md (Default CVSS Version: exclusion
  from an active recalculation and the no-op; Setting Mutation Service:
  Concurrent requests and the execution fence);
- docs/features/platform/default-cvss-version-operations.md (Execution
  Fence; Admission Ordering: an effective setting change cannot overtake a
  runner protected by the fence, even when the lease is absent);
- docs/features/platform/testing-strategy.md (System Settings Mutation,
  Concurrency tests; All-CVE Recalculation Runner, Coordination integration
  tests: "a setting `PATCH` is blocked by an active runner protected by the
  fence even when Redis is empty"; Concurrency Testing; Lock-Wait
  Observation).

Every request runs on its own `db_session_factory` session and connection
and ends as the PATCH's caller-owned transaction does: it commits after the
service returns and rolls back when an exception escapes. The row-lock
order is forced, never left to timing: the first request runs the service
to completion without committing, so it holds the `FOR UPDATE` row lock
(and, for an effective change, the transaction-level fence); the second is
started as a task and proven to wait on the first with `assert_lock_wait()`
before the first commits. The waiter first loads the setting into its
identity map while the holder's change is uncommitted and keeps the
instance alive, so a stale pre-lock observation exists when the waiter
classifies.

The held fence is a real session-level fence on an independent connection
of a dedicated `NullPool` engine (another process or Celery worker); the
active-runner case pauses the real runner at its first unit boundary on the
recalculation harness (tests/support/cvss_recalculation.py) and empties
its Redis database, as `test_cvss_recalculation_admission_races.py` does
for an admission.

The workers' databases are dedicated (testing-strategy.md, Parallel
Execution), so the `default_cvss_version` singleton is not shared between
xdist workers. Committed rows are deleted explicitly at teardown and the
setting is restored or removed. Expected values are transcribed from the
specifications, never computed with the module under test.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass
from typing import Any, Literal

import pytest
import redis.asyncio as redis_asyncio
from sqlalchemy import delete, select, text, update
from sqlalchemy.ext.asyncio import (
    AsyncConnection,
    AsyncEngine,
    AsyncSession,
    create_async_engine,
)
from sqlalchemy.pool import NullPool

from app.core.enums import Role
from app.models.setting_audit_event import SettingAuditEvent
from app.models.system_setting import SystemSetting
from app.models.user import User
from app.models.user_role import UserRole
from app.services.cvss_recalculation_coordination import (
    FenceAcquireOutcome,
    FenceReleaseOutcome,
    release_execution_fence,
    try_acquire_execution_fence,
)
from app.services.settings import (
    CVSSRecalculationAlreadyInProgressError,
    update_default_cvss_version,
)
from tests.support.cvss_recalculation import (
    TARGET,
    DrainSpy,
    RecalculationHarness,
    capture_events,
    completed_run,
    connection_pid,
    fence_holders,
    recalculation_harness,
    runner_events,
    wait_until_fence_free,
)
from tests.support.cvss_recalculation_admission import WAIT, Gate, finish
from tests.support.database import assert_lock_wait, backend_pid
from tests.support.suse_cvss_races import CommittedWorld, SessionStatementRecorder
from tests.support.ticket_mutations import StatementRecorder

pytestmark = pytest.mark.integration

Factory = Callable[[], Awaitable[AsyncSession]]
Version = Literal["3.1", "4.0"]

_KEY = "default_cvss_version"
_ADVISORY = "pg_try_advisory_xact_lock"

_OTHER: dict[str, Version] = {"3.1": "4.0", "4.0": "3.1"}
_PERSISTED = [
    pytest.param("3.1", id="persisted-3.1"),
    pytest.param("4.0", id="persisted-4.0"),
]

_BACKEND_LOCKS = text("SELECT locktype, mode FROM pg_locks WHERE pid = :pid")


# ---------------------------------------------------------------------------
# Committed world
# ---------------------------------------------------------------------------


class SettingWorld(CommittedWorld):
    """Committed administrators and the `default_cvss_version` row on
    independent sessions. Teardown releases the racing sessions, deletes the
    setting audit events of its administrators and the administrators, and
    restores the setting's original value (or removes the row when this
    world created it)."""

    def __init__(self, factory: Factory, session: AsyncSession) -> None:
        super().__init__(factory, session)
        self._setting_created = False
        self._setting_original: str | None = None
        self._probe: AsyncSession | None = None

    async def admin(self, prefix: str) -> User:
        suffix = uuid.uuid4().hex[:10]
        user = User(
            username=f"{prefix}.{suffix}",
            email=f"{prefix}.{suffix}@example.com",
            password_hash="$2b$12$" + "s" * 53,
        )
        self.session.add(user)
        await self.session.flush()
        self.user_ids.append(user.id)
        self.session.add(UserRole(user_id=user.id, role=Role.ADMIN.value))
        await self.session.commit()
        return user

    async def seed(self, value: str) -> None:
        """Commit `default_cvss_version = value`, remembering how to undo it."""
        current = await _persisted(self.session)
        if current is None:
            self.session.add(SystemSetting(key=_KEY, value=value))
            self._setting_created = True
        else:
            self._setting_original = current
            await self.session.execute(
                update(SystemSetting)
                .where(SystemSetting.key == _KEY)
                .values(value=value)
            )
        await self.session.commit()

    async def committed(self) -> tuple[str | None, list[tuple[Any, ...]]]:
        """The committed setting value and every setting audit event, read
        through a fresh transaction of a dedicated probe session."""
        if self._probe is None:
            self._probe = await self.open_session()
        try:
            return await _persisted(self._probe), await _events(self._probe)
        finally:
            await self._probe.rollback()

    async def cleanup(self) -> None:
        # Release the racing sessions first: an uncommitted request may still
        # hold the setting row lock that the restore needs.
        await self._release()
        await self.session.rollback()
        await self.session.execute(
            delete(SettingAuditEvent).where(
                SettingAuditEvent.user_id.in_(self.user_ids)
            )
        )
        if self._setting_created:
            await self.session.execute(
                delete(SystemSetting).where(SystemSetting.key == _KEY)
            )
        elif self._setting_original is not None:
            await self.session.execute(
                update(SystemSetting)
                .where(SystemSetting.key == _KEY)
                .values(value=self._setting_original)
            )
        await self.session.commit()
        await super().cleanup()


@pytest.fixture
async def world(db_session_factory: Factory) -> AsyncIterator[SettingWorld]:
    created = SettingWorld(db_session_factory, await db_session_factory())
    try:
        yield created
    finally:
        await created.cleanup()


@dataclass(frozen=True)
class HeldFence:
    """The session-level execution fence held on `connection` (backend
    `pid`), with an autocommit `observer` of the same database."""

    engine: AsyncEngine
    connection: AsyncConnection
    observer: AsyncConnection
    pid: int


@pytest.fixture
async def held_fence(_engine: AsyncEngine) -> AsyncIterator[HeldFence]:
    """The fence held by an independent connection of a dedicated `NullPool`
    engine, standing in for another process or Celery worker. Teardown
    closes the connection (ending its backend, which releases a fence still
    held) and proves the fence free."""
    engine = create_async_engine(_engine.url, poolclass=NullPool)
    opened: list[AsyncConnection] = []
    try:
        connection = await engine.connect()
        opened.append(connection)
        observer = await (await engine.connect()).execution_options(
            isolation_level="AUTOCOMMIT"
        )
        opened.append(observer)
        assert (
            await try_acquire_execution_fence(connection)
            == FenceAcquireOutcome.ACQUIRED
        )
        yield HeldFence(engine, connection, observer, connection_pid(connection))
    finally:
        for connection in opened:
            await connection.close()
        await wait_until_fence_free(engine)
        await engine.dispose()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _persisted(session: AsyncSession) -> str | None:
    """The stored value, read with a column query that bypasses the
    identity map."""
    return await session.scalar(
        select(SystemSetting.value).where(SystemSetting.key == _KEY)
    )


async def _events(session: AsyncSession) -> list[tuple[Any, ...]]:
    """Every `SettingAuditEvent` as `(event_type, setting_key, user_id,
    old_value, new_value)`, in insertion (UUIDv7 `id`) order."""
    rows = await session.execute(
        select(
            SettingAuditEvent.event_type,
            SettingAuditEvent.setting_key,
            SettingAuditEvent.user_id,
            SettingAuditEvent.old_value,
            SettingAuditEvent.new_value,
        ).order_by(SettingAuditEvent.id)
    )
    return [tuple(row) for row in rows]


def _changed(user: User, old: str, new: str) -> tuple[Any, ...]:
    return ("setting_changed", _KEY, user.id, old, new)


def _advisory(statements: list[str]) -> list[str]:
    return [s for s in statements if "advisory" in s]


def _assert_effective(recorder: StatementRecorder) -> None:
    """Exactly one transaction-level fence request on this request's
    connection."""
    [request] = _advisory(recorder.statements)
    assert f"{_ADVISORY}(" in request


def _assert_no_op(recorder: StatementRecorder) -> None:
    """Only the row lock: no fence request and no write."""
    assert len(recorder.statements) == 1
    assert recorder.row_locks() == recorder.statements
    assert recorder.writes() == []


async def _request(session: AsyncSession, version: Version, user: User) -> str:
    """One PATCH's transaction: the service, then the caller's commit, or
    the caller's rollback when an exception escapes (the `DatabaseSession`
    contract)."""
    try:
        result = await update_default_cvss_version(
            session, new_version=version, acting_user_id=user.id
        )
    except Exception:
        await session.rollback()
        raise
    await session.commit()
    return result


@dataclass(frozen=True)
class Race:
    """The outcome of two serialized requests: each one's return value and
    statements, and the waiter's stale pre-lock instance."""

    first: str
    second: str
    holder: StatementRecorder
    waiter: StatementRecorder
    stale: SystemSetting


async def _race(
    world: SettingWorld,
    *,
    persisted: Version,
    first: tuple[Version, User],
    second: tuple[Version, User],
) -> Race:
    """Commit `persisted`, then run `first` to completion without committing
    (it holds the row lock), observe the setting in the waiter's session,
    start `second`, prove it waits on `first`, commit `first`, and await
    `second` (which commits)."""
    await world.seed(persisted)
    holder = await world.open_session()
    waiter = await world.open_session()

    with SessionStatementRecorder(holder) as holder_statements:
        first_result = await update_default_cvss_version(
            holder, new_version=first[0], acting_user_id=first[1].id
        )

    # A pre-lock observation: the identity map holds weak references, so the
    # strong reference keeps the stale instance alive for the service's lock
    # query to meet.
    stale = await waiter.get(SystemSetting, _KEY)
    assert stale is not None
    assert stale.value == persisted

    with SessionStatementRecorder(waiter) as waiter_statements:
        task = world.start(waiter, _request(waiter, second[0], second[1]))
        await assert_lock_wait(task, waiter=waiter, blocked_by=holder)
        await holder.commit()
        second_result = await asyncio.wait_for(task, WAIT)

    assert not holder.in_transaction()
    assert not waiter.in_transaction()
    return Race(
        first_result, second_result, holder_statements, waiter_statements, stale
    )


# ---------------------------------------------------------------------------
# Concurrent requests
# ---------------------------------------------------------------------------


class TestConcurrentRequests:
    """system-settings.md, Setting Mutation Service, Concurrent requests:
    each request classifies against the value it observes while holding the
    row lock. Two distinct administrators make the attribution of every
    event to its request observable."""

    @pytest.mark.parametrize("persisted", _PERSISTED)
    async def test_same_value_different_from_persisted_changes_once(
        self, world: SettingWorld, persisted: Version
    ) -> None:
        requested = _OTHER[persisted]
        alice = await world.admin("alice.admin")
        bob = await world.admin("bob.admin")

        race = await _race(
            world,
            persisted=persisted,
            first=(requested, alice),
            second=(requested, bob),
        )

        assert (race.first, race.second) == (requested, requested)
        _assert_effective(race.holder)
        _assert_no_op(race.waiter)
        assert race.stale.value == requested
        assert await world.committed() == (
            requested,
            [_changed(alice, persisted, requested)],
        )

    @pytest.mark.parametrize("persisted", _PERSISTED)
    async def test_same_value_equal_to_persisted_is_two_no_ops(
        self, world: SettingWorld, persisted: Version
    ) -> None:
        alice = await world.admin("alice.admin")
        bob = await world.admin("bob.admin")

        race = await _race(
            world,
            persisted=persisted,
            first=(persisted, alice),
            second=(persisted, bob),
        )

        assert (race.first, race.second) == (persisted, persisted)
        _assert_no_op(race.holder)
        _assert_no_op(race.waiter)
        assert race.stale.value == persisted
        assert await world.committed() == (persisted, [])

    @pytest.mark.parametrize("persisted", _PERSISTED)
    async def test_persisted_value_first_is_a_no_op_then_one_change(
        self, world: SettingWorld, persisted: Version
    ) -> None:
        other = _OTHER[persisted]
        alice = await world.admin("alice.admin")
        bob = await world.admin("bob.admin")

        race = await _race(
            world,
            persisted=persisted,
            first=(persisted, alice),
            second=(other, bob),
        )

        assert (race.first, race.second) == (persisted, other)
        _assert_no_op(race.holder)
        _assert_effective(race.waiter)
        assert race.stale.value == other
        assert await world.committed() == (other, [_changed(bob, persisted, other)])

    @pytest.mark.parametrize("persisted", _PERSISTED)
    async def test_other_value_first_is_two_serialized_changes(
        self, world: SettingWorld, persisted: Version
    ) -> None:
        """The waiter requests the value its stale observation still
        shows; classified against the locked-current value committed by the
        first request, it is an effective change whose `old_value` is that
        committed value."""
        other = _OTHER[persisted]
        alice = await world.admin("alice.admin")
        bob = await world.admin("bob.admin")

        race = await _race(
            world,
            persisted=persisted,
            first=(other, alice),
            second=(persisted, bob),
        )

        assert (race.first, race.second) == (other, persisted)
        _assert_effective(race.holder)
        _assert_effective(race.waiter)
        assert race.stale.value == persisted
        assert await world.committed() == (
            persisted,
            [_changed(alice, persisted, other), _changed(bob, other, persisted)],
        )


# ---------------------------------------------------------------------------
# Execution fence held by another connection
# ---------------------------------------------------------------------------


async def _backend_locks(observer: AsyncConnection, pid: int) -> list[tuple[str, str]]:
    result = await observer.execute(_BACKEND_LOCKS, {"pid": pid})
    return [(row.locktype, row.mode) for row in result]


class TestHeldExecutionFence:
    """The session-level fence held by another process's connection."""

    @pytest.mark.parametrize("persisted", _PERSISTED)
    async def test_effective_change_is_rejected_and_commits_nothing(
        self, world: SettingWorld, held_fence: HeldFence, persisted: Version
    ) -> None:
        requested = _OTHER[persisted]
        alice = await world.admin("alice.admin")
        await world.seed(persisted)
        caller = await world.open_session()

        with (
            SessionStatementRecorder(caller) as recorder,
            pytest.raises(CVSSRecalculationAlreadyInProgressError),
        ):
            await _request(caller, requested, alice)

        _assert_effective(recorder)
        assert recorder.writes() == []
        assert not caller.in_transaction()
        assert await world.committed() == (persisted, [])
        # The rolled-back request holds no lock of any kind; the fence is
        # still held by its owner alone.
        assert await _backend_locks(held_fence.observer, backend_pid(caller)) == []
        assert await fence_holders(held_fence.observer) == [held_fence.pid]

        # Once the owner releases the fence, the same request succeeds.
        assert (
            await release_execution_fence(held_fence.connection)
            == FenceReleaseOutcome.RELEASED
        )
        retry = await world.open_session()
        assert await _request(retry, requested, alice) == requested
        assert await world.committed() == (
            requested,
            [_changed(alice, persisted, requested)],
        )

    @pytest.mark.parametrize("persisted", _PERSISTED)
    async def test_no_op_succeeds_without_a_coordination_check(
        self, world: SettingWorld, held_fence: HeldFence, persisted: Version
    ) -> None:
        alice = await world.admin("alice.admin")
        await world.seed(persisted)
        caller = await world.open_session()

        with SessionStatementRecorder(caller) as recorder:
            assert await _request(caller, persisted, alice) == persisted

        _assert_no_op(recorder)
        assert not caller.in_transaction()
        assert await world.committed() == (persisted, [])
        assert await fence_holders(held_fence.observer) == [held_fence.pid]


# ---------------------------------------------------------------------------
# Active runner with an empty Redis
# ---------------------------------------------------------------------------


@pytest.fixture
async def h(
    _engine: AsyncEngine,
    redis_client: redis_asyncio.Redis,
    monkeypatch: pytest.MonkeyPatch,
) -> AsyncIterator[RecalculationHarness]:
    async with recalculation_harness(_engine.url, redis_client, monkeypatch) as harness:
        yield harness


@pytest.fixture
def drain(monkeypatch: pytest.MonkeyPatch) -> DrainSpy:
    return DrainSpy(monkeypatch)


class TestActiveRunnerFence:
    async def test_effective_change_is_rejected_by_a_running_runner_without_redis(
        self,
        # `world` is requested after `h` so that it tears down first: its
        # setting audit events reference the setting row that the harness
        # restores or removes.
        h: RecalculationHarness,
        drain: DrainSpy,
        world: SettingWorld,
    ) -> None:
        """The real runner, paused at its first unit boundary (fence held,
        no open transaction), after `FLUSHDB` emptied the worker Redis
        database: an effective change on another connection is rejected and
        commits nothing, a no-op succeeds, and the run completes for its
        unchanged target. After the run, the effective change succeeds."""
        ids = await h.world.bulk_cves(2)
        alice = await world.admin("alice.admin")
        current: Version = "3.1"
        assert await h.world.setting() == TARGET == current
        requested = _OTHER[current]
        task_id = await h.admit()
        gate = Gate()
        drain.after[0] = gate.pause

        with capture_events() as logs:
            run = asyncio.create_task(h.run(task_id))
            try:
                await gate.wait_reached()
                assert await h.fence_holders() == [h.pid]
                assert await h.redis.flushdb() is True
                assert await h.lease() is None

                effective = await world.open_session()
                assert backend_pid(effective) != h.pid
                with (
                    SessionStatementRecorder(effective) as rejected,
                    pytest.raises(CVSSRecalculationAlreadyInProgressError),
                ):
                    await asyncio.wait_for(_request(effective, requested, alice), WAIT)

                _assert_effective(rejected)
                assert rejected.writes() == []
                assert not effective.in_transaction()
                assert await world.committed() == (current, [])

                no_op = await world.open_session()
                with SessionStatementRecorder(no_op) as unchecked:
                    assert (
                        await asyncio.wait_for(_request(no_op, current, alice), WAIT)
                        == current
                    )

                _assert_no_op(unchecked)
                assert await world.committed() == (current, [])
                assert await h.fence_holders() == [h.pid]
                assert await h.lease() is None
                gate.release()
                assert await asyncio.wait_for(run, WAIT) is None
            finally:
                await finish(run, gate)

        assert runner_events(logs) == completed_run(task_id, ids[-1], unchanged=2)
        assert await h.fence_holders() == []
        assert await h.lease() is None

        after = await world.open_session()
        assert await _request(after, requested, alice) == requested
        assert await world.committed() == (
            requested,
            [_changed(alice, current, requested)],
        )
