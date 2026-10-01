"""Tests for shared database transaction and locking test helpers."""

from __future__ import annotations

import asyncio
import contextlib
import time
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from typing import Any

import pytest
from sqlalchemy import delete, select, text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import NullPool

from app.models.user import User
from tests.support.database import (
    assert_lock_wait,
    backend_pid,
    create_database,
    drop_database,
    rollback_test_scope,
)

Factory = Callable[[], Awaitable[AsyncSession]]


@pytest.mark.integration
class TestRollbackTestScope:
    async def test_preserves_setup_and_rolls_back_scoped_mutation(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        user = await user_factory(full_name=None)
        user_id = user.id

        async with rollback_test_scope(db_session):
            user.full_name = "Changed Name"
            await db_session.flush()

        refreshed = await db_session.get(User, user_id, populate_existing=True)
        assert refreshed is not None
        assert refreshed.full_name is None

    async def test_rolls_back_scoped_mutation_when_exception_escapes(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        user = await user_factory(full_name=None)
        user_id = user.id

        async def _mutate_then_fail() -> None:
            async with rollback_test_scope(db_session):
                user.full_name = "Changed Name"
                await db_session.flush()
                raise RuntimeError("simulated failure")

        with pytest.raises(RuntimeError, match="simulated failure"):
            await _mutate_then_fail()

        refreshed = await db_session.get(User, user_id, populate_existing=True)
        assert refreshed is not None
        assert refreshed.full_name is None


# ---------------------------------------------------------------------------
# Lock-wait observation (testing-strategy.md, Lock-Wait Observation)
# ---------------------------------------------------------------------------


class _Row:
    """One committed User row, deleted explicitly at teardown
    (testing-strategy.md, Concurrency Testing), plus the racing sessions
    and tasks released before the delete."""

    def __init__(self, factory: Factory, user_id: uuid.UUID) -> None:
        self._factory = factory
        self.user_id = user_id
        self._sessions: list[AsyncSession] = []
        self._tasks: list[asyncio.Task[Any]] = []

    async def session(self) -> AsyncSession:
        session = await self._factory()
        self._sessions.append(session)
        return session

    def start(self, coroutine: Any) -> asyncio.Task[Any]:
        task: asyncio.Task[Any] = asyncio.create_task(coroutine)
        self._tasks.append(task)
        return task

    async def lock(self, session: AsyncSession) -> None:
        await session.execute(
            select(User.id).where(User.id == self.user_id).with_for_update()
        )

    async def release(self) -> None:
        for task in self._tasks:
            task.cancel()
            with contextlib.suppress(Exception, asyncio.CancelledError):
                await task
        for session in self._sessions:
            with contextlib.suppress(Exception):
                await session.rollback()


@pytest.fixture
async def row(db_session_factory: Factory) -> AsyncIterator[_Row]:
    owner = await db_session_factory()
    suffix = uuid.uuid4().hex[:10]
    user = User(
        username=f"carol.lock.{suffix}",
        email=f"carol.lock.{suffix}@example.com",
        password_hash="$2b$12$" + "l" * 53,
    )
    owner.add(user)
    await owner.commit()
    fixture = _Row(db_session_factory, user.id)
    try:
        yield fixture
    finally:
        await fixture.release()
        await owner.execute(delete(User).where(User.id == user.id))
        await owner.commit()


@pytest.mark.integration
class TestBackendPid:
    async def test_matches_the_server_pid_without_starting_a_transaction(
        self, db_session_factory: Factory
    ) -> None:
        session = await db_session_factory()

        pid = backend_pid(session)

        assert not session.in_transaction()
        assert (await session.execute(text("SELECT pg_backend_pid()"))).scalar() == pid

    async def test_session_bound_to_an_engine_is_rejected(
        self, real_session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        async with real_session_factory() as session:
            with pytest.raises(TypeError, match="own connection"):
                backend_pid(session)


@pytest.mark.integration
class TestAssertLockWait:
    async def test_row_lock_wait_is_detected_promptly(self, row: _Row) -> None:
        holder = await row.session()
        waiter = await row.session()
        await row.lock(holder)
        task = row.start(row.lock(waiter))

        started = time.monotonic()
        await assert_lock_wait(task, waiter=waiter, blocked_by=holder, deadline=5)

        assert time.monotonic() - started < 2.5
        assert not task.done()
        await holder.rollback()
        await asyncio.wait_for(task, timeout=5)

    async def test_task_completing_without_a_wait_fails_immediately(
        self, row: _Row
    ) -> None:
        holder = await row.session()
        waiter = await row.session()
        await row.lock(holder)

        async def _unrelated() -> int:
            await asyncio.sleep(0.05)
            return (await waiter.execute(text("SELECT 1"))).scalar_one()

        task = row.start(_unrelated())
        started = time.monotonic()
        with pytest.raises(AssertionError, match="completed with 1 before waiting"):
            await assert_lock_wait(task, waiter=waiter, blocked_by=holder, deadline=5)

        assert time.monotonic() - started < 2.5

    async def test_task_raising_before_a_wait_fails_immediately_with_its_error(
        self, row: _Row
    ) -> None:
        holder = await row.session()
        waiter = await row.session()
        await row.lock(holder)
        error = RuntimeError("simulated failure before the lock")

        async def _fail() -> None:
            await asyncio.sleep(0.05)
            raise error

        task = row.start(_fail())
        started = time.monotonic()
        with pytest.raises(AssertionError, match="raised RuntimeError") as raised:
            await assert_lock_wait(task, waiter=waiter, blocked_by=holder, deadline=5)

        assert raised.value.__cause__ is error
        assert time.monotonic() - started < 2.5

    async def test_cancelled_task_fails_immediately(self, row: _Row) -> None:
        holder = await row.session()
        waiter = await row.session()
        await row.lock(holder)
        task = row.start(asyncio.sleep(30))
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task

        with pytest.raises(AssertionError, match="was cancelled before waiting"):
            await assert_lock_wait(task, waiter=waiter, blocked_by=holder)

    async def test_task_delayed_without_a_lock_wait_fails_at_the_deadline(
        self, row: _Row
    ) -> None:
        holder = await row.session()
        waiter = await row.session()
        await row.lock(holder)
        task = row.start(asyncio.sleep(30))

        started = time.monotonic()
        with pytest.raises(AssertionError, match="no lock wait observed") as raised:
            await assert_lock_wait(task, waiter=waiter, blocked_by=holder, deadline=0.2)

        assert time.monotonic() - started >= 0.2
        message = str(raised.value)
        assert f"waiter PID {backend_pid(waiter)}" in message
        assert f"expected blocking PIDs [{backend_pid(holder)}]" in message
        assert "pg_blocking_pids []" in message
        assert "wait_event_type 'Client'" in message
        assert "wait_event 'ClientRead'" in message
        assert not task.done()

    async def test_wait_on_a_different_session_fails_at_the_deadline(
        self, row: _Row
    ) -> None:
        holder = await row.session()
        bystander = await row.session()
        waiter = await row.session()
        await row.lock(holder)
        task = row.start(row.lock(waiter))
        await assert_lock_wait(task, waiter=waiter, blocked_by=holder)

        with pytest.raises(
            AssertionError, match=rf"pg_blocking_pids \[{backend_pid(holder)}\]"
        ) as raised:
            await assert_lock_wait(
                task, waiter=waiter, blocked_by=bystander, deadline=0.2
            )

        assert "wait_event_type 'Lock'" in str(raised.value)

    async def test_waiter_queued_behind_an_earlier_waiter_is_accepted(
        self, row: _Row
    ) -> None:
        holder = await row.session()
        first = await row.session()
        second = await row.session()
        await row.lock(holder)
        first_task = row.start(row.lock(first))
        await assert_lock_wait(first_task, waiter=first, blocked_by=holder)

        second_task = row.start(row.lock(second))
        await assert_lock_wait(second_task, waiter=second, blocked_by=(holder, first))

        # PostgreSQL reports the earlier waiter, not the holder, for the
        # queued waiter: the holder alone is not accepted.
        with pytest.raises(
            AssertionError, match=rf"pg_blocking_pids \[{backend_pid(first)}\]"
        ):
            await assert_lock_wait(
                second_task, waiter=second, blocked_by=holder, deadline=0.2
            )

        await holder.rollback()
        await asyncio.wait_for(first_task, timeout=5)
        await first.rollback()
        await asyncio.wait_for(second_task, timeout=5)

    @pytest.mark.parametrize("blockers", ["waiter", "none"])
    async def test_blocked_by_without_another_session_is_rejected(
        self, row: _Row, blockers: str
    ) -> None:
        waiter = await row.session()
        task = row.start(asyncio.sleep(30))
        blocked_by = (waiter,) if blockers == "waiter" else ()

        with pytest.raises(ValueError, match="other than the waiter"):
            await assert_lock_wait(task, waiter=waiter, blocked_by=blocked_by)


class _Server:
    """The PostgreSQL test server, inspected through this worker's database."""

    def __init__(self, engine: AsyncEngine) -> None:
        self.engine = engine
        self.url = engine.url.render_as_string(hide_password=False)

    def database_url(self, name: str) -> str:
        return self.engine.url.set(database=name).render_as_string(hide_password=False)

    async def exists(self, name: str) -> bool:
        async with self.engine.connect() as conn:
            found = await conn.scalar(
                text("SELECT count(*) FROM pg_database WHERE datname = :name"),
                {"name": name},
            )
        return bool(found == 1)


@pytest.fixture
def server(_engine: AsyncEngine) -> _Server:
    return _Server(_engine)


@pytest.fixture
async def database_name(server: _Server) -> AsyncIterator[str]:
    """A unique database name that needs quoting; dropped at teardown."""
    name = f"Parallel-Test_{uuid.uuid4().hex[:10]}"
    try:
        yield name
    finally:
        await drop_database(server.url, name)


@pytest.mark.integration
class TestCreateAndDropDatabase:
    async def test_create_makes_an_empty_database_with_the_exact_name(
        self, server: _Server, database_name: str
    ) -> None:
        await create_database(server.url, database_name)

        assert await server.exists(database_name)
        engine = create_async_engine(
            server.database_url(database_name), poolclass=NullPool
        )
        try:
            async with engine.connect() as conn:
                tables = await conn.scalar(
                    text(
                        "SELECT count(*) FROM information_schema.tables "
                        "WHERE table_schema = 'public'"
                    )
                )
        finally:
            await engine.dispose()
        assert tables == 0

    async def test_drop_removes_the_database(
        self, server: _Server, database_name: str
    ) -> None:
        await create_database(server.url, database_name)

        await drop_database(server.url, database_name)

        assert not await server.exists(database_name)

    async def test_drop_of_an_absent_database_succeeds(
        self, server: _Server, database_name: str
    ) -> None:
        await drop_database(server.url, database_name)

        assert not await server.exists(database_name)

    async def test_drop_terminates_connections_left_open(
        self, server: _Server, database_name: str
    ) -> None:
        await create_database(server.url, database_name)
        leaked = create_async_engine(
            server.database_url(database_name), poolclass=NullPool
        )
        connection = await leaked.connect()
        try:
            await connection.execute(text("SELECT 1"))

            await drop_database(server.url, database_name)

            assert not await server.exists(database_name)
        finally:
            with contextlib.suppress(Exception):
                await connection.close()
            await leaked.dispose()
