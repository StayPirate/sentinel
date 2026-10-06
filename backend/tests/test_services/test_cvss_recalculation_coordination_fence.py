"""Tests for the CVSS recalculation execution fence helpers
`try_acquire_execution_fence()` and `release_execution_fence()`
(backend/app/services/cvss_recalculation_coordination.py).

Owning specifications:

- docs/features/platform/default-cvss-version-operations.md (Execution
  Fence; Coordination Resources);
- docs/features/platform/system-settings.md (Default CVSS Version: the
  same identifier in transaction-level, non-blocking form);
- docs/features/platform/testing-strategy.md (Concurrency Testing;
  All-CVE Recalculation Runner, Complete-run coordination; Parallel
  Execution);
- issue #835 decisions T2 (uncertain acquisition invalidates), T3 (no open
  transaction), and T4 (invalidation failure during release).

Every test uses independent connections of the shared test engine (one
PostgreSQL session each), because a session-level advisory lock is
re-entrant within one session. Advisory locks are scoped to the current
database, so pytest-xdist workers, each on its own database, never
contend. Teardown invalidates every connection a test opened, which ends
its backend session and so releases any fence it still holds, and then
proves the fence is free: no test leaves a held fence in the pool.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Awaitable, Callable, Iterator
from contextlib import contextmanager
from typing import Any

import pytest
from sqlalchemy import BigInteger, bindparam, event, text
from sqlalchemy.exc import OperationalError
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine, create_async_engine

from app.services.cvss_recalculation_coordination import (
    EXECUTION_FENCE_ID,
    FenceAcquireOutcome,
    FenceReleaseOutcome,
    release_execution_fence,
    try_acquire_execution_fence,
)

Connect = Callable[[], Awaitable[AsyncConnection]]

_DEADLINE = 5.0
_POLL_INTERVAL = 0.01

_FENCE_ID = bindparam("fence_id", EXECUTION_FENCE_ID, type_=BigInteger)

_TRY_XACT_LOCK = text("SELECT pg_try_advisory_xact_lock(:fence_id)").bindparams(
    _FENCE_ID
)

_FENCE_HOLDERS = text(
    "SELECT pid FROM pg_locks "
    "WHERE locktype = 'advisory' AND granted AND mode = 'ExclusiveLock' "
    "AND database = (SELECT oid FROM pg_database WHERE datname = current_database()) "
    "AND classid::bigint = :fence_id >> 32 "
    "AND objid::bigint = :fence_id & 4294967295 "
    "AND objsubid = 1"
).bindparams(_FENCE_ID)
"""The backend PIDs holding the session-level fence: a bigint advisory key
is reported as its high and low 32 bits with `objsubid` 1."""


def _database_error() -> OperationalError:
    return OperationalError(
        "SELECT pg_advisory_unlock($1::BIGINT)",
        None,
        ConnectionResetError("fictional connection reset by peer"),
    )


_ERRORS = [
    pytest.param(_database_error, id="database-error"),
    pytest.param(lambda: TimeoutError("fictional statement timeout"), id="timeout"),
    pytest.param(asyncio.CancelledError, id="cancelled"),
]


@pytest.fixture
async def connect(_engine: AsyncEngine) -> AsyncIterator[Connect]:
    """Open independent connections of the shared test engine; teardown
    invalidates and closes each one, then proves the fence is free."""
    opened: list[AsyncConnection] = []

    async def _connect() -> AsyncConnection:
        connection = await _engine.connect()
        opened.append(connection)
        return connection

    try:
        yield _connect
    finally:
        for connection in opened:
            if connection.closed:
                continue
            if not connection.invalidated:
                await connection.invalidate()
            await connection.close()
        observer = await _engine.connect()
        try:
            await _wait_until_fence_free(observer)
        finally:
            await observer.close()


async def _backend_pid(connection: AsyncConnection) -> int:
    """The backend PID, read from the driver without a round trip."""
    raw = await connection.get_raw_connection()
    driver: Any = raw.driver_connection
    pid: int = driver.get_server_pid()
    return pid


async def _fence_holders(observer: AsyncConnection) -> list[int]:
    result = await observer.execute(_FENCE_HOLDERS)
    holders: list[int] = list(result.scalars())
    await observer.rollback()
    return holders


async def _try_transaction_level(observer: AsyncConnection) -> bool:
    """Request the fence in transaction-level, non-blocking form, as the
    setting mutation does, then roll back (releasing it if granted)."""
    result = await observer.execute(_TRY_XACT_LOCK)
    granted = bool(result.scalar_one())
    await observer.rollback()
    return granted


async def _wait_until_fence_free(observer: AsyncConnection) -> None:
    """Bounded poll: a closed or terminated backend releases its locks when
    it exits, which PostgreSQL completes asynchronously."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + _DEADLINE
    while not await _try_transaction_level(observer):
        assert loop.time() < deadline, "the execution fence was never released"
        await asyncio.sleep(_POLL_INTERVAL)


async def _assert_fresh_acquisition(connect: Connect) -> None:
    """Prove the fence is free: wait for it, then acquire and release it on
    a connection that did not hold it."""
    fresh = await connect()
    await _wait_until_fence_free(fresh)
    assert await try_acquire_execution_fence(fresh) is FenceAcquireOutcome.ACQUIRED
    assert await release_execution_fence(fresh) is FenceReleaseOutcome.RELEASED
    await fresh.close()


@contextmanager
def _failing(
    target: AsyncConnection,
    method: str,
    error: BaseException,
    *,
    after_delegating: bool = False,
) -> Iterator[None]:
    """Make `target.<method>` raise `error`, before the real call or after
    it completed; every other connection is unaffected."""
    original = getattr(AsyncConnection, method)

    async def _replacement(self: AsyncConnection, *args: Any, **kwargs: Any) -> Any:
        if self is not target:
            return await original(self, *args, **kwargs)
        if after_delegating:
            await original(self, *args, **kwargs)
        raise error

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(AsyncConnection, method, _replacement)
        yield


@pytest.mark.integration
class TestTryAcquireExecutionFence:
    async def test_free_fence_returns_acquired_and_holds_it_without_transaction(
        self, connect: Connect
    ) -> None:
        holder = await connect()
        observer = await connect()
        pid = await _backend_pid(holder)

        outcome = await try_acquire_execution_fence(holder)

        assert outcome is FenceAcquireOutcome.ACQUIRED
        assert holder.in_transaction() is False
        assert await _fence_holders(observer) == [pid]
        assert await release_execution_fence(holder) is FenceReleaseOutcome.RELEASED

    async def test_second_connection_returns_busy_without_waiting(
        self, connect: Connect
    ) -> None:
        first = await connect()
        second = await connect()
        observer = await connect()
        first_pid = await _backend_pid(first)
        assert await try_acquire_execution_fence(first) is FenceAcquireOutcome.ACQUIRED

        outcome = await asyncio.wait_for(try_acquire_execution_fence(second), _DEADLINE)

        # It returned while the first connection still holds the fence, so
        # it cannot have waited for the release.
        assert outcome is FenceAcquireOutcome.BUSY
        assert second.in_transaction() is False
        assert await _fence_holders(observer) == [first_pid]
        assert second.invalidated is False

        assert await release_execution_fence(first) is FenceReleaseOutcome.RELEASED
        assert await try_acquire_execution_fence(second) is FenceAcquireOutcome.ACQUIRED
        assert await release_execution_fence(second) is FenceReleaseOutcome.RELEASED

    async def test_repeated_busy_attempts_never_acquire_while_held(
        self, connect: Connect
    ) -> None:
        holder = await connect()
        contender = await connect()
        assert await try_acquire_execution_fence(holder) is FenceAcquireOutcome.ACQUIRED

        for _ in range(3):
            assert (
                await try_acquire_execution_fence(contender) is FenceAcquireOutcome.BUSY
            )

        assert await release_execution_fence(holder) is FenceReleaseOutcome.RELEASED
        await _assert_fresh_acquisition(connect)

    async def test_open_transaction_raises_runtime_error_without_statement(
        self, connect: Connect
    ) -> None:
        connection = await connect()
        observer = await connect()
        transaction = await connection.begin()
        await connection.execute(text("SELECT 1"))
        statements: list[str] = []

        def _record(*args: Any) -> None:
            statements.append(str(args[2]))

        sync_connection = connection.sync_connection
        assert sync_connection is not None
        event.listen(sync_connection, "before_cursor_execute", _record)
        try:
            with pytest.raises(RuntimeError, match="open transaction"):
                await try_acquire_execution_fence(connection)
        finally:
            event.remove(sync_connection, "before_cursor_execute", _record)

        assert statements == []
        assert connection.in_transaction() is True
        assert connection.get_transaction() is transaction
        assert connection.invalidated is False
        assert await _fence_holders(observer) == []
        await transaction.rollback()

    @pytest.mark.parametrize("make_error", _ERRORS)
    @pytest.mark.parametrize(
        ("method", "after_delegating"),
        [
            pytest.param("execute", False, id="before-lock-request"),
            pytest.param("execute", True, id="after-lock-granted"),
            pytest.param("commit", False, id="commit-after-lock-granted"),
        ],
    )
    async def test_error_propagates_unchanged_invalidates_and_frees_fence(
        self,
        connect: Connect,
        make_error: Callable[[], BaseException],
        method: str,
        after_delegating: bool,
    ) -> None:
        """Decision T2: the lock may have been granted before the error, so
        the connection is invalidated (releasing it) and the error is never
        reported as busy."""
        connection = await connect()
        error = make_error()

        with (
            _failing(connection, method, error, after_delegating=after_delegating),
            pytest.raises(type(error)) as excinfo,
        ):
            await try_acquire_execution_fence(connection)

        assert excinfo.value is error
        assert connection.invalidated is True
        await _assert_fresh_acquisition(connect)

    async def test_lock_granted_before_commit_error_is_held_until_invalidation(
        self, connect: Connect
    ) -> None:
        """Without the invalidation, the session would keep the lock that
        `pg_try_advisory_lock` granted before the failing commit."""
        connection = await connect()
        observer = await connect()
        pid = await _backend_pid(connection)
        error = _database_error()
        held_during_failure: list[int] = []

        original = AsyncConnection.invalidate

        async def _observe_then_invalidate(self: AsyncConnection) -> None:
            if self is connection:
                held_during_failure.extend(await _fence_holders(observer))
            await original(self)

        with (
            pytest.MonkeyPatch.context() as patch,
            _failing(connection, "commit", error),
        ):
            patch.setattr(AsyncConnection, "invalidate", _observe_then_invalidate)
            with pytest.raises(OperationalError) as excinfo:
                await try_acquire_execution_fence(connection)

        assert excinfo.value is error
        assert held_during_failure == [pid]
        assert connection.invalidated is True
        await _assert_fresh_acquisition(connect)


@pytest.mark.integration
class TestReleaseExecutionFence:
    async def test_held_fence_returns_released_and_frees_it_without_transaction(
        self, connect: Connect
    ) -> None:
        holder = await connect()
        observer = await connect()
        assert await try_acquire_execution_fence(holder) is FenceAcquireOutcome.ACQUIRED

        outcome = await release_execution_fence(holder)

        assert outcome is FenceReleaseOutcome.RELEASED
        assert holder.in_transaction() is False
        assert holder.invalidated is False
        assert await _fence_holders(observer) == []
        await _assert_fresh_acquisition(connect)

    async def test_released_connection_may_return_to_pool(
        self, connect: Connect
    ) -> None:
        holder = await connect()
        assert await try_acquire_execution_fence(holder) is FenceAcquireOutcome.ACQUIRED
        assert await release_execution_fence(holder) is FenceReleaseOutcome.RELEASED

        await holder.close()

        await _assert_fresh_acquisition(connect)

    async def test_transaction_level_attempt_fails_while_held_succeeds_after(
        self, connect: Connect
    ) -> None:
        holder = await connect()
        third = await connect()
        assert await try_acquire_execution_fence(holder) is FenceAcquireOutcome.ACQUIRED

        assert await _try_transaction_level(third) is False

        assert await release_execution_fence(holder) is FenceReleaseOutcome.RELEASED
        assert await _try_transaction_level(third) is True
        assert third.in_transaction() is False

    @pytest.mark.parametrize("holds_fence", [False, True])
    async def test_open_transaction_raises_runtime_error_without_statement(
        self, connect: Connect, holds_fence: bool
    ) -> None:
        connection = await connect()
        observer = await connect()
        pid = await _backend_pid(connection)
        if holds_fence:
            assert (
                await try_acquire_execution_fence(connection)
                is FenceAcquireOutcome.ACQUIRED
            )
        transaction = await connection.begin()
        await connection.execute(text("SELECT 1"))
        statements: list[str] = []

        def _record(*args: Any) -> None:
            statements.append(str(args[2]))

        sync_connection = connection.sync_connection
        assert sync_connection is not None
        event.listen(sync_connection, "before_cursor_execute", _record)
        try:
            with pytest.raises(RuntimeError, match="open transaction"):
                await release_execution_fence(connection)
        finally:
            event.remove(sync_connection, "before_cursor_execute", _record)

        assert statements == []
        assert connection.in_transaction() is True
        assert connection.get_transaction() is transaction
        assert connection.invalidated is False
        assert await _fence_holders(observer) == ([pid] if holds_fence else [])
        await transaction.rollback()
        if holds_fence:
            assert (
                await release_execution_fence(connection)
                is FenceReleaseOutcome.RELEASED
            )

    async def test_definitive_false_returns_not_confirmed_and_invalidates(
        self, connect: Connect
    ) -> None:
        """`pg_advisory_unlock` returns false (with a server WARNING) for a
        session that does not hold the fence; another holder keeps it."""
        holder = await connect()
        stranger = await connect()
        observer = await connect()
        holder_pid = await _backend_pid(holder)
        assert await try_acquire_execution_fence(holder) is FenceAcquireOutcome.ACQUIRED

        outcome = await release_execution_fence(stranger)

        assert outcome is FenceReleaseOutcome.NOT_CONFIRMED
        assert stranger.invalidated is True
        assert await _fence_holders(observer) == [holder_pid]
        assert await release_execution_fence(holder) is FenceReleaseOutcome.RELEASED

    async def test_definitive_false_with_failing_invalidate_still_not_confirmed(
        self, connect: Connect
    ) -> None:
        """Decision T4: a failure of `invalidate()` itself is suppressed."""
        connection = await connect()

        with _failing(connection, "invalidate", RuntimeError("fictional failure")):
            outcome = await release_execution_fence(connection)

        assert outcome is FenceReleaseOutcome.NOT_CONFIRMED

    @pytest.mark.parametrize("make_error", _ERRORS)
    @pytest.mark.parametrize(
        ("method", "after_delegating"),
        [
            pytest.param("execute", False, id="before-unlock"),
            pytest.param("execute", True, id="after-unlock"),
            pytest.param("commit", False, id="commit-after-unlock"),
        ],
    )
    async def test_error_propagates_unchanged_invalidates_and_frees_fence(
        self,
        connect: Connect,
        make_error: Callable[[], BaseException],
        method: str,
        after_delegating: bool,
    ) -> None:
        """Before the unlock ran, only the invalidation can free the fence;
        the fresh acquisition proves it did."""
        holder = await connect()
        observer = await connect()
        holder_pid = await _backend_pid(holder)
        assert await try_acquire_execution_fence(holder) is FenceAcquireOutcome.ACQUIRED
        assert await _fence_holders(observer) == [holder_pid]
        error = make_error()

        with (
            _failing(holder, method, error, after_delegating=after_delegating),
            pytest.raises(type(error)) as excinfo,
        ):
            await release_execution_fence(holder)

        assert excinfo.value is error
        assert holder.invalidated is True
        await _assert_fresh_acquisition(connect)

    async def test_invalidate_failure_during_release_error_is_suppressed(
        self, connect: Connect
    ) -> None:
        """Decision T4: the original unlock error propagates, not the
        secondary invalidation failure."""
        holder = await connect()
        assert await try_acquire_execution_fence(holder) is FenceAcquireOutcome.ACQUIRED
        error = _database_error()

        with (
            _failing(holder, "invalidate", RuntimeError("fictional failure")),
            _failing(holder, "execute", error),
            pytest.raises(OperationalError) as excinfo,
        ):
            await release_execution_fence(holder)

        assert excinfo.value is error
        # The failed invalidation left the session, and so the fence, alive.
        await holder.invalidate()
        await _assert_fresh_acquisition(connect)


@pytest.mark.integration
class TestFenceLifetime:
    async def test_close_to_pool_while_held_does_not_release_fence(
        self,
        _engine: AsyncEngine,  # noqa: PT019 — value used below (.url), not just setup
        connect: Connect,
    ) -> None:
        """The pool reset only rolls back; the session-level lock survives
        `close()`. A one-connection pool hands the same session back, which
        then releases the fence it still holds."""
        private = create_async_engine(_engine.url, pool_size=1, max_overflow=0)
        try:
            holder = await private.connect()
            pid = await _backend_pid(holder)
            assert (
                await try_acquire_execution_fence(holder)
                is FenceAcquireOutcome.ACQUIRED
            )

            await holder.close()

            observer = await connect()
            assert await try_acquire_execution_fence(observer) is (
                FenceAcquireOutcome.BUSY
            )
            assert await _try_transaction_level(observer) is False
            assert await _fence_holders(observer) == [pid]

            reused = await private.connect()
            assert await _backend_pid(reused) == pid
            assert await release_execution_fence(reused) is FenceReleaseOutcome.RELEASED
            await reused.close()
            await _assert_fresh_acquisition(connect)
        finally:
            await private.dispose()

    async def test_invalidation_releases_fence(self, connect: Connect) -> None:
        holder = await connect()
        assert await try_acquire_execution_fence(holder) is FenceAcquireOutcome.ACQUIRED

        await holder.invalidate()

        await _assert_fresh_acquisition(connect)

    async def test_backend_termination_releases_fence(self, connect: Connect) -> None:
        holder = await connect()
        terminator = await connect()
        pid = await _backend_pid(holder)
        assert await try_acquire_execution_fence(holder) is FenceAcquireOutcome.ACQUIRED

        result = await terminator.execute(
            text("SELECT pg_terminate_backend(:pid)"), {"pid": pid}
        )
        assert result.scalar_one() is True
        await terminator.commit()

        await _assert_fresh_acquisition(connect)
