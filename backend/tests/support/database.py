"""Shared test-only helpers for database transaction and locking tests.

See docs/features/platform/testing-strategy.md (Rollback Within a Test) for
the savepoint contract of `rollback_test_scope()`, and (Concurrency Testing,
Lock-Wait Observation) for the lock-wait proof of `assert_lock_wait()`.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import AsyncIterator, Iterable
from contextlib import asynccontextmanager
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncSession

LOCK_WAIT_DEADLINE = 5.0
"""Default bound, in seconds, on detecting a lock wait that never happens."""

_POLL_INTERVAL = 0.01


@asynccontextmanager
async def rollback_test_scope(session: AsyncSession) -> AsyncIterator[None]:
    """Preserve existing setup and roll back all work performed in the scope.

    The shared ``db_session`` fixture joins an external transaction using
    ``join_transaction_mode="create_savepoint"``. Committing here releases the
    current setup savepoint without committing the external transaction. Work
    in the context starts a new savepoint, which is rolled back on exit.

    Code inside the scope must not commit.
    """
    await session.commit()
    try:
        yield
    finally:
        await session.rollback()


def _connection(session: AsyncSession) -> AsyncConnection:
    bind = session.bind
    if not isinstance(bind, AsyncConnection):
        raise TypeError(
            "lock-wait observation needs a session bound to its own connection "
            f"(db_session_factory), not {type(bind).__name__}"
        )
    return bind


def backend_pid(session: AsyncSession) -> int:
    """The PostgreSQL backend PID of `session`'s connection.

    Read from the driver connection without a round trip, so it neither
    starts a transaction nor interferes with a statement the session is
    currently running."""
    connection = _connection(session).sync_connection
    if connection is None:
        raise TypeError("the session's connection has not been started")
    driver_connection = connection.connection.driver_connection
    if driver_connection is None:
        raise TypeError("the session's connection has no driver connection")
    pid: int = driver_connection.get_server_pid()
    return pid


def _fail_if_done(task: asyncio.Task[Any], waiter_pid: int) -> None:
    if not task.done():
        return
    prefix = f"waiter task (backend PID {waiter_pid})"
    if task.cancelled():
        raise AssertionError(f"{prefix} was cancelled before waiting on a lock")
    exception = task.exception()
    if exception is not None:
        raise AssertionError(
            f"{prefix} raised {exception!r} before waiting on a lock"
        ) from exception
    raise AssertionError(
        f"{prefix} completed with {task.result()!r} before waiting on a lock"
    )


async def assert_lock_wait(
    task: asyncio.Task[Any],
    *,
    waiter: AsyncSession,
    blocked_by: AsyncSession | Iterable[AsyncSession],
    deadline: float = LOCK_WAIT_DEADLINE,
) -> None:
    """Prove that `task`, running on `waiter`, waits on a PostgreSQL lock
    held by `blocked_by`.

    Polls `pg_blocking_pids()` for the waiter's backend from a separate
    autocommit connection until it reports a `blocked_by` session's PID.
    Pass several sessions when the waiter may be queued behind an earlier
    waiter of the same row rather than directly behind the holder. Fails
    immediately when the task finishes first, and at the monotonic
    `deadline` with the waiter's `pg_stat_activity` wait event otherwise.
    The task is never cancelled."""
    holders = (blocked_by,) if isinstance(blocked_by, AsyncSession) else blocked_by
    waiter_pid = backend_pid(waiter)
    holder_pids = {backend_pid(holder) for holder in holders}
    if not holder_pids or waiter_pid in holder_pids:
        raise ValueError("blocked_by must name sessions other than the waiter")

    blocking: list[int] = []
    async with _connection(waiter).engine.connect() as connection:
        observer = await connection.execution_options(isolation_level="AUTOCOMMIT")
        limit = time.monotonic() + deadline
        while True:
            _fail_if_done(task, waiter_pid)
            result = await observer.execute(
                text("SELECT pg_blocking_pids(:pid)"), {"pid": waiter_pid}
            )
            blocking = list(result.scalar_one())
            if holder_pids.intersection(blocking):
                return
            if time.monotonic() >= limit:
                break
            await asyncio.sleep(_POLL_INTERVAL)
        activity = (
            await observer.execute(
                text(
                    "SELECT state, wait_event_type, wait_event "
                    "FROM pg_stat_activity WHERE pid = :pid"
                ),
                {"pid": waiter_pid},
            )
        ).one_or_none()

    _fail_if_done(task, waiter_pid)
    state, wait_event_type, wait_event = activity or (None, None, None)
    raise AssertionError(
        f"no lock wait observed within {deadline} s: waiter PID {waiter_pid}, "
        f"expected blocking PIDs {sorted(holder_pids)}, "
        f"pg_blocking_pids {blocking}, state {state!r}, "
        f"wait_event_type {wait_event_type!r}, wait_event {wait_event!r}"
    )
