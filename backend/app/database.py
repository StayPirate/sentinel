"""Database setup and session management."""

from __future__ import annotations

from collections.abc import AsyncGenerator, Awaitable, Callable
from typing import Annotated

import structlog
from fastapi import Depends
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

from app.config import settings

logger = structlog.get_logger(__name__)

engine = create_async_engine(settings.database_url, hide_parameters=True)

async_session_factory = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


class Base(DeclarativeBase):
    """Base class for all SQLAlchemy models."""

    pass


# Key under which post-commit callbacks are stashed in `AsyncSession.info`
# (a per-session, user-modifiable dict SQLAlchemy provides for exactly
# this kind of use). See `register_post_commit_callback()`.
_POST_COMMIT_CALLBACKS_KEY = "post_commit_callbacks"


def register_post_commit_callback(
    session: AsyncSession, callback: Callable[[], Awaitable[None]]
) -> None:
    """Register a callback to run after `get_db()`'s commit succeeds.

    Per `docs/conventions.md` (Transaction Hygiene Rules), network I/O
    (e.g. a Redis cache purge) must never execute before a transaction
    commits. FastAPI's `BackgroundTasks` mechanism does not guarantee
    this ordering relative to a `yield`-based dependency's post-yield
    code (empirically, `BackgroundTasks` run *before* `get_db()`'s
    post-yield `commit()` completes) — see `docs/conventions.md`:
    "The internal callback or framework mechanism used to bridge
    handler return and dependency completion is an implementation
    choice." This function is that mechanism: `get_db()` invokes every
    registered callback, best-effort, strictly after its own
    `session.commit()` succeeds. Callbacks registered on a request that
    ends in rollback (an exception escaped the handler) never run.
    """
    callbacks: list[Callable[[], Awaitable[None]]] = session.info.setdefault(
        _POST_COMMIT_CALLBACKS_KEY, []
    )
    callbacks.append(callback)


def detach_post_commit_callbacks(
    session: AsyncSession,
) -> list[Callable[[], Awaitable[None]]]:
    """Remove and return the callbacks registered on `session`.

    For a workflow owner that commits its own session instead of using
    `get_db()` (`docs/conventions.md`, Caller-Owned Service Transactions):
    after its commit succeeds it detaches the callbacks and awaits them
    once its session is closed, never after a rollback. A second call
    returns an empty list, so each callback runs at most once.
    """
    callbacks: list[Callable[[], Awaitable[None]]] = session.info.pop(
        _POST_COMMIT_CALLBACKS_KEY, []
    )
    return callbacks


async def get_db() -> AsyncGenerator[AsyncSession]:
    """Dependency that provides a database session.

    Commits exactly once after the handler succeeds, or rolls back
    exactly once when an exception escapes — see `docs/conventions.md`
    (Caller-Owned Service Transactions). On the success path only, runs
    every callback registered via `register_post_commit_callback()`,
    each independently caught and logged so one failing best-effort
    side effect never blocks the others.

    Not used directly as a route dependency — see `DatabaseSession`
    below, which pins the required `scope="function"`.
    """
    async with async_session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        else:
            for callback in session.info.get(_POST_COMMIT_CALLBACKS_KEY, []):
                try:
                    await callback()
                except Exception:
                    logger.error("post_commit_callback_failed", exc_info=True)


# Canonical route dependency for the API transaction session — see
# `docs/conventions.md` (API Transaction Dependency Scope). `get_db()` is
# a `yield`-based dependency; without an explicit `scope`, FastAPI
# defaults a `yield` dependency to `scope="request"`, whose post-yield
# code (commit/rollback/post-commit callbacks above) runs *after* the
# HTTP response has already been transmitted to the client — breaking
# the "commits before the caller can observe success" guarantee in
# `docs/conventions.md` (Caller-Owned Service Transactions). Declaring
# `scope="function"` here runs that same post-yield code before the
# response is sent, so a commit failure surfaces as a real error
# response instead of an already-decided success one.
#
# Every route (and every dependency nested under a route, e.g.
# authentication) that needs the caller-owned transaction session MUST
# use this alias instead of declaring `Depends(get_db)` inline — see
# `backend/tests/test_api_conventions.py`
# (`TestTransactionDependencyScope`) for the structural test that
# enforces this.
DatabaseSession = Annotated[AsyncSession, Depends(get_db, scope="function")]
