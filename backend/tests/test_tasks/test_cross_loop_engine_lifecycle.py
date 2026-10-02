"""Regression tests: pooled connections must not cross Celery
event-loop boundaries.

See `docs/conventions.md` (Cross-loop pooled connection lifecycle) and
`docs/features/platform/testing-strategy.md` (Cross-Loop Engine
Lifecycle) for the contract under test.

A process-lifetime SQLAlchemy engine using the default pooled
connection implementation must not let a connection survive the
`asyncio.run()` event loop that checked it out — SQLAlchemy documents
this explicitly (see "Using multiple asyncio event loops",
https://docs.sqlalchemy.org/en/20/orm/extensions/asyncio.html). Before
the fix (awaiting `engine.dispose()` before the invocation's
`asyncio.run()` loop closes), a second sequential invocation of the
real synchronous Celery wrapper — the scenario a long-lived prefork
worker child repeats indefinitely — reproduces SQLAlchemy's cross-loop
`RuntimeError`/`InterfaceError`.

Every test in this module is Tier 2 (integration): each exercises a
real pooled engine against the shared test PostgreSQL server. None
requires a Celery broker or worker process — the failure is a
SQLAlchemy/asyncio event-loop invariant, reproducible directly by
calling the production synchronous entry point twice in the same test
process.
"""

from __future__ import annotations

import asyncio
from uuid import uuid4

import pytest
from sqlalchemy import delete, text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

import app.services.base_fetcher as base_fetcher_module
from app.models.fetcher_config import FetcherConfig
from app.models.fetcher_run import FetcherRun
from app.services.base_fetcher import FETCHER_REGISTRY, BaseFetcher
from app.tasks import fetchers as fetchers_module
from app.tasks import session_cleanup


@pytest.mark.integration
def test_cleanup_sessions_wrapper_survives_two_consecutive_event_loops(
    _engine: AsyncEngine,  # noqa: PT019 — value used below (.url), not just for setup
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Two sequential invocations of the real `cleanup_sessions`
    synchronous wrapper — each its own `asyncio.run()` event loop —
    both succeed against one shared, pooled engine.

    A dedicated engine (not the session-scoped `_engine` used by the
    rest of the suite) is required here: this test needs a pool that
    is genuinely reused and disposed across two independent event
    loops, which must not be entangled with the connection pytest-
    asyncio's own long-lived loop holds open via `_engine`/`db_session`
    for the remainder of the test session.
    """
    dedicated_engine = create_async_engine(
        _engine.url.render_as_string(hide_password=False), echo=False
    )
    dedicated_factory = async_sessionmaker(
        dedicated_engine, class_=AsyncSession, expire_on_commit=False
    )
    monkeypatch.setattr(session_cleanup, "engine", dedicated_engine)
    monkeypatch.setattr(session_cleanup, "async_session_factory", dedicated_factory)

    try:
        # First invocation: opens its own event loop, deletes zero
        # eligible sessions, commits, and — per the fix — disposes the
        # pool before this loop closes.
        first_result = session_cleanup._cleanup_sessions_sync()

        # Second invocation: a brand-new event loop. Before the fix,
        # the pool would still hold a connection bound to the first
        # (now-closed) loop, and checking it out here would raise
        # `RuntimeError: ... attached to a different loop`.
        second_result = session_cleanup._cleanup_sessions_sync()
    finally:
        asyncio.run(dedicated_engine.dispose())

    assert isinstance(first_result, int)
    assert isinstance(second_result, int)


@pytest.mark.integration
def test_run_fetcher_wrapper_survives_two_consecutive_event_loops(
    _engine: AsyncEngine,  # noqa: PT019 — value used below (.url), not just for setup
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Two sequential invocations of the real `run_fetcher` synchronous
    wrapper — each its own `asyncio.run()` event loop — both succeed
    against one shared, pooled engine.

    Unlike `cleanup_sessions` (a single session per invocation),
    `run_fetcher_async` opens at least two independent sessions per
    invocation: the acquisition session in `app/tasks/fetchers.py`, and
    the settings/cursor/execution/finalization sessions
    `BaseFetcher.run()` opens via the module-level
    `async_session_factory` reference in `app/services/base_fetcher.py`
    (see that module's docstring under "run() lifecycle"). Both module
    references are redirected to the same dedicated pooled engine so
    the fix's disposal must reclaim every connection this richer,
    multi-session invocation shape can check out — not just the single
    one `cleanup_sessions` exercises.
    """
    fetcher_name = "test_cross_loop_probe_fetcher"

    class _FakeRequest:
        timelimit = (3600, 3420)

    class _FakeTask:
        """Minimal stand-in for the bound Celery Task instance (`self`),
        carrying only the `request.timelimit` attribute
        `_run_fetcher_sync` reads."""

        request = _FakeRequest()

    class _ProbeFetcher(BaseFetcher):
        name = fetcher_name
        description = "Cross-loop lifecycle regression probe (no-op execute)"
        default_schedule = "0 * * * *"

        async def execute(self, session: AsyncSession) -> None:
            pass

    dedicated_engine = create_async_engine(
        _engine.url.render_as_string(hide_password=False), echo=False
    )
    dedicated_factory = async_sessionmaker(
        dedicated_engine, class_=AsyncSession, expire_on_commit=False
    )

    async def _seed_and_drain() -> None:
        async with dedicated_factory() as session:
            session.add(FetcherConfig(fetcher_name=fetcher_name))
            await session.commit()
        # Drain the seeding connection from the pool before the first
        # real invocation opens its own event loop below — otherwise
        # the pool would hand out a connection bound to *this* loop,
        # a setup artifact unrelated to the fix under test.
        await dedicated_engine.dispose()

    async def _cleanup() -> None:
        async with dedicated_factory() as session:
            await session.execute(
                delete(FetcherRun).where(FetcherRun.fetcher_name == fetcher_name)
            )
            await session.execute(
                delete(FetcherConfig).where(FetcherConfig.fetcher_name == fetcher_name)
            )
            await session.commit()
        await dedicated_engine.dispose()

    monkeypatch.setattr(fetchers_module, "engine", dedicated_engine)
    monkeypatch.setattr(fetchers_module, "async_session_factory", dedicated_factory)
    monkeypatch.setattr(base_fetcher_module, "async_session_factory", dedicated_factory)

    try:
        asyncio.run(_seed_and_drain())

        # First invocation: opens its own event loop, acquires and
        # executes the run, and — per the fix — disposes the pool
        # before this loop closes.
        fetchers_module._run_fetcher_sync(_FakeTask(), fetcher_name)

        # Second invocation: a brand-new event loop. Before the fix,
        # the pool would still hold a connection bound to the first
        # (now-closed) loop, and checking it out here would raise
        # `RuntimeError: ... attached to a different loop`.
        fetchers_module._run_fetcher_sync(_FakeTask(), fetcher_name)
    finally:
        FETCHER_REGISTRY.pop(fetcher_name, None)
        asyncio.run(_cleanup())


@pytest.mark.integration
@pytest.mark.usefixtures("isolated_fetcher_registries")
def test_run_catch_up_wrapper_survives_two_consecutive_event_loops(
    _engine: AsyncEngine,  # noqa: PT019 — value used below (.url), not just for setup
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Two sequential invocations of the real `run_catch_up` synchronous
    wrapper — each its own `asyncio.run()` event loop — both succeed
    against one shared, pooled engine.

    `run_catch_up_async` opens two sessions per invocation through the
    module-level `async_session_factory` reference in
    `app/tasks/fetchers.py`: the enabled read, then the caller-owned
    session passed to `catch_up()`. The test-only fetcher's `catch_up()`
    runs a trivial query through that session, so both sessions check a
    connection out of the dedicated pool on every invocation. Celery
    retries are also new invocations in the same worker child, so the
    same disposal protects them.
    """
    fetcher_name = f"test_cross_loop_catch_up_probe_{uuid4().hex}"
    probe_ticket_id = str(uuid4())
    executed: list[str] = []

    class _FakeRequest:
        retries = 0

    class _FakeTask:
        """Minimal stand-in for the bound Celery Task instance (`self`),
        carrying only what `_run_catch_up_sync` reads."""

        request = _FakeRequest()

        def retry(self, **kwargs: object) -> BaseException:
            raise AssertionError(f"run_catch_up must not retry: {kwargs!r}")

    class _CatchUpProbeFetcher(BaseFetcher):
        name = fetcher_name
        description = "Cross-loop lifecycle regression probe (SELECT 1 catch-up)"
        default_schedule = "0 * * * *"
        participates_in_catch_up = True

        async def execute(self, session: AsyncSession) -> None:
            pass

        async def catch_up(self, ticket_id: str, session: AsyncSession) -> None:
            await session.execute(text("SELECT 1"))
            executed.append(ticket_id)

    dedicated_engine = create_async_engine(
        _engine.url.render_as_string(hide_password=False), echo=False
    )
    dedicated_factory = async_sessionmaker(
        dedicated_engine, class_=AsyncSession, expire_on_commit=False
    )

    async def _seed_and_drain() -> None:
        async with dedicated_factory() as session:
            session.add(FetcherConfig(fetcher_name=fetcher_name))
            await session.commit()
        # Drain the seeding connection so the first real invocation does
        # not receive a connection bound to this setup loop.
        await dedicated_engine.dispose()

    async def _cleanup() -> None:
        async with dedicated_factory() as session:
            await session.execute(
                delete(FetcherConfig).where(FetcherConfig.fetcher_name == fetcher_name)
            )
            await session.commit()
        await dedicated_engine.dispose()

    monkeypatch.setattr(fetchers_module, "engine", dedicated_engine)
    monkeypatch.setattr(fetchers_module, "async_session_factory", dedicated_factory)

    try:
        asyncio.run(_seed_and_drain())

        # First invocation: its own event loop; disposes the pool before
        # the loop closes.
        fetchers_module._run_catch_up_sync(_FakeTask(), fetcher_name, probe_ticket_id)

        # Second invocation: a brand-new event loop. Without disposal the
        # pool would hand out a connection bound to the first (closed)
        # loop.
        fetchers_module._run_catch_up_sync(_FakeTask(), fetcher_name, probe_ticket_id)
    finally:
        asyncio.run(_cleanup())

    assert executed == [probe_ticket_id, probe_ticket_id]
