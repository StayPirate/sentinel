"""Shared harness of the default CVE `catch_up()` tests through the real
`run_catch_up` workflow (`app.tasks.fetchers`).

Consumers:

- `tests/test_tasks/test_run_catch_up.py` (the generic wrapper contract;
  wrapper doubles only);
- `tests/test_services/test_cve_fetcher_catch_up.py` (the default
  `BaseCVEFetcher.catch_up()` contract through `run_catch_up_async` and the
  synchronous `_run_catch_up_sync` wrapper);
- `tests/test_services/test_cve_fetcher_ingestion_composition.py` (the real
  `upsert_cve()` / `upsert_references()` ingestion finalized by the default
  catch-up).

Provided here:

- wrapper doubles: `FakeEngine` (the module-level `engine` with an
  `AsyncMock` `dispose`), `FakeTask` (the bound Celery task: `request.retries`
  and a `retry()` returning `RetryRequested`), and `FakeHttpClient`;
- `define_cve_fetcher()`, which registers a concrete test-only
  `BaseCVEFetcher` whose `fetch_single()` runs a per-test step and whose
  `commit_and_dispatch()` records, then delegates unchanged to the real
  finalizer, whether the session had pending unflushed state when
  finalization started. The consumer requests `isolated_fetcher_registries`;
- `RecordingSessions`, a substitute for a module-level `async_session_factory`
  that appends every explicit `flush`, `commit`, and `rollback` to an ordered
  event list, can make one operation raise instead, and applies optional
  per-session hooks;
- `Publications`, a substitute for `task_publication.publish_task` sharing
  the same event list, with an optional awaited hook and per-task errors;
  `watch_drain()` wraps the real Ticket convergence drain;
- `install_harness()`, which installs all of the above for one
  `run_catch_up_async` test as a `CatchUpHarness`;
- committed `FetcherConfig` seeding and `FetcherRun`/`CVESource` observation.

Nothing here computes an expectation with the module under test. All
identifiers are fictional.
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import datetime
from types import SimpleNamespace
from typing import Any, NamedTuple
from unittest.mock import AsyncMock, MagicMock

import pytest
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.enums import CVESourceType
from app.models.cve_source import CVESource
from app.models.fetcher_config import FetcherConfig
from app.models.fetcher_run import FetcherRun
from app.services import (
    base_cve_fetcher,
    package_service,
    task_publication,
    ticket_convergence_publication,
)
from app.services.base_cve_fetcher import (
    _CVE_SOURCE_TYPE_MAP,
    BaseCVEFetcher,
    CVEFetchResult,
)
from app.services.ticket_convergence_publication import RUN_TICKET_CONVERGENCE_TASK
from app.tasks import fetchers

SOURCE = CVESourceType.NVD
"""The default `cve_source_type` of a test-only fetcher."""

CONVERGE = RUN_TICKET_CONVERGENCE_TASK
RESOLVE = package_service.RESOLVE_TICKET_PACKAGES_TASK
CATCH_UP = package_service.RUN_CATCH_UP_TASK

Step = Callable[[str, AsyncSession], Awaitable[CVEFetchResult]]
"""One scripted `fetch_single(cve_id, session)` body."""


# ---------------------------------------------------------------------------
# Wrapper doubles
# ---------------------------------------------------------------------------


class FakeEngine:
    """Substitute for the module-level `engine` singleton
    (`AsyncEngine.dispose` is read-only on the real engine)."""

    def __init__(self) -> None:
        self.dispose = AsyncMock()


class RetryRequested(Exception):  # noqa: N818 — mirrors celery's `Retry`
    """Stand-in for the `celery.exceptions.Retry` that `Task.retry()`
    produces; the wrapper raises whatever `self.retry()` returns."""


class FakeTask:
    """Minimal stand-in for the bound Celery Task instance (`self`),
    carrying only what `_run_catch_up_sync` reads: `request.retries` and
    `retry()`."""

    def __init__(self, retries: int = 0) -> None:
        self.request = SimpleNamespace(retries=retries)
        self.retry = MagicMock(return_value=RetryRequested())


class FakeHttpClient:
    def __init__(self, aclose: AsyncMock) -> None:
        self.aclose = aclose


# ---------------------------------------------------------------------------
# Test-only CVE fetcher
# ---------------------------------------------------------------------------


@dataclass
class CVEProbe:
    """Observations of one test-only CVE fetcher class.

    `step` is the `fetch_single()` body; `instances` and `fetched` record
    each call's fetcher instance and CVE-ID; `flushed_at_finalization`
    records, per `commit_and_dispatch()` call, whether the session had no
    new, dirty, or deleted instance left to flush.
    """

    name: str
    events: list[str]
    step: Step | None = None
    instances: list[BaseCVEFetcher] = field(default_factory=list)
    fetched: list[str] = field(default_factory=list)
    flushed_at_finalization: list[bool] = field(default_factory=list)

    @property
    def fetcher(self) -> BaseCVEFetcher:
        """The instance of the latest `fetch_single()` call."""
        return self.instances[-1]


def define_cve_fetcher(
    events: list[str] | None = None,
    *,
    source: CVESourceType = SOURCE,
    supports: bool = True,
    fetcher_queue: str | None = None,
) -> CVEProbe:
    """Register a concrete test-only CVE fetcher owning `source`.

    The class keeps the inherited default `catch_up()` and derives
    `participates_in_catch_up` from `supports` (`supports_fetch_single`).
    A production owner of `source`, if any, is restored by
    `isolated_fetcher_registries`.
    """
    _CVE_SOURCE_TYPE_MAP.pop(source, None)
    probe = CVEProbe(
        name=f"test_cve_catch_up_{uuid.uuid4().hex[:12]}",
        events=[] if events is None else events,
    )
    probe_name = probe.name

    class _ProbeCVEFetcher(BaseCVEFetcher):
        name = probe_name
        description = "Test-only default catch-up CVE fetcher"
        default_schedule = "0 * * * *"
        cve_source_type = source
        supports_fetch_single = supports
        queue = fetcher_queue

        async def execute(self, session: AsyncSession) -> None:
            raise AssertionError("execute() is never called by catch-up")

        async def fetch_single(
            self, cve_id: str, session: AsyncSession
        ) -> CVEFetchResult:
            probe.instances.append(self)
            probe.fetched.append(cve_id)
            probe.events.append("fetch_single")
            if probe.step is None:
                raise AssertionError("fetch_single() called without a step")
            return await probe.step(cve_id, session)

        async def commit_and_dispatch(
            self, session: AsyncSession, result: CVEFetchResult
        ) -> None:
            probe.events.append("commit_and_dispatch")
            probe.flushed_at_finalization.append(
                not (session.new or session.dirty or session.deleted)
            )
            await super().commit_and_dispatch(session, result)

    return probe


def counters(fetcher: BaseCVEFetcher) -> tuple[int, int, int, int]:
    """(succeeded, created, updated, failed)."""
    return (fetcher._succeeded, fetcher._created, fetcher._updated, fetcher._failed)


# ---------------------------------------------------------------------------
# Session, publication, and drain recorders
# ---------------------------------------------------------------------------


class RecordingSessions:
    """Substitute for a module-level `async_session_factory`.

    Delegates to `factory`; every opened session's explicit `flush`,
    `commit`, and `rollback` append `f"{label}{operation}"` to `events`
    before running. An operation listed in `failures` raises that error
    instead of running (a definite failure). `hooks` instrument each opened
    session afterwards.
    """

    def __init__(
        self,
        factory: Callable[[], AsyncSession],
        events: list[str] | None = None,
        *,
        label: str = "",
    ) -> None:
        self._factory = factory
        self._label = label
        self.events: list[str] = [] if events is None else events
        self.opened: list[AsyncSession] = []
        self.failures: dict[str, BaseException] = {}
        self.hooks: list[Callable[[AsyncSession], None]] = []

    def __call__(self) -> AsyncSession:
        session = self._factory()
        for operation in ("flush", "commit", "rollback"):
            self._record(session, operation)
        for hook in self.hooks:
            hook(session)
        self.opened.append(session)
        return session

    def _record(self, session: AsyncSession, operation: str) -> None:
        original = getattr(session, operation)

        async def recorded(*args: Any, **kwargs: Any) -> None:
            self.events.append(f"{self._label}{operation}")
            if operation in self.failures:
                raise self.failures[operation]
            await original(*args, **kwargs)

        setattr(session, operation, recorded)

    def install(self, monkeypatch: pytest.MonkeyPatch, module: object) -> None:
        monkeypatch.setattr(module, "async_session_factory", self)


PublishHook = Callable[[dict[str, Any]], Awaitable[None]]


@dataclass
class Publications:
    """Substitute for `task_publication.publish_task`.

    Each call is recorded as `{"task_name": ..., **options}` and appends
    `publish:<task_name>` to `events`; `before` is awaited next, then the
    call raises `errors[task_name]` when present.
    """

    events: list[str] = field(default_factory=list)
    calls: list[dict[str, Any]] = field(default_factory=list)
    errors: dict[str, BaseException] = field(default_factory=dict)
    before: PublishHook | None = None

    async def __call__(self, task_name: str, **options: Any) -> None:
        call = {"task_name": task_name, **options}
        self.calls.append(call)
        self.events.append(f"publish:{task_name}")
        if self.before is not None:
            await self.before(call)
        if task_name in self.errors:
            raise self.errors[task_name]

    def published(self, task_name: str) -> list[dict[str, Any]]:
        """The `kwargs` of every call of `task_name`, in order."""
        return [call["kwargs"] for call in self.calls if call["task_name"] == task_name]


def watch_drain(monkeypatch: pytest.MonkeyPatch, events: list[str]) -> None:
    """Append `drain` to `events` before each real convergence drain."""
    real_drain = ticket_convergence_publication.drain_ticket_convergence

    async def drain(session: AsyncSession) -> None:
        events.append("drain")
        await real_drain(session)

    monkeypatch.setattr(
        ticket_convergence_publication, "drain_ticket_convergence", drain
    )


# ---------------------------------------------------------------------------
# Committed configuration and observation
# ---------------------------------------------------------------------------


@dataclass
class CatchUpHarness:
    """The substitutes of one `run_catch_up_async` test sharing `events`.

    `sessions` replaces `app.tasks.fetchers.async_session_factory` (the
    enabled read, then the caller-owned catch-up session), `status` replaces
    `app.services.base_cve_fetcher.async_session_factory` (isolated status
    sessions, recorded with the `status:` prefix), `published` replaces
    `task_publication.publish_task`, and `engine` the module-level `engine`
    of `app.tasks.fetchers`. `fetcher()` defines a probe and commits its
    `FetcherConfig`; `cleanup()` deletes every committed row it created.
    """

    factory: async_sessionmaker[AsyncSession]
    events: list[str]
    sessions: RecordingSessions
    status: RecordingSessions
    published: Publications
    engine: FakeEngine
    names: list[str] = field(default_factory=list)

    async def fetcher(
        self,
        *,
        enabled: bool = True,
        source: CVESourceType = SOURCE,
        fetcher_queue: str | None = None,
    ) -> CVEProbe:
        probe = define_cve_fetcher(
            self.events, source=source, fetcher_queue=fetcher_queue
        )
        self.names.append(probe.name)
        await seed_fetcher_config(self.factory, probe.name, enabled=enabled)
        return probe

    @property
    def catch_up_session(self) -> AsyncSession:
        """The latest session opened by the workflow (the catch-up session
        once `catch_up()` runs)."""
        return self.sessions.opened[-1]

    async def cleanup(self) -> None:
        await delete_fetcher_rows(self.factory, self.names)


def install_harness(
    monkeypatch: pytest.MonkeyPatch, factory: async_sessionmaker[AsyncSession]
) -> CatchUpHarness:
    """Install every `CatchUpHarness` substitute and the drain spy."""
    events: list[str] = []
    harness = CatchUpHarness(
        factory=factory,
        events=events,
        sessions=RecordingSessions(factory, events),
        status=RecordingSessions(factory, events, label="status:"),
        published=Publications(events),
        engine=FakeEngine(),
    )
    harness.sessions.install(monkeypatch, fetchers)
    harness.status.install(monkeypatch, base_cve_fetcher)
    monkeypatch.setattr(task_publication, "publish_task", harness.published)
    monkeypatch.setattr(fetchers, "engine", harness.engine)
    watch_drain(monkeypatch, events)
    return harness


async def seed_fetcher_config(
    factory: async_sessionmaker[AsyncSession], fetcher_name: str, *, enabled: bool
) -> None:
    async with factory() as session:
        session.add(FetcherConfig(fetcher_name=fetcher_name, enabled=enabled))
        await session.commit()


async def delete_fetcher_rows(
    factory: async_sessionmaker[AsyncSession], names: list[str]
) -> None:
    """Delete the committed `FetcherConfig` rows of `names` and any
    `FetcherRun` a regression might have created for them."""
    if not names:
        return
    async with factory() as session:
        await session.execute(
            delete(FetcherRun).where(FetcherRun.fetcher_name.in_(names))
        )
        await session.execute(
            delete(FetcherConfig).where(FetcherConfig.fetcher_name.in_(names))
        )
        await session.commit()


async def fetcher_run_count(
    factory: async_sessionmaker[AsyncSession], fetcher_name: str
) -> int:
    async with factory() as session:
        count = await session.scalar(
            select(func.count())
            .select_from(FetcherRun)
            .where(FetcherRun.fetcher_name == fetcher_name)
        )
    return int(count or 0)


class SourceState(NamedTuple):
    status: str
    fetched_at: datetime
    first_failed_at: datetime | None


async def source_state(
    factory: async_sessionmaker[AsyncSession],
    cve_id: uuid.UUID,
    source: CVESourceType = SOURCE,
) -> SourceState | None:
    """The committed latest `source` state of one CVE, from a fresh session."""
    async with factory() as session:
        row = (
            await session.execute(
                select(
                    CVESource.status, CVESource.fetched_at, CVESource.first_failed_at
                ).where(CVESource.cve_id == cve_id, CVESource.source == source.value)
            )
        ).one_or_none()
    return None if row is None else SourceState(*row)
