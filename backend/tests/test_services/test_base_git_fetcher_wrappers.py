"""A test-only `BaseGitFetcher` subclass through the real on-demand and
catch-up wrappers: publication of `fetch_single_cve` and `run_catch_up` on
the `git` queue, and execution of the inherited default `fetch_single()` by
`cve_service.run_fetch_single_cve()` and by the default
`BaseCVEFetcher.catch_up()` through `run_catch_up_async` and its synchronous
wrapper (backend/app/services/base_git_fetcher.py,
backend/app/services/cve_service.py, backend/app/tasks/fetchers.py).

Owning specifications:

- docs/features/platform/git-fetcher-infrastructure.md (Worker Affinity:
  `fetch_single()` and `catch_up()` routing; Default `fetch_single()`
  Implementation, the two caller purposes of `RuntimeError` and
  `CVENotInSource`; Concurrency Rules 1-2).
- docs/features/platform/cve-fetcher-infrastructure.md (On-demand
  Single-Item Fetch; `fetch_single` Signaling Convention; Retry Policy for
  `fetch_single`; Error Categorization; Default catch_up Implementation).
- docs/features/tickets/cve-service.md (On-Demand Fetch: fetch_single_cve;
  Fetch Orchestration: `trigger_on_demand_fetch()`, Transactional
  Preparation and Database-Free Publication).
- docs/features/platform/fetcher-infrastructure.md (Per-Ticket Catch-Up:
  Celery task wrapper and Post-commit enqueue queue routing; On-Demand Queue
  Routing).
- docs/features/platform/testing-strategy.md (CVE Fetcher Infrastructure:
  Default catch-up, Git queue preservation and the absence of `FetcherRun`
  records and `fetch_pending` keys; Git boundaries; Tier 1 hermetic Git
  rules; Concurrency Testing: explicit cleanup of committed rows).

Repositories are real temporary ones under `tmp_path` (an upstream served
through a `file://` URL and the fetcher's bare clone under the redirected
`GIT_CLONE_BASE_DIR`) with hermetic Git processes; `git_operations` is
wrapped by the recording `GitCalls` spy (`tests/support/git_fetchers.py`).
The fetcher's `process_item()` runs the real `upsert_cve()` /
`upsert_references()` ingestion of a fictional file.

Publication runs the real preparation (`refetch_cve()` over sessions joined
to the rolled-back `db_session`) or the real catch-up roster
(`run_ticket_convergence()`), and the real `publish_task()` over a
substituted `celery_app.send_task`, with both registries emptied so the
roster is exact. Execution uses the existing harnesses
(`tests/support/fetch_single_cve.py`, `tests/support/cve_catch_up.py`) over
`real_session_factory`, or the `NullPool` `cli_session_factory` for the
synchronous wrapper; committed CVE, Ticket, and `FetcherConfig` rows are
deleted at teardown, which also asserts that no CVE leaked. Test-only
fetchers are defined under `isolated_fetcher_registries`. All identifiers
are fictional.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, call

import pytest
import redis.asyncio as redis_asyncio
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncSession, async_sessionmaker
from structlog.testing import capture_logs

import app.services.base_cve_fetcher as base_cve_fetcher_module
from app.celery_app import celery_app
from app.core.enums import CVESourceFetchStatus, Scope, TicketStatus
from app.models.cve import CVE
from app.models.fetcher_config import FetcherConfig
from app.models.ticket import Ticket
from app.services import cve_service, package_service, task_publication
from app.services.base_git_fetcher import CLONE_UNAVAILABLE_MESSAGE
from app.services.cve_service import refetch_cve
from app.services.http_client import is_retryable_condition
from app.services.ticket_visibility import TicketCaller
from app.tasks import fetchers
from tests.support.cve_catch_up import (
    CATCH_UP,
    RESOLVE,
    CatchUpHarness,
    FakeEngine,
    FakeTask,
    Publications,
    RecordingSessions,
    delete_fetcher_rows,
    fetcher_run_count,
    install_harness,
    seed_fetcher_config,
    source_state,
)
from tests.support.cve_ingest import IngestionWorld
from tests.support.cve_source_status import clear_fetcher_registries
from tests.support.fetch_single_cve import (
    COMPLETED,
    FAILED,
    RETRY_SCHEDULED,
    TASK,
    FetchSingleHarness,
    ScriptedRedis,
    events_named,
    install_fetch_single_harness,
)
from tests.support.git_fetchers import (
    SOURCE,
    GitCalls,
    GitFetcherProbe,
    GitWorkspace,
    cve_file,
    cve_path,
    define_git_fetcher,
    ingest,
    install_git_workspace,
)

pytestmark = [
    pytest.mark.integration,
    pytest.mark.usefixtures("isolated_fetcher_registries"),
]

SessionFactory = Callable[[], Awaitable[AsyncSession]]

MITRE = SOURCE.value
D_BASE = "2024-01-05T00:00:00+00:00"
TITLE = "Example Git source title"
CONTENT = cve_file(TITLE, resolved_packages=["example-package"])
"""A fictional CVE file whose ingestion yields a package handoff."""
READ_ONLY_CALLS = {"is_clone_valid", "show_file"}
SCOPE_ALL = TicketCaller.authenticated(uuid.uuid4(), Scope.ALL)

OUTCOMES = ["absent-clone", "not-in-source", "success"]
"""The three source outcomes of the default `fetch_single()` under test."""


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------


@pytest.fixture
def workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> GitWorkspace:
    return install_git_workspace(tmp_path, monkeypatch)


@pytest.fixture
def git_calls(workspace: GitWorkspace, monkeypatch: pytest.MonkeyPatch) -> GitCalls:
    return GitCalls(monkeypatch)


async def _cve_count(factory: async_sessionmaker[AsyncSession]) -> int:
    async with factory() as session:
        return int(await session.scalar(select(func.count()).select_from(CVE)) or 0)


@pytest.fixture
async def world(
    db_session_factory: SessionFactory,
    real_session_factory: async_sessionmaker[AsyncSession],
) -> AsyncIterator[IngestionWorld]:
    """Committed CVEs and Tickets, deleted at teardown with every Ticket the
    ingestion associated with them; teardown asserts no CVE leaked."""
    baseline = await _cve_count(real_session_factory)
    created = IngestionWorld(db_session_factory, await db_session_factory())
    try:
        yield created
    finally:
        await created.cleanup()
        assert await _cve_count(real_session_factory) == baseline, "a CVE leaked"


def _git_fetcher(
    workspace: GitWorkspace, events: list[str] | None = None
) -> GitFetcherProbe:
    """The test-only Git fetcher owning `mitre`: `cves/<year>/<id>.json`
    candidates and the real ingestion."""
    return define_git_fetcher(
        repo_url=workspace.upstream.url, step=ingest(), events=events
    )


def _arrange_source(
    outcome: str, workspace: GitWorkspace, probe: GitFetcherProbe, cve_id: str
) -> None:
    """`absent-clone`: no clone exists. `not-in-source`: the clone has no
    file of `cve_id`. `success`: the clone holds its file."""
    if outcome == "absent-clone":
        workspace.upstream.commit({cve_path(cve_id): CONTENT}, date=D_BASE)
        return
    files = {"README": b"example\n"}
    if outcome == "success":
        files[cve_path(cve_id)] = CONTENT
    workspace.upstream.commit(files, date=D_BASE)
    workspace.clone(probe)


async def _title(factory: async_sessionmaker[AsyncSession], cve_id: uuid.UUID) -> Any:
    async with factory() as session:
        return await session.scalar(select(CVE.title).where(CVE.id == cve_id))


def _finalized_after_return(events: list[str], path: str) -> list[str]:
    """The flush and finalization events after `process_item()` returned."""
    start = events.index(f"process_item_returned:{path}") + 1
    kept = {"flush", "commit_and_dispatch", "commit", "drain"}
    return [event for event in events[start:] if event in kept]


def _expected_status(outcome: str) -> CVESourceFetchStatus:
    return {
        "absent-clone": CVESourceFetchStatus.FAILURE,
        "not-in-source": CVESourceFetchStatus.MISSING,
        "success": CVESourceFetchStatus.SUCCESS,
    }[outcome]


# ---------------------------------------------------------------------------
# Publication on the `git` queue
# ---------------------------------------------------------------------------


@pytest.fixture
def service_sessions(db_session: AsyncSession) -> async_sessionmaker[AsyncSession]:
    """Service sessions joined to the `db_session` connection: they observe
    the test's flushed rows inside their own savepoint."""
    assert isinstance(db_session.bind, AsyncConnection)
    return async_sessionmaker(
        bind=db_session.bind,
        class_=AsyncSession,
        expire_on_commit=False,
        join_transaction_mode="create_savepoint",
    )


class TestPublication:
    async def test_on_demand_preparation_publishes_fetch_single_cve_on_git_queue(
        self,
        workspace: GitWorkspace,
        git_calls: GitCalls,
        db_session: AsyncSession,
        service_sessions: async_sessionmaker[AsyncSession],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The transactional preparation reads the inherited class `queue`
        and the real `publish_task()` passes it to the broker call;
        publication touches no clone."""
        clear_fetcher_registries()
        probe = _git_fetcher(workspace)
        db_session.add(FetcherConfig(fetcher_name=probe.name, enabled=True))
        cve = CVE(cve_id=f"CVE-2099-{uuid.uuid4().int % 10**8:08d}")
        db_session.add(cve)
        await db_session.flush()
        redis = ScriptedRedis()
        redis.install(monkeypatch)
        send_task = MagicMock()
        monkeypatch.setattr(celery_app, "send_task", send_task)

        result = await refetch_cve(
            cve_id=cve.cve_id,
            source=None,
            caller=SCOPE_ALL,
            session_factory=service_sessions,
        )

        assert result.sources_enqueued == [MITRE]
        assert send_task.call_args_list == [
            call(
                TASK,
                kwargs={
                    "fetcher_name": probe.name,
                    "cve_id": cve.cve_id,
                    "source": MITRE,
                    "token": redis.values("set")[0],
                },
                ignore_result=True,
                queue="git",
            )
        ]
        assert git_calls.calls == []

    async def test_ticket_convergence_publishes_run_catch_up_on_git_queue(
        self,
        workspace: GitWorkspace,
        git_calls: GitCalls,
        real_session_factory: async_sessionmaker[AsyncSession],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The catch-up roster includes the Git fetcher through its derived
        participation and publishes `run_catch_up` with its class `queue`;
        the roster publication only enqueues."""
        clear_fetcher_registries()
        probe = _git_fetcher(workspace)
        ticket_id = uuid.uuid7()
        send_task = MagicMock()
        monkeypatch.setattr(celery_app, "send_task", send_task)

        await package_service.run_ticket_convergence(
            ticket_id=ticket_id, session_factory=real_session_factory
        )

        assert send_task.call_args_list == [
            call(
                CATCH_UP,
                kwargs={"fetcher_name": probe.name, "ticket_id": str(ticket_id)},
                ignore_result=True,
                queue="git",
            )
        ]
        assert probe.calls == []
        assert git_calls.calls == []


# ---------------------------------------------------------------------------
# On-demand: `run_fetch_single_cve`
# ---------------------------------------------------------------------------


@pytest.fixture
async def on_demand(
    real_session_factory: async_sessionmaker[AsyncSession],
    redis_client: redis_asyncio.Redis,
    monkeypatch: pytest.MonkeyPatch,
) -> AsyncIterator[FetchSingleHarness]:
    installed = install_fetch_single_harness(
        monkeypatch, real_session_factory, redis_client
    )
    try:
        yield installed
    finally:
        await installed.cleanup()


class TestOnDemand:
    @pytest.mark.parametrize("outcome", OUTCOMES)
    async def test_source_outcome_maps_to_status_without_fetcher_run(
        self,
        workspace: GitWorkspace,
        git_calls: GitCalls,
        world: IngestionWorld,
        on_demand: FetchSingleHarness,
        outcome: str,
    ) -> None:
        """Absent clone: the `RuntimeError` is non-retryable even on the
        first attempt (no retry signal), the status is `failure`, and the
        exception propagates. Absent file: `missing`. Present file: the
        real ingestion is committed with `success`. Every terminal outcome
        releases the marker; no `FetcherRun` exists and the clone is only
        read."""
        cve = await world.cve_in()
        probe = _git_fetcher(workspace, on_demand.events)
        on_demand.names.append(probe.name)
        await seed_fetcher_config(on_demand.factory, probe.name, enabled=True)
        _arrange_source(outcome, workspace, probe, cve.cve_id)
        token = await on_demand.marker(cve.cve_id, MITRE)

        with capture_logs() as logs:
            if outcome == "absent-clone":
                with pytest.raises(RuntimeError) as raised:
                    await on_demand.run(probe.name, cve.cve_id, MITRE, token)
                assert str(raised.value) == CLONE_UNAVAILABLE_MESSAGE
            else:
                assert await on_demand.run(probe.name, cve.cve_id, MITRE, token) is None

        state = await source_state(on_demand.factory, cve.id, SOURCE)
        assert state is not None
        assert state.status == _expected_status(outcome)
        assert await on_demand.marker_value(cve.cve_id, MITRE) is None
        assert events_named(logs, RETRY_SCHEDULED) == []
        context = {"fetcher_name": probe.name, "cve_id": cve.cve_id, "source": MITRE}
        if outcome == "absent-clone":
            assert events_named(logs, FAILED) == [
                {
                    "event": FAILED,
                    "log_level": "error",
                    "stage": "pre_finalization",
                    "cause": "RuntimeError",
                    "retries": 0,
                    **context,
                }
            ]
            assert git_calls.names() == ["is_clone_valid"]
            assert not workspace.clone_path(probe).exists()
            assert probe.calls == []
        else:
            action = "missing" if outcome == "not-in-source" else "updated"
            assert events_named(logs, COMPLETED) == [
                {"event": COMPLETED, "log_level": "info", "outcome": action, **context}
            ]
        if outcome == "success":
            assert probe.paths == [cve_path(cve.cve_id)]
            assert await _title(on_demand.factory, cve.id) == TITLE
            assert _finalized_after_return(on_demand.events, cve_path(cve.cve_id)) == [
                "flush",
                "commit_and_dispatch",
                "commit",
                "drain",
            ]
            assert len(on_demand.published.published(RESOLVE)) == 1
        else:
            assert await _title(on_demand.factory, cve.id) is None
            assert on_demand.published.calls == []
        assert set(git_calls.names()) <= READ_ONLY_CALLS
        assert await fetcher_run_count(on_demand.factory, probe.name) == 0


# ---------------------------------------------------------------------------
# Catch-up: `run_catch_up_async` and `_run_catch_up_sync`
# ---------------------------------------------------------------------------


@pytest.fixture
async def catch_up(
    real_session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> AsyncIterator[CatchUpHarness]:
    installed = install_harness(monkeypatch, real_session_factory)
    try:
        yield installed
    finally:
        await installed.cleanup()


class TestCatchUp:
    @pytest.mark.parametrize("outcome", OUTCOMES)
    async def test_default_catch_up_maps_outcome_without_run_or_pending_key(
        self,
        workspace: GitWorkspace,
        git_calls: GitCalls,
        world: IngestionWorld,
        catch_up: CatchUpHarness,
        redis_client: redis_asyncio.Redis,
        outcome: str,
    ) -> None:
        """The inherited default `catch_up()` calls the inherited Git
        `fetch_single()`: an absent clone writes `failure` and propagates
        the non-retryable `RuntimeError`; an absent file writes `missing`;
        a present file commits the real ingestion with `success`. No
        `FetcherRun` and no `fetch_pending` key are created."""
        cve = await world.cve_in()
        ticket = await world.ticket(cve_id=cve.id)
        probe = _git_fetcher(workspace, catch_up.events)
        catch_up.names.append(probe.name)
        await seed_fetcher_config(catch_up.factory, probe.name, enabled=True)
        _arrange_source(outcome, workspace, probe, cve.cve_id)

        if outcome == "absent-clone":
            with pytest.raises(RuntimeError) as raised:
                await fetchers.run_catch_up_async(probe.name, str(ticket.id))
            assert str(raised.value) == CLONE_UNAVAILABLE_MESSAGE
            assert is_retryable_condition(raised.value) is False
            assert git_calls.names() == ["is_clone_valid"]
            assert not workspace.clone_path(probe).exists()
        else:
            await fetchers.run_catch_up_async(probe.name, str(ticket.id))

        state = await source_state(catch_up.factory, cve.id, SOURCE)
        assert state is not None
        assert state.status == _expected_status(outcome)
        if outcome == "success":
            assert probe.paths == [cve_path(cve.cve_id)]
            assert await _title(catch_up.factory, cve.id) == TITLE
            assert _finalized_after_return(catch_up.events, cve_path(cve.cve_id)) == [
                "flush",
                "commit_and_dispatch",
                "commit",
                "drain",
            ]
            assert len(catch_up.published.published(RESOLVE)) == 1
        else:
            assert probe.calls == []
            assert await _title(catch_up.factory, cve.id) is None
            assert catch_up.published.calls == []
        assert set(git_calls.names()) <= READ_ONLY_CALLS
        assert await fetcher_run_count(catch_up.factory, probe.name) == 0
        assert await redis_client.keys(f"{cve_service.FETCH_PENDING_KEY_PREFIX}*") == []
        catch_up.engine.dispose.assert_awaited_once_with()


@dataclass
class _SyncWorld:
    """Committed rows and substitutes of the synchronous wrapper test; every
    database operation runs in its own `asyncio.run()` on the `NullPool`
    factory, as does the wrapper."""

    factory: async_sessionmaker[AsyncSession]
    engine: FakeEngine
    asyncio_run: MagicMock
    cve_ids: list[uuid.UUID] = field(default_factory=list)
    ticket_ids: list[uuid.UUID] = field(default_factory=list)
    names: list[str] = field(default_factory=list)

    def target(self) -> tuple[uuid.UUID, str, str]:
        """A committed CVE with a Ticket: `(cve pk, CVE-ID, ticket id)`."""

        async def seed() -> tuple[uuid.UUID, str, str]:
            async with self.factory() as session:
                cve = CVE(cve_id=f"CVE-2099-{uuid.uuid4().int % 10**8:08d}")
                session.add(cve)
                await session.flush()
                ticket = Ticket(status=TicketStatus.ANALYSIS.value, cve_id=cve.id)
                session.add(ticket)
                await session.commit()
                return cve.id, cve.cve_id, str(ticket.id)

        cve_pk, cve_id, ticket_id = asyncio.run(seed())
        self.cve_ids.append(cve_pk)
        self.ticket_ids.append(uuid.UUID(ticket_id))
        return cve_pk, cve_id, ticket_id

    def register(self, probe: GitFetcherProbe) -> None:
        self.names.append(probe.name)
        asyncio.run(seed_fetcher_config(self.factory, probe.name, enabled=True))

    def cleanup(self) -> None:
        async def delete_rows() -> None:
            async with self.factory() as session:
                await session.execute(
                    delete(Ticket).where(Ticket.id.in_(self.ticket_ids))
                )
                await session.execute(delete(CVE).where(CVE.id.in_(self.cve_ids)))
                await session.commit()
            await delete_fetcher_rows(self.factory, self.names)

        asyncio.run(delete_rows())


@pytest.fixture
def sync_world(
    cli_session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[_SyncWorld]:
    created = _SyncWorld(
        factory=cli_session_factory,
        engine=FakeEngine(),
        asyncio_run=MagicMock(side_effect=asyncio.run),
    )
    events: list[str] = []
    RecordingSessions(cli_session_factory, events).install(monkeypatch, fetchers)
    RecordingSessions(cli_session_factory, events, label="status:").install(
        monkeypatch, base_cve_fetcher_module
    )
    monkeypatch.setattr(task_publication, "publish_task", Publications(events))
    monkeypatch.setattr(fetchers, "engine", created.engine)
    monkeypatch.setattr(fetchers, "asyncio", SimpleNamespace(run=created.asyncio_run))
    try:
        yield created
    finally:
        created.cleanup()


class TestCatchUpSyncWrapper:
    def test_absent_clone_is_a_non_retryable_failure(
        self,
        workspace: GitWorkspace,
        git_calls: GitCalls,
        sync_world: _SyncWorld,
    ) -> None:
        """The wrapper classifies the clone-unavailable `RuntimeError` as
        non-retryable: no retry is scheduled, one terminal ERROR is
        logged, the exception propagates, and the status is `failure`."""
        cve_pk, _, ticket_id = sync_world.target()
        probe = _git_fetcher(workspace)
        sync_world.register(probe)
        task = FakeTask()

        with capture_logs() as logs, pytest.raises(RuntimeError) as raised:
            fetchers._run_catch_up_sync(task, probe.name, ticket_id)

        assert str(raised.value) == CLONE_UNAVAILABLE_MESSAGE
        task.retry.assert_not_called()
        failed = [entry for entry in logs if entry["log_level"] == "error"]
        assert failed == [
            {
                "event": "run_catch_up_failed",
                "log_level": "error",
                "fetcher_name": probe.name,
                "ticket_id": ticket_id,
                "cause": "RuntimeError",
                "retries": 0,
            }
        ]
        state = asyncio.run(source_state(sync_world.factory, cve_pk, SOURCE))
        assert state is not None
        assert state.status == CVESourceFetchStatus.FAILURE
        assert git_calls.names() == ["is_clone_valid"]
        assert sync_world.asyncio_run.call_count == 1
        sync_world.engine.dispose.assert_awaited_once_with()
        assert asyncio.run(fetcher_run_count(sync_world.factory, probe.name)) == 0
