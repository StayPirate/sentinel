"""Production reachability of the real `SyncKernelCves` class
(backend/app/services/tickets/sync_kernel_cves.py): the on-demand
`fetch_single_cve` workflow and the default catch-up through
`run_catch_up` over a real `vulns.git` bare clone, the `git`-queue
publication of both, the bootstrapped `FetcherConfig`, and the RedBeat
schedule entry.

Owning specifications:

- docs/features/tickets/cve-sync-kernel.md (Fetcher Definition;
  `fetch_single()` Behavior: published, then rejected candidate, missing
  as `CVENotInSource`; Storage and Recovery, the bootstrap `run_timeout`).
- docs/features/platform/git-fetcher-infrastructure.md (Default
  `fetch_single()` Implementation, `RuntimeError` for an absent clone;
  Worker Affinity: `fetch_single()` and `catch_up()` routing; Concurrency
  Rules, read-only single-item lookup).
- docs/features/platform/cve-fetcher-infrastructure.md (Default catch_up
  Implementation; `fetch_single` Signaling Convention; Retry Policy for
  `fetch_single`).
- docs/features/tickets/cve-service.md (On-Demand Fetch: fetch_single_cve;
  Fetch Orchestration: `trigger_on_demand_fetch()`).
- docs/features/platform/fetcher-infrastructure.md (FetcherConfig
  bootstrap; Celery Beat Schedule Synchronization, Redbeat Entry Structure
  and Time Limits).
- docs/features/platform/testing-strategy.md (CVE Fetcher Infrastructure:
  Default catch-up, Git queue preservation; Git boundaries; On-Demand CVE
  Refetch: task identity from `fetcher_cls.name` and Git queue
  preservation for Kernel).

Repositories are real temporary ones under `tmp_path` with hermetic Git
processes: an upstream served through a `file://` URL and its bare
`vulns.git` clone, created outside the code under test, under the
redirected `GIT_CLONE_BASE_DIR`. The production class is resolved from the
registries filled by fetcher discovery; no test-only fetcher is defined.
Execution uses the harnesses of `tests/support/fetch_single_cve.py` and
`tests/support/cve_catch_up.py` over `real_session_factory`; committed
CVE, Ticket, and `FetcherConfig` rows are deleted at teardown, which also
asserts that no CVE leaked, and no committed run or configuration of the
fetcher may exist before seeding. Publication runs the real preparation
(`refetch_cve()` over sessions joined to the rolled-back `db_session`) or
the real catch-up roster (`run_ticket_convergence()`) and the real
`publish_task()` over a substituted `celery_app.send_task`. Records are
sanitized fixtures re-keyed to fictional CVE-IDs.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from pathlib import Path
from typing import Any, Final
from unittest.mock import MagicMock, call

import pytest
import redis.asyncio as redis_asyncio
from celery import Celery
from redbeat import RedBeatSchedulerEntry
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncSession, async_sessionmaker
from structlog.testing import capture_logs

from app.celery_app import celery_app
from app.core.enums import CVESourceFetchStatus, CVESourceType, CveState, Scope
from app.models.cve import CVE
from app.models.fetcher_config import FetcherConfig
from app.services import cve_service, package_service
from app.services.base_cve_fetcher import get_fetch_single_fetchers
from app.services.base_fetcher import get_catch_up_fetchers
from app.services.base_git_fetcher import CLONE_UNAVAILABLE_MESSAGE
from app.services.cve_service import refetch_cve
from app.services.fetcher_bootstrap import bootstrap_fetcher_configs
from app.services.fetcher_schedule import reconcile_beat_schedule
from app.services.http_client import is_retryable_condition
from app.services.ticket_visibility import TicketCaller
from app.services.tickets.sync_kernel_cves import SyncKernelCves
from app.tasks import fetchers
from tests.support.cve_catch_up import (
    CATCH_UP,
    RESOLVE,
    CatchUpHarness,
    fetcher_run_count,
    install_harness,
    seed_fetcher_config,
    source_state,
)
from tests.support.cve_ingest import IngestionWorld
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
    GitCalls,
    GitWorkspace,
    assert_bounded_logs,
    install_git_workspace,
)
from tests.support.kernel_fetcher import (
    AUTHOR_EMAIL,
    AUTHOR_NAME,
    NAME,
    commit,
    committed_fetcher_rows,
    derived_record,
    kernel_probe,
    record_path,
)

pytestmark = pytest.mark.integration

SessionFactory = Callable[[], Awaitable[AsyncSession]]

KERNEL: Final = CVESourceType.KERNEL
SOURCE: Final = KERNEL.value
D_BASE: Final = "2026-10-01T00:00:00+00:00"
READ_ONLY_CALLS: Final = {"is_clone_valid", "show_file"}
SCOPE_ALL: Final = TicketCaller.authenticated(uuid.uuid4(), Scope.ALL)
RECORD_TEXTS: Final = ("fictional title", "fictional subject", "Fictional scenario")

OUTCOMES: Final = ["published", "rejected-only", "both", "absent", "no-clone"]
"""`published`: only the published record exists; `rejected-only`: only
the rejected one; `both`: both directories hold the CVE; `absent`: the
clone holds no record of it; `no-clone`: no clone exists."""


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------


@pytest.fixture
def workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> GitWorkspace:
    created = install_git_workspace(tmp_path, monkeypatch)
    monkeypatch.setattr(SyncKernelCves, "repo_url", created.upstream.url)
    return created


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
        await created.ensure_default_setting()
        yield created
    finally:
        await created.cleanup()
        assert await _cve_count(real_session_factory) == baseline, "a CVE leaked"


def _arrange(outcome: str, workspace: GitWorkspace, cve_id: str) -> None:
    """Commit the outcome's upstream files and, except for `no-clone`,
    create the `vulns.git` bare clone outside the code under test."""
    published = record_path("published", cve_id)
    rejected = record_path("rejected", cve_id)
    files: dict[str, bytes | None] = {"cve/README": b"example: fictional README\n"}
    if outcome in ("published", "both", "no-clone"):
        files[published] = derived_record("published_cvss_v3_1", cve_id)
    if outcome in ("rejected-only", "both"):
        files[rejected] = derived_record("rejected_cvss_v3_1", cve_id)
    commit(workspace.upstream, files, date=D_BASE)
    if outcome != "no-clone":
        workspace.clone(kernel_probe([]))


def _expected_status(outcome: str) -> CVESourceFetchStatus:
    if outcome == "absent":
        return CVESourceFetchStatus.MISSING
    if outcome == "no-clone":
        return CVESourceFetchStatus.FAILURE
    return CVESourceFetchStatus.SUCCESS


def _expected_reads(outcome: str, cve_id: str) -> list[str]:
    """The candidate paths read at `HEAD`, in order."""
    published = record_path("published", cve_id)
    if outcome in ("published", "both"):
        return [published]
    if outcome == "no-clone":
        return []
    return [published, record_path("rejected", cve_id)]


def _shown(git_calls: GitCalls) -> list[str]:
    return [args[2] for args, _ in git_calls.of("show_file")]


async def _stored(factory: async_sessionmaker[AsyncSession], cve_pk: uuid.UUID) -> CVE:
    async with factory() as session:
        cve = await session.get(CVE, cve_pk)
    assert cve is not None
    return cve


def _bounded(logs: list[Any], workspace: GitWorkspace) -> None:
    assert_bounded_logs(
        logs,
        *workspace.forbidden_texts(),
        *RECORD_TEXTS,
        AUTHOR_NAME,
        AUTHOR_EMAIL,
        "://",
        "cve/published",
        "cve/rejected",
    )


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
    async def test_refetch_preparation_publishes_fetch_single_cve_on_git_queue(
        self,
        db_session: AsyncSession,
        service_sessions: async_sessionmaker[AsyncSession],
        workspace: GitWorkspace,
        git_calls: GitCalls,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The production registry's Kernel entry: the task identity is
        the class `name` and the queue its inherited `queue`."""
        assert get_fetch_single_fetchers()[SOURCE] is SyncKernelCves
        assert await db_session.get(FetcherConfig, NAME) is None
        db_session.add(FetcherConfig(fetcher_name=NAME, enabled=True))
        cve = CVE(cve_id=f"CVE-2099-{uuid.uuid4().int % 10**8:08d}")
        db_session.add(cve)
        await db_session.flush()
        redis = ScriptedRedis()
        redis.install(monkeypatch)
        send_task = MagicMock()
        monkeypatch.setattr(celery_app, "send_task", send_task)

        result = await refetch_cve(
            cve_id=cve.cve_id,
            source=SOURCE,
            caller=SCOPE_ALL,
            session_factory=service_sessions,
        )

        assert result.sources_enqueued == [SOURCE]
        assert send_task.call_args_list == [
            call(
                TASK,
                kwargs={
                    "fetcher_name": NAME,
                    "cve_id": cve.cve_id,
                    "source": SOURCE,
                    "token": redis.values("set")[0],
                },
                ignore_result=True,
                queue="git",
            )
        ]
        # Publication touches no clone.
        assert git_calls.calls == []

    async def test_ticket_convergence_publishes_run_catch_up_on_git_queue(
        self,
        real_session_factory: async_sessionmaker[AsyncSession],
        workspace: GitWorkspace,
        git_calls: GitCalls,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        assert get_catch_up_fetchers()[NAME] is SyncKernelCves
        ticket_id = uuid.uuid7()
        send_task = MagicMock()
        monkeypatch.setattr(celery_app, "send_task", send_task)

        await package_service.run_ticket_convergence(
            ticket_id=ticket_id, session_factory=real_session_factory
        )

        kernel_calls = [
            recorded
            for recorded in send_task.call_args_list
            if recorded.kwargs.get("kwargs", {}).get("fetcher_name") == NAME
        ]
        assert kernel_calls == [
            call(
                CATCH_UP,
                kwargs={"fetcher_name": NAME, "ticket_id": str(ticket_id)},
                ignore_result=True,
                queue="git",
            )
        ]
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
    assert await committed_fetcher_rows(real_session_factory) == 0
    harness = install_fetch_single_harness(
        monkeypatch, real_session_factory, redis_client
    )
    try:
        harness.names.append(NAME)
        await seed_fetcher_config(real_session_factory, NAME, enabled=True)
        yield harness
    finally:
        await harness.cleanup()


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
        cve = await world.cve_in()
        _arrange(outcome, workspace, cve.cve_id)
        token = await on_demand.marker(cve.cve_id, SOURCE)

        with capture_logs() as logs:
            if outcome == "no-clone":
                with pytest.raises(RuntimeError) as raised:
                    await on_demand.run(NAME, cve.cve_id, SOURCE, token)
                assert str(raised.value) == CLONE_UNAVAILABLE_MESSAGE
                assert is_retryable_condition(raised.value) is False
            else:
                assert await on_demand.run(NAME, cve.cve_id, SOURCE, token) is None

        state = await source_state(on_demand.factory, cve.id, KERNEL)
        assert state is not None
        assert state.status == _expected_status(outcome)
        assert await on_demand.marker_value(cve.cve_id, SOURCE) is None
        assert events_named(logs, RETRY_SCHEDULED) == []
        assert _shown(git_calls) == _expected_reads(outcome, cve.cve_id)
        assert set(git_calls.names()) <= READ_ONLY_CALLS
        assert await fetcher_run_count(on_demand.factory, NAME) == 0
        stored = await _stored(on_demand.factory, cve.id)
        context = {"fetcher_name": NAME, "cve_id": cve.cve_id, "source": SOURCE}
        if outcome == "no-clone":
            assert [entry["cause"] for entry in events_named(logs, FAILED)] == [
                "RuntimeError"
            ]
            assert not workspace.clone_path(kernel_probe([])).exists()
        else:
            action = "missing" if outcome == "absent" else "updated"
            assert events_named(logs, COMPLETED) == [
                {"event": COMPLETED, "log_level": "info", "outcome": action, **context}
            ]
        if outcome in ("published", "both", "rejected-only"):
            expected = (
                CveState.REJECTED if outcome == "rejected-only" else CveState.PUBLISHED
            )
            assert stored.cve_state == expected
            assert stored.title is not None
            [handoff] = on_demand.published.published(RESOLVE)
            assert "kernel-source" in handoff["resolved_packages"]
        else:
            assert stored.title is None
            assert on_demand.published.published(RESOLVE) == []
        _bounded(logs, workspace)


# ---------------------------------------------------------------------------
# Catch-up through the inherited default
# ---------------------------------------------------------------------------


@pytest.fixture
async def catch_up(
    real_session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> AsyncIterator[CatchUpHarness]:
    assert await committed_fetcher_rows(real_session_factory) == 0
    harness = install_harness(monkeypatch, real_session_factory)
    try:
        harness.names.append(NAME)
        await seed_fetcher_config(real_session_factory, NAME, enabled=True)
        yield harness
    finally:
        await harness.cleanup()


class TestCatchUp:
    @pytest.mark.parametrize("outcome", ["published", "absent", "no-clone"])
    async def test_default_catch_up_maps_outcome_without_run_or_pending_key(
        self,
        workspace: GitWorkspace,
        git_calls: GitCalls,
        world: IngestionWorld,
        catch_up: CatchUpHarness,
        redis_client: redis_asyncio.Redis,
        outcome: str,
    ) -> None:
        cve = await world.cve_in()
        ticket = await world.ticket(cve_id=cve.id)
        _arrange(outcome, workspace, cve.cve_id)

        if outcome == "no-clone":
            with pytest.raises(RuntimeError) as raised:
                await fetchers.run_catch_up_async(NAME, str(ticket.id))
            assert str(raised.value) == CLONE_UNAVAILABLE_MESSAGE
            assert is_retryable_condition(raised.value) is False
        else:
            await fetchers.run_catch_up_async(NAME, str(ticket.id))

        state = await source_state(catch_up.factory, cve.id, KERNEL)
        assert state is not None
        assert state.status == _expected_status(outcome)
        assert _shown(git_calls) == _expected_reads(outcome, cve.cve_id)
        assert set(git_calls.names()) <= READ_ONLY_CALLS
        if outcome == "published":
            events = catch_up.events
            assert events.count("commit") == 1
            assert events[events.index("commit") - 1] == "flush"
            [handoff] = catch_up.published.published(RESOLVE)
            assert handoff["ticket_id"] == str(ticket.id)
            assert "kernel-source" in handoff["resolved_packages"]
            assert (await _stored(catch_up.factory, cve.id)).title is not None
        else:
            assert "commit" not in catch_up.events
            assert "status:commit" in catch_up.events
            assert catch_up.published.published(RESOLVE) == []
        assert await fetcher_run_count(catch_up.factory, NAME) == 0
        assert await redis_client.keys(f"{cve_service.FETCH_PENDING_KEY_PREFIX}*") == []
        catch_up.engine.dispose.assert_awaited_once_with()


# ---------------------------------------------------------------------------
# Configuration bootstrap and the RedBeat entry
# ---------------------------------------------------------------------------


class TestBootstrapAndSchedule:
    async def test_bootstrap_creates_the_configuration_from_the_class(
        self, db_session: AsyncSession
    ) -> None:
        assert await db_session.get(FetcherConfig, NAME) is None

        await bootstrap_fetcher_configs(db_session)

        config = await db_session.get(FetcherConfig, NAME)
        assert config is not None
        assert config.enabled is True
        assert config.schedule_override is None
        assert config.request_delay == SyncKernelCves.default_request_delay == 0
        assert config.run_timeout == 3600
        assert config.custom_settings == {}

    async def test_reconciliation_writes_the_git_queue_entry_from_the_class(
        self, db_session: AsyncSession, celery_test_app: Celery
    ) -> None:
        await bootstrap_fetcher_configs(db_session)

        await reconcile_beat_schedule(db_session, celery_test_app)

        key = RedBeatSchedulerEntry.generate_key(celery_test_app, NAME)
        entry = RedBeatSchedulerEntry.from_key(key, app=celery_test_app)
        assert entry.task == "run_fetcher"
        assert entry.kwargs == {"fetcher_name": NAME, "triggered_by": "schedule"}
        # 0 */3 * * *
        assert entry.schedule.minute == {0}
        assert entry.schedule.hour == set(range(0, 24, 3))
        assert entry.schedule.day_of_month == set(range(1, 32))
        assert entry.schedule.month_of_year == set(range(1, 13))
        assert entry.schedule.day_of_week == set(range(7))
        assert entry.options["queue"] == "git"
        assert entry.options["time_limit"] == 3600
        assert entry.options["soft_time_limit"] == 3420
