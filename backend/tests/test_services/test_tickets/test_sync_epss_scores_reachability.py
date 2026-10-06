"""Production reachability of the real `SyncEpssScores` class: the on-demand
`fetch_single_cve` workflow, the default catch-up through `run_catch_up`,
the bootstrapped `FetcherConfig`, and the RedBeat schedule entry.

Owning specifications:

- docs/features/tickets/cve-sync-epss.md (Fetcher Definition; `fetch_single`
  method: on-demand discovery and catch-up for free; Error Handling,
  `fetch_single()` table; Custom Settings).
- docs/features/tickets/cve-service.md (On-Demand Fetch: fetch_single_cve,
  Orchestrator Behavior) and docs/features/platform/cve-fetcher-infrastructure.md
  (`fetch_single` Signaling Convention; Retry Policy for `fetch_single`;
  Error Categorization; Default catch_up Implementation).
- docs/features/platform/fetcher-infrastructure.md (Per-Ticket Catch-Up:
  Celery task wrapper; Data Model, FetcherConfig bootstrap and the
  `default_request_delay` note; Celery Beat Schedule Synchronization,
  Redbeat Entry Structure and Startup Reconciliation).
- docs/features/platform/testing-strategy.md (CVE Fetcher Infrastructure,
  Default catch-up and Concrete compliance; On-Demand CVE Refetch).

The workflows run against real PostgreSQL with the harnesses of
`tests/support/fetch_single_cve.py` and `tests/support/cve_catch_up.py`
(recording session factories over `real_session_factory`, a recorded
`task_publication.publish_task`, and the real convergence drain). The
production class is resolved from the registries filled by fetcher
discovery; no test-only fetcher is defined. Every HTTP client the fetcher
creates is the in-process `EpssServer`. The committed `sync_epss_scores`
`FetcherConfig` row, CVEs, Tickets, and their children (including
`cve_epss_score` and `cve_source`) are deleted at teardown. Bootstrap and
reconciliation run on `db_session`, rolled back at teardown, and the worker
Redis database. All CVE-IDs are fictional.

The generic task terminal matrix is owned by
`test_fetch_single_cve_workflow.py` and `test_cve_fetcher_catch_up.py`, and
EPSS exception classification by `test_sync_epss_scores.py`; the retry and
failure cases here only prove that the EPSS outcomes reach those paths.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Awaitable, Callable
from datetime import date
from typing import Any, Final

import httpx
import pytest
import redis.asyncio as redis_asyncio
from celery import Celery
from pydantic import ValidationError
from redbeat import RedBeatSchedulerEntry
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from structlog.testing import capture_logs

import app.services.base_fetcher as base_fetcher_module
import app.services.fetcher_discovery  # noqa: F401
from app.core.enums import CVESourceFetchStatus, CVESourceType
from app.models.cve import CVE
from app.models.cve_epss_score import CVEEPSSScore
from app.models.fetcher_config import FetcherConfig
from app.services.cve_service import FetchSingleRetry
from app.services.fetcher_bootstrap import bootstrap_fetcher_configs
from app.services.fetcher_schedule import reconcile_beat_schedule
from app.services.http_client import is_retryable_condition
from app.services.tickets.sync_epss_scores import SyncEpssScores
from app.tasks import fetchers
from tests.support.cve_catch_up import (
    RESOLVE,
    CatchUpHarness,
    fetcher_run_count,
    install_harness,
    seed_fetcher_config,
    source_state,
)
from tests.support.cve_ingest import IngestionWorld
from tests.support.epss import EpssServer, body, entry_for, envelope, status
from tests.support.fetch_single_cve import (
    COMPLETED,
    FAILED,
    RETRY_SCHEDULED,
    FetchSingleHarness,
    events_named,
    install_fetch_single_harness,
)

SessionFactory = Callable[[], Awaitable[AsyncSession]]

NAME: Final = "sync_epss_scores"
EPSS: Final = CVESourceType.EPSS
LAST_ATTEMPT: Final = 3
"""The zero-based attempt index after which no retry remains (3 retries)."""


@pytest.fixture
async def world(db_session_factory: SessionFactory) -> AsyncIterator[IngestionWorld]:
    created = IngestionWorld(db_session_factory, await db_session_factory())
    try:
        yield created
    finally:
        await created.cleanup()


class ClientServer(EpssServer):
    """An `EpssServer` recording every client it creates."""

    def __init__(self) -> None:
        super().__init__()
        self.clients: list[httpx.AsyncClient] = []

    def client(self) -> httpx.AsyncClient:
        created = super().client()
        self.clients.append(created)
        return created


@pytest.fixture
def server(monkeypatch: pytest.MonkeyPatch) -> ClientServer:
    """Every lazily created fetcher HTTP client serves this fake."""
    fake = ClientServer()

    def create_http_client(name: str, **options: Any) -> httpx.AsyncClient:
        assert name == NAME
        assert options == {}
        return fake.client()

    monkeypatch.setattr(base_fetcher_module, "create_http_client", create_http_client)
    return fake


async def _active_cve(world: IngestionWorld) -> tuple[CVE, Any]:
    cve = await world.cve_in()
    ticket = await world.ticket(cve_id=cve.id)
    return cve, ticket


def _serve(server: EpssServer, cve: CVE) -> None:
    server.entries[cve.cve_id] = entry_for(
        cve.cve_id, epss="0.031000000", percentile="0.420000000", date="2026-10-06"
    )


def _malformed(cve: CVE) -> Any:
    return body(envelope(entry_for(cve.cve_id, percentile="abc")))


async def _score(
    factory: async_sessionmaker[AsyncSession], cve: CVE
) -> tuple[float, float, date] | None:
    async with factory() as session:
        row = (
            await session.execute(
                select(
                    CVEEPSSScore.score,
                    CVEEPSSScore.percentile,
                    CVEEPSSScore.assessed_at,
                ).where(CVEEPSSScore.cve_id == cve.id)
            )
        ).one_or_none()
    return None if row is None else (row[0], row[1], row[2])


# ---------------------------------------------------------------------------
# On-demand fetch_single_cve
# ---------------------------------------------------------------------------


@pytest.fixture
async def on_demand(
    real_session_factory: async_sessionmaker[AsyncSession],
    redis_client: redis_asyncio.Redis,
    monkeypatch: pytest.MonkeyPatch,
) -> AsyncIterator[FetchSingleHarness]:
    harness = install_fetch_single_harness(
        monkeypatch, real_session_factory, redis_client
    )
    try:
        await seed_fetcher_config(real_session_factory, NAME, enabled=True)
        harness.names.append(NAME)
        yield harness
    finally:
        await harness.cleanup()


@pytest.mark.integration
class TestOnDemandFetch:
    async def test_success_writes_the_score_without_a_package_handoff(
        self,
        world: IngestionWorld,
        on_demand: FetchSingleHarness,
        server: ClientServer,
    ) -> None:
        cve, _ = await _active_cve(world)
        _serve(server, cve)
        token = await on_demand.marker(cve.cve_id, EPSS.value)

        with capture_logs() as logs:
            outcome = await on_demand.run(NAME, cve.cve_id, EPSS.value, token)

        assert outcome is None
        assert server.requested_cve_ids == [cve.cve_id]
        state = await source_state(on_demand.factory, cve.id, EPSS)
        assert state is not None
        assert state.status == CVESourceFetchStatus.SUCCESS
        assert await _score(on_demand.factory, cve) == (
            0.031,
            0.42,
            date(2026, 10, 6),
        )
        # post_ingest is None: no resolve_ticket_packages publication.
        assert on_demand.published.published(RESOLVE) == []
        assert await on_demand.marker_value(cve.cve_id, EPSS.value) is None
        assert await fetcher_run_count(on_demand.factory, NAME) == 0
        assert events_named(logs, COMPLETED) == [
            {
                "event": COMPLETED,
                "log_level": "info",
                "outcome": "updated",
                "fetcher_name": NAME,
                "cve_id": cve.cve_id,
                "source": EPSS.value,
            }
        ]
        # The workflow closed the client it created.
        assert server.clients
        assert all(client.is_closed for client in server.clients)

    async def test_empty_data_is_missing(
        self,
        world: IngestionWorld,
        on_demand: FetchSingleHarness,
        server: ClientServer,
    ) -> None:
        cve, _ = await _active_cve(world)
        token = await on_demand.marker(cve.cve_id, EPSS.value)

        with capture_logs() as logs:
            outcome = await on_demand.run(NAME, cve.cve_id, EPSS.value, token)

        assert outcome is None
        state = await source_state(on_demand.factory, cve.id, EPSS)
        assert state is not None
        assert state.status == CVESourceFetchStatus.MISSING
        assert await _score(on_demand.factory, cve) is None
        assert await on_demand.marker_value(cve.cve_id, EPSS.value) is None
        assert [entry["outcome"] for entry in events_named(logs, COMPLETED)] == [
            "missing"
        ]
        assert all(client.is_closed for client in server.clients)

    @pytest.mark.parametrize("code", [429, 503])
    async def test_retryable_status_schedules_a_retry_without_status(
        self,
        code: int,
        world: IngestionWorld,
        on_demand: FetchSingleHarness,
        server: ClientServer,
    ) -> None:
        cve, _ = await _active_cve(world)
        server.responses[cve.cve_id] = status(code)
        token = await on_demand.marker(cve.cve_id, EPSS.value)

        with capture_logs() as logs:
            outcome = await on_demand.run(NAME, cve.cve_id, EPSS.value, token)

        assert isinstance(outcome, FetchSingleRetry)
        assert outcome.countdown == 5
        assert isinstance(outcome.cause, httpx.HTTPStatusError)
        assert outcome.cause.response.status_code == code
        assert await source_state(on_demand.factory, cve.id, EPSS) is None
        assert await on_demand.marker_value(cve.cve_id, EPSS.value) == token
        [retry] = events_named(logs, RETRY_SCHEDULED)
        assert retry["cause"] == "HTTPStatusError"
        assert all(client.is_closed for client in server.clients)

    async def test_retryable_failure_after_the_last_retry_is_failure(
        self,
        world: IngestionWorld,
        on_demand: FetchSingleHarness,
        server: ClientServer,
    ) -> None:
        cve, _ = await _active_cve(world)
        server.responses[cve.cve_id] = status(503)
        token = await on_demand.marker(cve.cve_id, EPSS.value)

        with capture_logs() as logs, pytest.raises(httpx.HTTPStatusError):
            await on_demand.run(
                NAME, cve.cve_id, EPSS.value, token, attempt=LAST_ATTEMPT
            )

        state = await source_state(on_demand.factory, cve.id, EPSS)
        assert state is not None
        assert state.status == CVESourceFetchStatus.FAILURE
        assert await on_demand.marker_value(cve.cve_id, EPSS.value) is None
        assert events_named(logs, RETRY_SCHEDULED) == []
        assert [entry["stage"] for entry in events_named(logs, FAILED)] == [
            "pre_finalization"
        ]
        assert all(client.is_closed for client in server.clients)

    async def test_data_quality_error_is_an_immediate_failure(
        self,
        world: IngestionWorld,
        on_demand: FetchSingleHarness,
        server: ClientServer,
    ) -> None:
        cve, _ = await _active_cve(world)
        server.responses[cve.cve_id] = _malformed(cve)
        token = await on_demand.marker(cve.cve_id, EPSS.value)

        with capture_logs() as logs, pytest.raises(ValidationError):
            await on_demand.run(NAME, cve.cve_id, EPSS.value, token)

        state = await source_state(on_demand.factory, cve.id, EPSS)
        assert state is not None
        assert state.status == CVESourceFetchStatus.FAILURE
        assert await _score(on_demand.factory, cve) is None
        assert await on_demand.marker_value(cve.cve_id, EPSS.value) is None
        assert events_named(logs, RETRY_SCHEDULED) == []
        [failed] = events_named(logs, FAILED)
        assert failed["cause"] == "ValidationError"
        assert failed["retries"] == 0
        assert all(client.is_closed for client in server.clients)


# ---------------------------------------------------------------------------
# Catch-up through the inherited default
# ---------------------------------------------------------------------------


@pytest.fixture
async def catch_up(
    real_session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> AsyncIterator[CatchUpHarness]:
    harness = install_harness(monkeypatch, real_session_factory)
    try:
        await seed_fetcher_config(real_session_factory, NAME, enabled=True)
        harness.names.append(NAME)
        yield harness
    finally:
        await harness.cleanup()


@pytest.mark.integration
class TestCatchUp:
    async def test_run_catch_up_uses_the_inherited_default(
        self,
        world: IngestionWorld,
        catch_up: CatchUpHarness,
        server: ClientServer,
    ) -> None:
        cve, ticket = await _active_cve(world)
        _serve(server, cve)

        await fetchers.run_catch_up_async(NAME, str(ticket.id))

        assert server.requested_cve_ids == [cve.cve_id]
        # The catch-up flushes, then the finalizer commits once and only
        # then drains; there is no package handoff.
        events = catch_up.events
        commit = events.index("commit")
        assert events.count("commit") == 1
        assert events[commit - 1] == "flush"
        assert commit < events.index("drain")
        assert catch_up.published.published(RESOLVE) == []
        state = await source_state(catch_up.factory, cve.id, EPSS)
        assert state is not None
        assert state.status == CVESourceFetchStatus.SUCCESS
        assert await _score(catch_up.factory, cve) == (0.031, 0.42, date(2026, 10, 6))
        assert await fetcher_run_count(catch_up.factory, NAME) == 0
        catch_up.engine.dispose.assert_awaited_once()
        assert all(client.is_closed for client in server.clients)

    async def test_empty_data_writes_missing_and_returns(
        self,
        world: IngestionWorld,
        catch_up: CatchUpHarness,
        server: ClientServer,
    ) -> None:
        cve, ticket = await _active_cve(world)

        await fetchers.run_catch_up_async(NAME, str(ticket.id))

        state = await source_state(catch_up.factory, cve.id, EPSS)
        assert state is not None
        assert state.status == CVESourceFetchStatus.MISSING
        assert "commit" not in catch_up.events
        assert "status:commit" in catch_up.events
        assert await fetcher_run_count(catch_up.factory, NAME) == 0
        catch_up.engine.dispose.assert_awaited_once()
        assert all(client.is_closed for client in server.clients)

    async def test_failure_on_every_attempt_writes_failure_and_propagates(
        self,
        world: IngestionWorld,
        catch_up: CatchUpHarness,
        server: ClientServer,
    ) -> None:
        cve, ticket = await _active_cve(world)
        server.responses[cve.cve_id] = status(503)
        states = []

        # The initial attempt and its three retries, each a new invocation.
        for _ in range(LAST_ATTEMPT + 1):
            with pytest.raises(httpx.HTTPStatusError) as raised:
                await fetchers.run_catch_up_async(NAME, str(ticket.id))
            assert is_retryable_condition(raised.value)
            state = await source_state(catch_up.factory, cve.id, EPSS)
            assert state is not None
            assert state.status == CVESourceFetchStatus.FAILURE
            states.append(state)

        assert server.requested_cve_ids == [cve.cve_id] * (LAST_ATTEMPT + 1)
        # One failure streak: its start is kept, each attempt refreshes it.
        assert {state.first_failed_at for state in states} == {
            states[0].first_failed_at
        }
        fetched = [state.fetched_at for state in states]
        assert fetched == sorted(fetched)
        assert len(set(fetched)) == len(fetched)
        assert "commit" not in catch_up.events
        assert catch_up.events.count("status:commit") == LAST_ATTEMPT + 1
        assert await fetcher_run_count(catch_up.factory, NAME) == 0
        assert catch_up.engine.dispose.await_count == LAST_ATTEMPT + 1
        assert len(server.clients) == LAST_ATTEMPT + 1
        assert all(client.is_closed for client in server.clients)

    async def test_data_quality_failure_writes_failure_and_is_not_retryable(
        self,
        world: IngestionWorld,
        catch_up: CatchUpHarness,
        server: ClientServer,
    ) -> None:
        cve, ticket = await _active_cve(world)
        server.responses[cve.cve_id] = _malformed(cve)

        with pytest.raises(ValidationError) as raised:
            await fetchers.run_catch_up_async(NAME, str(ticket.id))

        assert not is_retryable_condition(raised.value)
        state = await source_state(catch_up.factory, cve.id, EPSS)
        assert state is not None
        assert state.status == CVESourceFetchStatus.FAILURE
        assert await _score(catch_up.factory, cve) is None
        assert await fetcher_run_count(catch_up.factory, NAME) == 0
        assert all(client.is_closed for client in server.clients)


# ---------------------------------------------------------------------------
# Configuration bootstrap and the RedBeat entry
# ---------------------------------------------------------------------------


@pytest.mark.integration
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
        assert config.request_delay == SyncEpssScores.default_request_delay == 0.2
        assert config.custom_settings == {}

    async def test_reconciliation_writes_the_entry_from_the_class(
        self, db_session: AsyncSession, celery_test_app: Celery
    ) -> None:
        await bootstrap_fetcher_configs(db_session)

        await reconcile_beat_schedule(db_session, celery_test_app)

        key = RedBeatSchedulerEntry.generate_key(celery_test_app, NAME)
        entry = RedBeatSchedulerEntry.from_key(key, app=celery_test_app)
        assert entry.task == "run_fetcher"
        assert entry.kwargs == {"fetcher_name": NAME, "triggered_by": "schedule"}
        assert entry.schedule.minute == {0}
        assert entry.schedule.hour == {14}
        assert entry.schedule.day_of_month == set(range(1, 32))
        assert entry.schedule.month_of_year == set(range(1, 13))
        assert entry.schedule.day_of_week == set(range(7))
        assert "queue" not in entry.options
