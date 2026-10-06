"""Production reachability of the real `SyncRedhatCves` class: the on-demand
`fetch_single_cve` workflow, the default catch-up through `run_catch_up`,
the bootstrapped `FetcherConfig`, and the RedBeat schedule entry.

Owning specifications:

- docs/features/tickets/cve-sync-redhat.md (Fetcher Definition; `fetch_single`
  method: on-demand discovery and catch-up for free; Error Handling,
  `fetch_single()` table).
- docs/features/tickets/cve-service.md (On-Demand Fetch: fetch_single_cve,
  Orchestrator Behavior) and docs/features/platform/cve-fetcher-infrastructure.md
  (Retry Policy for `fetch_single`; Default catch_up Implementation).
- docs/features/platform/fetcher-infrastructure.md (Per-Ticket Catch-Up:
  Celery task wrapper; Data Model, FetcherConfig bootstrap and the
  `default_request_delay` note; Celery Beat Schedule Synchronization,
  Redbeat Entry Structure and Startup Reconciliation).
- docs/features/platform/testing-strategy.md (CVE Fetcher Infrastructure,
  Concrete compliance; On-Demand CVE Refetch).

The workflows run against real PostgreSQL with the harnesses of
`tests/support/fetch_single_cve.py` and `tests/support/cve_catch_up.py`
(recording session factories over `real_session_factory`, a recorded
`task_publication.publish_task`, and the real convergence drain). The
production class is resolved from the registries filled by fetcher
discovery; no test-only fetcher is defined. Every HTTP client the fetcher
creates is the in-process `RedhatServer`. The committed `sync_redhat_cves`
`FetcherConfig` row, CVEs, Tickets, and their children are deleted at
teardown. Bootstrap and reconciliation run on `db_session`, rolled back at
teardown, and the worker Redis database. All CVE-IDs are fictional.

These tests prove only that the production class is reachable through each
workflow. The generic task terminal matrix (missing, retry, and failure) is
owned by `test_fetch_single_cve_workflow.py` and
`test_cve_fetcher_catch_up.py`, and Red Hat's exception classification by
`test_sync_redhat_cves.py`.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Awaitable, Callable
from typing import Any, Final

import httpx
import pytest
import redis.asyncio as redis_asyncio
from celery import Celery
from redbeat import RedBeatSchedulerEntry
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from structlog.testing import capture_logs

import app.services.base_fetcher as base_fetcher_module
import app.services.fetcher_discovery  # noqa: F401
from app.core.enums import CVESourceFetchStatus, CVESourceType
from app.models.cve import CVE
from app.models.fetcher_config import FetcherConfig
from app.services.fetcher_bootstrap import bootstrap_fetcher_configs
from app.services.fetcher_schedule import reconcile_beat_schedule
from app.services.tickets.sync_redhat_cves import SyncRedhatCves
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
from tests.support.fetch_single_cve import (
    COMPLETED,
    FetchSingleHarness,
    install_fetch_single_harness,
)
from tests.support.redhat import RedhatServer, load_cve_fixture

SessionFactory = Callable[[], Awaitable[AsyncSession]]

NAME: Final = "sync_redhat_cves"
REDHAT: Final = CVESourceType.REDHAT


@pytest.fixture
async def world(db_session_factory: SessionFactory) -> AsyncIterator[IngestionWorld]:
    created = IngestionWorld(db_session_factory, await db_session_factory())
    try:
        await created.ensure_default_setting()
        yield created
    finally:
        await created.cleanup()


class ClientServer(RedhatServer):
    """A `RedhatServer` recording every client it creates."""

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
    async def test_success_writes_success_and_publishes_the_package_handoff(
        self,
        world: IngestionWorld,
        on_demand: FetchSingleHarness,
        server: ClientServer,
    ) -> None:
        cve, ticket = await _active_cve(world)
        server.bodies[cve.cve_id] = load_cve_fixture("cve_full_v3")
        token = await on_demand.marker(cve.cve_id, REDHAT.value)

        with capture_logs() as logs:
            outcome = await on_demand.run(NAME, cve.cve_id, REDHAT.value, token)

        assert outcome is None
        assert server.requested_cve_ids == [cve.cve_id]
        state = await source_state(on_demand.factory, cve.id, REDHAT)
        assert state is not None
        assert state.status == CVESourceFetchStatus.SUCCESS
        assert on_demand.published.published(RESOLVE) == [
            {
                "ticket_id": str(ticket.id),
                "cpe_matches": [],
                "affected_cpes": [],
                "vendor_products": [],
                "resolved_packages": ["openssh"],
            }
        ]
        assert await on_demand.marker_value(cve.cve_id, REDHAT.value) is None
        assert await fetcher_run_count(on_demand.factory, NAME) == 0
        assert [entry for entry in logs if entry["event"] == COMPLETED] == [
            {
                "event": COMPLETED,
                "log_level": "info",
                "outcome": "updated",
                "fetcher_name": NAME,
                "cve_id": cve.cve_id,
                "source": REDHAT.value,
            }
        ]
        # The workflow closed the client it created.
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
        server.bodies[cve.cve_id] = load_cve_fixture("cve_v2_only")

        await fetchers.run_catch_up_async(NAME, str(ticket.id))

        assert server.requested_cve_ids == [cve.cve_id]
        # The catch-up flushes, then the finalizer commits once and only
        # then drains and publishes.
        events = catch_up.events
        commit = events.index("commit")
        assert events.count("commit") == 1
        assert events[commit - 1] == "flush"
        assert commit < events.index("drain") < events.index(f"publish:{RESOLVE}")
        state = await source_state(catch_up.factory, cve.id, REDHAT)
        assert state is not None
        assert state.status == CVESourceFetchStatus.SUCCESS
        [handoff] = catch_up.published.published(RESOLVE)
        assert handoff["ticket_id"] == str(ticket.id)
        assert handoff["resolved_packages"] == ["openssl", "openssl097a", "openssl098e"]
        assert await fetcher_run_count(catch_up.factory, NAME) == 0
        catch_up.engine.dispose.assert_awaited_once()
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
        assert config.request_delay == SyncRedhatCves.default_request_delay == 2.0
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
        assert entry.schedule.hour == {3}
        assert entry.schedule.day_of_month == set(range(1, 32))
        assert entry.schedule.day_of_week == set(range(7))
        assert "queue" not in entry.options
