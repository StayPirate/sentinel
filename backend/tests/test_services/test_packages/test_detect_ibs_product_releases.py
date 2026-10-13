"""Tests for the `detect_ibs_product_releases` fetcher
(backend/app/services/packages/detect_ibs_product_releases.py): class
contract and registration, `run()` finalization over the real
`BaseFetcher.run()`, the HTTP client lifecycle, `catch_up()`, and the
`run_catch_up` composition.

Owning specifications:

- docs/features/packages/ibs-product-release-detection.md (Fetcher:
  `detect_ibs_product_releases` properties, Algorithm, Request Delay,
  Catch-Up, Error Handling, Metrics and Run Status; Local mutation and
  concurrency: per-unit finalization; Testing Requirements).
- docs/features/platform/fetcher-infrastructure.md (BaseFetcher Base
  Class, Finalization; Per-Ticket Catch-Up: Celery task wrapper, Interface
  contract, Fetcher inventory; Error Message Sanitization and the
  `SoftTimeLimitExceeded` convention; BaseFetcher HTTP Client Integration;
  Fetcher Discovery; Redbeat Entry Structure; Data Model, FetcherConfig
  bootstrap).
- docs/features/platform/testing-strategy.md (Fetcher Outcome and Effect
  Accounting, including the IBS release-detector per-unit finalizer
  exception; Ticket Convergence Publication Handoff, "IBS track and
  Product release detection").
- docs/features/packages/package-service.md (`run_ticket_convergence()`
  workflow step 4, the catch-up roster).

The reconciliation boundary itself (selection, tiers, outcomes, races,
failure conversion, commit and drain, logs, dimension independence) is
covered by `test_ibs_product_release.py` and
`test_ibs_product_release_races.py`; this module tests the fetcher-level
composition around it and reuses their helpers from
`tests/support/ibs_product_release.py`.

The boundary's module-level `async_session_factory` is replaced by
`UnitSessions` over `real_session_factory`, `task_publication.publish_task`
by a recorder, `IBS_DOWNLOAD_BASE_URL` by the fictional `TEST_BASE_URL`, and
`base_fetcher.create_http_client` by a factory that records each call and
returns a client over the in-process `DownloadServer`, so no test reaches
a broker or the network. The `run()` tests also redirect `base_fetcher`'s
session factory and own committed `FetcherConfig`/`FetcherRun` rows under a
test-only name (deleted at teardown); the `run_catch_up` tests own the
committed `FetcherConfig` row of the production name. Each pytest-xdist
worker owns its database and runs one test at a time, so the unrestricted
periodic selection sees only the rows a test committed. The package
service's evaluation date is pinned to `EVAL`. Unless a test states
otherwise, each occurrence sits below its own `Analysis` Ticket with its
own CVE and an `ANALYSIS`/`PENDING` IBS track, and holds a Product whose
only current association is `REPOSITORY`. All data is fictional.
"""

from __future__ import annotations

import ast
import asyncio
import inspect
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Final
from unittest.mock import AsyncMock, MagicMock, Mock

import httpx
import pytest
from celery import Celery
from celery.exceptions import OperationalError as KombuOperationalError
from celery.exceptions import SoftTimeLimitExceeded
from redbeat import RedBeatSchedulerEntry
from sqlalchemy import select, update
from sqlalchemy.exc import DBAPIError, OperationalError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from structlog.contextvars import (
    bind_contextvars,
    merge_contextvars,
    unbind_contextvars,
)
from structlog.testing import capture_logs

import app.services.base_fetcher as base_fetcher_module
import app.services.fetcher_discovery  # noqa: F401
from app.config import settings
from app.core.enums import TicketStatus, WorkflowType
from app.models.fetcher_config import FetcherConfig
from app.models.fetcher_run import FetcherRun
from app.models.ticket import Ticket
from app.models.ticket_package_product import TicketPackageProduct
from app.services import package_service, task_publication
from app.services.base_fetcher import (
    FETCHER_REGISTRY,
    BaseFetcher,
    FetcherError,
    FetcherRunConfig,
    get_catch_up_fetchers,
)
from app.services.fetcher_bootstrap import bootstrap_fetcher_configs
from app.services.fetcher_schedule import reconcile_beat_schedule
from app.services.http_client import create_http_client, is_retryable_condition
from app.services.package_service import run_ticket_convergence
from app.services.packages import detect_ibs_product_releases as detector
from app.services.packages import ibs_product_download as download
from app.services.packages import ibs_product_release as boundary
from app.services.packages.detect_ibs_product_releases import (
    DetectIbsProductReleases,
)
from app.services.packages.ibs_product_release import ProductReleaseCandidate
from app.tasks import fetchers
from tests.support.cve_catch_up import (
    FakeEngine,
    FakeTask,
    delete_fetcher_rows,
    fetcher_run_count,
    seed_fetcher_config,
)
from tests.support.ibs_download import TEST_BASE_URL, DownloadServer
from tests.support.ibs_product_release import (
    FETCHER,
    ISSUED_AT,
    OCCURRENCE_FAILED,
    OCCURRENCE_STALE,
    OTHER_REPOSITORY,
    REPOSITORY,
    REPOSITORY_FAILED,
    RUN_COMPLETED,
    Occurrence,
    Publish,
    ReleaseWorld,
    Seed,
    UnitSessions,
    between_phases,
    events_of,
    install_units,
    logged,
    matching,
    occurrence_failed,
    occurrence_stale,
    publication_failed,
    published,
    register_after_release,
    released_at,
    released_events,
    repository,
    run_completed,
    status_response,
)
from tests.support.module_imports import APP_ROOT, imported_modules
from tests.support.suse_cvss_races import SessionStatementRecorder
from tests.support.ticket_mutations import EVAL

Factory = Callable[[], Awaitable[AsyncSession]]
Outcome = tuple[str, int, int, int, int]
"""`(status, succeeded, created, updated, failed)` of one finalized run."""

NAME: Final = FETCHER
SCHEDULE: Final = "0 4 * * *"
DESCRIPTION: Final = (
    "Reconcile unreleased active-Ticket IBS Product occurrences against "
    "validated updateinfo advisories"
)
TIMEOUT: Final = httpx.Timeout(10.0, read=120.0)
ENUMERATION_FAILED: Final = "Failed to enumerate IBS Product release candidates"
RUN_CATCH_UP: Final = "run_catch_up"

WINNER_AT: Final = datetime(2024, 1, 2, 3, 4, 5, tzinfo=UTC)
"""A concurrent winner's committed release instant."""

SECRET: Final = "fictional-secret"
INTERNAL_URL: Final = f"https://ibs-user:{SECRET}@download.internal.example.test/ibs"
"""A fictional internal URL with credentials; never public or logged."""

BROKER_FAILURE: Final = f"redis://sentinel:{SECRET}@broker.example.test:6379/1 down"

_REAL_CREATE_HTTP_CLIENT = create_http_client

_RUN_CONFIG: Final = FetcherRunConfig(
    hard_time_limit_seconds=3600, request_delay=0, custom_settings={}
)


# ---------------------------------------------------------------------------
# Substitutes and fixtures
# ---------------------------------------------------------------------------


@dataclass
class _Clients:
    """Substitute for `base_fetcher.create_http_client`: records each call
    and returns a client over `server` with the requested options."""

    server: DownloadServer
    calls: list[tuple[str, dict[str, Any]]] = field(default_factory=list)
    created: list[httpx.AsyncClient] = field(default_factory=list)

    def __call__(self, name: str, **options: Any) -> httpx.AsyncClient:
        self.calls.append((name, options))
        client = httpx.AsyncClient(transport=self.server.transport(), **options)
        self.created.append(client)
        return client


@pytest.fixture(autouse=True)
def configured_base(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "ibs_download_base_url", TEST_BASE_URL)


@pytest.fixture(autouse=True)
def clock(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(package_service, "_utc_today", lambda: EVAL)


@pytest.fixture(autouse=True)
def publication(monkeypatch: pytest.MonkeyPatch) -> Publish:
    recorder = Publish()
    monkeypatch.setattr(task_publication, "publish_task", recorder)
    return recorder


@pytest.fixture
def server() -> DownloadServer:
    return DownloadServer()


@pytest.fixture(autouse=True)
def clients(server: DownloadServer, monkeypatch: pytest.MonkeyPatch) -> _Clients:
    recorder = _Clients(server)
    monkeypatch.setattr(base_fetcher_module, "create_http_client", recorder)
    return recorder


@pytest.fixture
def units(
    real_session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> UnitSessions:
    return install_units(monkeypatch, real_session_factory)


@pytest.fixture
async def world(db_session_factory: Factory) -> AsyncIterator[ReleaseWorld]:
    created = ReleaseWorld(db_session_factory, await db_session_factory())
    try:
        yield created
    finally:
        await created.cleanup()


@pytest.fixture
def metric_helpers(monkeypatch: pytest.MonkeyPatch) -> dict[str, Mock]:
    """Spies replacing the four `BaseFetcher` metric helpers."""
    spies = {}
    for helper in (
        "record_succeeded",
        "record_failed",
        "record_created",
        "record_updated",
    ):
        spies[helper] = Mock()
        monkeypatch.setattr(BaseFetcher, helper, spies[helper])
    return spies


async def _seeded(
    world: ReleaseWorld,
    count: int = 1,
    *,
    status: TicketStatus = TicketStatus.ANALYSIS,
    current: tuple[str, ...] = (REPOSITORY,),
) -> list[Occurrence]:
    """`count` committed occurrences, each below its own Ticket and
    Product, in occurrence-ID order."""
    seed = Seed(world.session, world)
    created = []
    for _ in range(count):
        ticket = await seed.ticket(status)
        product = await seed.product(current=current)
        created.append(await seed.occurrence(ticket, product))
    await seed.commit()
    return sorted(created, key=lambda occurrence: occurrence.id)


def _serve(server: DownloadServer, *occurrences: Occurrence, **kwargs: Any) -> None:
    """`REPOSITORY` with one advisory matching every given occurrence."""
    server.add(
        REPOSITORY, repository(matching(*(o.cve_id for o in occurrences), **kwargs))
    )


def _forbid(server: DownloadServer, repo_name: str) -> None:
    server.script(server.repomd_url(repo_name), status_response(403))


async def _commit(world: ReleaseWorld, *statements: Any) -> None:
    session = await world.open_session()
    for statement in statements:
        await session.execute(statement)
    await session.commit()


def _failing_for(
    monkeypatch: pytest.MonkeyPatch, occurrence: Occurrence, error: BaseException
) -> None:
    """Make `set_product_released_at()` raise `error` for `occurrence`
    after the real call; other occurrences are unchanged."""
    original = package_service.set_product_released_at

    async def failing(db: AsyncSession, **kwargs: Any) -> Any:
        result = await original(db, **kwargs)
        if kwargs["ticket_package_product_id"] == occurrence.id:
            raise error
        return result

    monkeypatch.setattr(package_service, "set_product_released_at", failing)


def _leaves(world: ReleaseWorld, ticket_id: uuid.UUID, status: TicketStatus) -> Any:
    """A committed concurrent change moving the Ticket to `status`."""

    async def change() -> None:
        values: dict[str, Any] = {"status": status.value}
        if status is TicketStatus.DUPLICATED:
            seed = Seed(world.session, world)
            canonical = await seed.ticket(with_cve=False)
            await seed.commit()
            values["duplicate_of_id"] = canonical.id
        await _commit(
            world, update(Ticket).where(Ticket.id == ticket_id).values(**values)
        )

    return change


def _released_concurrently(world: ReleaseWorld, occurrence: Occurrence) -> Any:
    return lambda: _commit(
        world,
        update(TicketPackageProduct)
        .where(TicketPackageProduct.id == occurrence.id)
        .values(released_at=WINNER_AT),
    )


# ---------------------------------------------------------------------------
# run() harness: committed FetcherConfig and FetcherRun under a test name
# ---------------------------------------------------------------------------


class _Runs:
    """Commits one `running` FetcherRun per `start()` and reads it back."""

    def __init__(self, factory: async_sessionmaker[AsyncSession]) -> None:
        self._factory = factory
        self.fetcher_name = f"test_ibs_release_run_{uuid.uuid4().hex[:12]}"
        self.configured = False

    async def start(self) -> uuid.UUID:
        async with self._factory() as session:
            if not self.configured:
                session.add(
                    FetcherConfig(
                        fetcher_name=self.fetcher_name,
                        enabled=True,
                        run_timeout=3600,
                        request_delay=0,
                        custom_settings={},
                    )
                )
                self.configured = True
            run = FetcherRun(
                fetcher_name=self.fetcher_name,
                started_at=datetime.now(UTC),
                status="running",
                triggered_by="schedule",
            )
            session.add(run)
            await session.commit()
            return run.id

    async def finalized(self, run_id: uuid.UUID) -> FetcherRun:
        async with self._factory() as session:
            run = await session.get(FetcherRun, run_id)
            assert run is not None
            return run


@pytest.fixture
async def runs(
    real_session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> AsyncIterator[_Runs]:
    monkeypatch.setattr(
        base_fetcher_module, "async_session_factory", real_session_factory
    )
    created = _Runs(real_session_factory)
    try:
        yield created
    finally:
        await delete_fetcher_rows(real_session_factory, [created.fetcher_name])


def _outcome(run: FetcherRun) -> Outcome:
    return (
        run.status,
        run.items_succeeded,
        run.items_created,
        run.items_updated,
        run.items_failed,
    )


async def _run(
    runs: _Runs, fetcher: DetectIbsProductReleases | None = None
) -> FetcherRun:
    """One complete `run()` that returns normally; the finalized row."""
    run_id = await runs.start()
    await (fetcher or DetectIbsProductReleases()).run(run_id=run_id, config=_RUN_CONFIG)
    return await runs.finalized(run_id)


async def _run_failing(
    runs: _Runs, error: type[BaseException]
) -> tuple[BaseException, FetcherRun]:
    run_id = await runs.start()
    with pytest.raises(error) as raised:
        await DetectIbsProductReleases().run(run_id=run_id, config=_RUN_CONFIG)
    return raised.value, await runs.finalized(run_id)


def _soft_limit_message(processed: int) -> str:
    return (
        "Execution reached the soft time limit (hard limit for this run: "
        f"3600s; {processed} items processed). Review FetcherConfig.run_timeout "
        f"for future runs of fetcher '{NAME}'."
    )


# ---------------------------------------------------------------------------
# A1. Class contract, registration, bootstrap, schedule, and roster
# ---------------------------------------------------------------------------


def _class_body_assignments(cls: type) -> set[str]:
    """The names assigned in `cls`'s own class body (static, from source)."""
    source = Path(inspect.getfile(cls)).read_text(encoding="utf-8")
    [class_def] = [
        node
        for node in ast.parse(source).body
        if isinstance(node, ast.ClassDef) and node.name == cls.__name__
    ]
    names: set[str] = set()
    for node in class_def.body:
        if isinstance(node, ast.Assign):
            names.update(t.id for t in node.targets if isinstance(t, ast.Name))
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            names.add(node.target.id)
        elif isinstance(node, ast.ClassDef):
            names.add(node.name)
    return names


@pytest.mark.unit
class TestRegistration:
    def test_properties_match_the_specification(self) -> None:
        assert DetectIbsProductReleases.name == NAME
        assert DetectIbsProductReleases.description == DESCRIPTION
        assert DetectIbsProductReleases.default_schedule == SCHEDULE
        assert DetectIbsProductReleases.participates_in_catch_up is True
        assert DetectIbsProductReleases.queue is None
        assert DetectIbsProductReleases.Settings is None
        assert DetectIbsProductReleases.default_request_delay == 0
        assert DetectIbsProductReleases.http_client_options == {"timeout": TIMEOUT}

    def test_class_body_declares_no_settings_or_queue(self) -> None:
        """Custom settings: None; default routing (no `queue`); the 0 s
        `default_request_delay` is declared explicitly."""
        assert _class_body_assignments(DetectIbsProductReleases) == {
            "name",
            "description",
            "default_schedule",
            "default_request_delay",
            "participates_in_catch_up",
            "http_client_options",
        }

    def test_read_timeout_is_120_seconds_and_the_others_10(self) -> None:
        timeout = DetectIbsProductReleases.http_client_options["timeout"]

        assert (timeout.connect, timeout.read, timeout.write, timeout.pool) == (
            10.0,
            120.0,
            10.0,
            10.0,
        )

    def test_class_name_is_derived_from_the_fetcher_name(self) -> None:
        derived = "".join(part.capitalize() for part in NAME.split("_"))

        assert derived == DetectIbsProductReleases.__name__

    def test_execute_and_catch_up_are_custom_overrides(self) -> None:
        assert "execute" in DetectIbsProductReleases.__dict__
        assert "catch_up" in DetectIbsProductReleases.__dict__
        assert DetectIbsProductReleases.catch_up is not BaseFetcher.catch_up

    def test_discovery_registers_the_fetcher(self) -> None:
        discovery = APP_ROOT / "services" / "fetcher_discovery.py"

        assert detector.__name__ in imported_modules(discovery, "app.services")
        assert FETCHER_REGISTRY[NAME] is DetectIbsProductReleases

    def test_fetcher_participates_in_catch_up(self) -> None:
        assert get_catch_up_fetchers()[NAME] is DetectIbsProductReleases

    async def test_http_client_is_created_lazily_with_the_read_timeout(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The real shared factory: `self.http_client` carries the
        fetcher's timeout override (no request is sent)."""
        monkeypatch.setattr(
            base_fetcher_module, "create_http_client", _REAL_CREATE_HTTP_CLIENT
        )
        fetcher = DetectIbsProductReleases()
        assert fetcher._http_client is None

        client = fetcher.http_client
        try:
            assert fetcher.http_client is client
            assert client.timeout == TIMEOUT
            assert (
                client.timeout.connect,
                client.timeout.read,
                client.timeout.write,
                client.timeout.pool,
            ) == (10.0, 120.0, 10.0, 10.0)
        finally:
            await fetcher._teardown_http_client()

        assert client.is_closed
        assert fetcher._http_client is None


@pytest.mark.integration
class TestBootstrapAndSchedule:
    async def test_bootstrap_creates_the_enabled_fetcher_config(
        self, db_session: AsyncSession
    ) -> None:
        assert await db_session.get(FetcherConfig, NAME) is None

        await bootstrap_fetcher_configs(db_session)

        config = await db_session.get(FetcherConfig, NAME)
        assert config is not None
        assert config.enabled is True
        assert config.schedule_override is None
        assert config.request_delay == 0
        assert config.custom_settings == {}

    async def test_reconciliation_writes_the_daily_entry_on_default_routing(
        self, db_session: AsyncSession, celery_test_app: Celery
    ) -> None:
        await bootstrap_fetcher_configs(db_session)
        config = await db_session.get(FetcherConfig, NAME)
        assert config is not None
        assert config.run_timeout == 3600

        await reconcile_beat_schedule(db_session, celery_test_app)

        key = RedBeatSchedulerEntry.generate_key(celery_test_app, NAME)
        entry = RedBeatSchedulerEntry.from_key(key, app=celery_test_app)
        assert entry.task == "run_fetcher"
        assert entry.args == []
        assert entry.kwargs == {"fetcher_name": NAME, "triggered_by": "schedule"}
        # 0 4 * * *
        assert entry.schedule.minute == {0}
        assert entry.schedule.hour == {4}
        assert entry.schedule.day_of_month == set(range(1, 32))
        assert entry.schedule.month_of_year == set(range(1, 13))
        assert entry.schedule.day_of_week == set(range(7))
        # max(5, 3600) and max(1, floor(3600 * 0.95)); no queue.
        assert entry.options == {"time_limit": 3600, "soft_time_limit": 3420}


@pytest.mark.integration
class TestTicketConvergenceRoster:
    async def test_convergence_publishes_the_catch_up_on_default_routing(
        self,
        real_session_factory: async_sessionmaker[AsyncSession],
        publication: Publish,
    ) -> None:
        """A missing Ticket still publishes the complete roster; the
        detector receives exactly one `run_catch_up` with no queue."""
        ticket_id = uuid.uuid7()

        await run_ticket_convergence(
            ticket_id=ticket_id, session_factory=real_session_factory
        )

        mine = [
            call
            for call in publication.calls
            if call["task_name"] == RUN_CATCH_UP
            and call["kwargs"]["fetcher_name"] == NAME
        ]
        assert mine == [
            {
                "task_name": RUN_CATCH_UP,
                "kwargs": {"fetcher_name": NAME, "ticket_id": str(ticket_id)},
                "queue": None,
            }
        ]


# ---------------------------------------------------------------------------
# A2. run() outcomes: exact FetcherRun status and counters
# ---------------------------------------------------------------------------


@pytest.mark.integration
@pytest.mark.usefixtures("units")
class TestRunOutcomes:
    async def test_updated_only_is_success(
        self, world: ReleaseWorld, runs: _Runs, server: DownloadServer
    ) -> None:
        first, second = await _seeded(world, 2)
        _serve(server, first, second)

        with capture_logs() as logs:
            run = await _run(runs)

        assert _outcome(run) == ("success", 2, 0, 2, 0)
        assert (run.error_message, run.error_detail) == (None, None)
        assert logged(logs, RUN_COMPLETED) == [run_completed(selected=2, updated=2)]
        for occurrence in (first, second):
            assert await released_at(world, occurrence) == ISSUED_AT
            assert await released_events(world, occurrence.ticket_id) == [
                occurrence.released_event()
            ]

    async def test_no_match_only_is_success_without_update(
        self, world: ReleaseWorld, runs: _Runs, server: DownloadServer
    ) -> None:
        (occurrence,) = await _seeded(world)
        server.add(REPOSITORY, repository(matching("CVE-2099-99999999")))

        run = await _run(runs)

        assert _outcome(run) == ("success", 1, 0, 0, 0)
        assert await released_at(world, occurrence) is None
        assert await events_of(world, occurrence.ticket_id) == []

    async def test_concurrent_already_released_is_succeeded_not_updated(
        self,
        world: ReleaseWorld,
        runs: _Runs,
        server: DownloadServer,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        (occurrence,) = await _seeded(world)
        _serve(server, occurrence)
        between_phases(monkeypatch, _released_concurrently(world, occurrence))

        run = await _run(runs)

        assert _outcome(run) == ("success", 1, 0, 0, 0)
        assert await released_at(world, occurrence) == WINNER_AT
        assert await events_of(world, occurrence.ticket_id) == []

    async def test_stale_inapplicable_is_succeeded(
        self,
        world: ReleaseWorld,
        runs: _Runs,
        server: DownloadServer,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        (occurrence,) = await _seeded(world)
        _serve(server, occurrence)
        between_phases(
            monkeypatch, _leaves(world, occurrence.ticket_id, TicketStatus.IGNORED)
        )

        with capture_logs() as logs:
            run = await _run(runs)

        assert _outcome(run) == ("success", 1, 0, 0, 0)
        assert logged(logs, OCCURRENCE_STALE) == [
            occurrence_stale(occurrence, "ticket_not_operable")
        ]
        assert await released_at(world, occurrence) is None

    async def test_failed_only_is_a_normal_return_failure(
        self, world: ReleaseWorld, runs: _Runs, server: DownloadServer
    ) -> None:
        (occurrence,) = await _seeded(world)
        _forbid(server, REPOSITORY)

        with capture_logs() as logs:
            run = await _run(runs)

        assert _outcome(run) == ("failure", 0, 0, 0, 1)
        assert run.error_message == "All 1 items failed"
        assert (run.error_detail, run.error_traceback) == (None, None)
        assert logged(logs, OCCURRENCE_FAILED) == [
            occurrence_failed(occurrence, REPOSITORY, "http_status")
        ]
        assert await released_at(world, occurrence) is None

    async def test_mixed_outcomes_are_partial(
        self, world: ReleaseWorld, runs: _Runs, server: DownloadServer
    ) -> None:
        """One updated, one no-match, and one failed occurrence."""
        updated, no_match = await _seeded(world, 2)
        (failed,) = await _seeded(world, current=(OTHER_REPOSITORY,))
        _serve(server, updated)
        _forbid(server, OTHER_REPOSITORY)

        with capture_logs() as logs:
            run = await _run(runs)

        assert _outcome(run) == ("partial", 2, 0, 1, 1)
        assert run.error_message is None
        assert logged(logs, RUN_COMPLETED) == [
            run_completed(selected=3, updated=1, no_op=1, failed=1)
        ]
        assert await released_at(world, updated) == ISSUED_AT
        assert await released_at(world, no_match) is None
        assert await released_at(world, failed) is None

    async def test_empty_run_is_success_with_zero_counters(
        self,
        runs: _Runs,
        server: DownloadServer,
        units: UnitSessions,
    ) -> None:
        with capture_logs() as logs:
            run = await _run(runs)

        assert _outcome(run) == ("success", 0, 0, 0, 0)
        assert (run.error_message, run.error_detail) == (None, None)
        assert server.requests == []
        assert units.sessions == []
        assert logged(logs, RUN_COMPLETED) == [run_completed()]

    async def test_shared_repository_failure_counts_each_occurrence_once(
        self, world: ReleaseWorld, runs: _Runs, server: DownloadServer
    ) -> None:
        occurrences = await _seeded(world, 3)
        _forbid(server, REPOSITORY)

        with capture_logs() as logs:
            run = await _run(runs)

        assert _outcome(run) == ("failure", 0, 0, 0, 3)
        assert run.error_message == "All 3 items failed"
        assert [str(r.url) for r in server.requests] == [server.repomd_url(REPOSITORY)]
        assert len(logged(logs, REPOSITORY_FAILED)) == 1
        assert logged(logs, OCCURRENCE_FAILED) == [
            occurrence_failed(o, REPOSITORY, "http_status") for o in occurrences
        ]


# ---------------------------------------------------------------------------
# A3. Per-unit finalizer (testing-strategy.md, Fetcher Outcome and Effect
# Accounting: the IBS release-detector exception)
# ---------------------------------------------------------------------------


@pytest.mark.integration
@pytest.mark.usefixtures("units")
class TestPerUnitFinalizer:
    async def test_commit_exception_fails_the_run_without_a_unit_metric(
        self,
        world: ReleaseWorld,
        runs: _Runs,
        server: DownloadServer,
        units: UnitSessions,
        publication: Publish,
    ) -> None:
        """The second unit's commit fails: the run fails with the first
        unit's success and update preserved, no terminal or update metric
        for the second, and the third never processed."""
        first, second, third = await _seeded(world, 3)
        _serve(server, first, second, third)
        error = OperationalError("COMMIT", None, Exception("fictional reset"))
        units.failing_commit = (1, error)

        with capture_logs() as logs:
            raised, run = await _run_failing(runs, OperationalError)

        assert raised is error
        assert _outcome(run) == ("failure", 1, 0, 1, 0)
        assert run.error_message == "Unexpected error"
        assert len(units.sessions) == 2
        assert logged(logs, OCCURRENCE_FAILED) == []
        assert logged(logs, RUN_COMPLETED) == []
        assert publication.calls == []
        assert await released_at(world, first) == ISSUED_AT
        assert await released_at(world, second) is None
        assert await released_at(world, third) is None

    @pytest.mark.parametrize(
        ("make_error", "message"),
        [
            pytest.param(
                lambda: RuntimeError("fictional bug"),
                "Unexpected error",
                id="programming-error",
            ),
            pytest.param(
                SoftTimeLimitExceeded, _soft_limit_message(1), id="soft-time-limit"
            ),
        ],
    )
    async def test_non_operational_drain_exception_keeps_committed_metrics(
        self,
        world: ReleaseWorld,
        runs: _Runs,
        server: DownloadServer,
        units: UnitSessions,
        publication: Publish,
        monkeypatch: pytest.MonkeyPatch,
        make_error: Callable[[], BaseException],
        message: str,
    ) -> None:
        """After the first committed release, its convergence publication
        raises: the run fails with that unit's success and update metrics
        and `items_failed` unchanged; the release stays committed and the
        second occurrence is not processed."""
        first, second = await _seeded(world, 2)
        _serve(server, first, second)
        register_after_release(monkeypatch)
        error = make_error()
        publication.error = error

        with capture_logs() as logs:
            raised, run = await _run_failing(runs, type(error))

        assert raised is error
        assert _outcome(run) == ("failure", 1, 0, 1, 0)
        assert run.error_message == message
        assert published(publication.calls) == [first.ticket_id]
        assert len(units.sessions) == 1
        assert logged(logs, OCCURRENCE_FAILED) == []
        assert [e for e in logs if e["log_level"] == "error"] == []
        assert await released_at(world, first) == ISSUED_AT
        assert await released_events(world, first.ticket_id) == [first.released_event()]
        assert await released_at(world, second) is None

    async def test_broker_operational_error_is_absorbed(
        self,
        world: ReleaseWorld,
        runs: _Runs,
        server: DownloadServer,
        publication: Publish,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        first, second = await _seeded(world, 2)
        _serve(server, first, second)
        register_after_release(monkeypatch)
        publication.error = KombuOperationalError(BROKER_FAILURE)

        with capture_logs() as logs:
            run = await _run(runs)

        assert _outcome(run) == ("success", 2, 0, 2, 0)
        assert run.error_message is None
        assert published(publication.calls) == [first.ticket_id, second.ticket_id]
        assert [e for e in logs if e["log_level"] == "error"] == [
            publication_failed(first.ticket_id),
            publication_failed(second.ticket_id),
        ]
        assert SECRET not in repr(logs)
        assert "broker.example.test" not in repr(logs)
        assert await released_at(world, first) == ISSUED_AT
        assert await released_at(world, second) == ISSUED_AT


# ---------------------------------------------------------------------------
# A4. Whole-run errors and sanitization
# ---------------------------------------------------------------------------


@pytest.mark.integration
@pytest.mark.usefixtures("units")
class TestRunErrors:
    @pytest.mark.parametrize(
        "make_error",
        [
            pytest.param(
                lambda: OperationalError("SELECT", None, Exception("outage")),
                id="operational",
            ),
            pytest.param(
                lambda: DBAPIError("SELECT", None, Exception("outage")), id="dbapi"
            ),
        ],
    )
    async def test_enumeration_failure_is_a_sanitized_fetcher_error(
        self,
        world: ReleaseWorld,
        runs: _Runs,
        clients: _Clients,
        units: UnitSessions,
        monkeypatch: pytest.MonkeyPatch,
        make_error: Callable[[], Exception],
    ) -> None:
        (occurrence,) = await _seeded(world)
        error = make_error()

        async def failing(db: AsyncSession, **kwargs: Any) -> Any:
            raise error

        monkeypatch.setattr(detector, "load_product_release_candidates", failing)

        with capture_logs() as logs:
            raised, run = await _run_failing(runs, FetcherError)

        assert str(raised) == ENUMERATION_FAILED
        assert raised.__cause__ is error
        assert _outcome(run) == ("failure", 0, 0, 0, 0)
        assert run.error_message == ENUMERATION_FAILED
        assert run.error_detail == str(error)
        assert clients.calls == []
        assert units.sessions == []
        assert logged(logs, RUN_COMPLETED) == []
        assert await released_at(world, occurrence) is None

    async def test_unexpected_exception_uses_the_generic_message(
        self,
        world: ReleaseWorld,
        runs: _Runs,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        await _seeded(world)
        error = RuntimeError(f"cannot reach {INTERNAL_URL}/repodata/repomd.xml")

        async def failing(db: AsyncSession, **kwargs: Any) -> Any:
            raise error

        monkeypatch.setattr(detector, "load_product_release_candidates", failing)

        with capture_logs() as logs:
            raised, run = await _run_failing(runs, RuntimeError)

        assert raised is error
        assert run.status == "failure"
        assert run.error_message == "Unexpected error"
        assert run.error_message is not None
        assert "example.test" not in run.error_message
        assert SECRET not in run.error_message
        # The raw text is restricted to the operator-only detail.
        assert run.error_detail == str(error)
        assert SECRET not in repr(logs)
        assert "example.test" not in repr(logs)

    async def test_soft_time_limit_in_a_unit_uses_the_enriched_message(
        self,
        world: ReleaseWorld,
        runs: _Runs,
        server: DownloadServer,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        first, second = await _seeded(world, 2)
        _serve(server, first, second)
        signal = SoftTimeLimitExceeded()
        _failing_for(monkeypatch, second, signal)

        raised, run = await _run_failing(runs, SoftTimeLimitExceeded)

        assert raised is signal
        assert _outcome(run) == ("failure", 1, 0, 1, 0)
        assert run.error_message == _soft_limit_message(1)
        assert await released_at(world, first) == ISSUED_AT
        assert await released_at(world, second) is None

    async def test_failed_repository_leaves_no_raw_data_in_public_fields(
        self, world: ReleaseWorld, runs: _Runs, server: DownloadServer
    ) -> None:
        """A transport error carrying a credential-bearing URL: the public
        message is the bounded all-failed message and no log echoes it."""
        await _seeded(world)

        def refuse(_: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError(f"{INTERNAL_URL} refused")

        server.script(server.repomd_url(REPOSITORY), refuse)

        with capture_logs() as logs:
            run = await _run(runs)

        assert _outcome(run) == ("failure", 0, 0, 0, 1)
        assert run.error_message == "All 1 items failed"
        assert run.error_detail is None
        assert SECRET not in repr(logs)
        assert "download.internal.example.test" not in repr(logs)


# ---------------------------------------------------------------------------
# A5. HTTP client lifecycle
# ---------------------------------------------------------------------------


@pytest.mark.integration
@pytest.mark.usefixtures("units")
class TestHttpClientLifecycle:
    async def test_client_is_created_lazily_once_and_closed_by_run(
        self,
        world: ReleaseWorld,
        runs: _Runs,
        server: DownloadServer,
        clients: _Clients,
    ) -> None:
        (occurrence,) = await _seeded(world)
        _serve(server, occurrence)
        fetcher = DetectIbsProductReleases()
        assert fetcher._http_client is None
        assert clients.calls == []

        run = await _run(runs, fetcher)

        assert _outcome(run) == ("success", 1, 0, 1, 0)
        assert clients.calls == [(NAME, {"timeout": TIMEOUT})]
        [client] = clients.created
        assert client.is_closed
        assert fetcher._http_client is None
        assert server.requests
        for request in server.requests:
            assert "authorization" not in request.headers
            assert "cookie" not in request.headers


# ---------------------------------------------------------------------------
# A6. catch_up()
# ---------------------------------------------------------------------------


SilentBuild = Callable[[ReleaseWorld], Awaitable[str]]


async def _missing(world: ReleaseWorld) -> str:
    return str(uuid.uuid4())


def _in_status(status: TicketStatus) -> SilentBuild:
    async def build(world: ReleaseWorld) -> str:
        (occurrence,) = await _seeded(world, status=status)
        return str(occurrence.ticket_id)

    return build


async def _cveless(world: ReleaseWorld) -> str:
    seed = Seed(world.session, world)
    ticket = await seed.ticket(with_cve=False)
    await seed.occurrence(ticket, await seed.product())
    await seed.commit()
    return str(ticket.id)


async def _empty_tree(world: ReleaseWorld) -> str:
    seed = Seed(world.session, world)
    ticket = await seed.ticket()
    await seed.commit()
    return str(ticket.id)


async def _git_only(world: ReleaseWorld) -> str:
    seed = Seed(world.session, world)
    ticket = await seed.ticket()
    await seed.occurrence(ticket, await seed.product(), workflow=WorkflowType.GIT)
    await seed.commit()
    return str(ticket.id)


async def _all_released(world: ReleaseWorld) -> str:
    seed = Seed(world.session, world)
    ticket = await seed.ticket()
    await seed.occurrence(ticket, await seed.product(), released_at=ISSUED_AT)
    await seed.commit()
    return str(ticket.id)


_SILENT_CASES = [
    pytest.param(_missing, id="missing-ticket"),
    pytest.param(_cveless, id="ticket-without-cve"),
    pytest.param(_in_status(TicketStatus.RESOLVED), id="resolved"),
    pytest.param(_in_status(TicketStatus.IGNORED), id="ignored"),
    pytest.param(_in_status(TicketStatus.DUPLICATED), id="duplicated"),
    pytest.param(_empty_tree, id="no-packages"),
    pytest.param(_git_only, id="no-ibs-occurrence"),
    pytest.param(_all_released, id="all-released"),
]


@pytest.mark.integration
@pytest.mark.usefixtures("units")
class TestCatchUp:
    @pytest.mark.parametrize("build", _SILENT_CASES)
    async def test_silent_return_performs_no_http_log_or_write(
        self,
        world: ReleaseWorld,
        server: DownloadServer,
        clients: _Clients,
        units: UnitSessions,
        build: SilentBuild,
    ) -> None:
        ticket_id = await build(world)
        session = await world.open_session()
        fetcher = DetectIbsProductReleases()

        with capture_logs() as logs, SessionStatementRecorder(session) as recorder:
            await fetcher.catch_up(ticket_id, session)

        assert logs == []
        assert clients.calls == []
        assert fetcher._http_client is None
        assert server.requests == []
        assert units.sessions == []
        assert len(recorder.statements) == 1
        assert recorder.writes() == []
        assert recorder.row_locks() == []
        assert not session.in_transaction()

    async def test_passed_session_only_reads_and_the_release_is_committed(
        self,
        world: ReleaseWorld,
        server: DownloadServer,
        units: UnitSessions,
        metric_helpers: dict[str, Mock],
    ) -> None:
        (occurrence,) = await _seeded(world)
        _serve(server, occurrence)
        session = await world.open_session()

        with capture_logs() as logs, SessionStatementRecorder(session) as recorder:
            await DetectIbsProductReleases().catch_up(
                str(occurrence.ticket_id), session
            )

        assert recorder.statements
        assert recorder.writes() == []
        assert recorder.row_locks() == []
        assert not session.in_transaction()
        assert not session.new
        assert not session.dirty
        assert not session.deleted
        assert len(units.sessions) == 1
        assert units.sessions[0] is not session
        assert logs == [run_completed(selected=1, updated=1)]
        # Visible from an independent session after catch-up returned.
        assert await released_at(world, occurrence) == ISSUED_AT
        assert await released_events(world, occurrence.ticket_id) == [
            occurrence.released_event()
        ]
        for spy in metric_helpers.values():
            spy.assert_not_called()

    async def test_only_the_tickets_occurrences_are_processed(
        self, world: ReleaseWorld, server: DownloadServer
    ) -> None:
        mine, other = await _seeded(world, 2)
        _serve(server, mine, other)

        await DetectIbsProductReleases().catch_up(
            str(mine.ticket_id), await world.open_session()
        )

        assert await released_at(world, mine) == ISSUED_AT
        assert await released_at(world, other) is None
        assert await events_of(world, other.ticket_id) == []

    async def test_advisory_predating_the_ticket_keeps_its_issued_time(
        self, world: ReleaseWorld, server: DownloadServer
    ) -> None:
        (occurrence,) = await _seeded(world)
        _serve(server, occurrence, issued="1000000000")
        old = datetime(2001, 9, 9, 1, 46, 40, tzinfo=UTC)
        probe = await world.probe()
        created_at = (
            await probe.execute(
                select(Ticket.created_at).where(Ticket.id == occurrence.ticket_id)
            )
        ).scalar_one()
        await probe.rollback()
        assert created_at > old

        await DetectIbsProductReleases().catch_up(
            str(occurrence.ticket_id), await world.open_session()
        )

        assert await released_at(world, occurrence) == old
        assert await released_events(world, occurrence.ticket_id) == [
            occurrence.released_event("2001-09-09T01:46:40Z")
        ]

    async def test_partial_failure_returns_and_logs_with_the_task_id(
        self,
        world: ReleaseWorld,
        server: DownloadServer,
        metric_helpers: dict[str, Mock],
    ) -> None:
        """One released and one failed occurrence of one Ticket: normal
        return; the failed one is logged at WARNING with the Ticket,
        fetcher, occurrence, repository, bounded cause, and the task-bound
        `celery_task_id`."""
        seed = Seed(world.session, world)
        ticket = await seed.ticket()
        released = await seed.occurrence(ticket, await seed.product())
        failed = await seed.occurrence(
            ticket, await seed.product(current=(OTHER_REPOSITORY,))
        )
        await seed.commit()
        _serve(server, released)
        _forbid(server, OTHER_REPOSITORY)
        celery_task_id = str(uuid.uuid4())
        bind_contextvars(celery_task_id=celery_task_id)
        try:
            with capture_logs(processors=[merge_contextvars]) as logs:
                await DetectIbsProductReleases().catch_up(
                    str(ticket.id), await world.open_session()
                )
        finally:
            unbind_contextvars("celery_task_id")

        assert logged(logs, OCCURRENCE_FAILED) == [
            {
                **occurrence_failed(failed, OTHER_REPOSITORY, "http_status"),
                "celery_task_id": celery_task_id,
            }
        ]
        assert await released_at(world, released) == ISSUED_AT
        assert await released_at(world, failed) is None
        for spy in metric_helpers.values():
            spy.assert_not_called()

    async def test_all_failed_raises_the_sanitized_fetcher_error(
        self,
        world: ReleaseWorld,
        server: DownloadServer,
        units: UnitSessions,
        metric_helpers: dict[str, Mock],
    ) -> None:
        seed = Seed(world.session, world)
        ticket = await seed.ticket()
        first, second = sorted(
            [
                await seed.occurrence(ticket, await seed.product()),
                await seed.occurrence(
                    ticket, await seed.product(current=(OTHER_REPOSITORY,))
                ),
            ],
            key=lambda occurrence: occurrence.id,
        )
        await seed.commit()
        _forbid(server, REPOSITORY)
        _forbid(server, OTHER_REPOSITORY)

        with capture_logs() as logs, pytest.raises(FetcherError) as raised:
            await DetectIbsProductReleases().catch_up(
                str(ticket.id), await world.open_session()
            )

        assert str(raised.value) == "All 2 IBS Product release occurrences failed"
        assert raised.value.__cause__ is None
        assert not is_retryable_condition(raised.value)
        assert len(logged(logs, OCCURRENCE_FAILED)) == 2
        assert logged(logs, RUN_COMPLETED) == [run_completed(selected=2, failed=2)]
        assert units.sessions == []
        for occurrence in (first, second):
            assert await released_at(world, occurrence) is None
        for spy in metric_helpers.values():
            spy.assert_not_called()

    @pytest.mark.parametrize(
        "status", [TicketStatus.IGNORED, TicketStatus.DUPLICATED], ids=str
    )
    async def test_ticket_leaving_the_active_states_is_a_stale_no_op(
        self,
        world: ReleaseWorld,
        server: DownloadServer,
        monkeypatch: pytest.MonkeyPatch,
        status: TicketStatus,
    ) -> None:
        (occurrence,) = await _seeded(world)
        _serve(server, occurrence)
        between_phases(monkeypatch, _leaves(world, occurrence.ticket_id, status))

        with capture_logs() as logs:
            await DetectIbsProductReleases().catch_up(
                str(occurrence.ticket_id), await world.open_session()
            )

        assert logs == [
            occurrence_stale(occurrence, "ticket_not_operable"),
            run_completed(selected=1, no_op=1),
        ]
        assert await released_at(world, occurrence) is None
        assert await events_of(world, occurrence.ticket_id) == []

    @pytest.mark.parametrize("concurrent", ["periodic", "catch-up"])
    async def test_concurrent_invocations_are_idempotent(
        self,
        world: ReleaseWorld,
        server: DownloadServer,
        monkeypatch: pytest.MonkeyPatch,
        concurrent: str,
    ) -> None:
        """A periodic execution (or a second catch-up) runs to completion
        after this catch-up's repository I/O and before its transaction:
        exactly one `released_at` and one event; the later unit observes
        the committed release as a no-op."""
        (occurrence,) = await _seeded(world)
        _serve(server, occurrence)
        other = DetectIbsProductReleases()
        started: list[bool] = []

        async def run_other() -> None:
            if started:
                return
            started.append(True)
            session = await world.open_session()
            if concurrent == "periodic":
                await other.execute(session)
            else:
                await other.catch_up(str(occurrence.ticket_id), session)
            await other._teardown_http_client()

        between_phases(monkeypatch, run_other)

        with capture_logs() as logs:
            await DetectIbsProductReleases().catch_up(
                str(occurrence.ticket_id), await world.open_session()
            )

        assert started == [True]
        assert logged(logs, RUN_COMPLETED) == [
            run_completed(selected=1, updated=1),
            run_completed(selected=1, no_op=1),
        ]
        expected = (1, 0, 1, 0) if concurrent == "periodic" else (0, 0, 0, 0)
        assert (other._succeeded, other._created, other._updated, other._failed) == (
            expected
        )
        assert await released_at(world, occurrence) == ISSUED_AT
        assert await released_events(world, occurrence.ticket_id) == [
            occurrence.released_event()
        ]


# ---------------------------------------------------------------------------
# A6b. Request delay (Fetcher: Request Delay); the placement of each wait is
# covered by `test_ibs_product_download_http.py` and
# `test_ibs_product_release.py`
# ---------------------------------------------------------------------------


def _recorded_sleeps(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    """Replace the download module's `asyncio.sleep` by a recorder."""
    sleeps: list[float] = []

    async def sleep(delay: float) -> None:
        sleeps.append(delay)

    monkeypatch.setattr(
        download, "asyncio", SimpleNamespace(Lock=asyncio.Lock, sleep=sleep)
    )
    return sleeps


@pytest.mark.integration
@pytest.mark.usefixtures("units")
class TestRequestDelay:
    @pytest.mark.parametrize(
        ("configured", "expected"), [(0.0, []), (0.5, [0.5] * 3)], ids=["0", "0.5"]
    )
    async def test_run_waits_its_snapshot_delay_between_requests(
        self,
        world: ReleaseWorld,
        runs: _Runs,
        server: DownloadServer,
        monkeypatch: pytest.MonkeyPatch,
        configured: float,
        expected: list[float],
    ) -> None:
        """The run snapshot's `request_delay`, not the class value, separates
        the four requests of one repository examination."""
        (occurrence,) = await _seeded(world)
        _serve(server, occurrence)
        sleeps = _recorded_sleeps(monkeypatch)
        monkeypatch.setattr(DetectIbsProductReleases, "default_request_delay", 9.0)
        run_id = await runs.start()

        await DetectIbsProductReleases().run(
            run_id=run_id,
            config=FetcherRunConfig(
                hard_time_limit_seconds=3600,
                request_delay=configured,
                custom_settings={},
            ),
        )

        assert _outcome(await runs.finalized(run_id)) == ("success", 1, 0, 1, 0)
        assert len(server.requests) == 4
        assert sleeps == expected

    async def test_catch_up_waits_the_class_default_delay(
        self,
        world: ReleaseWorld,
        server: DownloadServer,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Catch-up has no run snapshot: the class `default_request_delay`
        (0 in production, patched here) separates its requests."""
        (occurrence,) = await _seeded(world)
        _serve(server, occurrence)
        sleeps = _recorded_sleeps(monkeypatch)
        monkeypatch.setattr(DetectIbsProductReleases, "default_request_delay", 0.25)

        await DetectIbsProductReleases().catch_up(
            str(occurrence.ticket_id), await world.open_session()
        )

        assert len(server.requests) == 4
        assert sleeps == [0.25] * 3
        assert await released_at(world, occurrence) == ISSUED_AT


# ---------------------------------------------------------------------------
# A7. run_catch_up composition
# ---------------------------------------------------------------------------


@dataclass
class _CatchUpTask:
    factory: async_sessionmaker[AsyncSession]
    engine: FakeEngine


@pytest.fixture
async def catch_up_task(
    real_session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> AsyncIterator[_CatchUpTask]:
    """Route `run_catch_up_async()` to the test database with a fake
    engine and the committed enabled `FetcherConfig` of the fetcher."""
    created = _CatchUpTask(real_session_factory, FakeEngine())
    monkeypatch.setattr(fetchers, "async_session_factory", real_session_factory)
    monkeypatch.setattr(fetchers, "engine", created.engine)
    await seed_fetcher_config(real_session_factory, NAME, enabled=True)
    try:
        yield created
    finally:
        await delete_fetcher_rows(real_session_factory, [NAME])


@pytest.mark.integration
@pytest.mark.usefixtures("units")
class TestRunCatchUpAsync:
    async def test_success_releases_and_closes_the_client(
        self,
        world: ReleaseWorld,
        server: DownloadServer,
        clients: _Clients,
        catch_up_task: _CatchUpTask,
    ) -> None:
        (occurrence,) = await _seeded(world)
        _serve(server, occurrence)

        with capture_logs() as logs:
            await fetchers.run_catch_up_async(NAME, str(occurrence.ticket_id))

        assert [e for e in logs if e["log_level"] == "error"] == []
        assert await released_at(world, occurrence) == ISSUED_AT
        [client] = clients.created
        assert client.is_closed
        catch_up_task.engine.dispose.assert_awaited_once_with()
        assert await fetcher_run_count(catch_up_task.factory, NAME) == 0

    async def test_all_failed_propagates_as_non_retryable(
        self,
        world: ReleaseWorld,
        server: DownloadServer,
        clients: _Clients,
        catch_up_task: _CatchUpTask,
    ) -> None:
        (occurrence,) = await _seeded(world)
        _forbid(server, REPOSITORY)

        with pytest.raises(FetcherError) as raised:
            await fetchers.run_catch_up_async(NAME, str(occurrence.ticket_id))

        assert str(raised.value) == "All 1 IBS Product release occurrences failed"
        assert not is_retryable_condition(raised.value)
        [client] = clients.created
        assert client.is_closed
        catch_up_task.engine.dispose.assert_awaited_once_with()
        assert await fetcher_run_count(catch_up_task.factory, NAME) == 0
        assert await released_at(world, occurrence) is None


class _StandInSession:
    """The caller-owned catch-up session of the no-database wrapper test:
    only the read commit is reachable (enumeration is substituted)."""

    def __init__(self) -> None:
        self.commit = AsyncMock()


class _StandInContext:
    def __init__(self, session: _StandInSession) -> None:
        self.session = session

    async def __aenter__(self) -> _StandInSession:
        return self.session

    async def __aexit__(self, *exc_info: object) -> bool:
        return False


@pytest.mark.unit
class TestRunCatchUpSyncWrapper:
    def test_all_failed_fails_terminally_without_retry(
        self, server: DownloadServer, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The real fetcher inside the wrapper's own `asyncio.run()`, with
        the enabled read, the session, and the enumeration substituted:
        every occurrence fails in repository I/O, so no unit session is
        opened and the `FetcherError` is not retried."""
        engine = FakeEngine()
        monkeypatch.setattr(fetchers, "engine", engine)
        monkeypatch.setattr(
            fetchers, "get_fetcher_enabled", AsyncMock(return_value=True)
        )
        session = _StandInSession()
        monkeypatch.setattr(
            fetchers, "async_session_factory", lambda: _StandInContext(session)
        )
        ticket_id = uuid.uuid4()
        candidate = ProductReleaseCandidate(
            occurrence_id=uuid.uuid4(),
            ticket_id=ticket_id,
            package_id=uuid.uuid4(),
            track_id=uuid.uuid4(),
            product_id=uuid.uuid4(),
            cve_id="CVE-2099-00000001",
            package_name="example",
            current_repositories=(REPOSITORY,),
            historical_repositories=(),
        )
        selections: list[uuid.UUID | None] = []

        async def load(
            db: Any, *, ticket_id: uuid.UUID | None = None
        ) -> list[ProductReleaseCandidate]:
            assert db is session
            selections.append(ticket_id)
            return [candidate]

        monkeypatch.setattr(detector, "load_product_release_candidates", load)
        unit_factory = MagicMock(side_effect=AssertionError("must not open a unit"))
        monkeypatch.setattr(boundary, "async_session_factory", unit_factory)
        _forbid(server, REPOSITORY)
        task = FakeTask()

        with capture_logs() as logs, pytest.raises(FetcherError) as raised:
            fetchers._run_catch_up_sync(task, NAME, str(ticket_id))

        assert str(raised.value) == "All 1 IBS Product release occurrences failed"
        task.retry.assert_not_called()
        assert selections == [ticket_id]
        session.commit.assert_awaited_once_with()
        assert [e for e in logs if e["log_level"] == "error"] == [
            {
                "event": "run_catch_up_failed",
                "log_level": "error",
                "fetcher_name": NAME,
                "ticket_id": str(ticket_id),
                "cause": "FetcherError",
                "retries": 0,
            }
        ]
        unit_factory.assert_not_called()
        engine.dispose.assert_awaited_once_with()
