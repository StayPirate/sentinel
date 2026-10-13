"""Tests for the `detect_ibs_track_releases` fetcher
(backend/app/services/packages/detect_ibs_track_releases.py): class
contract and registration, `run()` finalization over the real
`BaseFetcher.run()`, the `IBSClient` lifetime, `catch_up()`, and the
`run_catch_up` composition.

Owning specifications:

- docs/features/packages/ibs-track-release-detection.md (Scope; Scheduled
  Reconciliation Algorithm steps 1 and 9; Catch-Up; Error Handling and its
  Structured Logs; Background Fetcher: Fetcher `detect_ibs_track_releases`,
  Request Delay, Metrics and Run Status; Testing Requirements).
- docs/features/platform/fetcher-infrastructure.md (BaseFetcher Base
  Class: Finalization, Outcome and effect accounting; Abstract Interface,
  Naming Convention; Per-Ticket Catch-Up: Override-point contract, Celery
  task wrapper, Interface contract, Fetcher inventory; Error Message
  Sanitization and the `SoftTimeLimitExceeded` convention; BaseFetcher
  HTTP Client Integration: HTTP Client Ownership Rule; Registry: Fetcher
  Discovery; Redbeat Entry Structure; Data Model, FetcherConfig
  bootstrap).
- docs/features/platform/testing-strategy.md (Fetcher Outcome and Effect
  Accounting, including the IBS release-detector per-unit finalizer
  exception and shared failures counted once per unit; Ticket Convergence
  Publication Handoff, "IBS track and Product release detection").
- docs/features/integrations/ibs-integration.md (Service Layer > IBSClient:
  one client per workflow invocation, closed before it returns; Request
  Authentication step 1: credentials not configured, no HTTP request).
- docs/features/packages/package-service.md (`run_ticket_convergence()`,
  the catch-up roster).

The reconciliation boundary itself (selection, evidence, source info and
diffs, fallback, races, failure conversion, commit, hook, and drain) is
covered by `test_ibs_track_release.py` and
`test_ibs_track_release_races.py`; this module tests the fetcher-level
composition around it and reuses their helpers from
`tests/support/ibs_track_release.py`.

Every `IBSClient` is the production client built from the application
settings, which are pointed at the fictional `TEST_API_URL` with the
account `jdoe` and a fictional key (or left empty for the
credentials-not-configured case), behind the fake IBS API of `FakeIBS`.
The fetcher module's `IBSClient` name is replaced by `_IBSClients`, which
constructs that real client and records each construction and completed
`aclose()`. `base_fetcher.create_http_client` is replaced by a spy that
fails if `BaseFetcher.http_client` is ever created. The boundary's
module-level `async_session_factory` is replaced by `TrackUnitSessions`
over `real_session_factory`, and `task_publication.publish_task` by a
recorder, so no test reaches a broker or the network. The `run()` tests
also redirect `base_fetcher`'s session factory and own committed
`FetcherConfig`/`FetcherRun` rows under a test-only name (deleted at
teardown); the `run_catch_up` tests own the committed `FetcherConfig` row
of the production name. Each pytest-xdist worker owns its database and
runs one test at a time, so the unrestricted periodic selection sees only
the rows a test committed. The package service's evaluation date is
pinned to `EVAL`. Unless a test states otherwise, each track is an
`ANALYSIS`/`PENDING` IBS track of `PROJECT` below its own `Analysis`
Ticket with its own CVE, and source info serves `CURRENT`. All data is
fictional.
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
from pydantic import SecretStr
from redbeat import RedBeatSchedulerEntry
from sqlalchemy import delete, event, insert, update
from sqlalchemy.exc import DBAPIError, OperationalError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from sqlalchemy.orm import Session
from structlog.contextvars import (
    bind_contextvars,
    merge_contextvars,
    unbind_contextvars,
)
from structlog.testing import capture_logs

import app.services.base_fetcher as base_fetcher_module
import app.services.fetcher_discovery  # noqa: F401
from app.config import settings
from app.core.enums import PackageStatus, TicketStatus, WorkflowType
from app.models.fetcher_config import FetcherConfig
from app.models.fetcher_run import FetcherRun
from app.models.ticket import Ticket
from app.models.ticket_package_track import TicketPackageTrack
from app.models.track_release_checkpoint import TrackReleaseCheckpoint
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
from app.services.http_client import is_retryable_condition
from app.services.ibs_client import IBSClient
from app.services.package_service import run_ticket_convergence
from app.services.packages import detect_ibs_track_releases as detector
from app.services.packages import ibs_track_release as boundary
from app.services.packages.detect_ibs_track_releases import DetectIbsTrackReleases
from app.services.packages.ibs_track_release import TrackReleaseCandidate
from app.tasks import fetchers
from tests.support.cve_catch_up import (
    FakeEngine,
    FakeTask,
    delete_fetcher_rows,
    fetcher_run_count,
    seed_fetcher_config,
)
from tests.support.ibs_api import TEST_API_URL, TEST_HOST, status_response
from tests.support.ibs_keys import fictional_settings_value
from tests.support.ibs_product_release import Publish, published
from tests.support.ibs_track_release import (
    CHECKPOINT,
    CURRENT,
    DIFF_FAILED,
    FETCHER,
    HISTORY_UNAVAILABLE,
    OTHER_CVE,
    OTHER_PROJECT,
    PACKAGE,
    PROJECT,
    SEEN_AT,
    SIBLING_PACKAGE,
    SOURCE_INFO_FAILED,
    TRACK_FAILED,
    WAIT,
    FakeIBS,
    Seed,
    Track,
    TrackUnitSessions,
    TrackWorld,
    before_local_unit,
    checkpoint_of,
    checkpoint_srcmd5,
    diff_failed,
    events_of,
    history_unavailable,
    install_ibs,
    install_units,
    issue,
    logged,
    own,
    publication_failed,
    raising,
    register_after_fixed,
    source_info_failed,
    track_failed,
    track_stale,
    track_status,
    unavailable,
)
from tests.support.module_imports import APP_ROOT, imported_modules
from tests.support.suse_cvss_races import SessionStatementRecorder
from tests.support.ticket_mutations import EVAL

Factory = Callable[[], Awaitable[AsyncSession]]
Outcome = tuple[str, int, int, int, int]
"""`(status, succeeded, created, updated, failed)` of one finalized run."""

NAME: Final = FETCHER
SCHEDULE: Final = "0 2 * * *"
DESCRIPTION: Final = (
    "Reconcile existing active-Ticket IBS tracks against expanded package source state"
)
ENUMERATION_FAILED: Final = "Failed to enumerate IBS track release candidates"
RUN_CATCH_UP: Final = "run_catch_up"
CREDENTIALS: Final = "credentials_not_configured"

LATER: Final = datetime(2026, 6, 1, 12, 0, tzinfo=UTC)
"""When a concurrent handler accepted its checkpoint."""

SECRET: Final = "fictional-secret"
INTERNAL_URL: Final = f"https://ibs-user:{SECRET}@api.internal.example.test"
"""A fictional internal URL with credentials; never public or logged."""

BROKER_FAILURE: Final = f"redis://sentinel:{SECRET}@broker.example.test:6379/1 down"

ZZ_PACKAGE: Final = "example-zz"
"""A third logical package, examined after `PACKAGE` and `SIBLING_PACKAGE`
(diffs are requested in package-name order)."""

_RUN_CONFIG: Final = FetcherRunConfig(
    hard_time_limit_seconds=3600, request_delay=0, custom_settings={}
)


# ---------------------------------------------------------------------------
# Substitutes and fixtures
# ---------------------------------------------------------------------------


@dataclass
class _IBSClients:
    """Substitute for the fetcher module's `IBSClient`: constructs the real
    client with the given arguments (none in production, so the client
    reads the application settings) and records each construction and
    each completed `aclose()`."""

    arguments: list[dict[str, Any]] = field(default_factory=list)
    created: list[IBSClient] = field(default_factory=list)
    closed: list[IBSClient] = field(default_factory=list)

    def __call__(self, **kwargs: Any) -> IBSClient:
        self.arguments.append(kwargs)
        client = IBSClient(**kwargs)
        self.created.append(client)
        close = client.aclose

        async def _recording_close() -> None:
            await close()
            self.closed.append(client)

        client.aclose = _recording_close  # type: ignore[method-assign]
        return client

    def assert_each_closed(self, count: int) -> None:
        """Exactly `count` clients were created from the settings, each
        closed once (in any order), and each one's connection pool is
        closed."""
        assert len(self.created) == count
        assert len(self.closed) == count
        assert {id(client) for client in self.closed} == {
            id(client) for client in self.created
        }
        for client in self.created:
            assert client._http.is_closed
        assert self.arguments == [{}] * count


@pytest.fixture(autouse=True)
def configured_ibs(monkeypatch: pytest.MonkeyPatch) -> None:
    """Production `IBSClient()` settings: the fictional API, account, and
    key."""
    monkeypatch.setattr(settings, "ibs_api_url", TEST_API_URL)
    monkeypatch.setattr(settings, "ibs_username", "jdoe")
    monkeypatch.setattr(
        settings, "ibs_ssh_private_key", SecretStr(fictional_settings_value())
    )


@pytest.fixture(autouse=True)
def clock(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(package_service, "_utc_today", lambda: EVAL)


@pytest.fixture(autouse=True)
def publication(monkeypatch: pytest.MonkeyPatch) -> Publish:
    recorder = Publish()
    monkeypatch.setattr(task_publication, "publish_task", recorder)
    return recorder


@pytest.fixture(autouse=True)
def ibs(monkeypatch: pytest.MonkeyPatch) -> FakeIBS:
    return install_ibs(monkeypatch)


@pytest.fixture(autouse=True)
def ibs_clients(monkeypatch: pytest.MonkeyPatch) -> _IBSClients:
    recorder = _IBSClients()
    monkeypatch.setattr(detector, "IBSClient", recorder)
    return recorder


@pytest.fixture(autouse=True)
def fetcher_http_client(monkeypatch: pytest.MonkeyPatch) -> Mock:
    """`BaseFetcher.http_client` is never created by this fetcher."""
    factory = Mock(side_effect=AssertionError("BaseFetcher.http_client was created"))
    monkeypatch.setattr(base_fetcher_module, "create_http_client", factory)
    return factory


@pytest.fixture
def units(
    real_session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> TrackUnitSessions:
    return install_units(monkeypatch, real_session_factory)


@pytest.fixture
async def world(db_session_factory: Factory) -> AsyncIterator[TrackWorld]:
    created = TrackWorld(db_session_factory, await db_session_factory())
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
    world: TrackWorld,
    count: int = 1,
    status: TicketStatus = TicketStatus.ANALYSIS,
    **kwargs: Any,
) -> list[Track]:
    """`count` committed tracks, each below its own Ticket (in `status`),
    in track-ID order."""
    seed = Seed(world.session, world)
    created = []
    for _ in range(count):
        created.append(await seed.track(await seed.ticket(status), **kwargs))
    await seed.commit()
    return sorted(created, key=lambda track: track.id)


async def _three(world: TrackWorld, ibs: FakeIBS) -> tuple[Track, Track, Track]:
    """Three evidence tracks of three Tickets, examined in this order (one
    diff per package, packages in name order)."""
    seed = Seed(world.session, world)
    first = await seed.track(await seed.ticket())
    second = await seed.track(await seed.ticket(), package_name=SIBLING_PACKAGE)
    third = await seed.track(await seed.ticket(), package_name=ZZ_PACKAGE)
    await seed.commit()
    _evidence(ibs, first, second, third)
    return first, second, third


def _cve(track: Track) -> str:
    assert track.cve_id is not None
    return track.cve_id


def _evidence(ibs: FakeIBS, *tracks: Track, baseline: str = "0") -> None:
    """Source info `CURRENT` for each track's package and one diff per
    package from `baseline` naming every given track's CVE."""
    packages: dict[tuple[str, str], list[str]] = {}
    for track in tracks:
        packages.setdefault((track.project, track.package_name), []).append(_cve(track))
    for (project, package), cves in packages.items():
        ibs.source(project, package, CURRENT)
        ibs.issues(project, package, baseline, CURRENT, *(issue(cve) for cve in cves))


def _no_match(ibs: FakeIBS, track: Track, baseline: str = "0") -> None:
    ibs.source(track.project, track.package_name, CURRENT)
    ibs.issues(track.project, track.package_name, baseline, CURRENT, issue(OTHER_CVE))


def _sorted_logs(entries: list[Any]) -> list[Any]:
    """`entries` in a content order independent of dict key order."""
    return sorted(entries, key=lambda e: repr(sorted(e.items())))


async def _commit(world: TrackWorld, *statements: Any) -> None:
    """Commit `statements` through a fresh independent session."""
    session = await world.open_session()
    for statement in statements:
        await session.execute(statement)
    await session.commit()


def _before_first_unit(
    monkeypatch: pytest.MonkeyPatch, action: Callable[[], Awaitable[None]]
) -> None:
    """Await `action()` once, after the first track's diff and before its
    local unit takes the Ticket lock."""
    done: list[bool] = []

    async def once(_: TrackReleaseCandidate) -> None:
        if not done:
            done.append(True)
            await action()

    before_local_unit(monkeypatch, once)


def _concurrently(
    monkeypatch: pytest.MonkeyPatch, world: TrackWorld, *statements: Any
) -> None:
    """Commit `statements` once, before the first local unit's lock."""
    _before_first_unit(monkeypatch, lambda: _commit(world, *statements))


def _leaves(world: TrackWorld, ticket_id: uuid.UUID, status: TicketStatus) -> Any:
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


def _failing_for(
    monkeypatch: pytest.MonkeyPatch, track: Track, error: BaseException
) -> None:
    """Make `set_track_status()` raise `error` for `track` after the real
    call; other tracks are unchanged."""
    original = package_service.set_track_status

    async def failing(db: AsyncSession, **kwargs: Any) -> Any:
        result = await original(db, **kwargs)
        if kwargs["track_id"] == track.id:
            raise error
        return result

    monkeypatch.setattr(package_service, "set_track_status", failing)


# ---------------------------------------------------------------------------
# run() harness: committed FetcherConfig and FetcherRun under a test name
# ---------------------------------------------------------------------------


class _Runs:
    """Commits one `running` FetcherRun per `start()` and reads it back."""

    def __init__(self, factory: async_sessionmaker[AsyncSession]) -> None:
        self._factory = factory
        self.fetcher_name = f"test_ibs_track_run_{uuid.uuid4().hex[:12]}"
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
    runs: _Runs, fetcher: DetectIbsTrackReleases | None = None
) -> FetcherRun:
    """One complete `run()` that returns normally; the finalized row."""
    run_id = await runs.start()
    await (fetcher or DetectIbsTrackReleases()).run(run_id=run_id, config=_RUN_CONFIG)
    return await runs.finalized(run_id)


async def _run_failing(
    runs: _Runs, error: type[BaseException]
) -> tuple[BaseException, FetcherRun]:
    run_id = await runs.start()
    with pytest.raises(error) as raised:
        await DetectIbsTrackReleases().run(run_id=run_id, config=_RUN_CONFIG)
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
        assert DetectIbsTrackReleases.name == NAME
        assert DetectIbsTrackReleases.description == DESCRIPTION
        assert DetectIbsTrackReleases.default_schedule == SCHEDULE
        assert DetectIbsTrackReleases.participates_in_catch_up is True
        assert DetectIbsTrackReleases.queue is None
        assert DetectIbsTrackReleases.Settings is None
        assert DetectIbsTrackReleases.default_request_delay == 0
        assert DetectIbsTrackReleases.http_client_options == {}

    def test_class_body_declares_no_settings_queue_or_client_options(self) -> None:
        """Custom settings: None; default routing (no `queue`); the 0 s
        `default_request_delay` is declared explicitly; the fetcher's HTTP
        client is never used, so it overrides no option."""
        assert _class_body_assignments(DetectIbsTrackReleases) == {
            "name",
            "description",
            "default_schedule",
            "default_request_delay",
            "participates_in_catch_up",
        }

    def test_class_name_is_derived_from_the_fetcher_name(self) -> None:
        derived = "".join(part.capitalize() for part in NAME.split("_"))

        assert derived == DetectIbsTrackReleases.__name__ == "DetectIbsTrackReleases"

    def test_execute_and_catch_up_are_custom_overrides(self) -> None:
        assert "execute" in DetectIbsTrackReleases.__dict__
        assert "catch_up" in DetectIbsTrackReleases.__dict__
        assert DetectIbsTrackReleases.catch_up is not BaseFetcher.catch_up

    def test_discovery_registers_the_fetcher(self) -> None:
        discovery = APP_ROOT / "services" / "fetcher_discovery.py"

        assert detector.__name__ in imported_modules(discovery, "app.services")
        assert FETCHER_REGISTRY[NAME] is DetectIbsTrackReleases

    def test_fetcher_participates_in_catch_up(self) -> None:
        assert get_catch_up_fetchers()[NAME] is DetectIbsTrackReleases


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
        # 0 2 * * *
        assert entry.schedule.minute == {0}
        assert entry.schedule.hour == {2}
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
# A2. run() outcomes: exact FetcherRun status and counters (Metrics and Run
# Status)
# ---------------------------------------------------------------------------


@pytest.mark.integration
@pytest.mark.usefixtures("units")
class TestRunOutcomes:
    async def test_updated_is_success(
        self, world: TrackWorld, runs: _Runs, ibs: FakeIBS
    ) -> None:
        (track,) = await _seeded(world)
        _evidence(ibs, track)

        with capture_logs() as logs:
            run = await _run(runs)

        assert _outcome(run) == ("success", 1, 0, 1, 0)
        assert (run.error_message, run.error_detail) == (None, None)
        assert own(logs) == []
        assert await track_status(world, track) == PackageStatus.FIXED.value
        assert await events_of(world, track.ticket_id) == [track.fixed_event()]
        assert await checkpoint_srcmd5(world, track) == CURRENT

    async def test_unchanged_source_is_succeeded_without_diff_or_unit(
        self,
        world: TrackWorld,
        runs: _Runs,
        ibs: FakeIBS,
        units: TrackUnitSessions,
    ) -> None:
        (track,) = await _seeded(world, checkpoint=CURRENT)
        ibs.source(PROJECT, PACKAGE, CURRENT)

        run = await _run(runs)

        assert _outcome(run) == ("success", 1, 0, 0, 0)
        assert ibs.diffs() == []
        assert units.sessions == []
        assert await checkpoint_of(world, track) == (CURRENT, SEEN_AT)

    async def test_valid_no_match_is_succeeded_and_advances_the_checkpoint(
        self, world: TrackWorld, runs: _Runs, ibs: FakeIBS
    ) -> None:
        (track,) = await _seeded(world, checkpoint=CHECKPOINT)
        _no_match(ibs, track, baseline=CHECKPOINT)

        run = await _run(runs)

        assert _outcome(run) == ("success", 1, 0, 0, 0)
        assert await track_status(world, track) == PackageStatus.ANALYSIS.value
        assert await checkpoint_srcmd5(world, track) == CURRENT
        assert await events_of(world, track.ticket_id) == []

    @pytest.mark.parametrize(
        "final",
        [PackageStatus.NOT_AFFECTED, PackageStatus.FIXED, PackageStatus.WONT_FIX],
        ids=str,
    )
    async def test_final_status_race_is_succeeded_not_updated(
        self,
        world: TrackWorld,
        runs: _Runs,
        ibs: FakeIBS,
        monkeypatch: pytest.MonkeyPatch,
        final: PackageStatus,
    ) -> None:
        (track,) = await _seeded(world)
        _evidence(ibs, track)
        _concurrently(
            monkeypatch,
            world,
            update(TicketPackageTrack)
            .where(TicketPackageTrack.id == track.id)
            .values(status=final.value),
        )

        run = await _run(runs)

        assert _outcome(run) == ("success", 1, 0, 0, 0)
        assert await track_status(world, track) == final.value
        assert await checkpoint_srcmd5(world, track) == CURRENT
        assert await events_of(world, track.ticket_id) == []

    async def test_checkpoint_already_advanced_is_succeeded_not_updated(
        self,
        world: TrackWorld,
        runs: _Runs,
        ibs: FakeIBS,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        (track,) = await _seeded(world)
        _evidence(ibs, track)
        _concurrently(
            monkeypatch,
            world,
            insert(TrackReleaseCheckpoint).values(
                ticket_package_track_id=track.id, srcmd5=CURRENT, last_seen_at=LATER
            ),
        )

        run = await _run(runs)

        assert _outcome(run) == ("success", 1, 0, 0, 0)
        assert await checkpoint_of(world, track) == (CURRENT, LATER)
        assert await track_status(world, track) == PackageStatus.ANALYSIS.value
        assert await events_of(world, track.ticket_id) == []

    @pytest.mark.parametrize(
        ("fallback", "expected"),
        [
            pytest.param("no-match", ("success", 1, 0, 0, 0), id="no-transition"),
            pytest.param("evidence", ("success", 1, 0, 1, 0), id="transition"),
            pytest.param("failed", ("failure", 0, 0, 0, 1), id="fallback-failed"),
        ],
    )
    async def test_unavailable_history_fallback_accounting(
        self,
        world: TrackWorld,
        runs: _Runs,
        ibs: FakeIBS,
        fallback: str,
        expected: Outcome,
    ) -> None:
        """Fallback success is succeeded (updated only for an effective
        `FIXED`); fallback failure is failed and keeps the checkpoint."""
        (track,) = await _seeded(world, checkpoint=CHECKPOINT)
        ibs.source(PROJECT, PACKAGE, CURRENT)
        ibs.diff(
            PROJECT,
            PACKAGE,
            CHECKPOINT,
            CURRENT,
            unavailable(PROJECT, PACKAGE, CHECKPOINT),
        )
        if fallback == "failed":
            ibs.diff(PROJECT, PACKAGE, "0", CURRENT, status_response(403))
        else:
            label = _cve(track) if fallback == "evidence" else OTHER_CVE
            ibs.issues(PROJECT, PACKAGE, "0", CURRENT, issue(label))

        with capture_logs() as logs:
            run = await _run(runs)

        assert _outcome(run) == expected
        assert logged(logs, HISTORY_UNAVAILABLE) == [history_unavailable(track)]
        assert ibs.diffs() == [
            (PROJECT, PACKAGE, CHECKPOINT, CURRENT),
            (PROJECT, PACKAGE, "0", CURRENT),
        ]
        if fallback == "failed":
            assert run.error_message == "All 1 items failed"
            assert await checkpoint_of(world, track) == (CHECKPOINT, SEEN_AT)
        else:
            assert run.error_message is None
            assert await checkpoint_srcmd5(world, track) == CURRENT
        fixed = fallback == "evidence"
        assert await events_of(world, track.ticket_id) == (
            [track.fixed_event()] if fixed else []
        )

    @pytest.mark.parametrize(
        "status", [TicketStatus.IGNORED, TicketStatus.DUPLICATED], ids=str
    )
    async def test_stale_ignored_or_duplicated_race_is_succeeded(
        self,
        world: TrackWorld,
        runs: _Runs,
        ibs: FakeIBS,
        monkeypatch: pytest.MonkeyPatch,
        status: TicketStatus,
    ) -> None:
        (track,) = await _seeded(world, checkpoint=CHECKPOINT)
        _evidence(ibs, track, baseline=CHECKPOINT)
        _before_first_unit(monkeypatch, _leaves(world, track.ticket_id, status))

        with capture_logs() as logs:
            run = await _run(runs)

        assert _outcome(run) == ("success", 1, 0, 0, 0)
        assert own(logs) == [track_stale(track)]
        assert await checkpoint_of(world, track) == (CHECKPOINT, SEEN_AT)
        assert await track_status(world, track) == PackageStatus.ANALYSIS.value
        assert await events_of(world, track.ticket_id) == []

    @pytest.mark.parametrize(
        "change", ["track-disappeared", "scope-changed", "cve-lost"]
    )
    async def test_disappeared_changed_or_cve_less_track_is_failed(
        self,
        world: TrackWorld,
        runs: _Runs,
        ibs: FakeIBS,
        monkeypatch: pytest.MonkeyPatch,
        change: str,
    ) -> None:
        (track,) = await _seeded(world)
        _evidence(ibs, track)
        statement: Any
        if change == "track-disappeared":
            statement = delete(TicketPackageTrack).where(
                TicketPackageTrack.id == track.id
            )
        elif change == "scope-changed":
            statement = (
                update(TicketPackageTrack)
                .where(TicketPackageTrack.id == track.id)
                .values(reference=OTHER_PROJECT)
            )
        else:
            statement = (
                update(Ticket).where(Ticket.id == track.ticket_id).values(cve_id=None)
            )
        _concurrently(monkeypatch, world, statement)

        with capture_logs() as logs:
            run = await _run(runs)

        assert _outcome(run) == ("failure", 0, 0, 0, 1)
        assert run.error_message == "All 1 items failed"
        assert (run.error_detail, run.error_traceback) == (None, None)
        assert own(logs) == [track_failed(track, "scope_changed")]
        assert await events_of(world, track.ticket_id) == []
        assert await checkpoint_of(world, track) is None
        assert await track_status(world, track) in (
            None,
            PackageStatus.ANALYSIS.value,
        )

    async def test_shared_source_info_failure_counts_each_track_once(
        self, world: TrackWorld, runs: _Runs, ibs: FakeIBS
    ) -> None:
        """Three tracks of one project (two packages, two baselines) share
        one failed source-info request."""
        seed = Seed(world.session, world)
        tracks = [
            await seed.track(await seed.ticket(), checkpoint=CHECKPOINT),
            await seed.track(await seed.ticket()),
            await seed.track(await seed.ticket(), package_name=SIBLING_PACKAGE),
        ]
        await seed.commit()
        ibs.fail_source(PROJECT, status_response(403))

        with capture_logs() as logs:
            run = await _run(runs)

        assert _outcome(run) == ("failure", 0, 0, 0, 3)
        assert run.error_message == "All 3 items failed"
        assert len(ibs.sources()) == 1
        assert ibs.diffs() == []
        assert logged(logs, SOURCE_INFO_FAILED) == [
            source_info_failed(PROJECT, 3, "http_status", 403)
        ]
        assert _sorted_logs(logged(logs, TRACK_FAILED)) == _sorted_logs(
            [track_failed(t, "http_status") for t in tracks]
        )
        assert await checkpoint_of(world, tracks[0]) == (CHECKPOINT, SEEN_AT)

    async def test_shared_diff_failure_counts_each_track_once(
        self, world: TrackWorld, runs: _Runs, ibs: FakeIBS
    ) -> None:
        tracks = await _seeded(world, 2, checkpoint=CHECKPOINT)
        ibs.source(PROJECT, PACKAGE, CURRENT)
        ibs.diff(PROJECT, PACKAGE, CHECKPOINT, CURRENT, status_response(403))

        with capture_logs() as logs:
            run = await _run(runs)

        assert _outcome(run) == ("failure", 0, 0, 0, 2)
        assert run.error_message == "All 2 items failed"
        assert ibs.diffs() == [(PROJECT, PACKAGE, CHECKPOINT, CURRENT)]
        assert logged(logs, DIFF_FAILED) == [
            diff_failed(PROJECT, PACKAGE, 2, "http_status", 403)
        ]
        assert _sorted_logs(logged(logs, TRACK_FAILED)) == _sorted_logs(
            [track_failed(t, "http_status") for t in tracks]
        )
        for track in tracks:
            assert await checkpoint_of(world, track) == (CHECKPOINT, SEEN_AT)

    async def test_mixed_outcomes_are_partial(
        self, world: TrackWorld, runs: _Runs, ibs: FakeIBS
    ) -> None:
        """One updated, one no-match, and one failed track."""
        seed = Seed(world.session, world)
        updated = await seed.track(await seed.ticket())
        no_match = await seed.track(await seed.ticket(), package_name=SIBLING_PACKAGE)
        failed = await seed.track(await seed.ticket(), project=OTHER_PROJECT)
        await seed.commit()
        _evidence(ibs, updated)
        _no_match(ibs, no_match)
        ibs.fail_source(OTHER_PROJECT, status_response(403))

        with capture_logs() as logs:
            run = await _run(runs)

        assert _outcome(run) == ("partial", 2, 0, 1, 1)
        assert run.error_message is None
        assert logged(logs, TRACK_FAILED) == [track_failed(failed, "http_status")]
        assert await track_status(world, updated) == PackageStatus.FIXED.value
        assert await checkpoint_srcmd5(world, no_match) == CURRENT
        assert await checkpoint_of(world, failed) is None

    async def test_all_failed_is_a_normal_return_failure(
        self, world: TrackWorld, runs: _Runs, ibs: FakeIBS
    ) -> None:
        """Two independently failed tracks (unusable package, failed
        diff): `failure` with exactly `All 2 items failed`."""
        seed = Seed(world.session, world)
        missing = await seed.track(await seed.ticket())
        broken = await seed.track(await seed.ticket(), package_name=SIBLING_PACKAGE)
        await seed.commit()
        ibs.entries(PROJECT, PACKAGE)
        ibs.source(PROJECT, SIBLING_PACKAGE, CURRENT)
        ibs.diff(PROJECT, SIBLING_PACKAGE, "0", CURRENT, status_response(404))

        with capture_logs() as logs:
            run = await _run(runs)

        assert _outcome(run) == ("failure", 0, 0, 0, 2)
        assert run.error_message == "All 2 items failed"
        assert (run.error_detail, run.error_traceback) == (None, None)
        assert _sorted_logs(logged(logs, TRACK_FAILED)) == _sorted_logs(
            [track_failed(missing, "missing"), track_failed(broken, "http_status")]
        )

    async def test_empty_selection_is_success_without_a_client(
        self,
        runs: _Runs,
        ibs: FakeIBS,
        ibs_clients: _IBSClients,
        units: TrackUnitSessions,
    ) -> None:
        with capture_logs() as logs:
            run = await _run(runs)

        assert _outcome(run) == ("success", 0, 0, 0, 0)
        assert (run.error_message, run.error_detail) == (None, None)
        assert ibs_clients.created == []
        assert ibs.server.requests == []
        assert units.sessions == []
        assert own(logs) == []


# ---------------------------------------------------------------------------
# A3. Step 1: the candidate read ends before the first IBS request
# ---------------------------------------------------------------------------


@pytest.mark.integration
@pytest.mark.usefixtures("units")
class TestCandidateRead:
    @pytest.mark.parametrize("invocation", ["execute", "catch-up"])
    async def test_read_is_committed_before_the_first_ibs_request(
        self, world: TrackWorld, ibs: FakeIBS, invocation: str
    ) -> None:
        (track,) = await _seeded(world)
        _evidence(ibs, track)
        session = await world.open_session()
        events: list[str] = []
        ibs.events = events
        open_at_request: list[bool] = []
        ibs.after_source = lambda: open_at_request.append(session.in_transaction())

        def committed(_: Session) -> None:
            events.append("read:commit")

        event.listen(session.sync_session, "after_commit", committed)
        fetcher = DetectIbsTrackReleases()

        with SessionStatementRecorder(session) as recorder:
            if invocation == "execute":
                await fetcher.execute(session)
            else:
                await fetcher.catch_up(str(track.ticket_id), session)

        assert events[:2] == ["read:commit", "http:source"]
        assert events.count("read:commit") == 1
        assert open_at_request == [False]
        assert len(recorder.statements) == 1
        assert recorder.writes() == []
        assert recorder.row_locks() == []
        assert await track_status(world, track) == PackageStatus.FIXED.value


# ---------------------------------------------------------------------------
# A4. Credentials not configured (Error Handling, credentials row)
# ---------------------------------------------------------------------------


def _unconfigure(monkeypatch: pytest.MonkeyPatch, setting: str) -> None:
    empty: str | SecretStr = SecretStr("") if setting == "ibs_ssh_private_key" else ""
    monkeypatch.setattr(settings, setting, empty)


_EMPTY_SETTINGS = [
    pytest.param("ibs_username", id="IBS_USERNAME"),
    pytest.param("ibs_ssh_private_key", id="IBS_SSH_PRIVATE_KEY"),
]


@pytest.mark.integration
@pytest.mark.usefixtures("units")
class TestCredentialsNotConfigured:
    @pytest.mark.parametrize("setting", _EMPTY_SETTINGS)
    async def test_selected_tracks_fail_without_any_request(
        self,
        world: TrackWorld,
        runs: _Runs,
        ibs: FakeIBS,
        ibs_clients: _IBSClients,
        units: TrackUnitSessions,
        monkeypatch: pytest.MonkeyPatch,
        setting: str,
    ) -> None:
        """Every selected track fails once; one source-info warning per
        source-info request; no HTTP request; checkpoints unchanged."""
        seed = Seed(world.session, world)
        first = await seed.track(await seed.ticket(), checkpoint=CHECKPOINT)
        second = await seed.track(await seed.ticket(), package_name=SIBLING_PACKAGE)
        other = await seed.track(await seed.ticket(), project=OTHER_PROJECT)
        await seed.commit()
        tracks = (first, second, other)
        _evidence(ibs, *tracks)
        _unconfigure(monkeypatch, setting)

        with capture_logs() as logs:
            run = await _run(runs)

        assert _outcome(run) == ("failure", 0, 0, 0, 3)
        assert run.error_message == "All 3 items failed"
        assert run.error_detail is None
        assert ibs.server.requests == []
        assert units.sessions == []
        assert _sorted_logs(logged(logs, SOURCE_INFO_FAILED)) == _sorted_logs(
            [
                source_info_failed(PROJECT, 2, CREDENTIALS),
                source_info_failed(OTHER_PROJECT, 1, CREDENTIALS),
            ]
        )
        assert _sorted_logs(logged(logs, TRACK_FAILED)) == _sorted_logs(
            [track_failed(t, CREDENTIALS) for t in tracks]
        )
        assert logged(logs, DIFF_FAILED) == []
        assert await checkpoint_of(world, first) == (CHECKPOINT, SEEN_AT)
        assert await checkpoint_of(world, second) is None
        assert await checkpoint_of(world, other) is None
        for track in tracks:
            assert await track_status(world, track) == PackageStatus.ANALYSIS.value
        ibs_clients.assert_each_closed(1)

    @pytest.mark.parametrize("setting", _EMPTY_SETTINGS)
    async def test_empty_selection_still_succeeds(
        self,
        runs: _Runs,
        ibs: FakeIBS,
        ibs_clients: _IBSClients,
        monkeypatch: pytest.MonkeyPatch,
        setting: str,
    ) -> None:
        _unconfigure(monkeypatch, setting)

        with capture_logs() as logs:
            run = await _run(runs)

        assert _outcome(run) == ("success", 0, 0, 0, 0)
        assert run.error_message is None
        assert ibs_clients.created == []
        assert ibs.server.requests == []
        assert own(logs) == []


# ---------------------------------------------------------------------------
# A5. Per-unit finalizer (testing-strategy.md, Fetcher Outcome and Effect
# Accounting: the IBS release-detector exception; Ticket Convergence
# Publication Handoff)
# ---------------------------------------------------------------------------


@pytest.mark.integration
@pytest.mark.usefixtures("units")
class TestPerUnitFinalizer:
    @pytest.mark.parametrize("ambiguous", [False, True], ids=["failed", "ambiguous"])
    async def test_commit_exception_fails_the_run_without_a_unit_metric(
        self,
        world: TrackWorld,
        runs: _Runs,
        ibs: FakeIBS,
        units: TrackUnitSessions,
        publication: Publish,
        ambiguous: bool,
    ) -> None:
        """The second unit's commit fails (or raises after the database
        committed): the run fails with the first unit's success and update
        preserved, no terminal or update metric for the second, and the
        third never processed."""
        first, second, third = await _three(world, ibs)
        error = OperationalError("COMMIT", None, Exception("fictional reset"))
        if ambiguous:
            units.after_commit_error = (1, error)
        else:
            units.failing_commit = (1, error)

        with capture_logs() as logs:
            raised, run = await _run_failing(runs, OperationalError)

        assert raised is error
        assert _outcome(run) == ("failure", 1, 0, 1, 0)
        assert run.error_message == "Unexpected error"
        assert len(units.sessions) == 2
        assert logged(logs, TRACK_FAILED) == []
        assert publication.calls == []
        assert await track_status(world, first) == PackageStatus.FIXED.value
        expected = PackageStatus.FIXED if ambiguous else PackageStatus.ANALYSIS
        assert await track_status(world, second) == expected.value
        assert await track_status(world, third) == PackageStatus.ANALYSIS.value
        assert await checkpoint_of(world, third) is None

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
        world: TrackWorld,
        runs: _Runs,
        ibs: FakeIBS,
        units: TrackUnitSessions,
        publication: Publish,
        monkeypatch: pytest.MonkeyPatch,
        make_error: Callable[[], BaseException],
        message: str,
    ) -> None:
        """After the first committed transition, its convergence
        publication raises: the run fails with that unit's success and
        update metrics and `items_failed` unchanged; the transition stays
        committed and the second track is not processed."""
        first, second, _ = await _three(world, ibs)
        register_after_fixed(monkeypatch)
        error = make_error()
        publication.error = error

        with capture_logs() as logs:
            raised, run = await _run_failing(runs, type(error))

        assert raised is error
        assert _outcome(run) == ("failure", 1, 0, 1, 0)
        assert run.error_message == message
        assert published(publication.calls) == [first.ticket_id]
        assert len(units.sessions) == 1
        assert logged(logs, TRACK_FAILED) == []
        assert [e for e in logs if e["log_level"] == "error"] == []
        assert await events_of(world, first.ticket_id) == [first.fixed_event()]
        assert await checkpoint_srcmd5(world, first) == CURRENT
        assert await track_status(world, second) == PackageStatus.ANALYSIS.value
        assert await checkpoint_of(world, second) is None

    async def test_broker_operational_error_is_absorbed(
        self,
        world: TrackWorld,
        runs: _Runs,
        ibs: FakeIBS,
        publication: Publish,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        first, second, third = await _three(world, ibs)
        register_after_fixed(monkeypatch)
        publication.error = KombuOperationalError(BROKER_FAILURE)

        with capture_logs() as logs:
            run = await _run(runs)

        assert _outcome(run) == ("success", 3, 0, 3, 0)
        assert run.error_message is None
        tickets = [first.ticket_id, second.ticket_id, third.ticket_id]
        assert published(publication.calls) == tickets
        assert [e for e in logs if e["log_level"] == "error"] == [
            publication_failed(ticket_id) for ticket_id in tickets
        ]
        assert SECRET not in repr(logs)
        assert "broker.example.test" not in repr(logs)
        for track in (first, second, third):
            assert await track_status(world, track) == PackageStatus.FIXED.value


# ---------------------------------------------------------------------------
# A6. Whole-run errors and sanitization
# ---------------------------------------------------------------------------


@pytest.mark.integration
@pytest.mark.usefixtures("units")
class TestRunErrors:
    @pytest.mark.parametrize(
        "make_error",
        [
            pytest.param(
                lambda: OperationalError("SELECT", None, Exception(INTERNAL_URL)),
                id="operational",
            ),
            pytest.param(
                lambda: DBAPIError("SELECT", None, Exception(INTERNAL_URL)),
                id="dbapi",
            ),
        ],
    )
    async def test_enumeration_failure_is_a_sanitized_fetcher_error(
        self,
        world: TrackWorld,
        runs: _Runs,
        ibs: FakeIBS,
        ibs_clients: _IBSClients,
        units: TrackUnitSessions,
        monkeypatch: pytest.MonkeyPatch,
        make_error: Callable[[], Exception],
    ) -> None:
        (track,) = await _seeded(world)
        error = make_error()

        async def failing(db: AsyncSession, **kwargs: Any) -> Any:
            raise error

        monkeypatch.setattr(detector, "load_track_release_candidates", failing)

        raised, run = await _run_failing(runs, FetcherError)

        assert str(raised) == ENUMERATION_FAILED
        assert raised.__cause__ is error
        assert _outcome(run) == ("failure", 0, 0, 0, 0)
        assert run.error_message == ENUMERATION_FAILED
        assert run.error_detail == str(error)
        assert ibs_clients.created == []
        assert ibs.server.requests == []
        assert units.sessions == []
        assert await track_status(world, track) == PackageStatus.ANALYSIS.value

    async def test_unexpected_exception_uses_the_generic_message(
        self,
        world: TrackWorld,
        runs: _Runs,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        await _seeded(world)
        error = RuntimeError(f"cannot reach {INTERNAL_URL}/source")

        async def failing(db: AsyncSession, **kwargs: Any) -> Any:
            raise error

        monkeypatch.setattr(detector, "load_track_release_candidates", failing)

        with capture_logs() as logs:
            raised, run = await _run_failing(runs, RuntimeError)

        assert raised is error
        assert run.status == "failure"
        assert run.error_message == "Unexpected error"
        # The raw text is restricted to the operator-only detail.
        assert run.error_detail == str(error)
        assert SECRET not in repr(logs)
        assert "example.test" not in repr(logs)

    async def test_soft_time_limit_in_a_unit_uses_the_enriched_message(
        self,
        world: TrackWorld,
        runs: _Runs,
        ibs: FakeIBS,
        ibs_clients: _IBSClients,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        first, second, third = await _three(world, ibs)
        signal = SoftTimeLimitExceeded()
        _failing_for(monkeypatch, second, signal)

        raised, run = await _run_failing(runs, SoftTimeLimitExceeded)

        assert raised is signal
        assert _outcome(run) == ("failure", 1, 0, 1, 0)
        assert run.error_message == _soft_limit_message(1)
        assert await track_status(world, first) == PackageStatus.FIXED.value
        assert await track_status(world, second) == PackageStatus.ANALYSIS.value
        assert await events_of(world, second.ticket_id) == []
        assert await checkpoint_of(world, third) is None
        ibs_clients.assert_each_closed(1)

    async def test_failed_request_leaves_no_raw_data_in_public_fields(
        self, world: TrackWorld, runs: _Runs, ibs: FakeIBS
    ) -> None:
        """A transport error carrying a credential-bearing URL and an
        upstream body: the public message is the bounded all-failed
        message and no log echoes either."""
        seed = Seed(world.session, world)
        refused = await seed.track(await seed.ticket())
        forbidden = await seed.track(await seed.ticket(), project=OTHER_PROJECT)
        await seed.commit()
        ibs.fail_source(PROJECT, raising(httpx.ConnectError(f"{INTERNAL_URL} refused")))
        ibs.fail_source(
            OTHER_PROJECT, status_response(403, f"<status>{SECRET}</status>".encode())
        )

        with capture_logs() as logs:
            run = await _run(runs)

        assert _outcome(run) == ("failure", 0, 0, 0, 2)
        assert run.error_message == "All 2 items failed"
        assert run.error_detail is None
        assert _sorted_logs(logged(logs, TRACK_FAILED)) == _sorted_logs(
            [track_failed(refused, "transport"), track_failed(forbidden, "http_status")]
        )
        assert SECRET not in repr(logs)
        assert "api.internal.example.test" not in repr(logs)


# ---------------------------------------------------------------------------
# A7. IBSClient lifetime and teardown (ibs-integration.md, Service Layer >
# IBSClient; fetcher-infrastructure.md, HTTP Client Ownership Rule)
# ---------------------------------------------------------------------------


async def _invoke(
    fetcher: DetectIbsTrackReleases,
    invocation: str,
    session: AsyncSession,
    ticket_id: uuid.UUID,
) -> None:
    if invocation == "execute":
        await fetcher.execute(session)
    else:
        await fetcher.catch_up(str(ticket_id), session)


_INVOCATIONS = ["execute", "catch-up"]


@pytest.mark.integration
@pytest.mark.usefixtures("units")
class TestIbsClientLifecycle:
    async def test_run_creates_one_production_client_and_closes_it(
        self,
        world: TrackWorld,
        runs: _Runs,
        ibs: FakeIBS,
        ibs_clients: _IBSClients,
        fetcher_http_client: Mock,
    ) -> None:
        """One client for the whole run (two projects, several requests),
        built from the settings, closed before `run()` returns; the
        fetcher's own HTTP client is never created."""
        seed = Seed(world.session, world)
        first = await seed.track(await seed.ticket())
        other = await seed.track(await seed.ticket(), project=OTHER_PROJECT)
        await seed.commit()
        _evidence(ibs, first, other)
        fetcher = DetectIbsTrackReleases()

        run = await _run(runs, fetcher)

        assert _outcome(run) == ("success", 2, 0, 2, 0)
        ibs_clients.assert_each_closed(1)
        assert len(ibs.served) == 4
        assert ibs.server.requests
        assert {request.url.host for request in ibs.server.requests} == {TEST_HOST}
        # One authenticated session for every request of the invocation.
        assert len(ibs.server.signatures) == 1
        fetcher_http_client.assert_not_called()
        assert fetcher._http_client is None

    @pytest.mark.parametrize("invocation", _INVOCATIONS)
    async def test_each_invocation_owns_its_own_client(
        self,
        world: TrackWorld,
        ibs: FakeIBS,
        ibs_clients: _IBSClients,
        fetcher_http_client: Mock,
        invocation: str,
    ) -> None:
        """Two invocations of one fetcher instance: two clients, each
        created during and closed by its own invocation."""
        (track,) = await _seeded(world, checkpoint=CURRENT)
        ibs.source(PROJECT, PACKAGE, CURRENT)
        fetcher = DetectIbsTrackReleases()

        await _invoke(fetcher, invocation, await world.open_session(), track.ticket_id)
        ibs_clients.assert_each_closed(1)
        await _invoke(fetcher, invocation, await world.open_session(), track.ticket_id)

        ibs_clients.assert_each_closed(2)
        assert ibs_clients.created[0] is not ibs_clients.created[1]
        assert len(ibs.sources()) == 2
        fetcher_http_client.assert_not_called()
        assert fetcher._http_client is None

    @pytest.mark.parametrize("invocation", _INVOCATIONS)
    async def test_client_is_closed_on_a_propagating_failure(
        self,
        world: TrackWorld,
        ibs: FakeIBS,
        ibs_clients: _IBSClients,
        monkeypatch: pytest.MonkeyPatch,
        invocation: str,
    ) -> None:
        (track,) = await _seeded(world)
        _evidence(ibs, track)
        error = RuntimeError("fictional bug")
        _failing_for(monkeypatch, track, error)

        with pytest.raises(RuntimeError) as raised:
            await _invoke(
                DetectIbsTrackReleases(),
                invocation,
                await world.open_session(),
                track.ticket_id,
            )

        assert raised.value is error
        ibs_clients.assert_each_closed(1)
        assert await track_status(world, track) == PackageStatus.ANALYSIS.value

    @pytest.mark.parametrize("invocation", _INVOCATIONS)
    async def test_client_is_closed_on_cancellation(
        self,
        world: TrackWorld,
        ibs: FakeIBS,
        ibs_clients: _IBSClients,
        monkeypatch: pytest.MonkeyPatch,
        invocation: str,
    ) -> None:
        """The invocation is cancelled while its first unit waits: the
        cancellation propagates and the client is closed."""
        (track,) = await _seeded(world)
        _evidence(ibs, track)
        waiting = asyncio.Event()

        async def block() -> None:
            waiting.set()
            await asyncio.Event().wait()

        _before_first_unit(monkeypatch, block)
        task = asyncio.create_task(
            _invoke(
                DetectIbsTrackReleases(),
                invocation,
                await world.open_session(),
                track.ticket_id,
            )
        )
        await asyncio.wait_for(waiting.wait(), timeout=WAIT)
        assert len(ibs_clients.created) == 1
        assert ibs_clients.closed == []

        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

        ibs_clients.assert_each_closed(1)
        assert await track_status(world, track) == PackageStatus.ANALYSIS.value
        assert await checkpoint_of(world, track) is None


# ---------------------------------------------------------------------------
# A8. catch_up()
# ---------------------------------------------------------------------------


SilentBuild = Callable[[TrackWorld], Awaitable[str]]


async def _missing(world: TrackWorld) -> str:
    return str(uuid.uuid4())


def _in_status(status: TicketStatus) -> SilentBuild:
    async def build(world: TrackWorld) -> str:
        (track,) = await _seeded(world, status=status)
        return str(track.ticket_id)

    return build


async def _cveless(world: TrackWorld) -> str:
    seed = Seed(world.session, world)
    ticket = await seed.ticket(with_cve=False)
    await seed.track(ticket)
    await seed.commit()
    return str(ticket.id)


async def _empty_tree(world: TrackWorld) -> str:
    seed = Seed(world.session, world)
    ticket = await seed.ticket()
    await seed.commit()
    return str(ticket.id)


async def _git_only(world: TrackWorld) -> str:
    seed = Seed(world.session, world)
    ticket = await seed.ticket()
    await seed.track(ticket, workflow=WorkflowType.GIT)
    await seed.commit()
    return str(ticket.id)


async def _final_only(world: TrackWorld) -> str:
    seed = Seed(world.session, world)
    ticket = await seed.ticket()
    for index, status in enumerate(
        (PackageStatus.NOT_AFFECTED, PackageStatus.FIXED, PackageStatus.WONT_FIX)
    ):
        await seed.track(ticket, package_name=f"example-{index}", status=status)
    await seed.commit()
    return str(ticket.id)


_SILENT_CASES = [
    pytest.param(_missing, id="missing-ticket"),
    pytest.param(_cveless, id="ticket-without-cve"),
    pytest.param(_in_status(TicketStatus.RESOLVED), id="resolved"),
    pytest.param(_in_status(TicketStatus.IGNORED), id="ignored"),
    pytest.param(_in_status(TicketStatus.DUPLICATED), id="duplicated"),
    pytest.param(_empty_tree, id="no-packages"),
    pytest.param(_git_only, id="no-ibs-track"),
    pytest.param(_final_only, id="only-final-tracks"),
]


@pytest.mark.integration
@pytest.mark.usefixtures("units")
class TestCatchUp:
    @pytest.mark.parametrize("build", _SILENT_CASES)
    async def test_silent_return_performs_no_client_http_log_or_write(
        self,
        world: TrackWorld,
        ibs: FakeIBS,
        ibs_clients: _IBSClients,
        units: TrackUnitSessions,
        build: SilentBuild,
    ) -> None:
        ticket_id = await build(world)
        session = await world.open_session()
        fetcher = DetectIbsTrackReleases()

        with capture_logs() as logs, SessionStatementRecorder(session) as recorder:
            await fetcher.catch_up(ticket_id, session)

        assert logs == []
        assert ibs_clients.created == []
        assert ibs.server.requests == []
        assert units.sessions == []
        assert fetcher._http_client is None
        assert len(recorder.statements) == 1
        assert recorder.writes() == []
        assert recorder.row_locks() == []
        assert not session.in_transaction()

    async def test_passed_session_only_reads_and_the_transition_is_committed(
        self,
        world: TrackWorld,
        ibs: FakeIBS,
        units: TrackUnitSessions,
        metric_helpers: dict[str, Mock],
    ) -> None:
        (track,) = await _seeded(world)
        _evidence(ibs, track)
        session = await world.open_session()
        flushes: list[bool] = []

        def flushed(*_: Any) -> None:
            flushes.append(True)

        event.listen(session.sync_session, "before_flush", flushed)

        with capture_logs() as logs, SessionStatementRecorder(session) as recorder:
            await DetectIbsTrackReleases().catch_up(str(track.ticket_id), session)

        assert recorder.statements
        assert recorder.writes() == []
        assert recorder.row_locks() == []
        assert flushes == []
        assert not session.in_transaction()
        assert not session.new
        assert not session.dirty
        assert not session.deleted
        assert len(units.sessions) == 1
        assert units.sessions[0] is not session
        assert units.closed == units.sessions
        assert own(logs) == []
        # Visible from an independent session after catch-up returned.
        assert await track_status(world, track) == PackageStatus.FIXED.value
        assert await events_of(world, track.ticket_id) == [track.fixed_event()]
        assert await checkpoint_srcmd5(world, track) == CURRENT
        for spy in metric_helpers.values():
            spy.assert_not_called()

    async def test_only_the_tickets_tracks_are_processed(
        self, world: TrackWorld, ibs: FakeIBS
    ) -> None:
        seed = Seed(world.session, world)
        mine = await seed.track(await seed.ticket())
        other = await seed.track(await seed.ticket(), package_name=SIBLING_PACKAGE)
        await seed.commit()
        _evidence(ibs, mine, other)

        await DetectIbsTrackReleases().catch_up(
            str(mine.ticket_id), await world.open_session()
        )

        assert [served.packages for served in ibs.sources()] == [(PACKAGE,)]
        assert ibs.diffs() == [(PROJECT, PACKAGE, "0", CURRENT)]
        assert await track_status(world, mine) == PackageStatus.FIXED.value
        assert await track_status(world, other) == PackageStatus.ANALYSIS.value
        assert await checkpoint_of(world, other) is None
        assert await events_of(world, other.ticket_id) == []

    async def test_catch_up_applies_the_checkpoint_algorithm_per_track(
        self, world: TrackWorld, ibs: FakeIBS, units: TrackUnitSessions
    ) -> None:
        """One Ticket: a first observation (`orev=0`), an equal checkpoint
        (no diff, no unit), an incremental diff, and an unavailable
        checkpoint that falls back to `orev=0`."""
        seed = Seed(world.session, world)
        ticket = await seed.ticket()
        first = await seed.track(ticket)
        unchanged = await seed.track(
            ticket, package_name=SIBLING_PACKAGE, checkpoint=CURRENT
        )
        incremental = await seed.track(
            ticket, package_name=ZZ_PACKAGE, checkpoint=CHECKPOINT
        )
        fallback = await seed.track(
            ticket, package_name="example-fallback", checkpoint=CHECKPOINT
        )
        await seed.commit()
        cve = _cve(first)
        for package in (PACKAGE, SIBLING_PACKAGE, ZZ_PACKAGE, "example-fallback"):
            ibs.source(PROJECT, package, CURRENT)
        ibs.issues(PROJECT, PACKAGE, "0", CURRENT, issue(cve))
        ibs.issues(PROJECT, ZZ_PACKAGE, CHECKPOINT, CURRENT, issue(OTHER_CVE))
        ibs.diff(
            PROJECT,
            "example-fallback",
            CHECKPOINT,
            CURRENT,
            unavailable(PROJECT, "example-fallback", CHECKPOINT),
        )
        ibs.issues(PROJECT, "example-fallback", "0", CURRENT, issue(OTHER_CVE))

        with capture_logs() as logs:
            await DetectIbsTrackReleases().catch_up(
                str(ticket.id), await world.open_session()
            )

        assert sorted(ibs.diffs()) == sorted(
            [
                (PROJECT, PACKAGE, "0", CURRENT),
                (PROJECT, ZZ_PACKAGE, CHECKPOINT, CURRENT),
                (PROJECT, "example-fallback", CHECKPOINT, CURRENT),
                (PROJECT, "example-fallback", "0", CURRENT),
            ]
        )
        assert own(logs) == [history_unavailable(fallback)]
        assert len(units.sessions) == 3
        assert await track_status(world, first) == PackageStatus.FIXED.value
        assert await checkpoint_of(world, unchanged) == (CURRENT, SEEN_AT)
        assert await checkpoint_srcmd5(world, incremental) == CURRENT
        assert await checkpoint_srcmd5(world, fallback) == CURRENT
        assert await events_of(world, ticket.id) == [first.fixed_event()]

    async def test_partial_failure_returns_and_logs_with_the_task_id(
        self,
        world: TrackWorld,
        ibs: FakeIBS,
        metric_helpers: dict[str, Mock],
    ) -> None:
        """One transitioned and one failed track of one Ticket: normal
        return; the failed one is logged at WARNING with the Ticket,
        fetcher, track identity, bounded cause, and the task-bound
        `celery_task_id`."""
        seed = Seed(world.session, world)
        ticket = await seed.ticket()
        fixed = await seed.track(ticket)
        failed = await seed.track(ticket, project=OTHER_PROJECT)
        await seed.commit()
        _evidence(ibs, fixed)
        ibs.fail_source(OTHER_PROJECT, status_response(403))
        celery_task_id = str(uuid.uuid4())
        bind_contextvars(celery_task_id=celery_task_id)
        try:
            with capture_logs(processors=[merge_contextvars]) as logs:
                await DetectIbsTrackReleases().catch_up(
                    str(ticket.id), await world.open_session()
                )
        finally:
            unbind_contextvars("celery_task_id")

        assert logged(logs, TRACK_FAILED) == [
            {
                **track_failed(failed, "http_status"),
                "celery_task_id": celery_task_id,
            }
        ]
        assert await track_status(world, fixed) == PackageStatus.FIXED.value
        assert await track_status(world, failed) == PackageStatus.ANALYSIS.value
        assert await checkpoint_of(world, failed) is None
        for spy in metric_helpers.values():
            spy.assert_not_called()

    @pytest.mark.parametrize("cause", ["request-failed", "credentials-not-configured"])
    async def test_all_failed_raises_the_sanitized_non_retryable_error(
        self,
        world: TrackWorld,
        ibs: FakeIBS,
        ibs_clients: _IBSClients,
        units: TrackUnitSessions,
        metric_helpers: dict[str, Mock],
        monkeypatch: pytest.MonkeyPatch,
        cause: str,
    ) -> None:
        seed = Seed(world.session, world)
        ticket = await seed.ticket()
        first = await seed.track(ticket, checkpoint=CHECKPOINT)
        second = await seed.track(ticket, project=OTHER_PROJECT)
        await seed.commit()
        if cause == "request-failed":
            ibs.fail_source(PROJECT, status_response(403))
            ibs.fail_source(OTHER_PROJECT, status_response(403))
            category = "http_status"
        else:
            _evidence(ibs, first, second)
            _unconfigure(monkeypatch, "ibs_username")
            category = CREDENTIALS

        with capture_logs() as logs, pytest.raises(FetcherError) as raised:
            await DetectIbsTrackReleases().catch_up(
                str(ticket.id), await world.open_session()
            )

        assert str(raised.value) == "All 2 IBS track release checks failed"
        assert raised.value.__cause__ is None
        assert not is_retryable_condition(raised.value)
        assert _sorted_logs(logged(logs, TRACK_FAILED)) == _sorted_logs(
            [track_failed(first, category), track_failed(second, category)]
        )
        assert len(logged(logs, SOURCE_INFO_FAILED)) == 2
        if cause == "credentials-not-configured":
            assert ibs.server.requests == []
        assert units.sessions == []
        assert await checkpoint_of(world, first) == (CHECKPOINT, SEEN_AT)
        assert await checkpoint_of(world, second) is None
        ibs_clients.assert_each_closed(1)
        for spy in metric_helpers.values():
            spy.assert_not_called()

    @pytest.mark.parametrize(
        "status", [TicketStatus.IGNORED, TicketStatus.DUPLICATED], ids=str
    )
    async def test_ticket_leaving_the_active_states_is_a_stale_no_op(
        self,
        world: TrackWorld,
        ibs: FakeIBS,
        monkeypatch: pytest.MonkeyPatch,
        status: TicketStatus,
    ) -> None:
        (track,) = await _seeded(world)
        _evidence(ibs, track)
        _before_first_unit(monkeypatch, _leaves(world, track.ticket_id, status))

        with capture_logs() as logs:
            await DetectIbsTrackReleases().catch_up(
                str(track.ticket_id), await world.open_session()
            )

        assert own(logs) == [track_stale(track)]
        assert logged(logs, TRACK_FAILED) == []
        assert await track_status(world, track) == PackageStatus.ANALYSIS.value
        assert await checkpoint_of(world, track) is None
        assert await events_of(world, track.ticket_id) == []

    @pytest.mark.parametrize("concurrent", ["periodic", "catch-up"])
    async def test_concurrent_invocations_transition_once(
        self,
        world: TrackWorld,
        ibs: FakeIBS,
        ibs_clients: _IBSClients,
        monkeypatch: pytest.MonkeyPatch,
        concurrent: str,
    ) -> None:
        """A periodic execution (or a second catch-up) runs to completion
        after this catch-up's IBS I/O and before its local unit: exactly
        one transition and one event; the later unit observes the
        accepted checkpoint as an already-complete no-op."""
        (track,) = await _seeded(world)
        _evidence(ibs, track)
        other = DetectIbsTrackReleases()

        async def run_other() -> None:
            await _invoke(
                other,
                "execute" if concurrent == "periodic" else "catch-up",
                await world.open_session(),
                track.ticket_id,
            )

        _before_first_unit(monkeypatch, run_other)

        with capture_logs() as logs:
            await DetectIbsTrackReleases().catch_up(
                str(track.ticket_id), await world.open_session()
            )

        assert own(logs) == []
        expected = (1, 0, 1, 0) if concurrent == "periodic" else (0, 0, 0, 0)
        assert (other._succeeded, other._created, other._updated, other._failed) == (
            expected
        )
        assert await track_status(world, track) == PackageStatus.FIXED.value
        assert await events_of(world, track.ticket_id) == [track.fixed_event()]
        assert await checkpoint_srcmd5(world, track) == CURRENT
        ibs_clients.assert_each_closed(2)


# ---------------------------------------------------------------------------
# A8b. Request delay (Background Fetcher: Request Delay); the boundary's
# placement of each wait is covered by `test_ibs_track_release_races.py`
# ---------------------------------------------------------------------------


def _recorded_sleeps(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    """Replace the boundary's `asyncio.sleep` by a recorder."""
    sleeps: list[float] = []

    async def sleep(delay: float) -> None:
        sleeps.append(delay)

    monkeypatch.setattr(boundary, "asyncio", SimpleNamespace(sleep=sleep))
    return sleeps


async def _two_packages(world: TrackWorld, ibs: FakeIBS) -> tuple[Track, Track]:
    """Two evidence tracks of two packages below one Ticket: one source-info
    request and two diffs."""
    seed = Seed(world.session, world)
    ticket = await seed.ticket()
    first = await seed.track(ticket)
    second = await seed.track(ticket, package_name=SIBLING_PACKAGE)
    await seed.commit()
    _evidence(ibs, first, second)
    return first, second


@pytest.mark.integration
@pytest.mark.usefixtures("units")
class TestRequestDelay:
    @pytest.mark.parametrize(
        ("configured", "expected"), [(0.0, []), (0.5, [0.5, 0.5])], ids=["0", "0.5"]
    )
    async def test_run_waits_its_snapshot_delay_between_requests(
        self,
        world: TrackWorld,
        runs: _Runs,
        ibs: FakeIBS,
        monkeypatch: pytest.MonkeyPatch,
        configured: float,
        expected: list[float],
    ) -> None:
        """The run snapshot's `request_delay`, not the class value, separates
        the three requests of a periodic run."""
        await _two_packages(world, ibs)
        sleeps = _recorded_sleeps(monkeypatch)
        monkeypatch.setattr(DetectIbsTrackReleases, "default_request_delay", 9.0)
        run_id = await runs.start()

        await DetectIbsTrackReleases().run(
            run_id=run_id,
            config=FetcherRunConfig(
                hard_time_limit_seconds=3600,
                request_delay=configured,
                custom_settings={},
            ),
        )

        assert _outcome(await runs.finalized(run_id)) == ("success", 2, 0, 2, 0)
        assert len(ibs.served) == 3
        assert sleeps == expected

    async def test_catch_up_waits_the_class_default_delay(
        self,
        world: TrackWorld,
        ibs: FakeIBS,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Catch-up has no run snapshot: the class `default_request_delay`
        (0 in production, patched here) separates its requests."""
        first, second = await _two_packages(world, ibs)
        sleeps = _recorded_sleeps(monkeypatch)
        monkeypatch.setattr(DetectIbsTrackReleases, "default_request_delay", 0.25)

        await DetectIbsTrackReleases().catch_up(
            str(first.ticket_id), await world.open_session()
        )

        assert len(ibs.served) == 3
        assert sleeps == [0.25, 0.25]
        for track in (first, second):
            assert await track_status(world, track) == PackageStatus.FIXED.value


# ---------------------------------------------------------------------------
# A9. run_catch_up composition
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
    async def test_success_transitions_and_closes_the_client(
        self,
        world: TrackWorld,
        ibs: FakeIBS,
        ibs_clients: _IBSClients,
        fetcher_http_client: Mock,
        catch_up_task: _CatchUpTask,
    ) -> None:
        (track,) = await _seeded(world)
        _evidence(ibs, track)

        with capture_logs() as logs:
            await fetchers.run_catch_up_async(NAME, str(track.ticket_id))

        assert [e for e in logs if e["log_level"] == "error"] == []
        assert await track_status(world, track) == PackageStatus.FIXED.value
        assert await events_of(world, track.ticket_id) == [track.fixed_event()]
        ibs_clients.assert_each_closed(1)
        fetcher_http_client.assert_not_called()
        catch_up_task.engine.dispose.assert_awaited_once_with()
        assert await fetcher_run_count(catch_up_task.factory, NAME) == 0

    async def test_all_failed_propagates_as_non_retryable(
        self,
        world: TrackWorld,
        ibs: FakeIBS,
        ibs_clients: _IBSClients,
        catch_up_task: _CatchUpTask,
    ) -> None:
        (track,) = await _seeded(world)
        ibs.fail_source(PROJECT, status_response(403))

        with pytest.raises(FetcherError) as raised:
            await fetchers.run_catch_up_async(NAME, str(track.ticket_id))

        assert str(raised.value) == "All 1 IBS track release checks failed"
        assert not is_retryable_condition(raised.value)
        ibs_clients.assert_each_closed(1)
        catch_up_task.engine.dispose.assert_awaited_once_with()
        assert await fetcher_run_count(catch_up_task.factory, NAME) == 0
        assert await checkpoint_of(world, track) is None


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
        self,
        ibs: FakeIBS,
        ibs_clients: _IBSClients,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The real fetcher inside the wrapper's own `asyncio.run()`, with
        the enabled read, the session, and the enumeration substituted:
        the track fails in source-info I/O, so no unit session is opened,
        the client is closed, and the `FetcherError` is not retried."""
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
        candidate = TrackReleaseCandidate(
            track_id=uuid.uuid4(),
            package_id=uuid.uuid4(),
            ticket_id=ticket_id,
            cve_id="CVE-2099-00000001",
            package_name=PACKAGE,
            project=PROJECT,
            checkpoint=None,
        )
        selections: list[uuid.UUID | None] = []

        async def load(
            db: Any, *, ticket_id: uuid.UUID | None = None
        ) -> list[TrackReleaseCandidate]:
            assert db is session
            selections.append(ticket_id)
            return [candidate]

        monkeypatch.setattr(detector, "load_track_release_candidates", load)
        unit_factory = MagicMock(side_effect=AssertionError("must not open a unit"))
        monkeypatch.setattr(boundary, "async_session_factory", unit_factory)
        ibs.fail_source(PROJECT, status_response(403))
        task = FakeTask()

        with capture_logs() as logs, pytest.raises(FetcherError) as raised:
            fetchers._run_catch_up_sync(task, NAME, str(ticket_id))

        assert str(raised.value) == "All 1 IBS track release checks failed"
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
        assert logged(logs, TRACK_FAILED) == [
            {
                "event": TRACK_FAILED,
                "log_level": "warning",
                "codestream": PROJECT,
                "package_name": PACKAGE,
                "track_id": str(candidate.track_id),
                "ticket_id": str(ticket_id),
                "fetcher_name": NAME,
                "reason_category": "http_status",
            }
        ]
        unit_factory.assert_not_called()
        ibs_clients.assert_each_closed(1)
        engine.dispose.assert_awaited_once_with()
