"""Tests for the `sync_ibs_requests` fetcher
(backend/app/services/packages/sync_ibs_requests.py): class contract and
registration, `run()` finalization over the real `BaseFetcher.run()`,
durability and exclusivity of the per-scope metrics, the `IBSClient`
lifetime, the request delay, logs, audit, `catch_up()`, and the
`run_catch_up` composition.

Owning specifications:

- docs/features/packages/ibs-submission-tracking.md (Shared Authoritative
  Reconciliation > Scope Identity, Algorithm, Structured Logs: the
  `ibs_request_run_completed` row and the optional `fetcher_name` of
  `ibs_request_scope_failed`; Accelerators > Ticket Convergence; Fetcher:
  sync_ibs_requests > Properties, Request Delay, Algorithm, Error Handling,
  Metrics, including the all-failed catch-up paragraph; Testing
  Requirements; Security and Privacy; Recovery Guarantees; Scope
  Exclusions: no cursor or per-track progress row).
- docs/features/platform/fetcher-infrastructure.md (BaseFetcher Base
  Class: Finalization, Exception Propagation, Outcome and effect
  accounting; Per-Ticket Catch-Up: Override-point contract, Celery task
  wrapper, Interface contract, Fetcher inventory; Error Message
  Sanitization and the `SoftTimeLimitExceeded` convention; BaseFetcher
  HTTP Client Integration: HTTP Client Ownership Rule; Registry: Fetcher
  Discovery; Data Model: FetcherRun, FetcherConfig, Request Delay).
- docs/features/platform/testing-strategy.md (Fetcher Outcome and Effect
  Accounting, including durability, exclusivity, and shared failures
  counted once per unit; Audit Trail Testing: the explicit no-event
  contract; Database Strategy > Concurrency Testing).

The reconciliation boundary itself (selection, observation, derivation,
persistence, races of the locked unit) is covered by
`test_ibs_request_reconciliation.py`, `test_ibs_request_observation.py`,
and `test_ibs_request_reconciliation_races.py`; this module tests the
fetcher-level composition around it and reuses their helpers from
`tests/support/ibs_request_reconciliation.py`.

Every `IBSClient` is the production client built from the application
settings, which are pointed at the fictional `TEST_API_URL` with the
account `jdoe` and a fictional key (or left empty for the
credentials-not-configured case), behind the authenticating fake IBS API
of `FakeRequests` (`install_fake_requests()`: no proxy, the network
transport replaced, transport retry backoff not slept). The fetcher
module's `IBSClient` name is replaced by `_IBSClients`, which constructs
that real client and records each construction and completed `aclose()`.
`base_fetcher.create_http_client` is replaced by a spy that fails if
`BaseFetcher.http_client` is ever created, and `task_publication.
publish_task` by a recorder, so no test reaches a broker or the network.
The boundary's module-level `async_session_factory` is replaced by
`UnitSessions` over `real_session_factory` (index 0 is the step-1
snapshot session, then one unit per complete scope). The `run()` tests
also redirect `base_fetcher`'s session factory and own committed
`FetcherConfig`/`FetcherRun` rows under a test-only name (deleted at
teardown); the `run_catch_up` tests own the committed `FetcherConfig` row
of the production name. Each pytest-xdist worker owns its database and
runs one test at a time, so the unrestricted periodic selection sees only
the rows a test committed (`RequestWorld` deletes them, with the evidence
of its registered request numbers). Unless a test states otherwise, a
scope is an `ANALYSIS`/`PENDING` IBS track of `CODESTREAM` below its own
`Analysis` Ticket with its own CVE and a fresh logical package. All data
is fictional.
"""

from __future__ import annotations

import ast
import asyncio
import inspect
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Final
from unittest.mock import AsyncMock, MagicMock, Mock

import httpx
import pytest
from celery import Celery
from celery.exceptions import SoftTimeLimitExceeded
from pydantic import SecretStr
from redbeat import RedBeatSchedulerEntry
from sqlalchemy import event, func, select, update
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
from app.core.enums import (
    DeliveryStatus,
    IBSRequestActionType,
    IBSRequestState,
    TicketStatus,
    WorkflowType,
)
from app.models.fetcher_config import FetcherConfig
from app.models.fetcher_run import FetcherRun
from app.models.ticket import Ticket
from app.models.ticket_audit_event import TicketAuditEvent
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
from app.services.packages import ibs_request_observation, ibs_request_reconciliation
from app.services.packages import sync_ibs_requests as fetcher_module
from app.services.packages.ibs_request_reconciliation import IBSRequestScope
from app.services.packages.sync_ibs_requests import SyncIbsRequests
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
from tests.support.ibs_product_release import Publish, UnitSessions
from tests.support.ibs_request_reconciliation import (
    CODESTREAM,
    SCOPE_FAILED,
    SCOPE_STALE,
    Action,
    EvidenceRow,
    FakeRequests,
    RequestSeed,
    RequestWorld,
    before_lock,
    cve_issue,
    delivery_of,
    evidence_of,
    install_fake_requests,
    install_request_units,
    request_rows,
    snapshot,
    submission,
    unique_package,
)
from tests.support.ibs_track_release import WAIT, events_of, logged, raising
from tests.support.module_imports import APP_ROOT, imported_modules
from tests.support.suse_cvss_races import SessionStatementRecorder
from tests.support.ticket_mutations import StatementRecorder

Factory = Callable[[], Awaitable[AsyncSession]]
Outcome = tuple[str, int, int, int, int]
"""`(status, succeeded, created, updated, failed)` of one finalized run."""

NAME: Final = "sync_ibs_requests"
SCHEDULE: Final = "30 2 * * *"
DESCRIPTION: Final = (
    "Synchronize IBS maintenance request actions and reconcile track delivery state"
)
ENUMERATION_FAILED: Final = "Failed to enumerate IBS request scopes"
RUN_COMPLETED: Final = "ibs_request_run_completed"
CREDENTIALS: Final = "credentials_not_configured"

MI: Final = IBSRequestActionType.MAINTENANCE_INCIDENT
REVIEW: Final = IBSRequestState.REVIEW
DECLINED: Final = IBSRequestState.DECLINED
PENDING: Final = DeliveryStatus.PENDING
IN_PROGRESS: Final = DeliveryStatus.IN_PROGRESS

LATER: Final = "2026-10-02T11:00:00"
"""A current-state time newer than the seeded `WHEN_AT`."""

TRANSPORT_ATTEMPTS: Final = 4
"""One original attempt and three transport retries of a failing request
(networking.md, Transport-Level Retry)."""

SECRET: Final = "fictional-secret"
INTERNAL_HOST: Final = "api.internal.example.test"
INTERNAL_URL: Final = f"https://ibs-user:{SECRET}@{INTERNAL_HOST}"
"""A fictional internal URL with credentials; never public or logged."""
MARKER: Final = "fictional-private-marker"
"""Fictional upstream text that must never reach a log or a public field."""

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
def publication(monkeypatch: pytest.MonkeyPatch) -> Publish:
    recorder = Publish()
    monkeypatch.setattr(task_publication, "publish_task", recorder)
    return recorder


@pytest.fixture(autouse=True)
def fake(monkeypatch: pytest.MonkeyPatch) -> FakeRequests:
    return install_fake_requests(monkeypatch)


@pytest.fixture(autouse=True)
def ibs_clients(monkeypatch: pytest.MonkeyPatch) -> _IBSClients:
    recorder = _IBSClients()
    monkeypatch.setattr(fetcher_module, "IBSClient", recorder)
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
) -> UnitSessions:
    return install_request_units(monkeypatch, real_session_factory)


@pytest.fixture
async def world(db_session_factory: Factory) -> AsyncIterator[RequestWorld]:
    created = RequestWorld(db_session_factory, await db_session_factory())
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


# ---------------------------------------------------------------------------
# Builders
# ---------------------------------------------------------------------------


def _cve(scope: IBSRequestScope) -> str:
    assert scope.cve_id is not None
    return scope.cve_id


async def _seeded(
    world: RequestWorld,
    count: int = 1,
    *,
    delivery: DeliveryStatus = PENDING,
) -> list[IBSRequestScope]:
    """`count` committed scopes, each below its own Ticket with its own
    package, in track-ID order (the processing order)."""
    seed = RequestSeed(world)
    created = [
        await seed.track(
            await seed.ticket(), package=unique_package(), delivery=delivery
        )
        for _ in range(count)
    ]
    await seed.commit()
    return sorted(created, key=lambda scope: scope.track_id)


async def _correlated(
    seed: RequestSeed, scope: IBSRequestScope, state: IBSRequestState = REVIEW
) -> tuple[int, Action]:
    """A retained SR of `scope`'s package and codestream correlated to its
    track (not committed)."""
    number = seed.world.number()
    action = submission(scope.package_name, number, codestream=scope.codestream)
    await seed.evidence(number, state, action, tracks=[scope])
    return number, action


def _positive(fake: FakeRequests, world: RequestWorld, scope: IBSRequestScope) -> int:
    """One new open SR with a positive diff found by the open-SR search, and
    current release evidence without the CVE: a complete `IN_PROGRESS`
    observation that creates a request, an action, and a correlation."""
    number = world.number()
    action = submission(scope.package_name, number, codestream=scope.codestream)
    fake.request(number, REVIEW, action)
    fake.action_diff(
        number, action, cve_issue(_cve(scope)), codestream_package=scope.package_name
    )
    fake.quiet(scope.package_name, scope.codestream, open_submissions=[number])
    return number


async def _commit(world: RequestWorld, *statements: Any) -> None:
    """Commit `statements` through a fresh independent session."""
    session = await world.open_session()
    for statement in statements:
        await session.execute(statement)
    await session.commit()


def _before_first_lock(
    monkeypatch: pytest.MonkeyPatch, action: Callable[[], Awaitable[None]]
) -> None:
    """Await `action()` once, after the first scope's IBS requests and
    before its unit takes the Ticket lock."""
    done: list[bool] = []

    async def once(_: IBSRequestScope) -> None:
        if not done:
            done.append(True)
            await action()

    before_lock(monkeypatch, once)


def _leaves(world: RequestWorld, scope: IBSRequestScope, status: TicketStatus) -> Any:
    """A committed concurrent change moving the scope's Ticket to
    `status`."""

    async def change() -> None:
        values: dict[str, Any] = {"status": status.value}
        if status is TicketStatus.DUPLICATED:
            seed = RequestSeed(world)
            canonical = await seed.ticket(with_cve=False)
            await seed.commit()
            values["duplicate_of_id"] = canonical.id
        await _commit(
            world, update(Ticket).where(Ticket.id == scope.ticket_id).values(**values)
        )

    return change


class _DriverError(Exception):
    """A fictional driver exception, optionally carrying an SQLSTATE."""

    sqlstate: str

    def __init__(self, sqlstate: str | None) -> None:
        super().__init__("fictional driver failure")
        if sqlstate is not None:
            self.sqlstate = sqlstate


def _commit_error(
    sqlstate: str | None, *, connection_invalidated: bool = False
) -> OperationalError:
    return OperationalError(
        "COMMIT",
        None,
        _DriverError(sqlstate),
        connection_invalidated=connection_invalidated,
    )


def _recorded_sleeps(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    """Replace the request-delay `asyncio.sleep` of `EvidenceCache` by a
    recorder."""
    sleeps: list[float] = []

    async def sleep(delay: float) -> None:
        sleeps.append(delay)

    monkeypatch.setattr(
        ibs_request_observation, "asyncio", SimpleNamespace(sleep=sleep)
    )
    return sleeps


def _served(fake: FakeRequests, path: str) -> int:
    return sum(1 for _, served_path, _ in fake.served if served_path == path)


# ---------------------------------------------------------------------------
# Committed state and logs
# ---------------------------------------------------------------------------


async def _delivery(world: RequestWorld, scope: IBSRequestScope) -> str | None:
    return await delivery_of(await world.probe(), scope.track_id)


async def _evidence(world: RequestWorld, scope: IBSRequestScope) -> list[EvidenceRow]:
    return await evidence_of(await world.probe(), scope.track_id)


async def _requests(world: RequestWorld, *numbers: int) -> dict[int, Any]:
    return await request_rows(await world.probe(), numbers)


async def _audit_count(world: RequestWorld, *scopes: IBSRequestScope) -> int:
    probe = await world.probe()
    count = await probe.scalar(
        select(func.count())
        .select_from(TicketAuditEvent)
        .where(TicketAuditEvent.ticket_id.in_([s.ticket_id for s in scopes]))
    )
    await probe.rollback()
    return int(count or 0)


def _own(logs: Sequence[Mapping[str, Any]]) -> list[Mapping[str, Any]]:
    """The request reconciliation and fetcher events (the HTTP client
    factory may log unrelated TLS diagnostics)."""
    return [entry for entry in logs if entry["event"].startswith("ibs_request_")]


def _sorted_logs(entries: list[Any]) -> list[Any]:
    """`entries` in a content order independent of dict key order."""
    return sorted(entries, key=lambda e: repr(sorted(e.items())))


def _scope_fields(scope: IBSRequestScope) -> dict[str, Any]:
    return {
        "log_level": "warning",
        "ticket_id": str(scope.ticket_id),
        "track_id": str(scope.track_id),
        "package_name": scope.package_name,
        "codestream": scope.codestream,
    }


def _failed(
    scope: IBSRequestScope,
    reason_category: str,
    *,
    request_number: int | None = None,
    http_status: int | None = None,
) -> dict[str, Any]:
    """The `ibs_request_scope_failed` of the fetcher (with `fetcher_name`)."""
    entry: dict[str, Any] = {
        "event": SCOPE_FAILED,
        **_scope_fields(scope),
        "reason_category": reason_category,
        "fetcher_name": NAME,
    }
    if request_number is not None:
        entry["request_number"] = request_number
    if http_status is not None:
        entry["http_status"] = http_status
    return entry


def _stale(scope: IBSRequestScope, reason_category: str) -> dict[str, Any]:
    return {
        "event": SCOPE_STALE,
        **_scope_fields(scope),
        "reason_category": reason_category,
    }


def _completed(
    selected: int,
    *,
    created: int = 0,
    updated: int = 0,
    no_op: int = 0,
    failed: int = 0,
    ticket_id: uuid.UUID | None = None,
) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "event": RUN_COMPLETED,
        "log_level": "info",
        "selected": selected,
        "created": created,
        "updated": updated,
        "no_op": no_op,
        "failed": failed,
    }
    if ticket_id is not None:
        entry["ticket_id"] = str(ticket_id)
    return entry


# ---------------------------------------------------------------------------
# run() harness: committed FetcherConfig and FetcherRun under a test name
# ---------------------------------------------------------------------------


class _Runs:
    """Commits one `running` FetcherRun per `start()` and reads it back."""

    def __init__(self, factory: async_sessionmaker[AsyncSession]) -> None:
        self._factory = factory
        self.fetcher_name = f"test_ibs_request_run_{uuid.uuid4().hex[:12]}"
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
    runs: _Runs,
    fetcher: SyncIbsRequests | None = None,
    config: FetcherRunConfig = _RUN_CONFIG,
) -> FetcherRun:
    """One complete `run()` that returns normally; the finalized row."""
    run_id = await runs.start()
    await (fetcher or SyncIbsRequests()).run(run_id=run_id, config=config)
    return await runs.finalized(run_id)


async def _run_failing(
    runs: _Runs, error: type[BaseException]
) -> tuple[BaseException, FetcherRun]:
    run_id = await runs.start()
    with pytest.raises(error) as raised:
        await SyncIbsRequests().run(run_id=run_id, config=_RUN_CONFIG)
    return raised.value, await runs.finalized(run_id)


def _soft_limit_message(processed: int) -> str:
    return (
        "Execution reached the soft time limit (hard limit for this run: "
        f"3600s; {processed} items processed). Review FetcherConfig.run_timeout "
        f"for future runs of fetcher '{NAME}'."
    )


async def _invoke(
    fetcher: SyncIbsRequests,
    invocation: str,
    session: AsyncSession,
    ticket_id: uuid.UUID,
) -> None:
    if invocation == "execute":
        await fetcher.execute(session)
    else:
        await fetcher.catch_up(str(ticket_id), session)


_INVOCATIONS = ["execute", "catch-up"]


# ---------------------------------------------------------------------------
# A1. Class contract, registration, bootstrap, and schedule (the roster
# publication is proven with the real class in test_run_ticket_convergence.py)
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
        assert SyncIbsRequests.name == NAME
        assert SyncIbsRequests.description == DESCRIPTION
        assert SyncIbsRequests.default_schedule == SCHEDULE
        assert SyncIbsRequests.participates_in_catch_up is True
        assert SyncIbsRequests.queue is None
        assert SyncIbsRequests.Settings is None
        assert SyncIbsRequests.default_request_delay == 0
        assert SyncIbsRequests.http_client_options == {}

    def test_class_body_declares_no_settings_queue_or_client_options(self) -> None:
        """Custom settings: No; default routing (no `queue`); the 0 s
        `default_request_delay` is declared explicitly; the fetcher's HTTP
        client is never used, so it overrides no option."""
        assert _class_body_assignments(SyncIbsRequests) == {
            "name",
            "description",
            "default_schedule",
            "default_request_delay",
            "participates_in_catch_up",
        }

    def test_class_name_is_derived_from_the_fetcher_name(self) -> None:
        derived = "".join(part.capitalize() for part in NAME.split("_"))

        assert derived == SyncIbsRequests.__name__ == "SyncIbsRequests"

    def test_execute_and_catch_up_are_custom_overrides(self) -> None:
        assert "execute" in SyncIbsRequests.__dict__
        assert "catch_up" in SyncIbsRequests.__dict__
        assert SyncIbsRequests.catch_up is not BaseFetcher.catch_up

    def test_discovery_registers_the_fetcher(self) -> None:
        discovery = APP_ROOT / "services" / "fetcher_discovery.py"

        assert fetcher_module.__name__ in imported_modules(discovery, "app.services")
        assert FETCHER_REGISTRY[NAME] is SyncIbsRequests

    def test_fetcher_participates_in_catch_up(self) -> None:
        assert get_catch_up_fetchers()[NAME] is SyncIbsRequests


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
        assert config.run_timeout == 3600
        assert config.request_delay == 0
        assert config.custom_settings == {}

    async def test_reconciliation_writes_the_daily_entry_on_default_routing(
        self, db_session: AsyncSession, celery_test_app: Celery
    ) -> None:
        await bootstrap_fetcher_configs(db_session)

        await reconcile_beat_schedule(db_session, celery_test_app)

        key = RedBeatSchedulerEntry.generate_key(celery_test_app, NAME)
        entry = RedBeatSchedulerEntry.from_key(key, app=celery_test_app)
        assert entry.task == "run_fetcher"
        assert entry.args == []
        assert entry.kwargs == {"fetcher_name": NAME, "triggered_by": "schedule"}
        # 30 2 * * *
        assert entry.schedule.minute == {30}
        assert entry.schedule.hour == {2}
        assert entry.schedule.day_of_month == set(range(1, 32))
        assert entry.schedule.month_of_year == set(range(1, 13))
        assert entry.schedule.day_of_week == set(range(7))
        # max(5, 3600) and max(1, floor(3600 * 0.95)); no queue.
        assert entry.options == {"time_limit": 3600, "soft_time_limit": 3420}


# ---------------------------------------------------------------------------
# A2. run() outcomes: exact FetcherRun status and counters (Metrics)
# ---------------------------------------------------------------------------


@pytest.mark.integration
@pytest.mark.usefixtures("units")
class TestRunOutcomes:
    async def test_created_scope_is_success_with_only_a_created_effect(
        self, world: RequestWorld, runs: _Runs, fake: FakeRequests
    ) -> None:
        """A new request, action, and correlation that also move delivery
        to `IN_PROGRESS`: created once, never also updated."""
        (scope,) = await _seeded(world)
        number = _positive(fake, world, scope)

        with capture_logs() as logs:
            run = await _run(runs)

        assert _outcome(run) == ("success", 1, 1, 0, 0)
        assert (run.error_message, run.error_detail) == (None, None)
        assert run.cursor is None
        assert _own(logs) == [_completed(1, created=1)]
        assert fake.unrouted == []
        assert [row.request_number for row in await _evidence(world, scope)] == [number]
        assert await _delivery(world, scope) == IN_PROGRESS.value

    @pytest.mark.parametrize("change", ["request-state", "delivery-only"])
    async def test_updated_scope_is_success_with_only_an_updated_effect(
        self, world: RequestWorld, runs: _Runs, fake: FakeRequests, change: str
    ) -> None:
        """A retained SR observed declined later (existing evidence changes)
        or an unchanged open SR whose track is still `PENDING` (only
        delivery changes)."""
        seed = RequestSeed(world)
        scope = await seed.track(await seed.ticket(), package=unique_package())
        number, action = await _correlated(seed, scope)
        await seed.commit()
        before = await _requests(world, number)
        if change == "request-state":
            fake.request(number, DECLINED, action, when=LATER)
        else:
            fake.request(number, REVIEW, action)
        fake.quiet(scope.package_name)

        with capture_logs() as logs:
            run = await _run(runs)

        assert _outcome(run) == ("success", 1, 0, 1, 0)
        assert run.error_message is None
        assert _own(logs) == [_completed(1, updated=1)]
        if change == "request-state":
            assert (await _requests(world, number))[number][0] == DECLINED.value
            assert await _delivery(world, scope) == PENDING.value
        else:
            assert await _requests(world, number) == before
            assert await _delivery(world, scope) == IN_PROGRESS.value

    async def test_complete_positive_unchanged_is_a_no_op_success(
        self,
        world: RequestWorld,
        runs: _Runs,
        fake: FakeRequests,
        units: UnitSessions,
    ) -> None:
        seed = RequestSeed(world)
        scope = await seed.track(
            await seed.ticket(), package=unique_package(), delivery=IN_PROGRESS
        )
        number, action = await _correlated(seed, scope)
        await seed.commit()
        before = await _requests(world, number)
        fake.request(number, REVIEW, action)
        fake.quiet(scope.package_name, open_submissions=[number])
        units.events = []

        with capture_logs() as logs:
            run = await _run(runs)

        assert _outcome(run) == ("success", 1, 0, 0, 0)
        assert _own(logs) == [_completed(1, no_op=1)]
        assert units.events == ["unit", "close", "unit", "close"]
        assert await _requests(world, number) == before
        assert await _delivery(world, scope) == IN_PROGRESS.value

    async def test_complete_no_match_is_a_no_op_success(
        self, world: RequestWorld, runs: _Runs, fake: FakeRequests
    ) -> None:
        (scope,) = await _seeded(world)
        fake.quiet(scope.package_name)

        with capture_logs() as logs:
            run = await _run(runs)

        assert _outcome(run) == ("success", 1, 0, 0, 0)
        assert _own(logs) == [_completed(1, no_op=1)]
        assert fake.unrouted == []
        assert await _evidence(world, scope) == []
        assert await _delivery(world, scope) == PENDING.value

    @pytest.mark.parametrize(
        ("status", "reason"),
        [
            pytest.param(TicketStatus.RESOLVED, "scope_changed", id="resolved"),
            pytest.param(TicketStatus.IGNORED, "ticket_not_operable", id="ignored"),
            pytest.param(
                TicketStatus.DUPLICATED, "ticket_not_operable", id="duplicated"
            ),
        ],
    )
    async def test_stale_or_inapplicable_scope_is_succeeded_without_effect(
        self,
        world: RequestWorld,
        runs: _Runs,
        fake: FakeRequests,
        monkeypatch: pytest.MonkeyPatch,
        status: TicketStatus,
        reason: str,
    ) -> None:
        """The Ticket leaves the active states after the observation and
        before the lock: a successful no-op, not a failure."""
        (scope,) = await _seeded(world)
        number = _positive(fake, world, scope)
        _before_first_lock(monkeypatch, _leaves(world, scope, status))

        with capture_logs() as logs:
            run = await _run(runs)

        assert _outcome(run) == ("success", 1, 0, 0, 0)
        assert run.error_message is None
        assert _own(logs) == [_stale(scope, reason), _completed(1, no_op=1)]
        assert await _requests(world, number) == {}
        assert await _evidence(world, scope) == []
        assert await _delivery(world, scope) == PENDING.value

    @pytest.mark.parametrize(
        ("responder", "reason", "http_status", "attempts"),
        [
            pytest.param(status_response(404), "not_found", None, 1, id="incomplete"),
            pytest.param(
                status_response(500),
                "http_status",
                500,
                TRANSPORT_ATTEMPTS,
                id="http-500",
            ),
            pytest.param(
                raising(httpx.ConnectError("fictional connection refused")),
                "transport",
                None,
                TRANSPORT_ATTEMPTS,
                id="transport",
            ),
        ],
    )
    async def test_incomplete_or_failed_scope_is_failed(
        self,
        world: RequestWorld,
        runs: _Runs,
        fake: FakeRequests,
        responder: Any,
        reason: str,
        http_status: int | None,
        attempts: int,
    ) -> None:
        """The correlated request's detail is missing (incomplete) or fails
        after the shared transport retries: one failed scope, no write, and
        the normal-return all-failed message."""
        seed = RequestSeed(world)
        scope = await seed.track(
            await seed.ticket(), package=unique_package(), delivery=IN_PROGRESS
        )
        number, _ = await _correlated(seed, scope)
        await seed.commit()
        before = await _requests(world, number)
        fake.raw_request(number, responder)
        fake.quiet(scope.package_name)

        with capture_logs() as logs:
            run = await _run(runs)

        assert _outcome(run) == ("failure", 0, 0, 0, 1)
        assert run.error_message == "All 1 items failed"
        assert (run.error_detail, run.error_traceback) == (None, None)
        assert _own(logs) == [
            _failed(scope, reason, request_number=number, http_status=http_status),
            _completed(1, failed=1),
        ]
        assert _served(fake, f"/request/{number}") == attempts
        assert await _requests(world, number) == before
        assert await _delivery(world, scope) == IN_PROGRESS.value

    async def test_shared_failed_artifact_counts_each_scope_once(
        self, world: RequestWorld, runs: _Runs, fake: FakeRequests
    ) -> None:
        """Two Tickets' tracks of one package and codestream share one
        current release evidence request, which fails: one request (with
        its transport retries), two failed scopes."""
        package = unique_package()
        seed = RequestSeed(world)
        scopes = sorted(
            [
                await seed.track(await seed.ticket(), package=package),
                await seed.track(await seed.ticket(), package=package),
            ],
            key=lambda scope: scope.track_id,
        )
        await seed.commit()
        fake.release_evidence(CODESTREAM, package, source=status_response(500))

        with capture_logs() as logs:
            run = await _run(runs)

        assert _outcome(run) == ("failure", 0, 0, 0, 2)
        assert run.error_message == "All 2 items failed"
        assert _served(fake, f"/source/{CODESTREAM}") == TRANSPORT_ATTEMPTS
        assert len(fake.served) == TRANSPORT_ATTEMPTS
        assert logged(logs, SCOPE_FAILED) == [
            _failed(scope, "http_status", http_status=500) for scope in scopes
        ]
        assert logged(logs, RUN_COMPLETED) == [_completed(2, failed=2)]

    async def test_mixed_outcomes_are_partial(
        self, world: RequestWorld, runs: _Runs, fake: FakeRequests
    ) -> None:
        """One created, one complete no-match, and one incomplete scope."""
        seed = RequestSeed(world)
        created = await seed.track(await seed.ticket(), package=unique_package())
        no_match = await seed.track(await seed.ticket(), package=unique_package())
        failed = await seed.track(
            await seed.ticket(), package=unique_package(), delivery=IN_PROGRESS
        )
        missing, _ = await _correlated(seed, failed)
        await seed.commit()
        _positive(fake, world, created)
        fake.quiet(no_match.package_name)
        fake.respond("GET", f"/request/{missing}", [], 404)
        fake.quiet(failed.package_name)

        with capture_logs() as logs:
            run = await _run(runs)

        assert _outcome(run) == ("partial", 2, 1, 0, 1)
        assert run.error_message is None
        assert run.cursor is None
        assert logged(logs, SCOPE_FAILED) == [
            _failed(failed, "not_found", request_number=missing)
        ]
        assert logged(logs, RUN_COMPLETED) == [
            _completed(3, created=1, no_op=1, failed=1)
        ]
        assert await _delivery(world, created) == IN_PROGRESS.value
        assert await _evidence(world, no_match) == []
        assert await _delivery(world, failed) == IN_PROGRESS.value

    async def test_all_failed_is_a_normal_return_failure(
        self, world: RequestWorld, runs: _Runs, fake: FakeRequests
    ) -> None:
        seed = RequestSeed(world)
        first = await seed.track(await seed.ticket(), package=unique_package())
        second = await seed.track(await seed.ticket(), package=unique_package())
        first_number, _ = await _correlated(seed, first)
        second_number, _ = await _correlated(seed, second)
        await seed.commit()
        fake.respond("GET", f"/request/{first_number}", [], 404)
        fake.raw_request(second_number, raising(httpx.ConnectError("fictional")))
        for scope in (first, second):
            fake.quiet(scope.package_name)

        with capture_logs() as logs:
            run = await _run(runs)

        assert _outcome(run) == ("failure", 0, 0, 0, 2)
        assert run.error_message == "All 2 items failed"
        assert (run.error_detail, run.error_traceback) == (None, None)
        assert _sorted_logs(logged(logs, SCOPE_FAILED)) == _sorted_logs(
            [
                _failed(first, "not_found", request_number=first_number),
                _failed(second, "transport", request_number=second_number),
            ]
        )
        assert logged(logs, RUN_COMPLETED) == [_completed(2, failed=2)]

    async def test_empty_selection_is_success_without_a_client(
        self,
        runs: _Runs,
        fake: FakeRequests,
        ibs_clients: _IBSClients,
        units: UnitSessions,
    ) -> None:
        with capture_logs() as logs:
            run = await _run(runs)

        assert _outcome(run) == ("success", 0, 0, 0, 0)
        assert (run.error_message, run.error_detail) == (None, None)
        assert run.cursor is None
        assert ibs_clients.created == []
        assert fake.server.requests == []
        assert units.sessions == []
        assert _own(logs) == [_completed(0)]


# ---------------------------------------------------------------------------
# A3. Durability and exclusivity (testing-strategy.md, Fetcher Outcome and
# Effect Accounting; Error Handling, the commit rows)
# ---------------------------------------------------------------------------


@pytest.mark.integration
@pytest.mark.usefixtures("units")
class TestCommitDurability:
    async def test_definitely_failed_commit_fails_that_scope_and_continues(
        self,
        world: RequestWorld,
        runs: _Runs,
        fake: FakeRequests,
        units: UnitSessions,
    ) -> None:
        """The database rejects the first unit's commit: that scope fails
        (`database`) without an effect, the second is still created."""
        first, second = await _seeded(world, 2)
        rejected = _positive(fake, world, first)
        committed = _positive(fake, world, second)
        units.failing_commit = (1, _commit_error("40001"))

        with capture_logs() as logs:
            run = await _run(runs)

        assert _outcome(run) == ("partial", 1, 1, 0, 1)
        assert logged(logs, SCOPE_FAILED) == [_failed(first, "database")]
        assert logged(logs, RUN_COMPLETED) == [_completed(2, created=1, failed=1)]
        assert await _requests(world, rejected) == {}
        assert await _delivery(world, first) == PENDING.value
        assert [row.request_number for row in await _evidence(world, second)] == [
            committed
        ]

    @pytest.mark.parametrize(
        "error",
        [
            pytest.param(_commit_error(None), id="no-sqlstate"),
            pytest.param(
                _commit_error("40001", connection_invalidated=True),
                id="connection-invalidated",
            ),
        ],
    )
    async def test_ambiguous_commit_ends_the_run_keeping_earlier_metrics(
        self,
        world: RequestWorld,
        runs: _Runs,
        fake: FakeRequests,
        units: UnitSessions,
        ibs_clients: _IBSClients,
        error: OperationalError,
    ) -> None:
        """The second unit's commit outcome is unknown: the run fails with
        the generic message, the first scope stays committed with its
        success and created metrics, the second records nothing, and the
        third is never attempted."""
        first, second, third = await _seeded(world, 3)
        committed = _positive(fake, world, first)
        unknown = _positive(fake, world, second)
        untouched = _positive(fake, world, third)
        units.failing_commit = (2, error)

        with capture_logs() as logs:
            raised, run = await _run_failing(runs, OperationalError)

        assert raised is error
        assert _outcome(run) == ("failure", 1, 1, 0, 0)
        assert run.error_message == "Unexpected error"
        assert logged(logs, SCOPE_FAILED) == []
        assert logged(logs, RUN_COMPLETED) == []
        assert len(units.sessions) == 3
        assert units.closed == units.sessions
        assert [row.request_number for row in await _evidence(world, first)] == [
            committed
        ]
        assert await _requests(world, unknown, untouched) == {}
        assert third.package_name not in repr(fake.served)
        ibs_clients.assert_each_closed(1)


# ---------------------------------------------------------------------------
# A4. Whole-run errors and sanitization (Error Handling)
# ---------------------------------------------------------------------------


_ENUMERATION_ERRORS = [
    pytest.param(
        lambda: OperationalError("SELECT", None, Exception(INTERNAL_URL)),
        id="operational",
    ),
    pytest.param(
        lambda: DBAPIError("SELECT", None, Exception(INTERNAL_URL)), id="dbapi"
    ),
]


@pytest.mark.integration
@pytest.mark.usefixtures("units")
class TestRunErrors:
    @pytest.mark.parametrize("make_error", _ENUMERATION_ERRORS)
    async def test_enumeration_failure_is_a_sanitized_fetcher_error(
        self,
        world: RequestWorld,
        runs: _Runs,
        fake: FakeRequests,
        ibs_clients: _IBSClients,
        units: UnitSessions,
        monkeypatch: pytest.MonkeyPatch,
        make_error: Callable[[], Exception],
    ) -> None:
        (scope,) = await _seeded(world)
        _positive(fake, world, scope)
        error = make_error()

        async def failing(db: AsyncSession, **kwargs: Any) -> Any:
            raise error

        monkeypatch.setattr(fetcher_module, "load_ibs_request_scopes", failing)

        raised, run = await _run_failing(runs, FetcherError)

        assert str(raised) == ENUMERATION_FAILED
        assert raised.__cause__ is error
        assert _outcome(run) == ("failure", 0, 0, 0, 0)
        assert run.error_message == ENUMERATION_FAILED
        assert run.error_detail == str(error)
        assert ibs_clients.created == []
        assert fake.server.requests == []
        assert units.sessions == []
        assert await _evidence(world, scope) == []

    async def test_snapshot_read_failure_uses_the_generic_category(
        self,
        world: RequestWorld,
        runs: _Runs,
        fake: FakeRequests,
        ibs_clients: _IBSClients,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Another whole-run database prerequisite (the step-1 snapshot
        read) fails: the infrastructure's generic public message, the raw
        text only in the restricted detail, and no IBS request."""
        (scope,) = await _seeded(world)
        _positive(fake, world, scope)
        error = OperationalError("SELECT", None, Exception(INTERNAL_URL))

        async def failing(scopes: Sequence[IBSRequestScope]) -> Any:
            raise error

        monkeypatch.setattr(ibs_request_reconciliation, "_read_snapshots", failing)

        raised, run = await _run_failing(runs, OperationalError)

        assert raised is error
        assert _outcome(run) == ("failure", 0, 0, 0, 0)
        assert run.error_message == "Unexpected error"
        assert run.error_detail == str(error)
        assert fake.server.requests == []
        ibs_clients.assert_each_closed(1)

    async def test_failure_ending_the_enumeration_read_is_the_same_error(
        self,
        world: RequestWorld,
        fake: FakeRequests,
        ibs_clients: _IBSClients,
        units: UnitSessions,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The commit that ends the scope read fails: the same sanitized
        `FetcherError` before any IBS request or unit."""
        (scope,) = await _seeded(world)
        _positive(fake, world, scope)
        session = await world.open_session()
        error = OperationalError("COMMIT", None, Exception(INTERNAL_URL))
        monkeypatch.setattr(session, "commit", AsyncMock(side_effect=error))

        with pytest.raises(FetcherError) as raised:
            await SyncIbsRequests().execute(session)

        assert str(raised.value) == ENUMERATION_FAILED
        assert raised.value.__cause__ is error
        assert ibs_clients.created == []
        assert fake.server.requests == []
        assert units.sessions == []

    @pytest.mark.parametrize(
        ("signal", "message"),
        [
            pytest.param(
                SoftTimeLimitExceeded, _soft_limit_message(1), id="soft-time-limit"
            ),
            pytest.param(MemoryError, "Unexpected error", id="memory-error"),
        ],
    )
    async def test_whole_run_signal_in_a_later_scope_fails_the_run(
        self,
        world: RequestWorld,
        runs: _Runs,
        fake: FakeRequests,
        ibs_clients: _IBSClients,
        signal: type[BaseException],
        message: str,
    ) -> None:
        """The signal escapes from the second scope's IBS I/O: never a
        per-scope failure; the first scope stays committed and counted,
        the third is not attempted."""
        first, second, third = await _seeded(world, 3)
        committed = _positive(fake, world, first)
        error = signal()
        fake.release_evidence(CODESTREAM, second.package_name)
        fake.search(MI, second.package_name, responder=raising(error))
        untouched = _positive(fake, world, third)

        with capture_logs() as logs:
            raised, run = await _run_failing(runs, signal)

        assert raised is error
        assert _outcome(run) == ("failure", 1, 1, 0, 0)
        assert run.error_message == message
        assert logged(logs, SCOPE_FAILED) == []
        assert logged(logs, RUN_COMPLETED) == []
        assert [row.request_number for row in await _evidence(world, first)] == [
            committed
        ]
        assert await _evidence(world, second) == []
        assert await _requests(world, untouched) == {}
        assert third.package_name not in repr(fake.served)
        ibs_clients.assert_each_closed(1)


# ---------------------------------------------------------------------------
# A5. Credentials not configured (Error Handling, credentials row)
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
    async def test_scopes_needing_ibs_fail_without_any_request(
        self,
        world: RequestWorld,
        runs: _Runs,
        fake: FakeRequests,
        ibs_clients: _IBSClients,
        units: UnitSessions,
        monkeypatch: pytest.MonkeyPatch,
        setting: str,
    ) -> None:
        """Every scope with a CVE fails once without HTTP; the CVE-less
        scope is still a successful no-op without I/O."""
        seed = RequestSeed(world)
        needing = sorted(
            [
                await seed.track(await seed.ticket(), package=unique_package()),
                await seed.track(await seed.ticket(), package=unique_package()),
            ],
            key=lambda scope: scope.track_id,
        )
        cveless = await seed.track(
            await seed.ticket(with_cve=False), package=unique_package()
        )
        await seed.commit()
        for scope in needing:
            _positive(fake, world, scope)
        _unconfigure(monkeypatch, setting)

        with capture_logs() as logs:
            run = await _run(runs)

        assert _outcome(run) == ("partial", 1, 0, 0, 2)
        assert run.error_message is None
        assert fake.server.requests == []
        assert logged(logs, SCOPE_FAILED) == [
            _failed(scope, CREDENTIALS) for scope in needing
        ]
        assert logged(logs, RUN_COMPLETED) == [_completed(3, no_op=1, failed=2)]
        # The step-1 snapshot session and the CVE-less scope's unit.
        assert len(units.sessions) == 2
        for scope in (*needing, cveless):
            assert await _evidence(world, scope) == []
            assert await _delivery(world, scope) == PENDING.value
        ibs_clients.assert_each_closed(1)

    @pytest.mark.parametrize("setting", _EMPTY_SETTINGS)
    async def test_empty_selection_still_succeeds(
        self,
        runs: _Runs,
        fake: FakeRequests,
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
        assert fake.server.requests == []
        assert _own(logs) == [_completed(0)]


# ---------------------------------------------------------------------------
# A6. First run, long gap, and re-enable (Properties; Algorithm; Recovery
# Guarantees)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestStateBasedRerun:
    async def test_second_run_over_unchanged_upstream_writes_nothing(
        self,
        world: RequestWorld,
        runs: _Runs,
        fake: FakeRequests,
        units: UnitSessions,
    ) -> None:
        """The same complete algorithm runs every time: no cursor and no
        progress row; the second run over the same upstream evidence (as
        after a long gap or a re-enable without upstream change) is an
        idempotent success whose unit commits nothing."""
        (scope,) = await _seeded(world)
        number = _positive(fake, world, scope)

        first = await _run(runs)
        requests_before = await _requests(world, number)
        evidence_before = await _evidence(world, scope)
        units.events = []
        second = await _run(runs)

        assert _outcome(first) == ("success", 1, 1, 0, 0)
        assert _outcome(second) == ("success", 1, 0, 0, 0)
        assert (first.cursor, second.cursor) == (None, None)
        assert units.events == ["unit", "close", "unit", "close"]
        assert await _requests(world, number) == requests_before
        assert await _evidence(world, scope) == evidence_before
        assert await _delivery(world, scope) == IN_PROGRESS.value


# ---------------------------------------------------------------------------
# A7. Request delay (Fetcher: Request Delay); the boundary's placement of
# each wait outside every session is covered by
# `test_ibs_request_reconciliation.py`
# ---------------------------------------------------------------------------


@pytest.mark.integration
@pytest.mark.usefixtures("units")
class TestRequestDelay:
    @pytest.mark.parametrize("configured", [0.0, 0.5], ids=["0", "0.5"])
    async def test_run_waits_its_snapshot_delay_between_requests(
        self,
        world: RequestWorld,
        runs: _Runs,
        fake: FakeRequests,
        monkeypatch: pytest.MonkeyPatch,
        configured: float,
    ) -> None:
        """The run snapshot's `request_delay`, not the class value, precedes
        every IBS request of the run except the first (one operation, with
        its unsigned and signed attempts, is one request); zero never
        waits."""
        scopes = await _seeded(world, 2)
        for scope in scopes:
            _positive(fake, world, scope)
        sleeps = _recorded_sleeps(monkeypatch)
        monkeypatch.setattr(SyncIbsRequests, "default_request_delay", 9.0)

        run = await _run(
            runs,
            config=FetcherRunConfig(
                hard_time_limit_seconds=3600,
                request_delay=configured,
                custom_settings={},
            ),
        )

        assert _outcome(run) == ("success", 2, 2, 0, 0)
        assert fake.unrouted == []
        assert len(fake.served) > 2
        assert len(fake.server.requests) > len(fake.served)
        expected = [configured] * (len(fake.served) - 1) if configured else []
        assert sleeps == expected

    async def test_catch_up_waits_the_class_default_delay(
        self,
        world: RequestWorld,
        fake: FakeRequests,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Catch-up has no run snapshot: the class `default_request_delay`
        (0 in production, patched here) separates its requests, whatever
        run configuration the instance last held."""
        seed = RequestSeed(world)
        ticket = await seed.ticket()
        scopes = [await seed.track(ticket, package=unique_package()) for _ in range(2)]
        await seed.commit()
        for scope in scopes:
            _positive(fake, world, scope)
        sleeps = _recorded_sleeps(monkeypatch)
        monkeypatch.setattr(SyncIbsRequests, "default_request_delay", 0.25)
        fetcher = SyncIbsRequests()
        fetcher.config = FetcherRunConfig(
            hard_time_limit_seconds=3600, request_delay=9.0, custom_settings={}
        )

        await fetcher.catch_up(str(ticket.id), await world.open_session())

        assert fake.unrouted == []
        assert len(fake.served) > 2
        assert sleeps == [0.25] * (len(fake.served) - 1)
        for scope in scopes:
            assert await _delivery(world, scope) == IN_PROGRESS.value


# ---------------------------------------------------------------------------
# A8. IBSClient lifetime and teardown (ibs-integration.md, Service Layer >
# IBSClient; fetcher-infrastructure.md, HTTP Client Ownership Rule)
# ---------------------------------------------------------------------------


@pytest.mark.integration
@pytest.mark.usefixtures("units")
class TestIbsClientLifecycle:
    async def test_run_creates_one_production_client_and_closes_it(
        self,
        world: RequestWorld,
        runs: _Runs,
        fake: FakeRequests,
        ibs_clients: _IBSClients,
        fetcher_http_client: Mock,
    ) -> None:
        """One client for the whole run (two scopes, several requests),
        built from the settings, closed before `run()` returns; the
        fetcher's own HTTP client is never created."""
        scopes = await _seeded(world, 2)
        for scope in scopes:
            _positive(fake, world, scope)
        fetcher = SyncIbsRequests()

        run = await _run(runs, fetcher)

        assert _outcome(run) == ("success", 2, 2, 0, 0)
        ibs_clients.assert_each_closed(1)
        assert {request.url.host for request in fake.server.requests} == {TEST_HOST}
        # One authenticated session for every request of the invocation.
        assert len(fake.server.signatures) == 1
        fetcher_http_client.assert_not_called()
        assert fetcher._http_client is None

    @pytest.mark.parametrize("invocation", _INVOCATIONS)
    async def test_each_invocation_owns_its_own_client(
        self,
        world: RequestWorld,
        fake: FakeRequests,
        ibs_clients: _IBSClients,
        fetcher_http_client: Mock,
        invocation: str,
    ) -> None:
        """Two invocations of one fetcher instance: two clients, each
        created during and closed by its own invocation."""
        (scope,) = await _seeded(world)
        fake.quiet(scope.package_name)
        fetcher = SyncIbsRequests()

        await _invoke(fetcher, invocation, await world.open_session(), scope.ticket_id)
        ibs_clients.assert_each_closed(1)
        served = len(fake.served)
        await _invoke(fetcher, invocation, await world.open_session(), scope.ticket_id)

        ibs_clients.assert_each_closed(2)
        assert ibs_clients.created[0] is not ibs_clients.created[1]
        assert len(fake.served) == 2 * served
        fetcher_http_client.assert_not_called()
        assert fetcher._http_client is None

    @pytest.mark.parametrize("invocation", _INVOCATIONS)
    async def test_client_is_closed_on_a_propagating_failure(
        self,
        world: RequestWorld,
        fake: FakeRequests,
        ibs_clients: _IBSClients,
        monkeypatch: pytest.MonkeyPatch,
        invocation: str,
    ) -> None:
        (scope,) = await _seeded(world)
        _positive(fake, world, scope)
        error = RuntimeError("fictional bug")

        async def failing(db: AsyncSession, **kwargs: Any) -> Any:
            raise error

        monkeypatch.setattr(package_service, "set_track_delivery_status", failing)

        with pytest.raises(RuntimeError) as raised:
            await _invoke(
                SyncIbsRequests(),
                invocation,
                await world.open_session(),
                scope.ticket_id,
            )

        assert raised.value is error
        ibs_clients.assert_each_closed(1)
        assert await _evidence(world, scope) == []
        assert await _delivery(world, scope) == PENDING.value

    @pytest.mark.parametrize("invocation", _INVOCATIONS)
    async def test_client_is_closed_on_cancellation(
        self,
        world: RequestWorld,
        fake: FakeRequests,
        ibs_clients: _IBSClients,
        monkeypatch: pytest.MonkeyPatch,
        invocation: str,
    ) -> None:
        """The invocation is cancelled while its first scope waits before
        the lock: the cancellation propagates and the client is closed."""
        (scope,) = await _seeded(world)
        _positive(fake, world, scope)
        waiting = asyncio.Event()

        async def block() -> None:
            waiting.set()
            await asyncio.Event().wait()

        _before_first_lock(monkeypatch, block)
        task = asyncio.create_task(
            _invoke(
                SyncIbsRequests(),
                invocation,
                await world.open_session(),
                scope.ticket_id,
            )
        )
        await asyncio.wait_for(waiting.wait(), timeout=WAIT)
        assert len(ibs_clients.created) == 1
        assert ibs_clients.closed == []

        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

        ibs_clients.assert_each_closed(1)
        assert await _evidence(world, scope) == []
        assert await _delivery(world, scope) == PENDING.value


# ---------------------------------------------------------------------------
# A9. Logs and privacy (Structured Logs; Error Handling; Security and
# Privacy)
# ---------------------------------------------------------------------------


@pytest.mark.integration
@pytest.mark.usefixtures("units")
class TestLogsAndPrivacy:
    async def test_logs_and_public_fields_carry_no_upstream_text_url_or_secret(
        self, world: RequestWorld, runs: _Runs, fake: FakeRequests
    ) -> None:
        """A transport error whose text carries a credential-bearing URL and
        an HTTP 500 whose body carries a fictional marker and secret: the
        public message is the bounded all-failed message, and neither the
        logs nor the run's public fields echo either."""
        seed = RequestSeed(world)
        refused = await seed.track(await seed.ticket(), package=unique_package())
        marked = await seed.track(await seed.ticket(), package=unique_package())
        refused_number, _ = await _correlated(seed, refused)
        marked_number, _ = await _correlated(seed, marked)
        await seed.commit()
        fake.raw_request(
            refused_number, raising(httpx.ConnectError(f"{INTERNAL_URL} refused"))
        )
        fake.raw_request(
            marked_number,
            status_response(500, f"<status>{MARKER} {SECRET}</status>".encode()),
        )
        for scope in (refused, marked):
            fake.quiet(scope.package_name)

        with capture_logs() as logs:
            run = await _run(runs)

        assert _outcome(run) == ("failure", 0, 0, 0, 2)
        assert run.error_message == "All 2 items failed"
        assert (run.error_detail, run.error_traceback) == (None, None)
        assert _sorted_logs(logged(logs, SCOPE_FAILED)) == _sorted_logs(
            [
                _failed(refused, "transport", request_number=refused_number),
                _failed(
                    marked, "http_status", request_number=marked_number, http_status=500
                ),
            ]
        )
        rendered = repr(logs)
        for forbidden in (SECRET, MARKER, INTERNAL_HOST, "jdoe"):
            assert forbidden not in rendered
        assert TEST_HOST not in repr(_own(logs))
        assert "authorization" not in rendered.lower()


# ---------------------------------------------------------------------------
# A10. Audit (Testing Requirements: zero Ticket events; Audit Trail Testing)
# ---------------------------------------------------------------------------


@pytest.mark.integration
@pytest.mark.usefixtures("units")
class TestAudit:
    async def test_no_run_or_catch_up_outcome_creates_a_ticket_event(
        self, world: RequestWorld, runs: _Runs, fake: FakeRequests
    ) -> None:
        """Created, updated, unchanged, and failed scopes of a run, then a
        no-op and an all-failed catch-up: no `TicketAuditEvent` is written
        or synthesized by the rollback of a failed scope."""
        seed = RequestSeed(world)
        created = await seed.track(await seed.ticket(), package=unique_package())
        updated = await seed.track(await seed.ticket(), package=unique_package())
        unchanged = await seed.track(
            await seed.ticket(), package=unique_package(), delivery=IN_PROGRESS
        )
        failed = await seed.track(
            await seed.ticket(), package=unique_package(), delivery=IN_PROGRESS
        )
        declined, declined_action = await _correlated(seed, updated)
        kept, kept_action = await _correlated(seed, unchanged)
        missing, _ = await _correlated(seed, failed)
        await seed.commit()
        _positive(fake, world, created)
        fake.request(declined, DECLINED, declined_action, when=LATER)
        fake.quiet(updated.package_name)
        fake.request(kept, REVIEW, kept_action)
        fake.quiet(unchanged.package_name, open_submissions=[kept])
        fake.respond("GET", f"/request/{missing}", [], 404)
        fake.quiet(failed.package_name)
        scopes = (created, updated, unchanged, failed)
        assert await _audit_count(world, *scopes) == 0

        with StatementRecorder(world.session) as recorder:
            run = await _run(runs)
            await SyncIbsRequests().catch_up(
                str(created.ticket_id), await world.open_session()
            )
            with pytest.raises(FetcherError):
                await SyncIbsRequests().catch_up(
                    str(failed.ticket_id), await world.open_session()
                )

        assert _outcome(run) == ("partial", 3, 1, 1, 1)
        assert any("INSERT INTO ibs_request" in s for s in recorder.statements)
        assert [s for s in recorder.statements if "ticket_audit_event" in s] == []
        assert await _audit_count(world, *scopes) == 0
        for scope in scopes:
            assert await events_of(world, scope.ticket_id) == []


# ---------------------------------------------------------------------------
# A11. catch_up() (Accelerators > Ticket Convergence; Metrics, the catch-up
# paragraph; fetcher-infrastructure.md, Interface contract)
# ---------------------------------------------------------------------------


SilentBuild = Callable[[RequestWorld], Awaitable[str]]


async def _missing(world: RequestWorld) -> str:
    return str(uuid.uuid4())


def _in_status(status: TicketStatus) -> SilentBuild:
    async def build(world: RequestWorld) -> str:
        seed = RequestSeed(world)
        ticket = await seed.ticket(status)
        await seed.track(ticket, package=unique_package())
        await seed.commit()
        return str(ticket.id)

    return build


async def _git_only(world: RequestWorld) -> str:
    seed = RequestSeed(world)
    ticket = await seed.ticket()
    await seed.track(
        ticket,
        package=unique_package(),
        codestream="slfo-1.2",
        workflow=WorkflowType.GIT,
    )
    await seed.commit()
    return str(ticket.id)


async def _empty_tree(world: RequestWorld) -> str:
    seed = RequestSeed(world)
    ticket = await seed.ticket()
    await seed.commit()
    return str(ticket.id)


_SILENT_CASES = [
    pytest.param(_missing, id="missing-ticket"),
    pytest.param(_in_status(TicketStatus.RESOLVED), id="resolved"),
    pytest.param(_in_status(TicketStatus.IGNORED), id="ignored"),
    pytest.param(_in_status(TicketStatus.DUPLICATED), id="duplicated"),
    pytest.param(_git_only, id="only-git-tracks"),
    pytest.param(_empty_tree, id="no-packages"),
]


@pytest.mark.integration
@pytest.mark.usefixtures("units")
class TestCatchUp:
    @pytest.mark.parametrize("build", _SILENT_CASES)
    async def test_silent_return_performs_no_client_http_log_or_write(
        self,
        world: RequestWorld,
        fake: FakeRequests,
        ibs_clients: _IBSClients,
        units: UnitSessions,
        build: SilentBuild,
    ) -> None:
        ticket_id = await build(world)
        session = await world.open_session()
        fetcher = SyncIbsRequests()

        with capture_logs() as logs, SessionStatementRecorder(session) as recorder:
            await fetcher.catch_up(ticket_id, session)

        assert logs == []
        assert ibs_clients.created == []
        assert fake.server.requests == []
        assert units.sessions == []
        assert fetcher._http_client is None
        assert len(recorder.statements) == 1
        assert recorder.writes() == []
        assert recorder.row_locks() == []
        assert not session.in_transaction()

    @pytest.mark.parametrize("invocation", _INVOCATIONS)
    async def test_scope_read_ends_before_the_first_ibs_request(
        self,
        world: RequestWorld,
        fake: FakeRequests,
        units: UnitSessions,
        invocation: str,
    ) -> None:
        """The passed session reads the scopes in one statement and commits
        before the first IBS request; the scope's mutations commit in the
        boundary's own sessions."""
        (scope,) = await _seeded(world)
        number = _positive(fake, world, scope)
        session = await world.open_session()
        events: list[str] = []
        open_at_request: list[bool] = []

        def requested(_: Any) -> None:
            events.append("http")
            open_at_request.append(session.in_transaction())

        def committed(_: Session) -> None:
            events.append("read:commit")

        fake.on_request = requested
        event.listen(session.sync_session, "after_commit", committed)

        with SessionStatementRecorder(session) as recorder:
            await _invoke(SyncIbsRequests(), invocation, session, scope.ticket_id)

        assert events[0] == "read:commit"
        assert events.count("read:commit") == 1
        assert open_at_request
        assert set(open_at_request) == {False}
        assert len(recorder.statements) == 1
        assert recorder.writes() == []
        assert recorder.row_locks() == []
        assert units.sessions
        assert all(unit is not session for unit in units.sessions)
        assert [row.request_number for row in await _evidence(world, scope)] == [number]

    async def test_catch_up_mutates_only_through_its_own_units_without_metrics(
        self,
        world: RequestWorld,
        fake: FakeRequests,
        units: UnitSessions,
        real_session_factory: async_sessionmaker[AsyncSession],
        metric_helpers: dict[str, Mock],
    ) -> None:
        (scope,) = await _seeded(world)
        number = _positive(fake, world, scope)
        session = await world.open_session()
        flushes: list[bool] = []

        def flushed(*_: Any) -> None:
            flushes.append(True)

        event.listen(session.sync_session, "before_flush", flushed)

        with capture_logs() as logs:
            await SyncIbsRequests().catch_up(str(scope.ticket_id), session)

        assert flushes == []
        assert not session.in_transaction()
        assert not session.new
        assert not session.dirty
        assert not session.deleted
        assert units.closed == units.sessions
        assert _own(logs) == [_completed(1, created=1, ticket_id=scope.ticket_id)]
        # Visible from an independent session after catch-up returned.
        assert [row.request_number for row in await _evidence(world, scope)] == [number]
        assert await _delivery(world, scope) == IN_PROGRESS.value
        for spy in metric_helpers.values():
            spy.assert_not_called()
        assert await fetcher_run_count(real_session_factory, NAME) == 0

    async def test_only_the_tickets_scopes_are_processed(
        self, world: RequestWorld, fake: FakeRequests
    ) -> None:
        mine, other = await _seeded(world, 2)
        _positive(fake, world, mine)
        other_number = _positive(fake, world, other)

        with capture_logs() as logs:
            await SyncIbsRequests().catch_up(
                str(mine.ticket_id), await world.open_session()
            )

        assert other.package_name not in repr(fake.served)
        assert mine.package_name in repr(fake.served)
        assert _own(logs) == [_completed(1, created=1, ticket_id=mine.ticket_id)]
        assert await _delivery(world, mine) == IN_PROGRESS.value
        assert await _requests(world, other_number) == {}
        assert await _delivery(world, other) == PENDING.value

    async def test_partial_failure_returns_and_logs_with_the_task_id(
        self,
        world: RequestWorld,
        fake: FakeRequests,
        metric_helpers: dict[str, Mock],
    ) -> None:
        """One created and one failed scope of one Ticket: normal return;
        the failed one is logged at WARNING with the Ticket, track, fetcher,
        bounded category, and the task-bound `celery_task_id`."""
        seed = RequestSeed(world)
        ticket = await seed.ticket()
        created = await seed.track(ticket, package=unique_package())
        failed = await seed.track(
            ticket, package=unique_package(), delivery=IN_PROGRESS
        )
        broken, _ = await _correlated(seed, failed)
        await seed.commit()
        _positive(fake, world, created)
        fake.raw_request(broken, status_response(500))
        fake.quiet(failed.package_name)
        celery_task_id = str(uuid.uuid4())
        bind_contextvars(celery_task_id=celery_task_id)
        try:
            with capture_logs(processors=[merge_contextvars]) as logs:
                await SyncIbsRequests().catch_up(
                    str(ticket.id), await world.open_session()
                )
        finally:
            unbind_contextvars("celery_task_id")

        assert logged(logs, SCOPE_FAILED) == [
            {
                **_failed(
                    failed, "http_status", request_number=broken, http_status=500
                ),
                "celery_task_id": celery_task_id,
            }
        ]
        assert logged(logs, RUN_COMPLETED) == [
            {
                **_completed(2, created=1, failed=1, ticket_id=ticket.id),
                "celery_task_id": celery_task_id,
            }
        ]
        assert await _delivery(world, created) == IN_PROGRESS.value
        assert await _delivery(world, failed) == IN_PROGRESS.value
        for spy in metric_helpers.values():
            spy.assert_not_called()

    @pytest.mark.parametrize("cause", ["request-failed", "credentials-not-configured"])
    async def test_all_failed_raises_the_sanitized_non_retryable_error(
        self,
        world: RequestWorld,
        fake: FakeRequests,
        ibs_clients: _IBSClients,
        units: UnitSessions,
        metric_helpers: dict[str, Mock],
        monkeypatch: pytest.MonkeyPatch,
        cause: str,
    ) -> None:
        """Every selected scope failed: the completion log, then
        `FetcherError("All 2 IBS request reconciliations failed")`, which
        `run_catch_up` does not retry."""
        seed = RequestSeed(world)
        ticket = await seed.ticket()
        scopes = sorted(
            [
                await seed.track(
                    ticket, package=unique_package(), delivery=IN_PROGRESS
                ),
                await seed.track(
                    ticket, package=unique_package(), delivery=IN_PROGRESS
                ),
            ],
            key=lambda scope: scope.track_id,
        )
        numbers = [(await _correlated(seed, scope))[0] for scope in scopes]
        await seed.commit()
        for scope, number in zip(scopes, numbers, strict=True):
            fake.respond("GET", f"/request/{number}", [], 404)
            fake.quiet(scope.package_name)
        if cause == "request-failed":
            expected = [
                _failed(scope, "not_found", request_number=number)
                for scope, number in zip(scopes, numbers, strict=True)
            ]
        else:
            _unconfigure(monkeypatch, "ibs_username")
            expected = [_failed(scope, CREDENTIALS) for scope in scopes]

        with capture_logs() as logs, pytest.raises(FetcherError) as raised:
            await SyncIbsRequests().catch_up(str(ticket.id), await world.open_session())

        assert str(raised.value) == "All 2 IBS request reconciliations failed"
        assert raised.value.__cause__ is None
        assert not is_retryable_condition(raised.value)
        assert _own(logs) == [
            *expected,
            _completed(2, failed=2, ticket_id=ticket.id),
        ]
        if cause == "credentials-not-configured":
            assert fake.server.requests == []
        # Only the step-1 snapshot session; no unit.
        assert len(units.sessions) == 1
        for scope in scopes:
            assert await _delivery(world, scope) == IN_PROGRESS.value
        ibs_clients.assert_each_closed(1)
        for spy in metric_helpers.values():
            spy.assert_not_called()

    async def test_ambiguous_commit_propagates_unchanged(
        self,
        world: RequestWorld,
        fake: FakeRequests,
        units: UnitSessions,
        ibs_clients: _IBSClients,
    ) -> None:
        """The first unit's commit outcome is unknown: the driver error
        escapes as is (not the all-failed `FetcherError`), without a
        failure warning for that scope, and the second scope is not
        attempted."""
        seed = RequestSeed(world)
        ticket = await seed.ticket()
        scopes = sorted(
            [
                await seed.track(ticket, package=unique_package()),
                await seed.track(ticket, package=unique_package()),
            ],
            key=lambda scope: scope.track_id,
        )
        await seed.commit()
        numbers = [_positive(fake, world, scope) for scope in scopes]
        error = _commit_error(None)
        units.failing_commit = (1, error)

        with capture_logs() as logs, pytest.raises(OperationalError) as raised:
            await SyncIbsRequests().catch_up(str(ticket.id), await world.open_session())

        assert raised.value is error
        assert _own(logs) == []
        assert scopes[1].package_name not in repr(fake.served)
        assert await _requests(world, *numbers) == {}
        ibs_clients.assert_each_closed(1)

    @pytest.mark.parametrize(
        "status", [TicketStatus.IGNORED, TicketStatus.DUPLICATED], ids=str
    )
    async def test_ticket_leaving_the_active_states_is_a_stale_no_op(
        self,
        world: RequestWorld,
        fake: FakeRequests,
        monkeypatch: pytest.MonkeyPatch,
        status: TicketStatus,
    ) -> None:
        (scope,) = await _seeded(world)
        number = _positive(fake, world, scope)
        _before_first_lock(monkeypatch, _leaves(world, scope, status))

        with capture_logs() as logs:
            await SyncIbsRequests().catch_up(
                str(scope.ticket_id), await world.open_session()
            )

        assert _own(logs) == [
            _stale(scope, "ticket_not_operable"),
            _completed(1, no_op=1, ticket_id=scope.ticket_id),
        ]
        assert await _requests(world, number) == {}
        assert await _delivery(world, scope) == PENDING.value

    @pytest.mark.parametrize("concurrent", ["periodic", "catch-up"])
    async def test_concurrent_invocations_reconcile_once(
        self,
        world: RequestWorld,
        fake: FakeRequests,
        ibs_clients: _IBSClients,
        monkeypatch: pytest.MonkeyPatch,
        concurrent: str,
    ) -> None:
        """A periodic execution (or a second catch-up) over the same Ticket
        runs to completion in its own sessions after this catch-up's IBS
        I/O and before its unit: one set of evidence rows and the correct
        delivery; the later unit is an idempotent no-op."""
        (scope,) = await _seeded(world)
        number = _positive(fake, world, scope)
        other = SyncIbsRequests()
        periodic = concurrent == "periodic"

        async def run_other() -> None:
            await _invoke(
                other,
                "execute" if periodic else "catch-up",
                await world.open_session(),
                scope.ticket_id,
            )

        _before_first_lock(monkeypatch, run_other)

        with capture_logs() as logs:
            await SyncIbsRequests().catch_up(
                str(scope.ticket_id), await world.open_session()
            )

        assert _own(logs) == [
            _completed(1, created=1, ticket_id=None if periodic else scope.ticket_id),
            _completed(1, no_op=1, ticket_id=scope.ticket_id),
        ]
        expected = (1, 1, 0, 0) if periodic else (0, 0, 0, 0)
        assert (other._succeeded, other._created, other._updated, other._failed) == (
            expected
        )
        assert [row.request_number for row in await _evidence(world, scope)] == [number]
        assert list(await _requests(world, number)) == [number]
        assert await _delivery(world, scope) == IN_PROGRESS.value
        ibs_clients.assert_each_closed(2)


# ---------------------------------------------------------------------------
# A12. run_catch_up composition (fetcher-infrastructure.md, Celery task
# wrapper)
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
    async def test_success_reconciles_and_closes_the_client(
        self,
        world: RequestWorld,
        fake: FakeRequests,
        ibs_clients: _IBSClients,
        fetcher_http_client: Mock,
        catch_up_task: _CatchUpTask,
    ) -> None:
        (scope,) = await _seeded(world)
        number = _positive(fake, world, scope)

        with capture_logs() as logs:
            await fetchers.run_catch_up_async(NAME, str(scope.ticket_id))

        assert [e for e in logs if e["log_level"] == "error"] == []
        assert [row.request_number for row in await _evidence(world, scope)] == [number]
        assert await _delivery(world, scope) == IN_PROGRESS.value
        ibs_clients.assert_each_closed(1)
        fetcher_http_client.assert_not_called()
        catch_up_task.engine.dispose.assert_awaited_once_with()
        assert await fetcher_run_count(catch_up_task.factory, NAME) == 0


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
        fake: FakeRequests,
        ibs_clients: _IBSClients,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The real fetcher and boundary inside the wrapper's own
        `asyncio.run()`, with the enabled read, the sessions, the scope
        read, and the step-1 snapshot read substituted: the scope fails in
        its first IBS request, so no unit session is opened, the client is
        closed, and the `FetcherError` is not retried."""
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
        scope = IBSRequestScope(
            ticket_id=ticket_id,
            cve_id="CVE-2099-00000001",
            package_id=uuid.uuid4(),
            package_name="example-wrapper",
            track_id=uuid.uuid4(),
            codestream=CODESTREAM,
        )
        selections: list[uuid.UUID | None] = []

        async def load(
            db: Any, *, ticket_id: uuid.UUID | None = None
        ) -> list[IBSRequestScope]:
            assert db is session
            selections.append(ticket_id)
            return [scope]

        async def snapshots(
            scopes: Sequence[IBSRequestScope],
        ) -> dict[uuid.UUID, Any]:
            return {selected.track_id: snapshot() for selected in scopes}

        monkeypatch.setattr(fetcher_module, "load_ibs_request_scopes", load)
        monkeypatch.setattr(ibs_request_reconciliation, "_read_snapshots", snapshots)
        unit_factory = MagicMock(side_effect=AssertionError("must not open a unit"))
        monkeypatch.setattr(
            ibs_request_reconciliation, "async_session_factory", unit_factory
        )
        fake.release_evidence(
            CODESTREAM, scope.package_name, source=status_response(403)
        )
        task = FakeTask()

        with capture_logs() as logs, pytest.raises(FetcherError) as raised:
            fetchers._run_catch_up_sync(task, NAME, str(ticket_id))

        assert str(raised.value) == "All 1 IBS request reconciliations failed"
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
        assert _own(logs) == [
            _failed(scope, "http_status", http_status=403),
            _completed(1, failed=1, ticket_id=ticket_id),
        ]
        unit_factory.assert_not_called()
        ibs_clients.assert_each_closed(1)
        engine.dispose.assert_awaited_once_with()
