"""Per-CVE finalization and isolated status writes of `BaseCVEFetcher`
(backend/app/services/base_cve_fetcher.py).

Owning specifications:

- docs/features/platform/cve-fetcher-infrastructure.md (`CVEFetchResult`;
  Per-CVE Finalization; Session Lifecycle for API-based CVE Fetchers,
  including the `resolve_ticket_packages` handoff, Isolated status commit,
  and Metric placement; Metric Definitions).
- docs/features/platform/fetcher-infrastructure.md (`run()` lifecycle
  step 5, the automatic periodic context; Finalization; Outcome and effect
  accounting).
- docs/features/tickets/cve-service.md (Post-Commit Package-Candidate
  Handoff; UpsertResult Design Context, Fetcher effect mapping) and
  docs/features/tickets/ticket-service.md (Publication policies;
  Publication failure logging).
- docs/features/platform/testing-strategy.md (CVE Fetcher Infrastructure:
  One-shot finalization, Periodic metrics, Isolated statuses; Fetcher
  Outcome and Effect Accounting, Regression combinations; Ticket
  Convergence Publication Handoff, the CVE/fetcher owner rows and Control
  signals and security).

Finalization runs against real PostgreSQL. The reusable per-CVE session is
an independent `db_session_factory` session whose commits are real, so the
transaction-local Ticket convergence registry observes genuine commit,
rollback, and close boundaries; committed rows are deleted explicitly at
teardown. `BaseFetcher.run()` and `_isolated_status_commit()` open their own
sessions through the module-level `async_session_factory` references in
`app.services.base_fetcher` and `app.services.base_cve_fetcher`, which are
redirected to the test engine. The broker call is substituted through
`task_publication.publish_task`; the convergence drain is the real adapter
wrapped by an order-recording spy.

Test-only fetchers are concrete subclasses of the abstract
`_ScriptedCVEFetcher` below, defined per test under the shared
`isolated_fetcher_registries` fixture. Its `execute()` follows the
`fetch_single()` loop template of the Session Lifecycle section, without
the source-specific consecutive-failure counter, raw per-item log, and
request delay.
"""

from __future__ import annotations

import asyncio
import dataclasses
import json
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable, MutableMapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, NamedTuple, cast

import pytest
from celery.exceptions import OperationalError, SoftTimeLimitExceeded
from kombu.exceptions import EncodeError  # type: ignore[import-untyped]
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from structlog.contextvars import (
    bind_contextvars,
    merge_contextvars,
    unbind_contextvars,
)
from structlog.testing import capture_logs

import app.services.base_cve_fetcher as base_cve_fetcher_module
import app.services.base_fetcher as base_fetcher_module
from app.core.enums import CVESourceFetchStatus, CVESourceType, TicketStatus
from app.models.cve import CVE
from app.models.cve_source import CVESource
from app.models.fetcher_config import FetcherConfig
from app.models.fetcher_run import FetcherRun
from app.models.ticket import Ticket
from app.services import (
    cve_service,
    package_service,
    task_publication,
    ticket_convergence_publication,
)
from app.services.base_cve_fetcher import (
    _CVE_SOURCE_TYPE_MAP,
    HANDOFF_PUBLICATION_FAILED_EVENT,
    ISOLATED_STATUS_CVE_MISSING_EVENT,
    ISOLATED_STATUS_WRITE_FAILED_EVENT,
    BaseCVEFetcher,
    CVEFetchResult,
    CVENotInSource,
)
from app.services.base_fetcher import FetcherRunConfig
from app.services.cve_ingest import PostIngestTasks, UpsertAction
from app.services.ticket_convergence_publication import (
    PUBLICATION_FAILED_EVENT,
    RUN_TICKET_CONVERGENCE_TASK,
)
from app.services.ticket_convergence_registry import register_ticket_convergence

pytestmark = pytest.mark.usefixtures("isolated_fetcher_registries")

SessionFactory = Callable[[], Awaitable[AsyncSession]]
Step = Callable[[AsyncSession], Awaitable[CVEFetchResult]]
LogEntry = MutableMapping[str, Any]

_SOURCE = CVESourceType.NVD
_CONVERGE = RUN_TICKET_CONVERGENCE_TASK
_RESOLVE = package_service.RESOLVE_TICKET_PACKAGES_TASK
_SECRET = "broker-secret-host:5672"
_PACKAGE = "example-package"
_CPE = "cpe:2.3:a:example_vendor:example_product:1.0:*:*:*:*:*:*:*"
_OTHER_CPE = "cpe:2.3:a:example_vendor:other_product:*:*:*:*:*:*:*:*"
_MATCH_ID = "00000000-0000-4000-8000-000000000001"
_CONFIG = FetcherRunConfig(
    hard_time_limit_seconds=3600, request_delay=0, custom_settings={}
)


# ---------------------------------------------------------------------------
# Test-only fetcher
# ---------------------------------------------------------------------------


class _ScriptedCVEFetcher(BaseCVEFetcher):
    """Abstract test-only CVE fetcher driven by a per-CVE step plan.

    `fetch_single()` records whether the automatic periodic context is set
    and runs the planned step for the CVE-ID; `execute()` iterates over the
    plan with the documented per-CVE isolation boundary.
    """

    abstract = True

    def __init__(self) -> None:
        super().__init__()
        self.plan: dict[str, Step] = {}
        self.contexts: list[bool] = []

    async def fetch_single(self, cve_id: str, session: AsyncSession) -> CVEFetchResult:
        self.contexts.append(self._periodic_context)
        return await self.plan[cve_id](session)

    async def execute(self, session: AsyncSession) -> None:
        for cve_id in self.plan:
            try:
                result = await self.fetch_single(cve_id, session)
                await session.flush()
            except asyncio.CancelledError, SoftTimeLimitExceeded, MemoryError:
                raise
            except CVENotInSource:
                await session.rollback()
                await self._isolated_status_commit(cve_id, CVESourceFetchStatus.MISSING)
                self.record_succeeded()
            except Exception:
                await session.rollback()
                await self._isolated_status_commit(cve_id, CVESourceFetchStatus.FAILURE)
                self.record_failed()
            else:
                await self.commit_and_dispatch(session, result)


def _define_fetcher(name: str | None = None) -> type[_ScriptedCVEFetcher]:
    """Register one concrete scripted fetcher owning `_SOURCE`."""
    # A production owner of the source, if any, is restored by
    # `isolated_fetcher_registries`.
    _CVE_SOURCE_TYPE_MAP.pop(_SOURCE, None)
    namespace: dict[str, Any] = {
        "name": name or f"test_cve_finalization_{uuid.uuid4().hex[:12]}",
        "description": "Test-only CVE finalization fetcher",
        "default_schedule": "0 * * * *",
        "cve_source_type": _SOURCE,
    }
    return cast(
        type[_ScriptedCVEFetcher],
        type("ScriptedCveFetcher", (_ScriptedCVEFetcher,), namespace),
    )


def _counters(fetcher: BaseCVEFetcher) -> tuple[int, int, int, int]:
    """(succeeded, created, updated, failed)."""
    return (fetcher._succeeded, fetcher._created, fetcher._updated, fetcher._failed)


class _CommitFailureError(Exception):
    """An injected commit exception."""


# ---------------------------------------------------------------------------
# Committed world
# ---------------------------------------------------------------------------


class _Cve(NamedTuple):
    id: uuid.UUID
    cve_id: str


class _SourceState(NamedTuple):
    status: str
    fetched_at: datetime
    first_failed_at: datetime | None


@dataclass
class _World:
    """Committed CVE and Ticket rows, deleted explicitly at teardown
    (testing-strategy.md, Concurrency Testing); `CVESource` rows follow by
    their `ON DELETE CASCADE` foreign key."""

    factory: SessionFactory
    setup: AsyncSession
    probe: AsyncSession
    cve_ids: list[uuid.UUID] = field(default_factory=list)
    ticket_ids: list[uuid.UUID] = field(default_factory=list)
    owners: list[AsyncSession] = field(default_factory=list)

    async def owner(self) -> AsyncSession:
        """A reusable per-CVE session with real commits."""
        session = await self.factory()
        self.owners.append(session)
        return session

    async def cve(self) -> _Cve:
        cve = CVE(cve_id=f"CVE-2099-{uuid.uuid4().int % 10**8:08d}")
        self.setup.add(cve)
        await self.setup.commit()
        self.cve_ids.append(cve.id)
        return _Cve(cve.id, cve.cve_id)

    async def ticket(self, cve: _Cve) -> uuid.UUID:
        ticket = Ticket(status=TicketStatus.ANALYSIS.value, cve_id=cve.id)
        self.setup.add(ticket)
        await self.setup.commit()
        self.ticket_ids.append(ticket.id)
        return ticket.id

    async def seed_status(
        self, cve: _Cve, status: CVESourceFetchStatus
    ) -> _SourceState:
        await cve_service.record_source_status(self.setup, cve.id, _SOURCE, status)
        await self.setup.commit()
        state = await self.source_state(cve)
        assert state is not None
        return state

    async def source_state(self, cve: _Cve) -> _SourceState | None:
        """The committed latest `_SOURCE` state, read from the probe."""
        row = (
            await self.probe.execute(
                select(
                    CVESource.status, CVESource.fetched_at, CVESource.first_failed_at
                ).where(CVESource.cve_id == cve.id, CVESource.source == _SOURCE.value)
            )
        ).one_or_none()
        await self.probe.rollback()
        return None if row is None else _SourceState(*row)

    async def cleanup(self) -> None:
        for session in self.owners:
            await session.rollback()
        await self.probe.rollback()
        await self.setup.rollback()
        await self.setup.execute(delete(Ticket).where(Ticket.id.in_(self.ticket_ids)))
        await self.setup.execute(delete(CVE).where(CVE.id.in_(self.cve_ids)))
        await self.setup.commit()


@pytest.fixture
async def world(db_session_factory: SessionFactory) -> AsyncIterator[_World]:
    committed = _World(
        db_session_factory, await db_session_factory(), await db_session_factory()
    )
    try:
        yield committed
    finally:
        await committed.cleanup()


# ---------------------------------------------------------------------------
# Substitutes and spies
# ---------------------------------------------------------------------------


@dataclass
class _Trace:
    """Order-recording substitutes for the broker call and the drain.

    `events` records commits, metric helpers, drains, and publications in
    the order they happen; `calls` records every publication with its
    options. `errors` maps `(task_name, ticket_id)` — or `(task_name,
    None)` for any Ticket — to the exception the publication raises.
    """

    events: list[str] = field(default_factory=list)
    calls: list[dict[str, Any]] = field(default_factory=list)
    errors: dict[tuple[str, str | None], BaseException] = field(default_factory=dict)
    on_publish: Callable[[dict[str, Any]], None] | None = None

    def fail(
        self, task_name: str, error: BaseException, *, ticket_id: str | None = None
    ) -> None:
        self.errors[(task_name, ticket_id)] = error

    async def publish(self, task_name: str, **options: Any) -> None:
        call = {"task_name": task_name, **options}
        self.calls.append(call)
        self.events.append(f"publish:{task_name}")
        if self.on_publish is not None:
            self.on_publish(call)
        ticket_id = options["kwargs"].get("ticket_id")
        for key in ((task_name, ticket_id), (task_name, None)):
            if key in self.errors:
                raise self.errors[key]

    def published(self, task_name: str) -> list[Any]:
        return [call["kwargs"] for call in self.calls if call["task_name"] == task_name]

    def watch_commit(
        self,
        monkeypatch: pytest.MonkeyPatch,
        session: AsyncSession,
        *,
        error: BaseException | None = None,
        after_real_commit: bool = False,
    ) -> None:
        """Record each commit; optionally raise `error` instead of the real
        commit (definite failure) or after it (ambiguous outcome)."""
        real_commit = session.commit

        async def commit() -> None:
            self.events.append("commit")
            if error is not None and not after_real_commit:
                raise error
            await real_commit()
            if error is not None:
                raise error

        monkeypatch.setattr(session, "commit", commit)

    def watch_metrics(
        self, monkeypatch: pytest.MonkeyPatch, fetcher: BaseCVEFetcher
    ) -> None:
        for helper in (
            "record_succeeded",
            "record_created",
            "record_updated",
            "record_failed",
        ):
            real: Callable[[int], None] = getattr(fetcher, helper)

            def spy(
                count: int = 1,
                *,
                _real: Callable[[int], None] = real,
                _helper: str = helper,
            ) -> None:
                self.events.append(_helper)
                _real(count)

            monkeypatch.setattr(fetcher, helper, spy)


@pytest.fixture
def trace(monkeypatch: pytest.MonkeyPatch) -> _Trace:
    recorder = _Trace()
    monkeypatch.setattr(task_publication, "publish_task", recorder.publish)
    real_drain = ticket_convergence_publication.drain_ticket_convergence

    async def drain(session: AsyncSession) -> None:
        recorder.events.append("drain")
        await real_drain(session)

    monkeypatch.setattr(
        ticket_convergence_publication, "drain_ticket_convergence", drain
    )
    return recorder


@dataclass
class _StatusSessions:
    """Counting substitute for `base_cve_fetcher.async_session_factory`.

    `open_error` makes opening fail; `fault` patches each opened session.
    """

    factory: async_sessionmaker[AsyncSession]
    opened: int = 0
    open_error: BaseException | None = None
    fault: Callable[[AsyncSession], None] | None = None

    def __call__(self) -> AsyncSession:
        self.opened += 1
        if self.open_error is not None:
            raise self.open_error
        session = self.factory()
        if self.fault is not None:
            self.fault(session)
        return session


@pytest.fixture(autouse=True)
def _no_production_status_session(monkeypatch: pytest.MonkeyPatch) -> None:
    """No test reaches the production engine through an isolated status
    write; tests that exercise one request `status_sessions`."""

    def forbidden() -> AsyncSession:
        raise AssertionError("isolated status session opened without a test engine")

    monkeypatch.setattr(base_cve_fetcher_module, "async_session_factory", forbidden)


@pytest.fixture
def status_sessions(
    real_session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> _StatusSessions:
    sessions = _StatusSessions(real_session_factory)
    monkeypatch.setattr(base_cve_fetcher_module, "async_session_factory", sessions)
    return sessions


@pytest.fixture
def fetcher(isolated_fetcher_registries: None) -> _ScriptedCVEFetcher:
    """A fresh instance: no `run()`, so no automatic periodic context."""
    return _define_fetcher()()


class _RunOutcome(NamedTuple):
    status: str
    succeeded: int
    created: int
    updated: int
    failed: int


@dataclass
class _PeriodicRuns:
    """Committed `FetcherConfig` + `running` `FetcherRun` pairs, as the atomic
    run acquisition would leave them before `run()`; deleted at teardown."""

    factory: async_sessionmaker[AsyncSession]
    names: list[str] = field(default_factory=list)

    async def create(self) -> tuple[_ScriptedCVEFetcher, uuid.UUID]:
        name = f"test_cve_finalization_{uuid.uuid4().hex[:12]}"
        async with self.factory() as session:
            session.add(
                FetcherConfig(
                    fetcher_name=name,
                    enabled=True,
                    run_timeout=3600,
                    request_delay=0,
                    custom_settings={},
                )
            )
            await session.flush()
            run = FetcherRun(
                fetcher_name=name,
                started_at=datetime.now(UTC),
                status="running",
                triggered_by="schedule",
            )
            session.add(run)
            await session.commit()
            run_id = run.id
        self.names.append(name)
        return _define_fetcher(name)(), run_id

    async def outcome(self, run_id: uuid.UUID) -> _RunOutcome:
        async with self.factory() as session:
            row = (
                await session.execute(
                    select(
                        FetcherRun.status,
                        FetcherRun.items_succeeded,
                        FetcherRun.items_created,
                        FetcherRun.items_updated,
                        FetcherRun.items_failed,
                    ).where(FetcherRun.id == run_id)
                )
            ).one()
        return _RunOutcome(*row)

    async def cleanup(self) -> None:
        if not self.names:
            return
        async with self.factory() as session:
            await session.execute(
                delete(FetcherRun).where(FetcherRun.fetcher_name.in_(self.names))
            )
            await session.execute(
                delete(FetcherConfig).where(FetcherConfig.fetcher_name.in_(self.names))
            )
            await session.commit()


@pytest.fixture
async def periodic_runs(
    real_session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
    isolated_fetcher_registries: None,
) -> AsyncIterator[_PeriodicRuns]:
    monkeypatch.setattr(
        base_fetcher_module, "async_session_factory", real_session_factory
    )
    runs = _PeriodicRuns(real_session_factory)
    try:
        yield runs
    finally:
        await runs.cleanup()


# ---------------------------------------------------------------------------
# Per-CVE transaction helpers
# ---------------------------------------------------------------------------


async def _per_cve_writes(
    session: AsyncSession, cve: _Cve, *, register: uuid.UUID | None = None
) -> None:
    """One per-CVE transaction's database write (a `success` source status)
    and, optionally, a real Ticket convergence registration; then flush."""
    await cve_service.record_source_status(
        session, cve.id, _SOURCE, CVESourceFetchStatus.SUCCESS
    )
    if register is not None:
        register_ticket_convergence(session, register)
    await session.flush()


def _succeeds(
    cve: _Cve,
    action: UpsertAction,
    *,
    post_ingest: PostIngestTasks | None = None,
    register: uuid.UUID | None = None,
) -> Step:
    async def step(session: AsyncSession) -> CVEFetchResult:
        await _per_cve_writes(session, cve, register=register)
        return CVEFetchResult(action=action, post_ingest=post_ingest)

    return step


def _raises(
    cve: _Cve, error: BaseException, *, register: uuid.UUID | None = None
) -> Step:
    """A step that writes (and optionally registers), then raises."""

    async def step(session: AsyncSession) -> CVEFetchResult:
        await _per_cve_writes(session, cve, register=register)
        raise error

    return step


def _handoff(ticket_id: uuid.UUID) -> PostIngestTasks:
    return PostIngestTasks(
        ticket_id=str(ticket_id),
        cpe_matches=[
            {"criteria": _CPE, "vulnerable": True, "match_criteria_id": _MATCH_ID},
            {"criteria": _OTHER_CPE, "vulnerable": False, "match_criteria_id": None},
        ],
        affected_cpes=[_CPE, _OTHER_CPE],
        vendor_products=[
            ["example_vendor", "example_product"],
            ["example_vendor", "other_product"],
        ],
        resolved_packages=[_PACKAGE, "other-example-package"],
    )


def _assert_json_primitives(value: object) -> None:
    """Every node is a plain list/str-keyed dict or a JSON scalar; no
    dataclass instance occurs anywhere."""
    assert not dataclasses.is_dataclass(value)
    if type(value) is dict:
        for key, item in value.items():
            assert type(key) is str
            _assert_json_primitives(item)
    elif type(value) is list:
        for item in value:
            _assert_json_primitives(item)
    else:
        assert value is None or type(value) in (str, bool, int, float), value


def _assert_sanitized(logs: list[LogEntry]) -> None:
    """No exception text, payload, external data, or traceback is logged."""
    rendered = repr(logs)
    for forbidden in (_SECRET, _PACKAGE, _CPE, _OTHER_CPE, "Traceback"):
        assert forbidden not in rendered
    assert all("exc_info" not in entry for entry in logs)


def _events(logs: list[LogEntry], event: str) -> list[LogEntry]:
    return [entry for entry in logs if entry["event"] == event]


# ---------------------------------------------------------------------------
# One-shot token
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestOneShotFinalization:
    async def test_second_finalization_raises_before_commit_publication_or_metric(
        self,
        world: _World,
        trace: _Trace,
        fetcher: _ScriptedCVEFetcher,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        cve, later = await world.cve(), await world.cve()
        ticket_id = await world.ticket(cve)
        owner = await world.owner()
        fetcher._periodic_context = True
        trace.watch_commit(monkeypatch, owner)
        trace.watch_metrics(monkeypatch, fetcher)
        result = CVEFetchResult(
            action=UpsertAction.CREATED, post_ingest=_handoff(ticket_id)
        )
        await _per_cve_writes(owner, cve, register=ticket_id)
        await fetcher.commit_and_dispatch(owner, result)
        assert len(trace.calls) == 2
        trace.events.clear()
        # A later transaction with its own write and registration is open.
        await _per_cve_writes(owner, later, register=ticket_id)

        with pytest.raises(RuntimeError, match="already been finalized"):
            await fetcher.commit_and_dispatch(owner, result)

        assert trace.events == []
        assert len(trace.calls) == 2
        assert _counters(fetcher) == (1, 1, 0, 0)
        assert owner.in_transaction()
        assert await world.source_state(later) is None

    async def test_consumption_persists_after_commit_failure(
        self,
        world: _World,
        trace: _Trace,
        fetcher: _ScriptedCVEFetcher,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        cve = await world.cve()
        owner = await world.owner()
        trace.watch_commit(monkeypatch, owner, error=_CommitFailureError())
        result = CVEFetchResult(action=UpsertAction.UPDATED, post_ingest=None)
        await _per_cve_writes(owner, cve)
        with pytest.raises(_CommitFailureError):
            await fetcher.commit_and_dispatch(owner, result)
        await owner.rollback()

        with pytest.raises(RuntimeError, match="already been finalized"):
            await fetcher.commit_and_dispatch(owner, result)

        assert result._consumed is True
        assert trace.events == ["commit"]
        assert await world.source_state(cve) is None


# ---------------------------------------------------------------------------
# Finalization order, metrics, and the convergence drain
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestFinalizationOrder:
    async def test_commit_then_metrics_then_convergence_then_handoff(
        self,
        world: _World,
        trace: _Trace,
        fetcher: _ScriptedCVEFetcher,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        cve = await world.cve()
        ticket_id = await world.ticket(cve)
        owner = await world.owner()
        fetcher._periodic_context = True
        trace.watch_commit(monkeypatch, owner)
        trace.watch_metrics(monkeypatch, fetcher)
        in_transaction: list[bool] = []
        trace.on_publish = lambda _call: in_transaction.append(owner.in_transaction())
        await _per_cve_writes(owner, cve, register=ticket_id)

        await fetcher.commit_and_dispatch(
            owner,
            CVEFetchResult(
                action=UpsertAction.CREATED, post_ingest=_handoff(ticket_id)
            ),
        )

        assert trace.events == [
            "commit",
            "record_created",
            "record_succeeded",
            "drain",
            f"publish:{_CONVERGE}",
            f"publish:{_RESOLVE}",
        ]
        convergence = trace.calls[0]
        assert convergence["kwargs"] == {"ticket_id": str(ticket_id)}
        assert isinstance(convergence["task_id"], str)
        assert trace.published(_RESOLVE)[0]["ticket_id"] == str(ticket_id)
        # The commit precedes every publication; none performs database work.
        assert in_transaction == [False, False]
        assert _counters(fetcher) == (1, 1, 0, 0)
        state = await world.source_state(cve)
        assert state is not None
        assert state.status == CVESourceFetchStatus.SUCCESS

    @pytest.mark.parametrize(
        ("action", "metric_events", "counters"),
        [
            pytest.param(
                UpsertAction.CREATED,
                ["record_created", "record_succeeded"],
                (1, 1, 0, 0),
                id="created",
            ),
            pytest.param(
                UpsertAction.UPDATED,
                ["record_updated", "record_succeeded"],
                (1, 0, 1, 0),
                id="updated",
            ),
            pytest.param(
                UpsertAction.UNCHANGED,
                ["record_succeeded"],
                (1, 0, 0, 0),
                id="unchanged",
            ),
        ],
    )
    async def test_periodic_context_maps_action_after_commit(
        self,
        world: _World,
        trace: _Trace,
        fetcher: _ScriptedCVEFetcher,
        monkeypatch: pytest.MonkeyPatch,
        action: UpsertAction,
        metric_events: list[str],
        counters: tuple[int, int, int, int],
    ) -> None:
        cve = await world.cve()
        owner = await world.owner()
        fetcher._periodic_context = True
        trace.watch_commit(monkeypatch, owner)
        trace.watch_metrics(monkeypatch, fetcher)
        await _per_cve_writes(owner, cve)

        await fetcher.commit_and_dispatch(
            owner, CVEFetchResult(action=action, post_ingest=None)
        )

        assert trace.events == ["commit", *metric_events, "drain"]
        assert _counters(fetcher) == counters

    @pytest.mark.parametrize("action", list(UpsertAction))
    async def test_no_metric_without_periodic_context(
        self,
        world: _World,
        trace: _Trace,
        fetcher: _ScriptedCVEFetcher,
        monkeypatch: pytest.MonkeyPatch,
        action: UpsertAction,
    ) -> None:
        cve = await world.cve()
        owner = await world.owner()
        trace.watch_commit(monkeypatch, owner)
        trace.watch_metrics(monkeypatch, fetcher)
        await _per_cve_writes(owner, cve)

        await fetcher.commit_and_dispatch(
            owner, CVEFetchResult(action=action, post_ingest=None)
        )

        assert fetcher._periodic_context is False
        assert trace.events == ["commit", "drain"]
        assert _counters(fetcher) == (0, 0, 0, 0)

    async def test_convergence_broker_failure_still_attempts_handoff(
        self,
        world: _World,
        trace: _Trace,
        fetcher: _ScriptedCVEFetcher,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        cve = await world.cve()
        ticket_id = await world.ticket(cve)
        owner = await world.owner()
        fetcher._periodic_context = True
        trace.watch_commit(monkeypatch, owner)
        trace.fail(_CONVERGE, OperationalError(_SECRET))
        await _per_cve_writes(owner, cve, register=ticket_id)

        with capture_logs() as logs:
            await fetcher.commit_and_dispatch(
                owner,
                CVEFetchResult(
                    action=UpsertAction.UPDATED, post_ingest=_handoff(ticket_id)
                ),
            )

        assert trace.events == [
            "commit",
            "drain",
            f"publish:{_CONVERGE}",
            f"publish:{_RESOLVE}",
        ]
        # Exactly the one Ticket-owned event; the finalizer adds none.
        assert logs == [
            {
                "event": PUBLICATION_FAILED_EVENT,
                "log_level": "error",
                "ticket_id": str(ticket_id),
                "cause": "broker_operational_error",
            }
        ]
        _assert_sanitized(logs)
        assert _counters(fetcher) == (1, 0, 1, 0)

    async def test_null_handoff_commits_and_drains_without_package_task(
        self,
        world: _World,
        trace: _Trace,
        fetcher: _ScriptedCVEFetcher,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        cve = await world.cve()
        ticket_id = await world.ticket(cve)
        owner = await world.owner()
        trace.watch_commit(monkeypatch, owner)
        await _per_cve_writes(owner, cve, register=ticket_id)

        await fetcher.commit_and_dispatch(
            owner, CVEFetchResult(action=UpsertAction.UNCHANGED, post_ingest=None)
        )

        assert trace.events == ["commit", "drain", f"publish:{_CONVERGE}"]
        assert trace.published(_CONVERGE) == [{"ticket_id": str(ticket_id)}]
        assert trace.published(_RESOLVE) == []
        state = await world.source_state(cve)
        assert state is not None
        assert state.status == CVESourceFetchStatus.SUCCESS


# ---------------------------------------------------------------------------
# Package handoff payload
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestHandoffPayload:
    async def test_handoff_is_five_detached_primitive_arguments(
        self, world: _World, trace: _Trace, fetcher: _ScriptedCVEFetcher
    ) -> None:
        cve = await world.cve()
        ticket_id = await world.ticket(cve)
        owner = await world.owner()
        handoff = _handoff(ticket_id)
        await _per_cve_writes(owner, cve)

        await fetcher.commit_and_dispatch(
            owner, CVEFetchResult(action=UpsertAction.CREATED, post_ingest=handoff)
        )

        assert [call["task_name"] for call in trace.calls] == [_RESOLVE]
        assert _RESOLVE == "resolve_ticket_packages"
        call = trace.calls[0]
        # No queue and no task ID: the default route.
        assert set(call) == {"task_name", "kwargs"}
        kwargs = call["kwargs"]
        assert type(kwargs) is dict
        assert list(kwargs) == [
            "ticket_id",
            "cpe_matches",
            "affected_cpes",
            "vendor_products",
            "resolved_packages",
        ]
        assert kwargs == dataclasses.asdict(handoff)
        _assert_json_primitives(kwargs)
        assert json.loads(json.dumps(kwargs)) == kwargs
        # Fresh containers, never the dataclass's own lists or objects.
        for name in ("cpe_matches", "affected_cpes", "vendor_products"):
            assert kwargs[name] is not getattr(handoff, name)
        assert kwargs["resolved_packages"] is not handoff.resolved_packages
        for sent, source in [
            *zip(kwargs["cpe_matches"], handoff.cpe_matches, strict=True),
            *zip(kwargs["vendor_products"], handoff.vendor_products, strict=True),
        ]:
            assert sent is not source


# ---------------------------------------------------------------------------
# Commit failure and transaction-local effects
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestCommitFailure:
    @pytest.mark.parametrize(
        "ambiguous", [False, True], ids=["definite-failure", "ambiguous-outcome"]
    )
    async def test_commit_exception_propagates_before_any_effect(
        self,
        world: _World,
        trace: _Trace,
        fetcher: _ScriptedCVEFetcher,
        status_sessions: _StatusSessions,
        monkeypatch: pytest.MonkeyPatch,
        ambiguous: bool,
    ) -> None:
        cve = await world.cve()
        ticket_id = await world.ticket(cve)
        owner = await world.owner()
        fetcher._periodic_context = True
        failure = _CommitFailureError()
        trace.watch_commit(
            monkeypatch, owner, error=failure, after_real_commit=ambiguous
        )
        trace.watch_metrics(monkeypatch, fetcher)
        await _per_cve_writes(owner, cve, register=ticket_id)

        with capture_logs() as logs, pytest.raises(_CommitFailureError) as raised:
            await fetcher.commit_and_dispatch(
                owner,
                CVEFetchResult(
                    action=UpsertAction.CREATED, post_ingest=_handoff(ticket_id)
                ),
            )

        assert raised.value is failure
        # No metric, drain, convergence, or package publication.
        assert trace.events == ["commit"]
        assert trace.calls == []
        assert _counters(fetcher) == (0, 0, 0, 0)
        # No isolated source status and no per-item log.
        assert status_sessions.opened == 0
        assert logs == []
        if ambiguous:
            # The simulated ambiguous outcome did commit; still nothing is
            # published or recorded.
            state = await world.source_state(cve)
            assert state is not None
            assert state.status == CVESourceFetchStatus.SUCCESS
        else:
            await owner.rollback()
            assert await world.source_state(cve) is None


@pytest.mark.integration
class TestTransactionLocalEffects:
    @pytest.mark.parametrize("discard", ["rollback", "close"])
    async def test_discarded_registrations_are_never_published(
        self,
        world: _World,
        trace: _Trace,
        fetcher: _ScriptedCVEFetcher,
        discard: str,
    ) -> None:
        """A caller rollback, or the session close of a pre-commit
        cancellation, clears the registrations; a later finalization on the
        same session publishes only its own effect."""
        first, second = await world.cve(), await world.cve()
        first_ticket = await world.ticket(first)
        second_ticket = await world.ticket(second)
        owner = await world.owner()
        await _per_cve_writes(owner, first, register=first_ticket)
        if discard == "rollback":
            await owner.rollback()
        else:
            await owner.close()
        await _per_cve_writes(owner, second, register=second_ticket)

        await fetcher.commit_and_dispatch(
            owner, CVEFetchResult(action=UpsertAction.UNCHANGED, post_ingest=None)
        )

        assert trace.published(_CONVERGE) == [{"ticket_id": str(second_ticket)}]
        assert await world.source_state(first) is None

    async def test_reused_session_never_replays_an_attempted_effect(
        self, world: _World, trace: _Trace, fetcher: _ScriptedCVEFetcher
    ) -> None:
        first, second = await world.cve(), await world.cve()
        first_ticket = await world.ticket(first)
        second_ticket = await world.ticket(second)
        trace.fail(_CONVERGE, OperationalError(_SECRET), ticket_id=str(first_ticket))
        owner = await world.owner()

        with capture_logs() as logs:
            await _per_cve_writes(owner, first, register=first_ticket)
            await fetcher.commit_and_dispatch(
                owner, CVEFetchResult(action=UpsertAction.UNCHANGED, post_ingest=None)
            )
            await _per_cve_writes(owner, second, register=second_ticket)
            await fetcher.commit_and_dispatch(
                owner, CVEFetchResult(action=UpsertAction.UNCHANGED, post_ingest=None)
            )

        assert trace.published(_CONVERGE) == [
            {"ticket_id": str(first_ticket)},
            {"ticket_id": str(second_ticket)},
        ]
        assert [entry["event"] for entry in logs] == [PUBLICATION_FAILED_EVENT]
        assert logs[0]["ticket_id"] == str(first_ticket)
        _assert_sanitized(logs)


# ---------------------------------------------------------------------------
# Package handoff publication failures
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestHandoffPublicationFailure:
    async def test_broker_failure_logs_one_bounded_error_and_returns(
        self,
        world: _World,
        trace: _Trace,
        fetcher: _ScriptedCVEFetcher,
        status_sessions: _StatusSessions,
    ) -> None:
        cve = await world.cve()
        ticket_id = await world.ticket(cve)
        owner = await world.owner()
        fetcher._periodic_context = True
        trace.fail(_RESOLVE, OperationalError(_SECRET))
        await _per_cve_writes(owner, cve)
        run_id = str(uuid.uuid4())

        bind_contextvars(fetcher_run_id=run_id)
        try:
            with capture_logs(processors=[merge_contextvars]) as logs:
                await fetcher.commit_and_dispatch(
                    owner,
                    CVEFetchResult(
                        action=UpsertAction.CREATED, post_ingest=_handoff(ticket_id)
                    ),
                )
        finally:
            unbind_contextvars("fetcher_run_id")

        assert logs == [
            {
                "event": HANDOFF_PUBLICATION_FAILED_EVENT,
                "log_level": "error",
                "ticket_id": str(ticket_id),
                "fetcher_name": fetcher.name,
                "cause": "OperationalError",
                "fetcher_run_id": run_id,
            }
        ]
        _assert_sanitized(logs)
        assert len(trace.published(_RESOLVE)) == 1
        # Committed success and effect are kept; no failure is recorded.
        assert _counters(fetcher) == (1, 1, 0, 0)
        assert status_sessions.opened == 0
        state = await world.source_state(cve)
        assert state is not None
        assert state.status == CVESourceFetchStatus.SUCCESS

    @pytest.mark.parametrize(
        "error",
        [
            EncodeError(_SECRET),
            TypeError(_SECRET),
            asyncio.CancelledError(),
            SoftTimeLimitExceeded(),
            MemoryError(),
        ],
        ids=lambda error: type(error).__name__,
    )
    async def test_non_operational_handoff_error_propagates_unchanged(
        self,
        world: _World,
        trace: _Trace,
        fetcher: _ScriptedCVEFetcher,
        status_sessions: _StatusSessions,
        error: BaseException,
    ) -> None:
        cve = await world.cve()
        ticket_id = await world.ticket(cve)
        owner = await world.owner()
        fetcher._periodic_context = True
        trace.fail(_RESOLVE, error)
        await _per_cve_writes(owner, cve)

        with capture_logs() as logs, pytest.raises(type(error)) as raised:
            await fetcher.commit_and_dispatch(
                owner,
                CVEFetchResult(
                    action=UpsertAction.CREATED, post_ingest=_handoff(ticket_id)
                ),
            )

        assert raised.value is error
        assert logs == []
        assert _counters(fetcher) == (1, 1, 0, 0)
        assert status_sessions.opened == 0
        state = await world.source_state(cve)
        assert state is not None
        assert state.status == CVESourceFetchStatus.SUCCESS

    @pytest.mark.parametrize(
        "error",
        [RuntimeError(_SECRET), EncodeError(_SECRET), asyncio.CancelledError()],
        ids=lambda error: type(error).__name__,
    )
    async def test_non_operational_drain_error_propagates_without_handoff(
        self,
        world: _World,
        trace: _Trace,
        fetcher: _ScriptedCVEFetcher,
        status_sessions: _StatusSessions,
        error: BaseException,
    ) -> None:
        cve = await world.cve()
        ticket_id = await world.ticket(cve)
        owner = await world.owner()
        fetcher._periodic_context = True
        trace.fail(_CONVERGE, error)
        await _per_cve_writes(owner, cve, register=ticket_id)

        with capture_logs() as logs, pytest.raises(type(error)) as raised:
            await fetcher.commit_and_dispatch(
                owner,
                CVEFetchResult(
                    action=UpsertAction.UPDATED, post_ingest=_handoff(ticket_id)
                ),
            )

        assert raised.value is error
        assert [call["task_name"] for call in trace.calls] == [_CONVERGE]
        assert logs == []
        assert _counters(fetcher) == (1, 0, 1, 0)
        assert status_sessions.opened == 0


# ---------------------------------------------------------------------------
# Periodic metrics through BaseFetcher.run()
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestPeriodicMetricsThroughRun:
    @pytest.mark.parametrize(
        ("action", "expected"),
        [
            pytest.param(
                UpsertAction.CREATED,
                _RunOutcome("success", 1, 1, 0, 0),
                id="created",
            ),
            pytest.param(
                UpsertAction.UPDATED,
                _RunOutcome("success", 1, 0, 1, 0),
                id="updated",
            ),
            pytest.param(
                UpsertAction.UNCHANGED,
                _RunOutcome("success", 1, 0, 0, 0),
                id="unchanged",
            ),
        ],
    )
    async def test_successful_unit_maps_action_once(
        self,
        world: _World,
        trace: _Trace,
        periodic_runs: _PeriodicRuns,
        status_sessions: _StatusSessions,
        action: UpsertAction,
        expected: _RunOutcome,
    ) -> None:
        fetcher, run_id = await periodic_runs.create()
        cve = await world.cve()
        fetcher.plan[cve.cve_id] = _succeeds(cve, action)
        assert fetcher._periodic_context is False

        await fetcher.run(run_id=run_id, config=_CONFIG)

        assert await periodic_runs.outcome(run_id) == expected
        assert fetcher.contexts == [True]
        assert fetcher._periodic_context is False
        assert status_sessions.opened == 0
        state = await world.source_state(cve)
        assert state is not None
        assert state.status == CVESourceFetchStatus.SUCCESS

    async def test_missing_is_terminal_success_without_effect(
        self,
        world: _World,
        trace: _Trace,
        periodic_runs: _PeriodicRuns,
        status_sessions: _StatusSessions,
    ) -> None:
        fetcher, run_id = await periodic_runs.create()
        cve = await world.cve()
        ticket_id = await world.ticket(cve)
        fetcher.plan[cve.cve_id] = _raises(cve, CVENotInSource(), register=ticket_id)

        await fetcher.run(run_id=run_id, config=_CONFIG)

        assert await periodic_runs.outcome(run_id) == _RunOutcome("success", 1, 0, 0, 0)
        assert status_sessions.opened == 1
        state = await world.source_state(cve)
        assert state is not None
        assert state.status == CVESourceFetchStatus.MISSING
        assert trace.calls == []

    async def test_pre_finalization_failure_records_one_failure(
        self,
        world: _World,
        trace: _Trace,
        periodic_runs: _PeriodicRuns,
        status_sessions: _StatusSessions,
    ) -> None:
        fetcher, run_id = await periodic_runs.create()
        cve = await world.cve()
        ticket_id = await world.ticket(cve)
        fetcher.plan[cve.cve_id] = _raises(
            cve, ValueError("example parse failure"), register=ticket_id
        )

        await fetcher.run(run_id=run_id, config=_CONFIG)

        assert await periodic_runs.outcome(run_id) == _RunOutcome("failure", 0, 0, 0, 1)
        state = await world.source_state(cve)
        assert state is not None
        assert state.status == CVESourceFetchStatus.FAILURE
        assert state.first_failed_at is not None
        # The rolled back unit publishes nothing.
        assert trace.events == []
        assert trace.calls == []

    async def test_unchanged_unit_plus_failed_unit_is_partial(
        self,
        world: _World,
        trace: _Trace,
        periodic_runs: _PeriodicRuns,
        status_sessions: _StatusSessions,
    ) -> None:
        fetcher, run_id = await periodic_runs.create()
        unchanged, failed = await world.cve(), await world.cve()
        fetcher.plan[unchanged.cve_id] = _succeeds(unchanged, UpsertAction.UNCHANGED)
        fetcher.plan[failed.cve_id] = _raises(failed, ValueError("example failure"))

        await fetcher.run(run_id=run_id, config=_CONFIG)

        assert await periodic_runs.outcome(run_id) == _RunOutcome("partial", 1, 0, 0, 1)

    async def test_commit_failure_terminates_run_without_metrics_for_that_cve(
        self,
        world: _World,
        trace: _Trace,
        periodic_runs: _PeriodicRuns,
        status_sessions: _StatusSessions,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        fetcher, run_id = await periodic_runs.create()
        committed, failing = await world.cve(), await world.cve()
        failure = _CommitFailureError()

        async def commit_fails(session: AsyncSession) -> CVEFetchResult:
            await _per_cve_writes(session, failing)
            trace.watch_commit(monkeypatch, session, error=failure)
            return CVEFetchResult(action=UpsertAction.CREATED, post_ingest=None)

        fetcher.plan[committed.cve_id] = _succeeds(committed, UpsertAction.CREATED)
        fetcher.plan[failing.cve_id] = commit_fails

        with pytest.raises(_CommitFailureError) as raised:
            await fetcher.run(run_id=run_id, config=_CONFIG)

        assert raised.value is failure
        # Only the first, committed unit is counted.
        assert await periodic_runs.outcome(run_id) == _RunOutcome("failure", 1, 1, 0, 0)
        assert status_sessions.opened == 0
        assert await world.source_state(failing) is None
        assert fetcher._periodic_context is False

    async def test_post_commit_error_fails_run_and_keeps_success_and_effect(
        self,
        world: _World,
        trace: _Trace,
        periodic_runs: _PeriodicRuns,
        status_sessions: _StatusSessions,
    ) -> None:
        fetcher, run_id = await periodic_runs.create()
        cve = await world.cve()
        ticket_id = await world.ticket(cve)
        error = TypeError(_SECRET)
        trace.fail(_RESOLVE, error)
        fetcher.plan[cve.cve_id] = _succeeds(
            cve, UpsertAction.CREATED, post_ingest=_handoff(ticket_id)
        )

        with capture_logs() as logs, pytest.raises(TypeError) as raised:
            await fetcher.run(run_id=run_id, config=_CONFIG)

        assert raised.value is error
        assert await periodic_runs.outcome(run_id) == _RunOutcome("failure", 1, 1, 0, 0)
        assert _events(logs, HANDOFF_PUBLICATION_FAILED_EVENT) == []
        # No rollback reclassification and no isolated failure status.
        assert status_sessions.opened == 0
        state = await world.source_state(cve)
        assert state is not None
        assert state.status == CVESourceFetchStatus.SUCCESS
        assert fetcher._periodic_context is False

    async def test_handoff_broker_failure_keeps_run_success(
        self,
        world: _World,
        trace: _Trace,
        periodic_runs: _PeriodicRuns,
        status_sessions: _StatusSessions,
    ) -> None:
        fetcher, run_id = await periodic_runs.create()
        cve = await world.cve()
        ticket_id = await world.ticket(cve)
        trace.fail(_RESOLVE, OperationalError(_SECRET))
        fetcher.plan[cve.cve_id] = _succeeds(
            cve, UpsertAction.CREATED, post_ingest=_handoff(ticket_id)
        )

        with capture_logs(processors=[merge_contextvars]) as logs:
            await fetcher.run(run_id=run_id, config=_CONFIG)

        assert await periodic_runs.outcome(run_id) == _RunOutcome("success", 1, 1, 0, 0)
        assert _events(logs, HANDOFF_PUBLICATION_FAILED_EVENT) == [
            {
                "event": HANDOFF_PUBLICATION_FAILED_EVENT,
                "log_level": "error",
                "ticket_id": str(ticket_id),
                "fetcher_name": fetcher.name,
                "cause": "OperationalError",
                "fetcher_run_id": str(run_id),
            }
        ]
        assert _SECRET not in repr(logs)

    async def test_periodic_context_is_cleared_after_escaping_control_signal(
        self,
        world: _World,
        trace: _Trace,
        periodic_runs: _PeriodicRuns,
        status_sessions: _StatusSessions,
    ) -> None:
        fetcher, run_id = await periodic_runs.create()
        cve = await world.cve()
        fetcher.plan[cve.cve_id] = _raises(cve, asyncio.CancelledError())
        assert fetcher._periodic_context is False

        with pytest.raises(asyncio.CancelledError):
            await fetcher.run(run_id=run_id, config=_CONFIG)

        assert fetcher.contexts == [True]
        assert fetcher._periodic_context is False
        # A whole-run signal bypasses isolated status handling.
        assert status_sessions.opened == 0
        assert await world.source_state(cve) is None

    async def test_on_demand_finalization_records_no_metric(
        self,
        world: _World,
        trace: _Trace,
        fetcher: _ScriptedCVEFetcher,
    ) -> None:
        cve = await world.cve()
        ticket_id = await world.ticket(cve)
        owner = await world.owner()
        fetcher.plan[cve.cve_id] = _succeeds(
            cve,
            UpsertAction.CREATED,
            post_ingest=_handoff(ticket_id),
            register=ticket_id,
        )

        result = await fetcher.fetch_single(cve.cve_id, owner)
        await owner.flush()
        await fetcher.commit_and_dispatch(owner, result)

        assert fetcher.contexts == [False]
        assert _counters(fetcher) == (0, 0, 0, 0)
        assert [call["task_name"] for call in trace.calls] == [_CONVERGE, _RESOLVE]
        state = await world.source_state(cve)
        assert state is not None
        assert state.status == CVESourceFetchStatus.SUCCESS


# ---------------------------------------------------------------------------
# Isolated status commit
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestIsolatedStatusValidation:
    @pytest.mark.parametrize(
        "status",
        ["failure", "missing", CVESourceFetchStatus.SUCCESS],
        ids=["raw-failure-string", "raw-missing-string", "success-member"],
    )
    async def test_rejects_anything_but_typed_failure_or_missing(
        self,
        fetcher: _ScriptedCVEFetcher,
        monkeypatch: pytest.MonkeyPatch,
        status: object,
    ) -> None:
        opened: list[None] = []

        def spy() -> AsyncSession:
            opened.append(None)
            raise AssertionError("no database work expected")

        monkeypatch.setattr(base_cve_fetcher_module, "async_session_factory", spy)

        with pytest.raises(ValueError, match="FAILURE or"):
            await fetcher._isolated_status_commit(
                "CVE-2099-0001", cast(CVESourceFetchStatus, status)
            )

        assert opened == []


def _inject_status_failure(
    point: str,
    error: BaseException,
    sessions: _StatusSessions,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def fail(*args: Any, **kwargs: Any) -> Any:
        raise error

    if point == "session":
        sessions.open_error = error
    elif point == "lookup":
        sessions.fault = lambda session: monkeypatch.setattr(session, "scalar", fail)
    elif point == "write":
        monkeypatch.setattr(cve_service, "record_source_status", fail)
    else:
        sessions.fault = lambda session: monkeypatch.setattr(session, "commit", fail)


@pytest.mark.integration
class TestIsolatedStatusCommit:
    @pytest.mark.parametrize(
        "status", [CVESourceFetchStatus.FAILURE, CVESourceFetchStatus.MISSING]
    )
    async def test_writes_latest_status_in_an_independent_transaction(
        self,
        world: _World,
        trace: _Trace,
        fetcher: _ScriptedCVEFetcher,
        status_sessions: _StatusSessions,
        status: CVESourceFetchStatus,
    ) -> None:
        cve, other = await world.cve(), await world.cve()
        caller = await world.owner()
        # The caller's own uncommitted work stays untouched.
        await _per_cve_writes(caller, other)

        await fetcher._isolated_status_commit(cve.cve_id, status)

        assert status_sessions.opened == 1
        state = await world.source_state(cve)
        assert state is not None
        assert state.status == status
        expected_first_failed = (
            state.fetched_at if status is CVESourceFetchStatus.FAILURE else None
        )
        assert state.first_failed_at == expected_first_failed
        assert caller.in_transaction()
        assert await world.source_state(other) is None

    async def test_failure_starts_and_keeps_streak_and_missing_clears_it(
        self,
        world: _World,
        trace: _Trace,
        fetcher: _ScriptedCVEFetcher,
        status_sessions: _StatusSessions,
    ) -> None:
        cve = await world.cve()
        await world.seed_status(cve, CVESourceFetchStatus.SUCCESS)

        await fetcher._isolated_status_commit(cve.cve_id, CVESourceFetchStatus.FAILURE)
        started = await world.source_state(cve)
        await fetcher._isolated_status_commit(cve.cve_id, CVESourceFetchStatus.FAILURE)
        kept = await world.source_state(cve)
        await fetcher._isolated_status_commit(cve.cve_id, CVESourceFetchStatus.MISSING)
        cleared = await world.source_state(cve)

        assert started is not None
        assert kept is not None
        assert cleared is not None
        assert started.status == CVESourceFetchStatus.FAILURE
        assert started.first_failed_at == started.fetched_at
        assert kept.status == CVESourceFetchStatus.FAILURE
        assert kept.first_failed_at == started.first_failed_at
        assert kept.fetched_at >= started.fetched_at
        assert cleared.status == CVESourceFetchStatus.MISSING
        assert cleared.first_failed_at is None

    async def test_missing_cve_row_is_skipped_with_debug_event(
        self,
        world: _World,
        trace: _Trace,
        fetcher: _ScriptedCVEFetcher,
        status_sessions: _StatusSessions,
    ) -> None:
        absent = f"CVE-2099-{uuid.uuid4().int % 10**8:08d}"

        with capture_logs() as logs:
            await fetcher._isolated_status_commit(absent, CVESourceFetchStatus.MISSING)

        assert logs == [
            {
                "event": ISOLATED_STATUS_CVE_MISSING_EVENT,
                "log_level": "debug",
                "cve_id": absent,
                "source": _SOURCE.value,
                "status": CVESourceFetchStatus.MISSING.value,
            }
        ]
        assert status_sessions.opened == 1
        count = (
            await world.probe.execute(
                select(CVESource.id)
                .join(CVE, CVE.id == CVESource.cve_id)
                .where(CVE.cve_id == absent)
            )
        ).all()
        await world.probe.rollback()
        assert count == []

    @pytest.mark.parametrize("point", ["session", "lookup", "write", "commit"])
    async def test_ordinary_failure_is_logged_once_and_suppressed(
        self,
        world: _World,
        trace: _Trace,
        fetcher: _ScriptedCVEFetcher,
        status_sessions: _StatusSessions,
        monkeypatch: pytest.MonkeyPatch,
        point: str,
    ) -> None:
        cve = await world.cve()
        before = await world.seed_status(cve, CVESourceFetchStatus.SUCCESS)
        _inject_status_failure(
            point, RuntimeError(_SECRET), status_sessions, monkeypatch
        )

        with capture_logs() as logs:
            await fetcher._isolated_status_commit(
                cve.cve_id, CVESourceFetchStatus.FAILURE
            )

        assert logs == [
            {
                "event": ISOLATED_STATUS_WRITE_FAILED_EVENT,
                "log_level": "warning",
                "cve_id": cve.cve_id,
                "source": _SOURCE.value,
                "status": CVESourceFetchStatus.FAILURE.value,
                "fetcher_name": fetcher.name,
                "cause": "RuntimeError",
            }
        ]
        _assert_sanitized(logs)
        assert await world.source_state(cve) == before

    async def test_original_exception_survives_a_suppressed_failure(
        self,
        world: _World,
        trace: _Trace,
        fetcher: _ScriptedCVEFetcher,
        status_sessions: _StatusSessions,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        cve = await world.cve()
        _inject_status_failure(
            "write", RuntimeError(_SECRET), status_sessions, monkeypatch
        )
        original = ValueError("example pre-finalization failure")

        async def handler() -> None:
            try:
                raise original
            except ValueError:
                await fetcher._isolated_status_commit(
                    cve.cve_id, CVESourceFetchStatus.FAILURE
                )
                raise

        with (
            capture_logs() as logs,
            pytest.raises(ValueError, match="example") as raised,
        ):
            await handler()

        assert raised.value is original
        assert [entry["event"] for entry in logs] == [
            ISOLATED_STATUS_WRITE_FAILED_EVENT
        ]

    @pytest.mark.parametrize(
        "error",
        [asyncio.CancelledError(), SoftTimeLimitExceeded(), MemoryError()],
        ids=lambda error: type(error).__name__,
    )
    @pytest.mark.parametrize("point", ["lookup", "write"])
    async def test_control_signals_propagate(
        self,
        world: _World,
        trace: _Trace,
        fetcher: _ScriptedCVEFetcher,
        status_sessions: _StatusSessions,
        monkeypatch: pytest.MonkeyPatch,
        point: str,
        error: BaseException,
    ) -> None:
        cve = await world.cve()
        before = await world.seed_status(cve, CVESourceFetchStatus.SUCCESS)
        _inject_status_failure(point, error, status_sessions, monkeypatch)

        with capture_logs() as logs, pytest.raises(type(error)) as raised:
            await fetcher._isolated_status_commit(
                cve.cve_id, CVESourceFetchStatus.FAILURE
            )

        assert raised.value is error
        assert logs == []
        assert await world.source_state(cve) == before

    @pytest.mark.parametrize(
        "status", [CVESourceFetchStatus.FAILURE, CVESourceFetchStatus.MISSING]
    )
    async def test_publishes_nothing_and_records_no_metric(
        self,
        world: _World,
        trace: _Trace,
        fetcher: _ScriptedCVEFetcher,
        status_sessions: _StatusSessions,
        monkeypatch: pytest.MonkeyPatch,
        status: CVESourceFetchStatus,
    ) -> None:
        cve = await world.cve()
        fetcher._periodic_context = True
        trace.watch_metrics(monkeypatch, fetcher)

        await fetcher._isolated_status_commit(cve.cve_id, status)

        assert trace.events == []
        assert trace.calls == []
        assert _counters(fetcher) == (0, 0, 0, 0)
        state = await world.source_state(cve)
        assert state is not None
        assert state.status == status
