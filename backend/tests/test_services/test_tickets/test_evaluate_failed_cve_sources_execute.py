"""Tests for `EvaluateFailedCveSources.execute()` and its `run()` metrics
(backend/app/services/tickets/evaluate_failed_cve_sources.py).

Owning specifications:

- docs/features/platform/cve-source-failure-retry.md (Algorithm steps 1-5
  with the Note on step 1 query, Transaction constraint, and Whole-run
  signal handling; Error Handling; Metrics; Active Ticket Check;
  Interaction with Existing Mechanisms: `trigger_on_demand_fetch()`,
  `fetch_single_cve` tasks, the retry task's own `CVESource` writes, and
  FetcherRun records; Observability, Logging).
- docs/features/tickets/cve-service.md (Fetch Orchestration:
  `trigger_on_demand_fetch()` — Database-Free Publication; On-Demand
  Fetch: fetch_single_cve, disabled meanwhile).
- docs/features/platform/fetcher-infrastructure.md (`run()` lifecycle,
  Finalization, Outcome and effect accounting; `SoftTimeLimitExceeded`
  handling convention; On-Demand Queue Routing).
- docs/features/platform/logging.md (Secrets and PII Discipline).
- docs/features/platform/testing-strategy.md (On-Demand CVE Refetch, the
  `evaluate_failed_cve_sources` bullet; Fetcher Outcome and Effect
  Accounting, the `evaluate_failed_cve_sources` mapping; Concurrency
  Testing; Redis Strategy).

Every test commits real rows through a `CommittedWorld`: CVEs with their
`CVESource` rows and Tickets (deleted at teardown, the sources by `ON
DELETE CASCADE`) and the `FetcherConfig` rows of the fetchers a test
configures (deleted with any `FetcherRun` of those names). The evaluator's
module-level `async_session_factory` (the revalidation read) is a
`RecordingSessions` over `real_session_factory` that also records each
session's opening and close; the candidate read is the real
`find_failed_cve_source_candidates()` wrapped by a spy that restricts its
result to this test's CVEs, so rows committed by no other test can enter
it. Publication is the real `cve_service.trigger_on_demand_fetch()` over
the worker Redis database of `redis_client`, with
`task_publication.publish_task` replaced by `Publications`, so no broker is
reached. `run()` tests also route `base_fetcher`'s sessions to the test
database and finalize a committed `FetcherRun` under a test-only fetcher
name. Every test runs under `isolated_fetcher_registries`; it uses the
production fetch-single classes registered by `fetcher_discovery` or
test-only owners from `tests.support.cve_catch_up.define_cve_fetcher()`.
Expected values are transcribed from the specifications. All identifiers
and texts are fictional.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import (
    AsyncIterator,
    Awaitable,
    Callable,
    Iterable,
    Mapping,
    Sequence,
)
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Final

import pytest
import redis.asyncio as redis_asyncio
from celery.exceptions import OperationalError as KombuOperationalError
from celery.exceptions import SoftTimeLimitExceeded
from sqlalchemy import select, update
from sqlalchemy.exc import OperationalError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from structlog.testing import capture_logs

import app.services.base_fetcher as base_fetcher_module
from app.core.enums import CVESourceType, TicketStatus
from app.models.cve import CVE
from app.models.cve_source import CVESource
from app.models.fetcher_config import FetcherConfig
from app.models.fetcher_run import FetcherRun
from app.models.ticket import Ticket
from app.services import cve_service, task_publication
from app.services.base_cve_fetcher import BaseCVEFetcher, get_fetch_single_fetchers
from app.services.base_fetcher import FETCHER_REGISTRY, FetcherRunConfig
from app.services.cve_service import FetchDispatchResult, trigger_on_demand_fetch
from app.services.fetcher_execution import get_fetcher_enabled
from app.services.tickets import evaluate_failed_cve_sources as evaluator
from app.services.tickets.evaluate_failed_cve_sources import (
    EvaluateFailedCveSources,
    RetryCandidate,
)
from app.services.tickets.sync_cisa_kev import SyncCisaKev
from app.services.tickets.sync_kernel_cves import SyncKernelCves
from app.services.tickets.sync_mitre_cves import SyncMitreCves
from app.services.tickets.sync_redhat_cves import SyncRedhatCves
from app.tasks import cve_tasks
from tests.support.cve_catch_up import (
    FakeEngine,
    Publications,
    RecordingSessions,
    define_cve_fetcher,
    delete_fetcher_rows,
    fetcher_run_count,
    seed_fetcher_config,
    source_state,
)
from tests.support.cve_ingest import persisted_snapshot
from tests.support.fetch_single_cve import (
    FETCHER_DISABLED,
    PENDING_TTL,
    TASK,
    TOKEN_PATTERN,
    NoDatabaseAccess,
    fictional_cve_id,
    pending_key,
)
from tests.support.suse_cvss_races import CommittedWorld

SessionFactory = Callable[[], Awaitable[AsyncSession]]
Counters = tuple[int, int, int, int]
"""`(succeeded, created, updated, failed)` of one fetcher run."""

WAIT: Final = 10
"""Upper bound, in seconds, of every wait that is expected to finish."""

FAILURE: Final = "failure"
WINDOW: Final = timedelta(hours=720)

REDHAT: Final = "sync_redhat_cves"
OSV: Final = "sync_osv_advisories"
GHSA: Final = "sync_ghsa_advisories"
EPSS: Final = "sync_epss_scores"
MITRE: Final = "sync_mitre_cves"
KERNEL: Final = "sync_kernel_cves"

SKIPPED: Final = "cve_source_retry_skipped"
DISPATCHED: Final = "cve_source_retry_dispatched"
ALREADY_PENDING: Final = "cve_source_retry_already_pending"
CONFIG_MISSING: Final = "cve_source_retry_config_missing"
DISPATCH_FAILED: Final = "cve_source_retry_dispatch_failed"
SUMMARY: Final = "failed_cve_sources_evaluated"
PAIR_EVENTS: Final = frozenset(
    {SKIPPED, DISPATCHED, ALREADY_PENDING, CONFIG_MISSING, DISPATCH_FAILED}
)
SUMMARY_COUNTERS: Final = (
    "dispatched",
    "already_pending",
    "dispatch_failed",
    "config_missing",
    "skipped_no_capability",
    "skipped_no_active_ticket",
    "excluded_at_revalidation",
)
ALLOWED_KEYS: Final = frozenset(
    {
        "event",
        "log_level",
        "cve_id",
        "source",
        "reason",
        "cause",
        "fetcher_name",
        "candidates",
        *SUMMARY_COUNTERS,
    }
)

SECRET_TEXT: Final = (
    "Example-Secret-Detail alice.example@example.invalid "
    "redis://sentinel:fictional-secret@broker.example.invalid:6379/1"
)
"""Exception text that must never reach a log record."""

_WHOLE_RUN_SIGNALS = [
    pytest.param(asyncio.CancelledError, id="cancelled"),
    pytest.param(SoftTimeLimitExceeded, id="soft-time-limit"),
    pytest.param(MemoryError, id="memory-error"),
]


# ---------------------------------------------------------------------------
# Committed world
# ---------------------------------------------------------------------------


class _World(CommittedWorld):
    """Committed CVEs, `CVESource` rows, Tickets, and `FetcherConfig` rows,
    all deleted at teardown."""

    def __init__(
        self,
        factory: SessionFactory,
        session: AsyncSession,
        sessions: async_sessionmaker[AsyncSession],
    ) -> None:
        super().__init__(factory, session)
        self.sessions = sessions
        self.cve_strings: list[str] = []
        self.config_names: list[str] = []

    async def new_cve(
        self, *, ticket: TicketStatus | None = TicketStatus.ANALYSIS
    ) -> CVE:
        """A committed CVE with a fresh fictional CVE-ID; `ticket` is the
        status of its one Ticket, or `None` for a ticketless CVE. A
        `Duplicated` Ticket points at a CVE-less `Analysis` Ticket."""
        cve = CVE(cve_id=fictional_cve_id())
        self.session.add(cve)
        await self.session.flush()
        self.cve_ids.append(cve.id)
        self.cve_strings.append(cve.cve_id)
        if ticket is not None:
            canonical_id: uuid.UUID | None = None
            if ticket is TicketStatus.DUPLICATED:
                canonical = Ticket(status=TicketStatus.ANALYSIS.value)
                self.session.add(canonical)
                await self.session.flush()
                self.ticket_ids.append(canonical.id)
                canonical_id = canonical.id
            created = Ticket(
                status=ticket.value, cve_id=cve.id, duplicate_of_id=canonical_id
            )
            self.session.add(created)
            await self.session.flush()
            self.ticket_ids.append(created.id)
        await self.session.commit()
        return cve

    async def source(
        self,
        cve: CVE,
        source: str,
        *,
        status: str = FAILURE,
        age: timedelta | None = timedelta(hours=1),
    ) -> None:
        """Commit one `CVESource` row whose streak began `age` ago
        (`None`: no streak)."""
        now = datetime.now(UTC)
        self.session.add(
            CVESource(
                cve_id=cve.id,
                source=source,
                status=status,
                fetched_at=now,
                first_failed_at=None if age is None else now - age,
            )
        )
        await self.session.commit()

    async def pair(
        self,
        source: str,
        *,
        age: timedelta = timedelta(hours=1),
        ticket: TicketStatus | None = TicketStatus.ANALYSIS,
    ) -> CVE:
        """A CVE with one in-window `failure` row of `source`."""
        cve = await self.new_cve(ticket=ticket)
        await self.source(cve, source, age=age)
        return cve

    async def config(self, name: str, *, enabled: bool = True) -> None:
        await seed_fetcher_config(self.sessions, name, enabled=enabled)
        self.config_names.append(name)

    async def set_enabled(self, name: str, *, enabled: bool) -> None:
        async with self.sessions() as session:
            await session.execute(
                update(FetcherConfig)
                .where(FetcherConfig.fetcher_name == name)
                .values(enabled=enabled)
            )
            await session.commit()

    async def cleanup(self) -> None:
        await super().cleanup()
        await delete_fetcher_rows(self.sessions, self.config_names)


def _record_lifecycle(events: list[str], label: str) -> Callable[[AsyncSession], None]:
    """A `RecordingSessions` hook appending `<label>open` when a session is
    handed out and `<label>close` once its `close()` completed."""

    def hook(session: AsyncSession) -> None:
        events.append(f"{label}open")
        close = session.close

        async def recorded_close() -> None:
            await close()
            events.append(f"{label}close")

        session.close = recorded_close  # type: ignore[method-assign]

    return hook


@dataclass
class _Env:
    world: _World
    redis: redis_asyncio.Redis
    published: Publications
    revalidation: RecordingSessions
    events: list[str]

    async def keys(self) -> list[str]:
        keys: list[str] = sorted(await self.redis.keys("*"))
        return keys


@pytest.fixture
async def env(
    db_session_factory: SessionFactory,
    real_session_factory: async_sessionmaker[AsyncSession],
    redis_client: redis_asyncio.Redis,
    isolated_fetcher_registries: None,
    monkeypatch: pytest.MonkeyPatch,
) -> AsyncIterator[_Env]:
    events: list[str] = []
    world = _World(db_session_factory, await db_session_factory(), real_session_factory)
    published = Publications(events)
    monkeypatch.setattr(task_publication, "publish_task", published)
    revalidation = RecordingSessions(real_session_factory, events, label="revalidate:")
    revalidation.hooks.append(_record_lifecycle(events, "revalidate:"))
    revalidation.install(monkeypatch, evaluator)
    real_find = evaluator.find_failed_cve_source_candidates

    async def scoped(db: AsyncSession) -> list[RetryCandidate]:
        return [c for c in await real_find(db) if c.cve_id in world.cve_strings]

    monkeypatch.setattr(evaluator, "find_failed_cve_source_candidates", scoped)
    try:
        yield _Env(world, redis_client, published, revalidation, events)
    finally:
        await world.cleanup()


# ---------------------------------------------------------------------------
# run() lifecycle: finalized FetcherRun (committed; explicit cleanup)
# ---------------------------------------------------------------------------


class _Runs:
    """Commits one `running` FetcherRun per `start()` and reads it back."""

    def __init__(self, factory: async_sessionmaker[AsyncSession]) -> None:
        self._factory = factory
        self.fetcher_name = f"test_failed_sources_run_{uuid.uuid4().hex[:12]}"
        self.configured = False

    async def start(self) -> uuid.UUID:
        async with self._factory() as session:
            if not self.configured:
                session.add(FetcherConfig(fetcher_name=self.fetcher_name))
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
    """Route `run()`'s own sessions to the test database; delete the
    committed `FetcherConfig` and `FetcherRun` rows at teardown."""
    monkeypatch.setattr(
        base_fetcher_module, "async_session_factory", real_session_factory
    )
    created = _Runs(real_session_factory)
    try:
        yield created
    finally:
        await delete_fetcher_rows(real_session_factory, [created.fetcher_name])


def _run_config() -> FetcherRunConfig:
    return FetcherRunConfig(
        hard_time_limit_seconds=3600, request_delay=0, custom_settings={}
    )


def _run_metrics(run: FetcherRun) -> Counters:
    return (run.items_succeeded, run.items_created, run.items_updated, run.items_failed)


async def _run(runs: _Runs) -> FetcherRun:
    """One complete `run()` that returns normally; the finalized row."""
    run_id = await runs.start()
    await EvaluateFailedCveSources().run(run_id=run_id, config=_run_config())
    return await runs.finalized(run_id)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _counters(fetcher: EvaluateFailedCveSources) -> Counters:
    return (fetcher._succeeded, fetcher._created, fetcher._updated, fetcher._failed)


async def _execute(env: _Env) -> EvaluateFailedCveSources:
    fetcher = EvaluateFailedCveSources()
    await fetcher.execute(await env.world.open_session())
    return fetcher


async def _execute_failing(
    env: _Env, error: type[BaseException]
) -> tuple[BaseException, EvaluateFailedCveSources]:
    fetcher = EvaluateFailedCveSources()
    session = await env.world.open_session()
    with pytest.raises(error) as raised:
        await fetcher.execute(session)
    return raised.value, fetcher


def _events(logs: Iterable[Mapping[str, Any]], *names: str) -> list[Mapping[str, Any]]:
    return [entry for entry in logs if entry["event"] in names]


def _pair_events(logs: Iterable[Mapping[str, Any]]) -> list[Mapping[str, Any]]:
    return [entry for entry in logs if entry["event"] in PAIR_EVENTS]


def _skipped(cve: CVE, source: str, reason: str) -> dict[str, Any]:
    return {
        "event": SKIPPED,
        "log_level": "debug",
        "cve_id": cve.cve_id,
        "source": source,
        "reason": reason,
    }


def _dispatched(cve: CVE, source: str) -> dict[str, Any]:
    return {
        "event": DISPATCHED,
        "log_level": "info",
        "cve_id": cve.cve_id,
        "source": source,
    }


def _already_pending(cve: CVE, source: str) -> dict[str, Any]:
    return {
        "event": ALREADY_PENDING,
        "log_level": "info",
        "cve_id": cve.cve_id,
        "source": source,
    }


def _config_missing(cve: CVE, source: str, fetcher_name: str) -> dict[str, Any]:
    return {
        "event": CONFIG_MISSING,
        "log_level": "error",
        "cve_id": cve.cve_id,
        "source": source,
        "fetcher_name": fetcher_name,
    }


def _unconfirmed(cve: CVE, source: str) -> dict[str, Any]:
    return {
        "event": DISPATCH_FAILED,
        "log_level": "warning",
        "cve_id": cve.cve_id,
        "source": source,
        "reason": "publication_unconfirmed",
    }


def _unexpected(cve: CVE, source: str, cause: str) -> dict[str, Any]:
    return {
        "event": DISPATCH_FAILED,
        "log_level": "warning",
        "cve_id": cve.cve_id,
        "source": source,
        "reason": "unexpected_error",
        "cause": cause,
    }


def _summary(**counters: int) -> dict[str, Any]:
    """The closed summary; `candidates` is the sum of the seven outcome
    counters, each defaulting to zero."""
    assert set(counters) <= set(SUMMARY_COUNTERS)
    values = {name: counters.get(name, 0) for name in SUMMARY_COUNTERS}
    return {
        "event": SUMMARY,
        "log_level": "info",
        "candidates": sum(values.values()),
        **values,
    }


def _assert_private(logs: Iterable[Mapping[str, Any]], *forbidden: str) -> None:
    """Only documented fields, and never exception text, a URL, or any of
    the `forbidden` fragments (tokens)."""
    for entry in logs:
        assert set(entry) <= ALLOWED_KEYS, entry
        rendered = repr(dict(entry))
        assert "://" not in rendered, entry
        for fragment in (SECRET_TEXT, "Example-Secret-Detail", "alice", *forbidden):
            assert fragment not in rendered, entry


def _published_sources(published: Publications) -> list[tuple[str, str]]:
    return [(k["cve_id"], k["source"]) for k in published.published(TASK)]


def _fail_publication_of(cve: CVE) -> Callable[[dict[str, Any]], Awaitable[None]]:
    """A `Publications.before` hook making only `cve`'s publication raise
    an ordinary broker error (acceptance unconfirmed)."""

    async def before(call: dict[str, Any]) -> None:
        if call["kwargs"]["cve_id"] == cve.cve_id:
            raise KombuOperationalError(SECRET_TEXT)

    return before


# ---------------------------------------------------------------------------
# Eligibility: pre-scope exclusions of steps 2a and 2b
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestEligibility:
    async def test_not_fetch_single_capable_sources_are_skipped_without_metric(
        self, env: _Env
    ) -> None:
        """The production KEV source is registered but not fetch-single
        capable, and a deregistered value has no owner; capability is
        checked before the active-Ticket flag."""
        assert FETCHER_REGISTRY["sync_cisa_kev"] is SyncCisaKev
        assert "kev" not in get_fetch_single_fetchers()
        await env.world.config("sync_cisa_kev")
        kev = await env.world.pair("kev", age=timedelta(hours=3))
        retired = await env.world.pair("retired_source", age=timedelta(hours=2))
        kev_ticketless = await env.world.pair(
            "kev", age=timedelta(hours=1), ticket=None
        )

        with capture_logs() as logs:
            fetcher = await _execute(env)

        assert _counters(fetcher) == (0, 0, 0, 0)
        assert _pair_events(logs) == [
            _skipped(kev, "kev", "not_fetch_single_capable"),
            _skipped(retired, "retired_source", "not_fetch_single_capable"),
            _skipped(kev_ticketless, "kev", "not_fetch_single_capable"),
        ]
        assert _events(logs, SUMMARY) == [_summary(skipped_no_capability=3)]
        assert env.published.calls == []
        assert env.revalidation.opened == []
        assert await env.keys() == []

    async def test_cves_without_an_active_ticket_are_skipped_without_metric(
        self, env: _Env
    ) -> None:
        """Only inactive Tickets (`Resolved`, `Ignored`, `Duplicated`) or
        no Ticket at all: no revalidation, publication, or metric, although
        the source is registered, capable, and enabled."""
        await env.world.config(REDHAT)
        cves = [
            await env.world.pair(
                "redhat", age=timedelta(hours=4 - index), ticket=status
            )
            for index, status in enumerate(
                (
                    TicketStatus.RESOLVED,
                    TicketStatus.IGNORED,
                    TicketStatus.DUPLICATED,
                    None,
                )
            )
        ]

        with capture_logs() as logs:
            fetcher = await _execute(env)

        assert _counters(fetcher) == (0, 0, 0, 0)
        assert _pair_events(logs) == [
            _skipped(cve, "redhat", "no_active_ticket") for cve in cves
        ]
        assert _events(logs, SUMMARY) == [_summary(skipped_no_active_ticket=4)]
        assert env.published.calls == []
        assert env.revalidation.opened == []
        assert await env.keys() == []


# ---------------------------------------------------------------------------
# Revalidation (step 2c): non-locking, exclusion, configuration invariant
# ---------------------------------------------------------------------------

ROW_LOCKS: Final = ("FOR UPDATE", "FOR NO KEY UPDATE", "FOR SHARE", "FOR KEY SHARE")


@pytest.mark.integration
class TestRevalidation:
    async def test_locked_cve_and_ticket_rows_do_not_block_the_retry(
        self, env: _Env
    ) -> None:
        """An independent transaction holds `FOR UPDATE` on the CVE and on
        its Ticket throughout: the candidate read, the revalidation read,
        and the publication complete, and every statement is a lock-free
        `SELECT` (no write)."""
        await env.world.config(REDHAT)
        cve = await env.world.pair("redhat")
        holder = await env.world.open_session()
        await holder.execute(select(CVE.id).where(CVE.id == cve.id).with_for_update())
        await holder.execute(
            select(Ticket.id).where(Ticket.cve_id == cve.id).with_for_update()
        )
        fetcher = EvaluateFailedCveSources()
        session = await env.world.open_session()

        with capture_logs() as logs, NoDatabaseAccess() as observed:
            await asyncio.wait_for(fetcher.execute(session), timeout=WAIT)

        assert holder.in_transaction()
        await holder.rollback()
        assert _counters(fetcher) == (1, 0, 0, 0)
        assert _pair_events(logs) == [_dispatched(cve, "redhat")]
        assert _published_sources(env.published) == [(cve.cve_id, "redhat")]
        assert len(observed.statements) == 2
        for statement in observed.statements:
            assert statement.lstrip().upper().startswith("SELECT"), statement
            for row_lock in ROW_LOCKS:
                assert row_lock not in statement.upper(), statement

    async def test_source_unregistered_at_revalidation_is_excluded(
        self, env: _Env, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The source leaves the fetch-single registry between step 2a and
        the revalidation: excluded with no metric, no configuration read,
        and no publication; the next pair is dispatched."""
        await env.world.config(REDHAT)
        await env.world.config(MITRE)
        leaving = await env.world.pair("redhat", age=timedelta(hours=2))
        staying = await env.world.pair("mitre", age=timedelta(hours=1))
        calls = [0]

        def fetchers() -> dict[str, type[BaseCVEFetcher]]:
            calls[0] += 1
            registry = get_fetch_single_fetchers()
            if calls[0] >= 2:
                registry.pop("redhat")
            return registry

        monkeypatch.setattr(evaluator, "get_fetch_single_fetchers", fetchers)

        with capture_logs() as logs:
            fetcher = await _execute(env)

        assert calls[0] >= 2
        assert _counters(fetcher) == (1, 0, 0, 0)
        assert _pair_events(logs) == [
            _skipped(leaving, "redhat", "excluded_at_revalidation"),
            _dispatched(staying, "mitre"),
        ]
        assert _events(logs, SUMMARY) == [
            _summary(excluded_at_revalidation=1, dispatched=1)
        ]
        assert len(env.revalidation.opened) == 1
        assert _published_sources(env.published) == [(staying.cve_id, "mitre")]
        assert await env.keys() == [pending_key(staying.cve_id, "mitre")]

    async def test_disabled_source_is_excluded_after_a_closed_read(
        self, env: _Env
    ) -> None:
        await env.world.config(REDHAT, enabled=False)
        await env.world.config(GHSA)
        disabled = await env.world.pair("redhat", age=timedelta(hours=2))
        enabled = await env.world.pair("ghsa", age=timedelta(hours=1))

        with capture_logs() as logs:
            fetcher = await _execute(env)

        assert _counters(fetcher) == (1, 0, 0, 0)
        assert _pair_events(logs) == [
            _skipped(disabled, "redhat", "excluded_at_revalidation"),
            _dispatched(enabled, "ghsa"),
        ]
        assert _events(logs, SUMMARY) == [
            _summary(excluded_at_revalidation=1, dispatched=1)
        ]
        assert env.events == [
            "revalidate:open",
            "revalidate:close",
            "revalidate:open",
            "revalidate:close",
            "publish:fetch_single_cve",
        ]
        assert _published_sources(env.published) == [(enabled.cve_id, "ghsa")]
        assert await env.keys() == [pending_key(enabled.cve_id, "ghsa")]

    async def test_missing_configuration_fails_the_pair_and_the_next_continues(
        self, env: _Env
    ) -> None:
        """The configuration row is read under `fetcher_cls.name`, not the
        source value; its absence is one failure with one ERROR."""
        await env.world.config(MITRE)
        missing = await env.world.pair("redhat", age=timedelta(hours=2))
        configured = await env.world.pair("mitre", age=timedelta(hours=1))

        with capture_logs() as logs:
            fetcher = await _execute(env)

        assert _counters(fetcher) == (1, 0, 0, 1)
        assert _pair_events(logs) == [
            _config_missing(missing, "redhat", REDHAT),
            _dispatched(configured, "mitre"),
        ]
        assert _events(logs, SUMMARY) == [_summary(config_missing=1, dispatched=1)]
        assert _published_sources(env.published) == [(configured.cve_id, "mitre")]
        _assert_private(logs)


# ---------------------------------------------------------------------------
# Dispatch: exactly the failed source, marker, queue, and failure handling
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestDispatch:
    async def test_only_the_failed_source_is_published_with_its_marker(
        self, env: _Env
    ) -> None:
        """The CVE's other sources are `success`, `missing`, a stalled
        failure, and a failure without a streak, each with an enabled
        fetcher: none is published."""
        for name in (REDHAT, OSV, GHSA, EPSS, MITRE):
            await env.world.config(name)
        cve = await env.world.pair("redhat")
        await env.world.source(cve, "osv", status="success", age=None)
        await env.world.source(cve, "ghsa", status="missing", age=None)
        await env.world.source(cve, "epss", age=WINDOW + timedelta(days=1))
        await env.world.source(cve, "mitre", age=None)

        with capture_logs() as logs:
            fetcher = await _execute(env)

        assert _counters(fetcher) == (1, 0, 0, 0)
        (call,) = env.published.calls
        token = call["kwargs"]["token"]
        assert TOKEN_PATTERN.fullmatch(token)
        assert call == {
            "task_name": TASK,
            "kwargs": {
                "fetcher_name": REDHAT,
                "cve_id": cve.cve_id,
                "source": "redhat",
                "token": token,
            },
            "queue": None,
        }
        key = pending_key(cve.cve_id, "redhat")
        assert await env.keys() == [key]
        assert await env.redis.get(key) == token
        assert 0 < await env.redis.ttl(key) <= PENDING_TTL
        assert _pair_events(logs) == [_dispatched(cve, "redhat")]
        assert _events(logs, SUMMARY) == [_summary(dispatched=1)]
        _assert_private(logs, token)

    async def test_production_git_fetchers_keep_the_git_queue(self, env: _Env) -> None:
        """The production MITRE and Kernel classes publish on `git`; the
        production Red Hat class passes no queue (`None`, omitted by
        `publish_task()`)."""
        registry = get_fetch_single_fetchers()
        assert registry["mitre"] is SyncMitreCves
        assert registry["kernel"] is SyncKernelCves
        assert registry["redhat"] is SyncRedhatCves
        for name in (MITRE, KERNEL, REDHAT):
            await env.world.config(name)
        mitre = await env.world.pair("mitre", age=timedelta(hours=3))
        kernel = await env.world.pair("kernel", age=timedelta(hours=2))
        redhat = await env.world.pair("redhat", age=timedelta(hours=1))

        fetcher = await _execute(env)

        assert _counters(fetcher) == (3, 0, 0, 0)
        assert [
            (call["kwargs"]["fetcher_name"], call["kwargs"]["cve_id"], call["queue"])
            for call in env.published.calls
        ] == [
            (MITRE, mitre.cve_id, "git"),
            (KERNEL, kernel.cve_id, "git"),
            (REDHAT, redhat.cve_id, None),
        ]

    async def test_already_pending_pair_succeeds_without_publication(
        self, env: _Env
    ) -> None:
        await env.world.config(REDHAT)
        cve = await env.world.pair("redhat")
        key = pending_key(cve.cve_id, "redhat")
        await env.redis.set(key, "fictional-earlier-owner", ex=300)

        with capture_logs() as logs:
            fetcher = await _execute(env)

        assert _counters(fetcher) == (1, 0, 0, 0)
        assert env.published.calls == []
        assert await env.redis.get(key) == "fictional-earlier-owner"
        assert 0 < await env.redis.ttl(key) <= 300
        assert _pair_events(logs) == [_already_pending(cve, "redhat")]
        assert _events(logs, SUMMARY) == [_summary(already_pending=1)]

    async def test_unconfirmed_publication_fails_the_pair_and_the_next_continues(
        self, env: _Env
    ) -> None:
        """One WARNING without `cause` and without the broker error text."""
        await env.world.config(REDHAT)
        failing = await env.world.pair("redhat", age=timedelta(hours=2))
        later = await env.world.pair("redhat", age=timedelta(hours=1))
        env.published.before = _fail_publication_of(failing)

        with capture_logs() as logs:
            fetcher = await _execute(env)

        assert _counters(fetcher) == (1, 0, 0, 1)
        assert _published_sources(env.published) == [
            (failing.cve_id, "redhat"),
            (later.cve_id, "redhat"),
        ]
        assert _pair_events(logs) == [
            _unconfirmed(failing, "redhat"),
            _dispatched(later, "redhat"),
        ]
        assert _events(logs, SUMMARY) == [_summary(dispatch_failed=1, dispatched=1)]
        _assert_private(logs, *(c["kwargs"]["token"] for c in env.published.calls))

    @pytest.mark.parametrize("stage", ["revalidation", "publication"])
    async def test_ordinary_exception_fails_the_pair_without_its_text(
        self, env: _Env, monkeypatch: pytest.MonkeyPatch, stage: str
    ) -> None:
        """An ordinary exception from the revalidation read or from
        `trigger_on_demand_fetch()`: one WARNING naming only the exception
        class, and the next pair continues."""
        await env.world.config(REDHAT)
        await env.world.config(GHSA)
        failing = await env.world.pair("redhat", age=timedelta(hours=2))
        later = await env.world.pair("ghsa", age=timedelta(hours=1))
        error = RuntimeError(f"{SECRET_TEXT} {failing.cve_id}")
        if stage == "revalidation":
            real_enabled = get_fetcher_enabled

            async def enabled(session: AsyncSession, fetcher_name: str) -> bool:
                if fetcher_name == REDHAT:
                    raise error
                return await real_enabled(session, fetcher_name)

            monkeypatch.setattr(evaluator, "get_fetcher_enabled", enabled)
        else:
            real_trigger = trigger_on_demand_fetch

            async def trigger(
                cve_id: str,
                dispatch_sources: Sequence[tuple[str, str, str | None]],
                disabled_sources: Sequence[str] = (),
            ) -> FetchDispatchResult:
                if cve_id == failing.cve_id:
                    raise error
                return await real_trigger(cve_id, dispatch_sources, disabled_sources)

            monkeypatch.setattr(evaluator, "trigger_on_demand_fetch", trigger)

        with capture_logs() as logs:
            fetcher = await _execute(env)

        assert _counters(fetcher) == (1, 0, 0, 1)
        assert _pair_events(logs) == [
            _unexpected(failing, "redhat", "RuntimeError"),
            _dispatched(later, "ghsa"),
        ]
        assert _events(logs, SUMMARY) == [_summary(dispatch_failed=1, dispatched=1)]
        assert _published_sources(env.published) == [(later.cve_id, "ghsa")]
        _assert_private(logs)


# ---------------------------------------------------------------------------
# Later disablement: dispatch success, then the task's disabled no-op
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestLaterDisablement:
    async def test_disablement_after_publication_keeps_success_and_task_no_ops(
        self,
        env: _Env,
        runs: _Runs,
        real_session_factory: async_sessionmaker[AsyncSession],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Database-free publication cannot observe a later disablement:
        the run records dispatch success. The published task, executed with
        the recorded payload after the disablement, performs the disabled
        no-op and owner-releases the marker without fetching or writing
        the source row; the run's metrics stay unchanged."""
        probe = define_cve_fetcher(source=CVESourceType.OSV)
        await env.world.config(probe.name)
        cve = await env.world.pair("osv")
        before = await source_state(real_session_factory, cve.id, CVESourceType.OSV)

        run = await _run(runs)

        assert (run.status, _run_metrics(run)) == ("success", (1, 0, 0, 0))
        (payload,) = env.published.published(TASK)
        assert payload["fetcher_name"] == probe.name
        key = pending_key(cve.cve_id, "osv")
        assert await env.redis.get(key) == payload["token"]

        await env.world.set_enabled(probe.name, enabled=False)
        engine = FakeEngine()
        monkeypatch.setattr(cve_tasks, "async_session_factory", real_session_factory)
        monkeypatch.setattr(cve_tasks, "engine", engine)
        with capture_logs() as logs:
            outcome = await cve_tasks.fetch_single_cve_async(**payload, attempt=0)

        assert outcome is None
        assert logs == [
            {
                "event": FETCHER_DISABLED,
                "log_level": "info",
                "fetcher_name": probe.name,
                "cve_id": cve.cve_id,
                "source": "osv",
            }
        ]
        assert probe.fetched == []
        assert await env.redis.exists(key) == 0
        engine.dispose.assert_awaited_once_with()
        assert (
            await source_state(real_session_factory, cve.id, CVESourceType.OSV)
            == before
        )
        assert _run_metrics(await runs.finalized(run.id)) == (1, 0, 0, 0)
        assert await fetcher_run_count(real_session_factory, probe.name) == 0


# ---------------------------------------------------------------------------
# Metrics through run() (concrete mapping; Error Handling)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestRunOutcomes:
    async def test_empty_candidate_set_is_success_with_zero_counters(
        self,
        env: _Env,
        runs: _Runs,
        real_session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        with capture_logs() as logs:
            run = await _run(runs)

        assert run.status == "success"
        assert _run_metrics(run) == (0, 0, 0, 0)
        assert (run.error_message, run.error_detail) == (None, None)
        assert _pair_events(logs) == []
        assert _events(logs, SUMMARY) == [_summary()]
        assert env.published.calls == []
        assert await fetcher_run_count(real_session_factory, runs.fetcher_name) == 1

    async def test_mixed_outcomes_are_partial_with_one_event_per_pair(
        self,
        env: _Env,
        runs: _Runs,
        real_session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        """One pair per outcome, oldest streak first: each selected pair
        reaches exactly one terminal outcome, exclusions reach none, and
        every pair yields exactly one bounded event. The summary is closed
        and agrees with the persisted counters. One `FetcherRun` is
        finalized for the evaluator."""
        world = env.world
        for name in (REDHAT, OSV, GHSA, MITRE):
            await world.config(name)
        await world.config(KERNEL, enabled=False)
        hours = iter(range(10, 0, -1))
        dispatched = await world.pair("redhat", age=timedelta(hours=next(hours)))
        pending = await world.pair("osv", age=timedelta(hours=next(hours)))
        unconfirmed = await world.pair("ghsa", age=timedelta(hours=next(hours)))
        missing = await world.pair("epss", age=timedelta(hours=next(hours)))
        kev = await world.pair("kev", age=timedelta(hours=next(hours)))
        resolved = await world.pair(
            "mitre", age=timedelta(hours=next(hours)), ticket=TicketStatus.RESOLVED
        )
        disabled = await world.pair("kernel", age=timedelta(hours=next(hours)))
        await env.redis.set(pending_key(pending.cve_id, "osv"), "fictional-owner")
        env.published.before = _fail_publication_of(unconfirmed)

        with capture_logs() as logs:
            run = await _run(runs)

        assert run.status == "partial"
        assert run.error_message is None
        assert _run_metrics(run) == (2, 0, 0, 2)
        assert _pair_events(logs) == [
            _dispatched(dispatched, "redhat"),
            _already_pending(pending, "osv"),
            _unconfirmed(unconfirmed, "ghsa"),
            _config_missing(missing, "epss", EPSS),
            _skipped(kev, "kev", "not_fetch_single_capable"),
            _skipped(resolved, "mitre", "no_active_ticket"),
            _skipped(disabled, "kernel", "excluded_at_revalidation"),
        ]
        (summary,) = _events(logs, SUMMARY)
        assert summary == _summary(
            dispatched=1,
            already_pending=1,
            dispatch_failed=1,
            config_missing=1,
            skipped_no_capability=1,
            skipped_no_active_ticket=1,
            excluded_at_revalidation=1,
        )
        assert summary["candidates"] == 7
        assert summary["dispatched"] + summary["already_pending"] == (
            run.items_succeeded
        )
        assert summary["dispatch_failed"] + summary["config_missing"] == (
            run.items_failed
        )
        assert _published_sources(env.published) == [
            (dispatched.cve_id, "redhat"),
            (unconfirmed.cve_id, "ghsa"),
        ]
        _assert_private(logs, *(c["kwargs"]["token"] for c in env.published.calls))
        assert await fetcher_run_count(real_session_factory, runs.fetcher_name) == 1

    async def test_every_selected_pair_failing_is_a_normal_return_failure(
        self, env: _Env, runs: _Runs
    ) -> None:
        """An excluded pair does not turn the all-failed outcome into a
        success."""
        await env.world.config(GHSA)
        missing = await env.world.pair("redhat", age=timedelta(hours=3))
        unconfirmed = await env.world.pair("ghsa", age=timedelta(hours=2))
        await env.world.pair("ghsa", age=timedelta(hours=1), ticket=None)
        env.published.before = _fail_publication_of(unconfirmed)

        with capture_logs() as logs:
            run = await _run(runs)

        assert run.status == "failure"
        assert run.error_message == "All 2 items failed"
        assert (run.error_detail, run.error_traceback) == (None, None)
        assert _run_metrics(run) == (0, 0, 0, 2)
        assert _events(logs, SUMMARY) == [
            _summary(config_missing=1, dispatch_failed=1, skipped_no_active_ticket=1)
        ]
        assert [entry["cve_id"] for entry in _pair_events(logs)][:2] == [
            missing.cve_id,
            unconfirmed.cve_id,
        ]

    async def test_only_exclusions_is_success_with_zero_counters(
        self, env: _Env, runs: _Runs
    ) -> None:
        """Every skip and every revalidation exclusion contributes to
        neither counter."""
        await env.world.config(REDHAT, enabled=False)
        await env.world.pair("kev", age=timedelta(hours=3))
        await env.world.pair("osv", age=timedelta(hours=2), ticket=None)
        await env.world.pair("redhat", age=timedelta(hours=1))

        with capture_logs() as logs:
            run = await _run(runs)

        assert run.status == "success"
        assert _run_metrics(run) == (0, 0, 0, 0)
        assert (run.error_message, run.error_detail) == (None, None)
        assert _events(logs, SUMMARY) == [
            _summary(
                skipped_no_capability=1,
                skipped_no_active_ticket=1,
                excluded_at_revalidation=1,
            )
        ]
        assert env.published.calls == []

    async def test_candidate_query_failure_fails_the_run(
        self, env: _Env, runs: _Runs, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        await env.world.config(REDHAT)
        await env.world.pair("redhat")
        error = OperationalError("SELECT", None, Exception("fictional outage"))

        async def failing(db: AsyncSession) -> list[RetryCandidate]:
            await db.execute(select(1))
            raise error

        monkeypatch.setattr(evaluator, "find_failed_cve_source_candidates", failing)
        run_id = await runs.start()

        with capture_logs() as logs, pytest.raises(OperationalError) as raised:
            await EvaluateFailedCveSources().run(run_id=run_id, config=_run_config())

        assert raised.value is error
        run = await runs.finalized(run_id)
        assert run.status == "failure"
        assert run.error_message == "Unexpected error"
        assert _run_metrics(run) == (0, 0, 0, 0)
        assert _pair_events(logs) == []
        assert _events(logs, SUMMARY) == []
        assert env.revalidation.opened == []
        assert env.published.calls == []


# ---------------------------------------------------------------------------
# Whole-run signals (SoftTimeLimitExceeded handling convention)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestWholeRunSignals:
    @pytest.mark.parametrize("stage", ["revalidation", "publication"])
    @pytest.mark.parametrize("make_signal", _WHOLE_RUN_SIGNALS)
    async def test_signal_propagates_and_later_pairs_are_not_processed(
        self,
        env: _Env,
        monkeypatch: pytest.MonkeyPatch,
        make_signal: Callable[[], BaseException],
        stage: str,
    ) -> None:
        await env.world.config(REDHAT)
        await env.world.config(GHSA)
        first = await env.world.pair("redhat", age=timedelta(hours=2))
        await env.world.pair("ghsa", age=timedelta(hours=1))
        signal = make_signal()
        if stage == "revalidation":

            async def enabled(session: AsyncSession, fetcher_name: str) -> bool:
                raise signal

            monkeypatch.setattr(evaluator, "get_fetcher_enabled", enabled)
        else:
            env.published.errors[TASK] = signal

        with capture_logs() as logs:
            raised, fetcher = await _execute_failing(env, type(signal))

        assert raised is signal
        assert _counters(fetcher) == (0, 0, 0, 0)
        assert _pair_events(logs) == []
        assert _events(logs, SUMMARY) == []
        assert len(env.revalidation.opened) == 1
        expected = [] if stage == "revalidation" else [(first.cve_id, "redhat")]
        assert _published_sources(env.published) == expected


# ---------------------------------------------------------------------------
# Transaction boundaries and the absence of writes
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestTransactionBoundaries:
    async def test_reads_are_closed_before_every_redis_and_celery_call(
        self, env: _Env, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The step-1 read transaction is committed before any Redis or
        Celery call; each revalidation session is opened and closed before
        its pair's Redis marker and publication, and neither the execution
        session nor any revalidation session has an open transaction then.
        The revalidation sessions never flush, commit, or roll back."""
        await env.world.config(REDHAT)
        await env.world.config(GHSA)
        first = await env.world.pair("redhat", age=timedelta(hours=2))
        second = await env.world.pair("ghsa", age=timedelta(hours=1))
        session = await env.world.open_session()
        original_commit = session.commit
        observed: list[tuple[bool, list[bool]]] = []

        async def recording_commit() -> None:
            await original_commit()
            env.events.append("execute:commit")

        def observe() -> None:
            observed.append(
                (
                    session.in_transaction(),
                    [s.in_transaction() for s in env.revalidation.opened],
                )
            )

        real_client = cve_service._new_redis_client

        def client_factory() -> redis_asyncio.Redis:
            client = real_client()
            original_set = client.set

            async def recorded_set(*args: Any, **kwargs: Any) -> Any:
                env.events.append("redis:set")
                observe()
                return await original_set(*args, **kwargs)

            client.set = recorded_set  # type: ignore[method-assign]
            return client

        async def before(call: dict[str, Any]) -> None:
            observe()

        monkeypatch.setattr(session, "commit", recording_commit)
        monkeypatch.setattr(cve_service, "_new_redis_client", client_factory)
        env.published.before = before

        fetcher = EvaluateFailedCveSources()
        await fetcher.execute(session)

        assert env.events == [
            "execute:commit",
            "revalidate:open",
            "revalidate:close",
            "redis:set",
            "publish:fetch_single_cve",
            "revalidate:open",
            "revalidate:close",
            "redis:set",
            "publish:fetch_single_cve",
        ]
        assert observed == [
            (False, [False]),
            (False, [False]),
            (False, [False, False]),
            (False, [False, False]),
        ]
        assert _counters(fetcher) == (2, 0, 0, 0)
        assert _published_sources(env.published) == [
            (first.cve_id, "redhat"),
            (second.cve_id, "ghsa"),
        ]


@pytest.mark.integration
class TestNoWrites:
    async def test_execute_writes_no_source_cve_ticket_reference_or_audit_row(
        self,
        env: _Env,
        real_session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        """Every outcome is exercised; publication is recorded, so only the
        evaluator itself could write. Every statement it issues is a
        `SELECT`."""
        world = env.world
        for name in (REDHAT, OSV, GHSA, MITRE):
            await world.config(name)
        await world.config(KERNEL, enabled=False)
        await world.pair("redhat", age=timedelta(hours=7))
        pending = await world.pair("osv", age=timedelta(hours=6))
        unconfirmed = await world.pair("ghsa", age=timedelta(hours=5))
        await world.pair("epss", age=timedelta(hours=4))
        await world.pair("kev", age=timedelta(hours=3))
        await world.pair("mitre", age=timedelta(hours=2), ticket=TicketStatus.IGNORED)
        await world.pair("kernel", age=timedelta(hours=1))
        await env.redis.set(pending_key(pending.cve_id, "osv"), "fictional-owner")
        env.published.before = _fail_publication_of(unconfirmed)

        async with real_session_factory() as probe:
            before = await persisted_snapshot(probe)
        with NoDatabaseAccess() as observed:
            fetcher = await _execute(env)
        async with real_session_factory() as probe:
            after = await persisted_snapshot(probe)

        assert _counters(fetcher) == (2, 0, 0, 2)
        assert after == before
        assert observed.statements
        for statement in observed.statements:
            assert statement.lstrip().upper().startswith("SELECT"), statement
