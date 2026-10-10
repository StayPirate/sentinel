"""Tests for the periodic batch `SyncEpssScores.execute()` and its `run()`
metrics (backend/app/services/tickets/sync_epss_scores.py).

Owning specifications:

- docs/features/tickets/cve-sync-epss.md (Algorithm: scope snapshot,
  staleness validation, consecutive failure abort; `fetch_single` method
  class structure; Error Handling, `execute()` table and sanitized
  messages; Metrics).
- docs/features/platform/cve-fetcher-infrastructure.md (Per-CVE
  Finalization; Session Lifecycle for API-based CVE Fetchers, template 1;
  Batch Error Handling, Per-item failure event and Consecutive failure
  abort; Metric Definitions).
- docs/features/tickets/cve-service.md (Active-Ticket CVE Scope).
- docs/features/platform/fetcher-infrastructure.md (Outcome and effect
  accounting; Error Message Sanitization; `SoftTimeLimitExceeded` handling
  convention) and docs/features/platform/logging.md (Secrets and PII
  Discipline).
- docs/features/platform/testing-strategy.md (CVE Fetcher Infrastructure:
  One-shot finalization, Periodic metrics, Isolated statuses; Fetcher
  Outcome and Effect Accounting, the `sync_epss_scores` mapping; External
  String Admissibility).

Every test commits real rows: CVEs with active Tickets of an
`IngestionWorld` (deleted with their children, including `cve_epss_score`
and `cve_source`, and their Ticket events at teardown), the isolated status
sessions (`base_cve_fetcher.async_session_factory`) on
`real_session_factory`, and, for `run()`, a committed
`FetcherConfig`/`FetcherRun` pair under a test-only name, deleted at
teardown. `execute()` tests use an independent `db_session_factory` session
with real commits and set the automatic periodic context that `run()`
establishes, so the finalizer records metrics. The scope query is the real
`cve_service.get_active_ticket_cve_ids()` wrapped by a spy that restricts
the snapshot to this test's CVEs, so rows committed by no other test can
enter it. HTTP is the in-process `EpssServer`; the broker call is the
recorded `task_publication.publish_task`; the inter-CVE delay is recorded
instead of slept; "today (UTC)" is the fixed `TODAY`. All identifiers and
texts are fictional.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable, Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from types import SimpleNamespace
from typing import Any, Final, NamedTuple

import httpx
import pytest
from celery.exceptions import SoftTimeLimitExceeded
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from structlog.contextvars import merge_contextvars
from structlog.testing import capture_logs

import app.services.base_cve_fetcher as base_cve_fetcher_module
import app.services.base_fetcher as base_fetcher_module
from app.core.enums import CVESourceFetchStatus, TicketStatus
from app.models.cve import CVE
from app.models.cve_epss_score import CVEEPSSScore
from app.models.cve_source import CVESource
from app.models.fetcher_config import FetcherConfig
from app.models.fetcher_run import FetcherRun
from app.services import (
    cve_service,
    task_publication,
    ticket_convergence_publication,
)
from app.services.base_cve_fetcher import CVE_FETCH_ITEM_FAILED_EVENT
from app.services.base_fetcher import FetcherError, FetcherRunConfig
from app.services.tickets import sync_epss_scores as sync_module
from app.services.tickets.sync_epss_scores import (
    EPSS_DATA_STALE_EVENT,
    EPSS_STALENESS_CHECK_FAILED_EVENT,
    SyncEpssScores,
)
from tests.support.cve_ingest import IngestionWorld
from tests.support.epss import (
    EpssServer,
    Responder,
    body,
    entry_for,
    envelope,
    raising,
    status,
)

SessionFactory = Callable[[], Awaitable[AsyncSession]]

NAME: Final = "sync_epss_scores"
ABORT_MESSAGE: Final = (
    "sync_epss_scores: source unreachable — aborted after 3 consecutive failures"
)
TODAY: Final = date(2026, 10, 6)
"""The patched current UTC date (`sync_epss_scores._utc_today()`)."""

SCORED: Final = {
    "epss": "0.500000000",
    "percentile": "0.500000000",
    "date": "2026-10-06",
}
"""The served fields of every scored CVE unless a test overrides them."""

PERSONAL_TEXT: Final = "Reported by Alice Example <alice.example@example.invalid>"
SECRET_VALUE: Final = "api_token=Example-Secret-Token-0123456789"
FAILURE_TEXT: Final = f"{PERSONAL_TEXT}; {SECRET_VALUE}"
"""Exception or upstream text that must appear in no log field."""

FAILED_EVENT_KEYS: Final = frozenset(
    {"event", "log_level", "cve_id", "fetcher_name", "cause"}
)


class Counters(NamedTuple):
    succeeded: int
    created: int
    updated: int
    failed: int


def counters(fetcher: SyncEpssScores) -> Counters:
    return Counters(
        fetcher._succeeded, fetcher._created, fetcher._updated, fetcher._failed
    )


def _events(logs: Iterable[Mapping[str, Any]], name: str) -> list[Mapping[str, Any]]:
    return [entry for entry in logs if entry["event"] == name]


def _assert_private(logs: Iterable[Mapping[str, Any]]) -> None:
    for entry in logs:
        rendered = repr(dict(entry))
        for fragment in (FAILURE_TEXT, PERSONAL_TEXT, SECRET_VALUE, "Alice"):
            assert fragment not in rendered, entry
        assert "Example-Secret-Token" not in rendered, entry
        assert "\\x00" not in rendered, entry


# ---------------------------------------------------------------------------
# Harness
# ---------------------------------------------------------------------------


@dataclass
class Publications:
    """Substitute for `task_publication.publish_task`."""

    calls: list[dict[str, Any]] = field(default_factory=list)

    async def __call__(self, task_name: str, **options: Any) -> None:
        self.calls.append({"task_name": task_name, **options})


@dataclass
class Env:
    world: IngestionWorld
    factory: async_sessionmaker[AsyncSession]
    server: EpssServer
    published: Publications
    scope_calls: list[list[str]] = field(default_factory=list)
    requests_at_scope: list[int] = field(default_factory=list)
    sleeps: list[float] = field(default_factory=list)
    status_opened: list[int] = field(default_factory=lambda: [0])
    run_names: list[str] = field(default_factory=list)
    cve_ids: list[str] = field(default_factory=list)

    async def active_cve(self, *, status: TicketStatus = TicketStatus.ANALYSIS) -> CVE:
        """A committed CVE with a Ticket in `status`, admitted to the scope
        spy; EPSS answers it as unscored until a test serves an entry."""
        cve = await self.world.cve_in()
        await self.world.ticket(cve_id=cve.id, status=status)
        self.cve_ids.append(cve.cve_id)
        return cve

    def serve(self, cve: CVE, **fields: str) -> None:
        self.server.entries[cve.cve_id] = entry_for(cve.cve_id, **{**SCORED, **fields})

    def respond(self, cve: CVE, responder: Responder) -> None:
        self.server.responses[cve.cve_id] = responder

    async def seed_score(self, cve: CVE) -> None:
        """Commit the `CVEEPSSScore` equal to the default served entry."""
        self.world.session.add(
            CVEEPSSScore(
                cve_id=cve.id, score=0.5, percentile=0.5, assessed_at=date(2026, 10, 6)
            )
        )
        await self.world.session.commit()

    async def updated_cve(self, **fields: str) -> CVE:
        """An active CVE whose ingestion creates its score (`updated`)."""
        cve = await self.active_cve()
        self.serve(cve, **fields)
        return cve

    async def unchanged_cve(self) -> CVE:
        """An active CVE whose served score equals the stored one."""
        cve = await self.active_cve()
        await self.seed_score(cve)
        self.serve(cve)
        return cve

    def fetcher(self) -> SyncEpssScores:
        instance = SyncEpssScores()
        instance._http_client = self.server.client()
        return instance

    async def source_status(self, cve: CVE) -> str | None:
        async with self.factory() as session:
            value: str | None = await session.scalar(
                select(CVESource.status).where(
                    CVESource.cve_id == cve.id, CVESource.source == "epss"
                )
            )
        return value

    async def score(self, cve: CVE) -> tuple[float, float, date] | None:
        async with self.factory() as session:
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

    async def score_count(self, cve: CVE) -> int:
        async with self.factory() as session:
            count = await session.scalar(
                select(func.count())
                .select_from(CVEEPSSScore)
                .where(CVEEPSSScore.cve_id == cve.id)
            )
        return int(count or 0)

    async def run_row(self) -> tuple[SyncEpssScores, uuid.UUID]:
        """A committed `running` FetcherRun under a test-only configuration
        name, as the atomic acquisition leaves it before `run()`."""
        name = f"test_epss_run_{uuid.uuid4().hex[:12]}"
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
        self.run_names.append(name)
        return self.fetcher(), run_id

    async def run_outcome(self, run_id: uuid.UUID) -> FetcherRun:
        async with self.factory() as session:
            run = await session.get(FetcherRun, run_id)
        assert run is not None
        return run

    async def cleanup(self) -> None:
        await self.world.cleanup()
        if self.run_names:
            async with self.factory() as session:
                await session.execute(
                    delete(FetcherRun).where(
                        FetcherRun.fetcher_name.in_(self.run_names)
                    )
                )
                await session.execute(
                    delete(FetcherConfig).where(
                        FetcherConfig.fetcher_name.in_(self.run_names)
                    )
                )
                await session.commit()


@pytest.fixture
async def env(
    db_session_factory: SessionFactory,
    real_session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> AsyncIterator[Env]:
    world = IngestionWorld(db_session_factory, await db_session_factory())
    created = Env(
        world=world,
        factory=real_session_factory,
        server=EpssServer(),
        published=Publications(),
    )

    def status_sessions() -> AsyncSession:
        created.status_opened[0] += 1
        return real_session_factory()

    real_scope = cve_service.get_active_ticket_cve_ids

    async def scope(session: AsyncSession) -> list[str]:
        created.requests_at_scope.append(len(created.server.requests))
        selected = await real_scope(session)
        created.scope_calls.append(selected)
        return [cve_id for cve_id in selected if cve_id in created.cve_ids]

    async def sleep(delay: float) -> None:
        created.sleeps.append(delay)

    monkeypatch.setattr(
        base_cve_fetcher_module, "async_session_factory", status_sessions
    )
    monkeypatch.setattr(
        base_fetcher_module, "async_session_factory", real_session_factory
    )
    monkeypatch.setattr(task_publication, "publish_task", created.published)
    monkeypatch.setattr(cve_service, "get_active_ticket_cve_ids", scope)
    monkeypatch.setattr(sync_module, "asyncio", SimpleNamespace(sleep=sleep))
    monkeypatch.setattr(sync_module, "_utc_today", lambda: TODAY)
    try:
        yield created
    finally:
        await created.cleanup()


@dataclass
class Batch:
    """`execute()` invocations on a reusable session with real commits,
    under the automatic periodic context that `run()` establishes."""

    env: Env
    fetcher: SyncEpssScores
    session: AsyncSession

    async def execute(self) -> None:
        if self.fetcher._http_client is None:
            self.fetcher._http_client = self.env.server.client()
        try:
            await self.fetcher.execute(self.session)
        finally:
            await self.fetcher._teardown_http_client()


@pytest.fixture
async def batch(env: Env) -> Batch:
    fetcher = env.fetcher()
    fetcher.config = FetcherRunConfig(
        hard_time_limit_seconds=3600, request_delay=0.25, custom_settings={}
    )
    fetcher._periodic_context = True
    return Batch(env, fetcher, await env.world.open_session())


def _fail_upsert_for(
    monkeypatch: pytest.MonkeyPatch, cve_ids: set[str], error: BaseException
) -> None:
    """Make `upsert_cve()` raise `error` for `cve_ids` after it has written
    that CVE's score and success status in the same transaction."""
    real = cve_service.upsert_cve

    async def upsert_cve(
        session: AsyncSession, cve_id: str, source: Any, payload: Any
    ) -> Any:
        result = await real(session, cve_id, source, payload)
        if cve_id in cve_ids:
            raise error
        return result

    monkeypatch.setattr(cve_service, "upsert_cve", upsert_cve)


def _spy_staleness(
    monkeypatch: pytest.MonkeyPatch, fetcher: SyncEpssScores
) -> list[date]:
    """Record every `_check_staleness()` argument; calls through."""
    calls: list[date] = []
    real = fetcher._check_staleness

    def check(assessed_at: date) -> None:
        calls.append(assessed_at)
        real(assessed_at)

    monkeypatch.setattr(fetcher, "_check_staleness", check)
    return calls


Plan = list[str]
"""Per-CVE outcome codes, in request order."""


async def _planned(env: Env, plan: Plan) -> list[CVE]:
    """Committed CVEs whose responses follow `plan` in request order."""
    cves = [await env.active_cve() for _ in plan]
    ordered = sorted(cves, key=lambda cve: cve.cve_id)
    for cve, outcome in zip(ordered, plan, strict=True):
        if outcome == "ok":
            await env.seed_score(cve)
            env.serve(cve)
        elif outcome == "updated":
            env.serve(cve)
        elif outcome == "missing":
            pass
        elif outcome == "connect":
            env.respond(cve, raising(httpx.ConnectError("refused")))
        elif outcome == "timeout":
            env.respond(cve, raising(httpx.ReadTimeout("timed out")))
        elif outcome == "json":
            env.respond(cve, status(200, b"{"))
        elif outcome == "schema":
            env.respond(cve, body(envelope(entry_for(cve.cve_id, epss="2.0"))))
        else:
            env.respond(cve, status(int(outcome)))
    return ordered


# ---------------------------------------------------------------------------
# Scope snapshot and per-CVE finalization
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestScope:
    async def test_one_snapshot_at_entry_selects_only_active_ticket_cves(
        self, env: Env, batch: Batch, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        active = []
        for ticket_status in (
            TicketStatus.NEW,
            TicketStatus.ANALYSIS,
            TicketStatus.ANALYZED,
        ):
            cve = await env.active_cve(status=ticket_status)
            env.serve(cve)
            active.append(cve)
        inactive = []
        for ticket_status in (TicketStatus.RESOLVED, TicketStatus.IGNORED):
            cve = await env.active_cve(status=ticket_status)
            env.serve(cve)
            inactive.append(cve)
        # A ticketless CVE, admitted by the spy, and a CVE-less active Ticket.
        ticketless = await env.world.cve_in()
        env.cve_ids.append(ticketless.cve_id)
        env.serve(ticketless)
        await env.world.ticket(cve_id=None, status=TicketStatus.ANALYSIS)
        private_calls: list[None] = []
        real_private = batch.fetcher._get_active_ticket_cve_ids

        async def private(session: AsyncSession) -> list[str]:
            private_calls.append(None)
            return await real_private(session)

        monkeypatch.setattr(batch.fetcher, "_get_active_ticket_cve_ids", private)

        await batch.execute()

        assert len(private_calls) == 1
        assert len(env.scope_calls) == 1
        assert env.requests_at_scope == [0]
        expected = sorted(cve.cve_id for cve in active)
        assert env.server.requested_cve_ids == expected
        excluded = {cve.cve_id for cve in inactive} | {ticketless.cve_id}
        assert not excluded & set(env.scope_calls[0])
        # Pre-scope exclusions contribute no terminal or effect metric.
        assert counters(batch.fetcher) == Counters(3, 0, 3, 0)
        for cve in [*inactive, ticketless]:
            assert await env.source_status(cve) is None
            assert await env.score(cve) is None

    async def test_ticket_created_mid_run_is_not_added_to_the_snapshot(
        self, env: Env, batch: Batch, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        first = await env.unchanged_cve()
        late: list[CVE] = []
        real_flush = batch.session.flush

        async def flush(*args: Any, **kwargs: Any) -> None:
            await real_flush(*args, **kwargs)
            if not late:
                late.append(await env.unchanged_cve())

        monkeypatch.setattr(batch.session, "flush", flush)

        await batch.execute()

        assert late
        assert env.server.requested_cve_ids == [first.cve_id]
        assert counters(batch.fetcher) == Counters(1, 0, 0, 0)

    async def test_empty_scope_requests_nothing_and_succeeds(
        self, env: Env, batch: Batch
    ) -> None:
        with capture_logs() as logs:
            await batch.execute()

        assert env.server.requests == []
        assert env.sleeps == []
        assert counters(batch.fetcher) == Counters(0, 0, 0, 0)
        assert logs == []


@pytest.mark.integration
class TestFinalization:
    async def test_flush_precedes_finalization_and_effects_follow_commit(
        self, env: Env, batch: Batch, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cve = await env.updated_cve(epss="0.120000000", date="2026-10-05")
        events: list[str] = []
        pending_at_finalization: list[bool] = []
        at_commit: list[Counters] = []
        real_fetch = batch.fetcher.fetch_single
        real_finalize = batch.fetcher.commit_and_dispatch
        real_flush = batch.session.flush
        real_commit = batch.session.commit
        inside_fetch = [False]

        async def fetch_single(cve_id: str, session: AsyncSession) -> Any:
            events.append("fetch_single")
            inside_fetch[0] = True
            try:
                return await real_fetch(cve_id, session)
            finally:
                inside_fetch[0] = False

        async def commit_and_dispatch(session: AsyncSession, result: Any) -> None:
            events.append("commit_and_dispatch")
            pending_at_finalization.append(
                bool(session.new or session.dirty or session.deleted)
            )
            await real_finalize(session, result)

        async def flush(*args: Any, **kwargs: Any) -> None:
            # The delegates' own flushes happen inside fetch_single().
            if not inside_fetch[0]:
                events.append("flush")
            await real_flush(*args, **kwargs)

        async def commit() -> None:
            events.append("commit")
            at_commit.append(counters(batch.fetcher))
            await real_commit()

        monkeypatch.setattr(batch.fetcher, "fetch_single", fetch_single)
        monkeypatch.setattr(batch.fetcher, "commit_and_dispatch", commit_and_dispatch)
        monkeypatch.setattr(batch.session, "flush", flush)
        monkeypatch.setattr(batch.session, "commit", commit)

        await batch.execute()

        assert events == ["fetch_single", "flush", "commit_and_dispatch", "commit"]
        assert pending_at_finalization == [False]
        # The effect and the success are absent until the commit.
        assert at_commit == [Counters(0, 0, 0, 0)]
        assert counters(batch.fetcher) == Counters(1, 0, 1, 0)
        assert await env.source_status(cve) == CVESourceFetchStatus.SUCCESS
        assert await env.score(cve) == (0.12, 0.5, date(2026, 10, 5))
        # No package handoff: post_ingest is None.
        assert env.published.calls == []
        assert env.status_opened == [0]
        assert env.sleeps == [0.25]

    async def test_unchanged_records_success_without_effect(
        self, env: Env, batch: Batch
    ) -> None:
        cve = await env.unchanged_cve()

        with capture_logs() as logs:
            await batch.execute()

        assert await env.source_status(cve) == CVESourceFetchStatus.SUCCESS
        assert counters(batch.fetcher) == Counters(1, 0, 0, 0)
        assert _events(logs, CVE_FETCH_ITEM_FAILED_EVENT) == []
        assert env.published.calls == []

    async def test_commit_failure_terminates_without_status_warning_or_metric(
        self, env: Env, batch: Batch, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        first = await env.updated_cve()
        second = await env.updated_cve()
        error = RuntimeError(FAILURE_TEXT)

        async def commit() -> None:
            raise error

        monkeypatch.setattr(batch.session, "commit", commit)

        with capture_logs() as logs, pytest.raises(RuntimeError) as raised:
            await batch.execute()

        assert raised.value is error
        ordered = sorted([first, second], key=lambda cve: cve.cve_id)
        assert env.server.requested_cve_ids == [ordered[0].cve_id]
        assert counters(batch.fetcher) == Counters(0, 0, 0, 0)
        assert env.status_opened == [0]
        assert _events(logs, CVE_FETCH_ITEM_FAILED_EVENT) == []
        assert await env.source_status(ordered[0]) is None
        assert await env.score(ordered[0]) is None
        assert env.sleeps == []

    async def test_ambiguous_commit_terminates_without_isolated_status_or_metric(
        self, env: Env, batch: Batch, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cve = await env.updated_cve()
        real_commit = batch.session.commit
        error = ConnectionResetError("commit outcome unknown")

        async def commit() -> None:
            await real_commit()
            raise error

        monkeypatch.setattr(batch.session, "commit", commit)

        with capture_logs() as logs, pytest.raises(ConnectionResetError):
            await batch.execute()

        assert counters(batch.fetcher) == Counters(0, 0, 0, 0)
        assert env.status_opened == [0]
        assert _events(logs, CVE_FETCH_ITEM_FAILED_EVENT) == []
        # The durable commit is never reclassified as an isolated failure.
        assert await env.source_status(cve) == CVESourceFetchStatus.SUCCESS

    async def test_non_operational_post_commit_error_aborts_and_keeps_success(
        self, env: Env, batch: Batch, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cves = [await env.updated_cve(), await env.updated_cve()]
        ordered = sorted(cves, key=lambda cve: cve.cve_id)
        error = RuntimeError(FAILURE_TEXT)

        async def drain(session: AsyncSession) -> None:
            raise error

        monkeypatch.setattr(
            ticket_convergence_publication, "drain_ticket_convergence", drain
        )

        with capture_logs() as logs, pytest.raises(RuntimeError) as raised:
            await batch.execute()

        assert raised.value is error
        assert env.server.requested_cve_ids == [ordered[0].cve_id]
        # Success and effect were recorded after the commit; no failure.
        assert counters(batch.fetcher) == Counters(1, 0, 1, 0)
        assert env.status_opened == [0]
        assert _events(logs, CVE_FETCH_ITEM_FAILED_EVENT) == []
        assert await env.source_status(ordered[0]) == CVESourceFetchStatus.SUCCESS
        assert await env.score_count(ordered[0]) == 1
        assert await env.source_status(ordered[1]) is None
        assert env.sleeps == []


# ---------------------------------------------------------------------------
# Missing and per-item failures
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestMissing:
    async def test_empty_data_is_an_isolated_missing_status_and_success(
        self, env: Env, batch: Batch
    ) -> None:
        cve = await env.active_cve()

        with capture_logs() as logs:
            await batch.execute()

        assert env.server.requested_cve_ids == [cve.cve_id]
        assert await env.source_status(cve) == CVESourceFetchStatus.MISSING
        assert await env.score(cve) is None
        assert env.status_opened == [1]
        assert counters(batch.fetcher) == Counters(1, 0, 0, 0)
        assert logs == []
        assert env.published.calls == []
        assert env.sleeps == [0.25]

    async def test_missing_retains_a_stored_score(self, env: Env, batch: Batch) -> None:
        cve = await env.active_cve()
        await env.seed_score(cve)

        await batch.execute()

        assert await env.source_status(cve) == CVESourceFetchStatus.MISSING
        assert await env.score(cve) == (0.5, 0.5, date(2026, 10, 6))


@pytest.mark.integration
class TestItemFailure:
    async def test_failure_rolls_back_writes_isolated_failure_and_one_event(
        self, env: Env, batch: Batch, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        failing = await env.updated_cve()
        other = await env.unchanged_cve()
        _fail_upsert_for(monkeypatch, {failing.cve_id}, RuntimeError(FAILURE_TEXT))

        with capture_logs(processors=[merge_contextvars]) as logs:
            await batch.execute()

        # upsert_cve() wrote the score and success status; rollback
        # discarded both before the isolated failure status.
        assert await env.score(failing) is None
        assert await env.source_status(failing) == CVESourceFetchStatus.FAILURE
        assert await env.source_status(other) == CVESourceFetchStatus.SUCCESS
        assert env.status_opened == [1]
        assert _events(logs, CVE_FETCH_ITEM_FAILED_EVENT) == [
            {
                "event": CVE_FETCH_ITEM_FAILED_EVENT,
                "log_level": "warning",
                "cve_id": failing.cve_id,
                "fetcher_name": NAME,
                "cause": "RuntimeError",
            }
        ]
        assert counters(batch.fetcher) == Counters(1, 0, 0, 1)
        assert env.published.calls == []
        _assert_private(logs)

    @pytest.mark.parametrize(
        ("responder", "cause"),
        [
            (status(403, FAILURE_TEXT.encode()), "HTTPStatusError"),
            (status(429, FAILURE_TEXT.encode()), "HTTPStatusError"),
            (status(503, FAILURE_TEXT.encode()), "HTTPStatusError"),
            (status(200, f"{{{FAILURE_TEXT}".encode()), "JSONDecodeError"),
            (
                body(envelope(entry_for("CVE-2099-48001", percentile=FAILURE_TEXT))),
                "ValidationError",
            ),
            (
                body(envelope(entry_for("CVE-2099-48001", epss="1.000000001"))),
                "ValidationError",
            ),
            (
                body(
                    envelope(
                        entry_for("CVE-2099-48001"),
                        entry_for("CVE-2099-48002", date=FAILURE_TEXT),
                    )
                ),
                "ValidationError",
            ),
            (body([FAILURE_TEXT]), "ValidationError"),
            (raising(httpx.ConnectError(FAILURE_TEXT)), "ConnectError"),
        ],
        ids=[
            "forbidden",
            "rate_limited",
            "server_error",
            "json",
            "schema",
            "out_of_range",
            "two_entries",
            "array_root",
            "connect",
        ],
    )
    async def test_event_names_only_the_exception_class(
        self, responder: Responder, cause: str, env: Env, batch: Batch
    ) -> None:
        cve = await env.active_cve()
        env.respond(cve, responder)

        with capture_logs() as logs:
            await batch.execute()

        assert _events(logs, CVE_FETCH_ITEM_FAILED_EVENT) == [
            {
                "event": CVE_FETCH_ITEM_FAILED_EVENT,
                "log_level": "warning",
                "cve_id": cve.cve_id,
                "fetcher_name": NAME,
                "cause": cause,
            }
        ]
        assert set(_events(logs, CVE_FETCH_ITEM_FAILED_EVENT)[0]) == FAILED_EVENT_KEYS
        _assert_private(logs)
        assert await env.source_status(cve) == CVESourceFetchStatus.FAILURE
        assert await env.score(cve) is None
        assert counters(batch.fetcher) == Counters(0, 0, 0, 1)
        assert env.sleeps == [0.25]

    @pytest.mark.parametrize("member", ["epss", "percentile", "date"])
    async def test_nul_in_a_consumed_field_is_an_isolated_failure(
        self, member: str, env: Env, batch: Batch
    ) -> None:
        cve = await env.active_cve()
        await env.seed_score(cve)
        env.serve(cve, **{member: f"{SCORED[member]}\x00"})

        with capture_logs() as logs:
            await batch.execute()

        assert await env.source_status(cve) == CVESourceFetchStatus.FAILURE
        # The stored score is untouched; no database error occurred.
        assert await env.score(cve) == (0.5, 0.5, date(2026, 10, 6))
        assert [
            entry["cause"] for entry in _events(logs, CVE_FETCH_ITEM_FAILED_EVENT)
        ] == ["ValidationError"]
        assert counters(batch.fetcher) == Counters(0, 0, 0, 1)
        _assert_private(logs)

    async def test_flush_failure_is_an_isolated_item_failure(
        self, env: Env, batch: Batch, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        first, second = sorted(
            [await env.updated_cve(), await env.updated_cve()],
            key=lambda cve: cve.cve_id,
        )
        real_fetch = batch.fetcher.fetch_single
        real_finalize = batch.fetcher.commit_and_dispatch
        real_flush = batch.session.flush
        inside_fetch = [False]
        own_flushes: list[str] = []
        finalized: list[str] = []
        current: list[str] = []

        async def fetch_single(cve_id: str, session: AsyncSession) -> Any:
            current[:] = [cve_id]
            inside_fetch[0] = True
            try:
                return await real_fetch(cve_id, session)
            finally:
                inside_fetch[0] = False

        async def commit_and_dispatch(session: AsyncSession, result: Any) -> None:
            finalized.extend(current)
            await real_finalize(session, result)

        async def flush(*args: Any, **kwargs: Any) -> None:
            await real_flush(*args, **kwargs)
            # Only the template's own per-item flush of the first CVE fails;
            # the delegates' flushes inside fetch_single() succeed.
            if not inside_fetch[0]:
                own_flushes.extend(current)
                if current == [first.cve_id]:
                    raise RuntimeError(FAILURE_TEXT)

        monkeypatch.setattr(batch.fetcher, "fetch_single", fetch_single)
        monkeypatch.setattr(batch.fetcher, "commit_and_dispatch", commit_and_dispatch)
        monkeypatch.setattr(batch.session, "flush", flush)

        with capture_logs() as logs:
            await batch.execute()

        assert own_flushes == [first.cve_id, second.cve_id]
        assert finalized == [second.cve_id]
        assert await env.source_status(first) == CVESourceFetchStatus.FAILURE
        assert await env.score(first) is None
        assert await env.source_status(second) == CVESourceFetchStatus.SUCCESS
        assert await env.score(second) is not None
        assert [
            (entry["cve_id"], entry["cause"])
            for entry in _events(logs, CVE_FETCH_ITEM_FAILED_EVENT)
        ] == [(first.cve_id, "RuntimeError")]
        assert counters(batch.fetcher) == Counters(1, 0, 1, 1)
        _assert_private(logs)


# ---------------------------------------------------------------------------
# Consecutive infrastructure failures
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestConsecutiveFailures:
    @pytest.mark.parametrize(
        "plan",
        [
            ["503", "500", "502", "ok"],
            ["connect", "timeout", "503", "ok"],
        ],
        ids=["http_5xx", "transport_and_5xx"],
    )
    async def test_third_infrastructure_failure_aborts_with_the_sanitized_error(
        self, plan: Plan, env: Env, batch: Batch
    ) -> None:
        ordered = await _planned(env, plan)

        with pytest.raises(FetcherError) as raised:
            await batch.execute()

        assert str(raised.value) == ABORT_MESSAGE
        assert isinstance(raised.value.__cause__, httpx.HTTPError)
        assert env.server.requested_cve_ids == [cve.cve_id for cve in ordered[:3]]
        assert counters(batch.fetcher) == Counters(0, 0, 0, 3)
        for cve in ordered[:3]:
            assert await env.source_status(cve) == CVESourceFetchStatus.FAILURE
        assert await env.source_status(ordered[3]) is None
        assert env.sleeps == [0.25, 0.25]

    async def test_abort_chains_the_triggering_exception(
        self, env: Env, batch: Batch
    ) -> None:
        ordered = await _planned(env, ["503", "503", "ok"])
        error = httpx.ConnectError("refused")
        env.respond(ordered[2], raising(error))

        with pytest.raises(FetcherError) as raised:
            await batch.execute()

        assert raised.value.__cause__ is error

    @pytest.mark.parametrize(
        "plan",
        [
            ["503", "503", "ok", "503", "503"],
            ["503", "503", "updated", "503", "503"],
            ["503", "503", "missing", "503", "503"],
            ["503", "503", "429", "503", "503"],
            ["503", "503", "403", "503", "503"],
            ["503", "503", "schema", "503", "503"],
            ["503", "503", "json", "503", "503"],
        ],
        ids=[
            "unchanged",
            "updated",
            "missing",
            "http_429",
            "http_403",
            "data_quality",
            "unparseable",
        ],
    )
    async def test_reachability_resets_the_counter(
        self, plan: Plan, env: Env, batch: Batch
    ) -> None:
        ordered = await _planned(env, plan)

        await batch.execute()

        assert env.server.requested_cve_ids == [cve.cve_id for cve in ordered]
        failed = sum(outcome not in {"ok", "updated", "missing"} for outcome in plan)
        succeeded = len(plan) - failed
        updated = plan.count("updated")
        assert counters(batch.fetcher) == Counters(succeeded, 0, updated, failed)

    async def test_non_infrastructure_failures_never_abort(
        self, env: Env, batch: Batch
    ) -> None:
        ordered = await _planned(env, ["403", "429", "json", "schema", "401"])

        await batch.execute()

        assert env.server.requested_cve_ids == [cve.cve_id for cve in ordered]
        assert counters(batch.fetcher) == Counters(0, 0, 0, 5)


# ---------------------------------------------------------------------------
# Whole-run signals and request delay
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestWholeRunSignals:
    @pytest.mark.parametrize(
        "signal",
        [asyncio.CancelledError(), SoftTimeLimitExceeded(), MemoryError()],
        ids=lambda signal: type(signal).__name__,
    )
    async def test_signal_propagates_without_item_handling(
        self, signal: BaseException, env: Env, batch: Batch
    ) -> None:
        await env.updated_cve()
        await env.updated_cve()

        def respond(request: httpx.Request) -> httpx.Response:
            raise signal

        env.server.responses.update(dict.fromkeys(env.server.entries, respond))

        with capture_logs() as logs, pytest.raises(type(signal)) as raised:
            await batch.execute()

        assert raised.value is signal
        assert len(env.server.requests) == 1
        assert counters(batch.fetcher) == Counters(0, 0, 0, 0)
        assert env.status_opened == [0]
        assert logs == []
        assert env.sleeps == []


@pytest.mark.integration
class TestRequestDelay:
    async def test_configured_delay_follows_every_selected_cve(
        self, env: Env, batch: Batch
    ) -> None:
        ordered = await _planned(env, ["ok", "missing", "403", "503"])

        await batch.execute()

        assert env.server.requested_cve_ids == [cve.cve_id for cve in ordered]
        assert env.sleeps == [0.25, 0.25, 0.25, 0.25]

    async def test_missing_configuration_snapshot_uses_no_delay(
        self, env: Env, batch: Batch
    ) -> None:
        await env.unchanged_cve()
        batch.fetcher.config = None

        await batch.execute()

        assert env.sleeps == [0.0]


# ---------------------------------------------------------------------------
# Diagnostic staleness check
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestStaleness:
    @pytest.mark.parametrize(
        "assessed", ["2026-10-05", "2026-10-06", "2026-10-07"], ids=str
    )
    async def test_today_minus_one_or_later_is_not_stale(
        self, assessed: str, env: Env, batch: Batch, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        await env.updated_cve(date=assessed)
        checks = _spy_staleness(monkeypatch, batch.fetcher)

        with capture_logs() as logs:
            await batch.execute()

        assert checks == [date.fromisoformat(assessed)]
        assert logs == []

    async def test_today_minus_two_logs_one_bounded_warning(
        self, env: Env, batch: Batch
    ) -> None:
        cve = await env.updated_cve(
            epss="0.987650000", percentile="0.123450000", date="2026-10-04"
        )

        with capture_logs() as logs:
            await batch.execute()

        assert logs == [
            {
                "event": EPSS_DATA_STALE_EVENT,
                "log_level": "warning",
                "fetcher_name": NAME,
                "assessed_at": "2026-10-04",
                "expected": "2026-10-06",
            }
        ]
        # Stale data is still ingested.
        assert await env.score(cve) == (0.98765, 0.12345, date(2026, 10, 4))
        assert counters(batch.fetcher) == Counters(1, 0, 1, 0)

    async def test_evaluated_once_with_the_first_parsed_date(
        self, env: Env, batch: Batch, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cves = [await env.active_cve() for _ in range(4)]
        ordered = sorted(cves, key=lambda cve: cve.cve_id)
        env.respond(ordered[0], status(503))
        env.serve(ordered[1], date="2026-10-01")
        env.serve(ordered[2], date="2026-10-02")
        env.serve(ordered[3], date="2026-10-03")
        checks = _spy_staleness(monkeypatch, batch.fetcher)

        with capture_logs() as logs:
            await batch.execute()

        assert checks == [date(2026, 10, 1)]
        assert [
            entry["assessed_at"] for entry in _events(logs, EPSS_DATA_STALE_EVENT)
        ] == ["2026-10-01"]

    async def test_first_parse_is_evaluated_when_its_ingestion_fails(
        self, env: Env, batch: Batch, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # The assessment date is cached by the first successful parse
        # (Algorithm, Staleness validation), before upsert_cve().
        first, second = sorted(
            [await env.updated_cve(date="2026-10-01"), await env.updated_cve()],
            key=lambda cve: cve.cve_id,
        )
        env.serve(first, date="2026-10-01")
        env.serve(second, date="2026-10-06")
        _fail_upsert_for(monkeypatch, {first.cve_id}, RuntimeError(FAILURE_TEXT))
        checks = _spy_staleness(monkeypatch, batch.fetcher)

        with capture_logs() as logs:
            await batch.execute()

        assert checks == [date(2026, 10, 1)]
        assert len(_events(logs, EPSS_DATA_STALE_EVENT)) == 1
        assert counters(batch.fetcher) == Counters(1, 0, 1, 1)

    async def test_no_successful_parse_skips_the_check(
        self, env: Env, batch: Batch, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        await _planned(env, ["missing", "schema", "429"])
        checks = _spy_staleness(monkeypatch, batch.fetcher)

        await batch.execute()

        assert checks == []

    async def test_ordinary_check_exception_is_swallowed_without_effect(
        self, env: Env, batch: Batch, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # A first success then two infrastructure failures: counting the
        # swallowed exception as a failure would abort the run.
        ordered = await _planned(env, ["ok", "503", "503"])
        calls: list[date] = []

        def check(assessed_at: date) -> None:
            calls.append(assessed_at)
            raise RuntimeError(FAILURE_TEXT)

        monkeypatch.setattr(batch.fetcher, "_check_staleness", check)

        with capture_logs() as logs:
            await batch.execute()

        assert calls == [date(2026, 10, 6)]
        assert _events(logs, EPSS_STALENESS_CHECK_FAILED_EVENT) == [
            {
                "event": EPSS_STALENESS_CHECK_FAILED_EVENT,
                "log_level": "debug",
                "fetcher_name": NAME,
                "cause": "RuntimeError",
            }
        ]
        assert counters(batch.fetcher) == Counters(1, 0, 0, 2)
        assert await env.source_status(ordered[0]) == CVESourceFetchStatus.SUCCESS
        assert [
            entry["cve_id"] for entry in _events(logs, CVE_FETCH_ITEM_FAILED_EVENT)
        ] == [ordered[1].cve_id, ordered[2].cve_id]
        assert env.server.requested_cve_ids == [cve.cve_id for cve in ordered]
        _assert_private(logs)

    @pytest.mark.parametrize(
        "signal",
        [asyncio.CancelledError(), SoftTimeLimitExceeded(), MemoryError()],
        ids=lambda signal: type(signal).__name__,
    )
    async def test_whole_run_signal_in_the_check_propagates(
        self,
        signal: BaseException,
        env: Env,
        batch: Batch,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        ordered = await _planned(env, ["updated", "updated"])

        def check(assessed_at: date) -> None:
            raise signal

        monkeypatch.setattr(batch.fetcher, "_check_staleness", check)

        with capture_logs() as logs, pytest.raises(type(signal)) as raised:
            await batch.execute()

        assert raised.value is signal
        assert env.server.requested_cve_ids == [ordered[0].cve_id]
        assert await env.source_status(ordered[0]) == CVESourceFetchStatus.SUCCESS
        assert counters(batch.fetcher) == Counters(1, 0, 1, 0)
        assert logs == []
        assert env.sleeps == []

    @pytest.mark.parametrize("second", ["missing", "fresh"])
    async def test_reused_instance_never_evaluates_a_previous_run_date(
        self, second: str, env: Env, batch: Batch, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cve = await env.updated_cve(date="2026-09-01")
        checks = _spy_staleness(monkeypatch, batch.fetcher)
        with capture_logs() as first_logs:
            await batch.execute()
        assert len(_events(first_logs, EPSS_DATA_STALE_EVENT)) == 1
        if second == "missing":
            del env.server.entries[cve.cve_id]
        else:
            env.serve(cve, date="2026-10-06")

        with capture_logs() as second_logs:
            await batch.execute()

        assert _events(second_logs, EPSS_DATA_STALE_EVENT) == []
        if second == "missing":
            assert checks == [date(2026, 9, 1)]
        else:
            assert checks == [date(2026, 9, 1), date(2026, 10, 6)]

    async def test_a_prior_on_demand_parse_is_not_evaluated(
        self, env: Env, batch: Batch, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cve = await env.updated_cve(date="2026-09-01")
        checks = _spy_staleness(monkeypatch, batch.fetcher)
        assert batch.fetcher._http_client is not None
        with capture_logs() as on_demand_logs:
            await batch.fetcher.fetch_single(cve.cve_id, batch.session)
        await batch.session.rollback()
        assert checks == []
        assert on_demand_logs == []
        del env.server.entries[cve.cve_id]

        with capture_logs() as logs:
            await batch.execute()

        assert checks == []
        assert _events(logs, EPSS_DATA_STALE_EVENT) == []


# ---------------------------------------------------------------------------
# run(): the sync_epss_scores metric mapping on a finalized FetcherRun
# ---------------------------------------------------------------------------

_RUN_CONFIG: Final = FetcherRunConfig(
    hard_time_limit_seconds=3600, request_delay=0, custom_settings={}
)


def _outcome(run: FetcherRun) -> tuple[str, int, int, int, int]:
    return (
        run.status,
        run.items_succeeded,
        run.items_created,
        run.items_updated,
        run.items_failed,
    )


def _forbid_record_created(
    monkeypatch: pytest.MonkeyPatch, fetcher: SyncEpssScores
) -> list[int]:
    calls: list[int] = []
    monkeypatch.setattr(fetcher, "record_created", calls.append)
    return calls


@pytest.mark.integration
class TestRunMetrics:
    async def test_success_run_maps_updated_unchanged_and_missing(
        self, env: Env, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        await env.updated_cve()
        await env.unchanged_cve()
        await env.active_cve()  # data: [] -> missing
        fetcher, run_id = await env.run_row()
        created = _forbid_record_created(monkeypatch, fetcher)

        await fetcher.run(run_id=run_id, config=_RUN_CONFIG)

        run = await env.run_outcome(run_id)
        # Never `record_created`: EPSS only enriches existing CVEs.
        assert _outcome(run) == ("success", 3, 0, 1, 0)
        assert run.error_message is None
        assert created == []
        assert env.sleeps == [0, 0, 0]

    async def test_repeat_run_is_unchanged(self, env: Env) -> None:
        await env.updated_cve()
        fetcher, first = await env.run_row()
        await fetcher.run(run_id=first, config=_RUN_CONFIG)
        fetcher, second = await env.run_row()

        await fetcher.run(run_id=second, config=_RUN_CONFIG)

        assert _outcome(await env.run_outcome(first)) == ("success", 1, 0, 1, 0)
        assert _outcome(await env.run_outcome(second)) == ("success", 1, 0, 0, 0)

    async def test_empty_run_is_success(self, env: Env) -> None:
        fetcher, run_id = await env.run_row()

        await fetcher.run(run_id=run_id, config=_RUN_CONFIG)

        assert _outcome(await env.run_outcome(run_id)) == ("success", 0, 0, 0, 0)
        assert env.server.requests == []

    async def test_unchanged_success_plus_failure_is_partial(
        self, env: Env, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        await env.unchanged_cve()
        failing = await env.active_cve()
        env.respond(failing, body(envelope(entry_for(failing.cve_id, epss="7"))))
        fetcher, run_id = await env.run_row()
        created = _forbid_record_created(monkeypatch, fetcher)

        with capture_logs(processors=[merge_contextvars]) as logs:
            await fetcher.run(run_id=run_id, config=_RUN_CONFIG)

        assert _outcome(await env.run_outcome(run_id)) == ("partial", 1, 0, 0, 1)
        assert created == []
        # The per-item event binds to the run's correlation context.
        assert _events(logs, CVE_FETCH_ITEM_FAILED_EVENT) == [
            {
                "event": CVE_FETCH_ITEM_FAILED_EVENT,
                "log_level": "warning",
                "cve_id": failing.cve_id,
                "fetcher_name": NAME,
                "cause": "ValidationError",
                "fetcher_run_id": str(run_id),
            }
        ]

    async def test_all_failed_is_failure(self, env: Env) -> None:
        await _planned(env, ["403", "json", "schema"])
        fetcher, run_id = await env.run_row()

        await fetcher.run(run_id=run_id, config=_RUN_CONFIG)

        run = await env.run_outcome(run_id)
        assert _outcome(run) == ("failure", 0, 0, 0, 3)
        assert run.error_message == "All 3 items failed"

    async def test_abort_is_a_failure_with_the_sanitized_message(
        self, env: Env
    ) -> None:
        await _planned(env, ["updated", "503", "503", "503"])
        fetcher, run_id = await env.run_row()

        with pytest.raises(FetcherError):
            await fetcher.run(run_id=run_id, config=_RUN_CONFIG)

        run = await env.run_outcome(run_id)
        assert _outcome(run) == ("failure", 1, 0, 1, 3)
        assert run.error_message == ABORT_MESSAGE
        assert run.error_detail is not None

    async def test_post_commit_error_fails_the_run_and_keeps_success_metrics(
        self, env: Env, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cve = await env.updated_cve()
        fetcher, run_id = await env.run_row()

        async def drain(session: AsyncSession) -> None:
            raise RuntimeError(FAILURE_TEXT)

        monkeypatch.setattr(
            ticket_convergence_publication, "drain_ticket_convergence", drain
        )

        with pytest.raises(RuntimeError):
            await fetcher.run(run_id=run_id, config=_RUN_CONFIG)

        run = await env.run_outcome(run_id)
        assert _outcome(run) == ("failure", 1, 0, 1, 0)
        assert run.error_message == "Unexpected error"
        assert await env.source_status(cve) == CVESourceFetchStatus.SUCCESS
        assert env.status_opened == [0]

    async def test_commit_failure_fails_the_run_without_unit_metrics(
        self, env: Env, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cve = await env.updated_cve()
        fetcher, run_id = await env.run_row()
        error = RuntimeError(FAILURE_TEXT)
        real_factory = env.factory

        def execution_sessions() -> AsyncSession:
            session = real_factory()

            async def commit() -> None:
                raise error

            monkeypatch.setattr(session, "commit", commit)
            return session

        calls = [0]

        def factory() -> AsyncSession:
            # Cursor load, then the execution session, then finalization:
            # only the execution session fails to commit.
            calls[0] += 1
            return execution_sessions() if calls[0] == 2 else real_factory()

        monkeypatch.setattr(base_fetcher_module, "async_session_factory", factory)

        with pytest.raises(RuntimeError):
            await fetcher.run(run_id=run_id, config=_RUN_CONFIG)

        run = await env.run_outcome(run_id)
        assert _outcome(run) == ("failure", 0, 0, 0, 0)
        assert run.error_message == "Unexpected error"
        assert await env.source_status(cve) is None
        assert await env.score(cve) is None
        assert env.status_opened == [0]
