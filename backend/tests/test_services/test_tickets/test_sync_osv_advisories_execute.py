"""Tests for the periodic batch `SyncOsvAdvisories.execute()` and its `run()`
metrics (backend/app/services/tickets/sync_osv_advisories.py).

Owning specifications:

- docs/features/tickets/cve-sync-osv.md (Algorithm; `fetch_single` Method
  class structure; Error Handling, `execute()` table, abort threshold
  semantics, sanitized messages; Metrics; Custom Settings, Operational notes;
  `CompletenessGuardError`, caller handling).
- docs/features/platform/cve-fetcher-infrastructure.md (Per-CVE
  Finalization; Session Lifecycle for API-based CVE Fetchers, template 1,
  Scope snapshot; Batch Error Handling, Per-item failure event and
  Consecutive failure abort; Metric Definitions).
- docs/features/tickets/cve-service.md (Active-Ticket CVE Scope).
- docs/features/platform/fetcher-infrastructure.md (Outcome and effect
  accounting; Error Message Sanitization; `SoftTimeLimitExceeded` handling
  convention; Runtime Configuration Snapshot) and
  docs/features/platform/logging.md (Secrets and PII Discipline;
  Correlation IDs, Fetcher run binding detail).
- docs/features/platform/testing-strategy.md (CVE Fetcher Infrastructure:
  One-shot finalization, Periodic metrics, Isolated statuses; Fetcher
  Outcome and Effect Accounting, the `sync_osv_advisories` mapping).

Every test commits real rows: CVEs with Tickets of an `IngestionWorld`
(deleted with their children, references, and Ticket events at teardown),
the isolated status sessions (`base_cve_fetcher.async_session_factory`) on
`real_session_factory`, and, for `run()`, a committed
`FetcherConfig`/`FetcherRun` pair under a test-only name, deleted at
teardown. `execute()` tests use an independent `db_session_factory` session
with real commits and set the automatic periodic context that `run()`
establishes, so the finalizer records metrics. The scope query is the real
`cve_service.get_active_ticket_cve_ids()` wrapped by a spy that restricts
the snapshot to this test's CVEs, so rows committed by no other test can
enter it. HTTP is the in-process `OsvServer`; alias IDs carry no
whitelisted prefix, so no committed run writes a global external
identifier, and each package-bearing alias record names its own CVE so
that it applies (Algorithm step 6). The broker call is the recorded
`task_publication.publish_task`; every `asyncio.sleep` of the module (the
step-13 throttle and the inter-CVE delay) is recorded instead of slept.
All identifiers and texts are fictional.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable, Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any, Final, NamedTuple

import httpx
import pytest
from celery.exceptions import OperationalError as BrokerOperationalError
from celery.exceptions import SoftTimeLimitExceeded
from kombu.exceptions import EncodeError  # type: ignore[import-untyped]
from sqlalchemy import delete, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from structlog.contextvars import merge_contextvars
from structlog.testing import capture_logs

import app.services.base_cve_fetcher as base_cve_fetcher_module
import app.services.base_fetcher as base_fetcher_module
from app.core.enums import CVESourceFetchStatus, TicketStatus
from app.models.cve import CVE
from app.models.cve_affected_version import CVEAffectedVersion
from app.models.cve_source import CVESource
from app.models.fetcher_config import FetcherConfig
from app.models.fetcher_run import FetcherRun
from app.models.ticket import Ticket
from app.services import (
    cve_service,
    package_service,
    reference_service,
    task_publication,
)
from app.services.base_cve_fetcher import (
    CVE_FETCH_ITEM_FAILED_EVENT,
    HANDOFF_PUBLICATION_FAILED_EVENT,
)
from app.services.base_fetcher import FetcherError, FetcherRunConfig
from app.services.tickets import sync_osv_advisories as sync_module
from app.services.tickets.sync_osv_advisories import (
    OSV_SUBREQUEST_SKIPPED_EVENT,
    SyncOsvAdvisories,
)
from tests.support.cve_ingest import IngestionWorld
from tests.support.osv import OsvServer, raising, status

SessionFactory = Callable[[], Awaitable[AsyncSession]]

NAME: Final = "sync_osv_advisories"
RESOLVE: Final = package_service.RESOLVE_TICKET_PACKAGES_TASK
REPO: Final = "https://git.example.invalid/project/example"
URL_1: Final = "https://advisory.example.invalid/upstream/1"
FAILING: Final = "EXAMPLE-SA-2099-0503"
"""A sub-request that always answers HTTP 503."""
ABORT_MESSAGE: Final = (
    "sync_osv_advisories: source unreachable — aborted after 3 consecutive failures"
)
PERSONAL_TEXT: Final = "Reported by Alice Example <alice.example@example.invalid>"
SECRET_VALUE: Final = "api_token=Example-Secret-Token-0123456789"
FAILURE_TEXT: Final = f"{PERSONAL_TEXT}; {SECRET_VALUE}"
"""Exception text that must appear in no log field."""

FAILED_EVENT_KEYS: Final = frozenset(
    {"event", "log_level", "cve_id", "fetcher_name", "cause"}
)

GIT_AFFECTED: Final = [
    {"ranges": [{"type": "GIT", "repo": REPO, "events": [{"fixed": "c1"}]}]}
]

UNCHANGED_BODY: Final = {"references": [{"type": "WEB", "url": URL_1}]}
"""HTTP 200 body whose ingestion is `unchanged` without a handoff (one
request: the empty `osv` scope is replaced by an empty snapshot)."""

GUARD_BODY: Final = {
    "affected": [],
    "aliases": [FAILING, "CVE-2099-990000001", "x/y"],
    "related": ["EXAMPLE-SA-2099-0001"],
}
"""HTTP 200 body whose every alias sub-request fails (the `CVE-*` alias and
the `related` ID are not sub-requests): the completeness guard."""


class Counters(NamedTuple):
    succeeded: int
    created: int
    updated: int
    failed: int


def counters(fetcher: SyncOsvAdvisories) -> Counters:
    return Counters(
        fetcher._succeeded, fetcher._created, fetcher._updated, fetcher._failed
    )


def _events(logs: Iterable[Mapping[str, Any]], name: str) -> list[Mapping[str, Any]]:
    return [entry for entry in logs if entry["event"] == name]


# ---------------------------------------------------------------------------
# Harness
# ---------------------------------------------------------------------------


@dataclass
class Publications:
    """Substitute for `task_publication.publish_task`; `errors` maps a task
    name to the exception its publication raises."""

    calls: list[dict[str, Any]] = field(default_factory=list)
    errors: dict[str, BaseException] = field(default_factory=dict)

    async def __call__(self, task_name: str, **options: Any) -> None:
        self.calls.append({"task_name": task_name, **options})
        if task_name in self.errors:
            raise self.errors[task_name]

    def published(self, task_name: str) -> list[Any]:
        return [call["kwargs"] for call in self.calls if call["task_name"] == task_name]


@dataclass
class Env:
    world: IngestionWorld
    factory: async_sessionmaker[AsyncSession]
    server: OsvServer
    published: Publications
    scope_calls: list[list[str]] = field(default_factory=list)
    sleeps: list[tuple[float, int]] = field(default_factory=list)
    """Each recorded sleep and the number of requests made before it."""
    status_opened: list[int] = field(default_factory=lambda: [0])
    run_names: list[str] = field(default_factory=list)
    cve_ids: list[str] = field(default_factory=list)
    alias_ids: list[str] = field(default_factory=list)

    async def active_cve(
        self, body: Any = None, *, status: TicketStatus = TicketStatus.ANALYSIS
    ) -> CVE:
        """A committed CVE with a Ticket in `status`; `body` is served with
        HTTP 200 when given (otherwise the CVE is answered with 404)."""
        cve = await self.world.cve_in()
        await self.world.ticket(cve_id=cve.id, status=status)
        self.cve_ids.append(cve.cve_id)
        if body is not None:
            self.server.bodies[cve.cve_id] = body
        return cve

    async def updated_cve(self) -> CVE:
        """A committed active CVE served by `serve_updated()`."""
        cve = await self.active_cve()
        self.serve_updated(cve)
        return cve

    def serve_updated(
        self, cve: CVE, package_name: str = "example", **extra: Any
    ) -> None:
        """Serve `cve` with one `GIT` entry and one alias record that names
        it and the package `package_name`: its ingestion is `updated` with
        a package handoff (two requests). `extra` joins the Phase 1 body."""
        alias_id = f"EXAMPLE-SA-{cve.cve_id.removeprefix('CVE-')}"
        self.alias_ids.append(alias_id)
        self.server.bodies[cve.cve_id] = {
            "affected": GIT_AFFECTED,
            "aliases": [alias_id],
            **extra,
        }
        self.server.bodies[alias_id] = {
            "aliases": [cve.cve_id],
            "affected": [{"package": {"name": package_name}}],
        }

    async def duplicated_cve(self, body: Any) -> CVE:
        """A committed CVE whose only Ticket is `Duplicated` (of the
        latest world Ticket), served `body`."""
        canonical = self.world.ticket_ids[-1]
        cve = await self.active_cve(body)
        ticket_id = self.world.ticket_ids[-1]
        await self.world.session.execute(
            update(Ticket)
            .where(Ticket.id == ticket_id)
            .values(status=TicketStatus.DUPLICATED.value, duplicate_of_id=canonical)
        )
        await self.world.session.commit()
        return cve

    def respond(self, cve: CVE, responder: Any) -> None:
        self.server.responses[cve.cve_id] = responder

    @property
    def requested_cve_ids(self) -> list[str | None]:
        """The Phase 1 requests, in order."""
        return [
            record_id
            for record_id in self.server.requested_ids
            if record_id in self.cve_ids
        ]

    @property
    def delays(self) -> list[float]:
        return [delay for delay, _ in self.sleeps]

    def fetcher(self) -> SyncOsvAdvisories:
        instance = SyncOsvAdvisories()
        instance._http_client = self.server.client()
        return instance

    async def source_status(self, cve: CVE) -> str | None:
        async with self.factory() as session:
            status: str | None = await session.scalar(
                select(CVESource.status).where(
                    CVESource.cve_id == cve.id, CVESource.source == "osv"
                )
            )
        return status

    async def osv_row_count(self, cve: CVE) -> int:
        async with self.factory() as session:
            count = await session.scalar(
                select(func.count())
                .select_from(CVEAffectedVersion)
                .where(
                    CVEAffectedVersion.cve_id == cve.id,
                    CVEAffectedVersion.source_container == "osv",
                )
            )
        return int(count or 0)

    async def run_row(self) -> tuple[SyncOsvAdvisories, uuid.UUID]:
        """A committed `running` FetcherRun under a test-only configuration
        name, as the atomic acquisition leaves it before `run()`."""
        name = f"test_osv_run_{uuid.uuid4().hex[:12]}"
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
        server=OsvServer(),
        published=Publications(),
    )
    created.server.responses[FAILING] = status(503)

    def status_sessions() -> AsyncSession:
        created.status_opened[0] += 1
        return real_session_factory()

    real_scope = cve_service.get_active_ticket_cve_ids

    async def scope(session: AsyncSession) -> list[str]:
        selected = await real_scope(session)
        created.scope_calls.append(selected)
        return [cve_id for cve_id in selected if cve_id in created.cve_ids]

    async def sleep(delay: float) -> None:
        created.sleeps.append((delay, len(created.server.requests)))

    monkeypatch.setattr(
        base_cve_fetcher_module, "async_session_factory", status_sessions
    )
    monkeypatch.setattr(
        base_fetcher_module, "async_session_factory", real_session_factory
    )
    monkeypatch.setattr(task_publication, "publish_task", created.published)
    monkeypatch.setattr(cve_service, "get_active_ticket_cve_ids", scope)
    monkeypatch.setattr(sync_module, "asyncio", SimpleNamespace(sleep=sleep))
    try:
        yield created
    finally:
        await created.cleanup()


@dataclass
class Batch:
    """One `execute()` invocation on a reusable session with real commits,
    under the automatic periodic context that `run()` establishes."""

    env: Env
    fetcher: SyncOsvAdvisories
    session: AsyncSession

    async def execute(self) -> None:
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


def _fail_references_for(
    monkeypatch: pytest.MonkeyPatch, cve_ids: set[str], error: BaseException
) -> None:
    """Make `upsert_references()` raise `error` for `cve_ids`, after
    `upsert_cve()` has written that CVE's data in the same transaction."""
    real = reference_service.upsert_references

    async def upsert_references(
        session: AsyncSession, ticket_id: Any, cve_id: str, *args: Any
    ) -> None:
        if cve_id in cve_ids:
            raise error
        await real(session, ticket_id, cve_id, *args)

    monkeypatch.setattr(reference_service, "upsert_references", upsert_references)


def _ordered(cves: Iterable[CVE]) -> list[CVE]:
    return sorted(cves, key=lambda cve: cve.cve_id)


# ---------------------------------------------------------------------------
# Scope snapshot and per-CVE finalization
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestScope:
    async def test_one_snapshot_selects_active_cves_in_code_point_order(
        self, env: Env, batch: Batch, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        active = [
            await env.active_cve(UNCHANGED_BODY, status=status)
            for status in (
                TicketStatus.NEW,
                TicketStatus.ANALYSIS,
                TicketStatus.ANALYZED,
            )
        ]
        inactive = [
            await env.active_cve(UNCHANGED_BODY, status=status)
            for status in (TicketStatus.RESOLVED, TicketStatus.IGNORED)
        ]
        inactive.append(await env.duplicated_cve(UNCHANGED_BODY))
        # A ticketless CVE, admitted by the spy, is outside the real query.
        ticketless = await env.world.cve_in()
        env.cve_ids.append(ticketless.cve_id)
        env.server.bodies[ticketless.cve_id] = UNCHANGED_BODY
        private_calls: list[None] = []
        real_private = batch.fetcher._get_active_ticket_cve_ids

        async def private(session: AsyncSession) -> list[str]:
            private_calls.append(None)
            return await real_private(session)

        monkeypatch.setattr(batch.fetcher, "_get_active_ticket_cve_ids", private)

        await batch.execute()

        assert len(private_calls) == 1
        assert len(env.scope_calls) == 1
        assert env.requested_cve_ids == sorted(cve.cve_id for cve in active)
        excluded = {cve.cve_id for cve in [*inactive, ticketless]}
        assert not excluded & set(env.scope_calls[0])
        # Pre-scope exclusions contribute to no metric and no status.
        assert counters(batch.fetcher) == Counters(3, 0, 0, 0)
        for cve in [*inactive, ticketless]:
            assert await env.source_status(cve) is None

    async def test_ticket_created_mid_run_is_not_added_to_the_snapshot(
        self, env: Env, batch: Batch, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        first = await env.active_cve(UNCHANGED_BODY)
        late: list[CVE] = []
        real_flush = batch.session.flush

        async def flush(*args: Any, **kwargs: Any) -> None:
            await real_flush(*args, **kwargs)
            if not late:
                late.append(await env.active_cve(UNCHANGED_BODY))

        monkeypatch.setattr(batch.session, "flush", flush)

        await batch.execute()

        assert late
        assert env.requested_cve_ids == [first.cve_id]

    async def test_empty_scope_requests_nothing(self, env: Env, batch: Batch) -> None:
        await batch.execute()

        assert env.server.requests == []
        assert env.sleeps == []
        assert counters(batch.fetcher) == Counters(0, 0, 0, 0)


@pytest.mark.integration
class TestFinalization:
    async def test_flush_precedes_finalization_outside_the_item_catch(
        self, env: Env, batch: Batch, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cve = await env.updated_cve()
        events: list[str] = []
        pending_at_finalization: list[bool] = []
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
            await real_commit()

        monkeypatch.setattr(batch.fetcher, "fetch_single", fetch_single)
        monkeypatch.setattr(batch.fetcher, "commit_and_dispatch", commit_and_dispatch)
        monkeypatch.setattr(batch.session, "flush", flush)
        monkeypatch.setattr(batch.session, "commit", commit)

        await batch.execute()

        assert events == ["fetch_single", "flush", "commit_and_dispatch", "commit"]
        assert pending_at_finalization == [False]
        assert await env.source_status(cve) == CVESourceFetchStatus.SUCCESS
        assert await env.osv_row_count(cve) == 1
        assert env.published.published(RESOLVE) == [
            {
                "ticket_id": str(env.world.ticket_ids[-1]),
                "cpe_matches": [],
                "affected_cpes": [],
                "vendor_products": [],
                "resolved_packages": ["example"],
            }
        ]
        assert counters(batch.fetcher) == Counters(1, 0, 1, 0)
        assert env.status_opened == [0]

    async def test_unchanged_records_success_without_effect(
        self, env: Env, batch: Batch
    ) -> None:
        cve = await env.active_cve(UNCHANGED_BODY)

        await batch.execute()

        assert await env.source_status(cve) == CVESourceFetchStatus.SUCCESS
        assert counters(batch.fetcher) == Counters(1, 0, 0, 0)
        assert env.published.published(RESOLVE) == []

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
        ordered = _ordered([first, second])
        assert env.requested_cve_ids == [ordered[0].cve_id]
        assert counters(batch.fetcher) == Counters(0, 0, 0, 0)
        assert env.status_opened == [0]
        assert _events(logs, CVE_FETCH_ITEM_FAILED_EVENT) == []
        assert await env.source_status(ordered[0]) is None
        assert await env.osv_row_count(ordered[0]) == 0
        assert env.published.calls == []

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
        assert env.published.calls == []

    async def test_non_operational_post_commit_error_aborts_and_keeps_success(
        self, env: Env, batch: Batch
    ) -> None:
        ordered = _ordered([await env.updated_cve(), await env.updated_cve()])
        error = EncodeError(FAILURE_TEXT)
        env.published.errors[RESOLVE] = error

        with capture_logs() as logs, pytest.raises(EncodeError) as raised:
            await batch.execute()

        assert raised.value is error
        assert env.requested_cve_ids == [ordered[0].cve_id]
        # Success and effect were recorded after the commit; no failure.
        assert counters(batch.fetcher) == Counters(1, 0, 1, 0)
        assert env.status_opened == [0]
        assert _events(logs, CVE_FETCH_ITEM_FAILED_EVENT) == []
        assert await env.source_status(ordered[0]) == CVESourceFetchStatus.SUCCESS
        assert await env.source_status(ordered[1]) is None
        # Only the step-13 throttle of the first CVE; no inter-CVE delay.
        assert env.sleeps == [(0.25, 1)]

    async def test_broker_operational_handoff_failure_keeps_success(
        self, env: Env, batch: Batch
    ) -> None:
        cve = await env.updated_cve()
        env.published.errors[RESOLVE] = BrokerOperationalError(FAILURE_TEXT)

        with capture_logs() as logs:
            await batch.execute()

        assert counters(batch.fetcher) == Counters(1, 0, 1, 0)
        assert await env.source_status(cve) == CVESourceFetchStatus.SUCCESS
        assert len(_events(logs, HANDOFF_PUBLICATION_FAILED_EVENT)) == 1
        assert _events(logs, CVE_FETCH_ITEM_FAILED_EVENT) == []
        assert FAILURE_TEXT not in repr(logs)


# ---------------------------------------------------------------------------
# Missing and per-item failures
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestMissing:
    @pytest.mark.parametrize(
        "body", [None, {}], ids=["http_404", "no_extractable_data"]
    )
    async def test_missing_is_an_isolated_status_and_success(
        self, body: Any, env: Env, batch: Batch
    ) -> None:
        cve = await env.active_cve(body)

        with capture_logs() as logs:
            await batch.execute()

        assert await env.source_status(cve) == CVESourceFetchStatus.MISSING
        assert env.status_opened == [1]
        assert counters(batch.fetcher) == Counters(1, 0, 0, 0)
        assert _events(logs, CVE_FETCH_ITEM_FAILED_EVENT) == []
        assert env.published.calls == []
        assert env.sleeps == [(0.25, 1)]

    async def test_missing_then_success(self, env: Env, batch: Batch) -> None:
        missing, present = _ordered([await env.active_cve(), await env.updated_cve()])
        env.server.bodies.pop(missing.cve_id, None)
        env.serve_updated(present)

        await batch.execute()

        assert await env.source_status(missing) == CVESourceFetchStatus.MISSING
        assert await env.source_status(present) == CVESourceFetchStatus.SUCCESS
        assert counters(batch.fetcher) == Counters(2, 0, 1, 0)


@pytest.mark.integration
class TestItemFailure:
    async def test_failure_rolls_back_writes_isolated_failure_and_one_event(
        self, env: Env, batch: Batch, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        failing = await env.updated_cve()
        other = await env.active_cve(UNCHANGED_BODY)
        _fail_references_for(monkeypatch, {failing.cve_id}, RuntimeError(FAILURE_TEXT))

        with capture_logs(processors=[merge_contextvars]) as logs:
            await batch.execute()

        # upsert_cve() wrote the osv rows and success status; rollback
        # discarded both before the isolated failure status.
        assert await env.osv_row_count(failing) == 0
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
        assert env.published.published(RESOLVE) == []
        for entry in logs:
            rendered = repr(dict(entry))
            for fragment in (FAILURE_TEXT, PERSONAL_TEXT, SECRET_VALUE, "Alice"):
                assert fragment not in rendered, entry
            assert "Example-Secret-Token" not in rendered, entry

    @pytest.mark.parametrize(
        ("body", "responder", "cause"),
        [
            (None, status(403, FAILURE_TEXT.encode()), "HTTPStatusError"),
            (None, status(429), "HTTPStatusError"),
            (None, status(200, b"{"), "JSONDecodeError"),
            (None, status(200, b"[1]"), "ValidationError"),
            (None, status(204), "OsvResponseError"),
            (None, raising(httpx.ConnectError(FAILURE_TEXT)), "ConnectError"),
            (GUARD_BODY, None, "CompletenessGuardError"),
            ({"summary": FAILURE_TEXT}, None, "ValidationError"),
        ],
        ids=[
            "forbidden",
            "rate_limited",
            "json",
            "schema",
            "unexpected_2xx",
            "connect",
            "completeness_guard",
            "payload",
        ],
    )
    async def test_event_names_only_the_exception_class(
        self,
        body: Any,
        responder: Any,
        cause: str,
        env: Env,
        batch: Batch,
    ) -> None:
        cve = await env.active_cve(body)
        if responder is not None:
            env.respond(cve, responder)
        if cause == "ValidationError" and body is not None:
            # An applicable alias package name containing U+0000 fails the
            # payload.
            env.serve_updated(cve, f"{PERSONAL_TEXT}\x00", **body)

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
        assert FAILURE_TEXT not in repr(logs)
        assert PERSONAL_TEXT not in repr(logs)
        assert await env.source_status(cve) == CVESourceFetchStatus.FAILURE
        assert counters(batch.fetcher) == Counters(0, 0, 0, 1)

    async def test_guard_failure_keeps_previous_data_and_logs_bounded_skips(
        self, env: Env, batch: Batch
    ) -> None:
        cve = await env.updated_cve()
        await batch.execute()
        assert await env.osv_row_count(cve) == 1
        env.server.bodies[cve.cve_id] = GUARD_BODY
        second = env.fetcher()
        second.config = batch.fetcher.config
        second._periodic_context = True

        with capture_logs() as logs:
            await Batch(env, second, batch.session).execute()

        assert await env.osv_row_count(cve) == 1
        assert await env.source_status(cve) == CVESourceFetchStatus.FAILURE
        assert [
            (entry["reason"], entry.get("record_id"))
            for entry in _events(logs, OSV_SUBREQUEST_SKIPPED_EVENT)
        ] == [("http_status", FAILING), ("unsafe_id", None)]
        assert counters(second) == Counters(0, 0, 0, 1)

    async def test_flush_failure_is_an_isolated_item_failure(
        self, env: Env, batch: Batch, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        first, second = _ordered([await env.updated_cve(), await env.updated_cve()])
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
        assert await env.osv_row_count(first) == 0
        assert await env.source_status(second) == CVESourceFetchStatus.SUCCESS
        assert await env.osv_row_count(second) == 1
        assert [
            (entry["cve_id"], entry["cause"])
            for entry in _events(logs, CVE_FETCH_ITEM_FAILED_EVENT)
        ] == [(first.cve_id, "RuntimeError")]
        assert counters(batch.fetcher) == Counters(1, 0, 1, 1)
        assert PERSONAL_TEXT not in repr(logs)


# ---------------------------------------------------------------------------
# Consecutive infrastructure failures
# ---------------------------------------------------------------------------


Plan = list[str]
"""Per-CVE outcome codes, in request order."""


async def _planned(env: Env, plan: Plan) -> list[CVE]:
    """Committed CVEs whose responses follow `plan` in request order."""
    cves = [await env.active_cve() for _ in plan]
    ordered = _ordered(cves)
    for cve, outcome in zip(ordered, plan, strict=True):
        if outcome == "ok":
            env.server.bodies[cve.cve_id] = UNCHANGED_BODY
        elif outcome == "missing":
            pass
        elif outcome == "guard":
            env.server.bodies[cve.cve_id] = GUARD_BODY
        elif outcome == "connect":
            env.respond(cve, raising(httpx.ConnectError("refused")))
        elif outcome == "timeout":
            env.respond(cve, raising(httpx.ReadTimeout("timed out")))
        elif outcome == "json":
            env.respond(cve, status(200, b"{"))
        else:
            env.respond(cve, status(int(outcome)))
    return ordered


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
        assert env.requested_cve_ids == [cve.cve_id for cve in ordered[:3]]
        assert counters(batch.fetcher) == Counters(0, 0, 0, 3)
        for cve in ordered[:3]:
            assert await env.source_status(cve) == CVESourceFetchStatus.FAILURE
        assert await env.source_status(ordered[3]) is None
        assert env.delays == [0.25, 0.25]

    async def test_abort_chains_the_triggering_exception(
        self, env: Env, batch: Batch
    ) -> None:
        ordered = await _planned(env, ["503", "503", "ok"])
        error = httpx.ConnectError("refused")
        del env.server.bodies[ordered[2].cve_id]
        env.respond(ordered[2], raising(error))

        with pytest.raises(FetcherError) as raised:
            await batch.execute()

        assert raised.value.__cause__ is error

    @pytest.mark.parametrize(
        "plan",
        [
            ["503", "503", "ok", "503", "503"],
            ["503", "503", "missing", "503", "503"],
            ["503", "503", "403", "503", "503"],
            ["503", "503", "429", "503", "503"],
            ["503", "503", "json", "503", "503"],
            ["503", "503", "guard", "503", "503"],
        ],
        ids=["success", "missing", "http_403", "http_429", "unparseable", "guard"],
    )
    async def test_reachability_resets_the_counter(
        self, plan: Plan, env: Env, batch: Batch
    ) -> None:
        ordered = await _planned(env, plan)

        await batch.execute()

        assert env.requested_cve_ids == [cve.cve_id for cve in ordered]
        failed = sum(outcome not in {"ok", "missing"} for outcome in plan)
        succeeded = len(plan) - failed
        assert counters(batch.fetcher) == Counters(succeeded, 0, 0, failed)

    async def test_non_infrastructure_failures_never_abort(
        self, env: Env, batch: Batch
    ) -> None:
        """A guard failure whose every sub-request was a 5xx is still not a
        Phase 1 infrastructure failure."""
        ordered = await _planned(env, ["guard", "guard", "guard", "403", "429", "json"])

        await batch.execute()

        assert env.requested_cve_ids == [cve.cve_id for cve in ordered]
        assert counters(batch.fetcher) == Counters(0, 0, 0, 6)


# ---------------------------------------------------------------------------
# Whole-run signals and request delay
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestWholeRunSignals:
    @pytest.mark.parametrize("phase", ["cve_record", "sub_request"])
    @pytest.mark.parametrize(
        "signal",
        [asyncio.CancelledError(), SoftTimeLimitExceeded(), MemoryError()],
        ids=lambda signal: type(signal).__name__,
    )
    async def test_signal_propagates_without_item_handling(
        self, signal: BaseException, phase: str, env: Env, batch: Batch
    ) -> None:
        await env.updated_cve()
        await env.updated_cve()

        def respond(request: httpx.Request) -> httpx.Response:
            raise signal

        if phase == "cve_record":
            env.server.responses.update(dict.fromkeys(env.cve_ids, respond))
        else:
            env.server.responses.update(dict.fromkeys(env.alias_ids, respond))

        with capture_logs() as logs, pytest.raises(type(signal)) as raised:
            await batch.execute()

        assert raised.value is signal
        assert len(env.server.requests) == (1 if phase == "cve_record" else 2)
        assert counters(batch.fetcher) == Counters(0, 0, 0, 0)
        assert env.status_opened == [0]
        assert logs == []
        assert env.published.calls == []


@pytest.mark.integration
class TestRequestDelay:
    async def test_configured_delay_follows_every_cve(
        self, env: Env, batch: Batch
    ) -> None:
        ordered = await _planned(env, ["ok", "missing", "403"])

        await batch.execute()

        assert env.requested_cve_ids == [cve.cve_id for cve in ordered]
        assert env.sleeps == [(0.25, 1), (0.25, 2), (0.25, 3)]

    async def test_configured_delay_also_separates_sub_requests(
        self, env: Env, batch: Batch
    ) -> None:
        await env.updated_cve()
        await env.active_cve(UNCHANGED_BODY)

        await batch.execute()

        # Three requests (two CVE records and one alias record), each
        # pair separated by one delay, whichever CVE comes first.
        assert len(env.server.requests) == 3
        assert env.sleeps == [(0.25, 1), (0.25, 2), (0.25, 3)]

    async def test_missing_configuration_snapshot_uses_the_class_default(
        self, env: Env, batch: Batch
    ) -> None:
        await env.updated_cve()
        batch.fetcher.config = None

        await batch.execute()

        assert env.sleeps == [(0.2, 1), (0.2, 2)]


# ---------------------------------------------------------------------------
# run(): the sync_osv_advisories metric mapping on a finalized FetcherRun
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
    fetcher: SyncOsvAdvisories, monkeypatch: pytest.MonkeyPatch
) -> list[int]:
    """Record every `record_created()` call (OSV never creates a CVE)."""
    calls: list[int] = []

    def record_created(count: int = 1) -> None:
        calls.append(count)

    monkeypatch.setattr(fetcher, "record_created", record_created)
    return calls


@pytest.mark.integration
class TestRunMetrics:
    async def test_success_run_maps_updated_unchanged_and_missing(
        self, env: Env, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        await env.updated_cve()
        await env.active_cve(UNCHANGED_BODY)
        await env.active_cve()  # HTTP 404: missing
        await env.active_cve({"withdrawn": "2026-01-01T00:00:00Z"})  # no data
        await env.active_cve(UNCHANGED_BODY, status=TicketStatus.RESOLVED)
        fetcher, run_id = await env.run_row()
        created = _forbid_record_created(fetcher, monkeypatch)

        await fetcher.run(run_id=run_id, config=_RUN_CONFIG)

        run = await env.run_outcome(run_id)
        # The Resolved Ticket's CVE is a pre-scope exclusion.
        assert _outcome(run) == ("success", 4, 0, 1, 0)
        assert run.error_message is None
        assert created == []

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

    async def test_success_plus_guard_failure_is_partial(self, env: Env) -> None:
        await env.updated_cve()
        failing = await env.active_cve(GUARD_BODY)
        fetcher, run_id = await env.run_row()

        with capture_logs(processors=[merge_contextvars]) as logs:
            await fetcher.run(run_id=run_id, config=_RUN_CONFIG)

        assert _outcome(await env.run_outcome(run_id)) == ("partial", 1, 0, 1, 1)
        # The per-item event binds to the run's correlation context.
        assert _events(logs, CVE_FETCH_ITEM_FAILED_EVENT) == [
            {
                "event": CVE_FETCH_ITEM_FAILED_EVENT,
                "log_level": "warning",
                "cve_id": failing.cve_id,
                "fetcher_name": NAME,
                "cause": "CompletenessGuardError",
                "fetcher_run_id": str(run_id),
            }
        ]
        assert {
            entry["fetcher_run_id"]
            for entry in _events(logs, OSV_SUBREQUEST_SKIPPED_EVENT)
        } == {str(run_id)}

    async def test_unchanged_success_plus_failure_is_partial(
        self, env: Env, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        await env.active_cve(UNCHANGED_BODY)
        failing = await env.updated_cve()
        _fail_references_for(monkeypatch, {failing.cve_id}, RuntimeError(FAILURE_TEXT))
        fetcher, run_id = await env.run_row()

        with capture_logs() as logs:
            await fetcher.run(run_id=run_id, config=_RUN_CONFIG)

        assert _outcome(await env.run_outcome(run_id)) == ("partial", 1, 0, 0, 1)
        assert FAILURE_TEXT not in repr(logs)

    async def test_all_failed_is_failure(self, env: Env) -> None:
        await _planned(env, ["403", "json", "guard", "503"])
        fetcher, run_id = await env.run_row()

        await fetcher.run(run_id=run_id, config=_RUN_CONFIG)

        run = await env.run_outcome(run_id)
        assert _outcome(run) == ("failure", 0, 0, 0, 4)
        assert run.error_message == "All 4 items failed"

    async def test_abort_is_a_failure_with_the_sanitized_message(
        self, env: Env
    ) -> None:
        await _planned(env, ["503", "503", "503"])
        fetcher, run_id = await env.run_row()

        with pytest.raises(FetcherError):
            await fetcher.run(run_id=run_id, config=_RUN_CONFIG)

        run = await env.run_outcome(run_id)
        assert _outcome(run) == ("failure", 0, 0, 0, 3)
        assert run.error_message == ABORT_MESSAGE
        assert run.error_detail is not None

    async def test_handoff_broker_failure_keeps_the_run_success(self, env: Env) -> None:
        cve = await env.updated_cve()
        env.published.errors[RESOLVE] = BrokerOperationalError(FAILURE_TEXT)
        fetcher, run_id = await env.run_row()

        with capture_logs(processors=[merge_contextvars]) as logs:
            await fetcher.run(run_id=run_id, config=_RUN_CONFIG)

        assert _outcome(await env.run_outcome(run_id)) == ("success", 1, 0, 1, 0)
        assert await env.source_status(cve) == CVESourceFetchStatus.SUCCESS
        [event] = _events(logs, HANDOFF_PUBLICATION_FAILED_EVENT)
        assert event["fetcher_name"] == NAME
        assert event["cause"] == "OperationalError"
        assert event["fetcher_run_id"] == str(run_id)
        assert FAILURE_TEXT not in repr(logs)

    async def test_post_commit_error_fails_the_run_and_keeps_success_metrics(
        self, env: Env
    ) -> None:
        cve = await env.updated_cve()
        env.published.errors[RESOLVE] = EncodeError(FAILURE_TEXT)
        fetcher, run_id = await env.run_row()

        with pytest.raises(EncodeError):
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
            # Settings/cursor load, then the execution session, then
            # finalization: only the execution session fails to commit.
            calls[0] += 1
            return execution_sessions() if calls[0] == 2 else real_factory()

        monkeypatch.setattr(base_fetcher_module, "async_session_factory", factory)

        with pytest.raises(RuntimeError):
            await fetcher.run(run_id=run_id, config=_RUN_CONFIG)

        run = await env.run_outcome(run_id)
        assert _outcome(run) == ("failure", 0, 0, 0, 0)
        assert run.error_message == "Unexpected error"
        assert await env.source_status(cve) is None
        assert env.status_opened == [0]
