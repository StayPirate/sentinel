"""Tests for the periodic batch `SyncNvdCves.execute()` and its `run()`
metrics (backend/app/services/tickets/sync_nvd_cves.py).

Owning specifications:

- docs/features/tickets/cve-sync-nvd.md (Custom Settings; Algorithm steps
  1-4.i, including the `totalResults` stability rule; NVD Date Format; Rate
  Limiting; Field Mapping, including the candidate skip event, CPE
  configurations, and External String Admissibility; NVD Source API Caching,
  including the Lifecycle's periodic run, which neither reads nor fills the
  cache that on-demand fetches share; First Run and >120-day Gap Handling;
  Overlap Buffer; Cursor Mechanism; Error Handling, the `execute()`
  page-level and per-CVE tables, the partial extraction model, Work unit and
  metric mapping, and Sanitized error messages; NVD Source API Failure
  Handling).
- docs/features/platform/cve-fetcher-infrastructure.md (`CVEFetchResult`;
  Per-CVE Finalization; Session Lifecycle for API-based CVE Fetchers,
  template 2, isolated status commit, and metric placement; Batch Error
  Handling, Per-item failure event; Candidate Skip Event; Metric
  Definitions).
- docs/features/platform/fetcher-infrastructure.md (Custom Settings Schema;
  Error Message Sanitization; `SoftTimeLimitExceeded` handling convention)
  and docs/features/platform/logging.md (Secrets and PII Discipline).
- docs/features/platform/testing-strategy.md (CVE Fetcher Infrastructure:
  One-shot finalization, Periodic metrics, Isolated statuses; Fetcher
  Outcome and Effect Accounting, the `sync_nvd_cves` mapping; External
  String Admissibility; NVD CPE Applicability Selection, the outcome,
  logging, and handoff obligations of `execute()`; Parallel Execution).

Every test commits real rows: CVEs with Tickets of an `IngestionWorld`
(deleted at teardown with their children, references, and Ticket events,
including every CVE and Ticket the code under test creates, whose CVE-IDs
are drawn from the world), the `sync_nvd_cves` `FetcherConfig` and its
`FetcherRun` rows, and a test-only "other fetcher" configuration. The
derived cursor is read from the latest `success`/`partial` `FetcherRun` of
the fetcher's own name, so these tests own every committed row under that
name while they run:

- each pytest-xdist worker uses its own PostgreSQL database and runs one
  test at a time (testing-strategy.md, Parallel Execution);
- inside a worker, no other test leaves a committed `sync_nvd_cves` row:
  the reachability tests delete the configuration they seed and create no
  run, and bootstrap tests roll back;
- the `env` fixture asserts that no such row exists before it seeds its
  own and none remains at teardown, and that the number of committed CVEs
  is unchanged, so a leak fails loudly.

Live record fixtures are retargeted to world CVE-IDs. `execute()` tests use
an independent `db_session_factory` session with real commits and set the
automatic periodic context that `run()` establishes. HTTP is the in-process
`NvdServer` serving the CVE API and the trimmed live Source API body;
`NVD_API_KEY` is set to a fictional value on `app.config.settings`; the
broker call is the recorded `task_publication.publish_task`; the isolated
status sessions are counted and `_isolated_status_commit()` is spied; every
throttle and rate-limit sleep is recorded instead of slept; the monotonic
clock of the shared Source API cache is controlled where its age matters.
All identifiers and texts are fictional, except the public data of the live
fixtures and NVD's institutional source identifier `nvd@nist.gov`.
"""

from __future__ import annotations

import asyncio
import copy
import re
import uuid
from collections.abc import (
    AsyncIterator,
    Awaitable,
    Callable,
    Iterable,
    Iterator,
    Mapping,
)
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta, timezone
from types import SimpleNamespace
from typing import Any, Final, NamedTuple

import httpx
import pytest
from celery.exceptions import OperationalError as BrokerOperationalError
from celery.exceptions import SoftTimeLimitExceeded
from kombu.exceptions import EncodeError  # type: ignore[import-untyped]
from pydantic import SecretStr
from sqlalchemy import delete, event, func, select
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncSession, async_sessionmaker
from structlog.contextvars import merge_contextvars
from structlog.testing import capture_logs

import app.services.base_cve_fetcher as base_cve_fetcher_module
import app.services.base_fetcher as base_fetcher_module
from app.config import settings as app_settings
from app.core.enums import CVESourceFetchStatus, CveState, TicketStatus
from app.models.cve import CVE
from app.models.cve_cvss_assessment import CVECVSSAssessment
from app.models.cve_cwe import CVECWE
from app.models.cve_source import CVESource
from app.models.fetcher_config import FetcherConfig
from app.models.fetcher_run import FetcherRun
from app.models.ticket import Ticket
from app.models.ticket_reference import TicketReference
from app.services import (
    cve_service,
    fetcher_execution,
    package_service,
    reference_service,
    task_publication,
)
from app.services.base_cve_fetcher import (
    CVE_FETCH_CANDIDATE_SKIPPED_EVENT,
    CVE_FETCH_ITEM_FAILED_EVENT,
    HANDOFF_PUBLICATION_FAILED_EVENT,
    CVEFetchResult,
)
from app.services.base_fetcher import FetcherConfigError, FetcherError, FetcherRunConfig
from app.services.cve_ingest import UpsertAction
from app.services.tickets import nvd_cve_record
from app.services.tickets import sync_nvd_cves as sync_module
from app.services.tickets.nvd_cve_record import NvdPageError
from app.services.tickets.sync_nvd_cves import (
    CONNECTION_FAILED,
    NVD_CURSOR_RESET_EVENT,
    NVD_FIRST_RUN_EVENT,
    NVD_SOURCE_API_UNAVAILABLE_EVENT,
    NVD_SOURCE_CACHE_INCOMPLETE_EVENT,
    NVD_SOURCE_ENTRIES_SKIPPED_EVENT,
    NVD_VULN_STATUS_UNRECOGNIZED_EVENT,
    RATE_LIMIT_EXHAUSTED,
    RATE_LIMIT_RETRY_DELAY,
    TIMED_OUT,
    UNPARSEABLE_RESPONSE,
    SyncNvdCves,
)
from tests.support.cve_catch_up import Publications
from tests.support.cve_ingest import SKIP_EVENT, IngestionWorld
from tests.support.inadmissible import INADMISSIBLE_CHARACTERS, SURROGATE
from tests.support.nvd import (
    API_KEY_HEADER,
    CVE_API_URL,
    PAGE_REJECTED,
    SOURCE_API_URL,
    SOURCE_PAGE,
    NvdServer,
    Responder,
    load_json_fixture,
    load_record,
    raising,
    status,
)
from tests.support.nvd import body as json_body
from tests.support.ticket_mutations import EventRow, ticket_events_by_id

SessionFactory = Callable[[], Awaitable[AsyncSession]]

NAME: Final = "sync_nvd_cves"
API_KEY: Final = "fictional-nvd-api-key-0001"
"""A fictional `NVD_API_KEY`; never a real key shape."""
RESOLVE: Final = package_service.RESOLVE_TICKET_PACKAGES_TASK
INGESTION_COMMENT: Final = "CVE ingested from NVD"
NVD: Final = "nvd@nist.gov"
CNA_SOURCE: Final = "hackerone-1@example.com"
"""A fictional CNA identifier of the trimmed live Source API body."""
CNA_NAME: Final = "HackerOne"
UNKNOWN_SOURCE: Final = "unknown-cna-1@example.com"
PUBLISHED: Final = "2026-01-01T00:00:00.000"
LAST_MODIFIED: Final = "2026-01-02T03:04:05.678"
V31: Final = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
V31_CNA: Final = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
CPE_A: Final = "cpe:2.3:a:example:product:1.0:*:*:*:*:*:*:*"
CPE_O: Final = "cpe:2.3:o:example:system:2.0:*:*:*:*:*:*:*"
CPE_H: Final = "cpe:2.3:h:example:board:-:*:*:*:*:*:*:*"
CPE_PLATFORM: Final = "cpe:2.3:o:example:platform:-:*:*:*:*:*:*:*"
CPE_NEGATED: Final = "cpe:2.3:a:example:negated:-:*:*:*:*:*:*:*"
MATCH_ID: Final = "0A1B2C3D-4E5F-4A6B-8C7D-0E1F2A3B4C5D"
URL_1: Final = "https://advisory.example.invalid/upstream/1"
URL_2: Final = "https://advisory.example.invalid/upstream/2"
PERSONAL_TEXT: Final = "Reported by Alice Example <alice.example@example.invalid>"
SECRET_VALUE: Final = "api_token=Example-Secret-Token-0123456789"
FAILURE_TEXT: Final = f"{PERSONAL_TEXT}; {SECRET_VALUE}"
"""Exception or upstream text that must appear in no log field or error."""

FAILED_EVENT_KEYS: Final = frozenset(
    {"event", "log_level", "cve_id", "fetcher_name", "cause"}
)
INVALID_ID_EVENT_KEYS: Final = FAILED_EVENT_KEYS - {"cve_id"}
OVERLAP: Final = timedelta(minutes=15)
DATE_FORMAT: Final = "%Y-%m-%dT%H:%M:%S.000"
BATCH_DELAY: Final = 0.25
RESULTS_PER_PAGE: Final = 2000
_RUN_CONFIG: Final = FetcherRunConfig(
    hard_time_limit_seconds=3600, request_delay=0.5, custom_settings={}
)

UNAVAILABLE: Final = {
    "event": NVD_SOURCE_API_UNAVAILABLE_EVENT,
    "log_level": "warning",
    "fetcher_name": NAME,
}


class Counters(NamedTuple):
    succeeded: int
    created: int
    updated: int
    failed: int


def counters(fetcher: SyncNvdCves) -> Counters:
    return Counters(
        fetcher._succeeded, fetcher._created, fetcher._updated, fetcher._failed
    )


def _events(logs: Iterable[Mapping[str, Any]], name: str) -> list[Mapping[str, Any]]:
    return [entry for entry in logs if entry["event"] == name]


def _assert_private(logs: Iterable[Mapping[str, Any]], *values: str) -> None:
    for entry in logs:
        rendered = repr(dict(entry))
        for fragment in (
            API_KEY,
            API_KEY_HEADER,
            FAILURE_TEXT,
            PERSONAL_TEXT,
            SECRET_VALUE,
            "Alice",
            "cpe:2.3",
            "\\x00",
            "\\ud800",
            *values,
        ):
            assert fragment not in rendered, entry


def _failed(cve_id: str | None, cause: str) -> dict[str, Any]:
    """The exact `cve_fetch_item_failed` WARNING (no `cve_id` without a
    canonical one)."""
    entry: dict[str, Any] = {
        "event": CVE_FETCH_ITEM_FAILED_EVENT,
        "log_level": "warning",
        "fetcher_name": NAME,
        "cause": cause,
    }
    if cve_id is not None:
        entry["cve_id"] = cve_id
    return entry


def _skip(cve_id: str, reason: str) -> dict[str, Any]:
    return {
        "event": CVE_FETCH_CANDIDATE_SKIPPED_EVENT,
        "log_level": "warning",
        "cve_id": cve_id,
        "fetcher_name": NAME,
        "reason": reason,
    }


def _nvd_date(instant: datetime) -> str:
    return instant.astimezone(UTC).strftime(DATE_FORMAT)


def _window_start(cursor: datetime) -> str:
    return _nvd_date(cursor - OVERLAP)


def _outcome(run: FetcherRun) -> tuple[str, int, int, int, int]:
    return (
        run.status,
        run.items_succeeded,
        run.items_created,
        run.items_updated,
        run.items_failed,
    )


def _metric(source: object, vector: str) -> dict[str, Any]:
    return {
        "source": source,
        "type": "Primary",
        "cvssData": {"version": "3.1", "vectorString": vector},
    }


def _weakness(source: object, value: str) -> dict[str, Any]:
    return {
        "source": source,
        "type": "Primary",
        "description": [{"lang": "en", "value": value}],
    }


def _configuration(*entries: Any, negate: bool | None = None) -> dict[str, Any]:
    configuration: dict[str, Any] = {
        "operator": "OR",
        "nodes": [{"operator": "OR", "negate": False, "cpeMatch": list(entries)}],
    }
    if negate is not None:
        configuration["negate"] = negate
    return configuration


def _match(criteria: object, *, vulnerable: object = True, **members: Any) -> Any:
    return {"vulnerable": vulnerable, "criteria": criteria, **members}


CPE_CONFIGURATIONS: Final = [
    {
        "operator": "AND",
        "nodes": [
            {
                "operator": "OR",
                "negate": False,
                "cpeMatch": [
                    _match(CPE_A, matchCriteriaId=MATCH_ID),
                    _match(CPE_O),
                    _match(f"{CPE_A}\x00"),
                    _match(f"{CPE_A}{SURROGATE}"),
                    _match(CPE_H, vulnerable="yes"),
                ],
            },
            {
                "operator": "OR",
                "negate": False,
                "cpeMatch": [_match(CPE_PLATFORM, vulnerable=False)],
            },
        ],
    },
    _configuration(_match(CPE_NEGATED), negate=True),
    {"operator": "OR", "nodes": FAILURE_TEXT},
    _configuration(_match(CPE_H, matchCriteriaId="not-a-uuid")),
]
"""Two selected entries, an excluded platform and negated configuration,
four invalid entries, and an invalid configuration."""

SELECTED_CPES: Final = [
    {
        "criteria": CPE_A,
        "vulnerable": True,
        "match_criteria_id": str(uuid.UUID(MATCH_ID)),
    },
    {"criteria": CPE_O, "vulnerable": True, "match_criteria_id": None},
]


# ---------------------------------------------------------------------------
# Harness
# ---------------------------------------------------------------------------


@dataclass
class Env:
    world: IngestionWorld
    factory: async_sessionmaker[AsyncSession]
    server: NvdServer
    published: Publications
    cve_baseline: int
    sleeps: list[tuple[float, int]] = field(default_factory=list)
    """Each recorded sleep and the number of requests made before it."""
    status_opened: list[int] = field(default_factory=lambda: [0])
    isolated: list[tuple[str, CVESourceFetchStatus]] = field(default_factory=list)
    other_names: list[str] = field(default_factory=list)

    # -- data ----------------------------------------------------------

    async def cve(self, ticket_status: TicketStatus = TicketStatus.ANALYSIS) -> CVE:
        """A committed CVE with a Ticket in `ticket_status`."""
        cve = await self.world.cve_in()
        await self.world.ticket(cve_id=cve.id, status=ticket_status)
        return cve

    def new_cve_id(self) -> str:
        """A CVE-ID absent from the database, deleted at teardown should
        the code under test create it."""
        return self.world.new_cve_id()

    @staticmethod
    def record(cve_id: object, **members: Any) -> dict[str, Any]:
        """A minimal fictional `vulnerabilities[]` element."""
        cve: dict[str, Any] = {
            "id": cve_id,
            "published": PUBLISHED,
            "lastModified": LAST_MODIFIED,
            "vulnStatus": "Analyzed",
        }
        cve.update(members)
        return {"cve": cve}

    @staticmethod
    def sourced(cve_id: str) -> dict[str, Any]:
        """NVD's own and a CNA's CVSS vector and CWE."""
        return Env.record(
            cve_id,
            metrics={
                "cvssMetricV31": [_metric(NVD, V31), _metric(CNA_SOURCE, V31_CNA)]
            },
            weaknesses=[_weakness(NVD, "CWE-79"), _weakness(CNA_SOURCE, "CWE-352")],
        )

    @staticmethod
    def fixture(name: str, cve_id: str) -> dict[str, Any]:
        """A live record fixture retargeted to `cve_id`."""
        element = copy.deepcopy(load_record(name))
        element["cve"]["id"] = cve_id
        return element

    def pages(self, *pages: list[Any]) -> None:
        self.server.pages = [list(page) for page in pages]

    # -- runs ------------------------------------------------------------

    async def seed_run(
        self,
        status_value: str,
        started_at: datetime | None,
        *,
        fetcher_name: str = NAME,
    ) -> uuid.UUID:
        async with self.factory() as session:
            run = FetcherRun(
                fetcher_name=fetcher_name,
                started_at=started_at,
                status=status_value,
                triggered_by="schedule",
            )
            session.add(run)
            await session.commit()
            return run.id

    async def other_fetcher(self) -> str:
        name = f"test_nvd_other_{uuid.uuid4().hex[:12]}"
        async with self.factory() as session:
            session.add(FetcherConfig(fetcher_name=name, enabled=True))
            await session.commit()
        self.other_names.append(name)
        return name

    def fetcher(self) -> SyncNvdCves:
        instance = SyncNvdCves()
        instance._http_client = self.server.client()
        return instance

    async def batch(self, *, cursor: bool = True) -> Batch:
        """An `execute()` harness; `cursor` seeds a `success` run one hour
        ago so that the window is fetched."""
        started_at = None
        if cursor:
            started_at = datetime.now(UTC) - timedelta(hours=1)
            await self.seed_run("success", started_at)
        fetcher = self.fetcher()
        fetcher.config = FetcherRunConfig(
            hard_time_limit_seconds=3600,
            request_delay=BATCH_DELAY,
            custom_settings={},
        )
        fetcher._periodic_context = True
        return Batch(self, fetcher, await self.world.open_session(), started_at)

    async def run_row(self) -> tuple[SyncNvdCves, uuid.UUID]:
        """A committed `running` FetcherRun, as the atomic acquisition leaves
        it before `run()`."""
        run_id = await self.seed_run("running", datetime.now(UTC))
        return self.fetcher(), run_id

    async def run(self, config: FetcherRunConfig = _RUN_CONFIG) -> FetcherRun:
        """One complete `run()`; returns the finalized FetcherRun."""
        fetcher, run_id = await self.run_row()
        await fetcher.run(run_id=run_id, config=config)
        return await self.run_outcome(run_id)

    async def run_outcome(self, run_id: uuid.UUID) -> FetcherRun:
        async with self.factory() as session:
            run = await session.get(FetcherRun, run_id)
        assert run is not None
        return run

    # -- observation -------------------------------------------------------

    @property
    def page_params(self) -> list[dict[str, str]]:
        return [dict(request.url.params) for request in self.server.page_requests]

    @property
    def window_starts(self) -> list[str]:
        return [params["lastModStartDate"] for params in self.page_params]

    async def source_status(self, cve: CVE) -> str | None:
        async with self.factory() as session:
            value: str | None = await session.scalar(
                select(CVESource.status).where(
                    CVESource.cve_id == cve.id, CVESource.source == "nvd"
                )
            )
        return value

    async def cve_named(self, cve_id: str) -> CVE | None:
        async with self.factory() as session:
            cve: CVE | None = await session.scalar(
                select(CVE).where(CVE.cve_id == cve_id)
            )
        return cve

    async def count(self, model: Any, cve: CVE) -> int:
        async with self.factory() as session:
            value = await session.scalar(
                select(func.count()).select_from(model).where(model.cve_id == cve.id)
            )
        return int(value or 0)

    async def cwes(self, cve: CVE) -> set[tuple[str, str]]:
        async with self.factory() as session:
            rows = await session.execute(
                select(CVECWE.cwe_id, CVECWE.source).where(CVECWE.cve_id == cve.id)
            )
        return {(cwe_id, source) for cwe_id, source in rows}

    async def assessments(self, cve: CVE) -> set[tuple[str, str]]:
        async with self.factory() as session:
            rows = await session.execute(
                select(
                    CVECVSSAssessment.provider_name, CVECVSSAssessment.vector_string
                ).where(CVECVSSAssessment.cve_id == cve.id)
            )
        return {(provider, vector) for provider, vector in rows}

    async def references(self, cve: CVE) -> list[tuple[str, str | None, str | None]]:
        async with self.factory() as session:
            rows = await session.execute(
                select(TicketReference.url, TicketReference.title, TicketReference.type)
                .join(Ticket, TicketReference.ticket_id == Ticket.id)
                .where(Ticket.cve_id == cve.id)
            )
        return sorted((url, title, kind) for url, title, kind in rows)

    async def tickets(self, cve: CVE) -> list[Ticket]:
        async with self.factory() as session:
            rows = await session.scalars(select(Ticket).where(Ticket.cve_id == cve.id))
            return list(rows.all())

    async def assert_untouched(self, cve: CVE) -> None:
        """No NVD child, source status, or reference row."""
        for model in (CVECVSSAssessment, CVECWE, CVESource):
            assert await self.count(model, cve) == 0, model
        assert await self.references(cve) == []

    async def committed_rows(self) -> int:
        async with self.factory() as session:
            configs = await session.scalar(
                select(func.count())
                .select_from(FetcherConfig)
                .where(FetcherConfig.fetcher_name == NAME)
            )
            runs = await session.scalar(
                select(func.count())
                .select_from(FetcherRun)
                .where(FetcherRun.fetcher_name == NAME)
            )
        return int(configs or 0) + int(runs or 0)

    async def cleanup(self) -> None:
        try:
            await self.world.cleanup()
        finally:
            names = [NAME, *self.other_names]
            async with self.factory() as session:
                await session.execute(
                    delete(FetcherRun).where(FetcherRun.fetcher_name.in_(names))
                )
                await session.execute(
                    delete(FetcherConfig).where(FetcherConfig.fetcher_name.in_(names))
                )
                await session.commit()
        assert await self.committed_rows() == 0
        assert await _cve_count(self.factory) == self.cve_baseline, "a CVE leaked"


async def _cve_count(factory: async_sessionmaker[AsyncSession]) -> int:
    async with factory() as session:
        return int(await session.scalar(select(func.count()).select_from(CVE)) or 0)


@pytest.fixture
async def env(
    db_session_factory: SessionFactory,
    real_session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> AsyncIterator[Env]:
    created = Env(
        world=IngestionWorld(db_session_factory, await db_session_factory()),
        factory=real_session_factory,
        server=NvdServer(),
        published=Publications(),
        cve_baseline=await _cve_count(real_session_factory),
    )
    # The derived cursor reads every committed run of this name.
    assert await created.committed_rows() == 0

    def status_sessions() -> AsyncSession:
        created.status_opened[0] += 1
        return real_session_factory()

    real_isolated = SyncNvdCves._isolated_status_commit

    async def isolated(
        self: SyncNvdCves, cve_id: str, status_value: CVESourceFetchStatus
    ) -> None:
        created.isolated.append((cve_id, status_value))
        await real_isolated(self, cve_id, status_value)

    async def sleep(delay: float) -> None:
        created.sleeps.append((delay, len(created.server.requests)))

    monkeypatch.setattr(app_settings, "nvd_api_key", SecretStr(API_KEY))
    monkeypatch.setattr(
        base_cve_fetcher_module, "async_session_factory", status_sessions
    )
    monkeypatch.setattr(
        base_fetcher_module, "async_session_factory", real_session_factory
    )
    monkeypatch.setattr(task_publication, "publish_task", created.published)
    monkeypatch.setattr(SyncNvdCves, "_isolated_status_commit", isolated)
    monkeypatch.setattr(sync_module, "asyncio", SimpleNamespace(sleep=sleep))
    try:
        await created.world.ensure_default_setting()
        async with real_session_factory() as session:
            session.add(FetcherConfig(fetcher_name=NAME, enabled=True))
            await session.commit()
        yield created
    finally:
        await created.cleanup()


@dataclass
class Batch:
    """`execute()` invocations on a reusable session with real commits,
    under the automatic periodic context that `run()` establishes."""

    env: Env
    fetcher: SyncNvdCves
    session: AsyncSession
    cursor: datetime | None

    async def execute(self) -> None:
        if self.fetcher._http_client is None:
            self.fetcher._http_client = self.env.server.client()
        try:
            await self.fetcher.execute(self.session)
        finally:
            await self.fetcher._teardown_http_client()


@pytest.fixture
async def batch(env: Env) -> Batch:
    return await env.batch()


@dataclass
class Trace:
    """Per-element observation of one `execute()`: the page element being
    processed, every SQL statement and rollback on the batch session's own
    connection, and every `_ingest()` call, each tagged with that index."""

    current: list[int] = field(default_factory=lambda: [-1])
    statements: list[tuple[int, str]] = field(default_factory=list)
    rollbacks: list[int] = field(default_factory=list)
    ingested: list[int] = field(default_factory=list)

    def statements_of(self, index: int) -> list[str]:
        return [statement for i, statement in self.statements if i == index]

    @contextmanager
    def recording(self, batch: Batch) -> Iterator[Trace]:
        bind = batch.session.bind
        assert isinstance(bind, AsyncConnection)
        connection = bind.sync_connection
        assert connection is not None

        def record(*args: Any) -> None:
            self.statements.append((self.current[0], args[2]))

        event.listen(connection, "before_cursor_execute", record)
        try:
            yield self
        finally:
            event.remove(connection, "before_cursor_execute", record)


def _trace(monkeypatch: pytest.MonkeyPatch, batch: Batch) -> Trace:
    trace = Trace()
    real_process = batch.fetcher._process_vulnerability
    real_ingest = batch.fetcher._ingest
    real_rollback = batch.session.rollback
    position = [0]

    async def process_vulnerability(
        session: AsyncSession, element: object, source_names: Any
    ) -> None:
        trace.current[0] = position[0]
        position[0] += 1
        await real_process(session, element, source_names)

    async def ingest(
        session: AsyncSession, element: object, source_names: Any
    ) -> CVEFetchResult:
        trace.ingested.append(trace.current[0])
        return await real_ingest(session, element, source_names)

    async def rollback() -> None:
        trace.rollbacks.append(trace.current[0])
        await real_rollback()

    monkeypatch.setattr(batch.fetcher, "_process_vulnerability", process_vulnerability)
    monkeypatch.setattr(batch.fetcher, "_ingest", ingest)
    monkeypatch.setattr(batch.session, "rollback", rollback)
    return trace


def _fail_references_for(
    monkeypatch: pytest.MonkeyPatch, cve_ids: set[str], error: BaseException
) -> None:
    """Make `upsert_references()` raise `error` for `cve_ids` after it has
    written the references in the same transaction."""
    real = reference_service.upsert_references

    async def upsert_references(
        session: AsyncSession, ticket_id: Any, cve_id: str, *args: Any
    ) -> None:
        await real(session, ticket_id, cve_id, *args)
        if cve_id in cve_ids:
            raise error

    monkeypatch.setattr(reference_service, "upsert_references", upsert_references)


async def _run_expecting(env: Env, error: type[BaseException]) -> FetcherRun:
    fetcher, run_id = await env.run_row()
    with pytest.raises(error):
        await fetcher.run(run_id=run_id, config=_RUN_CONFIG)
    return await env.run_outcome(run_id)


def _freeze(monkeypatch: pytest.MonkeyPatch, instant: datetime) -> None:
    """Freeze the `now` captured at `execute()` entry (Algorithm step 2)."""
    monkeypatch.setattr(
        sync_module, "datetime", SimpleNamespace(now=lambda tz: instant)
    )


@pytest.fixture
def frozen_now(monkeypatch: pytest.MonkeyPatch) -> datetime:
    """Freeze `now` at the real instant of fixture setup, so that the runs
    a test dates from it precede the `execute()` entry as in production."""
    now = datetime.now(UTC)
    _freeze(monkeypatch, now)
    return now


# ---------------------------------------------------------------------------
# Derived cursor, first run, and window (Algorithm steps 1-2, 4.b)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestCursor:
    async def test_first_run_is_success_without_any_request(self, env: Env) -> None:
        cve_id = env.new_cve_id()
        env.pages([env.record(cve_id)])
        await env.seed_run("failure", datetime.now(UTC) - timedelta(hours=2))
        await env.seed_run("queued", None)

        with capture_logs() as logs:
            run = await env.run()

        assert _outcome(run) == ("success", 0, 0, 0, 0)
        assert run.error_message is None
        assert run.cursor is None
        # Neither the CVE API nor the Source API is requested.
        assert env.server.requests == []
        assert env.sleeps == []
        assert logs == [
            {"event": NVD_FIRST_RUN_EVENT, "log_level": "info", "fetcher_name": NAME}
        ]
        assert await env.cve_named(cve_id) is None

    async def test_first_run_execute_returns_after_ending_the_read(
        self, env: Env, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        batch = await env.batch(cursor=False)
        trace = _trace(monkeypatch, batch)

        with trace.recording(batch):
            await batch.execute()

        assert env.server.requests == []
        assert trace.rollbacks == [-1]
        [statement] = trace.statements_of(-1)
        assert statement.lstrip().startswith("SELECT")
        assert "FROM fetcher_run" in statement
        assert "FOR " not in statement.upper()
        assert counters(batch.fetcher) == Counters(0, 0, 0, 0)

    async def test_first_run_becomes_the_cursor_of_the_next_run(self, env: Env) -> None:
        first = await env.run()

        second = await env.run()

        assert _outcome(first) == _outcome(second) == ("success", 0, 0, 0, 0)
        assert first.started_at is not None
        assert env.window_starts == [_window_start(first.started_at)]
        assert first.cursor is None
        assert second.cursor is None

    async def test_latest_success_or_partial_of_this_fetcher_is_the_cursor(
        self, env: Env
    ) -> None:
        now = datetime.now(UTC)
        other = await env.other_fetcher()
        await env.seed_run("success", now - timedelta(hours=5))
        await env.seed_run("partial", now - timedelta(hours=3))
        await env.seed_run("failure", now - timedelta(hours=2))
        await env.seed_run("queued", None)
        await env.seed_run("running", now - timedelta(hours=1))
        await env.seed_run("success", now - timedelta(minutes=10), fetcher_name=other)
        batch = await env.batch(cursor=False)

        await batch.execute()

        assert env.window_starts == [_window_start(now - timedelta(hours=3))]

    async def test_requests_are_the_documented_source_and_window_queries(
        self, env: Env, frozen_now: datetime
    ) -> None:
        cursor = frozen_now - timedelta(hours=6, microseconds=987654)
        await env.seed_run("success", cursor)
        batch = await env.batch(cursor=False)

        await batch.execute()

        source, page = env.server.requests
        assert source.method == page.method == "GET"
        assert str(source.url) == SOURCE_API_URL
        assert str(page.url.copy_with(query=None)) == CVE_API_URL
        assert list(page.url.params.multi_items()) == [
            ("lastModStartDate", _window_start(cursor)),
            ("lastModEndDate", _nvd_date(frozen_now)),
            ("startIndex", "0"),
            ("resultsPerPage", "2000"),
        ]
        # UTC, `.000` milliseconds, no offset.
        for value in (_window_start(cursor), _nvd_date(frozen_now)):
            assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.000", value)
        assert env.server.api_key_headers == [API_KEY, API_KEY]

    async def test_window_is_formatted_in_utc(
        self, env: Env, batch: Batch, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        offset = timezone(timedelta(hours=2))
        cursor = datetime(2026, 10, 11, 10, 0, 30, 999999, tzinfo=offset)
        _freeze(monkeypatch, datetime(2026, 10, 11, 9, 30, 0, 123456, tzinfo=UTC))

        async def derived_cursor(session: AsyncSession, name: str) -> datetime:
            return cursor

        monkeypatch.setattr(fetcher_execution, "get_derived_cursor", derived_cursor)

        await batch.execute()

        [params] = env.page_params
        assert params["lastModStartDate"] == "2026-10-11T07:45:30.000"
        assert params["lastModEndDate"] == "2026-10-11T09:30:00.000"

    async def test_read_transaction_ends_before_the_first_request(
        self, env: Env, batch: Batch
    ) -> None:
        in_transaction: list[bool] = []

        def respond(request: httpx.Request) -> httpx.Response:
            in_transaction.append(batch.session.in_transaction())
            return httpx.Response(
                200, json=load_json_fixture(SOURCE_PAGE), request=request
            )

        env.server.source_response = respond

        await batch.execute()

        assert in_transaction == [False]

    async def test_current_run_is_never_its_own_cursor(self, env: Env) -> None:
        previous = datetime.now(UTC) - timedelta(hours=2)
        await env.seed_run("success", previous)

        run = await env.run()

        assert _outcome(run) == ("success", 0, 0, 0, 0)
        assert env.window_starts == [_window_start(previous)]

    async def test_failed_run_does_not_advance_the_cursor(self, env: Env) -> None:
        previous = datetime.now(UTC) - timedelta(hours=2)
        await env.seed_run("success", previous)
        env.server.page_responses[0] = status(500)
        failed = await _run_expecting(env, FetcherError)
        assert _outcome(failed) == ("failure", 0, 0, 0, 0)
        assert failed.cursor is None
        del env.server.page_responses[0]

        second = await env.run()
        third = await env.run()

        assert _outcome(second) == ("success", 0, 0, 0, 0)
        assert second.started_at is not None
        assert env.window_starts == [
            _window_start(previous),
            _window_start(previous),
            _window_start(second.started_at),
        ]
        assert second.cursor is None
        assert third.cursor is None

    async def test_overlap_redelivery_is_one_unchanged_success(self, env: Env) -> None:
        await env.seed_run("success", datetime.now(UTC) - timedelta(hours=3))
        cve = await env.cve()
        record = env.record(cve.cve_id, configurations=[_configuration(_match(CPE_A))])
        env.pages([record])
        first = await env.run()
        published = len(env.published.published(RESOLVE))

        second = await env.run()

        assert _outcome(first) == ("success", 1, 0, 1, 0)
        assert _outcome(second) == ("success", 1, 0, 0, 0)
        assert first.started_at is not None
        assert env.window_starts[1] == _window_start(first.started_at)
        # The unchanged re-delivery still hands off its package candidates.
        assert len(env.published.published(RESOLVE)) == published + 1
        assert first.cursor is None
        assert second.cursor is None


STALE_AFTER: Final = timedelta(days=120)


@pytest.mark.integration
class TestStaleCursor:
    @pytest.mark.parametrize(
        "age",
        [STALE_AFTER, timedelta(days=119, hours=23, minutes=59), timedelta(0)],
        ids=["exactly_120_days", "just_under", "now"],
    )
    async def test_window_start_within_120_days_is_fetched(
        self, age: timedelta, env: Env, frozen_now: datetime
    ) -> None:
        window_start = frozen_now - age
        await env.seed_run("success", window_start + OVERLAP)
        batch = await env.batch(cursor=False)

        with capture_logs() as logs:
            await batch.execute()

        assert env.window_starts == [_nvd_date(window_start)]
        assert env.server.kinds == ["source", "page"]
        assert _events(logs, NVD_CURSOR_RESET_EVENT) == []

    @pytest.mark.parametrize(
        ("beyond", "age_days"),
        [
            (timedelta(microseconds=1), 120),
            (timedelta(hours=23), 120),
            (timedelta(days=15), 135),
            (timedelta(days=245), 365),
        ],
        ids=["one_microsecond", "hours", "135_days", "one_year"],
    )
    async def test_older_window_start_resets_without_any_request(
        self,
        beyond: timedelta,
        age_days: int,
        env: Env,
        frozen_now: datetime,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        window_start = frozen_now - STALE_AFTER - beyond
        await env.seed_run("success", window_start + OVERLAP)
        cve = await env.cve()
        env.pages([env.record(cve.cve_id)])
        batch = await env.batch(cursor=False)
        trace = _trace(monkeypatch, batch)

        with capture_logs() as logs:
            await batch.execute()

        assert logs == [
            {
                "event": NVD_CURSOR_RESET_EVENT,
                "log_level": "warning",
                "fetcher_name": NAME,
                "age_days": age_days,
            }
        ]
        # Neither the CVE API nor the Source API is requested.
        assert env.server.requests == []
        assert env.sleeps == []
        assert trace.current == [-1]
        assert counters(batch.fetcher) == Counters(0, 0, 0, 0)
        await env.assert_untouched(cve)

    async def test_now_is_captured_once_at_execute_entry(
        self, env: Env, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Algorithm step 2: the window end and the 120-day comparison use the
        instant captured when `execute()` starts. A later `now` would end the
        window one day later and reset this exactly-120-day cursor."""
        entry = datetime.now(UTC)
        window_start = entry - STALE_AFTER
        await env.seed_run("success", window_start + OVERLAP)
        instants = iter(entry + timedelta(days=offset) for offset in range(10))
        calls: list[object] = []

        def now(tz: object) -> datetime:
            calls.append(tz)
            return next(instants)

        monkeypatch.setattr(sync_module, "datetime", SimpleNamespace(now=now))
        batch = await env.batch(cursor=False)

        with capture_logs() as logs:
            await batch.execute()

        assert calls == [UTC]
        assert _events(logs, NVD_CURSOR_RESET_EVENT) == []
        assert env.server.kinds == ["source", "page"]
        assert [params["lastModEndDate"] for params in env.page_params] == [
            _nvd_date(entry)
        ]

    async def test_reset_run_is_success_and_becomes_the_cursor(
        self, env: Env, frozen_now: datetime, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        await env.seed_run("success", frozen_now - timedelta(days=200))

        with capture_logs(processors=[merge_contextvars]) as logs:
            reset = await env.run()

        assert _outcome(reset) == ("success", 0, 0, 0, 0)
        assert reset.error_message is None
        assert reset.cursor is None
        assert env.server.requests == []
        [event_entry] = _events(logs, NVD_CURSOR_RESET_EVENT)
        assert event_entry["age_days"] == 200
        assert reset.started_at is not None

        # The reset run's started_at is now the latest success: the next
        # scheduled run, six hours after it, fetches the window from it.
        _freeze(monkeypatch, reset.started_at + timedelta(hours=6))
        second = await env.run()

        assert _outcome(second) == ("success", 0, 0, 0, 0)
        assert env.window_starts == [_window_start(reset.started_at)]


# ---------------------------------------------------------------------------
# Source API cache (Algorithm step 3; Failure Handling)
# ---------------------------------------------------------------------------


_SOURCE_FAILURES: Final[list[Responder]] = [
    status(500, FAILURE_TEXT.encode()),
    status(429),
    status(403),
    status(404, headers={"message": "Invalid apiKey."}),
    status(302, headers={"Location": "https://nvd.example.invalid/source"}),
    status(204),
    raising(httpx.ConnectError("[Errno 111] Connection refused")),
    raising(httpx.ReadTimeout("timed out")),
    status(200, b"not gzip", headers={"Content-Encoding": "gzip"}),
    status(200, f"<html>{FAILURE_TEXT}</html>".encode()),
    json_body({"totalResults": 1, "sources": []}),
]
_SOURCE_FAILURE_IDS: Final = [
    "http_500",
    "http_429",
    "http_403",
    "http_404",
    "http_302",
    "http_204",
    "connection_refused",
    "read_timeout",
    "undecodable",
    "html",
    "envelope",
]


@pytest.mark.integration
class TestSourceApi:
    async def test_one_source_request_resolves_cna_names_for_every_page(
        self, env: Env, batch: Batch
    ) -> None:
        first, second = await env.cve(), await env.cve()
        env.pages([env.sourced(first.cve_id)], [env.sourced(second.cve_id)])

        with capture_logs() as logs:
            await batch.execute()

        assert env.server.kinds == ["source", "page", "page"]
        for cve in (first, second):
            assert await env.assessments(cve) == {("NVD", V31), (CNA_NAME, V31_CNA)}
            assert await env.cwes(cve) == {("CWE-79", "NVD"), ("CWE-352", CNA_NAME)}
        assert logs == []
        assert counters(batch.fetcher) == Counters(2, 0, 2, 0)

    @pytest.mark.parametrize("responder", _SOURCE_FAILURES, ids=_SOURCE_FAILURE_IDS)
    async def test_failure_is_degraded_mode_and_the_pages_are_still_fetched(
        self, responder: Responder, env: Env, batch: Batch
    ) -> None:
        cve = await env.cve()
        env.pages([env.sourced(cve.cve_id)])
        env.server.source_response = responder

        with capture_logs() as logs:
            await batch.execute()

        # A single attempt, then the throttle and the window.
        assert env.server.kinds == ["source", "page"]
        assert env.sleeps == [(BATCH_DELAY, 1)]
        assert logs == [UNAVAILABLE, _skip(cve.cve_id, "unresolved_source")]
        _assert_private(logs, CNA_SOURCE, CNA_NAME)
        assert await env.assessments(cve) == {("NVD", V31)}
        assert await env.cwes(cve) == {("CWE-79", "NVD")}
        assert counters(batch.fetcher) == Counters(1, 0, 1, 0)

    async def test_invalid_key_degrades_then_aborts_on_the_first_page(
        self, env: Env, batch: Batch
    ) -> None:
        """NVD answers every request with an invalid key with HTTP 404."""
        cve = await env.cve()
        env.pages([env.record(cve.cve_id)])
        env.server.source_response = status(404)
        env.server.page_responses[0] = status(404)

        with capture_logs() as logs, pytest.raises(FetcherError) as raised:
            await batch.execute()

        assert str(raised.value) == "NVD API returned HTTP 404"
        assert logs == [UNAVAILABLE]
        assert counters(batch.fetcher) == Counters(0, 0, 0, 0)
        await env.assert_untouched(cve)

    async def test_malformed_entries_log_only_their_count(
        self, env: Env, batch: Batch
    ) -> None:
        sources = copy.deepcopy(load_json_fixture(SOURCE_PAGE))
        sources["sources"].extend(
            [
                {"name": "", "sourceIdentifiers": [UNKNOWN_SOURCE]},
                {"name": FAILURE_TEXT, "sourceIdentifiers": UNKNOWN_SOURCE},
            ]
        )
        env.server.sources = sources
        cve = await env.cve()
        env.pages([env.sourced(cve.cve_id)])

        with capture_logs() as logs:
            await batch.execute()

        assert logs == [
            {
                "event": NVD_SOURCE_ENTRIES_SKIPPED_EVENT,
                "log_level": "warning",
                "fetcher_name": NAME,
                "count": 2,
            }
        ]
        _assert_private(logs, UNKNOWN_SOURCE)
        assert await env.assessments(cve) == {("NVD", V31), (CNA_NAME, V31_CNA)}

    async def test_more_sources_than_one_page_warns_and_uses_the_partial_cache(
        self, env: Env, batch: Batch
    ) -> None:
        sources = copy.deepcopy(load_json_fixture(SOURCE_PAGE))
        sources["sources"] = [
            entry for entry in sources["sources"] if entry["name"] != CNA_NAME
        ]
        sources["totalResults"] = 514
        sources["resultsPerPage"] = 513
        env.server.sources = sources
        cve = await env.cve()
        env.pages([env.sourced(cve.cve_id)])

        with capture_logs() as logs:
            await batch.execute()

        assert logs == [
            {
                "event": NVD_SOURCE_CACHE_INCOMPLETE_EVENT,
                "log_level": "warning",
                "fetcher_name": NAME,
            },
            _skip(cve.cve_id, "unresolved_source"),
        ]
        assert await env.assessments(cve) == {("NVD", V31)}


# ---------------------------------------------------------------------------
# Shared Source API cache (NVD Source API Caching, Lifecycle)
# ---------------------------------------------------------------------------

TTL: Final = sync_module.SOURCE_CACHE_TTL
EPSILON: Final = 0.001
BUILT_AT: Final = 10_000.0
"""The controlled clock's first instant, away from the holder's initial 0.0."""
CNA_CONTACT: Final = "contact-hackerone@example.com"


class Clock:
    """The controlled monotonic clock of the shared cache."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.now = BUILT_AT
        monkeypatch.setattr(sync_module, "_monotonic", lambda: self.now)


@pytest.fixture
def clock(monkeypatch: pytest.MonkeyPatch) -> Clock:
    return Clock(monkeypatch)


def _shared() -> Mapping[str, str] | None:
    return sync_module._shared_source_cache.get()


async def _on_demand_build(env: Env) -> Mapping[str, str] | None:
    """The shared cache lookup of one `fetch_single()`, on a fresh fetcher
    and client."""
    fetcher = env.fetcher()
    try:
        return await fetcher._shared_source_names()
    finally:
        await fetcher._teardown_http_client()


@pytest.mark.integration
class TestSharedSourceCacheIsolation:
    @pytest.mark.parametrize("run_source", ["available", "unavailable"])
    async def test_run_builds_its_own_cache_and_leaves_a_warm_shared_one(
        self, run_source: str, env: Env, batch: Batch, clock: Clock
    ) -> None:
        assert _shared() is None
        shared = await _on_demand_build(env)
        assert shared is not None
        assert env.server.kinds == ["source"]
        cve = await env.cve()
        env.pages([env.sourced(cve.cve_id)])
        if run_source == "unavailable":
            env.server.source_response = status(503)
        clock.now += 300.0

        with capture_logs() as logs:
            await batch.execute()

        assert env.server.kinds == ["source", "source", "page"]
        if run_source == "available":
            assert logs == []
            assert await env.assessments(cve) == {("NVD", V31), (CNA_NAME, V31_CNA)}
        else:
            # Degraded mode: the run never falls back to the shared cache.
            assert logs == [UNAVAILABLE, _skip(cve.cve_id, "unresolved_source")]
            assert await env.assessments(cve) == {("NVD", V31)}
        _assert_private(logs, CNA_SOURCE, CNA_NAME, CNA_CONTACT)
        # The same mapping object, still dated from the on-demand build.
        clock.now = BUILT_AT + TTL - EPSILON
        assert _shared() is shared
        clock.now = BUILT_AT + TTL
        assert _shared() is None

    async def test_successful_run_leaves_a_cold_shared_cache_empty(
        self, env: Env, batch: Batch
    ) -> None:
        assert _shared() is None
        cve = await env.cve()
        env.pages([env.sourced(cve.cve_id)])

        await batch.execute()

        assert env.server.kinds == ["source", "page"]
        assert await env.assessments(cve) == {("NVD", V31), (CNA_NAME, V31_CNA)}
        assert _shared() is None
        # The next on-demand fetch still builds with its own request.
        assert await _on_demand_build(env) is not None
        assert env.server.kinds == ["source", "page", "source"]


# ---------------------------------------------------------------------------
# Pagination and the throttle (Algorithm step 4; Rate Limiting)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestPagination:
    async def test_start_index_advances_by_the_page_size_over_one_window(
        self, env: Env, batch: Batch
    ) -> None:
        cves = [await env.cve() for _ in range(3)]
        env.pages(*([env.record(cve.cve_id)] for cve in cves))

        await batch.execute()

        assert env.server.requested_page_indexes == [0, 1, 2]
        params = env.page_params
        assert [p["startIndex"] for p in params] == ["0", "2000", "4000"]
        assert {p["resultsPerPage"] for p in params} == {"2000"}
        assert len({(p["lastModStartDate"], p["lastModEndDate"]) for p in params}) == 1
        assert batch.cursor is not None
        assert params[0]["lastModStartDate"] == _window_start(batch.cursor)
        assert env.server.api_key_headers == [API_KEY] * 4
        assert counters(batch.fetcher) == Counters(3, 0, 3, 0)
        for cve in cves:
            assert await env.source_status(cve) == CVESourceFetchStatus.SUCCESS

    @pytest.mark.parametrize(
        ("first_total", "later_totals", "expected_pages"),
        [
            (4001, {1: 10**6, 2: 10**6}, 3),
            (4001, {1: 1, 2: 0}, 3),
            (2001, {1: 10**6}, 2),
        ],
        ids=["later_grows", "later_shrinks", "two_pages_later_grows"],
    )
    async def test_first_page_total_results_is_the_fixed_bound(
        self,
        first_total: int,
        later_totals: dict[int, int],
        expected_pages: int,
        env: Env,
        batch: Batch,
    ) -> None:
        env.pages([], [], [], [])
        env.server.totals = {0: first_total, **later_totals}

        await batch.execute()

        assert env.server.requested_page_indexes == list(range(expected_pages))
        assert counters(batch.fetcher) == Counters(0, 0, 0, 0)

    async def test_zero_total_results_is_success_without_another_page(
        self, env: Env
    ) -> None:
        await env.seed_run("success", datetime.now(UTC) - timedelta(hours=1))

        with capture_logs() as logs:
            run = await env.run()

        assert _outcome(run) == ("success", 0, 0, 0, 0)
        assert run.error_message is None
        assert env.server.kinds == ["source", "page"]
        # The throttle after the Source API only; none after the last page.
        assert env.sleeps == [(0.5, 1)]
        assert logs == []

    async def test_rejected_live_page_is_processed_completely(
        self, env: Env, batch: Batch
    ) -> None:
        elements = copy.deepcopy(load_json_fixture(PAGE_REJECTED)["vulnerabilities"])
        cves = [await env.cve() for _ in elements]
        for element, cve in zip(elements, cves, strict=True):
            element["cve"]["id"] = cve.cve_id
        env.pages(elements)

        await batch.execute()

        assert counters(batch.fetcher) == Counters(12, 0, 12, 0)
        for cve in cves:
            named = await env.cve_named(cve.cve_id)
            assert named is not None
            assert named.cve_state == CveState.REJECTED.value


@pytest.mark.integration
class TestThrottle:
    async def test_delay_follows_the_source_request_and_each_page_but_the_last(
        self, env: Env, batch: Batch
    ) -> None:
        cves = [await env.cve() for _ in range(4)]
        env.pages(
            [env.record(cves[0].cve_id), env.record(cves[1].cve_id)],
            [env.record(cves[2].cve_id)],
            [env.record(cves[3].cve_id)],
        )

        await batch.execute()

        # Not between CVEs of a page, not after the last page.
        assert env.sleeps == [(BATCH_DELAY, 1), (BATCH_DELAY, 2), (BATCH_DELAY, 3)]
        assert env.server.kinds == ["source", "page", "page", "page"]

    async def test_single_page_is_delayed_only_after_the_source_request(
        self, env: Env, batch: Batch
    ) -> None:
        await batch.execute()

        assert env.server.kinds == ["source", "page"]
        assert env.sleeps == [(BATCH_DELAY, 1)]

    async def test_missing_configuration_snapshot_uses_the_class_default(
        self, env: Env, batch: Batch
    ) -> None:
        batch.fetcher.config = None
        env.pages([], [], [])
        env.server.totals[0] = 4001

        await batch.execute()

        assert env.sleeps == [(6.0, 1), (6.0, 2), (6.0, 3)]
        assert SyncNvdCves.default_request_delay == 6.0

    async def test_run_uses_its_snapshot_delay(self, env: Env) -> None:
        await env.seed_run("success", datetime.now(UTC) - timedelta(hours=1))
        env.pages([], [])
        env.server.totals[0] = 2001

        await env.run(
            FetcherRunConfig(
                hard_time_limit_seconds=3600, request_delay=0.6, custom_settings={}
            )
        )

        assert env.sleeps == [(0.6, 1), (0.6, 2)]


# ---------------------------------------------------------------------------
# Custom settings (Custom Settings)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestCustomSettings:
    async def test_stored_page_size_sets_the_stride(self, env: Env) -> None:
        await env.seed_run("success", datetime.now(UTC) - timedelta(hours=1))
        env.pages([], [], [])
        env.server.totals[0] = 201

        run = await env.run(
            FetcherRunConfig(
                hard_time_limit_seconds=3600,
                request_delay=0.5,
                custom_settings={"results_per_page": 100},
            )
        )

        assert _outcome(run) == ("success", 0, 0, 0, 0)
        assert [(p["startIndex"], p["resultsPerPage"]) for p in env.page_params] == [
            ("0", "100"),
            ("100", "100"),
            ("200", "100"),
        ]

    @pytest.mark.parametrize("value", [99, 2001, "many"], ids=["99", "2001", "text"])
    async def test_out_of_range_stored_value_fails_the_run_before_any_request(
        self, value: object, env: Env
    ) -> None:
        await env.seed_run("success", datetime.now(UTC) - timedelta(hours=1))
        fetcher, run_id = await env.run_row()

        with pytest.raises(FetcherConfigError):
            await fetcher.run(
                run_id=run_id,
                config=FetcherRunConfig(
                    hard_time_limit_seconds=3600,
                    request_delay=0.5,
                    custom_settings={"results_per_page": value},
                ),
            )

        run = await env.run_outcome(run_id)
        assert _outcome(run) == ("failure", 0, 0, 0, 0)
        assert run.error_message == (
            "Fetcher 'sync_nvd_cves' has invalid stored settings — update via the API"
        )
        assert env.server.requests == []


# ---------------------------------------------------------------------------
# Page-level failures (Error Handling, `execute()` page-level table)
# ---------------------------------------------------------------------------


def _with_status(code: int) -> Responder:
    def respond(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            code,
            json={
                "totalResults": 1,
                "vulnerabilities": [
                    {"cve": {"id": "CVE-2099-0001", "descriptions": FAILURE_TEXT}}
                ],
            },
            request=request,
        )

    return respond


def _http(code: int) -> str:
    return f"NVD API returned HTTP {code}"


_PAGE_FAILURES: Final[list[tuple[Responder, str, type[BaseException] | None]]] = [
    (status(500, FAILURE_TEXT.encode()), _http(500), httpx.HTTPStatusError),
    (status(503), _http(503), httpx.HTTPStatusError),
    (status(403, FAILURE_TEXT.encode()), _http(403), httpx.HTTPStatusError),
    (status(400), _http(400), httpx.HTTPStatusError),
    (status(401), _http(401), httpx.HTTPStatusError),
    (
        status(404, headers={"message": "Invalid apiKey."}),
        _http(404),
        httpx.HTTPStatusError,
    ),
    (status(422), _http(422), httpx.HTTPStatusError),
    (
        status(301, headers={"Location": "https://advisory.example.invalid/x"}),
        _http(301),
        httpx.HTTPStatusError,
    ),
    (
        status(302, headers={"Location": f"{CVE_API_URL}?startIndex=0"}),
        _http(302),
        httpx.HTTPStatusError,
    ),
    (status(204), _http(204), None),
    (_with_status(201), _http(201), None),
    (_with_status(206), _http(206), None),
    (
        raising(httpx.ConnectError("[Errno 111] Connection refused")),
        CONNECTION_FAILED,
        httpx.ConnectError,
    ),
    (
        raising(httpx.RemoteProtocolError("peer closed connection")),
        CONNECTION_FAILED,
        httpx.RemoteProtocolError,
    ),
    (raising(httpx.ConnectTimeout("timed out")), TIMED_OUT, httpx.ConnectTimeout),
    (raising(httpx.ReadTimeout("timed out")), TIMED_OUT, httpx.ReadTimeout),
    (
        status(200, b"not gzip", headers={"Content-Encoding": "gzip"}),
        UNPARSEABLE_RESPONSE,
        httpx.DecodingError,
    ),
    (status(200, b"{"), UNPARSEABLE_RESPONSE, NvdPageError),
    (status(200, b""), UNPARSEABLE_RESPONSE, NvdPageError),
    (
        status(200, f"<html>{FAILURE_TEXT}</html>".encode()),
        UNPARSEABLE_RESPONSE,
        NvdPageError,
    ),
    (
        status(200, b'{"totalResults": 1, "vulnerabilities": ["\xff\xfe"]}'),
        UNPARSEABLE_RESPONSE,
        NvdPageError,
    ),
    (
        json_body([{"cve": {"id": "CVE-2099-0001", "descriptions": FAILURE_TEXT}}]),
        UNPARSEABLE_RESPONSE,
        NvdPageError,
    ),
    (
        json_body({"totalResults": -1, "vulnerabilities": []}),
        UNPARSEABLE_RESPONSE,
        NvdPageError,
    ),
    (
        json_body({"totalResults": "1", "vulnerabilities": [FAILURE_TEXT]}),
        UNPARSEABLE_RESPONSE,
        NvdPageError,
    ),
    (json_body({"totalResults": 0}), UNPARSEABLE_RESPONSE, NvdPageError),
    (json_body(None), UNPARSEABLE_RESPONSE, NvdPageError),
]
_PAGE_FAILURE_IDS: Final = [
    "http_500",
    "http_503",
    "http_403",
    "http_400",
    "http_401",
    "http_404",
    "http_422",
    "http_301",
    "http_302",
    "http_204",
    "http_201",
    "http_206",
    "connection_refused",
    "protocol_error",
    "connect_timeout",
    "read_timeout",
    "undecodable_content_encoding",
    "truncated_json",
    "empty_body",
    "html",
    "invalid_utf8",
    "array_root",
    "negative_total",
    "string_total",
    "vulnerabilities_absent",
    "null_root",
]


def _assert_content_free(*values: str | None) -> None:
    for value in values:
        if value is None:
            continue
        for fragment in (
            API_KEY,
            API_KEY_HEADER,
            FAILURE_TEXT,
            PERSONAL_TEXT,
            SECRET_VALUE,
            "Invalid apiKey",
        ):
            assert fragment not in value, (fragment, value)


@pytest.mark.integration
class TestPageFailures:
    @pytest.mark.parametrize(
        ("responder", "message", "cause"), _PAGE_FAILURES, ids=_PAGE_FAILURE_IDS
    )
    async def test_execute_aborts_with_the_sanitized_chained_error(
        self,
        responder: Responder,
        message: str,
        cause: type[BaseException] | None,
        env: Env,
        batch: Batch,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        env.server.page_responses[0] = responder
        trace = _trace(monkeypatch, batch)

        with capture_logs() as logs, pytest.raises(FetcherError) as raised:
            await batch.execute()

        assert str(raised.value) == message
        if cause is None:
            assert raised.value.__cause__ is None
        else:
            assert isinstance(raised.value.__cause__, cause)
        # One page request; a redirect is not followed and no page retried.
        assert env.server.kinds == ["source", "page"]
        assert env.sleeps == [(BATCH_DELAY, 1)]
        assert trace.current == [-1]
        assert counters(batch.fetcher) == Counters(0, 0, 0, 0)
        assert logs == []

    @pytest.mark.parametrize(
        ("responder", "message", "cause"), _PAGE_FAILURES, ids=_PAGE_FAILURE_IDS
    )
    async def test_run_failure_has_the_exact_message_and_a_content_free_detail(
        self,
        responder: Responder,
        message: str,
        cause: type[BaseException] | None,
        env: Env,
    ) -> None:
        await env.seed_run("success", datetime.now(UTC) - timedelta(hours=1))
        env.server.page_responses[0] = responder

        with capture_logs() as logs:
            run = await _run_expecting(env, FetcherError)

        assert _outcome(run) == ("failure", 0, 0, 0, 0)
        assert run.error_message == message
        if cause is None:
            assert run.error_detail is None
        else:
            assert run.error_detail is not None
        if cause is NvdPageError:
            assert run.error_detail == "NVD response is not a CVE API page"
        assert run.cursor is None
        _assert_content_free(run.error_message, run.error_detail, run.error_traceback)
        _assert_private(logs)
        assert env.server.kinds == ["source", "page"]

    async def test_persistent_429_is_retried_once_after_30_seconds(
        self, env: Env, batch: Batch
    ) -> None:
        env.server.page_responses[0] = status(429, FAILURE_TEXT.encode())

        with capture_logs() as logs, pytest.raises(FetcherError) as raised:
            await batch.execute()

        assert (
            str(raised.value)
            == RATE_LIMIT_EXHAUSTED
            == ("NVD API rate limit exceeded — retries exhausted")
        )
        assert isinstance(raised.value.__cause__, httpx.HTTPStatusError)
        assert raised.value.__cause__.response.status_code == 429
        assert env.server.requested_page_indexes == [0, 0]
        assert env.sleeps == [(BATCH_DELAY, 1), (RATE_LIMIT_RETRY_DELAY, 2)]
        assert RATE_LIMIT_RETRY_DELAY == 30.0
        assert counters(batch.fetcher) == Counters(0, 0, 0, 0)
        assert logs == []

    async def test_persistent_429_run_is_a_failure_without_cursor_advance(
        self, env: Env
    ) -> None:
        previous = datetime.now(UTC) - timedelta(hours=1)
        await env.seed_run("success", previous)
        env.server.page_responses[0] = status(429)

        failed = await _run_expecting(env, FetcherError)
        del env.server.page_responses[0]
        await env.run()

        assert _outcome(failed) == ("failure", 0, 0, 0, 0)
        assert failed.error_message == RATE_LIMIT_EXHAUSTED
        assert failed.error_detail is not None
        _assert_content_free(failed.error_detail, failed.error_traceback)
        assert env.window_starts == [_window_start(previous)] * 3

    async def test_429_resolved_by_the_retry_continues_the_run(
        self, env: Env, batch: Batch
    ) -> None:
        first, second = await env.cve(), await env.cve()
        env.pages([env.record(first.cve_id)], [env.record(second.cve_id)])
        env.server.page_once[1] = [status(429)]

        await batch.execute()

        assert env.server.requested_page_indexes == [0, 1, 1]
        assert env.sleeps == [
            (BATCH_DELAY, 1),
            (BATCH_DELAY, 2),
            (RATE_LIMIT_RETRY_DELAY, 3),
        ]
        assert counters(batch.fetcher) == Counters(2, 0, 2, 0)

    @pytest.mark.parametrize(
        ("retry", "message", "cause"),
        [
            (status(500), _http(500), httpx.HTTPStatusError),
            (status(204), _http(204), None),
            (
                raising(httpx.ConnectError("refused")),
                CONNECTION_FAILED,
                httpx.ConnectError,
            ),
            (raising(httpx.ReadTimeout("timed out")), TIMED_OUT, httpx.ReadTimeout),
            (status(200, b"{"), UNPARSEABLE_RESPONSE, NvdPageError),
        ],
        ids=[
            "http_500",
            "http_204",
            "connection_refused",
            "read_timeout",
            "unparseable",
        ],
    )
    async def test_failed_retry_after_429_is_its_own_page_failure(
        self,
        retry: Responder,
        message: str,
        cause: type[BaseException] | None,
        env: Env,
        batch: Batch,
    ) -> None:
        env.server.page_once[0] = [status(429), retry]

        with pytest.raises(FetcherError) as raised:
            await batch.execute()

        assert str(raised.value) == message
        if cause is None:
            assert raised.value.__cause__ is None
        else:
            assert isinstance(raised.value.__cause__, cause)
        assert env.server.requested_page_indexes == [0, 0]

    async def test_failure_on_a_later_page_keeps_earlier_commits(
        self, env: Env
    ) -> None:
        await env.seed_run("success", datetime.now(UTC) - timedelta(hours=1))
        committed = await env.cve()
        later = await env.cve()
        env.pages([env.record(committed.cve_id)], [env.record(later.cve_id)])
        env.server.page_responses[1] = status(503, FAILURE_TEXT.encode())

        run = await _run_expecting(env, FetcherError)

        assert _outcome(run) == ("failure", 1, 0, 1, 0)
        assert run.error_message == _http(503)
        assert env.server.requested_page_indexes == [0, 1]
        assert await env.source_status(committed) == CVESourceFetchStatus.SUCCESS
        await env.assert_untouched(later)


# ---------------------------------------------------------------------------
# Elements without a valid CVE-ID (Algorithm step 4.e)
# ---------------------------------------------------------------------------

_STRUCTURE: Final = "NvdRecordStructureError"
_ID: Final = "NvdRecordIdError"

_INVALID_ELEMENTS: Final[list[tuple[Any, str]]] = [
    ("CVE-2099-0001", _STRUCTURE),
    (48001, _STRUCTURE),
    (None, _STRUCTURE),
    (True, _STRUCTURE),
    ([], _STRUCTURE),
    ({}, _STRUCTURE),
    ({"cve": None}, _STRUCTURE),
    ({"cve": "CVE-2099-0001"}, _STRUCTURE),
    ({"cve": ["CVE-2099-0001"]}, _STRUCTURE),
    ("id:absent", _STRUCTURE),
    ("id:null", _STRUCTURE),
    ("id:integer", _STRUCTURE),
    ("id:list", _STRUCTURE),
    ("id:CVE-24-1", _ID),
    ("id:GHSA-fict-0001-aaaa", _ID),
    ("id:", _ID),
    ("id:cve-2099-0001", _ID),
    ("id:CVE-2099-111111111111", _ID),
    ("id:free_text", _ID),
    ("id:nul", _ID),
    ("id:surrogate", _ID),
]
_INVALID_IDS: Final = [
    "string_element",
    "number_element",
    "null_element",
    "boolean_element",
    "list_element",
    "no_cve",
    "null_cve",
    "string_cve",
    "list_cve",
    "absent_id",
    "null_id",
    "integer_id",
    "list_id",
    "short_year",
    "ghsa_id",
    "empty",
    "lowercase",
    "over_long",
    "free_text",
    "nul",
    "surrogate",
]


def _invalid_element(spec: Any) -> Any:
    if not (isinstance(spec, str) and spec.startswith("id:")):
        return spec
    value: Any = spec.removeprefix("id:")
    special: dict[str, Any] = {
        "absent": None,
        "null": None,
        "integer": 20990001,
        "list": ["CVE-2099-0001"],
        "free_text": f"CVE-2099-0001 {FAILURE_TEXT}",
        "nul": "CVE-2099-0001\x00",
        "surrogate": f"CVE-2099-0001{SURROGATE}",
    }
    value = special.get(value, value)
    element = Env.record(value, descriptions=[{"lang": "en", "value": FAILURE_TEXT}])
    if spec == "id:absent":
        del element["cve"]["id"]
    return element


@pytest.mark.integration
class TestInvalidCveId:
    @pytest.mark.parametrize(("spec", "cause"), _INVALID_ELEMENTS, ids=_INVALID_IDS)
    async def test_invalid_element_is_one_failed_unit_without_database_work(
        self,
        spec: Any,
        cause: str,
        env: Env,
        batch: Batch,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        later = await env.cve()
        env.pages([_invalid_element(spec), env.record(later.cve_id)])
        trace = _trace(monkeypatch, batch)

        with capture_logs() as logs, trace.recording(batch):
            await batch.execute()

        assert trace.statements_of(0) == []
        assert trace.rollbacks == [-1]
        assert trace.ingested == [1]
        # Exactly one event: no second WARNING carrying the raw identifier.
        assert logs == [_failed(None, cause)]
        assert set(logs[0]) == INVALID_ID_EVENT_KEYS
        _assert_private(logs, "GHSA-", "CVE-24-1", "cve-2099")
        # No isolated status for the invalid element.
        assert env.isolated == []
        assert env.status_opened == [0]
        assert counters(batch.fetcher) == Counters(1, 0, 1, 1)
        assert await env.source_status(later) == CVESourceFetchStatus.SUCCESS


# ---------------------------------------------------------------------------
# Per-CVE success and finalization (Algorithm step 4.e)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestCveSuccess:
    async def test_new_cve_is_created_with_a_new_ticket_and_handoff(
        self, env: Env, batch: Batch
    ) -> None:
        cve_id = env.new_cve_id()
        record = env.record(
            cve_id,
            descriptions=[{"lang": "en", "value": "Fictional description"}],
            references=[{"url": URL_1, "tags": ["Patch"]}],
            configurations=[_configuration(_match(CPE_A))],
        )
        env.pages([record])

        await batch.execute()

        assert counters(batch.fetcher) == Counters(1, 1, 0, 0)
        cve = await env.cve_named(cve_id)
        assert cve is not None
        assert cve.description == "Fictional description"
        [ticket] = await env.tickets(cve)
        assert ticket.status == "New"
        async with env.factory() as session:
            events = await ticket_events_by_id(session, ticket.id)
        assert events == [
            EventRow("ticket_created", None, None, None, INGESTION_COMMENT, None),
            EventRow("cve_associated", None, None, cve_id, None, None),
        ]
        assert await env.references(cve) == [
            (URL_1, None, "patch"),
            (f"https://nvd.nist.gov/vuln/detail/{cve_id}", "NVD", "advisory"),
        ]
        assert await env.source_status(cve) == CVESourceFetchStatus.SUCCESS
        assert env.published.published(RESOLVE) == [
            {
                "ticket_id": str(ticket.id),
                "cpe_matches": [
                    {"criteria": CPE_A, "vulnerable": True, "match_criteria_id": None}
                ],
                "affected_cpes": [],
                "vendor_products": [],
                "resolved_packages": [],
            }
        ]
        assert env.isolated == []

    async def test_flush_precedes_finalization_and_effects_follow_commit(
        self, env: Env, batch: Batch, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cve = await env.cve()
        env.pages(
            [env.record(cve.cve_id, configurations=[_configuration(_match(CPE_A))])]
        )
        events: list[str] = []
        env.published.events = events
        pending_at_finalization: list[bool] = []
        tokens: list[Any] = []
        at_commit: list[Counters] = []
        real_ingest = batch.fetcher._ingest
        real_finalize = batch.fetcher.commit_and_dispatch
        real_flush = batch.session.flush
        real_commit = batch.session.commit
        inside_ingest = [False]

        async def ingest(
            session: AsyncSession, element: object, source_names: Any
        ) -> CVEFetchResult:
            events.append("ingest")
            inside_ingest[0] = True
            try:
                return await real_ingest(session, element, source_names)
            finally:
                inside_ingest[0] = False

        async def commit_and_dispatch(session: AsyncSession, result: Any) -> None:
            events.append("commit_and_dispatch")
            tokens.append(result)
            pending_at_finalization.append(
                bool(session.new or session.dirty or session.deleted)
            )
            await real_finalize(session, result)

        async def flush(*args: Any, **kwargs: Any) -> None:
            # The delegates' own flushes happen inside _ingest().
            if not inside_ingest[0]:
                events.append("flush")
            await real_flush(*args, **kwargs)

        async def commit() -> None:
            events.append("commit")
            at_commit.append(counters(batch.fetcher))
            await real_commit()

        monkeypatch.setattr(batch.fetcher, "_ingest", ingest)
        monkeypatch.setattr(batch.fetcher, "commit_and_dispatch", commit_and_dispatch)
        monkeypatch.setattr(batch.session, "flush", flush)
        monkeypatch.setattr(batch.session, "commit", commit)

        await batch.execute()

        assert events[:4] == ["ingest", "flush", "commit_and_dispatch", "commit"]
        assert events[-1] == f"publish:{RESOLVE}"
        assert pending_at_finalization == [False]
        [token] = tokens
        assert isinstance(token, CVEFetchResult)
        assert token.action is UpsertAction.UPDATED
        assert token.post_ingest is not None
        assert token._consumed
        # The effect and the success are absent until the commit.
        assert at_commit == [Counters(0, 0, 0, 0)]
        assert counters(batch.fetcher) == Counters(1, 0, 1, 0)

    async def test_live_records_are_committed_completely(
        self, env: Env, batch: Batch
    ) -> None:
        full, non_base, legacy = await env.cve(), await env.cve(), await env.cve()
        env.pages(
            [
                env.fixture("record_analyzed_full", full.cve_id),
                env.fixture("record_awaiting_v40_non_base", non_base.cve_id),
                env.fixture("record_modified_v2", legacy.cve_id),
            ]
        )

        with capture_logs() as logs:
            await batch.execute()

        assert counters(batch.fetcher) == Counters(3, 0, 3, 0)
        assert await env.assessments(full) == {
            ("NVD", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
            ("CISA-ADP", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"),
        }
        assert await env.cwes(full) == {("CWE-787", "NVD"), ("CWE-120", "CISA-ADP")}
        # The non-Base v4.0 vector persists as its canonical Base vector.
        assert await env.assessments(non_base) == {
            (
                CNA_NAME,
                "CVSS:4.0/AV:L/AC:L/AT:N/PR:H/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
            )
        }
        assert {provider for provider, _ in await env.assessments(legacy)} == {"NVD"}
        # The placeholder weakness is not a CWE.
        assert await env.cwes(legacy) == set()
        references = await env.references(full)
        assert (
            f"https://nvd.nist.gov/vuln/detail/{full.cve_id}",
            "NVD",
            "advisory",
        ) in references
        assert len(references) == 3
        # Only the firmware entry is handed off; its hardware platform not.
        [handoff] = [
            call
            for call in env.published.published(RESOLVE)
            if call["cpe_matches"]
            and call["cpe_matches"][0]["criteria"].startswith("cpe:2.3:o:tenda")
        ]
        assert [match["criteria"] for match in handoff["cpe_matches"]] == [
            "cpe:2.3:o:tenda:ac6_firmware:15.03.05.16_multi:*:*:*:*:*:*:*"
        ]
        _assert_private(logs)

    async def test_unchanged_records_success_without_effect(
        self, env: Env, batch: Batch
    ) -> None:
        cve = await env.cve()
        env.pages([env.record(cve.cve_id)])
        await batch.execute()
        second = await env.batch(cursor=False)

        await second.execute()

        assert counters(second.fetcher) == Counters(1, 0, 0, 0)
        assert env.published.published(RESOLVE) == []

    async def test_rejected_record_moves_a_new_ticket_to_ignored(
        self, env: Env, batch: Batch
    ) -> None:
        cve = await env.cve(TicketStatus.NEW)
        element = copy.deepcopy(load_json_fixture(PAGE_REJECTED)["vulnerabilities"][0])
        element["cve"]["id"] = cve.cve_id
        env.pages([element])

        await batch.execute()

        assert counters(batch.fetcher) == Counters(1, 0, 1, 0)
        named = await env.cve_named(cve.cve_id)
        assert named is not None
        assert named.cve_state == CveState.REJECTED.value
        [ticket] = await env.tickets(cve)
        assert ticket.status == "Ignored"
        async with env.factory() as session:
            events = await ticket_events_by_id(session, ticket.id)
        assert events[-1] == EventRow(
            "status_change", None, "New", "Ignored", "CVE rejected", None
        )

    async def test_unknown_vuln_status_is_published_with_one_bounded_warning(
        self, env: Env, batch: Batch
    ) -> None:
        cve = await env.cve()
        env.pages([env.record(cve.cve_id, vulnStatus=FAILURE_TEXT)])

        with capture_logs() as logs:
            await batch.execute()

        assert logs == [
            {
                "event": NVD_VULN_STATUS_UNRECOGNIZED_EVENT,
                "log_level": "warning",
                "cve_id": cve.cve_id,
                "fetcher_name": NAME,
            }
        ]
        assert counters(batch.fetcher) == Counters(1, 0, 1, 0)
        named = await env.cve_named(cve.cve_id)
        assert named is not None
        assert named.cve_state == CveState.PUBLISHED.value


# ---------------------------------------------------------------------------
# Per-CVE failures and the hard finalization boundary
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestCveFailure:
    async def test_non_processable_record_rolls_back_and_writes_isolated_failure(
        self, env: Env, batch: Batch, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        failing, later = await env.cve(), await env.cve()
        env.pages(
            [
                env.record(failing.cve_id, published=FAILURE_TEXT),
                env.record(later.cve_id),
            ]
        )
        trace = _trace(monkeypatch, batch)

        with capture_logs() as logs:
            await batch.execute()

        assert trace.rollbacks == [-1, 0]
        assert trace.ingested == [0, 1]
        assert _events(logs, CVE_FETCH_ITEM_FAILED_EVENT) == [
            _failed(failing.cve_id, _STRUCTURE)
        ]
        _assert_private(logs)
        assert env.isolated == [(failing.cve_id, CVESourceFetchStatus.FAILURE)]
        assert env.status_opened == [1]
        assert await env.source_status(failing) == CVESourceFetchStatus.FAILURE
        assert await env.source_status(later) == CVESourceFetchStatus.SUCCESS
        assert counters(batch.fetcher) == Counters(1, 0, 1, 1)

    async def test_failure_after_upsert_rolls_back_its_writes(
        self, env: Env, batch: Batch, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        failing = await env.cve()
        env.pages(
            [
                env.record(
                    failing.cve_id,
                    metrics={"cvssMetricV31": [_metric(NVD, V31)]},
                    references=[{"url": URL_1}],
                    configurations=[_configuration(_match(CPE_A))],
                )
            ]
        )
        _fail_references_for(monkeypatch, {failing.cve_id}, RuntimeError(FAILURE_TEXT))

        with capture_logs() as logs:
            await batch.execute()

        # upsert_cve() wrote the assessment and the success status and the
        # references were written; the rollback discarded all of them.
        assert await env.count(CVECVSSAssessment, failing) == 0
        assert await env.references(failing) == []
        assert await env.source_status(failing) == CVESourceFetchStatus.FAILURE
        [failed] = _events(logs, CVE_FETCH_ITEM_FAILED_EVENT)
        assert failed == _failed(failing.cve_id, "RuntimeError")
        assert set(failed) == FAILED_EVENT_KEYS
        _assert_private(logs)
        assert counters(batch.fetcher) == Counters(0, 0, 0, 1)
        assert env.published.calls == []

    async def test_first_seen_cve_failure_leaves_no_cve_and_no_status(
        self, env: Env, batch: Batch, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cve_id = env.new_cve_id()
        env.pages([env.record(cve_id)])
        _fail_references_for(monkeypatch, {cve_id}, RuntimeError(FAILURE_TEXT))

        with capture_logs() as logs:
            await batch.execute()

        # The insert was rolled back, so the isolated status finds no CVE.
        assert await env.cve_named(cve_id) is None
        assert env.isolated == [(cve_id, CVESourceFetchStatus.FAILURE)]
        assert env.status_opened == [1]
        assert _events(logs, CVE_FETCH_ITEM_FAILED_EVENT) == [
            _failed(cve_id, "RuntimeError")
        ]
        assert counters(batch.fetcher) == Counters(0, 0, 0, 1)
        assert env.published.calls == []

    async def test_own_flush_failure_is_an_isolated_failure(
        self, env: Env, batch: Batch, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        first, second = await env.cve(), await env.cve()
        env.pages([env.record(first.cve_id), env.record(second.cve_id)])
        trace = _trace(monkeypatch, batch)
        traced_ingest = batch.fetcher._ingest
        real_finalize = batch.fetcher.commit_and_dispatch
        real_flush = batch.session.flush
        inside_ingest = [False]
        own_flushes: list[int] = []
        finalized: list[int] = []

        async def ingest(
            session: AsyncSession, element: object, source_names: Any
        ) -> CVEFetchResult:
            inside_ingest[0] = True
            try:
                return await traced_ingest(session, element, source_names)
            finally:
                inside_ingest[0] = False

        async def commit_and_dispatch(session: AsyncSession, result: Any) -> None:
            finalized.append(trace.current[0])
            await real_finalize(session, result)

        async def flush(*args: Any, **kwargs: Any) -> None:
            await real_flush(*args, **kwargs)
            # Only the fetcher's own per-CVE flush of the first CVE fails;
            # the delegates' flushes inside _ingest() succeed.
            if not inside_ingest[0]:
                own_flushes.append(trace.current[0])
                if trace.current[0] == 0:
                    raise RuntimeError(FAILURE_TEXT)

        monkeypatch.setattr(batch.fetcher, "_ingest", ingest)
        monkeypatch.setattr(batch.fetcher, "commit_and_dispatch", commit_and_dispatch)
        monkeypatch.setattr(batch.session, "flush", flush)

        with capture_logs() as logs:
            await batch.execute()

        assert own_flushes == [0, 1]
        assert finalized == [1]
        assert trace.rollbacks == [-1, 0]
        assert _events(logs, CVE_FETCH_ITEM_FAILED_EVENT) == [
            _failed(first.cve_id, "RuntimeError")
        ]
        assert await env.source_status(first) == CVESourceFetchStatus.FAILURE
        assert await env.source_status(second) == CVESourceFetchStatus.SUCCESS
        assert counters(batch.fetcher) == Counters(1, 0, 1, 1)
        _assert_private(logs)

    async def test_commit_failure_terminates_without_warning_metric_or_status(
        self, env: Env, batch: Batch, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        first, second = await env.cve(), await env.cve()
        env.pages([env.record(first.cve_id), env.record(second.cve_id)])
        trace = _trace(monkeypatch, batch)
        error = RuntimeError(FAILURE_TEXT)

        async def commit() -> None:
            raise error

        monkeypatch.setattr(batch.session, "commit", commit)

        with capture_logs() as logs, pytest.raises(RuntimeError) as raised:
            await batch.execute()

        assert raised.value is error
        assert trace.ingested == [0]
        assert trace.rollbacks == [-1]
        assert counters(batch.fetcher) == Counters(0, 0, 0, 0)
        assert _events(logs, CVE_FETCH_ITEM_FAILED_EVENT) == []
        await batch.session.rollback()
        await env.assert_untouched(first)
        await env.assert_untouched(second)
        assert env.isolated == []
        assert env.status_opened == [0]
        assert env.published.calls == []

    async def test_ambiguous_commit_terminates_without_metric_or_status(
        self, env: Env, batch: Batch, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        first, second = await env.cve(), await env.cve()
        env.pages([env.record(first.cve_id), env.record(second.cve_id)])
        real_commit = batch.session.commit
        error = ConnectionResetError("commit outcome unknown")

        async def commit() -> None:
            await real_commit()
            raise error

        monkeypatch.setattr(batch.session, "commit", commit)

        with capture_logs() as logs, pytest.raises(ConnectionResetError):
            await batch.execute()

        assert counters(batch.fetcher) == Counters(0, 0, 0, 0)
        assert _events(logs, CVE_FETCH_ITEM_FAILED_EVENT) == []
        # The durable commit is never reclassified as an isolated failure.
        assert await env.source_status(first) == CVESourceFetchStatus.SUCCESS
        await env.assert_untouched(second)
        assert env.isolated == []
        assert env.published.calls == []

    async def test_non_operational_post_commit_error_aborts_and_keeps_success(
        self, env: Env, batch: Batch
    ) -> None:
        first, second = await env.cve(), await env.cve()
        env.pages(
            [
                env.record(
                    first.cve_id, configurations=[_configuration(_match(CPE_A))]
                ),
                env.record(second.cve_id),
            ]
        )
        error = EncodeError(FAILURE_TEXT)
        env.published.errors[RESOLVE] = error

        with capture_logs() as logs, pytest.raises(EncodeError) as raised:
            await batch.execute()

        assert raised.value is error
        # Success and effect were recorded after the commit; no failure.
        assert counters(batch.fetcher) == Counters(1, 0, 1, 0)
        assert _events(logs, CVE_FETCH_ITEM_FAILED_EVENT) == []
        assert await env.source_status(first) == CVESourceFetchStatus.SUCCESS
        await env.assert_untouched(second)
        assert env.isolated == []

    async def test_broker_operational_handoff_failure_keeps_success(
        self, env: Env, batch: Batch
    ) -> None:
        cve = await env.cve()
        env.pages(
            [env.record(cve.cve_id, configurations=[_configuration(_match(CPE_A))])]
        )
        env.published.errors[RESOLVE] = BrokerOperationalError(FAILURE_TEXT)

        with capture_logs() as logs:
            await batch.execute()

        assert counters(batch.fetcher) == Counters(1, 0, 1, 0)
        assert await env.source_status(cve) == CVESourceFetchStatus.SUCCESS
        assert len(_events(logs, HANDOFF_PUBLICATION_FAILED_EVENT)) == 1
        assert _events(logs, CVE_FETCH_ITEM_FAILED_EVENT) == []
        _assert_private(logs)


_SIGNALS: Final = [asyncio.CancelledError, SoftTimeLimitExceeded, MemoryError]


@pytest.mark.integration
class TestWholeRunSignals:
    @pytest.mark.parametrize("stage", ["map", "upsert", "references", "flush"])
    @pytest.mark.parametrize("signal_type", _SIGNALS, ids=lambda t: t.__name__)
    async def test_signal_propagates_from_the_cve_boundary(
        self,
        stage: str,
        signal_type: type[BaseException],
        env: Env,
        batch: Batch,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        first, second = await env.cve(), await env.cve()
        env.pages([env.record(first.cve_id), env.record(second.cve_id)])
        trace = _trace(monkeypatch, batch)
        signal = signal_type()

        async def raise_signal(*args: Any, **kwargs: Any) -> Any:
            raise signal

        def raise_signal_sync(*args: Any, **kwargs: Any) -> Any:
            raise signal

        if stage == "map":
            monkeypatch.setattr(nvd_cve_record, "map_vulnerability", raise_signal_sync)
        elif stage == "upsert":
            monkeypatch.setattr(cve_service, "upsert_cve", raise_signal)
        elif stage == "references":
            monkeypatch.setattr(reference_service, "upsert_references", raise_signal)
        else:
            real_flush = batch.session.flush
            traced_ingest = batch.fetcher._ingest
            inside_ingest = [False]

            async def ingest(
                session: AsyncSession, element: object, source_names: Any
            ) -> CVEFetchResult:
                inside_ingest[0] = True
                try:
                    return await traced_ingest(session, element, source_names)
                finally:
                    inside_ingest[0] = False

            async def flush(*args: Any, **kwargs: Any) -> None:
                await real_flush(*args, **kwargs)
                if not inside_ingest[0]:
                    raise signal

            monkeypatch.setattr(batch.fetcher, "_ingest", ingest)
            monkeypatch.setattr(batch.session, "flush", flush)

        with capture_logs() as logs, pytest.raises(signal_type) as raised:
            await batch.execute()

        assert raised.value is signal
        assert trace.current == [0]
        assert trace.rollbacks == [-1]
        assert counters(batch.fetcher) == Counters(0, 0, 0, 0)
        assert logs == []
        assert env.isolated == []
        await batch.session.rollback()
        await env.assert_untouched(first)
        await env.assert_untouched(second)

    @pytest.mark.parametrize("request_kind", ["source", "page"])
    @pytest.mark.parametrize("signal_type", _SIGNALS, ids=lambda t: t.__name__)
    async def test_signal_propagates_from_an_nvd_request(
        self,
        request_kind: str,
        signal_type: type[BaseException],
        env: Env,
        batch: Batch,
    ) -> None:
        """Neither the Source API degraded mode nor the page-level
        sanitization converts a whole-run signal."""
        cve = await env.cve()
        env.pages([env.record(cve.cve_id)])
        signal = signal_type()
        if request_kind == "source":
            env.server.source_once.append(raising(signal))
        else:
            env.server.page_once[0] = [raising(signal)]

        with capture_logs() as logs, pytest.raises(signal_type) as raised:
            await batch.execute()

        assert raised.value is signal
        assert raised.value.__cause__ is None
        assert env.server.kinds == (
            ["source"] if request_kind == "source" else ["source", "page"]
        )
        assert counters(batch.fetcher) == Counters(0, 0, 0, 0)
        assert logs == []
        await env.assert_untouched(cve)


# ---------------------------------------------------------------------------
# CPE applicability outcomes (NVD CPE Applicability Selection)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestCpeOutcomes:
    async def test_skipped_units_keep_the_ordinary_outcome_and_hand_off_selected(
        self, env: Env, batch: Batch
    ) -> None:
        skipped, plain = await env.cve(), await env.cve()
        env.pages(
            [
                env.record(skipped.cve_id, configurations=CPE_CONFIGURATIONS),
                env.record(plain.cve_id),
            ]
        )

        with capture_logs() as logs:
            await batch.execute()

        # No failure, the ordinary updated action and success for both.
        assert counters(batch.fetcher) == Counters(2, 0, 2, 0)
        assert logs == [
            _skip(skipped.cve_id, "invalid_cpe_configuration"),
            _skip(skipped.cve_id, "invalid_cpe_match"),
        ]
        _assert_private(logs, MATCH_ID, MATCH_ID.lower(), "example")
        [ticket] = await env.tickets(skipped)
        assert env.published.published(RESOLVE) == [
            {
                "ticket_id": str(ticket.id),
                "cpe_matches": SELECTED_CPES,
                "affected_cpes": [],
                "vendor_products": [],
                "resolved_packages": [],
            }
        ]
        assert await env.source_status(skipped) == CVESourceFetchStatus.SUCCESS

    async def test_excluded_entries_alone_log_and_hand_off_nothing(
        self, env: Env, batch: Batch
    ) -> None:
        cve = await env.cve()
        env.pages(
            [
                env.record(
                    cve.cve_id,
                    configurations=[
                        _configuration(_match(CPE_PLATFORM, vulnerable=False)),
                        _configuration(_match(CPE_NEGATED), negate=True),
                    ],
                )
            ]
        )

        with capture_logs() as logs:
            await batch.execute()

        assert counters(batch.fetcher) == Counters(1, 0, 1, 0)
        assert logs == []
        assert env.published.calls == []


# ---------------------------------------------------------------------------
# External String Admissibility (periodic outcomes)
# ---------------------------------------------------------------------------


@pytest.mark.integration
@pytest.mark.parametrize("character", INADMISSIBLE_CHARACTERS)
class TestExternalStringAdmissibility:
    @pytest.mark.parametrize(
        ("members", "cause"),
        [
            (
                lambda c: {
                    "descriptions": [{"lang": "en", "value": f"{FAILURE_TEXT}{c}"}]
                },
                "ValidationError",
            ),
            (lambda c: {"published": f"{PUBLISHED}{c}"}, _STRUCTURE),
            (lambda c: {"lastModified": f"{LAST_MODIFIED}{c}"}, _STRUCTURE),
        ],
        ids=["description", "published", "last_modified"],
    )
    async def test_inadmissible_character_in_a_global_string_is_an_isolated_failure(
        self, members: Any, cause: str, env: Env, batch: Batch, character: str
    ) -> None:
        failing, later = await env.cve(), await env.cve()
        record = env.sourced(failing.cve_id)
        record["cve"].update(members(character), references=[{"url": URL_1}])
        env.pages([record, env.record(later.cve_id)])

        with capture_logs() as logs:
            await batch.execute()

        assert _events(logs, CVE_FETCH_ITEM_FAILED_EVENT) == [
            _failed(failing.cve_id, cause)
        ]
        _assert_private(logs)
        # No database error and no write from the unit.
        assert await env.count(CVECVSSAssessment, failing) == 0
        assert await env.count(CVECWE, failing) == 0
        assert await env.references(failing) == []
        named = await env.cve_named(failing.cve_id)
        assert named is not None
        assert named.description is None
        assert await env.source_status(failing) == CVESourceFetchStatus.FAILURE
        assert await env.source_status(later) == CVESourceFetchStatus.SUCCESS
        assert counters(batch.fetcher) == Counters(1, 0, 1, 1)

    async def test_inadmissible_character_in_the_record_id_is_the_invalid_id_path(
        self, env: Env, batch: Batch, character: str
    ) -> None:
        cve = await env.cve()
        env.pages([env.record(f"{cve.cve_id}{character}")])

        with capture_logs() as logs:
            await batch.execute()

        assert _events(logs, CVE_FETCH_ITEM_FAILED_EVENT) == [_failed(None, _ID)]
        _assert_private(logs, cve.cve_id)
        await env.assert_untouched(cve)
        assert env.isolated == []
        assert counters(batch.fetcher) == Counters(0, 0, 0, 1)

    async def test_inadmissible_character_in_a_candidate_skips_only_that_candidate(
        self, env: Env, batch: Batch, character: str
    ) -> None:
        """The resolved Source API display name of `UNKNOWN_SOURCE` carries
        the character: its CVSS candidate is skipped by `upsert_cve()` as
        `invalid_provider` and its CWE as `invalid_cwe`."""
        sources = copy.deepcopy(load_json_fixture(SOURCE_PAGE))
        sources["sources"].append(
            {"name": f"Example{character}CNA", "sourceIdentifiers": [UNKNOWN_SOURCE]}
        )
        env.server.sources = sources
        cve = await env.cve()
        env.pages(
            [
                env.record(
                    cve.cve_id,
                    metrics={
                        "cvssMetricV30": [_metric(CNA_SOURCE, f"{V31}{character}")],
                        "cvssMetricV31": [
                            _metric(NVD, V31),
                            _metric(UNKNOWN_SOURCE, V31_CNA),
                        ],
                    },
                    weaknesses=[
                        _weakness(NVD, f"CWE-79{character}"),
                        _weakness(NVD, "CWE-352"),
                        _weakness(UNKNOWN_SOURCE, "CWE-20"),
                    ],
                    references=[
                        {"url": f"{URL_1}{FAILURE_TEXT}{character}"},
                        {"url": f"{URL_1}?{FAILURE_TEXT}{character}"},
                        {"url": f"{URL_1}#{FAILURE_TEXT}{character}"},
                        {"url": URL_2},
                    ],
                    configurations=[
                        _configuration(
                            _match(f"{CPE_A}{character}"),
                            _match(CPE_O, matchCriteriaId=f"{MATCH_ID}{character}"),
                            _match(CPE_H),
                        )
                    ],
                )
            ]
        )

        with capture_logs() as logs:
            await batch.execute()

        assert counters(batch.fetcher) == Counters(1, 0, 1, 0)
        assert sorted((entry["event"], entry.get("reason")) for entry in logs) == [
            ("automatic_reference_rejected", "control_character"),
            ("automatic_reference_rejected", "control_character"),
            ("automatic_reference_rejected", "control_character"),
            (SKIP_EVENT, "invalid_provider"),
            (CVE_FETCH_CANDIDATE_SKIPPED_EVENT, "invalid_cpe_match"),
            (CVE_FETCH_CANDIDATE_SKIPPED_EVENT, "invalid_cwe"),
            (CVE_FETCH_CANDIDATE_SKIPPED_EVENT, "invalid_vector"),
        ]
        _assert_private(logs, V31, URL_1, "Example")
        assert await env.assessments(cve) == {("NVD", V31)}
        assert await env.cwes(cve) == {("CWE-352", "NVD")}
        assert [url for url, _, _ in await env.references(cve)] == [
            URL_2,
            f"https://nvd.nist.gov/vuln/detail/{cve.cve_id}",
        ]
        [handoff] = env.published.published(RESOLVE)
        assert handoff["cpe_matches"] == [
            {"criteria": CPE_H, "vulnerable": True, "match_criteria_id": None}
        ]


# ---------------------------------------------------------------------------
# run(): the sync_nvd_cves metric mapping on a finalized FetcherRun
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestRunMetrics:
    async def test_success_maps_created_updated_and_unchanged(self, env: Env) -> None:
        await env.seed_run("success", datetime.now(UTC) - timedelta(hours=1))
        unchanged = await env.cve()
        unchanged_record = env.record(unchanged.cve_id)
        env.pages([unchanged_record])
        await (await env.batch(cursor=False)).execute()
        updated = await env.cve()
        created_id = env.new_cve_id()
        env.pages(
            [unchanged_record, env.record(updated.cve_id)],
            [env.record(created_id)],
        )

        run = await env.run()

        assert _outcome(run) == ("success", 3, 1, 1, 0)
        assert run.error_message is None
        assert run.error_detail is None
        assert run.cursor is None
        assert await env.cve_named(created_id) is not None

    async def test_success_plus_failure_is_partial(self, env: Env) -> None:
        await env.seed_run("success", datetime.now(UTC) - timedelta(hours=1))
        ok, failing = await env.cve(), await env.cve()
        env.pages(
            [
                env.record(ok.cve_id),
                env.record(failing.cve_id, vulnStatus=None),
                "not-a-record",
            ]
        )
        fetcher, run_id = await env.run_row()

        with capture_logs(processors=[merge_contextvars]) as logs:
            await fetcher.run(run_id=run_id, config=_RUN_CONFIG)

        run = await env.run_outcome(run_id)
        assert _outcome(run) == ("partial", 1, 0, 1, 2)
        assert run.error_message is None
        assert run.cursor is None
        # The per-CVE events bind to the run's correlation context.
        assert _events(logs, CVE_FETCH_ITEM_FAILED_EVENT) == [
            {**_failed(failing.cve_id, _STRUCTURE), "fetcher_run_id": str(run_id)},
            {**_failed(None, _STRUCTURE), "fetcher_run_id": str(run_id)},
        ]

    async def test_all_selected_units_failed_is_failure(self, env: Env) -> None:
        await env.seed_run("success", datetime.now(UTC) - timedelta(hours=1))
        structure = await env.cve()
        env.pages(
            [
                env.record("CVE-24-1"),
                env.record(structure.cve_id, lastModified=None),
                1,
            ]
        )

        run = await env.run()

        assert _outcome(run) == ("failure", 0, 0, 0, 3)
        assert run.error_message == "All 3 items failed"
        assert run.error_detail is None
        assert run.cursor is None

    async def test_post_commit_error_fails_the_run_and_keeps_success_metrics(
        self, env: Env
    ) -> None:
        await env.seed_run("success", datetime.now(UTC) - timedelta(hours=1))
        cve = await env.cve()
        env.pages(
            [env.record(cve.cve_id, configurations=[_configuration(_match(CPE_A))])]
        )
        env.published.errors[RESOLVE] = EncodeError(FAILURE_TEXT)

        run = await _run_expecting(env, EncodeError)

        assert _outcome(run) == ("failure", 1, 0, 1, 0)
        assert run.error_message == "Unexpected error"
        assert await env.source_status(cve) == CVESourceFetchStatus.SUCCESS

    async def test_commit_failure_fails_the_run_without_unit_metrics(
        self, env: Env, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        await env.seed_run("success", datetime.now(UTC) - timedelta(hours=1))
        cve = await env.cve()
        env.pages([env.record(cve.cve_id)])
        real_factory = env.factory
        sessions = [0]

        def execution_session() -> AsyncSession:
            session = real_factory()

            async def commit() -> None:
                raise RuntimeError(FAILURE_TEXT)

            monkeypatch.setattr(session, "commit", commit)
            return session

        def factory() -> AsyncSession:
            # Settings/cursor load, then the execution session, then
            # finalization: only the execution session fails to commit.
            sessions[0] += 1
            return execution_session() if sessions[0] == 2 else real_factory()

        monkeypatch.setattr(base_fetcher_module, "async_session_factory", factory)

        run = await _run_expecting(env, RuntimeError)

        assert _outcome(run) == ("failure", 0, 0, 0, 0)
        assert run.error_message == "Unexpected error"
        await env.assert_untouched(cve)
        assert env.isolated == []


# ---------------------------------------------------------------------------
# Privacy and secrets across a run
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestPrivacy:
    async def test_logs_and_run_fields_carry_no_secret_or_upstream_text(
        self, env: Env, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        await env.seed_run("success", datetime.now(UTC) - timedelta(hours=1))
        ok, failing = await env.cve(), await env.cve()
        noisy = env.fixture("record_analyzed_full", ok.cve_id)
        cve = noisy["cve"]
        cve["descriptions"] = [{"lang": "en", "value": FAILURE_TEXT}]
        cve["vulnStatus"] = FAILURE_TEXT
        cve["metrics"]["cvssMetricV31"].extend(
            [
                _metric(UNKNOWN_SOURCE, V31_CNA),
                _metric("suse-1@example.com", V31_CNA),
                _metric(NVD, f"CVSS:3.1/AV:N/{FAILURE_TEXT}"),
            ]
        )
        cve["weaknesses"].append(_weakness(CNA_SOURCE, FAILURE_TEXT))
        cve["configurations"].append(
            _configuration(_match(f"cpe:2.3:a:{FAILURE_TEXT}\x00"))
        )
        invalid = env.record(f"CVE-2099-{FAILURE_TEXT}")
        env.pages(
            [
                invalid,
                noisy,
                env.record(failing.cve_id, lastModified=FAILURE_TEXT),
            ]
        )
        fetcher, run_id = await env.run_row()

        with capture_logs(processors=[merge_contextvars]) as logs:
            await fetcher.run(run_id=run_id, config=_RUN_CONFIG)

        run = await env.run_outcome(run_id)
        assert _outcome(run) == ("partial", 1, 0, 1, 2)
        assert {entry["event"] for entry in logs} == {
            CVE_FETCH_ITEM_FAILED_EVENT,
            CVE_FETCH_CANDIDATE_SKIPPED_EVENT,
            NVD_VULN_STATUS_UNRECOGNIZED_EVENT,
        }
        assert SKIP_EVENT not in {entry["event"] for entry in logs}
        _assert_private(
            logs,
            UNKNOWN_SOURCE,
            "suse-1@example.com",
            "134c704f-9b21-4f2e-91b3-4a467353bcc0",
            "CISA-ADP",
            "SUSE",
            V31_CNA,
            "tenda",
            "CVE-2099-Reported",
        )
        _assert_content_free(run.error_message, run.error_detail, run.error_traceback)
        assert env.server.kinds == ["source", "page"]
        for request in env.server.requests:
            assert request.headers[API_KEY_HEADER] == API_KEY
            assert API_KEY not in str(request.url)

    async def test_a_failed_page_detail_names_the_url_without_the_key(
        self, env: Env
    ) -> None:
        await env.seed_run("success", datetime.now(UTC) - timedelta(hours=1))
        env.server.page_responses[0] = status(500, FAILURE_TEXT.encode())

        run = await _run_expecting(env, FetcherError)

        assert run.error_message == _http(500)
        assert run.error_detail is not None
        assert "500 Internal Server Error" in run.error_detail
        assert CVE_API_URL in run.error_detail
        _assert_content_free(run.error_detail, run.error_traceback)
