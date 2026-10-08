"""Tests for the periodic batch `SyncGhsaAdvisories.execute()` and its `run()`
metrics (backend/app/services/tickets/sync_ghsa_advisories.py).

Owning specifications:

- docs/features/tickets/cve-sync-ghsa.md (Algorithm steps 1-6.f, including
  the next-URL check and the throttle; First Run Behavior; Stale Cursor
  Handling; Overlap Buffer; Cursor Mechanism; Field Mapping; Response
  Validation, including External String Admissibility; Error Handling, the
  `execute()` page-level and per-advisory tables and Sanitized error
  messages; Metrics).
- docs/features/platform/cve-fetcher-infrastructure.md (`CVEFetchResult`;
  Per-CVE Finalization; Session Lifecycle for API-based CVE Fetchers,
  template 2, isolated status commit, and metric placement; Batch Error
  Handling, Per-item failure event; Metric Definitions).
- docs/features/platform/fetcher-infrastructure.md (Error Message
  Sanitization; `SoftTimeLimitExceeded` handling convention) and
  docs/features/platform/logging.md (Secrets and PII Discipline).
- docs/features/platform/testing-strategy.md (CVE Fetcher Infrastructure:
  One-shot finalization, Periodic metrics, Isolated statuses; Fetcher
  Outcome and Effect Accounting, the `sync_ghsa_advisories` mapping;
  External String Admissibility; Parallel Execution).

Every test commits real rows: CVEs with Tickets of an `IngestionWorld`
(deleted at teardown with their children, references, and Ticket events,
including every CVE and Ticket the code under test creates, whose CVE-IDs
are drawn from the world), the `sync_ghsa_advisories` `FetcherConfig` and
its `FetcherRun` rows, and a test-only "other fetcher" configuration. The
derived cursor is read from the latest `success`/`partial` `FetcherRun` of
the fetcher's own name, so these tests own every committed row under that
name while they run:

- each pytest-xdist worker uses its own PostgreSQL database and runs one
  test at a time (testing-strategy.md, Parallel Execution);
- inside a worker, no other test leaves a committed `sync_ghsa_advisories`
  row: the reachability tests delete the configuration they seed and create
  no run, and bootstrap tests roll back;
- the `env` fixture asserts that no such row exists before it seeds its
  own and none remains at teardown, and that the number of committed CVEs
  is unchanged, so a leak fails loudly.

Advisories carry unique fictional GHSA-IDs because `(source, identifier)`
of an external identifier is globally unique; live fixtures are retargeted
to world CVE-IDs and fresh GHSA-IDs. `execute()` tests use an independent
`db_session_factory` session with real commits and set the automatic
periodic context that `run()` establishes. HTTP is the in-process
`GhsaServer`; `GITHUB_TOKEN` is set to a fictional value on
`app.config.settings`; the broker call is the recorded
`task_publication.publish_task`; the isolated status sessions are counted
and `_isolated_status_commit()` is spied; the throttle sleep is recorded
instead of slept. All identifiers and texts are fictional, except the
public data of the live fixtures.
"""

from __future__ import annotations

import asyncio
import copy
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
from datetime import UTC, datetime, timedelta
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
from app.core.enums import CVESourceFetchStatus
from app.models.cve import CVE
from app.models.cve_affected_version import CVEAffectedVersion
from app.models.cve_cvss_assessment import CVECVSSAssessment
from app.models.cve_cwe import CVECWE
from app.models.cve_external_identifier import CVEExternalIdentifier
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
    HANDOFF_PUBLICATION_FAILED_EVENT,
    CVEFetchResult,
)
from app.services.base_fetcher import FetcherError, FetcherRunConfig
from app.services.cve_ingest import UpsertAction
from app.services.tickets import ghsa_advisory_record
from app.services.tickets import sync_ghsa_advisories as sync_module
from app.services.tickets.sync_ghsa_advisories import (
    AUTHENTICATION_FAILED,
    CONNECTION_FAILED,
    CVE_FETCH_CANDIDATE_SKIPPED_EVENT,
    CVE_FETCH_ITEM_FAILED_EVENT,
    GHSA_CURSOR_RESET_EVENT,
    GHSA_VERSION_RANGE_UNRECOGNIZED_EVENT,
    RATE_LIMITED,
    TOKEN_NOT_CONFIGURED,
    UNPARSEABLE_RESPONSE,
    UNTRUSTED_NEXT_URL,
    SyncGhsaAdvisories,
)
from tests.support.cve_catch_up import Publications
from tests.support.cve_ingest import SKIP_EVENT, SKIP_EVENT_KEYS, IngestionWorld
from tests.support.ghsa import (
    ADVISORIES_URL,
    AUTH_401_FIXTURE,
    LIVE_NEXT_LINK,
    SINGLE_REVIEWED_FIXTURE,
    GhsaServer,
    Responder,
    load_advisory_fixture,
    load_list_fixture,
    load_raw_fixture,
    raising,
    status,
)
from tests.support.ghsa import body as json_body
from tests.support.ticket_mutations import EventRow, ticket_events_by_id

SessionFactory = Callable[[], Awaitable[AsyncSession]]

NAME: Final = "sync_ghsa_advisories"
TOKEN: Final = "fictional-github-token-0001"
"""A fictional `GITHUB_TOKEN`; never a real token shape."""
RESOLVE: Final = package_service.RESOLVE_TICKET_PACKAGES_TASK
INGESTION_COMMENT: Final = "CVE ingested from GitHub Advisory Database"
V31: Final = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
V40: Final = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
URL_1: Final = "https://advisory.example.invalid/upstream/1"
REPO: Final = "https://git.example.invalid/example/project"
CREDIT_LOGIN: Final = "example-researcher"
"""The fictional credited login of every sanitized fixture."""
PERSONAL_TEXT: Final = "Reported by Alice Example <alice.example@example.invalid>"
SECRET_VALUE: Final = "api_token=Example-Secret-Token-0123456789"
FAILURE_TEXT: Final = f"{PERSONAL_TEXT}; {SECRET_VALUE}"
"""Exception or upstream text that must appear in no log field or error."""

FAILED_EVENT_KEYS: Final = frozenset(
    {"event", "log_level", "cve_id", "fetcher_name", "cause"}
)
INVALID_ID_EVENT_KEYS: Final = FAILED_EVENT_KEYS - {"cve_id"}
OVERLAP: Final = timedelta(minutes=15)
WINDOW_FORMAT: Final = "%Y-%m-%dT%H:%M:%SZ"
BATCH_DELAY: Final = 0.25
_RUN_CONFIG: Final = FetcherRunConfig(
    hard_time_limit_seconds=3600, request_delay=0.5, custom_settings={}
)

PAGE_PARAMS: Final = {
    "type": "reviewed",
    "is_withdrawn": "false",
    "sort": "updated",
    "direction": "asc",
    "per_page": "100",
}
"""The fixed filters of every page request (Algorithm step 5)."""


class Counters(NamedTuple):
    succeeded: int
    created: int
    updated: int
    failed: int


def counters(fetcher: SyncGhsaAdvisories) -> Counters:
    return Counters(
        fetcher._succeeded, fetcher._created, fetcher._updated, fetcher._failed
    )


def _events(logs: Iterable[Mapping[str, Any]], name: str) -> list[Mapping[str, Any]]:
    return [entry for entry in logs if entry["event"] == name]


def _assert_private(logs: Iterable[Mapping[str, Any]], *values: str) -> None:
    for entry in logs:
        rendered = repr(dict(entry))
        for fragment in (
            TOKEN,
            "Bearer",
            FAILURE_TEXT,
            PERSONAL_TEXT,
            SECRET_VALUE,
            "Alice",
            CREDIT_LOGIN,
            "\\x00",
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


def _window(cursor: datetime) -> str:
    return f">={(cursor - OVERLAP).strftime(WINDOW_FORMAT)}"


def _outcome(run: FetcherRun) -> tuple[str, int, int, int, int]:
    return (
        run.status,
        run.items_succeeded,
        run.items_created,
        run.items_updated,
        run.items_failed,
    )


def _new_ghsa_id() -> str:
    """A unique fictional GHSA-ID (external identifiers are globally
    unique per source)."""
    digits = uuid.uuid4().hex
    return f"GHSA-{digits[:4]}-{digits[4:8]}-{digits[8:12]}"


def _vulnerability(
    name: str | None, ecosystem: str = "npm", version_range: str | None = "< 1.0"
) -> dict[str, Any]:
    return {
        "package": {"ecosystem": ecosystem, "name": name},
        "vulnerable_version_range": version_range,
    }


# ---------------------------------------------------------------------------
# Harness
# ---------------------------------------------------------------------------


@dataclass
class Env:
    world: IngestionWorld
    factory: async_sessionmaker[AsyncSession]
    server: GhsaServer
    published: Publications
    cve_baseline: int
    sleeps: list[tuple[float, int]] = field(default_factory=list)
    """Each recorded throttle sleep and the number of requests made before
    it."""
    status_opened: list[int] = field(default_factory=lambda: [0])
    isolated: list[tuple[str, CVESourceFetchStatus]] = field(default_factory=list)
    other_names: list[str] = field(default_factory=list)

    # -- data ----------------------------------------------------------

    async def cve(self) -> CVE:
        """A committed CVE with an `Analysis` Ticket."""
        cve = await self.world.cve_in()
        await self.world.ticket(cve_id=cve.id)
        return cve

    def new_cve_id(self) -> str:
        """A CVE-ID absent from the database, deleted at teardown should
        the code under test create it."""
        return self.world.new_cve_id()

    @staticmethod
    def advisory(cve_id: object, **members: Any) -> dict[str, Any]:
        """A minimal fictional advisory with a fresh GHSA-ID."""
        ghsa_id = _new_ghsa_id()
        advisory: dict[str, Any] = {
            "ghsa_id": ghsa_id,
            "html_url": f"https://github.com/advisories/{ghsa_id}",
            "cve_id": cve_id,
        }
        advisory.update(members)
        return advisory

    @staticmethod
    def fixture(name: str, cve_id: str) -> dict[str, Any]:
        """A live advisory fixture retargeted to `cve_id` and a fresh
        GHSA-ID; its own advisory URL in `references` follows."""
        if name == SINGLE_REVIEWED_FIXTURE:
            advisory: dict[str, Any] = copy.deepcopy(load_list_fixture(name)[0])
        else:
            advisory = copy.deepcopy(load_advisory_fixture(name))
        old_url = advisory["html_url"]
        ghsa_id = _new_ghsa_id()
        advisory["cve_id"] = cve_id
        advisory["ghsa_id"] = ghsa_id
        advisory["html_url"] = f"https://github.com/advisories/{ghsa_id}"
        advisory["references"] = [
            advisory["html_url"] if url == old_url else url
            for url in advisory["references"]
        ]
        return advisory

    def pages(self, *pages: Any) -> None:
        self.server.pages = list(pages)

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
        name = f"test_ghsa_other_{uuid.uuid4().hex[:12]}"
        async with self.factory() as session:
            session.add(FetcherConfig(fetcher_name=name, enabled=True))
            await session.commit()
        self.other_names.append(name)
        return name

    def fetcher(self) -> SyncGhsaAdvisories:
        instance = SyncGhsaAdvisories()
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

    async def run_row(self) -> tuple[SyncGhsaAdvisories, uuid.UUID]:
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

    async def source_status(self, cve: CVE) -> str | None:
        async with self.factory() as session:
            value: str | None = await session.scalar(
                select(CVESource.status).where(
                    CVESource.cve_id == cve.id, CVESource.source == "ghsa"
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

    async def ghsa_rows(self, cve: CVE) -> set[tuple[Any, ...]]:
        async with self.factory() as session:
            rows = await session.execute(
                select(
                    CVEAffectedVersion.product,
                    CVEAffectedVersion.ecosystem,
                    CVEAffectedVersion.repo,
                    CVEAffectedVersion.version,
                    CVEAffectedVersion.version_end,
                    CVEAffectedVersion.version_end_inclusive,
                ).where(
                    CVEAffectedVersion.cve_id == cve.id,
                    CVEAffectedVersion.source_container == "ghsa",
                )
            )
        return {tuple(row) for row in rows}

    async def identifiers(self, cve: CVE) -> set[tuple[str, str, str | None]]:
        async with self.factory() as session:
            rows = await session.execute(
                select(
                    CVEExternalIdentifier.source,
                    CVEExternalIdentifier.identifier,
                    CVEExternalIdentifier.url,
                ).where(CVEExternalIdentifier.cve_id == cve.id)
            )
        return {(source, identifier, url) for source, identifier, url in rows}

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
        """No GHSA child, source status, or reference row."""
        for model in (CVEAffectedVersion, CVEExternalIdentifier, CVECWE, CVESource):
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
        server=GhsaServer(),
        published=Publications(),
        cve_baseline=await _cve_count(real_session_factory),
    )
    # The derived cursor reads every committed run of this name.
    assert await created.committed_rows() == 0

    def status_sessions() -> AsyncSession:
        created.status_opened[0] += 1
        return real_session_factory()

    real_isolated = SyncGhsaAdvisories._isolated_status_commit

    async def isolated(
        self: SyncGhsaAdvisories, cve_id: str, status_value: CVESourceFetchStatus
    ) -> None:
        created.isolated.append((cve_id, status_value))
        await real_isolated(self, cve_id, status_value)

    async def sleep(delay: float) -> None:
        created.sleeps.append((delay, len(created.server.requests)))

    monkeypatch.setattr(app_settings, "github_token", SecretStr(TOKEN))
    monkeypatch.setattr(
        base_cve_fetcher_module, "async_session_factory", status_sessions
    )
    monkeypatch.setattr(
        base_fetcher_module, "async_session_factory", real_session_factory
    )
    monkeypatch.setattr(task_publication, "publish_task", created.published)
    monkeypatch.setattr(SyncGhsaAdvisories, "_isolated_status_commit", isolated)
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
    fetcher: SyncGhsaAdvisories
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
    real_process = batch.fetcher._process_advisory
    real_ingest = batch.fetcher._ingest
    real_rollback = batch.session.rollback
    position = [0]

    async def process_advisory(session: AsyncSession, element: object) -> None:
        trace.current[0] = position[0]
        position[0] += 1
        await real_process(session, element)

    async def ingest(
        session: AsyncSession, cve_id: str, element: dict[str, object]
    ) -> CVEFetchResult:
        trace.ingested.append(trace.current[0])
        return await real_ingest(session, cve_id, element)

    async def rollback() -> None:
        trace.rollbacks.append(trace.current[0])
        await real_rollback()

    monkeypatch.setattr(batch.fetcher, "_process_advisory", process_advisory)
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


# ---------------------------------------------------------------------------
# Token guard (Algorithm step 1)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestTokenGuard:
    async def test_execute_raises_before_the_cursor_read(
        self, env: Env, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        batch = await env.batch()
        cve = await env.cve()
        env.pages([env.advisory(cve.cve_id)])
        monkeypatch.setattr(app_settings, "github_token", SecretStr(""))
        reads: list[str] = []
        real_cursor = fetcher_execution.get_derived_cursor

        async def derived_cursor(session: AsyncSession, name: str) -> Any:
            reads.append(name)
            return await real_cursor(session, name)

        monkeypatch.setattr(fetcher_execution, "get_derived_cursor", derived_cursor)
        trace = _trace(monkeypatch, batch)

        with (
            capture_logs() as logs,
            trace.recording(batch),
            pytest.raises(FetcherError) as raised,
        ):
            await batch.execute()

        assert str(raised.value) == TOKEN_NOT_CONFIGURED
        assert raised.value.__cause__ is None
        assert reads == []
        assert trace.statements == []
        assert trace.rollbacks == []
        assert env.server.requests == []
        assert logs == []

    async def test_run_is_a_failure_with_the_exact_message_and_no_detail(
        self, env: Env, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        await env.seed_run("success", datetime.now(UTC) - timedelta(hours=1))
        cve = await env.cve()
        env.pages([env.advisory(cve.cve_id)])
        monkeypatch.setattr(app_settings, "github_token", SecretStr(""))
        fetcher, run_id = await env.run_row()

        with pytest.raises(FetcherError):
            await fetcher.run(run_id=run_id, config=_RUN_CONFIG)

        run = await env.run_outcome(run_id)
        assert _outcome(run) == ("failure", 0, 0, 0, 0)
        assert run.error_message == "GITHUB_TOKEN not configured"
        assert run.error_detail is None
        assert run.cursor is None
        assert env.server.requests == []
        await env.assert_untouched(cve)


# ---------------------------------------------------------------------------
# Derived cursor, first run, window, and stale cursor (steps 2-5)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestCursor:
    async def test_first_run_is_success_without_any_request(self, env: Env) -> None:
        cve_id = env.new_cve_id()
        env.pages([env.advisory(cve_id)])
        await env.seed_run("failure", datetime.now(UTC) - timedelta(hours=2))
        await env.seed_run("queued", None)

        with capture_logs() as logs:
            run = await env.run()

        assert _outcome(run) == ("success", 0, 0, 0, 0)
        assert run.error_message is None
        assert run.cursor is None
        assert env.server.requests == []
        assert env.sleeps == []
        assert logs == []
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

        assert env.page_params == [
            {**PAGE_PARAMS, "modified": _window(now - timedelta(hours=3))}
        ]

    async def test_first_request_is_the_documented_query(
        self, env: Env, batch: Batch
    ) -> None:
        assert batch.cursor is not None

        await batch.execute()

        [request] = env.server.requests
        assert request.method == "GET"
        assert str(request.url.copy_with(query=None)) == ADVISORIES_URL
        assert dict(request.url.params) == {
            **PAGE_PARAMS,
            "modified": _window(batch.cursor),
        }
        assert len(request.url.params.multi_items()) == 6
        assert request.headers["Authorization"] == f"Bearer {TOKEN}"
        assert request.headers["Accept"] == "application/vnd.github+json"
        assert request.headers["X-GitHub-Api-Version"] == "2022-11-28"

    async def test_read_transaction_ends_before_the_first_request(
        self, env: Env, batch: Batch
    ) -> None:
        in_transaction: list[bool] = []

        def respond(request: httpx.Request) -> httpx.Response:
            in_transaction.append(batch.session.in_transaction())
            return httpx.Response(200, json=[], request=request)

        env.server.page_responses[0] = respond

        await batch.execute()

        assert in_transaction == [False]

    async def test_current_run_is_never_its_own_cursor(self, env: Env) -> None:
        previous = datetime.now(UTC) - timedelta(hours=2)
        await env.seed_run("success", previous)

        run = await env.run()

        assert _outcome(run) == ("success", 0, 0, 0, 0)
        assert env.page_params == [{**PAGE_PARAMS, "modified": _window(previous)}]

    async def test_failed_run_does_not_advance_the_cursor(self, env: Env) -> None:
        previous = datetime.now(UTC) - timedelta(hours=2)
        await env.seed_run("success", previous)
        env.server.page_responses[0] = status(500)
        failed = await _run_expecting(env, FetcherError)
        assert _outcome(failed) == ("failure", 0, 0, 0, 0)
        del env.server.page_responses[0]

        second = await env.run()
        third = await env.run()

        assert _outcome(second) == ("success", 0, 0, 0, 0)
        assert second.started_at is not None
        assert env.page_params == [
            {**PAGE_PARAMS, "modified": _window(previous)},
            {**PAGE_PARAMS, "modified": _window(previous)},
            {**PAGE_PARAMS, "modified": _window(second.started_at)},
        ]
        assert third.cursor is None

    async def test_overlap_redelivery_is_one_unchanged_success(self, env: Env) -> None:
        await env.seed_run("success", datetime.now(UTC) - timedelta(hours=3))
        cve = await env.cve()
        advisory = env.advisory(cve.cve_id, vulnerabilities=[_vulnerability("example")])
        env.pages([advisory])
        first = await env.run()
        published = len(env.published.published(RESOLVE))

        second = await env.run()

        assert _outcome(first) == ("success", 1, 0, 1, 0)
        assert _outcome(second) == ("success", 1, 0, 0, 0)
        assert first.started_at is not None
        assert env.page_params[1]["modified"] == _window(first.started_at)
        # The unchanged re-delivery still hands off its package candidates.
        assert len(env.published.published(RESOLVE)) == published + 1
        assert first.cursor is None
        assert second.cursor is None


async def _run_expecting(env: Env, error: type[BaseException]) -> FetcherRun:
    fetcher, run_id = await env.run_row()
    with pytest.raises(error):
        await fetcher.run(run_id=run_id, config=_RUN_CONFIG)
    return await env.run_outcome(run_id)


STALE_AFTER: Final = timedelta(days=30)


def _freeze(monkeypatch: pytest.MonkeyPatch, instant: datetime) -> None:
    """Freeze the `now` captured at `execute()` entry (Algorithm step 3)."""
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


@pytest.mark.integration
class TestStaleCursor:
    @pytest.mark.parametrize(
        "age",
        [STALE_AFTER, timedelta(days=29, hours=23), timedelta(0)],
        ids=["exactly_30_days", "just_under", "now"],
    )
    async def test_window_start_within_30_days_is_fetched(
        self, age: timedelta, env: Env, frozen_now: datetime
    ) -> None:
        window_start = frozen_now - age
        await env.seed_run("success", window_start + OVERLAP)
        batch = await env.batch(cursor=False)

        with capture_logs() as logs:
            await batch.execute()

        assert env.page_params == [
            {**PAGE_PARAMS, "modified": f">={window_start.strftime(WINDOW_FORMAT)}"}
        ]
        assert _events(logs, GHSA_CURSOR_RESET_EVENT) == []

    @pytest.mark.parametrize(
        ("beyond", "age_days"),
        [
            (timedelta(microseconds=1), 30),
            (timedelta(hours=23), 30),
            (timedelta(days=15), 45),
            (timedelta(days=335), 365),
        ],
        ids=["one_microsecond", "hours", "45_days", "one_year"],
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
        env.pages([env.advisory(cve.cve_id)])
        batch = await env.batch(cursor=False)
        trace = _trace(monkeypatch, batch)

        with capture_logs() as logs:
            await batch.execute()

        assert logs == [
            {
                "event": GHSA_CURSOR_RESET_EVENT,
                "log_level": "warning",
                "fetcher_name": NAME,
                "age_days": age_days,
            }
        ]
        assert env.server.requests == []
        assert env.sleeps == []
        assert trace.current == [-1]
        assert counters(batch.fetcher) == Counters(0, 0, 0, 0)
        await env.assert_untouched(cve)

    async def test_reset_run_is_success_and_becomes_the_cursor(
        self, env: Env, frozen_now: datetime, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        await env.seed_run("success", frozen_now - timedelta(days=90))

        with capture_logs(processors=[merge_contextvars]) as logs:
            reset = await env.run()

        assert _outcome(reset) == ("success", 0, 0, 0, 0)
        assert reset.error_message is None
        assert reset.cursor is None
        assert env.server.requests == []
        [event_entry] = _events(logs, GHSA_CURSOR_RESET_EVENT)
        assert event_entry["age_days"] == 90
        assert reset.started_at is not None

        # The reset run's started_at is now the latest success: the next
        # scheduled run, three hours after it, fetches the window from it.
        _freeze(monkeypatch, reset.started_at + timedelta(hours=3))
        second = await env.run()

        assert _outcome(second) == ("success", 0, 0, 0, 0)
        assert env.page_params == [
            {**PAGE_PARAMS, "modified": _window(reset.started_at)}
        ]


# ---------------------------------------------------------------------------
# Pagination, the next-URL check, and the throttle (steps 6.e-f)
# ---------------------------------------------------------------------------


class LiveCursorServer(GhsaServer):
    """Also serves the live `Link` next URL of the first page with `[]`."""

    live_url = httpx.Response(200, headers={"Link": LIVE_NEXT_LINK}).links["next"][
        "url"
    ]

    def handler(self, request: httpx.Request) -> httpx.Response:
        if str(request.url) == self.live_url:
            self.requests.append(request)
            return httpx.Response(200, json=[], request=request)
        return super().handler(request)


UNTRUSTED_LINKS: Final = [
    "https://advisory.example.invalid/advisories?after=cursor-1",
    "https://api.github.com.evil.example/advisories?after=cursor-1",
    "http://api.github.com/advisories?after=cursor-1",
    "https://user@api.github.com/advisories?after=cursor-1",
    "https://api.github.com:443/advisories?after=cursor-1",
    "https://api.github.com:8443/advisories?after=cursor-1",
    "https://api.github.com/advisories/x?after=cursor-1",
    "https://api.github.com/repos?after=cursor-1",
    "https://api.github.com/advisories?after=cursor-1#x",
    "https://api.github.com/advisories?after=cursor-1#",
    "https://api.github.com/advisories?after=cursor-1 x",
    "https://api.github.com/advisories?after=cursor-1\tx",
    "https://api.github.com/advisories?after=cursor-1\x01",
    "https://API.GITHUB.COM/advisories?after=cursor-1",
]
UNTRUSTED_IDS: Final = [
    "foreign_host",
    "suffix_host",
    "http",
    "userinfo",
    "port_443",
    "port_8443",
    "sub_path",
    "other_path",
    "fragment",
    "bare_fragment",
    "space",
    "tab",
    "control",
    "uppercase_host",
]


@pytest.mark.integration
class TestPagination:
    async def test_follows_next_links_until_absent_preserving_the_filters(
        self, env: Env, batch: Batch
    ) -> None:
        cves = [await env.cve() for _ in range(3)]
        env.pages(*([env.advisory(cve.cve_id)] for cve in cves), [])

        await batch.execute()

        assert env.server.requested_page_indexes == [0, 1, 2, 3]
        assert batch.cursor is not None
        window = _window(batch.cursor)
        for index, params in enumerate(env.page_params):
            expected = {**PAGE_PARAMS, "modified": window}
            if index:
                expected["after"] = f"cursor-{index}"
            assert params == expected
        for request in env.server.requests:
            # The next URL is requested unchanged: no parameter repeated.
            keys = [key for key, _ in request.url.params.multi_items()]
            assert len(keys) == len(set(keys))
        assert env.server.authorization_headers == [f"Bearer {TOKEN}"] * 4
        assert counters(batch.fetcher) == Counters(3, 0, 3, 0)
        for cve in cves:
            assert await env.source_status(cve) == CVESourceFetchStatus.SUCCESS

    async def test_live_link_form_is_followed_unchanged(self, env: Env) -> None:
        env.server = LiveCursorServer()
        env.server.link_overrides[0] = LIVE_NEXT_LINK
        batch = await env.batch()

        await batch.execute()

        assert env.server.requested_urls[1] == LiveCursorServer.live_url
        assert env.server.authorization_headers == [f"Bearer {TOKEN}"] * 2
        assert len(env.server.requests) == 2

    @pytest.mark.parametrize("url", UNTRUSTED_LINKS, ids=UNTRUSTED_IDS)
    async def test_untrusted_next_url_aborts_without_sending_the_request(
        self, url: str, env: Env, batch: Batch
    ) -> None:
        cve = await env.cve()
        env.pages([env.advisory(cve.cve_id)], [])
        env.server.link_overrides[0] = f'<{url}>; rel="next"'

        with capture_logs() as logs, pytest.raises(FetcherError) as raised:
            await batch.execute()

        assert str(raised.value) == UNTRUSTED_NEXT_URL
        assert raised.value.__cause__ is None
        # Only the first page was requested; the token reached no other URL.
        assert env.server.requested_page_indexes == [0]
        assert len(env.server.requests) == 1
        assert env.server.authorization_headers == [f"Bearer {TOKEN}"]
        assert url not in env.server.requested_urls
        assert env.sleeps == []
        # The first page's advisory was committed before the check.
        assert counters(batch.fetcher) == Counters(1, 0, 1, 0)
        assert await env.source_status(cve) == CVESourceFetchStatus.SUCCESS
        _assert_private(logs, url)

    async def test_untrusted_next_url_run_failure_has_no_detail(self, env: Env) -> None:
        await env.seed_run("success", datetime.now(UTC) - timedelta(hours=1))
        env.pages([], [])
        env.server.link_overrides[0] = f'<{UNTRUSTED_LINKS[0]}>; rel="next"'

        run = await _run_expecting(env, FetcherError)

        assert _outcome(run) == ("failure", 0, 0, 0, 0)
        assert run.error_message == UNTRUSTED_NEXT_URL
        assert run.error_detail is None
        assert run.error_traceback is not None
        assert UNTRUSTED_LINKS[0] not in run.error_traceback

    @pytest.mark.parametrize(
        "link",
        [
            "garbage",
            f'<{ADVISORIES_URL}?before=cursor-0>; rel="prev"',
            f"<{ADVISORIES_URL}?after=cursor-1>",
            f'<{ADVISORIES_URL}?after=cursor-1>; rel="last"',
        ],
        ids=["garbage", "prev_only", "no_rel", "last_only"],
    )
    async def test_link_without_next_ends_pagination(
        self, link: str, env: Env, batch: Batch
    ) -> None:
        cve = await env.cve()
        env.pages([env.advisory(cve.cve_id)], [])
        env.server.link_overrides[0] = link

        await batch.execute()

        assert env.server.requested_page_indexes == [0]
        assert counters(batch.fetcher) == Counters(1, 0, 1, 0)


@pytest.mark.integration
class TestThrottle:
    async def test_delay_precedes_each_request_after_the_first(
        self, env: Env, batch: Batch
    ) -> None:
        cves = [await env.cve() for _ in range(4)]
        env.pages(
            [env.advisory(cves[0].cve_id), env.advisory(cves[1].cve_id)],
            [env.advisory(cves[2].cve_id)],
            [env.advisory(cves[3].cve_id)],
        )

        await batch.execute()

        # Not before the first request, not between advisories, not after
        # the last page.
        assert env.sleeps == [(BATCH_DELAY, 1), (BATCH_DELAY, 2)]
        assert len(env.server.requests) == 3

    async def test_single_page_is_never_delayed(self, env: Env, batch: Batch) -> None:
        await batch.execute()

        assert len(env.server.requests) == 1
        assert env.sleeps == []

    async def test_missing_configuration_snapshot_uses_the_class_default(
        self, env: Env, batch: Batch
    ) -> None:
        batch.fetcher.config = None
        env.pages([], [], [])

        await batch.execute()

        assert env.sleeps == [(1.0, 1), (1.0, 2)]
        assert SyncGhsaAdvisories.default_request_delay == 1.0

    async def test_run_uses_its_snapshot_delay(self, env: Env) -> None:
        await env.seed_run("success", datetime.now(UTC) - timedelta(hours=1))
        env.pages([], [])

        await env.run(
            FetcherRunConfig(
                hard_time_limit_seconds=3600, request_delay=7.5, custom_settings={}
            )
        )

        assert env.sleeps == [(7.5, 1)]


# ---------------------------------------------------------------------------
# Page-level failures (Error Handling, `execute()` page-level table)
# ---------------------------------------------------------------------------


class _TooDeeplyNestedResponse(httpx.Response):
    """A body whose decoding exhausts the recursion limit. The depth at
    which CPython's JSON decoder raises `RecursionError` depends on the
    interpreter build and stack size, so the outcome is forced here."""

    def json(self, **kwargs: Any) -> Any:
        raise RecursionError("maximum recursion depth exceeded")


def _too_deeply_nested(request: httpx.Request) -> httpx.Response:
    return _TooDeeplyNestedResponse(200, content=b"[[[]]]", request=request)


def _with_status(code: int) -> Responder:
    def respond(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            code,
            json=[{"cve_id": "CVE-2099-0001", "summary": FAILURE_TEXT}],
            request=request,
        )

    return respond


def _http(code: int) -> str:
    return f"GitHub Advisory API returned HTTP {code}"


_PAGE_FAILURES: Final[list[tuple[Responder, str, type[BaseException] | None]]] = [
    (
        status(401, load_raw_fixture(AUTH_401_FIXTURE)),
        AUTHENTICATION_FAILED,
        httpx.HTTPStatusError,
    ),
    (status(403, FAILURE_TEXT.encode()), RATE_LIMITED, httpx.HTTPStatusError),
    (status(429, FAILURE_TEXT.encode()), RATE_LIMITED, httpx.HTTPStatusError),
    (status(500, FAILURE_TEXT.encode()), _http(500), httpx.HTTPStatusError),
    (status(503), _http(503), httpx.HTTPStatusError),
    (status(400), _http(400), httpx.HTTPStatusError),
    (status(404, FAILURE_TEXT.encode()), _http(404), httpx.HTTPStatusError),
    (status(422), _http(422), httpx.HTTPStatusError),
    (
        status(301, headers={"Location": "https://advisory.example.invalid/x"}),
        _http(301),
        httpx.HTTPStatusError,
    ),
    (
        status(302, headers={"Location": f"{ADVISORIES_URL}?after=cursor-1"}),
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
        raising(httpx.ConnectTimeout("timed out")),
        CONNECTION_FAILED,
        httpx.ConnectTimeout,
    ),
    (raising(httpx.ReadTimeout("timed out")), CONNECTION_FAILED, httpx.ReadTimeout),
    (
        raising(httpx.RemoteProtocolError("peer closed connection")),
        CONNECTION_FAILED,
        httpx.RemoteProtocolError,
    ),
    (
        status(200, b"not gzip", headers={"Content-Encoding": "gzip"}),
        UNPARSEABLE_RESPONSE,
        httpx.DecodingError,
    ),
    (status(200, b"{"), UNPARSEABLE_RESPONSE, ValueError),
    (status(200, b""), UNPARSEABLE_RESPONSE, ValueError),
    (
        status(200, f"<html>{FAILURE_TEXT}</html>".encode()),
        UNPARSEABLE_RESPONSE,
        ValueError,
    ),
    (
        status(200, b'[{"cve_id": "\xff\xfe"}]'),
        UNPARSEABLE_RESPONSE,
        UnicodeDecodeError,
    ),
    (_too_deeply_nested, UNPARSEABLE_RESPONSE, RecursionError),
    (
        json_body({"cve_id": "CVE-2099-0001", "summary": FAILURE_TEXT}),
        UNPARSEABLE_RESPONSE,
        None,
    ),
    (json_body(FAILURE_TEXT), UNPARSEABLE_RESPONSE, None),
    (json_body(None), UNPARSEABLE_RESPONSE, None),
    (json_body(1), UNPARSEABLE_RESPONSE, None),
]
_PAGE_FAILURE_IDS: Final = [
    "http_401",
    "http_403",
    "http_429",
    "http_500",
    "http_503",
    "http_400",
    "http_404",
    "http_422",
    "http_301",
    "http_302",
    "http_204",
    "http_201",
    "http_206",
    "connection_refused",
    "connect_timeout",
    "read_timeout",
    "protocol_error",
    "undecodable_content_encoding",
    "truncated_json",
    "empty_body",
    "html",
    "invalid_utf8",
    "too_deeply_nested",
    "object_root",
    "string_root",
    "null_root",
    "number_root",
]


def _assert_content_free(*values: str | None) -> None:
    for value in values:
        if value is None:
            continue
        for fragment in (
            TOKEN,
            "Bearer",
            "Authorization",
            FAILURE_TEXT,
            PERSONAL_TEXT,
            SECRET_VALUE,
            CREDIT_LOGIN,
            "Bad credentials",
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
        # One request; a redirect is not followed and no page is retried.
        assert len(env.server.requests) == 1
        assert env.sleeps == []
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
        assert run.cursor is None
        _assert_content_free(run.error_message, run.error_detail, run.error_traceback)
        _assert_private(logs)
        assert len(env.server.requests) == 1

    async def test_failure_on_a_later_page_keeps_earlier_commits(
        self, env: Env
    ) -> None:
        await env.seed_run("success", datetime.now(UTC) - timedelta(hours=1))
        committed = await env.cve()
        later = await env.cve()
        env.pages(
            [env.advisory(committed.cve_id)],
            [env.advisory(later.cve_id)],
        )
        env.server.page_responses[1] = status(503, FAILURE_TEXT.encode())

        run = await _run_expecting(env, FetcherError)

        assert _outcome(run) == ("failure", 1, 0, 1, 0)
        assert run.error_message == _http(503)
        assert env.server.requested_page_indexes == [0, 1]
        assert await env.source_status(committed) == CVESourceFetchStatus.SUCCESS
        assert await env.count(CVEExternalIdentifier, committed) == 1
        await env.assert_untouched(later)


# ---------------------------------------------------------------------------
# Per-advisory selection and invalid CVE-IDs (steps 6.d.i-ii)
# ---------------------------------------------------------------------------


_INVALID_ELEMENTS: Final[list[Any]] = [
    "CVE-2099-0001",
    48001,
    None,
    True,
    [],
    ["CVE-2099-0001"],
    "advisory:CVE-24-1",
    "advisory:GHSA-fict-0001-aaaa",
    "advisory:int",
    "advisory:list",
    "advisory:empty",
    "advisory:lowercase",
    "advisory:over_long",
    "advisory:free_text",
    "advisory:nul",
]
_INVALID_IDS: Final = [
    "string_element",
    "number_element",
    "null_element",
    "boolean_element",
    "empty_list_element",
    "list_element",
    "short_year",
    "ghsa_id",
    "integer",
    "list",
    "empty",
    "lowercase",
    "over_long",
    "free_text",
    "nul",
]
_INVALID_VALUES: Final[dict[str, Any]] = {
    "advisory:CVE-24-1": "CVE-24-1",
    "advisory:GHSA-fict-0001-aaaa": "GHSA-fict-0001-aaaa",
    "advisory:int": 20990001,
    "advisory:list": ["CVE-2099-0001"],
    "advisory:empty": "",
    "advisory:lowercase": "cve-2099-0001",
    "advisory:over_long": "CVE-2099-" + "1" * 12,
    "advisory:free_text": f"CVE-2099-0001 {FAILURE_TEXT}",
    "advisory:nul": "CVE-2099-0001\x00",
}


@pytest.mark.integration
class TestSelection:
    async def test_null_and_absent_cve_id_are_skipped_silently(
        self, env: Env, batch: Batch, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        later = await env.cve()
        null_advisory = env.fixture("advisory_v3_v4", later.cve_id)
        null_advisory["cve_id"] = None
        live_null = copy.deepcopy(load_advisory_fixture("advisory_null_cve_id"))
        absent = env.advisory(None, summary=FAILURE_TEXT)
        del absent["cve_id"]
        env.pages([live_null, null_advisory, absent, env.advisory(later.cve_id)])
        trace = _trace(monkeypatch, batch)

        with capture_logs() as logs, trace.recording(batch):
            await batch.execute()

        assert trace.ingested == [3]
        for index in (0, 1, 2):
            assert trace.statements_of(index) == []
        assert trace.rollbacks == [-1]
        assert logs == []
        # Excluded before work-unit selection: neither success nor failure.
        assert counters(batch.fetcher) == Counters(1, 0, 1, 0)
        assert env.isolated == []

    @pytest.mark.parametrize("element", _INVALID_ELEMENTS, ids=_INVALID_IDS)
    async def test_invalid_cve_id_is_one_failed_unit_without_database_work(
        self, element: Any, env: Env, batch: Batch, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        later = await env.cve()
        if isinstance(element, str) and element in _INVALID_VALUES:
            element = env.advisory(_INVALID_VALUES[element], summary=FAILURE_TEXT)
        env.pages([element, env.advisory(later.cve_id)])
        trace = _trace(monkeypatch, batch)

        with capture_logs() as logs, trace.recording(batch):
            await batch.execute()

        assert trace.statements_of(0) == []
        assert trace.rollbacks == [-1]
        assert trace.ingested == [1]
        [failed] = _events(logs, CVE_FETCH_ITEM_FAILED_EVENT)
        assert failed == _failed(None, "InvalidCveIdError")
        assert set(failed) == INVALID_ID_EVENT_KEYS
        _assert_private(logs, "GHSA-", "CVE-24-1", "cve-2099")
        # No isolated status for the invalid element.
        assert env.isolated == []
        assert env.status_opened == [0]
        assert counters(batch.fetcher) == Counters(1, 0, 1, 1)
        assert await env.source_status(later) == CVESourceFetchStatus.SUCCESS


# ---------------------------------------------------------------------------
# Per-advisory success and finalization (steps 6.d.iii-vi)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestAdvisorySuccess:
    async def test_new_cve_is_created_with_a_new_ticket_and_handoff(
        self, env: Env, batch: Batch
    ) -> None:
        cve_id = env.new_cve_id()
        advisory = env.advisory(
            cve_id,
            summary="Fictional title",
            references=[URL_1],
            vulnerabilities=[_vulnerability("example"), _vulnerability("other")],
        )
        env.pages([advisory])

        await batch.execute()

        assert counters(batch.fetcher) == Counters(1, 1, 0, 0)
        cve = await env.cve_named(cve_id)
        assert cve is not None
        assert cve.title == "Fictional title"
        [ticket] = await env.tickets(cve)
        assert ticket.status == "New"
        async with env.factory() as session:
            events = await ticket_events_by_id(session, ticket.id)
        assert events == [
            EventRow("ticket_created", None, None, None, INGESTION_COMMENT, None),
            EventRow("cve_associated", None, None, cve_id, None, None),
        ]
        assert await env.identifiers(cve) == {
            ("GHSA", advisory["ghsa_id"], advisory["html_url"])
        }
        assert await env.source_status(cve) == CVESourceFetchStatus.SUCCESS
        assert env.published.published(RESOLVE) == [
            {
                "ticket_id": str(ticket.id),
                "cpe_matches": [],
                "affected_cpes": [],
                "vendor_products": [],
                "resolved_packages": ["example", "other"],
            }
        ]
        assert env.isolated == []

    async def test_flush_precedes_finalization_and_effects_follow_commit(
        self, env: Env, batch: Batch, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cve = await env.cve()
        env.pages(
            [env.advisory(cve.cve_id, vulnerabilities=[_vulnerability("example")])]
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
            session: AsyncSession, cve_id: str, element: dict[str, object]
        ) -> CVEFetchResult:
            events.append("ingest")
            inside_ingest[0] = True
            try:
                return await real_ingest(session, cve_id, element)
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
        assert token.post_ingest.resolved_packages == ["example"]
        assert token._consumed
        # The effect and the success are absent until the commit.
        assert at_commit == [Counters(0, 0, 0, 0)]
        assert counters(batch.fetcher) == Counters(1, 0, 1, 0)

    async def test_live_advisories_are_committed_completely(
        self, env: Env, batch: Batch
    ) -> None:
        erlang, log4j = await env.cve(), await env.cve()
        erlang_advisory = env.fixture("advisory_erlang", erlang.cve_id)
        log4j_advisory = env.fixture("advisory_empty_source_location", log4j.cve_id)
        env.pages([erlang_advisory, log4j_advisory])

        with capture_logs() as logs:
            await batch.execute()

        assert counters(batch.fetcher) == Counters(2, 0, 2, 0)
        assert await env.ghsa_rows(erlang) == {
            (
                "ash",
                "Hex",
                "https://github.com/ash-project/ash",
                "3.0.0",
                "3.29.3",
                False,
            )
        }
        assert {row[2] for row in await env.ghsa_rows(log4j)} == {None}
        assert {row[1] for row in await env.ghsa_rows(log4j)} == {"Maven"}
        assert await env.cwes(erlang) == {("CWE-915", "GitHub")}
        assert await env.assessments(erlang) == {
            ("GitHub", erlang_advisory["cvss_severities"]["cvss_v4"]["vector_string"])
        }
        for cve, advisory in ((erlang, erlang_advisory), (log4j, log4j_advisory)):
            assert await env.identifiers(cve) == {
                ("GHSA", advisory["ghsa_id"], advisory["html_url"])
            }
            references = await env.references(cve)
            # The advisory URL listed in references[] is one source row.
            assert [url for url, _, _ in references] == sorted(
                set(advisory["references"])
            )
            assert (advisory["html_url"], "GitHub Advisory", "advisory") in references
        _assert_private(logs)

    async def test_unchanged_records_success_without_effect(
        self, env: Env, batch: Batch
    ) -> None:
        cve = await env.cve()
        advisory = env.advisory(cve.cve_id)
        env.pages([advisory])
        await batch.execute()
        second = await env.batch(cursor=False)

        await second.execute()

        assert counters(second.fetcher) == Counters(1, 0, 0, 0)
        assert env.published.published(RESOLVE) == []


# ---------------------------------------------------------------------------
# Per-advisory failures (step 6.d.vii) and the hard finalization boundary
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestAdvisoryFailure:
    async def test_schema_mismatch_rolls_back_and_writes_isolated_failure(
        self, env: Env, batch: Batch, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        failing, later = await env.cve(), await env.cve()
        env.pages(
            [
                env.advisory(failing.cve_id, published_at=FAILURE_TEXT),
                env.advisory(later.cve_id),
            ]
        )
        trace = _trace(monkeypatch, batch)

        with capture_logs() as logs:
            await batch.execute()

        assert trace.rollbacks == [-1, 0]
        assert trace.ingested == [0, 1]
        assert _events(logs, CVE_FETCH_ITEM_FAILED_EVENT) == [
            _failed(failing.cve_id, "ValidationError")
        ]
        _assert_private(logs)
        assert env.isolated == [(failing.cve_id, CVESourceFetchStatus.FAILURE)]
        assert env.status_opened == [1]
        assert await env.source_status(failing) == CVESourceFetchStatus.FAILURE
        assert await env.count(CVEExternalIdentifier, failing) == 0
        assert await env.source_status(later) == CVESourceFetchStatus.SUCCESS
        assert counters(batch.fetcher) == Counters(1, 0, 1, 1)

    async def test_failure_after_upsert_rolls_back_its_writes(
        self, env: Env, batch: Batch, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        failing = await env.cve()
        env.pages(
            [
                env.advisory(
                    failing.cve_id,
                    references=[URL_1],
                    vulnerabilities=[_vulnerability("example")],
                )
            ]
        )
        _fail_references_for(monkeypatch, {failing.cve_id}, RuntimeError(FAILURE_TEXT))

        with capture_logs() as logs:
            await batch.execute()

        # upsert_cve() wrote the GHSA rows and the success status and the
        # references were written; the rollback discarded all of them.
        assert await env.count(CVEAffectedVersion, failing) == 0
        assert await env.count(CVEExternalIdentifier, failing) == 0
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
        env.pages([env.advisory(cve_id)])
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
        env.pages([env.advisory(first.cve_id), env.advisory(second.cve_id)])
        trace = _trace(monkeypatch, batch)
        traced_ingest = batch.fetcher._ingest
        real_finalize = batch.fetcher.commit_and_dispatch
        real_flush = batch.session.flush
        inside_ingest = [False]
        own_flushes: list[int] = []
        finalized: list[int] = []

        async def ingest(
            session: AsyncSession, cve_id: str, element: dict[str, object]
        ) -> CVEFetchResult:
            inside_ingest[0] = True
            try:
                return await traced_ingest(session, cve_id, element)
            finally:
                inside_ingest[0] = False

        async def commit_and_dispatch(session: AsyncSession, result: Any) -> None:
            finalized.append(trace.current[0])
            await real_finalize(session, result)

        async def flush(*args: Any, **kwargs: Any) -> None:
            await real_flush(*args, **kwargs)
            # Only the fetcher's own per-advisory flush of the first
            # advisory fails; the delegates' flushes inside _ingest()
            # succeed.
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
        assert await env.count(CVEExternalIdentifier, first) == 0
        assert await env.source_status(second) == CVESourceFetchStatus.SUCCESS
        assert counters(batch.fetcher) == Counters(1, 0, 1, 1)
        _assert_private(logs)

    async def test_commit_failure_terminates_without_warning_metric_or_status(
        self, env: Env, batch: Batch, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        first, second = await env.cve(), await env.cve()
        env.pages([env.advisory(first.cve_id), env.advisory(second.cve_id)])
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
        env.pages([env.advisory(first.cve_id), env.advisory(second.cve_id)])
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
                env.advisory(first.cve_id, vulnerabilities=[_vulnerability("a")]),
                env.advisory(second.cve_id),
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
        env.pages([env.advisory(cve.cve_id, vulnerabilities=[_vulnerability("a")])])
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
    @pytest.mark.parametrize("stage", ["parse", "upsert", "references", "flush"])
    @pytest.mark.parametrize("signal_type", _SIGNALS, ids=lambda t: t.__name__)
    async def test_signal_propagates_from_the_advisory_boundary(
        self,
        stage: str,
        signal_type: type[BaseException],
        env: Env,
        batch: Batch,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        first, second = await env.cve(), await env.cve()
        env.pages([env.advisory(first.cve_id), env.advisory(second.cve_id)])
        trace = _trace(monkeypatch, batch)
        signal = signal_type()

        async def raise_signal(*args: Any, **kwargs: Any) -> Any:
            raise signal

        def raise_signal_sync(*args: Any, **kwargs: Any) -> Any:
            raise signal

        if stage == "parse":
            monkeypatch.setattr(
                ghsa_advisory_record, "parse_advisory", raise_signal_sync
            )
        elif stage == "upsert":
            monkeypatch.setattr(cve_service, "upsert_cve", raise_signal)
        elif stage == "references":
            monkeypatch.setattr(reference_service, "upsert_references", raise_signal)
        else:
            real_flush = batch.session.flush
            traced_ingest = batch.fetcher._ingest
            inside_ingest = [False]

            async def ingest(
                session: AsyncSession, cve_id: str, element: dict[str, object]
            ) -> CVEFetchResult:
                inside_ingest[0] = True
                try:
                    return await traced_ingest(session, cve_id, element)
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


# ---------------------------------------------------------------------------
# CVSS through the real upsert_cve()
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestCvss:
    async def test_rejected_vectors_are_skipped_and_the_advisories_succeed(
        self, env: Env, batch: Batch
    ) -> None:
        non_base_v4, temporal_v3, malformed, over_long = [
            await env.cve() for _ in range(4)
        ]
        long_vector = V31 + "/AV:N" * 40
        assert len(long_vector) > 200

        def with_vectors(cve: CVE, v3: str) -> dict[str, Any]:
            return env.advisory(
                cve.cve_id,
                cvss_severities={
                    "cvss_v3": {"vector_string": v3, "score": 9.8},
                    "cvss_v4": {"vector_string": V40, "score": 9.3},
                },
            )

        live_v4 = env.fixture("advisory_v4_non_base", non_base_v4.cve_id)
        live_v3 = env.fixture(SINGLE_REVIEWED_FIXTURE, temporal_v3.cve_id)
        env.pages(
            [
                live_v4,
                live_v3,
                with_vectors(malformed, f"CVSS:3.1/AV:N/{FAILURE_TEXT}"),
                with_vectors(over_long, long_vector),
            ]
        )

        with capture_logs() as logs:
            await batch.execute()

        assert counters(batch.fetcher) == Counters(4, 0, 4, 0)
        skips = _events(logs, SKIP_EVENT)
        assert [(entry["cve_id"], entry["reason"]) for entry in skips] == [
            (cve.cve_id, "invalid_vector")
            for cve in (non_base_v4, temporal_v3, malformed, over_long)
        ]
        assert all(set(entry) <= SKIP_EVENT_KEYS for entry in skips)
        assert _events(logs, CVE_FETCH_ITEM_FAILED_EVENT) == []
        _assert_private(
            logs,
            live_v4["cvss_severities"]["cvss_v4"]["vector_string"],
            live_v3["cvss_severities"]["cvss_v3"]["vector_string"],
            long_vector,
        )
        assert await env.assessments(non_base_v4) == set()
        assert await env.assessments(temporal_v3) == set()
        for cve in (malformed, over_long):
            assert await env.assessments(cve) == {("GitHub", V40)}
        assert await env.cwes(non_base_v4) == {("CWE-295", "GitHub")}


# ---------------------------------------------------------------------------
# External String Admissibility (periodic outcomes)
# ---------------------------------------------------------------------------

NUL: Final = f"{FAILURE_TEXT}\x00"
VERSION_NUL: Final = "1.0-fictional\x00"
"""A U+0000 operand without `<`, `>`, or `=`, so the range is recognized."""


def _nul_members(field_name: str) -> dict[str, Any]:
    vulnerability = _vulnerability("example", "npm", ">= 1.0, < 2.0")
    members: dict[str, Any] = {"vulnerabilities": [vulnerability]}
    if field_name in {"summary", "description", "ghsa_id", "html_url"}:
        members[field_name] = NUL
    elif field_name in {"published_at", "updated_at"}:
        members[field_name] = "2026-01-01T00:00:00Z\x00"
    elif field_name == "source_code_location":
        members[field_name] = f"https://git.example.invalid/{NUL}"
    elif field_name == "package_name":
        vulnerability["package"]["name"] = NUL
    elif field_name == "ecosystem":
        vulnerability["package"]["ecosystem"] = NUL
    elif field_name == "version":
        vulnerability["vulnerable_version_range"] = f">= {VERSION_NUL}, < 2.0"
    elif field_name == "version_end":
        vulnerability["vulnerable_version_range"] = f">= 1.0, < {VERSION_NUL}"
    elif field_name == "ecosystem_51":
        vulnerability["package"]["ecosystem"] = "E" * 51
    elif field_name == "source_code_location_2049":
        members["source_code_location"] = REPO + "/" + "r" * (2048 - len(REPO))
    else:
        assert field_name == "ghsa_id_101"
        members["ghsa_id"] = "G" * 101
    return members


@pytest.mark.integration
class TestExternalStringAdmissibility:
    @pytest.mark.parametrize(
        "field_name",
        [
            "summary",
            "description",
            "ghsa_id",
            "html_url",
            "published_at",
            "updated_at",
            "source_code_location",
            "package_name",
            "ecosystem",
            "version",
            "version_end",
            "ecosystem_51",
            "source_code_location_2049",
            "ghsa_id_101",
        ],
    )
    async def test_inadmissible_payload_value_is_an_isolated_failure(
        self, field_name: str, env: Env, batch: Batch
    ) -> None:
        failing, later = await env.cve(), await env.cve()
        env.pages(
            [
                env.advisory(failing.cve_id, **_nul_members(field_name)),
                env.advisory(later.cve_id),
            ]
        )

        with capture_logs() as logs:
            await batch.execute()

        assert _events(logs, CVE_FETCH_ITEM_FAILED_EVENT) == [
            _failed(failing.cve_id, "ValidationError")
        ]
        _assert_private(logs)
        assert await env.source_status(failing) == CVESourceFetchStatus.FAILURE
        assert await env.count(CVEAffectedVersion, failing) == 0
        assert await env.count(CVEExternalIdentifier, failing) == 0
        assert await env.references(failing) == []
        assert await env.source_status(later) == CVESourceFetchStatus.SUCCESS
        assert counters(batch.fetcher) == Counters(1, 0, 1, 1)

    async def test_nul_in_a_candidate_skips_only_that_candidate(
        self, env: Env, batch: Batch
    ) -> None:
        cve = await env.cve()
        advisory = env.advisory(
            cve.cve_id,
            cvss_severities={
                "cvss_v3": {"vector_string": f"{V31}\x00"},
                "cvss_v4": {"vector_string": V40},
            },
            cwes=[{"cwe_id": "CWE-79\x00"}, {"cwe_id": "CWE-352"}],
            references=[f"{URL_1}?{NUL}"],
        )
        env.pages([advisory])

        with capture_logs() as logs:
            await batch.execute()

        assert counters(batch.fetcher) == Counters(1, 0, 1, 0)
        assert sorted(
            (entry["event"], entry.get("reason"))
            for entry in logs
            if entry["log_level"] == "warning"
        ) == sorted(
            [
                (CVE_FETCH_CANDIDATE_SKIPPED_EVENT, "invalid_cwe"),
                (SKIP_EVENT, "invalid_vector"),
                ("automatic_reference_rejected", "control_character"),
            ]
        )
        _assert_private(logs, V31)
        assert await env.assessments(cve) == {("GitHub", V40)}
        assert await env.cwes(cve) == {("CWE-352", "GitHub")}
        assert [url for url, _, _ in await env.references(cve)] == [
            advisory["html_url"]
        ]

    async def test_nul_in_cve_id_is_the_invalid_id_path(
        self, env: Env, batch: Batch
    ) -> None:
        cve = await env.cve()
        env.pages([env.advisory(f"{cve.cve_id}\x00")])

        with capture_logs() as logs:
            await batch.execute()

        assert _events(logs, CVE_FETCH_ITEM_FAILED_EVENT) == [
            _failed(None, "InvalidCveIdError")
        ]
        _assert_private(logs, cve.cve_id)
        await env.assert_untouched(cve)
        assert counters(batch.fetcher) == Counters(0, 0, 0, 1)


# ---------------------------------------------------------------------------
# run(): the sync_ghsa_advisories metric mapping on a finalized FetcherRun
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestRunMetrics:
    async def test_success_maps_created_updated_unchanged_and_excludes_null(
        self, env: Env
    ) -> None:
        await env.seed_run("success", datetime.now(UTC) - timedelta(hours=1))
        unchanged = await env.cve()
        unchanged_advisory = env.advisory(unchanged.cve_id)
        env.pages([unchanged_advisory])
        await (await env.batch(cursor=False)).execute()
        updated = await env.cve()
        created_id = env.new_cve_id()
        env.pages(
            [
                unchanged_advisory,
                env.advisory(None),
                env.advisory(updated.cve_id),
            ],
            [env.advisory(created_id)],
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
                env.advisory(ok.cve_id),
                env.advisory(failing.cve_id, ghsa_id=None),
                "not-an-advisory",
            ]
        )
        fetcher, run_id = await env.run_row()

        with capture_logs(processors=[merge_contextvars]) as logs:
            await fetcher.run(run_id=run_id, config=_RUN_CONFIG)

        run = await env.run_outcome(run_id)
        assert _outcome(run) == ("partial", 1, 0, 1, 2)
        assert run.error_message is None
        assert run.cursor is None
        # The per-advisory events bind to the run's correlation context.
        assert _events(logs, CVE_FETCH_ITEM_FAILED_EVENT) == [
            {
                **_failed(failing.cve_id, "ValidationError"),
                "fetcher_run_id": str(run_id),
            },
            {**_failed(None, "InvalidCveIdError"), "fetcher_run_id": str(run_id)},
        ]

    async def test_all_selected_units_failed_is_failure(self, env: Env) -> None:
        await env.seed_run("success", datetime.now(UTC) - timedelta(hours=1))
        schema = await env.cve()
        env.pages(
            [
                env.advisory(None),
                env.advisory("CVE-24-1"),
                env.advisory(schema.cve_id, html_url=None),
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
        env.pages([env.advisory(cve.cve_id, vulnerabilities=[_vulnerability("a")])])
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
        env.pages([env.advisory(cve.cve_id)])
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
        noisy = env.fixture("advisory_v3_v4", ok.cve_id)
        noisy["summary"] = FAILURE_TEXT
        noisy["description"] = FAILURE_TEXT
        noisy["cwes"].append({"cwe_id": FAILURE_TEXT})
        noisy["vulnerabilities"].append(_vulnerability("x", "npm", FAILURE_TEXT))
        invalid = env.advisory(f"CVE-2099-{FAILURE_TEXT}", summary=FAILURE_TEXT)
        env.pages(
            [
                invalid,
                noisy,
                env.advisory(failing.cve_id, updated_at=FAILURE_TEXT),
            ]
        )
        _fail_references_for(monkeypatch, {failing.cve_id}, RuntimeError(FAILURE_TEXT))
        fetcher, run_id = await env.run_row()

        with capture_logs(processors=[merge_contextvars]) as logs:
            await fetcher.run(run_id=run_id, config=_RUN_CONFIG)

        run = await env.run_outcome(run_id)
        assert _outcome(run) == ("partial", 1, 0, 1, 2)
        assert {entry["event"] for entry in logs} >= {
            CVE_FETCH_ITEM_FAILED_EVENT,
            CVE_FETCH_CANDIDATE_SKIPPED_EVENT,
            GHSA_VERSION_RANGE_UNRECOGNIZED_EVENT,
        }
        _assert_private(logs, invalid["ghsa_id"], noisy["ghsa_id"], "Fictional")
        _assert_content_free(run.error_message, run.error_detail, run.error_traceback)
        for request in env.server.requests:
            assert request.headers["Authorization"] == f"Bearer {TOKEN}"
            assert TOKEN not in str(request.url)
