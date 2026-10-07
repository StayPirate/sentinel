"""Tests for the periodic catalog `SyncCisaKev.execute()` and its `run()`
metrics (backend/app/services/tickets/sync_cisa_kev.py).

Owning specifications:

- docs/features/tickets/cve-sync-kev.md (Conventions, the isolated-status
  deviation; Algorithm; Behavioral Notes; Error Handling, fatal and
  isolated tables, candidate skip event, External String Admissibility;
  Metrics; MITRE/KEV Overlap).
- docs/features/platform/cve-fetcher-infrastructure.md (`CVEFetchResult`;
  Per-CVE Finalization; Session Lifecycle for API-based CVE Fetchers;
  Batch Error Handling, Per-item failure event; Metric Definitions).
- docs/features/tickets/cve-service.md (Primary Entry Point: `upsert_cve()`,
  the audit label table and Ticket Creation Decision),
  docs/features/tickets/ticket-priority.md (Decision Table), and
  docs/features/tickets/ticket-references.md (Database Merge Rules).
- docs/features/platform/fetcher-infrastructure.md (Outcome and effect
  accounting; Error Message Sanitization) and
  docs/features/platform/logging.md (Secrets and PII Discipline).
- docs/features/platform/testing-strategy.md (Fetcher Outcome and Effect
  Accounting, the `sync_cisa_kev` mapping; External String Admissibility;
  CVE Fetcher Infrastructure).

Every test commits real rows: CVEs with or without Tickets of an
`IngestionWorld` (deleted at teardown with their `cve_kev_entry`,
`cve_cwe`, and `cve_source` children, their Tickets, Ticket references,
and Ticket events, including a Ticket the code under test creates for an
orphan CVE), and, for `run()`, a committed `FetcherConfig`/`FetcherRun`
pair under a test-only name, deleted at teardown. CVE-IDs that must stay
unknown are drawn from the world too, so a row created by mistake is
deleted as well. `execute()` tests use an independent `db_session_factory`
session with real commits and set the automatic periodic context that
`run()` establishes, so the finalizer records metrics. HTTP is the
in-process `KevServer`; the broker call is the recorded
`task_publication.publish_task`; the isolated status sessions
(`base_cve_fetcher.async_session_factory`) are counted and
`_isolated_status_commit()` is spied. All identifiers and texts are
fictional.
"""

from __future__ import annotations

import asyncio
import dataclasses
import json
import uuid
from collections.abc import (
    AsyncIterator,
    Awaitable,
    Callable,
    Iterable,
    Iterator,
    Mapping,
    Sequence,
)
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from typing import Any, Final, NamedTuple

import httpx
import pytest
from celery.exceptions import SoftTimeLimitExceeded
from sqlalchemy import delete, event, select, text
from sqlalchemy.exc import OperationalError
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncSession, async_sessionmaker
from structlog.contextvars import merge_contextvars
from structlog.testing import capture_logs

import app.services.base_cve_fetcher as base_cve_fetcher_module
import app.services.base_fetcher as base_fetcher_module
from app.core.enums import CVESourceFetchStatus, CVESourceType, ReferenceType
from app.models.cve import CVE
from app.models.cve_cwe import CVECWE
from app.models.cve_kev_entry import CVEKEVEntry
from app.models.cve_source import CVESource
from app.models.fetcher_config import FetcherConfig
from app.models.fetcher_run import FetcherRun
from app.models.ticket import Ticket
from app.models.ticket_reference import TicketReference
from app.services import (
    cve_service,
    package_service,
    reference_service,
    task_publication,
    ticket_convergence_publication,
)
from app.services.base_cve_fetcher import CVEFetchResult
from app.services.base_fetcher import FetcherError, FetcherRunConfig
from app.services.cve_ingest import (
    CVEIngestPayload,
    CWEEntry,
    KEVEntry,
    UpsertAction,
)
from app.services.tickets import cisa_kev_catalog
from app.services.tickets.cisa_kev_catalog import KevCatalogStructureError
from app.services.tickets.sync_cisa_kev import (
    CISA_KEV_CATALOG_RECEIVED_EVENT,
    CISA_KEV_URL,
    CVE_FETCH_CANDIDATE_SKIPPED_EVENT,
    CVE_FETCH_ITEM_FAILED_EVENT,
    SyncCisaKev,
)
from tests.support.cisa_kev import (
    FIXTURE_CVE_IDS,
    KEV_URL,
    KevServer,
    Responder,
    catalog_of,
    entry_for,
    load_catalog,
    raising,
    raw_body,
    reference_url,
    status,
)
from tests.support.cve_ingest import IngestionWorld
from tests.support.ticket_mutations import EventRow, ticket_events_by_id

SessionFactory = Callable[[], Awaitable[AsyncSession]]

NAME: Final = "sync_cisa_kev"
MITRE_NAME: Final = "sync_mitre_cves"
KEV_CWE_SOURCE: Final = "CISA KEV"
MITRE_CWE_SOURCE: Final = "adp:CISA-ADP"
RESOLVE: Final = package_service.RESOLVE_TICKET_PACKAGES_TASK
INGESTION_COMMENT: Final = "CVE ingested from CISA KEV"
DATE_ADDED: Final = date(2026, 10, 1)
"""The `dateAdded` of `entry_for()` unless a test overrides it."""

PERSONAL_TEXT: Final = "Reported by Alice Example <alice.example@example.invalid>"
SECRET_VALUE: Final = "api_token=Example-Secret-Token-0123456789"
FAILURE_TEXT: Final = f"{PERSONAL_TEXT}; {SECRET_VALUE}"
"""Exception or feed text that must appear in no log field."""

FAILED_EVENT_KEYS: Final = frozenset(
    {"event", "log_level", "cve_id", "fetcher_name", "cause"}
)
INVALID_ID_EVENT_KEYS: Final = FAILED_EVENT_KEYS - {"cve_id"}
SKIPPED_EVENT_KEYS: Final = frozenset(
    {"event", "log_level", "cve_id", "fetcher_name", "reason"}
)
RECEIVED_EVENT_KEYS: Final = frozenset(
    {"event", "log_level", "fetcher_name", "count", "entries"}
)
ABSENT: Final = object()
"""Marks a member removed from an entry or the catalog."""


class Counters(NamedTuple):
    succeeded: int
    created: int
    updated: int
    failed: int


def counters(fetcher: SyncCisaKev) -> Counters:
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
        assert "\x00" not in rendered, entry


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


def _skipped(cve_id: str) -> dict[str, Any]:
    return {
        "event": CVE_FETCH_CANDIDATE_SKIPPED_EVENT,
        "log_level": "warning",
        "cve_id": cve_id,
        "fetcher_name": NAME,
        "reason": "invalid_cwe",
    }


def _entry(cve_id: Any, **members: Any) -> dict[str, Any]:
    """A live-shaped entry; `ABSENT` removes a member."""
    entry = entry_for("CVE-2099-0000")
    members = {"cveID": cve_id, **members}
    for key, value in members.items():
        if value is ABSENT:
            del entry[key]
        else:
            entry[key] = value
    return entry


def _kev_cwes(*cwe_ids: str) -> list[tuple[str, str]]:
    return sorted((cwe_id, KEV_CWE_SOURCE) for cwe_id in cwe_ids)


def _kev_reference(cve: CVE) -> tuple[str, str, str, str, None]:
    """The exact source reference row (url, title, type, source,
    description)."""
    return (reference_url(cve.cve_id), "CISA KEV", "advisory", NAME, None)


# ---------------------------------------------------------------------------
# Harness
# ---------------------------------------------------------------------------


@dataclass
class Publications:
    """Substitute for `task_publication.publish_task`."""

    calls: list[dict[str, Any]] = field(default_factory=list)

    async def __call__(self, task_name: str, **options: Any) -> None:
        self.calls.append({"task_name": task_name, **options})

    def published(self, task_name: str) -> list[Any]:
        return [call for call in self.calls if call["task_name"] == task_name]


class State(NamedTuple):
    """The persisted KEV-relevant state of one CVE, row identities and
    timestamps included, for no-write and idempotency proofs."""

    kev: tuple[Any, ...] | None
    cwes: list[tuple[Any, ...]]
    sources: list[tuple[str, str]]
    tickets: list[uuid.UUID]
    references: list[tuple[Any, ...]]
    events: list[EventRow]
    priority_auto: str | None


@dataclass
class Env:
    world: IngestionWorld
    factory: async_sessionmaker[AsyncSession]
    server: KevServer
    published: Publications
    status_opened: list[int] = field(default_factory=lambda: [0])
    isolated: list[tuple[str, CVESourceFetchStatus]] = field(default_factory=list)
    run_names: list[str] = field(default_factory=list)

    async def cve(self) -> CVE:
        """A committed published CVE with an `Analysis` Ticket, no KEV, CWE,
        SSVC, or EPSS evidence, NULL severity, and NULL `priority_auto`."""
        cve = await self.world.cve_in()
        await self.world.ticket(cve_id=cve.id)
        return cve

    async def orphan(self) -> CVE:
        """A committed CVE that no Ticket references."""
        return await self.world.cve_in()

    def unknown_id(self) -> str:
        """A canonical CVE-ID absent from the database (deleted at teardown
        should the code under test create it)."""
        return self.world.new_cve_id()

    def serve(self, *entries: Any) -> None:
        self.server.catalog = catalog_of(*entries)

    def fetcher(self) -> SyncCisaKev:
        instance = SyncCisaKev()
        instance._http_client = self.server.client()
        return instance

    async def batch(self) -> Batch:
        fetcher = self.fetcher()
        fetcher.config = FetcherRunConfig(
            hard_time_limit_seconds=3600, request_delay=0, custom_settings={}
        )
        fetcher._periodic_context = True
        return Batch(self, fetcher, await self.world.open_session())

    async def kev(self, cve: CVE) -> tuple[date, str | None] | None:
        async with self.factory() as session:
            row = (
                await session.execute(
                    select(CVEKEVEntry.date_added, CVEKEVEntry.reference_url).where(
                        CVEKEVEntry.cve_id == cve.id
                    )
                )
            ).one_or_none()
        return None if row is None else (row[0], row[1])

    async def cwes(self, cve: CVE) -> list[tuple[str, str]]:
        async with self.factory() as session:
            rows = await session.execute(
                select(CVECWE.cwe_id, CVECWE.source).where(CVECWE.cve_id == cve.id)
            )
        return sorted((cwe_id, source) for cwe_id, source in rows)

    async def sources(self, cve: CVE) -> list[tuple[str, str]]:
        async with self.factory() as session:
            rows = await session.execute(
                select(CVESource.source, CVESource.status).where(
                    CVESource.cve_id == cve.id
                )
            )
        return sorted((source, value) for source, value in rows)

    async def tickets(self, cve: CVE) -> list[uuid.UUID]:
        async with self.factory() as session:
            rows = await session.scalars(
                select(Ticket.id).where(Ticket.cve_id == cve.id)
            )
        return list(rows.all())

    async def references(self, cve: CVE) -> list[tuple[Any, ...]]:
        async with self.factory() as session:
            rows = await session.execute(
                select(
                    TicketReference.url,
                    TicketReference.title,
                    TicketReference.type,
                    TicketReference.source,
                    TicketReference.description,
                )
                .join(Ticket, TicketReference.ticket_id == Ticket.id)
                .where(Ticket.cve_id == cve.id)
                .order_by(TicketReference.url)
            )
        return [tuple(row) for row in rows]

    async def priority_auto(self, cve: CVE) -> str | None:
        async with self.factory() as session:
            value: str | None = await session.scalar(
                select(Ticket.priority_auto).where(Ticket.cve_id == cve.id)
            )
        return value

    async def events(self, cve: CVE) -> list[EventRow]:
        [ticket_id] = await self.tickets(cve)
        async with self.factory() as session:
            return await ticket_events_by_id(session, ticket_id)

    async def state(self, cve: CVE) -> State:
        async with self.factory() as session:
            kev = (
                await session.execute(
                    select(
                        CVEKEVEntry.id,
                        CVEKEVEntry.date_added,
                        CVEKEVEntry.reference_url,
                        CVEKEVEntry.updated_at,
                    ).where(CVEKEVEntry.cve_id == cve.id)
                )
            ).one_or_none()
            cwes = await session.execute(
                select(
                    CVECWE.id, CVECWE.cwe_id, CVECWE.source, CVECWE.updated_at
                ).where(CVECWE.cve_id == cve.id)
            )
            references = await session.execute(
                select(
                    TicketReference.id,
                    TicketReference.url,
                    TicketReference.title,
                    TicketReference.type,
                    TicketReference.source,
                    TicketReference.updated_at,
                )
                .join(Ticket, TicketReference.ticket_id == Ticket.id)
                .where(Ticket.cve_id == cve.id)
            )
            kev_row = None if kev is None else tuple(kev)
            cwe_rows = sorted(tuple(row) for row in cwes)
            reference_rows = sorted(tuple(row) for row in references)
        tickets = await self.tickets(cve)
        return State(
            kev=kev_row,
            cwes=cwe_rows,
            sources=await self.sources(cve),
            tickets=tickets,
            references=reference_rows,
            events=await self.events(cve) if tickets else [],
            priority_auto=await self.priority_auto(cve),
        )

    async def assert_untouched(self, cve: CVE) -> None:
        """No KEV, CWE, source-status, reference, priority, or audit write."""
        assert await self.kev(cve) is None
        assert await self.cwes(cve) == []
        assert await self.sources(cve) == []
        assert await self.references(cve) == []
        assert await self.priority_auto(cve) is None
        assert await self.events(cve) == []

    async def assert_no_isolated_status(self, *cves: CVE) -> None:
        """The documented deviation: no `_isolated_status_commit()`, no
        independent status session, and no `failure`/`missing` row."""
        assert self.isolated == []
        assert self.status_opened == [0]
        for cve in cves:
            assert all(
                value == CVESourceFetchStatus.SUCCESS
                for _, value in await self.sources(cve)
            )

    async def seed_mitre(self, cve: CVE, *, reference_title: str | None = None) -> None:
        """The MITRE CISA-ADP writer's rows for `cve`: the identical KEV
        entry, an `adp:CISA-ADP` CWE, and a `sync_mitre_cves` reference for
        the KEV URL with NULL type (and the given title)."""
        session = self.world.session
        result = await cve_service.upsert_cve(
            session,
            cve.cve_id,
            CVESourceType.MITRE,
            CVEIngestPayload(
                kev_data=KEVEntry(
                    date_added=DATE_ADDED, reference_url=reference_url(cve.cve_id)
                ),
                cwe_classifications=[
                    CWEEntry(cwe_id="CWE-79", source=MITRE_CWE_SOURCE)
                ],
            ),
        )
        await reference_service.upsert_references(
            session,
            result.ticket.id,
            cve.cve_id,
            MITRE_NAME,
            reference_service.AutomaticReferenceInput(
                url=reference_url(cve.cve_id), title=reference_title
            ),
            (),
        )
        await session.commit()

    async def run_row(self) -> tuple[SyncCisaKev, uuid.UUID]:
        """A committed `running` FetcherRun under a test-only configuration
        name, as the atomic acquisition leaves it before `run()`."""
        name = f"test_kev_run_{uuid.uuid4().hex[:12]}"
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

    async def run(self) -> FetcherRun:
        """One complete `run()`; returns the finalized FetcherRun."""
        fetcher, run_id = await self.run_row()
        await fetcher.run(run_id=run_id, config=_RUN_CONFIG)
        return await self.run_outcome(run_id)

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
        server=KevServer(catalog_of()),
        published=Publications(),
    )

    def status_sessions() -> AsyncSession:
        created.status_opened[0] += 1
        return real_session_factory()

    real_isolated = SyncCisaKev._isolated_status_commit

    async def isolated(
        self: SyncCisaKev, cve_id: str, status: CVESourceFetchStatus
    ) -> None:
        created.isolated.append((cve_id, status))
        await real_isolated(self, cve_id, status)

    monkeypatch.setattr(
        base_cve_fetcher_module, "async_session_factory", status_sessions
    )
    monkeypatch.setattr(
        base_fetcher_module, "async_session_factory", real_session_factory
    )
    monkeypatch.setattr(task_publication, "publish_task", created.published)
    monkeypatch.setattr(SyncCisaKev, "_isolated_status_commit", isolated)
    try:
        yield created
    finally:
        await created.cleanup()


@dataclass
class Batch:
    """`execute()` invocations on a reusable session with real commits,
    under the automatic periodic context that `run()` establishes."""

    env: Env
    fetcher: SyncCisaKev
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
    return await env.batch()


@dataclass
class Trace:
    """Per-entry observation of one `execute()`: the catalog index being
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
    real_process = batch.fetcher._process_entry
    real_ingest = batch.fetcher._ingest
    real_rollback = batch.session.rollback
    position = [0]

    async def process_entry(session: AsyncSession, entry: object) -> None:
        trace.current[0] = position[0]
        position[0] += 1
        await real_process(session, entry)

    async def ingest(
        session: AsyncSession, cve_id: str, entry: dict[str, object]
    ) -> CVEFetchResult:
        trace.ingested.append(trace.current[0])
        return await real_ingest(session, cve_id, entry)

    async def rollback() -> None:
        trace.rollbacks.append(trace.current[0])
        await real_rollback()

    monkeypatch.setattr(batch.fetcher, "_process_entry", process_entry)
    monkeypatch.setattr(batch.fetcher, "_ingest", ingest)
    monkeypatch.setattr(batch.session, "rollback", rollback)
    return trace


def _fail_upsert_for(
    monkeypatch: pytest.MonkeyPatch, cve_ids: set[str], error: BaseException
) -> None:
    """Make `upsert_cve()` raise `error` for `cve_ids` after it has written
    that CVE's KEV, CWE, Ticket priority, and success status."""
    real = cve_service.upsert_cve

    async def upsert_cve(
        session: AsyncSession, cve_id: str, source: Any, payload: Any
    ) -> Any:
        result = await real(session, cve_id, source, payload)
        if cve_id in cve_ids:
            raise error
        return result

    monkeypatch.setattr(cve_service, "upsert_cve", upsert_cve)


def _fail_references_for(
    monkeypatch: pytest.MonkeyPatch, cve_ids: set[str], error: BaseException
) -> None:
    """Make `upsert_references()` raise `error` for `cve_ids` after it has
    written the source reference in the same transaction."""
    real = reference_service.upsert_references

    async def upsert_references(
        session: AsyncSession, ticket_id: Any, cve_id: str, *args: Any
    ) -> None:
        await real(session, ticket_id, cve_id, *args)
        if cve_id in cve_ids:
            raise error

    monkeypatch.setattr(reference_service, "upsert_references", upsert_references)


def _spy_upsert(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, Any, Any]]:
    calls: list[tuple[str, Any, Any]] = []
    real = cve_service.upsert_cve

    async def upsert_cve(
        session: AsyncSession, cve_id: str, source: Any, payload: Any
    ) -> Any:
        calls.append((cve_id, source, payload))
        return await real(session, cve_id, source, payload)

    monkeypatch.setattr(cve_service, "upsert_cve", upsert_cve)
    return calls


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


# ---------------------------------------------------------------------------
# Download and fatal feed errors
# ---------------------------------------------------------------------------

_FATAL_CASES: Final[
    list[tuple[Responder | None, Any, str, type[BaseException] | None]]
] = [
    (
        raising(httpx.ConnectError("[Errno 111] Connection refused")),
        None,
        "Failed to connect to CISA KEV feed",
        httpx.ConnectError,
    ),
    (
        raising(httpx.ConnectError("[Errno -2] Name or service not known")),
        None,
        "Failed to connect to CISA KEV feed",
        httpx.ConnectError,
    ),
    (
        raising(httpx.ConnectTimeout("timed out")),
        None,
        "Failed to connect to CISA KEV feed",
        httpx.ConnectTimeout,
    ),
    (
        raising(httpx.ReadTimeout("timed out")),
        None,
        "Failed to connect to CISA KEV feed",
        httpx.ReadTimeout,
    ),
    (
        raising(httpx.RemoteProtocolError("peer closed connection")),
        None,
        "Failed to connect to CISA KEV feed",
        httpx.RemoteProtocolError,
    ),
    (
        status(301, location="https://www.cisa.gov/elsewhere.json"),
        None,
        "CISA KEV feed returned HTTP 301",
        httpx.HTTPStatusError,
    ),
    (
        status(302, location=KEV_URL),
        None,
        "CISA KEV feed returned HTTP 302",
        httpx.HTTPStatusError,
    ),
    (
        status(404, FAILURE_TEXT.encode()),
        None,
        "CISA KEV feed returned HTTP 404",
        httpx.HTTPStatusError,
    ),
    (status(403), None, "CISA KEV feed returned HTTP 403", httpx.HTTPStatusError),
    (
        status(503, FAILURE_TEXT.encode()),
        None,
        "CISA KEV feed returned HTTP 503",
        httpx.HTTPStatusError,
    ),
    (status(500), None, "CISA KEV feed returned HTTP 500", httpx.HTTPStatusError),
    (status(204), None, "CISA KEV feed returned HTTP 204", None),
    (status(206, b"{}"), None, "CISA KEV feed returned HTTP 206", None),
    (
        raw_body(b"{"),
        None,
        "CISA KEV feed returned unparseable response",
        json.JSONDecodeError,
    ),
    (
        raw_body(f"<html>{FAILURE_TEXT}</html>".encode()),
        None,
        "CISA KEV feed returned unparseable response",
        json.JSONDecodeError,
    ),
    (
        raw_body(b'{"vulnerabilities": [], "title": "\xff\xfe"}'),
        None,
        "CISA KEV feed returned unparseable response",
        UnicodeDecodeError,
    ),
    (
        raw_body(b""),
        None,
        "CISA KEV feed returned unparseable response",
        json.JSONDecodeError,
    ),
    (None, [], "CISA KEV feed has unexpected structure", KevCatalogStructureError),
    (
        None,
        [{"cveID": "CVE-2099-0001"}],
        "CISA KEV feed has unexpected structure",
        KevCatalogStructureError,
    ),
    (
        None,
        FAILURE_TEXT,
        "CISA KEV feed has unexpected structure",
        KevCatalogStructureError,
    ),
    (None, 1734, "CISA KEV feed has unexpected structure", KevCatalogStructureError),
    (
        raw_body(b"null"),
        None,
        "CISA KEV feed has unexpected structure",
        KevCatalogStructureError,
    ),
    (
        None,
        {"count": 0},
        "CISA KEV feed has unexpected structure",
        KevCatalogStructureError,
    ),
    (
        None,
        {"vulnerabilities": None},
        "CISA KEV feed has unexpected structure",
        KevCatalogStructureError,
    ),
    (
        None,
        {"vulnerabilities": {}},
        "CISA KEV feed has unexpected structure",
        KevCatalogStructureError,
    ),
    (
        None,
        {"vulnerabilities": "[]"},
        "CISA KEV feed has unexpected structure",
        KevCatalogStructureError,
    ),
]
_FATAL_IDS: Final = [
    "connection_refused",
    "dns_failure",
    "connect_timeout",
    "read_timeout",
    "protocol_error",
    "http_301",
    "http_302_to_itself",
    "http_404",
    "http_403",
    "http_503",
    "http_500",
    "http_204",
    "http_206",
    "truncated_json",
    "html",
    "non_utf8",
    "empty_body",
    "root_empty_list",
    "root_list",
    "root_string",
    "root_number",
    "root_null",
    "missing_vulnerabilities",
    "null_vulnerabilities",
    "object_vulnerabilities",
    "string_vulnerabilities",
]


def _serve_fatal(env: Env, responder: Responder | None, document: Any) -> None:
    if responder is not None:
        env.server.response = responder
    else:
        env.server.catalog = document


@pytest.mark.integration
class TestFatalFeedErrors:
    @pytest.mark.parametrize(
        ("responder", "document", "message", "cause"), _FATAL_CASES, ids=_FATAL_IDS
    )
    async def test_execute_raises_the_sanitized_chained_error_before_any_entry(
        self,
        responder: Responder | None,
        document: Any,
        message: str,
        cause: type[BaseException] | None,
        env: Env,
        batch: Batch,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        _serve_fatal(env, responder, document)
        trace = _trace(monkeypatch, batch)
        upserts = _spy_upsert(monkeypatch)

        with (
            capture_logs() as logs,
            trace.recording(batch),
            pytest.raises(FetcherError) as raised,
        ):
            await batch.execute()

        assert str(raised.value) == message
        if cause is None:
            assert raised.value.__cause__ is None
        else:
            assert isinstance(raised.value.__cause__, cause)
        assert FAILURE_TEXT not in str(raised.value)
        # Exactly one GET of the documented URL; a redirect is not followed.
        assert [(r.method, str(r.url)) for r in env.server.requests] == [
            ("GET", CISA_KEV_URL)
        ]
        # No entry is processed and no database work happens.
        assert trace.current == [-1]
        assert trace.statements == []
        assert upserts == []
        assert counters(batch.fetcher) == Counters(0, 0, 0, 0)
        assert logs == []

    @pytest.mark.parametrize(
        ("responder", "document", "message", "cause"), _FATAL_CASES, ids=_FATAL_IDS
    )
    async def test_run_is_a_failure_with_the_exact_message_and_detail(
        self,
        responder: Responder | None,
        document: Any,
        message: str,
        cause: type[BaseException] | None,
        env: Env,
    ) -> None:
        cve = await env.cve()
        _serve_fatal(env, responder, document)
        fetcher, run_id = await env.run_row()

        with pytest.raises(FetcherError):
            await fetcher.run(run_id=run_id, config=_RUN_CONFIG)

        run = await env.run_outcome(run_id)
        assert _outcome(run) == ("failure", 0, 0, 0, 0)
        assert run.error_message == message
        if cause is None:
            assert run.error_detail is None
        else:
            assert run.error_detail is not None
        assert run.cursor is None
        assert len(env.server.requests) == 1
        await env.assert_untouched(cve)
        await env.assert_no_isolated_status(cve)

    def test_production_url_is_the_documented_source(self) -> None:
        assert CISA_KEV_URL == (
            "https://www.cisa.gov/sites/default/files/feeds/"
            "known_exploited_vulnerabilities.json"
        )


# ---------------------------------------------------------------------------
# Per-entry success
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestEntrySuccess:
    async def test_existing_cve_gains_kev_cwes_reference_and_p1(
        self, env: Env, batch: Batch, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cve = await env.cve()
        env.serve(
            _entry(
                cve.cve_id,
                dateAdded="2026-09-08",
                cwes=["CWE-59", "CWE-284", "CWE-59"],
            )
        )
        upserts = _spy_upsert(monkeypatch)

        with capture_logs() as logs:
            await batch.execute()

        assert await env.kev(cve) == (date(2026, 9, 8), reference_url(cve.cve_id))
        assert await env.cwes(cve) == _kev_cwes("CWE-59", "CWE-284")
        # The source reference only: the feed supplies no upstream reference.
        assert await env.references(cve) == [_kev_reference(cve)]
        assert await env.sources(cve) == [("kev", CVESourceFetchStatus.SUCCESS)]
        # KEV presence is the highest exploitation level (Decision Table).
        assert await env.priority_auto(cve) == "P1"
        assert await env.events(cve) == [
            EventRow("priority_changed", None, None, "P1", None, None)
        ]
        # One `updated` although both KEV and CWE changed.
        assert counters(batch.fetcher) == Counters(1, 0, 1, 0)
        [(cve_id, source, payload)] = upserts
        assert (cve_id, source) == (cve.cve_id, CVESourceType.KEV)
        assert payload == CVEIngestPayload(
            kev_data=KEVEntry(
                date_added=date(2026, 9, 8), reference_url=reference_url(cve.cve_id)
            ),
            cwe_classifications=[
                CWEEntry(cwe_id="CWE-59", source=KEV_CWE_SOURCE),
                CWEEntry(cwe_id="CWE-284", source=KEV_CWE_SOURCE),
            ],
        )
        assert payload.model_fields_set == {"kev_data", "cwe_classifications"}
        assert env.published.published(RESOLVE) == []
        await env.assert_no_isolated_status(cve)
        assert logs == [
            {
                "event": CISA_KEV_CATALOG_RECEIVED_EVENT,
                "log_level": "info",
                "fetcher_name": NAME,
                "count": 1,
                "entries": 1,
            }
        ]

    async def test_every_fixture_entry_is_ingested_under_a_test_cve(
        self, env: Env, batch: Batch
    ) -> None:
        # The live fixture entries, each rebound to a fictional CVE-ID.
        cves = [await env.cve() for _ in FIXTURE_CVE_IDS]
        catalog = load_catalog()
        originals = list(catalog["vulnerabilities"])
        for entry, cve in zip(catalog["vulnerabilities"], cves, strict=True):
            entry["cveID"] = cve.cve_id
        env.server.catalog = catalog

        await batch.execute()

        for original, cve in zip(originals, cves, strict=True):
            assert await env.kev(cve) == (
                date.fromisoformat(original["dateAdded"]),
                reference_url(cve.cve_id),
            )
            assert await env.cwes(cve) == _kev_cwes(*original["cwes"])
            assert await env.references(cve) == [_kev_reference(cve)]
        assert counters(batch.fetcher) == Counters(5, 0, 5, 0)

    @pytest.mark.parametrize(
        "cwes", [ABSENT, None, []], ids=["absent", "null", "empty"]
    )
    async def test_missing_null_or_empty_cwes_retain_prior_rows(
        self, cwes: Any, env: Env
    ) -> None:
        cve = await env.cve()
        env.serve(_entry(cve.cve_id, cwes=["CWE-79"]))
        await (await env.batch()).execute()
        before = await env.state(cve)
        env.serve(_entry(cve.cve_id, cwes=cwes))
        second = await env.batch()

        await second.execute()

        assert await env.cwes(cve) == _kev_cwes("CWE-79")
        assert await env.state(cve) == before
        assert counters(second.fetcher) == Counters(1, 0, 0, 0)

    async def test_new_cwe_with_equal_kev_is_one_update(self, env: Env) -> None:
        cve = await env.cve()
        env.serve(_entry(cve.cve_id, cwes=["CWE-79"]))
        await (await env.batch()).execute()
        env.serve(_entry(cve.cve_id, cwes=["CWE-79", "CWE-352"]))
        second = await env.batch()

        await second.execute()

        assert await env.cwes(cve) == _kev_cwes("CWE-79", "CWE-352")
        assert counters(second.fetcher) == Counters(1, 0, 1, 0)

    async def test_changed_date_added_updates_the_kev_entry(self, env: Env) -> None:
        cve = await env.cve()
        env.serve(_entry(cve.cve_id, dateAdded="2026-09-01"))
        await (await env.batch()).execute()
        env.serve(_entry(cve.cve_id, dateAdded="2026-09-02"))
        second = await env.batch()

        await second.execute()

        assert await env.kev(cve) == (date(2026, 9, 2), reference_url(cve.cve_id))
        assert counters(second.fetcher) == Counters(1, 0, 1, 0)

    async def test_equal_reprocessing_is_unchanged_without_writes(
        self, env: Env
    ) -> None:
        cve = await env.cve()
        env.serve(_entry(cve.cve_id, cwes=["CWE-79", "CWE-352"]))
        await (await env.batch()).execute()
        before = await env.state(cve)
        second = await env.batch()

        with capture_logs() as logs:
            await second.execute()

        assert counters(second.fetcher) == Counters(1, 0, 0, 0)
        # No row, event, reference, or priority change; only the
        # vestigial source status is refreshed.
        assert await env.state(cve) == before
        assert _events(logs, CVE_FETCH_ITEM_FAILED_EVENT) == []
        assert env.published.published(RESOLVE) == []

    async def test_newly_created_reference_alone_is_unchanged(self, env: Env) -> None:
        cve = await env.cve()
        env.serve(_entry(cve.cve_id))
        await (await env.batch()).execute()
        async with env.factory() as session:
            await session.execute(
                delete(TicketReference).where(
                    TicketReference.url == reference_url(cve.cve_id)
                )
            )
            await session.commit()
        assert await env.references(cve) == []
        second = await env.batch()

        await second.execute()

        assert await env.references(cve) == [_kev_reference(cve)]
        # A reference-only change stays outside `UpsertResult.action`.
        assert counters(second.fetcher) == Counters(1, 0, 0, 0)

    async def test_unknown_cve_is_skipped_silently(
        self, env: Env, batch: Batch, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        unknown = env.unknown_id()
        known = await env.cve()
        env.serve(_entry(unknown), _entry(known.cve_id))
        trace = _trace(monkeypatch, batch)
        upserts = _spy_upsert(monkeypatch)

        with capture_logs() as logs, trace.recording(batch):
            await batch.execute()

        # The lookup read is ended; nothing else happens for the entry.
        assert trace.rollbacks == [0]
        assert trace.ingested == [1]
        assert len(trace.statements_of(0)) == 1
        assert trace.statements_of(0)[0].lstrip().startswith("SELECT cve.id")
        assert [cve_id for cve_id, _, _ in upserts] == [known.cve_id]
        assert [entry["event"] for entry in logs] == [CISA_KEV_CATALOG_RECEIVED_EVENT]
        # The known entry is the only selected unit.
        assert counters(batch.fetcher) == Counters(1, 0, 1, 0)
        async with env.factory() as session:
            assert (
                await session.scalar(select(CVE.id).where(CVE.cve_id == unknown))
                is None
            )
            assert (
                await session.scalar(
                    select(Ticket.id)
                    .join(CVE, Ticket.cve_id == CVE.id)
                    .where(CVE.cve_id == unknown)
                )
                is None
            )

    async def test_orphan_cve_gets_its_ticket_through_upsert_cve(
        self, env: Env, batch: Batch
    ) -> None:
        orphan = await env.orphan()
        env.serve(_entry(orphan.cve_id, cwes=["CWE-79"]))

        await batch.execute()

        [ticket_id] = await env.tickets(orphan)
        assert await env.events(orphan) == [
            EventRow("ticket_created", None, None, None, INGESTION_COMMENT, None),
            EventRow("cve_associated", None, None, orphan.cve_id, None, None),
            EventRow("priority_changed", None, None, "P1", None, None),
        ]
        async with env.factory() as session:
            ticket = await session.get(Ticket, ticket_id)
        assert ticket is not None
        assert ticket.priority_auto == "P1"
        assert ticket.status == "New"
        assert await env.kev(orphan) == (DATE_ADDED, reference_url(orphan.cve_id))
        assert await env.cwes(orphan) == _kev_cwes("CWE-79")
        assert await env.references(orphan) == [_kev_reference(orphan)]
        # The CVE existed: enrichment is `updated`, never `created`.
        assert counters(batch.fetcher) == Counters(1, 0, 1, 0)
        assert env.published.published(RESOLVE) == []
        await env.assert_no_isolated_status(orphan)


# ---------------------------------------------------------------------------
# Isolated per-entry errors
# ---------------------------------------------------------------------------

_INVALID_ENTRIES: Final[list[Any]] = [
    "CVE-2099-0001",
    48001,
    None,
    [],
    ["CVE-2099-0001"],
    _entry(ABSENT),
    _entry(None),
    _entry(20990001),
    _entry(["CVE-2099-0001"]),
    _entry(""),
    _entry("cve-2099-0001"),
    _entry("CVE-2099-1"),
    _entry("CVE-99-0001"),
    _entry(" CVE-2099-0001"),
    _entry("CVE-2099-0001\n"),
    _entry("CVE-2099-" + "1" * 12),
    _entry(f"CVE-2099-0001 {FAILURE_TEXT}"),
    _entry("CVE-2099-0001\x00"),
]
_INVALID_IDS: Final = [
    "string_entry",
    "number_entry",
    "null_entry",
    "empty_list_entry",
    "list_entry",
    "missing",
    "null",
    "number",
    "list",
    "empty",
    "lowercase",
    "short_sequence",
    "short_year",
    "leading_space",
    "trailing_newline",
    "over_long",
    "free_text",
    "nul",
]


@pytest.mark.integration
class TestInvalidCveId:
    @pytest.mark.parametrize("entry", _INVALID_ENTRIES, ids=_INVALID_IDS)
    async def test_is_one_failed_unit_without_database_work(
        self, entry: Any, env: Env, batch: Batch, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        later = await env.cve()
        env.serve(entry, _entry(later.cve_id))
        trace = _trace(monkeypatch, batch)

        with capture_logs() as logs, trace.recording(batch):
            await batch.execute()

        # No statement, no rollback, and no ingestion for the invalid entry.
        assert trace.statements_of(0) == []
        assert trace.rollbacks == []
        assert trace.ingested == [1]
        [failed] = _events(logs, CVE_FETCH_ITEM_FAILED_EVENT)
        assert failed == _failed(None, "InvalidCveIdError")
        assert set(failed) == INVALID_ID_EVENT_KEYS
        _assert_private(logs)
        # The later entry is still processed.
        assert await env.kev(later) == (DATE_ADDED, reference_url(later.cve_id))
        assert counters(batch.fetcher) == Counters(1, 0, 1, 1)
        await env.assert_no_isolated_status(later)


@pytest.mark.integration
class TestLookupError:
    @pytest.mark.parametrize("kind", ["database", "operational"])
    async def test_rolls_back_and_is_one_failed_unit(
        self, kind: str, env: Env, batch: Batch, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        failing = await env.cve()
        later = await env.cve()
        env.serve(_entry(failing.cve_id), _entry(later.cve_id))
        trace = _trace(monkeypatch, batch)
        real_lookup = batch.fetcher._cve_exists
        causes: list[str] = []

        async def cve_exists(session: AsyncSession, cve_id: str) -> bool:
            if cve_id == failing.cve_id:
                try:
                    if kind == "database":
                        # A real error that aborts the transaction: the
                        # later entry succeeds only after the rollback.
                        await session.execute(text("SELECT 1 / 0"))
                    raise OperationalError("SELECT cve.id", {}, Exception(FAILURE_TEXT))
                except Exception as exc:
                    causes.append(type(exc).__name__)
                    raise
            return await real_lookup(session, cve_id)

        monkeypatch.setattr(batch.fetcher, "_cve_exists", cve_exists)

        with capture_logs() as logs:
            await batch.execute()

        assert trace.rollbacks == [0]
        assert trace.ingested == [1]
        [failed] = _events(logs, CVE_FETCH_ITEM_FAILED_EVENT)
        assert failed == _failed(failing.cve_id, causes[0])
        assert set(failed) == FAILED_EVENT_KEYS
        _assert_private(logs)
        await env.assert_untouched(failing)
        assert await env.kev(later) == (DATE_ADDED, reference_url(later.cve_id))
        assert counters(batch.fetcher) == Counters(1, 0, 1, 1)
        await env.assert_no_isolated_status(failing, later)


async def _assert_rolled_back_unit(
    env: Env,
    batch: Batch,
    trace: Trace,
    logs: Sequence[Mapping[str, Any]],
    failing: CVE,
    later: CVE,
    cause: str,
) -> None:
    """One rolled-back failed unit at index 0 followed by a committed one."""
    assert trace.rollbacks == [0]
    assert trace.ingested == [0, 1]
    [failed] = _events(logs, CVE_FETCH_ITEM_FAILED_EVENT)
    assert failed == _failed(failing.cve_id, cause)
    assert set(failed) == FAILED_EVENT_KEYS
    _assert_private(logs)
    await env.assert_untouched(failing)
    assert await env.kev(later) == (DATE_ADDED, reference_url(later.cve_id))
    assert await env.references(later) == [_kev_reference(later)]
    assert counters(batch.fetcher) == Counters(1, 0, 1, 1)
    await env.assert_no_isolated_status(failing, later)


@pytest.mark.integration
class TestEntryFailure:
    @pytest.mark.parametrize(
        "date_added",
        [
            ABSENT,
            None,
            20261001,
            "2026-1-01",
            "2026-02-30",
            "2026-10-01T00:00:00",
            " 2026-10-01",
            "2026-10-01\n",
            FAILURE_TEXT,
            "2026-10-01\x00",
        ],
        ids=[
            "missing",
            "null",
            "number",
            "one_digit_month",
            "february_30",
            "datetime",
            "leading_space",
            "trailing_newline",
            "free_text",
            "nul",
        ],
    )
    async def test_invalid_date_added_rolls_back(
        self,
        date_added: Any,
        env: Env,
        batch: Batch,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        failing = await env.cve()
        later = await env.cve()
        env.serve(
            _entry(failing.cve_id, dateAdded=date_added, cwes=["CWE-79", "cwe-1"]),
            _entry(later.cve_id),
        )
        trace = _trace(monkeypatch, batch)
        upserts = _spy_upsert(monkeypatch)

        with capture_logs() as logs:
            await batch.execute()

        await _assert_rolled_back_unit(
            env, batch, trace, logs, failing, later, "InvalidDateAddedError"
        )
        assert [cve_id for cve_id, _, _ in upserts] == [later.cve_id]
        # The entry fails before its CWE items are examined.
        assert _events(logs, CVE_FETCH_CANDIDATE_SKIPPED_EVENT) == []

    @pytest.mark.parametrize(
        "cwes",
        ["CWE-79", {"cweID": "CWE-79"}, 79, True, FAILURE_TEXT],
        ids=["string", "object", "number", "bool", "free_text"],
    )
    async def test_non_list_cwes_rolls_back_and_keeps_prior_rows(
        self, cwes: Any, env: Env, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        failing = await env.cve()
        later = await env.cve()
        env.serve(_entry(failing.cve_id, cwes=["CWE-352"]))
        await (await env.batch()).execute()
        before = await env.state(failing)
        env.serve(_entry(failing.cve_id, cwes=cwes), _entry(later.cve_id))
        second = await env.batch()
        trace = _trace(monkeypatch, second)

        with capture_logs() as logs:
            await second.execute()

        assert trace.rollbacks == [0]
        assert _events(logs, CVE_FETCH_ITEM_FAILED_EVENT) == [
            _failed(failing.cve_id, "InvalidCwesError")
        ]
        _assert_private(logs)
        # The previous state, including the source status, is preserved.
        assert await env.state(failing) == before
        assert await env.kev(later) == (DATE_ADDED, reference_url(later.cve_id))
        assert counters(second.fetcher) == Counters(1, 0, 1, 1)
        await env.assert_no_isolated_status(failing, later)

    async def test_upsert_cve_failure_rolls_back_its_writes(
        self, env: Env, batch: Batch, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        failing = await env.cve()
        later = await env.cve()
        env.serve(_entry(failing.cve_id), _entry(later.cve_id))
        trace = _trace(monkeypatch, batch)
        _fail_upsert_for(monkeypatch, {failing.cve_id}, RuntimeError(FAILURE_TEXT))

        with capture_logs() as logs:
            await batch.execute()

        # upsert_cve() wrote KEV, CWE, priority, its event, and the success
        # status; the rollback discarded all of them.
        await _assert_rolled_back_unit(
            env, batch, trace, logs, failing, later, "RuntimeError"
        )

    async def test_record_source_status_failure_rolls_back_the_entry(
        self, env: Env, batch: Batch, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        failing = await env.cve()
        later = await env.cve()
        env.serve(_entry(failing.cve_id), _entry(later.cve_id))
        trace = _trace(monkeypatch, batch)
        real_record = cve_service.record_source_status
        recorded: list[Any] = []

        async def record_source_status(
            session: AsyncSession, cve_uuid: uuid.UUID, source: Any, value: Any
        ) -> None:
            recorded.append((cve_uuid, source, value))
            if cve_uuid == failing.id:
                raise OperationalError(
                    "INSERT INTO cve_source", {}, Exception(FAILURE_TEXT)
                )
            await real_record(session, cve_uuid, source, value)

        monkeypatch.setattr(cve_service, "record_source_status", record_source_status)

        with capture_logs() as logs:
            await batch.execute()

        assert recorded == [
            (failing.id, CVESourceType.KEV, CVESourceFetchStatus.SUCCESS),
            (later.id, CVESourceType.KEV, CVESourceFetchStatus.SUCCESS),
        ]
        await _assert_rolled_back_unit(
            env, batch, trace, logs, failing, later, "OperationalError"
        )

    async def test_own_flush_failure_is_an_isolated_failure(
        self, env: Env, batch: Batch, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        failing = await env.cve()
        later = await env.cve()
        env.serve(_entry(failing.cve_id), _entry(later.cve_id))
        trace = _trace(monkeypatch, batch)
        traced_ingest = batch.fetcher._ingest
        real_finalize = batch.fetcher.commit_and_dispatch
        real_flush = batch.session.flush
        inside_ingest = [False]
        own_flushes: list[int] = []
        finalized: list[int] = []

        async def ingest(
            session: AsyncSession, cve_id: str, entry: dict[str, object]
        ) -> CVEFetchResult:
            inside_ingest[0] = True
            try:
                return await traced_ingest(session, cve_id, entry)
            finally:
                inside_ingest[0] = False

        async def commit_and_dispatch(session: AsyncSession, result: Any) -> None:
            finalized.append(trace.current[0])
            await real_finalize(session, result)

        async def flush(*args: Any, **kwargs: Any) -> None:
            await real_flush(*args, **kwargs)
            # Only the fetcher's own per-entry flush of the first entry
            # fails; the delegates' flushes inside _ingest() succeed.
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
        await _assert_rolled_back_unit(
            env, batch, trace, logs, failing, later, "RuntimeError"
        )

    async def test_upsert_references_failure_rolls_back_cve_and_reference(
        self, env: Env, batch: Batch, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        failing = await env.cve()
        later = await env.cve()
        env.serve(_entry(failing.cve_id), _entry(later.cve_id))
        trace = _trace(monkeypatch, batch)
        _fail_references_for(
            monkeypatch,
            {failing.cve_id},
            OperationalError("INSERT", {}, Exception(FAILURE_TEXT)),
        )

        with capture_logs() as logs:
            await batch.execute()

        await _assert_rolled_back_unit(
            env, batch, trace, logs, failing, later, "OperationalError"
        )

    async def test_invalid_reference_candidate_is_skipped_and_the_entry_commits(
        self, env: Env, batch: Batch, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cve = await env.cve()
        env.serve(_entry(cve.cve_id))
        # A source URL with user information is an invalid candidate; the
        # KEV entry contract still accepts it.
        pattern = (
            "https://kev@www.cisa.gov/known-exploited-vulnerabilities-catalog"
            "?field_cve={cve_id}"
        )
        monkeypatch.setattr(batch.fetcher, "source_reference_url_pattern", pattern)

        with capture_logs() as logs:
            await batch.execute()

        assert await env.kev(cve) == (DATE_ADDED, pattern.format(cve_id=cve.cve_id))
        assert await env.references(cve) == []
        assert _events(logs, "automatic_reference_rejected") == [
            {
                "event": "automatic_reference_rejected",
                "log_level": "warning",
                "cve_id": cve.cve_id,
                "source": NAME,
                "reason": "userinfo_forbidden",
            }
        ]
        assert _events(logs, CVE_FETCH_ITEM_FAILED_EVENT) == []
        assert counters(batch.fetcher) == Counters(1, 0, 1, 0)
        await env.assert_no_isolated_status(cve)

    async def test_invalid_cwe_items_are_skipped_and_the_entry_commits(
        self, env: Env, batch: Batch
    ) -> None:
        cve = await env.cve()
        env.serve(
            _entry(
                cve.cve_id,
                cwes=[
                    "CWE-79",
                    "cwe-79",
                    79,
                    None,
                    "CWE-0",
                    "CWE-12345678901234567",
                    "NVD-CWE-Other",
                    FAILURE_TEXT,
                    "CWE-352",
                ],
            )
        )

        with capture_logs() as logs:
            await batch.execute()

        assert await env.cwes(cve) == _kev_cwes("CWE-79", "CWE-352")
        skipped = _events(logs, CVE_FETCH_CANDIDATE_SKIPPED_EVENT)
        assert skipped == [_skipped(cve.cve_id)] * 7
        assert all(set(entry) == SKIPPED_EVENT_KEYS for entry in skipped)
        assert _events(logs, CVE_FETCH_ITEM_FAILED_EVENT) == []
        _assert_private(logs)
        assert counters(batch.fetcher) == Counters(1, 0, 1, 0)

    async def test_every_isolated_failure_kind_writes_no_isolated_status(
        self, env: Env, batch: Batch, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        lookup, date_error, cwes_error, upsert, references, success = [
            await env.cve() for _ in range(6)
        ]
        env.serve(
            _entry("CVE-2099-1"),
            _entry(lookup.cve_id),
            _entry(date_error.cve_id, dateAdded="2026-02-30"),
            _entry(cwes_error.cve_id, cwes="CWE-79"),
            _entry(upsert.cve_id),
            _entry(references.cve_id),
            _entry(success.cve_id),
        )
        real_lookup = batch.fetcher._cve_exists

        async def cve_exists(session: AsyncSession, cve_id: str) -> bool:
            if cve_id == lookup.cve_id:
                raise OperationalError("SELECT", {}, Exception(FAILURE_TEXT))
            return await real_lookup(session, cve_id)

        monkeypatch.setattr(batch.fetcher, "_cve_exists", cve_exists)
        _fail_upsert_for(monkeypatch, {upsert.cve_id}, RuntimeError(FAILURE_TEXT))
        _fail_references_for(
            monkeypatch, {references.cve_id}, RuntimeError(FAILURE_TEXT)
        )

        with capture_logs() as logs:
            await batch.execute()

        assert [
            (entry.get("cve_id"), entry["cause"])
            for entry in _events(logs, CVE_FETCH_ITEM_FAILED_EVENT)
        ] == [
            (None, "InvalidCveIdError"),
            (lookup.cve_id, "OperationalError"),
            (date_error.cve_id, "InvalidDateAddedError"),
            (cwes_error.cve_id, "InvalidCwesError"),
            (upsert.cve_id, "RuntimeError"),
            (references.cve_id, "RuntimeError"),
        ]
        assert counters(batch.fetcher) == Counters(1, 0, 1, 6)
        for cve in (lookup, date_error, cwes_error, upsert, references):
            await env.assert_untouched(cve)
        await env.assert_no_isolated_status(
            lookup, date_error, cwes_error, upsert, references, success
        )
        assert await env.sources(success) == [("kev", CVESourceFetchStatus.SUCCESS)]
        _assert_private(logs)


# ---------------------------------------------------------------------------
# External String Admissibility
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestExternalStringAdmissibility:
    @pytest.mark.parametrize(
        "cve_id",
        ["CVE-2099-0001\x00", "\x00CVE-2099-0001", "CVE-2099-\x000001", "\x00"],
        ids=["end", "start", "middle", "whole"],
    )
    async def test_nul_in_cve_id_is_an_invalid_id_unit_with_no_query(
        self, cve_id: str, env: Env, batch: Batch, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        later = await env.cve()
        env.serve(_entry(cve_id), _entry(later.cve_id))
        trace = _trace(monkeypatch, batch)

        with capture_logs() as logs, trace.recording(batch):
            await batch.execute()

        assert trace.statements_of(0) == []
        assert trace.rollbacks == []
        assert _events(logs, CVE_FETCH_ITEM_FAILED_EVENT) == [
            _failed(None, "InvalidCveIdError")
        ]
        _assert_private(logs)
        assert counters(batch.fetcher) == Counters(1, 0, 1, 1)

    @pytest.mark.parametrize(
        "item",
        ["CWE-79\x00", "\x00CWE-79", "CWE-\x0079", "\x00"],
        ids=["end", "start", "middle", "whole"],
    )
    async def test_nul_in_a_cwe_item_skips_that_cwe(
        self, item: str, env: Env, batch: Batch
    ) -> None:
        cve = await env.cve()
        env.serve(_entry(cve.cve_id, cwes=[item, "CWE-352"]))

        with capture_logs() as logs:
            await batch.execute()

        assert await env.cwes(cve) == _kev_cwes("CWE-352")
        assert _events(logs, CVE_FETCH_CANDIDATE_SKIPPED_EVENT) == [
            _skipped(cve.cve_id)
        ]
        assert _events(logs, CVE_FETCH_ITEM_FAILED_EVENT) == []
        _assert_private(logs)
        assert counters(batch.fetcher) == Counters(1, 0, 1, 0)

    @pytest.mark.parametrize(
        "date_added",
        ["2026-10-01\x00", "\x002026-10-01", "2026-10\x00-01", "\x00"],
        ids=["end", "start", "middle", "whole"],
    )
    async def test_nul_in_date_added_is_an_invalid_date_unit(
        self,
        date_added: str,
        env: Env,
        batch: Batch,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        failing = await env.cve()
        later = await env.cve()
        env.serve(_entry(failing.cve_id, dateAdded=date_added), _entry(later.cve_id))
        trace = _trace(monkeypatch, batch)

        with capture_logs() as logs:
            await batch.execute()

        await _assert_rolled_back_unit(
            env, batch, trace, logs, failing, later, "InvalidDateAddedError"
        )


# ---------------------------------------------------------------------------
# Per-entry finalization and run boundaries
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestFinalization:
    async def test_flush_precedes_finalization_and_effects_follow_commit(
        self, env: Env, batch: Batch, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cve = await env.cve()
        env.serve(_entry(cve.cve_id))
        events: list[str] = []
        pending_at_finalization: list[bool] = []
        tokens: list[Any] = []
        at_commit: list[Counters] = []
        real_ingest = batch.fetcher._ingest
        real_finalize = batch.fetcher.commit_and_dispatch
        real_flush = batch.session.flush
        real_commit = batch.session.commit
        inside_ingest = [False]

        async def ingest(
            session: AsyncSession, cve_id: str, entry: dict[str, object]
        ) -> CVEFetchResult:
            events.append("ingest")
            inside_ingest[0] = True
            try:
                return await real_ingest(session, cve_id, entry)
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

        assert events == ["ingest", "flush", "commit_and_dispatch", "commit"]
        assert pending_at_finalization == [False]
        [token] = tokens
        assert isinstance(token, CVEFetchResult)
        assert token.action is UpsertAction.UPDATED
        assert token.post_ingest is None
        assert token._consumed
        # The effect and the success are absent until the commit.
        assert at_commit == [Counters(0, 0, 0, 0)]
        assert counters(batch.fetcher) == Counters(1, 0, 1, 0)
        assert env.published.published(RESOLVE) == []

    async def test_commit_failure_terminates_without_warning_metric_or_status(
        self, env: Env, batch: Batch, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        first = await env.cve()
        second = await env.cve()
        env.serve(_entry(first.cve_id), _entry(second.cve_id))
        trace = _trace(monkeypatch, batch)
        error = RuntimeError(FAILURE_TEXT)

        async def commit() -> None:
            raise error

        monkeypatch.setattr(batch.session, "commit", commit)

        with capture_logs() as logs, pytest.raises(RuntimeError) as raised:
            await batch.execute()

        assert raised.value is error
        assert trace.ingested == [0]
        assert trace.rollbacks == []
        assert counters(batch.fetcher) == Counters(0, 0, 0, 0)
        assert _events(logs, CVE_FETCH_ITEM_FAILED_EVENT) == []
        await batch.session.rollback()
        await env.assert_untouched(first)
        await env.assert_untouched(second)
        await env.assert_no_isolated_status(first, second)
        assert env.published.calls == []

    async def test_ambiguous_commit_terminates_without_metric_or_status(
        self, env: Env, batch: Batch, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        first = await env.cve()
        second = await env.cve()
        env.serve(_entry(first.cve_id), _entry(second.cve_id))
        trace = _trace(monkeypatch, batch)
        real_commit = batch.session.commit
        error = ConnectionResetError("commit outcome unknown")

        async def commit() -> None:
            await real_commit()
            raise error

        monkeypatch.setattr(batch.session, "commit", commit)

        with capture_logs() as logs, pytest.raises(ConnectionResetError):
            await batch.execute()

        assert trace.ingested == [0]
        assert counters(batch.fetcher) == Counters(0, 0, 0, 0)
        assert _events(logs, CVE_FETCH_ITEM_FAILED_EVENT) == []
        # The durable commit is never reclassified as an isolated failure.
        assert await env.kev(first) == (DATE_ADDED, reference_url(first.cve_id))
        assert await env.sources(first) == [("kev", CVESourceFetchStatus.SUCCESS)]
        await env.assert_untouched(second)
        await env.assert_no_isolated_status(first, second)

    async def test_non_operational_post_commit_error_aborts_and_keeps_success(
        self, env: Env, batch: Batch, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        first = await env.cve()
        second = await env.cve()
        env.serve(_entry(first.cve_id), _entry(second.cve_id))
        trace = _trace(monkeypatch, batch)
        error = RuntimeError(FAILURE_TEXT)

        async def drain(session: AsyncSession) -> None:
            raise error

        monkeypatch.setattr(
            ticket_convergence_publication, "drain_ticket_convergence", drain
        )

        with capture_logs() as logs, pytest.raises(RuntimeError) as raised:
            await batch.execute()

        assert raised.value is error
        assert trace.ingested == [0]
        assert trace.rollbacks == []
        # Success and effect were recorded after the commit; no failure.
        assert counters(batch.fetcher) == Counters(1, 0, 1, 0)
        assert _events(logs, CVE_FETCH_ITEM_FAILED_EVENT) == []
        assert await env.kev(first) == (DATE_ADDED, reference_url(first.cve_id))
        assert await env.references(first) == [_kev_reference(first)]
        await env.assert_untouched(second)
        await env.assert_no_isolated_status(first, second)


_SIGNALS: Final = [asyncio.CancelledError, SoftTimeLimitExceeded, MemoryError]


@pytest.mark.integration
class TestWholeRunSignals:
    @pytest.mark.parametrize(
        "stage", ["lookup", "extract", "upsert", "references", "flush"]
    )
    @pytest.mark.parametrize("signal_type", _SIGNALS, ids=lambda t: t.__name__)
    async def test_signal_propagates_from_the_entry_boundary(
        self,
        stage: str,
        signal_type: type[BaseException],
        env: Env,
        batch: Batch,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        first = await env.cve()
        second = await env.cve()
        env.serve(_entry(first.cve_id), _entry(second.cve_id))
        trace = _trace(monkeypatch, batch)
        signal = signal_type()

        async def raise_signal(*args: Any, **kwargs: Any) -> Any:
            raise signal

        def raise_signal_sync(*args: Any, **kwargs: Any) -> Any:
            raise signal

        if stage == "lookup":
            monkeypatch.setattr(batch.fetcher, "_cve_exists", raise_signal)
        elif stage == "extract":
            monkeypatch.setattr(cisa_kev_catalog, "extract", raise_signal_sync)
        elif stage == "upsert":
            monkeypatch.setattr(cve_service, "upsert_cve", raise_signal)
        elif stage == "references":
            monkeypatch.setattr(reference_service, "upsert_references", raise_signal)
        else:
            traced_ingest = batch.fetcher._ingest
            real_flush = batch.session.flush
            inside_ingest = [False]

            async def ingest(
                session: AsyncSession, cve_id: str, entry: dict[str, object]
            ) -> CVEFetchResult:
                inside_ingest[0] = True
                try:
                    return await traced_ingest(session, cve_id, entry)
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
        # Only the first entry was entered; no per-entry handling occurred.
        assert trace.current == [0]
        assert trace.rollbacks == []
        assert counters(batch.fetcher) == Counters(0, 0, 0, 0)
        assert [entry["event"] for entry in logs] == [CISA_KEV_CATALOG_RECEIVED_EVENT]
        await batch.session.rollback()
        await env.assert_untouched(first)
        await env.assert_untouched(second)
        await env.assert_no_isolated_status(first, second)


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestCatalogReceivedLog:
    @pytest.mark.parametrize(
        ("count", "logged"),
        [
            (ABSENT, None),
            ("1", None),
            (1.0, None),
            (True, None),
            (None, None),
            ({"value": 1}, None),
            (1, 1),
            (1734, 1734),
            (0, 0),
        ],
        ids=[
            "absent",
            "string",
            "float",
            "bool",
            "null",
            "object",
            "matching",
            "larger",
            "smaller",
        ],
    )
    async def test_count_is_logged_in_the_bounded_form_and_never_aborts(
        self, count: Any, logged: int | None, env: Env, batch: Batch
    ) -> None:
        cve = await env.cve()
        env.serve(_entry(cve.cve_id))
        if count is ABSENT:
            del env.server.catalog["count"]
        else:
            env.server.catalog["count"] = count

        with capture_logs() as logs:
            await batch.execute()

        [received] = _events(logs, CISA_KEV_CATALOG_RECEIVED_EVENT)
        assert received == {
            "event": CISA_KEV_CATALOG_RECEIVED_EVENT,
            "log_level": "info",
            "fetcher_name": NAME,
            "count": logged,
            "entries": 1,
        }
        assert set(received) == RECEIVED_EVENT_KEYS
        assert counters(batch.fetcher) == Counters(1, 0, 1, 0)

    async def test_raw_feed_text_reaches_no_log(self, env: Env, batch: Batch) -> None:
        cve = await env.cve()
        noisy = _entry(cve.cve_id, cwes=[FAILURE_TEXT, "CWE-79"])
        for key in ("vendorProject", "shortDescription", "notes", "requiredAction"):
            noisy[key] = FAILURE_TEXT
        env.serve(
            _entry(f"CVE-2099-{FAILURE_TEXT}"),
            _entry(env.unknown_id(), dateAdded=FAILURE_TEXT),
            noisy,
        )
        env.server.catalog["title"] = FAILURE_TEXT
        env.server.catalog["count"] = FAILURE_TEXT

        with capture_logs() as logs:
            await batch.execute()

        assert [entry["event"] for entry in logs] == [
            CISA_KEV_CATALOG_RECEIVED_EVENT,
            CVE_FETCH_ITEM_FAILED_EVENT,
            CVE_FETCH_CANDIDATE_SKIPPED_EVENT,
        ]
        _assert_private(logs)
        assert counters(batch.fetcher) == Counters(1, 0, 1, 1)


# ---------------------------------------------------------------------------
# MITRE/KEV overlap
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestMitreOverlap:
    async def test_identical_kev_entry_is_unchanged(
        self, env: Env, batch: Batch
    ) -> None:
        cve = await env.cve()
        await env.seed_mitre(cve)
        before = await env.state(cve)
        env.serve(_entry(cve.cve_id, cwes=[]))

        await batch.execute()

        assert counters(batch.fetcher) == Counters(1, 0, 0, 0)
        after = await env.state(cve)
        assert after.kev == before.kev
        assert after.cwes == before.cwes
        assert after.events == before.events
        assert after.priority_auto == "P1"
        assert after.sources == [
            ("kev", CVESourceFetchStatus.SUCCESS),
            ("mitre", CVESourceFetchStatus.SUCCESS),
        ]

    async def test_kev_cwe_coexists_with_the_cisa_adp_cwe(
        self, env: Env, batch: Batch
    ) -> None:
        cve = await env.cve()
        await env.seed_mitre(cve)
        env.serve(_entry(cve.cve_id, cwes=["CWE-79"]))

        await batch.execute()

        assert await env.cwes(cve) == [
            ("CWE-79", KEV_CWE_SOURCE),
            ("CWE-79", MITRE_CWE_SOURCE),
        ]
        assert await env.kev(cve) == (DATE_ADDED, reference_url(cve.cve_id))
        # The additional provenance row is an effective CWE change.
        assert counters(batch.fetcher) == Counters(1, 0, 1, 0)

    @pytest.mark.parametrize(
        ("mitre_title", "title"),
        [(None, "CISA KEV"), ("Example MITRE Title", "Example MITRE Title")],
        ids=["null_title", "existing_title"],
    )
    async def test_mitre_reference_keeps_its_source_and_only_nulls_are_filled(
        self, mitre_title: str | None, title: str, env: Env, batch: Batch
    ) -> None:
        cve = await env.cve()
        await env.seed_mitre(cve, reference_title=mitre_title)
        assert await env.references(cve) == [
            (reference_url(cve.cve_id), mitre_title, None, MITRE_NAME, None)
        ]
        env.serve(_entry(cve.cve_id, cwes=[]))

        await batch.execute()

        assert await env.references(cve) == [
            (
                reference_url(cve.cve_id),
                title,
                ReferenceType.ADVISORY.value,
                MITRE_NAME,
                None,
            )
        ]
        assert counters(batch.fetcher) == Counters(1, 0, 0, 0)


# ---------------------------------------------------------------------------
# run(): the sync_cisa_kev metric mapping on a finalized FetcherRun
# ---------------------------------------------------------------------------


def _forbid_record_created(
    monkeypatch: pytest.MonkeyPatch, fetcher: SyncCisaKev
) -> list[int]:
    calls: list[int] = []
    monkeypatch.setattr(fetcher, "record_created", calls.append)
    return calls


@pytest.mark.integration
class TestRunMetrics:
    async def test_success_maps_updated_unchanged_and_excludes_unknown(
        self, env: Env, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        unchanged = await env.cve()
        env.serve(_entry(unchanged.cve_id))
        await (await env.batch()).execute()
        updated = await env.cve()
        orphan = await env.orphan()
        env.serve(
            _entry(env.unknown_id()),
            _entry(unchanged.cve_id),
            _entry(updated.cve_id),
            _entry(orphan.cve_id),
            _entry(env.unknown_id()),
        )
        fetcher, run_id = await env.run_row()
        created = _forbid_record_created(monkeypatch, fetcher)

        await fetcher.run(run_id=run_id, config=_RUN_CONFIG)

        run = await env.run_outcome(run_id)
        # Never `record_created`: KEV only enriches existing CVEs.
        assert _outcome(run) == ("success", 3, 0, 2, 0)
        assert run.error_message is None
        assert run.error_detail is None
        assert run.cursor is None
        assert created == []
        await env.assert_no_isolated_status(unchanged, updated, orphan)

    async def test_empty_catalog_is_success_with_zero_metrics(self, env: Env) -> None:
        run = await env.run()

        assert _outcome(run) == ("success", 0, 0, 0, 0)
        assert run.error_message is None
        assert run.cursor is None
        assert len(env.server.requests) == 1

    async def test_first_run_on_an_empty_database_is_success_with_zero_metrics(
        self, env: Env
    ) -> None:
        # The unmodified fixture: none of its CVEs exists here.
        env.world.cve_id_strings.extend(FIXTURE_CVE_IDS)
        async with env.factory() as session:
            assert (
                await session.scalar(
                    select(CVE.id).where(CVE.cve_id.in_(FIXTURE_CVE_IDS))
                )
                is None
            )
        env.server.catalog = load_catalog()

        with capture_logs() as logs:
            run = await env.run()

        assert _outcome(run) == ("success", 0, 0, 0, 0)
        assert run.cursor is None
        assert _events(logs, CVE_FETCH_ITEM_FAILED_EVENT) == []
        async with env.factory() as session:
            assert (
                await session.scalar(
                    select(CVE.id).where(CVE.cve_id.in_(FIXTURE_CVE_IDS))
                )
                is None
            )

    async def test_all_selected_units_failed_is_failure(self, env: Env) -> None:
        date_error = await env.cve()
        cwes_error = await env.cve()
        env.serve(
            _entry(None),
            _entry(env.unknown_id()),
            _entry(date_error.cve_id, dateAdded=None),
            _entry(cwes_error.cve_id, cwes={}),
        )

        run = await env.run()

        assert _outcome(run) == ("failure", 0, 0, 0, 3)
        assert run.error_message == "All 3 items failed"
        assert run.error_detail is None
        assert run.cursor is None
        await env.assert_no_isolated_status(date_error, cwes_error)

    async def test_success_plus_failure_is_partial(
        self, env: Env, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        unchanged = await env.cve()
        env.serve(_entry(unchanged.cve_id))
        await (await env.batch()).execute()
        failing = await env.cve()
        env.serve(_entry(unchanged.cve_id), _entry(failing.cve_id, dateAdded=""))
        fetcher, run_id = await env.run_row()
        created = _forbid_record_created(monkeypatch, fetcher)

        with capture_logs(processors=[merge_contextvars]) as logs:
            await fetcher.run(run_id=run_id, config=_RUN_CONFIG)

        run = await env.run_outcome(run_id)
        assert _outcome(run) == ("partial", 1, 0, 0, 1)
        assert run.error_message is None
        assert run.cursor is None
        assert created == []
        # The per-entry event binds to the run's correlation context.
        assert _events(logs, CVE_FETCH_ITEM_FAILED_EVENT) == [
            {
                **_failed(failing.cve_id, "InvalidDateAddedError"),
                "fetcher_run_id": str(run_id),
            }
        ]

    async def test_post_commit_error_fails_the_run_and_keeps_success_metrics(
        self, env: Env, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cve = await env.cve()
        env.serve(_entry(cve.cve_id))
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
        assert await env.kev(cve) == (DATE_ADDED, reference_url(cve.cve_id))
        await env.assert_no_isolated_status(cve)

    async def test_commit_failure_fails_the_run_without_unit_metrics(
        self, env: Env, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cve = await env.cve()
        env.serve(_entry(cve.cve_id))
        fetcher, run_id = await env.run_row()
        _fail_execution_commit(monkeypatch, env, fail_at=1)

        with pytest.raises(RuntimeError):
            await fetcher.run(run_id=run_id, config=_RUN_CONFIG)

        run = await env.run_outcome(run_id)
        assert _outcome(run) == ("failure", 0, 0, 0, 0)
        assert run.error_message == "Unexpected error"
        await env.assert_untouched(cve)
        await env.assert_no_isolated_status(cve)


def _fail_execution_commit(
    monkeypatch: pytest.MonkeyPatch, env: Env, *, fail_at: int
) -> None:
    """Make the `fail_at`-th commit of the next `run()`'s execution session
    raise without committing; earlier commits are real."""
    real_factory = env.factory
    sessions = [0]

    def execution_session() -> AsyncSession:
        session = real_factory()
        real_commit = session.commit
        commits = [0]

        async def commit() -> None:
            commits[0] += 1
            if commits[0] == fail_at:
                raise RuntimeError(FAILURE_TEXT)
            await real_commit()

        monkeypatch.setattr(session, "commit", commit)
        return session

    def factory() -> AsyncSession:
        # Cursor load, then the execution session, then finalization:
        # only the execution session is instrumented.
        sessions[0] += 1
        return execution_session() if sessions[0] == 2 else real_factory()

    monkeypatch.setattr(base_fetcher_module, "async_session_factory", factory)


# ---------------------------------------------------------------------------
# Re-invocation
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestReinvocation:
    async def test_second_run_creates_no_row_event_or_effect(self, env: Env) -> None:
        listed = await env.cve()
        orphan = await env.orphan()
        env.serve(
            _entry(listed.cve_id, cwes=["CWE-79", "CWE-79", "CWE-352"]),
            _entry(orphan.cve_id, cwes=[]),
            _entry(env.unknown_id()),
        )
        first = await env.run()
        before = [await env.state(listed), await env.state(orphan)]
        published = len(env.published.calls)

        second = await env.run()

        assert _outcome(first) == ("success", 2, 0, 2, 0)
        assert _outcome(second) == ("success", 2, 0, 0, 0)
        after = [await env.state(listed), await env.state(orphan)]
        assert after == before
        assert len(env.published.calls) == published
        assert env.published.published(RESOLVE) == []

    async def test_rerun_after_a_mid_run_failure_reaches_the_same_final_state(
        self, env: Env, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        interrupted = [await env.cve() for _ in range(3)]
        control = [await env.cve() for _ in range(3)]
        shapes = [
            {"dateAdded": "2026-09-01", "cwes": ["CWE-79"]},
            {"dateAdded": "2026-09-02", "cwes": ["CWE-352", "CWE-352"]},
            {"dateAdded": "2026-09-03", "cwes": []},
        ]

        def catalog(cves: list[CVE]) -> None:
            env.serve(
                *(
                    _entry(cve.cve_id, **shape)
                    for cve, shape in zip(cves, shapes, strict=True)
                )
            )

        # The first run aborts on the commit of the second entry.
        catalog(interrupted)
        fetcher, run_id = await env.run_row()
        with monkeypatch.context() as patch:
            _fail_execution_commit(patch, env, fail_at=2)
            with pytest.raises(RuntimeError):
                await fetcher.run(run_id=run_id, config=_RUN_CONFIG)
        assert _outcome(await env.run_outcome(run_id)) == ("failure", 1, 0, 1, 0)
        assert await env.kev(interrupted[0]) is not None
        await env.assert_untouched(interrupted[1])
        await env.assert_untouched(interrupted[2])

        rerun = await env.run()
        catalog(control)
        uninterrupted = await env.run()

        assert _outcome(rerun) == ("success", 3, 0, 2, 0)
        assert _outcome(uninterrupted) == ("success", 3, 0, 3, 0)
        for retried, reference in zip(interrupted, control, strict=True):
            assert await _normalized(env, retried) == await _normalized(env, reference)
        await env.assert_no_isolated_status(*interrupted, *control)


async def _normalized(env: Env, cve: CVE) -> tuple[Any, ...]:
    """The CVE's KEV-relevant state with its own CVE-ID replaced, for
    comparing two CVEs."""

    def strip(value: Any) -> Any:
        return (
            value.replace(cve.cve_id, "{cve_id}") if isinstance(value, str) else value
        )

    kev = await env.kev(cve)
    return (
        None if kev is None else tuple(strip(value) for value in kev),
        await env.cwes(cve),
        await env.sources(cve),
        [tuple(strip(value) for value in row) for row in await env.references(cve)],
        await env.priority_auto(cve),
        [
            dataclasses.replace(row, new_value=strip(row.new_value))
            for row in await env.events(cve)
        ],
    )
