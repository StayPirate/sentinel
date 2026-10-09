"""KEV evidence written through the real `SyncMitreCves` class
(backend/app/services/tickets/sync_mitre_cves.py): the KEV source-status
projection of a MITRE-written `CVEKEVEntry`, and the MITRE/KEV overlap with
the real `SyncCisaKev` (backend/app/services/tickets/sync_cisa_kev.py) in
either execution order.

Owning specifications:

- docs/features/tickets/cve-sync-mitre.md (CISA-ADP specific fields:
  `kev_data`, `cwe_classifications` with `source = "adp:CISA-ADP"`;
  Algorithm step 2, the CNA `references[]` candidates).
- docs/features/tickets/cve-sync-kev.md (Algorithm: enrichment of existing
  CVEs only; Field Mapping; MITRE/KEV Overlap).
- docs/features/tickets/cve-service.md (KEV status derivation:
  `fetched_at = CVEKEVEntry.updated_at` whichever writer persisted it).
- docs/features/tickets/ticket-references.md (Automatic Ingestion,
  Database Merge Rules: different automatic source).
- docs/features/tickets/ticket-priority.md (Exploitation Level: KEV
  presence; Decision Table: `kev` is P1 at every severity).
- docs/features/platform/testing-strategy.md (CVE and Source Reads, KEV
  projection: an entry written through the MITRE CISA-ADP container).

The MITRE runs are the inherited `execute()` through the real
`BaseFetcher.run()` over a real temporary upstream and bare `cvelistV5`
clone (`open_git_run_harness()` of `tests/support/git_fetchers.py`). The
KEV runs are the real `SyncCisaKev.run()` over the in-process `KevServer`
of `tests/support/cisa_kev.py`, on the same run-session substitute. The
record is `cisa_kev_cwe_tags` re-keyed to a fictional CVE-ID, with its KEV
`reference` re-keyed to the CVE's catalog URL, a CISA-ADP `cweId`, no SSVC
(so KEV is the only exploitation input of the priority), and the catalog
URL among its CNA `references[]`, so the reference overlap is real: the
captured record carries that URL only in the CISA-ADP container, whose
references are not candidates.

Every committed CVE, Ticket, `FetcherRun`, and `FetcherConfig` row is
deleted at teardown, which asserts that no CVE leaked. The KEV status
derivation reads the latest successful `sync_cisa_kev` run globally, so
no committed row of either fetcher may exist before seeding
(testing-strategy.md, Parallel Execution: one test at a time per worker
database). All identifiers are fictional.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any, Final, NamedTuple

import httpx
import pytest
import redis.asyncio as redis_asyncio
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

import app.services.base_fetcher as base_fetcher_module
from app.core.enums import (
    CVESourceDerivedStatus,
    CVESourceType,
    ReferenceType,
    Scope,
    TicketPriority,
)
from app.models.cve import CVE
from app.models.cve_kev_entry import CVEKEVEntry
from app.models.fetcher_run import FetcherRun
from app.models.ticket import Ticket
from app.services import cve_service
from app.services.base_fetcher import FetcherRunConfig
from app.services.cve_service import CVESourceStatusEntry
from app.services.ticket_visibility import TicketCaller
from app.services.tickets.sync_cisa_kev import SyncCisaKev
from app.services.tickets.sync_mitre_cves import SyncMitreCves
from tests.support.cisa_kev import KevServer, catalog_of, entry_for, reference_url
from tests.support.cve_catch_up import seed_fetcher_config
from tests.support.git_fetcher_state import (
    ReferenceRow,
    committed_fetcher_rows,
    references,
    ticket_of,
)
from tests.support.git_fetchers import (
    GitFetcherProbe,
    GitRunHarness,
    GitWorkspace,
    RunRow,
    SessionFactory,
    install_git_workspace,
    open_git_run_harness,
)
from tests.support.mitre import CISA_ADP_ORG_ID
from tests.support.mitre_fetcher import (
    NAME,
    KevRow,
    adps,
    cna,
    commit,
    cwes,
    derived_record,
    kev,
    mitre_probe,
    record_path,
)

pytestmark = pytest.mark.integration

KEV_NAME: Final = "sync_cisa_kev"
KEV: Final = CVESourceType.KEV
SUCCESS: Final = CVESourceDerivedStatus.SUCCESS
ALL_SCOPE: Final = TicketCaller.authenticated(uuid.uuid4(), Scope.ALL)

D_BASE: Final = "2026-10-01T00:00:00+00:00"
D_1: Final = "2026-10-02T00:00:00+00:00"
DATE_ADDED: Final = "2026-06-01"
"""The CISA-ADP KEV `dateAdded` of `cisa_kev_cwe_tags`, served unchanged by
the catalog entry."""
CWE: Final = "CWE-79"
CVE_ORG: Final = "https://cve.org/CVERecord?id="
ORACLE_ADVISORY: Final = "https://www.oracle.com/security-alerts/cpujul2024.html"

_KEV_RUN_CONFIG: Final = FetcherRunConfig(
    hard_time_limit_seconds=3600, request_delay=0, custom_settings={}
)

ORDERS: Final = ["mitre-first", "kev-first"]


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------


@pytest.fixture
def workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> GitWorkspace:
    created = install_git_workspace(tmp_path, monkeypatch)
    monkeypatch.setattr(SyncMitreCves, "repo_url", created.upstream.url)
    return created


@pytest.fixture
async def harness(
    monkeypatch: pytest.MonkeyPatch,
    real_session_factory: async_sessionmaker[AsyncSession],
    db_session_factory: SessionFactory,
    redis_client: redis_asyncio.Redis,
) -> AsyncIterator[GitRunHarness]:
    """`redis_client` points the pending overlay of the status read at the
    worker's Redis database."""
    # The MITRE cursor and the KEV latest-run read span every committed
    # run of the name.
    assert await committed_fetcher_rows(real_session_factory, NAME) == 0
    assert await committed_fetcher_rows(real_session_factory, KEV_NAME) == 0
    opened = await open_git_run_harness(
        monkeypatch, real_session_factory, db_session_factory
    )
    try:
        await opened.world.ensure_default_setting()
        yield opened
    finally:
        await opened.cleanup()


@pytest.fixture
async def mitre(harness: GitRunHarness) -> GitFetcherProbe:
    """The production class with its committed, enabled `FetcherConfig`."""
    probe = mitre_probe(harness.events)
    await harness.register(probe)
    return probe


@pytest.fixture
async def kev_server(
    harness: GitRunHarness,
    real_session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> KevServer:
    """The catalog the real `SyncCisaKev` downloads through its lazily
    created HTTP client, and its committed, enabled `FetcherConfig`
    (deleted at teardown with its runs)."""
    server = KevServer(catalog_of())

    def create_http_client(name: str, **options: Any) -> httpx.AsyncClient:
        assert name == KEV_NAME
        assert options == {}
        return server.client()

    monkeypatch.setattr(base_fetcher_module, "create_http_client", create_http_client)
    harness.names.append(KEV_NAME)
    await seed_fetcher_config(real_session_factory, KEV_NAME, enabled=True)
    return server


def _cisa(record: dict[str, Any]) -> dict[str, Any]:
    [cisa] = [
        adp
        for adp in adps(record)
        if adp["providerMetadata"].get("orgId") == CISA_ADP_ORG_ID
    ]
    return cisa


def _overlap_record(cve_id: str, tags: list[str] | None) -> bytes:
    """`cisa_kev_cwe_tags` re-keyed to `cve_id` with the edits of the
    module docstring; `tags` are the CNA tags of the catalog URL (`None`
    omits the key)."""

    def edit(record: dict[str, Any]) -> None:
        cisa = _cisa(record)
        metrics = [
            metric
            for metric in cisa["metrics"]
            if metric.get("other", {}).get("type") != "ssvc"
        ]
        [kev_metric] = metrics
        assert kev_metric["other"]["content"]["dateAdded"] == DATE_ADDED
        kev_metric["other"]["content"]["reference"] = reference_url(cve_id)
        cisa["metrics"] = metrics
        cisa["problemTypes"] = [
            {
                "descriptions": [
                    {
                        "type": "CWE",
                        "lang": "en",
                        "cweId": CWE,
                        "description": f"{CWE} Fictional weakness",
                    }
                ]
            }
        ]
        candidate: dict[str, Any] = {"url": reference_url(cve_id)}
        if tags is not None:
            candidate["tags"] = tags
        cna(record)["references"].append(candidate)

    return derived_record("cisa_kev_cwe_tags", cve_id, edit)


async def _first_run(
    workspace: GitWorkspace, harness: GitRunHarness, mitre: GitFetcherProbe
) -> None:
    """Commit a base without records and record HEAD with a first run."""
    commit(
        workspace.upstream, {"README.md": b"example: fictional README\n"}, date=D_BASE
    )
    assert (await harness.run(mitre)).row.status == "success"


async def _mitre_run(
    workspace: GitWorkspace,
    harness: GitRunHarness,
    mitre: GitFetcherProbe,
    cve_id: str,
    tags: list[str] | None,
) -> RunRow:
    commit(
        workspace.upstream,
        {record_path(cve_id): _overlap_record(cve_id, tags)},
        date=D_1,
    )
    return (await harness.run(mitre)).row


async def _kev_run(harness: GitRunHarness, server: KevServer, cve_id: str) -> RunRow:
    """One complete `run()` of the real KEV class on a committed `running`
    run, serving one entry for `cve_id` with the record's `dateAdded`."""
    server.catalog = catalog_of(entry_for(cve_id, date_added=DATE_ADDED, cwes=[CWE]))
    async with harness.factory() as session:
        run = FetcherRun(
            fetcher_name=KEV_NAME,
            started_at=datetime.now(UTC),
            status="running",
            triggered_by="schedule",
        )
        session.add(run)
        await session.commit()
        run_id = run.id
    harness.sessions.reset()
    await SyncCisaKev().run(run_id=run_id, config=_KEV_RUN_CONFIG)
    return await harness.row(run_id)


async def _seed_cve(harness: GitRunHarness, cve_id: str) -> CVE:
    """A committed CVE with an `Analysis` Ticket and no evidence, as an
    earlier source ingested it: KEV only enriches existing CVEs."""
    world = harness.world
    cve = CVE(cve_id=cve_id)
    world.session.add(cve)
    await world.session.flush()
    world.cve_ids.append(cve.id)
    await world.session.commit()
    await world.ticket(cve_id=cve.id)
    return cve


async def _cve(harness: GitRunHarness, cve_id: str) -> CVE:
    cve = await harness.cve_named(cve_id)
    assert cve is not None
    return cve


async def _ticket(harness: GitRunHarness, cve: CVE) -> Ticket:
    ticket = await ticket_of(harness.factory, cve.id)
    assert ticket is not None
    return ticket


class KevEntryRow(NamedTuple):
    id: uuid.UUID
    date_added: date
    reference_url: str | None
    updated_at: datetime


async def _kev_entries(harness: GitRunHarness, cve: CVE) -> list[KevEntryRow]:
    """Every committed `CVEKEVEntry` of `cve`, identity and timestamp
    included, for a no-write proof."""
    async with harness.factory() as session:
        rows = await session.execute(
            select(
                CVEKEVEntry.id,
                CVEKEVEntry.date_added,
                CVEKEVEntry.reference_url,
                CVEKEVEntry.updated_at,
            ).where(CVEKEVEntry.cve_id == cve.id)
        )
    return [KevEntryRow(*row) for row in rows]


async def _kev_status(harness: GitRunHarness, cve: CVE) -> CVESourceStatusEntry:
    result = await cve_service.get_cve_source_status(
        cve.cve_id, ALL_SCOPE, session_factory=harness.factory
    )
    [entry] = [entry for entry in result.entries if entry.source == KEV.value]
    return entry


def _kev_success(fetched_at: datetime) -> CVESourceStatusEntry:
    """The `kev` entry of the registered, enabled production class with
    persisted evidence."""
    return CVESourceStatusEntry(
        source=KEV.value,
        status=SUCCESS,
        fetched_at=fetched_at,
        first_failed_at=None,
        registered=True,
        refetchable=False,
        enabled=True,
    )


# ---------------------------------------------------------------------------
# KEV projection of a MITRE-written entry
# ---------------------------------------------------------------------------


class TestKevProjection:
    async def test_mitre_written_entry_yields_success_at_its_updated_at(
        self,
        workspace: GitWorkspace,
        harness: GitRunHarness,
        mitre: GitFetcherProbe,
    ) -> None:
        """No `sync_cisa_kev` configuration or run exists: the entry the
        CISA-ADP container supplied is the evidence."""
        cve_id = harness.world.new_cve_id()
        await _first_run(workspace, harness, mitre)

        row = await _mitre_run(workspace, harness, mitre, cve_id, ["exploit"])

        assert row.status == "success"
        assert row.metrics == (1, 1, 0, 0)
        assert await committed_fetcher_rows(harness.factory, KEV_NAME) == 0
        cve = await _cve(harness, cve_id)
        [entry] = await _kev_entries(harness, cve)
        assert (entry.date_added, entry.reference_url) == (
            date(2026, 6, 1),
            reference_url(cve_id),
        )
        assert await _kev_status(harness, cve) == _kev_success(entry.updated_at)


# ---------------------------------------------------------------------------
# MITRE/KEV overlap
# ---------------------------------------------------------------------------


class TestMitreKevOverlap:
    @pytest.mark.parametrize("order", ORDERS)
    async def test_both_writers_converge_in_either_order(
        self,
        workspace: GitWorkspace,
        harness: GitRunHarness,
        mitre: GitFetcherProbe,
        kev_server: KevServer,
        order: str,
    ) -> None:
        """One `CVEKEVEntry`, identical whichever writer ran first and not
        rewritten by the second; both CWE provenances coexist; the catalog
        URL is one reference owned by the first writer, the second filling
        only NULL fields; the KEV entry drives the priority to P1."""
        cve_id = harness.world.new_cve_id()
        kev_url = reference_url(cve_id)
        await _first_run(workspace, harness, mitre)

        if order == "mitre-first":
            first = await _mitre_run(workspace, harness, mitre, cve_id, ["exploit"])
            assert first.metrics == (1, 1, 0, 0)
        else:
            seeded = await _seed_cve(harness, cve_id)
            assert (await _ticket(harness, seeded)).priority_auto is None
            first = await _kev_run(harness, kev_server, cve_id)
            assert first.metrics == (1, 0, 1, 0)
        assert first.status == "success"
        cve = await _cve(harness, cve_id)
        written = await _kev_entries(harness, cve)
        assert [(row.date_added, row.reference_url) for row in written] == [
            (date(2026, 6, 1), kev_url)
        ]
        assert (await _ticket(harness, cve)).priority_auto == TicketPriority.P1

        if order == "mitre-first":
            second = await _kev_run(harness, kev_server, cve_id)
        else:
            second = await _mitre_run(workspace, harness, mitre, cve_id, ["exploit"])
        # The second writer adds its CWE provenance (and, for MITRE, the
        # CNA data): one updated unit.
        assert second.status == "success"
        assert second.metrics == (1, 0, 1, 0)

        # The equal KEV values are a no-op of the conflict-aware write.
        assert await _kev_entries(harness, cve) == written
        assert await kev(harness.factory, cve.id) == [KevRow(date(2026, 6, 1), kev_url)]
        assert sorted(await cwes(harness.factory, cve.id)) == [
            (CWE, "CISA KEV"),
            (CWE, "adp:CISA-ADP"),
        ]
        ticket = await _ticket(harness, cve)
        mitre_rows = [
            ReferenceRow(f"{CVE_ORG}{cve_id}", "MITRE", ReferenceType.ADVISORY, NAME),
            # `vendor-advisory` tag.
            ReferenceRow(ORACLE_ADVISORY, None, ReferenceType.ADVISORY, NAME),
        ]
        if order == "mitre-first":
            # MITRE's `exploit` candidate owns the row with a NULL title; KEV
            # fills only the title and keeps the non-NULL type.
            expected = [
                *mitre_rows,
                ReferenceRow(kev_url, "CISA KEV", ReferenceType.ARTICLE, NAME),
            ]
        else:
            # KEV's source candidate owns the row; MITRE's has nothing NULL
            # to fill.
            expected = [
                ReferenceRow(kev_url, "CISA KEV", ReferenceType.ADVISORY, KEV_NAME),
                *mitre_rows,
            ]
        assert await references(harness.factory, ticket.id) == expected
        assert ticket.priority_auto == TicketPriority.P1
        assert await _kev_status(harness, cve) == _kev_success(written[0].updated_at)
        # KEV writes no isolated status (its documented deviation), and no
        # MITRE unit failed.
        assert harness.status.opened == []

    async def test_kev_fills_both_null_fields_of_an_untagged_mitre_reference(
        self,
        workspace: GitWorkspace,
        harness: GitRunHarness,
        mitre: GitFetcherProbe,
        kev_server: KevServer,
    ) -> None:
        """An untagged catalog URL matches no URL pattern: MITRE stores NULL
        title and type, and KEV fills both while MITRE keeps ownership."""
        cve_id = harness.world.new_cve_id()
        kev_url = reference_url(cve_id)
        await _first_run(workspace, harness, mitre)
        created = await _mitre_run(workspace, harness, mitre, cve_id, None)
        assert created.metrics == (1, 1, 0, 0)
        cve = await _cve(harness, cve_id)
        ticket = await _ticket(harness, cve)
        before = await references(harness.factory, ticket.id)
        assert [row for row in before if row.url == kev_url] == [
            ReferenceRow(kev_url, None, None, NAME)
        ]

        row = await _kev_run(harness, kev_server, cve_id)

        assert row.status == "success"
        assert await references(harness.factory, ticket.id) == [
            ReferenceRow(kev_url, "CISA KEV", ReferenceType.ADVISORY, NAME)
            if stored.url == kev_url
            else stored
            for stored in before
        ]
