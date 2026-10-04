"""End-to-end on-demand CVE fetch pipeline: database-free publication, the
published `fetch_single_cve`, the published `resolve_ticket_packages`, and
the package tree it creates (issue #799 acceptance criterion "End-to-end
pipeline"; the umbrella #797 decision L15 evidence of the M3 exit
criterion, verified with a test-only CVE source).

Owning specifications:

- docs/features/tickets/cve-service.md (Fetch Orchestration:
  `trigger_on_demand_fetch()`, Database-Free Publication and
  `FetchDispatchResult`; On-Demand Fetch: fetch_single_cve, Orchestrator
  Behavior: successful `CVEFetchResult` finalization through
  `commit_and_dispatch()`, owner release of the marker, no `FetcherRun`;
  Complete `upsert_cve()` Composition; Post-Commit Package-Candidate
  Handoff).
- docs/features/platform/cve-fetcher-infrastructure.md (Per-CVE
  Finalization: the `resolve_ticket_packages` handoff after the commit).
- docs/features/packages/package-service.md (Post-ingest CVE package
  resolution: Task boundary and arguments, Per-package workflow and
  transactions, Audit and observability; `add_package_to_ticket()` steps
  2-8; `add_package_records()` steps 10-13; Record Creation Logic) and
  docs/features/packages/package-model.md (SMELT Query for Package
  Resolution: `codestream.name` is the track reference, `SLE_15` maps to
  `ibs`, exact CPE match against the current Product catalog snapshot;
  Ticket Events for Package Changes; Axis 2: Eligibility).
- docs/features/packages/product-catalog.md (SMELT Integration > Product
  Sync steps 1-7: the synchronized catalog the CPEs are matched against).
- docs/features/platform/testing-strategy.md (On-Demand CVE Refetch;
  Post-Ingest Package Resolution; Sync Entry-Point Tests; Redis Strategy).

One `def` test drives the whole pipeline through the real code: a
registered test-only CVE fetcher (`tests/support/cve_catch_up.py`,
`isolated_fetcher_registries`) whose `fetch_single()` ingests through the
real `cve_service.upsert_cve()` and returns the real
`build_post_ingest_tasks()` handoff with one direct package candidate. The
recorded `fetch_single_cve` and `resolve_ticket_packages` messages are
delivered, after a JSON round trip, to the real synchronous Celery
wrappers of `app.tasks.cve_tasks`. Every phase runs in its own
`asyncio.run()`; the wrappers' session factory and the isolated status
sessions are `RecordingSessions` over the `NullPool` `cli_session_factory`,
so no connection crosses event loops, and the module-level `engine` is a
`FakeEngine`. Redis is the worker database of `redis_client`, whose URL
alone is used by clients created on each loop.

SMELT is the in-process `Smelt` fake of
`tests/support/post_ingest_resolution.py` serving the sanitized live
fixtures of #782 (`maintained_sle15_only.json`) and #775
(`maintainership_users_only.json`). The Product catalog is synchronized
from the captured live listing pages (`products_page_*.json`) through the
real Product Sync listing, validation, and publication. Expected rows are
transcribed from those fixtures, never computed with the module under
test. Every committed row is deleted explicitly at teardown. All CVE-IDs,
package names, users, and emails are fictional.
"""

from __future__ import annotations

import asyncio
import json
import uuid
from collections.abc import Awaitable, Callable, Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Final, TypeVar

import pytest
import redis.asyncio as redis_asyncio
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from structlog.testing import capture_logs

from app.core.enums import (
    CVESourceFetchStatus,
    CveState,
    Role,
    TicketStatus,
    WorkflowType,
)
from app.models.cve import CVE
from app.models.product import Product
from app.models.product_repository import ProductRepository
from app.models.system_setting import SystemSetting
from app.models.ticket import Ticket
from app.models.user import User
from app.services import base_cve_fetcher, cve_service, task_publication
from app.services.base_cve_fetcher import CVEFetchResult
from app.services.cve_ingest import CVEIngestPayload
from app.services.cve_service import FetchDispatchResult
from app.services.packages.smelt_product_listing import fetch_product_listing
from app.services.packages.sync_smelt_products import (
    publish_snapshot,
    validate_snapshot,
)
from app.tasks import cve_tasks
from tests.support.cve_catch_up import (
    RESOLVE,
    SOURCE,
    CVEProbe,
    FakeEngine,
    FakeTask,
    Publications,
    RecordingSessions,
    SourceState,
    Step,
    define_cve_fetcher,
    delete_fetcher_rows,
    fetcher_run_count,
    seed_fetcher_config,
    source_state,
)
from tests.support.cve_ingest import DEFAULT_SETTING_KEY, DEFAULT_VERSION
from tests.support.fetch_single_cve import (
    COMPLETED as FETCH_COMPLETED,
)
from tests.support.fetch_single_cve import (
    PENDING_TTL,
    TASK,
    TOKEN_PATTERN,
    fictional_cve_id,
    pending_key,
)
from tests.support.package_addition import SNAPSHOT_AT, reply
from tests.support.package_records import (
    NEW_TRACK,
    Tree,
    maintainer_event,
    maintainers,
    new_occurrence,
    package_tree,
    seed_user,
    ticket_row,
    tree_rows,
)
from tests.support.post_ingest_resolution import (
    CLIENT_NAME,
    Answer,
    Smelt,
    added,
    both,
    completed,
    install_environment,
    package_names,
    workflow_logs,
)
from tests.support.redis import redis_url_from_client
from tests.support.smelt import (
    FIXTURE_PAGES,
    SMELT_TEST_API_URL,
    SmeltServer,
    load_maintained_fixture,
    load_maintainership_fixture,
    load_products_page,
)
from tests.support.suse_cvss_races import CommittedWorld
from tests.support.ticket_mutations import EventRow, ticket_events_by_id

pytestmark = pytest.mark.usefixtures("isolated_fetcher_registries")

T = TypeVar("T")

NVD: Final = SOURCE.value

MAINTAINED_FIXTURE: Final = "sle15_only"
"""#782 `maintained_sle15_only.json`: two `SLE_15` codestreams."""

MAINTAINERSHIP_FIXTURE: Final = "users_only"
"""#775 `maintainership_users_only.json`: one direct user, twice."""

# Transcribed from `maintained_sle15_only.json`.
SLE_12_UPDATE: Final = "SUSE:SLE-12:Update"
SLE_15_UPDATE: Final = "SUSE:SLE-15:Update"
SLES_LTSS_12_SP5: Final = "cpe:/o:suse:sles-ltss:12:sp5"
SLES_LTSS_ES_12_SP5: Final = "cpe:/o:suse:sles-ltss-extended-security:12:sp5"
PACKAGE_HUB_15_SP7: Final = "cpe:/o:suse:packagehub:15:sp7"

MAINTAINER_EMAIL: Final = "maintainer.1@example.com"
"""Transcribed from `maintainership_users_only.json` (fictional)."""

CATALOG_PRODUCTS: Final = {
    SLES_LTSS_12_SP5: (
        "SLES-LTSS",
        "12-SP5",
        "SUSE Linux Enterprise Server 12 SP5 LTSS",
    ),
    SLES_LTSS_ES_12_SP5: (
        "SLES-LTSS-Extended-Security",
        "12-SP5",
        "SUSE Linux Enterprise Server 12 SP5 LTSS Extended Security",
    ),
    PACKAGE_HUB_15_SP7: ("PackageHub", "15-SP7", "SUSE Package Hub 15"),
}
"""`(name, version, display_name)` of the matched Products, transcribed
from the `products_page_*.json` rows (`name`, `version`, `friendly_name`)."""

TITLE: Final = "Fictional pipeline vulnerability"
DESCRIPTION: Final = "A fictional vulnerability ingested on demand."
PUBLISHED_AT: Final = datetime(2099, 2, 3, 4, 5, tzinfo=UTC)

ANALYSIS: Final = TicketStatus.ANALYSIS.value


def _delivered(kwargs: Mapping[str, Any]) -> dict[str, Any]:
    """The task arguments as a JSON-serializing broker delivers them."""
    delivered: dict[str, Any] = json.loads(json.dumps(kwargs))
    return delivered


def _on_demand_logs(logs: Iterable[Mapping[str, Any]]) -> list[Mapping[str, Any]]:
    return [
        entry
        for entry in logs
        if str(entry["event"]).startswith(("fetch_single_cve_", "fetch_pending_"))
    ]


# ---------------------------------------------------------------------------
# Committed world
# ---------------------------------------------------------------------------


@dataclass
class _Target:
    cve_uuid: uuid.UUID
    cve_id: str
    ticket_id: uuid.UUID
    package: str
    maintainer: User
    products: dict[str, uuid.UUID]
    probe: CVEProbe

    @property
    def payload(self) -> CVEIngestPayload:
        return CVEIngestPayload(
            title=TITLE,
            description=DESCRIPTION,
            published_date=PUBLISHED_AT,
            cve_state=CveState.PUBLISHED,
            resolved_packages=[self.package],
        )


@dataclass(frozen=True)
class _Observed:
    """The committed Ticket state after the pipeline."""

    ticket: tuple[str, uuid.UUID | None]
    events: list[EventRow]
    tree: Tree | None
    rows: int
    maintainers: list[tuple[str, uuid.UUID]]
    products: dict[uuid.UUID, tuple[str, str, str]]


@dataclass
class _Pipeline:
    """Committed rows and substitutes of the pipeline test; every operation
    of the test itself runs in its own `asyncio.run()`."""

    factory: async_sessionmaker[AsyncSession]
    redis_url: str
    events: list[str]
    sessions: RecordingSessions
    status: RecordingSessions
    published: Publications
    engine: FakeEngine
    cve_ids: list[uuid.UUID] = field(default_factory=list)
    ticket_ids: list[uuid.UUID] = field(default_factory=list)
    product_ids: list[uuid.UUID] = field(default_factory=list)
    user_ids: list[uuid.UUID] = field(default_factory=list)
    names: list[str] = field(default_factory=list)
    owns_setting: bool = False

    def arrange(self) -> _Target:
        """A committed placeholder CVE with its `Analysis` Ticket, the
        fictional maintainer User, the synchronized catalog, and an enabled
        test-only fetcher of `nvd`."""
        probe = define_cve_fetcher(self.events)
        (package,) = package_names("pipeline")

        async def seed() -> _Target:
            async with self.factory() as session:
                if await session.get(SystemSetting, DEFAULT_SETTING_KEY) is None:
                    session.add(
                        SystemSetting(key=DEFAULT_SETTING_KEY, value=DEFAULT_VERSION)
                    )
                    await session.commit()
                    self.owns_setting = True
                cve = CVE(cve_id=fictional_cve_id())
                session.add(cve)
                await session.flush()
                self.cve_ids.append(cve.id)
                ticket = Ticket(status=ANALYSIS, cve_id=cve.id)
                session.add(ticket)
                await session.flush()
                self.ticket_ids.append(ticket.id)
                user = await seed_user(
                    session, email=MAINTAINER_EMAIL, roles=(Role.RESTRICTED_ANALYST,)
                )
                self.user_ids.append(user.id)
                await session.commit()
                cve_uuid, cve_id, ticket_id = cve.id, cve.cve_id, ticket.id
                session.expunge(user)
                products = await self._synchronize_catalog(session)
            self.names.append(probe.name)
            await seed_fetcher_config(self.factory, probe.name, enabled=True)
            return _Target(cve_uuid, cve_id, ticket_id, package, user, products, probe)

        return asyncio.run(seed())

    async def _synchronize_catalog(self, session: AsyncSession) -> dict[str, uuid.UUID]:
        """Product Sync steps 1-7 over the captured live listing rows,
        served as one valid paginated listing; the snapshot is the current
        one (`SNAPSHOT_AT`). Returns the Product IDs by CPE."""
        rows = [
            row for page in FIXTURE_PAGES for row in load_products_page(page)["results"]
        ]
        cpes = [row["cpe"] for row in rows]
        assert (
            await session.scalars(select(Product.cpe).where(Product.cpe.in_(cpes)))
        ).all() == [], "the catalog CPEs must not be committed yet"
        await session.rollback()
        async with SmeltServer.for_rows(rows).client() as client:
            listing = await fetch_product_listing(
                client, api_url=SMELT_TEST_API_URL, request_delay=0.0
            )
        try:
            await publish_snapshot(session, validate_snapshot(listing), SNAPSHOT_AT)
        finally:
            await session.rollback()
            synchronized: dict[str, uuid.UUID] = dict(
                (
                    await session.execute(
                        select(Product.cpe, Product.id).where(Product.cpe.in_(cpes))
                    )
                ).all()
            )
            self.product_ids.extend(synchronized.values())
            await session.rollback()
        assert len(synchronized) == len(rows)
        return synchronized

    def _redis(self, operation: Callable[[redis_asyncio.Redis], Awaitable[T]]) -> T:
        async def run() -> T:
            client = redis_asyncio.Redis.from_url(self.redis_url, decode_responses=True)
            try:
                return await operation(client)
            finally:
                await client.aclose()

        return asyncio.run(run())

    def marker(self, cve_id: str) -> tuple[str | None, int]:
        """The marker value and its remaining TTL (`-2` when absent)."""

        async def read(client: redis_asyncio.Redis) -> tuple[str | None, int]:
            key = pending_key(cve_id)
            value: str | None = await client.get(key)
            ttl: int = await client.ttl(key)
            return value, ttl

        return self._redis(read)

    def cve_row(self, cve_uuid: uuid.UUID) -> tuple[str, str | None, str | None, Any]:
        async def read() -> tuple[str, str | None, str | None, Any]:
            async with self.factory() as session:
                row = (
                    await session.execute(
                        select(
                            CVE.cve_state,
                            CVE.title,
                            CVE.description,
                            CVE.published_date,
                        ).where(CVE.id == cve_uuid)
                    )
                ).one()
            return row[0], row[1], row[2], row[3]

        return asyncio.run(read())

    def state(self, cve_uuid: uuid.UUID) -> SourceState | None:
        return asyncio.run(source_state(self.factory, cve_uuid))

    def run_count(self, fetcher_name: str) -> int:
        return asyncio.run(fetcher_run_count(self.factory, fetcher_name))

    def observe(self, target: _Target) -> _Observed:
        async def read() -> _Observed:
            async with self.factory() as session:
                observed = _Observed(
                    await ticket_row(session, target.ticket_id),
                    await ticket_events_by_id(session, target.ticket_id),
                    await package_tree(session, target.ticket_id, target.package),
                    len(await tree_rows(session, target.ticket_id)),
                    await maintainers(session, target.ticket_id),
                    {
                        row.id: (row.name, row.version, row.display_name)
                        for row in await session.execute(
                            select(
                                Product.id,
                                Product.name,
                                Product.version,
                                Product.display_name,
                            ).where(Product.cpe.in_(list(CATALOG_PRODUCTS)))
                        )
                    },
                )
                await session.rollback()
            return observed

        return asyncio.run(read())

    def cleanup(self) -> None:
        async def delete_rows() -> None:
            async with self.factory() as session:
                found = (
                    await session.scalars(
                        select(Ticket.id).where(Ticket.cve_id.in_(self.cve_ids))
                    )
                ).all()
                self.ticket_ids.extend(set(found) - set(self.ticket_ids))
                await session.execute(
                    delete(ProductRepository).where(
                        ProductRepository.product_id.in_(self.product_ids)
                    )
                )
                await session.commit()

            async def open_session() -> AsyncSession:
                return self.factory()

            world = CommittedWorld(open_session, self.factory())
            world.cve_ids.extend(self.cve_ids)
            world.ticket_ids.extend(self.ticket_ids)
            world.product_ids.extend(self.product_ids)
            world.user_ids.extend(self.user_ids)
            try:
                await world.cleanup()
                if self.owns_setting:
                    await world.session.execute(
                        delete(SystemSetting).where(
                            SystemSetting.key == DEFAULT_SETTING_KEY
                        )
                    )
                    await world.session.commit()
            finally:
                await world.session.close()
            await delete_fetcher_rows(self.factory, self.names)

        asyncio.run(delete_rows())


@pytest.fixture
def pipeline(
    cli_session_factory: async_sessionmaker[AsyncSession],
    redis_client: redis_asyncio.Redis,
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[_Pipeline]:
    """`redis_client` is used only for its worker-database URL and its
    redirection of the pending-marker boundary; no client object crosses
    event loops."""
    events: list[str] = []
    created = _Pipeline(
        factory=cli_session_factory,
        redis_url=redis_url_from_client(redis_client),
        events=events,
        sessions=RecordingSessions(cli_session_factory, events),
        status=RecordingSessions(cli_session_factory, events, label="status:"),
        published=Publications(events),
        engine=FakeEngine(),
    )
    created.sessions.install(monkeypatch, cve_tasks)
    created.status.install(monkeypatch, base_cve_fetcher)
    monkeypatch.setattr(task_publication, "publish_task", created.published)
    monkeypatch.setattr(cve_tasks, "engine", created.engine)
    install_environment(monkeypatch)
    try:
        yield created
    finally:
        created.cleanup()


def _ingest(probe: CVEProbe, payload: CVEIngestPayload) -> Step:
    """`fetch_single()` composing the real ingestion: `upsert_cve()`, then
    the token carrying the pure post-ingest handoff."""

    async def step(cve_id: str, session: AsyncSession) -> CVEFetchResult:
        result = await cve_service.upsert_cve(
            session, cve_id, probe.fetcher.cve_source_type, payload
        )
        probe.events.append("upsert")
        return CVEFetchResult(
            result.action, cve_service.build_post_ingest_tasks(result, payload)
        )

    return step


# ---------------------------------------------------------------------------
# The pipeline
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_published_fetch_ingests_and_resolves_the_package_tree(
    pipeline: _Pipeline, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = pipeline.arrange()
    probe = target.probe
    probe.step = _ingest(probe, target.payload)

    # 1. Database-free publication: one token marker and one message.
    with capture_logs() as publication_logs:
        dispatch = asyncio.run(
            cve_service.trigger_on_demand_fetch(
                target.cve_id, [(probe.name, NVD, None)]
            )
        )

    assert dispatch == FetchDispatchResult(
        sources_enqueued=[NVD],
        sources_already_pending=[],
        sources_disabled=[],
        sources_failed=[],
    )
    (publication,) = pipeline.published.calls
    token = publication["kwargs"]["token"]
    assert TOKEN_PATTERN.fullmatch(token)
    assert publication == {
        "task_name": TASK,
        "kwargs": {
            "fetcher_name": probe.name,
            "cve_id": target.cve_id,
            "source": NVD,
            "token": token,
        },
        "queue": None,
    }
    value, ttl = pipeline.marker(target.cve_id)
    assert value == token
    assert 0 < ttl <= PENDING_TTL
    assert publication_logs == []
    assert probe.fetched == []

    # 2. The published `fetch_single_cve` commits the ingestion and
    # publishes the package handoff after the commit.
    fetch_task = FakeTask()
    with capture_logs() as fetch_logs:
        cve_tasks._fetch_single_cve_sync(
            fetch_task, **_delivered(publication["kwargs"])
        )

    fetch_task.retry.assert_not_called()
    assert probe.fetched == [target.cve_id]
    assert len(pipeline.sessions.opened) == 1
    assert pipeline.status.opened == []
    assert pipeline.events[pipeline.events.index("upsert") :] == [
        "upsert",
        "flush",
        "commit_and_dispatch",
        "commit",
        f"publish:{RESOLVE}",
    ]
    pipeline.engine.dispose.assert_awaited_once_with()
    assert _on_demand_logs(fetch_logs) == [
        {
            "event": FETCH_COMPLETED,
            "log_level": "info",
            "outcome": "updated",
            "fetcher_name": probe.name,
            "cve_id": target.cve_id,
            "source": NVD,
        }
    ]
    assert pipeline.cve_row(target.cve_uuid) == (
        CveState.PUBLISHED.value,
        TITLE,
        DESCRIPTION,
        PUBLISHED_AT,
    )
    state = pipeline.state(target.cve_uuid)
    assert state is not None
    assert state.status == CVESourceFetchStatus.SUCCESS
    assert pipeline.marker(target.cve_id) == (None, -2)
    assert pipeline.run_count(probe.name) == 0
    assert [call["task_name"] for call in pipeline.published.calls] == [
        TASK,
        RESOLVE,
    ]
    handoff = pipeline.published.calls[1]
    assert handoff == {
        "task_name": RESOLVE,
        "kwargs": {
            "ticket_id": str(target.ticket_id),
            "cpe_matches": [],
            "affected_cpes": [],
            "vendor_products": [],
            "resolved_packages": [target.package],
        },
    }

    # 3. The published `resolve_ticket_packages` creates the package tree
    # from the SMELT fixtures and the synchronized catalog.
    smelt = Smelt(
        {
            target.package: Answer(
                reply(200, load_maintained_fixture(MAINTAINED_FIXTURE)),
                reply(200, load_maintainership_fixture(MAINTAINERSHIP_FIXTURE)),
            )
        }
    )
    clients = smelt.install(monkeypatch)
    with capture_logs() as resolve_logs:
        cve_tasks._resolve_ticket_packages_sync(**_delivered(handoff["kwargs"]))

    assert clients == [CLIENT_NAME]
    assert smelt.requests == both(target.package)
    assert smelt.closed() == [True]
    assert len(pipeline.sessions.opened) == 2
    assert pipeline.engine.dispose.await_count == 2
    assert workflow_logs(resolve_logs) == [
        completed(target.ticket_id, 1, package_tree_changed=1)
    ]
    # The new-IBS-track catch-up (add_package_to_ticket() step 9) is not
    # implemented yet, and a package unit registers no convergence effect.
    assert len(pipeline.published.calls) == 2

    ltss = target.products[SLES_LTSS_12_SP5]
    ltss_extended = target.products[SLES_LTSS_ES_12_SP5]
    package_hub = target.products[PACKAGE_HUB_15_SP7]
    observed = pipeline.observe(target)
    assert observed.tree == Tree(
        None,
        {
            SLE_12_UPDATE: NEW_TRACK[WorkflowType.IBS],
            SLE_15_UPDATE: NEW_TRACK[WorkflowType.IBS],
        },
        {
            (SLE_12_UPDATE, ltss): new_occurrence(True),
            (SLE_12_UPDATE, ltss_extended): new_occurrence(True),
            (SLE_15_UPDATE, package_hub): new_occurrence(True),
        },
    )
    # One package, two tracks, three Product occurrences, nothing else.
    assert observed.rows == 6
    assert observed.products == {
        target.products[cpe]: product for cpe, product in CATALOG_PRODUCTS.items()
    }
    assert observed.maintainers == [(target.package, target.maintainer.id)]
    assert observed.ticket == (ANALYSIS, None)
    assert observed.events == [
        maintainer_event(target.package, target.maintainer),
        added(target.package),
    ]
