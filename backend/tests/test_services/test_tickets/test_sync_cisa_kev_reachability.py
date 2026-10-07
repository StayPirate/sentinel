"""Registration, capability, production reachability, and the KEV
source-status projection of the real `SyncCisaKev` class
(backend/app/services/tickets/sync_cisa_kev.py).

Owning specifications:

- docs/features/tickets/cve-sync-kev.md (Conventions, the isolated-status
  deviation; Class Structure; Fetcher Definition; Behavioral Notes, Data
  lifecycle).
- docs/features/platform/cve-fetcher-infrastructure.md (Class Attributes;
  `__init_subclass__` Validation; On-demand Single-Item Fetch, the catalog
  opt-out; CVE Source Type Identity, both registry accessors; Default
  catch_up Implementation).
- docs/features/platform/fetcher-infrastructure.md (Naming Convention, Class
  Name Derivation; Per-Ticket Catch-Up, Registry accessor
  `get_catch_up_fetchers()` and Fetchers that do NOT need `catch_up()`;
  Fetcher Discovery; Data Model, FetcherConfig bootstrap; Celery Beat
  Schedule Synchronization, Redbeat Entry Structure and Startup
  Reconciliation).
- docs/features/packages/package-service.md (`run_ticket_convergence()`
  workflow step 4, the catch-up roster).
- docs/features/tickets/cve-service.md (CVE Source Status: Status values,
  Resolution algorithm, KEV status derivation).
- docs/features/platform/testing-strategy.md (CVE Fetcher Infrastructure,
  Concrete compliance, KEV clause; CVE and Source Reads, KEV projection;
  Parallel Execution).

The production class is resolved from the registries filled by fetcher
discovery; no test-only fetcher is defined, so no registry isolation is
needed. The HTTP refetch and create/associate freshness outcomes with the
production registry are e2e classes of `tests/test_api/test_cve_refetch.py`
and `tests/test_api/test_ticket_freshness_refresh.py`, and the `kev` entry
of `GET /api/v1/cves/{cve_id}/sources` one of
`tests/test_api/test_cve_source_status.py`, which own those harnesses.

Bootstrap and reconciliation run on `db_session`, rolled back at teardown,
and the worker Redis database. The convergence roster reads a missing
Ticket and writes nothing.

The KEV projection tests run the real `SyncCisaKev.run()` over the
in-process `KevServer`, obtained through the lazily created HTTP client,
and commit real rows: CVEs with Tickets of an `IngestionWorld` (deleted at
teardown with their children), and the `sync_cisa_kev` `FetcherConfig` and
`FetcherRun` rows (deleted at teardown). The KEV status derivation reads the
latest successful `sync_cisa_kev` run globally, so these tests own every
committed row under that name while they run:

- each pytest-xdist worker uses its own PostgreSQL database and runs one
  test at a time (testing-strategy.md, Parallel Execution), so no other
  worker can commit or observe a run in this database;
- inside a worker, no other test leaves a committed `sync_cisa_kev` row:
  the periodic-run tests of `test_sync_cisa_kev_execute.py` use test-only
  fetcher names, the source-status tests flush their KEV runs inside the
  rolled-back `db_session` transaction, the lifespan bootstrap test empties
  the registry, and the system suite prunes it to its own fetcher;
- the `projection` fixture asserts that no committed `sync_cisa_kev`
  configuration or run exists before it seeds its own, so a leak fails
  loudly instead of silently turning `not_attempted` into `missing`.

The isolated status session factory fails the test on use (the documented
deviation), and the broker call is the recorded
`task_publication.publish_task`. All identifiers are fictional.
"""

from __future__ import annotations

import ast
import enum
import inspect
import textwrap
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, date, datetime
from types import ModuleType
from typing import Any, Final, cast

import httpx
import pytest
import redis.asyncio as redis_asyncio
from celery import Celery
from celery.app.task import Task
from redbeat import RedBeatSchedulerEntry
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase

import app.services.base_cve_fetcher as base_cve_fetcher_module
import app.services.base_fetcher as base_fetcher_module
import app.services.fetcher_discovery  # noqa: F401
from app.core.enums import CVESourceDerivedStatus, CVESourceType, Scope
from app.models.cve import CVE
from app.models.cve_cwe import CVECWE
from app.models.cve_kev_entry import CVEKEVEntry
from app.models.cve_source import CVESource
from app.models.fetcher_config import FetcherConfig
from app.models.fetcher_run import FetcherRun
from app.models.ticket import Ticket
from app.models.ticket_audit_event import TicketAuditEvent
from app.models.ticket_reference import TicketReference
from app.services import cve_service, task_publication
from app.services.base_cve_fetcher import (
    _CVE_SOURCE_TYPE_MAP,
    BaseCVEFetcher,
    get_all_cve_source_types,
    get_fetch_single_fetchers,
)
from app.services.base_fetcher import (
    FETCHER_REGISTRY,
    BaseFetcher,
    FetcherRunConfig,
    get_catch_up_fetchers,
)
from app.services.cve_service import CVESourceStatusEntry
from app.services.fetcher_bootstrap import bootstrap_fetcher_configs
from app.services.fetcher_schedule import reconcile_beat_schedule
from app.services.package_service import run_ticket_convergence
from app.services.ticket_visibility import TicketCaller
from app.services.tickets import cisa_kev_catalog
from app.services.tickets import sync_cisa_kev as sync_module
from app.services.tickets.sync_cisa_kev import SyncCisaKev
from tests.support.cisa_kev import KevServer, catalog_of, entry_for
from tests.support.cve_catch_up import (
    Publications,
    delete_fetcher_rows,
    seed_fetcher_config,
)
from tests.support.cve_ingest import IngestionWorld

SessionFactory = Callable[[], Awaitable[AsyncSession]]

NAME: Final = "sync_cisa_kev"
KEV: Final = CVESourceType.KEV
SCHEDULE: Final = "0 4,10,18,22 * * *"
REFERENCE_URL_PATTERN: Final = (
    "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve={cve_id}"
)
RUN_CATCH_UP: Final = "run_catch_up"
ALL_SCOPE: Final = TicketCaller.authenticated(uuid.uuid4(), Scope.ALL)
"""A caller that sees every CVE, so accessibility never decides a read."""

SUCCESS: Final = CVESourceDerivedStatus.SUCCESS
MISSING: Final = CVESourceDerivedStatus.MISSING
NOT_ATTEMPTED: Final = CVESourceDerivedStatus.NOT_ATTEMPTED

_RUN_CONFIG: Final = FetcherRunConfig(
    hard_time_limit_seconds=3600, request_delay=0, custom_settings={}
)


def _class_body_assignments(cls: type) -> set[str]:
    """The names assigned in `cls`'s own class body (static, from source)."""
    tree = ast.parse(textwrap.dedent(inspect.getsource(cls)))
    [class_def] = tree.body
    assert isinstance(class_def, ast.ClassDef)
    names: set[str] = set()
    for node in class_def.body:
        if isinstance(node, ast.Assign):
            names.update(t.id for t in node.targets if isinstance(t, ast.Name))
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            names.add(node.target.id)
        elif isinstance(node, ast.ClassDef):
            names.add(node.name)
    return names


# ---------------------------------------------------------------------------
# Registration and capability
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestRegistrationAndCapability:
    def test_properties_match_the_specification(self) -> None:
        assert SyncCisaKev.name == NAME
        assert SyncCisaKev.name == cve_service.KEV_FETCHER_NAME
        assert SyncCisaKev.cve_source_type is KEV
        assert SyncCisaKev.cve_source_type.value == "kev"
        assert SyncCisaKev.description == (
            "Sync Known Exploited Vulnerabilities from CISA KEV catalog"
        )
        assert SyncCisaKev.default_schedule == SCHEDULE
        assert SyncCisaKev.source_reference_url_pattern == REFERENCE_URL_PATTERN

    def test_class_body_declares_exactly_the_class_structure_attributes(
        self,
    ) -> None:
        """No `Settings`, `queue`, `default_request_delay`,
        `http_client_options`, or `participates_in_catch_up` in the class
        body (cve-sync-kev.md, Class Structure; Custom settings: None)."""
        assert _class_body_assignments(SyncCisaKev) == {
            "name",
            "cve_source_type",
            "description",
            "default_schedule",
            "supports_fetch_single",
            "source_reference_url_pattern",
        }

    def test_inherited_defaults_apply(self) -> None:
        assert SyncCisaKev.Settings is None
        assert SyncCisaKev.queue is None
        assert SyncCisaKev.default_request_delay == BaseFetcher.default_request_delay
        assert SyncCisaKev.default_request_delay == 0
        assert SyncCisaKev.http_client_options == {}
        assert SyncCisaKev.http_client_options is BaseFetcher.http_client_options
        for inherited in (
            "Settings",
            "queue",
            "default_request_delay",
            "http_client_options",
        ):
            assert inherited not in SyncCisaKev.__dict__, inherited

    def test_capability_flags_opt_out_and_derive_no_catch_up(self) -> None:
        assert SyncCisaKev.supports_fetch_single is False
        # Derived by BaseCVEFetcher.__init_subclass__, never declared.
        assert SyncCisaKev.participates_in_catch_up is False
        assert "participates_in_catch_up" not in _class_body_assignments(SyncCisaKev)
        assert "abstract" not in SyncCisaKev.__dict__

    def test_class_name_is_derived_from_the_fetcher_name(self) -> None:
        derived = "".join(part.capitalize() for part in NAME.split("_"))

        assert derived == SyncCisaKev.__name__ == "SyncCisaKev"

    def test_fetch_single_and_catch_up_are_the_inherited_base_methods(
        self,
    ) -> None:
        assert "fetch_single" not in SyncCisaKev.__dict__
        assert SyncCisaKev.fetch_single is BaseCVEFetcher.fetch_single
        assert "catch_up" not in SyncCisaKev.__dict__
        assert SyncCisaKev.catch_up is BaseCVEFetcher.catch_up
        assert "execute" in SyncCisaKev.__dict__
        assert inspect.iscoroutinefunction(SyncCisaKev.execute)

    async def test_fetch_single_raises_the_base_safety_net(self) -> None:
        fetcher = SyncCisaKev()

        with pytest.raises(RuntimeError) as raised:
            await fetcher.fetch_single("CVE-2099-0001", cast(AsyncSession, None))

        assert str(raised.value) == (
            "fetch_single() called on a fetcher that does not support it"
        )
        # Raised before any I/O: no HTTP client was created.
        assert fetcher._http_client is None

    def test_registered_in_both_registries(self) -> None:
        assert FETCHER_REGISTRY[NAME] is SyncCisaKev
        assert _CVE_SOURCE_TYPE_MAP[KEV] is SyncCisaKev
        assert get_all_cve_source_types()["kev"] is SyncCisaKev

    def test_absent_from_the_fetch_single_and_catch_up_rosters(self) -> None:
        fetch_single = get_fetch_single_fetchers()
        catch_up = get_catch_up_fetchers()

        assert "kev" not in fetch_single
        assert SyncCisaKev not in fetch_single.values()
        assert NAME not in catch_up
        assert SyncCisaKev not in catch_up.values()


# ---------------------------------------------------------------------------
# Structural absences
# ---------------------------------------------------------------------------


def _referenced_names(module: ModuleType) -> set[str]:
    """Every identifier and attribute name the module's code references."""
    tree = ast.parse(inspect.getsource(module))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            names.add(node.id)
        elif isinstance(node, ast.Attribute):
            names.add(node.attr)
        elif isinstance(node, ast.alias):
            names.add(node.name)
    return names


def _imported_modules(module: ModuleType) -> set[str]:
    tree = ast.parse(inspect.getsource(module))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            imported.add(node.module)
    return imported


_KEV_MODULES: Final = [sync_module, cisa_kev_catalog]


@pytest.mark.unit
class TestStructuralAbsences:
    def test_fetcher_never_uses_the_active_ticket_scope_or_isolated_status(
        self,
    ) -> None:
        """KEV is global in scope and omits the isolated status write
        (cve-sync-kev.md, Conventions)."""
        names = _referenced_names(sync_module)

        assert "get_active_ticket_cve_ids" not in names
        assert "_isolated_status_commit" not in names
        assert "record_source_status" not in names

    @pytest.mark.parametrize("module", _KEV_MODULES, ids=lambda module: module.__name__)
    def test_defines_no_task_model_or_enum(self, module: ModuleType) -> None:
        own = [
            value
            for value in vars(module).values()
            if getattr(value, "__module__", None) == module.__name__
        ]

        assert not [value for value in vars(module).values() if isinstance(value, Task)]
        assert not [
            value
            for value in own
            if isinstance(value, type)
            and issubclass(value, (DeclarativeBase, enum.Enum))
        ]

    @pytest.mark.parametrize("module", _KEV_MODULES, ids=lambda module: module.__name__)
    def test_reads_no_setting_and_touches_no_redis_task_or_api_layer(
        self, module: ModuleType
    ) -> None:
        imported = _imported_modules(module)

        forbidden = {
            name
            for name in imported
            if name in {"app.config", "app.celery_app"}
            or name.split(".")[0] == "redis"
            or name.startswith(("app.tasks", "app.api"))
        }
        assert forbidden == set()


# ---------------------------------------------------------------------------
# Configuration bootstrap and the RedBeat entry
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestBootstrapAndSchedule:
    async def test_bootstrap_creates_the_configuration_from_the_class(
        self, db_session: AsyncSession
    ) -> None:
        assert await db_session.get(FetcherConfig, NAME) is None

        await bootstrap_fetcher_configs(db_session)

        config = await db_session.get(FetcherConfig, NAME)
        assert config is not None
        assert config.enabled is True
        assert config.schedule_override is None
        assert config.request_delay == SyncCisaKev.default_request_delay == 0
        assert config.custom_settings == {}

    async def test_reconciliation_writes_the_entry_from_the_class(
        self, db_session: AsyncSession, celery_test_app: Celery
    ) -> None:
        await bootstrap_fetcher_configs(db_session)

        await reconcile_beat_schedule(db_session, celery_test_app)

        key = RedBeatSchedulerEntry.generate_key(celery_test_app, NAME)
        entry = RedBeatSchedulerEntry.from_key(key, app=celery_test_app)
        assert entry.task == "run_fetcher"
        assert entry.kwargs == {"fetcher_name": NAME, "triggered_by": "schedule"}
        # 0 4,10,18,22 * * *
        assert entry.schedule.minute == {0}
        assert entry.schedule.hour == {4, 10, 18, 22}
        assert entry.schedule.day_of_month == set(range(1, 32))
        assert entry.schedule.month_of_year == set(range(1, 13))
        assert entry.schedule.day_of_week == set(range(7))
        assert "queue" not in entry.options


# ---------------------------------------------------------------------------
# Ticket convergence: the production catch-up roster
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestTicketConvergenceRoster:
    async def test_convergence_publishes_no_catch_up_for_kev(
        self,
        real_session_factory: async_sessionmaker[AsyncSession],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A Ticket without package markers (here a missing one) still
        publishes the complete production roster: one `run_catch_up` per
        participating fetcher, never `sync_cisa_kev` (fetcher-infrastructure.md,
        Fetchers that do NOT need `catch_up()`)."""
        published = Publications()
        monkeypatch.setattr(task_publication, "publish_task", published)
        roster = sorted(get_catch_up_fetchers().items())
        assert roster, "no production catch-up participant is registered"
        ticket_id = uuid.uuid7()

        await run_ticket_convergence(
            ticket_id=ticket_id, session_factory=real_session_factory
        )

        assert published.calls == [
            {
                "task_name": RUN_CATCH_UP,
                "kwargs": {"fetcher_name": name, "ticket_id": str(ticket_id)},
                "queue": fetcher_cls.queue,
            }
            for name, fetcher_cls in roster
        ]
        published_names = [
            call["fetcher_name"] for call in published.published(RUN_CATCH_UP)
        ]
        assert NAME not in published_names


# ---------------------------------------------------------------------------
# KEV projection with the dedicated writer
# ---------------------------------------------------------------------------


@dataclass
class Projection:
    """Committed CVEs, the committed `sync_cisa_kev` configuration, real
    `run()` invocations under that name, and the status read."""

    world: IngestionWorld
    factory: async_sessionmaker[AsyncSession]
    server: KevServer
    published: Publications

    async def cve(self) -> CVE:
        """A committed CVE with an `Analysis` Ticket and no KEV evidence."""
        cve = await self.world.cve_in()
        await self.world.ticket(cve_id=cve.id)
        return cve

    async def cve_named(self, cve_id: str) -> CVE:
        """Like `cve()`, under a CVE-ID from `world.new_cve_id()`."""
        cve = CVE(cve_id=cve_id)
        self.world.session.add(cve)
        await self.world.session.flush()
        self.world.cve_ids.append(cve.id)
        await self.world.session.commit()
        await self.world.ticket(cve_id=cve.id)
        return cve

    async def created_at(self, cve: CVE) -> datetime:
        async with self.factory() as session:
            value: datetime = (
                await session.execute(select(CVE.created_at).where(CVE.id == cve.id))
            ).scalar_one()
        return value

    def serve(self, *entries: dict[str, Any]) -> None:
        self.server.catalog = catalog_of(*entries)

    async def run(self) -> FetcherRun:
        """One complete `run()` of the production class on a committed
        `running` run, as the atomic acquisition leaves it; returns the
        finalized run."""
        async with self.factory() as session:
            run = FetcherRun(
                fetcher_name=NAME,
                started_at=datetime.now(UTC),
                status="running",
                triggered_by="schedule",
            )
            session.add(run)
            await session.commit()
            run_id = run.id
        await SyncCisaKev().run(run_id=run_id, config=_RUN_CONFIG)
        async with self.factory() as session:
            finalized = await session.get(FetcherRun, run_id)
        assert finalized is not None
        return finalized

    async def status(self, cve: CVE) -> CVESourceStatusEntry:
        result = await cve_service.get_cve_source_status(
            cve.cve_id, ALL_SCOPE, session_factory=self.factory
        )
        [kev] = [entry for entry in result.entries if entry.source == KEV.value]
        return kev

    async def kev_updated_at(self, cve: CVE) -> datetime:
        async with self.factory() as session:
            value: datetime = (
                await session.execute(
                    select(CVEKEVEntry.updated_at).where(CVEKEVEntry.cve_id == cve.id)
                )
            ).scalar_one()
        return value

    async def snapshot(self, cve: CVE) -> tuple[Any, ...]:
        """Every KEV-relevant persisted row of `cve`, identities and
        timestamps included, for a no-write proof."""
        async with self.factory() as session:
            cve_row = (
                await session.execute(select(CVE.updated_at).where(CVE.id == cve.id))
            ).one()
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
            sources = await session.execute(
                select(
                    CVESource.source,
                    CVESource.status,
                    CVESource.fetched_at,
                    CVESource.first_failed_at,
                ).where(CVESource.cve_id == cve.id)
            )
            tickets = await session.execute(
                select(Ticket.id, Ticket.priority_auto, Ticket.updated_at).where(
                    Ticket.cve_id == cve.id
                )
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
            events = await session.scalar(
                select(func.count())
                .select_from(TicketAuditEvent)
                .join(Ticket, TicketAuditEvent.ticket_id == Ticket.id)
                .where(Ticket.cve_id == cve.id)
            )
            return (
                tuple(cve_row),
                None if kev is None else tuple(kev),
                sorted(tuple(row) for row in cwes),
                sorted(tuple(row) for row in sources),
                sorted(tuple(row) for row in tickets),
                sorted(tuple(row) for row in references),
                events,
            )


async def _committed_kev_rows(factory: async_sessionmaker[AsyncSession]) -> int:
    async with factory() as session:
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


@pytest.fixture
async def projection(
    db_session_factory: SessionFactory,
    real_session_factory: async_sessionmaker[AsyncSession],
    redis_client: redis_asyncio.Redis,
    monkeypatch: pytest.MonkeyPatch,
) -> AsyncIterator[Projection]:
    """`redis_client` points the pending overlay of the status read at the
    worker's Redis database."""
    # The latest-run read is global: no other committed sync_cisa_kev row
    # may exist (see the module docstring).
    assert await _committed_kev_rows(real_session_factory) == 0
    created = Projection(
        world=IngestionWorld(db_session_factory, await db_session_factory()),
        factory=real_session_factory,
        server=KevServer(catalog_of()),
        published=Publications(),
    )

    def create_http_client(name: str, **options: Any) -> httpx.AsyncClient:
        # The lazy client of the production class: no option override.
        assert name == NAME
        assert options == {}
        return created.server.client()

    def isolated_status_session() -> AsyncSession:
        raise AssertionError("KEV writes no isolated source status")

    monkeypatch.setattr(base_fetcher_module, "create_http_client", create_http_client)
    monkeypatch.setattr(
        base_fetcher_module, "async_session_factory", real_session_factory
    )
    monkeypatch.setattr(
        base_cve_fetcher_module, "async_session_factory", isolated_status_session
    )
    monkeypatch.setattr(task_publication, "publish_task", created.published)
    try:
        await seed_fetcher_config(real_session_factory, NAME, enabled=True)
        yield created
    finally:
        try:
            await created.world.cleanup()
        finally:
            await delete_fetcher_rows(real_session_factory, [NAME])
            assert await _committed_kev_rows(real_session_factory) == 0


def _outcome(run: FetcherRun) -> tuple[str, int, int, int, int]:
    return (
        run.status,
        run.items_succeeded,
        run.items_created,
        run.items_updated,
        run.items_failed,
    )


def _kev_entry(
    status: CVESourceDerivedStatus, fetched_at: datetime | None
) -> CVESourceStatusEntry:
    """The expected `kev` entry of the registered, enabled production class."""
    return CVESourceStatusEntry(
        source="kev",
        status=status,
        fetched_at=fetched_at,
        first_failed_at=None,
        registered=True,
        refetchable=False,
        enabled=True,
    )


@pytest.mark.integration
class TestKevProjection:
    async def test_successful_run_yields_success_for_listed_and_missing_for_unlisted(
        self, projection: Projection
    ) -> None:
        listed = await projection.cve()
        unlisted = await projection.cve()
        assert await projection.status(listed) == _kev_entry(NOT_ATTEMPTED, None)
        assert await projection.status(unlisted) == _kev_entry(NOT_ATTEMPTED, None)
        projection.serve(entry_for(listed.cve_id, cwes=["CWE-79"]))

        run = await projection.run()

        assert _outcome(run) == ("success", 1, 0, 1, 0)
        assert run.finished_at is not None
        # The entry written by the dedicated fetcher is the evidence.
        assert await projection.status(listed) == _kev_entry(
            SUCCESS, await projection.kev_updated_at(listed)
        )
        # The fully successful run postdates the CVE and did not list it.
        assert await projection.status(unlisted) == _kev_entry(MISSING, run.finished_at)

    async def test_cve_created_after_its_entry_was_examined_is_not_missing(
        self, projection: Projection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A listed CVE ingested mid-run, after the run looked up and
        skipped its entry, is not proven absent although the fully
        successful run finished after the CVE existed; the next run
        records its evidence. A CVE that existed when the run started
        still turns `missing`."""
        unlisted = await projection.cve()
        late_id = projection.world.new_cve_id()
        projection.serve(entry_for(late_id))
        real_cve_exists = SyncCisaKev._cve_exists
        created: list[CVE] = []

        async def cve_exists(
            fetcher: SyncCisaKev, session: AsyncSession, cve_id: str
        ) -> bool:
            exists = await real_cve_exists(fetcher, session, cve_id)
            if cve_id == late_id and not created:
                assert not exists
                created.append(await projection.cve_named(late_id))
            return exists

        monkeypatch.setattr(SyncCisaKev, "_cve_exists", cve_exists)

        run = await projection.run()

        # The skipped entry counts neither success nor failure.
        assert _outcome(run) == ("success", 0, 0, 0, 0)
        [late] = created
        assert run.started_at is not None
        assert run.finished_at is not None
        assert await projection.created_at(unlisted) <= run.started_at
        assert run.started_at < await projection.created_at(late) < run.finished_at
        assert await projection.status(late) == _kev_entry(NOT_ATTEMPTED, None)
        assert await projection.status(unlisted) == _kev_entry(MISSING, run.finished_at)

        second = await projection.run()

        assert _outcome(second) == ("success", 1, 0, 1, 0)
        assert await projection.status(late) == _kev_entry(
            SUCCESS, await projection.kev_updated_at(late)
        )

    async def test_partial_run_never_proves_absence(
        self, projection: Projection
    ) -> None:
        listed = await projection.cve()
        failing = await projection.cve()
        unlisted = await projection.cve()
        projection.serve(
            entry_for(listed.cve_id),
            entry_for(failing.cve_id, date_added="2026-02-30"),
        )

        run = await projection.run()

        assert _outcome(run) == ("partial", 1, 0, 1, 1)
        assert await projection.status(unlisted) == _kev_entry(NOT_ATTEMPTED, None)
        assert await projection.status(failing) == _kev_entry(NOT_ATTEMPTED, None)
        assert await projection.status(listed) == _kev_entry(
            SUCCESS, await projection.kev_updated_at(listed)
        )

    async def test_entry_removed_from_the_catalog_is_retained_without_writes(
        self, projection: Projection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        retained = await projection.cve()
        kept = await projection.cve()
        projection.serve(
            entry_for(retained.cve_id, date_added="2026-09-08", cwes=["CWE-59"]),
            entry_for(kept.cve_id),
        )
        first = await projection.run()
        assert _outcome(first) == ("success", 2, 0, 2, 0)
        retained_updated_at = await projection.kev_updated_at(retained)
        before = await projection.snapshot(retained)
        publications = len(projection.published.calls)
        upserted: list[str] = []
        real_upsert = cve_service.upsert_cve

        async def upsert_cve(
            session: AsyncSession, cve_id: str, source: Any, payload: Any
        ) -> Any:
            upserted.append(cve_id)
            return await real_upsert(session, cve_id, source, payload)

        monkeypatch.setattr(cve_service, "upsert_cve", upsert_cve)
        # CISA removed the retained CVE; the kept entry is unchanged.
        projection.serve(entry_for(kept.cve_id))

        second = await projection.run()

        assert _outcome(second) == ("success", 1, 0, 0, 0)
        assert upserted == [kept.cve_id]
        assert len(projection.published.calls) == publications
        # The KEV entry and its CWE rows persist as historical enrichment,
        # untouched (cve-sync-kev.md, Behavioral Notes, Data lifecycle).
        after = await projection.snapshot(retained)
        assert after == before
        assert after[1][1:3] == (
            date(2026, 9, 8),
            REFERENCE_URL_PATTERN.format(cve_id=retained.cve_id),
        )
        assert [(row[1], row[2]) for row in after[2]] == [("CWE-59", "CISA KEV")]
        assert second.finished_at is not None
        assert second.finished_at > retained_updated_at
        assert await projection.status(retained) == _kev_entry(
            SUCCESS, retained_updated_at
        )
