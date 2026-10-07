"""Registration, concrete compliance, structural absences, and production
reachability of the real `SyncOsvAdvisories` class
(backend/app/services/tickets/sync_osv_advisories.py): the on-demand
`fetch_single_cve` workflow, the default catch-up through `run_catch_up`,
the bootstrapped `FetcherConfig`, and the RedBeat schedule entry.

Owning specifications:

- docs/features/tickets/cve-sync-osv.md (Fetcher Definition; `fetch_single`
  Method, class structure, on-demand enrichment and catch-up for free;
  Algorithm steps 5, 6, and 13; Error Handling, `fetch_single()` table; Custom
  Settings, Operational notes; `CompletenessGuardError`).
- docs/features/platform/cve-fetcher-infrastructure.md (Class Attributes;
  `__init_subclass__` Validation; Non-Modification Statement; `fetch_single`
  Signaling Convention; Retry Policy for `fetch_single`; Error
  Categorization; CVE Source Type Identity, both registry accessors; Default
  catch_up Implementation).
- docs/features/tickets/cve-service.md (On-Demand Fetch: fetch_single_cve).
- docs/features/platform/fetcher-infrastructure.md (Naming Convention, Class
  Name Derivation; Fetcher Discovery, Domain Placement; Per-Ticket Catch-Up:
  Celery task wrapper and Registry accessor `get_catch_up_fetchers()`;
  BaseFetcher HTTP Client Integration, HTTP Client Ownership Rule; Data
  Model, FetcherConfig bootstrap, the `default_request_delay` seed and the
  `run_timeout` column default; Celery Beat Schedule Synchronization,
  Redbeat Entry Structure and Time Limits).
- docs/features/platform/testing-strategy.md (CVE Fetcher Infrastructure,
  Default catch-up and Concrete compliance; On-Demand CVE Refetch).

The workflows run against real PostgreSQL with the harnesses of
`tests/support/fetch_single_cve.py` and `tests/support/cve_catch_up.py`
(recording session factories over `real_session_factory`, a recorded
`task_publication.publish_task`, and the real convergence drain). The
production class is resolved from the registries filled by fetcher
discovery; no test-only fetcher is defined, so no registry isolation is
needed. Every HTTP client the fetcher creates is the in-process `OsvServer`,
and the step-13 throttle is recorded instead of slept. The committed
`sync_osv_advisories` `FetcherConfig` row, CVEs, Tickets, and their children
(including `cve_affected_version`, `cve_external_identifier`, and
`cve_source`) are deleted at teardown; alias IDs carry no whitelisted
prefix, so no global external identifier is committed. Bootstrap and
reconciliation run on `db_session`, rolled back at teardown, and the worker
Redis database. All identifiers are fictional.

The generic task terminal matrix is owned by
`test_fetch_single_cve_workflow.py` and `test_cve_fetcher_catch_up.py`, and
OSV exception classification by `test_sync_osv_advisories.py`; the retry
and failure cases here only prove that the OSV outcomes reach those paths.
"""

from __future__ import annotations

import ast
import enum
import inspect
import textwrap
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass, field
from types import ModuleType, SimpleNamespace
from typing import Any, Final

import httpx
import pytest
import redis.asyncio as redis_asyncio
from celery import Celery
from celery.app.task import Task
from pydantic import ValidationError
from redbeat import RedBeatSchedulerEntry
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase
from structlog.testing import capture_logs

import app.services.base_fetcher as base_fetcher_module
import app.services.fetcher_discovery  # noqa: F401
from app.core.enums import CVESourceFetchStatus, CVESourceType
from app.models.cve import CVE
from app.models.cve_affected_version import CVEAffectedVersion
from app.models.fetcher_config import FetcherConfig
from app.models.ticket import Ticket
from app.services.base_cve_fetcher import (
    _CVE_SOURCE_TYPE_MAP,
    BaseCVEFetcher,
    CVEFetchResult,
    get_all_cve_source_types,
    get_fetch_single_fetchers,
)
from app.services.base_fetcher import (
    FETCHER_REGISTRY,
    BaseFetcher,
    FetcherError,
    get_catch_up_fetchers,
)
from app.services.cve_service import FetchSingleRetry
from app.services.fetcher_bootstrap import bootstrap_fetcher_configs
from app.services.fetcher_schedule import reconcile_beat_schedule
from app.services.http_client import is_infrastructure_failure, is_retryable_condition
from app.services.tickets import osv_vulnerability_record
from app.services.tickets import sync_osv_advisories as sync_module
from app.services.tickets.sync_osv_advisories import (
    CompletenessGuardError,
    OsvResponseError,
    SyncOsvAdvisories,
)
from app.tasks import fetchers
from tests.support.cve_catch_up import (
    RESOLVE,
    CatchUpHarness,
    fetcher_run_count,
    install_harness,
    seed_fetcher_config,
    source_state,
)
from tests.support.cve_ingest import IngestionWorld
from tests.support.fetch_single_cve import (
    COMPLETED,
    FAILED,
    RETRY_SCHEDULED,
    FetchSingleHarness,
    events_named,
    install_fetch_single_harness,
)
from tests.support.osv import OsvServer, status

SessionFactory = Callable[[], Awaitable[AsyncSession]]

NAME: Final = "sync_osv_advisories"
OSV: Final = CVESourceType.OSV
SCHEDULE: Final = "0 5 * * *"
LAST_ATTEMPT: Final = 3
"""The zero-based attempt index after which no retry remains (3 retries)."""

ALIAS: Final = "EXAMPLE-ALIAS-2099-0001"
FAILING: Final = "EXAMPLE-ALIAS-2099-0503"
NOT_APPLICABLE: Final = "EXAMPLE-ALIAS-2099-0002"
"""An alias record that names another CVE: observed, contributes nothing."""
OTHER_CVE: Final = "CVE-2099-990000001"
RELATED: Final = "EXAMPLE-SA-2099-0001"
REPO: Final = "https://git.example.invalid/project/example"


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
# Registration, capability, and concrete compliance
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestRegistrationAndCapability:
    def test_properties_match_the_specification(self) -> None:
        assert SyncOsvAdvisories.name == NAME
        assert SyncOsvAdvisories.cve_source_type is OSV
        assert SyncOsvAdvisories.cve_source_type.value == "osv"
        assert SyncOsvAdvisories.description == (
            "Sync CVE enrichment data from OSV (osv.dev)"
        )
        assert SyncOsvAdvisories.default_schedule == SCHEDULE
        assert SyncOsvAdvisories.default_request_delay == 0.2
        assert SyncOsvAdvisories.source_reference_url_pattern == (
            "https://osv.dev/vulnerability/{cve_id}"
        )

    def test_class_body_declares_exactly_the_class_structure_attributes(
        self,
    ) -> None:
        """No `Settings`, `queue`, `http_client_options`,
        `supports_fetch_single`, or `participates_in_catch_up` in the class
        body (cve-sync-osv.md, `fetch_single` Method, class structure;
        Custom Settings: none)."""
        assert _class_body_assignments(SyncOsvAdvisories) == {
            "name",
            "cve_source_type",
            "description",
            "default_schedule",
            "default_request_delay",
            "source_reference_url_pattern",
        }

    def test_inherited_defaults_apply(self) -> None:
        assert SyncOsvAdvisories.Settings is None
        assert SyncOsvAdvisories.queue is None
        assert SyncOsvAdvisories.http_client_options == {}
        assert SyncOsvAdvisories.http_client_options is BaseFetcher.http_client_options

    def test_capability_flags_are_inherited_and_derived(self) -> None:
        assert SyncOsvAdvisories.supports_fetch_single is True
        assert SyncOsvAdvisories.participates_in_catch_up is True
        assert "supports_fetch_single" not in SyncOsvAdvisories.__dict__
        assert "abstract" not in SyncOsvAdvisories.__dict__

    def test_class_name_is_derived_from_the_fetcher_name(self) -> None:
        derived = "".join(part.capitalize() for part in NAME.split("_"))

        assert derived == SyncOsvAdvisories.__name__ == "SyncOsvAdvisories"

    def test_fetch_single_and_execute_are_overridden(self) -> None:
        assert "fetch_single" in SyncOsvAdvisories.__dict__
        assert SyncOsvAdvisories.fetch_single is not BaseCVEFetcher.fetch_single
        assert "execute" in SyncOsvAdvisories.__dict__
        assert SyncOsvAdvisories.execute is not BaseFetcher.execute
        assert inspect.iscoroutinefunction(SyncOsvAdvisories.fetch_single)
        assert inspect.iscoroutinefunction(SyncOsvAdvisories.execute)
        annotations = inspect.get_annotations(
            SyncOsvAdvisories.fetch_single, eval_str=True
        )
        assert annotations["return"] is CVEFetchResult

    def test_catch_up_is_the_inherited_default(self) -> None:
        assert "catch_up" not in SyncOsvAdvisories.__dict__
        assert SyncOsvAdvisories.catch_up is BaseCVEFetcher.catch_up

    def test_registered_in_both_registries(self) -> None:
        assert FETCHER_REGISTRY[NAME] is SyncOsvAdvisories
        assert _CVE_SOURCE_TYPE_MAP[OSV] is SyncOsvAdvisories
        assert get_all_cve_source_types()["osv"] is SyncOsvAdvisories

    def test_member_of_both_rosters(self) -> None:
        assert get_fetch_single_fetchers()["osv"] is SyncOsvAdvisories
        assert get_catch_up_fetchers()[NAME] is SyncOsvAdvisories

    def test_module_lives_in_the_tickets_domain(self) -> None:
        assert SyncOsvAdvisories.__module__ == (
            "app.services.tickets.sync_osv_advisories"
        )

    def test_no_base_cve_fetcher_member_is_added(self) -> None:
        assert not hasattr(BaseCVEFetcher, "_get_active_ticket_cve_ids")
        assert not hasattr(BaseCVEFetcher, "_request_delay")


@pytest.mark.unit
class TestSignalClasses:
    def test_completeness_guard_error_stays_in_the_osv_module(self) -> None:
        assert CompletenessGuardError.__module__ == sync_module.__name__
        assert CompletenessGuardError.__bases__ == (Exception,)
        assert not issubclass(CompletenessGuardError, FetcherError)
        assert not hasattr(BaseCVEFetcher, "CompletenessGuardError")
        assert not hasattr(base_fetcher_module, "CompletenessGuardError")

    def test_completeness_guard_error_is_non_retryable(self) -> None:
        error = CompletenessGuardError()

        assert is_retryable_condition(error) is False
        assert is_infrastructure_failure(error) is False
        assert str(error) == "Every OSV alias sub-request failed"

    def test_response_error_is_non_retryable_with_a_fixed_message(self) -> None:
        error = OsvResponseError()

        assert OsvResponseError.__bases__ == (Exception,)
        assert is_retryable_condition(error) is False
        assert is_infrastructure_failure(error) is False
        assert str(error) == "OSV API returned an unexpected status"


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


_OSV_MODULES: Final = [sync_module, osv_vulnerability_record]


@pytest.mark.unit
class TestStructuralAbsences:
    @pytest.mark.parametrize("module", _OSV_MODULES, ids=lambda module: module.__name__)
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

    @pytest.mark.parametrize("module", _OSV_MODULES, ids=lambda module: module.__name__)
    def test_reads_no_setting_and_touches_no_redis_task_or_api_layer(
        self, module: ModuleType
    ) -> None:
        imported = _imported_modules(module)

        forbidden = {
            name
            for name in imported
            if name in {"app.config", "app.celery_app"}
            or name.split(".")[0] == "redis"
            or name.startswith(("app.tasks", "app.api", "app.schemas"))
        }
        assert forbidden == set()

    @pytest.mark.parametrize("module", _OSV_MODULES, ids=lambda module: module.__name__)
    def test_raises_no_api_facing_error(self, module: ModuleType) -> None:
        names = _referenced_names(module)

        assert not {"ErrorCode", "ServiceError", "HTTPException"} & names
        assert not [name for name in names if name.endswith("ServiceError")], (
            "an API-facing service exception"
        )

    def test_raises_only_the_sanitized_abort_fetcher_error(self) -> None:
        source = inspect.getsource(sync_module)

        assert source.count("raise FetcherError(") == 1
        assert '" — aborted after 3 consecutive failures"' in source


# ---------------------------------------------------------------------------
# Shared harness of the wrapper tests
# ---------------------------------------------------------------------------


@pytest.fixture
async def world(db_session_factory: SessionFactory) -> AsyncIterator[IngestionWorld]:
    created = IngestionWorld(db_session_factory, await db_session_factory())
    try:
        yield created
    finally:
        await created.cleanup()


class ClientServer(OsvServer):
    """An `OsvServer` recording every client it creates."""

    def __init__(self) -> None:
        super().__init__()
        self.clients: list[httpx.AsyncClient] = []

    def client(self) -> httpx.AsyncClient:
        created = super().client()
        self.clients.append(created)
        return created


@dataclass
class Sleeps:
    """The recorded step-13 throttle delays."""

    delays: list[float] = field(default_factory=list)

    async def sleep(self, delay: float) -> None:
        self.delays.append(delay)


@pytest.fixture
def sleeps(monkeypatch: pytest.MonkeyPatch) -> Sleeps:
    recorder = Sleeps()
    monkeypatch.setattr(sync_module, "asyncio", SimpleNamespace(sleep=recorder.sleep))
    return recorder


@pytest.fixture
def server(monkeypatch: pytest.MonkeyPatch, sleeps: Sleeps) -> ClientServer:
    """Every lazily created fetcher HTTP client serves this fake."""
    fake = ClientServer()

    def create_http_client(name: str, **options: Any) -> httpx.AsyncClient:
        assert name == NAME
        assert options == {}
        return fake.client()

    monkeypatch.setattr(base_fetcher_module, "create_http_client", create_http_client)
    return fake


async def _active_cve(world: IngestionWorld) -> tuple[CVE, Ticket]:
    cve = await world.cve_in()
    ticket = await world.ticket(cve_id=cve.id)
    return cve, ticket


def _serve(server: OsvServer, cve: CVE) -> None:
    """A Phase 1 record with one `GIT` range and four aliases: an applicable
    record naming a package, a 404, a `CVE-*` alias (never requested), and a
    record naming another CVE (contributes nothing); its `related` record
    is never requested. Four throttled requests are three delays."""
    server.bodies[cve.cve_id] = {
        "affected": [
            {
                "ranges": [
                    {
                        "type": "GIT",
                        "repo": REPO,
                        "events": [{"introduced": "0"}, {"fixed": "c1"}],
                    }
                ]
            }
        ],
        "aliases": [ALIAS, "EXAMPLE-ALIAS-2099-0404", OTHER_CVE, NOT_APPLICABLE],
        "related": [RELATED],
    }
    server.bodies[ALIAS] = {
        "aliases": [cve.cve_id],
        "affected": [
            {
                "package": {"name": "example", "ecosystem": "PyPI"},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "0"}, {"fixed": "1.0"}],
                    }
                ],
            }
        ],
    }
    for record_id in (OTHER_CVE, RELATED, NOT_APPLICABLE):
        server.bodies[record_id] = {
            "aliases": [OTHER_CVE if record_id == NOT_APPLICABLE else cve.cve_id],
            "affected": [{"package": {"name": "suse-example"}}],
        }


def _guarded(server: OsvServer, cve: CVE) -> None:
    """A Phase 1 record whose every sub-request fails."""
    server.bodies[cve.cve_id] = {"affected": [], "aliases": [FAILING]}
    server.responses[FAILING] = status(503)


async def _osv_rows(factory: async_sessionmaker[AsyncSession], cve: CVE) -> int:
    async with factory() as session:
        count = await session.scalar(
            select(func.count())
            .select_from(CVEAffectedVersion)
            .where(
                CVEAffectedVersion.cve_id == cve.id,
                CVEAffectedVersion.source_container == "osv",
            )
        )
    return int(count or 0)


# ---------------------------------------------------------------------------
# On-demand fetch_single_cve
# ---------------------------------------------------------------------------


@pytest.fixture
async def on_demand(
    real_session_factory: async_sessionmaker[AsyncSession],
    redis_client: redis_asyncio.Redis,
    monkeypatch: pytest.MonkeyPatch,
) -> AsyncIterator[FetchSingleHarness]:
    harness = install_fetch_single_harness(
        monkeypatch, real_session_factory, redis_client
    )
    try:
        await seed_fetcher_config(real_session_factory, NAME, enabled=True)
        harness.names.append(NAME)
        yield harness
    finally:
        await harness.cleanup()


@pytest.mark.integration
class TestOnDemandFetch:
    async def test_success_writes_success_and_publishes_the_package_handoff(
        self,
        world: IngestionWorld,
        on_demand: FetchSingleHarness,
        server: ClientServer,
        sleeps: Sleeps,
    ) -> None:
        cve, ticket = await _active_cve(world)
        _serve(server, cve)
        token = await on_demand.marker(cve.cve_id, OSV.value)

        with capture_logs() as logs:
            outcome = await on_demand.run(NAME, cve.cve_id, OSV.value, token)

        assert outcome is None
        assert server.requested_ids == [
            cve.cve_id,
            ALIAS,
            "EXAMPLE-ALIAS-2099-0404",
            NOT_APPLICABLE,
        ]
        # Outside a run, the class default separates consecutive requests.
        assert sleeps.delays == [0.2, 0.2, 0.2]
        state = await source_state(on_demand.factory, cve.id, OSV)
        assert state is not None
        assert state.status == CVESourceFetchStatus.SUCCESS
        assert await _osv_rows(on_demand.factory, cve) == 2
        assert on_demand.published.published(RESOLVE) == [
            {
                "ticket_id": str(ticket.id),
                "cpe_matches": [],
                "affected_cpes": [],
                "vendor_products": [],
                "resolved_packages": ["example"],
            }
        ]
        assert await on_demand.marker_value(cve.cve_id, OSV.value) is None
        assert await fetcher_run_count(on_demand.factory, NAME) == 0
        assert events_named(logs, COMPLETED) == [
            {
                "event": COMPLETED,
                "log_level": "info",
                "outcome": "updated",
                "fetcher_name": NAME,
                "cve_id": cve.cve_id,
                "source": OSV.value,
            }
        ]
        # The workflow closed the client it created.
        assert server.clients
        assert all(client.is_closed for client in server.clients)

    async def test_ticketless_cve_gets_its_ticket_through_upsert_cve(
        self,
        world: IngestionWorld,
        on_demand: FetchSingleHarness,
        server: ClientServer,
    ) -> None:
        cve = await world.cve_in()
        _serve(server, cve)
        token = await on_demand.marker(cve.cve_id, OSV.value)

        outcome = await on_demand.run(NAME, cve.cve_id, OSV.value, token)

        assert outcome is None
        async with on_demand.factory() as session:
            tickets = (
                await session.scalars(select(Ticket).where(Ticket.cve_id == cve.id))
            ).all()
        assert len(tickets) == 1
        [handoff] = on_demand.published.published(RESOLVE)
        assert handoff["ticket_id"] == str(tickets[0].id)

    async def test_404_is_missing(
        self,
        world: IngestionWorld,
        on_demand: FetchSingleHarness,
        server: ClientServer,
        sleeps: Sleeps,
    ) -> None:
        cve, _ = await _active_cve(world)
        token = await on_demand.marker(cve.cve_id, OSV.value)

        with capture_logs() as logs:
            outcome = await on_demand.run(NAME, cve.cve_id, OSV.value, token)

        assert outcome is None
        state = await source_state(on_demand.factory, cve.id, OSV)
        assert state is not None
        assert state.status == CVESourceFetchStatus.MISSING
        assert sleeps.delays == []
        assert await on_demand.marker_value(cve.cve_id, OSV.value) is None
        assert [entry["outcome"] for entry in events_named(logs, COMPLETED)] == [
            "missing"
        ]
        assert all(client.is_closed for client in server.clients)

    @pytest.mark.parametrize("code", [429, 503])
    async def test_retryable_status_schedules_a_retry_without_status(
        self,
        code: int,
        world: IngestionWorld,
        on_demand: FetchSingleHarness,
        server: ClientServer,
    ) -> None:
        cve, _ = await _active_cve(world)
        server.responses[cve.cve_id] = status(code)
        token = await on_demand.marker(cve.cve_id, OSV.value)

        with capture_logs() as logs:
            outcome = await on_demand.run(NAME, cve.cve_id, OSV.value, token)

        assert isinstance(outcome, FetchSingleRetry)
        assert outcome.countdown == 5
        assert isinstance(outcome.cause, httpx.HTTPStatusError)
        assert outcome.cause.response.status_code == code
        assert await source_state(on_demand.factory, cve.id, OSV) is None
        assert await on_demand.marker_value(cve.cve_id, OSV.value) == token
        [retry] = events_named(logs, RETRY_SCHEDULED)
        assert retry["cause"] == "HTTPStatusError"
        assert all(client.is_closed for client in server.clients)

    async def test_retryable_failure_after_the_last_retry_is_failure(
        self,
        world: IngestionWorld,
        on_demand: FetchSingleHarness,
        server: ClientServer,
    ) -> None:
        cve, _ = await _active_cve(world)
        server.responses[cve.cve_id] = status(503)
        token = await on_demand.marker(cve.cve_id, OSV.value)

        with capture_logs() as logs, pytest.raises(httpx.HTTPStatusError):
            await on_demand.run(
                NAME, cve.cve_id, OSV.value, token, attempt=LAST_ATTEMPT
            )

        state = await source_state(on_demand.factory, cve.id, OSV)
        assert state is not None
        assert state.status == CVESourceFetchStatus.FAILURE
        assert await on_demand.marker_value(cve.cve_id, OSV.value) is None
        assert events_named(logs, RETRY_SCHEDULED) == []
        assert [entry["stage"] for entry in events_named(logs, FAILED)] == [
            "pre_finalization"
        ]
        assert all(client.is_closed for client in server.clients)

    @pytest.mark.parametrize(
        ("cause", "error"),
        [
            ("CompletenessGuardError", CompletenessGuardError),
            ("JSONDecodeError", ValueError),
            ("ValidationError", ValidationError),
        ],
        ids=["guard", "json", "schema"],
    )
    async def test_non_retryable_failure_is_immediate(
        self,
        cause: str,
        error: type[Exception],
        world: IngestionWorld,
        on_demand: FetchSingleHarness,
        server: ClientServer,
    ) -> None:
        cve, _ = await _active_cve(world)
        if cause == "CompletenessGuardError":
            _guarded(server, cve)
        elif cause == "JSONDecodeError":
            server.responses[cve.cve_id] = status(200, b"{")
        else:
            server.bodies[cve.cve_id] = {"aliases": "not-a-list"}
        token = await on_demand.marker(cve.cve_id, OSV.value)

        with capture_logs() as logs, pytest.raises(error):
            await on_demand.run(NAME, cve.cve_id, OSV.value, token)

        state = await source_state(on_demand.factory, cve.id, OSV)
        assert state is not None
        assert state.status == CVESourceFetchStatus.FAILURE
        assert await _osv_rows(on_demand.factory, cve) == 0
        assert await on_demand.marker_value(cve.cve_id, OSV.value) is None
        assert events_named(logs, RETRY_SCHEDULED) == []
        [failed] = events_named(logs, FAILED)
        assert failed["cause"] == cause
        assert failed["retries"] == 0
        assert await fetcher_run_count(on_demand.factory, NAME) == 0
        assert all(client.is_closed for client in server.clients)


# ---------------------------------------------------------------------------
# Catch-up through the inherited default
# ---------------------------------------------------------------------------


@pytest.fixture
async def catch_up(
    real_session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> AsyncIterator[CatchUpHarness]:
    harness = install_harness(monkeypatch, real_session_factory)
    try:
        await seed_fetcher_config(real_session_factory, NAME, enabled=True)
        harness.names.append(NAME)
        yield harness
    finally:
        await harness.cleanup()


@pytest.mark.integration
class TestCatchUp:
    async def test_run_catch_up_uses_the_inherited_default(
        self,
        world: IngestionWorld,
        catch_up: CatchUpHarness,
        server: ClientServer,
        sleeps: Sleeps,
    ) -> None:
        cve, ticket = await _active_cve(world)
        _serve(server, cve)

        await fetchers.run_catch_up_async(NAME, str(ticket.id))

        assert server.requested_ids[0] == cve.cve_id
        assert sleeps.delays == [0.2, 0.2, 0.2]
        # The catch-up flushes, then the finalizer commits once and only
        # then drains and publishes.
        events = catch_up.events
        commit = events.index("commit")
        assert events.count("commit") == 1
        assert events[commit - 1] == "flush"
        assert commit < events.index("drain") < events.index(f"publish:{RESOLVE}")
        state = await source_state(catch_up.factory, cve.id, OSV)
        assert state is not None
        assert state.status == CVESourceFetchStatus.SUCCESS
        [handoff] = catch_up.published.published(RESOLVE)
        assert handoff["ticket_id"] == str(ticket.id)
        assert handoff["resolved_packages"] == ["example"]
        assert await fetcher_run_count(catch_up.factory, NAME) == 0
        catch_up.engine.dispose.assert_awaited_once()
        assert all(client.is_closed for client in server.clients)

    async def test_404_writes_missing_and_returns(
        self,
        world: IngestionWorld,
        catch_up: CatchUpHarness,
        server: ClientServer,
    ) -> None:
        cve, ticket = await _active_cve(world)

        await fetchers.run_catch_up_async(NAME, str(ticket.id))

        state = await source_state(catch_up.factory, cve.id, OSV)
        assert state is not None
        assert state.status == CVESourceFetchStatus.MISSING
        assert "commit" not in catch_up.events
        assert "status:commit" in catch_up.events
        assert await fetcher_run_count(catch_up.factory, NAME) == 0
        catch_up.engine.dispose.assert_awaited_once()
        assert all(client.is_closed for client in server.clients)

    async def test_failure_on_every_attempt_writes_failure_and_propagates(
        self,
        world: IngestionWorld,
        catch_up: CatchUpHarness,
        server: ClientServer,
    ) -> None:
        cve, ticket = await _active_cve(world)
        server.responses[cve.cve_id] = status(503)

        # The initial attempt and its three retries, each a new invocation.
        for _ in range(LAST_ATTEMPT + 1):
            with pytest.raises(httpx.HTTPStatusError) as raised:
                await fetchers.run_catch_up_async(NAME, str(ticket.id))
            assert is_retryable_condition(raised.value)
            state = await source_state(catch_up.factory, cve.id, OSV)
            assert state is not None
            assert state.status == CVESourceFetchStatus.FAILURE

        assert server.requested_ids == [cve.cve_id] * (LAST_ATTEMPT + 1)
        assert "commit" not in catch_up.events
        assert catch_up.events.count("status:commit") == LAST_ATTEMPT + 1
        assert await fetcher_run_count(catch_up.factory, NAME) == 0
        assert catch_up.engine.dispose.await_count == LAST_ATTEMPT + 1
        assert len(server.clients) == LAST_ATTEMPT + 1
        assert all(client.is_closed for client in server.clients)

    @pytest.mark.parametrize("kind", ["guard", "schema"])
    async def test_non_retryable_failure_writes_failure(
        self,
        kind: str,
        world: IngestionWorld,
        catch_up: CatchUpHarness,
        server: ClientServer,
    ) -> None:
        cve, ticket = await _active_cve(world)
        if kind == "guard":
            _guarded(server, cve)
        else:
            server.bodies[cve.cve_id] = {"aliases": [1]}

        with pytest.raises((CompletenessGuardError, ValidationError)) as raised:
            await fetchers.run_catch_up_async(NAME, str(ticket.id))

        assert not is_retryable_condition(raised.value)
        state = await source_state(catch_up.factory, cve.id, OSV)
        assert state is not None
        assert state.status == CVESourceFetchStatus.FAILURE
        assert await _osv_rows(catch_up.factory, cve) == 0
        assert "commit" not in catch_up.events
        assert await fetcher_run_count(catch_up.factory, NAME) == 0
        assert all(client.is_closed for client in server.clients)


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
        assert config.request_delay == SyncOsvAdvisories.default_request_delay == 0.2
        # No per-class seed: the column default (cve-sync-osv.md, Custom
        # Settings, Operational notes).
        assert config.run_timeout == 3600
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
        assert entry.schedule.minute == {0}
        assert entry.schedule.hour == {5}
        assert entry.schedule.day_of_month == set(range(1, 32))
        assert entry.schedule.month_of_year == set(range(1, 13))
        assert entry.schedule.day_of_week == set(range(7))
        assert "queue" not in entry.options
        # The default 3600 s run timeout: soft limit 3420 s (cve-sync-osv.md,
        # Custom Settings, Operational notes).
        assert entry.options["time_limit"] == 3600
        assert entry.options["soft_time_limit"] == 3420
