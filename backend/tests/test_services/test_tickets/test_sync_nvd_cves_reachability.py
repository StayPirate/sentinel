"""Registration, concrete compliance, structural absences, and production
reachability of the real `SyncNvdCves` class
(backend/app/services/tickets/sync_nvd_cves.py): fetcher discovery, both
registries and the three rosters, the on-demand `fetch_single_cve`
workflow, the default catch-up through `run_catch_up`, the broadcast
refetch preparation, the bootstrapped `FetcherConfig`, and the RedBeat
schedule entry.

Owning specifications:

- docs/features/tickets/cve-sync-nvd.md (Fetcher Definition; Class
  Structure; Custom Settings; NVD Source API Caching, Lifecycle, the cache
  that on-demand fetches and catch-up share; `fetch_single(cve_id)`; Error
  Handling, the `fetch_single()` table, including HTTP 404 as a
  non-retryable failure).
- docs/features/platform/cve-fetcher-infrastructure.md (Class Attributes;
  `__init_subclass__` Validation; Non-Modification Statement; `fetch_single`
  Signaling Convention; Retry Policy for `fetch_single`; Error
  Categorization; CVE Source Type Identity, both registry accessors; Default
  catch_up Implementation).
- docs/features/tickets/cve-service.md (On-Demand Fetch: fetch_single_cve;
  Fetch Orchestration: `trigger_on_demand_fetch()`, Transactional
  Preparation).
- docs/features/platform/fetcher-infrastructure.md (Naming Convention, Class
  Name Derivation; Fetcher Discovery, Domain Placement; Custom Settings
  Schema; Per-Ticket Catch-Up: Celery task wrapper and Registry accessor
  `get_catch_up_fetchers()`; BaseFetcher HTTP Client Integration, HTTP
  Client Ownership Rule; Data Model, FetcherConfig bootstrap; Celery Beat
  Schedule Synchronization, Redbeat Entry Structure and Time Limits).
- docs/features/platform/testing-strategy.md (CVE Fetcher Infrastructure,
  Discovery completeness, Default catch-up, and Concrete compliance, "NVD
  and GHSA inline paths construct the token"; On-Demand CVE Refetch).

The workflows run against real PostgreSQL with the harnesses of
`tests/support/fetch_single_cve.py` and `tests/support/cve_catch_up.py`
(recording session factories over `real_session_factory`, a recorded
`task_publication.publish_task`, and the real convergence drain). The
production class is resolved from the registries filled by fetcher
discovery; no test-only fetcher is defined, so no registry isolation is
needed. Every HTTP client the fetcher creates is the in-process
`NvdServer`; `NVD_API_KEY` is set to a fictional value on
`app.config.settings`. The committed `FetcherConfig` rows, CVEs, Tickets,
and their children are deleted at teardown. Bootstrap and reconciliation
run on `db_session`, rolled back at teardown, and the worker Redis
database. All identifiers are fictional, except NVD's institutional source
identifier `nvd@nist.gov`.

The generic task terminal matrix is owned by
`test_fetch_single_cve_workflow.py` and `test_cve_fetcher_catch_up.py`, and
NVD exception classification by `test_sync_nvd_cves.py`; the cases here
prove that each row of the NVD `fetch_single()` error table reaches its
documented latest status and retry decision through the real wrappers.
"""

from __future__ import annotations

import ast
import enum
import inspect
import textwrap
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from types import ModuleType
from typing import Any, Final

import httpx
import pytest
import redis.asyncio as redis_asyncio
from celery import Celery
from celery.app.task import Task
from pydantic import SecretStr, ValidationError
from redbeat import RedBeatSchedulerEntry
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase
from structlog.testing import capture_logs

import app.services.base_fetcher as base_fetcher_module
import app.services.fetcher_discovery as fetcher_discovery
from app.config import settings as app_settings
from app.core.enums import CVESourceFetchStatus, CVESourceType, Scope
from app.core.errors import ErrorCode
from app.models.cve import CVE
from app.models.cve_cvss_assessment import CVECVSSAssessment
from app.models.fetcher_config import FetcherConfig
from app.models.ticket import Ticket
from app.services import cve_service, task_publication
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
from app.services.ticket_visibility import TicketCaller
from app.services.tickets import nvd_cve_record
from app.services.tickets import sync_nvd_cves as sync_module
from app.services.tickets.nvd_cve_record import (
    NvdPageError,
    NvdRecordIdError,
    NvdRecordStructureError,
)
from app.services.tickets.sync_nvd_cves import NvdResponseError, SyncNvdCves
from app.tasks import fetchers
from tests.support.cve_catch_up import (
    RESOLVE,
    CatchUpHarness,
    Publications,
    delete_fetcher_rows,
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
    ScriptedRedis,
    events_named,
    install_fetch_single_harness,
)
from tests.support.nvd import (
    API_KEY_HEADER,
    NvdServer,
    Responder,
    page_body,
    raising,
    status,
)
from tests.support.nvd import body as json_body

SessionFactory = Callable[[], Awaitable[AsyncSession]]

NAME: Final = "sync_nvd_cves"
NVD: Final = CVESourceType.NVD
SCHEDULE: Final = "0 */6 * * *"
API_KEY: Final = "fictional-nvd-api-key-0001"
"""A fictional `NVD_API_KEY`; never a real key shape."""
CPE: Final = "cpe:2.3:a:example:product:1.0:*:*:*:*:*:*:*"
V31: Final = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
LAST_ATTEMPT: Final = 3
"""The zero-based attempt index after which no retry remains (3 retries)."""
ALL_SCOPE: Final = TicketCaller.authenticated(uuid.uuid4(), Scope.ALL)
"""A caller that sees every CVE, so accessibility never decides a read."""


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


def _method_names(cls: type) -> set[str]:
    return {
        name
        for name, value in vars(cls).items()
        if inspect.isfunction(value) or inspect.iscoroutinefunction(value)
    }


def _referenced_names(source: str) -> set[str]:
    """Every identifier and attribute name the source references."""
    tree = ast.parse(textwrap.dedent(source))
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


# ---------------------------------------------------------------------------
# Discovery, registration, and capability
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestRegistrationAndCapability:
    def test_discovery_imports_the_module(self) -> None:
        assert sync_module.__name__ in _imported_modules(fetcher_discovery)
        assert SyncNvdCves.__module__ == "app.services.tickets.sync_nvd_cves"

    def test_class_body_declares_exactly_the_class_structure_attributes(
        self,
    ) -> None:
        """No `queue`, `http_client_options`, `supports_fetch_single`, or
        `participates_in_catch_up` in the class body (cve-sync-nvd.md, Class
        Structure); `Settings` is the first production custom-settings
        model."""
        assert _class_body_assignments(SyncNvdCves) == {
            "name",
            "cve_source_type",
            "description",
            "default_schedule",
            "default_request_delay",
            "Settings",
            "source_reference_url_pattern",
        }

    def test_inherited_defaults_apply(self) -> None:
        assert SyncNvdCves.queue is None
        assert SyncNvdCves.http_client_options is BaseFetcher.http_client_options
        for inherited in ("queue", "http_client_options"):
            assert inherited not in SyncNvdCves.__dict__, inherited

    def test_class_name_is_derived_from_the_fetcher_name(self) -> None:
        derived = "".join(part.capitalize() for part in NAME.split("_"))

        assert derived == SyncNvdCves.__name__ == "SyncNvdCves"

    def test_registered_in_both_registries(self) -> None:
        assert FETCHER_REGISTRY[NAME] is SyncNvdCves
        assert _CVE_SOURCE_TYPE_MAP[NVD] is SyncNvdCves
        assert get_all_cve_source_types()["nvd"] is SyncNvdCves

    def test_member_of_both_rosters(self) -> None:
        assert get_fetch_single_fetchers()["nvd"] is SyncNvdCves
        assert get_catch_up_fetchers()[NAME] is SyncNvdCves

    def test_no_base_cve_fetcher_member_is_added(self) -> None:
        for name in (
            "_shared_source_names",
            "_source_names",
            "_get_page",
            "_request_page",
            "_process_vulnerability",
            "_ingest",
            "_item_failed",
        ):
            assert not hasattr(BaseCVEFetcher, name), name


# ---------------------------------------------------------------------------
# Concrete compliance (testing-strategy.md, CVE Fetcher Infrastructure)
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestConcreteCompliance:
    def test_only_fetch_single_and_execute_override_the_base_contract(self) -> None:
        own = _method_names(SyncNvdCves)
        inherited_contract = _method_names(BaseCVEFetcher) | _method_names(BaseFetcher)

        assert own & inherited_contract == {"fetch_single", "execute"}
        assert SyncNvdCves.catch_up is BaseCVEFetcher.catch_up
        assert SyncNvdCves.commit_and_dispatch is BaseCVEFetcher.commit_and_dispatch
        assert (
            SyncNvdCves._isolated_status_commit
            is BaseCVEFetcher._isolated_status_commit
        )
        assert SyncNvdCves.run is BaseFetcher.run

    def test_typed_fetch_single_and_async_execute(self) -> None:
        assert inspect.iscoroutinefunction(SyncNvdCves.fetch_single)
        assert inspect.iscoroutinefunction(SyncNvdCves.execute)
        annotations = inspect.get_annotations(SyncNvdCves.fetch_single, eval_str=True)
        assert annotations["return"] is CVEFetchResult
        assert (
            inspect.get_annotations(SyncNvdCves._ingest, eval_str=True)["return"]
            is CVEFetchResult
        )

    def test_inline_periodic_path_constructs_the_token(self) -> None:
        """The periodic path processes paginated responses inline: it never
        delegates to `fetch_single()`, builds `CVEFetchResult` itself, and
        finalizes through the inherited `commit_and_dispatch()`."""
        periodic = "\n".join(
            inspect.getsource(method)
            for method in (
                SyncNvdCves.execute,
                SyncNvdCves._process_vulnerability,
                SyncNvdCves._ingest,
                SyncNvdCves._item_failed,
            )
        )
        names = _referenced_names(periodic)

        assert "fetch_single" not in names
        assert {"CVEFetchResult", "commit_and_dispatch", "record_failed"} <= names
        assert "record_succeeded" not in names
        assert "record_created" not in names
        assert "record_updated" not in names
        assert "get_active_ticket_cve_ids" not in names

    def test_on_demand_path_never_commits_records_or_closes(self) -> None:
        on_demand = "\n".join(
            inspect.getsource(method)
            for method in (
                SyncNvdCves.fetch_single,
                SyncNvdCves._shared_source_names,
                SyncNvdCves._source_names,
                SyncNvdCves._ingest,
            )
        )
        names = _referenced_names(on_demand)

        for forbidden in (
            "commit",
            "commit_and_dispatch",
            "rollback",
            "record_failed",
            "record_succeeded",
            "aclose",
            "_teardown_http_client",
            "sleep",
        ):
            assert forbidden not in names, forbidden


@pytest.mark.unit
class TestSignalClasses:
    def test_response_error_is_non_retryable_with_a_fixed_message(self) -> None:
        error = NvdResponseError()

        assert NvdResponseError.__bases__ == (Exception,)
        assert not issubclass(NvdResponseError, FetcherError)
        assert NvdResponseError.__module__ == sync_module.__name__
        assert str(error) == "NVD API returned an unexpected response"
        assert is_retryable_condition(error) is False
        assert is_infrastructure_failure(error) is False

    @pytest.mark.parametrize(
        "error",
        [NvdPageError(), NvdRecordStructureError(), NvdRecordIdError()],
        ids=lambda error: type(error).__name__,
    )
    def test_mapping_errors_are_non_retryable(self, error: Exception) -> None:
        assert is_retryable_condition(error) is False
        assert not isinstance(error, FetcherError)


# ---------------------------------------------------------------------------
# Structural absences
# ---------------------------------------------------------------------------


_NVD_MODULES: Final = [sync_module, nvd_cve_record]


@pytest.mark.unit
class TestStructuralAbsences:
    @pytest.mark.parametrize("module", _NVD_MODULES, ids=lambda module: module.__name__)
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

    @pytest.mark.parametrize("module", _NVD_MODULES, ids=lambda module: module.__name__)
    def test_touches_no_redis_task_or_api_layer(self, module: ModuleType) -> None:
        imported = _imported_modules(module)

        forbidden = {
            name
            for name in imported
            if name == "app.celery_app"
            or name.split(".")[0] == "redis"
            or name.startswith(("app.tasks", "app.api", "app.schemas"))
        }
        assert forbidden == set()

    def test_reads_configuration_only_for_the_api_key(self) -> None:
        assert "app.config" not in _imported_modules(nvd_cve_record)
        tree = ast.parse(inspect.getsource(sync_module))
        read = {
            node.attr
            for node in ast.walk(tree)
            if isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name)
            and node.value.id == "settings"
        }
        assert read == {"nvd_api_key"}

    @pytest.mark.parametrize("module", _NVD_MODULES, ids=lambda module: module.__name__)
    def test_raises_no_api_facing_error(self, module: ModuleType) -> None:
        names = _referenced_names(inspect.getsource(module))

        assert not {"ErrorCode", "ServiceError", "HTTPException"} & names
        assert not [name for name in names if name.endswith("ServiceError")]

    def test_no_route_task_or_error_code_names_the_source(self) -> None:
        from app.celery_app import celery_app
        from app.main import app as api

        paths = [getattr(route, "path", "") for route in api.routes]
        assert paths
        assert not [path for path in paths if "nvd" in path.lower()]
        assert not [name for name in celery_app.tasks if "nvd" in name.lower()]
        assert not [member for member in ErrorCode if "NVD" in member.name]


# ---------------------------------------------------------------------------
# Shared harness of the wrapper tests
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def nvd_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every test sets the key itself, never relying on the environment."""
    monkeypatch.setattr(app_settings, "nvd_api_key", SecretStr(API_KEY))


@pytest.fixture
async def world(db_session_factory: SessionFactory) -> AsyncIterator[IngestionWorld]:
    created = IngestionWorld(db_session_factory, await db_session_factory())
    try:
        await created.ensure_default_setting()
        yield created
    finally:
        await created.cleanup()


class ClientServer(NvdServer):
    """An `NvdServer` recording every client it creates."""

    def __init__(self) -> None:
        super().__init__()
        self.clients: list[httpx.AsyncClient] = []

    def client(self) -> httpx.AsyncClient:
        created = super().client()
        self.clients.append(created)
        return created


@pytest.fixture
def server(monkeypatch: pytest.MonkeyPatch) -> ClientServer:
    """Every lazily created fetcher HTTP client serves this fake."""
    fake = ClientServer()

    def create_http_client(name: str, **options: Any) -> httpx.AsyncClient:
        # The key is never a client option: it is attached per request.
        assert name == NAME
        assert options == {}
        return fake.client()

    monkeypatch.setattr(base_fetcher_module, "create_http_client", create_http_client)
    return fake


async def _active_cve(world: IngestionWorld) -> tuple[CVE, Ticket]:
    cve = await world.cve_in()
    ticket = await world.ticket(cve_id=cve.id)
    return cve, ticket


def _record(cve_id: object, **members: Any) -> dict[str, Any]:
    """A fictional record with NVD's own vector, an invalid one, and one
    vulnerable CPE entry."""
    cve: dict[str, Any] = {
        "id": cve_id,
        "published": "2026-01-01T00:00:00.000",
        "lastModified": "2026-01-02T03:04:05.678",
        "vulnStatus": "Analyzed",
        "metrics": {
            "cvssMetricV31": [
                {"source": "nvd@nist.gov", "cvssData": {"vectorString": V31}},
                {
                    "source": "nvd@nist.gov",
                    "cvssData": {"vectorString": "CVSS:3.1/AV:N"},
                },
            ]
        },
        "configurations": [
            {"nodes": [{"cpeMatch": [{"vulnerable": True, "criteria": CPE}]}]}
        ],
    }
    cve.update(members)
    return {"cve": cve}


def _serve(server: NvdServer, cve: CVE) -> dict[str, Any]:
    record = _record(cve.cve_id)
    server.singles[cve.cve_id] = [record]
    return record


async def _assessment_count(factory: async_sessionmaker[AsyncSession], cve: CVE) -> int:
    async with factory() as session:
        count = await session.scalar(
            select(func.count())
            .select_from(CVECVSSAssessment)
            .where(CVECVSSAssessment.cve_id == cve.id)
        )
    return int(count or 0)


def _respond(server: NvdServer, cve: CVE, kind: str) -> None:
    """Serve one documented `fetch_single()` error-table condition."""
    responders: dict[str, Responder] = {
        "http_404": status(404, headers={"message": "Invalid apiKey."}),
        "http_403": status(403),
        "http_400": status(400),
        "http_422": status(422),
        "http_302": status(302, headers={"Location": "https://nvd.nist.gov/"}),
        "http_204": status(204),
        "invalid_json": status(200, b"{"),
        "not_envelope": json_body([_record(cve.cve_id)]),
        "undecodable": status(200, b"not gzip", headers={"Content-Encoding": "gzip"}),
        "empty_with_total": json_body(page_body([], 1)),
        "two_elements": json_body(
            page_body([_record(cve.cve_id), _record(cve.cve_id)], 2)
        ),
        "structure": json_body(page_body([_record(cve.cve_id, published=None)], 1)),
        "nul_description": json_body(
            page_body(
                [
                    _record(
                        cve.cve_id,
                        descriptions=[{"lang": "en", "value": "Fictional\x00"}],
                    )
                ],
                1,
            )
        ),
    }
    server.single_responses[cve.cve_id] = responders[kind]


_NON_RETRYABLE: Final[list[tuple[str, type[BaseException], str]]] = [
    ("http_404", httpx.HTTPStatusError, "HTTPStatusError"),
    ("http_403", httpx.HTTPStatusError, "HTTPStatusError"),
    ("http_400", httpx.HTTPStatusError, "HTTPStatusError"),
    ("http_422", httpx.HTTPStatusError, "HTTPStatusError"),
    ("http_302", httpx.HTTPStatusError, "HTTPStatusError"),
    ("http_204", NvdResponseError, "NvdResponseError"),
    ("invalid_json", NvdPageError, "NvdPageError"),
    ("not_envelope", NvdPageError, "NvdPageError"),
    ("undecodable", httpx.DecodingError, "DecodingError"),
    ("empty_with_total", NvdResponseError, "NvdResponseError"),
    ("two_elements", NvdResponseError, "NvdResponseError"),
    ("structure", NvdRecordStructureError, "NvdRecordStructureError"),
    ("nul_description", ValidationError, "ValidationError"),
]


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
    ) -> None:
        cve, ticket = await _active_cve(world)
        _serve(server, cve)
        token = await on_demand.marker(cve.cve_id, NVD.value)

        with capture_logs() as logs:
            outcome = await on_demand.run(NAME, cve.cve_id, NVD.value, token)

        assert outcome is None
        single, _ = server.requests
        assert single.url.params["cveId"] == cve.cve_id
        assert server.kinds == ["single", "source"]
        assert [request.headers[API_KEY_HEADER] for request in server.requests] == [
            API_KEY,
            API_KEY,
        ]
        state = await source_state(on_demand.factory, cve.id, NVD)
        assert state is not None
        # The invalid CVSS vector is skipped without failing the CVE.
        assert state.status == CVESourceFetchStatus.SUCCESS
        assert await _assessment_count(on_demand.factory, cve) == 1
        assert on_demand.published.published(RESOLVE) == [
            {
                "ticket_id": str(ticket.id),
                "cpe_matches": [
                    {"criteria": CPE, "vulnerable": True, "match_criteria_id": None}
                ],
                "affected_cpes": [],
                "vendor_products": [],
                "resolved_packages": [],
            }
        ]
        assert await on_demand.marker_value(cve.cve_id, NVD.value) is None
        assert await fetcher_run_count(on_demand.factory, NAME) == 0
        assert events_named(logs, COMPLETED) == [
            {
                "event": COMPLETED,
                "log_level": "info",
                "outcome": "updated",
                "fetcher_name": NAME,
                "cve_id": cve.cve_id,
                "source": NVD.value,
            }
        ]
        assert [
            entry["reason"]
            for entry in events_named(logs, "cve_fetch_candidate_skipped")
        ] == ["invalid_vector"]
        assert API_KEY not in repr(logs)
        # The workflow closed the client it created.
        assert server.clients
        assert all(client.is_closed for client in server.clients)

    @pytest.mark.parametrize("answer", ["zero_results", "other", "invalid", "nul"])
    async def test_no_record_of_the_requested_cve_is_missing(
        self,
        answer: str,
        world: IngestionWorld,
        on_demand: FetchSingleHarness,
        server: ClientServer,
    ) -> None:
        cve, _ = await _active_cve(world)
        if answer != "zero_results":
            other = {
                "other": "CVE-2099-0001",
                "invalid": "CVE-24-1",
                "nul": f"{cve.cve_id}\x00",
            }
            server.singles[cve.cve_id] = [_record(other[answer])]
        token = await on_demand.marker(cve.cve_id, NVD.value)

        with capture_logs() as logs:
            outcome = await on_demand.run(NAME, cve.cve_id, NVD.value, token)

        assert outcome is None
        state = await source_state(on_demand.factory, cve.id, NVD)
        assert state is not None
        assert state.status == CVESourceFetchStatus.MISSING
        assert await _assessment_count(on_demand.factory, cve) == 0
        assert [entry["outcome"] for entry in events_named(logs, COMPLETED)] == [
            "missing"
        ]
        # A missing CVE spends no Source API request.
        assert server.kinds == ["single"]
        assert on_demand.published.published(RESOLVE) == []
        assert all(client.is_closed for client in server.clients)

    @pytest.mark.parametrize(
        ("kind", "error", "cause"),
        _NON_RETRYABLE,
        ids=[kind for kind, _, _ in _NON_RETRYABLE],
    )
    async def test_non_retryable_condition_is_an_immediate_failure(
        self,
        kind: str,
        error: type[BaseException],
        cause: str,
        world: IngestionWorld,
        on_demand: FetchSingleHarness,
        server: ClientServer,
    ) -> None:
        cve, _ = await _active_cve(world)
        _respond(server, cve, kind)
        token = await on_demand.marker(cve.cve_id, NVD.value)

        with capture_logs() as logs, pytest.raises(error):
            await on_demand.run(NAME, cve.cve_id, NVD.value, token)

        assert len(server.single_requests) == 1
        state = await source_state(on_demand.factory, cve.id, NVD)
        assert state is not None
        # HTTP 404 is a failure, never `missing`.
        assert state.status == CVESourceFetchStatus.FAILURE
        assert await _assessment_count(on_demand.factory, cve) == 0
        assert await on_demand.marker_value(cve.cve_id, NVD.value) is None
        assert events_named(logs, RETRY_SCHEDULED) == []
        [failed] = events_named(logs, FAILED)
        assert failed["cause"] == cause
        assert failed["retries"] == 0
        assert API_KEY not in repr(logs)
        assert all(client.is_closed for client in server.clients)

    @pytest.mark.parametrize(
        "kind", ["http_429", "http_500", "http_503", "connect", "timeout"]
    )
    async def test_retryable_condition_schedules_a_retry_without_status(
        self,
        kind: str,
        world: IngestionWorld,
        on_demand: FetchSingleHarness,
        server: ClientServer,
    ) -> None:
        cve, _ = await _active_cve(world)
        server.single_responses[cve.cve_id] = _retryable(kind)
        token = await on_demand.marker(cve.cve_id, NVD.value)

        with capture_logs() as logs:
            outcome = await on_demand.run(NAME, cve.cve_id, NVD.value, token)

        assert isinstance(outcome, FetchSingleRetry)
        assert outcome.countdown == 5
        assert is_retryable_condition(outcome.cause)
        assert await source_state(on_demand.factory, cve.id, NVD) is None
        assert await on_demand.marker_value(cve.cve_id, NVD.value) == token
        assert len(events_named(logs, RETRY_SCHEDULED)) == 1
        assert server.kinds == ["single"]
        assert all(client.is_closed for client in server.clients)

    async def test_retryable_failure_after_the_last_retry_is_failure(
        self,
        world: IngestionWorld,
        on_demand: FetchSingleHarness,
        server: ClientServer,
    ) -> None:
        cve, _ = await _active_cve(world)
        server.single_responses[cve.cve_id] = status(500)
        token = await on_demand.marker(cve.cve_id, NVD.value)

        with capture_logs() as logs, pytest.raises(httpx.HTTPStatusError):
            await on_demand.run(
                NAME, cve.cve_id, NVD.value, token, attempt=LAST_ATTEMPT
            )

        state = await source_state(on_demand.factory, cve.id, NVD)
        assert state is not None
        assert state.status == CVESourceFetchStatus.FAILURE
        assert events_named(logs, RETRY_SCHEDULED) == []
        assert [entry["stage"] for entry in events_named(logs, FAILED)] == [
            "pre_finalization"
        ]

    async def test_source_api_failure_still_succeeds_in_degraded_mode(
        self,
        world: IngestionWorld,
        on_demand: FetchSingleHarness,
        server: ClientServer,
    ) -> None:
        cve, _ = await _active_cve(world)
        _serve(server, cve)
        server.source_response = raising(httpx.ConnectError("refused"))
        token = await on_demand.marker(cve.cve_id, NVD.value)

        with capture_logs() as logs:
            outcome = await on_demand.run(NAME, cve.cve_id, NVD.value, token)

        assert outcome is None
        state = await source_state(on_demand.factory, cve.id, NVD)
        assert state is not None
        assert state.status == CVESourceFetchStatus.SUCCESS
        assert len(events_named(logs, "nvd_source_api_unavailable")) == 1


def _retryable(kind: str) -> Responder:
    if kind == "connect":
        return raising(httpx.ConnectError("[Errno 111] Connection refused"))
    if kind == "timeout":
        return raising(httpx.ReadTimeout("timed out"))
    return status(int(kind.removeprefix("http_")))


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
    ) -> None:
        cve, ticket = await _active_cve(world)
        _serve(server, cve)

        await fetchers.run_catch_up_async(NAME, str(ticket.id))

        assert [request.url.params["cveId"] for request in server.single_requests] == [
            cve.cve_id
        ]
        assert server.kinds == ["single", "source"]
        # The catch-up flushes, then the finalizer commits once and only
        # then drains and publishes.
        events = catch_up.events
        commit = events.index("commit")
        assert events.count("commit") == 1
        assert events[commit - 1] == "flush"
        assert commit < events.index("drain") < events.index(f"publish:{RESOLVE}")
        state = await source_state(catch_up.factory, cve.id, NVD)
        assert state is not None
        assert state.status == CVESourceFetchStatus.SUCCESS
        [handoff] = catch_up.published.published(RESOLVE)
        assert handoff["ticket_id"] == str(ticket.id)
        assert [match["criteria"] for match in handoff["cpe_matches"]] == [CPE]
        assert await fetcher_run_count(catch_up.factory, NAME) == 0
        catch_up.engine.dispose.assert_awaited_once()
        assert all(client.is_closed for client in server.clients)

    async def test_zero_results_writes_missing_and_returns(
        self,
        world: IngestionWorld,
        catch_up: CatchUpHarness,
        server: ClientServer,
    ) -> None:
        cve, ticket = await _active_cve(world)

        await fetchers.run_catch_up_async(NAME, str(ticket.id))

        state = await source_state(catch_up.factory, cve.id, NVD)
        assert state is not None
        assert state.status == CVESourceFetchStatus.MISSING
        assert "commit" not in catch_up.events
        assert "status:commit" in catch_up.events
        assert server.kinds == ["single"]
        catch_up.engine.dispose.assert_awaited_once()

    async def test_retryable_failure_on_every_attempt_writes_failure(
        self,
        world: IngestionWorld,
        catch_up: CatchUpHarness,
        server: ClientServer,
    ) -> None:
        cve, ticket = await _active_cve(world)
        server.single_responses[cve.cve_id] = status(503)

        for _ in range(LAST_ATTEMPT + 1):
            with pytest.raises(httpx.HTTPStatusError) as raised:
                await fetchers.run_catch_up_async(NAME, str(ticket.id))
            assert is_retryable_condition(raised.value)
            state = await source_state(catch_up.factory, cve.id, NVD)
            assert state is not None
            assert state.status == CVESourceFetchStatus.FAILURE

        assert len(server.requests) == LAST_ATTEMPT + 1
        assert "commit" not in catch_up.events
        assert catch_up.events.count("status:commit") == LAST_ATTEMPT + 1
        assert catch_up.engine.dispose.await_count == LAST_ATTEMPT + 1
        assert all(client.is_closed for client in server.clients)

    @pytest.mark.parametrize(
        ("kind", "error"),
        [
            ("http_404", httpx.HTTPStatusError),
            ("two_elements", NvdResponseError),
            ("structure", NvdRecordStructureError),
            ("nul_description", ValidationError),
        ],
        ids=["http_404", "two_elements", "structure", "nul_description"],
    )
    async def test_non_retryable_failure_writes_failure(
        self,
        kind: str,
        error: type[BaseException],
        world: IngestionWorld,
        catch_up: CatchUpHarness,
        server: ClientServer,
    ) -> None:
        cve, ticket = await _active_cve(world)
        _respond(server, cve, kind)

        with pytest.raises(error) as raised:
            await fetchers.run_catch_up_async(NAME, str(ticket.id))

        assert isinstance(raised.value, Exception)
        assert not is_retryable_condition(raised.value)
        state = await source_state(catch_up.factory, cve.id, NVD)
        assert state is not None
        assert state.status == CVESourceFetchStatus.FAILURE
        assert await _assessment_count(catch_up.factory, cve) == 0
        assert "commit" not in catch_up.events
        assert len(server.single_requests) == 1


# ---------------------------------------------------------------------------
# Shared Source API cache (NVD Source API Caching, Lifecycle)
# ---------------------------------------------------------------------------

CNA_SOURCE: Final = "hackerone-1@example.com"
CNA_NAME: Final = "HackerOne"
CNA_CONTACT: Final = "contact-hackerone@example.com"
"""A fictional CNA identifier, its display name, and its contact address in
the trimmed live Source API body."""
V31_CNA: Final = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
SOURCE_EVENTS: Final = frozenset(
    {
        "nvd_source_api_unavailable",
        "nvd_source_entries_skipped",
        "nvd_source_cache_incomplete",
    }
)


def _cna_record(cve_id: str) -> dict[str, Any]:
    """NVD's own and a CNA's vector, and one vulnerable CPE entry."""
    return _record(
        cve_id,
        metrics={
            "cvssMetricV31": [
                {"source": "nvd@nist.gov", "cvssData": {"vectorString": V31}},
                {"source": CNA_SOURCE, "cvssData": {"vectorString": V31_CNA}},
            ]
        },
    )


async def _providers(factory: async_sessionmaker[AsyncSession], cve: CVE) -> set[str]:
    async with factory() as session:
        rows = await session.scalars(
            select(CVECVSSAssessment.provider_name).where(
                CVECVSSAssessment.cve_id == cve.id
            )
        )
        return set(rows.all())


@pytest.mark.integration
class TestSharedSourceCacheThroughTheWrappers:
    async def test_on_demand_runs_and_catch_up_share_one_source_request(
        self,
        world: IngestionWorld,
        on_demand: FetchSingleHarness,
        server: ClientServer,
        real_session_factory: async_sessionmaker[AsyncSession],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        assert sync_module._shared_source_cache.get() is None
        active = [await _active_cve(world) for _ in range(3)]
        for cve, _ in active:
            server.singles[cve.cve_id] = [_cna_record(cve.cve_id)]
        (first, _), (second, _), (third, third_ticket) = active

        with capture_logs() as logs:
            for cve in (first, second):
                token = await on_demand.marker(cve.cve_id, NVD.value)
                outcome = await on_demand.run(NAME, cve.cve_id, NVD.value, token)
                assert outcome is None
            assert server.kinds == ["single", "source", "single"]
            # The catch-up substitutes replace the on-demand ones; the
            # configuration that `on_demand` seeded serves both wrappers.
            catch_up = install_harness(monkeypatch, real_session_factory)
            await fetchers.run_catch_up_async(NAME, str(third_ticket.id))

        assert server.kinds == ["single", "source", "single", "single"]
        assert [request.url.params["cveId"] for request in server.single_requests] == [
            first.cve_id,
            second.cve_id,
            third.cve_id,
        ]
        for cve in (first, second, third):
            state = await source_state(real_session_factory, cve.id, NVD)
            assert state is not None
            assert state.status == CVESourceFetchStatus.SUCCESS
            # The fetches served by the shared cache resolve the CNA as well.
            assert await _providers(real_session_factory, cve) == {"NVD", CNA_NAME}
        # Each run created its own fetcher client, and its workflow closed it.
        assert len(server.clients) == 3
        assert all(client.is_closed for client in server.clients)
        catch_up.engine.dispose.assert_awaited_once()
        assert [entry for entry in logs if entry["event"] in SOURCE_EVENTS] == []
        for value in (CNA_SOURCE, CNA_NAME, CNA_CONTACT, API_KEY):
            assert value not in repr(logs)


# ---------------------------------------------------------------------------
# Broadcast refetch preparation with NVD disabled
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestBroadcastRefetch:
    async def test_disabled_nvd_is_reported_and_not_published(
        self,
        world: IngestionWorld,
        real_session_factory: async_sessionmaker[AsyncSession],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        registry = get_fetch_single_fetchers()
        assert registry["nvd"] is SyncNvdCves
        names = [fetcher_cls.name for fetcher_cls in registry.values()]
        async with real_session_factory() as session:
            assert not await session.scalar(
                select(func.count())
                .select_from(FetcherConfig)
                .where(FetcherConfig.fetcher_name.in_(names))
            )
        published = Publications()
        monkeypatch.setattr(task_publication, "publish_task", published)
        redis = ScriptedRedis()
        redis.install(monkeypatch)
        cve, _ = await _active_cve(world)
        try:
            for source, fetcher_cls in registry.items():
                await seed_fetcher_config(
                    real_session_factory, fetcher_cls.name, enabled=source != "nvd"
                )

            result = await cve_service.refetch_cve(
                cve_id=cve.cve_id,
                source=None,
                caller=ALL_SCOPE,
                session_factory=real_session_factory,
            )
        finally:
            await delete_fetcher_rows(real_session_factory, names)

        enabled = sorted(source for source in registry if source != "nvd")
        assert result.sources_disabled == ["nvd"]
        assert result.sources_enqueued == enabled
        assert [call["kwargs"]["source"] for call in published.calls] == enabled
        assert NAME not in [call["kwargs"]["fetcher_name"] for call in published.calls]


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
        assert config.request_delay == SyncNvdCves.default_request_delay == 6.0
        assert config.run_timeout == 3600
        # The settings default applies; no override is stored.
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
        # 0 */6 * * *
        assert entry.schedule.minute == {0}
        assert entry.schedule.hour == set(range(0, 24, 6))
        assert entry.schedule.day_of_month == set(range(1, 32))
        assert entry.schedule.month_of_year == set(range(1, 13))
        assert entry.schedule.day_of_week == set(range(7))
        assert "queue" not in entry.options
        assert entry.options["time_limit"] == 3600
        assert entry.options["soft_time_limit"] == 3420
