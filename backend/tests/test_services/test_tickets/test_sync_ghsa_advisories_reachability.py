"""Registration, concrete compliance, structural absences, and production
reachability of the real `SyncGhsaAdvisories` class
(backend/app/services/tickets/sync_ghsa_advisories.py): fetcher discovery,
both registries, the on-demand `fetch_single_cve` workflow, the default
catch-up through `run_catch_up`, the broadcast refetch preparation, the
bootstrapped `FetcherConfig`, and the RedBeat schedule entry.

Owning specifications:

- docs/features/tickets/cve-sync-ghsa.md (Fetcher Definition; Class
  Structure; `fetch_single(cve_id)`; Error Handling, the `fetch_single()`
  table and Sanitized error messages).
- docs/features/platform/cve-fetcher-infrastructure.md (Class Attributes;
  `__init_subclass__` Validation; Non-Modification Statement; `fetch_single`
  Signaling Convention; Retry Policy for `fetch_single`; Error
  Categorization; CVE Source Type Identity, both registry accessors; Default
  catch_up Implementation).
- docs/features/tickets/cve-service.md (On-Demand Fetch: fetch_single_cve;
  Fetch Orchestration: `trigger_on_demand_fetch()`, Transactional
  Preparation).
- docs/features/platform/fetcher-infrastructure.md (Naming Convention, Class
  Name Derivation; Fetcher Discovery, Domain Placement; Per-Ticket Catch-Up:
  Celery task wrapper and Registry accessor `get_catch_up_fetchers()`;
  BaseFetcher HTTP Client Integration, HTTP Client Ownership Rule; Data
  Model, FetcherConfig bootstrap; Celery Beat Schedule Synchronization,
  Redbeat Entry Structure and Time Limits).
- docs/features/platform/testing-strategy.md (CVE Fetcher Infrastructure,
  Discovery completeness, Default catch-up, and Concrete compliance, "GHSA
  inline paths construct the token"; On-Demand CVE Refetch).

The workflows run against real PostgreSQL with the harnesses of
`tests/support/fetch_single_cve.py` and `tests/support/cve_catch_up.py`
(recording session factories over `real_session_factory`, a recorded
`task_publication.publish_task`, and the real convergence drain). The
production class is resolved from the registries filled by fetcher
discovery; no test-only fetcher is defined, so no registry isolation is
needed. Every HTTP client the fetcher creates is the in-process
`GhsaServer`; `GITHUB_TOKEN` is set to a fictional value on
`app.config.settings`. The committed `FetcherConfig` rows, CVEs, Tickets,
and their children are deleted at teardown; advisories carry unique
fictional GHSA-IDs. Bootstrap and reconciliation run on `db_session`, rolled
back at teardown, and the worker Redis database. All identifiers are
fictional.

The generic task terminal matrix is owned by
`test_fetch_single_cve_workflow.py` and `test_cve_fetcher_catch_up.py`, and
GHSA exception classification by `test_sync_ghsa_advisories.py`; the cases
here prove that each row of the GHSA `fetch_single()` error table reaches
its documented latest status and retry decision through the real wrappers.
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
from app.models.cve_external_identifier import CVEExternalIdentifier
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
from app.services.tickets import ghsa_advisory_record
from app.services.tickets import sync_ghsa_advisories as sync_module
from app.services.tickets.sync_ghsa_advisories import (
    GhsaResponseError,
    InvalidCveIdError,
    SyncGhsaAdvisories,
)
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
from tests.support.ghsa import GhsaServer, Responder, raising, status
from tests.support.ghsa import body as json_body

SessionFactory = Callable[[], Awaitable[AsyncSession]]

NAME: Final = "sync_ghsa_advisories"
GHSA: Final = CVESourceType.GHSA
SCHEDULE: Final = "0 */3 * * *"
TOKEN: Final = "fictional-github-token-0001"
"""A fictional `GITHUB_TOKEN`; never a real token shape."""
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
        assert SyncGhsaAdvisories.__module__ == (
            "app.services.tickets.sync_ghsa_advisories"
        )

    def test_properties_match_the_specification(self) -> None:
        assert SyncGhsaAdvisories.name == NAME
        assert SyncGhsaAdvisories.cve_source_type is GHSA
        assert SyncGhsaAdvisories.cve_source_type.value == "ghsa"
        assert SyncGhsaAdvisories.description == (
            "Sync CVE data from GitHub Advisory Database"
        )
        assert SyncGhsaAdvisories.default_schedule == SCHEDULE
        assert SyncGhsaAdvisories.default_request_delay == 1.0
        assert SyncGhsaAdvisories.source_reference_url_pattern is None

    def test_class_body_declares_exactly_the_class_structure_attributes(
        self,
    ) -> None:
        """No `Settings`, `queue`, `http_client_options`,
        `supports_fetch_single`, or `participates_in_catch_up` in the class
        body (cve-sync-ghsa.md, Class Structure; Custom settings: No)."""
        assert _class_body_assignments(SyncGhsaAdvisories) == {
            "name",
            "cve_source_type",
            "description",
            "default_schedule",
            "default_request_delay",
            "source_reference_url_pattern",
        }

    def test_inherited_defaults_apply(self) -> None:
        assert SyncGhsaAdvisories.Settings is None
        assert SyncGhsaAdvisories.queue is None
        assert SyncGhsaAdvisories.http_client_options == {}
        assert SyncGhsaAdvisories.http_client_options is BaseFetcher.http_client_options
        for inherited in ("Settings", "queue", "http_client_options"):
            assert inherited not in SyncGhsaAdvisories.__dict__, inherited

    def test_capability_flags_are_inherited_and_derived(self) -> None:
        assert SyncGhsaAdvisories.supports_fetch_single is True
        assert SyncGhsaAdvisories.participates_in_catch_up is True
        assert "supports_fetch_single" not in SyncGhsaAdvisories.__dict__
        assert "abstract" not in SyncGhsaAdvisories.__dict__

    def test_class_name_is_derived_from_the_fetcher_name(self) -> None:
        derived = "".join(part.capitalize() for part in NAME.split("_"))

        assert derived == SyncGhsaAdvisories.__name__ == "SyncGhsaAdvisories"

    def test_registered_in_both_registries(self) -> None:
        assert FETCHER_REGISTRY[NAME] is SyncGhsaAdvisories
        assert _CVE_SOURCE_TYPE_MAP[GHSA] is SyncGhsaAdvisories
        assert get_all_cve_source_types()["ghsa"] is SyncGhsaAdvisories

    def test_member_of_both_rosters(self) -> None:
        assert get_fetch_single_fetchers()["ghsa"] is SyncGhsaAdvisories
        assert get_catch_up_fetchers()[NAME] is SyncGhsaAdvisories

    def test_no_base_cve_fetcher_member_is_added(self) -> None:
        for name in ("_token", "_get_page", "_process_advisory", "_ingest"):
            assert not hasattr(BaseCVEFetcher, name), name


# ---------------------------------------------------------------------------
# Concrete compliance (testing-strategy.md, CVE Fetcher Infrastructure)
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestConcreteCompliance:
    def test_only_fetch_single_and_execute_override_the_base_contract(self) -> None:
        own = _method_names(SyncGhsaAdvisories)
        inherited_contract = _method_names(BaseCVEFetcher) | _method_names(BaseFetcher)

        assert own & inherited_contract == {"fetch_single", "execute"}
        assert SyncGhsaAdvisories.catch_up is BaseCVEFetcher.catch_up
        assert (
            SyncGhsaAdvisories.commit_and_dispatch is BaseCVEFetcher.commit_and_dispatch
        )
        assert (
            SyncGhsaAdvisories._isolated_status_commit
            is BaseCVEFetcher._isolated_status_commit
        )
        assert SyncGhsaAdvisories.run is BaseFetcher.run

    def test_typed_fetch_single_and_async_execute(self) -> None:
        assert inspect.iscoroutinefunction(SyncGhsaAdvisories.fetch_single)
        assert inspect.iscoroutinefunction(SyncGhsaAdvisories.execute)
        annotations = inspect.get_annotations(
            SyncGhsaAdvisories.fetch_single, eval_str=True
        )
        assert annotations["return"] is CVEFetchResult
        assert (
            inspect.get_annotations(SyncGhsaAdvisories._ingest, eval_str=True)["return"]
            is CVEFetchResult
        )

    def test_inline_periodic_path_constructs_the_token(self) -> None:
        """The periodic path processes paginated responses inline: it never
        delegates to `fetch_single()`, builds `CVEFetchResult` itself, and
        finalizes through the inherited `commit_and_dispatch()`."""
        periodic = "\n".join(
            inspect.getsource(method)
            for method in (
                SyncGhsaAdvisories.execute,
                SyncGhsaAdvisories._process_advisory,
                SyncGhsaAdvisories._ingest,
                SyncGhsaAdvisories._advisory_failed,
            )
        )
        names = _referenced_names(periodic)

        assert "fetch_single" not in names
        assert {"CVEFetchResult", "commit_and_dispatch", "record_failed"} <= names
        assert "record_succeeded" not in names
        assert "record_created" not in names
        assert "record_updated" not in names
        assert "get_active_ticket_cve_ids" not in names

    def test_sanitized_messages_match_the_specification(self) -> None:
        assert sync_module.TOKEN_NOT_CONFIGURED == "GITHUB_TOKEN not configured"
        assert sync_module.AUTHENTICATION_FAILED == "GitHub API authentication failed"
        assert sync_module.RATE_LIMITED == (
            "GitHub API rate limit exceeded or access denied"
        )
        assert sync_module.CONNECTION_FAILED == (
            "Failed to connect to GitHub Advisory API"
        )
        assert sync_module.UNPARSEABLE_RESPONSE == (
            "GitHub Advisory API returned unparseable response"
        )
        assert sync_module.UNTRUSTED_NEXT_URL == (
            "GitHub Advisory API returned an untrusted next-page URL"
        )
        assert sync_module.GHSA_ADVISORIES_URL == "https://api.github.com/advisories"


@pytest.mark.unit
class TestSignalClasses:
    def test_response_error_is_non_retryable_with_a_fixed_message(self) -> None:
        error = GhsaResponseError()

        assert GhsaResponseError.__bases__ == (Exception,)
        assert not issubclass(GhsaResponseError, FetcherError)
        assert str(error) == "GitHub Advisory API returned an unexpected response"
        assert is_retryable_condition(error) is False
        assert is_infrastructure_failure(error) is False

    def test_invalid_cve_id_error_is_a_module_local_cause_name(self) -> None:
        assert InvalidCveIdError.__name__ == "InvalidCveIdError"
        assert InvalidCveIdError.__module__ == sync_module.__name__
        assert issubclass(InvalidCveIdError, ValueError)
        assert not hasattr(BaseCVEFetcher, "InvalidCveIdError")


# ---------------------------------------------------------------------------
# Structural absences
# ---------------------------------------------------------------------------


_GHSA_MODULES: Final = [sync_module, ghsa_advisory_record]


@pytest.mark.unit
class TestStructuralAbsences:
    @pytest.mark.parametrize(
        "module", _GHSA_MODULES, ids=lambda module: module.__name__
    )
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

    @pytest.mark.parametrize(
        "module", _GHSA_MODULES, ids=lambda module: module.__name__
    )
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

    def test_reads_configuration_only_for_the_token(self) -> None:
        assert "app.config" not in _imported_modules(ghsa_advisory_record)
        tree = ast.parse(inspect.getsource(sync_module))
        read = {
            node.attr
            for node in ast.walk(tree)
            if isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name)
            and node.value.id == "settings"
        }
        assert read == {"github_token"}

    @pytest.mark.parametrize(
        "module", _GHSA_MODULES, ids=lambda module: module.__name__
    )
    def test_raises_no_api_facing_error(self, module: ModuleType) -> None:
        names = _referenced_names(inspect.getsource(module))

        assert not {"ErrorCode", "ServiceError", "HTTPException"} & names
        assert not [name for name in names if name.endswith("ServiceError")]

    def test_no_route_task_or_error_code_names_the_source(self) -> None:
        from app.celery_app import celery_app
        from app.main import app as api

        paths = [getattr(route, "path", "") for route in api.routes]
        assert paths
        assert not [path for path in paths if "ghsa" in path.lower()]
        assert not [name for name in celery_app.tasks if "ghsa" in name.lower()]
        assert not [
            member
            for member in ErrorCode
            if "GHSA" in member.name or "GITHUB" in member.name
        ]


# ---------------------------------------------------------------------------
# Shared harness of the wrapper tests
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def github_token(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every test sets the token itself, never relying on the environment."""
    monkeypatch.setattr(app_settings, "github_token", SecretStr(TOKEN))


@pytest.fixture
async def world(db_session_factory: SessionFactory) -> AsyncIterator[IngestionWorld]:
    created = IngestionWorld(db_session_factory, await db_session_factory())
    try:
        await created.ensure_default_setting()
        yield created
    finally:
        await created.cleanup()


class ClientServer(GhsaServer):
    """A `GhsaServer` recording every client it creates."""

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
        # The token is never a client option: it is attached per request.
        assert name == NAME
        assert options == {}
        return fake.client()

    monkeypatch.setattr(base_fetcher_module, "create_http_client", create_http_client)
    return fake


async def _active_cve(world: IngestionWorld) -> tuple[CVE, Ticket]:
    cve = await world.cve_in()
    ticket = await world.ticket(cve_id=cve.id)
    return cve, ticket


def _advisory(cve_id: object, **members: Any) -> dict[str, Any]:
    """A fictional advisory with a unique GHSA-ID and one npm package."""
    digits = uuid.uuid4().hex
    ghsa_id = f"GHSA-{digits[:4]}-{digits[4:8]}-{digits[8:12]}"
    advisory: dict[str, Any] = {
        "ghsa_id": ghsa_id,
        "html_url": f"https://github.com/advisories/{ghsa_id}",
        "cve_id": cve_id,
        "vulnerabilities": [
            {
                "package": {"ecosystem": "npm", "name": "example"},
                "vulnerable_version_range": "< 1.0",
            }
        ],
    }
    advisory.update(members)
    return advisory


def _serve(server: GhsaServer, cve: CVE) -> dict[str, Any]:
    advisory = _advisory(
        cve.cve_id,
        cvss_severities={"cvss_v3": {"vector_string": "CVSS:3.1/AV:N/E:H"}},
    )
    server.singles[cve.cve_id] = [advisory]
    return advisory


async def _identifier_count(factory: async_sessionmaker[AsyncSession], cve: CVE) -> int:
    async with factory() as session:
        count = await session.scalar(
            select(func.count())
            .select_from(CVEExternalIdentifier)
            .where(CVEExternalIdentifier.cve_id == cve.id)
        )
    return int(count or 0)


def _respond(server: GhsaServer, cve: CVE, kind: str) -> None:
    """Serve one documented `fetch_single()` error-table condition."""
    responders: dict[str, Responder] = {
        "http_401": status(401, b'{"message": "Bad credentials"}'),
        "http_403": status(403),
        "http_404": status(404),
        "http_422": status(422),
        "http_302": status(302, headers={"Location": "https://github.com/"}),
        "http_204": status(204),
        "invalid_json": status(200, b"{"),
        "undecodable": status(200, b"not gzip", headers={"Content-Encoding": "gzip"}),
        "object_root": json_body({"cve_id": cve.cve_id}),
        "non_object_first": json_body([cve.cve_id]),
        "schema_mismatch": json_body([_advisory(cve.cve_id, ghsa_id=None)]),
    }
    server.single_responses[cve.cve_id] = responders[kind]


_NON_RETRYABLE: Final[list[tuple[str, type[BaseException], str]]] = [
    ("http_401", FetcherError, "FetcherError"),
    ("http_403", httpx.HTTPStatusError, "HTTPStatusError"),
    ("http_404", httpx.HTTPStatusError, "HTTPStatusError"),
    ("http_422", httpx.HTTPStatusError, "HTTPStatusError"),
    ("http_302", httpx.HTTPStatusError, "HTTPStatusError"),
    ("http_204", GhsaResponseError, "GhsaResponseError"),
    ("invalid_json", ValueError, "JSONDecodeError"),
    ("undecodable", httpx.DecodingError, "DecodingError"),
    ("object_root", GhsaResponseError, "GhsaResponseError"),
    ("non_object_first", GhsaResponseError, "GhsaResponseError"),
    ("schema_mismatch", ValidationError, "ValidationError"),
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
        token = await on_demand.marker(cve.cve_id, GHSA.value)

        with capture_logs() as logs:
            outcome = await on_demand.run(NAME, cve.cve_id, GHSA.value, token)

        assert outcome is None
        [request] = server.requests
        assert request.url.params["cve_id"] == cve.cve_id
        assert request.headers["Authorization"] == f"Bearer {TOKEN}"
        state = await source_state(on_demand.factory, cve.id, GHSA)
        assert state is not None
        # The invalid CVSS vector is skipped without failing the advisory.
        assert state.status == CVESourceFetchStatus.SUCCESS
        assert await _identifier_count(on_demand.factory, cve) == 1
        assert on_demand.published.published(RESOLVE) == [
            {
                "ticket_id": str(ticket.id),
                "cpe_matches": [],
                "affected_cpes": [],
                "vendor_products": [],
                "resolved_packages": ["example"],
            }
        ]
        assert await on_demand.marker_value(cve.cve_id, GHSA.value) is None
        assert await fetcher_run_count(on_demand.factory, NAME) == 0
        assert events_named(logs, COMPLETED) == [
            {
                "event": COMPLETED,
                "log_level": "info",
                "outcome": "updated",
                "fetcher_name": NAME,
                "cve_id": cve.cve_id,
                "source": GHSA.value,
            }
        ]
        assert [
            entry["reason"]
            for entry in events_named(logs, "cve_cvss_candidate_skipped")
        ] == ["invalid_vector"]
        # The workflow closed the client it created.
        assert server.clients
        assert all(client.is_closed for client in server.clients)

    @pytest.mark.parametrize("answer", ["empty", "other", "null", "invalid"])
    async def test_no_usable_advisory_is_missing(
        self,
        answer: str,
        world: IngestionWorld,
        on_demand: FetchSingleHarness,
        server: ClientServer,
    ) -> None:
        cve, _ = await _active_cve(world)
        if answer != "empty":
            other = {"other": "CVE-2099-0001", "null": None, "invalid": "CVE-24-1"}
            server.singles[cve.cve_id] = [_advisory(other[answer])]
        token = await on_demand.marker(cve.cve_id, GHSA.value)

        with capture_logs() as logs:
            outcome = await on_demand.run(NAME, cve.cve_id, GHSA.value, token)

        assert outcome is None
        state = await source_state(on_demand.factory, cve.id, GHSA)
        assert state is not None
        assert state.status == CVESourceFetchStatus.MISSING
        assert await _identifier_count(on_demand.factory, cve) == 0
        assert [entry["outcome"] for entry in events_named(logs, COMPLETED)] == [
            "missing"
        ]
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
        token = await on_demand.marker(cve.cve_id, GHSA.value)

        with capture_logs() as logs, pytest.raises(error):
            await on_demand.run(NAME, cve.cve_id, GHSA.value, token)

        assert len(server.requests) == 1
        state = await source_state(on_demand.factory, cve.id, GHSA)
        assert state is not None
        assert state.status == CVESourceFetchStatus.FAILURE
        assert await _identifier_count(on_demand.factory, cve) == 0
        assert await on_demand.marker_value(cve.cve_id, GHSA.value) is None
        assert events_named(logs, RETRY_SCHEDULED) == []
        [failed] = events_named(logs, FAILED)
        assert failed["cause"] == cause
        assert failed["retries"] == 0
        assert TOKEN not in repr(logs)
        assert all(client.is_closed for client in server.clients)

    async def test_unconfigured_token_is_a_failure_without_any_request(
        self,
        world: IngestionWorld,
        on_demand: FetchSingleHarness,
        server: ClientServer,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        cve, _ = await _active_cve(world)
        _serve(server, cve)
        monkeypatch.setattr(app_settings, "github_token", SecretStr(""))
        token = await on_demand.marker(cve.cve_id, GHSA.value)

        with capture_logs() as logs, pytest.raises(FetcherError) as raised:
            await on_demand.run(NAME, cve.cve_id, GHSA.value, token)

        assert str(raised.value) == "GITHUB_TOKEN not configured"
        assert server.requests == []
        state = await source_state(on_demand.factory, cve.id, GHSA)
        assert state is not None
        assert state.status == CVESourceFetchStatus.FAILURE
        assert events_named(logs, RETRY_SCHEDULED) == []
        assert [entry["cause"] for entry in events_named(logs, FAILED)] == [
            "FetcherError"
        ]

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
        token = await on_demand.marker(cve.cve_id, GHSA.value)

        with capture_logs() as logs:
            outcome = await on_demand.run(NAME, cve.cve_id, GHSA.value, token)

        assert isinstance(outcome, FetchSingleRetry)
        assert outcome.countdown == 5
        assert is_retryable_condition(outcome.cause)
        assert await source_state(on_demand.factory, cve.id, GHSA) is None
        assert await on_demand.marker_value(cve.cve_id, GHSA.value) == token
        assert len(events_named(logs, RETRY_SCHEDULED)) == 1
        assert all(client.is_closed for client in server.clients)

    async def test_retryable_failure_after_the_last_retry_is_failure(
        self,
        world: IngestionWorld,
        on_demand: FetchSingleHarness,
        server: ClientServer,
    ) -> None:
        cve, _ = await _active_cve(world)
        server.single_responses[cve.cve_id] = status(500)
        token = await on_demand.marker(cve.cve_id, GHSA.value)

        with capture_logs() as logs, pytest.raises(httpx.HTTPStatusError):
            await on_demand.run(
                NAME, cve.cve_id, GHSA.value, token, attempt=LAST_ATTEMPT
            )

        state = await source_state(on_demand.factory, cve.id, GHSA)
        assert state is not None
        assert state.status == CVESourceFetchStatus.FAILURE
        assert events_named(logs, RETRY_SCHEDULED) == []
        assert [entry["stage"] for entry in events_named(logs, FAILED)] == [
            "pre_finalization"
        ]


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

        assert [request.url.params["cve_id"] for request in server.requests] == [
            cve.cve_id
        ]
        # The catch-up flushes, then the finalizer commits once and only
        # then drains and publishes.
        events = catch_up.events
        commit = events.index("commit")
        assert events.count("commit") == 1
        assert events[commit - 1] == "flush"
        assert commit < events.index("drain") < events.index(f"publish:{RESOLVE}")
        state = await source_state(catch_up.factory, cve.id, GHSA)
        assert state is not None
        assert state.status == CVESourceFetchStatus.SUCCESS
        [handoff] = catch_up.published.published(RESOLVE)
        assert handoff["ticket_id"] == str(ticket.id)
        assert handoff["resolved_packages"] == ["example"]
        assert await fetcher_run_count(catch_up.factory, NAME) == 0
        catch_up.engine.dispose.assert_awaited_once()
        assert all(client.is_closed for client in server.clients)

    async def test_empty_answer_writes_missing_and_returns(
        self,
        world: IngestionWorld,
        catch_up: CatchUpHarness,
        server: ClientServer,
    ) -> None:
        cve, ticket = await _active_cve(world)

        await fetchers.run_catch_up_async(NAME, str(ticket.id))

        state = await source_state(catch_up.factory, cve.id, GHSA)
        assert state is not None
        assert state.status == CVESourceFetchStatus.MISSING
        assert "commit" not in catch_up.events
        assert "status:commit" in catch_up.events
        assert len(server.requests) == 1
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
            state = await source_state(catch_up.factory, cve.id, GHSA)
            assert state is not None
            assert state.status == CVESourceFetchStatus.FAILURE

        assert len(server.requests) == LAST_ATTEMPT + 1
        assert "commit" not in catch_up.events
        assert catch_up.events.count("status:commit") == LAST_ATTEMPT + 1
        assert catch_up.engine.dispose.await_count == LAST_ATTEMPT + 1
        assert all(client.is_closed for client in server.clients)

    @pytest.mark.parametrize("kind", ["http_401", "schema_mismatch", "token"])
    async def test_non_retryable_failure_writes_failure(
        self,
        kind: str,
        world: IngestionWorld,
        catch_up: CatchUpHarness,
        server: ClientServer,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        cve, ticket = await _active_cve(world)
        if kind == "token":
            _serve(server, cve)
            monkeypatch.setattr(app_settings, "github_token", SecretStr(""))
        else:
            _respond(server, cve, kind)

        with pytest.raises((FetcherError, ValidationError)) as raised:
            await fetchers.run_catch_up_async(NAME, str(ticket.id))

        assert not is_retryable_condition(raised.value)
        state = await source_state(catch_up.factory, cve.id, GHSA)
        assert state is not None
        assert state.status == CVESourceFetchStatus.FAILURE
        assert await _identifier_count(catch_up.factory, cve) == 0
        assert "commit" not in catch_up.events
        assert len(server.requests) == (0 if kind == "token" else 1)


# ---------------------------------------------------------------------------
# Broadcast refetch preparation with GHSA disabled
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestBroadcastRefetch:
    async def test_disabled_ghsa_is_reported_and_not_published(
        self,
        world: IngestionWorld,
        real_session_factory: async_sessionmaker[AsyncSession],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        registry = get_fetch_single_fetchers()
        assert registry["ghsa"] is SyncGhsaAdvisories
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
                    real_session_factory, fetcher_cls.name, enabled=source != "ghsa"
                )

            result = await cve_service.refetch_cve(
                cve_id=cve.cve_id,
                source=None,
                caller=ALL_SCOPE,
                session_factory=real_session_factory,
            )
        finally:
            await delete_fetcher_rows(real_session_factory, names)

        enabled = sorted(source for source in registry if source != "ghsa")
        assert result.sources_disabled == ["ghsa"]
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
        assert config.request_delay == SyncGhsaAdvisories.default_request_delay == 1.0
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
        # 0 */3 * * *
        assert entry.schedule.minute == {0}
        assert entry.schedule.hour == set(range(0, 24, 3))
        assert entry.schedule.day_of_month == set(range(1, 32))
        assert entry.schedule.month_of_year == set(range(1, 13))
        assert entry.schedule.day_of_week == set(range(7))
        assert "queue" not in entry.options
        assert entry.options["time_limit"] == 3600
        assert entry.options["soft_time_limit"] == 3420
