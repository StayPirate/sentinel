"""End-to-end tests for `GET /api/v1/cves/{cve_id}/sources`
(`backend/app/api/v1/cves.py`).

See docs/features/tickets/cve-service.md (CVE Source Status: Response
schema, Status values, Service contract, Redis graceful degradation;
Transaction Ownership), docs/api-spec.md (Optional Authentication on Public
Endpoints; Infrastructure Dependency Errors; CVE Accessibility Check;
Anti-Enumeration Boundary; CVE Identifier Resolution), and
docs/features/platform/testing-strategy.md (CVE and Source Reads >
Per-CVE source status).

The status derivation, KEV projection, ordering, accessibility races, and
Redis I/O placement matrix lives in
tests/test_services/test_cve_source_status.py; these tests cover the HTTP
contract: wire format, optional authentication, anti-enumeration, the
status-reporting exception for Redis failures, handler delegation, and
OpenAPI. The service-owned session factory dependency is overridden with a
factory joined to the `db_session` connection, so the service observes the
test's rows and the per-test rollback still discards them.
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable, Iterator
from datetime import UTC, datetime
from typing import Any, Final
from unittest.mock import AsyncMock

import pytest
import redis.asyncio as redis_asyncio
from httpx import AsyncClient
from redis.exceptions import ConnectionError as RedisConnectionError
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncSession, async_sessionmaker

from app.api.dependencies import SESSION_COOKIE_NAME
from app.api.v1 import cves as cves_module
from app.core.enums import CVESourceType, Scope
from app.database import async_session_factory
from app.main import app
from app.models.cve import CVE
from app.models.ticket import Ticket
from app.models.user import User
from app.services import cve_service
from app.services.cve_service import (
    KEV_FETCHER_NAME,
    CVESourceStatusResult,
    fetch_pending_key,
)
from app.services.ticket_visibility import ANONYMOUS_CALLER, TicketCaller
from tests.support.cve_source_status import (
    clear_fetcher_registries,
    define_cve_fetcher,
    define_kev_fetcher,
)

Factory = Callable[..., Awaitable[Any]]

_PATH: Final = "/api/v1/cves/{cve_id}/sources"
_NOT_FOUND: Final = {"code": "CVE_NOT_FOUND", "detail": "CVE not found."}
_UNAUTHENTICATED: Final = {
    "code": "AUTH_NOT_AUTHENTICATED",
    "detail": "Authentication required",
}
_ITEM_FIELDS: Final = {
    "source",
    "status",
    "fetched_at",
    "first_failed_at",
    "registered",
    "refetchable",
    "enabled",
}

CREATED: Final = datetime(2099, 3, 1, 9, 0, tzinfo=UTC)
LEGACY_FETCHED: Final = datetime(2099, 3, 1, 12, 0, tzinfo=UTC)
KEV_RUN_FINISHED: Final = datetime(2099, 6, 28, 4, 0, tzinfo=UTC)
MITRE_FETCHED: Final = datetime(2099, 6, 28, 8, 0, tzinfo=UTC)
MITRE_FIRST_FAILED: Final = datetime(2099, 6, 20, 8, 0, tzinfo=UTC)
NVD_FETCHED: Final = datetime(2099, 6, 28, 10, 30, tzinfo=UTC)


def _url(cve_id: str) -> str:
    return _PATH.format(cve_id=cve_id)


def _random_cve_id() -> str:
    return f"CVE-2099-{uuid.uuid4().int % 10**9:09d}"


def _item(
    source: str,
    status: str,
    fetched_at: str | None = None,
    first_failed_at: str | None = None,
    *,
    registered: bool = True,
    refetchable: bool = True,
    enabled: bool = True,
) -> dict[str, Any]:
    return {
        "source": source,
        "status": status,
        "fetched_at": fetched_at,
        "first_failed_at": first_failed_at,
        "registered": registered,
        "refetchable": refetchable,
        "enabled": enabled,
    }


@pytest.fixture
def status_sessions(db_session: AsyncSession) -> Iterator[None]:
    """Point the service-owned session factory at the test transaction."""
    assert isinstance(db_session.bind, AsyncConnection)
    factory = async_sessionmaker(
        bind=db_session.bind,
        class_=AsyncSession,
        expire_on_commit=False,
        join_transaction_mode="create_savepoint",
    )
    dependency = cves_module.get_cve_source_status_session_factory
    app.dependency_overrides[dependency] = lambda: factory
    try:
        yield
    finally:
        app.dependency_overrides.pop(dependency, None)


@pytest.fixture
def registry(isolated_fetcher_registries: None) -> None:
    """Both registries cleared; the fixture restores them at teardown."""
    clear_fetcher_registries()


@pytest.fixture
def authenticated_user(
    _authenticated_user_and_client: tuple[User, AsyncClient],
) -> User:
    """The role-less (`non_confidential` scope) `User` behind
    `authenticated_client`."""
    return _authenticated_user_and_client[0]


async def _arrange_roster(
    redis_client: redis_asyncio.Redis,
    *,
    cve_factory: Factory,
    cve_source_factory: Factory,
    fetcher_config_factory: Factory,
    fetcher_run_factory: Factory,
) -> CVE:
    """The documented example roster plus a pending and a disabled source:
    KEV `missing` from a later successful run, a historical source, MITRE
    in a failure streak, NVD `success`, Red Hat pending without a row, and
    a disabled OSV whose marker is suppressed."""
    define_kev_fetcher()
    define_cve_fetcher(CVESourceType.MITRE)
    define_cve_fetcher(CVESourceType.NVD)
    define_cve_fetcher(CVESourceType.REDHAT)
    osv = define_cve_fetcher(CVESourceType.OSV, refetchable=False)
    await fetcher_config_factory(fetcher_name=KEV_FETCHER_NAME)
    await fetcher_config_factory(fetcher_name=osv.name, enabled=False)
    await fetcher_run_factory(
        fetcher_name=KEV_FETCHER_NAME, status="success", finished_at=KEV_RUN_FINISHED
    )
    cve: CVE = await cve_factory(cve_id=_random_cve_id(), created_at=CREATED)
    for source, status, fetched_at, first_failed_at in (
        ("nvd", "success", NVD_FETCHED, None),
        ("mitre", "failure", MITRE_FETCHED, MITRE_FIRST_FAILED),
        ("legacy_source", "success", LEGACY_FETCHED, None),
    ):
        await cve_source_factory(
            cve_id=cve.id,
            source=source,
            status=status,
            fetched_at=fetched_at,
            first_failed_at=first_failed_at,
        )
    for source in ("redhat", "osv"):
        await redis_client.set(fetch_pending_key(cve.cve_id, source), "1")
    return cve


_ROSTER: Final = [
    _item("kev", "missing", "2099-06-28T04:00:00Z", refetchable=False),
    _item(
        "legacy_source",
        "success",
        "2099-03-01T12:00:00Z",
        registered=False,
        refetchable=False,
        enabled=False,
    ),
    _item("mitre", "failure", "2099-06-28T08:00:00Z", "2099-06-20T08:00:00Z"),
    _item("nvd", "success", "2099-06-28T10:30:00Z"),
    _item("osv", "not_attempted", refetchable=False, enabled=False),
    _item("redhat", "pending"),
]


@pytest.mark.e2e
@pytest.mark.usefixtures("status_sessions", "registry")
class TestCVESourceStatus:
    async def test_anonymous_request_returns_the_complete_roster(
        self,
        client: AsyncClient,
        redis_client: redis_asyncio.Redis,
        cve_factory: Factory,
        cve_source_factory: Factory,
        fetcher_config_factory: Factory,
        fetcher_run_factory: Factory,
    ) -> None:
        cve = await _arrange_roster(
            redis_client,
            cve_factory=cve_factory,
            cve_source_factory=cve_source_factory,
            fetcher_config_factory=fetcher_config_factory,
            fetcher_run_factory=fetcher_run_factory,
        )

        response = await client.get(_url(cve.cve_id))

        assert response.status_code == 200
        assert response.headers["content-type"] == "application/json"
        body = response.json()
        assert set(body) == {"data"}
        assert body == {"data": _ROSTER}
        for item in body["data"]:
            assert set(item) == _ITEM_FIELDS
        assert str(cve.id) not in response.text

    async def test_authenticated_caller_with_a_grant_sees_a_confidential_cve(
        self,
        authenticated_client: AsyncClient,
        authenticated_user: User,
        redis_client: redis_asyncio.Redis,
        cve_factory: Factory,
        ticket_factory: Factory,
        ticket_access_grant_factory: Factory,
        cve_source_factory: Factory,
        fetcher_config_factory: Factory,
        fetcher_run_factory: Factory,
    ) -> None:
        cve = await _arrange_roster(
            redis_client,
            cve_factory=cve_factory,
            cve_source_factory=cve_source_factory,
            fetcher_config_factory=fetcher_config_factory,
            fetcher_run_factory=fetcher_run_factory,
        )
        ticket: Ticket = await ticket_factory(cve_id=cve.id, is_confidential=True)
        await ticket_access_grant_factory(
            ticket_id=ticket.id, user_id=authenticated_user.id
        )

        response = await authenticated_client.get(_url(cve.cve_id))

        assert response.status_code == 200
        assert response.json() == {"data": _ROSTER}
        assert str(ticket.id) not in response.text

    async def test_accessible_cve_without_any_source_returns_an_empty_list(
        self, client: AsyncClient, cve_factory: Factory
    ) -> None:
        cve: CVE = await cve_factory(cve_id=_random_cve_id())

        response = await client.get(_url(cve.cve_id))

        assert response.status_code == 200
        assert response.json() == {"data": []}

    async def test_every_not_found_cause_is_identical_for_both_callers(
        self,
        authenticated_client: AsyncClient,
        cve_factory: Factory,
        ticket_factory: Factory,
        cve_source_factory: Factory,
    ) -> None:
        define_cve_fetcher(CVESourceType.NVD)
        visible: CVE = await cve_factory(cve_id="CVE-2099-62001")
        confidential: CVE = await cve_factory(cve_id="CVE-2099-62002")
        await ticket_factory(cve_id=confidential.id, is_confidential=True)
        await cve_source_factory(cve_id=confidential.id, source="nvd")
        targets = [
            "not-a-cve",
            "cve-2099-62001",
            "CVE-2099-62001%20",
            "CVE-2099-" + "1" * 12,
            str(visible.id),
            "CVE-2099-99999",
            confidential.cve_id,
        ]
        token = authenticated_client.cookies[SESSION_COOKIE_NAME]

        authenticated = [await authenticated_client.get(_url(t)) for t in targets]
        authenticated_client.cookies.delete(SESSION_COOKIE_NAME)
        anonymous = [await authenticated_client.get(_url(t)) for t in targets]
        authenticated_client.cookies.set(SESSION_COOKIE_NAME, token)

        for target, response in zip(
            targets * 2, authenticated + anonymous, strict=True
        ):
            assert response.status_code == 404, target
            assert response.json() == _NOT_FOUND, target
            assert response.headers["content-type"] == "application/json"
        assert len({r.content for r in authenticated + anonymous}) == 1

    @pytest.mark.parametrize(
        "credential",
        [
            {"headers": {"Authorization": "Bearer invalid-token"}},
            {"cookies": {SESSION_COOKIE_NAME: "invalid-session-token"}},
        ],
        ids=["bearer", "cookie"],
    )
    @pytest.mark.parametrize("cve_id", ["CVE-2099-80001", "x"])
    async def test_invalid_selected_credential_returns_401_before_any_read(
        self,
        client: AsyncClient,
        cve_factory: Factory,
        monkeypatch: pytest.MonkeyPatch,
        credential: dict[str, dict[str, str]],
        cve_id: str,
    ) -> None:
        await cve_factory(cve_id="CVE-2099-80001")
        spy = AsyncMock()
        monkeypatch.setattr(cve_service, "get_cve_source_status", spy)
        for name, value in credential.get("cookies", {}).items():
            client.cookies.set(name, value)

        response = await client.get(_url(cve_id), headers=credential.get("headers", {}))

        assert response.status_code == 401
        assert response.json() == _UNAUTHENTICATED
        spy.assert_not_awaited()

    async def test_redis_failure_returns_200_with_the_durable_view(
        self,
        client: AsyncClient,
        redis_client: redis_asyncio.Redis,
        cve_factory: Factory,
        cve_source_factory: Factory,
        fetcher_config_factory: Factory,
        fetcher_run_factory: Factory,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The status-reporting exception: only the transient `pending`
        overlay is lost; Red Hat reports its durable `not_attempted`."""
        cve = await _arrange_roster(
            redis_client,
            cve_factory=cve_factory,
            cve_source_factory=cve_source_factory,
            fetcher_config_factory=fetcher_config_factory,
            fetcher_run_factory=fetcher_run_factory,
        )
        failing = AsyncMock()
        failing.mget.side_effect = RedisConnectionError("fictional refusal")
        monkeypatch.setattr(cve_service, "_new_redis_client", lambda: failing)

        response = await client.get(_url(cve.cve_id))

        assert response.status_code == 200
        assert response.json() == {
            "data": [
                *_ROSTER[:-1],
                _item("redhat", "not_attempted"),
            ]
        }
        failing.mget.assert_awaited_once()
        failing.aclose.assert_awaited_once()


@pytest.mark.e2e
@pytest.mark.usefixtures("status_sessions")
class TestHandlerDelegation:
    @pytest.mark.parametrize("authenticated", [False, True])
    async def test_raw_path_caller_and_session_factory_reach_the_service(
        self,
        authenticated_client: AsyncClient,
        authenticated_user: User,
        monkeypatch: pytest.MonkeyPatch,
        authenticated: bool,
    ) -> None:
        spy = AsyncMock(return_value=CVESourceStatusResult(entries=()))
        monkeypatch.setattr(cve_service, "get_cve_source_status", spy)
        if not authenticated:
            authenticated_client.cookies.delete(SESSION_COOKIE_NAME)

        response = await authenticated_client.get(_url("cve-2099-1"))

        assert response.status_code == 200
        assert response.json() == {"data": []}
        override = app.dependency_overrides[
            cves_module.get_cve_source_status_session_factory
        ]()
        expected_caller = (
            TicketCaller.authenticated(authenticated_user.id, Scope.NON_CONFIDENTIAL)
            if authenticated
            else ANONYMOUS_CALLER
        )
        spy.assert_awaited_once_with(
            "cve-2099-1", expected_caller, session_factory=override
        )


@pytest.mark.e2e
class TestGetCVESourceStatusSessionFactory:
    def test_returns_the_shared_application_session_factory(self) -> None:
        """Every request test overrides this dependency; the default
        implementation is exercised directly, mirroring
        `TestGetFetcherTriggerSessionFactory`."""
        assert (
            cves_module.get_cve_source_status_session_factory() is async_session_factory
        )


# ---------------------------------------------------------------------------
# OpenAPI contract
# ---------------------------------------------------------------------------


def _operation() -> dict[str, Any]:
    operation: dict[str, Any] = app.openapi()["paths"][_PATH]["get"]
    return operation


@pytest.mark.unit
class TestOpenApiContract:
    def test_get_is_the_only_documented_operation(self) -> None:
        assert set(app.openapi()["paths"][_PATH]) == {"get"}

    def test_operation_has_summary_description_and_tag(self) -> None:
        operation = _operation()

        assert operation["summary"]
        assert operation["description"]
        assert operation["tags"] == ["CVEs"]

    def test_only_the_path_parameter_without_pagination_or_sorting(self) -> None:
        (parameter,) = _operation()["parameters"]

        assert (parameter["name"], parameter["in"]) == ("cve_id", "path")
        assert "pattern" not in parameter["schema"]

    def test_documents_a_200_body_and_a_404_error(self) -> None:
        responses = _operation()["responses"]

        assert responses["200"]["content"]["application/json"]["schema"][
            "$ref"
        ].endswith("/CVESourceStatusResponse")
        assert responses["404"]["description"]
        assert responses["404"]["content"]["application/json"]["schema"][
            "$ref"
        ].endswith("/ErrorResponse")

    def test_response_schemas_expose_exactly_the_specified_fields(self) -> None:
        schemas = app.openapi()["components"]["schemas"]
        item = schemas["CVESourceStatusItem"]

        assert set(schemas["CVESourceStatusResponse"]["properties"]) == {"data"}
        assert set(item["properties"]) == _ITEM_FIELDS
        assert set(item["required"]) == _ITEM_FIELDS
        status = item["properties"]["status"]
        if "$ref" in status:
            status = schemas[status["$ref"].rsplit("/", 1)[1]]
        assert set(status["enum"]) == {
            "success",
            "failure",
            "missing",
            "pending",
            "not_attempted",
        }
        assert "meta" not in schemas["CVESourceStatusResponse"]["properties"]
