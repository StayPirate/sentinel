"""End-to-end tests for `POST /api/v1/tickets/{ticket_id}/packages`
(`add_ticket_package`, backend/app/api/v1/ticket_packages.py).

Owning specifications:

- docs/features/packages/package-model.md (API Endpoints; Add Package to
  Ticket; Adding Packages to a Ticket, public precedence 1-11 and
  Idempotency).
- docs/features/packages/package-maintainership.md (Locked mutation: the
  public response exposes no maintainer identity or count; Testing
  Requirements: maintainer-only public response, a maintainer without the
  capability).
- docs/features/tickets/ticket-audit-log.md (`package_added`,
  `package_maintainer_added`).
- docs/api-spec.md (Authorization Chain Evaluation Order flow 4, Global
  Responses, Ticket Accessibility Check, Ticket Identifier Resolution,
  Manual-Zone Mutability Guard).
- docs/features/platform/testing-strategy.md (API Endpoints; Ticket
  Accessibility: Locked mutations, External I/O and post-commit effects,
  Authentication, authorization, and anti-enumeration, Ticket identifier
  coverage; Ticket Convergence Publication Handoff, automatic API owner;
  Concurrency Testing; Audit Trail Testing).

These tests cover the HTTP boundary only: authentication and the
`manage_packages` check before any Ticket lookup, the identical not-found
bodies, request validation before any SMELT request, the documented
success bodies, the mapping of every service exception (with fixed,
sanitized details) in the documented public precedence, the drain of a
`Resolved` regression by the API transaction owner, and OpenAPI. The
orchestrator matrices (every SMELT failure category, every guard and
outcome combination, the complete race matrix) are proven in
`tests/test_services/test_add_package_to_ticket.py` and
`tests/test_services/test_add_package_to_ticket_races.py`; each HTTP case
here is a representative of its documented row.

Two worlds serve the requests through the production `app.database.get_db`
(its commit, rollback, and post-commit callbacks, so the API convergence
drain runs):

- `api`: request sessions join the per-test `db_session` connection with
  `join_transaction_mode="create_savepoint"` (the pattern of
  `tests/test_api/test_ticket_convergence_api_drain.py`), so a request
  commit is a savepoint release rolled back at teardown;
- `committed`: request sessions are independent pooled connections of the
  test engine, and setup rows are committed through `CommittedWorld`
  (`tests/support/package_records_races.py`) and deleted explicitly at
  teardown. Only the independent-session races use it: while the request
  is deterministically paused inside a SMELT request (a `Pause` of the
  `PackageSmelt` fake), an independent session commits a visibility loss.

SMELT is the in-process `PackageSmelt` fake (`tests/support/
package_addition.py`), injected by overriding the route's
`get_package_addition_http_client` dependency; `SMELT_API_URL` is the
fictional test origin. The broker call (`task_publication.publish_task`)
is substituted by a recorder. Unless a test states otherwise, a Ticket is
CVE-less with `severity_manual = High`, the service's UTC date is the
controlled `EVAL`, and a catalog Product expected to match is in General
Support with a `NULL` threshold and published in the current catalog
snapshot (`SNAPSHOT_AT`), so a created occurrence is eligible. Expected
values are transcribed from the specifications, never computed with the
module under test.
"""

from __future__ import annotations

import asyncio
import contextlib
import uuid
from collections.abc import (
    AsyncIterator,
    Awaitable,
    Callable,
    Iterable,
    Iterator,
    MutableMapping,
)
from dataclasses import dataclass, field
from typing import Any
from unittest.mock import AsyncMock

import httpx
import pytest
import pytest_asyncio
import redis.asyncio as redis_asyncio
from celery.exceptions import OperationalError as BrokerOperationalError
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncSession, async_sessionmaker
from structlog.contextvars import merge_contextvars
from structlog.testing import capture_logs

from app import database
from app.api.v1 import ticket_packages as route
from app.config import settings
from app.core.enums import (
    PackageStatus,
    Role,
    SessionCreationReason,
    TicketStatus,
    WorkflowType,
)
from app.database import get_db
from app.main import app
from app.models.product import Product
from app.models.session import Session as SessionRow
from app.models.ticket import Ticket
from app.models.user import User
from app.services import package_service, task_publication, ticket_service, user_service
from app.services.session_service import create_session
from tests.support.cvss_chain import DEFAULT_VERSION
from tests.support.package_addition import (
    Kind,
    PackageSmelt,
    Pause,
    Respond,
    codestream,
    fail,
    maintained,
    maintainership,
    not_found,
    publish,
    reply,
)
from tests.support.package_records import (
    NEW_TRACK,
    Tree,
    catalog_product,
    maintainer_event,
    maintainers,
    new_occurrence,
    package_added_event,
    package_tree,
    seed_maintainer,
    seed_occurrence,
    seed_package,
    seed_track,
    seed_user,
    ticket_row,
    tree_rows,
)
from tests.support.package_records_races import (
    LOSSES,
    WAIT,
    committed_state,
    committed_world,
    protected_state,
    world_product,
)
from tests.support.smelt import SMELT_TEST_API_URL
from tests.support.suse_cvss import assignment_event
from tests.support.suse_cvss_races import CommittedWorld, prepare_loss
from tests.support.ticket_api import (
    FORBIDDEN,
    INVALID_LOCATORS,
    MAX_SEQUENCE,
    NOT_FOUND,
    NOT_MUTABLE,
    UNAUTHENTICATED,
    locator,
)
from tests.support.ticket_mutations import (
    EVAL,
    TicketFactory,
    cveless,
    status_event,
    ticket_events_by_id,
)

Factory = Callable[..., Awaitable[Any]]
Logs = list[MutableMapping[str, Any]]

PATH = "/api/v1/tickets/{ticket_id}/packages"
PKG = "fictional-libexample"
IBS_REF = "Fictional:Product:15-SP7:Update"
GIT_REF = "fictional/slfo-1.1"
ABSENT = "cpe:/o:example:absent:1"
"""A CPE that no catalog Product carries."""

MARKER = "fictional-private-marker-7f3a"
"""A private string placed in SMELT bodies and exception messages; it must
never reach a response."""

BROKER_URL = "amqp://sentinel-user:fictional-secret@broker.example.test:5672//"
"""A fictional credential-bearing broker URL carried by the injected error."""

BOTH = ["maintained", "maintainership"]
"""The two SMELT requests of a request whose package targets resolved."""

PACKAGE_NAME_PATTERN = r"^[a-zA-Z0-9][a-zA-Z0-9._+\-]{0,253}[a-zA-Z0-9]$"
"""package-model.md, Add Package to Ticket, request body table."""

RESULT_FIELDS = {
    "package_name",
    "tracks_created",
    "tracks_skipped",
    "products_created",
    "products_skipped",
}
"""package-model.md, Add Package to Ticket, Response (201 Created)."""

SMELT_UNAVAILABLE = {"code": "SMELT_UNAVAILABLE", "detail": "SMELT is unavailable."}
CATALOG_NOT_READY = {
    "code": "PRODUCT_CATALOG_NOT_READY",
    "detail": "Product catalog is not ready.",
}
NOT_FOUND_IN_SMELT = {
    "code": "PACKAGE_NOT_FOUND_IN_SMELT",
    "detail": "Package not found in SMELT.",
}
TARGETS_UNRESOLVED = {
    "code": "PACKAGE_TARGETS_UNRESOLVED",
    "detail": "No package target resolves to a current catalog Product.",
}
ALREADY_EXCLUDED = {
    "code": "PACKAGE_ALREADY_EXCLUDED",
    "detail": "Package is excluded from this Ticket; restore it instead.",
}
"""The fixed, sanitized error bodies of the endpoint-specific codes."""

FEATURE_EVENTS = {
    "ticket_convergence_publication_failed",
    "ticket_convergence_dispatch_failed",
    "post_commit_callback_failed",
}
"""The feature-owned and generic callback events these tests account for."""

NEW = TicketStatus.NEW
ANALYSIS = TicketStatus.ANALYSIS
RESOLVED = TicketStatus.RESOLVED


def _url(ticket: Ticket | str) -> str:
    return PATH.format(ticket_id=ticket if isinstance(ticket, str) else locator(ticket))


def _data(
    tracks_created: int,
    tracks_skipped: int,
    products_created: int,
    products_skipped: int,
    package_name: str = PKG,
) -> dict[str, Any]:
    """The complete 201 body."""
    return {
        "data": {
            "package_name": package_name,
            "tracks_created": tracks_created,
            "tracks_skipped": tracks_skipped,
            "products_created": products_created,
            "products_skipped": products_skipped,
        }
    }


def _serve(
    smelt: PackageSmelt, *entries: dict[str, Any], emails: Iterable[str] = ()
) -> None:
    """Both SMELT endpoints succeed with `entries` and the maintainer
    `emails`."""
    smelt.responses["maintained"] = reply(200, maintained(*entries))
    smelt.responses["maintainership"] = reply(200, maintainership(*emails))


async def _current(db: AsyncSession, count: int = 1) -> list[Product]:
    """`count` catalog Products published in the current snapshot."""
    products = [await catalog_product(db) for _ in range(count)]
    await publish(db, *products)
    return products


def _feature_logs(logs: Logs) -> Logs:
    return [log for log in logs if log["event"] in FEATURE_EVENTS]


# ---------------------------------------------------------------------------
# Shared fixtures: clocks, SMELT origin, SMELT fake, broker recorder
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _clock(monkeypatch: pytest.MonkeyPatch) -> None:
    """The service's UTC date is the controlled `EVAL`."""
    monkeypatch.setattr(package_service, "_utc_today", lambda: EVAL)


@pytest.fixture(autouse=True)
def _smelt_api_url(monkeypatch: pytest.MonkeyPatch) -> None:
    """Both SMELT clients build their URLs from the fictional test origin."""
    monkeypatch.setattr(settings, "smelt_api_url", SMELT_TEST_API_URL)


@pytest.fixture
def smelt() -> Iterator[PackageSmelt]:
    """The SMELT fake behind the route's HTTP client dependency. Without
    configured responses, every request is recorded and answered with an
    HTTP 500."""
    server = PackageSmelt()

    async def _client() -> AsyncIterator[httpx.AsyncClient]:
        async with server.client() as client:
            yield client

    app.dependency_overrides[route.get_package_addition_http_client] = _client
    try:
        yield server
    finally:
        app.dependency_overrides.pop(route.get_package_addition_http_client, None)


class _RequestSessions:
    """Stands in for `app.database.async_session_factory`, recording every
    request session that the real `get_db()` opens."""

    def __init__(self, inner: async_sessionmaker[AsyncSession]) -> None:
        self._inner = inner
        self.sessions: list[AsyncSession] = []

    def __call__(self) -> AsyncSession:
        session = self._inner()
        self.sessions.append(session)
        return session

    def any_in_transaction(self) -> bool:
        return any(session.in_transaction() for session in self.sessions)


@dataclass
class _Publish:
    """Substitute for `task_publication.publish_task` recording each call."""

    sessions: _RequestSessions | None = None
    error: BaseException | None = None
    calls: list[dict[str, Any]] = field(default_factory=list)
    in_transaction: list[bool] = field(default_factory=list)

    async def __call__(self, task_name: str, **options: Any) -> None:
        self.calls.append({"task_name": task_name, **options})
        if self.sessions is not None:
            self.in_transaction.append(self.sessions.any_in_transaction())
        if self.error is not None:
            raise self.error

    def ticket_ids(self) -> list[tuple[str, str]]:
        return [(c["task_name"], c["kwargs"]["ticket_id"]) for c in self.calls]


@pytest.fixture
def broker(monkeypatch: pytest.MonkeyPatch) -> _Publish:
    recorder = _Publish()
    monkeypatch.setattr(task_publication, "publish_task", recorder)
    return recorder


# ---------------------------------------------------------------------------
# Savepoint-joined application (real `get_db`)
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _Caller:
    user: User
    headers: dict[str, str]


@dataclass
class _Api:
    client: AsyncClient
    db: AsyncSession
    smelt: PackageSmelt
    sessions: _RequestSessions

    async def caller(self, *roles: Role) -> _Caller:
        """A committed active User holding `roles` and its Bearer credential."""
        user = await seed_user(self.db, roles=roles)
        created = await create_session(
            self.db,
            user,
            SessionCreationReason.LOCAL_LOGIN,
            expected_password_hash=None,
        )
        assert created is not None
        await self.db.commit()
        return _Caller(user, {"Authorization": f"Bearer {created.token}"})

    async def post(
        self,
        ticket: Ticket | str,
        *,
        caller: _Caller | None = None,
        json: Any = None,
        headers: dict[str, str] | None = None,
        package_name: str = PKG,
    ) -> httpx.Response:
        """Commit the setup, then send the request."""
        await self.db.commit()
        return await self.client.post(
            _url(ticket),
            json={"package_name": package_name} if json is None else json,
            headers=headers
            if headers is not None
            else (caller.headers if caller else {}),
        )


@pytest_asyncio.fixture
async def api(
    db_session: AsyncSession,
    system_setting_factory: Factory,
    redis_client: redis_asyncio.Redis,
    smelt: PackageSmelt,
    broker: _Publish,
    monkeypatch: pytest.MonkeyPatch,
) -> AsyncIterator[_Api]:
    """A client served by the production `get_db()` over sessions joined to
    `db_session`'s connection (see the module docstring). `redis_client`
    isolates the session liveness cache."""
    assert get_db not in app.dependency_overrides
    await system_setting_factory(key="default_cvss_version", value=DEFAULT_VERSION)
    await db_session.commit()
    connection = db_session.bind
    assert isinstance(connection, AsyncConnection)
    sessions = _RequestSessions(
        async_sessionmaker(
            bind=connection,
            class_=AsyncSession,
            expire_on_commit=False,
            join_transaction_mode="create_savepoint",
        )
    )
    broker.sessions = sessions
    monkeypatch.setattr(database, "async_session_factory", sessions)
    async with AsyncClient(
        transport=ASGITransport(app=app, raise_app_exceptions=False),
        base_url="http://test",
    ) as client:
        yield _Api(client, db_session, smelt, sessions)


async def _state(db: AsyncSession, *tickets: Ticket) -> tuple[Any, ...]:
    """Everything a rejected request must leave unchanged: each Ticket's
    status and assignee, audit events, package-tree rows, and maintainer
    associations."""
    return (
        [await ticket_row(db, t.id) for t in tickets],
        [await ticket_events_by_id(db, t.id) for t in tickets],
        [await tree_rows(db, t.id) for t in tickets],
        [await maintainers(db, t.id) for t in tickets],
    )


def _forbid_lookups(monkeypatch: pytest.MonkeyPatch) -> list[AsyncMock]:
    """Replace the preliminary Ticket lookup and the orchestrator with spies
    that must stay unused."""
    spies = [AsyncMock(), AsyncMock()]
    monkeypatch.setattr(ticket_service, "resolve_ticket_locator", spies[0])
    monkeypatch.setattr(package_service, "add_package_to_ticket", spies[1])
    return spies


def _record_role_loads(monkeypatch: pytest.MonkeyPatch) -> list[uuid.UUID]:
    """Record every role load (the capability work of a request)."""
    calls: list[uuid.UUID] = []
    original = user_service.get_user_roles

    async def _spy(db: AsyncSession, user_id: uuid.UUID) -> list[Role]:
        calls.append(user_id)
        return await original(db, user_id)

    monkeypatch.setattr(user_service, "get_user_roles", _spy)
    return calls


# ---------------------------------------------------------------------------
# 1. Authentication and capability before any Ticket lookup (flow 4, step 1)
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestAuthenticationAndCapability:
    @pytest.mark.parametrize(
        "headers",
        [
            pytest.param({}, id="missing"),
            pytest.param({"Authorization": "Bearer invalid-token"}, id="invalid"),
        ],
    )
    async def test_credential_failure_returns_401_before_capability_work(
        self,
        api: _Api,
        ticket_factory: TicketFactory,
        monkeypatch: pytest.MonkeyPatch,
        headers: dict[str, str],
    ) -> None:
        """The global 401 for an existing and a missing Ticket, before any
        role load, Ticket lookup, orchestration, or SMELT request."""
        ticket = await cveless(ticket_factory)
        before = await _state(api.db, ticket)
        roles = _record_role_loads(monkeypatch)
        spies = _forbid_lookups(monkeypatch)

        responses = [
            await api.post(target, headers=headers)
            for target in (ticket, f"SNTL-{MAX_SEQUENCE}")
        ]

        assert [r.status_code for r in responses] == [401, 401]
        assert [r.json() for r in responses] == [UNAUTHENTICATED] * 2
        assert roles == []
        for spy in spies:
            spy.assert_not_awaited()
        assert api.smelt.requests == []
        assert await _state(api.db, ticket) == before

    @pytest.mark.parametrize(
        "roles",
        [
            pytest.param((), id="no-roles"),
            pytest.param((Role.ADMIN,), id="admin-without-manage_packages"),
        ],
    )
    async def test_caller_without_manage_packages_gets_the_generic_403(
        self,
        api: _Api,
        ticket_factory: TicketFactory,
        monkeypatch: pytest.MonkeyPatch,
        roles: tuple[Role, ...],
    ) -> None:
        """The identical generic 403 for an existing, a missing, an
        inaccessible (confidential; the role-less caller's scope is
        `non_confidential`), a malformed, and a UUID-form `{ticket_id}`,
        after exactly one role load and before any Ticket lookup,
        orchestration, or SMELT request. `admin` holds `admin_ticket_ops`
        but not `manage_packages` (rbac.md, Predefined Roles)."""
        caller = await api.caller(*roles)
        ticket = await cveless(ticket_factory)
        hidden = await cveless(ticket_factory, is_confidential=True)
        _serve(api.smelt, codestream(IBS_REF, "SLE_15", ABSENT))
        before = await _state(api.db, ticket, hidden)
        loads = _record_role_loads(monkeypatch)
        spies = _forbid_lookups(monkeypatch)

        responses = [
            await api.post(target, caller=caller)
            for target in (
                ticket,
                f"SNTL-{MAX_SEQUENCE}",
                hidden,
                "not-a-ticket",
                str(ticket.id),
            )
        ]

        assert [r.status_code for r in responses] == [403] * len(responses)
        assert {r.content for r in responses} == {responses[0].content}
        assert responses[0].json() == FORBIDDEN
        assert loads == [caller.user.id] * len(responses)
        for spy in spies:
            spy.assert_not_awaited()
        assert api.smelt.requests == []
        assert await _state(api.db, ticket, hidden) == before

    async def test_maintainer_with_visibility_but_without_manage_packages_gets_403(
        self, api: _Api, ticket_factory: TicketFactory
    ) -> None:
        """package-maintainership.md, Confidential Ticket Visibility and
        Testing Requirements: a role-less User associated with an included
        package of a confidential Ticket can read it, but the
        capability-protected addition returns the generic 403 with no SMELT
        request and no effect."""
        caller = await api.caller()
        ticket = await cveless(ticket_factory, is_confidential=True)
        package = await seed_package(api.db, ticket.id, "fictional-maintained")
        await seed_maintainer(api.db, package, caller.user)
        (product,) = await _current(api.db)
        _serve(
            api.smelt,
            codestream(IBS_REF, "SLE_15", product.cpe),
            emails=[caller.user.email],
        )
        before = await _state(api.db, ticket)

        visible = await api.client.get(_url(ticket), headers=caller.headers)
        response = await api.post(ticket, caller=caller)

        assert visible.status_code == 200
        assert response.status_code == 403
        assert response.json() == FORBIDDEN
        assert api.smelt.requests == []
        assert await _state(api.db, ticket) == before

    @pytest.mark.parametrize(
        "role",
        [
            pytest.param(Role.VULNERABILITY_ANALYST, id="vulnerability_analyst"),
            pytest.param(Role.RESTRICTED_ANALYST, id="restricted_analyst"),
        ],
    )
    async def test_predefined_role_with_manage_packages_adds_the_package(
        self, api: _Api, ticket_factory: TicketFactory, role: Role
    ) -> None:
        """rbac.md, Predefined Roles and Endpoint Permission Map: both analyst
        roles hold `manage_packages`."""
        caller = await api.caller(role)
        ticket = await cveless(ticket_factory, assignee_id=caller.user.id)
        (product,) = await _current(api.db)
        _serve(api.smelt, codestream(IBS_REF, "SLE_15", product.cpe))

        response = await api.post(ticket, caller=caller)

        assert response.status_code == 201, response.text
        assert response.json() == _data(1, 0, 1, 0)

    @pytest.mark.parametrize("path", ["grant", "maintained-package"])
    async def test_restricted_analyst_with_visibility_adds_to_a_confidential_ticket(
        self,
        api: _Api,
        ticket_factory: TicketFactory,
        ticket_access_grant_factory: Factory,
        path: str,
    ) -> None:
        """A `restricted_analyst` (scope `non_confidential`) sees the
        confidential Ticket through an explicit grant or an included
        maintained package, so its addition succeeds (testing-strategy.md,
        Ticket Accessibility, canonical predicate)."""
        caller = await api.caller(Role.RESTRICTED_ANALYST)
        granter = await seed_user(api.db)
        ticket = await cveless(ticket_factory, is_confidential=True)
        if path == "grant":
            await ticket_access_grant_factory(
                ticket_id=ticket.id, user_id=caller.user.id, granted_by_id=granter.id
            )
        else:
            package = await seed_package(api.db, ticket.id, "fictional-maintained")
            await seed_maintainer(api.db, package, caller.user)
        (product,) = await _current(api.db)
        _serve(api.smelt, codestream(IBS_REF, "SLE_15", product.cpe))

        response = await api.post(ticket, caller=caller)

        assert response.status_code == 201, response.text
        assert response.json() == _data(1, 0, 1, 0)


# ---------------------------------------------------------------------------
# 2. Locator and anti-enumeration (identical 404 before any SMELT request)
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestTicketNotFound:
    async def test_every_not_found_locator_returns_the_identical_404(
        self,
        api: _Api,
        ticket_factory: TicketFactory,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Malformed forms, the Ticket UUID in place of `SNTL-{n}`, a
        well-formed missing `SNTL-{n}`, an inaccessible confidential
        Ticket, and a confidential Ticket whose only maintained package of
        the caller is excluded (an excluded package grants no visibility)
        all return the same complete body for a `restricted_analyst`
        holding `manage_packages`, with no orchestration and no SMELT
        request (api-spec.md, Ticket Accessibility Check, Ticket
        Identifier Resolution)."""
        caller = await api.caller(Role.RESTRICTED_ANALYST)
        visible = await cveless(ticket_factory)
        hidden = await cveless(ticket_factory, is_confidential=True)
        excluded = await cveless(ticket_factory, is_confidential=True)
        package = await seed_package(
            api.db, excluded.id, "fictional-maintained", excluded=True
        )
        await seed_maintainer(api.db, package, caller.user)
        (product,) = await _current(api.db)
        _serve(
            api.smelt,
            codestream(IBS_REF, "SLE_15", product.cpe),
            emails=[caller.user.email],
        )
        before = await _state(api.db, visible, hidden, excluded)
        orchestrator = AsyncMock()
        monkeypatch.setattr(package_service, "add_package_to_ticket", orchestrator)
        locators = {name: build(visible) for name, build in INVALID_LOCATORS} | {
            "missing-sequence": f"SNTL-{visible.sequence_id + 1_000_000}",
            "inaccessible": locator(hidden),
            "maintainer-of-excluded-package": locator(excluded),
        }

        responses = {
            name: await api.post(value, caller=caller)
            for name, value in locators.items()
        }

        statuses = {name: r.status_code for name, r in responses.items()}
        assert statuses == dict.fromkeys(locators, 404)
        assert {r.content for r in responses.values()} == {NOT_FOUND}
        orchestrator.assert_not_awaited()
        assert api.smelt.requests == []
        assert await _state(api.db, visible, hidden, excluded) == before


# ---------------------------------------------------------------------------
# 4. Request validation (global 422 before any SMELT request)
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestValidation:
    @pytest.mark.parametrize(
        ("body", "error_type"),
        [
            pytest.param({}, "missing", id="missing-field"),
            pytest.param({"package_name": None}, "string_type", id="null"),
            pytest.param({"package_name": 42}, "string_type", id="not-a-string"),
            pytest.param({"package_name": ""}, "string_pattern_mismatch", id="empty"),
            pytest.param(
                {"package_name": "a"}, "string_pattern_mismatch", id="one-character"
            ),
            pytest.param(
                {"package_name": "a" * 256}, "string_too_long", id="256-chars"
            ),
            pytest.param(
                {"package_name": "-fictional"},
                "string_pattern_mismatch",
                id="leading-hyphen",
            ),
            pytest.param(
                {"package_name": "fictional."},
                "string_pattern_mismatch",
                id="trailing-dot",
            ),
            pytest.param(
                {"package_name": "fictional/lib"},
                "string_pattern_mismatch",
                id="slash",
            ),
            pytest.param(
                {"package_name": "fictional lib"},
                "string_pattern_mismatch",
                id="space",
            ),
            pytest.param(
                {"package_name": "fictional%2Flib"},
                "string_pattern_mismatch",
                id="percent",
            ),
            pytest.param(
                {"package_name": "fictionalé"},
                "string_pattern_mismatch",
                id="non-ascii",
            ),
        ],
    )
    async def test_invalid_package_name_is_the_global_422_before_any_smelt_request(
        self,
        api: _Api,
        ticket_factory: TicketFactory,
        body: dict[str, Any],
        error_type: str,
    ) -> None:
        caller = await api.caller(Role.VULNERABILITY_ANALYST)
        ticket = await cveless(ticket_factory)
        await _current(api.db)
        _serve(api.smelt, codestream(IBS_REF, "SLE_15", ABSENT))
        before = await _state(api.db, ticket)

        response = await api.post(ticket, caller=caller, json=body)

        assert response.status_code == 422
        payload = response.json()
        assert (payload["code"], payload["detail"]) == (
            "VALIDATION_ERROR",
            "Request validation failed",
        )
        assert [(e["loc"], e["type"]) for e in payload["errors"]] == [
            (["body", "package_name"], error_type)
        ]
        assert api.smelt.requests == []
        assert await _state(api.db, ticket) == before

    @pytest.mark.parametrize(
        "package_name",
        [
            pytest.param("ab", id="2-chars"),
            pytest.param("a" + "b.c_d+e-f" * 28 + "g" * 2, id="255-chars"),
        ],
    )
    async def test_boundary_names_pass_validation_and_reach_smelt(
        self, api: _Api, ticket_factory: TicketFactory, package_name: str
    ) -> None:
        """The shortest and longest admissible names reach the maintained
        request with the exact name in the URL path (here answered as
        not found)."""
        assert len(package_name) in (2, 255)
        caller = await api.caller(Role.VULNERABILITY_ANALYST)
        ticket = await cveless(ticket_factory)
        await _current(api.db)
        api.smelt.responses["maintained"] = reply(404, not_found(package_name))

        response = await api.post(ticket, caller=caller, package_name=package_name)

        assert response.status_code == 422
        assert response.json() == NOT_FOUND_IN_SMELT
        ((kind, request),) = api.smelt.requests
        assert kind == "maintained"
        # package-model.md, Add Package to Ticket: the name is URL-encoded
        # (`+` is the only character of the grammar that is not unreserved).
        encoded = package_name.replace("+", "%2B")
        assert str(request.url) == (
            f"{SMELT_TEST_API_URL}/experimental/v2/maintained/{encoded}"
            "?include_reactive_ltss=true"
        )


# ---------------------------------------------------------------------------
# 5. Success (201)
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestSuccess:
    async def test_first_addition_returns_exact_counts_and_one_package_added_event(
        self, api: _Api, ticket_factory: TicketFactory
    ) -> None:
        """A new package with an `SLE_15` (`ibs`) codestream of two current
        Products and an `SLFO` (`git`) codestream of one: the exact counts,
        the created tree, both SMELT requests for the requested name, and
        exactly one acting-user `package_added` with `comment = NULL` (the
        caller is already the assignee, so no assignment event). Nothing is
        published: the Ticket was not `Resolved`."""
        caller = await api.caller(Role.VULNERABILITY_ANALYST)
        ticket = await cveless(ticket_factory, assignee_id=caller.user.id)
        p1, p2, p3 = await _current(api.db, 3)
        _serve(
            api.smelt,
            codestream(IBS_REF, "SLE_15", p1.cpe, p2.cpe),
            codestream(GIT_REF, "SLFO", p3.cpe),
        )

        response = await api.post(ticket, caller=caller)

        assert response.status_code == 201, response.text
        assert response.json() == _data(2, 0, 3, 0)
        assert [str(request.url) for _kind, request in api.smelt.requests] == [
            f"{SMELT_TEST_API_URL}/experimental/v2/maintained/{PKG}"
            "?include_reactive_ltss=true",
            f"{SMELT_TEST_API_URL}/experimental/v2/packages/{PKG}/maintainership",
        ]
        assert await package_tree(api.db, ticket.id, PKG) == Tree(
            None,
            {
                IBS_REF: NEW_TRACK[WorkflowType.IBS],
                GIT_REF: NEW_TRACK[WorkflowType.GIT],
            },
            {
                (IBS_REF, p1.id): new_occurrence(True),
                (IBS_REF, p2.id): new_occurrence(True),
                (GIT_REF, p3.id): new_occurrence(True),
            },
        )
        assert await ticket_events_by_id(api.db, ticket.id) == [
            package_added_event(PKG, caller.user)
        ]
        assert await ticket_row(api.db, ticket.id) == (ANALYSIS, caller.user.id)
        assert api.sessions.sessions
        assert not api.sessions.any_in_transaction()

    async def test_repeated_addition_creates_nothing_and_records_no_event(
        self, api: _Api, ticket_factory: TicketFactory, broker: _Publish
    ) -> None:
        """package-model.md, Idempotency: the repeat performs both SMELT
        requests again, reports every resolved record as skipped with zero
        created counts, and changes nothing."""
        caller = await api.caller(Role.VULNERABILITY_ANALYST)
        ticket = await cveless(ticket_factory, assignee_id=caller.user.id)
        p1, p2, p3 = await _current(api.db, 3)
        _serve(
            api.smelt,
            codestream(IBS_REF, "SLE_15", p1.cpe, p2.cpe),
            codestream(GIT_REF, "SLFO", p3.cpe),
        )
        first = await api.post(ticket, caller=caller)
        assert first.status_code == 201, first.text
        after_first = await _state(api.db, ticket)

        repeated = await api.post(ticket, caller=caller)

        assert repeated.status_code == 201, repeated.text
        assert repeated.json() == _data(0, 2, 0, 3)
        assert api.smelt.kinds == BOTH * 2
        assert await _state(api.db, ticket) == after_first
        assert broker.calls == []

    async def test_incremental_addition_creates_only_the_new_records(
        self, api: _Api, ticket_factory: TicketFactory
    ) -> None:
        """SMELT now reports one more Product under the existing track and
        a new track: only those are created and counted, the existing track
        keeps its affectedness, and one `package_added` is recorded."""
        caller = await api.caller(Role.VULNERABILITY_ANALYST)
        ticket = await cveless(ticket_factory, assignee_id=caller.user.id)
        p1, p2, p3 = await _current(api.db, 3)
        package = await seed_package(api.db, ticket.id, PKG)
        track = await seed_track(
            api.db, package, IBS_REF, status=PackageStatus.AFFECTED
        )
        await seed_occurrence(api.db, track, p1)
        _serve(
            api.smelt,
            codestream(IBS_REF, "SLE_15", p1.cpe, p2.cpe),
            codestream(GIT_REF, "SLFO", p3.cpe),
        )

        response = await api.post(ticket, caller=caller)

        assert response.status_code == 201, response.text
        assert response.json() == _data(1, 1, 2, 1)
        tree = await package_tree(api.db, ticket.id, PKG)
        assert tree is not None
        assert tree.tracks[IBS_REF].status == PackageStatus.AFFECTED.value
        assert set(tree.occurrences) == {
            (IBS_REF, p1.id),
            (IBS_REF, p2.id),
            (GIT_REF, p3.id),
        }
        assert await ticket_events_by_id(api.db, ticket.id) == [
            package_added_event(PKG, caller.user)
        ]

    async def test_maintainer_only_outcome_exposes_no_maintainer_in_the_body(
        self, api: _Api, ticket_factory: TicketFactory
    ) -> None:
        """package-maintainership.md, Locked mutation and Testing
        Requirements: the package tree is already complete and SMELT now
        names a matching active User. The response keeps the five count
        fields with zero created counts and contains no maintainer
        identity or count; the only effect is the association with one
        system `package_maintainer_added`, without auto-assignment of the
        unassigned Ticket (package-service.md, Auto-Assignment Rule)."""
        caller = await api.caller(Role.VULNERABILITY_ANALYST)
        maintainer = await seed_user(
            api.db, username="erin.maintainer", email="erin.maintainer@example.com"
        )
        ticket = await cveless(ticket_factory)
        (product,) = await _current(api.db)
        package = await seed_package(api.db, ticket.id, PKG)
        track = await seed_track(api.db, package, IBS_REF)
        await seed_occurrence(api.db, track, product)
        _serve(
            api.smelt,
            codestream(IBS_REF, "SLE_15", product.cpe),
            emails=["Erin.Maintainer@Example.com"],
        )
        tree_before = await tree_rows(api.db, ticket.id)

        response = await api.post(ticket, caller=caller)

        assert response.status_code == 201, response.text
        assert response.json() == _data(0, 1, 0, 1)
        assert set(response.json()["data"]) == RESULT_FIELDS
        for fragment in ("erin", str(maintainer.id), "maintainer"):
            assert fragment not in response.text.lower()
        assert await ticket_events_by_id(api.db, ticket.id) == [
            maintainer_event(PKG, maintainer)
        ]
        assert await maintainers(api.db, ticket.id) == [(PKG, maintainer.id)]
        assert await tree_rows(api.db, ticket.id) == tree_before
        assert await ticket_row(api.db, ticket.id) == (ANALYSIS, None)

    async def test_unassigned_new_ticket_is_assigned_to_the_active_va_caller(
        self, api: _Api, ticket_factory: TicketFactory
    ) -> None:
        """package-service.md, Auto-Assignment Rule; ticket-audit-log.md,
        Cross-Event Ordering: the acting-user assignment and its system
        `New -> Analysis` promotion precede the acting-user
        `package_added`."""
        caller = await api.caller(Role.VULNERABILITY_ANALYST)
        ticket = await cveless(ticket_factory, status=NEW)
        (product,) = await _current(api.db)
        _serve(api.smelt, codestream(IBS_REF, "SLE_15", product.cpe))

        response = await api.post(ticket, caller=caller)

        assert response.status_code == 201, response.text
        assert response.json() == _data(1, 0, 1, 0)
        assert await ticket_row(api.db, ticket.id) == (ANALYSIS, caller.user.id)
        assert await ticket_events_by_id(api.db, ticket.id) == [
            assignment_event(caller.user),
            status_event(NEW, ANALYSIS),
            package_added_event(PKG, caller.user),
        ]

    async def test_restricted_analyst_caller_is_not_assigned(
        self, api: _Api, ticket_factory: TicketFactory
    ) -> None:
        """Only an active VA is auto-assigned: a `restricted_analyst` adds
        the package, and the Ticket stays unassigned with only its
        acting-user `package_added`."""
        caller = await api.caller(Role.RESTRICTED_ANALYST)
        ticket = await cveless(ticket_factory)
        (product,) = await _current(api.db)
        _serve(api.smelt, codestream(IBS_REF, "SLE_15", product.cpe))

        response = await api.post(ticket, caller=caller)

        assert response.status_code == 201, response.text
        assert await ticket_row(api.db, ticket.id) == (ANALYSIS, None)
        assert await ticket_events_by_id(api.db, ticket.id) == [
            package_added_event(PKG, caller.user)
        ]

    async def test_production_dependency_uses_one_shared_factory_client(
        self,
        api: _Api,
        ticket_factory: TicketFactory,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Without the test override, the route's dependency creates exactly
        one shared-factory client named `add_package_to_ticket` per
        request, performs both SMELT requests with it, and closes it
        (networking.md, Shared HTTP Client)."""
        caller = await api.caller(Role.VULNERABILITY_ANALYST)
        ticket = await cveless(ticket_factory, assignee_id=caller.user.id)
        (product,) = await _current(api.db)
        _serve(api.smelt, codestream(IBS_REF, "SLE_15", product.cpe))
        names: list[str] = []

        def _factory(name: str, **overrides: Any) -> httpx.AsyncClient:
            names.append(name)
            return api.smelt.client()

        monkeypatch.setattr(route, "create_http_client", _factory)
        app.dependency_overrides.pop(route.get_package_addition_http_client)

        response = await api.post(ticket, caller=caller)

        assert response.status_code == 201, response.text
        assert names == ["add_package_to_ticket"]
        assert api.smelt.kinds == BOTH
        (client,) = api.smelt.clients
        assert client.is_closed


# ---------------------------------------------------------------------------
# 6. Errors and their public precedence
# ---------------------------------------------------------------------------


MAINTAINED_UNAVAILABLE: dict[str, Respond] = {
    "http-500": reply(500, {"status": "error", "data": MARKER}),
    "http-200-jsend-error": reply(200, {"status": "error", "data": MARKER}),
    "transport-error": fail(httpx.ConnectError(f"{MARKER} {SMELT_TEST_API_URL}")),
}
"""Representative maintained responses that SMELT did not produce as a valid
successful response; each carries `MARKER`."""


def _assert_sanitized(response: httpx.Response) -> None:
    assert MARKER not in response.text
    assert "smelt.example.test" not in response.text


@pytest.mark.e2e
class TestErrors:
    @pytest.mark.parametrize("case", list(MAINTAINED_UNAVAILABLE))
    async def test_smelt_unavailable_is_a_sanitized_503(
        self, api: _Api, ticket_factory: TicketFactory, case: str
    ) -> None:
        caller = await api.caller(Role.VULNERABILITY_ANALYST)
        ticket = await cveless(ticket_factory)
        await _current(api.db)
        api.smelt.responses["maintained"] = MAINTAINED_UNAVAILABLE[case]
        api.smelt.responses["maintainership"] = reply(200, maintainership())
        before = await _state(api.db, ticket)

        response = await api.post(ticket, caller=caller)

        assert response.status_code == 503
        assert response.json() == SMELT_UNAVAILABLE
        _assert_sanitized(response)
        assert api.smelt.kinds == ["maintained"]
        assert await _state(api.db, ticket) == before

    async def test_smelt_unavailability_precedes_catalog_readiness(
        self, api: _Api, ticket_factory: TicketFactory, db_session: AsyncSession
    ) -> None:
        """No Product exists (the catalog is not ready), but the maintained
        request already failed: `SMELT_UNAVAILABLE`."""
        assert (await db_session.execute(select(Product.id).limit(1))).first() is None
        caller = await api.caller(Role.VULNERABILITY_ANALYST)
        ticket = await cveless(ticket_factory)
        api.smelt.responses["maintained"] = MAINTAINED_UNAVAILABLE["http-500"]

        response = await api.post(ticket, caller=caller)

        assert response.status_code == 503
        assert response.json() == SMELT_UNAVAILABLE
        assert api.smelt.kinds == ["maintained"]

    @pytest.mark.parametrize("smelt_outcome", ["not-found", "targets-unresolved"])
    async def test_catalog_not_ready_precedes_not_found_and_targets_unresolved(
        self,
        api: _Api,
        ticket_factory: TicketFactory,
        db_session: AsyncSession,
        smelt_outcome: str,
    ) -> None:
        """No Product exists, so no complete catalog snapshot has committed
        (product-catalog.md, Catalog Readiness and Freshness): a valid
        not-found response and a response whose targets match nothing
        both yield `PRODUCT_CATALOG_NOT_READY`, without the maintainership
        request."""
        assert (await db_session.execute(select(Product.id).limit(1))).first() is None
        caller = await api.caller(Role.VULNERABILITY_ANALYST)
        ticket = await cveless(ticket_factory)
        if smelt_outcome == "not-found":
            api.smelt.responses["maintained"] = reply(404, not_found(PKG))
        else:
            _serve(api.smelt, codestream(IBS_REF, "SLE_15", ABSENT))
        before = await _state(api.db, ticket)

        response = await api.post(ticket, caller=caller)

        assert response.status_code == 503
        assert response.json() == CATALOG_NOT_READY
        assert api.smelt.kinds == ["maintained"]
        assert await _state(api.db, ticket) == before

    async def test_package_not_found_in_smelt_is_a_sanitized_422(
        self, api: _Api, ticket_factory: TicketFactory
    ) -> None:
        caller = await api.caller(Role.VULNERABILITY_ANALYST)
        ticket = await cveless(ticket_factory)
        await _current(api.db)
        api.smelt.responses["maintained"] = reply(
            404, {"status": "error", "data": MARKER}
        )
        before = await _state(api.db, ticket)

        response = await api.post(ticket, caller=caller)

        assert response.status_code == 422
        assert response.json() == NOT_FOUND_IN_SMELT
        _assert_sanitized(response)
        assert api.smelt.kinds == ["maintained"]
        assert await _state(api.db, ticket) == before

    @pytest.mark.parametrize(
        "case", ["absent-cpe", "historical-product", "unsupported-process"]
    )
    async def test_unresolved_targets_are_a_422(
        self,
        api: _Api,
        ticket_factory: TicketFactory,
        case: str,
    ) -> None:
        """SMELT returned tracks, but no target of a supported codestream
        matches a Product of the current snapshot: a CPE no Product
        carries, a Product retained only from an earlier snapshot, or a
        codestream of an unsupported process (`SLFO_IBS`)."""
        caller = await api.caller(Role.VULNERABILITY_ANALYST)
        ticket = await cveless(ticket_factory)
        (current,) = await _current(api.db)
        historical = await catalog_product(api.db)
        entry = {
            "absent-cpe": codestream(IBS_REF, "SLE_15", ABSENT),
            "historical-product": codestream(IBS_REF, "SLE_15", historical.cpe),
            "unsupported-process": codestream(IBS_REF, "SLFO_IBS", current.cpe),
        }[case]
        _serve(api.smelt, entry)
        before = await _state(api.db, ticket)

        response = await api.post(ticket, caller=caller)

        assert response.status_code == 422
        assert response.json() == TARGETS_UNRESOLVED
        assert api.smelt.kinds == ["maintained"]
        assert await _state(api.db, ticket) == before

    async def test_excluded_package_is_a_409_after_both_smelt_requests(
        self, api: _Api, ticket_factory: TicketFactory
    ) -> None:
        """package-model.md, Adding Packages to a Ticket: the exclusion guard
        is decided under the Ticket lock after the maintained and the
        maintainership request. SMELT names a new Product and a matching
        active User, yet no record, association, event, or assignment is
        persisted."""
        caller = await api.caller(Role.VULNERABILITY_ANALYST)
        maintainer = await seed_user(api.db)
        ticket = await cveless(ticket_factory)
        p1, p2 = await _current(api.db, 2)
        package = await seed_package(api.db, ticket.id, PKG, excluded=True)
        track = await seed_track(api.db, package, IBS_REF)
        await seed_occurrence(api.db, track, p1)
        _serve(
            api.smelt,
            codestream(IBS_REF, "SLE_15", p1.cpe, p2.cpe),
            emails=[maintainer.email],
        )
        before = await _state(api.db, ticket)

        response = await api.post(ticket, caller=caller)

        assert response.status_code == 409
        assert response.json() == ALREADY_EXCLUDED
        assert api.smelt.kinds == BOTH
        assert await maintainers(api.db, ticket.id) == []
        assert await _state(api.db, ticket) == before

    @pytest.mark.parametrize(
        "status", [TicketStatus.IGNORED, TicketStatus.DUPLICATED], ids=str
    )
    async def test_manual_zone_ticket_is_not_mutable(
        self, api: _Api, ticket_factory: TicketFactory, status: TicketStatus
    ) -> None:
        """api-spec.md, Manual-Zone Mutability Guard: decided under the
        Ticket lock, so after both SMELT requests, with no effect."""
        caller = await api.caller(Role.VULNERABILITY_ANALYST)
        maintainer = await seed_user(api.db)
        ticket = await ticket_factory(status=status.value)
        (product,) = await _current(api.db)
        _serve(
            api.smelt,
            codestream(IBS_REF, "SLE_15", product.cpe),
            emails=[maintainer.email],
        )
        before = await _state(api.db, ticket)

        response = await api.post(ticket, caller=caller)

        assert response.status_code == 409
        assert response.json() == NOT_MUTABLE
        assert api.smelt.kinds == BOTH
        assert await _state(api.db, ticket) == before

    async def test_not_mutable_precedes_the_excluded_package_guard(
        self, api: _Api, ticket_factory: TicketFactory
    ) -> None:
        """Public precedence 9 before 10: an `Ignored` Ticket whose package
        is directly excluded returns `TICKET_NOT_MUTABLE`."""
        caller = await api.caller(Role.VULNERABILITY_ANALYST)
        ticket = await ticket_factory(status=TicketStatus.IGNORED.value)
        (product,) = await _current(api.db)
        package = await seed_package(api.db, ticket.id, PKG, excluded=True)
        track = await seed_track(api.db, package, IBS_REF)
        await seed_occurrence(api.db, track, product)
        _serve(api.smelt, codestream(IBS_REF, "SLE_15", product.cpe))

        response = await api.post(ticket, caller=caller)

        assert response.status_code == 409
        assert response.json() == NOT_MUTABLE


# ---------------------------------------------------------------------------
# 7. Ticket convergence through the API transaction owner
# ---------------------------------------------------------------------------


def _publication_failed(ticket_id: uuid.UUID, request_id: str) -> dict[str, Any]:
    """The one sanitized automatic publication-failure event: `ticket_id`,
    the closed cause, and the bound request correlation."""
    return {
        "event": "ticket_convergence_publication_failed",
        "log_level": "error",
        "ticket_id": str(ticket_id),
        "cause": "broker_operational_error",
        "request_id": request_id,
    }


@pytest.mark.e2e
class TestConvergence:
    async def _resolved_world(
        self, api: _Api, ticket_factory: TicketFactory
    ) -> tuple[_Caller, Ticket]:
        """A `Resolved` Ticket assigned to the VA caller; the addition creates
        a new `ANALYSIS` track, which regresses it to `Analysis`
        (ticket-mutations.md, `reconcile_ticket_status()` step 5)."""
        caller = await api.caller(Role.VULNERABILITY_ANALYST)
        ticket = await cveless(
            ticket_factory, status=RESOLVED, assignee_id=caller.user.id
        )
        (product,) = await _current(api.db)
        _serve(api.smelt, codestream(IBS_REF, "SLE_15", product.cpe))
        return caller, ticket

    async def test_resolved_regression_publishes_one_root_task_after_commit(
        self, api: _Api, ticket_factory: TicketFactory, broker: _Publish
    ) -> None:
        caller, ticket = await self._resolved_world(api, ticket_factory)

        with capture_logs() as logs:
            response = await api.post(ticket, caller=caller)

        assert response.status_code == 201, response.text
        assert response.json() == _data(1, 0, 1, 0)
        assert broker.ticket_ids() == [("run_ticket_convergence", str(ticket.id))]
        assert set(broker.calls[0]) == {"task_name", "kwargs", "task_id"}
        assert uuid.UUID(broker.calls[0]["task_id"]).version == 7
        assert broker.in_transaction == [False]
        assert await ticket_row(api.db, ticket.id) == (ANALYSIS, caller.user.id)
        assert await ticket_events_by_id(api.db, ticket.id) == [
            package_added_event(PKG, caller.user),
            status_event(RESOLVED, ANALYSIS),
        ]
        assert _feature_logs(logs) == []

    async def test_broker_operational_error_keeps_the_201_with_one_sanitized_log(
        self, api: _Api, ticket_factory: TicketFactory, broker: _Publish
    ) -> None:
        caller, ticket = await self._resolved_world(api, ticket_factory)
        broker.error = BrokerOperationalError(f"{BROKER_URL} connection refused")

        with capture_logs(processors=[merge_contextvars]) as logs:
            response = await api.post(ticket, caller=caller)

        assert response.status_code == 201, response.text
        assert response.json() == _data(1, 0, 1, 0)
        assert broker.ticket_ids() == [("run_ticket_convergence", str(ticket.id))]
        assert await ticket_row(api.db, ticket.id) == (ANALYSIS, caller.user.id)
        assert _feature_logs(logs) == [
            _publication_failed(ticket.id, response.headers["X-Request-ID"])
        ]
        rendered = repr(logs) + response.text
        for fragment in (
            "fictional-secret",
            "broker.example.test",
            "connection refused",
        ):
            assert fragment not in rendered

    async def test_rejected_request_publishes_nothing(
        self, api: _Api, ticket_factory: TicketFactory, broker: _Publish
    ) -> None:
        """A `Resolved` Ticket whose package is excluded: the request is
        rejected under the lock and rolled back, so nothing is published."""
        caller = await api.caller(Role.VULNERABILITY_ANALYST)
        ticket = await cveless(
            ticket_factory, status=RESOLVED, assignee_id=caller.user.id
        )
        (product,) = await _current(api.db)
        await seed_package(api.db, ticket.id, PKG, excluded=True)
        _serve(api.smelt, codestream(IBS_REF, "SLE_15", product.cpe))

        response = await api.post(ticket, caller=caller)

        assert response.status_code == 409
        assert broker.calls == []
        assert await ticket_row(api.db, ticket.id) == (RESOLVED, caller.user.id)


# ---------------------------------------------------------------------------
# 3 and 6. Independent-session races across the external phase
# ---------------------------------------------------------------------------


@dataclass
class _Committed:
    world: CommittedWorld
    client: AsyncClient
    smelt: PackageSmelt
    broker: _Publish

    async def headers(self, user: User) -> dict[str, str]:
        """A committed Bearer credential of the world's `user`."""
        created = await create_session(
            self.world.session,
            user,
            SessionCreationReason.LOCAL_LOGIN,
            expected_password_hash=None,
        )
        assert created is not None
        await self.world.session.commit()
        return {"Authorization": f"Bearer {created.token}"}

    async def current_product(self) -> Product:
        """A committed catalog Product published in the current snapshot."""
        product = await world_product(self.world)
        await publish(self.world.session, product)
        await self.world.session.commit()
        return product


@pytest_asyncio.fixture
async def committed(
    db_session_factory: Callable[[], Awaitable[AsyncSession]],
    real_session_factory: async_sessionmaker[AsyncSession],
    redis_client: redis_asyncio.Redis,
    smelt: PackageSmelt,
    broker: _Publish,
    monkeypatch: pytest.MonkeyPatch,
) -> AsyncIterator[_Committed]:
    """Committed rows (deleted explicitly, including the world users' auth
    sessions) and a client served by the production `get_db()` over
    independent pooled sessions of the test engine."""
    assert get_db not in app.dependency_overrides
    sessions = _RequestSessions(real_session_factory)
    broker.sessions = sessions
    monkeypatch.setattr(database, "async_session_factory", sessions)
    async with committed_world(db_session_factory) as world:
        try:
            async with AsyncClient(
                transport=ASGITransport(app=app, raise_app_exceptions=False),
                base_url="http://test",
            ) as client:
                yield _Committed(world, client, smelt, broker)
        finally:
            cleanup = await world.open_session()
            await cleanup.execute(
                delete(SessionRow).where(SessionRow.user_id.in_(world.user_ids))
            )
            await cleanup.commit()


@contextlib.asynccontextmanager
async def _in_flight(
    committed: _Committed,
    ticket: Ticket,
    package_name: str,
    headers: dict[str, str],
    pause: Pause,
) -> AsyncIterator[asyncio.Task[httpx.Response]]:
    """Send the request and yield once it is held inside its paused SMELT
    request; on exit the request is released and awaited at the latest."""
    task = asyncio.create_task(
        committed.client.post(
            _url(ticket), json={"package_name": package_name}, headers=headers
        )
    )
    try:
        arrived = asyncio.ensure_future(pause.arrived.wait())
        try:
            await asyncio.wait(
                {arrived, task}, timeout=WAIT, return_when=asyncio.FIRST_COMPLETED
            )
        finally:
            arrived.cancel()
        if task.done():
            raise AssertionError(
                f"the request finished before its paused SMELT request: "
                f"{task.result().text}"
            )
        assert pause.arrived.is_set(), "the request never reached SMELT"
        yield task
    finally:
        pause.release.set()
        with contextlib.suppress(Exception):
            await asyncio.wait_for(task, timeout=WAIT)


async def _commit_loss(world: CommittedWorld, statements: list[Any]) -> None:
    """Commit the visibility loss on an independent session within the
    bounded wait: the paused request holds no Ticket lock."""
    session = await world.open_session()

    async def run() -> None:
        for statement in statements:
            await session.execute(statement)
        await session.commit()

    await asyncio.wait_for(run(), timeout=WAIT)


def _race_name() -> str:
    return f"fictional-librace-{uuid.uuid4().hex[:10]}"


@pytest.mark.e2e
class TestAccessLostDuringExternalIO:
    """A `restricted_analyst` caller (effective scope `non_confidential`)
    can access the Ticket through exactly one path (`prepare_loss()`:
    visibility, an explicit grant, or one included maintained package), so
    its preliminary check passes. While its request is paused inside a
    SMELT request, an independent session removes that path and commits."""

    @pytest.mark.parametrize("pause_at", ["maintained", "maintainership"])
    @pytest.mark.parametrize("loss", LOSSES)
    async def test_successful_io_is_denied_by_the_locked_check(
        self, committed: _Committed, loss: str, pause_at: Kind
    ) -> None:
        """Both SMELT requests then succeed, naming a current Product and the
        caller's own email: the identical `404 TICKET_NOT_FOUND`, with zero
        package-tree write, association, event, assignment, or convergence
        publication (the fetched, unpersisted maintainer data cannot
        authorize the request)."""
        world = committed.world
        user, _cve, ticket, statements = await prepare_loss(world, loss)
        headers = await committed.headers(user)
        product = await committed.current_product()
        pkg = _race_name()
        _serve(
            committed.smelt,
            codestream(IBS_REF, "SLE_15", product.cpe),
            emails=[user.email],
        )
        pause = committed.smelt.pause(pause_at)
        before = await protected_state(world, ticket.id)

        async with _in_flight(committed, ticket, pkg, headers, pause) as task:
            await _commit_loss(world, statements)
            assert not task.done()
            pause.release.set()
            response = await asyncio.wait_for(task, timeout=WAIT)

        assert response.status_code == 404
        assert response.content == NOT_FOUND
        assert committed.smelt.kinds == BOTH
        assert committed.broker.calls == []
        assert await protected_state(world, ticket.id) == before
        state = await committed_state(world, ticket.id, pkg)
        assert (state.ticket, state.events, state.tree) == ((ANALYSIS, None), [], None)
        assert state.maintainers == (
            [("fictional-race-a", user.id)] if loss == "last-package-excluded" else []
        )

    @pytest.mark.parametrize("loss", LOSSES)
    async def test_external_failure_keeps_its_error_after_access_loss(
        self, committed: _Committed, loss: str
    ) -> None:
        """The maintained request then fails: the documented
        `SMELT_UNAVAILABLE`, not a concurrent 404 (api-spec.md, flow 4 step
        3), without the maintainership request and with no effect."""
        world = committed.world
        user, _cve, ticket, statements = await prepare_loss(world, loss)
        headers = await committed.headers(user)
        await committed.current_product()
        pkg = _race_name()
        committed.smelt.responses["maintained"] = MAINTAINED_UNAVAILABLE["http-500"]
        committed.smelt.responses["maintainership"] = reply(
            200, maintainership(user.email)
        )
        pause = committed.smelt.pause("maintained")
        before = await protected_state(world, ticket.id)

        async with _in_flight(committed, ticket, pkg, headers, pause) as task:
            await _commit_loss(world, statements)
            assert not task.done()
            pause.release.set()
            response = await asyncio.wait_for(task, timeout=WAIT)

        assert response.status_code == 503
        assert response.json() == SMELT_UNAVAILABLE
        _assert_sanitized(response)
        assert committed.smelt.kinds == ["maintained"]
        assert committed.broker.calls == []
        assert await protected_state(world, ticket.id) == before


# ---------------------------------------------------------------------------
# 8. OpenAPI contract
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestOpenApiContract:
    def _spec(self) -> dict[str, Any]:
        spec: dict[str, Any] = app.openapi()
        return spec

    def _resolve(self, schema: dict[str, Any]) -> dict[str, Any]:
        ref = schema.get("$ref")
        if ref is None:
            return schema
        resolved: dict[str, Any] = self._spec()["components"]["schemas"][
            ref.rsplit("/", 1)[-1]
        ]
        return self._resolve(resolved)

    def _operation(self) -> dict[str, Any]:
        operation: dict[str, Any] = self._spec()["paths"][PATH]["post"]
        return operation

    def test_operation_documents_the_route_and_its_ticket_locator(self) -> None:
        operation = self._operation()

        assert operation["summary"] == "Add Package to Ticket"
        assert operation["tags"] == ["Ticket Packages"]
        assert "manage_packages" in operation["description"]
        (parameter,) = operation["parameters"]
        assert (parameter["name"], parameter["in"], parameter["required"]) == (
            "ticket_id",
            "path",
            True,
        )
        assert parameter["schema"]["type"] == "string"
        assert "format" not in parameter["schema"]

    def test_request_body_documents_the_package_name_constraints(self) -> None:
        body = self._operation()["requestBody"]

        assert body["required"] is True
        schema = self._resolve(body["content"]["application/json"]["schema"])
        assert set(schema["properties"]) == {"package_name"}
        assert schema["required"] == ["package_name"]
        package_name = schema["properties"]["package_name"]
        assert package_name["type"] == "string"
        assert package_name["maxLength"] == 255
        assert package_name["pattern"] == PACKAGE_NAME_PATTERN

    def test_201_response_documents_exactly_the_count_fields(self) -> None:
        responses = self._operation()["responses"]

        assert "200" not in responses
        envelope = self._resolve(
            responses["201"]["content"]["application/json"]["schema"]
        )
        assert set(envelope["properties"]) == {"data"}
        assert envelope["required"] == ["data"]
        result = self._resolve(envelope["properties"]["data"])
        assert set(result["properties"]) == RESULT_FIELDS
        assert set(result["required"]) == RESULT_FIELDS
        assert result["properties"]["package_name"]["type"] == "string"
        for name in RESULT_FIELDS - {"package_name"}:
            assert result["properties"][name]["type"] == "integer"

    @pytest.mark.parametrize(
        ("status", "codes"),
        [
            ("404", ["TICKET_NOT_FOUND"]),
            ("409", ["PACKAGE_ALREADY_EXCLUDED", "TICKET_NOT_MUTABLE"]),
            ("422", ["PACKAGE_NOT_FOUND_IN_SMELT", "PACKAGE_TARGETS_UNRESOLVED"]),
            ("503", ["SMELT_UNAVAILABLE", "PRODUCT_CATALOG_NOT_READY"]),
        ],
    )
    def test_error_responses_name_each_documented_code(
        self, status: str, codes: list[str]
    ) -> None:
        response = self._operation()["responses"][status]

        ref: str = response["content"]["application/json"]["schema"]["$ref"]
        assert ref.rsplit("/", 1)[-1] == "ErrorResponse"
        for code in codes:
            assert code in response["description"]
