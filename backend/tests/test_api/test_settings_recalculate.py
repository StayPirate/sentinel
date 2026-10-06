"""End-to-end tests of the manual CVSS recalculation trigger
`POST /api/v1/admin/settings/default-cvss-version/recalculate`
(`trigger_cvss_recalculation`, backend/app/api/v1/settings.py).

Owning specifications:

- docs/features/platform/default-cvss-version-operations.md (Access
  Control; API Endpoints > Trigger CVSS Recalculation; Complete-Run
  Coordination: Admission Ordering, Manual Admission Service, Publication
  Uncertainty);
- docs/features/platform/system-settings.md (Service Exceptions:
  `CVSSRecalculationAlreadyInProgressError`);
- docs/api-spec.md (Global Responses; Infrastructure Dependency Errors);
- docs/features/identity/rbac.md (Endpoint Permission Map: the
  `manage_settings` row of this path);
- docs/features/platform/testing-strategy.md (All-CVE Recalculation Runner
  > Coordination API tests; System Settings Mutation > API tests, "the
  manual trigger creates no setting audit event and leaves the persisted
  setting unchanged"; Mandatory Test Scenarios > API Endpoints; Structural
  Tests);
- issue #837, acceptance group "API", and decisions V2 (the
  `get_cvss_admission_bind()` patch point) and V6 (fixed details).

Authentication runs through the request `DatabaseSession`, which the e2e
`client` binds to the savepoint-wrapped `db_session`; the admission owns a
separate connection. `get_cvss_admission_bind()` supplies the borrowed
fenced connection of the shared recalculation harness
(tests/support/cvss_recalculation.py), whose committed
`default_cvss_version` the admission reads under its fence. The shared
`AdmissionSpy` (tests/support/cvss_recalculation_admission.py) records the
admission steps and replaces the broker call; the lease lives in the worker
Redis database. The ordering, cleanup, event, and connection-ownership
details of the admission are proven by
`tests/test_services/test_cvss_recalculation_admission.py`; these tests
cover the HTTP contract. Control signals raised by the publisher are not
driven through HTTP: they are not `Exception`s and never reach a response
(the service tests prove that they propagate unchanged).

Expected bodies are transcribed from the specifications and the fixed
details recorded in issue #837 (V6), never computed with the module under
test.
"""

from __future__ import annotations

import ast
import hashlib
import inspect
import secrets
import textwrap
from collections.abc import AsyncIterator, Awaitable, Callable
from typing import Any
from unittest.mock import AsyncMock

import pytest
import pytest_asyncio
import redis.asyncio as redis_asyncio
from fastapi import routing as fastapi_routing
from fastapi.routing import APIRoute
from httpx import ASGITransport, AsyncClient, Response
from kombu.exceptions import (  # type: ignore[import-untyped]
    EncodeError,
    SerializerNotInstalled,
)
from kombu.exceptions import OperationalError as BrokerOperationalError
from redis.exceptions import ConnectionError as RedisConnectionError
from redis.exceptions import TimeoutError as RedisTimeoutError
from sqlalchemy import BigInteger, func, literal, select
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine, AsyncSession

from app.api import dependencies
from app.api.v1 import settings as settings_api
from app.core.enums import Role
from app.core.exceptions import ServiceError
from app.main import app
from app.models.api_key import ApiKey
from app.models.setting_audit_event import SettingAuditEvent
from app.models.ticket_audit_event import TicketAuditEvent
from app.models.user import User
from app.models.user_role import UserRole
from app.services import cvss_recalculation_admission as admission
from app.services import settings as settings_service
from app.services.cvss_recalculation_admission import (
    ADMISSION_REJECTED_EVENT,
    ADMITTED_EVENT,
    CLEANUP_FAILED_EVENT,
    PUBLICATION_UNCONFIRMED_EVENT,
    SUBMITTED_EVENT,
)
from app.services.cvss_recalculation_coordination import (
    EXECUTION_FENCE_ID,
    LEASE_KEY,
    FenceAcquireOutcome,
    FenceReleaseOutcome,
    LeaseDeleteOutcome,
    compare_and_delete_lease,
    release_execution_fence,
    try_acquire_execution_fence,
)
from tests.support.cvss_recalculation import (
    LEAK_MARKER,
    TARGET,
    ConnectionStatements,
    RecalculationHarness,
    capture_events,
    connection_pid,
    database_error,
    recalculation_harness,
    runner_events,
    wait_until_fence_free,
)
from tests.support.cvss_recalculation_admission import AdmissionSpy, Publication
from tests.support.ticket_mutations import StatementRecorder

_TRIGGER = "/api/v1/admin/settings/default-cvss-version/recalculate"
_TASK_NAME = "recalculate_cvss_derived_state"

_IN_PROGRESS = {
    "code": "CVSS_RECALC_ALREADY_IN_PROGRESS",
    "detail": "A CVSS recalculation is already in progress.",
}
_REDIS_UNAVAILABLE = {
    "code": "REDIS_UNAVAILABLE",
    "detail": "Recalculation could not be admitted because Redis is unavailable.",
}
_CELERY_UNAVAILABLE = {
    "code": "CELERY_UNAVAILABLE",
    "detail": "Recalculation task publication could not be confirmed",
}
_INTERNAL_ERROR = {"code": "INTERNAL_ERROR", "detail": "An unexpected error occurred."}
_NOT_AUTHENTICATED = {
    "code": "AUTH_NOT_AUTHENTICATED",
    "detail": "Authentication required",
}
_INSUFFICIENT_PERMISSION = {
    "code": "AUTH_INSUFFICIENT_PERMISSION",
    "detail": "Insufficient permissions",
}

_ADMISSION_EVENTS = {
    ADMITTED_EVENT,
    ADMISSION_REJECTED_EVENT,
    SUBMITTED_EVENT,
    PUBLICATION_UNCONFIRMED_EVENT,
    CLEANUP_FAILED_EVENT,
}

_UNLOCK = select(func.pg_advisory_unlock(literal(EXECUTION_FENCE_ID, BigInteger)))


def _accepted(target: str = TARGET) -> dict[str, Any]:
    """The exact `202` body (Trigger CVSS Recalculation)."""
    return {
        "data": {
            "message": "Recalculation batch enqueued",
            "default_cvss_version": target,
            "scope": "all_cves",
        }
    }


def _token(task_id: str, target: str = TARGET) -> str:
    return f"v1:{task_id}:{target}"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
async def h(
    _engine: AsyncEngine,
    redis_client: redis_asyncio.Redis,
    monkeypatch: pytest.MonkeyPatch,
) -> AsyncIterator[RecalculationHarness]:
    async with recalculation_harness(_engine.url, redis_client, monkeypatch) as harness:
        yield harness


@pytest.fixture
def spy(h: RecalculationHarness, monkeypatch: pytest.MonkeyPatch) -> AdmissionSpy:
    """The admission spy, installed after the harness (so its recorder
    replaces the harness's convergence publisher), with the harness's
    borrowed fenced connection as the admission bind."""
    installed = AdmissionSpy(monkeypatch)
    monkeypatch.setattr(admission, "get_cvss_admission_bind", lambda: h.connection)
    return installed


@pytest_asyncio.fixture
async def admin_api_key_client(
    client: AsyncClient,
    user_factory: Callable[..., Awaitable[User]],
    user_role_factory: Callable[..., Awaitable[UserRole]],
    api_key_factory: Callable[..., Awaitable[ApiKey]],
    monkeypatch: pytest.MonkeyPatch,
) -> AsyncClient:
    """The shared `client`, authenticated as an admin by an API key
    (`Authorization: Bearer`) instead of a JWT session cookie. Mirrors the
    identical fixture in `tests/test_api/test_settings.py`."""
    user = await user_factory()
    await user_role_factory(user_id=user.id, role=Role.ADMIN.value)
    token = "stl_ak_" + secrets.token_hex(16)
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
    await api_key_factory(user_id=user.id, key_hash=digest)
    monkeypatch.setattr(dependencies._last_used_debouncer, "touch", AsyncMock())
    client.headers["Authorization"] = f"Bearer {token}"
    return client


@pytest_asyncio.fixture
async def admin_error_client(
    admin_client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> AsyncIterator[AsyncClient]:
    """`admin_client`'s JWT session on a transport with
    `raise_app_exceptions=False`, so an unhandled exception yields the
    transmitted global `500` response instead of re-raising into the test
    (Starlette's `ServerErrorMiddleware` re-raises after responding). The
    `get_db` override installed by `client` still applies. Debug mode is
    forced off, and the cached middleware stack cleared so the app rebuilds
    it, because a local `DEBUG=true` would replace the global handler's
    envelope with Starlette's traceback page (the `transmitting_client`
    precedent in `tests/test_api/test_cves.py`); monkeypatch restores
    both."""
    monkeypatch.setattr(app, "debug", False)
    monkeypatch.setattr(app, "middleware_stack", None)
    async with AsyncClient(
        transport=ASGITransport(app=app, raise_app_exceptions=False),
        base_url="http://test",
        cookies=admin_client.cookies,
    ) as error_client:
        yield error_client


@pytest.fixture
def authenticated_user(
    _authenticated_user_and_client: tuple[User, AsyncClient],
) -> User:
    """The user behind `authenticated_client`, which holds no role."""
    return _authenticated_user_and_client[0]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _trigger(client: AsyncClient) -> Response:
    """The trigger, sent without a request body."""
    response = await client.post(_TRIGGER)
    assert response.request.content == b""
    return response


def _assert_untouched(spy: AdmissionSpy) -> None:
    """No fence, setting read, Redis client, lease, or publication."""
    assert spy.sequence == []
    assert spy.clients == 0
    assert spy.task_ids == []
    assert spy.published == []


def _assert_no_secret(response: Response, *secrets_: str) -> None:
    """Neither the body nor any header carries a run identity, the lease
    token, or injected exception text."""
    rendered = [response.text, *(f"{k}: {v}" for k, v in response.headers.items())]
    for secret in (LEAK_MARKER, "v1:", *secrets_):
        assert not any(secret in part for part in rendered), secret


async def _unlock_once(connection: AsyncConnection) -> None:
    """Release the fence once ahead of the admission's own unlock, which
    then returns the definitive `false` of a session holding nothing."""
    released: bool = (await connection.execute(_UNLOCK)).scalar_one()
    await connection.commit()
    assert released is True


async def _audit_counts(session: AsyncSession) -> dict[str, int]:
    return {
        model.__name__: (
            await session.execute(select(func.count()).select_from(model))
        ).scalar_one()
        for model in (SettingAuditEvent, TicketAuditEvent)
    }


# ---------------------------------------------------------------------------
# 202 Accepted
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestSubmitted:
    @pytest.mark.parametrize("target", ["3.1", "4.0"])
    async def test_returns_202_with_the_exact_body_for_the_persisted_version(
        self,
        h: RecalculationHarness,
        spy: AdmissionSpy,
        admin_client: AsyncClient,
        target: str,
    ) -> None:
        """The body names the persisted version read under the fence and
        nothing else: no task ID, lease token, or run state; the request
        carried no body."""
        await h.world.set_setting(target)

        with capture_events() as logs:
            response = await _trigger(admin_client)

        assert response.status_code == 202
        assert response.json() == _accepted(target)
        task_id = spy.task_id
        assert spy.published == [
            Publication(_TASK_NAME, {"target_version": target}, task_id, None)
        ]
        assert await h.lease() == _token(task_id, target)
        assert await h.fence_holders() == []
        _assert_no_secret(response, task_id, _token(task_id, target))
        # The admission events correlate through this request's ID only.
        events = [
            entry
            for entry in runner_events(logs)
            if entry["event"] in _ADMISSION_EVENTS
        ]
        assert [entry["event"] for entry in events] == [ADMITTED_EVENT, SUBMITTED_EVENT]
        request_id = response.headers["x-request-id"]
        assert all(entry["request_id"] == request_id for entry in events)
        assert task_id not in repr(events)

    async def test_api_key_credentials_are_accepted(
        self,
        h: RecalculationHarness,
        spy: AdmissionSpy,
        admin_api_key_client: AsyncClient,
    ) -> None:
        response = await _trigger(admin_api_key_client)

        assert response.status_code == 202
        assert response.json() == _accepted()
        assert spy.sequence == ["fence", "setting", "lease", "release", "publish"]
        assert await h.lease() == _token(spy.task_id)

    async def test_creates_no_audit_event_and_leaves_the_setting_unchanged(
        self,
        h: RecalculationHarness,
        spy: AdmissionSpy,
        admin_client: AsyncClient,
    ) -> None:
        """System Settings Mutation > API tests: the manual trigger creates
        no setting audit event and leaves the persisted setting unchanged;
        Publication Uncertainty: no `TicketAuditEvent` either."""
        before = await h.world.read(_audit_counts)

        response = await _trigger(admin_client)

        assert response.status_code == 202
        assert await h.world.read(_audit_counts) == before
        assert await h.world.setting() == TARGET


# ---------------------------------------------------------------------------
# 409 CVSS_RECALC_ALREADY_IN_PROGRESS
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestAlreadyInProgress:
    async def test_held_fence_returns_409_and_publishes_nothing(
        self,
        h: RecalculationHarness,
        spy: AdmissionSpy,
        admin_client: AsyncClient,
    ) -> None:
        """An independent connection, standing for another process, holds
        the fence; the lease is absent."""
        holder = (await h.borrow()).connection
        holder_pid = connection_pid(holder)
        assert await try_acquire_execution_fence(holder) is FenceAcquireOutcome.ACQUIRED

        response = await _trigger(admin_client)

        assert response.status_code == 409
        assert response.json() == _IN_PROGRESS
        assert spy.sequence == ["fence"]
        assert spy.clients == 0
        assert spy.published == []
        assert await h.lease() is None
        assert await h.fence_holders() == [holder_pid]
        assert await release_execution_fence(holder) is FenceReleaseOutcome.RELEASED

    async def test_held_lease_returns_409_and_publishes_nothing(
        self,
        h: RecalculationHarness,
        spy: AdmissionSpy,
        admin_client: AsyncClient,
    ) -> None:
        other = await h.admit()

        response = await _trigger(admin_client)

        assert response.status_code == 409
        assert response.json() == _IN_PROGRESS
        assert spy.sequence == ["fence", "setting", "lease", "release"]
        assert spy.published == []
        assert await h.lease() == _token(other)
        assert await h.fence_holders() == []
        _assert_no_secret(response, other, spy.task_id)


# ---------------------------------------------------------------------------
# 503 REDIS_UNAVAILABLE and CELERY_UNAVAILABLE
# ---------------------------------------------------------------------------


class _MimickingOperationalError(BrokerOperationalError):  # type: ignore[misc]
    """A broker operational error whose text names another class."""


@pytest.mark.e2e
class TestServiceUnavailable:
    @pytest.mark.parametrize(
        ("make_error", "after_write"),
        [
            pytest.param(
                lambda: RedisConnectionError(f"refused {LEAK_MARKER}"),
                False,
                id="connection-error",
            ),
            pytest.param(
                lambda: RedisTimeoutError(f"timed out {LEAK_MARKER}"),
                True,
                id="timeout-after-write",
            ),
        ],
    )
    async def test_redis_error_on_lease_acquire_returns_the_sanitized_503(
        self,
        h: RecalculationHarness,
        spy: AdmissionSpy,
        admin_client: AsyncClient,
        make_error: Callable[[], BaseException],
        after_write: bool,
    ) -> None:
        spy.lease_error = make_error()
        spy.lease_error_after_write = after_write

        response = await _trigger(admin_client)

        assert response.status_code == 503
        assert response.json() == _REDIS_UNAVAILABLE
        assert spy.sequence == ["fence", "setting", "lease", "release"]
        assert spy.published == []
        assert await h.fence_holders() == []
        _assert_no_secret(response, spy.task_id)

    @pytest.mark.parametrize(
        "make_error",
        [
            pytest.param(
                lambda: BrokerOperationalError(f"connection refused {LEAK_MARKER}"),
                id="operational",
            ),
            pytest.param(
                lambda: _MimickingOperationalError(f"EncodeError: {LEAK_MARKER}"),
                id="subclass-text-mimics-encode",
            ),
        ],
    )
    async def test_broker_operational_error_returns_503_and_retains_the_lease(
        self,
        h: RecalculationHarness,
        spy: AdmissionSpy,
        admin_client: AsyncClient,
        make_error: Callable[[], BaseException],
    ) -> None:
        """Acceptance unconfirmed: the fixed detail without the broker
        text, and the lease retained (with its TTL) for a delivery that may
        still adopt it."""
        spy.publish_error = make_error()

        response = await _trigger(admin_client)

        assert response.status_code == 503
        assert response.json() == _CELERY_UNAVAILABLE
        task_id = spy.task_id
        assert [call.task_id for call in spy.published] == [task_id]
        assert await h.lease() == _token(task_id)
        assert await h.redis.ttl(LEASE_KEY) > 0
        assert await h.fence_holders() == []
        _assert_no_secret(response, task_id)


# ---------------------------------------------------------------------------
# Global 500 INTERNAL_ERROR
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestInternalError:
    async def test_missing_setting_row_returns_500_before_publication(
        self,
        h: RecalculationHarness,
        spy: AdmissionSpy,
        admin_error_client: AsyncClient,
    ) -> None:
        """`RequiredSystemSettingMissingError` is a `SettingsServiceError`
        the route does not map: it reaches the global `500`."""
        await h.world.delete_setting()

        response = await _trigger(admin_error_client)

        assert response.status_code == 500
        assert response.json() == _INTERNAL_ERROR
        assert spy.sequence == ["fence", "setting", "release"]
        assert spy.published == []
        assert await h.lease() is None
        assert await h.fence_holders() == []

    async def test_database_error_on_setting_read_returns_500_before_publication(
        self,
        h: RecalculationHarness,
        spy: AdmissionSpy,
        admin_error_client: AsyncClient,
    ) -> None:
        spy.setting_error = database_error()

        response = await _trigger(admin_error_client)

        assert response.status_code == 500
        assert response.json() == _INTERNAL_ERROR
        assert spy.sequence == ["fence", "setting", "release"]
        assert spy.published == []
        assert await h.lease() is None
        assert await h.fence_holders() == []
        _assert_no_secret(response)

    @pytest.mark.parametrize(
        "make_error",
        [
            pytest.param(database_error, id="database-error"),
            pytest.param(lambda: TimeoutError(LEAK_MARKER), id="timeout"),
        ],
    )
    async def test_raising_fence_release_returns_500_without_publication(
        self,
        h: RecalculationHarness,
        spy: AdmissionSpy,
        admin_error_client: AsyncClient,
        make_error: Callable[[], BaseException],
    ) -> None:
        """The publisher is never invoked, so the outcome is never
        `CELERY_UNAVAILABLE`; the acquired lease is removed owner-safely."""
        spy.release_error = make_error()

        response = await _trigger(admin_error_client)

        assert response.status_code == 500
        assert response.json() == _INTERNAL_ERROR
        assert spy.sequence == ["fence", "setting", "lease", "release", "delete"]
        assert spy.published == []
        assert await h.lease() is None
        await wait_until_fence_free(h.engine)
        _assert_no_secret(response, spy.task_id)

    async def test_definitive_false_unlock_returns_500_without_publication(
        self,
        h: RecalculationHarness,
        spy: AdmissionSpy,
        admin_error_client: AsyncClient,
    ) -> None:
        spy.before_release = _unlock_once

        response = await _trigger(admin_error_client)

        assert response.status_code == 500
        assert response.json() == _INTERNAL_ERROR
        assert spy.release_raised == []
        assert spy.sequence == ["fence", "setting", "lease", "release", "delete"]
        assert spy.published == []
        assert await h.lease() is None
        assert await h.fence_holders() == []

    @pytest.mark.parametrize(
        "make_error",
        [
            pytest.param(lambda: EncodeError(LEAK_MARKER), id="encode"),
            pytest.param(lambda: SerializerNotInstalled(LEAK_MARKER), id="serializer"),
            pytest.param(lambda: TypeError(LEAK_MARKER), id="programming"),
            pytest.param(
                lambda: RuntimeError(f"OperationalError: refused {LEAK_MARKER}"),
                id="text-mimics-operational",
            ),
        ],
    )
    async def test_non_operational_publisher_error_returns_500_and_keeps_the_lease(
        self,
        h: RecalculationHarness,
        spy: AdmissionSpy,
        admin_error_client: AsyncClient,
        make_error: Callable[[], BaseException],
    ) -> None:
        """Only `kombu.exceptions.OperationalError`, by class, is
        `CELERY_UNAVAILABLE`; every other publisher exception is the global
        `500`, and the lease is retained conservatively."""
        spy.publish_error = make_error()

        response = await _trigger(admin_error_client)

        assert response.status_code == 500
        assert response.json() == _INTERNAL_ERROR
        task_id = spy.task_id
        assert [call.task_id for call in spy.published] == [task_id]
        assert await h.lease() == _token(task_id)
        assert await h.fence_holders() == []
        _assert_no_secret(response, task_id)


# ---------------------------------------------------------------------------
# The response reflects only its own publication outcome
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestOwnOutcomeOnly:
    async def test_retained_lease_is_409_and_after_removal_a_trigger_is_202(
        self,
        h: RecalculationHarness,
        spy: AdmissionSpy,
        admin_client: AsyncClient,
    ) -> None:
        """An earlier acceptance-unconfirmed admission retains its lease, so
        a new trigger is `lease_held`; its body is the fixed `409` and says
        nothing about the earlier run. After owner-safe removal of that
        lease, a trigger is admitted, and its exact `202` body asserts
        nothing about earlier runs (Publication Uncertainty)."""
        spy.publish_error = BrokerOperationalError(LEAK_MARKER)
        unconfirmed = await _trigger(admin_client)
        assert unconfirmed.status_code == 503
        assert unconfirmed.json() == _CELERY_UNAVAILABLE
        first = spy.task_ids[0]
        assert await h.lease() == _token(first)

        spy.publish_error = None
        blocked = await _trigger(admin_client)

        assert blocked.status_code == 409
        assert blocked.json() == _IN_PROGRESS
        assert len(spy.published) == 1
        assert await h.lease() == _token(first)
        _assert_no_secret(blocked, first, *spy.task_ids)

        deleted = await compare_and_delete_lease(
            h.redis, task_id=first, target_version=TARGET
        )
        assert deleted is LeaseDeleteOutcome.DELETED
        admitted = await _trigger(admin_client)

        assert admitted.status_code == 202
        assert admitted.json() == _accepted()
        second = spy.task_ids[-1]
        assert second != first
        assert [call.task_id for call in spy.published] == [first, second]
        assert await h.lease() == _token(second)
        _assert_no_secret(admitted, first, second)


# ---------------------------------------------------------------------------
# Authentication and authorization
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestAccessControl:
    @pytest.mark.parametrize(
        "headers",
        [
            pytest.param({}, id="missing"),
            pytest.param({"Authorization": "Bearer invalid-token"}, id="invalid"),
        ],
    )
    async def test_without_credentials_is_401_before_any_coordination(
        self,
        h: RecalculationHarness,
        spy: AdmissionSpy,
        client: AsyncClient,
        headers: dict[str, str],
    ) -> None:
        response = await client.post(_TRIGGER, headers=headers)

        assert response.status_code == 401
        assert response.json() == _NOT_AUTHENTICATED
        _assert_untouched(spy)
        assert await h.lease() is None
        assert await h.fence_holders() == []

    @pytest.mark.parametrize("role", [None, Role.VULNERABILITY_ANALYST])
    async def test_without_manage_settings_is_403_before_any_coordination(
        self,
        h: RecalculationHarness,
        spy: AdmissionSpy,
        authenticated_client: AsyncClient,
        authenticated_user: User,
        user_role_factory: Callable[..., Awaitable[UserRole]],
        role: Role | None,
    ) -> None:
        if role is not None:
            await user_role_factory(user_id=authenticated_user.id, role=role.value)

        response = await _trigger(authenticated_client)

        assert response.status_code == 403
        assert response.json() == _INSUFFICIENT_PERMISSION
        _assert_untouched(spy)
        assert await h.lease() is None
        assert await h.fence_holders() == []

    async def test_jwt_session_credentials_are_accepted(
        self,
        h: RecalculationHarness,
        spy: AdmissionSpy,
        admin_client: AsyncClient,
    ) -> None:
        response = await _trigger(admin_client)

        assert response.status_code == 202
        assert response.json() == _accepted()
        assert await h.lease() == _token(spy.task_id)


# ---------------------------------------------------------------------------
# Thin route: no business query, no session factory, 1:1 exception mapping
# ---------------------------------------------------------------------------


def _handler() -> ast.AsyncFunctionDef:
    source = textwrap.dedent(inspect.getsource(settings_api.trigger_cvss_recalculation))
    node = ast.parse(source).body[0]
    assert isinstance(node, ast.AsyncFunctionDef)
    assert node.name == "trigger_cvss_recalculation"
    return node


def _body_nodes(handler: ast.AsyncFunctionDef) -> list[ast.AST]:
    """Every node of the handler body (its decorators, which declare the
    route and the capability guard, excluded)."""
    return [node for statement in handler.body for node in ast.walk(statement)]


def _route() -> APIRoute:
    """The registered trigger route. `app.routes` alone does not expose
    routes included via `include_router()` (see
    `tests/test_api_conventions.py`)."""
    matches = [
        context.original_route
        for context in fastapi_routing.iter_route_contexts(app.routes)
        if isinstance(context.original_route, APIRoute)
        and context.path == _TRIGGER
        and "POST" in (context.methods or set())
    ]
    assert len(matches) == 1
    route = matches[0]
    assert isinstance(route, APIRoute)
    return route


_FORBIDDEN_NAMES = {
    "DatabaseSession",
    "AsyncSession",
    "get_db",
    "async_session_factory",
    "session_factory",
    "async_sessionmaker",
    "get_cvss_admission_bind",
    "database",
    "engine",
    "select",
    "text",
    "execute",
    "scalar",
    "scalars",
    "commit",
}

_EXPECTED_MAPPING = {
    "settings_service.CVSSRecalculationAlreadyInProgressError": (
        409,
        "ErrorCode.CVSS_RECALC_ALREADY_IN_PROGRESS",
        "settings_service.CVSS_RECALCULATION_IN_PROGRESS_MESSAGE",
    ),
    "cvss_recalculation_admission.CVSSRecalculationRedisUnavailableError": (
        503,
        "ErrorCode.REDIS_UNAVAILABLE",
        "cvss_recalculation_admission.REDIS_UNAVAILABLE_MESSAGE",
    ),
    "cvss_recalculation_admission.CVSSRecalculationBrokerUnavailableError": (
        503,
        "ErrorCode.CELERY_UNAVAILABLE",
        "cvss_recalculation_admission.BROKER_UNAVAILABLE_MESSAGE",
    ),
}


@pytest.mark.unit
class TestThinRoute:
    def test_route_is_registered_to_the_handler_with_status_202(self) -> None:
        route = _route()

        assert route.endpoint is settings_api.trigger_cvss_recalculation
        assert route.status_code == 202
        assert route.body_field is None

    def test_handler_takes_only_the_principal(self) -> None:
        """No `DatabaseSession` or other dependency besides the capability
        guard: the admission owns its own connection."""
        signature = inspect.signature(settings_api.trigger_cvss_recalculation)
        assert list(signature.parameters) == ["principal"]
        handler = _handler()
        annotations = [
            ast.unparse(arg.annotation)
            for arg in (*handler.args.args, *handler.args.kwonlyargs)
            if arg.annotation is not None
        ]
        assert annotations, "the principal parameter is annotated"
        assert not any(
            name in annotation
            for annotation in annotations
            for name in ("DatabaseSession", "AsyncSession", "get_db")
        )

    def test_handler_performs_no_query_and_references_no_session_factory(
        self,
    ) -> None:
        nodes = _body_nodes(_handler())
        referenced = {node.id for node in nodes if isinstance(node, ast.Name)} | {
            node.attr for node in nodes if isinstance(node, ast.Attribute)
        }

        assert referenced & _FORBIDDEN_NAMES == set()
        calls = {ast.unparse(node.func) for node in nodes if isinstance(node, ast.Call)}
        assert calls == {
            "cvss_recalculation_admission.admit_cvss_recalculation",
            "AppError",
            "CVSSRecalculationTriggerResponse",
            "CVSSRecalculationTriggerData",
        }
        awaited = [
            ast.unparse(node.value) for node in nodes if isinstance(node, ast.Await)
        ]
        assert awaited == ["cvss_recalculation_admission.admit_cvss_recalculation()"]

    def test_settings_router_module_references_no_session_factory(self) -> None:
        """The router obtains no session factory, engine, or admission bind
        of its own: the request session comes from `DatabaseSession`, and
        the admission's connection from the service."""
        source = inspect.getsource(settings_api)
        for name in (
            "async_session_factory",
            "async_sessionmaker",
            "create_async_engine",
            "database.engine",
            "get_cvss_admission_bind",
        ):
            assert name not in source, name

    def test_each_admission_exception_maps_individually_to_one_response(
        self,
    ) -> None:
        """Exactly three `except` clauses, one per admission exception and
        none for a base class, each raising one fixed `AppError` with the
        cause suppressed (Service Exception Conventions: 1:1 mapping)."""
        tries = [node for node in _body_nodes(_handler()) if isinstance(node, ast.Try)]
        assert len(tries) == 1
        (try_node,) = tries
        assert try_node.orelse == []
        assert try_node.finalbody == []
        mapping: dict[str, tuple[int, str, str]] = {}
        for clause in try_node.handlers:
            assert clause.type is not None, "a bare except"
            assert clause.name is None
            assert len(clause.body) == 1
            raise_node = clause.body[0]
            assert isinstance(raise_node, ast.Raise)
            assert isinstance(raise_node.cause, ast.Constant)
            assert raise_node.cause.value is None
            error = raise_node.exc
            assert isinstance(error, ast.Call)
            assert ast.unparse(error.func) == "AppError"
            keywords = {kw.arg: kw.value for kw in error.keywords}
            assert set(keywords) == {"status_code", "code", "detail"}
            status = keywords["status_code"]
            assert isinstance(status, ast.Constant)
            assert isinstance(status.value, int)
            mapping[ast.unparse(clause.type)] = (
                status.value,
                ast.unparse(keywords["code"]),
                ast.unparse(keywords["detail"]),
            )

        assert mapping == _EXPECTED_MAPPING

        caught = [
            settings_service.CVSSRecalculationAlreadyInProgressError,
            admission.CVSSRecalculationRedisUnavailableError,
            admission.CVSSRecalculationBrokerUnavailableError,
        ]
        assert vars(settings_api)["settings_service"] is settings_service
        assert vars(settings_api)["cvss_recalculation_admission"] is admission
        for cls in caught:
            assert cls not in (settings_service.SettingsServiceError, ServiceError)
            assert not any(
                issubclass(cls, other) for other in caught if other is not cls
            )
        assert not any(
            issubclass(settings_service.RequiredSystemSettingMissingError, cls)
            for cls in caught
        )


@pytest.mark.e2e
class TestRequestSession:
    async def test_request_session_runs_no_business_query(
        self,
        h: RecalculationHarness,
        spy: AdmissionSpy,
        admin_api_key_client: AsyncClient,
        db_session: AsyncSession,
    ) -> None:
        """At runtime, the request `DatabaseSession` serves authentication
        only: the setting read and the fence run on the admission's own
        connection, which a listener proves observed them."""
        with (
            StatementRecorder(db_session) as request_statements,
            ConnectionStatements(h.connection) as admission_statements,
        ):
            response = await _trigger(admin_api_key_client)

        assert response.status_code == 202
        assert request_statements.statements
        assert not any(
            "system_setting" in statement or "advisory" in statement
            for statement in request_statements.statements
        )
        assert request_statements.writes() == []
        assert request_statements.row_locks() == []
        executed = [statement for statement, _ in admission_statements.statements]
        assert any("system_setting" in statement for statement in executed)
        assert any("pg_try_advisory_lock" in statement for statement in executed)
