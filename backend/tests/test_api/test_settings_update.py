"""End-to-end tests of `PATCH /api/v1/admin/settings`
(`update_system_settings`, backend/app/api/v1/settings.py).

Owning specifications:

- docs/features/platform/system-settings.md (Default CVSS Version; Setting
  Mutation Service; Service Exceptions; Update System Settings; Setting
  Audit Log; List Settings Audit Events);
- docs/api-spec.md (Global Responses; Partial Update Semantics: a
  single-field PATCH whose field is required);
- docs/deployment.md (a failed or unconfirmed PATCH is reconciled by
  re-reading the setting);
- docs/features/platform/testing-strategy.md (System Settings Mutation >
  API tests; Default-CVSS Impact Preview > Regression tests: the preview is
  not a prerequisite for the PATCH; All-CVE Recalculation Runner >
  Coordination API tests: a setting PATCH performs no Redis access, lease
  acquisition, broker call, or post-commit callback; Mandatory Test
  Scenarios > API Endpoints; Audit Trail Testing);
- issue #838, decision W3: undeclared body members are ignored, so a
  preview count, high-water mark, or token sent in the body has no effect.

Most tests run through the shared `client`, whose request session is the
savepoint-wrapped `db_session`; the transaction-boundary tests use the real
`app.database.get_db` on independent sessions of the test engine and delete
their committed rows explicitly. The held execution fence is a real
session-level fence on an independent connection of a dedicated `NullPool`
engine, standing in for an active runner in another process; the committed
transaction-boundary test is the API-level proof of the `409` and of a no-op
against the held fence. Every `200` body is compared whole with `==`, which
also proves the absence of change, run, and scheduling fields.

Classification, statement order, the held-fence behavior, and the
concurrency matrix of the service are proven by
`tests/test_services/test_settings_mutation.py` and
`tests/test_services/test_settings_mutation_races.py`; the absence of
statements in the handler by the AST checks of `TestThinRoute`. The shared
NUL-character check (api-spec.md, NUL Characters in Request Input) is
proven by `tests/test_api/test_request_nul.py` and
`tests/test_core/test_request_nul.py`. These tests cover the HTTP contract,
the transaction boundary, and the audit actor. The OpenAPI surface is
asserted in `tests/test_api/test_settings.py`. The endpoint addresses no
resource, so the mandatory 404 scenario does not apply.

Expected values are transcribed from the specifications, never computed
with the module under test.
"""

from __future__ import annotations

import ast
import hashlib
import inspect
import secrets
import textwrap
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from typing import Any, Literal
from unittest.mock import AsyncMock

import celery
import celery.app.task
import pytest
import pytest_asyncio
import redis
import redis.asyncio as redis_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete, select, update
from sqlalchemy.exc import OperationalError
from sqlalchemy.ext.asyncio import (
    AsyncConnection,
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import NullPool

from app import database
from app.api import dependencies
from app.api.v1 import settings as settings_api
from app.core.enums import Role, Severity
from app.database import get_db
from app.main import app
from app.models.api_key import ApiKey
from app.models.setting_audit_event import SettingAuditEvent
from app.models.system_setting import SystemSetting
from app.models.user import User
from app.models.user_role import UserRole
from app.services import (
    cvss_impact_preview,
    cvss_recalculation_admission,
    task_publication,
)
from app.services import cvss_recalculation_coordination as coordination
from app.services import settings as settings_service
from app.services.cvss_recalculation_coordination import (
    FenceAcquireOutcome,
    FenceReleaseOutcome,
    release_execution_fence,
    try_acquire_execution_fence,
)
from tests.support.cvss_chain import Assessment, CVEBuilder
from tests.support.ticket_api import INTERNAL_ERROR, force_production_error_page

pytest_plugins = ["tests.support.ticket_mutation_fixtures"]

Factory = Callable[..., Awaitable[Any]]
SessionFactory = Callable[[], Awaitable[AsyncSession]]
Seed = Callable[[str], Awaitable[SystemSetting]]
Version = Literal["3.1", "4.0"]

_PATH = "/api/v1/admin/settings"
_AUDIT_LOG = "/api/v1/admin/settings/audit-log"
_PREVIEW = "/api/v1/admin/settings/default-cvss-version/impact"
_KEY = "default_cvss_version"

# system-settings.md, Service Exceptions; the fixed detail of issue #837 (V6).
_IN_PROGRESS = {
    "code": "CVSS_RECALC_ALREADY_IN_PROGRESS",
    "detail": "A CVSS recalculation is already in progress.",
}
# api-spec.md, Global Responses.
_UNAUTHENTICATED = {
    "code": "AUTH_NOT_AUTHENTICATED",
    "detail": "Authentication required",
}
_FORBIDDEN = {
    "code": "AUTH_INSUFFICIENT_PERMISSION",
    "detail": "Insufficient permissions",
}
_VALIDATION_DETAIL = "Request validation failed"

_CHANGES = [
    pytest.param("3.1", "4.0", id="3.1-to-4.0"),
    pytest.param("4.0", "3.1", id="4.0-to-3.1"),
]
_VALUES = [pytest.param("3.1", id="3.1"), pytest.param("4.0", id="4.0")]

_ADMIN_FULL_NAME = "Alice Admin"


def _settings(version: str) -> dict[str, Any]:
    """The exact `200` body (Update System Settings)."""
    return {"data": {"default_cvss_version": version}}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_api_key_credential() -> tuple[str, str]:
    """Return `(plaintext_token, sha256_hex_digest)` for a synthetic key.

    Mirrors the identical helper in `tests/test_api/test_settings.py`.
    """
    token = "stl_ak_" + secrets.token_hex(16)
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
    return token, digest


async def _persisted(session: AsyncSession) -> str | None:
    """The stored value, read with a column query that bypasses the
    identity map."""
    return await session.scalar(
        select(SystemSetting.value).where(SystemSetting.key == _KEY)
    )


async def _events(session: AsyncSession) -> list[tuple[Any, ...]]:
    """Every `SettingAuditEvent` as `(event_type, setting_key, user_id,
    old_value, new_value)`, in insertion (UUIDv7 `id`) order."""
    rows = await session.execute(
        select(
            SettingAuditEvent.event_type,
            SettingAuditEvent.setting_key,
            SettingAuditEvent.user_id,
            SettingAuditEvent.old_value,
            SettingAuditEvent.new_value,
        ).order_by(SettingAuditEvent.id)
    )
    return [tuple(row) for row in rows]


def _changed(user_id: uuid.UUID, old: str, new: str) -> tuple[Any, ...]:
    return ("setting_changed", _KEY, user_id, old, new)


def _validation_errors(body: Any) -> list[tuple[list[Any], str]]:
    """The `(loc, type)` of each error of a global `422` envelope, after
    asserting the envelope's fixed members."""
    assert set(body) == {"code", "detail", "errors"}
    assert body["code"] == "VALIDATION_ERROR"
    assert body["detail"] == _VALIDATION_DETAIL
    return [(error["loc"], error["type"]) for error in body["errors"]]


_ROUTER_DRAIN = "drain_ticket_convergence_after_commit.<locals>.<lambda>"


def _post_commit_callbacks(session: AsyncSession) -> list[str]:
    """The qualified names of the post-commit callbacks registered on a
    request session.

    Every `/api/v1` router mounts `drain_ticket_convergence_after_commit`
    (app/main.py), whose single callback drains the Ticket convergence
    effects registered in the request transaction, so `_ROUTER_DRAIN` is
    present on every request; any other entry would be the PATCH's own.
    """
    callbacks = session.info.get(database._POST_COMMIT_CALLBACKS_KEY, [])
    return [callback.__qualname__ for callback in callbacks]


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def seed(system_setting_factory: Factory) -> Seed:
    """Persist `default_cvss_version` (the test schema has none)."""

    async def _seed(value: str) -> SystemSetting:
        setting: SystemSetting = await system_setting_factory(key=_KEY, value=value)
        return setting

    return _seed


@pytest.fixture
def user_and_client(
    _authenticated_user_and_client: tuple[User, AsyncClient],
) -> tuple[User, AsyncClient]:
    """The shared `client` authenticated by a JWT session cookie as a user
    holding no role."""
    return _authenticated_user_and_client


@pytest_asyncio.fixture
async def admin_and_client(
    _authenticated_user_and_client: tuple[User, AsyncClient],
    user_role_factory: Factory,
    db_session: AsyncSession,
) -> tuple[User, AsyncClient]:
    """The shared `client`, authenticated by a JWT session cookie as a user
    holding only the Admin role."""
    user, client = _authenticated_user_and_client
    await user_role_factory(user_id=user.id, role=Role.ADMIN.value)
    user.full_name = _ADMIN_FULL_NAME
    await db_session.flush()
    return user, client


@pytest_asyncio.fixture
async def api_key_admin_and_client(
    client: AsyncClient,
    user_factory: Factory,
    user_role_factory: Factory,
    api_key_factory: Callable[..., Awaitable[ApiKey]],
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[User, AsyncClient]:
    """The shared `client`, authenticated as an admin by an API key
    (`Authorization: Bearer`) instead of a JWT session cookie. Mirrors
    `admin_api_key_client` in `tests/test_api/test_settings.py`, also
    returning the key's owner."""
    user: User = await user_factory(username="bob.admin", email="bob.admin@example.com")
    await user_role_factory(user_id=user.id, role=Role.ADMIN.value)
    token, digest = _make_api_key_credential()
    await api_key_factory(user_id=user.id, key_hash=digest)
    monkeypatch.setattr(dependencies._last_used_debouncer, "touch", AsyncMock())
    client.headers["Authorization"] = f"Bearer {token}"
    return user, client


@pytest_asyncio.fixture
async def admin_error_client(
    admin_and_client: tuple[User, AsyncClient], monkeypatch: pytest.MonkeyPatch
) -> AsyncIterator[AsyncClient]:
    """The admin's JWT session on a transport with
    `raise_app_exceptions=False`, so an unhandled exception yields the
    transmitted global `500` instead of re-raising into the test. The
    `get_db` override installed by `client` still applies. Mirrors the
    identical fixture in `tests/test_api/test_settings_recalculate.py`."""
    force_production_error_page(monkeypatch)
    _admin, client = admin_and_client
    async with AsyncClient(
        transport=ASGITransport(app=app, raise_app_exceptions=False),
        base_url="http://test",
        cookies=client.cookies,
    ) as error_client:
        yield error_client


@pytest.fixture
def forbidden_service(monkeypatch: pytest.MonkeyPatch) -> AsyncMock:
    """Replace the mutation service with a stub that must not run."""
    service = AsyncMock(side_effect=AssertionError("the service must not run"))
    monkeypatch.setattr(settings_service, "update_default_cvss_version", service)
    return service


@pytest.fixture
def service_calls(
    monkeypatch: pytest.MonkeyPatch,
) -> list[tuple[tuple[Any, ...], dict[str, Any]]]:
    """Record the arguments of every call to the real mutation service."""
    calls: list[tuple[tuple[Any, ...], dict[str, Any]]] = []
    original = settings_service.update_default_cvss_version

    async def _recording(*args: Any, **kwargs: Any) -> str:
        calls.append((args, kwargs))
        return await original(*args, **kwargs)

    monkeypatch.setattr(settings_service, "update_default_cvss_version", _recording)
    return calls


@pytest.fixture
def preview_calls(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Record the proposed version of every call to the real preview
    service, which still runs."""
    calls: list[str] = []
    original = cvss_impact_preview.get_default_cvss_version_impact

    async def _recording(session: AsyncSession, proposed_version: Any) -> Any:
        calls.append(proposed_version)
        return await original(session, proposed_version)

    monkeypatch.setattr(
        cvss_impact_preview, "get_default_cvss_version_impact", _recording
    )
    return calls


@pytest.fixture
async def held_fence(_engine: AsyncEngine) -> AsyncIterator[AsyncConnection]:
    """The session-level execution fence held by an independent connection
    of a dedicated `NullPool` engine, standing in for an active runner in
    another process; released at teardown."""
    engine = create_async_engine(_engine.url, poolclass=NullPool)
    try:
        connection = await engine.connect()
        try:
            assert (
                await try_acquire_execution_fence(connection)
                == FenceAcquireOutcome.ACQUIRED
            )
            yield connection
            assert (
                await release_execution_fence(connection)
                == FenceReleaseOutcome.RELEASED
            )
        finally:
            await connection.close()
    finally:
        await engine.dispose()


@pytest.fixture
def external_calls(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Replace every Redis, lease, session-level fence, publication,
    Celery, admission, and post-commit entry point with a recorder that
    also fails the call. Mirrors the service-test fixture in
    `tests/test_services/test_settings_mutation.py`, adding the manual
    admission."""
    calls: list[str] = []

    def _forbidden(name: str) -> Callable[..., Any]:
        def _call(*args: Any, **kwargs: Any) -> Any:
            calls.append(name)
            raise AssertionError(f"unexpected external side effect: {name}")

        return _call

    targets: list[tuple[object, str]] = [
        (redis_asyncio.Redis, "from_url"),
        (redis.Redis, "from_url"),
        (coordination, "new_cvss_recalculation_redis_client"),
        (coordination, "acquire_lease"),
        (coordination, "compare_and_renew_lease"),
        (coordination, "compare_and_delete_lease"),
        (coordination, "try_acquire_execution_fence"),
        (coordination, "release_execution_fence"),
        (task_publication, "publish_task"),
        (celery.Celery, "send_task"),
        (celery.app.task.Task, "apply_async"),
        (database, "register_post_commit_callback"),
        (cvss_recalculation_admission, "admit_cvss_recalculation"),
    ]
    for target, name in targets:
        monkeypatch.setattr(target, name, _forbidden(name))
    return calls


# ---------------------------------------------------------------------------
# 200 OK: effective change
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestEffectiveChange:
    """Here and in `TestNoOp`, the exact equality of the whole body with
    `_settings()` also proves the absence of `recalculation_scheduled`,
    `changed`, run, progress, and scheduling fields (system-settings.md,
    Update System Settings)."""

    @pytest.mark.parametrize(("old", "new"), _CHANGES)
    async def test_jwt_admin_changes_the_setting_and_logs_one_event(
        self,
        admin_and_client: tuple[User, AsyncClient],
        seed: Seed,
        db_session: AsyncSession,
        old: Version,
        new: Version,
    ) -> None:
        admin, client = admin_and_client
        await seed(old)

        response = await client.patch(_PATH, json={"default_cvss_version": new})

        assert response.status_code == 200
        assert response.json() == _settings(new)
        assert await _persisted(db_session) == new
        assert await _events(db_session) == [_changed(admin.id, old, new)]

    @pytest.mark.parametrize(("old", "new"), _CHANGES)
    async def test_api_key_admin_changes_the_setting_and_is_the_actor(
        self,
        api_key_admin_and_client: tuple[User, AsyncClient],
        seed: Seed,
        db_session: AsyncSession,
        old: Version,
        new: Version,
    ) -> None:
        """No session-only guard: an administrator's API key is accepted,
        and the key's owner attributes the event."""
        admin, client = api_key_admin_and_client
        await seed(old)

        response = await client.patch(_PATH, json={"default_cvss_version": new})

        assert response.status_code == 200
        assert response.json() == _settings(new)
        assert await _persisted(db_session) == new
        assert await _events(db_session) == [_changed(admin.id, old, new)]

    async def test_each_change_is_attributed_to_its_own_requesting_admin(
        self,
        client: AsyncClient,
        user_factory: Factory,
        user_role_factory: Factory,
        api_key_factory: Callable[..., Awaitable[ApiKey]],
        seed: Seed,
        db_session: AsyncSession,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Two administrators, each with an API key, change the setting in
        turn: every event names the administrator whose credential made the
        request, never another user."""
        monkeypatch.setattr(dependencies._last_used_debouncer, "touch", AsyncMock())
        await user_factory(username="dave.viewer", email="dave.viewer@example.com")
        headers: dict[str, dict[str, str]] = {}
        admins: dict[str, User] = {}
        for name in ("alice.admin", "erin.admin"):
            admin: User = await user_factory(username=name, email=f"{name}@example.com")
            await user_role_factory(user_id=admin.id, role=Role.ADMIN.value)
            token, digest = _make_api_key_credential()
            await api_key_factory(user_id=admin.id, key_hash=digest)
            admins[name] = admin
            headers[name] = {"Authorization": f"Bearer {token}"}
        await seed("3.1")

        first = await client.patch(
            _PATH, json={"default_cvss_version": "4.0"}, headers=headers["erin.admin"]
        )
        second = await client.patch(
            _PATH, json={"default_cvss_version": "3.1"}, headers=headers["alice.admin"]
        )

        assert (first.status_code, second.status_code) == (200, 200)
        assert await _events(db_session) == [
            _changed(admins["erin.admin"].id, "3.1", "4.0"),
            _changed(admins["alice.admin"].id, "4.0", "3.1"),
        ]


# ---------------------------------------------------------------------------
# 200 OK: no-op
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestNoOp:
    @pytest.mark.parametrize("value", _VALUES)
    async def test_returns_the_persisted_value_without_an_event(
        self,
        admin_and_client: tuple[User, AsyncClient],
        seed: Seed,
        db_session: AsyncSession,
        value: Version,
    ) -> None:
        _admin, client = admin_and_client
        await seed(value)

        response = await client.patch(_PATH, json={"default_cvss_version": value})

        assert response.status_code == 200
        assert response.json() == _settings(value)
        assert await _persisted(db_session) == value
        assert await _events(db_session) == []


# ---------------------------------------------------------------------------
# 401 and 403
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
    async def test_without_credentials_is_401_and_changes_nothing(
        self,
        client: AsyncClient,
        seed: Seed,
        db_session: AsyncSession,
        forbidden_service: AsyncMock,
        headers: dict[str, str],
    ) -> None:
        await seed("3.1")

        response = await client.patch(
            _PATH, json={"default_cvss_version": "4.0"}, headers=headers
        )

        assert response.status_code == 401
        assert response.json() == _UNAUTHENTICATED
        forbidden_service.assert_not_awaited()
        assert await _persisted(db_session) == "3.1"
        assert await _events(db_session) == []

    @pytest.mark.parametrize(
        "role",
        [
            pytest.param(None, id="no-role"),
            pytest.param(Role.VULNERABILITY_ANALYST, id="vulnerability-analyst"),
            pytest.param(Role.RESTRICTED_ANALYST, id="restricted-analyst"),
        ],
    )
    async def test_without_manage_settings_is_403_and_changes_nothing(
        self,
        user_and_client: tuple[User, AsyncClient],
        user_role_factory: Factory,
        seed: Seed,
        db_session: AsyncSession,
        forbidden_service: AsyncMock,
        role: Role | None,
    ) -> None:
        """`manage_settings` is held only by Admin (rbac.md, Predefined
        Roles)."""
        user, client = user_and_client
        if role is not None:
            await user_role_factory(user_id=user.id, role=role.value)
        await seed("3.1")

        response = await client.patch(_PATH, json={"default_cvss_version": "4.0"})

        assert response.status_code == 403
        assert response.json() == _FORBIDDEN
        forbidden_service.assert_not_awaited()
        assert await _persisted(db_session) == "3.1"
        assert await _events(db_session) == []


# ---------------------------------------------------------------------------
# 422 VALIDATION_ERROR
# ---------------------------------------------------------------------------

_FIELD = ["body", "default_cvss_version"]


@pytest.mark.e2e
class TestRequestValidation:
    @pytest.mark.parametrize(
        ("body", "error_type"),
        [
            pytest.param({}, "missing", id="missing-field"),
            pytest.param({"default_cvss_version": None}, "literal_error", id="null"),
            pytest.param({"default_cvss_version": 4.0}, "literal_error", id="4.0"),
            pytest.param({"default_cvss_version": "3.0"}, "literal_error", id="3.0"),
            pytest.param(
                {"default_cvss_version": "4.0 "}, "literal_error", id="trailing-space"
            ),
        ],
    )
    async def test_invalid_field_is_422_without_invoking_the_service(
        self,
        admin_and_client: tuple[User, AsyncClient],
        seed: Seed,
        db_session: AsyncSession,
        forbidden_service: AsyncMock,
        body: dict[str, Any],
        error_type: str,
    ) -> None:
        _admin, client = admin_and_client
        await seed("3.1")

        response = await client.patch(_PATH, json=body)

        assert response.status_code == 422
        assert _validation_errors(response.json()) == [(_FIELD, error_type)]
        forbidden_service.assert_not_awaited()
        assert await _persisted(db_session) == "3.1"
        assert await _events(db_session) == []

    async def test_request_without_a_body_is_422_without_invoking_the_service(
        self,
        admin_and_client: tuple[User, AsyncClient],
        seed: Seed,
        db_session: AsyncSession,
        forbidden_service: AsyncMock,
    ) -> None:
        _admin, client = admin_and_client
        await seed("3.1")

        response = await client.patch(_PATH)

        assert response.request.content == b""
        assert response.status_code == 422
        assert _validation_errors(response.json()) == [(["body"], "missing")]
        forbidden_service.assert_not_awaited()
        assert await _persisted(db_session) == "3.1"
        assert await _events(db_session) == []


# ---------------------------------------------------------------------------
# Undeclared body members (issue #838, W3)
# ---------------------------------------------------------------------------

_PREVIEW_LIKE_MEMBERS: dict[str, Any] = {
    "cves_evaluated": 5,
    "cve_severity_changes": 3,
    "high_water_mark": "01a110a0-0000-7000-8000-000000000001",
    "preview_token": "fictional-preview-token",
    "no_op": True,
    "observed_default_cvss_version": "4.0",
}


@pytest.mark.e2e
class TestUndeclaredMembers:
    async def test_preview_state_in_the_body_is_ignored_on_an_effective_change(
        self,
        admin_and_client: tuple[User, AsyncClient],
        seed: Seed,
        db_session: AsyncSession,
        service_calls: list[tuple[tuple[Any, ...], dict[str, Any]]],
    ) -> None:
        """The request behaves exactly like `{"default_cvss_version":
        "4.0"}`: a claimed `no_op = true` and stale counts do not change
        the classification, and the service receives only the value and
        the actor."""
        admin, client = admin_and_client
        await seed("3.1")

        response = await client.patch(
            _PATH, json={"default_cvss_version": "4.0", **_PREVIEW_LIKE_MEMBERS}
        )

        assert response.status_code == 200
        assert response.json() == _settings("4.0")
        assert service_calls == [
            ((db_session,), {"new_version": "4.0", "acting_user_id": admin.id})
        ]
        assert await _persisted(db_session) == "4.0"
        assert await _events(db_session) == [_changed(admin.id, "3.1", "4.0")]


# ---------------------------------------------------------------------------
# Independence from the impact preview
# ---------------------------------------------------------------------------

# The ticketless CVE of `_ticketless_cve` proposed at `4.0` with the setting
# at `3.1`: the cascade takes the non-SUSE assessment at the default
# version, 5.0 Medium under `3.1` and 8.0 High under `4.0` — one evaluated
# CVE with one severity change (default-cvss-version-operations.md, Result
# and Count Units).
_ONE_CVE_IMPACT = {
    "observed_default_cvss_version": "3.1",
    "proposed_default_cvss_version": "4.0",
    "no_op": False,
    "cves_evaluated": 1,
    "cve_severity_changes": 1,
    "product_eligibility_changes": 0,
    "product_eligibility_override_skips": 0,
    "resolved_ticket_regressions": 0,
}


async def _ticketless_cve(cve_with: CVEBuilder) -> None:
    await cve_with(
        Assessment("5.0", provider="NVD", version="3.1"),
        Assessment("8.0", provider="NVD", version="4.0"),
        severity=Severity.MEDIUM,
    )


@pytest.mark.e2e
class TestPreviewIndependence:
    """testing-strategy.md, Default-CVSS Impact Preview > Regression tests:
    the preview is not a prerequisite for the PATCH, which neither receives
    nor reuses preview counts, the high-water mark, or any preview state."""

    async def test_change_without_a_prior_preview(
        self,
        admin_and_client: tuple[User, AsyncClient],
        seed: Seed,
        db_session: AsyncSession,
        cve_with: CVEBuilder,
        preview_calls: list[str],
    ) -> None:
        admin, client = admin_and_client
        await seed("3.1")
        await _ticketless_cve(cve_with)

        response = await client.patch(_PATH, json={"default_cvss_version": "4.0"})

        assert response.status_code == 200
        assert response.json() == _settings("4.0")
        assert preview_calls == []
        assert await _events(db_session) == [_changed(admin.id, "3.1", "4.0")]

    async def test_preview_of_another_proposal_does_not_affect_the_change(
        self,
        admin_and_client: tuple[User, AsyncClient],
        seed: Seed,
        db_session: AsyncSession,
        cve_with: CVEBuilder,
        preview_calls: list[str],
    ) -> None:
        """A no-op preview of `3.1` precedes an effective PATCH to
        `4.0`."""
        admin, client = admin_and_client
        await seed("3.1")
        await _ticketless_cve(cve_with)
        preview = await client.get(_PREVIEW, params={"proposed_version": "3.1"})
        assert preview.status_code == 200
        assert preview.json()["data"]["no_op"] is True

        response = await client.patch(_PATH, json={"default_cvss_version": "4.0"})

        assert response.status_code == 200
        assert response.json() == _settings("4.0")
        assert preview_calls == ["3.1"]
        assert await _persisted(db_session) == "4.0"
        assert await _events(db_session) == [_changed(admin.id, "3.1", "4.0")]

    async def test_stale_preview_counts_do_not_affect_the_change(
        self,
        admin_and_client: tuple[User, AsyncClient],
        seed: Seed,
        db_session: AsyncSession,
        cve_with: CVEBuilder,
        preview_calls: list[str],
    ) -> None:
        """The population grows after the preview, so its counts no longer
        describe the persisted state when the PATCH runs."""
        admin, client = admin_and_client
        await seed("3.1")
        await _ticketless_cve(cve_with)
        preview = await client.get(_PREVIEW, params={"proposed_version": "4.0"})
        assert preview.status_code == 200
        assert preview.json()["data"] == _ONE_CVE_IMPACT
        await _ticketless_cve(cve_with)
        await _ticketless_cve(cve_with)

        response = await client.patch(_PATH, json={"default_cvss_version": "4.0"})

        assert response.status_code == 200
        assert response.json() == _settings("4.0")
        assert preview_calls == ["4.0"]
        assert await _persisted(db_session) == "4.0"
        assert await _events(db_session) == [_changed(admin.id, "3.1", "4.0")]


# ---------------------------------------------------------------------------
# Thin route
# ---------------------------------------------------------------------------


def _handler() -> ast.AsyncFunctionDef:
    source = textwrap.dedent(inspect.getsource(settings_api.update_system_settings))
    node = ast.parse(source).body[0]
    assert isinstance(node, ast.AsyncFunctionDef)
    assert node.name == "update_system_settings"
    return node


def _body_nodes(handler: ast.AsyncFunctionDef) -> list[ast.AST]:
    """Every node of the handler body (its decorators, which declare the
    route and the capability guard, excluded)."""
    return [node for statement in handler.body for node in ast.walk(statement)]


_FORBIDDEN_NAMES = {
    "AsyncSession",
    "get_db",
    "async_session_factory",
    "async_sessionmaker",
    "database",
    "engine",
    "select",
    "update",
    "insert",
    "text",
    "func",
    "execute",
    "scalar",
    "scalars",
    "scalar_one",
    "scalar_one_or_none",
    "get",
    "add",
    "flush",
    "commit",
    "rollback",
    "SystemSetting",
    "SettingAuditEvent",
    "SettingAuditLog",
    "log_event",
    "register_post_commit_callback",
    "cvss_impact_preview",
    "cvss_recalculation_admission",
    "admit_cvss_recalculation",
    "publish_task",
    "redis",
    "Redis",
}


@pytest.mark.unit
class TestThinRoute:
    def test_handler_takes_the_principal_the_session_and_the_body(self) -> None:
        signature = inspect.signature(settings_api.update_system_settings)
        assert list(signature.parameters) == ["principal", "db", "body"]

    def test_handler_delegates_to_the_service_and_runs_no_query(self) -> None:
        nodes = _body_nodes(_handler())
        referenced = {node.id for node in nodes if isinstance(node, ast.Name)} | {
            node.attr for node in nodes if isinstance(node, ast.Attribute)
        }

        assert referenced & _FORBIDDEN_NAMES == set()
        calls = {ast.unparse(node.func) for node in nodes if isinstance(node, ast.Call)}
        assert calls == {
            "settings_service.update_default_cvss_version",
            "AppError",
            "SystemSettingsResponse",
            "SystemSettingsData",
        }
        [awaited] = [node.value for node in nodes if isinstance(node, ast.Await)]
        assert isinstance(awaited, ast.Call)
        assert ast.unparse(awaited.func) == (
            "settings_service.update_default_cvss_version"
        )
        assert [ast.unparse(arg) for arg in awaited.args] == ["db"]
        assert {
            keyword.arg: ast.unparse(keyword.value) for keyword in awaited.keywords
        } == {
            "new_version": "body.default_cvss_version",
            "acting_user_id": "principal.user.id",
        }

    def test_only_the_in_progress_exception_is_mapped(self) -> None:
        """`RequiredSystemSettingMissingError` and every other exception
        propagate to the global `500` (system-settings.md, Service
        Exceptions)."""
        handlers = [
            node
            for node in _body_nodes(_handler())
            if isinstance(node, ast.ExceptHandler)
        ]
        assert [ast.unparse(handler.type) for handler in handlers if handler.type] == [
            "settings_service.CVSSRecalculationAlreadyInProgressError"
        ]
        assert all(handler.type is not None for handler in handlers)


# ---------------------------------------------------------------------------
# Missing required setting: the global 500
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestMissingRequiredSetting:
    async def test_production_client_receives_the_global_500(
        self, admin_error_client: AsyncClient, db_session: AsyncSession
    ) -> None:
        response = await admin_error_client.patch(
            _PATH, json={"default_cvss_version": "4.0"}
        )

        assert response.status_code == 500
        assert response.json() == INTERNAL_ERROR
        assert "default_cvss_version" not in response.text
        assert await db_session.get(SystemSetting, _KEY) is None
        assert await _events(db_session) == []


# ---------------------------------------------------------------------------
# Audit visibility through the settings audit log
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestAuditLogVisibility:
    async def test_effective_change_is_listed_with_the_acting_admin(
        self,
        admin_and_client: tuple[User, AsyncClient],
        seed: Seed,
        db_session: AsyncSession,
    ) -> None:
        admin, client = admin_and_client
        await seed("3.1")

        patched = await client.patch(_PATH, json={"default_cvss_version": "4.0"})
        response = await client.get(_AUDIT_LOG)

        assert patched.status_code == 200
        assert response.status_code == 200
        body = response.json()
        assert body["meta"] == {"total": 1, "page": 1, "per_page": 20}
        [item] = body["data"]
        event_id = await db_session.scalar(select(SettingAuditEvent.id))
        assert item["id"] == str(event_id)
        assert {key: value for key, value in item.items() if key != "created_at"} == {
            "id": str(event_id),
            "event_type": "setting_changed",
            "setting_key": _KEY,
            "old_value": "3.1",
            "new_value": "4.0",
            "actor": {
                "id": str(admin.id),
                "username": admin.username,
                "full_name": _ADMIN_FULL_NAME,
                "active": True,
            },
        }
        assert item["created_at"].endswith("Z")


# ---------------------------------------------------------------------------
# Transaction boundary (real commits)
# ---------------------------------------------------------------------------


class _CommittedSettingWorld:
    """Committed administrators with API keys and the committed
    `default_cvss_version` row, on independent sessions. `cleanup()`
    deletes the administrators' setting audit events, keys, roles, and
    users, and restores the setting's original value or removes the row it
    created, even after a failed assertion (testing-strategy.md,
    Concurrency Testing: explicit cleanup of committed rows)."""

    def __init__(self, factory: SessionFactory) -> None:
        self._factory = factory
        self.user_ids: list[uuid.UUID] = []
        self._setting_created = False
        self._setting_original: str | None = None

    async def session(self) -> AsyncSession:
        return await self._factory()

    async def admin(self, prefix: str) -> tuple[User, dict[str, str]]:
        db = await self.session()
        suffix = uuid.uuid4().hex[:10]
        user = User(
            username=f"{prefix}.{suffix}",
            email=f"{prefix}.{suffix}@example.com",
            full_name="Carol Admin",
            password_hash="$2b$12$" + "c" * 53,
        )
        db.add(user)
        await db.flush()
        self.user_ids.append(user.id)
        token, digest = _make_api_key_credential()
        db.add_all(
            [
                UserRole(user_id=user.id, role=Role.ADMIN.value),
                ApiKey(
                    user_id=user.id,
                    key_hash=digest,
                    prefix=token[:12],
                    name="settings-update-key",
                ),
            ]
        )
        await db.commit()
        return user, {"Authorization": f"Bearer {token}"}

    async def seed(self, value: str) -> None:
        db = await self.session()
        current = await _persisted(db)
        if current is None:
            db.add(SystemSetting(key=_KEY, value=value))
            self._setting_created = True
        else:
            self._setting_original = current
            await db.execute(
                update(SystemSetting)
                .where(SystemSetting.key == _KEY)
                .values(value=value)
            )
        await db.commit()

    async def committed(self) -> tuple[str | None, list[tuple[Any, ...]]]:
        """The committed setting value and every setting audit event, read
        through a fresh transaction of a fresh session."""
        db = await self.session()
        try:
            return await _persisted(db), await _events(db)
        finally:
            await db.rollback()

    async def cleanup(self) -> None:
        db = await self.session()
        for statement in (
            delete(SettingAuditEvent).where(
                SettingAuditEvent.user_id.in_(self.user_ids)
            ),
            delete(ApiKey).where(ApiKey.user_id.in_(self.user_ids)),
            delete(UserRole).where(UserRole.user_id.in_(self.user_ids)),
            delete(User).where(User.id.in_(self.user_ids)),
        ):
            await db.execute(statement)
        if self._setting_created:
            await db.execute(delete(SystemSetting).where(SystemSetting.key == _KEY))
        elif self._setting_original is not None:
            await db.execute(
                update(SystemSetting)
                .where(SystemSetting.key == _KEY)
                .values(value=self._setting_original)
            )
        await db.commit()


@pytest_asyncio.fixture
async def committed_world(
    db_session_factory: SessionFactory,
    real_session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> AsyncIterator[tuple[_CommittedSettingWorld, AsyncClient]]:
    """A client whose every request runs the production `get_db` — one
    commit after the handler succeeds, one rollback when an exception
    escapes, post-commit callbacks only after a successful commit — on an
    independent session of the test engine, with the global `500` envelope
    returned instead of re-raised. API keys authenticate the requests, with
    the debounced `last_used_at` touch replaced."""
    world = _CommittedSettingWorld(db_session_factory)
    monkeypatch.setattr(database, "async_session_factory", real_session_factory)
    monkeypatch.delitem(app.dependency_overrides, get_db, raising=False)
    monkeypatch.setattr(dependencies._last_used_debouncer, "touch", AsyncMock())
    force_production_error_page(monkeypatch)
    try:
        async with AsyncClient(
            transport=ASGITransport(app=app, raise_app_exceptions=False),
            base_url="http://test",
        ) as committed_client:
            yield world, committed_client
    finally:
        await world.cleanup()


def _commit_error() -> OperationalError:
    return OperationalError("COMMIT", {}, Exception("simulated commit failure"))


@pytest.mark.e2e
class TestTransactionBoundary:
    @pytest.mark.parametrize(("old", "new"), _CHANGES)
    async def test_commits_exactly_once_and_persists(
        self,
        committed_world: tuple[_CommittedSettingWorld, AsyncClient],
        monkeypatch: pytest.MonkeyPatch,
        old: Version,
        new: Version,
    ) -> None:
        """The flushed change is invisible to another transaction until the
        request's single commit, which makes the row and its event durable
        together."""
        world, committed_client = committed_world
        admin, headers = await world.admin("carol.admin")
        await world.seed(old)
        original = settings_service.update_default_cvss_version
        observed: list[tuple[str | None, list[tuple[Any, ...]]]] = []
        commits: list[str] = []

        async def _observe(db: AsyncSession, **kwargs: Any) -> str:
            result = await original(db, **kwargs)
            observed.append(await world.committed())
            real_commit = db.commit

            async def _counting_commit() -> None:
                commits.append("commit")
                await real_commit()

            monkeypatch.setattr(db, "commit", _counting_commit)
            return result

        monkeypatch.setattr(settings_service, "update_default_cvss_version", _observe)

        response = await committed_client.patch(
            _PATH, json={"default_cvss_version": new}, headers=headers
        )

        assert response.status_code == 200
        assert response.json() == _settings(new)
        # Not visible to another transaction before the commit ...
        assert observed == [(old, [])]
        assert commits == ["commit"]
        # ... and durable after it.
        assert await world.committed() == (new, [_changed(admin.id, old, new)])

    async def test_definitely_failed_commit_returns_500_and_persists_nothing(
        self,
        committed_world: tuple[_CommittedSettingWorld, AsyncClient],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        world, committed_client = committed_world
        _admin, headers = await world.admin("carol.admin")
        await world.seed("3.1")
        original = settings_service.update_default_cvss_version
        reached: list[str] = []

        async def _fail_commit() -> None:
            raise _commit_error()

        async def _arm(db: AsyncSession, **kwargs: Any) -> str:
            result = await original(db, **kwargs)
            reached.append(result)
            monkeypatch.setattr(db, "commit", _fail_commit)
            return result

        monkeypatch.setattr(settings_service, "update_default_cvss_version", _arm)

        response = await committed_client.patch(
            _PATH, json={"default_cvss_version": "4.0"}, headers=headers
        )

        assert response.status_code == 500
        assert response.json() == INTERNAL_ERROR
        # The change was flushed before the failed commit; none survives.
        assert reached == ["4.0"]
        assert await world.committed() == ("3.1", [])

    async def test_ambiguous_commit_is_reconciled_by_re_reading_the_setting(
        self,
        committed_world: tuple[_CommittedSettingWorld, AsyncClient],
        monkeypatch: pytest.MonkeyPatch,
        external_calls: list[str],
    ) -> None:
        """The commit reaches the database and then reports a failure, so
        durability is unknown to the client: the test does not assert the
        prior value. deployment.md: the operator re-reads the setting with
        `GET /api/v1/admin/settings`; no post-commit or publisher effect
        happens on this path."""
        world, committed_client = committed_world
        admin, headers = await world.admin("carol.admin")
        await world.seed("3.1")
        original = settings_service.update_default_cvss_version
        sessions: list[AsyncSession] = []

        async def _arm(db: AsyncSession, **kwargs: Any) -> str:
            result = await original(db, **kwargs)
            sessions.append(db)
            real_commit = db.commit

            async def _commit_then_fail() -> None:
                await real_commit()
                raise _commit_error()

            monkeypatch.setattr(db, "commit", _commit_then_fail)
            return result

        monkeypatch.setattr(settings_service, "update_default_cvss_version", _arm)

        response = await committed_client.patch(
            _PATH, json={"default_cvss_version": "4.0"}, headers=headers
        )

        assert response.status_code == 500
        assert response.json() == INTERNAL_ERROR
        assert external_calls == []
        [request_session] = sessions
        assert _post_commit_callbacks(request_session) == [_ROUTER_DRAIN]

        reread = await committed_client.get(_PATH, headers=headers)

        assert reread.status_code == 200
        value = reread.json()["data"]["default_cvss_version"]
        assert value in {"3.1", "4.0"}
        # Audit history is consistent with whichever state is durable.
        expected = [_changed(admin.id, "3.1", "4.0")] if value == "4.0" else []
        assert await world.committed() == (value, expected)
        assert external_calls == []

    @pytest.mark.parametrize(
        ("persisted", "requested"),
        [
            pytest.param("3.1", "4.0", id="effective"),
            pytest.param("3.1", "3.1", id="no-op"),
        ],
    )
    async def test_committed_request_has_no_post_commit_or_publisher_effect(
        self,
        committed_world: tuple[_CommittedSettingWorld, AsyncClient],
        monkeypatch: pytest.MonkeyPatch,
        external_calls: list[str],
        persisted: Version,
        requested: Version,
    ) -> None:
        """After the real commit, `get_db()` runs the registered callbacks:
        only the router-level drain, which finds no Ticket convergence
        effect, so nothing touches Redis, a lease, or the broker."""
        world, committed_client = committed_world
        admin, headers = await world.admin("carol.admin")
        await world.seed(persisted)
        original = settings_service.update_default_cvss_version
        sessions: list[AsyncSession] = []

        async def _capture(db: AsyncSession, **kwargs: Any) -> str:
            sessions.append(db)
            return await original(db, **kwargs)

        monkeypatch.setattr(settings_service, "update_default_cvss_version", _capture)

        response = await committed_client.patch(
            _PATH, json={"default_cvss_version": requested}, headers=headers
        )

        assert response.status_code == 200
        assert response.json() == _settings(requested)
        assert external_calls == []
        [request_session] = sessions
        assert _post_commit_callbacks(request_session) == [_ROUTER_DRAIN]
        expected = (
            [] if requested == persisted else [_changed(admin.id, persisted, requested)]
        )
        assert await world.committed() == (requested, expected)

    @pytest.mark.usefixtures("held_fence")
    async def test_held_fence_returns_409_and_commits_nothing(
        self,
        committed_world: tuple[_CommittedSettingWorld, AsyncClient],
    ) -> None:
        """The API-level proof that an effective change under an active
        execution fence is `409 CVSS_RECALC_ALREADY_IN_PROGRESS` and that a
        no-op against the still-held fence succeeds; the service's fence
        matrix is proven by
        `tests/test_services/test_settings_mutation_races.py`."""
        world, committed_client = committed_world
        _admin, headers = await world.admin("carol.admin")
        await world.seed("3.1")

        response = await committed_client.patch(
            _PATH, json={"default_cvss_version": "4.0"}, headers=headers
        )

        assert response.status_code == 409
        assert response.json() == _IN_PROGRESS
        assert await world.committed() == ("3.1", [])
        # The rolled-back request released its row lock: a no-op on another
        # request, with the fence still held, completes and commits nothing.
        no_op = await committed_client.patch(
            _PATH, json={"default_cvss_version": "3.1"}, headers=headers
        )
        assert no_op.status_code == 200
        assert no_op.json() == _settings("3.1")
        assert await world.committed() == ("3.1", [])
