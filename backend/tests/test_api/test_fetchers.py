"""End-to-end tests for the Public fetcher observation API
(`backend/app/api/v1/fetchers.py`).

See `docs/features/platform/fetcher-operations.md` (List Fetchers, List
Fetcher Runs, Get Fetcher Run Detail, Get Fetcher Run Timeline Data) for
the authoritative endpoint contracts under test. Filter/query
combination coverage for the underlying query lives in
`tests/test_services/test_fetcher_operations.py` — these tests focus on
the HTTP/route contract (status codes, envelopes, error mapping,
optional-authentication visibility, and OpenAPI route inventory).
"""

from __future__ import annotations

import hashlib
import secrets
from collections.abc import AsyncGenerator, Awaitable, Callable, Generator
from datetime import UTC, datetime, timedelta
from typing import Any, cast
from unittest.mock import AsyncMock, MagicMock
from uuid import UUID, uuid4

import pytest
import pytest_asyncio
from celery import Celery
from celery.schedules import crontab
from fastapi import routing as fastapi_routing
from fastapi.routing import APIRoute
from httpx import ASGITransport, AsyncClient
from pydantic import BaseModel, Field
from redbeat import RedBeatSchedulerEntry
from redis.exceptions import RedisError
from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

import app.api.v1.fetchers as fetchers_module
import app.services.fetcher_schedule as fetcher_schedule_module
from app.api import dependencies
from app.api.dependencies import SESSION_COOKIE_NAME
from app.core.enums import Role, SessionCreationReason
from app.database import async_session_factory, get_db
from app.main import app
from app.models.api_key import ApiKey
from app.models.fetcher_audit_event import FetcherAuditEvent
from app.models.fetcher_config import FetcherConfig
from app.models.fetcher_run import FetcherRun
from app.models.session import Session
from app.models.user import User
from app.models.user_role import UserRole
from app.services.base_fetcher import FETCHER_REGISTRY, BaseFetcher
from app.services.session_service import create_session

FetcherConfigFactory = Callable[..., Awaitable[FetcherConfig]]
FetcherRunFactory = Callable[..., Awaitable[FetcherRun]]
FetcherAuditEventFactory = Callable[..., Awaitable[FetcherAuditEvent]]
UserFactory = Callable[..., Awaitable[User]]
UserRoleFactory = Callable[..., Awaitable[UserRole]]
ApiKeyFactory = Callable[..., Awaitable[ApiKey]]


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_api_key_credential() -> tuple[str, str]:
    """Return `(plaintext_token, sha256_hex_digest)` for a synthetic key.

    Mirrors the identical helper in `tests/test_api/test_settings.py`.
    """
    token = "stl_ak_" + secrets.token_hex(16)
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
    return token, digest


@pytest_asyncio.fixture
async def admin_api_key_client(
    client: AsyncClient,
    user_factory: UserFactory,
    user_role_factory: UserRoleFactory,
    api_key_factory: ApiKeyFactory,
    monkeypatch: pytest.MonkeyPatch,
) -> AsyncClient:
    """The shared `client`, authenticated as an admin via an API key
    (`Authorization: Bearer`) instead of a JWT session cookie."""
    user = await user_factory()
    await user_role_factory(user_id=user.id, role=Role.ADMIN.value)
    token, digest = _make_api_key_credential()
    await api_key_factory(user_id=user.id, key_hash=digest)
    monkeypatch.setattr(dependencies._last_used_debouncer, "touch", AsyncMock())
    client.headers["Authorization"] = f"Bearer {token}"
    return client


@pytest_asyncio.fixture
async def admin_commit_client(
    db_session: AsyncSession,
    user_factory: UserFactory,
    user_role_factory: UserRoleFactory,
) -> AsyncGenerator[AsyncClient]:
    """An admin-authenticated client whose `get_db` override performs a
    real commit and executes post-commit callbacks.

    The shared `client`/`admin_client` fixtures keep one rollback-owned
    test transaction and never call `session.commit()`, so callbacks
    registered via `register_post_commit_callback()` (the PATCH config
    endpoint's post-commit RedBeat propagation) never run under them.
    Mirrors `tests/test_api/test_users.py`'s `admin_commit_client` and
    `tests/test_api/test_auth.py`'s `auth_client`. Redis isolation is
    already composed by this file's autouse `_patch_celery_app` fixture
    (which depends on `celery_test_app`, itself depending on
    `redis_client`) — no separate dependency is needed here.
    """
    admin = await user_factory()
    await user_role_factory(user_id=admin.id, role=Role.ADMIN.value)
    created = await create_session(db_session, admin, SessionCreationReason.LOCAL_LOGIN)

    async def _override_get_db() -> AsyncGenerator[AsyncSession]:
        try:
            yield db_session
            await db_session.commit()
        except Exception:
            await db_session.rollback()
            raise
        else:
            callbacks = db_session.info.pop("post_commit_callbacks", [])
            for callback in callbacks:
                await callback()

    app.dependency_overrides[get_db] = _override_get_db
    try:
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as commit_client:
            commit_client.cookies.set(SESSION_COOKIE_NAME, created.token)
            yield commit_client
    finally:
        app.dependency_overrides.pop(get_db, None)


@pytest.fixture(autouse=True)
def _isolated_registry() -> Generator[None]:
    """Snapshot/restore `FETCHER_REGISTRY` around every test in this
    file — mirrors `tests/test_services/test_fetcher_schedule.py`."""
    original = dict(FETCHER_REGISTRY)
    yield
    FETCHER_REGISTRY.clear()
    FETCHER_REGISTRY.update(original)


class _StubFetcherStub:
    """Minimal `FETCHER_REGISTRY` entry stub — deliberately NOT a
    `BaseFetcher` subclass (see `test_fetcher_schedule.py`, Test
    Independence)."""

    name = "test_api_fetcher"
    description = "Stub fetcher for API tests"
    default_schedule = "0 3 * * *"
    queue: str | None = None
    Settings: type[BaseModel] | None = None


class _StubSettingsModel(BaseModel):
    results_per_page: int = Field(default=100, ge=10, le=1000)


class _StubFetcherWithSettingsStub:
    """Same rationale as `_StubFetcherStub`, with a `Settings` model —
    used to exercise the generated `settings_schema` in `GET .../config`
    responses."""

    name = "test_api_fetcher_with_settings"
    description = "Stub fetcher with custom settings for API tests"
    default_schedule = "0 4 * * *"
    queue: str | None = None
    Settings = _StubSettingsModel


_StubFetcher = cast("type[BaseFetcher]", _StubFetcherStub)
_StubFetcherWithSettings = cast("type[BaseFetcher]", _StubFetcherWithSettingsStub)


def _register(*stubs: type[Any]) -> None:
    """Replace `FETCHER_REGISTRY` with exactly the given stub classes."""
    FETCHER_REGISTRY.clear()
    for stub in stubs:
        FETCHER_REGISTRY[stub.name] = stub


@pytest_asyncio.fixture(autouse=True)
async def _patch_celery_app(
    celery_test_app: Celery, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Point the router's module-level `celery_app` reference at the
    isolated test Celery/Redis instance, so `GET /api/v1/fetchers`
    never touches an uncontrolled production Redis instance during
    tests. Requesting `celery_test_app` also composes its Redis
    isolation automatically for every test in this file."""
    monkeypatch.setattr(fetchers_module, "celery_app", celery_test_app)


# ---------------------------------------------------------------------------
# Route inventory
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestRouteInventory:
    def test_only_the_eight_endpoints_are_registered(self) -> None:
        """No IBS consumer endpoint is introduced by this work item —
        see fetcher-operations.md (Scope). Route discovery uses
        `iter_route_contexts()` — see `tests/test_api_conventions.py`
        for why `app.routes` alone does not expose routes included via
        `include_router()`.
        """
        fetcher_routes = {
            (context.path, method)
            for context in fastapi_routing.iter_route_contexts(app.routes)
            if isinstance(context.original_route, APIRoute)
            and context.path is not None
            and context.path.startswith("/api/v1/fetchers")
            for method in (context.methods or set()) - {"HEAD", "OPTIONS"}
        }
        assert fetcher_routes == {
            ("/api/v1/fetchers", "GET"),
            ("/api/v1/fetchers/{fetcher_name}/runs", "GET"),
            ("/api/v1/fetchers/{fetcher_name}/runs/{run_id}", "GET"),
            ("/api/v1/fetchers/{fetcher_name}/timeline", "GET"),
            ("/api/v1/fetchers/{fetcher_name}/trigger", "POST"),
            ("/api/v1/fetchers/{fetcher_name}/config", "GET"),
            ("/api/v1/fetchers/{fetcher_name}/config", "PATCH"),
            ("/api/v1/fetchers/{fetcher_name}/audit-log", "GET"),
        }


# ---------------------------------------------------------------------------
# GET /api/v1/fetchers
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestListFetchersEndpoint:
    async def test_anonymous_returns_200_with_empty_envelope(
        self, client: AsyncClient
    ) -> None:
        FETCHER_REGISTRY.clear()
        response = await client.get("/api/v1/fetchers")
        assert response.status_code == 200
        assert response.json() == {"data": []}

    async def test_includes_deregistered_fetcher(
        self, client: AsyncClient, fetcher_config_factory: FetcherConfigFactory
    ) -> None:
        FETCHER_REGISTRY.clear()
        config = await fetcher_config_factory()

        response = await client.get("/api/v1/fetchers")

        assert response.status_code == 200
        names = [item["fetcher_name"] for item in response.json()["data"]]
        assert config.fetcher_name in names

    async def test_anonymous_does_not_see_triggered_by_user(
        self,
        client: AsyncClient,
        fetcher_config_factory: FetcherConfigFactory,
        fetcher_run_factory: FetcherRunFactory,
        user_factory: UserFactory,
    ) -> None:
        _register(_StubFetcher)
        config = await fetcher_config_factory(fetcher_name=_StubFetcher.name)
        actor = await user_factory()
        await fetcher_run_factory(
            fetcher_name=config.fetcher_name,
            triggered_by="manual",
            triggered_by_user_id=actor.id,
        )

        response = await client.get("/api/v1/fetchers")

        assert response.status_code == 200
        item = next(
            i for i in response.json()["data"] if i["fetcher_name"] == _StubFetcher.name
        )
        assert item["last_run"]["triggered_by_user"] is None

    async def test_admin_jwt_sees_triggered_by_user(
        self,
        admin_client: AsyncClient,
        fetcher_config_factory: FetcherConfigFactory,
        fetcher_run_factory: FetcherRunFactory,
        user_factory: UserFactory,
    ) -> None:
        _register(_StubFetcher)
        config = await fetcher_config_factory(fetcher_name=_StubFetcher.name)
        actor = await user_factory()
        await fetcher_run_factory(
            fetcher_name=config.fetcher_name,
            triggered_by="manual",
            triggered_by_user_id=actor.id,
        )

        response = await admin_client.get("/api/v1/fetchers")

        assert response.status_code == 200
        item = next(
            i for i in response.json()["data"] if i["fetcher_name"] == _StubFetcher.name
        )
        assert item["last_run"]["triggered_by_user"]["id"] == str(actor.id)

    async def test_admin_api_key_sees_triggered_by_user(
        self,
        admin_api_key_client: AsyncClient,
        fetcher_config_factory: FetcherConfigFactory,
        fetcher_run_factory: FetcherRunFactory,
        user_factory: UserFactory,
    ) -> None:
        _register(_StubFetcher)
        config = await fetcher_config_factory(fetcher_name=_StubFetcher.name)
        actor = await user_factory()
        await fetcher_run_factory(
            fetcher_name=config.fetcher_name,
            triggered_by="manual",
            triggered_by_user_id=actor.id,
        )

        response = await admin_api_key_client.get("/api/v1/fetchers")

        assert response.status_code == 200
        item = next(
            i for i in response.json()["data"] if i["fetcher_name"] == _StubFetcher.name
        )
        assert item["last_run"]["triggered_by_user"]["id"] == str(actor.id)

    async def test_authenticated_without_manage_fetchers_does_not_see_triggered_by_user(
        self,
        authenticated_client: AsyncClient,
        fetcher_config_factory: FetcherConfigFactory,
        fetcher_run_factory: FetcherRunFactory,
        user_factory: UserFactory,
    ) -> None:
        """An authenticated caller with no roles (and therefore no
        `manage_fetchers` capability) is treated identically to
        anonymous — capability, not mere authentication, gates
        visibility. See `_resolve_has_manage_fetchers`
        (`app/api/v1/fetchers.py`)."""
        _register(_StubFetcher)
        config = await fetcher_config_factory(fetcher_name=_StubFetcher.name)
        actor = await user_factory()
        await fetcher_run_factory(
            fetcher_name=config.fetcher_name,
            triggered_by="manual",
            triggered_by_user_id=actor.id,
        )

        response = await authenticated_client.get("/api/v1/fetchers")

        assert response.status_code == 200
        item = next(
            i for i in response.json()["data"] if i["fetcher_name"] == _StubFetcher.name
        )
        assert item["last_run"]["triggered_by_user"] is None

    async def test_invalid_selected_credential_returns_401(
        self, client: AsyncClient
    ) -> None:
        """A selected but rejected credential is never silently ignored
        — see `docs/api-spec.md` (Optional Authentication on Public
        Endpoints)."""
        response = await client.get(
            "/api/v1/fetchers", headers={"Authorization": "Bearer not-a-real-token"}
        )

        assert response.status_code == 401
        assert response.json()["code"] == "AUTH_NOT_AUTHENTICATED"

    async def test_queued_last_run_has_null_started_at_and_created_at_present(
        self,
        client: AsyncClient,
        fetcher_config_factory: FetcherConfigFactory,
        fetcher_run_factory: FetcherRunFactory,
    ) -> None:
        """A `queued` manual run is represented with `created_at`
        present and `started_at`/`finished_at`/`duration_seconds` all
        `null` — see `docs/features/platform/fetcher-operations.md`
        (List Fetchers, Fields)."""
        _register(_StubFetcher)
        config = await fetcher_config_factory(fetcher_name=_StubFetcher.name)
        await fetcher_run_factory(
            fetcher_name=config.fetcher_name,
            status="queued",
            started_at=None,
            triggered_by="manual",
        )

        response = await client.get("/api/v1/fetchers")

        assert response.status_code == 200
        item = next(
            i for i in response.json()["data"] if i["fetcher_name"] == _StubFetcher.name
        )
        assert item["last_run"]["status"] == "queued"
        assert item["last_run"]["started_at"] is None
        assert item["last_run"]["finished_at"] is None
        assert item["last_run"]["duration_seconds"] is None
        assert item["last_run"]["created_at"] is not None
        # Active run: all four counters expose the persisted zero defaults.
        assert item["last_run"]["items_succeeded"] == 0
        assert item["last_run"]["items_created"] == 0
        assert item["last_run"]["items_updated"] == 0
        assert item["last_run"]["items_failed"] == 0

    async def test_terminal_last_run_exposes_items_succeeded(
        self,
        client: AsyncClient,
        fetcher_config_factory: FetcherConfigFactory,
        fetcher_run_factory: FetcherRunFactory,
    ) -> None:
        """A terminal `last_run` exposes `items_succeeded`, which need
        not equal created plus updated (docs/features/platform/
        fetcher-operations.md, List Fetchers, Fields)."""
        _register(_StubFetcher)
        config = await fetcher_config_factory(fetcher_name=_StubFetcher.name)
        await fetcher_run_factory(
            fetcher_name=config.fetcher_name,
            status="success",
            finished_at=datetime.now(UTC),
            duration_seconds=10.0,
            items_succeeded=8,
            items_created=3,
            items_updated=0,
            items_failed=0,
        )

        response = await client.get("/api/v1/fetchers")

        assert response.status_code == 200
        item = next(
            i for i in response.json()["data"] if i["fetcher_name"] == _StubFetcher.name
        )
        assert item["last_run"]["items_succeeded"] == 8
        assert item["last_run"]["items_created"] == 3
        assert item["last_run"]["items_updated"] == 0
        assert item["last_run"]["items_failed"] == 0


# ---------------------------------------------------------------------------
# GET /api/v1/fetchers/{fetcher_name}/runs
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestListFetcherRunsEndpoint:
    async def test_unknown_fetcher_returns_404(self, client: AsyncClient) -> None:
        response = await client.get("/api/v1/fetchers/no-such-fetcher/runs")
        assert response.status_code == 404
        assert response.json()["code"] == "FETCHER_NOT_FOUND"

    async def test_returns_paginated_envelope(
        self,
        client: AsyncClient,
        fetcher_config_factory: FetcherConfigFactory,
        fetcher_run_factory: FetcherRunFactory,
    ) -> None:
        config = await fetcher_config_factory()
        await fetcher_run_factory(fetcher_name=config.fetcher_name)

        response = await client.get(f"/api/v1/fetchers/{config.fetcher_name}/runs")

        assert response.status_code == 200
        body = response.json()
        assert "data" in body
        assert "meta" in body
        assert body["meta"] == {"total": 1, "page": 1, "per_page": 20}
        assert body["data"][0]["items_succeeded"] == 0
        assert body["data"][0]["items_created"] == 0
        assert body["data"][0]["items_updated"] == 0
        assert body["data"][0]["items_failed"] == 0

    async def test_items_succeeded_need_not_equal_created_plus_updated(
        self,
        client: AsyncClient,
        fetcher_config_factory: FetcherConfigFactory,
        fetcher_run_factory: FetcherRunFactory,
    ) -> None:
        """`items_succeeded` is a terminal-outcome count, independent of
        the durable-effect `items_created`/`items_updated` counts
        (docs/features/platform/fetcher-operations.md, List Fetcher
        Runs, Notes)."""
        config = await fetcher_config_factory()
        await fetcher_run_factory(
            fetcher_name=config.fetcher_name,
            status="success",
            finished_at=datetime.now(UTC),
            duration_seconds=12.0,
            items_succeeded=5,
            items_created=1,
            items_updated=1,
            items_failed=0,
        )

        response = await client.get(f"/api/v1/fetchers/{config.fetcher_name}/runs")

        assert response.status_code == 200
        item = response.json()["data"][0]
        assert item["items_succeeded"] == 5
        assert item["items_created"] == 1
        assert item["items_updated"] == 1
        assert item["items_failed"] == 0

    async def test_raw_diagnostics_never_present_in_list_items(
        self,
        admin_client: AsyncClient,
        fetcher_config_factory: FetcherConfigFactory,
        fetcher_run_factory: FetcherRunFactory,
    ) -> None:
        config = await fetcher_config_factory()
        await fetcher_run_factory(
            fetcher_name=config.fetcher_name,
            status="failure",
            error_detail="raw detail",
            error_traceback="raw traceback",
        )

        response = await admin_client.get(
            f"/api/v1/fetchers/{config.fetcher_name}/runs"
        )

        assert response.status_code == 200
        item = response.json()["data"][0]
        assert "error_detail" not in item
        assert "error_traceback" not in item

    async def test_invalid_page_returns_422(
        self, client: AsyncClient, fetcher_config_factory: FetcherConfigFactory
    ) -> None:
        config = await fetcher_config_factory()
        response = await client.get(
            f"/api/v1/fetchers/{config.fetcher_name}/runs", params={"page": 0}
        )
        assert response.status_code == 422

    async def test_invalid_per_page_returns_422(
        self, client: AsyncClient, fetcher_config_factory: FetcherConfigFactory
    ) -> None:
        config = await fetcher_config_factory()
        response = await client.get(
            f"/api/v1/fetchers/{config.fetcher_name}/runs", params={"per_page": 101}
        )
        assert response.status_code == 422

    async def test_malformed_date_returns_422(
        self, client: AsyncClient, fetcher_config_factory: FetcherConfigFactory
    ) -> None:
        config = await fetcher_config_factory()
        response = await client.get(
            f"/api/v1/fetchers/{config.fetcher_name}/runs",
            params={"from_date": "not-a-date"},
        )
        assert response.status_code == 422

    async def test_inverted_range_returns_400(
        self, client: AsyncClient, fetcher_config_factory: FetcherConfigFactory
    ) -> None:
        config = await fetcher_config_factory()
        response = await client.get(
            f"/api/v1/fetchers/{config.fetcher_name}/runs",
            params={"from_date": "2025-06-01", "to_date": "2025-01-01"},
        )
        assert response.status_code == 400
        assert response.json()["code"] == "DATE_RANGE_INVERTED"

    async def test_invalid_status_returns_empty_page_not_error(
        self,
        client: AsyncClient,
        fetcher_config_factory: FetcherConfigFactory,
        fetcher_run_factory: FetcherRunFactory,
    ) -> None:
        config = await fetcher_config_factory()
        await fetcher_run_factory(fetcher_name=config.fetcher_name, status="success")

        response = await client.get(
            f"/api/v1/fetchers/{config.fetcher_name}/runs",
            params={"status": "not-a-real-status"},
        )

        assert response.status_code == 200
        assert response.json()["data"] == []
        assert response.json()["meta"]["total"] == 0

    async def test_filters_by_queued_status(
        self,
        client: AsyncClient,
        fetcher_config_factory: FetcherConfigFactory,
        fetcher_run_factory: FetcherRunFactory,
    ) -> None:
        config = await fetcher_config_factory()
        await fetcher_run_factory(fetcher_name=config.fetcher_name, status="success")
        queued = await fetcher_run_factory(
            fetcher_name=config.fetcher_name, status="queued", started_at=None
        )

        response = await client.get(
            f"/api/v1/fetchers/{config.fetcher_name}/runs",
            params={"status": "queued"},
        )

        assert response.status_code == 200
        body = response.json()
        assert body["meta"]["total"] == 1
        assert body["data"][0]["id"] == str(queued.id)
        assert body["data"][0]["started_at"] is None


# ---------------------------------------------------------------------------
# GET /api/v1/fetchers/{fetcher_name}/runs/{run_id}
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestGetFetcherRunEndpoint:
    async def test_unknown_fetcher_returns_404(self, client: AsyncClient) -> None:
        response = await client.get(f"/api/v1/fetchers/no-such-fetcher/runs/{uuid4()}")
        assert response.status_code == 404
        assert response.json()["code"] == "FETCHER_NOT_FOUND"

    async def test_unknown_run_returns_404(
        self, client: AsyncClient, fetcher_config_factory: FetcherConfigFactory
    ) -> None:
        config = await fetcher_config_factory()
        response = await client.get(
            f"/api/v1/fetchers/{config.fetcher_name}/runs/{uuid4()}"
        )
        assert response.status_code == 404
        assert response.json()["code"] == "FETCHER_NOT_FOUND"

    async def test_run_of_different_fetcher_returns_404(
        self,
        client: AsyncClient,
        fetcher_config_factory: FetcherConfigFactory,
        fetcher_run_factory: FetcherRunFactory,
    ) -> None:
        config_a = await fetcher_config_factory()
        config_b = await fetcher_config_factory()
        run = await fetcher_run_factory(fetcher_name=config_a.fetcher_name)

        response = await client.get(
            f"/api/v1/fetchers/{config_b.fetcher_name}/runs/{run.id}"
        )

        assert response.status_code == 404
        assert response.json()["code"] == "FETCHER_NOT_FOUND"

    async def test_queued_run_has_null_started_at_and_present_created_at(
        self,
        client: AsyncClient,
        fetcher_config_factory: FetcherConfigFactory,
        fetcher_run_factory: FetcherRunFactory,
    ) -> None:
        config = await fetcher_config_factory()
        run = await fetcher_run_factory(
            fetcher_name=config.fetcher_name,
            status="queued",
            started_at=None,
            triggered_by="manual",
        )

        response = await client.get(
            f"/api/v1/fetchers/{config.fetcher_name}/runs/{run.id}"
        )

        assert response.status_code == 200
        data = response.json()["data"]
        assert data["status"] == "queued"
        assert data["started_at"] is None
        assert data["finished_at"] is None
        assert data["duration_seconds"] is None
        assert data["created_at"] is not None

    async def test_anonymous_does_not_see_raw_diagnostics(
        self,
        client: AsyncClient,
        fetcher_config_factory: FetcherConfigFactory,
        fetcher_run_factory: FetcherRunFactory,
    ) -> None:
        config = await fetcher_config_factory()
        run = await fetcher_run_factory(
            fetcher_name=config.fetcher_name,
            status="failure",
            error_message="sanitized",
            error_detail="raw detail",
            error_traceback="raw traceback",
        )

        response = await client.get(
            f"/api/v1/fetchers/{config.fetcher_name}/runs/{run.id}"
        )

        assert response.status_code == 200
        data = response.json()["data"]
        assert data["error_message"] == "sanitized"
        assert "error_detail" not in data
        assert "error_traceback" not in data

    async def test_admin_jwt_sees_raw_diagnostics(
        self,
        admin_client: AsyncClient,
        fetcher_config_factory: FetcherConfigFactory,
        fetcher_run_factory: FetcherRunFactory,
    ) -> None:
        config = await fetcher_config_factory()
        run = await fetcher_run_factory(
            fetcher_name=config.fetcher_name,
            status="failure",
            error_detail="raw detail",
            error_traceback="raw traceback",
        )

        response = await admin_client.get(
            f"/api/v1/fetchers/{config.fetcher_name}/runs/{run.id}"
        )

        assert response.status_code == 200
        data = response.json()["data"]
        assert data["error_detail"] == "raw detail"
        assert data["error_traceback"] == "raw traceback"

    async def test_admin_api_key_sees_raw_diagnostics(
        self,
        admin_api_key_client: AsyncClient,
        fetcher_config_factory: FetcherConfigFactory,
        fetcher_run_factory: FetcherRunFactory,
    ) -> None:
        config = await fetcher_config_factory()
        run = await fetcher_run_factory(
            fetcher_name=config.fetcher_name,
            status="failure",
            error_detail="raw detail",
            error_traceback="raw traceback",
        )

        response = await admin_api_key_client.get(
            f"/api/v1/fetchers/{config.fetcher_name}/runs/{run.id}"
        )

        assert response.status_code == 200
        data = response.json()["data"]
        assert data["error_detail"] == "raw detail"
        assert data["error_traceback"] == "raw traceback"

    async def test_authenticated_without_manage_fetchers_does_not_see_raw_diagnostics(
        self,
        authenticated_client: AsyncClient,
        fetcher_config_factory: FetcherConfigFactory,
        fetcher_run_factory: FetcherRunFactory,
    ) -> None:
        """An authenticated caller with no roles (and therefore no
        `manage_fetchers` capability) is treated identically to
        anonymous — capability, not mere authentication, gates
        visibility. See `_resolve_has_manage_fetchers`
        (`app/api/v1/fetchers.py`)."""
        config = await fetcher_config_factory()
        run = await fetcher_run_factory(
            fetcher_name=config.fetcher_name,
            status="failure",
            error_message="sanitized",
            error_detail="raw detail",
            error_traceback="raw traceback",
        )

        response = await authenticated_client.get(
            f"/api/v1/fetchers/{config.fetcher_name}/runs/{run.id}"
        )

        assert response.status_code == 200
        data = response.json()["data"]
        assert data["error_message"] == "sanitized"
        assert "error_detail" not in data
        assert "error_traceback" not in data

    async def test_running_run_has_null_finished_at_and_duration(
        self,
        client: AsyncClient,
        fetcher_config_factory: FetcherConfigFactory,
        fetcher_run_factory: FetcherRunFactory,
    ) -> None:
        config = await fetcher_config_factory()
        run = await fetcher_run_factory(
            fetcher_name=config.fetcher_name,
            status="running",
            finished_at=None,
            duration_seconds=None,
        )

        response = await client.get(
            f"/api/v1/fetchers/{config.fetcher_name}/runs/{run.id}"
        )

        assert response.status_code == 200
        data = response.json()["data"]
        assert data["finished_at"] is None
        assert data["duration_seconds"] is None
        # Running run: all four counters expose the persisted zero defaults.
        assert data["items_succeeded"] == 0
        assert data["items_created"] == 0
        assert data["items_updated"] == 0
        assert data["items_failed"] == 0

    async def test_run_detail_exposes_items_succeeded(
        self,
        client: AsyncClient,
        fetcher_config_factory: FetcherConfigFactory,
        fetcher_run_factory: FetcherRunFactory,
    ) -> None:
        config = await fetcher_config_factory()
        run = await fetcher_run_factory(
            fetcher_name=config.fetcher_name,
            status="partial",
            finished_at=datetime.now(UTC),
            duration_seconds=30.0,
            items_succeeded=6,
            items_created=2,
            items_updated=3,
            items_failed=1,
        )

        response = await client.get(
            f"/api/v1/fetchers/{config.fetcher_name}/runs/{run.id}"
        )

        assert response.status_code == 200
        data = response.json()["data"]
        assert data["items_succeeded"] == 6
        assert data["items_created"] == 2
        assert data["items_updated"] == 3
        assert data["items_failed"] == 1


# ---------------------------------------------------------------------------
# GET /api/v1/fetchers/{fetcher_name}/timeline
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestGetFetcherTimelineEndpoint:
    async def test_unknown_fetcher_returns_404(self, client: AsyncClient) -> None:
        response = await client.get("/api/v1/fetchers/no-such-fetcher/timeline")
        assert response.status_code == 404
        assert response.json()["code"] == "FETCHER_NOT_FOUND"

    async def test_default_range_returns_envelope(
        self, client: AsyncClient, fetcher_config_factory: FetcherConfigFactory
    ) -> None:
        config = await fetcher_config_factory()
        response = await client.get(f"/api/v1/fetchers/{config.fetcher_name}/timeline")

        assert response.status_code == 200
        data = response.json()["data"]
        assert "points" in data
        assert "disabled_periods" in data

    async def test_queued_point_has_null_started_at_semantics(
        self,
        client: AsyncClient,
        fetcher_config_factory: FetcherConfigFactory,
        fetcher_run_factory: FetcherRunFactory,
    ) -> None:
        """A `queued` run appears in the timeline using `created_at` as
        its `timestamp`, with `duration_seconds = null` — see
        `docs/features/platform/fetcher-operations.md`
        (Get Fetcher Run Timeline Data)."""
        config = await fetcher_config_factory()
        await fetcher_run_factory(
            fetcher_name=config.fetcher_name, status="queued", started_at=None
        )

        response = await client.get(f"/api/v1/fetchers/{config.fetcher_name}/timeline")

        assert response.status_code == 200
        points = response.json()["data"]["points"]
        assert len(points) == 1
        assert points[0]["status"] == "queued"
        assert points[0]["duration_seconds"] is None
        assert points[0]["timestamp"] is not None
        # Queued point: all four counters expose the persisted zero defaults.
        assert points[0]["items_succeeded"] == 0
        assert points[0]["items_created"] == 0
        assert points[0]["items_updated"] == 0
        assert points[0]["items_failed"] == 0

    async def test_timeline_point_exposes_items_succeeded(
        self,
        client: AsyncClient,
        fetcher_config_factory: FetcherConfigFactory,
        fetcher_run_factory: FetcherRunFactory,
    ) -> None:
        """Every timeline point carries `items_succeeded`, which need not
        equal created plus updated (docs/features/platform/
        fetcher-operations.md, Get Fetcher Run Timeline Data)."""
        config = await fetcher_config_factory()
        await fetcher_run_factory(
            fetcher_name=config.fetcher_name,
            status="success",
            finished_at=datetime.now(UTC),
            duration_seconds=45.0,
            items_succeeded=9,
            items_created=4,
            items_updated=0,
            items_failed=0,
        )

        response = await client.get(f"/api/v1/fetchers/{config.fetcher_name}/timeline")

        assert response.status_code == 200
        points = response.json()["data"]["points"]
        assert len(points) == 1
        assert points[0]["items_succeeded"] == 9
        assert points[0]["items_created"] == 4
        assert points[0]["items_updated"] == 0
        assert points[0]["items_failed"] == 0

    async def test_date_range_too_wide_returns_400(
        self, client: AsyncClient, fetcher_config_factory: FetcherConfigFactory
    ) -> None:
        config = await fetcher_config_factory()
        response = await client.get(
            f"/api/v1/fetchers/{config.fetcher_name}/timeline",
            params={"from_date": "2000-01-01", "to_date": "2010-01-01"},
        )

        assert response.status_code == 400
        assert response.json()["code"] == "DATE_RANGE_TOO_WIDE"

    async def test_exactly_1825_days_is_accepted(
        self, client: AsyncClient, fetcher_config_factory: FetcherConfigFactory
    ) -> None:
        """Uses full ISO datetimes (not bare dates) so neither bound is
        widened to a day boundary (`docs/api-spec.md`, Date Range
        Interpretation) — the actual interval is exactly 1825 days,
        the documented maximum, and must be accepted."""
        config = await fetcher_config_factory()
        from_date = datetime(2020, 1, 1, tzinfo=UTC)
        to_date = from_date + timedelta(days=1825)

        response = await client.get(
            f"/api/v1/fetchers/{config.fetcher_name}/timeline",
            params={
                "from_date": from_date.isoformat(),
                "to_date": to_date.isoformat(),
            },
        )

        assert response.status_code == 200

    async def test_disabled_period_actor_hidden_without_manage_fetchers(
        self,
        client: AsyncClient,
        fetcher_config_factory: FetcherConfigFactory,
        fetcher_audit_event_factory: FetcherAuditEventFactory,
        user_factory: UserFactory,
    ) -> None:
        config = await fetcher_config_factory()
        actor = await user_factory()
        now = datetime.now(UTC)
        await fetcher_audit_event_factory(
            fetcher_name=config.fetcher_name,
            event_type="disabled",
            created_at=now - timedelta(days=1),
            user_id=actor.id,
        )

        response = await client.get(
            f"/api/v1/fetchers/{config.fetcher_name}/timeline",
            params={
                "from_date": (now - timedelta(days=5)).date().isoformat(),
                "to_date": now.date().isoformat(),
            },
        )

        assert response.status_code == 200
        period = response.json()["data"]["disabled_periods"][0]
        assert period["disabled_by"] is None

    async def test_disabled_period_actor_visible_with_manage_fetchers(
        self,
        admin_client: AsyncClient,
        fetcher_config_factory: FetcherConfigFactory,
        fetcher_audit_event_factory: FetcherAuditEventFactory,
        user_factory: UserFactory,
    ) -> None:
        config = await fetcher_config_factory()
        actor = await user_factory()
        now = datetime.now(UTC)
        await fetcher_audit_event_factory(
            fetcher_name=config.fetcher_name,
            event_type="disabled",
            created_at=now - timedelta(days=1),
            user_id=actor.id,
        )

        response = await admin_client.get(
            f"/api/v1/fetchers/{config.fetcher_name}/timeline",
            params={
                "from_date": (now - timedelta(days=5)).date().isoformat(),
                "to_date": now.date().isoformat(),
            },
        )

        assert response.status_code == 200
        period = response.json()["data"]["disabled_periods"][0]
        assert period["disabled_by"]["id"] == str(actor.id)


# ---------------------------------------------------------------------------
# POST /api/v1/fetchers/{fetcher_name}/trigger
#
# `trigger_fetcher()` manages its own sessions and commits real
# transactions (see its docstring in `app/services/fetcher_operations.py`)
# — it never participates in the request-scoped `DatabaseSession`
# transaction the `client`/`admin_client` fixtures override with the
# rollback-only `db_session`. Because `trigger_fetcher()` commits
# `FetcherRun` rows with a `triggered_by_user_id` foreign key through its
# own, separately connected session, the authenticating admin's `User`
# row must ALSO be committed for real (not merely visible inside
# `db_session`'s uncommitted savepoint) — otherwise the FK constraint
# fails from `trigger_fetcher`'s perspective. `admin_trigger_client`/
# `admin_api_key_trigger_client` below therefore create their own admin
# identity directly through `real_session_factory` and override both
# `get_db` and `get_fetcher_trigger_session_factory` to the same test
# engine, rather than reusing `admin_client`/`admin_api_key_client`.
# Fetcher-specific rows (`FetcherConfig`/`FetcherRun`/`FetcherAuditEvent`)
# are armed/cleaned up per test via `_arrange_trigger_fetcher`/
# `_cleanup_trigger_fetcher_rows`.
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def admin_trigger_client(
    real_session_factory: async_sessionmaker[AsyncSession],
) -> AsyncGenerator[AsyncClient]:
    """An `AsyncClient` authenticated as an admin whose `User`,
    `UserRole`, and `Session` rows are committed for real through
    `real_session_factory` — required because `trigger_fetcher()`
    commits `FetcherRun` rows referencing `triggered_by_user_id` via its
    own, separately connected session (see module note above); a user
    visible only inside the savepoint-scoped `db_session` (as
    `user_factory`/`admin_client` create it) would violate that foreign
    key from `trigger_fetcher`'s perspective. Also overrides `get_db` (so
    the request's own auth lookup uses the same real engine, not the
    savepoint-scoped one) and `get_fetcher_trigger_session_factory`.
    Cleans up the admin identity rows on teardown; fetcher-specific rows
    remain the caller's responsibility (see
    `_cleanup_trigger_fetcher_rows`)."""
    async with real_session_factory() as session:
        admin = User(
            username=f"triggerapiadmin{uuid4().hex[:8]}",
            email=f"triggerapiadmin{uuid4().hex[:8]}@example.com",
            password_hash="$2b$12$" + "a" * 53,
        )
        session.add(admin)
        await session.flush()
        session.add(UserRole(user_id=admin.id, role=Role.ADMIN.value))
        created = await create_session(
            session, admin, SessionCreationReason.LOCAL_LOGIN
        )
        await session.commit()
        admin_id = admin.id
        token = created.token

    async def _override_get_db() -> AsyncGenerator[AsyncSession]:
        async with real_session_factory() as session:
            yield session

    app.dependency_overrides[get_db] = _override_get_db
    app.dependency_overrides[fetchers_module.get_fetcher_trigger_session_factory] = (
        lambda: real_session_factory
    )
    try:
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as trigger_client:
            trigger_client.cookies.set(SESSION_COOKIE_NAME, token)
            yield trigger_client
    finally:
        app.dependency_overrides.pop(get_db, None)
        app.dependency_overrides.pop(
            fetchers_module.get_fetcher_trigger_session_factory, None
        )
        async with real_session_factory() as session:
            await session.execute(delete(UserRole).where(UserRole.user_id == admin_id))
            await session.execute(delete(Session).where(Session.user_id == admin_id))
            await session.execute(delete(User).where(User.id == admin_id))
            await session.commit()


@pytest_asyncio.fixture
async def admin_api_key_trigger_client(
    real_session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> AsyncGenerator[AsyncClient]:
    """Same as `admin_trigger_client`, authenticated via a real,
    committed API key instead of a JWT session cookie."""
    token, digest = _make_api_key_credential()
    async with real_session_factory() as session:
        admin = User(
            username=f"triggerapikeyadmin{uuid4().hex[:8]}",
            email=f"triggerapikeyadmin{uuid4().hex[:8]}@example.com",
            password_hash="$2b$12$" + "a" * 53,
        )
        session.add(admin)
        await session.flush()
        session.add(UserRole(user_id=admin.id, role=Role.ADMIN.value))
        session.add(
            ApiKey(
                user_id=admin.id,
                name="trigger-test-key",
                key_hash=digest,
                prefix=token[:12],
            )
        )
        await session.commit()
        admin_id = admin.id

    monkeypatch.setattr(dependencies._last_used_debouncer, "touch", AsyncMock())

    async def _override_get_db() -> AsyncGenerator[AsyncSession]:
        async with real_session_factory() as session:
            yield session

    app.dependency_overrides[get_db] = _override_get_db
    app.dependency_overrides[fetchers_module.get_fetcher_trigger_session_factory] = (
        lambda: real_session_factory
    )
    try:
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as trigger_client:
            trigger_client.headers["Authorization"] = f"Bearer {token}"
            yield trigger_client
    finally:
        app.dependency_overrides.pop(get_db, None)
        app.dependency_overrides.pop(
            fetchers_module.get_fetcher_trigger_session_factory, None
        )
        async with real_session_factory() as session:
            await session.execute(delete(ApiKey).where(ApiKey.user_id == admin_id))
            await session.execute(delete(UserRole).where(UserRole.user_id == admin_id))
            await session.execute(delete(User).where(User.id == admin_id))
            await session.commit()


async def _arrange_trigger_fetcher(
    real_session_factory: async_sessionmaker[AsyncSession],
    *,
    enabled: bool = True,
    queue: str | None = None,
) -> str:
    """Register a per-test stub fetcher and commit its `FetcherConfig`
    row through `real_session_factory` — see module note above for why
    `fetcher_config_factory` cannot be used here. Returns the generated
    `fetcher_name`."""
    fetcher_name = f"api_trigger_{uuid4().hex[:8]}"
    stub = cast(
        "type[Any]",
        type(
            "_ApiTriggerStub",
            (),
            {
                "name": fetcher_name,
                "description": "Stub fetcher for trigger endpoint tests",
                "default_schedule": "0 3 * * *",
                "queue": queue,
                "Settings": None,
            },
        ),
    )
    FETCHER_REGISTRY[fetcher_name] = stub
    async with real_session_factory() as session:
        session.add(
            FetcherConfig(fetcher_name=fetcher_name, enabled=enabled, run_timeout=3600)
        )
        await session.commit()
    return fetcher_name


async def _cleanup_trigger_fetcher_rows(
    real_session_factory: async_sessionmaker[AsyncSession], fetcher_name: str
) -> None:
    async with real_session_factory() as session:
        await session.execute(
            delete(FetcherAuditEvent).where(
                FetcherAuditEvent.fetcher_name == fetcher_name
            )
        )
        await session.execute(
            delete(FetcherRun).where(FetcherRun.fetcher_name == fetcher_name)
        )
        await session.execute(
            delete(FetcherConfig).where(FetcherConfig.fetcher_name == fetcher_name)
        )
        await session.commit()


@pytest.mark.unit
class TestGetFetcherTriggerSessionFactory:
    def test_returns_the_shared_application_session_factory(self) -> None:
        """Every trigger endpoint test overrides this dependency (via
        `admin_trigger_client`/`admin_api_key_trigger_client`) to point
        at the test database instead of whatever `DATABASE_URL` the
        environment running the suite happens to have configured — so
        the default, un-overridden implementation is exercised directly
        here instead, mirroring `TestGetReadinessSessionFactory`
        (`tests/test_health.py`)."""
        assert (
            fetchers_module.get_fetcher_trigger_session_factory()
            is async_session_factory
        )


@pytest.mark.e2e
class TestTriggerFetcherEndpoint:
    async def test_unauthenticated_returns_401(
        self, client: AsyncClient, fetcher_config_factory: FetcherConfigFactory
    ) -> None:
        config = await fetcher_config_factory()
        response = await client.post(f"/api/v1/fetchers/{config.fetcher_name}/trigger")
        assert response.status_code == 401
        assert response.json()["code"] == "AUTH_NOT_AUTHENTICATED"

    async def test_ordinary_user_returns_403(
        self,
        authenticated_client: AsyncClient,
        fetcher_config_factory: FetcherConfigFactory,
    ) -> None:
        config = await fetcher_config_factory()
        response = await authenticated_client.post(
            f"/api/v1/fetchers/{config.fetcher_name}/trigger"
        )
        assert response.status_code == 403
        assert response.json()["code"] == "AUTH_INSUFFICIENT_PERMISSION"

    async def test_unknown_fetcher_returns_404(
        self, admin_trigger_client: AsyncClient
    ) -> None:
        response = await admin_trigger_client.post(
            "/api/v1/fetchers/no-such-fetcher/trigger"
        )
        assert response.status_code == 404
        assert response.json()["code"] == "FETCHER_NOT_FOUND"

    async def test_deregistered_fetcher_returns_409(
        self,
        admin_trigger_client: AsyncClient,
        real_session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        fetcher_name = f"api_trigger_dereg_{uuid4().hex[:8]}"
        async with real_session_factory() as session:
            session.add(FetcherConfig(fetcher_name=fetcher_name, enabled=True))
            await session.commit()
        try:
            response = await admin_trigger_client.post(
                f"/api/v1/fetchers/{fetcher_name}/trigger"
            )
            assert response.status_code == 409
            assert response.json()["code"] == "FETCHER_DEREGISTERED"
        finally:
            await _cleanup_trigger_fetcher_rows(real_session_factory, fetcher_name)

    async def test_disabled_fetcher_returns_409(
        self,
        admin_trigger_client: AsyncClient,
        real_session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        fetcher_name = await _arrange_trigger_fetcher(
            real_session_factory, enabled=False
        )
        try:
            response = await admin_trigger_client.post(
                f"/api/v1/fetchers/{fetcher_name}/trigger"
            )
            assert response.status_code == 409
            assert response.json()["code"] == "FETCHER_DISABLED"
        finally:
            await _cleanup_trigger_fetcher_rows(real_session_factory, fetcher_name)

    async def test_active_run_returns_409(
        self,
        admin_trigger_client: AsyncClient,
        real_session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        fetcher_name = await _arrange_trigger_fetcher(real_session_factory)
        async with real_session_factory() as session:
            session.add(
                FetcherRun(
                    fetcher_name=fetcher_name, status="queued", triggered_by="manual"
                )
            )
            await session.commit()
        try:
            response = await admin_trigger_client.post(
                f"/api/v1/fetchers/{fetcher_name}/trigger"
            )
            assert response.status_code == 409
            assert response.json()["code"] == "FETCHER_ALREADY_RUNNING"
        finally:
            await _cleanup_trigger_fetcher_rows(real_session_factory, fetcher_name)

    async def test_admin_jwt_returns_202_with_queued_run(
        self,
        admin_trigger_client: AsyncClient,
        real_session_factory: async_sessionmaker[AsyncSession],
        monkeypatch: pytest.MonkeyPatch,
        celery_test_app: Celery,
    ) -> None:
        fetcher_name = await _arrange_trigger_fetcher(real_session_factory)
        monkeypatch.setattr(celery_test_app, "send_task", MagicMock())
        try:
            response = await admin_trigger_client.post(
                f"/api/v1/fetchers/{fetcher_name}/trigger"
            )

            assert response.status_code == 202
            data = response.json()["data"]
            assert set(data.keys()) == {"run_id", "message"}
            assert data["message"] == (
                f"Fetcher '{fetcher_name}' has been queued for execution"
            )
            async with real_session_factory() as session:
                run = await session.get(FetcherRun, UUID(data["run_id"]))
                assert run is not None
                assert run.status == "queued"
                assert run.triggered_by == "manual"
        finally:
            await _cleanup_trigger_fetcher_rows(real_session_factory, fetcher_name)

    async def test_admin_api_key_returns_202(
        self,
        admin_api_key_trigger_client: AsyncClient,
        real_session_factory: async_sessionmaker[AsyncSession],
        monkeypatch: pytest.MonkeyPatch,
        celery_test_app: Celery,
    ) -> None:
        fetcher_name = await _arrange_trigger_fetcher(real_session_factory)
        monkeypatch.setattr(celery_test_app, "send_task", MagicMock())
        try:
            response = await admin_api_key_trigger_client.post(
                f"/api/v1/fetchers/{fetcher_name}/trigger"
            )
            assert response.status_code == 202
        finally:
            await _cleanup_trigger_fetcher_rows(real_session_factory, fetcher_name)

    async def test_broker_unavailable_returns_503_sanitized(
        self,
        admin_trigger_client: AsyncClient,
        real_session_factory: async_sessionmaker[AsyncSession],
        monkeypatch: pytest.MonkeyPatch,
        celery_test_app: Celery,
    ) -> None:
        fetcher_name = await _arrange_trigger_fetcher(real_session_factory)

        def _raise(*_args: Any, **_kwargs: Any) -> None:
            raise ConnectionError(
                "redis://user:supersecret@203.0.113.5:6379 unreachable"
            )

        monkeypatch.setattr(celery_test_app, "send_task", _raise)
        try:
            response = await admin_trigger_client.post(
                f"/api/v1/fetchers/{fetcher_name}/trigger"
            )
            assert response.status_code == 503
            assert response.json()["code"] == "CELERY_UNAVAILABLE"
            assert "supersecret" not in response.text
            assert "203.0.113.5" not in response.text
        finally:
            await _cleanup_trigger_fetcher_rows(real_session_factory, fetcher_name)


# ---------------------------------------------------------------------------
# Out-of-scope endpoints
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestOutOfScopeEndpoints:
    """No IBS consumer endpoint is introduced by this work item — see
    `docs/features/platform/fetcher-operations.md` (Scope). Verified
    here in addition to `TestRouteInventory` since a client request to
    an unregistered path is the actually-observable contract at the
    HTTP layer."""

    async def test_ibs_consumer_status_endpoint_not_found(
        self, client: AsyncClient
    ) -> None:
        response = await client.get("/api/v1/ibs-consumer/status")
        assert response.status_code == 404


# ---------------------------------------------------------------------------
# GET /api/v1/fetchers/{fetcher_name}/config
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestGetFetcherConfigEndpoint:
    async def test_unauthenticated_returns_401(
        self, client: AsyncClient, fetcher_config_factory: FetcherConfigFactory
    ) -> None:
        config = await fetcher_config_factory()
        response = await client.get(f"/api/v1/fetchers/{config.fetcher_name}/config")
        assert response.status_code == 401
        assert response.json()["code"] == "AUTH_NOT_AUTHENTICATED"

    async def test_ordinary_user_returns_403(
        self,
        authenticated_client: AsyncClient,
        fetcher_config_factory: FetcherConfigFactory,
    ) -> None:
        config = await fetcher_config_factory()
        response = await authenticated_client.get(
            f"/api/v1/fetchers/{config.fetcher_name}/config"
        )
        assert response.status_code == 403
        assert response.json()["code"] == "AUTH_INSUFFICIENT_PERMISSION"

    async def test_admin_jwt_returns_the_config(
        self, admin_client: AsyncClient, fetcher_config_factory: FetcherConfigFactory
    ) -> None:
        config = await fetcher_config_factory()
        response = await admin_client.get(
            f"/api/v1/fetchers/{config.fetcher_name}/config"
        )
        assert response.status_code == 200

    async def test_admin_api_key_returns_the_config(
        self,
        admin_api_key_client: AsyncClient,
        fetcher_config_factory: FetcherConfigFactory,
    ) -> None:
        config = await fetcher_config_factory()
        response = await admin_api_key_client.get(
            f"/api/v1/fetchers/{config.fetcher_name}/config"
        )
        assert response.status_code == 200

    async def test_registered_fetcher_exact_item_shape_with_schema(
        self,
        admin_client: AsyncClient,
        fetcher_config_factory: FetcherConfigFactory,
    ) -> None:
        _register(_StubFetcherWithSettings)
        config = await fetcher_config_factory(
            fetcher_name=_StubFetcherWithSettings.name,
            custom_settings={"results_per_page": 250},
        )

        response = await admin_client.get(
            f"/api/v1/fetchers/{config.fetcher_name}/config"
        )

        assert response.status_code == 200
        data = response.json()["data"]
        assert set(data.keys()) == {
            "fetcher_name",
            "enabled",
            "schedule_override",
            "default_schedule",
            "effective_schedule",
            "run_timeout",
            "request_delay",
            "custom_settings",
            "settings_schema",
            "updated_at",
        }
        assert data["fetcher_name"] == config.fetcher_name
        assert data["default_schedule"] == _StubFetcherWithSettings.default_schedule
        assert data["custom_settings"] == {"results_per_page": 250}
        assert data["settings_schema"] == _StubSettingsModel.model_json_schema()

    async def test_registered_fetcher_without_settings_model_schema_is_null(
        self,
        admin_client: AsyncClient,
        fetcher_config_factory: FetcherConfigFactory,
    ) -> None:
        _register(_StubFetcher)
        config = await fetcher_config_factory(fetcher_name=_StubFetcher.name)

        response = await admin_client.get(
            f"/api/v1/fetchers/{config.fetcher_name}/config"
        )

        assert response.json()["data"]["settings_schema"] is None

    async def test_deregistered_fetcher_returns_raw_snapshot(
        self,
        admin_client: AsyncClient,
        fetcher_config_factory: FetcherConfigFactory,
    ) -> None:
        FETCHER_REGISTRY.clear()
        config = await fetcher_config_factory(
            schedule_override="0 5 * * *",
            custom_settings={"orphaned_key": "raw_value"},
        )

        response = await admin_client.get(
            f"/api/v1/fetchers/{config.fetcher_name}/config"
        )

        assert response.status_code == 200
        data = response.json()["data"]
        assert data["default_schedule"] is None
        assert data["settings_schema"] is None
        assert data["effective_schedule"] == "0 5 * * *"
        assert data["custom_settings"] == {"orphaned_key": "raw_value"}

    async def test_unknown_fetcher_returns_404(self, admin_client: AsyncClient) -> None:
        FETCHER_REGISTRY.clear()
        response = await admin_client.get("/api/v1/fetchers/no-such-fetcher/config")
        assert response.status_code == 404
        assert response.json()["code"] == "FETCHER_NOT_FOUND"


# ---------------------------------------------------------------------------
# PATCH /api/v1/fetchers/{fetcher_name}/config
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestUpdateFetcherConfigEndpoint:
    async def test_unauthenticated_returns_401(
        self, client: AsyncClient, fetcher_config_factory: FetcherConfigFactory
    ) -> None:
        config = await fetcher_config_factory()
        response = await client.patch(
            f"/api/v1/fetchers/{config.fetcher_name}/config", json={"enabled": False}
        )
        assert response.status_code == 401
        assert response.json()["code"] == "AUTH_NOT_AUTHENTICATED"

    async def test_ordinary_user_returns_403(
        self,
        authenticated_client: AsyncClient,
        fetcher_config_factory: FetcherConfigFactory,
    ) -> None:
        config = await fetcher_config_factory()
        response = await authenticated_client.patch(
            f"/api/v1/fetchers/{config.fetcher_name}/config", json={"enabled": False}
        )
        assert response.status_code == 403
        assert response.json()["code"] == "AUTH_INSUFFICIENT_PERMISSION"

    async def test_empty_body_returns_422(
        self, admin_client: AsyncClient, fetcher_config_factory: FetcherConfigFactory
    ) -> None:
        _register(_StubFetcher)
        config = await fetcher_config_factory(fetcher_name=_StubFetcher.name)
        response = await admin_client.patch(
            f"/api/v1/fetchers/{config.fetcher_name}/config", json={}
        )
        assert response.status_code == 422
        assert response.json()["code"] == "VALIDATION_ERROR"

    async def test_unknown_fetcher_returns_404(self, admin_client: AsyncClient) -> None:
        FETCHER_REGISTRY.clear()
        response = await admin_client.patch(
            "/api/v1/fetchers/no-such-fetcher/config", json={"enabled": False}
        )
        assert response.status_code == 404
        assert response.json()["code"] == "FETCHER_NOT_FOUND"

    async def test_deregistered_fetcher_returns_409(
        self,
        admin_client: AsyncClient,
        fetcher_config_factory: FetcherConfigFactory,
    ) -> None:
        FETCHER_REGISTRY.clear()
        config = await fetcher_config_factory()
        response = await admin_client.patch(
            f"/api/v1/fetchers/{config.fetcher_name}/config", json={"enabled": False}
        )
        assert response.status_code == 409
        assert response.json()["code"] == "FETCHER_DEREGISTERED"

    async def test_run_timeout_change_while_active_run_returns_409(
        self,
        admin_client: AsyncClient,
        fetcher_config_factory: FetcherConfigFactory,
        fetcher_run_factory: FetcherRunFactory,
    ) -> None:
        _register(_StubFetcher)
        config = await fetcher_config_factory(
            fetcher_name=_StubFetcher.name, run_timeout=3600
        )
        await fetcher_run_factory(
            fetcher_name=config.fetcher_name,
            status="running",
            started_at=datetime.now(UTC),
        )
        response = await admin_client.patch(
            f"/api/v1/fetchers/{config.fetcher_name}/config",
            json={"run_timeout": 1800},
        )
        assert response.status_code == 409
        assert response.json()["code"] == "FETCHER_ALREADY_RUNNING"

    async def test_run_timeout_change_while_active_queued_run_returns_409(
        self,
        admin_client: AsyncClient,
        fetcher_config_factory: FetcherConfigFactory,
        fetcher_run_factory: FetcherRunFactory,
    ) -> None:
        """The Run Timeout Active Guard covers `queued` runs too, not
        only `running` ones — see
        `docs/features/platform/fetcher-operations.md`
        (`update_fetcher_config`, Run Timeout Active Guard)."""
        _register(_StubFetcher)
        config = await fetcher_config_factory(
            fetcher_name=_StubFetcher.name, run_timeout=3600
        )
        await fetcher_run_factory(
            fetcher_name=config.fetcher_name,
            status="queued",
            started_at=None,
        )
        response = await admin_client.patch(
            f"/api/v1/fetchers/{config.fetcher_name}/config",
            json={"run_timeout": 1800},
        )
        assert response.status_code == 409
        assert response.json()["code"] == "FETCHER_ALREADY_RUNNING"

    async def test_unknown_custom_setting_returns_422(
        self,
        admin_client: AsyncClient,
        fetcher_config_factory: FetcherConfigFactory,
    ) -> None:
        _register(_StubFetcherWithSettings)
        config = await fetcher_config_factory(
            fetcher_name=_StubFetcherWithSettings.name
        )
        response = await admin_client.patch(
            f"/api/v1/fetchers/{config.fetcher_name}/config",
            json={"custom_settings": {"nonexistent": 1}},
        )
        assert response.status_code == 422
        assert response.json()["code"] == "FETCHER_SETTING_UNKNOWN"

    async def test_invalid_custom_setting_value_returns_422(
        self,
        admin_client: AsyncClient,
        fetcher_config_factory: FetcherConfigFactory,
    ) -> None:
        _register(_StubFetcherWithSettings)
        config = await fetcher_config_factory(
            fetcher_name=_StubFetcherWithSettings.name
        )
        response = await admin_client.patch(
            f"/api/v1/fetchers/{config.fetcher_name}/config",
            json={"custom_settings": {"results_per_page": 5000}},
        )
        assert response.status_code == 422
        assert response.json()["code"] == "FETCHER_SETTING_INVALID"

    async def test_invalid_cron_returns_422(
        self,
        admin_client: AsyncClient,
        fetcher_config_factory: FetcherConfigFactory,
    ) -> None:
        _register(_StubFetcher)
        config = await fetcher_config_factory(fetcher_name=_StubFetcher.name)
        response = await admin_client.patch(
            f"/api/v1/fetchers/{config.fetcher_name}/config",
            json={"schedule_override": "not-a-cron"},
        )
        assert response.status_code == 422
        assert response.json()["code"] == "VALIDATION_ERROR"

    async def test_run_timeout_out_of_bounds_returns_422(
        self,
        admin_client: AsyncClient,
        fetcher_config_factory: FetcherConfigFactory,
    ) -> None:
        _register(_StubFetcher)
        config = await fetcher_config_factory(fetcher_name=_StubFetcher.name)
        response = await admin_client.patch(
            f"/api/v1/fetchers/{config.fetcher_name}/config",
            json={"run_timeout": 30},
        )
        assert response.status_code == 422
        assert response.json()["code"] == "VALIDATION_ERROR"

    async def test_request_delay_out_of_bounds_returns_422(
        self,
        admin_client: AsyncClient,
        fetcher_config_factory: FetcherConfigFactory,
    ) -> None:
        _register(_StubFetcher)
        config = await fetcher_config_factory(fetcher_name=_StubFetcher.name)
        response = await admin_client.patch(
            f"/api/v1/fetchers/{config.fetcher_name}/config",
            json={"request_delay": 301.0},
        )
        assert response.status_code == 422
        assert response.json()["code"] == "VALIDATION_ERROR"

    async def test_schedule_override_too_long_returns_422(
        self,
        admin_client: AsyncClient,
        fetcher_config_factory: FetcherConfigFactory,
    ) -> None:
        """A syntactically valid cron expression longer than 50
        characters — the `FetcherConfig.schedule_override` storage
        bound — is rejected at the schema layer, never reaching a
        database flush (`fetcher-operations.md`, Update Fetcher
        Config, Validation rules)."""
        _register(_StubFetcher)
        config = await fetcher_config_factory(fetcher_name=_StubFetcher.name)
        long_valid_cron = "0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20 * * * *"
        assert len(long_valid_cron) > 50
        response = await admin_client.patch(
            f"/api/v1/fetchers/{config.fetcher_name}/config",
            json={"schedule_override": long_valid_cron},
        )
        assert response.status_code == 422
        assert response.json()["code"] == "VALIDATION_ERROR"

    async def test_enabled_null_returns_422(
        self,
        admin_client: AsyncClient,
        fetcher_config_factory: FetcherConfigFactory,
    ) -> None:
        _register(_StubFetcher)
        config = await fetcher_config_factory(fetcher_name=_StubFetcher.name)
        response = await admin_client.patch(
            f"/api/v1/fetchers/{config.fetcher_name}/config",
            json={"enabled": None},
        )
        assert response.status_code == 422
        assert response.json()["code"] == "VALIDATION_ERROR"

    async def test_run_timeout_null_returns_422(
        self,
        admin_client: AsyncClient,
        fetcher_config_factory: FetcherConfigFactory,
    ) -> None:
        _register(_StubFetcher)
        config = await fetcher_config_factory(fetcher_name=_StubFetcher.name)
        response = await admin_client.patch(
            f"/api/v1/fetchers/{config.fetcher_name}/config",
            json={"run_timeout": None},
        )
        assert response.status_code == 422
        assert response.json()["code"] == "VALIDATION_ERROR"

    async def test_request_delay_null_returns_422(
        self,
        admin_client: AsyncClient,
        fetcher_config_factory: FetcherConfigFactory,
    ) -> None:
        _register(_StubFetcher)
        config = await fetcher_config_factory(fetcher_name=_StubFetcher.name)
        response = await admin_client.patch(
            f"/api/v1/fetchers/{config.fetcher_name}/config",
            json={"request_delay": None},
        )
        assert response.status_code == 422
        assert response.json()["code"] == "VALIDATION_ERROR"

    async def test_custom_settings_null_returns_422(
        self,
        admin_client: AsyncClient,
        fetcher_config_factory: FetcherConfigFactory,
    ) -> None:
        _register(_StubFetcherWithSettings)
        config = await fetcher_config_factory(
            fetcher_name=_StubFetcherWithSettings.name
        )
        response = await admin_client.patch(
            f"/api/v1/fetchers/{config.fetcher_name}/config",
            json={"custom_settings": None},
        )
        assert response.status_code == 422
        assert response.json()["code"] == "VALIDATION_ERROR"

    async def test_admin_jwt_updates_config_and_returns_updated_shape(
        self,
        admin_client: AsyncClient,
        fetcher_config_factory: FetcherConfigFactory,
    ) -> None:
        _register(_StubFetcher)
        config = await fetcher_config_factory(
            fetcher_name=_StubFetcher.name, enabled=True
        )
        response = await admin_client.patch(
            f"/api/v1/fetchers/{config.fetcher_name}/config",
            json={"enabled": False, "request_delay": 3.5},
        )
        assert response.status_code == 200
        data = response.json()["data"]
        assert data["enabled"] is False
        assert data["request_delay"] == 3.5

        # The change is durable — a subsequent GET observes it.
        follow_up = await admin_client.get(
            f"/api/v1/fetchers/{config.fetcher_name}/config"
        )
        assert follow_up.json()["data"]["enabled"] is False

    async def test_admin_api_key_updates_config(
        self,
        admin_api_key_client: AsyncClient,
        fetcher_config_factory: FetcherConfigFactory,
    ) -> None:
        _register(_StubFetcher)
        config = await fetcher_config_factory(
            fetcher_name=_StubFetcher.name, enabled=True
        )
        response = await admin_api_key_client.patch(
            f"/api/v1/fetchers/{config.fetcher_name}/config",
            json={"enabled": False},
        )
        assert response.status_code == 200
        assert response.json()["data"]["enabled"] is False

    async def test_custom_setting_coercion_persists_canonical_value(
        self,
        admin_client: AsyncClient,
        fetcher_config_factory: FetcherConfigFactory,
    ) -> None:
        _register(_StubFetcherWithSettings)
        config = await fetcher_config_factory(
            fetcher_name=_StubFetcherWithSettings.name
        )
        response = await admin_client.patch(
            f"/api/v1/fetchers/{config.fetcher_name}/config",
            json={"custom_settings": {"results_per_page": "500"}},
        )
        assert response.status_code == 200
        assert response.json()["data"]["custom_settings"] == {"results_per_page": 500}

    async def test_schedule_override_explicit_null_reverts_to_default(
        self,
        admin_client: AsyncClient,
        fetcher_config_factory: FetcherConfigFactory,
    ) -> None:
        """An explicit `null` for `schedule_override` is a meaningful
        value distinct from omission — it reverts the fetcher to its
        code-defined `default_schedule` (`fetcher-operations.md`,
        Update Fetcher Config, Validation rules)."""
        _register(_StubFetcher)
        config = await fetcher_config_factory(
            fetcher_name=_StubFetcher.name, schedule_override="0 5 * * *"
        )
        response = await admin_client.patch(
            f"/api/v1/fetchers/{config.fetcher_name}/config",
            json={"schedule_override": None},
        )
        assert response.status_code == 200
        data = response.json()["data"]
        assert data["schedule_override"] is None
        assert data["effective_schedule"] == _StubFetcher.default_schedule

        follow_up = await admin_client.get(
            f"/api/v1/fetchers/{config.fetcher_name}/config"
        )
        assert follow_up.json()["data"]["schedule_override"] is None

    async def test_custom_setting_explicit_null_resets_to_schema_default(
        self,
        admin_client: AsyncClient,
        fetcher_config_factory: FetcherConfigFactory,
    ) -> None:
        """An explicit `null` for a `custom_settings` key removes the
        stored override, reverting `get_setting()` to the `Settings`
        field's schema default (`fetcher-operations.md`, Update Fetcher
        Config, Validation rules)."""
        _register(_StubFetcherWithSettings)
        config = await fetcher_config_factory(
            fetcher_name=_StubFetcherWithSettings.name,
            custom_settings={"results_per_page": 250},
        )
        response = await admin_client.patch(
            f"/api/v1/fetchers/{config.fetcher_name}/config",
            json={"custom_settings": {"results_per_page": None}},
        )
        assert response.status_code == 200
        assert response.json()["data"]["custom_settings"] == {}

        follow_up = await admin_client.get(
            f"/api/v1/fetchers/{config.fetcher_name}/config"
        )
        assert follow_up.json()["data"]["custom_settings"] == {}

    async def test_no_op_payload_returns_200_unchanged(
        self,
        admin_client: AsyncClient,
        fetcher_config_factory: FetcherConfigFactory,
    ) -> None:
        _register(_StubFetcher)
        config = await fetcher_config_factory(
            fetcher_name=_StubFetcher.name, enabled=True, request_delay=1.5
        )
        before = await admin_client.get(
            f"/api/v1/fetchers/{config.fetcher_name}/config"
        )
        updated_at_before = before.json()["data"]["updated_at"]

        response = await admin_client.patch(
            f"/api/v1/fetchers/{config.fetcher_name}/config",
            json={"enabled": True, "request_delay": 1.5},
        )

        assert response.status_code == 200
        assert response.json()["data"]["updated_at"] == updated_at_before

    async def test_enabling_creates_redbeat_entry(
        self,
        admin_commit_client: AsyncClient,
        fetcher_config_factory: FetcherConfigFactory,
        celery_test_app: Celery,
    ) -> None:
        """Real Redis integration: enabling a fetcher creates its
        canonical redbeat entry post-commit — see
        `docs/features/platform/fetcher-infrastructure.md` (Runtime
        Propagation). Uses `admin_commit_client` — the shared
        `admin_client` never commits, so the post-commit callback that
        performs this write never runs under it."""
        _register(_StubFetcher)
        config = await fetcher_config_factory(
            fetcher_name=_StubFetcher.name, enabled=False
        )

        response = await admin_commit_client.patch(
            f"/api/v1/fetchers/{config.fetcher_name}/config",
            json={"enabled": True},
        )

        assert response.status_code == 200
        key = RedBeatSchedulerEntry.generate_key(celery_test_app, config.fetcher_name)
        entry = RedBeatSchedulerEntry.from_key(key, app=celery_test_app)
        assert entry.task == "run_fetcher"

    async def test_disabling_removes_redbeat_entry(
        self,
        admin_commit_client: AsyncClient,
        fetcher_config_factory: FetcherConfigFactory,
        celery_test_app: Celery,
    ) -> None:
        _register(_StubFetcher)
        config = await fetcher_config_factory(
            fetcher_name=_StubFetcher.name, enabled=True
        )
        entry = RedBeatSchedulerEntry(
            name=config.fetcher_name,
            task="run_fetcher",
            schedule=crontab.from_string(_StubFetcher.default_schedule),
            args=[],
            kwargs={"fetcher_name": config.fetcher_name, "triggered_by": "schedule"},
            app=celery_test_app,
        )
        entry.save()

        response = await admin_commit_client.patch(
            f"/api/v1/fetchers/{config.fetcher_name}/config",
            json={"enabled": False},
        )

        assert response.status_code == 200
        key = RedBeatSchedulerEntry.generate_key(celery_test_app, config.fetcher_name)
        with pytest.raises(KeyError):
            RedBeatSchedulerEntry.from_key(key, app=celery_test_app)

    async def test_request_delay_only_change_does_not_touch_redbeat(
        self,
        admin_commit_client: AsyncClient,
        fetcher_config_factory: FetcherConfigFactory,
        celery_test_app: Celery,
    ) -> None:
        """`request_delay` never propagates — no entry is created even
        though the fetcher is enabled and has none yet."""
        _register(_StubFetcher)
        config = await fetcher_config_factory(
            fetcher_name=_StubFetcher.name, enabled=True, request_delay=0
        )

        response = await admin_commit_client.patch(
            f"/api/v1/fetchers/{config.fetcher_name}/config",
            json={"request_delay": 4.0},
        )

        assert response.status_code == 200
        key = RedBeatSchedulerEntry.generate_key(celery_test_app, config.fetcher_name)
        with pytest.raises(KeyError):
            RedBeatSchedulerEntry.from_key(key, app=celery_test_app)

    async def test_redis_failure_during_propagation_still_returns_200(
        self,
        admin_commit_client: AsyncClient,
        fetcher_config_factory: FetcherConfigFactory,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """A Redis failure during post-commit propagation is logged at
        WARNING and does not affect the already-committed PostgreSQL
        change or the response — see
        `docs/features/platform/fetcher-operations.md` (RedBeat
        Post-Commit Propagation)."""
        _register(_StubFetcher)
        config = await fetcher_config_factory(
            fetcher_name=_StubFetcher.name, enabled=False
        )

        def _raise_redis_error(*_args: Any, **_kwargs: Any) -> None:
            raise RedisError("simulated Redis outage")

        monkeypatch.setattr(
            fetcher_schedule_module, "propagate_config_update", _raise_redis_error
        )

        with caplog.at_level("WARNING", logger="app.api.v1.fetchers"):
            response = await admin_commit_client.patch(
                f"/api/v1/fetchers/{config.fetcher_name}/config",
                json={"enabled": True},
            )

        assert response.status_code == 200
        assert response.json()["data"]["enabled"] is True
        assert "fetcher_config_redbeat_propagation_failed" in caplog.text

        follow_up = await admin_commit_client.get(
            f"/api/v1/fetchers/{config.fetcher_name}/config"
        )
        assert follow_up.json()["data"]["enabled"] is True


class TestListFetcherAuditEventsEndpoint:
    async def test_unauthenticated_returns_401(
        self, client: AsyncClient, fetcher_config_factory: FetcherConfigFactory
    ) -> None:
        config = await fetcher_config_factory()
        response = await client.get(f"/api/v1/fetchers/{config.fetcher_name}/audit-log")
        assert response.status_code == 401
        assert response.json()["code"] == "AUTH_NOT_AUTHENTICATED"

    async def test_ordinary_user_returns_403(
        self,
        authenticated_client: AsyncClient,
        fetcher_config_factory: FetcherConfigFactory,
    ) -> None:
        config = await fetcher_config_factory()
        response = await authenticated_client.get(
            f"/api/v1/fetchers/{config.fetcher_name}/audit-log"
        )
        assert response.status_code == 403
        assert response.json()["code"] == "AUTH_INSUFFICIENT_PERMISSION"

    async def test_admin_jwt_can_list(
        self, admin_client: AsyncClient, fetcher_config_factory: FetcherConfigFactory
    ) -> None:
        config = await fetcher_config_factory()
        response = await admin_client.get(
            f"/api/v1/fetchers/{config.fetcher_name}/audit-log"
        )
        assert response.status_code == 200

    async def test_admin_api_key_can_list(
        self,
        admin_api_key_client: AsyncClient,
        fetcher_config_factory: FetcherConfigFactory,
    ) -> None:
        config = await fetcher_config_factory()
        response = await admin_api_key_client.get(
            f"/api/v1/fetchers/{config.fetcher_name}/audit-log"
        )
        assert response.status_code == 200

    async def test_empty_result_has_correct_envelope(
        self, admin_client: AsyncClient, fetcher_config_factory: FetcherConfigFactory
    ) -> None:
        config = await fetcher_config_factory()
        response = await admin_client.get(
            f"/api/v1/fetchers/{config.fetcher_name}/audit-log"
        )

        assert response.json() == {
            "data": [],
            "meta": {"total": 0, "page": 1, "per_page": 20},
        }

    async def test_exact_item_shape(
        self,
        admin_client: AsyncClient,
        fetcher_config_factory: FetcherConfigFactory,
        fetcher_audit_event_factory: FetcherAuditEventFactory,
    ) -> None:
        config = await fetcher_config_factory()
        await fetcher_audit_event_factory(fetcher_name=config.fetcher_name)

        response = await admin_client.get(
            f"/api/v1/fetchers/{config.fetcher_name}/audit-log"
        )

        item = response.json()["data"][0]
        assert set(item.keys()) == {
            "id",
            "fetcher_name",
            "event_type",
            "actor",
            "old_value",
            "new_value",
            "detail",
            "created_at",
        }
        assert item["fetcher_name"] == config.fetcher_name
        assert set(item["actor"].keys()) == {"id", "username", "full_name", "active"}

    async def test_populated_old_new_value_and_detail_round_trip(
        self,
        admin_client: AsyncClient,
        fetcher_config_factory: FetcherConfigFactory,
        fetcher_audit_event_factory: FetcherAuditEventFactory,
    ) -> None:
        """Regression: `old_value`/`new_value`/`detail` must survive the
        ORM -> service -> schema -> JSON round trip unchanged. All prior
        fixtures relied on factory defaults (all `None`), which would
        not catch a field-swap or serialization bug."""
        config = await fetcher_config_factory()
        await fetcher_audit_event_factory(
            fetcher_name=config.fetcher_name,
            event_type="config_changed",
            old_value="0 */6 * * *",
            new_value="0 */4 * * *",
            detail={"field": "schedule_override"},
        )

        response = await admin_client.get(
            f"/api/v1/fetchers/{config.fetcher_name}/audit-log"
        )

        item = response.json()["data"][0]
        assert item["event_type"] == "config_changed"
        assert item["old_value"] == "0 */6 * * *"
        assert item["new_value"] == "0 */4 * * *"
        assert item["detail"] == {"field": "schedule_override"}

    async def test_unknown_fetcher_returns_404(self, admin_client: AsyncClient) -> None:
        FETCHER_REGISTRY.clear()
        response = await admin_client.get("/api/v1/fetchers/no-such-fetcher/audit-log")
        assert response.status_code == 404
        assert response.json()["code"] == "FETCHER_NOT_FOUND"

    async def test_all_invalid_event_types_still_checks_fetcher_existence(
        self, admin_client: AsyncClient
    ) -> None:
        """Regression for the fix in this work item: an entirely
        invalid `event_type` filter must not mask a nonexistent
        fetcher behind an empty `200` — the existence check always
        runs first."""
        FETCHER_REGISTRY.clear()
        response = await admin_client.get(
            "/api/v1/fetchers/no-such-fetcher/audit-log",
            params=[("event_type", "not-a-real-type")],
        )
        assert response.status_code == 404
        assert response.json()["code"] == "FETCHER_NOT_FOUND"

    async def test_event_type_filter(
        self,
        admin_client: AsyncClient,
        fetcher_config_factory: FetcherConfigFactory,
        fetcher_audit_event_factory: FetcherAuditEventFactory,
    ) -> None:
        config = await fetcher_config_factory()
        await fetcher_audit_event_factory(
            fetcher_name=config.fetcher_name, event_type="disabled"
        )

        response = await admin_client.get(
            f"/api/v1/fetchers/{config.fetcher_name}/audit-log",
            params=[("event_type", "disabled")],
        )

        assert response.json()["meta"]["total"] == 1

    async def test_all_invalid_event_types_return_empty_result(
        self,
        admin_client: AsyncClient,
        fetcher_config_factory: FetcherConfigFactory,
        fetcher_audit_event_factory: FetcherAuditEventFactory,
    ) -> None:
        config = await fetcher_config_factory()
        await fetcher_audit_event_factory(fetcher_name=config.fetcher_name)

        response = await admin_client.get(
            f"/api/v1/fetchers/{config.fetcher_name}/audit-log",
            params=[("event_type", "not-a-real-type")],
        )

        assert response.status_code == 200
        assert response.json()["meta"]["total"] == 0

    async def test_actor_filter_by_uuid(
        self,
        admin_client: AsyncClient,
        fetcher_config_factory: FetcherConfigFactory,
        fetcher_audit_event_factory: FetcherAuditEventFactory,
        user_factory: UserFactory,
    ) -> None:
        config = await fetcher_config_factory()
        actor = await user_factory()
        await fetcher_audit_event_factory(
            fetcher_name=config.fetcher_name, user_id=actor.id
        )

        response = await admin_client.get(
            f"/api/v1/fetchers/{config.fetcher_name}/audit-log",
            params={"actor": str(actor.id)},
        )

        assert response.json()["meta"]["total"] == 1

    async def test_unknown_actor_returns_empty_result_not_404(
        self, admin_client: AsyncClient, fetcher_config_factory: FetcherConfigFactory
    ) -> None:
        config = await fetcher_config_factory()
        response = await admin_client.get(
            f"/api/v1/fetchers/{config.fetcher_name}/audit-log",
            params={"actor": "no-such-actor"},
        )
        assert response.status_code == 200
        assert response.json()["meta"]["total"] == 0

    async def test_system_actor_returns_empty_result(
        self,
        admin_client: AsyncClient,
        fetcher_config_factory: FetcherConfigFactory,
        fetcher_audit_event_factory: FetcherAuditEventFactory,
    ) -> None:
        """Every fetcher audit event has a human actor — `system` never
        matches (`fetcher-operations.md`, Get Fetcher Audit Log)."""
        config = await fetcher_config_factory()
        await fetcher_audit_event_factory(fetcher_name=config.fetcher_name)

        response = await admin_client.get(
            f"/api/v1/fetchers/{config.fetcher_name}/audit-log",
            params={"actor": "system"},
        )

        assert response.status_code == 200
        assert response.json()["meta"]["total"] == 0

    async def test_inclusive_date_range(
        self,
        admin_client: AsyncClient,
        fetcher_config_factory: FetcherConfigFactory,
        fetcher_audit_event_factory: FetcherAuditEventFactory,
    ) -> None:
        config = await fetcher_config_factory()
        await fetcher_audit_event_factory(
            fetcher_name=config.fetcher_name,
            created_at=datetime(2026, 5, 13, tzinfo=UTC),
        )

        response = await admin_client.get(
            f"/api/v1/fetchers/{config.fetcher_name}/audit-log",
            params={"from_date": "2026-05-01", "to_date": "2026-05-31"},
        )

        assert response.json()["meta"]["total"] == 1

    async def test_malformed_date_returns_422(
        self, admin_client: AsyncClient, fetcher_config_factory: FetcherConfigFactory
    ) -> None:
        config = await fetcher_config_factory()
        response = await admin_client.get(
            f"/api/v1/fetchers/{config.fetcher_name}/audit-log",
            params={"from_date": "not-a-date"},
        )
        assert response.status_code == 422

    async def test_inverted_date_range_returns_400(
        self, admin_client: AsyncClient, fetcher_config_factory: FetcherConfigFactory
    ) -> None:
        config = await fetcher_config_factory()
        response = await admin_client.get(
            f"/api/v1/fetchers/{config.fetcher_name}/audit-log",
            params={"from_date": "2026-05-16", "to_date": "2026-05-15"},
        )
        assert response.status_code == 400
        assert response.json()["code"] == "DATE_RANGE_INVERTED"

    async def test_page_below_one_returns_422(
        self, admin_client: AsyncClient, fetcher_config_factory: FetcherConfigFactory
    ) -> None:
        config = await fetcher_config_factory()
        response = await admin_client.get(
            f"/api/v1/fetchers/{config.fetcher_name}/audit-log", params={"page": 0}
        )
        assert response.status_code == 422

    async def test_per_page_out_of_range_returns_422(
        self, admin_client: AsyncClient, fetcher_config_factory: FetcherConfigFactory
    ) -> None:
        config = await fetcher_config_factory()
        response = await admin_client.get(
            f"/api/v1/fetchers/{config.fetcher_name}/audit-log",
            params={"per_page": 101},
        )
        assert response.status_code == 422

    async def test_page_beyond_last_page_returns_empty_with_correct_total(
        self,
        admin_client: AsyncClient,
        fetcher_config_factory: FetcherConfigFactory,
        fetcher_audit_event_factory: FetcherAuditEventFactory,
    ) -> None:
        config = await fetcher_config_factory()
        await fetcher_audit_event_factory(fetcher_name=config.fetcher_name)

        response = await admin_client.get(
            f"/api/v1/fetchers/{config.fetcher_name}/audit-log", params={"page": 2}
        )

        assert response.status_code == 200
        assert response.json()["data"] == []
        assert response.json()["meta"]["total"] == 1

    async def test_fixed_newest_first_ordering(
        self,
        admin_client: AsyncClient,
        fetcher_config_factory: FetcherConfigFactory,
        fetcher_audit_event_factory: FetcherAuditEventFactory,
    ) -> None:
        config = await fetcher_config_factory()
        older = await fetcher_audit_event_factory(
            fetcher_name=config.fetcher_name,
            created_at=datetime(2026, 5, 1, tzinfo=UTC),
        )
        newer = await fetcher_audit_event_factory(
            fetcher_name=config.fetcher_name,
            created_at=datetime(2026, 5, 2, tzinfo=UTC),
        )

        response = await admin_client.get(
            f"/api/v1/fetchers/{config.fetcher_name}/audit-log"
        )

        ids = [item["id"] for item in response.json()["data"]]
        assert ids == [str(newer.id), str(older.id)]

    async def test_sort_by_and_sort_order_are_ignored(
        self,
        admin_client: AsyncClient,
        fetcher_config_factory: FetcherConfigFactory,
        fetcher_audit_event_factory: FetcherAuditEventFactory,
    ) -> None:
        config = await fetcher_config_factory()
        older = await fetcher_audit_event_factory(
            fetcher_name=config.fetcher_name,
            created_at=datetime(2026, 5, 1, tzinfo=UTC),
        )
        newer = await fetcher_audit_event_factory(
            fetcher_name=config.fetcher_name,
            created_at=datetime(2026, 5, 2, tzinfo=UTC),
        )

        response = await admin_client.get(
            f"/api/v1/fetchers/{config.fetcher_name}/audit-log",
            params={"sort_by": "created_at", "sort_order": "asc"},
        )

        ids = [item["id"] for item in response.json()["data"]]
        assert ids == [str(newer.id), str(older.id)]

    async def test_no_mutation_methods_are_exposed(
        self, admin_client: AsyncClient, fetcher_config_factory: FetcherConfigFactory
    ) -> None:
        config = await fetcher_config_factory()
        response = await admin_client.post(
            f"/api/v1/fetchers/{config.fetcher_name}/audit-log"
        )
        assert response.status_code == 405


# ---------------------------------------------------------------------------
# OpenAPI surface
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestFetchersConfigAndAuditLogOpenAPISurface:
    def test_both_endpoints_have_summary_and_description(self) -> None:
        openapi_paths = app.openapi()["paths"]

        config_get = openapi_paths["/api/v1/fetchers/{fetcher_name}/config"]["get"]
        assert config_get["summary"]
        assert config_get["description"]

        config_patch = openapi_paths["/api/v1/fetchers/{fetcher_name}/config"]["patch"]
        assert config_patch["summary"]
        assert config_patch["description"]

        audit_get = openapi_paths["/api/v1/fetchers/{fetcher_name}/audit-log"]["get"]
        assert audit_get["summary"]
        assert audit_get["description"]

    def test_update_config_declares_a_request_body(self) -> None:
        openapi_paths = app.openapi()["paths"]
        config_patch = openapi_paths["/api/v1/fetchers/{fetcher_name}/config"]["patch"]
        assert "requestBody" in config_patch

    def test_audit_log_query_parameters_are_declared(self) -> None:
        openapi_paths = app.openapi()["paths"]
        audit_get = openapi_paths["/api/v1/fetchers/{fetcher_name}/audit-log"]["get"]
        param_names = {p["name"] for p in audit_get.get("parameters", [])}

        assert {"event_type", "actor", "from_date", "to_date", "page", "per_page"} <= (
            param_names
        )
        assert "sort_by" not in param_names
        assert "sort_order" not in param_names

    def test_event_type_parameter_is_repeatable(self) -> None:
        openapi_paths = app.openapi()["paths"]
        audit_get = openapi_paths["/api/v1/fetchers/{fetcher_name}/audit-log"]["get"]
        event_type_param = next(
            p for p in audit_get["parameters"] if p["name"] == "event_type"
        )
        assert event_type_param["schema"]["type"] == "array"
