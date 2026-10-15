"""End-to-end tests for the IBS consumer status endpoint
(`GET /api/v1/ibs-consumer/status`, `backend/app/api/v1/ibs_consumer.py`).

See docs/features/integrations/ibs-rabbitmq-integration.md (Status API > Get
IBS Consumer Status: Behavior, Response Schema; Monitoring and Observability >
Heartbeat Storage, Consumer States; Security; Testing Requirements),
docs/api-spec.md (Optional Authentication on Public Endpoints; Infrastructure
Dependency Errors > Status-reporting exception; Response Format; Global
Responses; Response Applicability Derivation), and
docs/features/platform/testing-strategy.md (API Endpoints; Redis Strategy;
Tier Responsibility and Proportionality).

These tests cover the HTTP contract: the envelope and wire format of every
status, HTTP 200 for every operational status (never `REDIS_UNAVAILABLE`),
the absence of stale fields beside `unreachable`, optional authentication,
ignored query parameters, response sanitization, the route inventory, and
OpenAPI. The heartbeat validation matrix lives in
`tests/test_services/test_ibs_consumer_status.py`; this module repeats a
representative case per rejection kind because the handler owns the
all-null `unreachable` response assembly.

Every test that can reach Redis requests `redis_client`, sets
`IBS_RABBITMQ_ENABLED` explicitly, and fixes the status read's clock.
Every value is fictional.
"""

from __future__ import annotations

import hashlib
import json
import secrets
from collections.abc import Awaitable, Callable, Mapping
from datetime import UTC, datetime
from typing import Any, Final
from unittest.mock import AsyncMock

import pytest
import redis.asyncio as redis_asyncio
from fastapi import routing as fastapi_routing
from fastapi.routing import APIRoute
from httpx import AsyncClient
from redis import exceptions as redis_exceptions

from app.api import dependencies
from app.api.dependencies import SESSION_COOKIE_NAME
from app.config import settings
from app.core.enums import IBSConsumerStatus
from app.main import app
from app.models.api_key import ApiKey
from app.models.user import User
from app.services import ibs_consumer_status
from app.services.ibs_consumer_status import STATUS_KEY, IBSConsumerStatusView
from tests.support.ticket_api import UNAUTHENTICATED

_PATH: Final = "/api/v1/ibs-consumer/status"
_NOW: Final = datetime(2026, 9, 8, 15, 42, 40, tzinfo=UTC)

_CONNECTED: Final[Mapping[str, Any]] = {
    "status": "connected",
    "heartbeat_at": "2026-09-08T15:42:30Z",
    "process_started_at": "2026-09-08T14:00:00Z",
    "status_since": "2026-09-08T15:40:12Z",
    "events_received": 12847,
    "events_relevant": 342,
    "events_processed": 338,
    "processing_failed": 4,
    "reconnect_attempts": 2,
    "next_retry_seconds": None,
    "last_error": "request_reconciliation_failed",
    "last_error_at": "2026-09-08T15:31:04Z",
}
"""The connected example of Heartbeat Storage (and of the response)."""

_DISCONNECTED: Final[Mapping[str, Any]] = {
    **_CONNECTED,
    "status": "disconnected",
    "status_since": "2026-09-08T15:42:30Z",
    "last_error": "rabbitmq_connection_lost",
    "last_error_at": "2026-09-08T15:42:30Z",
}

_RECONNECTING: Final[Mapping[str, Any]] = {
    **_CONNECTED,
    "status": "reconnecting",
    "status_since": "2026-09-08T15:42:30Z",
    "reconnect_attempts": 3,
    "next_retry_seconds": 10,
    "last_error": "rabbitmq_connection_failed",
    "last_error_at": "2026-09-08T15:42:30Z",
}

_FIELDS: Final = frozenset(_CONNECTED)

_PROJECT: Final = "SUSE:SLE-15-SP6:Update"
_PACKAGE: Final = "example-pkg"


def _null_body(status: str) -> dict[str, Any]:
    """The `disabled` / `unreachable` body: every other field `null`."""
    return {
        "data": {
            "status": status,
            **{name: None for name in _CONNECTED if name != "status"},
        }
    }


def _with(**overrides: Any) -> dict[str, Any]:
    return {**_CONNECTED, **overrides}


def _encode(members: Mapping[str, Any]) -> bytes:
    return json.dumps(members).encode()


async def _store(redis_client: redis_asyncio.Redis, value: bytes) -> None:
    await redis_client.set(STATUS_KEY, value, ex=60)


def _make_api_key_credential() -> tuple[str, str]:
    """Return `(plaintext_token, sha256_hex_digest)` for a synthetic key."""
    token = "stl_ak_" + secrets.token_hex(16)
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
    return token, digest


@pytest.fixture
def enabled(monkeypatch: pytest.MonkeyPatch) -> None:
    """`IBS_RABBITMQ_ENABLED=true` and a fixed clock for freshness."""
    monkeypatch.setattr(settings, "ibs_rabbitmq_enabled", True)
    monkeypatch.setattr(ibs_consumer_status, "utc_now", lambda: _NOW)


def _spy(monkeypatch: pytest.MonkeyPatch) -> AsyncMock:
    """Replace the status read the handler calls through its module."""
    spy = AsyncMock(return_value=IBSConsumerStatusView(IBSConsumerStatus.DISABLED))
    monkeypatch.setattr(ibs_consumer_status, "get_ibs_consumer_status", spy)
    return spy


def _forbid_redis(monkeypatch: pytest.MonkeyPatch) -> None:
    def _no_redis() -> redis_asyncio.Redis:
        raise AssertionError("Redis must not be read")

    monkeypatch.setattr(ibs_consumer_status, "_new_redis_client", _no_redis)


# ---------------------------------------------------------------------------
# Consumer-written states
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestConsumerWrittenStatus:
    @pytest.mark.parametrize(
        "members",
        [
            pytest.param(_CONNECTED, id="connected"),
            pytest.param(_DISCONNECTED, id="disconnected"),
            pytest.param(_RECONNECTING, id="reconnecting"),
        ],
    )
    async def test_valid_fresh_heartbeat_returns_200_with_every_field(
        self,
        client: AsyncClient,
        redis_client: redis_asyncio.Redis,
        enabled: None,
        members: Mapping[str, Any],
    ) -> None:
        await _store(redis_client, _encode(members))

        response = await client.get(_PATH)

        assert response.status_code == 200
        assert response.json() == {"data": dict(members)}
        assert set(response.json()["data"]) == _FIELDS

    async def test_plus_zero_offsets_render_with_z_and_extra_members_are_dropped(
        self, client: AsyncClient, redis_client: redis_asyncio.Redis, enabled: None
    ) -> None:
        stored = _with(
            heartbeat_at="2026-09-08T15:42:30+00:00",
            process_started_at="2026-09-08T14:00:00+00:00",
            status_since="2026-09-08T15:40:12+00:00",
            last_error_at="2026-09-08T15:31:04+00:00",
            schema_version=2,
            host="consumer-1.example.test",
        )
        await _store(redis_client, _encode(stored))

        response = await client.get(_PATH)

        assert response.status_code == 200
        assert response.json() == {"data": dict(_CONNECTED)}


# ---------------------------------------------------------------------------
# disabled
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestDisabledStatus:
    async def test_disabled_ignores_a_fresh_key_and_reads_no_redis(
        self,
        client: AsyncClient,
        redis_client: redis_asyncio.Redis,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(settings, "ibs_rabbitmq_enabled", False)
        monkeypatch.setattr(ibs_consumer_status, "utc_now", lambda: _NOW)
        await _store(redis_client, _encode(_CONNECTED))
        _forbid_redis(monkeypatch)

        response = await client.get(_PATH)

        assert response.status_code == 200
        assert response.json() == _null_body("disabled")


# ---------------------------------------------------------------------------
# unreachable
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestUnreachableStatus:
    @pytest.mark.parametrize(
        "value",
        [
            pytest.param(None, id="absent-key"),
            pytest.param(b"consumer is fine", id="non-json"),
            pytest.param(b'["connected"]', id="non-object"),
            pytest.param(
                _encode(
                    {k: v for k, v in _CONNECTED.items() if k != "events_received"}
                ),
                id="missing-field",
            ),
            pytest.param(_encode(_with(events_processed="338")), id="counter-type"),
            pytest.param(_encode(_with(status="paused")), id="unknown-status"),
            pytest.param(
                _encode(_with(last_error="disk_full")), id="unknown-last-error"
            ),
            pytest.param(
                _encode(_with(heartbeat_at="2026-09-08T15:42:41Z")),
                id="future-heartbeat_at",
            ),
            pytest.param(
                _encode(_with(status_since="2026-09-08T13:59:59Z")),
                id="invalid-ordering",
            ),
            pytest.param(
                _encode(_with(heartbeat_at="2026-09-08T15:41:39Z")),
                id="stale-61-seconds",
            ),
            pytest.param(
                _encode(_with(last_error_at=None)), id="mismatched-last-error-at"
            ),
            pytest.param(_encode(_with(events_relevant=12848)), id="counter-invariant"),
            pytest.param(
                _encode(_with(next_retry_seconds=5)), id="connected-with-next-retry"
            ),
        ],
    )
    async def test_unusable_heartbeat_returns_200_unreachable_with_null_fields(
        self,
        client: AsyncClient,
        redis_client: redis_asyncio.Redis,
        enabled: None,
        value: bytes | None,
    ) -> None:
        if value is not None:
            await _store(redis_client, value)

        response = await client.get(_PATH)

        assert response.status_code == 200
        assert response.json() == _null_body("unreachable")

    @pytest.mark.parametrize(
        "error",
        [
            pytest.param(
                redis_exceptions.ConnectionError("fictional refused"), id="connection"
            ),
            pytest.param(
                redis_exceptions.TimeoutError("fictional timeout"), id="timeout"
            ),
            pytest.param(
                redis_exceptions.ResponseError("OOM command not allowed"),
                id="oom-response",
            ),
        ],
    )
    async def test_redis_error_returns_200_unreachable_never_redis_unavailable(
        self,
        client: AsyncClient,
        redis_client: redis_asyncio.Redis,
        enabled: None,
        monkeypatch: pytest.MonkeyPatch,
        error: redis_exceptions.RedisError,
    ) -> None:
        await _store(redis_client, _encode(_CONNECTED))
        failing = AsyncMock()
        failing.get.side_effect = error
        monkeypatch.setattr(ibs_consumer_status, "_new_redis_client", lambda: failing)

        response = await client.get(_PATH)

        assert response.status_code == 200
        assert response.json() == _null_body("unreachable")
        assert "REDIS_UNAVAILABLE" not in response.text
        failing.aclose.assert_awaited_once()


# ---------------------------------------------------------------------------
# Optional authentication
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestOptionalAuthentication:
    async def test_anonymous_request_is_accepted(
        self, client: AsyncClient, redis_client: redis_asyncio.Redis, enabled: None
    ) -> None:
        await _store(redis_client, _encode(_CONNECTED))

        response = await client.get(_PATH)

        assert response.status_code == 200
        assert response.json() == {"data": dict(_CONNECTED)}

    async def test_valid_session_cookie_is_accepted_with_the_same_status(
        self,
        authenticated_client: AsyncClient,
        redis_client: redis_asyncio.Redis,
        enabled: None,
    ) -> None:
        await _store(redis_client, _encode(_CONNECTED))

        response = await authenticated_client.get(_PATH)

        assert response.status_code == 200
        assert response.json() == {"data": dict(_CONNECTED)}

    async def test_valid_api_key_is_accepted_and_processed(
        self,
        client: AsyncClient,
        redis_client: redis_asyncio.Redis,
        enabled: None,
        user_factory: Callable[..., Awaitable[User]],
        api_key_factory: Callable[..., Awaitable[ApiKey]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A valid selected API key authenticates the caller and runs the
        API-key operational effect (`last_used_at` debouncing)."""
        await _store(redis_client, _encode(_CONNECTED))
        user = await user_factory()
        token, digest = _make_api_key_credential()
        key = await api_key_factory(user_id=user.id, key_hash=digest)
        touch = AsyncMock()
        monkeypatch.setattr(dependencies._last_used_debouncer, "touch", touch)

        response = await client.get(_PATH, headers={"Authorization": f"Bearer {token}"})

        assert response.status_code == 200
        assert response.json() == {"data": dict(_CONNECTED)}
        touch.assert_awaited_once()
        assert touch.await_args is not None
        assert touch.await_args.args[0] == key.id

    @pytest.mark.parametrize(
        "credential",
        [
            {"headers": {"Authorization": "Bearer invalid-token"}},
            {"headers": {"Authorization": "Bearer stl_ak_" + "0" * 32}},
            {"cookies": {SESSION_COOKIE_NAME: "invalid-session-token"}},
        ],
        ids=["bearer", "unknown-api-key", "cookie"],
    )
    async def test_invalid_selected_credential_returns_401_before_the_service(
        self,
        client: AsyncClient,
        redis_client: redis_asyncio.Redis,
        enabled: None,
        monkeypatch: pytest.MonkeyPatch,
        credential: dict[str, dict[str, str]],
    ) -> None:
        spy = _spy(monkeypatch)
        for name, value in credential.get("cookies", {}).items():
            client.cookies.set(name, value)

        response = await client.get(_PATH, headers=credential.get("headers", {}))

        assert response.status_code == 401
        assert response.json() == UNAUTHENTICATED
        spy.assert_not_awaited()

    async def test_invalid_bearer_never_falls_back_to_a_valid_cookie(
        self,
        authenticated_client: AsyncClient,
        enabled: None,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        spy = _spy(monkeypatch)

        response = await authenticated_client.get(
            _PATH, headers={"Authorization": "Bearer invalid-token"}
        )

        assert response.status_code == 401
        assert response.json() == UNAUTHENTICATED
        spy.assert_not_awaited()

    async def test_handler_delegates_to_the_status_read_once(
        self, client: AsyncClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        spy = _spy(monkeypatch)

        response = await client.get(_PATH)

        assert response.status_code == 200
        assert response.json() == _null_body("disabled")
        spy.assert_awaited_once_with()


# ---------------------------------------------------------------------------
# Query parameters and sanitization
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestRequestAndResponseBoundaries:
    async def test_query_parameters_are_ignored(
        self, client: AsyncClient, redis_client: redis_asyncio.Redis, enabled: None
    ) -> None:
        await _store(redis_client, _encode(_RECONNECTING))

        plain = await client.get(_PATH)
        with_params = await client.get(
            _PATH, params={"status": "connected", "page": "0", "q": "x" * 600}
        )

        assert plain.status_code == with_params.status_code == 200
        assert with_params.json() == plain.json() == {"data": dict(_RECONNECTING)}

    @pytest.mark.parametrize(
        ("stored", "status"),
        [
            pytest.param(_CONNECTED, "connected", id="valid-heartbeat"),
            pytest.param(
                {k: v for k, v in _CONNECTED.items() if k != "status"},
                "unreachable",
                id="invalid-heartbeat",
            ),
        ],
    )
    async def test_response_exposes_no_broker_url_credential_project_or_package(
        self,
        client: AsyncClient,
        redis_client: redis_asyncio.Redis,
        enabled: None,
        monkeypatch: pytest.MonkeyPatch,
        stored: Mapping[str, Any],
        status: str,
    ) -> None:
        monkeypatch.setattr(
            settings,
            "ibs_rabbitmq_url",
            "amqps://example-user:example-secret@mq.example.test",
        )
        polluted = {
            **stored,
            "broker": "amqps://example-user:example-secret@mq.example.test",
            "project": _PROJECT,
            "package": _PACKAGE,
            "raw_error": "fictional upstream failure",
        }
        await _store(redis_client, _encode(polluted))

        response = await client.get(_PATH)

        assert response.status_code == 200
        assert response.json()["data"]["status"] == status
        for leaked in (
            "amqps",
            "example-user",
            "example-secret",
            "mq.example.test",
            _PROJECT,
            _PACKAGE,
            "fictional upstream failure",
        ):
            assert leaked not in response.text


# ---------------------------------------------------------------------------
# Route inventory and OpenAPI contract
# ---------------------------------------------------------------------------


def _schemas() -> dict[str, Any]:
    schemas: dict[str, Any] = app.openapi()["components"]["schemas"]
    return schemas


def _operation() -> dict[str, Any]:
    operation: dict[str, Any] = app.openapi()["paths"][_PATH]["get"]
    return operation


def _referenced(schema: dict[str, Any]) -> dict[str, Any]:
    referenced: dict[str, Any] = _schemas()[schema["$ref"].rsplit("/", 1)[1]]
    return referenced


def _branches(schema: dict[str, Any]) -> list[dict[str, Any]]:
    """The schema itself plus its `anyOf` alternatives."""
    return [schema, *schema.get("anyOf", [])]


def _enum_values(schema: dict[str, Any]) -> set[str]:
    for branch in _branches(schema):
        if "$ref" in branch:
            return set(_referenced(branch)["enum"])
        if "enum" in branch:
            return set(branch["enum"])
    raise AssertionError(f"no enum in {schema}")


@pytest.mark.unit
class TestRouteInventory:
    def test_only_the_status_endpoint_is_registered(self) -> None:
        """Route discovery uses `iter_route_contexts()` — see
        `tests/test_api_conventions.py` for why `app.routes` alone does not
        expose routes included via `include_router()`."""
        routes = {
            (context.path, method)
            for context in fastapi_routing.iter_route_contexts(app.routes)
            if isinstance(context.original_route, APIRoute)
            and context.path is not None
            and context.path.startswith("/api/v1/ibs-consumer")
            for method in (context.methods or set()) - {"HEAD", "OPTIONS"}
        }

        assert routes == {(_PATH, "GET")}


@pytest.mark.unit
class TestOpenApiContract:
    def test_operation_has_summary_description_tag_and_no_parameters(self) -> None:
        assert set(app.openapi()["paths"][_PATH]) == {"get"}
        operation = _operation()

        assert operation["summary"]
        assert operation["description"]
        assert operation["tags"] == ["IBS Consumer"]
        assert operation.get("parameters", []) == []
        assert "requestBody" not in operation

    def test_response_schema_is_the_envelope_with_every_field(self) -> None:
        response = _operation()["responses"]["200"]["content"]["application/json"]
        envelope = _referenced(response["schema"])

        assert response["schema"]["$ref"].endswith("/IBSConsumerStatusResponse")
        assert set(envelope["properties"]) == {"data"}
        assert envelope["required"] == ["data"]
        data = _referenced(envelope["properties"]["data"])
        assert set(data["properties"]) == _FIELDS
        assert set(data["required"]) == _FIELDS
        for name in _FIELDS - {"status"}:
            assert {"type": "null"} in data["properties"][name]["anyOf"], name

    def test_status_and_last_error_enums_are_exact(self) -> None:
        data = _schemas()["IBSConsumerStatusData"]["properties"]

        assert _enum_values(data["status"]) == {
            "connected",
            "disconnected",
            "reconnecting",
            "disabled",
            "unreachable",
        }
        assert _enum_values(data["last_error"]) == {
            "rabbitmq_connection_failed",
            "rabbitmq_connection_lost",
            "package_reconciliation_failed",
            "request_reconciliation_failed",
        }
