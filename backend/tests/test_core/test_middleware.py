"""Tests for RequestIDMiddleware (backend/app/core/middleware.py).

See docs/api-spec.md (Request Tracing) and
docs/features/platform/logging.md (Correlation IDs) for the contract
this middleware implements.

A minimal, isolated FastAPI app is used here (rather than the real
`app.main` app) so these tests exercise the middleware in isolation,
without depending on database/CORS/other application wiring.
"""

from __future__ import annotations

import re
from collections.abc import AsyncGenerator
from typing import Any
from unittest.mock import AsyncMock

import pytest
import structlog
from fastapi import BackgroundTasks, FastAPI, HTTPException
from httpx import ASGITransport, AsyncClient
from pydantic import BaseModel

from app.core.middleware import RequestIDMiddleware

_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)


class _Payload(BaseModel):
    value: int


def _build_test_app() -> FastAPI:
    """Minimal FastAPI app wired only with RequestIDMiddleware."""
    test_app = FastAPI()
    test_app.add_middleware(RequestIDMiddleware)

    captured_logs: list[dict[str, Any]] = []
    background_calls: list[dict[str, Any]] = []
    test_app.state.captured_logs = captured_logs
    test_app.state.background_calls = background_calls

    @test_app.get("/ok")
    async def ok_endpoint() -> dict[str, str]:
        captured_logs.append(dict(structlog.contextvars.get_contextvars()))
        return {"status": "ok"}

    @test_app.get("/boom")
    async def boom_endpoint() -> None:
        raise HTTPException(status_code=500, detail="boom")

    @test_app.post("/validate")
    async def validate_endpoint(payload: _Payload) -> dict[str, int]:
        return {"value": payload.value}

    @test_app.get("/background")
    async def background_endpoint(
        background_tasks: BackgroundTasks,
    ) -> dict[str, str]:
        def _record() -> None:
            background_calls.append(dict(structlog.contextvars.get_contextvars()))

        background_tasks.add_task(_record)
        return {"status": "scheduled"}

    return test_app


@pytest.fixture
async def middleware_app_client() -> AsyncGenerator[tuple[AsyncClient, FastAPI]]:
    test_app = _build_test_app()
    async with AsyncClient(
        transport=ASGITransport(app=test_app), base_url="http://test"
    ) as client:
        yield client, test_app


@pytest.mark.unit
class TestNonHttpScopePassthrough:
    """Non-HTTP ASGI scopes (websocket, lifespan) bypass the middleware."""

    async def test_non_http_scope_calls_through_without_binding(self) -> None:
        inner_app = AsyncMock()
        middleware = RequestIDMiddleware(inner_app)
        scope: dict[str, Any] = {"type": "lifespan"}
        receive = AsyncMock()
        send = AsyncMock()

        await middleware(scope, receive, send)

        inner_app.assert_awaited_once_with(scope, receive, send)
        assert structlog.contextvars.get_contextvars().get("request_id") is None


@pytest.mark.e2e
class TestRequestIDGeneration:
    """Adoption vs. generation of the X-Request-ID header."""

    async def test_generates_uuid_when_header_absent(
        self, middleware_app_client: tuple[AsyncClient, FastAPI]
    ) -> None:
        client, _ = middleware_app_client
        response = await client.get("/ok")
        assert response.status_code == 200
        request_id = response.headers["x-request-id"]
        assert _UUID_RE.match(request_id)

    async def test_adopts_valid_client_supplied_header(
        self, middleware_app_client: tuple[AsyncClient, FastAPI]
    ) -> None:
        client, _ = middleware_app_client
        response = await client.get("/ok", headers={"X-Request-ID": "my-custom-id.123"})
        assert response.headers["x-request-id"] == "my-custom-id.123"

    async def test_two_requests_get_different_generated_ids(
        self, middleware_app_client: tuple[AsyncClient, FastAPI]
    ) -> None:
        client, _ = middleware_app_client
        r1 = await client.get("/ok")
        r2 = await client.get("/ok")
        assert r1.headers["x-request-id"] != r2.headers["x-request-id"]


@pytest.mark.e2e
class TestRequestIDValidation:
    """Client-supplied value validation per docs/api-spec.md."""

    async def test_rejects_invalid_characters_falls_back_to_uuid(
        self, middleware_app_client: tuple[AsyncClient, FastAPI]
    ) -> None:
        client, _ = middleware_app_client
        response = await client.get("/ok", headers={"X-Request-ID": "has spaces!"})
        assert _UUID_RE.match(response.headers["x-request-id"])

    async def test_rejects_value_exceeding_128_chars(
        self, middleware_app_client: tuple[AsyncClient, FastAPI]
    ) -> None:
        client, _ = middleware_app_client
        too_long = "a" * 129
        response = await client.get("/ok", headers={"X-Request-ID": too_long})
        assert _UUID_RE.match(response.headers["x-request-id"])

    async def test_accepts_exactly_128_chars(
        self, middleware_app_client: tuple[AsyncClient, FastAPI]
    ) -> None:
        client, _ = middleware_app_client
        exactly_128 = "a" * 128
        response = await client.get("/ok", headers={"X-Request-ID": exactly_128})
        assert response.headers["x-request-id"] == exactly_128

    async def test_trims_leading_trailing_whitespace(
        self, middleware_app_client: tuple[AsyncClient, FastAPI]
    ) -> None:
        client, _ = middleware_app_client
        response = await client.get("/ok", headers={"X-Request-ID": "  trimmed-id  "})
        assert response.headers["x-request-id"] == "trimmed-id"

    async def test_rejects_empty_value_falls_back_to_uuid(
        self, middleware_app_client: tuple[AsyncClient, FastAPI]
    ) -> None:
        client, _ = middleware_app_client
        response = await client.get("/ok", headers={"X-Request-ID": ""})
        assert _UUID_RE.match(response.headers["x-request-id"])

    async def test_rejects_whitespace_only_value(
        self, middleware_app_client: tuple[AsyncClient, FastAPI]
    ) -> None:
        client, _ = middleware_app_client
        response = await client.get("/ok", headers={"X-Request-ID": "   "})
        assert _UUID_RE.match(response.headers["x-request-id"])

    async def test_duplicate_headers_uses_first_occurrence(
        self, middleware_app_client: tuple[AsyncClient, FastAPI]
    ) -> None:
        client, _ = middleware_app_client
        # httpx allows building a request with multiple same-name headers
        # via a list of tuples.
        request = client.build_request(
            "GET",
            "/ok",
            headers=[("X-Request-ID", "first-id"), ("X-Request-ID", "second-id")],
        )
        response = await client.send(request)
        assert response.headers["x-request-id"] == "first-id"

    async def test_invalid_first_occurrence_not_rescued_by_valid_second(
        self, middleware_app_client: tuple[AsyncClient, FastAPI]
    ) -> None:
        client, _ = middleware_app_client
        request = client.build_request(
            "GET",
            "/ok",
            headers=[("X-Request-ID", "invalid header!"), ("X-Request-ID", "valid-id")],
        )
        response = await client.send(request)
        assert _UUID_RE.match(response.headers["x-request-id"])


@pytest.mark.e2e
class TestRequestIDOnErrorResponses:
    """Every response carries X-Request-ID, including error responses."""

    async def test_present_on_404(
        self, middleware_app_client: tuple[AsyncClient, FastAPI]
    ) -> None:
        client, _ = middleware_app_client
        response = await client.get("/nonexistent")
        assert response.status_code == 404
        assert _UUID_RE.match(response.headers["x-request-id"])

    async def test_present_on_raised_http_exception(
        self, middleware_app_client: tuple[AsyncClient, FastAPI]
    ) -> None:
        client, _ = middleware_app_client
        response = await client.get("/boom")
        assert response.status_code == 500
        assert _UUID_RE.match(response.headers["x-request-id"])

    async def test_present_on_validation_error(
        self, middleware_app_client: tuple[AsyncClient, FastAPI]
    ) -> None:
        client, _ = middleware_app_client
        response = await client.post("/validate", json={"value": "not-an-int"})
        assert response.status_code == 422
        assert _UUID_RE.match(response.headers["x-request-id"])


@pytest.mark.e2e
class TestRequestIDCorrelationBinding:
    """request_id is bound to the structlog context during processing."""

    async def test_request_id_bound_during_handler_execution(
        self, middleware_app_client: tuple[AsyncClient, FastAPI]
    ) -> None:
        client, test_app = middleware_app_client
        response = await client.get("/ok", headers={"X-Request-ID": "bound-check-id"})
        assert response.headers["x-request-id"] == "bound-check-id"
        assert test_app.state.captured_logs[-1]["request_id"] == "bound-check-id"

    async def test_context_reset_after_request_no_leakage(
        self, middleware_app_client: tuple[AsyncClient, FastAPI]
    ) -> None:
        client, _test_app = middleware_app_client
        await client.get("/ok", headers={"X-Request-ID": "leak-check-id"})
        # After the request completes, the context var must not leak.
        assert structlog.contextvars.get_contextvars().get("request_id") is None

    async def test_background_task_sees_same_request_id(
        self, middleware_app_client: tuple[AsyncClient, FastAPI]
    ) -> None:
        client, test_app = middleware_app_client
        response = await client.get(
            "/background", headers={"X-Request-ID": "bg-task-id"}
        )
        assert response.status_code == 200
        assert test_app.state.background_calls
        assert test_app.state.background_calls[-1]["request_id"] == "bg-task-id"

    async def test_sequential_requests_do_not_leak_context(
        self, middleware_app_client: tuple[AsyncClient, FastAPI]
    ) -> None:
        client, test_app = middleware_app_client
        await client.get("/ok", headers={"X-Request-ID": "request-one"})
        await client.get("/ok", headers={"X-Request-ID": "request-two"})
        assert test_app.state.captured_logs[0]["request_id"] == "request-one"
        assert test_app.state.captured_logs[1]["request_id"] == "request-two"


@pytest.mark.e2e
class TestRequestIDOnRealApp:
    """Confirms the actual `app.main` wiring (real middleware stack, real
    settings) also carries X-Request-ID. The classes above exercise the
    middleware's internal behavior in an isolated app; this complements that
    by guarding the real registration in `main.py`, which unit tests cannot
    observe. Exposure of the header to an allowed cross-origin client is
    covered with the CORS configuration in `tests/test_main.py`.
    """

    async def test_real_app_response_carries_request_id(
        self, client: AsyncClient
    ) -> None:
        response = await client.get("/nonexistent-request-id-wiring-check")
        assert response.status_code == 404
        assert _UUID_RE.match(response.headers["x-request-id"])
