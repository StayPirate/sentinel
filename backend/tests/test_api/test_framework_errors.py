"""End-to-end tests for the errors the framework produces itself.

See `docs/api-spec.md` (Routing Responses, JSON Request Body Decoding,
Response Format) for the contracts and
`docs/features/platform/testing-strategy.md` (Routing and JSON Request Body
Decoding Responses) for the mandatory scenario. Every case goes through the
registered application, whose `HTTPException` and `RequestValidationError`
handlers (`app/main.py`) render the standard error envelope. The handlers'
own tests, including the fallback for any other framework error, are in
`tests/test_main.py`.
"""

from __future__ import annotations

import re
import sys
from collections import defaultdict
from typing import Any, Final

import pytest
import redis.asyncio as redis_asyncio
from fastapi import routing as fastapi_routing
from httpx import AsyncClient
from starlette.routing import compile_path

from app.main import app
from tests.support.json_decoding import (
    NESTED_ARRAY,
    OVERSIZED_INTEGER,
    limit_request_body_nesting,
)

_JSON_HEADERS: Final = {"content-type": "application/json"}
_LOGIN: Final = "/api/v1/auth/login"

_ROUTE_NOT_FOUND: Final = {
    "code": "ROUTE_NOT_FOUND",
    "detail": "No endpoint matches the request path.",
}
_METHOD_NOT_ALLOWED: Final = {
    "code": "ROUTE_METHOD_NOT_ALLOWED",
    "detail": "No endpoint at the request path accepts this method.",
}


def _json_invalid(loc: list[str | int]) -> dict[str, Any]:
    return {
        "code": "VALIDATION_ERROR",
        "detail": "Request validation failed",
        "errors": [{"loc": loc, "msg": "JSON decode error", "type": "json_invalid"}],
    }


def _registered_methods() -> dict[str, set[str]]:
    """Every registered path pattern with the methods its routes serve."""
    methods: dict[str, set[str]] = defaultdict(set)
    for context in fastapi_routing.iter_route_contexts(app.routes):
        if context.path is not None and context.methods:
            methods[context.path] |= context.methods
    return methods


def _concrete(path: str) -> str:
    """`path` with every path parameter replaced by a fictional value."""
    return re.sub(r"\{[^}]+\}", "fictional-segment", path)


@pytest.mark.e2e
class TestRouteNotFound:
    @pytest.mark.parametrize(
        "path",
        [
            "/api/v1/does-not-exist",
            "/api/v1/tickets/SNTL-1/does-not-exist",
            "/",
            "/health/does-not-exist",
        ],
    )
    async def test_unknown_path_returns_route_not_found(
        self, client: AsyncClient, path: str
    ) -> None:
        response = await client.get(path)

        assert response.status_code == 404
        assert response.json() == _ROUTE_NOT_FOUND

    async def test_neither_credentials_nor_body_are_considered(
        self, client: AsyncClient
    ) -> None:
        """Routing precedes authentication and body decoding: an invalid
        credential and a body that cannot be decoded change nothing."""
        response = await client.post(
            "/api/v1/does-not-exist",
            content=b'{"name": "fictional\xffvalue"}',
            headers={**_JSON_HEADERS, "Authorization": "Bearer stl_ak_fictional"},
        )

        assert response.status_code == 404
        assert response.json() == _ROUTE_NOT_FOUND

    async def test_every_endpoint_path_with_a_trailing_slash_returns_route_not_found(
        self, client: AsyncClient
    ) -> None:
        """The path is not redirected to the endpoint path: a redirect built
        from the request could point a client behind a TLS-terminating proxy
        at `http://`. Each registered path is requested with every method it
        serves, so a new endpoint is covered without changing this test. A
        response to `HEAD` has no body."""
        expected: dict[tuple[str, str], tuple[int, str | None, dict[str, Any]]] = {}
        observed: dict[tuple[str, str], tuple[int, str | None, dict[str, Any]]] = {}

        for path, methods in _registered_methods().items():
            for method in methods:
                body = {} if method == "HEAD" else _ROUTE_NOT_FOUND
                expected[path, method] = (404, None, body)
                response = await client.request(method, _concrete(path) + "/")
                observed[path, method] = (
                    response.status_code,
                    response.headers.get("location"),
                    response.json() if response.content else {},
                )

        assert observed == expected


@pytest.mark.e2e
class TestMethodNotAllowed:
    async def test_every_endpoint_path_allows_exactly_its_methods(
        self, client: AsyncClient
    ) -> None:
        """No endpoint serves `PUT` (`docs/api-spec.md`, Mutation Patterns),
        so it reaches the 405 on every registered path, before
        authentication and capability checks, which this anonymous client
        would otherwise fail. A concrete path is expected to allow every
        method of every registered pattern that matches it, so a new
        endpoint is covered without changing this test."""
        registered = _registered_methods()
        patterns = {path: compile_path(path)[0] for path in registered}
        expected: dict[str, tuple[int, set[str], dict[str, Any]]] = {}
        observed: dict[str, tuple[int, set[str], dict[str, Any]]] = {}

        for path in registered:
            concrete = _concrete(path)
            allowed = set[str]().union(
                *(
                    registered[pattern]
                    for pattern, regex in patterns.items()
                    if regex.match(concrete)
                )
            )
            expected[path] = (405, allowed, _METHOD_NOT_ALLOWED)
            response = await client.put(concrete)
            observed[path] = (
                response.status_code,
                set(response.headers.get("allow", "").split(", ")),
                response.json(),
            )

        assert observed == expected


@pytest.mark.e2e
class TestUndecodableBody:
    async def test_syntax_error_keeps_its_position(
        self, client: AsyncClient, redis_client: redis_asyncio.Redis
    ) -> None:
        """The trailing data follows complete login credentials, which a
        lenient decoder would pass to local login."""
        document = b'{"username": "fictional-user", "password": "irrelevant"}'

        response = await client.post(
            _LOGIN, content=document + b" x", headers=_JSON_HEADERS
        )

        assert response.status_code == 422
        assert response.json() == _json_invalid(["body", len(document) + 1])
        assert await redis_client.keys("login_attempts:*") == []

    @pytest.mark.parametrize(
        "body",
        [
            pytest.param(
                b'{"username": "fictional\xffuser", "password": "irrelevant"}',
                id="invalid-utf-8",
            ),
            pytest.param(
                (
                    '{"username": "fictional-user", "password": "irrelevant", '
                    f'"n": {OVERSIZED_INTEGER}}}'
                ).encode(),
                id="integer-beyond-the-conversion-limit",
            ),
        ],
    )
    async def test_body_is_rejected_before_lockout_accounting(
        self, client: AsyncClient, redis_client: redis_asyncio.Redis, body: bytes
    ) -> None:
        """Decoded, either body would reach local login, which counts a
        failed attempt for the unknown username."""
        response = await client.post(_LOGIN, content=body, headers=_JSON_HEADERS)

        assert response.status_code == 422
        assert response.json() == _json_invalid(["body"])
        assert await redis_client.keys("login_attempts:*") == []

    async def test_nesting_beyond_the_parser_limit_is_rejected(
        self,
        client: AsyncClient,
        redis_client: redis_asyncio.Redis,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The real parser accepts `NESTED_ARRAY`, so the field reaches schema
        validation; the replacement parser rejects it as nesting beyond its
        limit, whatever the stack size."""
        body = '{"username": ' + NESTED_ARRAY + ', "password": "irrelevant"}'

        accepted = await client.post(_LOGIN, content=body, headers=_JSON_HEADERS)
        limit_request_body_nesting(monkeypatch)
        rejected = await client.post(_LOGIN, content=body, headers=_JSON_HEADERS)

        assert accepted.status_code == 422
        assert [error["type"] for error in accepted.json()["errors"]] == ["string_type"]
        assert rejected.status_code == 422
        assert rejected.json() == _json_invalid(["body"])
        assert await redis_client.keys("login_attempts:*") == []

    async def test_rejection_precedes_authentication(self, client: AsyncClient) -> None:
        """Ticket creation requires a capability; this anonymous request
        would otherwise receive `401 AUTH_NOT_AUTHENTICATED`."""
        response = await client.post(
            "/api/v1/tickets",
            content=b'{"title": "fictional\xfftitle"}',
            headers=_JSON_HEADERS,
        )

        assert response.status_code == 422
        assert response.json() == _json_invalid(["body"])

    async def test_declared_field_deeper_than_the_recursion_limit_is_not_a_500(
        self, client: AsyncClient
    ) -> None:
        """The validation handler once encoded each error's `input` before
        projecting it and exceeded the interpreter recursion limit (`500
        INTERNAL_ERROR`). Whether or not the parser accepts this depth, the
        response is `422 VALIDATION_ERROR`, so only status and code are
        asserted."""
        depth = 2 * sys.getrecursionlimit()
        body = (
            '{"username": ' + "[" * depth + "]" * depth + ', "password": "irrelevant"}'
        )

        response = await client.post(_LOGIN, content=body, headers=_JSON_HEADERS)

        assert response.status_code == 422
        assert response.json()["code"] == "VALIDATION_ERROR"
