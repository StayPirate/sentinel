"""Tests for the shared query-parameter length limit dependency
(`backend/app/core/query_limits.py`).

See `docs/api-spec.md` (Query Parameter Length Limit, Undeclared Query
Parameters) for the authoritative contract under test.

This work item introduces no domain endpoint for these tests — a
minimal standalone FastAPI app (`_build_test_app()`) exercises the real
dependency through the actual ASGI/HTTP layer, mirroring the pattern in
`tests/test_api/test_dependencies.py` (`_build_test_app()`).
"""

from __future__ import annotations

from collections.abc import AsyncGenerator
from enum import StrEnum
from typing import Annotated

import pytest
from fastapi import Depends, FastAPI, Query
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from httpx import ASGITransport, AsyncClient

from app.core.query_limits import enforce_query_parameter_length_limit


class _Choice(StrEnum):
    ONE = "one"
    TWO = "two"


def _flat_query(
    status: Annotated[str | None, Query()] = None,
    page: Annotated[int, Query(ge=1)] = 1,
    sort_by: Annotated[_Choice, Query()] = _Choice.ONE,
    *,
    tag: Annotated[list[str], Query(default_factory=list)],
) -> dict[str, object]:
    return {"status": status, "page": page, "sort_by": sort_by.value, "tag": tag}


def _nested_query(
    common: Annotated[dict[str, object], Depends(_flat_query)],
    owner: Annotated[str | None, Query()] = None,
) -> dict[str, object]:
    return {**common, "owner": owner}


def _build_test_app() -> FastAPI:
    test_app = FastAPI(dependencies=[Depends(enforce_query_parameter_length_limit)])

    @test_app.exception_handler(RequestValidationError)
    async def _validation_handler(
        request: object, exc: RequestValidationError
    ) -> JSONResponse:
        return JSONResponse(
            status_code=422,
            content={
                "code": "VALIDATION_ERROR",
                "detail": "Request validation failed",
                "errors": [
                    {"loc": list(e["loc"]), "msg": e["msg"], "type": e["type"]}
                    for e in exc.errors()
                ],
            },
        )

    @test_app.get("/flat")
    async def flat(
        query: Annotated[dict[str, object], Depends(_flat_query)],
    ) -> dict[str, object]:
        return query

    @test_app.get("/nested")
    async def nested(
        query: Annotated[dict[str, object], Depends(_nested_query)],
    ) -> dict[str, object]:
        return query

    @test_app.get("/no-query-params")
    async def no_query_params() -> dict[str, object]:
        return {"ok": True}

    return test_app


@pytest.fixture
def test_app() -> FastAPI:
    return _build_test_app()


@pytest.fixture
async def limit_client(test_app: FastAPI) -> AsyncGenerator[AsyncClient]:
    async with AsyncClient(
        transport=ASGITransport(app=test_app), base_url="http://test"
    ) as client:
        yield client


@pytest.mark.e2e
class TestEnforceQueryParameterLengthLimit:
    """End-to-end coverage through the real ASGI/HTTP layer — see
    module docstring for why these are e2e despite not touching the
    database: they require an HTTP client
    (`docs/features/platform/testing-strategy.md`, Tier 1 exclusion)."""

    async def test_declared_string_param_at_limit_is_accepted(
        self, limit_client: AsyncClient
    ) -> None:
        response = await limit_client.get("/flat", params={"status": "x" * 500})
        assert response.status_code == 200

    async def test_declared_string_param_over_limit_is_rejected(
        self, limit_client: AsyncClient
    ) -> None:
        response = await limit_client.get("/flat", params={"status": "x" * 501})
        assert response.status_code == 422
        body = response.json()
        assert body["code"] == "VALIDATION_ERROR"
        assert body["errors"] == [
            {
                "loc": ["query", "status"],
                "msg": "String should have at most 500 characters",
                "type": "string_too_long",
            }
        ]

    async def test_undeclared_param_over_limit_is_ignored(
        self, limit_client: AsyncClient
    ) -> None:
        response = await limit_client.get("/flat", params={"unknown": "x" * 9000})
        assert response.status_code == 200

    async def test_int_param_over_500_chars_is_exempt_from_the_string_limit(
        self, limit_client: AsyncClient
    ) -> None:
        """A numeric field is never checked by this dependency, even
        when its raw value is over 500 characters — Python integers
        have no length limit, so this 501-digit value is a perfectly
        valid `page`. Applying the string length limit here would
        incorrectly reject it (see `app.core.route_params.is_string_like`)."""
        response = await limit_client.get("/flat", params={"page": "1" * 501})
        assert response.status_code == 200

    async def test_enum_param_over_limit_is_rejected_as_string_too_long(
        self, limit_client: AsyncClient
    ) -> None:
        """A `StrEnum` field is string-shaped: an over-limit value is
        rejected by the length check before enum-membership validation
        even runs."""
        response = await limit_client.get("/flat", params={"sort_by": "x" * 501})
        assert response.status_code == 422
        assert response.json()["errors"][0]["type"] == "string_too_long"

    async def test_repeated_param_checks_each_occurrence_individually(
        self, limit_client: AsyncClient
    ) -> None:
        response = await limit_client.get(
            "/flat", params=[("status", "ok"), ("status", "x" * 501)]
        )
        assert response.status_code == 422
        assert response.json()["errors"][0]["loc"] == ["query", "status"]

    async def test_repeated_param_produces_one_error_per_over_limit_occurrence(
        self, limit_client: AsyncClient
    ) -> None:
        """Two over-limit occurrences of the same repeated parameter
        produce exactly two error entries — one per occurrence, not one
        per parameter name — proving the dependency does not
        short-circuit after the first violation (see
        `enforce_query_parameter_length_limit`, Q6: "one Pydantic-shaped
        error entry per over-limit occurrence")."""
        response = await limit_client.get(
            "/flat",
            params=[
                ("status", "x" * 501),
                ("status", "ok"),
                ("status", "y" * 600),
            ],
        )
        assert response.status_code == 422
        errors = response.json()["errors"]
        assert len(errors) == 2
        assert all(error["loc"] == ["query", "status"] for error in errors)
        assert all(error["type"] == "string_too_long" for error in errors)

    async def test_nested_dependency_field_is_discovered(
        self, limit_client: AsyncClient
    ) -> None:
        """`owner` is declared inside `_nested_query`, a sub-dependency
        of the route's own query builder — the recursive walk must
        still find it."""
        response = await limit_client.get("/nested", params={"owner": "x" * 501})
        assert response.status_code == 422
        assert response.json()["errors"][0]["loc"] == ["query", "owner"]

    async def test_route_with_no_query_params_is_a_no_op(
        self, limit_client: AsyncClient
    ) -> None:
        response = await limit_client.get(
            "/no-query-params", params={"anything": "x" * 9000}
        )
        assert response.status_code == 200

    async def test_no_query_string_at_all_is_a_no_op(
        self, limit_client: AsyncClient
    ) -> None:
        response = await limit_client.get("/flat")
        assert response.status_code == 200

    async def test_repeatable_list_param_each_occurrence_checked_individually(
        self, limit_client: AsyncClient
    ) -> None:
        """A `list[str]` query field (repeatable filter) is
        string-shaped: each raw occurrence is checked individually,
        matching the existing repeated-string-param behavior."""
        response = await limit_client.get(
            "/flat", params=[("tag", "ok"), ("tag", "x" * 501)]
        )
        assert response.status_code == 422
        assert response.json()["errors"][0]["loc"] == ["query", "tag"]

    async def test_repeatable_list_param_within_limit_is_accepted(
        self, limit_client: AsyncClient
    ) -> None:
        response = await limit_client.get(
            "/flat", params=[("tag", "a" * 500), ("tag", "b" * 500)]
        )
        assert response.status_code == 200

    async def test_repeatable_list_param_absent_is_a_no_op(
        self, limit_client: AsyncClient
    ) -> None:
        response = await limit_client.get("/flat")
        assert response.status_code == 200
        assert response.json()["tag"] == []
