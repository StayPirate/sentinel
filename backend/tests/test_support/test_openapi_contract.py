"""Tests for the OpenAPI response contract check
(`tests/support/openapi_contract.py`) and its session-wide installation on
the registered application (`openapi_response_contract` in
`tests/conftest.py`).

See docs/features/platform/testing-strategy.md (OpenAPI Response Contract
Check).
"""

from __future__ import annotations

from typing import Any

import pytest
from fastapi import FastAPI, Response
from fastapi.responses import JSONResponse, PlainTextResponse
from httpx import ASGITransport, AsyncClient
from pydantic import BaseModel

from app.core.errors import AppError, ErrorCode
from app.core.query_limits import enforce_query_parameter_length_limit
from app.main import app
from tests.support.openapi_contract import (
    ResponseContractCheck,
    _close_objects,
    response_contract_check,
)


class _Owner(BaseModel):
    name: str


class _Item(BaseModel):
    name: str
    owner: _Owner | None = None


class _Error(BaseModel):
    code: str
    detail: str


_ERROR: dict[str, Any] = {"code": "ITEM_NOT_FOUND", "detail": "No such item."}

# The response each `GET /items/{case}` returns.
_RESPONSES: dict[str, Any] = {
    "ok": JSONResponse({"name": "first", "owner": {"name": "someone"}}),
    "missing": JSONResponse(_ERROR, status_code=404),
    "no-content": Response(status_code=204),
    "undocumented-status": JSONResponse(_ERROR, status_code=409),
    "undocumented-member": JSONResponse({**_ERROR, "errors": []}, status_code=404),
    "undocumented-nested-member": JSONResponse(
        {"name": "first", "owner": {"name": "someone", "email": "x@example.com"}}
    ),
    "wrong-type": JSONResponse({"name": 1}),
    "wrong-media-type": PlainTextResponse("first"),
    "not-json": Response(b"{", status_code=404, media_type="application/json"),
}


def _build_app() -> FastAPI:
    """An application whose `GET /items/{case}` documents `200 _Item` and
    `404 _Error` and returns the response `_RESPONSES` maps `case` to."""
    test_app = FastAPI()

    @test_app.get(
        "/items/{case}",
        response_model=_Item,
        responses={404: {"model": _Error}, 204: {"description": "No content"}},
    )
    async def get_item(case: str) -> Any:
        if case == "crash":
            raise RuntimeError("simulated failure")
        return _RESPONSES[case]

    @test_app.get("/hidden", include_in_schema=False)
    async def hidden() -> Any:
        return PlainTextResponse("hidden", status_code=418)

    return test_app


async def _get(check_app: FastAPI, path: str) -> None:
    async with AsyncClient(
        transport=ASGITransport(app=check_app, raise_app_exceptions=False),
        base_url="http://test",
    ) as client:
        await client.get(path)


@pytest.mark.unit
class TestResponseContractCheck:
    @pytest.mark.parametrize("case", ["ok", "missing", "no-content"])
    async def test_documented_response_records_nothing(self, case: str) -> None:
        test_app = _build_app()
        with response_contract_check(test_app) as check:
            await _get(test_app, f"/items/{case}")

        assert check.violations == []

    @pytest.mark.parametrize(
        ("case", "reason"),
        [
            pytest.param(
                "undocumented-status",
                "returned 409, which is not documented",
                id="status",
            ),
            pytest.param(
                "undocumented-member",
                "at $: Additional properties are not allowed ('errors'",
                id="member",
            ),
            pytest.param(
                "undocumented-nested-member",
                "at $.owner: Additional properties are not allowed ('email'",
                id="nested-member",
            ),
            pytest.param(
                "wrong-type", "at $.name: 1 is not of type 'string'", id="type"
            ),
            pytest.param(
                "wrong-media-type",
                "returned 200 as 'text/plain', but it is documented as "
                "application/json",
                id="media-type",
            ),
            pytest.param("not-json", "with a body that is not JSON", id="not-json"),
        ],
    )
    async def test_undocumented_response_is_recorded(
        self, case: str, reason: str
    ) -> None:
        test_app = _build_app()
        with response_contract_check(test_app) as check:
            await _get(test_app, f"/items/{case}")

        assert len(check.violations) == 1
        assert check.violations[0].startswith(
            f"GET /items/{case} (operation GET /items/{{case}}) returned"
        )
        assert reason in check.violations[0]

    async def test_unhandled_exception_500_is_checked(self) -> None:
        """Starlette's `ServerErrorMiddleware` renders the `500` and then
        re-raises; the check sits outside it and still sees the response."""
        test_app = _build_app()
        with response_contract_check(test_app) as check:
            await _get(test_app, "/items/crash")

        assert len(check.violations) == 1
        assert "returned 500, which is not documented" in check.violations[0]

    async def test_debug_traceback_is_not_checked(self) -> None:
        test_app = _build_app()
        test_app.debug = True
        with response_contract_check(test_app) as check:
            await _get(test_app, "/items/crash")

        assert check.violations == []

    @pytest.mark.parametrize(
        "path",
        [
            pytest.param("/nowhere", id="unknown-path"),
            pytest.param("/items/ok/", id="trailing-slash-redirect"),
            pytest.param("/hidden", id="undocumented-route"),
            pytest.param("/openapi.json", id="openapi-document"),
        ],
    )
    async def test_request_selecting_no_documented_operation_is_not_checked(
        self, path: str
    ) -> None:
        test_app = _build_app()
        with response_contract_check(test_app) as check:
            await _get(test_app, path)

        assert check.violations == []

    async def test_wrong_method_is_not_checked(self) -> None:
        test_app = _build_app()
        with response_contract_check(test_app) as check:
            async with AsyncClient(
                transport=ASGITransport(app=test_app), base_url="http://test"
            ) as client:
                response = await client.post("/items/ok")

        assert response.status_code == 405
        assert check.violations == []

    async def test_check_survives_a_rebuilt_middleware_stack(self) -> None:
        """Tests reset `middleware_stack` to rebuild it after changing
        `app.debug`; the rebuilt stack is checked too."""
        test_app = _build_app()
        with response_contract_check(test_app) as check:
            await _get(test_app, "/items/ok")
            test_app.middleware_stack = None
            await _get(test_app, "/items/undocumented-status")

        assert len(check.violations) == 1

    async def test_nothing_is_checked_after_exit(self) -> None:
        test_app = _build_app()
        with response_contract_check(test_app) as check:
            await _get(test_app, "/items/ok")
        await _get(test_app, "/items/undocumented-status")

        assert check.violations == []


@pytest.mark.unit
class TestCloseObjects:
    def test_closes_object_schemas_at_every_level_but_not_property_maps(
        self,
    ) -> None:
        """A property may be named like a keyword (`properties`, `type`):
        the map of properties is never treated as a schema."""
        schema: dict[str, Any] = {
            "type": "object",
            "properties": {
                "properties": {
                    "type": "object",
                    "properties": {"type": {"type": "string"}},
                },
                "items": {"type": "array", "items": {"$ref": "#/x"}},
                "choice": {"anyOf": [{"properties": {}}, {"type": "null"}]},
                "free": {"type": "object", "additionalProperties": True},
            },
        }

        _close_objects(schema)

        assert schema == {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "properties": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {"type": {"type": "string"}},
                },
                "items": {"type": "array", "items": {"$ref": "#/x"}},
                "choice": {
                    "anyOf": [
                        {"properties": {}, "additionalProperties": False},
                        {"type": "null"},
                    ]
                },
                "free": {"type": "object", "additionalProperties": True},
            },
        }


async def _raise_teapot() -> None:
    raise AppError(status_code=418, code=ErrorCode.INTERNAL_ERROR, detail="Teapot.")


@pytest.mark.unit
class TestSessionInstallation:
    async def test_registered_application_is_checked(
        self, openapi_response_contract: ResponseContractCheck
    ) -> None:
        """Any client of the registered application is checked: an
        app-level dependency made to fail with an undocumented status on
        `GET /health` is recorded, without a database."""
        app.dependency_overrides[enforce_query_parameter_length_limit] = _raise_teapot
        try:
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as client:
                response = await client.get("/health")
        finally:
            del app.dependency_overrides[enforce_query_parameter_length_limit]
        violations = list(openapi_response_contract.violations)
        # The violation is the subject of this test, not a failure of it.
        openapi_response_contract.violations.clear()

        assert response.status_code == 418
        assert violations == [
            "GET /health (operation GET /health) returned 418, which is not "
            "documented (documented: 200)"
        ]
