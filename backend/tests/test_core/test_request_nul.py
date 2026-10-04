"""Tests for the app-wide U+0000 rejection dependency
(`backend/app/core/request_nul.py`).

See `docs/api-spec.md` (NUL Characters in Request Input) for the
authoritative contract and `docs/features/platform/testing-strategy.md`
(NUL Characters in Request Input) for the required matrix. A minimal
standalone FastAPI app (`_build_test_app()`) exercises the real dependency
through the ASGI/HTTP layer, mirroring `tests/test_core/test_query_limits.py`.
Registration on the real application is covered by
`tests/test_api/test_request_nul.py`.
"""

from __future__ import annotations

import json
from collections.abc import AsyncGenerator
from enum import StrEnum
from typing import Annotated, Any
from uuid import UUID

import pytest
from fastapi import Body, Depends, FastAPI, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from httpx import ASGITransport, AsyncClient
from pydantic import BaseModel

from app.core.query_limits import enforce_query_parameter_length_limit
from app.core.request_nul import _body_nul_errors, reject_nul_in_request_input

_NUL_POSITIONS = [
    pytest.param("\x00abc", id="start"),
    pytest.param("ab\x00c", id="middle"),
    pytest.param("abc\x00", id="end"),
    pytest.param("\x00", id="whole"),
]


def _error(*loc: str | int) -> dict[str, Any]:
    return {
        "loc": list(loc),
        "msg": "Value error, must not contain U+0000",
        "type": "value_error",
    }


class _Choice(StrEnum):
    ONE = "one"
    TWO = "two"


class _Inner(BaseModel):
    note: str


class _Payload(BaseModel):
    title: str
    tags: list[str] = []
    inner: _Inner | None = None
    settings: dict[str, Any] = {}


def _nested_query(owner: Annotated[str | None, Query()] = None) -> str | None:
    return owner


def _build_test_app() -> FastAPI:
    test_app = FastAPI(dependencies=[Depends(reject_nul_in_request_input)])

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

    @test_app.get("/items/{name}")
    async def read_by_name(
        name: str,
        owner: Annotated[str | None, Depends(_nested_query)],
        state: Annotated[_Choice | None, Query(alias="status")] = None,
        tag: Annotated[list[str] | None, Query()] = None,
        page: Annotated[int, Query()] = 1,
    ) -> dict[str, object]:
        return {"name": name}

    @test_app.get("/numbers/{number}/{uid}")
    async def read_by_number(number: int, uid: UUID) -> dict[str, object]:
        return {"number": number}

    @test_app.post("/payloads")
    async def create(payload: _Payload) -> dict[str, object]:
        return {"title": payload.title}

    @test_app.post("/raw")
    async def create_raw(payload: Annotated[Any, Body()]) -> dict[str, object]:
        return {"ok": True}

    return test_app


@pytest.fixture
async def nul_client() -> AsyncGenerator[AsyncClient]:
    async with AsyncClient(
        transport=ASGITransport(app=_build_test_app()), base_url="http://test"
    ) as client:
        yield client


@pytest.mark.unit
class TestRequestWithoutMatchedRoute:
    """Both shared request input dependencies are no-ops when the scope
    carries no matched `APIRoute`: there are no declared parameters to
    inspect, so even a U+0000 in the query string is not examined and no
    `RequestValidationError` is raised."""

    @staticmethod
    def _request() -> Request:
        return Request(
            {
                "type": "http",
                "method": "GET",
                "path": "/",
                "headers": [],
                "query_string": b"q=%00",
            }
        )

    async def test_nul_check_is_a_no_op(self) -> None:
        await reject_nul_in_request_input(self._request())

    async def test_query_length_limit_is_a_no_op(self) -> None:
        await enforce_query_parameter_length_limit(self._request())


@pytest.mark.unit
class TestBodyNulErrors:
    """The pure JSON-document walk."""

    def test_clean_document_has_no_errors(self) -> None:
        assert _body_nul_errors({"a": ["b", {"c": "d"}], "e": 1, "f": None}) == []

    def test_errors_are_in_document_order(self) -> None:
        body = {"a": "\x00", "b": ["ok", "\x00"], "c": {"d": "\x00"}}

        assert [error["loc"] for error in _body_nul_errors(body)] == [
            ("body", "a"),
            ("body", "b", 1),
            ("body", "c", "d"),
        ]

    def test_member_name_is_reported_at_its_object_without_inspecting_value(
        self,
    ) -> None:
        body = {"outer": {"bad\x00key": "\x00", "good": "ok"}}

        assert [error["loc"] for error in _body_nul_errors(body)] == [("body", "outer")]

    def test_member_name_errors_keep_document_order_among_sibling_values(
        self,
    ) -> None:
        body = {"a": {"b": "\x00"}, "c\x00": "v", "d": "\x00"}

        assert [error["loc"] for error in _body_nul_errors(body)] == [
            ("body", "a", "b"),
            ("body",),
            ("body", "d"),
        ]

    def test_top_level_string_body(self) -> None:
        assert [error["loc"] for error in _body_nul_errors("\x00")] == [("body",)]

    def test_non_string_scalars_are_ignored(self) -> None:
        assert _body_nul_errors([1, 2.5, True, None]) == []

    def test_deep_nesting_does_not_recurse(self) -> None:
        """An iterative walk handles nesting beyond the interpreter
        recursion limit."""
        body: Any = "\x00"
        for _ in range(5000):
            body = [body]

        errors = _body_nul_errors(body)

        assert len(errors) == 1
        assert errors[0]["loc"] == ("body",) + (0,) * 5000


@pytest.mark.e2e
class TestRejectNulInRequestInput:
    """End-to-end coverage through the real ASGI/HTTP layer (an HTTP
    client is required, so these are e2e despite touching no database)."""

    async def test_clean_request_passes(self, nul_client: AsyncClient) -> None:
        response = await nul_client.get(
            "/items/plain", params={"owner": "a", "status": "one", "tag": ["x"]}
        )

        assert response.status_code == 200

    @pytest.mark.parametrize("value", _NUL_POSITIONS)
    async def test_path_parameter(self, nul_client: AsyncClient, value: str) -> None:
        response = await nul_client.get(f"/items/{value.replace(chr(0), '%00')}")

        assert response.status_code == 422
        assert response.json()["errors"] == [_error("path", "name")]

    async def test_non_string_path_parameters_keep_type_validation(
        self, nul_client: AsyncClient
    ) -> None:
        response = await nul_client.get("/numbers/1%00/a%00b")

        assert response.status_code == 422
        types = {error["type"] for error in response.json()["errors"]}
        assert types == {"int_parsing", "uuid_parsing"}

    @pytest.mark.parametrize("value", _NUL_POSITIONS)
    async def test_query_parameter(self, nul_client: AsyncClient, value: str) -> None:
        response = await nul_client.get("/items/plain", params={"tag": value})

        assert response.status_code == 422
        assert response.json()["errors"] == [_error("query", "tag")]

    async def test_repeated_query_parameter_reports_each_occurrence(
        self, nul_client: AsyncClient
    ) -> None:
        response = await nul_client.get(
            "/items/plain", params=[("tag", "\x00"), ("tag", "ok"), ("tag", "x\x00")]
        )

        assert response.status_code == 422
        assert response.json()["errors"] == [
            _error("query", "tag"),
            _error("query", "tag"),
        ]

    async def test_aliased_enum_and_nested_query_parameters(
        self, nul_client: AsyncClient
    ) -> None:
        """A string enum filter is rejected rather than silently ignored,
        and a parameter declared by a nested dependency is discovered."""
        response = await nul_client.get(
            "/items/plain", params={"status": "one\x00", "owner": "\x00"}
        )

        assert response.status_code == 422
        assert response.json()["errors"] == [
            _error("query", "status"),
            _error("query", "owner"),
        ]

    async def test_undeclared_query_parameter_is_ignored(
        self, nul_client: AsyncClient
    ) -> None:
        response = await nul_client.get("/items/plain", params={"unknown": "\x00"})

        assert response.status_code == 200

    async def test_non_string_query_parameter_keeps_type_validation(
        self, nul_client: AsyncClient
    ) -> None:
        response = await nul_client.get("/items/plain", params={"page": "1\x00"})

        assert response.status_code == 422
        assert [error["type"] for error in response.json()["errors"]] == ["int_parsing"]

    @pytest.mark.parametrize("value", _NUL_POSITIONS)
    async def test_body_value(self, nul_client: AsyncClient, value: str) -> None:
        response = await nul_client.post("/payloads", json={"title": value})

        assert response.status_code == 422
        assert response.json()["errors"] == [_error("body", "title")]

    async def test_body_list_item_nested_value_member_name_and_undeclared_member(
        self, nul_client: AsyncClient
    ) -> None:
        response = await nul_client.post(
            "/payloads",
            json={
                "title": "ok",
                "tags": ["ok", "\x00"],
                "inner": {"note": "n\x00"},
                "settings": {"k\x00": "v"},
                "undeclared": "\x00",
            },
        )

        assert response.status_code == 422
        assert response.json()["errors"] == [
            _error("body", "tags", 1),
            _error("body", "inner", "note"),
            _error("body", "settings"),
            _error("body", "undeclared"),
        ]

    async def test_json_suffix_content_type_is_inspected(
        self, nul_client: AsyncClient
    ) -> None:
        response = await nul_client.post(
            "/payloads",
            content=json.dumps({"title": "\x00"}),
            headers={"content-type": "application/merge-patch+json"},
        )

        assert response.status_code == 422
        assert response.json()["errors"] == [_error("body", "title")]

    @pytest.mark.parametrize(
        "headers",
        [
            pytest.param({"content-type": "text/plain"}, id="text-plain"),
            pytest.param({}, id="no-content-type"),
        ],
    )
    async def test_body_not_decoded_as_json_is_not_inspected(
        self, nul_client: AsyncClient, headers: dict[str, str]
    ) -> None:
        """FastAPI keeps such a body as raw bytes; the dependency neither
        decodes it nor fails, and the schema rejects the bytes instead."""
        response = await nul_client.post(
            "/payloads", content=json.dumps({"title": "\x00"}), headers=headers
        )

        assert response.status_code == 422
        assert all(
            error["type"] != "value_error" for error in response.json()["errors"]
        )

    async def test_body_on_route_without_body_is_not_inspected(
        self, nul_client: AsyncClient
    ) -> None:
        response = await nul_client.request(
            "GET",
            "/items/plain",
            content=json.dumps({"title": "\x00"}),
            headers={"content-type": "application/json"},
        )

        assert response.status_code == 200

    async def test_top_level_body_string(self, nul_client: AsyncClient) -> None:
        response = await nul_client.post("/raw", json="\x00")

        assert response.status_code == 422
        assert response.json()["errors"] == [_error("body")]

    async def test_path_and_query_violations_are_reported_together(
        self, nul_client: AsyncClient
    ) -> None:
        response = await nul_client.get("/items/a%00", params={"tag": "\x00"})

        assert response.status_code == 422
        assert response.json()["errors"] == [
            _error("path", "name"),
            _error("query", "tag"),
        ]

    async def test_offending_value_is_not_echoed(self, nul_client: AsyncClient) -> None:
        marker = "fictional-secret-marker"
        response = await nul_client.post(
            "/payloads", json={"title": f"{marker}\x00", f"{marker}\x00": "v"}
        )

        assert response.status_code == 422
        assert marker not in response.text
