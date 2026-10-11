"""Tests for the app-wide inadmissible-character rejection dependency
(`backend/app/core/request_admissibility.py`).

See `docs/api-spec.md` (Inadmissible Characters in Request Input) for the
authoritative contract and `docs/features/platform/testing-strategy.md`
(Inadmissible Characters in Request Input) for the required matrix: U+0000
in every input kind, and a surrogate code point in every body input kind,
both as an unpaired JSON escape and as its UTF-8-style encoding (path and
query parameters cannot carry one). A minimal standalone FastAPI app
(`_build_test_app()`) exercises the real dependency through the ASGI/HTTP
layer, mirroring `tests/test_core/test_query_limits.py`. Registration on the
real application is covered by `tests/test_api/test_request_admissibility.py`.
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
from app.core.request_admissibility import (
    _body_errors,
    reject_inadmissible_request_input,
)
from tests.support.inadmissible import (
    INADMISSIBLE_CHARACTERS,
    REQUEST_INPUT_ERROR,
    SURROGATE,
    json_bytes,
)

_NUL_POSITIONS = [
    pytest.param("\x00abc", id="start"),
    pytest.param("ab\x00c", id="middle"),
    pytest.param("abc\x00", id="end"),
    pytest.param("\x00", id="whole"),
]
_POSITIONS = [
    pytest.param("{c}abc", id="start"),
    pytest.param("ab{c}c", id="middle"),
    pytest.param("abc{c}", id="end"),
    pytest.param("{c}", id="whole"),
]
_JSON_HEADERS = {"content-type": "application/json"}


def _error(*loc: str | int) -> dict[str, Any]:
    return {"loc": list(loc), **REQUEST_INPUT_ERROR}


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
    test_app = FastAPI(dependencies=[Depends(reject_inadmissible_request_input)])

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
async def checked_client() -> AsyncGenerator[AsyncClient]:
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

    async def test_admissibility_check_is_a_no_op(self) -> None:
        await reject_inadmissible_request_input(self._request())

    async def test_query_length_limit_is_a_no_op(self) -> None:
        await enforce_query_parameter_length_limit(self._request())


@pytest.mark.unit
class TestBodyErrors:
    """The pure JSON-document walk."""

    def test_clean_document_has_no_errors(self) -> None:
        assert _body_errors({"a": ["b", {"c": "d"}], "e": 1, "f": None}) == []

    def test_supplementary_characters_are_admissible(self) -> None:
        assert _body_errors({"a\U0001f600": ["\U0001f600", "\U0010ffff"]}) == []

    @pytest.mark.parametrize("character", INADMISSIBLE_CHARACTERS)
    def test_errors_are_in_document_order(self, character: str) -> None:
        body = {"a": character, "b": ["ok", character], "c": {"d": character}}

        assert [error["loc"] for error in _body_errors(body)] == [
            ("body", "a"),
            ("body", "b", 1),
            ("body", "c", "d"),
        ]

    @pytest.mark.parametrize("character", INADMISSIBLE_CHARACTERS)
    def test_member_name_is_reported_at_its_object_without_inspecting_value(
        self, character: str
    ) -> None:
        body = {"outer": {f"bad{character}key": character, "good": "ok"}}

        assert [error["loc"] for error in _body_errors(body)] == [("body", "outer")]

    @pytest.mark.parametrize("character", INADMISSIBLE_CHARACTERS)
    def test_member_name_errors_keep_document_order_among_sibling_values(
        self, character: str
    ) -> None:
        body = {"a": {"b": character}, f"c{character}": "v", "d": character}

        assert [error["loc"] for error in _body_errors(body)] == [
            ("body", "a", "b"),
            ("body",),
            ("body", "d"),
        ]

    @pytest.mark.parametrize("character", INADMISSIBLE_CHARACTERS)
    def test_top_level_string_body(self, character: str) -> None:
        assert [error["loc"] for error in _body_errors(character)] == [("body",)]

    def test_high_then_low_surrogate_code_points_are_rejected(self) -> None:
        """Two surrogate code points, e.g. CESU-8 bytes decoded with
        `surrogatepass`, are inadmissible although `jsonb` would merge
        them into one character."""
        body = json.loads(b'["\xed\xa0\xbd\xed\xb8\x80"]')

        assert [error["loc"] for error in _body_errors(body)] == [("body", 0)]

    def test_non_string_scalars_are_ignored(self) -> None:
        assert _body_errors([1, 2.5, True, None]) == []

    def test_deep_nesting_does_not_recurse(self) -> None:
        """An iterative walk handles nesting beyond the interpreter
        recursion limit."""
        body: Any = "\x00"
        for _ in range(5000):
            body = [body]

        errors = _body_errors(body)

        assert len(errors) == 1
        assert errors[0]["loc"] == ("body",) + (0,) * 5000


@pytest.mark.e2e
class TestRejectInadmissibleRequestInput:
    """End-to-end coverage through the real ASGI/HTTP layer (an HTTP
    client is required, so these are e2e despite touching no database)."""

    async def test_clean_request_passes(self, checked_client: AsyncClient) -> None:
        response = await checked_client.get(
            "/items/plain", params={"owner": "a", "status": "one", "tag": ["x"]}
        )

        assert response.status_code == 200

    @pytest.mark.parametrize("value", _NUL_POSITIONS)
    async def test_path_parameter(
        self, checked_client: AsyncClient, value: str
    ) -> None:
        response = await checked_client.get(f"/items/{value.replace(chr(0), '%00')}")

        assert response.status_code == 422
        assert response.json()["errors"] == [_error("path", "name")]

    async def test_non_string_path_parameters_keep_type_validation(
        self, checked_client: AsyncClient
    ) -> None:
        response = await checked_client.get("/numbers/1%00/a%00b")

        assert response.status_code == 422
        types = {error["type"] for error in response.json()["errors"]}
        assert types == {"int_parsing", "uuid_parsing"}

    @pytest.mark.parametrize("value", _NUL_POSITIONS)
    async def test_query_parameter(
        self, checked_client: AsyncClient, value: str
    ) -> None:
        response = await checked_client.get("/items/plain", params={"tag": value})

        assert response.status_code == 422
        assert response.json()["errors"] == [_error("query", "tag")]

    async def test_repeated_query_parameter_reports_each_occurrence(
        self, checked_client: AsyncClient
    ) -> None:
        response = await checked_client.get(
            "/items/plain", params=[("tag", "\x00"), ("tag", "ok"), ("tag", "x\x00")]
        )

        assert response.status_code == 422
        assert response.json()["errors"] == [
            _error("query", "tag"),
            _error("query", "tag"),
        ]

    async def test_aliased_enum_and_nested_query_parameters(
        self, checked_client: AsyncClient
    ) -> None:
        """A string enum filter is rejected rather than silently ignored,
        and a parameter declared by a nested dependency is discovered."""
        response = await checked_client.get(
            "/items/plain", params={"status": "one\x00", "owner": "\x00"}
        )

        assert response.status_code == 422
        assert response.json()["errors"] == [
            _error("query", "status"),
            _error("query", "owner"),
        ]

    async def test_undeclared_query_parameter_is_ignored(
        self, checked_client: AsyncClient
    ) -> None:
        response = await checked_client.get("/items/plain", params={"unknown": "\x00"})

        assert response.status_code == 200

    async def test_non_string_query_parameter_keeps_type_validation(
        self, checked_client: AsyncClient
    ) -> None:
        response = await checked_client.get("/items/plain", params={"page": "1\x00"})

        assert response.status_code == 422
        assert [error["type"] for error in response.json()["errors"]] == ["int_parsing"]

    @pytest.mark.parametrize("character", INADMISSIBLE_CHARACTERS)
    @pytest.mark.parametrize("template", _POSITIONS)
    async def test_body_value(
        self, checked_client: AsyncClient, template: str, character: str
    ) -> None:
        response = await checked_client.post(
            "/payloads",
            content=json_bytes({"title": template.format(c=character)}),
            headers=_JSON_HEADERS,
        )

        assert response.status_code == 422
        assert response.json()["errors"] == [_error("body", "title")]

    @pytest.mark.parametrize("character", INADMISSIBLE_CHARACTERS)
    async def test_body_list_item_nested_value_member_name_and_undeclared_member(
        self, checked_client: AsyncClient, character: str
    ) -> None:
        response = await checked_client.post(
            "/payloads",
            content=json_bytes(
                {
                    "title": "ok",
                    "tags": ["ok", character],
                    "inner": {"note": f"n{character}"},
                    "settings": {f"k{character}": "v"},
                    "undeclared": character,
                }
            ),
            headers=_JSON_HEADERS,
        )

        assert response.status_code == 422
        assert response.json()["errors"] == [
            _error("body", "tags", 1),
            _error("body", "inner", "note"),
            _error("body", "settings"),
            _error("body", "undeclared"),
        ]

    async def test_json_suffix_content_type_is_inspected(
        self, checked_client: AsyncClient
    ) -> None:
        response = await checked_client.post(
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
        self, checked_client: AsyncClient, headers: dict[str, str]
    ) -> None:
        """FastAPI keeps such a body as raw bytes; the dependency neither
        decodes it nor fails, and the schema rejects the bytes instead."""
        response = await checked_client.post(
            "/payloads", content=json.dumps({"title": "\x00"}), headers=headers
        )

        assert response.status_code == 422
        assert all(
            error["type"] != "value_error" for error in response.json()["errors"]
        )

    async def test_body_on_route_without_body_is_not_inspected(
        self, checked_client: AsyncClient
    ) -> None:
        response = await checked_client.request(
            "GET",
            "/items/plain",
            content=json.dumps({"title": "\x00"}),
            headers={"content-type": "application/json"},
        )

        assert response.status_code == 200

    @pytest.mark.parametrize("character", INADMISSIBLE_CHARACTERS)
    async def test_top_level_body_string(
        self, checked_client: AsyncClient, character: str
    ) -> None:
        response = await checked_client.post(
            "/raw", content=json_bytes(character), headers=_JSON_HEADERS
        )

        assert response.status_code == 422
        assert response.json()["errors"] == [_error("body")]

    async def test_surrogate_encoded_in_the_body_bytes_is_rejected(
        self, checked_client: AsyncClient
    ) -> None:
        """The standard-library decoder turns the UTF-8-style bytes of a
        surrogate into a surrogate code point (`surrogatepass`)."""
        response = await checked_client.post(
            "/payloads",
            content=b'{"title": "ok", "tags": ["a\xed\xa0\x80b"]}',
            headers=_JSON_HEADERS,
        )

        assert response.status_code == 422
        assert response.json()["errors"] == [_error("body", "tags", 0)]

    async def test_paired_surrogate_escape_is_accepted(
        self, checked_client: AsyncClient
    ) -> None:
        """A correctly paired escape decodes to one supplementary
        character, which is admissible."""
        response = await checked_client.post(
            "/payloads",
            content=b'{"title": "a\\ud83d\\ude00b"}',
            headers=_JSON_HEADERS,
        )

        assert response.status_code == 200
        assert response.json() == {"title": "a\U0001f600b"}

    async def test_surrogate_member_name_does_not_break_the_response(
        self, checked_client: AsyncClient
    ) -> None:
        """A surrogate member name is never placed in a `loc`, which could
        not be rendered as UTF-8, even when its value is also offending."""
        response = await checked_client.post(
            "/payloads",
            content=json_bytes({"title": "ok", "settings": {SURROGATE: "\x00"}}),
            headers=_JSON_HEADERS,
        )

        assert response.status_code == 422
        assert response.json()["errors"] == [_error("body", "settings")]

    async def test_percent_encoded_surrogate_bytes_are_not_a_surrogate(
        self, checked_client: AsyncClient
    ) -> None:
        """Path and query parameters are percent-decoded as UTF-8 with
        replacement, so encoded surrogate bytes arrive as U+FFFD and
        cannot carry a surrogate code point."""
        response = await checked_client.get("/items/a%ED%A0%80?tag=%ED%A0%80")

        assert response.status_code == 200
        assert response.json() == {"name": "a\ufffd\ufffd\ufffd"}

    async def test_path_and_query_violations_are_reported_together(
        self, checked_client: AsyncClient
    ) -> None:
        response = await checked_client.get("/items/a%00", params={"tag": "\x00"})

        assert response.status_code == 422
        assert response.json()["errors"] == [
            _error("path", "name"),
            _error("query", "tag"),
        ]

    @pytest.mark.parametrize("character", INADMISSIBLE_CHARACTERS)
    async def test_offending_value_is_not_echoed(
        self, checked_client: AsyncClient, character: str
    ) -> None:
        marker = "fictional-secret-marker"
        response = await checked_client.post(
            "/payloads",
            content=json_bytes(
                {"title": f"{marker}{character}", f"{marker}{character}": "v"}
            ),
            headers=_JSON_HEADERS,
        )

        assert response.status_code == 422
        assert marker not in response.text
