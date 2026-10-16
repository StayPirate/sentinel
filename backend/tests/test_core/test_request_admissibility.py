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
import tracemalloc
from collections.abc import AsyncGenerator, Callable
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
    _first_body_violation,
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
# A body reports only its first offending string, so each body input kind
# beyond a plain value is sent on its own, after an admissible `title`.
_BODY_INPUT_KINDS = [
    pytest.param(lambda c: {"tags": ["ok", c]}, ("body", "tags", 1), id="list-item"),
    pytest.param(
        lambda c: {"inner": {"note": f"n{c}"}},
        ("body", "inner", "note"),
        id="nested-value",
    ),
    pytest.param(
        lambda c: {"settings": {f"k{c}": "v"}}, ("body", "settings"), id="member-name"
    ),
    pytest.param(
        lambda c: {"undeclared": c}, ("body", "undeclared"), id="undeclared-member"
    ),
]
_ENCODED_SURROGATE_BODIES = [
    pytest.param(b'{"title": "a\xed\xa0\x80"}', ("body", "title"), id="value"),
    pytest.param(
        b'{"title": "ok", "tags": ["ok", "\xed\xa0\x80"]}',
        ("body", "tags", 1),
        id="list-item",
    ),
    pytest.param(
        b'{"title": "ok", "inner": {"note": "n\xed\xa0\x80"}}',
        ("body", "inner", "note"),
        id="nested-value",
    ),
    pytest.param(
        b'{"title": "ok", "settings": {"k\xed\xa0\x80": "v"}}',
        ("body", "settings"),
        id="member-name",
    ),
    pytest.param(
        b'{"title": "ok", "undeclared": "\xed\xa0\x80"}',
        ("body", "undeclared"),
        id="undeclared-member",
    ),
]


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
class TestFirstBodyViolation:
    """The pure JSON-document walk."""

    def test_clean_document_has_no_violation(self) -> None:
        body = {"a": ["b", {"c": "d"}], "e": 1, "f": None}

        assert _first_body_violation(body) is None

    def test_supplementary_characters_are_admissible(self) -> None:
        body = {"a\U0001f600": ["\U0001f600", "\U0010ffff"]}

        assert _first_body_violation(body) is None

    @pytest.mark.parametrize("character", INADMISSIBLE_CHARACTERS)
    def test_first_violation_in_document_order_is_located(self, character: str) -> None:
        body = {"a": "ok", "b": ["ok", {"c": character}], "d": character}

        assert _first_body_violation(body) == ("body", "b", 1, "c")

    @pytest.mark.parametrize("character", INADMISSIBLE_CHARACTERS)
    def test_member_name_is_located_at_its_object_before_its_value(
        self, character: str
    ) -> None:
        body = {"a": "ok", "outer": {"good": "ok", f"bad{character}key": character}}

        assert _first_body_violation(body) == ("body", "outer")

    @pytest.mark.parametrize("character", INADMISSIBLE_CHARACTERS)
    def test_earlier_value_precedes_a_later_member_name(self, character: str) -> None:
        body = {"a": {"b": character}, f"c{character}": "v"}

        assert _first_body_violation(body) == ("body", "a", "b")

    @pytest.mark.parametrize("character", INADMISSIBLE_CHARACTERS)
    def test_top_level_string_body(self, character: str) -> None:
        assert _first_body_violation(character) == ("body",)

    def test_high_then_low_surrogate_code_points_are_rejected(self) -> None:
        """Two surrogate code points, e.g. CESU-8 bytes decoded with
        `surrogatepass`, are inadmissible although `jsonb` would merge
        them into one character."""
        body = json.loads(b'["\xed\xa0\xbd\xed\xb8\x80"]')

        assert _first_body_violation(body) == ("body", 0)

    def test_non_string_scalars_are_ignored(self) -> None:
        assert _first_body_violation([1, 2.5, True, None, [], {}]) is None

    def test_deep_nesting_does_not_recurse(self) -> None:
        """An iterative walk handles nesting beyond the interpreter
        recursion limit."""
        body: Any = "\x00"
        for _ in range(5000):
            body = [body]

        assert _first_body_violation(body) == ("body",) + (0,) * 5000

    def test_memory_does_not_grow_with_width_times_depth(self) -> None:
        """Regression: a walk that keeps a copy of its path for every
        pending value holds width x depth path elements at once, about
        31 MiB for this body, and needs quadratic time on a deep chain.
        This walk keeps memory linear in the depth (well under 1 MiB
        here). Traced memory, unlike timing, is machine-independent, and
        the body is built without the JSON decoder, so its accepted depth
        does not matter."""
        body: Any = ["ok"] * 2000
        for _ in range(2000):
            body = [body]

        started = not tracemalloc.is_tracing()
        if started:
            tracemalloc.start()
        try:
            tracemalloc.reset_peak()
            baseline = tracemalloc.get_traced_memory()[0]
            assert _first_body_violation(body) is None
            peak = tracemalloc.get_traced_memory()[1] - baseline
        finally:
            if started:
                tracemalloc.stop()

        assert peak < 4 * 1024 * 1024


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
    @pytest.mark.parametrize(("members", "loc"), _BODY_INPUT_KINDS)
    async def test_body_list_item_nested_value_member_name_and_undeclared_member(
        self,
        checked_client: AsyncClient,
        members: Callable[[str], dict[str, Any]],
        loc: tuple[str | int, ...],
        character: str,
    ) -> None:
        response = await checked_client.post(
            "/payloads",
            content=json_bytes({"title": "ok", **members(character)}),
            headers=_JSON_HEADERS,
        )

        assert response.status_code == 422
        assert response.json()["errors"] == [_error(*loc)]

    @pytest.mark.parametrize("character", INADMISSIBLE_CHARACTERS)
    async def test_body_reports_only_its_first_violation(
        self, checked_client: AsyncClient, character: str
    ) -> None:
        """However many offending strings follow, at whatever depth, the
        body contributes one entry, at the first in document order."""
        deep: Any = [character] * 100
        for _ in range(100):
            deep = [deep, character]
        response = await checked_client.post(
            "/payloads",
            content=json_bytes(
                {
                    "title": "ok",
                    "tags": ["ok", character, *[character] * 1000],
                    "settings": {f"k{character}": deep},
                    "undeclared": character,
                }
            ),
            headers=_JSON_HEADERS,
        )

        assert response.status_code == 422
        assert response.json()["errors"] == [_error("body", "tags", 1)]

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

    @pytest.mark.parametrize(("content", "loc"), _ENCODED_SURROGATE_BODIES)
    async def test_surrogate_encoded_in_the_body_bytes_is_rejected(
        self,
        checked_client: AsyncClient,
        content: bytes,
        loc: tuple[str | int, ...],
    ) -> None:
        """The standard-library decoder turns the UTF-8-style bytes of a
        surrogate into a surrogate code point (`surrogatepass`), in every
        body input kind."""
        response = await checked_client.post(
            "/payloads", content=content, headers=_JSON_HEADERS
        )

        assert response.status_code == 422
        assert response.json()["errors"] == [_error(*loc)]

    async def test_surrogate_encoded_in_a_top_level_body_string_is_rejected(
        self, checked_client: AsyncClient
    ) -> None:
        response = await checked_client.post(
            "/raw", content=b'"\xed\xa0\x80"', headers=_JSON_HEADERS
        )

        assert response.status_code == 422
        assert response.json()["errors"] == [_error("body")]

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
        name = response.json()["name"]
        assert name.startswith("a\ufffd")
        assert not any("\ud800" <= c <= "\udfff" for c in name)

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
