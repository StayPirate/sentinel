"""Tests for the external JSON decoding boundary
(backend/app/services/json_decoding.py) and the JSON decoding test support
(tests/support/json_decoding.py), including its request-body parser
replacement.

Owning convention: docs/conventions.md (External JSON Decoding); mandatory
scenario: docs/features/platform/testing-strategy.md (External JSON
Decoding). No case depends on the depth the real parser accepts: a
`RecursionError` is raised while parsing through a hook, and the nested
input of the support module is shallow enough for any parser.
"""

from __future__ import annotations

import json
import sys
from typing import Any, NoReturn

import pytest
from starlette.requests import Request

from app.services.json_decoding import JSONNestingError, decode_json
from tests.support.json_decoding import (
    NESTED_ARRAY,
    NESTING_RUN,
    OVERSIZED_INTEGER,
    limit_parser_nesting,
    limit_request_body_nesting,
)

pytestmark = pytest.mark.unit


def _raise_recursion(_: object) -> NoReturn:
    raise RecursionError("maximum recursion depth exceeded")


class TestDecodeJson:
    @pytest.mark.parametrize(
        "document", ['{"a": [1, 2.5, "x", null]}', b'{"a": [1, 2.5, "x", null]}']
    )
    def test_valid_document_decodes_from_text_and_bytes(
        self, document: str | bytes
    ) -> None:
        assert decode_json(document) == {"a": [1, 2.5, "x", None]}

    def test_bytes_keep_the_parser_encoding_detection(self) -> None:
        assert decode_json('{"a": 1}'.encode("utf-16")) == {"a": 1}

    def test_options_reach_the_parser(self) -> None:
        pairs: list[list[tuple[str, Any]]] = []
        constants: list[str] = []

        def object_pairs_hook(members: list[tuple[str, Any]]) -> dict[str, Any]:
            pairs.append(members)
            return dict(members)

        def parse_constant(name: str) -> str:
            constants.append(name)
            return name

        value = decode_json(
            '{"a": 1, "a": NaN}',
            object_pairs_hook=object_pairs_hook,
            parse_constant=parse_constant,
        )

        assert value == {"a": "NaN"}
        assert pairs == [[("a", 1), ("a", "NaN")]]
        assert constants == ["NaN"]

    def test_without_options_constants_are_the_parser_defaults(self) -> None:
        value = decode_json("[NaN]")

        assert isinstance(value[0], float)

    @pytest.mark.parametrize(
        ("document", "error"),
        [
            pytest.param("{", json.JSONDecodeError, id="syntax"),
            pytest.param("", json.JSONDecodeError, id="empty"),
            pytest.param(b'"\x80"', UnicodeDecodeError, id="invalid-utf-8"),
            pytest.param(
                '{"n": ' + OVERSIZED_INTEGER + "}", ValueError, id="integer-limit"
            ),
        ],
    )
    def test_every_decoding_failure_is_a_value_error(
        self, document: str | bytes, error: type[ValueError]
    ) -> None:
        with pytest.raises(error) as raised:
            decode_json(document)

        assert type(raised.value) is error
        assert isinstance(raised.value, ValueError)

    def test_value_error_from_a_hook_propagates(self) -> None:
        def parse_constant(_: str) -> NoReturn:
            raise ValueError("non-standard JSON constant")

        with pytest.raises(ValueError, match="non-standard JSON constant"):
            decode_json("[Infinity]", parse_constant=parse_constant)

    def test_recursion_error_while_parsing_becomes_json_nesting_error(self) -> None:
        with pytest.raises(JSONNestingError) as raised:
            decode_json('{"a": {}}', object_pairs_hook=_raise_recursion)

        assert isinstance(raised.value, ValueError)
        assert str(raised.value) == "JSON nesting exceeds the parser's limit"
        assert raised.value.__cause__ is None
        assert raised.value.__suppress_context__

    def test_memory_error_propagates(self) -> None:
        def object_pairs_hook(_: object) -> NoReturn:
            raise MemoryError

        with pytest.raises(MemoryError):
            decode_json('{"a": 1}', object_pairs_hook=object_pairs_hook)


class TestSupport:
    def test_integer_limit_is_pinned_to_the_default(self) -> None:
        assert sys.get_int_max_str_digits() == sys.int_info.default_max_str_digits

    def test_real_parser_accepts_the_nested_array(self) -> None:
        value = decode_json(NESTED_ARRAY)

        for _ in range(len(NESTING_RUN) - 1):
            value = value[0]
        assert value == []

    @pytest.mark.parametrize(
        "document",
        [
            '{"x": ' + NESTED_ARRAY + "}",
            ('{"x": ' + NESTED_ARRAY + "}").encode(),
            NESTING_RUN,
        ],
        ids=["text", "bytes", "unterminated"],
    )
    def test_limited_parser_rejects_the_nesting_run(
        self, monkeypatch: pytest.MonkeyPatch, document: str | bytes
    ) -> None:
        limit_parser_nesting(monkeypatch)

        with pytest.raises(JSONNestingError):
            decode_json(document)

    def test_limited_parser_decodes_other_documents_with_their_options(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        limit_parser_nesting(monkeypatch)
        shallow = "[" * (len(NESTING_RUN) - 1) + "]" * (len(NESTING_RUN) - 1)

        assert decode_json('{"a": 1, "a": 2}', object_pairs_hook=list) == [
            ("a", 1),
            ("a", 2),
        ]
        assert decode_json(shallow.encode()) is not None


def _request_with_body(body: bytes) -> Request:
    async def receive() -> dict[str, Any]:
        return {"type": "http.request", "body": body, "more_body": False}

    return Request({"type": "http", "method": "POST", "headers": []}, receive)


class TestRequestBodySupport:
    async def test_limited_request_body_parser_rejects_the_nesting_run(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        limit_request_body_nesting(monkeypatch)

        with pytest.raises(RecursionError):
            await _request_with_body(('{"x": ' + NESTED_ARRAY + "}").encode()).json()

    async def test_limited_request_body_parser_decodes_other_bodies(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        limit_request_body_nesting(monkeypatch)

        assert await _request_with_body(b'{"a": [1, "x"]}').json() == {"a": [1, "x"]}
