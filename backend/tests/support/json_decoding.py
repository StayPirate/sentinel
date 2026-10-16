"""Inputs and a parser replacement for External JSON Decoding tests.

`docs/conventions.md` (External JSON Decoding): the depth at which the
standard-library parser rejects nesting depends on the C stack of the
decoding thread, so no test may expect a real document to be accepted or
rejected because of its depth. `limit_parser_nesting()` replaces the parser
behind `decode_json()` with one that raises `RecursionError`, as the real
parser does for nesting beyond its limit, for every document containing
`NESTING_RUN`, and decodes any other document with the real parser. The
real `decode_json()` and each consumer's handling then run unchanged
(`docs/features/platform/testing-strategy.md`, External JSON Decoding).

The integer limit needs no replacement: the test session pins CPython's
default limit (`tests/conftest.py`), so `OVERSIZED_INTEGER` is rejected
whatever the environment.
"""

from __future__ import annotations

import json
import sys
from types import SimpleNamespace
from typing import Any, Final

import pytest

from app.services import json_decoding

NESTING_RUN: Final = "[" * 64
"""The run of `[` the replacement parser rejects; no fixture contains it."""

NESTED_ARRAY: Final = NESTING_RUN + "]" * len(NESTING_RUN)
"""A JSON value nested 64 levels deep: always accepted by the real parser,
rejected as too deep by the replacement."""

OVERSIZED_INTEGER: Final = "9" * (sys.int_info.default_max_str_digits + 1)
"""A JSON integer one digit beyond CPython's default conversion limit."""


def limit_parser_nesting(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make the parser behind `decode_json()` reject `NESTING_RUN` as nesting
    beyond its limit for the rest of the test."""

    def loads(document: str | bytes, **options: Any) -> Any:
        text = document if isinstance(document, str) else document.decode("latin-1")
        if NESTING_RUN in text:
            raise RecursionError("maximum recursion depth exceeded")
        return json.loads(document, **options)

    monkeypatch.setattr(json_decoding, "json", SimpleNamespace(loads=loads))
