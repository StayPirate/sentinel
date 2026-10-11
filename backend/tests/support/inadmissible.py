"""Inadmissible characters for admissibility tests.

`docs/conventions.md` (External String Admissibility) and
`docs/api-spec.md` (Inadmissible Characters in Request Input) reject
U+0000 and every surrogate code point. `docs/features/platform/
testing-strategy.md` requires each consumer test to supply both, so tests
parametrize over `INADMISSIBLE_CHARACTERS`.

A string containing a surrogate code point has no UTF-8 encoding, so it
cannot pass through `httpx`'s `json=` argument (which encodes with
`ensure_ascii=False`). `json_bytes()` serializes with JSON escapes
instead, as an upstream service sending `"\\ud800"` would.
"""

from __future__ import annotations

import json
from typing import Any, Final

import pytest

NUL: Final = "\x00"
"""U+0000."""

# Built with `chr()` rather than a literal: mypy cannot serialize a
# `Final` literal type containing a surrogate into its UTF-8 cache.
SURROGATE: Final = chr(0xD800)
"""A lone high surrogate code point (U+D800)."""

INADMISSIBLE_CHARACTERS: Final = [
    pytest.param(NUL, id="nul"),
    pytest.param(SURROGATE, id="surrogate"),
]
"""Parametrization over every inadmissible character, as `character`."""

REQUEST_INPUT_ERROR: Final = {
    "msg": "Value error, must not contain U+0000 or a surrogate code point",
    "type": "value_error",
}
"""The `msg`/`type` of an `errors` entry for an inadmissible character."""


def json_bytes(document: Any) -> bytes:
    """`document` as JSON bytes with non-ASCII characters escaped, so a
    surrogate code point travels as its `\\uXXXX` escape."""
    return json.dumps(document).encode("ascii")
