"""The single decoding boundary for JSON received from outside the process.

Implements docs/conventions.md (External JSON Decoding). The
standard-library parser cannot represent two kinds of valid JSON text: it
rejects nesting deeper than its limit with `RecursionError`, at a depth
that depends on the remaining C stack of the decoding thread, and an
integer longer than the interpreter's integer-string conversion limit with
a plain `ValueError`. Both are invalid JSON, so `decode_json()` makes every
decoding failure a `ValueError`: `json.JSONDecodeError` (syntax),
`UnicodeDecodeError` (bytes that are not UTF-8, UTF-16, or UTF-32), the
integer-limit `ValueError`, a `ValueError` raised by a caller's hook, and
`JSONNestingError`.

The parser and its options are otherwise unchanged and no limit or check is
added: strict UTF-8, a byte order mark, the non-standard constants, and
duplicate members remain each caller's decision.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any


class JSONNestingError(ValueError):
    """The document nests deeper than the parser's limit.

    The fixed message carries no document content.
    """

    def __init__(self) -> None:
        super().__init__("JSON nesting exceeds the parser's limit")


def decode_json(
    document: str | bytes,
    *,
    object_pairs_hook: Callable[[list[tuple[str, Any]]], Any] | None = None,
    parse_constant: Callable[[str], Any] | None = None,
) -> Any:
    """Decode one JSON text with the standard-library parser.

    Pure. `document` and the hooks are passed to `json.loads()` unchanged,
    so `bytes` keep its UTF-8, UTF-16, and UTF-32 detection. Raises
    `ValueError` for every document the parser rejects or cannot represent,
    `JSONNestingError` for nesting beyond its limit; `MemoryError`
    propagates.
    """
    try:
        return json.loads(
            document,
            object_pairs_hook=object_pairs_hook,
            parse_constant=parse_constant,
        )
    except RecursionError:
        raise JSONNestingError from None
