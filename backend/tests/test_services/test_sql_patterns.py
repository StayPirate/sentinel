"""Unit tests for the literal `LIKE` pattern helper (`app.services.sql_patterns`).

The searches of the Ticket list, the Ticket audit read, and the
cross-Ticket package search treat `%`, `_`, and backslash as literal
characters (docs/features/tickets/tickets.md, Search;
docs/features/tickets/ticket-audit-log.md, List Ticket Events;
docs/features/packages/package-service.md, `search_packages()`). Their
database behavior is covered by each consumer's integration tests; these
tests pin the escaping itself.
"""

from __future__ import annotations

import pytest

from app.services.sql_patterns import LIKE_ESCAPE, escape_like


@pytest.mark.unit
class TestEscapeLike:
    def test_escape_character_is_a_backslash(self) -> None:
        assert LIKE_ESCAPE == "\\"

    @pytest.mark.parametrize(
        ("term", "escaped"),
        [
            ("", ""),
            ("plain", "plain"),
            ("100%", "100\\%"),
            ("a_b", "a\\_b"),
            ("C:\\x", "C:\\\\x"),
            ("\\%", "\\\\\\%"),
            ("%_\\", "\\%\\_\\\\"),
        ],
    )
    def test_escapes_like_metacharacters_backslash_first(
        self, term: str, escaped: str
    ) -> None:
        assert escape_like(term) == escaped

    def test_adds_no_wildcard(self) -> None:
        assert escape_like("openssl") == "openssl"
