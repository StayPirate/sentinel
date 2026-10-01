"""Literal SQL `LIKE`/`ILIKE` pattern construction.

Single owner of the escaping that makes a user-supplied search term match
literally inside a `LIKE` or `ILIKE` pattern, as required wherever a
specification declares that `%`, `_`, and backslash are literal characters
rather than SQL pattern syntax (for example `docs/features/tickets/tickets.md`,
Search; `docs/features/tickets/ticket-audit-log.md`, List Ticket Events;
`docs/features/packages/package-service.md`, `search_packages()`).

Callers escape the term with `escape_like()`, add their own `%` wildcards
for the match shape they need (substring or prefix), and pass
`escape=LIKE_ESCAPE` to `ilike()`/`like()`.

This module imports nothing from the application, so every service can use
it without a dependency cycle. Pure: no I/O.
"""

from __future__ import annotations

from typing import Final

LIKE_ESCAPE: Final = "\\"
"""The escape character declared with every pattern built from
`escape_like()` (`ESCAPE '\\'`)."""


def escape_like(term: str) -> str:
    """Escape `term` so it matches literally in a `LIKE` pattern.

    Q1: `term` is any string, typically an already normalized search term.

    Q3: prefixes each backslash, `%`, and `_` with `LIKE_ESCAPE`.
    Backslash is escaped first, so the escapes added for `%` and `_` are
    not themselves doubled. Adds no wildcard.

    Q4: returns the escaped string; an empty term returns an empty string.
    Infallible.
    """
    return (
        term.replace(LIKE_ESCAPE, LIKE_ESCAPE * 2)
        .replace("%", f"{LIKE_ESCAPE}%")
        .replace("_", f"{LIKE_ESCAPE}_")
    )
