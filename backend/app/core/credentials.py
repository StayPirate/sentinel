"""Shared Bearer-over-cookie credential extraction.

See `docs/features/identity/authentication.md` (Session cookie; Authentication
Dependencies, Shared Credential Resolution) for the authoritative session
cookie reading and precedence rules these functions implement. They are pure
functions (no FastAPI/Starlette dependency) so they are directly
unit-testable, and they are shared by the logout endpoint and by the
credential resolution of `get_current_user`/`get_optional_current_user`
(`app.api.dependencies`).
"""

from __future__ import annotations

from typing import Final, final

# The fixed prefix identifying an API key credential (as opposed to a
# JWT) — see `docs/features/identity/api-key-management.md` ("the
# `stl_ak_` prefix lets the authentication boundary distinguish" a key
# from a JWT) and `docs/features/identity/authentication.md`,
# Shared Credential Resolution step 3.
API_KEY_PREFIX = "stl_ak_"

# The session cookie name (authentication.md, Session cookie). The `__Host-`
# prefix makes browsers accept the cookie only from the API host itself, so
# a page on a sibling host of the same site cannot plant one.
SESSION_COOKIE_NAME: Final = "__Host-sentinel_session"

# Only spaces and horizontal tabs surround a pair; any other character,
# including another whitespace octet such as 0x85 or 0xA0, is part of it.
_PAIR_PADDING: Final = " \t"


@final
class DuplicateSessionCookie:
    """The type of `DUPLICATE_SESSION_COOKIE`."""

    __slots__ = ()

    def __repr__(self) -> str:
        return "DUPLICATE_SESSION_COOKIE"


DUPLICATE_SESSION_COOKIE: Final = DuplicateSessionCookie()
"""The selected credential when the session cookie occurs more than once.

A browser that enforces the `__Host-` prefix sends at most one such cookie,
so a second one was planted. It is an invalid credential: callers reject it
with the generic 401 without credential type determination, lookup, or log
record (authentication.md, Shared Credential Resolution step 2)."""


def read_session_cookie(cookie_header: str | None) -> str | DuplicateSessionCookie:
    """Read the session cookie from the first `Cookie` request header field.

    Q1: `cookie_header` is the raw value of the first `Cookie` header field,
    as the server decoded it (one character per octet), or `None` when the
    request has none.

    Q3: splits the value on `;` into pairs and removes only the spaces and
    horizontal tabs around each pair. A pair's name is the text before its
    first `=`, compared exactly with `SESSION_COOKIE_NAME`, and its value
    the rest, returned without unquoting or other decoding; a segment
    without `=` has no name. Returns the value of the only matching pair,
    `""` when no pair matches (an absent cookie and an empty value select no
    credential alike), or `DUPLICATE_SESSION_COOKIE` when the name occurs
    more than once.

    Q6: infallible — never raises.
    """
    if not cookie_header:
        return ""
    values = [
        value
        for name, separator, value in (
            segment.strip(_PAIR_PADDING).partition("=")
            for segment in cookie_header.split(";")
        )
        if separator and name == SESSION_COOKIE_NAME
    ]
    if len(values) > 1:
        return DUPLICATE_SESSION_COOKIE
    return values[0] if values else ""


def extract_credential(
    authorization: str | None, cookie_header: str | None
) -> str | DuplicateSessionCookie | None:
    """Resolve the single credential to validate, or `None`.

    Q1: `authorization` is the raw `Authorization` header value (or
    `None` if absent); `cookie_header` is the raw value of the first
    `Cookie` header field (or `None` if absent), read by
    `read_session_cookie()`.

    Q3: behavior for every case:

    1. If `authorization` is present and its scheme is `Bearer`
       (case-insensitive): if the extracted token value is non-empty
       after stripping whitespace, return it — this is the final
       credential; the cookie is not read, and no cookie fallback occurs
       even if the token later fails validation.
    2. Otherwise (no `Authorization` header, an empty/whitespace-only
       Bearer value, or a non-Bearer/unparseable scheme): fall back to
       the session cookie. Return `DUPLICATE_SESSION_COOKIE` when it
       occurs more than once, otherwise its value when non-empty.
    3. If neither yields a credential, return `None`.

    Q6: infallible — never raises.
    """
    if authorization:
        parts = authorization.split(None, 1)
        if len(parts) == 2 and parts[0].lower() == "bearer":
            token = parts[1].strip()
            # Defensive: str.split(None, 1) never yields a `parts[1]` that
            # is empty or whitespace-only when len(parts) == 2 (a maximal
            # whitespace run is always consumed as the separator), so
            # `token` is always truthy here. Kept as defense-in-depth in
            # case the splitting logic above changes.
            if token:
                return token
    return read_session_cookie(cookie_header) or None
