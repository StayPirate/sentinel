"""Shared Bearer-over-cookie credential extraction.

See `docs/features/identity/authentication.md` (Authentication
Dependencies, Shared Credential Resolution) for the authoritative
precedence rule this function implements. It is a pure function (no
FastAPI/Starlette dependency) so it is directly unit-testable, and it is
shared by the logout endpoint and by the credential resolution of
`get_current_user`/`get_optional_current_user` (`app.api.dependencies`).
"""

from __future__ import annotations

# The fixed prefix identifying an API key credential (as opposed to a
# JWT) — see `docs/features/identity/api-key-management.md` ("the
# `stl_ak_` prefix lets the authentication boundary distinguish" a key
# from a JWT) and `docs/features/identity/authentication.md`,
# Shared Credential Resolution step 3.
API_KEY_PREFIX = "stl_ak_"


def extract_credential(authorization: str | None, cookie: str | None) -> str | None:
    """Resolve the single credential string to validate, or `None`.

    Q1: `authorization` is the raw `Authorization` header value (or
    `None` if absent); `cookie` is the raw `sentinel_session` cookie
    value (or `None` if absent).

    Q3: behavior for every case:

    1. If `authorization` is present and its scheme is `Bearer`
       (case-insensitive): if the extracted token value is non-empty
       after stripping whitespace, return it — this is the final
       credential; no cookie fallback occurs even if it later fails
       validation.
    2. Otherwise (no `Authorization` header, an empty/whitespace-only
       Bearer value, or a non-Bearer/unparseable scheme): fall back to
       `cookie`. Return it if present.
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
    if cookie:
        return cookie
    return None
