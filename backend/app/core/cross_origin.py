"""Cross-origin request protection.

See `docs/features/identity/authentication.md` (Cross-Origin Request
Protection) for the authoritative contract and `docs/api-spec.md`
(Cross-Origin Request Protection) for its place in request handling:
every request whose method is not `GET`, `HEAD`, or `OPTIONS` that a
browser sends for a page of an origin that is neither the API's own nor a
configured browser client receives `403 AUTH_CROSS_ORIGIN_REJECTED`, before
routing and every other outcome. `SameSite=Strict` does not withhold the
session cookie from a page on another host of the same site, so this is the
defense against request forgery from such pages.

The decision (`cross_origin_rejection()`) is a pure function;
`CrossOriginProtectionMiddleware` applies it as raw ASGI middleware, which
`app.main` registers inside `RequestIDMiddleware`, so a rejection carries
the request's `X-Request-ID` and its log record the `request_id`, and
outside everything that routes the request or reads its body. The trusted
origins are passed in by `app.main` (`CORS_ORIGINS`), because Core does not
import `app.config`.
"""

from __future__ import annotations

import re
import string
from collections.abc import Collection
from enum import StrEnum
from typing import TYPE_CHECKING, Final

import structlog
from starlette.responses import JSONResponse

from app.core.errors import ErrorCode

if TYPE_CHECKING:
    from starlette.types import ASGIApp, Receive, Scope, Send

logger = structlog.get_logger(__name__)

SAFE_METHODS: Final = frozenset({"GET", "HEAD", "OPTIONS"})
"""The methods the protection never rejects; every other method is unsafe."""

REJECTION_DETAIL: Final = "Cross-origin request not allowed."

_ACCEPTED_SEC_FETCH_SITE: Final = frozenset({"same-origin", "none"})

# A serialized origin: `scheme "://" host [":" port]`, with a non-empty host
# (a bracketed IPv6 literal or a name without `:`), and no user
# information, path (not even `/`), query, fragment, whitespace, or control
# character. `authority` is the part compared with `Host`.
_SERIALIZED_ORIGIN: Final = re.compile(
    r"[A-Za-z][A-Za-z0-9+.\-]*://"
    r"(?P<authority>"
    r"(?:\[[^\s\x00-\x1f\x7f/?#@\[\]]+\]|[^\s\x00-\x1f\x7f:/?#@\[\]]+)"
    r"(?::[0-9]+)?"
    r")"
)

_ASCII_LOWERCASE: Final = str.maketrans(string.ascii_uppercase, string.ascii_lowercase)

_ORIGIN_HEADER: Final = b"origin"
_SEC_FETCH_SITE_HEADER: Final = b"sec-fetch-site"
_HOST_HEADER: Final = b"host"


class CrossOriginRejectionReason(StrEnum):
    """The `reason` of a `cross_origin_request_rejected` record: the
    decision rule that rejected the request."""

    SEC_FETCH_SITE = "sec_fetch_site"
    ORIGIN = "origin"


def cross_origin_rejection(
    method: str,
    *,
    origin: str | None,
    sec_fetch_site: str | None,
    host: str | None,
    trusted_origins: Collection[str],
) -> CrossOriginRejectionReason | None:
    """Decide whether a request is rejected, and by which rule.

    Q1: `method` is the request method; `origin`, `sec_fetch_site`, and
    `host` are the first occurrence of the `Origin`, `Sec-Fetch-Site`, and
    `Host` request headers, or `None` when absent; `trusted_origins` are the
    `CORS_ORIGINS` entries.

    Q3: returns `None` (accept) for a `SAFE_METHODS` method. Otherwise
    applies the rules of authentication.md (Cross-Origin Request
    Protection, Decision) in order:

    1. `origin` equals a trusted origin exactly: accept.
    2. `sec_fetch_site` is present and not empty: accept when it is exactly
       `same-origin` or `none`, otherwise reject with `SEC_FETCH_SITE`.
    3. `origin` is absent or empty: accept.
    4. Accept when `origin` is a serialized origin whose host, with its
       port when stated, equals `host` compared ASCII case-insensitively;
       otherwise, including for `null` and an absent `host`, reject with
       `ORIGIN`. The scheme is not compared.

    Q6: infallible — never raises.
    """
    if method in SAFE_METHODS:
        return None
    if origin and origin in trusted_origins:
        return None
    if sec_fetch_site:
        if sec_fetch_site in _ACCEPTED_SEC_FETCH_SITE:
            return None
        return CrossOriginRejectionReason.SEC_FETCH_SITE
    if not origin:
        return None
    match = _SERIALIZED_ORIGIN.fullmatch(origin)
    if (
        match is not None
        and host is not None
        and match["authority"].translate(_ASCII_LOWERCASE)
        == host.translate(_ASCII_LOWERCASE)
    ):
        return None
    return CrossOriginRejectionReason.ORIGIN


def _decision_headers(scope: Scope) -> tuple[str | None, str | None, str | None]:
    """The first `Origin`, `Sec-Fetch-Site`, and `Host` header values of the
    request, decoded one character per octet as Starlette decodes them."""
    found: dict[bytes, str] = {}
    for name, value in scope.get("headers", []):
        lowered = name.lower()
        if lowered in (_ORIGIN_HEADER, _SEC_FETCH_SITE_HEADER, _HOST_HEADER):
            found.setdefault(lowered, value.decode("latin-1"))
    return (
        found.get(_ORIGIN_HEADER),
        found.get(_SEC_FETCH_SITE_HEADER),
        found.get(_HOST_HEADER),
    )


class CrossOriginProtectionMiddleware:
    """Pure ASGI middleware rejecting forged cross-origin unsafe requests.

    A rejected request never reaches the wrapped application: its body is
    not read, and no route, credential, or operation is evaluated. It
    receives the standard error envelope with `403
    AUTH_CROSS_ORIGIN_REJECTED` and emits one `cross_origin_request_rejected`
    WARNING carrying only `method` and `reason`; neither header value, the
    path, nor any credential is logged (authentication.md, Cross-Origin
    Request Protection, Rejection).
    """

    def __init__(self, app: ASGIApp, *, trusted_origins: Collection[str]) -> None:
        self.app = app
        self.trusted_origins = frozenset(trusted_origins)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http":
            origin, sec_fetch_site, host = _decision_headers(scope)
            reason = cross_origin_rejection(
                scope["method"],
                origin=origin,
                sec_fetch_site=sec_fetch_site,
                host=host,
                trusted_origins=self.trusted_origins,
            )
            if reason is not None:
                logger.warning(
                    "cross_origin_request_rejected",
                    method=scope["method"],
                    reason=reason.value,
                )
                response = JSONResponse(
                    status_code=403,
                    content={
                        "code": ErrorCode.AUTH_CROSS_ORIGIN_REJECTED.value,
                        "detail": REJECTION_DETAIL,
                    },
                )
                await response(scope, receive, send)
                return
        await self.app(scope, receive, send)
