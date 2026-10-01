"""Pure validation and normalization of Ticket reference URLs.

Implements `docs/features/tickets/ticket-references.md` (URL Boundary >
URL Normalization) steps 1-6, shared by the Pydantic request schemas and
by `reference_service` (manual references now, automatic ingestion
later). A URL is URI identifier syntax: the algorithm is purely lexical
and performs no DNS lookup, address resolution, request, TLS handshake,
or other outbound operation (Security and Privacy).

The value is split with the RFC 3986 Appendix B decomposition applied to
the raw string. The standard-library `urlsplit()` is deliberately not
used: it strips leading whitespace and C0 characters (which would
silently repair the input, contradicting step 1) and `urlunsplit()`
drops an empty trailing `?` or `#` (which would alter the query or
fragment, contradicting step 5). The normalized value is therefore
rebuilt from the lowercased scheme and host, the literal port, and the
literal remainder of the raw string.

The accepted authority grammar (step 3) is:

- a host that is either an ASCII RFC 3986 `reg-name` (unreserved
  characters, percent-encoded triplets, sub-delimiters; no IDNA
  conversion and no percent-decoding), where a host made only of digits
  and dots must be a valid dotted-quad IPv4 address, or a bracketed IPv6
  literal that is a valid IPv6 address with no zone identifier and no
  IPvFuture form;
- an optional port of one to five digits not exceeding 65535.

Any user-information component is rejected.
"""

from __future__ import annotations

import ipaddress
import re
from enum import StrEnum
from typing import Final

MAX_REFERENCE_URL_LENGTH: Final = 2048
"""Maximum URL length before and after normalization (`VARCHAR(2048)`)."""


class ReferenceUrlRejection(StrEnum):
    """Closed URL rejection categories.

    The URL subset of the bounded reason vocabulary in
    ticket-references.md (Automatic Rejection Logging). The remaining
    category of that vocabulary, `invalid_metadata`, concerns titles and
    descriptions and is not produced here.
    """

    URL_NOT_STRING = "url_not_string"
    URL_EMPTY = "url_empty"
    URL_TOO_LONG = "url_too_long"
    CONTROL_CHARACTER = "control_character"
    INVALID_URL = "invalid_url"
    INVALID_SCHEME = "invalid_scheme"
    INVALID_HOST = "invalid_host"
    USERINFO_FORBIDDEN = "userinfo_forbidden"


_MESSAGES: Final[dict[ReferenceUrlRejection, str]] = {
    ReferenceUrlRejection.URL_NOT_STRING: "URL must be a string.",
    ReferenceUrlRejection.URL_EMPTY: "URL must not be empty.",
    ReferenceUrlRejection.URL_TOO_LONG: "URL must be at most 2048 characters.",
    ReferenceUrlRejection.CONTROL_CHARACTER: "URL must not contain control characters.",
    ReferenceUrlRejection.INVALID_URL: "URL must be a well-formed absolute URL.",
    ReferenceUrlRejection.INVALID_SCHEME: "URL scheme must be http or https.",
    ReferenceUrlRejection.INVALID_HOST: "URL must have a valid host.",
    ReferenceUrlRejection.USERINFO_FORBIDDEN: "URL must not contain user information.",
}


class ReferenceUrlError(ValueError):
    """A reference URL violates the URL boundary.

    `reason` is one closed `ReferenceUrlRejection` category. The message
    is fixed per category and never contains any part of the rejected
    value, so it is safe to surface in a `422` body or a log record.
    """

    def __init__(self, reason: ReferenceUrlRejection) -> None:
        super().__init__(_MESSAGES[reason])
        self.reason = reason


# RFC 3986 Appendix B, matched against the whole string. Group 1 is the
# scheme, group 2 the `//authority` marker, group 3 the authority, and
# the remainder (path, query, fragment) starts where group 3 ends. Every
# string without a line break matches; line breaks are control
# characters and are rejected first.
_URI_PARTS: Final = re.compile(
    r"(?:([^:/?#]+):)?(//([^/?#]*))?[^?#]*(?:\?[^#]*)?(?:#.*)?", re.DOTALL
)

# Any C0 control character or DEL (step 2).
_CONTROL_CHARACTER: Final = re.compile(r"[\x00-\x1f\x7f]")

# RFC 3986 `reg-name`: unreserved / pct-encoded / sub-delims, ASCII only.
_REG_NAME: Final = re.compile(
    r"(?:[A-Za-z0-9\-._~!$&'()*+,;=]|%[0-9A-Fa-f]{2})+", re.ASCII
)

_DIGITS_AND_DOTS: Final = re.compile(r"[0-9.]+", re.ASCII)

_PORT: Final = re.compile(r"[0-9]{1,5}", re.ASCII)

_MAX_PORT: Final = 65535

_ACCEPTED_SCHEMES: Final = frozenset({"http", "https"})


def normalize_reference_url(value: object) -> str:
    """Validate `value` and return its normalized reference URL.

    The result is the stored URL, the input to URL-pattern
    classification, and the `(ticket_id, url)` identity. Normalization
    lowercases the scheme and host, replaces `http` with `https`, and
    removes only the slash of an otherwise empty root path; it preserves
    an explicit port, every non-root path (including a trailing slash),
    the query, and the fragment literally. The input is never trimmed or
    otherwise repaired. Normalizing an already normalized value returns
    it unchanged.

    Pure: no outbound operation and no side effects.

    Raises:
        ReferenceUrlError: the value violates the URL boundary; `reason`
            identifies the closed rejection category.
    """
    if not isinstance(value, str):
        raise ReferenceUrlError(ReferenceUrlRejection.URL_NOT_STRING)
    normalized = _normalize(value)
    # Step 6: post-normalization length, then the scheme, host,
    # user-information, and control-character invariants, rechecked by
    # running the same algorithm over the result.
    if len(normalized) > MAX_REFERENCE_URL_LENGTH:
        raise ReferenceUrlError(ReferenceUrlRejection.URL_TOO_LONG)
    _normalize(normalized)
    return normalized


def _normalize(value: str) -> str:
    """Steps 1-5 over one string; raises `ReferenceUrlError`."""
    # Step 1: at least one character; no trimming.
    if not value:
        raise ReferenceUrlError(ReferenceUrlRejection.URL_EMPTY)
    # Step 2: pre-parse length and control characters.
    if len(value) > MAX_REFERENCE_URL_LENGTH:
        raise ReferenceUrlError(ReferenceUrlRejection.URL_TOO_LONG)
    if _CONTROL_CHARACTER.search(value) is not None:
        raise ReferenceUrlError(ReferenceUrlRejection.CONTROL_CHARACTER)

    # Step 3: absolute http(s) URL with a valid authority.
    parts = _URI_PARTS.fullmatch(value)
    assert parts is not None  # the decomposition matches every string
    if parts.group(1) is None:
        # Without a scheme the value is a relative reference, not an
        # absolute URL.
        raise ReferenceUrlError(ReferenceUrlRejection.INVALID_URL)
    scheme = parts.group(1).lower()
    if scheme not in _ACCEPTED_SCHEMES:
        raise ReferenceUrlError(ReferenceUrlRejection.INVALID_SCHEME)
    authority = parts.group(3)
    if parts.group(2) is None or not authority:
        raise ReferenceUrlError(ReferenceUrlRejection.INVALID_HOST)
    if "@" in authority:
        raise ReferenceUrlError(ReferenceUrlRejection.USERINFO_FORBIDDEN)
    host, port = _split_authority(authority)

    # Steps 4 and 5: lowercase scheme and host, upgrade http, and drop
    # only the slash of an otherwise empty root path.
    remainder = value[parts.end(3) :]
    if remainder == "/" or remainder.startswith(("/?", "/#")):
        remainder = remainder[1:]
    port_part = f":{port}" if port is not None else ""
    return f"https://{host.lower()}{port_part}{remainder}"


def _split_authority(authority: str) -> tuple[str, str | None]:
    """Split a userinfo-free authority into a validated host and port."""
    if authority.startswith("["):
        closing = authority.find("]")
        if closing == -1:
            raise ReferenceUrlError(ReferenceUrlRejection.INVALID_HOST)
        host = authority[: closing + 1]
        _validate_ipv6_literal(authority[1:closing])
        rest = authority[closing + 1 :]
    else:
        host, separator, port_text = authority.partition(":")
        _validate_reg_name(host)
        rest = separator + port_text
    if not rest:
        return host, None
    if not rest.startswith(":"):
        raise ReferenceUrlError(ReferenceUrlRejection.INVALID_HOST)
    port = rest[1:]
    if _PORT.fullmatch(port) is None or int(port) > _MAX_PORT:
        raise ReferenceUrlError(ReferenceUrlRejection.INVALID_URL)
    return host, port


def _validate_reg_name(host: str) -> None:
    if _REG_NAME.fullmatch(host) is None:
        raise ReferenceUrlError(ReferenceUrlRejection.INVALID_HOST)
    if _DIGITS_AND_DOTS.fullmatch(host) is not None:
        try:
            ipaddress.IPv4Address(host)
        except ValueError:
            raise ReferenceUrlError(ReferenceUrlRejection.INVALID_HOST) from None


def _validate_ipv6_literal(literal: str) -> None:
    # A zone identifier (`%`) and the IPvFuture form (`v...`) are rejected
    # before parsing: `ipaddress` would otherwise accept a scope ID.
    if not literal or "%" in literal or literal[0] in "vV":
        raise ReferenceUrlError(ReferenceUrlRejection.INVALID_HOST)
    try:
        ipaddress.IPv6Address(literal)
    except ValueError:
        raise ReferenceUrlError(ReferenceUrlRejection.INVALID_HOST) from None
