"""SSH-signature authentication for the IBS API.

Implements docs/features/integrations/ibs-integration.md (Request
Authentication, Session Reuse) as an `httpx.Auth` flow used by `IBSClient`:

1. the request is sent without an `Authorization` header (with the client
   instance's session cookie, if one is held);
2. any response other than HTTP 401 is the operation's response;
3. on HTTP 401 every session cookie is discarded and the `WWW-Authenticate`
   values are parsed as RFC 9110 (section 11.6.1) challenge lists. Only
   exactly one `Signature` challenge with a non-empty printable-ASCII
   `realm` and an absent or exact `(created)` `headers` parameter is
   answered; otherwise `IBSAuthenticationError("unsupported_challenge")`
   is raised without a further request. `Basic` and other schemes are
   never answered;
4. the same request is resent once with an SSHSIG signature (namespace =
   realm, `sha512`, `ssh-ed25519`) over `(created): <unix seconds>`. A
   second HTTP 401 raises `IBSAuthenticationError("signature_rejected")`.

Signing is in process with `cryptography`: no subprocess, agent, or key
file is involved. A transport retry of the signed attempt resends the same
request object, and therefore the same signature. Nothing here logs; the
exception never carries challenge content, the realm, the account name, or
response data.
"""

from __future__ import annotations

import base64
import hashlib
import string
import struct
from collections.abc import Callable, Generator
from dataclasses import dataclass
from typing import Final, Literal

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

AuthenticationFailureReason = Literal["unsupported_challenge", "signature_rejected"]

SIGNATURE_SCHEME: Final = "Signature"
SIGNED_HEADERS: Final = "(created)"

_MAGIC: Final = b"SSHSIG"
_SIGNATURE_VERSION: Final = 1
_HASH_ALGORITHM: Final = b"sha512"
_KEY_TYPE: Final = b"ssh-ed25519"

_TCHARS: Final = frozenset(string.ascii_letters + string.digits + "!#$%&'*+-.^_`|~")
_TOKEN68_CHARS: Final = frozenset(string.ascii_letters + string.digits + "-._~+/")
_WHITESPACE: Final = " \t"


class IBSAuthenticationError(Exception):
    """The IBS API rejected authentication for one operation.

    `reason` is `unsupported_challenge` (an HTTP 401 without exactly one
    supported `Signature` challenge) or `signature_rejected` (an HTTP 401 to
    the signed attempt). Not an `httpx` exception, and not retryable
    (docs/features/integrations/ibs-integration.md, Request Authentication).
    """

    def __init__(self, reason: AuthenticationFailureReason) -> None:
        super().__init__(f"IBS API authentication failed: {reason}")
        self.reason: AuthenticationFailureReason = reason


# ---------------------------------------------------------------------------
# Challenge parsing (RFC 9110, section 11.6.1)
# ---------------------------------------------------------------------------


class ChallengeSyntaxError(ValueError):
    """A `WWW-Authenticate` value is not a valid challenge list."""


@dataclass(frozen=True, slots=True)
class Challenge:
    """One parsed challenge. Parameter names are lowercased and quoted
    values unescaped; `token68` is set instead of parameters when the
    challenge carries a token68."""

    scheme: str
    parameters: tuple[tuple[str, str], ...] = ()
    token68: str | None = None


def parse_challenges(value: str) -> list[Challenge]:
    """Parse one `WWW-Authenticate` field value into its challenges.

    Several challenges may share one value, separated by commas, and empty
    list elements are allowed. Raises `ChallengeSyntaxError` for any value
    that does not follow the grammar.
    """
    parser = _ChallengeParser(value)
    return parser.parse()


class _ChallengeParser:
    def __init__(self, value: str) -> None:
        self._text = value
        self._end = len(value)
        self._position = 0

    def parse(self) -> list[Challenge]:
        challenges: list[Challenge] = []
        while True:
            self._skip(_WHITESPACE + ",")
            if self._position >= self._end:
                return challenges
            challenges.append(self._challenge())

    def _challenge(self) -> Challenge:
        scheme = self._token()
        if not scheme:
            raise ChallengeSyntaxError("expected an authentication scheme")
        start = self._position
        self._skip(_WHITESPACE)
        if self._position >= self._end or self._peek() == ",":
            return Challenge(scheme)
        if self._position == start:
            raise ChallengeSyntaxError("expected a space after the scheme")
        if self._at_parameter():
            return Challenge(scheme, parameters=self._parameters())
        return Challenge(scheme, token68=self._token68())

    def _parameters(self) -> tuple[tuple[str, str], ...]:
        parameters: list[tuple[str, str]] = []
        while True:
            name = self._token().lower()
            self._skip(_WHITESPACE)
            self._expect("=")
            self._skip(_WHITESPACE)
            if self._peek() == '"':
                value = self._quoted_string()
            else:
                value = self._token()
                if not value:
                    raise ChallengeSyntaxError("expected a parameter value")
            parameters.append((name, value))
            self._skip(_WHITESPACE)
            if self._position >= self._end:
                return tuple(parameters)
            self._expect(",")
            lookahead = self._position
            self._skip(_WHITESPACE + ",")
            if self._position < self._end and self._at_parameter():
                continue
            # The next list element starts another challenge (or the list
            # ends); the outer loop resumes after this comma.
            self._position = lookahead
            return tuple(parameters)

    def _token68(self) -> str:
        start = self._position
        while self._position < self._end and self._peek() in _TOKEN68_CHARS:
            self._position += 1
        if self._position == start:
            raise ChallengeSyntaxError("expected a token68 or a parameter")
        while self._position < self._end and self._peek() == "=":
            self._position += 1
        value = self._text[start : self._position]
        self._skip(_WHITESPACE)
        if self._position < self._end and self._peek() != ",":
            raise ChallengeSyntaxError("unexpected text after a token68")
        return value

    def _at_parameter(self) -> bool:
        """Whether `token BWS "=" BWS (token / quoted-string)` starts here.

        `abc=` or `abc==` followed by a delimiter is a token68, whose
        trailing `=` cannot start a parameter value.
        """
        position = self._position
        while position < self._end and self._text[position] in _TCHARS:
            position += 1
        if position == self._position:
            return False
        while position < self._end and self._text[position] in _WHITESPACE:
            position += 1
        if position >= self._end or self._text[position] != "=":
            return False
        position += 1
        while position < self._end and self._text[position] in _WHITESPACE:
            position += 1
        return position < self._end and (
            self._text[position] == '"' or self._text[position] in _TCHARS
        )

    def _quoted_string(self) -> str:
        self._expect('"')
        characters: list[str] = []
        while self._position < self._end:
            character = self._text[self._position]
            if character == '"':
                self._position += 1
                return "".join(characters)
            if character == "\\":
                if self._position + 1 >= self._end:
                    break
                escaped = self._text[self._position + 1]
                if not _is_quoted_pair_character(escaped):
                    raise ChallengeSyntaxError("invalid quoted-pair")
                characters.append(escaped)
                self._position += 2
                continue
            if not _is_qdtext(character):
                raise ChallengeSyntaxError("invalid character in a quoted string")
            characters.append(character)
            self._position += 1
        raise ChallengeSyntaxError("unterminated quoted string")

    def _token(self) -> str:
        start = self._position
        while self._position < self._end and self._peek() in _TCHARS:
            self._position += 1
        return self._text[start : self._position]

    def _skip(self, characters: str) -> None:
        while self._position < self._end and self._peek() in characters:
            self._position += 1

    def _expect(self, character: str) -> None:
        if self._position >= self._end or self._peek() != character:
            raise ChallengeSyntaxError(f"expected {character!r}")
        self._position += 1

    def _peek(self) -> str:
        return self._text[self._position]


def _is_qdtext(character: str) -> bool:
    code = ord(character)
    return (
        character in "\t "
        or code == 0x21
        or 0x23 <= code <= 0x5B
        or 0x5D <= code <= 0x7E
        or 0x80 <= code <= 0xFF
    )


def _is_quoted_pair_character(character: str) -> bool:
    code = ord(character)
    return character in "\t " or 0x21 <= code <= 0x7E or 0x80 <= code <= 0xFF


def select_signature_realm(response: httpx.Response) -> str:
    """Return the realm of the one supported `Signature` challenge.

    Examines every `WWW-Authenticate` value of `response`. Raises
    `IBSAuthenticationError("unsupported_challenge")` unless the values
    parse, exactly one challenge uses the `Signature` scheme
    (case-insensitive), its parameter names are distinct, its `realm` is
    non-empty printable ASCII (U+0020 to U+007E), and its `headers`
    parameter is absent or exactly `(created)`. Other challenges are
    ignored.
    """
    values = [
        raw_value.decode("latin-1")
        for raw_name, raw_value in response.headers.raw
        if raw_name.lower() == b"www-authenticate"
    ]
    try:
        challenges = [
            challenge for value in values for challenge in parse_challenges(value)
        ]
    except ChallengeSyntaxError:
        raise IBSAuthenticationError("unsupported_challenge") from None
    signature = [c for c in challenges if c.scheme.lower() == SIGNATURE_SCHEME.lower()]
    if len(signature) != 1 or signature[0].token68 is not None:
        raise IBSAuthenticationError("unsupported_challenge")
    names = [name for name, _ in signature[0].parameters]
    parameters = dict(signature[0].parameters)
    realm = parameters.get("realm", "")
    headers = parameters.get("headers", SIGNED_HEADERS)
    if (
        len(names) != len(parameters)
        or not realm
        or not all(0x20 <= ord(character) <= 0x7E for character in realm)
        or headers != SIGNED_HEADERS
    ):
        raise IBSAuthenticationError("unsupported_challenge")
    return realm


# ---------------------------------------------------------------------------
# SSHSIG signing (OpenSSH PROTOCOL.sshsig, version 1)
# ---------------------------------------------------------------------------


def _ssh_string(value: bytes) -> bytes:
    return struct.pack(">I", len(value)) + value


def sign_created(
    private_key: Ed25519PrivateKey, *, namespace: str, created: int
) -> str:
    """Return the padded base64 SSHSIG blob over `(created): <created>`.

    The blob has no armor lines or line breaks. `namespace` is the
    challenge realm; the hash algorithm is `sha512` and the signature
    algorithm `ssh-ed25519`.
    """
    message = f"(created): {created}".encode("ascii")
    namespace_bytes = namespace.encode("ascii")
    signed_data = (
        _MAGIC
        + _ssh_string(namespace_bytes)
        + _ssh_string(b"")
        + _ssh_string(_HASH_ALGORITHM)
        + _ssh_string(hashlib.sha512(message).digest())
    )
    public_key = private_key.public_key().public_bytes_raw()
    blob = (
        _MAGIC
        + struct.pack(">I", _SIGNATURE_VERSION)
        + _ssh_string(_ssh_string(_KEY_TYPE) + _ssh_string(public_key))
        + _ssh_string(namespace_bytes)
        + _ssh_string(b"")
        + _ssh_string(_HASH_ALGORITHM)
        + _ssh_string(
            _ssh_string(_KEY_TYPE) + _ssh_string(private_key.sign(signed_data))
        )
    )
    return base64.b64encode(blob).decode("ascii")


def build_authorization(
    *, username: str, private_key: Ed25519PrivateKey, realm: str, created: int
) -> str:
    """Return the `Authorization` value in the exact specified form.

    `username` must already satisfy the `IBS_USERNAME` contract (no `"` or
    `\\`), so it needs no escaping inside the quoted `keyId`.
    """
    signature = sign_created(private_key, namespace=realm, created=created)
    return (
        f'{SIGNATURE_SCHEME} keyId="{username}",algorithm="ssh",'
        f'headers="{SIGNED_HEADERS}",created={created},signature="{signature}"'
    )


class IBSSignatureAuth(httpx.Auth):
    """Reactive SSH-signature authentication for one `IBSClient` instance.

    `discard_cookies` clears the owning client's session cookies; it is
    called on every HTTP 401. `clock` returns the current Unix time.
    """

    requires_request_body = False
    requires_response_body = False

    def __init__(
        self,
        *,
        username: str,
        private_key: Ed25519PrivateKey,
        clock: Callable[[], float],
        discard_cookies: Callable[[], None],
    ) -> None:
        self._username = username
        self._private_key = private_key
        self._clock = clock
        self._discard_cookies = discard_cookies

    def __repr__(self) -> str:
        return f"{type(self).__name__}()"

    def auth_flow(
        self, request: httpx.Request
    ) -> Generator[httpx.Request, httpx.Response]:
        response = yield request
        if response.status_code != httpx.codes.UNAUTHORIZED:
            return
        self._discard_cookies()
        request.headers.pop("cookie", None)
        realm = select_signature_realm(response)
        request.headers["authorization"] = build_authorization(
            username=self._username,
            private_key=self._private_key,
            realm=realm,
            created=int(self._clock()),
        )
        response = yield request
        if response.status_code == httpx.codes.UNAUTHORIZED:
            self._discard_cookies()
            raise IBSAuthenticationError("signature_rejected")
