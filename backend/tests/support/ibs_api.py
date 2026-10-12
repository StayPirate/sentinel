"""Shared IBS API fixtures, a signature verifier, and a fake IBS API server.

The documents under `backend/tests/fixtures/ibs/` were captured read-only
from the IBS API (`https://api.suse.de`) on 2026-10-12 with
`secbox osc -A https://api.suse.de api ...` and are stored exactly as served
(docs/conventions.md, External Integration Contract Verification;
docs/features/packages/ibs-track-release-detection.md, External Contract
Verification). `responses.json` records the method, path, ordered query,
and status of each request. All requests targeted
`SUSE:SLE-15-SP6:Update`:

- `sourceinfo_single_linked.xml`: targeted source info for one linked
  package (`openssh`): the root is `sourceinfolist` also for one requested
  package; the entry has `srcmd5`, a distinct `lsrcmd5`, and a `linked`
  child.
- `sourceinfo_multiple.xml`: three repeatable `package` parameters: two
  linked packages, one of them with an `originproject` child that Sentinel
  does not consume, and the fictional package `sentinel-nonexistent-pkg`,
  which IBS does not omit: its entry carries an `<error>` child, no
  checksum, and `linked` children.
- `diff_first_observation.xml`: an expanded diff from `orev=0` (`sudo`):
  `old rev="0"`, multi-CVE, with `cve`, `bnc`, `fate`, and `jsc` trackers.
- `diff_added_changed.xml`: an incremental expanded diff (`libxml2`) with
  `added` and `changed` issues of the `cve` and `bnc` trackers.
- `diff_deleted.xml`: the reverse of an incremental diff (`sudo`), which
  reports `deleted` `cve` and `bnc` issues.
- `diff_empty.xml`: a diff between identical revisions: a valid
  `sourcediff` without an `issues` element.

Every issue carries `state`, `tracker`, `name`, `label`, and an `url`
attribute that Sentinel does not consume. The documents contain public
package, project, checksum, CVE, and bug identifiers only; no personal
identifier was present, so nothing was replaced. The checksums are public
source-state identifiers. Response headers were not observable through
`osc api`, so the media type is not recorded; Sentinel does not consume it.

The `unauthenticated` entry of `responses.json` restates the sanitized
401 challenge recorded in docs/features/integrations/ibs-integration.md
(Authentication Contract Verification Status); the fake server below
answers unauthenticated requests the same way.

`IBSServer` is an `httpx.MockTransport` handler that serves scripted
responses under `TEST_API_URL`, challenges unauthenticated requests,
verifies signatures with `verify_signature_header()` (an implementation
independent of the production signer), issues a session cookie after a
successful signed request, and records every request.

Consumers: `tests/test_services/test_ibs_api_contract.py`,
`tests/test_services/test_ibs_signature_auth.py`, and
`tests/test_services/test_ibs_client.py`.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import struct
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final

import httpx
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

FIXTURE_DIR: Final = Path(__file__).resolve().parents[1] / "fixtures" / "ibs"
LIVE_PROJECT: Final = "SUSE:SLE-15-SP6:Update"
LIVE_REALM: Final = "Use your developer account"
LIVE_CHALLENGE: Final = f'Signature realm="{LIVE_REALM}",headers="(created)"'

TEST_API_URL: Final = "https://api.ibs.example.test"
TEST_HOST: Final = "api.ibs.example.test"
SESSION_COOKIE_NAME: Final = "IBS_session"

SOURCEINFO_FIXTURES: Final = ("sourceinfo_single_linked", "sourceinfo_multiple")
DIFF_FIXTURES: Final = (
    "diff_first_observation",
    "diff_added_changed",
    "diff_deleted",
    "diff_empty",
)


def load_fixture(name: str) -> bytes:
    """The bytes of fixture `name` (without the `.xml` suffix)."""
    return (FIXTURE_DIR / f"{name}.xml").read_bytes()


def load_responses() -> dict[str, Any]:
    """The parsed `responses.json`."""
    data: dict[str, Any] = json.loads(
        (FIXTURE_DIR / "responses.json").read_text(encoding="utf-8")
    )
    return data


def fixture_query(name: str) -> list[tuple[str, str]]:
    """The ordered query of the live request that produced fixture `name`."""
    record = load_responses()["documents"][f"{name}.xml"]
    return [(key, value) for key, value in record["query"]]


# ---------------------------------------------------------------------------
# Signature verification (independent of app.services.ibs_signature_auth)
# ---------------------------------------------------------------------------

_HEADER: Final = re.compile(
    r'Signature keyId="(?P<key_id>[^"\\]*)",algorithm="ssh",'
    r'headers="\(created\)",created=(?P<created>0|[1-9][0-9]*),'
    r'signature="(?P<signature>[A-Za-z0-9+/]+={0,2})"'
)


@dataclass(frozen=True)
class VerifiedSignature:
    key_id: str
    created: int


class SignatureVerificationError(AssertionError):
    """The `Authorization` value is not a valid signature for the key."""


def _read_string(blob: bytes, offset: int) -> tuple[bytes, int]:
    if offset + 4 > len(blob):
        raise SignatureVerificationError("truncated SSH string")
    (length,) = struct.unpack(">I", blob[offset : offset + 4])
    end = offset + 4 + length
    if end > len(blob):
        raise SignatureVerificationError("truncated SSH string")
    return blob[offset + 4 : end], end


def _ssh_string(value: bytes) -> bytes:
    return struct.pack(">I", len(value)) + value


def verify_signature_header(
    value: str, *, public_key: Ed25519PublicKey, realm: str
) -> VerifiedSignature:
    """Verify one `Authorization` value against PROTOCOL.sshsig.

    Checks the exact header form, the SSHSIG v1 envelope (magic, version,
    the signer's public key, namespace = `realm`, empty reserved field,
    `sha512`, an `ssh-ed25519` signature), and the Ed25519 signature over
    the SHA-512 digest of `(created): <created>`.
    """
    match = _HEADER.fullmatch(value)
    if match is None:
        raise SignatureVerificationError("unexpected Authorization form")
    blob = base64.b64decode(match["signature"], validate=True)
    if base64.b64encode(blob).decode("ascii") != match["signature"]:
        raise SignatureVerificationError("non-canonical base64")
    if blob[:6] != b"SSHSIG":
        raise SignatureVerificationError("bad magic")
    (version,) = struct.unpack(">I", blob[6:10])
    offset = 10
    public_blob, offset = _read_string(blob, offset)
    namespace, offset = _read_string(blob, offset)
    reserved, offset = _read_string(blob, offset)
    hash_algorithm, offset = _read_string(blob, offset)
    signature_blob, offset = _read_string(blob, offset)
    if version != 1 or offset != len(blob):
        raise SignatureVerificationError("bad envelope")
    raw_public = public_key.public_bytes_raw()
    if public_blob != _ssh_string(b"ssh-ed25519") + _ssh_string(raw_public):
        raise SignatureVerificationError("unexpected public key")
    if namespace != realm.encode("ascii") or reserved or hash_algorithm != b"sha512":
        raise SignatureVerificationError("unexpected namespace or hash")
    algorithm, inner = _read_string(signature_blob, 0)
    raw_signature, inner = _read_string(signature_blob, inner)
    if algorithm != b"ssh-ed25519" or inner != len(signature_blob):
        raise SignatureVerificationError("unexpected signature algorithm")
    message = f"(created): {match['created']}".encode("ascii")
    signed = (
        b"SSHSIG"
        + _ssh_string(namespace)
        + _ssh_string(b"")
        + _ssh_string(b"sha512")
        + _ssh_string(hashlib.sha512(message).digest())
    )
    try:
        public_key.verify(raw_signature, signed)
    except InvalidSignature:
        raise SignatureVerificationError("signature does not verify") from None
    return VerifiedSignature(key_id=match["key_id"], created=int(match["created"]))


# ---------------------------------------------------------------------------
# Fake IBS API server
# ---------------------------------------------------------------------------

Responder = Callable[[httpx.Request], httpx.Response]


def xml_response(document: bytes, status: int = 200) -> Responder:
    """Serve `document` with `status`; the body is unread, as from a real
    transport."""

    def respond(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            status,
            headers={"content-type": "application/xml"},
            stream=_Chunks([document]),
        )

    return respond


def chunked_response(chunks: list[bytes], *, fail_after: bool = False) -> Responder:
    """Serve `chunks` lazily, optionally failing after the last one as an
    interrupted body does."""

    def respond(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, stream=_Chunks(chunks, fail_after=fail_after))

    return respond


def status_response(status: int, body: bytes = b"") -> Responder:
    def respond(_: httpx.Request) -> httpx.Response:
        return httpx.Response(status, stream=_Chunks([body]))

    return respond


class _Chunks(httpx.AsyncByteStream):
    def __init__(self, chunks: list[bytes], *, fail_after: bool = False) -> None:
        self._chunks = chunks
        self._fail_after = fail_after

    async def __aiter__(self) -> Any:
        for chunk in self._chunks:
            yield chunk
        if self._fail_after:
            raise httpx.RemoteProtocolError("peer closed connection mid-body")

    async def aclose(self) -> None:
        return None


@dataclass
class IBSServer:
    """Scripted IBS API under `TEST_API_URL` with the live authentication
    behavior: unauthenticated requests receive HTTP 401 with `challenges`;
    a request carrying a verifiable signature, or an issued session cookie,
    is served from `routes` keyed by `(method, decoded path)`. `intercept`,
    when set, may answer (or raise for) a request before authentication.
    `requests` holds header snapshots in arrival order."""

    public_key: Ed25519PublicKey
    realm: str = LIVE_REALM
    username: str = "jdoe"
    challenges: list[str] = field(default_factory=lambda: [LIVE_CHALLENGE])
    issue_session: bool = True
    reject_signatures: bool = False
    intercept: Callable[[httpx.Request], httpx.Response | None] | None = None
    routes: dict[tuple[str, str], Responder] = field(default_factory=dict)
    requests: list[httpx.Request] = field(default_factory=list)
    signatures: list[VerifiedSignature] = field(default_factory=list)
    sessions: set[str] = field(default_factory=set)
    _issued: int = 0

    def route(self, method: str, path: str, responder: Responder) -> None:
        self.routes[(method, path)] = responder

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handle)

    def handle(self, request: httpx.Request) -> httpx.Response:
        # A snapshot: the authentication flow mutates and resends the same
        # request object.
        self.requests.append(
            httpx.Request(
                request.method, request.url, headers=list(request.headers.raw)
            )
        )
        if self.intercept is not None:
            intercepted = self.intercept(request)
            if intercepted is not None:
                return intercepted
        session = self._session(request)
        authorization = request.headers.get("authorization")
        set_cookie: str | None = None
        if session is None:
            if authorization is None or self.reject_signatures:
                return self._challenge()
            try:
                verified = verify_signature_header(
                    authorization, public_key=self.public_key, realm=self.realm
                )
            except SignatureVerificationError:
                return self._challenge()
            if verified.key_id != self.username:
                return self._challenge()
            self.signatures.append(verified)
            if self.issue_session:
                self._issued += 1
                token = f"fictional-session-{self._issued:04d}"
                self.sessions.add(token)
                set_cookie = f"{SESSION_COOKIE_NAME}={token}; Path=/; Secure; HttpOnly"
        responder = self.routes.get((request.method, request.url.path))
        if responder is None:
            response = httpx.Response(404, stream=_Chunks([b'<status code="404"/>']))
        else:
            response = responder(request)
        if set_cookie is not None:
            response.headers["set-cookie"] = set_cookie
        return response

    def expire_sessions(self) -> None:
        self.sessions.clear()

    def _session(self, request: httpx.Request) -> str | None:
        header: str | None = request.headers.get("cookie")
        if header is None:
            return None
        for part in header.split(";"):
            name, _, value = part.strip().partition("=")
            if name == SESSION_COOKIE_NAME and value in self.sessions:
                return value
        return None

    def _challenge(self) -> httpx.Response:
        headers = [("www-authenticate", value) for value in self.challenges]
        headers.append(("content-type", "text/html"))
        return httpx.Response(
            401, headers=headers, stream=_Chunks([b"<html>fictional</html>"])
        )
