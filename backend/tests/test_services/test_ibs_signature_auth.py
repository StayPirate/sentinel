"""Tests for the IBS API SSH-signature authentication.

Contract under test: docs/features/integrations/ibs-integration.md (Request
Authentication, Session Reuse). The challenge parser, the SSHSIG signer,
and the `Authorization` form are pure and tested here directly; the
reactive flow through a real `httpx.AsyncClient` (cookies, retries, and
the request counts) is tested in `test_ibs_client.py`.

The signer is checked two ways: against a known-answer vector produced
once by OpenSSH (`ssh-keygen -Y sign -n "Use your developer account"` over
`(created): 1700000000` with the fictional key of `tests/support/ibs_keys.py`;
Ed25519 signing is deterministic), and against the independent verifier in
`tests/support/ibs_api.py`.
"""

from __future__ import annotations

import base64
from collections.abc import Generator
from typing import Final

import httpx
import pytest

from app.services.ibs_signature_auth import (
    Challenge,
    ChallengeSyntaxError,
    IBSAuthenticationError,
    IBSSignatureAuth,
    build_authorization,
    parse_challenges,
    select_signature_realm,
    sign_created,
)
from tests.support.ibs_api import (
    LIVE_CHALLENGE,
    LIVE_REALM,
    SignatureVerificationError,
    verify_signature_header,
)
from tests.support.ibs_keys import fictional_ed25519_key

pytestmark = pytest.mark.unit

_CREATED: Final = 1700000000
_SSH_KEYGEN_SSHSIG: Final = (
    "U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAgfNcbtEV1UZvLSVo3wBJSFCkfYqsc"
    "6fXVxI4wLQeBTlsAAAAaVXNlIHlvdXIgZGV2ZWxvcGVyIGFjY291bnQAAAAAAAAABnNoYTUx"
    "MgAAAFMAAAALc3NoLWVkMjU1MTkAAABAoJQ8lP6yxbN2y5r991Kh4XiQgeiLn8yGeCLRAO2w"
    "QloDuKfqCjwxiejmxoFdGyL6l34NxzK5Dt/x3sL5ZFvUAw=="
)
"""`ssh-keygen -Y sign` output (armor and line breaks removed) for the
fictional key, namespace `LIVE_REALM`, and `(created): 1700000000`."""


def _response(*challenges: str, status: int = 401) -> httpx.Response:
    headers = [(b"WWW-Authenticate", value.encode("latin-1")) for value in challenges]
    return httpx.Response(status, headers=headers)


class TestParseChallenges:
    def test_live_challenge(self) -> None:
        assert parse_challenges(LIVE_CHALLENGE) == [
            Challenge(
                "Signature",
                parameters=(("realm", LIVE_REALM), ("headers", "(created)")),
            )
        ]

    def test_several_challenges_in_one_value(self) -> None:
        value = (
            'Basic realm="b", charset="UTF-8", Negotiate abc==, '
            'Signature realm="s",headers="(created)", Bearer'
        )
        assert parse_challenges(value) == [
            Challenge("Basic", parameters=(("realm", "b"), ("charset", "UTF-8"))),
            Challenge("Negotiate", token68="abc=="),
            Challenge(
                "Signature", parameters=(("realm", "s"), ("headers", "(created)"))
            ),
            Challenge("Bearer"),
        ]

    def test_names_are_case_insensitive_and_quoted_values_unescaped(self) -> None:
        [challenge] = parse_challenges(
            'signature REALM = "a \\"quoted\\" \\\\ realm" , Headers="(created)"'
        )
        assert challenge.scheme == "signature"
        assert challenge.parameters == (
            ("realm", 'a "quoted" \\ realm'),
            ("headers", "(created)"),
        )

    def test_empty_list_elements_are_ignored(self) -> None:
        assert parse_challenges(" , ,Basic, ,") == [Challenge("Basic")]
        assert parse_challenges("") == []

    def test_token_value_and_token68_forms(self) -> None:
        assert parse_challenges("Signature realm=token") == [
            Challenge("Signature", parameters=(("realm", "token"),))
        ]
        assert parse_challenges("Signature abc=") == [
            Challenge("Signature", token68="abc=")
        ]
        assert parse_challenges("Signature realm= , Basic") == [
            Challenge("Signature", token68="realm="),
            Challenge("Basic"),
        ]
        assert parse_challenges("Signature a/b+c") == [
            Challenge("Signature", token68="a/b+c")
        ]

    @pytest.mark.parametrize(
        "value",
        [
            '"Signature"',
            'Signature realm="unterminated',
            'Signature realm="a" headers="b"',
            "Signature abc== def",
            "Signature realm=@",
            'Signature realm="bad\x00character"',
            'Signature realm="trailing escape\\',
            "Signature, =realm",
            'Signature"realm"',
            "Signature @@@",
            'Signature realm="a\\\x00"',
        ],
    )
    def test_invalid_syntax_is_rejected(self, value: str) -> None:
        with pytest.raises(ChallengeSyntaxError):
            parse_challenges(value)


class TestSelectSignatureRealm:
    def test_live_challenge_yields_its_realm(self) -> None:
        assert select_signature_realm(_response(LIVE_CHALLENGE)) == LIVE_REALM

    @pytest.mark.parametrize(
        "challenges",
        [
            ('Signature realm="r"',),
            ('Basic realm="b"', 'Signature realm="r",headers="(created)"'),
            ('Basic realm="b", Signature realm="r"',),
            ('SIGNATURE realm="r", foo="ignored"',),
        ],
        ids=["headers_absent", "separate_values", "same_value", "other_parameter"],
    )
    def test_supported_challenge_is_selected_among_others(
        self, challenges: tuple[str, ...]
    ) -> None:
        assert select_signature_realm(_response(*challenges)) == "r"

    def test_realm_may_contain_spaces_and_escaped_quotes(self) -> None:
        response = _response('Signature realm="a \\"b\\" c"')
        assert select_signature_realm(response) == 'a "b" c'

    @pytest.mark.parametrize(
        "challenges",
        [
            (),
            ('Basic realm="b"',),
            ('Signature realm="a"', 'Signature realm="b"'),
            ('Signature realm="a", Signature realm="b"',),
            ("Signature",),
            ("Signature abc==",),
            ('Signature headers="(created)"',),
            ('Signature realm=""',),
            ('Signature realm="caf\u00e9"',),
            ('Signature realm="tab\there"',),
            ('Signature realm="r",headers="(created) date"',),
            ('Signature realm="r",headers="(CREATED)"',),
            ('Signature realm="r",realm="s"',),
            ('Signature realm="r",REALM="r"',),
            ('Basic realm="unterminated', 'Signature realm="r"'),
        ],
        ids=[
            "no_challenge",
            "basic_only",
            "two_signature_values",
            "two_signature_in_one_value",
            "no_parameters",
            "token68",
            "missing_realm",
            "empty_realm",
            "non_ascii_realm",
            "control_character_realm",
            "other_headers",
            "headers_case",
            "duplicate_realm",
            "duplicate_realm_case",
            "unparseable_other_value",
        ],
    )
    def test_unsupported_challenge_raises(self, challenges: tuple[str, ...]) -> None:
        with pytest.raises(IBSAuthenticationError) as raised:
            select_signature_realm(_response(*challenges))
        assert raised.value.reason == "unsupported_challenge"
        assert str(raised.value) == (
            "IBS API authentication failed: unsupported_challenge"
        )
        assert raised.value.__cause__ is None
        assert raised.value.__suppress_context__ or raised.value.__context__ is None

    def test_obs_text_in_another_challenge_is_tolerated(self) -> None:
        response = httpx.Response(
            401,
            headers=[
                (b"WWW-Authenticate", b'Basic realm="caf\xe9"'),
                (b"WWW-Authenticate", LIVE_CHALLENGE.encode()),
            ],
        )
        assert select_signature_realm(response) == LIVE_REALM


class TestSigning:
    def test_signature_matches_openssh_known_answer(self) -> None:
        signature = sign_created(
            fictional_ed25519_key(), namespace=LIVE_REALM, created=_CREATED
        )
        assert signature == _SSH_KEYGEN_SSHSIG

    def test_authorization_has_the_exact_specified_form(self) -> None:
        value = build_authorization(
            username="jdoe",
            private_key=fictional_ed25519_key(),
            realm=LIVE_REALM,
            created=_CREATED,
        )
        assert value == (
            'Signature keyId="jdoe",algorithm="ssh",headers="(created)",'
            f'created={_CREATED},signature="{_SSH_KEYGEN_SSHSIG}"'
        )

    def test_signature_verifies_with_the_public_key(self) -> None:
        key = fictional_ed25519_key()
        value = build_authorization(
            username="jdoe", private_key=key, realm="Other realm", created=_CREATED
        )
        verified = verify_signature_header(
            value, public_key=key.public_key(), realm="Other realm"
        )
        assert (verified.key_id, verified.created) == ("jdoe", _CREATED)

    def test_signature_is_bound_to_namespace_key_and_created(self) -> None:
        key = fictional_ed25519_key()
        value = build_authorization(
            username="jdoe", private_key=key, realm=LIVE_REALM, created=_CREATED
        )
        with pytest.raises(SignatureVerificationError):
            verify_signature_header(value, public_key=key.public_key(), realm="other")
        other = fictional_ed25519_key("sentinel-other-fictional-key").public_key()
        with pytest.raises(SignatureVerificationError):
            verify_signature_header(value, public_key=other, realm=LIVE_REALM)
        tampered = value.replace(f"created={_CREATED}", f"created={_CREATED + 1}")
        with pytest.raises(SignatureVerificationError):
            verify_signature_header(
                tampered, public_key=key.public_key(), realm=LIVE_REALM
            )

    def test_signature_is_one_padded_base64_line(self) -> None:
        signature = sign_created(fictional_ed25519_key(), namespace="r", created=0)
        assert base64.b64encode(
            base64.b64decode(signature, validate=True)
        ).decode() == (signature)
        assert "\n" not in signature


def _drive(
    flow: Generator[httpx.Request, httpx.Response], *responses: httpx.Response
) -> list[httpx.Request]:
    """Run an auth flow with scripted responses; return every yielded
    request (a copy of its headers is taken at each yield)."""
    sent = [next(flow)]
    snapshots = [httpx.Request(sent[0].method, sent[0].url, headers=sent[0].headers)]
    for response in responses:
        try:
            request = flow.send(response)
        except StopIteration:
            break
        sent.append(request)
        snapshots.append(
            httpx.Request(request.method, request.url, headers=request.headers)
        )
    return snapshots


class TestAuthFlow:
    def _auth(
        self, discarded: list[int], clock: float = _CREATED + 0.9
    ) -> IBSSignatureAuth:
        return IBSSignatureAuth(
            username="jdoe",
            private_key=fictional_ed25519_key(),
            clock=lambda: clock,
            discard_cookies=lambda: discarded.append(1),
        )

    def _request(self) -> httpx.Request:
        return httpx.Request(
            "POST",
            "https://api.ibs.example.test/source/p/q?cmd=diff",
            headers={"cookie": "IBS_session=fictional-session-0001"},
        )

    @pytest.mark.parametrize("status", [200, 302, 400, 403, 404, 500])
    def test_non_401_response_is_the_operation_response(self, status: int) -> None:
        discarded: list[int] = []
        flow = self._auth(discarded).auth_flow(self._request())
        sent = _drive(flow, httpx.Response(status))
        assert len(sent) == 1
        assert "authorization" not in sent[0].headers
        assert sent[0].headers["cookie"] == "IBS_session=fictional-session-0001"
        assert discarded == []

    def test_401_is_answered_once_with_a_signature_and_without_cookie(self) -> None:
        discarded: list[int] = []
        flow = self._auth(discarded).auth_flow(self._request())
        sent = _drive(flow, _response(LIVE_CHALLENGE), httpx.Response(200))
        assert len(sent) == 2
        assert "authorization" not in sent[0].headers
        assert "cookie" not in sent[1].headers
        assert sent[1].headers["authorization"] == (
            'Signature keyId="jdoe",algorithm="ssh",headers="(created)",'
            f'created={_CREATED},signature="{_SSH_KEYGEN_SSHSIG}"'
        )
        assert discarded == [1]

    def test_401_to_the_signed_attempt_is_signature_rejected(self) -> None:
        discarded: list[int] = []
        flow = self._auth(discarded).auth_flow(self._request())
        next(flow)
        flow.send(_response(LIVE_CHALLENGE))
        with pytest.raises(IBSAuthenticationError) as raised:
            flow.send(_response(LIVE_CHALLENGE))
        assert raised.value.reason == "signature_rejected"
        assert discarded == [1, 1]

    def test_unsupported_challenge_makes_no_further_request(self) -> None:
        discarded: list[int] = []
        flow = self._auth(discarded).auth_flow(self._request())
        next(flow)
        with pytest.raises(IBSAuthenticationError) as raised:
            flow.send(_response('Basic realm="fictional"'))
        assert raised.value.reason == "unsupported_challenge"
        assert discarded == [1]

    def test_repr_exposes_no_credential(self) -> None:
        assert repr(self._auth([])) == "IBSSignatureAuth()"
