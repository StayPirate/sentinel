"""Tests for the validated SMELT package maintainership retrieval.

Contract under test: docs/features/packages/package-maintainership.md (SMELT
Contract: Endpoint, Successful response, Missing and invalid responses;
Email Extraction; Security and Privacy; Testing Requirements) and the #775
warning-category precedence: `transport`, `http_status`, `package_missing`,
`envelope` (404), `envelope` (200), `schema`, first matching row wins. Every
missing or invalid result yields an empty set and exactly one PII-free
`package_maintainership_acquisition_unavailable` WARNING; cancellation,
`SoftTimeLimitExceeded`, `MemoryError`, and programming errors propagate.
The helper performs network I/O only (package-service.md, Module
invariant: I/O-then-Lock pattern).

Every test serves fictional responses through `httpx.MockTransport` (with
the sanitized live fixtures from `tests/support/smelt.py` where noted); no
network and no database are used.
"""

from __future__ import annotations

import ast
import asyncio
import json
from collections.abc import AsyncIterator, Callable, MutableMapping
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock
from uuid import UUID

import httpx
import pytest
from celery.exceptions import SoftTimeLimitExceeded
from structlog.testing import capture_logs

from app.config import settings
from app.services import http_client
from app.services.packages import smelt_maintainership
from app.services.packages.smelt_maintainership import (
    ACQUISITION_UNAVAILABLE_EVENT,
    fetch_package_maintainer_emails,
    maintainership_url,
)
from tests.support.smelt import (
    MAINTAINERSHIP_NOT_FOUND_FIXTURE,
    MAINTAINERSHIP_SUCCESS_FIXTURES,
    SMELT_TEST_API_URL,
    load_maintainership_fixture,
)

TICKET_ID = UUID("5f0c2a8e-3b1d-4e6f-9a7c-0d1e2f3a4b5c")
PACKAGE = "example-package"
ENDPOINT = f"{SMELT_TEST_API_URL}/experimental/v2/packages/{PACKAGE}/maintainership"

EMAIL_ONE = "maintainer.one@example.com"
EMAIL_TWO = "maintainer.two@example.com"
EMAIL_THREE = "maintainer.three@example.com"

Respond = Callable[[httpx.Request], httpx.Response]

_WARNING_KEYS = frozenset(
    {
        "event",
        "log_level",
        "ticket_id",
        "package_name",
        "category",
        "status_code",
        "error_type",
    }
)


@pytest.fixture(autouse=True)
def _smelt_api_url(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "smelt_api_url", SMELT_TEST_API_URL)


# ---------------------------------------------------------------------------
# Response builders (fictional data only)
# ---------------------------------------------------------------------------


def _person(email: Any, username: Any = "maintainer-one") -> dict[str, Any]:
    return {"username": username, "email": email}


def _group(
    *members: Any, name: Any = "fictional-group", email: Any = None
) -> dict[str, Any]:
    return {"name": name, "email": email, "members": list(members)}


def _entry(
    *,
    users: Any = (),
    groups: Any = (),
    codestream: Any = None,
) -> dict[str, Any]:
    return {
        "codestream": (
            {
                "name": "Fictional:Codestream:1",
                "url": "https://example.com/fictional-codestream-1",
            }
            if codestream is None
            else codestream
        ),
        "users": list(users),
        "groups": list(groups),
    }


def _success(*entries: Any) -> dict[str, Any]:
    return {"status": "success", "data": list(entries)}


def _valid_entry() -> dict[str, Any]:
    """A valid entry whose emails must never leak from a rejected response."""
    return _entry(
        users=[_person(EMAIL_ONE)],
        groups=[_group(_person(EMAIL_TWO, username="maintainer-two"))],
    )


def _json(status_code: int, body: Any) -> Respond:
    """Serve `body` serialized as JSON (`None` is served as `null`)."""
    raw = json.dumps(body).encode()

    def respond(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            status_code, content=raw, headers={"content-type": "application/json"}
        )

    return respond


def _raw(
    status_code: int, raw: bytes, headers: dict[str, str] | None = None
) -> Respond:
    """Serve undecoded bytes as a stream (content-encoding is applied on read)."""

    def respond(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            status_code, stream=httpx.ByteStream(raw), headers=headers or {}
        )

    return respond


def _corrupt_gzip(status_code: int) -> Respond:
    return _raw(status_code, b"not gzip at all", {"content-encoding": "gzip"})


def _raise(error: BaseException) -> Respond:
    def respond(request: httpx.Request) -> httpx.Response:
        raise error

    return respond


def _redirect(status_code: int) -> Respond:
    def respond(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            status_code, headers={"Location": "https://other.example.test/elsewhere"}
        )

    return respond


class _BodyReadFailure(httpx.AsyncByteStream):
    """A 200 body whose transfer fails after the headers arrived."""

    async def __aiter__(self) -> AsyncIterator[bytes]:
        yield b'{"status": "success", "data": [{"users": [{"email": "'
        raise httpx.ReadError(f"connection reset while reading {EMAIL_ONE}")


# ---------------------------------------------------------------------------
# Invocation helpers
# ---------------------------------------------------------------------------


@dataclass
class _Outcome:
    result: frozenset[str]
    requests: list[httpx.Request]
    logs: list[MutableMapping[str, Any]]


async def _fetch(
    respond: Respond, *, package_name: str = PACKAGE, **client_kwargs: Any
) -> _Outcome:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return respond(request)

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport, **client_kwargs) as client:
        with capture_logs() as logs:
            result = await fetch_package_maintainer_emails(
                client, ticket_id=TICKET_ID, package_name=package_name
            )
    return _Outcome(result=result, requests=requests, logs=logs)


def _warning(
    category: str, *, status_code: int | None = None, error_type: str | None = None
) -> dict[str, Any]:
    expected: dict[str, Any] = {
        "event": ACQUISITION_UNAVAILABLE_EVENT,
        "log_level": "warning",
        "ticket_id": str(TICKET_ID),
        "package_name": PACKAGE,
        "category": category,
    }
    if status_code is not None:
        expected["status_code"] = status_code
    if error_type is not None:
        expected["error_type"] = error_type
    return expected


def _assert_unavailable(
    outcome: _Outcome,
    category: str,
    *,
    status_code: int | None = None,
    error_type: str | None = None,
) -> None:
    assert outcome.result == frozenset()
    assert outcome.logs == [
        _warning(category, status_code=status_code, error_type=error_type)
    ]
    assert set(outcome.logs[0]) <= _WARNING_KEYS
    assert len(outcome.requests) == 1


def _ids(cases: list[tuple[str, Any]]) -> list[str]:
    return [name for name, _ in cases]


def _values(cases: list[tuple[str, Any]]) -> list[Any]:
    return [value for _, value in cases]


# ---------------------------------------------------------------------------
# Request construction (SMELT Contract > Endpoint)
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestRequest:
    async def test_request_targets_exact_endpoint_with_get_and_no_query(
        self,
    ) -> None:
        outcome = await _fetch(_json(200, _success()))

        (request,) = outcome.requests
        assert request.method == "GET"
        assert str(request.url) == ENDPOINT
        assert request.url.raw_path == (
            b"/api/experimental/v2/packages/example-package/maintainership"
        )
        assert request.url.query == b""
        assert not request.url.params
        assert maintainership_url(SMELT_TEST_API_URL, PACKAGE) == ENDPOINT

    @pytest.mark.parametrize(
        ("package_name", "segment"),
        [
            ("pkg/sub", b"pkg%2Fsub"),
            ("pkg?codestream=1", b"pkg%3Fcodestream%3D1"),
            ("pkg#fragment", b"pkg%23fragment"),
            ("pkg name", b"pkg%20name"),
            ("pkg+plus", b"pkg%2Bplus"),
            ("pkg%41", b"pkg%2541"),
            ("pkg&other", b"pkg%26other"),
            ("pkg-é", b"pkg-%C3%A9"),
            ("../pkg", b"..%2Fpkg"),
        ],
        ids=[
            "slash",
            "query",
            "fragment",
            "space",
            "plus",
            "percent",
            "ampersand",
            "non-ascii",
            "dot-dot-prefix",
        ],
    )
    async def test_reserved_characters_are_encoded_into_one_path_segment(
        self, package_name: str, segment: bytes
    ) -> None:
        outcome = await _fetch(_json(200, _success()), package_name=package_name)

        (request,) = outcome.requests
        assert request.url.raw_path == (
            b"/api/experimental/v2/packages/" + segment + b"/maintainership"
        )
        assert request.url.query == b""
        assert request.url.fragment == ""
        assert outcome.logs == []
        assert maintainership_url(SMELT_TEST_API_URL, package_name) == (
            f"{SMELT_TEST_API_URL}/experimental/v2/packages/"
            f"{segment.decode()}/maintainership"
        )

    @pytest.mark.parametrize("package_name", ["", ".", ".."])
    async def test_name_that_cannot_form_a_segment_raises_before_any_request(
        self, package_name: str
    ) -> None:
        requests: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            requests.append(request)
            return httpx.Response(200, json=_success())

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            with (
                capture_logs() as logs,
                pytest.raises(ValueError, match="single URL path segment"),
            ):
                await fetch_package_maintainer_emails(
                    client, ticket_id=TICKET_ID, package_name=package_name
                )

        assert requests == []
        assert logs == []
        with pytest.raises(ValueError, match="single URL path segment"):
            maintainership_url(SMELT_TEST_API_URL, package_name)

    async def test_request_sends_no_credentials_despite_client_defaults(
        self,
    ) -> None:
        outcome = await _fetch(
            _json(200, _success(_valid_entry())),
            auth=("fictional-user", "fictional-secret"),
            headers={"Authorization": "Bearer fictional-token"},
            cookies={"sessionid": "fictional-session"},
        )

        (request,) = outcome.requests
        assert "authorization" not in request.headers
        assert "cookie" not in request.headers
        assert outcome.result == frozenset({EMAIL_ONE, EMAIL_TWO})

    @pytest.mark.parametrize("status_code", [301, 302, 303, 307, 308])
    async def test_redirect_is_not_followed_even_when_client_follows(
        self, status_code: int
    ) -> None:
        outcome = await _fetch(_redirect(status_code), follow_redirects=True)

        _assert_unavailable(outcome, "http_status", status_code=status_code)
        assert str(outcome.requests[0].url) == ENDPOINT


# ---------------------------------------------------------------------------
# Successful extraction (Successful response; Email Extraction)
# ---------------------------------------------------------------------------

_FIXTURE_EMAILS: dict[str, frozenset[str]] = {
    "users_only": frozenset({"maintainer.1@example.com"}),
    "groups_only": frozenset(f"maintainer.{n}@example.com" for n in range(1, 5)),
    "users_and_groups": frozenset(f"maintainer.{n}@example.com" for n in range(1, 16)),
    "null_email": frozenset(f"maintainer.{n}@example.com" for n in range(1, 4)),
    "empty": frozenset(),
}

_SUCCESS_BODIES: list[tuple[str, tuple[dict[str, Any], frozenset[str]]]] = [
    (
        "direct-users-only",
        (
            _success(
                _entry(
                    users=[
                        _person(EMAIL_ONE),
                        _person(EMAIL_TWO, username="maintainer-two"),
                    ]
                )
            ),
            frozenset({EMAIL_ONE, EMAIL_TWO}),
        ),
    ),
    (
        "groups-and-members-only",
        (
            _success(
                _entry(
                    groups=[
                        _group(_person(EMAIL_ONE)),
                        _group(_person(EMAIL_TWO), name="fictional-group-two"),
                    ]
                )
            ),
            frozenset({EMAIL_ONE, EMAIL_TWO}),
        ),
    ),
    (
        "users-and-groups-with-duplicates-across-entries-users-and-members",
        (
            _success(
                _entry(
                    users=[_person(EMAIL_ONE), _person(EMAIL_ONE)],
                    groups=[_group(_person(EMAIL_ONE), _person(EMAIL_TWO))],
                ),
                _entry(
                    users=[_person(EMAIL_TWO)],
                    groups=[_group(_person(EMAIL_THREE), _person(EMAIL_ONE))],
                ),
            ),
            frozenset({EMAIL_ONE, EMAIL_TWO, EMAIL_THREE}),
        ),
    ),
    (
        "mixed-case-lowercased-and-deduplicated",
        (
            _success(
                _entry(
                    users=[_person("Maintainer.One@Example.com")],
                    groups=[
                        _group(
                            _person(EMAIL_ONE), _person("MAINTAINER.TWO@EXAMPLE.COM")
                        )
                    ],
                )
            ),
            frozenset({EMAIL_ONE, EMAIL_TWO}),
        ),
    ),
    (
        "surrounding-spaces-not-trimmed",
        (
            _success(_entry(users=[_person(" Maintainer.One@Example.com ")])),
            frozenset({" maintainer.one@example.com "}),
        ),
    ),
    (
        "null-and-omitted-emails-ignored",
        (
            _success(
                _entry(
                    users=[_person(None), {"username": "maintainer-two"}],
                    groups=[
                        _group(
                            _person(None),
                            {"username": "maintainer-three"},
                            _person(EMAIL_ONE),
                        )
                    ],
                )
            ),
            frozenset({EMAIL_ONE}),
        ),
    ),
    (
        "omitted-and-empty-members",
        (
            _success(
                _entry(
                    users=[_person(EMAIL_ONE)],
                    groups=[
                        {"name": "fictional-group", "email": None},
                        _group(),
                    ],
                )
            ),
            frozenset({EMAIL_ONE}),
        ),
    ),
    (
        "collective-group-email-not-included",
        (
            _success(
                _entry(
                    groups=[
                        _group(
                            _person(EMAIL_ONE),
                            email="fictional-group@example.com",
                        ),
                        _group(email="fictional-other-group@example.com"),
                    ]
                )
            ),
            frozenset({EMAIL_ONE}),
        ),
    ),
    (
        "empty-data",
        (_success(), frozenset()),
    ),
    (
        "all-emails-null",
        (
            _success(
                _entry(users=[_person(None)], groups=[_group(_person(None))]),
                _entry(groups=[_group(_person(None))]),
            ),
            frozenset(),
        ),
    ),
]

_UNCONSUMED_VALUES: list[tuple[str, dict[str, Any]]] = [
    (
        "missing-username",
        _success(
            _entry(
                users=[{"email": EMAIL_ONE}],
                groups=[_group({"email": EMAIL_TWO})],
            )
        ),
    ),
    (
        "missing-group-name",
        _success(
            _entry(
                users=[_person(EMAIL_ONE)],
                groups=[{"email": None, "members": [_person(EMAIL_TWO)]}],
            )
        ),
    ),
    (
        "unknown-fields-at-every-level",
        {
            "status": "success",
            "message": "fictional extra",
            "data": [
                {
                    "codestream": {
                        "name": "Fictional:Codestream:1",
                        "url": "https://example.com/fictional-codestream-1",
                        "extra": [1, 2],
                    },
                    "users": [{**_person(EMAIL_ONE), "extra": {"nested": True}}],
                    "groups": [
                        {
                            **_group({**_person(EMAIL_TWO), "extra": 7}),
                            "extra": "group",
                        }
                    ],
                    "extra": None,
                }
            ],
        },
    ),
    (
        "arbitrary-codestream-inner-values",
        _success(
            _entry(
                users=[_person(EMAIL_ONE)],
                codestream={"name": 1, "url": [[1, [2]]], "other": {}},
            ),
            _entry(groups=[_group(_person(EMAIL_TWO))], codestream={"x": None}),
        ),
    ),
    (
        "empty-codestream-object",
        _success(
            _entry(users=[_person(EMAIL_ONE)], codestream={}),
            _entry(groups=[_group(_person(EMAIL_TWO))]),
        ),
    ),
    (
        "non-string-group-email-name-and-username",
        _success(
            _entry(
                users=[_person(EMAIL_ONE, username=42)],
                groups=[
                    _group(
                        _person(EMAIL_TWO, username=["maintainer-two"]),
                        name=123,
                        email=123,
                    )
                ],
            )
        ),
    ),
]


@pytest.mark.unit
class TestSuccessfulExtraction:
    @pytest.mark.parametrize("name", MAINTAINERSHIP_SUCCESS_FIXTURES)
    async def test_sanitized_live_fixture_returns_exact_email_set(
        self, name: str
    ) -> None:
        outcome = await _fetch(_json(200, load_maintainership_fixture(name)))

        assert outcome.result == _FIXTURE_EMAILS[name]
        assert outcome.logs == []

    @pytest.mark.parametrize(
        ("body", "expected"), _values(_SUCCESS_BODIES), ids=_ids(_SUCCESS_BODIES)
    )
    async def test_valid_response_returns_lowercase_deduplicated_set(
        self, body: dict[str, Any], expected: frozenset[str]
    ) -> None:
        outcome = await _fetch(_json(200, body))

        assert outcome.result == expected
        assert outcome.logs == []

    async def test_usernames_and_group_names_are_never_returned(self) -> None:
        body = _success(
            _entry(
                users=[_person(EMAIL_ONE, username="maintainer-one@example.com")],
                groups=[
                    _group(
                        _person(None, username="maintainer-two"),
                        name="fictional-group@example.com",
                        email="fictional-group@example.com",
                    )
                ],
            )
        )

        outcome = await _fetch(_json(200, body))

        assert outcome.result == frozenset({EMAIL_ONE})
        assert outcome.logs == []

    @pytest.mark.parametrize(
        "body", _values(_UNCONSUMED_VALUES), ids=_ids(_UNCONSUMED_VALUES)
    )
    async def test_unconsumed_values_do_not_reject_the_response(
        self, body: dict[str, Any]
    ) -> None:
        outcome = await _fetch(_json(200, body))

        assert outcome.result == frozenset({EMAIL_ONE, EMAIL_TWO})
        assert outcome.logs == []

    async def test_result_is_a_frozenset(self) -> None:
        outcome = await _fetch(_json(200, _success(_valid_entry())))

        assert isinstance(outcome.result, frozenset)


# ---------------------------------------------------------------------------
# Whole-response rejection (precedence row 6: `schema`)
# ---------------------------------------------------------------------------


def _with_entry(**overrides: Any) -> dict[str, Any]:
    """A success body: one valid entry plus one entry with `overrides`."""
    broken = _valid_entry()
    broken.update(overrides)
    return _success(_valid_entry(), broken)


def _without(key: str) -> dict[str, Any]:
    broken = _valid_entry()
    del broken[key]
    return _success(_valid_entry(), broken)


def _with_user(user: Any) -> dict[str, Any]:
    return _with_entry(users=[_person(EMAIL_THREE), user])


def _with_group(group: Any) -> dict[str, Any]:
    return _with_entry(groups=[_group(_person(EMAIL_THREE)), group])


def _with_member(member: Any) -> dict[str, Any]:
    return _with_entry(groups=[_group(_person(EMAIL_THREE), member)])


_NON_OBJECTS: list[tuple[str, Any]] = [
    ("string", "maintainer-one"),
    ("list", [EMAIL_ONE]),
    ("null", None),
]
_NON_ARRAYS: list[tuple[str, Any]] = [
    ("object", {"0": _person(EMAIL_ONE)}),
    ("string", EMAIL_ONE),
    ("null", None),
]
_BAD_EMAILS: list[tuple[str, Any]] = [
    ("int", 42),
    ("bool", True),
    ("list", [EMAIL_ONE]),
    ("object", {"address": EMAIL_ONE}),
]

_SCHEMA_REJECTIONS: list[tuple[str, dict[str, Any]]] = [
    ("missing-data", {"status": "success", "results": [_valid_entry()]}),
    ("data-object", {"status": "success", "data": {"0": _valid_entry()}}),
    ("data-string", {"status": "success", "data": EMAIL_ONE}),
    ("data-null", {"status": "success", "data": None}),
    *[
        (f"entry-{kind}", _success(_valid_entry(), value))
        for kind, value in _NON_OBJECTS
    ],
    ("missing-codestream", _without("codestream")),
    ("codestream-list", _with_entry(codestream=[{"name": "Fictional:Codestream:1"}])),
    ("codestream-string", _with_entry(codestream="Fictional:Codestream:1")),
    ("codestream-null", _with_entry(codestream=None)),
    ("missing-users", _without("users")),
    *[(f"users-{kind}", _with_entry(users=value)) for kind, value in _NON_ARRAYS],
    ("missing-groups", _without("groups")),
    *[(f"groups-{kind}", _with_entry(groups=value)) for kind, value in _NON_ARRAYS],
    *[(f"user-{kind}", _with_user(value)) for kind, value in _NON_OBJECTS],
    *[(f"group-{kind}", _with_group(value)) for kind, value in _NON_OBJECTS],
    *[(f"member-{kind}", _with_member(value)) for kind, value in _NON_OBJECTS],
    *[
        (f"members-{kind}", _with_group({"name": "fictional-group", "members": value}))
        for kind, value in _NON_ARRAYS
    ],
    *[
        (f"user-email-{kind}", _with_user(_person(value)))
        for kind, value in _BAD_EMAILS
    ],
    *[
        (f"member-email-{kind}", _with_member(_person(value)))
        for kind, value in _BAD_EMAILS
    ],
]


@pytest.mark.unit
class TestWholeResponseRejection:
    @pytest.mark.parametrize(
        "body", _values(_SCHEMA_REJECTIONS), ids=_ids(_SCHEMA_REJECTIONS)
    )
    async def test_malformed_consumed_structure_rejects_whole_response(
        self, body: dict[str, Any]
    ) -> None:
        outcome = await _fetch(_json(200, body))

        _assert_unavailable(outcome, "schema", status_code=200)


# ---------------------------------------------------------------------------
# Failure categories (precedence rows 1-5)
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestTransportFailure:
    """Row 1: no HTTP response after the shared transport retries."""

    @pytest.mark.parametrize(
        "error",
        [
            httpx.ConnectError,
            httpx.ReadTimeout,
            httpx.ProxyError,
            httpx.RemoteProtocolError,
        ],
        ids=lambda error: error.__name__,
    )
    async def test_transport_error_yields_transport_warning(
        self, error: type[httpx.TransportError]
    ) -> None:
        outcome = await _fetch(_raise(error("fictional transport failure")))

        _assert_unavailable(outcome, "transport", error_type=error.__name__)

    async def test_transport_error_while_reading_body_yields_transport_warning(
        self,
    ) -> None:
        outcome = await _fetch(
            lambda request: httpx.Response(200, stream=_BodyReadFailure())
        )

        _assert_unavailable(
            outcome, "transport", status_code=200, error_type="ReadError"
        )

    async def test_transport_failure_after_shared_retries_yields_one_warning(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        sleep = AsyncMock()
        monkeypatch.setattr(http_client, "asyncio", SimpleNamespace(sleep=sleep))
        attempts: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            attempts.append(request)
            raise httpx.ConnectError("fictional connection refused", request=request)

        transport = http_client._RetryTransport(
            httpx.MockTransport(handler), retry_non_idempotent=False
        )
        async with httpx.AsyncClient(transport=transport) as client:
            with capture_logs() as logs:
                result = await fetch_package_maintainer_emails(
                    client, ticket_id=TICKET_ID, package_name=PACKAGE
                )

        assert result == frozenset()
        assert len(attempts) == 4
        assert [call.args[0] for call in sleep.await_args_list] == [1.0, 2.0, 4.0]
        assert logs == [_warning("transport", error_type="ConnectError")]


@pytest.mark.unit
class TestHttpStatusFailure:
    """Row 2: any status other than 200 and 404; the body is not read."""

    @pytest.mark.parametrize(
        "status_code", [400, 401, 403, 429, 500, 502, 503, 201, 204]
    )
    async def test_unexpected_status_yields_http_status_warning(
        self, status_code: int
    ) -> None:
        body = b"" if status_code == 204 else b"fictional body"

        outcome = await _fetch(_raw(status_code, body))

        _assert_unavailable(outcome, "http_status", status_code=status_code)

    @pytest.mark.parametrize("status_code", [302, 400, 500])
    @pytest.mark.parametrize(
        "body",
        [
            {"status": "error", "data": "Package example-package not found"},
            b"<html>not json</html>",
            _success(_valid_entry()),
        ],
        ids=["jsend-error", "invalid-json", "success-with-emails"],
    )
    async def test_status_precedes_any_body_interpretation(
        self, status_code: int, body: dict[str, Any] | bytes
    ) -> None:
        respond = (
            _raw(status_code, body)
            if isinstance(body, bytes)
            else _json(status_code, body)
        )

        outcome = await _fetch(respond)

        _assert_unavailable(outcome, "http_status", status_code=status_code)

    async def test_corrupt_compressed_body_is_not_read(self) -> None:
        outcome = await _fetch(_corrupt_gzip(500))

        _assert_unavailable(outcome, "http_status", status_code=500)


@pytest.mark.unit
class TestPackageMissing:
    """Row 3: 404 with a valid JSend error envelope."""

    async def test_jsend_error_404_yields_package_missing(self) -> None:
        outcome = await _fetch(
            _json(404, {"status": "error", "data": "Package example-package not found"})
        )

        _assert_unavailable(outcome, "package_missing", status_code=404)

    async def test_sanitized_live_not_found_fixture_yields_package_missing(
        self,
    ) -> None:
        body = load_maintainership_fixture(MAINTAINERSHIP_NOT_FOUND_FIXTURE)

        outcome = await _fetch(_json(404, body))

        _assert_unavailable(outcome, "package_missing", status_code=404)


_NOT_FOUND = "Package example-package not found"

# (responder, expected `error_type` or `None` when absent).
_ENVELOPE_404: list[tuple[str, tuple[Respond, str | None]]] = [
    ("invalid-json", (_raw(404, b"<html>Not Found</html>"), "JSONDecodeError")),
    ("non-object-list", (_json(404, [_NOT_FOUND]), None)),
    ("non-object-string", (_json(404, _NOT_FOUND), None)),
    ("non-object-number", (_json(404, 404), None)),
    ("non-object-null", (_json(404, None), None)),
    ("status-success-with-emails", (_json(404, _success(_valid_entry())), None)),
    ("status-fail", (_json(404, {"status": "fail", "data": _NOT_FOUND}), None)),
    ("missing-status", (_json(404, {"data": _NOT_FOUND}), None)),
    ("non-string-status", (_json(404, {"status": 404, "data": _NOT_FOUND}), None)),
    ("data-null", (_json(404, {"status": "error", "data": None}), None)),
    ("data-object", (_json(404, {"status": "error", "data": {"m": "x"}}), None)),
    ("data-list", (_json(404, {"status": "error", "data": [_NOT_FOUND]}), None)),
    ("data-number", (_json(404, {"status": "error", "data": 404}), None)),
    ("missing-data", (_json(404, {"status": "error"}), None)),
    ("corrupt-gzip", (_corrupt_gzip(404), "DecodingError")),
]

_ENVELOPE_200: list[tuple[str, tuple[Respond, str | None]]] = [
    ("invalid-json", (_raw(200, b"<html>maintenance</html>"), "JSONDecodeError")),
    (
        "invalid-utf8",
        (_raw(200, b'{"status": "success", "data": "\xc3\x28"}'), "UnicodeDecodeError"),
    ),
    ("non-object-list", (_json(200, [_valid_entry()]), None)),
    ("non-object-string", (_json(200, "success"), None)),
    ("non-object-number", (_json(200, 200), None)),
    ("non-object-null", (_json(200, None), None)),
    ("missing-status", (_json(200, {"data": [_valid_entry()]}), None)),
    (
        "status-fail",
        (_json(200, {"status": "fail", "data": [_valid_entry()]}), None),
    ),
    (
        "status-unrecognized",
        (_json(200, {"status": "ok", "data": [_valid_entry()]}), None),
    ),
    (
        "status-wrong-case",
        (_json(200, {"status": "Success", "data": [_valid_entry()]}), None),
    ),
    (
        "status-true",
        (_json(200, {"status": True, "data": [_valid_entry()]}), None),
    ),
    ("status-one", (_json(200, {"status": 1, "data": [_valid_entry()]}), None)),
    ("status-error", (_json(200, {"status": "error", "data": _NOT_FOUND}), None)),
    ("corrupt-gzip", (_corrupt_gzip(200), "DecodingError")),
]


@pytest.mark.unit
class TestEnvelopeFailure:
    """Row 4 (404 with any other body) and row 5 (200 envelope failures)."""

    @pytest.mark.parametrize(
        ("respond", "error_type"), _values(_ENVELOPE_404), ids=_ids(_ENVELOPE_404)
    )
    async def test_404_without_jsend_error_envelope_yields_envelope(
        self, respond: Respond, error_type: str | None
    ) -> None:
        outcome = await _fetch(respond)

        _assert_unavailable(outcome, "envelope", status_code=404, error_type=error_type)

    @pytest.mark.parametrize(
        ("respond", "error_type"), _values(_ENVELOPE_200), ids=_ids(_ENVELOPE_200)
    )
    async def test_200_without_success_envelope_yields_envelope(
        self, respond: Respond, error_type: str | None
    ) -> None:
        outcome = await _fetch(respond)

        _assert_unavailable(outcome, "envelope", status_code=200, error_type=error_type)

    async def test_recursion_error_while_decoding_yields_envelope(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def loads(content: bytes) -> Any:
            raise RecursionError("maximum recursion depth exceeded")

        monkeypatch.setattr(smelt_maintainership, "json", SimpleNamespace(loads=loads))

        outcome = await _fetch(_json(200, _success(_valid_entry())))

        _assert_unavailable(
            outcome, "envelope", status_code=200, error_type="RecursionError"
        )

    async def test_deeply_nested_json_yields_envelope(self) -> None:
        # Whether the decoder exhausts its depth guard (RecursionError) or
        # reaches the unterminated end (JSONDecodeError) depends on the
        # interpreter's available C stack; the outcome is the same.
        outcome = await _fetch(_raw(200, b"[" * 100_000))

        assert outcome.result == frozenset()
        (record,) = outcome.logs
        assert record["category"] == "envelope"
        assert record["status_code"] == 200
        assert record["error_type"] in {"RecursionError", "JSONDecodeError"}


# ---------------------------------------------------------------------------
# Propagation (no conversion, no warning)
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestPropagation:
    @pytest.mark.parametrize(
        "error",
        [
            asyncio.CancelledError(),
            SoftTimeLimitExceeded(),
            MemoryError(),
            httpx.UnsupportedProtocol("fictional unsupported protocol"),
            httpx.LocalProtocolError("fictional local protocol error"),
            RuntimeError("fictional programming error"),
        ],
        ids=lambda error: type(error).__name__,
    )
    async def test_non_converted_error_from_transport_propagates(
        self, error: BaseException
    ) -> None:
        with capture_logs() as logs, pytest.raises(type(error)) as raised:
            await _fetch(_raise(error))

        assert raised.value is error
        assert logs == []

    async def test_memory_error_during_json_decoding_propagates(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def loads(content: bytes) -> Any:
            raise MemoryError

        monkeypatch.setattr(smelt_maintainership, "json", SimpleNamespace(loads=loads))

        with capture_logs() as logs, pytest.raises(MemoryError):
            await _fetch(_json(200, _success(_valid_entry())))

        assert logs == []


# ---------------------------------------------------------------------------
# Privacy (Security and Privacy; Missing and invalid responses)
# ---------------------------------------------------------------------------

_PRIVATE_FRAGMENTS = (
    EMAIL_ONE,
    EMAIL_TWO,
    EMAIL_THREE,
    "maintainer-one",
    "maintainer-two",
    "fictional-group",
    "Fictional:Codestream",
    "example.com",
    "smelt.example.test",
    "https://",
    "/api",
    "/maintainership",
    "not found",
    '"status"',
    "status=",
    "<html>",
)


def _private_body() -> dict[str, Any]:
    return _success(
        _entry(
            users=[_person(EMAIL_ONE)],
            groups=[
                _group(
                    _person(EMAIL_TWO, username="maintainer-two"),
                    email="fictional-group@example.com",
                )
            ],
        )
    )


_PRIVACY_CASES: list[tuple[str, tuple[Respond, tuple[str, ...]]]] = [
    (
        "transport-error-message",
        (
            _raise(
                httpx.ConnectError(
                    f"refused by {ENDPOINT} for {EMAIL_ONE} (fictional detail)"
                )
            ),
            ("refused by", "fictional detail"),
        ),
    ),
    (
        "transport-error-while-reading-body",
        (
            lambda request: httpx.Response(200, stream=_BodyReadFailure()),
            ("connection reset",),
        ),
    ),
    (
        "http-status-with-private-body",
        (_json(500, _private_body()), ()),
    ),
    (
        "redirect-location",
        (_redirect(302), ("other.example.test", "elsewhere")),
    ),
    (
        "package-missing-message",
        (
            _json(404, {"status": "error", "data": f"{_NOT_FOUND} for {EMAIL_ONE}"}),
            ("Package ",),
        ),
    ),
    (
        "envelope-404-invalid-json",
        (
            _raw(404, f"<html>{EMAIL_ONE} not found</html>".encode()),
            ("Expecting value", "line 1"),
        ),
    ),
    (
        "envelope-200-status-fail",
        (_json(200, {"status": "fail", "data": _private_body()["data"]}), ("fail",)),
    ),
    (
        "envelope-200-invalid-utf8",
        (
            _raw(200, f'{{"status": "{EMAIL_ONE}\xff"}}'.encode("latin-1")),
            ("can't decode", "invalid", "position"),
        ),
    ),
    (
        "envelope-200-corrupt-gzip",
        (_corrupt_gzip(200), ("decompress", "header check", "not gzip")),
    ),
    (
        "schema-with-private-values",
        (
            _json(
                200,
                _success(
                    _private_body()["data"][0],
                    _entry(
                        users=[_person(EMAIL_THREE), _person(42)],
                        groups=[_group(_person(EMAIL_TWO))],
                    ),
                ),
            ),
            ("validation error", "input_value", "input_type", "string_type", "42"),
        ),
    ),
]


@pytest.mark.unit
class TestPrivacy:
    @pytest.mark.parametrize(
        ("respond", "forbidden"), _values(_PRIVACY_CASES), ids=_ids(_PRIVACY_CASES)
    )
    async def test_failure_warning_contains_no_private_or_raw_data(
        self, respond: Respond, forbidden: tuple[str, ...]
    ) -> None:
        outcome = await _fetch(respond)

        assert outcome.result == frozenset()
        (record,) = outcome.logs
        assert record["event"] == ACQUISITION_UNAVAILABLE_EVENT
        assert set(record) <= _WARNING_KEYS
        rendered = repr(outcome.logs)
        for fragment in (*_PRIVATE_FRAGMENTS, *forbidden):
            assert fragment not in rendered

    async def test_success_path_emits_no_log_record(self) -> None:
        outcome = await _fetch(
            _json(200, load_maintainership_fixture("users_and_groups"))
        )

        assert outcome.result
        assert outcome.logs == []


# ---------------------------------------------------------------------------
# Boundary (package-service.md, Module invariant: I/O-then-Lock pattern)
# ---------------------------------------------------------------------------

_FORBIDDEN_MODULES = ("sqlalchemy", "app.models", "app.database")
_FORBIDDEN_NAMES = frozenset(
    {"AsyncSession", "with_for_update", "async_session_factory", "get_db"}
)


@pytest.mark.unit
class TestIoOnlyBoundary:
    @staticmethod
    def _tree() -> ast.Module:
        source = Path(smelt_maintainership.__file__).read_text(encoding="utf-8")
        return ast.parse(source)

    def test_module_imports_no_database_or_model_module(self) -> None:
        imported: list[str] = []
        for node in ast.walk(self._tree()):
            if isinstance(node, ast.Import):
                imported.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module is not None:
                imported.append(node.module)
                imported.extend(f"{node.module}.{a.name}" for a in node.names)

        assert imported
        for module in imported:
            for forbidden in _FORBIDDEN_MODULES:
                assert module != forbidden
                assert not module.startswith(f"{forbidden}.")

    def test_module_references_no_session_or_lock_name(self) -> None:
        names = {
            node.id if isinstance(node, ast.Name) else node.attr
            for node in ast.walk(self._tree())
            if isinstance(node, ast.Name | ast.Attribute)
        }

        assert names
        assert names.isdisjoint(_FORBIDDEN_NAMES)
