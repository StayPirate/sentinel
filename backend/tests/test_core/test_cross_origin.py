"""Unit tests for cross-origin request protection (`app/core/cross_origin.py`).

See `docs/features/identity/authentication.md` (Cross-Origin Request
Protection) for the decision rules and the rejection under test, and
`docs/features/platform/testing-strategy.md` (Authentication and Session,
Cross-origin request protection) for the mandatory scenarios. The decision
function is tested directly; the middleware wraps a recording ASGI app, so
these tests prove that a rejected request never reaches it. The registered
application, the session-cookie and logout effects, and the OpenAPI document
are covered end to end in `tests/test_api/test_cross_origin_protection.py`.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

import pytest
from fastapi.middleware.cors import CORSMiddleware
from httpx import ASGITransport, AsyncClient, Response
from starlette.responses import PlainTextResponse
from starlette.types import Message, Receive, Scope, Send

import app.main as main_module
from app.config import settings
from app.core.cross_origin import (
    REJECTION_DETAIL,
    SAFE_METHODS,
    CrossOriginProtectionMiddleware,
    CrossOriginRejectionReason,
    cross_origin_rejection,
)
from app.core.middleware import RequestIDMiddleware

_HOST = "api.example.test"
_API_ORIGIN = f"https://{_HOST}"
_UI_ORIGIN = "https://ui.example.test"
_SIBLING_ORIGIN = "https://sibling.example.test"

_SEC_FETCH_SITE = CrossOriginRejectionReason.SEC_FETCH_SITE
_ORIGIN = CrossOriginRejectionReason.ORIGIN


def _decide(
    *,
    method: str = "POST",
    origin: str | None = None,
    sec_fetch_site: str | None = None,
    host: str | None = _HOST,
    trusted_origins: Sequence[str] = (),
) -> CrossOriginRejectionReason | None:
    return cross_origin_rejection(
        method,
        origin=origin,
        sec_fetch_site=sec_fetch_site,
        host=host,
        trusted_origins=frozenset(trusted_origins),
    )


@pytest.mark.unit
class TestSafeMethods:
    def test_safe_methods_are_get_head_and_options(self) -> None:
        assert frozenset({"GET", "HEAD", "OPTIONS"}) == SAFE_METHODS

    @pytest.mark.parametrize("method", ["GET", "HEAD", "OPTIONS"])
    @pytest.mark.parametrize(
        ("origin", "sec_fetch_site"),
        [
            pytest.param(_SIBLING_ORIGIN, "same-site", id="same-site"),
            pytest.param(_SIBLING_ORIGIN, "cross-site", id="cross-site"),
            pytest.param("null", None, id="null-origin"),
        ],
    )
    def test_are_never_rejected(
        self, method: str, origin: str, sec_fetch_site: str | None
    ) -> None:
        assert (
            _decide(method=method, origin=origin, sec_fetch_site=sec_fetch_site) is None
        )

    @pytest.mark.parametrize("method", ["POST", "PATCH", "DELETE", "PUT", "get"])
    def test_every_other_method_is_unsafe(self, method: str) -> None:
        """Methods are compared exactly: a lowercase `get` is not `GET`."""
        assert _decide(method=method, sec_fetch_site="cross-site") is _SEC_FETCH_SITE


@pytest.mark.unit
class TestTrustedOrigins:
    """Rule 1: an `Origin` equal to a `CORS_ORIGINS` entry is accepted."""

    @pytest.mark.parametrize("sec_fetch_site", ["cross-site", "same-site", None])
    def test_listed_origin_is_accepted(self, sec_fetch_site: str | None) -> None:
        assert (
            _decide(
                origin=_UI_ORIGIN,
                sec_fetch_site=sec_fetch_site,
                trusted_origins=[_UI_ORIGIN],
            )
            is None
        )

    @pytest.mark.parametrize(
        "origin",
        [
            pytest.param(f"{_UI_ORIGIN}/", id="trailing-slash"),
            pytest.param(_UI_ORIGIN.upper(), id="other-case"),
            pytest.param(_SIBLING_ORIGIN, id="other-origin"),
        ],
    )
    def test_only_an_exact_entry_matches(self, origin: str) -> None:
        assert (
            _decide(
                origin=origin, sec_fetch_site="cross-site", trusted_origins=[_UI_ORIGIN]
            )
            is _SEC_FETCH_SITE
        )
        assert _decide(origin=origin, trusted_origins=[_UI_ORIGIN]) is _ORIGIN


@pytest.mark.unit
class TestSecFetchSite:
    """Rule 2: a present, non-empty `Sec-Fetch-Site` decides."""

    @pytest.mark.parametrize("value", ["same-origin", "none"])
    def test_same_origin_and_none_are_accepted(self, value: str) -> None:
        assert _decide(sec_fetch_site=value) is None

    @pytest.mark.parametrize(
        "value",
        ["same-site", "cross-site", "Same-Origin", "NONE", "same-origin ", "fictional"],
    )
    def test_every_other_value_is_rejected(self, value: str) -> None:
        assert _decide(sec_fetch_site=value) is _SEC_FETCH_SITE

    def test_same_origin_wins_over_a_foreign_origin(self) -> None:
        assert _decide(origin=_SIBLING_ORIGIN, sec_fetch_site="same-origin") is None

    def test_cross_site_wins_over_an_origin_equal_to_host(self) -> None:
        assert (
            _decide(origin=_API_ORIGIN, sec_fetch_site="cross-site") is _SEC_FETCH_SITE
        )

    def test_empty_value_falls_through_to_origin(self) -> None:
        assert _decide(origin=_API_ORIGIN, sec_fetch_site="") is None
        assert _decide(origin=_SIBLING_ORIGIN, sec_fetch_site="") is _ORIGIN


@pytest.mark.unit
class TestOriginFallback:
    """Rules 3 and 4, without `Sec-Fetch-Site`."""

    @pytest.mark.parametrize("origin", [None, ""])
    def test_absent_or_empty_origin_is_accepted(self, origin: str | None) -> None:
        assert _decide(origin=origin) is None

    @pytest.mark.parametrize(
        ("origin", "host"),
        [
            pytest.param(_API_ORIGIN, _HOST, id="equal"),
            pytest.param("https://API.Example.TEST", _HOST, id="origin-case"),
            pytest.param(_API_ORIGIN, "API.EXAMPLE.test", id="host-case"),
            pytest.param(f"http://{_HOST}", _HOST, id="scheme-not-compared"),
            pytest.param(f"https://{_HOST}:8443", f"{_HOST}:8443", id="port"),
            pytest.param("http://[2001:db8::1]:8080", "[2001:DB8::1]:8080", id="ipv6"),
        ],
    )
    def test_origin_matching_host_is_accepted(self, origin: str, host: str) -> None:
        assert _decide(origin=origin, host=host) is None

    @pytest.mark.parametrize(
        ("origin", "host"),
        [
            pytest.param(_SIBLING_ORIGIN, _HOST, id="other-host"),
            pytest.param(f"https://{_HOST}:8443", _HOST, id="other-port"),
            pytest.param(_API_ORIGIN, f"{_HOST}:443", id="default-port-in-host"),
            pytest.param(f"https://{_HOST}:", f"{_HOST}:", id="empty-port"),
            pytest.param("null", _HOST, id="null"),
            pytest.param(_API_ORIGIN, None, id="no-host"),
            pytest.param(_API_ORIGIN, "", id="empty-host-header"),
            pytest.param(f"{_API_ORIGIN}/", _HOST, id="path-slash"),
            pytest.param(f"{_API_ORIGIN}/api", _HOST, id="path"),
            pytest.param(f"{_API_ORIGIN}?q", _HOST, id="query"),
            pytest.param(f"{_API_ORIGIN}#f", _HOST, id="fragment"),
            pytest.param(f"https://user@{_HOST}", _HOST, id="userinfo"),
            pytest.param("https://", "", id="empty-origin-host"),
            pytest.param(f"://{_HOST}", _HOST, id="empty-scheme"),
            pytest.param(f"1https://{_HOST}", _HOST, id="invalid-scheme"),
            pytest.param(_HOST, _HOST, id="no-scheme"),
            pytest.param(f"https://{_HOST} ", _HOST, id="trailing-space"),
            pytest.param(f"https://{_HOST}\xa0", f"{_HOST}\xa0", id="other-space"),
            pytest.param("https://É.example.test", "é.example.test", id="non-ascii"),
        ],
    )
    def test_any_other_origin_is_rejected(self, origin: str, host: str | None) -> None:
        assert _decide(origin=origin, host=host) is _ORIGIN


class _RecordingApp:
    """An ASGI app that records the requests it receives and answers 200."""

    def __init__(self) -> None:
        self.scopes: list[Scope] = []

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        self.scopes.append(scope)
        if scope["type"] == "http":
            await PlainTextResponse("reached")(scope, receive, send)


async def _request(
    headers: Sequence[tuple[str, str]],
    *,
    method: str = "POST",
    trusted_origins: Sequence[str] = (),
) -> tuple[Response, _RecordingApp]:
    inner = _RecordingApp()
    protected = CrossOriginProtectionMiddleware(inner, trusted_origins=trusted_origins)
    async with AsyncClient(
        transport=ASGITransport(app=protected), base_url=f"https://{_HOST}"
    ) as client:
        response = await client.request(method, "/resource", headers=list(headers))
    return response, inner


def _assert_rejected(response: Response, inner: _RecordingApp) -> None:
    assert response.status_code == 403
    assert response.json() == {
        "code": "AUTH_CROSS_ORIGIN_REJECTED",
        "detail": REJECTION_DETAIL,
    }
    assert "set-cookie" not in response.headers
    assert inner.scopes == []


@pytest.mark.unit
class TestMiddleware:
    async def test_rejected_request_never_reaches_the_app(self) -> None:
        response, inner = await _request([("Sec-Fetch-Site", "cross-site")])

        _assert_rejected(response, inner)

    async def test_accepted_request_reaches_the_app(self) -> None:
        response, inner = await _request([("Sec-Fetch-Site", "same-origin")])

        assert response.status_code == 200
        assert response.text == "reached"
        assert len(inner.scopes) == 1

    async def test_configured_trusted_origins_are_applied(self) -> None:
        headers = [("Origin", _UI_ORIGIN), ("Sec-Fetch-Site", "cross-site")]

        accepted, _ = await _request(headers, trusted_origins=[_UI_ORIGIN])
        rejected, inner = await _request(headers, trusted_origins=[_SIBLING_ORIGIN])

        assert accepted.status_code == 200
        _assert_rejected(rejected, inner)

    @pytest.mark.parametrize(
        "headers",
        [
            pytest.param(
                [("Sec-Fetch-Site", "cross-site"), ("Sec-Fetch-Site", "same-origin")],
                id="sec-fetch-site",
            ),
            pytest.param(
                [("Origin", _SIBLING_ORIGIN), ("Origin", _API_ORIGIN)], id="origin"
            ),
        ],
    )
    async def test_only_the_first_occurrence_is_considered(
        self, headers: list[tuple[str, str]]
    ) -> None:
        rejected, inner = await _request(headers)
        accepted, _ = await _request(list(reversed(headers)))

        _assert_rejected(rejected, inner)
        assert accepted.status_code == 200

    @pytest.mark.parametrize("header", ["X-Forwarded-Host", "Forwarded"])
    async def test_forwarded_headers_are_not_consulted(self, header: str) -> None:
        value = "sibling.example.test"
        if header == "Forwarded":
            value = f"host={value}"

        response, inner = await _request([("Origin", _SIBLING_ORIGIN), (header, value)])

        _assert_rejected(response, inner)

    @pytest.mark.parametrize("method", ["GET", "HEAD", "OPTIONS"])
    async def test_safe_methods_reach_the_app(self, method: str) -> None:
        response, inner = await _request(
            [("Origin", "null"), ("Sec-Fetch-Site", "cross-site")], method=method
        )

        assert response.status_code == 200
        assert len(inner.scopes) == 1

    async def test_request_without_host_is_rejected_without_reading_the_body(
        self,
    ) -> None:
        """A raw ASGI request, since an HTTP client always sends `Host`."""
        inner = _RecordingApp()
        protected = CrossOriginProtectionMiddleware(inner, trusted_origins=())
        sent: list[Message] = []

        async def receive() -> Message:
            raise AssertionError("the request body must not be read")

        async def send(message: Message) -> None:
            sent.append(message)

        scope: dict[str, Any] = {
            "type": "http",
            "method": "POST",
            "path": "/resource",
            "headers": [(b"origin", _API_ORIGIN.encode())],
        }
        await protected(scope, receive, send)

        assert sent[0]["type"] == "http.response.start"
        assert sent[0]["status"] == 403
        assert inner.scopes == []

    async def test_non_http_scopes_pass_through(self) -> None:
        inner = _RecordingApp()
        protected = CrossOriginProtectionMiddleware(inner, trusted_origins=())

        async def receive() -> Message:
            raise AssertionError("not used")

        async def send(message: Message) -> None:
            raise AssertionError("not used")

        await protected({"type": "lifespan"}, receive, send)

        assert [scope["type"] for scope in inner.scopes] == ["lifespan"]


@pytest.mark.unit
class TestRegistration:
    """`app.main` registers the protection with `CORS_ORIGINS`, inside
    `RequestIDMiddleware` and outside `CORSMiddleware`."""

    def test_trusts_exactly_the_configured_origins(self) -> None:
        registrations = [
            kwargs
            for cls, _, kwargs in main_module.app.user_middleware
            if cls is CrossOriginProtectionMiddleware
        ]

        assert registrations == [{"trusted_origins": settings.cors_origins}]
        assert registrations[0]["trusted_origins"] is settings.cors_origins

    def test_runs_after_request_ids_and_before_cors(self) -> None:
        # `user_middleware` lists the outermost middleware first.
        classes = [cls for cls, _, _ in main_module.app.user_middleware]

        assert classes == [
            RequestIDMiddleware,
            CrossOriginProtectionMiddleware,
            CORSMiddleware,
        ]
