"""End-to-end tests of cross-origin request protection through the
registered application.

See `docs/features/identity/authentication.md` (Cross-Origin Request
Protection), `docs/api-spec.md` (Cross-Origin Request Protection, Method
Response Derivation), and `docs/features/platform/testing-strategy.md`
(Authentication and Session, Cross-origin request protection). The decision
rules and the middleware in isolation are covered in
`tests/test_core/test_cross_origin.py`; these tests prove the registration
order, that the rejection precedes routing, body decoding, and
authentication, that a rejected request has no effect, the log record, and
the OpenAPI document. The test client's base URL makes `Host` equal `test`.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import secrets
from collections.abc import Awaitable, Callable, Iterator
from unittest.mock import AsyncMock

import pytest
import redis.asyncio as redis_asyncio
from fastapi import routing as fastapi_routing
from fastapi.routing import APIRoute
from httpx import AsyncClient, Response
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api import dependencies
from app.api.dependencies import SESSION_COOKIE_NAME
from app.core.cross_origin import REJECTION_DETAIL, SAFE_METHODS
from app.core.enums import Role, SessionCreationReason
from app.main import app
from app.models.api_key import ApiKey
from app.models.identity_audit_event import IdentityAuditEvent
from app.models.session import Session
from app.models.user import User
from app.models.user_role import UserRole
from app.services import api_key_service
from app.services.local_auth_service import guard_and_increment
from app.services.session_service import create_session

_LOGOUT = "/api/v1/auth/logout"
_SIBLING_ORIGIN = "https://sibling.example.test"
_CROSS_SITE = {"Sec-Fetch-Site": "cross-site"}
_SAME_ORIGIN = {"Sec-Fetch-Site": "same-origin"}
_REJECTED_SEC_FETCH_SITE = ["same-site", "cross-site", "Same-Origin", "fictional"]
_ACCEPTED_SEC_FETCH_SITE = ["same-origin", "none"]
_LOGGER = "app.core.cross_origin"


def _unsafe_operations() -> Iterator[tuple[str, str]]:
    """Every `(method, path)` with an unsafe method that the registered
    application serves, with each path parameter replaced by `x`."""
    for context in fastapi_routing.iter_route_contexts(app.routes):
        if not isinstance(context.original_route, APIRoute):
            continue
        path = re.sub(r"\{[^}]+\}", "x", context.path_format or "")
        for method in sorted(context.methods or ()):
            if method not in SAFE_METHODS:
                yield method, path


_UNSAFE_OPERATIONS = list(_unsafe_operations())


def _assert_rejected(response: Response) -> None:
    assert response.status_code == 403
    assert response.json() == {
        "code": "AUTH_CROSS_ORIGIN_REJECTED",
        "detail": REJECTION_DETAIL,
    }
    assert response.headers["x-request-id"]
    assert "set-cookie" not in response.headers


def _assert_not_rejected(response: Response) -> None:
    assert response.status_code != 403
    if response.content:
        assert response.json().get("code") != "AUTH_CROSS_ORIGIN_REJECTED"


async def _session_token(db_session: AsyncSession, user: User) -> str:
    created = await create_session(
        db_session, user, SessionCreationReason.LOCAL_LOGIN, expected_password_hash=None
    )
    assert created is not None
    return created.token


def _api_key_credential() -> tuple[str, str]:
    """`(plaintext_token, sha256_hex_digest)` for a synthetic key."""
    token = "stl_ak_" + secrets.token_hex(16)
    return token, hashlib.sha256(token.encode("utf-8")).hexdigest()


@pytest.mark.e2e
class TestEveryUnsafeOperation:
    def test_registered_application_serves_unsafe_operations(self) -> None:
        methods = {method for method, _ in _UNSAFE_OPERATIONS}

        assert {"POST", "PATCH", "DELETE"} <= methods

    @pytest.mark.parametrize(("method", "path"), _UNSAFE_OPERATIONS)
    async def test_forged_request_returns_403_and_same_origin_reaches_endpoint(
        self, client: AsyncClient, method: str, path: str
    ) -> None:
        """Derived from the registered routes, so a new endpoint is covered
        without a new test. An accepted request has the outcome of the same
        request without `Sec-Fetch-Site`; without a credential that is the
        endpoint's own response, such as its 401."""
        for value in _REJECTED_SEC_FETCH_SITE:
            response = await client.request(
                method, path, headers={"Sec-Fetch-Site": value}
            )
            _assert_rejected(response)

        baseline = await client.request(method, path)
        _assert_not_rejected(baseline)
        for value in _ACCEPTED_SEC_FETCH_SITE:
            response = await client.request(
                method, path, headers={"Sec-Fetch-Site": value}
            )
            assert (response.status_code, response.content) == (
                baseline.status_code,
                baseline.content,
            )


@pytest.mark.e2e
class TestOriginFallback:
    """Without `Sec-Fetch-Site`, or with an empty one, through the registered
    application, whose test client sends `Host: test`; an accepted logout
    without a credential returns its 401."""

    @pytest.mark.parametrize(
        "headers",
        [
            pytest.param({"Origin": "http://test"}, id="same-host"),
            pytest.param({"Origin": "https://TEST"}, id="other-case-and-scheme"),
            pytest.param(
                {"Origin": "http://test", "Sec-Fetch-Site": ""}, id="empty-sfs"
            ),
            pytest.param({"Origin": ""}, id="empty-origin"),
            pytest.param({}, id="no-origin"),
        ],
    )
    async def test_origin_matching_host_or_absent_origin_is_accepted(
        self, client: AsyncClient, headers: dict[str, str]
    ) -> None:
        response = await client.post(_LOGOUT, headers=headers)

        assert response.status_code == 401
        assert response.json()["code"] == "AUTH_NOT_AUTHENTICATED"

    async def test_origin_of_another_host_is_rejected(
        self, client: AsyncClient
    ) -> None:
        """The other rejected forms are covered by the decision tests in
        `tests/test_core/test_cross_origin.py`; this proves the request's
        `Host` reaches the decision in the registered application."""
        _assert_rejected(
            await client.post(_LOGOUT, headers={"Origin": _SIBLING_ORIGIN})
        )


@pytest.mark.e2e
class TestSafeMethods:
    async def test_get_cross_site_is_not_rejected(self, client: AsyncClient) -> None:
        response = await client.get(
            "/health", headers={"Origin": "null", "Sec-Fetch-Site": "cross-site"}
        )

        assert response.status_code == 200

    @pytest.mark.parametrize("method", ["HEAD", "OPTIONS"])
    async def test_head_and_options_cross_site_reach_routing(
        self, client: AsyncClient, method: str
    ) -> None:
        response = await client.request(method, _LOGOUT, headers=_CROSS_SITE)

        assert response.status_code == 405

    async def test_cors_preflight_from_unlisted_origin_reaches_cors(
        self, client: AsyncClient
    ) -> None:
        """A preflight from an origin that is not configured receives the CORS
        middleware's own rejection, not the protection's."""
        response = await client.options(
            _LOGOUT,
            headers={
                "Origin": _SIBLING_ORIGIN,
                "Access-Control-Request-Method": "POST",
                "Sec-Fetch-Site": "same-site",
            },
        )

        assert response.status_code == 400
        assert "access-control-allow-origin" not in response.headers


@pytest.mark.e2e
class TestPrecedence:
    """The rejection precedes routing, body decoding, the shared
    request-input constraints, and authentication; the same request with
    `same-origin` receives the outcome it would otherwise have."""

    @pytest.mark.parametrize(
        ("method", "path", "accepted_status"),
        [
            pytest.param("POST", "/api/v1/not-an-endpoint", 404, id="unknown-path"),
            pytest.param("POST", "/health", 405, id="unserved-method"),
            pytest.param("PUT", _LOGOUT, 405, id="method-no-endpoint-serves"),
            pytest.param("PUT", "/not-an-endpoint", 404, id="put-unknown-path"),
        ],
    )
    async def test_cross_site_rejection_precedes_routing(
        self, client: AsyncClient, method: str, path: str, accepted_status: int
    ) -> None:
        _assert_rejected(await client.request(method, path, headers=_CROSS_SITE))
        accepted = await client.request(method, path, headers=_SAME_ORIGIN)
        assert accepted.status_code == accepted_status

    async def test_cross_site_rejection_precedes_body_decoding(
        self, client: AsyncClient
    ) -> None:
        malformed = b'{"username": '
        json_type = {"Content-Type": "application/json"}

        rejected = await client.post(
            "/api/v1/auth/login",
            content=malformed,
            headers={**json_type, **_CROSS_SITE},
        )
        accepted = await client.post(
            "/api/v1/auth/login",
            content=malformed,
            headers={**json_type, **_SAME_ORIGIN},
        )

        _assert_rejected(rejected)
        assert accepted.status_code == 422

    async def test_cross_site_rejection_precedes_input_constraints(
        self, client: AsyncClient
    ) -> None:
        path = "/api/v1/tickets/SNTL-%00/ignore"

        _assert_rejected(await client.post(path, headers=_CROSS_SITE))
        accepted = await client.post(path, headers=_SAME_ORIGIN)
        assert accepted.status_code == 422


@pytest.mark.e2e
class TestNoEffect:
    async def test_rejected_logout_keeps_the_session(
        self,
        client: AsyncClient,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        user = await user_factory()
        client.cookies.set(SESSION_COOKIE_NAME, await _session_token(db_session, user))

        rejected = await client.post(_LOGOUT, headers=_CROSS_SITE)

        _assert_rejected(rejected)
        session = await db_session.scalar(select(Session).filter_by(user_id=user.id))
        assert session is not None
        assert session.is_active is True

        accepted = await client.post(_LOGOUT, headers=_SAME_ORIGIN)
        assert accepted.status_code == 204
        assert "set-cookie" in accepted.headers
        await db_session.refresh(session)
        assert session.is_active is False

    async def test_rejected_state_change_has_no_mutation_or_audit(
        self,
        client: AsyncClient,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        user_role_factory: Callable[..., Awaitable[UserRole]],
        redis_client: redis_asyncio.Redis,
    ) -> None:
        admin = await user_factory()
        await user_role_factory(user_id=admin.id, role=Role.ADMIN.value)
        target = await user_factory()
        client.cookies.set(SESSION_COOKIE_NAME, await _session_token(db_session, admin))
        path = f"/api/v1/admin/users/{target.id}/deactivate"
        audit_events = (
            select(func.count())
            .select_from(IdentityAuditEvent)
            .where(IdentityAuditEvent.target_user_id == target.id)
        )

        rejected = await client.post(path, headers=_CROSS_SITE)

        _assert_rejected(rejected)
        await db_session.refresh(target)
        assert target.active is True
        assert await db_session.scalar(audit_events) == 0

        accepted = await client.post(path, headers=_SAME_ORIGIN)
        assert accepted.status_code == 200
        await db_session.refresh(target)
        assert target.active is False
        assert await db_session.scalar(audit_events) == 1

    async def test_rejected_api_key_request_is_not_looked_up_or_touched(
        self,
        client: AsyncClient,
        user_factory: Callable[..., Awaitable[User]],
        api_key_factory: Callable[..., Awaitable[ApiKey]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        user = await user_factory()
        token, digest = _api_key_credential()
        await api_key_factory(user_id=user.id, key_hash=digest)
        lookup = AsyncMock(wraps=api_key_service.get_key_by_hash)
        touch = AsyncMock()
        monkeypatch.setattr(api_key_service, "get_key_by_hash", lookup)
        monkeypatch.setattr(dependencies._last_used_debouncer, "touch", touch)
        headers = {"Authorization": f"Bearer {token}"}

        rejected = await client.post(
            "/api/v1/fetchers/x/trigger", headers={**headers, **_CROSS_SITE}
        )

        _assert_rejected(rejected)
        lookup.assert_not_awaited()
        touch.assert_not_awaited()

        await client.post(
            "/api/v1/fetchers/x/trigger", headers={**headers, **_SAME_ORIGIN}
        )
        lookup.assert_awaited_once()
        touch.assert_awaited_once()

    async def test_rejected_login_creates_no_session_and_keeps_the_counter(
        self,
        client: AsyncClient,
        db_session: AsyncSession,
        local_user_factory: Callable[..., Awaitable[tuple[User, str]]],
        redis_client: redis_asyncio.Redis,
    ) -> None:
        user, password = await local_user_factory()
        await guard_and_increment(user.username)
        counter_key = f"login_attempts:{user.username}"
        body = {"username": user.username, "password": password}
        sessions = select(func.count()).select_from(Session).filter_by(user_id=user.id)

        rejected = await client.post(
            "/api/v1/auth/login", json=body, headers=_CROSS_SITE
        )

        _assert_rejected(rejected)
        assert await redis_client.get(counter_key) == "1"
        assert await db_session.scalar(sessions) == 0
        await db_session.refresh(user)
        assert user.last_login_at is None

        # Controls: the same requests, accepted, change both.
        wrong_password = {**body, "password": f"{password}-wrong"}
        failed = await client.post("/api/v1/auth/login", json=wrong_password)
        assert failed.status_code == 401
        assert await redis_client.get(counter_key) == "2"
        accepted = await client.post("/api/v1/auth/login", json=body)
        assert accepted.status_code == 200
        assert await db_session.scalar(sessions) == 1


@pytest.mark.e2e
class TestCredentialIndependence:
    @pytest.mark.parametrize("credential", ["none", "cookie", "bearer", "api_key"])
    async def test_decision_is_identical_for_every_credential(
        self,
        client: AsyncClient,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        api_key_factory: Callable[..., Awaitable[ApiKey]],
        credential: str,
    ) -> None:
        user = await user_factory()
        headers: dict[str, str] = {}
        if credential == "cookie":
            client.cookies.set(
                SESSION_COOKIE_NAME, await _session_token(db_session, user)
            )
        elif credential == "bearer":
            token = await _session_token(db_session, user)
            headers["Authorization"] = f"Bearer {token}"
        elif credential == "api_key":
            token, digest = _api_key_credential()
            await api_key_factory(user_id=user.id, key_hash=digest)
            headers["Authorization"] = f"Bearer {token}"

        _assert_rejected(await client.post(_LOGOUT, headers={**headers, **_CROSS_SITE}))
        _assert_not_rejected(
            await client.post(_LOGOUT, headers={**headers, **_SAME_ORIGIN})
        )


def _rejection_records(caplog: pytest.LogCaptureFixture) -> list[dict[str, object]]:
    return [
        record.msg
        for record in caplog.records
        if record.name == _LOGGER
        and isinstance(record.msg, dict)
        and record.msg.get("event") == "cross_origin_request_rejected"
    ]


@pytest.mark.e2e
class TestRejectionLog:
    @pytest.mark.parametrize(
        ("headers", "reason"),
        [
            pytest.param(
                {"Origin": _SIBLING_ORIGIN, "Sec-Fetch-Site": "same-site"},
                "sec_fetch_site",
                id="sec-fetch-site",
            ),
            pytest.param({"Origin": _SIBLING_ORIGIN}, "origin", id="origin"),
        ],
    )
    async def test_rejection_emits_one_bounded_warning(
        self,
        client: AsyncClient,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        caplog: pytest.LogCaptureFixture,
        headers: dict[str, str],
        reason: str,
    ) -> None:
        token = await _session_token(db_session, await user_factory())
        path = "/api/v1/tickets/SNTL-4242/ignore"

        with caplog.at_level(logging.WARNING, logger=_LOGGER):
            response = await client.post(
                path, headers={**headers, "Authorization": f"Bearer {token}"}
            )

        _assert_rejected(response)
        records = _rejection_records(caplog)
        assert len(records) == 1
        record = records[0]
        assert record["request_id"] == response.headers["x-request-id"]
        assert (record["method"], record["reason"], record["level"]) == (
            "POST",
            reason,
            "warning",
        )
        text = json.dumps(record)
        for value in [
            _SIBLING_ORIGIN,
            "sibling",
            "same-site",
            path,
            "SNTL-4242",
            token,
        ]:
            assert value not in text

    async def test_accepted_request_emits_none(
        self, client: AsyncClient, caplog: pytest.LogCaptureFixture
    ) -> None:
        with caplog.at_level(logging.WARNING, logger=_LOGGER):
            await client.post(_LOGOUT, headers=_SAME_ORIGIN)
            await client.get("/health", headers=_CROSS_SITE)

        assert _rejection_records(caplog) == []


@pytest.mark.unit
class TestOpenApiDocument:
    def test_every_unsafe_operation_and_no_other_documents_the_rejection(
        self,
    ) -> None:
        documented: dict[str, bool] = {}
        for path, operations in app.openapi()["paths"].items():
            for method, operation in operations.items():
                descriptions = " ".join(
                    response.get("description", "")
                    for response in operation.get("responses", {}).values()
                )
                names_code = "`AUTH_CROSS_ORIGIN_REJECTED`" in descriptions
                in_403 = "`AUTH_CROSS_ORIGIN_REJECTED`" in operation.get(
                    "responses", {}
                ).get("403", {}).get("description", "")
                assert names_code == in_403, (method, path)
                documented[f"{method.upper()} {path}"] = in_403

        unsafe = {
            key
            for key, in_403 in documented.items()
            if key.split()[0] not in SAFE_METHODS
        }
        assert unsafe
        assert all(key.split()[1].startswith("/api/v1/") for key in unsafe)
        assert {key for key, in_403 in documented.items() if in_403} == unsafe
