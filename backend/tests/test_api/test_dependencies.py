"""Unit and end-to-end tests for shared authentication and authorization
FastAPI dependencies (backend/app/api/dependencies.py).

See docs/features/identity/authentication.md (Authenticated Principal,
Middleware: get_current_user, API key validation, Session-Only
Authentication Dependency) and docs/features/identity/rbac.md
(require_capability() Dependency) for the contract under test.

This work item (#117) introduces no domain endpoint — a minimal
standalone FastAPI app (`_build_test_app()`) exercises the real
dependencies through the actual ASGI/HTTP layer without touching the
production `app`'s route table.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import logging
import secrets
import uuid
from collections.abc import AsyncGenerator, Awaitable, Callable
from dataclasses import FrozenInstanceError, fields
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any, cast
from unittest.mock import AsyncMock

import pytest
import redis.asyncio as redis_asyncio
from fastapi import Depends, FastAPI, Request, Response
from fastapi.responses import JSONResponse
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.api import dependencies
from app.api.dependencies import (
    SESSION_COOKIE_NAME,
    AuthenticatedPrincipal,
    AuthenticatedTicketCaller,
    CurrentUser,
    LastUsedDebouncer,
    OptionalCurrentUser,
    OptionalTicketCaller,
    UnknownKeyWarningLimiter,
    require_accessible_ticket,
    require_capability,
    require_session_authentication,
)
from app.config import settings
from app.core.enums import Capability, CredentialKind, Role, SessionCreationReason
from app.core.errors import AppError, ErrorCode
from app.core.identifiers import format_ticket_id
from app.core.jwt import issue_token
from app.database import get_db
from app.models.api_key import ApiKey
from app.models.session import Session
from app.models.ticket import Ticket
from app.models.user import User
from app.services import api_key_service, ticket_service, user_service
from app.services.session_service import create_session
from app.services.ticket_service import ResolvedTicket
from app.services.ticket_visibility import TicketCaller

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _dependency_log_text(caplog: pytest.LogCaptureFixture) -> str:
    """Join only log records emitted by `app.api.dependencies`.

    Scoping to this module's own records avoids false negatives/positives
    from unrelated propagated records (mirrors the identical helper in
    test_services/test_api_key_service.py and test_session_service.py).
    """
    return "\n".join(
        record.getMessage()
        for record in caplog.records
        if record.name == "app.api.dependencies"
    )


def _make_api_key_credential() -> tuple[str, str]:
    """Return `(plaintext_token, sha256_hex_digest)` for a synthetic key."""
    token = "stl_ak_" + secrets.token_hex(16)
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
    return token, digest


@pytest.fixture(autouse=True)
def _reset_authentication_state() -> None:
    """Reset the module-level limiter/debouncer singletons before each
    test — mirrors `session_service._redis_outage_active`'s per-test
    reset (docs/features/platform/testing-strategy.md, Test
    Independence). Autouse is scoped to this test module only.
    """
    dependencies._unknown_key_limiter = UnknownKeyWarningLimiter()
    dependencies._last_used_debouncer = LastUsedDebouncer()


def _build_test_app() -> FastAPI:
    test_app = FastAPI()

    @test_app.exception_handler(AppError)
    async def _app_error_handler(request: Request, exc: AppError) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content={"code": exc.code.value, "detail": exc.detail},
            headers=exc.headers,
        )

    @test_app.get("/whoami")
    async def whoami(principal: CurrentUser) -> dict[str, str]:
        return {
            "user_id": str(principal.user.id),
            "credential_kind": principal.credential_kind.value,
        }

    @test_app.get("/optional-whoami")
    async def optional_whoami(
        principal: OptionalCurrentUser,
    ) -> dict[str, str | None]:
        if principal is None:
            return {"user_id": None, "credential_kind": None}
        return {
            "user_id": str(principal.user.id),
            "credential_kind": principal.credential_kind.value,
        }

    @test_app.get("/capability-protected")
    async def capability_protected(
        principal: Annotated[
            AuthenticatedPrincipal,
            Depends(require_capability(Capability.MANAGE_USERS)),
        ],
    ) -> dict[str, str]:
        return {"user_id": str(principal.user.id)}

    def _caller_body(caller: TicketCaller) -> dict[str, str | None]:
        return {
            "user_id": None if caller.user_id is None else str(caller.user_id),
            "scope": None if caller.scope is None else caller.scope.value,
        }

    @test_app.get("/ticket-caller")
    async def ticket_caller(caller: AuthenticatedTicketCaller) -> dict[str, str | None]:
        return _caller_body(caller)

    @test_app.get("/optional-ticket-caller")
    async def optional_ticket_caller(
        caller: OptionalTicketCaller,
    ) -> dict[str, str | None]:
        return _caller_body(caller)

    @test_app.get("/tickets/{ticket_id}/accessible")
    async def accessible_ticket(
        caller: AuthenticatedTicketCaller,
        ticket: Annotated[ResolvedTicket, Depends(require_accessible_ticket)],
    ) -> dict[str, int | str | None]:
        return {"sequence_id": ticket.sequence_id, **_caller_body(caller)}

    @test_app.get("/session-only")
    async def session_only(
        principal: Annotated[
            AuthenticatedPrincipal, Depends(require_session_authentication)
        ],
    ) -> dict[str, str]:
        return {"user_id": str(principal.user.id)}

    return test_app


@pytest.fixture
def test_app() -> FastAPI:
    return _build_test_app()


@pytest.fixture
async def dep_client(
    test_app: FastAPI, db_session: AsyncSession
) -> AsyncGenerator[AsyncClient]:
    """An `AsyncClient` bound to the standalone dependency test app,
    sharing the test transaction. Mirrors `tests/test_api/test_auth.py`'s
    `auth_client` fixture: `db_session`'s savepoint-based rollback does
    not by itself execute `get_db`'s post-yield commit, but sliding
    refresh cookie assertions and role-change-on-next-request scenarios
    need real request/response round trips through the ASGI layer.
    """

    async def _override_get_db() -> AsyncGenerator[AsyncSession]:
        try:
            yield db_session
            await db_session.commit()
        except Exception:
            await db_session.rollback()
            raise

    test_app.dependency_overrides[get_db] = _override_get_db
    async with AsyncClient(
        transport=ASGITransport(app=test_app), base_url="http://test"
    ) as client:
        yield client


# ---------------------------------------------------------------------------
# AuthenticatedPrincipal
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAuthenticatedPrincipal:
    def test_carries_exactly_user_and_credential_kind(self) -> None:
        assert {f.name for f in fields(AuthenticatedPrincipal)} == {
            "user",
            "credential_kind",
        }

    def test_is_frozen(self) -> None:
        principal = AuthenticatedPrincipal(
            user=User(username="jdoe", email="jdoe@example.com"),
            credential_kind=CredentialKind.JWT,
        )
        with pytest.raises(FrozenInstanceError):
            principal.credential_kind = CredentialKind.API_KEY  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Error factories
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestErrorFactories:
    def test_unauthenticated_error_shape(self) -> None:
        error = dependencies.unauthenticated_error()
        assert error.status_code == 401
        assert error.code == ErrorCode.AUTH_NOT_AUTHENTICATED
        assert error.detail == "Authentication required"

    def test_unauthenticated_error_returns_fresh_instance(self) -> None:
        first = dependencies.unauthenticated_error()
        second = dependencies.unauthenticated_error()
        assert first is not second

    def test_user_not_found_error_shape(self) -> None:
        error = dependencies.user_not_found_error()
        assert error.status_code == 404
        assert error.code == ErrorCode.USER_NOT_FOUND
        assert error.detail == "User not found."

    def test_ticket_not_found_error_shape(self) -> None:
        error = dependencies.ticket_not_found_error()
        assert error.status_code == 404
        assert error.code == ErrorCode.TICKET_NOT_FOUND
        assert error.detail == "Ticket not found."
        assert error.headers is None


# ---------------------------------------------------------------------------
# UnknownKeyWarningLimiter
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestUnknownKeyWarningLimiter:
    def test_first_attempt_returns_zero_suppressed(self) -> None:
        limiter = UnknownKeyWarningLimiter()
        assert limiter.record("203.0.113.5", datetime.now(UTC)) == 0

    def test_within_window_suppresses_and_accumulates(self) -> None:
        limiter = UnknownKeyWarningLimiter()
        now = datetime.now(UTC)
        limiter.record("203.0.113.5", now)

        assert limiter.record("203.0.113.5", now + timedelta(seconds=10)) is None
        assert limiter.record("203.0.113.5", now + timedelta(seconds=20)) is None

    def test_after_window_elapses_emits_with_suppressed_count(self) -> None:
        limiter = UnknownKeyWarningLimiter()
        now = datetime.now(UTC)
        limiter.record("203.0.113.5", now)
        limiter.record("203.0.113.5", now + timedelta(seconds=10))
        limiter.record("203.0.113.5", now + timedelta(seconds=20))

        emitted = limiter.record("203.0.113.5", now + timedelta(seconds=61))

        assert emitted == 2

    def test_window_boundary_at_exactly_60_seconds_emits(self) -> None:
        limiter = UnknownKeyWarningLimiter()
        now = datetime.now(UTC)
        limiter.record("203.0.113.5", now)

        assert limiter.record("203.0.113.5", now + timedelta(seconds=60)) == 0

    def test_distinct_peers_are_independent(self) -> None:
        limiter = UnknownKeyWarningLimiter()
        now = datetime.now(UTC)
        limiter.record("203.0.113.5", now)

        assert limiter.record("198.51.100.7", now) == 0

    def test_inactivity_eviction_resets_state(self) -> None:
        limiter = UnknownKeyWarningLimiter()
        now = datetime.now(UTC)
        limiter.record("203.0.113.5", now)

        later = now + timedelta(seconds=301)
        assert limiter.record("203.0.113.5", later) == 0

    def test_lru_eviction_when_max_entries_exceeded(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(dependencies, "_LIMITER_MAX_ENTRIES", 2)
        limiter = UnknownKeyWarningLimiter()
        now = datetime.now(UTC)
        limiter.record("peer-a", now)
        limiter.record("peer-b", now)
        limiter.record("peer-c", now)  # evicts peer-a (least-recently-seen)

        assert "peer-a" not in limiter._entries
        assert "peer-b" in limiter._entries
        assert "peer-c" in limiter._entries


@pytest.mark.unit
class TestRecordUnknownKeyAttempt:
    """`_record_unknown_key_attempt()` peer extraction — isolated from
    the HTTP layer via a minimal duck-typed request."""

    class _FakeClient:
        def __init__(self, host: str) -> None:
            self.host = host

    class _FakeRequest:
        def __init__(self, client: Any) -> None:
            self.client = client

    def test_uses_asgi_peer_host(self, caplog: pytest.LogCaptureFixture) -> None:
        request = self._FakeRequest(client=self._FakeClient(host="203.0.113.5"))

        with caplog.at_level(logging.WARNING, logger="app.api.dependencies"):
            dependencies._record_unknown_key_attempt(
                cast(Request, request), datetime.now(UTC)
            )

        text = _dependency_log_text(caplog)
        assert "api_key_validation_failed" in text
        assert "203.0.113.5" in text

    def test_none_client_uses_unknown_sentinel(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        request = self._FakeRequest(client=None)

        with caplog.at_level(logging.WARNING, logger="app.api.dependencies"):
            dependencies._record_unknown_key_attempt(
                cast(Request, request), datetime.now(UTC)
            )

        assert "unknown" in _dependency_log_text(caplog)

    def test_second_attempt_within_window_is_not_logged(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        request = self._FakeRequest(client=self._FakeClient(host="203.0.113.5"))
        now = datetime.now(UTC)

        with caplog.at_level(logging.WARNING, logger="app.api.dependencies"):
            dependencies._record_unknown_key_attempt(cast(Request, request), now)
            caplog.clear()
            dependencies._record_unknown_key_attempt(
                cast(Request, request), now + timedelta(seconds=10)
            )

        assert _dependency_log_text(caplog) == ""


# ---------------------------------------------------------------------------
# LastUsedDebouncer (isolated — no real database)
# ---------------------------------------------------------------------------


class _FakeSession:
    def __init__(self) -> None:
        self.committed = False
        self.rolled_back = False

    async def __aenter__(self) -> _FakeSession:
        return self

    async def __aexit__(self, *exc: object) -> None:
        return None

    async def commit(self) -> None:
        self.committed = True

    async def rollback(self) -> None:
        self.rolled_back = True


@pytest.mark.unit
class TestLastUsedDebouncer:
    def _patch_factory(
        self, monkeypatch: pytest.MonkeyPatch, session: _FakeSession
    ) -> None:
        monkeypatch.setattr(
            dependencies, "get_last_used_session_factory", lambda: lambda: session
        )

    async def test_first_touch_writes_and_commits(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        session = _FakeSession()
        self._patch_factory(monkeypatch, session)
        calls: list[tuple[uuid.UUID, datetime]] = []

        async def _fake_update(s: Any, key_id: uuid.UUID, used_at: datetime) -> bool:
            calls.append((key_id, used_at))
            return True

        monkeypatch.setattr(api_key_service, "update_last_used_at", _fake_update)
        debouncer = LastUsedDebouncer()
        key_id = uuid.uuid4()
        now = datetime.now(UTC)

        await debouncer.touch(key_id, now)

        assert calls == [(key_id, now)]
        assert session.committed is True
        assert session.rolled_back is False

    async def test_second_touch_within_window_is_skipped(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        session = _FakeSession()
        self._patch_factory(monkeypatch, session)
        call_count = 0

        async def _fake_update(s: Any, key_id: uuid.UUID, used_at: datetime) -> bool:
            nonlocal call_count
            call_count += 1
            return True

        monkeypatch.setattr(api_key_service, "update_last_used_at", _fake_update)
        debouncer = LastUsedDebouncer()
        key_id = uuid.uuid4()
        now = datetime.now(UTC)
        await debouncer.touch(key_id, now)

        await debouncer.touch(key_id, now + timedelta(seconds=30))

        assert call_count == 1

    async def test_touch_after_window_writes_again(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        session = _FakeSession()
        self._patch_factory(monkeypatch, session)
        call_count = 0

        async def _fake_update(s: Any, key_id: uuid.UUID, used_at: datetime) -> bool:
            nonlocal call_count
            call_count += 1
            return True

        monkeypatch.setattr(api_key_service, "update_last_used_at", _fake_update)
        debouncer = LastUsedDebouncer()
        key_id = uuid.uuid4()
        now = datetime.now(UTC)
        await debouncer.touch(key_id, now)

        await debouncer.touch(key_id, now + timedelta(seconds=61))

        assert call_count == 2

    async def test_failure_rolls_back_and_does_not_advance_debounce(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        session = _FakeSession()
        self._patch_factory(monkeypatch, session)

        async def _fake_update_fails(
            s: Any, key_id: uuid.UUID, used_at: datetime
        ) -> bool:
            raise RuntimeError("simulated database failure")

        monkeypatch.setattr(api_key_service, "update_last_used_at", _fake_update_fails)
        debouncer = LastUsedDebouncer()
        key_id = uuid.uuid4()
        now = datetime.now(UTC)

        await debouncer.touch(key_id, now)  # must not raise

        assert session.rolled_back is True
        assert session.committed is False
        assert key_id not in debouncer._last_write_at

    async def test_concurrent_touches_for_same_key_write_once(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        session = _FakeSession()
        self._patch_factory(monkeypatch, session)
        call_count = 0

        async def _fake_update(s: Any, key_id: uuid.UUID, used_at: datetime) -> bool:
            nonlocal call_count
            call_count += 1
            await asyncio.sleep(0.01)
            return True

        monkeypatch.setattr(api_key_service, "update_last_used_at", _fake_update)
        debouncer = LastUsedDebouncer()
        key_id = uuid.uuid4()
        now = datetime.now(UTC)

        await asyncio.gather(
            debouncer.touch(key_id, now),
            debouncer.touch(key_id, now),
        )

        assert call_count == 1


@pytest.mark.integration
class TestLastUsedDebouncerIntegration:
    async def test_touch_persists_last_used_at_through_real_session(
        self,
        db_session: AsyncSession,
        api_key_factory: Callable[..., Awaitable[ApiKey]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Exercise the full path: ``get_last_used_session_factory()`` →
        real session → ``update_last_used_at()`` → commit, verifying
        that the dedicated transaction actually persists the write.

        Uses the savepoint-nested ``db_session`` as the backing session
        so the outer transaction rollback at teardown cleans up the
        write — no leaked state.
        """
        key = await api_key_factory(last_used_at=None)

        @contextlib.asynccontextmanager
        async def _session_cm() -> AsyncGenerator[AsyncSession]:
            yield db_session

        monkeypatch.setattr(
            dependencies,
            "get_last_used_session_factory",
            lambda: _session_cm,
        )
        debouncer = LastUsedDebouncer()
        now = datetime.now(UTC)

        await debouncer.touch(key.id, now)

        await db_session.refresh(key)
        assert key.last_used_at == now


# ---------------------------------------------------------------------------
# get_current_user — JWT path (e2e)
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestGetCurrentUserJwt:
    async def test_valid_jwt_cookie_returns_principal(
        self,
        dep_client: AsyncClient,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        redis_client: redis_asyncio.Redis,
    ) -> None:
        user = await user_factory()
        created = await create_session(
            db_session,
            user,
            SessionCreationReason.LOCAL_LOGIN,
            expected_password_hash=None,
        )
        assert created is not None
        dep_client.cookies.set(SESSION_COOKIE_NAME, created.token)

        response = await dep_client.get("/whoami")

        assert response.status_code == 200
        body = response.json()
        assert body["user_id"] == str(user.id)
        assert body["credential_kind"] == "jwt"

    async def test_bearer_takes_precedence_over_cookie(
        self,
        dep_client: AsyncClient,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        redis_client: redis_asyncio.Redis,
    ) -> None:
        bearer_user = await user_factory()
        bearer_created = await create_session(
            db_session,
            bearer_user,
            SessionCreationReason.LOCAL_LOGIN,
            expected_password_hash=None,
        )
        assert bearer_created is not None
        cookie_user = await user_factory()
        cookie_created = await create_session(
            db_session,
            cookie_user,
            SessionCreationReason.LOCAL_LOGIN,
            expected_password_hash=None,
        )
        assert cookie_created is not None
        dep_client.cookies.set(SESSION_COOKIE_NAME, cookie_created.token)

        response = await dep_client.get(
            "/whoami",
            headers={"Authorization": f"Bearer {bearer_created.token}"},
        )

        assert response.json()["user_id"] == str(bearer_user.id)

    async def test_missing_credential_returns_generic_401(
        self, dep_client: AsyncClient
    ) -> None:
        response = await dep_client.get("/whoami")

        assert response.status_code == 401
        assert response.json() == {
            "code": "AUTH_NOT_AUTHENTICATED",
            "detail": "Authentication required",
        }

    async def test_malformed_jwt_returns_generic_401(
        self, dep_client: AsyncClient
    ) -> None:
        response = await dep_client.get(
            "/whoami", headers={"Authorization": "Bearer not-a-real-token"}
        )

        assert response.status_code == 401
        assert response.json() == {
            "code": "AUTH_NOT_AUTHENTICATED",
            "detail": "Authentication required",
        }

    async def test_inactive_session_returns_generic_401(
        self,
        dep_client: AsyncClient,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        redis_client: redis_asyncio.Redis,
    ) -> None:
        user = await user_factory()
        created = await create_session(
            db_session,
            user,
            SessionCreationReason.LOCAL_LOGIN,
            expected_password_hash=None,
        )
        assert created is not None
        created.session.is_active = False
        await db_session.flush()

        response = await dep_client.get(
            "/whoami", headers={"Authorization": f"Bearer {created.token}"}
        )

        assert response.status_code == 401

    async def test_inactive_user_returns_generic_401(
        self,
        dep_client: AsyncClient,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        redis_client: redis_asyncio.Redis,
    ) -> None:
        user = await user_factory()
        created = await create_session(
            db_session,
            user,
            SessionCreationReason.LOCAL_LOGIN,
            expected_password_hash=None,
        )
        assert created is not None
        # The session must be created while the user is active; deactivate
        # afterwards so the dependency loads an inactive user with a still
        # active Session and must reject it.
        user.active = False
        await db_session.flush()

        response = await dep_client.get(
            "/whoami", headers={"Authorization": f"Bearer {created.token}"}
        )

        assert response.status_code == 401

    async def test_missing_user_returns_generic_401(
        self,
        dep_client: AsyncClient,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        redis_client: redis_asyncio.Redis,
    ) -> None:
        user = await user_factory()
        created = await create_session(
            db_session,
            user,
            SessionCreationReason.LOCAL_LOGIN,
            expected_password_hash=None,
        )
        assert created is not None
        issued = issue_token(
            user_id=uuid.uuid4(),
            session_id=created.session.id,
            issued_at=datetime.now(UTC),
            session_deadline=created.session.expires_at,
            jwt_expiry_hours=settings.jwt_expiry_hours,
            secret_key=settings.jwt_secret_key.get_secret_value(),
        )

        response = await dep_client.get(
            "/whoami", headers={"Authorization": f"Bearer {issued.token}"}
        )

        assert response.status_code == 401


@pytest.mark.e2e
class TestSlidingRefresh:
    async def test_refresh_sets_new_cookie_after_threshold(
        self,
        dep_client: AsyncClient,
        session_factory: Callable[..., Awaitable[Session]],
        redis_client: redis_asyncio.Redis,
    ) -> None:
        session = await session_factory()
        old_iat = datetime.now(UTC) - timedelta(hours=settings.jwt_expiry_hours * 0.6)
        issued = issue_token(
            user_id=session.user_id,
            session_id=session.id,
            issued_at=old_iat,
            session_deadline=session.expires_at,
            jwt_expiry_hours=settings.jwt_expiry_hours,
            secret_key=settings.jwt_secret_key.get_secret_value(),
        )

        response = await dep_client.get(
            "/whoami", headers={"Authorization": f"Bearer {issued.token}"}
        )

        assert response.status_code == 200
        assert "set-cookie" in response.headers
        assert response.headers["set-cookie"].startswith(f"{SESSION_COOKIE_NAME}=")
        assert issued.token not in response.headers["set-cookie"]

    async def test_no_refresh_before_threshold(
        self,
        dep_client: AsyncClient,
        session_factory: Callable[..., Awaitable[Session]],
        redis_client: redis_asyncio.Redis,
    ) -> None:
        session = await session_factory()
        recent_iat = datetime.now(UTC) - timedelta(
            hours=settings.jwt_expiry_hours * 0.1
        )
        issued = issue_token(
            user_id=session.user_id,
            session_id=session.id,
            issued_at=recent_iat,
            session_deadline=session.expires_at,
            jwt_expiry_hours=settings.jwt_expiry_hours,
            secret_key=settings.jwt_secret_key.get_secret_value(),
        )

        response = await dep_client.get(
            "/whoami", headers={"Authorization": f"Bearer {issued.token}"}
        )

        assert response.status_code == 200
        assert "set-cookie" not in response.headers

    async def test_api_key_never_refreshes(
        self,
        dep_client: AsyncClient,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        api_key_factory: Callable[..., Awaitable[ApiKey]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        user = await user_factory()
        token, digest = _make_api_key_credential()
        await api_key_factory(user_id=user.id, key_hash=digest)
        monkeypatch.setattr(dependencies._last_used_debouncer, "touch", AsyncMock())

        response = await dep_client.get(
            "/whoami", headers={"Authorization": f"Bearer {token}"}
        )

        assert response.status_code == 200
        assert "set-cookie" not in response.headers

    async def test_cookie_attachment_failure_does_not_fail_request(
        self,
        dep_client: AsyncClient,
        session_factory: Callable[..., Awaitable[Session]],
        redis_client: redis_asyncio.Redis,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """If `Response.set_cookie()` raises for any reason, the request
        still succeeds with the old JWT — see authentication.md, Token
        refresh notes."""
        session = await session_factory()
        old_iat = datetime.now(UTC) - timedelta(hours=settings.jwt_expiry_hours * 0.6)
        issued = issue_token(
            user_id=session.user_id,
            session_id=session.id,
            issued_at=old_iat,
            session_deadline=session.expires_at,
            jwt_expiry_hours=settings.jwt_expiry_hours,
            secret_key=settings.jwt_secret_key.get_secret_value(),
        )

        def _raise(*args: Any, **kwargs: Any) -> None:
            raise RuntimeError("simulated cookie attachment failure")

        monkeypatch.setattr(dependencies, "set_session_cookie", _raise)

        with caplog.at_level(logging.WARNING, logger="app.api.dependencies"):
            response = await dep_client.get(
                "/whoami", headers={"Authorization": f"Bearer {issued.token}"}
            )

        assert response.status_code == 200
        assert "session_cookie_refresh_failed" in _dependency_log_text(caplog)


# ---------------------------------------------------------------------------
# get_current_user — API key path (e2e)
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestGetCurrentUserApiKey:
    async def test_valid_key_returns_principal(
        self,
        dep_client: AsyncClient,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        api_key_factory: Callable[..., Awaitable[ApiKey]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        user = await user_factory()
        token, digest = _make_api_key_credential()
        await api_key_factory(user_id=user.id, key_hash=digest)
        monkeypatch.setattr(dependencies._last_used_debouncer, "touch", AsyncMock())

        response = await dep_client.get(
            "/whoami", headers={"Authorization": f"Bearer {token}"}
        )

        assert response.status_code == 200
        body = response.json()
        assert body["user_id"] == str(user.id)
        assert body["credential_kind"] == "api_key"

    async def test_successful_auth_touches_last_used(
        self,
        dep_client: AsyncClient,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        api_key_factory: Callable[..., Awaitable[ApiKey]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        user = await user_factory()
        token, digest = _make_api_key_credential()
        key = await api_key_factory(user_id=user.id, key_hash=digest)
        touch_mock = AsyncMock()
        monkeypatch.setattr(dependencies._last_used_debouncer, "touch", touch_mock)

        response = await dep_client.get(
            "/whoami", headers={"Authorization": f"Bearer {token}"}
        )

        assert response.status_code == 200
        touch_mock.assert_awaited_once()
        assert touch_mock.await_args is not None
        assert touch_mock.await_args.args[0] == key.id

    async def test_unknown_key_returns_generic_401_with_warning(
        self,
        dep_client: AsyncClient,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        token = "stl_ak_" + "0" * 32
        digest = hashlib.sha256(token.encode("utf-8")).hexdigest()

        with caplog.at_level(logging.WARNING, logger="app.api.dependencies"):
            response = await dep_client.get(
                "/whoami", headers={"Authorization": f"Bearer {token}"}
            )

        assert response.status_code == 401
        assert response.json() == {
            "code": "AUTH_NOT_AUTHENTICATED",
            "detail": "Authentication required",
        }
        text = _dependency_log_text(caplog)
        assert "api_key_validation_failed" in text

        # Complete secrets/PII exclusion contract (authentication.md, API
        # key validation, step 2): the log MUST NOT include the presented
        # key, its SHA-256 digest, the key prefix alone, a key name, a
        # username, or an email — nothing beyond the documented safe
        # fields (`event`, `source_ip`, `suppressed_count`).
        assert token not in text
        assert digest not in text
        assert "stl_ak_" not in text
        assert "key_name" not in text
        assert "username" not in text
        assert "email" not in text

        records = [
            record
            for record in caplog.records
            if record.name == "app.api.dependencies"
            and isinstance(record.msg, dict)
            and record.msg.get("event") == "api_key_validation_failed"
        ]
        assert len(records) == 1
        event_dict = records[0].msg
        # This exact field set reflects `_build_test_app()` (no
        # `CorrelationIdMiddleware`, hence no `request_id`), not a claim
        # that production emits nothing beyond these fields — the
        # negative assertions above (absence of token/digest/prefix)
        # are what the secrets/PII contract actually requires and hold
        # regardless of which non-sensitive fields the pipeline adds.
        assert set(event_dict) == {
            "event",
            "source_ip",
            "suppressed_count",
            "logger",
            "level",
            "timestamp",
            "app",
        }

    async def test_revoked_key_returns_generic_401_without_warning(
        self,
        dep_client: AsyncClient,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        api_key_factory: Callable[..., Awaitable[ApiKey]],
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        user = await user_factory()
        token, digest = _make_api_key_credential()
        await api_key_factory(
            user_id=user.id, key_hash=digest, revoked_at=datetime.now(UTC)
        )

        with caplog.at_level(logging.WARNING, logger="app.api.dependencies"):
            response = await dep_client.get(
                "/whoami", headers={"Authorization": f"Bearer {token}"}
            )

        assert response.status_code == 401
        assert "api_key_validation_failed" not in _dependency_log_text(caplog)

    async def test_expired_key_returns_generic_401_without_warning(
        self,
        dep_client: AsyncClient,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        api_key_factory: Callable[..., Awaitable[ApiKey]],
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        user = await user_factory()
        token, digest = _make_api_key_credential()
        await api_key_factory(
            user_id=user.id,
            key_hash=digest,
            expires_at=datetime.now(UTC) - timedelta(days=1),
        )

        with caplog.at_level(logging.WARNING, logger="app.api.dependencies"):
            response = await dep_client.get(
                "/whoami", headers={"Authorization": f"Bearer {token}"}
            )

        assert response.status_code == 401
        assert "api_key_validation_failed" not in _dependency_log_text(caplog)

    async def test_inactive_owner_returns_generic_401(
        self,
        dep_client: AsyncClient,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        api_key_factory: Callable[..., Awaitable[ApiKey]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        user = await user_factory(active=False)
        token, digest = _make_api_key_credential()
        await api_key_factory(user_id=user.id, key_hash=digest)
        monkeypatch.setattr(dependencies._last_used_debouncer, "touch", AsyncMock())

        response = await dep_client.get(
            "/whoami", headers={"Authorization": f"Bearer {token}"}
        )

        assert response.status_code == 401

    async def test_missing_user_returns_generic_401(
        self,
        dep_client: AsyncClient,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        api_key_factory: Callable[..., Awaitable[ApiKey]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Defensive guard: if the ApiKey.user_id references no User row
        (e.g. FK violation, data inconsistency), return the generic 401
        — matching the JWT path's test_missing_user_returns_generic_401.
        """
        user = await user_factory()
        token, digest = _make_api_key_credential()
        await api_key_factory(user_id=user.id, key_hash=digest)
        monkeypatch.setattr(dependencies._last_used_debouncer, "touch", AsyncMock())
        monkeypatch.setattr(
            user_service, "get_user_by_id", AsyncMock(return_value=None)
        )

        response = await dep_client.get(
            "/whoami", headers={"Authorization": f"Bearer {token}"}
        )

        assert response.status_code == 401
        assert response.json() == {
            "code": "AUTH_NOT_AUTHENTICATED",
            "detail": "Authentication required",
        }


# ---------------------------------------------------------------------------
# get_optional_current_user (e2e)
# ---------------------------------------------------------------------------
#
# See docs/features/identity/authentication.md (get_optional_current_user)
# and docs/features/platform/testing-strategy.md (Optional authentication
# mandatory scenarios). `get_current_user` and `get_optional_current_user`
# share the same `_resolve_principal()` selection/validation path — the
# rejection-matrix scenarios below are the optional-path counterparts of
# `TestGetCurrentUserJwt`/`TestGetCurrentUserApiKey` above and prove the two
# dependencies never diverge on a selected credential.


@pytest.mark.e2e
class TestGetOptionalCurrentUserAnonymous:
    """No credential selected — returns `None` with no authentication
    work at all."""

    async def test_no_credential_returns_anonymous(
        self, dep_client: AsyncClient
    ) -> None:
        response = await dep_client.get("/optional-whoami")

        assert response.status_code == 200
        assert response.json() == {"user_id": None, "credential_kind": None}
        assert "set-cookie" not in response.headers

    async def test_empty_cookie_returns_anonymous(
        self, dep_client: AsyncClient
    ) -> None:
        dep_client.cookies.set(SESSION_COOKIE_NAME, "")

        response = await dep_client.get("/optional-whoami")

        assert response.status_code == 200
        assert response.json() == {"user_id": None, "credential_kind": None}

    async def test_no_credential_performs_no_authentication_work(
        self,
        dep_client: AsyncClient,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Absence of a credential must short-circuit before any user
        lookup, `last_used_at` touch, or unknown-key warning — each
        side effect is made to fail loudly if invoked."""

        async def _fail_get_user_by_id(*args: Any, **kwargs: Any) -> User:
            raise AssertionError("user lookup must not occur when anonymous")

        def _fail_record_unknown_key(*args: Any, **kwargs: Any) -> None:
            raise AssertionError("unknown-key warning must not occur when anonymous")

        monkeypatch.setattr(user_service, "get_user_by_id", _fail_get_user_by_id)
        monkeypatch.setattr(
            dependencies._last_used_debouncer,
            "touch",
            AsyncMock(side_effect=AssertionError("touch must not occur")),
        )
        monkeypatch.setattr(
            dependencies, "_record_unknown_key_attempt", _fail_record_unknown_key
        )

        response = await dep_client.get("/optional-whoami")

        assert response.status_code == 200


@pytest.mark.unit
class TestResolvePrincipalWhitespaceCookie:
    """A whitespace-only cookie *value* reaching `_resolve_principal()`
    is a selected, invalid credential — not anonymous access (see
    authentication.md, Shared Credential Resolution step 2).

    Exercised by calling `_resolve_principal()` directly with a
    duck-typed request: Starlette's own `Cookie` header parser
    (`starlette.requests.cookie_parser`) unconditionally `.strip()`s
    cookie values before application code ever sees them, so a
    whitespace-only *raw* cookie cannot reach this function through a
    real HTTP round trip (verified separately — Starlette normalizes it
    to an empty string). This test proves the documented behavior of
    the shared resolver itself, independent of that framework-level
    normalization.
    """

    async def test_whitespace_only_cookie_value_is_selected_and_rejected(
        self,
    ) -> None:
        class _FakeHeaders:
            def get(self, key: str) -> str | None:
                return None

        class _FakeCookies:
            def get(self, key: str) -> str | None:
                return "   "

        class _FakeRequest:
            headers = _FakeHeaders()
            cookies = _FakeCookies()

        with pytest.raises(AppError) as exc_info:
            await dependencies._resolve_principal(
                cast(Request, _FakeRequest()),
                Response(),
                cast(AsyncSession, None),
            )

        assert exc_info.value.status_code == 401
        assert exc_info.value.code == ErrorCode.AUTH_NOT_AUTHENTICATED


@pytest.mark.e2e
class TestGetOptionalCurrentUserValidCredential:
    """A selected valid credential authenticates exactly as under
    mandatory authentication, including sliding refresh and API-key
    operational effects."""

    async def test_valid_jwt_cookie_returns_principal(
        self,
        dep_client: AsyncClient,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        redis_client: redis_asyncio.Redis,
    ) -> None:
        user = await user_factory()
        created = await create_session(
            db_session,
            user,
            SessionCreationReason.LOCAL_LOGIN,
            expected_password_hash=None,
        )
        assert created is not None
        dep_client.cookies.set(SESSION_COOKIE_NAME, created.token)

        response = await dep_client.get("/optional-whoami")

        assert response.status_code == 200
        body = response.json()
        assert body["user_id"] == str(user.id)
        assert body["credential_kind"] == "jwt"

    async def test_bearer_takes_precedence_over_cookie(
        self,
        dep_client: AsyncClient,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        redis_client: redis_asyncio.Redis,
    ) -> None:
        bearer_user = await user_factory()
        bearer_created = await create_session(
            db_session,
            bearer_user,
            SessionCreationReason.LOCAL_LOGIN,
            expected_password_hash=None,
        )
        assert bearer_created is not None
        cookie_user = await user_factory()
        cookie_created = await create_session(
            db_session,
            cookie_user,
            SessionCreationReason.LOCAL_LOGIN,
            expected_password_hash=None,
        )
        assert cookie_created is not None
        dep_client.cookies.set(SESSION_COOKIE_NAME, cookie_created.token)

        response = await dep_client.get(
            "/optional-whoami",
            headers={"Authorization": f"Bearer {bearer_created.token}"},
        )

        assert response.json()["user_id"] == str(bearer_user.id)

    async def test_empty_bearer_header_falls_back_to_cookie(
        self,
        dep_client: AsyncClient,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        redis_client: redis_asyncio.Redis,
    ) -> None:
        user = await user_factory()
        created = await create_session(
            db_session,
            user,
            SessionCreationReason.LOCAL_LOGIN,
            expected_password_hash=None,
        )
        assert created is not None
        dep_client.cookies.set(SESSION_COOKIE_NAME, created.token)

        response = await dep_client.get(
            "/optional-whoami", headers={"Authorization": "Bearer   "}
        )

        assert response.status_code == 200
        assert response.json()["user_id"] == str(user.id)

    async def test_eligible_jwt_refreshes_cookie(
        self,
        dep_client: AsyncClient,
        session_factory: Callable[..., Awaitable[Session]],
        redis_client: redis_asyncio.Redis,
    ) -> None:
        session = await session_factory()
        old_iat = datetime.now(UTC) - timedelta(hours=settings.jwt_expiry_hours * 0.6)
        issued = issue_token(
            user_id=session.user_id,
            session_id=session.id,
            issued_at=old_iat,
            session_deadline=session.expires_at,
            jwt_expiry_hours=settings.jwt_expiry_hours,
            secret_key=settings.jwt_secret_key.get_secret_value(),
        )

        response = await dep_client.get(
            "/optional-whoami", headers={"Authorization": f"Bearer {issued.token}"}
        )

        assert response.status_code == 200
        assert "set-cookie" in response.headers
        assert response.headers["set-cookie"].startswith(f"{SESSION_COOKIE_NAME}=")

    async def test_valid_api_key_returns_principal_and_touches_last_used(
        self,
        dep_client: AsyncClient,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        api_key_factory: Callable[..., Awaitable[ApiKey]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        user = await user_factory()
        token, digest = _make_api_key_credential()
        key = await api_key_factory(user_id=user.id, key_hash=digest)
        touch_mock = AsyncMock()
        monkeypatch.setattr(dependencies._last_used_debouncer, "touch", touch_mock)

        response = await dep_client.get(
            "/optional-whoami", headers={"Authorization": f"Bearer {token}"}
        )

        assert response.status_code == 200
        body = response.json()
        assert body["user_id"] == str(user.id)
        assert body["credential_kind"] == "api_key"
        touch_mock.assert_awaited_once()
        assert touch_mock.await_args is not None
        assert touch_mock.await_args.args[0] == key.id


@pytest.mark.e2e
class TestGetOptionalCurrentUserRejection:
    """A selected credential that fails validation returns the same
    generic 401 as mandatory authentication rather than degrading to
    anonymous access — see authentication.md,
    `get_optional_current_user`."""

    async def test_malformed_jwt_returns_generic_401(
        self, dep_client: AsyncClient
    ) -> None:
        response = await dep_client.get(
            "/optional-whoami", headers={"Authorization": "Bearer not-a-real-token"}
        )

        assert response.status_code == 401
        assert response.json() == {
            "code": "AUTH_NOT_AUTHENTICATED",
            "detail": "Authentication required",
        }

    async def test_invalid_non_empty_bearer_does_not_fall_back_to_valid_cookie(
        self,
        dep_client: AsyncClient,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        redis_client: redis_asyncio.Redis,
    ) -> None:
        user = await user_factory()
        created = await create_session(
            db_session,
            user,
            SessionCreationReason.LOCAL_LOGIN,
            expected_password_hash=None,
        )
        assert created is not None
        dep_client.cookies.set(SESSION_COOKIE_NAME, created.token)

        response = await dep_client.get(
            "/optional-whoami",
            headers={"Authorization": "Bearer not-a-real-token"},
        )

        assert response.status_code == 401

    async def test_inactive_session_returns_generic_401(
        self,
        dep_client: AsyncClient,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        redis_client: redis_asyncio.Redis,
    ) -> None:
        user = await user_factory()
        created = await create_session(
            db_session,
            user,
            SessionCreationReason.LOCAL_LOGIN,
            expected_password_hash=None,
        )
        assert created is not None
        created.session.is_active = False
        await db_session.flush()

        response = await dep_client.get(
            "/optional-whoami", headers={"Authorization": f"Bearer {created.token}"}
        )

        assert response.status_code == 401

    async def test_inactive_user_returns_generic_401(
        self,
        dep_client: AsyncClient,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        redis_client: redis_asyncio.Redis,
    ) -> None:
        user = await user_factory()
        created = await create_session(
            db_session,
            user,
            SessionCreationReason.LOCAL_LOGIN,
            expected_password_hash=None,
        )
        assert created is not None
        # The session must be created while the user is active; deactivate
        # afterwards so the dependency loads an inactive user with a still
        # active Session and must reject it.
        user.active = False
        await db_session.flush()

        response = await dep_client.get(
            "/optional-whoami", headers={"Authorization": f"Bearer {created.token}"}
        )

        assert response.status_code == 401

    async def test_missing_user_returns_generic_401(
        self,
        dep_client: AsyncClient,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        redis_client: redis_asyncio.Redis,
    ) -> None:
        user = await user_factory()
        created = await create_session(
            db_session,
            user,
            SessionCreationReason.LOCAL_LOGIN,
            expected_password_hash=None,
        )
        assert created is not None
        issued = issue_token(
            user_id=uuid.uuid4(),
            session_id=created.session.id,
            issued_at=datetime.now(UTC),
            session_deadline=created.session.expires_at,
            jwt_expiry_hours=settings.jwt_expiry_hours,
            secret_key=settings.jwt_secret_key.get_secret_value(),
        )

        response = await dep_client.get(
            "/optional-whoami", headers={"Authorization": f"Bearer {issued.token}"}
        )

        assert response.status_code == 401

    async def test_unknown_api_key_returns_generic_401_with_warning(
        self,
        dep_client: AsyncClient,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        token = "stl_ak_" + "1" * 32

        with caplog.at_level(logging.WARNING, logger="app.api.dependencies"):
            response = await dep_client.get(
                "/optional-whoami", headers={"Authorization": f"Bearer {token}"}
            )

        assert response.status_code == 401
        assert response.json() == {
            "code": "AUTH_NOT_AUTHENTICATED",
            "detail": "Authentication required",
        }
        assert "api_key_validation_failed" in _dependency_log_text(caplog)

    async def test_revoked_api_key_returns_generic_401_without_warning(
        self,
        dep_client: AsyncClient,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        api_key_factory: Callable[..., Awaitable[ApiKey]],
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        user = await user_factory()
        token, digest = _make_api_key_credential()
        await api_key_factory(
            user_id=user.id, key_hash=digest, revoked_at=datetime.now(UTC)
        )

        with caplog.at_level(logging.WARNING, logger="app.api.dependencies"):
            response = await dep_client.get(
                "/optional-whoami", headers={"Authorization": f"Bearer {token}"}
            )

        assert response.status_code == 401
        assert "api_key_validation_failed" not in _dependency_log_text(caplog)

    async def test_expired_api_key_returns_generic_401_without_warning(
        self,
        dep_client: AsyncClient,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        api_key_factory: Callable[..., Awaitable[ApiKey]],
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        user = await user_factory()
        token, digest = _make_api_key_credential()
        await api_key_factory(
            user_id=user.id,
            key_hash=digest,
            expires_at=datetime.now(UTC) - timedelta(days=1),
        )

        with caplog.at_level(logging.WARNING, logger="app.api.dependencies"):
            response = await dep_client.get(
                "/optional-whoami", headers={"Authorization": f"Bearer {token}"}
            )

        assert response.status_code == 401
        assert "api_key_validation_failed" not in _dependency_log_text(caplog)

    async def test_inactive_api_key_owner_returns_generic_401(
        self,
        dep_client: AsyncClient,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        api_key_factory: Callable[..., Awaitable[ApiKey]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        user = await user_factory(active=False)
        token, digest = _make_api_key_credential()
        await api_key_factory(user_id=user.id, key_hash=digest)
        monkeypatch.setattr(dependencies._last_used_debouncer, "touch", AsyncMock())

        response = await dep_client.get(
            "/optional-whoami", headers={"Authorization": f"Bearer {token}"}
        )

        assert response.status_code == 401

    async def test_database_failure_propagates_rather_than_anonymous(
        self,
        dep_client: AsyncClient,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        redis_client: redis_asyncio.Redis,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """An unexpected infrastructure failure must propagate — never
        be converted into an anonymous optional-authentication result
        — see authentication.md, Shared Credential Resolution: "Database
        failures and other infrastructure or unexpected exceptions
        propagate through normal error handling; neither dependency
        converts them to anonymous access"."""
        user = await user_factory()
        created = await create_session(
            db_session,
            user,
            SessionCreationReason.LOCAL_LOGIN,
            expected_password_hash=None,
        )
        assert created is not None

        async def _fail_get_user_by_id(*args: Any, **kwargs: Any) -> User:
            raise RuntimeError("simulated database failure")

        monkeypatch.setattr(user_service, "get_user_by_id", _fail_get_user_by_id)

        with pytest.raises(RuntimeError, match="simulated database failure"):
            await dep_client.get(
                "/optional-whoami",
                headers={"Authorization": f"Bearer {created.token}"},
            )


# ---------------------------------------------------------------------------
# require_capability (e2e)
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestRequireCapability:
    async def test_denies_without_capability(
        self,
        dep_client: AsyncClient,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        redis_client: redis_asyncio.Redis,
    ) -> None:
        user = await user_factory()
        created = await create_session(
            db_session,
            user,
            SessionCreationReason.LOCAL_LOGIN,
            expected_password_hash=None,
        )
        assert created is not None

        response = await dep_client.get(
            "/capability-protected",
            headers={"Authorization": f"Bearer {created.token}"},
        )

        assert response.status_code == 403
        assert response.json() == {
            "code": "AUTH_INSUFFICIENT_PERMISSION",
            "detail": "Insufficient permissions",
        }

    async def test_allows_with_matching_role(
        self,
        dep_client: AsyncClient,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        user_role_factory: Callable[..., Awaitable[Any]],
        redis_client: redis_asyncio.Redis,
    ) -> None:
        user = await user_factory()
        await user_role_factory(user_id=user.id, role=Role.ADMIN.value)
        created = await create_session(
            db_session,
            user,
            SessionCreationReason.LOCAL_LOGIN,
            expected_password_hash=None,
        )
        assert created is not None

        response = await dep_client.get(
            "/capability-protected",
            headers={"Authorization": f"Bearer {created.token}"},
        )

        assert response.status_code == 200

    async def test_admin_does_not_inherit_va_capability(
        self,
        dep_client: AsyncClient,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        user_role_factory: Callable[..., Awaitable[Any]],
        redis_client: redis_asyncio.Redis,
    ) -> None:
        user = await user_factory()
        await user_role_factory(user_id=user.id, role=Role.VULNERABILITY_ANALYST.value)
        created = await create_session(
            db_session,
            user,
            SessionCreationReason.LOCAL_LOGIN,
            expected_password_hash=None,
        )
        assert created is not None

        response = await dep_client.get(
            "/capability-protected",
            headers={"Authorization": f"Bearer {created.token}"},
        )

        assert response.status_code == 403

    async def test_role_added_takes_effect_on_next_request(
        self,
        dep_client: AsyncClient,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        user_role_factory: Callable[..., Awaitable[Any]],
        redis_client: redis_asyncio.Redis,
    ) -> None:
        user = await user_factory()
        created = await create_session(
            db_session,
            user,
            SessionCreationReason.LOCAL_LOGIN,
            expected_password_hash=None,
        )
        assert created is not None
        headers = {"Authorization": f"Bearer {created.token}"}
        # Capture the UUID before the failing request below: a rollback
        # (even a partial ROLLBACK TO SAVEPOINT) expires all tracked ORM
        # objects regardless of `expire_on_commit`, and a later
        # synchronous `user.id` access would raise `MissingGreenlet`.
        user_id = user.id
        # Checkpoint the fixture data via a savepoint commit: the first
        # request below is expected to fail (403), and the dep_client
        # override's rollback-on-exception would otherwise undo this
        # uncommitted user/session data too (see dep_client docstring).
        await db_session.commit()

        first = await dep_client.get("/capability-protected", headers=headers)
        assert first.status_code == 403

        await user_role_factory(user_id=user_id, role=Role.ADMIN.value)

        second = await dep_client.get("/capability-protected", headers=headers)
        assert second.status_code == 200

    async def test_role_removed_takes_effect_on_next_request(
        self,
        dep_client: AsyncClient,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        user_role_factory: Callable[..., Awaitable[Any]],
        redis_client: redis_asyncio.Redis,
    ) -> None:
        user = await user_factory()
        role = await user_role_factory(user_id=user.id, role=Role.ADMIN.value)
        created = await create_session(
            db_session,
            user,
            SessionCreationReason.LOCAL_LOGIN,
            expected_password_hash=None,
        )
        assert created is not None
        headers = {"Authorization": f"Bearer {created.token}"}

        first = await dep_client.get("/capability-protected", headers=headers)
        assert first.status_code == 200

        await db_session.delete(role)
        await db_session.flush()

        second = await dep_client.get("/capability-protected", headers=headers)
        assert second.status_code == 403

    async def test_denial_does_not_disclose_capability(
        self,
        dep_client: AsyncClient,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        redis_client: redis_asyncio.Redis,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        user = await user_factory()
        created = await create_session(
            db_session,
            user,
            SessionCreationReason.LOCAL_LOGIN,
            expected_password_hash=None,
        )
        assert created is not None

        with caplog.at_level(logging.WARNING, logger="app.api.dependencies"):
            response = await dep_client.get(
                "/capability-protected",
                headers={"Authorization": f"Bearer {created.token}"},
            )

        assert "manage_users" not in response.text.lower()
        assert "manage_users" not in _dependency_log_text(caplog).lower()


# ---------------------------------------------------------------------------
# require_session_authentication (e2e)
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestRequireSessionAuthentication:
    async def test_jwt_principal_passes_through(
        self,
        dep_client: AsyncClient,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        redis_client: redis_asyncio.Redis,
    ) -> None:
        user = await user_factory()
        created = await create_session(
            db_session,
            user,
            SessionCreationReason.LOCAL_LOGIN,
            expected_password_hash=None,
        )
        assert created is not None

        response = await dep_client.get(
            "/session-only", headers={"Authorization": f"Bearer {created.token}"}
        )

        assert response.status_code == 200
        assert response.json()["user_id"] == str(user.id)

    async def test_api_key_principal_is_rejected(
        self,
        dep_client: AsyncClient,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        api_key_factory: Callable[..., Awaitable[ApiKey]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        user = await user_factory()
        token, digest = _make_api_key_credential()
        await api_key_factory(user_id=user.id, key_hash=digest)
        monkeypatch.setattr(dependencies._last_used_debouncer, "touch", AsyncMock())

        response = await dep_client.get(
            "/session-only", headers={"Authorization": f"Bearer {token}"}
        )

        assert response.status_code == 403
        assert response.json() == {
            "code": "AUTH_SESSION_REQUIRED",
            "detail": "This operation requires session authentication.",
        }


# ---------------------------------------------------------------------------
# Ticket caller information and require_accessible_ticket (e2e)
# ---------------------------------------------------------------------------


async def _bearer(db_session: AsyncSession, user: User) -> dict[str, str]:
    created = await create_session(
        db_session,
        user,
        SessionCreationReason.LOCAL_LOGIN,
        expected_password_hash=None,
    )
    assert created is not None
    return {"Authorization": f"Bearer {created.token}"}


def _count_role_lookups(monkeypatch: pytest.MonkeyPatch) -> list[uuid.UUID]:
    """Record every `user_service.get_user_roles()` call made by the
    dependencies while still delegating to the real implementation."""
    calls: list[uuid.UUID] = []
    original = user_service.get_user_roles

    async def _spy(session: AsyncSession, user_id: uuid.UUID) -> list[Role]:
        calls.append(user_id)
        return await original(session, user_id)

    monkeypatch.setattr(user_service, "get_user_roles", _spy)
    return calls


@pytest.mark.e2e
class TestTicketCallerDependencies:
    async def test_optional_caller_without_credential_is_anonymous(
        self, dep_client: AsyncClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        calls = _count_role_lookups(monkeypatch)

        response = await dep_client.get("/optional-ticket-caller")

        assert response.status_code == 200
        assert response.json() == {"user_id": None, "scope": None}
        assert calls == []

    async def test_optional_caller_with_invalid_credential_returns_401(
        self, dep_client: AsyncClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        calls = _count_role_lookups(monkeypatch)

        response = await dep_client.get(
            "/optional-ticket-caller", headers={"Authorization": "Bearer invalid"}
        )

        assert response.status_code == 401
        assert response.json()["code"] == "AUTH_NOT_AUTHENTICATED"
        assert calls == []

    @pytest.mark.parametrize(
        ("roles", "scope"),
        [
            ([], "non_confidential"),
            ([Role.RESTRICTED_ANALYST], "non_confidential"),
            ([Role.VULNERABILITY_ANALYST], "all"),
            ([Role.RESTRICTED_ANALYST, Role.ADMIN], "all"),
        ],
    )
    @pytest.mark.parametrize("path", ["/ticket-caller", "/optional-ticket-caller"])
    async def test_authenticated_caller_carries_the_effective_scope(
        self,
        path: str,
        roles: list[Role],
        scope: str,
        dep_client: AsyncClient,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        user_role_factory: Callable[..., Awaitable[Any]],
        redis_client: redis_asyncio.Redis,
    ) -> None:
        user = await user_factory()
        for role in roles:
            await user_role_factory(user_id=user.id, role=role.value)
        headers = await _bearer(db_session, user)

        response = await dep_client.get(path, headers=headers)

        assert response.status_code == 200
        assert response.json() == {"user_id": str(user.id), "scope": scope}

    async def test_authenticated_caller_requires_a_credential(
        self, dep_client: AsyncClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        calls = _count_role_lookups(monkeypatch)

        response = await dep_client.get("/ticket-caller")

        assert response.status_code == 401
        assert calls == []

    async def test_caller_is_resolved_once_per_request(
        self,
        dep_client: AsyncClient,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        ticket_factory: Callable[..., Awaitable[Ticket]],
        redis_client: redis_asyncio.Redis,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        user = await user_factory()
        ticket = await ticket_factory()
        headers = await _bearer(db_session, user)
        calls = _count_role_lookups(monkeypatch)

        response = await dep_client.get(
            f"/tickets/{format_ticket_id(ticket.sequence_id)}/accessible",
            headers=headers,
        )

        assert response.status_code == 200
        assert calls == [user.id]


@pytest.mark.e2e
class TestRequireAccessibleTicket:
    async def test_accessible_ticket_resolves(
        self,
        dep_client: AsyncClient,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        ticket_factory: Callable[..., Awaitable[Ticket]],
        ticket_access_grant_factory: Callable[..., Awaitable[Any]],
        redis_client: redis_asyncio.Redis,
    ) -> None:
        user = await user_factory()
        ticket = await ticket_factory(is_confidential=True)
        await ticket_access_grant_factory(ticket_id=ticket.id, user_id=user.id)
        headers = await _bearer(db_session, user)

        response = await dep_client.get(
            f"/tickets/{format_ticket_id(ticket.sequence_id)}/accessible",
            headers=headers,
        )

        assert response.status_code == 200
        assert response.json()["sequence_id"] == ticket.sequence_id

    async def test_every_denial_cause_returns_the_identical_404(
        self,
        dep_client: AsyncClient,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        ticket_factory: Callable[..., Awaitable[Ticket]],
        redis_client: redis_asyncio.Redis,
    ) -> None:
        user = await user_factory()
        visible = await ticket_factory()
        hidden = await ticket_factory(is_confidential=True)
        headers = await _bearer(db_session, user)
        locators = [
            format_ticket_id(visible.sequence_id).lower(),
            f"SNTL-0{visible.sequence_id}",
            "SNTL-2147483648",
            str(visible.id),
            "SNTL-2147483647",
            format_ticket_id(hidden.sequence_id),
        ]
        # Checkpoint the fixtures: each 404 rolls back the request's work.
        await db_session.commit()

        bodies = []
        for locator in locators:
            response = await dep_client.get(
                f"/tickets/{locator}/accessible", headers=headers
            )
            assert response.status_code == 404, locator
            bodies.append(response.content)

        assert set(bodies) == {
            b'{"code":"TICKET_NOT_FOUND","detail":"Ticket not found."}'
        }

    async def test_missing_credential_returns_401_before_lookup(
        self, dep_client: AsyncClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        resolver = AsyncMock()
        monkeypatch.setattr(ticket_service, "resolve_ticket_locator", resolver)

        response = await dep_client.get("/tickets/SNTL-1/accessible")

        assert response.status_code == 401
        resolver.assert_not_awaited()
