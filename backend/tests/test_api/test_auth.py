"""End-to-end tests for ``POST /api/v1/auth/login`` and
``POST /api/v1/auth/logout``."""

from __future__ import annotations

import uuid
from collections.abc import AsyncGenerator, Awaitable, Callable
from datetime import UTC, datetime, timedelta

import jwt
import pytest
import redis.asyncio as redis_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import unauthenticated_error
from app.config import settings
from app.core.enums import SessionCreationReason
from app.core.errors import ErrorCode
from app.core.jwt import ALGORITHM, ISSUER, decode_and_validate
from app.database import get_db
from app.main import app
from app.models.session import Session
from app.models.user import User
from app.services import local_auth_service, session_service
from app.services.local_auth_service import guard_and_increment
from app.services.session_service import create_session


@pytest.fixture
async def auth_client(
    db_session: AsyncSession,
    redis_client: redis_asyncio.Redis,
) -> AsyncGenerator[AsyncClient]:
    """Exercise the production commit-before-callback ordering.

    The shared client fixture intentionally keeps one rollback-owned test
    transaction and therefore does not execute ``get_db`` post-yield logic.
    Login (post-commit lockout counter clear) and logout (post-commit
    session cache purge) both need that lifecycle to verify their
    respective best-effort side effects.

    Caveat for multi-request tests: a request that fails (raises
    ``AppError`` or any other exception) triggers this override's
    ``rollback()``, which rolls back ``db_session``'s *current*
    savepoint — undoing any fixture data flushed earlier in the same
    test if it was never checkpointed by an intervening commit. Tests
    that chain a failing request after creating fixture data should set
    up Redis-only preconditions directly (e.g. via
    ``guard_and_increment()``) rather than relying on an HTTP round trip
    that is expected to fail.
    """

    async def _override_get_db() -> AsyncGenerator[AsyncSession]:
        try:
            yield db_session
            await db_session.commit()
        except Exception:
            await db_session.rollback()
            raise
        else:
            callbacks = db_session.info.pop("post_commit_callbacks", [])
            for callback in callbacks:
                await callback()

    app.dependency_overrides[get_db] = _override_get_db
    try:
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            yield client
    finally:
        app.dependency_overrides.pop(get_db, None)


async def _created_session(
    db_session: AsyncSession,
    user_factory: Callable[..., Awaitable[User]],
) -> tuple[Session, str]:
    user = await user_factory()
    created = await create_session(
        db_session,
        user,
        SessionCreationReason.LOCAL_LOGIN,
        expected_password_hash=None,
    )
    assert created is not None
    return created.session, created.token


def _expired_token(session: Session) -> str:
    now = datetime.now(UTC)
    payload = {
        "sub": str(session.user_id),
        "session_id": str(session.id),
        "iat": int((now - timedelta(days=3)).timestamp()),
        "exp": int((now - timedelta(days=2)).timestamp()),
        "session_deadline": int((now - timedelta(days=1)).timestamp()),
        "iss": ISSUER,
    }
    return jwt.encode(
        payload,
        settings.jwt_secret_key.get_secret_value(),
        algorithm=ALGORITHM,
    )


@pytest.mark.e2e
class TestLogout:
    async def test_cookie_without_authorization_header_logs_out(
        self,
        auth_client: AsyncClient,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        _session, token = await _created_session(db_session, user_factory)
        auth_client.cookies.set("sentinel_session", token)

        response = await auth_client.post("/api/v1/auth/logout")

        assert response.status_code == 204

    async def test_valid_bearer_invalidates_session_purges_cache_and_clears_cookie(
        self,
        auth_client: AsyncClient,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        redis_client: redis_asyncio.Redis,
    ) -> None:
        session, token = await _created_session(db_session, user_factory)
        key = f"session_liveness:{session.id}"
        await redis_client.set(key, "1", ex=60)

        response = await auth_client.post(
            "/api/v1/auth/logout", headers={"Authorization": f"Bearer {token}"}
        )

        assert response.status_code == 204
        assert response.content == b""
        assert response.headers["set-cookie"] == (
            "sentinel_session=; Path=/api; Max-Age=0; HttpOnly; Secure; SameSite=Strict"
        )
        await db_session.refresh(session)
        assert session.is_active is False
        assert await redis_client.get(key) is None

    async def test_repeated_logout_and_missing_session_are_idempotent(
        self,
        auth_client: AsyncClient,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        session, token = await _created_session(db_session, user_factory)

        first = await auth_client.post(
            "/api/v1/auth/logout", headers={"Authorization": f"Bearer {token}"}
        )
        second = await auth_client.post(
            "/api/v1/auth/logout", headers={"Authorization": f"Bearer {token}"}
        )
        await db_session.delete(session)
        await db_session.flush()
        missing = await auth_client.post(
            "/api/v1/auth/logout", headers={"Authorization": f"Bearer {token}"}
        )

        assert first.status_code == second.status_code == missing.status_code == 204

    async def test_temporally_expired_signed_token_is_accepted(
        self,
        auth_client: AsyncClient,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        session, _ = await _created_session(db_session, user_factory)

        response = await auth_client.post(
            "/api/v1/auth/logout",
            headers={"Authorization": f"Bearer {_expired_token(session)}"},
        )

        assert response.status_code == 204

    @pytest.mark.parametrize(
        "headers",
        [
            {},
            {"Authorization": "Bearer malformed-token"},
            {"Authorization": "Bearer "},
        ],
    )
    async def test_missing_or_invalid_jwt_returns_generic_401(
        self, auth_client: AsyncClient, headers: dict[str, str]
    ) -> None:
        response = await auth_client.post("/api/v1/auth/logout", headers=headers)

        assert response.status_code == 401
        assert response.json() == {
            "code": "AUTH_NOT_AUTHENTICATED",
            "detail": "Authentication required",
        }

    async def test_api_key_returns_logout_not_applicable(
        self, auth_client: AsyncClient
    ) -> None:
        response = await auth_client.post(
            "/api/v1/auth/logout",
            headers={"Authorization": "Bearer stl_ak_fictional-key"},
        )

        assert response.status_code == 400
        assert response.json() == {
            "code": "AUTH_LOGOUT_NOT_APPLICABLE",
            "detail": "Logout is not applicable to API key authentication.",
        }

    @pytest.mark.parametrize(
        "authorization",
        ["Bearer", "Bearer   ", "Basic fictional", "scheme-less"],
    )
    async def test_empty_or_non_bearer_header_falls_back_to_cookie(
        self,
        auth_client: AsyncClient,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        authorization: str,
    ) -> None:
        _session, token = await _created_session(db_session, user_factory)
        auth_client.cookies.set("sentinel_session", token)

        response = await auth_client.post(
            "/api/v1/auth/logout",
            headers={"Authorization": authorization},
        )

        assert response.status_code == 204

    async def test_bearer_is_case_insensitive_and_takes_precedence_over_cookie(
        self,
        auth_client: AsyncClient,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        _session, cookie_token = await _created_session(db_session, user_factory)
        auth_client.cookies.set("sentinel_session", cookie_token)

        response = await auth_client.post(
            "/api/v1/auth/logout",
            headers={"Authorization": "bEaReR malformed-token"},
        )

        assert response.status_code == 401


@pytest.mark.e2e
class TestLogin:
    async def test_valid_credentials_returns_200_with_token_and_cookie(
        self,
        auth_client: AsyncClient,
        local_user_factory: Callable[..., Awaitable[tuple[User, str]]],
    ) -> None:
        user, password = await local_user_factory()

        response = await auth_client.post(
            "/api/v1/auth/login",
            json={"username": user.username, "password": password},
        )

        assert response.status_code == 200
        body = response.json()
        assert body["data"]["token_type"] == "bearer"
        assert isinstance(body["data"]["access_token"], str)
        assert body["data"]["access_token"]
        assert body["data"]["expires_at"].endswith("Z")
        assert response.headers["set-cookie"].startswith(
            f"sentinel_session={body['data']['access_token']}; "
        )
        cookie_header = response.headers["set-cookie"]
        assert "HttpOnly" in cookie_header
        assert "Secure" in cookie_header
        assert "samesite=strict" in cookie_header.lower()
        assert "Path=/api" in cookie_header

    async def test_jwt_claims_match_created_session(
        self,
        auth_client: AsyncClient,
        db_session: AsyncSession,
        local_user_factory: Callable[..., Awaitable[tuple[User, str]]],
    ) -> None:
        user, password = await local_user_factory()

        response = await auth_client.post(
            "/api/v1/auth/login",
            json={"username": user.username, "password": password},
        )

        token = response.json()["data"]["access_token"]
        claims = decode_and_validate(
            token,
            secret_key=settings.jwt_secret_key.get_secret_value(),
            now=datetime.now(UTC),
        )
        assert claims.user_id == user.id

    async def test_succeeds_despite_stale_authorization_and_cookie(
        self,
        auth_client: AsyncClient,
        local_user_factory: Callable[..., Awaitable[tuple[User, str]]],
    ) -> None:
        """Login is one of the documented exceptions to `Authentication:
        Optional` (see `docs/api-spec.md`, Optional Authentication on
        Public Endpoints): it ignores request credentials entirely, so a
        stale `Authorization` header and a stale session cookie
        presented alongside valid login credentials must not block
        authentication bootstrap — see
        `docs/features/platform/testing-strategy.md` (Optional
        authentication mandatory scenarios)."""
        user, password = await local_user_factory()
        auth_client.cookies.set("sentinel_session", "stale-cookie-value")

        response = await auth_client.post(
            "/api/v1/auth/login",
            json={"username": user.username, "password": password},
            headers={"Authorization": "Bearer not-a-real-token"},
        )

        assert response.status_code == 200
        assert response.json()["data"]["token_type"] == "bearer"

    async def test_username_is_trimmed_and_lowercased(
        self,
        auth_client: AsyncClient,
        local_user_factory: Callable[..., Awaitable[tuple[User, str]]],
    ) -> None:
        _user, password = await local_user_factory(username="bob")

        response = await auth_client.post(
            "/api/v1/auth/login",
            json={"username": "  Bob  ", "password": password},
        )

        assert response.status_code == 200

    @pytest.mark.parametrize("username", ["nosuchuser", None])
    async def test_wrong_password_and_unknown_user_return_identical_401(
        self,
        auth_client: AsyncClient,
        local_user_factory: Callable[..., Awaitable[tuple[User, str]]],
        username: str | None,
    ) -> None:
        user, _password = await local_user_factory()
        target_username = username or user.username

        response = await auth_client.post(
            "/api/v1/auth/login",
            json={"username": target_username, "password": "wrong-password-value"},
        )

        assert response.status_code == 401
        assert response.json() == {
            "code": "AUTH_INVALID_CREDENTIALS",
            "detail": "Invalid username or password.",
        }

    async def test_inactive_user_returns_generic_401(
        self,
        auth_client: AsyncClient,
        local_user_factory: Callable[..., Awaitable[tuple[User, str]]],
    ) -> None:
        user, password = await local_user_factory(active=False)

        response = await auth_client.post(
            "/api/v1/auth/login",
            json={"username": user.username, "password": password},
        )

        assert response.status_code == 401
        assert response.json()["code"] == "AUTH_INVALID_CREDENTIALS"

    async def test_external_user_returns_generic_401(
        self,
        auth_client: AsyncClient,
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        user = await user_factory(external_id=uuid.uuid4(), password_hash=None)

        response = await auth_client.post(
            "/api/v1/auth/login",
            json={"username": user.username, "password": "whatever-password-value"},
        )

        assert response.status_code == 401
        assert response.json()["code"] == "AUTH_INVALID_CREDENTIALS"

    async def test_locked_current_inactive_maps_to_generic_401_without_counter_clear(
        self,
        auth_client: AsyncClient,
        redis_client: redis_asyncio.Redis,
        local_user_factory: Callable[..., Awaitable[tuple[User, str]]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A valid password whose Session creation observes a committed
        deactivation (after the step-7 pre-check) returns the same generic
        401 body as every other failure and leaves the lockout counter in
        place — no successful-login clear is registered (see
        local-authentication.md, step 11)."""
        user, password = await local_user_factory()
        username = user.username
        real_create = session_service.create_session

        async def _create_after_deactivation(
            db: AsyncSession,
            target: User,
            reason: SessionCreationReason,
            *,
            expected_password_hash: str | None,
        ) -> object:
            await db.execute(
                update(User).where(User.id == target.id).values(active=False)
            )
            await db.flush()
            return await real_create(
                db,
                target,
                reason,
                expected_password_hash=expected_password_hash,
            )

        monkeypatch.setattr(
            local_auth_service, "create_session", _create_after_deactivation
        )

        response = await auth_client.post(
            "/api/v1/auth/login",
            json={"username": username, "password": password},
        )

        assert response.status_code == 401
        assert response.json() == {
            "code": "AUTH_INVALID_CREDENTIALS",
            "detail": "Invalid username or password.",
        }
        # A failed login sets no session cookie and is not the lockout
        # (429) response, so neither header is present.
        assert "set-cookie" not in response.headers
        assert "retry-after" not in response.headers
        assert await redis_client.get(f"login_attempts:{username}") == "1"

    async def test_locked_current_superseded_credential_maps_to_generic_401(
        self,
        auth_client: AsyncClient,
        redis_client: redis_asyncio.Redis,
        local_user_factory: Callable[..., Awaitable[tuple[User, str]]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A valid password whose Session creation observes a password
        reset committed after the step-8 verification (the locked-current
        `password_hash` no longer matches) returns the same generic 401
        body as every other failure and leaves the lockout counter in
        place — no successful-login clear is registered (see
        local-authentication.md, step 11, and authentication.md,
        Password-reset serialization)."""
        user, password = await local_user_factory()
        username = user.username
        real_create = session_service.create_session

        async def _create_after_reset(
            db: AsyncSession,
            target: User,
            reason: SessionCreationReason,
            *,
            expected_password_hash: str | None,
        ) -> object:
            await db.execute(
                update(User)
                .where(User.id == target.id)
                .values(password_hash="$2b$12$" + "b" * 53)
            )
            await db.flush()
            return await real_create(
                db,
                target,
                reason,
                expected_password_hash=expected_password_hash,
            )

        monkeypatch.setattr(local_auth_service, "create_session", _create_after_reset)

        response = await auth_client.post(
            "/api/v1/auth/login",
            json={"username": username, "password": password},
        )

        assert response.status_code == 401
        assert response.json() == {
            "code": "AUTH_INVALID_CREDENTIALS",
            "detail": "Invalid username or password.",
        }
        # A failed login sets no session cookie and is not the lockout
        # (429) response, so neither header is present.
        assert "set-cookie" not in response.headers
        assert "retry-after" not in response.headers
        assert await redis_client.get(f"login_attempts:{username}") == "1"

    @pytest.mark.parametrize(
        "payload",
        [
            {"password": "whatever-password-value"},
            {"username": "someone"},
            {"username": None, "password": "whatever-password-value"},
            {},
        ],
    )
    async def test_missing_or_invalid_fields_return_422(
        self, auth_client: AsyncClient, payload: dict[str, str | None]
    ) -> None:
        response = await auth_client.post("/api/v1/auth/login", json=payload)

        assert response.status_code == 422
        assert response.json()["code"] == "VALIDATION_ERROR"

    async def test_password_field_not_leaked_in_validation_error(
        self, auth_client: AsyncClient
    ) -> None:
        """A non-string `password` fails Pydantic validation on the
        `password` field itself — unlike a missing/None `username`
        (which fails on a different field and never puts the password
        value at risk), this exercises the actual leak `main.py`'s
        `_validation_error_handler` guards against by stripping
        Pydantic's `input`/`ctx` keys from the error response."""
        response = await auth_client.post(
            "/api/v1/auth/login", json={"username": "someone", "password": 123456789}
        )

        assert response.status_code == 422
        assert "123456789" not in response.text

    @pytest.mark.parametrize(
        "payload",
        [
            {"username": "validuser", "password": "x" * 129},
            {"username": "x" * 65, "password": "whatever-password-value"},
            {"username": "   ", "password": "whatever-password-value"},
        ],
        ids=["overlong_password", "overlong_username", "whitespace_only_username"],
    )
    async def test_oversized_or_empty_input_returns_401_not_422(
        self, auth_client: AsyncClient, payload: dict[str, str]
    ) -> None:
        """`schemas/auth.py` deliberately carries no length constraints
        so that these guards in `local_auth_service.authenticate_local_user()`
        produce the documented generic 401 rather than a schema-level 422
        — see `docs/features/identity/local-authentication.md` (Login,
        Behavior, steps 1-3)."""
        response = await auth_client.post("/api/v1/auth/login", json=payload)

        assert response.status_code == 401
        assert response.json()["code"] == "AUTH_INVALID_CREDENTIALS"

    async def test_lockout_returns_429_with_retry_after(
        self,
        auth_client: AsyncClient,
        local_user_factory: Callable[..., Awaitable[tuple[User, str]]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(settings, "login_max_attempts", 1)
        user, _password = await local_user_factory()

        first = await auth_client.post(
            "/api/v1/auth/login",
            json={"username": user.username, "password": "wrong-password-value"},
        )
        second = await auth_client.post(
            "/api/v1/auth/login",
            json={"username": user.username, "password": "wrong-password-value"},
        )

        assert first.status_code == 401
        assert second.status_code == 429
        assert second.json() == {
            "code": "AUTH_ACCOUNT_LOCKED",
            "detail": "Account temporarily locked. Try again later.",
        }
        assert int(second.headers["retry-after"]) >= 1

    async def test_login_then_logout_invalidates_that_session(
        self,
        auth_client: AsyncClient,
        db_session: AsyncSession,
        local_user_factory: Callable[..., Awaitable[tuple[User, str]]],
    ) -> None:
        user, password = await local_user_factory()

        login_response = await auth_client.post(
            "/api/v1/auth/login",
            json={"username": user.username, "password": password},
        )
        token = login_response.json()["data"]["access_token"]

        logout_response = await auth_client.post(
            "/api/v1/auth/logout", headers={"Authorization": f"Bearer {token}"}
        )

        assert logout_response.status_code == 204
        claims = decode_and_validate(
            token,
            secret_key=settings.jwt_secret_key.get_secret_value(),
            now=datetime.now(UTC),
        )
        session = await db_session.get(Session, claims.session_id)
        assert session is not None
        assert session.is_active is False

    async def test_successful_login_clears_lockout_counter_after_commit(
        self,
        auth_client: AsyncClient,
        redis_client: redis_asyncio.Redis,
        local_user_factory: Callable[..., Awaitable[tuple[User, str]]],
    ) -> None:
        user, password = await local_user_factory()
        # Simulate a prior failed attempt via the pure Redis lockout gate
        # directly, rather than a failing HTTP round trip: a failed
        # login raises `AppError`, which rolls back `db_session` to its
        # current savepoint — undoing the `local_user_factory` insert
        # above, since both share the same uncommitted savepoint (see
        # `auth_client`'s docstring). `guard_and_increment()` has no
        # database dependency, so it sets up the identical Redis
        # precondition without that hazard.
        await guard_and_increment(user.username)
        assert await redis_client.get(f"login_attempts:{user.username}") == "1"

        response = await auth_client.post(
            "/api/v1/auth/login",
            json={"username": user.username, "password": password},
        )

        assert response.status_code == 200
        assert await redis_client.get(f"login_attempts:{user.username}") is None

    async def test_login_route_is_public_and_documents_error_responses(self) -> None:
        openapi = app.openapi()
        login_op = openapi["paths"]["/api/v1/auth/login"]["post"]
        assert "security" not in login_op
        assert set(login_op["responses"]) >= {"200", "401", "422", "429"}
        assert openapi["components"]["schemas"]["LoginResponse"]["properties"]["data"]


@pytest.mark.unit
def test_unauthenticated_error_returns_fresh_exception_instances() -> None:
    """`unauthenticated_error()` must return a new `AppError` instance
    on every call — a shared singleton exception would accumulate a
    stale traceback across requests. See `app/api/dependencies.py`,
    reused by `app/api/v1/auth.py`'s logout endpoint."""
    first = unauthenticated_error()
    second = unauthenticated_error()

    assert first is not second
    assert first.code == second.code == ErrorCode.AUTH_NOT_AUTHENTICATED
