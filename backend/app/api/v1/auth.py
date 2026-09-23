"""Authentication endpoints.

See `docs/features/identity/authentication.md` (Logout) and
`docs/features/identity/local-authentication.md` (Login Endpoint) for
the authoritative endpoint contracts this module implements.
"""

from __future__ import annotations

from fastapi import APIRouter, Request, Response, status
from fastapi.responses import JSONResponse

from app.api.dependencies import (
    SESSION_COOKIE_NAME as _COOKIE_NAME,
)
from app.api.dependencies import (
    set_session_cookie as _set_session_cookie,
)
from app.api.dependencies import (
    unauthenticated_error as _unauthenticated_error,
)
from app.config import settings
from app.core.credentials import API_KEY_PREFIX, extract_credential
from app.core.errors import AppError, ErrorCode
from app.core.jwt import InvalidTokenError, decode_for_logout
from app.database import DatabaseSession, register_post_commit_callback
from app.schemas.auth import LoginData, LoginRequest, LoginResponse
from app.schemas.errors import ErrorResponse
from app.services.local_auth_service import (
    LoginInvalidCredentials,
    LoginLocked,
    authenticate_local_user,
    clear_login_attempts,
)
from app.services.session_service import invalidate_session, purge_session_cache

router = APIRouter(prefix="/api/v1/auth", tags=["Authentication"])

# The exact cookie-clearing header text from authentication.md (Logout,
# step 5). Built manually rather than via `Response.set_cookie()`:
# Python's stdlib `http.cookies` unconditionally double-quotes an empty
# cookie value (`sentinel_session=""`), which would diverge from the
# documented literal header value below (`sentinel_session=`, no quotes).
_CLEAR_COOKIE_HEADER = (
    f"{_COOKIE_NAME}=; Path=/api; Max-Age=0; HttpOnly; Secure; SameSite=Strict"
)


def _invalid_credentials_error() -> AppError:
    """Create a fresh generic invalid-credentials failure.

    Identical status/code/detail for every login failure cause (unknown
    username, wrong password, inactive user, external user, no password
    set, superseded password) — see
    `docs/features/identity/local-authentication.md`
    (Security Considerations). A fresh instance per call for the same
    reason as `_unauthenticated_error()`.
    """
    return AppError(
        status_code=status.HTTP_401_UNAUTHORIZED,
        code=ErrorCode.AUTH_INVALID_CREDENTIALS,
        detail="Invalid username or password.",
    )


def _clear_session_cookie(response: Response) -> None:
    """Set the exact cookie-clearing `Set-Cookie` header — see
    `_CLEAR_COOKIE_HEADER`."""
    response.headers.append("set-cookie", _CLEAR_COOKIE_HEADER)


@router.post(
    "/login",
    response_model=LoginResponse,
    summary="Log in with a local username and password",
    description=(
        "Authenticates a local user, creates a session, and returns a "
        "JWT. Public endpoint. Returns a generic 401 for every credential "
        "failure (unknown username, wrong password, inactive user, "
        "external user, no password set, or a superseded password) to "
        "prevent username enumeration."
    ),
    responses={
        401: {
            "model": ErrorResponse,
            "description": "Invalid username or password.",
        },
        429: {
            "model": ErrorResponse,
            "description": (
                "Account temporarily locked due to too many failed attempts."
            ),
            "headers": {
                "Retry-After": {
                    "description": "Seconds remaining until the lockout expires.",
                    "schema": {"type": "integer"},
                }
            },
        },
    },
)
async def login(body: LoginRequest, db: DatabaseSession) -> Response:
    """Login — see `docs/features/identity/local-authentication.md`
    (Login Endpoint)."""
    result = await authenticate_local_user(db, body.username, body.password)

    if isinstance(result, LoginLocked):
        raise AppError(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            code=ErrorCode.AUTH_ACCOUNT_LOCKED,
            detail="Account temporarily locked. Try again later.",
            headers={"Retry-After": str(result.retry_after_seconds)},
        )
    if isinstance(result, LoginInvalidCredentials):
        raise _invalid_credentials_error()

    register_post_commit_callback(
        db, lambda: clear_login_attempts(result.normalized_username)
    )
    created = result.created_session
    body_model = LoginResponse(
        data=LoginData(
            access_token=created.token,
            expires_at=created.token_expires_at,
        )
    )
    response = JSONResponse(
        status_code=status.HTTP_200_OK,
        content=body_model.model_dump(mode="json"),
    )
    _set_session_cookie(response, created.token)
    return response


@router.post(
    "/logout",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Log out",
    description=(
        "Invalidates the current session and clears the session cookie. "
        "Idempotent — safe to call multiple times, including with an "
        "already-invalidated or missing session, or a temporally expired "
        "(but validly signed) token."
    ),
    responses={
        400: {
            "model": ErrorResponse,
            "description": "Called with an API key credential instead of a JWT.",
        },
    },
)
async def logout(request: Request, db: DatabaseSession) -> Response:
    """Logout — see `docs/features/identity/authentication.md` (Logout)."""
    credential = extract_credential(
        request.headers.get("authorization"), request.cookies.get(_COOKIE_NAME)
    )
    if credential is None:
        raise _unauthenticated_error()
    if credential.startswith(API_KEY_PREFIX):
        raise AppError(
            status_code=status.HTTP_400_BAD_REQUEST,
            code=ErrorCode.AUTH_LOGOUT_NOT_APPLICABLE,
            detail="Logout is not applicable to API key authentication.",
        )
    try:
        claims = decode_for_logout(
            credential, secret_key=settings.jwt_secret_key.get_secret_value()
        )
    except InvalidTokenError:
        raise _unauthenticated_error() from None

    session_id = await invalidate_session(db, claims.session_id)
    register_post_commit_callback(db, lambda: purge_session_cache([session_id]))

    response = Response(status_code=status.HTTP_204_NO_CONTENT)
    _clear_session_cookie(response)
    return response
