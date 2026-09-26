"""Shared authentication and authorization FastAPI dependencies.

See `docs/features/identity/authentication.md` (Authenticated Principal,
Authentication Dependencies: `get_current_user`,
`get_optional_current_user`, API key validation, Session-Only
Authentication Dependency) and `docs/features/identity/rbac.md`
(`require_capability()` Dependency) for the authoritative contracts
this module implements.
"""

from __future__ import annotations

import asyncio
import hashlib
from collections import OrderedDict
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Annotated
from uuid import UUID

import structlog
from fastapi import Depends, Path, Request, Response, status
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.config import settings
from app.core.credentials import API_KEY_PREFIX, extract_credential
from app.core.enums import Capability, CredentialKind
from app.core.errors import AppError, ErrorCode
from app.core.exceptions import TicketNotFoundError
from app.core.jwt import InvalidTokenError, decode_and_validate, refresh_token
from app.core.permissions import get_capabilities, get_effective_scope
from app.database import DatabaseSession, async_session_factory
from app.models.user import User
from app.services import api_key_service, ticket_service, user_service
from app.services.session_service import is_session_active
from app.services.ticket_service import ResolvedTicket
from app.services.ticket_visibility import ANONYMOUS_CALLER, TicketCaller

logger = structlog.get_logger(__name__)

# The session cookie name and attributes are shared by every code path
# that sets or reads it: the login endpoint (`app/api/v1/auth.py`),
# this module's sliding-refresh attachment, and the logout endpoint's
# clearing header. Centralized here so all three stay in sync.
SESSION_COOKIE_NAME = "sentinel_session"


def unauthenticated_error() -> AppError:
    """Create a fresh generic 401 authentication failure.

    Shared by every credential-resolution failure path in
    `get_current_user()` (missing credential, invalid JWT, failed
    session liveness, unknown/revoked/expired API key, missing/inactive
    user) and by the logout endpoint's lightweight JWT-only dependency
    — see `docs/features/identity/authentication.md` (Shared Credential
    Resolution): "All HTTP 401 responses return a generic body ...
    regardless of the specific failure reason." A fresh instance per
    call avoids accumulating traceback state and request-local
    credential data on a shared singleton exception.
    """
    return AppError(
        status_code=status.HTTP_401_UNAUTHORIZED,
        code=ErrorCode.AUTH_NOT_AUTHENTICATED,
        detail="Authentication required",
    )


def user_not_found_error() -> AppError:
    """Create the standard 404 for an unresolved user-identifying parameter.

    See `docs/api-spec.md` (User Identifier Resolution). Endpoints that
    resolve a UUID-or-username parameter via
    `user_service.resolve_user_identifier()` (or any other service
    raising the shared `UserNotFoundError`) catch it and raise this,
    so every such endpoint returns the identical envelope.
    """
    return AppError(
        status_code=status.HTTP_404_NOT_FOUND,
        code=ErrorCode.USER_NOT_FOUND,
        detail="User not found.",
    )


def ticket_not_found_error() -> AppError:
    """Create the scoped 404 for an unresolved or inaccessible Ticket.

    See `docs/api-spec.md` (Ticket Accessibility Check): a malformed
    locator, a Ticket UUID, a missing Ticket, and an inaccessible Ticket
    all return this one identical response, so every endpoint that
    catches the shared `TicketNotFoundError` raises this.
    """
    return AppError(
        status_code=status.HTTP_404_NOT_FOUND,
        code=ErrorCode.TICKET_NOT_FOUND,
        detail="Ticket not found.",
    )


def set_session_cookie(response: Response, token: str) -> None:
    """Set the `sentinel_session` cookie with the approved secure attributes.

    Shared by the login endpoint (initial issuance) and this module's
    sliding-refresh attachment — see
    `docs/features/identity/authentication.md` (Frontend session
    behavior, Token refresh) for the attribute rationale.
    """
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=token,
        httponly=True,
        secure=True,
        samesite="strict",
        path="/api",
    )


@dataclass(frozen=True)
class AuthenticatedPrincipal:
    """The resolved identity of an authenticated request.

    See `docs/features/identity/authentication.md` (Authenticated
    Principal): carries the active `User` and the credential mechanism
    that authenticated the request, without retaining any raw
    credential material (no JWT, cookie value, API key plaintext,
    digest, prefix, or API key name). This is the single return type of
    `get_current_user()` and the input to every downstream
    authorization dependency (`require_capability()`,
    `require_session_authentication()`).
    """

    user: User
    credential_kind: CredentialKind


# ---------------------------------------------------------------------------
# Unknown API key warning limiter
# ---------------------------------------------------------------------------
#
# See `docs/features/identity/authentication.md` (API key validation,
# step 2): a bounded, per-instance, per-ASGI-peer-address rate limiter
# for the `api_key_validation_failed` WARNING emitted on a hash lookup
# miss only. Denial (the HTTP 401 response) is never rate-limited —
# only the log emission is suppressed.

_LIMITER_WINDOW_SECONDS = 60
_LIMITER_INACTIVITY_SECONDS = 300
_LIMITER_MAX_ENTRIES = 10_000
_UNKNOWN_PEER_SENTINEL = "unknown"


@dataclass
class _LimiterEntry:
    last_emitted_at: datetime
    last_seen_at: datetime
    suppressed_count: int


class UnknownKeyWarningLimiter:
    """Per-instance, per-peer rate limiter for the unknown-API-key WARNING.

    Bounds: at most one WARNING per 60 seconds per ASGI peer address: a
    10,000-entry maximum with LRU eviction on overflow, and a 5-minute
    inactivity eviction — see `docs/features/identity/authentication.md`
    (API key validation, step 2). Not designed for cross-task
    concurrency control (a single asyncio event loop serializes calls
    to `record()` within one server process); multiple worker processes
    each maintain independent state ("with N instances, the worst case
    is N WARNINGs per minute per IP").
    """

    def __init__(self) -> None:
        # Ordered by ascending `last_seen_at`: every access moves its
        # entry to the end, so the front is always the least-recently
        # seen — both LRU eviction and inactivity eviction scan from
        # the front and stop at the first entry that is still fresh.
        self._entries: OrderedDict[str, _LimiterEntry] = OrderedDict()

    def record(self, peer: str, now: datetime) -> int | None:
        """Register one failed lookup from `peer` at `now`.

        Returns the `suppressed_count` to log when a WARNING should be
        emitted for this call, or `None` when emission is suppressed
        (within the 60-second window of a previous emission for the
        same peer).
        """
        self._evict_inactive(now)

        entry = self._entries.get(peer)
        if entry is None:
            if len(self._entries) >= _LIMITER_MAX_ENTRIES:
                self._entries.popitem(last=False)
            self._entries[peer] = _LimiterEntry(
                last_emitted_at=now, last_seen_at=now, suppressed_count=0
            )
            return 0

        entry.last_seen_at = now
        self._entries.move_to_end(peer)
        if (now - entry.last_emitted_at).total_seconds() >= _LIMITER_WINDOW_SECONDS:
            emitted = entry.suppressed_count
            entry.last_emitted_at = now
            entry.suppressed_count = 0
            return emitted
        entry.suppressed_count += 1
        return None

    def _evict_inactive(self, now: datetime) -> None:
        while self._entries:
            peer, entry = next(iter(self._entries.items()))
            if (now - entry.last_seen_at).total_seconds() < _LIMITER_INACTIVITY_SECONDS:
                break
            del self._entries[peer]


# Module-level singleton — one limiter per server process, matching the
# "per-instance in-memory dictionary (no Redis)" storage contract.
_unknown_key_limiter = UnknownKeyWarningLimiter()


def _record_unknown_key_attempt(request: Request, now: datetime) -> None:
    """Update the limiter for an API key hash lookup miss and emit the
    rate-limited WARNING when not suppressed.

    The peer key is the ASGI peer address (`request.client.host`); a
    `None` `request.client` (e.g. a Unix domain socket connection) uses
    the sentinel `"unknown"` so all such requests share one bucket. No
    forwarded header (`X-Forwarded-For`, `Forwarded`) is consulted.
    """
    peer = request.client.host if request.client is not None else _UNKNOWN_PEER_SENTINEL
    suppressed_count = _unknown_key_limiter.record(peer, now)
    if suppressed_count is not None:
        logger.warning(
            "api_key_validation_failed",
            source_ip=peer,
            suppressed_count=suppressed_count,
        )


# ---------------------------------------------------------------------------
# `last_used_at` debounce
# ---------------------------------------------------------------------------
#
# See `docs/features/identity/authentication.md` (API key validation,
# step 5): the debounced operational touch, at most once per minute per
# key per server instance, in a transaction dedicated to this
# best-effort write.

_DEBOUNCE_INTERVAL_SECONDS = 60


def get_last_used_session_factory() -> async_sessionmaker[AsyncSession]:
    """Return the session factory for the dedicated `last_used_at` touch
    transaction.

    Performs no I/O — returns the production `async_session_factory`.
    Extracted as its own function — mirroring
    `session_service.get_session_redis_url()` — so tests can redirect it
    via `monkeypatch.setattr()` to a factory bound to the test engine,
    without needing a FastAPI dependency override.
    """
    return async_session_factory


class LastUsedDebouncer:
    """Per-instance debounce state for the `last_used_at` operational touch.

    A per-key `asyncio.Lock` serializes concurrent requests
    authenticating with the same key so they cannot both observe a
    stale "not yet written this minute" state and issue two writes.
    The lock map grows with the number of distinct keys ever
    authenticated by this process — bounded by the number of API keys
    that actually exist (unlike the peer-address limiter above, which
    must defend against unbounded IP spoofing).
    """

    def __init__(self) -> None:
        self._last_write_at: dict[UUID, datetime] = {}
        self._locks: dict[UUID, asyncio.Lock] = {}

    def _lock_for(self, key_id: UUID) -> asyncio.Lock:
        lock = self._locks.get(key_id)
        if lock is None:
            lock = asyncio.Lock()
            self._locks[key_id] = lock
        return lock

    async def touch(self, key_id: UUID, now: datetime) -> None:
        """Best-effort debounced write of `last_used_at` for `key_id`.

        Skips silently if less than 60 seconds have elapsed since the
        last successful write recorded for this key on this instance.
        Otherwise opens a transaction dedicated to this write — an
        orchestration boundary that owns its own session rather than
        the caller-supplied request session, per
        `docs/conventions.md` (Transaction and Locking) — commits on
        success and records the debounce timestamp only after that
        commit, or rolls back and leaves both the debounce timestamp
        and the (otherwise valid) authentication outcome unaffected on
        failure.
        """
        async with self._lock_for(key_id):
            last_write = self._last_write_at.get(key_id)
            if (
                last_write is not None
                and (now - last_write).total_seconds() < _DEBOUNCE_INTERVAL_SECONDS
            ):
                return

            async with get_last_used_session_factory()() as session:
                try:
                    await api_key_service.update_last_used_at(session, key_id, now)
                except Exception:
                    await session.rollback()
                    logger.warning(
                        "api_key_last_used_touch_failed",
                        key_id=str(key_id),
                        exc_info=True,
                    )
                    return
                await session.commit()

            self._last_write_at[key_id] = now


# Module-level singleton — one debounce cache per server process.
_last_used_debouncer = LastUsedDebouncer()


# ---------------------------------------------------------------------------
# Credential sub-flows
# ---------------------------------------------------------------------------


async def _authenticate_jwt(
    db: DatabaseSession, response: Response, token: str, now: datetime
) -> User:
    """JWT validation sub-flow — see `authentication.md`, JWT validation."""
    try:
        claims = decode_and_validate(
            token, secret_key=settings.jwt_secret_key.get_secret_value(), now=now
        )
    except InvalidTokenError:
        raise unauthenticated_error() from None

    if not await is_session_active(db, claims.session_id):
        raise unauthenticated_error()

    user = await user_service.get_user_by_id(db, claims.user_id)
    if user is None or not user.active:
        raise unauthenticated_error()

    # Sliding refresh occurs here — after the user-active check — so a
    # refreshed cookie is never emitted alongside a 401 for an inactive
    # user (authentication.md, Shared Credential Resolution step 6).
    refreshed = refresh_token(
        claims,
        now=now,
        jwt_expiry_hours=settings.jwt_expiry_hours,
        secret_key=settings.jwt_secret_key.get_secret_value(),
    )
    if refreshed is not None:
        try:
            set_session_cookie(response, refreshed.token)
        except Exception:
            # If the Set-Cookie header cannot be attached for any
            # reason, the old JWT remains valid and the request still
            # succeeds — the refresh is simply retried on the next
            # eligible request (authentication.md, Token refresh notes).
            logger.warning("session_cookie_refresh_failed", exc_info=True)

    return user


async def _authenticate_api_key(
    db: DatabaseSession, request: Request, token: str, now: datetime
) -> User:
    """API key validation sub-flow — see `authentication.md`, API key
    validation."""
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
    api_key = await api_key_service.get_key_by_hash(db, digest)
    if api_key is None:
        _record_unknown_key_attempt(request, now)
        raise unauthenticated_error()

    # Revoked and expired keys never authorize and never emit the
    # unknown-key warning (lookup miss only) — authentication.md, API
    # key validation, steps 3-4.
    if api_key.revoked_at is not None:
        raise unauthenticated_error()
    if api_key.expires_at is not None and api_key.expires_at <= now:
        raise unauthenticated_error()

    await _last_used_debouncer.touch(api_key.id, now)

    user = await user_service.get_user_by_id(db, api_key.user_id)
    if user is None or not user.active:
        raise unauthenticated_error()
    return user


# ---------------------------------------------------------------------------
# Shared credential resolution — `get_current_user` / `get_optional_current_user`
# ---------------------------------------------------------------------------


async def _resolve_principal(
    request: Request,
    response: Response,
    db: DatabaseSession,
) -> AuthenticatedPrincipal | None:
    """Apply Shared Credential Resolution and return the principal, or
    `None` when no credential is selected.

    See `docs/features/identity/authentication.md` (Authentication
    Dependencies, Shared Credential Resolution): `get_current_user` and
    `get_optional_current_user` share this single selection and
    validation path and differ only in how they handle the `None`
    case — they must never diverge on validation behavior or
    successful-authentication side effects. `Authorization: Bearer`
    takes precedence over the `sentinel_session` cookie; JWT-vs-API-key
    dispatch uses the `stl_ak_` prefix; any selected-but-rejected
    credential raises the generic 401 (never converted to `None` here);
    and JWT requests receive the sliding refresh evaluation.
    """
    credential = extract_credential(
        request.headers.get("authorization"),
        request.cookies.get(SESSION_COOKIE_NAME),
    )
    if credential is None:
        return None

    now = datetime.now(UTC)
    if credential.startswith(API_KEY_PREFIX):
        user = await _authenticate_api_key(db, request, credential, now)
        credential_kind = CredentialKind.API_KEY
    else:
        user = await _authenticate_jwt(db, response, credential, now)
        credential_kind = CredentialKind.JWT

    return AuthenticatedPrincipal(user=user, credential_kind=credential_kind)


async def get_current_user(
    request: Request,
    response: Response,
    db: DatabaseSession,
) -> AuthenticatedPrincipal:
    """Resolve and validate the request's credential; reject if absent.

    See `docs/features/identity/authentication.md` (`get_current_user`):
    applies Shared Credential Resolution and returns the generic 401
    when no credential is selected. Injected via `Depends()` into every
    endpoint that requires authentication.
    """
    principal = await _resolve_principal(request, response, db)
    if principal is None:
        raise unauthenticated_error()
    return principal


CurrentUser = Annotated[AuthenticatedPrincipal, Depends(get_current_user)]


async def get_optional_current_user(
    request: Request,
    response: Response,
    db: DatabaseSession,
) -> AuthenticatedPrincipal | None:
    """Resolve and validate the request's credential; return `None` if absent.

    See `docs/features/identity/authentication.md`
    (`get_optional_current_user`): applies Shared Credential Resolution
    to Public endpoints that declare `Authentication: Optional`. Returns
    `None` only when no credential is selected — no user/session/API-key
    lookup, refresh, `last_used_at` touch, or unknown-key WARNING occurs
    in that case. A selected credential is validated exactly as in
    `get_current_user`: success returns the same `AuthenticatedPrincipal`
    with the same side effects (JWT refresh, API-key `last_used_at`
    touch); rejection raises the same generic 401 rather than degrading
    to anonymous access.
    """
    return await _resolve_principal(request, response, db)


OptionalCurrentUser = Annotated[
    AuthenticatedPrincipal | None, Depends(get_optional_current_user)
]


# ---------------------------------------------------------------------------
# Authorization dependencies
# ---------------------------------------------------------------------------


def require_capability(
    capability: Capability,
) -> Callable[..., Awaitable[AuthenticatedPrincipal]]:
    """Dependency factory enforcing a single required capability.

    See `docs/features/identity/rbac.md` (`require_capability()`
    Dependency): loads the principal's current roles from the
    `UserRole` table on every request, unions their capabilities, and
    returns the unchanged principal when `capability` is included.
    Otherwise raises the generic 403 without disclosing the required or
    the caller's missing capability. Assumes the request has already
    passed `get_current_user` (which verifies `User.active`); this
    dependency does not re-verify active status.
    """

    async def _dependency(
        db: DatabaseSession, principal: CurrentUser
    ) -> AuthenticatedPrincipal:
        roles = await user_service.get_user_roles(db, principal.user.id)
        if capability not in get_capabilities(roles):
            raise AppError(
                status_code=status.HTTP_403_FORBIDDEN,
                code=ErrorCode.AUTH_INSUFFICIENT_PERMISSION,
                detail="Insufficient permissions",
            )
        return principal

    return _dependency


async def require_session_authentication(
    principal: CurrentUser,
) -> AuthenticatedPrincipal:
    """Reject API-key-authenticated requests; pass JWT sessions through.

    See `docs/features/identity/authentication.md` (Session-Only
    Authentication Dependency). Relies entirely on the credential kind
    already resolved by `get_current_user` — does not re-parse the
    request or duplicate the `stl_ak_` recognition rule. Shared by every
    endpoint that must not be reachable with an API key (API key
    creation, and the credential-minting admin user endpoints — see the
    Endpoint Permission Map in `docs/features/identity/rbac.md`).
    """
    if principal.credential_kind is CredentialKind.API_KEY:
        raise AppError(
            status_code=status.HTTP_403_FORBIDDEN,
            code=ErrorCode.AUTH_SESSION_REQUIRED,
            detail="This operation requires session authentication.",
        )
    return principal


# ---------------------------------------------------------------------------
# Ticket caller information and the `{ticket_id}` accessibility boundary
# ---------------------------------------------------------------------------


async def _ticket_caller_for(
    db: AsyncSession, principal: AuthenticatedPrincipal | None
) -> TicketCaller:
    """Map a validated principal (or `None`) to the Ticket caller value.

    See `docs/features/identity/rbac.md` (Optional Principal to Caller
    Context): `None` is the anonymous caller and loads no roles; an
    authenticated principal's current roles are loaded once and reduced
    to the effective scope with `get_effective_scope()`. The result is a
    plain service-layer value, so services never import API types.
    """
    if principal is None:
        return ANONYMOUS_CALLER
    roles = await user_service.get_user_roles(db, principal.user.id)
    return TicketCaller.authenticated(principal.user.id, get_effective_scope(roles))


async def get_ticket_caller(
    db: DatabaseSession, principal: CurrentUser
) -> TicketCaller:
    """Resolve the authenticated caller of a Ticket-derived operation.

    For `Access: Authenticated` and capability-protected endpoints: runs
    after `get_current_user`, so an absent or invalid credential returns
    the global 401 before any role or Ticket lookup. FastAPI caches the
    result per request, so the caller is resolved once and never
    reconstructed later in the same request.
    """
    return await _ticket_caller_for(db, principal)


async def get_optional_ticket_caller(
    db: DatabaseSession, principal: OptionalCurrentUser
) -> TicketCaller:
    """Resolve the caller of a Public (`Authentication: Optional`) Ticket read.

    No selected credential yields `ANONYMOUS_CALLER` without any role
    lookup; a selected invalid credential has already returned the
    global 401 in `get_optional_current_user`. Cached per request like
    `get_ticket_caller`.
    """
    return await _ticket_caller_for(db, principal)


AuthenticatedTicketCaller = Annotated[TicketCaller, Depends(get_ticket_caller)]
OptionalTicketCaller = Annotated[TicketCaller, Depends(get_optional_ticket_caller)]

TicketIdPath = Annotated[
    str,
    Path(
        description="Canonical Ticket identity (`SNTL-{n}`).",
        examples=["SNTL-42"],
    ),
]
"""The `{ticket_id}` path parameter.

Deliberately an unconstrained string: a malformed value must reach the
service and produce `404 TICKET_NOT_FOUND`, not the `422` a schema
pattern would return (`docs/api-spec.md`, Ticket Identifier Resolution).
"""


async def require_accessible_ticket(
    ticket_id: TicketIdPath,
    db: DatabaseSession,
    caller: AuthenticatedTicketCaller,
) -> ResolvedTicket:
    """The `require_accessible_ticket` boundary role for authenticated paths.

    See `docs/api-spec.md` (Ticket Accessibility Check) and
    `docs/features/identity/rbac.md` (Permission Checking): delegates the
    locator resolution and visibility decision to
    `ticket_service.resolve_ticket_locator()` and maps its
    `TicketNotFoundError` to the one identical `404 TICKET_NOT_FOUND`.
    It performs no ORM query itself. The result is a preliminary
    decision for shared HTTP handling only: the protected read or
    locked mutation that follows re-applies visibility in its own
    selection and never relies on this result to authorize an
    unconstrained query.
    """
    try:
        return await ticket_service.resolve_ticket_locator(db, ticket_id, caller)
    except TicketNotFoundError:
        raise ticket_not_found_error() from None
