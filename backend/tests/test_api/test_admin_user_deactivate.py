"""End-to-end tests for `POST /api/v1/admin/users/{user}/deactivate`
(`backend/app/api/v1/users.py`, `deactivate_user_admin`), and for the
stale session-liveness cache around a real deactivation and reactivation.

Owning specifications:

- docs/features/identity/user-management.md (Admin API endpoints preamble,
  Deactivate User, Get User response shape).
- docs/features/identity/user-service.md (`deactivate_user()`, Mutation
  Result Types).
- docs/features/identity/authentication.md (Session liveness check,
  including "Deactivation while the target remains inactive"; Session
  invalidation, `purge_session_cache()`; Deactivation ordering; Shared
  Credential Resolution).
- docs/features/identity/rbac.md (Endpoint Permission Map, Business Rules
  3-5).
- docs/api-spec.md (User Identifier Resolution, NUL Characters in Request
  Input, Global Responses, Authorization Chain Evaluation Order).
- docs/features/platform/testing-strategy.md (User Lifecycle and
  Management, "Deactivation API"; Authentication and Session, "Session
  liveness and invalidation"; API Key Management, no direct `ApiKey`
  query; Mandatory Test Scenarios, API Endpoints and User Identifier
  Resolution; Redis Strategy).

Guard classification, rollback of every composed step, and attribution of
`deactivate_user()` are proven by `tests/test_services/test_deactivate_user.py`;
these tests cover the HTTP contract, the transaction boundary, the
post-commit purge, and the credential path after deactivation. Two
precedence rows have no API path and are left to the service tests: an
inactive self-target (an inactive administrator cannot authenticate) and an
active external self-target (the authenticated caller is a local user).

Two worlds serve the requests:

- the shared rollback-owned `client` (one test transaction, no commit, no
  post-commit callback) for the HTTP contract and the persisted effects;
- `committed`: the production `app.database.get_db` over independent
  pooled sessions of the test engine, so its real commit, rollback, and
  post-commit callbacks run. A journal records each request commit, each
  purge, and each `http.response.start` message as the ASGI server would
  see it. Committed rows are deleted explicitly at teardown.

Expected values are transcribed from the specifications; nothing here
computes an expectation with the module under test.
"""

from __future__ import annotations

import asyncio
import hashlib
import secrets
import uuid
from collections.abc import AsyncGenerator, Awaitable, Callable, Iterator
from contextlib import ExitStack
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest
import pytest_asyncio
import redis.asyncio as redis_asyncio
from httpx import ASGITransport, AsyncClient
from redis.exceptions import RedisError
from sqlalchemy import delete, select
from sqlalchemy.exc import OperationalError
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker
from starlette.types import Message, Receive, Scope, Send

from app import database
from app.api.v1 import users as users_routes
from app.core.enums import Role, SessionCreationReason
from app.core.exceptions import UserNotFoundError
from app.database import get_db
from app.main import app
from app.models.api_key import ApiKey
from app.models.identity_audit_event import IdentityAuditEvent
from app.models.session import Session as SessionRow
from app.models.user import User
from app.models.user_role import UserRole
from app.services import api_key_service, session_service, user_service
from app.services.session_service import create_session
from app.services.user_service import DeactivationResult
from tests.support.ticket_api import INTERNAL_ERROR, force_production_error_page
from tests.support.ticket_mutations import StatementRecorder

Factory = Callable[..., Awaitable[Any]]
EventRow = tuple[str, uuid.UUID | None, str | None, str | None, object]

# user-management.md, Deactivate User step 3.
_API_REASON = "deactivated by admin via API"
_EXTERNAL_GROUP = "Example Security Group"
# Fictional bcrypt-shaped value, never a real hash.
_FICTIONAL_PASSWORD_HASH = "$2b$12$" + "d" * 53
_USER_NOT_FOUND = {"code": "USER_NOT_FOUND", "detail": "User not found."}
# user-management.md, Deactivate User error table and rendered details.
_EXTERNAL_READONLY = {
    "code": "USER_EXTERNAL_STATUS_READONLY",
    "detail": "Cannot deactivate external users.",
}
_SELF_DEACTIVATION = {
    "code": "USER_SELF_DEACTIVATION",
    "detail": "Cannot deactivate your own account.",
}
# api-spec.md, Global Responses.
_UNAUTHENTICATED = {
    "code": "AUTH_NOT_AUTHENTICATED",
    "detail": "Authentication required",
}
_FORBIDDEN = {
    "code": "AUTH_INSUFFICIENT_PERMISSION",
    "detail": "Insufficient permissions",
}
_NUL_ERROR = {"msg": "Value error, must not contain U+0000", "type": "value_error"}
# user-management.md, Get User.
_PROFILE_FIELDS = {
    "id",
    "username",
    "email",
    "full_name",
    "active",
    "source",
    "external_id",
    "manager",
    "roles",
    "created_at",
    "updated_at",
}
_ME = "/api/v1/users/me"


def _url(identifier: object) -> str:
    return f"/api/v1/admin/users/{identifier}/deactivate"


def _liveness_key(session_id: uuid.UUID) -> str:
    """authentication.md, Session liveness check: cache value contract."""
    return f"session_liveness:{session_id}"


# ---------------------------------------------------------------------------
# Shared helpers and fixtures
# ---------------------------------------------------------------------------


def _make_api_key_credential() -> tuple[str, str]:
    """Return `(plaintext_token, sha256_hex_digest)` for a synthetic key.

    Mirrors the identical helper in `tests/test_api/test_users.py`.
    """
    token = "stl_ak_" + secrets.token_hex(16)
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
    return token, digest


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _assert_nul_rejection(response_json: object, loc: list[object]) -> None:
    """Mirrors the identical helper in `tests/test_api/test_request_nul.py`."""
    assert response_json == {
        "code": "VALIDATION_ERROR",
        "detail": "Request validation failed",
        "errors": [{"loc": loc, **_NUL_ERROR}],
    }


async def _active(db: AsyncSession, user_id: uuid.UUID) -> bool:
    return bool(
        (await db.execute(select(User.active).where(User.id == user_id))).scalar_one()
    )


async def _keys(
    db: AsyncSession, user_id: uuid.UUID
) -> dict[uuid.UUID, tuple[datetime | None, uuid.UUID | None]]:
    """Current `(revoked_at, revoked_by)` of every key of the User."""
    rows = await db.execute(
        select(ApiKey.id, ApiKey.revoked_at, ApiKey.revoked_by).where(
            ApiKey.user_id == user_id
        )
    )
    return {row.id: (row.revoked_at, row.revoked_by) for row in rows}


async def _sessions(db: AsyncSession, user_id: uuid.UUID) -> dict[uuid.UUID, bool]:
    rows = await db.execute(
        select(SessionRow.id, SessionRow.is_active).where(SessionRow.user_id == user_id)
    )
    return {row.id: row.is_active for row in rows}


async def _identity_events(
    db: AsyncSession, target_user_id: uuid.UUID
) -> list[EventRow]:
    """Every `IdentityAuditEvent` targeting the user, in insertion (UUIDv7)
    order, as `(event_type, user_id, old_value, new_value, detail)`."""
    rows = (
        await db.execute(
            select(IdentityAuditEvent)
            .where(IdentityAuditEvent.target_user_id == target_user_id)
            .order_by(IdentityAuditEvent.id)
        )
    ).scalars()
    return [
        (row.event_type, row.user_id, row.old_value, row.new_value, row.detail)
        for row in rows
    ]


def _deactivated_event(actor: uuid.UUID | None) -> EventRow:
    """user-service.md, `deactivate_user()` step 5, with the API reason."""
    return ("user_deactivated", actor, "active", "inactive", {"reason": _API_REASON})


@pytest.fixture(autouse=True)
def _reset_redis_outage_state() -> Iterator[None]:
    """Reset the per-process outage-episode flag around every test: it is
    module-level state a simulated `RedisError` sets (testing-strategy.md,
    Test Independence; mirrors `tests/test_services/test_session_service.py`)."""
    session_service._redis_outage_active = False
    yield
    session_service._redis_outage_active = False


@pytest.fixture
def no_last_used_write(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep the API-key `last_used_at` touch out of these tests, as the
    precedent API-key tests do."""
    monkeypatch.setattr(
        api_key_service, "update_last_used_at", AsyncMock(return_value=True)
    )


@pytest_asyncio.fixture
async def admin_user_and_client(
    _authenticated_user_and_client: tuple[User, AsyncClient],
    user_role_factory: Factory,
) -> tuple[User, AsyncClient]:
    """The shared `client` authenticated by a JWT session as a user holding
    only the `_manual` Admin origin. Mirrors the identical fixture in
    `tests/test_api/test_admin_user_roles.py`."""
    user, client = _authenticated_user_and_client
    await user_role_factory(user_id=user.id, role=Role.ADMIN.value)
    return user, client


# ---------------------------------------------------------------------------
# A. Authentication and authorization
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestAuthenticationAndAuthorization:
    async def test_unauthenticated_returns_401_and_changes_nothing(
        self, client: AsyncClient, user_factory: Factory, db_session: AsyncSession
    ) -> None:
        target: User = await user_factory(username="bob.va")

        response = await client.post(_url(target.id))

        assert response.status_code == 401
        assert response.json() == _UNAUTHENTICATED
        assert await _active(db_session, target.id) is True
        assert await _identity_events(db_session, target.id) == []

    async def test_without_manage_users_returns_403_before_any_user_lookup(
        self,
        authenticated_client: AsyncClient,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The capability check precedes identifier resolution: an existing
        or missing user yields the generic 403, and no lookup or mutation
        runs (api-spec.md, Authorization Chain Evaluation Order)."""
        resolve = AsyncMock(side_effect=AssertionError("lookup must not run"))
        mutation = AsyncMock(side_effect=AssertionError("mutation must not run"))
        monkeypatch.setattr(user_service, "resolve_user_identifier", resolve)
        monkeypatch.setattr(user_service, "deactivate_user", mutation)

        responses = [
            await authenticated_client.post(_url(identifier))
            for identifier in (uuid4(), "no-such-user")
        ]

        for response in responses:
            assert response.status_code == 403
            assert response.json() == _FORBIDDEN
        resolve.assert_not_awaited()
        mutation.assert_not_awaited()

    async def test_admin_jwt_session_is_accepted(
        self,
        admin_user_and_client: tuple[User, AsyncClient],
        user_factory: Factory,
        db_session: AsyncSession,
    ) -> None:
        admin, client = admin_user_and_client
        target: User = await user_factory(username="bob.va")

        response = await client.post(_url(target.id))

        assert response.status_code == 200
        assert response.json()["data"]["active"] is False
        assert await _identity_events(db_session, target.id) == [
            _deactivated_event(admin.id)
        ]

    async def test_admin_api_key_is_accepted(
        self,
        client: AsyncClient,
        user_factory: Factory,
        user_role_factory: Factory,
        api_key_factory: Factory,
        db_session: AsyncSession,
        no_last_used_write: None,
    ) -> None:
        """Deactivation is not session-only (rbac.md, Endpoint Permission
        Map): an administrator's API key is accepted, and the key's owner
        is the audit actor."""
        admin: User = await user_factory(username="alice.admin")
        await user_role_factory(user_id=admin.id, role=Role.ADMIN.value)
        token, digest = _make_api_key_credential()
        await api_key_factory(user_id=admin.id, key_hash=digest)
        target: User = await user_factory(username="bob.va")

        response = await client.post(_url(target.id), headers=_bearer(token))

        assert response.status_code == 200
        assert response.json()["data"]["active"] is False
        assert await _identity_events(db_session, target.id) == [
            _deactivated_event(admin.id)
        ]


# ---------------------------------------------------------------------------
# B. Identifier resolution
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestIdentifierResolution:
    async def test_uuid_and_username_produce_the_same_outcome(
        self,
        admin_user_and_client: tuple[User, AsyncClient],
        user_factory: Factory,
        db_session: AsyncSession,
    ) -> None:
        """Two identically shaped targets, one addressed by UUID and one by
        username, return the same profile apart from their identity
        fields, and both are effectively deactivated."""
        admin, client = admin_user_and_client
        by_id_target: User = await user_factory(
            username="bob.va", full_name="Bob Example"
        )
        by_name_target: User = await user_factory(
            username="carol.va", full_name="Bob Example"
        )
        identity_fields = {"id", "username", "email", "created_at", "updated_at"}

        by_uuid = await client.post(_url(by_id_target.id))
        by_username = await client.post(_url(by_name_target.username))

        assert by_uuid.status_code == 200
        assert by_username.status_code == 200
        uuid_data = by_uuid.json()["data"]
        username_data = by_username.json()["data"]
        assert uuid_data["id"] == str(by_id_target.id)
        assert username_data["id"] == str(by_name_target.id)
        assert {k: v for k, v in uuid_data.items() if k not in identity_fields} == {
            k: v for k, v in username_data.items() if k not in identity_fields
        }
        assert uuid_data["active"] is False
        for target in (by_id_target, by_name_target):
            assert await _identity_events(db_session, target.id) == [
                _deactivated_event(admin.id)
            ]

    async def test_unknown_uuid_returns_404(
        self, admin_user_and_client: tuple[User, AsyncClient]
    ) -> None:
        _admin, client = admin_user_and_client

        response = await client.post(_url(uuid4()))

        assert response.status_code == 404
        assert response.json() == _USER_NOT_FOUND

    async def test_unknown_username_returns_404(
        self, admin_user_and_client: tuple[User, AsyncClient]
    ) -> None:
        _admin, client = admin_user_and_client

        response = await client.post(_url("no-such-user"))

        assert response.status_code == 404
        assert response.json() == _USER_NOT_FOUND

    async def test_user_deleted_after_resolution_returns_404(
        self,
        admin_user_and_client: tuple[User, AsyncClient],
        user_factory: Factory,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Maps the service's own `UserNotFoundError` (a user removed
        between resolution and the service lock) to the same 404. The race
        itself belongs to the service tier; this proves only the mapping."""
        _admin, client = admin_user_and_client
        target: User = await user_factory(username="bob.va")
        monkeypatch.setattr(
            user_service, "deactivate_user", AsyncMock(side_effect=UserNotFoundError())
        )

        response = await client.post(_url(target.id))

        assert response.status_code == 404
        assert response.json() == _USER_NOT_FOUND


# ---------------------------------------------------------------------------
# C. Guards, their exact bodies, and the documented precedence
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestGuards:
    async def test_active_external_target_returns_409_without_effect(
        self,
        admin_user_and_client: tuple[User, AsyncClient],
        user_factory: Factory,
        api_key_factory: Factory,
        session_factory: Factory,
        db_session: AsyncSession,
    ) -> None:
        _admin, client = admin_user_and_client
        target: User = await user_factory(
            username="erin.external", external_id=uuid4(), password_hash=None
        )
        key = await api_key_factory(user_id=target.id)
        session = await session_factory(user_id=target.id)

        response = await client.post(_url(target.id))

        assert response.status_code == 409
        assert response.json() == _EXTERNAL_READONLY
        assert await _active(db_session, target.id) is True
        assert await _keys(db_session, target.id) == {key.id: (None, None)}
        assert await _sessions(db_session, target.id) == {session.id: True}
        assert await _identity_events(db_session, target.id) == []

    @pytest.mark.parametrize("form", ["uuid", "username"])
    async def test_self_target_returns_409_without_effect(
        self,
        form: str,
        admin_user_and_client: tuple[User, AsyncClient],
        api_key_factory: Factory,
        db_session: AsyncSession,
    ) -> None:
        admin, client = admin_user_and_client
        key = await api_key_factory(user_id=admin.id)
        sessions_before = await _sessions(db_session, admin.id)
        identifier = admin.id if form == "uuid" else admin.username

        response = await client.post(_url(identifier))

        assert response.status_code == 409
        assert response.json() == _SELF_DEACTIVATION
        assert await _active(db_session, admin.id) is True
        assert await _keys(db_session, admin.id) == {key.id: (None, None)}
        assert sessions_before
        assert all(sessions_before.values())
        assert await _sessions(db_session, admin.id) == sessions_before
        assert await _identity_events(db_session, admin.id) == []

    async def test_inactive_external_target_is_a_200_no_op_before_the_external_guard(
        self,
        admin_user_and_client: tuple[User, AsyncClient],
        user_factory: Factory,
        db_session: AsyncSession,
    ) -> None:
        """user-management.md, Deactivate User Guard ordering: the
        already-inactive no-op precedes the active external rejection."""
        _admin, client = admin_user_and_client
        external_id = uuid4()
        target: User = await user_factory(
            username="erin.external",
            external_id=external_id,
            password_hash=None,
            active=False,
        )

        response = await client.post(_url(target.id))

        assert response.status_code == 200
        data = response.json()["data"]
        assert data["id"] == str(target.id)
        assert data["active"] is False
        assert data["source"] == "external"
        assert data["external_id"] == str(external_id)
        assert await _identity_events(db_session, target.id) == []


# ---------------------------------------------------------------------------
# D. Success: response shape and persisted effects
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestEffectiveDeactivation:
    async def test_returns_the_complete_profile_without_the_service_flag(
        self,
        admin_user_and_client: tuple[User, AsyncClient],
        user_factory: Factory,
        user_role_factory: Factory,
    ) -> None:
        """user-management.md, Deactivate User step 6: the Get User profile
        in the `{"data": ...}` envelope, never the `deactivated` flag."""
        _admin, client = admin_user_and_client
        manager: User = await user_factory(
            username="dave.manager", full_name="Dave Example"
        )
        target: User = await user_factory(
            username="bob.va", full_name="Bob Example", manager_id=manager.id
        )
        await user_role_factory(
            user_id=target.id, role=Role.VULNERABILITY_ANALYST.value
        )
        await user_role_factory(
            user_id=target.id,
            role=Role.VULNERABILITY_ANALYST.value,
            group_name=_EXTERNAL_GROUP,
        )

        response = await client.post(_url(target.username))

        assert response.status_code == 200
        body = response.json()
        assert set(body) == {"data"}
        data = body["data"]
        assert set(data) == _PROFILE_FIELDS
        assert data["id"] == str(target.id)
        assert data["username"] == "bob.va"
        assert data["full_name"] == "Bob Example"
        assert data["active"] is False
        assert data["source"] == "local"
        assert data["external_id"] is None
        assert data["manager"] == {
            "id": str(manager.id),
            "username": "dave.manager",
            "full_name": "Dave Example",
            "active": True,
            "email": manager.email,
        }
        assert [
            (entry["role"], entry["group_name"], entry["assigned_by"])
            for entry in data["roles"]
        ] == [
            ("vulnerability_analyst", _EXTERNAL_GROUP, None),
            ("vulnerability_analyst", "_manual", None),
        ]
        assert "deactivated" not in response.text
        # Same shape and values as the public Get User profile.
        profile = await client.get(f"/api/v1/users/{target.id}")
        assert profile.status_code == 200
        assert profile.json() == body


# ---------------------------------------------------------------------------
# H. U+0000 in the path
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestRequestValidation:
    async def test_nul_in_path_returns_422_without_echo_or_mutation(
        self,
        admin_user_and_client: tuple[User, AsyncClient],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        _admin, client = admin_user_and_client
        resolve = AsyncMock(side_effect=AssertionError("lookup must not run"))
        mutation = AsyncMock(side_effect=AssertionError("mutation must not run"))
        monkeypatch.setattr(user_service, "resolve_user_identifier", resolve)
        monkeypatch.setattr(user_service, "deactivate_user", mutation)

        response = await client.post("/api/v1/admin/users/fictional%00user/deactivate")

        assert response.status_code == 422
        _assert_nul_rejection(response.json(), ["path", "user"])
        assert "fictional" not in response.text
        resolve.assert_not_awaited()
        mutation.assert_not_awaited()


# ---------------------------------------------------------------------------
# I. The handler delegates to the service and runs no query itself
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestHandlerDelegation:
    async def test_actor_and_reason_reach_the_service_without_route_sql(
        self,
        admin_user_and_client: tuple[User, AsyncClient],
        user_factory: Factory,
        db_session: AsyncSession,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """user-management.md, Admin API endpoints preamble and Deactivate
        User steps 2-3; testing-strategy.md, API Key Management: the route
        delegates resolution and the mutation to `user_service` and runs no
        query (in particular none on `ApiKey` or `Session`). Recording
        starts at the handler's first step (the resolution call), so the
        authentication queries are excluded and every remaining statement
        would be the route's own."""
        admin, client = admin_user_and_client
        target: User = await user_factory(username="bob.va", active=False)
        # The serializable profile (roles and manager loaded), taken before
        # the service is replaced.
        profile = await user_service.get_user(db_session, str(target.id))
        resolved = SimpleNamespace(id=uuid4())
        recorder = StatementRecorder(db_session)

        with ExitStack() as stack:

            async def _resolve(db: AsyncSession, identifier: str) -> SimpleNamespace:
                stack.enter_context(recorder)
                return resolved

            resolve = AsyncMock(side_effect=_resolve)
            mutation = AsyncMock(
                return_value=DeactivationResult(
                    user=profile, deactivated=True, invalidated_session_ids=[uuid4()]
                )
            )
            monkeypatch.setattr(user_service, "resolve_user_identifier", resolve)
            monkeypatch.setattr(user_service, "deactivate_user", mutation)

            response = await client.post(_url(target.username))

        assert response.status_code == 200
        assert response.json()["data"]["id"] == str(target.id)
        resolve.assert_awaited_once_with(db_session, target.username)
        mutation.assert_awaited_once_with(
            db_session, resolved.id, acting_user_id=admin.id, reason=_API_REASON
        )
        assert recorder.statements == []


# ---------------------------------------------------------------------------
# Committed world: the production `get_db` over independent sessions
# ---------------------------------------------------------------------------


class _JournaledSession(AsyncSession):
    """A request session that records each successful commit."""

    journal: list[str]

    async def commit(self) -> None:
        await super().commit()
        self.journal.append("commit")


@dataclass
class _Committed:
    """Committed users and credentials plus a client served by the
    production `get_db()`. `journal` records `commit`, `purge`, and
    `response:<status>` in the order the request produced them; `purged`
    records the argument of each purge call."""

    sessions: async_sessionmaker[AsyncSession]
    client: AsyncClient
    redis: redis_asyncio.Redis
    journal: list[str] = field(default_factory=list)
    purged: list[list[uuid.UUID]] = field(default_factory=list)
    user_ids: list[uuid.UUID] = field(default_factory=list)

    async def user(
        self, name: str, *, roles: tuple[Role, ...] = (), active: bool = True
    ) -> User:
        suffix = uuid4().hex[:10]
        async with self.sessions() as db:
            user = User(
                username=f"{name}.{suffix}",
                email=f"{name}.{suffix}@example.com",
                full_name="Example Person",
                password_hash=_FICTIONAL_PASSWORD_HASH,
                active=active,
            )
            db.add(user)
            await db.flush()
            self.user_ids.append(user.id)
            for role in roles:
                db.add(UserRole(user_id=user.id, role=role.value))
            await db.commit()
        return user

    async def login(self, user: User) -> tuple[uuid.UUID, str]:
        """A real active Session and its JWT."""
        async with self.sessions() as db:
            created = await create_session(
                db, user, SessionCreationReason.LOCAL_LOGIN, expected_password_hash=None
            )
            assert created is not None
            await db.commit()
        return created.session.id, created.token

    async def admin(self) -> tuple[User, dict[str, str]]:
        admin = await self.user("alice.admin", roles=(Role.ADMIN,))
        _session_id, token = await self.login(admin)
        return admin, _bearer(token)

    async def inactive_session(self, user: User) -> uuid.UUID:
        async with self.sessions() as db:
            row = SessionRow(
                user_id=user.id,
                expires_at=datetime.now(UTC) + timedelta(days=30),
                is_active=False,
            )
            db.add(row)
            await db.commit()
        return row.id

    async def api_key(self, user: User) -> tuple[uuid.UUID, str]:
        token, digest = _make_api_key_credential()
        async with self.sessions() as db:
            key = ApiKey(
                user_id=user.id,
                key_hash=digest,
                prefix=token[:12],
                name=f"key-{uuid4().hex[:8]}",
            )
            db.add(key)
            await db.commit()
        return key.id, token

    async def deactivate(self, user: User) -> list[uuid.UUID]:
        """Deactivate through the real service (system actor) and commit,
        without the workflow's post-commit purge."""
        async with self.sessions() as db:
            result = await user_service.deactivate_user(
                db, user.id, acting_user_id=None, reason="fictional offboarding"
            )
            await db.commit()
        assert result.deactivated is True
        return result.invalidated_session_ids

    async def reactivate(self, user: User) -> None:
        async with self.sessions() as db:
            result = await user_service.reactivate_user(
                db, user.id, acting_user_id=None
            )
            await db.commit()
        assert result.reactivated is True

    async def read(self, reader: Callable[[AsyncSession], Awaitable[Any]]) -> Any:
        """Run `reader` in a fresh session: a read after every commit."""
        async with self.sessions() as db:
            return await reader(db)

    async def cleanup(self) -> None:
        ids = self.user_ids
        async with self.sessions() as db:
            for statement in (
                delete(ApiKey).where(
                    ApiKey.user_id.in_(ids) | ApiKey.revoked_by.in_(ids)
                ),
                delete(SessionRow).where(SessionRow.user_id.in_(ids)),
                delete(IdentityAuditEvent).where(
                    IdentityAuditEvent.target_user_id.in_(ids)
                    | IdentityAuditEvent.user_id.in_(ids)
                ),
                delete(UserRole).where(UserRole.user_id.in_(ids)),
                delete(User).where(User.id.in_(ids)),
            ):
                await db.execute(statement)
            await db.commit()


@pytest_asyncio.fixture
async def committed(
    _engine: AsyncEngine,
    redis_client: redis_asyncio.Redis,
    monkeypatch: pytest.MonkeyPatch,
    no_last_used_write: None,
) -> AsyncGenerator[_Committed]:
    """See the module docstring. `redis_client` routes the session cache to
    this worker's Redis database; the purge recorder delegates to the real
    `purge_session_cache()`."""
    assert get_db not in app.dependency_overrides
    sessions = async_sessionmaker(_engine, class_=AsyncSession, expire_on_commit=False)
    request_sessions = async_sessionmaker(
        _engine, class_=_JournaledSession, expire_on_commit=False
    )
    journal: list[str] = []
    purged: list[list[uuid.UUID]] = []

    def _request_session() -> _JournaledSession:
        session = request_sessions()
        session.journal = journal
        return session

    real_purge = session_service.purge_session_cache

    async def _purge(session_ids: list[uuid.UUID]) -> None:
        journal.append("purge")
        purged.append(list(session_ids))
        await real_purge(session_ids)

    async def _journaled_app(scope: Scope, receive: Receive, send: Send) -> None:
        async def _send(message: Message) -> None:
            if message["type"] == "http.response.start":
                journal.append(f"response:{message['status']}")
            await send(message)

        await app(scope, receive, _send)

    monkeypatch.setattr(database, "async_session_factory", _request_session)
    monkeypatch.setattr(users_routes, "purge_session_cache", _purge)
    async with AsyncClient(
        transport=ASGITransport(app=_journaled_app, raise_app_exceptions=False),
        base_url="http://test",
    ) as client:
        world = _Committed(
            sessions=sessions,
            client=client,
            redis=redis_client,
            journal=journal,
            purged=purged,
        )
        try:
            yield world
        finally:
            await world.cleanup()


# ---------------------------------------------------------------------------
# E. Already-inactive target: unchanged profile, no event, no purge
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestAlreadyInactiveTarget:
    async def test_returns_unchanged_profile_without_event_or_purge(
        self, committed: _Committed
    ) -> None:
        _admin, headers = await committed.admin()
        target = await committed.user("bob.va", active=False)
        before = await committed.client.get(f"/api/v1/users/{target.id}")
        assert before.status_code == 200
        committed.journal.clear()

        response = await committed.client.post(_url(target.id), headers=headers)

        assert response.status_code == 200
        assert response.json() == before.json()
        assert response.json()["data"]["active"] is False
        assert committed.journal == ["commit", "response:200"]
        assert committed.purged == []
        assert await committed.read(lambda db: _identity_events(db, target.id)) == []


# ---------------------------------------------------------------------------
# F. Commit ordering and commit failure
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestTransactionBoundary:
    async def test_commit_then_purge_then_response(
        self, committed: _Committed, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """user-management.md, Deactivate User steps 4-5: the flushed
        deactivation is invisible to another transaction before the single
        commit, the purge runs after the commit, and both complete before
        `http.response.start` is sent."""
        admin, headers = await committed.admin()
        target = await committed.user("bob.va")
        session_id, _token = await committed.login(target)
        original = user_service.deactivate_user
        observed: list[bool] = []

        async def _observe(
            db: AsyncSession, *args: Any, **kwargs: Any
        ) -> DeactivationResult:
            result = await original(db, *args, **kwargs)
            observed.append(await committed.read(lambda d: _active(d, target.id)))
            return result

        monkeypatch.setattr(user_service, "deactivate_user", _observe)
        committed.journal.clear()

        response = await committed.client.post(_url(target.id), headers=headers)

        assert response.status_code == 200
        assert observed == [True]
        assert committed.journal == ["commit", "purge", "response:200"]
        assert committed.purged == [[session_id]]
        assert await committed.read(lambda db: _active(db, target.id)) is False
        assert await committed.read(lambda db: _identity_events(db, target.id)) == [
            _deactivated_event(admin.id)
        ]

    async def test_commit_failure_returns_500_persists_nothing_and_skips_purge(
        self, committed: _Committed, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        force_production_error_page(monkeypatch)
        _admin, headers = await committed.admin()
        target = await committed.user("bob.va")
        session_id, _token = await committed.login(target)
        key_id, _key_token = await committed.api_key(target)
        await committed.redis.set(_liveness_key(session_id), "1", ex=60)
        original = user_service.deactivate_user
        reached: list[bool] = []

        async def _fail_commit() -> None:
            raise OperationalError("COMMIT", {}, Exception("simulated commit failure"))

        async def _arm(
            db: AsyncSession, *args: Any, **kwargs: Any
        ) -> DeactivationResult:
            result = await original(db, *args, **kwargs)
            reached.append(result.deactivated)
            monkeypatch.setattr(db, "commit", _fail_commit)
            return result

        monkeypatch.setattr(user_service, "deactivate_user", _arm)
        committed.journal.clear()

        response = await committed.client.post(_url(target.id), headers=headers)

        assert response.status_code == 500
        assert response.json() == INTERNAL_ERROR
        # The deactivation was flushed before the failed commit; none of it
        # survives, and the post-commit purge never runs.
        assert reached == [True]
        assert committed.journal == ["response:500"]
        assert committed.purged == []
        assert await committed.redis.get(_liveness_key(session_id)) == "1"
        assert await committed.read(lambda db: _active(db, target.id)) is True
        assert await committed.read(lambda db: _keys(db, target.id)) == {
            key_id: (None, None)
        }
        assert await committed.read(lambda db: _sessions(db, target.id)) == {
            session_id: True
        }
        assert await committed.read(lambda db: _identity_events(db, target.id)) == []


# ---------------------------------------------------------------------------
# G. Purge content and Redis failure
# ---------------------------------------------------------------------------


class _DeleteFailingRedis:
    """Delegates to a real client but raises `RedisError` on every `delete`,
    recording the attempted keys (testing-strategy.md, Redis Strategy:
    replace the boundary rather than stop the shared server)."""

    def __init__(self, delegate: redis_asyncio.Redis, attempts: list[str]) -> None:
        self._delegate = delegate
        self._attempts = attempts

    async def get(self, key: str) -> Any:
        return await self._delegate.get(key)

    async def set(self, key: str, value: str, ex: int) -> Any:
        return await self._delegate.set(key, value, ex=ex)

    async def delete(self, key: str) -> None:
        self._attempts.append(key)
        raise RedisError("simulated outage")

    async def aclose(self) -> None:
        await self._delegate.aclose()


@pytest.mark.e2e
class TestPostCommitPurge:
    async def test_purges_exactly_the_invalidated_sessions(
        self, committed: _Committed
    ) -> None:
        _admin, headers = await committed.admin()
        target = await committed.user("bob.va")
        other = await committed.user("carol.va")
        first, _ = await committed.login(target)
        second, _ = await committed.login(target)
        inactive = await committed.inactive_session(target)
        others, _ = await committed.login(other)
        for session_id in (first, second, inactive, others):
            await committed.redis.set(_liveness_key(session_id), "1", ex=60)

        response = await committed.client.post(_url(target.id), headers=headers)

        assert response.status_code == 200
        assert len(committed.purged) == 1
        assert sorted(committed.purged[0]) == sorted([first, second])
        assert await committed.redis.get(_liveness_key(first)) is None
        assert await committed.redis.get(_liveness_key(second)) is None
        # Neither the already-inactive Session nor another user's Session
        # was invalidated by this deactivation, so neither is purged.
        assert await committed.redis.get(_liveness_key(inactive)) == "1"
        assert await committed.redis.get(_liveness_key(others)) == "1"

    async def test_redis_failure_still_returns_the_committed_profile(
        self, committed: _Committed, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """authentication.md, `purge_session_cache()`: a `RedisError` is
        best-effort and cannot change the committed HTTP 200."""
        admin, headers = await committed.admin()
        target = await committed.user("bob.va")
        session_id, _token = await committed.login(target)
        await committed.redis.set(_liveness_key(session_id), "1", ex=60)
        attempts: list[str] = []
        real_client = session_service._new_redis_client
        monkeypatch.setattr(
            session_service,
            "_new_redis_client",
            lambda: _DeleteFailingRedis(real_client(), attempts),
        )

        response = await committed.client.post(_url(target.id), headers=headers)

        assert response.status_code == 200
        data = response.json()["data"]
        assert data["id"] == str(target.id)
        assert data["active"] is False
        assert attempts == [_liveness_key(session_id)]
        assert await committed.redis.get(_liveness_key(session_id)) == "1"
        assert await committed.read(lambda db: _active(db, target.id)) is False
        assert await committed.read(lambda db: _sessions(db, target.id)) == {
            session_id: False
        }
        assert await committed.read(lambda db: _identity_events(db, target.id)) == [
            _deactivated_event(admin.id)
        ]


# ---------------------------------------------------------------------------
# K. A stale positive liveness entry around deactivation and reactivation
# ---------------------------------------------------------------------------


@dataclass
class _WriteGate:
    """Holds the first positive-cache write for `key` until released."""

    key: str
    reached: asyncio.Event = field(default_factory=asyncio.Event)
    release: asyncio.Event = field(default_factory=asyncio.Event)
    armed: bool = True


class _HeldWriteRedis:
    """Delegates to a real client; the gated key's first `set` signals
    `reached` and waits for `release` before writing."""

    def __init__(self, delegate: redis_asyncio.Redis, gate: _WriteGate) -> None:
        self._delegate = delegate
        self._gate = gate

    async def get(self, key: str) -> Any:
        return await self._delegate.get(key)

    async def set(self, key: str, value: str, ex: int) -> Any:
        if self._gate.armed and key == self._gate.key:
            self._gate.armed = False
            self._gate.reached.set()
            await self._gate.release.wait()
        return await self._delegate.set(key, value, ex=ex)

    async def delete(self, key: str) -> Any:
        return await self._delegate.delete(key)

    async def aclose(self) -> None:
        await self._delegate.aclose()


async def _assert_positive_entry_within_ttl(
    redis: redis_asyncio.Redis, session_id: uuid.UUID
) -> None:
    """authentication.md, Session liveness check: value `"1"`, TTL 60."""
    assert await redis.get(_liveness_key(session_id)) == "1"
    ttl = await redis.ttl(_liveness_key(session_id))
    assert 0 < ttl <= 60


@pytest.mark.e2e
class TestStaleLivenessEntry:
    """testing-strategy.md, Authentication and Session, Session liveness and
    invalidation; authentication.md, Session liveness check, "Deactivation
    while the target remains inactive". The entry's expiry is simulated by
    deleting the key after asserting its TTL is at most 60 seconds, instead
    of sleeping (issue #810, decision D7)."""

    async def test_inactive_user_is_rejected_despite_a_surviving_entry(
        self, committed: _Committed
    ) -> None:
        _admin, headers = await committed.admin()
        target = await committed.user("bob.va")
        session_id, token = await committed.login(target)
        _key_id, key_token = await committed.api_key(target)
        warm = await committed.client.get(_ME, headers=_bearer(token))
        assert warm.status_code == 200
        await _assert_positive_entry_within_ttl(committed.redis, session_id)

        response = await committed.client.post(_url(target.id), headers=headers)
        assert response.status_code == 200
        assert await committed.redis.get(_liveness_key(session_id)) is None
        # A lost purge: the positive entry survives the deactivation.
        await committed.redis.set(_liveness_key(session_id), "1", ex=60)

        by_jwt = await committed.client.get(_ME, headers=_bearer(token))
        by_key = await committed.client.get(_ME, headers=_bearer(key_token))

        assert by_jwt.status_code == 401
        assert by_jwt.json() == _UNAUTHENTICATED
        # The cache still reports the Session active: the `User.active`
        # check rejected the JWT request.
        await _assert_positive_entry_within_ttl(committed.redis, session_id)
        # API keys never consult the liveness cache; the old key is rejected
        # because the deactivation revoked it (its inactive-owner rejection
        # is proven in tests/test_api/test_dependencies.py).
        assert by_key.status_code == 401
        assert by_key.json() == _UNAUTHENTICATED

    async def test_reactivation_within_the_ttl_accepts_until_the_entry_expires(
        self, committed: _Committed
    ) -> None:
        target = await committed.user("bob.va")
        session_id, token = await committed.login(target)
        _key_id, key_token = await committed.api_key(target)
        assert await committed.deactivate(target) == [session_id]
        await committed.redis.set(_liveness_key(session_id), "1", ex=60)

        await committed.reactivate(target)

        await _assert_positive_entry_within_ttl(committed.redis, session_id)
        accepted = await committed.client.get(_ME, headers=_bearer(token))
        assert accepted.status_code == 200
        assert accepted.json()["data"]["id"] == str(target.id)
        revoked_key = await committed.client.get(_ME, headers=_bearer(key_token))
        assert revoked_key.status_code == 401
        assert revoked_key.json() == _UNAUTHENTICATED

        await committed.redis.delete(_liveness_key(session_id))
        expired = await committed.client.get(_ME, headers=_bearer(token))

        assert expired.status_code == 401
        assert expired.json() == _UNAUTHENTICATED
        # The inactive row is never cached positively.
        assert await committed.redis.get(_liveness_key(session_id)) is None
        assert await committed.read(lambda db: _sessions(db, target.id)) == {
            session_id: False
        }

    async def test_write_after_purge_interleaving(
        self, committed: _Committed, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A liveness check reads the active row and is held before its
        positive write; the deactivation commits and purges; the held write
        then lands. The stale entry never authorizes while the target is
        inactive, authorizes after a reactivation within its TTL, and stops
        once it expires."""
        target = await committed.user("bob.va")
        session_id, token = await committed.login(target)
        gate = _WriteGate(key=_liveness_key(session_id))
        real_client = session_service._new_redis_client
        monkeypatch.setattr(
            session_service,
            "_new_redis_client",
            lambda: _HeldWriteRedis(real_client(), gate),
        )

        async with committed.sessions() as reader_db:
            reader = asyncio.create_task(
                session_service.is_session_active(reader_db, session_id)
            )
            try:
                await asyncio.wait_for(gate.reached.wait(), timeout=10)
                assert await committed.redis.get(_liveness_key(session_id)) is None

                invalidated = await committed.deactivate(target)
                await session_service.purge_session_cache(invalidated)

                assert invalidated == [session_id]
                assert await committed.redis.get(_liveness_key(session_id)) is None
            finally:
                gate.release.set()
                stale_observation = await asyncio.wait_for(reader, timeout=10)

        assert stale_observation is True
        await _assert_positive_entry_within_ttl(committed.redis, session_id)

        while_inactive = await committed.client.get(_ME, headers=_bearer(token))
        assert while_inactive.status_code == 401
        assert while_inactive.json() == _UNAUTHENTICATED
        await _assert_positive_entry_within_ttl(committed.redis, session_id)

        await committed.reactivate(target)
        after_reactivation = await committed.client.get(_ME, headers=_bearer(token))
        assert after_reactivation.status_code == 200
        await _assert_positive_entry_within_ttl(committed.redis, session_id)

        await committed.redis.delete(_liveness_key(session_id))
        after_expiry = await committed.client.get(_ME, headers=_bearer(token))

        assert after_expiry.status_code == 401
        assert after_expiry.json() == _UNAUTHENTICATED
        assert await committed.redis.get(_liveness_key(session_id)) is None


# ---------------------------------------------------------------------------
# J. OpenAPI surface
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestOpenAPI:
    def test_operation_documents_summary_and_responses(self) -> None:
        operation = app.openapi()["paths"]["/api/v1/admin/users/{user}/deactivate"][
            "post"
        ]

        assert operation["summary"]
        assert operation["description"]
        assert {"200", "404", "409"} <= set(operation["responses"])
        # user-management.md, Deactivate User: no application request schema.
        assert "requestBody" not in operation
