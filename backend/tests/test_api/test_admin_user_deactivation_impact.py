"""End-to-end tests for `GET /api/v1/admin/users/{user}/deactivation-impact`
(`backend/app/api/v1/users.py`, `get_deactivation_impact_admin`).

Owning specifications:

- docs/features/identity/user-management.md (Admin API endpoints preamble,
  Get Deactivation Impact, Deactivate User guard ordering).
- docs/features/identity/user-service.md (`get_deactivation_impact()`).
- docs/features/identity/rbac.md (Endpoint Permission Map, Business Rules
  3-4).
- docs/api-spec.md (Authorization Chain Evaluation Order, NUL Characters in
  Request Input, Response Format, Global Responses, User Identifier
  Resolution).
- docs/features/platform/testing-strategy.md (User Lifecycle and
  Management, "Deactivation API"; Ticket Accessibility, no grant or
  maintainership count in the impact API; API Key Management, no direct
  `ApiKey` query; Mandatory Test Scenarios, API Endpoints and User
  Identifier Resolution).

Guard classification, the observation predicates, and the advisory
semantics of `get_deactivation_impact()` are proven by
`tests/test_services/test_deactivation_impact.py`; these tests cover the
HTTP contract. Two precedence rows have no API path and are left to the
service tests: an inactive self-target (an inactive administrator cannot
authenticate) and an active external self-target (the authenticated caller
is a local user).

Expected values are transcribed from the specifications; nothing here
computes an expectation with the module under test.
"""

from __future__ import annotations

import hashlib
import secrets
from collections.abc import Awaitable, Callable
from contextlib import ExitStack
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import Role, TicketStatus
from app.core.exceptions import UserNotFoundError
from app.main import app
from app.models.user import User
from app.services import api_key_service, user_service
from app.services.user_service import DeactivationImpact
from tests.support.ticket_mutations import StatementRecorder

Factory = Callable[..., Awaitable[Any]]

_PATH = "/api/v1/admin/users/{user}/deactivation-impact"
_USER_NOT_FOUND = {"code": "USER_NOT_FOUND", "detail": "User not found."}
# user-management.md, Get Deactivation Impact error table and rendered details.
_EXTERNAL_READONLY = {
    "code": "USER_EXTERNAL_STATUS_READONLY",
    "detail": "Cannot deactivate external users.",
}
_SELF_PREVIEW = {
    "code": "USER_SELF_DEACTIVATION",
    "detail": "Cannot preview deactivation impact for your own account.",
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
# user-management.md, Get Deactivation Impact: the zero-impact response.
_ZEROED = {
    "data": {
        "already_inactive": True,
        "is_last_active_admin": False,
        "api_keys_count": 0,
        "sessions_count": 0,
        "tickets_count": 0,
    }
}
# The `eligible_target` fixture: three non-revoked keys (one expired), two
# active Sessions, and one active-status assigned Ticket. The target holds
# Admin, but the authenticated administrator is another active Admin.
_ELIGIBLE = {
    "data": {
        "already_inactive": False,
        "is_last_active_admin": False,
        "api_keys_count": 3,
        "sessions_count": 2,
        "tickets_count": 1,
    }
}
_FIELD_TYPES = {
    "already_inactive": bool,
    "is_last_active_admin": bool,
    "api_keys_count": int,
    "sessions_count": int,
    "tickets_count": int,
}


def _url(identifier: object) -> str:
    return _PATH.format(user=identifier)


def _make_api_key_credential() -> tuple[str, str]:
    """Return `(plaintext_token, sha256_hex_digest)` for a synthetic key.

    Mirrors the identical helper in `tests/test_api/test_users.py`.
    """
    token = "stl_ak_" + secrets.token_hex(16)
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
    return token, digest


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
    `tests/test_api/test_admin_user_deactivate.py`."""
    user, client = _authenticated_user_and_client
    await user_role_factory(user_id=user.id, role=Role.ADMIN.value)
    return user, client


@pytest_asyncio.fixture
async def eligible_target(
    user_factory: Factory,
    user_role_factory: Factory,
    api_key_factory: Factory,
    session_factory: Factory,
    ticket_factory: Factory,
    ticket_access_grant_factory: Factory,
    ticket_package_maintainer_factory: Factory,
) -> User:
    """An active local Admin with the resources counted in `_ELIGIBLE`,
    out-of-scope resources of each counted kind, and an explicit Ticket
    grant and a package-maintainer row, which deactivation retains."""
    target: User = await user_factory(username="bob.va")
    await user_role_factory(user_id=target.id, role=Role.ADMIN.value)
    now = datetime.now(UTC)
    await api_key_factory(user_id=target.id)
    await api_key_factory(user_id=target.id)
    await api_key_factory(user_id=target.id, expires_at=now - timedelta(days=1))
    await api_key_factory(
        user_id=target.id, revoked_at=now - timedelta(days=2), revoked_by=target.id
    )
    await session_factory(user_id=target.id)
    await session_factory(user_id=target.id)
    await session_factory(user_id=target.id, is_active=False)
    await ticket_factory(status=TicketStatus.ANALYSIS.value, assignee_id=target.id)
    await ticket_factory(status=TicketStatus.RESOLVED.value, assignee_id=target.id)
    await ticket_access_grant_factory(user_id=target.id)
    await ticket_package_maintainer_factory(user_id=target.id)
    return target


# ---------------------------------------------------------------------------
# A. Authentication and authorization
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestAuthenticationAndAuthorization:
    async def test_unauthenticated_returns_401_before_any_lookup(
        self,
        client: AsyncClient,
        user_factory: Factory,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        target: User = await user_factory(username="bob.va")
        resolve = AsyncMock(side_effect=AssertionError("lookup must not run"))
        monkeypatch.setattr(user_service, "resolve_user_identifier", resolve)

        response = await client.get(_url(target.id))

        assert response.status_code == 401
        assert response.json() == _UNAUTHENTICATED
        resolve.assert_not_awaited()

    async def test_without_manage_users_returns_403_before_any_user_lookup(
        self,
        authenticated_client: AsyncClient,
        user_factory: Factory,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The capability check precedes identifier resolution: an existing
        or missing user yields the generic 403, and neither the lookup nor
        the preview runs (api-spec.md, Authorization Chain Evaluation
        Order)."""
        target: User = await user_factory(username="bob.va")
        resolve = AsyncMock(side_effect=AssertionError("lookup must not run"))
        preview = AsyncMock(side_effect=AssertionError("preview must not run"))
        monkeypatch.setattr(user_service, "resolve_user_identifier", resolve)
        monkeypatch.setattr(user_service, "get_deactivation_impact", preview)

        responses = [
            await authenticated_client.get(_url(identifier))
            for identifier in (target.id, uuid4(), "no-such-user")
        ]

        for response in responses:
            assert response.status_code == 403
            assert response.json() == _FORBIDDEN
        resolve.assert_not_awaited()
        preview.assert_not_awaited()

    async def test_admin_api_key_is_accepted(
        self,
        client: AsyncClient,
        user_factory: Factory,
        user_role_factory: Factory,
        api_key_factory: Factory,
        eligible_target: User,
        no_last_used_write: None,
    ) -> None:
        """The preview is not session-only (rbac.md, Endpoint Permission
        Map): an administrator's API key is accepted."""
        admin: User = await user_factory(username="alice.admin")
        await user_role_factory(user_id=admin.id, role=Role.ADMIN.value)
        token, digest = _make_api_key_credential()
        await api_key_factory(user_id=admin.id, key_hash=digest)

        response = await client.get(
            _url(eligible_target.id), headers={"Authorization": f"Bearer {token}"}
        )

        assert response.status_code == 200
        assert response.json() == _ELIGIBLE


# ---------------------------------------------------------------------------
# B. Identifier resolution
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestIdentifierResolution:
    async def test_uuid_and_username_return_the_same_body(
        self,
        admin_user_and_client: tuple[User, AsyncClient],
        eligible_target: User,
    ) -> None:
        """Also proves that an administrator's JWT session credential is
        accepted."""
        _admin, client = admin_user_and_client

        by_uuid = await client.get(_url(eligible_target.id))
        by_username = await client.get(_url("bob.va"))

        assert by_uuid.status_code == 200
        assert by_username.status_code == 200
        assert by_uuid.json() == _ELIGIBLE
        assert by_username.json() == _ELIGIBLE

    @pytest.mark.parametrize("identifier", [uuid4(), "no-such-user"])
    async def test_unknown_identifier_returns_the_shared_404(
        self,
        identifier: object,
        admin_user_and_client: tuple[User, AsyncClient],
    ) -> None:
        """The same body as every other unresolved user identifier
        (api-spec.md, User Identifier Resolution)."""
        _admin, client = admin_user_and_client

        response = await client.get(_url(identifier))
        profile = await client.get(f"/api/v1/users/{identifier}")

        assert response.status_code == 404
        assert response.json() == _USER_NOT_FOUND
        assert profile.status_code == 404
        assert response.json() == profile.json()

    async def test_user_missing_at_the_preview_returns_404(
        self,
        admin_user_and_client: tuple[User, AsyncClient],
        user_factory: Factory,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Maps the service's own `UserNotFoundError` (a user removed
        between resolution and the preview read) to the same 404. Users are
        never deleted; this proves only the mapping."""
        _admin, client = admin_user_and_client
        target: User = await user_factory(username="bob.va")
        monkeypatch.setattr(
            user_service,
            "get_deactivation_impact",
            AsyncMock(side_effect=UserNotFoundError()),
        )

        response = await client.get(_url(target.id))

        assert response.status_code == 404
        assert response.json() == _USER_NOT_FOUND


# ---------------------------------------------------------------------------
# C. Guards and their exact bodies
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestGuards:
    async def test_active_external_target_returns_409(
        self,
        admin_user_and_client: tuple[User, AsyncClient],
        user_factory: Factory,
        api_key_factory: Factory,
        session_factory: Factory,
    ) -> None:
        _admin, client = admin_user_and_client
        target: User = await user_factory(
            username="erin.external", external_id=uuid4(), password_hash=None
        )
        await api_key_factory(user_id=target.id)
        await session_factory(user_id=target.id)

        response = await client.get(_url(target.id))

        assert response.status_code == 409
        assert response.json() == _EXTERNAL_READONLY

    @pytest.mark.parametrize("form", ["uuid", "username"])
    async def test_self_target_returns_409(
        self,
        form: str,
        admin_user_and_client: tuple[User, AsyncClient],
    ) -> None:
        admin, client = admin_user_and_client
        identifier = admin.id if form == "uuid" else admin.username

        response = await client.get(_url(identifier))

        assert response.status_code == 409
        assert response.json() == _SELF_PREVIEW


# ---------------------------------------------------------------------------
# D. Already-inactive target
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestAlreadyInactiveTarget:
    @pytest.mark.parametrize("external", [False, True], ids=["local", "external"])
    async def test_returns_the_zeroed_body(
        self,
        external: bool,
        admin_user_and_client: tuple[User, AsyncClient],
        user_factory: Factory,
        api_key_factory: Factory,
        session_factory: Factory,
        ticket_factory: Factory,
    ) -> None:
        """user-management.md, Get Deactivation Impact step 5. For the
        external target this is also the precedence row: the inactive no-op
        precedes the active external rejection. Leftover resources of each
        counted kind prove the zeroed values are not observations."""
        _admin, client = admin_user_and_client
        identity: dict[str, Any] = (
            {"external_id": uuid4(), "password_hash": None} if external else {}
        )
        target: User = await user_factory(username="bob.va", active=False, **identity)
        await api_key_factory(user_id=target.id)
        await session_factory(user_id=target.id)
        await ticket_factory(status=TicketStatus.NEW.value, assignee_id=target.id)

        response = await client.get(_url(target.id))

        assert response.status_code == 200
        assert response.json() == _ZEROED


# ---------------------------------------------------------------------------
# E. Active eligible target: the five documented fields
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestActiveEligibleTarget:
    async def test_returns_exactly_the_five_documented_fields(
        self,
        admin_user_and_client: tuple[User, AsyncClient],
        eligible_target: User,
    ) -> None:
        """The target holds Admin, a Ticket grant, and a package-maintainer
        row; the body carries no grant or maintainership count
        (testing-strategy.md, Confidentiality and explicit access grants),
        and `is_last_active_admin` is false because the authenticated
        administrator is another active Admin. The true value is
        unreachable with real data through this endpoint for that reason;
        its serialization is proven by `TestHandlerDelegation`."""
        _admin, client = admin_user_and_client

        response = await client.get(_url(eligible_target.id))

        assert response.status_code == 200
        body = response.json()
        assert body == _ELIGIBLE
        assert set(body) == {"data"}
        # `True == 1`: equality alone does not distinguish bool from int.
        assert {key: type(value) for key, value in body["data"].items()} == (
            _FIELD_TYPES
        )
        for forbidden in ("grant", "maintain"):
            assert forbidden not in response.text


# ---------------------------------------------------------------------------
# F. Request input: U+0000
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestRequestValidation:
    async def test_nul_in_path_returns_422_without_echo_or_lookup(
        self,
        admin_user_and_client: tuple[User, AsyncClient],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        _admin, client = admin_user_and_client
        resolve = AsyncMock(side_effect=AssertionError("lookup must not run"))
        preview = AsyncMock(side_effect=AssertionError("preview must not run"))
        monkeypatch.setattr(user_service, "resolve_user_identifier", resolve)
        monkeypatch.setattr(user_service, "get_deactivation_impact", preview)

        response = await client.get(_url("fictional%00user"))

        assert response.status_code == 422
        assert response.json() == {
            "code": "VALIDATION_ERROR",
            "detail": "Request validation failed",
            "errors": [{"loc": ["path", "user"], **_NUL_ERROR}],
        }
        assert "fictional" not in response.text
        resolve.assert_not_awaited()
        preview.assert_not_awaited()


# ---------------------------------------------------------------------------
# G. The handler delegates to the service and runs no query itself
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestHandlerDelegation:
    async def test_actor_and_target_reach_the_service_without_route_sql(
        self,
        admin_user_and_client: tuple[User, AsyncClient],
        db_session: AsyncSession,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """user-management.md, Get Deactivation Impact steps 2-3;
        testing-strategy.md, API Key Management: the route delegates
        resolution and the preview to `user_service` and runs no query of
        its own (in particular none on `ApiKey`, `Session`, `Ticket`, or
        `UserRole`). Recording starts at the handler's first step, so the
        authentication queries are excluded and every remaining statement
        would be the route's own. The stubbed result has
        `is_last_active_admin = true` and distinct counts, so the body also
        proves each field is serialized from its own service field."""
        admin, client = admin_user_and_client
        resolved = SimpleNamespace(id=uuid4())
        recorder = StatementRecorder(db_session)

        with ExitStack() as stack:

            async def _resolve(db: AsyncSession, identifier: str) -> SimpleNamespace:
                stack.enter_context(recorder)
                return resolved

            resolve = AsyncMock(side_effect=_resolve)
            preview = AsyncMock(
                return_value=DeactivationImpact(
                    already_inactive=False,
                    is_last_active_admin=True,
                    api_keys_count=7,
                    sessions_count=5,
                    tickets_count=3,
                )
            )
            monkeypatch.setattr(user_service, "resolve_user_identifier", resolve)
            monkeypatch.setattr(user_service, "get_deactivation_impact", preview)

            response = await client.get(_url("bob.va"))

        assert response.status_code == 200
        assert response.json() == {
            "data": {
                "already_inactive": False,
                "is_last_active_admin": True,
                "api_keys_count": 7,
                "sessions_count": 5,
                "tickets_count": 3,
            }
        }
        resolve.assert_awaited_once_with(db_session, "bob.va")
        preview.assert_awaited_once_with(
            db_session, resolved.id, acting_user_id=admin.id
        )
        assert recorder.statements == []


# ---------------------------------------------------------------------------
# H. OpenAPI surface
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestOpenAPI:
    def test_operation_documents_summary_and_responses(self) -> None:
        schema = app.openapi()
        path_item = schema["paths"][_PATH]
        assert set(path_item) == {"get"}
        operation = path_item["get"]

        assert operation["summary"]
        assert operation["description"]
        assert {"200", "404", "409"} <= set(operation["responses"])
        responses = operation["responses"]
        assert responses["200"]["content"]["application/json"]["schema"] == {
            "$ref": "#/components/schemas/DeactivationImpactResponse"
        }
        for status in ("404", "409"):
            assert responses[status]["content"]["application/json"]["schema"] == {
                "$ref": "#/components/schemas/ErrorResponse"
            }
        # No request schema, and only the `{user}` path parameter.
        assert "requestBody" not in operation
        assert [(p["name"], p["in"]) for p in operation["parameters"]] == [
            ("user", "path")
        ]
        components = schema["components"]["schemas"]
        envelope = components["DeactivationImpactResponse"]
        assert set(envelope["properties"]) == {"data"}
        data = components["DeactivationImpactData"]
        assert {name: prop["type"] for name, prop in data["properties"].items()} == {
            "already_inactive": "boolean",
            "is_last_active_admin": "boolean",
            "api_keys_count": "integer",
            "sessions_count": "integer",
            "tickets_count": "integer",
        }
        assert set(data["required"]) == set(data["properties"])
