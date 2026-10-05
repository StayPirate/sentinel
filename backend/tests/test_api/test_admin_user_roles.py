"""End-to-end tests for `POST /api/v1/admin/users/{user}/roles`
(`backend/app/api/v1/users.py`, `set_user_roles_admin`).

See `docs/features/identity/user-management.md` (Admin API endpoints, Set
User Roles) for the endpoint contract,
`docs/features/identity/rbac.md` (Role Wire Format, Deterministic ordering)
for the profile role order, and `docs/features/platform/testing-strategy.md`
(User Lifecycle and Management, Manual role mutation API) for the required
scenarios. A literal JSON `null` body is a no-op like an absent body (issue
#808, decision D1). Classification, locking, normalization, and the
concurrency matrix of `user_service.update_roles()` are covered by the
service tests (`tests/test_services/test_update_roles*.py`); these tests
cover the HTTP contract, the transaction boundary, and the audit actor.
"""

from __future__ import annotations

import hashlib
import secrets
import uuid
from collections.abc import AsyncGenerator, Awaitable, Callable
from typing import Any
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest
import pytest_asyncio
import redis.asyncio as redis_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete, select
from sqlalchemy.exc import OperationalError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import Role, SessionCreationReason, TicketStatus
from app.core.exceptions import UserNotFoundError
from app.database import get_db
from app.main import app
from app.models.api_key import ApiKey
from app.models.identity_audit_event import IdentityAuditEvent
from app.models.session import Session as SessionRow
from app.models.ticket import Ticket
from app.models.ticket_audit_event import TicketAuditEvent
from app.models.user import User
from app.models.user_role import UserRole
from app.services import api_key_service, user_service
from app.services.session_service import create_session
from app.services.user_service import RoleUpdateResult
from tests.support.ticket_api import INTERNAL_ERROR, force_production_error_page

Factory = Callable[..., Awaitable[Any]]
Origin = tuple[str, str, uuid.UUID | None]
EventRow = tuple[str, uuid.UUID | None, str | None, str | None, object]

_EXTERNAL_GROUP = "Example Security Group"
_OTHER_EXTERNAL_GROUP = "Example Analysts"
_USER_NOT_FOUND = {"code": "USER_NOT_FOUND", "detail": "User not found."}
_SELF_ROLE_REMOVAL = {
    "code": "USER_SELF_ROLE_REMOVAL",
    "detail": "Cannot remove your own final admin role.",
}
_UNAUTHENTICATED = {
    "code": "AUTH_NOT_AUTHENTICATED",
    "detail": "Authentication required",
}
_FORBIDDEN = {
    "code": "AUTH_INSUFFICIENT_PERMISSION",
    "detail": "Insufficient permissions",
}
_NUL_ERROR = {"msg": "Value error, must not contain U+0000", "type": "value_error"}


def _url(identifier: object) -> str:
    return f"/api/v1/admin/users/{identifier}/roles"


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


def _assert_nul_rejection(response_json: object, loc: list[object]) -> None:
    """Mirrors the identical helper in `tests/test_api/test_request_nul.py`."""
    assert response_json == {
        "code": "VALIDATION_ERROR",
        "detail": "Request validation failed",
        "errors": [{"loc": loc, **_NUL_ERROR}],
    }


async def _origins(db: AsyncSession, user_id: uuid.UUID) -> set[Origin]:
    """Every `UserRole` origin of the user as `(role, group_name,
    assigned_by)`, with the stored role value."""
    rows = await db.execute(
        select(UserRole.role, UserRole.group_name, UserRole.assigned_by).where(
            UserRole.user_id == user_id
        )
    )
    return {(row.role, row.group_name, row.assigned_by) for row in rows}


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


def _profile_roles(response_json: Any) -> list[tuple[str, str, str | None]]:
    """The response profile's role origins as `(role, group_name,
    assigned_by)`, in response order."""
    return [
        (entry["role"], entry["group_name"], entry["assigned_by"])
        for entry in response_json["data"]["roles"]
    ]


@pytest.fixture
def authenticated_user_and_client(
    _authenticated_user_and_client: tuple[User, AsyncClient],
) -> tuple[User, AsyncClient]:
    """Non-underscore-prefixed alias for `conftest.py`'s
    `_authenticated_user_and_client`, mirroring
    `tests/test_api/test_users.py`."""
    return _authenticated_user_and_client


@pytest_asyncio.fixture
async def admin_user_and_client(
    _authenticated_user_and_client: tuple[User, AsyncClient],
    user_role_factory: Factory,
) -> tuple[User, AsyncClient]:
    """The shared `client` authenticated as a user holding only the
    `_manual` Admin origin. Mirrors the identical fixture in
    `tests/test_api/test_users.py`."""
    user, client = _authenticated_user_and_client
    await user_role_factory(user_id=user.id, role=Role.ADMIN.value)
    return user, client


# ---------------------------------------------------------------------------
# Authentication and authorization
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestAuthenticationAndAuthorization:
    async def test_unauthenticated_returns_401(
        self, client: AsyncClient, user_factory: Factory
    ) -> None:
        target: User = await user_factory(username="rolesanontarget")

        response = await client.post(_url(target.id), json={"add": ["admin"]})

        assert response.status_code == 401
        assert response.json() == _UNAUTHENTICATED

    async def test_without_manage_users_returns_403_before_any_user_lookup(
        self,
        authenticated_client: AsyncClient,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The capability check precedes identifier resolution: a missing
        user yields the generic 403, not 404, and no lookup or mutation
        runs (docs/api-spec.md, Authorization Chain Evaluation Order)."""
        resolve = AsyncMock(side_effect=AssertionError("lookup must not run"))
        mutation = AsyncMock(side_effect=AssertionError("mutation must not run"))
        monkeypatch.setattr(user_service, "resolve_user_identifier", resolve)
        monkeypatch.setattr(user_service, "update_roles", mutation)

        responses = [
            await authenticated_client.post(_url(identifier), json={"add": ["admin"]})
            for identifier in (uuid4(), "no-such-user")
        ]

        for response in responses:
            assert response.status_code == 403
            assert response.json() == _FORBIDDEN
        resolve.assert_not_awaited()
        mutation.assert_not_awaited()

    async def test_vulnerability_analyst_returns_403_and_changes_nothing(
        self,
        authenticated_user_and_client: tuple[User, AsyncClient],
        user_factory: Factory,
        user_role_factory: Factory,
        db_session: AsyncSession,
    ) -> None:
        actor, client = authenticated_user_and_client
        await user_role_factory(user_id=actor.id, role=Role.VULNERABILITY_ANALYST.value)
        target: User = await user_factory(username="rolesvatarget")

        response = await client.post(_url(target.id), json={"add": ["admin"]})

        assert response.status_code == 403
        assert response.json() == _FORBIDDEN
        assert await _origins(db_session, target.id) == set()
        assert await _identity_events(db_session, target.id) == []

    async def test_api_key_credential_is_accepted(
        self,
        client: AsyncClient,
        user_factory: Factory,
        user_role_factory: Factory,
        api_key_factory: Callable[..., Awaitable[ApiKey]],
        db_session: AsyncSession,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """No session-only guard: an administrator's API key is accepted,
        and the key's owner is the audit actor."""
        admin: User = await user_factory(username="rolesapikeyadmin")
        await user_role_factory(user_id=admin.id, role=Role.ADMIN.value)
        token, digest = _make_api_key_credential()
        await api_key_factory(user_id=admin.id, key_hash=digest)
        monkeypatch.setattr(
            api_key_service, "update_last_used_at", AsyncMock(return_value=True)
        )
        target: User = await user_factory(username="rolesapikeytarget")

        response = await client.post(
            _url(target.id),
            json={"add": ["restricted_analyst"]},
            headers={"Authorization": f"Bearer {token}"},
        )

        assert response.status_code == 200
        assert _profile_roles(response.json()) == [
            ("restricted_analyst", "_manual", str(admin.id))
        ]
        assert await _identity_events(db_session, target.id) == [
            ("role_added", admin.id, None, "restricted_analyst", None)
        ]


# ---------------------------------------------------------------------------
# Identifier resolution
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestIdentifierResolution:
    async def test_uuid_and_username_return_the_same_result(
        self,
        admin_user_and_client: tuple[User, AsyncClient],
        user_factory: Factory,
        db_session: AsyncSession,
    ) -> None:
        admin, client = admin_user_and_client
        target: User = await user_factory(username="rolesresolvetarget")

        by_uuid = await client.post(
            _url(target.id), json={"add": ["restricted_analyst"]}
        )
        by_username = await client.post(
            _url(target.username), json={"add": ["restricted_analyst"]}
        )

        assert by_uuid.status_code == 200
        assert by_username.status_code == 200
        assert by_uuid.json() == by_username.json()
        assert by_uuid.json()["data"]["id"] == str(target.id)
        # The second request is an idempotent no-op on the same user.
        assert await _identity_events(db_session, target.id) == [
            ("role_added", admin.id, None, "restricted_analyst", None)
        ]

    @pytest.mark.parametrize("body", [{}, {"add": ["admin"]}], ids=["no-op", "add"])
    async def test_unknown_uuid_returns_404(
        self,
        admin_user_and_client: tuple[User, AsyncClient],
        body: dict[str, Any],
    ) -> None:
        _admin, client = admin_user_and_client

        response = await client.post(_url(uuid4()), json=body)

        assert response.status_code == 404
        assert response.json() == _USER_NOT_FOUND

    @pytest.mark.parametrize("body", [{}, {"add": ["admin"]}], ids=["no-op", "add"])
    async def test_unknown_username_returns_404(
        self,
        admin_user_and_client: tuple[User, AsyncClient],
        body: dict[str, Any],
    ) -> None:
        _admin, client = admin_user_and_client

        response = await client.post(_url("no-such-user"), json=body)

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
        target: User = await user_factory(username="rolesvanishedtarget")
        monkeypatch.setattr(
            user_service,
            "update_roles",
            AsyncMock(side_effect=UserNotFoundError()),
        )

        response = await client.post(_url(target.id), json={"add": ["admin"]})

        assert response.status_code == 404
        assert response.json() == _USER_NOT_FOUND


# ---------------------------------------------------------------------------
# No-op requests
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestNoOpRequests:
    @pytest.mark.parametrize(
        "request_kwargs",
        [
            pytest.param({"json": {}}, id="omitted-fields"),
            pytest.param({}, id="absent-body"),
            pytest.param(
                {
                    "content": b"null",
                    "headers": {"Content-Type": "application/json"},
                },
                id="literal-null-body",
            ),
            pytest.param({"json": {"add": [], "remove": []}}, id="empty-arrays"),
            pytest.param({"json": {"add": []}}, id="empty-add-only"),
            pytest.param({"json": {"remove": []}}, id="empty-remove-only"),
            pytest.param(
                {"json": {"add": ["vulnerability_analyst"]}}, id="already-present"
            ),
            pytest.param({"json": {"remove": ["admin"]}}, id="missing-removal"),
        ],
    )
    async def test_returns_complete_profile_without_change_or_event(
        self,
        request_kwargs: dict[str, Any],
        admin_user_and_client: tuple[User, AsyncClient],
        user_factory: Factory,
        user_role_factory: Factory,
        db_session: AsyncSession,
    ) -> None:
        _admin, client = admin_user_and_client
        target: User = await user_factory(
            username="rolesnooptarget", full_name="Dana Example"
        )
        await user_role_factory(
            user_id=target.id, role=Role.VULNERABILITY_ANALYST.value
        )
        before = await _origins(db_session, target.id)

        response = await client.post(_url(target.id), **request_kwargs)

        assert response.status_code == 200
        data = response.json()["data"]
        assert set(data) == {
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
        assert data["id"] == str(target.id)
        assert data["username"] == "rolesnooptarget"
        assert data["full_name"] == "Dana Example"
        assert _profile_roles(response.json()) == [
            ("vulnerability_analyst", "_manual", None)
        ]
        assert await _origins(db_session, target.id) == before
        assert await _identity_events(db_session, target.id) == []


# ---------------------------------------------------------------------------
# Request validation
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestRequestValidation:
    @pytest.mark.parametrize(
        "body",
        [
            pytest.param({"add": None}, id="null-add"),
            pytest.param({"remove": None}, id="null-remove"),
            pytest.param(
                {"add": None, "remove": ["vulnerability_analyst"]},
                id="null-add-with-remove",
            ),
            pytest.param({"add": ["superuser"]}, id="unknown-role"),
            pytest.param({"add": ["admin", "superuser"]}, id="unknown-with-valid"),
            pytest.param({"remove": ["superuser"]}, id="unknown-remove"),
            pytest.param({"add": ["Admin"]}, id="stored-enum-admin"),
            pytest.param({"add": ["Vulnerability Analyst"]}, id="stored-enum-va"),
            pytest.param(
                {"remove": ["Vulnerability Analyst"]}, id="stored-enum-remove"
            ),
            pytest.param({"add": ["ADMIN"]}, id="uppercase-wire"),
            pytest.param({"add": [""]}, id="empty-string"),
            pytest.param({"add": "admin"}, id="string-field"),
            pytest.param({"remove": "vulnerability_analyst"}, id="string-remove"),
            pytest.param({"add": {"role": "admin"}}, id="object-field"),
            pytest.param({"add": 1}, id="integer-field"),
            pytest.param({"add": [1]}, id="integer-element"),
            pytest.param({"add": [None]}, id="null-element"),
            pytest.param({"add": [True]}, id="boolean-element"),
            pytest.param({"add": [["admin"]]}, id="array-element"),
            pytest.param(
                {"remove": [{"role": "vulnerability_analyst"}]}, id="object-element"
            ),
            pytest.param({"add": ["admin", "admin"]}, id="duplicate-add"),
            pytest.param(
                {"remove": ["vulnerability_analyst", "vulnerability_analyst"]},
                id="duplicate-remove",
            ),
            pytest.param({"add": ["admin"], "remove": ["admin"]}, id="overlap"),
            pytest.param(
                {
                    "add": ["admin", "restricted_analyst"],
                    "remove": ["vulnerability_analyst", "restricted_analyst"],
                },
                id="partial-overlap",
            ),
            pytest.param([], id="array-body"),
            pytest.param("admin", id="string-body"),
        ],
    )
    async def test_returns_422_and_changes_nothing(
        self,
        body: Any,
        admin_user_and_client: tuple[User, AsyncClient],
        user_factory: Factory,
        user_role_factory: Factory,
        db_session: AsyncSession,
    ) -> None:
        _admin, client = admin_user_and_client
        target: User = await user_factory(username="rolesinvalidtarget")
        await user_role_factory(
            user_id=target.id, role=Role.VULNERABILITY_ANALYST.value
        )
        before = await _origins(db_session, target.id)

        response = await client.post(_url(target.id), json=body)

        assert response.status_code == 422
        payload = response.json()
        assert payload["code"] == "VALIDATION_ERROR"
        assert payload["errors"]
        assert await _origins(db_session, target.id) == before
        assert await _identity_events(db_session, target.id) == []

    async def test_validation_precedes_user_resolution(
        self,
        admin_user_and_client: tuple[User, AsyncClient],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A schema failure is the global 422 even for an unknown user;
        no lookup runs."""
        _admin, client = admin_user_and_client
        resolve = AsyncMock(side_effect=AssertionError("lookup must not run"))
        monkeypatch.setattr(user_service, "resolve_user_identifier", resolve)

        response = await client.post(_url("no-such-user"), json={"add": None})

        assert response.status_code == 422
        assert response.json()["code"] == "VALIDATION_ERROR"
        resolve.assert_not_awaited()

    async def test_nul_in_path_returns_422_without_echo(
        self, admin_user_and_client: tuple[User, AsyncClient]
    ) -> None:
        _admin, client = admin_user_and_client

        response = await client.post(
            "/api/v1/admin/users/fictional%00user/roles", json={"add": ["admin"]}
        )

        assert response.status_code == 422
        _assert_nul_rejection(response.json(), ["path", "user"])
        assert "fictional" not in response.text

    async def test_nul_in_body_element_returns_422_without_echo_or_write(
        self,
        admin_user_and_client: tuple[User, AsyncClient],
        user_factory: Factory,
        db_session: AsyncSession,
    ) -> None:
        _admin, client = admin_user_and_client
        target: User = await user_factory(username="rolesnultarget")

        response = await client.post(_url(target.id), json={"add": ["adm\u0000in"]})

        assert response.status_code == 422
        _assert_nul_rejection(response.json(), ["body", "add", 0])
        assert "adm" not in response.text
        assert await _origins(db_session, target.id) == set()
        assert await _identity_events(db_session, target.id) == []

    async def test_nul_rejection_precedes_authentication(
        self, client: AsyncClient
    ) -> None:
        response = await client.post(
            _url("fictional-user"), json={"remove": ["\u0000"]}
        )

        assert response.status_code == 422
        _assert_nul_rejection(response.json(), ["body", "remove", 0])


# ---------------------------------------------------------------------------
# Effective mutations and audit
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestEffectiveMutations:
    async def test_add_and_remove_persist_rows_and_actor_attributed_events(
        self,
        admin_user_and_client: tuple[User, AsyncClient],
        user_factory: Factory,
        user_role_factory: Factory,
        db_session: AsyncSession,
    ) -> None:
        admin, client = admin_user_and_client
        target: User = await user_factory(username="roleseffectivetarget")
        await user_role_factory(
            user_id=target.id, role=Role.VULNERABILITY_ANALYST.value
        )

        response = await client.post(
            _url(target.username),
            json={
                "add": ["restricted_analyst", "admin"],
                "remove": ["vulnerability_analyst"],
            },
        )

        assert response.status_code == 200
        assert _profile_roles(response.json()) == [
            ("admin", "_manual", str(admin.id)),
            ("restricted_analyst", "_manual", str(admin.id)),
        ]
        assert await _origins(db_session, target.id) == {
            (Role.ADMIN.value, "_manual", admin.id),
            (Role.RESTRICTED_ANALYST.value, "_manual", admin.id),
        }
        assert await _identity_events(db_session, target.id) == [
            ("role_added", admin.id, None, "admin", None),
            ("role_added", admin.id, None, "restricted_analyst", None),
            ("role_removed", admin.id, "vulnerability_analyst", None, None),
        ]

    async def test_remove_only_creates_one_role_removed_event(
        self,
        admin_user_and_client: tuple[User, AsyncClient],
        user_factory: Factory,
        user_role_factory: Factory,
        db_session: AsyncSession,
    ) -> None:
        admin, client = admin_user_and_client
        target: User = await user_factory(username="rolesremovetarget")
        await user_role_factory(user_id=target.id, role=Role.RESTRICTED_ANALYST.value)

        response = await client.post(
            _url(target.id), json={"remove": ["restricted_analyst"]}
        )

        assert response.status_code == 200
        assert response.json()["data"]["roles"] == []
        assert await _origins(db_session, target.id) == set()
        assert await _identity_events(db_session, target.id) == [
            ("role_removed", admin.id, "restricted_analyst", None, None)
        ]

    async def test_inactive_target_behaves_like_active(
        self,
        admin_user_and_client: tuple[User, AsyncClient],
        user_factory: Factory,
        user_role_factory: Factory,
        db_session: AsyncSession,
    ) -> None:
        admin, client = admin_user_and_client
        target: User = await user_factory(username="rolesinactivetarget", active=False)
        await user_role_factory(user_id=target.id, role=Role.RESTRICTED_ANALYST.value)

        response = await client.post(
            _url(target.id),
            json={"add": ["vulnerability_analyst"], "remove": ["restricted_analyst"]},
        )

        assert response.status_code == 200
        assert response.json()["data"]["active"] is False
        assert _profile_roles(response.json()) == [
            ("vulnerability_analyst", "_manual", str(admin.id))
        ]
        assert await _identity_events(db_session, target.id) == [
            ("role_added", admin.id, None, "vulnerability_analyst", None),
            ("role_removed", admin.id, "restricted_analyst", None, None),
        ]


# ---------------------------------------------------------------------------
# Self-Admin guard
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestSelfAdminGuard:
    @pytest.mark.parametrize(
        "body",
        [
            pytest.param({"remove": ["admin"]}, id="remove-only"),
            pytest.param(
                {"add": ["vulnerability_analyst"], "remove": ["admin"]},
                id="with-addition",
            ),
        ],
    )
    async def test_removing_own_final_admin_origin_returns_409(
        self,
        body: dict[str, Any],
        admin_user_and_client: tuple[User, AsyncClient],
        db_session: AsyncSession,
    ) -> None:
        admin, client = admin_user_and_client
        before = await _origins(db_session, admin.id)

        response = await client.post(_url(admin.username), json=body)

        assert response.status_code == 409
        assert response.json() == _SELF_ROLE_REMOVAL
        assert await _origins(db_session, admin.id) == before
        assert await _identity_events(db_session, admin.id) == []

    async def test_removing_own_manual_admin_with_external_origin_succeeds(
        self,
        admin_user_and_client: tuple[User, AsyncClient],
        user_role_factory: Factory,
        db_session: AsyncSession,
    ) -> None:
        admin, client = admin_user_and_client
        await user_role_factory(
            user_id=admin.id, role=Role.ADMIN.value, group_name=_EXTERNAL_GROUP
        )

        response = await client.post(_url(admin.id), json={"remove": ["admin"]})

        assert response.status_code == 200
        assert _profile_roles(response.json()) == [("admin", _EXTERNAL_GROUP, None)]
        assert await _origins(db_session, admin.id) == {
            (Role.ADMIN.value, _EXTERNAL_GROUP, None)
        }
        assert await _identity_events(db_session, admin.id) == [
            ("role_removed", admin.id, "admin", None, None)
        ]

    async def test_removing_another_users_final_admin_origin_succeeds(
        self,
        admin_user_and_client: tuple[User, AsyncClient],
        user_factory: Factory,
        user_role_factory: Factory,
        db_session: AsyncSession,
    ) -> None:
        """The guard applies only when actor and target are the same user."""
        admin, client = admin_user_and_client
        other: User = await user_factory(username="rolesotheradmin")
        await user_role_factory(user_id=other.id, role=Role.ADMIN.value)

        response = await client.post(_url(other.id), json={"remove": ["admin"]})

        assert response.status_code == 200
        assert response.json()["data"]["roles"] == []
        assert await _identity_events(db_session, other.id) == [
            ("role_removed", admin.id, "admin", None, None)
        ]


# ---------------------------------------------------------------------------
# Complete, deterministically ordered profile
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def mixed_origin_target(
    user_factory: Factory, user_role_factory: Factory
) -> User:
    """A user holding manual and external origins of several roles,
    inserted in an order unrelated to the response order."""
    target: User = await user_factory(username="rolesmixedtarget")
    for role, group_name in (
        (Role.VULNERABILITY_ANALYST, "_manual"),
        (Role.ADMIN, _EXTERNAL_GROUP),
        (Role.RESTRICTED_ANALYST, _OTHER_EXTERNAL_GROUP),
        (Role.ADMIN, "_manual"),
        (Role.VULNERABILITY_ANALYST, _EXTERNAL_GROUP),
    ):
        await user_role_factory(
            user_id=target.id, role=role.value, group_name=group_name
        )
    return target


@pytest.mark.e2e
class TestDeterministicProfile:
    async def test_no_op_returns_every_origin_in_rbac_order(
        self,
        admin_user_and_client: tuple[User, AsyncClient],
        mixed_origin_target: User,
    ) -> None:
        _admin, client = admin_user_and_client

        response = await client.post(_url(mixed_origin_target.id), json={})

        assert response.status_code == 200
        assert [
            (entry["role"], entry["group_name"])
            for entry in response.json()["data"]["roles"]
        ] == [
            ("admin", _EXTERNAL_GROUP),
            ("admin", "_manual"),
            ("restricted_analyst", _OTHER_EXTERNAL_GROUP),
            ("vulnerability_analyst", _EXTERNAL_GROUP),
            ("vulnerability_analyst", "_manual"),
        ]

    async def test_effective_change_returns_every_origin_and_keeps_external_rows(
        self,
        admin_user_and_client: tuple[User, AsyncClient],
        mixed_origin_target: User,
        db_session: AsyncSession,
    ) -> None:
        """Removing manual origins whose role an external origin also grants
        deletes only the `_manual` rows; the external rows are untouched and
        still reported."""
        admin, client = admin_user_and_client

        response = await client.post(
            _url(mixed_origin_target.id),
            json={
                "add": ["restricted_analyst"],
                "remove": ["vulnerability_analyst", "admin"],
            },
        )

        assert response.status_code == 200
        assert _profile_roles(response.json()) == [
            ("admin", _EXTERNAL_GROUP, None),
            ("restricted_analyst", _OTHER_EXTERNAL_GROUP, None),
            ("restricted_analyst", "_manual", str(admin.id)),
            ("vulnerability_analyst", _EXTERNAL_GROUP, None),
        ]
        assert await _origins(db_session, mixed_origin_target.id) == {
            (Role.ADMIN.value, _EXTERNAL_GROUP, None),
            (Role.RESTRICTED_ANALYST.value, _OTHER_EXTERNAL_GROUP, None),
            (Role.RESTRICTED_ANALYST.value, "_manual", admin.id),
            (Role.VULNERABILITY_ANALYST.value, _EXTERNAL_GROUP, None),
        }
        assert await _identity_events(db_session, mixed_origin_target.id) == [
            ("role_added", admin.id, None, "restricted_analyst", None),
            ("role_removed", admin.id, "admin", None, None),
            ("role_removed", admin.id, "vulnerability_analyst", None, None),
        ]


# ---------------------------------------------------------------------------
# Final vulnerability_analyst loss
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestFinalVulnerabilityAnalystLoss:
    async def test_unassigns_active_tickets_and_preserves_resolved(
        self,
        admin_user_and_client: tuple[User, AsyncClient],
        user_factory: Factory,
        user_role_factory: Factory,
        ticket_factory: Factory,
        db_session: AsyncSession,
    ) -> None:
        admin, client = admin_user_and_client
        analyst: User = await user_factory(username="erin.va")
        await user_role_factory(
            user_id=analyst.id, role=Role.VULNERABILITY_ANALYST.value
        )
        analysis: Ticket = await ticket_factory(
            status=TicketStatus.ANALYSIS.value, assignee_id=analyst.id
        )
        resolved: Ticket = await ticket_factory(
            status=TicketStatus.RESOLVED.value, assignee_id=analyst.id
        )

        response = await client.post(
            _url(analyst.id), json={"remove": ["vulnerability_analyst"]}
        )

        assert response.status_code == 200
        assert response.json()["data"]["roles"] == []
        tickets = {
            row.id: (row.status, row.assignee_id)
            for row in await db_session.execute(
                select(Ticket.id, Ticket.status, Ticket.assignee_id).where(
                    Ticket.id.in_([analysis.id, resolved.id])
                )
            )
        }
        assert tickets == {
            analysis.id: (TicketStatus.ANALYSIS.value, None),
            resolved.id: (TicketStatus.RESOLVED.value, analyst.id),
        }
        events = (
            await db_session.execute(
                select(TicketAuditEvent)
                .where(TicketAuditEvent.ticket_id.in_([analysis.id, resolved.id]))
                .order_by(TicketAuditEvent.id)
            )
        ).scalars()
        assert [
            (
                event.ticket_id,
                event.event_type,
                event.user_id,
                event.old_value,
                event.new_value,
                event.comment,
                event.detail,
            )
            for event in events
        ] == [
            (
                analysis.id,
                "assignment",
                None,
                "erin.va",
                None,
                "Unassigned from erin.va: vulnerability_analyst role removed",
                None,
            )
        ]
        assert await _identity_events(db_session, analyst.id) == [
            ("role_removed", admin.id, "vulnerability_analyst", None, None)
        ]


# ---------------------------------------------------------------------------
# Transaction boundary (real commits)
# ---------------------------------------------------------------------------


class _CommittedWorld:
    """Committed users for the real-commit tests, deleted explicitly by
    `cleanup()` even after a failed assertion (testing-strategy.md,
    Concurrency Testing: explicit cleanup of committed rows)."""

    def __init__(self, factory: Callable[[], Awaitable[AsyncSession]]) -> None:
        self._factory = factory
        self.user_ids: list[uuid.UUID] = []

    async def session(self) -> AsyncSession:
        return await self._factory()

    async def user(self, *, roles: tuple[Role, ...] = ()) -> User:
        db = await self.session()
        suffix = uuid.uuid4().hex[:10]
        user = User(
            username=f"frank.admin.{suffix}",
            email=f"frank.admin.{suffix}@example.com",
            full_name="Frank Example",
            password_hash="$2b$12$" + "f" * 53,
        )
        db.add(user)
        await db.flush()
        self.user_ids.append(user.id)
        for role in roles:
            db.add(UserRole(user_id=user.id, role=role.value))
        await db.commit()
        return user

    async def admin_headers(self) -> tuple[User, dict[str, str]]:
        admin = await self.user(roles=(Role.ADMIN,))
        db = await self.session()
        created = await create_session(
            db, admin, SessionCreationReason.LOCAL_LOGIN, expected_password_hash=None
        )
        assert created is not None
        await db.commit()
        return admin, {"Authorization": f"Bearer {created.token}"}

    async def cleanup(self) -> None:
        db = await self.session()
        for statement in (
            delete(IdentityAuditEvent).where(
                IdentityAuditEvent.target_user_id.in_(self.user_ids)
                | IdentityAuditEvent.user_id.in_(self.user_ids)
            ),
            delete(SessionRow).where(SessionRow.user_id.in_(self.user_ids)),
            delete(UserRole).where(UserRole.user_id.in_(self.user_ids)),
            delete(User).where(User.id.in_(self.user_ids)),
        ):
            await db.execute(statement)
        await db.commit()


@pytest_asyncio.fixture
async def committed_world(
    db_session_factory: Callable[[], Awaitable[AsyncSession]],
    redis_client: redis_asyncio.Redis,
) -> AsyncGenerator[tuple[_CommittedWorld, AsyncClient]]:
    """A client whose every request runs in its own independent session,
    committed or rolled back like production `app.database.get_db`, with
    the global 500 envelope returned instead of re-raised."""
    world = _CommittedWorld(db_session_factory)

    async def _override_get_db() -> AsyncGenerator[AsyncSession]:
        session = await world.session()
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise

    app.dependency_overrides[get_db] = _override_get_db
    try:
        async with AsyncClient(
            transport=ASGITransport(app=app, raise_app_exceptions=False),
            base_url="http://test",
        ) as committed_client:
            yield world, committed_client
    finally:
        app.dependency_overrides.pop(get_db, None)
        await world.cleanup()


@pytest.mark.e2e
class TestTransactionBoundary:
    async def test_commit_completes_once_before_the_response(
        self,
        committed_world: tuple[_CommittedWorld, AsyncClient],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        world, committed_client = committed_world
        admin, headers = await world.admin_headers()
        target = await world.user()
        original = user_service.update_roles
        observed: list[set[Origin]] = []
        commits: list[str] = []

        async def _observe(
            db: AsyncSession, *args: Any, **kwargs: Any
        ) -> RoleUpdateResult:
            result = await original(db, *args, **kwargs)
            independent = await world.session()
            observed.append(await _origins(independent, target.id))
            await independent.rollback()
            real_commit = db.commit

            async def _counting_commit() -> None:
                commits.append("commit")
                await real_commit()

            monkeypatch.setattr(db, "commit", _counting_commit)
            return result

        monkeypatch.setattr(user_service, "update_roles", _observe)

        response = await committed_client.post(
            _url(target.id), json={"add": ["restricted_analyst"]}, headers=headers
        )

        assert response.status_code == 200
        # Not visible to another transaction before the commit ...
        assert observed == [set()]
        assert commits == ["commit"]
        # ... and durable once the response has been received.
        fresh = await world.session()
        assert await _origins(fresh, target.id) == {
            (Role.RESTRICTED_ANALYST.value, "_manual", admin.id)
        }
        assert await _identity_events(fresh, target.id) == [
            ("role_added", admin.id, None, "restricted_analyst", None)
        ]

    async def test_commit_failure_returns_500_and_persists_nothing(
        self,
        committed_world: tuple[_CommittedWorld, AsyncClient],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        force_production_error_page(monkeypatch)
        world, committed_client = committed_world
        _admin, headers = await world.admin_headers()
        target = await world.user(roles=(Role.VULNERABILITY_ANALYST,))
        before = await _origins(await world.session(), target.id)
        original = user_service.update_roles
        reached: list[bool] = []

        async def _fail_commit() -> None:
            raise OperationalError("COMMIT", {}, Exception("simulated commit failure"))

        async def _arm(db: AsyncSession, *args: Any, **kwargs: Any) -> RoleUpdateResult:
            result = await original(db, *args, **kwargs)
            reached.append(bool(result.added_roles and result.removed_roles))
            monkeypatch.setattr(db, "commit", _fail_commit)
            return result

        monkeypatch.setattr(user_service, "update_roles", _arm)

        response = await committed_client.post(
            _url(target.id),
            json={"add": ["admin"], "remove": ["vulnerability_analyst"]},
            headers=headers,
        )

        assert response.status_code == 500
        assert response.json() == INTERNAL_ERROR
        # The mutation was flushed before the failed commit; none survives.
        assert reached == [True]
        fresh = await world.session()
        assert await _origins(fresh, target.id) == before
        assert await _identity_events(fresh, target.id) == []


# ---------------------------------------------------------------------------
# OpenAPI surface
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestOpenAPI:
    def test_operation_documents_summary_and_responses(self) -> None:
        operation = app.openapi()["paths"]["/api/v1/admin/users/{user}/roles"]["post"]

        assert operation["summary"]
        assert operation["description"]
        assert {"200", "404", "409", "422"} <= set(operation["responses"])
        # An absent body is a valid no-op, so the body is optional.
        assert operation["requestBody"].get("required", False) is False
