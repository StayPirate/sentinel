"""End-to-end tests for API key management endpoints
(`backend/app/api/v1/api_keys.py`).

See `docs/features/identity/api-key-management.md` (API) for the
authoritative endpoint contracts under test. Lifecycle, locking,
concurrency, and audit-atomicity coverage for `api_key_service` itself
already exists in `tests/test_services/test_api_key_service.py` — these
tests focus on the HTTP/route contract (status codes, envelopes, error
mapping, authentication/authorization, query parameter behavior) and do
not duplicate that service-level coverage.
"""

from __future__ import annotations

import hashlib
import secrets
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.api_keys import _parse_status_filter
from app.core.enums import ApiKeyStatus, Role
from app.core.exceptions import InactiveUserError
from app.models.api_key import ApiKey
from app.models.identity_audit_event import IdentityAuditEvent
from app.models.user import User
from app.models.user_role import UserRole
from app.services import api_key_service

# ---------------------------------------------------------------------------
# Shared helpers and fixtures
# ---------------------------------------------------------------------------


def _make_api_key_credential() -> tuple[str, str]:
    """Return `(plaintext_token, sha256_hex_digest)` for a synthetic key.

    Mirrors the identical helper in `tests/test_api/test_dependencies.py`.
    """
    token = "stl_ak_" + secrets.token_hex(16)
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
    return token, digest


async def _audit_events_for(
    db_session: AsyncSession, target_user_id: Any
) -> list[IdentityAuditEvent]:
    rows = await db_session.execute(
        select(IdentityAuditEvent).where(
            IdentityAuditEvent.target_user_id == target_user_id
        )
    )
    return list(rows.scalars().all())


@pytest_asyncio.fixture
async def admin_user_and_client(
    _authenticated_user_and_client: tuple[User, AsyncClient],
    user_role_factory: Callable[..., Awaitable[UserRole]],
) -> tuple[User, AsyncClient]:
    """Like `admin_client`, but also exposes the underlying admin
    `User` — needed to assert `revoked_by`/actor identity in responses
    and audit events."""
    user, client = _authenticated_user_and_client
    await user_role_factory(user_id=user.id, role=Role.ADMIN.value)
    return user, client


@pytest.fixture
def authenticated_user_and_client(
    _authenticated_user_and_client: tuple[User, AsyncClient],
) -> tuple[User, AsyncClient]:
    """Non-underscore-prefixed alias for `_authenticated_user_and_client`
    (`conftest.py`).

    ruff's `PT019` flags any leading-underscore fixture name requested
    directly by a test function, assuming it is unused by convention —
    this thin wrapper lets tests that need the authenticated `User`
    alongside its `AsyncClient` request a plain name instead.
    """
    return _authenticated_user_and_client


# ---------------------------------------------------------------------------
# `_parse_status_filter` (pure helper)
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestParseStatusFilter:
    def test_absent_is_valid_with_no_filter(self) -> None:
        assert _parse_status_filter(None) == (True, None)

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("active", ApiKeyStatus.ACTIVE),
            ("expired", ApiKeyStatus.EXPIRED),
            ("revoked", ApiKeyStatus.REVOKED),
        ],
    )
    def test_valid_value_resolves_to_typed_status(
        self, raw: str, expected: ApiKeyStatus
    ) -> None:
        assert _parse_status_filter(raw) == (True, expected)

    def test_invalid_value_is_flagged(self) -> None:
        assert _parse_status_filter("not-a-status") == (False, None)


# ---------------------------------------------------------------------------
# GET /api/v1/api-keys
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestListMyApiKeys:
    async def test_unauthenticated_returns_401(self, client: AsyncClient) -> None:
        response = await client.get("/api/v1/api-keys")
        assert response.status_code == 401

    async def test_no_keys_returns_empty_default_page(
        self, authenticated_client: AsyncClient
    ) -> None:
        response = await authenticated_client.get("/api/v1/api-keys")

        assert response.status_code == 200
        assert response.json() == {
            "data": [],
            "meta": {"total": 0, "page": 1, "per_page": 20},
        }

    async def test_returns_only_own_keys_newest_first(
        self,
        admin_user_and_client: tuple[User, AsyncClient],
        user_factory: Callable[..., Awaitable[User]],
        api_key_factory: Callable[..., Awaitable[ApiKey]],
    ) -> None:
        user, client = admin_user_and_client
        other = await user_factory()
        await api_key_factory(user_id=other.id, name="other-owner-key")
        now = datetime.now(UTC)
        # Explicit backdating: PostgreSQL's `now()` (the `created_at`
        # server_default) returns the transaction start time, so two
        # factory calls within the same test transaction would
        # otherwise get an identical timestamp — see
        # docs/features/platform/testing-strategy.md
        # (`server_default=func.now()` Testing).
        mine_older = await api_key_factory(
            user_id=user.id, name="mine-older", created_at=now - timedelta(hours=1)
        )
        mine_newer = await api_key_factory(
            user_id=user.id, name="mine-newer", created_at=now
        )

        response = await client.get("/api/v1/api-keys")

        assert response.status_code == 200
        body = response.json()
        assert body["meta"]["total"] == 2
        names = [item["name"] for item in body["data"]]
        assert names == [mine_newer.name, mine_older.name]

    async def test_response_never_exposes_secret_or_hash(
        self,
        authenticated_client: AsyncClient,
        authenticated_user_and_client: tuple[User, AsyncClient],
        api_key_factory: Callable[..., Awaitable[ApiKey]],
    ) -> None:
        user, _client = authenticated_user_and_client
        await api_key_factory(user_id=user.id)

        response = await authenticated_client.get("/api/v1/api-keys")

        assert response.status_code == 200
        item = response.json()["data"][0]
        assert "key" not in item
        assert "key_hash" not in item

    async def test_revoked_by_renders_as_user_reference(
        self,
        authenticated_user_and_client: tuple[User, AsyncClient],
        api_key_factory: Callable[..., Awaitable[ApiKey]],
    ) -> None:
        user, client = authenticated_user_and_client
        await api_key_factory(
            user_id=user.id,
            revoked_at=datetime.now(UTC),
            revoked_by=user.id,
        )

        response = await client.get("/api/v1/api-keys")

        assert response.status_code == 200
        item = response.json()["data"][0]
        assert item["status"] == "revoked"
        assert item["revoked_by"]["id"] == str(user.id)
        assert item["revoked_by"]["username"] == user.username

    async def test_non_revoked_key_has_null_revoked_by(
        self,
        authenticated_user_and_client: tuple[User, AsyncClient],
        api_key_factory: Callable[..., Awaitable[ApiKey]],
    ) -> None:
        user, client = authenticated_user_and_client
        await api_key_factory(user_id=user.id)

        response = await client.get("/api/v1/api-keys")

        assert response.json()["data"][0]["revoked_by"] is None

    @pytest.mark.parametrize(
        "status_value",
        ["active", "expired", "revoked"],
    )
    async def test_status_filter_scopes_to_exactly_one_status(
        self,
        authenticated_user_and_client: tuple[User, AsyncClient],
        api_key_factory: Callable[..., Awaitable[ApiKey]],
        status_value: str,
    ) -> None:
        user, client = authenticated_user_and_client
        now = datetime.now(UTC)
        await api_key_factory(user_id=user.id, name="active-key")
        await api_key_factory(
            user_id=user.id, name="expired-key", expires_at=now - timedelta(days=1)
        )
        await api_key_factory(
            user_id=user.id,
            name="revoked-key",
            revoked_at=now,
            revoked_by=user.id,
        )

        response = await client.get("/api/v1/api-keys", params={"status": status_value})

        assert response.status_code == 200
        body = response.json()
        assert body["meta"]["total"] == 1
        assert body["data"][0]["status"] == status_value

    async def test_invalid_status_filter_returns_empty_page(
        self,
        authenticated_user_and_client: tuple[User, AsyncClient],
        api_key_factory: Callable[..., Awaitable[ApiKey]],
    ) -> None:
        user, client = authenticated_user_and_client
        await api_key_factory(user_id=user.id)

        response = await client.get(
            "/api/v1/api-keys",
            params={"status": "not-a-real-status", "page": 1, "per_page": 10},
        )

        assert response.status_code == 200
        body = response.json()
        assert body["data"] == []
        assert body["meta"] == {"total": 0, "page": 1, "per_page": 10}

    async def test_status_filter_over_length_limit_returns_422(
        self, authenticated_client: AsyncClient
    ) -> None:
        """Exercises the app-wide `enforce_query_parameter_length_limit`
        dependency (`app/core/query_limits.py`, registered in
        `app/main.py`) through a real endpoint, not only through the
        synthetic app in `test_core/test_query_limits.py` — guards
        against the app-wide registration silently regressing."""
        response = await authenticated_client.get(
            "/api/v1/api-keys", params={"status": "a" * 501}
        )
        assert response.status_code == 422
        assert response.json()["code"] == "VALIDATION_ERROR"

    async def test_page_beyond_last_page_returns_empty_data_with_correct_total(
        self,
        authenticated_user_and_client: tuple[User, AsyncClient],
        api_key_factory: Callable[..., Awaitable[ApiKey]],
    ) -> None:
        user, client = authenticated_user_and_client
        await api_key_factory(user_id=user.id)

        response = await client.get(
            "/api/v1/api-keys", params={"page": 5, "per_page": 10}
        )

        assert response.status_code == 200
        body = response.json()
        assert body["data"] == []
        assert body["meta"] == {"total": 1, "page": 5, "per_page": 10}

    @pytest.mark.parametrize("bad_page", [0, -1])
    async def test_page_below_one_returns_422(
        self, authenticated_client: AsyncClient, bad_page: int
    ) -> None:
        response = await authenticated_client.get(
            "/api/v1/api-keys", params={"page": bad_page}
        )
        assert response.status_code == 422
        assert response.json()["code"] == "VALIDATION_ERROR"

    @pytest.mark.parametrize("bad_per_page", [0, 101])
    async def test_per_page_out_of_range_returns_422(
        self, authenticated_client: AsyncClient, bad_per_page: int
    ) -> None:
        response = await authenticated_client.get(
            "/api/v1/api-keys", params={"per_page": bad_per_page}
        )
        assert response.status_code == 422

    async def test_invalid_sort_by_returns_422(
        self, authenticated_client: AsyncClient
    ) -> None:
        response = await authenticated_client.get(
            "/api/v1/api-keys", params={"sort_by": "name"}
        )
        assert response.status_code == 422

    async def test_invalid_sort_order_returns_422(
        self, authenticated_client: AsyncClient
    ) -> None:
        response = await authenticated_client.get(
            "/api/v1/api-keys", params={"sort_order": "ascending"}
        )
        assert response.status_code == 422

    async def test_sort_order_asc_and_desc_reverse_the_result(
        self,
        authenticated_user_and_client: tuple[User, AsyncClient],
        api_key_factory: Callable[..., Awaitable[ApiKey]],
    ) -> None:
        user, client = authenticated_user_and_client
        now = datetime.now(UTC)
        first = await api_key_factory(
            user_id=user.id, name="first-created", created_at=now - timedelta(hours=1)
        )
        second = await api_key_factory(
            user_id=user.id, name="second-created", created_at=now
        )

        desc = await client.get(
            "/api/v1/api-keys", params={"sort_by": "created_at", "sort_order": "desc"}
        )
        asc = await client.get(
            "/api/v1/api-keys", params={"sort_by": "created_at", "sort_order": "asc"}
        )

        assert [item["name"] for item in desc.json()["data"]] == [
            second.name,
            first.name,
        ]
        assert [item["name"] for item in asc.json()["data"]] == [
            first.name,
            second.name,
        ]

    async def test_last_used_at_null_sorts_last_in_both_directions(
        self,
        authenticated_user_and_client: tuple[User, AsyncClient],
        api_key_factory: Callable[..., Awaitable[ApiKey]],
    ) -> None:
        user, client = authenticated_user_and_client
        never_used = await api_key_factory(user_id=user.id, last_used_at=None)
        used = await api_key_factory(
            user_id=user.id, last_used_at=datetime.now(UTC) - timedelta(hours=1)
        )

        for sort_order in ("asc", "desc"):
            response = await client.get(
                "/api/v1/api-keys",
                params={"sort_by": "last_used_at", "sort_order": sort_order},
            )
            names = [item["name"] for item in response.json()["data"]]
            assert names == [used.name, never_used.name], sort_order

    async def test_api_key_authentication_is_accepted(
        self,
        client: AsyncClient,
        user_factory: Callable[..., Awaitable[User]],
        api_key_factory: Callable[..., Awaitable[ApiKey]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        user = await user_factory()
        token, digest = _make_api_key_credential()
        await api_key_factory(user_id=user.id, key_hash=digest)
        monkeypatch.setattr(
            api_key_service, "update_last_used_at", AsyncMock(return_value=True)
        )

        response = await client.get(
            "/api/v1/api-keys", headers={"Authorization": f"Bearer {token}"}
        )

        assert response.status_code == 200
        assert response.json()["meta"]["total"] == 1


# ---------------------------------------------------------------------------
# POST /api/v1/api-keys
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestCreateApiKey:
    async def test_unauthenticated_returns_401(self, client: AsyncClient) -> None:
        response = await client.post("/api/v1/api-keys", json={"name": "ci.production"})
        assert response.status_code == 401

    async def test_api_key_authentication_returns_403_session_required(
        self,
        client: AsyncClient,
        user_factory: Callable[..., Awaitable[User]],
        api_key_factory: Callable[..., Awaitable[ApiKey]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        user = await user_factory()
        token, digest = _make_api_key_credential()
        await api_key_factory(user_id=user.id, key_hash=digest)
        monkeypatch.setattr(
            api_key_service, "update_last_used_at", AsyncMock(return_value=True)
        )

        response = await client.post(
            "/api/v1/api-keys",
            json={"name": "ci.production"},
            headers={"Authorization": f"Bearer {token}"},
        )

        assert response.status_code == 403
        assert response.json()["code"] == "AUTH_SESSION_REQUIRED"

    async def test_happy_path_returns_201_with_secret_once(
        self, authenticated_client: AsyncClient
    ) -> None:
        response = await authenticated_client.post(
            "/api/v1/api-keys",
            json={"name": "  CI.Production  ", "expires_at": "2026-12-01T10:00:00Z"},
        )

        assert response.status_code == 201
        data = response.json()["data"]
        assert data["name"] == "ci.production"
        assert data["key"].startswith("stl_ak_")
        assert data["status"] == "active"
        assert data["expires_at"] == "2026-12-01T10:00:00Z"

    async def test_expires_at_omitted_creates_a_key_that_never_expires(
        self, authenticated_client: AsyncClient
    ) -> None:
        response = await authenticated_client.post(
            "/api/v1/api-keys", json={"name": "no-expiry"}
        )

        assert response.status_code == 201
        assert response.json()["data"]["expires_at"] is None

    async def test_invalid_name_returns_422(
        self, authenticated_client: AsyncClient
    ) -> None:
        response = await authenticated_client.post(
            "/api/v1/api-keys", json={"name": "invalid name!"}
        )

        assert response.status_code == 422
        assert response.json()["code"] == "AUTH_API_KEY_NAME_INVALID"

    async def test_name_conflict_returns_409(
        self, authenticated_client: AsyncClient
    ) -> None:
        await authenticated_client.post(
            "/api/v1/api-keys", json={"name": "duplicate-name"}
        )

        response = await authenticated_client.post(
            "/api/v1/api-keys", json={"name": "duplicate-name"}
        )

        assert response.status_code == 409
        assert response.json()["code"] == "AUTH_API_KEY_NAME_CONFLICT"

    async def test_expiry_not_in_future_returns_400(
        self, authenticated_client: AsyncClient
    ) -> None:
        past = (datetime.now(UTC) - timedelta(days=1)).isoformat()
        response = await authenticated_client.post(
            "/api/v1/api-keys", json={"name": "past-expiry", "expires_at": past}
        )

        assert response.status_code == 400
        assert response.json()["code"] == "AUTH_API_KEY_INVALID_EXPIRY"

    async def test_date_only_expiry_returns_422_validation_error(
        self, authenticated_client: AsyncClient
    ) -> None:
        response = await authenticated_client.post(
            "/api/v1/api-keys", json={"name": "date-only", "expires_at": "2026-12-01"}
        )

        assert response.status_code == 422
        assert response.json()["code"] == "VALIDATION_ERROR"

    async def test_missing_name_returns_422(
        self, authenticated_client: AsyncClient
    ) -> None:
        response = await authenticated_client.post("/api/v1/api-keys", json={})
        assert response.status_code == 422

    async def test_inactive_owner_returns_409(
        self,
        authenticated_client: AsyncClient,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The genuine concurrent race (owner deactivated between
        `get_current_user`'s check and `create_key()`'s own lock) is
        covered at the service layer
        (`tests/test_services/test_api_key_service.py`). This verifies
        only the HTTP-layer mapping of `InactiveUserError` to `409
        USER_INACTIVE` — reproducing the race itself would require true
        cross-connection concurrency for a mapping that is otherwise a
        single deterministic `except` clause.
        """
        monkeypatch.setattr(
            api_key_service,
            "create_key",
            AsyncMock(side_effect=InactiveUserError()),
        )

        response = await authenticated_client.post(
            "/api/v1/api-keys", json={"name": "ci.production"}
        )

        assert response.status_code == 409
        assert response.json()["code"] == "USER_INACTIVE"

    async def test_creates_exactly_one_audit_event_with_correct_fields(
        self,
        authenticated_user_and_client: tuple[User, AsyncClient],
        db_session: AsyncSession,
    ) -> None:
        user, client = authenticated_user_and_client

        response = await client.post("/api/v1/api-keys", json={"name": "audited-key"})
        key_id = response.json()["data"]["id"]

        events = await _audit_events_for(db_session, user.id)
        assert len(events) == 1
        event = events[0]
        assert event.event_type == "api_key_created"
        assert event.user_id == user.id
        assert event.target_user_id == user.id
        assert event.new_value == "audited-key"
        assert event.detail == {"key_id": key_id}


# ---------------------------------------------------------------------------
# POST /api/v1/api-keys/{key_id}/revoke
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestRevokeMyApiKey:
    async def test_unauthenticated_returns_401(self, client: AsyncClient) -> None:
        response = await client.post(f"/api/v1/api-keys/{uuid4()}/revoke")
        assert response.status_code == 401

    async def test_happy_path_returns_200_revoked(
        self,
        authenticated_user_and_client: tuple[User, AsyncClient],
        api_key_factory: Callable[..., Awaitable[ApiKey]],
    ) -> None:
        user, client = authenticated_user_and_client
        key = await api_key_factory(user_id=user.id)

        response = await client.post(f"/api/v1/api-keys/{key.id}/revoke")

        assert response.status_code == 200
        data = response.json()["data"]
        assert data["status"] == "revoked"
        assert data["revoked_by"]["id"] == str(user.id)

    async def test_repeated_revoke_is_idempotent_and_creates_no_extra_audit_event(
        self,
        authenticated_user_and_client: tuple[User, AsyncClient],
        api_key_factory: Callable[..., Awaitable[ApiKey]],
        db_session: AsyncSession,
    ) -> None:
        user, client = authenticated_user_and_client
        key = await api_key_factory(user_id=user.id)

        first = await client.post(f"/api/v1/api-keys/{key.id}/revoke")
        second = await client.post(f"/api/v1/api-keys/{key.id}/revoke")

        assert first.status_code == 200
        assert second.status_code == 200
        assert first.json()["data"]["revoked_at"] == second.json()["data"]["revoked_at"]
        events = await _audit_events_for(db_session, user.id)
        assert len([e for e in events if e.event_type == "api_key_revoked"]) == 1

    async def test_unknown_key_returns_404(
        self, authenticated_client: AsyncClient
    ) -> None:
        response = await authenticated_client.post(f"/api/v1/api-keys/{uuid4()}/revoke")
        assert response.status_code == 404
        assert response.json()["code"] == "AUTH_API_KEY_NOT_FOUND"

    async def test_malformed_key_id_returns_422(
        self, authenticated_client: AsyncClient
    ) -> None:
        response = await authenticated_client.post("/api/v1/api-keys/not-a-uuid/revoke")
        assert response.status_code == 422

    async def test_another_users_key_returns_same_404_as_unknown_key(
        self,
        authenticated_client: AsyncClient,
        user_factory: Callable[..., Awaitable[User]],
        api_key_factory: Callable[..., Awaitable[ApiKey]],
    ) -> None:
        other = await user_factory()
        other_key = await api_key_factory(user_id=other.id)

        own_key_response = await authenticated_client.post(
            f"/api/v1/api-keys/{uuid4()}/revoke"
        )
        other_key_response = await authenticated_client.post(
            f"/api/v1/api-keys/{other_key.id}/revoke"
        )

        assert own_key_response.status_code == other_key_response.status_code == 404
        assert own_key_response.json() == other_key_response.json()

    async def test_creates_exactly_one_audit_event_with_correct_fields(
        self,
        authenticated_user_and_client: tuple[User, AsyncClient],
        api_key_factory: Callable[..., Awaitable[ApiKey]],
        db_session: AsyncSession,
    ) -> None:
        user, client = authenticated_user_and_client
        key = await api_key_factory(user_id=user.id, name="to-be-revoked")

        response = await client.post(f"/api/v1/api-keys/{key.id}/revoke")
        assert response.status_code == 200

        events = await _audit_events_for(db_session, user.id)
        revoke_events = [e for e in events if e.event_type == "api_key_revoked"]
        assert len(revoke_events) == 1
        event = revoke_events[0]
        assert event.user_id == user.id
        assert event.old_value == "to-be-revoked"
        assert event.detail == {"key_id": str(key.id)}


# ---------------------------------------------------------------------------
# GET /api/v1/admin/api-keys
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestListAllApiKeys:
    async def test_unauthenticated_returns_401(self, client: AsyncClient) -> None:
        response = await client.get("/api/v1/admin/api-keys")
        assert response.status_code == 401

    async def test_ordinary_user_returns_403(
        self, authenticated_client: AsyncClient
    ) -> None:
        response = await authenticated_client.get("/api/v1/admin/api-keys")
        assert response.status_code == 403
        assert response.json()["code"] == "AUTH_INSUFFICIENT_PERMISSION"

    async def test_admin_sees_keys_across_all_owners(
        self,
        admin_user_and_client: tuple[User, AsyncClient],
        user_factory: Callable[..., Awaitable[User]],
        api_key_factory: Callable[..., Awaitable[ApiKey]],
    ) -> None:
        admin_user, client = admin_user_and_client
        other = await user_factory()
        await api_key_factory(user_id=admin_user.id)
        await api_key_factory(user_id=other.id)

        response = await client.get("/api/v1/admin/api-keys")

        assert response.status_code == 200
        assert response.json()["meta"]["total"] == 2

    async def test_each_item_includes_owner_reference(
        self,
        admin_user_and_client: tuple[User, AsyncClient],
        api_key_factory: Callable[..., Awaitable[ApiKey]],
    ) -> None:
        admin_user, client = admin_user_and_client
        await api_key_factory(user_id=admin_user.id)

        response = await client.get("/api/v1/admin/api-keys")

        item = response.json()["data"][0]
        assert item["owner"]["id"] == str(admin_user.id)
        assert item["owner"]["username"] == admin_user.username

    async def test_owner_filter_by_uuid(
        self,
        admin_user_and_client: tuple[User, AsyncClient],
        user_factory: Callable[..., Awaitable[User]],
        api_key_factory: Callable[..., Awaitable[ApiKey]],
    ) -> None:
        admin_user, client = admin_user_and_client
        other = await user_factory()
        await api_key_factory(user_id=admin_user.id)
        target_key = await api_key_factory(user_id=other.id)

        response = await client.get(
            "/api/v1/admin/api-keys", params={"owner": str(other.id)}
        )

        assert response.status_code == 200
        body = response.json()
        assert body["meta"]["total"] == 1
        assert body["data"][0]["id"] == str(target_key.id)

    async def test_owner_filter_by_exact_username(
        self,
        admin_user_and_client: tuple[User, AsyncClient],
        user_factory: Callable[..., Awaitable[User]],
        api_key_factory: Callable[..., Awaitable[ApiKey]],
    ) -> None:
        admin_user, client = admin_user_and_client
        other = await user_factory(username="jdoe")
        await api_key_factory(user_id=admin_user.id)
        target_key = await api_key_factory(user_id=other.id)

        response = await client.get("/api/v1/admin/api-keys", params={"owner": "jdoe"})

        assert response.status_code == 200
        body = response.json()
        assert body["meta"]["total"] == 1
        assert body["data"][0]["id"] == str(target_key.id)

    async def test_owner_filter_username_is_case_sensitive(
        self,
        admin_user_and_client: tuple[User, AsyncClient],
        user_factory: Callable[..., Awaitable[User]],
        api_key_factory: Callable[..., Awaitable[ApiKey]],
    ) -> None:
        _admin_user, client = admin_user_and_client
        other = await user_factory(username="jdoe")
        await api_key_factory(user_id=other.id)

        response = await client.get("/api/v1/admin/api-keys", params={"owner": "JDOE"})

        assert response.status_code == 200
        assert response.json()["meta"] == {"total": 0, "page": 1, "per_page": 20}

    async def test_unknown_owner_returns_empty_page(
        self,
        admin_user_and_client: tuple[User, AsyncClient],
        api_key_factory: Callable[..., Awaitable[ApiKey]],
    ) -> None:
        admin_user, client = admin_user_and_client
        await api_key_factory(user_id=admin_user.id)

        response = await client.get(
            "/api/v1/admin/api-keys", params={"owner": str(uuid4())}
        )

        assert response.status_code == 200
        body = response.json()
        assert body["data"] == []
        assert body["meta"] == {"total": 0, "page": 1, "per_page": 20}

    async def test_invalid_status_filter_returns_empty_page(
        self,
        admin_user_and_client: tuple[User, AsyncClient],
        api_key_factory: Callable[..., Awaitable[ApiKey]],
    ) -> None:
        admin_user, client = admin_user_and_client
        await api_key_factory(user_id=admin_user.id)

        response = await client.get(
            "/api/v1/admin/api-keys", params={"status": "not-a-real-status"}
        )

        assert response.status_code == 200
        assert response.json()["data"] == []

    async def test_pagination_bounds_return_422(
        self, admin_user_and_client: tuple[User, AsyncClient]
    ) -> None:
        _admin_user, client = admin_user_and_client

        response = await client.get("/api/v1/admin/api-keys", params={"per_page": 101})

        assert response.status_code == 422

    @pytest.mark.parametrize(
        "status_value",
        ["active", "expired", "revoked"],
    )
    async def test_status_filter_scopes_to_exactly_one_status(
        self,
        admin_user_and_client: tuple[User, AsyncClient],
        user_factory: Callable[..., Awaitable[User]],
        api_key_factory: Callable[..., Awaitable[ApiKey]],
        status_value: str,
    ) -> None:
        """Mirrors `TestListMyApiKeys::test_status_filter_scopes_to_exactly_one_status`
        for the admin endpoint — keys belong to different owners, proving
        the filter is applied across all owners, not just the caller's own
        keys (docs/features/platform/testing-strategy.md, API Key
        Management: "pagination, status filtering, ... for self-service
        and admin lists")."""
        admin_user, client = admin_user_and_client
        other = await user_factory()
        now = datetime.now(UTC)
        await api_key_factory(user_id=admin_user.id, name="active-key")
        await api_key_factory(
            user_id=other.id, name="expired-key", expires_at=now - timedelta(days=1)
        )
        await api_key_factory(
            user_id=admin_user.id,
            name="revoked-key",
            revoked_at=now,
            revoked_by=admin_user.id,
        )

        response = await client.get(
            "/api/v1/admin/api-keys", params={"status": status_value}
        )

        assert response.status_code == 200
        body = response.json()
        assert body["meta"]["total"] == 1
        assert body["data"][0]["status"] == status_value

    async def test_page_beyond_last_page_returns_empty_data_with_correct_total(
        self,
        admin_user_and_client: tuple[User, AsyncClient],
        api_key_factory: Callable[..., Awaitable[ApiKey]],
    ) -> None:
        admin_user, client = admin_user_and_client
        await api_key_factory(user_id=admin_user.id)

        response = await client.get(
            "/api/v1/admin/api-keys", params={"page": 5, "per_page": 10}
        )

        assert response.status_code == 200
        body = response.json()
        assert body["data"] == []
        assert body["meta"] == {"total": 1, "page": 5, "per_page": 10}

    async def test_sort_order_asc_and_desc_reverse_the_result(
        self,
        admin_user_and_client: tuple[User, AsyncClient],
        user_factory: Callable[..., Awaitable[User]],
        api_key_factory: Callable[..., Awaitable[ApiKey]],
    ) -> None:
        admin_user, client = admin_user_and_client
        other = await user_factory()
        now = datetime.now(UTC)
        first = await api_key_factory(
            user_id=admin_user.id,
            name="first-created",
            created_at=now - timedelta(hours=1),
        )
        second = await api_key_factory(
            user_id=other.id, name="second-created", created_at=now
        )

        desc = await client.get(
            "/api/v1/admin/api-keys",
            params={"sort_by": "created_at", "sort_order": "desc"},
        )
        asc = await client.get(
            "/api/v1/admin/api-keys",
            params={"sort_by": "created_at", "sort_order": "asc"},
        )

        assert [item["name"] for item in desc.json()["data"]] == [
            second.name,
            first.name,
        ]
        assert [item["name"] for item in asc.json()["data"]] == [
            first.name,
            second.name,
        ]

    async def test_stable_ordering_tiebreaks_by_id_across_owners(
        self,
        admin_user_and_client: tuple[User, AsyncClient],
        user_factory: Callable[..., Awaitable[User]],
        api_key_factory: Callable[..., Awaitable[ApiKey]],
    ) -> None:
        """Two keys owned by different users with an identical
        `created_at` must still sort deterministically by `id` — proving
        the admin endpoint's ordering is stable across owners, not just
        within a single owner's keys."""
        admin_user, client = admin_user_and_client
        other = await user_factory()
        same_time = datetime.now(UTC)
        key1 = await api_key_factory(
            user_id=admin_user.id, name="k1", created_at=same_time
        )
        key2 = await api_key_factory(user_id=other.id, name="k2", created_at=same_time)
        expected_asc_ids = sorted([str(key1.id), str(key2.id)])

        response = await client.get(
            "/api/v1/admin/api-keys",
            params={"sort_by": "created_at", "sort_order": "asc"},
        )

        assert response.status_code == 200
        ids = [item["id"] for item in response.json()["data"]]
        assert ids == expected_asc_ids

    @pytest.mark.parametrize("sort_order", ["asc", "desc"])
    async def test_last_used_at_null_sorts_last_in_both_directions(
        self,
        admin_user_and_client: tuple[User, AsyncClient],
        user_factory: Callable[..., Awaitable[User]],
        api_key_factory: Callable[..., Awaitable[ApiKey]],
        sort_order: str,
    ) -> None:
        admin_user, client = admin_user_and_client
        other = await user_factory()
        never_used = await api_key_factory(
            user_id=admin_user.id, name="never-used", last_used_at=None
        )
        used = await api_key_factory(
            user_id=other.id,
            name="used",
            last_used_at=datetime.now(UTC) - timedelta(hours=1),
        )

        response = await client.get(
            "/api/v1/admin/api-keys",
            params={"sort_by": "last_used_at", "sort_order": sort_order},
        )

        assert response.status_code == 200
        names = [item["name"] for item in response.json()["data"]]
        assert names == [used.name, never_used.name]


# ---------------------------------------------------------------------------
# POST /api/v1/admin/api-keys/{key_id}/revoke
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestRevokeApiKey:
    async def test_unauthenticated_returns_401(self, client: AsyncClient) -> None:
        response = await client.post(f"/api/v1/admin/api-keys/{uuid4()}/revoke")
        assert response.status_code == 401

    async def test_ordinary_user_returns_403(
        self, authenticated_client: AsyncClient
    ) -> None:
        response = await authenticated_client.post(
            f"/api/v1/admin/api-keys/{uuid4()}/revoke"
        )
        assert response.status_code == 403

    async def test_admin_can_revoke_another_users_key(
        self,
        admin_user_and_client: tuple[User, AsyncClient],
        user_factory: Callable[..., Awaitable[User]],
        api_key_factory: Callable[..., Awaitable[ApiKey]],
    ) -> None:
        admin_user, client = admin_user_and_client
        other = await user_factory()
        key = await api_key_factory(user_id=other.id)

        response = await client.post(f"/api/v1/admin/api-keys/{key.id}/revoke")

        assert response.status_code == 200
        data = response.json()["data"]
        assert data["status"] == "revoked"
        assert data["owner"]["id"] == str(other.id)
        assert data["revoked_by"]["id"] == str(admin_user.id)

    async def test_unknown_key_returns_404(
        self, admin_user_and_client: tuple[User, AsyncClient]
    ) -> None:
        _admin_user, client = admin_user_and_client

        response = await client.post(f"/api/v1/admin/api-keys/{uuid4()}/revoke")

        assert response.status_code == 404
        assert response.json()["code"] == "AUTH_API_KEY_NOT_FOUND"

    async def test_admin_can_revoke_the_key_authenticating_this_request(
        self,
        client: AsyncClient,
        user_factory: Callable[..., Awaitable[User]],
        user_role_factory: Callable[..., Awaitable[UserRole]],
        api_key_factory: Callable[..., Awaitable[ApiKey]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        admin_user = await user_factory()
        await user_role_factory(user_id=admin_user.id, role=Role.ADMIN.value)
        token, digest = _make_api_key_credential()
        key = await api_key_factory(user_id=admin_user.id, key_hash=digest)
        monkeypatch.setattr(
            api_key_service, "update_last_used_at", AsyncMock(return_value=True)
        )
        headers = {"Authorization": f"Bearer {token}"}

        revoke_response = await client.post(
            f"/api/v1/admin/api-keys/{key.id}/revoke", headers=headers
        )
        assert revoke_response.status_code == 200

        second_request = await client.get("/api/v1/api-keys", headers=headers)
        assert second_request.status_code == 401

    async def test_creates_exactly_one_audit_event_identifying_admin_as_actor(
        self,
        admin_user_and_client: tuple[User, AsyncClient],
        user_factory: Callable[..., Awaitable[User]],
        api_key_factory: Callable[..., Awaitable[ApiKey]],
        db_session: AsyncSession,
    ) -> None:
        admin_user, client = admin_user_and_client
        other = await user_factory()
        key = await api_key_factory(user_id=other.id, name="owned-by-other")

        response = await client.post(f"/api/v1/admin/api-keys/{key.id}/revoke")
        assert response.status_code == 200

        events = await _audit_events_for(db_session, other.id)
        revoke_events = [e for e in events if e.event_type == "api_key_revoked"]
        assert len(revoke_events) == 1
        event = revoke_events[0]
        assert event.user_id == admin_user.id
        assert event.target_user_id == other.id
        assert event.old_value == "owned-by-other"
