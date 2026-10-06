"""End-to-end tests for system settings read and audit log endpoints
(`backend/app/api/v1/settings.py`).

See `docs/features/platform/system-settings.md` (Get System Settings,
List Settings Audit Events) for the authoritative endpoint contracts
under test. Filter/date/ordering combination coverage for the
underlying query lives in `tests/test_services/test_settings.py` —
these tests focus on the HTTP/route contract (status codes, envelopes,
error mapping, authentication/authorization). The OpenAPI surface below
also covers the default-CVSS impact preview route, whose HTTP contract is
tested in `tests/test_api/test_settings_impact_preview.py`.
"""

from __future__ import annotations

import hashlib
import secrets
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from unittest.mock import AsyncMock

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.api import dependencies
from app.api.v1.settings import _parse_event_types
from app.core.enums import Role, SettingAuditEventType
from app.main import app
from app.models.api_key import ApiKey
from app.models.setting_audit_event import SettingAuditEvent
from app.models.system_setting import SystemSetting
from app.models.user import User
from app.models.user_role import UserRole
from app.services.settings import (
    RequiredSystemSettingMissingError,
    bootstrap_system_settings,
)


def _make_api_key_credential() -> tuple[str, str]:
    """Return `(plaintext_token, sha256_hex_digest)` for a synthetic key.

    Mirrors the identical helper in `tests/test_api/test_api_keys.py`.
    """
    token = "stl_ak_" + secrets.token_hex(16)
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
    return token, digest


@pytest_asyncio.fixture
async def admin_api_key_client(
    client: AsyncClient,
    user_factory: Callable[..., Awaitable[User]],
    user_role_factory: Callable[..., Awaitable[UserRole]],
    api_key_factory: Callable[..., Awaitable[ApiKey]],
    monkeypatch: pytest.MonkeyPatch,
) -> AsyncClient:
    """The shared `client`, authenticated as an admin via an API key
    (`Authorization: Bearer`) instead of a JWT session cookie."""
    user = await user_factory()
    await user_role_factory(user_id=user.id, role=Role.ADMIN.value)
    token, digest = _make_api_key_credential()
    await api_key_factory(user_id=user.id, key_hash=digest)
    monkeypatch.setattr(dependencies._last_used_debouncer, "touch", AsyncMock())
    client.headers["Authorization"] = f"Bearer {token}"
    return client


# ---------------------------------------------------------------------------
# Pure helpers (`app.api.v1.settings`)
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestParseEventTypes:
    def test_absent_is_valid_with_no_filter(self) -> None:
        assert _parse_event_types([]) == (True, [])

    def test_valid_value_is_kept(self) -> None:
        is_valid, event_types = _parse_event_types(["setting_changed"])
        assert is_valid is True
        assert event_types == [SettingAuditEventType.SETTING_CHANGED]

    def test_mixed_valid_and_invalid_keeps_only_valid(self) -> None:
        is_valid, event_types = _parse_event_types(
            ["setting_changed", "not-a-real-type"]
        )
        assert is_valid is True
        assert len(event_types) == 1

    def test_all_invalid_is_rejected(self) -> None:
        assert _parse_event_types(["not-a-real-type"]) == (False, [])


# ---------------------------------------------------------------------------
# GET /api/v1/admin/settings
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestGetSystemSettings:
    async def test_unauthenticated_returns_401(self, client: AsyncClient) -> None:
        response = await client.get("/api/v1/admin/settings")
        assert response.status_code == 401
        assert response.json()["code"] == "AUTH_NOT_AUTHENTICATED"

    async def test_ordinary_user_returns_403(
        self, authenticated_client: AsyncClient
    ) -> None:
        response = await authenticated_client.get("/api/v1/admin/settings")
        assert response.status_code == 403
        assert response.json()["code"] == "AUTH_INSUFFICIENT_PERMISSION"

    async def test_admin_jwt_returns_the_setting(
        self,
        admin_client: AsyncClient,
        db_session: AsyncSession,
    ) -> None:
        await bootstrap_system_settings(db_session)

        response = await admin_client.get("/api/v1/admin/settings")

        assert response.status_code == 200
        assert response.json() == {"data": {"default_cvss_version": "3.1"}}

    async def test_admin_api_key_returns_the_setting(
        self,
        admin_api_key_client: AsyncClient,
        db_session: AsyncSession,
    ) -> None:
        await bootstrap_system_settings(db_session)

        response = await admin_api_key_client.get("/api/v1/admin/settings")

        assert response.status_code == 200
        assert response.json() == {"data": {"default_cvss_version": "3.1"}}

    async def test_custom_value_is_returned(
        self,
        admin_client: AsyncClient,
        db_session: AsyncSession,
    ) -> None:
        await bootstrap_system_settings(db_session)
        setting = await db_session.get(SystemSetting, "default_cvss_version")
        assert setting is not None
        setting.value = "4.0"
        await db_session.flush()

        response = await admin_client.get("/api/v1/admin/settings")

        assert response.json()["data"]["default_cvss_version"] == "4.0"

    async def test_missing_required_setting_propagates_without_fallback(
        self, admin_client: AsyncClient
    ) -> None:
        """No `default_cvss_version` row exists in the test schema
        unless a test seeds it. The route does not catch
        `RequiredSystemSettingMissingError` (`system-settings.md`,
        Service Exceptions) — it propagates through the ASGI transport
        here, and maps to the standard `500 INTERNAL_ERROR` envelope in
        production, verified generically (for any unhandled exception)
        in `tests/test_main.py`."""
        with pytest.raises(RequiredSystemSettingMissingError):
            await admin_client.get("/api/v1/admin/settings")

    async def test_no_patch_endpoint_is_exposed(
        self, admin_client: AsyncClient
    ) -> None:
        """PATCH /api/v1/admin/settings is out of scope for this work
        item (system-settings.md, Update System Settings — tracked
        separately)."""
        response = await admin_client.patch(
            "/api/v1/admin/settings", json={"default_cvss_version": "4.0"}
        )
        assert response.status_code == 405

    async def test_no_recalculate_endpoint_is_exposed(
        self, admin_client: AsyncClient
    ) -> None:
        response = await admin_client.post(
            "/api/v1/admin/settings/default-cvss-version/recalculate"
        )
        assert response.status_code == 404


# ---------------------------------------------------------------------------
# GET /api/v1/admin/settings/audit-log
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestListSettingAuditEvents:
    async def test_unauthenticated_returns_401(self, client: AsyncClient) -> None:
        response = await client.get("/api/v1/admin/settings/audit-log")
        assert response.status_code == 401
        assert response.json()["code"] == "AUTH_NOT_AUTHENTICATED"

    async def test_ordinary_user_returns_403(
        self, authenticated_client: AsyncClient
    ) -> None:
        response = await authenticated_client.get("/api/v1/admin/settings/audit-log")
        assert response.status_code == 403
        assert response.json()["code"] == "AUTH_INSUFFICIENT_PERMISSION"

    async def test_admin_jwt_can_list(self, admin_client: AsyncClient) -> None:
        response = await admin_client.get("/api/v1/admin/settings/audit-log")
        assert response.status_code == 200

    async def test_admin_api_key_can_list(
        self, admin_api_key_client: AsyncClient
    ) -> None:
        response = await admin_api_key_client.get("/api/v1/admin/settings/audit-log")
        assert response.status_code == 200

    async def test_empty_result_has_correct_envelope(
        self, admin_client: AsyncClient
    ) -> None:
        response = await admin_client.get("/api/v1/admin/settings/audit-log")

        assert response.json() == {
            "data": [],
            "meta": {"total": 0, "page": 1, "per_page": 20},
        }

    async def test_exact_item_shape(
        self,
        admin_client: AsyncClient,
        setting_audit_event_factory: Callable[..., Awaitable[SettingAuditEvent]],
    ) -> None:
        await setting_audit_event_factory()

        response = await admin_client.get("/api/v1/admin/settings/audit-log")

        item = response.json()["data"][0]
        assert set(item.keys()) == {
            "id",
            "event_type",
            "setting_key",
            "old_value",
            "new_value",
            "created_at",
            "actor",
        }
        assert set(item["actor"].keys()) == {"id", "username", "full_name", "active"}

    async def test_created_at_serializes_with_utc_z_suffix(
        self,
        admin_client: AsyncClient,
        setting_audit_event_factory: Callable[..., Awaitable[SettingAuditEvent]],
    ) -> None:
        await setting_audit_event_factory(
            created_at=datetime(2026, 5, 13, 14, 0, 0, tzinfo=UTC)
        )

        response = await admin_client.get("/api/v1/admin/settings/audit-log")

        assert response.json()["data"][0]["created_at"] == "2026-05-13T14:00:00Z"

    async def test_actor_is_never_null(
        self,
        admin_client: AsyncClient,
        setting_audit_event_factory: Callable[..., Awaitable[SettingAuditEvent]],
    ) -> None:
        await setting_audit_event_factory()

        response = await admin_client.get("/api/v1/admin/settings/audit-log")

        assert response.json()["data"][0]["actor"] is not None

    async def test_setting_key_filter(
        self,
        admin_client: AsyncClient,
        system_setting_factory: Callable[..., Awaitable[SystemSetting]],
        setting_audit_event_factory: Callable[..., Awaitable[SettingAuditEvent]],
    ) -> None:
        setting_a = await system_setting_factory()
        setting_b = await system_setting_factory()
        await setting_audit_event_factory(setting_key=setting_a.key)
        await setting_audit_event_factory(setting_key=setting_b.key)

        response = await admin_client.get(
            "/api/v1/admin/settings/audit-log",
            params={"setting_key": setting_a.key},
        )

        assert response.json()["meta"]["total"] == 1
        assert response.json()["data"][0]["setting_key"] == setting_a.key

    async def test_unknown_setting_key_returns_empty_result(
        self,
        admin_client: AsyncClient,
        setting_audit_event_factory: Callable[..., Awaitable[SettingAuditEvent]],
    ) -> None:
        await setting_audit_event_factory()

        response = await admin_client.get(
            "/api/v1/admin/settings/audit-log",
            params={"setting_key": "no-such-setting"},
        )

        assert response.status_code == 200
        assert response.json()["meta"]["total"] == 0

    async def test_actor_filter_by_uuid(
        self,
        admin_client: AsyncClient,
        user_factory: Callable[..., Awaitable[User]],
        setting_audit_event_factory: Callable[..., Awaitable[SettingAuditEvent]],
    ) -> None:
        actor = await user_factory()
        await setting_audit_event_factory(user_id=actor.id)

        response = await admin_client.get(
            "/api/v1/admin/settings/audit-log", params={"actor": str(actor.id)}
        )

        assert response.json()["meta"]["total"] == 1

    async def test_actor_filter_by_username(
        self,
        admin_client: AsyncClient,
        user_factory: Callable[..., Awaitable[User]],
        setting_audit_event_factory: Callable[..., Awaitable[SettingAuditEvent]],
    ) -> None:
        actor = await user_factory(username="filterbyusernamesettingapi")
        await setting_audit_event_factory(user_id=actor.id)

        response = await admin_client.get(
            "/api/v1/admin/settings/audit-log",
            params={"actor": "filterbyusernamesettingapi"},
        )

        assert response.json()["meta"]["total"] == 1

    async def test_unknown_actor_returns_empty_result_not_404(
        self, admin_client: AsyncClient
    ) -> None:
        response = await admin_client.get(
            "/api/v1/admin/settings/audit-log", params={"actor": "no-such-actor"}
        )
        assert response.status_code == 200
        assert response.json()["meta"]["total"] == 0

    async def test_system_actor_returns_empty_result(
        self,
        admin_client: AsyncClient,
        setting_audit_event_factory: Callable[..., Awaitable[SettingAuditEvent]],
    ) -> None:
        """Every setting audit event has a human actor — `system` never
        matches (system-settings.md, List Settings Audit Events)."""
        await setting_audit_event_factory()

        response = await admin_client.get(
            "/api/v1/admin/settings/audit-log", params={"actor": "system"}
        )

        assert response.status_code == 200
        assert response.json()["meta"]["total"] == 0

    async def test_event_type_filter(
        self,
        admin_client: AsyncClient,
        setting_audit_event_factory: Callable[..., Awaitable[SettingAuditEvent]],
    ) -> None:
        await setting_audit_event_factory(event_type="setting_changed")

        response = await admin_client.get(
            "/api/v1/admin/settings/audit-log",
            params=[("event_type", "setting_changed")],
        )

        assert response.json()["meta"]["total"] == 1

    async def test_mixed_valid_and_invalid_event_type_keeps_valid(
        self,
        admin_client: AsyncClient,
        setting_audit_event_factory: Callable[..., Awaitable[SettingAuditEvent]],
    ) -> None:
        await setting_audit_event_factory(event_type="setting_changed")

        response = await admin_client.get(
            "/api/v1/admin/settings/audit-log",
            params=[
                ("event_type", "setting_changed"),
                ("event_type", "not-a-real-type"),
            ],
        )

        assert response.status_code == 200
        assert response.json()["meta"]["total"] == 1

    async def test_all_invalid_event_types_return_empty_result(
        self,
        admin_client: AsyncClient,
        setting_audit_event_factory: Callable[..., Awaitable[SettingAuditEvent]],
    ) -> None:
        await setting_audit_event_factory()

        response = await admin_client.get(
            "/api/v1/admin/settings/audit-log",
            params=[("event_type", "not-a-real-type")],
        )

        assert response.status_code == 200
        assert response.json()["meta"]["total"] == 0

    async def test_inclusive_date_range(
        self,
        admin_client: AsyncClient,
        setting_audit_event_factory: Callable[..., Awaitable[SettingAuditEvent]],
    ) -> None:
        await setting_audit_event_factory(created_at=datetime(2026, 5, 13, tzinfo=UTC))

        response = await admin_client.get(
            "/api/v1/admin/settings/audit-log",
            params={"from_date": "2026-05-01", "to_date": "2026-05-31"},
        )

        assert response.json()["meta"]["total"] == 1

    async def test_malformed_date_returns_422(self, admin_client: AsyncClient) -> None:
        response = await admin_client.get(
            "/api/v1/admin/settings/audit-log", params={"from_date": "not-a-date"}
        )
        assert response.status_code == 422

    async def test_inverted_date_range_returns_400(
        self, admin_client: AsyncClient
    ) -> None:
        response = await admin_client.get(
            "/api/v1/admin/settings/audit-log",
            params={"from_date": "2026-05-16", "to_date": "2026-05-15"},
        )
        assert response.status_code == 400
        assert response.json()["code"] == "DATE_RANGE_INVERTED"

    async def test_page_below_one_returns_422(self, admin_client: AsyncClient) -> None:
        response = await admin_client.get(
            "/api/v1/admin/settings/audit-log", params={"page": 0}
        )
        assert response.status_code == 422

    async def test_per_page_out_of_range_returns_422(
        self, admin_client: AsyncClient
    ) -> None:
        response = await admin_client.get(
            "/api/v1/admin/settings/audit-log", params={"per_page": 101}
        )
        assert response.status_code == 422

    async def test_page_beyond_last_page_returns_empty_with_correct_total(
        self,
        admin_client: AsyncClient,
        setting_audit_event_factory: Callable[..., Awaitable[SettingAuditEvent]],
    ) -> None:
        await setting_audit_event_factory()

        response = await admin_client.get(
            "/api/v1/admin/settings/audit-log", params={"page": 2}
        )

        assert response.status_code == 200
        assert response.json()["data"] == []
        assert response.json()["meta"]["total"] == 1

    async def test_fixed_newest_first_ordering(
        self,
        admin_client: AsyncClient,
        setting_audit_event_factory: Callable[..., Awaitable[SettingAuditEvent]],
    ) -> None:
        older = await setting_audit_event_factory(
            created_at=datetime(2026, 5, 1, tzinfo=UTC)
        )
        newer = await setting_audit_event_factory(
            created_at=datetime(2026, 5, 2, tzinfo=UTC)
        )

        response = await admin_client.get("/api/v1/admin/settings/audit-log")

        ids = [item["id"] for item in response.json()["data"]]
        assert ids == [str(newer.id), str(older.id)]

    async def test_equal_timestamps_break_tie_by_id_desc(
        self,
        admin_client: AsyncClient,
        setting_audit_event_factory: Callable[..., Awaitable[SettingAuditEvent]],
    ) -> None:
        same_time = datetime(2026, 5, 13, tzinfo=UTC)
        first = await setting_audit_event_factory(created_at=same_time)
        second = await setting_audit_event_factory(created_at=same_time)
        expected_order = sorted([str(first.id), str(second.id)], reverse=True)

        response = await admin_client.get("/api/v1/admin/settings/audit-log")

        ids = [item["id"] for item in response.json()["data"]]
        assert ids == expected_order

    async def test_sort_by_and_sort_order_are_ignored(
        self,
        admin_client: AsyncClient,
        setting_audit_event_factory: Callable[..., Awaitable[SettingAuditEvent]],
    ) -> None:
        older = await setting_audit_event_factory(
            created_at=datetime(2026, 5, 1, tzinfo=UTC)
        )
        newer = await setting_audit_event_factory(
            created_at=datetime(2026, 5, 2, tzinfo=UTC)
        )

        response = await admin_client.get(
            "/api/v1/admin/settings/audit-log",
            params={"sort_by": "created_at", "sort_order": "asc"},
        )

        ids = [item["id"] for item in response.json()["data"]]
        assert ids == [str(newer.id), str(older.id)]

    async def test_no_mutation_methods_are_exposed(
        self, admin_client: AsyncClient
    ) -> None:
        response = await admin_client.post("/api/v1/admin/settings/audit-log")
        assert response.status_code == 405


# ---------------------------------------------------------------------------
# OpenAPI surface
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestSettingsOpenAPISurface:
    def test_both_endpoints_are_present_with_summary_and_description(self) -> None:
        openapi_paths = app.openapi()["paths"]

        settings_get = openapi_paths["/api/v1/admin/settings"]["get"]
        assert settings_get["summary"]
        assert settings_get["description"]

        audit_get = openapi_paths["/api/v1/admin/settings/audit-log"]["get"]
        assert audit_get["summary"]
        assert audit_get["description"]

    def test_no_patch_or_recalculate_endpoints_are_present(self) -> None:
        openapi_paths = app.openapi()["paths"]
        assert "patch" not in openapi_paths.get("/api/v1/admin/settings", {})
        assert (
            "/api/v1/admin/settings/default-cvss-version/recalculate"
            not in openapi_paths
        )

    def test_audit_log_query_parameters_are_declared(self) -> None:
        openapi_paths = app.openapi()["paths"]
        audit_get = openapi_paths["/api/v1/admin/settings/audit-log"]["get"]
        param_names = {p["name"] for p in audit_get.get("parameters", [])}

        assert {"event_type", "setting_key", "actor", "from_date", "to_date"} <= (
            param_names
        )
        assert "sort_by" not in param_names
        assert "sort_order" not in param_names

    def test_impact_preview_operation_is_documented(self) -> None:
        """default-cvss-version-operations.md, Get Default-CVSS Impact
        Preview: one required `proposed_version` query parameter, exactly
        `3.1` or `4.0`, and the `503 CVSS_PREVIEW_TIMEOUT` response. The
        HTTP contract is tested in
        `tests/test_api/test_settings_impact_preview.py`."""
        openapi_paths = app.openapi()["paths"]
        path_item = openapi_paths["/api/v1/admin/settings/default-cvss-version/impact"]
        assert set(path_item) == {"get"}
        operation = path_item["get"]

        assert operation["summary"]
        assert operation["description"]
        assert "requestBody" not in operation
        assert [(p["name"], p["in"]) for p in operation["parameters"]] == [
            ("proposed_version", "query")
        ]
        proposed_version = operation["parameters"][0]
        assert proposed_version["required"] is True
        assert proposed_version["schema"]["type"] == "string"
        assert proposed_version["schema"]["enum"] == ["3.1", "4.0"]
        # Undeclared query parameters are absent from the OpenAPI contract
        # (api-spec.md, Undeclared Query Parameters).
        param_names = {p["name"] for p in operation["parameters"]}
        assert not {"page", "per_page", "sort_by", "sort_order"} & param_names
        assert {"200", "422", "503"} <= set(operation["responses"])
        assert operation["responses"]["503"]["content"]["application/json"][
            "schema"
        ] == {"$ref": "#/components/schemas/ErrorResponse"}

    def test_event_type_parameter_is_repeatable(self) -> None:
        openapi_paths = app.openapi()["paths"]
        audit_get = openapi_paths["/api/v1/admin/settings/audit-log"]["get"]
        event_type_param = next(
            p for p in audit_get["parameters"] if p["name"] == "event_type"
        )
        assert event_type_param["schema"]["type"] == "array"
