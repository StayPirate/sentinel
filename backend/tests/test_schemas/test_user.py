"""Unit tests for user directory/profile request/response/query schemas
and the admin user mutation request/response schemas
(`backend/app/schemas/user.py`).

See `docs/features/identity/user-management.md` (List Users, Get User,
Admin API endpoints) for the authoritative contract under test.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest
from pydantic import ValidationError

from app.core.enums import SortOrder, UserSortField
from app.schemas.common import PaginationMeta
from app.schemas.user import (
    AdminPasswordResetRequest,
    AdminUserCreateRequest,
    AdminUserUpdateRequest,
    UserActionDetailData,
    UserActionDetailResponse,
    UserData,
    UserListQuery,
    UserListResponse,
    UserManagerData,
    UserResponse,
    UserRoleAssignmentData,
    UserRolesUpdateRequest,
)


@pytest.mark.unit
class TestUserListQuery:
    def test_defaults(self) -> None:
        query = UserListQuery()
        assert query.search is None
        assert query.type is None
        assert query.active is None
        assert query.role == []
        assert query.has_role is None
        assert query.page == 1
        assert query.per_page == 20
        assert query.sort_by is UserSortField.USERNAME
        assert query.sort_order is SortOrder.ASC

    def test_search_absent_is_valid(self) -> None:
        assert UserListQuery().search is None

    def test_search_at_minimum_length_is_accepted(self) -> None:
        assert UserListQuery(search="jd").search == "jd"

    def test_search_below_minimum_length_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            UserListQuery(search="j")

    def test_search_empty_string_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            UserListQuery(search="")

    def test_type_accepts_an_invalid_value_without_raising(self) -> None:
        """`type` is intentionally untyped at the schema level — an
        invalid value must reach the route handler so it can render an
        empty page (docs/api-spec.md, Enum Filter Validation)."""
        assert UserListQuery(type="not-a-real-type").type == "not-a-real-type"

    def test_role_accepts_a_list_of_raw_strings(self) -> None:
        query = UserListQuery(role=["admin", "not-a-real-role"])
        assert query.role == ["admin", "not-a-real-role"]

    def test_page_below_one_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            UserListQuery(page=0)

    def test_page_at_int32_max_is_accepted(self) -> None:
        assert UserListQuery(page=2_147_483_647).page == 2_147_483_647

    def test_page_above_int32_max_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            UserListQuery(page=2_147_483_648)

    def test_per_page_above_100_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            UserListQuery(per_page=101)

    def test_per_page_at_100_is_accepted(self) -> None:
        assert UserListQuery(per_page=100).per_page == 100

    @pytest.mark.parametrize(
        "sort_by", ["username", "full_name", "email", "created_at"]
    )
    def test_valid_sort_by_is_accepted(self, sort_by: str) -> None:
        assert UserListQuery(sort_by=sort_by).sort_by == sort_by

    def test_invalid_sort_by_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            UserListQuery(sort_by="active")

    @pytest.mark.parametrize("sort_order", ["asc", "desc"])
    def test_valid_sort_order_is_accepted(self, sort_order: str) -> None:
        assert UserListQuery(sort_order=sort_order).sort_order == sort_order

    def test_invalid_sort_order_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            UserListQuery(sort_order="ascending")


def _make_manager_kwargs(**overrides: object) -> dict[str, object]:
    defaults: dict[str, object] = {
        "id": uuid4(),
        "username": "bwilson",
        "full_name": "Bob Wilson",
        "active": True,
        "email": "bwilson@example.com",
    }
    defaults.update(overrides)
    return defaults


def _make_role_assignment_kwargs(**overrides: object) -> dict[str, object]:
    defaults: dict[str, object] = {
        "role": "admin",
        "group_name": "_manual",
        "assigned_by": uuid4(),
        "created_at": datetime(2026, 5, 1, tzinfo=UTC),
    }
    defaults.update(overrides)
    return defaults


def _make_user_data_kwargs(**overrides: object) -> dict[str, object]:
    defaults: dict[str, object] = {
        "id": uuid4(),
        "username": "jdoe",
        "email": "jdoe@example.com",
        "full_name": "John Doe",
        "active": True,
        "source": "local",
        "external_id": None,
        "manager": None,
        "roles": [],
        "created_at": datetime(2026, 5, 1, tzinfo=UTC),
        "updated_at": datetime(2026, 5, 1, tzinfo=UTC),
    }
    defaults.update(overrides)
    return defaults


@pytest.mark.unit
class TestUserManagerData:
    def test_full_name_accepts_null(self) -> None:
        manager = UserManagerData(**_make_manager_kwargs(full_name=None))
        assert manager.full_name is None

    def test_carries_email_unlike_the_common_user_reference(self) -> None:
        manager = UserManagerData(**_make_manager_kwargs())
        assert manager.email == "bwilson@example.com"


@pytest.mark.unit
class TestUserRoleAssignmentData:
    def test_assigned_by_accepts_null_for_system_assignment(self) -> None:
        assignment = UserRoleAssignmentData(
            **_make_role_assignment_kwargs(assigned_by=None)
        )
        assert assignment.assigned_by is None

    def test_group_name_carries_external_origin(self) -> None:
        assignment = UserRoleAssignmentData(
            **_make_role_assignment_kwargs(group_name="O SUSE Security")
        )
        assert assignment.group_name == "O SUSE Security"


@pytest.mark.unit
class TestUserData:
    def test_full_name_accepts_null_with_no_fallback(self) -> None:
        """docs/features/identity/user-management.md (Get User, Field
        notes): the API returns `null` verbatim — no `username`
        substitution happens at the schema/backend layer."""
        data = UserData(**_make_user_data_kwargs(full_name=None))
        assert data.full_name is None

    def test_source_external_pairs_with_external_id(self) -> None:
        external_id = uuid4()
        data = UserData(
            **_make_user_data_kwargs(source="external", external_id=external_id)
        )
        assert data.source == "external"
        assert data.external_id == external_id

    def test_manager_accepts_null(self) -> None:
        data = UserData(**_make_user_data_kwargs(manager=None))
        assert data.manager is None

    def test_manager_accepts_a_manager_object(self) -> None:
        manager = UserManagerData(**_make_manager_kwargs())
        data = UserData(**_make_user_data_kwargs(manager=manager))
        assert data.manager is not None
        assert data.manager.username == "bwilson"

    def test_roles_accepts_multiple_assignments(self) -> None:
        roles = [
            UserRoleAssignmentData(**_make_role_assignment_kwargs()),
            UserRoleAssignmentData(
                **_make_role_assignment_kwargs(
                    role="vulnerability_analyst", group_name="O SUSE Security"
                )
            ),
        ]
        data = UserData(**_make_user_data_kwargs(roles=roles))
        assert len(data.roles) == 2

    def test_has_no_last_login_at_field(self) -> None:
        """Structural guarantee: the public full profile must never
        expose the operational `last_login_at` field — CLI
        `manage-user show` remains its sole owner."""
        assert "last_login_at" not in UserData.model_fields

    def test_has_no_password_hash_field(self) -> None:
        assert "password_hash" not in UserData.model_fields

    def test_has_no_synced_at_field(self) -> None:
        assert "synced_at" not in UserData.model_fields


@pytest.mark.unit
class TestResponseEnvelopes:
    def test_user_response_wraps_a_single_object(self) -> None:
        response = UserResponse(data=UserData(**_make_user_data_kwargs()))
        assert response.data.username == "jdoe"

    def test_user_list_response_has_data_and_meta(self) -> None:
        response = UserListResponse(
            data=[UserData(**_make_user_data_kwargs())],
            meta=PaginationMeta(total=1, page=1, per_page=20),
        )
        assert len(response.data) == 1


# ---------------------------------------------------------------------------
# Admin mutation endpoint schemas
# ---------------------------------------------------------------------------


def _make_create_kwargs(**overrides: object) -> dict[str, object]:
    defaults: dict[str, object] = {
        "username": "jdoe",
        "email": "jdoe@example.com",
        "full_name": "John Doe",
        "password": "a-fictional-password-value",
    }
    defaults.update(overrides)
    return defaults


@pytest.mark.unit
class TestAdminUserCreateRequest:
    def test_valid_payload_is_accepted(self) -> None:
        request = AdminUserCreateRequest(**_make_create_kwargs())
        assert request.username == "jdoe"

    def test_username_is_trimmed_and_lowercased(self) -> None:
        request = AdminUserCreateRequest(**_make_create_kwargs(username="  JDoe  "))
        assert request.username == "jdoe"

    def test_malformed_username_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            AdminUserCreateRequest(**_make_create_kwargs(username="1-bad-start"))

    def test_username_starting_with_uppercase_after_trim_is_accepted(self) -> None:
        """Uppercase is valid pre-normalization — only the normalized
        (lowercased) value must match the Username Format pattern."""
        request = AdminUserCreateRequest(**_make_create_kwargs(username="JDoe"))
        assert request.username == "jdoe"

    def test_explicit_null_username_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            AdminUserCreateRequest(**_make_create_kwargs(username=None))

    def test_non_string_username_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            AdminUserCreateRequest(**_make_create_kwargs(username=12345))

    def test_email_is_trimmed_and_fully_lowercased(self) -> None:
        request = AdminUserCreateRequest(
            **_make_create_kwargs(email="  John.Doe@Example.COM  ")
        )
        assert request.email == "john.doe@example.com"

    def test_malformed_email_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            AdminUserCreateRequest(**_make_create_kwargs(email="not-an-email"))

    def test_explicit_null_email_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            AdminUserCreateRequest(**_make_create_kwargs(email=None))

    def test_full_name_omitted_defaults_to_none(self) -> None:
        kwargs = _make_create_kwargs()
        del kwargs["full_name"]
        request = AdminUserCreateRequest(**kwargs)
        assert request.full_name is None

    def test_full_name_explicit_null_is_accepted(self) -> None:
        request = AdminUserCreateRequest(**_make_create_kwargs(full_name=None))
        assert request.full_name is None

    def test_missing_password_is_rejected(self) -> None:
        kwargs = _make_create_kwargs()
        del kwargs["password"]
        with pytest.raises(ValidationError):
            AdminUserCreateRequest(**kwargs)

    def test_explicit_null_password_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            AdminUserCreateRequest(**_make_create_kwargs(password=None))

    def test_password_carries_no_length_constraint_at_schema_level(self) -> None:
        """Length policy (16-128 chars) is domain validation owned by
        `user_service.create_user()` — the schema must accept a
        too-short value so the service can raise the domain-specific
        `PasswordValidationError` instead of the generic
        `VALIDATION_ERROR` a schema constraint would produce."""
        request = AdminUserCreateRequest(**_make_create_kwargs(password="short"))
        assert request.password == "short"

    def test_roles_default_to_empty_list(self) -> None:
        kwargs = _make_create_kwargs()
        request = AdminUserCreateRequest(**kwargs)
        assert request.roles == []

    def test_valid_roles_are_accepted(self) -> None:
        request = AdminUserCreateRequest(
            **_make_create_kwargs(roles=["admin", "vulnerability_analyst"])
        )
        assert request.roles == ["admin", "vulnerability_analyst"]

    def test_unknown_role_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            AdminUserCreateRequest(**_make_create_kwargs(roles=["not-a-real-role"]))

    def test_duplicate_role_values_are_rejected(self) -> None:
        with pytest.raises(ValidationError):
            AdminUserCreateRequest(**_make_create_kwargs(roles=["admin", "admin"]))

    def test_explicit_null_roles_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            AdminUserCreateRequest(**_make_create_kwargs(roles=None))


@pytest.mark.unit
class TestAdminUserUpdateRequest:
    def test_email_only_is_accepted(self) -> None:
        request = AdminUserUpdateRequest(email="new@example.com")
        assert request.email == "new@example.com"
        assert request.full_name is None
        assert "full_name" not in request.model_fields_set

    def test_full_name_only_is_accepted(self) -> None:
        request = AdminUserUpdateRequest(full_name="New Name")
        assert request.full_name == "New Name"
        assert "email" not in request.model_fields_set

    def test_empty_body_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            AdminUserUpdateRequest()

    def test_explicit_null_email_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            AdminUserUpdateRequest(email=None)

    def test_explicit_null_full_name_is_accepted_and_tracked_as_set(self) -> None:
        request = AdminUserUpdateRequest(full_name=None)
        assert request.full_name is None
        assert "full_name" in request.model_fields_set

    def test_email_is_trimmed_and_fully_lowercased(self) -> None:
        request = AdminUserUpdateRequest(email="  New.Email@Example.COM  ")
        assert request.email == "new.email@example.com"

    def test_malformed_email_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            AdminUserUpdateRequest(email="not-an-email")

    def test_both_fields_present_are_both_tracked_as_set(self) -> None:
        request = AdminUserUpdateRequest(email="new@example.com", full_name="New Name")
        assert request.model_fields_set == {"email", "full_name"}


@pytest.mark.unit
class TestAdminPasswordResetRequest:
    def test_valid_password_is_accepted(self) -> None:
        request = AdminPasswordResetRequest(password="a-fictional-password-value")
        assert request.password == "a-fictional-password-value"

    def test_missing_password_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            AdminPasswordResetRequest()  # type: ignore[call-arg]

    def test_carries_no_length_constraint_at_schema_level(self) -> None:
        """Mirrors `AdminUserCreateRequest.password` — the 16-128 char
        policy is domain validation owned by
        `user_service.reset_password()`."""
        request = AdminPasswordResetRequest(password="short")
        assert request.password == "short"


@pytest.mark.unit
class TestUserRolesUpdateRequest:
    """`user-management.md` (Set User Roles): strict request validation."""

    def test_omitted_fields_default_to_empty_lists(self) -> None:
        request = UserRolesUpdateRequest()
        assert request.add == []
        assert request.remove == []

    def test_empty_lists_are_accepted(self) -> None:
        request = UserRolesUpdateRequest.model_validate({"add": [], "remove": []})
        assert request.add == []
        assert request.remove == []

    def test_every_wire_value_is_accepted_in_input_order(self) -> None:
        request = UserRolesUpdateRequest.model_validate(
            {
                "add": ["vulnerability_analyst", "admin"],
                "remove": ["restricted_analyst"],
            }
        )
        assert request.add == ["vulnerability_analyst", "admin"]
        assert request.remove == ["restricted_analyst"]

    def test_json_input_is_accepted(self) -> None:
        request = UserRolesUpdateRequest.model_validate_json('{"remove": ["admin"]}')
        assert request.add == []
        assert request.remove == ["admin"]

    @pytest.mark.parametrize(
        "payload",
        [
            pytest.param({"add": None}, id="null-add"),
            pytest.param({"remove": None}, id="null-remove"),
            pytest.param({"add": ["superuser"]}, id="unknown-value"),
            pytest.param({"remove": ["Admin"]}, id="stored-enum-value"),
            pytest.param({"add": ["Vulnerability Analyst"]}, id="stored-enum-va"),
            pytest.param({"add": ["ADMIN"]}, id="uppercase-wire"),
            pytest.param({"add": ["admin", "admin"]}, id="duplicate-add"),
            pytest.param(
                {"remove": ["restricted_analyst", "restricted_analyst"]},
                id="duplicate-remove",
            ),
            pytest.param({"add": ["admin"], "remove": ["admin"]}, id="overlap"),
            pytest.param({"add": "admin"}, id="string-field"),
            pytest.param({"remove": {"role": "admin"}}, id="object-field"),
            pytest.param({"add": [1]}, id="integer-element"),
            pytest.param({"add": [None]}, id="null-element"),
            pytest.param({"remove": [True]}, id="boolean-element"),
        ],
    )
    def test_invalid_payload_is_rejected(self, payload: dict[str, object]) -> None:
        with pytest.raises(ValidationError):
            UserRolesUpdateRequest.model_validate(payload)


@pytest.mark.unit
class TestUserActionDetailSchemas:
    def test_detail_data_carries_the_message(self) -> None:
        data = UserActionDetailData(detail="Account unlocked successfully.")
        assert data.detail == "Account unlocked successfully."

    def test_response_wraps_detail_data_in_the_standard_envelope(self) -> None:
        response = UserActionDetailResponse(
            data=UserActionDetailData(detail="Account unlocked successfully.")
        )
        assert response.data.detail == "Account unlocked successfully."
