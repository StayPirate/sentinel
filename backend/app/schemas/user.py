"""Request/response/query schemas for the public user directory/profile
endpoints and the admin user mutation endpoints.

See `docs/features/identity/user-management.md` (List Users, Get User,
Admin API endpoints) for the authoritative request/response contract
these schemas implement.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Final
from uuid import UUID

from email_validator import EmailNotValidError, validate_email
from pydantic import BaseModel, Field, field_validator, model_validator

from app.core.enums import SortOrder, UserSortField
from app.core.permissions import role_from_wire
from app.schemas.common import PaginationMeta

# Username Format (docs/conventions.md): 1-64 characters, starts with a
# letter, lowercase letters/numbers/dots/hyphens/underscores only.
# Duplicated from `app.services.user_service` deliberately — this is a
# boundary defense-in-depth check (see `user_service.create_user()`,
# "Defense in depth, not a single guarantee"): the request schema
# rejects a malformed username with the generic 422 `VALIDATION_ERROR`
# before it ever reaches the service, which is the sole guaranteed
# validation point (also reached by external provisioning, which has no
# Pydantic boundary in front of it).
_USERNAME_PATTERN: Final = re.compile(r"^[a-z][a-z0-9._-]{0,63}$")


class UserListQuery(BaseModel):
    """Query parameters for `GET /api/v1/users` (`user-management.md`,
    List Users).

    `type` and `role` are intentionally `str | None` / `list[str]`, not
    typed enums: an invalid value must be silently ignored and produce
    an empty result (`docs/api-spec.md`, Enum Filter Validation) rather
    than the schema-validation `422` a typed enum field would raise. The
    route handler parses them against `UserType`/`Role` itself.
    """

    search: str | None = Field(default=None, min_length=2)
    type: str | None = None
    active: bool | None = None
    role: list[str] = Field(default_factory=list)
    has_role: bool | None = None
    page: int = Field(default=1, ge=1, le=2_147_483_647)
    per_page: int = Field(default=20, ge=1, le=100)
    sort_by: UserSortField = UserSortField.USERNAME
    sort_order: SortOrder = SortOrder.ASC


class UserManagerData(BaseModel):
    """The `manager` object in a full user profile — the standard User
    Reference Object shape plus `email`, per `user-management.md` (Get
    User)."""

    id: UUID
    username: str
    full_name: str | None
    active: bool
    email: str


class UserRoleAssignmentData(BaseModel):
    """One entry of a full user profile's `roles` array
    (`user-management.md`, Get User)."""

    role: str
    group_name: str
    assigned_by: UUID | None
    created_at: datetime


class UserData(BaseModel):
    """The full user profile object shared by `GET /api/v1/users` (list
    items) and `GET /api/v1/users/{user}` (`user-management.md`, Get
    User). `full_name` and `manager.full_name` are nullable — the API
    returns `null` verbatim with no fallback substitution."""

    id: UUID
    username: str
    email: str
    full_name: str | None
    active: bool
    source: str
    external_id: UUID | None
    manager: UserManagerData | None
    roles: list[UserRoleAssignmentData]
    created_at: datetime
    updated_at: datetime


class UserResponse(BaseModel):
    """Response body for `GET /api/v1/users/{user}`."""

    data: UserData


class UserListResponse(BaseModel):
    """Response body for `GET /api/v1/users`."""

    data: list[UserData]
    meta: PaginationMeta


# ---------------------------------------------------------------------------
# Admin mutation endpoints (`user-management.md`, Admin API endpoints)
# ---------------------------------------------------------------------------


def _normalize_username_field(value: Any) -> Any:
    """Shared `username` normalize-and-validate step for admin request
    schemas. Trims and lowercases, then validates against the Username
    Format pattern. Raises `ValueError` for a non-string value (including
    explicit `null`) or a syntactically invalid username — Pydantic
    converts `ValueError` (unlike `TypeError`) raised inside a validator
    to the standard 422 `VALIDATION_ERROR` response.
    """
    if not isinstance(value, str):
        raise ValueError("username must be a string.")
    normalized = value.strip().lower()
    if not _USERNAME_PATTERN.fullmatch(normalized):
        raise ValueError(
            "Username must be 1-64 characters, start with a letter, and "
            "contain only lowercase letters, numbers, dots, hyphens, and "
            "underscores."
        )
    return normalized


def _normalize_email_field(value: Any) -> Any:
    """Shared `email` normalize-and-validate step for admin request
    schemas. Trims and lowercases the entire value, then validates format
    with `email-validator` (`check_deliverability=False` — no DNS
    lookup). Raises `ValueError` for a non-string value or an invalid
    format — Pydantic converts `ValueError` (unlike `TypeError`) raised
    inside a validator to the standard 422 `VALIDATION_ERROR` response.
    Mirrors the normalization performed by `user_service`
    (`docs/features/identity/user-service.md`,
    `create_user()`/`update_user()`) as a defense-in-depth boundary
    check, not a replacement for it.
    """
    if not isinstance(value, str):
        raise ValueError("email must be a string.")
    normalized = value.strip().lower()
    try:
        validate_email(normalized, check_deliverability=False)
    except EmailNotValidError as exc:
        raise ValueError("Invalid email format.") from exc
    return normalized


def _validate_role_list(value: list[str]) -> list[str]:
    """Reject unknown wire-format role values and repeated values within
    one list. Raises `ValueError`, which Pydantic renders as the global 422
    `VALIDATION_ERROR` response."""
    if len(value) != len(set(value)):
        raise ValueError("Duplicate role values are not allowed.")
    for item in value:
        try:
            role_from_wire(item)
        except ValueError as exc:
            raise ValueError(f"Unknown role value: {item!r}") from exc
    return value


class AdminUserCreateRequest(BaseModel):
    """Request body for `POST /api/v1/admin/users`
    (`user-management.md`, Create User (Admin)).

    `password` intentionally carries no length constraint at this layer:
    the 16-128 character policy is domain validation enforced by
    `user_service.create_user()`, which raises the domain-specific
    `PasswordValidationError` mapped to `422
    USER_PASSWORD_POLICY_VIOLATION` — a schema constraint here would
    instead produce the generic `422 VALIDATION_ERROR`, losing that
    documented code (mirrors `ApiKeyCreateRequest.name`).
    """

    username: str
    email: str
    full_name: str | None = Field(default=None, max_length=255)
    password: str = Field(repr=False)
    roles: list[str] = Field(default_factory=list)

    @field_validator("username", mode="before")
    @classmethod
    def _validate_username(cls, value: Any) -> Any:
        return _normalize_username_field(value)

    @field_validator("email", mode="before")
    @classmethod
    def _validate_email(cls, value: Any) -> Any:
        return _normalize_email_field(value)

    @field_validator("roles")
    @classmethod
    def _validate_roles(cls, value: list[str]) -> list[str]:
        return _validate_role_list(value)


class AdminUserUpdateRequest(BaseModel):
    """Request body for `PATCH /api/v1/admin/users/{user}`
    (`user-management.md`, Update User (Admin)).

    Both fields are optional but at least one must be provided
    (`docs/api-spec.md`, Partial Update Semantics). `email` rejects
    explicit `null` (non-nullable field); `full_name` accepts explicit
    `null` to clear the stored display name. The route distinguishes
    "omitted" from "explicitly provided" via `model_fields_set` — see
    `docs/features/identity/user-service.md` (`update_user()`, the
    `_MISSING` sentinel pattern) for how the route threads this into the
    service call.
    """

    email: str | None = None
    full_name: str | None = Field(default=None, max_length=255)

    @field_validator("email", mode="before")
    @classmethod
    def _validate_email(cls, value: Any) -> Any:
        if value is None:
            raise ValueError("email cannot be null.")
        return _normalize_email_field(value)

    @model_validator(mode="after")
    def _require_at_least_one_field(self) -> AdminUserUpdateRequest:
        if not self.model_fields_set:
            raise ValueError("At least one field must be provided.")
        return self


class AdminPasswordResetRequest(BaseModel):
    """Request body for `POST /api/v1/admin/users/{user}/password`
    (`user-management.md`, Reset User Password).

    `password` intentionally carries no length constraint at this layer
    for the same reason as `AdminUserCreateRequest.password` — the
    policy is domain validation owned by
    `user_service.reset_password()`.
    """

    password: str = Field(repr=False)


class UserRolesUpdateRequest(BaseModel):
    """Request body for `POST /api/v1/admin/users/{user}/roles`
    (`user-management.md`, Set User Roles).

    Validation is strict, unlike `user_service.update_roles()`'s permissive
    set normalization: an omitted field means `[]`, but explicit `null`, a
    non-array, a non-string element, an unknown role value, a role repeated
    within one list, and a role present in both lists are rejected. An
    absent body is handled by the route as `{}`.
    """

    add: list[str] = Field(default_factory=list)
    remove: list[str] = Field(default_factory=list)

    @field_validator("add", "remove")
    @classmethod
    def _validate_roles(cls, value: list[str]) -> list[str]:
        return _validate_role_list(value)

    @model_validator(mode="after")
    def _reject_overlap(self) -> UserRolesUpdateRequest:
        if set(self.add) & set(self.remove):
            raise ValueError("A role cannot be both added and removed.")
        return self


class UserActionDetailData(BaseModel):
    """The `detail` object shared by the password-reset and unlock
    action responses (`user-management.md`, Reset User Password / Unlock
    User) — a consolidated group per `docs/conventions.md` (Function
    Specification Completeness, Consolidated groups): both endpoints
    return an identical single-field confirmation shape."""

    detail: str


class UserActionDetailResponse(BaseModel):
    """Response body for `POST /api/v1/admin/users/{user}/password` and
    `POST /api/v1/admin/users/{user}/unlock`."""

    data: UserActionDetailData
