"""Public user directory, profile, and current-user endpoints, plus the
ticket-independent admin user mutation endpoints.

See `docs/features/identity/user-management.md` (List Users, Get User,
Admin API endpoints) and `docs/features/identity/authentication.md`
(Get Current User) for the authoritative endpoint contracts this module
implements. Handlers stay thin: they validate, delegate to
`user_service` (`docs/features/identity/user-service.md`), and map the
result or a typed service exception to the documented response — no
business logic or database query lives here.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query, status

from app.api.dependencies import (
    AuthenticatedPrincipal,
    CurrentUser,
    OptionalCurrentUser,
    require_capability,
    require_session_authentication,
    user_not_found_error,
)
from app.core.enums import Capability, Role, SortOrder, UserSortField, UserType
from app.core.errors import AppError, ErrorCode
from app.core.exceptions import UserNotFoundError
from app.core.passwords import PasswordValidationError
from app.core.permissions import role_from_wire, role_to_wire
from app.database import DatabaseSession, register_post_commit_callback
from app.models.user import User
from app.schemas.auth import CurrentUserData, CurrentUserResponse
from app.schemas.common import PaginationMeta
from app.schemas.errors import ErrorResponse
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
)
from app.services import user_service
from app.services.local_auth_service import clear_login_attempts
from app.services.session_service import purge_session_cache
from app.services.user_service import (
    ExternalUserFieldReadOnlyError,
    ExternalUserPasswordError,
    ExternalUserStatusReadOnlyError,
    UserConflictError,
)

router = APIRouter(prefix="/api/v1", tags=["Users"])


# ---------------------------------------------------------------------------
# Query parameter builder
#
# Declared as individual `Query()`-annotated parameters (rather than a
# single `Annotated[Model, Query()]` query-parameter-model field) so
# each field is visible individually to the shared query-length-limit
# dependency's route-dependant walk (`app.core.query_limits`), which
# inspects `Dependant.query_params` at every nesting depth. Mirrors
# `app/api/v1/api_keys.py`.
# ---------------------------------------------------------------------------


def _user_list_query(
    *,
    search: Annotated[
        str | None,
        Query(
            min_length=2,
            description=(
                "Case-insensitive substring across username, email, and full name."
            ),
        ),
    ] = None,
    type_filter: Annotated[
        str | None,
        Query(alias="type", description="One of 'local' or 'external'."),
    ] = None,
    active: Annotated[
        bool | None, Query(description="Filter by active status.")
    ] = None,
    role: Annotated[
        list[str],
        Query(
            default_factory=list,
            description=(
                "One or more of 'admin', 'vulnerability_analyst', "
                "'restricted_analyst'. Repeatable; OR semantics."
            ),
        ),
    ],
    has_role: Annotated[
        bool | None,
        Query(description="true for users with at least one role, false for none."),
    ] = None,
    page: Annotated[int, Query(ge=1, le=2_147_483_647, description="Page number.")] = 1,
    per_page: Annotated[
        int, Query(ge=1, le=100, description="Items per page; maximum 100.")
    ] = 20,
    sort_by: Annotated[
        UserSortField,
        Query(
            description="'username' (default), 'full_name', 'email', or 'created_at'."
        ),
    ] = UserSortField.USERNAME,
    sort_order: Annotated[SortOrder, Query(description="'asc' or 'desc'.")] = (
        SortOrder.ASC
    ),
) -> UserListQuery:
    return UserListQuery(
        search=search,
        type=type_filter,
        active=active,
        role=role,
        has_role=has_role,
        page=page,
        per_page=per_page,
        sort_by=sort_by,
        sort_order=sort_order,
    )


def _parse_user_type(raw: str | None) -> tuple[bool, UserType | None]:
    """Resolve the raw `type` query value to a typed filter.

    Returns `(True, None)` when `raw` is absent, `(True, <type>)` when
    it matches a valid `UserType` member, and `(False, None)` when
    present but invalid — the caller must then render an empty page
    without querying the service, per `docs/api-spec.md` (Enum Filter
    Validation): an invalid single-value enum filter yields an empty
    result, not an error.
    """
    if raw is None:
        return True, None
    try:
        return True, UserType(raw)
    except ValueError:
        return False, None


def _parse_role_filters(raw: list[str]) -> tuple[bool, list[Role]]:
    """Resolve the raw repeatable `role` query values to typed filters.

    Returns `(True, [])` when `raw` is empty (no filter applied),
    `(True, [...])` with the valid subset when at least one value is
    valid, and `(False, [])` when `raw` is non-empty but every value is
    invalid — the caller must then render an empty page without
    querying the service, per `docs/api-spec.md` (Enum Filter
    Validation): if all provided values are invalid, the result is
    empty, not unfiltered.
    """
    if not raw:
        return True, []
    valid: list[Role] = []
    for value in raw:
        try:
            valid.append(role_from_wire(value))
        except ValueError:
            continue
    if not valid:
        return False, []
    return True, valid


# ---------------------------------------------------------------------------
# Response serialization
# ---------------------------------------------------------------------------


def _serialize_user(user: User) -> UserData:
    """Build the full user profile response object.

    `source` is derived (never stored) from `external_id`. `roles` is
    ordered alphabetically by wire-format role value, then `group_name`,
    then `id` — deterministic regardless of assignment order or
    database physical order (`docs/features/identity/rbac.md`,
    Deterministic ordering).
    """
    manager = None
    if user.manager is not None:
        manager = UserManagerData(
            id=user.manager.id,
            username=user.manager.username,
            full_name=user.manager.full_name,
            active=user.manager.active,
            email=user.manager.email,
        )

    sorted_roles = sorted(
        user.roles,
        key=lambda user_role: (
            role_to_wire(Role(user_role.role)),
            user_role.group_name,
            user_role.id,
        ),
    )
    roles = [
        UserRoleAssignmentData(
            role=role_to_wire(Role(user_role.role)),
            group_name=user_role.group_name,
            assigned_by=user_role.assigned_by,
            created_at=user_role.created_at,
        )
        for user_role in sorted_roles
    ]

    return UserData(
        id=user.id,
        username=user.username,
        email=user.email,
        full_name=user.full_name,
        active=user.active,
        source="external" if user.external_id is not None else "local",
        external_id=user.external_id,
        manager=manager,
        roles=roles,
        created_at=user.created_at,
        updated_at=user.updated_at,
    )


# ---------------------------------------------------------------------------
# Endpoints
#
# `/users/me` MUST be registered before `/users/{user}`: Starlette
# matches routes in declaration order, and `/users/{user}` would
# otherwise capture the literal path segment `me` as a username.
# ---------------------------------------------------------------------------


@router.get(
    "/users",
    response_model=UserListResponse,
    summary="List users",
    description=(
        "Returns a paginated public directory of users. Supports search "
        "across username, email, and full name; local/external type; "
        "active status; repeatable role (OR semantics); and has_role "
        "filters, plus standard pagination and sorting. Public endpoint."
    ),
)
async def list_users(
    db: DatabaseSession,
    query: Annotated[UserListQuery, Depends(_user_list_query)],
    _principal: OptionalCurrentUser,
) -> UserListResponse:
    """List users — see
    `docs/features/identity/user-management.md` (List Users).

    `_principal` is unused by the response: it exists solely to run
    optional authentication (`Authentication: Optional`) so a valid
    selected credential participates in JWT sliding refresh and API-key
    operational effects — see `docs/api-spec.md` (Optional
    Authentication on Public Endpoints)."""
    type_valid, user_type = _parse_user_type(query.type)
    roles_valid, roles = _parse_role_filters(query.role)
    if not type_valid or not roles_valid:
        return UserListResponse(
            data=[],
            meta=PaginationMeta(total=0, page=query.page, per_page=query.per_page),
        )

    page = await user_service.list_users(
        db,
        search=query.search,
        user_type=user_type,
        active=query.active,
        roles=roles,
        has_role=query.has_role,
        page=query.page,
        per_page=query.per_page,
        sort_by=query.sort_by,
        sort_order=query.sort_order,
    )
    return UserListResponse(
        data=[_serialize_user(user) for user in page.items],
        meta=PaginationMeta(total=page.total, page=page.page, per_page=page.per_page),
    )


@router.get(
    "/users/me",
    response_model=CurrentUserResponse,
    summary="Get my profile",
    description=(
        "Returns the concise profile of the currently authenticated user, "
        "including current role values. Requires authentication (JWT "
        "session or API key)."
    ),
)
async def get_current_user_profile(
    principal: CurrentUser, db: DatabaseSession
) -> CurrentUserResponse:
    """Get current user — see
    `docs/features/identity/authentication.md` (Get Current User)."""
    roles = await user_service.get_user_roles(db, principal.user.id)
    return CurrentUserResponse(
        data=CurrentUserData(
            id=principal.user.id,
            username=principal.user.username,
            email=principal.user.email,
            full_name=principal.user.full_name,
            roles=sorted(role_to_wire(role) for role in roles),
            active=principal.user.active,
        )
    )


@router.get(
    "/users/{user}",
    response_model=UserResponse,
    summary="Get user",
    description=(
        "Returns the full profile of one user, resolved by UUID or exact, "
        "case-sensitive username. Public endpoint."
    ),
    responses={
        404: {
            "model": ErrorResponse,
            "description": "No user found matching the given UUID or username.",
        },
    },
)
async def get_user(
    user: str, db: DatabaseSession, _principal: OptionalCurrentUser
) -> UserResponse:
    """Get user — see
    `docs/features/identity/user-management.md` (Get User).

    `_principal` is unused by the response: it exists solely to run
    optional authentication (`Authentication: Optional`) so a valid
    selected credential participates in JWT sliding refresh and API-key
    operational effects — see `docs/api-spec.md` (Optional
    Authentication on Public Endpoints)."""
    try:
        resolved = await user_service.get_user(db, user)
    except UserNotFoundError:
        raise user_not_found_error() from None
    return UserResponse(data=_serialize_user(resolved))


# ---------------------------------------------------------------------------
# Admin mutation endpoints
#
# See `docs/features/identity/user-management.md` (Admin API endpoints):
# every endpoint requires `manage_users`; every `{user}` path parameter
# is resolved through `user_service.resolve_user_identifier()` before
# delegating to the owning lifecycle service, per the "route handlers
# execute no ORM lookup directly" rule stated there. Create User and
# Reset User Password additionally require JWT session authentication
# via `require_session_authentication()` — they mint credentials, so
# they must not be reachable with an API key (mirrors API key creation
# in `docs/features/identity/authentication.md`, Session-Only
# Authentication Dependency).
# ---------------------------------------------------------------------------


@router.post(
    "/admin/users",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create user (admin)",
    description=(
        "Creates a new local user with a password and optional initial "
        "manual roles. Requires the 'manage_users' capability and JWT "
        "session authentication — not reachable with an API key."
    ),
    responses={
        403: {
            "model": ErrorResponse,
            "description": "Request authenticated by API key instead of JWT session.",
        },
        409: {
            "model": ErrorResponse,
            "description": "Normalized username or email already in use.",
        },
        422: {
            "model": ErrorResponse,
            "description": "Password does not meet the 16-128 character policy.",
        },
    },
)
async def create_user_admin(
    body: AdminUserCreateRequest,
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(require_capability(Capability.MANAGE_USERS)),
    ],
    _session_check: Annotated[
        AuthenticatedPrincipal,
        Depends(require_session_authentication),
    ],
    db: DatabaseSession,
) -> UserResponse:
    """Create user (admin) — see
    `docs/features/identity/user-management.md` (Create User (Admin))."""
    roles = [(role_from_wire(value), "_manual") for value in body.roles]
    try:
        created = await user_service.create_user(
            db,
            username=body.username,
            email=body.email,
            full_name=body.full_name,
            active=True,
            password=body.password,
            roles=roles,
            acting_user_id=principal.user.id,
        )
    except UserConflictError:
        raise AppError(
            status_code=status.HTTP_409_CONFLICT,
            code=ErrorCode.USER_ALREADY_EXISTS,
            detail="A user with this username or email already exists.",
        ) from None
    except PasswordValidationError:
        raise AppError(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            code=ErrorCode.USER_PASSWORD_POLICY_VIOLATION,
            detail="Password must be between 16 and 128 characters.",
        ) from None

    return UserResponse(data=_serialize_user(created))


@router.patch(
    "/admin/users/{user}",
    response_model=UserResponse,
    summary="Update user (admin)",
    description=(
        "Updates a local user's email and/or full name. At least one field "
        "must be provided. Requires the 'manage_users' capability."
    ),
    responses={
        404: {
            "model": ErrorResponse,
            "description": "No user found matching the given UUID or username.",
        },
        409: {
            "model": ErrorResponse,
            "description": (
                "Normalized email already in use, or the target is an external user."
            ),
        },
    },
)
async def update_user_admin(
    user: str,
    body: AdminUserUpdateRequest,
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(require_capability(Capability.MANAGE_USERS)),
    ],
    db: DatabaseSession,
) -> UserResponse:
    """Update user (admin) — see
    `docs/features/identity/user-management.md` (Update User (Admin))."""
    try:
        target_user = await user_service.resolve_user_identifier(db, user)
    except UserNotFoundError:
        raise user_not_found_error() from None

    email_set = "email" in body.model_fields_set
    full_name_set = "full_name" in body.model_fields_set

    try:
        if email_set and full_name_set:
            # `AdminUserUpdateRequest._validate_email` rejects an explicit
            # `null`, so a present `email` is always a validated string.
            assert body.email is not None
            result = await user_service.update_user(
                db,
                target_user.id,
                acting_user_id=principal.user.id,
                email=body.email,
                full_name=body.full_name,
            )
        elif email_set:
            assert body.email is not None
            result = await user_service.update_user(
                db,
                target_user.id,
                acting_user_id=principal.user.id,
                email=body.email,
            )
        else:
            # `AdminUserUpdateRequest` guarantees at least one of
            # `email`/`full_name` is present, so `full_name_set` is True
            # here — this branch also covers `full_name_set` explicitly
            # for mypy's exhaustiveness, since both booleans cannot be
            # False at the same time.
            result = await user_service.update_user(
                db,
                target_user.id,
                acting_user_id=principal.user.id,
                full_name=body.full_name,
            )
    except ExternalUserFieldReadOnlyError:
        raise AppError(
            status_code=status.HTTP_409_CONFLICT,
            code=ErrorCode.USER_EXTERNAL_FIELD_READONLY,
            detail=(
                "Cannot modify identity fields for external users. These "
                "fields are managed by the external identity provider."
            ),
        ) from None
    except UserConflictError:
        raise AppError(
            status_code=status.HTTP_409_CONFLICT,
            code=ErrorCode.USER_ALREADY_EXISTS,
            detail="A user with this email already exists.",
        ) from None
    except UserNotFoundError:
        raise user_not_found_error() from None

    return UserResponse(data=_serialize_user(result.user))


@router.post(
    "/admin/users/{user}/reactivate",
    response_model=UserResponse,
    summary="Reactivate user (admin)",
    description=(
        "Reactivates a previously deactivated local user. Idempotent for "
        "an already-active local user. Requires the 'manage_users' "
        "capability."
    ),
    responses={
        404: {
            "model": ErrorResponse,
            "description": "No user found matching the given UUID or username.",
        },
        409: {
            "model": ErrorResponse,
            "description": "Target is an external user.",
        },
    },
)
async def reactivate_user_admin(
    user: str,
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(require_capability(Capability.MANAGE_USERS)),
    ],
    db: DatabaseSession,
) -> UserResponse:
    """Reactivate user (admin) — see
    `docs/features/identity/user-management.md` (Reactivate User)."""
    try:
        target_user = await user_service.resolve_user_identifier(db, user)
    except UserNotFoundError:
        raise user_not_found_error() from None

    try:
        result = await user_service.reactivate_user(
            db, target_user.id, acting_user_id=principal.user.id
        )
    except ExternalUserStatusReadOnlyError:
        raise AppError(
            status_code=status.HTTP_409_CONFLICT,
            code=ErrorCode.USER_EXTERNAL_STATUS_READONLY,
            detail="Cannot reactivate external users.",
        ) from None
    except UserNotFoundError:
        raise user_not_found_error() from None

    return UserResponse(data=_serialize_user(result.user))


@router.post(
    "/admin/users/{user}/password",
    response_model=UserActionDetailResponse,
    summary="Reset user password (admin)",
    description=(
        "Resets the password of a local user (active or inactive), "
        "invalidating all active sessions. Requires the 'manage_users' "
        "capability and JWT session authentication — not reachable with "
        "an API key."
    ),
    responses={
        403: {
            "model": ErrorResponse,
            "description": "Request authenticated by API key instead of JWT session.",
        },
        404: {
            "model": ErrorResponse,
            "description": "No user found matching the given UUID or username.",
        },
        409: {
            "model": ErrorResponse,
            "description": "Target is an external user.",
        },
        422: {
            "model": ErrorResponse,
            "description": "Password does not meet the 16-128 character policy.",
        },
    },
)
async def reset_user_password_admin(
    user: str,
    body: AdminPasswordResetRequest,
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(require_capability(Capability.MANAGE_USERS)),
    ],
    _session_check: Annotated[
        AuthenticatedPrincipal,
        Depends(require_session_authentication),
    ],
    db: DatabaseSession,
) -> UserActionDetailResponse:
    """Reset user password (admin) — see
    `docs/features/identity/user-management.md` (Reset User Password)."""
    try:
        target_user = await user_service.resolve_user_identifier(db, user)
    except UserNotFoundError:
        raise user_not_found_error() from None

    try:
        result = await user_service.reset_password(
            db, target_user.id, body.password, acting_user_id=principal.user.id
        )
    except ExternalUserPasswordError:
        raise AppError(
            status_code=status.HTTP_409_CONFLICT,
            code=ErrorCode.USER_EXTERNAL_PASSWORD_FORBIDDEN,
            detail=(
                "Cannot set password for external user. External users "
                "authenticate via SSO."
            ),
        ) from None
    except PasswordValidationError:
        raise AppError(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            code=ErrorCode.USER_PASSWORD_POLICY_VIOLATION,
            detail="Password must be between 16 and 128 characters.",
        ) from None
    except UserNotFoundError:
        raise user_not_found_error() from None

    async def _purge_sessions() -> None:
        await purge_session_cache(result.invalidated_session_ids)

    async def _clear_lockout() -> None:
        await clear_login_attempts(result.username)

    # Order matters: session-cache purge before lockout-counter clear,
    # matching `reset_password()`'s documented post-commit steps 8-9
    # (`docs/features/identity/user-service.md`).
    register_post_commit_callback(db, _purge_sessions)
    register_post_commit_callback(db, _clear_lockout)

    return UserActionDetailResponse(
        data=UserActionDetailData(
            detail="Password updated. All active sessions have been invalidated."
        )
    )


@router.post(
    "/admin/users/{user}/unlock",
    response_model=UserActionDetailResponse,
    summary="Unlock user (admin)",
    description=(
        "Clears the login lockout counter for a user. Idempotent — a user "
        "who is not locked out returns the same success response. "
        "Requires the 'manage_users' capability."
    ),
    responses={
        404: {
            "model": ErrorResponse,
            "description": "No user found matching the given UUID or username.",
        },
    },
)
async def unlock_user_admin(
    user: str,
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(require_capability(Capability.MANAGE_USERS)),
    ],
    db: DatabaseSession,
) -> UserActionDetailResponse:
    """Unlock user (admin) — see
    `docs/features/identity/user-management.md` (Unlock User)."""
    try:
        target_user = await user_service.resolve_user_identifier(db, user)
    except UserNotFoundError:
        raise user_not_found_error() from None

    try:
        await user_service.unlock_user(
            db, target_user.id, acting_user_id=principal.user.id
        )
    except UserNotFoundError:
        raise user_not_found_error() from None

    return UserActionDetailResponse(
        data=UserActionDetailData(detail="Account unlocked successfully.")
    )
