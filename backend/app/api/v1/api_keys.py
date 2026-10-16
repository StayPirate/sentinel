"""API key management endpoints: self-service and administrative.

See `docs/features/identity/api-key-management.md` (API) for the
authoritative endpoint contracts this module implements. Handlers stay
thin: they validate, delegate to `api_key_service`
(`docs/features/identity/api-key-service.md`), and map the result or a
typed service exception to the documented response — no business logic,
ownership check, or database query lives here.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query, status

from app.api.dependencies import (
    AuthenticatedPrincipal,
    CurrentUser,
    require_capability,
    require_session_authentication,
)
from app.core.enums import ApiKeySortField, ApiKeyStatus, Capability, SortOrder
from app.core.errors import AppError, ErrorCode
from app.core.exceptions import InactiveUserError
from app.database import DatabaseSession
from app.models.api_key import ApiKey
from app.schemas.api_key import (
    AdminApiKeyData,
    AdminApiKeyListQuery,
    AdminApiKeyListResponse,
    AdminApiKeyResponse,
    ApiKeyCreateRequest,
    ApiKeyData,
    ApiKeyListQuery,
    ApiKeyListResponse,
    ApiKeyResponse,
    CreatedApiKeyData,
    CreatedApiKeyResponse,
)
from app.schemas.common import PaginationMeta, UserReference
from app.schemas.errors import ErrorResponse, ValidationErrorResponse
from app.services import api_key_service
from app.services.api_key_service import (
    ApiKeyInvalidExpiryError,
    ApiKeyNameConflictError,
    ApiKeyNameValidationError,
    ApiKeyNotFoundError,
    ApiKeyWithOwner,
    CreatedApiKey,
)

router = APIRouter(prefix="/api/v1", tags=["API Keys"])


# ---------------------------------------------------------------------------
# Query parameter builders
#
# Declared as individual `Query()`-annotated parameters (rather than a
# single `Annotated[Model, Query()]` query-parameter-model field) so
# each field is visible individually to the shared query-length-limit
# dependency's route-dependant walk (`app.core.query_limits`), which
# inspects `Dependant.query_params` at every nesting depth.
# ---------------------------------------------------------------------------


def _api_key_list_query(
    status_filter: Annotated[
        str | None,
        Query(alias="status", description="One of 'active', 'expired', or 'revoked'."),
    ] = None,
    page: Annotated[
        int,
        Query(ge=1, le=2_147_483_647, description="Page number."),
    ] = 1,
    per_page: Annotated[
        int, Query(ge=1, le=100, description="Items per page; maximum 100.")
    ] = 20,
    sort_by: Annotated[
        ApiKeySortField,
        Query(description="'created_at' or 'last_used_at'."),
    ] = ApiKeySortField.CREATED_AT,
    sort_order: Annotated[
        SortOrder, Query(description="'asc' or 'desc'.")
    ] = SortOrder.DESC,
) -> ApiKeyListQuery:
    return ApiKeyListQuery(
        status=status_filter,
        page=page,
        per_page=per_page,
        sort_by=sort_by,
        sort_order=sort_order,
    )


def _admin_api_key_list_query(
    common: Annotated[ApiKeyListQuery, Depends(_api_key_list_query)],
    owner: Annotated[
        str | None,
        Query(description="Owner UUID or case-sensitive exact username."),
    ] = None,
) -> AdminApiKeyListQuery:
    return AdminApiKeyListQuery(**common.model_dump(), owner=owner)


def _parse_status_filter(raw: str | None) -> tuple[bool, ApiKeyStatus | None]:
    """Resolve the raw `status` query value to a typed filter.

    Returns `(True, None)` when `raw` is absent, `(True, <status>)`
    when it matches a valid `ApiKeyStatus` member, and `(False, None)`
    when present but invalid — the caller must then render an empty
    page without querying the service, per `docs/api-spec.md` (Enum
    Filter Validation): an invalid single-value enum filter yields an
    empty result, not an error.
    """
    if raw is None:
        return True, None
    try:
        return True, ApiKeyStatus(raw)
    except ValueError:
        return False, None


# ---------------------------------------------------------------------------
# Response serialization
# ---------------------------------------------------------------------------


def _serialize_api_key(api_key: ApiKey, now: datetime) -> ApiKeyData:
    """Build the common API key response object.

    `status` is derived (never stored) via
    `api_key_service.derive_api_key_status()`, using the caller's
    shared `now` snapshot. `revoked_by` is the standard User Reference
    Object when the key has a revoker, or `None` for a non-revoked key
    or a CLI/system revocation.
    """
    return ApiKeyData(
        id=api_key.id,
        prefix=api_key.prefix,
        name=api_key.name,
        status=api_key_service.derive_api_key_status(api_key, now),
        created_at=api_key.created_at,
        last_used_at=api_key.last_used_at,
        expires_at=api_key.expires_at,
        revoked_at=api_key.revoked_at,
        revoked_by=(
            UserReference.model_validate(api_key.revoking_user)
            if api_key.revoking_user is not None
            else None
        ),
    )


def _serialize_created_api_key(
    created: CreatedApiKey, now: datetime
) -> CreatedApiKeyData:
    """Build the creation-response object: the common object plus the
    one-time plaintext `key`."""
    common = _serialize_api_key(created.api_key, now)
    return CreatedApiKeyData(**common.model_dump(), key=created.plaintext_key)


def _serialize_api_key_with_owner(
    item: ApiKeyWithOwner, now: datetime
) -> AdminApiKeyData:
    """Build the admin response object: the common object plus `owner`,
    the standard User Reference Object."""
    common = _serialize_api_key(item.api_key, now)
    return AdminApiKeyData(
        **common.model_dump(), owner=UserReference.model_validate(item.owner)
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get(
    "/api-keys",
    response_model=ApiKeyListResponse,
    summary="List my API keys",
    description=(
        "Returns a paginated list of the authenticated user's own API "
        "keys, newest first by default. Never exposes the plaintext key "
        "or its hash."
    ),
)
async def list_my_api_keys(
    principal: CurrentUser,
    db: DatabaseSession,
    query: Annotated[ApiKeyListQuery, Depends(_api_key_list_query)],
) -> ApiKeyListResponse:
    """List my API keys — see
    `docs/features/identity/api-key-management.md` (List My API Keys).

    `api_key_service.list_user_keys()` can raise `UserNotFoundError` for
    an unknown `user_id`, but `principal.user` was already resolved and
    validated for this same request by `get_current_user()` — users are
    never physically deleted (`docs/data-model.md`, User), so that
    guard is unreachable here and is intentionally not caught (matching
    the endpoint's error table in `api-key-management.md`, which
    documents no 404 for this endpoint).
    """
    is_valid, status_filter = _parse_status_filter(query.status)
    if not is_valid:
        return ApiKeyListResponse(
            data=[],
            meta=PaginationMeta(total=0, page=query.page, per_page=query.per_page),
        )

    now = datetime.now(UTC)
    page = await api_key_service.list_user_keys(
        db,
        user_id=principal.user.id,
        status=status_filter,
        page=query.page,
        per_page=query.per_page,
        sort_by=query.sort_by,
        sort_order=query.sort_order,
        now=now,
    )
    return ApiKeyListResponse(
        data=[_serialize_api_key(item, now) for item in page.items],
        meta=PaginationMeta(total=page.total, page=page.page, per_page=page.per_page),
    )


@router.post(
    "/api-keys",
    response_model=CreatedApiKeyResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create an API key",
    description=(
        "Creates a new API key owned by the authenticated user. Requires "
        "JWT session authentication — a request authenticated by an API "
        "key is rejected. Returns the plaintext key exactly once, in "
        "this response only."
    ),
    responses={
        400: {
            "model": ErrorResponse,
            "description": "Expiration is not strictly in the future.",
        },
        403: {
            "model": ErrorResponse,
            "description": (
                "Request is authenticated by API key instead of a JWT session."
            ),
        },
        409: {
            "model": ErrorResponse,
            "description": (
                "Owner became inactive before creation acquired the user "
                "lock, or a non-revoked key already uses this name."
            ),
        },
        422: {
            "model": ValidationErrorResponse | ErrorResponse,
            "description": (
                "`AUTH_API_KEY_NAME_INVALID`: the normalized name violates the "
                "API Key Name Rule. `VALIDATION_ERROR`: the request body is "
                "invalid."
            ),
        },
    },
)
async def create_api_key(
    body: ApiKeyCreateRequest,
    principal: Annotated[
        AuthenticatedPrincipal, Depends(require_session_authentication)
    ],
    db: DatabaseSession,
) -> CreatedApiKeyResponse:
    """Create API key — see
    `docs/features/identity/api-key-management.md` (Create API Key)."""
    try:
        created = await api_key_service.create_key(
            db,
            user_id=principal.user.id,
            name=body.name,
            expires_at=body.expires_at,
        )
    except InactiveUserError:
        raise AppError(
            status_code=status.HTTP_409_CONFLICT,
            code=ErrorCode.USER_INACTIVE,
            detail="User is inactive.",
        ) from None
    except ApiKeyNameValidationError:
        raise AppError(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            code=ErrorCode.AUTH_API_KEY_NAME_INVALID,
            detail="API key name is invalid.",
        ) from None
    except ApiKeyInvalidExpiryError:
        raise AppError(
            status_code=status.HTTP_400_BAD_REQUEST,
            code=ErrorCode.AUTH_API_KEY_INVALID_EXPIRY,
            detail="API key expiration must be strictly in the future.",
        ) from None
    except ApiKeyNameConflictError:
        raise AppError(
            status_code=status.HTTP_409_CONFLICT,
            code=ErrorCode.AUTH_API_KEY_NAME_CONFLICT,
            detail="An active API key with this name already exists.",
        ) from None

    now = datetime.now(UTC)
    return CreatedApiKeyResponse(data=_serialize_created_api_key(created, now))


@router.post(
    "/api-keys/{key_id}/revoke",
    response_model=ApiKeyResponse,
    summary="Revoke my API key",
    description=(
        "Revokes one of the authenticated user's own API keys. "
        "Idempotent — an already-revoked key returns its unchanged "
        "representation. A key that does not exist or belongs to "
        "another user returns an identical 404, without revealing "
        "which case applies."
    ),
    responses={
        404: {
            "model": ErrorResponse,
            "description": "Key does not exist or belongs to another user.",
        },
    },
)
async def revoke_my_api_key(
    key_id: UUID,
    principal: CurrentUser,
    db: DatabaseSession,
) -> ApiKeyResponse:
    """Revoke my API key — see
    `docs/features/identity/api-key-management.md` (Revoke My API Key)."""
    try:
        result = await api_key_service.revoke_key(
            db,
            key_id=key_id,
            acting_user_id=principal.user.id,
            owner_user_id=principal.user.id,
        )
    except ApiKeyNotFoundError:
        raise AppError(
            status_code=status.HTTP_404_NOT_FOUND,
            code=ErrorCode.AUTH_API_KEY_NOT_FOUND,
            detail="API key not found.",
        ) from None

    now = datetime.now(UTC)
    return ApiKeyResponse(data=_serialize_api_key(result.api_key, now))


@router.get(
    "/admin/api-keys",
    response_model=AdminApiKeyListResponse,
    summary="List all API keys",
    description=(
        "Returns a paginated list of API keys across all owners, "
        "requiring the 'manage_users' capability."
    ),
)
async def list_all_api_keys(
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(require_capability(Capability.MANAGE_USERS)),
    ],
    db: DatabaseSession,
    query: Annotated[AdminApiKeyListQuery, Depends(_admin_api_key_list_query)],
) -> AdminApiKeyListResponse:
    """List all API keys — see
    `docs/features/identity/api-key-management.md` (List All API Keys)."""
    is_valid, status_filter = _parse_status_filter(query.status)
    if not is_valid:
        return AdminApiKeyListResponse(
            data=[],
            meta=PaginationMeta(total=0, page=query.page, per_page=query.per_page),
        )

    now = datetime.now(UTC)
    page = await api_key_service.list_all_keys(
        db,
        owner=query.owner,
        status=status_filter,
        page=query.page,
        per_page=query.per_page,
        sort_by=query.sort_by,
        sort_order=query.sort_order,
        now=now,
    )
    return AdminApiKeyListResponse(
        data=[_serialize_api_key_with_owner(item, now) for item in page.items],
        meta=PaginationMeta(total=page.total, page=page.page, per_page=page.per_page),
    )


@router.post(
    "/admin/api-keys/{key_id}/revoke",
    response_model=AdminApiKeyResponse,
    summary="Revoke an API key",
    description=(
        "Revokes any user's API key, requiring the 'manage_users' "
        "capability. An administrator may revoke the API key used to "
        "authenticate the current request. Idempotent."
    ),
    responses={
        404: {
            "model": ErrorResponse,
            "description": "Key does not exist.",
        },
    },
)
async def revoke_api_key(
    key_id: UUID,
    principal: Annotated[
        AuthenticatedPrincipal,
        Depends(require_capability(Capability.MANAGE_USERS)),
    ],
    db: DatabaseSession,
) -> AdminApiKeyResponse:
    """Revoke API key — see
    `docs/features/identity/api-key-management.md` (Revoke API Key)."""
    try:
        result = await api_key_service.revoke_key(
            db,
            key_id=key_id,
            acting_user_id=principal.user.id,
            owner_user_id=None,
        )
    except ApiKeyNotFoundError:
        raise AppError(
            status_code=status.HTTP_404_NOT_FOUND,
            code=ErrorCode.AUTH_API_KEY_NOT_FOUND,
            detail="API key not found.",
        ) from None

    now = datetime.now(UTC)
    return AdminApiKeyResponse(data=_serialize_api_key_with_owner(result, now))
