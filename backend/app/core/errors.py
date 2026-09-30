"""Standard API error envelope: error codes and the `AppError` exception.

See `docs/api-spec.md` (Response Format, Error Code Categories) for the
authoritative error response contract this module implements: every
error response body is `{"code": "...", "detail": "..."}` (plus an
optional `errors` array for `VALIDATION_ERROR`, and the top-level
`existing_ticket_id` of `TICKET_CVE_CONFLICT`). `ErrorCode` is the
"Python enum in the backend (`app/core/errors.py`)" the spec refers to
as the canonical registry of valid codes — new codes are added
incrementally as the corresponding feature is implemented, not
pre-declared for unimplemented features.

`AppError` is the exception API-layer code raises to produce this
envelope; it is translated to a JSON response by the global exception
handler registered in `app.main`. `RequestValidationError` (422) and
unhandled exceptions (500) are handled by their own dedicated handlers
there — see `docs/conventions.md` (Transaction and Locking) and
`docs/api-spec.md` (Global Responses) for the endpoints/handlers that
produce each of those two responses.
"""

from __future__ import annotations

from collections.abc import Mapping
from enum import StrEnum
from typing import Final


class ErrorCode(StrEnum):
    """Stable, machine-readable API error code identifiers.

    See `docs/api-spec.md` (Error Code Categories) for the full prefix
    taxonomy. Removing or renaming a value is a breaking API change.
    """

    VALIDATION_ERROR = "VALIDATION_ERROR"
    INTERNAL_ERROR = "INTERNAL_ERROR"
    AUTH_NOT_AUTHENTICATED = "AUTH_NOT_AUTHENTICATED"
    AUTH_LOGOUT_NOT_APPLICABLE = "AUTH_LOGOUT_NOT_APPLICABLE"
    AUTH_INVALID_CREDENTIALS = "AUTH_INVALID_CREDENTIALS"
    AUTH_ACCOUNT_LOCKED = "AUTH_ACCOUNT_LOCKED"
    AUTH_INSUFFICIENT_PERMISSION = "AUTH_INSUFFICIENT_PERMISSION"
    AUTH_SESSION_REQUIRED = "AUTH_SESSION_REQUIRED"
    AUTH_API_KEY_NOT_FOUND = "AUTH_API_KEY_NOT_FOUND"
    AUTH_API_KEY_NAME_CONFLICT = "AUTH_API_KEY_NAME_CONFLICT"
    AUTH_API_KEY_NAME_INVALID = "AUTH_API_KEY_NAME_INVALID"
    AUTH_API_KEY_INVALID_EXPIRY = "AUTH_API_KEY_INVALID_EXPIRY"
    USER_NOT_FOUND = "USER_NOT_FOUND"
    USER_INACTIVE = "USER_INACTIVE"
    USER_ALREADY_EXISTS = "USER_ALREADY_EXISTS"
    USER_EXTERNAL_STATUS_READONLY = "USER_EXTERNAL_STATUS_READONLY"
    USER_EXTERNAL_FIELD_READONLY = "USER_EXTERNAL_FIELD_READONLY"
    USER_EXTERNAL_PASSWORD_FORBIDDEN = "USER_EXTERNAL_PASSWORD_FORBIDDEN"  # nosec B105 -- error code, not a credential
    USER_PASSWORD_POLICY_VIOLATION = "USER_PASSWORD_POLICY_VIOLATION"  # nosec B105 -- error code, not a credential
    TICKET_NOT_FOUND = "TICKET_NOT_FOUND"
    TICKET_NOT_MUTABLE = "TICKET_NOT_MUTABLE"
    TICKET_SEVERITY_DERIVED = "TICKET_SEVERITY_DERIVED"
    TICKET_CVE_CONFLICT = "TICKET_CVE_CONFLICT"
    TICKET_CVE_ALREADY_SET = "TICKET_CVE_ALREADY_SET"
    TICKET_ASSIGNEE_NOT_VA = "TICKET_ASSIGNEE_NOT_VA"
    TICKET_ASSIGNEE_INACTIVE = "TICKET_ASSIGNEE_INACTIVE"
    TICKET_INVALID_TRANSITION = "TICKET_INVALID_TRANSITION"
    TICKET_SELF_DUPLICATE = "TICKET_SELF_DUPLICATE"
    TICKET_DUPLICATE_TARGET_DUPLICATED = "TICKET_DUPLICATE_TARGET_DUPLICATED"
    TICKET_DUPLICATE_CONCURRENT_MODIFICATION = (
        "TICKET_DUPLICATE_CONCURRENT_MODIFICATION"
    )
    TICKET_NOT_CONFIDENTIAL = "TICKET_NOT_CONFIDENTIAL"
    RESOURCE_NOT_FOUND = "RESOURCE_NOT_FOUND"
    CVE_NOT_FOUND = "CVE_NOT_FOUND"
    CVE_INVALID_FORMAT = "CVE_INVALID_FORMAT"
    CVSS_INVALID_VECTOR = "CVSS_INVALID_VECTOR"
    CVSS_ASSESSMENT_NOT_FOUND = "CVSS_ASSESSMENT_NOT_FOUND"
    DATE_RANGE_INVERTED = "DATE_RANGE_INVERTED"
    DATE_RANGE_TOO_WIDE = "DATE_RANGE_TOO_WIDE"
    FETCHER_NOT_FOUND = "FETCHER_NOT_FOUND"
    FETCHER_DEREGISTERED = "FETCHER_DEREGISTERED"
    FETCHER_DISABLED = "FETCHER_DISABLED"
    FETCHER_ALREADY_RUNNING = "FETCHER_ALREADY_RUNNING"
    FETCHER_SETTING_UNKNOWN = "FETCHER_SETTING_UNKNOWN"
    FETCHER_SETTING_INVALID = "FETCHER_SETTING_INVALID"
    CELERY_UNAVAILABLE = "CELERY_UNAVAILABLE"


_RESERVED_BODY_FIELDS: Final = frozenset({"code", "detail", "errors"})


class AppError(Exception):
    """Carries the standard `{"code": ..., "detail": ...}` error envelope.

    Raised by API-layer code to signal a domain error with a specific
    HTTP status code and `ErrorCode`. Translated to a `JSONResponse` by
    the `AppError` exception handler registered in `app.main` — API
    handlers never build the JSON envelope by hand. `headers`, when
    given, are attached to the response verbatim — used by
    `AUTH_ACCOUNT_LOCKED` to carry the `Retry-After` header (see
    `docs/features/identity/local-authentication.md`, Login Endpoint).
    `extra`, when given, holds additional top-level body fields that an
    owning error contract defines beside `code` and `detail` — only
    `existing_ticket_id` of `TICKET_CVE_CONFLICT` (`docs/api-spec.md`,
    Response Format). The envelope keys `code`, `detail`, and `errors`
    cannot be overridden.
    """

    def __init__(
        self,
        status_code: int,
        code: ErrorCode,
        detail: str,
        headers: dict[str, str] | None = None,
        extra: Mapping[str, str] | None = None,
    ) -> None:
        if extra is not None and not _RESERVED_BODY_FIELDS.isdisjoint(extra):
            raise ValueError("extra must not override the error envelope keys.")
        self.status_code = status_code
        self.code = code
        self.detail = detail
        self.headers = headers
        self.extra: Mapping[str, str] = dict(extra) if extra is not None else {}
        super().__init__(detail)
