"""Tests for the standard error envelope (backend/app/core/errors.py)."""

from __future__ import annotations

import pytest

from app.core.errors import AppError, ErrorCode


@pytest.mark.unit
class TestAppError:
    def test_carries_status_code_error_code_and_detail(self) -> None:
        error = AppError(
            status_code=400, code=ErrorCode.AUTH_LOGOUT_NOT_APPLICABLE, detail="nope"
        )
        assert error.status_code == 400
        assert error.code == ErrorCode.AUTH_LOGOUT_NOT_APPLICABLE
        assert error.detail == "nope"

    def test_is_an_exception(self) -> None:
        error = AppError(
            status_code=401, code=ErrorCode.AUTH_NOT_AUTHENTICATED, detail="nope"
        )
        assert isinstance(error, Exception)
        assert str(error) == "nope"

    def test_headers_default_to_none(self) -> None:
        error = AppError(
            status_code=401, code=ErrorCode.AUTH_INVALID_CREDENTIALS, detail="nope"
        )
        assert error.headers is None

    def test_carries_optional_headers(self) -> None:
        error = AppError(
            status_code=429,
            code=ErrorCode.AUTH_ACCOUNT_LOCKED,
            detail="locked",
            headers={"Retry-After": "60"},
        )
        assert error.headers == {"Retry-After": "60"}

    def test_extra_defaults_to_an_empty_mapping(self) -> None:
        error = AppError(status_code=404, code=ErrorCode.TICKET_NOT_FOUND, detail="x")
        assert error.extra == {}

    def test_carries_a_copy_of_the_extra_body_fields(self) -> None:
        """See docs/api-spec.md (Response Format): `existing_ticket_id` is
        the contract-defined top-level field of `TICKET_CVE_CONFLICT`."""
        extra = {"existing_ticket_id": "SNTL-42"}
        error = AppError(
            status_code=409,
            code=ErrorCode.TICKET_CVE_CONFLICT,
            detail="conflict",
            extra=extra,
        )
        extra["existing_ticket_id"] = "SNTL-7"
        extra["other"] = "value"

        assert error.extra == {"existing_ticket_id": "SNTL-42"}
        assert error.extra is not extra

    @pytest.mark.parametrize("key", ["code", "detail", "errors"])
    def test_extra_cannot_override_an_envelope_key(self, key: str) -> None:
        with pytest.raises(ValueError, match="envelope keys"):
            AppError(
                status_code=409,
                code=ErrorCode.TICKET_CVE_CONFLICT,
                detail="conflict",
                extra={"existing_ticket_id": "SNTL-42", key: "override"},
            )


@pytest.mark.unit
class TestErrorCode:
    def test_values_are_upper_snake_case_strings(self) -> None:
        for code in ErrorCode:
            assert code.value == code.value.upper()
            assert isinstance(code.value, str)

    def test_authorization_error_codes_are_registered(self) -> None:
        """See docs/features/identity/rbac.md (`require_capability()`
        Dependency) and authentication.md (Session-Only Authentication
        Dependency, API Endpoints)."""
        assert ErrorCode.AUTH_INSUFFICIENT_PERMISSION == "AUTH_INSUFFICIENT_PERMISSION"
        assert ErrorCode.AUTH_SESSION_REQUIRED == "AUTH_SESSION_REQUIRED"
        assert ErrorCode.USER_NOT_FOUND == "USER_NOT_FOUND"

    def test_api_key_management_error_codes_are_registered(self) -> None:
        """See docs/features/identity/api-key-service.md (Service
        Exceptions) and docs/features/identity/api-key-management.md
        (API, Error responses)."""
        assert ErrorCode.AUTH_API_KEY_NOT_FOUND == "AUTH_API_KEY_NOT_FOUND"
        assert ErrorCode.AUTH_API_KEY_NAME_CONFLICT == "AUTH_API_KEY_NAME_CONFLICT"
        assert ErrorCode.AUTH_API_KEY_NAME_INVALID == "AUTH_API_KEY_NAME_INVALID"
        assert ErrorCode.AUTH_API_KEY_INVALID_EXPIRY == "AUTH_API_KEY_INVALID_EXPIRY"
        assert ErrorCode.USER_INACTIVE == "USER_INACTIVE"

    def test_ticket_not_found_is_registered(self) -> None:
        """See docs/api-spec.md (Error Code Categories, Ticket
        Accessibility Check)."""
        assert ErrorCode.TICKET_NOT_FOUND == "TICKET_NOT_FOUND"

    def test_ticket_not_mutable_is_registered(self) -> None:
        """See docs/api-spec.md (Error Code Categories, Manual-Zone
        Mutability Guard) and docs/features/tickets/ticket-mutations.md
        (Service Exceptions)."""
        assert ErrorCode.TICKET_NOT_MUTABLE == "TICKET_NOT_MUTABLE"

    def test_ticket_severity_derived_is_registered(self) -> None:
        """See docs/api-spec.md (Error Code Categories) and
        docs/features/tickets/ticket-mutations.md (`set_severity_manual()`,
        Service Exceptions)."""
        assert ErrorCode.TICKET_SEVERITY_DERIVED == "TICKET_SEVERITY_DERIVED"

    def test_manual_zone_entry_error_codes_are_registered(self) -> None:
        """See docs/api-spec.md (Error Code Categories, `TICKET_*`) and
        docs/features/tickets/ticket-service.md (Service Exceptions:
        `InvalidTransitionError`, `SelfDuplicateError`,
        `DuplicateTargetIsDuplicatedError`,
        `DuplicateConcurrentModificationError`)."""
        assert ErrorCode.TICKET_INVALID_TRANSITION == "TICKET_INVALID_TRANSITION"
        assert ErrorCode.TICKET_SELF_DUPLICATE == "TICKET_SELF_DUPLICATE"
        assert (
            ErrorCode.TICKET_DUPLICATE_TARGET_DUPLICATED
            == "TICKET_DUPLICATE_TARGET_DUPLICATED"
        )
        assert (
            ErrorCode.TICKET_DUPLICATE_CONCURRENT_MODIFICATION
            == "TICKET_DUPLICATE_CONCURRENT_MODIFICATION"
        )

    def test_cve_not_found_is_registered(self) -> None:
        """See docs/api-spec.md (Error Code Categories, CVE Accessibility
        Check) and docs/features/tickets/cve-service.md (Exceptions)."""
        assert ErrorCode.CVE_NOT_FOUND == "CVE_NOT_FOUND"

    def test_cve_invalid_format_is_registered(self) -> None:
        """See docs/features/tickets/tickets.md (Create Ticket) and
        docs/features/tickets/cve-service.md (Caller Validation
        Responsibility, Exceptions)."""
        assert ErrorCode.CVE_INVALID_FORMAT == "CVE_INVALID_FORMAT"

    def test_ticket_cve_conflict_is_registered(self) -> None:
        """See docs/api-spec.md (Response Format, Anti-Enumeration
        Boundary) and docs/features/tickets/tickets.md (CVE Resolution
        Behavior, Create Ticket)."""
        assert ErrorCode.TICKET_CVE_CONFLICT == "TICKET_CVE_CONFLICT"

    def test_cvss_invalid_vector_is_registered(self) -> None:
        """See docs/api-spec.md (Error Code Categories) and
        docs/features/tickets/cvss-scoring.md (Input Rules)."""
        assert ErrorCode.CVSS_INVALID_VECTOR == "CVSS_INVALID_VECTOR"

    def test_cvss_assessment_not_found_is_registered(self) -> None:
        """See docs/api-spec.md (Error Code Categories),
        docs/features/tickets/ticket-mutations.md (Service Exceptions),
        and docs/features/tickets/cvss-scoring.md (Delete SUSE CVSS
        Assessment)."""
        assert ErrorCode.CVSS_ASSESSMENT_NOT_FOUND == "CVSS_ASSESSMENT_NOT_FOUND"

    def test_date_range_inverted_is_registered(self) -> None:
        """See docs/api-spec.md (Date Range Interpretation, Inverted
        range validation)."""
        assert ErrorCode.DATE_RANGE_INVERTED == "DATE_RANGE_INVERTED"

    def test_date_range_too_wide_is_registered(self) -> None:
        """See docs/api-spec.md (Date Range Interpretation, Maximum
        range constraint) and
        docs/features/platform/fetcher-operations.md (Get Fetcher Run
        Timeline Data, Date range constraint)."""
        assert ErrorCode.DATE_RANGE_TOO_WIDE == "DATE_RANGE_TOO_WIDE"

    def test_fetcher_not_found_is_registered(self) -> None:
        """See docs/features/platform/fetcher-operations.md (Fetcher
        Operations Service, Service Exceptions)."""
        assert ErrorCode.FETCHER_NOT_FOUND == "FETCHER_NOT_FOUND"

    def test_fetcher_disabled_is_registered(self) -> None:
        """See docs/features/platform/fetcher-operations.md (Fetcher
        Operations Service, Service Exceptions; Trigger Fetcher)."""
        assert ErrorCode.FETCHER_DISABLED == "FETCHER_DISABLED"

    def test_celery_unavailable_is_registered(self) -> None:
        """See docs/features/platform/fetcher-operations.md (Fetcher
        Operations Service, Service Exceptions; Trigger Fetcher) and
        docs/api-spec.md (Error Code Categories,
        `<DEPENDENCY>_UNAVAILABLE`)."""
        assert ErrorCode.CELERY_UNAVAILABLE == "CELERY_UNAVAILABLE"

    def test_admin_user_mutation_error_codes_are_registered(self) -> None:
        """See docs/features/identity/user-service.md (Service
        Exceptions) and docs/features/identity/user-management.md
        (Admin API endpoints, Error responses)."""
        assert ErrorCode.USER_ALREADY_EXISTS == "USER_ALREADY_EXISTS"
        assert (
            ErrorCode.USER_EXTERNAL_STATUS_READONLY == "USER_EXTERNAL_STATUS_READONLY"
        )
        assert ErrorCode.USER_EXTERNAL_FIELD_READONLY == "USER_EXTERNAL_FIELD_READONLY"
        assert (
            ErrorCode.USER_EXTERNAL_PASSWORD_FORBIDDEN
            == "USER_EXTERNAL_PASSWORD_FORBIDDEN"
        )
        assert (
            ErrorCode.USER_PASSWORD_POLICY_VIOLATION == "USER_PASSWORD_POLICY_VIOLATION"
        )
