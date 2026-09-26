"""Shared application exception hierarchy.

`ServiceError` is the common root for all exceptions raised by
service-layer modules and propagated to API handlers. Per
`docs/conventions.md` (Service Exception Conventions), every module's
own base class (e.g., `TicketServiceError`, `UserServiceError`)
inherits from `ServiceError`, and exceptions shared across multiple
modules inherit from `ServiceError` directly.
"""

from __future__ import annotations


class ServiceError(Exception):
    """Root exception for all service-layer errors."""


class TLSConfigurationError(ServiceError):
    """Raised when the configured SUSE CA certificate is unusable.

    This signals a configuration error (corrupt or unparseable
    certificate file) — not a transient condition. Retrying without
    fixing the file is pointless. See
    `docs/features/platform/networking.md` (TLS Trust Store
    Configuration).
    """

    def __init__(self, path: str, detail: str) -> None:
        self.path = path
        self.detail = detail
        super().__init__(f"Failed to load SUSE CA certificate from '{path}': {detail}")


class UserNotFoundError(ServiceError):
    """A required user identifier does not resolve to any `User` row.

    Shared across service modules (`user_service`, `api_key_service`,
    `ticket_service`) per `docs/conventions.md` (Service Exception
    Conventions, Shared exceptions) — inherits from `ServiceError`
    directly, not from any individual module's base class. The message
    is static and never includes the identifier value, to avoid
    leaking usernames or UUIDs into log output or exception traces
    that may be captured without the same care applied to structured
    log fields.
    """

    def __init__(self) -> None:
        super().__init__("User not found.")


class TicketNotFoundError(ServiceError):
    """A consumer Ticket locator does not resolve to an accessible Ticket.

    Shared across service modules (`ticket_service`, `ticket_mutations`,
    `package_service`, and the Ticket audit read) per
    `docs/conventions.md` (Service Exception Conventions, Shared
    exceptions) — inherits from `ServiceError` directly. A malformed
    locator, a Ticket UUID supplied as a locator, a missing Ticket, and
    a Ticket inaccessible to the caller all raise this same exception,
    so the API maps every cause to one identical `404 TICKET_NOT_FOUND`
    response (`docs/api-spec.md`, Ticket Accessibility Check). The
    message is static and never includes the locator value or the
    denial cause.
    """

    def __init__(self) -> None:
        super().__init__("Ticket not found.")


class InactiveUserError(ServiceError):
    """A user identified by a required owner/target parameter is inactive.

    Shared across service modules (`user_service`, `api_key_service`,
    `ticket_service`) per `docs/conventions.md` (Service Exception
    Conventions, Shared exceptions) — inherits from `ServiceError`
    directly. The message is static and never includes the identifier
    value.
    """

    def __init__(self) -> None:
        super().__init__("User is inactive.")
