"""Module-owned exceptions of the `ticket_mutations` service.

This leaf module defines the `TicketMutationsError` hierarchy so that the
pure CVSS module (`app.services.cvss`) can raise `InvalidCVSSVectorError`
without importing `ticket_mutations`, which will itself import
`app.services.cvss` and re-export these classes. See
`docs/features/tickets/ticket-mutations.md` (Service Exceptions) for the
authoritative hierarchy and HTTP mapping, and `docs/conventions.md`
(Service Exception Conventions, Base class requirement).

This module imports only Core and must never import another service.
"""

from __future__ import annotations

from app.core.exceptions import ServiceError


class TicketMutationsError(ServiceError):
    """Base class for all exceptions owned by the `ticket_mutations` module."""


class InvalidCVSSVectorError(TicketMutationsError):
    """A CVSS vector string violates the accepted Base-vector contract.

    Maps to `422 CVSS_INVALID_VECTOR`. The message is static and never
    includes the received vector, which is untrusted user or source input
    that must not reach log output or exception traces. See
    `docs/features/tickets/cvss-scoring.md` (Input Rules).
    """

    def __init__(self) -> None:
        super().__init__("Invalid CVSS vector.")


class CVSSAssessmentNotFoundError(TicketMutationsError):
    """No SUSE assessment can be addressed for the requested version.

    Raised for a version that is not an accepted CVSS version — an
    input-only check that precedes CVE resolution — and mapped by the API
    from a serialized `not_found` delete outcome. Maps to `404
    CVSS_ASSESSMENT_NOT_FOUND`. The message is static and never includes
    the received version. See `docs/features/tickets/ticket-mutations.md`
    (Service Exceptions) and `docs/features/tickets/cvss-scoring.md`
    (Delete SUSE CVSS Assessment).
    """

    def __init__(self) -> None:
        super().__init__("CVSS assessment not found.")
