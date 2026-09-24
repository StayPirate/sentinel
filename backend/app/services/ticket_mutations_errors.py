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
