"""Tests for shared service exceptions (backend/app/core/exceptions.py).

Owning specifications: docs/features/tickets/ticket-mutations.md (Service
Exceptions: shared exceptions inherit from `ServiceError`, not from
`TicketMutationsError`) and docs/conventions.md (Service Exception
Conventions, Shared exceptions).
"""

from __future__ import annotations

import pytest

from app.core.exceptions import CVENotFoundError, ServiceError, SeverityDerivedError
from app.services.ticket_mutations import TicketMutationsError


@pytest.mark.unit
class TestSeverityDerivedError:
    def test_is_a_direct_shared_service_error(self) -> None:
        assert SeverityDerivedError.__bases__ == (ServiceError,)
        assert not issubclass(SeverityDerivedError, TicketMutationsError)

    def test_message_is_static(self) -> None:
        assert (
            str(SeverityDerivedError())
            == "Ticket severity is derived from CVSS assessments."
        )

    def test_takes_no_arguments(self) -> None:
        with pytest.raises(TypeError):
            SeverityDerivedError("dynamic detail")  # type: ignore[call-arg]


@pytest.mark.unit
class TestCVENotFoundError:
    """docs/features/tickets/cve-service.md (Exceptions): shared, a direct
    `ServiceError` subclass, and one static message for every cause."""

    def test_is_a_direct_shared_service_error(self) -> None:
        assert CVENotFoundError.__bases__ == (ServiceError,)

    def test_message_is_static(self) -> None:
        assert str(CVENotFoundError()) == "CVE not found."

    def test_takes_no_arguments(self) -> None:
        with pytest.raises(TypeError):
            CVENotFoundError("CVE-2099-0001")  # type: ignore[call-arg]
