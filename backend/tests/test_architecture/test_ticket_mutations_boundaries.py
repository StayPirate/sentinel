"""Structural tests for the Ticket mutation primitive boundaries.

- `ticket_mutations` never imports `package_service` or `ticket_service`;
  both import it (docs/features/tickets/ticket-mutations.md, Relationship
  with other modules).
- The transaction-local convergence registry is a leaf reachable by every
  later transaction owner and performs no broker, Redis, or network I/O
  (ticket-mutations.md, Transaction-Local Ticket Convergence Registration;
  docs/features/tickets/ticket-service.md, Initial publication boundary).
"""

from __future__ import annotations

import pytest

from tests.support.module_imports import APP_ROOT, imported_modules

_SERVICES = APP_ROOT / "services"


@pytest.mark.unit
class TestTicketMutationsDependencies:
    def test_imports_neither_package_service_nor_ticket_service(self) -> None:
        modules = imported_modules(_SERVICES / "ticket_mutations.py", "app.services")

        forbidden = {"app.services.package_service", "app.services.ticket_service"}
        assert modules & forbidden == set()


@pytest.mark.unit
class TestConvergenceRegistryIsALeaf:
    def test_imports_only_the_standard_library_and_sqlalchemy(self) -> None:
        modules = imported_modules(
            _SERVICES / "ticket_convergence_registry.py", "app.services"
        )

        allowed_roots = {"__future__", "dataclasses", "typing", "uuid", "sqlalchemy"}
        assert {m.split(".")[0] for m in modules} <= allowed_roots
