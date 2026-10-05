"""Structural tests for the default-CVSS impact preview boundaries.

`get_default_cvss_version_impact()` performs no write, lock, Redis access,
publication, or post-commit registration, never calls
`reconcile_ticket_status()`, and has no side effect on an active
recalculation (docs/features/platform/default-cvss-version-operations.md,
Preview Service and Active Recalculation Run; tickets.md, Read-Only Gate
Projection; ticket-mutations.md, Read-Only Impact Projection). The
statement and spy assertions of
`tests/test_services/test_cvss_impact_preview.py` prove the behavior; this
import boundary keeps every mutation, coordination, and publication path
unreachable from the module, so a later direct import cannot bypass them.
"""

from __future__ import annotations

import pytest

from tests.support.module_imports import APP_ROOT, imported_modules

_PREVIEW = APP_ROOT / "services" / "cvss_impact_preview.py"

_FORBIDDEN = (
    "redis",
    "celery",
    "app.tasks",
    "app.celery_app",
    "app.services.task_publication",
    "app.services.ticket_mutations",
    "app.services.package_service",
    "app.services.ticket_service",
    "app.services.ticket_audit_log",
    "app.services.ticket_convergence_registry",
    "app.services.ticket_convergence_publication",
)


@pytest.mark.unit
class TestCVSSImpactPreviewDependencies:
    def test_imports_no_mutation_coordination_or_publication_module(self) -> None:
        modules = imported_modules(_PREVIEW, "app.services")

        assert {
            module
            for module in modules
            if any(
                module == forbidden or module.startswith(f"{forbidden}.")
                for forbidden in _FORBIDDEN
            )
        } == set()

    def test_reuses_the_shared_pure_resolutions_evaluator_and_gate(self) -> None:
        """The projection consumes the one owner of each formula instead of
        copying it (cvss-scoring.md, Read-Only Impact Projection;
        package-model.md, Axis 2: Eligibility; tickets.md, Read-Only Gate
        Projection)."""
        modules = imported_modules(_PREVIEW, "app.services")

        assert {
            "app.services.cvss",
            "app.services.product_eligibility",
            "app.services.ticket_gate_projection",
        } <= modules
