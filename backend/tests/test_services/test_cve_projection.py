"""Module-boundary and row-assembly tests for `app/services/cve_projection.py`.

Owning specifications: docs/features/tickets/cve-service.md (Service Read
Contracts > CVE Detail; Relationship with other modules) and
docs/features/tickets/tickets.md (Shared Sub-Schemas: `CVEDetail`). The
shared `CVEDetail` projection is a leaf module that imports only Models
and Core, so `cve_service` (CVE detail) and `ticket_service`
(`TicketDetail.cve`) share it without the CVE detail depending on
`ticket_service`. Projection content, ordering, and the equality of both
reads are covered in tests/test_services/test_cve_reads.py.
"""

from __future__ import annotations

import inspect
import uuid
from types import SimpleNamespace
from typing import Any, cast

import pytest
from sqlalchemy.engine import Row

from app.core.enums import CveState, Severity
from app.services import cve_projection
from app.services.cve_projection import CVEDetailProjection, cve_detail_from_row
from tests.support.module_imports import APP_ROOT, imported_modules

_SERVICES = APP_ROOT / "services"


def _app_imports(module: str) -> set[str]:
    modules = imported_modules(_SERVICES / f"{module}.py", "app.services")
    return {m for m in modules if m == "app" or m.startswith("app.")}


def _row(**values: Any) -> Row[Any]:
    """A stand-in for a result row: `cve_detail_from_row()` reads only
    attributes, so a namespace exercises the pure assembly without I/O."""
    return cast("Row[Any]", SimpleNamespace(**values))


@pytest.mark.unit
class TestModuleBoundary:
    def test_projection_imports_only_models_and_core(self) -> None:
        imports = _app_imports("cve_projection")

        assert imports
        assert {
            m for m in imports if not m.startswith(("app.models.", "app.core."))
        } == set()

    def test_cve_detail_projection_comes_from_the_leaf_module(self) -> None:
        """The CVE detail takes its projection from `cve_projection`, not
        from `ticket_service` (which `cve_service` imports only for the
        ingestion composition, cve-service.md, Relationship with other
        modules)."""
        imports = _app_imports("cve_service")

        assert "app.services.cve_projection" in imports
        assert "CVEDetailProjection" in cve_projection.__dict__

    def test_both_detail_reads_share_the_projection_module(self) -> None:
        assert "app.services.cve_projection" in _app_imports("ticket_service")

    def test_builders_and_assembly_are_synchronous(self) -> None:
        for function in (
            cve_projection.cve_detail_columns,
            cve_projection.join_cve_evidence,
            cve_projection.cve_detail_from_row,
        ):
            assert not inspect.iscoroutinefunction(function), function.__name__


@pytest.mark.unit
class TestRowAssembly:
    def test_row_without_a_cve_assembles_to_none(self) -> None:
        assert cve_detail_from_row(_row(cve_pk=None)) is None

    def test_row_with_a_cve_and_no_evidence(self) -> None:
        row = _row(
            cve_pk=uuid.uuid4(),
            cve_id="CVE-2099-90001",
            cve_title=None,
            cve_description="Fictional description",
            cve_published_date=None,
            cve_modified_date=None,
            cve_state=CveState.REJECTED.value,
            cve_date_rejected=None,
            cve_severity=Severity.NONE.value,
            cve_external_identifiers=[],
            kev_pk=None,
            epss_pk=None,
            ssvc_pk=None,
            cve_cwe_assignments=[["CWE-79", "NVD"], ["CWE-79", "NVD"]],
        )

        projection = cve_detail_from_row(row)

        assert projection == CVEDetailProjection(
            cve_id="CVE-2099-90001",
            title=None,
            description="Fictional description",
            published_date=None,
            modified_date=None,
            cve_state=CveState.REJECTED,
            date_rejected=None,
            severity=Severity.NONE,
            external_identifiers=(),
            kev=None,
            epss=None,
            ssvc=None,
            cwes=(cve_projection.CVEWeaknessProjection("CWE-79", ("NVD",)),),
        )
