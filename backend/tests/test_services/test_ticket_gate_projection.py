"""Tests for the pure Ticket gate projection and its SQL parity.

Covers `project_gate_status()` (backend/app/services/ticket_gate_projection.py)
against `ticket_mutations.gate_status_expression()`.

Owning specifications:

- docs/features/tickets/tickets.md (Gate: Analysis → Analyzed; Gate:
  Analyzed → Resolved; Deterministic Gate Edge Cases; Read-Only Gate
  Projection: the projection reuses the exact same predicates, sets, and
  clause semantics).
- docs/features/packages/package-model.md (Derived Actionability; Gate
  Participation).
- docs/features/platform/testing-strategy.md (Service Functions: Analyzed
  and Resolved formulas over empty sets, all-EOL trees, missing
  Products/lifecycle data, independently excluded descendants, eligibility
  overrides, CVE-less `FIXED`).

The curated cases of `tests/support/gate_matrix.py` carry expectations
transcribed from the specifications; the grid compares the two
implementations over the same persisted rows.
"""

from __future__ import annotations

import inspect
import uuid
from collections.abc import Awaitable, Callable
from decimal import Decimal

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import LifecyclePhase, Severity, TicketStatus
from app.models.cve import CVE
from app.models.cve_cvss_assessment import CVECVSSAssessment
from app.models.ticket import Ticket
from app.services import ticket_gate_projection
from app.services.ticket_gate_projection import project_gate_status
from app.services.ticket_mutations import gate_status_expression
from tests.support.gate_matrix import (
    GATE_CASES,
    SUPPORTED_PHASES,
    GateCase,
    MatrixProduct,
    gate_grid,
    pure_inputs,
)
from tests.support.module_imports import APP_ROOT, forbidden_imports, imported_modules
from tests.support.ticket_mutations import EVAL, Prod, TicketFactory, TreeBuilder

pytest_plugins = ["tests.support.ticket_mutation_fixtures"]
"""Provides the shared `tree` fixture."""

CVEFactory = Callable[..., Awaitable[CVE]]
AssessmentFactory = Callable[..., Awaitable[CVECVSSAssessment]]
Builder = Callable[[GateCase], Awaitable[uuid.UUID]]

_CASES = pytest.mark.parametrize(
    "case", [pytest.param(case, id=case.name) for case in GATE_CASES]
)


def _project(case: GateCase) -> TicketStatus:
    return project_gate_status(
        tracks=pure_inputs(case),
        has_cve=case.has_cve,
        severity_resolved=case.severity_resolved,
        has_canonical_suse_assessment=case.has_suse,
    )


def _prod(product: MatrixProduct) -> Prod:
    """The tree-builder spec whose catalog Product has `product.phase` on
    `EVAL`."""
    assert product.phase in SUPPORTED_PHASES
    return Prod(
        eligible=product.eligible,
        override=product.override,
        eol=product.phase is LifecyclePhase.EOL,
        lifecycle=product.phase is not None,
        excluded=product.excluded,
        released=product.released,
        reactive=product.phase is LifecyclePhase.REACTIVE_SUPPORT,
    )


@pytest.fixture
def build(
    ticket_factory: TicketFactory,
    cve_factory: CVEFactory,
    cve_cvss_assessment_factory: AssessmentFactory,
    tree: TreeBuilder,
) -> Builder:
    """Persist one gate-zone Ticket with the case's inputs; return its id."""

    async def _build(case: GateCase) -> uuid.UUID:
        severity = Severity.HIGH.value if case.severity_resolved else None
        if case.has_cve:
            cve = await cve_factory(severity=severity)
            await cve_cvss_assessment_factory(
                cve_id=cve.id,
                provider_name="SUSE" if case.has_suse else "Example Provider",
                cvss_version="3.1",
                score=Decimal("7.5"),
            )
            ticket = await ticket_factory(
                status=TicketStatus.ANALYSIS.value, cve_id=cve.id
            )
        else:
            ticket = await ticket_factory(
                status=TicketStatus.ANALYSIS.value, severity_manual=severity
            )
        for track in case.tracks:
            await tree(
                ticket,
                status=track.status,
                products=tuple(_prod(product) for product in track.products),
                package_excluded=track.package_excluded,
                track_excluded=track.track_excluded,
            )
        return ticket.id

    return _build


async def _sql_status(
    db: AsyncSession, ticket_ids: list[uuid.UUID]
) -> dict[uuid.UUID, TicketStatus]:
    rows = await db.execute(
        select(Ticket.id, gate_status_expression(EVAL)).where(Ticket.id.in_(ticket_ids))
    )
    return {ticket_id: TicketStatus(status) for ticket_id, status in rows}


class TestCuratedCases:
    @pytest.mark.unit
    @_CASES
    def test_pure_projection_matches_specification(self, case: GateCase) -> None:
        assert _project(case) is case.expected

    @_CASES
    async def test_sql_gate_matches_specification_and_projection(
        self, db_session: AsyncSession, build: Builder, case: GateCase
    ) -> None:
        ticket_id = await build(case)

        sql = (await _sql_status(db_session, [ticket_id]))[ticket_id]

        assert sql is case.expected
        assert sql is _project(case)


class TestGridParity:
    async def test_projection_equals_sql_gate_for_every_grid_tree(
        self, db_session: AsyncSession, build: Builder
    ) -> None:
        cases = list(gate_grid())
        ids = [await build(case) for case in cases]

        sql = await _sql_status(db_session, ids)

        mismatches = [
            (case.name, sql[ticket_id], _project(case))
            for case, ticket_id in zip(cases, ids, strict=True)
            if sql[ticket_id] is not _project(case)
        ]
        assert mismatches == []
        # The grid exercises every gate result, not only the floor.
        assert set(sql.values()) == {
            TicketStatus.ANALYSIS,
            TicketStatus.ANALYZED,
            TicketStatus.RESOLVED,
        }


@pytest.mark.unit
class TestModuleBoundary:
    def test_imports_only_core_enums_and_pure_actionability(self) -> None:
        modules = imported_modules(
            APP_ROOT / "services" / "ticket_gate_projection.py", "app.services"
        )

        assert {m for m in modules if m.startswith("app.")} == {
            "app.core.enums",
            "app.services.package_actionability",
        }
        assert forbidden_imports(modules) == set()

    def test_public_function_is_synchronous(self) -> None:
        assert not inspect.iscoroutinefunction(
            ticket_gate_projection.project_gate_status
        )
