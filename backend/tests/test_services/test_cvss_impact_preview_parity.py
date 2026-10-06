"""Preview/execution parity tests for `get_default_cvss_version_impact()`
(backend/app/services/cvss_impact_preview.py).

Owning specifications:

- docs/features/platform/default-cvss-version-operations.md (Default-CVSS
  Impact Preview: Result and Count Units, Projected Impact).
- docs/features/tickets/ticket-mutations.md (`recalculate_cvss_chain()`
  default-version mode; CVSS Status Matrix, default-version paragraph).
- docs/features/tickets/cvss-scoring.md (Required Tests: Default-CVSS
  impact-projection parity).
- docs/features/platform/testing-strategy.md (Default-CVSS Impact Preview:
  the Regression "preview/execution parity" bullet and the Integration
  "unconverged gate-zone Tickets" bullet).

For one mixed persisted population, the preview runs first and must leave
every assessment and `CVE.severity` unmodified. Every CVE is then executed,
in `CVE.id` order, through `recalculate_cvss_chain()` in default-version
mode with the proposed version, inside a savepoint that is rolled back; the
preview's counts must equal the execution's per-CVE outcomes and the
resulting gate-zone status of every Ticket.

Expected counts are transcribed from the specifications, never computed
with the module under test; the execution aggregates are a second,
independent oracle, so a drift of both implementations together still
fails the hand-derived assertions.
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, time
from decimal import Decimal
from typing import Any, Literal

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import PackageStatus, Severity, TicketStatus
from app.models.cve import CVE
from app.models.cve_cvss_assessment import CVECVSSAssessment
from app.models.system_setting import SystemSetting
from app.models.ticket import Ticket
from app.models.ticket_package_product import TicketPackageProduct
from app.services import cvss_impact_preview
from app.services.cvss_impact_preview import (
    DefaultCVSSVersionImpact,
    get_default_cvss_version_impact,
)
from app.services.ticket_convergence_registry import (
    TicketConvergenceEffect,
    pending_ticket_convergence_effects,
)
from app.services.ticket_mutations import (
    CVSSChainClassification,
    CVSSChainMode,
    CVSSChainResult,
    recalculate_cvss_chain,
)
from tests.support.cvss_chain import Assessment, CVEBuilder
from tests.support.ticket_mutations import EVAL, Prod, TicketFactory, TreeBuilder

pytest_plugins = ["tests.support.ticket_mutation_fixtures"]
"""Provides the shared `cve_with` and `tree` fixtures."""

T7 = Decimal("7.0")
"""A catalog threshold met by 7.0 and above."""

NEW = TicketStatus.NEW
ANALYSIS = TicketStatus.ANALYSIS
ANALYZED = TicketStatus.ANALYZED
RESOLVED = TicketStatus.RESOLVED
IGNORED = TicketStatus.IGNORED
DUPLICATED = TicketStatus.DUPLICATED

AFFECTED = PackageStatus.AFFECTED
FIXED = PackageStatus.FIXED
NOT_AFFECTED = PackageStatus.NOT_AFFECTED


def suse31(score: str) -> Assessment:
    return Assessment(score)


def suse40(score: str) -> Assessment:
    return Assessment(score, version="4.0")


def nvd(score: str, version: str) -> Assessment:
    return Assessment(score, provider="NVD", version=version)


@pytest.fixture(autouse=True)
async def setting(
    system_setting_factory: Callable[..., Awaitable[SystemSetting]],
) -> SystemSetting:
    """The persisted `default_cvss_version` (the test schema has none)."""
    return await system_setting_factory(key="default_cvss_version", value="3.1")


@pytest.fixture(autouse=True)
def fixed_evaluation_date(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pin the preview's UTC `evaluation_date` to `EVAL`, the date every
    execution unit receives explicitly."""
    monkeypatch.setattr(
        cvss_impact_preview,
        "_utc_now",
        lambda: datetime.combine(EVAL, time(12, 0), tzinfo=UTC),
    )


# ---------------------------------------------------------------------------
# Population
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _Case:
    """One seeded Ticket and the status execution must leave it in."""

    ticket_id: uuid.UUID
    cve_id: uuid.UUID
    expected: TicketStatus


@dataclass(slots=True)
class _Population:
    """The seeded Tickets, by case name."""

    cases: dict[str, _Case] = field(default_factory=dict)

    def expected_statuses(self) -> dict[uuid.UUID, str]:
        return {case.ticket_id: case.expected.value for case in self.cases.values()}


class _Seeder:
    """Builds one CVE unit at a time through the shared factories."""

    def __init__(
        self,
        cve_with: CVEBuilder,
        ticket_factory: TicketFactory,
        tree: TreeBuilder,
    ) -> None:
        self.cve = cve_with
        self.tree = tree
        self._ticket_factory = ticket_factory
        self.population = _Population()

    async def ticket(
        self,
        name: str,
        cve: CVE,
        status: TicketStatus,
        *,
        expected: TicketStatus,
    ) -> Ticket:
        ticket = await self._ticket_factory(status=status.value, cve_id=cve.id)
        self.population.cases[name] = _Case(ticket.id, cve.id, expected)
        return ticket


async def _seed_forward(s: _Seeder) -> None:
    """The `3.1 → 4.0` population: 18 CVEs.

    Each unit's comment states its intended per-unit contribution as
    `S` (severity change), `E` (automatic eligibility changes), `K`
    (override skips), `R` (`Resolved` regression), derived from
    cvss-scoring.md (Severity Resolution Cascade, Unified CVE Severity,
    Eligibility Score Resolution), package-model.md (Axis 2: Eligibility
    rules 1-5; Derived Actionability), tickets.md (Gate: Analysis →
    Analyzed, Gate: Analyzed → Resolved), and the default-version matrix
    (`New` and the gate zone are evaluated; the gate zone reconciles only
    on a severity or Product change; `Ignored`/`Duplicated` receive
    severity only).
    """
    # --- Ticketless CVEs: severity only. ------------------------------------
    # U1: SUSE 4.0 = 9.0 wins under 4.0: Medium → Critical. S=1.
    await s.cve(suse31("5.0"), suse40("9.0"), severity=Severity.MEDIUM)
    # U2: SUSE 4.0 = 9.5 keeps Critical. S=0.
    await s.cve(suse31("9.8"), suse40("9.5"), severity=Severity.CRITICAL)
    # U3: empty set with a non-NULL persisted severity: High → NULL. S=1.
    await s.cve(severity=Severity.HIGH)
    # U4: empty set, already NULL. S=0.
    await s.cve(severity=None)
    # U5: cascade step 2 (SUSE at another version, 4.0) precedes step 3
    # (non-SUSE at the default version, 9.9): stays Medium. S=0.
    await s.cve(nvd("9.9", "4.0"), suse31("4.0"), severity=Severity.MEDIUM)

    # --- New: severity and eligibility, never reconciled. -------------------
    # U6: Medium → Critical, eligibility 9.0. S=1, E=4, K=1.
    cve = await s.cve(suse31("5.0"), suse40("9.0"), severity=Severity.MEDIUM)
    ticket = await s.ticket("new-mixed", cve, NEW, expected=NEW)
    await s.tree(
        ticket,
        status=AFFECTED,
        products=(
            Prod(eligible=False, threshold=T7),  # 9.0 >= 7.0: true, E
            Prod(eligible=True, threshold=Decimal("9.5")),  # 9.0 < 9.5: false, E
            Prod(eligible=True, threshold=None),  # NULL is 0.0: true, unchanged
            Prod(eligible=False, override=True, threshold=T7),  # K
            Prod(eligible=True, reactive=True),  # Reactive Support: false, E
        ),
    )
    # EOL is not a formula input: 9.0 >= 7.0 keeps true.
    await s.tree(
        ticket,
        status=NOT_AFFECTED,
        products=(Prod(eligible=True, eol=True, threshold=T7),),
    )
    # A package exclusion is not a formula input: false → true, E.
    await s.tree(
        ticket,
        package_excluded=True,
        products=(Prod(eligible=False, threshold=T7),),
    )
    # U18: no SUSE 4.0 assessment: severity stays High through cascade step
    # 2 (SUSE 3.1 = 7.5); eligibility falls back to 10.0, so the automatic
    # occurrence stays true. Only the override counts. K=1.
    cve = await s.cve(suse31("7.5"), nvd("9.9", "4.0"), severity=Severity.HIGH)
    ticket = await s.ticket("new-fallback", cve, NEW, expected=NEW)
    await s.tree(
        ticket,
        products=(
            Prod(eligible=True, threshold=T7),
            Prod(eligible=False, override=True, threshold=T7),
        ),
    )

    # --- Analysis. ----------------------------------------------------------
    # U7: High stays High (8.5); eligibility 8.5. Two changes make execution
    # reconcile, but the actionable ANALYSIS track keeps the Analysis floor.
    # S=0, E=2, K=1.
    cve = await s.cve(suse31("8.0"), suse40("8.5"), severity=Severity.HIGH)
    ticket = await s.ticket("analysis-stays", cve, ANALYSIS, expected=ANALYSIS)
    await s.tree(
        ticket,
        status=PackageStatus.ANALYSIS,
        products=(
            Prod(eligible=False, threshold=Decimal("8.0")),  # true, E
            Prod(eligible=True, override=True, threshold=Decimal("9.0")),  # K
            Prod(eligible=False, excluded=True, threshold=T7),  # true, E
        ),
    )
    # U8: stale NULL → High (SUSE 4.0 = 7.5); the reconciliation the
    # severity change triggers promotes the NOT_AFFECTED Ticket to Resolved
    # (a promotion, never a regression). S=1.
    cve = await s.cve(suse40("7.5"), severity=None)
    ticket = await s.ticket("analysis-promoted", cve, ANALYSIS, expected=RESOLVED)
    await s.tree(ticket, status=NOT_AFFECTED, products=(Prod(threshold=T7),))

    # --- Analyzed. ----------------------------------------------------------
    # U9 (P5 c): the predicates would yield Resolved (NOT_AFFECTED), but
    # neither severity (Critical) nor eligibility (9.5 >= 7.0) changes:
    # execution does not reconcile and the Ticket stays Analyzed.
    cve = await s.cve(suse31("9.8"), suse40("9.5"), severity=Severity.CRITICAL)
    ticket = await s.ticket("analyzed-unconverged", cve, ANALYZED, expected=ANALYZED)
    await s.tree(ticket, status=NOT_AFFECTED, products=(Prod(threshold=T7),))
    # U10 (P5 d): eligibility-only change. High stays High (8.8); the only
    # occurrence turns false (8.8 < 9.0), the AFFECTED track's actionable
    # eligible set empties (clause c), and the reconciliation promotes the
    # Ticket to Resolved. E=1.
    cve = await s.cve(suse31("8.0"), suse40("8.8"), severity=Severity.HIGH)
    ticket = await s.ticket("analyzed-eligibility", cve, ANALYZED, expected=RESOLVED)
    await s.tree(ticket, products=(Prod(eligible=True, threshold=Decimal("9.0")),))

    # --- Resolved. ----------------------------------------------------------
    # U11 (P5 a): gate already unmet (an AFFECTED track with an actionable
    # eligible occurrence), but High stays High (8.5) and the occurrence
    # stays true: execution does not reconcile; it stays Resolved. R=0.
    cve = await s.cve(suse31("8.0"), suse40("8.5"), severity=Severity.HIGH)
    ticket = await s.ticket("resolved-unmet-stays", cve, RESOLVED, expected=RESOLVED)
    await s.tree(ticket, products=(Prod(threshold=T7),))
    # U12 (P5 b): the same shape with High → Critical (9.5): execution
    # reconciles and the predicates yield Analyzed. A second, FIXED track
    # (released eligible and unreleased ineligible occurrences, both
    # unchanged: 9.5 >= 7.0 and 9.5 < 9.8) stays complete. S=1, R=1.
    cve = await s.cve(suse31("8.0"), suse40("9.5"), severity=Severity.HIGH)
    ticket = await s.ticket(
        "resolved-unmet-regresses", cve, RESOLVED, expected=ANALYZED
    )
    await s.tree(ticket, products=(Prod(threshold=T7),))
    await s.tree(
        ticket,
        status=FIXED,
        products=(
            Prod(eligible=True, released=True, threshold=T7),
            Prod(eligible=False, threshold=Decimal("9.8")),
        ),
    )
    # U13: Critical stays Critical (9.8); the unreleased FIXED occurrence
    # turns true (9.8 >= 9.0), so the FIXED track is no longer complete:
    # Analyzed. The override under a NOT_AFFECTED track is skipped.
    # E=1, K=1, R=1.
    cve = await s.cve(suse31("9.8"), suse40("9.8"), severity=Severity.CRITICAL)
    ticket = await s.ticket(
        "resolved-fixed-regresses", cve, RESOLVED, expected=ANALYZED
    )
    await s.tree(
        ticket,
        status=FIXED,
        products=(
            Prod(eligible=False, threshold=Decimal("9.0")),
            Prod(eligible=True, released=True, threshold=T7),
        ),
    )
    await s.tree(
        ticket,
        status=NOT_AFFECTED,
        products=(Prod(eligible=False, override=True, threshold=T7),),
    )
    # U14: empty set: High → NULL; the fallback 10.0 keeps the occurrence
    # true. A NULL severity fails the Analyzed predicate: Analysis.
    # S=1, R=1.
    cve = await s.cve(severity=Severity.HIGH)
    ticket = await s.ticket("resolved-to-analysis", cve, RESOLVED, expected=ANALYSIS)
    await s.tree(ticket, status=NOT_AFFECTED, products=(Prod(threshold=T7),))
    # U15: Medium → Critical (9.0) on a Resolved Ticket that stays
    # Resolved: the AFFECTED track's actionable occurrences are the
    # preserved `false` override (K) and the NULL-lifecycle occurrence
    # that turns false (9.0 < 9.5, E); the EOL occurrence turns true (E)
    # but is not actionable; the excluded track's occurrence turns true (E)
    # but the track is outside M and A. S=1, E=3, K=1, R=0.
    cve = await s.cve(suse31("5.0"), suse40("9.0"), severity=Severity.MEDIUM)
    ticket = await s.ticket("resolved-stays", cve, RESOLVED, expected=RESOLVED)
    await s.tree(
        ticket,
        products=(
            Prod(eligible=False, override=True, threshold=T7),
            Prod(eligible=False, eol=True, threshold=T7),
            Prod(eligible=True, lifecycle=False, threshold=Decimal("9.5")),
        ),
    )
    await s.tree(
        ticket, track_excluded=True, products=(Prod(eligible=False, threshold=T7),)
    )

    # --- Manual zone: severity only. -----------------------------------------
    # U16: Medium → Critical. S=1; the stale occurrence and the override
    # are not evaluated.
    cve = await s.cve(suse31("5.0"), suse40("9.0"), severity=Severity.MEDIUM)
    ticket = await s.ticket("ignored", cve, IGNORED, expected=IGNORED)
    await s.tree(
        ticket,
        products=(
            Prod(eligible=False, threshold=T7),
            Prod(eligible=False, override=True, threshold=T7),
        ),
    )
    # U17: Critical stays Critical; 9.8 < 9.9 would turn the occurrence
    # false, but it is not evaluated.
    cve = await s.cve(suse31("9.8"), suse40("9.8"), severity=Severity.CRITICAL)
    ticket = await s.ticket("duplicated", cve, DUPLICATED, expected=DUPLICATED)
    await s.tree(
        ticket,
        products=(
            Prod(eligible=True, threshold=Decimal("9.9")),
            Prod(eligible=True, override=True),
        ),
    )


# Hand-derived `3.1 → 4.0` totals of `_seed_forward()`:
#
# - cves_evaluated: U1-U18 = 18 (the CVE-less duplicate target of U17 is
#   not a CVE).
# - cve_severity_changes: U1, U3, U6, U8, U12, U14, U15, U16 = 8; the other
#   ten CVEs keep their severity.
# - product_eligibility_changes: U6 (4) + U7 (2) + U10 (1) + U13 (1) +
#   U15 (3) = 11; the manual-zone U16 and U17 contribute none.
# - product_eligibility_override_skips: U6, U7, U13, U15, U18 = 5; the
#   overrides of U16 and U17 are not applicable.
# - resolved_ticket_regressions: U12, U13, U14 = 3; U11 (no gate input
#   change) and U15 (gate still true) stay Resolved.
FORWARD = DefaultCVSSVersionImpact(
    observed_default_cvss_version="3.1",
    proposed_default_cvss_version="4.0",
    no_op=False,
    cves_evaluated=18,
    cve_severity_changes=8,
    product_eligibility_changes=11,
    product_eligibility_override_skips=5,
    resolved_ticket_regressions=3,
)


async def _seed_reverse(s: _Seeder) -> None:
    """The `4.0 → 3.1` population: 5 CVEs converged under `4.0`."""
    # V1: ticketless, Critical (SUSE 4.0 = 9.0) → Medium (SUSE 3.1 = 5.0).
    # S=1.
    await s.cve(suse31("5.0"), suse40("9.0"), severity=Severity.CRITICAL)
    # V2: Critical → Medium; eligibility 5.0. The unreleased FIXED
    # occurrence turns true (5.0 >= 4.0) and blocks resolution: Analyzed.
    # The override is skipped. S=1, E=1, K=1, R=1.
    cve = await s.cve(suse31("5.0"), suse40("9.0"), severity=Severity.CRITICAL)
    ticket = await s.ticket("resolved-regresses", cve, RESOLVED, expected=ANALYZED)
    await s.tree(
        ticket, status=FIXED, products=(Prod(eligible=False, threshold=Decimal("4.0")),)
    )
    await s.tree(
        ticket,
        status=NOT_AFFECTED,
        products=(Prod(eligible=True, override=True, threshold=T7),),
    )
    # V3: Critical → Medium; the AFFECTED occurrence turns false (5.0 <
    # 7.0), so the Ticket is promoted to Resolved. S=1, E=1.
    cve = await s.cve(suse31("5.0"), suse40("9.0"), severity=Severity.CRITICAL)
    ticket = await s.ticket("analyzed-promoted", cve, ANALYZED, expected=RESOLVED)
    await s.tree(ticket, products=(Prod(eligible=True, threshold=T7),))
    # V4 (P5 a): gate already unmet; High stays High (SUSE 3.1 = 8.0) and
    # the occurrence stays true (8.0 >= 7.0): stays Resolved. R=0.
    cve = await s.cve(suse31("8.0"), suse40("8.5"), severity=Severity.HIGH)
    ticket = await s.ticket("resolved-unmet-stays", cve, RESOLVED, expected=RESOLVED)
    await s.tree(ticket, products=(Prod(threshold=T7),))
    # V5: NVD-only: stale NULL → Medium (cascade step 3, 6.0); eligibility
    # falls back to 10.0, turning the occurrence true. S=1, E=1.
    cve = await s.cve(nvd("6.0", "3.1"), severity=None)
    ticket = await s.ticket("new-nvd-only", cve, NEW, expected=NEW)
    await s.tree(ticket, products=(Prod(eligible=False, threshold=Decimal("9.0")),))


# Hand-derived `4.0 → 3.1` totals of `_seed_reverse()`: 5 CVEs; severity
# changes V1, V2, V3, V5 = 4; eligibility changes V2, V3, V5 = 3; one skip
# (V2); one regression (V2).
REVERSE = DefaultCVSSVersionImpact(
    observed_default_cvss_version="4.0",
    proposed_default_cvss_version="3.1",
    no_op=False,
    cves_evaluated=5,
    cve_severity_changes=4,
    product_eligibility_changes=3,
    product_eligibility_override_skips=1,
    resolved_ticket_regressions=1,
)


# ---------------------------------------------------------------------------
# Persisted state and execution
# ---------------------------------------------------------------------------


async def _state(db: AsyncSession) -> dict[str, list[tuple[Any, ...]]]:
    """Every persisted value the preview reads and execution may write."""
    return {
        "assessments": [
            tuple(r)
            for r in await db.execute(
                select(
                    CVECVSSAssessment.id,
                    CVECVSSAssessment.provider_name,
                    CVECVSSAssessment.cvss_version,
                    CVECVSSAssessment.score,
                    CVECVSSAssessment.vector_string,
                    CVECVSSAssessment.severity,
                    CVECVSSAssessment.updated_at,
                ).order_by(CVECVSSAssessment.id)
            )
        ],
        "cves": [
            tuple(r)
            for r in await db.execute(select(CVE.id, CVE.severity).order_by(CVE.id))
        ],
        "tickets": [
            tuple(r)
            for r in await db.execute(
                select(Ticket.id, Ticket.status, Ticket.priority_auto).order_by(
                    Ticket.id
                )
            )
        ],
        "occurrences": [
            tuple(r)
            for r in await db.execute(
                select(
                    TicketPackageProduct.id,
                    TicketPackageProduct.eligible,
                    TicketPackageProduct.is_eligible_override,
                ).order_by(TicketPackageProduct.id)
            )
        ],
    }


async def _severities(db: AsyncSession) -> dict[uuid.UUID, str | None]:
    rows = await db.execute(select(CVE.id, CVE.severity))
    return {row.id: row.severity for row in rows}


async def _statuses(db: AsyncSession) -> dict[uuid.UUID, str]:
    """The status of every Ticket associated with a CVE."""
    rows = await db.execute(
        select(Ticket.id, Ticket.status).where(Ticket.cve_id.is_not(None))
    )
    return {row.id: row.status for row in rows}


async def _eligibility(db: AsyncSession) -> dict[uuid.UUID, bool]:
    rows = await db.execute(
        select(TicketPackageProduct.id, TicketPackageProduct.eligible)
    )
    return {row.id: row.eligible for row in rows}


@dataclass(frozen=True, slots=True)
class _Execution:
    """The per-CVE results and the persisted state after every unit."""

    results: dict[uuid.UUID, CVSSChainResult]
    severities: dict[uuid.UUID, str | None]
    statuses: dict[uuid.UUID, str]
    eligibility: dict[uuid.UUID, bool]
    effects: tuple[TicketConvergenceEffect, ...]


async def _execute_in_savepoint(
    db: AsyncSession, proposed: Literal["3.1", "4.0"]
) -> _Execution:
    """Run the default-version chain for every CVE, ordered by `CVE.id`,
    inside a savepoint that is always rolled back."""
    cve_ids = list((await db.execute(select(CVE.id).order_by(CVE.id))).scalars())
    savepoint = await db.begin_nested()
    try:
        results: dict[uuid.UUID, CVSSChainResult] = {}
        for cve_id in cve_ids:
            results[cve_id] = await recalculate_cvss_chain(
                db,
                cve_id=cve_id,
                mode=CVSSChainMode.DEFAULT_VERSION,
                default_cvss_version=proposed,
                evaluation_date=EVAL,
            )
        return _Execution(
            results=results,
            severities=await _severities(db),
            statuses=await _statuses(db),
            eligibility=await _eligibility(db),
            effects=pending_ticket_convergence_effects(db),
        )
    finally:
        await savepoint.rollback()


async def _assert_parity(
    db: AsyncSession,
    population: _Population,
    proposed: Literal["3.1", "4.0"],
    expected: DefaultCVSSVersionImpact,
) -> _Execution:
    """Preview, execute in a rolled-back savepoint, and compare."""
    before = await _state(db)
    severities_before = await _severities(db)
    statuses_before = await _statuses(db)
    eligibility_before = await _eligibility(db)
    assert pending_ticket_convergence_effects(db) == ()

    preview = await get_default_cvss_version_impact(db, proposed)

    # The preview modifies no assessment, `CVE.severity`, status, or
    # occurrence, and registers no convergence effect.
    assert await _state(db) == before
    assert pending_ticket_convergence_effects(db) == ()

    execution = await _execute_in_savepoint(db, proposed)

    # The savepoint rollback restored every persisted value.
    assert await _state(db) == before

    results = execution.results
    assert len(results) == len(severities_before)
    assert all(
        r.classification is not CVSSChainClassification.MISSING
        for r in results.values()
    )
    # `severity_changed` holds exactly when execution wrote a different
    # `CVE.severity`, and the written value is the resolved label.
    for cve_id, result in results.items():
        written = execution.severities[cve_id]
        assert result.severity_changed is (written != severities_before[cve_id])
        resolution = result.severity_resolution
        assert written == (resolution.label.value if resolution else None)
    # `products.changed` counts exactly the occurrences whose `eligible`
    # execution rewrote.
    rewritten = sum(
        execution.eligibility[occurrence] != eligible
        for occurrence, eligible in eligibility_before.items()
    )
    regressed = {
        ticket_id
        for ticket_id, status in statuses_before.items()
        if status == RESOLVED and execution.statuses[ticket_id] in {ANALYSIS, ANALYZED}
    }
    executed = DefaultCVSSVersionImpact(
        observed_default_cvss_version=expected.observed_default_cvss_version,
        proposed_default_cvss_version=proposed,
        no_op=False,
        cves_evaluated=len(results),
        cve_severity_changes=sum(r.severity_changed for r in results.values()),
        product_eligibility_changes=sum(r.products.changed for r in results.values()),
        product_eligibility_override_skips=sum(
            r.products.override_skipped for r in results.values()
        ),
        resolved_ticket_regressions=len(regressed),
    )
    assert rewritten == executed.product_eligibility_changes

    assert preview == executed
    assert preview == expected
    assert execution.statuses == population.expected_statuses()

    # Each regression registered its convergence effect inside the
    # savepoint. A savepoint boundary neither commits nor discards effects
    # (ticket_convergence_registry: only the root transaction decides), so
    # they remain pending here; the fixture's root rollback at teardown
    # discards them without publication, and nothing leaks into another
    # test.
    assert {effect.ticket_id for effect in execution.effects} == regressed
    assert set(pending_ticket_convergence_effects(db)) == set(execution.effects)
    return execution


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestPreviewExecutionParity:
    async def test_mixed_population_3_1_to_4_0(
        self,
        db_session: AsyncSession,
        cve_with: CVEBuilder,
        ticket_factory: TicketFactory,
        tree: TreeBuilder,
    ) -> None:
        """testing-strategy.md, Default-CVSS Impact Preview (Regression:
        preview/execution parity), including the unconverged gate-zone
        Tickets of Projected Impact."""
        seeder = _Seeder(cve_with, ticket_factory, tree)
        await _seed_forward(seeder)
        cases = seeder.population.cases

        execution = await _assert_parity(db_session, seeder.population, "4.0", FORWARD)

        def outcome(name: str) -> tuple[str, bool, bool]:
            """`(status, reconciled, registered a convergence effect)`."""
            case = cases[name]
            return (
                execution.statuses[case.ticket_id],
                execution.results[case.cve_id].reconciled,
                TicketConvergenceEffect(case.ticket_id) in execution.effects,
            )

        # (a) No gate input change: execution does not reconcile, so the
        # already-unmet gate stays Resolved and counts no regression.
        assert outcome("resolved-unmet-stays") == (RESOLVED, False, False)
        # (b) The same shape with a severity change reconciles and regresses.
        assert outcome("resolved-unmet-regresses") == (ANALYZED, True, True)
        # (c) Predicates that would yield Resolved do not promote an
        # Analyzed Ticket without a gate input change.
        assert outcome("analyzed-unconverged") == (ANALYZED, False, False)
        # (d) An eligibility-only change reconciles (here, a promotion).
        assert outcome("analyzed-eligibility") == (RESOLVED, True, False)

    async def test_reverse_direction_4_0_to_3_1(
        self,
        db_session: AsyncSession,
        setting: SystemSetting,
        cve_with: CVEBuilder,
        ticket_factory: TicketFactory,
        tree: TreeBuilder,
    ) -> None:
        setting.value = "4.0"
        await db_session.flush()
        seeder = _Seeder(cve_with, ticket_factory, tree)
        await _seed_reverse(seeder)

        execution = await _assert_parity(db_session, seeder.population, "3.1", REVERSE)

        unmet = seeder.population.cases["resolved-unmet-stays"]
        assert execution.statuses[unmet.ticket_id] == RESOLVED
        assert not execution.results[unmet.cve_id].reconciled
