"""Service tests for `get_default_cvss_version_impact()`
(backend/app/services/cvss_impact_preview.py).

Owning specifications:

- docs/features/platform/default-cvss-version-operations.md (Default-CVSS
  Impact Preview: Preview Service, Result and Count Units, No-op Proposal,
  Projected Impact, Consistency and Staleness, Timeout and Partial Results,
  Preview Service Exception).
- docs/features/tickets/cvss-scoring.md (Severity Resolution Cascade,
  Eligibility Score Resolution, Read-Only Impact Projection).
- docs/features/packages/package-model.md (Axis 2: Eligibility, rules 1-5
  and Read-only projection; Derived Actionability).
- docs/features/tickets/ticket-mutations.md (CVSS Status Matrix, the
  default-version paragraph; `recalculate_cvss_chain()` default-version
  mode; Read-Only Impact Projection).
- docs/features/tickets/tickets.md (Gate: Analysis → Analyzed, Gate:
  Analyzed → Resolved, Read-Only Gate Projection).
- docs/features/platform/testing-strategy.md (Default-CVSS Impact
  Preview: Unit, Integration, and Regression tests).

Preview/execution parity is in test_cvss_impact_preview_parity.py; the
deadline, the per-page observation model, and the population boundary are
in test_cvss_impact_preview_observation.py; the HTTP contract is in
tests/test_api/test_settings_impact_preview.py.

Expected counts are transcribed from the specifications, never computed
with the module under test.
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable
from datetime import UTC, date, datetime, time, timedelta
from decimal import Decimal
from typing import Any

import pytest
from celery import Celery, Task
from redis.asyncio import Redis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import PackageStatus, Severity, TicketStatus
from app.models.cve import CVE
from app.models.product import Product
from app.models.system_setting import SystemSetting
from app.models.ticket import Ticket
from app.models.ticket_audit_event import TicketAuditEvent
from app.models.ticket_package import TicketPackage
from app.models.ticket_package_product import TicketPackageProduct
from app.models.ticket_package_track import TicketPackageTrack
from app.services import cvss_impact_preview, settings
from app.services.cvss_impact_preview import (
    DefaultCVSSVersionImpact,
    get_default_cvss_version_impact,
)
from app.services.ticket_convergence_registry import (
    pending_ticket_convergence_effects,
)
from tests.support.cvss_chain import Assessment, CVEBuilder
from tests.support.ticket_mutations import (
    EVAL,
    Prod,
    StatementRecorder,
    TicketFactory,
    TreeBuilder,
)

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

ProductFactory = Callable[..., Awaitable[Product]]
OccurrenceFactory = Callable[..., Awaitable[TicketPackageProduct]]


@pytest.fixture(autouse=True)
async def setting(
    system_setting_factory: Callable[..., Awaitable[SystemSetting]],
) -> SystemSetting:
    """The persisted `default_cvss_version` (the test schema has none)."""
    return await system_setting_factory(key="default_cvss_version", value="3.1")


@pytest.fixture(autouse=True)
def fixed_evaluation_date(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pin the invocation's UTC `evaluation_date` to `EVAL`."""
    monkeypatch.setattr(
        cvss_impact_preview,
        "_utc_now",
        lambda: datetime.combine(EVAL, time(12, 0), tzinfo=UTC),
    )


def impact(**counts: int) -> DefaultCVSSVersionImpact:
    """The expected `3.1 → 4.0` result; omitted counts are `0`."""
    values = {
        "cves_evaluated": 0,
        "cve_severity_changes": 0,
        "product_eligibility_changes": 0,
        "product_eligibility_override_skips": 0,
        "resolved_ticket_regressions": 0,
    }
    values.update(counts)
    return DefaultCVSSVersionImpact(
        observed_default_cvss_version="3.1",
        proposed_default_cvss_version="4.0",
        no_op=False,
        **values,
    )


async def preview(db: AsyncSession) -> DefaultCVSSVersionImpact:
    return await get_default_cvss_version_impact(db, "4.0")


class Spy:
    """Records the calls of one module-level name of the preview module."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch, name: str) -> None:
        self.calls: list[tuple[tuple[Any, ...], dict[str, Any]]] = []
        original = getattr(cvss_impact_preview, name)

        def _spy(*args: Any, **kwargs: Any) -> Any:
            self.calls.append((args, kwargs))
            return original(*args, **kwargs)

        monkeypatch.setattr(cvss_impact_preview, name, _spy)


def _assessment_set(
    call: tuple[tuple[Any, ...], dict[str, Any]],
) -> set[tuple[str, str, Decimal]]:
    assessments, _version = call[0]
    return {(a.provider_name, a.cvss_version, a.score) for a in assessments}


async def _ticket(
    ticket_factory: TicketFactory, cve: CVE, status: TicketStatus
) -> Ticket:
    return await ticket_factory(status=status.value, cve_id=cve.id)


async def _regressing(
    cve_with: CVEBuilder,
    ticket_factory: TicketFactory,
    tree: TreeBuilder,
    status: TicketStatus = RESOLVED,
) -> Ticket:
    """A Ticket converged under `3.1` whose projection under `4.0` changes
    severity, one automatic eligibility, and the gate.

    SUSE `3.1` = 5.0 (`Medium`, persisted) and SUSE `4.0` = 9.0
    (`Critical`). One `AFFECTED` track with catalog threshold 7.0 holds an
    automatic occurrence (persisted `false`, projected `true`) and an
    overridden one (preserved `false`, one skip). Under `3.1` the actionable
    eligible set is empty, so the track is resolution-complete by clause
    (c) and the Ticket is `Resolved`; under `4.0` it is not, so the
    projected gate is `Analyzed`.
    """
    cve = await cve_with(
        Assessment("5.0"), Assessment("9.0", version="4.0"), severity=Severity.MEDIUM
    )
    ticket = await _ticket(ticket_factory, cve, status)
    await tree(
        ticket,
        status=PackageStatus.AFFECTED,
        products=(
            Prod(eligible=False, threshold=T7),
            Prod(eligible=False, override=True, threshold=T7),
        ),
    )
    return ticket


# ---------------------------------------------------------------------------
# Severity projection
# ---------------------------------------------------------------------------


class TestSeverityProjection:
    async def test_proposed_version_and_complete_set_reach_both_resolutions(
        self,
        db_session: AsyncSession,
        cve_with: CVEBuilder,
        ticket_factory: TicketFactory,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """cvss-scoring.md, Read-Only Impact Projection: the proposed
        version, not the observed `3.1`, is passed explicitly, with the
        complete unfiltered set. Under `4.0` the cascade selects the
        canonical SUSE `4.0` assessment (4.0, `Medium`), not the higher
        non-SUSE `4.0` score nor the persisted SUSE `3.1` result."""
        severity_spy = Spy(monkeypatch, "resolve_severity_score")
        eligibility_spy = Spy(monkeypatch, "resolve_eligibility_score")
        cve = await cve_with(
            Assessment("9.8"),
            Assessment("4.0", version="4.0"),
            Assessment("9.9", provider="NVD", version="4.0"),
            severity=Severity.CRITICAL,
        )
        await _ticket(ticket_factory, cve, NEW)

        assert await preview(db_session) == impact(
            cves_evaluated=1, cve_severity_changes=1
        )

        expected_set = {
            ("SUSE", "3.1", Decimal("9.8")),
            ("SUSE", "4.0", Decimal("4.0")),
            ("NVD", "4.0", Decimal("9.9")),
        }
        for spy in (severity_spy, eligibility_spy):
            assert [call[0][1] for call in spy.calls] == ["4.0"]
            assert _assessment_set(spy.calls[0]) == expected_set

    async def test_observed_setting_is_read_once_per_invocation(
        self,
        db_session: AsyncSession,
        cve_with: CVEBuilder,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """default-cvss-version-operations.md, Projected Impact: the
        setting is not read again per unit or page."""
        monkeypatch.setattr(cvss_impact_preview, "_PAGE_SIZE", 1)
        reads = Spy(monkeypatch, "get_default_cvss_version")
        for _ in range(3):
            await cve_with(Assessment("9.8"), severity=Severity.CRITICAL)

        assert await preview(db_session) == impact(cves_evaluated=3)
        assert len(reads.calls) == 1

    async def test_an_empty_set_projects_an_unresolved_severity(
        self, db_session: AsyncSession, cve_with: CVEBuilder
    ) -> None:
        await cve_with(severity=Severity.HIGH)
        await cve_with(severity=None)

        assert await preview(db_session) == impact(
            cves_evaluated=2, cve_severity_changes=1
        )


# ---------------------------------------------------------------------------
# Eligibility projection
# ---------------------------------------------------------------------------


class TestEligibilityProjection:
    @pytest.mark.parametrize(
        ("assessments", "persisted_severity", "severity_changes", "persisted"),
        [
            pytest.param(
                (Assessment("9.0"), Assessment("5.0", version="4.0")),
                Severity.CRITICAL,
                1,
                True,
                id="suse-at-proposed-version-5.0-below-threshold",
            ),
            pytest.param(
                (Assessment("5.0"), Assessment("2.0", provider="NVD", version="4.0")),
                Severity.MEDIUM,
                0,
                False,
                id="fallback-10.0-without-suse-at-proposed-version",
            ),
        ],
    )
    async def test_suse_at_proposed_version_or_fallback(
        self,
        db_session: AsyncSession,
        cve_with: CVEBuilder,
        ticket_factory: TicketFactory,
        tree: TreeBuilder,
        assessments: tuple[Assessment, ...],
        persisted_severity: Severity,
        severity_changes: int,
        persisted: bool,
    ) -> None:
        """Only the canonical SUSE assessment at the proposed version feeds
        eligibility, otherwise `10.0`. In the fallback case the severity
        winner stays SUSE `3.1` (5.0, `Medium`, a SUSE assessment at another
        version precedes a non-SUSE one at the default version) and is not
        the eligibility score, and the non-SUSE 2.0 feeds neither: severity
        and eligibility stay separate."""
        cve = await cve_with(*assessments, severity=persisted_severity)
        ticket = await _ticket(ticket_factory, cve, NEW)
        await tree(ticket, products=(Prod(eligible=persisted, threshold=T7),))

        assert await preview(db_session) == impact(
            cves_evaluated=1,
            cve_severity_changes=severity_changes,
            product_eligibility_changes=1,
        )

    @pytest.mark.parametrize(
        ("score", "severity", "product"),
        [
            pytest.param(
                "9.8",
                Severity.CRITICAL,
                Prod(eligible=True, reactive=True),
                id="reactive-support-forces-false",
            ),
            pytest.param(
                "0.0",
                Severity.NONE,
                Prod(eligible=False, threshold=None),
                id="null-threshold-is-0.0",
            ),
            pytest.param(
                "9.0",
                Severity.CRITICAL,
                Prod(eligible=False, lifecycle=False, threshold=T7),
                id="null-lifecycle-activates-no-override",
            ),
        ],
    )
    async def test_package_model_rules(
        self,
        db_session: AsyncSession,
        cve_with: CVEBuilder,
        ticket_factory: TicketFactory,
        tree: TreeBuilder,
        score: str,
        severity: Severity,
        product: Prod,
    ) -> None:
        """package-model.md, Axis 2: Eligibility, rules 2 and 3 and the
        `NULL`-lifecycle rule; each case flips the persisted boolean, and
        the persisted severity is already converged."""
        cve = await cve_with(
            Assessment(score), Assessment(score, version="4.0"), severity=severity
        )
        ticket = await _ticket(ticket_factory, cve, NEW)
        await tree(ticket, products=(product,))

        assert await preview(db_session) == impact(
            cves_evaluated=1, product_eligibility_changes=1
        )

    async def test_override_is_preserved_and_counted_as_a_skip(
        self,
        db_session: AsyncSession,
        cve_with: CVEBuilder,
        ticket_factory: TicketFactory,
        tree: TreeBuilder,
    ) -> None:
        """Rule 1: the override is reported as a skip, never as a change,
        and neither persisted field changes."""
        cve = await cve_with(
            Assessment("5.0"), Assessment("9.0", version="4.0"), severity=None
        )
        ticket = await _ticket(ticket_factory, cve, NEW)
        await tree(
            ticket, products=(Prod(eligible=False, override=True, threshold=T7),)
        )

        assert await preview(db_session) == impact(
            cves_evaluated=1,
            cve_severity_changes=1,
            product_eligibility_override_skips=1,
        )
        assert await _occurrences(db_session, ticket.id) == [(False, True)]


async def _occurrences(db: AsyncSession, ticket_id: uuid.UUID) -> list[tuple[Any, ...]]:
    rows = await db.execute(
        select(TicketPackageProduct.eligible, TicketPackageProduct.is_eligible_override)
        .join(
            TicketPackageTrack,
            TicketPackageTrack.id == TicketPackageProduct.ticket_package_track_id,
        )
        .join(TicketPackage, TicketPackage.id == TicketPackageTrack.ticket_package_id)
        .where(TicketPackage.ticket_id == ticket_id)
        .order_by(TicketPackageProduct.id)
    )
    return [tuple(row) for row in rows]


# ---------------------------------------------------------------------------
# Gate projection
# ---------------------------------------------------------------------------


class TestGateProjection:
    async def test_resolved_to_analyzed_is_one_regression(
        self,
        db_session: AsyncSession,
        cve_with: CVEBuilder,
        ticket_factory: TicketFactory,
        tree: TreeBuilder,
    ) -> None:
        await _regressing(cve_with, ticket_factory, tree)

        assert await preview(db_session) == impact(
            cves_evaluated=1,
            cve_severity_changes=1,
            product_eligibility_changes=1,
            product_eligibility_override_skips=1,
            resolved_ticket_regressions=1,
        )

    async def test_resolved_to_analysis_is_one_regression(
        self,
        db_session: AsyncSession,
        cve_with: CVEBuilder,
        ticket_factory: TicketFactory,
        tree: TreeBuilder,
    ) -> None:
        """An assessment set that projects no severity fails the Analyzed
        predicate's severity condition: the projected gate is `Analysis`."""
        cve = await cve_with(severity=Severity.HIGH)
        ticket = await _ticket(ticket_factory, cve, RESOLVED)
        await tree(ticket, status=PackageStatus.NOT_AFFECTED)

        assert await preview(db_session) == impact(
            cves_evaluated=1, cve_severity_changes=1, resolved_ticket_regressions=1
        )

    async def test_preserved_override_keeps_the_gate_true(
        self,
        db_session: AsyncSession,
        cve_with: CVEBuilder,
        ticket_factory: TicketFactory,
        tree: TreeBuilder,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """testing-strategy.md, Default-CVSS Impact Preview: the only
        applicable occurrence is overridden `false`; the hypothetical
        automatic `true` is not substituted, so the `AFFECTED` track keeps
        an empty actionable eligible set and no regression is counted,
        although a severity change makes the gate evaluated."""
        gate = Spy(monkeypatch, "project_gate_status")
        cve = await cve_with(
            Assessment("5.0"),
            Assessment("9.0", version="4.0"),
            severity=Severity.MEDIUM,
        )
        ticket = await _ticket(ticket_factory, cve, RESOLVED)
        await tree(
            ticket, products=(Prod(eligible=False, override=True, threshold=T7),)
        )

        assert await preview(db_session) == impact(
            cves_evaluated=1,
            cve_severity_changes=1,
            product_eligibility_override_skips=1,
        )
        (tracks,) = [call[1]["tracks"] for call in gate.calls]
        assert [p.eligible for t in tracks for p in t.products] == [False]

    async def test_suse_presence_stays_version_independent(
        self,
        db_session: AsyncSession,
        cve_with: CVEBuilder,
        ticket_factory: TicketFactory,
        tree: TreeBuilder,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Regression: a canonical SUSE assessment at `3.1` only still
        satisfies the SUSE-presence condition under the proposed `4.0`. The
        `4.0` fallback score 10.0 makes the occurrence eligible, so the
        gate is evaluated; the `NOT_AFFECTED` Ticket stays `Resolved`."""
        gate = Spy(monkeypatch, "project_gate_status")
        cve = await cve_with(Assessment("5.0"), severity=Severity.MEDIUM)
        ticket = await _ticket(ticket_factory, cve, RESOLVED)
        await tree(
            ticket,
            status=PackageStatus.NOT_AFFECTED,
            products=(Prod(eligible=False, threshold=T7),),
        )

        assert await preview(db_session) == impact(
            cves_evaluated=1, product_eligibility_changes=1
        )
        assert [call[1]["has_canonical_suse_assessment"] for call in gate.calls] == [
            True
        ]

    async def test_overlapping_categories_and_unchanged_effects(
        self,
        db_session: AsyncSession,
        cve_with: CVEBuilder,
        ticket_factory: TicketFactory,
        tree: TreeBuilder,
    ) -> None:
        """One CVE contributes a severity change, two eligibility changes,
        two override skips, and one regression; its unchanged occurrence and
        a second, converged CVE receive no count."""
        cve = await cve_with(
            Assessment("5.0"),
            Assessment("9.0", version="4.0"),
            severity=Severity.MEDIUM,
        )
        ticket = await _ticket(ticket_factory, cve, RESOLVED)
        await tree(
            ticket,
            products=(
                Prod(eligible=False, threshold=T7),
                Prod(eligible=False, threshold=T7),
                Prod(eligible=True, threshold=None),
                Prod(eligible=False, override=True, threshold=T7),
                Prod(eligible=True, override=True, threshold=T7),
            ),
        )
        await cve_with(Assessment("7.5"), severity=Severity.HIGH)

        assert await preview(db_session) == impact(
            cves_evaluated=2,
            cve_severity_changes=1,
            product_eligibility_changes=2,
            product_eligibility_override_skips=2,
            resolved_ticket_regressions=1,
        )

    async def test_cve_without_projected_effect_counts_only_as_evaluated(
        self,
        db_session: AsyncSession,
        cve_with: CVEBuilder,
        ticket_factory: TicketFactory,
        tree: TreeBuilder,
    ) -> None:
        cve = await cve_with(
            Assessment("9.0"),
            Assessment("9.5", version="4.0"),
            severity=Severity.CRITICAL,
        )
        ticket = await _ticket(ticket_factory, cve, RESOLVED)
        await tree(
            ticket,
            status=PackageStatus.FIXED,
            products=(Prod(eligible=True, released=True),),
        )

        assert await preview(db_session) == impact(cves_evaluated=1)


# ---------------------------------------------------------------------------
# No-op proposal
# ---------------------------------------------------------------------------


class TestNoOpProposal:
    async def test_equal_versions_return_zero_counts_without_a_scan(
        self,
        db_session: AsyncSession,
        cve_with: CVEBuilder,
        ticket_factory: TicketFactory,
        tree: TreeBuilder,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        page = Spy(monkeypatch, "_page_statement")
        await _regressing(cve_with, ticket_factory, tree)

        with StatementRecorder(db_session) as recorder:
            result = await get_default_cvss_version_impact(db_session, "3.1")

        assert result == DefaultCVSSVersionImpact(
            observed_default_cvss_version="3.1",
            proposed_default_cvss_version="3.1",
            no_op=True,
            cves_evaluated=0,
            cve_severity_changes=0,
            product_eligibility_changes=0,
            product_eligibility_override_skips=0,
            resolved_ticket_regressions=0,
        )
        assert page.calls == []
        assert recorder.selects_from("cve") == []

    async def test_empty_population_is_a_complete_evaluation(
        self, db_session: AsyncSession
    ) -> None:
        """Distinct from the no-op: `no_op` is `false`."""
        assert await preview(db_session) == impact()


# ---------------------------------------------------------------------------
# Default-version state matrix
# ---------------------------------------------------------------------------


class TestStatusMatrix:
    async def test_ticketless_cve_projects_severity_only(
        self,
        db_session: AsyncSession,
        cve_with: CVEBuilder,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        eligibility = Spy(monkeypatch, "resolve_eligibility_score")
        gate = Spy(monkeypatch, "project_gate_status")
        await cve_with(
            Assessment("5.0"),
            Assessment("9.0", version="4.0"),
            severity=Severity.MEDIUM,
        )
        await cve_with(Assessment("9.0", version="4.0"), severity=Severity.CRITICAL)

        assert await preview(db_session) == impact(
            cves_evaluated=2, cve_severity_changes=1
        )
        assert (eligibility.calls, gate.calls) == ([], [])

    @pytest.mark.parametrize(
        ("status", "products", "gate", "regressions"),
        [
            (NEW, True, 0, 0),
            (ANALYSIS, True, 1, 0),
            (ANALYZED, True, 1, 0),
            (RESOLVED, True, 1, 1),
            (IGNORED, False, 0, 0),
            (DUPLICATED, False, 0, 0),
        ],
    )
    async def test_every_associated_ticket_status(
        self,
        db_session: AsyncSession,
        cve_with: CVEBuilder,
        ticket_factory: TicketFactory,
        tree: TreeBuilder,
        monkeypatch: pytest.MonkeyPatch,
        status: TicketStatus,
        products: bool,
        gate: int,
        regressions: int,
    ) -> None:
        """ticket-mutations.md, CVSS Status Matrix (default-version
        paragraph): `New` receives severity and eligibility but no gate;
        the gate zone receives severity, eligibility, and the projected
        gate; `Ignored` and `Duplicated` receive severity only, so neither
        their eligibility change nor their override is counted. Only a
        `Resolved` Ticket counts a regression."""
        gate_spy = Spy(monkeypatch, "project_gate_status")
        await _regressing(cve_with, ticket_factory, tree, status)

        assert await preview(db_session) == impact(
            cves_evaluated=1,
            cve_severity_changes=1,
            product_eligibility_changes=int(products),
            product_eligibility_override_skips=int(products),
            resolved_ticket_regressions=regressions,
        )
        assert len(gate_spy.calls) == gate

    async def test_multiple_occurrences_per_cve_and_per_ticket(
        self,
        db_session: AsyncSession,
        cve_with: CVEBuilder,
        ticket_factory: TicketFactory,
        tree: TreeBuilder,
    ) -> None:
        cve = await cve_with(
            Assessment("5.0"), Assessment("9.0", version="4.0"), severity=None
        )
        ticket = await _ticket(ticket_factory, cve, NEW)
        for _ in range(2):
            await tree(
                ticket,
                products=(
                    Prod(eligible=False, threshold=T7),
                    Prod(eligible=False, threshold=T7),
                    Prod(eligible=True, threshold=Decimal("9.5")),
                ),
            )

        assert await preview(db_session) == impact(
            cves_evaluated=1, cve_severity_changes=1, product_eligibility_changes=6
        )

    async def test_excluded_eol_and_non_actionable_products_are_evaluated(
        self,
        db_session: AsyncSession,
        cve_with: CVEBuilder,
        ticket_factory: TicketFactory,
        tree: TreeBuilder,
    ) -> None:
        """package-model.md, Axis 2: Eligibility (Read-only projection):
        exclusion, EOL, and affectedness are not formula inputs."""
        cve = await cve_with(
            Assessment("5.0"), Assessment("9.0", version="4.0"), severity=None
        )
        ticket = await _ticket(ticket_factory, cve, ANALYSIS)
        stale = Prod(eligible=False, threshold=T7)
        await tree(ticket, products=(stale,), package_excluded=True)
        await tree(ticket, products=(stale,), track_excluded=True)
        await tree(
            ticket,
            status=PackageStatus.NOT_AFFECTED,
            products=(
                Prod(eligible=False, threshold=T7, excluded=True),
                Prod(eligible=False, threshold=T7, eol=True),
            ),
        )

        assert await preview(db_session) == impact(
            cves_evaluated=1, cve_severity_changes=1, product_eligibility_changes=4
        )

    @pytest.mark.parametrize(
        ("status", "skips"),
        [(NEW, 1), (ANALYSIS, 1), (RESOLVED, 1), (IGNORED, 0), (DUPLICATED, 0)],
    )
    async def test_overrides_counted_only_where_execution_evaluates(
        self,
        db_session: AsyncSession,
        cve_with: CVEBuilder,
        ticket_factory: TicketFactory,
        tree: TreeBuilder,
        status: TicketStatus,
        skips: int,
    ) -> None:
        cve = await cve_with(
            Assessment("9.0", version="4.0"), severity=Severity.CRITICAL
        )
        ticket = await _ticket(ticket_factory, cve, status)
        await tree(
            ticket,
            status=PackageStatus.NOT_AFFECTED,
            products=(Prod(eligible=True, override=True),),
        )

        assert await preview(db_session) == impact(
            cves_evaluated=1, product_eligibility_override_skips=skips
        )


# ---------------------------------------------------------------------------
# Unconverged gate-zone Tickets (Projected Impact)
# ---------------------------------------------------------------------------


class TestUnconvergedGateZone:
    @staticmethod
    async def _unmet_resolved(
        cve_with: CVEBuilder,
        ticket_factory: TicketFactory,
        tree: TreeBuilder,
        *,
        proposed_score: str,
        status: TicketStatus = RESOLVED,
    ) -> Ticket:
        """A Ticket persisted as `status` whose gate is already unmet for a
        reason unrelated to the default version: its `AFFECTED` track has
        an actionable eligible occurrence (threshold 7.0, met by both
        versions), so the predicates yield `Analyzed`. SUSE `3.1` = 8.0
        (`High`, persisted)."""
        cve = await cve_with(
            Assessment("8.0"),
            Assessment(proposed_score, version="4.0"),
            severity=Severity.HIGH,
        )
        ticket = await _ticket(ticket_factory, cve, status)
        await tree(ticket, products=(Prod(eligible=True, threshold=T7),))
        return ticket

    async def test_without_gate_input_change_projects_the_persisted_status(
        self,
        db_session: AsyncSession,
        cve_with: CVEBuilder,
        ticket_factory: TicketFactory,
        tree: TreeBuilder,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """SUSE `4.0` = 8.5 keeps `High` and `eligible`: execution would not
        reconcile, so no regression is counted."""
        gate = Spy(monkeypatch, "project_gate_status")
        await self._unmet_resolved(cve_with, ticket_factory, tree, proposed_score="8.5")

        assert await preview(db_session) == impact(cves_evaluated=1)
        assert gate.calls == []

    async def test_with_severity_change_projects_the_predicate_result(
        self,
        db_session: AsyncSession,
        cve_with: CVEBuilder,
        ticket_factory: TicketFactory,
        tree: TreeBuilder,
    ) -> None:
        """SUSE `4.0` = 9.5 projects `Critical`: execution reconciles, and
        the predicates yield `Analyzed`, one regression."""
        await self._unmet_resolved(cve_with, ticket_factory, tree, proposed_score="9.5")

        assert await preview(db_session) == impact(
            cves_evaluated=1, cve_severity_changes=1, resolved_ticket_regressions=1
        )

    async def test_with_eligibility_change_projects_the_predicate_result(
        self,
        db_session: AsyncSession,
        cve_with: CVEBuilder,
        ticket_factory: TicketFactory,
        tree: TreeBuilder,
    ) -> None:
        """A second occurrence (threshold 8.5) projects `true` under `4.0`
        (8.8) without a severity change: execution reconciles, one
        regression."""
        ticket = await self._unmet_resolved(
            cve_with, ticket_factory, tree, proposed_score="8.8"
        )
        await tree(ticket, products=(Prod(eligible=False, threshold=Decimal("8.5")),))

        assert await preview(db_session) == impact(
            cves_evaluated=1,
            product_eligibility_changes=1,
            resolved_ticket_regressions=1,
        )

    @pytest.mark.parametrize("status", [ANALYSIS, ANALYZED])
    async def test_analysis_and_analyzed_keep_their_persisted_status(
        self,
        db_session: AsyncSession,
        cve_with: CVEBuilder,
        ticket_factory: TicketFactory,
        tree: TreeBuilder,
        monkeypatch: pytest.MonkeyPatch,
        status: TicketStatus,
    ) -> None:
        gate = Spy(monkeypatch, "project_gate_status")
        await self._unmet_resolved(
            cve_with, ticket_factory, tree, proposed_score="8.5", status=status
        )

        assert await preview(db_session) == impact(cves_evaluated=1)
        assert gate.calls == []


# ---------------------------------------------------------------------------
# Evaluation date
# ---------------------------------------------------------------------------


class TestEvaluationDate:
    async def test_one_utc_date_governs_every_page_across_midnight(
        self,
        db_session: AsyncSession,
        cve_with: CVEBuilder,
        ticket_factory: TicketFactory,
        tree: TreeBuilder,
        product_factory: ProductFactory,
        ticket_package_product_factory: OccurrenceFactory,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A controlled clock crosses UTC midnight after the first capture.
        Each catalog Product is in Reactive Support on `EVAL` (rule 2:
        `false`) and EOL the next day (threshold rule: `true`); with one
        page per CVE both units must use `EVAL`, so both persisted `true`
        occurrences change. The clock is read exactly once."""
        monkeypatch.setattr(cvss_impact_preview, "_PAGE_SIZE", 1)
        instants = iter(
            [
                datetime.combine(EVAL, time(23, 59, 59), tzinfo=UTC),
                datetime.combine(EVAL + timedelta(days=1), time(0, 0), tzinfo=UTC),
            ]
        )
        captured: list[date] = []

        def _clock() -> datetime:
            instant = next(instants)
            captured.append(instant.date())
            return instant

        monkeypatch.setattr(cvss_impact_preview, "_utc_now", _clock)
        for _ in range(2):
            cve = await cve_with(Assessment("9.0", version="4.0"), severity=None)
            ticket = await _ticket(ticket_factory, cve, ANALYZED)
            track = await tree(ticket, products=())
            product = await product_factory(
                general_support_end_date=EVAL - timedelta(days=90),
                extended_support_end_date=EVAL - timedelta(days=30),
                reactive_support_end_date=EVAL,
            )
            await ticket_package_product_factory(
                ticket_package_track_id=track.id, product_id=product.id, eligible=True
            )

        assert await preview(db_session) == impact(
            cves_evaluated=2, cve_severity_changes=2, product_eligibility_changes=2
        )
        assert captured == [EVAL]


# ---------------------------------------------------------------------------
# Read-only, no coordination, no side effect
# ---------------------------------------------------------------------------


class TestNoSideEffects:
    async def test_no_write_lock_audit_assignment_or_reconciliation(
        self,
        db_session: AsyncSession,
        cve_with: CVEBuilder,
        ticket_factory: TicketFactory,
        tree: TreeBuilder,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """No write, lock, audit event, assignment, or convergence effect.
        `reconcile_ticket_status()` is excluded structurally instead of by a
        spy: the preview module imports no Ticket mutation module
        (tests/test_architecture/test_cvss_impact_preview_boundaries.py), so
        a spy on `ticket_mutations` would never be reachable."""
        for status in (NEW, ANALYSIS, RESOLVED, IGNORED):
            await _regressing(cve_with, ticket_factory, tree, status)
        before = await _snapshot(db_session)

        with StatementRecorder(db_session) as recorder:
            result = await preview(db_session)

        assert result.resolved_ticket_regressions == 1
        assert await _snapshot(db_session) == before
        assert recorder.writes() == []
        assert recorder.row_locks() == []
        assert [s for s in recorder.statements if "advisory" in s.lower()] == []
        assert not db_session.info.get("post_commit_callbacks")
        assert pending_ticket_convergence_effects(db_session) == ()

    async def test_no_redis_task_state_or_celery_publication(
        self,
        db_session: AsyncSession,
        cve_with: CVEBuilder,
        ticket_factory: TicketFactory,
        tree: TreeBuilder,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """default-cvss-version-operations.md, Preview Service and Active
        Recalculation Run: no Redis client, key, or task-state read, and no
        publication. A run's lease and task state live only in Redis, so
        no Redis access also proves no task-state read."""
        touched: list[str] = []

        def _forbid(name: str) -> Callable[..., Any]:
            def _call(*args: Any, **kwargs: Any) -> Any:
                touched.append(name)
                raise AssertionError(f"the preview must not use {name}")

            return _call

        monkeypatch.setattr(Redis, "__init__", _forbid("Redis()"))
        monkeypatch.setattr(Redis, "execute_command", _forbid("Redis command"))
        monkeypatch.setattr(Celery, "send_task", _forbid("send_task"))
        monkeypatch.setattr(Task, "apply_async", _forbid("apply_async"))
        await _regressing(cve_with, ticket_factory, tree)

        assert (await preview(db_session)).resolved_ticket_regressions == 1
        assert touched == []

    async def test_shares_no_state_with_later_invocations(
        self,
        db_session: AsyncSession,
        cve_with: CVEBuilder,
        ticket_factory: TicketFactory,
        tree: TreeBuilder,
    ) -> None:
        """Consistency and Staleness: the high-water mark is neither
        returned nor persisted, and a repeated preview observes the state
        committed when it runs."""
        await _regressing(cve_with, ticket_factory, tree)
        first = await preview(db_session)
        assert set(DefaultCVSSVersionImpact.__dataclass_fields__) == {
            "observed_default_cvss_version",
            "proposed_default_cvss_version",
            "no_op",
            "cves_evaluated",
            "cve_severity_changes",
            "product_eligibility_changes",
            "product_eligibility_override_skips",
            "resolved_ticket_regressions",
        }
        await cve_with(Assessment("9.0", version="4.0"), severity=None)

        second = await preview(db_session)

        assert first.cves_evaluated == 1
        assert second.cves_evaluated == 2
        assert second.cve_severity_changes == first.cve_severity_changes + 1

    def test_evaluation_instant_is_utc(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The unpatched clock yields an aware UTC instant, whose date is
        the invocation's `evaluation_date`."""
        monkeypatch.undo()

        assert cvss_impact_preview._utc_now().tzinfo is UTC

    async def test_missing_setting_propagates(
        self, db_session: AsyncSession, setting: SystemSetting
    ) -> None:
        await db_session.delete(setting)
        await db_session.flush()

        with pytest.raises(settings.RequiredSystemSettingMissingError):
            await preview(db_session)

    async def test_unsupported_proposal_raises_value_error_before_any_read(
        self, db_session: AsyncSession
    ) -> None:
        with (
            StatementRecorder(db_session) as recorder,
            pytest.raises(ValueError, match="proposed_version"),
        ):
            await get_default_cvss_version_impact(db_session, "3.0")  # type: ignore[arg-type]

        assert recorder.statements == []

    async def test_invalid_persisted_assessment_set_propagates_value_error(
        self,
        db_session: AsyncSession,
        cve_with: CVEBuilder,
    ) -> None:
        """An unsupported persisted version fails pure validation; no
        partial result is returned."""
        await cve_with(Assessment("5.0", version="1.0"), severity=None)

        with pytest.raises(ValueError, match="Unsupported CVSS assessment version"):
            await preview(db_session)


async def _snapshot(db: AsyncSession) -> dict[str, list[tuple[Any, ...]]]:
    """Every persisted value the preview projects or could write."""
    return {
        "cves": [
            tuple(r)
            for r in await db.execute(select(CVE.id, CVE.severity).order_by(CVE.id))
        ],
        "tickets": [
            tuple(r)
            for r in await db.execute(
                select(
                    Ticket.id, Ticket.status, Ticket.assignee_id, Ticket.priority_auto
                ).order_by(Ticket.id)
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
        "events": [tuple(r) for r in await db.execute(select(TicketAuditEvent.id))],
    }
