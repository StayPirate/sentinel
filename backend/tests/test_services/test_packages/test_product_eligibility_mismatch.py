"""Tests for the shared Product eligibility-mismatch scan
(backend/app/services/packages/product_eligibility_mismatch.py).

Owning specifications:

- docs/features/packages/product-catalog.md (CVSS Threshold Sync step 9):
  system-managed occurrences of operable Tickets (`New`, `Analysis`,
  `Analyzed`, `Resolved`) whose stored `eligible` differs from the result
  under the committed thresholds, for one UTC `evaluation_date`, including
  directly and effectively excluded records and EOL Products.
- docs/features/packages/package-model.md (Axis 2: Eligibility): manual
  overrides never change; the Reactive Support rule; `NULL` threshold as
  `0.0`; only the canonical SUSE assessment of the default CVSS version,
  otherwise `10.0` (also for a CVE-less Ticket); one shared pure evaluator
  and no copied formula.
- docs/features/platform/testing-strategy.md (Service Functions: valid
  input, Q5 re-invocation, Q6 propagation).

Every test runs against the per-test rolled-back `db_session`. The curated
tests transcribe their expectation from the specification; the parity
matrix compares scan membership with `evaluate_product_eligibility()` over
the lifecycle inputs of `tests/support/lifecycle_matrix.py`, whose phases
are themselves transcribed from the Lifecycle Evaluator.
"""

from __future__ import annotations

import itertools
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from decimal import Decimal
from typing import Final

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import EligibilitySource, LifecyclePhase, TicketStatus
from app.models.cve import CVE
from app.models.cve_cvss_assessment import CVECVSSAssessment
from app.models.product import Product
from app.models.system_setting import SystemSetting
from app.models.ticket import Ticket
from app.models.ticket_package import TicketPackage
from app.models.ticket_package_product import TicketPackageProduct
from app.models.ticket_package_track import TicketPackageTrack
from app.services.cvss import EligibilityResolution
from app.services.packages.product_eligibility_mismatch import (
    find_product_eligibility_mismatches,
)
from app.services.product_eligibility import evaluate_product_eligibility
from app.services.settings import RequiredSystemSettingMissingError
from tests.support.lifecycle_matrix import LIFECYCLE_CASES, LifecycleCase
from tests.support.product_eligibility import set_default_version
from tests.support.ticket_mutations import (
    AFTER_EVAL,
    BEFORE_EVAL,
    EVAL,
    StatementRecorder,
)

DEFAULT_VERSION: Final = "3.1"

ProductFactory = Callable[..., Awaitable[Product]]
TicketFactory = Callable[..., Awaitable[Ticket]]
CVEFactory = Callable[..., Awaitable[CVE]]
AssessmentFactory = Callable[..., Awaitable[CVECVSSAssessment]]
SettingFactory = Callable[..., Awaitable[SystemSetting]]

OPERABLE: Final = (
    TicketStatus.NEW,
    TicketStatus.ANALYSIS,
    TicketStatus.ANALYZED,
    TicketStatus.RESOLVED,
)
MANUAL_ZONE: Final = (TicketStatus.IGNORED, TicketStatus.DUPLICATED)


@pytest.fixture
async def default_setting(system_setting_factory: SettingFactory) -> SystemSetting:
    """The persisted `default_cvss_version` (the test schema has none)."""
    return await system_setting_factory(
        key="default_cvss_version", value=DEFAULT_VERSION
    )


@dataclass
class World:
    """Seeds catalog Products, Tickets, CVEs, and occurrences."""

    db: AsyncSession
    products: ProductFactory
    tickets: TicketFactory
    cves: CVEFactory
    assessments: AssessmentFactory

    async def product(
        self, threshold: str | Decimal | None = None, **dates: date | None
    ) -> Product:
        """A catalog Product (in support on `EVAL` unless dates are given)."""
        if not dates:
            dates = {"general_support_end_date": AFTER_EVAL}
        return await self.products(
            cvss_threshold=None if threshold is None else Decimal(threshold), **dates
        )

    async def cve(self, *assessments: tuple[str, str, str]) -> CVE:
        """A CVE with `(provider, version, score)` assessments."""
        cve = await self.cves()
        for provider, version, score in assessments:
            await self.assessments(
                cve_id=cve.id,
                provider_name=provider,
                cvss_version=version,
                score=Decimal(score),
            )
        return cve

    async def ticket(
        self, status: TicketStatus = TicketStatus.ANALYSIS, cve: CVE | None = None
    ) -> Ticket:
        return await self.tickets(
            status=status.value, cve_id=None if cve is None else cve.id
        )

    async def occurrence(
        self,
        ticket: Ticket,
        product: Product,
        *,
        eligible: bool,
        override: bool = False,
        excluded: bool = False,
        track_excluded: bool = False,
        package_excluded: bool = False,
    ) -> TicketPackageProduct:
        """One occurrence of `product` on a fresh track of a fresh package."""
        now = datetime.now(UTC)
        package = TicketPackage(
            ticket_id=ticket.id,
            package_name=f"example-package-{uuid.uuid4().hex[:12]}",
            deleted_at=now if package_excluded else None,
        )
        self.db.add(package)
        await self.db.flush()
        track = TicketPackageTrack(
            ticket_package_id=package.id,
            workflow_type="ibs",
            reference=f"Example:Codestream:{uuid.uuid4().hex[:12]}:Update",
            deleted_at=now if track_excluded else None,
        )
        self.db.add(track)
        await self.db.flush()
        occurrence = TicketPackageProduct(
            ticket_package_track_id=track.id,
            product_id=product.id,
            eligible=eligible,
            is_eligible_override=override,
            deleted_at=now if excluded else None,
        )
        self.db.add(occurrence)
        await self.db.flush()
        return occurrence


@pytest.fixture
def world(
    db_session: AsyncSession,
    product_factory: ProductFactory,
    ticket_factory: TicketFactory,
    cve_factory: CVEFactory,
    cve_cvss_assessment_factory: AssessmentFactory,
) -> World:
    return World(
        db_session,
        product_factory,
        ticket_factory,
        cve_factory,
        cve_cvss_assessment_factory,
    )


def _statements(recorder: StatementRecorder) -> list[str]:
    """The recorded statements without the test harness's savepoints."""
    return [s for s in recorder.statements if "SAVEPOINT" not in s]


async def _scan(db: AsyncSession, evaluation_date: date = EVAL) -> frozenset[uuid.UUID]:
    return await find_product_eligibility_mismatches(
        db, evaluation_date=evaluation_date
    )


# ---------------------------------------------------------------------------
# Selection scope (operable Tickets; excluded and EOL included; overrides)
# ---------------------------------------------------------------------------


@pytest.mark.integration
@pytest.mark.usefixtures("default_setting")
class TestSelectionScope:
    @pytest.mark.parametrize("status", OPERABLE, ids=[s.value for s in OPERABLE])
    async def test_operable_ticket_mismatch_is_found(
        self, db_session: AsyncSession, world: World, status: TicketStatus
    ) -> None:
        """`NULL` threshold, CVE-less fallback 10.0: automatic `true`."""
        product = await world.product()
        await world.occurrence(await world.ticket(status), product, eligible=False)

        assert await _scan(db_session) == frozenset({product.id})

    @pytest.mark.parametrize("status", MANUAL_ZONE, ids=[s.value for s in MANUAL_ZONE])
    async def test_manual_zone_ticket_is_ignored(
        self, db_session: AsyncSession, world: World, status: TicketStatus
    ) -> None:
        product = await world.product()
        await world.occurrence(await world.ticket(status), product, eligible=False)

        assert await _scan(db_session) == frozenset()

    @pytest.mark.parametrize(
        "variant",
        [
            pytest.param({"excluded": True}, id="direct"),
            pytest.param({"track_excluded": True}, id="track"),
            pytest.param({"package_excluded": True}, id="package"),
        ],
    )
    async def test_excluded_occurrence_is_included(
        self, db_session: AsyncSession, world: World, variant: dict[str, bool]
    ) -> None:
        product = await world.product()
        await world.occurrence(await world.ticket(), product, eligible=False, **variant)

        assert await _scan(db_session) == frozenset({product.id})

    async def test_eol_product_is_included(
        self, db_session: AsyncSession, world: World
    ) -> None:
        product = await world.product(general_support_end_date=BEFORE_EVAL)
        await world.occurrence(await world.ticket(), product, eligible=False)

        assert await _scan(db_session) == frozenset({product.id})

    @pytest.mark.parametrize("stored", [True, False])
    async def test_manual_override_never_mismatches(
        self, db_session: AsyncSession, world: World, stored: bool
    ) -> None:
        """Rule 1: an override preserves either stored value."""
        product = await world.product(threshold="9.0")
        cve = await world.cve(("SUSE", DEFAULT_VERSION, "5.0"))
        await world.occurrence(
            await world.ticket(cve=cve), product, eligible=stored, override=True
        )

        assert await _scan(db_session) == frozenset()

    async def test_converged_products_are_not_returned(
        self, db_session: AsyncSession, world: World
    ) -> None:
        eligible = await world.product(threshold="5.0")
        ineligible = await world.product(threshold="9.0")
        cve = await world.cve(("SUSE", DEFAULT_VERSION, "7.0"))
        ticket = await world.ticket(cve=cve)
        await world.occurrence(ticket, eligible, eligible=True)
        await world.occurrence(ticket, ineligible, eligible=False)

        assert await _scan(db_session) == frozenset()

    async def test_product_is_returned_once_for_many_mismatches(
        self, db_session: AsyncSession, world: World
    ) -> None:
        """Three Tickets (one with a CVE) with two mismatching occurrences
        each, beside a converged Product in the same Tickets."""
        product = await world.product()
        converged = await world.product()
        cve = await world.cve(("SUSE", DEFAULT_VERSION, "9.0"))
        for ticket in [
            await world.ticket(TicketStatus.NEW),
            await world.ticket(TicketStatus.RESOLVED, cve=cve),
            await world.ticket(TicketStatus.ANALYZED),
        ]:
            await world.occurrence(ticket, product, eligible=False)
            await world.occurrence(ticket, product, eligible=False, excluded=True)
            await world.occurrence(ticket, converged, eligible=True)

        result = await _scan(db_session)

        assert type(result) is frozenset
        assert result == frozenset({product.id})

    async def test_product_with_any_mismatching_combination_is_returned(
        self, db_session: AsyncSession, world: World
    ) -> None:
        """One converged and one mismatching occurrence of the same Product,
        and two independent mismatching Products."""
        first = await world.product()
        second = await world.product(threshold="8.0")
        third = await world.product()
        cve = await world.cve(("SUSE", DEFAULT_VERSION, "6.0"))
        await world.occurrence(await world.ticket(), first, eligible=True)
        await world.occurrence(await world.ticket(), first, eligible=False)
        await world.occurrence(await world.ticket(cve=cve), second, eligible=True)
        await world.occurrence(await world.ticket(), third, eligible=True)

        assert await _scan(db_session) == frozenset({first.id, second.id})


# ---------------------------------------------------------------------------
# Eligibility inputs (threshold, lifecycle, score resolution)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestEligibilityInputs:
    @pytest.mark.usefixtures("default_setting")
    @pytest.mark.parametrize(("stored", "mismatch"), [(True, False), (False, True)])
    async def test_cve_less_ticket_uses_the_10_0_fallback(
        self, db_session: AsyncSession, world: World, stored: bool, mismatch: bool
    ) -> None:
        """Score 10.0 meets a 10.0 threshold: automatic `true`."""
        product = await world.product(threshold="10.0")
        await world.occurrence(await world.ticket(), product, eligible=stored)

        assert (product.id in await _scan(db_session)) is mismatch

    @pytest.mark.usefixtures("default_setting")
    async def test_cve_without_assessments_uses_the_fallback(
        self, db_session: AsyncSession, world: World
    ) -> None:
        product = await world.product(threshold="10.0")
        await world.occurrence(
            await world.ticket(cve=await world.cve()), product, eligible=False
        )

        assert await _scan(db_session) == frozenset({product.id})

    @pytest.mark.usefixtures("default_setting")
    async def test_only_the_suse_default_version_assessment_counts(
        self, db_session: AsyncSession, world: World
    ) -> None:
        """Under default `3.1`, a SUSE `4.0` score and an external `3.1`
        score below the threshold are ignored: the fallback 10.0 makes the
        occurrence eligible."""
        product = await world.product(threshold="7.0")
        cve = await world.cve(
            ("SUSE", "4.0", "2.0"), ("Example Provider", DEFAULT_VERSION, "2.0")
        )
        stale_true = await world.product(threshold="7.0")
        ticket = await world.ticket(cve=cve)
        await world.occurrence(ticket, product, eligible=False)
        await world.occurrence(ticket, stale_true, eligible=True)

        assert await _scan(db_session) == frozenset({product.id})

    @pytest.mark.usefixtures("default_setting")
    async def test_configured_default_version_selects_the_suse_assessment(
        self, db_session: AsyncSession, world: World
    ) -> None:
        """After switching the default to `4.0`, the SUSE `4.0` score 2.0 is
        below the 7.0 threshold: the stored `true` mismatches."""
        product = await world.product(threshold="7.0")
        cve = await world.cve(("SUSE", "4.0", "2.0"), ("SUSE", "3.1", "9.0"))
        await world.occurrence(await world.ticket(cve=cve), product, eligible=True)
        assert await _scan(db_session) == frozenset()

        await set_default_version(db_session, "4.0")

        assert await _scan(db_session) == frozenset({product.id})

    @pytest.mark.usefixtures("default_setting")
    @pytest.mark.parametrize(
        ("threshold", "stored", "mismatch"),
        [
            (None, True, False),
            ("6.9", True, False),
            ("7.0", True, False),
            ("7.1", True, True),
            ("7.1", False, False),
            (None, False, True),
        ],
        ids=[
            "null-true",
            "below-true",
            "equal-true",
            "above-true",
            "above-false",
            "null-false",
        ],
    )
    async def test_threshold_comparison_against_the_suse_score(
        self,
        db_session: AsyncSession,
        world: World,
        threshold: str | None,
        stored: bool,
        mismatch: bool,
    ) -> None:
        product = await world.product(threshold=threshold)
        cve = await world.cve(("SUSE", DEFAULT_VERSION, "7.0"))
        await world.occurrence(await world.ticket(cve=cve), product, eligible=stored)

        assert (product.id in await _scan(db_session)) is mismatch

    @pytest.mark.usefixtures("default_setting")
    async def test_supplied_evaluation_date_decides_the_lifecycle_phase(
        self, db_session: AsyncSession, world: World
    ) -> None:
        """General Support on `EVAL` (automatic `true`), Reactive Support a
        year later (automatic `false`): the stored `false` mismatches only
        on `EVAL`."""
        product = await world.product(
            first_customer_ship_date=EVAL - timedelta(days=400),
            general_support_end_date=EVAL + timedelta(days=10),
            extended_support_end_date=EVAL + timedelta(days=100),
            reactive_support_end_date=EVAL + timedelta(days=1000),
        )
        await world.occurrence(await world.ticket(), product, eligible=False)

        assert await _scan(db_session, EVAL) == frozenset({product.id})
        assert await _scan(db_session, EVAL + timedelta(days=365)) == frozenset()

    async def test_no_candidate_occurrence_reads_no_setting(
        self, db_session: AsyncSession, world: World
    ) -> None:
        """No setting row exists: reading it would raise. Only overrides and
        manual-zone Tickets exist, so the single selection returns nothing."""
        product = await world.product()
        await world.occurrence(
            await world.ticket(), product, eligible=False, override=True
        )
        await world.occurrence(
            await world.ticket(TicketStatus.IGNORED), product, eligible=False
        )

        with StatementRecorder(db_session) as recorder:
            result = await _scan(db_session)

        assert result == frozenset()
        assert len(_statements(recorder)) == 1
        assert recorder.selects_from("system_setting") == []

    async def test_empty_catalog_returns_an_empty_set(
        self, db_session: AsyncSession
    ) -> None:
        with StatementRecorder(db_session) as recorder:
            result = await _scan(db_session)

        assert result == frozenset()
        assert type(result) is frozenset
        assert len(_statements(recorder)) == 1


# ---------------------------------------------------------------------------
# Read-only contract, re-invocation, and propagation (Q2, Q5, Q6)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestReadOnlyContract:
    @pytest.mark.usefixtures("default_setting")
    async def test_scan_takes_no_lock_and_writes_nothing(
        self, db_session: AsyncSession, world: World
    ) -> None:
        product = await world.product(threshold="8.0")
        cves = [
            await world.cve(("SUSE", DEFAULT_VERSION, "9.0")),
            await world.cve(("SUSE", DEFAULT_VERSION, "5.0")),
        ]
        occurrences = [
            await world.occurrence(await world.ticket(cve=cve), product, eligible=True)
            for cve in cves
        ]
        await db_session.commit()

        with StatementRecorder(db_session) as recorder:
            first = await _scan(db_session)
            second = await _scan(db_session)

        assert first == second == frozenset({product.id})
        statements = _statements(recorder)
        assert len(statements) == 6  # per scan: selection, setting, assessments
        assert all(s.lstrip().upper().startswith("SELECT") for s in statements)
        assert recorder.row_locks() == []
        assert not db_session.new
        assert not db_session.dirty
        assert not db_session.deleted
        for occurrence in occurrences:
            await db_session.refresh(occurrence)
            assert occurrence.eligible is True

    async def test_missing_setting_propagates_when_candidates_exist(
        self, db_session: AsyncSession, world: World
    ) -> None:
        await world.occurrence(
            await world.ticket(), await world.product(), eligible=True
        )

        with pytest.raises(RequiredSystemSettingMissingError):
            await _scan(db_session)

    @pytest.mark.usefixtures("default_setting")
    async def test_invalid_default_version_propagates(
        self, db_session: AsyncSession, world: World
    ) -> None:
        await world.occurrence(
            await world.ticket(), await world.product(), eligible=True
        )
        await set_default_version(db_session, "2.0")

        with pytest.raises(ValueError, match=r"^Default CVSS version must be 3\.1"):
            await _scan(db_session)


# ---------------------------------------------------------------------------
# Parity matrix with the shared pure evaluator (package-model.md, Axis 2)
# ---------------------------------------------------------------------------

_PHASE_CASE_IDS: Final = {
    "full_day_before_fcs_pre_release": LifecyclePhase.PRE_RELEASE,
    "full_at_fcs_general_support": LifecyclePhase.GENERAL_SUPPORT,
    "full_day_after_gs_end_extended": LifecyclePhase.EXTENDED_SUPPORT,
    "full_day_after_extended_end_reactive": LifecyclePhase.REACTIVE_SUPPORT,
    "full_day_after_reactive_end_eol": LifecyclePhase.EOL,
    "all_absent_far_future_null": None,
    "inconsistent_extended_without_general_support_end_far_future_null": None,
}
_PHASE_CASES: Final[tuple[LifecycleCase, ...]] = tuple(
    case for case in LIFECYCLE_CASES if case.id in _PHASE_CASE_IDS
)
assert len(_PHASE_CASES) == len(_PHASE_CASE_IDS)
assert all(case.expected is _PHASE_CASE_IDS[case.id] for case in _PHASE_CASES)

_SUSE_SCORE: Final = Decimal("6.5")
_FALLBACK_SCORE: Final = Decimal("10.0")
_SCORES: Final = {"fallback": None, "suse": _SUSE_SCORE}
_THRESHOLD_OFFSETS: Final = {
    "none": None,
    "below": Decimal("-0.5"),
    "equal": Decimal("0.0"),
    "above": Decimal("0.5"),
}


@dataclass(frozen=True, slots=True)
class ParityCase:
    phase: LifecycleCase
    score: str
    threshold: str
    stored: bool

    @property
    def id(self) -> str:
        return f"{self.phase.id}-{self.score}-{self.threshold}-{self.stored}"

    @property
    def score_value(self) -> Decimal:
        suse = _SCORES[self.score]
        return _FALLBACK_SCORE if suse is None else suse

    @property
    def threshold_value(self) -> Decimal | None:
        offset = _THRESHOLD_OFFSETS[self.threshold]
        return None if offset is None else self.score_value + offset

    def expected_mismatch(self) -> bool:
        source = (
            EligibilitySource.FALLBACK
            if _SCORES[self.score] is None
            else EligibilitySource.SUSE
        )
        expected = evaluate_product_eligibility(
            is_eligible_override=False,
            lifecycle_phase=self.phase.expected,
            cvss_threshold=self.threshold_value,
            eligibility_score=EligibilityResolution(
                score=self.score_value, source=source
            ),
        ).automatic_eligible
        return expected != self.stored


_PARITY_CASES: Final = tuple(
    ParityCase(phase, score, threshold, stored)
    for phase, score, threshold, stored in itertools.product(
        _PHASE_CASES, _SCORES, _THRESHOLD_OFFSETS, (True, False)
    )
)


async def _seed_parity_case(
    world: World, case: ParityCase, shift: timedelta = timedelta(0)
) -> Product:
    """One Product and one occurrence realizing `case`; the lifecycle dates
    are shifted by `shift` (which preserves the phase when the evaluation
    date is shifted equally)."""
    inputs = case.phase.inputs

    def shifted(value: date | None) -> date | None:
        return None if value is None else value + shift

    product = await world.product(
        case.threshold_value,
        first_customer_ship_date=shifted(inputs.first_customer_ship_date),
        general_support_end_date=shifted(inputs.general_support_end_date),
        extended_support_end_date=shifted(inputs.extended_support_end_date),
        reactive_support_end_date=shifted(inputs.reactive_support_end_date),
    )
    suse = _SCORES[case.score]
    cve = (
        None if suse is None else await world.cve(("SUSE", DEFAULT_VERSION, str(suse)))
    )
    await world.occurrence(await world.ticket(cve=cve), product, eligible=case.stored)
    return product


@pytest.mark.integration
@pytest.mark.usefixtures("default_setting")
class TestEvaluatorParity:
    @pytest.mark.parametrize("case", _PARITY_CASES, ids=[c.id for c in _PARITY_CASES])
    async def test_membership_agrees_with_the_pure_evaluator(
        self, db_session: AsyncSession, world: World, case: ParityCase
    ) -> None:
        product = await _seed_parity_case(world, case)

        result = await _scan(db_session, case.phase.inputs.evaluation_date)

        expected: set[uuid.UUID] = {product.id} if case.expected_mismatch() else set()
        assert result == frozenset(expected)

    async def test_complete_grid_in_one_scan(
        self, db_session: AsyncSession, world: World
    ) -> None:
        """Every case seeded at once, its dates shifted to one evaluation
        date: the distinct-combination reduction keeps every case apart."""
        evaluation_date = EVAL
        expected: set[uuid.UUID] = set()
        converged: set[uuid.UUID] = set()
        for case in _PARITY_CASES:
            shift = evaluation_date - case.phase.inputs.evaluation_date
            product = await _seed_parity_case(world, case, shift)
            (expected if case.expected_mismatch() else converged).add(product.id)

        result = await _scan(db_session, evaluation_date)

        assert result == frozenset(expected)
        # The grid exercises both outcomes.
        assert expected
        assert converged
