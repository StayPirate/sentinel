"""Tests for the pure automatic Product eligibility evaluator.

Owning specification: `docs/features/packages/package-model.md` (Axis 2:
Eligibility — rules 1-5 and the complete automatic evaluator; Package
Eligibility > Override Model), `docs/features/packages/package-service.md`
(Relationship with other modules), and
`docs/features/tickets/cvss-scoring.md` (Eligibility Score Resolution, the
consumed input).
"""

from __future__ import annotations

import inspect
from decimal import Decimal

import pytest

from app.core.enums import EligibilitySource, LifecyclePhase
from app.services import product_eligibility
from app.services.cvss import EligibilityResolution, resolve_eligibility_score
from app.services.product_eligibility import (
    IMPLICIT_CVSS_THRESHOLD,
    EligibilityOutcome,
    evaluate_product_eligibility,
)
from tests.support.module_imports import APP_ROOT, forbidden_imports, imported_modules

_NON_REACTIVE_PHASES: tuple[LifecyclePhase | None, ...] = (
    None,
    LifecyclePhase.PRE_RELEASE,
    LifecyclePhase.GENERAL_SUPPORT,
    LifecyclePhase.EXTENDED_SUPPORT,
    LifecyclePhase.EOL,
)
_ALL_PHASES: tuple[LifecyclePhase | None, ...] = (None, *LifecyclePhase)
_THRESHOLDS: tuple[Decimal | None, ...] = (
    None,
    Decimal("0.0"),
    Decimal("7.0"),
    Decimal("10.0"),
)
_SCORES: tuple[EligibilityResolution, ...] = (
    EligibilityResolution(score=Decimal("0.0"), source=EligibilitySource.SUSE),
    EligibilityResolution(score=Decimal("6.9"), source=EligibilitySource.SUSE),
    EligibilityResolution(score=Decimal("7.0"), source=EligibilitySource.SUSE),
    EligibilityResolution(score=Decimal("10.0"), source=EligibilitySource.FALLBACK),
)


def _suse(score: str) -> EligibilityResolution:
    return EligibilityResolution(score=Decimal(score), source=EligibilitySource.SUSE)


def _evaluate(
    *,
    is_eligible_override: bool = False,
    lifecycle_phase: LifecyclePhase | None = LifecyclePhase.GENERAL_SUPPORT,
    cvss_threshold: Decimal | None = None,
    eligibility_score: EligibilityResolution | None = None,
) -> EligibilityOutcome:
    return evaluate_product_eligibility(
        is_eligible_override=is_eligible_override,
        lifecycle_phase=lifecycle_phase,
        cvss_threshold=cvss_threshold,
        eligibility_score=(
            _suse("7.5") if eligibility_score is None else eligibility_score
        ),
    )


# ---------------------------------------------------------------------------
# Rule 1 — manual override
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestOverridePreserved:
    def test_override_is_preserved_for_every_input_combination(self) -> None:
        for phase in _ALL_PHASES:
            for threshold in _THRESHOLDS:
                for score in _SCORES:
                    outcome = _evaluate(
                        is_eligible_override=True,
                        lifecycle_phase=phase,
                        cvss_threshold=threshold,
                        eligibility_score=score,
                    )
                    assert outcome is EligibilityOutcome.OVERRIDE_PRESERVED

    def test_override_produces_no_automatic_value(self) -> None:
        outcome = _evaluate(is_eligible_override=True)

        assert outcome.automatic_eligible is None

    def test_override_precedes_reactive_support(self) -> None:
        outcome = _evaluate(
            is_eligible_override=True,
            lifecycle_phase=LifecyclePhase.REACTIVE_SUPPORT,
        )

        assert outcome is EligibilityOutcome.OVERRIDE_PRESERVED

    def test_override_precedes_a_below_threshold_score(self) -> None:
        outcome = _evaluate(
            is_eligible_override=True,
            cvss_threshold=Decimal("9.0"),
            eligibility_score=_suse("1.0"),
        )

        assert outcome is EligibilityOutcome.OVERRIDE_PRESERVED


# ---------------------------------------------------------------------------
# Rule 2 — Reactive Support and other lifecycle phases
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestLifecycleRule:
    @pytest.mark.parametrize("threshold", _THRESHOLDS)
    @pytest.mark.parametrize("score", _SCORES, ids=lambda s: f"{s.score}-{s.source}")
    def test_reactive_support_is_ineligible_regardless_of_score(
        self, threshold: Decimal | None, score: EligibilityResolution
    ) -> None:
        outcome = _evaluate(
            lifecycle_phase=LifecyclePhase.REACTIVE_SUPPORT,
            cvss_threshold=threshold,
            eligibility_score=score,
        )

        assert outcome is EligibilityOutcome.INELIGIBLE

    def test_reactive_support_forces_false_even_with_the_fallback(self) -> None:
        outcome = _evaluate(
            lifecycle_phase=LifecyclePhase.REACTIVE_SUPPORT,
            eligibility_score=resolve_eligibility_score([], "3.1"),
        )

        assert outcome.automatic_eligible is False

    @pytest.mark.parametrize("phase", _NON_REACTIVE_PHASES)
    def test_other_phases_and_null_force_nothing(
        self, phase: LifecyclePhase | None
    ) -> None:
        """`None` (lifecycle unavailable) and every non-reactive phase,
        including `eol`, leave the threshold comparison in control."""
        eligible = _evaluate(
            lifecycle_phase=phase,
            cvss_threshold=Decimal("7.0"),
            eligibility_score=_suse("7.0"),
        )
        ineligible = _evaluate(
            lifecycle_phase=phase,
            cvss_threshold=Decimal("7.0"),
            eligibility_score=_suse("6.9"),
        )

        assert eligible is EligibilityOutcome.ELIGIBLE
        assert ineligible is EligibilityOutcome.INELIGIBLE

    def test_eol_does_not_exclude_an_otherwise_eligible_product(self) -> None:
        outcome = _evaluate(
            lifecycle_phase=LifecyclePhase.EOL,
            cvss_threshold=None,
            eligibility_score=_suse("0.0"),
        )

        assert outcome is EligibilityOutcome.ELIGIBLE


# ---------------------------------------------------------------------------
# Rules 3-5 — threshold, score, comparison
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestThresholdComparison:
    def test_implicit_threshold_is_zero(self) -> None:
        assert Decimal("0.0") == IMPLICIT_CVSS_THRESHOLD

    @pytest.mark.parametrize("score", _SCORES, ids=lambda s: f"{s.score}-{s.source}")
    def test_null_threshold_behaves_as_explicit_zero(
        self, score: EligibilityResolution
    ) -> None:
        implicit = _evaluate(cvss_threshold=None, eligibility_score=score)
        explicit = _evaluate(cvss_threshold=Decimal("0.0"), eligibility_score=score)

        assert implicit is explicit is EligibilityOutcome.ELIGIBLE

    def test_null_threshold_makes_a_zero_score_eligible(self) -> None:
        outcome = _evaluate(cvss_threshold=None, eligibility_score=_suse("0.0"))

        assert outcome.automatic_eligible is True

    def test_score_below_threshold_is_ineligible(self) -> None:
        outcome = _evaluate(
            cvss_threshold=Decimal("7.0"), eligibility_score=_suse("6.9")
        )

        assert outcome is EligibilityOutcome.INELIGIBLE
        assert outcome.automatic_eligible is False

    def test_score_equal_to_threshold_is_eligible(self) -> None:
        outcome = _evaluate(
            cvss_threshold=Decimal("7.0"), eligibility_score=_suse("7.0")
        )

        assert outcome is EligibilityOutcome.ELIGIBLE
        assert outcome.automatic_eligible is True

    def test_score_above_threshold_is_eligible(self) -> None:
        outcome = _evaluate(
            cvss_threshold=Decimal("7.0"), eligibility_score=_suse("7.1")
        )

        assert outcome is EligibilityOutcome.ELIGIBLE

    def test_maximum_threshold_is_met_only_by_ten(self) -> None:
        assert (
            _evaluate(cvss_threshold=Decimal("10.0"), eligibility_score=_suse("9.9"))
            is EligibilityOutcome.INELIGIBLE
        )
        assert (
            _evaluate(cvss_threshold=Decimal("10.0"), eligibility_score=_suse("10.0"))
            is EligibilityOutcome.ELIGIBLE
        )

    def test_fallback_score_of_ten_meets_every_threshold(self) -> None:
        fallback = resolve_eligibility_score([], "4.0")

        assert fallback.source is EligibilitySource.FALLBACK
        for threshold in _THRESHOLDS:
            outcome = _evaluate(cvss_threshold=threshold, eligibility_score=fallback)
            assert outcome is EligibilityOutcome.ELIGIBLE

    def test_score_source_does_not_affect_the_result(self) -> None:
        for threshold in _THRESHOLDS:
            suse = _evaluate(
                cvss_threshold=threshold,
                eligibility_score=EligibilityResolution(
                    score=Decimal("10.0"), source=EligibilitySource.SUSE
                ),
            )
            fallback = _evaluate(
                cvss_threshold=threshold,
                eligibility_score=EligibilityResolution(
                    score=Decimal("10.0"), source=EligibilitySource.FALLBACK
                ),
            )
            assert suse is fallback

    def test_comparison_is_exact_decimal_just_below_threshold(self) -> None:
        """A float conversion would round the score up to 7.0 and wrongly
        report eligibility."""
        score = Decimal("6.99999999999999999999")
        assert float(score) == 7.0

        outcome = _evaluate(
            cvss_threshold=Decimal("7.0"), eligibility_score=_suse(str(score))
        )

        assert outcome is EligibilityOutcome.INELIGIBLE

    def test_comparison_is_exact_decimal_just_above_score(self) -> None:
        threshold = Decimal("7.00000000000000000001")
        assert float(threshold) == 7.0

        outcome = _evaluate(cvss_threshold=threshold, eligibility_score=_suse("7.0"))

        assert outcome is EligibilityOutcome.INELIGIBLE

    def test_comparison_ignores_decimal_exponent_representation(self) -> None:
        outcome = _evaluate(
            cvss_threshold=Decimal("7.00"), eligibility_score=_suse("7.0")
        )

        assert outcome is EligibilityOutcome.ELIGIBLE


# ---------------------------------------------------------------------------
# Result type and evaluator contract
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestEligibilityOutcome:
    def test_members(self) -> None:
        assert {member.value for member in EligibilityOutcome} == {
            "override_preserved",
            "eligible",
            "ineligible",
        }

    def test_automatic_eligible_mapping(self) -> None:
        assert EligibilityOutcome.OVERRIDE_PRESERVED.automatic_eligible is None
        assert EligibilityOutcome.ELIGIBLE.automatic_eligible is True
        assert EligibilityOutcome.INELIGIBLE.automatic_eligible is False


@pytest.mark.unit
class TestEvaluateProductEligibility:
    def test_signature_is_exactly_the_four_specified_inputs(self) -> None:
        """Ticket status, affectedness, delivery, release state, EOL-as-
        exclusion, and exclusion markers are not evaluator inputs."""
        parameters = inspect.signature(evaluate_product_eligibility).parameters

        assert list(parameters) == [
            "is_eligible_override",
            "lifecycle_phase",
            "cvss_threshold",
            "eligibility_score",
        ]
        assert all(
            p.kind is inspect.Parameter.KEYWORD_ONLY for p in parameters.values()
        )

    def test_outcome_is_exhaustive_over_the_input_space(self) -> None:
        for override in (False, True):
            for phase in _ALL_PHASES:
                for threshold in _THRESHOLDS:
                    for score in _SCORES:
                        outcome = _evaluate(
                            is_eligible_override=override,
                            lifecycle_phase=phase,
                            cvss_threshold=threshold,
                            eligibility_score=score,
                        )
                        assert type(outcome) is EligibilityOutcome


# ---------------------------------------------------------------------------
# Module boundary
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestProductEligibilityModuleBoundary:
    def test_imports_only_core_enums_and_pure_cvss(self) -> None:
        """Importable by `package_service` and `ticket_mutations` without
        either importing the other."""
        modules = imported_modules(
            APP_ROOT / "services" / "product_eligibility.py", "app.services"
        )

        assert {m for m in modules if m.startswith("app.")} == {
            "app.core.enums",
            "app.services.cvss",
        }

    def test_imports_no_model_settings_or_io(self) -> None:
        modules = imported_modules(
            APP_ROOT / "services" / "product_eligibility.py", "app.services"
        )

        assert forbidden_imports(modules) == set()

    def test_public_function_is_synchronous(self) -> None:
        assert not inspect.iscoroutinefunction(
            product_eligibility.evaluate_product_eligibility
        )
