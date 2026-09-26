"""Tests for the pure Product lifecycle-phase evaluator.

Owning specification: `docs/features/packages/product-catalog.md`
(Product Lifecycle Phases, Lifecycle Evaluator) and
`docs/features/packages/product-lifecycle-transitions.md` (Lifecycle
Authority and Effects). The curated cases and the combinatorial grid come
from the shared matrix in `tests/support/lifecycle_matrix.py`, which the
Product query service's Python/SQL parity test reuses.
"""

from __future__ import annotations

import inspect
import itertools
from collections.abc import Iterable
from datetime import date

import pytest

from app.core.enums import LifecyclePhase
from app.services import product_lifecycle
from app.services.product_lifecycle import evaluate_product_lifecycle_phase
from tests.support.lifecycle_matrix import (
    CONSISTENCY_VIOLATIONS,
    GRID_DATES,
    LIFECYCLE_CASES,
    ONE_DAY,
    LifecycleCase,
    LifecycleInputs,
    grid_evaluation_dates,
    lifecycle_grid,
)
from tests.support.module_imports import APP_ROOT, forbidden_imports, imported_modules

_PHASE_ORDER = list(LifecyclePhase)


def _evaluate(inputs: LifecycleInputs) -> LifecyclePhase | None:
    return evaluate_product_lifecycle_phase(**inputs.evaluator_kwargs())


def _dates_of(inputs: LifecycleInputs) -> tuple[date | None, ...]:
    return (
        inputs.first_customer_ship_date,
        inputs.general_support_end_date,
        inputs.extended_support_end_date,
        inputs.reactive_support_end_date,
    )


def _violations(inputs: LifecycleInputs) -> set[str]:
    """The consistency rules broken by a date set, stated independently."""
    fcs, gs, extended, reactive = _dates_of(inputs)
    broken: set[str] = set()
    if extended is not None and gs is None:
        broken.add("extended_without_general_support_end")
    if reactive is not None and extended is None:
        broken.add("reactive_without_extended_end")
    if fcs is not None and gs is not None and fcs > gs:
        broken.add("fcs_after_general_support_end")
    if gs is not None and extended is not None and gs > extended:
        broken.add("general_support_end_after_extended_end")
    if extended is not None and reactive is not None and extended > reactive:
        broken.add("extended_end_after_reactive_end")
    return broken


def _reference_phase(inputs: LifecycleInputs) -> LifecyclePhase | None:
    """Independent interval-containment formulation of the evaluator.

    Each phase owns the closed interval from the day after the previous
    phase's end to its own inclusive end; General Support starts at FCS
    (or unbounded without FCS); `pre_release` is everything before FCS; EOL
    is everything after the last available end. An empty interval (start
    after end) contains no date.
    """
    if _violations(inputs):
        return None
    fcs, gs, extended, reactive = _dates_of(inputs)
    day = inputs.evaluation_date
    intervals: list[tuple[LifecyclePhase, date | None, date | None]] = []
    if fcs is not None:
        intervals.append((LifecyclePhase.PRE_RELEASE, None, fcs - ONE_DAY))
    previous_end: date | None = None
    for phase, end in (
        (LifecyclePhase.GENERAL_SUPPORT, gs),
        (LifecyclePhase.EXTENDED_SUPPORT, extended),
        (LifecyclePhase.REACTIVE_SUPPORT, reactive),
    ):
        if end is None:
            break
        start = fcs if previous_end is None else previous_end + ONE_DAY
        intervals.append((phase, start, end))
        previous_end = end
    if previous_end is not None:
        intervals.append((LifecyclePhase.EOL, previous_end + ONE_DAY, None))

    containing = [
        phase
        for phase, start, end in intervals
        if (start is None or start <= day) and (end is None or day <= end)
    ]
    assert len(containing) <= 1, "phase intervals must not overlap"
    return containing[0] if containing else None


def _grid_by_date_set() -> Iterable[list[LifecycleInputs]]:
    """Grid inputs grouped per date set, in ascending evaluation date."""
    rows = sorted(
        lifecycle_grid(), key=lambda i: (str(_dates_of(i)), i.evaluation_date)
    )
    for _, group in itertools.groupby(rows, key=lambda i: str(_dates_of(i))):
        yield list(group)


# ---------------------------------------------------------------------------
# Curated matrix
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestLifecycleMatrix:
    @pytest.mark.parametrize("case", LIFECYCLE_CASES, ids=lambda c: c.id)
    def test_matrix_phase(self, case: LifecycleCase) -> None:
        assert evaluate_product_lifecycle_phase(**case.evaluator_kwargs()) == (
            case.expected
        )

    def test_matrix_covers_every_phase_and_null(self) -> None:
        assert {case.expected for case in LIFECYCLE_CASES} == {*LifecyclePhase, None}

    def test_matrix_covers_every_consistency_violation_as_null(self) -> None:
        inconsistent = [c for c in LIFECYCLE_CASES if c.violation is not None]

        assert {c.violation for c in inconsistent} == set(CONSISTENCY_VIOLATIONS)
        assert len(CONSISTENCY_VIOLATIONS) == 5
        assert all(c.expected is None for c in inconsistent)

    def test_matrix_violation_labels_match_the_dates(self) -> None:
        """A row's `violation` label is exactly the rule its dates break,
        and every row without a label is consistent."""
        for case in LIFECYCLE_CASES:
            expected = set() if case.violation is None else {case.violation}
            assert _violations(case.inputs) == expected, case.id

    def test_each_violation_is_null_before_inside_and_after_its_dates(self) -> None:
        for violation in CONSISTENCY_VIOLATIONS:
            days = sorted(
                c.inputs.evaluation_date
                for c in LIFECYCLE_CASES
                if c.violation == violation
            )
            chain = [
                d
                for c in LIFECYCLE_CASES
                if c.violation == violation
                for d in _dates_of(c.inputs)
                if d is not None
            ]
            assert days[0] < min(chain)
            assert days[-1] > max(chain)

    def test_matrix_case_ids_are_unique(self) -> None:
        ids = [case.id for case in LIFECYCLE_CASES]

        assert len(ids) == len(set(ids))

    def test_matrix_expectations_are_independent_of_the_module(self) -> None:
        """The shared matrix must never compute expectations with the code
        under test, or the Python/SQL parity test becomes circular."""
        modules = imported_modules(
            APP_ROOT.parent / "tests" / "support" / "lifecycle_matrix.py",
            "tests.support",
        )

        assert {m for m in modules if m.startswith("app.")} == {"app.core.enums"}


# ---------------------------------------------------------------------------
# Combinatorial grid
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestLifecycleGrid:
    def test_grid_is_the_complete_cartesian_product(self) -> None:
        grid = list(lifecycle_grid())
        evaluation_dates = grid_evaluation_dates()

        assert len(GRID_DATES) == 3
        assert GRID_DATES[1] == GRID_DATES[0] + ONE_DAY
        assert len(evaluation_dates) == 7
        assert len(grid) == 4**4 * len(evaluation_dates)
        assert len(set(grid)) == len(grid)

    def test_grid_contains_consistent_and_every_inconsistent_kind(self) -> None:
        broken = {v for inputs in lifecycle_grid() for v in _violations(inputs)}

        assert broken == set(CONSISTENCY_VIOLATIONS)
        assert any(not _violations(inputs) for inputs in lifecycle_grid())

    def test_grid_matches_independent_interval_formulation(self) -> None:
        mismatches = [
            inputs
            for inputs in lifecycle_grid()
            if _evaluate(inputs) != _reference_phase(inputs)
        ]

        assert mismatches == []

    def test_grid_inconsistent_sets_are_null_for_every_date(self) -> None:
        for inputs in lifecycle_grid():
            if _violations(inputs):
                assert _evaluate(inputs) is None, inputs

    def test_grid_eol_only_after_the_last_end_of_a_consistent_chain(self) -> None:
        for inputs in lifecycle_grid():
            if _evaluate(inputs) is not LifecyclePhase.EOL:
                continue
            ends = [d for d in _dates_of(inputs)[1:] if d is not None]
            assert not _violations(inputs), inputs
            assert ends, inputs
            assert inputs.evaluation_date > max(ends), inputs

    def test_grid_phases_never_move_backwards_in_time(self) -> None:
        """Per date set, non-NULL phases are chronologically non-decreasing
        and NULL is never followed by a phase."""
        for rows in _grid_by_date_set():
            phases = [_evaluate(inputs) for inputs in rows]
            seen_null = False
            previous = -1
            for phase in phases:
                if phase is None:
                    seen_null = True
                    continue
                assert not seen_null, rows[0]
                assert _PHASE_ORDER.index(phase) >= previous, rows[0]
                previous = _PHASE_ORDER.index(phase)

    def test_grid_consistent_set_with_gs_end_always_has_a_phase(self) -> None:
        for inputs in lifecycle_grid():
            if not _violations(inputs) and inputs.general_support_end_date is not None:
                assert _evaluate(inputs) is not None, inputs


# ---------------------------------------------------------------------------
# Contract details
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestEvaluateProductLifecyclePhase:
    def test_signature_is_exactly_the_four_dates_and_evaluation_date(self) -> None:
        parameters = inspect.signature(evaluate_product_lifecycle_phase).parameters

        assert list(parameters) == [
            "evaluation_date",
            "first_customer_ship_date",
            "general_support_end_date",
            "extended_support_end_date",
            "reactive_support_end_date",
        ]
        assert all(
            p.kind is inspect.Parameter.KEYWORD_ONLY for p in parameters.values()
        )

    def test_result_is_a_lifecycle_phase_member_or_none(self) -> None:
        for inputs in lifecycle_grid():
            result = _evaluate(inputs)
            assert result is None or type(result) is LifecyclePhase

    def test_is_deterministic(self) -> None:
        for case in LIFECYCLE_CASES:
            first = evaluate_product_lifecycle_phase(**case.evaluator_kwargs())
            second = evaluate_product_lifecycle_phase(**case.evaluator_kwargs())
            assert first == second


# ---------------------------------------------------------------------------
# Module boundary
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestProductLifecycleModuleBoundary:
    def test_imports_only_core_enums(self) -> None:
        modules = imported_modules(
            APP_ROOT / "services" / "product_lifecycle.py", "app.services"
        )

        assert {m for m in modules if m.startswith("app.")} == {"app.core.enums"}

    def test_imports_no_model_settings_or_io(self) -> None:
        modules = imported_modules(
            APP_ROOT / "services" / "product_lifecycle.py", "app.services"
        )

        assert forbidden_imports(modules) == set()

    def test_public_function_is_synchronous(self) -> None:
        assert not inspect.iscoroutinefunction(
            product_lifecycle.evaluate_product_lifecycle_phase
        )
