"""Shared input matrix for the Product lifecycle-phase evaluator.

`docs/features/packages/product-catalog.md` (Lifecycle Evaluator) and
`docs/features/packages/package-model.md` (Derived Actionability) require
the pure evaluator and the Product query service's SQL lifecycle
expression to agree for every valid, incomplete, inconsistent, and
boundary-date combination. This module is the shared input for both: the
pure tests (`tests/test_services/test_product_lifecycle.py`) consume it
now, and the Python/SQL parity test consumes the same inputs once the SQL
expression exists.

Two parts:

- `LIFECYCLE_CASES` — curated rows whose expected phase is transcribed
  independently from the specification (never computed by the module
  under test).
- `lifecycle_grid()` — an expectation-free combinatorial grid over a small
  date alphabet (including adjacent days and `None`) for all four dates
  and every evaluation date around each alphabet date. Consumers compare
  implementations against each other or check invariants on it.

A persistence-backed consumer builds one `Product` row per input whose
four lifecycle date columns equal the input dates and evaluates it for
`evaluation_date`.
"""

from __future__ import annotations

import itertools
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import date, timedelta
from typing import Any, Final

from app.core.enums import LifecyclePhase

ONE_DAY: Final = timedelta(days=1)

FCS: Final = date(2024, 1, 15)
GS_END: Final = date(2026, 6, 30)
EXTENDED_END: Final = date(2029, 6, 30)
REACTIVE_END: Final = date(2031, 6, 30)
"""Fixed, strictly ordered date chain used by the curated cases."""

FAR_PAST: Final = date(2000, 1, 1)
FAR_FUTURE: Final = date(2099, 12, 31)

# The five consistency rules of the Lifecycle Evaluator, one label each.
EXTENDED_WITHOUT_GS: Final = "extended_without_general_support_end"
REACTIVE_WITHOUT_EXTENDED: Final = "reactive_without_extended_end"
FCS_AFTER_GS: Final = "fcs_after_general_support_end"
GS_AFTER_EXTENDED: Final = "general_support_end_after_extended_end"
EXTENDED_AFTER_REACTIVE: Final = "extended_end_after_reactive_end"

CONSISTENCY_VIOLATIONS: Final = (
    EXTENDED_WITHOUT_GS,
    REACTIVE_WITHOUT_EXTENDED,
    FCS_AFTER_GS,
    GS_AFTER_EXTENDED,
    EXTENDED_AFTER_REACTIVE,
)


@dataclass(frozen=True, slots=True)
class LifecycleInputs:
    """The complete input of `evaluate_product_lifecycle_phase()`."""

    evaluation_date: date
    first_customer_ship_date: date | None
    general_support_end_date: date | None
    extended_support_end_date: date | None
    reactive_support_end_date: date | None

    def evaluator_kwargs(self) -> dict[str, Any]:
        """Keyword arguments of `evaluate_product_lifecycle_phase()`."""
        return {
            "evaluation_date": self.evaluation_date,
            "first_customer_ship_date": self.first_customer_ship_date,
            "general_support_end_date": self.general_support_end_date,
            "extended_support_end_date": self.extended_support_end_date,
            "reactive_support_end_date": self.reactive_support_end_date,
        }


@dataclass(frozen=True, slots=True)
class LifecycleCase:
    """One curated row: inputs and the expected phase (`None` = `NULL`).

    `violation` names the consistency rule an inconsistent row breaks.
    """

    id: str
    inputs: LifecycleInputs
    expected: LifecyclePhase | None
    violation: str | None = None

    def evaluator_kwargs(self) -> dict[str, Any]:
        """Keyword arguments of `evaluate_product_lifecycle_phase()`."""
        return self.inputs.evaluator_kwargs()


@dataclass(frozen=True, slots=True)
class _Dates:
    fcs: date | None = None
    gs: date | None = None
    extended: date | None = None
    reactive: date | None = None


def _case(
    case_id: str,
    evaluation_date: date,
    expected: LifecyclePhase | None,
    dates: _Dates,
    violation: str | None = None,
) -> LifecycleCase:
    return LifecycleCase(
        id=case_id,
        inputs=LifecycleInputs(
            evaluation_date=evaluation_date,
            first_customer_ship_date=dates.fcs,
            general_support_end_date=dates.gs,
            extended_support_end_date=dates.extended,
            reactive_support_end_date=dates.reactive,
        ),
        expected=expected,
        violation=violation,
    )


_FULL = _Dates(fcs=FCS, gs=GS_END, extended=EXTENDED_END, reactive=REACTIVE_END)
_NONE = _Dates()

PRE = LifecyclePhase.PRE_RELEASE
GS = LifecyclePhase.GENERAL_SUPPORT
EXT = LifecyclePhase.EXTENDED_SUPPORT
RS = LifecyclePhase.REACTIVE_SUPPORT
EOL = LifecyclePhase.EOL

_CONSISTENT_CASES: tuple[LifecycleCase, ...] = (
    # --- Complete chain: each inclusive end date and the following day ------
    _case("full_far_past_pre_release", FAR_PAST, PRE, _FULL),
    _case("full_day_before_fcs_pre_release", FCS - ONE_DAY, PRE, _FULL),
    _case("full_at_fcs_general_support", FCS, GS, _FULL),
    _case("full_at_gs_end_general_support", GS_END, GS, _FULL),
    _case("full_day_after_gs_end_extended", GS_END + ONE_DAY, EXT, _FULL),
    _case("full_at_extended_end_extended", EXTENDED_END, EXT, _FULL),
    _case("full_day_after_extended_end_reactive", EXTENDED_END + ONE_DAY, RS, _FULL),
    _case("full_at_reactive_end_reactive", REACTIVE_END, RS, _FULL),
    _case("full_day_after_reactive_end_eol", REACTIVE_END + ONE_DAY, EOL, _FULL),
    _case("full_far_future_eol", FAR_FUTURE, EOL, _FULL),
    # --- Missing FCS never prevents General Support --------------------------
    _case(
        "no_fcs_far_past_general_support",
        FAR_PAST,
        GS,
        _Dates(gs=GS_END, extended=EXTENDED_END, reactive=REACTIVE_END),
    ),
    _case("gs_only_far_past_general_support", FAR_PAST, GS, _Dates(gs=GS_END)),
    _case("gs_only_at_gs_end_general_support", GS_END, GS, _Dates(gs=GS_END)),
    # --- GS end alone establishes EOL from the next day -----------------------
    _case("gs_only_day_after_gs_end_eol", GS_END + ONE_DAY, EOL, _Dates(gs=GS_END)),
    _case(
        "fcs_gs_day_after_gs_end_eol", GS_END + ONE_DAY, EOL, _Dates(fcs=FCS, gs=GS_END)
    ),
    _case(
        "fcs_gs_day_before_fcs_pre_release",
        FCS - ONE_DAY,
        PRE,
        _Dates(fcs=FCS, gs=GS_END),
    ),
    # --- Chain ending at the extended end -------------------------------------
    _case(
        "no_reactive_at_extended_end_extended",
        EXTENDED_END,
        EXT,
        _Dates(fcs=FCS, gs=GS_END, extended=EXTENDED_END),
    ),
    _case(
        "no_reactive_day_after_extended_end_eol",
        EXTENDED_END + ONE_DAY,
        EOL,
        _Dates(fcs=FCS, gs=GS_END, extended=EXTENDED_END),
    ),
    _case(
        "no_fcs_no_reactive_day_after_gs_end_extended",
        GS_END + ONE_DAY,
        EXT,
        _Dates(gs=GS_END, extended=EXTENDED_END),
    ),
    # --- FCS alone: pre_release before FCS, NULL from FCS onward -------------
    _case("fcs_only_day_before_fcs_pre_release", FCS - ONE_DAY, PRE, _Dates(fcs=FCS)),
    _case("fcs_only_at_fcs_null", FCS, None, _Dates(fcs=FCS)),
    _case("fcs_only_far_future_null", FAR_FUTURE, None, _Dates(fcs=FCS)),
    # --- All dates absent -------------------------------------------------------
    _case("all_absent_far_past_null", FAR_PAST, None, _NONE),
    _case("all_absent_far_future_null", FAR_FUTURE, None, _NONE),
    # --- Equal adjacent boundaries: the later phase has an empty interval ------
    _case(
        "fcs_equals_gs_end_day_before_pre_release",
        GS_END - ONE_DAY,
        PRE,
        _Dates(fcs=GS_END, gs=GS_END),
    ),
    _case(
        "fcs_equals_gs_end_at_date_general_support",
        GS_END,
        GS,
        _Dates(fcs=GS_END, gs=GS_END),
    ),
    _case(
        "fcs_equals_gs_end_day_after_eol",
        GS_END + ONE_DAY,
        EOL,
        _Dates(fcs=GS_END, gs=GS_END),
    ),
    _case(
        "gs_equals_extended_at_date_general_support",
        GS_END,
        GS,
        _Dates(fcs=FCS, gs=GS_END, extended=GS_END, reactive=REACTIVE_END),
    ),
    _case(
        "gs_equals_extended_day_after_skips_to_reactive",
        GS_END + ONE_DAY,
        RS,
        _Dates(fcs=FCS, gs=GS_END, extended=GS_END, reactive=REACTIVE_END),
    ),
    _case(
        "gs_equals_extended_no_reactive_day_after_eol",
        GS_END + ONE_DAY,
        EOL,
        _Dates(fcs=FCS, gs=GS_END, extended=GS_END),
    ),
    _case(
        "extended_equals_reactive_at_date_extended",
        EXTENDED_END,
        EXT,
        _Dates(fcs=FCS, gs=GS_END, extended=EXTENDED_END, reactive=EXTENDED_END),
    ),
    _case(
        "extended_equals_reactive_day_after_eol",
        EXTENDED_END + ONE_DAY,
        EOL,
        _Dates(fcs=FCS, gs=GS_END, extended=EXTENDED_END, reactive=EXTENDED_END),
    ),
    _case(
        "all_equal_day_before_pre_release",
        GS_END - ONE_DAY,
        PRE,
        _Dates(fcs=GS_END, gs=GS_END, extended=GS_END, reactive=GS_END),
    ),
    _case(
        "all_equal_at_date_general_support",
        GS_END,
        GS,
        _Dates(fcs=GS_END, gs=GS_END, extended=GS_END, reactive=GS_END),
    ),
    _case(
        "all_equal_day_after_eol",
        GS_END + ONE_DAY,
        EOL,
        _Dates(fcs=GS_END, gs=GS_END, extended=GS_END, reactive=GS_END),
    ),
)

# Each inconsistent date set, keyed by the violation it contains. Every set
# is evaluated before, inside, at, and after all of its dates: the result is
# always NULL, never `eol`.
_INCONSISTENT_SETS: tuple[tuple[str, _Dates], ...] = (
    (
        EXTENDED_WITHOUT_GS,
        _Dates(fcs=FCS, extended=EXTENDED_END, reactive=REACTIVE_END),
    ),
    (EXTENDED_WITHOUT_GS + "_extended_only", _Dates(extended=EXTENDED_END)),
    (REACTIVE_WITHOUT_EXTENDED, _Dates(fcs=FCS, gs=GS_END, reactive=REACTIVE_END)),
    (REACTIVE_WITHOUT_EXTENDED + "_reactive_only", _Dates(reactive=REACTIVE_END)),
    (FCS_AFTER_GS, _Dates(fcs=GS_END + ONE_DAY, gs=GS_END)),
    (
        FCS_AFTER_GS + "_full_chain",
        _Dates(
            fcs=GS_END + ONE_DAY,
            gs=GS_END,
            extended=EXTENDED_END,
            reactive=REACTIVE_END,
        ),
    ),
    (
        GS_AFTER_EXTENDED,
        _Dates(fcs=FCS, gs=EXTENDED_END + ONE_DAY, extended=EXTENDED_END),
    ),
    (
        EXTENDED_AFTER_REACTIVE,
        _Dates(
            fcs=FCS,
            gs=GS_END,
            extended=REACTIVE_END + ONE_DAY,
            reactive=REACTIVE_END,
        ),
    ),
)

_INCONSISTENT_EVALUATION_DATES: tuple[tuple[str, date], ...] = (
    ("far_past", FAR_PAST),
    ("at_gs_end", GS_END),
    ("day_after_extended_end", EXTENDED_END + ONE_DAY),
    ("day_after_reactive_end", REACTIVE_END + ONE_DAY),
    ("far_future", FAR_FUTURE),
)


def _violation_of(set_id: str) -> str:
    return next(v for v in CONSISTENCY_VIOLATIONS if set_id.startswith(v))


_INCONSISTENT_CASES: tuple[LifecycleCase, ...] = tuple(
    _case(
        f"inconsistent_{set_id}_{date_id}_null",
        evaluation_date,
        None,
        dates,
        violation=_violation_of(set_id),
    )
    for set_id, dates in _INCONSISTENT_SETS
    for date_id, evaluation_date in _INCONSISTENT_EVALUATION_DATES
)

LIFECYCLE_CASES: tuple[LifecycleCase, ...] = _CONSISTENT_CASES + _INCONSISTENT_CASES
"""Every curated row. Case ids are unique."""


GRID_DATES: Final[tuple[date, ...]] = (
    date(2025, 3, 1),
    date(2025, 3, 2),
    date(2025, 6, 30),
)
"""Grid date alphabet: two adjacent days and one later day."""


def grid_evaluation_dates() -> tuple[date, ...]:
    """The day before, the day of, and the day after each grid date, sorted."""
    return tuple(
        sorted({d + offset * ONE_DAY for d in GRID_DATES for offset in (-1, 0, 1)})
    )


def lifecycle_grid() -> Iterator[LifecycleInputs]:
    """Every combination of `GRID_DATES` or `None` for the four dates, for
    every date of `grid_evaluation_dates()` (1792 inputs, no expectations).

    Includes consistent, incomplete, inconsistent, and equal-boundary sets.
    """
    choices: tuple[date | None, ...] = (*GRID_DATES, None)
    for fcs, gs, extended, reactive in itertools.product(choices, repeat=4):
        for evaluation_date in grid_evaluation_dates():
            yield LifecycleInputs(
                evaluation_date=evaluation_date,
                first_customer_ship_date=fcs,
                general_support_end_date=gs,
                extended_support_end_date=extended,
                reactive_support_end_date=reactive,
            )
