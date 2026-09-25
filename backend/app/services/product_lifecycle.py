"""Pure Product lifecycle-phase evaluator.

Single database-free formula owner for the Product lifecycle phase. See
`docs/features/packages/product-catalog.md` (Product Lifecycle Phases,
Lifecycle Evaluator) for the complete contract and
`docs/features/packages/product-lifecycle-transitions.md` (Lifecycle
Authority and Effects) for how consumers use the result.

The evaluator is Category B: no database access, write, audit, lock,
logging, or external call, and no domain exception. Its result is never
persisted. It depends only on the four AIMAAS date projections and one
UTC calendar `evaluation_date`; SMELT catalog presence, Ticket state,
eligibility, and any previously derived phase are not inputs. All inputs
are calendar dates, so no date-time or timezone conversion is involved.

The Product query service owns an equivalent reusable SQL expression;
both forms must agree for every valid, incomplete, inconsistent, and
boundary-date combination (shared matrix: `tests/support/lifecycle_matrix.py`).

This module imports no other service module, so `package_service`,
`ticket_mutations`, and the Product query service may all use it without
a dependency cycle.
"""

from __future__ import annotations

from datetime import date

from app.core.enums import LifecyclePhase


def _is_consistent(
    first_customer_ship_date: date | None,
    general_support_end_date: date | None,
    extended_support_end_date: date | None,
    reactive_support_end_date: date | None,
) -> bool:
    """Whether the available dates form one valid continuous chain."""
    if extended_support_end_date is not None and general_support_end_date is None:
        return False
    if reactive_support_end_date is not None and extended_support_end_date is None:
        return False
    if (
        first_customer_ship_date is not None
        and general_support_end_date is not None
        and first_customer_ship_date > general_support_end_date
    ):
        return False
    if (
        general_support_end_date is not None
        and extended_support_end_date is not None
        and general_support_end_date > extended_support_end_date
    ):
        return False
    return not (
        extended_support_end_date is not None
        and reactive_support_end_date is not None
        and extended_support_end_date > reactive_support_end_date
    )


def evaluate_product_lifecycle_phase(
    *,
    evaluation_date: date,
    first_customer_ship_date: date | None,
    general_support_end_date: date | None,
    extended_support_end_date: date | None,
    reactive_support_end_date: date | None,
) -> LifecyclePhase | None:
    """Derive the lifecycle phase of one Product on one UTC calendar date.

    Every phase-end date is inclusive and the following phase begins on
    the next calendar day; equal adjacent boundaries give the later phase
    an empty interval.

    The available dates are first validated: an extended end requires a
    General Support end, a reactive end requires an extended end, and
    each present date must be no later than the next present date of
    FCS <= GS end <= extended end <= reactive end. Any violation makes
    the complete set inconsistent and the result is `None` for every
    `evaluation_date` (never `eol`).

    For a consistent set, in order: before FCS → `pre_release`; up to the
    GS end → `general_support` (even without FCS); up to the extended end
    → `extended_support`; up to the reactive end → `reactive_support`;
    after the last available end date of the chain → `eol`; otherwise
    `None` (an FCS date without any end date yields `None` from FCS
    onward, and all dates absent yields `None`).

    Returns the phase, or `None` when the phase is unavailable. Raises no
    exception for valid typed inputs.
    """
    if not _is_consistent(
        first_customer_ship_date,
        general_support_end_date,
        extended_support_end_date,
        reactive_support_end_date,
    ):
        return None

    # Rule 1.
    if (
        first_customer_ship_date is not None
        and evaluation_date < first_customer_ship_date
    ):
        return LifecyclePhase.PRE_RELEASE
    # Rule 2. A missing FCS date does not prevent this result.
    if (
        general_support_end_date is not None
        and evaluation_date <= general_support_end_date
    ):
        return LifecyclePhase.GENERAL_SUPPORT
    # Rule 3. Consistency guarantees the GS end exists; rule 2 failing
    # guarantees the evaluation date is after it.
    if (
        extended_support_end_date is not None
        and evaluation_date <= extended_support_end_date
    ):
        return LifecyclePhase.EXTENDED_SUPPORT
    # Rule 4. Consistency guarantees the extended end exists; rule 3
    # failing guarantees the evaluation date is after it.
    if (
        reactive_support_end_date is not None
        and evaluation_date <= reactive_support_end_date
    ):
        return LifecyclePhase.REACTIVE_SUPPORT
    # Rule 5. The last available end date of the valid continuous chain.
    last_end_date = (
        reactive_support_end_date
        or extended_support_end_date
        or general_support_end_date
    )
    if last_end_date is not None and evaluation_date > last_end_date:
        return LifecyclePhase.EOL
    # Rule 6.
    return None
