"""Pure automatic Product eligibility evaluator.

The one shared implementation of the ordered automatic eligibility rules
in `docs/features/packages/package-model.md` (Axis 2: Eligibility;
Package Eligibility > Override Model). Every creation, override-clear,
threshold, lifecycle, convergence, CVSS, and default-version workflow —
including the atomic CVSS chain in `ticket_mutations` and the read-only
default-CVSS impact preview — applies this evaluator instead of copying
the formula.

The evaluator is Category B: no database access, write, audit, lock,
logging, or external call, and no domain exception for valid typed
inputs. Its inputs are exactly the current override marker, the Product
lifecycle phase, `Product.cvss_threshold`, and the Eligibility Score
Resolution result from `services/cvss.py`. Ticket status, affectedness,
delivery, Product release state, EOL, and direct or effective manual
exclusion are deliberately not inputs: EOL and exclusion affect derived
actionability and meet eligibility only at Ticket gates.

This module imports only Core and the pure `services/cvss.py`, so
`package_service` and `ticket_mutations` may both use it without either
importing the other.
"""

from __future__ import annotations

from decimal import Decimal
from enum import StrEnum
from typing import Final

from app.core.enums import LifecyclePhase
from app.services.cvss import EligibilityResolution

IMPLICIT_CVSS_THRESHOLD: Final = Decimal("0.0")
"""Threshold applied when `Product.cvss_threshold` is `NULL`."""


class EligibilityOutcome(StrEnum):
    """Result of the automatic eligibility evaluation of one occurrence.

    Service-internal: neither persisted nor serialized.
    `OVERRIDE_PRESERVED` means rule 1 applies: the persisted `eligible`
    value is retained, and automatic workflows skip the occurrence without
    changing either field or creating an eligibility event (the read-only
    preview reports it as an override skip). `ELIGIBLE` and `INELIGIBLE`
    are the automatic boolean results.
    """

    OVERRIDE_PRESERVED = "override_preserved"
    ELIGIBLE = "eligible"
    INELIGIBLE = "ineligible"

    @property
    def automatic_eligible(self) -> bool | None:
        """The automatic `eligible` value, or `None` for a preserved override."""
        if self is EligibilityOutcome.OVERRIDE_PRESERVED:
            return None
        return self is EligibilityOutcome.ELIGIBLE


def evaluate_product_eligibility(
    *,
    is_eligible_override: bool,
    lifecycle_phase: LifecyclePhase | None,
    cvss_threshold: Decimal | None,
    eligibility_score: EligibilityResolution,
) -> EligibilityOutcome:
    """Apply the ordered automatic eligibility rules to one occurrence.

    1. `is_eligible_override` → `OVERRIDE_PRESERVED` (no automatic value).
    2. `lifecycle_phase` is `reactive_support` → `INELIGIBLE` regardless
       of score. `None` (lifecycle unavailable) and every other phase,
       including `eol`, force nothing.
    3. A `None` threshold is the implicit threshold `0.0`.
    4. The score is `eligibility_score.score` (the canonical SUSE score at
       the default CVSS version, or the `10.0` fallback).
    5. Score below the threshold → `INELIGIBLE`; otherwise (including
       equal) → `ELIGIBLE`. The comparison is exact `Decimal` arithmetic.

    Raises no exception for valid typed inputs.
    """
    if is_eligible_override:
        return EligibilityOutcome.OVERRIDE_PRESERVED
    if lifecycle_phase is LifecyclePhase.REACTIVE_SUPPORT:
        return EligibilityOutcome.INELIGIBLE
    threshold = IMPLICIT_CVSS_THRESHOLD if cvss_threshold is None else cvss_threshold
    if eligibility_score.score < threshold:
        return EligibilityOutcome.INELIGIBLE
    return EligibilityOutcome.ELIGIBLE
