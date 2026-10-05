"""Pure projection of the Ticket Analyzed and Resolved gates.

Evaluates the exact gate predicates of `docs/features/tickets/tickets.md`
(Gate: Analysis → Analyzed, Gate: Analyzed → Resolved, Deterministic Gate
Edge Cases) over supplied inputs instead of persisted rows. It is the
read-only twin of `ticket_mutations.gate_status_expression()`, which stays
the one SQL form used by reconciliation; both forms must agree for every
input (shared matrix: `tests/support/gate_matrix.py`).

Its consumer is the default-CVSS impact preview
(`docs/features/platform/default-cvss-version-operations.md`, Projected
Impact), which supplies projected severity and projected effective Product
eligibility (tickets.md, Read-Only Gate Projection).

Actionability composes the pure `package_actionability` twins, so manual
exclusion and lifecycle combine only through the canonical predicates of
`docs/features/packages/package-model.md` (Derived Actionability, Gate
Participation). Delivery status, Ticket status, assignment, and audit
history are not inputs.

Category B: no database access, write, audit, lock, or external call.
Imports only Core enums and the pure actionability module.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from app.core.enums import LifecyclePhase, PackageStatus, TicketStatus
from app.services.package_actionability import (
    product_non_actionable_reason,
    track_non_actionable_reason,
)

_UNCONDITIONALLY_COMPLETE = frozenset(
    {PackageStatus.NOT_AFFECTED, PackageStatus.WONT_FIX}
)


@dataclass(frozen=True, slots=True)
class GateProductInput:
    """One `TicketPackageProduct` occurrence as a gate input.

    `excluded` states whether the occurrence's own `deleted_at` is set;
    `lifecycle_phase` is the catalog Product's phase on the caller's
    `evaluation_date` (`None` when unavailable); `eligible` is the
    effective eligibility the gate observes; `released` states whether
    `released_at` is set.
    """

    excluded: bool
    lifecycle_phase: LifecyclePhase | None
    eligible: bool
    released: bool


@dataclass(frozen=True, slots=True)
class GateTrackInput:
    """One `TicketPackageTrack` as a gate input.

    `package_excluded` and `track_excluded` state whether the parent
    package's and the track's own `deleted_at` are set; `status` is the
    track affectedness; `products` are all of the track's occurrences,
    excluded ones included.
    """

    package_excluded: bool
    track_excluded: bool
    status: PackageStatus
    products: tuple[GateProductInput, ...]


def project_gate_status(
    *,
    tracks: Iterable[GateTrackInput],
    has_cve: bool,
    severity_resolved: bool,
    has_canonical_suse_assessment: bool,
) -> TicketStatus:
    """Return the highest valid gate-zone status for the supplied inputs.

    `tracks` is the Ticket's complete track set; `has_cve` states whether
    the Ticket has an associated CVE; `severity_resolved` whether its
    resolved severity is not `NULL`; `has_canonical_suse_assessment`
    whether a canonical `SUSE` assessment exists in an accepted CVSS
    version (ignored for a Ticket without a CVE).

    Returns `Resolved` when the Analyzed predicate and universal resolution
    completeness over the actionable tracks hold, `Analyzed` when only the
    Analyzed predicate holds, and otherwise the `Analysis` floor; never
    `New` or a manual-zone status. Infallible.
    """
    has_manually_included = False
    actionable: list[tuple[GateTrackInput, list[GateProductInput]]] = []
    for track in tracks:
        if not track.package_excluded and not track.track_excluded:
            has_manually_included = True
        actionable_products = [
            product
            for product in track.products
            if product_non_actionable_reason(
                package_excluded=track.package_excluded,
                track_excluded=track.track_excluded,
                product_excluded=product.excluded,
                lifecycle_phase=product.lifecycle_phase,
            )
            is None
        ]
        if (
            track_non_actionable_reason(
                package_excluded=track.package_excluded,
                track_excluded=track.track_excluded,
                has_actionable_product=bool(actionable_products),
            )
            is None
        ):
            actionable.append((track, actionable_products))

    analyzed = (
        has_manually_included
        and all(track.status is not PackageStatus.ANALYSIS for track, _ in actionable)
        and severity_resolved
        and (not has_cve or has_canonical_suse_assessment)
    )
    if not analyzed:
        return TicketStatus.ANALYSIS
    if all(
        _resolution_complete(track, products, has_cve=has_cve)
        for track, products in actionable
    ):
        return TicketStatus.RESOLVED
    return TicketStatus.ANALYZED


def _resolution_complete(
    track: GateTrackInput,
    actionable_products: list[GateProductInput],
    *,
    has_cve: bool,
) -> bool:
    """Whether one actionable track is resolution-complete.

    `AEP(t)` is the set of actionable Products whose effective
    eligibility is true (tickets.md, Gate: Analyzed → Resolved).
    """
    if track.status in _UNCONDITIONALLY_COMPLETE:
        return True
    eligible = [product for product in actionable_products if product.eligible]
    if track.status is PackageStatus.FIXED:
        return not has_cve or all(product.released for product in eligible)
    # An actionable `ANALYSIS` track is never resolution-complete.
    return track.status is PackageStatus.AFFECTED and not eligible
