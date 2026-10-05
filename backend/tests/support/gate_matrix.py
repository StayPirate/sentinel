"""Shared input matrix for the Ticket gate: pure projection vs SQL.

`docs/features/tickets/tickets.md` (Read-Only Gate Projection) requires the
read-only gate projection to reuse the exact Analyzed and Resolved
predicates. The pure projection
(`app.services.ticket_gate_projection.project_gate_status()`) and the SQL
form evaluated by reconciliation
(`app.services.ticket_mutations.gate_status_expression()`) must therefore
agree for every input. This module is the shared input for both: the pure
tests and the persistence-backed parity test
(`tests/test_services/test_ticket_gate_projection.py`) consume the same
cases.

Two parts:

- `GATE_CASES` — curated rows covering tickets.md § Deterministic Gate Edge
  Cases and testing-strategy.md § Service Functions (gate formulas); each
  expected status is transcribed independently from the specifications,
  never computed by the module under test.
- `gate_grid()` — an expectation-free combinatorial grid of one-track trees
  over every affectedness, the three direct-marker shapes, and Product
  multisets from a small alphabet, with and without a CVE. Consumers compare
  the two implementations against each other.

A persistence-backed consumer builds one Ticket per case: one package per
`MatrixTrack` (the gate never aggregates per package, so a per-track
package marker is representative), one catalog Product per `MatrixProduct`
whose lifecycle dates yield `phase` on the fixed evaluation date, and stores
`MatrixProduct.eligible` as the persisted (effective) `eligible` value.
"""

from __future__ import annotations

import itertools
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Final

from app.core.enums import LifecyclePhase, PackageStatus, TicketStatus
from app.services.ticket_gate_projection import GateProductInput, GateTrackInput

GS: Final = LifecyclePhase.GENERAL_SUPPORT
EOL: Final = LifecyclePhase.EOL
REACTIVE: Final = LifecyclePhase.REACTIVE_SUPPORT

SUPPORTED_PHASES: Final = frozenset({GS, EOL, REACTIVE, None})
"""Phases a persistence-backed consumer can build on the evaluation date."""

ANALYSIS: Final = TicketStatus.ANALYSIS
ANALYZED: Final = TicketStatus.ANALYZED
RESOLVED: Final = TicketStatus.RESOLVED


@dataclass(frozen=True, slots=True)
class MatrixProduct:
    """One Product occurrence.

    `eligible` is the effective eligibility the gate observes; `override`
    is only the persisted marker, which the gate does not read (an override
    participates through `eligible`). `phase=None` is lifecycle-unavailable.
    """

    eligible: bool = True
    excluded: bool = False
    released: bool = False
    phase: LifecyclePhase | None = GS
    override: bool = False


@dataclass(frozen=True, slots=True)
class MatrixTrack:
    """One track under its own package."""

    status: PackageStatus
    products: tuple[MatrixProduct, ...] = (MatrixProduct(),)
    package_excluded: bool = False
    track_excluded: bool = False


@dataclass(frozen=True, slots=True)
class GateCase:
    """One Ticket's gate inputs.

    `has_suse` states whether a canonical SUSE assessment exists; it is
    only meaningful with `has_cve`. `expected` is `None` for grid rows.
    """

    name: str
    tracks: tuple[MatrixTrack, ...]
    expected: TicketStatus | None
    has_cve: bool = True
    severity_resolved: bool = True
    has_suse: bool = True


def pure_inputs(case: GateCase) -> tuple[GateTrackInput, ...]:
    """The case's tracks as pure projection inputs."""
    return tuple(
        GateTrackInput(
            package_excluded=track.package_excluded,
            track_excluded=track.track_excluded,
            status=track.status,
            products=tuple(
                GateProductInput(
                    excluded=product.excluded,
                    lifecycle_phase=product.phase,
                    eligible=product.eligible,
                    released=product.released,
                )
                for product in track.products
            ),
        )
        for track in case.tracks
    )


_P = MatrixProduct
_T = MatrixTrack
_S = PackageStatus


def _both(
    name: str, tracks: tuple[MatrixTrack, ...], expected: TicketStatus
) -> list[GateCase]:
    """The same tree with a CVE (SUSE present) and without one."""
    return [
        GateCase(f"{name}-cve", tracks, expected),
        GateCase(f"{name}-cveless", tracks, expected, has_cve=False),
    ]


GATE_CASES: Final[tuple[GateCase, ...]] = (
    # Structural condition |M| >= 1.
    *_both("empty-tree", (), ANALYSIS),
    *_both(
        "only-excluded-package",
        (_T(_S.NOT_AFFECTED, package_excluded=True),),
        ANALYSIS,
    ),
    *_both(
        "only-excluded-track", (_T(_S.NOT_AFFECTED, track_excluded=True),), ANALYSIS
    ),
    # Manually included but non-actionable trees resolve by empty-set
    # universal quantification.
    *_both(
        "all-eol",
        (
            _T(_S.ANALYSIS, (_P(phase=EOL),)),
            _T(_S.AFFECTED, (_P(phase=EOL),)),
        ),
        RESOLVED,
    ),
    *_both("track-without-products-affected", (_T(_S.AFFECTED, ()),), RESOLVED),
    *_both("track-without-products-analysis", (_T(_S.ANALYSIS, ()),), RESOLVED),
    # An actionable ANALYSIS track blocks Analyzed; a non-actionable one does
    # not.
    *_both("actionable-analysis", (_T(_S.ANALYSIS),), ANALYSIS),
    *_both(
        "analysis-with-only-excluded-product",
        (
            _T(_S.ANALYSIS, (_P(excluded=True),)),
            _T(_S.NOT_AFFECTED),
        ),
        RESOLVED,
    ),
    *_both(
        "analysis-with-eol-and-actionable-product",
        (_T(_S.ANALYSIS, (_P(phase=EOL), _P())),),
        ANALYSIS,
    ),
    # Missing lifecycle data and Reactive Support never make a Product
    # non-actionable.
    *_both(
        "missing-lifecycle-affected", (_T(_S.AFFECTED, (_P(phase=None),)),), ANALYZED
    ),
    *_both(
        "missing-lifecycle-analysis", (_T(_S.ANALYSIS, (_P(phase=None),)),), ANALYSIS
    ),
    *_both("reactive-affected", (_T(_S.AFFECTED, (_P(phase=REACTIVE),)),), ANALYZED),
    # Independently excluded descendants.
    *_both(
        "independently-excluded-descendants",
        (
            _T(_S.ANALYSIS, track_excluded=True),
            _T(_S.ANALYSIS, package_excluded=True),
            _T(_S.AFFECTED, (_P(excluded=True),)),
            _T(_S.NOT_AFFECTED),
        ),
        RESOLVED,
    ),
    *_both(
        "excluded-product-leaves-track-actionable",
        (_T(_S.AFFECTED, (_P(excluded=True), _P())),),
        ANALYZED,
    ),
    *_both(
        "eol-product-with-actionable-eligible-sibling",
        (_T(_S.AFFECTED, (_P(phase=EOL), _P())),),
        ANALYZED,
    ),
    *_both(
        "eol-product-with-actionable-ineligible-sibling",
        (_T(_S.AFFECTED, (_P(phase=EOL), _P(eligible=False))),),
        RESOLVED,
    ),
    # Final affectedness.
    *_both("not-affected", (_T(_S.NOT_AFFECTED),), RESOLVED),
    *_both("wont-fix", (_T(_S.WONT_FIX),), RESOLVED),
    *_both(
        "mixed-final-and-affected",
        (_T(_S.NOT_AFFECTED), _T(_S.AFFECTED)),
        ANALYZED,
    ),
    # Clause (b): FIXED and the publication condition.
    GateCase("fixed-unreleased-cve", (_T(_S.FIXED),), ANALYZED),
    GateCase("fixed-unreleased-cveless", (_T(_S.FIXED),), RESOLVED, has_cve=False),
    *_both("fixed-released", (_T(_S.FIXED, (_P(released=True),)),), RESOLVED),
    GateCase(
        "fixed-partially-released-cve",
        (_T(_S.FIXED, (_P(released=True), _P())),),
        ANALYZED,
    ),
    *_both(
        "fixed-only-ineligible-unreleased",
        (_T(_S.FIXED, (_P(eligible=False),)),),
        RESOLVED,
    ),
    *_both(
        "fixed-eol-unreleased-eligible",
        (_T(_S.FIXED, (_P(phase=EOL), _P(released=True))),),
        RESOLVED,
    ),
    GateCase(
        "fixed-excluded-unreleased-eligible-cve",
        (_T(_S.FIXED, (_P(excluded=True), _P(released=True))),),
        RESOLVED,
    ),
    # Clause (c): AFFECTED with an empty AEP.
    *_both("affected-eligible", (_T(_S.AFFECTED),), ANALYZED),
    *_both(
        "affected-empty-aep",
        (_T(_S.AFFECTED, (_P(eligible=False), _P(eligible=False))),),
        RESOLVED,
    ),
    # Eligibility overrides participate through the effective value.
    *_both(
        "override-false",
        (_T(_S.AFFECTED, (_P(eligible=False, override=True),)),),
        RESOLVED,
    ),
    *_both(
        "override-true",
        (_T(_S.AFFECTED, (_P(eligible=True, override=True),)),),
        ANALYZED,
    ),
    # Severity condition.
    GateCase(
        "missing-severity-cve",
        (_T(_S.NOT_AFFECTED),),
        ANALYSIS,
        severity_resolved=False,
    ),
    GateCase(
        "missing-severity-cveless",
        (_T(_S.NOT_AFFECTED),),
        ANALYSIS,
        has_cve=False,
        severity_resolved=False,
    ),
    # SUSE-assessment presence applies only to a Ticket with a CVE.
    GateCase("absent-suse-cve", (_T(_S.NOT_AFFECTED),), ANALYSIS, has_suse=False),
    GateCase(
        "absent-suse-cve-empty-tree",
        (),
        ANALYSIS,
        has_suse=False,
    ),
    GateCase(
        "absent-suse-cveless",
        (_T(_S.NOT_AFFECTED),),
        RESOLVED,
        has_cve=False,
        has_suse=False,
    ),
)


_PRODUCT_ALPHABET: Final[tuple[MatrixProduct, ...]] = (
    _P(),
    _P(released=True),
    _P(eligible=False),
    _P(phase=EOL),
    _P(excluded=True),
    _P(phase=None),
)

_MARKERS: Final = ((False, False), (True, False), (False, True))
"""`(package_excluded, track_excluded)` shapes."""


def gate_grid() -> Iterator[GateCase]:
    """Yield the expectation-free one-track grid.

    The cross product of every affectedness, the three marker shapes, every
    Product multiset of size 0 to 2 over `_PRODUCT_ALPHABET`, and with or
    without a CVE (resolved severity and a canonical SUSE assessment
    present, so the package tree decides).
    """
    multisets = [
        combo
        for size in range(3)
        for combo in itertools.combinations_with_replacement(_PRODUCT_ALPHABET, size)
    ]
    shapes = itertools.product(PackageStatus, _MARKERS, multisets, (True, False))
    for status, markers, products, has_cve in shapes:
        package_excluded, track_excluded = markers
        yield GateCase(
            f"grid-{status.value}-{int(package_excluded)}{int(track_excluded)}"
            f"-{len(products)}-{'cve' if has_cve else 'cveless'}",
            (
                _T(
                    status,
                    tuple(products),
                    package_excluded=package_excluded,
                    track_excluded=track_excluded,
                ),
            ),
            None,
            has_cve=has_cve,
        )
