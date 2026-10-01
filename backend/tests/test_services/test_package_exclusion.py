"""Single-session service integration tests for the package-tree exclusion
and restoration operations (backend/app/services/package_service.py:
`soft_delete_ticket_package[_track|_product]()` and
`restore_ticket_package[_track|_product]()`), part A.

Owning specifications:

- docs/features/packages/package-service.md (Auto-Assignment Rule; Exclusion
  and restoration operations; Exclusion and Actionability Invariant; Service
  Exceptions; Excluded and Non-Actionable Records; Architectural Test
  Requirement: Forward transitions, Backward transitions, Independent
  exclusion scopes, Auto-assignment, Derived actionability (reason
  precedence and parent actionability), Public Product identity,
  Human-readable Product audit subjects, Exclusion/restore actor).
- docs/features/packages/package-model.md (Manual Exclusion Markers,
  including the eight-combination table; Derived Actionability; Gate
  Participation; Restore; Ticket Events for Exclusion; the Soft-Delete and
  Restore Package, Track, and Product endpoint sections and their
  examples).
- docs/features/tickets/tickets.md (Gate: Analysis -> Analyzed; Gate:
  Analyzed -> Resolved; Deterministic Gate Edge Cases; Auto-Assignment on
  Unassigned Tickets).
- docs/features/tickets/ticket-audit-log.md (Event Type Contract and detail
  JSONB Schema Contract rows for package/track/product excluded/restored;
  Canonical Mutation and No-Event Matrix row "Direct package, track, or
  Product exclusion/restoration"; Cross-Event Ordering; Testing
  Requirements 1-6, 8, 12 (derived actionability), 13, 14 (repeated-call
  part)).

Unless a test states otherwise, a Ticket is CVE-less with
`severity_manual = High` and each factory-built track carries one eligible
Product in General Support on `EVAL`. The gate results follow from
tickets.md: any actionable `ANALYSIS` track gives `Analysis`; otherwise an
`AFFECTED` track with an actionable eligible Product gives `Analyzed`;
otherwise `Resolved` (with at least one manually included track). A
"pinned" Ticket additionally carries an untouched actionable `ANALYSIS`
track, so it stays in `Analysis` whatever the operation does, isolating the
direct event from any gate event.

Expected values are transcribed from the specifications, never computed
with the module under test; the derived package-tree state after an
operation is observed through the independent `get_ticket_packages()`
query with the same `evaluation_date`.
"""

from __future__ import annotations

import itertools
import json
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Any

import pytest
from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import NonActionableReason, PackageStatus, Role, Scope, TicketStatus
from app.core.exceptions import ServiceError
from app.core.identifiers import format_ticket_id
from app.models.product import Product
from app.models.ticket import Ticket
from app.models.ticket_package_product import TicketPackageProduct
from app.services.package_service import (
    PackageAlreadyExcludedError,
    PackageMarkerProjection,
    PackageNotExcludedError,
    PackageServiceError,
    ProductMarkerProjection,
    TrackMarkerProjection,
)
from app.services.ticket_audit_log import list_ticket_events
from app.services.ticket_convergence_registry import (
    TicketConvergenceEffect,
    pending_ticket_convergence_effects,
)
from app.services.ticket_visibility import TicketCaller
from tests.support.package_exclusion import (
    DIRECTIONS,
    LEVELS,
    MARKER_NOW,
    Direction,
    Level,
    State,
    assert_no_effects,
    change,
    gate_world,
    marker_event,
    markers,
    observed,
    patch_marker_now,
    with_target,
)
from tests.support.product_eligibility import (
    only_occurrence,
    product_subject,
    track_occurrences,
)
from tests.support.suse_cvss import assignment_event
from tests.support.ticket_mutations import (
    AFTER_EVAL,
    EVAL,
    EventRow,
    Prod,
    TicketFactory,
    TreeBuilder,
    VAUser,
    cveless,
    status_event,
    ticket_events,
)
from tests.support.track_status import Spy, ticket_state

pytest_plugins = ["tests.support.ticket_mutation_fixtures"]
"""Provides the shared `va_user` and `tree` fixtures."""

Factory = Callable[..., Awaitable[Any]]

PKG_EXCLUDED = NonActionableReason.PACKAGE_EXCLUDED
TRK_EXCLUDED = NonActionableReason.TRACK_EXCLUDED
PRD_EXCLUDED = NonActionableReason.PRODUCT_EXCLUDED
EOL = NonActionableReason.EOL
NO_TRACKS = NonActionableReason.NO_ACTIONABLE_TRACKS
NO_PRODUCTS = NonActionableReason.NO_ACTIONABLE_PRODUCTS

PROMOTION = status_event(TicketStatus.NEW, TicketStatus.ANALYSIS)
"""The system `New -> Analysis` event of the auto-assignment."""


@pytest.fixture(autouse=True)
def _marker_clock(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every exclusion sets its marker to the controlled `MARKER_NOW`."""
    patch_marker_now(monkeypatch)


async def _pinned(
    ticket_factory: TicketFactory, tree: TreeBuilder, **overrides: Any
) -> Ticket:
    """A CVE-less High Ticket (default `Analysis`) with an untouched
    actionable `ANALYSIS` track that keeps it in `Analysis`."""
    ticket = await cveless(ticket_factory, **overrides)
    await tree(ticket, status=PackageStatus.ANALYSIS)
    return ticket


async def _target(
    db: AsyncSession,
    tree: TreeBuilder,
    ticket: Ticket,
    *,
    package: bool = False,
    track: bool = False,
    product: bool = False,
    eol: bool = False,
    status: PackageStatus = PackageStatus.ANALYSIS,
) -> TicketPackageProduct:
    """One package with one track and one Product occurrence, with the
    given direct markers set and the Product EOL on `EVAL` if requested."""
    built = await tree(
        ticket,
        status=status,
        products=(Prod(eol=eol, excluded=product),),
        package_excluded=package,
        track_excluded=track,
    )
    return await only_occurrence(db, built)


# ---------------------------------------------------------------------------
# Independent exclusion scopes: the eight direct-marker combinations
# ---------------------------------------------------------------------------

PRODUCT_REASON: dict[tuple[bool, bool, bool], NonActionableReason | None] = {
    (False, False, False): None,
    (False, False, True): PRD_EXCLUDED,
    (False, True, False): TRK_EXCLUDED,
    (False, True, True): TRK_EXCLUDED,
    (True, False, False): PKG_EXCLUDED,
    (True, False, True): PKG_EXCLUDED,
    (True, True, False): PKG_EXCLUDED,
    (True, True, True): PKG_EXCLUDED,
}
"""package-model.md, Manual Exclusion Markers: the Product reason of each
`(package, track, Product)` direct-marker combination before lifecycle."""


def _expected_states(
    flags: tuple[bool, bool, bool], eol: bool
) -> tuple[State, State, State]:
    """The `(package, track, Product)` state of a one-track, one-Product
    package, transcribed from package-model.md: the eight-combination table
    (only the all-clear row changes to `eol` when the Product is EOL), then
    the ordered track (`package_excluded`, `track_excluded`,
    `no_actionable_products`) and package (`package_excluded`,
    `no_actionable_tracks`) reasons of Derived Actionability."""
    package_marker, track_marker, _ = flags
    product_reason = PRODUCT_REASON[flags]
    if product_reason is None and eol:
        product_reason = EOL
    product_actionable = product_reason is None
    if package_marker:
        track_reason: NonActionableReason | None = PKG_EXCLUDED
    elif track_marker:
        track_reason = TRK_EXCLUDED
    else:
        track_reason = None if product_actionable else NO_PRODUCTS
    track_actionable = track_reason is None
    if package_marker:
        package_reason: NonActionableReason | None = PKG_EXCLUDED
    else:
        package_reason = None if track_actionable else NO_TRACKS
    return (
        (package_reason is None, package_reason),
        (track_actionable, track_reason),
        (product_actionable, product_reason),
    )


def _matrix() -> list[Any]:
    """Every valid `(level, direction, markers, eol)`: an exclusion requires
    the target marker clear and a restore requires it set."""
    params = []
    for level, direction in itertools.product(Level, Direction):
        index = list(Level).index(level)
        for flags in itertools.product((False, True), repeat=3):
            if flags[index] is not (direction is Direction.RESTORE):
                continue
            for eol in (False, True):
                marks = "".join("x" if f else "-" for f in flags)
                params.append(
                    pytest.param(
                        level,
                        direction,
                        flags,
                        eol,
                        id=f"{level}-{direction}-{marks}{'-eol' if eol else ''}",
                    )
                )
    return params


@pytest.mark.integration
class TestIndependentExclusionScopes:
    """package-service.md, Exclusion and restoration operations steps 6-10
    and Architectural Test Requirement: Independent exclusion scopes (all
    eight combinations, each with and without EOL; exclusion beneath an
    excluded ancestor; parents with no actionable descendants; ancestor
    restore with directly excluded descendants; deterministic reason
    precedence). Ids spell the seeded package/track/Product markers (`x`
    set, `-` clear).

    Only the target marker changes (exclusion to the controlled current
    instant, restore to `NULL`); every derived state follows the spec
    tables; exactly one direct event is recorded, even when actionability
    was already false or stays false (ticket-audit-log.md, Testing
    Requirements 12 and 13)."""

    @pytest.mark.parametrize(("level", "direction", "flags", "eol"), _matrix())
    async def test_operation_changes_only_the_target_marker(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        tree: TreeBuilder,
        monkeypatch: pytest.MonkeyPatch,
        level: Level,
        direction: Direction,
        flags: tuple[bool, bool, bool],
        eol: bool,
    ) -> None:
        actor = await va_user()
        ticket = await _pinned(ticket_factory, tree, assignee_id=actor.id)
        package_marker, track_marker, product_marker = flags
        occurrence = await _target(
            db_session,
            tree,
            ticket,
            package=package_marker,
            track=track_marker,
            product=product_marker,
            eol=eol,
        )
        subject = await product_subject(db_session, occurrence)
        before = await markers(db_session, occurrence)
        reconcile = Spy(monkeypatch, "reconcile_ticket_status")

        result = await change(db_session, level, direction, occurrence, actor)

        index = list(Level).index(level)
        exclude = direction is Direction.EXCLUDE
        after_flags = (*flags[:index], exclude, *flags[index + 1 :])
        package_state, track_state, product_state = _expected_states(
            (after_flags[0], after_flags[1], after_flags[2]), eol
        )
        assert await markers(db_session, occurrence) == with_target(
            before, level, MARKER_NOW if exclude else None
        )
        assert await observed(db_session, occurrence) == (
            package_state,
            track_state,
            product_state,
        )
        assert (
            result.target
            == {
                Level.PACKAGE: PackageMarkerProjection(
                    subject["package"], *package_state
                ),
                Level.TRACK: TrackMarkerProjection(subject["track"], *track_state),
                Level.PRODUCT: ProductMarkerProjection(
                    occurrence.id,
                    subject["product_cpe"],
                    subject["product_name"],
                    *product_state,
                ),
            }[level]
        )
        assert result.evaluation_date == EVAL
        assert [kwargs for _, kwargs in reconcile.calls] == [{"evaluation_date": EVAL}]
        assert await ticket_events(db_session, ticket) == [
            await marker_event(db_session, level, direction, occurrence, actor)
        ]
        assert await ticket_state(db_session, ticket) == (
            TicketStatus.ANALYSIS,
            actor.id,
        )


# ---------------------------------------------------------------------------
# Specific scenarios and the package-model.md examples
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestSpecificScenarios:
    """package-model.md, Manual Exclusion Markers, Restore, and the endpoint
    examples; package-service.md, Exclusion and Actionability Invariant (no
    helper propagates exclusion; a parent without actionable descendants
    retains its `NULL` marker)."""

    async def test_track_exclusion_beneath_excluded_package_reports_package(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        tree: TreeBuilder,
    ) -> None:
        """Soft-Delete Track example: the new direct track marker is
        recorded, but the reason is `package_excluded`."""
        actor = await va_user()
        ticket = await _pinned(ticket_factory, tree, assignee_id=actor.id)
        occurrence = await _target(db_session, tree, ticket, package=True)
        package_marker, _, _ = await markers(db_session, occurrence)
        subject = await product_subject(db_session, occurrence)

        result = await change(
            db_session, Level.TRACK, Direction.EXCLUDE, occurrence, actor
        )

        assert result.target == TrackMarkerProjection(
            subject["track"], False, PKG_EXCLUDED
        )
        assert await markers(db_session, occurrence) == (
            package_marker,
            MARKER_NOW,
            None,
        )

    async def test_eol_product_excluded_under_excluded_track_then_track_restored(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        tree: TreeBuilder,
    ) -> None:
        """Soft-Delete Product example: excluding an EOL Product beneath an
        excluded track reports `track_excluded`; after the track restore the
        still directly excluded Product reports `product_excluded`, not
        `eol`, and the restored track has no actionable Product."""
        actor = await va_user()
        ticket = await _pinned(ticket_factory, tree, assignee_id=actor.id)
        occurrence = await _target(db_session, tree, ticket, track=True, eol=True)
        subject = await product_subject(db_session, occurrence)

        excluded = await change(
            db_session, Level.PRODUCT, Direction.EXCLUDE, occurrence, actor
        )
        restored = await change(
            db_session, Level.TRACK, Direction.RESTORE, occurrence, actor
        )

        assert excluded.target == ProductMarkerProjection(
            occurrence.id,
            subject["product_cpe"],
            subject["product_name"],
            False,
            TRK_EXCLUDED,
        )
        assert restored.target == TrackMarkerProjection(
            subject["track"], False, NO_PRODUCTS
        )
        assert await markers(db_session, occurrence) == (None, None, MARKER_NOW)
        assert await observed(db_session, occurrence) == (
            (False, NO_TRACKS),
            (False, NO_PRODUCTS),
            (False, PRD_EXCLUDED),
        )
        assert await ticket_events(db_session, ticket) == [
            await marker_event(
                db_session, Level.PRODUCT, Direction.EXCLUDE, occurrence, actor
            ),
            await marker_event(
                db_session, Level.TRACK, Direction.RESTORE, occurrence, actor
            ),
        ]

    @pytest.mark.parametrize(
        "descendants", ["track-excluded", "all-products-eol", "products-excluded"]
    )
    async def test_package_restore_with_non_actionable_tracks(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        tree: TreeBuilder,
        descendants: str,
    ) -> None:
        """Restore Package: the package may remain non-actionable with
        `no_actionable_tracks`; child markers are not modified (ancestor
        restore with directly excluded descendants)."""
        actor = await va_user()
        ticket = await _pinned(ticket_factory, tree, assignee_id=actor.id)
        occurrence = await _target(
            db_session,
            tree,
            ticket,
            package=True,
            track=descendants == "track-excluded",
            product=descendants in ("track-excluded", "products-excluded"),
            eol=descendants == "all-products-eol",
        )
        _, track_marker, product_marker = await markers(db_session, occurrence)
        subject = await product_subject(db_session, occurrence)

        result = await change(
            db_session, Level.PACKAGE, Direction.RESTORE, occurrence, actor
        )

        assert result.target == PackageMarkerProjection(
            subject["package"], False, NO_TRACKS
        )
        assert await markers(db_session, occurrence) == (
            None,
            track_marker,
            product_marker,
        )
        assert (
            await observed(db_session, occurrence)
            == {
                "track-excluded": (
                    (False, NO_TRACKS),
                    (False, TRK_EXCLUDED),
                    (False, TRK_EXCLUDED),
                ),
                "all-products-eol": (
                    (False, NO_TRACKS),
                    (False, NO_PRODUCTS),
                    (False, EOL),
                ),
                "products-excluded": (
                    (False, NO_TRACKS),
                    (False, NO_PRODUCTS),
                    (False, PRD_EXCLUDED),
                ),
            }[descendants]
        )

    async def test_product_restore_of_eol_product_reports_eol(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        tree: TreeBuilder,
    ) -> None:
        """Restore Product example: the restored EOL Product stays
        non-actionable with `eol`; no lifecycle pre-check applies."""
        actor = await va_user()
        ticket = await _pinned(ticket_factory, tree, assignee_id=actor.id)
        occurrence = await _target(db_session, tree, ticket, product=True, eol=True)
        subject = await product_subject(db_session, occurrence)

        result = await change(
            db_session, Level.PRODUCT, Direction.RESTORE, occurrence, actor
        )

        assert result.target == ProductMarkerProjection(
            occurrence.id,
            subject["product_cpe"],
            subject["product_name"],
            False,
            EOL,
        )
        assert await markers(db_session, occurrence) == (None, None, None)
        assert await ticket_events(db_session, ticket) == [
            await marker_event(
                db_session, Level.PRODUCT, Direction.RESTORE, occurrence, actor
            )
        ]

    @pytest.mark.parametrize("sibling", ["eol", "excluded-later"])
    async def test_parents_without_actionable_descendants_keep_null_markers(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        tree: TreeBuilder,
        sibling: str,
    ) -> None:
        """A track whose Products are all excluded or EOL reports
        `no_actionable_products` and its package `no_actionable_tracks`;
        neither parent marker is set and no track or package event is
        recorded for the derived change (ticket-audit-log.md, Testing
        Requirement 12: derived actionability)."""
        actor = await va_user()
        ticket = await _pinned(ticket_factory, tree, assignee_id=actor.id)
        track = await tree(
            ticket,
            status=PackageStatus.ANALYSIS,
            products=(Prod(), Prod(eol=sibling == "eol")),
        )
        first, second = await track_occurrences(db_session, track)
        expected_events = []

        first_result = await change(
            db_session, Level.PRODUCT, Direction.EXCLUDE, first, actor
        )
        expected_events.append(
            await marker_event(
                db_session, Level.PRODUCT, Direction.EXCLUDE, first, actor
            )
        )
        if sibling == "excluded-later":
            # The sibling is still actionable: the track remains actionable.
            assert (await observed(db_session, first))[:2] == (
                (True, None),
                (True, None),
            )
            await change(db_session, Level.PRODUCT, Direction.EXCLUDE, second, actor)
            expected_events.append(
                await marker_event(
                    db_session, Level.PRODUCT, Direction.EXCLUDE, second, actor
                )
            )

        assert (
            first_result.target.actionable,
            first_result.target.non_actionable_reason,
        ) == (
            False,
            PRD_EXCLUDED,
        )
        assert await observed(db_session, second) == (
            (False, NO_TRACKS),
            (False, NO_PRODUCTS),
            (False, EOL if sibling == "eol" else PRD_EXCLUDED),
        )
        assert (await markers(db_session, first))[:2] == (None, None)
        assert await ticket_events(db_session, ticket) == expected_events


# ---------------------------------------------------------------------------
# Direct-marker guard
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestDirectMarkerGuard:
    """package-service.md, Exclusion and restoration operations step 6 (only
    the target's locked direct marker is inspected; the guard runs before
    assignment or any durable side effect) and Re-invocation; Service
    Exceptions; ticket-audit-log.md, Testing Requirement 14 (repeated-call
    losers leave zero events and zero other durable effects).

    The Ticket is an unassigned `New` Ticket and the actor an active VA, so
    any assignment or promotion would be visible."""

    @LEVELS
    async def test_exclusion_of_directly_excluded_target_raises(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        tree: TreeBuilder,
        monkeypatch: pytest.MonkeyPatch,
        level: Level,
    ) -> None:
        actor = await va_user()
        ticket = await cveless(ticket_factory, status=TicketStatus.NEW)
        occurrence = await _target(
            db_session,
            tree,
            ticket,
            package=level is Level.PACKAGE,
            track=level is Level.TRACK,
            product=level is Level.PRODUCT,
        )

        await assert_no_effects(
            db_session,
            monkeypatch,
            lambda: change(db_session, level, Direction.EXCLUDE, occurrence, actor),
            tickets=(ticket,),
            occurrences=(occurrence,),
            error=PackageAlreadyExcludedError,
        )

    @pytest.mark.parametrize(
        ("level", "seeded"),
        [
            pytest.param(Level.PACKAGE, (), id="package-all-clear"),
            pytest.param(
                Level.PACKAGE, ("track", "product"), id="package-descendants-excluded"
            ),
            pytest.param(Level.TRACK, (), id="track-all-clear"),
            pytest.param(
                Level.TRACK, ("package",), id="track-beneath-excluded-package"
            ),
            pytest.param(Level.TRACK, ("product",), id="track-product-excluded"),
            pytest.param(Level.PRODUCT, (), id="product-all-clear"),
            pytest.param(
                Level.PRODUCT, ("track",), id="product-beneath-excluded-track"
            ),
            pytest.param(
                Level.PRODUCT,
                ("package", "track"),
                id="product-beneath-excluded-ancestors",
            ),
        ],
    )
    async def test_restore_of_null_direct_marker_raises(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        tree: TreeBuilder,
        monkeypatch: pytest.MonkeyPatch,
        level: Level,
        seeded: tuple[str, ...],
    ) -> None:
        """A record effectively excluded only through an ancestor is not
        directly excluded (package-service.md, Package-tree exclusion and
        actionability: restore requires the targeted record's own
        marker)."""
        actor = await va_user()
        ticket = await cveless(ticket_factory, status=TicketStatus.NEW)
        occurrence = await _target(
            db_session,
            tree,
            ticket,
            package="package" in seeded,
            track="track" in seeded,
            product="product" in seeded,
        )

        await assert_no_effects(
            db_session,
            monkeypatch,
            lambda: change(db_session, level, Direction.RESTORE, occurrence, actor),
            tickets=(ticket,),
            occurrences=(occurrence,),
            error=PackageNotExcludedError,
        )

    @LEVELS
    @DIRECTIONS
    async def test_same_direction_reinvocation_fails_on_the_guard(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        tree: TreeBuilder,
        monkeypatch: pytest.MonkeyPatch,
        level: Level,
        direction: Direction,
    ) -> None:
        """A successful call followed by the same call: the second fails
        without a second assignment, event, or reconciliation."""
        actor = await va_user()
        ticket = await cveless(ticket_factory, status=TicketStatus.NEW)
        await tree(ticket, status=PackageStatus.ANALYSIS)
        seeded = direction is Direction.RESTORE
        occurrence = await _target(
            db_session,
            tree,
            ticket,
            package=seeded and level is Level.PACKAGE,
            track=seeded and level is Level.TRACK,
            product=seeded and level is Level.PRODUCT,
        )
        await change(db_session, level, direction, occurrence, actor)
        assert await ticket_events(db_session, ticket) == [
            assignment_event(actor),
            PROMOTION,
            await marker_event(db_session, level, direction, occurrence, actor),
        ]

        await assert_no_effects(
            db_session,
            monkeypatch,
            lambda: change(db_session, level, direction, occurrence, actor),
            tickets=(ticket,),
            occurrences=(occurrence,),
            error=(
                PackageAlreadyExcludedError
                if direction is Direction.EXCLUDE
                else PackageNotExcludedError
            ),
        )

    @pytest.mark.parametrize(
        "error", [PackageAlreadyExcludedError, PackageNotExcludedError]
    )
    def test_guard_errors_are_package_service_errors(
        self, error: type[Exception]
    ) -> None:
        """package-service.md, Service Exceptions: module-owned exceptions
        inherit from `PackageServiceError`."""
        assert issubclass(error, PackageServiceError)
        assert issubclass(error, ServiceError)


# ---------------------------------------------------------------------------
# Forward and backward transitions through reconciliation
# ---------------------------------------------------------------------------

TRANSITIONS = [
    # (direction, other track, target track, Ticket before, Ticket after)
    pytest.param(
        Direction.EXCLUDE,
        PackageStatus.AFFECTED,
        PackageStatus.ANALYSIS,
        TicketStatus.ANALYSIS,
        TicketStatus.ANALYZED,
        id="exclude-last-analysis-to-analyzed",
    ),
    pytest.param(
        Direction.EXCLUDE,
        PackageStatus.NOT_AFFECTED,
        PackageStatus.ANALYSIS,
        TicketStatus.ANALYSIS,
        TicketStatus.RESOLVED,
        id="exclude-last-analysis-to-resolved",
    ),
    pytest.param(
        Direction.EXCLUDE,
        PackageStatus.NOT_AFFECTED,
        PackageStatus.AFFECTED,
        TicketStatus.ANALYZED,
        TicketStatus.RESOLVED,
        id="exclude-last-affected-to-resolved",
    ),
    pytest.param(
        Direction.RESTORE,
        PackageStatus.AFFECTED,
        PackageStatus.ANALYSIS,
        TicketStatus.ANALYZED,
        TicketStatus.ANALYSIS,
        id="restore-analysis-from-analyzed",
    ),
    pytest.param(
        Direction.RESTORE,
        PackageStatus.NOT_AFFECTED,
        PackageStatus.ANALYSIS,
        TicketStatus.RESOLVED,
        TicketStatus.ANALYSIS,
        id="restore-analysis-from-resolved",
    ),
    pytest.param(
        Direction.RESTORE,
        PackageStatus.NOT_AFFECTED,
        PackageStatus.AFFECTED,
        TicketStatus.RESOLVED,
        TicketStatus.ANALYZED,
        id="restore-affected-from-resolved",
    ),
]
"""tickets.md gates over two tracks, each with one eligible in-support
Product. Excluding the target at any level removes it from `A` (package or
track exclusion also from `M`; the other track keeps `|M| >= 1`); restoring
it makes it actionable again. An actionable `ANALYSIS` track blocks
`Analyzed`; an `AFFECTED` track with an actionable eligible Product blocks
`Resolved` (clause (c)); `NOT_AFFECTED` is resolution-complete."""


@pytest.mark.integration
class TestGateTransitions:
    """package-service.md, Architectural Test Requirement: Forward and
    Backward transitions (e.g., restoring a soft-deleted track with
    non-final status); package-model.md, Gate Participation;
    ticket-audit-log.md, Cross-Event Ordering (the system gate event is
    last); ticket-mutations.md, `reconcile_ticket_status()` step 5 (a
    `Resolved` regression registers one Ticket convergence effect)."""

    @LEVELS
    @pytest.mark.parametrize(
        ("direction", "other", "target", "before", "after"), TRANSITIONS
    )
    async def test_operation_reconciles_the_ticket_once(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        tree: TreeBuilder,
        monkeypatch: pytest.MonkeyPatch,
        level: Level,
        direction: Direction,
        other: PackageStatus,
        target: PackageStatus,
        before: TicketStatus,
        after: TicketStatus,
    ) -> None:
        actor = await va_user()
        ticket = await cveless(ticket_factory, status=before, assignee_id=actor.id)
        occurrence = await gate_world(
            db_session, tree, ticket, level, direction, other=other, target=target
        )
        reconcile = Spy(monkeypatch, "reconcile_ticket_status")

        await change(db_session, level, direction, occurrence, actor)

        assert [(args[0].id, kwargs) for args, kwargs in reconcile.calls] == [
            (ticket.id, {"evaluation_date": EVAL})
        ]
        assert await ticket_state(db_session, ticket) == (after, actor.id)
        assert await ticket_events(db_session, ticket) == [
            await marker_event(db_session, level, direction, occurrence, actor),
            status_event(before, after),
        ]
        regression = before is TicketStatus.RESOLVED
        assert pending_ticket_convergence_effects(db_session) == (
            (TicketConvergenceEffect(ticket.id),) if regression else ()
        )


# ---------------------------------------------------------------------------
# Auto-assignment
# ---------------------------------------------------------------------------

INELIGIBLE_ACTORS = pytest.mark.parametrize(
    ("active", "roles"),
    [
        pytest.param(True, (Role.RESTRICTED_ANALYST,), id="restricted-analyst"),
        pytest.param(True, (Role.ADMIN,), id="admin-only"),
        pytest.param(False, (Role.VULNERABILITY_ANALYST,), id="inactive-va"),
    ],
)


@pytest.mark.integration
class TestAutoAssignment:
    """package-service.md, Auto-Assignment Rule and Exclusion and restoration
    operations step 7; tickets.md, Auto-Assignment on Unassigned Tickets;
    ticket-audit-log.md, Cross-Event Ordering (assignment and its system
    `New -> Analysis` precede the direct event; the optional final gate
    event is last).

    The `New` Ticket has a `NOT_AFFECTED` track and the target `ANALYSIS`
    track: after the promotion, excluding the target leaves only the final
    track (`Resolved`); restoring it leaves an actionable `ANALYSIS` track
    (`Analysis`, no gate event)."""

    @LEVELS
    @DIRECTIONS
    async def test_active_va_on_new_ticket_assigns_and_promotes_first(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        tree: TreeBuilder,
        level: Level,
        direction: Direction,
    ) -> None:
        actor = await va_user()
        ticket = await cveless(ticket_factory, status=TicketStatus.NEW)
        occurrence = await gate_world(db_session, tree, ticket, level, direction)

        await change(db_session, level, direction, occurrence, actor)

        final = (
            TicketStatus.RESOLVED
            if direction is Direction.EXCLUDE
            else TicketStatus.ANALYSIS
        )
        gate = (
            [status_event(TicketStatus.ANALYSIS, final)]
            if final is not TicketStatus.ANALYSIS
            else []
        )
        assert await ticket_state(db_session, ticket) == (final, actor.id)
        assert await ticket_events(db_session, ticket) == [
            assignment_event(actor),
            PROMOTION,
            await marker_event(db_session, level, direction, occurrence, actor),
            *gate,
        ]

    @INELIGIBLE_ACTORS
    @LEVELS
    @DIRECTIONS
    async def test_ineligible_actor_changes_without_assignment(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        tree: TreeBuilder,
        active: bool,
        roles: tuple[Role, ...],
        level: Level,
        direction: Direction,
    ) -> None:
        """The operation succeeds; the unassigned `New` Ticket is outside
        the gate zone (ticket-mutations.md, `reconcile_ticket_status()` step
        1) and stays `New`."""
        actor = await va_user(active=active, roles=roles)
        ticket = await cveless(ticket_factory, status=TicketStatus.NEW)
        occurrence = await gate_world(db_session, tree, ticket, level, direction)
        before = await markers(db_session, occurrence)

        await change(db_session, level, direction, occurrence, actor)

        assert await markers(db_session, occurrence) == with_target(
            before, level, MARKER_NOW if direction is Direction.EXCLUDE else None
        )
        assert await ticket_state(db_session, ticket) == (TicketStatus.NEW, None)
        assert await ticket_events(db_session, ticket) == [
            await marker_event(db_session, level, direction, occurrence, actor)
        ]

    @DIRECTIONS
    async def test_already_assigned_ticket_keeps_its_assignee(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        tree: TreeBuilder,
        direction: Direction,
    ) -> None:
        assignee = await va_user()
        actor = await va_user()
        ticket = await _pinned(ticket_factory, tree, assignee_id=assignee.id)
        occurrence = await _target(
            db_session, tree, ticket, track=direction is Direction.RESTORE
        )

        await change(db_session, Level.TRACK, direction, occurrence, actor)

        assert await ticket_state(db_session, ticket) == (
            TicketStatus.ANALYSIS,
            assignee.id,
        )
        assert await ticket_events(db_session, ticket) == [
            await marker_event(db_session, Level.TRACK, direction, occurrence, actor)
        ]


# ---------------------------------------------------------------------------
# Audit payload, human-readable Product subjects, and public Product identity
# ---------------------------------------------------------------------------

PACKAGE_NAME = "example-libwidget"
TRACK_REFERENCE = "Example:Distro:15-SP9:Update"
PRODUCT_SHORT_NAME = "exwidget-server"
PRODUCT_DISPLAY_NAME = "Example Widget Server 15 SP9"
PRODUCT_CPE = "cpe:/o:example:widget_server:15:sp9"
SEEDED_AT = datetime(2026, 9, 1, 8, 0, tzinfo=UTC)

LITERAL_PAYLOADS: dict[Level, tuple[str, dict[str, str] | None]] = {
    Level.PACKAGE: (PACKAGE_NAME, None),
    Level.TRACK: (
        TRACK_REFERENCE,
        {"track": TRACK_REFERENCE, "package": PACKAGE_NAME},
    ),
    Level.PRODUCT: (
        PRODUCT_DISPLAY_NAME,
        {
            "track": TRACK_REFERENCE,
            "package": PACKAGE_NAME,
            "product_name": PRODUCT_DISPLAY_NAME,
            "product_cpe": PRODUCT_CPE,
        },
    ),
}
"""ticket-audit-log.md, Event Type Contract and detail JSONB Schema
Contract: the subject (package name, track reference, or
`Product.display_name`, never `Product.name`) and the exact `detail`."""


@pytest.mark.integration
class TestAuditPayload:
    """ticket-audit-log.md, Event Type Contract rows `package_excluded`,
    `package_restored`, `track_excluded`, `track_restored`,
    `product_excluded`, `product_restored`; detail JSONB Schema Contract
    (Product subject without internal UUIDs; `product_name` is
    `Product.display_name`); Testing Requirements 1-6, 8, 13;
    package-service.md, Architectural Test Requirement: Human-readable
    Product audit subjects, Exclusion/restore actor, and Public Product
    identity."""

    @staticmethod
    async def _occurrence(
        ticket: Ticket,
        level: Level,
        direction: Direction,
        *,
        product_factory: Factory,
        ticket_package_factory: Factory,
        ticket_package_track_factory: Factory,
        ticket_package_product_factory: Factory,
    ) -> tuple[Product, TicketPackageProduct]:
        """The literal-named path; for a restore only the `level` marker is
        seeded."""
        seeded = direction is Direction.RESTORE

        def marker(at: Level) -> datetime | None:
            return SEEDED_AT if seeded and level is at else None

        package = await ticket_package_factory(
            ticket_id=ticket.id,
            package_name=PACKAGE_NAME,
            deleted_at=marker(Level.PACKAGE),
        )
        track = await ticket_package_track_factory(
            ticket_package_id=package.id,
            reference=TRACK_REFERENCE,
            status=PackageStatus.ANALYSIS.value,
            deleted_at=marker(Level.TRACK),
        )
        product = await product_factory(
            name=PRODUCT_SHORT_NAME,
            display_name=PRODUCT_DISPLAY_NAME,
            cpe=PRODUCT_CPE,
            general_support_end_date=AFTER_EVAL,
        )
        occurrence = await ticket_package_product_factory(
            ticket_package_track_id=track.id,
            product_id=product.id,
            deleted_at=marker(Level.PRODUCT),
        )
        return product, occurrence

    @LEVELS
    @DIRECTIONS
    async def test_event_has_exact_literal_payload(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        tree: TreeBuilder,
        product_factory: Factory,
        ticket_package_factory: Factory,
        ticket_package_track_factory: Factory,
        ticket_package_product_factory: Factory,
        level: Level,
        direction: Direction,
    ) -> None:
        actor = await va_user()
        ticket = await _pinned(ticket_factory, tree, assignee_id=actor.id)
        product, occurrence = await self._occurrence(
            ticket,
            level,
            direction,
            product_factory=product_factory,
            ticket_package_factory=ticket_package_factory,
            ticket_package_track_factory=ticket_package_track_factory,
            ticket_package_product_factory=ticket_package_product_factory,
        )

        await change(db_session, level, direction, occurrence, actor)

        subject, detail = LITERAL_PAYLOADS[level]
        suffix = "excluded" if direction is Direction.EXCLUDE else "restored"
        old, new = (
            (subject, None) if direction is Direction.EXCLUDE else (None, subject)
        )
        events = await ticket_events(db_session, ticket)
        assert events == [
            EventRow(f"{level}_{suffix}", actor.id, old, new, None, detail)
        ]
        serialized = json.dumps([events[0].old_value, events[0].new_value, detail])
        for internal in (
            occurrence.id,
            occurrence.ticket_package_track_id,
            product.id,
            ticket.id,
        ):
            assert str(internal) not in serialized
        assert PRODUCT_SHORT_NAME not in serialized

    @DIRECTIONS
    async def test_product_projection_exposes_occurrence_id_and_catalog_cpe(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        tree: TreeBuilder,
        product_factory: Factory,
        ticket_package_factory: Factory,
        ticket_package_track_factory: Factory,
        ticket_package_product_factory: Factory,
        direction: Direction,
    ) -> None:
        """package-model.md, Soft-Delete and Restore Product responses:
        `id` is `TicketPackageProduct.id`, `product_cpe` the related catalog
        CPE, and `product_name` its display name; no catalog `Product.id`."""
        actor = await va_user()
        ticket = await _pinned(ticket_factory, tree, assignee_id=actor.id)
        product, occurrence = await self._occurrence(
            ticket,
            Level.PRODUCT,
            direction,
            product_factory=product_factory,
            ticket_package_factory=ticket_package_factory,
            ticket_package_track_factory=ticket_package_track_factory,
            ticket_package_product_factory=ticket_package_product_factory,
        )

        result = await change(db_session, Level.PRODUCT, direction, occurrence, actor)

        excluded = direction is Direction.EXCLUDE
        assert result.target == ProductMarkerProjection(
            occurrence.id,
            PRODUCT_CPE,
            PRODUCT_DISPLAY_NAME,
            not excluded,
            PRD_EXCLUDED if excluded else None,
        )
        assert result.target.id != product.id

    @pytest.mark.parametrize("term", ["Widget Server 15 SP9", PRODUCT_CPE])
    async def test_product_events_are_searchable_by_name_and_cpe(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        tree: TreeBuilder,
        product_factory: Factory,
        ticket_package_factory: Factory,
        ticket_package_track_factory: Factory,
        ticket_package_product_factory: Factory,
        term: str,
    ) -> None:
        """ticket-audit-log.md, Testing Requirement 8 (searchable by both
        event-time values)."""
        actor = await va_user()
        ticket = await _pinned(ticket_factory, tree, assignee_id=actor.id)
        await db_session.refresh(ticket, ["sequence_id"])
        _, occurrence = await self._occurrence(
            ticket,
            Level.PRODUCT,
            Direction.EXCLUDE,
            product_factory=product_factory,
            ticket_package_factory=ticket_package_factory,
            ticket_package_track_factory=ticket_package_track_factory,
            ticket_package_product_factory=ticket_package_product_factory,
        )
        await change(db_session, Level.PRODUCT, Direction.EXCLUDE, occurrence, actor)
        await change(db_session, Level.PRODUCT, Direction.RESTORE, occurrence, actor)

        page = await list_ticket_events(
            db_session,
            ticket_id=format_ticket_id(ticket.sequence_id),
            caller=TicketCaller.authenticated(actor.id, Scope.ALL),
            search=term,
        )

        assert sorted(e.event_type for e in page.items) == [
            "product_excluded",
            "product_restored",
        ]

    async def test_product_subject_is_an_event_time_snapshot(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        tree: TreeBuilder,
        product_factory: Factory,
        ticket_package_factory: Factory,
        ticket_package_track_factory: Factory,
        ticket_package_product_factory: Factory,
    ) -> None:
        """ticket-audit-log.md, Rules (Product subject fields are event-time
        snapshots): a later catalog rename changes only later events."""
        actor = await va_user()
        ticket = await _pinned(ticket_factory, tree, assignee_id=actor.id)
        product, occurrence = await self._occurrence(
            ticket,
            Level.PRODUCT,
            Direction.EXCLUDE,
            product_factory=product_factory,
            ticket_package_factory=ticket_package_factory,
            ticket_package_track_factory=ticket_package_track_factory,
            ticket_package_product_factory=ticket_package_product_factory,
        )
        await change(db_session, Level.PRODUCT, Direction.EXCLUDE, occurrence, actor)
        renamed = "Example Widget Server 15 SP9 Renamed"
        await db_session.execute(
            update(Product).where(Product.id == product.id).values(display_name=renamed)
        )

        await change(db_session, Level.PRODUCT, Direction.RESTORE, occurrence, actor)

        _, detail = LITERAL_PAYLOADS[Level.PRODUCT]
        assert detail is not None
        assert await ticket_events(db_session, ticket) == [
            EventRow(
                "product_excluded", actor.id, PRODUCT_DISPLAY_NAME, None, None, detail
            ),
            EventRow(
                "product_restored",
                actor.id,
                None,
                renamed,
                None,
                {**detail, "product_name": renamed},
            ),
        ]
