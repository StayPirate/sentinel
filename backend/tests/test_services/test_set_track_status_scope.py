"""Single-session service integration tests for `set_track_status()`
(backend/app/services/package_service.py), part B.

Owning specifications:

- docs/features/packages/package-service.md (Consumer caller context and
  Ticket accessibility; `set_track_status()`; Excluded and Non-Actionable
  Records; Architectural Test Requirement: Atomic consumer accessibility
  (mutation part), Derived actionability (shared date), Dimension
  independence (affectedness part)).
- docs/features/packages/package-model.md (Delivery Relevance Indicator;
  Manual Exclusion Markers; Derived Actionability, including the one-date
  rule; Change Track Status response field table).
- docs/features/packages/product-catalog.md (Lifecycle Evaluator: inclusive
  phase-end dates).
- docs/features/identity/rbac.md (Scope and Confidential Ticket Visibility).
- docs/features/tickets/tickets.md (Mutability Guard; Gate: Analysis ->
  Analyzed; Gate: Analyzed -> Resolved; Deterministic Gate Edge Cases).
- docs/features/tickets/ticket-audit-log.md (Testing Requirements 7, 25).
- docs/features/platform/testing-strategy.md (Ticket Accessibility: Locked
  mutations and the controlled-clock bullet; Audit Trail Testing).

Independent-session races are out of scope for this module; every test uses
the single `db_session`.

Unless a test states otherwise, a Ticket is CVE-less with
`severity_manual = High` and each factory-built track carries one eligible
Product in General Support on `EVAL`. Expected values are transcribed from
the specifications, never computed with the module under test.
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable
from datetime import date, timedelta
from typing import Any
from unittest.mock import Mock

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import (
    DeliveryStatus,
    LifecyclePhase,
    NonActionableReason,
    PackageStatus,
    Role,
    Scope,
    TicketAuditEventType,
    TicketStatus,
)
from app.core.exceptions import TicketNotFoundError, TicketNotMutableError
from app.models.cve import CVE
from app.models.product import Product
from app.models.ticket import Ticket
from app.models.ticket_access_grant import TicketAccessGrant
from app.models.ticket_package import TicketPackage
from app.models.ticket_package_maintainer import TicketPackageMaintainer
from app.models.ticket_package_product import TicketPackageProduct
from app.models.ticket_package_track import TicketPackageTrack
from app.models.user import User
from app.services import package_service, ticket_mutations
from app.services.package_service import (
    MutationOutcome,
    TrackStatusProjection,
    TrackStatusResult,
    set_track_status,
)
from app.services.ticket_audit_log import TicketAuditLog
from app.services.ticket_convergence_registry import (
    TicketConvergenceEffect,
    pending_ticket_convergence_effects,
)
from app.services.ticket_visibility import TicketCaller
from tests.support.database import rollback_test_scope
from tests.support.ticket_mutations import (
    AFTER_EVAL,
    BEFORE_EVAL,
    EVAL,
    Prod,
    StatementRecorder,
    TicketFactory,
    TreeBuilder,
    VAUser,
    cveless,
    status_event,
    ticket_events,
)
from tests.support.track_status import (
    Spy,
    assert_no_effects,
    persisted_track_status,
    set_status,
    ticket_state,
    track_event,
)

pytest_plugins = ["tests.support.ticket_mutation_fixtures"]
"""Provides the shared `va_user` and `tree` fixtures."""

CveFactory = Callable[..., Awaitable[CVE]]
ProductFactory = Callable[..., Awaitable[Product]]
TrackFactory = Callable[..., Awaitable[TicketPackageTrack]]
OccurrenceFactory = Callable[..., Awaitable[TicketPackageProduct]]
GrantFactory = Callable[..., Awaitable[TicketAccessGrant]]
PackageFactory = Callable[..., Awaitable[TicketPackage]]
MaintainerFactory = Callable[..., Awaitable[TicketPackageMaintainer]]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _restricted(va_user: VAUser) -> User:
    """An active `restricted_analyst`: effective scope `non_confidential`
    (rbac.md, Predefined Roles) and never auto-assigned (not a VA)."""
    return await va_user(roles=(Role.RESTRICTED_ANALYST,))


# ---------------------------------------------------------------------------
# Locked-current consumer accessibility (point 8)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestAccessibility:
    """package-service.md, Consumer caller context and Ticket accessibility
    and `set_track_status()` step 2; rbac.md, Scope and Confidential Ticket
    Visibility (four additive branches); testing-strategy.md, Ticket
    Accessibility (Locked mutations: nested-resource, operability, status,
    idempotency, and authority decisions never precede the denial)."""

    @pytest.mark.parametrize("system", [False, True], ids=["user", "system"])
    async def test_missing_ticket_raises_without_effects(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        tree: TreeBuilder,
        monkeypatch: pytest.MonkeyPatch,
        system: bool,
    ) -> None:
        actor = None if system else await va_user()
        ticket = await cveless(ticket_factory)
        track = await tree(ticket, status=PackageStatus.ANALYSIS)

        await assert_no_effects(
            db_session,
            monkeypatch,
            lambda: set_status(
                db_session,
                track,
                PackageStatus.FIXED,
                actor,
                ticket_id=uuid.uuid4(),
            ),
            tickets=(ticket,),
            tracks=(track,),
            error=TicketNotFoundError,
        )

    @pytest.mark.parametrize(
        "case",
        [
            "no-visibility-path",
            "maintainer-of-other-excluded-package",
            "maintainer-of-own-excluded-package",
            "cve-fixed-without-force",
            "wrong-package-id",
        ],
    )
    async def test_inaccessible_ticket_raises_before_every_other_decision(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_factory: CveFactory,
        va_user: VAUser,
        tree: TreeBuilder,
        ticket_package_factory: PackageFactory,
        ticket_access_grant_factory: GrantFactory,
        ticket_package_maintainer_factory: MaintainerFactory,
        monkeypatch: pytest.MonkeyPatch,
        case: str,
    ) -> None:
        """A confidential Ticket seen by a `non_confidential` caller with no
        own grant and no included maintained package is not found. Another
        user's grant or maintainership never qualifies the caller; a
        maintainership only of an excluded package does not qualify. The
        CVE-less `FIXED` restriction and nested ownership are not evaluated
        before the denial."""
        actor = await _restricted(va_user)
        other = await va_user()
        if case == "cve-fixed-without-force":
            cve = await cve_factory()
            ticket = await ticket_factory(
                status=TicketStatus.ANALYSIS.value, cve_id=cve.id, is_confidential=True
            )
        else:
            ticket = await cveless(ticket_factory, is_confidential=True)
        track = await tree(
            ticket,
            status=PackageStatus.ANALYSIS,
            package_excluded=case == "maintainer-of-own-excluded-package",
        )
        await ticket_access_grant_factory(ticket_id=ticket.id, user_id=other.id)
        await ticket_package_maintainer_factory(
            ticket_package_id=track.ticket_package_id, user_id=other.id
        )
        if case == "maintainer-of-other-excluded-package":
            excluded = await ticket_package_factory(
                ticket_id=ticket.id, deleted_at=ticket.created_at
            )
            await ticket_package_maintainer_factory(
                ticket_package_id=excluded.id, user_id=actor.id
            )
        elif case == "maintainer-of-own-excluded-package":
            await ticket_package_maintainer_factory(
                ticket_package_id=track.ticket_package_id, user_id=actor.id
            )
        target = (
            PackageStatus.FIXED
            if case == "cve-fixed-without-force"
            else PackageStatus.AFFECTED
        )
        package_id = uuid.uuid4() if case == "wrong-package-id" else None

        await assert_no_effects(
            db_session,
            monkeypatch,
            lambda: set_status(
                db_session,
                track,
                target,
                actor,
                ticket_id=ticket.id,
                package_id=package_id,
                scope=Scope.NON_CONFIDENTIAL,
            ),
            tickets=(ticket,),
            tracks=(track,),
            error=TicketNotFoundError,
        )

    @pytest.mark.parametrize(
        ("case", "confidential", "scope"),
        [
            ("non-confidential", False, Scope.NON_CONFIDENTIAL),
            ("scope-all", True, Scope.ALL),
            ("explicit-grant", True, Scope.NON_CONFIDENTIAL),
            ("maintainer-of-own-package", True, Scope.NON_CONFIDENTIAL),
            ("maintainer-of-other-included-package", True, Scope.NON_CONFIDENTIAL),
        ],
    )
    async def test_each_visibility_branch_permits_the_mutation(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        tree: TreeBuilder,
        ticket_package_factory: PackageFactory,
        ticket_access_grant_factory: GrantFactory,
        ticket_package_maintainer_factory: MaintainerFactory,
        case: str,
        confidential: bool,
        scope: Scope,
    ) -> None:
        """Each branch is independently sufficient. The restricted analyst
        is not a VA, so the unassigned Ticket stays unassigned; the single
        `AFFECTED` track with an eligible actionable Product gives
        `Analyzed`."""
        actor = await _restricted(va_user)
        ticket = await cveless(ticket_factory, is_confidential=confidential)
        track = await tree(ticket, status=PackageStatus.ANALYSIS)
        if case == "explicit-grant":
            await ticket_access_grant_factory(ticket_id=ticket.id, user_id=actor.id)
        elif case == "maintainer-of-own-package":
            await ticket_package_maintainer_factory(
                ticket_package_id=track.ticket_package_id, user_id=actor.id
            )
        elif case == "maintainer-of-other-included-package":
            maintained = await ticket_package_factory(ticket_id=ticket.id)
            await ticket_package_maintainer_factory(
                ticket_package_id=maintained.id, user_id=actor.id
            )

        result = await set_status(
            db_session, track, PackageStatus.AFFECTED, actor, scope=scope
        )

        assert result.outcome is MutationOutcome.CHANGED
        assert await persisted_track_status(db_session, track) == (
            PackageStatus.AFFECTED
        )
        assert await ticket_state(db_session, ticket) == (TicketStatus.ANALYZED, None)
        assert await ticket_events(db_session, ticket) == [
            await track_event(
                db_session,
                track,
                actor,
                PackageStatus.ANALYSIS,
                PackageStatus.AFFECTED,
            ),
            status_event(TicketStatus.ANALYSIS, TicketStatus.ANALYZED),
        ]


# ---------------------------------------------------------------------------
# Manual-zone operability (point 9)
# ---------------------------------------------------------------------------

MANUAL_ZONE = pytest.mark.parametrize(
    "zone", [TicketStatus.IGNORED, TicketStatus.DUPLICATED], ids=str
)
SYSTEM = pytest.mark.parametrize("system", [False, True], ids=["user", "system"])


@pytest.mark.integration
class TestManualZone:
    """tickets.md, Mutability Guard; package-service.md, `set_track_status()`
    steps 2-4 and Ticket-level operability: accessibility precedes
    operability, which precedes the locked path reload."""

    @MANUAL_ZONE
    @SYSTEM
    async def test_manual_zone_ticket_is_not_mutable(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        tree: TreeBuilder,
        monkeypatch: pytest.MonkeyPatch,
        zone: TicketStatus,
        system: bool,
    ) -> None:
        """An unassigned manual-zone Ticket and an active VA actor: neither
        the change, the assignment, nor any other effect occurs."""
        actor = None if system else await va_user()
        ticket = await cveless(ticket_factory, status=zone)
        track = await tree(ticket, status=PackageStatus.ANALYSIS)
        target = PackageStatus.FIXED if system else PackageStatus.AFFECTED

        await assert_no_effects(
            db_session,
            monkeypatch,
            lambda: set_status(db_session, track, target, actor),
            tickets=(ticket,),
            tracks=(track,),
            error=TicketNotMutableError,
        )

    @MANUAL_ZONE
    async def test_inaccessible_manual_zone_ticket_is_not_found(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        tree: TreeBuilder,
        monkeypatch: pytest.MonkeyPatch,
        zone: TicketStatus,
    ) -> None:
        actor = await _restricted(va_user)
        ticket = await cveless(ticket_factory, status=zone, is_confidential=True)
        track = await tree(ticket, status=PackageStatus.ANALYSIS)

        await assert_no_effects(
            db_session,
            monkeypatch,
            lambda: set_status(
                db_session,
                track,
                PackageStatus.AFFECTED,
                actor,
                scope=Scope.NON_CONFIDENTIAL,
            ),
            tickets=(ticket,),
            tracks=(track,),
            error=TicketNotFoundError,
        )

    @MANUAL_ZONE
    @SYSTEM
    @pytest.mark.parametrize("level", ["package", "track"])
    async def test_operability_precedes_the_path_reload(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        tree: TreeBuilder,
        monkeypatch: pytest.MonkeyPatch,
        zone: TicketStatus,
        system: bool,
        level: str,
    ) -> None:
        """A missing package (or a track of another package) on a
        manual-zone Ticket raises `TicketNotMutableError`, not the
        path-level not-found exception."""
        actor = None if system else await va_user()
        ticket = await cveless(ticket_factory, status=zone)
        track = await tree(ticket, status=PackageStatus.ANALYSIS)
        sibling = await tree(ticket, status=PackageStatus.ANALYSIS)
        package_id = uuid.uuid4() if level == "package" else sibling.ticket_package_id

        await assert_no_effects(
            db_session,
            monkeypatch,
            lambda: set_status(
                db_session,
                track,
                PackageStatus.FIXED,
                actor,
                ticket_id=ticket.id,
                package_id=package_id,
            ),
            tickets=(ticket,),
            tracks=(track, sibling),
            error=TicketNotMutableError,
        )


# ---------------------------------------------------------------------------
# Excluded and EOL tracks remain mutable (point 10)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestExcludedAndEolTracks:
    """package-service.md, Package-tree exclusion and actionability
    (mutation functions do not require `deleted_at IS NULL`);
    package-model.md, Manual Exclusion Markers and Derived Actionability
    (reason precedence); tickets.md, Gate: Analysis -> Analyzed (`M` and
    `A`) and Deterministic Gate Edge Cases.

    The mutated track is the Ticket's only track. An excluded track or a
    track under an excluded package leaves `M` empty, so the `Analysis`
    Ticket keeps `Analysis`; an all-EOL track is in `M` but not in `A`, so
    the Ticket becomes `Resolved` by empty-set quantification."""

    @SYSTEM
    @pytest.mark.parametrize(
        ("kind", "track_reason", "product_reason", "after"),
        [
            (
                "track-excluded",
                NonActionableReason.TRACK_EXCLUDED,
                NonActionableReason.TRACK_EXCLUDED,
                TicketStatus.ANALYSIS,
            ),
            (
                "package-excluded",
                NonActionableReason.PACKAGE_EXCLUDED,
                NonActionableReason.PACKAGE_EXCLUDED,
                TicketStatus.ANALYSIS,
            ),
            (
                "all-products-eol",
                NonActionableReason.NO_ACTIONABLE_PRODUCTS,
                NonActionableReason.EOL,
                TicketStatus.RESOLVED,
            ),
        ],
    )
    async def test_non_actionable_track_changes_with_its_event(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        tree: TreeBuilder,
        system: bool,
        kind: str,
        track_reason: NonActionableReason,
        product_reason: NonActionableReason,
        after: TicketStatus,
    ) -> None:
        actor = None if system else await va_user()
        ticket = await cveless(ticket_factory, assignee_id=actor.id if actor else None)
        track = await tree(
            ticket,
            status=PackageStatus.ANALYSIS,
            products=(
                (Prod(eol=True), Prod(eol=True))
                if kind == "all-products-eol"
                else (Prod(), Prod())
            ),
            track_excluded=kind == "track-excluded",
            package_excluded=kind == "package-excluded",
        )
        target = PackageStatus.FIXED if system else PackageStatus.AFFECTED
        gate = (
            [status_event(TicketStatus.ANALYSIS, after)]
            if after != TicketStatus.ANALYSIS
            else []
        )

        result = await set_status(db_session, track, target, actor)

        assert result.outcome is MutationOutcome.CHANGED
        assert await persisted_track_status(db_session, track) == target
        assert await ticket_state(db_session, ticket) == (
            after,
            actor.id if actor else None,
        )
        assert await ticket_events(db_session, ticket) == [
            await track_event(db_session, track, actor, PackageStatus.ANALYSIS, target),
            *gate,
        ]
        assert (result.track.status, result.track.actionable) == (target, False)
        assert result.track.non_actionable_reason is track_reason
        assert [
            (p.actionable, p.non_actionable_reason) for p in result.track.products
        ] == [(False, product_reason)] * 2


# ---------------------------------------------------------------------------
# Dimension independence (point 11)
# ---------------------------------------------------------------------------


async def _dimensions(db: AsyncSession, track: TicketPackageTrack) -> tuple[Any, ...]:
    """Every non-affectedness value of the track's subtree: package marker;
    track delivery and marker; each Product occurrence's eligibility,
    override marker, release observation, and marker (occurrence order)."""
    track_row = (
        await db.execute(
            select(
                TicketPackage.deleted_at,
                TicketPackageTrack.delivery_status,
                TicketPackageTrack.deleted_at,
            )
            .join(
                TicketPackage, TicketPackage.id == TicketPackageTrack.ticket_package_id
            )
            .where(TicketPackageTrack.id == track.id)
        )
    ).one()
    products = (
        await db.execute(
            select(
                TicketPackageProduct.eligible,
                TicketPackageProduct.is_eligible_override,
                TicketPackageProduct.released_at,
                TicketPackageProduct.deleted_at,
            )
            .where(TicketPackageProduct.ticket_package_track_id == track.id)
            .order_by(TicketPackageProduct.id)
        )
    ).all()
    return tuple(track_row), [tuple(p) for p in products]


@pytest.mark.integration
class TestDimensionIndependence:
    """package-service.md, Architectural Test Requirement: Dimension
    independence (affectedness part); package-model.md, Three Orthogonal
    Dimensions and Gate Participation; tickets.md, Gate: Analyzed ->
    Resolved (`delivery_status` is not a gate input).

    Products: a manual `eligible = false` override, an eligible released
    Product, and a directly excluded Product, so `AEP` is exactly the
    released Product. `AFFECTED` then gives `Analyzed`; `NOT_AFFECTED` and
    CVE-less `FIXED` give `Resolved` although delivery is `IN_PROGRESS`."""

    @pytest.mark.parametrize(
        ("system", "source", "target", "before", "after"),
        [
            pytest.param(
                False,
                PackageStatus.ANALYSIS,
                PackageStatus.AFFECTED,
                TicketStatus.ANALYSIS,
                TicketStatus.ANALYZED,
                id="user-to-AFFECTED",
            ),
            pytest.param(
                False,
                PackageStatus.AFFECTED,
                PackageStatus.NOT_AFFECTED,
                TicketStatus.ANALYZED,
                TicketStatus.RESOLVED,
                id="user-to-NOT_AFFECTED",
            ),
            pytest.param(
                True,
                PackageStatus.AFFECTED,
                PackageStatus.FIXED,
                TicketStatus.ANALYZED,
                TicketStatus.RESOLVED,
                id="system-to-FIXED",
            ),
        ],
    )
    async def test_affectedness_change_mutates_no_other_dimension(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        tree: TreeBuilder,
        system: bool,
        source: PackageStatus,
        target: PackageStatus,
        before: TicketStatus,
        after: TicketStatus,
    ) -> None:
        actor = None if system else await va_user()
        ticket = await cveless(
            ticket_factory, status=before, assignee_id=actor.id if actor else None
        )
        track = await tree(
            ticket,
            status=source,
            products=(
                Prod(eligible=False, override=True),
                Prod(released=True),
                Prod(excluded=True),
            ),
        )
        track.delivery_status = DeliveryStatus.IN_PROGRESS.value
        await db_session.flush()
        seeded = await _dimensions(db_session, track)
        assert seeded[0] == (None, DeliveryStatus.IN_PROGRESS, None)
        # (eligible, is_eligible_override, released, excluded) as seeded.
        assert sorted(
            (p[0], p[1], p[2] is not None, p[3] is not None) for p in seeded[1]
        ) == [
            (False, True, False, False),
            (True, False, False, True),
            (True, False, True, False),
        ]

        result = await set_status(db_session, track, target, actor)

        assert result.outcome is MutationOutcome.CHANGED
        assert result.track.delivery_status is DeliveryStatus.IN_PROGRESS
        assert await _dimensions(db_session, track) == seeded
        assert await ticket_state(db_session, ticket) == (
            after,
            actor.id if actor else None,
        )


# ---------------------------------------------------------------------------
# Result projection (point 12)
# ---------------------------------------------------------------------------


def _response(track: TrackStatusProjection) -> dict[str, Any]:
    """The Change Track Status response fields of a projection, exactly
    the package-model.md field table (Products in returned order)."""
    return {
        "ticket_id": track.ticket_id,
        "package_name": track.package_name,
        "reference": track.reference,
        "status": track.status,
        "delivery_status": track.delivery_status,
        "delivery_relevant": track.delivery_relevant,
        "actionable": track.actionable,
        "non_actionable_reason": track.non_actionable_reason,
        "products": [
            {
                "id": p.id,
                "product_cpe": p.product_cpe,
                "product_name": p.product_name,
                "eligible": p.eligible,
                "is_eligible_override": p.is_eligible_override,
                "lifecycle_phase": p.lifecycle_phase,
                "actionable": p.actionable,
                "non_actionable_reason": p.non_actionable_reason,
            }
            for p in track.products
        ],
    }


PROJECTION_CASES = [
    # (outcome, system, source, target, delivery, delivery_relevant)
    ("changed", False, "ANALYSIS", "AFFECTED", "PENDING", True),
    ("changed", False, "AFFECTED", "ANALYSIS", "PENDING", True),
    ("changed", False, "ANALYSIS", "NOT_AFFECTED", "IN_PROGRESS", True),
    ("changed", True, "AFFECTED", "FIXED", "RELEASED", True),
    ("changed", False, "AFFECTED", "WONT_FIX", "PENDING", False),
    ("changed", True, "ANALYSIS", "FIXED", "PENDING", False),
    ("changed", False, "AFFECTED", "NOT_AFFECTED", "PENDING", False),
    ("no_op", False, "AFFECTED", "AFFECTED", "IN_PROGRESS", True),
    ("no_op", False, "WONT_FIX", "WONT_FIX", "PENDING", False),
    ("no_op", True, "NOT_AFFECTED", "FIXED", "PENDING", False),
    ("rejected", True, "ANALYSIS", "AFFECTED", "PENDING", True),
    ("rejected", True, "NOT_AFFECTED", "WONT_FIX", "IN_PROGRESS", True),
]
"""package-model.md, Delivery Relevance Indicator: relevant exactly when the
status is `ANALYSIS`/`AFFECTED` or delivery is not `PENDING`."""


@pytest.mark.integration
class TestResultProjection:
    """package-model.md, Change Track Status (response field table: the
    same shape for an effective change and a true no-op) and Derived
    Actionability; package-service.md, `set_track_status()` (projection
    from locked-current state with the shared `evaluation_date`; the
    rejected outcome carries the same projection).

    Product CPEs differ in code-point versus case-insensitive or locale
    order: code point puts `Zeta` (U+005A) before `alpha` (U+0061) and
    `éclair` (U+00E9) after `beta`. `Product.cpe` is unique and one track
    has at most one occurrence per Product, so the occurrence-id
    tie-breaker cannot be reached within one track."""

    @pytest.mark.parametrize(
        ("outcome", "system", "source", "target", "delivery", "relevant"),
        PROJECTION_CASES,
        ids=[f"{c[0]}-{c[2]}-{c[3]}-{c[4]}" for c in PROJECTION_CASES],
    )
    async def test_projection_matches_the_response_contract(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        product_factory: ProductFactory,
        ticket_package_factory: PackageFactory,
        ticket_package_track_factory: TrackFactory,
        ticket_package_product_factory: OccurrenceFactory,
        outcome: str,
        system: bool,
        source: str,
        target: str,
        delivery: str,
        relevant: bool,
    ) -> None:
        actor = None if system else await va_user()
        ticket = await cveless(ticket_factory, assignee_id=actor.id if actor else None)
        await db_session.refresh(ticket, ["sequence_id"])
        package = await ticket_package_factory(
            ticket_id=ticket.id, package_name="example-libprojection"
        )
        track = await ticket_package_track_factory(
            ticket_package_id=package.id,
            reference="Example:Projection:Update",
            status=source,
            delivery_status=delivery,
        )
        # (cpe, display name, GS end, eligible, override, excluded), inserted
        # out of canonical order.
        seeds = [
            ("cpe:/o:example:éclair", "Example Eclair", AFTER_EVAL, True, True, True),
            ("cpe:/o:example:alpha", "Example Alpha", None, True, False, False),
            ("cpe:/o:example:beta", "Example Beta", AFTER_EVAL, False, False, False),
            ("cpe:/o:example:Zeta", "Example Zeta", BEFORE_EVAL, False, True, False),
        ]
        occurrences: dict[str, uuid.UUID] = {}
        for cpe, name, gs_end, eligible, override, excluded in seeds:
            product = await product_factory(
                cpe=cpe, display_name=name, general_support_end_date=gs_end
            )
            occurrence = await ticket_package_product_factory(
                ticket_package_track_id=track.id,
                product_id=product.id,
                eligible=eligible,
                is_eligible_override=override,
                deleted_at=ticket.created_at if excluded else None,
            )
            occurrences[name] = occurrence.id
        status = target if outcome == "changed" else source

        result = await set_status(db_session, track, PackageStatus(target), actor)

        assert (result.outcome, result.evaluation_date) == (
            MutationOutcome(outcome),
            EVAL,
        )
        assert _response(result.track) == {
            "ticket_id": f"SNTL-{ticket.sequence_id}",
            "package_name": "example-libprojection",
            "reference": "Example:Projection:Update",
            "status": PackageStatus(status),
            "delivery_status": DeliveryStatus(delivery),
            "delivery_relevant": relevant,
            "actionable": True,
            "non_actionable_reason": None,
            "products": [
                {
                    "id": occurrences["Example Zeta"],
                    "product_cpe": "cpe:/o:example:Zeta",
                    "product_name": "Example Zeta",
                    "eligible": False,
                    "is_eligible_override": True,
                    "lifecycle_phase": LifecyclePhase.EOL,
                    "actionable": False,
                    "non_actionable_reason": NonActionableReason.EOL,
                },
                {
                    "id": occurrences["Example Alpha"],
                    "product_cpe": "cpe:/o:example:alpha",
                    "product_name": "Example Alpha",
                    "eligible": True,
                    "is_eligible_override": False,
                    "lifecycle_phase": None,
                    "actionable": True,
                    "non_actionable_reason": None,
                },
                {
                    "id": occurrences["Example Beta"],
                    "product_cpe": "cpe:/o:example:beta",
                    "product_name": "Example Beta",
                    "eligible": False,
                    "is_eligible_override": False,
                    "lifecycle_phase": LifecyclePhase.GENERAL_SUPPORT,
                    "actionable": True,
                    "non_actionable_reason": None,
                },
                {
                    "id": occurrences["Example Eclair"],
                    "product_cpe": "cpe:/o:example:éclair",
                    "product_name": "Example Eclair",
                    "eligible": True,
                    "is_eligible_override": True,
                    "lifecycle_phase": LifecyclePhase.GENERAL_SUPPORT,
                    "actionable": False,
                    "non_actionable_reason": NonActionableReason.PRODUCT_EXCLUDED,
                },
            ],
        }


# ---------------------------------------------------------------------------
# One shared evaluation date (point 13)
# ---------------------------------------------------------------------------

LAST_SUPPORT_DAY = EVAL
"""The inclusive General Support end of the boundary Product: in General
Support on this date and EOL on the next (product-catalog.md, Lifecycle
Evaluator steps 2 and 5)."""

NEXT_DAY = LAST_SUPPORT_DAY + timedelta(days=1)

ON_LAST_SUPPORT_DAY = (
    TicketStatus.ANALYZED,
    True,
    None,
    LifecyclePhase.GENERAL_SUPPORT,
    True,
    None,
)
"""(Ticket status, track actionable, track reason, Product phase, Product
actionable, Product reason): the `AFFECTED` track has an actionable eligible
Product, so the Ticket is `Analyzed`."""

ON_NEXT_DAY = (
    TicketStatus.RESOLVED,
    False,
    NonActionableReason.NO_ACTIONABLE_PRODUCTS,
    LifecyclePhase.EOL,
    False,
    NonActionableReason.EOL,
)
"""The track is in `M` but not in `A`: `Resolved` by empty-set universal
quantification (tickets.md, Deterministic Gate Edge Cases)."""


@pytest.mark.integration
class TestSharedEvaluationDate:
    """package-model.md, Derived Actionability (one UTC `evaluation_date`
    for mutation, reconciliation, and result projection);
    package-service.md, `set_track_status()` (`evaluation_date` captured once
    at entry when omitted) and Architectural Test Requirement: Derived
    actionability; testing-strategy.md, controlled-clock bullet.

    A CVE-less High `Analysis` Ticket whose single track goes from
    `ANALYSIS` to `AFFECTED` with one eligible Product whose General Support
    ends on `LAST_SUPPORT_DAY`."""

    @staticmethod
    async def _boundary_track(
        ticket: Ticket,
        product_factory: ProductFactory,
        ticket_package_factory: PackageFactory,
        ticket_package_track_factory: TrackFactory,
        ticket_package_product_factory: OccurrenceFactory,
    ) -> TicketPackageTrack:
        package = await ticket_package_factory(ticket_id=ticket.id)
        track = await ticket_package_track_factory(
            ticket_package_id=package.id, status=PackageStatus.ANALYSIS.value
        )
        product = await product_factory(general_support_end_date=LAST_SUPPORT_DAY)
        await ticket_package_product_factory(
            ticket_package_track_id=track.id, product_id=product.id
        )
        return track

    @staticmethod
    async def _assert_consistent(
        db: AsyncSession,
        result: TrackStatusResult,
        ticket: Ticket,
        track: TicketPackageTrack,
        actor: User,
        expected: tuple[Any, ...],
    ) -> None:
        after, actionable, reason, phase, product_actionable, product_reason = expected
        assert await ticket_state(db, ticket) == (after, actor.id)
        assert await ticket_events(db, ticket) == [
            await track_event(
                db, track, actor, PackageStatus.ANALYSIS, PackageStatus.AFFECTED
            ),
            status_event(TicketStatus.ANALYSIS, after),
        ]
        assert (result.track.actionable, result.track.non_actionable_reason) == (
            actionable,
            reason,
        )
        assert [
            (p.lifecycle_phase, p.actionable, p.non_actionable_reason)
            for p in result.track.products
        ] == [(phase, product_actionable, product_reason)]

    @pytest.mark.parametrize(
        ("evaluation_date", "expected"),
        [
            pytest.param(LAST_SUPPORT_DAY, ON_LAST_SUPPORT_DAY, id="last-support-day"),
            pytest.param(NEXT_DAY, ON_NEXT_DAY, id="next-day"),
        ],
    )
    async def test_explicit_date_drives_gate_and_projection(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        product_factory: ProductFactory,
        ticket_package_factory: PackageFactory,
        ticket_package_track_factory: TrackFactory,
        ticket_package_product_factory: OccurrenceFactory,
        monkeypatch: pytest.MonkeyPatch,
        evaluation_date: date,
        expected: tuple[Any, ...],
    ) -> None:
        actor = await va_user()
        ticket = await cveless(ticket_factory, assignee_id=actor.id)
        track = await self._boundary_track(
            ticket,
            product_factory,
            ticket_package_factory,
            ticket_package_track_factory,
            ticket_package_product_factory,
        )
        reconcile = Spy(monkeypatch, "reconcile_ticket_status")

        result = await set_status(
            db_session,
            track,
            PackageStatus.AFFECTED,
            actor,
            evaluation_date=evaluation_date,
        )

        assert [kwargs for _, kwargs in reconcile.calls] == [
            {"evaluation_date": evaluation_date}
        ]
        assert result.evaluation_date == evaluation_date
        await self._assert_consistent(
            db_session, result, ticket, track, actor, expected
        )

    @pytest.mark.parametrize(
        "clock",
        [
            pytest.param([LAST_SUPPORT_DAY], id="single-reading"),
            pytest.param([LAST_SUPPORT_DAY, NEXT_DAY], id="crossing-midnight"),
        ],
    )
    async def test_omitted_date_is_captured_once_at_entry(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        product_factory: ProductFactory,
        ticket_package_factory: PackageFactory,
        ticket_package_track_factory: TrackFactory,
        ticket_package_product_factory: OccurrenceFactory,
        monkeypatch: pytest.MonkeyPatch,
        clock: list[date],
    ) -> None:
        """The controlled clock would return `NEXT_DAY` on a second reading;
        only the first reading governs reconciliation and the projection."""
        actor = await va_user()
        ticket = await cveless(ticket_factory, assignee_id=actor.id)
        track = await self._boundary_track(
            ticket,
            product_factory,
            ticket_package_factory,
            ticket_package_track_factory,
            ticket_package_product_factory,
        )
        utc_today = Mock(side_effect=clock)
        monkeypatch.setattr(package_service, "_utc_today", utc_today)
        reconcile = Spy(monkeypatch, "reconcile_ticket_status")

        result = await set_track_status(
            db_session,
            ticket_id=ticket.id,
            package_id=track.ticket_package_id,
            track_id=track.id,
            status=PackageStatus.AFFECTED,
            acting_user_id=actor.id,
            caller=TicketCaller.authenticated(actor.id, Scope.ALL),
        )

        assert utc_today.call_count == 1
        assert [kwargs for _, kwargs in reconcile.calls] == [
            {"evaluation_date": LAST_SUPPORT_DAY}
        ]
        assert result.evaluation_date == LAST_SUPPORT_DAY
        await self._assert_consistent(
            db_session, result, ticket, track, actor, ON_LAST_SUPPORT_DAY
        )


# ---------------------------------------------------------------------------
# Whole-operation rollback (point 14) and audit-history independence (15)
# ---------------------------------------------------------------------------

SCENARIOS = pytest.mark.parametrize(
    "scenario", ["new-unassigned", "resolved-regression"]
)
"""`new-unassigned`: an unassigned `New` Ticket and an active VA actor, so
an effective change assigns, promotes to `Analysis`, and reaches
`Analyzed`. `resolved-regression`: an assigned `Resolved` Ticket whose
final track returns to `AFFECTED`, so reconciliation regresses it to
`Analyzed` and registers one Ticket convergence effect (ticket-mutations.md,
`reconcile_ticket_status()` step 5)."""


async def _scenario(
    scenario: str,
    ticket_factory: TicketFactory,
    tree: TreeBuilder,
    actor: User,
) -> tuple[Ticket, TicketPackageTrack, PackageStatus]:
    """Build the scenario; return its Ticket, track, and source status."""
    if scenario == "new-unassigned":
        ticket = await cveless(ticket_factory, status=TicketStatus.NEW)
        source = PackageStatus.ANALYSIS
    else:
        ticket = await cveless(
            ticket_factory, status=TicketStatus.RESOLVED, assignee_id=actor.id
        )
        source = PackageStatus.NOT_AFFECTED
    return ticket, await tree(ticket, status=source), source


@pytest.mark.integration
class TestRollback:
    """ticket-audit-log.md, Testing Requirement 7; package-service.md,
    `set_track_status()` Exceptions (audit, reconciliation, and flush
    failures propagate and roll back the caller-owned transaction).

    After the savepoint rollback, the track status, the Ticket status and
    assignee, the Ticket's events, and the pending convergence effects all
    equal the pre-call state."""

    @SCENARIOS
    @pytest.mark.parametrize(
        "failure",
        ["track-audit", "reconcile-before", "reconcile-after", "final-flush"],
    )
    async def test_failure_rolls_back_every_effect(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        tree: TreeBuilder,
        monkeypatch: pytest.MonkeyPatch,
        scenario: str,
        failure: str,
    ) -> None:
        actor = await va_user()
        ticket, track, source = await _scenario(scenario, ticket_factory, tree, actor)
        before = (
            await ticket_state(db_session, ticket),
            await ticket_events(db_session, ticket),
            await persisted_track_status(db_session, track),
            pending_ticket_convergence_effects(db_session),
        )
        assert before == (
            (
                (TicketStatus.NEW, None)
                if scenario == "new-unassigned"
                else (TicketStatus.RESOLVED, actor.id)
            ),
            [],
            source,
            (),
        )
        original_reconcile = ticket_mutations.reconcile_ticket_status
        reconciled = False

        async def reconcile(*args: Any, **kwargs: Any) -> None:
            nonlocal reconciled
            if failure == "reconcile-before":
                raise RuntimeError("injected reconciliation failure")
            await original_reconcile(*args, **kwargs)
            reconciled = True
            if failure == "reconcile-after":
                raise RuntimeError("injected reconciliation failure")

        original_log = TicketAuditLog.log_event

        async def log_event(*args: Any, **kwargs: Any) -> None:
            if kwargs["event_type"] is TicketAuditEventType.TRACK_STATUS_CHANGED:
                raise RuntimeError("injected audit failure")
            await original_log(*args, **kwargs)

        original_flush = db_session.flush

        async def flush(*args: Any, **kwargs: Any) -> None:
            if reconciled:
                raise RuntimeError("injected flush failure")
            await original_flush(*args, **kwargs)

        async with rollback_test_scope(db_session):
            monkeypatch.setattr(package_service, "reconcile_ticket_status", reconcile)
            if failure == "track-audit":
                # The class object `package_service` references by name.
                monkeypatch.setattr(TicketAuditLog, "log_event", log_event)
            elif failure == "final-flush":
                monkeypatch.setattr(db_session, "flush", flush)

            with pytest.raises(RuntimeError, match="injected"):
                await set_status(db_session, track, PackageStatus.AFFECTED, actor)

            if scenario == "resolved-regression" and reconciled:
                # The regression registered its effect before the failure.
                assert pending_ticket_convergence_effects(db_session) == (
                    TicketConvergenceEffect(ticket.id),
                )
        monkeypatch.undo()
        # The rollback expired every loaded instance.
        await db_session.refresh(ticket)
        await db_session.refresh(track)

        assert (
            await ticket_state(db_session, ticket),
            await ticket_events(db_session, ticket),
            await persisted_track_status(db_session, track),
            pending_ticket_convergence_effects(db_session),
        ) == before


@pytest.mark.integration
class TestNoAuditHistoryRead:
    """ticket-audit-log.md, Testing Requirement 25; testing-strategy.md,
    Audit Trail Testing (audit history is never queried to determine
    current state, authorization, or idempotency). An effective call only
    inserts into `ticket_audit_event`."""

    @pytest.mark.parametrize(
        "scenario", ["new-unassigned", "resolved-regression", "system"]
    )
    async def test_effective_call_never_selects_audit_history(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        tree: TreeBuilder,
        scenario: str,
    ) -> None:
        actor = await va_user()
        if scenario == "system":
            ticket, track, _ = await _scenario(
                "new-unassigned", ticket_factory, tree, actor
            )
            ticket.status = TicketStatus.ANALYSIS.value
            await db_session.flush()
            target, caller_actor = PackageStatus.FIXED, None
        else:
            ticket, track, _ = await _scenario(scenario, ticket_factory, tree, actor)
            target, caller_actor = PackageStatus.AFFECTED, actor

        with StatementRecorder(db_session) as recorder:
            result = await set_status(db_session, track, target, caller_actor)

        assert result.outcome is MutationOutcome.CHANGED
        audit = [s for s in recorder.statements if "ticket_audit_event" in s]
        assert audit
        assert [s for s in audit if not s.lstrip().upper().startswith("INSERT")] == []
