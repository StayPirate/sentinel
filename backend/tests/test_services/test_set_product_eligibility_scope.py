"""Single-session service integration tests for `set_product_eligibility()`
(backend/app/services/package_service.py), part B.

Owning specifications:

- docs/features/packages/package-service.md (Consumer caller context and
  Ticket accessibility; Semantic locators and locked ownership validation;
  `set_product_eligibility()`; Service Exceptions; Excluded and
  Non-Actionable Records; Architectural Test Requirement: Nested ownership
  validation, Atomic consumer accessibility (mutation part), Derived
  actionability (shared date), Override metadata transitions (one
  evaluation date)).
- docs/features/packages/package-model.md (Axis 2: Eligibility; Derived
  Actionability, including the one-date rule; Gate Participation;
  Continued Updates).
- docs/features/packages/product-catalog.md (Lifecycle Evaluator: inclusive
  phase-end dates).
- docs/features/identity/rbac.md (Scope and Confidential Ticket Visibility).
- docs/features/tickets/tickets.md (Mutability Guard; Gate: Analysis ->
  Analyzed; Gate: Analyzed -> Resolved; Deterministic Gate Edge Cases).
- docs/features/tickets/ticket-audit-log.md (Canonical Mutation and No-Event
  Matrix; Cross-Event Ordering, Locking, and Rollback; Testing Requirements
  7, 23 (rollback part), 25).
- docs/features/platform/testing-strategy.md (Ticket Accessibility: Locked
  mutations and the controlled-clock bullet; Rollback Within a Test; Audit
  Trail Testing).

Independent-session races are out of scope for this module; every test uses
the single `db_session`.

Unless a test states otherwise, a Ticket is CVE-less with
`severity_manual = High` and each factory-built track carries one Product
in General Support on `EVAL` with a `NULL` threshold, so a reset
recalculates `true` (the CVE-less `10.0` fallback against the implicit
`0.0`). Expected values are transcribed from the specifications, never
computed with the module under test.
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable
from datetime import date, timedelta
from typing import Any
from unittest.mock import Mock

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import (
    LifecyclePhase,
    NonActionableReason,
    PackageStatus,
    Role,
    Scope,
    TicketAuditEventType,
    TicketStatus,
)
from app.core.exceptions import TicketNotFoundError, TicketNotMutableError
from app.models.product import Product
from app.models.system_setting import SystemSetting
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
    PackageNotFoundError,
    ProductEligibilityResult,
    ProductNotFoundError,
    TrackNotFoundError,
)
from app.services.settings import RequiredSystemSettingMissingError
from app.services.ticket_audit_log import TicketAuditLog
from app.services.ticket_convergence_registry import (
    TicketConvergenceEffect,
    pending_ticket_convergence_effects,
)
from tests.support.cvss_chain import DEFAULT_VERSION
from tests.support.database import rollback_test_scope
from tests.support.product_eligibility import (
    assert_no_effects,
    eligibility_event,
    only_occurrence,
    persisted_occurrence,
    set_eligibility,
)
from tests.support.suse_cvss import assignment_event
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
from tests.support.track_status import Spy, ticket_state

pytest_plugins = ["tests.support.ticket_mutation_fixtures"]
"""Provides the shared `va_user` and `tree` fixtures."""

ProductFactory = Callable[..., Awaitable[Product]]
PackageFactory = Callable[..., Awaitable[TicketPackage]]
TrackFactory = Callable[..., Awaitable[TicketPackageTrack]]
OccurrenceFactory = Callable[..., Awaitable[TicketPackageProduct]]
GrantFactory = Callable[..., Awaitable[TicketAccessGrant]]
MaintainerFactory = Callable[..., Awaitable[TicketPackageMaintainer]]
SettingFactory = Callable[..., Awaitable[SystemSetting]]

REQUESTS = pytest.mark.parametrize(
    "request_value", [False, None], ids=["override", "clear"]
)
"""An override to `false` and a reset; with the seeded override `true`
occurrence both would be effective changes."""


@pytest.fixture
async def default_setting(system_setting_factory: SettingFactory) -> SystemSetting:
    """The persisted `default_cvss_version` (the test schema has none)."""
    return await system_setting_factory(
        key="default_cvss_version", value=DEFAULT_VERSION
    )


async def _restricted(va_user: VAUser) -> User:
    """An active `restricted_analyst`: effective scope `non_confidential`
    (rbac.md, Predefined Roles) and never auto-assigned (not a VA)."""
    return await va_user(roles=(Role.RESTRICTED_ANALYST,))


OVERRIDDEN = (Prod(eligible=True, override=True),)
"""One manual `true` override: an override to `false` and a reset to the
automatic value are both effective."""


# ---------------------------------------------------------------------------
# Nested ownership validation
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestNestedOwnership:
    """package-service.md, Semantic locators and locked ownership
    validation, `set_product_eligibility()` step 4, Service Exceptions, and
    Architectural Test Requirement: Nested ownership validation and Public
    Product identity (`ticket_package_product_id` is the package-tree
    occurrence, never the catalog `Product.id`). A mismatch never mutates
    or reveals the occurrence under the other path.

    The Ticket is unassigned and the actor an active VA, so an assignment
    would be visible."""

    @staticmethod
    async def _world(
        ticket_factory: TicketFactory,
        tree: TreeBuilder,
        product_factory: ProductFactory,
        ticket_package_track_factory: TrackFactory,
        ticket_package_product_factory: OccurrenceFactory,
        db: AsyncSession,
    ) -> dict[str, Any]:
        ticket = await cveless(ticket_factory)
        other_ticket = await cveless(ticket_factory)
        own_track = await tree(
            ticket, status=PackageStatus.ANALYSIS, products=OVERRIDDEN
        )
        own = await only_occurrence(db, own_track)
        sibling_track = await ticket_package_track_factory(
            ticket_package_id=own_track.ticket_package_id,
            status=PackageStatus.ANALYSIS.value,
        )
        sibling_product = await product_factory(general_support_end_date=AFTER_EVAL)
        same_package = await ticket_package_product_factory(
            ticket_package_track_id=sibling_track.id,
            product_id=sibling_product.id,
            eligible=True,
            is_eligible_override=True,
        )
        other_package_track = await tree(
            ticket, status=PackageStatus.ANALYSIS, products=OVERRIDDEN
        )
        other_package = await only_occurrence(db, other_package_track)
        foreign_track = await tree(
            other_ticket, status=PackageStatus.ANALYSIS, products=OVERRIDDEN
        )
        foreign = await only_occurrence(db, foreign_track)
        return {
            "ticket": ticket,
            "other_ticket": other_ticket,
            "own_track": own_track,
            "own": own,
            "sibling_track": sibling_track,
            "same_package": same_package,
            "other_package_track": other_package_track,
            "other_package": other_package,
            "foreign_track": foreign_track,
            "foreign": foreign,
        }

    @REQUESTS
    @pytest.mark.parametrize(
        ("case", "error"),
        [
            ("missing-package", PackageNotFoundError),
            ("package-of-other-ticket", PackageNotFoundError),
            ("missing-track", TrackNotFoundError),
            ("track-of-other-package", TrackNotFoundError),
            ("missing-occurrence", ProductNotFoundError),
            ("occurrence-of-sibling-track", ProductNotFoundError),
            ("occurrence-of-other-package", ProductNotFoundError),
            ("occurrence-of-other-ticket", ProductNotFoundError),
            ("catalog-product-id", ProductNotFoundError),
        ],
    )
    async def test_mismatched_path_raises_without_effects(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        tree: TreeBuilder,
        product_factory: ProductFactory,
        ticket_package_track_factory: TrackFactory,
        ticket_package_product_factory: OccurrenceFactory,
        default_setting: SystemSetting,
        monkeypatch: pytest.MonkeyPatch,
        request_value: bool | None,
        case: str,
        error: type[Exception],
    ) -> None:
        actor = await va_user()
        w = await self._world(
            ticket_factory,
            tree,
            product_factory,
            ticket_package_track_factory,
            ticket_package_product_factory,
            db_session,
        )
        own_track: TicketPackageTrack = w["own_track"]
        foreign_track: TicketPackageTrack = w["foreign_track"]
        other_track: TicketPackageTrack = w["other_package_track"]
        own = (own_track.ticket_package_id, own_track.id, w["own"].id)
        # (package_id, track_id, ticket_package_product_id) under the own
        # Ticket; a mismatched level names an existing record elsewhere.
        package_id, track_id, occurrence_id = {
            "missing-package": (uuid.uuid4(), own[1], own[2]),
            "package-of-other-ticket": (
                foreign_track.ticket_package_id,
                foreign_track.id,
                w["foreign"].id,
            ),
            "missing-track": (own[0], uuid.uuid4(), own[2]),
            "track-of-other-package": (own[0], other_track.id, w["other_package"].id),
            "missing-occurrence": (own[0], own[1], uuid.uuid4()),
            "occurrence-of-sibling-track": (own[0], own[1], w["same_package"].id),
            "occurrence-of-other-package": (own[0], own[1], w["other_package"].id),
            "occurrence-of-other-ticket": (own[0], own[1], w["foreign"].id),
            "catalog-product-id": (own[0], own[1], w["own"].product_id),
        }[case]

        await assert_no_effects(
            db_session,
            monkeypatch,
            lambda: set_eligibility(
                db_session,
                w["own"],
                request_value,
                actor,
                ticket_id=w["ticket"].id,
                package_id=package_id,
                track_id=track_id,
                occurrence_id=occurrence_id,
            ),
            tickets=(w["ticket"], w["other_ticket"]),
            occurrences=(w["own"], w["same_package"], w["other_package"], w["foreign"]),
            error=error,
        )

    @REQUESTS
    async def test_correct_path_changes_only_the_declared_occurrence(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        tree: TreeBuilder,
        product_factory: ProductFactory,
        ticket_package_track_factory: TrackFactory,
        ticket_package_product_factory: OccurrenceFactory,
        default_setting: SystemSetting,
        request_value: bool | None,
    ) -> None:
        actor = await va_user()
        w = await self._world(
            ticket_factory,
            tree,
            product_factory,
            ticket_package_track_factory,
            ticket_package_product_factory,
            db_session,
        )
        own: TicketPackageProduct = w["own"]
        expected = (False, True) if request_value is False else (True, False)

        result = await set_eligibility(db_session, own, request_value, actor)

        assert (result.outcome, result.product.id) == (
            MutationOutcome.CHANGED,
            own.id,
        )
        assert [
            await persisted_occurrence(db_session, w[name])
            for name in ("own", "same_package", "other_package", "foreign")
        ] == [expected, (True, True), (True, True), (True, True)]
        assert await ticket_events(db_session, w["ticket"]) == [
            assignment_event(actor),
            await eligibility_event(
                db_session,
                own,
                actor,
                True,
                expected[0],
                "changed" if request_value is False else "cleared",
            ),
        ]
        assert await ticket_events(db_session, w["other_ticket"]) == []


# ---------------------------------------------------------------------------
# Locked-current consumer accessibility
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestAccessibility:
    """package-service.md, Consumer caller context and Ticket accessibility
    and `set_product_eligibility()` step 2; rbac.md, Scope and Confidential
    Ticket Visibility; testing-strategy.md, Ticket Accessibility (Locked
    mutations: nested-resource, operability, and idempotency decisions
    never precede the denial)."""

    async def test_missing_ticket_raises_without_effects(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        tree: TreeBuilder,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        actor = await va_user()
        ticket = await cveless(ticket_factory)
        track = await tree(ticket, status=PackageStatus.ANALYSIS, products=OVERRIDDEN)
        occurrence = await only_occurrence(db_session, track)

        await assert_no_effects(
            db_session,
            monkeypatch,
            lambda: set_eligibility(
                db_session, occurrence, False, actor, ticket_id=uuid.uuid4()
            ),
            tickets=(ticket,),
            occurrences=(occurrence,),
            error=TicketNotFoundError,
        )

    @pytest.mark.parametrize(
        "case",
        [
            "no-visibility-path",
            "maintainer-of-own-excluded-package",
            "no-op-request",
            "wrong-occurrence-id",
        ],
    )
    async def test_inaccessible_ticket_raises_before_every_other_decision(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        tree: TreeBuilder,
        ticket_access_grant_factory: GrantFactory,
        ticket_package_maintainer_factory: MaintainerFactory,
        monkeypatch: pytest.MonkeyPatch,
        case: str,
    ) -> None:
        """A confidential Ticket seen by a `non_confidential` caller with no
        own grant and no included maintained package is not found. Another
        user's grant and maintainership never qualify the caller; a
        maintainership of an excluded package does not qualify. Neither the
        no-op classification nor the occurrence lookup precedes the
        denial."""
        actor = await _restricted(va_user)
        other = await va_user()
        ticket = await cveless(ticket_factory, is_confidential=True)
        track = await tree(
            ticket,
            status=PackageStatus.ANALYSIS,
            products=OVERRIDDEN,
            package_excluded=case == "maintainer-of-own-excluded-package",
        )
        occurrence = await only_occurrence(db_session, track)
        await ticket_access_grant_factory(ticket_id=ticket.id, user_id=other.id)
        await ticket_package_maintainer_factory(
            ticket_package_id=track.ticket_package_id, user_id=other.id
        )
        if case == "maintainer-of-own-excluded-package":
            await ticket_package_maintainer_factory(
                ticket_package_id=track.ticket_package_id, user_id=actor.id
            )
        request_value = case == "no-op-request"
        occurrence_id = uuid.uuid4() if case == "wrong-occurrence-id" else None

        await assert_no_effects(
            db_session,
            monkeypatch,
            lambda: set_eligibility(
                db_session,
                occurrence,
                request_value,
                actor,
                occurrence_id=occurrence_id,
                scope=Scope.NON_CONFIDENTIAL,
            ),
            tickets=(ticket,),
            occurrences=(occurrence,),
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
        is not a VA, so the unassigned Ticket stays unassigned."""
        actor = await _restricted(va_user)
        ticket = await cveless(ticket_factory, is_confidential=confidential)
        track = await tree(ticket, status=PackageStatus.ANALYSIS, products=OVERRIDDEN)
        occurrence = await only_occurrence(db_session, track)
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

        result = await set_eligibility(
            db_session, occurrence, False, actor, scope=scope
        )

        assert result.outcome is MutationOutcome.CHANGED
        assert await persisted_occurrence(db_session, occurrence) == (False, True)
        assert await ticket_state(db_session, ticket) == (TicketStatus.ANALYSIS, None)
        assert await ticket_events(db_session, ticket) == [
            await eligibility_event(
                db_session, occurrence, actor, True, False, "changed"
            )
        ]


# ---------------------------------------------------------------------------
# Manual-zone operability
# ---------------------------------------------------------------------------

MANUAL_ZONE = pytest.mark.parametrize(
    "zone", [TicketStatus.IGNORED, TicketStatus.DUPLICATED], ids=str
)


@pytest.mark.integration
class TestManualZone:
    """tickets.md, Mutability Guard; package-service.md,
    `set_product_eligibility()` steps 2-4 and Ticket-level operability:
    accessibility precedes operability, which precedes the locked path
    reload and the no-op classification."""

    @MANUAL_ZONE
    @REQUESTS
    async def test_manual_zone_ticket_is_not_mutable(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        tree: TreeBuilder,
        monkeypatch: pytest.MonkeyPatch,
        zone: TicketStatus,
        request_value: bool | None,
    ) -> None:
        """An unassigned manual-zone Ticket and an active VA actor: neither
        the change, the assignment, nor any other effect occurs."""
        actor = await va_user()
        ticket = await cveless(ticket_factory, status=zone)
        track = await tree(ticket, status=PackageStatus.ANALYSIS, products=OVERRIDDEN)
        occurrence = await only_occurrence(db_session, track)

        await assert_no_effects(
            db_session,
            monkeypatch,
            lambda: set_eligibility(db_session, occurrence, request_value, actor),
            tickets=(ticket,),
            occurrences=(occurrence,),
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
        track = await tree(ticket, status=PackageStatus.ANALYSIS, products=OVERRIDDEN)
        occurrence = await only_occurrence(db_session, track)

        await assert_no_effects(
            db_session,
            monkeypatch,
            lambda: set_eligibility(
                db_session, occurrence, False, actor, scope=Scope.NON_CONFIDENTIAL
            ),
            tickets=(ticket,),
            occurrences=(occurrence,),
            error=TicketNotFoundError,
        )

    @MANUAL_ZONE
    @pytest.mark.parametrize("case", ["missing-occurrence", "no-op-request"])
    async def test_operability_precedes_path_reload_and_no_op(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        tree: TreeBuilder,
        monkeypatch: pytest.MonkeyPatch,
        zone: TicketStatus,
        case: str,
    ) -> None:
        """A missing occurrence raises `TicketNotMutableError`, not
        `ProductNotFoundError`; a request equal to the locked override is
        rejected rather than classified as a no-op."""
        actor = await va_user()
        ticket = await cveless(ticket_factory, status=zone)
        track = await tree(ticket, status=PackageStatus.ANALYSIS, products=OVERRIDDEN)
        occurrence = await only_occurrence(db_session, track)
        missing = case == "missing-occurrence"

        await assert_no_effects(
            db_session,
            monkeypatch,
            lambda: set_eligibility(
                db_session,
                occurrence,
                not missing,
                actor,
                occurrence_id=uuid.uuid4() if missing else None,
            ),
            tickets=(ticket,),
            occurrences=(occurrence,),
            error=TicketNotMutableError,
        )


# ---------------------------------------------------------------------------
# Excluded and EOL occurrences remain mutable
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestExcludedAndEolOccurrences:
    """package-service.md, Package-tree exclusion and actionability
    (mutation functions do not require `deleted_at IS NULL`); package-model.md,
    Continued Updates (exclusion and EOL never suppress a permitted
    eligibility update) and Axis 2 (neither is a formula input).

    The occurrence is seeded as a manual `false` for a reset (recalculated
    `true`) and as an automatic `true` for an override to `false`. It is the
    Ticket's only occurrence, so the seeded Ticket status is the gate result
    (tickets.md, Deterministic Gate Edge Cases): an excluded track or
    package leaves `M` empty (`Analysis`); a directly excluded or EOL
    Product leaves its included track in `M` but not in `A` (`Resolved`).
    No gate event therefore follows the eligibility event."""

    @pytest.mark.parametrize(
        ("kind", "status"),
        [
            ("product-excluded", TicketStatus.RESOLVED),
            ("effective-through-track", TicketStatus.ANALYSIS),
            ("effective-through-package", TicketStatus.ANALYSIS),
            ("product-excluded-beneath-excluded-track", TicketStatus.ANALYSIS),
            ("eol", TicketStatus.RESOLVED),
        ],
    )
    @pytest.mark.parametrize("request_value", [False, None], ids=["set", "clear"])
    async def test_non_actionable_occurrence_changes_with_its_event(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        tree: TreeBuilder,
        default_setting: SystemSetting,
        monkeypatch: pytest.MonkeyPatch,
        kind: str,
        status: TicketStatus,
        request_value: bool | None,
    ) -> None:
        actor = await va_user()
        ticket = await cveless(ticket_factory, status=status, assignee_id=actor.id)
        clear = request_value is None
        track = await tree(
            ticket,
            status=PackageStatus.ANALYSIS,
            products=(
                Prod(
                    eligible=not clear,
                    override=clear,
                    eol=kind == "eol",
                    excluded=kind.startswith("product-excluded"),
                ),
            ),
            track_excluded=kind
            in ("effective-through-track", "product-excluded-beneath-excluded-track"),
            package_excluded=kind == "effective-through-package",
        )
        occurrence = await only_occurrence(db_session, track)
        reconcile = Spy(monkeypatch, "reconcile_ticket_status")

        result = await set_eligibility(db_session, occurrence, request_value, actor)

        expected = (True, False) if clear else (False, True)
        assert result.outcome is MutationOutcome.CHANGED
        assert result.product.actionable is False
        assert await persisted_occurrence(db_session, occurrence) == expected
        assert len(reconcile.calls) == 1
        assert await ticket_state(db_session, ticket) == (status, actor.id)
        assert await ticket_events(db_session, ticket) == [
            await eligibility_event(
                db_session,
                occurrence,
                actor,
                not expected[0],
                expected[0],
                "cleared" if clear else "set",
            )
        ]


# ---------------------------------------------------------------------------
# One shared evaluation date
# ---------------------------------------------------------------------------

LAST_EXTENDED_DAY = EVAL
"""The inclusive Extended Support end of the reactive-boundary Product: in
Extended Support on this date and in Reactive Support on the next
(product-catalog.md, Lifecycle Evaluator steps 3-4)."""

LAST_SUPPORT_DAY = EVAL
"""The inclusive General Support end of the EOL-boundary Product: in General
Support on this date and EOL on the next (steps 2 and 5)."""

NEXT_DAY = EVAL + timedelta(days=1)


async def _boundary_occurrence(
    ticket: Ticket,
    boundary: str,
    *,
    product_factory: ProductFactory,
    ticket_package_factory: PackageFactory,
    ticket_package_track_factory: TrackFactory,
    ticket_package_product_factory: OccurrenceFactory,
) -> TicketPackageProduct:
    """One `AFFECTED` track with one boundary Product occurrence.

    `reactive`: a manual `true` override of a Product whose Extended
    Support ends on `LAST_EXTENDED_DAY`. `eol`: an automatic `false` of a
    Product whose General Support ends on `LAST_SUPPORT_DAY`."""
    package = await ticket_package_factory(ticket_id=ticket.id)
    track = await ticket_package_track_factory(
        ticket_package_id=package.id, status=PackageStatus.AFFECTED.value
    )
    if boundary == "reactive":
        product = await product_factory(
            general_support_end_date=BEFORE_EVAL,
            extended_support_end_date=LAST_EXTENDED_DAY,
            reactive_support_end_date=AFTER_EVAL,
        )
    else:
        product = await product_factory(general_support_end_date=LAST_SUPPORT_DAY)
    return await ticket_package_product_factory(
        ticket_package_track_id=track.id,
        product_id=product.id,
        eligible=boundary == "reactive",
        is_eligible_override=boundary == "reactive",
    )


BOUNDARY_CASES = [
    # (boundary, date, request, before, after, eligible, phase, actionable,
    #  reason, action)
    pytest.param(
        "reactive",
        LAST_EXTENDED_DAY,
        None,
        TicketStatus.ANALYZED,
        TicketStatus.ANALYZED,
        True,
        LifecyclePhase.EXTENDED_SUPPORT,
        True,
        None,
        "cleared",
        id="reset-on-last-extended-day",
    ),
    pytest.param(
        "reactive",
        NEXT_DAY,
        None,
        TicketStatus.ANALYZED,
        TicketStatus.RESOLVED,
        False,
        LifecyclePhase.REACTIVE_SUPPORT,
        True,
        None,
        "cleared",
        id="reset-on-first-reactive-day",
    ),
    pytest.param(
        "eol",
        LAST_SUPPORT_DAY,
        True,
        TicketStatus.RESOLVED,
        TicketStatus.ANALYZED,
        True,
        LifecyclePhase.GENERAL_SUPPORT,
        True,
        None,
        "set",
        id="override-on-last-support-day",
    ),
    pytest.param(
        "eol",
        NEXT_DAY,
        True,
        TicketStatus.RESOLVED,
        TicketStatus.RESOLVED,
        True,
        LifecyclePhase.EOL,
        False,
        NonActionableReason.EOL,
        "set",
        id="override-on-first-eol-day",
    ),
]
"""A CVE-less High Ticket (`10.0` fallback, `NULL` threshold). Reset: the
Reactive Support rule forces `false` on the next day, emptying `AEP` of the
`AFFECTED` track (clause (c): `Resolved`). Override `true`: an actionable
eligible Product gives `Analyzed`; on the first EOL day the track has no
actionable Product, so `A` is empty and the Ticket stays `Resolved`
(tickets.md, Deterministic Gate Edge Cases)."""


@pytest.mark.integration
class TestSharedEvaluationDate:
    """package-model.md, Derived Actionability (one UTC `evaluation_date`
    for lifecycle evaluation, reconciliation, and result projection);
    package-service.md, `set_product_eligibility()` (both paths reuse the
    one date; captured once at entry when omitted) and Architectural Test
    Requirement: Derived actionability and Override metadata transitions;
    testing-strategy.md, controlled-clock bullet."""

    @pytest.mark.parametrize(
        (
            "boundary",
            "evaluation_date",
            "request_value",
            "before",
            "after",
            "eligible",
            "phase",
            "actionable",
            "reason",
            "action",
        ),
        BOUNDARY_CASES,
    )
    async def test_explicit_date_drives_recalculation_gate_and_projection(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        product_factory: ProductFactory,
        ticket_package_factory: PackageFactory,
        ticket_package_track_factory: TrackFactory,
        ticket_package_product_factory: OccurrenceFactory,
        default_setting: SystemSetting,
        monkeypatch: pytest.MonkeyPatch,
        boundary: str,
        evaluation_date: date,
        request_value: bool | None,
        before: TicketStatus,
        after: TicketStatus,
        eligible: bool,
        phase: LifecyclePhase,
        actionable: bool,
        reason: NonActionableReason | None,
        action: str,
    ) -> None:
        actor = await va_user()
        ticket = await cveless(ticket_factory, status=before, assignee_id=actor.id)
        occurrence = await _boundary_occurrence(
            ticket,
            boundary,
            product_factory=product_factory,
            ticket_package_factory=ticket_package_factory,
            ticket_package_track_factory=ticket_package_track_factory,
            ticket_package_product_factory=ticket_package_product_factory,
        )
        old = occurrence.eligible
        reconcile = Spy(monkeypatch, "reconcile_ticket_status")

        result = await set_eligibility(
            db_session,
            occurrence,
            request_value,
            actor,
            evaluation_date=evaluation_date,
        )

        assert [kwargs for _, kwargs in reconcile.calls] == [
            {"evaluation_date": evaluation_date}
        ]
        assert result.evaluation_date == evaluation_date
        assert (
            result.product.eligible,
            result.product.lifecycle_phase,
            result.product.actionable,
            result.product.non_actionable_reason,
        ) == (eligible, phase, actionable, reason)
        gate = [status_event(before, after)] if before != after else []
        assert await ticket_state(db_session, ticket) == (after, actor.id)
        assert await ticket_events(db_session, ticket) == [
            await eligibility_event(
                db_session, occurrence, actor, old, eligible, action
            ),
            *gate,
        ]

    @pytest.mark.parametrize(
        "clock",
        [
            pytest.param([LAST_EXTENDED_DAY], id="single-reading"),
            pytest.param([LAST_EXTENDED_DAY, NEXT_DAY], id="crossing-midnight"),
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
        default_setting: SystemSetting,
        monkeypatch: pytest.MonkeyPatch,
        clock: list[date],
    ) -> None:
        """The controlled clock would return `NEXT_DAY` (Reactive Support)
        on a second reading; only the first reading governs the
        recalculation, the reconciliation, and the projection."""
        actor = await va_user()
        ticket = await cveless(
            ticket_factory, status=TicketStatus.ANALYZED, assignee_id=actor.id
        )
        occurrence = await _boundary_occurrence(
            ticket,
            "reactive",
            product_factory=product_factory,
            ticket_package_factory=ticket_package_factory,
            ticket_package_track_factory=ticket_package_track_factory,
            ticket_package_product_factory=ticket_package_product_factory,
        )
        utc_today = Mock(side_effect=clock)
        monkeypatch.setattr(package_service, "_utc_today", utc_today)
        reconcile = Spy(monkeypatch, "reconcile_ticket_status")

        result = await set_eligibility(
            db_session, occurrence, None, actor, evaluation_date=None
        )

        assert utc_today.call_count == 1
        assert [kwargs for _, kwargs in reconcile.calls] == [
            {"evaluation_date": LAST_EXTENDED_DAY}
        ]
        assert result.evaluation_date == LAST_EXTENDED_DAY
        assert (result.product.eligible, result.product.lifecycle_phase) == (
            True,
            LifecyclePhase.EXTENDED_SUPPORT,
        )
        assert await persisted_occurrence(db_session, occurrence) == (True, False)
        assert await ticket_state(db_session, ticket) == (
            TicketStatus.ANALYZED,
            actor.id,
        )
        assert await ticket_events(db_session, ticket) == [
            await eligibility_event(
                db_session, occurrence, actor, True, True, "cleared"
            )
        ]


# ---------------------------------------------------------------------------
# Whole-operation rollback and audit-history independence
# ---------------------------------------------------------------------------

SCENARIOS = pytest.mark.parametrize(
    "scenario", ["new-unassigned", "resolved-regression"]
)
"""`new-unassigned`: an unassigned `New` Ticket and an active VA actor, so an
effective change assigns, promotes to `Analysis`, and reaches `Analyzed`.
`resolved-regression`: an assigned `Resolved` Ticket whose only `AFFECTED`
track has a manual `false` Product that becomes `true` (override or
recalculation), so reconciliation regresses it to `Analyzed` and registers
one Ticket convergence effect (ticket-mutations.md,
`reconcile_ticket_status()` step 5)."""


async def _scenario(
    scenario: str, ticket_factory: TicketFactory, tree: TreeBuilder, actor: User
) -> Ticket:
    if scenario == "new-unassigned":
        return await cveless(ticket_factory, status=TicketStatus.NEW)
    return await cveless(
        ticket_factory, status=TicketStatus.RESOLVED, assignee_id=actor.id
    )


FAILURES = [
    pytest.param("settings-missing", None, id="settings-missing-clear"),
    *(
        pytest.param(failure, request_value, id=f"{failure}-{label}")
        for failure in ("audit", "reconcile-before", "reconcile-after", "final-flush")
        for request_value, label in ((True, "override"), (None, "clear"))
    ),
]
"""`settings-missing`: no `default_cvss_version` row, so the reset's
recalculation raises `RequiredSystemSettingMissingError` after the
assignment and the marker clear."""


@pytest.mark.integration
class TestRollback:
    """ticket-audit-log.md, Testing Requirement 7 and Cross-Event Ordering,
    Locking, and Rollback; package-service.md, `set_product_eligibility()`
    Exceptions (settings, eligibility-resolution, audit, reconciliation,
    and flush failures propagate and roll back the caller-owned
    transaction).

    After the savepoint rollback, the occurrence, the Ticket status and
    assignee, the Ticket's events, and the pending convergence effects all
    equal the pre-call state."""

    @SCENARIOS
    @pytest.mark.parametrize(("failure", "request_value"), FAILURES)
    async def test_failure_rolls_back_every_effect(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        tree: TreeBuilder,
        system_setting_factory: SettingFactory,
        monkeypatch: pytest.MonkeyPatch,
        scenario: str,
        failure: str,
        request_value: bool | None,
    ) -> None:
        actor = await va_user()
        if failure != "settings-missing":
            await system_setting_factory(
                key="default_cvss_version", value=DEFAULT_VERSION
            )
        ticket = await _scenario(scenario, ticket_factory, tree, actor)
        track = await tree(
            ticket,
            status=PackageStatus.AFFECTED,
            products=(Prod(eligible=False, override=True),),
        )
        occurrence = await only_occurrence(db_session, track)
        before = (
            await ticket_state(db_session, ticket),
            await ticket_events(db_session, ticket),
            await persisted_occurrence(db_session, occurrence),
            pending_ticket_convergence_effects(db_session),
        )
        assert before == (
            (
                (TicketStatus.NEW, None)
                if scenario == "new-unassigned"
                else (TicketStatus.RESOLVED, actor.id)
            ),
            [],
            (False, True),
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
            if kwargs["event_type"] is TicketAuditEventType.PRODUCT_ELIGIBILITY_CHANGED:
                raise RuntimeError("injected audit failure")
            await original_log(*args, **kwargs)

        original_flush = db_session.flush

        async def flush(*args: Any, **kwargs: Any) -> None:
            if reconciled:
                raise RuntimeError("injected flush failure")
            await original_flush(*args, **kwargs)

        expected_error: type[Exception] = (
            RequiredSystemSettingMissingError
            if failure == "settings-missing"
            else RuntimeError
        )

        async with rollback_test_scope(db_session):
            monkeypatch.setattr(package_service, "reconcile_ticket_status", reconcile)
            if failure == "audit":
                # The class object `package_service` references by name.
                monkeypatch.setattr(TicketAuditLog, "log_event", log_event)
            elif failure == "final-flush":
                monkeypatch.setattr(db_session, "flush", flush)

            with pytest.raises(expected_error):
                await set_eligibility(db_session, occurrence, request_value, actor)

            if scenario == "resolved-regression" and reconciled:
                # The regression registered its effect before the failure.
                assert pending_ticket_convergence_effects(db_session) == (
                    TicketConvergenceEffect(ticket.id),
                )
        monkeypatch.undo()
        # The rollback expired every loaded instance.
        await db_session.refresh(ticket)
        await db_session.refresh(occurrence)

        assert (
            await ticket_state(db_session, ticket),
            await ticket_events(db_session, ticket),
            await persisted_occurrence(db_session, occurrence),
            pending_ticket_convergence_effects(db_session),
        ) == before


@pytest.mark.integration
class TestNoAuditHistoryRead:
    """ticket-audit-log.md, Testing Requirement 25; testing-strategy.md,
    Audit Trail Testing (audit history is never queried to determine
    current state, authorization, or idempotency). An effective call only
    inserts into `ticket_audit_event`; a no-op never touches it."""

    @pytest.mark.parametrize(
        ("scenario", "request_value", "outcome"),
        [
            ("new-unassigned", True, MutationOutcome.CHANGED),
            ("resolved-regression", None, MutationOutcome.CHANGED),
            ("resolved-regression", False, MutationOutcome.NO_OP),
        ],
        ids=["override", "clear", "no-op"],
    )
    async def test_call_never_selects_audit_history(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        tree: TreeBuilder,
        default_setting: SystemSetting,
        scenario: str,
        request_value: bool | None,
        outcome: MutationOutcome,
    ) -> None:
        actor = await va_user()
        ticket = await _scenario(scenario, ticket_factory, tree, actor)
        track = await tree(
            ticket,
            status=PackageStatus.AFFECTED,
            products=(Prod(eligible=False, override=True),),
        )
        occurrence = await only_occurrence(db_session, track)

        with StatementRecorder(db_session) as recorder:
            result: ProductEligibilityResult = await set_eligibility(
                db_session, occurrence, request_value, actor
            )

        assert result.outcome is outcome
        audit = [s for s in recorder.statements if "ticket_audit_event" in s]
        assert recorder.selects_from("ticket_audit_event") == []
        assert [s for s in audit if not s.lstrip().upper().startswith("INSERT")] == []
        assert bool(audit) is (outcome is MutationOutcome.CHANGED)
