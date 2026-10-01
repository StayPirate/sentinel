"""Single-session service integration tests for the package-tree exclusion
and restoration operations (backend/app/services/package_service.py:
`soft_delete_ticket_package[_track|_product]()` and
`restore_ticket_package[_track|_product]()`), part B.

Owning specifications:

- docs/features/packages/package-service.md (Semantic locators and locked
  ownership validation; Exclusion and restoration operations steps 1-10;
  Service Exceptions; Ticket-level operability; Architectural Test
  Requirement: Nested ownership validation, Derived actionability (one
  shared UTC date, crossing midnight), Public Product identity (the
  occurrence locator is never a catalog `Product.id`), Exclusion/restore
  actor and rollback).
- docs/features/packages/package-model.md (Derived Actionability, including
  the one-date rule; Gate Participation; the endpoint sections' "projected
  from locked-current state ... shared with Ticket reconciliation" rule).
- docs/features/packages/product-catalog.md (Lifecycle Evaluator: inclusive
  phase-end dates).
- docs/features/tickets/tickets.md (Mutability Guard; Gate: Analysis ->
  Analyzed; Gate: Analyzed -> Resolved).
- docs/features/tickets/ticket-audit-log.md (Canonical Mutation and No-Event
  Matrix; Cross-Event Ordering, Locking, and Rollback; Testing Requirements
  7, 14, 25).
- docs/features/platform/testing-strategy.md (Ticket Accessibility:
  controlled-clock bullet; Rollback Within a Test; Audit Trail Testing).

Accessibility and independent-session races are out of scope for this
module; every test uses the single `db_session`.

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
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import (
    NonActionableReason,
    PackageStatus,
    Scope,
    TicketAuditEventType,
    TicketStatus,
)
from app.core.exceptions import TicketNotFoundError, TicketNotMutableError
from app.models.ticket import Ticket
from app.models.ticket_package_product import TicketPackageProduct
from app.models.ticket_package_track import TicketPackageTrack
from app.services import package_service, ticket_mutations
from app.services.package_service import (
    SYSTEM_INVOCATION,
    PackageAlreadyExcludedError,
    PackageNotExcludedError,
    PackageNotFoundError,
    ProductNotFoundError,
    TrackNotFoundError,
)
from app.services.ticket_audit_log import TicketAuditLog
from app.services.ticket_convergence_registry import (
    TicketConvergenceEffect,
    pending_ticket_convergence_effects,
)
from app.services.ticket_visibility import TicketCaller
from tests.support.database import rollback_test_scope
from tests.support.package_exclusion import (
    DIRECTIONS,
    LEVELS,
    MARKER_NOW,
    Direction,
    Level,
    assert_no_effects,
    call_operation,
    change,
    gate_world,
    marker_event,
    markers,
    observed,
    patch_marker_now,
    with_target,
)
from tests.support.product_eligibility import occurrence_path, only_occurrence
from tests.support.suse_cvss import assignment_event
from tests.support.ticket_mutations import (
    AFTER_EVAL,
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

Factory = Callable[..., Awaitable[Any]]

PROMOTION = status_event(TicketStatus.NEW, TicketStatus.ANALYSIS)
"""The system `New -> Analysis` event of the auto-assignment."""

MARKER_EVENTS = frozenset(
    {
        TicketAuditEventType.PACKAGE_EXCLUDED,
        TicketAuditEventType.TRACK_EXCLUDED,
        TicketAuditEventType.PRODUCT_EXCLUDED,
        TicketAuditEventType.PACKAGE_RESTORED,
        TicketAuditEventType.TRACK_RESTORED,
        TicketAuditEventType.PRODUCT_RESTORED,
    }
)


@pytest.fixture(autouse=True)
def _marker_clock(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every exclusion sets its marker to the controlled `MARKER_NOW`."""
    patch_marker_now(monkeypatch)


# ---------------------------------------------------------------------------
# Caller boundary
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestCallerValidation:
    """package-service.md, Exclusion and restoration operations step 1 (a
    `None` actor raises `ValueError` before any database operation; there is
    no system caller), Exclusion and Actionability Invariant, and
    Architectural Test Requirement: Exclusion/restore actor. A non-consumer
    context or a caller that does not identify the actor is the same
    caller-contract violation."""

    @LEVELS
    @DIRECTIONS
    @pytest.mark.parametrize(
        "case", ["null-actor", "other-user", "anonymous", "system-invocation"]
    )
    async def test_inconsistent_pairing_raises_before_any_statement(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        tree: TreeBuilder,
        level: Level,
        direction: Direction,
        case: str,
    ) -> None:
        actor = await va_user()
        other = await va_user()
        ticket = await cveless(ticket_factory, status=TicketStatus.NEW)
        seeded = direction is Direction.RESTORE
        track = await tree(
            ticket,
            status=PackageStatus.ANALYSIS,
            products=(Prod(excluded=seeded),),
            package_excluded=seeded,
            track_excluded=seeded,
        )
        occurrence = await only_occurrence(db_session, track)
        ticket_id, package_id, track_id = await occurrence_path(db_session, occurrence)
        before = await markers(db_session, occurrence)
        pairings: dict[str, tuple[Any, Any]] = {
            "null-actor": (None, TicketCaller.authenticated(actor.id, Scope.ALL)),
            "other-user": (actor.id, TicketCaller.authenticated(other.id, Scope.ALL)),
            "anonymous": (actor.id, TicketCaller()),
            "system-invocation": (None, SYSTEM_INVOCATION),
        }
        acting_user_id, caller = pairings[case]

        with (
            StatementRecorder(db_session) as recorder,
            pytest.raises(ValueError, match="acting user"),
        ):
            await call_operation(
                db_session,
                level,
                direction,
                ticket_id=ticket_id,
                package_id=package_id,
                track_id=track_id,
                occurrence_id=occurrence.id,
                acting_user_id=acting_user_id,
                caller=caller,
            )

        assert recorder.statements == []
        assert await markers(db_session, occurrence) == before
        assert await ticket_events(db_session, ticket) == []
        assert await ticket_state(db_session, ticket) == (TicketStatus.NEW, None)
        assert pending_ticket_convergence_effects(db_session) == ()

    @DIRECTIONS
    async def test_system_invocation_with_actor_raises_before_any_statement(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        tree: TreeBuilder,
        direction: Direction,
    ) -> None:
        """The system context is rejected even when an actor is supplied."""
        actor = await va_user()
        ticket = await cveless(ticket_factory, status=TicketStatus.NEW)
        seeded = direction is Direction.RESTORE
        track = await tree(
            ticket, status=PackageStatus.ANALYSIS, package_excluded=seeded
        )
        occurrence = await only_occurrence(db_session, track)

        with (
            StatementRecorder(db_session) as recorder,
            pytest.raises(ValueError, match="acting user"),
        ):
            await call_operation(
                db_session,
                Level.PACKAGE,
                direction,
                ticket_id=ticket.id,
                package_id=track.ticket_package_id,
                track_id=track.id,
                occurrence_id=occurrence.id,
                acting_user_id=actor.id,
                caller=SYSTEM_INVOCATION,
            )

        assert recorder.statements == []
        assert await ticket_events(db_session, ticket) == []


# ---------------------------------------------------------------------------
# Nested ownership validation
# ---------------------------------------------------------------------------

# Each case: (deepest locator level it applies to, expected error).
PATH_CASES: dict[str, tuple[Level, type[Exception]]] = {
    "missing-ticket": (Level.PACKAGE, TicketNotFoundError),
    "missing-package": (Level.PACKAGE, PackageNotFoundError),
    "package-of-other-ticket": (Level.PACKAGE, PackageNotFoundError),
    "missing-track": (Level.TRACK, TrackNotFoundError),
    "track-of-other-package": (Level.TRACK, TrackNotFoundError),
    "track-of-other-ticket": (Level.TRACK, TrackNotFoundError),
    "missing-occurrence": (Level.PRODUCT, ProductNotFoundError),
    "occurrence-of-sibling-track": (Level.PRODUCT, ProductNotFoundError),
    "occurrence-of-other-package": (Level.PRODUCT, ProductNotFoundError),
    "occurrence-of-other-ticket": (Level.PRODUCT, ProductNotFoundError),
    "catalog-product-id": (Level.PRODUCT, ProductNotFoundError),
}
"""package-service.md, Semantic locators and locked ownership validation:
a missing identifier or one that belongs to another declared parent raises
the not-found exception of its level; the occurrence locator is the
`TicketPackageProduct.id`, never the catalog `Product.id`."""


def _path_cases() -> list[Any]:
    order = list(Level)
    return [
        pytest.param(level, case, error, id=f"{level}-{case}")
        for level in Level
        for case, (applies, error) in PATH_CASES.items()
        if order.index(applies) <= order.index(level)
    ]


@pytest.mark.integration
class TestNestedOwnership:
    """package-service.md, Semantic locators and locked ownership
    validation, Exclusion and restoration operations step 5, Service
    Exceptions, and Architectural Test Requirement: Nested ownership
    validation (a correct path, each missing level, and each
    child-belongs-to-another-parent mismatch, without mutating or revealing
    the other occurrence).

    The own Ticket is unassigned (`Analysis`) and the actor an active VA, so
    an assignment would be visible; an untouched actionable `ANALYSIS`
    track pins the Ticket in `Analysis`. For a restore every package,
    track, and Product marker of the world is seeded, so a mismatch that
    reached the guard would succeed on the other occurrence."""

    @staticmethod
    async def _world(
        db: AsyncSession,
        direction: Direction,
        ticket_factory: TicketFactory,
        tree: TreeBuilder,
        product_factory: Factory,
        ticket_package_track_factory: Factory,
        ticket_package_product_factory: Factory,
    ) -> dict[str, Any]:
        seeded = direction is Direction.RESTORE
        ticket = await cveless(ticket_factory)
        other_ticket = await cveless(ticket_factory)
        await tree(ticket, status=PackageStatus.ANALYSIS)

        async def path(owner: Ticket) -> TicketPackageTrack:
            return await tree(
                owner,
                status=PackageStatus.ANALYSIS,
                products=(Prod(excluded=seeded),),
                package_excluded=seeded,
                track_excluded=seeded,
            )

        own_track = await path(ticket)
        own_marker = (await markers(db, await only_occurrence(db, own_track)))[1]
        sibling_track = await ticket_package_track_factory(
            ticket_package_id=own_track.ticket_package_id,
            status=PackageStatus.ANALYSIS.value,
            deleted_at=own_marker,
        )
        sibling_product = await product_factory(general_support_end_date=AFTER_EVAL)
        sibling = await ticket_package_product_factory(
            ticket_package_track_id=sibling_track.id,
            product_id=sibling_product.id,
            deleted_at=own_marker,
        )
        other_package_track = await path(ticket)
        foreign_track = await path(other_ticket)
        return {
            "ticket": ticket,
            "other_ticket": other_ticket,
            "own_track": own_track,
            "own": await only_occurrence(db, own_track),
            "sibling": sibling,
            "other_package_track": other_package_track,
            "other_package": await only_occurrence(db, other_package_track),
            "foreign_track": foreign_track,
            "foreign": await only_occurrence(db, foreign_track),
        }

    @DIRECTIONS
    @pytest.mark.parametrize(("level", "case", "error"), _path_cases())
    async def test_mismatched_path_raises_without_effects(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        tree: TreeBuilder,
        product_factory: Factory,
        ticket_package_track_factory: Factory,
        ticket_package_product_factory: Factory,
        monkeypatch: pytest.MonkeyPatch,
        direction: Direction,
        level: Level,
        case: str,
        error: type[Exception],
    ) -> None:
        actor = await va_user()
        w = await self._world(
            db_session,
            direction,
            ticket_factory,
            tree,
            product_factory,
            ticket_package_track_factory,
            ticket_package_product_factory,
        )
        own: TicketPackageProduct = w["own"]
        own_track: TicketPackageTrack = w["own_track"]
        other_track: TicketPackageTrack = w["other_package_track"]
        foreign_track: TicketPackageTrack = w["foreign_track"]
        own_path = (own_track.ticket_package_id, own_track.id, own.id)
        # (ticket_id, package_id, track_id, occurrence_id); a mismatched
        # level names an existing record elsewhere.
        overrides: dict[str, tuple[uuid.UUID, ...]] = {
            "missing-ticket": (uuid.uuid4(), *own_path),
            "missing-package": (w["ticket"].id, uuid.uuid4(), *own_path[1:]),
            "package-of-other-ticket": (
                w["ticket"].id,
                foreign_track.ticket_package_id,
                foreign_track.id,
                w["foreign"].id,
            ),
            "missing-track": (w["ticket"].id, own_path[0], uuid.uuid4(), own.id),
            "track-of-other-package": (
                w["ticket"].id,
                own_path[0],
                other_track.id,
                w["other_package"].id,
            ),
            "track-of-other-ticket": (
                w["ticket"].id,
                own_path[0],
                foreign_track.id,
                w["foreign"].id,
            ),
            "missing-occurrence": (w["ticket"].id, *own_path[:2], uuid.uuid4()),
            "occurrence-of-sibling-track": (
                w["ticket"].id,
                *own_path[:2],
                w["sibling"].id,
            ),
            "occurrence-of-other-package": (
                w["ticket"].id,
                *own_path[:2],
                w["other_package"].id,
            ),
            "occurrence-of-other-ticket": (
                w["ticket"].id,
                *own_path[:2],
                w["foreign"].id,
            ),
            "catalog-product-id": (w["ticket"].id, *own_path[:2], own.product_id),
        }
        ticket_id, package_id, track_id, occurrence_id = overrides[case]

        await assert_no_effects(
            db_session,
            monkeypatch,
            lambda: change(
                db_session,
                level,
                direction,
                own,
                actor,
                ticket_id=ticket_id,
                package_id=package_id,
                track_id=track_id,
                occurrence_id=occurrence_id,
            ),
            tickets=(w["ticket"], w["other_ticket"]),
            occurrences=(own, w["sibling"], w["other_package"], w["foreign"]),
            error=error,
        )

    @LEVELS
    @DIRECTIONS
    async def test_correct_path_changes_only_the_declared_record(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        tree: TreeBuilder,
        product_factory: Factory,
        ticket_package_track_factory: Factory,
        ticket_package_product_factory: Factory,
        level: Level,
        direction: Direction,
    ) -> None:
        actor = await va_user()
        w = await self._world(
            db_session,
            direction,
            ticket_factory,
            tree,
            product_factory,
            ticket_package_track_factory,
            ticket_package_product_factory,
        )
        others = ("sibling", "other_package", "foreign")
        before = {name: await markers(db_session, w[name]) for name in ("own", *others)}

        await change(db_session, level, direction, w["own"], actor)

        assert await markers(db_session, w["own"]) == with_target(
            before["own"],
            level,
            MARKER_NOW if direction is Direction.EXCLUDE else None,
        )
        for name in others:
            if name == "sibling" and level is Level.PACKAGE:
                # The sibling track shares the own (target) package.
                expected = with_target(
                    before[name],
                    level,
                    MARKER_NOW if direction is Direction.EXCLUDE else None,
                )
            else:
                expected = before[name]
            assert await markers(db_session, w[name]) == expected
        assert await ticket_events(db_session, w["ticket"]) == [
            assignment_event(actor),
            await marker_event(db_session, level, direction, w["own"], actor),
        ]
        assert await ticket_events(db_session, w["other_ticket"]) == []


# ---------------------------------------------------------------------------
# Manual-zone operability
# ---------------------------------------------------------------------------

MANUAL_ZONE = pytest.mark.parametrize(
    "zone", [TicketStatus.IGNORED, TicketStatus.DUPLICATED], ids=str
)


@pytest.mark.integration
class TestManualZone:
    """tickets.md, Mutability Guard; package-service.md, Exclusion and
    restoration operations step 4 and Ticket-level operability:
    operability precedes the locked path reload and the direct-marker
    guard. The Ticket is unassigned and the actor an active VA."""

    @MANUAL_ZONE
    @LEVELS
    @DIRECTIONS
    async def test_manual_zone_ticket_is_not_mutable(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        tree: TreeBuilder,
        monkeypatch: pytest.MonkeyPatch,
        zone: TicketStatus,
        level: Level,
        direction: Direction,
    ) -> None:
        actor = await va_user()
        ticket = await cveless(ticket_factory, status=zone)
        occurrence = await gate_world(db_session, tree, ticket, level, direction)

        await assert_no_effects(
            db_session,
            monkeypatch,
            lambda: change(db_session, level, direction, occurrence, actor),
            tickets=(ticket,),
            occurrences=(occurrence,),
            error=TicketNotMutableError,
        )

    @MANUAL_ZONE
    @pytest.mark.parametrize("case", ["missing-occurrence", "guard-violation"])
    async def test_operability_precedes_path_reload_and_guard(
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
        `ProductNotFoundError`; a restore of a `NULL` marker raises it
        rather than `PackageNotExcludedError`."""
        actor = await va_user()
        ticket = await cveless(ticket_factory, status=zone)
        occurrence = await gate_world(
            db_session, tree, ticket, Level.PRODUCT, Direction.EXCLUDE
        )
        missing = case == "missing-occurrence"

        await assert_no_effects(
            db_session,
            monkeypatch,
            lambda: change(
                db_session,
                Level.PRODUCT,
                Direction.EXCLUDE if missing else Direction.RESTORE,
                occurrence,
                actor,
                occurrence_id=uuid.uuid4() if missing else None,
            ),
            tickets=(ticket,),
            occurrences=(occurrence,),
            error=TicketNotMutableError,
        )


# ---------------------------------------------------------------------------
# One shared evaluation date
# ---------------------------------------------------------------------------

LAST_SUPPORT_DAY = EVAL
"""The inclusive General Support end of the boundary Product: in General
Support on this date and EOL on the next (product-catalog.md, Lifecycle
Evaluator)."""

NEXT_DAY = LAST_SUPPORT_DAY + timedelta(days=1)

NAR = NonActionableReason

BOUNDARY_STATES: dict[date, tuple[tuple[bool, NAR | None], ...]] = {
    LAST_SUPPORT_DAY: ((True, None), (True, None), (True, None)),
    NEXT_DAY: (
        (False, NAR.NO_ACTIONABLE_TRACKS),
        (False, NAR.NO_ACTIONABLE_PRODUCTS),
        (False, NAR.EOL),
    ),
}
"""The `(package, track, Product)` state of the restored boundary path: all
markers clear, so only lifecycle applies (package-model.md, Derived
Actionability)."""

BOUNDARY_RESULT: dict[date, TicketStatus] = {
    LAST_SUPPORT_DAY: TicketStatus.ANALYZED,
    NEXT_DAY: TicketStatus.RESOLVED,
}
"""tickets.md gates: on the last support day the restored `AFFECTED` track
has an actionable eligible Product (`Analyzed`); on the next day the
Product is EOL, so the track leaves `A` and the `NOT_AFFECTED` track keeps
the Ticket `Resolved`."""


async def _boundary_world(
    db: AsyncSession,
    ticket: Ticket,
    level: Level,
    *,
    tree: TreeBuilder,
    product_factory: Factory,
    ticket_package_factory: Factory,
    ticket_package_track_factory: Factory,
    ticket_package_product_factory: Factory,
) -> TicketPackageProduct:
    """A `NOT_AFFECTED` track plus an `AFFECTED` track whose only eligible
    Product's General Support ends on `LAST_SUPPORT_DAY`; only the target
    `level` marker of the boundary path is seeded. Before the restore the
    Ticket is `Resolved` on both dates."""
    await tree(ticket, status=PackageStatus.NOT_AFFECTED)
    seeded = MARKER_NOW
    package = await ticket_package_factory(
        ticket_id=ticket.id, deleted_at=seeded if level is Level.PACKAGE else None
    )
    track = await ticket_package_track_factory(
        ticket_package_id=package.id,
        status=PackageStatus.AFFECTED.value,
        deleted_at=seeded if level is Level.TRACK else None,
    )
    product = await product_factory(general_support_end_date=LAST_SUPPORT_DAY)
    occurrence: TicketPackageProduct = await ticket_package_product_factory(
        ticket_package_track_id=track.id,
        product_id=product.id,
        eligible=True,
        deleted_at=seeded if level is Level.PRODUCT else None,
    )
    return occurrence


@pytest.mark.integration
class TestSharedEvaluationDate:
    """package-model.md, Derived Actionability (one UTC `evaluation_date` for
    the mutation, reconciliation, and result projection); package-service.md,
    Exclusion and restoration operations (captured once at entry when
    omitted and returned) and Architectural Test Requirement: Derived
    actionability (a workflow that crosses midnight UTC); testing-strategy.md,
    controlled-clock bullet."""

    @LEVELS
    @pytest.mark.parametrize(
        "evaluation_date", [LAST_SUPPORT_DAY, NEXT_DAY], ids=["last-day", "next-day"]
    )
    async def test_explicit_date_drives_gate_and_projection(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        tree: TreeBuilder,
        product_factory: Factory,
        ticket_package_factory: Factory,
        ticket_package_track_factory: Factory,
        ticket_package_product_factory: Factory,
        monkeypatch: pytest.MonkeyPatch,
        level: Level,
        evaluation_date: date,
    ) -> None:
        actor = await va_user()
        ticket = await cveless(
            ticket_factory, status=TicketStatus.RESOLVED, assignee_id=actor.id
        )
        occurrence = await _boundary_world(
            db_session,
            ticket,
            level,
            tree=tree,
            product_factory=product_factory,
            ticket_package_factory=ticket_package_factory,
            ticket_package_track_factory=ticket_package_track_factory,
            ticket_package_product_factory=ticket_package_product_factory,
        )
        reconcile = Spy(monkeypatch, "reconcile_ticket_status")

        result = await change(
            db_session,
            level,
            Direction.RESTORE,
            occurrence,
            actor,
            evaluation_date=evaluation_date,
        )

        states = BOUNDARY_STATES[evaluation_date]
        after = BOUNDARY_RESULT[evaluation_date]
        assert [kwargs for _, kwargs in reconcile.calls] == [
            {"evaluation_date": evaluation_date}
        ]
        assert result.evaluation_date == evaluation_date
        index = list(Level).index(level)
        assert (
            result.target.actionable,
            result.target.non_actionable_reason,
        ) == states[index]
        assert await observed(db_session, occurrence, evaluation_date) == states
        gate = (
            [status_event(TicketStatus.RESOLVED, after)]
            if after is not TicketStatus.RESOLVED
            else []
        )
        assert await ticket_state(db_session, ticket) == (after, actor.id)
        assert await ticket_events(db_session, ticket) == [
            await marker_event(db_session, level, Direction.RESTORE, occurrence, actor),
            *gate,
        ]

    @LEVELS
    @pytest.mark.parametrize(
        "clock",
        [
            pytest.param([LAST_SUPPORT_DAY], id="single-reading"),
            pytest.param([LAST_SUPPORT_DAY, NEXT_DAY], id="crossing-midnight"),
        ],
    )
    async def test_omitted_date_is_captured_once_and_returned(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        tree: TreeBuilder,
        product_factory: Factory,
        ticket_package_factory: Factory,
        ticket_package_track_factory: Factory,
        ticket_package_product_factory: Factory,
        monkeypatch: pytest.MonkeyPatch,
        level: Level,
        clock: list[date],
    ) -> None:
        """The controlled clock would return `NEXT_DAY` (EOL) on a second
        reading; only the first reading governs reconciliation and the
        projection, and it is returned in the result."""
        actor = await va_user()
        ticket = await cveless(
            ticket_factory, status=TicketStatus.RESOLVED, assignee_id=actor.id
        )
        occurrence = await _boundary_world(
            db_session,
            ticket,
            level,
            tree=tree,
            product_factory=product_factory,
            ticket_package_factory=ticket_package_factory,
            ticket_package_track_factory=ticket_package_track_factory,
            ticket_package_product_factory=ticket_package_product_factory,
        )
        utc_today = Mock(side_effect=clock)
        monkeypatch.setattr(package_service, "_utc_today", utc_today)
        reconcile = Spy(monkeypatch, "reconcile_ticket_status")

        result = await change(
            db_session,
            level,
            Direction.RESTORE,
            occurrence,
            actor,
            evaluation_date=None,
        )

        assert utc_today.call_count == 1
        assert [kwargs for _, kwargs in reconcile.calls] == [
            {"evaluation_date": LAST_SUPPORT_DAY}
        ]
        assert result.evaluation_date == LAST_SUPPORT_DAY
        assert (result.target.actionable, result.target.non_actionable_reason) == (
            True,
            None,
        )
        assert await ticket_state(db_session, ticket) == (
            TicketStatus.ANALYZED,
            actor.id,
        )
        assert await ticket_events(db_session, ticket) == [
            await marker_event(db_session, level, Direction.RESTORE, occurrence, actor),
            status_event(TicketStatus.RESOLVED, TicketStatus.ANALYZED),
        ]


# ---------------------------------------------------------------------------
# Whole-operation rollback and audit-history independence
# ---------------------------------------------------------------------------

SCENARIOS: dict[str, tuple[Direction, TicketStatus, bool]] = {
    "exclude-new-unassigned": (Direction.EXCLUDE, TicketStatus.NEW, False),
    "exclude-analysis-advance": (Direction.EXCLUDE, TicketStatus.ANALYSIS, True),
    "restore-new-unassigned": (Direction.RESTORE, TicketStatus.NEW, False),
    "restore-resolved-regression": (Direction.RESTORE, TicketStatus.RESOLVED, True),
}
"""`(direction, Ticket status, assigned to the actor)` over the
`gate_world()` tree (a `NOT_AFFECTED` track and the target `ANALYSIS`
track). An effective change on the unassigned `New` Ticket assigns the
active VA and promotes it; excluding the target advances `Analysis` to
`Resolved`; restoring it regresses `Resolved` to `Analysis` and registers
one Ticket convergence effect (ticket-mutations.md,
`reconcile_ticket_status()` step 5)."""


async def _scenario_world(
    db: AsyncSession,
    scenario: str,
    level: Level,
    actor_id: uuid.UUID,
    ticket_factory: TicketFactory,
    tree: TreeBuilder,
) -> tuple[Direction, Ticket, TicketPackageProduct]:
    direction, status, assigned = SCENARIOS[scenario]
    ticket = await cveless(
        ticket_factory, status=status, assignee_id=actor_id if assigned else None
    )
    occurrence = await gate_world(db, tree, ticket, level, direction)
    return direction, ticket, occurrence


@pytest.mark.integration
class TestRollback:
    """ticket-audit-log.md, Testing Requirements 7 and 14 and Cross-Event
    Ordering, Locking, and Rollback; package-service.md, Exclusion and
    restoration operations (audit, reconciliation, database, and flush
    failures propagate unchanged and roll back the marker, assignment, and
    every audit or status effect) and Architectural Test Requirement:
    Exclusion/restore actor and rollback.

    After the savepoint rollback, the markers, the Ticket status and
    assignee, the Ticket's events, and the pending convergence effects all
    equal the pre-call state."""

    @pytest.mark.parametrize("scenario", list(SCENARIOS))
    @LEVELS
    @pytest.mark.parametrize(
        "failure", ["audit", "reconcile-before", "reconcile-after", "final-flush"]
    )
    async def test_failure_rolls_back_every_effect(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        tree: TreeBuilder,
        monkeypatch: pytest.MonkeyPatch,
        scenario: str,
        level: Level,
        failure: str,
    ) -> None:
        actor = await va_user()
        direction, ticket, occurrence = await _scenario_world(
            db_session, scenario, level, actor.id, ticket_factory, tree
        )
        before = (
            await ticket_state(db_session, ticket),
            await ticket_events(db_session, ticket),
            await markers(db_session, occurrence),
            pending_ticket_convergence_effects(db_session),
        )
        target_marker = before[2][list(Level).index(level)]
        assert (before[1], before[3]) == ([], ())
        assert before[2] == with_target((None, None, None), level, target_marker)
        assert (target_marker is not None) is (direction is Direction.RESTORE)
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
            if kwargs["event_type"] in MARKER_EVENTS:
                raise RuntimeError("injected audit failure")
            await original_log(*args, **kwargs)

        original_flush = db_session.flush

        async def flush(*args: Any, **kwargs: Any) -> None:
            if reconciled:
                raise RuntimeError("injected flush failure")
            await original_flush(*args, **kwargs)

        async with rollback_test_scope(db_session):
            monkeypatch.setattr(package_service, "reconcile_ticket_status", reconcile)
            if failure == "audit":
                # The class object `package_service` references by name.
                monkeypatch.setattr(TicketAuditLog, "log_event", log_event)
            elif failure == "final-flush":
                monkeypatch.setattr(db_session, "flush", flush)

            with pytest.raises(RuntimeError, match="injected"):
                await change(db_session, level, direction, occurrence, actor)

            if scenario == "restore-resolved-regression" and reconciled:
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
            await markers(db_session, occurrence),
            pending_ticket_convergence_effects(db_session),
        ) == before

    @pytest.mark.parametrize("scenario", list(SCENARIOS))
    @LEVELS
    async def test_unfailed_scenario_has_the_effects_rolled_back_above(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        tree: TreeBuilder,
        scenario: str,
        level: Level,
    ) -> None:
        """Control for the rollback cases: without a failure, each scenario
        changes the marker and creates its assignment, direct, and gate
        events, so the rollback assertions above are not vacuous."""
        actor = await va_user()
        direction, ticket, occurrence = await _scenario_world(
            db_session, scenario, level, actor.id, ticket_factory, tree
        )
        before = await markers(db_session, occurrence)

        await change(db_session, level, direction, occurrence, actor)

        exclude = direction is Direction.EXCLUDE
        direct = await marker_event(db_session, level, direction, occurrence, actor)
        expected_events = {
            "exclude-new-unassigned": [
                assignment_event(actor),
                PROMOTION,
                direct,
                status_event(TicketStatus.ANALYSIS, TicketStatus.RESOLVED),
            ],
            "exclude-analysis-advance": [
                direct,
                status_event(TicketStatus.ANALYSIS, TicketStatus.RESOLVED),
            ],
            "restore-new-unassigned": [assignment_event(actor), PROMOTION, direct],
            "restore-resolved-regression": [
                direct,
                status_event(TicketStatus.RESOLVED, TicketStatus.ANALYSIS),
            ],
        }[scenario]
        assert await markers(db_session, occurrence) == with_target(
            before, level, MARKER_NOW if exclude else None
        )
        assert await ticket_events(db_session, ticket) == expected_events
        assert await ticket_state(db_session, ticket) == (
            TicketStatus.RESOLVED if exclude else TicketStatus.ANALYSIS,
            actor.id,
        )


@pytest.mark.integration
class TestNoAuditHistoryRead:
    """ticket-audit-log.md, Testing Requirement 25; testing-strategy.md,
    Audit Trail Testing (audit history is never queried to determine
    current state, authorization, idempotency, or restoration). An
    effective call only inserts into `ticket_audit_event`; a rejected guard
    never touches it."""

    @pytest.mark.parametrize("scenario", list(SCENARIOS))
    @LEVELS
    async def test_effective_call_never_selects_audit_history(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        tree: TreeBuilder,
        scenario: str,
        level: Level,
    ) -> None:
        actor = await va_user()
        direction, _, occurrence = await _scenario_world(
            db_session, scenario, level, actor.id, ticket_factory, tree
        )

        with StatementRecorder(db_session) as recorder:
            await change(db_session, level, direction, occurrence, actor)

        audit = [s for s in recorder.statements if "ticket_audit_event" in s]
        assert audit
        assert recorder.selects_from("ticket_audit_event") == []
        assert [s for s in audit if not s.lstrip().upper().startswith("INSERT")] == []

    @LEVELS
    @DIRECTIONS
    async def test_rejected_guard_never_touches_audit_history(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        tree: TreeBuilder,
        level: Level,
        direction: Direction,
    ) -> None:
        """The opposite seeding of `gate_world()`: an exclusion finds its
        target already excluded, a restore finds it not excluded."""
        actor = await va_user()
        ticket = await cveless(ticket_factory, status=TicketStatus.NEW)
        opposite = (
            Direction.RESTORE if direction is Direction.EXCLUDE else Direction.EXCLUDE
        )
        occurrence = await gate_world(db_session, tree, ticket, level, opposite)
        error: type[Exception] = (
            PackageAlreadyExcludedError
            if direction is Direction.EXCLUDE
            else PackageNotExcludedError
        )

        with StatementRecorder(db_session) as recorder, pytest.raises(error):
            await change(db_session, level, direction, occurrence, actor)

        assert [s for s in recorder.statements if "ticket_audit_event" in s] == []
