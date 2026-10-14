"""Single-session service integration tests for `set_track_delivery_status()`
(backend/app/services/package_service.py).

Owning specifications:

- docs/features/packages/package-service.md (Transaction ownership;
  Semantic locators and locked ownership validation;
  `set_track_delivery_status()`; Concurrency Control (the Ticket lock is
  compatible when the caller already holds it); Service Exceptions >
  System-internal exceptions; Excluded and Non-Actionable Records;
  Architectural Test Requirement: Nested ownership validation, Delivery
  mutation composition, Dimension independence (delivery part)).
- docs/features/packages/package-model.md (Axis 3: Delivery and Release
  Observation; Affectedness-Delivery Independence; Automatic Transitions:
  delivery status transitions, Delivery status regression, RELEASED is
  irreversible).
- docs/features/tickets/ticket-audit-log.md (a delivery change creates no
  Ticket event).
- docs/features/platform/testing-strategy.md (Audit Trail Testing; Service
  Functions; Rollback Within a Test).

Independent-session behavior (committed atomicity, lock serialization, and
the winner-current outcome) is covered by
`tests/test_services/test_set_track_delivery_status_atomicity.py`; the
other dimension writers' side of Dimension independence by
`tests/test_services/test_delivery_dimension_independence.py`.

Unless a test states otherwise, a Ticket is CVE-less in `Analysis` with
`severity_manual = High` and each factory-built track carries one Product in
General Support on `EVAL`. Expected values are transcribed from the
specifications, never computed with the module under test.
"""

from __future__ import annotations

import re
import uuid
from typing import Any

import pytest
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import DeliveryStatus, PackageStatus, TicketStatus
from app.core.exceptions import (
    ServiceError,
    TicketNotFoundError,
    TicketNotMutableError,
)
from app.models.ticket import Ticket
from app.models.ticket_package import TicketPackage
from app.models.ticket_package_product import TicketPackageProduct
from app.models.ticket_package_track import TicketPackageTrack
from app.services.package_service import (
    DeliveryStatusResult,
    InvalidDeliveryStatusTransition,
    MutationOutcome,
    PackageNotFoundError,
    PackageServiceError,
    TrackNotFoundError,
    set_track_delivery_status,
)
from app.services.ticket_convergence_registry import (
    pending_ticket_convergence_effects,
)
from tests.support.database import rollback_test_scope
from tests.support.ticket_mutations import (
    Prod,
    StatementRecorder,
    TicketFactory,
    TreeBuilder,
    VAUser,
    cveless,
    lock_ticket,
    ticket_events,
)
from tests.support.track_status import Spy, ticket_state

pytest_plugins = ["tests.support.ticket_mutation_fixtures"]
"""Provides the shared `va_user` and `tree` fixtures."""

TICKET_STATEMENT = re.compile(r"\bFROM ticket\b")
"""A statement reading the `ticket` table itself (not `ticket_package`)."""

PENDING = DeliveryStatus.PENDING
IN_PROGRESS = DeliveryStatus.IN_PROGRESS
RELEASED = DeliveryStatus.RELEASED

APPROVED = [
    pytest.param(PENDING, IN_PROGRESS, id="PENDING-to-IN_PROGRESS"),
    pytest.param(IN_PROGRESS, RELEASED, id="IN_PROGRESS-to-RELEASED"),
    pytest.param(IN_PROGRESS, PENDING, id="IN_PROGRESS-to-PENDING"),
]
"""package-model.md, Automatic Transitions: the delivery status
transitions."""

PROHIBITED = [
    pytest.param(PENDING, RELEASED, id="PENDING-to-RELEASED"),
    pytest.param(RELEASED, PENDING, id="RELEASED-to-PENDING"),
    pytest.param(RELEASED, IN_PROGRESS, id="RELEASED-to-IN_PROGRESS"),
]
"""package-service.md, `set_track_delivery_status()` step 5: a direct
`PENDING -> RELEASED` and every change out of `RELEASED` are illegal."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _seed(
    db: AsyncSession, track: TicketPackageTrack, delivery: DeliveryStatus
) -> None:
    """Persist `delivery` as the track's delivery value (a column UPDATE,
    leaving the identity-map copy stale on purpose)."""
    await db.execute(
        update(TicketPackageTrack)
        .where(TicketPackageTrack.id == track.id)
        .values(delivery_status=delivery.value)
        .execution_options(synchronize_session=False)
    )


async def _persisted(db: AsyncSession, track: TicketPackageTrack) -> str:
    """The persisted delivery value of a track (a column read)."""
    return (
        await db.execute(
            select(TicketPackageTrack.delivery_status).where(
                TicketPackageTrack.id == track.id
            )
        )
    ).scalar_one()


async def _ticket_id(db: AsyncSession, track: TicketPackageTrack) -> uuid.UUID:
    return (
        await db.execute(
            select(TicketPackage.ticket_id).where(
                TicketPackage.id == track.ticket_package_id
            )
        )
    ).scalar_one()


async def _set(
    db: AsyncSession,
    track: TicketPackageTrack,
    delivery: DeliveryStatus,
    *,
    ticket_id: uuid.UUID | None = None,
    package_id: uuid.UUID | None = None,
    track_id: uuid.UUID | None = None,
) -> DeliveryStatusResult:
    """Call the service as the shared IBS reconciler would, for `track`'s
    own path unless a locator level is overridden."""
    return await set_track_delivery_status(
        db,
        ticket_id=await _ticket_id(db, track) if ticket_id is None else ticket_id,
        package_id=track.ticket_package_id if package_id is None else package_id,
        track_id=track.id if track_id is None else track_id,
        delivery_status=delivery,
    )


async def _subtree(db: AsyncSession, track: TicketPackageTrack) -> tuple[Any, ...]:
    """Every non-delivery value of the track's subtree: package marker;
    track affectedness and marker; each Product occurrence's eligibility,
    override marker, release observation, and marker (occurrence order)."""
    track_row = (
        await db.execute(
            select(
                TicketPackage.deleted_at,
                TicketPackageTrack.status,
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


async def _assert_no_write(
    db: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
    track: TicketPackageTrack,
    ticket: Ticket,
    *,
    request: DeliveryStatus,
    error: type[Exception] | None,
    **locator: Any,
) -> DeliveryStatusResult | None:
    """Run the call and assert the zero-side-effect contract: no write, no
    assignment, no reconciliation, no registered convergence effect, and
    unchanged delivery value, subtree, Ticket state, and Ticket events.
    Returns the result of a non-raising call."""

    async def snapshot() -> tuple[Any, ...]:
        return (
            await _persisted(db, track),
            await _subtree(db, track),
            await ticket_state(db, ticket),
            await ticket_events(db, ticket),
        )

    before = await snapshot()
    assign = Spy(monkeypatch, "auto_assign_actor")
    reconcile = Spy(monkeypatch, "reconcile_ticket_status")
    result: DeliveryStatusResult | None = None
    with StatementRecorder(db) as recorder:
        if error is None:
            result = await _set(db, track, request, **locator)
        else:
            with pytest.raises(error):
                await _set(db, track, request, **locator)

    assert recorder.writes() == []
    assert (assign.calls, reconcile.calls) == ([], [])
    assert pending_ticket_convergence_effects(db) == ()
    assert await snapshot() == before
    return result


# ---------------------------------------------------------------------------
# Approved transitions (package-service.md, `set_track_delivery_status()`
# steps 1-7; package-model.md, Automatic Transitions)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestApprovedTransitions:
    """package-service.md, Architectural Test Requirement: Delivery mutation
    composition (every approved transition; two-step atomic advancement from
    `PENDING` to `RELEASED`; compatibility when the caller already holds the
    Ticket lock; caller-owned rollback)."""

    @pytest.mark.parametrize(("source", "target"), APPROVED)
    async def test_approved_transition_changes_the_value(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        tree: TreeBuilder,
        source: DeliveryStatus,
        target: DeliveryStatus,
    ) -> None:
        ticket = await cveless(ticket_factory)
        track = await tree(ticket)
        await _seed(db_session, track, source)

        result = await _set(db_session, track, target)

        assert result == DeliveryStatusResult(
            outcome=MutationOutcome.CHANGED,
            track_id=track.id,
            delivery_status=target,
        )
        assert await _persisted(db_session, track) == target.value

    async def test_two_step_advancement_to_released_in_one_transaction(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        tree: TreeBuilder,
    ) -> None:
        """package-model.md, Automatic Transitions: a release proven while
        the persisted value is `PENDING` applies `PENDING -> IN_PROGRESS ->
        RELEASED` in the same transaction; the caller's rollback leaves
        `PENDING`, so no intermediate state survives."""
        ticket = await cveless(ticket_factory)
        track = await tree(ticket)

        async with rollback_test_scope(db_session):
            first = await _set(db_session, track, IN_PROGRESS)
            second = await _set(db_session, track, RELEASED)

            assert (first.outcome, first.delivery_status) == (
                MutationOutcome.CHANGED,
                IN_PROGRESS,
            )
            assert (second.outcome, second.delivery_status) == (
                MutationOutcome.CHANGED,
                RELEASED,
            )
            assert await _persisted(db_session, track) == RELEASED.value
        await db_session.refresh(track)

        assert await _persisted(db_session, track) == PENDING.value

    async def test_function_flushes_and_never_commits(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        tree: TreeBuilder,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """package-service.md, Transaction ownership and step 7: the track
        UPDATE reaches the database inside the call, nothing is left
        pending, and no commit is issued; the caller's rollback removes the
        change."""
        ticket = await cveless(ticket_factory)
        track = await tree(ticket)
        commits: list[object] = []

        async with rollback_test_scope(db_session):
            original_commit = db_session.commit

            async def commit() -> None:
                commits.append(object())
                await original_commit()

            monkeypatch.setattr(db_session, "commit", commit)
            with StatementRecorder(db_session) as recorder:
                result = await _set(db_session, track, IN_PROGRESS)

            assert [
                s
                for s in recorder.writes()
                if s.lstrip().startswith("UPDATE ticket_package_track ")
            ]
            assert (len(db_session.new), len(db_session.dirty)) == (0, 0)
            assert result.outcome is MutationOutcome.CHANGED
            assert commits == []
            monkeypatch.undo()
        await db_session.refresh(track)

        assert await _persisted(db_session, track) == PENDING.value

    async def test_ticket_lock_is_the_first_statement(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        tree: TreeBuilder,
    ) -> None:
        """package-service.md, step 1: the Ticket `FOR UPDATE` is the first
        state-dependent database operation, and no other row lock is
        taken."""
        ticket = await cveless(ticket_factory)
        track = await tree(ticket)
        ticket_id = await _ticket_id(db_session, track)

        with StatementRecorder(db_session) as recorder:
            await set_track_delivery_status(
                db_session,
                ticket_id=ticket_id,
                package_id=track.ticket_package_id,
                track_id=track.id,
                delivery_status=IN_PROGRESS,
            )

        first = recorder.statements[0]
        assert TICKET_STATEMENT.search(first) is not None
        assert first.rstrip().endswith("FOR UPDATE")
        assert recorder.row_locks() == [first]

    async def test_caller_already_holding_the_ticket_lock_is_compatible(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        tree: TreeBuilder,
    ) -> None:
        """package-service.md, step 1: re-acquisition in the caller's
        transaction is compatible and establishes no nested transaction."""
        ticket = await cveless(ticket_factory)
        track = await tree(ticket)
        await lock_ticket(db_session, ticket)

        result = await _set(db_session, track, IN_PROGRESS)

        assert result.outcome is MutationOutcome.CHANGED
        assert await _persisted(db_session, track) == IN_PROGRESS.value

    async def test_stale_identity_map_copy_is_refreshed_under_the_lock(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        tree: TreeBuilder,
    ) -> None:
        """package-service.md, step 3 and Concurrent outcome: the transition
        is validated from the value reloaded under the lock, never from a
        stale copy (the in-memory track still reads `PENDING`)."""
        ticket = await cveless(ticket_factory)
        track = await tree(ticket)
        await _seed(db_session, track, IN_PROGRESS)
        assert track.delivery_status == PENDING.value

        result = await _set(db_session, track, RELEASED)

        assert (result.outcome, result.delivery_status) == (
            MutationOutcome.CHANGED,
            RELEASED,
        )


# ---------------------------------------------------------------------------
# No-op and prohibited transitions (steps 4-5; Idempotency)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestNoOpAndProhibitedTransitions:
    """package-service.md, `set_track_delivery_status()` steps 4-5 and
    Idempotency; Architectural Test Requirement: Delivery mutation
    composition (an unchanged no-op; rejection of direct `PENDING ->
    RELEASED` and of every change out of `RELEASED`); package-model.md,
    RELEASED is irreversible."""

    @pytest.mark.parametrize("value", [PENDING, IN_PROGRESS, RELEASED], ids=str)
    async def test_unchanged_value_is_a_no_op_without_write(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        tree: TreeBuilder,
        monkeypatch: pytest.MonkeyPatch,
        value: DeliveryStatus,
    ) -> None:
        ticket = await cveless(ticket_factory)
        track = await tree(ticket)
        await _seed(db_session, track, value)

        result = await _assert_no_write(
            db_session, monkeypatch, track, ticket, request=value, error=None
        )

        assert result == DeliveryStatusResult(
            outcome=MutationOutcome.NO_OP, track_id=track.id, delivery_status=value
        )

    @pytest.mark.parametrize(("source", "target"), PROHIBITED)
    async def test_prohibited_transition_raises_without_modification(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        tree: TreeBuilder,
        monkeypatch: pytest.MonkeyPatch,
        source: DeliveryStatus,
        target: DeliveryStatus,
    ) -> None:
        ticket = await cveless(ticket_factory)
        track = await tree(ticket)
        await _seed(db_session, track, source)

        await _assert_no_write(
            db_session,
            monkeypatch,
            track,
            ticket,
            request=target,
            error=InvalidDeliveryStatusTransition,
        )

        with pytest.raises(InvalidDeliveryStatusTransition) as raised:
            await _set(db_session, track, target)
        assert (raised.value.current, raised.value.requested) == (source, target)
        assert await _persisted(db_session, track) == source.value


# ---------------------------------------------------------------------------
# System attribution and side effects
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestSystemAttributionAndSideEffects:
    """package-service.md, `set_track_delivery_status()` (never
    `auto_assign_actor()` or `reconcile_ticket_status()`; no
    `TicketAuditEvent`; System attribution) and Architectural Test
    Requirement: Delivery mutation composition (the absence of assignment,
    Ticket reconciliation, and audit events); ticket-audit-log.md (no event
    for a delivery change); testing-strategy.md, Audit Trail Testing."""

    @pytest.mark.parametrize(
        "steps",
        [
            pytest.param((IN_PROGRESS,), id="PENDING-to-IN_PROGRESS"),
            pytest.param((IN_PROGRESS, RELEASED), id="two-step-to-RELEASED"),
            pytest.param((IN_PROGRESS, PENDING), id="regression-to-PENDING"),
        ],
    )
    async def test_effective_change_has_no_assignment_reconciliation_or_event(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        tree: TreeBuilder,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
        steps: tuple[DeliveryStatus, ...],
    ) -> None:
        """The Ticket is unassigned while an active VA exists, so an
        assignment-capable path would assign; a `New` Ticket with an
        `AFFECTED` track would advance under reconciliation."""
        await va_user()
        ticket = await cveless(ticket_factory, status=TicketStatus.NEW)
        track = await tree(ticket, status=PackageStatus.AFFECTED)
        assign = Spy(monkeypatch, "auto_assign_actor")
        reconcile = Spy(monkeypatch, "reconcile_ticket_status")

        with StatementRecorder(db_session) as recorder:
            for target in steps:
                result = await _set(db_session, track, target)
                assert result.outcome is MutationOutcome.CHANGED

        assert (assign.calls, reconcile.calls) == ([], [])
        assert pending_ticket_convergence_effects(db_session) == ()
        assert await ticket_state(db_session, ticket) == (TicketStatus.NEW, None)
        assert await ticket_events(db_session, ticket) == []
        assert [s for s in recorder.statements if "ticket_audit_event" in s] == []
        assert [
            s
            for s in recorder.writes()
            if not s.lstrip().startswith("UPDATE ticket_package_track ")
        ] == []

    async def test_acting_user_is_rejected_before_any_database_operation(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        tree: TreeBuilder,
        va_user: VAUser,
    ) -> None:
        """package-service.md, System attribution: every caller passes
        `acting_user_id = None`."""
        actor = await va_user()
        ticket = await cveless(ticket_factory)
        track = await tree(ticket)
        ticket_id = await _ticket_id(db_session, track)

        with (
            StatementRecorder(db_session) as recorder,
            pytest.raises(ValueError, match="no acting user"),
        ):
            await set_track_delivery_status(
                db_session,
                ticket_id=ticket_id,
                package_id=track.ticket_package_id,
                track_id=track.id,
                delivery_status=IN_PROGRESS,
                acting_user_id=actor.id,  # type: ignore[arg-type]
            )

        assert recorder.statements == []
        assert await _persisted(db_session, track) == PENDING.value

    @pytest.mark.parametrize("value", ["IN_PROGRESS", "in_progress", None])
    async def test_value_outside_the_enum_is_rejected_before_any_database_operation(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        tree: TreeBuilder,
        value: object,
    ) -> None:
        ticket = await cveless(ticket_factory)
        track = await tree(ticket)
        ticket_id = await _ticket_id(db_session, track)

        with (
            StatementRecorder(db_session) as recorder,
            pytest.raises(ValueError, match="DeliveryStatus"),
        ):
            await set_track_delivery_status(
                db_session,
                ticket_id=ticket_id,
                package_id=track.ticket_package_id,
                track_id=track.id,
                delivery_status=value,  # type: ignore[arg-type]
            )

        assert recorder.statements == []

    async def test_no_op_never_reads_audit_history(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        tree: TreeBuilder,
    ) -> None:
        """testing-strategy.md, Audit Trail Testing: audit history is never
        queried for idempotency (the effective transitions are covered by
        `test_effective_change_has_no_assignment_reconciliation_or_event`)."""
        ticket = await cveless(ticket_factory)
        track = await tree(ticket)
        await _seed(db_session, track, RELEASED)

        with StatementRecorder(db_session) as recorder:
            await _set(db_session, track, RELEASED)

        assert [s for s in recorder.statements if "ticket_audit_event" in s] == []


# ---------------------------------------------------------------------------
# Declared path (package-service.md, Semantic locators and locked ownership
# validation)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestNestedOwnershipValidation:
    """package-service.md, Architectural Test Requirement: Nested ownership
    validation (each missing level and each child-belongs-to-another-parent
    mismatch, without mutating or revealing the other occurrence)."""

    async def test_missing_ticket_raises_without_effects(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        tree: TreeBuilder,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        ticket = await cveless(ticket_factory)
        track = await tree(ticket)

        await _assert_no_write(
            db_session,
            monkeypatch,
            track,
            ticket,
            request=IN_PROGRESS,
            error=TicketNotFoundError,
            ticket_id=uuid.uuid7(),
        )

    async def test_missing_package_raises_without_effects(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        tree: TreeBuilder,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        ticket = await cveless(ticket_factory)
        track = await tree(ticket)

        await _assert_no_write(
            db_session,
            monkeypatch,
            track,
            ticket,
            request=IN_PROGRESS,
            error=PackageNotFoundError,
            package_id=uuid.uuid7(),
        )

    async def test_missing_track_raises_without_effects(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        tree: TreeBuilder,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        ticket = await cveless(ticket_factory)
        track = await tree(ticket)

        await _assert_no_write(
            db_session,
            monkeypatch,
            track,
            ticket,
            request=IN_PROGRESS,
            error=TrackNotFoundError,
            track_id=uuid.uuid7(),
        )

    async def test_package_of_another_ticket_raises_without_effects(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        tree: TreeBuilder,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The declared Ticket is locked, but its declared package belongs
        to another Ticket: the other occurrence is neither mutated nor
        revealed."""
        declared = await cveless(ticket_factory)
        await tree(declared)
        owner = await cveless(ticket_factory)
        foreign = await tree(owner)

        await _assert_no_write(
            db_session,
            monkeypatch,
            foreign,
            owner,
            request=IN_PROGRESS,
            error=PackageNotFoundError,
            ticket_id=declared.id,
        )

    async def test_track_of_another_package_raises_without_effects(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        tree: TreeBuilder,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Both packages belong to the declared Ticket, but the track
        belongs to the other package."""
        ticket = await cveless(ticket_factory)
        declared = await tree(ticket)
        foreign = await tree(ticket)

        await _assert_no_write(
            db_session,
            monkeypatch,
            foreign,
            ticket,
            request=IN_PROGRESS,
            error=TrackNotFoundError,
            package_id=declared.ticket_package_id,
        )


# ---------------------------------------------------------------------------
# Operability, exclusion, and final affectedness (package-service.md,
# Excluded and Non-Actionable Records)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestOperabilityAndRecordStates:
    """package-service.md, `set_track_delivery_status()` step 2 and
    Excluded and Non-Actionable Records (Ticket-level operability; mutation
    functions never require `deleted_at IS NULL`); package-model.md,
    Affectedness-Delivery Independence (all combinations are valid)."""

    @pytest.mark.parametrize(
        "status", [TicketStatus.IGNORED, TicketStatus.DUPLICATED], ids=str
    )
    async def test_manual_zone_ticket_is_not_mutable(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        tree: TreeBuilder,
        monkeypatch: pytest.MonkeyPatch,
        status: TicketStatus,
    ) -> None:
        ticket = await cveless(ticket_factory, status=status)
        track = await tree(ticket)

        await _assert_no_write(
            db_session,
            monkeypatch,
            track,
            ticket,
            request=IN_PROGRESS,
            error=TicketNotMutableError,
        )

    @pytest.mark.parametrize(
        "status",
        [
            TicketStatus.NEW,
            TicketStatus.ANALYSIS,
            TicketStatus.ANALYZED,
            TicketStatus.RESOLVED,
        ],
        ids=str,
    )
    async def test_operable_ticket_is_mutable(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        tree: TreeBuilder,
        status: TicketStatus,
    ) -> None:
        ticket = await cveless(ticket_factory, status=status)
        track = await tree(ticket)

        result = await _set(db_session, track, IN_PROGRESS)

        assert result.outcome is MutationOutcome.CHANGED
        assert await ticket_state(db_session, ticket) == (status, None)

    @pytest.mark.parametrize(
        ("package_excluded", "track_excluded", "products"),
        [
            pytest.param(True, False, (Prod(),), id="package-excluded"),
            pytest.param(False, True, (Prod(),), id="track-excluded"),
            pytest.param(True, True, (Prod(),), id="both-excluded"),
            pytest.param(False, False, (Prod(excluded=True),), id="product-excluded"),
            pytest.param(False, False, (Prod(eol=True),), id="eol-only"),
            pytest.param(False, False, (), id="no-products"),
        ],
    )
    async def test_excluded_and_non_actionable_track_is_mutable(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        tree: TreeBuilder,
        package_excluded: bool,
        track_excluded: bool,
        products: tuple[Prod, ...],
    ) -> None:
        ticket = await cveless(ticket_factory)
        track = await tree(
            ticket,
            products=products,
            package_excluded=package_excluded,
            track_excluded=track_excluded,
        )

        result = await _set(db_session, track, IN_PROGRESS)

        assert result.outcome is MutationOutcome.CHANGED
        assert await _persisted(db_session, track) == IN_PROGRESS.value

    @pytest.mark.parametrize("status", list(PackageStatus), ids=str)
    async def test_every_affectedness_status_is_mutable(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        tree: TreeBuilder,
        status: PackageStatus,
    ) -> None:
        ticket = await cveless(ticket_factory)
        track = await tree(ticket, status=status)

        result = await _set(db_session, track, IN_PROGRESS)

        assert result.outcome is MutationOutcome.CHANGED


# ---------------------------------------------------------------------------
# Dimension independence (delivery part)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestDimensionIndependence:
    """package-service.md, Architectural Test Requirement: Dimension
    independence (a delivery change does not mutate affectedness,
    eligibility, or Product release, and the Ticket gate ignores
    `delivery_status`); package-model.md, Axis 3 (neither delivery fact
    derives the other or changes affectedness or eligibility) and
    Affectedness-Delivery Independence.

    Products: a manual `eligible = false` override, an eligible released
    Product, a directly excluded Product, and an EOL Product. Ticket
    status and assignee stay as seeded for every transition, including a
    `Resolved` Ticket whose release is proven and an `Analyzed` Ticket
    whose delivery regresses."""

    @pytest.mark.parametrize(
        ("ticket_status", "track_status", "steps"),
        [
            pytest.param(
                TicketStatus.ANALYZED,
                PackageStatus.AFFECTED,
                (IN_PROGRESS,),
                id="AFFECTED-to-IN_PROGRESS",
            ),
            pytest.param(
                TicketStatus.ANALYZED,
                PackageStatus.AFFECTED,
                (IN_PROGRESS, PENDING),
                id="AFFECTED-regression-to-PENDING",
            ),
            pytest.param(
                TicketStatus.RESOLVED,
                PackageStatus.FIXED,
                (IN_PROGRESS, RELEASED),
                id="FIXED-two-step-to-RELEASED",
            ),
            pytest.param(
                TicketStatus.RESOLVED,
                PackageStatus.NOT_AFFECTED,
                (IN_PROGRESS, RELEASED),
                id="NOT_AFFECTED-two-step-to-RELEASED",
            ),
        ],
    )
    async def test_delivery_change_mutates_no_other_dimension(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        tree: TreeBuilder,
        va_user: VAUser,
        ticket_status: TicketStatus,
        track_status: PackageStatus,
        steps: tuple[DeliveryStatus, ...],
    ) -> None:
        assignee = await va_user()
        ticket = await cveless(
            ticket_factory, status=ticket_status, assignee_id=assignee.id
        )
        track = await tree(
            ticket,
            status=track_status,
            products=(
                Prod(eligible=False, override=True),
                Prod(released=True),
                Prod(excluded=True),
                Prod(eol=True),
            ),
            track_excluded=True,
        )
        seeded = await _subtree(db_session, track)
        seeded_ticket = await ticket_state(db_session, ticket)
        assert seeded_ticket == (ticket_status, assignee.id)

        for target in steps:
            result = await _set(db_session, track, target)
            assert result.outcome is MutationOutcome.CHANGED

        assert await _persisted(db_session, track) == steps[-1].value
        assert await _subtree(db_session, track) == seeded
        assert await ticket_state(db_session, ticket) == seeded_ticket
        assert await ticket_events(db_session, ticket) == []


# ---------------------------------------------------------------------------
# Exception hierarchy (package-service.md, Service Exceptions)
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestInvalidDeliveryStatusTransition:
    """package-service.md, Service Exceptions > System-internal exceptions;
    conventions.md, Service Exception Conventions (module base class)."""

    def test_is_a_module_owned_exception_with_a_static_message(self) -> None:
        error = InvalidDeliveryStatusTransition(RELEASED, PENDING)

        assert isinstance(error, PackageServiceError)
        assert issubclass(PackageServiceError, ServiceError)
        assert str(error) == "Delivery status transition not permitted."
        assert (error.current, error.requested) == (RELEASED, PENDING)
