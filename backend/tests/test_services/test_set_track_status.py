"""Single-session service integration tests for `set_track_status()`
(backend/app/services/package_service.py), part A.

Owning specifications:

- docs/features/packages/package-service.md (Auto-Assignment Rule;
  Semantic locators and locked ownership validation; `set_track_status()`;
  Service Exceptions; Architectural Test Requirement: Forward transitions,
  Backward transitions, Auto-assignment, Nested ownership validation,
  Affectedness authority matrix).
- docs/features/packages/package-model.md (Status Behavior: User-Attributed
  Status Change, Automatic Transitions, Manual Transitions).
- docs/features/tickets/tickets.md (Gate: Analysis -> Analyzed; Gate:
  Analyzed -> Resolved).
- docs/features/tickets/ticket-mutations.md (`reconcile_ticket_status()`;
  Assignment Eligibility Sanitization).
- docs/features/tickets/ticket-audit-log.md (Event Type Contract:
  `track_status_changed`, `assignment`, `status_change`; Rules; Cross-Event
  Ordering; detail JSONB Schema Contract: `track_status_changed`; Testing
  Requirements 1-6).

The actor/context pairing validation, the system-form `force` handling, and
the sanitized rejection warning (`track_status_system_target_rejected` with
`ticket_id`, `package_id`, `track_id`, `requested_status`) are recorded
implementation decisions of the tracking issue.

Unless a test states otherwise, a gate-evaluated Ticket is CVE-less with
`severity_manual = High` and each track carries one eligible in-support
Product on `EVAL`, so the gate result follows directly from tickets.md:
any actionable `ANALYSIS` track gives `Analysis`; otherwise an `AFFECTED`
track with an actionable eligible Product gives `Analyzed`; otherwise
(`NOT_AFFECTED`, `WONT_FIX`, or CVE-less `FIXED`) `Resolved`.

Expected values are transcribed from the specifications, never computed
with the module under test.
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable
from typing import Any

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import PackageStatus, Role, Scope, TicketStatus
from app.core.exceptions import ServiceError, TicketNotFoundError
from app.models.cve import CVE
from app.models.ticket import Ticket
from app.models.ticket_package import TicketPackage
from app.models.ticket_package_track import TicketPackageTrack
from app.models.user import User
from app.services import package_service
from app.services.package_service import (
    SYSTEM_INVOCATION,
    MutationOutcome,
    PackageNotFoundError,
    PackageServiceError,
    TrackFixedStatusRestrictedError,
    TrackNotFoundError,
    TrackStatusResult,
    set_track_status,
)
from app.services.ticket_convergence_registry import (
    TicketConvergenceEffect,
    pending_ticket_convergence_effects,
)
from app.services.ticket_visibility import TicketCaller
from tests.support.ticket_mutations import (
    EVAL,
    EventRow,
    Prod,
    StatementRecorder,
    TicketFactory,
    TreeBuilder,
    VAUser,
    cveless,
    status_event,
    ticket_events,
    unassigned_event,
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

FINAL = (PackageStatus.NOT_AFFECTED, PackageStatus.FIXED, PackageStatus.WONT_FIX)
"""package-model.md, Automatic Transitions: the final affectedness states."""

NON_FIXED = (
    PackageStatus.ANALYSIS,
    PackageStatus.AFFECTED,
    PackageStatus.NOT_AFFECTED,
    PackageStatus.WONT_FIX,
)

GATE: dict[PackageStatus, TicketStatus] = {
    PackageStatus.ANALYSIS: TicketStatus.ANALYSIS,
    PackageStatus.AFFECTED: TicketStatus.ANALYZED,
    PackageStatus.NOT_AFFECTED: TicketStatus.RESOLVED,
    PackageStatus.FIXED: TicketStatus.RESOLVED,
    PackageStatus.WONT_FIX: TicketStatus.RESOLVED,
}
"""tickets.md gates: the result of a CVE-less High Ticket whose single
track has the key status and one eligible in-support Product."""

PROMOTION = status_event(TicketStatus.NEW.value, TicketStatus.ANALYSIS.value)
"""The system `New -> Analysis` event of the auto-assignment."""

CveFactory = Callable[..., Awaitable[CVE]]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _stale(source: PackageStatus) -> TicketStatus:
    """A Ticket status that reconciliation would change for a single
    `source` track (see `GATE`)."""
    return (
        TicketStatus.ANALYZED
        if source is PackageStatus.ANALYSIS
        else TicketStatus.ANALYSIS
    )


def _assignment_event(actor: User) -> EventRow:
    """The acting-user auto-assignment of an unassigned Ticket."""
    return EventRow("assignment", actor.id, None, actor.username, None, None)


async def _cve_ticket(
    ticket_factory: TicketFactory,
    cve_factory: CveFactory,
    *,
    status: TicketStatus = TicketStatus.ANALYSIS,
    **overrides: Any,
) -> Ticket:
    """A CVE-associated Ticket. Its CVE has no severity and no SUSE
    assessment, so every gate evaluation gives `Analysis`."""
    cve = await cve_factory()
    return await ticket_factory(status=status.value, cve_id=cve.id, **overrides)


class _Logs:
    """Replaces the `package_service` structlog logger, recording every
    `(level, event, keys)` call."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.calls: list[tuple[str, str, dict[str, Any]]] = []
        monkeypatch.setattr(package_service, "logger", self)

    def __getattr__(self, level: str) -> Callable[..., None]:
        def _log(event: str, *args: Any, **kwargs: Any) -> None:
            assert args == ()
            self.calls.append((level, event, kwargs))

        return _log


# ---------------------------------------------------------------------------
# Actor/context pairing (tracking-issue decision)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestActorContextValidation:
    """An inconsistent actor/context pairing is a caller-contract violation
    rejected with `ValueError` before any database statement; a missing
    consumer context is never system authority (package-service.md,
    Consumer caller context and Ticket accessibility)."""

    @pytest.mark.parametrize(
        "case",
        ["system-with-actor", "consumer-without-actor", "other-user", "anonymous"],
    )
    async def test_inconsistent_pairing_raises_before_any_statement(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        tree: TreeBuilder,
        case: str,
    ) -> None:
        actor = await va_user()
        other = await va_user()
        ticket = await cveless(ticket_factory, assignee_id=actor.id)
        track = await tree(ticket, status=PackageStatus.ANALYSIS)
        pairings: dict[
            str,
            tuple[uuid.UUID | None, TicketCaller | package_service.SystemInvocation],
        ] = {
            "system-with-actor": (actor.id, SYSTEM_INVOCATION),
            "consumer-without-actor": (
                None,
                TicketCaller.authenticated(actor.id, Scope.ALL),
            ),
            "other-user": (actor.id, TicketCaller.authenticated(other.id, Scope.ALL)),
            "anonymous": (actor.id, TicketCaller()),
        }
        acting_user_id, caller = pairings[case]

        with (
            StatementRecorder(db_session) as recorder,
            pytest.raises(ValueError, match="acting user"),
        ):
            await set_track_status(
                db_session,
                ticket_id=ticket.id,
                package_id=track.ticket_package_id,
                track_id=track.id,
                status=PackageStatus.AFFECTED,
                acting_user_id=acting_user_id,
                caller=caller,
                evaluation_date=EVAL,
            )

        assert recorder.statements == []
        assert await persisted_track_status(db_session, track) == PackageStatus.ANALYSIS
        assert await ticket_events(db_session, ticket) == []
        assert pending_ticket_convergence_effects(db_session) == ()


async def _assert_changed(
    db: AsyncSession,
    result: TrackStatusResult,
    ticket: Ticket,
    track: TicketPackageTrack,
    actor: User | None,
    old: PackageStatus,
    new: PackageStatus,
    *,
    old_ticket: TicketStatus,
    new_ticket: TicketStatus,
    assignee: uuid.UUID | None,
) -> None:
    """An effective change: `changed`, the persisted target, the one
    `track_status_changed` event followed by the final gate event when the
    Ticket status changes (Cross-Event Ordering)."""
    gate = [status_event(old_ticket, new_ticket)] if old_ticket != new_ticket else []
    assert (result.outcome, result.track.status, result.evaluation_date) == (
        MutationOutcome.CHANGED,
        new,
        EVAL,
    )
    assert await persisted_track_status(db, track) == new
    assert await ticket_state(db, ticket) == (new_ticket, assignee)
    assert await ticket_events(db, ticket) == [
        await track_event(db, track, actor, old, new),
        *gate,
    ]


# ---------------------------------------------------------------------------
# Affectedness authority matrix: user-attributed callers
# ---------------------------------------------------------------------------

SOURCES = pytest.mark.parametrize("source", list(PackageStatus), ids=str)


@pytest.mark.integration
class TestUserAuthority:
    """package-model.md, Manual Transitions; package-service.md,
    `set_track_status()` steps 5-7 and FIXED restriction."""

    @SOURCES
    @pytest.mark.parametrize("target", NON_FIXED, ids=str)
    @pytest.mark.parametrize("with_cve", [False, True], ids=["cveless", "cve"])
    async def test_non_fixed_target_from_any_state(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_factory: CveFactory,
        va_user: VAUser,
        tree: TreeBuilder,
        monkeypatch: pytest.MonkeyPatch,
        source: PackageStatus,
        target: PackageStatus,
        with_cve: bool,
    ) -> None:
        actor = await va_user()
        if with_cve:
            ticket = await _cve_ticket(
                ticket_factory, cve_factory, assignee_id=actor.id
            )
            before, after = TicketStatus.ANALYSIS, TicketStatus.ANALYSIS
        else:
            before, after = GATE[source], GATE[target]
            ticket = await cveless(ticket_factory, status=before, assignee_id=actor.id)
        track = await tree(ticket, status=source)

        if source is target:
            result = await assert_no_effects(
                db_session,
                monkeypatch,
                lambda: set_status(db_session, track, target, actor),
                tickets=(ticket,),
                tracks=(track,),
            )
            assert result is not None
            assert (result.outcome, result.track.status) == (
                MutationOutcome.NO_OP,
                source,
            )
            return

        result = await set_status(db_session, track, target, actor)

        await _assert_changed(
            db_session,
            result,
            ticket,
            track,
            actor,
            source,
            target,
            old_ticket=before,
            new_ticket=after,
            assignee=actor.id,
        )

    @SOURCES
    @pytest.mark.parametrize(
        ("with_cve", "force"),
        [
            pytest.param(False, False, id="manage-packages-cveless"),
            pytest.param(False, True, id="admin-cveless"),
            pytest.param(True, True, id="admin-cve"),
        ],
    )
    async def test_permitted_fixed_from_any_state(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_factory: CveFactory,
        va_user: VAUser,
        tree: TreeBuilder,
        monkeypatch: pytest.MonkeyPatch,
        source: PackageStatus,
        with_cve: bool,
        force: bool,
    ) -> None:
        actor = await va_user()
        if with_cve:
            ticket = await _cve_ticket(
                ticket_factory, cve_factory, assignee_id=actor.id
            )
            before, after = TicketStatus.ANALYSIS, TicketStatus.ANALYSIS
        else:
            before, after = GATE[source], TicketStatus.RESOLVED
            ticket = await cveless(ticket_factory, status=before, assignee_id=actor.id)
        track = await tree(ticket, status=source)
        fixed = PackageStatus.FIXED

        if source is fixed:
            result = await assert_no_effects(
                db_session,
                monkeypatch,
                lambda: set_status(db_session, track, fixed, actor, force=force),
                tickets=(ticket,),
                tracks=(track,),
            )
            assert result is not None
            assert result.outcome is MutationOutcome.NO_OP
            return

        result = await set_status(db_session, track, fixed, actor, force=force)

        await _assert_changed(
            db_session,
            result,
            ticket,
            track,
            actor,
            source,
            fixed,
            old_ticket=before,
            new_ticket=after,
            assignee=actor.id,
        )

    @SOURCES
    async def test_manage_packages_fixed_on_cve_ticket_is_restricted(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_factory: CveFactory,
        va_user: VAUser,
        tree: TreeBuilder,
        monkeypatch: pytest.MonkeyPatch,
        source: PackageStatus,
    ) -> None:
        """Rejected even when already `FIXED`: authority (step 6) precedes
        the unchanged-target no-op (step 7). The unassigned Ticket, active
        VA actor, and stale status prove no assignment or reconciliation."""
        actor = await va_user()
        ticket = await _cve_ticket(
            ticket_factory, cve_factory, status=TicketStatus.ANALYZED
        )
        track = await tree(ticket, status=source)

        await assert_no_effects(
            db_session,
            monkeypatch,
            lambda: set_status(db_session, track, PackageStatus.FIXED, actor),
            tickets=(ticket,),
            tracks=(track,),
            error=TrackFixedStatusRestrictedError,
        )

    @SOURCES
    @pytest.mark.parametrize("target", NON_FIXED, ids=str)
    async def test_force_with_non_fixed_target_is_restricted(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        tree: TreeBuilder,
        monkeypatch: pytest.MonkeyPatch,
        source: PackageStatus,
        target: PackageStatus,
    ) -> None:
        actor = await va_user()
        ticket = await cveless(ticket_factory, status=_stale(source))
        track = await tree(ticket, status=source)

        await assert_no_effects(
            db_session,
            monkeypatch,
            lambda: set_status(db_session, track, target, actor, force=True),
            tickets=(ticket,),
            tracks=(track,),
            error=TrackFixedStatusRestrictedError,
        )


# ---------------------------------------------------------------------------
# Affectedness authority matrix: system callers
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestSystemAuthority:
    """package-model.md, Automatic Transitions and Manual Transitions (system
    rows); package-service.md, `set_track_status()` steps 5, 6, 8, 9 and
    Automatic authority. System callers never assign and `force` is not
    evaluated for them."""

    @pytest.mark.parametrize(
        "source", [PackageStatus.ANALYSIS, PackageStatus.AFFECTED], ids=str
    )
    @pytest.mark.parametrize("with_cve", [False, True], ids=["cveless", "cve"])
    @pytest.mark.parametrize("force", [False, True], ids=["default", "force"])
    async def test_fixed_from_open_state_changes_without_assignment(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_factory: CveFactory,
        tree: TreeBuilder,
        source: PackageStatus,
        with_cve: bool,
        force: bool,
    ) -> None:
        if with_cve:
            ticket = await _cve_ticket(ticket_factory, cve_factory)
            before, after = TicketStatus.ANALYSIS, TicketStatus.ANALYSIS
        else:
            before, after = GATE[source], TicketStatus.RESOLVED
            ticket = await cveless(ticket_factory, status=before)
        track = await tree(ticket, status=source)

        result = await set_status(
            db_session, track, PackageStatus.FIXED, None, force=force
        )

        await _assert_changed(
            db_session,
            result,
            ticket,
            track,
            None,
            source,
            PackageStatus.FIXED,
            old_ticket=before,
            new_ticket=after,
            assignee=None,
        )

    @pytest.mark.parametrize("source", FINAL, ids=str)
    @pytest.mark.parametrize("with_cve", [False, True], ids=["cveless", "cve"])
    @pytest.mark.parametrize("force", [False, True], ids=["default", "force"])
    async def test_fixed_on_final_state_is_protected_no_op(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_factory: CveFactory,
        tree: TreeBuilder,
        monkeypatch: pytest.MonkeyPatch,
        source: PackageStatus,
        with_cve: bool,
        force: bool,
    ) -> None:
        if with_cve:
            ticket = await _cve_ticket(
                ticket_factory, cve_factory, status=TicketStatus.ANALYZED
            )
        else:
            ticket = await cveless(ticket_factory, status=_stale(source))
        track = await tree(ticket, status=source)
        logs = _Logs(monkeypatch)

        result = await assert_no_effects(
            db_session,
            monkeypatch,
            lambda: set_status(
                db_session, track, PackageStatus.FIXED, None, force=force
            ),
            tickets=(ticket,),
            tracks=(track,),
        )

        assert result is not None
        assert (result.outcome, result.track.status, result.evaluation_date) == (
            MutationOutcome.NO_OP,
            source,
            EVAL,
        )
        assert logs.calls == []

    @SOURCES
    @pytest.mark.parametrize("target", NON_FIXED, ids=str)
    @pytest.mark.parametrize("force", [False, True], ids=["default", "force"])
    async def test_non_fixed_target_is_rejected_with_one_warning(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        tree: TreeBuilder,
        monkeypatch: pytest.MonkeyPatch,
        source: PackageStatus,
        target: PackageStatus,
        force: bool,
    ) -> None:
        """`rejected` is a result, not an escaping exception; `force=True`
        does not turn it into the user-attributed restriction error. The
        stale Ticket status proves that reconciliation did not run."""
        ticket = await cveless(ticket_factory, status=_stale(source))
        track = await tree(ticket, status=source)
        logs = _Logs(monkeypatch)

        result = await assert_no_effects(
            db_session,
            monkeypatch,
            lambda: set_status(db_session, track, target, None, force=force),
            tickets=(ticket,),
            tracks=(track,),
        )

        assert result is not None
        assert (result.outcome, result.track.status, result.evaluation_date) == (
            MutationOutcome.REJECTED,
            source,
            EVAL,
        )
        assert logs.calls == [
            (
                "warning",
                "track_status_system_target_rejected",
                {
                    "ticket_id": str(ticket.id),
                    "package_id": str(track.ticket_package_id),
                    "track_id": str(track.id),
                    "requested_status": target.value,
                },
            )
        ]


# ---------------------------------------------------------------------------
# Unchanged target: true no-op before every side effect
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestUnchangedTarget:
    """package-service.md, `set_track_status()` step 7, Idempotency, and
    Auto-Assignment Rule (a true no-op never assigns, audits, reconciles,
    or registers); package-model.md, User-Attributed Status Change."""

    @SOURCES
    @pytest.mark.parametrize("new_ticket", [False, True], ids=["stale", "new"])
    async def test_user_request_equal_to_locked_status(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        tree: TreeBuilder,
        monkeypatch: pytest.MonkeyPatch,
        source: PackageStatus,
        new_ticket: bool,
    ) -> None:
        """An unassigned Ticket and an active VA actor: an assignment (and,
        for `New`, the promotion) would be visible; the stale gate-zone
        status would be corrected by any reconciliation."""
        actor = await va_user()
        status = TicketStatus.NEW if new_ticket else _stale(source)
        ticket = await cveless(ticket_factory, status=status)
        track = await tree(ticket, status=source)

        result = await assert_no_effects(
            db_session,
            monkeypatch,
            lambda: set_status(db_session, track, source, actor),
            tickets=(ticket,),
            tracks=(track,),
        )

        assert result is not None
        assert (result.outcome, result.track.status, result.evaluation_date) == (
            MutationOutcome.NO_OP,
            source,
            EVAL,
        )
        assert await ticket_state(db_session, ticket) == (status, None)

    async def test_system_fixed_on_fixed(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        tree: TreeBuilder,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        ticket = await cveless(ticket_factory, status=TicketStatus.ANALYSIS)
        track = await tree(ticket, status=PackageStatus.FIXED)
        logs = _Logs(monkeypatch)

        result = await assert_no_effects(
            db_session,
            monkeypatch,
            lambda: set_status(db_session, track, PackageStatus.FIXED, None),
            tickets=(ticket,),
            tracks=(track,),
        )

        assert result is not None
        assert result.outcome is MutationOutcome.NO_OP
        assert logs.calls == []
        assert await ticket_state(db_session, ticket) == (TicketStatus.ANALYSIS, None)


# ---------------------------------------------------------------------------
# Forward and backward transitions through reconciliation
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestGateTransitions:
    """package-service.md, Architectural Test Requirement: Forward and
    Backward transitions; tickets.md gates; ticket-mutations.md,
    `reconcile_ticket_status()` step 5 (a `Resolved` regression registers
    one Ticket convergence effect)."""

    @pytest.mark.parametrize(
        ("other", "source", "target", "before", "after"),
        [
            *(
                pytest.param(
                    PackageStatus.NOT_AFFECTED,
                    PackageStatus.AFFECTED,
                    target,
                    TicketStatus.ANALYZED,
                    TicketStatus.RESOLVED,
                    id=f"last-affected-to-{target}",
                )
                for target in FINAL
            ),
            pytest.param(
                PackageStatus.AFFECTED,
                PackageStatus.ANALYSIS,
                PackageStatus.AFFECTED,
                TicketStatus.ANALYSIS,
                TicketStatus.ANALYZED,
                id="last-analysis-to-AFFECTED",
            ),
        ],
    )
    async def test_forward_transition_reconciles_once(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        tree: TreeBuilder,
        monkeypatch: pytest.MonkeyPatch,
        other: PackageStatus,
        source: PackageStatus,
        target: PackageStatus,
        before: TicketStatus,
        after: TicketStatus,
    ) -> None:
        actor = await va_user()
        ticket = await cveless(ticket_factory, status=before, assignee_id=actor.id)
        await tree(ticket, status=other)
        track = await tree(ticket, status=source)
        reconcile = Spy(monkeypatch, "reconcile_ticket_status")

        result = await set_status(db_session, track, target, actor)

        assert [(args[0].id, kwargs) for args, kwargs in reconcile.calls] == [
            (ticket.id, {"evaluation_date": EVAL})
        ]
        await _assert_changed(
            db_session,
            result,
            ticket,
            track,
            actor,
            source,
            target,
            old_ticket=before,
            new_ticket=after,
            assignee=actor.id,
        )
        assert pending_ticket_convergence_effects(db_session) == ()

    @pytest.mark.parametrize(
        ("target", "after"),
        [
            (PackageStatus.AFFECTED, TicketStatus.ANALYZED),
            (PackageStatus.ANALYSIS, TicketStatus.ANALYSIS),
        ],
        ids=str,
    )
    async def test_resolved_regression_registers_one_convergence_effect(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        tree: TreeBuilder,
        target: PackageStatus,
        after: TicketStatus,
    ) -> None:
        actor = await va_user()
        ticket = await cveless(
            ticket_factory, status=TicketStatus.RESOLVED, assignee_id=actor.id
        )
        await tree(ticket, status=PackageStatus.WONT_FIX)
        track = await tree(ticket, status=PackageStatus.NOT_AFFECTED)

        result = await set_status(db_session, track, target, actor)

        await _assert_changed(
            db_session,
            result,
            ticket,
            track,
            actor,
            PackageStatus.NOT_AFFECTED,
            target,
            old_ticket=TicketStatus.RESOLVED,
            new_ticket=after,
            assignee=actor.id,
        )
        assert pending_ticket_convergence_effects(db_session) == (
            TicketConvergenceEffect(ticket.id),
        )

    async def test_affected_without_eligible_product_stays_resolved(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        tree: TreeBuilder,
    ) -> None:
        """tickets.md, resolution-complete clause (c): an `AFFECTED` track
        whose actionable Products are all ineligible keeps `Resolved`, so
        no regression and no convergence registration occur."""
        actor = await va_user()
        ticket = await cveless(
            ticket_factory, status=TicketStatus.RESOLVED, assignee_id=actor.id
        )
        track = await tree(
            ticket, status=PackageStatus.NOT_AFFECTED, products=(Prod(eligible=False),)
        )

        result = await set_status(db_session, track, PackageStatus.AFFECTED, actor)

        await _assert_changed(
            db_session,
            result,
            ticket,
            track,
            actor,
            PackageStatus.NOT_AFFECTED,
            PackageStatus.AFFECTED,
            old_ticket=TicketStatus.RESOLVED,
            new_ticket=TicketStatus.RESOLVED,
            assignee=actor.id,
        )
        assert pending_ticket_convergence_effects(db_session) == ()

    @pytest.mark.parametrize(
        ("products", "excluded", "after"),
        [
            pytest.param((Prod(),), False, TicketStatus.ANALYSIS, id="actionable"),
            pytest.param(
                (Prod(eol=True),), False, TicketStatus.ANALYZED, id="eol-only"
            ),
            pytest.param((Prod(),), True, TicketStatus.ANALYZED, id="excluded"),
        ],
    )
    async def test_second_analysis_track_blocks_only_when_actionable(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        tree: TreeBuilder,
        products: tuple[Prod, ...],
        excluded: bool,
        after: TicketStatus,
    ) -> None:
        """tickets.md, Gate: Analysis -> Analyzed condition 2: only an
        actionable `ANALYSIS` track blocks the gate."""
        actor = await va_user()
        ticket = await cveless(
            ticket_factory, status=TicketStatus.ANALYSIS, assignee_id=actor.id
        )
        await tree(
            ticket,
            status=PackageStatus.ANALYSIS,
            products=products,
            track_excluded=excluded,
        )
        track = await tree(ticket, status=PackageStatus.ANALYSIS)

        result = await set_status(db_session, track, PackageStatus.AFFECTED, actor)

        await _assert_changed(
            db_session,
            result,
            ticket,
            track,
            actor,
            PackageStatus.ANALYSIS,
            PackageStatus.AFFECTED,
            old_ticket=TicketStatus.ANALYSIS,
            new_ticket=after,
            assignee=actor.id,
        )


# ---------------------------------------------------------------------------
# Auto-assignment
# ---------------------------------------------------------------------------

INELIGIBLE_ACTORS = pytest.mark.parametrize(
    ("active", "roles", "target", "force"),
    [
        pytest.param(
            True,
            (Role.RESTRICTED_ANALYST,),
            PackageStatus.AFFECTED,
            False,
            id="restricted-analyst",
        ),
        pytest.param(True, (Role.ADMIN,), PackageStatus.FIXED, True, id="admin-only"),
        pytest.param(
            False,
            (Role.VULNERABILITY_ANALYST,),
            PackageStatus.AFFECTED,
            False,
            id="inactive-va",
        ),
    ],
)


@pytest.mark.integration
class TestAutoAssignment:
    """package-service.md, Auto-Assignment Rule and `set_track_status()`
    step 9; ticket-audit-log.md, Cross-Event Ordering (assignment and its
    `New -> Analysis` precede the direct event; the gate event is last)."""

    @pytest.mark.parametrize(
        ("source", "target", "final"),
        [
            (PackageStatus.AFFECTED, PackageStatus.ANALYSIS, TicketStatus.ANALYSIS),
            (PackageStatus.ANALYSIS, PackageStatus.AFFECTED, TicketStatus.ANALYZED),
            (
                PackageStatus.ANALYSIS,
                PackageStatus.NOT_AFFECTED,
                TicketStatus.RESOLVED,
            ),
        ],
        ids=["to-analysis", "to-analyzed", "to-resolved"],
    )
    async def test_active_va_on_new_ticket_assigns_and_promotes(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        tree: TreeBuilder,
        source: PackageStatus,
        target: PackageStatus,
        final: TicketStatus,
    ) -> None:
        actor = await va_user()
        ticket = await cveless(ticket_factory, status=TicketStatus.NEW)
        track = await tree(ticket, status=source)

        result = await set_status(db_session, track, target, actor)

        gate = (
            [status_event(TicketStatus.ANALYSIS, final)]
            if final is not TicketStatus.ANALYSIS
            else []
        )
        assert result.outcome is MutationOutcome.CHANGED
        assert await ticket_state(db_session, ticket) == (final, actor.id)
        assert await ticket_events(db_session, ticket) == [
            _assignment_event(actor),
            PROMOTION,
            await track_event(db_session, track, actor, source, target),
            *gate,
        ]

    async def test_active_va_on_unassigned_analysis_ticket_assigns_only(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        tree: TreeBuilder,
    ) -> None:
        actor = await va_user()
        ticket = await cveless(ticket_factory, status=TicketStatus.ANALYSIS)
        track = await tree(ticket, status=PackageStatus.ANALYSIS)

        await set_status(db_session, track, PackageStatus.AFFECTED, actor)

        assert await ticket_state(db_session, ticket) == (
            TicketStatus.ANALYZED,
            actor.id,
        )
        assert await ticket_events(db_session, ticket) == [
            _assignment_event(actor),
            await track_event(
                db_session, track, actor, PackageStatus.ANALYSIS, PackageStatus.AFFECTED
            ),
            status_event(TicketStatus.ANALYSIS, TicketStatus.ANALYZED),
        ]

    @INELIGIBLE_ACTORS
    async def test_ineligible_actor_changes_without_assignment(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        tree: TreeBuilder,
        active: bool,
        roles: tuple[Role, ...],
        target: PackageStatus,
        force: bool,
    ) -> None:
        actor = await va_user(active=active, roles=roles)
        ticket = await cveless(ticket_factory, status=TicketStatus.ANALYSIS)
        track = await tree(ticket, status=PackageStatus.ANALYSIS)

        result = await set_status(db_session, track, target, actor, force=force)

        await _assert_changed(
            db_session,
            result,
            ticket,
            track,
            actor,
            PackageStatus.ANALYSIS,
            target,
            old_ticket=TicketStatus.ANALYSIS,
            new_ticket=GATE[target],
            assignee=None,
        )

    @INELIGIBLE_ACTORS
    async def test_ineligible_actor_on_new_ticket_neither_assigns_nor_promotes(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        tree: TreeBuilder,
        active: bool,
        roles: tuple[Role, ...],
        target: PackageStatus,
        force: bool,
    ) -> None:
        """ticket-mutations.md, `reconcile_ticket_status()` step 1: a `New`
        Ticket is outside the gate zone, so it stays `New`."""
        actor = await va_user(active=active, roles=roles)
        ticket = await cveless(ticket_factory, status=TicketStatus.NEW)
        track = await tree(ticket, status=PackageStatus.ANALYSIS)

        result = await set_status(db_session, track, target, actor, force=force)

        await _assert_changed(
            db_session,
            result,
            ticket,
            track,
            actor,
            PackageStatus.ANALYSIS,
            target,
            old_ticket=TicketStatus.NEW,
            new_ticket=TicketStatus.NEW,
            assignee=None,
        )

    async def test_already_assigned_ticket_keeps_its_assignee(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        tree: TreeBuilder,
    ) -> None:
        assignee = await va_user()
        actor = await va_user()
        ticket = await cveless(
            ticket_factory, status=TicketStatus.ANALYSIS, assignee_id=assignee.id
        )
        track = await tree(ticket, status=PackageStatus.ANALYSIS)

        result = await set_status(db_session, track, PackageStatus.AFFECTED, actor)

        await _assert_changed(
            db_session,
            result,
            ticket,
            track,
            actor,
            PackageStatus.ANALYSIS,
            PackageStatus.AFFECTED,
            old_ticket=TicketStatus.ANALYSIS,
            new_ticket=TicketStatus.ANALYZED,
            assignee=assignee.id,
        )

    @pytest.mark.parametrize(
        "status", [TicketStatus.NEW, TicketStatus.ANALYSIS], ids=str
    )
    async def test_system_change_never_assigns(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        tree: TreeBuilder,
        monkeypatch: pytest.MonkeyPatch,
        status: TicketStatus,
    ) -> None:
        await va_user()  # an active VA exists but is not the actor
        ticket = await cveless(ticket_factory, status=status)
        track = await tree(ticket, status=PackageStatus.AFFECTED)
        assign = Spy(monkeypatch, "auto_assign_actor")

        result = await set_status(db_session, track, PackageStatus.FIXED, None)

        final = (
            TicketStatus.NEW if status is TicketStatus.NEW else TicketStatus.RESOLVED
        )
        assert assign.calls == []
        await _assert_changed(
            db_session,
            result,
            ticket,
            track,
            None,
            PackageStatus.AFFECTED,
            PackageStatus.FIXED,
            old_ticket=status,
            new_ticket=final,
            assignee=None,
        )


# ---------------------------------------------------------------------------
# Audit payload and sanitation ordering
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestAuditPayload:
    """ticket-audit-log.md, Event Type Contract `track_status_changed`,
    Rules (enum names), detail JSONB Schema Contract, Cross-Event Ordering,
    and Testing Requirements 1-6."""

    @pytest.mark.parametrize("system", [False, True], ids=["user", "system"])
    async def test_event_has_exact_payload(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        ticket_package_factory: Callable[..., Awaitable[TicketPackage]],
        ticket_package_track_factory: Callable[..., Awaitable[TicketPackageTrack]],
        system: bool,
    ) -> None:
        actor = await va_user()
        ticket = await cveless(
            ticket_factory, status=TicketStatus.ANALYSIS, assignee_id=actor.id
        )
        package = await ticket_package_factory(
            ticket_id=ticket.id, package_name="example-libwidget"
        )
        track = await ticket_package_track_factory(
            ticket_package_id=package.id,
            reference="Example:Distro:15-SP9:Update",
            status=PackageStatus.AFFECTED.value,
        )

        await set_status(
            db_session, track, PackageStatus.FIXED, None if system else actor
        )

        # No Product: |M| >= 1 and no actionable track in ANALYSIS, hence
        # the Analyzed and (vacuously) Resolved predicates hold.
        assert await ticket_events(db_session, ticket) == [
            EventRow(
                "track_status_changed",
                None if system else actor.id,
                "AFFECTED",
                "FIXED",
                None,
                {
                    "track": "Example:Distro:15-SP9:Update",
                    "package": "example-libwidget",
                },
            ),
            status_event("Analysis", "Resolved"),
        ]

    @pytest.mark.parametrize(
        ("source", "target", "before", "after"),
        [
            pytest.param(
                PackageStatus.ANALYSIS,
                PackageStatus.AFFECTED,
                TicketStatus.ANALYSIS,
                TicketStatus.ANALYZED,
                id="to-analyzed",
            ),
            pytest.param(
                PackageStatus.AFFECTED,
                PackageStatus.ANALYSIS,
                TicketStatus.ANALYZED,
                TicketStatus.ANALYSIS,
                id="to-analysis",
            ),
        ],
    )
    async def test_sanitation_follows_direct_event_and_precedes_gate_event(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        tree: TreeBuilder,
        source: PackageStatus,
        target: PackageStatus,
        before: TicketStatus,
        after: TicketStatus,
    ) -> None:
        """ticket-mutations.md, Assignment Eligibility Sanitization: an
        inactive assignee of an `Analysis`/`Analyzed` result is cleared by
        a system `assignment` event after the direct event and before the
        final `status_change`. The actor does not auto-assign: the Ticket
        is assigned when auto-assignment runs."""
        inactive = await va_user(active=False)
        actor = await va_user()
        ticket = await cveless(ticket_factory, status=before, assignee_id=inactive.id)
        track = await tree(ticket, status=source)

        await set_status(db_session, track, target, actor)

        assert await ticket_state(db_session, ticket) == (after, None)
        assert await ticket_events(db_session, ticket) == [
            await track_event(db_session, track, actor, source, target),
            unassigned_event(inactive.username, "inactive assignee"),
            status_event(before, after),
        ]


# ---------------------------------------------------------------------------
# Nested ownership validation and exception hierarchy
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestNestedOwnership:
    """package-service.md, Semantic locators and locked ownership
    validation; `set_track_status()` step 4; Architectural Test
    Requirement: Nested ownership validation. A mismatch never mutates or
    reveals the occurrence under the other path."""

    @pytest.mark.parametrize("system", [False, True], ids=["user", "system"])
    @pytest.mark.parametrize(
        ("case", "error"),
        [
            ("missing-ticket", TicketNotFoundError),
            ("missing-package", PackageNotFoundError),
            ("missing-track", TrackNotFoundError),
            ("track-of-sibling-package", TrackNotFoundError),
            ("package-of-other-ticket", PackageNotFoundError),
        ],
    )
    async def test_mismatched_path_raises_without_effects(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        tree: TreeBuilder,
        monkeypatch: pytest.MonkeyPatch,
        system: bool,
        case: str,
        error: type[Exception],
    ) -> None:
        actor = None if system else await va_user()
        ticket = await cveless(ticket_factory, status=TicketStatus.ANALYZED)
        other_ticket = await cveless(ticket_factory, status=TicketStatus.ANALYZED)
        own = await tree(ticket, status=PackageStatus.ANALYSIS)
        sibling = await tree(ticket, status=PackageStatus.ANALYSIS)
        foreign = await tree(other_ticket, status=PackageStatus.ANALYSIS)
        ticket_id, package_id, track_id = {
            "missing-ticket": (uuid.uuid4(), own.ticket_package_id, own.id),
            "missing-package": (ticket.id, uuid.uuid4(), own.id),
            "missing-track": (ticket.id, own.ticket_package_id, uuid.uuid4()),
            "track-of-sibling-package": (ticket.id, own.ticket_package_id, sibling.id),
            "package-of-other-ticket": (
                ticket.id,
                foreign.ticket_package_id,
                foreign.id,
            ),
        }[case]

        await assert_no_effects(
            db_session,
            monkeypatch,
            lambda: set_track_status(
                db_session,
                ticket_id=ticket_id,
                package_id=package_id,
                track_id=track_id,
                status=PackageStatus.FIXED,
                acting_user_id=actor.id if actor else None,
                caller=(
                    TicketCaller.authenticated(actor.id, Scope.ALL)
                    if actor
                    else SYSTEM_INVOCATION
                ),
                evaluation_date=EVAL,
            ),
            tickets=(ticket, other_ticket),
            tracks=(own, sibling, foreign),
            error=error,
        )

    @pytest.mark.parametrize("system", [False, True], ids=["user", "system"])
    async def test_correct_path_changes_only_the_declared_track(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        tree: TreeBuilder,
        system: bool,
    ) -> None:
        actor = None if system else await va_user()
        ticket = await cveless(
            ticket_factory,
            status=TicketStatus.ANALYSIS,
            assignee_id=actor.id if actor else None,
        )
        other_ticket = await cveless(ticket_factory, status=TicketStatus.ANALYSIS)
        own = await tree(ticket, status=PackageStatus.ANALYSIS)
        sibling = await tree(ticket, status=PackageStatus.ANALYSIS)
        foreign = await tree(other_ticket, status=PackageStatus.ANALYSIS)

        result = await set_status(db_session, own, PackageStatus.FIXED, actor)

        assert result.outcome is MutationOutcome.CHANGED
        assert result.track.reference == own.reference
        assert [
            await persisted_track_status(db_session, t) for t in (own, sibling, foreign)
        ] == [PackageStatus.FIXED, PackageStatus.ANALYSIS, PackageStatus.ANALYSIS]
        # The sibling ANALYSIS track keeps the Ticket in Analysis.
        assert await ticket_events(db_session, ticket) == [
            await track_event(
                db_session, own, actor, PackageStatus.ANALYSIS, PackageStatus.FIXED
            )
        ]
        assert await ticket_events(db_session, other_ticket) == []


@pytest.mark.unit
class TestExceptionHierarchy:
    """package-service.md, Service Exceptions."""

    @pytest.mark.parametrize(
        "error",
        [PackageNotFoundError, TrackNotFoundError, TrackFixedStatusRestrictedError],
    )
    def test_module_exceptions_inherit_package_service_error(
        self, error: type[Exception]
    ) -> None:
        assert issubclass(error, PackageServiceError)
        assert issubclass(PackageServiceError, ServiceError)
