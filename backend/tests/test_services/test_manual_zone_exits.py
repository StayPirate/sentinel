"""Single-session service integration tests for the manual-zone exits
`reopen_from_ignored()`, `reopen_from_ignored_as_system()`, and
`revert_duplicate()` (backend/app/services/ticket_service.py), composed
with `package_service.converge_manual_zone_exit_eligibility()` and
`ticket_mutations.reconcile_ticket_status()`.

Owning specifications:

- docs/features/tickets/ticket-service.md (Manual-Zone Exit Operations:
  `_complete_manual_zone_exit()`, `reopen_from_ignored()` including the
  CVE-ingestion composition's system boundary, `revert_duplicate()`;
  Ticket Convergence, registration; Architectural Test Requirements 10,
  11 (registration and sanitation parts), and 15 (single-session part)).
- docs/features/tickets/ticket-mutations.md (`reconcile_ticket_status()`,
  including Assignment Eligibility Sanitization and `previous_status`;
  `auto_assign_actor()` with `force=True`).
- docs/features/packages/package-service.md (Synchronous manual-zone-exit
  eligibility convergence) and docs/features/packages/package-model.md
  (Ticket Convergence, phase 1).
- docs/features/tickets/ticket-audit-log.md (Event Type Contract:
  `status_change`, `assignment`, `duplicate_removed`,
  `product_eligibility_changed`; Canonical Mutation and No-Event Matrix:
  Ignore, mark duplicate, reopen, or revert duplicate; Cross-Event
  Ordering, Locking, and Rollback; Testing Requirements 1-8, 20, 24).
- docs/features/tickets/ticket-deadlines.md (Due Dates: Formula and Null
  Due Dates; Track Milestones; Testing Requirements 3 (reopen and revert)
  and 4).
- docs/features/platform/testing-strategy.md (Tier Responsibility and
  Proportionality).

The eligibility formula, the Product event payload, and the package
boundary's own statements are proven once in
`tests/test_services/test_manual_zone_exit_eligibility.py`; this module
proves only the composition around them. Independent-session races (the
CVSS race of ATR 10 and the locked-current accessibility races of ATR 15)
and the HTTP contract belong to other modules. Publication of registered
effects is not implemented yet (ticket_convergence_registry.py), so the
publication parts of ATR 11 are not covered here.

Expected values are transcribed from the specifications, never computed
with the module under test.
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable, Iterable
from datetime import UTC, date, datetime, timedelta, timezone
from types import ModuleType
from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import (
    CurrentPhase,
    MilestoneStatus,
    PackageStatus,
    Role,
    Scope,
    Severity,
    TicketAuditEventType,
    TicketStatus,
)
from app.core.exceptions import InvalidTransitionError, TicketNotFoundError
from app.models.system_setting import SystemSetting
from app.models.ticket import Ticket
from app.models.ticket_access_grant import TicketAccessGrant
from app.models.ticket_audit_event import TicketAuditEvent
from app.models.user import User
from app.models.user_role import UserRole
from app.services import package_service, ticket_mutations, ticket_service
from app.services.ticket_audit_log import TicketAuditLog
from app.services.ticket_convergence_registry import (
    TicketConvergenceEffect,
    pending_ticket_convergence_effects,
)
from app.services.ticket_deadlines import DueDates, TrackMilestones
from app.services.ticket_service import (
    TicketDetailProjection,
    assemble_ticket_detail,
    reopen_from_ignored,
    reopen_from_ignored_as_system,
    revert_duplicate,
)
from app.services.ticket_visibility import TicketCaller
from tests.support.cvss_chain import eligibility, subjects
from tests.support.database import rollback_test_scope
from tests.support.ticket_mutations import (
    EVAL,
    EventRow,
    Prod,
    StatementRecorder,
    TicketFactory,
    TreeBuilder,
    VAUser,
    status_event,
    ticket_events_by_id,
    tree_for,
    unassigned_event,
)

pytest_plugins = ["tests.support.ticket_mutation_fixtures"]
"""Provides the shared `va_user` and `tree` fixtures."""

EXITS = ["reopen", "revert"]
"""The two consumer exits; behavior shared by both is parametrized."""

SOURCE = {"reopen": TicketStatus.IGNORED, "revert": TicketStatus.DUPLICATED}
"""The exact source status each exit accepts."""

OTHER_MANUAL_ZONE = {"reopen": TicketStatus.DUPLICATED, "revert": TicketStatus.IGNORED}

GATE_RESULTS = [TicketStatus.ANALYSIS, TicketStatus.ANALYZED, TicketStatus.RESOLVED]

GATE_TRACK = {
    TicketStatus.ANALYSIS: PackageStatus.ANALYSIS,
    TicketStatus.ANALYZED: PackageStatus.AFFECTED,
    TicketStatus.RESOLVED: PackageStatus.NOT_AFFECTED,
}
"""A CVE-less track status whose gate result is the key (tickets.md, Gates;
the same mapping as `tests.support.ticket_mutations.tree_for`)."""

INACTIVE = "inactive assignee"
VA_REMOVED = "vulnerability_analyst role removed"
"""The closed sanitation reasons (ticket-mutations.md, Assignment Eligibility
Sanitization)."""

State = tuple[str, uuid.UUID | None, uuid.UUID | None]
"""The persisted `(status, duplicate_of_id, assignee_id)` of a Ticket."""


@pytest.fixture(autouse=True)
async def default_setting(
    system_setting_factory: Callable[..., Awaitable[SystemSetting]],
) -> SystemSetting:
    """The persisted `default_cvss_version` read by the package boundary."""
    return await system_setting_factory(key="default_cvss_version", value="3.1")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _sntl(ticket: Ticket) -> str:
    """The public `SNTL-{n}` identifier (tickets.md, SNTL-{n} Format)."""
    return f"SNTL-{ticket.sequence_id}"


async def _source(
    ticket_factory: TicketFactory, exit_: str, **overrides: Any
) -> tuple[Ticket, Ticket | None]:
    """A CVE-less `High` Ticket in the exit's source status and, for a
    revert, its duplicate target."""
    overrides.setdefault("severity_manual", Severity.HIGH.value)
    if exit_ == "reopen":
        ticket = await ticket_factory(status=TicketStatus.IGNORED.value, **overrides)
        return ticket, None
    target = await ticket_factory(status=TicketStatus.ANALYSIS.value)
    ticket = await ticket_factory(duplicate_of_id=target.id, **overrides)
    return ticket, target


async def _exit(
    db: AsyncSession,
    exit_: str,
    ticket_id: uuid.UUID,
    actor: User,
    *,
    scope: Scope = Scope.ALL,
    evaluation_date: date | None = EVAL,
) -> Ticket:
    """Call a consumer exit as an API handler would."""
    operation = reopen_from_ignored if exit_ == "reopen" else revert_duplicate
    return await operation(
        db,
        ticket_id=ticket_id,
        acting_user_id=actor.id,
        caller=TicketCaller.authenticated(actor.id, scope),
        evaluation_date=evaluation_date,
    )


async def _states(
    db: AsyncSession, ticket_ids: Iterable[uuid.UUID]
) -> dict[uuid.UUID, State]:
    rows = await db.execute(
        select(
            Ticket.id, Ticket.status, Ticket.duplicate_of_id, Ticket.assignee_id
        ).where(Ticket.id.in_(list(ticket_ids)))
    )
    return {r.id: (r.status, r.duplicate_of_id, r.assignee_id) for r in rows}


async def _state(db: AsyncSession, ticket_id: uuid.UUID) -> State:
    return (await _states(db, [ticket_id]))[ticket_id]


def _claim(actor: User, previous: User | None) -> EventRow:
    """The acting-user `assignment` of `auto_assign_actor(force=True)`."""
    return EventRow(
        "assignment",
        actor.id,
        previous.username if previous is not None else None,
        actor.username,
        None,
        None,
    )


def _direct(exit_: str, actor: User, target: Ticket | None) -> list[EventRow]:
    """The direct exit event: none for a reopen; the acting-user
    `duplicate_removed` with the pre-clear target for a revert."""
    if exit_ == "reopen":
        return []
    assert target is not None
    return [EventRow("duplicate_removed", actor.id, _sntl(target), None, None, None)]


def _final(exit_: str, status: TicketStatus) -> EventRow:
    """The one system `status_change` from the preserved source status."""
    return status_event(SOURCE[exit_].value, status.value)


def _reactivation(subject: dict[str, str], old: bool, new: bool) -> EventRow:
    """A system Product event of the exit's convergence."""
    return EventRow(
        "product_eligibility_changed",
        None,
        "true" if old else "false",
        "true" if new else "false",
        None,
        {**subject, "reason": "reactivation"},
    )


async def _reactivation_subjects(
    db: AsyncSession, ticket_id: uuid.UUID
) -> list[dict[str, str]]:
    return [
        {k: v for k, v in s.items() if k != "reason"}
        for s in await subjects(db, ticket_id)
    ]


def _spy(
    monkeypatch: pytest.MonkeyPatch, module: ModuleType, name: str
) -> list[tuple[tuple[Any, ...], dict[str, Any]]]:
    """Wrap an async module attribute, recording each call's arguments."""
    calls: list[tuple[tuple[Any, ...], dict[str, Any]]] = []
    original = getattr(module, name)

    async def _wrapper(*args: Any, **kwargs: Any) -> Any:
        calls.append((args, kwargs))
        return await original(*args, **kwargs)

    monkeypatch.setattr(module, name, _wrapper)
    return calls


class _Composition:
    """Records, in call order, the package boundary and the reconciliation
    invoked by `ticket_service`, with the Ticket state at call time."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []
        converge = package_service.converge_manual_zone_exit_eligibility
        reconcile = ticket_mutations.reconcile_ticket_status

        async def _converge(
            db: AsyncSession, *, ticket: Ticket, evaluation_date: date
        ) -> Any:
            self.calls.append(
                (
                    "converge",
                    {
                        "ticket": ticket,
                        "status": ticket.status,
                        "duplicate_of_id": ticket.duplicate_of_id,
                        "evaluation_date": evaluation_date,
                    },
                )
            )
            return await converge(db, ticket=ticket, evaluation_date=evaluation_date)

        async def _reconcile(
            ticket: Ticket,
            db: AsyncSession,
            previous_status: TicketStatus | None = None,
            evaluation_date: date | None = None,
        ) -> None:
            self.calls.append(
                (
                    "reconcile",
                    {
                        "ticket": ticket,
                        "previous_status": previous_status,
                        "evaluation_date": evaluation_date,
                    },
                )
            )
            await reconcile(
                ticket,
                db,
                previous_status=previous_status,
                evaluation_date=evaluation_date,
            )

        monkeypatch.setattr(
            package_service, "converge_manual_zone_exit_eligibility", _converge
        )
        monkeypatch.setattr(ticket_service, "reconcile_ticket_status", _reconcile)


def _first(statements: list[str], *markers: str) -> int:
    return next(i for i, s in enumerate(statements) if all(m in s for m in markers))


# ---------------------------------------------------------------------------
# ATR 10: composition, lock order, one date, one reconciliation
# ---------------------------------------------------------------------------

CAPTURED_INSTANT = datetime(2026, 9, 27, 21, 30, tzinfo=timezone(timedelta(hours=-5)))
"""A controlled clock whose UTC date (2026-09-28) differs from its local date."""


@pytest.mark.integration
class TestComposition:
    @pytest.mark.parametrize(
        ("supplied", "expected_date"),
        [
            pytest.param(EVAL, EVAL, id="supplied-date"),
            pytest.param(None, date(2026, 9, 28), id="captured-utc-date"),
        ],
    )
    @pytest.mark.parametrize("exit_", EXITS)
    async def test_locks_then_converges_then_reconciles_once_with_one_date(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
        exit_: str,
        supplied: date | None,
        expected_date: date,
    ) -> None:
        """ticket-service.md, `_complete_manual_zone_exit()`: the acting
        User `FOR SHARE` then the Ticket `FOR UPDATE` (the revert target is
        not locked); the package boundary receives the locked Ticket at the
        `Analysis` floor (link already cleared) and the workflow date; then
        exactly one reconciliation with the preserved source status and the
        same date. No audit history is read and nothing is committed."""
        actor = await va_user()
        ticket, target = await _source(ticket_factory, exit_)
        composition = _Composition(monkeypatch)
        monkeypatch.setattr(ticket_service, "_utc_now", lambda: CAPTURED_INSTANT)

        async def forbidden() -> None:
            raise AssertionError("a manual-zone exit must not commit or roll back")

        monkeypatch.setattr(db_session, "commit", forbidden)
        monkeypatch.setattr(db_session, "rollback", forbidden)

        with StatementRecorder(db_session) as recorder:
            result = await _exit(
                db_session, exit_, ticket.id, actor, evaluation_date=supplied
            )

        assert composition.calls == [
            (
                "converge",
                {
                    "ticket": result,
                    "status": TicketStatus.ANALYSIS,
                    "duplicate_of_id": None,
                    "evaluation_date": expected_date,
                },
            ),
            (
                "reconcile",
                {
                    "ticket": result,
                    "previous_status": SOURCE[exit_],
                    "evaluation_date": expected_date,
                },
            ),
        ]
        statements = recorder.statements
        user_share = _first(statements, 'FROM "user"', "FOR SHARE")
        ticket_lock = _first(statements, "FROM ticket", "FOR UPDATE")
        assert user_share < ticket_lock
        assert len(recorder.row_locks()) == 2
        assert recorder.parameters[ticket_lock][0] == ticket.id
        assert recorder.selects_from("ticket_audit_event") == []
        assert result.id == ticket.id
        assert await _state(db_session, ticket.id) == (
            TicketStatus.ANALYSIS,
            None,
            actor.id,
        )
        assert await ticket_events_by_id(db_session, ticket.id) == [
            _claim(actor, None),
            *_direct(exit_, actor, target),
            _final(exit_, TicketStatus.ANALYSIS),
        ]


# ---------------------------------------------------------------------------
# Assignment (auto_assign_actor(force=True))
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestAssignment:
    @pytest.mark.parametrize(
        "case",
        [
            "unassigned",
            "replaces-other",
            "already-assignee",
            "non-va-actor",
            "inactive-va-actor",
        ],
    )
    @pytest.mark.parametrize("exit_", EXITS)
    async def test_active_va_actor_becomes_the_assignee_otherwise_unchanged(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        exit_: str,
        case: str,
    ) -> None:
        """ticket-service.md, `reopen_from_ignored()` / `revert_duplicate()`
        step 3: an active VA actor becomes the assignee, replacing a
        different one (`old_value` its username); an actor that already is
        the assignee, a non-VA actor, and an inactive VA actor leave the
        assignee unchanged without an `assignment` event. The final result
        is the `Analysis` floor (no package) with an eligible assignee."""
        owner = await va_user()
        scope = Scope.ALL
        if case == "non-va-actor":
            actor = await va_user(roles=(Role.RESTRICTED_ANALYST,))
            scope = Scope.NON_CONFIDENTIAL
        elif case == "inactive-va-actor":
            actor = await va_user(active=False)
        else:
            actor = await va_user()
        previous = {"unassigned": None, "already-assignee": actor}.get(case, owner)
        ticket, target = await _source(
            ticket_factory,
            exit_,
            assignee_id=previous.id if previous is not None else None,
        )

        await _exit(db_session, exit_, ticket.id, actor, scope=scope)

        claimed = case in ("unassigned", "replaces-other")
        expected = actor if claimed else previous
        assert expected is not None
        assert await _state(db_session, ticket.id) == (
            TicketStatus.ANALYSIS,
            None,
            expected.id,
        )
        assert await ticket_events_by_id(db_session, ticket.id) == [
            *([_claim(actor, previous)] if claimed else []),
            *_direct(exit_, actor, target),
            _final(exit_, TicketStatus.ANALYSIS),
        ]


# ---------------------------------------------------------------------------
# Guards and their order, with zero side effects
# ---------------------------------------------------------------------------


async def _assert_rejected(
    db: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
    error_type: type[Exception],
    *,
    exit_: str,
    ticket_id: uuid.UUID,
    actor: User,
    scope: Scope = Scope.ALL,
) -> None:
    """The zero-side-effect contract of a rejected exit: the error, no
    write, no assignment, no convergence, no reconciliation, no registered
    effect, the Ticket (and any target) unchanged, and no event."""
    assign = _spy(monkeypatch, ticket_service, "auto_assign_actor")
    converge = _spy(
        monkeypatch, package_service, "converge_manual_zone_exit_eligibility"
    )
    reconcile = _spy(monkeypatch, ticket_service, "reconcile_ticket_status")
    # A `Duplicated` Ticket's target is involved as well.
    links = [s[1] for s in (await _states(db, [ticket_id])).values() if s[1]]
    involved = [ticket_id, *links]
    before = await _states(db, involved)

    with StatementRecorder(db) as recorder, pytest.raises(error_type):
        await _exit(db, exit_, ticket_id, actor, scope=scope)

    assert recorder.writes() == []
    assert (assign, converge, reconcile) == ([], [], [])
    assert pending_ticket_convergence_effects(db) == ()
    assert await _states(db, involved) == before
    for involved_id in involved:
        assert await ticket_events_by_id(db, involved_id) == []


@pytest.mark.integration
class TestGuards:
    @pytest.mark.parametrize(
        "status",
        [
            TicketStatus.NEW,
            TicketStatus.ANALYSIS,
            TicketStatus.ANALYZED,
            TicketStatus.RESOLVED,
            None,
        ],
        ids=["New", "Analysis", "Analyzed", "Resolved", "other-manual-zone"],
    )
    @pytest.mark.parametrize("exit_", EXITS)
    async def test_any_other_status_is_an_invalid_transition(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
        exit_: str,
        status: TicketStatus | None,
    ) -> None:
        """Exact source state only (no `ensure_ticket_operable()`): an
        unassigned Ticket and a VA actor make an assignment before the
        guard observable."""
        actor = await va_user()
        ticket = await ticket_factory(
            status=(status or OTHER_MANUAL_ZONE[exit_]).value,
            severity_manual=Severity.HIGH.value,
        )

        await _assert_rejected(
            db_session,
            monkeypatch,
            InvalidTransitionError,
            exit_=exit_,
            ticket_id=ticket.id,
            actor=actor,
        )

    @pytest.mark.parametrize("exit_", EXITS)
    async def test_missing_ticket_is_not_found(
        self,
        db_session: AsyncSession,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
        exit_: str,
    ) -> None:
        actor = await va_user()

        await _assert_rejected(
            db_session,
            monkeypatch,
            TicketNotFoundError,
            exit_=exit_,
            ticket_id=uuid.uuid7(),
            actor=actor,
        )

    @pytest.mark.parametrize(
        "valid_source", [True, False], ids=["source", "also-invalid"]
    )
    @pytest.mark.parametrize("exit_", EXITS)
    async def test_inaccessible_ticket_is_not_found_before_the_status_guard(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        ticket_access_grant_factory: Callable[..., Awaitable[TicketAccessGrant]],
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
        exit_: str,
        valid_source: bool,
    ) -> None:
        """A VA origin with a request-resolved `non_confidential` scope; the
        confidential Ticket's only grant belongs to another user. A Ticket
        in a wrong status is still `TicketNotFoundError`."""
        actor = await va_user()
        status = SOURCE[exit_] if valid_source else TicketStatus.ANALYSIS
        ticket = await ticket_factory(status=status.value, is_confidential=True)
        await ticket_access_grant_factory(ticket_id=ticket.id)

        await _assert_rejected(
            db_session,
            monkeypatch,
            TicketNotFoundError,
            exit_=exit_,
            ticket_id=ticket.id,
            actor=actor,
            scope=Scope.NON_CONFIDENTIAL,
        )

    @pytest.mark.parametrize("exit_", EXITS)
    async def test_caller_mismatch_raises_before_any_statement(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        exit_: str,
    ) -> None:
        actor = await va_user()
        other = await va_user()
        ticket, _target = await _source(ticket_factory, exit_)
        operation = reopen_from_ignored if exit_ == "reopen" else revert_duplicate

        with (
            StatementRecorder(db_session) as recorder,
            pytest.raises(ValueError, match="acting user"),
        ):
            await operation(
                db_session,
                ticket_id=ticket.id,
                acting_user_id=actor.id,
                caller=TicketCaller.authenticated(other.id, Scope.ALL),
                evaluation_date=EVAL,
            )

        assert recorder.statements == []
        assert (await _state(db_session, ticket.id))[0] == SOURCE[exit_]
        assert await ticket_events_by_id(db_session, ticket.id) == []


# ---------------------------------------------------------------------------
# Trusted system reopen (reopen_from_ignored_as_system())
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestSystemReopen:
    async def test_no_user_root_no_visibility_filter_and_the_assignee_is_retained(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """ticket-service.md, `reopen_from_ignored()` step 1 and the
        CVE-ingestion composition: only the Ticket `FOR UPDATE`, no User
        lock and no consumer visibility statement (the Ticket is
        confidential), no actor assignment; the same composition follows."""
        owner = await va_user()
        ticket = await ticket_factory(
            status=TicketStatus.IGNORED.value,
            severity_manual=Severity.HIGH.value,
            is_confidential=True,
            assignee_id=owner.id,
        )
        composition = _Composition(monkeypatch)

        with StatementRecorder(db_session) as recorder:
            result = await reopen_from_ignored_as_system(
                db_session, ticket_id=ticket.id, evaluation_date=EVAL
            )

        assert [name for name, _ in composition.calls] == ["converge", "reconcile"]
        assert composition.calls[1][1]["previous_status"] is TicketStatus.IGNORED
        assert composition.calls[0][1]["evaluation_date"] == EVAL
        assert composition.calls[1][1]["evaluation_date"] == EVAL
        locks = recorder.row_locks()
        assert len(locks) == 1
        assert "FROM ticket" in locks[0]
        assert "FOR UPDATE" in locks[0]
        assert [s for s in recorder.statements if "ticket_access_grant" in s] == []
        assert result.status == TicketStatus.ANALYSIS
        assert await _state(db_session, ticket.id) == (
            TicketStatus.ANALYSIS,
            None,
            owner.id,
        )
        assert await ticket_events_by_id(db_session, ticket.id) == [
            _final("reopen", TicketStatus.ANALYSIS)
        ]
        assert pending_ticket_convergence_effects(db_session) == (
            TicketConvergenceEffect(ticket.id),
        )

    @pytest.mark.parametrize(
        "status",
        [None, TicketStatus.ANALYSIS, TicketStatus.DUPLICATED],
        ids=["missing", "Analysis", "Duplicated"],
    )
    async def test_missing_or_non_ignored_ticket_is_rejected_without_effect(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        monkeypatch: pytest.MonkeyPatch,
        status: TicketStatus | None,
    ) -> None:
        ticket_id = (
            uuid.uuid7()
            if status is None
            else (await ticket_factory(status=status.value)).id
        )
        before = await _states(db_session, [ticket_id])
        converge = _spy(
            monkeypatch, package_service, "converge_manual_zone_exit_eligibility"
        )
        error = TicketNotFoundError if status is None else InvalidTransitionError

        with StatementRecorder(db_session) as recorder, pytest.raises(error):
            await reopen_from_ignored_as_system(
                db_session, ticket_id=ticket_id, evaluation_date=EVAL
            )

        assert recorder.writes() == []
        assert converge == []
        assert pending_ticket_convergence_effects(db_session) == ()
        assert await _states(db_session, [ticket_id]) == before
        assert await ticket_events_by_id(db_session, ticket_id) == []


# ---------------------------------------------------------------------------
# Final status from current gates and convergence registration (ATR 11)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestFinalStatus:
    @pytest.mark.parametrize("final", GATE_RESULTS, ids=str)
    @pytest.mark.parametrize("exit_", EXITS)
    async def test_final_status_is_evaluated_and_one_effect_is_registered(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        tree: TreeBuilder,
        exit_: str,
        final: TicketStatus,
    ) -> None:
        """The one system `status_change` records the real transition from
        the preserved source (e.g. `Ignored -> Analyzed`), and every final
        status, including `Resolved`, registers exactly one effect."""
        actor = await va_user()
        ticket, target = await _source(ticket_factory, exit_)
        await tree_for(final, ticket, tree)

        result = await _exit(db_session, exit_, ticket.id, actor)

        assert result.status == final
        assert await _state(db_session, ticket.id) == (final, None, actor.id)
        assert await ticket_events_by_id(db_session, ticket.id) == [
            _claim(actor, None),
            *_direct(exit_, actor, target),
            _final(exit_, final),
        ]
        assert pending_ticket_convergence_effects(db_session) == (
            TicketConvergenceEffect(ticket.id),
        )

    @pytest.mark.parametrize(
        ("override", "final"),
        [
            pytest.param(False, TicketStatus.RESOLVED, id="automatic"),
            pytest.param(True, TicketStatus.ANALYZED, id="override-skipped"),
        ],
    )
    @pytest.mark.parametrize("exit_", EXITS)
    async def test_eligibility_converges_before_the_final_gate(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        tree: TreeBuilder,
        exit_: str,
        override: bool,
        final: TicketStatus,
    ) -> None:
        """An `AFFECTED` track whose only Product is persisted eligible but
        is in Reactive Support: on the stale value the track is incomplete
        (`Analyzed`). The automatic record converges to ineligible first,
        so the track is resolution-complete and the result is `Resolved`;
        an override is skipped without an event and stays `Analyzed`."""
        actor = await va_user()
        ticket, target = await _source(ticket_factory, exit_)
        await tree(
            ticket,
            status=PackageStatus.AFFECTED,
            products=(Prod(eligible=True, reactive=True, override=override),),
        )
        subject = (await _reactivation_subjects(db_session, ticket.id))[0]

        await _exit(db_session, exit_, ticket.id, actor)

        assert await eligibility(db_session, ticket.id) == [(override, override)]
        assert await ticket_events_by_id(db_session, ticket.id) == [
            _claim(actor, None),
            *_direct(exit_, actor, target),
            *([] if override else [_reactivation(subject, True, False)]),
            _final(exit_, final),
        ]

    @pytest.mark.parametrize(
        ("assignee_kind", "reason"),
        [("inactive", INACTIVE), ("non-va", VA_REMOVED)],
        ids=["inactive", "non-va"],
    )
    @pytest.mark.parametrize("final", GATE_RESULTS, ids=str)
    @pytest.mark.parametrize("exit_", EXITS)
    async def test_ineligible_assignee_is_cleared_only_below_resolved(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        tree: TreeBuilder,
        exit_: str,
        final: TicketStatus,
        assignee_kind: str,
        reason: str,
    ) -> None:
        """ATR 11 and ticket-mutations.md, Assignment Eligibility
        Sanitization: a non-VA actor keeps the pre-existing ineligible
        assignee through step 3; the reconciliation clears it for final
        `Analysis` or `Analyzed` and retains it for `Resolved`. The full
        sequence: direct event, system Product events in occurrence order,
        the sanitation `assignment`, then the final `status_change`."""
        actor = await va_user(roles=(Role.RESTRICTED_ANALYST,))
        if assignee_kind == "inactive":
            assignee = await va_user(active=False)
        else:
            assignee = await va_user(roles=(Role.RESTRICTED_ANALYST,))
        ticket, target = await _source(ticket_factory, exit_, assignee_id=assignee.id)
        await tree(
            ticket,
            status=GATE_TRACK[final],
            products=(Prod(eligible=False), Prod(eligible=False)),
        )
        detail = await _reactivation_subjects(db_session, ticket.id)

        await _exit(db_session, exit_, ticket.id, actor, scope=Scope.NON_CONFIDENTIAL)

        cleared = final is not TicketStatus.RESOLVED
        assert await _state(db_session, ticket.id) == (
            final,
            None,
            None if cleared else assignee.id,
        )
        assert await ticket_events_by_id(db_session, ticket.id) == [
            *_direct(exit_, actor, target),
            _reactivation(detail[0], False, True),
            _reactivation(detail[1], False, True),
            *([unassigned_event(assignee.username, reason)] if cleared else []),
            _final(exit_, final),
        ]
        assert pending_ticket_convergence_effects(db_session) == (
            TicketConvergenceEffect(ticket.id),
        )


# ---------------------------------------------------------------------------
# Revert specifics
# ---------------------------------------------------------------------------


def _ticket_updates(statements: Iterable[str]) -> list[str]:
    return [s for s in statements if s.lstrip().startswith("UPDATE ticket SET")]


@pytest.mark.integration
class TestRevert:
    async def test_forced_autoflush_writes_the_link_clear_and_floor_together(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """ATR 10 (revert): an autoflush-capable role lookup is forced at
        the first operation after the clear (the `duplicate_removed` audit
        write). The autoflush issues one Ticket `UPDATE` carrying both
        `status` and `duplicate_of_id`, which satisfies
        `chk_ticket_duplicate_status_coherence`; the persisted row is then
        `Analysis` without a link. No other `UPDATE` touches the link."""
        actor = await va_user()
        ticket, target = await _source(ticket_factory, "revert")
        assert target is not None
        original_log = TicketAuditLog.log_event
        observed: dict[str, Any] = {}

        async def log_with_role_lookup(*args: Any, **kwargs: Any) -> None:
            if kwargs["event_type"] is TicketAuditEventType.DUPLICATE_REMOVED:
                start = len(recorder.statements)
                await db_session.execute(
                    select(UserRole.role).where(UserRole.user_id == actor.id)
                )
                observed["autoflush"] = recorder.statements[start:]
                observed["persisted"] = tuple(
                    (
                        await db_session.execute(
                            select(Ticket.status, Ticket.duplicate_of_id).where(
                                Ticket.id == ticket.id
                            )
                        )
                    ).one()
                )
            await original_log(*args, **kwargs)

        monkeypatch.setattr(TicketAuditLog, "log_event", log_with_role_lookup)

        with StatementRecorder(db_session) as recorder:
            await _exit(db_session, "revert", ticket.id, actor)

        (flushed,) = _ticket_updates(observed["autoflush"])
        assert "status=" in flushed
        assert "duplicate_of_id=" in flushed
        assert observed["persisted"] == (TicketStatus.ANALYSIS, None)
        assert [
            s for s in _ticket_updates(recorder.statements) if "duplicate_of_id=" in s
        ] == [flushed]
        assert await ticket_events_by_id(db_session, ticket.id) == [
            _claim(actor, None),
            EventRow("duplicate_removed", actor.id, _sntl(target), None, None, None),
            _final("revert", TicketStatus.ANALYSIS),
        ]

    async def test_other_tickets_keep_their_targets(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
    ) -> None:
        """Non-retroactive: a dependent repointed to the target when the
        source was marked stays pointed there; neither it nor the target is
        locked, changed, or given an event."""
        actor = await va_user(roles=(Role.RESTRICTED_ANALYST,))
        ticket, target = await _source(ticket_factory, "revert")
        assert target is not None
        sibling = await ticket_factory(duplicate_of_id=target.id)
        others = [target.id, sibling.id]
        before = await _states(db_session, others)

        with StatementRecorder(db_session) as recorder:
            await _exit(
                db_session, "revert", ticket.id, actor, scope=Scope.NON_CONFIDENTIAL
            )

        assert len(recorder.row_locks()) == 2
        assert await _states(db_session, others) == before
        assert before[sibling.id] == (TicketStatus.DUPLICATED, target.id, None)
        for other_id in others:
            assert await ticket_events_by_id(db_session, other_id) == []
        assert await _state(db_session, ticket.id) == (
            TicketStatus.ANALYSIS,
            None,
            None,
        )


# ---------------------------------------------------------------------------
# Whole-workflow rollback (audit Testing Requirements 7 and 24)
# ---------------------------------------------------------------------------

FAILURES = [
    "package",
    "audit-duplicate-removed",
    "audit-product",
    "audit-status",
    "flush",
    "reconcile",
]

ROLLBACK_CASES = [
    pytest.param(exit_, failure, id=f"{exit_}-{failure}")
    for exit_ in EXITS
    for failure in FAILURES
    if not (exit_ == "reopen" and failure == "audit-duplicate-removed")
]

_AUDIT_FAILURES = {
    "audit-duplicate-removed": TicketAuditEventType.DUPLICATE_REMOVED,
    "audit-product": TicketAuditEventType.PRODUCT_ELIGIBILITY_CHANGED,
    "audit-status": TicketAuditEventType.STATUS_CHANGE,
}


@pytest.mark.integration
class TestRollback:
    @pytest.mark.parametrize(("exit_", "failure"), ROLLBACK_CASES)
    async def test_injected_failure_rolls_back_every_effect(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        tree: TreeBuilder,
        monkeypatch: pytest.MonkeyPatch,
        exit_: str,
        failure: str,
    ) -> None:
        """A VA actor replaces another assignee, the link is cleared, and a
        Product converges before the final `Ignored/Duplicated -> Analyzed`.
        A failure at each position (the package boundary, the direct,
        Product, or final audit write, the flush inserting the final event,
        or the reconciliation) escapes, and the caller's rollback leaves
        status, link, assignee, Product eligibility, events, and pending
        effects exactly as before."""
        actor = await va_user()
        owner = await va_user()
        ticket, target = await _source(ticket_factory, exit_, assignee_id=owner.id)
        await tree(
            ticket, status=PackageStatus.AFFECTED, products=(Prod(eligible=False),)
        )
        # Primary keys are captured before the scope expires the instances.
        ticket_id = ticket.id
        target_id = target.id if target is not None else None
        before = await _state(db_session, ticket_id)
        assert before == (SOURCE[exit_], target_id, owner.id)
        reached = False
        original_log = TicketAuditLog.log_event
        original_flush = db_session.flush

        async def failing(*args: Any, **kwargs: Any) -> None:
            nonlocal reached
            reached = True
            raise RuntimeError("injected failure")

        async def failing_log(*args: Any, **kwargs: Any) -> None:
            if kwargs["event_type"] is _AUDIT_FAILURES[failure]:
                await failing()
            await original_log(*args, **kwargs)

        async def failing_flush(*args: Any, **kwargs: Any) -> None:
            if any(
                isinstance(o, TicketAuditEvent)
                and o.event_type == TicketAuditEventType.STATUS_CHANGE
                for o in db_session.new
            ):
                await failing()
            await original_flush(*args, **kwargs)

        async with rollback_test_scope(db_session):
            if failure == "package":
                monkeypatch.setattr(
                    package_service, "converge_manual_zone_exit_eligibility", failing
                )
            elif failure == "reconcile":
                monkeypatch.setattr(ticket_service, "reconcile_ticket_status", failing)
            elif failure == "flush":
                monkeypatch.setattr(db_session, "flush", failing_flush)
            else:
                monkeypatch.setattr(TicketAuditLog, "log_event", failing_log)
            with pytest.raises(RuntimeError, match="injected"):
                await _exit(db_session, exit_, ticket_id, actor)
        monkeypatch.undo()

        assert reached
        assert pending_ticket_convergence_effects(db_session) == ()
        assert await _state(db_session, ticket_id) == before
        assert await eligibility(db_session, ticket_id) == [(False, False)]
        assert await ticket_events_by_id(db_session, ticket_id) == []

    async def test_registered_effect_is_discarded_on_rollback(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
    ) -> None:
        """ATR 11: a rolled-back exit leaves no pending effect to publish."""
        actor = await va_user()
        ticket, _target = await _source(ticket_factory, "reopen")
        ticket_id = ticket.id

        async with rollback_test_scope(db_session):
            await _exit(db_session, "reopen", ticket_id, actor)
            assert pending_ticket_convergence_effects(db_session) == (
                TicketConvergenceEffect(ticket_id),
            )

        assert pending_ticket_convergence_effects(db_session) == ()
        assert await _state(db_session, ticket_id) == (TicketStatus.IGNORED, None, None)
        assert await ticket_events_by_id(db_session, ticket_id) == []


# ---------------------------------------------------------------------------
# Deadlines (ticket-deadlines.md, Testing Requirements 3 and 4)
# ---------------------------------------------------------------------------

CREATED_AT = datetime(2026, 9, 26, 10, 15, 30, tzinfo=UTC)
DETAIL_INSTANT = datetime(2026, 9, 27, 12, 0, tzinfo=UTC)
"""The projection's controlled evaluation instant: before every due date."""


def _milestones(detail: TicketDetailProjection) -> list[TrackMilestones]:
    return [track.milestones for package in detail.packages for track in package.tracks]


@pytest.mark.integration
class TestDeadlines:
    @pytest.mark.parametrize("exit_", EXITS)
    async def test_deadlines_are_null_in_the_manual_zone_and_reappear_after_exit(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        tree: TreeBuilder,
        monkeypatch: pytest.MonkeyPatch,
        exit_: str,
    ) -> None:
        """Null Due Dates and Track Milestones rule 1 while `Ignored` or
        `Duplicated`; after the exit (final `Analysis`, CVE-less `High`,
        30-day tier) the dates reappear from the unchanged `created_at`:
        +3, +18, +21, +30, +30 days. The `ANALYSIS` track's `triage` is
        pending, later phases are `null` for a CVE-less Ticket, and the
        current phase is `triage`."""
        monkeypatch.setattr(ticket_service, "_utc_now", lambda: DETAIL_INSTANT)
        actor = await va_user(roles=(Role.RESTRICTED_ANALYST,))
        ticket, _target = await _source(ticket_factory, exit_, created_at=CREATED_AT)
        await tree(ticket, status=PackageStatus.ANALYSIS)

        inactive = await assemble_ticket_detail(
            db_session, ticket_id=ticket.id, evaluation_date=EVAL
        )
        await _exit(db_session, exit_, ticket.id, actor, scope=Scope.NON_CONFIDENTIAL)
        active = await assemble_ticket_detail(
            db_session, ticket_id=ticket.id, evaluation_date=EVAL
        )

        assert inactive.due_dates is None
        assert _milestones(inactive) == [TrackMilestones(None, None, None, None, None)]
        assert active.status == TicketStatus.ANALYSIS
        assert inactive.created_at == active.created_at == CREATED_AT
        assert active.due_dates == DueDates(
            triage=CREATED_AT + timedelta(days=3),
            submission=CREATED_AT + timedelta(days=18),
            um=CREATED_AT + timedelta(days=21),
            qa=CREATED_AT + timedelta(days=30),
            release=CREATED_AT + timedelta(days=30),
        )
        assert _milestones(active) == [
            TrackMilestones(
                MilestoneStatus.PENDING, None, None, None, CurrentPhase.TRIAGE
            )
        ]
