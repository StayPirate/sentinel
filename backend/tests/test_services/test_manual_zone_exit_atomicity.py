"""Independent-session tests for the manual-zone exits
`reopen_from_ignored()` and `revert_duplicate()`
(backend/app/services/ticket_service.py), composed with
`package_service.converge_manual_zone_exit_eligibility()`.

Owning specifications:

- docs/features/tickets/ticket-service.md (Caller category and Ticket
  accessibility; `_complete_manual_zone_exit()`; `reopen_from_ignored()`;
  `revert_duplicate()`; Architectural Test Requirements 10, the race with
  CVSS mutation, and 15, manual-zone exit part).
- docs/features/packages/package-service.md (Synchronous manual-zone-exit
  eligibility convergence: current committed CVE-owned state only; a
  concurrent manual CVSS workflow follows User then CVE then Ticket and
  recomputes from winner-current state).
- docs/features/tickets/ticket-mutations.md (CVSS Status Matrix: manual
  SUSE mutations reject `Ignored` and `Duplicated`; Architectural Test
  Requirement: Independent-session races, CVSS/reactivation).
- docs/features/tickets/ticket-audit-log.md (Cross-Event Ordering, Locking,
  and Rollback; Testing Requirement 23).
- docs/features/platform/testing-strategy.md (Concurrency Testing; Ticket
  Accessibility: Locked mutations; Tier Responsibility and
  Proportionality).

The single-session behavior (composition, lock order, assignment, guards
and their order, final status, rollback) is covered by
`tests/test_services/test_manual_zone_exits.py` and the package boundary by
`tests/test_services/test_manual_zone_exit_eligibility.py`; this module
adds only what needs independent sessions:

- the CVSS/reactivation race in both serialization orders, for both exits
  and both manual SUSE mutations (ATR 10; ticket-mutations.md,
  CVSS/reactivation). When the exit holds the Ticket first it is paused
  inside the package boundary, so the CVSS mutation provably holds the CVE
  and waits for the Ticket while the exit completes: the exit never waits
  for, or requests, the CVE root lock (the foreign-key `FOR KEY SHARE`
  PostgreSQL takes on a second Ticket UPDATE stays compatible with the
  CVE root's `FOR NO KEY UPDATE`; `docs/conventions.md`, Cross-Domain Root
  Lock Order). When the CVSS mutation locks first, its
  `TicketNotMutableError` leaves its User, CVE, and Ticket locks held until
  the caller's rollback, so the exit provably waits on the Ticket without
  any additional pause;
- locked-current accessibility races (ATR 15), including a Ticket that the
  same committed change also moved out of the source status: the denial
  precedes the exact-source-status guard;
- a waiting exit that observes the winner's committed exit (audit TR 23).

Not applicable, hence not tested here:

- the `association-changed` visibility loss of
  `tests.support.suse_cvss_races.VISIBILITY_LOSSES`. It is a CVE-path loss
  (testing-strategy.md, Locked mutations: "changing the CVE-to-Ticket
  association for a CVE-scoped operation"); the exits are Ticket-scoped
  and the canonical predicate of a Ticket does not depend on its CVE
  association;
- the converse self-loss case of ATR 15. The canonical predicate
  (docs/features/identity/rbac.md, Scope and Confidential Ticket
  Visibility) depends only on the Ticket's confidentiality, the caller's
  scope, explicit grants, and included-package maintainership; the exits
  change only the status, `duplicate_of_id`, `assignee_id`, and Product
  eligibility, so they cannot remove a visibility path;
- the trusted `reopen_from_ignored_as_system()` form: it has no consumer
  accessibility, and its only caller already holds the CVE then Ticket
  locks (ATR 18, the CVE republication composition).

Committed rows are deleted explicitly at teardown (testing-strategy.md,
Concurrency Testing). Every wait is bounded with `asyncio.wait_for()` (over
`asyncio.shield()` where the task must survive the timeout) so a regression
fails instead of hanging. Expected values are transcribed from the
specifications, never computed with the module under test.
"""

from __future__ import annotations

import asyncio
import re
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass
from decimal import Decimal
from types import ModuleType
from typing import Any

import pytest
from sqlalchemy import Select, delete, select, update
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import Role, Scope, Severity, TicketStatus
from app.core.exceptions import (
    InvalidTransitionError,
    TicketNotFoundError,
    TicketNotMutableError,
)
from app.models.cve import CVE
from app.models.system_setting import SystemSetting
from app.models.ticket import Ticket
from app.models.user import User
from app.services import package_service, ticket_mutations, ticket_service
from app.services.ticket_convergence_registry import (
    pending_ticket_convergence_effects,
)
from app.services.ticket_mutations import (
    CVSSAssessmentMutationResult,
    CVSSPropagation,
)
from app.services.ticket_service import (
    reopen_from_ignored,
    resolve_ticket_locator,
    revert_duplicate,
)
from app.services.ticket_visibility import TicketCaller
from tests.support.cvss_chain import (
    cve_severity,
    eligibility,
    priority_event,
    product_event,
    severity_event,
    ticket_state,
)
from tests.support.suse_cvss import (
    V31_CRITICAL,
    cvss_delete_event,
    cvss_event,
    delete_assessment,
    persisted_assessments,
    unit,
    upsert,
)
from tests.support.suse_cvss_races import (
    CommittedWorld,
    SessionStatementRecorder,
    assert_blocked,
    prepare_loss,
)
from tests.support.ticket_mutations import (
    EVAL,
    EventRow,
    StatementRecorder,
    status_event,
    ticket_events_by_id,
)

Factory = Callable[[], Awaitable[AsyncSession]]
State = tuple[str, uuid.UUID | None, uuid.UUID | None]
"""The committed `(status, duplicate_of_id, assignee_id)` of a Ticket."""

EXITS = ["reopen", "revert"]
SOURCE = {"reopen": TicketStatus.IGNORED, "revert": TicketStatus.DUPLICATED}
"""The exact source status each exit accepts."""

DEFAULT_VERSION = "3.1"
"""The committed `default_cvss_version` read by both racing workflows."""

T50 = Decimal("5.0")
"""A Product threshold reached by both the SUSE 9.8 score and the 10.0
fallback: its automatic value is `true` in every race state."""

T99 = Decimal("9.9")
"""A Product threshold above the SUSE 9.8 score and below the 10.0
fallback: its automatic value flips with every change of SUSE presence."""

CVE_STATEMENT = re.compile(r"\b(?:FROM|JOIN|INTO|UPDATE) cve\b")
TICKET_STATEMENT = re.compile(r"\b(?:FROM|JOIN|INTO|UPDATE) ticket\b")
WAIT = 5
"""Upper bound, in seconds, of every wait that is expected to finish."""


# ---------------------------------------------------------------------------
# Committed world and helpers
# ---------------------------------------------------------------------------


class _World(CommittedWorld):
    """A `CommittedWorld` that also owns the committed `default_cvss_version`
    setting (the test schema has none), read by the package boundary
    without a caller-supplied override."""

    probe: AsyncSession
    """The independent session that observes committed state and probes
    locks; separate from `session`, whose committed model instances the
    tests keep reading."""

    def __init__(self, factory: Factory, session: AsyncSession) -> None:
        super().__init__(factory, session)
        self._owns_setting = False

    async def ensure_default_setting(self) -> None:
        setting = await self.session.get(SystemSetting, "default_cvss_version")
        if setting is None:
            self.session.add(
                SystemSetting(key="default_cvss_version", value=DEFAULT_VERSION)
            )
            self._owns_setting = True
        else:
            assert setting.value == DEFAULT_VERSION
        await self.session.commit()

    async def cleanup(self) -> None:
        await super().cleanup()
        if self._owns_setting:
            await self.session.execute(
                delete(SystemSetting).where(SystemSetting.key == "default_cvss_version")
            )
            await self.session.commit()


@pytest.fixture
async def world(db_session_factory: Factory) -> AsyncIterator[_World]:
    created = _World(db_session_factory, await db_session_factory())
    try:
        created.probe = await created.open_session()
        await created.ensure_default_setting()
        yield created
    finally:
        await created.cleanup()


async def _ticket(
    world: CommittedWorld,
    *,
    status: TicketStatus = TicketStatus.ANALYSIS,
    cve: CVE | None = None,
    duplicate_of: Ticket | None = None,
    priority_auto: str | None = None,
    severity_manual: Severity | None = None,
) -> Ticket:
    """A committed, unassigned, non-confidential Ticket with an optional
    CVE and duplicate link, registered with the world for cleanup."""
    ticket = Ticket(
        id=uuid.uuid7(),
        status=status.value,
        cve_id=cve.id if cve is not None else None,
        duplicate_of_id=duplicate_of.id if duplicate_of is not None else None,
        priority_auto=priority_auto,
        severity_manual=severity_manual.value if severity_manual else None,
    )
    world.session.add(ticket)
    await world.session.flush()
    world.ticket_ids.append(ticket.id)
    await world.session.commit()
    return ticket


def _sntl(ticket: Ticket) -> str:
    """The public `SNTL-{n}` identifier (tickets.md, SNTL-{n} Format)."""
    return f"SNTL-{ticket.sequence_id}"


async def _exit(
    db: AsyncSession,
    exit_: str,
    ticket_id: uuid.UUID,
    actor: User,
    *,
    scope: Scope = Scope.ALL,
) -> Ticket:
    """Call a consumer exit as an API handler would, with the fixed `EVAL`."""
    operation = reopen_from_ignored if exit_ == "reopen" else revert_duplicate
    return await operation(
        db,
        ticket_id=ticket_id,
        acting_user_id=actor.id,
        caller=TicketCaller.authenticated(actor.id, scope),
        evaluation_date=EVAL,
    )


async def _cvss(
    db: AsyncSession, op: str, cve: CVE, actor: User
) -> CVSSAssessmentMutationResult:
    """The manual SUSE mutation of the race (the committed setting supplies
    the default version; the date is the fixed `EVAL`)."""
    if op == "upsert":
        return await upsert(db, cve.id, V31_CRITICAL.canonical, actor)
    return await delete_assessment(db, cve.id, V31_CRITICAL.version, actor)


def _claim(actor: User) -> EventRow:
    """The acting-user `assignment` of `auto_assign_actor(force=True)` on
    an unassigned Ticket."""
    return EventRow("assignment", actor.id, None, actor.username, None, None)


def _direct(exit_: str, actor: User, target: Ticket | None) -> list[EventRow]:
    """None for a reopen; the acting-user `duplicate_removed` with the
    pre-clear target for a revert."""
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


class _Spy:
    """Wraps an async module attribute, recording the session (positional
    argument `index`) of every call; racing sessions share the module."""

    def __init__(
        self, monkeypatch: pytest.MonkeyPatch, module: ModuleType, name: str, index: int
    ) -> None:
        self.sessions: list[AsyncSession] = []
        original = getattr(module, name)

        async def _wrapper(*args: Any, **kwargs: Any) -> Any:
            self.sessions.append(args[index])
            return await original(*args, **kwargs)

        monkeypatch.setattr(module, name, _wrapper)


class _Boundary:
    """Records every session entering the package boundary and, for the
    session `pause_in`, stops at its entry (after the exit locked the Ticket
    and set the floor, before any CVE-owned read) until `resume` is set."""

    def __init__(
        self, monkeypatch: pytest.MonkeyPatch, pause_in: AsyncSession | None = None
    ) -> None:
        self.sessions: list[AsyncSession] = []
        self.reached = asyncio.Event()
        self.resume = asyncio.Event()
        original = package_service.converge_manual_zone_exit_eligibility

        async def _wrapper(db: AsyncSession, **kwargs: Any) -> Any:
            self.sessions.append(db)
            if db is pause_in:
                self.reached.set()
                await self.resume.wait()
            return await original(db, **kwargs)

        monkeypatch.setattr(
            package_service, "converge_manual_zone_exit_eligibility", _wrapper
        )


def _is_user_share(statement: str) -> bool:
    return 'FROM "user"' in statement and "FOR SHARE" in statement


def _is_cve_lock(statement: str) -> bool:
    """The CVE root lock (`docs/conventions.md`, Cross-Domain Root Lock
    Order: `FOR NO KEY UPDATE`)."""
    return CVE_STATEMENT.search(statement) is not None and statement.rstrip().endswith(
        "FOR NO KEY UPDATE"
    )


def _is_ticket_lock(statement: str) -> bool:
    return TICKET_STATEMENT.search(
        statement
    ) is not None and statement.rstrip().endswith("FOR UPDATE")


def _assert_exit_locks(recorder: StatementRecorder) -> None:
    """Exactly the acting User `FOR SHARE` then the Ticket `FOR UPDATE`:
    no statement of the exit locks, or waits for, the CVE."""
    locks = recorder.row_locks()
    assert len(locks) == 2
    assert _is_user_share(locks[0])
    assert _is_ticket_lock(locks[1])
    assert [s for s in locks if CVE_STATEMENT.search(s)] == []


def _assert_cvss_locks(recorder: StatementRecorder) -> None:
    """User `FOR SHARE`, then CVE `FOR NO KEY UPDATE`, then Ticket
    `FOR UPDATE`."""

    def first(predicate: Callable[[str], bool]) -> int:
        return next(i for i, s in enumerate(recorder.statements) if predicate(s))

    assert first(_is_user_share) < first(_is_cve_lock) < first(_is_ticket_lock)


def _ticket_row(ticket_id: uuid.UUID) -> Select[Any]:
    return select(Ticket.id).where(Ticket.id == ticket_id)


def _cve_row(cve: CVE) -> Select[Any]:
    return select(CVE.id).where(CVE.id == cve.id)


async def _is_locked(
    probe: AsyncSession, statement: Select[Any], *, cve_root: bool = False
) -> bool:
    """Whether another transaction holds a lock on the row that `statement`
    selects conflicting with the probe (`FOR UPDATE NOWAIT`, released at
    once). With `cve_root`, the probe is the CVE root mode
    (`FOR NO KEY UPDATE NOWAIT`): the foreign-key `FOR KEY SHARE` that
    PostgreSQL takes on the CVE when the exit updates its Ticket a second
    time is expected and compatible with every CVE-root holder, so only a
    conflicting CVE root lock counts."""
    try:
        await probe.execute(statement.with_for_update(nowait=True, key_share=cve_root))
    except DBAPIError:
        await probe.rollback()
        return True
    await probe.rollback()
    return False


async def _states(probe: AsyncSession, *tickets: Ticket) -> dict[uuid.UUID, State]:
    """The committed states of `tickets`, read through the probe."""
    rows = await probe.execute(
        select(
            Ticket.id, Ticket.status, Ticket.duplicate_of_id, Ticket.assignee_id
        ).where(Ticket.id.in_([t.id for t in tickets]))
    )
    states = {r.id: (r.status, r.duplicate_of_id, r.assignee_id) for r in rows}
    await probe.rollback()
    return states


# ---------------------------------------------------------------------------
# ATR 10: CVSS/reactivation race, both serialization orders
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _Scenario:
    """One exit/CVSS race world.

    The CVE carries the SUSE 9.8 assessment only for `op = delete`. The
    exiting Ticket is unassigned, with the `priority_auto` of that CVE
    state, and has two automatic Product occurrences in occurrence-ID
    order: `p1` (threshold 9.9) persisted opposite to its value under the
    pre-race assessments, and `p2` (threshold 5.0) persisted `false`, so
    the exit changes both while a later CVSS mutation changes only `p1`.
    """

    exit_actor: User
    cvss_actor: User
    cve: CVE
    ticket: Ticket
    target: Ticket | None
    p1: dict[str, str]
    p2: dict[str, str]


async def _race_scenario(world: _World, exit_: str, op: str) -> _Scenario:
    exit_actor = await world.user(role=Role.VULNERABILITY_ANALYST)
    cvss_actor = await world.user(role=Role.VULNERABILITY_ANALYST)
    suse = op == "delete"
    cve = (
        await world.cve(V31_CRITICAL, severity=Severity.CRITICAL)
        if suse
        else await world.cve()
    )
    target = await _ticket(world) if exit_ == "revert" else None
    ticket = await _ticket(
        world,
        status=SOURCE[exit_],
        cve=cve,
        duplicate_of=target,
        priority_auto="P2" if suse else None,
    )
    # Creation order differs from occurrence-ID order.
    low, high = sorted(uuid.uuid7() for _ in range(2))
    p2 = await world.affected_product(
        ticket,
        threshold=T50,
        eligible=False,
        occurrence_id=high,
        package_name="fictional-race-b2",
    )
    p1 = await world.affected_product(
        ticket,
        threshold=T99,
        eligible=suse,
        occurrence_id=low,
        package_name="fictional-race-b1",
    )
    return _Scenario(exit_actor, cvss_actor, cve, ticket, target, p1, p2)


def _exit_events(exit_: str, op: str, s: _Scenario) -> list[EventRow]:
    """The exit's events from the pre-race committed assessments.

    Without SUSE (upsert race) the 10.0 fallback makes `p1` eligible and
    the unresolved severity keeps the `Analysis` floor. With SUSE 9.8
    (delete race) `p1` becomes ineligible; `Critical`, the SUSE assessment,
    and no `ANALYSIS` track pass the Analyzed gate, and `p2`'s eligible
    `AFFECTED` track is incomplete, so the result is `Analyzed`."""
    suse = op == "delete"
    return [
        _claim(s.exit_actor),
        *_direct(exit_, s.exit_actor, s.target),
        _reactivation(s.p1, suse, not suse),
        _reactivation(s.p2, False, True),
        _final(exit_, TicketStatus.ANALYZED if suse else TicketStatus.ANALYSIS),
    ]


def _cvss_events(op: str, s: _Scenario) -> list[EventRow]:
    """The CVSS mutation's events on the exit's committed result: no
    assignment (the exit assigned its actor), `reason = cvss` only for `p1`
    (`p2` is already `true` under both scores), one final status change."""
    if op == "upsert":
        return [
            cvss_event(s.cvss_actor, None, V31_CRITICAL),
            severity_event(None, "Critical"),
            product_event(s.p1, True, False),
            priority_event(None, "P2"),
            status_event(TicketStatus.ANALYSIS.value, TicketStatus.ANALYZED.value),
        ]
    return [
        cvss_delete_event(s.cvss_actor, V31_CRITICAL),
        severity_event("Critical", None),
        product_event(s.p1, False, True),
        priority_event("P2", None),
        status_event(TicketStatus.ANALYZED.value, TicketStatus.ANALYSIS.value),
    ]


@pytest.mark.integration
class TestExitAndCVSSRace:
    """ATR 10 (race with CVSS mutation) and ticket-mutations.md,
    CVSS/reactivation. Two acting VAs use independent sessions; the exit
    locks User then Ticket, the manual CVSS mutation User then CVE then
    Ticket, so they serialize on the Ticket without deadlock."""

    @pytest.mark.parametrize("order", ["exit-first", "cvss-first"])
    @pytest.mark.parametrize("op", ["upsert", "delete"])
    @pytest.mark.parametrize("exit_", EXITS)
    async def test_serialized_outcome_of_both_orderings(
        self,
        world: _World,
        monkeypatch: pytest.MonkeyPatch,
        exit_: str,
        op: str,
        order: str,
    ) -> None:
        s = await _race_scenario(world, exit_, op)
        a = await world.open_session()  # the exit
        b = await world.open_session()  # the CVSS mutation
        boundary = _Boundary(monkeypatch, pause_in=a if order == "exit-first" else None)
        exit_reconciled = _Spy(
            monkeypatch, ticket_service, "reconcile_ticket_status", 1
        )
        cvss_reconciled = _Spy(
            monkeypatch, ticket_mutations, "reconcile_ticket_status", 1
        )
        cvss_result: CVSSAssessmentMutationResult | None = None

        with (
            SessionStatementRecorder(a) as exit_recorder,
            SessionStatementRecorder(b) as cvss_recorder,
        ):
            if order == "exit-first":
                exit_task = world.start(a, _exit(a, exit_, s.ticket.id, s.exit_actor))
                await asyncio.wait_for(boundary.reached.wait(), timeout=WAIT)
                # Paused inside the boundary: A holds the Ticket, not the CVE.
                assert await _is_locked(world.probe, _ticket_row(s.ticket.id))
                assert not await _is_locked(world.probe, _cve_row(s.cve), cve_root=True)
                cvss_task = world.start(b, _cvss(b, op, s.cve, s.cvss_actor))
                await assert_blocked(cvss_task)
                # B holds the CVE and waits for the Ticket.
                assert _is_ticket_lock(cvss_recorder.statements[-1])
                assert await _is_locked(world.probe, _cve_row(s.cve), cve_root=True)
                boundary.resume.set()
                # A completes while B still holds the CVE lock.
                exit_result = await asyncio.wait_for(
                    asyncio.shield(exit_task), timeout=WAIT
                )
                await assert_blocked(cvss_task)
                await a.commit()
                cvss_result = await asyncio.wait_for(
                    asyncio.shield(cvss_task), timeout=WAIT
                )
                await b.commit()
            else:
                with pytest.raises(TicketNotMutableError):
                    await _cvss(b, op, s.cve, s.cvss_actor)
                # The rejected mutation still holds its roots until rollback.
                assert cvss_recorder.writes() == []
                exit_task = world.start(a, _exit(a, exit_, s.ticket.id, s.exit_actor))
                await assert_blocked(exit_task)
                assert _is_ticket_lock(exit_recorder.statements[-1])
                await b.rollback()
                exit_result = await asyncio.wait_for(
                    asyncio.shield(exit_task), timeout=WAIT
                )
                await a.commit()

        _assert_exit_locks(exit_recorder)
        _assert_cvss_locks(cvss_recorder)
        assert exit_result.id == s.ticket.id

        # The complete committed history: the exit's events from the
        # pre-race assessments, then only the CVSS winner-current deltas.
        expected = _exit_events(exit_, op, s)
        if order == "exit-first":
            expected += _cvss_events(op, s)
        probe = world.probe
        assert await ticket_events_by_id(probe, s.ticket.id) == expected
        assert [e for e in expected if e.event_type == "assignment"] == [
            _claim(s.exit_actor)
        ]
        assert [e.event_type for e in expected].count("status_change") == (
            2 if order == "exit-first" else 1
        )

        # Final committed state: SUSE 9.8 is present exactly when the upsert
        # committed or the delete was rejected; it decides every value.
        suse = (op == "upsert") == (order == "exit-first")
        final = TicketStatus.ANALYZED if suse else TicketStatus.ANALYSIS
        assert await ticket_state(probe, s.ticket.id) == (
            final,
            s.exit_actor.id,
            "P2" if suse else None,
            None,
            None,
        )
        assert await eligibility(probe, s.ticket.id) == [
            (not suse, False),
            (True, False),
        ]
        assert await persisted_assessments(probe, s.cve.id) == (
            [unit("SUSE", V31_CRITICAL)] if suse else []
        )
        assert await cve_severity(probe, s.cve.id) == ("Critical" if suse else None)
        await probe.rollback()
        if s.target is not None:
            assert await _states(probe, s.ticket, s.target) == {
                s.ticket.id: (final, None, s.exit_actor.id),
                s.target.id: (TicketStatus.ANALYSIS, None, None),
            }
            assert await ticket_events_by_id(probe, s.target.id) == []
            await probe.rollback()

        # One convergence and one final reconciliation per transaction.
        assert boundary.sessions == [a]
        assert exit_reconciled.sessions == [a]
        if order == "exit-first":
            assert cvss_result is not None
            assert cvss_reconciled.sessions == [b]
            assert cvss_result.propagation is CVSSPropagation.IMMEDIATE
            assert cvss_result.assigned is False
            assert cvss_result.reconciled is True
            assert (cvss_result.products.examined, cvss_result.products.changed) == (
                2,
                1,
            )
        else:
            assert cvss_reconciled.sessions == []


# ---------------------------------------------------------------------------
# ATR 15: locked-current accessibility (manual-zone exit part)
# ---------------------------------------------------------------------------


LOSSES = ["confidentiality-set", "grant-revoked", "last-package-excluded"]
"""The Ticket-path visibility losses (`association-changed` is CVE-path
only; see the module docstring)."""


@pytest.mark.integration
class TestLockedCurrentAccessibilityRaces:
    """The `restricted_analyst` caller passes the preliminary locator check
    through exactly one visibility path; an independent session then holds
    the Ticket `FOR UPDATE` and removes that path. The exit is proven
    blocked on the Ticket, the holder commits, and the exit must be denied
    from the locked-current state with zero side effects
    (testing-strategy.md, Ticket Accessibility: Locked mutations)."""

    @pytest.mark.parametrize(
        "moved", [False, True], ids=["source-status", "also-moved-out"]
    )
    @pytest.mark.parametrize("loss", LOSSES)
    @pytest.mark.parametrize("exit_", EXITS)
    async def test_visibility_lost_while_waiting_is_not_found(
        self,
        world: _World,
        monkeypatch: pytest.MonkeyPatch,
        exit_: str,
        loss: str,
        moved: bool,
    ) -> None:
        """`also-moved-out`: the same committed change also moves the
        Ticket out of its source status, so the exact-source-status guard
        would raise `InvalidTransitionError`; the denial must precede it."""
        user, _cve, ticket, statements = await prepare_loss(world, loss)
        owner = await world.user(role=Role.VULNERABILITY_ANALYST)
        target = await _ticket(world) if exit_ == "revert" else None
        await world.session.execute(
            update(Ticket)
            .where(Ticket.id == ticket.id)
            .values(
                status=SOURCE[exit_].value,
                duplicate_of_id=target.id if target is not None else None,
                assignee_id=owner.id,
            )
        )
        await world.session.commit()
        # Stale against the 10.0 fallback: a proceeding exit would change it.
        await world.affected_product(ticket, threshold=T99, eligible=False)
        if moved:
            statements = [
                *statements,
                update(Ticket)
                .where(Ticket.id == ticket.id)
                .values(status=TicketStatus.ANALYSIS.value, duplicate_of_id=None),
            ]
        committed: State = (
            (TicketStatus.ANALYSIS, None, owner.id)
            if moved
            else (SOURCE[exit_], target.id if target else None, owner.id)
        )
        a = await world.open_session()
        b = await world.open_session()
        caller = TicketCaller.authenticated(user.id, Scope.NON_CONFIDENTIAL)
        boundary = _Boundary(monkeypatch)
        assigned = _Spy(monkeypatch, ticket_service, "auto_assign_actor", 2)
        reconciled = _Spy(monkeypatch, ticket_service, "reconcile_ticket_status", 1)

        resolved = await resolve_ticket_locator(a, _sntl(ticket), caller)
        assert resolved.id == ticket.id
        for statement in statements:
            await b.execute(statement)
        with SessionStatementRecorder(a) as recorder:
            task = world.start(
                a, _exit(a, exit_, ticket.id, user, scope=Scope.NON_CONFIDENTIAL)
            )
            await assert_blocked(task)
            assert _is_user_share(recorder.statements[0])
            assert _is_ticket_lock(recorder.statements[-1])
            await b.commit()
            with pytest.raises(TicketNotFoundError):
                await asyncio.wait_for(asyncio.shield(task), timeout=WAIT)

        # The premise: the committed loss really removed the caller's access.
        with pytest.raises(TicketNotFoundError):
            await resolve_ticket_locator(world.probe, _sntl(ticket), caller)
        await world.probe.rollback()

        # Nothing happened before the denial, not even a registration.
        assert recorder.writes() == []
        assert (boundary.sessions, assigned.sessions, reconciled.sessions) == (
            [],
            [],
            [],
        )
        assert pending_ticket_convergence_effects(a) == ()
        await a.rollback()

        states = await _states(world.probe, ticket)
        assert states == {ticket.id: committed}
        assert await ticket_events_by_id(world.probe, ticket.id) == []
        assert await eligibility(world.probe, ticket.id) == [(False, False)]
        await world.probe.rollback()


# ---------------------------------------------------------------------------
# Waiting winner/loser pre-state (audit Testing Requirement 23)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestExitLockSerialization:
    async def test_waiting_reopen_after_a_committed_reopen_is_an_invalid_transition(
        self, world: _World, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A CVE-less `High` Ignored Ticket with one stale ineligible Product
        (threshold 9.9, eligible under the 10.0 fallback on an `AFFECTED`
        track, hence `Analyzed`). The loser waits on the Ticket lock and,
        after the winner commits, observes `Analyzed` under its lock: it
        raises `InvalidTransitionError` with no write, assignment,
        convergence, or event, and the winner's events are exact."""
        winner_actor = await world.user(role=Role.VULNERABILITY_ANALYST)
        loser_actor = await world.user(role=Role.VULNERABILITY_ANALYST)
        ticket = await _ticket(
            world, status=TicketStatus.IGNORED, severity_manual=Severity.HIGH
        )
        subject = await world.affected_product(ticket, threshold=T99, eligible=False)
        winner = await world.open_session()
        loser = await world.open_session()
        boundary = _Boundary(monkeypatch)
        reconciled = _Spy(monkeypatch, ticket_service, "reconcile_ticket_status", 1)

        await _exit(winner, "reopen", ticket.id, winner_actor)
        with SessionStatementRecorder(loser) as recorder:
            task = world.start(loser, _exit(loser, "reopen", ticket.id, loser_actor))
            await assert_blocked(task)
            assert _is_user_share(recorder.statements[0])
            assert _is_ticket_lock(recorder.statements[-1])
            await winner.commit()
            with pytest.raises(InvalidTransitionError):
                await asyncio.wait_for(asyncio.shield(task), timeout=WAIT)

        assert recorder.writes() == []
        assert pending_ticket_convergence_effects(loser) == ()
        await loser.rollback()
        assert boundary.sessions == [winner]
        assert reconciled.sessions == [winner]
        assert await _states(world.probe, ticket) == {
            ticket.id: (TicketStatus.ANALYZED, None, winner_actor.id)
        }
        assert await ticket_events_by_id(world.probe, ticket.id) == [
            _claim(winner_actor),
            _reactivation(subject, False, True),
            _final("reopen", TicketStatus.ANALYZED),
        ]
        assert await eligibility(world.probe, ticket.id) == [(True, False)]
        await world.probe.rollback()
