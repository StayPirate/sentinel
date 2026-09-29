"""Independent-session, lock-order, and whole-chain rollback tests for
`associate_cve()` (backend/app/services/ticket_service.py).

Owning specifications:

- docs/features/tickets/ticket-service.md (Caller category and Ticket
  accessibility; Concurrency control; `associate_cve`; Architectural Test
  Requirement 9 and 15, association part).
- docs/features/tickets/ticket-mutations.md (`recalculate_cvss_chain()`:
  association mode; Architectural Test Requirement: Serialized outcomes,
  Complete atomic chain, Independent-session races, Locked-current consumer
  accessibility).
- docs/features/tickets/ticket-audit-log.md (Event Type Contract;
  Cross-Event Ordering, Locking, and Rollback; Testing Requirements 7, 16,
  17, 23, 24).
- docs/features/platform/testing-strategy.md (Concurrency Testing; Ticket
  Accessibility: Locked mutations; Audit Trail Testing).
- docs/conventions.md (Transaction and Locking: Caller-Owned Service
  Transactions, Cross-Domain Root Lock Order).

The single-session behavior of `associate_cve()` is covered by
`tests/test_services/test_associate_cve.py`; this module adds only what
needs independent sessions or an independent committed observer. Step 14 of
the specification (the CVE freshness refresh) is deferred to M3.1 and is
neither tested nor expected here.

Not reachable, hence not tested: the converse self-loss case of Architectural
Test Requirement 15 (an authorized association that itself removes the
caller's last visibility path). The canonical predicate
(`docs/features/identity/rbac.md`, Scope and Confidential Ticket
Visibility) depends only on the Ticket's confidentiality, the caller's
scope, explicit grants, and included-package maintainership; the testing
strategy's canonical matrix states that Ticket status and the other package
and Ticket state do not change visibility. `associate_cve()` changes only
`cve_id`, `severity_manual`, assignment, status, Product eligibility, and
`priority_auto`, so it cannot remove any visibility path.

Committed rows are deleted explicitly at teardown (testing-strategy.md,
Concurrency Testing). Expected values are transcribed from the
specifications, never computed with the module under test.
"""

from __future__ import annotations

import asyncio
import re
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from decimal import Decimal
from types import ModuleType
from typing import Any

import pytest
from sqlalchemy import Select, delete, false, select, text, update
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import (
    Role,
    Scope,
    Severity,
    TicketAuditEventType,
    TicketStatus,
)
from app.core.exceptions import TicketNotFoundError
from app.models.cve import CVE
from app.models.system_setting import SystemSetting
from app.models.ticket import Ticket
from app.models.ticket_access_grant import TicketAccessGrant
from app.models.ticket_audit_event import TicketAuditEvent
from app.models.ticket_package import TicketPackage
from app.models.ticket_package_product import TicketPackageProduct
from app.models.ticket_package_track import TicketPackageTrack
from app.models.user import User
from app.services import ticket_mutations, ticket_service
from app.services.settings import RequiredSystemSettingMissingError
from app.services.ticket_audit_log import TicketAuditLog
from app.services.ticket_convergence_registry import (
    pending_ticket_convergence_effects,
)
from app.services.ticket_mutations import (
    CVSSChainMode,
    CVSSPropagation,
    reconcile_ticket_status,
)
from app.services.ticket_service import (
    TicketCVEAlreadySetError,
    TicketCVEConflictError,
    associate_cve,
    resolve_ticket_locator,
)
from app.services.ticket_visibility import TicketCaller
from tests.support.cvss_chain import (
    DEFAULT_VERSION,
    cve_severity,
    eligibility,
    label,
    priority_event,
    product_event,
    severity_event,
    ticket_state,
)
from tests.support.suse_cvss import (
    V31_CRITICAL,
    assignment_event,
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
)
from tests.support.ticket_mutations import (
    EVAL,
    EventRow,
    StatementRecorder,
    status_event,
    ticket_events_by_id,
)

Factory = Callable[[], Awaitable[AsyncSession]]

EVAL_CVSS = EVAL + timedelta(days=1)
"""The evaluation date of the racing CVSS mutation: distinct from `EVAL`,
which the association uses, so each operation's one date is observable.
Every fixture Product is in support on both days."""

T99 = Decimal("9.9")
"""A Product threshold above the 9.8 SUSE score and below the 10.0
fallback score."""

T100 = Decimal("10.0")
"""A Product threshold that only the 10.0 fallback score reaches."""

PRIORITY: dict[Severity | None, str | None] = {
    None: None,
    Severity.MEDIUM: "P4",
    Severity.CRITICAL: "P2",
}
"""ticket-priority.md, Decision Table: the `unknown` exploitation row (a
fixture CVE has no exploitation evidence) by resolved severity."""

PROMOTION = status_event(TicketStatus.NEW.value, TicketStatus.ANALYSIS.value)
"""The system `New -> Analysis` event that follows an auto-assignment."""

CVE_STATEMENT = re.compile(r"\b(?:FROM|JOIN|INTO|UPDATE) cve\b")
TICKET_STATEMENT = re.compile(r"\b(?:FROM|JOIN|INTO|UPDATE) ticket\b")


# ---------------------------------------------------------------------------
# Committed world and helpers
# ---------------------------------------------------------------------------


class _World(CommittedWorld):
    """A `CommittedWorld` that also owns the committed `default_cvss_version`
    setting (the test schema has none) and deletes the CVE placeholders the
    code under test may create, found by CVE-ID string, so a failing
    assertion cannot leak rows."""

    probe: AsyncSession
    """The independent session that observes committed state and probes
    locks; separate from `session`, whose committed model instances the
    tests keep reading (a rollback would expire them)."""

    def __init__(self, factory: Factory, session: AsyncSession) -> None:
        super().__init__(factory, session)
        self.cve_id_strings: list[str] = []
        self._owns_setting = False

    def new_cve_id(self) -> str:
        cve_id = f"CVE-2099-{uuid.uuid4().int % 10**8:08d}"
        self.cve_id_strings.append(cve_id)
        return cve_id

    async def ensure_default_setting(self) -> None:
        if await self.session.get(SystemSetting, "default_cvss_version") is None:
            self.session.add(
                SystemSetting(key="default_cvss_version", value=DEFAULT_VERSION)
            )
            self._owns_setting = True
        await self.session.commit()

    async def cleanup(self) -> None:
        await self._release()
        await self.session.rollback()
        found = (
            await self.session.scalars(
                select(CVE.id).where(CVE.cve_id.in_(self.cve_id_strings))
            )
        ).all()
        self.cve_ids.extend(set(found) - set(self.cve_ids))
        await self.session.rollback()
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


async def _associate(
    db: AsyncSession,
    ticket_id: uuid.UUID,
    cve_id: str,
    actor: User,
    *,
    scope: Scope = Scope.ALL,
    evaluation_date: date | None = EVAL,
) -> Ticket:
    """Call the service as an API handler would."""
    return await associate_cve(
        db,
        ticket_id=ticket_id,
        cve_id=cve_id,
        acting_user_id=actor.id,
        caller=TicketCaller.authenticated(actor.id, scope),
        evaluation_date=evaluation_date,
    )


def _assoc_event(actor: User, cve_id: str) -> EventRow:
    """The acting-user `cve_associated` event."""
    return EventRow("cve_associated", actor.id, None, cve_id, None, None)


class _Spy:
    """Wraps an async module function, recording each call's arguments."""

    def __init__(
        self, monkeypatch: pytest.MonkeyPatch, module: ModuleType, name: str
    ) -> None:
        self.calls: list[tuple[tuple[Any, ...], dict[str, Any]]] = []
        original = getattr(module, name)

        async def _wrapper(*args: Any, **kwargs: Any) -> Any:
            self.calls.append((args, kwargs))
            return await original(*args, **kwargs)

        monkeypatch.setattr(module, name, _wrapper)

    def reconciliations(self) -> list[tuple[uuid.UUID, date]]:
        """`(ticket id, evaluation_date)` of every recorded
        `reconcile_ticket_status()` call."""
        return [(args[0].id, kwargs["evaluation_date"]) for args, kwargs in self.calls]


class _TransactionGuard:
    """The service under test neither commits nor rolls back the caller's
    transaction: a commit raises; rollbacks are counted (the test itself
    performs the caller's rollback afterwards)."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch, session: AsyncSession) -> None:
        self.rollbacks = 0
        original_rollback = session.rollback

        async def commit() -> None:
            raise AssertionError("associate_cve() must not commit")

        async def rollback() -> None:
            self.rollbacks += 1
            await original_rollback()

        monkeypatch.setattr(session, "commit", commit)
        monkeypatch.setattr(session, "rollback", rollback)


async def _is_locked(probe: AsyncSession, statement: Select[Any]) -> bool:
    """Whether another transaction holds a conflicting lock on the row that
    `statement` selects (`FOR UPDATE NOWAIT`, released at once)."""
    try:
        await probe.execute(statement.with_for_update(nowait=True))
    except DBAPIError:
        await probe.rollback()
        return True
    await probe.rollback()
    return False


def _user_row(user: User) -> Select[Any]:
    return select(User.id).where(User.id == user.id)


def _ticket_row(ticket: Ticket) -> Select[Any]:
    return select(Ticket.id).where(Ticket.id == ticket.id)


def _cve_row(cve: CVE) -> Select[Any]:
    return select(CVE.id).where(CVE.id == cve.id)


def _is_user_share(statement: str) -> bool:
    return 'FROM "user"' in statement and "FOR SHARE" in statement


def _is_cve_lock(statement: str) -> bool:
    return "FROM cve " in statement and statement.rstrip().endswith("FOR UPDATE")


def _is_ticket_lock(statement: str) -> bool:
    return (
        TICKET_STATEMENT.search(statement) is not None
        and statement.lstrip().startswith("SELECT")
        and statement.rstrip().endswith("FOR UPDATE")
    )


def _touches_ticket(statements: list[str]) -> bool:
    return any(TICKET_STATEMENT.search(s) is not None for s in statements)


def _root_order(statements: list[str]) -> tuple[int, int, int]:
    """Indexes of the acting-User `FOR SHARE`, the first statement touching
    the CVE, and the first statement touching the Ticket."""

    def first(predicate: Callable[[str], bool]) -> int:
        return next(i for i, s in enumerate(statements) if predicate(s))

    return (
        first(_is_user_share),
        first(lambda s: CVE_STATEMENT.search(s) is not None),
        first(lambda s: TICKET_STATEMENT.search(s) is not None),
    )


def _writes(recorder: StatementRecorder) -> list[str]:
    """Every write except transaction-control statements."""
    return [
        w
        for w in recorder.writes()
        if not w.startswith(("SAVEPOINT", "RELEASE SAVEPOINT", "ROLLBACK"))
    ]


def _sql_dates(recorder: StatementRecorder) -> set[date]:
    """Every pure `date` bound in the recorded statements."""
    return {
        value
        for params in recorder.parameters
        for value in (params.values() if isinstance(params, dict) else params)
        if isinstance(value, date) and not isinstance(value, datetime)
    }


async def _sequence(db: AsyncSession, ticket_id: uuid.UUID) -> int:
    sequence = await db.scalar(select(Ticket.sequence_id).where(Ticket.id == ticket_id))
    await db.rollback()
    assert sequence is not None
    return sequence


async def _committed_state(
    db: AsyncSession, *, ticket_ids: list[uuid.UUID], actor_ids: list[uuid.UUID]
) -> tuple[list[tuple[Any, ...]], ...]:
    """Everything an association may change on the committed Tickets: every
    Ticket column, every Ticket audit event column, every Product
    occurrence column, and every event attributed to the actors on any
    Ticket. Read through the given (independent) session, which ends its
    read transaction afterwards."""
    tickets = (
        await db.execute(
            select(Ticket.__table__)
            .where(Ticket.id.in_(ticket_ids))
            .order_by(Ticket.id)
        )
    ).all()
    events = (
        await db.execute(
            select(TicketAuditEvent.__table__)
            .where(TicketAuditEvent.ticket_id.in_(ticket_ids))
            .order_by(TicketAuditEvent.id)
        )
    ).all()
    products = (
        await db.execute(
            select(TicketPackageProduct.__table__)
            .join(
                TicketPackageTrack,
                TicketPackageTrack.id == TicketPackageProduct.ticket_package_track_id,
            )
            .join(
                TicketPackage, TicketPackage.id == TicketPackageTrack.ticket_package_id
            )
            .where(TicketPackage.ticket_id.in_(ticket_ids))
            .order_by(TicketPackageProduct.id)
        )
    ).all()
    actor_events = (
        await db.execute(
            select(TicketAuditEvent.id).where(TicketAuditEvent.user_id.in_(actor_ids))
        )
    ).all()
    await db.rollback()
    return (
        [tuple(r) for r in tickets],
        [tuple(r) for r in events],
        [tuple(r) for r in products],
        [tuple(r) for r in actor_events],
    )


async def _cve_rows(db: AsyncSession, cve_id: str) -> list[tuple[Any, ...]]:
    """Every column of the CVE rows with this CVE-ID string."""
    rows = (await db.execute(select(CVE.__table__).where(CVE.cve_id == cve_id))).all()
    await db.rollback()
    return [tuple(r) for r in rows]


async def _cve_uuid(db: AsyncSession, cve_string: str) -> uuid.UUID:
    value = await db.scalar(select(CVE.id).where(CVE.cve_id == cve_string))
    await db.rollback()
    assert value is not None
    return value


async def _ticket_cve(db: AsyncSession, ticket: Ticket) -> uuid.UUID | None:
    value = await db.scalar(select(Ticket.cve_id).where(Ticket.id == ticket.id))
    await db.rollback()
    return value


async def _tickets_of(db: AsyncSession, cve_string: str) -> list[uuid.UUID]:
    rows = await db.scalars(
        select(Ticket.id)
        .join(CVE, Ticket.cve_id == CVE.id)
        .where(CVE.cve_id == cve_string)
    )
    result = list(rows.all())
    await db.rollback()
    return result


# ---------------------------------------------------------------------------
# ATR 9: association and manual CVSS mutation race
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _Race:
    """One ordering of `associate_cve()` against a manual SUSE CVSS mutation.

    `derived` is the severity the association resolves from the committed
    assessments it observes; `initial` is the Products' persisted
    eligibility before the race (every fixture Product flips on each
    recalculation: SUSE 9.8 makes both thresholds ineligible, the 10.0
    fallback makes both eligible)."""

    op: str
    first: str
    derived: Severity | None
    initial: bool

    @property
    def id(self) -> str:
        return f"{self.op}-{self.first}-first"


RACES = [
    # The upsert commits SUSE 9.8 first: the association observes it.
    _Race("upsert", "cvss", Severity.CRITICAL, True),
    # The association commits first on an assessment-less CVE (fallback).
    _Race("upsert", "association", None, False),
    # The delete commits first: the association observes an empty set.
    _Race("delete", "cvss", None, False),
    # The association commits first and observes the SUSE 9.8 assessment.
    _Race("delete", "association", Severity.CRITICAL, True),
]


def _association_events(
    race: _Race,
    actor: User,
    cve_string: str,
    manual: Severity | None,
    subjects: list[dict[str, str]],
) -> list[EventRow]:
    """The association's events on the unassigned `New` Ticket
    (ticket-service.md, `associate_cve` Audit events; ticket-audit-log.md,
    Cross-Event Ordering): assignment and its promotion, `cve_associated`,
    the system handover only when it changes value, the Product events in
    occurrence-ID order, the priority change, and the one final gate event."""
    events = [assignment_event(actor), PROMOTION, _assoc_event(actor, cve_string)]
    if manual is not race.derived:
        events.append(severity_event(label(manual), label(race.derived)))
    events += [product_event(s, race.initial, not race.initial) for s in subjects]
    if PRIORITY[manual] != PRIORITY[race.derived]:
        events.append(priority_event(PRIORITY[manual], PRIORITY[race.derived]))
    if race.derived is not None:
        events.append(
            status_event(TicketStatus.ANALYSIS.value, TicketStatus.RESOLVED.value)
        )
    return events


def _cvss_events(
    race: _Race, actor: User, subjects: list[dict[str, str]]
) -> list[EventRow]:
    """The events of the CVSS mutation that runs after the association on
    the associated Ticket: its own direct audit and propagation (no
    assignment: the Ticket is assigned)."""
    if race.op == "upsert":
        events = [
            cvss_event(actor, None, V31_CRITICAL),
            severity_event(None, "Critical"),
        ]
        events += [product_event(s, not race.initial, race.initial) for s in subjects]
        events += [
            priority_event(None, "P2"),
            status_event(TicketStatus.ANALYSIS.value, TicketStatus.RESOLVED.value),
        ]
        return events
    events = [
        cvss_delete_event(actor, V31_CRITICAL),
        severity_event("Critical", None),
    ]
    events += [product_event(s, not race.initial, race.initial) for s in subjects]
    events += [
        priority_event("P2", None),
        status_event(TicketStatus.RESOLVED.value, TicketStatus.ANALYSIS.value),
    ]
    return events


async def _cvss(
    session: AsyncSession, race: _Race, cve: CVE, actor: User
) -> ticket_mutations.CVSSAssessmentMutationResult:
    """The manual SUSE mutation of the race, with its own evaluation date."""
    if race.op == "upsert":
        return await upsert(
            session,
            cve.id,
            V31_CRITICAL.canonical,
            actor,
            evaluation_date=EVAL_CVSS,
        )
    return await delete_assessment(
        session, cve.id, V31_CRITICAL.version, actor, evaluation_date=EVAL_CVSS
    )


@pytest.mark.integration
class TestAssociationAndCVSSRace:
    """Architectural Test Requirement 9 for both manual CVSS mutations and
    both orderings. Two different acting VAs use independent sessions; the
    first mutation holds its User -> CVE (-> Ticket) locks uncommitted, the
    second must block on the CVE lock and, once the first commits, work from
    the committed state (ticket-service.md, `associate_cve` Locking)."""

    @pytest.mark.parametrize("manual_kind", ["handover-changes", "handover-equal"])
    @pytest.mark.parametrize("race", [pytest.param(r, id=r.id) for r in RACES])
    async def test_serialized_outcome_of_both_orderings(
        self,
        world: _World,
        monkeypatch: pytest.MonkeyPatch,
        race: _Race,
        manual_kind: str,
    ) -> None:
        va1 = await world.user(role=Role.VULNERABILITY_ANALYST)  # associates
        va2 = await world.user(role=Role.VULNERABILITY_ANALYST)  # mutates CVSS
        cve = (
            await world.cve(V31_CRITICAL, severity=Severity.CRITICAL)
            if race.op == "delete"
            else await world.cve()
        )
        manual = Severity.MEDIUM if manual_kind == "handover-changes" else race.derived
        ticket = await world.ticket(
            cve_id=None,
            status=TicketStatus.NEW,
            severity_manual=manual,
            priority_auto=PRIORITY[manual],
        )
        # Creation order differs from occurrence-ID order.
        ids = sorted(uuid.uuid7() for _ in range(2))
        created_first = await world.affected_product(
            ticket,
            threshold=T99,
            eligible=race.initial,
            occurrence_id=ids[1],
            package_name="fictional-race-b1",
        )
        created_second = await world.affected_product(
            ticket,
            threshold=T100,
            eligible=race.initial,
            occurrence_id=ids[0],
            package_name="fictional-race-b2",
        )
        subjects = [created_second, created_first]
        a = await world.open_session()
        b = await world.open_session()
        chain = _Spy(monkeypatch, ticket_service, "recalculate_cvss_chain")
        assigned = _Spy(monkeypatch, ticket_service, "auto_assign_actor")
        reconciled = _Spy(monkeypatch, ticket_service, "reconcile_ticket_status")
        cvss_reconciled = _Spy(monkeypatch, ticket_mutations, "reconcile_ticket_status")

        with (
            SessionStatementRecorder(a) as association,
            SessionStatementRecorder(b) as mutation,
        ):
            if race.first == "cvss":
                cvss_result = await _cvss(b, race, cve, va2)
                task = world.start(
                    a, _associate(a, ticket.id, cve.cve_id, va1, evaluation_date=EVAL)
                )
                await assert_blocked(task)
                blocked = list(association.statements)
                # User lock first, then waiting on the CVE lock; no Ticket
                # lock is held or requested while waiting.
                assert _is_user_share(blocked[0])
                assert _is_cve_lock(blocked[-1])
                assert not _touches_ticket(blocked)
                assert await _is_locked(world.probe, _user_row(va1)) is True
                assert await _is_locked(world.probe, _ticket_row(ticket)) is False
                await b.commit()
                await asyncio.wait_for(task, timeout=5)
                await a.commit()
            else:
                await _associate(a, ticket.id, cve.cve_id, va1, evaluation_date=EVAL)
                mutation_task = world.start(b, _cvss(b, race, cve, va2))
                await assert_blocked(mutation_task)
                blocked = list(mutation.statements)
                assert _is_user_share(blocked[0])
                assert _is_cve_lock(blocked[-1])
                assert not _touches_ticket(blocked)
                assert await _is_locked(world.probe, _user_row(va2)) is True
                await a.commit()
                cvss_result = await asyncio.wait_for(mutation_task, timeout=5)
                await b.commit()

        # User -> CVE -> Ticket on both manual paths; the first Ticket
        # statement is its `FOR UPDATE` lock.
        for statements in (association.statements, mutation.statements):
            user_lock, cve_lock, ticket_lock = _root_order(statements)
            assert user_lock < cve_lock < ticket_lock
            assert _is_ticket_lock(statements[ticket_lock])

        # Committed-current outcome, observed by an independent session.
        probe = world.probe
        expected = _association_events(race, va1, cve.cve_id, manual, subjects)
        if race.first == "association":
            expected += _cvss_events(race, va2, subjects)
        assert await ticket_events_by_id(probe, ticket.id) == expected
        await probe.rollback()
        # After both mutations, whatever their order: SUSE 9.8 (upsert) or
        # the 10.0 fallback of an empty set (delete) decides every value.
        if race.op == "upsert":
            status, severity, priority = TicketStatus.RESOLVED, "Critical", "P2"
            eligible = False
            assessments = [unit("SUSE", V31_CRITICAL)]
        else:
            status, severity, priority = TicketStatus.ANALYSIS, None, None
            eligible = True
            assessments = []
        assert await ticket_state(probe, ticket.id) == (
            status,
            va1.id,
            priority,
            None,
            None,
        )
        assert await _ticket_cve(probe, ticket) == cve.id
        assert await cve_severity(probe, cve.id) == severity
        assert await eligibility(probe, ticket.id) == [(eligible, False)] * 2
        assert await persisted_assessments(probe, cve.id) == assessments
        await probe.rollback()

        # No second assignment: one event, and the association's actor stays.
        assert [e for e in expected if e.event_type == "assignment"] == [
            assignment_event(va1)
        ]
        assert len(assigned.calls) == 1

        # One shared evaluation date per operation and one final
        # reconciliation each; the chain performs neither assignment nor
        # reconciliation.
        assert [
            (
                c[1]["mode"],
                c[1]["association_previous_severity"],
                c[1]["evaluation_date"],
            )
            for c in chain.calls
        ] == [(CVSSChainMode.ASSOCIATION, manual, EVAL)]
        assert reconciled.reconciliations() == [(ticket.id, EVAL)]
        assert _sql_dates(association) == {EVAL}
        assert cvss_result.evaluation_date == EVAL_CVSS
        if race.first == "association":
            assert cvss_reconciled.reconciliations() == [(ticket.id, EVAL_CVSS)]
            assert cvss_result.reconciled is True
            assert cvss_result.assigned is False
            assert cvss_result.propagation is CVSSPropagation.IMMEDIATE
            assert _sql_dates(mutation) == {EVAL_CVSS}
        else:
            # The mutation ran on the ticketless CVE: nothing on the Ticket.
            assert cvss_reconciled.calls == []
            assert cvss_result.reconciled is False
            assert cvss_result.propagation is CVSSPropagation.NOT_APPLICABLE


# ---------------------------------------------------------------------------
# D2 extra race: association against association
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestAssociationRaces:
    @pytest.mark.parametrize("cve_kind", ["existing", "placeholder"])
    async def test_two_tickets_one_cve_serialize_and_the_loser_has_no_effect(
        self, world: _World, monkeypatch: pytest.MonkeyPatch, cve_kind: str
    ) -> None:
        """The CVE lock (or the placeholder key) serializes the callers; the
        loser's association read under the lock observes the winner and raises
        `TicketCVEConflictError` with the winner's `SNTL-{n}`, having written
        nothing but, at most, its no-op placeholder INSERT."""
        winner_actor = await world.user(role=Role.VULNERABILITY_ANALYST)
        loser_actor = await world.user(role=Role.VULNERABILITY_ANALYST)
        cve_string = (
            (await world.cve()).cve_id if cve_kind == "existing" else world.new_cve_id()
        )
        winner_ticket = await world.ticket(cve_id=None, status=TicketStatus.NEW)
        loser_ticket = await world.ticket(
            cve_id=None,
            status=TicketStatus.NEW,
            severity_manual=Severity.MEDIUM,
            priority_auto="P4",
        )
        await world.affected_product(loser_ticket, threshold=T99, eligible=False)
        before = await _committed_state(
            world.probe, ticket_ids=[loser_ticket.id], actor_ids=[loser_actor.id]
        )
        a = await world.open_session()
        b = await world.open_session()
        guard = _TransactionGuard(monkeypatch, b)
        winner_sequence = await _sequence(world.probe, winner_ticket.id)

        await _associate(a, winner_ticket.id, cve_string, winner_actor)
        with SessionStatementRecorder(b) as recorder:
            task = world.start(
                b, _associate(b, loser_ticket.id, cve_string, loser_actor)
            )
            await assert_blocked(task)
            # Waiting on the CVE root: no Ticket statement has been issued.
            assert _is_user_share(recorder.statements[0])
            assert not _touches_ticket(recorder.statements)
            await a.commit()
            with pytest.raises(TicketCVEConflictError) as raised:
                await asyncio.wait_for(task, timeout=5)

        assert raised.value.existing_ticket_id == f"SNTL-{winner_sequence}"
        assert guard.rollbacks == 0
        assert _touches_ticket(recorder.statements)
        assert [w.split(" (")[0] for w in _writes(recorder)] == (
            ["INSERT INTO cve"] if cve_kind == "placeholder" else []
        )
        assert pending_ticket_convergence_effects(b) == ()
        await b.rollback()

        assert (
            await _committed_state(
                world.probe,
                ticket_ids=[loser_ticket.id],
                actor_ids=[loser_actor.id],
            )
            == before
        )
        assert await _tickets_of(world.probe, cve_string) == [winner_ticket.id]
        assert len(await _cve_rows(world.probe, cve_string)) == 1
        assert await ticket_events_by_id(world.probe, winner_ticket.id) == [
            assignment_event(winner_actor),
            PROMOTION,
            _assoc_event(winner_actor, cve_string),
        ]
        await world.probe.rollback()

    @pytest.mark.parametrize("second_kind", ["existing", "placeholder"])
    @pytest.mark.parametrize("first_kind", ["existing", "placeholder"])
    async def test_one_ticket_two_cves_the_loser_leaves_no_placeholder(
        self,
        world: _World,
        monkeypatch: pytest.MonkeyPatch,
        first_kind: str,
        second_kind: str,
    ) -> None:
        """Different CVEs do not serialize on the CVE lock: the loser holds its
        own CVE, waits on the Ticket lock, then finds the Ticket associated
        (`TicketCVEAlreadySetError`, not a conflict). Its rollback leaves no
        placeholder CVE."""
        winner_actor = await world.user(role=Role.VULNERABILITY_ANALYST)
        loser_actor = await world.user(role=Role.VULNERABILITY_ANALYST)
        first_cve = await world.cve() if first_kind == "existing" else None
        second_cve = await world.cve() if second_kind == "existing" else None
        first_string = first_cve.cve_id if first_cve else world.new_cve_id()
        second_string = second_cve.cve_id if second_cve else world.new_cve_id()
        ticket = await world.ticket(
            cve_id=None,
            status=TicketStatus.NEW,
            severity_manual=Severity.MEDIUM,
            priority_auto="P4",
        )
        subject = await world.affected_product(ticket, threshold=T99, eligible=False)
        second_before = await _cve_rows(world.probe, second_string)
        a = await world.open_session()
        b = await world.open_session()
        guard = _TransactionGuard(monkeypatch, b)

        await _associate(a, ticket.id, first_string, winner_actor)
        with SessionStatementRecorder(b) as recorder:
            task = world.start(b, _associate(b, ticket.id, second_string, loser_actor))
            await assert_blocked(task)
            # The loser got past its own CVE root and waits for the Ticket.
            assert _is_user_share(recorder.statements[0])
            assert _is_ticket_lock(recorder.statements[-1])
            if second_cve is None:
                assert any(
                    s.startswith("INSERT INTO cve ") for s in recorder.statements
                )
            else:
                assert await _is_locked(world.probe, _cve_row(second_cve)) is True
            await a.commit()
            with pytest.raises(TicketCVEAlreadySetError) as raised:
                await asyncio.wait_for(task, timeout=5)

        assert not isinstance(raised.value, TicketCVEConflictError)
        assert guard.rollbacks == 0
        assert [w.split(" (")[0] for w in _writes(recorder)] == (
            ["INSERT INTO cve"] if second_kind == "placeholder" else []
        )
        assert pending_ticket_convergence_effects(b) == ()
        await b.rollback()

        winner_cve = await _cve_uuid(world.probe, first_string)
        assert await _ticket_cve(world.probe, ticket) == winner_cve
        assert await ticket_events_by_id(world.probe, ticket.id) == [
            assignment_event(winner_actor),
            PROMOTION,
            _assoc_event(winner_actor, first_string),
            severity_event("Medium", None),
            product_event(subject, False, True),
            priority_event("P4", None),
        ]
        assert (await ticket_state(world.probe, ticket.id))[1] == winner_actor.id
        # No surviving placeholder of the loser; an existing CVE untouched.
        assert await _cve_rows(world.probe, second_string) == second_before
        assert await _tickets_of(world.probe, second_string) == []
        await world.probe.rollback()

    async def test_unique_backstop_violation_escapes_untranslated(
        self, world: _World, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The association read under the CVE lock is forced to observe
        nothing (an injected invariant violation), so the association UPDATE
        hits `Ticket.cve_id UNIQUE`. The `IntegrityError` escapes as-is, is
        never translated into `TicketCVEConflictError`, and no statement
        follows it (ticket-service.md, `associate_cve` step 7; cve-service.md,
        CVE Upsert Serialization > Ticket creation winner)."""
        actor = await world.user(role=Role.VULNERABILITY_ANALYST)
        cve = await world.cve()
        existing = await world.ticket(cve_id=cve.id)
        ticket = await world.ticket(cve_id=None, status=TicketStatus.NEW)
        session = await world.open_session()
        original_execute = session.execute
        suppressed = 0

        async def execute(statement: Any, *args: Any, **kwargs: Any) -> Any:
            nonlocal suppressed
            if (
                isinstance(statement, Select)
                and [c.key for c in statement.selected_columns] == ["sequence_id"]
                and Ticket.__table__ in statement.get_final_froms()
            ):
                suppressed += 1
                statement = statement.where(false())
            return await original_execute(statement, *args, **kwargs)

        monkeypatch.setattr(session, "execute", execute)

        with (
            SessionStatementRecorder(session) as recorder,
            pytest.raises(IntegrityError) as raised,
        ):
            await _associate(session, ticket.id, cve.cve_id, actor)
        monkeypatch.undo()
        await session.rollback()

        assert suppressed == 1
        assert not isinstance(raised.value, TicketCVEConflictError)
        assert "cve_id" in str(raised.value.orig)
        assert recorder.statements[-1].startswith("UPDATE ticket ")
        assert await _tickets_of(world.probe, cve.cve_id) == [existing.id]
        assert await _ticket_cve(world.probe, ticket) is None
        assert await ticket_events_by_id(world.probe, ticket.id) == []
        await world.probe.rollback()


# ---------------------------------------------------------------------------
# ATR 15: locked-current accessibility (association part)
# ---------------------------------------------------------------------------


LOSSES = ["grant-revoked", "last-package-excluded", "confidentiality-set"]


@pytest.mark.integration
class TestLockedCurrentAccessibility:
    """Session A passes the preliminary locator check and holds the acting
    User and CVE locks; session B, holding the Ticket lock, commits the loss
    of A's only visibility path. A must be denied from the locked-current
    state with zero side effects (testing-strategy.md, Ticket
    Accessibility: Locked mutations; ticket-service.md, Caller category and
    Ticket accessibility)."""

    @pytest.mark.parametrize("cve_kind", ["existing", "placeholder"])
    @pytest.mark.parametrize("timing", ["while-waiting", "before-start"])
    @pytest.mark.parametrize("loss", LOSSES)
    async def test_visibility_lost_before_the_ticket_lock_is_ticket_not_found(
        self,
        world: _World,
        monkeypatch: pytest.MonkeyPatch,
        loss: str,
        timing: str,
        cve_kind: str,
    ) -> None:
        user = await world.user(role=Role.RESTRICTED_ANALYST)
        confidential = loss != "confidentiality-set"
        ticket = await world.ticket(
            cve_id=None,
            status=TicketStatus.NEW,
            is_confidential=confidential,
            severity_manual=Severity.MEDIUM,
            priority_auto="P4",
        )
        await world.affected_product(ticket, threshold=T99, eligible=False)
        # The caller's one visibility path, and the statements (lock first)
        # that remove it.
        lock = select(Ticket.id).where(Ticket.id == ticket.id).with_for_update()
        statements: list[Any]
        if loss == "grant-revoked":
            granter = await world.user(role=Role.VULNERABILITY_ANALYST)
            await world.grant(ticket, user, granter)
            statements = [
                lock,
                delete(TicketAccessGrant).where(
                    TicketAccessGrant.ticket_id == ticket.id
                ),
            ]
        elif loss == "last-package-excluded":
            package = await world.maintained_package(ticket, user)
            statements = [
                lock,
                update(TicketPackage)
                .where(TicketPackage.id == package.id)
                .values(deleted_at=datetime.now(UTC)),
            ]
        else:
            statements = [
                lock,
                update(Ticket)
                .where(Ticket.id == ticket.id)
                .values(is_confidential=True),
            ]
        existing = await world.cve() if cve_kind == "existing" else None
        cve_string = existing.cve_id if existing else world.new_cve_id()
        cve_before = await _cve_rows(world.probe, cve_string)
        caller = TicketCaller.authenticated(user.id, Scope.NON_CONFIDENTIAL)
        locator = f"SNTL-{await _sequence(world.probe, ticket.id)}"
        a = await world.open_session()
        b = await world.open_session()
        guard = _TransactionGuard(monkeypatch, a)
        assigned = _Spy(monkeypatch, ticket_service, "auto_assign_actor")
        chain = _Spy(monkeypatch, ticket_service, "recalculate_cvss_chain")
        reconciled = _Spy(monkeypatch, ticket_service, "reconcile_ticket_status")
        inner_reconciled = _Spy(
            monkeypatch, ticket_mutations, "reconcile_ticket_status"
        )
        propagated = _Spy(
            monkeypatch,
            ticket_mutations,
            "_propagate_automatic_product_eligibility",
        )

        # The preliminary delegated check passes.
        resolved = await resolve_ticket_locator(a, locator, caller)
        assert resolved.id == ticket.id
        for statement in statements:
            await b.execute(statement)
        with SessionStatementRecorder(a) as recorder:
            if timing == "while-waiting":
                task = world.start(
                    a,
                    _associate(
                        a, ticket.id, cve_string, user, scope=Scope.NON_CONFIDENTIAL
                    ),
                )
                await assert_blocked(task)
                # Holding the User and CVE locks, waiting on the Ticket lock.
                assert any(_is_user_share(s) for s in recorder.statements)
                assert _is_ticket_lock(recorder.statements[-1])
                if existing is not None:
                    assert await _is_locked(world.probe, _cve_row(existing)) is True
                await b.commit()
            else:
                await b.commit()
                task = world.start(
                    a,
                    _associate(
                        a, ticket.id, cve_string, user, scope=Scope.NON_CONFIDENTIAL
                    ),
                )
            before = await _committed_state(
                world.probe, ticket_ids=[ticket.id], actor_ids=[user.id]
            )
            with pytest.raises(TicketNotFoundError):
                await asyncio.wait_for(task, timeout=5)

        # The premise: the committed loss really removed the caller's access.
        with pytest.raises(TicketNotFoundError):
            await resolve_ticket_locator(world.probe, locator, caller)
        await world.probe.rollback()

        assert guard.rollbacks == 0
        assert (
            assigned.calls,
            chain.calls,
            reconciled.calls,
            inner_reconciled.calls,
            propagated.calls,
        ) == ([], [], [], [], [])
        assert pending_ticket_convergence_effects(a) == ()
        # Nothing was written but, for a placeholder CVE, its own INSERT.
        assert [w.split(" (")[0] for w in _writes(recorder)] == (
            ["INSERT INTO cve"] if cve_kind == "placeholder" else []
        )
        await a.rollback()

        after = await _committed_state(
            world.probe, ticket_ids=[ticket.id], actor_ids=[user.id]
        )
        assert after == before
        assert after[1] == []
        assert after[3] == []
        assert await ticket_events_by_id(world.probe, ticket.id) == []
        assert (await ticket_state(world.probe, ticket.id))[1] is None
        assert await _ticket_cve(world.probe, ticket) is None
        assert await eligibility(world.probe, ticket.id) == [(False, False)]
        # No surviving placeholder; an existing CVE untouched and unassociated.
        assert await _cve_rows(world.probe, cve_string) == cve_before
        assert await _tickets_of(world.probe, cve_string) == []
        await world.probe.rollback()


# ---------------------------------------------------------------------------
# Whole-chain rollback with an independent committed observer
# ---------------------------------------------------------------------------


EXISTING_EVENT_TYPES = [
    "assignment",
    "status_change",
    "cve_associated",
    "severity_changed",
    "product_eligibility_changed",
    "product_eligibility_changed",
    "priority_changed",
    "status_change",
]
"""The events of the rollback scenario with an existing CVE that carries a
SUSE 9.8 assessment, in order: assignment and its promotion, association,
handover, two Product events, priority, and the final gate event."""

PLACEHOLDER_EVENT_TYPES = EXISTING_EVENT_TYPES[:7]
"""The same scenario with a placeholder CVE (no assessment): the severity
resolves to `NULL`, so the gate stays `Analysis` and no final event exists."""

FAILURES: list[Any] = [
    pytest.param("settings", None, id="settings"),
    pytest.param("database", None, id="database"),
    pytest.param("eligibility", None, id="eligibility"),
    pytest.param("flush", "ticket-update", id="flush-ticket-update"),
    pytest.param("flush", "cve_associated", id="flush-cve-associated"),
    pytest.param("flush", "priority_changed", id="flush-priority"),
    pytest.param("reconciliation", None, id="reconciliation"),
]


@dataclass(slots=True)
class _Expectation:
    """The exception a rollback scenario expects, whether its injection
    point was reached, and the exception that actually escaped."""

    error_type: type[BaseException]
    reached: bool = False
    raised: BaseException | None = None


@dataclass(frozen=True, slots=True)
class _Scenario:
    actor: User
    ticket: Ticket
    cve_string: str
    subjects: list[dict[str, str]]
    expected_events: list[EventRow]
    expected_state: tuple[Any, ...]
    expected_eligible: bool


async def _scenario(world: _World, cve_kind: str) -> _Scenario:
    """An unassigned `New` Ticket with a manual severity and two automatic
    Products whose effective chain assigns, promotes, associates, hands the
    severity over, changes both Products, refreshes the priority, and (for
    an existing CVE with a SUSE assessment) reaches `Resolved`: SUSE 9.8 makes
    both Products ineligible, so no actionable track remains (tickets.md,
    Gates)."""
    actor = await world.user(role=Role.VULNERABILITY_ANALYST)
    existing = cve_kind == "existing"
    cve_string = (
        (await world.cve(V31_CRITICAL, severity=Severity.LOW)).cve_id
        if existing
        else world.new_cve_id()
    )
    ticket = await world.ticket(
        cve_id=None,
        status=TicketStatus.NEW,
        severity_manual=Severity.MEDIUM,
        priority_auto="P4",
    )
    ids = sorted(uuid.uuid7() for _ in range(2))
    first = await world.affected_product(
        ticket,
        threshold=T99,
        eligible=existing,
        occurrence_id=ids[1],
        package_name="fictional-race-b1",
    )
    second = await world.affected_product(
        ticket,
        threshold=T100,
        eligible=existing,
        occurrence_id=ids[0],
        package_name="fictional-race-b2",
    )
    subjects = [second, first]
    events = [
        assignment_event(actor),
        PROMOTION,
        _assoc_event(actor, cve_string),
        severity_event("Medium", "Critical" if existing else None),
        *[product_event(s, existing, not existing) for s in subjects],
        priority_event("P4", "P2" if existing else None),
    ]
    if existing:
        events.append(
            status_event(TicketStatus.ANALYSIS.value, TicketStatus.RESOLVED.value)
        )
    return _Scenario(
        actor=actor,
        ticket=ticket,
        cve_string=cve_string,
        subjects=subjects,
        expected_events=events,
        expected_state=(
            TicketStatus.RESOLVED if existing else TicketStatus.ANALYSIS,
            actor.id,
            "P2" if existing else None,
            None,
            None,
        ),
        expected_eligible=not existing,
    )


AUDIT_FAILURES: list[Any] = [
    pytest.param("existing", index, id=f"existing-audit-{index}-{event_type}")
    for index, event_type in enumerate(EXISTING_EVENT_TYPES, start=1)
] + [
    pytest.param("placeholder", index, id=f"placeholder-audit-{index}-{event_type}")
    for index, event_type in enumerate(PLACEHOLDER_EVENT_TYPES, start=1)
]


@pytest.mark.integration
class TestRollbackIsIndependentlyObservable:
    """An injected failure escapes unchanged, the service never commits, and
    an independent committed session proves that nothing persisted, neither
    while the failed transaction is still open nor after the caller's
    rollback: the association, the cleared manual severity, the assignment,
    the Products, the priority, the status, every event, and a placeholder
    CVE (ticket-service.md, `associate_cve`; ticket-audit-log.md, Testing
    Requirements 7 and 24). This is the one service-level rollback matrix;
    the endpoint module adds only the request-level injections."""

    async def _assert_nothing_persisted(
        self,
        world: _World,
        scenario: _Scenario,
        before: tuple[list[tuple[Any, ...]], ...],
        cve_before: list[tuple[Any, ...]],
    ) -> None:
        assert (
            await _committed_state(
                world.probe,
                ticket_ids=[scenario.ticket.id],
                actor_ids=[scenario.actor.id],
            )
            == before
        )
        assert await _cve_rows(world.probe, scenario.cve_string) == cve_before
        assert await _tickets_of(world.probe, scenario.cve_string) == []
        assert await _ticket_cve(world.probe, scenario.ticket) is None
        assert await ticket_state(world.probe, scenario.ticket.id) == (
            TicketStatus.NEW,
            None,
            "P4",
            None,
            Severity.MEDIUM.value,
        )
        assert await ticket_events_by_id(world.probe, scenario.ticket.id) == []
        assert (
            await eligibility(world.probe, scenario.ticket.id)
            == [(not scenario.expected_eligible, False)] * 2
        )
        await world.probe.rollback()

    async def _run(
        self,
        world: _World,
        monkeypatch: pytest.MonkeyPatch,
        cve_kind: str,
        error_type: type[BaseException],
        arm: Callable[[AsyncSession, _Expectation], Awaitable[None]],
    ) -> _Expectation:
        scenario = await _scenario(world, cve_kind)
        session = await world.open_session()
        before = await _committed_state(
            world.probe,
            ticket_ids=[scenario.ticket.id],
            actor_ids=[scenario.actor.id],
        )
        cve_before = await _cve_rows(world.probe, scenario.cve_string)
        guard = _TransactionGuard(monkeypatch, session)
        expectation = _Expectation(error_type)
        await arm(session, expectation)

        with pytest.raises(error_type) as raised:
            await _associate(
                session, scenario.ticket.id, scenario.cve_string, scenario.actor
            )
        expectation.raised = raised.value

        assert guard.rollbacks == 0
        assert pending_ticket_convergence_effects(session) == ()
        # The independent observer sees nothing while the failed transaction
        # is still open: no partial state was committed.
        await self._assert_nothing_persisted(world, scenario, before, cve_before)
        await session.rollback()
        await self._assert_nothing_persisted(world, scenario, before, cve_before)
        return expectation

    @pytest.mark.parametrize("cve_kind", ["existing", "placeholder"])
    @pytest.mark.parametrize(("failure", "position"), FAILURES)
    async def test_injected_failure_persists_nothing(
        self,
        world: _World,
        monkeypatch: pytest.MonkeyPatch,
        cve_kind: str,
        failure: str,
        position: str | None,
    ) -> None:
        injected = RuntimeError(f"injected {failure} failure")
        error_type: type[BaseException] = {
            "settings": RequiredSystemSettingMissingError,
            "database": DBAPIError,
        }.get(failure, RuntimeError)

        async def arm(session: AsyncSession, expectation: _Expectation) -> None:
            if failure == "settings":
                # Uncommitted in the caller's transaction, like the other
                # injections: the row is back after the caller's rollback.
                await session.execute(
                    delete(SystemSetting).where(
                        SystemSetting.key == "default_cvss_version"
                    )
                )
            elif failure == "database":
                original_refresh = ticket_mutations.refresh_priority_auto

                async def failing_refresh(db: AsyncSession, *, ticket: Ticket) -> bool:
                    await original_refresh(db, ticket=ticket)
                    expectation.reached = True
                    await db.execute(text("SELECT 1 / 0"))
                    raise AssertionError("unreachable")  # pragma: no cover

                monkeypatch.setattr(
                    ticket_mutations, "refresh_priority_auto", failing_refresh
                )
            elif failure == "eligibility":

                def failing_evaluate(**kwargs: Any) -> Any:
                    expectation.reached = True
                    raise injected

                monkeypatch.setattr(
                    ticket_mutations, "evaluate_product_eligibility", failing_evaluate
                )
            elif failure == "flush":
                original_flush = session.flush

                def pending() -> bool:
                    if position == "ticket-update":
                        return any(
                            isinstance(o, Ticket) and o.cve_id is not None
                            for o in session.dirty
                        )
                    return any(
                        isinstance(o, TicketAuditEvent) and o.event_type == position
                        for o in session.new
                    )

                async def failing_flush(*args: Any, **kwargs: Any) -> None:
                    if pending():
                        expectation.reached = True
                        raise injected
                    await original_flush(*args, **kwargs)

                monkeypatch.setattr(session, "flush", failing_flush)
            else:
                original_reconcile = reconcile_ticket_status

                async def failing_reconcile(*args: Any, **kwargs: Any) -> None:
                    await original_reconcile(*args, **kwargs)
                    expectation.reached = True
                    raise injected

                monkeypatch.setattr(
                    ticket_service, "reconcile_ticket_status", failing_reconcile
                )

        expectation = await self._run(world, monkeypatch, cve_kind, error_type, arm)

        # The exception reaches the caller unchanged.
        if failure == "settings":
            assert type(expectation.raised) is RequiredSystemSettingMissingError
        elif failure == "database":
            assert expectation.reached is True
            assert "division by zero" in str(expectation.raised)
        else:
            assert expectation.reached is True
            assert expectation.raised is injected

    @pytest.mark.parametrize(("cve_kind", "index"), AUDIT_FAILURES)
    async def test_audit_failure_at_each_event_position_persists_nothing(
        self,
        world: _World,
        monkeypatch: pytest.MonkeyPatch,
        cve_kind: str,
        index: int,
    ) -> None:
        injected = RuntimeError("injected audit failure")
        recorded: list[str] = []

        async def arm(session: AsyncSession, expectation: _Expectation) -> None:
            original_log = TicketAuditLog.log_event

            async def failing_log(*args: Any, **kwargs: Any) -> None:
                event_type: TicketAuditEventType = kwargs["event_type"]
                recorded.append(event_type.value)
                if len(recorded) == index:
                    expectation.reached = True
                    raise injected
                await original_log(*args, **kwargs)

            monkeypatch.setattr(TicketAuditLog, "log_event", failing_log)

        expectation = await self._run(world, monkeypatch, cve_kind, RuntimeError, arm)

        types = (
            EXISTING_EVENT_TYPES if cve_kind == "existing" else PLACEHOLDER_EVENT_TYPES
        )
        assert expectation.reached is True
        assert expectation.raised is injected
        # The scenario reaches exactly this position and no later event.
        assert recorded == types[:index]

    @pytest.mark.parametrize("cve_kind", ["existing", "placeholder"])
    async def test_unfailed_scenario_persists_everything_the_failures_roll_back(
        self, world: _World, cve_kind: str
    ) -> None:
        """Control for the rollback matrix: without an injected failure the
        same scenario, committed by the caller, changes every value the
        failures leave untouched."""
        scenario = await _scenario(world, cve_kind)
        session = await world.open_session()
        before = await _committed_state(
            world.probe,
            ticket_ids=[scenario.ticket.id],
            actor_ids=[scenario.actor.id],
        )

        await _associate(
            session, scenario.ticket.id, scenario.cve_string, scenario.actor
        )
        await session.commit()

        assert (
            await _committed_state(
                world.probe,
                ticket_ids=[scenario.ticket.id],
                actor_ids=[scenario.actor.id],
            )
            != before
        )
        assert await ticket_events_by_id(world.probe, scenario.ticket.id) == (
            scenario.expected_events
        )
        assert await ticket_state(world.probe, scenario.ticket.id) == (
            scenario.expected_state
        )
        assert (
            await eligibility(world.probe, scenario.ticket.id)
            == [(scenario.expected_eligible, False)] * 2
        )
        assert await _ticket_cve(world.probe, scenario.ticket) == await _cve_uuid(
            world.probe, scenario.cve_string
        )
        assert await _tickets_of(world.probe, scenario.cve_string) == [
            scenario.ticket.id
        ]
        await world.probe.rollback()
