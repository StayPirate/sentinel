"""Independent-session tests for `set_product_eligibility()`
(backend/app/services/package_service.py).

Owning specifications:

- docs/features/packages/package-service.md (`set_product_eligibility()`,
  including "After a concurrent winner commits, the waiting caller
  determines override action and audit old/new values from the reloaded
  locked state"; Consumer caller context and Ticket accessibility;
  Concurrency Control; Architectural Test Requirement bullets "Atomic
  consumer accessibility", "Concurrent direct mutations", and "Override
  metadata transitions").
- docs/features/tickets/ticket-mutations.md (`upsert_cvss_assessment()`,
  `delete_cvss_assessment()`: User `FOR SHARE`, CVE `FOR NO KEY UPDATE`,
  Ticket `FOR UPDATE`, override skip; Architectural Test Requirement
  bullets "Independent-session races" (CVSS/override; a Ticket-first
  mutation writing the Ticket more than once while a CVSS mutation holds
  the CVE root, no deadlock) and "Authority and audit").
- docs/conventions.md (Transaction and Locking: Cross-Domain Root Lock
  Order).
- docs/features/packages/package-model.md (Axis 2: Eligibility; Override
  Product Eligibility, Reset behavior).
- docs/features/tickets/ticket-audit-log.md (Testing Requirements 16, 21,
  23).
- docs/features/platform/testing-strategy.md (Concurrency Testing; Ticket
  Accessibility: Locked mutations).

The single-session behavior (metadata transitions, no-ops, reset matrix,
gate transitions, auto-assignment, audit payload, projection, nested
ownership, manual zone, shared date, and rollback) is covered by
`tests/test_services/test_set_product_eligibility.py` and
`tests/test_services/test_set_product_eligibility_scope.py`; this module
adds only what needs independent sessions:

- CVSS/override races in both orders, for a manual SUSE upsert and delete,
  for an override set and an override clear;
- a Ticket-first override that writes the Ticket more than once while a
  CVSS mutation holds the CVE root and waits for that Ticket;
- override/override winner and waiter serialization with truthful old
  values and true no-op waiters;
- locked-current accessibility races for a `non_confidential` caller;
- the acting-User `FOR SHARE` lock preceding the Ticket lock.

Every race serializes a winner that keeps its locks in an open transaction
and a waiter proven blocked (`assert_lock_wait`) on the lock. The fixture
Product threshold is `THRESHOLD` (9.0): the SUSE v3.1 medium score 4.8 is
below it, while the critical scores 9.8 and 10.0 and the 10.0 fallback
reach it (package-model.md, Axis 2: Eligibility, rules 3-5). Committed rows,
including the `default_cvss_version` setting the test schema lacks, are
deleted explicitly at teardown (testing-strategy.md, Concurrency Testing).
Expected values are transcribed from the specifications, never computed
with the module under test.
"""

from __future__ import annotations

import asyncio
import re
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable, Coroutine
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any

import pytest
from sqlalchemy import Select, delete, select, update
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import Role, Scope, Severity, TicketStatus
from app.core.exceptions import TicketNotFoundError
from app.core.identifiers import format_ticket_id
from app.models.cve import CVE
from app.models.cve_cvss_assessment import CVECVSSAssessment
from app.models.product import Product
from app.models.system_setting import SystemSetting
from app.models.ticket import Ticket
from app.models.ticket_package import TicketPackage
from app.models.ticket_package_product import TicketPackageProduct
from app.models.ticket_package_track import TicketPackageTrack
from app.models.user import User
from app.services.package_service import (
    MutationOutcome,
    ProductEligibilityResult,
    set_product_eligibility,
)
from app.services.ticket_audit_log import TicketAuditLog
from app.services.ticket_convergence_registry import (
    pending_ticket_convergence_effects,
)
from app.services.ticket_mutations import CVSSAssessmentMutationResult
from app.services.ticket_service import resolve_ticket_locator
from app.services.ticket_visibility import TicketCaller
from tests.support.cvss_chain import (
    CallCounter,
    eligibility,
    priority_event,
    product_event,
    severity_event,
    ticket_state,
)
from tests.support.database import assert_lock_wait
from tests.support.suse_cvss import (
    V31_CRITICAL,
    V31_CRITICAL_10,
    V31_MEDIUM,
    Vector,
    assignment_event,
    cvss_delete_event,
    cvss_event,
    delete_assessment,
    upsert,
)
from tests.support.suse_cvss_races import (
    CommittedWorld,
    SessionStatementRecorder,
    prepare_loss,
)
from tests.support.ticket_mutations import (
    AFTER_EVAL,
    EVAL,
    EventRow,
    status_event,
    ticket_events_by_id,
)
from tests.support.track_status import Spy

Factory = Callable[[], Awaitable[AsyncSession]]

TICKET_STATEMENT = re.compile(r"\b(?:FROM|JOIN|INTO|UPDATE) ticket\b")
USER_STATEMENT = re.compile(r'\b(?:FROM|JOIN|UPDATE) "user"')
WAIT = 5
"""Upper bound, in seconds, of every wait that is expected to finish."""

PACKAGE_NAME = "fictional-override-race"
DEFAULT_VERSION = "3.1"
THRESHOLD = Decimal("9.0")
"""The fixture Product threshold (see the module docstring)."""

OPERATIONS = ["upsert", "delete"]
"""The manual SUSE CVSS mutation racing with the override: an upsert of
the SUSE v3.1 row or the delete of that default-version row."""

ANALYSIS = TicketStatus.ANALYSIS.value
ANALYZED = TicketStatus.ANALYZED.value
RESOLVED = TicketStatus.RESOLVED.value


# ---------------------------------------------------------------------------
# Committed world
# ---------------------------------------------------------------------------


class _World(CommittedWorld):
    """A `CommittedWorld` that also owns the committed `default_cvss_version`
    setting (the test schema has none), which an override clear reads."""

    def __init__(self, factory: Factory, session: AsyncSession) -> None:
        super().__init__(factory, session)
        self._owns_setting = False

    async def ensure_default_setting(self) -> None:
        if await self.session.get(SystemSetting, "default_cvss_version") is None:
            self.session.add(
                SystemSetting(key="default_cvss_version", value=DEFAULT_VERSION)
            )
            self._owns_setting = True
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
        await created.ensure_default_setting()
        yield created
    finally:
        await created.cleanup()


@dataclass(frozen=True, slots=True)
class _Occurrence:
    """One committed Product occurrence with its declared path and its
    event-time Product subject (ticket-audit-log.md, detail JSONB Schema
    Contract: `product_eligibility_changed`)."""

    ticket_id: uuid.UUID
    package_id: uuid.UUID
    track_id: uuid.UUID
    id: uuid.UUID
    subject: dict[str, str]


async def _occurrence(
    world: CommittedWorld, ticket: Ticket, *, eligible: bool, override: bool = False
) -> _Occurrence:
    """Commit one `AFFECTED` track with one in-support Product occurrence
    (threshold `THRESHOLD`) under the Ticket's existing package, or under a
    new `PACKAGE_NAME` package when the Ticket has none. Rows are owned by
    the world."""
    session = world.session
    package = (
        await session.execute(
            select(TicketPackage).where(TicketPackage.ticket_id == ticket.id)
        )
    ).scalar_one_or_none()
    if package is None:
        package = TicketPackage(ticket_id=ticket.id, package_name=PACKAGE_NAME)
        session.add(package)
        await session.flush()
    suffix = uuid.uuid4().hex[:10]
    product = Product(
        name=f"Example Product {suffix}",
        version="1",
        display_name=f"EP {suffix}",
        cpe=f"cpe:/o:example:product:{suffix}",
        catalog_last_seen_at=datetime.now(UTC),
        cvss_threshold=THRESHOLD,
        general_support_end_date=AFTER_EVAL,
    )
    track = TicketPackageTrack(
        ticket_package_id=package.id,
        workflow_type="ibs",
        reference=f"Example:Codestream:{suffix}:Update",
        status="AFFECTED",
    )
    session.add_all([product, track])
    await session.flush()
    world.product_ids.append(product.id)
    occurrence = TicketPackageProduct(
        ticket_package_track_id=track.id,
        product_id=product.id,
        eligible=eligible,
        is_eligible_override=override,
    )
    session.add(occurrence)
    await session.commit()
    return _Occurrence(
        ticket.id,
        package.id,
        track.id,
        occurrence.id,
        {
            "track": track.reference,
            "package": package.package_name,
            "product_name": product.display_name,
            "product_cpe": product.cpe,
        },
    )


# ---------------------------------------------------------------------------
# Calls and expected events
# ---------------------------------------------------------------------------


def _override(
    session: AsyncSession,
    occurrence: _Occurrence,
    eligible: bool | None,
    actor: User,
    *,
    occurrence_id: uuid.UUID | None = None,
    scope: Scope = Scope.ALL,
) -> Coroutine[Any, Any, ProductEligibilityResult]:
    """The service call as the API makes it, with the explicit declared
    path, so the call issues no statement before its own locks."""
    return set_product_eligibility(
        session,
        ticket_id=occurrence.ticket_id,
        package_id=occurrence.package_id,
        track_id=occurrence.track_id,
        ticket_package_product_id=(
            occurrence.id if occurrence_id is None else occurrence_id
        ),
        eligible=eligible,
        acting_user_id=actor.id,
        caller=TicketCaller.authenticated(actor.id, scope),
        evaluation_date=EVAL,
    )


def _cvss(
    session: AsyncSession, operation: str, cve: CVE, actor: User, vector: Vector
) -> Coroutine[Any, Any, CVSSAssessmentMutationResult]:
    """A manual SUSE upsert of `vector`, or the delete of the SUSE v3.1 row,
    as the CVSS handlers would call it."""
    if operation == "upsert":
        return upsert(
            session,
            cve.id,
            vector.canonical,
            actor,
            default_cvss_version=DEFAULT_VERSION,
        )
    return delete_assessment(
        session, cve.id, "3.1", actor, default_cvss_version=DEFAULT_VERSION
    )


def _value(eligible: bool) -> str:
    return "true" if eligible else "false"


def _override_event(
    occurrence: _Occurrence, actor: User, old: bool, new: bool, action: str
) -> EventRow:
    """The acting-user `product_eligibility_changed` with `va_override`."""
    return EventRow(
        "product_eligibility_changed",
        actor.id,
        _value(old),
        _value(new),
        None,
        {**occurrence.subject, "reason": "va_override", "override_action": action},
    )


def _chain_event(occurrence: _Occurrence, old: bool, new: bool) -> EventRow:
    """The system `product_eligibility_changed` of the CVSS chain."""
    return product_event({**occurrence.subject, "reason": "cvss"}, old, new)


def _direct_cvss_event(
    operation: str, actor: User, old: Vector, new: Vector
) -> EventRow:
    """The acting-user `cvss_assessment_changed` of the racing operation."""
    if operation == "upsert":
        return cvss_event(actor, old, new)
    return cvss_delete_event(actor, old)


def _sessions(spy: Spy, position: int) -> list[Any]:
    """The session argument of each recorded call."""
    return [args[position] for args, _kwargs in spy.calls]


def _is_user_share(statement: str) -> bool:
    return USER_STATEMENT.search(statement) is not None and statement.rstrip().endswith(
        "FOR SHARE"
    )


def _is_ticket_lock(statement: str) -> bool:
    return TICKET_STATEMENT.search(
        statement
    ) is not None and statement.rstrip().endswith("FOR UPDATE")


def _is_ticket_update(statement: str) -> bool:
    return statement.lstrip().startswith("UPDATE ticket ")


async def _is_locked(
    probe: AsyncSession, statement: Select[Any], *, key_share: bool = False
) -> bool:
    """Whether another transaction holds a lock on the selected row that
    conflicts with `FOR UPDATE NOWAIT`, or with `FOR NO KEY UPDATE NOWAIT`
    when `key_share` (released at once)."""
    try:
        await probe.execute(statement.with_for_update(nowait=True, key_share=key_share))
    except DBAPIError:
        await probe.rollback()
        return True
    await probe.rollback()
    return False


async def _cve_root_held(probe: AsyncSession, cve: CVE) -> bool:
    """Whether another transaction holds the CVE root: `FOR NO KEY UPDATE
    NOWAIT` conflicts with a CVE-root holder's `FOR NO KEY UPDATE` but not
    with the foreign-key `FOR KEY SHARE` of a Ticket UPDATE."""
    return await _is_locked(
        probe, select(CVE.id).where(CVE.id == cve.id), key_share=True
    )


@dataclass(frozen=True, slots=True)
class _Committed:
    """The committed Ticket `(status, assignee_id, priority_auto,
    priority_override, severity_manual)`, the `(eligible,
    is_eligible_override)` of its occurrences, and its audit events."""

    ticket: tuple[Any, ...]
    occurrences: list[tuple[bool, bool]]
    events: list[EventRow]


async def _committed(world: CommittedWorld, ticket: Ticket) -> _Committed:
    """The committed state, read through a fresh independent session."""
    probe = await world.open_session()
    committed = _Committed(
        await ticket_state(probe, ticket.id),
        await eligibility(probe, ticket.id),
        await ticket_events_by_id(probe, ticket.id),
    )
    await probe.rollback()
    return committed


async def _hold_user(session: AsyncSession, user: User) -> None:
    """A simulated identity lifecycle writer's `FOR NO KEY UPDATE` lock on
    the User row (the lock of deactivation and role-origin removal)."""
    await session.execute(
        select(User.id).where(User.id == user.id).with_for_update(key_share=True)
    )


class _PauseAfterFirstAuditEvent:
    """Pauses `session`'s workflow right after its first Ticket audit event
    returns, i.e. after the flush that wrote its first Ticket UPDATE, while
    it holds the Ticket lock. Other sessions pass through unchanged."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch, session: AsyncSession) -> None:
        self.paused = asyncio.Event()
        self.resume = asyncio.Event()
        original = TicketAuditLog.log_event

        async def _wrapper(db: AsyncSession, *args: Any, **kwargs: Any) -> None:
            await original(db, *args, **kwargs)
            if db is session and not self.paused.is_set():
                self.paused.set()
                await self.resume.wait()

        monkeypatch.setattr(TicketAuditLog, "log_event", _wrapper)


# ---------------------------------------------------------------------------
# CVSS/override races (ticket-mutations.md, Independent-session races)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestCVSSFirstThenOverride:
    """The manual SUSE CVSS mutation holds its User, CVE, and Ticket roots
    uncommitted; the override takes its acting User `FOR SHARE` and is
    proven blocked on the Ticket lock. After the CVSS mutation commits, the
    override decides its action and old value from the reloaded
    winner-current state (package-service.md, `set_product_eligibility()`
    Idempotency paragraph). Both transactions reconcile exactly once."""

    @pytest.mark.parametrize("operation", OPERATIONS)
    async def test_waiting_set_uses_the_cvss_winner_value_as_old_value(
        self, world: _World, monkeypatch: pytest.MonkeyPatch, operation: str
    ) -> None:
        """An unassigned `Resolved` Ticket with one automatic ineligible
        occurrence (SUSE v3.1 medium, 4.8). The upsert of v3.1 critical
        (9.8) or the delete of the v3.1 row (10.0 fallback) makes it
        automatically eligible with a system `reason = cvss` event from the
        pre-override automatic state and assigns the scorer. The waiting
        override `false` then records `set` with old value `true`, the
        winner-current value, not the stale identity-map `false`, and does
        not assign again."""
        scorer = await world.user(role=Role.VULNERABILITY_ANALYST)
        actor = await world.user(role=Role.VULNERABILITY_ANALYST)
        cve = await world.cve(V31_MEDIUM, severity=Severity.MEDIUM)
        ticket = await world.ticket(
            cve_id=cve.id, status=TicketStatus.RESOLVED, priority_auto="P4"
        )
        occurrence = await _occurrence(world, ticket, eligible=False)
        a = await world.open_session()
        b = await world.open_session()
        stale = await a.get(TicketPackageProduct, occurrence.id)
        assert stale is not None
        assert (stale.eligible, stale.is_eligible_override) == (False, False)
        override_reconcile = Spy(monkeypatch, "reconcile_ticket_status")
        chain_reconcile = CallCounter(monkeypatch, "reconcile_ticket_status")

        chain = await _cvss(b, operation, cve, scorer, V31_CRITICAL)
        with SessionStatementRecorder(a) as recorder:
            task = world.start(a, _override(a, occurrence, False, actor))
            await assert_lock_wait(task, waiter=a, blocked_by=b)
            assert _is_user_share(recorder.statements[0])
            assert _is_ticket_lock(recorder.statements[-1])
            await b.commit()
            result = await asyncio.wait_for(task, timeout=WAIT)
        await a.commit()

        upserted = operation == "upsert"
        assert (chain.products.changed, chain.products.override_skipped) == (1, 0)
        assert (chain.assigned, chain.reconciled) == (True, True)
        assert len(chain_reconcile.calls) == 1
        assert _sessions(override_reconcile, 1) == [a]
        assert result.outcome is MutationOutcome.CHANGED
        assert (result.product.eligible, result.product.is_eligible_override) == (
            False,
            True,
        )
        assert await _committed(world, ticket) == _Committed(
            (
                RESOLVED if upserted else ANALYSIS,
                scorer.id,
                "P2" if upserted else None,
                None,
                None,
            ),
            [(False, True)],
            [
                assignment_event(scorer),
                _direct_cvss_event(operation, scorer, V31_MEDIUM, V31_CRITICAL),
                severity_event("Medium", "Critical" if upserted else None),
                _chain_event(occurrence, False, True),
                priority_event("P4", "P2" if upserted else None),
                status_event(RESOLVED, ANALYZED if upserted else ANALYSIS),
                _override_event(occurrence, actor, True, False, "set"),
                # Without severity and SUSE the delete's Ticket stays in
                # Analysis: the override's reconciliation changes nothing.
                *([status_event(ANALYZED, RESOLVED)] if upserted else []),
            ],
        )

    @pytest.mark.parametrize("operation", OPERATIONS)
    async def test_waiting_clear_recalculates_from_the_winner_assessments(
        self, world: _World, monkeypatch: pytest.MonkeyPatch, operation: str
    ) -> None:
        """The waiting clear recalculates from the CVSS winner's committed
        assessment set, not from an identity-map copy it read earlier.
        Upsert: v3.1 critical (9.8) becomes v3.1 medium (4.8) under an
        eligible override, so the clear yields `false`. Delete: the only
        SUSE row (v3.1 medium, 4.8) is deleted under an ineligible
        override, so the clear falls back to 10.0 and yields `true`. The
        CVSS chain skips the override (no `reason = cvss` event)."""
        scorer = await world.user(role=Role.VULNERABILITY_ANALYST)
        actor = await world.user(role=Role.VULNERABILITY_ANALYST)
        upserted = operation == "upsert"
        initial = V31_CRITICAL if upserted else V31_MEDIUM
        severity = Severity.CRITICAL if upserted else Severity.MEDIUM
        cve = await world.cve(initial, severity=severity)
        ticket = await world.ticket(
            cve_id=cve.id,
            status=TicketStatus.ANALYZED if upserted else TicketStatus.RESOLVED,
            priority_auto="P2" if upserted else "P4",
        )
        occurrence = await _occurrence(world, ticket, eligible=upserted, override=True)
        a = await world.open_session()
        b = await world.open_session()
        stale = (
            (
                await a.execute(
                    select(CVECVSSAssessment).where(CVECVSSAssessment.cve_id == cve.id)
                )
            )
            .scalars()
            .all()
        )
        assert [(s.cvss_version, str(s.score)) for s in stale] == [
            ("3.1", initial.score)
        ]
        override_reconcile = Spy(monkeypatch, "reconcile_ticket_status")
        chain_reconcile = CallCounter(monkeypatch, "reconcile_ticket_status")

        chain = await _cvss(b, operation, cve, scorer, V31_MEDIUM)
        task = world.start(a, _override(a, occurrence, None, actor))
        await assert_lock_wait(task, waiter=a, blocked_by=b)
        await b.commit()
        result = await asyncio.wait_for(task, timeout=WAIT)
        await a.commit()

        assert (chain.products.changed, chain.products.override_skipped) == (0, 1)
        assert chain.assigned is True
        assert len(chain_reconcile.calls) == 1
        assert _sessions(override_reconcile, 1) == [a]
        assert result.outcome is MutationOutcome.CHANGED
        assert (result.product.eligible, result.product.is_eligible_override) == (
            not upserted,
            False,
        )
        final_state: tuple[Any, ...]
        if upserted:
            chain_events = [
                cvss_event(scorer, V31_CRITICAL, V31_MEDIUM),
                severity_event("Critical", "Medium"),
                priority_event("P2", "P4"),
                # The severity change reconciles; the override keeps the
                # track incomplete, so the Ticket stays Analyzed.
            ]
            override_events = [
                _override_event(occurrence, actor, True, False, "cleared"),
                status_event(ANALYZED, RESOLVED),
            ]
            final_state = (RESOLVED, scorer.id, "P4", None, None)
        else:
            chain_events = [
                cvss_delete_event(scorer, V31_MEDIUM),
                severity_event("Medium", None),
                priority_event("P4", None),
                status_event(RESOLVED, ANALYSIS),
            ]
            # Without severity and SUSE the Ticket stays in Analysis.
            override_events = [
                _override_event(occurrence, actor, False, True, "cleared")
            ]
            final_state = (ANALYSIS, scorer.id, None, None, None)
        assert await _committed(world, ticket) == _Committed(
            final_state,
            [(not upserted, False)],
            [assignment_event(scorer), *chain_events, *override_events],
        )


@pytest.mark.integration
class TestOverrideFirstThenCVSS:
    """The override holds the Ticket lock uncommitted; the manual SUSE CVSS
    mutation takes its User and CVE roots and is proven blocked on the
    Ticket lock while holding the CVE root. After the override commits, the
    CVSS chain recomputes from the committed override state."""

    @pytest.mark.parametrize("operation", OPERATIONS)
    async def test_waiting_cvss_chain_skips_the_committed_override(
        self, world: _World, monkeypatch: pytest.MonkeyPatch, operation: str
    ) -> None:
        """An unassigned `Analyzed` Ticket with one automatic eligible
        occurrence (v3.1 critical, 9.8). The override `false` assigns the
        actor and resolves the Ticket. The waiting upsert of v3.1 critical
        10.0 or delete of the v3.1 row (10.0 fallback) would make an
        automatic record eligible, but skips the override: no `reason =
        cvss` event, value unchanged, no second assignment. The upsert
        changes no gate input and does not reconcile; the delete removes
        severity and SUSE and reconciles once to Analysis."""
        scorer = await world.user(role=Role.VULNERABILITY_ANALYST)
        actor = await world.user(role=Role.VULNERABILITY_ANALYST)
        cve = await world.cve(V31_CRITICAL, severity=Severity.CRITICAL)
        ticket = await world.ticket(
            cve_id=cve.id, status=TicketStatus.ANALYZED, priority_auto="P2"
        )
        occurrence = await _occurrence(world, ticket, eligible=True)
        a = await world.open_session()
        b = await world.open_session()
        probe = await world.open_session()
        override_reconcile = Spy(monkeypatch, "reconcile_ticket_status")
        chain_reconcile = CallCounter(monkeypatch, "reconcile_ticket_status")

        result = await _override(a, occurrence, False, actor)
        task = world.start(b, _cvss(b, operation, cve, scorer, V31_CRITICAL_10))
        await assert_lock_wait(task, waiter=b, blocked_by=a)
        assert await _cve_root_held(probe, cve) is True
        await a.commit()
        chain = await asyncio.wait_for(task, timeout=WAIT)
        await b.commit()

        upserted = operation == "upsert"
        assert result.outcome is MutationOutcome.CHANGED
        assert (chain.products.examined, chain.products.override_skipped) == (1, 1)
        assert chain.products.changed == 0
        assert (chain.assigned, chain.reconciled) == (False, not upserted)
        assert len(chain_reconcile.calls) == (0 if upserted else 1)
        assert _sessions(override_reconcile, 1) == [a]
        chain_events = (
            [cvss_event(scorer, V31_CRITICAL, V31_CRITICAL_10)]
            if upserted
            else [
                cvss_delete_event(scorer, V31_CRITICAL),
                severity_event("Critical", None),
                priority_event("P2", None),
                status_event(RESOLVED, ANALYSIS),
            ]
        )
        assert await _committed(world, ticket) == _Committed(
            (
                RESOLVED if upserted else ANALYSIS,
                actor.id,
                "P2" if upserted else None,
                None,
                None,
            ),
            [(False, True)],
            [
                assignment_event(actor),
                _override_event(occurrence, actor, True, False, "set"),
                status_event(ANALYZED, RESOLVED),
                *chain_events,
            ],
        )

    @pytest.mark.parametrize("operation", OPERATIONS)
    async def test_waiting_cvss_chain_updates_the_cleared_occurrence(
        self, world: _World, monkeypatch: pytest.MonkeyPatch, operation: str
    ) -> None:
        """An eligible override under SUSE v3.1 medium (4.8) is cleared: it
        is recalculated to `false` from the pre-CVSS assessments and the
        Ticket resolves. The waiting upsert of v3.1 critical (9.8) or delete
        of the v3.1 row (10.0 fallback) then updates the now automatic
        occurrence with one system `reason = cvss` event `false -> true`
        (package-service.md, Override metadata transitions: clearing
        "permits later automatic CVSS mutation")."""
        scorer = await world.user(role=Role.VULNERABILITY_ANALYST)
        actor = await world.user(role=Role.VULNERABILITY_ANALYST)
        cve = await world.cve(V31_MEDIUM, severity=Severity.MEDIUM)
        ticket = await world.ticket(
            cve_id=cve.id, status=TicketStatus.ANALYZED, priority_auto="P4"
        )
        occurrence = await _occurrence(world, ticket, eligible=True, override=True)
        a = await world.open_session()
        b = await world.open_session()
        override_reconcile = Spy(monkeypatch, "reconcile_ticket_status")
        chain_reconcile = CallCounter(monkeypatch, "reconcile_ticket_status")

        result = await _override(a, occurrence, None, actor)
        task = world.start(b, _cvss(b, operation, cve, scorer, V31_CRITICAL))
        await assert_lock_wait(task, waiter=b, blocked_by=a)
        await a.commit()
        chain = await asyncio.wait_for(task, timeout=WAIT)
        await b.commit()

        upserted = operation == "upsert"
        assert result.outcome is MutationOutcome.CHANGED
        assert (result.product.eligible, result.product.is_eligible_override) == (
            False,
            False,
        )
        assert (chain.products.changed, chain.products.override_skipped) == (1, 0)
        assert (chain.assigned, chain.reconciled) == (False, True)
        assert len(chain_reconcile.calls) == 1
        assert _sessions(override_reconcile, 1) == [a]
        assert await _committed(world, ticket) == _Committed(
            (
                ANALYZED if upserted else ANALYSIS,
                actor.id,
                "P2" if upserted else None,
                None,
                None,
            ),
            [(True, False)],
            [
                assignment_event(actor),
                _override_event(occurrence, actor, True, False, "cleared"),
                status_event(ANALYZED, RESOLVED),
                _direct_cvss_event(operation, scorer, V31_MEDIUM, V31_CRITICAL),
                severity_event("Medium", "Critical" if upserted else None),
                _chain_event(occurrence, False, True),
                priority_event("P4", "P2" if upserted else None),
                status_event(RESOLVED, ANALYZED if upserted else ANALYSIS),
            ],
        )


@pytest.mark.integration
class TestTicketFirstOverrideAgainstCVSSHolder:
    """ticket-mutations.md, Independent-session races: "A Ticket-first
    mutation that writes a CVE-associated Ticket more than once completes
    and commits while a manual CVSS upsert or delete holds the CVE root and
    waits for that Ticket (no deadlock)"; conventions.md, Cross-Domain Root
    Lock Order (the CVE root is `FOR NO KEY UPDATE`, so the foreign-key
    `FOR KEY SHARE` of the second Ticket UPDATE stays compatible)."""

    @pytest.mark.parametrize("operation", OPERATIONS)
    async def test_override_on_a_new_ticket_completes_while_cvss_holds_the_cve(
        self, world: _World, monkeypatch: pytest.MonkeyPatch, operation: str
    ) -> None:
        """A VA overrides an automatic ineligible occurrence to `true` on an
        unassigned `New` Ticket: auto-assignment writes the Ticket, then
        `New -> Analysis` and the final `Analysis -> Analyzed` write it
        again. The override pauses after its first Ticket UPDATE; the CVSS
        mutation then locks the CVE and waits for the Ticket. The override
        resumes, writes the Ticket again, and commits without a deadlock;
        the CVSS mutation then applies from the committed winner, skips the
        override, and does not assign again."""
        scorer = await world.user(role=Role.VULNERABILITY_ANALYST)
        actor = await world.user(role=Role.VULNERABILITY_ANALYST)
        cve = await world.cve(V31_MEDIUM, severity=Severity.MEDIUM)
        ticket = await world.ticket(
            cve_id=cve.id, status=TicketStatus.NEW, priority_auto="P4"
        )
        occurrence = await _occurrence(world, ticket, eligible=False)
        a = await world.open_session()
        b = await world.open_session()
        probe = await world.open_session()
        pause = _PauseAfterFirstAuditEvent(monkeypatch, a)

        with SessionStatementRecorder(a) as recorder:
            first = world.start(a, _override(a, occurrence, True, actor))
            await asyncio.wait_for(pause.paused.wait(), timeout=WAIT)
            assert len([s for s in recorder.statements if _is_ticket_update(s)]) == 1
            assert await _cve_root_held(probe, cve) is False

            second = world.start(b, _cvss(b, operation, cve, scorer, V31_CRITICAL))
            await assert_lock_wait(second, waiter=b, blocked_by=a)
            assert await _cve_root_held(probe, cve) is True

            pause.resume.set()
            result = await asyncio.wait_for(first, timeout=WAIT)

        assert len([s for s in recorder.statements if _is_ticket_update(s)]) >= 2
        await assert_lock_wait(second, waiter=b, blocked_by=a)
        await a.commit()
        chain = await asyncio.wait_for(second, timeout=WAIT)
        await b.commit()

        upserted = operation == "upsert"
        assert result.outcome is MutationOutcome.CHANGED
        assert (chain.assigned, chain.reconciled) == (False, True)
        assert (chain.products.changed, chain.products.override_skipped) == (0, 1)
        chain_events = [
            _direct_cvss_event(operation, scorer, V31_MEDIUM, V31_CRITICAL),
            severity_event("Medium", "Critical" if upserted else None),
            priority_event("P4", "P2" if upserted else None),
            # The upsert's severity change reconciles to the unchanged
            # Analyzed; the delete loses severity and SUSE.
            *([] if upserted else [status_event(ANALYZED, ANALYSIS)]),
        ]
        assert await _committed(world, ticket) == _Committed(
            (
                ANALYZED if upserted else ANALYSIS,
                actor.id,
                "P2" if upserted else None,
                None,
                None,
            ),
            [(True, True)],
            [
                assignment_event(actor),
                status_event(TicketStatus.NEW.value, ANALYSIS),
                _override_event(occurrence, actor, False, True, "set"),
                status_event(ANALYSIS, ANALYZED),
                *chain_events,
            ],
        )


# ---------------------------------------------------------------------------
# Concurrent override/override (package-service.md, Concurrent direct
# mutations; audit Testing Requirement 23)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestOverrideSerialization:
    """Two active VAs change one occurrence of an unassigned CVE-less `High`
    Ticket (10.0 fallback: automatic `true`). The winner holds the Ticket
    lock uncommitted; the waiter holds a stale identity-map copy of the
    occurrence and is proven blocked on the Ticket lock. After the winner
    commits, the waiter classifies from the reloaded locked state."""

    async def _world(
        self, world: _World, *, eligible: bool, override: bool, status: TicketStatus
    ) -> tuple[User, User, Ticket, _Occurrence]:
        winner_actor = await world.user(role=Role.VULNERABILITY_ANALYST)
        waiter_actor = await world.user(role=Role.VULNERABILITY_ANALYST)
        ticket = await world.ticket(
            cve_id=None, severity_manual=Severity.HIGH, status=status
        )
        occurrence = await _occurrence(
            world, ticket, eligible=eligible, override=override
        )
        return winner_actor, waiter_actor, ticket, occurrence

    async def _race(
        self,
        world: _World,
        occurrence: _Occurrence,
        winner_value: bool | None,
        waiter_value: bool | None,
        winner_actor: User,
        waiter_actor: User,
    ) -> tuple[
        AsyncSession, AsyncSession, ProductEligibilityResult, SessionStatementRecorder
    ]:
        winner = await world.open_session()
        waiter = await world.open_session()
        stale = await waiter.get(TicketPackageProduct, occurrence.id)
        assert stale is not None

        await _override(winner, occurrence, winner_value, winner_actor)
        recorder = SessionStatementRecorder(waiter)
        with recorder:
            task = world.start(
                waiter, _override(waiter, occurrence, waiter_value, waiter_actor)
            )
            await assert_lock_wait(task, waiter=waiter, blocked_by=winner)
            assert _is_user_share(recorder.statements[0])
            assert _is_ticket_lock(recorder.statements[-1])
            await winner.commit()
            result = await asyncio.wait_for(task, timeout=WAIT)
        return winner, waiter, result, recorder

    async def test_waiting_change_uses_the_winner_value_as_old_value(
        self, world: _World
    ) -> None:
        """A sets `false` from automatic `true`; B, waiting with a stale
        `true`, sets `true`: B's event is `changed` with old `false`."""
        winner_actor, waiter_actor, ticket, occurrence = await self._world(
            world, eligible=True, override=False, status=TicketStatus.ANALYZED
        )

        _, waiter, result, _ = await self._race(
            world, occurrence, False, True, winner_actor, waiter_actor
        )
        await waiter.commit()

        assert result.outcome is MutationOutcome.CHANGED
        assert (result.product.eligible, result.product.is_eligible_override) == (
            True,
            True,
        )
        assert await _committed(world, ticket) == _Committed(
            (ANALYZED, winner_actor.id, None, None, "High"),
            [(True, True)],
            [
                assignment_event(winner_actor),
                _override_event(occurrence, winner_actor, True, False, "set"),
                status_event(ANALYZED, RESOLVED),
                _override_event(occurrence, waiter_actor, False, True, "changed"),
                status_event(RESOLVED, ANALYZED),
            ],
        )

    @pytest.mark.parametrize(
        ("eligible", "override", "status", "value"),
        [
            pytest.param(True, False, TicketStatus.ANALYZED, False, id="set-set"),
            pytest.param(False, True, TicketStatus.RESOLVED, None, id="clear-clear"),
        ],
    )
    async def test_waiter_observing_the_target_state_is_a_true_no_op(
        self,
        world: _World,
        monkeypatch: pytest.MonkeyPatch,
        eligible: bool,
        override: bool,
        status: TicketStatus,
        value: bool | None,
    ) -> None:
        """Both callers request the same state. `set-set`: A sets `false`
        from automatic `true`; B's `false` finds the override already
        `false`. `clear-clear`: A clears an ineligible override (10.0
        fallback: `true`); B's clear finds automatic management. B returns
        `no_op` with no write, assignment, event, reconciliation, or
        convergence registration."""
        winner_actor, waiter_actor, ticket, occurrence = await self._world(
            world, eligible=eligible, override=override, status=status
        )
        assign = Spy(monkeypatch, "auto_assign_actor")
        reconcile = Spy(monkeypatch, "reconcile_ticket_status")

        winner, waiter, result, recorder = await self._race(
            world, occurrence, value, value, winner_actor, waiter_actor
        )

        final = (False, True) if value is False else (True, False)
        assert result.outcome is MutationOutcome.NO_OP
        assert (result.product.eligible, result.product.is_eligible_override) == final
        assert recorder.writes() == []
        # `auto_assign_actor(ticket, acting_user, db)`,
        # `reconcile_ticket_status(ticket, db, ...)`.
        assert _sessions(assign, 2) == [winner]
        assert _sessions(reconcile, 1) == [winner]
        assert pending_ticket_convergence_effects(waiter) == ()
        await waiter.commit()
        winner_events = (
            [
                _override_event(occurrence, winner_actor, True, False, "set"),
                status_event(ANALYZED, RESOLVED),
            ]
            if value is False
            else [
                _override_event(occurrence, winner_actor, False, True, "cleared"),
                status_event(RESOLVED, ANALYZED),
            ]
        )
        assert await _committed(world, ticket) == _Committed(
            (
                RESOLVED if value is False else ANALYZED,
                winner_actor.id,
                None,
                None,
                "High",
            ),
            [final],
            [assignment_event(winner_actor), *winner_events],
        )

    async def test_waiting_clear_uses_the_winner_override_as_old_value(
        self, world: _World
    ) -> None:
        """A sets `false` from automatic `true`; B, waiting with a stale
        automatic copy, clears: B's event is `cleared` with old value
        `false` (A's value) and the recalculated `true`."""
        winner_actor, waiter_actor, ticket, occurrence = await self._world(
            world, eligible=True, override=False, status=TicketStatus.ANALYZED
        )

        _, waiter, result, _ = await self._race(
            world, occurrence, False, None, winner_actor, waiter_actor
        )
        await waiter.commit()

        assert result.outcome is MutationOutcome.CHANGED
        assert (result.product.eligible, result.product.is_eligible_override) == (
            True,
            False,
        )
        assert await _committed(world, ticket) == _Committed(
            (ANALYZED, winner_actor.id, None, None, "High"),
            [(True, False)],
            [
                assignment_event(winner_actor),
                _override_event(occurrence, winner_actor, True, False, "set"),
                status_event(ANALYZED, RESOLVED),
                _override_event(occurrence, waiter_actor, False, True, "cleared"),
                status_event(RESOLVED, ANALYZED),
            ],
        )


# ---------------------------------------------------------------------------
# Atomic consumer accessibility (mutation part): locked-current state
# ---------------------------------------------------------------------------


LOSSES = ["confidentiality-set", "grant-revoked", "last-package-excluded"]
"""The Ticket-scoped visibility losses of testing-strategy.md, Locked
mutations. `association-changed` is a CVE-path loss: this operation is
Ticket-scoped and the Ticket predicate does not depend on its CVE."""

REQUESTS = ["effective", "no-op", "wrong-occurrence", "ignored"]
"""`effective`: override `false` of an automatic eligible occurrence;
`no-op`: clear of an automatic occurrence; `wrong-occurrence`: the
effective request for a nonexistent occurrence; `ignored`: B also makes
the Ticket `Ignored` with the visibility loss."""


@pytest.mark.integration
class TestLockedCurrentAccessibilityRaces:
    """A `restricted_analyst` caller with effective scope `non_confidential`
    passes the preliminary locator check through exactly one visibility
    path. Session B then holds the Ticket `FOR UPDATE` and removes that
    path. A takes its acting User `FOR SHARE`, is proven blocked on the
    Ticket lock, B commits, and A must raise `TicketNotFoundError` from the
    locked-current state with zero side effects. No-op, nested-ownership,
    and operability decisions never precede the denial (testing-strategy.md,
    Ticket Accessibility: Locked mutations; package-service.md,
    `set_product_eligibility()` steps 2-5)."""

    @pytest.mark.parametrize("request_kind", REQUESTS)
    @pytest.mark.parametrize("loss", LOSSES)
    async def test_visibility_lost_while_waiting_for_the_lock_is_not_found(
        self,
        world: _World,
        monkeypatch: pytest.MonkeyPatch,
        loss: str,
        request_kind: str,
    ) -> None:
        user, _cve, ticket, statements = await prepare_loss(world, loss)
        # Under the maintained package for `last-package-excluded`: an
        # excluded occurrence remains mutable, so only the denial stops it.
        occurrence = await _occurrence(world, ticket, eligible=True)
        value = None if request_kind == "no-op" else False
        occurrence_id = uuid.uuid7() if request_kind == "wrong-occurrence" else None
        final_status = ANALYSIS
        if request_kind == "ignored":
            final_status = TicketStatus.IGNORED.value
            statements.append(
                update(Ticket)
                .where(Ticket.id == ticket.id)
                .values(status=TicketStatus.IGNORED.value)
            )
        a = await world.open_session()
        b = await world.open_session()
        caller = TicketCaller.authenticated(user.id, Scope.NON_CONFIDENTIAL)
        assign = Spy(monkeypatch, "auto_assign_actor")
        reconcile = Spy(monkeypatch, "reconcile_ticket_status")

        resolved = await resolve_ticket_locator(
            a, format_ticket_id(ticket.sequence_id), caller
        )
        assert resolved.id == ticket.id
        for statement in statements:
            await b.execute(statement)
        with SessionStatementRecorder(a) as recorder:
            task = world.start(
                a,
                _override(
                    a,
                    occurrence,
                    value,
                    user,
                    occurrence_id=occurrence_id,
                    scope=Scope.NON_CONFIDENTIAL,
                ),
            )
            await assert_lock_wait(task, waiter=a, blocked_by=b)
            assert _is_user_share(recorder.statements[0])
            assert _is_ticket_lock(recorder.statements[-1])
            await b.commit()
            with pytest.raises(TicketNotFoundError):
                await asyncio.wait_for(task, timeout=WAIT)

        assert recorder.writes() == []
        assert (assign.calls, reconcile.calls) == ([], [])
        assert pending_ticket_convergence_effects(a) == ()
        await a.rollback()
        assert await _committed(world, ticket) == _Committed(
            (final_status, None, None, None, None), [(True, False)], []
        )


# ---------------------------------------------------------------------------
# Lock order: acting User `FOR SHARE` before the Ticket `FOR UPDATE`
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestActingUserLockOrder:
    """package-service.md, `set_product_eligibility()` step 1 and
    Concurrency Control; conventions.md, Cross-Domain Root Lock Order."""

    @pytest.mark.parametrize("release", ["rollback", "deactivation-committed"])
    async def test_call_waits_for_a_lifecycle_writer_before_the_ticket_lock(
        self, world: _World, release: str
    ) -> None:
        """B holds the acting User `FOR NO KEY UPDATE`. A blocks on its
        `FOR SHARE` before requesting the Ticket lock, which an independent
        session can still take with `NOWAIT`. After B releases, A proceeds
        and decides auto-assignment from the locked-current User: a rolled
        back writer leaves an active VA that is assigned; a committed
        deactivation changes the occurrence without assignment
        (package-service.md, Auto-Assignment Rule)."""
        actor = await world.user(role=Role.VULNERABILITY_ANALYST)
        ticket = await world.ticket(
            cve_id=None, severity_manual=Severity.HIGH, status=TicketStatus.ANALYZED
        )
        occurrence = await _occurrence(world, ticket, eligible=True)
        a = await world.open_session()
        b = await world.open_session()
        probe = await world.open_session()

        await _hold_user(b, actor)
        with SessionStatementRecorder(a) as recorder:
            task = world.start(a, _override(a, occurrence, False, actor))
            await assert_lock_wait(task, waiter=a, blocked_by=b)
            assert _is_user_share(recorder.statements[-1])
            assert not any(TICKET_STATEMENT.search(s) for s in recorder.statements)
            assert not await _is_locked(
                probe, select(Ticket.id).where(Ticket.id == ticket.id)
            )
            if release == "rollback":
                await b.rollback()
            else:
                await b.execute(
                    update(User).where(User.id == actor.id).values(active=False)
                )
                await b.commit()
            result = await asyncio.wait_for(task, timeout=WAIT)
        assert _is_ticket_lock(
            next(s for s in recorder.statements if TICKET_STATEMENT.search(s))
        )
        await a.commit()

        assert result.outcome is MutationOutcome.CHANGED
        assigned = release == "rollback"
        assert await _committed(world, ticket) == _Committed(
            (RESOLVED, actor.id if assigned else None, None, None, "High"),
            [(False, True)],
            [
                *([assignment_event(actor)] if assigned else []),
                _override_event(occurrence, actor, True, False, "set"),
                status_event(ANALYZED, RESOLVED),
            ],
        )
