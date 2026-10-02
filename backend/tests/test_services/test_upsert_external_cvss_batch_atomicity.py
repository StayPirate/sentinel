"""Atomicity, evaluation-date, and independent-session tests for
`upsert_external_cvss_batch()` (backend/app/services/ticket_mutations.py).

Owning specifications:

- docs/features/tickets/ticket-mutations.md (CVSS Mutation Authority and
  Result: rollback of the complete chain; CVSS Status Matrix, trusted
  external batch column; `upsert_external_cvss_batch()`: Behavior 2-9 and
  the atomicity paragraph; `recalculate_cvss_chain()`: default-version
  mode and runner-facing classification; Architectural Test Requirement:
  Complete atomic chain, Serialized outcomes, Independent-session races
  (CVSS/CVSS, CVSS/override, CVSS/reactivation, default-version/CVSS, and
  a Ticket-first mutation writing the Ticket more than once while a CVSS
  root holder waits); Service Exceptions, last paragraphs).
- docs/features/tickets/cvss-scoring.md (Eligibility Score Resolution:
  external assessments never participate; Serialization and Concurrent
  Outcomes; Required Tests > Persistence and API Tests: two-session lock
  tests, including two external batches from distinct sources racing on
  the same CVE).
- docs/features/packages/package-service.md (`set_product_eligibility()`:
  the waiting caller decides from the reloaded locked state; Synchronous
  manual-zone-exit eligibility convergence: current committed CVE-owned
  state only, a system CVSS workflow follows CVE then Ticket).
- docs/features/packages/package-model.md (Override Model: automatic
  workflows skip overrides).
- docs/features/tickets/ticket-service.md (`_complete_manual_zone_exit()`,
  `reopen_from_ignored()`, `revert_duplicate()`).
- docs/features/tickets/ticket-audit-log.md (Testing Requirements 7, 16,
  20, 23, 24).
- docs/features/platform/testing-strategy.md (Rollback Within a Test;
  Concurrency Testing and Lock-Wait Observation; Parallel Execution).

The single-session behavior (guards, empty and all-unchanged batches,
status matrix, canonical order, propagation, gate, priority, lock order) is
covered by `tests/test_services/test_upsert_external_cvss_batch.py`.

External assessments never participate in the Eligibility Score
Resolution, so every Product change of a batch in this module is the
repair of a stale automatic value from the observed SUSE assessment,
setting, threshold, lifecycle, and override state, never a consequence of
the external vectors themselves.

The racing tests commit through independent sessions; committed rows,
including any non-SUSE assessments and the `default_cvss_version` setting
the test schema lacks (created, or changed and restored, by this module),
are deleted explicitly at teardown (testing-strategy.md, Concurrency
Testing). A waiter is proven blocked by observing its wait in PostgreSQL's
lock manager (`assert_lock_wait`); every other wait is bounded with
`asyncio.wait_for()`. Expected values are transcribed from the
specifications and the `Vector` constants, never computed with the module
under test.
"""

from __future__ import annotations

import asyncio
import re
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable, Coroutine
from dataclasses import dataclass
from datetime import UTC, date, datetime
from decimal import Decimal
from types import ModuleType
from typing import Any

import pytest
from sqlalchemy import Select, delete, select, text, update
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import (
    CVSSVersion,
    PackageStatus,
    Role,
    Scope,
    Severity,
    TicketAuditEventType,
    TicketStatus,
)
from app.core.identifiers import format_ticket_id
from app.models.cve import CVE
from app.models.product import Product
from app.models.system_setting import SystemSetting
from app.models.ticket import Ticket
from app.models.ticket_package import TicketPackage
from app.models.ticket_package_product import TicketPackageProduct
from app.models.ticket_package_track import TicketPackageTrack
from app.models.user import User
from app.services import package_service, ticket_mutations, ticket_service
from app.services.package_service import (
    MutationOutcome,
    ProductEligibilityResult,
    set_product_eligibility,
)
from app.services.product_eligibility import evaluate_product_eligibility
from app.services.settings import RequiredSystemSettingMissingError
from app.services.ticket_audit_log import TicketAuditLog
from app.services.ticket_convergence_registry import (
    TicketConvergenceEffect,
    pending_ticket_convergence_effects,
)
from app.services.ticket_mutations import (
    CVSSAssessmentAction,
    CVSSChainClassification,
    CVSSChainMode,
    CVSSChainResult,
    CVSSPropagation,
    ExternalCVSSAssessmentOutcome,
    ExternalCVSSBatchResult,
    ParsedExternalCVSSAssessment,
    ProductPropagationSummary,
    recalculate_cvss_chain,
)
from app.services.ticket_service import reopen_from_ignored, revert_duplicate
from app.services.ticket_visibility import TicketCaller
from tests.support.cvss_chain import (
    FALLBACK,
    CallCounter,
    cve_severity,
    eligibility,
    priority_event,
    product_event,
    severity_event,
    severity_resolution,
    subjects,
    suse_eligibility,
    ticket_state,
)
from tests.support.database import assert_lock_wait, rollback_test_scope
from tests.support.external_cvss import (
    external,
    external_cvss_event,
    external_value,
    run_batch,
)
from tests.support.suse_cvss import (
    V31_CRITICAL,
    V31_HIGH,
    V31_MEDIUM,
    V40_CRITICAL,
    Vector,
    assignment_event,
    persisted_assessments,
    unit,
)
from tests.support.suse_cvss_races import CommittedWorld, SessionStatementRecorder
from tests.support.ticket_mutations import (
    AFTER_EVAL,
    EVAL,
    EventRow,
    Prod,
    StatementRecorder,
    TicketFactory,
    TreeBuilder,
    VAUser,
    status_event,
    ticket_events,
    ticket_events_by_id,
    unassigned_event,
)

pytest_plugins = ["tests.support.ticket_mutation_fixtures"]
"""Provides the shared `va_user` and `tree` fixtures."""

Factory = Callable[..., Awaitable[Any]]
SessionFactory = Callable[[], Awaitable[AsyncSession]]
CVEOf = Callable[..., Awaitable[CVE]]
Batch = tuple[ParsedExternalCVSSAssessment, ...]

CREATED = CVSSAssessmentAction.CREATED
UPDATED = CVSSAssessmentAction.UPDATED
IMMEDIATE = CVSSPropagation.IMMEDIATE
DEFERRED = CVSSPropagation.DEFERRED_UNTIL_REACTIVATION
NO_PRODUCTS = ProductPropagationSummary()

NEW = TicketStatus.NEW.value
ANALYSIS = TicketStatus.ANALYSIS.value
ANALYZED = TicketStatus.ANALYZED.value
RESOLVED = TicketStatus.RESOLVED.value

DEFAULT_VERSION = "3.1"
"""The committed `default_cvss_version` of the racing tests, unless a test
changes it explicitly."""

SETTING_KEY = "default_cvss_version"

T4 = Decimal("4.0")
"""A Product threshold reached by the SUSE v3.1 medium score 4.8."""

T7 = Decimal("7.0")
"""A Product threshold reached by the `10.0` fallback."""

T9 = Decimal("9.0")
"""A Product threshold above the SUSE v3.1 medium score 4.8."""

T99 = Decimal("9.9")
"""A Product threshold above the SUSE v3.1 critical score 9.8 and below the
`10.0` fallback."""

WAIT = 5
"""Upper bound, in seconds, of every wait that is expected to finish."""

CVE_STATEMENT = re.compile(r"\b(?:FROM|JOIN|INTO|UPDATE) cve\b")
TICKET_STATEMENT = re.compile(r"\b(?:FROM|JOIN|INTO|UPDATE) ticket\b")
USER_STATEMENT = re.compile(r'\b(?:FROM|JOIN|UPDATE) "user"')


# ---------------------------------------------------------------------------
# Shared expectation helpers
# ---------------------------------------------------------------------------


def outcome(
    provider: str, version: CVSSVersion, action: CVSSAssessmentAction
) -> ExternalCVSSAssessmentOutcome:
    return ExternalCVSSAssessmentOutcome(
        provider=provider, version=version, action=action
    )


def created_event(provider: str, vector: Vector) -> EventRow:
    """The system `cvss_assessment_changed` of a created external row."""
    return external_cvss_event(None, external_value(provider, vector))


def updated_event(provider: str, old: Vector, new: Vector) -> EventRow:
    """The system `cvss_assessment_changed` of an updated external row."""
    return external_cvss_event(
        external_value(provider, old), external_value(provider, new)
    )


def _sql_dates(recorder: StatementRecorder) -> set[date]:
    """Every pure `date` bound in the recorded statements."""
    return {
        value
        for params in recorder.parameters
        for value in (params.values() if isinstance(params, dict) else params)
        if isinstance(value, date) and not isinstance(value, datetime)
    }


# ---------------------------------------------------------------------------
# Single-session fixtures (rollback and evaluation date)
# ---------------------------------------------------------------------------


@pytest.fixture
async def default_setting(system_setting_factory: Factory) -> SystemSetting:
    """The persisted `default_cvss_version` (the test schema has none)."""
    setting: SystemSetting = await system_setting_factory(
        key=SETTING_KEY, value=DEFAULT_VERSION
    )
    return setting


@pytest.fixture
def cve_of(cve_factory: Factory, cve_cvss_assessment_factory: Factory) -> CVEOf:
    """Create a CVE with a persisted `severity` and `(provider, vector)`
    assessments whose vector-derived units are consistent."""

    async def _create(
        *assessments: tuple[str, Vector], severity: Severity | None = None
    ) -> CVE:
        cve: CVE = await cve_factory(severity=severity.value if severity else None)
        for provider, vector in assessments:
            await cve_cvss_assessment_factory(
                cve_id=cve.id, provider_name=provider, **vector.columns()
            )
        return cve

    return _create


async def _stale_resolved_ticket(
    ticket_factory: TicketFactory, cve_of: CVEOf, tree: TreeBuilder, va_user: VAUser
) -> tuple[User, CVE, Ticket]:
    """A `Resolved` Ticket with an inactive assignee, `priority_auto = P4`,
    and two automatic ineligible Products (threshold 7.0) on an `AFFECTED`
    track; its CVE carries only the `Example CNA` v3.1 medium assessment
    and the converged `Medium` severity.

    `_mixed_batch()` then changes everything the rollback matrix checks:
    one updated and two created assessments; severity `Medium -> Critical`
    (the non-SUSE default-version step, `NVD` 9.8); both Products
    `false -> true` (no SUSE: the `10.0` fallback); priority `P4 -> P2`;
    and, without canonical SUSE, the `Analysis` floor, which sanitizes the
    inactive assignee and regresses `Resolved` (registering one
    convergence effect)."""
    inactive = await va_user(active=False)
    cve = await cve_of(("Example CNA", V31_MEDIUM), severity=Severity.MEDIUM)
    ticket = await ticket_factory(
        status=RESOLVED, cve_id=cve.id, assignee_id=inactive.id, priority_auto="P4"
    )
    await tree(
        ticket,
        status=PackageStatus.AFFECTED,
        products=(
            Prod(eligible=False, threshold=T7),
            Prod(eligible=False, threshold=T7),
        ),
    )
    return inactive, cve, ticket


def _mixed_batch() -> tuple[ParsedExternalCVSSAssessment, ...]:
    return (
        external("NVD", V31_CRITICAL),
        external("Example CNA", V31_HIGH),
        external("NVD", V40_CRITICAL),
    )


# ---------------------------------------------------------------------------
# Whole-chain rollback (audit Testing Requirements 7 and 24)
# ---------------------------------------------------------------------------


FAILURES = [
    "settings",
    "database",
    "eligibility",
    "audit",
    "flush",
    "reconciliation",
    "cancellation",
    "programming",
]


@pytest.mark.integration
class TestRollback:
    """ticket-mutations.md, `upsert_external_cvss_batch()` atomicity
    paragraph: every failure propagates unchanged and rolls back every
    assessment of the batch plus the caller's complete transaction."""

    @pytest.mark.parametrize("failure", FAILURES)
    async def test_failure_rolls_back_the_complete_chain(
        self,
        db_session: AsyncSession,
        default_setting: SystemSetting,
        ticket_factory: TicketFactory,
        cve_of: CVEOf,
        tree: TreeBuilder,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
        failure: str,
    ) -> None:
        inactive, cve, ticket = await _stale_resolved_ticket(
            ticket_factory, cve_of, tree, va_user
        )
        cve_id, ticket_id, inactive_id = cve.id, ticket.id, inactive.id
        expected_error: type[BaseException] = RuntimeError
        injected: BaseException | None = None
        reached = False

        async with rollback_test_scope(db_session):
            if failure == "settings":
                await db_session.delete(default_setting)
                await db_session.flush()
                expected_error = RequiredSystemSettingMissingError
            elif failure == "database":
                original_refresh = ticket_mutations.refresh_priority_auto

                async def failing_refresh(db: AsyncSession, *, ticket: Ticket) -> bool:
                    nonlocal reached
                    reached = await original_refresh(db, ticket=ticket)
                    await db.execute(text("SELECT 1 / 0"))
                    raise AssertionError("unreachable")  # pragma: no cover

                monkeypatch.setattr(
                    ticket_mutations, "refresh_priority_auto", failing_refresh
                )
                expected_error = DBAPIError
            elif failure == "eligibility":
                injected = RuntimeError("injected eligibility failure")
                evaluations = 0

                def failing_evaluate(**kwargs: Any) -> Any:
                    nonlocal reached, evaluations
                    evaluations += 1
                    # The first Product has already changed with its event.
                    if evaluations == 2:
                        reached = True
                        assert injected is not None
                        raise injected
                    return evaluate_product_eligibility(**kwargs)

                monkeypatch.setattr(
                    ticket_mutations, "evaluate_product_eligibility", failing_evaluate
                )
            elif failure == "audit":
                injected = RuntimeError("injected audit failure")
                original_log = TicketAuditLog.log_event

                async def failing_log(*args: Any, **kwargs: Any) -> None:
                    nonlocal reached
                    # After the assessment, severity, and Product events.
                    if kwargs["event_type"] is TicketAuditEventType.PRIORITY_CHANGED:
                        reached = True
                        assert injected is not None
                        raise injected
                    await original_log(*args, **kwargs)

                monkeypatch.setattr(TicketAuditLog, "log_event", failing_log)
            elif failure == "flush":
                injected = RuntimeError("injected flush failure")
                original_reconcile = ticket_mutations.reconcile_ticket_status
                original_flush = db_session.flush

                async def tracking_reconcile(*args: Any, **kwargs: Any) -> None:
                    nonlocal reached
                    await original_reconcile(*args, **kwargs)
                    reached = True

                async def failing_flush(*args: Any, **kwargs: Any) -> None:
                    if reached:
                        assert injected is not None
                        raise injected
                    await original_flush(*args, **kwargs)

                monkeypatch.setattr(
                    ticket_mutations, "reconcile_ticket_status", tracking_reconcile
                )
                monkeypatch.setattr(db_session, "flush", failing_flush)
            elif failure in ("reconciliation", "cancellation"):
                if failure == "reconciliation":
                    injected = RuntimeError("injected reconciliation failure")
                else:
                    injected = asyncio.CancelledError()
                    expected_error = asyncio.CancelledError
                original_reconcile = ticket_mutations.reconcile_ticket_status

                async def failing_reconcile(*args: Any, **kwargs: Any) -> None:
                    nonlocal reached
                    await original_reconcile(*args, **kwargs)
                    reached = True
                    assert injected is not None
                    raise injected

                monkeypatch.setattr(
                    ticket_mutations, "reconcile_ticket_status", failing_reconcile
                )
            else:
                injected = TypeError("injected programming error")
                expected_error = TypeError
                original_refresh = ticket_mutations.refresh_priority_auto

                async def broken_refresh(db: AsyncSession, *, ticket: Ticket) -> bool:
                    nonlocal reached
                    reached = await original_refresh(db, ticket=ticket)
                    assert injected is not None
                    raise injected

                monkeypatch.setattr(
                    ticket_mutations, "refresh_priority_auto", broken_refresh
                )

            with pytest.raises(expected_error) as raised:
                await run_batch(db_session, cve_id, *_mixed_batch())
        monkeypatch.undo()

        if injected is not None:
            assert raised.value is injected
        assert reached is (failure != "settings")
        assert await persisted_assessments(db_session, cve_id) == [
            unit("Example CNA", V31_MEDIUM)
        ]
        assert await cve_severity(db_session, cve_id) == "Medium"
        assert await eligibility(db_session, ticket_id) == [
            (False, False),
            (False, False),
        ]
        assert await ticket_state(db_session, ticket_id) == (
            RESOLVED,
            inactive_id,
            "P4",
            None,
            None,
        )
        assert await ticket_events_by_id(db_session, ticket_id) == []
        assert pending_ticket_convergence_effects(db_session) == ()

    async def test_unfailed_scenario_mutates_everything_the_failures_roll_back(
        self,
        db_session: AsyncSession,
        default_setting: SystemSetting,
        ticket_factory: TicketFactory,
        cve_of: CVEOf,
        tree: TreeBuilder,
        va_user: VAUser,
    ) -> None:
        """Control for the rollback matrix: without an injected failure the
        same scenario changes every asserted value."""
        inactive, cve, ticket = await _stale_resolved_ticket(
            ticket_factory, cve_of, tree, va_user
        )

        result = await run_batch(db_session, cve.id, *_mixed_batch())

        assert result == ExternalCVSSBatchResult(
            actions=(
                outcome("NVD", CVSSVersion.V4_0, CREATED),
                outcome("Example CNA", CVSSVersion.V3_1, UPDATED),
                outcome("NVD", CVSSVersion.V3_1, CREATED),
            ),
            severity_resolution=severity_resolution(
                "9.8", Severity.CRITICAL, provider="NVD"
            ),
            eligibility_resolution=FALLBACK,
            propagation=IMMEDIATE,
            products=ProductPropagationSummary(2, 0, 2),
            severity_changed=True,
            reconciled=True,
            evaluation_date=EVAL,
        )
        assert sorted(await persisted_assessments(db_session, cve.id)) == sorted(
            [
                unit("Example CNA", V31_HIGH),
                unit("NVD", V31_CRITICAL),
                unit("NVD", V40_CRITICAL),
            ]
        )
        assert await cve_severity(db_session, cve.id) == "Critical"
        assert await eligibility(db_session, ticket.id) == [
            (True, False),
            (True, False),
        ]
        assert await ticket_state(db_session, ticket.id) == (
            ANALYSIS,
            None,
            "P2",
            None,
            None,
        )
        detail = await subjects(db_session, ticket.id)
        assert await ticket_events(db_session, ticket) == [
            created_event("NVD", V40_CRITICAL),
            updated_event("Example CNA", V31_MEDIUM, V31_HIGH),
            created_event("NVD", V31_CRITICAL),
            severity_event("Medium", "Critical"),
            product_event(detail[0], False, True),
            product_event(detail[1], False, True),
            priority_event("P4", "P2"),
            unassigned_event(inactive.username, "inactive assignee"),
            status_event(RESOLVED, ANALYSIS),
        ]
        assert pending_ticket_convergence_effects(db_session) == (
            TicketConvergenceEffect(ticket.id),
        )


# ---------------------------------------------------------------------------
# One evaluation date
# ---------------------------------------------------------------------------


@pytest.mark.integration
@pytest.mark.usefixtures("default_setting")
class TestEvaluationDate:
    async def test_supplied_date_is_used_throughout_without_the_clock(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_of: CVEOf,
        tree: TreeBuilder,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The supplied date drives the Product lifecycle, the gate's
        actionability, reconciliation, and the result; the boundary never
        reads the clock, and every date bound in SQL is the supplied one."""

        def clock() -> datetime:
            raise AssertionError("the supplied evaluation date must be used")

        monkeypatch.setattr(ticket_mutations, "_utc_now", clock)
        reconcile = CallCounter(monkeypatch, "reconcile_ticket_status")
        propagate = CallCounter(monkeypatch, "_propagate_automatic_product_eligibility")
        _inactive, cve, _ticket = await _stale_resolved_ticket(
            ticket_factory, cve_of, tree, va_user
        )
        supplied = date(2026, 1, 2)

        with StatementRecorder(db_session) as recorder:
            result = await run_batch(
                db_session, cve.id, *_mixed_batch(), evaluation_date=supplied
            )

        assert result.evaluation_date == supplied
        assert (result.products, result.reconciled) == (
            ProductPropagationSummary(2, 0, 2),
            True,
        )
        assert [call["evaluation_date"] for call in propagate.calls] == [supplied]
        assert reconcile.calls == [{"evaluation_date": supplied}]
        assert _sql_dates(recorder) == {supplied}


# ---------------------------------------------------------------------------
# Committed world and race helpers
# ---------------------------------------------------------------------------


class _World(CommittedWorld):
    """A `CommittedWorld` that also owns the committed `default_cvss_version`
    setting (the test schema has none), read by the batch itself, the
    override clear, and the manual-zone-exit convergence. A row this world
    created is deleted at teardown; a pre-existing row is restored to its
    original value."""

    probe: AsyncSession
    """The independent session that observes committed state and probes
    locks."""

    def __init__(self, factory: SessionFactory, session: AsyncSession) -> None:
        super().__init__(factory, session)
        self._owns_setting = False
        self._original_setting: str | None = None

    async def ensure_default_setting(self) -> None:
        setting = await self.session.get(SystemSetting, SETTING_KEY)
        if setting is None:
            self.session.add(SystemSetting(key=SETTING_KEY, value=DEFAULT_VERSION))
            self._owns_setting = True
        else:
            self._original_setting = setting.value
            setting.value = DEFAULT_VERSION
        await self.session.commit()

    async def set_default_version(self, value: str) -> None:
        """Commit another setting value (restored or deleted at teardown)."""
        await self.session.execute(
            update(SystemSetting)
            .where(SystemSetting.key == SETTING_KEY)
            .values(value=value)
        )
        await self.session.commit()

    async def cleanup(self) -> None:
        await super().cleanup()
        if self._owns_setting:
            await self.session.execute(
                delete(SystemSetting).where(SystemSetting.key == SETTING_KEY)
            )
        elif self._original_setting is not None:
            await self.session.execute(
                update(SystemSetting)
                .where(SystemSetting.key == SETTING_KEY)
                .values(value=self._original_setting)
            )
        await self.session.commit()


@pytest.fixture
async def world(db_session_factory: SessionFactory) -> AsyncIterator[_World]:
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
    cve: CVE | None,
    status: str,
    duplicate_of: Ticket | None = None,
    assignee: User | None = None,
    priority_auto: str | None = None,
) -> Ticket:
    """A committed non-confidential Ticket, registered for cleanup."""
    ticket = Ticket(
        id=uuid.uuid7(),
        status=status,
        cve_id=cve.id if cve is not None else None,
        duplicate_of_id=duplicate_of.id if duplicate_of is not None else None,
        assignee_id=assignee.id if assignee is not None else None,
        priority_auto=priority_auto,
    )
    world.session.add(ticket)
    await world.session.flush()
    world.ticket_ids.append(ticket.id)
    await world.session.commit()
    return ticket


@dataclass(frozen=True, slots=True)
class _Occurrence:
    """One committed Product occurrence with its declared path and its
    event-time Product subject (ticket-audit-log.md, detail JSONB Schema
    Contract: `product_eligibility_changed`, without `reason`)."""

    ticket_id: uuid.UUID
    package_id: uuid.UUID
    track_id: uuid.UUID
    id: uuid.UUID
    subject: dict[str, str]


async def _product(
    world: CommittedWorld,
    ticket: Ticket,
    *,
    threshold: Decimal,
    eligible: bool,
    override: bool = False,
    occurrence_id: uuid.UUID | None = None,
) -> _Occurrence:
    """Commit one package with one `AFFECTED` track and one Product
    occurrence in General Support on `EVAL`; `occurrence_id` fixes the
    Product event ordering key. Rows are owned by the world."""
    session = world.session
    suffix = uuid.uuid4().hex[:10]
    product = Product(
        name=f"Example Product {suffix}",
        version="1",
        display_name=f"EP {suffix}",
        cpe=f"cpe:/o:example:product:{suffix}",
        catalog_last_seen_at=datetime.now(UTC),
        cvss_threshold=threshold,
        general_support_end_date=AFTER_EVAL,
    )
    package = TicketPackage(ticket_id=ticket.id, package_name=f"fictional-{suffix}")
    session.add_all([product, package])
    await session.flush()
    world.product_ids.append(product.id)
    track = TicketPackageTrack(
        ticket_package_id=package.id,
        workflow_type="ibs",
        reference=f"Example:Codestream:{suffix}:Update",
        status=PackageStatus.AFFECTED.value,
    )
    session.add(track)
    await session.flush()
    occurrence = TicketPackageProduct(
        ticket_package_track_id=track.id,
        product_id=product.id,
        eligible=eligible,
        is_eligible_override=override,
    )
    if occurrence_id is not None:
        occurrence.id = occurrence_id
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


def _chain_event(occurrence: _Occurrence, old: bool, new: bool) -> EventRow:
    """The system `product_eligibility_changed` of a CVSS chain."""
    return product_event({**occurrence.subject, "reason": "cvss"}, old, new)


def _value(eligible: bool) -> str:
    return "true" if eligible else "false"


def _reactivation_event(occurrence: _Occurrence, old: bool, new: bool) -> EventRow:
    """The system `product_eligibility_changed` of a manual-zone exit."""
    return EventRow(
        "product_eligibility_changed",
        None,
        _value(old),
        _value(new),
        None,
        {**occurrence.subject, "reason": "reactivation"},
    )


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


def _batch_result(
    actions: tuple[ExternalCVSSAssessmentOutcome, ...],
    severity: Any,
    *,
    eligibility_resolution: Any = FALLBACK,
    propagation: CVSSPropagation = IMMEDIATE,
    products: ProductPropagationSummary,
    severity_changed: bool,
    reconciled: bool,
) -> ExternalCVSSBatchResult:
    return ExternalCVSSBatchResult(
        actions=actions,
        severity_resolution=severity,
        eligibility_resolution=eligibility_resolution,
        propagation=propagation,
        products=products,
        severity_changed=severity_changed,
        reconciled=reconciled,
        evaluation_date=EVAL,
    )


class _Spy:
    """Wraps an async module attribute, recording the session (positional
    argument `index`) of every call; racing sessions share the module.

    Patching `ticket_mutations` observes only the calls made inside that
    module (the batch and the default-version unit): `ticket_service` and
    `package_service` call their own imported names."""

    def __init__(
        self, monkeypatch: pytest.MonkeyPatch, module: ModuleType, name: str, index: int
    ) -> None:
        self.sessions: list[AsyncSession] = []
        original = getattr(module, name)

        async def _wrapper(*args: Any, **kwargs: Any) -> Any:
            self.sessions.append(args[index])
            return await original(*args, **kwargs)

        monkeypatch.setattr(module, name, _wrapper)


class _BatchSpies:
    """The batch-side `ticket_mutations` calls: final reconciliation,
    immediate Product pass, and (never expected) auto-assignment."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.reconciled = _Spy(
            monkeypatch, ticket_mutations, "reconcile_ticket_status", 1
        )
        self.propagated = _Spy(
            monkeypatch, ticket_mutations, "_propagate_automatic_product_eligibility", 0
        )
        self.assigned = _Spy(monkeypatch, ticket_mutations, "auto_assign_actor", 2)


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


def _is_user_share(statement: str) -> bool:
    return USER_STATEMENT.search(statement) is not None and statement.rstrip().endswith(
        "FOR SHARE"
    )


def _is_ticket_update(statement: str) -> bool:
    return statement.lstrip().startswith("UPDATE ticket ")


def _assert_batch_locks(recorder: StatementRecorder) -> None:
    """The CVE `FOR NO KEY UPDATE` then the Ticket `FOR UPDATE` are the first
    two statements and the only row locks: no User lock."""
    statements = recorder.statements
    assert _is_cve_lock(statements[0])
    assert _is_ticket_lock(statements[1])
    assert recorder.row_locks() == statements[:2]


async def _is_locked(
    probe: AsyncSession, statement: Select[Any], *, key_share: bool = False
) -> bool:
    """Whether another transaction holds a conflicting lock on the selected
    row (`FOR UPDATE NOWAIT`, or `FOR NO KEY UPDATE NOWAIT` with
    `key_share`; released at once)."""
    try:
        await probe.execute(statement.with_for_update(nowait=True, key_share=key_share))
    except DBAPIError:
        await probe.rollback()
        return True
    await probe.rollback()
    return False


async def _cve_root_held(probe: AsyncSession, cve: CVE) -> bool:
    """Whether another transaction holds the CVE root: `FOR NO KEY UPDATE
    NOWAIT` conflicts with a root holder's `FOR NO KEY UPDATE` but not with
    the foreign-key `FOR KEY SHARE` of a Ticket write."""
    return await _is_locked(
        probe, select(CVE.id).where(CVE.id == cve.id), key_share=True
    )


@dataclass(frozen=True, slots=True)
class _Committed:
    """The committed Ticket `(status, assignee_id, priority_auto,
    priority_override, severity_manual)`, the `(eligible,
    is_eligible_override)` of its occurrences in occurrence-ID order, the
    CVE severity, the sorted persisted assessments, and the Ticket's
    audit events in insertion order."""

    ticket: tuple[Any, ...]
    occurrences: list[tuple[bool, bool]]
    severity: str | None
    assessments: list[tuple[str, str, Decimal, str, str]]
    events: list[EventRow]


async def _committed(world: _World, ticket: Ticket, cve: CVE) -> _Committed:
    """The committed state, read through the independent probe session."""
    probe = world.probe
    try:
        return _Committed(
            await ticket_state(probe, ticket.id),
            await eligibility(probe, ticket.id),
            await cve_severity(probe, cve.id),
            sorted(await persisted_assessments(probe, cve.id)),
            await ticket_events_by_id(probe, ticket.id),
        )
    finally:
        await probe.rollback()


# ---------------------------------------------------------------------------
# CVSS/CVSS: two external batches from distinct sources
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _Run:
    """The expected result and events of one serialized batch."""

    result: ExternalCVSSBatchResult
    events: list[EventRow]


@dataclass(frozen=True, slots=True)
class _BatchRace:
    first: tuple[ParsedExternalCVSSAssessment, ...]
    second: tuple[ParsedExternalCVSSAssessment, ...]
    winner: _Run
    waiter: _Run
    severity: str
    priority: str
    assessments: list[tuple[str, str, Decimal, str, str]]


def _batch_race(case: str, order: str, p: _Occurrence) -> _BatchRace:
    """The transcribed outcomes of each race.

    The CVE has no SUSE assessment: severity is the non-SUSE default-version
    (3.1) winner, by score, and eligibility the `10.0` fallback, so only the
    first serialized batch repairs the stale `false` Product and regresses
    the stale `Resolved` Ticket to the `Analysis` floor (no assignment
    anywhere). The waiter recomputes from the winner's committed rows:
    no Product event, and a final reconciliation only when its own
    severity changed.

    `distinct-keys`: an `NVD` feed batch (v4.0 critical 9.3, v3.1 high 8.1)
    and an `Example CNA` record batch (v3.1 critical 9.8).
    `shared-key`: the feed batch carries only `NVD` v3.1 high (8.1); the
    record batch carries `NVD` v3.1 critical (9.8) and `Example CNA` v4.0
    critical, so the waiter updates the winner's committed `NVD` v3.1 row.
    """
    regression = [_chain_event(p, False, True)]
    floor = status_event(RESOLVED, ANALYSIS)
    feed: Batch
    record: Batch
    if case == "distinct-keys":
        feed = (external("NVD", V31_HIGH), external("NVD", V40_CRITICAL))
        record = (external("Example CNA", V31_CRITICAL),)
        assessments = sorted(
            [
                unit("NVD", V31_HIGH),
                unit("NVD", V40_CRITICAL),
                unit("Example CNA", V31_CRITICAL),
            ]
        )
        feed_actions = (
            outcome("NVD", CVSSVersion.V4_0, CREATED),
            outcome("NVD", CVSSVersion.V3_1, CREATED),
        )
        record_actions = (outcome("Example CNA", CVSSVersion.V3_1, CREATED),)
        feed_events = [
            created_event("NVD", V40_CRITICAL),
            created_event("NVD", V31_HIGH),
        ]
        record_events = [created_event("Example CNA", V31_CRITICAL)]
        cna_critical = severity_resolution(
            "9.8", Severity.CRITICAL, provider="Example CNA"
        )
        if order == "feed-first":
            return _BatchRace(
                feed,
                record,
                _Run(
                    _batch_result(
                        feed_actions,
                        severity_resolution("8.1", Severity.HIGH, provider="NVD"),
                        products=ProductPropagationSummary(1, 0, 1),
                        severity_changed=True,
                        reconciled=True,
                    ),
                    [
                        *feed_events,
                        severity_event(None, "High"),
                        *regression,
                        priority_event(None, "P3"),
                        floor,
                    ],
                ),
                _Run(
                    _batch_result(
                        record_actions,
                        cna_critical,
                        products=ProductPropagationSummary(1, 0, 0),
                        severity_changed=True,
                        reconciled=True,
                    ),
                    [
                        *record_events,
                        severity_event("High", "Critical"),
                        priority_event("P3", "P2"),
                    ],
                ),
                "Critical",
                "P2",
                assessments,
            )
        return _BatchRace(
            record,
            feed,
            _Run(
                _batch_result(
                    record_actions,
                    cna_critical,
                    products=ProductPropagationSummary(1, 0, 1),
                    severity_changed=True,
                    reconciled=True,
                ),
                [
                    *record_events,
                    severity_event(None, "Critical"),
                    *regression,
                    priority_event(None, "P2"),
                    floor,
                ],
            ),
            # The record's 9.8 still wins: no severity, Product, priority,
            # or gate input changes, hence no reconciliation.
            _Run(
                _batch_result(
                    feed_actions,
                    cna_critical,
                    products=ProductPropagationSummary(1, 0, 0),
                    severity_changed=False,
                    reconciled=False,
                ),
                feed_events,
            ),
            "Critical",
            "P2",
            assessments,
        )

    feed = (external("NVD", V31_HIGH),)
    record = (external("NVD", V31_CRITICAL), external("Example CNA", V40_CRITICAL))
    if order == "feed-first":
        return _BatchRace(
            feed,
            record,
            _Run(
                _batch_result(
                    (outcome("NVD", CVSSVersion.V3_1, CREATED),),
                    severity_resolution("8.1", Severity.HIGH, provider="NVD"),
                    products=ProductPropagationSummary(1, 0, 1),
                    severity_changed=True,
                    reconciled=True,
                ),
                [
                    created_event("NVD", V31_HIGH),
                    severity_event(None, "High"),
                    *regression,
                    priority_event(None, "P3"),
                    floor,
                ],
            ),
            _Run(
                _batch_result(
                    (
                        outcome("Example CNA", CVSSVersion.V4_0, CREATED),
                        outcome("NVD", CVSSVersion.V3_1, UPDATED),
                    ),
                    severity_resolution("9.8", Severity.CRITICAL, provider="NVD"),
                    products=ProductPropagationSummary(1, 0, 0),
                    severity_changed=True,
                    reconciled=True,
                ),
                [
                    created_event("Example CNA", V40_CRITICAL),
                    updated_event("NVD", V31_HIGH, V31_CRITICAL),
                    severity_event("High", "Critical"),
                    priority_event("P3", "P2"),
                ],
            ),
            "Critical",
            "P2",
            sorted([unit("NVD", V31_CRITICAL), unit("Example CNA", V40_CRITICAL)]),
        )
    return _BatchRace(
        record,
        feed,
        _Run(
            _batch_result(
                (
                    outcome("Example CNA", CVSSVersion.V4_0, CREATED),
                    outcome("NVD", CVSSVersion.V3_1, CREATED),
                ),
                severity_resolution("9.8", Severity.CRITICAL, provider="NVD"),
                products=ProductPropagationSummary(1, 0, 1),
                severity_changed=True,
                reconciled=True,
            ),
            [
                created_event("Example CNA", V40_CRITICAL),
                created_event("NVD", V31_CRITICAL),
                severity_event(None, "Critical"),
                *regression,
                priority_event(None, "P2"),
                floor,
            ],
        ),
        # The default-version `NVD` 8.1 outranks the non-default v4.0 9.3.
        _Run(
            _batch_result(
                (outcome("NVD", CVSSVersion.V3_1, UPDATED),),
                severity_resolution("8.1", Severity.HIGH, provider="NVD"),
                products=ProductPropagationSummary(1, 0, 0),
                severity_changed=True,
                reconciled=True,
            ),
            [
                updated_event("NVD", V31_CRITICAL, V31_HIGH),
                severity_event("Critical", "High"),
                priority_event("P2", "P3"),
            ],
        ),
        "High",
        "P3",
        sorted([unit("NVD", V31_HIGH), unit("Example CNA", V40_CRITICAL)]),
    )


@pytest.mark.integration
class TestTwoExternalBatches:
    """cvss-scoring.md, Required Tests: two external batches from distinct
    sources racing on the same CVE; ticket-mutations.md, Serialized
    outcomes. The winner holds its CVE and Ticket roots uncommitted; the
    waiter is proven blocked on the CVE root before any other statement."""

    @pytest.mark.parametrize("order", ["feed-first", "record-first"])
    @pytest.mark.parametrize("case", ["distinct-keys", "shared-key"])
    async def test_waiter_recomputes_from_the_committed_winner(
        self, world: _World, monkeypatch: pytest.MonkeyPatch, case: str, order: str
    ) -> None:
        cve = await world.cve()
        ticket = await _ticket(world, cve=cve, status=RESOLVED)
        p = await _product(world, ticket, threshold=T7, eligible=False)
        race = _batch_race(case, order, p)
        a = await world.open_session()  # the winner
        b = await world.open_session()  # the waiter
        spies = _BatchSpies(monkeypatch)

        with (
            SessionStatementRecorder(a) as winner_recorder,
            SessionStatementRecorder(b) as waiter_recorder,
        ):
            winner = await run_batch(a, cve.id, *race.first)
            assert pending_ticket_convergence_effects(a) == (
                TicketConvergenceEffect(ticket.id),
            )
            task = world.start(b, run_batch(b, cve.id, *race.second))
            await assert_lock_wait(task, waiter=b, blocked_by=a)
            # Blocked on the CVE root: the Ticket is requested only after it.
            assert len(waiter_recorder.statements) == 1
            assert _is_cve_lock(waiter_recorder.statements[0])
            await a.commit()
            waiter = await asyncio.wait_for(task, timeout=WAIT)
            assert pending_ticket_convergence_effects(b) == ()
            await b.commit()

        _assert_batch_locks(winner_recorder)
        _assert_batch_locks(waiter_recorder)
        assert winner == race.winner.result
        assert waiter == race.waiter.result
        assert spies.propagated.sessions == [a, b]
        assert spies.reconciled.sessions == (
            [a, b] if race.waiter.result.reconciled else [a]
        )
        assert spies.assigned.sessions == []
        assert await _committed(world, ticket, cve) == _Committed(
            (ANALYSIS, None, race.priority, None, None),
            [(True, False)],
            race.severity,
            race.assessments,
            [*race.winner.events, *race.waiter.events],
        )


# ---------------------------------------------------------------------------
# CVSS/override (both orders) and the Ticket-first no-deadlock case
# ---------------------------------------------------------------------------


def _override(
    session: AsyncSession, occurrence: _Occurrence, eligible: bool | None, actor: User
) -> Coroutine[Any, Any, ProductEligibilityResult]:
    """The consumer override call with the explicit declared path."""
    return set_product_eligibility(
        session,
        ticket_id=occurrence.ticket_id,
        package_id=occurrence.package_id,
        track_id=occurrence.track_id,
        ticket_package_product_id=occurrence.id,
        eligible=eligible,
        acting_user_id=actor.id,
        caller=TicketCaller.authenticated(actor.id, Scope.ALL),
        evaluation_date=EVAL,
    )


def _override_batch() -> tuple[ParsedExternalCVSSAssessment, ...]:
    return (external("NVD", V31_HIGH), external("Example CNA", V40_CRITICAL))


class _PauseAfterFirstAuditEvent:
    """Pauses `session`'s workflow right after its first Ticket audit event
    returns (after the flush that wrote its first Ticket UPDATE), while it
    holds the Ticket lock. Other sessions pass through unchanged."""

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


@pytest.mark.integration
class TestOverrideRace:
    """ticket-mutations.md, Independent-session races (CVSS/override);
    package-service.md, `set_product_eligibility()`; package-model.md,
    Override Model.

    An unassigned `Analysis` Ticket of a CVE without assessments has two
    occurrences (threshold 7.0, automatic `true` under the `10.0`
    fallback), in occurrence-ID order: `p`, the override target, and `q`, a
    stale automatic `false`. For `set`, `p` is a stale automatic `false`
    overridden to `false`; for `clear`, `p` is an override `false` that is
    cleared. The batch (`NVD` v3.1 high, `Example CNA` v4.0 critical) sets
    severity `High` and priority `P3`, repairs `q`, and reconciles once to
    the unchanged `Analysis` floor (no SUSE); the override assigns its
    actor and reconciles once. `p` receives exactly one override event in
    every order and one automatic `reason = cvss` event only when the batch
    precedes a set; an overridden `p` is skipped and a cleared `p` is
    already converged, so no automatic event is ever duplicated."""

    @pytest.mark.parametrize("order", ["batch-first", "override-first"])
    @pytest.mark.parametrize("request_kind", ["set", "clear"])
    async def test_serialized_outcome_of_both_orders(
        self,
        world: _World,
        monkeypatch: pytest.MonkeyPatch,
        request_kind: str,
        order: str,
    ) -> None:
        clear = request_kind == "clear"
        actor = await world.user(role=Role.VULNERABILITY_ANALYST)
        cve = await world.cve()
        ticket = await _ticket(world, cve=cve, status=ANALYSIS)
        low, high = sorted(uuid.uuid7() for _ in range(2))
        p = await _product(
            world,
            ticket,
            threshold=T7,
            eligible=False,
            override=clear,
            occurrence_id=low,
        )
        q = await _product(
            world, ticket, threshold=T7, eligible=False, occurrence_id=high
        )
        a = await world.open_session()  # the override
        b = await world.open_session()  # the batch
        spies = _BatchSpies(monkeypatch)
        override_reconciled = _Spy(
            monkeypatch, package_service, "reconcile_ticket_status", 1
        )
        value = None if clear else False

        if order == "batch-first":
            batch = await run_batch(b, cve.id, *_override_batch())
            with SessionStatementRecorder(a) as recorder:
                task = world.start(a, _override(a, p, value, actor))
                await assert_lock_wait(task, waiter=a, blocked_by=b)
                assert _is_user_share(recorder.statements[0])
                assert _is_ticket_lock(recorder.statements[-1])
            await b.commit()
            result = await asyncio.wait_for(task, timeout=WAIT)
            await a.commit()
        else:
            result = await _override(a, p, value, actor)
            with SessionStatementRecorder(b) as recorder:
                task = world.start(b, run_batch(b, cve.id, *_override_batch()))
                await assert_lock_wait(task, waiter=b, blocked_by=a)
                # The batch holds the CVE root and waits for the Ticket.
                assert len(recorder.statements) == 2
                assert _is_cve_lock(recorder.statements[0])
                assert _is_ticket_lock(recorder.statements[1])
                assert await _cve_root_held(world.probe, cve) is True
            await a.commit()
            batch = await asyncio.wait_for(task, timeout=WAIT)
            await b.commit()

        batch_first = order == "batch-first"
        # The batch skips `p` while it carries the override (before a clear,
        # after a set), repairs it only before a set, and finds it already
        # converged after a clear.
        p_overridden = clear == batch_first
        p_repaired = batch_first and not clear
        batch_products = [
            *([_chain_event(p, False, True)] if p_repaired else []),
            _chain_event(q, False, True),
        ]
        summary = ProductPropagationSummary(2, int(p_overridden), 1 + int(p_repaired))
        assert batch == _batch_result(
            (
                outcome("Example CNA", CVSSVersion.V4_0, CREATED),
                outcome("NVD", CVSSVersion.V3_1, CREATED),
            ),
            severity_resolution("8.1", Severity.HIGH, provider="NVD"),
            products=summary,
            severity_changed=True,
            reconciled=True,
        )
        batch_events = [
            created_event("Example CNA", V40_CRITICAL),
            created_event("NVD", V31_HIGH),
            severity_event(None, "High"),
            *batch_products,
            priority_event(None, "P3"),
        ]
        if clear:
            # Recalculated from the winner-current set: the `10.0` fallback.
            change = _override_event(p, actor, False, True, "cleared")
        elif batch_first:
            # The old value is the batch's committed repair, not the stale
            # `false` persisted before the race.
            change = _override_event(p, actor, True, False, "set")
        else:
            change = _override_event(p, actor, False, False, "set")
        override_events = [assignment_event(actor), change]

        assert result.outcome is MutationOutcome.CHANGED
        assert (result.product.eligible, result.product.is_eligible_override) == (
            (True, False) if clear else (False, True)
        )
        assert spies.reconciled.sessions == [b]
        assert spies.propagated.sessions == [b]
        assert spies.assigned.sessions == []
        assert override_reconciled.sessions == [a]
        committed = await _committed(world, ticket, cve)
        assert committed == _Committed(
            (ANALYSIS, actor.id, "P3", None, None),
            [(True, False) if clear else (False, True), (True, False)],
            "High",
            sorted([unit("NVD", V31_HIGH), unit("Example CNA", V40_CRITICAL)]),
            (
                [*batch_events, *override_events]
                if batch_first
                else [*override_events, *batch_events]
            ),
        )
        p_reasons = [
            e.detail["reason"]
            for e in committed.events
            if e.detail is not None and e.detail.get("track") == p.subject["track"]
        ]
        # At most one automatic event and exactly one override event for `p`.
        assert sorted(p_reasons) == sorted(
            ["va_override", *(["cvss"] if p_repaired else [])]
        )

    async def test_ticket_first_override_completes_while_the_batch_holds_the_cve(
        self, world: _World, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """ticket-mutations.md, Independent-session races: a Ticket-first
        mutation that writes the Ticket more than once completes and commits
        while a CVSS root holder waits for that Ticket (no deadlock), and
        the batch outcome reflects the committed winner.

        The CVE carries SUSE v3.1 medium (4.8) with a stale `NULL`
        severity; the unassigned `New` Ticket has one automatic `false`
        occurrence (threshold 9.0). The override `true` assigns the actor
        (first Ticket UPDATE), moves `New -> Analysis` (second UPDATE), and
        reconciles to the `Analysis` floor (no resolved severity). The
        waiting batch (`NVD` v3.1 critical) then sees the committed
        `Analysis` Ticket: it persists the SUSE-derived `Medium`, skips the
        override, never assigns, and its one reconciliation reaches
        `Analyzed`. Had it seen the pre-override `New`, it would not have
        reconciled."""
        actor = await world.user(role=Role.VULNERABILITY_ANALYST)
        cve = await world.cve(V31_MEDIUM)
        ticket = await _ticket(world, cve=cve, status=NEW)
        p = await _product(world, ticket, threshold=T9, eligible=False)
        a = await world.open_session()  # the override
        b = await world.open_session()  # the batch
        probe = world.probe
        pause = _PauseAfterFirstAuditEvent(monkeypatch, a)
        spies = _BatchSpies(monkeypatch)

        with SessionStatementRecorder(a) as recorder:
            first = world.start(a, _override(a, p, True, actor))
            await asyncio.wait_for(pause.paused.wait(), timeout=WAIT)
            assert len([s for s in recorder.statements if _is_ticket_update(s)]) == 1
            assert await _cve_root_held(probe, cve) is False

            second = world.start(b, run_batch(b, cve.id, external("NVD", V31_CRITICAL)))
            await assert_lock_wait(second, waiter=b, blocked_by=a)
            assert await _cve_root_held(probe, cve) is True

            pause.resume.set()
            result = await asyncio.wait_for(asyncio.shield(first), timeout=WAIT)

        assert len([s for s in recorder.statements if _is_ticket_update(s)]) >= 2
        await assert_lock_wait(second, waiter=b, blocked_by=a)
        await a.commit()
        batch = await asyncio.wait_for(asyncio.shield(second), timeout=WAIT)
        await b.commit()

        assert result.outcome is MutationOutcome.CHANGED
        assert batch == _batch_result(
            (outcome("NVD", CVSSVersion.V3_1, CREATED),),
            severity_resolution("4.8", Severity.MEDIUM),
            eligibility_resolution=suse_eligibility("4.8"),
            products=ProductPropagationSummary(1, 1, 0),
            severity_changed=True,
            reconciled=True,
        )
        assert spies.reconciled.sessions == [b]
        assert spies.assigned.sessions == []
        assert await _committed(world, ticket, cve) == _Committed(
            (ANALYZED, actor.id, "P4", None, None),
            [(True, True)],
            "Medium",
            sorted([unit("SUSE", V31_MEDIUM), unit("NVD", V31_CRITICAL)]),
            [
                assignment_event(actor),
                status_event(NEW, ANALYSIS),
                _override_event(p, actor, False, True, "set"),
                created_event("NVD", V31_CRITICAL),
                severity_event(None, "Medium"),
                priority_event(None, "P4"),
                status_event(ANALYSIS, ANALYZED),
            ],
        )


# ---------------------------------------------------------------------------
# CVSS/reactivation (both orders, both manual-zone exits)
# ---------------------------------------------------------------------------


EXITS = ["reopen", "revert"]
SOURCE = {"reopen": TicketStatus.IGNORED.value, "revert": TicketStatus.DUPLICATED.value}
"""The exact source status each exit accepts."""


async def _exit(
    db: AsyncSession, exit_: str, ticket_id: uuid.UUID, actor: User
) -> Ticket:
    """A consumer exit as the API handler calls it, with the fixed `EVAL`."""
    operation = reopen_from_ignored if exit_ == "reopen" else revert_duplicate
    return await operation(
        db,
        ticket_id=ticket_id,
        acting_user_id=actor.id,
        caller=TicketCaller.authenticated(actor.id, Scope.ALL),
        evaluation_date=EVAL,
    )


class _Boundary:
    """Records every session entering the package convergence boundary and,
    for the session `pause_in`, stops at its entry (after the exit locked
    the Ticket and set the `Analysis` floor, before any CVE-owned read)
    until `resume` is set."""

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


def _reactivation_batch() -> tuple[ParsedExternalCVSSAssessment, ...]:
    return (external("NVD", V31_CRITICAL), external("Example CNA", V40_CRITICAL))


@pytest.mark.integration
class TestReactivationRace:
    """ticket-mutations.md, Independent-session races (CVSS/reactivation);
    CVSS Status Matrix (`Ignored`/`Duplicated` defer Product and gate
    effects); package-service.md, Synchronous manual-zone-exit eligibility
    convergence; ticket-service.md, `_complete_manual_zone_exit()`.

    The CVE carries SUSE v3.1 medium (4.8, the eligibility score under the
    committed default 3.1) with a stale `NULL` severity. The unassigned
    manual-zone Ticket has two automatic stale occurrences in occurrence-ID
    order: `p1` (threshold 9.0) persisted `true`, `p2` (threshold 4.0)
    persisted `false`. The batch (`NVD` v3.1 critical, `Example CNA` v4.0
    critical) persists the SUSE-derived `Medium` (the external rows never
    outrank SUSE) and priority `P4`. The exit's convergence flips both
    Products in either order (external rows never change eligibility); its
    final status depends on whether the committed severity is resolved:
    `p2`'s eligible `AFFECTED` track keeps resolution incomplete, so a
    resolved severity yields `Analyzed`, a `NULL` one the `Analysis` floor.
    """

    @pytest.mark.parametrize("order", ["batch-first", "exit-first"])
    @pytest.mark.parametrize("exit_", EXITS)
    async def test_serialized_outcome_of_both_orders(
        self, world: _World, monkeypatch: pytest.MonkeyPatch, exit_: str, order: str
    ) -> None:
        actor = await world.user(role=Role.VULNERABILITY_ANALYST)
        cve = await world.cve(V31_MEDIUM)
        target = (
            await _ticket(world, cve=None, status=ANALYSIS)
            if exit_ == "revert"
            else None
        )
        ticket = await _ticket(
            world, cve=cve, status=SOURCE[exit_], duplicate_of=target
        )
        low, high = sorted(uuid.uuid7() for _ in range(2))
        p1 = await _product(
            world, ticket, threshold=T9, eligible=True, occurrence_id=low
        )
        p2 = await _product(
            world, ticket, threshold=T4, eligible=False, occurrence_id=high
        )
        a = await world.open_session()  # the exit
        b = await world.open_session()  # the batch
        probe = world.probe
        exit_first = order == "exit-first"
        boundary = _Boundary(monkeypatch, pause_in=a if exit_first else None)
        exit_reconciled = _Spy(
            monkeypatch, ticket_service, "reconcile_ticket_status", 1
        )
        spies = _BatchSpies(monkeypatch)

        with (
            SessionStatementRecorder(a) as exit_recorder,
            SessionStatementRecorder(b) as batch_recorder,
        ):
            if exit_first:
                exit_task = world.start(a, _exit(a, exit_, ticket.id, actor))
                await asyncio.wait_for(boundary.reached.wait(), timeout=WAIT)
                # Paused inside the boundary: A holds the Ticket, not the CVE.
                assert await _is_locked(
                    probe, select(Ticket.id).where(Ticket.id == ticket.id)
                )
                assert await _cve_root_held(probe, cve) is False
                batch_task = world.start(
                    b, run_batch(b, cve.id, *_reactivation_batch())
                )
                await assert_lock_wait(batch_task, waiter=b, blocked_by=a)
                # B holds the CVE root and waits for the Ticket.
                assert len(batch_recorder.statements) == 2
                assert _is_ticket_lock(batch_recorder.statements[-1])
                assert await _cve_root_held(probe, cve) is True
                boundary.resume.set()
                # The exit completes while B still holds the CVE root.
                exit_result = await asyncio.wait_for(
                    asyncio.shield(exit_task), timeout=WAIT
                )
                await assert_lock_wait(batch_task, waiter=b, blocked_by=a)
                await a.commit()
                batch = await asyncio.wait_for(asyncio.shield(batch_task), timeout=WAIT)
                await b.commit()
            else:
                batch = await run_batch(b, cve.id, *_reactivation_batch())
                # Deferred: the stale Products are untouched.
                assert await eligibility(b, ticket.id) == [
                    (True, False),
                    (False, False),
                ]
                exit_task = world.start(a, _exit(a, exit_, ticket.id, actor))
                await assert_lock_wait(exit_task, waiter=a, blocked_by=b)
                assert _is_ticket_lock(exit_recorder.statements[-1])
                await b.commit()
                exit_result = await asyncio.wait_for(
                    asyncio.shield(exit_task), timeout=WAIT
                )
                await a.commit()

        # The exit locks only its acting User then the Ticket, never the CVE.
        exit_locks = exit_recorder.row_locks()
        assert len(exit_locks) == 2
        assert _is_user_share(exit_locks[0])
        assert _is_ticket_lock(exit_locks[1])
        assert [s for s in exit_locks if CVE_STATEMENT.search(s)] == []
        _assert_batch_locks(batch_recorder)
        assert exit_result.id == ticket.id

        actions = (
            outcome("Example CNA", CVSSVersion.V4_0, CREATED),
            outcome("NVD", CVSSVersion.V3_1, CREATED),
        )
        medium = severity_resolution("4.8", Severity.MEDIUM)
        direct = [
            created_event("Example CNA", V40_CRITICAL),
            created_event("NVD", V31_CRITICAL),
            severity_event(None, "Medium"),
        ]
        exit_prefix = [
            assignment_event(actor),
            *(
                [
                    EventRow(
                        "duplicate_removed",
                        actor.id,
                        format_ticket_id(target.sequence_id),
                        None,
                        None,
                        None,
                    )
                ]
                if target is not None
                else []
            ),
            _reactivation_event(p1, True, False),
            _reactivation_event(p2, False, True),
        ]
        if exit_first:
            # The exit converged from the pre-batch committed state (NULL
            # severity); the batch then applies immediate propagation with
            # no Product change and reconciles once for its severity.
            assert batch == _batch_result(
                actions,
                medium,
                eligibility_resolution=suse_eligibility("4.8"),
                products=ProductPropagationSummary(2, 0, 0),
                severity_changed=True,
                reconciled=True,
            )
            expected = [
                *exit_prefix,
                status_event(SOURCE[exit_], ANALYSIS),
                *direct,
                priority_event(None, "P4"),
                status_event(ANALYSIS, ANALYZED),
            ]
            assert spies.reconciled.sessions == [b]
            assert spies.propagated.sessions == [b]
        else:
            # Deferred: direct records and priority only; the exit then
            # converges from the batch's committed state.
            assert batch == _batch_result(
                actions,
                medium,
                eligibility_resolution=suse_eligibility("4.8"),
                propagation=DEFERRED,
                products=NO_PRODUCTS,
                severity_changed=True,
                reconciled=False,
            )
            expected = [
                *direct,
                priority_event(None, "P4"),
                *exit_prefix,
                status_event(SOURCE[exit_], ANALYZED),
            ]
            assert spies.reconciled.sessions == []
            assert spies.propagated.sessions == []
        assert spies.assigned.sessions == []
        assert boundary.sessions == [a]
        assert exit_reconciled.sessions == [a]
        assert await _committed(world, ticket, cve) == _Committed(
            (ANALYZED, actor.id, "P4", None, None),
            [(False, False), (True, False)],
            "Medium",
            sorted(
                [
                    unit("SUSE", V31_MEDIUM),
                    unit("NVD", V31_CRITICAL),
                    unit("Example CNA", V40_CRITICAL),
                ]
            ),
            expected,
        )
        if target is not None:
            assert await ticket_state(probe, target.id) == (
                ANALYSIS,
                None,
                None,
                None,
                None,
            )
            assert await ticket_events_by_id(probe, target.id) == []
            await probe.rollback()


# ---------------------------------------------------------------------------
# Default-version/CVSS (both orders)
# ---------------------------------------------------------------------------


def _default_version_batch() -> tuple[ParsedExternalCVSSAssessment, ...]:
    return (external("NVD", V40_CRITICAL), external("Example CNA", V31_HIGH))


@pytest.mark.integration
class TestDefaultVersionRace:
    """ticket-mutations.md, Independent-session races (default-version/CVSS);
    `recalculate_cvss_chain()` default-version mode and runner-facing
    classification.

    The committed setting is changed to `4.0`, and the runner's unit is
    given the same `4.0`. The CVE carries SUSE v3.1 critical (9.8) with the
    `Critical` severity of both versions (the SUSE other-version step
    outranks every external row). The `Resolved` Ticket, assigned to an
    active VA, has one occurrence (threshold 9.9) persisted `false`,
    converged under `3.1` (9.8) but stale under `4.0`, where eligibility is
    the `10.0` fallback. Whichever unit serializes first repairs it
    (`false -> true`) and regresses the Ticket once to `Analyzed`; the
    waiter recomputes from the winner's committed state and the committed
    setting and changes nothing derived."""

    @pytest.mark.parametrize("order", ["runner-first", "batch-first"])
    async def test_serialized_outcome_of_both_orders(
        self, world: _World, monkeypatch: pytest.MonkeyPatch, order: str
    ) -> None:
        await world.set_default_version("4.0")
        owner = await world.user(role=Role.VULNERABILITY_ANALYST)
        cve = await world.cve(V31_CRITICAL, severity=Severity.CRITICAL)
        ticket = await _ticket(
            world, cve=cve, status=RESOLVED, assignee=owner, priority_auto="P2"
        )
        p = await _product(world, ticket, threshold=T99, eligible=False)
        a = await world.open_session()  # the batch
        b = await world.open_session()  # the default-version unit
        spies = _BatchSpies(monkeypatch)

        def runner_unit() -> Coroutine[Any, Any, CVSSChainResult]:
            return recalculate_cvss_chain(
                b,
                cve_id=cve.id,
                mode=CVSSChainMode.DEFAULT_VERSION,
                default_cvss_version="4.0",
                evaluation_date=EVAL,
            )

        if order == "runner-first":
            runner = await runner_unit()
            with SessionStatementRecorder(a) as recorder:
                task = world.start(a, run_batch(a, cve.id, *_default_version_batch()))
                await assert_lock_wait(task, waiter=a, blocked_by=b)
                assert len(recorder.statements) == 1
                assert _is_cve_lock(recorder.statements[0])
            await b.commit()
            batch = await asyncio.wait_for(task, timeout=WAIT)
            await a.commit()
        else:
            batch = await run_batch(a, cve.id, *_default_version_batch())
            with SessionStatementRecorder(b) as recorder:
                runner_task = world.start(b, runner_unit())
                await assert_lock_wait(runner_task, waiter=b, blocked_by=a)
                assert len(recorder.statements) == 1
                assert _is_cve_lock(recorder.statements[0])
            await a.commit()
            runner = await asyncio.wait_for(runner_task, timeout=WAIT)
            await b.commit()

        runner_first = order == "runner-first"
        critical = severity_resolution("9.8", Severity.CRITICAL)
        # The fallback proves the batch read the committed `4.0` setting
        # (under `3.1` it would be the SUSE 9.8).
        assert batch == _batch_result(
            (
                outcome("NVD", CVSSVersion.V4_0, CREATED),
                outcome("Example CNA", CVSSVersion.V3_1, CREATED),
            ),
            critical,
            products=ProductPropagationSummary(1, 0, 0 if runner_first else 1),
            severity_changed=False,
            reconciled=not runner_first,
        )
        assert runner == CVSSChainResult(
            mode=CVSSChainMode.DEFAULT_VERSION,
            classification=(
                CVSSChainClassification.CHANGED
                if runner_first
                else CVSSChainClassification.UNCHANGED
            ),
            severity_resolution=critical,
            eligibility_resolution=FALLBACK,
            propagation=IMMEDIATE,
            products=ProductPropagationSummary(1, 0, 1 if runner_first else 0),
            severity_changed=False,
            reconciled=runner_first,
            evaluation_date=EVAL,
        )
        repair = [_chain_event(p, False, True), status_event(RESOLVED, ANALYZED)]
        direct = [
            created_event("NVD", V40_CRITICAL),
            created_event("Example CNA", V31_HIGH),
        ]
        assert spies.propagated.sessions == ([b, a] if runner_first else [a, b])
        assert spies.reconciled.sessions == ([b] if runner_first else [a])
        assert spies.assigned.sessions == []
        assert await _committed(world, ticket, cve) == _Committed(
            (ANALYZED, owner.id, "P2", None, None),
            [(True, False)],
            "Critical",
            sorted(
                [
                    unit("SUSE", V31_CRITICAL),
                    unit("NVD", V40_CRITICAL),
                    unit("Example CNA", V31_HIGH),
                ]
            ),
            [*repair, *direct] if runner_first else [*direct, *repair],
        )
