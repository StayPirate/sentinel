"""Tests for the `evaluate_lifecycle_transitions` fetcher
(backend/app/services/packages/evaluate_lifecycle_transitions.py):
`EvaluateLifecycleTransitions.execute()`, `run()` finalization, and
`catch_up()`.

Owning specifications:

- docs/features/packages/product-lifecycle-transitions.md (Fetcher
  properties, Algorithm, Idempotency and Convergence, Error Handling,
  Metrics with its mandated cases, Catch-Up, TicketAuditEvent Records).
  The post-commit Ticket convergence drains (Algorithm step 5 drain
  sentences; the Catch-Up detach-and-attempt and drain-exception
  sentences) are not implemented yet: a registered effect is discarded
  when its Ticket transaction ends, and nothing here tests a drain.
- docs/features/platform/fetcher-infrastructure.md (BaseFetcher run
  lifecycle, Finalization, Outcome and effect accounting; Per-Ticket
  Catch-Up: override-point contract, boundary conditions for custom
  overrides, `get_catch_up_fetchers()`, Celery task wrapper, Interface
  contract; `SoftTimeLimitExceeded` handling convention; Registry and
  Fetcher Discovery).
- docs/features/platform/testing-strategy.md (Fetcher Outcome and Effect
  Accounting, including the lifecycle per-unit finalizer exception: only
  its commit-failure half; Concurrency Testing and Lock-Wait Observation;
  Audit Trail Testing).
- docs/features/tickets/ticket-audit-log.md (Canonical Mutation and
  No-Event Matrix rows "EOL entry/exit or derived actionability change"
  and "Product catalog source mutation or workflow-only
  dispatch/checkpoint outcome"; Testing Requirement 12).
- docs/data-sources.md (Fetcher Registry row `evaluate_lifecycle_transitions`).

Candidate-discovery gate parity is covered by
`tests/test_services/test_lifecycle_gate_parity.py` and the single-Ticket
reconciliation boundary by `tests/test_services/
test_reconcile_lifecycle_actionability*.py`; this module tests the
fetcher around them.

Every Ticket unit commits through its own session, so the integration
tests seed a `CommittedWorld` (which also owns the committed
`default_cvss_version` setting read by the Product scan) and delete every
committed row at teardown. The fetcher's module-level
`async_session_factory` is replaced by `_UnitSessions` over
`real_session_factory`; the `run()` tests also redirect `base_fetcher`'s
factory and delete their `FetcherConfig` and `FetcherRun` rows. The
Product dispatch is substituted by an autouse recorder unless a test
restores the production chain down to `task_publication.publish_task`.
The fetcher clock is fixed to `EVAL`.

Unless a test states otherwise, every Ticket is CVE-less with
`severity_manual = High` and unassigned, and every track holds one
occurrence of its own catalog Product with a `NULL` threshold, so a
supported or EOL Product's automatic eligibility is `true` and a Reactive
Support Product's is `false`. On `EVAL` an `Analyzed` Ticket whose only
`AFFECTED` track holds an EOL Product gates to `Resolved`; a `Resolved`
Ticket whose `AFFECTED` track holds a supported Product gates to
`Analyzed`; an `Analysis` Ticket with an actionable `ANALYSIS` track is
converged. Expected values are transcribed from the specifications, never
computed with the module under test.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta
from types import SimpleNamespace
from typing import Any, Final, Literal
from unittest.mock import AsyncMock, Mock

import pytest
from celery.exceptions import OperationalError as KombuOperationalError
from celery.exceptions import SoftTimeLimitExceeded
from sqlalchemy import delete, event, func, select, update
from sqlalchemy.exc import OperationalError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from sqlalchemy.orm import Session
from structlog.testing import capture_logs

import app.services.base_fetcher as base_fetcher_module
from app.celery_app import celery_app
from app.core.enums import PackageStatus, Severity, TicketStatus
from app.core.exceptions import TicketNotFoundError
from app.models.fetcher_config import FetcherConfig
from app.models.fetcher_run import FetcherRun
from app.models.product import Product
from app.models.system_setting import SystemSetting
from app.models.ticket import Ticket
from app.models.ticket_audit_event import TicketAuditEvent
from app.models.ticket_package import TicketPackage
from app.models.ticket_package_product import TicketPackageProduct
from app.models.ticket_package_track import TicketPackageTrack
from app.services import task_publication
from app.services.base_fetcher import (
    FETCHER_REGISTRY,
    BaseFetcher,
    FetcherRunConfig,
    get_catch_up_fetchers,
)
from app.services.fetcher_bootstrap import bootstrap_fetcher_configs
from app.services.package_service import (
    LifecycleReconciliationResult,
    reconcile_lifecycle_actionability_for_ticket,
)
from app.services.packages import evaluate_lifecycle_transitions as evaluator
from app.services.packages import product_eligibility_recalculation as recalculation
from app.services.packages.evaluate_lifecycle_transitions import (
    EvaluateLifecycleTransitions,
)
from app.services.packages.product_eligibility_mismatch import (
    find_product_eligibility_mismatches,
)
from app.services.packages.product_eligibility_recalculation import (
    dispatch_product_eligibility_recalculation,
    re_evaluate_product_eligibility,
)
from app.tasks import fetchers
from tests.support.cvss_chain import DEFAULT_VERSION
from tests.support.database import assert_lock_wait
from tests.support.suse_cvss_races import CommittedWorld, SessionStatementRecorder
from tests.support.ticket_mutations import (
    AFTER_EVAL,
    BEFORE_EVAL,
    EVAL,
    REACTIVE_END,
    REACTIVE_EXTENDED_END,
    REACTIVE_GS_END,
    EventRow,
    status_event,
    ticket_events_by_id,
)

Factory = Callable[[], Awaitable[AsyncSession]]
Metrics = tuple[int, int, int, int]
"""`(succeeded, created, updated, failed)` of one fetcher run."""

NAME: Final = "evaluate_lifecycle_transitions"
NEXT_DAY: Final = EVAL + timedelta(days=1)
WAIT: Final = 5
"""Upper bound, in seconds, of every wait that is expected to finish."""

ANALYSIS = TicketStatus.ANALYSIS
ANALYZED = TicketStatus.ANALYZED
RESOLVED = TicketStatus.RESOLVED

DISPATCH_FAILED: Final = "lifecycle_eligibility_dispatch_failed"
TICKET_FAILED: Final = "lifecycle_reconciliation_ticket_failed"
SUMMARY: Final = "lifecycle_transitions_evaluated"
CATCH_UP_RECONCILED: Final = "lifecycle_catch_up_reconciled"

_REAL_RECONCILE = reconcile_lifecycle_actionability_for_ticket
_REAL_FIND_PRODUCTS = find_product_eligibility_mismatches
_REAL_FIND_TICKETS = evaluator.find_lifecycle_gate_mismatches
_REAL_UTC_TODAY = evaluator._utc_today

_WHOLE_RUN_SIGNALS = [
    pytest.param(asyncio.CancelledError, id="cancelled"),
    pytest.param(SoftTimeLimitExceeded, id="soft-time-limit"),
    pytest.param(MemoryError, id="memory-error"),
]


# ---------------------------------------------------------------------------
# Substitutes and recorders
# ---------------------------------------------------------------------------


@dataclass
class DispatchRecorder:
    """Substitute for `dispatch_product_eligibility_recalculation()`.

    Records each `(catalog_product_id, reason)`; raises the configured
    exception for a Product in `failures`; when `session` is set, records
    whether that session had an open transaction at dispatch time; when
    `events` is set, appends `"dispatch"` to it.
    """

    calls: list[tuple[uuid.UUID, str]] = field(default_factory=list)
    failures: dict[uuid.UUID, BaseException] = field(default_factory=dict)
    session: AsyncSession | None = None
    in_transaction: list[bool] = field(default_factory=list)
    events: list[str] | None = None

    async def __call__(self, catalog_product_id: uuid.UUID, reason: str) -> None:
        self.calls.append((catalog_product_id, reason))
        if self.events is not None:
            self.events.append("dispatch")
        if self.session is not None:
            self.in_transaction.append(self.session.in_transaction())
        error = self.failures.get(catalog_product_id)
        if error is not None:
            raise error

    @property
    def product_ids(self) -> list[uuid.UUID]:
        return [product_id for product_id, _ in self.calls]


@dataclass(frozen=True, slots=True)
class _Call:
    session: AsyncSession
    ticket_id: uuid.UUID
    evaluation_date: date


class _ReconcileSpy:
    """Replaces the evaluator's reference to
    `reconcile_lifecycle_actionability_for_ticket()`: records each call and
    delegates to the real service. `fail_after[ticket_id]` is raised after
    the real call has flushed its writes; `fail_instead[ticket_id]` is
    raised without calling the service."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.calls: list[_Call] = []
        self.results: dict[uuid.UUID, LifecycleReconciliationResult] = {}
        self.fail_after: dict[uuid.UUID, BaseException] = {}
        self.fail_instead: dict[uuid.UUID, BaseException] = {}
        monkeypatch.setattr(
            evaluator, "reconcile_lifecycle_actionability_for_ticket", self._call
        )

    async def _call(
        self, db: AsyncSession, ticket_id: uuid.UUID, evaluation_date: date
    ) -> LifecycleReconciliationResult:
        self.calls.append(_Call(db, ticket_id, evaluation_date))
        if ticket_id in self.fail_instead:
            raise self.fail_instead[ticket_id]
        result = await _REAL_RECONCILE(db, ticket_id, evaluation_date)
        self.results[ticket_id] = result
        if ticket_id in self.fail_after:
            raise self.fail_after[ticket_id]
        return result

    @property
    def ticket_ids(self) -> list[uuid.UUID]:
        return [call.ticket_id for call in self.calls]


class _UnitSessions:
    """Replaces the evaluator's module-level `async_session_factory`.

    Hands out the `queued` sessions first, then sessions of the real
    factory; records every session it hands out; optionally makes the
    commit of the session at one index fail; when `events` is set, appends
    `"unit"` to it; when `observed` is set, records whether that session
    had an open transaction when each unit session was opened."""

    def __init__(self, factory: async_sessionmaker[AsyncSession]) -> None:
        self._factory = factory
        self.sessions: list[AsyncSession] = []
        self.queued: list[AsyncSession] = []
        self.failing_commit: tuple[int, BaseException] | None = None
        self.events: list[str] | None = None
        self.observed: AsyncSession | None = None
        self.observed_in_transaction: list[bool] = []

    def __call__(self) -> AsyncSession:
        session = self.queued.pop(0) if self.queued else self._factory()
        if self.failing_commit is not None:
            index, error = self.failing_commit
            if index == len(self.sessions):

                def _fail(_session: Session) -> None:
                    raise error

                event.listen(session.sync_session, "before_commit", _fail)
        if self.events is not None:
            self.events.append("unit")
        if self.observed is not None:
            self.observed_in_transaction.append(self.observed.in_transaction())
        self.sessions.append(session)
        return session


@pytest.fixture(autouse=True)
def clock(monkeypatch: pytest.MonkeyPatch) -> Mock:
    """The fetcher's UTC clock, fixed to `EVAL`."""
    today = Mock(return_value=EVAL)
    monkeypatch.setattr(evaluator, "_utc_today", today)
    return today


@pytest.fixture(autouse=True)
def dispatcher(monkeypatch: pytest.MonkeyPatch) -> DispatchRecorder:
    """Substitute the Product dispatch: no test reaches a broker."""
    recorder = DispatchRecorder()
    monkeypatch.setattr(
        evaluator, "dispatch_product_eligibility_recalculation", recorder
    )
    return recorder


@pytest.fixture(autouse=True)
def reconcile(monkeypatch: pytest.MonkeyPatch) -> _ReconcileSpy:
    return _ReconcileSpy(monkeypatch)


@pytest.fixture
def units(
    real_session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> _UnitSessions:
    sessions = _UnitSessions(real_session_factory)
    monkeypatch.setattr(evaluator, "async_session_factory", sessions)
    return sessions


# ---------------------------------------------------------------------------
# Committed world
# ---------------------------------------------------------------------------


@pytest.fixture
async def world(db_session_factory: Factory) -> AsyncIterator[CommittedWorld]:
    """A `CommittedWorld` that also owns the committed `default_cvss_version`
    setting (the test schema has none), which the Product scan reads."""
    created = CommittedWorld(db_session_factory, await db_session_factory())
    owns_setting = False
    try:
        if await created.session.get(SystemSetting, "default_cvss_version") is None:
            created.session.add(
                SystemSetting(key="default_cvss_version", value=DEFAULT_VERSION)
            )
            owns_setting = True
        await created.session.commit()
        yield created
    finally:
        await created.cleanup()
        if owns_setting:
            await created.session.execute(
                delete(SystemSetting).where(SystemSetting.key == "default_cvss_version")
            )
            await created.session.commit()


Lifecycle = Literal["supported", "eol", "reactive", "boundary"]

_LIFECYCLE_DATES: Final[Mapping[str, Mapping[str, date]]] = {
    "supported": {"general_support_end_date": AFTER_EVAL},
    "eol": {"general_support_end_date": BEFORE_EVAL},
    # General Support ends on `EVAL`: actionable on `EVAL`, EOL from NEXT_DAY.
    "boundary": {"general_support_end_date": EVAL},
    "reactive": {
        "general_support_end_date": REACTIVE_GS_END,
        "extended_support_end_date": REACTIVE_EXTENDED_END,
        "reactive_support_end_date": REACTIVE_END,
    },
}


async def _product(
    world: CommittedWorld, lifecycle: Lifecycle = "supported"
) -> Product:
    """A committed catalog Product in the given lifecycle phase on `EVAL`."""
    suffix = uuid.uuid4().hex[:10]
    product = Product(
        name=f"Example Product {suffix}",
        version="1",
        display_name=f"EP {suffix}",
        cpe=f"cpe:/o:example:product:{suffix}",
        catalog_last_seen_at=datetime.now(UTC),
        **_LIFECYCLE_DATES[lifecycle],
    )
    world.session.add(product)
    await world.session.flush()
    world.product_ids.append(product.id)
    await world.session.commit()
    return product


async def _ticket(world: CommittedWorld, status: TicketStatus) -> Ticket:
    """A committed Ticket; a `Duplicated` one points at a fresh canonical
    `Analysis` Ticket."""
    if status is not TicketStatus.DUPLICATED:
        return await world.ticket(
            cve_id=None, status=status, severity_manual=Severity.HIGH
        )
    canonical = await _ticket(world, ANALYSIS)
    ticket = Ticket(
        status=status.value,
        severity_manual=Severity.HIGH.value,
        duplicate_of_id=canonical.id,
    )
    world.session.add(ticket)
    await world.session.flush()
    world.ticket_ids.append(ticket.id)
    await world.session.commit()
    return ticket


async def _track(
    world: CommittedWorld,
    ticket: Ticket,
    status: PackageStatus,
    product: Product,
    *,
    eligible: bool = True,
    excluded: bool = False,
) -> None:
    """Commit one package with one track of `status` holding one
    occurrence of `product`."""
    session = world.session
    suffix = uuid.uuid4().hex[:10]
    package = TicketPackage(ticket_id=ticket.id, package_name=f"fictional-{suffix}")
    session.add(package)
    await session.flush()
    track = TicketPackageTrack(
        ticket_package_id=package.id,
        workflow_type="ibs",
        reference=f"Example:Codestream:{suffix}:Update",
        status=status.value,
    )
    session.add(track)
    await session.flush()
    session.add(
        TicketPackageProduct(
            ticket_package_track_id=track.id,
            product_id=product.id,
            eligible=eligible,
            deleted_at=datetime.now(UTC) if excluded else None,
        )
    )
    await session.commit()


async def _eol_ticket(world: CommittedWorld, status: TicketStatus = ANALYZED) -> Ticket:
    """A Ticket whose only `AFFECTED` track holds an EOL Product: it gates
    to `Resolved` on `EVAL` (no actionable track)."""
    ticket = await _ticket(world, status)
    await _track(world, ticket, PackageStatus.AFFECTED, await _product(world, "eol"))
    return ticket


async def _regressing_ticket(world: CommittedWorld) -> Ticket:
    """A `Resolved` Ticket whose `AFFECTED` track holds a supported,
    eligible, unreleased Product: it gates to `Analyzed` on `EVAL`."""
    ticket = await _ticket(world, RESOLVED)
    await _track(world, ticket, PackageStatus.AFFECTED, await _product(world))
    return ticket


async def _converged_ticket(world: CommittedWorld) -> Ticket:
    """An `Analyzed` Ticket that gates to `Analyzed` on `EVAL`."""
    ticket = await _ticket(world, ANALYZED)
    await _track(world, ticket, PackageStatus.AFFECTED, await _product(world))
    return ticket


async def _mismatched_product(world: CommittedWorld) -> Product:
    """A Reactive Support Product whose only occurrence still stores
    `eligible = true`, on a converged `Analysis` Ticket."""
    product = await _product(world, "reactive")
    ticket = await _ticket(world, ANALYSIS)
    await _track(world, ticket, PackageStatus.ANALYSIS, product)
    return product


@dataclass(frozen=True, slots=True)
class _State:
    """The committed Ticket status and its audit events in insertion order."""

    status: str
    events: list[EventRow]


async def _state(world: CommittedWorld, ticket: Ticket) -> _State:
    probe = await world.open_session()
    status = (
        await probe.execute(select(Ticket.status).where(Ticket.id == ticket.id))
    ).scalar_one()
    events = await ticket_events_by_id(probe, ticket.id)
    await probe.rollback()
    return _State(status, events)


def _unchanged(status: TicketStatus) -> _State:
    return _State(status.value, [])


def _changed(old: TicketStatus, new: TicketStatus) -> _State:
    return _State(new.value, [status_event(old.value, new.value)])


async def _stored_eligibility(world: CommittedWorld, product: Product) -> list[bool]:
    probe = await world.open_session()
    rows = await probe.execute(
        select(TicketPackageProduct.eligible)
        .where(TicketPackageProduct.product_id == product.id)
        .order_by(TicketPackageProduct.id)
    )
    values = list(rows.scalars())
    await probe.rollback()
    return values


def _metrics(fetcher: BaseFetcher) -> Metrics:
    return (fetcher._succeeded, fetcher._created, fetcher._updated, fetcher._failed)


def _logged(logs: Sequence[Mapping[str, Any]], name: str) -> list[Mapping[str, Any]]:
    return [entry for entry in logs if entry["event"] == name]


def _summary(
    *,
    products: int = 0,
    dispatched: int = 0,
    dispatch_failed: int = 0,
    tickets: int = 0,
    tickets_changed: int = 0,
    tickets_failed: int = 0,
) -> dict[str, Any]:
    return {
        "event": SUMMARY,
        "log_level": "info",
        "products": products,
        "dispatched": dispatched,
        "dispatch_failed": dispatch_failed,
        "tickets": tickets,
        "tickets_changed": tickets_changed,
        "tickets_failed": tickets_failed,
    }


def _by_id(product: Product) -> uuid.UUID:
    return product.id


async def _execute(world: CommittedWorld) -> EvaluateLifecycleTransitions:
    fetcher = EvaluateLifecycleTransitions()
    await fetcher.execute(await world.open_session())
    return fetcher


async def _execute_failing(
    world: CommittedWorld, error: type[BaseException]
) -> tuple[BaseException, EvaluateLifecycleTransitions]:
    fetcher = EvaluateLifecycleTransitions()
    session = await world.open_session()
    with pytest.raises(error) as raised:
        await fetcher.execute(session)
    return raised.value, fetcher


# ---------------------------------------------------------------------------
# run() lifecycle: finalized FetcherRun (committed; explicit cleanup)
# ---------------------------------------------------------------------------


class _Runs:
    """Commits one `running` FetcherRun per `start()` and reads it back."""

    def __init__(self, factory: async_sessionmaker[AsyncSession]) -> None:
        self._factory = factory
        self.fetcher_name = f"test_lifecycle_run_{uuid.uuid4().hex[:12]}"
        self.configured = False

    async def start(self) -> uuid.UUID:
        async with self._factory() as session:
            if not self.configured:
                session.add(
                    FetcherConfig(
                        fetcher_name=self.fetcher_name,
                        enabled=True,
                        run_timeout=3600,
                        request_delay=0,
                        custom_settings={},
                    )
                )
                self.configured = True
            run = FetcherRun(
                fetcher_name=self.fetcher_name,
                started_at=datetime.now(UTC),
                status="running",
                triggered_by="schedule",
            )
            session.add(run)
            await session.commit()
            return run.id

    async def finalized(self, run_id: uuid.UUID) -> FetcherRun:
        async with self._factory() as session:
            run = await session.get(FetcherRun, run_id)
            assert run is not None
            return run


@pytest.fixture
async def runs(
    real_session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> AsyncIterator[_Runs]:
    """Route `run()`'s own sessions to the test database; delete the
    committed `FetcherConfig` and `FetcherRun` rows at teardown."""
    monkeypatch.setattr(
        base_fetcher_module, "async_session_factory", real_session_factory
    )
    created = _Runs(real_session_factory)
    try:
        yield created
    finally:
        async with real_session_factory() as session:
            await session.execute(
                delete(FetcherRun).where(
                    FetcherRun.fetcher_name == created.fetcher_name
                )
            )
            await session.execute(
                delete(FetcherConfig).where(
                    FetcherConfig.fetcher_name == created.fetcher_name
                )
            )
            await session.commit()


def _run_config() -> FetcherRunConfig:
    return FetcherRunConfig(
        hard_time_limit_seconds=3600, request_delay=0, custom_settings={}
    )


def _run_metrics(run: FetcherRun) -> Metrics:
    return (run.items_succeeded, run.items_created, run.items_updated, run.items_failed)


async def _run(runs: _Runs) -> FetcherRun:
    """One complete `run()` that returns normally; the finalized row."""
    run_id = await runs.start()
    await EvaluateLifecycleTransitions().run(run_id=run_id, config=_run_config())
    return await runs.finalized(run_id)


async def _run_failing(
    runs: _Runs, error: type[BaseException]
) -> tuple[BaseException, FetcherRun]:
    run_id = await runs.start()
    with pytest.raises(error) as raised:
        await EvaluateLifecycleTransitions().run(run_id=run_id, config=_run_config())
    return raised.value, await runs.finalized(run_id)


@pytest.mark.integration
@pytest.mark.usefixtures("units")
class TestRunOutcomes:
    """Metrics: every mandated case with exact counters and run status."""

    async def test_product_dispatch_success(
        self, world: CommittedWorld, runs: _Runs, dispatcher: DispatchRecorder
    ) -> None:
        product = await _mismatched_product(world)

        run = await _run(runs)

        assert run.status == "success"
        assert _run_metrics(run) == (1, 0, 0, 0)
        assert dispatcher.calls == [(product.id, "reactive_ltss")]

    async def test_product_dispatch_failure(
        self, world: CommittedWorld, runs: _Runs, dispatcher: DispatchRecorder
    ) -> None:
        product = await _mismatched_product(world)
        dispatcher.failures[product.id] = KombuOperationalError("example failure")

        with capture_logs() as logs:
            run = await _run(runs)

        assert run.status == "failure"
        assert run.error_message == "All 1 items failed"
        assert (run.error_detail, run.error_traceback) == (None, None)
        assert _run_metrics(run) == (0, 0, 0, 1)
        assert _logged(logs, DISPATCH_FAILED) == [
            {
                "event": DISPATCH_FAILED,
                "log_level": "warning",
                "product_id": str(product.id),
                "error_type": "OperationalError",
            }
        ]
        assert "example failure" not in repr(logs)

    async def test_committed_ticket_status_change(
        self, world: CommittedWorld, runs: _Runs, reconcile: _ReconcileSpy
    ) -> None:
        ticket = await _eol_ticket(world)

        run = await _run(runs)

        assert run.status == "success"
        assert _run_metrics(run) == (1, 0, 1, 0)
        assert reconcile.ticket_ids == [ticket.id]
        assert await _state(world, ticket) == _changed(ANALYZED, RESOLVED)

    async def test_locked_current_ticket_no_op(
        self,
        world: CommittedWorld,
        runs: _Runs,
        units: _UnitSessions,
        reconcile: _ReconcileSpy,
    ) -> None:
        """The Ticket is selected while a concurrent reconciliation holds
        its row lock with an uncommitted `Resolved`. The fetcher's unit is
        proven blocked on that lock; after the winner commits, the unit
        reevaluates the locked-current state and commits a no-op:
        succeeded without an update, and no second `status_change`."""
        ticket = await _eol_ticket(world)
        holder = await world.open_session()
        waiter = await world.open_session()
        units.queued.append(waiter)
        winner = await reconcile_lifecycle_actionability_for_ticket(
            holder, ticket.id, EVAL
        )
        assert winner.changed
        run_id = await runs.start()

        task = world.start(
            waiter,
            EvaluateLifecycleTransitions().run(run_id=run_id, config=_run_config()),
        )
        await assert_lock_wait(task, waiter=waiter, blocked_by=holder)
        await holder.commit()
        await asyncio.wait_for(task, timeout=WAIT)

        run = await runs.finalized(run_id)
        assert run.status == "success"
        assert _run_metrics(run) == (1, 0, 0, 0)
        assert units.sessions == [waiter]
        assert reconcile.results[ticket.id] == LifecycleReconciliationResult(
            previous_status=RESOLVED,
            current_status=RESOLVED,
            changed=False,
            skipped=False,
        )
        assert await _state(world, ticket) == _changed(ANALYZED, RESOLVED)

    @pytest.mark.parametrize(
        ("failure", "instead"),
        [
            pytest.param(RuntimeError("fictional secret detail"), False, id="flushed"),
            pytest.param(TicketNotFoundError(), True, id="ticket-not-found"),
        ],
    )
    async def test_ticket_transaction_failure_rolls_back_only_that_ticket(
        self,
        world: CommittedWorld,
        runs: _Runs,
        reconcile: _ReconcileSpy,
        failure: Exception,
        instead: bool,
    ) -> None:
        """The middle Ticket fails before commit (after its status change
        was flushed, or before any write): only it is rolled back, one
        WARNING names its ID and exception type, and the earlier and later
        Tickets commit."""
        first, middle, last = [await _eol_ticket(world) for _ in range(3)]
        assert [first.id, middle.id, last.id] == sorted([first.id, middle.id, last.id])
        (reconcile.fail_instead if instead else reconcile.fail_after)[middle.id] = (
            failure
        )

        with capture_logs() as logs:
            run = await _run(runs)

        assert run.status == "partial"
        assert _run_metrics(run) == (2, 0, 2, 1)
        assert reconcile.ticket_ids == [first.id, middle.id, last.id]
        assert _logged(logs, TICKET_FAILED) == [
            {
                "event": TICKET_FAILED,
                "log_level": "warning",
                "ticket_id": str(middle.id),
                "error_type": type(failure).__name__,
            }
        ]
        assert "fictional secret detail" not in repr(logs)
        assert await _state(world, first) == _changed(ANALYZED, RESOLVED)
        assert await _state(world, middle) == _unchanged(ANALYZED)
        assert await _state(world, last) == _changed(ANALYZED, RESOLVED)

    async def test_every_ticket_failing_is_a_normal_return_failure(
        self, world: CommittedWorld, runs: _Runs, reconcile: _ReconcileSpy
    ) -> None:
        ticket = await _eol_ticket(world)
        reconcile.fail_after[ticket.id] = RuntimeError("example failure")

        run = await _run(runs)

        assert run.status == "failure"
        assert run.error_message == "All 1 items failed"
        assert _run_metrics(run) == (0, 0, 0, 1)
        assert await _state(world, ticket) == _unchanged(ANALYZED)

    async def test_mixed_product_and_ticket_outcomes(
        self,
        world: CommittedWorld,
        runs: _Runs,
        dispatcher: DispatchRecorder,
        reconcile: _ReconcileSpy,
    ) -> None:
        """Product and Ticket candidates are independent units, even for
        a Ticket whose tree also holds a mismatched Product."""
        dispatched, failing = sorted(
            [await _mismatched_product(world) for _ in range(2)], key=_by_id
        )
        dispatcher.failures[failing.id] = RuntimeError("example failure")
        resolving = await _eol_ticket(world)
        shared = await _product(world, "reactive")
        await _track(world, resolving, PackageStatus.NOT_AFFECTED, shared)
        regressing = await _regressing_ticket(world)
        broken = await _eol_ticket(world)
        reconcile.fail_after[broken.id] = RuntimeError("example failure")
        mismatched = sorted([dispatched.id, failing.id, shared.id])

        with capture_logs() as logs:
            run = await _run(runs)

        assert run.status == "partial"
        assert _run_metrics(run) == (4, 0, 2, 2)
        assert dispatcher.product_ids == mismatched
        assert reconcile.ticket_ids == [resolving.id, regressing.id, broken.id]
        assert _logged(logs, SUMMARY) == [
            _summary(
                products=3,
                dispatched=2,
                dispatch_failed=1,
                tickets=3,
                tickets_changed=2,
                tickets_failed=1,
            )
        ]
        assert await _state(world, resolving) == _changed(ANALYZED, RESOLVED)
        assert await _state(world, regressing) == _changed(RESOLVED, ANALYZED)
        assert await _state(world, broken) == _unchanged(ANALYZED)

    async def test_empty_candidate_sets(
        self,
        world: CommittedWorld,
        runs: _Runs,
        units: _UnitSessions,
        dispatcher: DispatchRecorder,
        reconcile: _ReconcileSpy,
    ) -> None:
        """Converged Products and Tickets are excluded before selection."""
        converged = await _converged_ticket(world)
        await _track(
            world, converged, PackageStatus.NOT_AFFECTED, await _product(world)
        )

        with capture_logs() as logs:
            run = await _run(runs)

        assert run.status == "success"
        assert _run_metrics(run) == (0, 0, 0, 0)
        assert (run.error_message, run.error_detail) == (None, None)
        assert dispatcher.calls == []
        assert reconcile.calls == []
        assert units.sessions == []
        assert _logged(logs, SUMMARY) == [_summary()]

    async def test_product_scan_failure_is_a_whole_run_failure(
        self,
        world: CommittedWorld,
        runs: _Runs,
        units: _UnitSessions,
        dispatcher: DispatchRecorder,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        await _mismatched_product(world)
        ticket = await _eol_ticket(world)
        error = OperationalError("SELECT", None, Exception("fictional outage"))

        async def failing_scan(db: AsyncSession, **kwargs: Any) -> frozenset[Any]:
            await db.execute(select(1))
            raise error

        monkeypatch.setattr(
            evaluator, "find_product_eligibility_mismatches", failing_scan
        )

        raised, run = await _run_failing(runs, OperationalError)

        assert raised is error
        assert run.status == "failure"
        assert run.error_message == "Unexpected error"
        assert _run_metrics(run) == (0, 0, 0, 0)
        assert dispatcher.calls == []
        assert units.sessions == []
        assert await _state(world, ticket) == _unchanged(ANALYZED)

    async def test_ticket_enumeration_failure_is_a_whole_run_failure(
        self,
        world: CommittedWorld,
        runs: _Runs,
        units: _UnitSessions,
        dispatcher: DispatchRecorder,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The earlier Product dispatch keeps its success metric for
        diagnostics; no synthetic per-Ticket outcome is recorded."""
        product = await _mismatched_product(world)
        ticket = await _eol_ticket(world)
        error = OperationalError("SELECT", None, Exception("fictional outage"))

        async def failing_enumeration(
            db: AsyncSession, **kwargs: Any
        ) -> Sequence[uuid.UUID]:
            await db.execute(select(1))
            raise error

        monkeypatch.setattr(
            evaluator, "find_lifecycle_gate_mismatches", failing_enumeration
        )

        raised, run = await _run_failing(runs, OperationalError)

        assert raised is error
        assert run.status == "failure"
        assert run.error_message == "Unexpected error"
        assert _run_metrics(run) == (1, 0, 0, 0)
        assert dispatcher.calls == [(product.id, "reactive_ltss")]
        assert units.sessions == []
        assert await _state(world, ticket) == _unchanged(ANALYZED)

    async def test_ticket_commit_failure_terminates_the_run(
        self,
        world: CommittedWorld,
        runs: _Runs,
        units: _UnitSessions,
        reconcile: _ReconcileSpy,
    ) -> None:
        """Lifecycle per-unit finalizer exception (testing-strategy.md):
        the middle Ticket's commit failure terminates the run before any
        terminal or effect metric for it; it is neither logged nor counted
        as an isolated failure, the earlier unit's metrics are preserved,
        and the later Ticket is not processed."""
        first, middle, last = [await _eol_ticket(world) for _ in range(3)]
        error = OperationalError("COMMIT", None, Exception("fictional reset"))
        units.failing_commit = (1, error)

        with capture_logs() as logs:
            raised, run = await _run_failing(runs, OperationalError)

        assert raised is error
        assert run.status == "failure"
        assert run.error_message == "Unexpected error"
        assert _run_metrics(run) == (1, 0, 1, 0)
        assert reconcile.ticket_ids == [first.id, middle.id]
        assert reconcile.results[middle.id].changed
        assert _logged(logs, TICKET_FAILED) == []
        assert _logged(logs, SUMMARY) == []
        assert await _state(world, first) == _changed(ANALYZED, RESOLVED)
        assert await _state(world, middle) == _unchanged(ANALYZED)
        assert await _state(world, last) == _unchanged(ANALYZED)

    async def test_soft_time_limit_in_a_ticket_unit_fails_the_run(
        self, world: CommittedWorld, runs: _Runs, reconcile: _ReconcileSpy
    ) -> None:
        first, middle, last = [await _eol_ticket(world) for _ in range(3)]
        reconcile.fail_after[middle.id] = SoftTimeLimitExceeded()

        raised, run = await _run_failing(runs, SoftTimeLimitExceeded)

        assert raised is reconcile.fail_after[middle.id]
        assert run.status == "failure"
        assert run.error_message == (
            "Execution reached the soft time limit (hard limit for this run: "
            "3600s; 1 items processed). Review FetcherConfig.run_timeout for "
            f"future runs of fetcher '{NAME}'."
        )
        assert _run_metrics(run) == (1, 0, 1, 0)
        assert await _state(world, first) == _changed(ANALYZED, RESOLVED)
        assert await _state(world, middle) == _unchanged(ANALYZED)
        assert await _state(world, last) == _unchanged(ANALYZED)


# ---------------------------------------------------------------------------
# Whole-run signals (SoftTimeLimitExceeded handling convention)
# ---------------------------------------------------------------------------


@pytest.mark.integration
@pytest.mark.usefixtures("units")
class TestWholeRunSignals:
    @pytest.mark.parametrize("make_signal", _WHOLE_RUN_SIGNALS)
    async def test_signal_from_a_product_dispatch_propagates(
        self,
        world: CommittedWorld,
        units: _UnitSessions,
        dispatcher: DispatchRecorder,
        reconcile: _ReconcileSpy,
        make_signal: Callable[[], BaseException],
    ) -> None:
        first, _ = sorted(
            [await _mismatched_product(world) for _ in range(2)], key=_by_id
        )
        ticket = await _eol_ticket(world)
        signal = make_signal()
        dispatcher.failures[first.id] = signal

        with capture_logs() as logs:
            raised, fetcher = await _execute_failing(world, type(signal))

        assert raised is signal
        assert dispatcher.product_ids == [first.id]
        assert _metrics(fetcher) == (0, 0, 0, 0)
        assert _logged(logs, DISPATCH_FAILED) == []
        assert _logged(logs, SUMMARY) == []
        assert reconcile.calls == []
        assert units.sessions == []
        assert await _state(world, ticket) == _unchanged(ANALYZED)

    @pytest.mark.parametrize("make_signal", _WHOLE_RUN_SIGNALS)
    async def test_signal_from_a_ticket_unit_propagates(
        self,
        world: CommittedWorld,
        reconcile: _ReconcileSpy,
        make_signal: Callable[[], BaseException],
    ) -> None:
        """The interrupted Ticket is rolled back, the earlier commit
        remains, and the later Ticket is not processed."""
        first, middle, last = [await _eol_ticket(world) for _ in range(3)]
        signal = make_signal()
        reconcile.fail_after[middle.id] = signal

        with capture_logs() as logs:
            raised, fetcher = await _execute_failing(world, type(signal))

        assert raised is signal
        assert reconcile.ticket_ids == [first.id, middle.id]
        assert _metrics(fetcher) == (1, 0, 1, 0)
        assert _logged(logs, TICKET_FAILED) == []
        assert _logged(logs, SUMMARY) == []
        assert await _state(world, first) == _changed(ANALYZED, RESOLVED)
        assert await _state(world, middle) == _unchanged(ANALYZED)
        assert await _state(world, last) == _unchanged(ANALYZED)


# ---------------------------------------------------------------------------
# Scope, dispatch arguments, and the single evaluation date
# ---------------------------------------------------------------------------


@pytest.mark.integration
@pytest.mark.usefixtures("units")
class TestScope:
    async def test_manual_zone_and_new_tickets_and_included_occurrences(
        self,
        world: CommittedWorld,
        dispatcher: DispatchRecorder,
        reconcile: _ReconcileSpy,
    ) -> None:
        """`New`, `Ignored`, and `Duplicated` Tickets whose trees would
        gate to `Resolved` are never reconciled. The Product scan includes
        a directly excluded occurrence, an EOL occurrence, and a `New`
        Ticket's occurrence, but not a manual-zone Ticket's. Each gate-zone
        Ticket keeps an actionable `ANALYSIS` blocker track."""
        selected: list[uuid.UUID] = []
        included: list[tuple[Lifecycle, bool]] = [("supported", True), ("eol", False)]
        for lifecycle, excluded in included:
            ticket = await _ticket(world, ANALYSIS)
            await _track(world, ticket, PackageStatus.ANALYSIS, await _product(world))
            product = await _product(world, lifecycle)
            await _track(
                world,
                ticket,
                PackageStatus.ANALYSIS,
                product,
                eligible=False,
                excluded=excluded,
            )
            selected.append(product.id)
        outside: dict[Ticket, TicketStatus] = {}
        for status in (
            TicketStatus.NEW,
            TicketStatus.IGNORED,
            TicketStatus.DUPLICATED,
        ):
            ticket = await _eol_ticket(world, status)
            product = await _product(world)
            await _track(world, ticket, PackageStatus.ANALYSIS, product, eligible=False)
            outside[ticket] = status
            if status is TicketStatus.NEW:
                selected.append(product.id)

        fetcher = await _execute(world)

        assert _metrics(fetcher) == (3, 0, 0, 0)
        assert dispatcher.calls == [
            (product_id, "reactive_ltss") for product_id in sorted(selected)
        ]
        assert reconcile.calls == []
        for ticket, status in outside.items():
            assert await _state(world, ticket) == _unchanged(status)

    async def test_dispatch_publishes_string_arguments_in_product_id_order(
        self, world: CommittedWorld, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The production dispatch chain down to a substituted
        `task_publication.publish_task()`; no broker is reached."""
        products = [await _mismatched_product(world) for _ in range(3)]
        published: list[tuple[str, dict[str, str]]] = []

        async def publish(task_name: str, *, kwargs: Mapping[str, str]) -> None:
            published.append((task_name, dict(kwargs)))

        monkeypatch.setattr(
            evaluator,
            "dispatch_product_eligibility_recalculation",
            dispatch_product_eligibility_recalculation,
        )
        monkeypatch.setattr(task_publication, "publish_task", publish)

        fetcher = await _execute(world)

        assert _metrics(fetcher) == (3, 0, 0, 0)
        assert published == [
            (
                "re_evaluate_product_eligibility",
                {"catalog_product_id": str(product_id), "reason": "reactive_ltss"},
            )
            for product_id in sorted(product.id for product in products)
        ]

    async def test_one_evaluation_date_reaches_every_delegate(
        self,
        world: CommittedWorld,
        reconcile: _ReconcileSpy,
        clock: Mock,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The clock is read once even when a second read would cross
        midnight UTC: the Product scan, the Ticket selection, and every
        reconciliation receive the same `evaluation_date`."""
        clock.side_effect = [EVAL, NEXT_DAY]
        await _mismatched_product(world)
        tickets = [await _eol_ticket(world), await _regressing_ticket(world)]
        dates: list[tuple[str, date]] = []

        async def scan(db: AsyncSession, *, evaluation_date: date) -> frozenset[Any]:
            dates.append(("products", evaluation_date))
            return await _REAL_FIND_PRODUCTS(db, evaluation_date=evaluation_date)

        async def enumerate_tickets(
            db: AsyncSession, *, evaluation_date: date
        ) -> Sequence[uuid.UUID]:
            dates.append(("tickets", evaluation_date))
            return await _REAL_FIND_TICKETS(db, evaluation_date=evaluation_date)

        monkeypatch.setattr(evaluator, "find_product_eligibility_mismatches", scan)
        monkeypatch.setattr(
            evaluator, "find_lifecycle_gate_mismatches", enumerate_tickets
        )

        fetcher = await _execute(world)

        clock.assert_called_once_with()
        assert dates == [("products", EVAL), ("tickets", EVAL)]
        assert reconcile.ticket_ids == [ticket.id for ticket in tickets]
        assert [call.evaluation_date for call in reconcile.calls] == [EVAL, EVAL]
        assert _metrics(fetcher) == (3, 0, 2, 0)


# ---------------------------------------------------------------------------
# Transaction boundaries (Algorithm steps 2-5)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestTransactionBoundaries:
    async def test_reads_end_before_dispatch_and_each_ticket_has_its_own_unit(
        self,
        world: CommittedWorld,
        units: _UnitSessions,
        dispatcher: DispatchRecorder,
        reconcile: _ReconcileSpy,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        products = sorted(
            [await _mismatched_product(world) for _ in range(2)], key=_by_id
        )
        tickets = [await _eol_ticket(world) for _ in range(2)]
        session = await world.open_session()
        sequence: list[str] = []
        original_commit = session.commit

        async def recording_commit() -> None:
            await original_commit()
            sequence.append("commit")

        async def scan(db: AsyncSession, **kwargs: Any) -> frozenset[Any]:
            assert db is session
            sequence.append("scan")
            return await _REAL_FIND_PRODUCTS(db, **kwargs)

        async def enumerate_tickets(
            db: AsyncSession, **kwargs: Any
        ) -> Sequence[uuid.UUID]:
            assert db is session
            sequence.append("enumerate")
            return await _REAL_FIND_TICKETS(db, **kwargs)

        monkeypatch.setattr(session, "commit", recording_commit)
        monkeypatch.setattr(evaluator, "find_product_eligibility_mismatches", scan)
        monkeypatch.setattr(
            evaluator, "find_lifecycle_gate_mismatches", enumerate_tickets
        )
        dispatcher.events = sequence
        dispatcher.session = session
        units.events = sequence
        units.observed = session

        fetcher = EvaluateLifecycleTransitions()
        await fetcher.execute(session)

        assert sequence == [
            "scan",
            "commit",
            "dispatch",
            "dispatch",
            "enumerate",
            "commit",
            "unit",
            "unit",
        ]
        assert dispatcher.in_transaction == [False, False]
        assert units.observed_in_transaction == [False, False]
        assert dispatcher.product_ids == [product.id for product in products]
        assert [call.session for call in reconcile.calls] == units.sessions
        assert len({id(s) for s in (session, *units.sessions)}) == 3
        assert not session.in_transaction()
        assert _metrics(fetcher) == (4, 0, 2, 0)
        for ticket in tickets:
            assert await _state(world, ticket) == _changed(ANALYZED, RESOLVED)


# ---------------------------------------------------------------------------
# Ticket audit events (TicketAuditEvent Records; ticket-audit-log.md TR 12)
# ---------------------------------------------------------------------------


async def _marker_count(world: CommittedWorld, ticket: Ticket) -> int:
    """The Ticket's set package, track, and Product exclusion markers."""
    probe = await world.open_session()
    packages = select(TicketPackage.id).where(TicketPackage.ticket_id == ticket.id)
    tracks = select(TicketPackageTrack.id).where(
        TicketPackageTrack.ticket_package_id.in_(packages)
    )
    total = 0
    for statement in (
        select(func.count())
        .select_from(TicketPackage)
        .where(
            TicketPackage.ticket_id == ticket.id, TicketPackage.deleted_at.is_not(None)
        ),
        select(func.count())
        .select_from(TicketPackageTrack)
        .where(
            TicketPackageTrack.id.in_(tracks),
            TicketPackageTrack.deleted_at.is_not(None),
        ),
        select(func.count())
        .select_from(TicketPackageProduct)
        .where(
            TicketPackageProduct.ticket_package_track_id.in_(tracks),
            TicketPackageProduct.deleted_at.is_not(None),
        ),
    ):
        total += (await probe.execute(statement)).scalar_one()
    await probe.rollback()
    return total


@pytest.mark.integration
@pytest.mark.usefixtures("units")
class TestAuditEvents:
    async def test_eol_driven_status_change_is_one_system_status_change(
        self, world: CommittedWorld
    ) -> None:
        """No exclusion or restoration event and no marker write: only the
        system `status_change` (`user_id`, `comment`, `detail` NULL)."""
        ticket = await _eol_ticket(world)

        await _execute(world)

        assert await _state(world, ticket) == _State(
            RESOLVED.value,
            [EventRow("status_change", None, "Analyzed", "Resolved", None, None)],
        )
        assert await _marker_count(world, ticket) == 0

    async def test_product_dispatch_creates_no_ticket_event(
        self, world: CommittedWorld, dispatcher: DispatchRecorder
    ) -> None:
        """Workflow-only dispatch outcome: the dispatched and the failed
        dispatch change no eligibility and create no Ticket event."""
        dispatched, failing = sorted(
            [await _mismatched_product(world) for _ in range(2)], key=_by_id
        )
        dispatcher.failures[failing.id] = RuntimeError("example failure")

        fetcher = await _execute(world)

        assert _metrics(fetcher) == (1, 0, 0, 1)
        for product in (dispatched, failing):
            assert await _stored_eligibility(world, product) == [True]
        probe = await world.open_session()
        count = await probe.scalar(
            select(func.count())
            .select_from(TicketAuditEvent)
            .where(TicketAuditEvent.ticket_id.in_(world.ticket_ids))
        )
        await probe.rollback()
        assert count == 0

    async def test_pure_eol_entry_and_exit_create_no_event(
        self,
        world: CommittedWorld,
        clock: Mock,
        reconcile: _ReconcileSpy,
    ) -> None:
        """An `Analysis` Ticket keeps an actionable `ANALYSIS` blocker
        while its boundary Product enters EOL on NEXT_DAY and leaves it
        again after a lifecycle correction: no run selects or changes it."""
        ticket = await _ticket(world, ANALYSIS)
        await _track(world, ticket, PackageStatus.ANALYSIS, await _product(world))
        boundary = await _product(world, "boundary")
        await _track(world, ticket, PackageStatus.AFFECTED, boundary)
        observed: list[Metrics] = []

        observed.append(_metrics(await _execute(world)))
        clock.return_value = NEXT_DAY
        observed.append(_metrics(await _execute(world)))
        await world.session.execute(
            update(Product)
            .where(Product.id == boundary.id)
            .values(general_support_end_date=AFTER_EVAL)
        )
        await world.session.commit()
        observed.append(_metrics(await _execute(world)))

        assert observed == [(0, 0, 0, 0)] * 3
        assert reconcile.calls == []
        assert await _state(world, ticket) == _unchanged(ANALYSIS)
        assert await _marker_count(world, ticket) == 0


# ---------------------------------------------------------------------------
# End to end: committed effects of complete runs and idempotency
# ---------------------------------------------------------------------------


@pytest.mark.integration
@pytest.mark.usefixtures("units")
class TestEndToEnd:
    async def test_runs_converge_and_a_second_run_selects_nothing(
        self,
        world: CommittedWorld,
        runs: _Runs,
        real_session_factory: async_sessionmaker[AsyncSession],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A `Resolved` Ticket whose Product leaves EOL through a committed
        AIMAAS correction regresses to `Analyzed` (its convergence effect
        is discarded unpublished); a Reactive Support Product with a stale
        `true` is dispatched once with `reason = reactive_ltss`. After the
        dispatched sub-task workflow converges the Product, a second run
        selects nothing."""
        send_task = Mock(side_effect=AssertionError("must not publish"))
        monkeypatch.setattr(celery_app, "send_task", send_task)
        published: list[tuple[str, dict[str, str]]] = []

        async def publish(task_name: str, *, kwargs: Mapping[str, str]) -> None:
            published.append((task_name, dict(kwargs)))

        monkeypatch.setattr(
            evaluator,
            "dispatch_product_eligibility_recalculation",
            dispatch_product_eligibility_recalculation,
        )
        monkeypatch.setattr(task_publication, "publish_task", publish)
        monkeypatch.setattr(recalculation, "_utc_today", Mock(return_value=EVAL))

        regressed = await _ticket(world, RESOLVED)
        corrected = await _product(world, "eol")
        await _track(world, regressed, PackageStatus.AFFECTED, corrected)
        reactive = await _product(world, "reactive")
        holder = await _ticket(world, ANALYSIS)
        await _track(world, holder, PackageStatus.ANALYSIS, reactive)
        await world.session.execute(
            update(Product)
            .where(Product.id == corrected.id)
            .values(general_support_end_date=AFTER_EVAL)
        )
        await world.session.commit()

        first = await _run(runs)

        assert (first.status, _run_metrics(first)) == ("success", (2, 0, 1, 0))
        assert published == [
            (
                "re_evaluate_product_eligibility",
                {"catalog_product_id": str(reactive.id), "reason": "reactive_ltss"},
            )
        ]
        send_task.assert_not_called()
        assert await _state(world, regressed) == _changed(RESOLVED, ANALYZED)
        assert await _stored_eligibility(world, reactive) == [True]

        summary = await re_evaluate_product_eligibility(
            reactive.id, "reactive_ltss", session_factory=real_session_factory
        )
        assert (summary.candidates, summary.changed_records) == (1, 1)

        second = await _run(runs)

        assert (second.status, _run_metrics(second)) == ("success", (0, 0, 0, 0))
        assert len(published) == 1
        assert await _stored_eligibility(world, reactive) == [False]
        assert await _state(world, regressed) == _changed(RESOLVED, ANALYZED)
        holder_events = (await _state(world, holder)).events
        assert [
            (e.event_type, e.user_id, e.detail["reason"]) for e in holder_events
        ] == [("product_eligibility_changed", None, "reactive_ltss")]


# ---------------------------------------------------------------------------
# catch_up() (Catch-Up; fetcher-infrastructure.md Interface contract)
# ---------------------------------------------------------------------------


async def _missing(world: CommittedWorld) -> tuple[str, TicketStatus | None]:
    return str(uuid.uuid4()), None


async def _empty_tree(world: CommittedWorld) -> tuple[str, TicketStatus | None]:
    """An `Analyzed` Ticket without packages: its gates evaluate to
    `Analysis`, but an empty package tree returns silently."""
    return str((await _ticket(world, ANALYZED)).id), ANALYZED


async def _converged(world: CommittedWorld) -> tuple[str, TicketStatus | None]:
    return str((await _converged_ticket(world)).id), ANALYZED


def _outside(
    status: TicketStatus,
) -> Callable[[CommittedWorld], Awaitable[tuple[str, TicketStatus | None]]]:
    async def _build(world: CommittedWorld) -> tuple[str, TicketStatus | None]:
        return str((await _eol_ticket(world, status)).id), status

    return _build


_SILENT_CASES = [
    pytest.param(_missing, id="missing-ticket"),
    pytest.param(_empty_tree, id="empty-tree"),
    pytest.param(_converged, id="converged"),
    pytest.param(_outside(TicketStatus.NEW), id="new"),
    pytest.param(_outside(TicketStatus.IGNORED), id="ignored"),
    pytest.param(_outside(TicketStatus.DUPLICATED), id="duplicated"),
]


async def _status_of(world: CommittedWorld, ticket_id: str) -> _State | None:
    probe = await world.open_session()
    status = (
        await probe.execute(
            select(Ticket.status).where(Ticket.id == uuid.UUID(ticket_id))
        )
    ).scalar_one_or_none()
    events = await ticket_events_by_id(probe, uuid.UUID(ticket_id))
    await probe.rollback()
    return None if status is None else _State(status, events)


async def _catch_up_ticket(world: CommittedWorld) -> tuple[Ticket, Product]:
    """An `Analyzed` Ticket whose `AFFECTED` track holds an EOL Product
    and whose `NOT_AFFECTED` track holds a Reactive Support Product with a
    stale stored `true`: it gates to `Resolved` on `EVAL`."""
    ticket = await _eol_ticket(world)
    reactive = await _product(world, "reactive")
    await _track(world, ticket, PackageStatus.NOT_AFFECTED, reactive)
    return ticket, reactive


@pytest.mark.integration
class TestCatchUp:
    @pytest.mark.parametrize("build", _SILENT_CASES)
    async def test_silent_return_opens_no_mutation_session(
        self,
        world: CommittedWorld,
        units: _UnitSessions,
        reconcile: _ReconcileSpy,
        build: Callable[[CommittedWorld], Awaitable[tuple[str, TicketStatus | None]]],
    ) -> None:
        ticket_id, status = await build(world)
        session = await world.open_session()

        with capture_logs() as logs, SessionStatementRecorder(session) as recorder:
            await EvaluateLifecycleTransitions().catch_up(ticket_id, session)

        assert units.sessions == []
        assert reconcile.calls == []
        assert logs == []
        assert len(recorder.statements) == 1
        assert recorder.writes() == []
        assert recorder.row_locks() == []
        assert not session.in_transaction()
        expected = None if status is None else _unchanged(status)
        assert await _status_of(world, ticket_id) == expected

    async def test_mismatch_commits_one_reconciliation_in_an_independent_session(
        self,
        world: CommittedWorld,
        units: _UnitSessions,
        reconcile: _ReconcileSpy,
        dispatcher: DispatchRecorder,
        clock: Mock,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The passed session only reads; one independent session commits
        the delegated reconciliation with the one captured date. Product
        eligibility is never recalculated: the stale Reactive Support
        occurrence keeps its stored `true` and no eligibility event
        exists."""
        ticket, reactive = await _catch_up_ticket(world)
        scan = Mock(side_effect=AssertionError("must not scan Products"))
        monkeypatch.setattr(evaluator, "find_product_eligibility_mismatches", scan)
        session = await world.open_session()

        with capture_logs() as logs, SessionStatementRecorder(session) as recorder:
            await EvaluateLifecycleTransitions().catch_up(str(ticket.id), session)

        clock.assert_called_once_with()
        assert len(units.sessions) == 1
        assert units.sessions[0] is not session
        assert reconcile.calls == [_Call(units.sessions[0], ticket.id, EVAL)]
        assert len(recorder.statements) == 1
        assert recorder.writes() == []
        assert recorder.row_locks() == []
        assert logs == [
            {
                "event": CATCH_UP_RECONCILED,
                "log_level": "info",
                "ticket_id": str(ticket.id),
                "changed": True,
            }
        ]
        assert await _state(world, ticket) == _changed(ANALYZED, RESOLVED)
        assert await _stored_eligibility(world, reactive) == [True]
        scan.assert_not_called()
        assert dispatcher.calls == []

    async def test_pre_commit_failure_propagates(
        self,
        world: CommittedWorld,
        units: _UnitSessions,
        reconcile: _ReconcileSpy,
    ) -> None:
        ticket, _ = await _catch_up_ticket(world)
        error = RuntimeError("example failure")
        reconcile.fail_after[ticket.id] = error

        with capture_logs() as logs, pytest.raises(RuntimeError) as raised:
            await EvaluateLifecycleTransitions().catch_up(
                str(ticket.id), await world.open_session()
            )

        assert raised.value is error
        assert len(units.sessions) == 1
        assert logs == []
        assert await _state(world, ticket) == _unchanged(ANALYZED)

    async def test_commit_failure_propagates(
        self,
        world: CommittedWorld,
        units: _UnitSessions,
        reconcile: _ReconcileSpy,
    ) -> None:
        ticket, _ = await _catch_up_ticket(world)
        error = OperationalError("COMMIT", None, Exception("fictional reset"))
        units.failing_commit = (0, error)

        with capture_logs() as logs, pytest.raises(OperationalError) as raised:
            await EvaluateLifecycleTransitions().catch_up(
                str(ticket.id), await world.open_session()
            )

        assert raised.value is error
        assert reconcile.results[ticket.id].changed
        assert logs == []
        assert await _state(world, ticket) == _unchanged(ANALYZED)


class _CatchUpTask:
    """Routes `run_catch_up_async()` to the test database with a fake
    engine and commits this fetcher's `FetcherConfig` on request."""

    def __init__(self, factory: async_sessionmaker[AsyncSession]) -> None:
        self._factory = factory
        self.engine = SimpleNamespace(dispose=AsyncMock())
        self.configured = False

    async def configure(self, *, enabled: bool) -> None:
        async with self._factory() as session:
            session.add(FetcherConfig(fetcher_name=NAME, enabled=enabled))
            await session.commit()
        self.configured = True


@pytest.fixture
async def catch_up_task(
    real_session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> AsyncIterator[_CatchUpTask]:
    created = _CatchUpTask(real_session_factory)
    monkeypatch.setattr(fetchers, "async_session_factory", real_session_factory)
    monkeypatch.setattr(fetchers, "engine", created.engine)
    try:
        yield created
    finally:
        if created.configured:
            async with real_session_factory() as session:
                await session.execute(
                    delete(FetcherConfig).where(FetcherConfig.fetcher_name == NAME)
                )
                await session.commit()


@pytest.mark.integration
@pytest.mark.usefixtures("units")
class TestRunCatchUpAsync:
    async def test_enabled_fetcher_reconciles_the_mismatch(
        self,
        world: CommittedWorld,
        catch_up_task: _CatchUpTask,
        reconcile: _ReconcileSpy,
    ) -> None:
        ticket, _ = await _catch_up_ticket(world)
        await catch_up_task.configure(enabled=True)

        with capture_logs() as logs:
            await fetchers.run_catch_up_async(NAME, str(ticket.id))

        assert reconcile.ticket_ids == [ticket.id]
        assert [entry for entry in logs if entry["log_level"] == "error"] == []
        assert await _state(world, ticket) == _changed(ANALYZED, RESOLVED)
        catch_up_task.engine.dispose.assert_awaited_once_with()

    async def test_disabled_fetcher_does_not_reconcile(
        self,
        world: CommittedWorld,
        catch_up_task: _CatchUpTask,
        units: _UnitSessions,
        reconcile: _ReconcileSpy,
    ) -> None:
        ticket, _ = await _catch_up_ticket(world)
        await catch_up_task.configure(enabled=False)

        with capture_logs() as logs:
            await fetchers.run_catch_up_async(NAME, str(ticket.id))

        assert [entry["event"] for entry in logs] == ["run_catch_up_fetcher_disabled"]
        assert reconcile.calls == []
        assert units.sessions == []
        assert await _state(world, ticket) == _unchanged(ANALYZED)
        catch_up_task.engine.dispose.assert_awaited_once_with()

    async def test_unknown_fetcher_does_not_reconcile(
        self,
        world: CommittedWorld,
        catch_up_task: _CatchUpTask,
        units: _UnitSessions,
        reconcile: _ReconcileSpy,
    ) -> None:
        ticket, _ = await _catch_up_ticket(world)

        with capture_logs() as logs:
            await fetchers.run_catch_up_async("ghost_lifecycle_fetcher", str(ticket.id))

        assert [entry["event"] for entry in logs] == ["run_catch_up_unknown_fetcher"]
        assert reconcile.calls == []
        assert units.sessions == []
        assert await _state(world, ticket) == _unchanged(ANALYZED)
        catch_up_task.engine.dispose.assert_awaited_once_with()


# ---------------------------------------------------------------------------
# Registration and properties
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestRegistration:
    def test_discovery_registers_the_fetcher(self) -> None:
        assert FETCHER_REGISTRY[NAME] is EvaluateLifecycleTransitions

    def test_properties_match_the_specification(self) -> None:
        assert EvaluateLifecycleTransitions.name == NAME
        assert EvaluateLifecycleTransitions.description == (
            "Reconcile lifecycle-derived Product eligibility and Ticket gate state"
        )
        assert EvaluateLifecycleTransitions.default_schedule == "15 4 * * *"
        assert EvaluateLifecycleTransitions.participates_in_catch_up is True
        assert EvaluateLifecycleTransitions.Settings is None
        assert EvaluateLifecycleTransitions.queue is None

    def test_class_name_is_derived_from_the_fetcher_name(self) -> None:
        derived = "".join(part.capitalize() for part in NAME.split("_"))

        assert derived == EvaluateLifecycleTransitions.__name__

    def test_catch_up_is_a_custom_override(self) -> None:
        """Passes the `participates_in_catch_up` / `catch_up()` consistency
        validation of `BaseFetcher.__init_subclass__`."""
        assert "catch_up" in EvaluateLifecycleTransitions.__dict__
        assert EvaluateLifecycleTransitions.catch_up is not BaseFetcher.catch_up

    def test_fetcher_participates_in_catch_up(self) -> None:
        assert get_catch_up_fetchers()[NAME] is EvaluateLifecycleTransitions

    def test_utc_today_is_the_current_utc_date(self) -> None:
        before = datetime.now(UTC).date()
        today = _REAL_UTC_TODAY()
        after = datetime.now(UTC).date()

        assert type(today) is date
        assert today in {before, after}


@pytest.mark.integration
class TestBootstrap:
    async def test_bootstrap_creates_the_fetcher_config(
        self, db_session: AsyncSession
    ) -> None:
        assert await db_session.get(FetcherConfig, NAME) is None

        await bootstrap_fetcher_configs(db_session)

        config = await db_session.get(FetcherConfig, NAME)
        assert config is not None
        assert config.enabled is True
        assert config.schedule_override is None
        assert config.request_delay == 0
        assert config.custom_settings == {}
