"""Tests for the Product-originated eligibility recalculation workflow
(backend/app/services/packages/product_eligibility_recalculation.py).

Owning specifications:

- docs/features/packages/product-lifecycle-transitions.md (Sub-task:
  `re_evaluate_product_eligibility`: argument validation, steps 1-5, no
  automatic Celery retry). The post-commit convergence drain of step 3 and
  the drain sentence of step 4 are not implemented yet: a registered
  effect is discarded when its Ticket transaction ends and nothing is
  published.
- docs/features/platform/fetcher-infrastructure.md (Celery Integration,
  Result handling: a non-fetcher sub-operation creates no `FetcherRun`).
- docs/features/platform/testing-strategy.md (Concurrency Testing:
  explicit cleanup of committed rows).

The single-Ticket service boundary
`package_service.recalculate_product_eligibility_for_ticket()` is covered
by `tests/test_services/test_recalculate_product_eligibility*.py`; this
module tests only the workflow around it.

Argument validation and the clock are unit tests. Candidate selection runs
against the per-test rolled-back `db_session`. The workflow commits one
transaction per Ticket through `real_session_factory`, so its tests seed a
`CommittedWorld` and delete every committed row at teardown. Unless a test
states otherwise, every Ticket is CVE-less with a `High` manual severity,
every occurrence sits alone on a fresh `ANALYSIS` track of a fresh
package, and the catalog Product is in General Support on `EVAL` with a
`NULL` threshold, so its automatic eligibility is `true`: an occurrence
seeded `false` changes, one seeded `true` is a no-op. The workflow clock is
fixed to `EVAL`.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable, MutableMapping
from dataclasses import dataclass
from datetime import UTC, date, datetime
from typing import Any, cast
from unittest.mock import Mock

import pytest
from celery.app.task import Task
from celery.exceptions import SoftTimeLimitExceeded
from sqlalchemy import delete, event, func, select, update
from sqlalchemy.exc import OperationalError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from sqlalchemy.orm import Session
from structlog.testing import capture_logs

from app.celery_app import celery_app
from app.core.enums import PackageStatus, Role, Severity, TicketStatus
from app.core.exceptions import TicketNotFoundError
from app.models.fetcher_run import FetcherRun
from app.models.product import Product
from app.models.system_setting import SystemSetting
from app.models.ticket import Ticket
from app.models.ticket_package import TicketPackage
from app.models.ticket_package_product import TicketPackageProduct
from app.models.ticket_package_track import TicketPackageTrack
from app.models.user import User
from app.services import package_service
from app.services.package_service import (
    ProductEligibilityRecalculationResult,
    ProductNotFoundError,
    ProductRecalculationReason,
)
from app.services.packages import product_eligibility_recalculation as workflow
from app.services.packages.product_eligibility_recalculation import (
    ProductEligibilityRecalculationSummary,
    parse_recalculation_arguments,
    re_evaluate_product_eligibility,
    select_candidate_ticket_ids,
)
from app.services.ticket_convergence_registry import (
    TicketConvergenceEffect,
    pending_ticket_convergence_effects,
)
from tests.support.cvss_chain import DEFAULT_VERSION, eligibility, ticket_state
from tests.support.suse_cvss_races import CommittedWorld
from tests.support.ticket_mutations import (
    AFTER_EVAL,
    BEFORE_EVAL,
    EVAL,
    EventRow,
    StatementRecorder,
    ticket_events_by_id,
)

Factory = Callable[[], Awaitable[AsyncSession]]
LogEntry = MutableMapping[str, Any]
ProductFactory = Callable[..., Awaitable[Product]]
TicketFactory = Callable[..., Awaitable[Ticket]]
PackageFactory = Callable[..., Awaitable[TicketPackage]]
TrackFactory = Callable[..., Awaitable[TicketPackageTrack]]
OccurrenceFactory = Callable[..., Awaitable[TicketPackageProduct]]
Placer = Callable[..., Awaitable[TicketPackageProduct]]

_REAL_SERVICE = package_service.recalculate_product_eligibility_for_ticket
_REAL_SELECT = workflow.select_candidate_ticket_ids
_REAL_UTC_TODAY = workflow._utc_today

COMPLETED = "product_eligibility_recalculation_completed"
TICKET_FAILED = "product_eligibility_recalculation_ticket_failed"

CHANGED = ("product_eligibility_changed", "false", "true")
"""A system `product_eligibility_changed` from `false` to `true`."""

OPERABLE = (
    TicketStatus.NEW,
    TicketStatus.ANALYSIS,
    TicketStatus.ANALYZED,
    TicketStatus.RESOLVED,
)

_WHOLE_RUN_SIGNALS = [
    pytest.param(SoftTimeLimitExceeded, id="soft-time-limit"),
    pytest.param(MemoryError, id="memory-error"),
    pytest.param(asyncio.CancelledError, id="cancelled"),
]


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _events(logs: list[LogEntry], name: str) -> list[LogEntry]:
    return [entry for entry in logs if entry["event"] == name]


def _level(logs: list[LogEntry], level: str) -> list[LogEntry]:
    return [entry for entry in logs if entry["log_level"] == level]


def _completed(
    product_id: uuid.UUID,
    reason: str,
    summary: ProductEligibilityRecalculationSummary,
) -> LogEntry:
    """The exact completion log of a run (Sub-task step 5)."""
    return {
        "event": COMPLETED,
        "log_level": "info",
        "catalog_product_id": str(product_id),
        "reason": reason,
        "candidates": summary.candidates,
        "successful": summary.successful,
        "skipped": summary.skipped,
        "no_op": summary.no_op,
        "changed_records": summary.changed_records,
        "failed": summary.failed,
    }


def _summary(
    *,
    candidates: int,
    successful: int,
    skipped: int = 0,
    no_op: int = 0,
    changed_records: int = 0,
    failed: int = 0,
) -> ProductEligibilityRecalculationSummary:
    return ProductEligibilityRecalculationSummary(
        candidates=candidates,
        successful=successful,
        skipped=skipped,
        no_op=no_op,
        changed_records=changed_records,
        failed=failed,
    )


@pytest.fixture(autouse=True)
def clock(monkeypatch: pytest.MonkeyPatch) -> Mock:
    """The workflow's UTC clock, fixed to `EVAL`."""
    today = Mock(return_value=EVAL)
    monkeypatch.setattr(workflow, "_utc_today", today)
    return today


# ---------------------------------------------------------------------------
# Argument validation (Sub-task: "validates `reason` and
# `catalog_product_id` before opening a database session")
# ---------------------------------------------------------------------------


_REASONS: list[ProductRecalculationReason] = ["threshold", "reactive_ltss"]

REASON_ERROR = "unsupported Product eligibility recalculation reason"
PRODUCT_ERROR = "catalog_product_id must be a UUID"

_INVALID_REASONS = [
    pytest.param("reactivation", id="reactivation"),
    pytest.param("cvss", id="cvss"),
    pytest.param("va_override", id="va-override"),
    pytest.param("THRESHOLD", id="wrong-case"),
    pytest.param("", id="empty"),
    pytest.param(None, id="none"),
    pytest.param(1, id="integer"),
    pytest.param(b"threshold", id="bytes"),
]

_INVALID_PRODUCT_IDS = [
    pytest.param("not-a-uuid", id="non-uuid-string"),
    pytest.param("", id="empty-string"),
    pytest.param("cpe:/o:example:product:1", id="cpe"),
    pytest.param(12345, id="integer"),
    pytest.param(None, id="none"),
    pytest.param(b"0192f0c4-0000-7000-8000-000000000001", id="bytes"),
]


@pytest.mark.unit
class TestParseRecalculationArguments:
    @pytest.mark.parametrize("reason", _REASONS)
    def test_uuid_string_is_converted(self, reason: str) -> None:
        product_id = uuid.uuid4()

        with capture_logs() as logs:
            parsed = parse_recalculation_arguments(str(product_id), reason)

        assert parsed == (product_id, reason)
        assert type(parsed[0]) is uuid.UUID
        assert logs == []

    @pytest.mark.parametrize("reason", _REASONS)
    def test_uuid_instance_is_returned_unchanged(self, reason: str) -> None:
        product_id = uuid.uuid4()

        with capture_logs() as logs:
            parsed = parse_recalculation_arguments(product_id, reason)

        assert parsed[0] is product_id
        assert parsed[1] == reason
        assert logs == []

    @pytest.mark.parametrize("reason", _INVALID_REASONS)
    def test_unsupported_reason_logs_one_error_without_value(
        self, reason: object
    ) -> None:
        with capture_logs() as logs, pytest.raises(ValueError, match=REASON_ERROR):
            parse_recalculation_arguments(str(uuid.uuid4()), reason)

        assert logs == [
            {
                "event": "product_eligibility_recalculation_invalid_reason",
                "log_level": "error",
            }
        ]

    @pytest.mark.parametrize("product_id", _INVALID_PRODUCT_IDS)
    @pytest.mark.parametrize("reason", _REASONS)
    def test_malformed_product_id_logs_one_error_without_value(
        self, product_id: object, reason: str
    ) -> None:
        with capture_logs() as logs, pytest.raises(ValueError, match=PRODUCT_ERROR):
            parse_recalculation_arguments(product_id, reason)

        assert logs == [
            {
                "event": "product_eligibility_recalculation_invalid_product_id",
                "log_level": "error",
            }
        ]

    def test_reason_is_validated_first(self) -> None:
        """Both arguments invalid: one ERROR, naming the reason."""
        with capture_logs() as logs, pytest.raises(ValueError, match=REASON_ERROR):
            parse_recalculation_arguments("not-a-uuid", "reactivation")

        assert [entry["event"] for entry in _level(logs, "error")] == [
            "product_eligibility_recalculation_invalid_reason"
        ]


@pytest.mark.unit
def test_utc_today_is_the_current_utc_date() -> None:
    before = datetime.now(UTC).date()
    today = _REAL_UTC_TODAY()
    after = datetime.now(UTC).date()

    assert type(today) is date
    assert today in {before, after}


# ---------------------------------------------------------------------------
# Candidate selection (Sub-task step 2)
# ---------------------------------------------------------------------------


@pytest.fixture
def place(
    ticket_package_factory: PackageFactory,
    ticket_package_track_factory: TrackFactory,
    ticket_package_product_factory: OccurrenceFactory,
) -> Placer:
    """Place one occurrence of a catalog Product in a Ticket, on the track
    `track_id` or on a fresh track (of `status`) of the package
    `package_id` or of a fresh package."""

    async def _create(
        ticket: Ticket,
        product: Product,
        *,
        status: PackageStatus = PackageStatus.ANALYSIS,
        package_id: uuid.UUID | None = None,
        track_id: uuid.UUID | None = None,
        override: bool = False,
        excluded: bool = False,
        track_excluded: bool = False,
        package_excluded: bool = False,
    ) -> TicketPackageProduct:
        now = datetime.now(UTC)
        if track_id is None:
            if package_id is None:
                package = await ticket_package_factory(
                    ticket_id=ticket.id,
                    deleted_at=now if package_excluded else None,
                )
                package_id = package.id
            track = await ticket_package_track_factory(
                ticket_package_id=package_id,
                status=status.value,
                deleted_at=now if track_excluded else None,
            )
            track_id = track.id
        return await ticket_package_product_factory(
            ticket_package_track_id=track_id,
            product_id=product.id,
            is_eligible_override=override,
            deleted_at=now if excluded else None,
        )

    return _create


@pytest.mark.integration
class TestSelectCandidateTicketIds:
    async def test_only_operable_statuses_are_selected(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        product_factory: ProductFactory,
        place: Placer,
    ) -> None:
        """New, Analysis, Analyzed, and Resolved are operable; Ignored and
        Duplicated remain in the manual zone."""
        product = await product_factory(general_support_end_date=AFTER_EVAL)
        tickets = {
            status: await ticket_factory(status=status.value) for status in TicketStatus
        }
        for ticket in tickets.values():
            await place(ticket, product)

        selected = await select_candidate_ticket_ids(db_session, product.id)

        assert list(selected) == sorted(tickets[status].id for status in OPERABLE)

    async def test_excluded_override_eol_and_every_track_status_are_selected(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        product_factory: ProductFactory,
        place: Placer,
    ) -> None:
        """Each Ticket's only occurrence of an EOL Product is directly or
        effectively excluded, a manual override, or under one of the four
        track statuses: exclusion, actionability, and overrides do not
        suspend factual eligibility maintenance."""
        product = await product_factory(general_support_end_date=BEFORE_EVAL)
        variants: list[dict[str, Any]] = [
            {"excluded": True},
            {"track_excluded": True},
            {"package_excluded": True},
            {"override": True},
            *({"status": status} for status in PackageStatus),
        ]
        expected = []
        for variant in variants:
            ticket = await ticket_factory(status=TicketStatus.ANALYSIS.value)
            await place(ticket, product, **variant)
            expected.append(ticket.id)

        selected = await select_candidate_ticket_ids(db_session, product.id)

        assert list(selected) == sorted(expected)

    async def test_distinct_tickets_in_ticket_id_order(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        product_factory: ProductFactory,
        place: Placer,
    ) -> None:
        """A Ticket with several occurrences (two tracks of one package and
        a second package) appears once; a Ticket containing only another
        Product is not selected. Occurrences are inserted in descending
        Ticket order, so the result order comes from the Ticket ID."""
        product = await product_factory()
        other = await product_factory()
        first, second, third, unrelated = [
            await ticket_factory(status=TicketStatus.ANALYSIS.value) for _ in range(4)
        ]
        assert first.id < second.id < third.id
        await place(unrelated, other)
        await place(third, product)
        shared = await place(second, product)
        track = await db_session.get(TicketPackageTrack, shared.ticket_package_track_id)
        assert track is not None
        await place(second, product, package_id=track.ticket_package_id)
        await place(second, product)
        await place(second, other, track_id=shared.ticket_package_track_id)
        await place(first, product)

        selected = await select_candidate_ticket_ids(db_session, product.id)

        assert list(selected) == [first.id, second.id, third.id]

    async def test_product_without_occurrences_selects_nothing(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        product_factory: ProductFactory,
        place: Placer,
    ) -> None:
        product = await product_factory()
        await place(await ticket_factory(), await product_factory())

        assert list(await select_candidate_ticket_ids(db_session, product.id)) == []

    async def test_selection_is_one_unlocked_read(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        product_factory: ProductFactory,
        place: Placer,
    ) -> None:
        product = await product_factory()
        ticket = await ticket_factory(status=TicketStatus.RESOLVED.value)
        await place(ticket, product)

        with StatementRecorder(db_session) as recorder:
            selected = await select_candidate_ticket_ids(db_session, product.id)

        assert list(selected) == [ticket.id]
        assert len(recorder.statements) == 1
        assert recorder.row_locks() == []
        assert recorder.writes() == []
        assert not db_session.new
        assert not db_session.dirty
        assert not db_session.deleted


# ---------------------------------------------------------------------------
# Committed world for the workflow
# ---------------------------------------------------------------------------


@pytest.fixture
async def world(db_session_factory: Factory) -> AsyncIterator[CommittedWorld]:
    """A `CommittedWorld` that also owns the committed `default_cvss_version`
    setting (the test schema has none), which every recalculation reads."""
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


async def _product(world: CommittedWorld) -> Product:
    """A committed catalog Product in General Support on `EVAL`."""
    suffix = uuid.uuid4().hex[:10]
    product = Product(
        name=f"Example Product {suffix}",
        version="1",
        display_name=f"EP {suffix}",
        cpe=f"cpe:/o:example:product:{suffix}",
        catalog_last_seen_at=datetime.now(UTC),
        general_support_end_date=AFTER_EVAL,
    )
    world.session.add(product)
    await world.session.flush()
    world.product_ids.append(product.id)
    await world.session.commit()
    return product


async def _ticket(
    world: CommittedWorld,
    *,
    status: TicketStatus = TicketStatus.ANALYSIS,
    assignee: User | None = None,
    severity: Severity | None = Severity.HIGH,
) -> Ticket:
    return await world.ticket(
        cve_id=None,
        status=status,
        severity_manual=severity,
        assignee_id=assignee.id if assignee else None,
    )


async def _occurrences(
    world: CommittedWorld,
    ticket: Ticket,
    product: Product,
    *seeded: bool,
    status: PackageStatus = PackageStatus.ANALYSIS,
) -> None:
    """Commit one occurrence per `seeded` eligibility value, each on a fresh
    track of `status` in a fresh package."""
    session = world.session
    for eligible in seeded:
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
            )
        )
    await session.commit()


@dataclass(frozen=True, slots=True)
class _Committed:
    """The committed Ticket status, `(eligible, is_eligible_override)` of its
    occurrences in occurrence-ID order, and `(event_type, old, new)` of its
    audit events in insertion order."""

    status: str
    occurrences: list[tuple[bool, bool]]
    events: list[tuple[str, str | None, str | None]]


def _changes(events: list[EventRow]) -> list[tuple[str, str | None, str | None]]:
    return [(e.event_type, e.old_value, e.new_value) for e in events]


async def _committed(world: CommittedWorld, ticket: Ticket) -> _Committed:
    """The committed state, read through a fresh independent session."""
    probe = await world.open_session()
    committed = _Committed(
        (await ticket_state(probe, ticket.id))[0],
        await eligibility(probe, ticket.id),
        _changes(await ticket_events_by_id(probe, ticket.id)),
    )
    await probe.rollback()
    return committed


async def _committed_reasons(world: CommittedWorld, ticket: Ticket) -> list[Any]:
    probe = await world.open_session()
    events = await ticket_events_by_id(probe, ticket.id)
    await probe.rollback()
    return [e.detail["reason"] for e in events]


class _RecordingFactory:
    """Session factory passed to the workflow: delegates to the real
    factory, records every session it opens (index 0 is the candidate
    selection, then one per Ticket), and optionally makes the commit of
    one session fail."""

    def __init__(self, factory: async_sessionmaker[AsyncSession]) -> None:
        self._factory = factory
        self.sessions: list[AsyncSession] = []
        self.failing_commit: tuple[int, BaseException] | None = None

    def __call__(self) -> AsyncSession:
        session = self._factory()
        if self.failing_commit is not None:
            index, error = self.failing_commit
            if index == len(self.sessions):

                def _fail(_session: Session) -> None:
                    raise error

                event.listen(session.sync_session, "before_commit", _fail)
        self.sessions.append(session)
        return session

    def maker(self) -> async_sessionmaker[AsyncSession]:
        return cast(async_sessionmaker[AsyncSession], self)


@pytest.fixture
def sessions(
    real_session_factory: async_sessionmaker[AsyncSession],
) -> _RecordingFactory:
    return _RecordingFactory(real_session_factory)


@dataclass(frozen=True, slots=True)
class _Call:
    session: AsyncSession
    ticket_id: uuid.UUID
    catalog_product_id: uuid.UUID
    reason: str
    evaluation_date: date | None


class _ServiceSpy:
    """Replaces the workflow's reference to
    `recalculate_product_eligibility_for_ticket()`: records each call and
    delegates to the real service. `fail_after[ticket_id]` is raised after
    the real call has flushed its writes; `fail_instead[ticket_id]` is
    raised without calling the service. `effects` keeps the convergence
    effects pending in the Ticket transaction after the real call."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.calls: list[_Call] = []
        self.results: dict[uuid.UUID, ProductEligibilityRecalculationResult] = {}
        self.effects: dict[uuid.UUID, tuple[TicketConvergenceEffect, ...]] = {}
        self.fail_after: dict[uuid.UUID, BaseException] = {}
        self.fail_instead: dict[uuid.UUID, BaseException] = {}
        monkeypatch.setattr(
            workflow, "recalculate_product_eligibility_for_ticket", self._call
        )

    async def _call(
        self,
        db: AsyncSession,
        ticket_id: uuid.UUID,
        catalog_product_id: uuid.UUID,
        reason: ProductRecalculationReason,
        evaluation_date: date | None = None,
    ) -> ProductEligibilityRecalculationResult:
        self.calls.append(
            _Call(db, ticket_id, catalog_product_id, reason, evaluation_date)
        )
        if ticket_id in self.fail_instead:
            raise self.fail_instead[ticket_id]
        result = await _REAL_SERVICE(
            db, ticket_id, catalog_product_id, reason, evaluation_date=evaluation_date
        )
        self.results[ticket_id] = result
        self.effects[ticket_id] = pending_ticket_convergence_effects(db)
        if ticket_id in self.fail_after:
            raise self.fail_after[ticket_id]
        return result

    @property
    def ticket_ids(self) -> list[uuid.UUID]:
        return [call.ticket_id for call in self.calls]


@pytest.fixture
def service(monkeypatch: pytest.MonkeyPatch) -> _ServiceSpy:
    return _ServiceSpy(monkeypatch)


async def _three_changing_tickets(
    world: CommittedWorld, product: Product
) -> list[Ticket]:
    """Three Analysis Tickets, each with one occurrence seeded `false`."""
    actor = await world.user(role=Role.VULNERABILITY_ANALYST)
    tickets = [await _ticket(world, assignee=actor) for _ in range(3)]
    for ticket in tickets:
        await _occurrences(world, ticket, product, False)
    assert [t.id for t in tickets] == sorted(t.id for t in tickets)
    return tickets


CHANGED_ONCE = _Committed(TicketStatus.ANALYSIS, [(True, False)], [CHANGED])
UNCHANGED = _Committed(TicketStatus.ANALYSIS, [(False, False)], [])


# ---------------------------------------------------------------------------
# Workflow: outcomes and counts (Sub-task steps 1-3 and 5)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestWorkflowOutcomes:
    async def test_no_candidate_is_a_successful_no_op(
        self,
        world: CommittedWorld,
        sessions: _RecordingFactory,
        service: _ServiceSpy,
    ) -> None:
        """Step 5: no candidate Tickets is a successful no-op; only the
        read-only selection session is opened."""
        product = await _product(world)

        with capture_logs() as logs:
            summary = await re_evaluate_product_eligibility(
                product.id, "threshold", session_factory=sessions.maker()
            )

        assert summary == _summary(candidates=0, successful=0)
        assert logs == [_completed(product.id, "threshold", summary)]
        assert len(sessions.sessions) == 1
        assert service.calls == []

    async def test_mixed_outcomes_commit_independently_with_exact_counts(
        self,
        world: CommittedWorld,
        sessions: _RecordingFactory,
        service: _ServiceSpy,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Four candidates: an Analysis Ticket with two changing
        occurrences, a New Ticket with one, a converged Analysis Ticket
        (no-op), and an Analysis Ticket that enters `Ignored` after
        candidate selection (manual-zone skip). Each Ticket is processed in
        its own session and committed independently."""
        actor = await world.user(role=Role.VULNERABILITY_ANALYST)
        product = await _product(world)
        changed_twice = await _ticket(world, assignee=actor)
        changed_new = await _ticket(world, status=TicketStatus.NEW)
        converged = await _ticket(world, assignee=actor)
        ignored = await _ticket(world, assignee=actor)
        await _occurrences(world, changed_twice, product, False, False)
        await _occurrences(world, changed_new, product, False)
        await _occurrences(world, converged, product, True)
        await _occurrences(world, ignored, product, False)
        ordered = [changed_twice.id, changed_new.id, converged.id, ignored.id]
        assert ordered == sorted(ordered)

        async def select_then_ignore(
            db: AsyncSession, catalog_product_id: uuid.UUID
        ) -> Any:
            selected = await _REAL_SELECT(db, catalog_product_id)
            concurrent = await world.open_session()
            await concurrent.execute(
                update(Ticket)
                .where(Ticket.id == ignored.id)
                .values(status=TicketStatus.IGNORED.value)
            )
            await concurrent.commit()
            return selected

        monkeypatch.setattr(workflow, "select_candidate_ticket_ids", select_then_ignore)

        with capture_logs() as logs:
            summary = await re_evaluate_product_eligibility(
                product.id, "threshold", session_factory=sessions.maker()
            )

        expected = _summary(
            candidates=4, successful=4, skipped=1, no_op=1, changed_records=3
        )
        assert summary == expected
        assert logs == [_completed(product.id, "threshold", expected)]
        assert service.ticket_ids == ordered
        assert [call.session for call in service.calls] == sessions.sessions[1:]
        assert len({id(s) for s in sessions.sessions}) == 5
        assert all(call.catalog_product_id == product.id for call in service.calls)
        assert all(call.reason == "threshold" for call in service.calls)
        assert service.results[ignored.id].manual_zone_skipped
        assert await _committed(world, changed_twice) == _Committed(
            TicketStatus.ANALYSIS, [(True, False), (True, False)], [CHANGED, CHANGED]
        )
        assert await _committed(world, changed_new) == _Committed(
            TicketStatus.NEW, [(True, False)], [CHANGED]
        )
        assert await _committed(world, converged) == _Committed(
            TicketStatus.ANALYSIS, [(True, False)], []
        )
        assert await _committed(world, ignored) == _Committed(
            TicketStatus.IGNORED, [(False, False)], []
        )
        assert await _committed_reasons(world, changed_twice) == [
            "threshold",
            "threshold",
        ]

    async def test_one_evaluation_date_and_the_reason_reach_every_ticket(
        self,
        world: CommittedWorld,
        sessions: _RecordingFactory,
        service: _ServiceSpy,
        clock: Mock,
    ) -> None:
        """Step 1: one UTC `evaluation_date` is captured once for the whole
        invocation and passed to every per-Ticket call, as is the
        `reason` recorded in each changed-record event."""
        product = await _product(world)
        tickets = await _three_changing_tickets(world, product)

        summary = await re_evaluate_product_eligibility(
            product.id, "reactive_ltss", session_factory=sessions.maker()
        )

        assert summary == _summary(candidates=3, successful=3, changed_records=3)
        clock.assert_called_once_with()
        assert [call.evaluation_date for call in service.calls] == [EVAL] * 3
        assert [call.reason for call in service.calls] == ["reactive_ltss"] * 3
        for ticket in tickets:
            assert await _committed_reasons(world, ticket) == ["reactive_ltss"]

    async def test_rerun_after_convergence_is_a_no_op(
        self,
        world: CommittedWorld,
        sessions: _RecordingFactory,
        service: _ServiceSpy,
    ) -> None:
        """Re-invocation recomputes from current committed inputs: the
        converged Tickets are successful no-ops without new events."""
        product = await _product(world)
        tickets = await _three_changing_tickets(world, product)
        await re_evaluate_product_eligibility(
            product.id, "threshold", session_factory=sessions.maker()
        )

        summary = await re_evaluate_product_eligibility(
            product.id, "threshold", session_factory=sessions.maker()
        )

        assert summary == _summary(candidates=3, successful=3, no_op=3)
        for ticket in tickets:
            assert await _committed(world, ticket) == CHANGED_ONCE

    async def test_run_creates_no_fetcher_run(
        self,
        world: CommittedWorld,
        sessions: _RecordingFactory,
        service: _ServiceSpy,
    ) -> None:
        """A non-fetcher sub-operation creates no `FetcherRun`
        (fetcher-infrastructure.md, Celery Integration, Result handling)."""
        product = await _product(world)
        await _three_changing_tickets(world, product)

        async def run_count() -> int:
            probe = await world.open_session()
            count = await probe.scalar(select(func.count()).select_from(FetcherRun))
            await probe.rollback()
            return int(count or 0)

        before = await run_count()
        summary = await re_evaluate_product_eligibility(
            product.id, "threshold", session_factory=sessions.maker()
        )

        assert summary.successful == 3
        assert await run_count() == before


# ---------------------------------------------------------------------------
# Workflow: failure isolation and propagation (Sub-task step 4)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestWorkflowFailures:
    async def test_pre_commit_failure_rolls_back_only_that_ticket(
        self,
        world: CommittedWorld,
        sessions: _RecordingFactory,
        service: _ServiceSpy,
    ) -> None:
        """The middle Ticket fails after its writes were flushed: only it is
        rolled back, one WARNING carries exactly the Ticket ID, Product ID,
        reason, and exception type (never the message), and the run
        continues and returns normally."""
        product = await _product(world)
        first, middle, last = await _three_changing_tickets(world, product)
        service.fail_after[middle.id] = RuntimeError("fictional secret detail")

        with capture_logs() as logs:
            summary = await re_evaluate_product_eligibility(
                product.id, "threshold", session_factory=sessions.maker()
            )

        expected = _summary(candidates=3, successful=2, changed_records=2, failed=1)
        assert summary == expected
        assert service.results[middle.id].changed == 1
        assert service.ticket_ids == [first.id, middle.id, last.id]
        assert logs == [
            {
                "event": TICKET_FAILED,
                "log_level": "warning",
                "ticket_id": str(middle.id),
                "catalog_product_id": str(product.id),
                "reason": "threshold",
                "error_type": "RuntimeError",
            },
            _completed(product.id, "threshold", expected),
        ]
        assert "fictional secret detail" not in repr(logs)
        assert await _committed(world, first) == CHANGED_ONCE
        assert await _committed(world, middle) == UNCHANGED
        assert await _committed(world, last) == CHANGED_ONCE

    @pytest.mark.parametrize(
        "error",
        [
            pytest.param(TicketNotFoundError(), id="ticket-not-found"),
            pytest.param(ProductNotFoundError(), id="product-not-found"),
        ],
    )
    async def test_not_found_errors_are_isolated_ticket_failures(
        self,
        world: CommittedWorld,
        sessions: _RecordingFactory,
        service: _ServiceSpy,
        error: Exception,
    ) -> None:
        product = await _product(world)
        first, middle, last = await _three_changing_tickets(world, product)
        service.fail_instead[middle.id] = error

        with capture_logs() as logs:
            summary = await re_evaluate_product_eligibility(
                product.id, "reactive_ltss", session_factory=sessions.maker()
            )

        assert summary == _summary(
            candidates=3, successful=2, changed_records=2, failed=1
        )
        failures = _events(logs, TICKET_FAILED)
        assert len(failures) == 1
        assert failures[0]["ticket_id"] == str(middle.id)
        assert failures[0]["reason"] == "reactive_ltss"
        assert failures[0]["error_type"] == type(error).__name__
        assert service.ticket_ids == [first.id, middle.id, last.id]
        assert await _committed(world, middle) == UNCHANGED
        assert await _committed(world, last) == CHANGED_ONCE

    async def test_commit_failure_propagates_without_isolation(
        self,
        world: CommittedWorld,
        sessions: _RecordingFactory,
        service: _ServiceSpy,
    ) -> None:
        """A commit exception of the middle Ticket terminates the run: it
        is neither logged nor counted as an isolated failure, the later
        Ticket is not processed, and the earlier commit remains."""
        product = await _product(world)
        first, middle, last = await _three_changing_tickets(world, product)
        error = OperationalError("COMMIT", None, Exception("fictional reset"))
        sessions.failing_commit = (2, error)

        with capture_logs() as logs, pytest.raises(OperationalError) as exc_info:
            await re_evaluate_product_eligibility(
                product.id, "threshold", session_factory=sessions.maker()
            )

        assert exc_info.value is error
        assert service.ticket_ids == [first.id, middle.id]
        assert service.results[middle.id].changed == 1
        assert logs == []
        assert await _committed(world, first) == CHANGED_ONCE
        assert await _committed(world, middle) == UNCHANGED
        assert await _committed(world, last) == UNCHANGED

    @pytest.mark.parametrize("make_signal", _WHOLE_RUN_SIGNALS)
    async def test_whole_run_signal_propagates(
        self,
        world: CommittedWorld,
        sessions: _RecordingFactory,
        service: _ServiceSpy,
        make_signal: Callable[[], BaseException],
    ) -> None:
        """`SoftTimeLimitExceeded`, `MemoryError`, and cancellation from the
        per-Ticket call are whole-run failures: no isolated failure, no
        later Ticket, no completion log; the earlier commit remains and the
        interrupted Ticket is rolled back."""
        product = await _product(world)
        first, middle, last = await _three_changing_tickets(world, product)
        signal = make_signal()
        service.fail_after[middle.id] = signal

        with capture_logs() as logs, pytest.raises(type(signal)) as exc_info:
            await re_evaluate_product_eligibility(
                product.id, "threshold", session_factory=sessions.maker()
            )

        assert exc_info.value is signal
        assert service.ticket_ids == [first.id, middle.id]
        assert logs == []
        assert await _committed(world, first) == CHANGED_ONCE
        assert await _committed(world, middle) == UNCHANGED
        assert await _committed(world, last) == UNCHANGED

    async def test_candidate_selection_failure_propagates(
        self,
        world: CommittedWorld,
        sessions: _RecordingFactory,
        service: _ServiceSpy,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        product = await _product(world)
        ticket = await _ticket(world)
        await _occurrences(world, ticket, product, False)
        error = OperationalError("SELECT", None, Exception("fictional outage"))

        async def failing_select(
            db: AsyncSession, catalog_product_id: uuid.UUID
        ) -> Any:
            await db.execute(select(1))
            raise error

        monkeypatch.setattr(workflow, "select_candidate_ticket_ids", failing_select)

        with capture_logs() as logs, pytest.raises(OperationalError) as exc_info:
            await re_evaluate_product_eligibility(
                product.id, "threshold", session_factory=sessions.maker()
            )

        assert exc_info.value is error
        assert service.calls == []
        assert len(sessions.sessions) == 1
        assert logs == []
        assert await _committed(world, ticket) == UNCHANGED


# ---------------------------------------------------------------------------
# Workflow: Ticket convergence (Sub-task step 3; drain deferred)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestWorkflowConvergence:
    async def test_resolved_regression_effect_is_discarded_unpublished(
        self,
        world: CommittedWorld,
        sessions: _RecordingFactory,
        service: _ServiceSpy,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A `Resolved` Ticket without severity whose `AFFECTED` occurrence
        becomes eligible regresses to `Analysis` and registers one
        convergence effect in its transaction. Until the drain exists, the
        effect is discarded when that transaction ends and nothing is
        published through Celery."""
        send_task = Mock(side_effect=AssertionError("must not publish"))
        apply_async = Mock(side_effect=AssertionError("must not publish"))
        monkeypatch.setattr(celery_app, "send_task", send_task)
        monkeypatch.setattr(Task, "apply_async", apply_async)
        actor = await world.user(role=Role.VULNERABILITY_ANALYST)
        product = await _product(world)
        ticket = await _ticket(
            world, status=TicketStatus.RESOLVED, assignee=actor, severity=None
        )
        await _occurrences(world, ticket, product, False, status=PackageStatus.AFFECTED)

        summary = await re_evaluate_product_eligibility(
            product.id, "threshold", session_factory=sessions.maker()
        )

        assert summary == _summary(candidates=1, successful=1, changed_records=1)
        assert service.effects[ticket.id] == (TicketConvergenceEffect(ticket.id),)
        assert pending_ticket_convergence_effects(service.calls[0].session) == ()
        send_task.assert_not_called()
        apply_async.assert_not_called()
        assert await _committed(world, ticket) == _Committed(
            TicketStatus.ANALYSIS,
            [(True, False)],
            [CHANGED, ("status_change", "Resolved", "Analysis")],
        )
