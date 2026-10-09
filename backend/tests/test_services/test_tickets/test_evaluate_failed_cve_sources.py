"""Tests for the candidate read, module hygiene, and registration of the
`evaluate_failed_cve_sources` fetcher
(backend/app/services/tickets/evaluate_failed_cve_sources.py):
`find_failed_cve_source_candidates()`, `RetryCandidate`, and
`EvaluateFailedCveSources` as a registered fetcher.

Owning specifications:

- docs/features/platform/cve-source-failure-retry.md (Properties Table;
  Algorithm step 1 with the Window note and the Note on step 2b; Active
  Ticket Check, including the CVE-with-no-Ticket edge case; Interaction with
  Existing Mechanisms, FetcherRun records).
- docs/features/tickets/cve-service.md (Active-Ticket CVE Scope).
- docs/features/platform/fetcher-infrastructure.md (Registry and Fetcher
  Discovery; naming convention) and docs/features/platform/cve-fetcher-
  infrastructure.md (`get_fetch_single_fetchers()`).
- docs/features/platform/testing-strategy.md (On-Demand CVE Refetch, the
  `evaluate_failed_cve_sources` bullet; Fetcher Outcome and Effect
  Accounting, the `evaluate_failed_cve_sources` mapping; `now()` testing).
- docs/data-sources.md (Fetcher Registry row `evaluate_failed_cve_sources`).

`execute()` and `run()` are covered by
`test_evaluate_failed_cve_sources_execute.py`.

Every candidate test runs in the savepoint `db_session`, so it starts from
empty CVE, `cve_source`, and Ticket tables, and PostgreSQL's `now()` is the
constant transaction timestamp that the read's own statement observes.
`Ticket.cve_id` is UNIQUE, so one CVE is referenced by at most one Ticket.
Rows are written through the model factories, which bypass
`record_source_status()` so arbitrary statuses and streak timestamps can be
set. All identifiers are fictional.
"""

from __future__ import annotations

import ast
import dataclasses
import inspect
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from typing import Any, Final

import pytest
from celery import Celery
from redbeat import RedBeatSchedulerEntry
from sqlalchemy import event, func, select
from sqlalchemy.ext.asyncio import AsyncSession

import app.services.fetcher_discovery as fetcher_discovery
from app.core.enums import TicketStatus
from app.models.cve import CVE
from app.models.cve_source import CVESource
from app.models.fetcher_config import FetcherConfig
from app.services.base_cve_fetcher import BaseCVEFetcher, get_fetch_single_fetchers
from app.services.base_fetcher import (
    FETCHER_REGISTRY,
    BaseFetcher,
    get_catch_up_fetchers,
)
from app.services.fetcher_bootstrap import bootstrap_fetcher_configs
from app.services.fetcher_schedule import reconcile_beat_schedule
from app.services.tickets import evaluate_failed_cve_sources as evaluator
from app.services.tickets.evaluate_failed_cve_sources import (
    EvaluateFailedCveSources,
    RetryCandidate,
    find_failed_cve_source_candidates,
)

Factory = Callable[..., Awaitable[Any]]

NAME: Final = "evaluate_failed_cve_sources"
FAILURE: Final = "failure"
WINDOW: Final = timedelta(hours=720)
ONE_US: Final = timedelta(microseconds=1)
ROW_LOCKS: Final = ("FOR UPDATE", "FOR NO KEY UPDATE", "FOR SHARE", "FOR KEY SHARE")

ACTIVE = (TicketStatus.NEW, TicketStatus.ANALYSIS, TicketStatus.ANALYZED)
INACTIVE = (TicketStatus.RESOLVED, TicketStatus.IGNORED, TicketStatus.DUPLICATED)


async def _db_now(db: AsyncSession) -> datetime:
    """`now()` of the session's transaction: the instant the read's own
    statement observes in the same transaction."""
    now: datetime = (await db.execute(select(func.now()))).scalar_one()
    return now


def _keys(candidates: list[RetryCandidate]) -> list[tuple[str, str]]:
    return [(candidate.cve_id, candidate.source) for candidate in candidates]


@dataclasses.dataclass(frozen=True)
class _Row:
    cve: CVE
    row: CVESource

    @property
    def key(self) -> tuple[str, str]:
        return (self.cve.cve_id, self.row.source)


MakeRow = Callable[..., Awaitable[_Row]]


@pytest.fixture
def make_row(cve_factory: Factory, cve_source_factory: Factory) -> MakeRow:
    """A `CVESource` row for `cve` or a fresh CVE: source `redhat`, status
    `failure`, and a streak that began one day before the current UTC time,
    unless overridden."""

    async def _create(*, cve: CVE | None = None, **fields: Any) -> _Row:
        owner: CVE = cve if cve is not None else await cve_factory()
        fields.setdefault("source", "redhat")
        fields.setdefault("status", FAILURE)
        fields.setdefault("first_failed_at", datetime.now(UTC) - timedelta(days=1))
        return _Row(owner, await cve_source_factory(cve_id=owner.id, **fields))

    return _create


# ---------------------------------------------------------------------------
# Window: status gate, NULL streak, and the 720-hour boundary
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestWindow:
    async def test_failure_inside_window_selected_other_statuses_never(
        self, db_session: AsyncSession, make_row: MakeRow
    ) -> None:
        """`success` and `missing` rows are never selected, whether their
        `first_failed_at` is recent or older than the window; a `failure`
        row with a NULL streak is never selected either."""
        now = await _db_now(db_session)
        recent = now - timedelta(hours=1)
        old = now - WINDOW - timedelta(days=5)
        selected = await make_row(first_failed_at=recent)
        for status in ("success", "missing"):
            for streak in (recent, old, None):
                await make_row(status=status, first_failed_at=streak)
        await make_row(first_failed_at=None)

        candidates = await find_failed_cve_source_candidates(db_session)

        assert _keys(candidates) == [selected.key]

    async def test_boundary_is_evaluated_at_the_statement_database_now(
        self, db_session: AsyncSession, make_row: MakeRow
    ) -> None:
        """`now() - 720h + 1us` and exactly `now() - 720h` (equality is
        inside) are selected; `now() - 720h - 1us` is excluded."""
        now = await _db_now(db_session)
        threshold = now - WINDOW
        excluded = await make_row(first_failed_at=threshold - ONE_US)
        exact = await make_row(first_failed_at=threshold)
        inside = await make_row(first_failed_at=threshold + ONE_US)

        candidates = await find_failed_cve_source_candidates(db_session)

        assert await _db_now(db_session) == now
        assert _keys(candidates) == [exact.key, inside.key]
        assert excluded.key not in _keys(candidates)

    async def test_empty_database_returns_an_empty_list(
        self, db_session: AsyncSession
    ) -> None:
        assert await find_failed_cve_source_candidates(db_session) == []


# ---------------------------------------------------------------------------
# Order: oldest streak first, then CVE-ID and source in code-point order
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestOrder:
    async def test_oldest_streak_first_ties_by_cve_id_then_source_code_points(
        self, db_session: AsyncSession, cve_factory: Factory, make_row: MakeRow
    ) -> None:
        """Insertion order differs from the result order. At the tied
        instant, `CVE-2099-10000` precedes `CVE-2099-9999` (code points,
        not numeric order), and an upper-case deregistered source precedes
        the lower-case ones (code points, not a case-insensitive
        collation)."""
        now = await _db_now(db_session)
        oldest, tied, newest = (now - timedelta(hours=h) for h in (300, 200, 100))
        short: CVE = await cve_factory(cve_id="CVE-2099-9999")
        long: CVE = await cve_factory(cve_id="CVE-2099-10000")
        last = await make_row(first_failed_at=newest)
        short_redhat = await make_row(cve=short, first_failed_at=tied)
        long_redhat = await make_row(cve=long, first_failed_at=tied)
        long_osv = await make_row(cve=long, source="osv", first_failed_at=tied)
        long_upper = await make_row(
            cve=long, source="Zz_retired_source", first_failed_at=tied
        )
        first = await make_row(source="osv", first_failed_at=oldest)

        candidates = await find_failed_cve_source_candidates(db_session)

        assert _keys(candidates) == [
            first.key,
            long_upper.key,
            long_osv.key,
            long_redhat.key,
            short_redhat.key,
            last.key,
        ]


# ---------------------------------------------------------------------------
# Active-Ticket flag (Note on step 2b; Active Ticket Check)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestActiveTicketFlag:
    @pytest.mark.parametrize("status", ACTIVE)
    async def test_cve_of_an_active_ticket_is_flagged(
        self,
        db_session: AsyncSession,
        make_row: MakeRow,
        ticket_factory: Factory,
        status: TicketStatus,
    ) -> None:
        row = await make_row()
        await ticket_factory(cve_id=row.cve.id, status=status.value)

        assert await find_failed_cve_source_candidates(db_session) == [
            RetryCandidate(
                cve_id=row.cve.cve_id, source="redhat", has_active_ticket=True
            )
        ]

    @pytest.mark.parametrize("status", INACTIVE)
    async def test_cve_of_an_inactive_ticket_is_returned_unflagged(
        self,
        db_session: AsyncSession,
        make_row: MakeRow,
        ticket_factory: Factory,
        status: TicketStatus,
    ) -> None:
        row = await make_row()
        await ticket_factory(cve_id=row.cve.id, status=status.value)

        assert await find_failed_cve_source_candidates(db_session) == [
            RetryCandidate(
                cve_id=row.cve.cve_id, source="redhat", has_active_ticket=False
            )
        ]

    async def test_ticketless_cve_is_unflagged_and_cve_less_tickets_do_not_count(
        self, db_session: AsyncSession, make_row: MakeRow, ticket_factory: Factory
    ) -> None:
        for status in ACTIVE:
            await ticket_factory(status=status.value)
        row = await make_row()

        assert await find_failed_cve_source_candidates(db_session) == [
            RetryCandidate(
                cve_id=row.cve.cve_id, source="redhat", has_active_ticket=False
            )
        ]

    async def test_one_pair_per_source_without_duplication_by_the_flag(
        self, db_session: AsyncSession, make_row: MakeRow, ticket_factory: Factory
    ) -> None:
        """Every failing source of a CVE with an active Ticket is returned
        exactly once, among unflagged pairs of other CVEs."""
        now = await _db_now(db_session)
        active = await make_row(first_failed_at=now - timedelta(hours=3))
        await ticket_factory(cve_id=active.cve.id, status=TicketStatus.NEW.value)
        for status in ACTIVE:
            await ticket_factory(status=status.value)
        sources = [
            await make_row(
                cve=active.cve, source=source, first_failed_at=now - timedelta(hours=3)
            )
            for source in ("osv", "mitre")
        ]
        resolved = await make_row(first_failed_at=now - timedelta(hours=2))
        await ticket_factory(cve_id=resolved.cve.id, status=TicketStatus.RESOLVED.value)
        ticketless = await make_row(first_failed_at=now - timedelta(hours=1))

        candidates = await find_failed_cve_source_candidates(db_session)

        assert [
            (candidate.cve_id, candidate.source, candidate.has_active_ticket)
            for candidate in candidates
        ] == [
            (*sources[1].key, True),
            (*sources[0].key, True),
            (*active.key, True),
            (*resolved.key, False),
            (*ticketless.key, False),
        ]


# ---------------------------------------------------------------------------
# One read-only statement; return type
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestReadOnly:
    async def test_one_lock_free_select_leaves_the_session_untouched(
        self,
        db_session: AsyncSession,
        make_row: MakeRow,
        ticket_factory: Factory,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Several flagged and unflagged pairs are read by exactly one
        statement (no N+1). A pending, unflushed in-window failure row is
        neither flushed nor returned; the function never flushes, commits,
        or rolls back, and the caller-owned transaction stays open."""
        rows = [await make_row() for _ in range(4)]
        for row in rows[:2]:
            await ticket_factory(cve_id=row.cve.id, status=TicketStatus.ANALYSIS.value)
        pending = CVESource(
            cve_id=rows[0].cve.id,
            source="osv",
            status=FAILURE,
            fetched_at=datetime.now(UTC),
            first_failed_at=datetime.now(UTC) - timedelta(hours=1),
        )
        db_session.add(pending)
        controls: list[str] = []
        for operation in ("flush", "commit", "rollback"):
            original = getattr(db_session, operation)

            async def recorded(
                *args: Any, _name: str = operation, _call: Any = original, **kw: Any
            ) -> None:
                controls.append(_name)
                await _call(*args, **kw)

            monkeypatch.setattr(db_session, operation, recorded)
        statements: list[str] = []
        engine = db_session.get_bind().engine

        def record(*args: Any) -> None:
            statements.append(args[2])

        event.listen(engine, "before_cursor_execute", record)
        try:
            candidates = await find_failed_cve_source_candidates(db_session)
        finally:
            event.remove(engine, "before_cursor_execute", record)

        assert set(_keys(candidates)) == {row.key for row in rows}
        assert len(candidates) == len(rows)
        (statement,) = statements
        assert statement.lstrip().upper().startswith("SELECT")
        for row_lock in ROW_LOCKS:
            assert row_lock not in statement.upper()
        assert controls == []
        assert list(db_session.new) == [pending]
        assert not db_session.dirty
        assert not db_session.deleted
        assert db_session.in_transaction()

    async def test_returns_a_list_of_frozen_retry_candidates(
        self, db_session: AsyncSession, make_row: MakeRow, ticket_factory: Factory
    ) -> None:
        row = await make_row()
        await ticket_factory(cve_id=row.cve.id, status=TicketStatus.NEW.value)

        candidates = await find_failed_cve_source_candidates(db_session)

        assert type(candidates) is list
        (candidate,) = candidates
        assert type(candidate) is RetryCandidate
        assert type(candidate.cve_id) is str
        assert type(candidate.source) is str
        assert type(candidate.has_active_ticket) is bool
        assert [f.name for f in dataclasses.fields(RetryCandidate)] == [
            "cve_id",
            "source",
            "has_active_ticket",
        ]
        with pytest.raises(dataclasses.FrozenInstanceError):
            candidate.has_active_ticket = False  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Module hygiene: only public `cve_service` names
# ---------------------------------------------------------------------------

_CVE_SERVICE = "app.services.cve_service"


def _private_cve_service_uses(source: str) -> list[str]:
    """Every private (`_`-prefixed) name imported from, or read as an
    attribute of, `app.services.cve_service`."""
    tree = ast.parse(source)
    aliases: set[str] = set()
    found: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            if node.module == _CVE_SERVICE:
                found.extend(a.name for a in node.names if a.name.startswith("_"))
            elif node.module == "app.services":
                aliases.update(
                    a.asname or a.name for a in node.names if a.name == "cve_service"
                )
        elif isinstance(node, ast.Import):
            aliases.update(
                a.asname for a in node.names if a.name == _CVE_SERVICE and a.asname
            )
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and node.attr.startswith("_"):
            owner = ast.unparse(node.value)
            if owner in aliases or owner == _CVE_SERVICE:
                found.append(f"{owner}.{node.attr}")
    return found


@pytest.mark.unit
class TestModuleHygiene:
    def test_module_uses_no_private_cve_service_name(self) -> None:
        source = inspect.getsource(evaluator)

        assert _private_cve_service_uses(source) == []
        assert "cve_service" in source

    @pytest.mark.parametrize(
        "source",
        [
            "from app.services.cve_service import _STALLED_AFTER_HOURS",
            "from app.services import cve_service\nx = cve_service._helper",
            "from app.services import cve_service as svc\nx = svc._helper",
            "import app.services.cve_service as svc\nx = svc._helper",
            "import app.services.cve_service\nx = app.services.cve_service._helper",
        ],
    )
    def test_detector_finds_private_uses(self, source: str) -> None:
        """The detector is not vacuous."""
        assert len(_private_cve_service_uses(source)) == 1


# ---------------------------------------------------------------------------
# Registration, properties, and discovery
# ---------------------------------------------------------------------------


def _imported_modules(module: Any) -> set[str]:
    tree = ast.parse(inspect.getsource(module))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            imported.add(node.module)
    return imported


@pytest.mark.unit
class TestRegistration:
    def test_discovery_imports_the_module_and_registers_the_fetcher(self) -> None:
        assert evaluator.__name__ in _imported_modules(fetcher_discovery)
        assert EvaluateFailedCveSources.__module__ == (
            "app.services.tickets.evaluate_failed_cve_sources"
        )
        assert FETCHER_REGISTRY[NAME] is EvaluateFailedCveSources

    def test_properties_match_the_specification(self) -> None:
        assert EvaluateFailedCveSources.name == NAME
        assert EvaluateFailedCveSources.description == (
            "Retry CVE source records stuck in failure for CVEs with an active Ticket"
        )
        assert EvaluateFailedCveSources.default_schedule == "0 6 * * *"
        assert EvaluateFailedCveSources.queue is None
        assert EvaluateFailedCveSources.default_request_delay == 0
        assert EvaluateFailedCveSources.Settings is None
        assert EvaluateFailedCveSources.participates_in_catch_up is False
        assert "catch_up" not in EvaluateFailedCveSources.__dict__

    def test_class_name_is_derived_from_the_fetcher_name(self) -> None:
        derived = "".join(part.capitalize() for part in NAME.split("_"))

        assert derived == EvaluateFailedCveSources.__name__

    def test_is_a_plain_fetcher_outside_the_cve_registries(self) -> None:
        assert issubclass(EvaluateFailedCveSources, BaseFetcher)
        assert not issubclass(EvaluateFailedCveSources, BaseCVEFetcher)
        assert not hasattr(EvaluateFailedCveSources, "cve_source_type")
        assert NAME not in {cls.name for cls in get_fetch_single_fetchers().values()}
        assert NAME not in get_catch_up_fetchers()


@pytest.mark.integration
class TestBootstrapAndSchedule:
    async def test_bootstrap_creates_the_configuration_from_the_class(
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

    async def test_reconciliation_writes_the_entry_from_the_class(
        self, db_session: AsyncSession, celery_test_app: Celery
    ) -> None:
        await bootstrap_fetcher_configs(db_session)

        await reconcile_beat_schedule(db_session, celery_test_app)

        key = RedBeatSchedulerEntry.generate_key(celery_test_app, NAME)
        entry = RedBeatSchedulerEntry.from_key(key, app=celery_test_app)
        assert entry.task == "run_fetcher"
        assert entry.kwargs == {"fetcher_name": NAME, "triggered_by": "schedule"}
        assert entry.schedule.minute == {0}
        assert entry.schedule.hour == {6}
        assert entry.schedule.day_of_month == set(range(1, 32))
        assert entry.schedule.month_of_year == set(range(1, 13))
        assert entry.schedule.day_of_week == set(range(7))
        assert "queue" not in entry.options
