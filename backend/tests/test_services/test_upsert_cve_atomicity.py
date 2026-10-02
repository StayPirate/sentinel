"""Independent-session race tests for `upsert_cve()` and
`record_source_status()` (backend/app/services/cve_service.py).

Owning specifications:

- docs/features/tickets/cve-service.md (CVESource Management; Concurrency >
  CVE Upsert Serialization: Existing CVE, New CVE, CVE state transition
  detection, Ticket creation winner; Concurrency > CVSS Lock Composition;
  On-Demand Fetch: `ensure_cve_exists()` > Concurrency).
- docs/features/tickets/cvss-scoring.md (Serialization and Concurrent
  Outcomes; Required Tests > Persistence and API Tests: two-session lock
  tests, composition with CVE ingestion).
- docs/features/tickets/ticket-mutations.md (Architectural Test
  Requirement: Serialized outcomes).
- docs/features/tickets/ticket-service.md (Architectural Test Requirement
  9, the system path).
- docs/features/tickets/ticket-references.md (Mutability and Concurrency >
  Race Outcomes).
- docs/features/tickets/ticket-audit-log.md (Testing Requirements 16, 23).
- docs/conventions.md (Cross-Domain Root Lock Order).
- docs/features/platform/testing-strategy.md (Concurrency Testing and
  Lock-Wait Observation; CVE Ingestion Persistence, the create/create,
  create/ensure, and same-source status race bullets; CVE Ingestion and
  Ticket Composition, the same-CVE race bullet; Ticket References, the
  manual/automatic race bullet with `upsert_cve()` already holding the
  Ticket lock through Ticket-associated CVSS processing).

Covered here: create/create with an `updated` and an `unchanged` loser; a
rolled-back apparent winner; create/ensure in both orders and both
`ensure_cve_exists()` forms, including a rolled-back ensure winner;
conflicting rejection/republication payloads from `New` and from
`Ignored` in both commit orders; Ticket creation on an existing ticketless
CVE; manual SUSE upsert and delete against ingestion CVSS in both orders;
`associate_cve()` against ingestion in both orders for an orphan and a new
CVE; every ordered same-source status pair after commit and after a
holder rollback; and the composed reference race in both orders, which
also confirms that the Ticket lock is already held when
`upsert_references()` starts (the residual deadlock risk deferred from
the reference work).

Not covered here: the single-session persistence and composition matrices
(`tests/test_services/test_upsert_cve.py`,
`tests/test_services/test_upsert_cve_composition.py`), the reference race
without a pre-existing Ticket lock
(`tests/test_services/test_reference_ingestion_races.py`), ensure/ensure
(`tests/test_services/test_create_ticket_atomicity.py`), and two external
batches (`tests/test_services/test_upsert_external_cvss_batch_atomicity.py`).

Every race keeps the holder's transaction open after its call returns,
proves the waiter blocked by the holder with `assert_lock_wait()` (never a
sleep) at the statement the scenario names, releases the holder, and waits
for the waiter with a bounded wait. Committed rows are deleted at teardown
by `IngestionWorld` (testing-strategy.md, Concurrency Testing); each test
uses fresh fictional CVE-IDs. Final state is read through an independent
probe session. Expected values are transcribed from the specifications and
the `Vector` constants, never computed with the module under test.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable, Coroutine
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any

import pytest
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import (
    CVESourceFetchStatus,
    CVESourceType,
    CveState,
    CVSSVersion,
    ReferenceType,
    Role,
    Scope,
    Severity,
    TicketStatus,
)
from app.models.cve import CVE
from app.models.ticket import Ticket
from app.models.ticket_reference import TicketReference
from app.models.user import User
from app.services import cve_service, ticket_mutations, ticket_service
from app.services.cve_ingest import CVEIngestPayload, UpsertAction, UpsertResult
from app.services.cve_service import ensure_cve_exists, record_source_status
from app.services.reference_service import (
    AutomaticReferenceInput,
    ManualReferenceCreateInput,
    ReferenceConflictError,
    TicketReferenceProjection,
    create_reference,
    upsert_references,
)
from app.services.ticket_convergence_registry import (
    TicketConvergenceEffect,
    pending_ticket_convergence_effects,
)
from app.services.ticket_mutations import (
    CVSSAssessmentAction,
    CVSSAssessmentMutationResult,
    CVSSPropagation,
    ExternalCVSSAssessmentOutcome,
    ExternalCVSSBatchResult,
)
from app.services.ticket_service import TicketCVEConflictError, associate_cve
from app.services.ticket_visibility import TicketCaller
from tests.support.cve_ingest import (
    IngestionWorld,
    SessionCallSpy,
    cve_ids_of,
    cvss,
    is_root_lock,
    lock_not_available,
    root_lock_order,
    source_rows,
    tickets_of,
)
from tests.support.cvss_chain import (
    cve_severity,
    eligibility,
    priority_event,
    severity_event,
    ticket_state,
)
from tests.support.database import assert_lock_wait
from tests.support.external_cvss import external_cvss_event, external_value
from tests.support.suse_cvss import (
    V31_CRITICAL,
    V31_HIGH,
    V31_MEDIUM,
    Vector,
    cvss_delete_event,
    cvss_event,
    delete_assessment,
    persisted_assessments,
    unit,
    upsert,
)
from tests.support.suse_cvss_races import SessionStatementRecorder
from tests.support.ticket_creation import creation_events, ingestion_comment
from tests.support.ticket_mutations import (
    EVAL,
    EventRow,
    status_event,
    ticket_events_by_id,
)

SessionFactory = Callable[[], Awaitable[AsyncSession]]

NVD = CVESourceType.NVD
MITRE = CVESourceType.MITRE
SUCCESS = CVESourceFetchStatus.SUCCESS
FAILURE = CVESourceFetchStatus.FAILURE
MISSING = CVESourceFetchStatus.MISSING

PROVIDER = "Example CNA"
OTHER_PROVIDER = "Example Vendor"

CLOCK = datetime(2026, 9, 27, 12, 0, tzinfo=UTC)
"""The patched `cve_service._utc_now()`; its UTC date is `EVAL`, the date
the manual SUSE helpers pass explicitly."""

REJECTED_AT = datetime(2099, 3, 4, tzinfo=UTC)
LATER_REJECTED_AT = datetime(2099, 5, 6, tzinfo=UTC)

WINNER_TITLE = "Fictional winner title"
LOSER_TITLE = "Fictional loser title"

T4 = Decimal("4.0")
"""A Product threshold met by the SUSE v3.1 medium score 4.8 and by the
`10.0` fallback, so automatic eligibility stays `true` throughout."""

FETCHER = "sync_nvd_cves"
"""A fictional fetcher name, the automatic-reference `source`."""

REFERENCE_URL = "https://advisories.example.test/notes/750"
REFERENCE_VARIANT = "HTTP://ADVISORIES.EXAMPLE.TEST/notes/750"
"""Normalizes to `REFERENCE_URL` (ticket-references.md, URL Normalization)."""

UPSTREAM_TITLE = "Fictional upstream advisory"
MANUAL_DESCRIPTION = "Fictional analyst context"

NEW = TicketStatus.NEW.value
ANALYSIS = TicketStatus.ANALYSIS.value
ANALYZED = TicketStatus.ANALYZED.value
IGNORED = TicketStatus.IGNORED.value

REJECTION = EventRow("status_change", None, NEW, IGNORED, "CVE rejected", None)
"""The exact system rejection event (cve-tracking.md, Rejection handling)."""

REOPENED = status_event(IGNORED, ANALYSIS)
"""The system reopen of an unassigned `Ignored` Ticket without a package
tree: the gates leave it at the `Analysis` floor."""

WAIT = 5
"""Upper bound, in seconds, of every wait that is expected to finish."""


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------


@pytest.fixture
async def world(db_session_factory: SessionFactory) -> AsyncIterator[IngestionWorld]:
    created = IngestionWorld(db_session_factory, await db_session_factory())
    try:
        created.probe = await created.open_session()
        await created.ensure_default_setting()
        yield created
    finally:
        await created.cleanup()


@pytest.fixture(autouse=True)
def fixed_clock(monkeypatch: pytest.MonkeyPatch) -> None:
    """`upsert_cve()` captures its one `evaluation_date` from `_utc_now()`."""
    monkeypatch.setattr(cve_service, "_utc_now", lambda: CLOCK)


async def _observe[T](
    world: IngestionWorld, read: Callable[[AsyncSession], Awaitable[T]]
) -> T:
    """Read committed state through the probe, then end its transaction."""
    try:
        return await read(world.probe)
    finally:
        await world.probe.rollback()


async def _upsert(
    db: AsyncSession,
    cve_id: str,
    payload: CVEIngestPayload,
    *,
    source: CVESourceType = NVD,
) -> UpsertResult:
    return await cve_service.upsert_cve(db, cve_id, source, payload)


def _cvss_payload(provider: str, vector: Vector, **fields: Any) -> CVEIngestPayload:
    return CVEIngestPayload(
        cvss_assessments=[cvss(provider, vector.canonical)], **fields
    )


def _created(provider: str, vector: Vector) -> EventRow:
    """The system `cvss_assessment_changed` of a created external row."""
    return external_cvss_event(None, external_value(provider, vector))


def _ingestion_creation(cve_id: str, source: CVESourceType) -> list[EventRow]:
    """`ticket_created` with the exact ingestion label, then the system
    `cve_associated`."""
    return creation_events(
        creator_id=None, comment=ingestion_comment(source), cve_id=cve_id
    )


async def _cve_columns(
    db: AsyncSession, cve_id: uuid.UUID
) -> tuple[str | None, str, datetime | None, str | None]:
    """The committed `(title, cve_state, date_rejected, severity)`."""
    row = (
        await db.execute(
            select(CVE.title, CVE.cve_state, CVE.date_rejected, CVE.severity).where(
                CVE.id == cve_id
            )
        )
    ).one()
    return row[0], row[1], row[2], row[3]


async def _sntl(db: AsyncSession, ticket_id: uuid.UUID) -> str:
    sequence = await db.scalar(select(Ticket.sequence_id).where(Ticket.id == ticket_id))
    return f"SNTL-{sequence}"


def _is_cve_insert(statement: str) -> bool:
    """The conflict-aware CVE insert of the shared create-or-obtain
    protocol."""
    return statement.startswith("INSERT INTO cve ")


def _ticket_inserts(statements: list[str]) -> list[str]:
    return [s for s in statements if s.startswith("INSERT INTO ticket ")]


def _winner_payload() -> CVEIngestPayload:
    return _cvss_payload(
        PROVIDER, V31_HIGH, cve_state=CveState.PUBLISHED, title=WINNER_TITLE
    )


def _high_batch() -> list[EventRow]:
    """The system batch events of a first `High` assessment."""
    return [
        _created(PROVIDER, V31_HIGH),
        severity_event(None, "High"),
        priority_event(None, "P3"),
    ]


# ---------------------------------------------------------------------------
# create/create and the rolled-back apparent winner (CVE Upsert
# Serialization > New CVE; testing-strategy.md, CVE Ingestion Persistence)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestCreateCreate:
    @pytest.mark.parametrize("loser", ["updated", "unchanged"])
    async def test_one_insert_winner_and_the_loser_merges_into_it(
        self, world: IngestionWorld, monkeypatch: pytest.MonkeyPatch, loser: str
    ) -> None:
        """The loser waits at the conflict-aware insert, obtains and locks
        the committed winner, applies its own merge and CVSS batch to the
        winner's Ticket (no second Ticket insert, no conflict error), and
        its transaction stays usable for an unrelated committed write."""
        updated = loser == "updated"
        cve_id = world.new_cve_id()
        loser_payload = (
            _cvss_payload(OTHER_PROVIDER, V31_CRITICAL, title=LOSER_TITLE)
            if updated
            else _winner_payload()
        )
        loser_source = MITRE if updated else NVD
        create = SessionCallSpy(monkeypatch, ticket_service, "create_ticket")
        a = await world.open_session()
        b = await world.open_session()

        with SessionStatementRecorder(b) as recorder:
            winner = await _upsert(a, cve_id, _winner_payload())
            winner_cve, winner_ticket = winner.cve.id, winner.ticket.id
            [(_, _, winner_fetched, _)] = await source_rows(a, winner_cve)
            task = world.start(
                b, _upsert(b, cve_id, loser_payload, source=loser_source)
            )
            await assert_lock_wait(task, waiter=b, blocked_by=a)
            # The locking read found no committed row; the insert waits for
            # the uncommitted winner.
            assert len(recorder.statements) == 2
            assert is_root_lock(recorder.statements[0], "cve")
            assert _is_cve_insert(recorder.statements[1])
            await a.commit()
            result = await asyncio.wait_for(task, timeout=WAIT)

        assert winner.action is UpsertAction.CREATED
        assert result.action is (
            UpsertAction.UPDATED if updated else UpsertAction.UNCHANGED
        )
        assert (result.cve.id, result.ticket.id) == (winner_cve, winner_ticket)
        assert create.sessions == [a]
        assert _ticket_inserts(recorder.statements) == []
        assert root_lock_order(recorder.statements) == ["cve", "ticket"]

        unrelated_id = world.new_cve_id()
        unrelated = await ensure_cve_exists(b, unrelated_id)
        await b.commit()

        assert await _observe(world, lambda s: cve_ids_of(s, cve_id)) == [winner_cve]
        assert await _observe(world, lambda s: cve_ids_of(s, unrelated_id)) == [
            unrelated.id
        ]
        assert await _observe(world, lambda s: tickets_of(s, cve_id)) == [winner_ticket]
        loser_events = (
            [
                _created(OTHER_PROVIDER, V31_CRITICAL),
                severity_event("High", "Critical"),
                priority_event("P3", "P2"),
            ]
            if updated
            else []
        )
        assert await _observe(
            world, lambda s: ticket_events_by_id(s, winner_ticket)
        ) == [*_ingestion_creation(cve_id, NVD), *_high_batch(), *loser_events]
        assert await _observe(world, lambda s: ticket_state(s, winner_ticket)) == (
            NEW,
            None,
            "P2" if updated else "P3",
            None,
            None,
        )
        assert await _observe(world, lambda s: _cve_columns(s, winner_cve)) == (
            LOSER_TITLE if updated else WINNER_TITLE,
            CveState.PUBLISHED.value,
            None,
            "Critical" if updated else "High",
        )
        sources = await _observe(world, lambda s: source_rows(s, winner_cve))
        if updated:
            assert [row[:2] for row in sources] == [
                ("mitre", "success"),
                ("nvd", "success"),
            ]
        else:
            [(source, status, fetched, first_failed)] = sources
            assert (source, status, first_failed) == ("nvd", "success", None)
            # The loser's serialized success write is the latest state.
            assert fetched > winner_fetched

    async def test_rolled_back_apparent_winner_lets_the_waiter_create(
        self, world: IngestionWorld, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cve_id = world.new_cve_id()
        create = SessionCallSpy(monkeypatch, ticket_service, "create_ticket")
        a = await world.open_session()
        b = await world.open_session()

        apparent = await _upsert(a, cve_id, _winner_payload())
        apparent_ids = (apparent.cve.id, apparent.ticket.id)
        task = world.start(
            b,
            _upsert(
                b, cve_id, _cvss_payload(OTHER_PROVIDER, V31_CRITICAL), source=MITRE
            ),
        )
        await assert_lock_wait(task, waiter=b, blocked_by=a)
        await a.rollback()
        result = await asyncio.wait_for(task, timeout=WAIT)
        await b.commit()

        assert result.action is UpsertAction.CREATED
        assert result.cve.id != apparent_ids[0]
        assert result.ticket.id != apparent_ids[1]
        assert create.sessions == [a, b]
        assert await _observe(world, lambda s: cve_ids_of(s, cve_id)) == [result.cve.id]
        assert await _observe(world, lambda s: tickets_of(s, cve_id)) == [
            result.ticket.id
        ]
        assert await _observe(
            world, lambda s: ticket_events_by_id(s, result.ticket.id)
        ) == [
            *_ingestion_creation(cve_id, MITRE),
            _created(OTHER_PROVIDER, V31_CRITICAL),
            severity_event(None, "Critical"),
            priority_event(None, "P2"),
        ]
        sources = await _observe(world, lambda s: source_rows(s, result.cve.id))
        assert [row[:2] for row in sources] == [("mitre", "success")]


# ---------------------------------------------------------------------------
# create/ensure (On-Demand Fetch: `ensure_cve_exists()` > Concurrency)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestCreateEnsure:
    @pytest.mark.parametrize("release", ["commit", "rollback"])
    @pytest.mark.parametrize("lock", [False, True], ids=["plain", "locked"])
    async def test_ensure_waits_for_the_ingestion_insert(
        self, world: IngestionWorld, lock: bool, release: str
    ) -> None:
        """Ensure returns the committed ingestion winner, or becomes the
        insert winner of a placeholder when ingestion rolls back."""
        cve_id = world.new_cve_id()
        a = await world.open_session()
        b = await world.open_session()

        apparent = await _upsert(a, cve_id, _winner_payload())
        apparent_ids = (apparent.cve.id, apparent.ticket.id)
        with SessionStatementRecorder(b) as recorder:
            task = world.start(b, ensure_cve_exists(b, cve_id, lock=lock))
            await assert_lock_wait(task, waiter=b, blocked_by=a)
            assert len(recorder.statements) == 2
            assert is_root_lock(recorder.statements[0], "cve") is lock
            assert _is_cve_insert(recorder.statements[1])
            if release == "commit":
                await a.commit()
            else:
                await a.rollback()
            row = await asyncio.wait_for(task, timeout=WAIT)

        committed = release == "commit"
        assert (row.id == apparent_ids[0]) is committed
        assert row.title == (WINNER_TITLE if committed else None)
        assert await b.scalar(text("SELECT 1")) == 1
        await b.commit()

        assert await _observe(world, lambda s: cve_ids_of(s, cve_id)) == [row.id]
        assert await _observe(world, lambda s: tickets_of(s, cve_id)) == (
            [apparent_ids[1]] if committed else []
        )

    @pytest.mark.parametrize("release", ["commit", "rollback"])
    @pytest.mark.parametrize("payload", ["empty", "title"])
    @pytest.mark.parametrize("lock", [False, True], ids=["plain", "locked"])
    async def test_ingestion_waits_for_the_placeholder_insert(
        self,
        world: IngestionWorld,
        monkeypatch: pytest.MonkeyPatch,
        lock: bool,
        payload: str,
        release: str,
    ) -> None:
        """Ingestion that loses to a committed placeholder obtains it and
        returns `updated` or `unchanged` from its own merge (creating the
        orphan's Ticket is excluded from the action); a rolled-back
        placeholder lets it return `created`."""
        cve_id = world.new_cve_id()
        data = (
            CVEIngestPayload()
            if payload == "empty"
            else CVEIngestPayload(title=WINNER_TITLE)
        )
        create = SessionCallSpy(monkeypatch, ticket_service, "create_ticket")
        a = await world.open_session()
        b = await world.open_session()

        placeholder_id = (await ensure_cve_exists(a, cve_id, lock=lock)).id
        with SessionStatementRecorder(b) as recorder:
            task = world.start(b, _upsert(b, cve_id, data))
            await assert_lock_wait(task, waiter=b, blocked_by=a)
            assert len(recorder.statements) == 2
            assert is_root_lock(recorder.statements[0], "cve")
            assert _is_cve_insert(recorder.statements[1])
            if release == "commit":
                await a.commit()
            else:
                await a.rollback()
            result = await asyncio.wait_for(task, timeout=WAIT)
        await b.commit()

        committed = release == "commit"
        if not committed:
            expected = UpsertAction.CREATED
        elif payload == "empty":
            expected = UpsertAction.UNCHANGED
        else:
            expected = UpsertAction.UPDATED
        assert result.action is expected
        assert (result.cve.id == placeholder_id) is committed
        assert create.sessions == [b]
        assert await _observe(world, lambda s: cve_ids_of(s, cve_id)) == [result.cve.id]
        assert await _observe(world, lambda s: tickets_of(s, cve_id)) == [
            result.ticket.id
        ]
        assert await _observe(
            world, lambda s: ticket_events_by_id(s, result.ticket.id)
        ) == _ingestion_creation(cve_id, NVD)


# ---------------------------------------------------------------------------
# Conflicting rejection and republication (CVE state transition detection;
# testing-strategy.md, CVE Ingestion and Ticket Composition)
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _Lifecycle:
    """The transcribed serialized outcome of one start and commit order.

    `ignore_by` and `reopen_by` name the session (`holder`, `waiter`) that
    invokes the rejection boundary or the system reopen; `None` means no
    call."""

    holder: UpsertAction
    waiter: UpsertAction
    ignore_by: str | None
    reopen_by: str | None
    status: str
    state: CveState
    date_rejected: datetime | None
    events: list[EventRow]


LIFECYCLE: dict[tuple[str, str], _Lifecycle] = {
    # A committed rejection moves `New` to `Ignored`; the waiting
    # republication then observes `REJECTED -> PUBLISHED` and reopens.
    ("new", "rejection-first"): _Lifecycle(
        UpsertAction.UPDATED,
        UpsertAction.UPDATED,
        "holder",
        "waiter",
        ANALYSIS,
        CveState.PUBLISHED,
        None,
        [REJECTION, REOPENED],
    ),
    # The republication of a published CVE is no transition; the waiting
    # rejection observes `PUBLISHED -> REJECTED` and ignores the `New`
    # Ticket.
    ("new", "republication-first"): _Lifecycle(
        UpsertAction.UNCHANGED,
        UpsertAction.UPDATED,
        "waiter",
        None,
        IGNORED,
        CveState.REJECTED,
        LATER_REJECTED_AT,
        [REJECTION],
    ),
    # An unchanged `REJECTED` state (new date only) has no lifecycle
    # effect; the waiting republication reopens the `Ignored` Ticket.
    ("ignored", "rejection-first"): _Lifecycle(
        UpsertAction.UPDATED,
        UpsertAction.UPDATED,
        None,
        "waiter",
        ANALYSIS,
        CveState.PUBLISHED,
        None,
        [REOPENED],
    ),
    # The committed republication reopens; the waiting rejection invokes
    # the boundary on the now-active Ticket, which leaves it unchanged
    # (the accepted oscillation).
    ("ignored", "republication-first"): _Lifecycle(
        UpsertAction.UPDATED,
        UpsertAction.UPDATED,
        "waiter",
        "holder",
        ANALYSIS,
        CveState.REJECTED,
        LATER_REJECTED_AT,
        [REOPENED],
    ),
}


@pytest.mark.integration
class TestLifecycleRace:
    @pytest.mark.parametrize("order", ["rejection-first", "republication-first"])
    @pytest.mark.parametrize("start", ["new", "ignored"])
    async def test_waiter_decides_from_the_locked_current_state(
        self,
        world: IngestionWorld,
        monkeypatch: pytest.MonkeyPatch,
        start: str,
        order: str,
    ) -> None:
        expected = LIFECYCLE[(start, order)]
        if start == "new":
            cve = await world.cve_in()
            ticket = await world.ticket(cve_id=cve.id, status=TicketStatus.NEW)
        else:
            cve = await world.cve_in(state=CveState.REJECTED, date_rejected=REJECTED_AT)
            ticket = await world.ticket(cve_id=cve.id, status=TicketStatus.IGNORED)
        rejection = CVEIngestPayload(
            cve_state=CveState.REJECTED, date_rejected=LATER_REJECTED_AT
        )
        republication = CVEIngestPayload(cve_state=CveState.PUBLISHED)
        first, second = (
            (rejection, republication)
            if order == "rejection-first"
            else (republication, rejection)
        )
        ignore = SessionCallSpy(
            monkeypatch, ticket_service, "ignore_new_for_rejected_cve"
        )
        reopen = SessionCallSpy(
            monkeypatch, ticket_service, "reopen_from_ignored_as_system"
        )
        create = SessionCallSpy(monkeypatch, ticket_service, "create_ticket")
        holder = await world.open_session()
        waiter = await world.open_session()
        sessions = {"holder": holder, "waiter": waiter}
        effect = (TicketConvergenceEffect(ticket.id),)

        with SessionStatementRecorder(waiter) as recorder:
            held = await _upsert(holder, cve.cve_id, first)
            assert pending_ticket_convergence_effects(holder) == (
                effect if expected.reopen_by == "holder" else ()
            )
            task = world.start(waiter, _upsert(waiter, cve.cve_id, second))
            await assert_lock_wait(task, waiter=waiter, blocked_by=holder)
            assert len(recorder.statements) == 1
            assert is_root_lock(recorder.statements[0], "cve")
            await holder.commit()
            waited = await asyncio.wait_for(task, timeout=WAIT)
            assert pending_ticket_convergence_effects(waiter) == (
                effect if expected.reopen_by == "waiter" else ()
            )
            await waiter.commit()

        assert (held.action, waited.action) == (expected.holder, expected.waiter)
        assert held.ticket.id == waited.ticket.id == ticket.id
        assert create.sessions == []
        assert ignore.sessions == (
            [sessions[expected.ignore_by]] if expected.ignore_by else []
        )
        assert reopen.sessions == (
            [sessions[expected.reopen_by]] if expected.reopen_by else []
        )
        assert root_lock_order(recorder.statements) == ["cve", "ticket"]
        assert await _observe(world, lambda s: ticket_state(s, ticket.id)) == (
            expected.status,
            None,
            None,
            None,
            None,
        )
        assert await _observe(world, lambda s: _cve_columns(s, cve.id)) == (
            None,
            expected.state.value,
            expected.date_rejected,
            None,
        )
        assert (
            await _observe(world, lambda s: ticket_events_by_id(s, ticket.id))
            == expected.events
        )


# ---------------------------------------------------------------------------
# Ticket creation on an existing ticketless CVE (Ticket creation winner)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestTicketCreationRace:
    @pytest.mark.parametrize("release", ["commit", "rollback"])
    async def test_one_ticket_and_the_waiter_loads_the_winner(
        self, world: IngestionWorld, monkeypatch: pytest.MonkeyPatch, release: str
    ) -> None:
        """The waiter blocks on the CVE root and then reads the committed
        Ticket under that lock: it attempts no Ticket insert, so no
        `TicketCVEConflictError` or catch-and-requery path exists. A
        rolled-back creator leaves the orphan for the waiter."""
        cve = await world.cve_in()
        create = SessionCallSpy(monkeypatch, ticket_service, "create_ticket")
        a = await world.open_session()
        b = await world.open_session()

        with SessionStatementRecorder(b) as recorder:
            first = await _upsert(a, cve.cve_id, _cvss_payload(PROVIDER, V31_HIGH))
            first_ticket = first.ticket.id
            task = world.start(
                b,
                _upsert(
                    b,
                    cve.cve_id,
                    _cvss_payload(OTHER_PROVIDER, V31_CRITICAL),
                    source=MITRE,
                ),
            )
            await assert_lock_wait(task, waiter=b, blocked_by=a)
            assert len(recorder.statements) == 1
            assert is_root_lock(recorder.statements[0], "cve")
            if release == "commit":
                await a.commit()
            else:
                await a.rollback()
            result = await asyncio.wait_for(task, timeout=WAIT)
            await b.commit()

        committed = release == "commit"
        assert first.action is UpsertAction.UPDATED
        assert result.action is UpsertAction.UPDATED
        assert (result.ticket.id == first_ticket) is committed
        assert root_lock_order(recorder.statements) == ["cve", "ticket"]
        if committed:
            assert create.sessions == [a]
            assert _ticket_inserts(recorder.statements) == []
            events = [
                *_ingestion_creation(cve.cve_id, NVD),
                *_high_batch(),
                _created(OTHER_PROVIDER, V31_CRITICAL),
                severity_event("High", "Critical"),
                priority_event("P3", "P2"),
            ]
        else:
            assert create.sessions == [a, b]
            events = [
                *_ingestion_creation(cve.cve_id, MITRE),
                _created(OTHER_PROVIDER, V31_CRITICAL),
                severity_event(None, "Critical"),
                priority_event(None, "P2"),
            ]
        assert await _observe(world, lambda s: tickets_of(s, cve.cve_id)) == [
            result.ticket.id
        ]
        assert (
            await _observe(world, lambda s: ticket_events_by_id(s, result.ticket.id))
            == events
        )


# ---------------------------------------------------------------------------
# Manual SUSE CVSS against ingestion (cvss-scoring.md, Serialization and
# Concurrent Outcomes and Required Tests; ticket-mutations.md, Serialized
# outcomes)
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _CVSSRace:
    """The transcribed serialized outcome of one manual operation and one
    commit order; `reconciled_by` lists the sessions (`manual`,
    `ingestion`) whose chain reconciled, in order."""

    manual_action: CVSSAssessmentAction
    manual_severity_changed: bool
    batch_severity_changed: bool
    reconciled_by: list[str]
    events: list[EventRow]
    final: tuple[str, str, str]
    assessments: list[tuple[str, str, Decimal, str, str]]


def _cvss_race(operation: str, order: str, actor: User) -> _CVSSRace:
    """The CVE starts without assessments (upsert) or with only SUSE v3.1
    medium (delete); the Ticket is assigned to the active VA actor with one
    automatic Product (threshold 4.0) that stays eligible. Severity follows
    the cascade: SUSE at the default 3.1 wins over `NVD` v3.1 critical. The
    gate reaches `Analyzed` exactly while a SUSE assessment exists.
    `final` is `(status, priority_auto, CVE.severity)`."""
    critical = _created("NVD", V31_CRITICAL)
    manual_first = order == "manual-first"
    if operation == "upsert":
        if manual_first:
            return _CVSSRace(
                CVSSAssessmentAction.CREATED,
                True,
                False,
                ["manual"],
                [
                    cvss_event(actor, None, V31_MEDIUM),
                    severity_event(None, "Medium"),
                    priority_event(None, "P4"),
                    status_event(ANALYSIS, ANALYZED),
                    critical,
                ],
                (ANALYZED, "P4", "Medium"),
                sorted([unit("NVD", V31_CRITICAL), unit("SUSE", V31_MEDIUM)]),
            )
        return _CVSSRace(
            CVSSAssessmentAction.CREATED,
            True,
            True,
            ["ingestion", "manual"],
            [
                critical,
                severity_event(None, "Critical"),
                priority_event(None, "P2"),
                cvss_event(actor, None, V31_MEDIUM),
                severity_event("Critical", "Medium"),
                priority_event("P2", "P4"),
                status_event(ANALYSIS, ANALYZED),
            ],
            (ANALYZED, "P4", "Medium"),
            sorted([unit("NVD", V31_CRITICAL), unit("SUSE", V31_MEDIUM)]),
        )
    if manual_first:
        return _CVSSRace(
            CVSSAssessmentAction.DELETED,
            True,
            True,
            ["manual", "ingestion"],
            [
                cvss_delete_event(actor, V31_MEDIUM),
                severity_event("Medium", None),
                priority_event("P4", None),
                status_event(ANALYZED, ANALYSIS),
                critical,
                severity_event(None, "Critical"),
                priority_event(None, "P2"),
            ],
            (ANALYSIS, "P2", "Critical"),
            [unit("NVD", V31_CRITICAL)],
        )
    return _CVSSRace(
        CVSSAssessmentAction.DELETED,
        True,
        False,
        ["manual"],
        [
            critical,
            cvss_delete_event(actor, V31_MEDIUM),
            severity_event("Medium", "Critical"),
            priority_event("P4", "P2"),
            status_event(ANALYZED, ANALYSIS),
        ],
        (ANALYSIS, "P2", "Critical"),
        [unit("NVD", V31_CRITICAL)],
    )


@pytest.mark.integration
class TestManualCVSSRace:
    @pytest.mark.parametrize("order", ["manual-first", "ingestion-first"])
    @pytest.mark.parametrize("operation", ["upsert", "delete"])
    async def test_serialized_outcome_of_both_orders(
        self,
        world: IngestionWorld,
        monkeypatch: pytest.MonkeyPatch,
        operation: str,
        order: str,
    ) -> None:
        actor = await world.user(role=Role.VULNERABILITY_ANALYST)
        if operation == "upsert":
            cve = await world.cve_in()
            ticket = await world.ticket(
                cve_id=cve.id, status=TicketStatus.ANALYSIS, assignee_id=actor.id
            )
        else:
            cve = await world.cve_in(
                severity=Severity.MEDIUM, assessments=[("SUSE", V31_MEDIUM)]
            )
            ticket = await world.ticket(
                cve_id=cve.id,
                status=TicketStatus.ANALYZED,
                assignee_id=actor.id,
                priority_auto="P4",
            )
        await world.affected_product(ticket, threshold=T4, eligible=True)
        expected = _cvss_race(operation, order, actor)
        batch = SessionCallSpy(
            monkeypatch, ticket_mutations, "upsert_external_cvss_batch"
        )
        reconciled = SessionCallSpy(
            monkeypatch, ticket_mutations, "reconcile_ticket_status", index=1
        )
        assigning = SessionCallSpy(
            monkeypatch, ticket_mutations, "auto_assign_actor", index=2
        )
        manual = await world.open_session()
        ingestion = await world.open_session()
        names = {id(manual): "manual", id(ingestion): "ingestion"}

        def manual_call() -> Coroutine[Any, Any, CVSSAssessmentMutationResult]:
            if operation == "upsert":
                return upsert(manual, cve.id, V31_MEDIUM.canonical, actor)
            return delete_assessment(manual, cve.id, "3.1", actor)

        def ingestion_call() -> Coroutine[Any, Any, UpsertResult]:
            return _upsert(ingestion, cve.cve_id, _cvss_payload("NVD", V31_CRITICAL))

        with (
            SessionStatementRecorder(manual) as manual_recorder,
            SessionStatementRecorder(ingestion) as ingestion_recorder,
        ):
            if order == "manual-first":
                manual_result = await manual_call()
                task = world.start(ingestion, ingestion_call())
                await assert_lock_wait(task, waiter=ingestion, blocked_by=manual)
                assert len(ingestion_recorder.statements) == 1
                assert is_root_lock(ingestion_recorder.statements[0], "cve")
                await manual.commit()
                ingested = await asyncio.wait_for(task, timeout=WAIT)
                await ingestion.commit()
            else:
                ingested = await ingestion_call()
                task = world.start(manual, manual_call())
                await assert_lock_wait(task, waiter=manual, blocked_by=ingestion)
                assert is_root_lock(manual_recorder.statements[0], "user")
                assert is_root_lock(manual_recorder.statements[-1], "cve")
                await ingestion.commit()
                manual_result = await asyncio.wait_for(task, timeout=WAIT)
                await manual.commit()

        assert root_lock_order(manual_recorder.statements) == ["user", "cve", "ticket"]
        assert root_lock_order(ingestion_recorder.statements) == ["cve", "ticket"]
        assert manual_result.action is expected.manual_action
        assert manual_result.severity_changed is expected.manual_severity_changed
        assert manual_result.propagation is CVSSPropagation.IMMEDIATE
        assert manual_result.products.changed == 0
        assert manual_result.assigned is False
        assert manual_result.reconciled is ("manual" in expected.reconciled_by)
        assert ingested.action is UpsertAction.UPDATED
        assert ingested.ticket.id == ticket.id
        [batch_result] = batch.results(ingestion)
        assert batch.sessions == [ingestion]
        assert isinstance(batch_result, ExternalCVSSBatchResult)
        assert batch_result.actions == (
            ExternalCVSSAssessmentOutcome(
                provider="NVD",
                version=CVSSVersion.V3_1,
                action=CVSSAssessmentAction.CREATED,
            ),
        )
        assert batch_result.severity_changed is expected.batch_severity_changed
        assert batch_result.propagation is CVSSPropagation.IMMEDIATE
        assert batch_result.reconciled is ("ingestion" in expected.reconciled_by)
        assert [names[id(s)] for s in reconciled.sessions] == expected.reconciled_by
        # Ingestion is a system action: it never reaches auto-assignment.
        assert assigning.sessions == [manual]

        status, priority, severity = expected.final
        assert await _observe(world, lambda s: ticket_state(s, ticket.id)) == (
            status,
            actor.id,
            priority,
            None,
            None,
        )
        assert await _observe(world, lambda s: cve_severity(s, cve.id)) == severity
        assert await _observe(world, lambda s: eligibility(s, ticket.id)) == [
            (True, False)
        ]
        assert (
            sorted(await _observe(world, lambda s: persisted_assessments(s, cve.id)))
            == expected.assessments
        )
        assert (
            await _observe(world, lambda s: ticket_events_by_id(s, ticket.id))
            == expected.events
        )


# ---------------------------------------------------------------------------
# CVE association against ingestion (ticket-service.md, ATR 9, system path)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestAssociationRace:
    @pytest.mark.parametrize("order", ["association-first", "ingestion-first"])
    @pytest.mark.parametrize("cve_kind", ["orphan", "new"])
    async def test_serialized_outcome_of_both_orders(
        self,
        world: IngestionWorld,
        monkeypatch: pytest.MonkeyPatch,
        cve_kind: str,
        order: str,
    ) -> None:
        """Association first: ingestion loads the associated manual Ticket
        and applies its batch there with system events. Ingestion first:
        the CVE gets its ingestion Ticket and the association raises the
        documented conflict with no effect. A `new` CVE races through the
        shared conflict-aware insert before the root lock."""
        actor = await world.user(role=Role.VULNERABILITY_ANALYST)
        manual_ticket = await world.ticket(
            cve_id=None, status=TicketStatus.ANALYSIS, assignee_id=actor.id
        )
        orphan = cve_kind == "orphan"
        cve_id = (await world.cve_in()).cve_id if orphan else world.new_cve_id()
        create = SessionCallSpy(monkeypatch, ticket_service, "create_ticket")
        batch = SessionCallSpy(
            monkeypatch, ticket_mutations, "upsert_external_cvss_batch"
        )
        chain_reconciled = SessionCallSpy(
            monkeypatch, ticket_mutations, "reconcile_ticket_status", index=1
        )
        association_reconciled = SessionCallSpy(
            monkeypatch, ticket_service, "reconcile_ticket_status", index=1
        )
        manual = await world.open_session()
        ingestion = await world.open_session()

        def associate() -> Coroutine[Any, Any, Ticket]:
            return associate_cve(
                manual,
                ticket_id=manual_ticket.id,
                cve_id=cve_id,
                acting_user_id=actor.id,
                caller=TicketCaller.authenticated(actor.id, Scope.ALL),
                evaluation_date=EVAL,
            )

        def ingest() -> Coroutine[Any, Any, UpsertResult]:
            return _upsert(ingestion, cve_id, _cvss_payload(PROVIDER, V31_HIGH))

        def blocked_at(statements: list[str]) -> bool:
            """An orphan waits at the CVE root lock; a new CVE at the
            conflict-aware insert."""
            last = statements[-1]
            return is_root_lock(last, "cve") if orphan else _is_cve_insert(last)

        with (
            SessionStatementRecorder(manual) as manual_recorder,
            SessionStatementRecorder(ingestion) as ingestion_recorder,
        ):
            if order == "association-first":
                await associate()
                task = world.start(ingestion, ingest())
                await assert_lock_wait(task, waiter=ingestion, blocked_by=manual)
                assert blocked_at(ingestion_recorder.statements)
                assert len(ingestion_recorder.statements) == (1 if orphan else 2)
                await manual.commit()
                result = await asyncio.wait_for(task, timeout=WAIT)
                await ingestion.commit()
            else:
                result = await ingest()
                task = world.start(manual, associate())
                await assert_lock_wait(task, waiter=manual, blocked_by=ingestion)
                assert is_root_lock(manual_recorder.statements[0], "user")
                assert blocked_at(manual_recorder.statements)
                await ingestion.commit()
                with pytest.raises(TicketCVEConflictError) as raised:
                    await asyncio.wait_for(task, timeout=WAIT)
                await manual.rollback()

        assert root_lock_order(manual_recorder.statements) == ["user", "cve", "ticket"]
        assert root_lock_order(ingestion_recorder.statements) == ["cve", "ticket"]
        # The batch reconciles the associated `Analysis` Ticket once; an
        # ingestion-created Ticket is `New`, outside the gate zone.
        association_first = order == "association-first"
        assert chain_reconciled.sessions == ([ingestion] if association_first else [])
        [batch_result] = batch.results(ingestion)
        assert batch_result.severity_changed is True
        assert batch_result.propagation is CVSSPropagation.IMMEDIATE
        assert batch_result.reconciled is association_first
        assert await _observe(world, lambda s: tickets_of(s, cve_id)) == [
            result.ticket.id
        ]

        if association_first:
            assert result.action is UpsertAction.UPDATED
            assert result.ticket.id == manual_ticket.id
            assert create.sessions == []
            assert association_reconciled.sessions == [manual]
            assert await _observe(
                world, lambda s: ticket_events_by_id(s, manual_ticket.id)
            ) == [
                EventRow("cve_associated", actor.id, None, cve_id, None, None),
                *_high_batch(),
            ]
            assert await _observe(
                world, lambda s: ticket_state(s, manual_ticket.id)
            ) == (ANALYSIS, actor.id, "P3", None, None)
            return

        assert result.action is (
            UpsertAction.UPDATED if orphan else UpsertAction.CREATED
        )
        assert result.ticket.id != manual_ticket.id
        assert create.sessions == [ingestion]
        assert association_reconciled.sessions == []
        assert raised.value.existing_ticket_id == await _observe(
            world, lambda s: _sntl(s, result.ticket.id)
        )
        # The loser wrote no Ticket row or event before raising.
        assert [
            s
            for s in manual_recorder.writes()
            if s.startswith(("UPDATE ticket ", "INSERT INTO ticket_audit_event"))
        ] == []
        assert await _observe(
            world, lambda s: ticket_events_by_id(s, result.ticket.id)
        ) == [*_ingestion_creation(cve_id, NVD), *_high_batch()]
        assert (
            await _observe(world, lambda s: ticket_events_by_id(s, manual_ticket.id))
            == []
        )
        assert await _observe(world, lambda s: ticket_state(s, manual_ticket.id)) == (
            ANALYSIS,
            actor.id,
            None,
            None,
            None,
        )
        assert (
            await _observe(
                world,
                lambda s: s.scalar(
                    select(Ticket.cve_id).where(Ticket.id == manual_ticket.id)
                ),
            )
            is None
        )


# ---------------------------------------------------------------------------
# Same-source status writes (CVESource Management; testing-strategy.md, CVE
# Ingestion Persistence)
# ---------------------------------------------------------------------------


STATUSES = [SUCCESS, FAILURE, MISSING]


@pytest.mark.integration
class TestSourceStatusRace:
    @pytest.mark.parametrize("release", ["commit", "rollback"])
    @pytest.mark.parametrize("second", STATUSES, ids=str)
    @pytest.mark.parametrize("first", STATUSES, ids=str)
    @pytest.mark.parametrize("prior", ["absent", "failure-streak"])
    async def test_last_serialized_write_wins(
        self,
        world: IngestionWorld,
        prior: str,
        first: CVESourceFetchStatus,
        second: CVESourceFetchStatus,
        release: str,
    ) -> None:
        """The holder's write serializes first; the waiter's write is the
        latest state. After a holder rollback the waiter serializes against
        the prior committed state. `fetched_at` is the write statement's
        wall clock: later than the waiter's own transaction start, which
        precedes the holder's write."""
        cve = await world.cve_in()
        prior_first_failed: datetime | None = None
        if prior == "failure-streak":
            await record_source_status(world.session, cve.id, NVD, FAILURE)
            await world.session.commit()
            [(_, _, prior_fetched, prior_first_failed)] = await source_rows(
                world.session, cve.id
            )
            await world.session.commit()
            assert prior_first_failed == prior_fetched
        holder = await world.open_session()
        waiter = await world.open_session()

        waiter_start = await waiter.scalar(text("SELECT now()"))
        await record_source_status(holder, cve.id, NVD, first)
        [(_, held_status, held_fetched, held_first_failed)] = await source_rows(
            holder, cve.id
        )
        assert held_status == first.value
        if first is FAILURE:
            assert held_first_failed == (prior_first_failed or held_fetched)
        else:
            assert held_first_failed is None
        task = world.start(waiter, record_source_status(waiter, cve.id, NVD, second))
        await assert_lock_wait(task, waiter=waiter, blocked_by=holder)
        if release == "commit":
            await holder.commit()
        else:
            await holder.rollback()
        await asyncio.wait_for(task, timeout=WAIT)
        await waiter.commit()

        [(source, status, fetched, first_failed)] = await _observe(
            world, lambda s: source_rows(s, cve.id)
        )
        assert (source, status) == ("nvd", second.value)
        assert waiter_start < held_fetched < fetched
        serialized_against = (
            held_first_failed if release == "commit" else prior_first_failed
        )
        if second is not FAILURE:
            assert first_failed is None
        elif serialized_against is not None:
            # A repeated failure preserves the streak start.
            assert first_failed == serialized_against
        else:
            # A failure after success, missing, or no row starts a streak.
            assert first_failed == fetched


# ---------------------------------------------------------------------------
# Composed reference race (ticket-references.md, Race Outcomes; CVSS Lock
# Composition)
# ---------------------------------------------------------------------------


async def _references(
    db: AsyncSession, ticket_id: uuid.UUID
) -> list[tuple[str, str, str | None, str | None, str | None, datetime]]:
    rows = await db.execute(
        select(
            TicketReference.url,
            TicketReference.source,
            TicketReference.type,
            TicketReference.title,
            TicketReference.description,
            TicketReference.updated_at,
        ).where(TicketReference.ticket_id == ticket_id)
    )
    return [
        (r.url, r.source, r.type, r.title, r.description, r.updated_at) for r in rows
    ]


def _automatic_candidate() -> AutomaticReferenceInput:
    return AutomaticReferenceInput(
        url=REFERENCE_URL, title=UPSTREAM_TITLE, explicit_type=ReferenceType.ADVISORY
    )


def _manual_create(
    db: AsyncSession, ticket: Ticket, actor: User
) -> Coroutine[Any, Any, TicketReferenceProjection]:
    """A manual create of the normalized `REFERENCE_URL` with an explicit
    `NULL` type (no classification)."""
    return create_reference(
        db,
        f"SNTL-{ticket.sequence_id}",
        TicketCaller.authenticated(actor.id, Scope.ALL),
        ManualReferenceCreateInput(
            url=REFERENCE_VARIANT, description=MANUAL_DESCRIPTION, type=None
        ),
    )


async def _ingest_with_references(db: AsyncSession, cve_id: str) -> UpsertResult:
    """The fetcher's Phase 1: `upsert_cve()` then, in the same transaction,
    the automatic references."""
    result = await _upsert(db, cve_id, _cvss_payload(PROVIDER, V31_HIGH))
    await upsert_references(
        db, result.ticket.id, cve_id, FETCHER, None, [_automatic_candidate()]
    )
    return result


@pytest.mark.integration
class TestComposedReferenceRace:
    async def test_manual_create_waits_on_the_ingestion_ticket_lock(
        self, world: IngestionWorld
    ) -> None:
        """`upsert_cve()` already holds the Ticket lock through its CVSS
        processing when `upsert_references()` starts (no deadlock window),
        so the manual create waits on that lock and then observes the
        automatic winner: `ReferenceConflictError` with no event."""
        actor = await world.user(role=Role.VULNERABILITY_ANALYST)
        cve = await world.cve_in()
        ticket = await world.ticket(cve_id=cve.id, status=TicketStatus.ANALYSIS)
        a = await world.open_session()
        b = await world.open_session()

        result = await _upsert(a, cve.cve_id, _cvss_payload(PROVIDER, V31_HIGH))
        assert result.ticket.id == ticket.id
        assert await lock_not_available(
            world.probe,
            select(Ticket.id)
            .where(Ticket.id == ticket.id)
            .with_for_update(nowait=True),
        )
        assert await lock_not_available(
            world.probe,
            select(CVE.id)
            .where(CVE.id == cve.id)
            .with_for_update(nowait=True, key_share=True),
        )
        await upsert_references(
            a, ticket.id, cve.cve_id, FETCHER, None, [_automatic_candidate()]
        )
        with SessionStatementRecorder(b) as recorder:
            task = world.start(b, _manual_create(b, ticket, actor))
            await assert_lock_wait(task, waiter=b, blocked_by=a)
            assert len(recorder.statements) == 1
            assert is_root_lock(recorder.statements[0], "ticket")
            await a.commit()
            with pytest.raises(ReferenceConflictError):
                await asyncio.wait_for(task, timeout=WAIT)
        await b.rollback()

        [row] = await _observe(world, lambda s: _references(s, ticket.id))
        assert row[:5] == (REFERENCE_URL, FETCHER, "advisory", UPSTREAM_TITLE, None)
        assert (
            await _observe(world, lambda s: ticket_events_by_id(s, ticket.id))
            == _high_batch()
        )

    async def test_ingestion_waits_on_the_manual_ticket_lock_and_skips_its_row(
        self, world: IngestionWorld
    ) -> None:
        """The manual create holds the Ticket lock; ingestion holds the CVE
        root and waits for the Ticket (CVE then Ticket, no deadlock). After
        the manual commit, the automatic upsert observes the manual winner
        and leaves every field untouched."""
        actor = await world.user(role=Role.VULNERABILITY_ANALYST)
        cve = await world.cve_in()
        ticket = await world.ticket(cve_id=cve.id, status=TicketStatus.ANALYSIS)
        a = await world.open_session()
        b = await world.open_session()

        manual = await _manual_create(b, ticket, actor)
        with SessionStatementRecorder(a) as recorder:
            task = world.start(a, _ingest_with_references(a, cve.cve_id))
            await assert_lock_wait(task, waiter=a, blocked_by=b)
            assert root_lock_order(recorder.statements) == ["cve", "ticket"]
            assert is_root_lock(recorder.statements[-1], "ticket")
            await b.commit()
            result = await asyncio.wait_for(task, timeout=WAIT)
            await a.commit()

        assert result.ticket.id == ticket.id
        assert result.action is UpsertAction.UPDATED
        assert await _observe(world, lambda s: _references(s, ticket.id)) == [
            (REFERENCE_URL, "manual", None, None, MANUAL_DESCRIPTION, manual.updated_at)
        ]
        assert await _observe(world, lambda s: ticket_events_by_id(s, ticket.id)) == [
            EventRow("reference_added", actor.id, None, REFERENCE_URL, None, None),
            *_high_batch(),
        ]
