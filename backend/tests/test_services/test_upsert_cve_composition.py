"""Single-session integration tests for the Ticket composition of
`cve_service.upsert_cve()` (backend/app/services/cve_service.py).

Owning specifications:

- docs/features/tickets/cve-service.md (Primary Entry Point: `upsert_cve()`
  — Parameter `source` label table, evaluation date; Ticket Creation
  Decision; Complete `upsert_cve()` Composition steps 1-10; Post-Ingestion
  Side Effects; Transaction Boundaries > Phase 1; Concurrency > CVE Upsert
  Serialization (closing test paragraph) and CVSS Lock Composition;
  Exceptions).
- docs/features/tickets/cve-tracking.md (Business Rules; CVE Rejection
  Handling: Rejection handling, Rejection revert handling, Rationale).
- docs/features/tickets/ticket-service.md (`create_ticket`,
  `ignore_new_for_rejected_cve()`, `reopen_from_ignored()` CVE-ingestion
  composition; Architectural Test Requirements 13, 17, 18, 19).
- docs/features/tickets/ticket-mutations.md (`upsert_external_cvss_batch()`;
  `refresh_priority_auto()`).
- docs/features/tickets/ticket-priority.md (Refresh Points; Testing
  Requirements 3 and 6).
- docs/features/tickets/tickets.md (Ticket Creation > Automatic: CVE
  Ingestion; Status Transitions, CVE rows; CVE Resolution Behavior).
- docs/features/tickets/ticket-audit-log.md (Canonical Mutation and No-Event
  Matrix rows "Ticket creation", "CVE association and rejection/revert",
  "Other CVE-owned metadata or enrichment mutation"; Cross-Event Ordering,
  Locking, and Rollback; Testing Requirements 1-7, 12, 24, 25, 27, 28).
- docs/features/platform/testing-strategy.md (CVE Ingestion and Ticket
  Composition, pre-commit items; Ticket References, the per-CVE rollback
  injection; Audit Trail Testing; Rollback Within a Test).

Phase order is observed with `tests.support.cve_ingest.CompositionTimeline`,
which records SQL statements, CVSS parse calls, the module logger, and the
composed delegates in one ordered list. Rollback is proven with
`rollback_test_scope()` and a whole-table `persisted_snapshot()`.

Out of scope here: the sole commit and everything after it (registered
Ticket-convergence publication, the package handoff, and
`commit_and_dispatch()`), independent-session races, and the persistence
matrix already owned by `tests/test_services/test_upsert_cve.py`.

Expected values are transcribed from the specifications and the `Vector`
constants, never computed with the module under test. The ingestion audit
labels come from the literal cve-service.md transcription in
`tests/support/ticket_creation.py`. All identifiers, names, and hosts are
fictional.
"""

from __future__ import annotations

import re
import uuid
from collections.abc import Awaitable, Callable
from datetime import UTC, date, datetime
from decimal import Decimal
from typing import Any

import celery
import celery.app.task
import pytest
import redis
import redis.asyncio
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import (
    CVEExternalIdentifierSource,
    CVESourceFetchStatus,
    CVESourceType,
    CveState,
    CVSSVersion,
    PackageStatus,
    ReferenceType,
    Scope,
    SSVCAutomatable,
    SSVCExploitation,
    SSVCTechnicalImpact,
    TicketAuditEventType,
    TicketStatus,
)
from app.models.cve import CVE
from app.models.system_setting import SystemSetting
from app.models.ticket import Ticket
from app.models.ticket_audit_event import TicketAuditEvent
from app.models.ticket_reference import TicketReference
from app.services import (
    cve_service,
    package_service,
    reference_service,
    ticket_mutations,
    ticket_service,
)
from app.services.cve_ingest import (
    AffectedVersionEntry,
    CVEIngestPayload,
    CWEEntry,
    EPSSEntry,
    ExternalIdentifierEntry,
    KEVEntry,
    SSVCEntry,
    UpsertAction,
    UpsertResult,
)
from app.services.reference_service import AutomaticReferenceInput
from app.services.settings import RequiredSystemSettingMissingError
from app.services.ticket_audit_log import TicketAuditLog
from app.services.ticket_convergence_registry import (
    TicketConvergenceEffect,
    pending_ticket_convergence_effects,
)
from app.services.ticket_mutations import (
    CVSSAssessmentAction,
    CVSSPropagation,
    ExternalCVSSAssessmentOutcome,
)
from app.services.ticket_service import TicketCreationSource, TicketCVEConflictError
from app.services.ticket_visibility import TicketCaller
from tests.support.cve_ingest import (
    SKIP_EVENT,
    CompositionTimeline,
    create_default_cvss_version,
    cvss,
    persisted_snapshot,
    replace,
    source_rows,
)
from tests.support.cvss_chain import (
    CallCounter,
    eligibility,
    priority_event,
    product_event,
    severity_event,
    subjects,
    ticket_state,
)
from tests.support.database import rollback_test_scope
from tests.support.external_cvss import external_cvss_event, external_value
from tests.support.no_outbound import OutboundGuard
from tests.support.suse_cvss import (
    V20_CRITICAL,
    V30_CRITICAL,
    V31_CRITICAL,
    V31_HIGH,
    V40_CRITICAL,
    Vector,
    assignment_event,
    persisted_assessments,
    unit,
)
from tests.support.ticket_creation import (
    INGESTION_LABELS,
    creation_events,
    ingestion_comment,
)
from tests.support.ticket_mutations import (
    EVAL,
    EventRow,
    Prod,
    StatementRecorder,
    TicketFactory,
    TreeBuilder,
    VAUser,
    lock_ticket,
    status_event,
    ticket_events,
    unassigned_event,
)

pytest_plugins = [
    "tests.support.ticket_mutation_fixtures",
    "tests.support.no_outbound_fixtures",
]
"""Provides the shared `va_user`, `tree`, and `no_outbound` fixtures."""

pytestmark = pytest.mark.usefixtures("no_fetch_single_sources")
"""An empty fetch-single registry: the freshness refresh of a manual
creation or association takes its no-eligible-source branch."""

Factory = Callable[..., Awaitable[Any]]
CVETicket = Callable[..., Awaitable[tuple[CVE, Ticket | None]]]

NVD = CVESourceType.NVD
NEW_CVE_ID = "CVE-2099-0300"
FETCHER = "sync_nvd_cves"
"""A fetcher name, the automatic-reference `source` (cve-tracking.md,
Business Rule 10)."""

PROVIDER = "Example CNA"
OTHER_PROVIDER = "Example Vendor"
ALPHA_PROVIDER = "Alpha Vendor"
ZETA_PROVIDER = "Zeta Advisory"

CLOCK = datetime(2026, 9, 27, 23, 59, tzinfo=UTC)
"""The patched `cve_service._utc_now()`; its UTC date is `EVAL`."""

REJECTED_AT = datetime(2099, 3, 4, tzinfo=UTC)
T9 = Decimal("9.0")
"""A Product threshold met by the 10.0 fallback but not by 8.1."""
T7 = Decimal("7.0")
"""A Product threshold met by 8.1."""

INACTIVE = "inactive assignee"
"""The closed sanitation reason (ticket-mutations.md, Assignment Eligibility
Sanitization)."""

STATUSES = (
    TicketStatus.NEW,
    TicketStatus.ANALYSIS,
    TicketStatus.ANALYZED,
    TicketStatus.RESOLVED,
    TicketStatus.IGNORED,
    TicketStatus.DUPLICATED,
)

REJECTION = EventRow(
    "status_change",
    None,
    TicketStatus.NEW.value,
    TicketStatus.IGNORED.value,
    "CVE rejected",
    None,
)
"""The exact system rejection event (cve-tracking.md, Rejection handling)."""

CREATE = "create_ticket"
BATCH = "upsert_external_cvss_batch"
REFRESH = "refresh_priority_auto"
IGNORE = "ignore_new_for_rejected_cve"
REOPEN = "reopen_from_ignored_as_system"
SOURCE_STATUS = "record_source_status"

KEV = KEVEntry(date_added=date(2099, 1, 15))


def _ssvc(exploitation: SSVCExploitation) -> SSVCEntry:
    return SSVCEntry(
        exploitation=exploitation,
        automatable=SSVCAutomatable.NO,
        technical_impact=SSVCTechnicalImpact.PARTIAL,
        version="2.0.3",
    )


def _epss(percentile: float) -> EPSSEntry:
    return EPSSEntry(score=0.01, percentile=percentile, assessed_at=date(2099, 1, 15))


EVIDENCE: dict[str, tuple[dict[str, Any], str]] = {
    "kev": ({"kev_data": KEV}, "P1"),
    "ssvc-active": ({"ssvc_assessment": _ssvc(SSVCExploitation.ACTIVE)}, "P2"),
    "ssvc-poc": ({"ssvc_assessment": _ssvc(SSVCExploitation.POC)}, "P3"),
    "epss-0.95": ({"epss_score": _epss(0.95)}, "P3"),
}
"""Evidence-only payload fields and the automatic priority they yield for a
CVE whose severity is SQL `NULL` (ticket-priority.md, Exploitation Level
and Decision Table: `kev` P1, `active` P2, `likely` P3)."""


@pytest.fixture(autouse=True)
async def default_setting(system_setting_factory: Factory) -> SystemSetting:
    """The persisted `default_cvss_version` (the test schema has none)."""
    return await create_default_cvss_version(system_setting_factory)


@pytest.fixture(autouse=True)
def fixed_clock(monkeypatch: pytest.MonkeyPatch) -> None:
    """`upsert_cve()` captures its one `evaluation_date` from `_utc_now()`."""
    monkeypatch.setattr(cve_service, "_utc_now", lambda: CLOCK)


@pytest.fixture
def cve_ticket(cve_factory: Factory, ticket_factory: TicketFactory) -> CVETicket:
    """An existing CVE in `state` and, unless `status` is `None`, its
    associated Ticket in `status` with the given extra columns."""

    async def _create(
        *,
        state: CveState = CveState.PUBLISHED,
        status: TicketStatus | None = TicketStatus.NEW,
        severity: str | None = None,
        **ticket_columns: Any,
    ) -> tuple[CVE, Ticket | None]:
        rejected = state is CveState.REJECTED
        cve: CVE = await cve_factory(
            cve_state=state.value,
            date_rejected=REJECTED_AT if rejected else None,
            severity=severity,
        )
        if status is None:
            return cve, None
        ticket = await ticket_factory(
            status=status.value, cve_id=cve.id, **ticket_columns
        )
        return cve, ticket

    return _create


async def _upsert(
    db: AsyncSession,
    cve_id: str = NEW_CVE_ID,
    payload: CVEIngestPayload | None = None,
    *,
    source: CVESourceType = NVD,
) -> UpsertResult:
    result = await cve_service.upsert_cve(
        db, cve_id, source, payload if payload is not None else CVEIngestPayload()
    )
    assert result.ticket.cve_id == result.cve.id
    return result


def _created(provider: str, vector: Vector) -> EventRow:
    return external_cvss_event(None, external_value(provider, vector))


def _updated(provider: str, old: Vector, new: Vector) -> EventRow:
    return external_cvss_event(
        external_value(provider, old), external_value(provider, new)
    )


def _reactivation(subject: dict[str, str], old: bool, new: bool) -> EventRow:
    """A system Product event of the manual-zone exit's convergence."""
    return product_event({**subject, "reason": "reactivation"}, old, new)


async def _cve_row(db: AsyncSession, cve_id: str) -> CVE | None:
    row: CVE | None = (
        await db.execute(
            select(CVE)
            .where(CVE.cve_id == cve_id)
            .execution_options(populate_existing=True)
        )
    ).scalar_one_or_none()
    return row


async def _external(
    cve_cvss_assessment_factory: Factory,
    cve: CVE,
    provider: str,
    vector: Vector,
) -> None:
    """A persisted assessment whose vector-derived unit is consistent."""
    await cve_cvss_assessment_factory(
        cve_id=cve.id, provider_name=provider, **vector.columns()
    )


_CVE_LOCK = re.compile(r"\bFROM cve\b.*\bFOR (NO KEY )?UPDATE\b", re.DOTALL)
_TICKET_LOCK = re.compile(r"\bFROM ticket\b.*\bFOR UPDATE\b", re.DOTALL)


def _is_cve_lock(statement: str) -> bool:
    return _CVE_LOCK.search(statement) is not None


def _is_ticket_lock(statement: str) -> bool:
    return _TICKET_LOCK.search(statement) is not None


# ---------------------------------------------------------------------------
# One phase order and one evaluation date (Complete Composition steps 1-9)
# ---------------------------------------------------------------------------


def _forbid_date_recapture(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fail any delegate that would capture its own date instead of the
    one supplied by `upsert_cve()` (cve-service.md, Primary Entry Point)."""

    def recapture() -> Any:
        raise AssertionError("a delegate recaptured the evaluation date")

    monkeypatch.setattr(ticket_service, "_utc_now", recapture)
    monkeypatch.setattr(ticket_mutations, "_utc_now", recapture)
    monkeypatch.setattr(package_service, "_utc_today", recapture)


@pytest.mark.integration
class TestPhaseOrder:
    async def test_rejected_creation_follows_the_one_phase_order(
        self, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _forbid_date_recapture(monkeypatch)
        payload = CVEIngestPayload(
            cve_state=CveState.REJECTED,
            date_rejected=REJECTED_AT,
            cvss_assessments=[
                cvss(PROVIDER, "CVSS:3.1/not-a-vector"),
                cvss(PROVIDER, V31_HIGH.canonical),
                cvss(" SUSE ", V31_CRITICAL.canonical),
            ],
        )
        timeline = CompositionTimeline(db_session, monkeypatch)

        with timeline:
            result = await _upsert(db_session, payload=payload)

        assert timeline.top_level() == [
            CREATE,
            BATCH,
            REFRESH,
            IGNORE,
            SOURCE_STATUS,
        ]
        # Step 2 completes, including both sanitized skip warnings, before
        # the first statement of step 3.
        first_sql = timeline.positions("sql")[0]
        parse_and_skip = timeline.positions("parse") + timeline.positions("warning")
        assert timeline.positions("parse") != []
        assert [timeline.entries[i] for i in timeline.positions("warning")] == [
            ("warning", SKIP_EVENT),
            ("warning", SKIP_EVENT),
        ]
        assert max(parse_and_skip) < first_sql
        assert _is_cve_lock(timeline.statements()[0])

        [create] = timeline.calls_of(CREATE)
        assert create.kwargs == {
            "acting_user_id": None,
            "cve_id": NEW_CVE_ID,
            "source": TicketCreationSource.CVE_INGESTION,
            "ingestion_source": NVD,
        }
        [batch] = timeline.calls_of(BATCH)
        assert batch.kwargs["evaluation_date"] == EVAL
        assert batch.kwargs["cve_id"] == result.cve.id
        [ignore] = timeline.calls_of(IGNORE)
        assert ignore.kwargs == {"cve_id": result.cve.id, "ticket": result.ticket}
        [status] = timeline.calls_of(SOURCE_STATUS)
        assert status.args[1:] == (result.cve.id, NVD, CVESourceFetchStatus.SUCCESS)

    async def test_republication_passes_the_same_date_to_batch_and_reopen(
        self,
        db_session: AsyncSession,
        cve_ticket: CVETicket,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        _forbid_date_recapture(monkeypatch)
        cve, ticket = await cve_ticket(
            state=CveState.REJECTED, status=TicketStatus.IGNORED
        )
        assert ticket is not None
        timeline = CompositionTimeline(db_session, monkeypatch)

        with timeline:
            await _upsert(
                db_session,
                cve.cve_id,
                CVEIngestPayload(
                    cve_state=CveState.PUBLISHED,
                    cvss_assessments=[cvss(PROVIDER, V31_HIGH.canonical)],
                ),
            )

        assert timeline.top_level() == [BATCH, REFRESH, REOPEN, SOURCE_STATUS]
        [batch] = timeline.calls_of(BATCH)
        [reopen] = timeline.calls_of(REOPEN)
        assert batch.kwargs["evaluation_date"] == EVAL
        assert reopen.kwargs == {"ticket_id": ticket.id, "evaluation_date": EVAL}


# ---------------------------------------------------------------------------
# The eight ingestion paths (testing-strategy.md, CVE Ingestion and Ticket
# Composition; cve-tracking.md, CVE Rejection Handling)
# ---------------------------------------------------------------------------


def _high_payload(state: CveState | None) -> CVEIngestPayload:
    fields: dict[str, Any] = {"cvss_assessments": [cvss(PROVIDER, V31_HIGH.canonical)]}
    if state is not None:
        fields["cve_state"] = state
    return CVEIngestPayload(**fields)


def _high_creation(cve_id: str) -> list[EventRow]:
    """Ingestion creation of a Ticket with one created `High` assessment:
    creation events, then the CVSS batch (cvss, severity, priority)."""
    return [
        *creation_events(
            creator_id=None, comment=ingestion_comment(NVD), cve_id=cve_id
        ),
        _created(PROVIDER, V31_HIGH),
        severity_event(None, "High"),
        priority_event(None, "P3"),
    ]


@pytest.mark.integration
class TestIngestionPaths:
    async def test_brand_new_published_cve_gets_a_new_ticket(
        self, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        timeline = CompositionTimeline(db_session, monkeypatch)

        result = await _upsert(db_session, payload=_high_payload(CveState.PUBLISHED))

        assert result.action is UpsertAction.CREATED
        assert timeline.top_level() == [CREATE, BATCH, REFRESH, SOURCE_STATUS]
        assert await ticket_state(db_session, result.ticket.id) == (
            TicketStatus.NEW,
            None,
            "P3",
            None,
            None,
        )
        assert await ticket_events(db_session, result.ticket) == _high_creation(
            NEW_CVE_ID
        )

    async def test_brand_new_rejected_cve_gets_a_new_ignored_ticket(
        self, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        timeline = CompositionTimeline(db_session, monkeypatch)

        result = await _upsert(db_session, payload=_high_payload(CveState.REJECTED))

        assert result.action is UpsertAction.CREATED
        assert timeline.top_level() == [CREATE, BATCH, REFRESH, IGNORE, SOURCE_STATUS]
        assert (await ticket_state(db_session, result.ticket.id))[:2] == (
            TicketStatus.IGNORED,
            None,
        )
        assert await ticket_events(db_session, result.ticket) == [
            *_high_creation(NEW_CVE_ID),
            REJECTION,
        ]

    async def test_existing_cve_with_ticket_reuses_it_without_lifecycle(
        self,
        db_session: AsyncSession,
        cve_ticket: CVETicket,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        cve, ticket = await cve_ticket()
        assert ticket is not None
        timeline = CompositionTimeline(db_session, monkeypatch)

        result = await _upsert(
            db_session,
            cve.cve_id,
            CVEIngestPayload(cve_state=CveState.PUBLISHED, title="Fictional"),
        )

        assert result.action is UpsertAction.UPDATED
        assert result.ticket.id == ticket.id
        assert timeline.top_level() == [BATCH, REFRESH, SOURCE_STATUS]
        assert await ticket_events(db_session, ticket) == []

    async def test_published_orphan_gets_a_ticket(
        self,
        db_session: AsyncSession,
        cve_ticket: CVETicket,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        cve, _ = await cve_ticket(status=None)
        timeline = CompositionTimeline(db_session, monkeypatch)

        result = await _upsert(db_session, cve.cve_id, _high_payload(None))

        assert result.action is UpsertAction.UPDATED
        assert timeline.top_level() == [CREATE, BATCH, REFRESH, SOURCE_STATUS]
        assert (await ticket_state(db_session, result.ticket.id))[0] == "New"
        assert await ticket_events(db_session, result.ticket) == _high_creation(
            cve.cve_id
        )

    async def test_unchanged_rejected_cve_has_no_lifecycle_effect(
        self,
        db_session: AsyncSession,
        cve_ticket: CVETicket,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A `New` Ticket of an already-`REJECTED` CVE (for example a manual
        creation) stays `New`: an unchanged `REJECTED` state makes no
        lifecycle call (cve-tracking.md, Rejection handling)."""
        cve, ticket = await cve_ticket(state=CveState.REJECTED)
        assert ticket is not None
        timeline = CompositionTimeline(db_session, monkeypatch)

        result = await _upsert(
            db_session,
            cve.cve_id,
            CVEIngestPayload(
                cve_state=CveState.REJECTED,
                date_rejected=datetime(2099, 4, 5, tzinfo=UTC),
            ),
        )

        assert result.action is UpsertAction.UPDATED
        assert timeline.top_level() == [BATCH, REFRESH, SOURCE_STATUS]
        assert (await ticket_state(db_session, ticket.id))[0] == "New"
        assert await ticket_events(db_session, ticket) == []

    @pytest.mark.parametrize("status", STATUSES, ids=str)
    async def test_published_to_rejected_ignores_only_a_new_ticket(
        self,
        db_session: AsyncSession,
        cve_ticket: CVETicket,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
        status: TicketStatus,
    ) -> None:
        """The boundary is invoked once for every status; only `New` moves.
        An inactive assignee would be cleared by any reconciliation."""
        inactive = await va_user(active=False)
        cve, ticket = await cve_ticket(status=status, assignee_id=inactive.id)
        assert ticket is not None
        timeline = CompositionTimeline(db_session, monkeypatch)

        await _upsert(
            db_session, cve.cve_id, CVEIngestPayload(cve_state=CveState.REJECTED)
        )

        assert timeline.top_level() == [BATCH, REFRESH, IGNORE, SOURCE_STATUS]
        [ignore] = timeline.calls_of(IGNORE)
        assert ignore.kwargs["cve_id"] == cve.id
        assert ignore.kwargs["ticket"].id == ticket.id
        new = status is TicketStatus.NEW
        assert await ticket_state(db_session, ticket.id) == (
            TicketStatus.IGNORED if new else status,
            inactive.id,
            None,
            None,
            None,
        )
        assert await ticket_events(db_session, ticket) == ([REJECTION] if new else [])
        assert pending_ticket_convergence_effects(db_session) == ()

    @pytest.mark.parametrize("status", STATUSES, ids=str)
    async def test_rejected_to_published_reopens_only_an_ignored_ticket(
        self,
        db_session: AsyncSession,
        cve_ticket: CVETicket,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
        status: TicketStatus,
    ) -> None:
        """An `Ignored` Ticket reopens through the system form with its
        assignee retained and its final status from the gates (no tree:
        `Analysis`); every other status is unchanged and not reopened."""
        analyst = await va_user()
        cve, ticket = await cve_ticket(
            state=CveState.REJECTED, status=status, assignee_id=analyst.id
        )
        assert ticket is not None
        timeline = CompositionTimeline(db_session, monkeypatch)

        result = await _upsert(
            db_session, cve.cve_id, CVEIngestPayload(cve_state=CveState.PUBLISHED)
        )

        ignored = status is TicketStatus.IGNORED
        assert timeline.top_level() == [
            BATCH,
            REFRESH,
            *([REOPEN] if ignored else []),
            SOURCE_STATUS,
        ]
        final = TicketStatus.ANALYSIS if ignored else status
        assert result.ticket.status == final
        assert await ticket_state(db_session, ticket.id) == (
            final,
            analyst.id,
            None,
            None,
            None,
        )
        assert await ticket_events(db_session, ticket) == (
            [status_event("Ignored", "Analysis")] if ignored else []
        )
        assert pending_ticket_convergence_effects(db_session) == (
            (TicketConvergenceEffect(ticket.id),) if ignored else ()
        )
        refreshed = await _cve_row(db_session, cve.cve_id)
        assert refreshed is not None
        assert (refreshed.cve_state, refreshed.date_rejected) == ("PUBLISHED", None)


# ---------------------------------------------------------------------------
# Rejected-creation event order (ATR 17; audit "CVE association and
# rejection/revert" row)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestRejectedCreationOrder:
    @pytest.mark.parametrize("path", ["brand-new", "orphan"])
    async def test_creation_then_canonical_cvss_then_rejection_last(
        self,
        db_session: AsyncSession,
        cve_ticket: CVETicket,
        monkeypatch: pytest.MonkeyPatch,
        path: str,
    ) -> None:
        """Candidates arrive version-ascending; events follow version
        (`4.0` before `3.1`) then provider order. The orphan payload omits
        `cve_state` (a non-lifecycle source): creating its Ticket still
        applies the rejection boundary."""
        if path == "orphan":
            cve, _ = await cve_ticket(state=CveState.REJECTED, status=None)
            cve_id = cve.cve_id
            state: dict[str, Any] = {}
        else:
            cve_id = NEW_CVE_ID
            state = {"cve_state": CveState.REJECTED}
        payload = CVEIngestPayload(
            **state,
            cvss_assessments=[
                cvss(PROVIDER, V31_HIGH.canonical),
                cvss(PROVIDER, V40_CRITICAL.canonical),
                cvss(ALPHA_PROVIDER, V40_CRITICAL.canonical),
            ],
        )

        timeline = CompositionTimeline(db_session, monkeypatch)

        result = await _upsert(db_session, cve_id, payload)

        assert timeline.top_level() == [CREATE, BATCH, REFRESH, IGNORE, SOURCE_STATUS]
        assert (await ticket_state(db_session, result.ticket.id))[0] == "Ignored"
        # Severity: no SUSE, so the non-SUSE default-version (3.1) `High`
        # wins over the non-default `4.0` (cvss-scoring.md cascade).
        assert await ticket_events(db_session, result.ticket) == [
            *creation_events(
                creator_id=None, comment=ingestion_comment(NVD), cve_id=cve_id
            ),
            _created(ALPHA_PROVIDER, V40_CRITICAL),
            _created(PROVIDER, V40_CRITICAL),
            _created(PROVIDER, V31_HIGH),
            severity_event(None, "High"),
            priority_event(None, "P3"),
            REJECTION,
        ]


# ---------------------------------------------------------------------------
# Republication with changed CVSS (ATR 18; audit Testing Requirement 27)
# ---------------------------------------------------------------------------


async def _stale_ignored(
    cve_ticket: CVETicket,
    cve_cvss_assessment_factory: Factory,
    tree: TreeBuilder,
    **ticket_columns: Any,
) -> tuple[CVE, Ticket]:
    """A `REJECTED` CVE with a `SUSE` 8.1 assessment behind a stale `NULL`
    severity, and its `Ignored` Ticket with one `AFFECTED` track whose
    Product values are stale for 8.1 (threshold 9.0 eligible, threshold
    7.0 ineligible)."""
    cve, ticket = await cve_ticket(
        state=CveState.REJECTED, status=TicketStatus.IGNORED, **ticket_columns
    )
    assert ticket is not None
    await _external(cve_cvss_assessment_factory, cve, "SUSE", V31_HIGH)
    await tree(
        ticket,
        status=PackageStatus.AFFECTED,
        products=(
            Prod(eligible=True, threshold=T9),
            Prod(eligible=False, threshold=T7),
        ),
    )
    return cve, ticket


@pytest.mark.integration
class TestRepublicationComposition:
    async def test_reopen_converges_from_the_assessment_set_of_this_batch(
        self,
        db_session: AsyncSession,
        cve_ticket: CVETicket,
        cve_cvss_assessment_factory: Factory,
        va_user: VAUser,
        tree: TreeBuilder,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The CVE has a `SUSE` 8.1 assessment but a stale `NULL` severity;
        the `Ignored` Ticket has stale Product values (threshold 9.0
        eligible, threshold 7.0 ineligible).

        The payload's external candidate makes the deferred batch resolve
        the complete set once: direct CVSS, `NULL -> High`, and priority
        events, with Product and gate effects deferred. The reopen then
        converges both Products from the persisted SUSE score and reaches
        `Analyzed` only because the batch persisted `High`: from the stale
        pre-ingest `NULL` severity the gate result would be `Analysis`.
        """
        analyst = await va_user()
        cve, ticket = await _stale_ignored(
            cve_ticket, cve_cvss_assessment_factory, tree, assignee_id=analyst.id
        )
        detail = [
            {k: v for k, v in s.items() if k != "reason"}
            for s in await subjects(db_session, ticket.id)
        ]
        timeline = CompositionTimeline(db_session, monkeypatch)

        with timeline:
            result = await _upsert(
                db_session,
                cve.cve_id,
                CVEIngestPayload(
                    cve_state=CveState.PUBLISHED,
                    cvss_assessments=[cvss(PROVIDER, V31_CRITICAL.canonical)],
                ),
            )

        [batch] = timeline.calls_of(BATCH)
        assert batch.result.propagation is CVSSPropagation.DEFERRED_UNTIL_REACTIVATION
        assert batch.result.reconciled is False
        assert [c.result for c in timeline.calls_of(REFRESH)] == [True, False]
        assert timeline.top_level() == [BATCH, REFRESH, REOPEN, SOURCE_STATUS]
        assert await ticket_events(db_session, ticket) == [
            _created(PROVIDER, V31_CRITICAL),
            severity_event(None, "High"),
            priority_event(None, "P3"),
            _reactivation(detail[0], True, False),
            _reactivation(detail[1], False, True),
            status_event("Ignored", "Analyzed"),
        ]
        assert result.ticket.status == TicketStatus.ANALYZED
        assert await ticket_state(db_session, ticket.id) == (
            TicketStatus.ANALYZED,
            analyst.id,
            "P3",
            None,
            None,
        )
        assert await eligibility(db_session, ticket.id) == [
            (False, False),
            (True, False),
        ]

        # The reopen's Ticket reselect is a same-transaction re-lock: the
        # CVE root was locked first, the Ticket was already locked before
        # the reopen, and nothing after the reopen's re-lock locks the CVE.
        statements = timeline.statements()
        first_cve_lock = next(i for i, s in enumerate(statements) if _is_cve_lock(s))
        first_ticket_lock = next(
            i for i, s in enumerate(statements) if _is_ticket_lock(s)
        )
        assert first_cve_lock < first_ticket_lock
        reopen_at = timeline.entries.index(("call", REOPEN))
        after = [d for k, d in timeline.entries[reopen_at:] if k == "sql"]
        assert _is_ticket_lock(after[0])
        assert "ticket.id" in after[0]
        assert not any(_is_cve_lock(s) for s in after)
        assert db_session.in_transaction()

    async def test_control_stale_severity_alone_reopens_to_analysis(
        self,
        db_session: AsyncSession,
        cve_ticket: CVETicket,
        cve_cvss_assessment_factory: Factory,
        tree: TreeBuilder,
    ) -> None:
        """Control for the test above: the same Ticket reopened without the
        ingestion batch converges the same Products but, with the stale
        `NULL` severity, fails the severity gate and stays `Analysis`."""
        _, ticket = await _stale_ignored(cve_ticket, cve_cvss_assessment_factory, tree)

        result = await ticket_service.reopen_from_ignored_as_system(
            db_session, ticket_id=ticket.id, evaluation_date=EVAL
        )

        assert result.status == TicketStatus.ANALYSIS
        assert await eligibility(db_session, ticket.id) == [
            (False, False),
            (True, False),
        ]

    async def test_association_mismatch_makes_no_lifecycle_call(
        self,
        db_session: AsyncSession,
        cve_ticket: CVETicket,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A locked `Ignored` Ticket that is not the CVE's association (an
        injected invariant violation) is never reopened."""
        cve, _ = await cve_ticket(state=CveState.REJECTED, status=None)
        _, foreign = await cve_ticket(
            state=CveState.REJECTED, status=TicketStatus.IGNORED
        )
        assert foreign is not None

        async def foreign_ticket(db: AsyncSession, locked_cve: CVE) -> Ticket:
            return await lock_ticket(db, foreign)

        monkeypatch.setattr(cve_service, "_lock_ticket_of", foreign_ticket)
        timeline = CompositionTimeline(db_session, monkeypatch)

        await cve_service.upsert_cve(
            db_session, cve.cve_id, NVD, CVEIngestPayload(cve_state=CveState.PUBLISHED)
        )

        assert timeline.top_level() == [BATCH, REFRESH, SOURCE_STATUS]
        assert (await ticket_state(db_session, foreign.id))[0] == "Ignored"
        assert await ticket_events(db_session, foreign) == []


# ---------------------------------------------------------------------------
# Accepted REJECTED -> PUBLISHED -> REJECTED oscillation (cve-tracking.md,
# Rationale)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestOscillation:
    async def test_later_rejection_leaves_the_reopened_ticket_active(
        self,
        db_session: AsyncSession,
        cve_ticket: CVETicket,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        analyst = await va_user()
        cve, ticket = await cve_ticket(
            state=CveState.REJECTED,
            status=TicketStatus.IGNORED,
            assignee_id=analyst.id,
        )
        assert ticket is not None
        await _upsert(
            db_session, cve.cve_id, CVEIngestPayload(cve_state=CveState.PUBLISHED)
        )
        reopened = [status_event("Ignored", "Analysis")]
        assert await ticket_events(db_session, ticket) == reopened
        timeline = CompositionTimeline(db_session, monkeypatch)

        with StatementRecorder(db_session) as recorder:
            await _upsert(
                db_session, cve.cve_id, CVEIngestPayload(cve_state=CveState.REJECTED)
            )

        assert timeline.top_level() == [BATCH, REFRESH, IGNORE, SOURCE_STATUS]
        assert recorder.selects_from("ticket_audit_event") == []
        assert await ticket_state(db_session, ticket.id) == (
            TicketStatus.ANALYSIS,
            analyst.id,
            None,
            None,
            None,
        )
        assert await ticket_events(db_session, ticket) == reopened
        refreshed = await _cve_row(db_session, cve.cve_id)
        assert refreshed is not None
        assert refreshed.cve_state == "REJECTED"


# ---------------------------------------------------------------------------
# Manual operations with an already-REJECTED CVE (tickets.md, CVE Resolution
# Behavior; cve-tracking.md, Rationale)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestManualRejectedCVE:
    async def test_manual_creation_keeps_its_sequence_and_ingestion_stays_inert(
        self,
        db_session: AsyncSession,
        cve_ticket: CVETicket,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Neither the manual creation nor a later ingestion that still
        reports `REJECTED` invokes the rejection boundary."""
        creator = await va_user()
        cve, _ = await cve_ticket(state=CveState.REJECTED, status=None)
        timeline = CompositionTimeline(db_session, monkeypatch)

        ticket = await ticket_service.create_ticket(
            db_session,
            acting_user_id=creator.id,
            cve_id=cve.cve_id,
            source=TicketCreationSource.MANUAL,
        )
        creation = creation_events(
            creator_id=creator.id,
            assignee_username=creator.username,
            cve_id=cve.cve_id,
        )
        assert await ticket_events(db_session, ticket) == creation
        assert (await ticket_state(db_session, ticket.id))[0] == "Analysis"

        await _upsert(
            db_session, cve.cve_id, CVEIngestPayload(cve_state=CveState.REJECTED)
        )

        assert timeline.calls_of(IGNORE) == []
        assert (await ticket_state(db_session, ticket.id))[0] == "Analysis"
        assert await ticket_events(db_session, ticket) == creation

    async def test_manual_association_keeps_its_sequence(
        self,
        db_session: AsyncSession,
        cve_ticket: CVETicket,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        actor = await va_user()
        cve, _ = await cve_ticket(state=CveState.REJECTED, status=None)
        ticket = await ticket_factory(status=TicketStatus.NEW.value)
        timeline = CompositionTimeline(db_session, monkeypatch)

        await ticket_service.associate_cve(
            db_session,
            ticket_id=ticket.id,
            cve_id=cve.cve_id,
            acting_user_id=actor.id,
            caller=TicketCaller.authenticated(actor.id, Scope.ALL),
            evaluation_date=EVAL,
        )

        assert timeline.calls_of(IGNORE) == []
        assert (await ticket_state(db_session, ticket.id))[0] == "Analysis"
        assert await ticket_events(db_session, ticket) == [
            assignment_event(actor),
            status_event("New", "Analysis"),
            EventRow("cve_associated", actor.id, None, cve.cve_id, None, None),
        ]


# ---------------------------------------------------------------------------
# Canonical creation comment for every source (ATR 13; cve-service.md,
# Parameter `source`)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestCreationLabels:
    def test_transcribed_label_table_covers_every_source(self) -> None:
        assert set(INGESTION_LABELS) == set(CVESourceType)

    @pytest.mark.parametrize("path", ["brand-new", "orphan"])
    @pytest.mark.parametrize("source", list(CVESourceType), ids=str)
    async def test_every_source_creates_its_exact_comment(
        self,
        db_session: AsyncSession,
        cve_ticket: CVETicket,
        source: CVESourceType,
        path: str,
    ) -> None:
        if path == "orphan":
            cve, _ = await cve_ticket(status=None)
            cve_id = cve.cve_id
        else:
            cve_id = NEW_CVE_ID

        result = await _upsert(db_session, cve_id, source=source)

        assert await ticket_events(db_session, result.ticket) == [
            EventRow(
                "ticket_created",
                None,
                None,
                None,
                f"CVE ingested from {INGESTION_LABELS[source]}",
                None,
            ),
            EventRow("cve_associated", None, None, cve_id, None, None),
        ]


# ---------------------------------------------------------------------------
# CVE-owned metadata creates no Ticket event (audit Testing Requirement 12)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestCVEOwnedMetadata:
    @pytest.mark.parametrize("status", STATUSES, ids=str)
    async def test_metadata_and_source_status_create_no_ticket_event(
        self,
        db_session: AsyncSession,
        cve_ticket: CVETicket,
        status: TicketStatus,
    ) -> None:
        """Every global field, CWE, external identifier, affected-version
        scope, and evidence that leaves the priority unchanged (SSVC `none`,
        EPSS percentile just below 0.95), plus the source-status write."""
        cve, ticket = await cve_ticket(status=status)
        assert ticket is not None

        result = await _upsert(
            db_session,
            cve.cve_id,
            CVEIngestPayload(
                title="Fictional title",
                description="Fictional description",
                published_date=datetime(2099, 1, 2, tzinfo=UTC),
                modified_date=datetime(2099, 1, 3, tzinfo=UTC),
                cve_state=CveState.PUBLISHED,
                cwe_classifications=[CWEEntry(cwe_id="CWE-79", source="NVD")],
                external_identifiers=[
                    ExternalIdentifierEntry(
                        source=CVEExternalIdentifierSource.GHSA,
                        identifier="GHSA-test-0300-xxxx",
                    )
                ],
                affected_version_operations=[
                    replace(
                        "cna", AffectedVersionEntry(vendor="Example", version="1.0")
                    )
                ],
                ssvc_assessment=_ssvc(SSVCExploitation.NONE),
                epss_score=_epss(0.9499),
            ),
        )

        assert result.action is UpsertAction.UPDATED
        assert result.ticket.id == ticket.id
        assert await ticket_events(db_session, ticket) == []
        assert (await ticket_state(db_session, ticket.id))[0] == status
        [(stored, state, _, _)] = await source_rows(db_session, cve.id)
        assert (stored, state) == ("nvd", "success")


# ---------------------------------------------------------------------------
# Automatic priority refresh (ticket-priority.md, Refresh Points; Testing
# Requirements 3 and 6; ATR 19)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestPriorityRefresh:
    @pytest.mark.parametrize("status", STATUSES, ids=str)
    @pytest.mark.parametrize("evidence", list(EVIDENCE))
    async def test_evidence_only_payload_refreshes_in_every_status(
        self,
        db_session: AsyncSession,
        cve_ticket: CVETicket,
        va_user: VAUser,
        tree: TreeBuilder,
        monkeypatch: pytest.MonkeyPatch,
        evidence: str,
        status: TicketStatus,
    ) -> None:
        """Exactly one system `priority_changed`, and nothing else: an
        inactive assignee, a stale Product value, and a gate result that a
        reconciliation would regress (no SUSE assessment) all survive."""
        fields, expected = EVIDENCE[evidence]
        inactive = await va_user(active=False)
        cve, ticket = await cve_ticket(status=status, assignee_id=inactive.id)
        assert ticket is not None
        await tree(
            ticket, status=PackageStatus.AFFECTED, products=(Prod(eligible=False),)
        )
        timeline = CompositionTimeline(db_session, monkeypatch)

        result = await _upsert(db_session, cve.cve_id, CVEIngestPayload(**fields))

        assert result.action is UpsertAction.UPDATED
        assert timeline.top_level() == [BATCH, REFRESH, SOURCE_STATUS]
        assert [c.result for c in timeline.calls_of(REFRESH)] == [True]
        assert await ticket_events(db_session, ticket) == [
            priority_event(None, expected)
        ]
        assert await ticket_state(db_session, ticket.id) == (
            status,
            inactive.id,
            expected,
            None,
            None,
        )
        assert await eligibility(db_session, ticket.id) == [(False, False)]

    @pytest.mark.parametrize("case", ["unchanged-evidence", "repeat", "override"])
    async def test_unchanged_or_masked_refresh_creates_no_event(
        self,
        db_session: AsyncSession,
        cve_ticket: CVETicket,
        case: str,
    ) -> None:
        columns: dict[str, Any] = {}
        payload = CVEIngestPayload(kev_data=KEV)
        if case == "unchanged-evidence":
            payload = CVEIngestPayload(
                ssvc_assessment=_ssvc(SSVCExploitation.NONE), epss_score=_epss(0.9499)
            )
        elif case == "override":
            columns["priority_override"] = "P4"
        cve, ticket = await cve_ticket(**columns)
        assert ticket is not None
        if case == "repeat":
            await _upsert(db_session, cve.cve_id, payload)
            assert await ticket_events(db_session, ticket) == [
                priority_event(None, "P1")
            ]
        before = await ticket_events(db_session, ticket)

        result = await _upsert(db_session, cve.cve_id, payload)

        assert await ticket_events(db_session, ticket) == before
        expected_auto = {"unchanged-evidence": None, "repeat": "P1", "override": "P1"}
        assert (await ticket_state(db_session, ticket.id))[2] == expected_auto[case]
        assert result.action is (
            UpsertAction.UNCHANGED if case == "repeat" else UpsertAction.UPDATED
        )

    async def test_effective_batch_refreshes_before_reconciliation_once(
        self,
        db_session: AsyncSession,
        cve_ticket: CVETicket,
        cve_cvss_assessment_factory: Factory,
        va_user: VAUser,
        tree: TreeBuilder,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A SUSE 8.1 assessment behind a stale `NULL` severity; an external
        candidate makes the batch resolve `High`. The batch's refresh
        follows the severity and Product events and precedes sanitation and
        the final gate event; the later `upsert_cve()` refresh is a no-op."""
        inactive = await va_user(active=False)
        cve, ticket = await cve_ticket(
            status=TicketStatus.ANALYSIS, assignee_id=inactive.id
        )
        assert ticket is not None
        await _external(cve_cvss_assessment_factory, cve, "SUSE", V31_HIGH)
        await tree(
            ticket,
            status=PackageStatus.AFFECTED,
            products=(Prod(eligible=True, threshold=T9), Prod(eligible=True)),
        )
        detail = await subjects(db_session, ticket.id)
        reconcile = CallCounter(monkeypatch, "reconcile_ticket_status")
        propagate = CallCounter(monkeypatch, "_propagate_automatic_product_eligibility")
        timeline = CompositionTimeline(db_session, monkeypatch)

        result = await _upsert(
            db_session,
            cve.cve_id,
            CVEIngestPayload(cvss_assessments=[cvss(PROVIDER, V40_CRITICAL.canonical)]),
        )

        assert [c.result for c in timeline.calls_of(REFRESH)] == [True, False]
        assert [c.depth for c in timeline.calls_of(REFRESH)] == [1, 0]
        assert (len(reconcile.calls), len(propagate.calls)) == (1, 1)
        assert await ticket_events(db_session, ticket) == [
            _created(PROVIDER, V40_CRITICAL),
            severity_event(None, "High"),
            product_event(detail[0], True, False),
            priority_event(None, "P3"),
            unassigned_event(inactive.username, INACTIVE),
            status_event("Analysis", "Analyzed"),
        ]
        assert result.action is UpsertAction.UPDATED

    @pytest.mark.parametrize("cvss_input", [True, False], ids=["with-cvss", "kev-only"])
    async def test_ingestion_created_ticket_gets_one_refresh_event(
        self,
        db_session: AsyncSession,
        monkeypatch: pytest.MonkeyPatch,
        cvss_input: bool,
    ) -> None:
        """`create_ticket()` leaves the refresh to `upsert_cve()`: one
        refresh outcome, inside the batch when it is effective."""
        timeline = CompositionTimeline(db_session, monkeypatch)
        payload = CVEIngestPayload(
            kev_data=KEV,
            cvss_assessments=(
                [cvss(PROVIDER, V31_HIGH.canonical)] if cvss_input else None
            ),
        )

        result = await _upsert(db_session, payload=payload)

        assert [c.result for c in timeline.calls_of(REFRESH)] == (
            [True, False] if cvss_input else [True]
        )
        cvss_events = (
            [_created(PROVIDER, V31_HIGH), severity_event(None, "High")]
            if cvss_input
            else []
        )
        assert await ticket_events(db_session, result.ticket) == [
            *creation_events(
                creator_id=None, comment=ingestion_comment(NVD), cve_id=NEW_CVE_ID
            ),
            *cvss_events,
            priority_event(None, "P1"),
        ]
        assert result.action is UpsertAction.CREATED


# ---------------------------------------------------------------------------
# One trusted-external CVSS batch (testing-strategy.md, CVE Ingestion and
# Ticket Composition; ticket-mutations.md, `upsert_external_cvss_batch()`)
# ---------------------------------------------------------------------------


def _outcome(
    provider: str, version: CVSSVersion, action: CVSSAssessmentAction
) -> ExternalCVSSAssessmentOutcome:
    return ExternalCVSSAssessmentOutcome(
        provider=provider, version=version, action=action
    )


@pytest.mark.integration
class TestCVSSBatchComposition:
    async def test_mixed_payload_is_one_canonical_batch(
        self,
        db_session: AsyncSession,
        cve_ticket: CVETicket,
        cve_cvss_assessment_factory: Factory,
        tree: TreeBuilder,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Created, updated, unchanged, and three individually invalid
        candidates (reserved provider, unparsable and non-string vectors)
        in scrambled order: one setting read, canonical version-then-
        provider events, one severity event, one Product pass, one
        reconciliation, and no assignment."""
        cve, ticket = await cve_ticket(
            status=TicketStatus.ANALYSIS, severity="High", priority_auto="P3"
        )
        assert ticket is not None
        await _external(cve_cvss_assessment_factory, cve, PROVIDER, V31_HIGH)
        await _external(cve_cvss_assessment_factory, cve, OTHER_PROVIDER, V30_CRITICAL)
        await tree(
            ticket, status=PackageStatus.AFFECTED, products=(Prod(eligible=False),)
        )
        detail = await subjects(db_session, ticket.id)
        reconcile = CallCounter(monkeypatch, "reconcile_ticket_status")
        propagate = CallCounter(monkeypatch, "_propagate_automatic_product_eligibility")
        timeline = CompositionTimeline(db_session, monkeypatch)
        payload = CVEIngestPayload(
            cvss_assessments=[
                cvss(ZETA_PROVIDER, V20_CRITICAL.canonical),
                cvss("SUSE", V31_CRITICAL.canonical),
                cvss(PROVIDER, V40_CRITICAL.canonical),
                cvss(OTHER_PROVIDER, V30_CRITICAL.canonical),
                cvss(PROVIDER, "not a vector"),
                cvss(PROVIDER, V31_CRITICAL.canonical),
                cvss(ALPHA_PROVIDER, V40_CRITICAL.canonical),
                cvss(PROVIDER, 42),
            ]
        )

        with StatementRecorder(db_session) as recorder:
            result = await _upsert(db_session, cve.cve_id, payload)

        assert len(recorder.selects_from("system_setting")) == 1
        assert len(timeline.positions("warning")) == 3
        [batch] = timeline.calls_of(BATCH)
        assert batch.result.actions == (
            _outcome(ALPHA_PROVIDER, CVSSVersion.V4_0, CVSSAssessmentAction.CREATED),
            _outcome(PROVIDER, CVSSVersion.V4_0, CVSSAssessmentAction.CREATED),
            _outcome(PROVIDER, CVSSVersion.V3_1, CVSSAssessmentAction.UPDATED),
            _outcome(OTHER_PROVIDER, CVSSVersion.V3_0, CVSSAssessmentAction.UNCHANGED),
            _outcome(ZETA_PROVIDER, CVSSVersion.V2_0, CVSSAssessmentAction.CREATED),
        )
        assert (len(reconcile.calls), len(propagate.calls)) == (1, 1)
        assert await ticket_events(db_session, ticket) == [
            _created(ALPHA_PROVIDER, V40_CRITICAL),
            _created(PROVIDER, V40_CRITICAL),
            _updated(PROVIDER, V31_HIGH, V31_CRITICAL),
            _created(ZETA_PROVIDER, V20_CRITICAL),
            severity_event("High", "Critical"),
            product_event(detail[0], False, True),
            priority_event("P3", "P2"),
        ]
        assert sorted(await persisted_assessments(db_session, cve.id)) == sorted(
            [
                unit(ZETA_PROVIDER, V20_CRITICAL),
                unit(OTHER_PROVIDER, V30_CRITICAL),
                unit(PROVIDER, V31_CRITICAL),
                unit(ALPHA_PROVIDER, V40_CRITICAL),
                unit(PROVIDER, V40_CRITICAL),
            ]
        )
        assert await ticket_state(db_session, ticket.id) == (
            TicketStatus.ANALYSIS,
            None,
            "P2",
            None,
            None,
        )
        assert result.action is UpsertAction.UPDATED

    async def test_empty_cvss_input_reads_no_setting(
        self,
        db_session: AsyncSession,
        cve_ticket: CVETicket,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        cve, ticket = await cve_ticket(status=TicketStatus.ANALYSIS)
        assert ticket is not None
        timeline = CompositionTimeline(db_session, monkeypatch)

        with StatementRecorder(db_session) as recorder:
            await _upsert(db_session, cve.cve_id, CVEIngestPayload(title="Fictional"))

        assert recorder.selects_from("system_setting") == []
        [batch] = timeline.calls_of(BATCH)
        assert batch.kwargs["assessments"] == []
        assert batch.result.actions == ()
        assert await ticket_events(db_session, ticket) == []


# ---------------------------------------------------------------------------
# No audit-history read (audit Testing Requirement 25)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestNoAuditHistoryRead:
    @pytest.mark.parametrize(
        ("state", "status", "payload_state"),
        [
            pytest.param(None, None, CveState.REJECTED, id="rejected-creation"),
            pytest.param(
                CveState.PUBLISHED,
                TicketStatus.NEW,
                CveState.REJECTED,
                id="published-to-rejected",
            ),
            pytest.param(
                CveState.REJECTED,
                TicketStatus.IGNORED,
                CveState.PUBLISHED,
                id="republication",
            ),
        ],
    )
    async def test_lifecycle_never_selects_audit_events(
        self,
        db_session: AsyncSession,
        cve_ticket: CVETicket,
        state: CveState | None,
        status: TicketStatus | None,
        payload_state: CveState,
    ) -> None:
        cve_id = NEW_CVE_ID
        if state is not None:
            cve, _ = await cve_ticket(state=state, status=status)
            cve_id = cve.cve_id

        with StatementRecorder(db_session) as recorder:
            result = await _upsert(db_session, cve_id, _high_payload(payload_state))

        assert recorder.selects_from("ticket_audit_event") == []
        assert any("INSERT INTO ticket_audit_event" in s for s in recorder.writes())
        assert (await ticket_events(db_session, result.ticket))[-1].event_type == (
            "status_change"
        )


# ---------------------------------------------------------------------------
# No external I/O in Phase 1 (cve-service.md, Complete Composition)
# ---------------------------------------------------------------------------


@pytest.fixture
def broker_and_cache(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Failing substitutes at the Celery publication and Redis command
    boundaries; each blocked call is recorded before it raises."""
    attempts: list[str] = []

    def forbid(name: str) -> Callable[..., Any]:
        def _call(*args: Any, **kwargs: Any) -> Any:
            attempts.append(name)
            raise AssertionError(f"{name} called in Phase 1")

        return _call

    def forbid_async(name: str) -> Callable[..., Awaitable[Any]]:
        async def _call(*args: Any, **kwargs: Any) -> Any:
            attempts.append(name)
            raise AssertionError(f"{name} called in Phase 1")

        return _call

    monkeypatch.setattr(celery.Celery, "send_task", forbid("Celery.send_task"))
    monkeypatch.setattr(celery.app.task.Task, "apply_async", forbid("Task.apply_async"))
    monkeypatch.setattr(redis.Redis, "execute_command", forbid("Redis.execute_command"))
    monkeypatch.setattr(
        redis.asyncio.Redis,
        "execute_command",
        forbid_async("asyncio.Redis.execute_command"),
    )
    return attempts


def _references(
    cve_id: str,
) -> tuple[AutomaticReferenceInput, list[AutomaticReferenceInput]]:
    """A source reference and upstream candidates, one of them invalid."""
    source = AutomaticReferenceInput(
        url=f"https://nvd.example.test/vuln/detail/{cve_id}",
        explicit_type=ReferenceType.ADVISORY,
    )
    upstream = [
        AutomaticReferenceInput(url="ftp://files.example.test/notes.txt"),
        AutomaticReferenceInput(
            url="https://vendor.example.test/advisory/0300", title="Vendor advisory"
        ),
    ]
    return source, upstream


async def _apply_references(db: AsyncSession, result: UpsertResult) -> None:
    """The fetcher's step 10: automatic references in the same transaction."""
    source, upstream = _references(result.cve.cve_id)
    await reference_service.upsert_references(
        db, result.ticket.id, result.cve.cve_id, FETCHER, source, upstream
    )


@pytest.mark.integration
class TestNoExternalIO:
    @pytest.mark.parametrize("path", ["rejected-creation", "republication"])
    async def test_phase_one_with_references_performs_no_external_io(
        self,
        db_session: AsyncSession,
        cve_ticket: CVETicket,
        no_outbound: OutboundGuard,
        broker_and_cache: list[str],
        path: str,
    ) -> None:
        cve_id = NEW_CVE_ID
        payload_state = CveState.REJECTED
        if path == "republication":
            cve, _ = await cve_ticket(
                state=CveState.REJECTED, status=TicketStatus.IGNORED
            )
            cve_id = cve.cve_id
            payload_state = CveState.PUBLISHED

        result = await _upsert(db_session, cve_id, _high_payload(payload_state))
        await _apply_references(db_session, result)

        assert no_outbound.attempts == []
        assert broker_and_cache == []
        assert (await ticket_state(db_session, result.ticket.id))[0] == (
            "Ignored" if path == "rejected-creation" else "Analysis"
        )


# ---------------------------------------------------------------------------
# Composed automatic references and the per-CVE rollback (Phase 1;
# testing-strategy.md, Ticket References)
# ---------------------------------------------------------------------------


async def _reference_rows(
    db: AsyncSession, ticket_id: uuid.UUID
) -> list[tuple[str, str, str | None, str | None]]:
    rows = await db.execute(
        select(
            TicketReference.url,
            TicketReference.source,
            TicketReference.type,
            TicketReference.title,
        )
        .where(TicketReference.ticket_id == ticket_id)
        .order_by(TicketReference.url)
    )
    return [(url, source, type_, title) for url, source, type_, title in rows]


@pytest.mark.integration
class TestComposedReferences:
    async def test_references_join_the_ingestion_without_ticket_events(
        self, db_session: AsyncSession
    ) -> None:
        result = await _upsert(db_session, payload=_high_payload(CveState.REJECTED))
        events = await ticket_events(db_session, result.ticket)

        await _apply_references(db_session, result)

        assert await _reference_rows(db_session, result.ticket.id) == [
            (
                f"https://nvd.example.test/vuln/detail/{NEW_CVE_ID}",
                FETCHER,
                "advisory",
                None,
            ),
            (
                "https://vendor.example.test/advisory/0300",
                FETCHER,
                None,
                "Vendor advisory",
            ),
        ]
        assert await ticket_events(db_session, result.ticket) == events

    @pytest.mark.parametrize("path", ["created-ticket", "existing-ticket"])
    async def test_unexpected_reference_failure_rolls_back_every_effect(
        self,
        db_session: AsyncSession,
        cve_ticket: CVETicket,
        tree: TreeBuilder,
        monkeypatch: pytest.MonkeyPatch,
        path: str,
    ) -> None:
        """A newly created Ticket has no Product, so the Product effect is
        proven on an existing `New` Ticket whose stale Product the batch
        corrects; both paths then reject the Ticket, record source success,
        and write one reference before the injected failure."""
        cve_id = NEW_CVE_ID
        payload_state: CveState | None = CveState.REJECTED
        if path == "existing-ticket":
            cve, ticket = await cve_ticket()
            assert ticket is not None
            await tree(
                ticket, status=PackageStatus.AFFECTED, products=(Prod(eligible=False),)
            )
            cve_id = cve.cve_id
        before = await persisted_snapshot(db_session)
        injected = RuntimeError("injected reference failure")

        async def failing_merge(*args: Any, **kwargs: Any) -> None:
            raise injected

        async with rollback_test_scope(db_session):
            result = await _upsert(db_session, cve_id, _high_payload(payload_state))
            await reference_service.upsert_references(
                db_session,
                result.ticket.id,
                cve_id,
                FETCHER,
                AutomaticReferenceInput(url="https://nvd.example.test/first"),
                [],
            )
            events = await ticket_events(db_session, result.ticket)
            assert events[-1] == REJECTION
            assert any(e.event_type == "cvss_assessment_changed" for e in events)
            assert any(
                e.event_type == "product_eligibility_changed" for e in events
            ) is (path == "existing-ticket")
            assert [
                row[:2] for row in await source_rows(db_session, result.cve.id)
            ] == [("nvd", "success")]
            assert len(await _reference_rows(db_session, result.ticket.id)) == 1
            monkeypatch.setattr(reference_service, "_merge_candidate", failing_merge)
            with pytest.raises(RuntimeError) as raised:
                await reference_service.upsert_references(
                    db_session,
                    result.ticket.id,
                    cve_id,
                    FETCHER,
                    AutomaticReferenceInput(url="https://nvd.example.test/second"),
                    [],
                )
        monkeypatch.undo()

        assert raised.value is injected
        assert await persisted_snapshot(db_session) == before


# ---------------------------------------------------------------------------
# Whole-chain rollback for delegate failures (cve-service.md, Exceptions;
# audit Testing Requirement 24)
# ---------------------------------------------------------------------------

FAILURES = [
    "settings",
    "audit",
    "flush",
    "source-status",
    "eligibility",
    "reconciliation",
    "ticket-conflict",
]


@pytest.mark.integration
class TestWholeChainRollback:
    @pytest.mark.parametrize("failure", FAILURES)
    async def test_delegate_failure_propagates_and_leaves_nothing(
        self,
        db_session: AsyncSession,
        cve_ticket: CVETicket,
        default_setting: SystemSetting,
        tree: TreeBuilder,
        monkeypatch: pytest.MonkeyPatch,
        failure: str,
    ) -> None:
        """Brand-new rejected ingestion for the creation-side failures; a
        republication of an `Ignored` Ticket with a tree for the
        manual-zone-exit failures; an existing Ticket hidden from the lock
        lookup for the uniqueness invariant."""
        injected: BaseException = RuntimeError(f"injected {failure} failure")
        expected: type[BaseException] = RuntimeError
        cve_id = NEW_CVE_ID
        payload = _high_payload(CveState.REJECTED)

        if failure in ("eligibility", "reconciliation"):
            cve, ticket = await cve_ticket(
                state=CveState.REJECTED, status=TicketStatus.IGNORED
            )
            assert ticket is not None
            await tree(
                ticket, status=PackageStatus.AFFECTED, products=(Prod(eligible=False),)
            )
            cve_id = cve.cve_id
            payload = _high_payload(CveState.PUBLISHED)
        elif failure == "ticket-conflict":
            cve, _ = await cve_ticket()
            cve_id = cve.cve_id
            payload = CVEIngestPayload(title="Fictional", kev_data=KEV)
            expected = TicketCVEConflictError
        elif failure == "settings":
            await db_session.delete(default_setting)
            await db_session.flush()
            expected = RequiredSystemSettingMissingError
        before = await persisted_snapshot(db_session)

        async def raising(*args: Any, **kwargs: Any) -> Any:
            raise injected

        original_log = TicketAuditLog.log_event
        original_flush = db_session.flush

        async def failing_log(session: AsyncSession, **kwargs: Any) -> None:
            if kwargs["event_type"] is TicketAuditEventType.STATUS_CHANGE:
                raise injected
            await original_log(session, **kwargs)

        async def failing_flush(*args: Any, **kwargs: Any) -> None:
            if any(
                isinstance(o, TicketAuditEvent) and o.comment == "CVE rejected"
                for o in db_session.new
            ):
                raise injected
            await original_flush(*args, **kwargs)

        async def no_ticket(db: AsyncSession, cve: CVE) -> None:
            return None

        async with rollback_test_scope(db_session):
            if failure == "audit":
                monkeypatch.setattr(TicketAuditLog, "log_event", failing_log)
            elif failure == "flush":
                monkeypatch.setattr(db_session, "flush", failing_flush)
            elif failure == "source-status":
                monkeypatch.setattr(cve_service, "record_source_status", raising)
            elif failure == "eligibility":
                monkeypatch.setattr(
                    package_service, "converge_manual_zone_exit_eligibility", raising
                )
            elif failure == "reconciliation":
                monkeypatch.setattr(ticket_service, "reconcile_ticket_status", raising)
            elif failure == "ticket-conflict":
                monkeypatch.setattr(cve_service, "_lock_ticket_of", no_ticket)
            with pytest.raises(expected) as raised:
                await cve_service.upsert_cve(db_session, cve_id, NVD, payload)
        monkeypatch.undo()

        if expected is RuntimeError:
            assert raised.value is injected
        assert await persisted_snapshot(db_session) == before
        if cve_id == NEW_CVE_ID:
            assert await _cve_row(db_session, NEW_CVE_ID) is None
