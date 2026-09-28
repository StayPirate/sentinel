"""Service integration tests for `refresh_priority_auto()`
(backend/app/services/ticket_mutations.py).

Owning specifications:

- docs/features/tickets/ticket-priority.md (Exploitation Level; Decision
  Table; Persistence and Effective Priority; Automatic Refresh:
  `refresh_priority_auto()`; Audit; Testing Requirements 3 — persisted
  value, exact system event, and every Ticket status —, 4 — the masking
  half — and 6).
- docs/features/tickets/ticket-mutations.md (Utility Functions:
  `refresh_priority_auto()`; Architectural Test Requirement: Automatic
  priority).
- docs/features/tickets/ticket-audit-log.md (Event Type Contract:
  `priority_changed`; Canonical Mutation and No-Event Matrix: Automatic
  priority refresh; Testing Requirements 1-7, 12, 24, 28).
- docs/features/tickets/tickets.md (Severity Resolution; Tickets Without
  CVE).

The pure decision table and exploitation precedence are unit-tested in
test_ticket_priority.py. These tests prove that the persisted evidence
read by the primitive feeds that classification correctly, and they pin
the persistence, audit, idempotency, and non-effect contracts. Expected
values are transcribed from the specification's Decision Table, never
computed with the module under test. The refresh position inside each
calling workflow is tested with that workflow (for manual severity, in
test_set_severity_manual.py).
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import date
from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import PackageStatus, Role, Severity, TicketStatus
from app.models.cve import CVE
from app.models.cve_epss_score import CVEEPSSScore
from app.models.cve_kev_entry import CVEKEVEntry
from app.models.cve_ssvc_assessment import CVESSVCAssessment
from app.models.ticket import Ticket
from app.models.ticket_audit_event import TicketAuditEvent
from app.models.ticket_package_product import TicketPackageProduct
from app.models.ticket_package_track import TicketPackageTrack
from app.services.ticket_audit_log import TicketAuditLog
from app.services.ticket_convergence_registry import (
    pending_ticket_convergence_effects,
)
from app.services.ticket_mutations import refresh_priority_auto
from tests.support.database import rollback_test_scope
from tests.support.ticket_mutations import (
    EventRow,
    Prod,
    StatementRecorder,
    TicketFactory,
    TreeBuilder,
    VAUser,
    cveless,
    lock_ticket,
    ticket_events,
)

pytest_plugins = ["tests.support.ticket_mutation_fixtures"]
"""Provides the shared `va_user` and `tree` fixtures."""

ALL_STATUSES = (
    TicketStatus.NEW,
    TicketStatus.ANALYSIS,
    TicketStatus.ANALYZED,
    TicketStatus.RESOLVED,
    TicketStatus.IGNORED,
    TicketStatus.DUPLICATED,
)


def _priority_event(old: str | None, new: str | None) -> EventRow:
    """The system `priority_changed` event of an automatic refresh
    (ticket-audit-log.md, Event Type Contract)."""
    return EventRow("priority_changed", None, old, new, None, None)


@dataclass(frozen=True, slots=True)
class Evidence:
    """Persisted exploitation evidence of a CVE (ticket-priority.md,
    Exploitation Level). `None` means the row does not exist."""

    kev: bool = False
    ssvc_exploitation: str | None = None
    ssvc_automatable: str = "no"
    ssvc_technical_impact: str = "partial"
    epss_percentile: float | None = None
    epss_score: float = 0.00043


NO_EVIDENCE = Evidence()

CVETicketBuilder = Callable[..., Awaitable[Ticket]]


@pytest.fixture
def cve_ticket(
    ticket_factory: TicketFactory,
    cve_factory: Callable[..., Awaitable[CVE]],
    cve_kev_entry_factory: Callable[..., Awaitable[CVEKEVEntry]],
    cve_ssvc_assessment_factory: Callable[..., Awaitable[CVESSVCAssessment]],
    cve_epss_score_factory: Callable[..., Awaitable[CVEEPSSScore]],
) -> CVETicketBuilder:
    """A Ticket associated with a CVE of `severity` and `evidence`."""

    async def _create(
        *,
        severity: Severity | None,
        evidence: Evidence = NO_EVIDENCE,
        status: TicketStatus = TicketStatus.ANALYSIS,
        **ticket_overrides: Any,
    ) -> Ticket:
        cve = await cve_factory(severity=severity.value if severity else None)
        if evidence.kev:
            await cve_kev_entry_factory(cve_id=cve.id)
        if evidence.ssvc_exploitation is not None:
            await cve_ssvc_assessment_factory(
                cve_id=cve.id,
                exploitation=evidence.ssvc_exploitation,
                automatable=evidence.ssvc_automatable,
                technical_impact=evidence.ssvc_technical_impact,
            )
        if evidence.epss_percentile is not None:
            await cve_epss_score_factory(
                cve_id=cve.id,
                percentile=evidence.epss_percentile,
                score=evidence.epss_score,
            )
        return await ticket_factory(
            status=status.value, cve_id=cve.id, **ticket_overrides
        )

    return _create


async def _refresh(db: AsyncSession, ticket: Ticket) -> bool:
    """Refresh under the caller-held Ticket lock (the documented
    precondition)."""
    locked = await lock_ticket(db, ticket)
    return await refresh_priority_auto(db, ticket=locked)


async def _persisted(db: AsyncSession, ticket: Ticket) -> tuple[str | None, str | None]:
    """The persisted `(priority_auto, priority_override)` columns."""
    row = (
        await db.execute(
            select(Ticket.priority_auto, Ticket.priority_override).where(
                Ticket.id == ticket.id
            )
        )
    ).one()
    return row.priority_auto, row.priority_override


def _is_ticket_update(statement: str) -> bool:
    return statement.lstrip().upper().startswith("UPDATE TICKET SET")


def _is_audit_insert(statement: str) -> bool:
    return statement.lstrip().upper().startswith("INSERT INTO TICKET_AUDIT_EVENT")


# ---------------------------------------------------------------------------
# Persisted evidence feeds the classification
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestEvidenceReads:
    @pytest.mark.parametrize(
        ("severity", "evidence", "expected"),
        [
            pytest.param(Severity.HIGH, Evidence(), "P3", id="no-evidence-unknown"),
            pytest.param(Severity.HIGH, Evidence(kev=True), "P1", id="kev"),
            pytest.param(
                Severity.MEDIUM,
                Evidence(kev=True, ssvc_exploitation="poc", epss_percentile=0.99),
                "P1",
                id="kev-precedes-ssvc-and-epss",
            ),
            pytest.param(
                Severity.MEDIUM,
                Evidence(ssvc_exploitation="active"),
                "P2",
                id="ssvc-active",
            ),
            pytest.param(
                Severity.MEDIUM,
                Evidence(ssvc_exploitation="active", epss_percentile=0.99),
                "P2",
                id="ssvc-active-precedes-epss-likely",
            ),
            pytest.param(
                Severity.MEDIUM, Evidence(ssvc_exploitation="poc"), "P3", id="ssvc-poc"
            ),
            pytest.param(
                Severity.MEDIUM,
                Evidence(ssvc_exploitation="none"),
                "P4",
                id="ssvc-none-is-no-evidence",
            ),
            pytest.param(
                Severity.HIGH,
                Evidence(
                    ssvc_exploitation="none",
                    ssvc_automatable="yes",
                    ssvc_technical_impact="total",
                ),
                "P3",
                id="ssvc-automatable-and-technical-impact-ignored",
            ),
            pytest.param(
                Severity.HIGH,
                Evidence(epss_percentile=0.95),
                "P2",
                id="epss-percentile-at-threshold",
            ),
            pytest.param(
                Severity.HIGH,
                Evidence(epss_percentile=0.9499),
                "P3",
                id="epss-percentile-just-below",
            ),
            pytest.param(
                Severity.HIGH,
                Evidence(epss_percentile=0.10, epss_score=0.99),
                "P3",
                id="epss-score-ignored",
            ),
            pytest.param(
                Severity.CRITICAL,
                Evidence(epss_percentile=0.97),
                "P2",
                id="critical-likely",
            ),
            pytest.param(Severity.LOW, Evidence(), "P4", id="low-unknown"),
            pytest.param(Severity.NONE, Evidence(), "P4", id="none-label-unknown"),
            pytest.param(
                Severity.NONE,
                Evidence(ssvc_exploitation="active"),
                "P3",
                id="none-label-active",
            ),
            pytest.param(None, Evidence(kev=True), "P1", id="null-severity-kev"),
            pytest.param(
                None,
                Evidence(ssvc_exploitation="active"),
                "P2",
                id="null-severity-active",
            ),
            pytest.param(
                None,
                Evidence(epss_percentile=0.95),
                "P3",
                id="null-severity-likely",
            ),
        ],
    )
    async def test_persists_priority_and_records_one_system_event(
        self,
        db_session: AsyncSession,
        cve_ticket: CVETicketBuilder,
        severity: Severity | None,
        evidence: Evidence,
        expected: str,
    ) -> None:
        ticket = await cve_ticket(severity=severity, evidence=evidence)

        assert await _refresh(db_session, ticket) is True

        assert ticket.priority_auto == expected
        assert await _persisted(db_session, ticket) == (expected, None)
        assert await ticket_events(db_session, ticket) == [
            _priority_event(None, expected)
        ]

    async def test_null_severity_without_evidence_stays_null(
        self, db_session: AsyncSession, cve_ticket: CVETicketBuilder
    ) -> None:
        """The `unknown` row with severity `NULL` is `NULL`, never `P4`; the
        `None` severity label (above) is a different input."""
        ticket = await cve_ticket(
            severity=None, evidence=Evidence(ssvc_exploitation="none")
        )
        ticket = await lock_ticket(db_session, ticket)

        with StatementRecorder(db_session) as recorder:
            assert await refresh_priority_auto(db_session, ticket=ticket) is False

        assert recorder.writes() == []
        assert await _persisted(db_session, ticket) == (None, None)
        assert await ticket_events(db_session, ticket) == []

    async def test_reads_evidence_of_the_ticket_own_cve_only(
        self,
        db_session: AsyncSession,
        cve_ticket: CVETicketBuilder,
        cve_kev_entry_factory: Callable[..., Awaitable[CVEKEVEntry]],
        cve_factory: Callable[..., Awaitable[CVE]],
    ) -> None:
        other = await cve_factory(severity=Severity.CRITICAL.value)
        await cve_kev_entry_factory(cve_id=other.id)
        ticket = await cve_ticket(severity=Severity.MEDIUM)

        assert await _refresh(db_session, ticket) is True

        assert ticket.priority_auto == "P4"


# ---------------------------------------------------------------------------
# Return value, idempotency, and old/new effective values
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestReturnValueAndIdempotency:
    async def test_second_invocation_is_a_no_op(
        self, db_session: AsyncSession, cve_ticket: CVETicketBuilder
    ) -> None:
        ticket = await cve_ticket(severity=Severity.HIGH, evidence=Evidence(kev=True))
        assert await _refresh(db_session, ticket) is True

        with StatementRecorder(db_session) as recorder:
            assert await refresh_priority_auto(db_session, ticket=ticket) is False

        # One evidence read and nothing else.
        assert len(recorder.statements) == 1
        assert recorder.writes() == []
        assert await ticket_events(db_session, ticket) == [_priority_event(None, "P1")]

    async def test_unchanged_persisted_value_writes_nothing(
        self, db_session: AsyncSession, cve_ticket: CVETicketBuilder
    ) -> None:
        ticket = await cve_ticket(severity=Severity.HIGH, priority_auto="P3")
        ticket = await lock_ticket(db_session, ticket)

        with StatementRecorder(db_session) as recorder:
            assert await refresh_priority_auto(db_session, ticket=ticket) is False

        assert recorder.writes() == []
        assert await _persisted(db_session, ticket) == ("P3", None)
        assert await ticket_events(db_session, ticket) == []

    @pytest.mark.parametrize(
        ("severity", "evidence", "old", "new"),
        [
            pytest.param(Severity.HIGH, Evidence(kev=True), "P3", "P1", id="raised"),
            pytest.param(Severity.LOW, Evidence(), "P1", "P4", id="lowered"),
            pytest.param(None, Evidence(), "P4", None, id="to-null"),
        ],
    )
    async def test_change_records_old_and_new_effective_priority(
        self,
        db_session: AsyncSession,
        cve_ticket: CVETicketBuilder,
        severity: Severity | None,
        evidence: Evidence,
        old: str,
        new: str | None,
    ) -> None:
        ticket = await cve_ticket(
            severity=severity, evidence=evidence, priority_auto=old
        )

        assert await _refresh(db_session, ticket) is True

        assert await _persisted(db_session, ticket) == (new, None)
        assert await ticket_events(db_session, ticket) == [_priority_event(old, new)]


# ---------------------------------------------------------------------------
# Override masking (Testing Requirement 4, masking half)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestOverrideMasking:
    @pytest.mark.parametrize(
        ("override", "old_auto"),
        [
            pytest.param("P2", "P3", id="override-differs-from-both"),
            pytest.param("P1", "P3", id="override-equals-new-auto"),
            pytest.param("P4", None, id="auto-from-null"),
            pytest.param("P3", "P3", id="override-equals-old-auto"),
        ],
    )
    async def test_masked_change_persists_without_event(
        self,
        db_session: AsyncSession,
        cve_ticket: CVETicketBuilder,
        override: str,
        old_auto: str | None,
    ) -> None:
        ticket = await cve_ticket(
            severity=Severity.HIGH,
            evidence=Evidence(kev=True),
            priority_auto=old_auto,
            priority_override=override,
        )

        assert await _refresh(db_session, ticket) is True

        assert await _persisted(db_session, ticket) == ("P1", override)
        assert await ticket_events(db_session, ticket) == []

    async def test_unchanged_value_behind_override_is_a_no_op(
        self, db_session: AsyncSession, cve_ticket: CVETicketBuilder
    ) -> None:
        ticket = await cve_ticket(
            severity=Severity.HIGH, priority_auto="P3", priority_override="P1"
        )

        assert await _refresh(db_session, ticket) is False

        assert await _persisted(db_session, ticket) == ("P3", "P1")
        assert await ticket_events(db_session, ticket) == []


# ---------------------------------------------------------------------------
# Every Ticket status (Testing Requirement 3)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestEveryStatus:
    @pytest.mark.parametrize("status", ALL_STATUSES)
    async def test_refreshes_in_every_status_without_status_change(
        self,
        db_session: AsyncSession,
        cve_ticket: CVETicketBuilder,
        status: TicketStatus,
    ) -> None:
        ticket = await cve_ticket(
            severity=Severity.HIGH,
            evidence=Evidence(kev=True),
            status=status,
            priority_auto="P3",
        )

        assert await _refresh(db_session, ticket) is True

        assert ticket.status == status
        assert await _persisted(db_session, ticket) == ("P1", None)
        assert await ticket_events(db_session, ticket) == [_priority_event("P3", "P1")]

    @pytest.mark.parametrize("status", [TicketStatus.IGNORED, TicketStatus.DUPLICATED])
    async def test_cveless_manual_zone_ticket_refreshes(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        status: TicketStatus,
    ) -> None:
        ticket = await cveless(ticket_factory, status=status, severity=Severity.HIGH)

        assert await _refresh(db_session, ticket) is True

        assert ticket.status == status
        assert await ticket_events(db_session, ticket) == [_priority_event(None, "P3")]


# ---------------------------------------------------------------------------
# CVE-less Tickets (tickets.md, Tickets Without CVE)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestCvelessTickets:
    @pytest.mark.parametrize(
        ("severity", "expected"),
        [
            (Severity.CRITICAL, "P2"),
            (Severity.HIGH, "P3"),
            (Severity.MEDIUM, "P4"),
            (Severity.LOW, "P4"),
            (Severity.NONE, "P4"),
        ],
    )
    async def test_uses_severity_manual_with_the_unknown_row(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        severity: Severity,
        expected: str,
    ) -> None:
        ticket = await lock_ticket(
            db_session, await cveless(ticket_factory, severity=severity)
        )

        with StatementRecorder(db_session) as recorder:
            assert await refresh_priority_auto(db_session, ticket=ticket) is True

        # No evidence is read for a Ticket without a CVE; the only
        # statements are the Ticket write and its event.
        assert [s for s in recorder.statements if s not in recorder.writes()] == []
        writes = recorder.writes()
        assert len(writes) == 2
        assert sum(map(_is_ticket_update, writes)) == 1
        assert sum(map(_is_audit_insert, writes)) == 1
        assert await _persisted(db_session, ticket) == (expected, None)
        assert await ticket_events(db_session, ticket) == [
            _priority_event(None, expected)
        ]

    async def test_null_severity_manual_keeps_null_without_event(
        self, db_session: AsyncSession, ticket_factory: TicketFactory
    ) -> None:
        ticket = await lock_ticket(
            db_session, await cveless(ticket_factory, severity=None)
        )

        with StatementRecorder(db_session) as recorder:
            assert await refresh_priority_auto(db_session, ticket=ticket) is False

        assert recorder.statements == []
        assert await _persisted(db_session, ticket) == (None, None)
        assert await ticket_events(db_session, ticket) == []

    async def test_cleared_severity_manual_returns_to_null(
        self, db_session: AsyncSession, ticket_factory: TicketFactory
    ) -> None:
        ticket = await cveless(ticket_factory, severity=None, priority_auto="P4")

        assert await _refresh(db_session, ticket) is True

        assert await _persisted(db_session, ticket) == (None, None)
        assert await ticket_events(db_session, ticket) == [_priority_event("P4", None)]


# ---------------------------------------------------------------------------
# Locked-current, in-transaction reads
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestInTransactionReads:
    async def test_observes_unflushed_cve_severity(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_factory: Callable[..., Awaitable[CVE]],
    ) -> None:
        cve = await cve_factory(severity=Severity.LOW.value)
        ticket = await ticket_factory(cve_id=cve.id, priority_auto="P4")

        cve.severity = Severity.CRITICAL.value
        assert await _refresh(db_session, ticket) is True

        assert await ticket_events(db_session, ticket) == [_priority_event("P4", "P2")]

    async def test_observes_unflushed_new_kev_entry(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_factory: Callable[..., Awaitable[CVE]],
    ) -> None:
        cve = await cve_factory(severity=Severity.HIGH.value)
        ticket = await ticket_factory(cve_id=cve.id, priority_auto="P3")

        db_session.add(CVEKEVEntry(cve_id=cve.id, date_added=date(2026, 9, 1)))
        assert await _refresh(db_session, ticket) is True

        assert await ticket_events(db_session, ticket) == [_priority_event("P3", "P1")]

    async def test_observes_unflushed_ssvc_and_epss_updates(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_factory: Callable[..., Awaitable[CVE]],
        cve_ssvc_assessment_factory: Callable[..., Awaitable[CVESSVCAssessment]],
        cve_epss_score_factory: Callable[..., Awaitable[CVEEPSSScore]],
    ) -> None:
        cve = await cve_factory(severity=Severity.MEDIUM.value)
        ssvc = await cve_ssvc_assessment_factory(cve_id=cve.id, exploitation="none")
        epss = await cve_epss_score_factory(cve_id=cve.id, percentile=0.5)
        ticket = await ticket_factory(cve_id=cve.id, priority_auto="P4")

        epss.percentile = 0.96
        assert await _refresh(db_session, ticket) is True
        ssvc.exploitation = "active"
        assert await _refresh(db_session, ticket) is True

        assert await ticket_events(db_session, ticket) == [
            _priority_event("P4", "P3"),
            _priority_event("P3", "P2"),
        ]

    async def test_observes_unflushed_severity_manual(
        self, db_session: AsyncSession, ticket_factory: TicketFactory
    ) -> None:
        ticket = await lock_ticket(
            db_session, await cveless(ticket_factory, severity=None)
        )

        ticket.severity_manual = Severity.CRITICAL.value
        assert await refresh_priority_auto(db_session, ticket=ticket) is True

        assert await _persisted(db_session, ticket) == ("P2", None)


# ---------------------------------------------------------------------------
# Non-effects (Testing Requirement 6) and audit-history independence
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestNonEffects:
    async def test_never_alters_status_assignment_eligibility_or_visibility(
        self,
        db_session: AsyncSession,
        cve_ticket: CVETicketBuilder,
        tree: TreeBuilder,
        va_user: VAUser,
    ) -> None:
        # Reconciliation would regress this Resolved Ticket (actionable
        # AFFECTED track with an unreleased eligible Product, no SUSE
        # assessment) and sanitize its inactive assignee; a refresh must do
        # neither.
        assignee = await va_user(active=False, roles=(Role.RESTRICTED_ANALYST,))
        ticket = await cve_ticket(
            severity=Severity.HIGH,
            evidence=Evidence(kev=True),
            status=TicketStatus.RESOLVED,
            assignee_id=assignee.id,
            is_confidential=True,
        )
        track = await tree(
            ticket,
            status=PackageStatus.AFFECTED,
            products=(Prod(), Prod(eligible=False)),
        )
        ticket = await lock_ticket(db_session, ticket)

        with StatementRecorder(db_session) as recorder:
            assert await refresh_priority_auto(db_session, ticket=ticket) is True

        await db_session.refresh(ticket)
        assert ticket.status == TicketStatus.RESOLVED
        assert ticket.assignee_id == assignee.id
        assert ticket.is_confidential is True
        assert ticket.severity_manual is None
        eligibility = (
            await db_session.execute(
                select(
                    TicketPackageProduct.eligible,
                    TicketPackageProduct.is_eligible_override,
                )
                .where(TicketPackageProduct.ticket_package_track_id == track.id)
                .order_by(TicketPackageProduct.id)
            )
        ).all()
        assert [tuple(row) for row in eligibility] == [(True, False), (False, False)]
        track_status = (
            await db_session.execute(
                select(TicketPackageTrack.status).where(
                    TicketPackageTrack.id == track.id
                )
            )
        ).scalar_one()
        assert track_status == PackageStatus.AFFECTED
        assert pending_ticket_convergence_effects(db_session) == ()
        assert await ticket_events(db_session, ticket) == [_priority_event(None, "P1")]

        # No lock, no audit-history read, no User/package/access read, and
        # exactly the Ticket write plus its event.
        assert recorder.row_locks() == []
        assert recorder.selects_from("ticket_audit_event") == []
        touched = ('"user"', "user_role", "ticket_package", "ticket_access_grant")
        assert [s for s in recorder.statements if any(t in s for t in touched)] == []
        writes = recorder.writes()
        assert len(writes) == 2
        assert sum(map(_is_ticket_update, writes)) == 1
        assert sum(map(_is_audit_insert, writes)) == 1

    async def test_audit_history_is_never_an_input(
        self,
        db_session: AsyncSession,
        cve_ticket: CVETicketBuilder,
        ticket_audit_event_factory: Callable[..., Awaitable[TicketAuditEvent]],
    ) -> None:
        ticket = await cve_ticket(severity=Severity.HIGH)
        # Misleading history claiming an effective P1.
        await ticket_audit_event_factory(
            ticket_id=ticket.id,
            event_type="priority_changed",
            old_value=None,
            new_value="P1",
        )
        ticket = await lock_ticket(db_session, ticket)

        with StatementRecorder(db_session) as recorder:
            assert await refresh_priority_auto(db_session, ticket=ticket) is True

        assert recorder.selects_from("ticket_audit_event") == []
        events = await ticket_events(db_session, ticket)
        assert events[1:] == [_priority_event(None, "P3")]


# ---------------------------------------------------------------------------
# Rollback atomicity (audit Testing Requirements 7 and 24)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestRollback:
    async def test_audit_failure_rolls_back_the_priority_write(
        self,
        db_session: AsyncSession,
        cve_ticket: CVETicketBuilder,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        ticket = await cve_ticket(
            severity=Severity.HIGH, evidence=Evidence(kev=True), priority_auto="P3"
        )

        async def failing(*args: Any, **kwargs: Any) -> None:
            raise RuntimeError("injected audit failure")

        async with rollback_test_scope(db_session):
            monkeypatch.setattr(TicketAuditLog, "log_event", failing)
            with pytest.raises(RuntimeError, match="injected"):
                await _refresh(db_session, ticket)
        monkeypatch.undo()

        await db_session.refresh(ticket)
        assert (ticket.priority_auto, ticket.priority_override) == ("P3", None)
        assert await ticket_events(db_session, ticket) == []

    async def test_flush_failure_rolls_back_a_masked_write(
        self,
        db_session: AsyncSession,
        cve_ticket: CVETicketBuilder,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        ticket = await cve_ticket(
            severity=Severity.HIGH,
            evidence=Evidence(kev=True),
            priority_auto="P3",
            priority_override="P2",
        )

        async def failing(*args: Any, **kwargs: Any) -> None:
            raise RuntimeError("injected flush failure")

        async with rollback_test_scope(db_session):
            locked = await lock_ticket(db_session, ticket)
            monkeypatch.setattr(db_session, "flush", failing)
            with pytest.raises(RuntimeError, match="injected"):
                await refresh_priority_auto(db_session, ticket=locked)
        monkeypatch.undo()

        await db_session.refresh(ticket)
        assert (ticket.priority_auto, ticket.priority_override) == ("P3", "P2")
        assert await ticket_events(db_session, ticket) == []
