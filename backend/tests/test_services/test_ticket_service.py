"""Tests for the Ticket service (backend/app/services/ticket_service.py).

Owning specifications:

- docs/features/tickets/ticket-service.md (Ticket Query Operations >
  Ticket locator resolution and `get_ticket_detail()`): SNTL-only parsing
  without normalization, the canonical visibility predicate, one
  indistinguishable `TicketNotFoundError`, one coherent observation for
  the whole detail, the identifier-only duplicate target, and the
  mutation-assembly mode (workflow date, instant at projection entry, no
  second visibility decision).
- docs/features/tickets/tickets.md (Severity Resolution, Priority,
  Duplicate Handling, Response Schemas > CVEDetail and TicketDetail).
- docs/features/tickets/ticket-priority.md (Persistence and Effective
  Priority; Testing Requirement 9 fields).
- docs/features/tickets/ticket-deadlines.md (Due Dates, Null Due Dates,
  Ticket and Track Dates, Evaluation Instant; Testing Requirements 2, 4,
  7, 12).
- docs/features/platform/testing-strategy.md (Ticket Accessibility >
  single, nested, and assembled reads; identifier-only exceptions;
  controlled clock; independent-session races).

Expected values are transcribed from the specifications, never computed
by the module under test.
"""

from __future__ import annotations

import inspect
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from datetime import UTC, date, datetime, timedelta, timezone
from typing import Any
from unittest.mock import AsyncMock

import pytest
from sqlalchemy import delete, event, func, select, update
from sqlalchemy.exc import NoResultFound, OperationalError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import (
    CveState,
    DeliveryStatus,
    LifecyclePhase,
    MilestoneStatus,
    PackageStatus,
    Role,
    Scope,
    Severity,
    TicketPriority,
    TicketStatus,
    WorkflowType,
)
from app.core.exceptions import ServiceError, TicketNotFoundError
from app.core.identifiers import format_ticket_id
from app.models.cve import CVE
from app.models.cve_epss_score import CVEEPSSScore
from app.models.cve_kev_entry import CVEKEVEntry
from app.models.product import Product
from app.models.ticket import Ticket
from app.models.ticket_access_grant import TicketAccessGrant
from app.models.ticket_audit_event import TicketAuditEvent
from app.models.ticket_package import TicketPackage
from app.models.ticket_package_maintainer import TicketPackageMaintainer
from app.models.ticket_package_product import TicketPackageProduct
from app.models.ticket_package_track import TicketPackageTrack
from app.models.user import User
from app.models.user_role import UserRole
from app.services import package_service, ticket_service
from app.services.ticket_deadlines import DueDates
from app.services.ticket_service import (
    CVEDetailProjection,
    CVEEPSSProjection,
    CVEExternalIdentifierProjection,
    CVEKEVProjection,
    CVESSVCProjection,
    CVEWeaknessProjection,
    ResolvedTicket,
    TicketDetailProjection,
    TicketUserProjection,
    assemble_ticket_detail,
    get_ticket_detail,
    resolve_ticket_locator,
)
from app.services.ticket_visibility import ANONYMOUS_CALLER, TicketCaller
from tests.support.deadline_matrix import (
    BEFORE_ANY_DUE,
    CREATED_AT,
    TIER_30_OFFSETS_DAYS,
    TIER_90_OFFSETS_DAYS,
    TIER_180_OFFSETS_DAYS,
)

Factory = Callable[..., Awaitable[Any]]

MALFORMED_LOCATORS = [
    "sntl-1",
    "Sntl-1",
    " SNTL-1",
    "SNTL-1 ",
    "SNTL-1\n",
    "SNTL-0",
    "SNTL-01",
    "SNTL-0042",
    "SNTL-+1",
    "SNTL--1",
    "SNTL-",
    "SNTL-2147483648",
    "SNTL-99999999999999999999",
    "1",
    "",
    "SNTL-1/audit-log",
    "018f0e2a-7b1c-7cde-8f00-000000000001",
]

ALL_SCOPE = TicketCaller.authenticated(uuid.uuid4(), Scope.ALL)
UPDATED_AT = datetime(2026, 3, 10, 18, 5, 0, 654321, tzinfo=UTC)
CRD = datetime(2026, 4, 1, 12, 0, tzinfo=UTC)
PUBLISHED = datetime(2026, 2, 1, 8, 30, tzinfo=UTC)
MODIFIED = datetime(2026, 2, 3, 9, 45, tzinfo=UTC)
REJECTED = datetime(2026, 2, 5, 10, 0, tzinfo=UTC)
SSVC_AT = datetime(2026, 2, 4, 11, 15, tzinfo=UTC)


def _sntl(ticket: Ticket) -> str:
    return format_ticket_id(ticket.sequence_id)


def _due_dates(offsets: tuple[int, ...]) -> DueDates:
    triage, submission, um, qa, release = (
        CREATED_AT + timedelta(days=days) for days in offsets
    )
    return DueDates(triage=triage, submission=submission, um=um, qa=qa, release=release)


class Clock:
    """Controlled `ticket_service._utc_now()`: each capture pops the next
    queued instant (or reuses `default`) and is recorded in `calls`."""

    def __init__(self) -> None:
        self.default = BEFORE_ANY_DUE
        self.queue: list[datetime] = []
        self.calls: list[datetime] = []

    def now(self) -> datetime:
        instant = self.queue.pop(0) if self.queue else self.default
        self.calls.append(instant)
        return instant


@pytest.fixture
def clock(monkeypatch: pytest.MonkeyPatch) -> Clock:
    controlled = Clock()
    monkeypatch.setattr(ticket_service, "_utc_now", controlled.now)
    return controlled


async def _detail(
    db: AsyncSession, ticket: Ticket, caller: TicketCaller = ALL_SCOPE
) -> TicketDetailProjection:
    return await get_ticket_detail(db, ticket_id=_sntl(ticket), caller=caller)


class _StatementRecorder:
    """Records every SQL statement executed through the test engine."""

    def __init__(self, db: AsyncSession) -> None:
        bind = db.bind
        assert bind is not None
        self._engine = bind.engine.sync_engine
        self.statements: list[str] = []

    def _record(self, *args: Any) -> None:
        self.statements.append(args[2])

    def __enter__(self) -> _StatementRecorder:
        event.listen(self._engine, "before_cursor_execute", self._record)
        return self

    def __exit__(self, *exc: object) -> None:
        event.remove(self._engine, "before_cursor_execute", self._record)


# ---------------------------------------------------------------------------
# Ticket locator resolution
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestTicketNotFoundError:
    def test_is_a_shared_service_error(self) -> None:
        assert issubclass(TicketNotFoundError, ServiceError)

    def test_message_is_static(self) -> None:
        assert str(TicketNotFoundError()) == "Ticket not found."


@pytest.mark.unit
class TestMalformedLocatorPerformsNoQuery:
    @pytest.mark.parametrize("locator", MALFORMED_LOCATORS)
    async def test_malformed_locator_raises_without_database_access(
        self, locator: str
    ) -> None:
        db = AsyncMock(spec=AsyncSession)

        with pytest.raises(TicketNotFoundError):
            await resolve_ticket_locator(db, locator, ANONYMOUS_CALLER)

        db.execute.assert_not_awaited()


@pytest.mark.integration
class TestResolveTicketLocator:
    async def test_visible_ticket_resolves_to_internal_identity(
        self, db_session: AsyncSession, ticket_factory: Factory
    ) -> None:
        ticket: Ticket = await ticket_factory()

        resolved = await resolve_ticket_locator(
            db_session, format_ticket_id(ticket.sequence_id), ANONYMOUS_CALLER
        )

        assert resolved == ResolvedTicket(id=ticket.id, sequence_id=ticket.sequence_id)

    async def test_ticket_uuid_is_not_a_locator(
        self, db_session: AsyncSession, ticket_factory: Factory
    ) -> None:
        ticket: Ticket = await ticket_factory()

        with pytest.raises(TicketNotFoundError):
            await resolve_ticket_locator(db_session, str(ticket.id), ANONYMOUS_CALLER)

    async def test_well_formed_missing_locator_is_not_found(
        self, db_session: AsyncSession
    ) -> None:
        with pytest.raises(TicketNotFoundError):
            await resolve_ticket_locator(
                db_session, "SNTL-2147483647", ANONYMOUS_CALLER
            )

    async def test_inaccessible_ticket_is_not_found(
        self, db_session: AsyncSession, ticket_factory: Factory, user_factory: Factory
    ) -> None:
        ticket: Ticket = await ticket_factory(is_confidential=True)
        user = await user_factory()
        locator = format_ticket_id(ticket.sequence_id)

        for caller in (
            ANONYMOUS_CALLER,
            TicketCaller.authenticated(user.id, Scope.NON_CONFIDENTIAL),
        ):
            with pytest.raises(TicketNotFoundError):
                await resolve_ticket_locator(db_session, locator, caller)

    async def test_accessible_confidential_ticket_resolves(
        self,
        db_session: AsyncSession,
        ticket_factory: Factory,
        user_factory: Factory,
        ticket_access_grant_factory: Factory,
    ) -> None:
        ticket: Ticket = await ticket_factory(is_confidential=True)
        user = await user_factory()
        await ticket_access_grant_factory(ticket_id=ticket.id, user_id=user.id)
        locator = format_ticket_id(ticket.sequence_id)

        for caller in (
            TicketCaller.authenticated(user.id, Scope.NON_CONFIDENTIAL),
            TicketCaller.authenticated(uuid.uuid4(), Scope.ALL),
        ):
            resolved = await resolve_ticket_locator(db_session, locator, caller)
            assert resolved.id == ticket.id

    async def test_every_denial_cause_raises_the_same_exception(
        self, db_session: AsyncSession, ticket_factory: Factory
    ) -> None:
        confidential: Ticket = await ticket_factory(is_confidential=True)
        causes = [
            "sntl-1",
            str(confidential.id),
            "SNTL-2147483647",
            format_ticket_id(confidential.sequence_id),
        ]
        messages = set()
        for locator in causes:
            with pytest.raises(TicketNotFoundError) as excinfo:
                await resolve_ticket_locator(db_session, locator, ANONYMOUS_CALLER)
            assert type(excinfo.value) is TicketNotFoundError
            messages.add(str(excinfo.value))
        assert messages == {"Ticket not found."}

    async def test_database_error_propagates(self) -> None:
        db = AsyncMock(spec=AsyncSession)
        failure = OperationalError("SELECT 1", {}, Exception("connection lost"))
        db.execute.side_effect = failure

        with pytest.raises(OperationalError) as excinfo:
            await resolve_ticket_locator(db, "SNTL-1", ANONYMOUS_CALLER)

        assert excinfo.value is failure


# ---------------------------------------------------------------------------
# Ticket detail: projection
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestDetailProjection:
    async def test_cve_less_ticket_projects_every_root_field(
        self, db_session: AsyncSession, clock: Clock, ticket_factory: Factory
    ) -> None:
        ticket: Ticket = await ticket_factory(
            severity_manual=Severity.MEDIUM.value,
            priority_auto=TicketPriority.P3.value,
            coordinated_release_at=CRD,
            created_at=CREATED_AT,
            updated_at=UPDATED_AT,
        )

        detail = await _detail(db_session, ticket)

        assert detail == TicketDetailProjection(
            ticket_id=_sntl(ticket),
            status=TicketStatus.NEW,
            severity=Severity.MEDIUM,
            priority=TicketPriority.P3,
            priority_automatic=TicketPriority.P3,
            priority_override=None,
            assignee=None,
            cve=None,
            duplicate_of_ticket_id=None,
            is_confidential=False,
            coordinated_release_at=CRD,
            due_dates=_due_dates(TIER_90_OFFSETS_DAYS),
            packages=(),
            created_at=CREATED_AT,
            updated_at=UPDATED_AT,
        )

    async def test_placeholder_cve_without_evidence(
        self,
        db_session: AsyncSession,
        clock: Clock,
        ticket_factory: Factory,
        cve_factory: Factory,
    ) -> None:
        cve = await cve_factory(cve_id="CVE-2099-40001")
        ticket: Ticket = await ticket_factory(cve_id=cve.id, created_at=CREATED_AT)

        detail = await _detail(db_session, ticket)

        assert detail.cve == CVEDetailProjection(
            cve_id="CVE-2099-40001",
            title=None,
            description=None,
            published_date=None,
            modified_date=None,
            cve_state=CveState.PUBLISHED,
            date_rejected=None,
            severity=None,
            external_identifiers=(),
            kev=None,
            epss=None,
            ssvc=None,
            cwes=(),
        )
        assert detail.severity is None
        assert detail.due_dates == _due_dates(TIER_30_OFFSETS_DAYS)

    async def test_complete_cve_evidence_is_expanded_and_ordered(
        self,
        db_session: AsyncSession,
        clock: Clock,
        ticket_factory: Factory,
        cve_factory: Factory,
        cve_kev_entry_factory: Factory,
        cve_epss_score_factory: Factory,
        cve_ssvc_assessment_factory: Factory,
        cve_cwe_factory: Factory,
        cve_external_identifier_factory: Factory,
        cve_cvss_assessment_factory: Factory,
    ) -> None:
        cve = await cve_factory(
            cve_id="CVE-2099-40002",
            title="Fictional overflow",
            description="A fictional heap overflow in example-lib.",
            published_date=PUBLISHED,
            modified_date=MODIFIED,
            cve_state=CveState.REJECTED.value,
            date_rejected=REJECTED,
            severity=Severity.CRITICAL.value,
        )
        ticket: Ticket = await ticket_factory(cve_id=cve.id, created_at=CREATED_AT)
        await cve_kev_entry_factory(
            cve_id=cve.id,
            date_added=date(2026, 2, 6),
            reference_url="https://kev.example.com/CVE-2099-40002",
        )
        await cve_epss_score_factory(
            cve_id=cve.id,
            score=0.97125,
            percentile=0.99876,
            assessed_at=date(2026, 2, 7),
        )
        await cve_ssvc_assessment_factory(
            cve_id=cve.id,
            exploitation="active",
            automatable="yes",
            technical_impact="total",
            version="2.0.3",
            assessed_at=SSVC_AT,
        )
        # Inserted out of order: code-point order differs from both the
        # insertion (UUID) order and a case-insensitive locale collation.
        for cwe_id, source in (
            ("NVD-CWE-noinfo", "NVD"),
            ("CWE-79", "cisa-adp"),
            ("NVD-CWE-Other", "MITRE"),
            ("CWE-79", "Red Hat"),
            ("CWE-79", "NVD"),
            ("CWE-1021", "NVD"),
            ("CWE-79", "MITRE"),
        ):
            await cve_cwe_factory(cve_id=cve.id, cwe_id=cwe_id, source=source)
        for source, identifier, url in (
            ("PYSEC", "PYSEC-2099-1", None),
            ("GHSA", "GHSA-aaaa-bbbb-cccc", "https://advisories.example.com/a"),
            ("GHSA", "GHSA-Zzzz-bbbb-cccc", None),
            # Sorts after PYSEC by identifier but before it by source.
            ("GHSA", "ZZZZ-fictional-0001", None),
        ):
            await cve_external_identifier_factory(
                cve_id=cve.id, source=source, identifier=identifier, url=url
            )
        await cve_cvss_assessment_factory(cve_id=cve.id)

        detail = await _detail(db_session, ticket)

        assert detail.cve == CVEDetailProjection(
            cve_id="CVE-2099-40002",
            title="Fictional overflow",
            description="A fictional heap overflow in example-lib.",
            published_date=PUBLISHED,
            modified_date=MODIFIED,
            cve_state=CveState.REJECTED,
            date_rejected=REJECTED,
            severity=Severity.CRITICAL,
            external_identifiers=(
                CVEExternalIdentifierProjection(
                    source="GHSA", identifier="GHSA-Zzzz-bbbb-cccc", url=None
                ),
                CVEExternalIdentifierProjection(
                    source="GHSA",
                    identifier="GHSA-aaaa-bbbb-cccc",
                    url="https://advisories.example.com/a",
                ),
                CVEExternalIdentifierProjection(
                    source="GHSA", identifier="ZZZZ-fictional-0001", url=None
                ),
                CVEExternalIdentifierProjection(
                    source="PYSEC", identifier="PYSEC-2099-1", url=None
                ),
            ),
            kev=CVEKEVProjection(
                date_added=date(2026, 2, 6),
                reference_url="https://kev.example.com/CVE-2099-40002",
            ),
            epss=CVEEPSSProjection(
                score=0.97125, percentile=0.99876, assessed_at=date(2026, 2, 7)
            ),
            ssvc=CVESSVCProjection(
                exploitation="active",
                automatable="yes",
                technical_impact="total",
                version="2.0.3",
                assessed_at=SSVC_AT,
            ),
            cwes=(
                CVEWeaknessProjection(cwe_id="CWE-1021", sources=("NVD",)),
                CVEWeaknessProjection(
                    cwe_id="CWE-79", sources=("MITRE", "NVD", "Red Hat", "cisa-adp")
                ),
                CVEWeaknessProjection(cwe_id="NVD-CWE-Other", sources=("MITRE",)),
                CVEWeaknessProjection(cwe_id="NVD-CWE-noinfo", sources=("NVD",)),
            ),
        )
        assert detail.severity is Severity.CRITICAL

    @pytest.mark.parametrize("present", ["kev", "epss", "ssvc"])
    async def test_each_evidence_kind_is_independent(
        self,
        present: str,
        db_session: AsyncSession,
        clock: Clock,
        ticket_factory: Factory,
        cve_factory: Factory,
        cve_kev_entry_factory: Factory,
        cve_epss_score_factory: Factory,
        cve_ssvc_assessment_factory: Factory,
    ) -> None:
        cve = await cve_factory()
        ticket: Ticket = await ticket_factory(cve_id=cve.id)
        factory = {
            "kev": cve_kev_entry_factory,
            "epss": cve_epss_score_factory,
            "ssvc": cve_ssvc_assessment_factory,
        }[present]
        await factory(cve_id=cve.id)

        detail = await _detail(db_session, ticket)

        assert detail.cve is not None
        assert {
            kind: getattr(detail.cve, kind) is not None
            for kind in ("kev", "epss", "ssvc")
        } == {kind: kind == present for kind in ("kev", "epss", "ssvc")}

    def test_cwe_grouping_exact_deduplicates_sources(self) -> None:
        """The `(cve_id, cwe_id, source)` unique key already prevents
        duplicate rows; the grouping keeps sources exact-deduplicated
        even if it received one."""
        grouped = ticket_service._cwes(
            [["CWE-79", "MITRE"], ["CWE-79", "MITRE"], ["CWE-79", "NVD"]]
        )

        assert grouped == (
            CVEWeaknessProjection(cwe_id="CWE-79", sources=("MITRE", "NVD")),
        )

    @pytest.mark.parametrize(
        ("cve_severity", "severity_manual", "expected", "offsets"),
        [
            (Severity.CRITICAL, None, Severity.CRITICAL, TIER_30_OFFSETS_DAYS),
            (Severity.HIGH, None, Severity.HIGH, TIER_30_OFFSETS_DAYS),
            (Severity.MEDIUM, None, Severity.MEDIUM, TIER_90_OFFSETS_DAYS),
            (Severity.LOW, None, Severity.LOW, TIER_180_OFFSETS_DAYS),
            (Severity.NONE, None, Severity.NONE, None),
            ("cve-null", None, None, TIER_30_OFFSETS_DAYS),
            (None, Severity.CRITICAL, Severity.CRITICAL, TIER_30_OFFSETS_DAYS),
            (None, Severity.HIGH, Severity.HIGH, TIER_30_OFFSETS_DAYS),
            (None, Severity.MEDIUM, Severity.MEDIUM, TIER_90_OFFSETS_DAYS),
            (None, Severity.LOW, Severity.LOW, TIER_180_OFFSETS_DAYS),
            (None, Severity.NONE, Severity.NONE, None),
            (None, None, None, TIER_30_OFFSETS_DAYS),
        ],
    )
    async def test_severity_resolution_and_due_date_tier(
        self,
        cve_severity: Severity | str | None,
        severity_manual: Severity | None,
        expected: Severity | None,
        offsets: tuple[int, ...] | None,
        db_session: AsyncSession,
        clock: Clock,
        ticket_factory: Factory,
        cve_factory: Factory,
    ) -> None:
        """tickets.md, Severity Resolution; ticket-deadlines.md, SLA Tier:
        the `None` label has no SLA while SQL `NULL` uses 30 days."""
        overrides: dict[str, Any] = {"created_at": CREATED_AT}
        if cve_severity is not None:
            stored = None if cve_severity == "cve-null" else str(cve_severity)
            overrides["cve_id"] = (await cve_factory(severity=stored)).id
        if severity_manual is not None:
            overrides["severity_manual"] = severity_manual.value
        ticket: Ticket = await ticket_factory(**overrides)

        detail = await _detail(db_session, ticket)

        assert detail.severity is expected
        assert detail.due_dates == (_due_dates(offsets) if offsets else None)
        if detail.cve is not None:
            assert detail.cve.severity is expected

    @pytest.mark.parametrize(
        ("auto", "override", "effective"),
        [
            (TicketPriority.P3, None, TicketPriority.P3),
            (TicketPriority.P3, TicketPriority.P1, TicketPriority.P1),
            (TicketPriority.P2, TicketPriority.P2, TicketPriority.P2),
            (None, TicketPriority.P4, TicketPriority.P4),
            (None, None, None),
        ],
    )
    async def test_effective_automatic_and_override_priority(
        self,
        auto: TicketPriority | None,
        override: TicketPriority | None,
        effective: TicketPriority | None,
        db_session: AsyncSession,
        clock: Clock,
        ticket_factory: Factory,
    ) -> None:
        ticket: Ticket = await ticket_factory(
            priority_auto=auto.value if auto else None,
            priority_override=override.value if override else None,
        )

        detail = await _detail(db_session, ticket)

        assert (
            detail.priority,
            detail.priority_automatic,
            detail.priority_override,
        ) == (effective, auto, override)

    @pytest.mark.parametrize("status", [TicketStatus.IGNORED, TicketStatus.DUPLICATED])
    async def test_manual_zone_has_no_due_dates(
        self,
        status: TicketStatus,
        db_session: AsyncSession,
        clock: Clock,
        ticket_factory: Factory,
        ticket_package_factory: Factory,
        ticket_package_track_factory: Factory,
    ) -> None:
        ticket: Ticket = await ticket_factory(
            status=status.value,
            severity_manual=Severity.CRITICAL.value,
            created_at=CREATED_AT,
        )
        package = await ticket_package_factory(ticket_id=ticket.id)
        await ticket_package_track_factory(ticket_package_id=package.id)

        detail = await _detail(db_session, ticket)

        assert detail.status is status
        assert detail.due_dates is None
        assert detail.packages[0].tracks[0].due_dates is None
        assert detail.packages[0].tracks[0].milestones.current_phase is None

    async def test_ticket_and_track_due_dates_are_equal(
        self,
        db_session: AsyncSession,
        clock: Clock,
        ticket_factory: Factory,
        ticket_package_factory: Factory,
        ticket_package_track_factory: Factory,
    ) -> None:
        ticket: Ticket = await ticket_factory(
            severity_manual=Severity.LOW.value, created_at=CREATED_AT
        )
        for name in ("example-a", "example-b"):
            package = await ticket_package_factory(
                ticket_id=ticket.id, package_name=name, deleted_at=None
            )
            await ticket_package_track_factory(ticket_package_id=package.id)

        detail = await _detail(db_session, ticket)

        expected = _due_dates(TIER_180_OFFSETS_DAYS)
        assert detail.due_dates == expected
        assert [t.due_dates for p in detail.packages for t in p.tracks] == [
            expected,
            expected,
        ]
        assert expected.qa == expected.release
        assert expected.triage.time() == CREATED_AT.time()

    async def test_assignee_is_the_current_user_profile(
        self,
        db_session: AsyncSession,
        clock: Clock,
        ticket_factory: Factory,
        user_factory: Factory,
    ) -> None:
        active = await user_factory(
            username="fictional.analyst", full_name="Fictional Analyst"
        )
        inactive = await user_factory(
            username="fictional.former", full_name=None, active=False
        )
        with_active: Ticket = await ticket_factory(assignee_id=active.id)
        with_inactive: Ticket = await ticket_factory(assignee_id=inactive.id)
        await db_session.execute(
            update(User)
            .where(User.id == active.id)
            .values(username="fictional.renamed", full_name="Renamed Analyst")
        )

        first = await _detail(db_session, with_active)
        second = await _detail(db_session, with_inactive)

        assert first.assignee == TicketUserProjection(
            id=active.id,
            username="fictional.renamed",
            full_name="Renamed Analyst",
            active=True,
        )
        assert second.assignee == TicketUserProjection(
            id=inactive.id, username="fictional.former", full_name=None, active=False
        )

    async def test_inaccessible_duplicate_target_exposes_only_its_identifier(
        self,
        db_session: AsyncSession,
        clock: Clock,
        ticket_factory: Factory,
        cve_factory: Factory,
        ticket_package_factory: Factory,
    ) -> None:
        target_cve = await cve_factory(severity=Severity.CRITICAL.value)
        target: Ticket = await ticket_factory(
            is_confidential=True,
            cve_id=target_cve.id,
            priority_auto=TicketPriority.P1.value,
        )
        await ticket_package_factory(ticket_id=target.id, package_name="secret-lib")
        duplicate: Ticket = await ticket_factory(duplicate_of_id=target.id)

        detail = await _detail(db_session, duplicate, ANONYMOUS_CALLER)

        assert detail.duplicate_of_ticket_id == _sntl(target)
        assert (detail.cve, detail.severity, detail.priority, detail.packages) == (
            None,
            None,
            None,
            (),
        )
        with pytest.raises(TicketNotFoundError):
            await _detail(db_session, target, ANONYMOUS_CALLER)

    async def test_duplicate_chain_is_not_followed(
        self, db_session: AsyncSession, clock: Clock, ticket_factory: Factory
    ) -> None:
        """A chain violates the `mark_as_duplicate` invariant but not the
        database constraints; the projection still selects only the
        direct target's `sequence_id`."""
        root: Ticket = await ticket_factory()
        middle: Ticket = await ticket_factory(duplicate_of_id=root.id)
        leaf: Ticket = await ticket_factory(duplicate_of_id=middle.id)

        detail = await _detail(db_session, leaf)

        assert detail.duplicate_of_ticket_id == _sntl(middle)

    async def test_package_tree_is_the_package_owned_projection(
        self,
        db_session: AsyncSession,
        clock: Clock,
        ticket_factory: Factory,
        cve_factory: Factory,
        product_factory: Factory,
        ticket_package_factory: Factory,
        ticket_package_track_factory: Factory,
        ticket_package_product_factory: Factory,
        ticket_package_maintainer_factory: Factory,
        user_factory: Factory,
    ) -> None:
        cve = await cve_factory(severity=Severity.HIGH.value)
        ticket: Ticket = await ticket_factory(cve_id=cve.id, created_at=CREATED_AT)
        maintainer = await user_factory()
        for name in ("zlib", "Example-Tool", "curl"):
            package = await ticket_package_factory(
                ticket_id=ticket.id, package_name=name
            )
            await ticket_package_maintainer_factory(
                ticket_package_id=package.id, user_id=maintainer.id
            )
            for reference in ("Example:B", "Example:A"):
                track = await ticket_package_track_factory(
                    ticket_package_id=package.id,
                    reference=reference,
                    status=PackageStatus.AFFECTED.value,
                )
                await ticket_package_product_factory(
                    ticket_package_track_id=track.id,
                    product_id=(
                        await product_factory(general_support_end_date=date(2030, 1, 1))
                    ).id,
                )

        detail = await _detail(db_session, ticket)

        assert detail.packages == await package_service.get_ticket_packages(
            db_session,
            ticket_id=_sntl(ticket),
            caller=ALL_SCOPE,
            evaluation_date=BEFORE_ANY_DUE.date(),
            evaluation_instant=BEFORE_ANY_DUE,
        )
        assert [p.package_name for p in detail.packages] == [
            "Example-Tool",
            "curl",
            "zlib",
        ]
        assert [t.reference for t in detail.packages[0].tracks] == [
            "Example:A",
            "Example:B",
        ]


# ---------------------------------------------------------------------------
# Ticket detail: accessibility
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestDetailAccessibility:
    @pytest.mark.parametrize("locator", MALFORMED_LOCATORS)
    async def test_malformed_locator_raises_without_database_access(
        self, locator: str
    ) -> None:
        db = AsyncMock(spec=AsyncSession)

        with pytest.raises(TicketNotFoundError):
            await get_ticket_detail(db, ticket_id=locator, caller=ALL_SCOPE)

        db.execute.assert_not_awaited()

    async def test_uuid_missing_and_inaccessible_raise_the_same_error(
        self, db_session: AsyncSession, ticket_factory: Factory
    ) -> None:
        confidential: Ticket = await ticket_factory(is_confidential=True)

        for locator in (
            str(confidential.id),
            "SNTL-2147483647",
            _sntl(confidential),
        ):
            with pytest.raises(TicketNotFoundError) as excinfo:
                await get_ticket_detail(
                    db_session, ticket_id=locator, caller=ANONYMOUS_CALLER
                )
            assert type(excinfo.value) is TicketNotFoundError

    @pytest.mark.parametrize("branch", ["scope_all", "grant", "maintainer"])
    async def test_each_visibility_branch_returns_the_confidential_detail(
        self,
        branch: str,
        db_session: AsyncSession,
        ticket_factory: Factory,
        user_factory: Factory,
        ticket_access_grant_factory: Factory,
        ticket_package_factory: Factory,
        ticket_package_maintainer_factory: Factory,
    ) -> None:
        ticket: Ticket = await ticket_factory(is_confidential=True)
        package = await ticket_package_factory(ticket_id=ticket.id)
        user = await user_factory()
        scope = Scope.ALL if branch == "scope_all" else Scope.NON_CONFIDENTIAL
        if branch == "grant":
            await ticket_access_grant_factory(ticket_id=ticket.id, user_id=user.id)
        elif branch == "maintainer":
            await ticket_package_maintainer_factory(
                ticket_package_id=package.id, user_id=user.id
            )

        detail = await _detail(
            db_session, ticket, TicketCaller.authenticated(user.id, scope)
        )

        assert detail.ticket_id == _sntl(ticket)
        assert detail.is_confidential is True

    async def test_non_confidential_detail_is_visible_to_anonymous(
        self, db_session: AsyncSession, ticket_factory: Factory
    ) -> None:
        ticket: Ticket = await ticket_factory()

        detail = await _detail(db_session, ticket, ANONYMOUS_CALLER)

        assert detail.ticket_id == _sntl(ticket)

    async def test_excluded_maintained_package_grants_no_access(
        self,
        db_session: AsyncSession,
        ticket_factory: Factory,
        user_factory: Factory,
        ticket_package_factory: Factory,
        ticket_package_maintainer_factory: Factory,
    ) -> None:
        ticket: Ticket = await ticket_factory(is_confidential=True)
        package = await ticket_package_factory(
            ticket_id=ticket.id, deleted_at=datetime(2026, 3, 11, tzinfo=UTC)
        )
        user = await user_factory()
        await ticket_package_maintainer_factory(
            ticket_package_id=package.id, user_id=user.id
        )

        with pytest.raises(TicketNotFoundError):
            await _detail(
                db_session,
                ticket,
                TicketCaller.authenticated(user.id, Scope.NON_CONFIDENTIAL),
            )

    async def test_database_errors_propagate(self) -> None:
        db = AsyncMock(spec=AsyncSession)
        failure = OperationalError("SELECT 1", {}, Exception("connection lost"))
        db.execute.side_effect = failure

        with pytest.raises(OperationalError) as excinfo:
            await get_ticket_detail(db, ticket_id="SNTL-1", caller=ALL_SCOPE)
        assert excinfo.value is failure

        with pytest.raises(OperationalError) as excinfo:
            await assemble_ticket_detail(
                db, ticket_id=uuid.uuid4(), evaluation_date=date(2026, 3, 11)
            )
        assert excinfo.value is failure


# ---------------------------------------------------------------------------
# Evaluation date and instant
# ---------------------------------------------------------------------------

_DAY = date(2026, 3, 19)
_MIDNIGHT = datetime(2026, 3, 20, tzinfo=UTC)


async def _lifecycle_ticket(
    ticket_factory: Factory,
    product_factory: Factory,
    ticket_package_factory: Factory,
    ticket_package_track_factory: Factory,
    ticket_package_product_factory: Factory,
) -> Ticket:
    """A Ticket whose triage is due exactly at `_MIDNIGHT` (30-day tier)
    with one ANALYSIS track whose only Product leaves general support at
    the end of `_DAY`."""
    ticket: Ticket = await ticket_factory(created_at=_MIDNIGHT - timedelta(days=3))
    package = await ticket_package_factory(ticket_id=ticket.id)
    track = await ticket_package_track_factory(ticket_package_id=package.id)
    product = await product_factory(general_support_end_date=_DAY)
    await ticket_package_product_factory(
        ticket_package_track_id=track.id, product_id=product.id
    )
    return ticket


@pytest.mark.integration
class TestEvaluationDateAndInstant:
    async def test_consumer_captures_one_instant_and_uses_its_utc_date(
        self,
        db_session: AsyncSession,
        clock: Clock,
        ticket_factory: Factory,
        product_factory: Factory,
        ticket_package_factory: Factory,
        ticket_package_track_factory: Factory,
        ticket_package_product_factory: Factory,
    ) -> None:
        ticket = await _lifecycle_ticket(
            ticket_factory,
            product_factory,
            ticket_package_factory,
            ticket_package_track_factory,
            ticket_package_product_factory,
        )
        before_midnight = _MIDNIGHT - timedelta(seconds=1)
        # 23:30 UTC on _DAY expressed at +02:00 (local date is the next day).
        offset_instant = datetime(
            2026, 3, 20, 1, 30, tzinfo=timezone(timedelta(hours=2))
        )
        clock.queue = [before_midnight, offset_instant, _MIDNIGHT]

        results = [await _detail(db_session, ticket) for _ in range(3)]

        assert clock.calls == [before_midnight, offset_instant, _MIDNIGHT]
        tracks = [detail.packages[0].tracks[0] for detail in results]
        for track in tracks[:2]:
            assert track.products[0].lifecycle_phase is LifecyclePhase.GENERAL_SUPPORT
            assert track.actionable is True
            assert track.milestones.triage is MilestoneStatus.PENDING
        assert tracks[2].products[0].lifecycle_phase is LifecyclePhase.EOL
        assert tracks[2].actionable is False
        assert tracks[2].milestones.triage is MilestoneStatus.NOT_APPLICABLE

    async def test_assembly_keeps_the_workflow_date_across_midnight(
        self,
        db_session: AsyncSession,
        clock: Clock,
        ticket_factory: Factory,
        product_factory: Factory,
        ticket_package_factory: Factory,
        ticket_package_track_factory: Factory,
        ticket_package_product_factory: Factory,
    ) -> None:
        """ticket-deadlines.md, Evaluation Instant: actionability uses the
        workflow date while milestones compare against the later instant
        captured at projection entry."""
        ticket = await _lifecycle_ticket(
            ticket_factory,
            product_factory,
            ticket_package_factory,
            ticket_package_track_factory,
            ticket_package_product_factory,
        )
        after_midnight = _MIDNIGHT + timedelta(seconds=1)
        clock.queue = [after_midnight]

        detail = await assemble_ticket_detail(
            db_session, ticket_id=ticket.id, evaluation_date=_DAY
        )

        assert clock.calls == [after_midnight]
        track = detail.packages[0].tracks[0]
        assert track.products[0].lifecycle_phase is LifecyclePhase.GENERAL_SUPPORT
        assert track.actionable is True
        assert detail.due_dates is not None
        assert detail.due_dates.triage == _MIDNIGHT
        assert track.milestones.triage is MilestoneStatus.OVERDUE

    def test_consumer_mode_accepts_no_evaluation_date(self) -> None:
        """A read-only request derives its date from its own instant; only
        mutation assembly receives a workflow date."""
        assert list(inspect.signature(get_ticket_detail).parameters) == [
            "db",
            "ticket_id",
            "caller",
        ]
        assert list(inspect.signature(assemble_ticket_detail).parameters) == [
            "db",
            "ticket_id",
            "evaluation_date",
        ]


# ---------------------------------------------------------------------------
# Mutation-assembly mode
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestMutationAssembly:
    async def test_assembles_a_confidential_ticket_without_a_caller(
        self, db_session: AsyncSession, clock: Clock, ticket_factory: Factory
    ) -> None:
        ticket: Ticket = await ticket_factory(
            is_confidential=True, created_at=CREATED_AT, updated_at=UPDATED_AT
        )

        detail = await assemble_ticket_detail(
            db_session, ticket_id=ticket.id, evaluation_date=BEFORE_ANY_DUE.date()
        )

        assert detail.ticket_id == _sntl(ticket)
        assert detail.is_confidential is True
        assert detail == await _detail(db_session, ticket)

    async def test_observes_the_caller_sessions_uncommitted_post_state(
        self,
        db_session: AsyncSession,
        clock: Clock,
        ticket_factory: Factory,
        user_factory: Factory,
    ) -> None:
        ticket: Ticket = await ticket_factory()
        assignee = await user_factory()
        ticket.priority_override = TicketPriority.P1.value
        ticket.assignee_id = assignee.id
        await db_session.flush()
        db_session.add(TicketPackage(ticket_id=ticket.id, package_name="example-new"))
        await db_session.flush()

        detail = await assemble_ticket_detail(
            db_session, ticket_id=ticket.id, evaluation_date=BEFORE_ANY_DUE.date()
        )

        assert detail.priority is TicketPriority.P1
        assert detail.assignee is not None
        assert detail.assignee.id == assignee.id
        assert [p.package_name for p in detail.packages] == ["example-new"]

    async def test_missing_uuid_is_an_invariant_violation(
        self, db_session: AsyncSession, clock: Clock
    ) -> None:
        with pytest.raises(NoResultFound):
            await assemble_ticket_detail(
                db_session, ticket_id=uuid.uuid4(), evaluation_date=date(2026, 3, 11)
            )


# ---------------------------------------------------------------------------
# Bounded database work
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestBoundedQueries:
    async def _ticket(
        self,
        factories: dict[str, Factory],
        *,
        cwes: int,
        sources: int,
        identifiers: int,
        packages: int,
        tracks: int,
        products: int,
    ) -> Ticket:
        cve = await factories["cve"](severity=Severity.HIGH.value)
        target: Ticket = await factories["ticket"]()
        assignee = await factories["user"]()
        ticket: Ticket = await factories["ticket"](
            cve_id=cve.id, duplicate_of_id=target.id, assignee_id=assignee.id
        )
        await factories["kev"](cve_id=cve.id)
        await factories["epss"](cve_id=cve.id)
        await factories["ssvc"](cve_id=cve.id)
        for c in range(cwes):
            for s in range(sources):
                await factories["cwe"](
                    cve_id=cve.id, cwe_id=f"CWE-{c + 1}", source=f"Source-{s}"
                )
        for i in range(identifiers):
            await factories["identifier"](
                cve_id=cve.id, identifier=f"GHSA-bound-{uuid.uuid4().hex[:8]}-{i}"
            )
        for p in range(packages):
            package = await factories["package"](
                ticket_id=ticket.id, package_name=f"pkg-{p}"
            )
            for _ in range(tracks):
                track = await factories["track"](ticket_package_id=package.id)
                for _ in range(products):
                    await factories["product"](ticket_package_track_id=track.id)
        return ticket

    async def test_query_count_is_independent_of_detail_cardinality(
        self,
        db_session: AsyncSession,
        clock: Clock,
        ticket_factory: Factory,
        user_factory: Factory,
        cve_factory: Factory,
        cve_kev_entry_factory: Factory,
        cve_epss_score_factory: Factory,
        cve_ssvc_assessment_factory: Factory,
        cve_cwe_factory: Factory,
        cve_external_identifier_factory: Factory,
        ticket_package_factory: Factory,
        ticket_package_track_factory: Factory,
        ticket_package_product_factory: Factory,
    ) -> None:
        factories = {
            "ticket": ticket_factory,
            "user": user_factory,
            "cve": cve_factory,
            "kev": cve_kev_entry_factory,
            "epss": cve_epss_score_factory,
            "ssvc": cve_ssvc_assessment_factory,
            "cwe": cve_cwe_factory,
            "identifier": cve_external_identifier_factory,
            "package": ticket_package_factory,
            "track": ticket_package_track_factory,
            "product": ticket_package_product_factory,
        }
        small = await self._ticket(
            factories,
            cwes=1,
            sources=1,
            identifiers=1,
            packages=1,
            tracks=1,
            products=1,
        )
        large = await self._ticket(
            factories,
            cwes=4,
            sources=3,
            identifiers=5,
            packages=3,
            tracks=2,
            products=2,
        )
        evaluation_date = BEFORE_ANY_DUE.date()

        counts: list[int] = []
        details: list[TicketDetailProjection] = []
        for ticket in (small, large):
            with _StatementRecorder(db_session) as consumer:
                details.append(await _detail(db_session, ticket))
            with _StatementRecorder(db_session) as assembly:
                details.append(
                    await assemble_ticket_detail(
                        db_session, ticket_id=ticket.id, evaluation_date=evaluation_date
                    )
                )
            counts += [len(consumer.statements), len(assembly.statements)]

        assert counts == [1, 1, 1, 1]
        large_detail = details[2]
        assert large_detail == details[3]
        assert large_detail.cve is not None
        assert [len(cwe.sources) for cwe in large_detail.cve.cwes] == [3, 3, 3, 3]
        assert len(large_detail.cve.external_identifiers) == 5
        assert (
            sum(len(t.products) for p in large_detail.packages for t in p.tracks) == 12
        )


# ---------------------------------------------------------------------------
# The read writes nothing
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestDetailReadIsSideEffectFree:
    async def test_read_writes_no_row_and_creates_no_event(
        self,
        db_session: AsyncSession,
        clock: Clock,
        ticket_factory: Factory,
        user_factory: Factory,
        cve_factory: Factory,
        ticket_package_factory: Factory,
        ticket_package_track_factory: Factory,
    ) -> None:
        cve = await cve_factory(severity=Severity.HIGH.value)
        assignee = await user_factory()
        ticket: Ticket = await ticket_factory(
            cve_id=cve.id, assignee_id=assignee.id, created_at=CREATED_AT
        )
        package = await ticket_package_factory(ticket_id=ticket.id)
        await ticket_package_track_factory(ticket_package_id=package.id)
        snapshot = (
            select(
                Ticket.status,
                Ticket.updated_at,
                Ticket.priority_auto,
                Ticket.assignee_id,
                CVE.updated_at,
            )
            .join(CVE, CVE.id == Ticket.cve_id)
            .where(Ticket.id == ticket.id)
        )
        before = (await db_session.execute(snapshot)).one()

        with _StatementRecorder(db_session) as recorder:
            await _detail(db_session, ticket)
            await assemble_ticket_detail(
                db_session, ticket_id=ticket.id, evaluation_date=BEFORE_ANY_DUE.date()
            )

        after = (await db_session.execute(snapshot)).one()
        events = await db_session.scalar(
            select(func.count()).select_from(TicketAuditEvent)
        )
        assert after == before
        assert events == 0
        assert not db_session.new
        assert not db_session.dirty
        assert all(s.lstrip().upper().startswith("SELECT") for s in recorder.statements)


# ---------------------------------------------------------------------------
# Independent-session races and self-loss (one coherent observation)
# ---------------------------------------------------------------------------


class _CommittedWorld:
    """Commits fixture rows through an independent session and deletes them
    at teardown in FK-safe order (testing-strategy.md, Concurrency Testing:
    committed data is not rolled back by the fixture)."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.ticket_ids: list[uuid.UUID] = []
        self.cve_ids: list[uuid.UUID] = []
        self.user_ids: list[uuid.UUID] = []
        self.product_ids: list[uuid.UUID] = []

    async def user(self, *, role: Role | None = None) -> User:
        user = User(
            username=f"fictional.detail.{uuid.uuid4().hex[:10]}",
            email=f"detail.{uuid.uuid4().hex[:10]}@example.com",
            password_hash="$2b$12$" + "a" * 53,
        )
        self.session.add(user)
        await self.session.flush()
        self.user_ids.append(user.id)
        if role is not None:
            self.session.add(UserRole(user_id=user.id, role=role.value))
        await self.session.commit()
        return user

    async def ticket(
        self,
        *,
        is_confidential: bool,
        maintainer: User | None = None,
        assignee: User | None = None,
        cve_severity: Severity | None = None,
    ) -> tuple[Ticket, TicketPackage, TicketPackageTrack, CVE]:
        cve = CVE(
            cve_id=f"CVE-2099-{uuid.uuid4().int % 10**7:07d}",
            severity=cve_severity.value if cve_severity else None,
        )
        self.session.add(cve)
        await self.session.flush()
        self.cve_ids.append(cve.id)
        ticket = Ticket(
            is_confidential=is_confidential,
            cve_id=cve.id,
            assignee_id=assignee.id if assignee else None,
        )
        self.session.add(ticket)
        await self.session.flush()
        self.ticket_ids.append(ticket.id)
        package = TicketPackage(ticket_id=ticket.id, package_name="fictional-race")
        self.session.add(package)
        await self.session.flush()
        if maintainer is not None:
            self.session.add(
                TicketPackageMaintainer(
                    ticket_package_id=package.id, user_id=maintainer.id
                )
            )
        track = TicketPackageTrack(
            ticket_package_id=package.id,
            workflow_type=WorkflowType.IBS.value,
            reference="Example:Codestream:Race:Update",
        )
        self.session.add(track)
        await self.session.flush()
        product = Product(
            name="Race Product",
            version="1",
            display_name="Race Product 1",
            cpe=f"cpe:/o:example:race:{uuid.uuid4().hex}",
            catalog_last_seen_at=datetime.now(UTC),
        )
        self.session.add(product)
        await self.session.flush()
        self.product_ids.append(product.id)
        self.session.add(
            TicketPackageProduct(
                ticket_package_track_id=track.id, product_id=product.id
            )
        )
        await self.session.commit()
        return ticket, package, track, cve

    async def grant(self, ticket: Ticket, user: User, granter: User) -> None:
        self.session.add(
            TicketAccessGrant(
                ticket_id=ticket.id, user_id=user.id, granted_by_id=granter.id
            )
        )
        await self.session.commit()

    async def cleanup(self) -> None:
        await self.session.rollback()
        packages = select(TicketPackage.id).where(
            TicketPackage.ticket_id.in_(self.ticket_ids)
        )
        tracks = select(TicketPackageTrack.id).where(
            TicketPackageTrack.ticket_package_id.in_(packages)
        )
        for statement in (
            delete(TicketPackageProduct).where(
                TicketPackageProduct.ticket_package_track_id.in_(tracks)
            ),
            delete(TicketPackageTrack).where(
                TicketPackageTrack.ticket_package_id.in_(packages)
            ),
            delete(TicketPackageMaintainer).where(
                TicketPackageMaintainer.ticket_package_id.in_(packages)
            ),
            delete(TicketPackage).where(TicketPackage.ticket_id.in_(self.ticket_ids)),
            delete(TicketAccessGrant).where(
                TicketAccessGrant.ticket_id.in_(self.ticket_ids)
            ),
            delete(Ticket).where(Ticket.id.in_(self.ticket_ids)),
            delete(CVE).where(CVE.id.in_(self.cve_ids)),
            delete(Product).where(Product.id.in_(self.product_ids)),
            delete(UserRole).where(UserRole.user_id.in_(self.user_ids)),
            delete(User).where(User.id.in_(self.user_ids)),
        ):
            await self.session.execute(statement)
        await self.session.commit()


@pytest.fixture
async def committed_world(
    db_session_factory: Callable[[], Awaitable[AsyncSession]],
) -> AsyncIterator[_CommittedWorld]:
    world = _CommittedWorld(await db_session_factory())
    try:
        yield world
    finally:
        await world.cleanup()


async def _commit(session: AsyncSession, *statements: Any) -> None:
    for statement in statements:
        await session.execute(statement)
    await session.commit()


@pytest.mark.integration
class TestDetailReadRaces:
    """Session R performs a preliminary SNTL resolution or a first detail
    read, session W then commits a change, and R reads again. The steps run
    in a fixed order on independent connections, so the interleaving is
    deterministic. The detail is one statement, so R observes either the
    complete post-change detail or `TicketNotFoundError`, never a detail
    assembled from a stale access decision or from mixed views."""

    async def test_confidentiality_set_after_preliminary_resolution(
        self,
        committed_world: _CommittedWorld,
        db_session_factory: Callable[[], Awaitable[AsyncSession]],
    ) -> None:
        user = await committed_world.user()
        ticket, _, _, _ = await committed_world.ticket(is_confidential=False)
        reader = await db_session_factory()
        writer = await db_session_factory()
        caller = TicketCaller.authenticated(user.id, Scope.NON_CONFIDENTIAL)

        await resolve_ticket_locator(reader, _sntl(ticket), caller)
        await _commit(
            writer,
            update(Ticket).where(Ticket.id == ticket.id).values(is_confidential=True),
        )

        with pytest.raises(TicketNotFoundError):
            await _detail(reader, ticket, caller)

    async def test_grant_revoked_after_preliminary_resolution(
        self,
        committed_world: _CommittedWorld,
        db_session_factory: Callable[[], Awaitable[AsyncSession]],
    ) -> None:
        user = await committed_world.user()
        granter = await committed_world.user()
        ticket, _, _, _ = await committed_world.ticket(is_confidential=True)
        await committed_world.grant(ticket, user, granter)
        reader = await db_session_factory()
        writer = await db_session_factory()
        caller = TicketCaller.authenticated(user.id, Scope.NON_CONFIDENTIAL)

        await resolve_ticket_locator(reader, _sntl(ticket), caller)
        await _commit(
            writer,
            delete(TicketAccessGrant).where(TicketAccessGrant.ticket_id == ticket.id),
        )

        with pytest.raises(TicketNotFoundError):
            await _detail(reader, ticket, caller)

    async def test_last_maintained_package_excluded_together_with_tree_change(
        self,
        committed_world: _CommittedWorld,
        db_session_factory: Callable[[], Awaitable[AsyncSession]],
    ) -> None:
        user = await committed_world.user()
        ticket, package, track, _ = await committed_world.ticket(
            is_confidential=True, maintainer=user
        )
        reader = await db_session_factory()
        writer = await db_session_factory()
        caller = TicketCaller.authenticated(user.id, Scope.NON_CONFIDENTIAL)

        before = await _detail(reader, ticket, caller)
        assert before.packages[0].deleted_at is None
        await _commit(
            writer,
            update(TicketPackage)
            .where(TicketPackage.id == package.id)
            .values(deleted_at=datetime.now(UTC)),
            update(TicketPackageTrack)
            .where(TicketPackageTrack.id == track.id)
            .values(status=PackageStatus.NOT_AFFECTED.value),
        )

        with pytest.raises(TicketNotFoundError):
            await _detail(reader, ticket, caller)

    async def test_visibility_acquired_with_detail_changes_is_observed_whole(
        self,
        committed_world: _CommittedWorld,
        db_session_factory: Callable[[], Awaitable[AsyncSession]],
    ) -> None:
        user = await committed_world.user()
        granter = await committed_world.user()
        ticket, _, track, cve = await committed_world.ticket(is_confidential=True)
        reader = await db_session_factory()
        writer = await db_session_factory()
        caller = TicketCaller.authenticated(user.id, Scope.NON_CONFIDENTIAL)

        with pytest.raises(TicketNotFoundError):
            await _detail(reader, ticket, caller)
        writer.add(
            TicketAccessGrant(
                ticket_id=ticket.id, user_id=user.id, granted_by_id=granter.id
            )
        )
        writer.add(CVEKEVEntry(cve_id=cve.id, date_added=date(2026, 3, 9)))
        await _commit(
            writer,
            update(Ticket)
            .where(Ticket.id == ticket.id)
            .values(priority_override=TicketPriority.P1.value),
            update(TicketPackageTrack)
            .where(TicketPackageTrack.id == track.id)
            .values(delivery_status=DeliveryStatus.IN_PROGRESS.value),
        )

        after = await _detail(reader, ticket, caller)
        assert after.priority is TicketPriority.P1
        assert after.cve is not None
        assert after.cve.kev == CVEKEVProjection(
            date_added=date(2026, 3, 9), reference_url=None
        )
        assert after.packages[0].tracks[0].delivery_status is DeliveryStatus.IN_PROGRESS

    async def test_committed_detail_changes_are_observed_entirely(
        self,
        committed_world: _CommittedWorld,
        db_session_factory: Callable[[], Awaitable[AsyncSession]],
    ) -> None:
        """Root, CVE, CVE evidence, assignee, and tree changes committed
        together between two reads are observed all at once."""
        first = await committed_world.user()
        second = await committed_world.user()
        ticket, _, track, cve = await committed_world.ticket(
            is_confidential=False, assignee=first, cve_severity=Severity.LOW
        )
        reader = await db_session_factory()
        writer = await db_session_factory()

        before = await _detail(reader, ticket, ANONYMOUS_CALLER)
        writer.add(
            CVEEPSSScore(
                cve_id=cve.id, score=0.5, percentile=0.96, assessed_at=date(2026, 3, 9)
            )
        )
        await _commit(
            writer,
            update(CVE)
            .where(CVE.id == cve.id)
            .values(severity=Severity.CRITICAL.value),
            update(Ticket).where(Ticket.id == ticket.id).values(assignee_id=second.id),
            update(TicketPackageTrack)
            .where(TicketPackageTrack.id == track.id)
            .values(status=PackageStatus.AFFECTED.value),
        )
        after = await _detail(reader, ticket, ANONYMOUS_CALLER)

        assert before.cve is not None
        assert after.cve is not None
        assert (
            before.severity,
            before.cve.epss,
            before.assignee.id if before.assignee else None,
            before.packages[0].tracks[0].status,
        ) == (Severity.LOW, None, first.id, PackageStatus.ANALYSIS)
        assert (
            after.severity,
            after.cve.severity,
            after.cve.epss is not None,
            after.assignee.id if after.assignee else None,
            after.packages[0].tracks[0].status,
        ) == (
            Severity.CRITICAL,
            Severity.CRITICAL,
            True,
            second.id,
            PackageStatus.AFFECTED,
        )
        assert after.due_dates is not None
        assert before.due_dates is not None
        assert after.due_dates.release - after.due_dates.triage == timedelta(days=27)
        assert before.due_dates.release - before.due_dates.triage == timedelta(days=162)

    async def test_role_removed_after_caller_resolution_does_not_change_the_read(
        self,
        committed_world: _CommittedWorld,
        db_session_factory: Callable[[], Awaitable[AsyncSession]],
    ) -> None:
        """The service consumes the request-resolved caller and never reloads
        roles: a committed role removal applies only to the next caller
        resolution."""
        user = await committed_world.user(role=Role.VULNERABILITY_ANALYST)
        ticket, _, _, _ = await committed_world.ticket(is_confidential=True)
        reader = await db_session_factory()
        writer = await db_session_factory()
        in_flight = TicketCaller.authenticated(user.id, Scope.ALL)

        await _commit(writer, delete(UserRole).where(UserRole.user_id == user.id))

        assert (await _detail(reader, ticket, in_flight)).ticket_id == _sntl(ticket)
        with pytest.raises(TicketNotFoundError):
            await _detail(
                reader,
                ticket,
                TicketCaller.authenticated(user.id, Scope.NON_CONFIDENTIAL),
            )

    async def test_mutation_that_removes_final_visibility_still_assembles(
        self,
        committed_world: _CommittedWorld,
        db_session_factory: Callable[[], Awaitable[AsyncSession]],
    ) -> None:
        """Self-loss (ticket-service.md, Caller category and Ticket
        accessibility): a restricted maintainer excludes the last package
        through which it sees the Ticket. Assembly inside that transaction
        returns the post-mutation detail with no second visibility
        decision, while the next request is denied."""
        user = await committed_world.user(role=Role.RESTRICTED_ANALYST)
        ticket, package, _, _ = await committed_world.ticket(
            is_confidential=True, maintainer=user
        )
        caller = TicketCaller.authenticated(user.id, Scope.NON_CONFIDENTIAL)
        mutation = await db_session_factory()
        excluded_at = datetime(2026, 3, 12, 9, 30, tzinfo=UTC)

        await mutation.execute(
            update(TicketPackage)
            .where(TicketPackage.id == package.id)
            .values(deleted_at=excluded_at)
        )
        detail = await assemble_ticket_detail(
            mutation, ticket_id=ticket.id, evaluation_date=date(2026, 3, 12)
        )
        with pytest.raises(TicketNotFoundError):
            await _detail(mutation, ticket, caller)
        await mutation.commit()

        assert detail.ticket_id == _sntl(ticket)
        assert detail.packages[0].deleted_at == excluded_at
        next_request = await db_session_factory()
        with pytest.raises(TicketNotFoundError):
            await _detail(next_request, ticket, caller)


# ---------------------------------------------------------------------------
# Module boundary
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestTicketServiceQueryBoundary:
    def test_query_operations_are_the_only_coroutines(self) -> None:
        coroutines = {
            name
            for name, member in inspect.getmembers(ticket_service, inspect.isfunction)
            if member.__module__ == ticket_service.__name__
            and inspect.iscoroutinefunction(member)
        }

        assert coroutines == {
            "resolve_ticket_locator",
            "get_ticket_detail",
            "assemble_ticket_detail",
        }

    def test_projection_exposes_no_internal_ticket_uuid(self) -> None:
        fields = set(TicketDetailProjection.__dataclass_fields__)

        assert "ticket_id" in fields
        assert (
            not {"id", "identifier", "ticket_sequence_id", "duplicate_of_id"} & fields
        )
