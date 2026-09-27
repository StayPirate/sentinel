"""Tests for the Ticket list read (`ticket_service.list_tickets()`).

Owning specifications:

- docs/features/tickets/ticket-service.md (Ticket Query Operations >
  `list_tickets()`): one evaluation instant, one visible candidate set,
  search normalization, filters with supplied-versus-omitted state,
  one resolved severity and effective priority per Ticket, fan-out
  collapse, `package_names`, sorting with the `Ticket.id` tie-breaker,
  `total` before slicing, and one coherent PostgreSQL observation.
- docs/features/tickets/tickets.md (Ticket Identification > Search;
  Severity Resolution; Response Schemas > TicketSummary; List Tickets).
- docs/features/tickets/ticket-priority.md (Testing Requirement 9).
- docs/features/tickets/ticket-deadlines.md (Evaluation Instant,
  Ticket-Level Overdue Filter, Sorting; Testing Requirements 7-9, 11).
- docs/api-spec.md (Semantic Sort Fields, Nullable Sort Field Ordering,
  Deterministic Pagination Ordering, User Identifier Resolution).
- docs/features/platform/testing-strategy.md (Ticket Accessibility >
  list and count reads; Ticket identifier and read-contract coverage).

Expected values are transcribed from the specifications or from the
shared deadline matrix, never computed by the module under test. Every
test starts from an empty Ticket table (per-test transaction rollback),
so a list observes exactly the Tickets the test creates.
"""

from __future__ import annotations

import dataclasses
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable, Sequence
from datetime import UTC, date, datetime, timedelta, timezone
from typing import Any
from unittest.mock import AsyncMock

import pytest
from sqlalchemy import delete, event, func, select, update
from sqlalchemy.exc import OperationalError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import (
    DeliveryStatus,
    MilestonePhase,
    PackageStatus,
    Role,
    Scope,
    Severity,
    SortOrder,
    TicketPriority,
    TicketSortField,
    TicketStatus,
    WorkflowType,
)
from app.core.identifiers import format_ticket_id
from app.models.cve import CVE
from app.models.ticket import Ticket
from app.models.ticket_access_grant import TicketAccessGrant
from app.models.ticket_audit_event import TicketAuditEvent
from app.models.ticket_package import TicketPackage
from app.models.ticket_package_maintainer import TicketPackageMaintainer
from app.models.ticket_package_product import TicketPackageProduct
from app.models.ticket_package_track import TicketPackageTrack
from app.models.user import User
from app.models.user_role import UserRole
from app.services import ticket_service
from app.services.ticket_deadlines import DueDates
from app.services.ticket_service import (
    CVESummaryProjection,
    TicketPage,
    TicketSummaryProjection,
    TicketUserProjection,
    list_tickets,
)
from app.services.ticket_visibility import ANONYMOUS_CALLER, TicketCaller
from tests.support.deadline_matrix import (
    AFTER_ALL_DUE,
    AFTER_TRIAGE_DUE,
    AT_TRIAGE_DUE,
    BEFORE_ANY_DUE,
    CREATED_AT,
    DEADLINE_CASES,
    DeadlineCase,
    O,
    ProductEvidence,
)
from tests.support.deadline_persistence import DeadlineWorld

Factory = Callable[..., Awaitable[Any]]

ALL_SCOPE = TicketCaller.authenticated(uuid.uuid4(), Scope.ALL)
UPDATED_AT = datetime(2026, 3, 10, 18, 5, tzinfo=UTC)
CRD = datetime(2026, 4, 1, 12, 0, tzinfo=UTC)
EXCLUDED_AT = datetime(2026, 3, 11, 9, 0, tzinfo=UTC)
LATER_PHASE_INDEX = {
    MilestonePhase.SUBMISSION: 1,
    MilestonePhase.UM: 2,
    MilestonePhase.QA: 3,
}


class Clock:
    """Controlled `ticket_service._utc_now()` recording every capture."""

    def __init__(self) -> None:
        self.instant = BEFORE_ANY_DUE
        self.calls: list[datetime] = []

    def now(self) -> datetime:
        self.calls.append(self.instant)
        return self.instant


@pytest.fixture
def clock(monkeypatch: pytest.MonkeyPatch) -> Clock:
    controlled = Clock()
    monkeypatch.setattr(ticket_service, "_utc_now", controlled.now)
    return controlled


@pytest.fixture
def deadline_world(request: pytest.FixtureRequest) -> DeadlineWorld:
    return DeadlineWorld.from_request(request)


class _StatementRecorder:
    """Records every SQL statement executed through the session's engine."""

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


async def _list(
    db: AsyncSession, caller: TicketCaller = ALL_SCOPE, **filters: Any
) -> TicketPage:
    return await list_tickets(db, caller=caller, **filters)


async def _ids(
    db: AsyncSession, caller: TicketCaller = ALL_SCOPE, **filters: Any
) -> list[str]:
    page = await _list(db, caller, per_page=100, **filters)
    assert page.total == len(page.items)
    return [item.ticket_id for item in page.items]


def _sntl(ticket: Ticket) -> str:
    return format_ticket_id(ticket.sequence_id)


def _set(tickets: Sequence[Ticket]) -> set[str]:
    return {_sntl(ticket) for ticket in tickets}


# ---------------------------------------------------------------------------
# Projection
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestSummaryProjection:
    async def test_cve_ticket_projects_every_summary_field(
        self,
        db_session: AsyncSession,
        clock: Clock,
        ticket_factory: Factory,
        cve_factory: Factory,
        user_factory: Factory,
        ticket_package_factory: Factory,
    ) -> None:
        assignee: User = await user_factory(
            username="fictional.analyst", full_name=None, active=False
        )
        target: Ticket = await ticket_factory()
        cve: CVE = await cve_factory(
            cve_id="CVE-2099-40001",
            title="Fictional title",
            description="Fictional description",
            severity=Severity.MEDIUM.value,
        )
        ticket: Ticket = await ticket_factory(
            cve_id=cve.id,
            assignee_id=assignee.id,
            duplicate_of_id=target.id,
            is_confidential=True,
            coordinated_release_at=CRD,
            priority_auto=TicketPriority.P3.value,
            priority_override=TicketPriority.P1.value,
            created_at=CREATED_AT,
            updated_at=UPDATED_AT,
        )
        for name in ("openssl-3", "curl"):
            await ticket_package_factory(ticket_id=ticket.id, package_name=name)

        page = await _list(db_session, search=_sntl(ticket))

        assert page.total == 1
        assert page.items == (
            TicketSummaryProjection(
                ticket_id=_sntl(ticket),
                status=TicketStatus.DUPLICATED,
                severity=Severity.MEDIUM,
                priority=TicketPriority.P1,
                assignee=TicketUserProjection(
                    id=assignee.id,
                    username="fictional.analyst",
                    full_name=None,
                    active=False,
                ),
                cve=CVESummaryProjection(
                    cve_id="CVE-2099-40001",
                    title="Fictional title",
                    description="Fictional description",
                ),
                duplicate_of_ticket_id=_sntl(target),
                is_confidential=True,
                coordinated_release_at=CRD,
                due_dates=None,
                package_names=("curl", "openssl-3"),
                created_at=CREATED_AT,
                updated_at=UPDATED_AT,
            ),
        )

    async def test_cve_less_ticket_uses_manual_severity_and_the_90_day_tier(
        self, db_session: AsyncSession, clock: Clock, ticket_factory: Factory
    ) -> None:
        ticket: Ticket = await ticket_factory(
            severity_manual=Severity.MEDIUM.value,
            priority_auto=TicketPriority.P3.value,
            created_at=CREATED_AT,
        )

        (item,) = (await _list(db_session)).items

        assert item.ticket_id == _sntl(ticket)
        assert item.severity is Severity.MEDIUM
        assert item.priority is TicketPriority.P3
        assert item.cve is None
        assert item.assignee is None
        assert item.duplicate_of_ticket_id is None
        assert item.package_names == ()
        # ticket-deadlines.md (Formula): 90-day tier offsets 9/54/63/90/90.
        assert item.due_dates == DueDates(
            triage=CREATED_AT + timedelta(days=9),
            submission=CREATED_AT + timedelta(days=54),
            um=CREATED_AT + timedelta(days=63),
            qa=CREATED_AT + timedelta(days=90),
            release=CREATED_AT + timedelta(days=90),
        )

    @pytest.mark.parametrize(
        ("severity", "status"),
        [
            (Severity.NONE, TicketStatus.ANALYSIS),
            (Severity.HIGH, TicketStatus.IGNORED),
        ],
    )
    async def test_no_sla_yields_no_due_dates(
        self,
        db_session: AsyncSession,
        clock: Clock,
        ticket_factory: Factory,
        severity: Severity,
        status: TicketStatus,
    ) -> None:
        await ticket_factory(severity_manual=severity.value, status=status.value)

        (item,) = (await _list(db_session)).items

        assert item.due_dates is None

    async def test_unresolved_severity_uses_the_30_day_tier(
        self, db_session: AsyncSession, clock: Clock, ticket_factory: Factory
    ) -> None:
        await ticket_factory(created_at=CREATED_AT)

        (item,) = (await _list(db_session)).items

        assert item.severity is None
        assert item.priority is None
        assert item.due_dates is not None
        assert item.due_dates.triage == CREATED_AT + timedelta(days=3)
        assert item.due_dates.release == CREATED_AT + timedelta(days=30)

    async def test_package_names_are_included_only_in_code_point_order(
        self,
        db_session: AsyncSession,
        clock: Clock,
        ticket_factory: Factory,
        ticket_package_factory: Factory,
        ticket_package_track_factory: Factory,
        ticket_package_product_factory: Factory,
        product_factory: Factory,
    ) -> None:
        """Excluded packages are absent; a package whose only Product is
        EOL stays listed; order is by Unicode code point, not collation."""
        ticket: Ticket = await ticket_factory()
        names = ["éclair", "curl", "Zlib", "openssl-3", "_private", "a"]
        for name in names:
            await ticket_package_factory(ticket_id=ticket.id, package_name=name)
        await ticket_package_factory(
            ticket_id=ticket.id, package_name="excluded", deleted_at=EXCLUDED_AT
        )
        eol_package = await ticket_package_factory(
            ticket_id=ticket.id, package_name="eol-only"
        )
        track = await ticket_package_track_factory(ticket_package_id=eol_package.id)
        eol = await product_factory(general_support_end_date=date(2020, 1, 1))
        await ticket_package_product_factory(
            ticket_package_track_id=track.id, product_id=eol.id
        )

        (item,) = (await _list(db_session)).items

        assert item.package_names == (
            "Zlib",
            "_private",
            "a",
            "curl",
            "eol-only",
            "openssl-3",
            "éclair",
        )


@pytest.mark.unit
class TestSummaryProjectionShape:
    def test_projection_exposes_no_internal_ticket_uuid(self) -> None:
        fields = set(TicketSummaryProjection.__dataclass_fields__)

        assert "ticket_id" in fields
        assert (
            not {"id", "identifier", "ticket_sequence_id", "duplicate_of_id"} & fields
        )


# ---------------------------------------------------------------------------
# Search
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestSearch:
    async def test_numeric_term_prefix_matches_the_sequence_number(
        self, db_session: AsyncSession, clock: Clock, ticket_factory: Factory
    ) -> None:
        t42 = await ticket_factory(sequence_id=42)
        t420 = await ticket_factory(sequence_id=420)
        await ticket_factory(sequence_id=1042)
        await ticket_factory(sequence_id=7)

        for term in ("42", "SNTL-42", "sntl-42", "Sntl-42", "  42  "):
            assert set(await _ids(db_session, search=term)) == _set([t42, t420]), term
        assert await _ids(db_session, search="420") == [_sntl(t420)]

    async def test_bare_or_non_numeric_sntl_prefix_is_ignored_for_the_identifier(
        self,
        db_session: AsyncSession,
        clock: Clock,
        ticket_factory: Factory,
        ticket_package_factory: Factory,
    ) -> None:
        """`SNTL-` alone matches no sequence number; other fields still
        apply to the whole term (here a package-name substring)."""
        await ticket_factory(sequence_id=42)
        named = await ticket_factory(sequence_id=43)
        await ticket_package_factory(ticket_id=named.id, package_name="my-sntl-tool")

        assert await _ids(db_session, search="SNTL-") == [_sntl(named)]
        assert await _ids(db_session, search="SNTL-4a") == []
        assert await _ids(db_session, search="SNTL-SNTL-42") == []
        assert await _ids(db_session, search="4x") == []

    async def test_cve_id_prefix_is_case_insensitive_with_optional_prefix(
        self,
        db_session: AsyncSession,
        clock: Clock,
        ticket_factory: Factory,
        cve_factory: Factory,
    ) -> None:
        tickets: dict[str, Ticket] = {}
        for sequence, cve_id in (
            (901, "CVE-2024-1234"),
            (902, "CVE-2024-1200"),
            (903, "CVE-2025-1234"),
        ):
            cve = await cve_factory(cve_id=cve_id)
            tickets[cve_id] = await ticket_factory(sequence_id=sequence, cve_id=cve.id)
        both = _set([tickets["CVE-2024-1234"], tickets["CVE-2024-1200"]])

        assert set(await _ids(db_session, search="CVE-2024-12")) == both
        assert set(await _ids(db_session, search="cve-2024-12")) == both
        assert set(await _ids(db_session, search="2024-12")) == both
        assert await _ids(db_session, search="2024-1234") == [
            _sntl(tickets["CVE-2024-1234"])
        ]
        assert len(await _ids(db_session, search="CVE-")) == 3
        # `2024` is not year-number (no hyphen and number) and no stored
        # CVE-ID starts with it.
        assert await _ids(db_session, search="2024") == []
        assert await _ids(db_session, search="2024-") == []
        assert await _ids(db_session, search="24-1234") == []

    async def test_package_name_substring_is_case_insensitive_and_included_only(
        self,
        db_session: AsyncSession,
        clock: Clock,
        ticket_factory: Factory,
        ticket_package_factory: Factory,
    ) -> None:
        included = await ticket_factory(sequence_id=801)
        await ticket_package_factory(ticket_id=included.id, package_name="openssl-3")
        excluded = await ticket_factory(sequence_id=802)
        await ticket_package_factory(
            ticket_id=excluded.id, package_name="libopenssl", deleted_at=EXCLUDED_AT
        )

        assert await _ids(db_session, search="SSL") == [_sntl(included)]
        assert await _ids(db_session, search="penss") == [_sntl(included)]

    async def test_external_identifier_prefix_is_case_insensitive(
        self,
        db_session: AsyncSession,
        clock: Clock,
        ticket_factory: Factory,
        cve_factory: Factory,
        cve_external_identifier_factory: Factory,
    ) -> None:
        cve = await cve_factory()
        ticket = await ticket_factory(sequence_id=701, cve_id=cve.id)
        await cve_external_identifier_factory(
            cve_id=cve.id, identifier="GHSA-abcd-efgh-ijkl"
        )
        orphan = await cve_factory()
        await cve_external_identifier_factory(
            cve_id=orphan.id, identifier="GHSA-zzzz-efgh-ijkl"
        )

        assert await _ids(db_session, search="ghsa-abcd") == [_sntl(ticket)]
        assert await _ids(db_session, search="GHSA-ABCD-EFGH-IJKL") == [_sntl(ticket)]
        # Prefix only: an inner fragment does not match.
        assert await _ids(db_session, search="efgh") == []

    async def test_wildcard_characters_are_literal(
        self,
        db_session: AsyncSession,
        clock: Clock,
        ticket_factory: Factory,
        ticket_package_factory: Factory,
        cve_factory: Factory,
        cve_external_identifier_factory: Factory,
    ) -> None:
        by_name: dict[str, Ticket] = {}
        for index, name in enumerate(
            ("lib_foo", "libxfoo", "a%b", "axb", "back\\slash", "backxslash")
        ):
            ticket = await ticket_factory(sequence_id=600 + index)
            await ticket_package_factory(ticket_id=ticket.id, package_name=name)
            by_name[name] = ticket
        cve = await cve_factory(cve_id="CVE-2099-1234")
        await ticket_factory(sequence_id=610, cve_id=cve.id)
        await cve_external_identifier_factory(cve_id=cve.id, identifier="GHSA-1234")

        assert await _ids(db_session, search="lib_") == [_sntl(by_name["lib_foo"])]
        assert await _ids(db_session, search="a%b") == [_sntl(by_name["a%b"])]
        assert await _ids(db_session, search="k\\s") == [_sntl(by_name["back\\slash"])]
        assert await _ids(db_session, search="%") == [_sntl(by_name["a%b"])]
        assert await _ids(db_session, search="CVE-2099-1_3") == []
        assert await _ids(db_session, search="GHSA-%") == []

    @pytest.mark.parametrize("term", ["", " ", "   \t\n "])
    async def test_empty_or_whitespace_only_search_applies_no_filter(
        self, db_session: AsyncSession, clock: Clock, ticket_factory: Factory, term: str
    ) -> None:
        tickets = [await ticket_factory() for _ in range(3)]

        assert set(await _ids(db_session, search=term)) == _set(tickets)

    async def test_fields_combine_with_or_and_fan_out_is_collapsed(
        self,
        db_session: AsyncSession,
        clock: Clock,
        ticket_factory: Factory,
        ticket_package_factory: Factory,
        cve_factory: Factory,
        cve_external_identifier_factory: Factory,
    ) -> None:
        """One Ticket matching through its sequence number, its CVE-ID,
        three package names, and two external identifiers is one row."""
        cve = await cve_factory(cve_id="CVE-2099-55001")
        ticket = await ticket_factory(sequence_id=55, cve_id=cve.id)
        for name in ("pkg-55-a", "pkg-55-b", "pkg-55-c"):
            await ticket_package_factory(ticket_id=ticket.id, package_name=name)
        for identifier in ("55-GHSA-1", "55-GHSA-2"):
            await cve_external_identifier_factory(cve_id=cve.id, identifier=identifier)
        other = await ticket_factory(sequence_id=99)

        page = await _list(db_session, search="55")

        assert [item.ticket_id for item in page.items] == [_sntl(ticket)]
        assert page.total == 1
        assert await _ids(db_session, search="pkg-55") == [_sntl(ticket)]
        assert _sntl(other) not in await _ids(db_session, search="55")


# ---------------------------------------------------------------------------
# Filters
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestEnumFilters:
    async def test_status_filter_is_or_within_and_empty_matches_nothing(
        self, db_session: AsyncSession, clock: Clock, ticket_factory: Factory
    ) -> None:
        by_status = {
            status: await ticket_factory(status=status.value)
            for status in (
                TicketStatus.NEW,
                TicketStatus.ANALYSIS,
                TicketStatus.RESOLVED,
            )
        }

        assert await _ids(db_session, status=[TicketStatus.NEW]) == [
            _sntl(by_status[TicketStatus.NEW])
        ]
        assert set(
            await _ids(db_session, status=[TicketStatus.NEW, TicketStatus.RESOLVED])
        ) == _set([by_status[TicketStatus.NEW], by_status[TicketStatus.RESOLVED]])
        assert await _ids(db_session, status=[]) == []
        assert len(await _ids(db_session, status=None)) == 3

    async def test_severity_filter_distinguishes_none_label_from_unresolved(
        self,
        db_session: AsyncSession,
        clock: Clock,
        ticket_factory: Factory,
        cve_factory: Factory,
    ) -> None:
        critical_cve = await cve_factory(severity=Severity.CRITICAL.value)
        none_cve = await cve_factory(severity=Severity.NONE.value)
        unresolved_cve = await cve_factory(severity=None)
        cve_critical = await ticket_factory(cve_id=critical_cve.id)
        cve_none = await ticket_factory(cve_id=none_cve.id)
        cve_unresolved = await ticket_factory(cve_id=unresolved_cve.id)
        manual_none = await ticket_factory(severity_manual=Severity.NONE.value)
        manual_low = await ticket_factory(severity_manual=Severity.LOW.value)
        manual_unresolved = await ticket_factory()

        assert set(await _ids(db_session, severity=[Severity.NONE])) == _set(
            [cve_none, manual_none]
        )
        assert set(await _ids(db_session, severity=[None])) == _set(
            [cve_unresolved, manual_unresolved]
        )
        assert set(
            await _ids(db_session, severity=[Severity.CRITICAL, Severity.LOW])
        ) == _set([cve_critical, manual_low])
        assert await _ids(db_session, severity=[]) == []

    async def test_priority_filter_uses_the_effective_priority(
        self, db_session: AsyncSession, clock: Clock, ticket_factory: Factory
    ) -> None:
        overridden = await ticket_factory(
            priority_auto=TicketPriority.P4.value,
            priority_override=TicketPriority.P1.value,
        )
        override_only = await ticket_factory(priority_override=TicketPriority.P2.value)
        automatic = await ticket_factory(priority_auto=TicketPriority.P4.value)
        unresolved = await ticket_factory()

        assert await _ids(db_session, priority=[TicketPriority.P1]) == [
            _sntl(overridden)
        ]
        assert await _ids(db_session, priority=[TicketPriority.P4]) == [
            _sntl(automatic)
        ]
        assert await _ids(db_session, priority=[None]) == [_sntl(unresolved)]
        assert set(await _ids(db_session, priority=[TicketPriority.P2, None])) == _set(
            [override_only, unresolved]
        )
        assert await _ids(db_session, priority=[]) == []

    async def test_different_filters_combine_with_and(
        self, db_session: AsyncSession, clock: Clock, ticket_factory: Factory
    ) -> None:
        match = await ticket_factory(
            status=TicketStatus.ANALYSIS.value,
            severity_manual=Severity.HIGH.value,
            priority_auto=TicketPriority.P2.value,
        )
        await ticket_factory(
            status=TicketStatus.NEW.value,
            severity_manual=Severity.HIGH.value,
            priority_auto=TicketPriority.P2.value,
        )
        await ticket_factory(
            status=TicketStatus.ANALYSIS.value,
            severity_manual=Severity.LOW.value,
            priority_auto=TicketPriority.P2.value,
        )
        await ticket_factory(
            status=TicketStatus.ANALYSIS.value,
            severity_manual=Severity.HIGH.value,
            priority_auto=TicketPriority.P3.value,
        )

        assert await _ids(
            db_session,
            status=[TicketStatus.ANALYSIS],
            severity=[Severity.HIGH],
            priority=[TicketPriority.P2],
        ) == [_sntl(match)]
        assert (
            await _ids(
                db_session,
                status=[TicketStatus.ANALYSIS],
                severity=[Severity.HIGH],
                priority=[],
            )
            == []
        )


@pytest.mark.integration
class TestUserFilters:
    async def test_assignee_by_uuid_username_and_literal_none(
        self,
        db_session: AsyncSession,
        clock: Clock,
        ticket_factory: Factory,
        user_factory: Factory,
    ) -> None:
        analyst: User = await user_factory(username="fictional.va")
        # A user literally named `none` never shadows the keyword, which is
        # handled before User resolution.
        named_none: User = await user_factory(username="none")
        assigned = await ticket_factory(assignee_id=analyst.id)
        assigned_to_none_user = await ticket_factory(assignee_id=named_none.id)
        unassigned = await ticket_factory()

        assert await _ids(db_session, assignee=str(analyst.id)) == [_sntl(assigned)]
        assert await _ids(db_session, assignee="fictional.va") == [_sntl(assigned)]
        assert await _ids(db_session, assignee="none") == [_sntl(unassigned)]
        assert await _ids(db_session, assignee=str(named_none.id)) == [
            _sntl(assigned_to_none_user)
        ]

    @pytest.mark.parametrize(
        "identifier",
        [
            "unknown.user",
            str(uuid.UUID(int=7)),
            "Fictional.VA",
            "NONE",
            "",
            # Email input is not accepted (tickets.md, List Tickets).
            "fictional.va@example.com",
        ],
    )
    async def test_unknown_or_non_exact_user_filter_yields_an_empty_page(
        self,
        db_session: AsyncSession,
        clock: Clock,
        ticket_factory: Factory,
        user_factory: Factory,
        ticket_package_factory: Factory,
        ticket_package_maintainer_factory: Factory,
        identifier: str,
    ) -> None:
        analyst: User = await user_factory(
            username="fictional.va", email="fictional.va@example.com"
        )
        ticket = await ticket_factory(assignee_id=analyst.id)
        package = await ticket_package_factory(ticket_id=ticket.id)
        await ticket_package_maintainer_factory(
            ticket_package_id=package.id, user_id=analyst.id
        )
        await ticket_factory()

        for page in (
            await _list(db_session, assignee=identifier),
            await _list(db_session, maintainer=identifier),
        ):
            assert page.items == ()
            assert page.total == 0

    async def test_maintainer_matches_included_packages_without_fan_out(
        self,
        db_session: AsyncSession,
        clock: Clock,
        ticket_factory: Factory,
        user_factory: Factory,
        ticket_package_factory: Factory,
        ticket_package_maintainer_factory: Factory,
    ) -> None:
        maintainer: User = await user_factory(username="fictional.maint")
        other: User = await user_factory()
        several = await ticket_factory()
        for name in ("pkg-a", "pkg-b", "pkg-c"):
            package = await ticket_package_factory(
                ticket_id=several.id, package_name=name
            )
            await ticket_package_maintainer_factory(
                ticket_package_id=package.id, user_id=maintainer.id
            )
            await ticket_package_maintainer_factory(
                ticket_package_id=package.id, user_id=other.id
            )
        excluded_only = await ticket_factory()
        excluded = await ticket_package_factory(
            ticket_id=excluded_only.id, deleted_at=EXCLUDED_AT
        )
        await ticket_package_maintainer_factory(
            ticket_package_id=excluded.id, user_id=maintainer.id
        )
        await ticket_factory()

        for identifier in (str(maintainer.id), "fictional.maint"):
            page = await _list(db_session, maintainer=identifier)
            assert [item.ticket_id for item in page.items] == [_sntl(several)]
            assert page.total == 1
        assert await _ids(db_session, maintainer="unknown.user") == []
        assert await _ids(db_session, maintainer=str(uuid.UUID(int=9))) == []

    async def test_maintainer_filter_never_widens_visibility(
        self,
        db_session: AsyncSession,
        clock: Clock,
        ticket_factory: Factory,
        user_factory: Factory,
        ticket_package_factory: Factory,
        ticket_package_maintainer_factory: Factory,
    ) -> None:
        maintainer: User = await user_factory()
        confidential = await ticket_factory(is_confidential=True)
        package = await ticket_package_factory(ticket_id=confidential.id)
        await ticket_package_maintainer_factory(
            ticket_package_id=package.id, user_id=maintainer.id
        )
        stranger = TicketCaller.authenticated(uuid.uuid4(), Scope.NON_CONFIDENTIAL)

        assert await _ids(db_session, stranger, maintainer=str(maintainer.id)) == []
        assert (
            await _ids(db_session, ANONYMOUS_CALLER, maintainer=str(maintainer.id))
            == []
        )


# ---------------------------------------------------------------------------
# Overdue filter (ticket-deadlines.md, Ticket-Level Overdue Filter)
# ---------------------------------------------------------------------------


def _triage_overdue(case: DeadlineCase) -> bool:
    """Ticket-level triage oracle: status `New`/`Analysis` and the
    matrix-expected triage due date strictly before the instant."""
    expected = case.expected_due_dates()
    return (
        case.ticket_status in {TicketStatus.NEW, TicketStatus.ANALYSIS}
        and expected is not None
        and expected[0] < case.evaluation_instant
    )


@pytest.mark.integration
class TestOverdueMatrix:
    @pytest.mark.parametrize("case", DEADLINE_CASES, ids=lambda case: case.id)
    async def test_overdue_filter_and_due_dates_match_the_shared_matrix(
        self,
        db_session: AsyncSession,
        clock: Clock,
        deadline_world: DeadlineWorld,
        case: DeadlineCase,
    ) -> None:
        """For every shared-matrix case, the list selects the Ticket for a
        later phase exactly when the case's track milestone is `overdue`,
        for `triage` by the Ticket-level rule, and projects the expected
        Ticket-level due dates."""
        persisted = await deadline_world.build(case)
        clock.instant = case.evaluation_instant
        sntl = _sntl(persisted.ticket)

        # Other Tickets may exist (a duplicate target, the parent of an
        # uncorrelated request's track); the case's Ticket is asserted by
        # membership.
        (item,) = [
            item
            for item in (await _list(db_session, per_page=100)).items
            if item.ticket_id == sntl
        ]
        expected_due = case.expected_due_dates()
        projected = (
            None
            if item.due_dates is None
            else (
                item.due_dates.triage,
                item.due_dates.submission,
                item.due_dates.um,
                item.due_dates.qa,
                item.due_dates.release,
            )
        )
        assert projected == expected_due

        for phase, index in LATER_PHASE_INDEX.items():
            selected = await _ids(db_session, overdue=[phase])
            assert (sntl in selected) is (case.expected_statuses[index] is O), phase
        triage = await _ids(db_session, overdue=[MilestonePhase.TRIAGE])
        assert (sntl in triage) is _triage_overdue(case)


def _overdue_track_case(name: str, **changes: Any) -> DeadlineCase:
    """A CVE-associated IBS `AFFECTED` track with one unreleased actionable
    eligible Product and no submission evidence."""
    return dataclasses.replace(
        DeadlineCase(
            id=name,
            expected_offsets_days=None,
            expected_statuses=(None, None, None, None),
            expected_current_phase=None,
        ),
        **changes,
    )


@pytest.mark.integration
class TestOverdueFilter:
    async def test_triage_is_ticket_level_for_tickets_without_packages(
        self, db_session: AsyncSession, clock: Clock, ticket_factory: Factory
    ) -> None:
        clock.instant = AFTER_TRIAGE_DUE
        by_status = {
            status: await ticket_factory(status=status.value, created_at=CREATED_AT)
            for status in TicketStatus
            if status is not TicketStatus.DUPLICATED
        }
        duplicated = await ticket_factory(
            status=TicketStatus.DUPLICATED.value,
            created_at=CREATED_AT,
            duplicate_of_id=by_status[TicketStatus.NEW].id,
        )

        selected = set(await _ids(db_session, overdue=[MilestonePhase.TRIAGE]))

        assert selected == _set(
            [by_status[TicketStatus.NEW], by_status[TicketStatus.ANALYSIS]]
        )
        assert _sntl(duplicated) not in selected

    async def test_triage_due_equal_to_the_instant_is_not_overdue(
        self, db_session: AsyncSession, clock: Clock, ticket_factory: Factory
    ) -> None:
        ticket = await ticket_factory(created_at=CREATED_AT)

        clock.instant = AT_TRIAGE_DUE
        assert await _ids(db_session, overdue=[MilestonePhase.TRIAGE]) == []
        clock.instant = AT_TRIAGE_DUE + timedelta(microseconds=1)
        assert await _ids(db_session, overdue=[MilestonePhase.TRIAGE]) == [
            _sntl(ticket)
        ]

    async def test_severity_none_never_matches(
        self, db_session: AsyncSession, clock: Clock, ticket_factory: Factory
    ) -> None:
        clock.instant = AFTER_ALL_DUE
        await ticket_factory(severity_manual=Severity.NONE.value, created_at=CREATED_AT)

        assert await _ids(db_session, overdue=list(MilestonePhase)) == []

    async def test_qa_returns_a_ticket_with_an_unreleased_actionable_eligible_product(
        self, db_session: AsyncSession, clock: Clock, deadline_world: DeadlineWorld
    ) -> None:
        clock.instant = AFTER_ALL_DUE
        unreleased = await deadline_world.build(
            _overdue_track_case(
                "unreleased",
                delivery_status=DeliveryStatus.IN_PROGRESS,
                products=(ProductEvidence(released=True), ProductEvidence()),
            )
        )
        await deadline_world.build(
            _overdue_track_case(
                "released",
                track_status=PackageStatus.FIXED,
                delivery_status=DeliveryStatus.RELEASED,
                products=(ProductEvidence(released=True),),
            )
        )

        assert await _ids(db_session, overdue=[MilestonePhase.QA]) == [
            _sntl(unreleased.ticket)
        ]
        assert await _ids(db_session, overdue=[MilestonePhase.SUBMISSION]) == []

    async def test_resolved_ticket_never_matches(
        self, db_session: AsyncSession, clock: Clock, deadline_world: DeadlineWorld
    ) -> None:
        """A `Resolved` Ticket: its applicable `FIXED` track is released to
        every actionable eligible Product; a `NOT_AFFECTED` track has its
        later phases `not_applicable`."""
        clock.instant = AFTER_ALL_DUE
        resolved = await deadline_world.build(
            _overdue_track_case(
                "resolved",
                ticket_status=TicketStatus.RESOLVED,
                track_status=PackageStatus.FIXED,
                delivery_status=DeliveryStatus.RELEASED,
                products=(ProductEvidence(released=True),),
            )
        )
        await deadline_world.build(
            _overdue_track_case(
                "resolved-na",
                ticket_status=TicketStatus.RESOLVED,
                track_status=PackageStatus.NOT_AFFECTED,
            ),
            ticket=resolved.ticket,
        )

        assert await _ids(db_session, overdue=list(MilestonePhase)) == []

    async def test_phases_combine_with_or_and_other_filters_with_and(
        self,
        db_session: AsyncSession,
        clock: Clock,
        deadline_world: DeadlineWorld,
        ticket_factory: Factory,
    ) -> None:
        clock.instant = AFTER_ALL_DUE
        submission = await deadline_world.build(_overdue_track_case("submission"))
        triage_only = await ticket_factory(
            status=TicketStatus.NEW.value, created_at=CREATED_AT
        )
        await deadline_world.build(
            # Git later phases are unobservable (`null`); `Analyzed` has
            # completed triage.
            _overdue_track_case(
                "git",
                workflow_type=WorkflowType.GIT,
                ticket_status=TicketStatus.ANALYZED,
            )
        )

        both = [MilestonePhase.SUBMISSION, MilestonePhase.TRIAGE]
        assert set(await _ids(db_session, overdue=both)) == _set(
            [submission.ticket, triage_only]
        )
        assert await _ids(db_session, overdue=both, status=[TicketStatus.NEW]) == [
            _sntl(triage_only)
        ]
        assert await _ids(db_session, overdue=[]) == []

    async def test_several_overdue_tracks_count_the_ticket_once(
        self, db_session: AsyncSession, clock: Clock, deadline_world: DeadlineWorld
    ) -> None:
        clock.instant = AFTER_ALL_DUE
        first = await deadline_world.build(_overdue_track_case("a"))
        for name in ("b", "c"):
            await deadline_world.build(_overdue_track_case(name), ticket=first.ticket)

        page = await _list(
            db_session,
            overdue=[MilestonePhase.SUBMISSION, MilestonePhase.UM, MilestonePhase.QA],
        )

        assert [item.ticket_id for item in page.items] == [_sntl(first.ticket)]
        assert page.total == 1

    async def test_actionability_uses_the_utc_date_of_the_one_instant(
        self,
        db_session: AsyncSession,
        clock: Clock,
        deadline_world: DeadlineWorld,
    ) -> None:
        """The instant 2026-03-29T01:00+02:00 is 2026-03-28T23:00Z: its UTC
        date keeps a Product whose General Support ends on 2026-03-28
        actionable, so the submission milestone (due 2026-03-28T14:37Z)
        is overdue. A local-date evaluation would make it `eol`."""
        persisted = await deadline_world.build(
            _overdue_track_case("lifecycle", products=())
        )
        product = await deadline_world.factory("product_factory")(
            general_support_end_date=date(2026, 3, 28)
        )
        await deadline_world.factory("ticket_package_product_factory")(
            ticket_package_track_id=persisted.track.id, product_id=product.id
        )

        clock.instant = datetime(2026, 3, 29, 1, 0, tzinfo=timezone(timedelta(hours=2)))
        assert await _ids(db_session, overdue=[MilestonePhase.SUBMISSION]) == [
            _sntl(persisted.ticket)
        ]
        clock.instant = datetime(2026, 3, 29, 0, 30, tzinfo=UTC)
        assert await _ids(db_session, overdue=[MilestonePhase.SUBMISSION]) == []


# ---------------------------------------------------------------------------
# Sorting and pagination
# ---------------------------------------------------------------------------


async def _order(
    db: AsyncSession, sort_by: TicketSortField, sort_order: SortOrder
) -> list[str]:
    return await _ids(db, sort_by=sort_by, sort_order=sort_order)


@pytest.mark.integration
class TestSorting:
    async def test_default_order_is_created_at_descending(
        self, db_session: AsyncSession, clock: Clock, ticket_factory: Factory
    ) -> None:
        tickets = [
            await ticket_factory(created_at=CREATED_AT + timedelta(hours=hours))
            for hours in (2, 0, 1)
        ]

        assert await _ids(db_session) == [
            _sntl(tickets[0]),
            _sntl(tickets[2]),
            _sntl(tickets[1]),
        ]

    async def test_severity_uses_semantic_rank_with_null_last(
        self, db_session: AsyncSession, clock: Clock, ticket_factory: Factory
    ) -> None:
        ranked = {
            label: await ticket_factory(severity_manual=label.value)
            for label in (
                Severity.LOW,
                Severity.CRITICAL,
                Severity.NONE,
                Severity.HIGH,
                Severity.MEDIUM,
            )
        }
        unresolved = await ticket_factory()
        ascending = [
            _sntl(ranked[label])
            for label in (
                Severity.NONE,
                Severity.LOW,
                Severity.MEDIUM,
                Severity.HIGH,
                Severity.CRITICAL,
            )
        ]

        assert await _order(db_session, TicketSortField.SEVERITY, SortOrder.ASC) == [
            *ascending,
            _sntl(unresolved),
        ]
        assert await _order(db_session, TicketSortField.SEVERITY, SortOrder.DESC) == [
            *reversed(ascending),
            _sntl(unresolved),
        ]

    async def test_priority_uses_semantic_rank_of_the_effective_priority(
        self, db_session: AsyncSession, clock: Clock, ticket_factory: Factory
    ) -> None:
        p1 = await ticket_factory(
            priority_auto=TicketPriority.P4.value,
            priority_override=TicketPriority.P1.value,
        )
        p3 = await ticket_factory(priority_auto=TicketPriority.P3.value)
        p2 = await ticket_factory(priority_override=TicketPriority.P2.value)
        p4 = await ticket_factory(priority_auto=TicketPriority.P4.value)
        unresolved = await ticket_factory()
        ascending = [_sntl(t) for t in (p4, p3, p2, p1)]

        assert await _order(db_session, TicketSortField.PRIORITY, SortOrder.ASC) == [
            *ascending,
            _sntl(unresolved),
        ]
        assert await _order(db_session, TicketSortField.PRIORITY, SortOrder.DESC) == [
            *reversed(ascending),
            _sntl(unresolved),
        ]

    async def test_status_uses_semantic_rank(
        self, db_session: AsyncSession, clock: Clock, ticket_factory: Factory
    ) -> None:
        target = await ticket_factory(status=TicketStatus.ANALYZED.value)
        by_status = {
            TicketStatus.ANALYZED: target,
            TicketStatus.DUPLICATED: await ticket_factory(duplicate_of_id=target.id),
        }
        for status in (
            TicketStatus.RESOLVED,
            TicketStatus.NEW,
            TicketStatus.IGNORED,
            TicketStatus.ANALYSIS,
        ):
            by_status[status] = await ticket_factory(status=status.value)
        ascending = [
            _sntl(by_status[status])
            for status in (
                TicketStatus.NEW,
                TicketStatus.ANALYSIS,
                TicketStatus.ANALYZED,
                TicketStatus.RESOLVED,
                TicketStatus.IGNORED,
                TicketStatus.DUPLICATED,
            )
        ]

        assert (
            await _order(db_session, TicketSortField.STATUS, SortOrder.ASC) == ascending
        )
        assert await _order(db_session, TicketSortField.STATUS, SortOrder.DESC) == [
            *reversed(ascending)
        ]

    async def test_ticket_id_sorts_by_numeric_sequence(
        self, db_session: AsyncSession, clock: Clock, ticket_factory: Factory
    ) -> None:
        tickets = [await ticket_factory(sequence_id=n) for n in (10, 9, 100)]
        ascending = [_sntl(tickets[1]), _sntl(tickets[0]), _sntl(tickets[2])]

        assert (
            await _order(db_session, TicketSortField.TICKET_ID, SortOrder.ASC)
            == ascending
        )
        assert await _order(db_session, TicketSortField.TICKET_ID, SortOrder.DESC) == [
            *reversed(ascending)
        ]

    @pytest.mark.parametrize(
        "sort_by", [TicketSortField.CREATED_AT, TicketSortField.UPDATED_AT]
    )
    async def test_timestamps_sort_in_both_directions(
        self,
        db_session: AsyncSession,
        clock: Clock,
        ticket_factory: Factory,
        sort_by: TicketSortField,
    ) -> None:
        tickets = [
            await ticket_factory(
                created_at=CREATED_AT + timedelta(hours=hours),
                updated_at=UPDATED_AT - timedelta(hours=hours),
            )
            for hours in (1, 2, 0)
        ]
        by_created = [_sntl(tickets[i]) for i in (2, 0, 1)]
        ascending = (
            by_created if sort_by is TicketSortField.CREATED_AT else by_created[::-1]
        )

        assert await _order(db_session, sort_by, SortOrder.ASC) == ascending
        assert await _order(db_session, sort_by, SortOrder.DESC) == ascending[::-1]

    @pytest.mark.parametrize(
        ("sort_by", "ascending_names"),
        [
            # Expected orders transcribed from the ticket-deadlines.md
            # Formula table (30-day tier 3/18/21/30/30, 90-day 9/54/63/90/90,
            # 180-day 18/108/126/180/180 days) for: `medium` created at
            # +0 d, `critical40` at +40 d, `low` at +0 d, `critical120` at
            # +120 d. Triage 9/43/18/123, submission 54/58/108/138, um
            # 63/61/126/141, qa and release 90/70/180/150 days: each phase
            # has its own order, so a field-to-date mix-up fails.
            (
                TicketSortField.TRIAGE_DUE_AT,
                ["medium", "low", "critical40", "critical120"],
            ),
            (
                TicketSortField.SUBMISSION_DUE_AT,
                ["medium", "critical40", "low", "critical120"],
            ),
            (TicketSortField.UM_DUE_AT, ["critical40", "medium", "low", "critical120"]),
            (TicketSortField.QA_DUE_AT, ["critical40", "medium", "critical120", "low"]),
            (
                TicketSortField.RELEASE_DUE_AT,
                ["critical40", "medium", "critical120", "low"],
            ),
        ],
    )
    async def test_due_dates_sort_by_their_own_date_with_null_last(
        self,
        db_session: AsyncSession,
        clock: Clock,
        ticket_factory: Factory,
        sort_by: TicketSortField,
        ascending_names: list[str],
    ) -> None:
        """Each due-date field sorts by its own Ticket-level date; Ignored
        and severity `None` Tickets have no date and sort last in both
        directions, tie-broken by `Ticket.id` in the requested direction."""
        tickets = {
            name: await ticket_factory(
                severity_manual=severity.value,
                created_at=CREATED_AT + timedelta(days=offset),
            )
            for name, severity, offset in (
                ("medium", Severity.MEDIUM, 0),
                ("critical40", Severity.CRITICAL, 40),
                ("low", Severity.LOW, 0),
                ("critical120", Severity.CRITICAL, 120),
            )
        }
        ignored = await ticket_factory(
            severity_manual=Severity.CRITICAL.value,
            status=TicketStatus.IGNORED.value,
            created_at=CREATED_AT,
        )
        no_sla = await ticket_factory(
            severity_manual=Severity.NONE.value, created_at=CREATED_AT
        )
        nulls = [_sntl(t) for t in sorted([ignored, no_sla], key=lambda t: t.id)]
        ascending = [_sntl(tickets[name]) for name in ascending_names]

        assert await _order(db_session, sort_by, SortOrder.ASC) == [*ascending, *nulls]
        assert await _order(db_session, sort_by, SortOrder.DESC) == [
            *reversed(ascending),
            *reversed(nulls),
        ]

    @pytest.mark.parametrize("sort_order", list(SortOrder))
    @pytest.mark.parametrize(
        "sort_by",
        [
            TicketSortField.SEVERITY,
            TicketSortField.PRIORITY,
            TicketSortField.STATUS,
            TicketSortField.CREATED_AT,
            TicketSortField.TRIAGE_DUE_AT,
        ],
    )
    async def test_equal_keys_page_deterministically_by_internal_id(
        self,
        db_session: AsyncSession,
        clock: Clock,
        ticket_factory: Factory,
        sort_by: TicketSortField,
        sort_order: SortOrder,
    ) -> None:
        """Equal primary keys are tie-broken by `Ticket.id` in the requested
        direction: paging one row at a time neither repeats nor skips."""
        tickets = [
            await ticket_factory(
                severity_manual=Severity.HIGH.value,
                priority_auto=TicketPriority.P2.value,
                created_at=CREATED_AT,
            )
            for _ in range(5)
        ]
        expected = [
            _sntl(t)
            for t in sorted(
                tickets,
                key=lambda ticket: ticket.id,
                reverse=sort_order is SortOrder.DESC,
            )
        ]

        pages = [
            await _list(
                db_session, sort_by=sort_by, sort_order=sort_order, page=n, per_page=1
            )
            for n in range(1, 6)
        ]

        assert [page.items[0].ticket_id for page in pages] == expected
        assert {page.total for page in pages} == {5}


@pytest.mark.integration
class TestPagination:
    async def test_total_is_computed_before_slicing(
        self, db_session: AsyncSession, clock: Clock, ticket_factory: Factory
    ) -> None:
        tickets = [
            await ticket_factory(created_at=CREATED_AT + timedelta(minutes=n))
            for n in range(5)
        ]

        page = await _list(db_session, page=2, per_page=2)

        assert page.total == 5
        assert (page.page, page.per_page) == (2, 2)
        assert [item.ticket_id for item in page.items] == [
            _sntl(tickets[2]),
            _sntl(tickets[1]),
        ]

    async def test_page_beyond_the_last_is_empty_with_the_correct_total(
        self, db_session: AsyncSession, clock: Clock, ticket_factory: Factory
    ) -> None:
        for _ in range(3):
            await ticket_factory()

        page = await _list(db_session, page=4, per_page=1)

        assert page.items == ()
        assert page.total == 3

    async def test_empty_table_yields_an_empty_page(
        self, db_session: AsyncSession, clock: Clock
    ) -> None:
        page = await _list(db_session)

        assert page == TicketPage(items=(), total=0, page=1, per_page=20)

    @pytest.mark.parametrize(
        ("page", "per_page"), [(0, 20), (-1, 20), (1, 0), (1, 101)]
    )
    async def test_out_of_range_pagination_raises_before_any_query(
        self, page: int, per_page: int
    ) -> None:
        db = AsyncMock(spec=AsyncSession)

        with pytest.raises(ValueError, match="page"):
            await list_tickets(db, caller=ALL_SCOPE, page=page, per_page=per_page)

        db.execute.assert_not_awaited()

    async def test_database_error_propagates(self) -> None:
        db = AsyncMock(spec=AsyncSession)
        failure = OperationalError("SELECT 1", {}, Exception("connection lost"))
        db.execute.side_effect = failure

        with pytest.raises(OperationalError) as excinfo:
            await list_tickets(db, caller=ALL_SCOPE)

        assert excinfo.value is failure


# ---------------------------------------------------------------------------
# Visibility (testing-strategy.md, Ticket Accessibility > list and count)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestVisibility:
    async def test_mixed_visibility_rows_and_total(
        self,
        db_session: AsyncSession,
        clock: Clock,
        ticket_factory: Factory,
        user_factory: Factory,
        ticket_access_grant_factory: Factory,
        ticket_package_factory: Factory,
        ticket_package_maintainer_factory: Factory,
    ) -> None:
        caller_user: User = await user_factory()
        public = await ticket_factory()
        granted = await ticket_factory(is_confidential=True)
        await ticket_access_grant_factory(ticket_id=granted.id, user_id=caller_user.id)
        maintained = await ticket_factory(is_confidential=True)
        package = await ticket_package_factory(ticket_id=maintained.id)
        await ticket_package_maintainer_factory(
            ticket_package_id=package.id, user_id=caller_user.id
        )
        excluded_maintained = await ticket_factory(is_confidential=True)
        excluded = await ticket_package_factory(
            ticket_id=excluded_maintained.id, deleted_at=EXCLUDED_AT
        )
        await ticket_package_maintainer_factory(
            ticket_package_id=excluded.id, user_id=caller_user.id
        )
        hidden = await ticket_factory(is_confidential=True)
        restricted = TicketCaller.authenticated(caller_user.id, Scope.NON_CONFIDENTIAL)
        no_path = TicketCaller.authenticated(uuid.uuid4(), Scope.NON_CONFIDENTIAL)

        expectations = {
            ANONYMOUS_CALLER: [public],
            no_path: [public],
            restricted: [public, granted, maintained],
            ALL_SCOPE: [public, granted, maintained, excluded_maintained, hidden],
        }
        for caller, visible in expectations.items():
            page = await _list(db_session, caller, per_page=1)
            assert page.total == len(visible), caller
            assert set(await _ids(db_session, caller)) == _set(visible), caller

    async def test_filters_and_search_apply_only_to_visible_candidates(
        self,
        db_session: AsyncSession,
        clock: Clock,
        ticket_factory: Factory,
        ticket_package_factory: Factory,
    ) -> None:
        clock.instant = AFTER_TRIAGE_DUE
        hidden = await ticket_factory(
            is_confidential=True,
            severity_manual=Severity.CRITICAL.value,
            created_at=CREATED_AT,
        )
        await ticket_package_factory(ticket_id=hidden.id, package_name="secret-pkg")

        for filters in (
            {"search": "secret"},
            {"severity": [Severity.CRITICAL]},
            {"overdue": [MilestonePhase.TRIAGE]},
            {"sort_by": TicketSortField.SEVERITY},
        ):
            page = await _list(db_session, ANONYMOUS_CALLER, **filters)
            assert page.items == ()
            assert page.total == 0

    async def test_anonymous_list_evaluates_no_grant_or_maintainer_branch(
        self, db_session: AsyncSession, clock: Clock, ticket_factory: Factory
    ) -> None:
        await ticket_factory()

        with _StatementRecorder(db_session) as recorder:
            await _list(db_session, ANONYMOUS_CALLER)

        (statement,) = recorder.statements
        assert "ticket_access_grant" not in statement
        assert "ticket_package_maintainer" not in statement


# ---------------------------------------------------------------------------
# One statement, one instant, no side effects
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestBoundedRead:
    async def test_one_statement_regardless_of_page_size(
        self,
        db_session: AsyncSession,
        clock: Clock,
        ticket_factory: Factory,
        user_factory: Factory,
        cve_factory: Factory,
        cve_external_identifier_factory: Factory,
        ticket_package_factory: Factory,
        ticket_package_maintainer_factory: Factory,
    ) -> None:
        """No per-row loading: every page size runs exactly one statement
        (fan-out through packages, maintainers, and external IDs)."""
        for index in range(12):
            assignee = await user_factory()
            cve = await cve_factory()
            ticket = await ticket_factory(cve_id=cve.id, assignee_id=assignee.id)
            await cve_external_identifier_factory(cve_id=cve.id)
            for name in ("a", "b"):
                package = await ticket_package_factory(
                    ticket_id=ticket.id, package_name=f"{name}-{index}"
                )
                await ticket_package_maintainer_factory(
                    ticket_package_id=package.id, user_id=assignee.id
                )

        counts = []
        for per_page in (1, 5, 12):
            with _StatementRecorder(db_session) as recorder:
                page = await _list(db_session, search="-", per_page=per_page)
            assert page.total == 12
            assert len(page.items) == per_page
            counts.append(len(recorder.statements))

        assert counts == [1, 1, 1]

    async def test_one_instant_is_captured_per_list(
        self, db_session: AsyncSession, clock: Clock, ticket_factory: Factory
    ) -> None:
        await ticket_factory()

        await _list(
            db_session,
            overdue=list(MilestonePhase),
            sort_by=TicketSortField.TRIAGE_DUE_AT,
        )

        assert len(clock.calls) == 1

    async def test_list_writes_no_row_and_creates_no_event(
        self,
        db_session: AsyncSession,
        clock: Clock,
        deadline_world: DeadlineWorld,
    ) -> None:
        """Requirement 11: listing, filtering, and sorting by deadlines
        only read; nothing is persisted and no audit event is created."""
        clock.instant = AFTER_ALL_DUE
        persisted = await deadline_world.build(_overdue_track_case("side-effects"))
        snapshot = select(
            Ticket.status,
            Ticket.updated_at,
            Ticket.priority_auto,
            Ticket.assignee_id,
        ).where(Ticket.id == persisted.ticket.id)
        before = (await db_session.execute(snapshot)).one()

        with _StatementRecorder(db_session) as recorder:
            await _list(
                db_session,
                overdue=list(MilestonePhase),
                sort_by=TicketSortField.SUBMISSION_DUE_AT,
            )

        after = (await db_session.execute(snapshot)).one()
        events = await db_session.scalar(
            select(func.count()).select_from(TicketAuditEvent)
        )
        assert after == before
        assert events == 0
        assert not db_session.new
        assert not db_session.dirty
        assert [s.lstrip()[:4].upper() for s in recorder.statements] == ["WITH"]


# ---------------------------------------------------------------------------
# Independent-session races (one coherent observation)
# ---------------------------------------------------------------------------

_RACE_PACKAGE = "fictional-list-race"


class _CommittedWorld:
    """Commits fixture rows through an independent session and deletes them
    at teardown in FK-safe order (committed data is not rolled back)."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.ticket_ids: list[uuid.UUID] = []
        self.user_ids: list[uuid.UUID] = []

    async def user(self) -> User:
        user = User(
            username=f"fictional.list.{uuid.uuid4().hex[:10]}",
            email=f"list.{uuid.uuid4().hex[:10]}@example.com",
            password_hash="$2b$12$" + "a" * 53,
        )
        self.session.add(user)
        await self.session.commit()
        self.user_ids.append(user.id)
        return user

    async def ticket(
        self, *, is_confidential: bool, maintainer: User | None = None
    ) -> tuple[Ticket, TicketPackage]:
        ticket = Ticket(is_confidential=is_confidential)
        self.session.add(ticket)
        await self.session.flush()
        self.ticket_ids.append(ticket.id)
        package = TicketPackage(ticket_id=ticket.id, package_name=_RACE_PACKAGE)
        self.session.add(package)
        await self.session.flush()
        if maintainer is not None:
            self.session.add(
                TicketPackageMaintainer(
                    ticket_package_id=package.id, user_id=maintainer.id
                )
            )
        await self.session.commit()
        return ticket, package

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


async def _race_page(reader: AsyncSession, caller: TicketCaller) -> TicketPage:
    return await list_tickets(reader, caller=caller, search=_RACE_PACKAGE)


@pytest.mark.integration
class TestListRaces:
    """Session R lists once (the access decision a split implementation
    would reuse), session W commits a visibility change, and R lists
    again on the same connection. The list is one statement, so R's rows
    and total both reflect the committed change; no row selected after
    access was lost is returned and the count never disagrees with the
    page."""

    async def test_confidentiality_set_between_lists(
        self,
        committed_world: _CommittedWorld,
        db_session_factory: Callable[[], Awaitable[AsyncSession]],
    ) -> None:
        user = await committed_world.user()
        ticket, _ = await committed_world.ticket(is_confidential=False)
        await committed_world.ticket(is_confidential=False)
        reader = await db_session_factory()
        writer = await db_session_factory()
        caller = TicketCaller.authenticated(user.id, Scope.NON_CONFIDENTIAL)

        assert (await _race_page(reader, caller)).total == 2
        await _commit(
            writer,
            update(Ticket).where(Ticket.id == ticket.id).values(is_confidential=True),
        )
        after = await _race_page(reader, caller)

        assert after.total == 1 == len(after.items)
        assert _sntl(ticket) not in {item.ticket_id for item in after.items}

    async def test_grant_revoked_between_lists(
        self,
        committed_world: _CommittedWorld,
        db_session_factory: Callable[[], Awaitable[AsyncSession]],
    ) -> None:
        user = await committed_world.user()
        granter = await committed_world.user()
        ticket, _ = await committed_world.ticket(is_confidential=True)
        await committed_world.grant(ticket, user, granter)
        reader = await db_session_factory()
        writer = await db_session_factory()
        caller = TicketCaller.authenticated(user.id, Scope.NON_CONFIDENTIAL)

        assert [i.ticket_id for i in (await _race_page(reader, caller)).items] == [
            _sntl(ticket)
        ]
        await _commit(
            writer,
            delete(TicketAccessGrant).where(TicketAccessGrant.ticket_id == ticket.id),
        )

        assert await _race_page(reader, caller) == TicketPage(
            items=(), total=0, page=1, per_page=20
        )

    async def test_last_maintained_package_excluded_between_lists(
        self,
        committed_world: _CommittedWorld,
        db_session_factory: Callable[[], Awaitable[AsyncSession]],
    ) -> None:
        user = await committed_world.user()
        ticket, package = await committed_world.ticket(
            is_confidential=True, maintainer=user
        )
        reader = await db_session_factory()
        writer = await db_session_factory()
        caller = TicketCaller.authenticated(user.id, Scope.NON_CONFIDENTIAL)

        assert (await _race_page(reader, caller)).total == 1
        await _commit(
            writer,
            update(TicketPackage)
            .where(TicketPackage.id == package.id)
            .values(deleted_at=datetime.now(UTC)),
        )
        after = await list_tickets(reader, caller=caller)

        assert _sntl(ticket) not in {item.ticket_id for item in after.items}
        assert after.total == len(after.items)

    async def test_visibility_acquired_between_lists_is_observed_whole(
        self,
        committed_world: _CommittedWorld,
        db_session_factory: Callable[[], Awaitable[AsyncSession]],
    ) -> None:
        user = await committed_world.user()
        granter = await committed_world.user()
        ticket, _ = await committed_world.ticket(is_confidential=True)
        reader = await db_session_factory()
        writer = await db_session_factory()
        caller = TicketCaller.authenticated(user.id, Scope.NON_CONFIDENTIAL)

        assert (await _race_page(reader, caller)).total == 0
        writer.add(
            TicketAccessGrant(
                ticket_id=ticket.id, user_id=user.id, granted_by_id=granter.id
            )
        )
        await _commit(
            writer,
            update(Ticket)
            .where(Ticket.id == ticket.id)
            .values(severity_manual=Severity.HIGH.value),
        )
        after = await _race_page(reader, caller)

        assert after.total == 1
        (item,) = after.items
        assert item.ticket_id == _sntl(ticket)
        assert item.severity is Severity.HIGH
        assert item.package_names == (_RACE_PACKAGE,)

    async def test_concurrent_role_change_does_not_alter_the_resolved_caller(
        self,
        committed_world: _CommittedWorld,
        db_session_factory: Callable[[], Awaitable[AsyncSession]],
    ) -> None:
        """The service consumes the request-resolved scope: a role removal
        committed during the request does not narrow its visibility; the
        next request's newly resolved caller is narrowed."""
        user = await committed_world.user()
        committed_world.session.add(
            UserRole(user_id=user.id, role=Role.VULNERABILITY_ANALYST.value)
        )
        await committed_world.session.commit()
        ticket, _ = await committed_world.ticket(is_confidential=True)
        reader = await db_session_factory()
        writer = await db_session_factory()
        in_flight = TicketCaller.authenticated(user.id, Scope.ALL)

        await _commit(writer, delete(UserRole).where(UserRole.user_id == user.id))

        assert [i.ticket_id for i in (await _race_page(reader, in_flight)).items] == [
            _sntl(ticket)
        ]
        next_request = TicketCaller.authenticated(user.id, Scope.NON_CONFIDENTIAL)
        assert (await _race_page(reader, next_request)).total == 0
