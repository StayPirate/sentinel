"""Single-session service integration tests for the synchronous
manual-zone-exit eligibility convergence
`package_service.converge_manual_zone_exit_eligibility()`
(backend/app/services/package_service.py).

The package boundary is called directly with a Ticket locked in the
session at the `Analysis` floor, as the owning `ticket_service` exit
workflow leaves it.

Owning specifications:

- docs/features/packages/package-service.md (Synchronous
  manual-zone-exit eligibility convergence; Architectural Test
  Requirement: Synchronous manual-zone-exit eligibility, package-boundary
  part).
- docs/features/packages/package-model.md (Axis 2: Eligibility; Ticket
  Convergence, phase 1).
- docs/features/tickets/cvss-scoring.md (Eligibility Score Resolution).
- docs/features/tickets/ticket-audit-log.md (Event Type Contract:
  `product_eligibility_changed`; detail JSONB Schema Contract, notes on
  `reason` and `product_name`; Testing Requirements 1-6, 8, 10, 20).
- docs/features/platform/testing-strategy.md (Tier Responsibility and
  Proportionality).

The `ticket_service` composition (the caller-locked Ticket, one shared
evaluation date, the final gate, registration, and whole-workflow
rollback of audit Testing Requirements 7 and 24) is proven in
`tests/test_services/test_manual_zone_exits.py`; this module keeps one
representative propagation case.

Expected values are transcribed from the specifications, never computed
with the module under test.
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable
from decimal import Decimal
from typing import Any

import pytest
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import (
    PackageStatus,
    Severity,
    TicketAuditEventType,
    TicketStatus,
)
from app.models.cve import CVE
from app.models.product import Product
from app.models.system_setting import SystemSetting
from app.models.ticket import Ticket
from app.models.user import User
from app.services.package_service import (
    ManualZoneExitEligibilityResult,
    converge_manual_zone_exit_eligibility,
)
from app.services.ticket_audit_log import TicketAuditLog
from app.services.ticket_convergence_registry import (
    pending_ticket_convergence_effects,
)
from tests.support.cvss_chain import Assessment, CVEBuilder, eligibility, subjects
from tests.support.database import rollback_test_scope
from tests.support.ticket_mutations import (
    AFTER_EVAL,
    EVAL,
    REACTIVE_END,
    REACTIVE_EXTENDED_END,
    REACTIVE_GS_END,
    EventRow,
    Prod,
    StatementRecorder,
    TicketFactory,
    TreeBuilder,
    VAUser,
    cveless,
    lock_ticket,
    ticket_events,
    ticket_events_by_id,
)

pytest_plugins = ["tests.support.ticket_mutation_fixtures"]
"""Provides the shared `va_user`, `tree`, and `cve_with` fixtures."""

Factory = Callable[..., Awaitable[Any]]

DEFAULT_VERSION = "3.1"
"""The persisted `default_cvss_version` unless a test changes it."""


@pytest.fixture(autouse=True)
async def default_setting(
    system_setting_factory: Callable[..., Awaitable[SystemSetting]],
) -> SystemSetting:
    """The persisted `default_cvss_version` (the test schema has none)."""
    return await system_setting_factory(
        key="default_cvss_version", value=DEFAULT_VERSION
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _result(
    examined: int, skipped: int, changed: int
) -> ManualZoneExitEligibilityResult:
    return ManualZoneExitEligibilityResult(
        examined=examined, override_skipped=skipped, changed=changed
    )


def _reactivation(subject: dict[str, str], old: bool, new: bool) -> EventRow:
    """The system `product_eligibility_changed` of the manual-zone-exit
    convergence (ticket-audit-log.md, detail JSONB Schema Contract:
    `reason = reactivation`, no `override_action`, `user_id` and `comment`
    `NULL`)."""
    return EventRow(
        "product_eligibility_changed",
        None,
        "true" if old else "false",
        "true" if new else "false",
        None,
        {**subject, "reason": "reactivation"},
    )


async def _reactivation_subjects(
    db: AsyncSession, ticket_id: uuid.UUID
) -> list[dict[str, str]]:
    """The fixture Product subjects in occurrence-ID order, without the
    `reason` key of the shared helper."""
    return [
        {k: v for k, v in subject.items() if k != "reason"}
        for subject in await subjects(db, ticket_id)
    ]


async def _converge(
    db: AsyncSession, ticket: Ticket
) -> ManualZoneExitEligibilityResult:
    """Lock the Ticket `FOR UPDATE` (the exit workflow's lock) and call the
    boundary with the fixed `EVAL`."""
    locked = await lock_ticket(db, ticket)
    return await converge_manual_zone_exit_eligibility(
        db, ticket=locked, evaluation_date=EVAL
    )


async def _set_default_version(db: AsyncSession, version: str) -> None:
    await db.execute(
        update(SystemSetting)
        .where(SystemSetting.key == "default_cvss_version")
        .values(value=version)
    )


def _updates(recorder: StatementRecorder, table: str) -> list[str]:
    """Every recorded `UPDATE` of exactly `table`."""
    prefix = f"UPDATE {table} SET"
    return [s for s in recorder.statements if s.lstrip().startswith(prefix)]


async def _cve_ticket(
    ticket_factory: TicketFactory, cve_with: CVEBuilder, *assessments: Assessment
) -> Ticket:
    cve = await cve_with(*assessments, severity=Severity.HIGH)
    return await ticket_factory(status=TicketStatus.ANALYSIS.value, cve_id=cve.id)


# ---------------------------------------------------------------------------
# Convergence from current inputs (package-model.md, Axis 2: Eligibility)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestCurrentInputs:
    async def test_suse_default_version_score_against_threshold_and_lifecycle(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_with: CVEBuilder,
        tree: TreeBuilder,
    ) -> None:
        """Rules 2-5 with a SUSE 3.1 score of 7.5. An external-provider
        9.8 at the default version never participates: it would make the
        7.6-threshold Product eligible."""
        ticket = await _cve_ticket(
            ticket_factory,
            cve_with,
            Assessment("7.5"),
            Assessment("9.8", provider="Fictional Provider"),
        )
        await tree(
            ticket,
            products=(
                Prod(eligible=True, threshold=Decimal("7.6")),  # below -> false
                Prod(eligible=False, threshold=Decimal("7.5")),  # equal -> true
                Prod(eligible=False, threshold=None),  # implicit 0.0 -> true
                Prod(eligible=True, threshold=Decimal("7.0")),  # unchanged
                Prod(eligible=True, reactive=True),  # Reactive Support -> false
            ),
        )

        result = await _converge(db_session, ticket)

        assert result == _result(5, 0, 4)
        assert await eligibility(db_session, ticket.id) == [
            (False, False),
            (True, False),
            (True, False),
            (True, False),
            (False, False),
        ]
        detail = await _reactivation_subjects(db_session, ticket.id)
        assert await ticket_events(db_session, ticket) == [
            _reactivation(detail[0], True, False),
            _reactivation(detail[1], False, True),
            _reactivation(detail[2], False, True),
            _reactivation(detail[4], True, False),
        ]

    @pytest.mark.parametrize("case", ["cve-less", "no-suse-default-version"])
    async def test_fallback_score_is_ten(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_with: CVEBuilder,
        tree: TreeBuilder,
        case: str,
    ) -> None:
        """cvss-scoring.md, Eligibility Score Resolution: without a SUSE
        assessment at the default version the score is 10.0, including for
        a Ticket without a CVE. A SUSE 4.0 and an external 3.1 assessment
        of 2.0 would each keep the Product ineligible."""
        if case == "cve-less":
            ticket = await cveless(ticket_factory)
        else:
            ticket = await _cve_ticket(
                ticket_factory,
                cve_with,
                Assessment("2.0", version="4.0"),
                Assessment("2.0", provider="Fictional Provider"),
            )
        await tree(ticket, products=(Prod(eligible=False, threshold=Decimal("9.9")),))

        result = await _converge(db_session, ticket)

        assert result == _result(1, 0, 1)
        assert await eligibility(db_session, ticket.id) == [(True, False)]

    @pytest.mark.parametrize(
        ("version", "expected"), [("3.1", False), ("4.0", True)], ids=["3.1", "4.0"]
    )
    async def test_current_default_version_setting_is_honoured(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_with: CVEBuilder,
        tree: TreeBuilder,
        version: str,
        expected: bool,
    ) -> None:
        """package-model.md, Axis 2 (Important): the version is the current
        persisted setting, never hardcoded. SUSE 3.1 scores 5.0 and SUSE
        4.0 scores 9.0 against a 7.0 threshold."""
        ticket = await _cve_ticket(
            ticket_factory,
            cve_with,
            Assessment("5.0", version="3.1"),
            Assessment("9.0", version="4.0"),
        )
        await tree(
            ticket, products=(Prod(eligible=not expected, threshold=Decimal("7.0")),)
        )
        await _set_default_version(db_session, version)

        result = await _converge(db_session, ticket)

        assert result == _result(1, 0, 1)
        assert await eligibility(db_session, ticket.id) == [(expected, False)]

    async def test_excluded_and_eol_are_processed_and_overrides_skipped(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        tree: TreeBuilder,
    ) -> None:
        """package-service.md, Synchronous manual-zone-exit eligibility
        convergence, step 2. A CVE-less Ticket (10.0) and implicit
        thresholds: every automatic record is eligible. The override would
        also become eligible, yet keeps its value without an event."""
        ticket = await cveless(ticket_factory)
        await tree(
            ticket,
            products=(
                Prod(eligible=False, excluded=True),
                Prod(eligible=False, eol=True),
                Prod(eligible=False, override=True),
            ),
        )
        await tree(ticket, products=(Prod(eligible=False),), track_excluded=True)
        await tree(ticket, products=(Prod(eligible=False),), package_excluded=True)

        result = await _converge(db_session, ticket)

        assert result == _result(5, 1, 4)
        assert await eligibility(db_session, ticket.id) == [
            (True, False),
            (True, False),
            (False, True),
            (True, False),
            (True, False),
        ]
        detail = await _reactivation_subjects(db_session, ticket.id)
        assert await ticket_events(db_session, ticket) == [
            _reactivation(detail[i], False, True) for i in (0, 1, 3, 4)
        ]


# ---------------------------------------------------------------------------
# Events (ticket-audit-log.md, Event Type Contract and detail contract)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestEvents:
    async def test_one_exact_system_event_per_change_in_occurrence_id_order(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        product_factory: Factory,
        ticket_package_factory: Factory,
        ticket_package_track_factory: Factory,
        ticket_package_product_factory: Factory,
    ) -> None:
        """Occurrences are inserted in descending UUID order, so the events
        follow `TicketPackageProduct.id`, not insertion. `product_name` is
        the catalog `display_name`, never the short `name`."""
        ticket = await cveless(ticket_factory)
        package = await ticket_package_factory(
            ticket_id=ticket.id, package_name="fictional-openssl"
        )
        track = await ticket_package_track_factory(
            ticket_package_id=package.id, reference="Fictional:Codestream:16:Update"
        )
        server: Product = await product_factory(
            name="fes",
            display_name="Fictional Enterprise Server 16 SP1",
            cpe="cpe:/o:fictional:fes:16:sp1",
            general_support_end_date=AFTER_EVAL,
        )
        steady: Product = await product_factory(general_support_end_date=AFTER_EVAL)
        micro: Product = await product_factory(
            name="fmicro",
            display_name="Fictional Micro 6.1",
            cpe="cpe:/o:fictional:fmicro:6.1",
            general_support_end_date=REACTIVE_GS_END,
            extended_support_end_date=REACTIVE_EXTENDED_END,
            reactive_support_end_date=REACTIVE_END,
        )
        low, mid, high = sorted(uuid.uuid4() for _ in range(3))
        for occurrence_id, product, eligible in (
            (high, server, False),  # 10.0 >= implicit 0.0 -> true
            (mid, steady, True),  # unchanged
            (low, micro, True),  # Reactive Support -> false
        ):
            await ticket_package_product_factory(
                id=occurrence_id,
                ticket_package_track_id=track.id,
                product_id=product.id,
                eligible=eligible,
            )

        result = await _converge(db_session, ticket)

        assert result == _result(3, 0, 2)
        assert await ticket_events(db_session, ticket) == [
            EventRow(
                "product_eligibility_changed",
                None,
                "true",
                "false",
                None,
                {
                    "track": "Fictional:Codestream:16:Update",
                    "package": "fictional-openssl",
                    "product_name": "Fictional Micro 6.1",
                    "product_cpe": "cpe:/o:fictional:fmicro:6.1",
                    "reason": "reactivation",
                },
            ),
            EventRow(
                "product_eligibility_changed",
                None,
                "false",
                "true",
                None,
                {
                    "track": "Fictional:Codestream:16:Update",
                    "package": "fictional-openssl",
                    "product_name": "Fictional Enterprise Server 16 SP1",
                    "product_cpe": "cpe:/o:fictional:fes:16:sp1",
                    "reason": "reactivation",
                },
            ),
        ]

    async def test_reinvocation_is_a_no_op(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        tree: TreeBuilder,
    ) -> None:
        ticket = await cveless(ticket_factory)
        await tree(
            ticket,
            products=(Prod(eligible=False), Prod(eligible=True)),
        )
        await _converge(db_session, ticket)
        events = await ticket_events(db_session, ticket)

        with StatementRecorder(db_session) as recorder:
            result = await _converge(db_session, ticket)

        assert result == _result(2, 0, 0)
        assert recorder.writes() == []
        assert await ticket_events(db_session, ticket) == events
        assert len(events) == 1


# ---------------------------------------------------------------------------
# Precondition and boundary (package-service.md, Q2/Q3/Q6)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestBoundary:
    @pytest.mark.parametrize(
        "status",
        [
            TicketStatus.IGNORED,
            TicketStatus.DUPLICATED,
            TicketStatus.NEW,
            TicketStatus.ANALYZED,
        ],
        ids=str,
    )
    async def test_ticket_not_at_the_analysis_floor_raises_before_any_statement(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        tree: TreeBuilder,
        status: TicketStatus,
    ) -> None:
        """A manual-zone Ticket is never passed directly: the exit workflow
        first sets the intermediate `Analysis` floor."""
        ticket = await cveless(ticket_factory, status=status)
        await tree(ticket, products=(Prod(eligible=False),))

        with (
            StatementRecorder(db_session) as recorder,
            pytest.raises(ValueError, match="Analysis"),
        ):
            await converge_manual_zone_exit_eligibility(
                db_session, ticket=ticket, evaluation_date=EVAL
            )

        assert recorder.statements == []
        assert await eligibility(db_session, ticket.id) == [(False, False)]
        assert await ticket_events(db_session, ticket) == []

    async def test_acquires_no_lock_and_never_writes_the_ticket_or_the_cve(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_with: CVEBuilder,
        tree: TreeBuilder,
        va_user: VAUser,
    ) -> None:
        """The Ticket's gates evaluate to `Resolved` (a canonical SUSE
        assessment, a resolved severity, a `NOT_AFFECTED` track) and its
        assignee is inactive: a reconciliation or sanitation would be
        observable. The boundary changes only the Product and its event."""
        assignee: User = await va_user(active=False)
        cve = await cve_with(Assessment("9.8"), severity=Severity.CRITICAL)
        ticket = await ticket_factory(
            status=TicketStatus.ANALYSIS.value, cve_id=cve.id, assignee_id=assignee.id
        )
        await tree(
            ticket,
            status=PackageStatus.NOT_AFFECTED,
            products=(Prod(eligible=False),),
        )
        locked = await lock_ticket(db_session, ticket)

        with StatementRecorder(db_session) as recorder:
            result = await converge_manual_zone_exit_eligibility(
                db_session, ticket=locked, evaluation_date=EVAL
            )

        assert result == _result(1, 0, 1)
        assert recorder.row_locks() == []
        assert _updates(recorder, "ticket") == []
        assert _updates(recorder, "cve") == []
        assert recorder.selects_from("ticket_audit_event") == []
        assert pending_ticket_convergence_effects(db_session) == ()
        row = (
            await db_session.execute(
                select(Ticket.status, Ticket.assignee_id, CVE.severity)
                .join(CVE, CVE.id == Ticket.cve_id)
                .where(Ticket.id == ticket.id)
            )
        ).one()
        assert tuple(row) == (TicketStatus.ANALYSIS, assignee.id, "Critical")
        assert [e.event_type for e in await ticket_events(db_session, ticket)] == [
            "product_eligibility_changed"
        ]

    async def test_audit_failure_propagates(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        tree: TreeBuilder,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Q6: the boundary never absorbs an audit failure; the caller's
        rollback then discards the eligibility update."""
        ticket = await cveless(ticket_factory)
        await tree(ticket, products=(Prod(eligible=False),))
        ticket_id = ticket.id
        original_log = TicketAuditLog.log_event

        async def failing_log(*args: Any, **kwargs: Any) -> None:
            if kwargs["event_type"] is TicketAuditEventType.PRODUCT_ELIGIBILITY_CHANGED:
                raise RuntimeError("injected audit failure")
            await original_log(*args, **kwargs)

        async with rollback_test_scope(db_session):
            monkeypatch.setattr(TicketAuditLog, "log_event", failing_log)
            locked = (
                await db_session.execute(
                    select(Ticket).where(Ticket.id == ticket_id).with_for_update()
                )
            ).scalar_one()
            with pytest.raises(RuntimeError, match="injected"):
                await converge_manual_zone_exit_eligibility(
                    db_session, ticket=locked, evaluation_date=EVAL
                )
        monkeypatch.undo()

        assert await eligibility(db_session, ticket_id) == [(False, False)]
        assert await ticket_events_by_id(db_session, ticket_id) == []
