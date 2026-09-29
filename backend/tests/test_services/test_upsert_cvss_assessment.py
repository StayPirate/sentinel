"""Service integration tests for `upsert_cvss_assessment()`
(backend/app/services/ticket_mutations.py).

Owning specifications:

- docs/features/tickets/ticket-mutations.md (Authorization responsibility;
  Gate-Relevant Mutation Operations; CVSS Vector Parsing; CVSS Mutation
  Authority and Result; CVSS Status Matrix, manual column;
  `upsert_cvss_assessment()`; Auto-Assignment Rule; Architectural Test
  Requirement: forward transitions, no-op, CVSS status matrix, eligibility
  through the shared helper, manual SUSE assignment, CVE severity
  ownership, authority and audit, SUSE gate independence, locked-current
  consumer accessibility, automatic priority; Service Exceptions).
- docs/features/tickets/cvss-scoring.md (Input Rules; Provider Identity and
  Authority; Assessment Persistence and Ticket Status; Direct Audit
  Summary; Serialization and Concurrent Outcomes; Workflow Gate; Required
  Tests > Persistence and API Tests, manual rows).
- docs/features/packages/package-model.md (Axis 2: Eligibility; Override
  Model, sole exception).
- docs/features/tickets/tickets.md (Gate Input and Reconciliation
  Ownership, CVSS row; Mutability Guard).
- docs/features/tickets/ticket-priority.md (Refresh Points, manual SUSE;
  Testing Requirement 3).
- docs/features/tickets/ticket-deadlines.md (Testing Requirement 3: the
  `created_at` start is immutable across a CVSS-derived severity change).
- docs/features/tickets/ticket-audit-log.md (Event Type Contract;
  No-Event Matrix rows "Effective CVSS assessment mutation" and
  "Ticketless CVE, CVSS ..."; Testing Requirements 1-6, 12, 15-18, 20,
  28).
- docs/features/platform/testing-strategy.md (Ticket Accessibility;
  Audit Trail Testing).

Rollback, the evaluation date, and independent-session races live in
test_upsert_cvss_assessment_atomicity.py. Expected values are transcribed
from the specifications, never computed with the module under test.
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any, cast

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import (
    CVSSVersion,
    PackageStatus,
    Role,
    Scope,
    Severity,
    TicketStatus,
)
from app.core.exceptions import CVENotFoundError, TicketNotMutableError
from app.models.cve import CVE
from app.models.cve_cvss_assessment import CVECVSSAssessment
from app.models.system_setting import SystemSetting
from app.models.ticket import Ticket
from app.models.ticket_access_grant import TicketAccessGrant
from app.models.ticket_audit_event import TicketAuditEvent
from app.models.ticket_package import TicketPackage
from app.models.ticket_package_maintainer import TicketPackageMaintainer
from app.services.ticket_convergence_registry import (
    TicketConvergenceEffect,
    pending_ticket_convergence_effects,
)
from app.services.ticket_mutations import (
    CVSSAssessmentAction,
    CVSSMutationCaller,
    CVSSPropagation,
    InvalidCVSSVectorError,
    ProductPropagationSummary,
    upsert_cvss_assessment,
)
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
from tests.support.suse_cvss import (
    V20_CRITICAL,
    V30_CRITICAL,
    V31_CRITICAL,
    V31_CRITICAL_10,
    V31_CRITICAL_REORDERED,
    V31_HIGH,
    V31_MEDIUM,
    V31_NONE,
    V40_CRITICAL,
    Vector,
    assignment_event,
    cvss_event,
    persisted_assessments,
    unit,
    upsert,
)
from tests.support.ticket_mutations import (
    EVAL,
    Prod,
    StatementRecorder,
    TicketFactory,
    TreeBuilder,
    VAUser,
    status_event,
    ticket_events,
    unassigned_event,
)

pytest_plugins = ["tests.support.ticket_mutation_fixtures"]
"""Provides the shared `va_user` and `tree` fixtures."""

Factory = Callable[..., Awaitable[Any]]

CREATED_AT = datetime(2026, 3, 10, 14, 37, 21, 123456, tzinfo=UTC)
"""A fixed Ticket start with a non-midnight time of day."""

GATE_ZONE = [TicketStatus.ANALYSIS, TicketStatus.ANALYZED, TicketStatus.RESOLVED]


@pytest.fixture
async def default_setting(system_setting_factory: Factory) -> SystemSetting:
    """The persisted `default_cvss_version` (the test schema has none)."""
    setting: SystemSetting = await system_setting_factory(
        key="default_cvss_version", value="3.1"
    )
    return setting


@pytest.fixture
def cve_of(
    cve_factory: Factory, cve_cvss_assessment_factory: Factory
) -> Callable[..., Awaitable[CVE]]:
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


CVEOf = Callable[..., Awaitable[CVE]]


async def _total_events(db: AsyncSession) -> int:
    return (
        await db.execute(select(func.count()).select_from(TicketAuditEvent))
    ).scalar_one()


# ---------------------------------------------------------------------------
# CVSS status matrix, manual column
# ---------------------------------------------------------------------------


@pytest.mark.integration
@pytest.mark.usefixtures("default_setting")
class TestStatusMatrix:
    async def test_ticketless_cve_maintains_cve_state_without_any_ticket_event(
        self, db_session: AsyncSession, cve_of: CVEOf, va_user: VAUser
    ) -> None:
        actor = await va_user()
        cve = await cve_of()

        created = await upsert(db_session, cve.id, V31_MEDIUM.canonical, actor)
        updated = await upsert(db_session, cve.id, V31_CRITICAL.canonical, actor)

        assert (created.action, updated.action) == (
            CVSSAssessmentAction.CREATED,
            CVSSAssessmentAction.UPDATED,
        )
        for result in (created, updated):
            assert result.propagation is CVSSPropagation.NOT_APPLICABLE
            assert result.products == ProductPropagationSummary()
            assert (result.assigned, result.reconciled) == (False, False)
            assert result.severity_changed is True
        assert await cve_severity(db_session, cve.id) == "Critical"
        assert await persisted_assessments(db_session, cve.id) == [
            unit("SUSE", V31_CRITICAL)
        ]
        assert await _total_events(db_session) == 0

    @pytest.mark.parametrize("status", [TicketStatus.NEW, *GATE_ZONE])
    async def test_every_active_status_propagates_immediately(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_of: CVEOf,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
        status: TicketStatus,
    ) -> None:
        """An already-assigned Ticket isolates the propagation from
        assignment: the direct and derived events are created in every
        active status and at most one reconciliation runs, only in the
        gate zone."""
        actor = await va_user()
        owner = await va_user()
        cve = await cve_of(severity=None)
        ticket = await ticket_factory(
            status=status.value, cve_id=cve.id, assignee_id=owner.id
        )
        reconcile = CallCounter(monkeypatch, "reconcile_ticket_status")

        result = await upsert(db_session, cve.id, V31_HIGH.canonical, actor)

        assert result.action is CVSSAssessmentAction.CREATED
        assert result.propagation is CVSSPropagation.IMMEDIATE
        assert result.severity_resolution == severity_resolution("8.1", Severity.HIGH)
        assert result.eligibility_resolution == suse_eligibility("8.1")
        assert len(reconcile.calls) == (0 if status is TicketStatus.NEW else 1)
        assert result.reconciled is (status is not TicketStatus.NEW)
        events = await ticket_events(db_session, ticket)
        assert events[:3] == [
            cvss_event(actor, None, V31_HIGH),
            severity_event(None, "High"),
            priority_event(None, "P3"),
        ]
        # Without a package tree every gate-zone Ticket evaluates to the
        # `Analysis` floor.
        final = (
            [status_event(status.value, TicketStatus.ANALYSIS.value)]
            if status in (TicketStatus.ANALYZED, TicketStatus.RESOLVED)
            else []
        )
        assert events[3:] == final

    async def test_resolved_regression_is_ordinary_and_registers_one_effect(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_of: CVEOf,
        tree: TreeBuilder,
        va_user: VAUser,
    ) -> None:
        """`Resolved` is part of the gate zone: the newly eligible Product
        makes the AFFECTED track incomplete again."""
        actor = await va_user()
        cve = await cve_of(("SUSE", V31_MEDIUM), severity=Severity.MEDIUM)
        ticket = await ticket_factory(
            status=TicketStatus.RESOLVED.value,
            cve_id=cve.id,
            assignee_id=actor.id,
            priority_auto="P4",
        )
        await tree(
            ticket,
            status=PackageStatus.AFFECTED,
            products=(Prod(eligible=False, threshold=Decimal("7.0")),),
        )

        result = await upsert(db_session, cve.id, V31_CRITICAL.canonical, actor)

        assert result.action is CVSSAssessmentAction.UPDATED
        assert result.propagation is CVSSPropagation.IMMEDIATE
        assert result.products == ProductPropagationSummary(1, 0, 1)
        assert result.reconciled is True
        assert await ticket_state(db_session, ticket.id) == (
            TicketStatus.ANALYZED,
            actor.id,
            "P2",
            None,
            None,
        )
        detail = await subjects(db_session, ticket.id)
        assert await ticket_events(db_session, ticket) == [
            cvss_event(actor, V31_MEDIUM, V31_CRITICAL),
            severity_event("Medium", "Critical"),
            product_event(detail[0], False, True),
            priority_event("P4", "P2"),
            status_event(TicketStatus.RESOLVED.value, TicketStatus.ANALYZED.value),
        ]
        assert pending_ticket_convergence_effects(db_session) == (
            TicketConvergenceEffect(ticket.id),
        )

    @pytest.mark.parametrize("status", [TicketStatus.IGNORED, TicketStatus.DUPLICATED])
    @pytest.mark.parametrize(
        "vector",
        [
            pytest.param(V31_CRITICAL.canonical, id="effective"),
            pytest.param(V31_MEDIUM.canonical, id="same-as-persisted"),
        ],
    )
    async def test_manual_zone_rejects_with_zero_effect(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_of: CVEOf,
        tree: TreeBuilder,
        va_user: VAUser,
        status: TicketStatus,
        vector: str,
    ) -> None:
        actor = await va_user()
        cve = await cve_of(("SUSE", V31_MEDIUM), severity=Severity.MEDIUM)
        ticket = await ticket_factory(
            status=status.value, cve_id=cve.id, priority_auto="P4"
        )
        await tree(ticket, products=(Prod(eligible=False, threshold=Decimal("7.0")),))

        with (
            StatementRecorder(db_session) as recorder,
            pytest.raises(TicketNotMutableError),
        ):
            await upsert(db_session, cve.id, vector, actor)

        assert recorder.writes() == []
        assert await persisted_assessments(db_session, cve.id) == [
            unit("SUSE", V31_MEDIUM)
        ]
        assert await cve_severity(db_session, cve.id) == "Medium"
        assert await eligibility(db_session, ticket.id) == [(False, False)]
        assert await ticket_state(db_session, ticket.id) == (
            status,
            None,
            "P4",
            None,
            None,
        )
        assert await ticket_events(db_session, ticket) == []
        assert pending_ticket_convergence_effects(db_session) == ()


# ---------------------------------------------------------------------------
# Unassigned `New` with an ineligible actor (upsert step 13)
# ---------------------------------------------------------------------------


@pytest.mark.integration
@pytest.mark.usefixtures("default_setting")
class TestUnassignedNewWithIneligibleActor:
    @pytest.mark.parametrize(
        ("active", "roles"),
        [
            pytest.param(False, (Role.VULNERABILITY_ANALYST,), id="inactive-va"),
        ],
    )
    async def test_applies_the_chain_without_assignment_or_reconciliation(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_of: CVEOf,
        tree: TreeBuilder,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
        active: bool,
        roles: tuple[Role, ...],
    ) -> None:
        actor = await va_user(active=active, roles=roles)
        cve = await cve_of()
        ticket = await ticket_factory(status=TicketStatus.NEW.value, cve_id=cve.id)
        # A gate-satisfying tree: reconciliation would move the Ticket if it
        # ran.
        await tree(
            ticket,
            status=PackageStatus.NOT_AFFECTED,
            products=(Prod(eligible=False, threshold=Decimal("7.0")),),
        )
        reconcile = CallCounter(monkeypatch, "reconcile_ticket_status")

        result = await upsert(db_session, cve.id, V31_CRITICAL.canonical, actor)

        assert (result.assigned, result.reconciled) == (False, False)
        assert reconcile.calls == []
        assert result.products == ProductPropagationSummary(1, 0, 1)
        assert await cve_severity(db_session, cve.id) == "Critical"
        assert await eligibility(db_session, ticket.id) == [(True, False)]
        assert await ticket_state(db_session, ticket.id) == (
            TicketStatus.NEW,
            None,
            "P2",
            None,
            None,
        )
        detail = await subjects(db_session, ticket.id)
        assert await ticket_events(db_session, ticket) == [
            cvss_event(actor, None, V31_CRITICAL),
            severity_event(None, "Critical"),
            product_event(detail[0], False, True),
            priority_event(None, "P2"),
        ]
        assert pending_ticket_convergence_effects(db_session) == ()


# ---------------------------------------------------------------------------
# Created, updated, unchanged
# ---------------------------------------------------------------------------


@pytest.mark.integration
@pytest.mark.usefixtures("default_setting")
class TestClassification:
    async def test_created_persists_the_canonical_unit(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_of: CVEOf,
        va_user: VAUser,
    ) -> None:
        actor = await va_user()
        cve = await cve_of(("Example Vendor", V31_MEDIUM), severity=Severity.MEDIUM)
        ticket = await ticket_factory(
            status=TicketStatus.ANALYSIS.value,
            cve_id=cve.id,
            assignee_id=actor.id,
            priority_auto="P4",
        )

        result = await upsert(
            db_session, cve.id, f"  {V31_CRITICAL_REORDERED}\t\n", actor
        )

        assert result.action is CVSSAssessmentAction.CREATED
        assessment = result.assessment
        assert assessment is not None
        assert (
            assessment.provider_name,
            assessment.cvss_version,
            assessment.score,
            assessment.severity,
            assessment.vector_string,
        ) == unit("SUSE", V31_CRITICAL)
        assert assessment.created_at is not None
        assert assessment.updated_at is not None
        assert result.severity_changed is True
        assert await persisted_assessments(db_session, cve.id) == [
            unit("Example Vendor", V31_MEDIUM),
            unit("SUSE", V31_CRITICAL),
        ]
        assert await ticket_events(db_session, ticket) == [
            cvss_event(actor, None, V31_CRITICAL),
            severity_event("Medium", "Critical"),
            priority_event("P4", "P2"),
        ]

    async def test_updated_keeps_the_row_and_records_the_true_old_value(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_of: CVEOf,
        va_user: VAUser,
    ) -> None:
        actor = await va_user()
        cve = await cve_of(("SUSE", V31_MEDIUM), severity=Severity.MEDIUM)
        original = (
            await db_session.execute(
                select(CVECVSSAssessment.id, CVECVSSAssessment.created_at).where(
                    CVECVSSAssessment.cve_id == cve.id
                )
            )
        ).one()
        ticket = await ticket_factory(
            status=TicketStatus.ANALYSIS.value,
            cve_id=cve.id,
            assignee_id=actor.id,
            priority_auto="P4",
        )

        result = await upsert(db_session, cve.id, V31_HIGH.canonical, actor)

        assert result.action is CVSSAssessmentAction.UPDATED
        assert result.assessment is not None
        assert (result.assessment.id, result.assessment.created_at) == tuple(original)
        assert await persisted_assessments(db_session, cve.id) == [
            unit("SUSE", V31_HIGH)
        ]
        assert await ticket_events(db_session, ticket) == [
            cvss_event(actor, V31_MEDIUM, V31_HIGH),
            severity_event("Medium", "High"),
            priority_event("P4", "P3"),
        ]

    @pytest.mark.parametrize(
        "received",
        [
            pytest.param(V31_CRITICAL.canonical, id="identical"),
            pytest.param(V31_CRITICAL_REORDERED, id="metric-order"),
            pytest.param(f" \t{V31_CRITICAL.canonical}\n ", id="outer-whitespace"),
        ],
    )
    async def test_unchanged_has_no_effect_of_any_kind(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_of: CVEOf,
        tree: TreeBuilder,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
        received: str,
    ) -> None:
        """Stale `CVE.severity`, Product, and priority values and an
        unassigned `New` Ticket with a VA actor prove that no severity
        write, propagation, refresh, assignment, or reconciliation runs."""
        actor = await va_user()
        cve = await cve_of(("SUSE", V31_CRITICAL), severity=Severity.LOW)
        ticket = await ticket_factory(
            status=TicketStatus.NEW.value, cve_id=cve.id, priority_auto="P4"
        )
        await tree(ticket, products=(Prod(eligible=False),))
        counters = [
            CallCounter(monkeypatch, name)
            for name in (
                "auto_assign_actor",
                "refresh_priority_auto",
                "reconcile_ticket_status",
                "_propagate_automatic_product_eligibility",
            )
        ]

        with StatementRecorder(db_session) as recorder:
            result = await upsert(db_session, cve.id, received, actor)

        assert result.action is CVSSAssessmentAction.UNCHANGED
        assert result.propagation is CVSSPropagation.NONE
        assert result.severity_changed is False
        assert result.severity_resolution == severity_resolution(
            "9.8", Severity.CRITICAL
        )
        assert result.eligibility_resolution == suse_eligibility("9.8")
        assert result.products == ProductPropagationSummary()
        assert (result.assigned, result.reconciled) == (False, False)
        assert [c.calls for c in counters] == [[], [], [], []]
        assert recorder.writes() == []
        assert await cve_severity(db_session, cve.id) == "Low"
        assert await eligibility(db_session, ticket.id) == [(False, False)]
        assert await ticket_state(db_session, ticket.id) == (
            TicketStatus.NEW,
            None,
            "P4",
            None,
            None,
        )
        assert await ticket_events(db_session, ticket) == []

    async def test_effective_update_without_a_gate_input_change_does_not_reconcile(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_of: CVEOf,
        tree: TreeBuilder,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Same unified severity, no Product change, and SUSE already
        present: only the direct event."""
        actor = await va_user()
        cve = await cve_of(("SUSE", V31_CRITICAL), severity=Severity.CRITICAL)
        ticket = await ticket_factory(
            status=TicketStatus.ANALYSIS.value,
            cve_id=cve.id,
            assignee_id=actor.id,
            priority_auto="P2",
        )
        await tree(ticket, status=PackageStatus.ANALYSIS)
        reconcile = CallCounter(monkeypatch, "reconcile_ticket_status")

        result = await upsert(db_session, cve.id, V31_CRITICAL_10.canonical, actor)

        assert result.action is CVSSAssessmentAction.UPDATED
        assert (result.severity_changed, result.reconciled) == (False, False)
        assert reconcile.calls == []
        assert await ticket_events(db_session, ticket) == [
            cvss_event(actor, V31_CRITICAL, V31_CRITICAL_10)
        ]

    async def test_effective_update_with_unchanged_severity_still_propagates(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_of: CVEOf,
        tree: TreeBuilder,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The unified severity stays `Critical`, but the eligibility score
        crosses a `10.0` threshold: the Product change reconciles once."""
        actor = await va_user()
        cve = await cve_of(("SUSE", V31_CRITICAL), severity=Severity.CRITICAL)
        ticket = await ticket_factory(
            status=TicketStatus.ANALYSIS.value,
            cve_id=cve.id,
            assignee_id=actor.id,
            priority_auto="P2",
        )
        await tree(
            ticket,
            status=PackageStatus.AFFECTED,
            products=(Prod(eligible=False, threshold=Decimal("10.0")),),
        )
        reconcile = CallCounter(monkeypatch, "reconcile_ticket_status")

        result = await upsert(db_session, cve.id, V31_CRITICAL_10.canonical, actor)

        assert result.severity_changed is False
        assert reconcile.calls == [{"evaluation_date": EVAL}]
        detail = await subjects(db_session, ticket.id)
        assert await ticket_events(db_session, ticket) == [
            cvss_event(actor, V31_CRITICAL, V31_CRITICAL_10),
            product_event(detail[0], False, True),
            status_event(TicketStatus.ANALYSIS.value, TicketStatus.ANALYZED.value),
        ]

    async def test_score_zero_is_unified_none_not_null(
        self, db_session: AsyncSession, cve_of: CVEOf, va_user: VAUser
    ) -> None:
        actor = await va_user()
        cve = await cve_of()

        await upsert(db_session, cve.id, V31_NONE.canonical, actor)

        assert await cve_severity(db_session, cve.id) == "None"

    async def test_never_commits(
        self,
        db_session: AsyncSession,
        cve_of: CVEOf,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        actor = await va_user()
        cve = await cve_of()

        async def forbidden() -> None:
            raise AssertionError("upsert_cvss_assessment() must not commit")

        monkeypatch.setattr(db_session, "commit", forbidden)
        monkeypatch.setattr(db_session, "rollback", forbidden)

        await upsert(db_session, cve.id, V31_CRITICAL.canonical, actor)


# ---------------------------------------------------------------------------
# Authority and input-only validation
# ---------------------------------------------------------------------------


@pytest.mark.integration
@pytest.mark.usefixtures("default_setting")
class TestAuthority:
    @pytest.mark.parametrize("provider", ["SUSE", "suse", " Suse ", "\tsUsE\n"])
    async def test_reserved_variants_are_stored_as_canonical_suse(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_of: CVEOf,
        va_user: VAUser,
        provider: str,
    ) -> None:
        actor = await va_user()
        cve = await cve_of()
        ticket = await ticket_factory(
            status=TicketStatus.ANALYSIS.value, cve_id=cve.id, assignee_id=actor.id
        )

        result = await upsert(
            db_session, cve.id, V31_MEDIUM.canonical, actor, provider=provider
        )

        assert result.assessment is not None
        assert result.assessment.provider_name == "SUSE"
        assert await persisted_assessments(db_session, cve.id) == [
            unit("SUSE", V31_MEDIUM)
        ]
        assert (await ticket_events(db_session, ticket))[0] == cvss_event(
            actor, None, V31_MEDIUM
        )

    @pytest.mark.parametrize(
        ("violation", "message"),
        [
            ("external-caller", "requires MANUAL_SUSE authority"),
            ("missing-actor", "requires an acting user"),
            ("external-provider", "only mutate the SUSE provider"),
            ("other-caller", "must identify the acting user"),
        ],
    )
    async def test_contract_violation_raises_before_any_statement(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_of: CVEOf,
        va_user: VAUser,
        violation: str,
        message: str,
    ) -> None:
        actor = await va_user()
        other = await va_user()
        cve = await cve_of()
        ticket = await ticket_factory(status=TicketStatus.NEW.value, cve_id=cve.id)
        kwargs: dict[str, Any] = {
            "cve_id": cve.id,
            "provider": "SUSE",
            "vector_string": V31_CRITICAL.canonical,
            "caller": CVSSMutationCaller.MANUAL_SUSE,
            "acting_user_id": actor.id,
            "ticket_caller": TicketCaller.authenticated(actor.id, Scope.ALL),
            "evaluation_date": EVAL,
        }
        if violation == "external-caller":
            kwargs["caller"] = cast(CVSSMutationCaller, "external")
        elif violation == "missing-actor":
            kwargs["acting_user_id"] = None
        elif violation == "external-provider":
            kwargs["provider"] = "Example Vendor"
        else:
            kwargs["ticket_caller"] = TicketCaller.authenticated(other.id, Scope.ALL)

        with (
            StatementRecorder(db_session) as recorder,
            pytest.raises(ValueError, match=message),
        ):
            await upsert_cvss_assessment(db_session, **kwargs)

        assert recorder.statements == []
        assert await persisted_assessments(db_session, cve.id) == []
        assert await ticket_events(db_session, ticket) == []

    @pytest.mark.parametrize(
        "vector",
        [
            pytest.param("", id="empty"),
        ],
    )
    async def test_invalid_vector_raises_before_any_statement(
        self, db_session: AsyncSession, cve_of: CVEOf, va_user: VAUser, vector: str
    ) -> None:
        actor = await va_user()
        cve = await cve_of()

        with (
            StatementRecorder(db_session) as recorder,
            pytest.raises(InvalidCVSSVectorError),
        ):
            await upsert(db_session, cve.id, vector, actor)

        assert recorder.statements == []

    async def test_missing_cve_is_not_found(
        self, db_session: AsyncSession, va_user: VAUser
    ) -> None:
        actor = await va_user()

        with (
            StatementRecorder(db_session) as recorder,
            pytest.raises(CVENotFoundError),
        ):
            await upsert(db_session, uuid.uuid7(), V31_CRITICAL.canonical, actor)

        assert recorder.writes() == []


# ---------------------------------------------------------------------------
# Manual SUSE auto-assignment and the exact event order
# ---------------------------------------------------------------------------


@pytest.mark.integration
@pytest.mark.usefixtures("default_setting")
class TestAssignment:
    async def test_new_ticket_assigns_promotes_then_records_the_cvss_chain(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_of: CVEOf,
        tree: TreeBuilder,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        actor = await va_user()
        cve = await cve_of()
        ticket = await ticket_factory(status=TicketStatus.NEW.value, cve_id=cve.id)
        await tree(ticket, status=PackageStatus.AFFECTED)
        reconcile = CallCounter(monkeypatch, "reconcile_ticket_status")

        result = await upsert(db_session, cve.id, V31_CRITICAL.canonical, actor)

        assert (result.assigned, result.reconciled) == (True, True)
        assert reconcile.calls == [{"evaluation_date": EVAL}]
        assert await ticket_state(db_session, ticket.id) == (
            TicketStatus.ANALYZED,
            actor.id,
            "P2",
            None,
            None,
        )
        assert await ticket_events(db_session, ticket) == [
            assignment_event(actor),
            status_event(TicketStatus.NEW.value, TicketStatus.ANALYSIS.value),
            cvss_event(actor, None, V31_CRITICAL),
            severity_event(None, "Critical"),
            priority_event(None, "P2"),
            status_event(TicketStatus.ANALYSIS.value, TicketStatus.ANALYZED.value),
        ]
        assert pending_ticket_convergence_effects(db_session) == ()

    async def test_promotion_alone_reconciles_the_new_gate_zone_ticket(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_of: CVEOf,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """An effective update with no gate-input change still reconciles
        once because the assignment moved `New` into `Analysis`."""
        actor = await va_user()
        cve = await cve_of(("SUSE", V31_CRITICAL), severity=Severity.CRITICAL)
        ticket = await ticket_factory(
            status=TicketStatus.NEW.value, cve_id=cve.id, priority_auto="P2"
        )
        reconcile = CallCounter(monkeypatch, "reconcile_ticket_status")

        await upsert(db_session, cve.id, V31_CRITICAL_10.canonical, actor)

        assert reconcile.calls == [{"evaluation_date": EVAL}]
        assert await ticket_events(db_session, ticket) == [
            assignment_event(actor),
            status_event(TicketStatus.NEW.value, TicketStatus.ANALYSIS.value),
            cvss_event(actor, V31_CRITICAL, V31_CRITICAL_10),
        ]

    async def test_unassigned_gate_zone_ticket_is_assigned_without_promotion(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_of: CVEOf,
        va_user: VAUser,
    ) -> None:
        actor = await va_user()
        cve = await cve_of()
        ticket = await ticket_factory(status=TicketStatus.ANALYSIS.value, cve_id=cve.id)

        await upsert(db_session, cve.id, V31_MEDIUM.canonical, actor)

        assert await ticket_events(db_session, ticket) == [
            assignment_event(actor),
            cvss_event(actor, None, V31_MEDIUM),
            severity_event(None, "Medium"),
            priority_event(None, "P4"),
        ]

    async def test_assigned_ticket_keeps_its_assignee(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_of: CVEOf,
        va_user: VAUser,
    ) -> None:
        actor = await va_user()
        owner = await va_user()
        cve = await cve_of()
        ticket = await ticket_factory(
            status=TicketStatus.ANALYSIS.value, cve_id=cve.id, assignee_id=owner.id
        )

        result = await upsert(db_session, cve.id, V31_MEDIUM.canonical, actor)

        assert result.assigned is False
        assert (await ticket_state(db_session, ticket.id))[1] == owner.id

    @pytest.mark.parametrize(
        ("active", "roles", "reason"),
        [
            pytest.param(
                False, (Role.VULNERABILITY_ANALYST,), "inactive assignee", id="inactive"
            ),
        ],
    )
    async def test_sanitation_follows_priority_and_precedes_the_final_status(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_of: CVEOf,
        tree: TreeBuilder,
        va_user: VAUser,
        active: bool,
        roles: tuple[Role, ...],
        reason: str,
    ) -> None:
        actor = await va_user()
        assignee = await va_user(active=active, roles=roles)
        cve = await cve_of()
        ticket = await ticket_factory(
            status=TicketStatus.ANALYSIS.value, cve_id=cve.id, assignee_id=assignee.id
        )
        await tree(ticket, status=PackageStatus.AFFECTED)

        await upsert(db_session, cve.id, V31_CRITICAL.canonical, actor)

        assert await ticket_events(db_session, ticket) == [
            cvss_event(actor, None, V31_CRITICAL),
            severity_event(None, "Critical"),
            priority_event(None, "P2"),
            unassigned_event(assignee.username, reason),
            status_event(TicketStatus.ANALYSIS.value, TicketStatus.ANALYZED.value),
        ]


# ---------------------------------------------------------------------------
# SUSE workflow gate
# ---------------------------------------------------------------------------


@pytest.mark.integration
@pytest.mark.usefixtures("default_setting")
class TestWorkflowGate:
    async def test_first_suse_assessment_alone_promotes(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_of: CVEOf,
        tree: TreeBuilder,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """An external assessment already resolves `Critical` and the
        Product is eligible under the fallback: only canonical-SUSE
        presence changes."""
        actor = await va_user()
        cve = await cve_of(("NVD", V31_CRITICAL), severity=Severity.CRITICAL)
        ticket = await ticket_factory(
            status=TicketStatus.ANALYSIS.value,
            cve_id=cve.id,
            assignee_id=actor.id,
            priority_auto="P2",
        )
        await tree(ticket, status=PackageStatus.AFFECTED)
        reconcile = CallCounter(monkeypatch, "reconcile_ticket_status")

        result = await upsert(db_session, cve.id, V31_CRITICAL.canonical, actor)

        assert (result.severity_changed, result.products.changed) == (False, 0)
        assert reconcile.calls == [{"evaluation_date": EVAL}]
        assert await ticket_events(db_session, ticket) == [
            cvss_event(actor, None, V31_CRITICAL),
            status_event(TicketStatus.ANALYSIS.value, TicketStatus.ANALYZED.value),
        ]

    async def test_another_suse_assessment_leaves_the_predicate_unchanged(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_of: CVEOf,
        tree: TreeBuilder,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        actor = await va_user()
        cve = await cve_of(("SUSE", V31_CRITICAL), severity=Severity.CRITICAL)
        ticket = await ticket_factory(
            status=TicketStatus.ANALYZED.value,
            cve_id=cve.id,
            assignee_id=actor.id,
            priority_auto="P2",
        )
        await tree(ticket, status=PackageStatus.AFFECTED)
        reconcile = CallCounter(monkeypatch, "reconcile_ticket_status")

        result = await upsert(db_session, cve.id, V40_CRITICAL.canonical, actor)

        assert result.action is CVSSAssessmentAction.CREATED
        assert reconcile.calls == []
        assert await ticket_events(db_session, ticket) == [
            cvss_event(actor, None, V40_CRITICAL)
        ]

    @pytest.mark.parametrize(
        ("vector", "version"),
        [
            pytest.param(V20_CRITICAL, CVSSVersion.V2_0, id="v2.0"),
            pytest.param(V30_CRITICAL, CVSSVersion.V3_0, id="v3.0"),
            pytest.param(V31_CRITICAL, CVSSVersion.V3_1, id="v3.1"),
        ],
    )
    async def test_default_v40_with_only_an_older_suse_version(
        self,
        db_session: AsyncSession,
        default_setting: SystemSetting,
        ticket_factory: TicketFactory,
        cve_of: CVEOf,
        tree: TreeBuilder,
        va_user: VAUser,
        vector: Vector,
        version: CVSSVersion,
    ) -> None:
        """Severity follows the full cascade, eligibility uses the 10.0
        fallback (the `9.9` threshold is met only by it), and the SUSE gate
        is satisfied."""
        default_setting.value = "4.0"
        await db_session.flush()
        actor = await va_user()
        cve = await cve_of()
        ticket = await ticket_factory(
            status=TicketStatus.ANALYSIS.value, cve_id=cve.id, assignee_id=actor.id
        )
        await tree(
            ticket,
            status=PackageStatus.AFFECTED,
            products=(Prod(eligible=False, threshold=Decimal("9.9")),),
        )

        result = await upsert(db_session, cve.id, vector.canonical, actor)

        assert result.severity_resolution == severity_resolution(
            vector.score, Severity.CRITICAL, version=version
        )
        assert result.eligibility_resolution == FALLBACK
        assert await eligibility(db_session, ticket.id) == [(True, False)]
        assert (await ticket_state(db_session, ticket.id))[0] == TicketStatus.ANALYZED


# ---------------------------------------------------------------------------
# Immediate Product propagation through the shared helper
# ---------------------------------------------------------------------------


@pytest.mark.integration
@pytest.mark.usefixtures("default_setting")
class TestProductPropagation:
    async def test_changed_products_follow_severity_in_occurrence_order(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_of: CVEOf,
        tree: TreeBuilder,
        va_user: VAUser,
    ) -> None:
        actor = await va_user()
        cve = await cve_of(("SUSE", V31_MEDIUM), severity=Severity.MEDIUM)
        ticket = await ticket_factory(
            status=TicketStatus.ANALYSIS.value,
            cve_id=cve.id,
            assignee_id=actor.id,
            priority_auto="P4",
        )
        threshold = Decimal("7.0")
        await tree(
            ticket,
            status=PackageStatus.AFFECTED,
            products=(
                Prod(eligible=False, threshold=threshold),
                Prod(eligible=False, threshold=threshold, override=True),
                Prod(eligible=False, threshold=threshold, excluded=True),
            ),
        )

        result = await upsert(db_session, cve.id, V31_CRITICAL.canonical, actor)

        assert result.products == ProductPropagationSummary(3, 1, 2)
        assert await eligibility(db_session, ticket.id) == [
            (True, False),
            (False, True),
            (True, False),
        ]
        detail = await subjects(db_session, ticket.id)
        assert await ticket_events(db_session, ticket) == [
            cvss_event(actor, V31_MEDIUM, V31_CRITICAL),
            severity_event("Medium", "Critical"),
            product_event(detail[0], False, True),
            product_event(detail[2], False, True),
            priority_event("P4", "P2"),
            status_event(TicketStatus.ANALYSIS.value, TicketStatus.ANALYZED.value),
        ]

    async def test_lower_score_makes_a_product_ineligible(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_of: CVEOf,
        tree: TreeBuilder,
        va_user: VAUser,
    ) -> None:
        actor = await va_user()
        cve = await cve_of(("SUSE", V31_CRITICAL), severity=Severity.CRITICAL)
        ticket = await ticket_factory(
            status=TicketStatus.ANALYZED.value,
            cve_id=cve.id,
            assignee_id=actor.id,
            priority_auto="P2",
        )
        await tree(
            ticket,
            status=PackageStatus.AFFECTED,
            products=(Prod(eligible=True, threshold=Decimal("7.0")),),
        )

        await upsert(db_session, cve.id, V31_MEDIUM.canonical, actor)

        detail = await subjects(db_session, ticket.id)
        assert await ticket_events(db_session, ticket) == [
            cvss_event(actor, V31_CRITICAL, V31_MEDIUM),
            severity_event("Critical", "Medium"),
            product_event(detail[0], True, False),
            priority_event("P2", "P4"),
            status_event(TicketStatus.ANALYZED.value, TicketStatus.RESOLVED.value),
        ]


# ---------------------------------------------------------------------------
# Deadline start
# ---------------------------------------------------------------------------


@pytest.mark.integration
@pytest.mark.usefixtures("default_setting")
class TestDerivedTicketFields:
    async def test_created_at_is_unchanged_by_a_cvss_derived_severity_change(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_of: CVEOf,
        va_user: VAUser,
    ) -> None:
        actor = await va_user()
        cve = await cve_of(("SUSE", V31_MEDIUM), severity=Severity.MEDIUM)
        ticket = await ticket_factory(
            status=TicketStatus.ANALYSIS.value,
            cve_id=cve.id,
            assignee_id=actor.id,
            created_at=CREATED_AT,
        )

        result = await upsert(db_session, cve.id, V31_CRITICAL.canonical, actor)

        assert result.severity_changed is True
        created_at = (
            await db_session.execute(
                select(Ticket.created_at).where(Ticket.id == ticket.id)
            )
        ).scalar_one()
        assert created_at == CREATED_AT


# ---------------------------------------------------------------------------
# Locked-current CVE accessibility (single session)
# ---------------------------------------------------------------------------


@pytest.mark.integration
@pytest.mark.usefixtures("default_setting")
class TestAccessibility:
    @pytest.mark.parametrize(
        ("status", "vector"),
        [
            pytest.param(TicketStatus.NEW, V31_CRITICAL, id="effective"),
            pytest.param(TicketStatus.IGNORED, V31_CRITICAL, id="before-operability"),
            pytest.param(TicketStatus.NEW, V31_MEDIUM, id="before-unchanged"),
        ],
    )
    @pytest.mark.parametrize(
        "roles",
        [
            pytest.param((Role.RESTRICTED_ANALYST,), id="restricted-analyst"),
            # A VA origin committed after the request resolved the caller's
            # `non_confidential` scope: any assignment before the denial
            # would be observable.
            pytest.param((Role.VULNERABILITY_ANALYST,), id="va-after-resolution"),
        ],
    )
    async def test_inaccessible_associated_ticket_is_cve_not_found(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_of: CVEOf,
        ticket_access_grant_factory: Callable[..., Awaitable[TicketAccessGrant]],
        ticket_package_factory: Callable[..., Awaitable[TicketPackage]],
        ticket_package_maintainer_factory: Callable[
            ..., Awaitable[TicketPackageMaintainer]
        ],
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
        status: TicketStatus,
        vector: Vector,
        roles: tuple[Role, ...],
    ) -> None:
        actor = await va_user(roles=roles)
        cve = await cve_of(("SUSE", V31_MEDIUM), severity=Severity.MEDIUM)
        ticket = await ticket_factory(
            status=status.value, cve_id=cve.id, is_confidential=True
        )
        # Non-qualifying paths: another user's grant and maintainership, and
        # the caller's maintainership of an excluded package.
        await ticket_access_grant_factory(ticket_id=ticket.id)
        await ticket_package_maintainer_factory(
            ticket_package_id=(await ticket_package_factory(ticket_id=ticket.id)).id
        )
        excluded = await ticket_package_factory(
            ticket_id=ticket.id, deleted_at=datetime.now(UTC)
        )
        await ticket_package_maintainer_factory(
            ticket_package_id=excluded.id, user_id=actor.id
        )
        assign = CallCounter(monkeypatch, "auto_assign_actor")
        reconcile = CallCounter(monkeypatch, "reconcile_ticket_status")

        with (
            StatementRecorder(db_session) as recorder,
            pytest.raises(CVENotFoundError),
        ):
            await upsert(
                db_session,
                cve.id,
                vector.canonical,
                actor,
                scope=Scope.NON_CONFIDENTIAL,
            )

        assert (assign.calls, reconcile.calls) == ([], [])
        assert recorder.writes() == []
        assert recorder.selects_from("system_setting") == []
        assert await persisted_assessments(db_session, cve.id) == [
            unit("SUSE", V31_MEDIUM)
        ]
        assert await cve_severity(db_session, cve.id) == "Medium"
        assert await ticket_events(db_session, ticket) == []
        assert pending_ticket_convergence_effects(db_session) == ()

    @pytest.mark.parametrize("path", ["grant", "maintainer"])
    async def test_visibility_path_allows_a_restricted_analyst(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_of: CVEOf,
        ticket_access_grant_factory: Callable[..., Awaitable[TicketAccessGrant]],
        ticket_package_factory: Callable[..., Awaitable[TicketPackage]],
        ticket_package_maintainer_factory: Callable[
            ..., Awaitable[TicketPackageMaintainer]
        ],
        va_user: VAUser,
        path: str,
    ) -> None:
        actor = await va_user(roles=(Role.RESTRICTED_ANALYST,))
        cve = await cve_of()
        ticket = await ticket_factory(
            status=TicketStatus.ANALYSIS.value, cve_id=cve.id, is_confidential=True
        )
        if path == "grant":
            await ticket_access_grant_factory(ticket_id=ticket.id, user_id=actor.id)
        else:
            package = await ticket_package_factory(ticket_id=ticket.id)
            await ticket_package_maintainer_factory(
                ticket_package_id=package.id, user_id=actor.id
            )

        result = await upsert(
            db_session,
            cve.id,
            V31_MEDIUM.canonical,
            actor,
            scope=Scope.NON_CONFIDENTIAL,
        )

        assert result.action is CVSSAssessmentAction.CREATED
        # A restricted analyst is not VA-eligible: no assignment.
        assert await ticket_events(db_session, ticket) == [
            cvss_event(actor, None, V31_MEDIUM),
            severity_event(None, "Medium"),
            priority_event(None, "P4"),
        ]

    async def test_ticketless_cve_is_accessible_to_every_scope(
        self, db_session: AsyncSession, cve_of: CVEOf, va_user: VAUser
    ) -> None:
        actor = await va_user(roles=())
        cve = await cve_of()

        result = await upsert(
            db_session,
            cve.id,
            V31_MEDIUM.canonical,
            actor,
            scope=Scope.NON_CONFIDENTIAL,
        )

        assert result.action is CVSSAssessmentAction.CREATED


# ---------------------------------------------------------------------------
# Lock order and the locked-current revalidation statement
# ---------------------------------------------------------------------------


@pytest.mark.integration
@pytest.mark.usefixtures("default_setting")
class TestLockOrder:
    async def test_user_then_cve_then_ticket_then_visibility_then_setting(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_of: CVEOf,
        ticket_access_grant_factory: Callable[..., Awaitable[TicketAccessGrant]],
        va_user: VAUser,
    ) -> None:
        actor = await va_user(roles=(Role.RESTRICTED_ANALYST,))
        cve = await cve_of()
        ticket = await ticket_factory(
            status=TicketStatus.ANALYSIS.value, cve_id=cve.id, is_confidential=True
        )
        await ticket_access_grant_factory(ticket_id=ticket.id, user_id=actor.id)

        with StatementRecorder(db_session) as recorder:
            await upsert(
                db_session,
                cve.id,
                V31_CRITICAL.canonical,
                actor,
                scope=Scope.NON_CONFIDENTIAL,
            )

        statements = recorder.statements

        def first(predicate: Callable[[str], bool]) -> int:
            return next(i for i, s in enumerate(statements) if predicate(s))

        user_share = first(lambda s: 'FROM "user"' in s and "FOR SHARE" in s)
        cve_lock = first(lambda s: "FROM cve " in s and "FOR UPDATE" in s)
        ticket_lock = first(lambda s: "FROM ticket " in s and "FOR UPDATE" in s)
        visibility = first(lambda s: "ticket_access_grant" in s)
        setting = first(lambda s: "FROM system_setting" in s)
        assessments = first(lambda s: "FROM cve_cvss_assessment" in s)
        assert user_share == 0
        assert user_share < cve_lock < ticket_lock < visibility < setting
        assert visibility < assessments
        assert "ticket_access_grant" not in statements[ticket_lock]
        assert len(recorder.row_locks()) == 3
        assert recorder.selects_from("ticket_audit_event") == []
