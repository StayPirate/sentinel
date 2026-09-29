"""Service integration tests for `delete_cvss_assessment()` and
`require_accepted_cvss_version()` (backend/app/services/ticket_mutations.py).

Owning specifications:

- docs/features/tickets/ticket-mutations.md (CVSS Mutation Authority and
  Result; CVSS Status Matrix, manual column; `delete_cvss_assessment()`
  steps 1-11; Auto-Assignment Rule; Architectural Test Requirement:
  backward transitions, no-op (`not_found`), CVSS status matrix, manual
  SUSE assignment, CVE severity ownership, authority and audit, SUSE gate
  independence, locked-current consumer accessibility, automatic priority;
  Service Exceptions: `CVSSAssessmentNotFoundError`).
- docs/features/tickets/cvss-scoring.md (Provider Identity and Authority;
  Assessment Persistence and Ticket Status; Direct Audit Summary;
  Serialization and Concurrent Outcomes; Workflow Gate; Delete SUSE CVSS
  Assessment; Required Tests > Persistence and API Tests, manual rows).
- docs/features/tickets/ticket-audit-log.md (Event Type Contract row
  `cvss_assessment_changed`: `new_value` NULL on removal; Canonical
  Mutation and No-Event Matrix; Cross-Event Ordering).
- docs/features/tickets/ticket-priority.md (Refresh Points, manual SUSE
  delete).
- docs/features/platform/testing-strategy.md (Ticket Accessibility;
  Audit Trail Testing).

Rollback, the evaluation date, and independent-session races live in
test_delete_cvss_assessment_atomicity.py. Expected values are transcribed
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
from app.services import ticket_mutations_errors
from app.services.cvss import SeverityResolution
from app.services.ticket_convergence_registry import (
    TicketConvergenceEffect,
    pending_ticket_convergence_effects,
)
from app.services.ticket_mutations import (
    CVSSAssessmentAction,
    CVSSAssessmentNotFoundError,
    CVSSMutationCaller,
    CVSSPropagation,
    ProductPropagationSummary,
    TicketMutationsError,
    delete_cvss_assessment,
    require_accepted_cvss_version,
)
from app.services.ticket_visibility import ANONYMOUS_CALLER, TicketCaller
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
    V31_HIGH,
    V31_MEDIUM,
    V31_NONE,
    V40_CRITICAL,
    Vector,
    assignment_event,
    cvss_delete_event,
    delete_assessment,
    persisted_assessments,
    unit,
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

ACCEPTED = [
    pytest.param("2.0", V20_CRITICAL, id="v2.0"),
    pytest.param("3.0", V30_CRITICAL, id="v3.0"),
    pytest.param("3.1", V31_CRITICAL, id="v3.1"),
    pytest.param("4.0", V40_CRITICAL, id="v4.0"),
]

UNACCEPTED_VERSIONS = [
    pytest.param("3", id="major-only"),
    pytest.param("3.10", id="extra-digit"),
    pytest.param(" 3.1", id="leading-space"),
    pytest.param("3.1 ", id="trailing-space"),
    pytest.param("3.1\n", id="trailing-newline"),
    pytest.param("v3.1", id="v-prefix"),
    pytest.param("", id="empty"),
    pytest.param("CVSS:3.1", id="vector-prefix"),
    pytest.param("5.0", id="future"),
    pytest.param("3,1", id="comma"),
    pytest.param("V3_1", id="enum-name"),
]


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
# `require_accepted_cvss_version()` (pure; delete step 1)
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestRequireAcceptedCVSSVersion:
    @pytest.mark.parametrize(
        ("received", "expected"),
        [
            ("2.0", CVSSVersion.V2_0),
            ("3.0", CVSSVersion.V3_0),
            ("3.1", CVSSVersion.V3_1),
            ("4.0", CVSSVersion.V4_0),
        ],
    )
    def test_accepted_version_returns_the_enum_member(
        self, received: str, expected: CVSSVersion
    ) -> None:
        assert require_accepted_cvss_version(received) is expected

    @pytest.mark.parametrize("received", UNACCEPTED_VERSIONS)
    def test_unaccepted_version_raises_the_static_not_found_error(
        self, received: str
    ) -> None:
        with pytest.raises(CVSSAssessmentNotFoundError) as excinfo:
            require_accepted_cvss_version(received)

        assert str(excinfo.value) == "CVSS assessment not found."

    def test_error_is_a_ticket_mutations_error_reexported_by_the_service(
        self,
    ) -> None:
        assert (
            CVSSAssessmentNotFoundError
            is ticket_mutations_errors.CVSSAssessmentNotFoundError
        )
        assert issubclass(CVSSAssessmentNotFoundError, TicketMutationsError)


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
        cve = await cve_of(
            ("SUSE", V31_MEDIUM), ("SUSE", V40_CRITICAL), severity=Severity.MEDIUM
        )

        first = await delete_assessment(db_session, cve.id, "3.1", actor)

        assert first.action is CVSSAssessmentAction.DELETED
        assert first.severity_resolution == severity_resolution(
            "9.3", Severity.CRITICAL, version=CVSSVersion.V4_0
        )
        assert first.eligibility_resolution == FALLBACK
        assert await cve_severity(db_session, cve.id) == "Critical"
        assert await persisted_assessments(db_session, cve.id) == [
            unit("SUSE", V40_CRITICAL)
        ]

        last = await delete_assessment(db_session, cve.id, "4.0", actor)

        assert last.action is CVSSAssessmentAction.DELETED
        assert last.severity_resolution is None
        assert last.eligibility_resolution == FALLBACK
        for result in (first, last):
            assert result.propagation is CVSSPropagation.NOT_APPLICABLE
            assert result.products == ProductPropagationSummary()
            assert (result.assigned, result.reconciled) == (False, False)
            assert result.severity_changed is True
            assert result.evaluation_date == EVAL
        assert await cve_severity(db_session, cve.id) is None
        assert await persisted_assessments(db_session, cve.id) == []
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
        gate zone. Deleting the only assessment resolves `NULL`."""
        actor = await va_user()
        owner = await va_user()
        cve = await cve_of(("SUSE", V31_HIGH), severity=Severity.HIGH)
        ticket = await ticket_factory(
            status=status.value,
            cve_id=cve.id,
            assignee_id=owner.id,
            priority_auto="P3",
        )
        reconcile = CallCounter(monkeypatch, "reconcile_ticket_status")

        result = await delete_assessment(db_session, cve.id, "3.1", actor)

        assert result.action is CVSSAssessmentAction.DELETED
        assert result.propagation is CVSSPropagation.IMMEDIATE
        assert result.severity_resolution is None
        assert result.severity_changed is True
        assert result.eligibility_resolution == FALLBACK
        assert len(reconcile.calls) == (0 if status is TicketStatus.NEW else 1)
        assert result.reconciled is (status is not TicketStatus.NEW)
        assert await cve_severity(db_session, cve.id) is None
        assert await persisted_assessments(db_session, cve.id) == []
        events = await ticket_events(db_session, ticket)
        assert events[:3] == [
            cvss_delete_event(actor, V31_HIGH),
            severity_event("High", None),
            priority_event("P3", None),
        ]
        # Without a package tree and with a NULL severity every gate-zone
        # Ticket evaluates to the `Analysis` floor.
        regressed = status in (TicketStatus.ANALYZED, TicketStatus.RESOLVED)
        final = (
            [status_event(status.value, TicketStatus.ANALYSIS.value)]
            if regressed
            else []
        )
        assert events[3:] == final
        assert pending_ticket_convergence_effects(db_session) == (
            (TicketConvergenceEffect(ticket.id),)
            if status is TicketStatus.RESOLVED
            else ()
        )

    @pytest.mark.parametrize("status", [TicketStatus.IGNORED, TicketStatus.DUPLICATED])
    @pytest.mark.parametrize(
        "version",
        [
            pytest.param("3.1", id="effective"),
            pytest.param("4.0", id="absent-version"),
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
        version: str,
    ) -> None:
        """The rejection precedes the `not_found` classification and every
        write; an unassigned Ticket and a VA actor prove no assignment."""
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
            await delete_assessment(db_session, cve.id, version, actor)

        assert recorder.writes() == []
        assert recorder.selects_from("cve_cvss_assessment") == []
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
# Deletion by natural key for every accepted version
# ---------------------------------------------------------------------------


@pytest.mark.integration
@pytest.mark.usefixtures("default_setting")
class TestAcceptedVersions:
    @pytest.mark.parametrize(("version", "vector"), ACCEPTED)
    async def test_deletes_only_the_suse_row_of_that_version(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_of: CVEOf,
        va_user: VAUser,
        version: str,
        vector: Vector,
    ) -> None:
        """Another provider's row of the same version and the other SUSE
        versions survive; the result carries the deleted snapshot."""
        actor = await va_user()
        vectors = [V20_CRITICAL, V30_CRITICAL, V31_CRITICAL, V40_CRITICAL]
        providers = ("Example Vendor", "SUSE")
        cve = await cve_of(
            *[(provider, v) for v in vectors for provider in providers],
            severity=Severity.CRITICAL,
        )
        target_id = (
            await db_session.execute(
                select(CVECVSSAssessment.id).where(
                    CVECVSSAssessment.cve_id == cve.id,
                    CVECVSSAssessment.provider_name == "SUSE",
                    CVECVSSAssessment.cvss_version == version,
                )
            )
        ).scalar_one()
        ticket = await ticket_factory(
            status=TicketStatus.ANALYSIS.value,
            cve_id=cve.id,
            assignee_id=actor.id,
            priority_auto="P2",
        )

        result = await delete_assessment(db_session, cve.id, version, actor)

        assert result.action is CVSSAssessmentAction.DELETED
        snapshot = result.assessment
        assert snapshot is not None
        assert snapshot.id == target_id
        assert (
            snapshot.provider_name,
            snapshot.cvss_version,
            snapshot.score,
            snapshot.severity,
            snapshot.vector_string,
        ) == unit("SUSE", vector)
        assert await persisted_assessments(db_session, cve.id) == [
            unit(provider, v)
            for v in vectors
            for provider in providers
            if (provider, v) != ("SUSE", vector)
        ]
        assert await cve_severity(db_session, cve.id) == "Critical"
        assert await ticket_events(db_session, ticket) == [
            cvss_delete_event(actor, vector)
        ]


# ---------------------------------------------------------------------------
# `not_found` (delete step 6)
# ---------------------------------------------------------------------------


NOT_FOUND_CASES = [
    pytest.param((), "3.1", None, FALLBACK, id="no-assessment"),
    pytest.param(
        (("NVD", V31_CRITICAL),),
        "3.1",
        severity_resolution("9.8", Severity.CRITICAL, provider="NVD"),
        FALLBACK,
        id="external-row-of-that-version",
    ),
    pytest.param(
        (("SUSE", V31_MEDIUM), ("NVD", V40_CRITICAL)),
        "4.0",
        severity_resolution("4.8", Severity.MEDIUM),
        suse_eligibility("4.8"),
        id="other-suse-version-and-external-row",
    ),
]


@pytest.mark.integration
@pytest.mark.usefixtures("default_setting")
class TestNotFound:
    @pytest.mark.parametrize(
        ("assessments", "version", "severity", "eligibility_result"), NOT_FOUND_CASES
    )
    async def test_absent_suse_row_has_no_effect_of_any_kind(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_of: CVEOf,
        tree: TreeBuilder,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
        assessments: tuple[tuple[str, Vector], ...],
        version: str,
        severity: SeverityResolution | None,
        eligibility_result: Any,
    ) -> None:
        """Stale `CVE.severity`, Product, and priority values and an
        unassigned `New` Ticket with a VA actor prove that no severity
        write, propagation, refresh, assignment, or reconciliation runs;
        the result carries the current resolutions."""
        actor = await va_user()
        cve = await cve_of(*assessments, severity=Severity.LOW)
        before = await persisted_assessments(db_session, cve.id)
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
            result = await delete_assessment(db_session, cve.id, version, actor)

        assert result.action is CVSSAssessmentAction.NOT_FOUND
        assert result.assessment is None
        assert result.propagation is CVSSPropagation.NONE
        assert result.severity_changed is False
        assert result.severity_resolution == severity
        assert result.eligibility_resolution == eligibility_result
        assert result.products == ProductPropagationSummary()
        assert (result.assigned, result.reconciled) == (False, False)
        assert result.evaluation_date == EVAL
        assert [c.calls for c in counters] == [[], [], [], []]
        assert recorder.writes() == []
        assert await persisted_assessments(db_session, cve.id) == before
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
        assert pending_ticket_convergence_effects(db_session) == ()

    async def test_ticketless_not_found_propagates_none(
        self, db_session: AsyncSession, cve_of: CVEOf, va_user: VAUser
    ) -> None:
        actor = await va_user()
        cve = await cve_of(("Example Vendor", V31_HIGH), severity=Severity.LOW)

        with StatementRecorder(db_session) as recorder:
            result = await delete_assessment(db_session, cve.id, "3.1", actor)

        assert result.action is CVSSAssessmentAction.NOT_FOUND
        assert result.propagation is CVSSPropagation.NONE
        assert result.severity_resolution == severity_resolution(
            "8.1", Severity.HIGH, provider="Example Vendor"
        )
        assert recorder.writes() == []
        assert await cve_severity(db_session, cve.id) == "Low"
        assert await _total_events(db_session) == 0

    async def test_repeated_delete_after_an_effective_delete_is_not_found(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_of: CVEOf,
        va_user: VAUser,
    ) -> None:
        actor = await va_user()
        cve = await cve_of(("SUSE", V31_HIGH), severity=Severity.HIGH)
        ticket = await ticket_factory(
            status=TicketStatus.ANALYSIS.value,
            cve_id=cve.id,
            assignee_id=actor.id,
            priority_auto="P3",
        )

        first = await delete_assessment(db_session, cve.id, "3.1", actor)
        with StatementRecorder(db_session) as recorder:
            second = await delete_assessment(db_session, cve.id, "3.1", actor)

        assert first.action is CVSSAssessmentAction.DELETED
        assert second.action is CVSSAssessmentAction.NOT_FOUND
        assert second.severity_resolution is None
        assert recorder.writes() == []
        assert await ticket_events(db_session, ticket) == [
            cvss_delete_event(actor, V31_HIGH),
            severity_event("High", None),
            priority_event("P3", None),
        ]


# ---------------------------------------------------------------------------
# Input-only version validation (delete step 1)
# ---------------------------------------------------------------------------


@pytest.mark.integration
@pytest.mark.usefixtures("default_setting")
class TestVersionValidation:
    @pytest.mark.parametrize("version", UNACCEPTED_VERSIONS)
    @pytest.mark.parametrize("target", ["existing-cve", "missing-cve"])
    async def test_unaccepted_version_raises_before_any_statement(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_of: CVEOf,
        va_user: VAUser,
        version: str,
        target: str,
    ) -> None:
        """The persisted SUSE v3.1 row proves that no normalization maps a
        near-miss onto it; a missing CVE proves the check precedes CVE
        resolution."""
        actor = await va_user()
        cve = await cve_of(("SUSE", V31_MEDIUM), severity=Severity.MEDIUM)
        ticket = await ticket_factory(status=TicketStatus.NEW.value, cve_id=cve.id)
        cve_id = cve.id if target == "existing-cve" else uuid.uuid7()

        with (
            StatementRecorder(db_session) as recorder,
            pytest.raises(CVSSAssessmentNotFoundError),
        ):
            await delete_assessment(db_session, cve_id, version, actor)

        assert recorder.statements == []
        assert await persisted_assessments(db_session, cve.id) == [
            unit("SUSE", V31_MEDIUM)
        ]
        assert await ticket_events(db_session, ticket) == []


# ---------------------------------------------------------------------------
# Authority (delete step 1)
# ---------------------------------------------------------------------------


@pytest.mark.integration
@pytest.mark.usefixtures("default_setting")
class TestAuthority:
    @pytest.mark.parametrize("provider", ["SUSE", "suse", "Suse", " suse ", "\tsUsE\n"])
    async def test_reserved_variants_delete_the_canonical_suse_row(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_of: CVEOf,
        va_user: VAUser,
        provider: str,
    ) -> None:
        actor = await va_user()
        cve = await cve_of(
            ("SUSE", V31_MEDIUM), ("NVD", V31_MEDIUM), severity=Severity.MEDIUM
        )
        ticket = await ticket_factory(
            status=TicketStatus.ANALYSIS.value,
            cve_id=cve.id,
            assignee_id=actor.id,
            priority_auto="P4",
        )

        result = await delete_assessment(
            db_session, cve.id, "3.1", actor, provider=provider
        )

        assert result.action is CVSSAssessmentAction.DELETED
        assert result.assessment is not None
        assert result.assessment.provider_name == "SUSE"
        assert await persisted_assessments(db_session, cve.id) == [
            unit("NVD", V31_MEDIUM)
        ]
        assert await ticket_events(db_session, ticket) == [
            cvss_delete_event(actor, V31_MEDIUM)
        ]

    @pytest.mark.parametrize(
        "version",
        [
            pytest.param("3.1", id="accepted-version"),
            pytest.param("5.0", id="unaccepted-version"),
        ],
    )
    @pytest.mark.parametrize(
        ("violation", "message"),
        [
            pytest.param(
                "external-caller", "requires MANUAL_SUSE authority", id="caller"
            ),
            pytest.param("missing-actor", "requires an acting user", id="actor"),
            pytest.param("NVD", "only delete the SUSE provider", id="nvd"),
            pytest.param("Red Hat", "only delete the SUSE provider", id="red-hat"),
            pytest.param(
                "SUSE Linux", "only delete the SUSE provider", id="suse-prefixed"
            ),
            pytest.param(
                "other-caller", "must identify the acting user", id="other-caller"
            ),
            pytest.param(
                "anonymous-caller", "must identify the acting user", id="anonymous"
            ),
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
        version: str,
    ) -> None:
        """`ValueError` also takes precedence over an unaccepted version."""
        actor = await va_user()
        other = await va_user()
        cve = await cve_of(
            ("SUSE", V31_MEDIUM), ("NVD", V31_MEDIUM), severity=Severity.MEDIUM
        )
        ticket = await ticket_factory(status=TicketStatus.NEW.value, cve_id=cve.id)
        kwargs: dict[str, Any] = {
            "cve_id": cve.id,
            "provider": "SUSE",
            "cvss_version": version,
            "caller": CVSSMutationCaller.MANUAL_SUSE,
            "acting_user_id": actor.id,
            "ticket_caller": TicketCaller.authenticated(actor.id, Scope.ALL),
            "evaluation_date": EVAL,
        }
        if violation == "external-caller":
            kwargs["caller"] = cast(CVSSMutationCaller, "external")
        elif violation == "missing-actor":
            kwargs["acting_user_id"] = None
        elif violation == "other-caller":
            kwargs["ticket_caller"] = TicketCaller.authenticated(other.id, Scope.ALL)
        elif violation == "anonymous-caller":
            kwargs["ticket_caller"] = ANONYMOUS_CALLER
        else:
            kwargs["provider"] = violation

        with (
            StatementRecorder(db_session) as recorder,
            pytest.raises(ValueError, match=message),
        ):
            await delete_cvss_assessment(db_session, **kwargs)

        assert recorder.statements == []
        assert await persisted_assessments(db_session, cve.id) == [
            unit("NVD", V31_MEDIUM),
            unit("SUSE", V31_MEDIUM),
        ]
        assert await ticket_events(db_session, ticket) == []

    @pytest.mark.parametrize("version", ["3.1"])
    async def test_missing_cve_is_not_found(
        self, db_session: AsyncSession, va_user: VAUser, version: str
    ) -> None:
        actor = await va_user()

        with (
            StatementRecorder(db_session) as recorder,
            pytest.raises(CVENotFoundError),
        ):
            await delete_assessment(db_session, uuid.uuid7(), version, actor)

        assert recorder.writes() == []

    async def test_never_commits(
        self,
        db_session: AsyncSession,
        cve_of: CVEOf,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        actor = await va_user()
        cve = await cve_of(("SUSE", V31_CRITICAL), severity=Severity.CRITICAL)

        async def forbidden() -> None:
            raise AssertionError("delete_cvss_assessment() must not commit")

        monkeypatch.setattr(db_session, "commit", forbidden)
        monkeypatch.setattr(db_session, "rollback", forbidden)

        result = await delete_assessment(db_session, cve.id, "3.1", actor)

        assert result.action is CVSSAssessmentAction.DELETED


# ---------------------------------------------------------------------------
# Backward transitions and SUSE gate independence
# ---------------------------------------------------------------------------


REGRESSING = [
    pytest.param(TicketStatus.ANALYZED, PackageStatus.AFFECTED, id="analyzed"),
    pytest.param(TicketStatus.RESOLVED, PackageStatus.NOT_AFFECTED, id="resolved"),
]


@pytest.mark.integration
@pytest.mark.usefixtures("default_setting")
class TestBackwardTransitions:
    @pytest.mark.parametrize(("start", "track_status"), REGRESSING)
    async def test_deleting_the_last_suse_assessment_regresses_to_analysis(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_of: CVEOf,
        tree: TreeBuilder,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
        start: TicketStatus,
        track_status: PackageStatus,
    ) -> None:
        """An external assessment keeps the unified severity `Critical`
        and the Product stays eligible under the fallback: only
        canonical-SUSE presence changes, and it alone reconciles."""
        actor = await va_user()
        cve = await cve_of(
            ("SUSE", V31_CRITICAL), ("NVD", V31_CRITICAL), severity=Severity.CRITICAL
        )
        ticket = await ticket_factory(
            status=start.value,
            cve_id=cve.id,
            assignee_id=actor.id,
            priority_auto="P2",
        )
        await tree(ticket, status=track_status)
        reconcile = CallCounter(monkeypatch, "reconcile_ticket_status")

        result = await delete_assessment(db_session, cve.id, "3.1", actor)

        assert (result.severity_changed, result.products.changed) == (False, 0)
        assert result.eligibility_resolution == FALLBACK
        assert result.reconciled is True
        assert reconcile.calls == [{"evaluation_date": EVAL}]
        assert await ticket_state(db_session, ticket.id) == (
            TicketStatus.ANALYSIS,
            actor.id,
            "P2",
            None,
            None,
        )
        assert await ticket_events(db_session, ticket) == [
            cvss_delete_event(actor, V31_CRITICAL),
            status_event(start.value, TicketStatus.ANALYSIS.value),
        ]
        assert pending_ticket_convergence_effects(db_session) == (
            (TicketConvergenceEffect(ticket.id),)
            if start is TicketStatus.RESOLVED
            else ()
        )

    @pytest.mark.parametrize(("start", "track_status"), REGRESSING)
    @pytest.mark.parametrize(
        ("version", "deleted"),
        [
            pytest.param("4.0", V40_CRITICAL, id="non-default"),
            pytest.param("3.1", V31_CRITICAL, id="default"),
        ],
    )
    async def test_deleting_one_of_several_suse_assessments_keeps_the_status(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_of: CVEOf,
        tree: TreeBuilder,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
        start: TicketStatus,
        track_status: PackageStatus,
        version: str,
        deleted: Vector,
    ) -> None:
        """Another SUSE version remains, the unified severity stays
        `Critical`, and the fallback keeps the Product eligible: no gate
        input changed, so no reconciliation runs."""
        actor = await va_user()
        cve = await cve_of(
            ("SUSE", V31_CRITICAL), ("SUSE", V40_CRITICAL), severity=Severity.CRITICAL
        )
        ticket = await ticket_factory(
            status=start.value,
            cve_id=cve.id,
            assignee_id=actor.id,
            priority_auto="P2",
        )
        await tree(ticket, status=track_status)
        reconcile = CallCounter(monkeypatch, "reconcile_ticket_status")

        result = await delete_assessment(db_session, cve.id, version, actor)

        assert result.action is CVSSAssessmentAction.DELETED
        assert (result.severity_changed, result.products.changed) == (False, 0)
        assert result.reconciled is False
        assert reconcile.calls == []
        assert (await ticket_state(db_session, ticket.id))[0] == start
        assert await ticket_events(db_session, ticket) == [
            cvss_delete_event(actor, deleted)
        ]
        assert pending_ticket_convergence_effects(db_session) == ()

    async def test_another_gate_input_reconciles_while_suse_remains(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_of: CVEOf,
        tree: TreeBuilder,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """SUSE v4.0 remains, but deleting the default-version winner
        changes the unified severity: one reconciliation runs."""
        actor = await va_user()
        cve = await cve_of(
            ("SUSE", V31_MEDIUM), ("SUSE", V40_CRITICAL), severity=Severity.MEDIUM
        )
        ticket = await ticket_factory(
            status=TicketStatus.ANALYSIS.value,
            cve_id=cve.id,
            assignee_id=actor.id,
            priority_auto="P4",
        )
        await tree(ticket, status=PackageStatus.ANALYSIS)
        reconcile = CallCounter(monkeypatch, "reconcile_ticket_status")

        result = await delete_assessment(db_session, cve.id, "3.1", actor)

        assert result.severity_changed is True
        assert reconcile.calls == [{"evaluation_date": EVAL}]
        assert await ticket_events(db_session, ticket) == [
            cvss_delete_event(actor, V31_MEDIUM),
            severity_event("Medium", "Critical"),
            priority_event("P4", "P2"),
        ]


# ---------------------------------------------------------------------------
# Derived `CVE.severity` (delete steps 7 and 9)
# ---------------------------------------------------------------------------


@pytest.mark.integration
@pytest.mark.usefixtures("default_setting")
class TestSeverity:
    @pytest.mark.parametrize(
        ("remaining", "resolution", "new_label", "new_priority"),
        [
            pytest.param(
                ("SUSE", V40_CRITICAL),
                severity_resolution("9.3", Severity.CRITICAL, version=CVSSVersion.V4_0),
                "Critical",
                "P2",
                id="suse-other-version",
            ),
            pytest.param(
                ("NVD", V31_HIGH),
                severity_resolution("8.1", Severity.HIGH, provider="NVD"),
                "High",
                "P3",
                id="external-default-version",
            ),
            pytest.param(
                ("NVD", V31_NONE),
                severity_resolution("0.0", Severity.NONE, provider="NVD"),
                "None",
                "P4",
                id="score-zero-is-none-not-null",
            ),
        ],
    )
    async def test_deleting_the_winner_resolves_the_next_winner(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_of: CVEOf,
        va_user: VAUser,
        remaining: tuple[str, Vector],
        resolution: SeverityResolution,
        new_label: str,
        new_priority: str,
    ) -> None:
        actor = await va_user()
        cve = await cve_of(("SUSE", V31_MEDIUM), remaining, severity=Severity.MEDIUM)
        ticket = await ticket_factory(
            status=TicketStatus.ANALYSIS.value,
            cve_id=cve.id,
            assignee_id=actor.id,
            priority_auto="P4",
        )

        result = await delete_assessment(db_session, cve.id, "3.1", actor)

        assert result.severity_resolution == resolution
        assert result.severity_changed is True
        assert await cve_severity(db_session, cve.id) == new_label
        expected = [
            cvss_delete_event(actor, V31_MEDIUM),
            severity_event("Medium", new_label),
        ]
        if new_priority != "P4":
            expected.append(priority_event("P4", new_priority))
        assert await ticket_events(db_session, ticket) == expected

    async def test_deleting_a_non_winner_keeps_the_severity(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_of: CVEOf,
        va_user: VAUser,
    ) -> None:
        actor = await va_user()
        cve = await cve_of(
            ("SUSE", V31_MEDIUM), ("SUSE", V40_CRITICAL), severity=Severity.MEDIUM
        )
        ticket = await ticket_factory(
            status=TicketStatus.ANALYSIS.value,
            cve_id=cve.id,
            assignee_id=actor.id,
            priority_auto="P4",
        )

        result = await delete_assessment(db_session, cve.id, "4.0", actor)

        assert result.severity_resolution == severity_resolution("4.8", Severity.MEDIUM)
        assert result.eligibility_resolution == suse_eligibility("4.8")
        assert result.severity_changed is False
        assert await cve_severity(db_session, cve.id) == "Medium"
        assert await ticket_events(db_session, ticket) == [
            cvss_delete_event(actor, V40_CRITICAL)
        ]

    async def test_stale_severity_is_rewritten_even_when_the_winner_survives(
        self, db_session: AsyncSession, cve_of: CVEOf, va_user: VAUser
    ) -> None:
        """Step 7 always persists the re-resolved value."""
        actor = await va_user()
        cve = await cve_of(
            ("SUSE", V31_MEDIUM), ("SUSE", V40_CRITICAL), severity=Severity.LOW
        )

        result = await delete_assessment(db_session, cve.id, "4.0", actor)

        assert result.severity_changed is True
        assert await cve_severity(db_session, cve.id) == "Medium"


# ---------------------------------------------------------------------------
# Immediate Product propagation (delete step 10)
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
        """Deleting the default-version SUSE assessment moves eligibility to
        the `10.0` fallback: every automatic occurrence below the `7.0`
        threshold becomes eligible, including an excluded one; the override
        is skipped and counted."""
        actor = await va_user()
        cve = await cve_of(
            ("SUSE", V31_MEDIUM), ("SUSE", V40_CRITICAL), severity=Severity.MEDIUM
        )
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
                Prod(eligible=True, threshold=threshold),
            ),
        )

        result = await delete_assessment(db_session, cve.id, "3.1", actor)

        assert result.eligibility_resolution == FALLBACK
        assert result.products == ProductPropagationSummary(4, 1, 2)
        assert await eligibility(db_session, ticket.id) == [
            (True, False),
            (False, True),
            (True, False),
            (True, False),
        ]
        detail = await subjects(db_session, ticket.id)
        assert await ticket_events(db_session, ticket) == [
            cvss_delete_event(actor, V31_MEDIUM),
            severity_event("Medium", "Critical"),
            product_event(detail[0], False, True),
            product_event(detail[2], False, True),
            priority_event("P4", "P2"),
            status_event(TicketStatus.ANALYSIS.value, TicketStatus.ANALYZED.value),
        ]

    async def test_product_change_alone_reconciles(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_of: CVEOf,
        tree: TreeBuilder,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Severity stays `Critical` and SUSE v4.0 remains, but the `10.0`
        fallback crosses the `9.9` threshold."""
        actor = await va_user()
        cve = await cve_of(
            ("SUSE", V31_CRITICAL), ("SUSE", V40_CRITICAL), severity=Severity.CRITICAL
        )
        ticket = await ticket_factory(
            status=TicketStatus.ANALYSIS.value,
            cve_id=cve.id,
            assignee_id=actor.id,
            priority_auto="P2",
        )
        await tree(
            ticket,
            status=PackageStatus.AFFECTED,
            products=(Prod(eligible=False, threshold=Decimal("9.9")),),
        )
        reconcile = CallCounter(monkeypatch, "reconcile_ticket_status")

        result = await delete_assessment(db_session, cve.id, "3.1", actor)

        assert result.severity_changed is False
        assert result.products == ProductPropagationSummary(1, 0, 1)
        assert reconcile.calls == [{"evaluation_date": EVAL}]
        detail = await subjects(db_session, ticket.id)
        assert await ticket_events(db_session, ticket) == [
            cvss_delete_event(actor, V31_CRITICAL),
            product_event(detail[0], False, True),
            status_event(TicketStatus.ANALYSIS.value, TicketStatus.ANALYZED.value),
        ]


# ---------------------------------------------------------------------------
# Manual SUSE auto-assignment and the exact event order (delete steps 8-11)
# ---------------------------------------------------------------------------


@pytest.mark.integration
@pytest.mark.usefixtures("default_setting")
class TestAssignment:
    async def test_new_ticket_assigns_promotes_then_records_the_complete_chain(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_of: CVEOf,
        tree: TreeBuilder,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        actor = await va_user()
        cve = await cve_of(
            ("SUSE", V31_MEDIUM), ("SUSE", V40_CRITICAL), severity=Severity.MEDIUM
        )
        ticket = await ticket_factory(
            status=TicketStatus.NEW.value, cve_id=cve.id, priority_auto="P4"
        )
        await tree(
            ticket,
            status=PackageStatus.AFFECTED,
            products=(Prod(eligible=False, threshold=Decimal("7.0")),),
        )
        reconcile = CallCounter(monkeypatch, "reconcile_ticket_status")

        result = await delete_assessment(db_session, cve.id, "3.1", actor)

        assert (result.assigned, result.reconciled) == (True, True)
        assert reconcile.calls == [{"evaluation_date": EVAL}]
        assert await ticket_state(db_session, ticket.id) == (
            TicketStatus.ANALYZED,
            actor.id,
            "P2",
            None,
            None,
        )
        detail = await subjects(db_session, ticket.id)
        assert await ticket_events(db_session, ticket) == [
            assignment_event(actor),
            status_event(TicketStatus.NEW.value, TicketStatus.ANALYSIS.value),
            cvss_delete_event(actor, V31_MEDIUM),
            severity_event("Medium", "Critical"),
            product_event(detail[0], False, True),
            priority_event("P4", "P2"),
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
        """Deleting a non-winning SUSE version changes no gate input, but
        the assignment moved `New` into `Analysis`."""
        actor = await va_user()
        cve = await cve_of(
            ("SUSE", V31_CRITICAL), ("SUSE", V40_CRITICAL), severity=Severity.CRITICAL
        )
        ticket = await ticket_factory(
            status=TicketStatus.NEW.value, cve_id=cve.id, priority_auto="P2"
        )
        reconcile = CallCounter(monkeypatch, "reconcile_ticket_status")

        result = await delete_assessment(db_session, cve.id, "4.0", actor)

        assert (result.assigned, result.reconciled) == (True, True)
        assert reconcile.calls == [{"evaluation_date": EVAL}]
        assert await ticket_events(db_session, ticket) == [
            assignment_event(actor),
            status_event(TicketStatus.NEW.value, TicketStatus.ANALYSIS.value),
            cvss_delete_event(actor, V40_CRITICAL),
        ]

    async def test_unassigned_gate_zone_ticket_is_assigned_without_promotion(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_of: CVEOf,
        va_user: VAUser,
    ) -> None:
        actor = await va_user()
        cve = await cve_of(("SUSE", V31_MEDIUM), severity=Severity.MEDIUM)
        ticket = await ticket_factory(
            status=TicketStatus.ANALYSIS.value, cve_id=cve.id, priority_auto="P4"
        )

        await delete_assessment(db_session, cve.id, "3.1", actor)

        assert await ticket_events(db_session, ticket) == [
            assignment_event(actor),
            cvss_delete_event(actor, V31_MEDIUM),
            severity_event("Medium", None),
            priority_event("P4", None),
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
        cve = await cve_of(("SUSE", V31_MEDIUM), severity=Severity.MEDIUM)
        ticket = await ticket_factory(
            status=TicketStatus.ANALYSIS.value, cve_id=cve.id, assignee_id=owner.id
        )

        result = await delete_assessment(db_session, cve.id, "3.1", actor)

        assert result.assigned is False
        assert (await ticket_state(db_session, ticket.id))[1] == owner.id
        assert [
            e for e in await ticket_events(db_session, ticket) if e.user_id == actor.id
        ] == [cvss_delete_event(actor, V31_MEDIUM)]

    @pytest.mark.parametrize(
        ("active", "roles"),
        [
            pytest.param(False, (Role.VULNERABILITY_ANALYST,), id="inactive-va"),
        ],
    )
    async def test_ineligible_actor_deletes_without_assignment_or_reconciliation(
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
        """The unassigned `New` Ticket stays outside gate reconciliation
        although a gate-satisfying tree would move it."""
        actor = await va_user(active=active, roles=roles)
        cve = await cve_of(
            ("SUSE", V31_MEDIUM), ("SUSE", V40_CRITICAL), severity=Severity.MEDIUM
        )
        ticket = await ticket_factory(
            status=TicketStatus.NEW.value, cve_id=cve.id, priority_auto="P4"
        )
        await tree(
            ticket,
            status=PackageStatus.NOT_AFFECTED,
            products=(Prod(eligible=False, threshold=Decimal("7.0")),),
        )
        reconcile = CallCounter(monkeypatch, "reconcile_ticket_status")

        result = await delete_assessment(db_session, cve.id, "3.1", actor)

        assert result.action is CVSSAssessmentAction.DELETED
        assert (result.assigned, result.reconciled) == (False, False)
        assert reconcile.calls == []
        assert result.products == ProductPropagationSummary(1, 0, 1)
        assert await persisted_assessments(db_session, cve.id) == [
            unit("SUSE", V40_CRITICAL)
        ]
        assert await ticket_state(db_session, ticket.id) == (
            TicketStatus.NEW,
            None,
            "P2",
            None,
            None,
        )
        detail = await subjects(db_session, ticket.id)
        assert await ticket_events(db_session, ticket) == [
            cvss_delete_event(actor, V31_MEDIUM),
            severity_event("Medium", "Critical"),
            product_event(detail[0], False, True),
            priority_event("P4", "P2"),
        ]
        assert pending_ticket_convergence_effects(db_session) == ()

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
        cve = await cve_of(
            ("SUSE", V31_MEDIUM), ("SUSE", V40_CRITICAL), severity=Severity.MEDIUM
        )
        ticket = await ticket_factory(
            status=TicketStatus.ANALYSIS.value,
            cve_id=cve.id,
            assignee_id=assignee.id,
            priority_auto="P4",
        )
        await tree(ticket, status=PackageStatus.AFFECTED)

        await delete_assessment(db_session, cve.id, "3.1", actor)

        assert await ticket_events(db_session, ticket) == [
            cvss_delete_event(actor, V31_MEDIUM),
            severity_event("Medium", "Critical"),
            priority_event("P4", "P2"),
            unassigned_event(assignee.username, reason),
            status_event(TicketStatus.ANALYSIS.value, TicketStatus.ANALYZED.value),
        ]


# ---------------------------------------------------------------------------
# Automatic priority and deadline start
# ---------------------------------------------------------------------------


@pytest.mark.integration
@pytest.mark.usefixtures("default_setting")
class TestDerivedTicketFields:
    async def test_priority_change_alone_never_reconciles(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_of: CVEOf,
        tree: TreeBuilder,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A stale `priority_auto` is refreshed by an effective delete that
        changes no gate input; a gate-satisfying tree proves that the
        refresh does not reconcile."""
        actor = await va_user()
        cve = await cve_of(
            ("SUSE", V31_CRITICAL), ("SUSE", V40_CRITICAL), severity=Severity.CRITICAL
        )
        ticket = await ticket_factory(
            status=TicketStatus.ANALYSIS.value,
            cve_id=cve.id,
            assignee_id=actor.id,
            priority_auto="P4",
        )
        await tree(ticket, status=PackageStatus.AFFECTED)
        reconcile = CallCounter(monkeypatch, "reconcile_ticket_status")

        result = await delete_assessment(db_session, cve.id, "4.0", actor)

        assert result.reconciled is False
        assert reconcile.calls == []
        assert await ticket_state(db_session, ticket.id) == (
            TicketStatus.ANALYSIS,
            actor.id,
            "P2",
            None,
            None,
        )
        assert await ticket_events(db_session, ticket) == [
            cvss_delete_event(actor, V40_CRITICAL),
            priority_event("P4", "P2"),
        ]

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

        result = await delete_assessment(db_session, cve.id, "3.1", actor)

        assert result.severity_changed is True
        created_at = (
            await db_session.execute(
                select(Ticket.created_at).where(Ticket.id == ticket.id)
            )
        ).scalar_one()
        assert created_at == CREATED_AT


# ---------------------------------------------------------------------------
# Locked-current CVE accessibility (single session; delete step 3)
# ---------------------------------------------------------------------------


@pytest.mark.integration
@pytest.mark.usefixtures("default_setting")
class TestAccessibility:
    @pytest.mark.parametrize(
        ("status", "version"),
        [
            pytest.param(TicketStatus.NEW, "3.1", id="effective"),
            pytest.param(TicketStatus.IGNORED, "3.1", id="before-operability"),
            pytest.param(TicketStatus.NEW, "4.0", id="before-not-found"),
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
        version: str,
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
            await delete_assessment(
                db_session, cve.id, version, actor, scope=Scope.NON_CONFIDENTIAL
            )

        assert (assign.calls, reconcile.calls) == ([], [])
        assert recorder.writes() == []
        assert recorder.selects_from("system_setting") == []
        assert recorder.selects_from("cve_cvss_assessment") == []
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
        cve = await cve_of(("SUSE", V31_MEDIUM), severity=Severity.MEDIUM)
        ticket = await ticket_factory(
            status=TicketStatus.ANALYSIS.value,
            cve_id=cve.id,
            is_confidential=True,
            priority_auto="P4",
        )
        if path == "grant":
            await ticket_access_grant_factory(ticket_id=ticket.id, user_id=actor.id)
        else:
            package = await ticket_package_factory(ticket_id=ticket.id)
            await ticket_package_maintainer_factory(
                ticket_package_id=package.id, user_id=actor.id
            )

        result = await delete_assessment(
            db_session, cve.id, "3.1", actor, scope=Scope.NON_CONFIDENTIAL
        )

        assert result.action is CVSSAssessmentAction.DELETED
        # A restricted analyst is not VA-eligible: no assignment.
        assert await ticket_events(db_session, ticket) == [
            cvss_delete_event(actor, V31_MEDIUM),
            severity_event("Medium", None),
            priority_event("P4", None),
        ]

    async def test_ticketless_cve_is_accessible_to_every_scope(
        self, db_session: AsyncSession, cve_of: CVEOf, va_user: VAUser
    ) -> None:
        actor = await va_user(roles=())
        cve = await cve_of(("SUSE", V31_MEDIUM), severity=Severity.MEDIUM)

        result = await delete_assessment(
            db_session, cve.id, "3.1", actor, scope=Scope.NON_CONFIDENTIAL
        )

        assert result.action is CVSSAssessmentAction.DELETED


# ---------------------------------------------------------------------------
# Lock order and the locked-current revalidation statement (delete step 2)
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
        cve = await cve_of(("SUSE", V31_CRITICAL), severity=Severity.CRITICAL)
        ticket = await ticket_factory(
            status=TicketStatus.ANALYSIS.value, cve_id=cve.id, is_confidential=True
        )
        await ticket_access_grant_factory(ticket_id=ticket.id, user_id=actor.id)

        with StatementRecorder(db_session) as recorder:
            await delete_assessment(
                db_session, cve.id, "3.1", actor, scope=Scope.NON_CONFIDENTIAL
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
        removal = first(lambda s: s.lstrip().startswith("DELETE FROM cve_cvss_"))
        assert user_share == 0
        assert user_share < cve_lock < ticket_lock < visibility < setting
        assert visibility < assessments < removal
        assert "ticket_access_grant" not in statements[ticket_lock]
