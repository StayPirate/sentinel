"""Tests for the CVE service CVSS read (backend/app/services/cve_service.py).

Owning specifications:

- docs/features/tickets/cvss-scoring.md (Accepted Base Vectors; Severity;
  Eligibility Score Resolution; API Endpoints > Shared Assessment Item and
  Get CVSS Assessments for a CVE; Required Tests > Persistence and API
  Tests).
- docs/features/tickets/cve-service.md (CVE Read and Accessibility
  Boundary): CVE accessibility is a projection of the canonical Ticket
  predicate and the CVE, association, accessibility, setting, and child
  rows come from one coherent PostgreSQL view.
- docs/api-spec.md (CVE Accessibility Check, CVE Identifier Resolution).
- docs/features/identity/rbac.md (Scope and Confidential Ticket
  Visibility).
- docs/features/platform/testing-strategy.md (Ticket Accessibility >
  Canonical predicate and Single, nested, and assembled reads;
  Concurrency Testing).

Expected wire values, scores, and resolution winners are transcribed from
the specifications. The shared pure parser only builds consistent stored
rows (the database does not validate the vector-derived unit).
"""

from __future__ import annotations

import ast
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import asdict
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any

import pytest
from sqlalchemy import delete, event, func, insert, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import (
    CVSSAssessmentSeverity,
    CVSSVersion,
    EligibilitySource,
    Scope,
    Severity,
    TicketStatus,
)
from app.core.exceptions import CVENotFoundError, ServiceError
from app.core.permissions import get_effective_scope
from app.models.cve import CVE
from app.models.cve_cvss_assessment import CVECVSSAssessment
from app.models.system_setting import SystemSetting
from app.models.ticket import Ticket
from app.models.ticket_access_grant import TicketAccessGrant
from app.models.ticket_audit_event import TicketAuditEvent
from app.models.ticket_package import TicketPackage
from app.models.ticket_package_maintainer import TicketPackageMaintainer
from app.models.user import User
from app.services.cve_service import (
    CVECVSSAssessments,
    CVSSAssessmentIntegrityError,
    ResolvedCVE,
    get_cvss_assessments,
    project_cvss_assessment,
    resolve_cve_locator,
)
from app.services.cvss import (
    EligibilityResolution,
    SeverityResolution,
    resolve_eligibility_score,
    resolve_severity_score,
    validate_cvss_vector,
)
from app.services.settings import RequiredSystemSettingMissingError
from app.services.ticket_visibility import ANONYMOUS_CALLER, TicketCaller

Factory = Callable[..., Awaitable[Any]]

SETTING_KEY = "default_cvss_version"
SUSE = "SUSE"
VENDOR = "Example Vendor"

# Valid complete Base vectors (cvss-scoring.md, Accepted Base Vectors).
V20_HIGH = "AV:N/AC:L/Au:N/C:C/I:C/A:C"  # 10.0, assessment `high`
V20_ZERO = "AV:N/AC:L/Au:N/C:N/I:N/A:N"  # 0.0, assessment `low`
V30 = "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"  # 9.8 critical
V31 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"  # 9.8 critical
V31_MEDIUM = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N"  # 4.8 medium
V40 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"  # 9.3
# The V31 metrics in a non-canonical (but otherwise valid) input order.
V31_REORDERED = "CVSS:3.1/AC:L/AV:N/PR:N/UI:N/S:U/C:H/I:H/A:H"

CREATED_AT = datetime(2026, 9, 10, 10, 30, tzinfo=UTC)
UPDATED_AT = datetime(2026, 9, 10, 10, 31, tzinfo=UTC)

MALFORMED_CVE_IDS = [
    "cve-2099-0001",
    "Cve-2099-0001",
    " CVE-2099-0001",
    "CVE-2099-0001 ",
    "CVE-2099-0001\n",
    "CVE-2099-" + "1" * 12,
    "CVE-2099-001",
    "CVE-99-0001",
    "CVE-2099-0001/cvss",
    "018f0e2a-7b1c-7cde-8f00-000000000001",
    "",
]

ALL_SCOPE = TicketCaller.authenticated(uuid.uuid4(), Scope.ALL)


def _unit(vector: str) -> dict[str, Any]:
    """The consistent vector-derived column unit for a stored assessment."""
    parsed = validate_cvss_vector(vector)
    return {
        "cvss_version": parsed.version.value,
        "score": parsed.score,
        "severity": parsed.severity.value,
        "vector_string": parsed.canonical_vector,
    }


def _restricted(user: User) -> TicketCaller:
    return TicketCaller.authenticated(user.id, Scope.NON_CONFIDENTIAL)


async def _read(
    db: AsyncSession, cve: CVE | str, caller: TicketCaller = ANONYMOUS_CALLER
) -> CVECVSSAssessments:
    cve_id = cve if isinstance(cve, str) else cve.cve_id
    return await get_cvss_assessments(db, cve_id=cve_id, caller=caller)


def _summary(result: CVECVSSAssessments) -> list[tuple[str, str, Decimal]]:
    return [
        (item.cvss_version.value, item.provider_name, item.score)
        for item in result.assessments
    ]


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


def _integrity_events(caplog: pytest.LogCaptureFixture) -> list[dict[str, Any]]:
    """Structured `cvss_assessment_integrity_violation` records."""
    matches = []
    for record in caplog.records:
        if record.name != "app.services.cve_service":
            continue
        try:
            parsed = ast.literal_eval(record.getMessage())
        except ValueError, SyntaxError:
            continue
        if (
            isinstance(parsed, dict)
            and parsed.get("event") == "cvss_assessment_integrity_violation"
        ):
            matches.append(parsed)
    return matches


@pytest.fixture
async def default_setting(system_setting_factory: Factory) -> SystemSetting:
    """The persisted `default_cvss_version` (the test schema has none)."""
    setting: SystemSetting = await system_setting_factory(key=SETTING_KEY, value="3.1")
    return setting


# ---------------------------------------------------------------------------
# Exception contract
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestExceptions:
    def test_not_found_is_the_shared_static_service_error(self) -> None:
        assert issubclass(CVENotFoundError, ServiceError)
        assert str(CVENotFoundError()) == "CVE not found."

    def test_integrity_error_is_not_a_domain_error(self) -> None:
        """Corrupt persisted data surfaces as the global 500, never as a
        mapped domain error code."""
        assert issubclass(CVSSAssessmentIntegrityError, RuntimeError)
        assert not issubclass(CVSSAssessmentIntegrityError, ServiceError)
        assert str(CVSSAssessmentIntegrityError()) == (
            "A persisted CVSS assessment violates its vector-derived unit."
        )


# ---------------------------------------------------------------------------
# CVE identifier resolution
# ---------------------------------------------------------------------------


@pytest.mark.integration
@pytest.mark.usefixtures("default_setting")
class TestIdentifierResolution:
    @pytest.mark.parametrize("cve_id", MALFORMED_CVE_IDS)
    async def test_malformed_identifier_raises_without_any_statement(
        self, db_session: AsyncSession, cve_factory: Factory, cve_id: str
    ) -> None:
        await cve_factory(cve_id="CVE-2099-0001")

        with (
            _StatementRecorder(db_session) as recorder,
            pytest.raises(CVENotFoundError),
        ):
            await _read(db_session, cve_id)

        assert recorder.statements == []

    async def test_internal_uuid_is_never_accepted(
        self, db_session: AsyncSession, cve_factory: Factory
    ) -> None:
        cve: CVE = await cve_factory()

        with (
            _StatementRecorder(db_session) as recorder,
            pytest.raises(CVENotFoundError),
        ):
            await _read(db_session, str(cve.id))

        assert recorder.statements == []

    async def test_well_formed_missing_identifier_is_not_found(
        self, db_session: AsyncSession
    ) -> None:
        with pytest.raises(CVENotFoundError):
            await _read(db_session, "CVE-2099-99999")

    async def test_maximum_length_identifier_is_looked_up(
        self, db_session: AsyncSession, cve_factory: Factory
    ) -> None:
        cve: CVE = await cve_factory(cve_id="CVE-2099-" + "1" * 11)

        result = await _read(db_session, cve)

        assert result.assessments == ()

    async def test_successful_read_is_exactly_one_statement(
        self,
        db_session: AsyncSession,
        cve_factory: Factory,
        ticket_factory: Factory,
        cve_cvss_assessment_factory: Factory,
    ) -> None:
        cve: CVE = await cve_factory()
        await ticket_factory(cve_id=cve.id)
        for provider, vector in ((SUSE, V31), (VENDOR, V40), (VENDOR, V20_HIGH)):
            await cve_cvss_assessment_factory(
                cve_id=cve.id, provider_name=provider, **_unit(vector)
            )

        with _StatementRecorder(db_session) as recorder:
            result = await _read(db_session, cve)

        assert len(result.assessments) == 3
        assert len(recorder.statements) == 1
        assert recorder.statements[0].lstrip().upper().startswith("SELECT")


# ---------------------------------------------------------------------------
# Canonical predicate applied to a CVE
# ---------------------------------------------------------------------------


@pytest.mark.integration
@pytest.mark.usefixtures("default_setting")
class TestCVEAccessibility:
    async def test_ticketless_cve_is_visible_to_every_caller(
        self,
        db_session: AsyncSession,
        cve_factory: Factory,
        cve_cvss_assessment_factory: Factory,
        user_factory: Factory,
    ) -> None:
        cve: CVE = await cve_factory()
        await cve_cvss_assessment_factory(cve_id=cve.id, provider_name=VENDOR)
        user: User = await user_factory()

        for caller in (ANONYMOUS_CALLER, _restricted(user), ALL_SCOPE):
            result = await _read(db_session, cve, caller)
            assert _summary(result) == [("3.1", VENDOR, Decimal("9.8"))]

    async def test_non_confidential_associated_cve_is_visible_to_everyone(
        self,
        db_session: AsyncSession,
        cve_factory: Factory,
        ticket_factory: Factory,
        user_factory: Factory,
    ) -> None:
        cve: CVE = await cve_factory()
        await ticket_factory(cve_id=cve.id, is_confidential=False)
        user: User = await user_factory()

        for caller in (ANONYMOUS_CALLER, _restricted(user), ALL_SCOPE):
            assert (await _read(db_session, cve, caller)).assessments == ()

    async def test_anonymous_caller_never_sees_a_confidential_cve(
        self,
        db_session: AsyncSession,
        cve_factory: Factory,
        ticket_factory: Factory,
        ticket_access_grant_factory: Factory,
        ticket_package_factory: Factory,
        ticket_package_maintainer_factory: Factory,
    ) -> None:
        """Grant and maintainer rows exist for some user; an anonymous
        caller has no identity, so neither branch can authorize it."""
        cve: CVE = await cve_factory()
        ticket: Ticket = await ticket_factory(cve_id=cve.id, is_confidential=True)
        await ticket_access_grant_factory(ticket_id=ticket.id)
        package = await ticket_package_factory(ticket_id=ticket.id)
        await ticket_package_maintainer_factory(ticket_package_id=package.id)

        with pytest.raises(CVENotFoundError):
            await _read(db_session, cve, ANONYMOUS_CALLER)

    async def test_scope_all_sees_a_confidential_cve_without_grant(
        self, db_session: AsyncSession, cve_factory: Factory, ticket_factory: Factory
    ) -> None:
        cve: CVE = await cve_factory()
        await ticket_factory(cve_id=cve.id, is_confidential=True)

        assert (await _read(db_session, cve, ALL_SCOPE)).assessments == ()

    async def test_explicit_grant_authorizes_only_its_holder(
        self,
        db_session: AsyncSession,
        cve_factory: Factory,
        ticket_factory: Factory,
        ticket_access_grant_factory: Factory,
        user_factory: Factory,
    ) -> None:
        cve: CVE = await cve_factory()
        ticket: Ticket = await ticket_factory(cve_id=cve.id, is_confidential=True)
        holder: User = await user_factory()
        other: User = await user_factory()
        await ticket_access_grant_factory(ticket_id=ticket.id, user_id=holder.id)

        assert (await _read(db_session, cve, _restricted(holder))).assessments == ()
        with pytest.raises(CVENotFoundError):
            await _read(db_session, cve, _restricted(other))

    async def test_grant_on_another_ticket_does_not_authorize(
        self,
        db_session: AsyncSession,
        cve_factory: Factory,
        ticket_factory: Factory,
        ticket_access_grant_factory: Factory,
        user_factory: Factory,
    ) -> None:
        cve: CVE = await cve_factory()
        await ticket_factory(cve_id=cve.id, is_confidential=True)
        holder: User = await user_factory()
        await ticket_access_grant_factory(user_id=holder.id)

        with pytest.raises(CVENotFoundError):
            await _read(db_session, cve, _restricted(holder))

    async def test_included_package_maintainer_sees_the_cve(
        self,
        db_session: AsyncSession,
        cve_factory: Factory,
        ticket_factory: Factory,
        ticket_package_factory: Factory,
        ticket_package_maintainer_factory: Factory,
        user_factory: Factory,
    ) -> None:
        cve: CVE = await cve_factory()
        ticket: Ticket = await ticket_factory(cve_id=cve.id, is_confidential=True)
        maintainer: User = await user_factory()
        package = await ticket_package_factory(ticket_id=ticket.id)
        await ticket_package_maintainer_factory(
            ticket_package_id=package.id, user_id=maintainer.id
        )

        assert (await _read(db_session, cve, _restricted(maintainer))).assessments == ()

    async def test_excluded_maintained_package_does_not_authorize(
        self,
        db_session: AsyncSession,
        cve_factory: Factory,
        ticket_factory: Factory,
        ticket_package_factory: Factory,
        ticket_package_maintainer_factory: Factory,
        user_factory: Factory,
    ) -> None:
        cve: CVE = await cve_factory()
        ticket: Ticket = await ticket_factory(cve_id=cve.id, is_confidential=True)
        maintainer: User = await user_factory()
        package = await ticket_package_factory(
            ticket_id=ticket.id, deleted_at=datetime(2026, 9, 1, tzinfo=UTC)
        )
        await ticket_package_maintainer_factory(
            ticket_package_id=package.id, user_id=maintainer.id
        )

        with pytest.raises(CVENotFoundError):
            await _read(db_session, cve, _restricted(maintainer))

    async def test_access_is_lost_only_with_the_last_qualifying_package(
        self,
        db_session: AsyncSession,
        cve_factory: Factory,
        ticket_factory: Factory,
        ticket_package_factory: Factory,
        ticket_package_maintainer_factory: Factory,
        user_factory: Factory,
    ) -> None:
        cve: CVE = await cve_factory()
        ticket: Ticket = await ticket_factory(cve_id=cve.id, is_confidential=True)
        maintainer: User = await user_factory()
        first = await ticket_package_factory(ticket_id=ticket.id)
        second = await ticket_package_factory(ticket_id=ticket.id)
        for package in (first, second):
            await ticket_package_maintainer_factory(
                ticket_package_id=package.id, user_id=maintainer.id
            )
        caller = _restricted(maintainer)

        first.deleted_at = datetime(2026, 9, 1, tzinfo=UTC)
        await db_session.flush()
        assert (await _read(db_session, cve, caller)).assessments == ()

        second.deleted_at = datetime(2026, 9, 2, tzinfo=UTC)
        await db_session.flush()
        with pytest.raises(CVENotFoundError):
            await _read(db_session, cve, caller)

    async def test_ticket_status_does_not_change_visibility(
        self,
        db_session: AsyncSession,
        cve_factory: Factory,
        ticket_factory: Factory,
        user_factory: Factory,
    ) -> None:
        cve: CVE = await cve_factory()
        await ticket_factory(
            cve_id=cve.id, is_confidential=True, status=TicketStatus.RESOLVED.value
        )
        user: User = await user_factory()

        with pytest.raises(CVENotFoundError):
            await _read(db_session, cve, _restricted(user))
        assert (await _read(db_session, cve, ALL_SCOPE)).assessments == ()

    async def test_user_without_roles_gains_visibility_through_a_grant(
        self,
        db_session: AsyncSession,
        cve_factory: Factory,
        ticket_factory: Factory,
        ticket_access_grant_factory: Factory,
        cve_cvss_assessment_factory: Factory,
        user_factory: Factory,
    ) -> None:
        cve: CVE = await cve_factory()
        ticket: Ticket = await ticket_factory(cve_id=cve.id, is_confidential=True)
        await cve_cvss_assessment_factory(cve_id=cve.id, provider_name=VENDOR)
        user: User = await user_factory()
        caller = TicketCaller.authenticated(user.id, get_effective_scope([]))
        assert caller.scope is Scope.NON_CONFIDENTIAL

        with pytest.raises(CVENotFoundError):
            await _read(db_session, cve, caller)
        await ticket_access_grant_factory(ticket_id=ticket.id, user_id=user.id)

        result = await _read(db_session, cve, caller)
        assert _summary(result) == [("3.1", VENDOR, Decimal("9.8"))]


# ---------------------------------------------------------------------------
# Composite content, ordering, and resolutions
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestCompositeContent:
    async def test_projection_expands_every_version_with_canonical_values(
        self,
        db_session: AsyncSession,
        default_setting: SystemSetting,
        cve_factory: Factory,
        cve_cvss_assessment_factory: Factory,
    ) -> None:
        cve: CVE = await cve_factory()
        rows: dict[str, CVECVSSAssessment] = {}
        for vector in (V20_HIGH, V30, V31, V40):
            row = await cve_cvss_assessment_factory(
                cve_id=cve.id,
                provider_name=VENDOR,
                created_at=CREATED_AT,
                updated_at=UPDATED_AT,
                **_unit(vector),
            )
            rows[row.cvss_version] = row

        result = await _read(db_session, cve)

        v3_metrics = {
            "attack_vector": "network",
            "attack_complexity": "low",
            "privileges_required": "none",
            "user_interaction": "none",
            "scope": "unchanged",
            "confidentiality_impact": "high",
            "integrity_impact": "high",
            "availability_impact": "high",
        }
        expected = {
            "4.0": (
                V40,
                Decimal("9.3"),
                CVSSAssessmentSeverity.CRITICAL,
                {
                    "attack_vector": "network",
                    "attack_complexity": "low",
                    "attack_requirements": "none",
                    "privileges_required": "none",
                    "user_interaction": "none",
                    "vulnerable_system_confidentiality": "high",
                    "vulnerable_system_integrity": "high",
                    "vulnerable_system_availability": "high",
                    "subsequent_system_confidentiality": "none",
                    "subsequent_system_integrity": "none",
                    "subsequent_system_availability": "none",
                },
            ),
            "3.1": (V31, Decimal("9.8"), CVSSAssessmentSeverity.CRITICAL, v3_metrics),
            "3.0": (V30, Decimal("9.8"), CVSSAssessmentSeverity.CRITICAL, v3_metrics),
            "2.0": (
                V20_HIGH,
                Decimal("10.0"),
                CVSSAssessmentSeverity.HIGH,
                {
                    "access_vector": "network",
                    "access_complexity": "low",
                    "authentication": "none",
                    "confidentiality_impact": "complete",
                    "integrity_impact": "complete",
                    "availability_impact": "complete",
                },
            ),
        }
        assert [item.cvss_version for item in result.assessments] == [
            CVSSVersion.V4_0,
            CVSSVersion.V3_1,
            CVSSVersion.V3_0,
            CVSSVersion.V2_0,
        ]
        for item in result.assessments:
            vector, score, severity, metrics = expected[item.cvss_version.value]
            assert item.id == rows[item.cvss_version.value].id
            assert item.provider_name == VENDOR
            assert item.vector_string == vector
            assert item.score == score
            assert item.severity is severity
            assert asdict(item.metrics) == metrics
            assert (item.created_at, item.updated_at) == (CREATED_AT, UPDATED_AT)
        assert result.default_cvss_version is CVSSVersion.V3_1
        assert result.severity == SeverityResolution(
            score=Decimal("9.8"),
            version=CVSSVersion.V3_1,
            provider=VENDOR,
            label=Severity.CRITICAL,
        )
        assert result.eligibility == EligibilityResolution(
            score=Decimal("10.0"), source=EligibilitySource.FALLBACK
        )

    async def test_order_is_version_then_provider_code_point(
        self,
        db_session: AsyncSession,
        default_setting: SystemSetting,
        cve_factory: Factory,
        cve_cvss_assessment_factory: Factory,
    ) -> None:
        """Code-point order puts uppercase before lowercase
        (`B-Vendor` < `Zeta` < `a-vendor`); a typical linguistic database
        collation would instead yield `a-vendor`, `B-Vendor`, `Zeta`. The
        rows are inserted in neither order."""
        cve: CVE = await cve_factory()
        for provider, vector in (
            ("a-vendor", V31_MEDIUM),
            ("B-Vendor", V20_HIGH),
            ("a-vendor", V30),
            ("Zeta", V31),
            ("Zeta", V40),
            ("B-Vendor", V31),
        ):
            await cve_cvss_assessment_factory(
                cve_id=cve.id, provider_name=provider, **_unit(vector)
            )

        result = await _read(db_session, cve)

        assert _summary(result) == [
            ("4.0", "Zeta", Decimal("9.3")),
            ("3.1", "B-Vendor", Decimal("9.8")),
            ("3.1", "Zeta", Decimal("9.8")),
            ("3.1", "a-vendor", Decimal("4.8")),
            ("3.0", "a-vendor", Decimal("9.8")),
            ("2.0", "B-Vendor", Decimal("10.0")),
        ]

    async def test_list_order_is_independent_of_the_severity_winner(
        self,
        db_session: AsyncSession,
        default_setting: SystemSetting,
        cve_factory: Factory,
        cve_cvss_assessment_factory: Factory,
    ) -> None:
        cve: CVE = await cve_factory()
        await cve_cvss_assessment_factory(
            cve_id=cve.id, provider_name=VENDOR, **_unit(V40)
        )
        await cve_cvss_assessment_factory(
            cve_id=cve.id, provider_name=SUSE, **_unit(V20_HIGH)
        )

        result = await _read(db_session, cve)

        assert _summary(result) == [
            ("4.0", VENDOR, Decimal("9.3")),
            ("2.0", SUSE, Decimal("10.0")),
        ]
        assert result.severity == SeverityResolution(
            score=Decimal("10.0"),
            version=CVSSVersion.V2_0,
            provider=SUSE,
            label=Severity.CRITICAL,
        )

    async def test_empty_set_has_no_severity_and_the_fallback_eligibility(
        self,
        db_session: AsyncSession,
        default_setting: SystemSetting,
        cve_factory: Factory,
    ) -> None:
        cve: CVE = await cve_factory()

        result = await _read(db_session, cve)

        assert result == CVECVSSAssessments(
            assessments=(),
            default_cvss_version=CVSSVersion.V3_1,
            severity=None,
            eligibility=EligibilityResolution(
                score=Decimal("10.0"), source=EligibilitySource.FALLBACK
            ),
        )

    async def test_v2_zero_score_is_assessment_low_and_unified_none(
        self,
        db_session: AsyncSession,
        default_setting: SystemSetting,
        cve_factory: Factory,
        cve_cvss_assessment_factory: Factory,
    ) -> None:
        cve: CVE = await cve_factory()
        await cve_cvss_assessment_factory(
            cve_id=cve.id, provider_name=VENDOR, **_unit(V20_ZERO)
        )

        result = await _read(db_session, cve)

        (item,) = result.assessments
        assert (item.score, item.severity) == (
            Decimal("0.0"),
            CVSSAssessmentSeverity.LOW,
        )
        assert result.severity == SeverityResolution(
            score=Decimal("0.0"),
            version=CVSSVersion.V2_0,
            provider=VENDOR,
            label=Severity.NONE,
        )

    async def test_default_version_selects_severity_and_eligibility(
        self,
        db_session: AsyncSession,
        default_setting: SystemSetting,
        cve_factory: Factory,
        cve_cvss_assessment_factory: Factory,
    ) -> None:
        """The same persisted set read under 3.1 and then 4.0 resolves to a
        different canonical SUSE winner and eligibility score."""
        cve: CVE = await cve_factory()
        for provider, vector in ((SUSE, V31_MEDIUM), (SUSE, V40), (VENDOR, V31)):
            await cve_cvss_assessment_factory(
                cve_id=cve.id, provider_name=provider, **_unit(vector)
            )

        under_31 = await _read(db_session, cve)
        default_setting.value = "4.0"
        await db_session.flush()
        under_40 = await _read(db_session, cve)

        assert under_31.default_cvss_version is CVSSVersion.V3_1
        assert under_31.severity == SeverityResolution(
            score=Decimal("4.8"),
            version=CVSSVersion.V3_1,
            provider=SUSE,
            label=Severity.MEDIUM,
        )
        assert under_31.eligibility == EligibilityResolution(
            score=Decimal("4.8"), source=EligibilitySource.SUSE
        )
        assert under_40.default_cvss_version is CVSSVersion.V4_0
        assert under_40.severity == SeverityResolution(
            score=Decimal("9.3"),
            version=CVSSVersion.V4_0,
            provider=SUSE,
            label=Severity.CRITICAL,
        )
        assert under_40.eligibility == EligibilityResolution(
            score=Decimal("9.3"), source=EligibilitySource.SUSE
        )
        assert _summary(under_31) == _summary(under_40)

    async def test_suse_at_another_version_never_supplies_eligibility(
        self,
        db_session: AsyncSession,
        default_setting: SystemSetting,
        cve_factory: Factory,
        cve_cvss_assessment_factory: Factory,
    ) -> None:
        """Default 4.0 with only a canonical SUSE v3.1 assessment: severity
        follows the full cascade (SUSE at another version beats a non-SUSE
        default-version score) while eligibility uses the 10.0 fallback."""
        default_setting.value = "4.0"
        await db_session.flush()
        cve: CVE = await cve_factory()
        await cve_cvss_assessment_factory(
            cve_id=cve.id, provider_name=SUSE, **_unit(V31_MEDIUM)
        )
        await cve_cvss_assessment_factory(
            cve_id=cve.id, provider_name=VENDOR, **_unit(V40)
        )

        result = await _read(db_session, cve)

        assert result.default_cvss_version is CVSSVersion.V4_0
        assert result.severity == SeverityResolution(
            score=Decimal("4.8"),
            version=CVSSVersion.V3_1,
            provider=SUSE,
            label=Severity.MEDIUM,
        )
        assert result.eligibility == EligibilityResolution(
            score=Decimal("10.0"), source=EligibilitySource.FALLBACK
        )

    async def test_read_creates_nothing_and_leaves_the_session_clean(
        self,
        db_session: AsyncSession,
        default_setting: SystemSetting,
        cve_factory: Factory,
        ticket_factory: Factory,
        cve_cvss_assessment_factory: Factory,
    ) -> None:
        cve: CVE = await cve_factory()
        await ticket_factory(cve_id=cve.id)
        await cve_cvss_assessment_factory(cve_id=cve.id, provider_name=SUSE)
        counts = select(
            select(func.count()).select_from(CVECVSSAssessment).scalar_subquery(),
            select(func.count()).select_from(TicketAuditEvent).scalar_subquery(),
        )
        before = (await db_session.execute(counts)).one()

        with _StatementRecorder(db_session) as recorder:
            await _read(db_session, cve)

        assert len(recorder.statements) == 1
        assert not db_session.new
        assert not db_session.dirty
        assert not db_session.deleted
        assert db_session.in_transaction()
        assert (await db_session.execute(counts)).one() == before


# ---------------------------------------------------------------------------
# Required setting
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestRequiredSetting:
    async def test_accessible_cve_without_setting_raises(
        self,
        db_session: AsyncSession,
        cve_factory: Factory,
        cve_cvss_assessment_factory: Factory,
    ) -> None:
        with_rows: CVE = await cve_factory()
        await cve_cvss_assessment_factory(cve_id=with_rows.id)
        empty: CVE = await cve_factory()

        for cve in (with_rows, empty):
            with pytest.raises(RequiredSystemSettingMissingError):
                await _read(db_session, cve)

    async def test_missing_cve_without_setting_is_not_found(
        self, db_session: AsyncSession
    ) -> None:
        with pytest.raises(CVENotFoundError):
            await _read(db_session, "CVE-2099-99999")

    async def test_inaccessible_cve_without_setting_is_not_found(
        self, db_session: AsyncSession, cve_factory: Factory, ticket_factory: Factory
    ) -> None:
        cve: CVE = await cve_factory()
        await ticket_factory(cve_id=cve.id, is_confidential=True)

        with pytest.raises(CVENotFoundError):
            await _read(db_session, cve)

    async def test_unsupported_persisted_setting_is_a_contract_violation(
        self,
        db_session: AsyncSession,
        system_setting_factory: Factory,
        cve_factory: Factory,
    ) -> None:
        await system_setting_factory(key=SETTING_KEY, value="3.0")
        cve: CVE = await cve_factory()

        with pytest.raises(ValueError, match=r"3\.1 or 4\.0"):
            await _read(db_session, cve)


# ---------------------------------------------------------------------------
# Persisted vector-derived unit integrity
# ---------------------------------------------------------------------------


@pytest.mark.integration
@pytest.mark.usefixtures("default_setting")
class TestAssessmentIntegrity:
    @pytest.mark.parametrize(
        ("overrides", "fields"),
        [
            ({"vector_string": "not-a-cvss-vector"}, ["vector_string"]),
            ({"vector_string": V31_REORDERED}, ["vector_string"]),
            ({"score": Decimal("9.7")}, ["score"]),
            ({"severity": "high"}, ["severity"]),
            ({"cvss_version": "3.0"}, ["cvss_version"]),
            (
                {
                    "cvss_version": "2.0",
                    "score": Decimal("10.0"),
                    "severity": "high",
                },
                ["cvss_version", "score", "severity"],
            ),
        ],
        ids=[
            "unparseable-vector",
            "non-canonical-order",
            "score",
            "severity",
            "version",
            "version-score-severity",
        ],
    )
    async def test_inconsistent_row_is_logged_and_raised(
        self,
        db_session: AsyncSession,
        cve_factory: Factory,
        cve_cvss_assessment_factory: Factory,
        caplog: pytest.LogCaptureFixture,
        overrides: dict[str, Any],
        fields: list[str],
    ) -> None:
        cve: CVE = await cve_factory()
        await cve_cvss_assessment_factory(
            cve_id=cve.id, provider_name=SUSE, **_unit(V40)
        )
        corrupt = await cve_cvss_assessment_factory(
            cve_id=cve.id, provider_name=VENDOR, **{**_unit(V31), **overrides}
        )

        with caplog.at_level("ERROR"), pytest.raises(CVSSAssessmentIntegrityError):
            await _read(db_session, cve)

        events = _integrity_events(caplog)
        assert len(events) == 1
        assert events[0]["cve_id"] == cve.cve_id
        assert events[0]["assessment_id"] == str(corrupt.id)
        assert events[0]["fields"] == fields
        assert events[0]["level"] == "error"
        service_text = "\n".join(
            record.getMessage()
            for record in caplog.records
            if record.name == "app.services.cve_service"
        )
        assert corrupt.vector_string not in service_text
        assert "CVSS:" not in service_text


# ---------------------------------------------------------------------------
# Independent-session races (one coherent observation)
# ---------------------------------------------------------------------------


class _CommittedWorld:
    """Commits fixture rows through an independent session and deletes them
    at teardown in FK-safe order (testing-strategy.md, Concurrency Testing:
    committed data is not rolled back by the fixture).

    The test schema has no committed `default_cvss_version` row, and other
    tests rely on that; cleanup therefore always deletes that key.
    """

    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.user_ids: list[uuid.UUID] = []
        self.cve_ids: list[uuid.UUID] = []
        self.ticket_ids: list[uuid.UUID] = []

    async def user(self) -> User:
        suffix = uuid.uuid4().hex[:10]
        user = User(
            username=f"fictional.cvss.{suffix}",
            email=f"cvss.{suffix}@example.com",
            password_hash="$2b$12$" + "a" * 53,
        )
        self.session.add(user)
        await self.session.flush()
        self.user_ids.append(user.id)
        await self.session.commit()
        return user

    async def setting(self, value: str) -> None:
        self.session.add(SystemSetting(key=SETTING_KEY, value=value))
        await self.session.commit()

    async def cve(self, *assessments: tuple[str, str]) -> CVE:
        cve = CVE(cve_id=f"CVE-2099-{uuid.uuid4().int % 10**7:07d}")
        self.session.add(cve)
        await self.session.flush()
        self.cve_ids.append(cve.id)
        for provider, vector in assessments:
            self.session.add(
                CVECVSSAssessment(
                    cve_id=cve.id, provider_name=provider, **_unit(vector)
                )
            )
        await self.session.commit()
        return cve

    async def ticket(
        self,
        cve: CVE | None,
        *,
        is_confidential: bool,
        maintainer: User | None = None,
    ) -> tuple[Ticket, TicketPackage]:
        ticket = Ticket(is_confidential=is_confidential, cve_id=cve.id if cve else None)
        self.session.add(ticket)
        await self.session.flush()
        self.ticket_ids.append(ticket.id)
        package = TicketPackage(ticket_id=ticket.id, package_name="fictional-cvss")
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
        for statement in (
            delete(CVECVSSAssessment).where(CVECVSSAssessment.cve_id.in_(self.cve_ids)),
            delete(TicketPackageMaintainer).where(
                TicketPackageMaintainer.ticket_package_id.in_(packages)
            ),
            delete(TicketPackage).where(TicketPackage.ticket_id.in_(self.ticket_ids)),
            delete(TicketAccessGrant).where(
                TicketAccessGrant.ticket_id.in_(self.ticket_ids)
            ),
            delete(Ticket).where(Ticket.id.in_(self.ticket_ids)),
            delete(CVE).where(CVE.id.in_(self.cve_ids)),
            delete(User).where(User.id.in_(self.user_ids)),
            delete(SystemSetting).where(SystemSetting.key == SETTING_KEY),
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


def _add_assessment(cve: CVE, provider: str, vector: str) -> Any:
    return insert(CVECVSSAssessment).values(
        cve_id=cve.id, provider_name=provider, **_unit(vector)
    )


def _commit_after_first_statement(
    monkeypatch: pytest.MonkeyPatch,
    reader: AsyncSession,
    change: Callable[[], Awaitable[None]],
) -> list[int]:
    """Commit `change` from another session right after the reader's first
    statement returns. Returns a one-element call counter.

    A read split into several statements observes the change in every
    statement after the first and therefore returns a mixed or post-change
    result; a read performed in one statement observes only the pre-change
    view.
    """
    original = reader.execute
    calls = [0]

    async def _execute(*args: Any, **kwargs: Any) -> Any:
        result = await original(*args, **kwargs)
        calls[0] += 1
        if calls[0] == 1:
            await change()
        return result

    monkeypatch.setattr(reader, "execute", _execute)
    return calls


def _assert_self_consistent(result: CVECVSSAssessments) -> None:
    """Severity and eligibility are the pure resolutions of the returned
    set under the returned default version."""
    version = result.default_cvss_version.value
    assert result.severity == resolve_severity_score(result.assessments, version)
    assert result.eligibility == resolve_eligibility_score(result.assessments, version)


@pytest.mark.integration
class TestChangeBeforeProtectedSelection:
    """Session R performs a first read, session W then commits a change, and
    R reads again (a sequential re-read on independent connections, in a
    fixed order). A committed visibility change applies to the next read and
    is never masked by an earlier successful read. The in-request coherence
    proof, a change committed between statements of one read, is
    `TestChangeAfterFirstStatement`."""

    async def test_confidentiality_set_after_first_read(
        self,
        committed_world: _CommittedWorld,
        db_session_factory: Callable[[], Awaitable[AsyncSession]],
    ) -> None:
        await committed_world.setting("3.1")
        user = await committed_world.user()
        cve = await committed_world.cve((VENDOR, V31))
        ticket, _ = await committed_world.ticket(cve, is_confidential=False)
        reader = await db_session_factory()
        writer = await db_session_factory()
        caller = _restricted(user)

        assert len((await _read(reader, cve, caller)).assessments) == 1
        await _commit(
            writer,
            update(Ticket).where(Ticket.id == ticket.id).values(is_confidential=True),
        )

        with pytest.raises(CVENotFoundError):
            await _read(reader, cve, caller)

    async def test_grant_revoked_after_first_read(
        self,
        committed_world: _CommittedWorld,
        db_session_factory: Callable[[], Awaitable[AsyncSession]],
    ) -> None:
        await committed_world.setting("3.1")
        user = await committed_world.user()
        granter = await committed_world.user()
        cve = await committed_world.cve((VENDOR, V31))
        ticket, _ = await committed_world.ticket(cve, is_confidential=True)
        await committed_world.grant(ticket, user, granter)
        reader = await db_session_factory()
        writer = await db_session_factory()
        caller = _restricted(user)

        assert len((await _read(reader, cve, caller)).assessments) == 1
        await _commit(
            writer,
            delete(TicketAccessGrant).where(TicketAccessGrant.ticket_id == ticket.id),
        )

        with pytest.raises(CVENotFoundError):
            await _read(reader, cve, caller)

    async def test_last_maintained_package_excluded_after_first_read(
        self,
        committed_world: _CommittedWorld,
        db_session_factory: Callable[[], Awaitable[AsyncSession]],
    ) -> None:
        await committed_world.setting("3.1")
        user = await committed_world.user()
        cve = await committed_world.cve((VENDOR, V31))
        _, package = await committed_world.ticket(
            cve, is_confidential=True, maintainer=user
        )
        reader = await db_session_factory()
        writer = await db_session_factory()
        caller = _restricted(user)

        assert len((await _read(reader, cve, caller)).assessments) == 1
        await _commit(
            writer,
            update(TicketPackage)
            .where(TicketPackage.id == package.id)
            .values(deleted_at=datetime.now(UTC)),
        )

        with pytest.raises(CVENotFoundError):
            await _read(reader, cve, caller)

    async def test_ticketless_cve_associated_with_confidential_ticket(
        self,
        committed_world: _CommittedWorld,
        db_session_factory: Callable[[], Awaitable[AsyncSession]],
    ) -> None:
        await committed_world.setting("3.1")
        cve = await committed_world.cve((VENDOR, V31))
        ticket, _ = await committed_world.ticket(None, is_confidential=True)
        reader = await db_session_factory()
        writer = await db_session_factory()

        assert len((await _read(reader, cve)).assessments) == 1
        await _commit(
            writer, update(Ticket).where(Ticket.id == ticket.id).values(cve_id=cve.id)
        )

        with pytest.raises(CVENotFoundError):
            await _read(reader, cve)

    async def test_visibility_acquired_with_assessment_change_is_observed_whole(
        self,
        committed_world: _CommittedWorld,
        db_session_factory: Callable[[], Awaitable[AsyncSession]],
    ) -> None:
        await committed_world.setting("3.1")
        user = await committed_world.user()
        granter = await committed_world.user()
        cve = await committed_world.cve((VENDOR, V31))
        ticket, _ = await committed_world.ticket(cve, is_confidential=True)
        reader = await db_session_factory()
        writer = await db_session_factory()
        caller = _restricted(user)

        with pytest.raises(CVENotFoundError):
            await _read(reader, cve, caller)
        await _commit(
            writer,
            insert(TicketAccessGrant).values(
                ticket_id=ticket.id, user_id=user.id, granted_by_id=granter.id
            ),
            _add_assessment(cve, SUSE, V31_MEDIUM),
        )

        after = await _read(reader, cve, caller)
        assert _summary(after) == [
            ("3.1", VENDOR, Decimal("9.8")),
            ("3.1", SUSE, Decimal("4.8")),
        ]
        assert after.severity == SeverityResolution(
            score=Decimal("4.8"),
            version=CVSSVersion.V3_1,
            provider=SUSE,
            label=Severity.MEDIUM,
        )
        assert after.eligibility == EligibilityResolution(
            score=Decimal("4.8"), source=EligibilitySource.SUSE
        )


@pytest.mark.integration
class TestChangeAfterFirstStatement:
    """Session W commits immediately after R's first statement returns. The
    read is one statement, so R returns the complete pre-change composite
    (or `CVENotFoundError` when the pre-change view denies access), never a
    response mixing the pre- and post-change views. A fresh session then
    proves the change was committed."""

    async def test_confidentiality_set_with_new_assessment(
        self,
        committed_world: _CommittedWorld,
        db_session_factory: Callable[[], Awaitable[AsyncSession]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        await committed_world.setting("3.1")
        user = await committed_world.user()
        cve = await committed_world.cve((VENDOR, V31))
        ticket, _ = await committed_world.ticket(cve, is_confidential=False)
        reader = await db_session_factory()
        writer = await db_session_factory()
        caller = _restricted(user)

        async def change() -> None:
            await _commit(
                writer,
                update(Ticket)
                .where(Ticket.id == ticket.id)
                .values(is_confidential=True),
                _add_assessment(cve, SUSE, V31_MEDIUM),
            )

        calls = _commit_after_first_statement(monkeypatch, reader, change)
        result = await _read(reader, cve, caller)

        assert calls == [1]
        assert _summary(result) == [("3.1", VENDOR, Decimal("9.8"))]
        assert result.eligibility == EligibilityResolution(
            score=Decimal("10.0"), source=EligibilitySource.FALLBACK
        )
        _assert_self_consistent(result)
        with pytest.raises(CVENotFoundError):
            await _read(await db_session_factory(), cve, caller)

    async def test_grant_revoked_with_new_assessment(
        self,
        committed_world: _CommittedWorld,
        db_session_factory: Callable[[], Awaitable[AsyncSession]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        await committed_world.setting("3.1")
        user = await committed_world.user()
        granter = await committed_world.user()
        cve = await committed_world.cve((VENDOR, V31))
        ticket, _ = await committed_world.ticket(cve, is_confidential=True)
        await committed_world.grant(ticket, user, granter)
        reader = await db_session_factory()
        writer = await db_session_factory()
        caller = _restricted(user)

        async def change() -> None:
            await _commit(
                writer,
                delete(TicketAccessGrant).where(
                    TicketAccessGrant.ticket_id == ticket.id
                ),
                _add_assessment(cve, SUSE, V31_MEDIUM),
            )

        calls = _commit_after_first_statement(monkeypatch, reader, change)
        result = await _read(reader, cve, caller)

        assert calls == [1]
        assert _summary(result) == [("3.1", VENDOR, Decimal("9.8"))]
        _assert_self_consistent(result)
        with pytest.raises(CVENotFoundError):
            await _read(await db_session_factory(), cve, caller)

    async def test_last_maintained_package_excluded_with_new_assessment(
        self,
        committed_world: _CommittedWorld,
        db_session_factory: Callable[[], Awaitable[AsyncSession]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        await committed_world.setting("3.1")
        user = await committed_world.user()
        cve = await committed_world.cve((VENDOR, V31))
        _, package = await committed_world.ticket(
            cve, is_confidential=True, maintainer=user
        )
        reader = await db_session_factory()
        writer = await db_session_factory()
        caller = _restricted(user)

        async def change() -> None:
            await _commit(
                writer,
                update(TicketPackage)
                .where(TicketPackage.id == package.id)
                .values(deleted_at=datetime.now(UTC)),
                _add_assessment(cve, SUSE, V31_MEDIUM),
            )

        calls = _commit_after_first_statement(monkeypatch, reader, change)
        result = await _read(reader, cve, caller)

        assert calls == [1]
        assert _summary(result) == [("3.1", VENDOR, Decimal("9.8"))]
        _assert_self_consistent(result)
        with pytest.raises(CVENotFoundError):
            await _read(await db_session_factory(), cve, caller)

    async def test_association_changed_with_new_assessment(
        self,
        committed_world: _CommittedWorld,
        db_session_factory: Callable[[], Awaitable[AsyncSession]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        await committed_world.setting("3.1")
        cve = await committed_world.cve((VENDOR, V31))
        ticket, _ = await committed_world.ticket(None, is_confidential=True)
        reader = await db_session_factory()
        writer = await db_session_factory()

        async def change() -> None:
            await _commit(
                writer,
                update(Ticket).where(Ticket.id == ticket.id).values(cve_id=cve.id),
                _add_assessment(cve, SUSE, V31_MEDIUM),
            )

        calls = _commit_after_first_statement(monkeypatch, reader, change)
        result = await _read(reader, cve)

        assert calls == [1]
        assert _summary(result) == [("3.1", VENDOR, Decimal("9.8"))]
        _assert_self_consistent(result)
        with pytest.raises(CVENotFoundError):
            await _read(await db_session_factory(), cve)

    async def test_visibility_acquired_with_new_assessment(
        self,
        committed_world: _CommittedWorld,
        db_session_factory: Callable[[], Awaitable[AsyncSession]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        await committed_world.setting("3.1")
        user = await committed_world.user()
        granter = await committed_world.user()
        cve = await committed_world.cve((VENDOR, V31))
        ticket, _ = await committed_world.ticket(cve, is_confidential=True)
        reader = await db_session_factory()
        writer = await db_session_factory()
        caller = _restricted(user)

        async def change() -> None:
            await _commit(
                writer,
                insert(TicketAccessGrant).values(
                    ticket_id=ticket.id, user_id=user.id, granted_by_id=granter.id
                ),
                _add_assessment(cve, SUSE, V31_MEDIUM),
            )

        calls = _commit_after_first_statement(monkeypatch, reader, change)
        with pytest.raises(CVENotFoundError):
            await _read(reader, cve, caller)

        assert calls == [1]
        after = await _read(await db_session_factory(), cve, caller)
        assert _summary(after) == [
            ("3.1", VENDOR, Decimal("9.8")),
            ("3.1", SUSE, Decimal("4.8")),
        ]

    async def test_default_version_changed_with_new_suse_assessment(
        self,
        committed_world: _CommittedWorld,
        db_session_factory: Callable[[], Awaitable[AsyncSession]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        await committed_world.setting("3.1")
        cve = await committed_world.cve((SUSE, V31_MEDIUM), (VENDOR, V40))
        reader = await db_session_factory()
        writer = await db_session_factory()

        async def change() -> None:
            await _commit(
                writer,
                update(SystemSetting)
                .where(SystemSetting.key == SETTING_KEY)
                .values(value="4.0"),
                _add_assessment(cve, SUSE, V40),
            )

        calls = _commit_after_first_statement(monkeypatch, reader, change)
        result = await _read(reader, cve)

        assert calls == [1]
        assert result.default_cvss_version is CVSSVersion.V3_1
        assert _summary(result) == [
            ("4.0", VENDOR, Decimal("9.3")),
            ("3.1", SUSE, Decimal("4.8")),
        ]
        assert result.severity == SeverityResolution(
            score=Decimal("4.8"),
            version=CVSSVersion.V3_1,
            provider=SUSE,
            label=Severity.MEDIUM,
        )
        assert result.eligibility == EligibilityResolution(
            score=Decimal("4.8"), source=EligibilitySource.SUSE
        )
        _assert_self_consistent(result)

        after = await _read(await db_session_factory(), cve)
        assert after.default_cvss_version is CVSSVersion.V4_0
        assert _summary(after) == [
            ("4.0", VENDOR, Decimal("9.3")),
            ("4.0", SUSE, Decimal("9.3")),
            ("3.1", SUSE, Decimal("4.8")),
        ]
        assert after.eligibility == EligibilityResolution(
            score=Decimal("9.3"), source=EligibilitySource.SUSE
        )
        _assert_self_consistent(after)


# ---------------------------------------------------------------------------
# Preliminary CVE locator of the mutation paths (`resolve_cve_locator()`)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestResolveCVELocator:
    """The thin `require_accessible_cve` boundary role (api-spec.md, CVE
    Accessibility Check; CVE Identifier Resolution): the same malformed,
    missing, and inaccessible outcomes as the read, in one read-only
    statement."""

    @pytest.mark.parametrize("cve_id", MALFORMED_CVE_IDS)
    async def test_malformed_identifier_raises_without_any_statement(
        self, db_session: AsyncSession, cve_factory: Factory, cve_id: str
    ) -> None:
        await cve_factory(cve_id="CVE-2099-0001")

        with (
            _StatementRecorder(db_session) as recorder,
            pytest.raises(CVENotFoundError),
        ):
            await resolve_cve_locator(db_session, cve_id, ALL_SCOPE)

        assert recorder.statements == []

    async def test_internal_uuid_is_never_accepted(
        self, db_session: AsyncSession, cve_factory: Factory
    ) -> None:
        cve: CVE = await cve_factory()

        with pytest.raises(CVENotFoundError):
            await resolve_cve_locator(db_session, str(cve.id), ALL_SCOPE)

    async def test_well_formed_missing_identifier_is_not_found(
        self, db_session: AsyncSession
    ) -> None:
        with pytest.raises(CVENotFoundError):
            await resolve_cve_locator(db_session, "CVE-2099-99999", ALL_SCOPE)

    async def test_ticketless_cve_resolves_in_one_read_only_statement(
        self, db_session: AsyncSession, cve_factory: Factory, user_factory: Factory
    ) -> None:
        cve: CVE = await cve_factory()
        user: User = await user_factory()

        with _StatementRecorder(db_session) as recorder:
            resolved = await resolve_cve_locator(
                db_session, cve.cve_id, _restricted(user)
            )

        assert resolved == ResolvedCVE(id=cve.id, cve_id=cve.cve_id)
        assert len(recorder.statements) == 1
        statement = recorder.statements[0]
        assert statement.lstrip().upper().startswith("SELECT")
        assert "FOR UPDATE" not in statement
        assert "FOR SHARE" not in statement

    async def test_confidential_associated_cve_follows_the_canonical_predicate(
        self,
        db_session: AsyncSession,
        cve_factory: Factory,
        ticket_factory: Factory,
        user_factory: Factory,
        ticket_access_grant_factory: Factory,
        ticket_package_factory: Factory,
        ticket_package_maintainer_factory: Factory,
    ) -> None:
        hidden: CVE = await cve_factory()
        granted: CVE = await cve_factory()
        maintained: CVE = await cve_factory()
        excluded: CVE = await cve_factory()
        user: User = await user_factory()
        await ticket_factory(cve_id=hidden.id, is_confidential=True)
        granted_ticket = await ticket_factory(cve_id=granted.id, is_confidential=True)
        await ticket_access_grant_factory(ticket_id=granted_ticket.id, user_id=user.id)
        maintained_ticket = await ticket_factory(
            cve_id=maintained.id, is_confidential=True
        )
        package = await ticket_package_factory(ticket_id=maintained_ticket.id)
        await ticket_package_maintainer_factory(
            ticket_package_id=package.id, user_id=user.id
        )
        excluded_ticket = await ticket_factory(cve_id=excluded.id, is_confidential=True)
        excluded_package = await ticket_package_factory(
            ticket_id=excluded_ticket.id, deleted_at=CREATED_AT
        )
        await ticket_package_maintainer_factory(
            ticket_package_id=excluded_package.id, user_id=user.id
        )
        caller = _restricted(user)

        for cve in (granted, maintained):
            resolved = await resolve_cve_locator(db_session, cve.cve_id, caller)
            assert resolved.id == cve.id
        for cve in (hidden, excluded):
            with pytest.raises(CVENotFoundError) as denied:
                await resolve_cve_locator(db_session, cve.cve_id, caller)
            with pytest.raises(CVENotFoundError) as missing:
                await resolve_cve_locator(db_session, "CVE-2099-99999", caller)
            assert str(denied.value) == str(missing.value)
        for cve in (hidden, excluded):
            resolved = await resolve_cve_locator(db_session, cve.cve_id, ALL_SCOPE)
            assert resolved.id == cve.id


# ---------------------------------------------------------------------------
# Shared item projection of a mutation result (`project_cvss_assessment()`)
# ---------------------------------------------------------------------------


@pytest.mark.integration
@pytest.mark.usefixtures("default_setting")
class TestProjectCVSSAssessment:
    async def test_projects_the_same_item_as_the_read(
        self,
        db_session: AsyncSession,
        cve_factory: Factory,
        cve_cvss_assessment_factory: Factory,
    ) -> None:
        cve: CVE = await cve_factory()
        assessment = await cve_cvss_assessment_factory(
            cve_id=cve.id,
            provider_name=SUSE,
            created_at=CREATED_AT,
            updated_at=UPDATED_AT,
            **_unit(V40),
        )

        with _StatementRecorder(db_session) as recorder:
            projection = project_cvss_assessment(cve.cve_id, assessment)

        assert recorder.statements == []
        (read,) = (await _read(db_session, cve)).assessments
        assert projection == read

    async def test_inconsistent_instance_is_logged_and_raised(
        self,
        db_session: AsyncSession,
        cve_factory: Factory,
        cve_cvss_assessment_factory: Factory,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        cve: CVE = await cve_factory()
        corrupt = await cve_cvss_assessment_factory(
            cve_id=cve.id, provider_name=SUSE, **{**_unit(V31), "score": Decimal("9.7")}
        )

        with caplog.at_level("ERROR"), pytest.raises(CVSSAssessmentIntegrityError):
            project_cvss_assessment(cve.cve_id, corrupt)

        events = _integrity_events(caplog)
        assert [(e["assessment_id"], e["fields"]) for e in events] == [
            (str(corrupt.id), ["score"])
        ]
