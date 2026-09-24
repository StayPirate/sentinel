"""Tests for static enumerations (backend/app/core/enums.py).

Each test class cites the specification section that owns its enum,
for example docs/features/identity/rbac.md (Authorization Model),
docs/data-model.md (Role Enum), and docs/features/tickets/cvss-scoring.md
(Accepted Base Vectors, Severity, Eligibility Score Resolution).
"""

from __future__ import annotations

from enum import StrEnum

import pytest

from app.core.enums import (
    Capability,
    CredentialKind,
    CVSS2AccessComplexity,
    CVSS2AccessVector,
    CVSS2Authentication,
    CVSS2Impact,
    CVSS3Scope,
    CVSS3UserInteraction,
    CVSS4AttackRequirements,
    CVSS4UserInteraction,
    CVSSAssessmentSeverity,
    CVSSAttackComplexity,
    CVSSAttackVector,
    CVSSImpact,
    CVSSPrivilegesRequired,
    CVSSVersion,
    EligibilitySource,
    FetcherAuditEventType,
    FetcherRunStatus,
    FetcherRunTriggeredBy,
    HealthCheckStatus,
    IdentityAuditEventType,
    Role,
    Scope,
    SettingAuditEventType,
    Severity,
    UserSortField,
    UserType,
)


@pytest.mark.unit
class TestRoleEnum:
    """Role must have exactly the three members defined in rbac.md."""

    def test_exact_members(self) -> None:
        assert {member.name for member in Role} == {
            "ADMIN",
            "VULNERABILITY_ANALYST",
            "RESTRICTED_ANALYST",
        }

    def test_db_values(self) -> None:
        """DB storage values match the Role Enum table in data-model.md."""
        assert Role.ADMIN.value == "Admin"
        assert Role.VULNERABILITY_ANALYST.value == "Vulnerability Analyst"
        assert Role.RESTRICTED_ANALYST.value == "Restricted Analyst"


@pytest.mark.unit
class TestCapabilityEnum:
    """Capability must have exactly the 11 members defined in rbac.md."""

    def test_exact_members(self) -> None:
        assert {member.value for member in Capability} == {
            "create_ticket",
            "triage_ticket",
            "manage_packages",
            "manage_cvss",
            "manage_references",
            "manage_confidentiality",
            "manage_users",
            "manage_role_mappings",
            "manage_settings",
            "manage_fetchers",
            "admin_ticket_ops",
        }

    def test_count(self) -> None:
        assert len(list(Capability)) == 11


@pytest.mark.unit
class TestScopeEnum:
    """Scope must have exactly the two members defined in rbac.md."""

    def test_exact_members(self) -> None:
        assert {member.value for member in Scope} == {"all", "non_confidential"}


@pytest.mark.unit
class TestHealthCheckStatusEnum:
    """HealthCheckStatus must have exactly the three members defined in
    health-endpoints.md (Check result values)."""

    def test_exact_members(self) -> None:
        assert {member.value for member in HealthCheckStatus} == {
            "ok",
            "timeout",
            "unreachable",
        }


@pytest.mark.unit
class TestIdentityAuditEventTypeEnum:
    """IdentityAuditEventType must have exactly the 14 members defined
    in identity-audit-log.md (IdentityAuditEventType Enum)."""

    def test_exact_members(self) -> None:
        assert {member.value for member in IdentityAuditEventType} == {
            "user_created",
            "user_deactivated",
            "user_reactivated",
            "password_reset",
            "role_added",
            "role_removed",
            "role_mapping_created",
            "role_mapping_deleted",
            "username_changed",
            "api_key_created",
            "api_key_revoked",
            "email_changed",
            "full_name_changed",
            "manager_changed",
        }

    def test_count(self) -> None:
        assert len(list(IdentityAuditEventType)) == 14


@pytest.mark.unit
class TestSettingAuditEventTypeEnum:
    """SettingAuditEventType must have exactly the one member defined
    in system-settings.md (Setting Audit Log)."""

    def test_exact_members(self) -> None:
        assert {member.value for member in SettingAuditEventType} == {
            "setting_changed",
        }

    def test_count(self) -> None:
        assert len(list(SettingAuditEventType)) == 1


@pytest.mark.unit
class TestFetcherRunStatusEnum:
    """FetcherRunStatus must have exactly the five members defined in
    fetcher-infrastructure.md (FetcherRunStatus Enum)."""

    def test_exact_members(self) -> None:
        assert {member.value for member in FetcherRunStatus} == {
            "queued",
            "running",
            "success",
            "failure",
            "partial",
        }

    def test_count(self) -> None:
        assert len(list(FetcherRunStatus)) == 5


@pytest.mark.unit
class TestFetcherRunTriggeredByEnum:
    """FetcherRunTriggeredBy must have exactly the two members defined
    in fetcher-infrastructure.md (FetcherRunTriggeredBy Enum)."""

    def test_exact_members(self) -> None:
        assert {member.value for member in FetcherRunTriggeredBy} == {
            "schedule",
            "manual",
        }

    def test_count(self) -> None:
        assert len(list(FetcherRunTriggeredBy)) == 2


@pytest.mark.unit
class TestFetcherAuditEventTypeEnum:
    """FetcherAuditEventType must have exactly the four members defined
    in fetcher-infrastructure.md (FetcherAuditEventType Enum)."""

    def test_exact_members(self) -> None:
        assert {member.value for member in FetcherAuditEventType} == {
            "disabled",
            "enabled",
            "triggered",
            "config_changed",
        }

    def test_count(self) -> None:
        assert len(list(FetcherAuditEventType)) == 4


@pytest.mark.unit
class TestCredentialKindEnum:
    """CredentialKind must have exactly the two members defined in
    authentication.md (`CredentialKind`)."""

    def test_exact_members(self) -> None:
        assert {member.value for member in CredentialKind} == {"jwt", "api_key"}

    def test_values(self) -> None:
        assert CredentialKind.JWT.value == "jwt"
        assert CredentialKind.API_KEY.value == "api_key"


@pytest.mark.unit
class TestUserTypeEnum:
    """UserType must have exactly the two members defined in
    user-management.md (List Users)."""

    def test_exact_members(self) -> None:
        assert {member.value for member in UserType} == {"local", "external"}


@pytest.mark.unit
class TestUserSortFieldEnum:
    """UserSortField must have exactly the four members defined in
    user-management.md (List Users)."""

    def test_exact_members(self) -> None:
        assert {member.value for member in UserSortField} == {
            "username",
            "full_name",
            "email",
            "created_at",
        }


@pytest.mark.unit
class TestCVSSVersionEnum:
    """CVSSVersion is the closed vector-derived set in cvss-scoring.md
    (Accepted Base Vectors) and data-model.md (CVECVSSAssessment)."""

    def test_exact_values(self) -> None:
        assert [member.value for member in CVSSVersion] == ["2.0", "3.0", "3.1", "4.0"]


@pytest.mark.unit
class TestCVSSAssessmentSeverityEnum:
    """Version-specific assessment severity is stored lowercase
    (data-model.md, CVECVSSAssessment.severity)."""

    def test_exact_values_are_lowercase(self) -> None:
        assert {member.value for member in CVSSAssessmentSeverity} == {
            "none",
            "low",
            "medium",
            "high",
            "critical",
        }


@pytest.mark.unit
class TestSeverityEnum:
    """Unified Severity is stored in PascalCase (data-model.md, CVE.severity
    and Ticket.severity_manual); `None` is a label, not SQL NULL."""

    def test_stored_values_are_pascal_case(self) -> None:
        assert Severity.CRITICAL.value == "Critical"
        assert Severity.HIGH.value == "High"
        assert Severity.MEDIUM.value == "Medium"
        assert Severity.LOW.value == "Low"
        assert Severity.NONE.value == "None"

    def test_count(self) -> None:
        assert len(list(Severity)) == 5

    def test_none_label_is_a_string_distinct_from_python_none(self) -> None:
        assert Severity("None") is Severity.NONE
        assert Severity.NONE is not None
        assert isinstance(Severity.NONE, str)


@pytest.mark.unit
class TestEligibilitySourceEnum:
    """EligibilitySource per cvss-scoring.md (Eligibility Score Resolution)."""

    def test_exact_values(self) -> None:
        assert {member.value for member in EligibilitySource} == {"suse", "fallback"}


@pytest.mark.unit
class TestCVSSMetricWireValueEnums:
    """Base-metric API wire values match the tables in cvss-scoring.md
    (Accepted Base Vectors): lowercase with underscores."""

    @pytest.mark.parametrize(
        ("enum_type", "expected"),
        [
            (CVSS2AccessVector, {"local", "adjacent_network", "network"}),
            (CVSS2AccessComplexity, {"high", "medium", "low"}),
            (CVSS2Authentication, {"multiple", "single", "none"}),
            (CVSS2Impact, {"none", "partial", "complete"}),
            (CVSSAttackVector, {"network", "adjacent", "local", "physical"}),
            (CVSSAttackComplexity, {"low", "high"}),
            (CVSSPrivilegesRequired, {"none", "low", "high"}),
            (CVSSImpact, {"none", "low", "high"}),
            (CVSS3UserInteraction, {"none", "required"}),
            (CVSS3Scope, {"unchanged", "changed"}),
            (CVSS4AttackRequirements, {"none", "present"}),
            (CVSS4UserInteraction, {"none", "passive", "active"}),
        ],
    )
    def test_exact_wire_values(
        self, enum_type: type[StrEnum], expected: set[str]
    ) -> None:
        assert {member.value for member in enum_type} == expected
