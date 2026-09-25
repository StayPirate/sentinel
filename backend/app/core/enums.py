"""Static enumerations shared across the application.

Every enumerated column in the schema is validated against a `StrEnum`
defined in this module — both Category A (state-machine, additionally
protected by a database CHECK constraint) and Category B (classification,
validated only in Python). See `docs/conventions.md` (Enum Storage
Strategy) for the classification criterion.
"""

from __future__ import annotations

from enum import StrEnum


class Role(StrEnum):
    """Sentinel platform roles.

    Category A — state-machine (VARCHAR + CHECK constraints:
    `chk_user_role_role_valid` on `user_role`,
    `chk_role_mapping_role_valid` on `role_mapping`). Adding a value
    requires an Alembic migration. See `docs/features/identity/rbac.md`
    (Predefined Roles) and `docs/data-model.md` (Role Enum).
    """

    ADMIN = "Admin"
    VULNERABILITY_ANALYST = "Vulnerability Analyst"
    RESTRICTED_ANALYST = "Restricted Analyst"


class Capability(StrEnum):
    """Static capabilities granted by roles.

    Category B — classification (Python Enum only, no CHECK constraint;
    capabilities are never stored in the database). See
    `docs/features/identity/rbac.md` (Capabilities) for the full
    description of the operations each capability covers.
    """

    # Vulnerability Analyst capabilities
    CREATE_TICKET = "create_ticket"
    TRIAGE_TICKET = "triage_ticket"
    MANAGE_PACKAGES = "manage_packages"
    MANAGE_CVSS = "manage_cvss"
    MANAGE_REFERENCES = "manage_references"
    MANAGE_CONFIDENTIALITY = "manage_confidentiality"

    # Admin capabilities
    MANAGE_USERS = "manage_users"
    MANAGE_ROLE_MAPPINGS = "manage_role_mappings"
    MANAGE_SETTINGS = "manage_settings"
    MANAGE_FETCHERS = "manage_fetchers"
    ADMIN_TICKET_OPS = "admin_ticket_ops"


class Scope(StrEnum):
    """Default visibility scope for confidential tickets.

    Category B — classification (Python Enum only, never stored in the
    database; scope is a static, code-resolved property of a role). See
    `docs/features/identity/rbac.md` (Scope).
    """

    ALL = "all"
    NON_CONFIDENTIAL = "non_confidential"


class HealthCheckStatus(StrEnum):
    """Result value of a single readiness dependency check.

    Category B — classification (Python Enum only; never stored in the
    database — readiness results are never persisted). See
    `docs/features/platform/health-endpoints.md` (Check result values,
    Readiness — GET /ready) for the severity order used when aggregating
    multiple Redis instance results: `OK < TIMEOUT < UNREACHABLE`.
    """

    OK = "ok"
    TIMEOUT = "timeout"
    UNREACHABLE = "unreachable"


class IdentityAuditEventType(StrEnum):
    """Classifies the action recorded in an `IdentityAuditEvent`.

    Category B — classification (Python Enum only, no CHECK constraint;
    adding a value requires only a code change). See
    `docs/features/identity/identity-audit-log.md` (IdentityAuditEventType
    Enum) for the full event type contract: trigger, actor/target
    semantics, and `old_value`/`new_value`/`detail` field values per
    event type.
    """

    USER_CREATED = "user_created"
    USER_DEACTIVATED = "user_deactivated"
    USER_REACTIVATED = "user_reactivated"
    PASSWORD_RESET = "password_reset"  # classification value # nosec B105
    ROLE_ADDED = "role_added"
    ROLE_REMOVED = "role_removed"
    ROLE_MAPPING_CREATED = "role_mapping_created"
    ROLE_MAPPING_DELETED = "role_mapping_deleted"
    USERNAME_CHANGED = "username_changed"
    API_KEY_CREATED = "api_key_created"
    API_KEY_REVOKED = "api_key_revoked"
    EMAIL_CHANGED = "email_changed"
    FULL_NAME_CHANGED = "full_name_changed"
    MANAGER_CHANGED = "manager_changed"


class SettingAuditEventType(StrEnum):
    """Classifies the action recorded in a `SettingAuditEvent`.

    Category B — classification (Python Enum only, no CHECK constraint;
    adding a value requires only a code change). See
    `docs/features/platform/system-settings.md` (Setting Audit Log) for
    the full event type contract.
    """

    SETTING_CHANGED = "setting_changed"


class FetcherRunStatus(StrEnum):
    """Execution outcome of a `FetcherRun`.

    Category A — state-machine (VARCHAR + CHECK constraint
    `chk_fetcher_run_status_valid`; adding a value requires an Alembic
    migration). See `docs/features/platform/fetcher-infrastructure.md`
    (FetcherRunStatus Enum) for the full status determination
    precedence and lifecycle transitions.
    """

    QUEUED = "queued"
    RUNNING = "running"
    SUCCESS = "success"
    FAILURE = "failure"
    PARTIAL = "partial"


class FetcherRunTriggeredBy(StrEnum):
    """How a `FetcherRun` was initiated.

    Category B — classification (Python Enum only, no CHECK constraint;
    adding a value requires only a code change). See
    `docs/features/platform/fetcher-infrastructure.md`
    (FetcherRunTriggeredBy Enum).
    """

    SCHEDULE = "schedule"
    MANUAL = "manual"


class FetcherAuditEventType(StrEnum):
    """Classifies the action recorded in a `FetcherAuditEvent`.

    Category B — classification (Python Enum only, no CHECK constraint;
    adding a value requires only a code change). See
    `docs/features/platform/fetcher-infrastructure.md`
    (FetcherAuditEventType Enum, Event Field Values) for the field value
    contract, and `docs/features/platform/fetcher-operations.md`
    (`update_fetcher_config`) for the one-event-per-changed-field rule.
    """

    DISABLED = "disabled"
    ENABLED = "enabled"
    TRIGGERED = "triggered"
    CONFIG_CHANGED = "config_changed"


class SessionCreationReason(StrEnum):
    """The login provider that created a `Session`.

    Category B — classification (Python Enum only; never stored in the
    database — used only for the `session_created` operational log
    event). See `docs/features/identity/authentication.md` (Session
    creation).
    """

    LOCAL_LOGIN = "local_login"
    SSO_LOGIN = "sso_login"


class SessionInvalidationReason(StrEnum):
    """The trigger for a bulk session invalidation
    (`session_service.invalidate_user_sessions()`).

    Category B — classification (Python Enum only; never stored in the
    database — used only for the `sessions_invalidated` operational log
    event). See `docs/features/identity/authentication.md` (Session
    invalidation).
    """

    DEACTIVATION = "deactivation"
    PASSWORD_RESET = "password_reset"  # nosec B105 -- classification value, not a credential


class ApiKeyStatus(StrEnum):
    """Derived, non-persisted lifecycle status of an `ApiKey`.

    Category B — classification (Python Enum only; never stored in the
    database — status is computed at read time from `revoked_at` and
    `expires_at`). See `docs/features/identity/api-key-management.md`
    (Derived Status) for the exclusive precedence rule:
    `revoked` > `expired` > `active`.
    """

    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"


class ApiKeySortField(StrEnum):
    """Sortable fields for API key list queries.

    Category B — classification (Python Enum only; never stored in the
    database). See `docs/features/identity/api-key-management.md` (API)
    for the supported fields and `docs/features/identity/api-key-service.md`
    (`list_user_keys()`, `list_all_keys()`) for their use.
    """

    CREATED_AT = "created_at"
    LAST_USED_AT = "last_used_at"


class SortOrder(StrEnum):
    """Sort direction shared by every sortable list query.

    Category B — classification (Python Enum only; never stored in the
    database). See `docs/api-spec.md` (Sorting) for the shared pagination
    and sorting contract.
    """

    ASC = "asc"
    DESC = "desc"


class CredentialKind(StrEnum):
    """How a request was authenticated.

    Category B — classification (Python Enum only; never stored in the
    database — carried only in the in-memory `AuthenticatedPrincipal`).
    See `docs/features/identity/authentication.md` (`CredentialKind`).
    """

    JWT = "jwt"
    API_KEY = "api_key"


class UserType(StrEnum):
    """Local vs external authentication origin filter for user queries.

    Category B — classification (Python Enum only; never stored in the
    database — `User.source` is a derived field, never a persisted
    column). See `docs/features/identity/user-management.md` (List
    Users).
    """

    LOCAL = "local"
    EXTERNAL = "external"


class UserSortField(StrEnum):
    """Sortable fields for the public user directory list query.

    Category B — classification (Python Enum only; never stored in the
    database). See `docs/features/identity/user-management.md` (List
    Users) for the supported fields and NULL-placement rule for
    `full_name`.
    """

    USERNAME = "username"
    FULL_NAME = "full_name"
    EMAIL = "email"
    CREATED_AT = "created_at"


class CVSSVersion(StrEnum):
    """Accepted CVSS Base-vector versions, always derived from the vector.

    Category B — classification (Python Enum only; stored in
    `CVECVSSAssessment.cvss_version`, a closed vector-derived set). See
    `docs/features/tickets/cvss-scoring.md` (Accepted Base Vectors) and
    `docs/data-model.md` (CVECVSSAssessment).
    """

    V2_0 = "2.0"
    V3_0 = "3.0"
    V3_1 = "3.1"
    V4_0 = "4.0"


class CVSSAssessmentSeverity(StrEnum):
    """Version-specific severity of one CVSS assessment.

    Category B — classification (Python Enum only; stored lowercase in
    `CVECVSSAssessment.severity`). CVSS v2.0 produces only `low`,
    `medium`, or `high`; v3.0, v3.1, and v4.0 use the full FIRST scale.
    Distinct from the unified `Severity`. See
    `docs/features/tickets/cvss-scoring.md` (Version-Specific Assessment
    Severity).
    """

    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Severity(StrEnum):
    """Unified five-label severity scale.

    Category B — classification (Python Enum only; stored in PascalCase
    in `CVE.severity` and `Ticket.severity_manual`, while the API wire
    format is lowercase). The `NONE` member is the resolved label for a
    score of exactly 0.0 and is distinct from SQL `NULL` (unresolved).
    See `docs/features/tickets/cvss-scoring.md` (Unified CVE Severity)
    and `docs/data-model.md` (CVE, Ticket).
    """

    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    NONE = "None"


class EligibilitySource(StrEnum):
    """Source of an Eligibility Score Resolution result.

    Category B — classification (Python Enum only; never stored in the
    database). See `docs/features/tickets/cvss-scoring.md` (Eligibility
    Score Resolution).
    """

    SUSE = "suse"
    FALLBACK = "fallback"


# CVSS Base-metric API wire values. All are Category B classifications
# (Python Enum only; never stored in the database — expanded metrics are
# always derived from the canonical vector). See
# `docs/features/tickets/cvss-scoring.md` (Accepted Base Vectors) for the
# official vector values each wire value corresponds to. Value sets that
# the specification defines identically for CVSS v3.x and v4.0 share one
# enum.


class CVSS2AccessVector(StrEnum):
    """CVSS v2.0 Access Vector (`AV`) wire values."""

    LOCAL = "local"
    ADJACENT_NETWORK = "adjacent_network"
    NETWORK = "network"


class CVSS2AccessComplexity(StrEnum):
    """CVSS v2.0 Access Complexity (`AC`) wire values."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class CVSS2Authentication(StrEnum):
    """CVSS v2.0 Authentication (`Au`) wire values."""

    MULTIPLE = "multiple"
    SINGLE = "single"
    NONE = "none"


class CVSS2Impact(StrEnum):
    """CVSS v2.0 Confidentiality/Integrity/Availability Impact wire values."""

    NONE = "none"
    PARTIAL = "partial"
    COMPLETE = "complete"


class CVSSAttackVector(StrEnum):
    """CVSS v3.x and v4.0 Attack Vector (`AV`) wire values."""

    NETWORK = "network"
    ADJACENT = "adjacent"
    LOCAL = "local"
    PHYSICAL = "physical"


class CVSSAttackComplexity(StrEnum):
    """CVSS v3.x and v4.0 Attack Complexity (`AC`) wire values."""

    LOW = "low"
    HIGH = "high"


class CVSSPrivilegesRequired(StrEnum):
    """CVSS v3.x and v4.0 Privileges Required (`PR`) wire values."""

    NONE = "none"
    LOW = "low"
    HIGH = "high"


class CVSSImpact(StrEnum):
    """CVSS v3.x Impact and v4.0 Vulnerable/Subsequent System wire values."""

    NONE = "none"
    LOW = "low"
    HIGH = "high"


class CVSS3UserInteraction(StrEnum):
    """CVSS v3.x User Interaction (`UI`) wire values."""

    NONE = "none"
    REQUIRED = "required"


class CVSS3Scope(StrEnum):
    """CVSS v3.x Scope (`S`) wire values."""

    UNCHANGED = "unchanged"
    CHANGED = "changed"


class CVSS4AttackRequirements(StrEnum):
    """CVSS v4.0 Attack Requirements (`AT`) wire values."""

    NONE = "none"
    PRESENT = "present"


class CVSS4UserInteraction(StrEnum):
    """CVSS v4.0 User Interaction (`UI`) wire values."""

    NONE = "none"
    PASSIVE = "passive"
    ACTIVE = "active"


class TicketStatus(StrEnum):
    """Ticket lifecycle status.

    Category A — state-machine (`Ticket.status`, VARCHAR + CHECK
    constraint `chk_ticket_status_valid`, added with the Ticket model).
    Adding a value requires an Alembic migration. See
    `docs/data-model.md` (TicketStatus Enum) and
    `docs/features/tickets/tickets.md` (Ticket Lifecycle).
    """

    NEW = "New"
    ANALYSIS = "Analysis"
    ANALYZED = "Analyzed"
    RESOLVED = "Resolved"
    IGNORED = "Ignored"
    DUPLICATED = "Duplicated"


class TicketPriority(StrEnum):
    """Remediation urgency of a Ticket.

    Category B — classification (Python Enum only; stored in
    `Ticket.priority_auto` and `Ticket.priority_override`, while the API
    wire format is lowercase `p1`-`p4`). SQL `NULL` is not a level. See
    `docs/data-model.md` (TicketPriority Enum) and
    `docs/features/tickets/ticket-priority.md` (Priority Levels).
    """

    P1 = "P1"
    P2 = "P2"
    P3 = "P3"
    P4 = "P4"


class PackageStatus(StrEnum):
    """Affectedness status of a `TicketPackageTrack`.

    Category A — state-machine (VARCHAR + CHECK constraint
    `chk_ticket_package_track_status_valid`, added with the model).
    Adding a value requires an Alembic migration. See
    `docs/data-model.md` (PackageStatus Enum) and
    `docs/features/packages/package-model.md` (Axis 1: Affectedness).
    """

    ANALYSIS = "ANALYSIS"
    AFFECTED = "AFFECTED"
    NOT_AFFECTED = "NOT_AFFECTED"
    FIXED = "FIXED"
    WONT_FIX = "WONT_FIX"


class DeliveryStatus(StrEnum):
    """Delivery pipeline status of a `TicketPackageTrack`.

    Category A — state-machine (VARCHAR + CHECK constraint
    `chk_ticket_package_track_delivery_status_valid`, added with the
    model). Adding a value requires an Alembic migration. See
    `docs/data-model.md` (DeliveryStatus Enum).
    """

    PENDING = "PENDING"
    IN_PROGRESS = "IN_PROGRESS"
    RELEASED = "RELEASED"


class WorkflowType(StrEnum):
    """Workflow type assigned at `TicketPackageTrack` creation.

    Category B — classification (Python Enum only). See
    `docs/data-model.md` (WorkflowType Enum).
    """

    IBS = "ibs"
    GIT = "git"


class MilestonePhase(StrEnum):
    """Actor phase of the remediation SLA window, in execution order.

    Category B — classification (Python Enum only; never stored in the
    database — milestones are computed at read time). See
    `docs/features/tickets/ticket-deadlines.md` (Actors and Phases).
    """

    TRIAGE = "triage"
    SUBMISSION = "submission"
    UM = "um"
    QA = "qa"


class MilestoneStatus(StrEnum):
    """Status of one track milestone.

    Category B — classification (Python Enum only; never stored in the
    database). The additional `null` status (no SLA, or the phase is not
    observable) is represented by Python `None`. `PENDING` is unrelated
    to `DeliveryStatus.PENDING`. See
    `docs/features/tickets/ticket-deadlines.md` (Track Milestones).
    """

    DONE = "done"
    PENDING = "pending"
    OVERDUE = "overdue"
    NOT_APPLICABLE = "not_applicable"


class CurrentPhase(StrEnum):
    """First not-yet-completed phase of a track, or `done`.

    Category B — classification (Python Enum only; never stored in the
    database). The additional `null` value is represented by Python
    `None`. See `docs/features/tickets/ticket-deadlines.md` (Current
    Phase).
    """

    TRIAGE = "triage"
    SUBMISSION = "submission"
    UM = "um"
    QA = "qa"
    DONE = "done"


class LifecyclePhase(StrEnum):
    """Derived Product lifecycle phase, in chronological order.

    Category B — classification (Python Enum only; never stored in the
    database — the phase is derived from the four AIMAAS date projections
    and one UTC evaluation date at read time). An unavailable phase
    (absent, incomplete, or inconsistent dates) is Python `None`, exposed
    as `NULL`, and is never a member. See
    `docs/features/packages/product-catalog.md` (Product Lifecycle Phases,
    Lifecycle Evaluator).
    """

    PRE_RELEASE = "pre_release"
    GENERAL_SUPPORT = "general_support"
    EXTENDED_SUPPORT = "extended_support"
    REACTIVE_SUPPORT = "reactive_support"
    EOL = "eol"
