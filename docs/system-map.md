# System Map

Visual overview of the Sentinel platform. This document provides navigational
diagrams to understand how components, data, and features relate to each
other. For full details, follow the links to the relevant specification
documents.

## Table of Contents

- [System Components](#system-components)
- [Data Model](#data-model)
- [Data Flows](#data-flows)
  - [CVE Ingestion](#cve-ingestion)
  - [Package and Release Tracking](#package-and-release-tracking)
  - [Ticket Lifecycle](#ticket-lifecycle)
  - [Ticket Status Zones](#ticket-status-zones)
- [Feature Specification Map](#feature-specification-map)

---

## System Components

How the main components of Sentinel connect to each other and to external
services. See [architecture.md](architecture.md) for architectural
decisions and design constraints.

```mermaid
flowchart TB
    subgraph backend["Backend"]
        API["FastAPI API<br/>(api/v1/)"]
        SVC["Services<br/>(business logic)"]
        MDL["SQLAlchemy Models"]
        API --> SVC --> MDL
    end

    subgraph taskqueue["Task Queue"]
        BEAT["Celery Beat<br/>(scheduler)"]
        WORKER["Celery Workers<br/>(background tasks)"]
        GITWORKER["Git Worker<br/>(git-based fetchers)"]
        BEAT -->|triggers| WORKER
        BEAT -->|triggers| GITWORKER
    end

    subgraph datastores["Data Stores"]
        PG[("PostgreSQL")]
        RD[("Redis<br/>(broker + cache +<br/>ephemeral status)")]
    end

    CONSUMER["IBS RabbitMQ<br/>Consumer"]

    subgraph external["External Services"]
        NVD["NVD<br/>(services.nvd.nist.gov)"]
        MITRE["MITRE cvelistV5<br/>(github.com)"]
        KERNEL["Linux Kernel<br/>(git.kernel.org)"]
        REDHAT["Red Hat<br/>(access.redhat.com)"]
        IBS["IBS<br/>(build.suse.de)"]
        SMELT["SMELT<br/>(smelt.suse.de)"]
        AIMAAS["AIMAAS<br/>(aimaas.suse.de)"]
        RABBIT["IBS RabbitMQ<br/>(rabbit.suse.de)"]
        IDP["SUSE IdP<br/>(id.suse.com)"]
    end

    MDL --> PG
    WORKER --> PG
    WORKER <--> RD
    GITWORKER --> PG
    GITWORKER <--> RD
    BEAT <--> RD
    CONSUMER -->|"inline domain writes"| PG

    API -->|"OIDC/SSO"| IDP

    WORKER -->|"REST API"| NVD
    WORKER -->|"REST API"| REDHAT
    WORKER -->|"REST API"| IBS
    WORKER -->|"REST API"| SMELT
    WORKER -->|"REST API"| AIMAAS

    GITWORKER -->|"Git (clone/fetch)"| MITRE
    GITWORKER -->|"Git (clone/fetch)"| KERNEL

    CONSUMER -->|"AMQP"| RABBIT
    CONSUMER -->|"current request/source state"| IBS
    CONSUMER -->|"best-effort heartbeat"| RD

    style backend fill:#fef3c7,stroke:#d97706
    style taskqueue fill:#fce7f3,stroke:#db2777
    style datastores fill:#d1fae5,stroke:#059669
    style external fill:#f3e8ff,stroke:#7c3aed
```

---

## Data Model

Entity-relationship diagram showing all database tables and their
connections. Only primary keys and foreign keys are shown for readability.
See [data-model.md](data-model.md) for full column details.

The diagram contains 34 physical tables across the groups summarized below.

```mermaid
erDiagram
    CVE {
        UUID id PK
        VARCHAR cve_id UK
        VARCHAR severity
        VARCHAR cve_state
    }

    CVESource {
        UUID id PK
        UUID cve_id FK
        VARCHAR source
        VARCHAR status
    }

    CVECVSSAssessment {
        UUID id PK
        UUID cve_id FK
        VARCHAR provider_name
        VARCHAR cvss_version
        DECIMAL score
    }

    CVEExternalIdentifier {
        UUID id PK
        UUID cve_id FK
        VARCHAR source
        VARCHAR identifier
    }

    CVEAffectedVersion {
        UUID id PK
        UUID cve_id FK
        VARCHAR source_container
        VARCHAR vendor "nullable"
        VARCHAR product "nullable"
    }

    CVECWE {
        UUID id PK
        UUID cve_id FK
        VARCHAR cwe_id
        VARCHAR source
    }

    CVESSVCAssessment {
        UUID id PK
        UUID cve_id FK "unique"
        VARCHAR exploitation
    }

    CVEKEVEntry {
        UUID id PK
        UUID cve_id FK "unique"
        DATE date_added
    }

    CVEEPSSScore {
        UUID id PK
        UUID cve_id FK "unique"
        FLOAT score
        FLOAT percentile
    }

    Ticket {
        UUID id PK
        INTEGER sequence_id UK
        UUID cve_id FK "nullable, unique"
        VARCHAR status
        BOOLEAN is_confidential
        UUID assignee_id FK "nullable"
        UUID duplicate_of_id FK "nullable, self-ref"
    }

    TicketAuditEvent {
        UUID id PK
        UUID ticket_id FK
        UUID user_id FK "nullable"
        VARCHAR event_type
    }

    TicketAccessGrant {
        UUID ticket_id PK_FK
        UUID user_id PK_FK
        UUID granted_by_id FK
    }

    TicketReference {
        UUID id PK
        UUID ticket_id FK
        TEXT url
    }

    TicketPackage {
        UUID id PK
        UUID ticket_id FK
        VARCHAR package_name
    }
    TicketPackageMaintainer {
        UUID id PK
        UUID ticket_package_id FK
        UUID user_id FK
    }

    TicketPackageTrack {
        UUID id PK
        UUID ticket_package_id FK
        VARCHAR workflow_type
        VARCHAR reference
        VARCHAR status
        VARCHAR delivery_status
    }

    TicketPackageProduct {
        UUID id PK
        UUID ticket_package_track_id FK
        UUID product_id FK
        BOOLEAN eligible
        BOOLEAN is_eligible_override
        TIMESTAMPTZ released_at "nullable"
    }

    Product {
        UUID id PK
        VARCHAR cpe UK
        VARCHAR name
        VARCHAR version
        DECIMAL cvss_threshold "nullable"
        DATE first_customer_ship_date "nullable"
        DATE general_support_end_date "nullable"
        DATE extended_support_end_date "nullable"
        DATE reactive_support_end_date "nullable"
        TIMESTAMPTZ catalog_last_seen_at
    }

    ProductRepository {
        UUID id PK
        UUID product_id FK
        VARCHAR repo_name
        TIMESTAMPTZ catalog_last_seen_at
    }

    User {
        UUID id PK
        VARCHAR username UK
        VARCHAR email UK
        UUID external_id "UNIQUE, nullable"
        UUID manager_id FK "nullable"
    }

    UserRole {
        UUID id PK
        UUID user_id FK
        VARCHAR role
        VARCHAR group_name
        UUID assigned_by FK "nullable"
    }

    RoleMapping {
        UUID id PK
        VARCHAR group_name
        VARCHAR role
        UUID created_by FK
    }

    Session {
        UUID id PK
        UUID user_id FK
        TIMESTAMPTZ expires_at
        BOOLEAN is_active
    }

    ApiKey {
        UUID id PK
        UUID user_id FK
        VARCHAR key_hash UK
        VARCHAR prefix
        VARCHAR name
        TIMESTAMPTZ expires_at "nullable"
        TIMESTAMPTZ revoked_at "nullable"
        UUID revoked_by FK "nullable"
    }

    IdentityAuditEvent {
        UUID id PK
        VARCHAR event_type
        UUID user_id FK "nullable"
        UUID target_user_id FK "nullable"
    }

    SystemSetting {
        VARCHAR key PK
        VARCHAR value
    }

    SettingAuditEvent {
        UUID id PK
        VARCHAR event_type
        VARCHAR setting_key
        UUID user_id FK "nullable"
    }

    TrackReleaseCheckpoint {
        UUID id PK
        UUID ticket_package_track_id FK
        VARCHAR srcmd5
        TIMESTAMPTZ last_seen_at
    }

    IBSRequest {
        UUID id PK
        INTEGER request_number UK
        VARCHAR state
        INTEGER superseded_by_request_number "nullable"
        TIMESTAMPTZ upstream_created_at
        TIMESTAMPTZ upstream_updated_at
    }

    IBSRequestAction {
        UUID id PK
        UUID ibs_request_id FK
        VARCHAR action_type
        VARCHAR logical_package
        VARCHAR codestream_name
        INTEGER incident_number "nullable"
    }

    IBSRequestActionTrack {
        UUID id PK
        UUID ibs_request_action_id FK
        UUID ticket_package_track_id FK
    }

    FetcherConfig {
        VARCHAR fetcher_name PK
        BOOLEAN enabled
    }

    FetcherRun {
        UUID id PK
        VARCHAR fetcher_name FK
        VARCHAR status
        UUID triggered_by_user_id FK "nullable"
    }

    FetcherAuditEvent {
        UUID id PK
        VARCHAR fetcher_name FK
        VARCHAR event_type
        UUID user_id FK "nullable"
    }

    CVE ||--o{ CVESource : "has sources"
    CVE ||--o{ CVECVSSAssessment : "has assessments"
    CVE ||--o{ CVEExternalIdentifier : "has external identifiers"
    CVE ||--o{ CVEAffectedVersion : "has affected versions"
    CVE ||--o{ CVECWE : "has weaknesses"
    CVE ||--o| CVESSVCAssessment : "has SSVC assessment"
    CVE ||--o| CVEKEVEntry : "is in KEV catalog"
    CVE ||--o| CVEEPSSScore : "has EPSS score"
    CVE |o--o| Ticket : "tracked by"

    Ticket ||--o{ TicketAuditEvent : "has events"
    Ticket ||--o{ TicketAccessGrant : "has access grants"
    Ticket ||--o{ TicketReference : "has references"
    Ticket ||--o{ TicketPackage : "has packages"
    Ticket }o--o| User : "assigned to"
    Ticket }o--o| Ticket : "duplicate of"

    TicketAccessGrant }o--|| User : "granted to"
    TicketAccessGrant }o--|| User : "granted by"

    TicketPackage ||--o{ TicketPackageTrack : "has tracks"
    TicketPackage ||--o{ TicketPackageMaintainer : "has maintainers"
    TicketPackageMaintainer }o--|| User : "references"
    TicketPackageTrack ||--o{ TicketPackageProduct : "has products"
    TicketPackageTrack ||--o| TrackReleaseCheckpoint : "has release checkpoint"
    TicketPackageProduct }o--|| Product : "targets"

    Product ||--o{ ProductRepository : "has repositories"

    User ||--o{ UserRole : "has roles"
    User ||--o{ Session : "has sessions"
    User ||--o{ ApiKey : "owns keys"
    User ||--o{ TicketAuditEvent : "performed"
    RoleMapping }o--|| User : "created by"
    ApiKey }o--o| User : "revoked by"
    IdentityAuditEvent }o--o| User : "performed by"
    IdentityAuditEvent }o--o| User : "targets"

    IBSRequest ||--o{ IBSRequestAction : "has actions"
    IBSRequestAction ||--o{ IBSRequestActionTrack : "has track links"
    IBSRequestActionTrack }o--|| TicketPackageTrack : "correlates"

    FetcherConfig ||--o{ FetcherRun : "has runs"
    FetcherConfig ||--o{ FetcherAuditEvent : "has audit events"
    SystemSetting ||--o{ SettingAuditEvent : "has audit events"
    FetcherRun }o--o| User : "triggered by"
    FetcherAuditEvent }o--o| User : "performed by"
    SettingAuditEvent }o--o| User : "performed by"
```

### Entity Groups

| Group | Tables | Purpose |
|-------|--------|---------|
| **CVE Core** | CVE, CVESource, CVECVSSAssessment, CVEExternalIdentifier | Vulnerability data from external sources — drives ticket creation and severity |
| **CVE Enrichment** | CVEAffectedVersion, CVECWE, CVESSVCAssessment, CVEKEVEntry, CVEEPSSScore | Supplementary CVE intelligence from secondary sources (CISA, FIRST) |
| **Ticket Domain** | Ticket, TicketAuditEvent, TicketAccessGrant, TicketReference, TicketPackage, TicketPackageMaintainer, TicketPackageTrack, TicketPackageProduct | Security workflow, audit trail, and access control |
| **Product Domain** | Product, ProductRepository | SUSE distribution products and update repositories |
| **Identity Domain** | User, UserRole, RoleMapping, Session, ApiKey, IdentityAuditEvent | Users, roles, sessions, API keys, and identity audit trail |
| **IBS Integration** | IBSRequest, IBSRequestAction, IBSRequestActionTrack | Current IBS request parents, normalized submission/release actions, and exact track correlations |
| **Platform** | FetcherConfig, FetcherRun, FetcherAuditEvent, SystemSetting, SettingAuditEvent | Background task monitoring and system configuration |
| **Operational** | TrackReleaseCheckpoint | Per-track expanded IBS source state last successfully examined |

---

## Data Flows

### CVE Ingestion

How CVEs flow from external sources into Sentinel and trigger ticket creation.
See [features/tickets/cve-tracking.md](features/tickets/cve-tracking.md) and
[features/tickets/cvss-scoring.md](features/tickets/cvss-scoring.md).

```mermaid
flowchart LR
    subgraph sources["External Sources"]
        NVD["NVD"]
        MITRE["MITRE"]
        RH["Red Hat"]
    end

    subgraph celery["Celery Workers"]
        SYNC_NVD["sync_nvd_cves"]
        SYNC_MITRE["sync_mitre_cves"]
        SYNC_RH["sync_redhat_cves"]
    end

    subgraph store["Database Operations"]
        CVE_REC["Create/Update CVE<br/>+ CVESource"]
        CVSS_REC["Create/Update<br/>CVECVSSAssessment"]
        REF_REC["Create<br/>TicketReference"]
        SEV["Recalculate<br/>CVE.severity"]
    end

    subgraph ticket_ops["Ticket Operations"]
        NEW_TKT["Auto-create Ticket<br/>(status: New)"]
        ELIG_EVAL["Eligibility cascade<br/>(product thresholds)"]
        EVENT["Create<br/>TicketAuditEvent"]
    end

    NVD --> SYNC_NVD
    MITRE --> SYNC_MITRE
    RH --> SYNC_RH

    SYNC_NVD --> CVE_REC
    SYNC_NVD --> CVSS_REC
    SYNC_NVD --> REF_REC
    SYNC_MITRE --> CVE_REC
    SYNC_MITRE --> REF_REC
    SYNC_RH --> CVSS_REC

    CVE_REC -->|new CVE| NEW_TKT
    CVSS_REC --> SEV
    SEV --> ELIG_EVAL
    NEW_TKT --> EVENT
    ELIG_EVAL --> EVENT

    style sources fill:#f3e8ff,stroke:#7c3aed
    style celery fill:#fce7f3,stroke:#db2777
    style store fill:#d1fae5,stroke:#059669
    style ticket_ops fill:#fef3c7,stroke:#d97706
```

### Package and Release Tracking

How packages are resolved, tracked across codestreams and products, and how
releases are detected. See
[features/packages/package-model.md](features/packages/package-model.md),
[features/integrations/ibs-integration.md](features/integrations/ibs-integration.md),
[features/integrations/ibs-rabbitmq-integration.md](features/integrations/ibs-rabbitmq-integration.md),
and [features/packages/ibs-submission-tracking.md](features/packages/ibs-submission-tracking.md).

```mermaid
flowchart LR
    subgraph add_pkg["Package Addition"]
        VA_ADD["VA adds package<br/>to ticket"]
        CPE_MATCH["Auto-add via<br/>CVE ingestion"]
    end

    subgraph resolve["Resolution (on-demand)"]
        SMELT_Q["Query SMELT<br/>maintained (v2)"]
        SMELT_M["Query SMELT<br/>maintainership"]
        CREATE_CS["Create<br/>TicketPackageTrack<br/>(per codestream)"]
        CREATE_PR["Create<br/>TicketPackageProduct<br/>(per product)"]
        CREATE_PM["Create additive<br/>TicketPackageMaintainer"]
    end

    subgraph status["Track Status & Eligibility"]
        VA_SET["VA sets codestream<br/>status"]
        ELIG["Eligibility check<br/>(CVSS vs threshold)"]
        ELIG_OVR["VA overrides<br/>product eligibility"]
    end

    subgraph release["Release Detection"]
        direction TB
        RT["Real-time:<br/>IBS RabbitMQ<br/>Consumer"]
        PERIODIC["Periodic:<br/>detect_ibs_track_releases<br/>(daily 02:00 UTC)"]
        SELECT["Select exact existing<br/>IBS project + package tracks"]
        INFO["Targeted IBS source info<br/>(expanded srcmd5)"]
        CHECKPOINT["Per-track checkpoint<br/>(TrackReleaseCheckpoint)"]
        DIFF["Expanded IBS diff<br/>(canonical Ticket CVE)"]
        CS_REL["Codestream → FIXED"]

        RT --> SELECT
        PERIODIC --> SELECT
        SELECT --> INFO
        INFO --> CHECKPOINT
        CHECKPOINT --> DIFF
        DIFF --> CS_REL
    end

    subgraph prod_release["Product Release"]
        PROD_PERIODIC["detect_ibs_product_releases<br/>(daily 04:00 UTC)"]
        REPOS["Current repositories,<br/>then historical fallback"]
        UINFO["Validate repomd + updateinfo<br/>integrity and resource bounds"]
        MATCH["Stable security advisory<br/>+ exact CVE/source package"]
        PKG_SVC["package_service<br/>atomic mutation + audit"]
        PR_REL["Product released_at set<br/>to advisory-issued UTC time"]

        PROD_PERIODIC --> REPOS --> UINFO --> MATCH --> PKG_SVC --> PR_REL
    end

    subgraph request_delivery["IBS Request and Delivery Reconciliation"]
        direction TB
        REQ_EVENT["IBS RabbitMQ consumer:<br/>inline request-number wake-up"]
        REQ_PERIODIC["sync_ibs_requests<br/>(daily 02:30 UTC)"]
        REQ_CATCHUP["Package-add / reactivation<br/>catch-up"]
        CURRENT["Point-fetch current request detail<br/>+ action diffs and source history"]
        SHARED["Shared authoritative<br/>track-scope reconciliation"]
        subgraph request_tx["One atomic track-scope PostgreSQL transaction"]
            REQUEST_PARENT["Upsert IBSRequest<br/>(current parent state)"]
            REQUEST_ACTION["Upsert IBSRequestAction<br/>(submission / release action)"]
            ACTION_TRACK["Upsert IBSRequestActionTrack<br/>(exact action / track join)"]
            DELIVERY["Derive TicketPackageTrack<br/>delivery_status"]
        end

        REQ_EVENT --> CURRENT
        REQ_PERIODIC --> CURRENT
        REQ_CATCHUP --> CURRENT
        CURRENT --> SHARED
        SHARED --> REQUEST_PARENT --> REQUEST_ACTION --> ACTION_TRACK --> DELIVERY
    end

    VA_ADD --> SMELT_Q
    CPE_MATCH --> SMELT_Q
    SMELT_Q --> CREATE_CS --> CREATE_PR
    SMELT_Q --> SMELT_M --> CREATE_PM
    CREATE_CS -.->|"post-commit acceleration"| REQ_CATCHUP

    VA_SET --> ELIG
    ELIG_OVR -.->|manual| ELIG

    style add_pkg fill:#e0f2fe,stroke:#0284c7
    style resolve fill:#fef3c7,stroke:#d97706
    style status fill:#d1fae5,stroke:#059669
    style release fill:#fce7f3,stroke:#db2777
    style prod_release fill:#f3e8ff,stroke:#7c3aed
    style request_delivery fill:#ede9fe,stroke:#7c3aed
```

### Ticket Lifecycle

State machine for ticket status transitions. Gates control automatic
transitions between Analysis, Analyzed, and Resolved. See
[features/tickets/tickets.md](features/tickets/tickets.md).

```mermaid
flowchart TD
    NEW["🔵 New"]
    ANALYSIS["🟡 Analysis"]
    ANALYZED["🟢 Analyzed"]
    RESOLVED["✅ Resolved"]
    IGNORED["⚪ Ignored"]
    DUPLICATED["🔗 Duplicated"]

    NEW -->|"assignment or<br/>any modifying operation"| ANALYSIS
    NEW -->|"manual or<br/>NVD rejection"| IGNORED

    ANALYSIS -->|"✓ all gates met:<br/>≥1 package,<br/>no ANALYSIS statuses,<br/>severity set,<br/>SUSE CVSS (if CVE)"| ANALYZED
    ANALYSIS -->|"manual"| IGNORED

    ANALYZED -->|"✓ all tracks<br/>resolution-complete"| RESOLVED
    ANALYZED -->|"gate conditions<br/>no longer met"| ANALYSIS

    RESOLVED -->|"resolved gates broken,<br/>analyzed gates still met"| ANALYZED
    RESOLVED -->|"both gates broken"| ANALYSIS

    NEW -->|"manual"| DUPLICATED
    ANALYSIS -->|"manual"| DUPLICATED
    ANALYZED -->|"manual"| DUPLICATED
    RESOLVED -->|"manual"| DUPLICATED

    DUPLICATED -->|"revert:<br/>_reenter_gate_zone"| ANALYSIS
    IGNORED -->|"reopen:<br/>_reenter_gate_zone"| ANALYSIS

    style NEW fill:#dbeafe,stroke:#2563eb
    style ANALYSIS fill:#fef9c3,stroke:#ca8a04
    style ANALYZED fill:#dcfce7,stroke:#16a34a
    style RESOLVED fill:#d1fae5,stroke:#059669
    style IGNORED fill:#f3f4f6,stroke:#6b7280
    style DUPLICATED fill:#e0e7ff,stroke:#4f46e5
```

**Analyzed gate** (all must be true):
- At least one manually included `TicketPackageTrack`
- No actionable `TicketPackageTrack` in `ANALYSIS` status
- Severity is determined (not `NULL`)
- If CVE is associated: SUSE CVSS v3.1 and v4.0 assessments exist

**Resolved gate**: every actionable `TicketPackageTrack` is
resolution-complete: (a) `NOT_AFFECTED`/`WONT_FIX`, or (b) `FIXED` with
all actionable eligible Products having `released_at IS NOT NULL`, or
(c) `AFFECTED` with no actionable eligible Products. Actionability combines
manual hierarchical exclusion with derived Product EOL; it is not persisted.
Delivery status
(`PENDING`/`IN_PROGRESS`/`RELEASED`) is tracked independently for workflow
visibility but is not a gate condition.

### Ticket Status Zones

The ticket state machine is divided into distinct zones that determine how
status transitions are governed. See
[features/tickets/ticket-mutations.md](features/tickets/ticket-mutations.md)
for the authoritative zone definitions and gate evaluation logic.

```mermaid
flowchart TD
    subgraph pre["PRE-STATE"]
        direction LR
        NEW["New"]
        NOTE_PRE["reconcile_ticket_status() skips<br/>this status entirely"]
    end

    subgraph gate["GATE ZONE — automatic status via reconcile_ticket_status()"]
        direction TB
        ANALYSIS["Analysis<br/>(floor)"]
        ANALYZED["Analyzed"]
        RESOLVED["Resolved"]

        ANALYSIS -->|"Gate #1 met"| ANALYZED
        ANALYZED -->|"Gate #1 unmet"| ANALYSIS
        ANALYZED -->|"Gate #2 met"| RESOLVED
        RESOLVED -->|"Gate #2 unmet"| ANALYZED
        RESOLVED -->|"Both gates unmet"| ANALYSIS
    end

    subgraph manual["NON-GATE ZONE (Manual) — gate mutations blocked"]
        direction LR
        IGNORED["Ignored"]
        DUPLICATED["Duplicated"]
        NOTE_MANUAL["Gate-relevant mutations → 409<br/>reconcile_ticket_status() never runs"]
    end

    subgraph gates_ref["Gate Conditions"]
        direction LR
        G1["<b>Gate #1 (→ Analyzed)</b><br/>① ≥1 manually included track<br/>② all actionable tracks decided<br/>③ severity determined<br/>④ SUSE CVSS v3.1 + v4.0 (CVE only)"]
        G2["<b>Gate #2 (→ Resolved)</b><br/>Every actionable track is resolution-complete:<br/>(a) NOT_AFFECTED / WONT_FIX, or<br/>(b) FIXED + all actionable eligible Products released, or<br/>(c) AFFECTED + no actionable eligible Products"]
    end

    %% Entry from pre-state to gate zone
    NEW -->|"first assignment<br/>(irreversible)"| ANALYSIS

    %% Exit to manual zone
    NEW -->|"ignore / NVD rejection"| IGNORED
    ANALYSIS -->|"ignore"| IGNORED
    ANALYSIS -->|"mark duplicate"| DUPLICATED
    ANALYZED -->|"mark duplicate"| DUPLICATED
    RESOLVED -->|"mark duplicate"| DUPLICATED

    %% Re-entry from manual zone to gate zone
    IGNORED -->|"reopen →<br/>_reenter_gate_zone()"| ANALYSIS
    DUPLICATED -->|"revert →<br/>_reenter_gate_zone()"| ANALYSIS

    %% Styling
    style pre fill:#dbeafe,stroke:#2563eb
    style gate fill:#dcfce7,stroke:#16a34a
    style manual fill:#f3f4f6,stroke:#6b7280
    style gates_ref fill:#fef9c3,stroke:#ca8a04

    style NEW fill:#bfdbfe,stroke:#2563eb
    style ANALYSIS fill:#fef08a,stroke:#ca8a04
    style ANALYZED fill:#86efac,stroke:#16a34a
    style RESOLVED fill:#6ee7b7,stroke:#059669
    style IGNORED fill:#e5e7eb,stroke:#6b7280
    style DUPLICATED fill:#c7d2fe,stroke:#4f46e5

    style NOTE_PRE fill:none,stroke:none
    style NOTE_MANUAL fill:none,stroke:none
```

**Zone summary:**

| Zone | Statuses | Governed by | Gate mutations |
|------|----------|-------------|----------------|
| Pre-state | `New` | Explicit assignment only | Allowed but do not trigger reconciliation |
| Gate zone | `Analysis`, `Analyzed`, `Resolved` | `reconcile_ticket_status()` — sole authority | Allowed; each triggers reconciliation |
| Non-gate zone | `Ignored`, `Duplicated` | Explicit user actions | **Blocked** (`TicketNotMutableError` → 409) |

Re-entry from the non-gate zone always passes through `_reenter_gate_zone()`,
which sets the floor (`Analysis`) and calls `reconcile_ticket_status()` to
promote to the correct status in a single transaction.

---

## Feature Specification Map

How the feature specifications relate to each other. Arrows indicate
dependencies (A → B means A depends on or references B). Specs are
grouped by domain. See individual specs in [features/](features/).

```mermaid
flowchart TD
    subgraph core["Core"]
        TICKETS["tickets"]
        HISTORY["ticket-audit-log"]
        PKG["package-model"]
    end

    subgraph ingestion["Data Ingestion"]
        CVE["cve-tracking"]
        CVSS["cvss-scoring"]
        REFS["references"]
        CPE_MAP["cpe-package-mapping"]
    end

    subgraph integration["External Integration"]
        OBS["ibs-integration"]
        RABBIT["ibs-rabbitmq-integration"]
        SUBMISSION["ibs-submission-tracking"]
        TRACK_RELEASE["ibs-track-release-detection"]
        PRODUCT_RELEASE["ibs-product-release-detection"]
        MAINTAINERSHIP["package-maintainership"]
        MAINT["maintainer"]
    end

    subgraph identity["Identity and Access"]
        IDP["identity-provisioning"]
        RBAC["rbac"]
    end

    subgraph platform["Platform"]
        SETTINGS["system-settings"]
        FETCHER_INFRA["fetcher-infrastructure"]
        CVE_FETCHER_INFRA["cve-fetcher-infrastructure"]
        GIT_FETCHER_INFRA["git-fetcher-infrastructure"]
        NETWORKING["networking"]
        FETCHER["fetcher-operations"]
    end

    %% Core internal links
    TICKETS <--> PKG
    TICKETS --> HISTORY

    %% Ingestion → Core
    CVE --> TICKETS
    CVE --> CVSS
    CVE --> REFS
    CVE --> CPE_MAP
    CPE_MAP --> PKG
    CVSS --> TICKETS
    CVSS --> PKG

    %% Integration → Core
    OBS --> PKG
    RABBIT --> PKG
    RABBIT --> OBS
    RABBIT --> SUBMISSION
    SUBMISSION --> OBS
    SUBMISSION --> PKG
    TRACK_RELEASE --> OBS
    RABBIT --> TRACK_RELEASE
    TRACK_RELEASE --> PKG
    PRODUCT_RELEASE --> OBS
    PRODUCT_RELEASE --> PKG
    MAINTAINERSHIP --> PKG
    MAINT --> MAINTAINERSHIP
    MAINT --> PKG

    %% Identity → Core
    IDP --> RBAC
    RBAC --> TICKETS

    %% Platform → everything
    SETTINGS --> CVSS
    SETTINGS --> TICKETS
    FETCHER --> CVE
    FETCHER --> RABBIT

    %% History links
    HISTORY --> PKG

    style core fill:#fef3c7,stroke:#d97706
    style ingestion fill:#d1fae5,stroke:#059669
    style integration fill:#f3e8ff,stroke:#7c3aed
    style identity fill:#e0f2fe,stroke:#0284c7
    style platform fill:#fce7f3,stroke:#db2777
```

### Hub Specifications

The two most interconnected specifications, referenced by almost every
other feature:

- **[tickets](features/tickets/tickets.md)**: the central workflow entity — ticket
  creation, lifecycle, status gates, severity resolution. The service-layer
  module contract is in
  [ticket-mutations](features/tickets/ticket-mutations.md)
- **[package-model](features/packages/package-model.md)**: codestream/product
  resolution, status propagation, eligibility rules, and release detection

### Specification Index

| Spec | Domain | Summary |
|------|--------|---------|
| [tickets](features/tickets/tickets.md) | Core | Ticket entity, lifecycle, gates, severity resolution |
| [ticket-audit-log](features/tickets/ticket-audit-log.md) | Core | Audit trail via TicketAuditEvent records |
| [package-model](features/packages/package-model.md) | Core | Track affectedness, product eligibility, and release detection |
| [cve-tracking](features/tickets/cve-tracking.md) | Ingestion | CVE sync from NVD, MITRE, and other sources |
| [cvss-scoring](features/tickets/cvss-scoring.md) | Ingestion | Multi-provider CVSS assessment and severity derivation |
| [references](features/tickets/ticket-references.md) | Ingestion | External links on tickets (auto and manual) |
| [cpe-package-mapping](features/packages/cpe-package-mapping.md) | Ingestion | CPE-to-package resolution via static mapping file |
| [ibs-integration](features/integrations/ibs-integration.md) | Integration | IBS API client for source info, diffs, and requests |
| [ibs-rabbitmq-integration](features/integrations/ibs-rabbitmq-integration.md) | Integration | Real-time IBS track-release and request/submission acceleration via RabbitMQ |
| [ibs-submission-tracking](features/packages/ibs-submission-tracking.md) | Integration | Current IBS request actions, exact track correlation, and delivery reconciliation |
| [ibs-track-release-detection](features/packages/ibs-track-release-detection.md) | Integration | Existing-track reconciliation via expanded IBS source state and per-track checkpoints |
| [ibs-product-release-detection](features/packages/ibs-product-release-detection.md) | Integration | Product release reconciliation via validated stable security advisories and exact source-package matches |
| [package-maintainership](features/packages/package-maintainership.md) | Integration | SMELT package maintainer acquisition and durable package associations |
| [identity-provisioning](features/identity/identity-provisioning.md) | Identity | External identity provisioning (not yet active) |
| [rbac](features/identity/rbac.md) | Identity | Role-based access control and permissions |
| [system-settings](features/platform/system-settings.md) | Platform | System settings (default CVSS version) |
| [fetcher-infrastructure](features/platform/fetcher-infrastructure.md) | Platform | BaseFetcher base class, registry, data model |
| [cve-fetcher-infrastructure](features/platform/cve-fetcher-infrastructure.md) | Platform | BaseCVEFetcher base class, CVE fetcher conventions |
| [git-fetcher-infrastructure](features/platform/git-fetcher-infrastructure.md) | Platform | BaseGitFetcher base class, git_operations, delta flow |
| [networking](features/platform/networking.md) | Platform | Shared HTTP client factory, transport retry, TLS trust store |
| [fetcher-operations](features/platform/fetcher-operations.md) | Platform | Background task monitoring, API, and CLI diagnostics |
| [maintainer](features/packages/maintainer.md) | Integration | Maintainer-oriented package/ticket views |
