# Code Conventions

## Contents

- [Document Scope, Authority, and Navigation](#document-scope-authority-and-navigation)
- [General Principles](#general-principles)
- [Terminology](#terminology)
  - [External Identity / SSO Terminology](#external-identity--sso-terminology)
  - [Cascade / Chain / Flattening Terminology](#cascade--chain--flattening-terminology)
  - [Ticket Status Category Terminology](#ticket-status-category-terminology)
  - [Ecosystem Naming](#ecosystem-naming)
- [Cross-Cutting Rules](#cross-cutting-rules)
  - [Example Data in Documentation](#example-data-in-documentation)
  - [Username Format](#username-format)
  - [Timestamps & Timezones](#timestamps--timezones)
  - [Configuration Management](#configuration-management)
- [Python (Backend)](#python-backend)
  - [Style](#style)
  - [Type Hints](#type-hints)
  - [Static Type Checking](#static-type-checking)
  - [Naming](#naming)
- [API and Schema Conventions](#api-and-schema-conventions)
  - [FastAPI Conventions](#fastapi-conventions)
  - [Pydantic Conventions](#pydantic-conventions)
- [Database, Transactions, and State](#database-transactions-and-state)
  - [SQLAlchemy Conventions](#sqlalchemy-conventions)
    - [Async-only Database Access](#async-only-database-access)
    - [Sync-to-Async Bridging](#sync-to-async-bridging)
    - [Cross-Loop Pooled Connection Lifecycle](#cross-loop-pooled-connection-lifecycle)
  - [Enum Storage Strategy](#enum-storage-strategy)
  - [Audit Trail](#audit-trail)
  - [Transaction and Locking](#transaction-and-locking)
    - [Caller-Owned Service Transactions](#caller-owned-service-transactions)
    - [API Transaction Dependency Scope](#api-transaction-dependency-scope)
    - [Pessimistic Locking Pattern](#pessimistic-locking-pattern)
    - [Transaction Hygiene Rules](#transaction-hygiene-rules)
  - [Redis](#redis)
    - [Redis Key Conventions](#redis-key-conventions)
    - [Redis Error Handling](#redis-error-handling)
- [Runtime, Integration, and Verification](#runtime-integration-and-verification)
  - [Secret Field Typing](#secret-field-typing)
  - [Logging](#logging)
  - [Testing Conventions](#testing-conventions)
  - [External Integration Contract Verification](#external-integration-contract-verification)
  - [Runtime Version](#runtime-version)
    - [Source of Truth](#source-of-truth)
    - [Dockerfile Convention](#dockerfile-convention)
    - [Version Bump Checklist](#version-bump-checklist)
- [CLI Conventions](#cli-conventions)
  - [Output Contract](#output-contract)
- [Shell Scripting](#shell-scripting)
- [Git Conventions](#git-conventions)
  - [Workflow](#workflow)
  - [Pull Request Requirements](#pull-request-requirements)
  - [Versioning](#versioning)
- [Specification Writing](#specification-writing)
  - [Function Specification Completeness](#function-specification-completeness)
    - [Required Information](#required-information-by-function-category)
    - [Decision rule](#decision-rule)
    - [Scope and Exclusions](#scope-and-exclusions)
  - [Service Exception Conventions](#service-exception-conventions)
  - [Roadmap Independence](#roadmap-independence)

## Document Scope, Authority, and Navigation

This document defines Sentinel's technical, documentation, and Git
conventions. It owns reusable engineering patterns, naming, repository
workflow, and specification-writing rules. Product behavior and specialist
contracts for the API, data model, configuration, external sources, deployment,
and feature-specific operational outcomes remain in their corresponding
authorities.

Summaries and examples here explain how to apply a convention; they do not
replace a more specific owning contract. When this document names such an
authority, follow that authority for behavior and use this document for the
shared implementation or writing pattern. `AGENTS.md` defines when each
section and related authority must be loaded.

## General Principles

- All code, comments, docstrings, and documentation MUST be in English
- Follow the principle of least surprise: code should do what a reader expects
- Prefer explicit over implicit
- Keep functions short and focused on a single responsibility
- Apply the **API-first** and **HTTP APIs for external services** design
  constraints in `docs/architecture.md`. That document owns the consumer
  parity requirement and the distinction between prohibited service-wrapper
  CLIs and permitted transport-protocol clients. Service-wrapper CLIs available
  on the development machine MAY be used for ad-hoc exploratory testing, such
  as verifying an API response format, but never in application code or
  background tasks

## Terminology

### External Identity / SSO Terminology

These terms have distinct meanings in the Sentinel codebase and
documentation. They MUST NOT be used interchangeably:

| Term | Scope | Usage |
|------|-------|-------|
| **External** | Data origin | Prefix for columns, error classes, error codes, and CLI/API values that identify data originating from an external identity provider. Examples: `external_id`, `synced_at`, `ExternalUserStatusReadOnlyError`, `USER_EXTERNAL_STATUS_READONLY`, `--type external`, `"source": "external"` |
| **SSO** | Authentication method | Used only for the browser-based single sign-on flow (OIDC/OAuth2). Never as a user type — external users authenticate via SSO, but their identity source is the external provider |
| **SCIM** | Provisioning protocol (future) | Used only when referring to the SCIM 2.0 protocol specifically (RFC 7642-7644). The generic term for the provisioning capability is "external provisioning" |

Rules:
- A user whose `external_id IS NOT NULL` is an "external user" (not
  "LDAP user", "SSO user", or "directory user")
- A user whose `external_id IS NULL` is a "local user"
- The `source` field in API responses returns `"external"` or `"local"`

### Cascade / Chain / Flattening Terminology

These three terms have distinct meanings in the Sentinel codebase and
documentation. They MUST NOT be used interchangeably:

| Term | Concept | Usage |
|------|---------|-------|
| **cascade** | Resolution strategy | Prioritized fallback sequence that tries sources in order until a result is found. Example: "Severity Resolution Cascade" |
| **chain** | Propagation of side effects | Sequence of derived mutations triggered by a primary change. Examples: "Recalculation Chain", "Deactivation chain", "orphan chain" |
| **flattening** | Linked-list resolution | Resolution and update of pointer chains |

Rules:

- Do not use "cascade" for propagation/side-effect sequences
- The term "chain" in this convention refers exclusively to mutation
  propagation. Pre-existing domain-specific uses of "chain" in other
   contexts are unrelated and unaffected: "submission chain"
   (IBS SR/incident/RR pipeline in `maintainer.md`), "manager chain"
   (reporting hierarchy in `docs/data-model.md`), "certificate chain"
  (TLS)

### Ticket Status Category Terminology

Ticket statuses are grouped into two categories. Use the following
canonical terms consistently across all documentation and code:

| Category | Statuses | Canonical term |
|----------|----------|----------------|
| Active | `New`, `Analysis`, `Analyzed` | **active status** / **active ticket** |
| Inactive | `Resolved`, `Ignored`, `Duplicated` | **inactive status** / **inactive ticket** |

The authoritative definition of which statuses compose each set is in
`docs/features/tickets/tickets.md` (Status Categories).

Forbidden alternatives (MUST NOT be used for ticket status categories):

| Forbidden term | Why |
|----------------|-----|
| "terminal status" / "terminal state" | Semantically inaccurate — all three inactive statuses admit reverse transitions |
| "final status" (for tickets) | Reserved for `TicketPackageTrack` statuses `{NOT_AFFECTED, FIXED, WONT_FIX}` per `package-model.md` |
| "non-final" (for tickets) | Inverse of "final status" — same ambiguity |
| "non-active" | Non-standard variant; use "inactive" |
| "open tickets" / "open status" | Conflicts with IBS request states and the "Reopen" transition verb |
| "closed" / "closure" / "auto-closed" / "manually-closed" | Informal and inconsistent; no ticket status is named "Closed" |

**Disambiguation scope**: this convention applies exclusively to
**ticket** status categories. The following unrelated uses are NOT
affected:

- User lifecycle: `User.active` field, "inactive user", "active status"
  as a boolean attribute (identity domain)
- Assignee state: "inactive assignee" = user whose `active` field is
  `false` (ticket-mutations domain)
- IBS request states: `new`, `review`, `accepted`, `declined`, `revoked`,
  `superseded`, and `deleted` (IBS domain)
- IBS incident lifecycle: "incident closed" (IBS domain)
- Status transition verbs: "Reopen" (action, not state category)

### Ecosystem Naming

Sentinel uses the [OSSF OSV Schema](https://ossf.github.io/osv-schema/)
ecosystem enumeration as its canonical standard for the
`CVEAffectedVersion.ecosystem` column. Examples of canonical identifiers:
`"PyPI"`, `"npm"`, `"Go"`, `"crates.io"`, `"Maven"`, `"NuGet"`,
`"RubyGems"`, `"Packagist"`, `"Pub"`, `"Hex"`, `"GitHub Actions"`,
`"SwiftURL"`.

Rules:

- Fetchers whose upstream source uses OSSF canonical ecosystem identifiers
  natively (e.g., `sync_osv_advisories`) store the values as-is — no
  normalization required
- Fetchers whose upstream source uses non-canonical names (e.g.,
  `sync_ghsa_advisories` receives GitHub's `"pip"` instead of `"PyPI"`)
  MUST normalize to OSSF canonical values before storage. The specific
  mapping is documented in the owning fetcher spec
- Fetchers whose upstream source has no ecosystem concept (NVD, MITRE, Red
  Hat, Kernel) set the field to NULL
- The authoritative list of defined ecosystems is maintained by the OSSF at
  the schema URL above. New ecosystems added by the OSSF are automatically
  valid — Sentinel does not maintain a local copy of the enumeration

See `docs/data-model.md` (`CVEAffectedVersion.ecosystem`) for the column
definition and constraints.

## Cross-Cutting Rules

### Example Data in Documentation

All examples, API response samples, test fixtures, and documentation
snippets MUST use fictional placeholder data. Never copy real personal
identifiers — names, email addresses, usernames, Distinguished Names, or
any other PII — from external systems (IBS, SMELT, Bugzilla, NVD,
etc.) into the repository.

Approved placeholder patterns:

| Type          | Examples                                             |
|---------------|------------------------------------------------------|
| Person names  | `John Doe`, `Alice Smith`, `Bob Wilson`              |
| Usernames     | `jdoe`, `asmith`, `bwilson`                          |
| Emails        | `john.doe@suse.com`, `alice.smith@example.com`       |
| Groups        | `pkg-maintainers`, `kernel-team`                     |
| Group emails  | `pkg-maintainers@suse.de`                            |
| External IDs  | `ext-12345`, `00000000-0000-0000-0000-000000000001` |
| IPv4 addresses | RFC 5737 TEST-NET ranges: `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` |

When documenting API response formats from external services, first
sanitize the response by replacing all real identifiers with fictional
equivalents before inserting it into a specification or documentation file.

### Username Format

Usernames must be 1-64 characters, start with a letter, and contain only
lowercase letters, numbers, dots, hyphens, and underscores
(`[a-z0-9._-]`). Usernames are stored exclusively as lowercase in the
database. Any entry point that accepts a username for user creation MUST
normalize it (trim whitespace, lowercase) and validate the format before
storage.

### Timestamps & Timezones

Sentinel follows the **"UTC everywhere, local display"** convention:

- **Database**: all timestamp columns use PostgreSQL `TIMESTAMPTZ` (which
  normalizes values to UTC internally). Never use bare `TIMESTAMP`
  (without time zone) — naive timestamps are ambiguous and a source of
  bugs in multi-timezone environments
- **Backend**: all datetime operations (comparisons, arithmetic,
  scheduling, TTL checks) operate in UTC. Use `datetime.now(UTC)` (never
  `datetime.utcnow()`, which returns a naive datetime). Celery Beat
  schedules are expressed in UTC. The Celery application MUST be
  configured with `timezone = "UTC"` and `enable_utc = True` (the
  Celery 4+ defaults). These settings MUST NOT be overridden in any
  environment — the Celery app factory validates them at module import
  time and refuses to start any process if they are incorrect (see
  `docs/features/platform/fetcher-infrastructure.md`, Startup
  Validation)
- **API responses**: all datetime values are serialized in UTC with the
  `Z` suffix (e.g., `2025-03-15T10:30:00Z`)
- **API inputs**: datetime filter parameters (e.g., `from_date`,
  `to_date`) interpret naive values (without timezone offset) as UTC.
  Values with an explicit offset (e.g., `+02:00`) are accepted and
  converted to UTC before comparison. See `docs/api-spec.md` (Date
  Range Interpretation) for the detailed parsing rules
- **API consumers**: convert UTC timestamps to local timezone at display
  time. When submitting datetime values to the API, convert local time
  to UTC before sending
- **CLI**: timestamps in CLI output are displayed in UTC with an
  explicit "UTC" suffix (e.g., `2025-03-15 10:30:00 UTC`)

### Configuration Management

Sentinel uses four configuration artifacts with distinct roles:

| Artifact | Role | Authority |
|----------|------|-----------|
| Feature spec named in the `Defined in` column | Defines feature-specific semantics, name, type, default, bounds | Source of truth for that feature setting |
| `docs/configuration.md` | Aggregated operational index; directly defines core infrastructure variables whose `Defined in` value is `—` | Mirrors feature specs and owns the documented core exceptions; all artifacts MUST agree |
| `backend/app/config.py` | Implementation (Pydantic `Settings` class) | Field names are the `lower_snake_case` form of the environment variable name defined by its owning authority |
| `backend/.env.example` | Developer quickstart template | Subset of `config.py` fields selected by the `.env.example` Inclusion Criteria |

**Invariant**: every field in `config.py` MUST correspond to an entry in
`docs/configuration.md`. A field that exists in code but not in the
registry is undocumented; a registry entry without a corresponding field
is either not-yet-implemented (acceptable during incremental development),
consumed by a specialized module outside the Settings class (e.g., Celery
app factory, subprocess environment), or a drift bug.

**`.env.example` inclusion criteria**: a variable appears in
`.env.example` if and only if a developer MUST or WILL LIKELY customize
it for local development. Variables excluded:

- Infrastructure URLs with stable defaults (e.g., `IBS_API_URL`,
  `SMELT_API_URL`) — usable only on SUSE internal network
- Fixed operational constants (e.g., `CELERY_TIMEZONE`) — must not be
  changed
- Optional API keys for external services (e.g., `NVD_API_KEY`) — empty
  default is functional for development

**Feature development workflow** (configuration aspect):

1. Define the variable in the owning feature spec (authoritative
   semantics). Core infrastructure variables without a feature owner are
   defined directly in `docs/configuration.md`
2. Add an entry to `docs/configuration.md` (operator reference)
3. Implement the field in `config.py` when the feature is implemented
4. Add to `.env.example` only if it meets the inclusion criteria

**List-type environment variables**: environment variables whose
application type is a list of strings use comma-separated format — not
JSON arrays. The `config.py` field uses a `CommaSeparated` type alias
(defined in the same module via `NoDecode` + `BeforeValidator`) to
parse the value. Example: `CORS_ORIGINS=http://a.com,http://b.com`.

**Optional string variable semantics**: for every optional string
environment variable (one whose absence or empty value does not prevent
application startup), the default interpretation is that **empty string
is equivalent to unset** — both mean "not configured." The canonical
phrase in specifications is "empty or unset."

If a variable intentionally treats empty string as a distinct valid
value (different from unset), the owning feature spec MUST declare this
explicitly. In the absence of such a declaration, the default (empty =
unset) applies.

Implementation rule: Pydantic's `Settings` class treats `""` as a valid
non-None `str`. Code that checks whether an optional string variable is
configured MUST use `if not value` (or equivalent), never
`if value is not None`.

## Python (Backend)

### Style

- **Formatter**: ruff format (black-compatible)
- **Linter**: ruff check
- **Line length**: 88 characters (ruff default)
- **Quotes**: double quotes for strings
- **Imports**: sorted by ruff (isort-compatible), grouped as:
  1. Standard library
  2. Third-party
  3. Local application

### Type Hints

- All function signatures MUST have type hints for parameters and return values
- Use `from __future__ import annotations` for modern annotation syntax
- Use `Optional[X]` or `X | None` for nullable types

### Static Type Checking

Type hints are enforced, not just written. Static type checking in strict
mode is a mandatory CI gate, equivalent in authority to linting — a pull
request with type errors cannot merge.

**Scope**: application code (`app/`), tests (`tests/`), and Alembic
migration scripts (`alembic/`) are checked so type errors cannot accumulate
silently outside application modules. Exemptions are limited to the explicitly
documented cases below.

**Async-await verification**: type checking flags a coroutine that is
never awaited or otherwise consumed. This catches a real class of bug in
an async-only codebase (see Architecture, Async-only database layer) — a
forgotten `await` that would otherwise silently skip the intended
operation at runtime.

**Suppressing false positives**: an inline suppression MUST always name the
specific error code it silences (e.g., a code suffix identifying the
category of error being ignored). An unqualified suppression that silences
every possible error category is forbidden, because it hides unrelated
future errors under the same line.

**Unstubbed third-party libraries**: a dependency that ships no type
information may be exempted from import-resolution errors on a per-module
basis. Each such exemption MUST be revisited when the dependency gains type
support, or when the feature area that depends on it moves from stub/interim
implementation to full implementation — whichever comes first. When a
tracking issue for that feature area already exists, note the pending
exemption removal there so it is not forgotten.

### Naming

- **Files**: `snake_case.py`
- **Classes**: `PascalCase`
- **Functions/methods**: `snake_case`
- **Constants**: `UPPER_SNAKE_CASE`
- **Private**: prefix with single underscore `_`
- **Fetchers**: `BaseFetcher` registry and class names follow the complete
  naming convention in `docs/features/platform/fetcher-infrastructure.md`:
  external-source names use `<verb>_<source>_<noun>`, while local `evaluate`
  fetchers omit the source and use `<verb>_<noun>`
- **CVE fetchers**: inherit from `BaseCVEFetcher`; follow the attributes,
  `fetch_single()`, and opt-out contracts in
  `docs/features/platform/cve-fetcher-infrastructure.md`
- **Git-based CVE fetchers (delta flow)**: inherit the `BaseGitFetcher`
  template, declare the required class attributes, and override only its
  documented hook methods. They MUST NOT override `execute()`. See
  `docs/features/platform/git-fetcher-infrastructure.md`

## API and Schema Conventions

### FastAPI Conventions

- Endpoint handlers should be thin: validate, call service, return response
- Use dependency injection (`Depends()`) for database sessions, auth, etc.
- All endpoints must have OpenAPI documentation through at least a summary or
  description
- Use appropriate HTTP status codes and response models
- **User identifier resolution**: parameters that identify a user follow
  `docs/api-spec.md` (User Identifier Resolution), including its distinction
  between target resources and optional list filters. API dependencies may
  parse or pass through the value, but MUST NOT execute the ORM lookup. A pure
  parser may live in Core; a resolver that loads `User` belongs to the service
  layer because Core has no application imports. Identity consumers use
  `user_service.resolve_user_identifier()` as specified in
  `docs/features/identity/user-service.md`

- **Capability-based authorization**: use `require_capability()` as the
  standard authorization dependency for capability-protected endpoints.
  Example:

  ```python
  @router.post("/tickets")
  async def create_ticket(
      ...,
      principal: AuthenticatedPrincipal = Depends(
          require_capability(Capability.CREATE_TICKET)
      ),
  ):
  ```

  The dependency returns an `AuthenticatedPrincipal` carrying both the
  active `User` and the `CredentialKind` (`jwt` or `api_key`) — see
  `docs/features/identity/authentication.md` (Authenticated Principal).
  Scope filtering (confidential ticket visibility) is handled by shared query
  utilities and API dependencies (`confidential_ticket_filter()`,
  `require_accessible_ticket`), not per-endpoint logic. See
  `docs/features/identity/rbac.md` for the full authorization model

- **Cross-cutting query parameter constraints**: enforce global constraints
  (such as the 500-character string parameter length limit defined in
  `docs/api-spec.md`) via a shared dependency injected at the app or router
  level, rather than repeating validation logic in individual endpoint
  handlers. This ensures consistent enforcement across all endpoints and
  reduces the risk of omission

### Pydantic Conventions

- Separate schemas for Create, Update, and Response
- Use `model_config = ConfigDict(from_attributes=True)` for ORM integration
- Validate transport shape, types, and transport-specific constraints in
  Pydantic schemas. Services enforce domain and data-integrity invariants for
  every caller; endpoint handlers do not duplicate either validation layer

## Database, Transactions, and State

### SQLAlchemy Conventions

- Use SQLAlchemy 2.0 style (mapped_column, declarative base)
- All models inherit from a common `Base` class
- **Use UUIDv7 primary keys**: every UUID primary key column declares
  both `default=uuid.uuid7` (Python-side, used for pre-flush ID access)
  and `server_default=text("uuidv7()")` (PostgreSQL-side safety net for
  any INSERT that bypasses the ORM's Python-side default). Never use
  `uuid.uuid4` for primary keys — UUIDv7 embeds a millisecond-precision
  timestamp in its most-significant bits, which gives near-sequential
  B-tree index insertion (no random page splits) and makes `ORDER BY id`
  equivalent to chronological order. `uuidv7()` requires PostgreSQL 18+
- Include `created_at` and `updated_at` timestamps by default. Semantic
  exceptions and alternate lifecycle timestamps MUST be documented in
  `docs/data-model.md` (Notes)
- Define relationships explicitly with `back_populates`

#### Async-only Database Access

Sentinel uses async-only database access everywhere. API handlers, service
modules, Celery tasks, and CLI commands all use `AsyncSession` backed by the
`asyncpg` driver. No synchronous database driver or engine is maintained.
Introducing one (e.g., for a CLI command "for performance" or "simplicity")
requires explicit written justification that the async-only model is
insufficient for the specific use case and MUST be approved by a human
reviewer before implementation. Do not introduce a synchronous driver or
engine autonomously.

#### Sync-to-Async Bridging

Synchronous entry points (CLI commands, Celery signal handlers, management
scripts) that need to call async code MUST follow this pattern:

1. Extract the async logic into a named `async def` function. This is the
   independently testable unit; tests `await` it directly without going
   through `asyncio.run()`.
2. The synchronous caller wraps the extracted function in exactly one
   `asyncio.run()` call per invocation.
3. Nested or multiple `asyncio.run()` calls within a single invocation are not
   supported. Each call creates and destroys an event loop; multiple calls add
   overhead and risk subtle state leaks between loops.

**Celery signal handler placement**: worker startup
(`celeryd_after_setup`) and Beat startup (`beat_init`) signal handlers live
under `app/tasks/`, not `app/core/`, because they import and call service-layer
functions (`bootstrap_fetcher_configs`, reconciliation). Core has no
application-level imports (see `docs/architecture.md`, Backend Layer
Architecture). The handlers are thin synchronous wrappers that use the
Sync-to-Async Bridging pattern and `sys.exit(1)` on failure (explicit
fail-fast).

See `docs/features/platform/testing-strategy.md` (Sync Entry-Point Tests) for
the corresponding test convention (why sync entry-point tests must be `def`,
not `async def`).

#### Cross-Loop Pooled Connection Lifecycle

The production database engine (`app/database.py`) is a process-lifetime
singleton using SQLAlchemy's default pooled connection implementation. A
pooled `asyncpg` connection is bound to the event loop that created it. Reusing
it after that loop has closed raises `RuntimeError` (`... attached to a
different loop`) or `InterfaceError`. This is an upstream SQLAlchemy
constraint, not a Sentinel-specific one.

A single `asyncio.run()` call per invocation (per Sync-to-Async Bridging) is
safe on its own. The risk appears when the same **process** repeats the pattern
across multiple invocations over its lifetime, as a Celery prefork worker child
does. Each invocation creates and destroys its own event loop; a pooled
connection checked back in by one invocation remains bound to that
invocation's now-closed loop and can be handed to the next invocation's new
loop.

Every async workflow function repeatedly invoked this way MUST `await
engine.dispose()` once its work is complete, on success or failure, before
returning control to its `asyncio.run()` caller. This drains connections tied
to the closing loop. The obligation belongs to the outermost workflow function
that owns the invocation's event loop, never to a nested service or fetcher
method that may be invoked through different wrappers. Owning workflow
specifications identify the concrete disposal boundary.

A synchronous entry point is exempt when its process exits after one
`asyncio.run()` call (for example, a CLI command or Alembic migration), or when
it provably does not share the process-lifetime pooled engine. A one-time
worker or Beat startup handler that uses the shared engine still disposes it
after bootstrap, so prefork children do not inherit live parent connections
and Beat does not reuse a bootstrap-loop connection. See the owning workflow
specification and `docs/features/platform/testing-strategy.md` (Sync
Entry-Point Tests).

See `docs/features/platform/testing-strategy.md` (Cross-Loop Engine Lifecycle)
for the required regression and structural test coverage.

### Enum Storage Strategy

Sentinel does not use PostgreSQL ENUM types (`CREATE TYPE ... AS ENUM`).
All enumerated columns use `VARCHAR(N)` with one of two validation
strategies:

| Category | Validation | Adding a value |
|----------|------------|----------------|
| **State-machine** | `VARCHAR(N)` + `CHECK` constraint | Alembic migration (reversible) |
| **Classification** | `VARCHAR(N)` + Python `StrEnum` in `app/core/enums.py` | Code change only |

**Migration reversibility note**: "reversible" in the strategy table means
the migration file contains both `upgrade()` and `downgrade()` functions
so that the CHECK constraint change can be rolled back during
development. It does not imply that `alembic downgrade` is supported in
production — see `docs/deployment.md` (Migration Failure Recovery) for
the production recovery policy (fix-forward only).

**Classification criterion**: a column uses a CHECK constraint if and
only if (a) the value is part of a state machine whose transitions are
managed by application code, or (b) the value has direct security
implications. All other enumerated columns (classifications, labels,
audit event types, source identifiers) use Python Enum validation only.

All Python Enums for enumerated columns — both categories — are defined
in `app/core/enums.py` as `StrEnum` subclasses. Category A enums are
additionally protected by a CHECK constraint at the database level.

All schema tables — in `docs/data-model.md` and in feature
specifications — use `VARCHAR(N)` as the column type for enumerated
columns. The enum name and valid values are documented in the column
description or in a dedicated enum section.

**CHECK constraint naming**: every CHECK constraint name starts with the
`chk_{table}_` prefix. Beyond the prefix, the suffix depends on what the
constraint validates:

- **Enum-validation constraints** (restrict a single column to the values of a
  Category A `StrEnum`): `chk_{table}_{column}_valid`. Example:
  `chk_ticket_status_valid`.
- **Logical/structural constraints** (any other invariant — typically
  spanning multiple columns, such as mutual exclusivity between two
  nullable columns): `chk_{table}_{semantic_description}`, where the
  description names the invariant being enforced, not a column. Example:
  `chk_user_auth_exclusive` (enforces that a `User` row has exactly one
  of `external_id` or `password_hash` set — see `docs/data-model.md`,
  `User`).

**Implementation patterns**:

```python
# Category A — State-machine (VARCHAR + CHECK)
class TicketStatus(StrEnum):
    NEW = "New"
    ANALYSIS = "Analysis"
    ...

status: Mapped[str] = mapped_column(String(20), nullable=False, default=TicketStatus.NEW)

__table_args__ = (
    CheckConstraint(
        status.in_([e.value for e in TicketStatus]),
        name="chk_ticket_status_valid",
    ),
)


# Category B — Classification (VARCHAR + Python Enum only)
class CVESourceType(StrEnum):
    NVD = "nvd"
    MITRE = "mitre"
    ...

source: Mapped[str] = mapped_column(String(100), nullable=False)
# Validation in service layer: CVESourceType(value) raises ValueError if invalid
```

See `docs/data-model.md` (Notes) for the classification of every enum
in the schema.

### Audit Trail

`docs/features/platform/audit-trail-infrastructure.md` is the single canonical
source for shared audit rules, including `AuditEventMixin`, `BaseAuditLog`,
atomicity, operational-state separation, permitted historical read models,
naming, and the Audit Trail Index. Domain audit specifications extend that
shared contract with their event types and data.

### Transaction and Locking

#### Caller-Owned Service Transactions

Composable service functions that accept an `AsyncSession` supplied by their
caller participate in the caller's transaction. They MUST flush when required
to expose generated identifiers, returned state, audit records, or constraint
violations before returning, but MUST NOT commit or roll back. Exceptions
propagate to the caller without preserving a partial service result.

The workflow entry point owns completion of that transaction:

- an API database-transaction dependency commits exactly once after the
  handler and all delegated services succeed, and rolls back exactly once when
  an exception escapes — in both cases, before the response is transmitted to
  the client (see API Transaction Dependency Scope for the FastAPI mechanism
  that guarantees this ordering);
- a mutating CLI async workflow follows the transaction contract in
  `docs/features/platform/cli-infrastructure.md`; and
- a Celery task or other synchronous process entry point wraps one complete
  async workflow, which commits once on success and rolls back once on
  failure.

This contract permits one workflow to compose multiple services and their
audit events atomically. A service MUST NOT commit an intermediate mutation or
roll back work that belongs to its caller. A component that explicitly owns
its sessions as an orchestration boundary rather than accepting a
caller-supplied session (for example `BaseFetcher.run()`) keeps the transaction
contract defined by its owning specification; this rule does not convert such
orchestrators into caller-owned services.

External effects remain outside the PostgreSQL transaction. A service may
return the data needed for a post-commit effect, but the workflow owner invokes
that effect only after its database commit succeeds and the row lock is
released, following Transaction Hygiene Rules. For API workflows, the
transaction boundary preserves or registers the returned effect data until the
dependency has committed, then runs the effect. The internal callback or
framework mechanism used to bridge handler return and dependency completion is
an implementation choice; executing the effect before commit is not.

#### API Transaction Dependency Scope

The API database-transaction dependency (`get_db()` in `app/database.py`) is
a `yield`-based FastAPI dependency: the code after `yield` — the commit,
rollback, and post-commit callbacks that complete the transaction — is its
exit phase. FastAPI determines *when* that exit phase runs relative to the
HTTP response through the dependency's `scope`:

- `scope="request"` — FastAPI's default when a `yield` dependency does not
  specify a scope: the exit phase runs after the response has already been
  transmitted to the client. This does NOT satisfy the ordering guarantee
  defined by Caller-Owned Service Transactions — a client can observe a
  success response before the commit (or a
  commit failure) has been resolved.
- `scope="function"`: the exit phase runs after the path operation function
  returns but before the response is transmitted. A commit failure at this
  point still surfaces as an error response instead of the already-decided
  success response, and every registered post-commit callback completes
  before the client receives the response.

Every endpoint dependency that supplies the API transaction session MUST
declare `scope="function"` explicitly — the framework default is unsafe for
this contract. Route handlers use the shared `DatabaseSession` type alias
(`app/database.py`) rather than declaring `Depends(get_db)` inline, so every
endpoint receives the correct scope without repeating it. A route that needs
a database session and does not use this alias is a bug, not an accepted
variation.

This requirement is specific to `yield`-based dependencies whose exit phase
performs transaction-completion work. It does not apply to plain
(non-`yield`) dependencies, which have no exit phase to order against the
response.

#### Pessimistic Locking Pattern

When a service module centralizes all mutations on an entity (e.g.,
`ticket_mutations` for tickets), concurrent transactions can produce lost
updates or stale audit trail values. To prevent this, apply pessimistic locking
at the module boundary.

Every public function in a centralized mutation module that performs a
state-dependent mutation of an existing root entity MUST acquire a row-level
lock on that root as its first database operation in the transaction:

```python
ticket = await db.execute(
    select(Ticket).where(Ticket.id == ticket_id).with_for_update()
)
```

This serializes all concurrent mutations on the same entity at the
database level. The lock is released automatically when the transaction
commits or rolls back.

The rule is proportional to the mutation:

- creation has no existing root row to lock; database uniqueness constraints
  and conflict translation are authoritative for concurrent creates;
- read-only functions acquire no mutation lock;
- an operational metadata touch implemented as one conditional atomic UPDATE
  (for example monotonic `last_used_at`) needs no separate row lock when its
  owning specification proves the race outcome; and
- validation or expensive input-only computation that does not query the
  database may occur before the first database operation and lock.

These cases are not permission to split a read-modify-write mutation around a
lock. Once a function begins reading persisted state that determines a root
mutation or its audit values, it must acquire the root lock first.

#### Transaction Hygiene Rules

The transaction that holds a pessimistic row lock (`FOR UPDATE`,
`FOR NO KEY UPDATE`, or another explicit row-level lock mode) MUST be kept
as short as possible. Two categories of work are forbidden inside it:

1. **No network I/O**: any operation that crosses a network boundary
   — HTTP requests to external services (IBS, SMELT, NVD, AIMAAS),
   Redis commands, Celery task enqueuing (which transits the Redis
   broker), or any other socket I/O — MUST NOT execute while a
   pessimistic row lock is held.

   Rationale: network I/O cannot be rolled back by a PostgreSQL
   transaction rollback. A `DEL` sent to Redis, a task published to
   Celery, or an HTTP request to an external service cannot be undone
   if the transaction later fails. Additionally, network latency or
   timeouts extend the lock hold time, blocking all concurrent
   mutations on the same entity.

   The correct pattern separates work into phases:

   ```
   1. Fetch data from external services (no lock held)
   2. Open transaction → SELECT ... FOR UPDATE on root entity
   3. Apply mutations + create audit events (DB only)
   4. Commit (lock released)
   5. Post-commit side effects: cache invalidation, task enqueue (best-effort)
   ```

   Post-commit side effects (step 5) use data returned by the transactional
   phase (e.g., a list of invalidated session IDs) to perform the necessary
   Redis or broker operations. The owning feature defines recovery when the
   process crashes between commit and the side effect, such as TTL expiry,
   reconciliation, idempotent retry, or an observable operator rerun.

   **Pre-transaction guards** are a distinct pattern: a Redis
   operation that serves as a distributed lock or precondition gate
   (e.g., `SET key NX EX ttl` to prevent concurrent batch processing)
   executes BEFORE the transaction — it gates entry into the
   transaction, not as a side effect of it. If the guard fails, no
   transaction is opened. This pattern is not subject to the No Network I/O
   prohibition.

   Ticket convergence is not an exception: its recovery publication occurs
   only after commit, as defined in
   `docs/features/platform/fetcher-infrastructure.md` (Per-Ticket Catch-Up,
   Post-commit enqueue) and `docs/features/packages/package-model.md`
   (Ticket Convergence). No pre-commit enqueue exception applies.

2. **No expensive queries**: analytical queries, aggregations over
   large tables, or computationally intensive operations MUST be
   executed before acquiring the lock. The locked transaction should
   contain only fast reads (single-row lookups for validation) and
   writes.

**I/O-then-Lock corollary**: in modules that contain both orchestration
functions (with external I/O) and mutation functions (with pessimistic row
locks), the two concerns MUST be separated into distinct functions —
orchestration functions MUST NOT acquire locks. See
`docs/features/packages/package-service.md` (Module Invariant) for the
canonical application of this rule.

### Redis

#### Redis Key Conventions

Redis keys in Sentinel fall into two categories with different
documentation rules:

**Application-owned keys**: keys whose format is defined by Sentinel
(e.g., `login_attempts:{username}`, `session_liveness:{session_id}`,
`fetch_pending:{cve_id}:{source}`). These are accessed via the Redis
client directly. The spec that owns the key MUST document the exact
format, TTL, and value contract — the format IS the specification.

**Library-managed keys**: keys whose format is defined by a third-party
library (e.g., `celery-redbeat` schedule entries). Sentinel code MUST
interact with these exclusively via the library's public API — never by
constructing Redis keys directly. Specifications MUST describe behavior
in terms of the library API (e.g., "create an entry via
`RedBeatSchedulerEntry`"), not in terms of internal key formats (e.g.,
"write to `redbeat:{name}`"). Internal key patterns may be documented
as informational notes for operational debugging, clearly marked as
library-internal.

#### Redis Error Handling

All application-owned Redis operations (operations that access
`REDIS_URL` directly, as opposed to library-managed broker operations)
MUST catch **`RedisError`** (the base class from `redis.exceptions`),
not narrower subclasses like `ConnectionError` or `TimeoutError`.

Application-owned Redis I/O in async workflows MUST be non-blocking and
awaited. Synchronous entry points such as CLI commands and Celery task wrappers
bridge once into an async workflow via the standard sync-to-async pattern;
they do not require a synchronous Redis client.

**Rationale**: under `noeviction` memory policy, when Redis reaches
`maxmemory`, write commands return an OOM error. The Python client
raises `redis.exceptions.ResponseError` — a subclass of `RedisError`
but NOT of `ConnectionError`. Catching only `ConnectionError` would
leave OOM errors unhandled (resulting in HTTP 500 responses).

By catching `RedisError`, each feature handles connection loss, timeout, OOM
rejection, and protocol errors through its specified degradation path. The
specification that owns the Redis operation MUST define that behavior;
infrastructure shared by multiple consumers MUST propagate `RedisError` rather
than selecting a fallback on their behalf. This keeps feature-specific
outcomes—such as fail-open, database fallback, best-effort continuation, or
request failure—in their natural owner and avoids a duplicated cross-feature
matrix in this convention.

Redis-dependent tests follow `docs/features/platform/testing-strategy.md`
(Redis Strategy), including isolated worker databases and replaceable
consumer boundaries for deterministic failure simulation.

**Scope**: this convention applies to application code that directly calls the
Redis client. It does NOT define error handling for library-managed operations:

- Celery broker operations (managed by the Celery framework; errors
  surface as task publish failures with Celery's own retry logic)
- Redbeat operations, whose owning specifications define behavior through the
  library API, including Beat fail-fast and post-commit propagation paths; see
  `docs/features/platform/fetcher-infrastructure.md` and the consuming feature

**Illustrative async pattern**:

```python
try:
    await redis_operation()
except RedisError as exc:
    # Apply the degradation behavior defined by the owning feature spec.
    logger.warning("redis_operation_failed", error=str(exc))
```

## Runtime, Integration, and Verification

### Secret Field Typing

Configuration fields in `backend/app/config.py` (`Settings` class) that
contain secrets MUST use Pydantic's `SecretStr` type instead of plain `str`.
This prevents accidental exposure through `repr()`, tracebacks, debug logging,
or JSON serialization. A Python-mode `model_dump()` retains `SecretStr`
objects; it does not make a complete settings dump safe to expose.

Classification:

| Field nature | Type | Example |
|---|---|---|
| Pure secret (signing key, password, token, API key) | `SecretStr` | `jwt_secret_key: SecretStr` |
| URL that may embed credentials (`user:password@host`) | `str` with `Field(..., repr=False)` | `database_url: str = Field(default="...", repr=False)` |
| Non-secret configuration (usernames, public URLs, flags) | plain type (default) | `ibs_api_url: str = "..."` |

Rules:

- Access the real value of a `SecretStr` field exclusively via
  `.get_secret_value()`. Never rely on implicit `str()` conversion, which
  returns the masked representation (`'**********'`), not the real value
- Validators (`@model_validator`) that inspect a `SecretStr` field MUST call
  `.get_secret_value()` before performing checks such as length or emptiness
  validation
- URL fields that may embed credentials use `Field(..., repr=False)` to retain
  direct string compatibility with downstream libraries. `repr=False` hides
  the field from `repr(settings)` but is not a serialization or logging
  boundary
- A username field (e.g., `ibs_username`) is NOT treated as a secret by this
  convention; only the paired credential (e.g., `ibs_password`) is
- When adding a new `Settings` field that holds credential material, apply
  this classification before implementation. If genuinely uncertain whether
  a value counts as a secret, treat it as a secret
- Never serialize the full `Settings` object (`model_dump()` or
  `model_dump_json()`) in API responses, health endpoints, logs, or error
  payloads. Credential-bearing URL fields remain plain strings, and
  Python-mode dumps retain secret-bearing objects

### Logging

Application code obtains a `structlog` logger bound to the module and
logs via its standard methods:

```python
import structlog

logger = structlog.get_logger(__name__)

logger.info("fetcher_run_started", fetcher_name=self.name)
logger.warning("retrying_http_call", service="example", attempt=attempt)
```

Log statements MUST NOT include secret or PII values — see
`docs/features/platform/logging.md` (Secrets and PII Discipline) and
Secret Field Typing. `docs/features/platform/logging.md` is the
authoritative specification for log format, levels, correlation IDs,
and the full secrets/PII policy — it is not restated here.

### Testing Conventions

For the full testing strategy — test pyramid, database setup, fixture
catalog, coverage policy, audit trail testing, and execution model — see
`docs/features/platform/testing-strategy.md`.

Style rules:

- Test files mirror the `app/` directory structure
- Use `pytest` with async support (`pytest-asyncio`)
- Use the canonical session, client, and Redis fixtures at the boundaries
  defined by the testing strategy. Create test data with factories where
  available or by direct model instantiation
- Test naming: `test_<what>_<condition>_<expected_result>`
- Example: `test_get_cve_not_found_returns_404`

Mandatory behavioral scenarios, including UUID and username forms for user
identifiers, are owned by `docs/features/platform/testing-strategy.md`. The API
contract distinguishes target-resource identifiers from optional list filters;
see `docs/api-spec.md` (User Identifier Resolution).

### External Integration Contract Verification

Code that parses responses from or sends requests to an external service MUST
verify the consumed contract against a real upstream response during
implementation. Documentation alone is not sufficient when the service is
reachable.

The implementing PR MUST:

1. obtain a representative real response from the upstream service;
2. compare every field consumed by the code, including names, nesting,
   nullability, collection shapes, pagination, and date formats;
3. sanitize all personal identifiers and save the result under
   `backend/tests/fixtures/<service_name>/`;
4. add contract tests that load the fixture before implementing the parser;
5. use a typed response model where practical; and
6. record the verification source and result in the PR.

If the upstream service is unreachable or credentials are unavailable, the PR
MUST identify the unverified fields and state that verification was
documentation-only. If the real response contradicts an owning specification,
stop implementation and resolve the discrepancy in a documentation PR before
continuing — unless the combined-PR exception in `AGENTS.md` (Guardrail 25)
applies, in which case the spec fix and implementation ship together.

### Runtime Version

Sentinel targets a single Python minor version for all runtime
components. The version is chosen based on: (1) active bugfix
maintenance status from python.org, and (2) declared support from all
critical dependencies (Celery in particular historically lags new
Python releases by 6-12 months).

**Current target**: Python **3.14** (bugfix maintenance, EOL 2030-10).

#### Source of Truth

The file `backend/.python-version` is the single source of truth for
the Python runtime version used across all environments:

| Consumer | How it reads the source of truth |
|---|---|
| Local development (pyenv, uv, mise) | Reads `backend/.python-version` natively |
| CI (`astral-sh/setup-uv`) | `uv` reads `backend/.python-version` natively |
| Dockerfile | `ARG PYTHON_VERSION=<value>` default; CI passes `--build-arg` from source of truth |
| ruff `target-version` | Inferred from `requires-python` in `pyproject.toml` (no explicit `target-version`) |

The `requires-python` field in `backend/pyproject.toml` MUST be kept
aligned with the source of truth (`>=3.<minor>` matching the minor in
`.python-version`). It serves as the package metadata floor — not as
the authoritative pin.

The `.python-version` file uses **minor-version granularity** (e.g.,
`3.13`, not `3.13.7`). This ensures the same value works directly as a
Docker image tag suffix, a `setup-python` specifier, and a pyenv/uv
prefix match. Patch-level reproducibility is captured by Docker image
digests and lockfiles, not by the version pin.

#### Dockerfile Convention

All Dockerfiles in the repository MUST use a global `ARG` for the
Python version:

```dockerfile
ARG PYTHON_VERSION=3.14
FROM python:${PYTHON_VERSION}-slim AS builder
...
FROM python:${PYTHON_VERSION}-slim AS runtime
```

The default value MUST match `backend/.python-version`. A CI drift-check
step verifies this automatically — a mismatch fails the build.

#### Version Bump Checklist

When upgrading to a new Python minor version:

1. **Verify dependency support**: check PyPI classifiers and changelog
   for all critical dependencies. Priority order (historically slowest
   to adopt):
   - `celery` / `kombu` / `billiard` (task queue stack)
   - `asyncpg` (C extension, needs wheel)
   - `pydantic-core` (Rust extension, needs wheel)
   - `bcrypt` (C extension)
   - All other dependencies with C/Rust extensions
2. **Update the source of truth**: change `backend/.python-version` to
   the new minor (e.g., `3.14`).
3. **Align `requires-python`**: update `backend/pyproject.toml`
   `requires-python` to `>=3.<new-minor>`.
4. **Update Dockerfile default**: change `ARG PYTHON_VERSION=...` in
   `backend/Dockerfile` to match. (The drift-check will catch this if
   forgotten.)
5. **Run the full test suite locally** on the new interpreter. Pay
   attention to `DeprecationWarning` output.
6. **Temporary CI matrix** (optional but recommended): for the PR that
   bumps the version, add the old version alongside the new one in CI
   to confirm no regressions. Remove the old version after merge.
7. **Update documentation**: change the "Current target" line in this
   section and the prerequisite in `docs/deployment.md` (Software
   Requirements table).
8. **Update prose references**: search for hardcoded version strings in
   `docs/` (e.g., `python:3.13-slim` in spec prose) and update or make
   version-agnostic.
9. **Rebuild and test images**: build the Docker image with the new
   base, run smoke tests against it.
10. **Deploy**: staging first, observe for one cycle of all fetchers,
    then production.

A scheduled, non-blocking workflow already provides part of this
checklist's early-warning signal automatically, ahead of any bump
decision — see `docs/deployment.md` (Python Forward-Compatibility
Check).

## CLI Conventions

See `docs/features/platform/cli-infrastructure.md` for the shared
implementation mechanism (entry point, session management, error
handling, signal handling) backing the contract defined in this section.

### Framework

- **Library**: Click
- **Entry point**: `sentinel` (registered as a console script in `pyproject.toml`)
- **Architecture**: command groups for related commands (e.g.,
  `sentinel manage-user create`, `sentinel manage-user update`)

### Naming

- Command groups: `noun` with `verb` subcommands for related operations
  (e.g., `sentinel manage-user create`, `sentinel fetcher list`)

### Command Design

- Commands that modify data MAY check a configuration guard before
  executing. If a guard is defined and not enabled, the command MUST exit
  with a clear error message explaining which setting to enable
- Commands follow the complete idempotency rules in Output Contract —
  Idempotency
- Use `--flag` for boolean options and `--option VALUE` for parameterized
  options
- Repeatable options use multiple `--option` flags (e.g.,
  `--role admin --role vulnerability_analyst`)
- **Repeatable filter semantics**: when a CLI command accepts a
  repeatable filter option, multiple values are combined with **OR**
  logic — the result includes resources matching ANY of the provided
  values. This is consistent with the multi-value query parameter
  semantics defined in `docs/api-spec.md`
- **Username normalization**: all CLI commands that accept a username
  argument MUST normalize it (trim whitespace, lowercase) before lookup.
  See Username Format for the full format specification
- **Thin command boundary**: follow `docs/architecture.md` (Backend Layer
  Architecture) for service delegation and the narrowly scoped read-only query
  exception

### Database Access

- CLI commands bridge into the async database layer via the
  Sync-to-Async Bridging pattern in SQLAlchemy Conventions. See
  `docs/features/platform/cli-infrastructure.md` (Database Session
  Management) for CLI-specific details (session factory injection,
  transaction lifecycle).

### Output Contract

All CLI commands MUST follow this output contract for consistency and
scriptability.

#### Channel Separation

- **stdout**: success messages, results, tables, structured step reports
- **stderr**: error messages (`Error: ...`), warnings (`Warning: ...`)

This separation allows callers to redirect stdout for parsing while
still receiving diagnostics on stderr.

#### Exit Codes

| Code | Meaning | Examples |
|------|---------|----------|
| 0    | Success (includes idempotent no-ops and user-cancelled confirmations) | Command completed, or state already reached, operator declined a confirmation prompt |
| 1    | User error | Bad input, validation failure, concurrency conflict, unknown resource |
| 2    | System error | Database unreachable, Redis unreachable, unhandled exception |
| 130  | Interrupted by SIGINT (Ctrl+C) | Operator cancelled a long-running command |
| 143  | Interrupted by SIGTERM | Process manager requested shutdown |

Every command specification MUST document which exit codes it can produce.

#### Success Output

Single-operation commands print a concise confirmation to stdout:

```
Created user 'jdoe' (jdoe@example.com) with roles: admin.
```

Read-only commands print structured output (tables, lists) to stdout.

#### Error Output

All errors go to stderr with the prefix `Error:`:

```
Error: User 'jdoe' not found.
```

Warnings go to stderr with the prefix `Warning:` and do NOT cause a
non-zero exit code:

```
Warning: User 'jdoe' is inactive. Unlock has no practical effect until the user is reactivated.
```

#### Multi-Step Reporting (Fail-Fast)

Commands that perform multiple sequential mutations with fail-fast
semantics MUST use structured step reporting on stdout:

| Prefix | Meaning |
|--------|---------|
| `✓`    | Step completed successfully |
| `✗`    | Step failed (include reason) |
| `—`    | Step not attempted (aborted due to previous failure) |

Example:

```
✓ Email updated to new@example.com
✗ Role update failed: role 'nonexistent' does not exist
— Reactivation not attempted (aborted due to previous error)
```

This pattern applies when a command executes >1 independent mutation in
sequence where partial success is possible. It does NOT apply to:

- Atomic single-operation commands (use simple success/error messages)
- Commands with internal phases that are not user-visible mutations
  (the user cares about the final result, not the internal phases)

#### Idempotency

Commands MUST be idempotent where practical. Specifically:

- If the desired state is already reached (e.g., deactivating an already
  inactive user, unlocking a user that is not locked), the command prints
  an informational message to stdout and exits with code 0 — never with
  an error
- Commands that require interactive input for security (e.g., password
  prompts) are exempt from idempotency — each invocation inherently
  changes state
- Commands that execute external work are exempt — they produce side
  effects by design

Each command specification MUST explicitly declare its idempotency:

- **Idempotent**: safe to re-run; no-op if state is already reached
- **Not idempotent (interactive)**: requires interactive input that
  changes state on every invocation
- **Not idempotent (by design)**: produces side effects intentionally

#### Human-Readable Format

- Output is human-readable plain text by default
- Structured/machine-readable output is never the default; if a command
  needs it, it MUST be an explicit per-command opt-in, never silently
  produced. As of this writing, no command defines such an option — see
  `docs/features/platform/cli-infrastructure.md` (Purpose & Scope) for the
  rationale
- Tables use fixed-width columns aligned with spaces (no box-drawing
  characters)

#### Automated Verification

When CLI commands are implemented, the mandatory mechanical scenarios are
defined in `docs/features/platform/testing-strategy.md` (Mandatory Test
Scenarios → CLI Commands). That suite verifies this Output Contract; scenarios
are not duplicated here.

## Shell Scripting

This section governs standalone shell scripts and shell embedded in CI
workflows. It is distinct from CLI Conventions, which cover the
Python (Click) `sentinel` command. Shell scripts in Sentinel are limited
to repository orchestration and developer/CI tooling — application and
background-task logic MUST be Python (see Backend Layer Architecture in
`docs/architecture.md`), never shell.

### Scope

These rules apply to:

- Standalone scripts under `scripts/` (repo-level orchestration) and
  `backend/scripts/` when they are shell (Python utilities there follow
  the Python conventions instead)
- Git hooks under `.githooks/`
- Shell embedded in `run:` steps of `.github/workflows/*.yml`

### Interpreter and Safety

- **Shebang**: `#!/usr/bin/env bash`. Sentinel scripts target Bash and
  use Bash features (`[[ ]]`, `BASH_SOURCE`, arrays); POSIX `sh` is not
  assumed
- **Strict mode**: every script MUST start with `set -euo pipefail`
  immediately after the shebang/header comment, so failures, unset
  variables, and broken pipes abort the script instead of propagating
  silently
- **Quoting**: quote all variable expansions (`"${var}"`). The only
  accepted exception is an intentional word-split of an assembled command
  string, which MUST carry a narrowly-scoped, justified
  `# shellcheck disable=SC2086` directive
- **Diagnostics and exit codes**: write error and warning messages to
  stderr; reserve stdout for results. Return a non-zero exit code on
  failure and propagate the exit code of the meaningful inner command
  when the script is a wrapper (e.g., `scripts/image-smoke.sh` exits with
  the pytest exit code, or with the earlier failing command's exit code if
  pytest never ran)

### Static Analysis — shellcheck

All shell scripts MUST pass `shellcheck` with no findings. This is the
shell equivalent of `ruff check` for Python.

- Suppressions MUST be **inline**, **narrowly scoped** (a single check
  ID, applied to the smallest possible span — a command or a function),
  and **justified** with a trailing comment explaining why the finding is
  a false positive or an accepted trade-off. Example:

  ```bash
  # shellcheck disable=SC2317  # body is reachable: invoked indirectly via 'trap teardown EXIT'
  teardown() {
      ...
  }
  ```

- Blanket, file-level, or unexplained disables are not allowed. A
  repository-wide `.shellcheckrc` MUST NOT be used to hide findings
  globally

### Formatting — shfmt

All shell scripts MUST be formatted with `shfmt` using the flags
`-i 4 -ci` (4-space indentation, indented switch cases). This is the
shell equivalent of `ruff format` for Python. CI runs `shfmt -d` (diff
mode) and fails if any file is not already formatted; run `shfmt -i 4
-ci -w <files>` locally to fix.

### Workflow Shell — actionlint

Shell embedded in GitHub Actions `run:` steps is validated by
`actionlint`, which checks workflow syntax and runs `shellcheck` on each
`run:` block. Keep embedded shell short; when a `run:` block grows beyond
simple orchestration, extract it into a script under `scripts/` (which is
then covered by the standalone `shellcheck`/`shfmt` gate) and invoke that
script from the workflow.

### Naming and Structure

- **Files**: `kebab-case.sh` for standalone scripts (e.g.,
  `dev-env.sh`, `image-smoke.sh`). Git hooks use the fixed names Git
  requires (`pre-commit`, `commit-msg`, `pre-push`) with no extension
- **Functions**: `snake_case`; **constants/globals**: `UPPER_SNAKE_CASE`
- Provide a header comment describing purpose and usage, and route
  subcommand dispatch through a `main` function (see `scripts/dev-env.sh`)
- **English only** (Guardrail 4) applies to all comments and messages

### File Placement

- `scripts/` — repo-level orchestration (compose wrappers, dev/CI
  tooling) that does not import the `app` package
- `backend/scripts/` — backend utilities that import `app` (these are
  Python, not shell)
- `.githooks/` — Git hooks (activation covered in
  `docs/features/platform/testing-strategy.md`, Pre-Commit Hooks)

See the file placement map in `AGENTS.md` (Guardrail 2) for the
authoritative mapping.

### Enforcement

- **CI** (`.github/workflows/ci.yml`) is the authoritative gate: a
  dedicated job discovers all tracked standalone scripts and git hooks
  (via `git ls-files`, so newly added scripts and hooks are covered
  automatically) and runs `shellcheck` + `shfmt -d` over them, plus
  `actionlint` over the workflows. Tool versions are pinned in the
  workflow, consistent with how Python tools (`ruff`, `bandit`) are
  pinned
- **Pre-commit hook** (`.githooks/pre-commit`) runs the same
  `shellcheck` + `shfmt` checks on staged shell files as a fast local
  safety net. Because these tools are not part of the Python
  environment, the hook degrades gracefully with a warning when they are
  not installed (matching the supplementary-safety-net philosophy in
  `docs/features/platform/testing-strategy.md`). Install `shellcheck` and
  `shfmt` locally to get pre-commit coverage

## Git Conventions

### Workflow

Sentinel uses GitHub Flow: `master` is always the stable, deployable
branch. All changes are developed on short-lived topic branches and
merged via pull request.

**Branch lifecycle**: create from `origin/master`, push regularly, open
a draft PR early, mark ready when implementation, verification evidence,
and applicable reviewer work are complete, squash-merge after approval,
branch auto-deleted.

#### Issues and work units

GitHub Issues are the canonical work item for every substantive,
human-directed repository change — including work an automation agent
performs on a person's request. Specifications, issues, pull requests, and
Projects each own a distinct concern:

| Owner | Owns |
|---|---|
| Specifications (`docs/features/`, cross-cutting docs) | Behavioral and structural contracts |
| Issues | The problem or outcome, bounded scope, acceptance criteria, owning-specification links, direct blockers |
| Pull requests | Implementation evidence: tests, manual verification, reviewer results, risks |
| Projects | Optional, initiative-scoped presentation of live status — never an additional completion gate |

Before creating a topic branch, search open issues in this repository.
Reuse a suitable issue only when all of the following hold: its outcome,
scope, acceptance criteria, and owning specifications cover the requested
change; it is a concrete work item and not a phase/initiative/parent issue;
it has no active linked branch or pull request; and its direct blockers are
resolved. Otherwise create a new issue using the "Work item" issue form —
no separate approval is needed merely to create the tracking object.

**Blocker linkage**: when an issue has direct blockers, declare them both
in the issue template's free-text "Direct blockers" field and via GitHub's
native `blocked_by` issue relationship (UI "Add blocked by" command, or the
GraphQL `addBlockedBy` mutation). The free-text field keeps the blocker
readable without leaving the issue body; the native relationship links
both issues bidirectionally, surfaces in each issue's sidebar, and warns
against closing an issue while an open blocker remains.

**Exemptions** — an issue is not required for:

- a pull request generated and maintained exclusively by Renovate or
  release-please (human-directed scope added to such a PR removes the
  exemption);
- pure exploration that creates no retained branch, commit, PR, or
  tracked-file change; or
- a genuinely cosmetic change limited to spelling, punctuation,
  whitespace, comments, or formatting, with no change to behavior,
  requirements, identifiers, commands, paths, or configuration.

When uncertain, create an issue.

**Single active domain branch**: develop one dependent domain work unit at a
time. Multiple branches may exist for genuinely independent concerns
(for example, a dependency update and a domain feature), but dependent
domain work is not stacked across unmerged branches.

**Work unit boundary**: the normal implementation unit is one tracking
issue, one topic branch created from the current `origin/master`, and one
squash-merged pull request. A milestone or roadmap phase groups multiple
work units; it is never itself a long-lived implementation branch. Start
a dependent work unit only after every direct blocker PR has merged, then
branch from the updated `origin/master`.

**Issue linkage**: every non-exempt pull request uses `Closes #<issue>` in
its body so merge completion closes the tracking issue. Exempt
human-authored PRs declare `N/A - <specific reason>` instead; approved
automated PRs (Renovate, release-please) are exempt entirely. Pull Request
Requirements defines the accepted formats. If a
specification gap blocks implementation, resolve it in a separate
documentation issue, branch, and merged PR before creating or resuming
the implementation branch — unless the combined-PR exception in
`AGENTS.md` (Guardrail 25) applies.

**No direct pushes to `master`**: all changes arrive via squash merge
of a reviewed PR. The pre-push hook enforces this locally.

**No force pushes**: never rewrite published branch history.

**No manual tags**: tags are created exclusively by release-please.

**Squash merge**: the only allowed merge method. The PR title becomes
the commit message on `master`.

**Branch deletion**: branches are deleted automatically after merge.

### Pull Request Requirements

- **Title**: Conventional Commits format, under 72 characters (validated
  by CI).
- **Description**: use the repository PR template. At minimum: issue
  linkage, owning spec reference, scope summary, test evidence, reviewer
  results, manual verification notes.
- **Issue linkage**: `Closes #<issue>` for normal work, `N/A - <specific
  reason>` for an exempt human-authored PR under "Issues and work units"
  in Workflow. Use the template's `- Issue linkage:` field, or a standalone
  `Closes #<issue>` line anywhere in the body. Approved automated PRs
  (Renovate, release-please) are exempt from this field. Validated by
  CI.
- **Manual verification**: record the exercised behavior and observed result.
  If no meaningful manual path exists, record `N/A` with a reason.
- **External contracts**: when an external integration is changed, record the
  live verification evidence, sanitized fixture, and any unverified fields per
  External Integration Contract Verification.
- **CI**: all checks must pass on the latest commit before merge is
  requested.
- **Reviewers**: applicable reviewer agents must be invoked and
  findings addressed (per existing guardrails).
- **Human approval**: the repository owner must explicitly authorize
  the merge by referencing the PR number.

### Issue and PR Body Formatting

Issue descriptions and pull request bodies are rendered as HTML by
GitHub's web UI, which wraps text to the viewport width automatically.
Do NOT hard-wrap lines in issue or PR bodies at a fixed column width
(72, 80, or any other limit) — let the browser handle wrapping. A
paragraph should be written as a single unwrapped line (or with one
sentence per line, if preferred for diff readability); it must not be
manually broken into fixed-width lines.

The 72-character hard-wrapping convention remains scoped to:

- The first line (subject) of commit messages — a Git convention
  respected by `git log`, terminal pagers, and `gh` output
- Files in the repository read in editors or terminals (source code,
  Markdown documentation, configuration) — see the 88-character line
  length rule under Python (Backend) for code, and standard prose
  wrapping for documentation files

### Branch Naming

| Prefix | Use |
|--------|-----|
| `feature/` | New features |
| `fix/` | Bug fixes |
| `docs/` | Documentation changes |
| `refactor/` | Code refactoring |
| `chore/` | Infrastructure, configuration, dependencies |
| `ci/` | CI/CD pipeline changes |
| `test/` | Test-only changes |

### Commit Messages

- Use conventional commits format: `type: description`
- Types: `feat`, `fix`, `docs`, `refactor`, `test`, `chore`, `ci`
- Use `!` only with `feat` or `fix` to signal a breaking change:
  `feat!: description`, `fix(scope)!: description`
- Keep the first line under 72 characters
- Use imperative mood: "add feature" not "added feature"
- Examples:
  - `feat: add CVE severity filtering to dashboard`
  - `fix: correct CVSS score parsing for NVD API v2`
  - `feat(api)!: remove a deprecated response field`
  - `docs: update data model with Product table`
  - `test: add integration tests for CVE sync service`

### Versioning

PR titles become commit subjects on `master` through squash merge and therefore
carry the release signal used by release-please:

| Commit type | Release signal |
|-------------|----------------|
| `fix` | Patch |
| `feat` | Minor |
| `fix!`, `feat!` | Breaking release; the resulting version depends on whether Sentinel is pre-1.0 or stable |
| `docs`, `chore`, `ci`, `test`, `refactor` | No release on their own; `!` is not permitted |

The complete Semantic Versioning interpretation, pre-1.0 policy, changelog
policy, version source of truth, and intentional `1.0.0` graduation procedure
are defined in `docs/deployment.md` (Release Process).

## Specification Writing

### API Cross-references

Feature specs that define API endpoints MUST include `docs/api-spec.md` in
their Cross-references section. The rules governing what appears in
per-endpoint error tables (global responses, scoped responses, Pydantic
validation) are defined in `docs/api-spec.md` (section "What belongs in
an endpoint error table") and are not restated here.

### Fetcher Documentation

Every `BaseFetcher` subclass follows the classification, minimum template,
cross-reference, registry, placement, and narrowly scoped test-only exception
rules in `docs/features/platform/fetcher-infrastructure.md` (Fetcher
Documentation Requirements). That specification is the single source of truth
for the complete documentation contract.

### Function Specification Completeness

Every function documented in a feature specification MUST provide enough
information to implement its contract without inventing behavior or semantics.
The Decision rule defines the controlling insufficiency and excess tests.

Specifications define **what the system must do**, including observable
behavior, business rules, persisted state, side effects, audit events, error
semantics, idempotency, concurrency guarantees, security and data-integrity
requirements, and externally relevant operational constraints. A technical
choice also belongs in a specification when choosing differently would alter
one of those contracts or violate an established architectural boundary.

Specifications do not normally prescribe **how equivalent behavior is
implemented**. Internal module organization, private helper interfaces,
dependency-injection mechanisms, interchangeable algorithms, connection
pooling, resource-lifecycle mechanics, and library options remain
implementation choices when they have no contract-level effect and do not
violate an established architectural boundary. The existence of multiple
technically valid implementations is not by itself a specification gap.

#### Required Information (by function category)

Functions are classified into two categories based on their observable
effects:

**Category A — Functions with side effects**: any function that mutates
database state, creates audit events, enqueues tasks, acquires locks, or
calls external services.

The spec MUST answer ALL of the following questions. Answer format and
location follow Structural freedom.

| # | Question | What the implementer needs to know |
|---|----------|------------------------------------|
| Q1 | What are all inputs and their types? | Function signature: parameter names, types, and semantic meaning of any parameter whose purpose is not obvious from name+type alone |
| Q2 | When does the function refuse to execute? | All guard conditions that cause early rejection (raises/returns before the main mutation begins), and what exception or error each guard produces |
| Q3 | What does it do in every possible case? | Complete behavioral specification covering all execution paths — the implementer must never encounter a case the spec does not address |
| Q4 | What audit events does it create, and under what conditions? | Event type, which fields are populated, and whether creation is conditional. If the function creates no audit events, state "None" explicitly (unless derivable per the Decision rule) |
| Q5 | What happens on re-invocation with the same inputs? | Whether the function is idempotent, conditionally idempotent, or creates new effects on every call. Critical for Celery retry safety and API consumer retry logic |
| Q6 | What exceptions does it propagate to callers? | All exceptions that escape the function boundary, including shared exceptions from other modules |

**Category B — Pure/stateless functions**: functions that perform
computation without side effects (no DB writes, no audit events, no
external calls). Includes query builders, resolution cascades, parsers,
validators, and read-only lookups.

The spec MUST answer:

| # | Question |
|---|----------|
| Q1 | What are all inputs and their types? |
| Q3 | What does it do in every possible case? |
| Q6 | What exceptions does it propagate? (or "None" if infallible) |

Q2, Q4, Q5 are not applicable to stateless functions and SHOULD be
omitted (their absence is not a gap).

#### Structural freedom

The convention prescribes WHAT information must be present, not HOW it
is organized. All of the following are valid structures for answering
the required questions:

- Dedicated labeled sections (e.g., "Preconditions", "Audit events")
- Numbered behavioral steps where guards, audit events, and
  re-invocation are naturally embedded in the flow
- Sub-sections organized by independent concerns (e.g., "Merge
  Strategy", "Transaction Boundaries") where each concern answers a
  subset of the questions
- Consolidated tables as defined in Consolidated groups
- Narrative prose with code blocks, flow diagrams, or pseudo-code
- Any combination of the above

The author SHOULD choose the structure that maximizes clarity for the
specific function. A complex orchestrator function benefits from
concern-based sub-sections; a trivial guard benefits from a one-line
signature description. Forcing either into the other's format degrades
readability.

#### Consolidated groups

When 2+ functions share an identical structural pattern (e.g., all are
HTTP client wrappers, all are single-statement metric helpers, all are
CRUD delegations with the same shape), they MAY be documented as a
single table with columns adapted to the group's nature. Grouping changes
only the presentation: the table MUST answer Q1, Q3, and Q6 for every
function, plus Q2, Q4, and Q5 for every Category A function unless the
answer is unambiguously derivable under the Decision rule.

#### Module-level defaults

A spec MAY declare default answers to Q4, Q5, or Q6 that apply to all
functions in a section. Per-function documentation then only states
deviations from the default. This eliminates repetitive "None"
statements across homogeneous function groups.

Example:

> All functions in this module propagate only the exceptions listed in
> the Service Exceptions table. No function creates audit events unless
> stated per-function. Read-only functions are infallible.

Example (delegate propagation):

> All public functions in this module propagate exceptions from
> delegated services (`ticket_mutations`, `user_service`) unless
> explicitly caught inline. Callers must handle both this module's
> Service Exceptions and those of the delegated modules.

A module-level default MUST be placed at the beginning of the functions
section (before the first function) so readers encounter it before any
individual specification. Per-function overrides take precedence over
the default.

#### Decision rule

**Insufficiency test**: if an implementer reading the specification must
choose between two plausible behaviors, guarantees, or contract semantics,
the specification fails the completeness requirement. A choice between
internal technical mechanisms that preserve all specified behavior and
constraints does not fail this test.

**Excess test**: if the spec repeats information already obvious from
the function's name and type signature alone, the documentation is
excessive. Likewise, if a technical detail does not constrain behavior,
interoperability, security, data integrity, operations, or an established
architectural boundary, omit it unless it is necessary explanatory context.

**Derivability rule**: a question's answer MAY be omitted when it is
unambiguously derivable from:

1. **The function's category** — Category B functions have no side
   effects by definition; Q4 is inherently "None" and Q5 is inherently
   "N/A" without per-function repetition
2. **Other answers already present** — if Q3 (behavior) or Q2 (guards)
   already make the answer logically certain, restating it is redundant.
   Examples: if Q2 shows a guard that rejects on a post-mutation state,
   Q5 (re-invocation fails on that guard) is derivable; if Q3 shows
   only deterministic in-memory operations with no failure paths, Q6
   ("None") is derivable
3. **A module- or section-level default for Q4, Q5, or Q6** — see
   Module-level defaults

The Insufficiency test takes precedence for contract-level questions: if
there is any reasonable ambiguity about required behavior or guarantees, the
specification MUST resolve it explicitly. Do not resolve that ambiguity by
prescribing unrelated implementation details, and do not add details merely
to eliminate legitimate implementation freedom.

#### Scope and Exclusions

This convention applies to **service-layer functions, private helpers,
and utility functions** documented in feature specifications. A specification
need not document a private helper whose interface and behavior are entirely
internal implementation choices. When a specification deliberately gives a
private helper contract-level responsibilities, however, that documented
contract follows this convention. The
following categories use their own documentation patterns and are NOT
subject to these completeness questions:

1. **API endpoint handlers**: documented using the endpoint format
   (Request body/Query parameters + Behavior + Response + Error
   responses). See `docs/api-spec.md` for endpoint documentation
   standards. This includes FastAPI dependencies that produce HTTP
   responses directly (authentication middleware, authorization guards
   injected via `Depends()`).

2. **Fetcher `execute()` algorithms**: documented using the fetcher
   documentation template (Properties table + Algorithm + Error handling
   + Metrics) defined in
   `docs/features/platform/fetcher-infrastructure.md`. Named helper
   functions documented exclusively as sub-steps within an excluded
   algorithm's section inherit the exclusion. If the helper is extracted
   into its own top-level section or referenced from multiple unrelated
   algorithms, this convention applies.

3. **Interface and abstract contracts**: abstract methods, protocol
   definitions, and hook method contracts that define what implementors
   must provide. These use: Signature + Contract semantics + Signaling
   convention (if applicable).

4. **Event-processing pipelines**: message handlers and long-running
   consumer pipelines whose "parameters" are message payload fields.
   These use numbered pipeline steps without the Q1-Q6 framework.

5. **CLI command behaviors**: documented using the CLI Output Contract
   (Parameters + Behavior + Idempotency + Exit codes + Output channels)
   defined in the CLI Conventions section. The "Idempotency" declaration
   satisfies Q5.

**Precedence rule**: when a more specific documentation template exists
for a function category, the specific template takes precedence. This
convention applies to all functions NOT covered by a more specific
template.

**Cross-reference overviews**: when a function's authoritative
specification lives in another document, a lighter behavioral overview
in the referencing document is acceptable. It MUST NOT be elevated to
the function's full completeness level — that would create
contradictory sources of truth.

#### Algorithm-reference pattern

When a function's complete algorithm is already specified in a dedicated
section of the same document (e.g., a resolution cascade, a match
procedure), the function's own entry MAY reference that section instead
of re-specifying the steps. The reference must be unambiguous (section
name or anchor). The referenced section must itself answer Q3 for all
execution paths.

### Service Exception Conventions

Every service module that raises exceptions propagated to API callers
MUST follow the standard exception documentation pattern established in
`docs/features/packages/package-service.md`.

#### Base class requirement

All module-owned exceptions inherit from a common `<Module>ServiceError` base
class (e.g., `TicketServiceError`, `UserServiceError`). Shared exceptions
follow the distinct inheritance rule in Shared exceptions. All module base
classes inherit from a common `ServiceError` root class. Each service spec MUST
state this hierarchy, identify shared exceptions with `†`, and require API
handlers to catch each documented exception and map it according to
`api-spec.md`. A module-level catch does not cover shared exceptions.

#### API-facing exception table format

All modules use a 4-column table for exceptions that reach API handlers:

| Exception | HTTP | Code | Raised when |
|-----------|------|------|-------------|
| `ExampleError` | 409 | `DOMAIN_ERROR_CODE` | Brief semantic condition |

#### System-internal exception sub-table

For exceptions that never reach an API handler (CLI-only, fetcher-only,
or caught internally), a separate sub-table is used:

| Exception | Raised when | Handling |
|-----------|-------------|----------|
| `InternalError` | Semantic condition | How callers handle it |

#### "Raised when" column rules

- Describes the **semantic condition** that triggers the exception in
  one brief sentence
- Does NOT list function names or code paths (avoids drift when
  implementations change)
- The condition should be stable — tied to the exception's meaning,
  not to implementation details

#### 1:1 mapping rule

Every API-facing exception MUST map to exactly one HTTP status code and
one error code. If an exception currently maps to multiple codes based
on an attribute (e.g., `reason`), it MUST be split into separate
exception classes — one per distinct error code.

#### Domain-specific validation codes

Domain-specific validation exceptions (e.g., `PasswordValidationError`,
`ApiKeyNameValidationError`) use domain-specific error codes (e.g.,
`USER_PASSWORD_POLICY_VIOLATION`, `AUTH_API_KEY_NAME_INVALID`) — NOT the
generic `VALIDATION_ERROR` code. Response-envelope and Pydantic validation
semantics are defined in `docs/api-spec.md`.

#### Mapping authority chain

The three-tier authority relationship for error information is:

1. **`api-spec.md`** — authoritative registry of all valid error codes
   (prefix, domain, enumeration)
2. **Service spec** — authoritative source for each exception's HTTP
   status code and error code mapping
3. **Endpoint error tables** (in feature specs like `tickets.md`,
   `user-management.md`) — reference the service spec's exceptions for
   traceability; not authoritative for the HTTP/code mapping

The HTTP/code mapping for each exception MUST be documented in the
service module spec itself — not deferred to endpoint-level error tables
in other specs.

Every error code appearing in a service exception table MUST also be
registered in the Error Code Categories table in `api-spec.md`.

#### Shared exceptions

Exceptions used by multiple service modules (e.g., `TicketNotFoundError`
used by `ticket-service`, `ticket-mutations`, and `package-service`) are
defined once in a common exceptions module and imported by each service.
Each service spec MUST still list the exception in its own table (the
reader should not need to consult another spec). Shared exceptions are
marked with `†` in exception tables.

**Inheritance**: shared exceptions inherit from `ServiceError` directly —
they are NOT subclasses of any individual module's base class.

**Handler requirements**: API handlers MUST catch each exception class
individually. Using `except ModuleServiceError` as a catch-all is
insufficient when the table includes shared exceptions (marked `†`),
since those do not inherit from the module's base class. A
`except ServiceError` fallback MAY be added for defense-in-depth but
MUST log a warning (indicates a missing specific handler).

#### Endpoint error tables (post-standardization)

Endpoint error-table membership, including global and scoped response
derivation, is defined in `docs/api-spec.md` (What belongs in an endpoint error
table and Response Applicability Derivation). The authoritative HTTP/code
mapping for a service exception remains in its owning service specification.

### Roadmap Independence

Behavioral specifications — everything in `docs/features/`,
`docs/architecture.md`, `docs/api-spec.md`, `docs/data-model.md`,
`docs/data-sources.md`, `docs/deployment.md`, `docs/configuration.md`,
`docs/cli-reference.md`, and `docs/system-map.md` — describe what the
system does. They MUST remain fully valid regardless of implementation
sequencing: which phase is in progress, which work item introduced a
behavior, or whether a given planning artifact still exists.

**Forbidden** in behavioral specifications:

- A roadmap phase label used to scope, justify, or explain a documented
  boundary (e.g., "Phase 3 owns...", "Excluded from Phase N",
  "(Phase N+)")
- A work-item, piece, or gate identifier (e.g., `P3-10`, `SG3-01`,
  `RG-01`) cited as the reason for a behavior or a scope boundary
- A cross-reference into a roadmap or planning document as the
  explanation for why something is or is not specified here
- A reviewer-finding identifier (e.g., "G-01", "GAP-3") or a reference
  to a "Reviewer Findings" section that does not exist in the spec
  itself

**Allowed**:

- "Phase" as a generic English word for a step within an algorithm,
  transaction, or lifecycle (e.g., "Phase 1 — lock and validate roots",
  "run() phase 4", or a product/domain lifecycle stage such as
  "Local-only phase (current)")
- A scope statement expressed purely in ownership terms, with a
  cross-reference to the actual owning spec (e.g., "The
  `GET /api/v1/ibs-consumer/status` endpoint is defined in
  `ibs-rabbitmq-integration.md`, not here") — without naming a roadmap
  phase or work-item ID

**Where this information belongs instead**:

- A living execution roadmap, if one is in use (see `docs/drafts/` for
  current planning material) — owns phase/piece sequencing, dependency
  rationale, and stable work-item IDs
- The GitHub issue tracking a specific work item — its description and
  comments are the right place to record phase-specific notes,
  implementation decisions, and notes on how reviewer findings were
  addressed for that piece of work (see Workflow — Issues and work units)

**Rationale**: work-item identifiers get renumbered as a roadmap
evolves, and planning artifacts are retired once fully consumed. A spec
that cites a phase number, work-item ID, or planning document by name
will silently go stale when the roadmap changes shape or the planning
document disappears, with no code or behavioral change to signal the
drift. The information worth keeping — which specification owns which
behavior — is always expressible as a spec-to-spec cross-reference,
independent of any roadmap state.
