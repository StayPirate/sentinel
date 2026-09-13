# Architecture

## Contents

- [Scope](#scope)
- [Authority and Navigation](#authority-and-navigation)
- [System Boundary](#system-boundary)
- [Architectural Decisions](#architectural-decisions)
  - [Async-only database layer](#async-only-database-layer)
  - [Single Docker image, multiple entrypoints](#single-docker-image-multiple-entrypoints)
  - [Celery + Redis with no result backend](#celery--redis-with-no-result-backend)
  - [PostgreSQL as single source of truth](#postgresql-as-single-source-of-truth)
  - [Capability-based RBAC](#capability-based-rbac)
  - [Specs-first development](#specs-first-development)
- [Design Constraints](#design-constraints)
- [Backend Layer Architecture](#backend-layer-architecture)
- [Integration Patterns](#integration-patterns)

---

## Scope

This document defines the structural decisions and design constraints of the
Sentinel platform: the reasoning behind the system's shape. It is the entry
point for understanding why the system is built the way it is.

Implementation patterns, operational procedures, data contracts, and feature
behavior belong to the authorities listed below. This document summarizes them
only where necessary to explain an architectural decision.

## Authority and Navigation

| Information type | Authoritative location |
|---|---|
| Database schema (tables, columns, relationships, constraints) | `docs/data-model.md` |
| External data sources (catalog, protocols, hosts, credentials) | `docs/data-sources.md` |
| Component diagrams and data flow visuals | `docs/system-map.md` |
| API surface, envelopes, errors, and pagination | `docs/api-spec.md` |
| Code patterns, naming, and technical conventions | `docs/conventions.md` |
| Environment variables and configuration | `docs/configuration.md` |
| Deployment, process topology, and operations | `docs/deployment.md` |
| CLI commands | `docs/cli-reference.md` |
| Identity and access control | `docs/features/identity/rbac.md` |
| Fetcher infrastructure | `docs/features/platform/fetcher-infrastructure.md` |
| CVE fetcher infrastructure | `docs/features/platform/cve-fetcher-infrastructure.md` |
| Git-based fetcher infrastructure | `docs/features/platform/git-fetcher-infrastructure.md` |
| IBS event-driven integration | `docs/features/integrations/ibs-rabbitmq-integration.md` |
| Operational logging | `docs/features/platform/logging.md` |

---

## System Boundary

Sentinel is a security update management platform for SUSE and openSUSE-based
Linux distributions. It automates CVE tracking, impact analysis, and update
coordination across multiple maintained distribution versions.

**What Sentinel does:**

- Ingests CVE data from multiple public and internal sources
- Creates and manages security tickets from CVE detections
- Tracks which packages, codestreams, and products are affected
- Detects when security fixes are released via IBS
- Evaluates product eligibility based on CVSS thresholds and lifecycle
- Provides an API for vulnerability analysts, team leads, and automation

**What Sentinel does NOT do:**

- Build or submit packages (IBS handles builds)
- Manage product lifecycle or release schedules (SMELT/AIMAAS own this)
- Provision user identities (deferred to external identity provider)
- Provide a web UI (frontend is developed in a separate repository)

**Repository scope:** this repository contains all product specifications (in
`docs/features/`) and the backend implementation (FastAPI, Celery workers,
migrations, CI/CD). The frontend will be developed in a dedicated repository
against the published OpenAPI contract.

---

## Architectural Decisions

These decisions shape the system at a structural level. Each entry states the
choice and its rationale; specialist authorities own the implementation and
operational details.

### Async-only database layer

Sentinel uses `asyncpg` with SQLAlchemy's async API for all database access in
API handlers, service modules, Celery tasks, and CLI commands. No synchronous
database driver or engine is maintained. Synchronous entry points bridge into
the async layer using the lifecycle rules in `docs/conventions.md`.

**Rationale:** one database access model prevents accidental mixing of sync and
async sessions, connection pools, and transaction semantics. It also keeps
service-layer code reusable across all entry points.

### Single Docker image, multiple entrypoints

All runtime processes — API server, Celery worker, git worker, Celery Beat,
and IBS RabbitMQ consumer — run from the same OCI image with different
entrypoint commands. There are no per-process image variants. See
`docs/deployment.md` (Container Images) for the canonical process roles.

**Rationale:** all processes share the same codebase and dependencies. Separate
images would add build and storage overhead while risking version skew between
components that must run the same code.

### Celery + Redis with no result backend

Sentinel uses Celery with Redis as its broker. The Celery result backend is
disabled (`task_ignore_result = True`), so task return values are not stored
there. Durable outcomes belong in PostgreSQL under the relevant domain model;
fetcher executions use `FetcherRun` records.

**Rationale:** durable outcomes must remain queryable and survive Redis
restarts. A Celery result backend would duplicate domain records in an
ephemeral store with inferior queryability and durability.

### PostgreSQL as single source of truth

All persistent Sentinel state lives in PostgreSQL. Redis is limited to
ephemeral coordination such as task queues, schedule entries, caches, and
locks. Redis persistence is disabled by design: its state is TTL-bounded and
self-healing, or reconstructible from PostgreSQL or code at process startup.

**Rationale:** a single persistent source of truth simplifies backup, recovery,
and operational reasoning. See `docs/deployment.md` (Redis Durability, Memory,
and Persistence) for the operational implications.

### Capability-based RBAC

Authorization uses a capability model: roles map to sets of capabilities, and
endpoint access is determined by checking whether the caller possesses the
required capability. This differs from pure role checks ("is the user an
admin?") and from attribute-based access control (ABAC).

**Rationale:** capability checks decouple endpoint authorization from role
definitions. New roles can combine existing capabilities without changing
endpoint code. See `docs/features/identity/rbac.md` for the full model.

### Specs-first development

Every feature must be specified in `docs/features/` before implementation
begins. The specification must be complete enough that an implementer does not
need to invent product behavior, guarantees, contract semantics, security, or
data-integrity properties. Internal technical choices remain with the
implementation when multiple approaches satisfy all specified behavior and
established architectural constraints.

**Rationale:** specifications form the contract between design and
implementation. They support review before implementation, prevent scope
creep, and provide a stable reference for future maintenance.

---

## Design Constraints

These non-negotiable principles inform every feature specification and
implementation decision.

**Stateless containers.** Application containers must not rely on local
persistent filesystem state for correctness. Persistent Sentinel state belongs
in PostgreSQL; Redis holds only ephemeral state, and external systems retain
the data they authoritatively own. Recoverable local caches, such as git clone
volumes used by CVE fetchers, may use persistent storage for performance when
the application remains correct without them.

**Deployment-agnostic packaging.** The application must not depend on a
specific runtime orchestrator. Sentinel publishes one OCI image without
environment-specific variants. Consumers may run that image with Docker,
Podman, Kubernetes, or another compatible runtime at their discretion; runtime
differences belong in deployment configuration, not in application code.
Repository-managed development and test tooling may standardize on Docker
without making the published artifact Docker-specific.

**API-first.** The REST API is the primary interface. Every operation needed by
any consumer (web UI, CLI, scripts, or third-party integrations) must be
achievable through the API, with equivalent filtering, pagination, and sorting
capabilities. The API must remain independent of any client or hosting
strategy.

**HTTP APIs for external services.** When Sentinel integrates with an external
service that exposes an HTTP/REST API, it uses that API directly.
Service-wrapper CLI tools such as `osc` and `secbox` add an unnecessary process
dependency and must not be used in application code or background tasks.

This constraint does not apply to transport-protocol clients when the data
source has no HTTP API equivalent. For example, the `git` binary provides the
transport needed by repository-based CVE sources. The applicable implementation
contract is in `docs/features/platform/git-fetcher-infrastructure.md`.

**Environment-variable configuration.** Deployment and infrastructure
configuration is provided through environment variables. Secrets must not be
baked into images or committed to the repository. Business settings that need
runtime modification without restart are stored in the database. See
`docs/configuration.md` for the configuration contract and
`docs/conventions.md` (Configuration Management) for its governance.

---

## Backend Layer Architecture

The backend uses seven application layers with an explicit dependency graph.
Each layer may depend only on the layers listed in the final column; listed
order does not imply additional dependencies.

| Layer | Location | Responsibility | May depend on |
|---|---|---|---|
| **API** | `app/api/` (`app/api/v1/` for versioned routes) | Thin endpoint handlers and API dependencies: validate input, resolve transport-level caller state, call services, map service outcomes to HTTP, and return responses. No business logic or business database queries. | Service, Schema, Model (for DI type annotations), Core |
| **CLI** | `app/cli/` | Thin command handlers: parse arguments, call services, format output. No business logic. | Service, Model (only where an owning specification explicitly permits a trivial read-only query), Core |
| **Task** | `app/tasks/` | Thin Celery task wrappers that call services, plus worker and Beat lifecycle signal handlers that necessarily depend on services. | Service, Core |
| **Service** | `app/services/` | All business logic and business database operations, including model-aware accessibility predicates and visibility-constrained resource queries. Accept typed parameters and return typed results. | Model, Core |
| **Schema** | `app/schemas/` | Pydantic models for request/response validation and serialization. | Model (for `from_attributes`), Core |
| **Model** | `app/models/` | SQLAlchemy ORM models: tables, columns, relationships, constraints. | Core (for enums only) |
| **Core** | `app/core/` | Cross-cutting concerns: authentication, authorization, configuration, exceptions, and enums. | (no application imports) |

**Key rules and exceptions:**

- Services own business queries and mutations. New or modified API reads use a
  service boundary; a route may execute a trivial legacy read only when an
  owning specification explicitly authorizes it. A CLI may execute a trivial
  read-only query under the same explicit-specification exception, although an
  existing service query boundary is preferred.
- Consumer-facing services receive the caller information needed by their
  owning access-control contract and own model-aware accessibility queries.
  Thin API dependencies may delegate to those services and translate an
  inaccessible result to the required HTTP response, but neither handlers nor
  dependencies construct business ORM predicates. Core may parse transport-
  independent identifier syntax or perform other pure authorization
  computation; it does not import application models or services and does not
  query application state.
- Entry-point infrastructure may manage session and transaction completion,
  but that responsibility does not move business database operations out of
  services. Composable services receiving a caller-supplied `AsyncSession`
  flush but do not commit or roll back. The API transaction dependency, a
  complete CLI workflow, or a complete task workflow owns one commit on
  success or one rollback on failure, as defined in `docs/conventions.md`
  (Caller-Owned Service Transactions).
- Core has no application-level imports and remains a leaf dependency. These
  accessibility responsibilities use the existing Service and API layers; they
  do not introduce another layer.

---

## Integration Patterns

Sentinel's background integrations follow two patterns. The complete source
catalog and request-driven interactions are documented in
`docs/data-sources.md` and their owning feature specifications.

**Scheduled integrations.** Periodic external-data synchronization uses Celery
Beat. Each scheduled integration is a `BaseFetcher` subclass, which provides
execution tracking, metrics, and registry integration. Specialized bases add
contracts without changing that classification:

- `BaseFetcher` supports generic external-data synchronization. See
  `docs/features/platform/fetcher-infrastructure.md`.
- `BaseCVEFetcher` extends it for CVE sources and on-demand CVE retrieval. See
  `docs/features/platform/cve-fetcher-infrastructure.md`.
- `BaseGitFetcher` extends the CVE contract for repository-based delta flows.
  See `docs/features/platform/git-fetcher-infrastructure.md`.

**Event-driven integrations.** The IBS integration additionally uses a
continuous AMQP consumer connected to the IBS RabbitMQ message bus for
near-real-time package commit and submission-state events. A periodic fetcher
runs alongside it to recover events missed during consumer downtime. See
`docs/features/integrations/ibs-rabbitmq-integration.md`.
