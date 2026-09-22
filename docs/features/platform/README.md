# Platform

Cross-cutting infrastructure and system administration.

## Specs

```
fetcher-infrastructure.md       BaseFetcher base class, registry, execution tracking
cve-fetcher-infrastructure.md   BaseCVEFetcher base class, CVE fetcher conventions
git-fetcher-infrastructure.md   BaseGitFetcher base class, git_operations module
networking.md                   HTTP client (httpx), TLS configuration, SUSE CA
fetcher-operations.md           Monitoring, API, and CLI diagnostics for fetchers
audit-trail-infrastructure.md   BaseAuditLog base class, AuditEventMixin
cli-infrastructure.md           Shared CLI mechanism: entry point, session management, error handling
system-settings.md              System-setting persistence, bootstrap, API, audit
default-cvss-version-operations.md  Default-CVSS preview and recalculation operations
health-endpoints.md             Liveness (/health) and readiness (/ready) probes
logging.md                       Operational/diagnostic logging model, correlation IDs
cve-record-parser.md            Shared CVE record parser for all CVE fetchers
cve-source-failure-retry.md     Retry policy for per-source CVE fetch failures
testing-strategy.md             Testing methodology, fixtures, coverage policy
```

## Relationships

- `fetcher-infrastructure.md` defines the base class contract that all
  scheduled data-fetching tasks inherit from. Continuous event consumers such
  as the IBS RabbitMQ consumer are separate integration processes rather than
  fetchers.
- `cve-fetcher-infrastructure.md` extends `fetcher-infrastructure.md` with
  the `BaseCVEFetcher` contract for CVE-specific fetchers.
- `git-fetcher-infrastructure.md` extends `cve-fetcher-infrastructure.md`
  with the `BaseGitFetcher` contract for git-based delta-flow fetchers.
- `networking.md` defines the shared HTTP client (`httpx`) and TLS
  configuration used by all fetchers and services.
- `fetcher-operations.md` is the monitoring layer built on top of
  `fetcher-infrastructure.md` — it consumes `FetcherRun` records.
- `cli-infrastructure.md` defines the shared mechanism backing every CLI
  command (entry point, session management, error handling, signal
  handling); individual command groups
  (`user-management.md`, `api-key-management.md`, `fetcher-operations.md`)
  consume it. It implements the contract declared in `docs/conventions.md`
  (CLI Conventions) and consumes the CLI bootstrap requirement declared in
  `logging.md` (Scope of this pipeline).
- `system-settings.md` defines the system-setting mechanism, general API, and
  setting audit. `default-cvss-version-operations.md` defines the impact
  preview, all-CVE recalculation runner, manual trigger, observability, and
  recovery for the `default_cvss_version` setting. Both consume the pure
  resolutions in `tickets/cvss-scoring.md` without redefining them.
- `testing-strategy.md` defines the testing methodology, database setup,
  and coverage policy. Its audit trail testing section references
  `audit-trail-infrastructure.md` for the Audit Trail Index.
- `logging.md` defines the operational logging model (structured logs,
  correlation IDs) consumed implicitly by every other spec that
  prescribes log statements; it is distinct from
  `audit-trail-infrastructure.md`, which governs persisted business
  audit events.
