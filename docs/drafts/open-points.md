# Open Points

Architectural decisions pending resolution before implementation begins.

## Summary

| ID | Title | Domain | Status |
|----|-------|--------|--------|
| OP-1 | Enum Storage Strategy | — | Resolved |
| OP-2 | Rate Limiting via Reverse Proxy | Deployment | Open |
| OP-4 | Anomaly Observer | Packages | Open |
| OP-6 | Periodic Ticket Status Reconciliation | Tickets | Open |
| OP-7 | Platform Status Monitoring | Platform | Open |
| OP-8 | Simplify Duplicate Handling | Tickets | Resolved |
| OP-11 | Ecosystem Prefix Mapping | Packages | Open |
| OP-13 | CWE Accumulation | Fetcher Infrastructure | Open |
| OP-15 | IBSEventConsumer Admin Restart Endpoint | Platform | Open |
| OP-16 | CPE Mapping Fail-Fast Asymmetry | — | Resolved |
| OP-17 | IBS RabbitMQ Consumer Startup Gaps | — | Resolved |
| OP-3 | Orphan CVE Re-Ticketing | — | Resolved |
| OP-5 | Response Header for Silently Ignored Parameters | — | Closed |
| OP-9 | Remove FetcherRunWeeklyAggregate | — | Resolved |
| OP-10 | Ecosystem Column on CVEAffectedVersion | — | Resolved |
| OP-12 | Fetcher Metrics Granularity | — | Resolved |
| OP-14 | BaseFetcher All-Items-Failed Safety Check | — | Resolved |
| OP-18 | Cross-Process Startup Ordering | — | Resolved |
| OP-19 | Beat Reconciliation Wiring Mechanism | — | Resolved |

---

## Open — Deployment

### OP-2. Rate Limiting via Dedicated Reverse Proxy

**Origin**: SSO-SEC-02 finding during sso-authentication spec review.

**Context**: the SSO endpoints (`POST /api/v1/auth/sso/callback` and
`GET /api/v1/auth/sso/authorize`) are public and perform
cryptographic operations (HMAC verification) and outbound HTTP requests
(token exchange with IdP) on every call. Without rate limiting, an
attacker could flood these endpoints for DoS against Sentinel or to
trigger rate limiting at the IdP, blocking legitimate logins.

More broadly, rate limiting is a cross-cutting concern that applies to
multiple public endpoints (login, SSO, password reset, etc.), not just
SSO.

**Proposed approach**: deploy a dedicated reverse proxy (nginx, Traefik,
or Kubernetes ingress controller) in front of Sentinel with rate
limiting rules per endpoint. This is preferable to application-level
rate limiting because:

- Centralized configuration — applies consistently across all endpoints
- More efficient — requests are rejected before reaching the application
- Avoids per-request Redis dependency for rate limit state
- Aligns with Sentinel's architecture (nginx or reverse proxy already
  planned for API routing)

**Recommended limits** (starting point):

| Endpoint | Limit | Window |
|----------|-------|--------|
| `GET /api/v1/auth/sso/authorize` | 20 requests per IP | 1 minute |
| `POST /api/v1/auth/sso/callback` | 10 requests per IP | 1 minute |
| `POST /api/v1/auth/login` | 10 requests per IP | 1 minute |

**When to implement**: before staging/production deployment. Not needed
for local development.

**Decision needed**: which proxy to use (nginx or a reverse proxy is
already planned for API routing — may be sufficient), and whether to add
application-level rate limiting as defense-in-depth or rely solely on
the proxy.

---

## Open — Tickets

### OP-6. Periodic Ticket Status Reconciliation as Drift Detection

**Origin**: analysis of TKM-DES-07 (race window between
`deactivate_user` and concurrent ticket mutations) and broader
consideration of status drift scenarios.

**Context**: `reconcile_ticket_status` is called inline after every
mutation, making the system event-driven correct. However, if a bug
causes a mutation path to skip reconciliation — or if a race condition
leaves a ticket in a transiently inconsistent state that never receives
a subsequent mutation — the ticket remains silently drifted with no
mechanism to detect or correct it. Today, no one would notice.

**Proposed approach**: create a daily scheduled task (BaseFetcher
subclass) that iterates over all tickets in active statuses and calls
`reconcile_ticket_status` on each. For every ticket where
reconciliation actually changes the status (i.e., a drift was found and
corrected), the task MUST emit a prominent log entry (WARNING level)
containing:

- Ticket ID and CVE
- Previous status → new status after reconciliation
- Timestamp of last mutation on the ticket (to help identify when the
  drift was introduced)

This allows administrators to discover that a drift occurred, identify
the affected ticket(s), and investigate the root cause — potentially
uncovering a bug in a mutation path that failed to call reconciliation.

**Why logging matters**: the primary value is not the self-healing (which
is a nice side effect) but the **observability**. A silent self-heal
hides bugs. A logged self-heal surfaces them. The task effectively acts
as a continuous integration test for the event-driven reconciliation
architecture.

**Expected behavior under normal operation**: the task completes with
zero corrections on every run, confirming that all mutation paths are
correctly calling `reconcile_ticket_status`. Any non-zero correction
count is an indicator of a defect somewhere in the system.

**Decision needed**: (a) whether this should be a standalone fetcher or
integrated into an existing periodic task, (b) log level and alerting
strategy (WARNING + optional webhook notification to ops channel), (c)
whether to also emit a `TicketAuditEvent` for drift corrections (to
distinguish admin-triggered reconciliation from bug-induced drift in
the audit trail).

---

## Open — Packages

### OP-4. Anomaly Observer Replacing Static Anomaly Matrix

**Origin**: dimension decoupling analysis (C9 — Anomaly matrix,
Affectedness x Delivery, observational coupling classified as KEEP).

**Context**: the anomaly matrix in `package-model.md:523-558` defines 5
anomalous combinations of affectedness and delivery as a static table.
With eligibility decoupled from affectedness, the matrix could be
extended to include eligibility-related
anomalies (7+ combinations). The spec notes these are "destined to be
integrated into the future Review Queue" but no implementation design
exists.

**Proposed approach**: replace the static matrix with an independent
Anomaly Observer service — a pure function that reads the current values
of all three dimensions (affectedness, eligibility, delivery) and
produces anomaly tags. The observer would be called as a post-mutation
hook (similar to `reconcile_ticket_status()`) and write results to a
separate table consumed by the Review Queue UI. It would NEVER modify
any dimension's state.

**Infrastructure prerequisite**: if the observer needs to detect fixes
present in codestreams where the track is in a final affectedness status
(`NOT_AFFECTED`, `WONT_FIX`, or already `FIXED`), the IBS consumer
(`IBSEventConsumer`) and the periodic fetcher
(`detect_ibs_track_releases`) would need to be extended to also scan
final-status tracks. Currently, both filter their scope to tracks with
`status in (ANALYSIS, AFFECTED)` because the release detector only
transitions non-final tracks. The anomaly observer would need the raw
detection signal without the transition, requiring a broader scan scope.

**Use case — rejected automatic transitions**: when `set_track_status()`
rejects an automatic transition on a final-status track (e.g., IBS
release detection finds a fix for a track marked `NOT_AFFECTED`), this
is currently logged as a warning (see `package-service.md`,
`set_track_status()` step 5). A future Anomaly Observer could consume
these signals to surface them in the Review Queue as actionable
anomalies (e.g., "IBS detected a fix in codestream X for track Y, but
the VA marked it `NOT_AFFECTED` — review recommended"). This would
replace the passive warning log with an active notification to the VA.

**Decision needed**: (a) timing — implement alongside the Review Queue
feature or earlier as infrastructure, (b) storage — separate
`TicketAnomaly` table vs. flags on existing records, (c) whether the
observer should also detect intra-dimensional anomalies (e.g., a track
in `FIXED` status whose parent ticket has no CVE), (d) whether to
extend the IBS consumer and fetcher scan scope immediately (as part of
the decoupling work) or defer until the observer is implemented.

---

### OP-11. Ecosystem Prefix Mapping for Package Resolution

**Origin**: GHSA fetcher spec (OP-9 follow-up), Session 2 (2026-06-18)

**Context**: GHSA `resolved_packages` passes ecosystem package names
(e.g., "lodash", "requests", "github.com/openfga/openfga") to Phase 2
for best-effort SMELT resolution. Hit rate is ecosystem-dependent — high
for system-level C libraries that share names with RPM source packages
(e.g., "curl", "openssl", "zlib"), low for language-specific packages
with different naming conventions (e.g., pip `requests` → RPM
`python-requests`, npm `lodash` → no RPM equivalent).

A prefix mapping table could transform package names before SMELT
resolution (e.g., `pip:requests` → `python-requests`, `npm:node-forge` →
`nodejs-node-forge`).

**Proposed approach**: ecosystem-aware prefix/transform rules applied to
`resolved_packages` before passing to `add_package_to_ticket()`. Rules
would be a simple dict in the fetcher or a shared module.

**Prerequisite satisfied**: the `ecosystem` column on
`CVEAffectedVersion` is now in place (see OP-10 resolution in Archive
section). The ecosystem context needed for prefix mapping is available
in the data model.

**Decision needed**: is the additional hit rate worth the mapping
maintenance burden? Revisit when: (a) GHSA and OSV hit rate is measured
post-implementation and found insufficient for system-level packages, or
(b) practical experience shows which transform rules have the highest
ROI.

---

## Open — Fetcher Infrastructure

### OP-13. CWE Accumulation — Stale Records from Additive-Only Upsert

**Origin**: CISA KEV fetcher spec review (Session 4, 2026-06-20)

**Context**: `upsert_cve()` uses an additive-only pattern for `CVECWE`
records — the upsert key is `(cve_id, cwe_id, source)`, so new CWE
entries are inserted and existing ones are updated, but removed entries
are never deleted. If an external source corrects a CWE classification
(e.g., changes CWE-306 to CWE-79), the old record persists indefinitely
alongside the new one.

This affects any source that can revise CWE data over time: CISA KEV
(`cwes` array), NVD (problemType), MITRE CNA/ADP containers. The issue
is not specific to the KEV fetcher — it is a cross-cutting limitation of
the `upsert_cve()` infrastructure.

**Contrast with `CVEAffectedVersion`**: affected versions use
delete-and-reinsert (clear all records for the source, then reinsert the
current set), which naturally handles removals. `CVECWE` does not use
this pattern — likely because CWE corrections are rare and the data is
supplementary (VAs rely primarily on NVD/MITRE for CWE).

**Proposed approaches**:

- (a) Accept the limitation as-is — CWE data is supplementary,
  corrections are rare, and stale entries have low practical impact
- (b) Switch `CVECWE` to delete-and-reinsert per `(cve_id, source)` on
  each fetch — clean but increases write I/O for every run
- (c) Add a periodic cleanup job that compares current source data
  against stored records — complex, deferred maintenance burden

**Impact**: low for individual VAs (CWE is informational, not used for
gating or automation). Higher if CWE data is ever exposed in the UI as
authoritative or used for automated categorization.

**Decision needed**: is the theoretical data staleness worth addressing
now, or should it be deferred until practical impact is observed? Revisit
when: (a) a VA reports incorrect CWE data on a ticket, or (b) CWE
classifications are used for automated triage/routing.

---

## Open — Platform

### OP-7. Platform Status Monitoring — System Info Endpoint and Admin Page

**Origin**: CPE-to-Package mapping v2 draft
(`docs/drafts/cpe-package-mapping-v2.md`) — the static mapping file is
loaded and cached by each real consumer process on first use, with no
runtime observability. An administrator has no way to verify whether a
consumer loaded the mapping or how many entries it contains.

**Context**: Sentinel currently has no system info or diagnostics
surface beyond the minimal `/health` liveness endpoint (now formally
specified in `docs/features/platform/health-endpoints.md` alongside
the `/ready` readiness endpoint). The fetcher
dashboard monitors `BaseFetcher` subclasses with execution lifecycle
(runs, metrics, schedules), but infrastructure components that are not
fetchers — such as in-memory static data, connection pools, or loaded
configuration — have no monitoring surface.

The CPE mapping dict (~2,450 entries, ~2,800 package mappings) is the
first concrete case, but the need is broader: any static data loaded at
startup, future sync diagnostics (referenced in
`ibs-product-release-detection.md`), and general platform health
indicators would benefit from a dedicated monitoring area.

**Proposed approach**: two complementary mechanisms (not mutually
exclusive):

**(A) Lightweight public endpoint** — `GET /api/v1/system/info`

A public read-only endpoint that reports the status of loaded
infrastructure components. Initial payload:

```json
{
  "data": {
    "cpe_mapping": {
      "loaded": true,
      "entry_count": 2453,
      "package_count": 2810
    }
  }
}
```

Follows the IBS consumer status pattern (`GET
/api/v1/ibs-consumer/status`) — a non-fetcher infrastructure
component reporting its state via a dedicated endpoint. Useful for
API consumers, health checks, and automated monitoring.

**(C) Dedicated System Info admin page**

A new page in the admin area (sidebar item under Admin Settings) backed
by `GET /api/v1/admin/system-info`. Shows platform status information
with admin-only details (file paths, version info, loaded module
diagnostics). Room for growth: future sync diagnostics, data freshness
indicators, dependency health.

Options A and C can coexist: A provides a public API surface for
monitoring tools and scripts, C provides a richer admin UI with
additional detail. The public endpoint exposes a subset of the
information available on the admin page.

**Decision needed**: (a) whether to implement A alone first (minimal
scope) or A+C together, (b) which additional platform components
beyond CPE mapping should be included in the initial version, (c)
capability requirement for the admin page (reuse `manage_settings`
or a new `view_system_info` capability).

---

### OP-15. IBSEventConsumer Admin Restart Endpoint

**Origin**: analysis during fix of NET-GAP-02/06 (networking.md spec
review). While evaluating the SSL context lifecycle for long-lived
components, we identified that the IBSEventConsumer process has no
application-level restart mechanism accessible to administrators.

**Context**: `IBSEventConsumer` is a singleton long-running process that
maintains a persistent AMQPS connection to `rabbit.suse.de`. On
connection loss, it reconnects with exponential backoff (5s → 300s) and
retries indefinitely — there is no give-up condition. The only existing
management surface is a read-only status endpoint
(`GET /api/v1/ibs-consumer/status`).

Currently, the only way to restart the consumer is via infrastructure
access (SSH, `docker restart`, Kubernetes pod deletion). This creates a
dependency on infrastructure operators for scenarios that an application
administrator should be able to resolve independently:

- **Stuck state**: consumer reports `connected` but is not processing
  messages (edge case in AMQP heartbeat detection)
- **Memory leak / resource exhaustion**: long-running process accumulates
  resources over weeks/months; periodic restart is a common operational
  practice
- **Credential rotation**: RabbitMQ credentials changed via environment
  variables but the running process holds the old credentials
- **Post-deploy verification**: after a deploy, admin wants to ensure the
  consumer picks up the new code without relying on orchestrator health
  checks
- **Generic "try restarting"**: most common first-response to anomalous
  behavior visible in the dashboard

**Proposed approach**: `POST /api/v1/admin/ibs-consumer/restart`
(admin-only, capability: `manage_settings` or a dedicated
`manage_ibs_consumer` capability).

Design considerations to evaluate:

1. **Signaling mechanism**: the API server and the consumer run in
   separate processes. Options: (a) Redis flag that the consumer checks
   periodically (simple, slight delay), (b) signal the process via
   orchestrator API (Docker/Kubernetes — couples to deployment target),
   (c) a dedicated control channel (AMQP management queue — adds
   complexity)
2. **Event loss window**: during restart, the transient AMQP queue is
   destroyed and messages are lost. The periodic catch-up fetcher
   (`detect_ibs_track_releases`, every 24h) mitigates this, but the
   admin should be warned in the UI. Consider a confirmation dialog:
   "Events will be lost during restart (~30s window). The periodic
   fetcher will catch up within 24 hours."
3. **Scope**: should this extend to other singleton processes (Celery
   Beat)? Or is the consumer the only one with this operational need?
4. **Audit trail**: should restart actions be logged in an audit trail?
   Probably yes (IdentityAuditEvent or a platform-level audit log).
5. **Cooldown**: prevent rapid repeated restarts (e.g., minimum 60s
   between restart requests).

**Decision needed**: (a) signaling mechanism, (b) scope (consumer only
vs. all singletons), (c) capability assignment, (d) priority relative
to other open points.

---

## Archive — Resolved

### OP-12. Fetcher Metrics — Granularity and Semantics — RESOLVED (2026-09-17)

**Resolution**: separated terminal outcomes from durable effects. Every
selected work unit now terminates exactly once as succeeded or failed through
`record_succeeded()` or `record_failed()`. `record_created()` and
`record_updated()` retain their narrower durable-effect meanings and are called
only after durability; successful unchanged and no-op work no longer needs to
masquerade as updated. Dispatch-only success likewise uses the outcome metric.

No `record_skipped`, `record_missed`, persisted per-item outcome, or additional
metric dimension was introduced. Concrete fetchers define pre-scope exclusions
and which unchanged, missing, no-match, already-pending, or stale/inapplicable
results are successful terminal outcomes. This supplies truthful throughput
without change-detection pre-reads or extra database I/O. The public dashboard
contract adds only `FetcherRun.items_succeeded` alongside the existing effect
and failure counts.

---

### OP-16. CPE Mapping Fail-Fast Asymmetry — SUPERSEDED

**Original resolution**: a `celeryd_after_setup` handler validated the
mapping before every generic worker accepted tasks.

**Superseding decision**: SG3-01 removes this domain-specific prerequisite
from generic worker startup. The mapping is loaded lazily by a real
consumer; an invalid non-empty file fails that consumer task without
preventing unrelated workers from starting. P4-05 owns the loader,
validation, and cache but introduces no eager check. Any later eager
validation belongs to the consuming work item and reuses a contract from
the mapping module. See `docs/features/packages/cpe-package-mapping.md`.

---

### OP-8. Simplify Duplicate Handling — Eliminate Chains — RESOLVED (2026-07-25)

**Resolution**: adopted corrected option (b) — inline atomic
repoint. `mark_as_duplicate` locks source and target with blocking
waits in UUID order, then locks dependents with `FOR UPDATE NOWAIT`.
All dependents repointed atomically. Duplicated targets rejected
with `TICKET_DUPLICATE_TARGET_DUPLICATED`. Concurrent conflicts
produce `TICKET_DUPLICATE_CONCURRENT_MODIFICATION` (retryable).
Resolver, flattening, cycle handling, and hop limit eliminated.
Changes applied to all relevant specs. See
`docs/drafts/op8-inline-atomic-repoint.md` for the full decision
record.

---

### OP-1. Enum Storage Strategy — RESOLVED (2026-07-24)

**Resolution**: decided on a zero-PG-ENUM strategy. All enumerated
columns use VARCHAR. State-machine enums (TicketStatus, PackageStatus,
DeliveryStatus, CveState, Role, FetcherRunStatus,
SubmissionRequestState, ReleaseRequestState) are protected by CHECK
constraints. Classification enums (audit event types, source types,
severity, informational labels) are validated exclusively
by Python StrEnum in `app/core/enums.py`. The classification criterion
is: CHECK if the value is part of a state machine with code-managed
transitions or has direct security implications; Python Enum only for
everything else. See `docs/conventions.md` (Enum Storage Strategy) for
the full convention.

---

### OP-3. Orphan CVE Re-Ticketing Mechanism — RESOLVED

**Resolution**: resolved by the `cve_service` architecture
(`docs/features/tickets/cve-service.md`). All CVE data now flows
through `cve_service.upsert_cve()`, which checks for ticket existence
on every call. Orphaned CVEs (those without a ticket due to data
inconsistencies) are automatically re-ticketed the next time any fetcher
processes them, according to that source's own schedule (see the Fetcher
Registry in `docs/data-sources.md`). This implements option (A) naturally
without a dedicated orphan scanner — the check is inherent in the
`upsert_cve()` contract and serves as a data integrity safeguard.

---

### OP-5. Response Header for Silently Ignored Parameters — CLOSED (2026-06-10)

**Resolution**: the Soft Conditional Check pattern and the associated
response header proposal have been removed from the specifications. The
only parameter that used the silent-ignore mechanism (`include_deleted`
on ticket/CVE list endpoints) was removed when ticket soft-deletion was
eliminated. With zero consumers of the pattern, the header adds
complexity without value. The entire "Conditional Capability Checks"
section in `rbac.md` and `api-spec.md` has been removed; the only
remaining field-level capability pattern (Hard Conditional / `†`) is
self-explanatory and documented inline in the Endpoint Permission Map
legend. If a similar need arises in the future, the pattern can be
re-introduced with a fresh design.

---

### OP-9. Remove FetcherRunWeeklyAggregate Table — RESOLVED

**Decision**: Accepted. Removed `FetcherRunWeeklyAggregate` and
`aggregate_fetcher_runs` entirely. `FetcherRun` records are retained
indefinitely (~20k rows/year, negligible for PostgreSQL). No cleanup task
or retention policy is needed. See
`docs/drafts/remove-fetcher-run-aggregation.md` for rationale.

---

### OP-10. Ecosystem Column on CVEAffectedVersion — RESOLVED (2026-06-19)

**Resolution**: `ecosystem VARCHAR(50)` nullable column added to
`CVEAffectedVersion` (see `docs/data-model.md`). Populated by
`sync_osv_advisories` (canonical OSV/OSSF values) and
`sync_ghsa_advisories` (normalized from GitHub names via mapping dict).
The column was justified by: (a) both OSV and GHSA fetchers populate it,
(b) it enables ecosystem-aware display and filtering in the UI,
(c) it is a prerequisite for OP-11 (Ecosystem Prefix Mapping).

See:
- `docs/features/tickets/cve-sync-osv.md` (Fetcher: `sync_osv_advisories` — Ecosystem normalization)
- `docs/features/tickets/cve-sync-ghsa.md` (Fetcher: `sync_ghsa_advisories` — Ecosystem normalization)
- `docs/data-model.md` (CVEAffectedVersion table)

---

### OP-14. BaseFetcher All-Items-Failed Safety Check — RESOLVED (2026-06-20; refined 2026-09-17)

**Original resolution**: promoted the all-items-failed safety check from
`BaseGitFetcher.execute()` to `BaseFetcher.run()`. The initial generic test used
`items_failed > 0 AND items_created + items_updated == 0` as a proxy for every
item failing and removed the redundant Git-specific check.

**Refinement**: the location and normal-return failure behavior remain correct,
but create/update effects are not proof of successful processing. The check now
uses terminal outcomes: `items_failed > 0 AND items_succeeded == 0`. Mixed
succeeded and failed outcomes are `partial`; no failed outcomes are `success`,
including an empty run. This correctly handles successful unchanged/no-op work
and permits a committed update followed by a required-step failure without
misclassifying the effect as a successful terminal outcome. See
`docs/features/platform/fetcher-infrastructure.md` (Status determination
precedence).

---

### OP-18. Cross-Process Startup Ordering — RESOLVED (2026-07-23)

**Resolution**: the "order-independent after migrations" property is
now documented as an explicit architectural invariant in
`docs/deployment.md` (Startup Ordering). The invariant is guaranteed
by `bootstrap_fetcher_configs()` running idempotently in every
process, `system_setting` seeding using `ON CONFLICT DO NOTHING`,
and the IBS consumer operating independently with retry semantics. A
cross-reference in `docs/features/platform/fetcher-infrastructure.md`
(Multi-Process Coordination → Startup Ordering) ensures discoverability
by spec authors.

---

### OP-19. Beat Reconciliation Wiring Mechanism — RESOLVED (2026-07-23)

**Resolution**: the reconciliation is invoked via a `beat_init`
signal handler (`@beat_init.connect`), registered in
`backend/app/tasks/beat_startup.py` and imported by the Celery app
module. The handler runs `bootstrap_fetcher_configs()` followed by
the reconciliation procedure, with `sys.exit(1)` on any failure
(explicit fail-fast). The `beat_scheduler` setting remains
`'redbeat.RedBeatScheduler'` (stock, unmodified). See
`docs/features/platform/fetcher-infrastructure.md` (Startup
Reconciliation) for the complete Beat startup sequence.

---

### OP-17. IBS RabbitMQ Consumer Startup Specification Gaps — RESOLVED (2026-07-23)

**Resolution**: all four startup gaps have been specified in
`docs/features/integrations/ibs-rabbitmq-integration.md` (section
"Process Startup"):

1. **Celery app sharing**: the consumer imports the Celery app module
   (inherits timezone and lock sentinel validation). It is explicitly
   NOT a Celery worker. The "(or standalone process)" ambiguity has been
   removed.
2. **`IBS_RABBITMQ_ENABLED=false`**: process exits immediately with
   code 0 and an INFO log. Orchestrator does not restart (exit 0 is not
   a failure).
3. **DB/Redis connectivity at startup**: fail-fast (exit 1) if
   PostgreSQL or Redis is unreachable (5-second timeout each, checked
   sequentially). Consistent with `deployment.md` assertion and Beat's
   fail-fast pattern.
4. **Fetcher module imports**: FETCHER_REGISTRY populates as side-effect
   of Celery app import (unused). Consumer does NOT run
   `bootstrap_fetcher_configs()`.

See `docs/features/integrations/ibs-rabbitmq-integration.md` (Process
Startup) for the complete startup sequence.
