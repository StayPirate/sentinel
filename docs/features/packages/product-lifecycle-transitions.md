# Product Lifecycle Transitions

## Purpose

Define how Product lifecycle changes affect package-tree actionability,
automatic eligibility, and persisted Ticket status. Lifecycle never mutates
manual package-tree exclusion markers. The canonical actionability predicates
are defined in `docs/features/packages/package-model.md` (Exclusion and
Actionability), and the lifecycle evaluator is defined in
`docs/features/packages/product-catalog.md` (Lifecycle Evaluator).

## Lifecycle Authority and Effects

The authoritative Product lifecycle phase is derived exclusively from the four
AIMAAS date projections and a UTC `evaluation_date`. SMELT catalog presence,
package-tree audit events, previous evaluator results, and Ticket state do not
affect the phase.

Lifecycle has two independent observable effects:

1. `reactive_support` forces automatic Product eligibility to `false` as
   defined in `package-model.md`. Leaving Reactive Support restores the
   threshold-derived value. Manual eligibility overrides remain untouched.
2. `eol` makes a manually included `TicketPackageProduct` non-actionable. This
   can make its parent track and package non-actionable through the derived
   actionability predicates and can therefore change Ticket gate results.

An unavailable (`NULL`) lifecycle phase applies neither effect. In particular,
missing or inconsistent dates never make a Product EOL.

No lifecycle phase sets or clears `TicketPackage`, `TicketPackageTrack`, or
`TicketPackageProduct.deleted_at`. Entering or leaving EOL therefore requires
no exclusion provenance, restore mutation, or package-tree audit event.

## Fetcher: `evaluate_lifecycle_transitions`

| Property | Value |
|----------|-------|
| Fetcher name | `evaluate_lifecycle_transitions` |
| Class name | `EvaluateLifecycleTransitions` |
| Description | Reconcile lifecycle-derived Product eligibility and Ticket gate state |
| Schedule | Daily at 04:15 UTC (`15 4 * * *`) |
| Source | Local (no external source) |
| Scope | Product eligibility mismatches and gate-zone Tickets requiring lifecycle-aware reconciliation |
| Auth | N/A |
| `participates_in_catch_up` | `True` — verifies lifecycle-aware gate state after reactivation; it does not repeat eligibility calculation already owned by the triggering or manual-zone-exit workflow |
| Custom settings | No |

The default schedule follows `sync_smelt_products` at 01:00 UTC,
`sync_aimaas_lifecycle` at 02:15 UTC, and `sync_aimaas_thresholds` at 02:45
UTC. The two-hour margin after lifecycle synchronization normally lets the
evaluator consume the latest lifecycle snapshot. This ordering is operational,
not a hard task dependency: evaluation still runs against the latest committed
valid dates when an earlier fetcher fails or runs long.

### Algorithm

The fetcher is idempotent and maintains no lifecycle cursor or phase cache.

1. Capture one UTC `evaluation_date`. Every lifecycle and actionability
   expression in this run uses that date.
2. Find catalog Products for which at least one system-managed
   `TicketPackageProduct` on an operable Ticket has stored eligibility that
   differs from the complete current eligibility result. Operable Tickets are
   `New`, `Analysis`, `Analyzed`, or `Resolved`; `Ignored` and `Duplicated`
   remain in the manual zone. Include directly and effectively manually excluded
   records and EOL Products in this scan; exclusion and actionability do not
   suspend factual eligibility maintenance. Candidate discovery may prefilter
   obvious mismatches, but mutation always recomputes from current persisted
   inputs.
3. For each Product found in step 2, enqueue one independent
   `re_evaluate_product_eligibility(catalog_product_id,
   reason="reactive_ltss")` task. Dispatch failures are logged per Product and
   do not stop later dispatches. This periodic scan is a general safety net
   over the complete eligibility result — the recorded `reason` identifies the
   discovery mechanism (this daily scan), not necessarily the original
   upstream cause of the mismatch. A mismatch first introduced by a threshold
   change (whose own dispatch already failed or was superseded) and later
   caught here is still recorded with `reason="reactive_ltss"`.
4. Using the same `evaluation_date`, select distinct Ticket IDs in `Analysis`,
   `Analyzed`, or `Resolved` whose persisted status differs from the status
   produced by the current gate predicates. Candidate discovery uses the same
   SQL actionability expressions as reconciliation. Process those IDs
   sequentially. For each Ticket, open a fresh session and independent
   transaction and call
   `package_service.reconcile_lifecycle_actionability_for_ticket()` with the
   run's `evaluation_date`.
5. A Ticket failure rolls back only that Ticket, logs the Ticket ID and
   exception type, increments the failure count, and does not stop later
   Tickets. A concurrent mutation is serialized by the Ticket row lock, and
   the service reevaluates current persisted state after acquiring that lock.

Step 4 deliberately includes `Resolved`: a corrected AIMAAS date can make a
previously EOL Product actionable again, invalidating resolution. `New` is not
selected because `reconcile_ticket_status()` deliberately does not evaluate
gates before first assignment. `Ignored` and `Duplicated` are not selected
because only their explicit exit operations may return them to the gate zone.

The current-state mismatch scan is the recovery mechanism. Without persisting
previous lifecycle phases, it discovers the remaining effect of a missed run,
date correction to `NULL`, or ordinary UTC date transition while avoiding
write transactions for already-converged Tickets. It introduces no lifecycle
cache, transition table, or audit-derived provenance.

### Idempotency and Convergence

Repeated runs may rediscover the same Product or Ticket. Product eligibility
tasks recompute current values and become no-ops once converged. Ticket
reconciliation creates an audit event only when persisted Ticket status
changes. Duplicate, delayed, and out-of-order work therefore converges to the
same current state.

The derived `actionable` value changes immediately for reads that evaluate it
after midnight UTC or an AIMAAS correction. Persisted `Ticket.status` converges
on the next successful evaluation; the default daily schedule therefore
permits a maximum ordinary calendar-transition lag of 4 hours 15 minutes.
Operators can trigger this fetcher through the existing fetcher-operations API
to reconcile sooner after an exceptional correction.

### Error Handling

- A Product task publication failure is logged with the Product ID and later
  Products continue. The next complete run rediscovers the mismatch.
- A Ticket transaction failure is logged with the Ticket ID and later Tickets
  continue. The next complete run retries the current-state reconciliation.
- `SoftTimeLimitExceeded` and `MemoryError` are excluded from both per-item
  catches and propagate to `BaseFetcher.run()` as whole-run failures.
- Whole-run database failures that prevent candidate enumeration propagate to
  `BaseFetcher.run()`.
- No lifecycle or Ticket mutation is rolled back because another Product or
  Ticket failed.

### Metrics

| Metric | Meaning |
|--------|---------|
| `record_created` | Not used; lifecycle evaluation creates no domain records |
| `record_updated` | One for each eligibility task successfully enqueued, plus one for each Ticket whose persisted status changed |
| `record_failed` | One for each failed Product dispatch or failed Ticket transaction |

Eligibility no-ops and Ticket reconciliation no-ops do not increment either
metric.

## Sub-task: `re_evaluate_product_eligibility`

This on-demand Celery task is a sub-operation, not a `BaseFetcher`; it has no
independent schedule or dashboard entry.

| Parameter | Type | Meaning |
|-----------|------|---------|
| `catalog_product_id` | `UUID` | Internal catalog `Product.id` |
| `reason` | `Literal["threshold", "reactive_ltss"]` | Trigger recorded in changed-record audit events |

The task validates `reason` before opening a database session. An unsupported
value raises `ValueError` and performs no work.

1. Capture one UTC `evaluation_date` for the complete task invocation.
2. In a read-only session, select distinct IDs of operable Tickets containing
   the Product. Include directly and effectively manually excluded records and EOL
   records; a Ticket containing only overrides may produce a harmless no-op.
3. Process Ticket IDs sequentially. For each ID, open a fresh session and
   independent transaction, invoke
   `package_service.recalculate_product_eligibility_for_ticket()` with that
   `evaluation_date`, and commit that Ticket independently.
4. If a Ticket operation fails, roll it back, log the Ticket ID, Product ID,
   reason, and exception type, and continue. Earlier successful Ticket
   transactions remain committed.
5. Log candidate, successful, skipped, no-op, changed-record, and failed-Ticket
   counts. No candidate Tickets is a successful no-op.

The service applies the complete current eligibility rules rather than an
unconditional assignment. It skips manual overrides and reads current Product
dates, threshold, default CVSS version, and CVSS assessments; no historical
value is carried in the task payload.

The task has no automatic Celery retry. A later complete parent run or explicit
operator-triggered run rediscovers remaining mismatches. Per-Ticket row locks
serialize concurrent Product tasks, and each later transaction recomputes from
current committed inputs. No Product-wide transaction, progress table, outbox,
additional distributed lock, or exactly-once mechanism is introduced.

CVSS assessment changes and the platform-wide `default_cvss_version` batch do
not use this task; their CVE-owned behavior remains specified in
`docs/features/tickets/cvss-scoring.md` and
`docs/features/platform/system-settings.md`.

## Catch-Up

`EvaluateLifecycleTransitions.catch_up(ticket_id, session)` is a custom
override of the shared per-Ticket catch-up contract and a current-state safety
net. For a manual-zone exit, the synchronous package-domain boundary has already
recalculated every existing system-managed Product with one UTC
`evaluation_date`, created any `reason = reactivation` events, and performed
the transition's single final gate reconciliation. For a `Resolved` regression,
the triggering gate-zone workflow has already maintained current eligibility.
The catch-up therefore verifies current lifecycle/actionability state and
normally returns without a mutation. It never recalculates existing Product
eligibility as part of this reactivation invocation.

The passed session is used only to verify that the Ticket exists and determine
whether current persisted status differs from current lifecycle-aware gates. A
missing Ticket, empty package tree, or converged Ticket returns silently. When a
later committed Product creation or lifecycle change leaves a mismatch, the
method delegates only current Ticket gate reconciliation through the ordinary
package service boundary; it does not recalculate Product eligibility, replay
the synchronous manual-zone-exit Product events, or reconcile once per catalog
Product. A distinct later committed lifecycle or Product creation mutation may
use its ordinary eligibility owner. No exclusion restoration is needed: EOL
participation is always derived from current Product dates.

The delegated reconciliation is the sole item in this custom catch-up
invocation. If it fails, the exception propagates to `run_catch_up` for the
shared retry classification; there is no partial-success case to return or
later sibling item to continue.

## TicketAuditEvent Records

Lifecycle processing creates audit events only for persisted mutations:

| Mutation | `event_type` | `user_id` | `detail.reason` |
|----------|--------------|-----------|-----------------|
| Product eligibility changes during periodic lifecycle evaluation | `product_eligibility_changed` | `NULL` | `reactive_ltss` |
| Ticket gate status changes because current actionability or eligibility changed | `status_change` | `NULL` | N/A |

EOL entry, EOL exit, and parent actionability changes create no package-tree
audit event because they do not mutate package-tree state. Exclusion and
restore events remain exclusive to authorized acting-user actions.
The package-owned synchronous manual-zone-exit boundary creates any
`reason = reactivation` eligibility events before this catch-up begins; see
`package-service.md` (Synchronous manual-zone-exit eligibility convergence).

## Integration with AIMAAS Synchronization

`sync_aimaas_lifecycle` commits lifecycle date changes but does not mutate
eligibility, exclusion, or Ticket status. The independent 04:15 UTC evaluator
consumes the latest committed valid dates. If lifecycle synchronization is
triggered manually after that daily evaluation, operators may trigger
`evaluate_lifecycle_transitions` explicitly; otherwise the next scheduled run
converges all affected Tickets.

`sync_aimaas_thresholds` retains its post-commit mismatch discovery and
dispatches `re_evaluate_product_eligibility(catalog_product_id,
reason="threshold")`. The Product task includes `Resolved` Tickets so a newly
eligible Product can invalidate resolution.

## Security

- Lifecycle evaluation and Product eligibility tasks are internal system
  workflows with no user authentication.
- No lifecycle workflow can set or clear a manual exclusion or eligibility
  override.
- All Ticket mutations remain serialized by the Ticket row lock and audited in
  the same transaction when persisted state changes.

## Cross-References

- `docs/features/packages/product-catalog.md` — lifecycle dates and evaluator
- `docs/features/packages/package-model.md` — actionability and eligibility
- `docs/features/packages/package-service.md` — package mutation boundaries
- `docs/features/tickets/tickets.md` — Ticket status gates
- `docs/features/tickets/ticket-mutations.md` — centralized reconciliation
- `docs/features/tickets/ticket-audit-log.md` — audit field contracts
- `docs/features/platform/fetcher-infrastructure.md` — fetcher and catch-up contracts
