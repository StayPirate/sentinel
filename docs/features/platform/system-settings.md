# System Settings

## Purpose

System-wide configuration and administrative operations for the Sentinel
platform. The System Settings page provides settings that affect platform behavior
across all users and tickets.

## Access Control

All administration endpoints and UI pages require the `manage_settings`
capability.

## Service Module

System-setting persistence, bootstrap, reads, audit logging, and future
mutations are implemented in `backend/app/services/settings.py`.

## Settings

### Default CVSS Version

Selects the preferred version in the cross-version Severity Resolution Cascade
and the exact canonical SUSE version used for Eligibility Score Resolution. It
does not exclude other accepted versions from severity and does not control the
version-independent SUSE-assessment presence gate.

| Property        | Value                            |
|-----------------|----------------------------------|
| Setting key     | `default_cvss_version`           |
| Type            | String                           |
| Allowed values  | `"3.1"`, `"4.0"`                 |
| Initial value   | `"3.1"`                          |
| Changed by      | Admin only                       |

**Impact of changing the default version**:

When the Admin changes the default CVSS version, the PATCH endpoint
executes the following sequence:

1. **Validate** the new value against allowed values (`"3.1"`, `"4.0"`)
2. **No-op check**: if the current value equals the new value, return
   200 immediately with `recalculation_scheduled: false` (no audit
   event, no batch — consistent with the audit-trail-infrastructure
   cross-cutting rule for idempotent no-ops)
3. **Acquire recalculation slot**: `SET cvss_recalc_active <timestamp>
   NX EX 900` on Redis. This step serves as both a Redis liveness probe
   and the endpoint's immediate admission guard. It is not the complete-run
   mutual exclusion mechanism; see "All-CVE Recalculation Runner" for the
   runner contract and its coordination boundary:
   - If slot acquisition raises any `RedisError` → return 503
     `REDIS_UNAVAILABLE` (nothing committed)
   - If the key already exists (a recalculation is in progress) → return
     409 `CVSS_RECALC_ALREADY_IN_PROGRESS` (nothing committed)
4. **Commit** the new setting value and a `SettingAuditEvent` record to
   the database. If the commit fails: release the slot (`DEL
   cvss_recalc_active`) and return 500
5. **Enqueue** the batch recalculation Celery task
   (`recalculate_cvss_derived_state`) with the new version as an explicit
   argument. If the enqueue fails: release the slot and return 200 with
   `recalculation_scheduled: false` (the primary operation — the setting
   change — succeeded; the admin can use the manual re-run endpoint to
   trigger the batch)
6. Return 200 OK with `recalculation_scheduled: true`

**Commit-first rationale**: the `SettingAuditEvent` is always the first
durable record. No ticket mutation can occur without the setting change
being audited. This prevents phantom mutations (ticket audit events
without a recorded cause).

The all-CVE recalculation runner (`recalculate_cvss_derived_state`) visits
every persisted CVE and calls `ticket_mutations.recalculate_cvss_chain()` in
default-version mode for each CVE in an independent database transaction. Its
complete execution contract, including the semantic effect matrix, is defined
in "All-CVE Recalculation Runner" below. The CVSS resolution functions return pure
resolved results; changing the setting does not alter any assessment. The
read-only projection of the runner's effects is specified in "Default-CVSS
Impact Preview" below, and `docs/features/tickets/cvss-scoring.md`
(Persistence and Propagation Boundary) defines the pure results the runner
consumes.

## All-CVE Recalculation Runner

The all-CVE recalculation runner applies the current `default_cvss_version`
policy to every persisted CVE. `PATCH /api/v1/admin/settings` and
`POST /api/v1/admin/settings/default-cvss-version/recalculate` enqueue it. It is
not a fetcher, sub-operation, or scheduled integration. It creates no
`FetcherRun`, no Celery result-backend entry, and no run, progress, or cursor
record.

### Task Identity and Workflow

The Celery task is `recalculate_cvss_derived_state(target_version)`. Its only
semantic input is the primitive `target_version`, exactly `"3.1"` or `"4.0"`.
No task argument carries a session, ORM object, collection, or per-CVE payload.

The synchronous task wrapper:

1. Validates the received `target_version` using input only. Any other value is
   a non-retryable caller-contract failure before any database read, before
   enumeration, and before any CVE mutation. It emits no run counters and no
   feature run event.
2. Invokes exactly one `asyncio.run()` around the service-owned asynchronous
   workflow. It delegates all logic to the service layer and performs no
   business query, settings read, transaction, or engine disposal of its own.
3. Returns `None` and stores no task result.
4. Lets cancellation, worker shutdown, `SoftTimeLimitExceeded`, `MemoryError`,
   and every other control signal propagate unchanged. It converts no control
   signal into an ordinary task outcome.

The service-owned asynchronous workflow
`run_cvss_derived_state_recalculation(target_version, session_factory)` opens
one independent session per unit, owns their commits and rollbacks, and returns
one fixed-size aggregate result used only for the run's structured logs. The
aggregate result contains `target_version`, the captured watermark (absent for
a stale delivery), `changed`, `unchanged`, `skipped`, `failed`, the derived
`succeeded` and `processed`, and the terminal outcome token. It contains no CVE,
Ticket, package, Product, or
occurrence identifier and no per-CVE detail collection. The workflow emits the
run's events from that aggregate and discards it; the wrapper receives no
result. The aggregate is never persisted and never published to a result
backend.

The same workflow awaits the shared pooled engine's disposal exactly once at
the outer asynchronous boundary, on both the success and the exception path,
after every unit session is closed and before control returns to
`asyncio.run()`.

### Input Validation and Stale Delivery

The wrapper validates `target_version` before entering the asynchronous
workflow. The workflow then:

1. reads the persisted `default_cvss_version` exactly once through
   `get_default_cvss_version()`, before capturing the watermark and before
   enumerating any CVE. A missing required setting is a whole-run failure that
   propagates;
2. compares the observed value with `target_version`; and
3. when they differ, terminates the delivery as `stale` before any CVE is read,
   locked, mutated, audited, or published for.

A `stale` delivery captures no watermark, creates no unit session and no
post-commit effect, leaves every counter zero, and emits only the
`cvss_recalculation_stale` terminal event. A delayed delivery must never move
derived state back to a superseded policy. A repeated valid delivery is safe
because already converged units classify `unchanged`.

Complete-run admission, ownership, lease renewal, execution fencing, and crash
cleanup are not defined by this contract. Any such coordination must preserve
the validation, paging, unit, drain, and outcome semantics defined in this
section; an ownership-loss termination is a whole-run condition and never an
ordinary failed unit.

### Watermark and Keyset Pagination

- The workflow captures one internal high-water mark equal to the maximum
  existing `CVE.id` before enumerating any CVE. The mark is not persisted, is
  not returned to the caller, and is exposed only in the run's own logs. An
  empty `cve` table has no watermark and no candidates: the delivery terminates
  `completed` with every counter zero and creates no unit session.
- It enumerates `CVE.id` in ascending order with the keyset predicate
  `last_id < CVE.id <= watermark`, where `last_id` is an in-memory cursor
  advanced only from the last identity of the page just processed. There is no
  offset arithmetic.
- One page carries at most 500 candidate identities. The bound is a
  feature-specific internal constant, not a database setting, environment
  variable, API parameter, or fetcher configuration, and it never limits the
  total population.
- A page carries only the candidate identity needed to address and log a unit:
  the CVE row identifier and its canonical CVE identifier. It never carries
  association, Ticket, assessment, threshold, lifecycle, override, Product, or
  gate data, and no value read in a page decides a domain effect.
- The runner never materializes the complete population in memory, and no read
  transaction is held open across pages or units. Each page read completes
  before the locked transaction of its units begins.
- Processing continues until the watermark is reached or a whole-run condition
  terminates the delivery.

### Concurrent-Change Semantics

- CVE rows whose `id` exceeds the captured watermark are excluded from the
  current invocation and belong to a later explicit invocation.
- A row whose `id` is within the watermark but becomes visible only after the
  cursor has passed its key may be observed by a later invocation. The runner
  promises one bounded observation, not a long-lived population snapshot.
- A candidate that no longer exists when its locked-current unit begins is
  `skipped`, not a failed mutation.
- Concurrent association, disassociation, Ticket status change, assessment
  write, threshold change, lifecycle transition, and override change are
  resolved from locked-current state under the unit's CVE-then-Ticket lock
  order. The unit applies the committed winner's state; no page-level or
  pre-lock observation decides an effect.

### Per-CVE Transactional Unit

Each candidate identity is one independent unit:

1. create a fresh `AsyncSession`;
2. open one transaction;
3. capture exactly one UTC `evaluation_date` for the unit;
4. call `ticket_mutations.recalculate_cvss_chain()` in default-version mode,
   passing `target_version` explicitly as its `default_cvss_version` argument
   and the captured date; the call acquires the CVE, then its optional Ticket,
   under the existing CVE-then-Ticket order;
5. flush every mutation and audit record before finalization;
6. commit exactly once when the unit succeeds;
7. roll back exactly once when an isolable pre-finalizer unit error occurs;
8. close the session;
9. ensure the unit's locks are released before any external effect;
10. detach and drain the unit's registered transaction-local Ticket convergence
    effects after commit and
   session close;
11. proceed to the next candidate only after the previous unit completes.

The run does not freeze one global date: each CVE unit uses its own UTC
`evaluation_date` consistently across its lifecycle, eligibility, actionability,
reconciliation, and result.

A `missing` result is a successful unit with no pending mutation: its
transaction commits, its session closes, no post-commit effect is registered,
and the runner counts it `skipped`. A rolled-back unit's drain is skipped and no
registered effect is published.

### Semantic Effect Matrix

The runner applies exactly the default-version mode of
`ticket_mutations.recalculate_cvss_chain()`. The formulas remain owned by their
authorities and are never duplicated here:

- severity uses the Severity Resolution Cascade in
  `docs/features/tickets/cvss-scoring.md`;
- the eligibility score uses Eligibility Score Resolution in the same
  specification;
- automatic Product eligibility uses the package-model-owned evaluator in
  `docs/features/packages/package-model.md`;
- gate results use the Analyzed and Resolved predicates in
  `docs/features/tickets/tickets.md`;
- audit events follow `docs/features/tickets/ticket-audit-log.md`.

| Locked-current associated Ticket state | Runner effect |
|---|---|
| No Ticket | Recalculate `CVE.severity`; there is no Ticket audit target |
| `New` | Recalculate severity and every automatic Product occurrence; remain `New` and perform no gate reconciliation; system work never assigns |
| `Analysis`, `Analyzed`, `Resolved` | Recalculate severity and every automatic Product occurrence, then perform at most one final Ticket reconciliation. `Resolved` may regress normally to `Analyzed` or `Analysis`; a regression registers the ordinary post-commit Ticket convergence |
| `Ignored`, `Duplicated` | Recalculate `CVE.severity` only at the operational-state level; if it changed and a Ticket exists, create the direct system-attributed `severity_changed` event. Do not mutate Product eligibility, assignment, Ticket status, manual-zone state, or gates |

Every applicable gate-zone or `New` Product update uses current persisted
assessments, Product threshold and lifecycle inputs, and override markers;
manual overrides are preserved. The runner never changes a CVSS assessment,
never assigns a Ticket, never exits a manual zone, and never applies a
remediation action. Re-invoking it on already converged inputs creates no
mutation and no audit event.

`recalculate_cvss_chain()` creates a system-attributed `severity_changed`
record whenever an associated Ticket's old and new unified severity differ,
before any Product event. It never creates `cvss_assessment_changed`, because
the setting change does not alter an assessment. One CVE transaction uses one
UTC `evaluation_date`; any local settings, database, eligibility, audit, flush,
or reconciliation error raised before finalization rolls back that complete CVE
unit and the batch continues with the next CVE. A commit exception or ambiguous
commit outcome terminates the run without classifying that CVE as failed; a
non-operational exception after successful commit likewise terminates without
reclassifying the committed unit.

Visiting a `Resolved` Ticket may regress it through ordinary gate evaluation and
register one transaction-local Ticket convergence effect. After that CVE unit
is flushed, committed, and its session closed, the runner drains the effect
before the next unit. A broker operational error follows the automatic
best-effort policy in `ticket-service.md`: it emits the shared sanitized Ticket
event, changes no runner counter or aggregate outcome, and does not stop the
scan. Visiting an
`Ignored` or `Duplicated` Ticket cannot exit its manual zone or register that
work; Product eligibility and gates for those Tickets converge only through the
owning manual-zone-exit workflow.

### Outcome Classification

The runner maintains four in-memory counters for the current delivery:

| Counter | Meaning |
|---|---|
| `changed` | The committed unit was classified `changed` by `recalculate_cvss_chain()`: it produced at least one durable semantic mutation or its required audit event. A reconciliation that changes nothing does not by itself make a unit `changed` |
| `unchanged` | The committed unit was classified `unchanged` by `recalculate_cvss_chain()`: it was already converged and created no mutation and no audit event |
| `skipped` | The enumerated candidate no longer existed when locked-current processing began. Ticketless, `New`, gate-zone, and manual-zone units are normal successful outcomes, never `skipped` |
| `failed` | The unit rolled back for an isolated per-CVE error |

The derived aggregate values are exactly
`succeeded = changed + unchanged` and
`processed = changed + unchanged + skipped + failed`.

The terminal outcome of a delivery is exactly one of:

| Terminal outcome | Condition |
|---|---|
| `completed` | The watermark was reached with `failed = 0` |
| `partial` | The watermark was reached with at least one isolated pre-finalizer failure |
| `stale` | The persisted default version differed from `target_version` before the scan |
| `cancelled` | An interceptable cancellation or worker shutdown terminated the delivery |
| `ownership_lost` | The complete-run coordination signalled that this delivery no longer owns the run |
| `failed` | A whole-run condition terminated the delivery |

A safe checkpoint is a point between units where the runner reports only work
already committed; a terminal event never claims a unit beyond its committed
classification. A hard kill or an OOM kill may produce no feature-owned terminal
event. Counters and logs are diagnostic only; they are never authoritative
progress, completion, or recovery state.

**Interruption window.** A whole-run signal can arrive after a unit commits and
before its drain completes. Such a signal terminates the delivery and is never
converted into a unit outcome. The committed unit remains durable and keeps its
classification; a detached effect whose publication attempt was not reached is
lost and is recovered by the explicit Ticket convergence rerun. The runner
performs no publication after a rollback, a failed or ambiguous commit, or an
interrupted pre-commit unit.

### Error Taxonomy

**Isolable per-CVE errors.** The runner continues with the next candidate only
when every one of the following holds for the failure:

- the error belongs to the single CVE unit;
- the unit's commit did not occur;
- the rollback succeeded;
- the session closed cleanly;
- the connection is not invalidated;
- the runner can reliably start and process the next candidate.

An isolable failure increments `failed`, emits one
`cvss_recalculation_cve_failed` warning, and never rolls back a committed
sibling.

**Whole-run errors.** These terminate the delivery and propagate. They are never
converted into the ordinary per-unit `failed` counter:

- enumeration failure;
- inability to create a unit session;
- commit failure or an ambiguous commit outcome;
- rollback failure;
- session cleanup failure;
- a globally unavailable database or an invalidated connection;
- a missing required system setting;
- an invalid task payload;
- a contract violation or programming error;
- cancellation;
- worker shutdown;
- `SoftTimeLimitExceeded`;
- `MemoryError`;
- ownership loss.

A broad per-item `except Exception` that maps these into `failed` is forbidden.
The per-unit handler catches only the isolable failure class it can prove
satisfies every isolation condition above. These whole-run conditions remain
whole-run when they are raised during enumeration, a unit transaction, or a
detached publication. Only `kombu.exceptions.OperationalError` from automatic
Ticket convergence publication is logged once by the shared Ticket-owned
adapter and absorbed without changing any runner counter or aggregate outcome.
Cancellation and worker shutdown terminate as the
`cancelled` outcome, an ownership-loss signal terminates as `ownership_lost`,
and every remaining whole-run condition terminates as the `failed` outcome.

**Retry.** The runner configures no Celery automatic retry and never calls
`self.retry()`. Recovery is an explicit complete rerun from the beginning: there
is no resume cursor and no partial-progress state. Already converged units
classify `unchanged` and create no duplicate mutation or audit event. A CVSS
rerun is not guaranteed recovery for a publication failure that already
committed, because the converged chain may be a no-op on the next invocation;
recovery for that failure is the explicit Ticket convergence rerun.

### Logging

The runner consumes the shared structured logging contract in
`docs/features/platform/logging.md` without modifying it. It emits these events:

| Event | Level | When |
|---|---|---|
| `cvss_recalculation_started` | INFO | Once, after the target is validated as current and the watermark is captured, before enumeration |
| `cvss_recalculation_cve_failed` | WARNING | Once per isolated failed unit |
| `cvss_recalculation_completed` | INFO | Terminal, `completed` |
| `cvss_recalculation_partial` | WARNING | Terminal, `partial` |
| `cvss_recalculation_stale` | INFO | Terminal, `stale` |
| `cvss_recalculation_cancelled` | WARNING | Terminal, `cancelled` |
| `cvss_recalculation_ownership_lost` | WARNING | Terminal, `ownership_lost` |
| `cvss_recalculation_failed` | ERROR | Terminal, `failed` |

The `cvss_recalculation_cve_failed` warning carries only the canonical CVE
identifier, `target_version`, a bounded failure phase, a closed sanitized cause
category, and the task-bound `celery_task_id`. Failure phases are a closed
vocabulary: `setting_read`, `enumeration`, `unit`, `publication`, and `control`. Cause
categories are a closed sanitized vocabulary: `database`, `domain`,
`programming`, `infrastructure`, `interrupted`, and `unexpected`.

Failure logs never contain CVSS vectors or assessments, full payloads, Ticket
descriptions, Product collections, SQL, raw exception text, URLs or external
data, credentials or secrets, or unbounded aggregate lists. Per-CVE successful
units emit no INFO log. The workflow emits exactly one terminal event for every
outcome it reaches and emits the applicable terminal event at a safe checkpoint
before a whole-run condition propagates. Terminal events from the table above
carry `target_version`, the captured watermark when one exists (it is omitted
for a stale delivery or a failure before capture), `changed`, `unchanged`,
`skipped`, `failed`, `succeeded`, `processed`, the task-bound `celery_task_id`, and the
failure phase and sanitized category when applicable. The terminal event never
carries an array of failed CVE identifiers; every failure already has its own
individual event.

### Absence of Persistent Run State

The runner introduces:

- no `FetcherRun` record;
- no Celery result-backend entry and no persisted task result;
- no run, progress, resume, or cursor table, column, or resource;
- no persisted high-water mark, offset, or continuation token;
- no metric or log used as authoritative state;
- no generic batch, backfill, or reusable runner framework;
- no new audit event type — the unit's ordinary domain audit events remain the
  only durable audit records;
- no new configuration variable or setting.

Crash recovery is a complete explicit rerun from the beginning, safe because
each committed unit is independently durable and idempotent.

## Default-CVSS Impact Preview

The read-only impact preview lets an administrator understand the expected
consequences of a proposed `default_cvss_version` change before mutating the
setting. It projects the same authoritative severity, eligibility, override,
lifecycle, and Ticket-gate outcomes that the all-CVE recalculation runner
applies, without performing any mutation.

The preview is advisory. It creates no approval, reservation, snapshot token,
or prerequisite for `PATCH /api/v1/admin/settings`, and that endpoint neither
requires nor consumes a preview result.

### Preview Service

```python
async def get_default_cvss_version_impact(
    session: AsyncSession,
    proposed_version: Literal["3.1", "4.0"],
) -> DefaultCVSSVersionImpact:
    ...
```

`session` is the caller-owned asynchronous database session. `proposed_version`
is the proposed setting value. The function:

1. Reads the observed `default_cvss_version` once through
   `get_default_cvss_version(session)`.
2. Returns the no-op result when `proposed_version` equals the observed value.
3. Otherwise captures one UTC `evaluation_date` for the invocation and one
   internal high-water mark on `CVE.id` before evaluating any CVE.
4. Evaluates the persisted CVEs whose row `id` is less than or equal to the
   mark, using bounded internal keyset pagination. CVEs whose row `id` exceeds
   the mark are excluded from the invocation; a CVE whose `id` was assigned
   before the mark but that becomes visible during the scan may or may not be
   observed, per the per-unit observation model below. The page size is an
   internal implementation choice; it is not configuration and is not part of
   the API contract.
5. Projects each CVE's severity and Ticket-scoped effects using the proposed
   version and the complete, unfiltered assessment set of that CVE, and
   accumulates the aggregate counts defined below.
6. Returns one complete `DefaultCVSSVersionImpact` result.

The function performs no write of any kind: it creates, updates, or deletes no
setting, CVE, assessment, severity, Product, Ticket, assignment, audit, cache,
or post-commit state. It acquires no mutation lock, reads no Redis key,
publishes no task, and has no side effect on an active recalculation. It is
read-only and may be invoked repeatedly; each invocation observes the state
committed when its own units are read, so repeated previews may differ.

Exceptions: `RequiredSystemSettingMissingError` and database or schema errors
propagate unchanged, and a deadline expiry raises `CVSSPreviewTimeoutError`
defined below. The function raises no other domain exception.

### Result and Count Units

The result is one fixed-size aggregate object. It contains no CVE, Ticket,
package, track, Product, or occurrence identifier and no detail collection.

| Field | Type | Meaning |
|---|---|---|
| `observed_default_cvss_version` | string, `3.1` or `4.0` | Setting value read once at invocation start |
| `proposed_default_cvss_version` | string, `3.1` or `4.0` | Requested proposed value |
| `no_op` | boolean | `true` exactly when the proposal equals the observed value |
| `cves_evaluated` | integer | CVEs fully evaluated within the bounded population |
| `cve_severity_changes` | integer | Evaluated CVEs whose projected unified severity differs from the observed persisted `CVE.severity` |
| `product_eligibility_changes` | integer | `TicketPackageProduct` occurrences whose projected automatic `eligible` boolean differs from the observed persisted value |
| `product_eligibility_override_skips` | integer | Applicable occurrences with `is_eligible_override = true` that execution would preserve |
| `resolved_ticket_regressions` | integer | Tickets observed as `Resolved` whose projected highest valid gate result is `Analysis` or `Analyzed` |

- The count unit for eligibility is the `TicketPackageProduct` occurrence,
  never the catalog Product. One CVE may produce changes in multiple
  occurrences under its associated Ticket.
- An occurrence with `is_eligible_override = true` is never counted in
  `product_eligibility_changes`: its override is preserved, so it contributes
  only to `product_eligibility_override_skips` when applicable.
- "Applicable occurrence" means an occurrence whose Ticket state projects
  automatic Product eligibility (`New`, `Analysis`, `Analyzed`, `Resolved`),
  regardless of exclusion, EOL, or actionability.
- Categories may overlap. One CVE may contribute to `cve_severity_changes`,
  several `product_eligibility_changes` occurrences, several
  `product_eligibility_override_skips` occurrences, and one
  `resolved_ticket_regressions`.
- A projected effect that equals the observed persisted value receives no
  count. An evaluated CVE with no projected effect contributes only to
  `cves_evaluated`.
- An override skip is not a projected mutation; it records an occurrence that
  an execution would preserve.
- An empty population is a complete evaluation: `no_op` is `false`,
  `cves_evaluated` is `0`, and every impact count is `0`.
- `cves_evaluated` counts only a complete invocation. A preview that does not
  produce a complete result returns no counts at all.

### No-op Proposal

When `proposed_version` equals the observed setting value, the preview returns
the no-op result without scanning the population:

- `no_op` is `true` and every count, including `cves_evaluated`, is `0`;
- no CVE, Ticket, Product, assessment, or gate evaluation is performed;
- no audit event, cache entry, Redis access, task publication, or other effect
  occurs;
- the result has no relationship to the manual recalculation operation, which
  remains the separate recovery and refresh surface.

### Projected Impact Matrix

The preview projects the same exhaustive side-effect matrix as the
"Semantic Effect Matrix" of the all-CVE recalculation runner above,
substituting projected values for persistence:

| Associated Ticket state | Projected effect |
|---|---|
| No Ticket | Unified severity only; no Ticket-scoped count |
| `New` | Unified severity and automatic Product eligibility; no gate projection |
| `Analysis`, `Analyzed`, `Resolved` | Unified severity, automatic Product eligibility, and the highest valid gate result. A Ticket observed as `Resolved` whose projected result is `Analysis` or `Analyzed` contributes one `resolved_ticket_regressions` count |
| `Ignored`, `Duplicated` | Unified severity only; no Product, assignment, gate, or manual-zone projection |

Projection rules:

- Severity and eligibility remain separate resolutions. The projected
  severity uses the Severity Resolution Cascade with the proposed version;
  the projected eligibility score uses the canonical SUSE assessment for the
  proposed version or the `10.0` fallback. Neither substitutes for the other.
- Automatic Product eligibility evaluates every applicable occurrence,
  including excluded, EOL, and otherwise non-actionable records, because
  exclusion, EOL, and actionability are not inputs of the eligibility
  formula. Rule 1 of the eligibility evaluator always preserves an occurrence
  with `is_eligible_override = true`; the preview reports it as a skip and
  changes no field.
- Product threshold and lifecycle inputs follow the authoritative
  package-model evaluator, including its Reactive Support, `NULL`-threshold,
  and `NULL`-lifecycle rules; this contract defines none of them.
- Gate projection reuses the exact Analyzed and Resolved predicates of
  `tickets.md`, substituting projected effective Product eligibility for the
  persisted boolean: the projected automatic result where no manual override
  applies, and the preserved persisted `eligible` value where
  `is_eligible_override = true`. It never calls `reconcile_ticket_status()`,
  never changes a status, and never registers a transaction-local Ticket
  convergence effect.
- The preview reads the setting once for the observed value. The proposed
  version is passed explicitly to the pure severity and eligibility
  resolutions; the preview does not read the setting again per unit.
- One UTC `evaluation_date` governs lifecycle, eligibility, actionability,
  and gate projection for the complete invocation.

### Consistency and Staleness

- The preview is one advisory bounded scan, not one coherent PostgreSQL
  snapshot of the complete population. Each CVE evaluation unit uses a
  coherent set of authoritative inputs for that unit; different units may
  observe different committed states. A unit's contribution must correspond
  entirely to one committed database observation: the implementation may read
  a single statement, a bounded page-level snapshot covering several CVEs, or
  use an equivalent mechanism, but it must not synthesize one unit from
  inputs observed on opposite sides of a concurrent commit. The observation
  mechanism, transaction shape, and page size remain internal implementation
  choices and are not part of the API contract.
- CVEs whose row `id` exceeds the captured high-water mark are excluded from
  the invocation. A CVE whose `id` does not exceed the mark may or may not be
  observed when it becomes visible during the invocation, and a committed
  change to an observed CVE may or may not be visible, depending on when that
  unit is read. CVE association, assignment, assessment, eligibility,
  lifecycle, and gate inputs are read from committed current state, not from a
  preview-time snapshot.
- The observed setting value is returned for orientation only. It does not
  block, freeze, or reserve a concurrent setting change, and the preview is
  not evidence that a later mutation will observe the same value.
- A repeated preview may return different counts. The preview result is not a
  snapshot token, reservation, approval, or binding prerequisite. A later
  `PATCH /api/v1/admin/settings` independently classifies its own current
  state and never receives, reuses, or trusts preview counts, the high-water
  mark, or any preview state.
- The high-water mark is internal to one invocation. It is neither persisted
  nor returned and is not shared between invocations.

### Active Recalculation Run

While an all-CVE recalculation is admitted, queued, or running, the preview
remains available and behaves as described above. It does not read Redis or
task state, does not report the run's progress, does not estimate remaining
work, and does not participate in run exclusion. It may observe a mix of
converged and not-yet-converged units; its result remains advisory.

### Timeout and Partial Results

The preview is bounded by one 30-second monotonic deadline started at Preview
Service function entry. Every blocking step of the invocation must respect the
remaining time. The deadline is a contract bound, not a performance target:
bounded internal paging is expected to project a representative persisted
population completely within it, and a population that cannot be projected
completely yields the timeout outcome below rather than a partial result. When
the deadline expires, the operation:

- raises `CVSSPreviewTimeoutError`;
- discards every intermediate count; and
- returns no partial result — an incomplete scan is never reported as a
  complete preview and never produces HTTP 200.

The preview has no resumable cursor, response pagination, continuation token,
persisted partial result, or progress resource.

## Bootstrap

The `default_cvss_version` setting (declared above with Initial value
`"3.1"`) MUST exist at runtime before any process reads it. The system
guarantees existence via two complementary mechanisms:

1. **Alembic data migration** (primary — runs before any process starts):

   ```sql
   INSERT INTO system_setting (key, value)
   VALUES ('default_cvss_version', '3.1')
   ON CONFLICT (key) DO NOTHING;
   ```

2. **FastAPI lifespan bootstrap** (defense-in-depth, self-healing):

   ```sql
   INSERT INTO system_setting (key, value)
   VALUES ('default_cvss_version', '3.1')
   ON CONFLICT (key) DO NOTHING;
   ```

Properties:

- **Idempotent**: if the setting already exists (e.g., Admin changed it
  to `"4.0"`), the INSERT is a no-op
- **Self-healing**: if the row is accidentally deleted, the next
  application restart restores the default
- **Multi-replica safe**: `ON CONFLICT DO NOTHING` handles concurrent
  startup of multiple API server instances without race conditions
- **Process-order independent after migration**: the Alembic migration
  guarantees the setting exists before any process (API server, Celery
  worker, RabbitMQ consumer) starts. The FastAPI lifespan bootstrap also
  restores a row deleted after migration before that API instance serves
  requests; non-API processes continue to rely on the migration guarantee

Neither initialization mechanism creates a `SettingAuditEvent`. They establish
or restore required baseline data idempotently; they are not administrative
setting mutations and have no human actor.

### Bootstrap Service

```python
async def bootstrap_system_settings(session: AsyncSession) -> None:
    ...
```

`session` is the caller-owned asynchronous database session. The function:

1. Inserts `default_cvss_version = "3.1"` with `ON CONFLICT (key) DO
   NOTHING`.
2. Flushes the insert before returning so database errors surface at this
   boundary. It never commits; the caller owns the transaction.
3. Returns `None` whether it inserted the row or found an existing row.

The operation is idempotent. Repeated calls preserve the existing value,
including an administrator-selected value of `"4.0"`. Concurrent calls are
safe: at most one inserts the row and every successful caller observes a
completed insert or conflict before returning. It creates no audit event.

Database availability, missing-table/schema, constraint, and flush failures
propagate to the caller. The function does not catch them, retry them, or
return partial success.

### Setting Read Service

```python
async def get_default_cvss_version(session: AsyncSession) -> str:
    ...
```

The function reads the `default_cvss_version` row from `system_setting` and
returns its stored value. If the row is absent, it raises
`RequiredSystemSettingMissingError`; it never substitutes a hardcoded or
environment-derived value. Database availability and schema errors propagate
unchanged. The function performs no writes and creates no audit event.

### Service Exceptions

All exceptions defined by the settings service inherit from
`SettingsServiceError`, which inherits from the shared `ServiceError` root.

API-facing exceptions:

| Exception | HTTP | Code | Raised when |
|---|---|---|---|
| `CVSSPreviewTimeoutError` | 503 | `CVSS_PREVIEW_TIMEOUT` | The monotonic preview deadline expires before a complete result is available |

System-internal exceptions:

| Exception | Raised when | Handling |
|---|---|---|
| `RequiredSystemSettingMissingError` | The required `default_cvss_version` row is absent | Propagates to the caller; API handlers do not catch it, so the framework returns the global `500 INTERNAL_ERROR` response |

The public response uses the standard non-sensitive `INTERNAL_ERROR` detail;
it does not disclose whether migration, bootstrap, or data corruption caused
the missing row. Because `500 INTERNAL_ERROR` is a global response, endpoint
error tables do not repeat it.

### FastAPI Lifespan Ordering and Failure

Database migration is an external deployment prerequisite and never runs in
the application lifespan. During API startup, after application configuration
is validated and before request serving begins, the lifespan opens a database
transaction, invokes `bootstrap_system_settings()` with that transaction's
session, and commits. Only a successful commit allows startup to complete.

If database connection, schema access, bootstrap, flush, or commit fails, the
transaction rolls back and the exception escapes the lifespan. FastAPI startup
therefore fails and the API process MUST NOT begin serving requests. Startup
does not continue in a degraded mode and does not use a fallback setting.

## API Endpoints

All endpoints in this section require the `manage_settings` capability.

### Get System Settings

```
GET /api/v1/admin/settings
```

**Request body**: none.

**Query parameters**: none. The endpoint is not paginated.

**Behavior**: call `get_default_cvss_version()` with the request session and
return the persisted value. A missing required row propagates
`RequiredSystemSettingMissingError` and is exposed through the standard `500
INTERNAL_ERROR` response; no fallback value is returned.

Response:

```json
{
  "data": {
    "default_cvss_version": "3.1"
  }
}
```

**`Capability: manage_settings`**

### Update System Settings

```
PATCH /api/v1/admin/settings
```

Request body:

```json
{
  "default_cvss_version": "4.0"
}
```

Validates the value against allowed values. On a value change, acquires
the recalculation slot, commits the setting and audit event, and
enqueues a batch recalculation task. See "Impact of changing the default
version" above for the full sequence. Changing the setting neither requires
nor consumes a prior impact preview; see "Default-CVSS Impact Preview".

**Note on PATCH with side effects**: this endpoint uses PATCH because
semantically it is a configuration field update — the setting changes
value and the response is returned immediately. The recalculation is an
asynchronous side effect (Celery background task) that does not block
the response. This is a documented deviation from the
`POST /resource/{id}/verb` convention for operations with side effects.

**Error responses**:

| Status | Code | Condition |
|--------|------|-----------|
| 409 | `CVSS_RECALC_ALREADY_IN_PROGRESS` | The recalculation admission slot is already held (setting change blocked while the slot is occupied) |
| 503 | `REDIS_UNAVAILABLE` | Redis rejected or could not complete slot acquisition (setting change requires Redis availability) |

Response (200 OK): the settings object in the standard
`{"data": ...}` envelope. The `recalculation_scheduled` boolean field
is **always present** in the response:

```json
{
  "data": {
    "default_cvss_version": "4.0",
    "recalculation_scheduled": true
  }
}
```

Values of `recalculation_scheduled`:

- `true` — value changed and batch task successfully enqueued
- `false` — either (a) no-op (value unchanged, no batch needed), or
  (b) value changed but enqueue failed (transient broker failure after
  slot acquisition — admin should use
  `POST /api/v1/admin/settings/default-cvss-version/recalculate` to
  trigger the batch manually)

**`Capability: manage_settings`**

### Get Default-CVSS Impact Preview

```
GET /api/v1/admin/settings/default-cvss-version/impact
```

**Request body**: none.

**Query parameters**:

| Parameter | Type | Default | Description |
|---|---|---|---|
| `proposed_version` | string | — (required) | Proposed `default_cvss_version`; exactly `3.1` or `4.0` |

A missing value, an unsupported value, or any other schema violation produces
the global `422 VALIDATION_ERROR` response. Undeclared query parameters are
ignored per the global undeclared-query convention.

**Behavior**: call `get_default_cvss_version_impact()` with the request
session and `proposed_version`, and return its complete aggregate result in
the standard `{"data": ...}` envelope. The endpoint is not paginated because
it returns one fixed-size aggregate object, and it has no `meta` object. A
`CVSSPreviewTimeoutError` is exposed as `503` `CVSS_PREVIEW_TIMEOUT`; an
incomplete scan is never returned as a partial success. A missing required
setting row propagates `RequiredSystemSettingMissingError` and is exposed
through the standard `500 INTERNAL_ERROR` response.

The preview evaluates the system-wide persisted-CVE population, including
ticketless CVEs and CVEs associated with confidential Tickets. The
`manage_settings` capability alone is sufficient: the preview introduces no
capability and applies no consumer Ticket visibility filtering, because it
must observe the same system-wide policy-migration set that the recalculation
operation targets. The aggregate count-only result exposes no Ticket or CVE
identifier and no protected Ticket content.

This disclosure boundary depends on `manage_settings` being held only by
all-scope roles. Any future capability split, new role, or scope change that
grants `manage_settings` to a limited-scope role requires reassessment of this
endpoint's authorization and filtering boundary before that role ships.

Response (200 OK):

```json
{
  "data": {
    "observed_default_cvss_version": "3.1",
    "proposed_default_cvss_version": "4.0",
    "no_op": false,
    "cves_evaluated": 120000,
    "cve_severity_changes": 1400,
    "product_eligibility_changes": 4700,
    "product_eligibility_override_skips": 82,
    "resolved_ticket_regressions": 37
  }
}
```

A no-op response has equal observed and proposed values, `no_op = true`, and
every count `0`.

**Error responses**:

| Status | Code | Condition |
|---|---|---|
| 503 | `CVSS_PREVIEW_TIMEOUT` | The monotonic preview deadline expired before a complete result was available (all intermediate counts discarded) |

`CVSS_RECALC_ALREADY_IN_PROGRESS` does not apply: the preview is permitted
while a recalculation is admitted, queued, or running.

**Idempotency**: the endpoint is read-only and repeatable. Each invocation
reports the state it observes and creates no persistent effect.

**`Capability: manage_settings`**

### Trigger CVSS Recalculation

```
POST /api/v1/admin/settings/default-cvss-version/recalculate
```

Manually triggers a CVSS recalculation batch for all persisted CVEs, using the
current `default_cvss_version` value. Used for
recovery after partial batch failures or as a general refresh mechanism.

The endpoint uses the same shared logic as the PATCH side-effect:

1. Read the current `default_cvss_version` from the database
2. Acquire the recalculation slot (`SET cvss_recalc_active <timestamp>
   NX EX 900`) as the endpoint's immediate admission guard, with the same
   complete-run coordination boundary as the PATCH path
3. Enqueue `recalculate_cvss_derived_state(target_version)`. On failure: release slot
   and return 503
4. Return 202 Accepted

No setting change is made. No `SettingAuditEvent` is created.

**Request body**: none.

**Response** (202 Accepted):

```json
{
  "data": {
    "message": "Recalculation batch enqueued",
    "default_cvss_version": "4.0",
    "scope": "all_cves"
  }
}
```

**Error responses**:

| Status | Code | Condition |
|--------|------|-----------|
| 409 | `CVSS_RECALC_ALREADY_IN_PROGRESS` | A recalculation batch is already running (slot occupied) |
| 503 | `REDIS_UNAVAILABLE` | Redis rejected or could not complete slot acquisition |
| 503 | `CELERY_UNAVAILABLE` | Task could not be enqueued (slot released) |

**Idempotency**: safe to call multiple times. If no derived values have
changed since the last run, the batch produces no mutations or audit
events (guaranteed by `recalculate_cvss_chain()` idempotency).

**`Capability: manage_settings`**

## Data Model

System settings are stored in a key-value configuration table. See
`docs/data-model.md` for the schema.

## Setting Audit Log

Every administrative modification to a system setting MUST produce a
`SettingAuditEvent` record in the same database transaction as the
setting update. Alembic seeding and lifespan bootstrap are initialization,
not administrative modifications, and create no event.

### SettingAuditEvent Table

See `docs/data-model.md` for the full table definition. Key columns:

| Column | Type | Description |
|---|---|---|
| event_type | VARCHAR(50) | `SettingAuditEventType` — currently only `setting_changed` |
| setting_key | VARCHAR(100) | Which setting was changed (e.g., `default_cvss_version`) |
| user_id | UUID | Admin who changed the setting (always present — no system-initiated changes) |
| old_value | TEXT | Previous value |
| new_value | TEXT | New value |

### SettingAuditLog Service

```python
class SettingAuditLog(BaseAuditLog):
    name = "setting"
    description = "System setting modifications"
    model_class = SettingAuditEvent

    @classmethod
    async def log_event(
        cls,
        session: AsyncSession,
        *,
        event_type: SettingAuditEventType,
        setting_key: str,
        user_id: UUID | None,
        old_value: str | None,
        new_value: str,
    ) -> None:
        ...
```

The method accepts only a `SettingAuditEventType` member; the currently valid
member is `SETTING_CHANGED` (`"setting_changed"`). It validates the enum at
the service boundary because this classification enum has no database CHECK
constraint. It also requires a non-null `user_id`; a missing human actor raises
`ValueError`. The database foreign key validates `setting_key`, and NOT NULL
constraints validate required persisted fields.

After validation, the method creates exactly one event and flushes it before
returning. It never commits. Each invocation creates a new event and is
therefore not idempotent; callers MUST invoke it only when a setting value
actually changes. `ValueError` and all database/flush exceptions propagate to
the caller.

Setting mutations use a caller-owned transaction and pass the same
`AsyncSession` to the setting update and `log_event()`. If audit validation or
insertion fails, the exception remains part of the mutation transaction and
the caller rolls back both changes. The caller MUST NOT commit the setting
update independently or catch an audit failure and continue.

### List Settings Audit Events

```
GET /api/v1/admin/settings/audit-log
```

**Request body**: none.

Returns a paginated list of setting changes, ordered by `created_at`
descending, with deterministic secondary ordering as defined by
`docs/api-spec.md` (Deterministic Pagination Ordering). Sorting is fixed —
client-controlled `sort_by` / `sort_order` parameters are not supported
(audit trail entries are always displayed in reverse chronological order).

**Query parameters**:

| Parameter | Type | Default | Description |
|---|---|---|---|
| `page` | int | 1 | Page number (1-indexed) |
| `per_page` | int | 20 | Items per page (max 100) |
| `event_type` | string (repeatable) | -- | Filter by event type (currently only `setting_changed`). Multiple values use OR semantics (e.g., `?event_type=setting_changed`). See `docs/api-spec.md` (Enum Filter Validation) for handling of invalid values |
| `setting_key` | string | -- | Filter by setting key |
| `actor` | string | -- | Filter by actor: user UUID or username. `system` is accepted but will return no results (all setting changes are user-initiated) |
| `from_date` | string | -- | ISO 8601 date/datetime. Include events from this date onwards (inclusive) |
| `to_date` | string | -- | ISO 8601 date/datetime. Include events up to this date (inclusive) |

Different filter types combine with AND. Repeated `event_type` values combine
with OR after invalid enum values are removed according to `docs/api-spec.md`.
`setting_key` is an exact match; an unknown key returns an empty page. Actor
resolution uses `BaseAuditLog.filter_by_actor()`: unknown UUIDs/usernames and
the literal `system` return an empty page rather than 404.

Pagination uses the global bounds without clamping, `meta.total` counts the
filtered result set, and a page beyond the final page returns an empty `data`
array with the requested page metadata. Date parsing and normalization follow
`docs/api-spec.md` (Date Range Interpretation): malformed values produce the
global `422 VALIDATION_ERROR`, while an inverted normalized range produces the
shared `400 DATE_RANGE_INVERTED` response. Undeclared query parameters,
including `sort_by` and `sort_order`, follow the global undeclared-query
semantics and are ignored.

**`Capability: manage_settings`**

**Response** (200 OK):

```json
{
  "data": [
    {
      "id": "uuid",
      "event_type": "setting_changed",
      "setting_key": "default_cvss_version",
      "old_value": "3.1",
      "new_value": "4.0",
      "created_at": "2026-05-13T14:00:00Z",
      "actor": {
        "id": "uuid",
        "username": "asmith",
        "full_name": "Alice Smith",
        "active": true
      }
    }
  ],
  "meta": {
    "total": 3,
    "page": 1,
    "per_page": 20
  }
}
```

`created_at` is serialized in UTC with a `Z` suffix. Because setting audit
events require a human actor and user rows cannot be hard-deleted, `actor` is
always the complete current user reference object shown above and is never
`null`.

### Data Retention

Indefinite. SettingAuditEvent records are never automatically deleted.

## Cross-references

- `docs/features/platform/audit-trail-infrastructure.md` — BaseAuditLog,
  AuditEventMixin
- `docs/api-spec.md` — global API conventions (envelope format, error codes,
  pagination, shared 422 responses)
- `docs/features/identity/rbac.md` — Endpoint Permission Map
- `docs/features/tickets/cvss-scoring.md` — pure severity and eligibility
  resolutions consumed by the runner and the impact preview
- `docs/features/tickets/ticket-mutations.md` — default-version chain,
  runner-facing classification, and post-commit handoff consumed by the runner;
  default-version state matrix projected read-only by the impact preview
- `docs/features/tickets/tickets.md` — Analyzed and Resolved gate predicates
  reused by the runner and the read-only gate projection
- `docs/features/tickets/ticket-audit-log.md` — event types created by the
  runner's units
- `docs/features/packages/package-model.md` — automatic eligibility evaluator
  and manual override precedence
- `docs/features/platform/logging.md` — structured log record, levels, and
  sanitization contract consumed by the runner's events
- `docs/conventions.md` — Sync-to-Async Bridging, Cross-Loop Pooled Connection
  Lifecycle, and Transaction and Locking conventions applied by the runner
