# Default-CVSS Version Operations

## Purpose

Define the administrative operations that preview and apply a change to the
system-wide `default_cvss_version` policy. This specification owns the
read-only impact preview, the all-CVE recalculation runner, the manual
recalculation operation, aggregate observability, and restart and recovery
behavior.

`docs/features/platform/system-settings.md` remains authoritative for the
setting declaration, persistence, bootstrap, required-row reads, setting audit,
and the `GET` and `PATCH /api/v1/admin/settings` read and mutation contracts.
The specialized operations here consume that setting contract without becoming
a second owner of it.

The preview, the setting mutation, and the manual trigger compose one advisory,
non-atomic administrative sequence: the optional impact preview, the setting
`PATCH /api/v1/admin/settings` mutation, and the manual trigger that admits the
run. Its step order and non-atomicity rules are defined in
`docs/features/platform/system-settings.md` (Default CVSS Version); no step is
a prerequisite or reservation for another, and no client carries a version from
one request to the next.

## Scope and Ownership

This specification owns:

- `get_default_cvss_version_impact()` and its API endpoint;
- `recalculate_cvss_derived_state(target_version)` and its complete bounded
  runner;
- `admit_cvss_recalculation()` and the manual all-CVE recalculation endpoint;
- complete-run coordination: run identity, admission, the Redis ownership
  lease, task adoption, the PostgreSQL execution fence, ownership loss,
  publication uncertainty, lease renewal, owner-safe cleanup, and the
  coordination conditions that require operator recovery;
- runner logging, retry, rerun, restart, and recovery behavior; and
- the absence of persistent run and progress state.

Domain behavior remains with its existing authorities:

- `docs/features/tickets/cvss-scoring.md` owns pure severity and eligibility
  resolution;
- `docs/features/tickets/ticket-mutations.md` owns the authoritative
  default-version state matrix and the `changed`, `unchanged`, and `missing`
  single-CVE classifications, plus transaction-local Ticket convergence
  registration and consumption;
- `docs/features/packages/package-model.md` owns automatic Product eligibility;
- `docs/features/tickets/tickets.md` owns the Analyzed and Resolved predicates;
- `docs/features/tickets/ticket-service.md` owns Ticket convergence publication
  vocabulary, owner policies, and recovery; and
- `docs/features/tickets/ticket-audit-log.md` owns the resulting audit events.

Neither operation changes a CVSS assessment or applies a remediation action.

## Access Control

Both API endpoints in this specification require the `manage_settings`
capability.

## All-CVE Recalculation Runner

The all-CVE recalculation runner applies the current `default_cvss_version`
policy to every persisted CVE.
`POST /api/v1/admin/settings/default-cvss-version/recalculate` enqueues it; the
setting `PATCH /api/v1/admin/settings` never enqueues, admits, or publishes a
run. It is not a fetcher, sub-operation, or scheduled integration.

### Task Identity and Workflow

The Celery task is `recalculate_cvss_derived_state(target_version)`. Its only
semantic input is the primitive `target_version`, exactly `"3.1"` or `"4.0"`.
Its Celery request ID is operational metadata rather than a second semantic
input. No task argument carries a session, ORM object, collection, or per-CVE
payload.

The synchronous task wrapper:

1. Validates the received `target_version` using input only. Any other value is
   a non-retryable caller-contract failure before any database read, before
   enumeration, and before any CVE mutation. It emits no run counters and no
   feature run event.
2. Reads `task.request.id`, validates that it is the canonical lowercase
   hyphenated representation of a UUID version 4, and passes it explicitly to
   the service-owned workflow as `celery_task_id`. A malformed or absent task ID
   is a non-retryable contract failure before `asyncio.run()`, fence
   acquisition, Redis access, or any database mutation. It emits only
   `cvss_recalculation_adoption_rejected` with reason `task_id_invalid`, creates
   no run counters, and emits no terminal run event.
3. Invokes exactly one `asyncio.run()` around the service-owned asynchronous
   workflow. It delegates all logic to the service layer and performs no
   business query, settings read, transaction, or engine disposal of its own.
4. Returns `None` and stores no task result.
5. Lets cancellation, worker shutdown, `SoftTimeLimitExceeded`, `MemoryError`,
   and every other control signal propagate unchanged. It converts no control
   signal into an ordinary task outcome.

The service-owned asynchronous workflow
`run_cvss_derived_state_recalculation(target_version, celery_task_id,
session_factory)` receives the validated task ID explicitly; service code does
not read `celery.current_task`, `task.request`, or logging context to recover
it. The workflow opens one independent session per unit, owns their commits and
rollbacks, and maintains one fixed-size in-memory aggregate used only for the
run's structured logs. Its run metadata is `target_version`,
`celery_task_id`, the captured watermark (absent for a stale delivery), and the
terminal outcome token. Its counters are exactly `changed`, `unchanged`,
`skipped`, `failed`, and the derived `succeeded` and `processed`. It contains no
other counter, no publication result, no CVE, Ticket, package, Product, or
occurrence identifier, and no per-CVE detail collection. The workflow emits
the run's events from that aggregate, discards it, and returns `None`; the
wrapper therefore receives no task result. The aggregate is never persisted
and never published to a result backend.

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

Complete-run admission, ownership, lease renewal, the execution fence that
prevents a setting change or another owner from overtaking an admitted run, and
crash cleanup are owned by Complete-Run Coordination below. That contract
preserves the validation, paging, unit, drain, and outcome semantics defined
here; an ownership-loss termination is a whole-run condition and never an
ordinary failed unit. A delivered task confirms exact ownership before it begins
its first unit, so a non-owner delivery mutates nothing.

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
7. apply the committed unit's `changed`, `unchanged`, or `skipped`
   classification to the in-memory counters;
8. roll back exactly once when an isolable pre-finalizer unit error occurs;
9. close the session;
10. ensure the unit's locks are released before any external effect;
11. detach and drain the unit's registered transaction-local Ticket convergence
     effects after commit and session close; and
12. proceed to the next candidate only after the previous unit completes.

The run does not freeze one global date: each CVE unit uses its own UTC
`evaluation_date` consistently across its lifecycle, eligibility, actionability,
reconciliation, and result.

A `missing` result is a successful unit with no pending mutation: its
transaction commits, its session closes, no post-commit effect is registered,
and the runner counts it `skipped`. A rolled-back unit's drain is skipped and no
registered effect is published.

The default-version mode, its exhaustive Ticket-state effects, and its
`changed`, `unchanged`, and `missing` classifications are authoritative in
`docs/features/tickets/ticket-mutations.md` (`recalculate_cvss_chain()`). The
runner neither copies nor extends that matrix. The function in turn delegates
severity, eligibility, Product, gate, and audit semantics to their owning
specifications listed under Scope and Ownership.

Visiting a `Resolved` Ticket may regress it through ordinary gate evaluation and
register one transaction-local Ticket convergence effect. After that CVE unit
is flushed, committed, and its session closed, the runner drains the effect
before the next unit. The registration lifecycle is authoritative in
`docs/features/tickets/ticket-mutations.md`; publication vocabulary and the
automatic owner policy are authoritative in
`docs/features/tickets/ticket-service.md` (`Ticket Convergence`). In particular:

- a broker `kombu.exceptions.OperationalError` is logged once by the shared
  Ticket-owned adapter and absorbed; it changes no runner counter, unit
  classification, result, event, or aggregate outcome, and the scan continues;
  and
- every non-operational post-commit exception propagates as a whole-run
  condition without rolling back or reclassifying the committed unit.

Visiting an `Ignored` or `Duplicated` Ticket cannot exit its manual zone or
register Ticket convergence work. Product eligibility and gates for those
Tickets converge only through the owning manual-zone-exit workflow.

### Outcome Classification

The runner aggregates the transaction-local classifications defined by
`ticket_mutations.recalculate_cvss_chain()` into four in-memory counters:

| Counter | Meaning |
|---|---|
| `changed` | A committed unit returned the authoritative `changed` classification |
| `unchanged` | A committed unit returned the authoritative `unchanged` classification |
| `skipped` | The authoritative result was `missing` because the enumerated candidate no longer existed when locked-current processing began |
| `failed` | The unit rolled back for an isolated pre-finalizer per-CVE error |

The derived aggregate values are exactly
`succeeded = changed + unchanged` and
`processed = changed + unchanged + skipped + failed`. There is no publication
counter or publication result in the aggregate.

The terminal outcome of a delivery is exactly one of:

| Terminal outcome | Condition |
|---|---|
| `completed` | The watermark was reached with `failed = 0` |
| `partial` | The watermark was reached with at least one isolated pre-finalizer failure |
| `stale` | The persisted default version differed from `target_version` before the scan |
| `cancelled` | An interceptable cancellation or worker shutdown terminated the delivery |
| `ownership_lost` | Complete-run coordination signalled that this delivery no longer owns the run |
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
- the connection is not invalidated; and
- the runner can reliably start and process the next candidate.

An isolable failure increments `failed`, emits one
`cvss_recalculation_cve_failed` warning, and never rolls back a committed
sibling. The increment and warning occur only after rollback and session cleanup
complete successfully.

**Whole-run errors.** These terminate the delivery and propagate. They are never
converted into the ordinary per-unit `failed` counter:

- enumeration failure;
- inability to create a unit session;
- commit failure or an ambiguous commit outcome;
- rollback failure;
- session cleanup failure;
- a globally unavailable database or an invalidated connection;
- a missing required system setting;
- a contract violation or programming error;
- a non-operational post-commit exception;
- cancellation;
- worker shutdown;
- `SoftTimeLimitExceeded`;
- `MemoryError`; and
- ownership loss.

A broad per-item `except Exception` that maps these into `failed` is forbidden.
The per-unit handler may isolate only an ordinary transaction-local domain/data
or database exception for which it proves every isolation condition above.
Database invalidation or global unavailability, contract violations,
programming errors, and unexpected exception types are always whole-run
conditions even when rollback and session cleanup succeed. These whole-run
conditions remain whole-run when they are raised during enumeration, a unit
transaction, or a detached publication. Only
`kombu.exceptions.OperationalError` from automatic Ticket convergence
publication is absorbed under the shared Ticket-owned policy, without changing
any runner counter or aggregate outcome. Cancellation and worker shutdown
terminate as the `cancelled` outcome, an ownership-loss signal terminates as
`ownership_lost`, and every remaining whole-run condition terminates as the
`failed` outcome.

Wrapper-rejected task inputs do not enter this taxonomy: an invalid
`target_version` emits no run or coordination event, and an invalid
`celery_task_id` emits only `cvss_recalculation_adoption_rejected`, as defined
under Task Identity and Workflow.

Counter treatment follows the commit boundary. A condition raised before
successful commit, or a failed or ambiguous commit, leaves every unit counter at
its pre-unit value. A session-cleanup or drain condition raised after successful
commit terminates the run but preserves the committed unit's classification and
its corresponding `changed`, `unchanged`, or `skipped` counter.

### Logging

The runner consumes the shared structured logging contract in
`docs/features/platform/logging.md` without modifying it. It emits these events:

| Event | Level | When |
|---|---|---|
| `cvss_recalculation_started` | INFO | Once, after the target is validated as current and the bounded population is established, including an empty population, before enumeration |
| `cvss_recalculation_cve_failed` | WARNING | Once per isolated failed unit |
| `cvss_recalculation_completed` | INFO | Terminal, `completed` |
| `cvss_recalculation_partial` | WARNING | Terminal, `partial` |
| `cvss_recalculation_stale` | INFO | Terminal, `stale` |
| `cvss_recalculation_cancelled` | WARNING | Terminal, `cancelled` |
| `cvss_recalculation_ownership_lost` | WARNING | Terminal, `ownership_lost` |
| `cvss_recalculation_failed` | ERROR | Terminal, `failed` |

The `cvss_recalculation_cve_failed` warning carries only the canonical CVE
identifier, `target_version`, a bounded failure phase, a closed sanitized cause
category, and the task-bound `celery_task_id`. Its phase is exactly `unit` and
its cause is exactly `database` or `domain`, because only an ordinary isolated
pre-finalizer unit failure produces this warning. Terminal failure phases use
the closed vocabulary `setting_read`, `enumeration`, `unit`, `publication`, and
`control`. Terminal cause categories use the closed sanitized vocabulary
`database`, `domain`, `programming`, `infrastructure`, `interrupted`, and
`unexpected`.

Failure logs never contain CVSS vectors or assessments, full payloads, Ticket
descriptions, Product collections, SQL, raw exception text, URLs or external
data, credentials or secrets, or unbounded aggregate lists. Per-CVE successful
units emit no INFO log. The start event carries `target_version`, the watermark
when one exists, zero-valued counters, and the task-bound `celery_task_id`; an
empty population emits the event without a watermark. The workflow emits
exactly one terminal event for every outcome it reaches and emits the applicable
terminal event at a safe checkpoint before a whole-run condition propagates.
Terminal events from the table above carry `target_version`, the captured
watermark when one exists (it is omitted for a stale delivery or a failure
before capture), `changed`, `unchanged`, `skipped`, `failed`, `succeeded`,
`processed`, and the task-bound `celery_task_id`. The `failed`, `cancelled`, and
`ownership_lost` events additionally carry their failure phase and sanitized
category; `partial` carries neither because its isolated causes are recorded by
the per-CVE warnings. The terminal event never carries an array of failed CVE
identifiers; every isolated failure already has its own individual event.

The shared `ticket_convergence_publication_failed` event remains owned by
`ticket-service.md`. It is not a runner event and carries no runner phase, CVE
identifier, counter, or aggregate outcome.

## Default-CVSS Impact Preview

The read-only impact preview lets an administrator understand the expected
consequences of a proposed `default_cvss_version` change before mutating the
setting. It projects the same authoritative single-CVE default-version outcomes
that the runner applies, without performing any mutation.

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
5. Projects each CVE using the authoritative default-version matrix in
   `docs/features/tickets/ticket-mutations.md`, the proposed version, and the
   complete, unfiltered assessment set, then accumulates the aggregate counts
   defined below.
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
- "Applicable occurrence" means an occurrence for which the authoritative
  default-version matrix evaluates automatic Product eligibility.
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
  occurs; and
- the result has no relationship to the manual recalculation operation, which
  remains the separate recovery and refresh surface.

### Projected Impact

The preview projects the default-version mode of
`ticket_mutations.recalculate_cvss_chain()` as defined by the authoritative
state matrix and classification in `docs/features/tickets/ticket-mutations.md`,
substituting projected values for persistence. It does not restate or alter that
matrix.

Projection rules:

- Severity and eligibility remain separate resolutions. The projected
  severity uses the Severity Resolution Cascade with the proposed version;
  the projected eligibility score uses the canonical SUSE assessment for the
  proposed version or the `10.0` fallback. Neither substitutes for the other.
- Automatic Product eligibility uses the package-model-owned evaluator for
  every occurrence selected by the authoritative state matrix. Exclusion, EOL,
  actionability, and affectedness are not formula inputs. Rule 1 of the
  eligibility evaluator always preserves an occurrence with
  `is_eligible_override = true`; the preview reports it as a skip and changes no
  field.
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
- One UTC `evaluation_date` governs lifecycle, eligibility, actionability, and
  gate projection for the complete invocation.

### Consistency and Staleness

- The preview is one advisory bounded scan, not one coherent PostgreSQL
  snapshot of the complete population. Each CVE evaluation unit uses a
  coherent set of authoritative inputs for that unit; different units may
  observe different committed states. A unit's contribution must correspond
  entirely to one committed database observation: the implementation may read
  a single statement, a bounded page-level snapshot covering several CVEs, or
  use an equivalent mechanism, but it must not synthesize one unit from inputs
  observed on opposite sides of a concurrent commit. The observation mechanism,
  transaction shape, and page size remain internal implementation choices and
  are not part of the API contract.
- CVEs whose row `id` exceeds the captured high-water mark are excluded from
  the invocation. A CVE whose `id` does not exceed the mark may or may not be
  observed when it becomes visible during the invocation, and a committed
  change to an observed CVE may or may not be visible, depending on when that
  unit is read. CVE association, assignment, assessment, eligibility,
  lifecycle, and gate inputs are read from committed current state, not from a
  preview-time snapshot.
- The observed setting value is returned for orientation only. It does not
  block, freeze, or reserve a concurrent setting change, and the preview is not
  evidence that a later mutation will observe the same value.
- A repeated preview may return different counts. The preview result is not a
  snapshot token, reservation, approval, or binding prerequisite. A later
  `PATCH /api/v1/admin/settings` independently classifies its own current state
  and never receives, reuses, or trusts preview counts, the high-water mark, or
  any preview state.
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
- returns no partial result: an incomplete scan is never reported as a complete
  preview and never produces HTTP 200.

The preview has no resumable cursor, response pagination, continuation token,
persisted partial result, or progress resource.

### Preview Service Exception

`CVSSPreviewTimeoutError` inherits from `SettingsServiceError`, which inherits
from the shared `ServiceError` root.

| Exception | HTTP | Code | Raised when |
|---|---|---|---|
| `CVSSPreviewTimeoutError` | 503 | `CVSS_PREVIEW_TIMEOUT` | The monotonic preview deadline expires before a complete result is available |

`RequiredSystemSettingMissingError` remains owned by
`docs/features/platform/system-settings.md`. It propagates through the preview
and produces the global, non-sensitive `500 INTERNAL_ERROR` response.

## API Endpoints

### Get Default-CVSS Impact Preview

```text
GET /api/v1/admin/settings/default-cvss-version/impact
```

**Request body**: none.

**Query parameters**:

| Parameter | Type | Default | Description |
|---|---|---|---|
| `proposed_version` | string | -- (required) | Proposed `default_cvss_version`; exactly `3.1` or `4.0` |

A missing value, an unsupported value, or any other schema violation produces
the global `422 VALIDATION_ERROR` response. Undeclared query parameters are
ignored per the global undeclared-query convention.

**Behavior**: call `get_default_cvss_version_impact()` with the request session
and `proposed_version`, and return its complete aggregate result in the standard
`{"data": ...}` envelope. The endpoint is not paginated because it returns one
fixed-size aggregate object, and it has no `meta` object. A
`CVSSPreviewTimeoutError` is exposed as `503 CVSS_PREVIEW_TIMEOUT`; an incomplete
scan is never returned as a partial success.

The preview evaluates the system-wide persisted-CVE population, including
ticketless CVEs and CVEs associated with confidential Tickets. The
`manage_settings` capability alone is sufficient: the preview introduces no
capability and applies no consumer Ticket visibility filtering, because it must
observe the same system-wide policy-migration set that the recalculation
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
| 503 | `CVSS_PREVIEW_TIMEOUT` | The monotonic preview deadline expired before a complete result was available; all intermediate counts were discarded |

`CVSS_RECALC_ALREADY_IN_PROGRESS` does not apply: the preview is permitted
while a recalculation is admitted, queued, or running.

**Idempotency**: the endpoint is read-only and repeatable. Each invocation
reports the state it observes and creates no persistent effect.

**`Capability: manage_settings`**

### Trigger CVSS Recalculation

```text
POST /api/v1/admin/settings/default-cvss-version/recalculate
```

Manually triggers the all-CVE recalculation runner using the current persisted
`default_cvss_version`. It is the explicit restart-from-beginning surface after
an interrupted or partial run and may also be used as a general refresh
operation. It is the only operation that admits or publishes the runner; the
setting `PATCH /api/v1/admin/settings` changes the value without starting,
resuming, or scheduling any run. A successful PATCH therefore converges
existing derived state only after a manual trigger. A setting change committed
after an admission but before the task's adoption does not retarget that
delivery; the delivery terminates `stale` instead.

The endpoint uses the complete admission and publication coordination:

1. Acquire the PostgreSQL execution fence with non-blocking semantics. A
   definitive lock-not-acquired result returns `409
   CVSS_RECALC_ALREADY_IN_PROGRESS` and performs no lease acquisition and no
   publication. A database or session error during acquisition propagates as a
   server error and is never reported as `409`.
2. While holding the fence, read the current `default_cvss_version` through the
   required-row read service. A setting-read or database failure releases the
   fence, acquires no lease, invokes no publisher, and propagates the original
   error.
3. Still while holding the fence, preallocate the run's Celery task ID and
   acquire the Redis lease `cvss_recalc_active` with `SET ... NX EX 900`. A
   held lease releases the fence and returns `409
   CVSS_RECALC_ALREADY_IN_PROGRESS`; a `RedisError` or uncertain acquisition
   releases the fence and returns `503 REDIS_UNAVAILABLE`.
4. Release the fence and confirm that release before any broker call. If
   `pg_advisory_unlock` fails or its result is uncertain, do not invoke the
   publisher, invalidate or close the dedicated connection so connection
   closure remains the release backstop, attempt owner-safe compare-and-delete
   of the lease, emit the applicable cleanup event, and propagate the original
   server error. This path is not `CELERY_UNAVAILABLE` because the publisher was
   never invoked. A definitive `false` return also means release was not
   confirmed; it is treated as an internal fence-release failure and follows
   this same global `500 INTERNAL_ERROR` path.
5. Enqueue `recalculate_cvss_derived_state(target_version)` with the preallocated
   task ID, then classify the publication outcome under Publication Uncertainty.
   A `submitted` outcome returns `202 Accepted`; an `acceptance_unconfirmed`
   outcome returns `503 CELERY_UNAVAILABLE` with the fixed sanitized detail
   `"Recalculation task publication could not be confirmed"` and retains the
   lease. Any other publisher exception propagates unchanged and retains the
   lease conservatively.

No setting change is made and no `SettingAuditEvent` is created. The endpoint
never asserts that the broker rejected an unconfirmed task, and it never treats
the absence of a terminal event as completion.

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
|---|---|---|
| 409 | `CVSS_RECALC_ALREADY_IN_PROGRESS` | The execution fence or the admission lease is already held |
| 503 | `REDIS_UNAVAILABLE` | Redis rejected or could not complete lease acquisition; no publication occurred and nothing was committed |
| 503 | `CELERY_UNAVAILABLE` | The publisher raised `kombu.exceptions.OperationalError`, so broker acceptance is unconfirmed and the lease is retained |

The `503 CELERY_UNAVAILABLE` detail is fixed and sanitized and never contains
the broker exception text:
`"Recalculation task publication could not be confirmed"`. An unconfirmed
acceptance is not proof of rejection: the task may still be delivered and adopt
the retained lease, or the lease may expire by its TTL if the task was never
accepted. Setting-read, database, commit, and fence-release failures that occur
before publisher invocation propagate through their ordinary server-error
mapping and are never reported as `CELERY_UNAVAILABLE`.

**Idempotency and recovery**: the operation is intentionally repeatable. See
All-CVE Recalculation Runner above for execution semantics and Retry, Rerun, and
Recovery below for the normative recovery contract.

**`Capability: manage_settings`**

## Retry, Rerun, and Recovery

The runner configures no Celery automatic retry and never calls `self.retry()`.
Recovery is a complete explicit rerun from the beginning through the manual
endpoint. There is no resume cursor or partial-progress state. Already
converged units classify `unchanged` and create no duplicate mutation or audit
event.

The manual endpoint is intentionally repeatable. If no derived values have
changed since the last run, the runner produces no mutations or audit events.
A broker operational failure while automatically publishing Ticket convergence
does not make the CVSS run partial and does not add a runner recovery record.
Recovery for that committed Ticket effect is the explicit complete Ticket
convergence rerun in `docs/features/tickets/tickets.md`; a CVSS rerun is not
guaranteed to republish an already-converged unit.

Complete-run coordination recovery is deterministic:

- a completed, partial, stale, cancelled, or ownership-lost delivery attempts
  owner-safe lease removal and releases the fence, so the next manual trigger
  admits immediately;
- a hard kill, OOM kill, or worker disappearance performs no explicit cleanup:
  the PostgreSQL connection closure releases the fence and the lease expires by
  its TTL, so the trigger is retryable after the TTL at the latest;
- a `503 CELERY_UNAVAILABLE` from an unconfirmed acceptance retains the lease:
  wait for the task to be delivered and adopt it, or wait for the lease TTL,
  then retry;
- a wedged process can retain the fence; the operator MUST terminate that worker
  or pod before retrying; and
- recovery never deletes a lease unconditionally. The complete operator
  procedure is in `docs/deployment.md` (CVSS Recalculation Recovery).

## Absence of Persistent Run State

The preview and runner introduce:

- no `FetcherRun` record;
- no Celery result-backend entry and no persisted task result;
- no run, progress, resume, or cursor table, column, or resource;
- no persisted high-water mark, offset, or continuation token;
- no metric or log used as authoritative state;
- no generic batch, backfill, or reusable runner framework;
- no new audit event type; the unit's ordinary domain audit events remain the
  only durable audit records;
- no persistent coordination record: the admission and ownership lease is a
  TTL-bounded
  Redis key and the execution fence is a session-scoped PostgreSQL advisory
  lock, neither of which is persisted, returned, or used as state; and
- no new configuration variable or setting.

The normative restart and recovery behavior is defined in Retry, Rerun, and
Recovery above, and the coordination resource lifecycle is defined in
Complete-Run Coordination below.

## Complete-Run Coordination

This section owns complete-run admission, run identity, ownership, lease
renewal, the execution fence and its stable identifier, task adoption,
ownership loss, Redis-loss behavior, publication uncertainty, protection of an
admitted run from another owner, cleanup, and the coordination conditions that
require operator recovery. It preserves every validation, stale-delivery,
bounded paging, independent-unit, post-commit, outcome, restart, and
no-persistent-state contract defined above. An ownership-loss termination is a
whole-run condition and is never an ordinary failed unit.

Coordination introduces no persistent run row, progress resource, resume cursor,
outbox, result-backend entry, audit event, capability, configuration variable,
or generic lease framework. Redis owns admission and cooperative ownership;
PostgreSQL owns the execution fence that prevents overlapping mutation after
Redis loss.

### Run Identity

One recalculation attempt is identified by one preallocated Celery task ID
(`celery_task_id`): a canonical lowercase hyphenated, cryptographically random
UUID (version 4) that the admitting API request allocates while it holds the
execution fence and before it acquires the lease. The same value is:

- the run identity;
- the Celery task ID supplied to the publication call, so that in the worker it
  equals `task.request.id`; and
- the Redis owner token.

`target_version` remains the only semantic task input. The task ID is
operational metadata: it is not passed as a separate semantic task argument, is
never persisted in PostgreSQL, is not returned by the coordination contract, and
is not derived from `request_id`, `target_version`, or any other value.

### Coordination Resources

| Resource | Name | Value | Lifetime |
|---|---|---|---|
| Admission and ownership lease | Redis key `cvss_recalc_active` | `v1:<celery_task_id>:<target_version>` | Set with `SET ... NX EX 900`; renewed at safe checkpoints; removed by owner-safe compare-and-delete |
| Execution fence | One stable feature-specific PostgreSQL session-level advisory lock | Carries no value | Held by one connection from non-blocking acquisition until explicit release or connection/process closure |

Lease value rules:

- `v1` is the value-schema version.
- `<celery_task_id>` is the canonical lowercase hyphenated UUID string.
- `<target_version>` is exactly `"3.1"` or `"4.0"`.
- Renewal and release compare the complete value atomically. A prefix,
  field-selective, or timestamp-only comparison is never ownership.
- The TTL is exactly 900 seconds from each successful acquisition or renewal.
  The renewal interval is at least 60 seconds since the last successful
  renewal; a checkpoint check made earlier than that performs no command. The
  adoption confirm-and-renew is exempt from this minimum and always executes.
  Both values are feature constants, not configuration.
- A timestamp is not part of the value and is never ownership.
- TTL expiry proves only that the bounded interval elapsed. It never proves
  that the runner stopped, and a missing key never proves completion.
- A stored value that does not parse as `v1:<canonical-uuid>:<target_version>`
  matches no owner: a fresh acquire returns `not_acquired`, and
  compare-and-renew and compare-and-delete return `mismatch`. Because there is
  no complete expected value to compare against, only TTL expiry recovers a
  malformed value; an operator cannot remove it owner-safely.
- The complete token is never written to a log beyond the normal bound
  `celery_task_id` correlation field, is never persisted, and is never returned
  by the API.
- PostgreSQL, not Redis, remains the source of truth for completed derived
  state.

The fence and the lease are independent. The lease admits at most one owner; the
fence prevents overlapping mutation after the lease is lost, expired, or
replaced. Neither resource is authoritative progress, completion, or recovery
state.

### Atomic Lease Operations

Complete-run coordination defines exactly three feature-specific Redis
operations. They are not a shared or generic lease framework. All three:

- are one atomic Redis command or server-side script;
- receive only the expected canonical task ID and target version;
- create no `SettingAuditEvent`, `TicketAuditEvent`, or other audit record;
- perform no database read, mutation, transaction, or row lock; and
- execute only outside every per-CVE database transaction and CVE/Ticket row
  lock.

All three are idempotent for ownership purposes: repeating one changes no
ownership and, except for an acquire that finds an existing key, converges to
the same resource state. When the client cannot determine whether a command
completed, the owner applies the conservative outcome that cannot authorize
mutation, as specified per operation. `RedisError` propagates to the caller,
whose behavior is specified below.

**Acquire.** `SET cvss_recalc_active v1:<task_id>:<target_version> NX EX 900`,
returning `acquired` when the key was absent and the complete value was written,
or `not_acquired` when a key already exists. A `not_acquired` result mutates
nothing and changes no ownership. On `RedisError`, the API returns `503
REDIS_UNAVAILABLE`. When completion is uncertain, the caller MUST NOT proceed to
publish: the write may have occurred, so the safe outcome is temporary
unavailability until any written key expires. Re-issuing acquire while a key
exists is a safe `not_acquired` no-op.

**Compare-and-renew.** Atomically set the TTL of `cvss_recalc_active` to 900
seconds if and only if its complete current value equals
`v1:<task_id>:<target_version>`, returning `renewed`, `absent` (the key does not
exist), or `mismatch` (the key exists with a different value). It performs no
removal and no value replacement. On `mismatch`, `absent`, `RedisError`, or
uncertain completion, the delivery does not hold confirmed ownership. The
calling phase owns the outcome: the initial adoption check produces only
`adoption_rejected`, while a checkpoint after successful adoption blocks the
next unit and terminates the active run as `ownership_lost`.

**Compare-and-delete.** Atomically delete `cvss_recalc_active` if and only if
its complete current value equals `v1:<task_id>:<target_version>`, returning
`deleted`, `absent`, or `mismatch`. `absent` and `mismatch` perform no deletion,
so an old owner can never remove a newer owner's record. On `RedisError` or
uncertain completion, the operation is recorded as a cleanup failure that
changes no committed state and no terminal classification; the key expires by
its TTL. Repeating a release after deletion is an idempotent `absent` no-op.

### Execution Fence

Complete-run coordination uses one stable, feature-specific PostgreSQL
session-level advisory-lock identifier. Its concrete numeric value is an
implementation constant, but it MUST be stable across releases, reserved for
this feature, and neither shared nor colliding with any other advisory-lock
consumer. The same identifier is used by the manual trigger, the task, and the
effective setting mutation defined in
`docs/features/platform/system-settings.md`: the manual trigger and the task
hold it at session level, while an effective setting change requests it in
transaction-level, non-blocking form. No path uses a different identifier.

- Acquisition is non-blocking (`pg_try_advisory_lock` semantics). A caller that
  does not acquire the fence waits for nothing and mutates nothing.
- The fence is session-scoped, not transaction-scoped, so it necessarily spans
  the independent per-CVE transactions.
- The fence is not a transaction. No single database transaction and no
  CVE/Ticket row lock spans units; each unit keeps its own transaction and lock
  scope as defined above.
- The fence is acquired and released on one dedicated connection that is not
  returned to the connection pool while the fence is held.
- Every unit's fresh session and independent transaction execute on that same
  fenced connection. The runner opens no unit session on a different connection
  while it holds the fence, so the fence cannot be silently released while the
  runner keeps mutating.
- A fenced connection that closes, is lost, or is invalidated is therefore
  observed when the next unit's session on it fails, or by a fence-ownership
  check performed on it before resuming. The runner MUST NOT reconnect, obtain
  another connection, or continue mutating after that loss; it terminates as a
  whole-run `failed` outcome.
- Every interceptable path releases the fence explicitly: success, every
  terminal outcome, an exception, cancellation, and worker shutdown.
- If the fenced connection closes without an explicit release, PostgreSQL
  releases the fence automatically.
- The fence carries no value and is never used as progress, a result, or durable
  state.

Because the fence is exclusive, two deliveries of the same token, or a delivery
and an API admission, cannot hold it at the same time. The fence therefore also
prevents concurrent same-token execution.

### Admission Ordering

The manual trigger's admission path is normative and ordered:

1. Acquire the fence with non-blocking semantics.
2. If the fence is not acquired, the request performs no lease acquisition and
   no publication. It receives `409 CVSS_RECALC_ALREADY_IN_PROGRESS`, and the
   run remains with its current owner. A fence that stays held while no runner
   is renewing its lease is the recovery-required condition described under
   Operator Recovery.
3. Read `default_cvss_version` through the required-row service while the fence
   is held. A read failure releases the fence, acquires no lease, invokes no
   publisher, and propagates the original error. This read is the only source
   of the run's `target_version`; no client-supplied version is accepted, and a
   setting change committed before this read is the version the admission
   publishes.
4. While holding the fence, preallocate the run's task ID and acquire the lease
   with atomic `SET ... NX EX 900`. A `not_acquired` result means another owner
   is admitted: release the fence and return `409
   CVSS_RECALC_ALREADY_IN_PROGRESS`; no publication occurs. A `RedisError` or
   uncertain acquisition releases the fence and returns `503
   REDIS_UNAVAILABLE`.
5. Release the fence and confirm successful release before invoking the broker
   publication call. The lease, not the fence, covers the interval between the
   release and the task's adoption. If explicit unlock fails or is uncertain,
   invoke no publisher, invalidate or close the dedicated connection, attempt
   owner-safe lease removal, emit the applicable cleanup event, and propagate
   the original server error. Connection closure is the automatic release
   backstop.
6. Invoke the publication call and classify its outcome under Publication
   Uncertainty.

Two manual admissions cannot overlap: the second admission either finds the
fence held by the first, or finds the lease held by the first admission's task
ID. An effective setting change likewise cannot overtake a runner protected by
the fence, even when the lease is absent, because the running task holds the
session-level fence for its complete mutating workflow and the setting
mutation's transaction-level request conflicts with it.

Releasing the fence before publication is required so that a very fast task does
not mistake the API's short fence hold for a genuine collision. It does not
weaken exclusion: the lease is acquired while the fence is held and is released
only at terminal cleanup.

A different admission's brief fence hold during its own lease attempt can still
make a legitimate delivery's non-blocking adoption acquire fail. That delivery
terminates as an adoption rejection, and recovery is the documented TTL-based
path. This is an accepted, safe availability cost: no overlapping mutation is
possible, because the rejected delivery mutates nothing and the lease owner is
unchanged.

The setting mutation contract in `docs/features/platform/system-settings.md`
shares the same fence identifier but performs no lease acquisition, no task-ID
allocation, and no publication; it owns its own row-lock, mutation, and audit
composition. A setting change committed after an admission but before the
task's adoption makes that delivery `stale` under Input Validation and Stale
Delivery, and recovery is always a new manual admission. A fence that cannot be
acquired because of a database or session error is a server error, not the
`fence_busy` rejection: only a definitive "lock not acquired" result produces
`409 CVSS_RECALC_ALREADY_IN_PROGRESS`.

### Manual Admission Service

The manual trigger delegates admission and publication to the service-owned
admission boundary:

```python
async def admit_cvss_recalculation() -> CVSSRecalculationAdmission:
    ...
```

The boundary accepts no caller-supplied input: no session, target version, or
task ID is passed in. It owns its dedicated fenced connection for the complete
admission sequence, including the post-release publication attempt, and
therefore accepts no caller-supplied session. The run's `target_version` is the
persisted setting read while the fence is held. `CVSSRecalculationAdmission` is
the successful result: it carries the `submitted` outcome and the target
version that was published, which the endpoint uses for the `202 Accepted`
response body.

The boundary creates no `SettingAuditEvent`, no durable run row, no progress or
resume resource, and no compensation record. It is repeatable: every admission
that reaches publication allocates a new run identity and publishes a new
complete run; a blocked admission publishes nothing.

All exceptions raised by the settings feature's service functions — setting
mutation, preview, runner, and manual admission — inherit from
`SettingsServiceError`, which inherits from the shared `ServiceError` root.
`CVSSRecalculationAlreadyInProgressError` is owned by
`docs/features/platform/system-settings.md`;
`CVSSRecalculationRedisUnavailableError` and
`CVSSRecalculationBrokerUnavailableError` are owned by this specification.

| Exception | HTTP | Code | Raised when |
|---|---|---|---|
| `CVSSRecalculationAlreadyInProgressError` | 409 | `CVSS_RECALC_ALREADY_IN_PROGRESS` | The execution fence or the admission lease is already held; no run is admitted and nothing is published |
| `CVSSRecalculationRedisUnavailableError` | 503 | `REDIS_UNAVAILABLE` | Lease acquisition raised `RedisError` or its completion was uncertain; the fence is released, nothing is published, and the exception carries a fixed sanitized detail that never contains the Redis exception text |
| `CVSSRecalculationBrokerUnavailableError` | 503 | `CELERY_UNAVAILABLE` | The publication call raised `kombu.exceptions.OperationalError`; the exception carries the fixed sanitized detail and never the broker exception text |

`CVSSRecalculationAlreadyInProgressError`'s HTTP/code mapping and the
transaction-level setting-change form are defined in
`docs/features/platform/system-settings.md`. Setting-read, database, commit, and
fence-release failures that occur before publisher invocation are not mapped to
`CELERY_UNAVAILABLE`; they propagate through their ordinary server-error
mapping.

### Task Adoption

A delivered task begins no CVE transaction until it has proven ownership. The
task:

1. arrives with a wrapper-validated canonical `celery_task_id`; an absent or
   malformed ID has already produced only the `task_id_invalid` adoption
   rejection and has not entered this workflow;
2. validates the received `target_version`; an invalid target remains the
   non-retryable caller-contract failure under Input Validation and Stale
   Delivery, with no coordination event or run event;
3. acquires the fence with non-blocking semantics; if it does not acquire the
   fence, it starts no CVE transaction, mutates nothing, releases nothing,
   emits the adoption-rejected event, and terminates;
4. confirms exact ownership with one atomic compare-and-renew of
   `cvss_recalc_active` against `v1:<task_id>:<target_version>`; on `mismatch`,
   `absent`, `RedisError`, or uncertain completion it releases the fence, starts
   no CVE transaction, mutates nothing, emits only
   `cvss_recalculation_adoption_rejected`, and terminates; and
5. only after steps 3 and 4 succeed, emits `cvss_recalculation_adopted`, starts
   the run workflow, performs the existing stale-delivery check, and begins
   enumeration.

Only a delivery that holds both the fence and a confirmed exact owner/target
lease may begin the first unit. Malformed, mismatched, absent, expired,
replaced, duplicate, redelivered, and delayed old deliveries therefore begin no
CVE read, lock, mutation, audit, or publication. A delivery whose token was
replaced by a newer owner fails step 4 against the newer value and mutates
nothing, even when it arrives after the newer owner has completed.

A delivery rejected during adoption terminates before the run workflow begins.
Fence occupancy, an absent or different lease, an invalid task ID, and
`RedisError` or uncertain completion during the initial compare-and-renew all
emit only `cvss_recalculation_adoption_rejected`, create no counters, begin no
CVE, and emit no terminal run event because they reach no run outcome. Invalid
`target_version` remains the input-contract failure defined above and emits no
coordination event.

### Lifecycle Phases

The phases below are narrative coordination stages, not a new enum or persisted
state. Every phase is derivable from the resources and events already defined.

| Phase | Lease holder | Fence holder | Allowed work | A second admission | A duplicate or late delivery |
|---|---|---|---|---|---|
| candidate | none | none | input validation only | may admit | nothing |
| admitted | the new task ID | the API request | task-ID preallocation, lease acquisition | rejected (fence or lease held) | not delivered yet |
| publication attempted | the admitted task ID | none (released) | broker publication only | rejected (lease held) | not delivered yet |
| submitted | the admitted task ID | none | waiting for delivery | rejected (lease held) | one delivery adopts; a duplicate is rejected at adoption |
| acceptance_unconfirmed | the admitted task ID | none | nothing until delivery or TTL | rejected (lease held) | if delivered, one delivery adopts; otherwise the lease expires |
| delivered | the admitted task ID | none until adoption | task-ID and target validation only | rejected (lease held) | rejected at adoption if a newer owner replaced it |
| fenced and adopted | the exact task ID | the task workflow | begin the first unit after the stale check | rejected (fence or lease held) | rejected at adoption |
| active | the exact task ID, renewed | the task workflow | per-CVE units, checkpoints, cleanup | rejected | no second unit starts |
| terminal cleanup | owner-safe removal pending | the task workflow until explicit release | close the current unit session, compare-and-delete, release fence, terminal event | rejected until fence release and lease removal complete | mutates nothing |

### Renewal Checkpoints

The runner integrates renewal with its safe checkpoints:

- It performs one confirm-and-renew as part of adoption before the watermark.
- Before a new unit, when at least 60 seconds have elapsed since the last
  successful renewal, it performs one compare-and-renew.
- It performs no Redis or broker command during a per-CVE transaction or while
  a CVE/Ticket row lock is held.
- A unit already started runs to its commit or rollback regardless of renewal
  state; renewal is evaluated only between units.
- A renewal that fails or is uncertain blocks the next unit. The delivery then
  closes the current unit session, attempts owner-safe lease removal while the
  fence is still held, releases the fence, emits the terminal
  `ownership_lost` event, and terminates. It never reclassifies a committed
  unit, and the failed renewal is not a per-CVE failure.
- Counters and the terminal event include only units already classified at the
  commit boundary.

### Ownership Loss

Ownership can be lost only after successful adoption has started the run
workflow. It occurs when a later checkpoint can no longer prove that the exact
token owns the lease: compare-and-renew returns `mismatch` or `absent`, raises
`RedisError`, or has uncertain completion. It terminates the whole run as
`ownership_lost`. The initial confirm-and-renew cannot produce ownership loss;
its failures are adoption rejections. Ownership loss is never an isolated
per-CVE failure and never rolls back or reclassifies a committed unit. After
the current unit session is closed, the delivery attempts owner-safe
compare-and-delete while still holding the fence, then releases the fence; if a
newer owner already replaced the lease, compare-and-delete is a `mismatch`
no-op.

A terminal `cvss_recalculation_ownership_lost` event uses failure phase
`control`; its sanitized category is `infrastructure` for a Redis failure and
for uncertain Redis-command completion, and `interrupted` for an ownership
mismatch or absence.

### Timeout and Cancellation

- The task configures no Celery `soft_time_limit`, no `time_limit`, and no
  automatic retry, and it never calls `self.retry()`. The 900-second lease TTL
  is a coordination backstop, not a task-execution limit.
- Cancellation and worker shutdown propagate unchanged. When observed between
  units, they prevent the next unit; when observed before a unit's commit, that
  unit rolls back; when observed after a unit's commit, the committed unit keeps
  its classification and is not reclassified.
- A hard kill, an OOM kill, or process disappearance may produce no terminal
  event, no lease removal, and no fence release beyond the automatic release
  from connection closure.
- A process that is alive but wedged can retain the fence indefinitely. This
  deliberately favors safety over availability. The operator MUST terminate the
  worker or pod before attempting a rerun.

### Publication Uncertainty

The publisher boundary begins only after confirmed fence release. Publication
classification uses the exception class only, never the exception text,
matching `docs/features/tickets/ticket-service.md` (Ticket Convergence):

| Observable phase and outcome | Cause | Coordination state | API response |
|---|---|---|---|
| pre-publisher setting, database, commit, or fence failure | the publisher was not invoked | attempt owner-safe lease removal where this request acquired it, then propagate the original error | ordinary error mapping; normally global `500 INTERNAL_ERROR` |
| `submitted` | the publication call returned without raising | lease retained; the task adopts on delivery | `202 Accepted` |
| `acceptance_unconfirmed` | the publication call raised `kombu.exceptions.OperationalError` | lease retained; acceptance is neither confirmed nor denied | `503 CELERY_UNAVAILABLE` with fixed sanitized detail |
| other publisher exception | the publication call raised any other exception, including serialization, configuration, security, control signals, and programming errors | the exception propagates unchanged and is never `acceptance_unconfirmed`; the lease is retained conservatively | propagated exception mapping; normally global `500 INTERNAL_ERROR` |
| crash before publisher invocation | the API process died after lease acquisition | lease retained because completion and cleanup cannot be observed safely; the publisher was not invoked | not observed by the API |
| crash after publisher invocation and before response | the API process died after invoking the publisher | lease retained; acceptance is unknown and the task may still be delivered and adopt it | not observed by the API |

For the manual trigger:

- `submitted` returns `202 Accepted`;
- `acceptance_unconfirmed` returns `503 CELERY_UNAVAILABLE` with the fixed
  sanitized detail `"Recalculation task publication could not be confirmed"`,
  and the lease is retained rather than released;
- the response never asserts that the broker rejected the task; a task that was
  actually accepted may still run and adopt the lease; and
- if the task was not accepted, the lease expires by its TTL, and the operation
  becomes retryable without any manual key deletion. An error before publisher
  invocation propagates as that original error after owner-safe cleanup is
  attempted; it is never mapped to `CELERY_UNAVAILABLE`.

The setting mutation in `docs/features/platform/system-settings.md` never
reaches this publisher boundary: it acquires no lease, invokes no publisher,
and its response never reports a publication or scheduling outcome.

No coordination outcome creates a `SettingAuditEvent` or `TicketAuditEvent`.

### Cleanup and Recovery Matrix

**Compare-and-delete** below means the owner-safe compare-and-delete of this
delivery's exact token. "Release fence" is explicit unless the connection is
already gone, in which case closure releases it automatically. A rerun always
restarts from the beginning.

Every interceptable terminal run path uses one cleanup order: close the current
per-CVE session and transaction; attempt compare-and-delete while the fence is
still held; release the fence; then emit the terminal event. A Redis cleanup
failure does not prevent fence release. This ordering prevents a delivery from
adopting the same token between fence release and lease deletion and ensures a
new admission first observes either the held fence or the already-removed
lease.

| Scenario | Compare-and-delete | Release fence | Terminal event | TTL wait | Operator intervention | Rerun |
|---|---|---|---|---|---|---|
| completed | yes | yes | `cvss_recalculation_completed` | no | none | optional; idempotent |
| partial | yes | yes | `cvss_recalculation_partial` | no | none | optional; idempotent |
| stale | yes | yes | `cvss_recalculation_stale` | no | none | optional |
| cancelled | yes, when interceptable | yes | `cvss_recalculation_cancelled` | no | none | yes, from the beginning |
| ownership lost | yes; `mismatch` is a no-op | yes | `cvss_recalculation_ownership_lost` | no | only if a foreign fence is wedged | yes, from the beginning |
| renewal failure | yes; classified as ownership loss | yes | `cvss_recalculation_ownership_lost` | no | only if a foreign fence is wedged | yes, from the beginning |
| whole-run failure | yes | yes | `cvss_recalculation_failed` | no | none | yes, from the beginning |
| adoption rejected | no; no ownership was confirmed | yes if this delivery acquired it | only `cvss_recalculation_adoption_rejected`, not a terminal run event | yes when the admitted lease remains | none required; wait or inspect | yes, after TTL or owner-safe removal |
| cleanup Redis failure | attempted; failure changes nothing | yes | unchanged terminal outcome | yes, up to 900 seconds | none required; wait or inspect | yes, after TTL |
| publication uncertainty | no | already released | none from the runner | yes, up to 900 seconds if not delivered | wait for delivery or TTL | yes, after resolution |
| Redis restart | attempted after restart; may fail | yes | `cvss_recalculation_ownership_lost` when active | yes | none required | yes, from the beginning |
| hard kill | no | automatic on connection closure | none | yes | confirm the process is dead | yes, after TTL |
| OOM kill | no | automatic on connection closure | none | yes | confirm the process is dead | yes, after TTL |
| worker disappearance | no | automatic on connection closure | none | yes | confirm the worker is gone | yes, after TTL |
| fenced connection loss | attempted on the Redis client | automatic on connection closure | `cvss_recalculation_failed` | yes | none required | yes, from the beginning |

A cleanup failure never changes committed state, a unit classification, or a
terminal outcome. The operator recovery procedure is authoritative in
`docs/deployment.md` (CVSS Recalculation Recovery).

### Coordination Logging

Coordination emits bounded feature-owned events through the shared logging
contract in `docs/features/platform/logging.md`. They correlate through the
existing `request_id` (API paths) and `celery_task_id` (task paths). They create
no audit event and are never authoritative state. The
`task_id_invalid` adoption-rejection event omits `celery_task_id` when no
canonical ID is available and never includes the raw malformed value in the
feature event.

| Event | Level | When |
|---|---|---|
| `cvss_recalculation_admitted` | INFO | The manual trigger admitted a run: fence acquired, task ID preallocated, lease acquired |
| `cvss_recalculation_admission_rejected` | WARNING | The manual trigger could not acquire the fence or the lease, or Redis failed during acquisition; carries the closed `reason` category `fence_busy`, `lease_held`, or `redis_error` |
| `cvss_recalculation_submitted` | INFO | The publication call returned without raising |
| `cvss_recalculation_publication_unconfirmed` | ERROR | The publication call raised a broker operational error; the lease is retained |
| `cvss_recalculation_adopted` | INFO | A task acquired the fence and confirmed exact owner/target before its first unit |
| `cvss_recalculation_adoption_rejected` | WARNING | Before the run workflow starts, the wrapper or task could not validate the task ID, acquire the fence, or confirm exact owner/target; carries the closed `reason` category `task_id_invalid`, `fence_busy`, `lease_absent`, `lease_mismatch`, or `redis_error` |
| `cvss_recalculation_renewal_failed` | WARNING | A checkpoint compare-and-renew returned `mismatch` or `absent`, raised `RedisError`, or was uncertain; the next unit is blocked |
| `cvss_recalculation_cleanup_failed` | WARNING | Owner-safe compare-and-delete or explicit fence release failed or was uncertain |

The terminal event table above owns `cvss_recalculation_ownership_lost` and the
other terminal outcomes. A `cvss_recalculation_admission_rejected` that repeats
while no active runner updates its lease is the recovery-required signal
described under Operator Recovery. No coordination event carries the full lease
token, a Redis command text, raw exception text, a database payload, or an
unbounded list.

### Operator Recovery

Operator recovery for a stuck, crashed, or uncertain run is a complete rerun
through the manual endpoint. The normative procedure is defined in
`docs/deployment.md` (CVSS Recalculation Recovery): identify the worker or pod,
terminate it if it is alive and wedged, wait for or owner-safely remove the
lease without unconditional deletion, retry the trigger, and let the run restart
from the beginning. No recovery procedure may treat logs, a missing Redis key,
or the absence of a terminal event as proof of completion.

The manual endpoint is also the only recovery surface for a setting change that
has not yet converged derived state: a successful PATCH records the new policy
but starts no work, so after any superseded delivery terminates `stale` or any
retained lease is resolved, the operator triggers a complete rerun. Repeating
the same PATCH never starts, resumes, or repairs a run.

## Cross-references

- `docs/features/platform/system-settings.md` - setting declaration,
  persistence, bootstrap, required-row read, setting mutation and audit, and
  the transaction-level exclusion boundary
- `docs/features/tickets/cvss-scoring.md` - pure severity and eligibility
  resolutions
- `docs/features/tickets/ticket-mutations.md` - authoritative default-version
  state matrix, single-CVE classifications, and transaction-local Ticket
  convergence registration lifecycle
- `docs/features/tickets/ticket-service.md` - Ticket convergence publication
  vocabulary, automatic owner policy, and recovery
- `docs/features/tickets/tickets.md` - Analyzed and Resolved gate predicates and
  explicit Ticket convergence rerun
- `docs/features/tickets/ticket-audit-log.md` - events created by committed
  runner units
- `docs/features/packages/package-model.md` - automatic eligibility evaluator
  and manual override precedence
- `docs/features/platform/logging.md` - structured log records, levels,
  correlation, and sanitization
- `docs/features/platform/testing-strategy.md` - preview, runner, and Ticket
  convergence publication tests
- `docs/features/identity/rbac.md` - capability definitions and endpoint map
- `docs/api-spec.md` - envelopes, error codes, validation, and API conventions
- `docs/deployment.md` - Redis durability and `noeviction`, and the
  complete-run operator recovery procedure
- `docs/conventions.md` - sync-to-async bridging, pooled-engine lifecycle,
  transactions, locking, Redis, and specification conventions
