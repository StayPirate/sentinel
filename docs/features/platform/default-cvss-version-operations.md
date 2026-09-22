# Default-CVSS Version Operations

## Purpose

Define the administrative operations that preview and apply a change to the
system-wide `default_cvss_version` policy. This specification owns the
read-only impact preview, the all-CVE recalculation runner, the manual
recalculation operation, aggregate observability, and restart and recovery
behavior.

`docs/features/platform/system-settings.md` remains authoritative for the
setting declaration, persistence, bootstrap, required-row reads, setting audit,
and the immediate `GET` and `PATCH /api/v1/admin/settings` composition. The
specialized operations here consume that setting contract without becoming a
second owner of it.

## Scope and Ownership

This specification owns:

- `get_default_cvss_version_impact()` and its API endpoint;
- `recalculate_cvss_derived_state(target_version)` and its complete bounded
  runner;
- the manual all-CVE recalculation endpoint;
- runner logging, retry, rerun, restart, and recovery behavior;
- the absence of persistent run and progress state; and
- the boundary within which complete-run coordination may be added.

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
policy to every persisted CVE. `PATCH /api/v1/admin/settings` and
`POST /api/v1/admin/settings/default-cvss-version/recalculate` enqueue it. It is
not a fetcher, sub-operation, or scheduled integration.

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
one independent session per unit, owns their commits and rollbacks, and
maintains one fixed-size in-memory aggregate used only for the run's structured
logs. Its
run metadata is `target_version`, the captured watermark (absent for a stale
delivery), and the terminal outcome token. Its counters are exactly `changed`,
`unchanged`, `skipped`, `failed`, and the derived `succeeded` and `processed`.
It contains no other counter, no publication result, no CVE, Ticket, package,
Product, or occurrence identifier, and no per-CVE detail collection. The
workflow emits the run's events from that aggregate, discards it, and returns
`None`; the wrapper therefore receives no task result. The aggregate is never
persisted and never published to a result backend.

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

Complete-run admission, ownership, lease renewal, execution fencing, prevention
of a setting change or another owner overtaking an admitted run, and crash
cleanup are not defined by this contract. Any such coordination must preserve
the validation, paging, unit, drain, and outcome semantics defined here; an
ownership-loss termination is a whole-run condition and never an ordinary
failed unit. The coordination contract owns the ownership-loss signal's type
and detection point.

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
- an invalid task payload;
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
operation.

The endpoint uses the same immediate admission and publication logic as the
`PATCH /api/v1/admin/settings` side effect:

1. Read the current `default_cvss_version` through the required-row read
   service.
2. Acquire the recalculation slot (`SET cvss_recalc_active <timestamp> NX EX
   900`) as the endpoint's immediate admission guard. The slot is not the
   complete-run coordination mechanism described below.
3. Enqueue `recalculate_cvss_derived_state(target_version)`. On publication
   failure, release the slot and return `503 CELERY_UNAVAILABLE`.
4. Return `202 Accepted` after the publication call returns without raising.

No setting change is made and no `SettingAuditEvent` is created.

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
| 409 | `CVSS_RECALC_ALREADY_IN_PROGRESS` | The recalculation admission slot is already held |
| 503 | `REDIS_UNAVAILABLE` | Redis rejected or could not complete slot acquisition |
| 503 | `CELERY_UNAVAILABLE` | The task could not be enqueued; the slot is released |

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

## Absence of Persistent Run State

The preview and runner introduce:

- no `FetcherRun` record;
- no Celery result-backend entry and no persisted task result;
- no run, progress, resume, or cursor table, column, or resource;
- no persisted high-water mark, offset, or continuation token;
- no metric or log used as authoritative state;
- no generic batch, backfill, or reusable runner framework;
- no new audit event type; the unit's ordinary domain audit events remain the
  only durable audit records; and
- no new configuration variable or setting.

The normative restart and recovery behavior is defined in Retry, Rerun, and
Recovery above.

## Complete-Run Coordination Boundary

The fixed 900-second endpoint slot is only an immediate Redis liveness probe and
admission guard. This specification does not yet define complete-run admission,
ownership, lease renewal, execution fencing, Redis-loss behavior, prevention of
a setting change or another owner overtaking an admitted run, or crash cleanup.

Any complete-run coordination added at this boundary must preserve the existing
validation, stale-delivery, bounded paging, independent-unit, post-commit,
outcome, restart, and no-persistent-state contracts. It must not turn an
ownership-loss signal into an isolated per-CVE failure or make Redis an
authoritative source of progress or completion.

## Cross-references

- `docs/features/platform/system-settings.md` - setting declaration,
  persistence, bootstrap, required-row read, setting audit, and immediate
  Settings PATCH composition
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
- `docs/conventions.md` - sync-to-async bridging, pooled-engine lifecycle,
  transactions, locking, Redis, and specification conventions
