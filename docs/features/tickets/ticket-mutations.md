# Ticket Mutations Service

## Purpose

Centralize ticket-centric operations that modify data relevant to ticket
status gates — CVSS assessment management, manual severity, and
manual-zone exits — in a single service module (`ticket_mutations`).
This module also provides the shared `reconcile_ticket_status()` function
and the `auto_assign_actor()` helper, which are called by both this
module and `package_service`.

Package-centric mutations (track status, delivery status, product eligibility,
soft-deletion/restore, record creation, and additive maintainer association) are
handled by `package_service` (`docs/features/packages/package-service.md`).
CVSS mutation functions maintain CVE-owned assessment and severity state and
return the deterministic eligibility result and propagation disposition needed
by that package-owned boundary; they do not modify Product eligibility.

Without this centralization, each gate-relevant caller would need to
independently:

- Acquire the correct row-level lock
- Apply the data mutation
- Call `reconcile_ticket_status`
- Create the correct `TicketAuditEvent`

Leading to inconsistency, missed re-evaluations, and bugs.

## Architecture

### Module location

`backend/app/services/ticket_mutations.py`

### Async pattern

The service is implemented as async functions. Async entry points, including
FastAPI and the IBS RabbitMQ consumer, call the service directly with `await`.
Synchronous Celery task wrappers establish one outer `asyncio.run()` boundary
for their complete async workflow; they do not create a bridge for each service
call.

| Entry point               | Invocation pattern                                              |
|---------------------------|-----------------------------------------------------------------|
| API endpoint              | `await ticket_mutations.set_severity_manual(session, ...)`    |
| Celery workflow           | `await ticket_mutations.reconcile_ticket_status(session, ...)` inside its one async workflow |
| IBS RabbitMQ consumer workflow | `await ticket_mutations.reconcile_ticket_status(session, ...)` inside the package-service call chain |

### Transaction ownership

The module does NOT commit or roll back. All operations execute within
the caller's database session. Commit responsibility belongs to the
caller.

This matches the `user_service` pattern — the module applies mutations
and creates audit events, but the transaction boundary is the caller's
decision. This enables callers to compose multiple operations within a
single transaction when needed (e.g., `revert_duplicate` clears
`duplicate_of_id` then calls `_reenter_gate_zone`).

### Acting user convention

All operations accept an `acting_user_id: UUID | None` parameter:

- `UUID` — action performed by an authenticated user (enables
  auto-assignment on unassigned tickets if the user holds the
  `vulnerability_analyst` role)
- `None` — system action (release detection, CVSS sync, product
  lifecycle transitions). Auto-assignment does not apply

**API handler rule**: API endpoint handlers MUST always pass the UUID of
the authenticated user as `acting_user_id`. Passing `None` from an API
handler is a bug — it would silently bypass auto-assignment. `None` is
reserved exclusively for system entry points.

#### Authorization responsibility

The module does NOT perform capability checks — this is by design.
API-layer callers MUST apply the appropriate `require_capability()`
dependency before invoking any module function; the module trusts that
the caller has already verified the user's permissions. System callers
(fetchers, Celery tasks) use `acting_user_id=None` and operate as
trusted internal processes — capability checks do not apply to them.
Adding a new caller that passes a non-None `acting_user_id` without
having verified the corresponding capability is a security bug.

CVSS assessment mutations additionally require an explicit typed caller
category. `CVSSMutationCaller.MANUAL_SUSE` identifies an authorized consumer
operation on the internal SUSE assessment, and
`CVSSMutationCaller.TRUSTED_EXTERNAL_INGESTION` identifies a trusted
source-ingestion operation on a non-SUSE assessment. Caller authority is never
inferred from whether `acting_user_id` is `NULL`.

### Relationship with other modules

| Module | Relationship |
|--------|-------------|
| `services/cvss.py` | `ticket_mutations` delegates CVSS resolution and severity calculation to pure functions in `cvss.py`. The resolution cascade logic is never reimplemented inside `ticket_mutations` |
| `services/package_service.py` | Handles all package-centric mutations (track status, delivery status, product eligibility, soft-delete/restore, record creation) and package queries. CVSS mutation results provide a deterministic eligibility result and propagation disposition for this owner to consume. `package_service` imports `reconcile_ticket_status()`, `auto_assign_actor()`, and `ensure_ticket_operable()` from `ticket_mutations`; `ticket_mutations` does not mutate package records |
| `services/ticket_service.py` | Handles non-gate operations (assignment, CVE association, mark-as-duplicate, set-confidentiality, access grants). See [ticket-service.md](ticket-service.md) for the full contract. These operations use the same FOR UPDATE pattern and import `ensure_ticket_operable()` from `ticket_mutations` |

## State Machine Zones

The ticket state machine has two zones that determine which operations
are valid:

### Gate zone (Analysis, Analyzed, Resolved)

Status is determined automatically by `reconcile_ticket_status` based on gate
conditions. Consumer-facing `ticket_mutations` operations act on Tickets in
this zone, with the documented manual-zone exit exceptions. Trusted external
CVSS ingestion is CVE-owned maintenance and follows the separate status matrix
below.

`New` is a pre-state, not part of the gate zone. A ticket in `New` status
has never been claimed by a VA. The `New → Analysis` transition is an
explicit one-way event triggered by assignment, not a gate evaluation.
`reconcile_ticket_status` skips tickets in `New` status entirely — the
floor of the gate zone is `Analysis`.

### Manual zone (Ignored, Duplicated)

Status is set by explicit user actions or specific system events.
`reconcile_ticket_status` never operates on tickets in the manual zone.
Gate-relevant mutations are blocked at the service layer by
`ensure_ticket_operable()` (raises `TicketNotMutableError` → 409
`TICKET_NOT_MUTABLE`).

### `_reenter_gate_zone()` (private helper)

To exit the manual zone, an explicit operation must call the private
helper `_reenter_gate_zone()`:

1. Saves the ticket's current status (Ignored or Duplicated) as
   `original_status`
2. Sets `status = Analysis` (floor of the gate zone)
3. Calls `reconcile_ticket_status(previous_status=original_status)`

This produces a single `TicketAuditEvent` with the real transition
(e.g., `old_value = Ignored, new_value = Analysis`). If the Analyzed
or Resolved gates are already satisfied, `reconcile_ticket_status`
promotes the ticket further in the same call and the audit event
reflects the final target (e.g., `old_value = Ignored,
new_value = Analyzed`).

The post-transition catch-up is initiated internally by
`reconcile_ticket_status()` step 4 when it detects the inactive-state exit.
The function registers the package-tree and fetcher recovery workflow for
post-commit execution. It does not recalculate CVE-owned severity while holding
the Ticket lock. No action is needed by the calling function or endpoint
handler.

Only the two manual-zone exit functions (`reopen_from_ignored`,
`revert_duplicate`) call this helper. It is never called directly by
external code.

## `reconcile_ticket_status()`

The sole authority for reconciling a ticket's status and assignment
state with current reality. This is a shared service-internal primitive, not an
API, CLI, task, or consumer operation. Owning mutation services call it only
after their effective gate-relevant mutations while already holding the Ticket
lock. Entry points never invoke it directly.

**Purpose**: Reconciles the ticket's status and assignment state with
current reality (gate conditions + data freshness).

**Side effects** (documented, intentional):

- May transition ticket status (forward or backward) based on gate
  evaluation
- May null `assignee_id` and create an `assignment` audit event if the
  current assignee is inactive (inactive assignee sanitization)
- May register the package-tree and fetcher catch-up workflow for post-commit
  execution when an inactive → active transition is detected

Callers must be aware that invoking this function may produce mutations
beyond status changes.

### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `ticket` | `Ticket` | Yes | The ticket instance (already loaded with FOR UPDATE by the caller) |
| `db` | `AsyncSession` | Yes | Database session |
| `previous_status` | `TicketStatus \| None` | No | If provided, used as `old_value` in the audit event instead of the ticket's current status field. Enables recording the real semantic transition (e.g., `Ignored → Analysis`) when the status has been set to an intermediate value |
| `evaluation_date` | `date \| None` | No | UTC date used for lifecycle and actionability predicates. If omitted, capture the current UTC date once at function entry |

### Behavior (top-down evaluation)

1. Guard clause: if `ticket.status == New`, return immediately. `New` is
   a pre-state outside the gate zone — the `New → Analysis` transition is
   handled explicitly by assignment code paths (`auto_assign_actor` and
   `assign_ticket`), never by this function. Before returning, if
   `ticket.assignee_id IS NOT NULL`, emit a warning-level log:
   `"Ticket {ticket_id} in New status with assignee {assignee_id} —
   assignment code path bug: assignee was set without transitioning
   status to Analysis"`.
2. Resolve one `evaluation_date` and evaluate gate conditions from highest to
   lowest using the canonical actionability expressions from
   `package-model.md` (two active tiers;
   `Analysis` is the unconditional floor, not a gate-evaluated tier):
   - If all "Resolved" gates are met (every actionable track is
     resolution-complete — see `tickets.md`, "Gate: Analyzed → Resolved")
     AND all "Analyzed" gates are met → status is Resolved
   - If all "Analyzed" gates are met (but "Resolved" gates are not) →
     status is Analyzed
   - Otherwise → status is Analysis (unconditional floor; this function
     never produces `New`)
3. If the determined status differs from the current status, or if
   `previous_status` is provided and differs from the determined status:
   - Update `ticket.status`
   - Create `TicketAuditEvent` with `event_type = status_change`
   - `old_value` is taken from `previous_status` if provided; otherwise
     from the ticket's current status field
4. **Post-transition catch-up** (inactive-state exit detection):
   - Resolve `effective_previous`: use `previous_status` parameter if
     provided (reactivation cases via `_reenter_gate_zone()`), otherwise
     capture the ticket's status before gate evaluation as a local
     variable at the start of the function (regression cases)
   - Resolve `new_status`: the status determined by step 2 (regardless of
     whether step 3 produced a change — see note below)
    - If `effective_previous ∈ {Resolved, Ignored, Duplicated}` AND
      `new_status ≠ effective_previous`, register one post-commit reactivation
      workflow. Its package-domain phase first re-resolves every persisted
      package marker, including soft-deleted markers, through
      `package_service`; after those per-package transactions finish, it
      enqueues `catch_up()` for every registered fetcher via
      `get_catch_up_fetchers()`. Registration does not introduce a
      `ticket_mutations` → `package_service` import: the post-commit workflow
      owner performs that orchestration. The workflow and failure isolation
      contract are defined in `package-service.md` (Package-tree reactivation
      workflow) and `package-model.md` (Reactivation and Convergence)
   - **Note**: step 4 is independent of step 3. In the
     `_reenter_gate_zone()` case, the caller has already set the status
     before invoking reconcile; step 3 sees no change but step 4
     correctly detects the inactive-state exit via `previous_status`.
      Post-commit workflow registration follows the inactive-state exit check;
      it does not re-check Ticket status after registration
   - **Registration deduplication**: recursive reconciliation within the same
     caller-owned transaction registers at most one reactivation workflow for
     the Ticket. Duplicate workflows across separate transactions remain safe
     because package resolution and all catch-ups are idempotent.
   - `reconcile_ticket_status()` never acquires or re-acquires a CVE lock. CVSS
     assessment mutations already maintain `CVE.severity`; package-domain
     reactivation owns eligibility convergence from persisted current inputs.
     Keeping this Ticket-locked primitive free of CVE acquisition prevents a
     `Ticket` then `CVE` inversion against the global CVSS lock order.
   - **Cost in the common case**: zero. When no inactive → active
     transition occurs (the overwhelmingly common path), step 4 is a
     single enum comparison
5. The function operates within the same database transaction as the
   triggering operation (atomicity guarantee)

Every query performed by one invocation, including aggregate and existence
checks, uses the same resolved `evaluation_date`. The function never persists
the lifecycle phase or actionability result.

### Inactive Assignee Sanitization

After determining the ticket's "natural" status via gate evaluation, if
the resulting status is active (Analysis or Analyzed) and
`assignee_id` points to an inactive user:

1. Set `assignee_id = NULL`
2. Create `TicketAuditEvent` with `event_type = assignment`
   (system-initiated, `user_id = NULL`,
   `comment = "Unassigned from {username}: employee deactivated"`)
3. Emit a warning-level log: `"Inactive assignee {user_id} detected on
   ticket {ticket_id} during reconciliation — this should have been
   handled by _unassign_active_tickets"`

If the resulting status is inactive (Resolved, Ignored, Duplicated): no
assignee check is performed — an inactive ticket does not need an
active assignee.

This mechanism complements the bulk unassignment performed by
`deactivate_user` (see
[user-service.md](../identity/user-service.md#deactivate_user)) by
catching any tickets that were missed or that entered the gate zone
after the deactivation event. Unassignment does not change the ticket's
status — the ticket remains in its current gate-zone status.

> **Invariant**: ticket status reflects work state, not staffing state.
> A ticket in `Analysis`, `Analyzed`, or `Resolved` status may have
> `assignee_id = NULL` (an orphaned ticket awaiting reassignment).
> See the Architectural Invariant in
> `docs/features/tickets/tickets.md`.

### `previous_status` parameter

The `previous_status` parameter exists to handle manual-zone exit
operations correctly. When `_reenter_gate_zone()` sets `status = Analysis`
before calling `reconcile_ticket_status`, if the function then promotes
the ticket further (to `Analyzed` or `Resolved`), the audit event must
record the real transition origin (e.g., `old_value = Ignored`) rather
than the intermediate `Analysis` value. Passing
`previous_status = Ignored` records the correct semantic transition
(e.g., `Ignored → Analyzed` rather than `Analysis → Analyzed`).

### Multiple invocations within a transaction

`reconcile_ticket_status` is idempotent and may be called multiple times in a
composed transaction. Each call evaluates the Ticket's current data using one
UTC evaluation date captured for that invocation or supplied by the owning
workflow. Package exclusion and restore operations call it once after their
single direct mutation and reuse that supplied date for result and response
projection; derived actionability never creates an intermediate package-tree
mutation chain.

## Concurrency Control

The generic pessimistic locking pattern and transaction hygiene rules
are defined in `docs/conventions.md` (Transaction and Locking). This
section documents ticket-specific refinements only.

### Extension to non-module operations

Every operation that modifies the `Ticket` row (any column: `status`,
`assignee_id`, `cve_id`, `duplicate_of_id`, `is_confidential`)
or that calls `reconcile_ticket_status` MUST acquire
`FOR UPDATE` on the Ticket row before any modification — not just
module functions. This prevents non-gate operations (assignment,
duplicate set/revert, ignore)
from racing with gate operations on the same ticket.

### Single-ticket scope

`ticket_mutations` functions operate on a single ticket per
transaction.

**Exception — `mark_as_duplicate` (in `ticket_service`)**: this
operation acquires `FOR UPDATE` on the source ticket, the target
ticket, and all current dependents of the source ticket in a
single transaction. Source and target are locked with blocking
waits in deterministic UUID order. Dependents are locked with
`FOR UPDATE NOWAIT` — if any dependent is currently locked by
another transaction, the operation aborts immediately
(`DuplicateConcurrentModificationError`) rather than waiting.
This two-phase protocol prevents deadlocks: Phase 1 (roots)
cannot form cycles due to UUID ordering; Phase 2 (dependents)
never waits, so it cannot participate in a wait cycle.

All other operations retain the single-ticket-scope rule and
blocking waits unchanged.

### Blocking wait

The default PostgreSQL behavior (blocking wait) is used. `NOWAIT` is
intentionally not specified — the transaction hygiene rules ensure
locks are held for milliseconds, making spurious failures from `NOWAIT`
more harmful than brief waits.

Exception: `mark_as_duplicate` Phase 2 uses `FOR UPDATE NOWAIT`
on dependent rows. See Single-ticket scope above.

### Ticket-not-found handling

If the `SELECT FOR UPDATE` returns no row (ticket does not exist,
invalid ID, or stale reference from a queue message), the function MUST
raise a domain-specific exception (`TicketNotFoundError`). It MUST NOT
proceed silently or operate on `None`. Callers handle the exception as
appropriate: background tasks log and skip; API endpoints return 404.

### `reconcile_ticket_status` does not acquire the lock

The function assumes the caller has already acquired `FOR UPDATE` on the
ticket. This is always the case because every caller — both within
`ticket_mutations` and in external modules (`package_service`,
`ticket_service`) — acquires `FOR UPDATE` on the Ticket before calling
`reconcile_ticket_status()`. A workflow that also owns a CVE lock acquires it
first under the global `CVE` then `Ticket` order.

## `ensure_ticket_operable()`

A shared guard function that rejects mutations on non-operable tickets.
Called after acquiring `FOR UPDATE` on the ticket row by all mutation
functions in `ticket_mutations`, `ticket_service`, and `package_service`
— except for explicit opt-outs documented per function.

**Signature**:

```python
def ensure_ticket_operable(ticket: Ticket) -> None:
    """Reject mutations on manual-zone inactive tickets.

    Call after acquiring FOR UPDATE on the ticket row.
    Raises TicketNotMutableError if status is Ignored or Duplicated.
    """
```

**Behavior**:

1. If `ticket.status ∈ {Ignored, Duplicated}` → raise
   `TicketNotMutableError`

This function performs no database operations. It validates invariants
on an already-loaded `Ticket` object. The caller is responsible for
loading the ticket with `SELECT ... FOR UPDATE` before invoking this
function.

**Opt-out cases**:

- `reopen_from_ignored` — must operate on Ignored tickets; skips
  mutability guard
- `revert_duplicate` — must operate on Duplicated tickets; skips
  mutability guard
- Trusted external CVSS ingestion — maintains source-owned CVE assessment and
  severity state in every Ticket status and follows the propagation
  disposition defined by the CVSS status matrix

**Consumers**:

| Module | Functions that call `ensure_ticket_operable` |
|--------|----------------------------------------------|
| `ticket_mutations` | Manual-SUSE `upsert_cvss_assessment`, `delete_cvss_assessment`, `set_severity_manual` |
| `ticket_service` | `associate_cve`, `assign_ticket`, `ignore_ticket`, `mark_as_duplicate`, `set_confidentiality`, `grant_access`, `revoke_access` |
| `package_service` | Gate-relevant mutations call the guard; `set_track_delivery_status` also calls it for operability but remains outside assignment, audit, and Ticket reconciliation |

Trusted external ingestion does not call this guard. It may maintain
CVE-owned assessment and severity state in every Ticket status but must obey
the propagation disposition returned by the mutation.

## Gate-Relevant Mutation Operations

Each ticket-mutation function below follows the same pattern unless its own
contract places semantic no-op or operation-specific guards before assignment:

1. Acquire `FOR UPDATE` on the owning root row
2. Call `ensure_ticket_operable(ticket)`
3. Call `auto_assign_actor()`
4. Validate additional preconditions
5. Apply the mutation
6. Create `TicketAuditEvent`
7. Call `reconcile_ticket_status()`
8. Return the updated record

Package-centric gate-relevant mutations (`set_track_status`,
`set_product_eligibility`, `set_product_released_at`,
`add_package_records`, soft-delete/restore for packages, tracks, and
products) have been moved to `package_service` — see
`docs/features/packages/package-service.md`.

Package exclusion and restoration specifically validate their direct marker
before `auto_assign_actor()` and call `reconcile_ticket_status()` exactly once
only after an effective direct mutation. They pass the UTC `evaluation_date`
chosen by the owning package workflow so gate evaluation and the mutation
response use the same temporal boundary. EOL or another derived actionability
change never creates an exclusion/restoration mutation chain.

`set_track_delivery_status()` is package-owned but is intentionally absent from
this gate-relevant pattern: delivery is not a Ticket gate input, and that
operation performs no assignment, Ticket reconciliation, or Ticket audit
event.

### CVSS Vector Parsing

The `cvss` Python library (PyPI: `cvss`, maintained by Red Hat Product
Security) is used for vector parsing, version detection, and score
computation. See
[Accepted Base Vectors](cvss-scoring.md#accepted-base-vectors) for the
system-wide ingestion rule that governs how scores and versions are handled.

Parsing and caller/provider validation use request input only and may run before
the transaction's first database operation. For a CVSS assessment mutation,
the first persistent read is always `SELECT ... FOR UPDATE` on the owning CVE.
If that CVE has an associated Ticket, the function then acquires
`SELECT ... FOR UPDATE` on the Ticket. Every operation that can participate in
both roots follows this global `CVE` then `Ticket` order.

### CVSS Mutation Authority and Result

The reserved provider comparison is `provider.strip().casefold() == "suse"`.
Every equivalent case or surrounding-whitespace form is reserved. The only
stored internal provider value is the canonical string `SUSE`.

| Caller category | Provider authority | Delete authority | Actor |
|---|---|---|---|
| `MANUAL_SUSE` | May create or update only the reserved SUSE assessment; the stored provider is canonicalized to `SUSE` | May delete only `SUSE` | `acting_user_id` is required and identifies the authorized user |
| `TRUSTED_EXTERNAL_INGESTION` | May create or update only a non-reserved provider supplied by its owning ingestion contract | None; upstream omission retains the last persisted assessment | System (`acting_user_id` must be `NULL`) |

A caller/provider or caller/actor mismatch is an internal contract violation:
it raises `ValueError` before persistent state is read and returns no mutation
result. It has no audit event or other side effect. Source-specific
normalization of non-reserved provider names remains with each ingestion
contract.

Both mutation functions communicate one transaction-local
`CVSSAssessmentMutationResult`, or an equivalent typed structure, containing:

| Field | Contract |
|---|---|
| `assessment` | The locked-current persisted assessment after create/update/unchanged, the deleted assessment snapshot after delete, or `NULL` for not found |
| `action` | Exactly `created`, `updated`, `unchanged`, `deleted`, or `not_found`, determined after both roots are locked |
| `severity_resolution` | The committed-current Severity Resolution result, including score, version, provider, and unified label, or the explicit absent result |
| `eligibility_resolution` | The committed-current Eligibility Score Resolution result: score plus `suse` or `fallback`; this is a handoff value and does not authorize Product mutation in this module |
| `propagation` | `immediate`, `deferred_until_reactivation`, `not_applicable`, or `none`, as defined below |

The result is valid inside the caller-owned transaction. It is not evidence of
durability until that transaction commits. Callers use `action` for HTTP and
metric classification: `created` maps to 201 and `record_created()`, `updated`
maps to 200 and `record_updated()`, and `unchanged` maps to 200 with no metric.
Delete maps `deleted` to 204 and `not_found` to the existing 404
`CVSS_ASSESSMENT_NOT_FOUND` response. No caller may classify an outcome from an
unlocked pre-read.

Propagation dispositions describe the required package-domain handoff without
prescribing its runtime mechanism:

- `immediate`: an associated Ticket may receive package-owned eligibility and
  Ticket gate propagation in the current workflow.
- `deferred_until_reactivation`: an external mutation associated with a
  `Resolved`, `Ignored`, or `Duplicated` Ticket is retained for package-owned
  propagation when that Ticket reactivates. For manual-zone Tickets this means
  after the explicit manual-zone exit.
- `not_applicable`: the CVE has no associated Ticket, so there is no Product
  eligibility or Ticket state to propagate.
- `none`: the serialized outcome is `unchanged` or `not_found`, so there is no
  effective mutation to propagate.

The disposition is part of every successful result and is actionable only for
`created`, `updated`, or `deleted`. `unchanged` and `not_found` return the
current resolution values with `propagation = none`.

An authority rejection, manual-zone rejection, unchanged result, not-found
result, waiting concurrent no-op, or caller rollback creates no durable audit,
assignment, Product eligibility, Ticket status, metric, or post-commit effect.
An effective mutation and its direct audit records are atomic: audit or flush
failure propagates and rolls back the assessment and `CVE.severity` together.

### CVSS Status Matrix

| Associated Ticket status | Manual SUSE upsert/delete | Trusted external upsert | Effective-mutation propagation |
|---|---|---|---|
| No Ticket | Allowed | Allowed | `not_applicable` |
| `New` | Allowed | Allowed | `immediate` |
| `Analysis` | Allowed | Allowed | `immediate` |
| `Analyzed` | Allowed | Allowed | `immediate` |
| `Resolved` | Allowed | Allowed | Manual SUSE: `immediate`; external: `deferred_until_reactivation` |
| `Ignored` | Reject with `TicketNotMutableError`; no result | Allowed | External: `deferred_until_reactivation` |
| `Duplicated` | Reject with `TicketNotMutableError`; no result | Allowed | External: `deferred_until_reactivation` |

External delete is rejected for every row of the matrix. An effective
assessment mutation always recomputes and persists `CVE.severity`, including
for a ticketless CVE and a CVE associated with an inactive Ticket. The mutation
does not change Product eligibility, a package-tree record, assignment, or
Ticket status. Those effects remain with their owning contracts and consume
only an applicable committed handoff.

### `upsert_cvss_assessment()`

Creates or updates a `CVECVSSAssessment` record for a CVE. The function
accepts a `cve_id` (not a `ticket_id`) and handles both CVEs with and
without an associated ticket. If an assessment for the same
`(cve_id, provider, version)` already exists, it is updated; otherwise a
new one is created.

**Parameters**:

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `db` | `AsyncSession` | Yes | Database session |
| `cve_id` | `UUID` | Yes | CVE that receives the assessment |
| `provider` | `str` | Yes | Assessment provider (e.g., `"SUSE"`, `"NVD"`) |
| `vector_string` | `str` | Yes | CVSS vector string (version, score, and severity derived from it) |
| `caller` | `CVSSMutationCaller` | Yes | `MANUAL_SUSE` or `TRUSTED_EXTERNAL_INGESTION`; authority is not inferred from actor presence |
| `acting_user_id` | `UUID \| None` | Yes | Required for `MANUAL_SUSE`; must be `NULL` for trusted external ingestion |
| `default_cvss_version` | `str \| None` | No | Version used for severity and eligibility resolution. If `None`, read it once from `settings_service.get_default_cvss_version(db)` after root locking |

**Preconditions**:

- Vector must be parseable — raises `InvalidCVSSVectorError`
- CVE must exist for `cve_id`; absence is an internal caller-contract violation
  and raises `ValueError` after the required CVE lock query. API callers cannot
  reach this case because CVE accessibility resolves the path first
- Caller category, actor, and provider must satisfy the authority table

**Return type**: `CVSSAssessmentMutationResult`, as defined above.

**Behavior**:

1. Validate caller/provider authority and parse the vector using only input
   data. Derive the exact version, canonical vector, decimal score, and
   version-specific assessment severity. Parsing failure raises
   `InvalidCVSSVectorError` before database access.
2. As the first persistent read, load the CVE with `FOR UPDATE`. If it does not
   exist, raise `ValueError` for the internal caller-contract violation.
3. Load the Ticket associated with that locked CVE, if any, with `FOR UPDATE`.
   This makes concurrent association compose in `CVE` then `Ticket` order.
4. Apply the status matrix. Manual SUSE callers reject a locked manual-zone
   Ticket before any write; external ingestion remains allowed.
5. Resolve `default_cvss_version`: if the parameter is `None`, read it once from
   `settings_service.get_default_cvss_version(db)`. Use this one value for both
   severity and eligibility resolution in this invocation.
6. Load the existing assessment for the canonical natural key under the CVE
   lock. Compare its persisted canonical vector with the incoming canonical
   vector, not with raw input text.
7. Classify and apply `created`, `updated`, or `unchanged` from that serialized
   state. `unchanged` resolves and returns the current severity and eligibility
   values without assignment, audit, severity write, package propagation,
   Ticket reconciliation, or metric.
8. For an effective create/update, persist the canonical vector and all parsed
   fields. Re-resolve the complete committed-current assessment set and always
   persist the resulting unified value to `CVE.severity`, including when its
   value is unchanged.
9. If a Ticket exists, create `cvss_assessment_changed` first. If unified
   severity changed, create `severity_changed` second. Both records are direct
   consequences of the committed assessment mutation and are created in every
   Ticket status; they are not deferred with package propagation. Do not
   auto-assign the Ticket.
10. Resolve the separate Eligibility Score result and return it with the status-
   and-caller-derived propagation disposition. The function itself performs no
   Product or Ticket mutation and invokes no post-commit effect. This
   specification does not define the package-owned consumer of that handoff.
11. Flush and return `CVSSAssessmentMutationResult`.

**Audit event values**:

| Action | `old_value` | `new_value` |
|--------|-------------|-------------|
| `created` | `NULL` | Canonical assessment value |
| `updated` | Previous canonical assessment value | Current canonical assessment value |
| `unchanged` | No event | No event |

The exact canonical assessment value is
`"{provider_name} v{cvss_version} {vector_string} ({score:.1f})"`.

**TicketAuditEvent**: `cvss_assessment_changed` for an effective mutation when
the CVE has an associated Ticket, in every Ticket status. Its actor is the
manual SUSE user or `NULL` for external ingestion. A changed derived severity
adds `severity_changed` with `user_id = NULL`.

---

### `delete_cvss_assessment()`

Deletes a `CVECVSSAssessment` record (hard delete). The function accepts
natural key parameters instead of a UUID, eliminating the need for
callers to resolve the assessment ID.

**Parameters**:

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `db` | `AsyncSession` | Yes | Database session |
| `cve_id` | `UUID` | Yes | CVE owning the assessment |
| `provider` | `str` | Yes | Assessment provider |
| `cvss_version` | `str` | Yes | CVSS version (`"3.1"`, `"4.0"`, etc.) |
| `caller` | `CVSSMutationCaller` | Yes | Must be `MANUAL_SUSE`; external deletion is never authorized |
| `acting_user_id` | `UUID` | Yes | Authorized user performing the SUSE deletion |
| `default_cvss_version` | `str \| None` | No | Version used for severity and eligibility resolution. If `None`, read it once from `settings_service.get_default_cvss_version(db)` after root locking |

**Preconditions**:

- Caller must have manual SUSE authority and provider must resolve to canonical
  `SUSE`

**Return type**: `CVSSAssessmentMutationResult`, as defined above. The
`not_found` action maps to `CVSSAssessmentNotFoundError` at the API boundary.

**Behavior**:

1. Validate caller/provider authority and the accepted version using only input
   data. External caller categories and external providers raise `ValueError`;
   they cannot use this deletion boundary.
2. As the first persistent read, load the CVE with `FOR UPDATE`; then load its
   associated Ticket, if any, with `FOR UPDATE`. A missing CVE is an internal
   caller-contract violation and raises `ValueError`; API callers cannot reach
   it because CVE accessibility resolves the path first.
3. Apply the status matrix. Reject manual-zone Tickets before any write.
4. Resolve `default_cvss_version`: if the parameter is `None`, read it once from
   `settings_service.get_default_cvss_version(db)`. Use this one value for both
   severity and eligibility resolution in this invocation.
5. Load the canonical SUSE assessment under the CVE lock. If absent, resolve
   and return the current severity and eligibility values with `not_found`, but
   perform no write, audit event, package propagation, or metric.
6. Snapshot the canonical audit value and delete the assessment. Re-resolve the
   complete remaining assessment set and always persist the resulting unified
   value, including `NULL`, to `CVE.severity`.
7. If a Ticket exists, create `cvss_assessment_changed` first with the snapshot
   as `old_value` and `NULL` as `new_value`. If unified severity changed, create
   system-attributed `severity_changed` second. Do not auto-assign the Ticket.
8. Resolve the separate Eligibility Score result, derive propagation from the
   status matrix, flush, and return `deleted` with the complete handoff. This
   function does not mutate Product eligibility or Ticket status.

**TicketAuditEvent**: `cvss_assessment_changed` for `deleted` when the CVE has
an associated Ticket, in every status; `severity_changed` follows when the
unified severity changed. Both use `detail = NULL`. `not_found`, rejection, and
rollback leave no event.

---

### `set_severity_manual()`

Sets or clears the `severity_manual` field on a ticket.

**Parameters**:

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `db` | `AsyncSession` | Yes | Database session |
| `ticket_id` | `UUID` | Yes | Ticket to modify |
| `severity` | `Severity \| None` | Yes | New severity value (`Critical`, `High`, `Medium`, `Low`, or `None` for CVSS score 0.0 / informational), or Python `None` to clear the value (sets `severity_manual` to SQL `NULL` = unresolved) |
| `acting_user_id` | `UUID \| None` | No | Who is performing the action |

**Preconditions**:

- Ticket must be operable (`ensure_ticket_operable`)
- Ticket must have `cve_id IS NULL` — raises `SeverityDerivedError`
  if the ticket has an associated CVE (severity is derived from CVSS
   scores and cannot be set manually)

**Behavior**:

1. Acquire `FOR UPDATE` on the Ticket row
2. Call `ensure_ticket_operable(ticket)`
3. Validate preconditions
4. If severity unchanged, return (no-op)
5. Call `auto_assign_actor(ticket, acting_user_id, db)`
6. Update `ticket.severity_manual`
7. Create `TicketAuditEvent` (`severity_changed`, `user_id = acting_user_id`)
8. Call `reconcile_ticket_status()`
9. Return updated ticket

**Gate relevance**: setting `severity_manual` affects the ticket's
resolved severity, which is gate-relevant (Analyzed gate #3 requires
severity). This operation is only valid when `cve_id IS NULL` — when a
CVE is associated, severity is derived from CVSS scores via the
resolution cascade and `severity_manual` is not applicable.

**TicketAuditEvent**: `severity_changed`

**Idempotency**: no-op if severity is unchanged.

---

### `recalculate_cvss_chain()`

Recalculates CVE-owned severity from current assessments and returns the
separate deterministic eligibility handoff for a Ticket. It does not create,
update, or delete a `CVECVSSAssessment`, mutate Product eligibility, or
reconcile Ticket status. The historical function name describes its role in a
larger composed workflow; it does not transfer package mutation ownership into
this module.

**Callers**: `associate_cve()` and the batch recalculation Celery task triggered
by a default CVSS version change (see
`docs/features/platform/system-settings.md`). This contract defines no
Ticket-reactivation caller.

**Parameters**:

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `db` | `AsyncSession` | Yes | Database session |
| `cve_id` | `UUID` | Yes | CVE whose assessment set and associated Ticket, if any, are recalculated |
| `default_cvss_version` | `str \| None` | No | The CVSS version to use for severity resolution and eligibility evaluation. If `None` (default), the function reads the current version from `settings_service.get_default_cvss_version(db)`. The batch recalculation task provides this explicitly (passed as a task argument from the triggering endpoint) to ensure all tickets in a batch use the same version. Other callers should typically omit this parameter |
| `evaluation_date` | `date \| None` | No | UTC date carried with the handoff so the composed package propagation and Ticket reconciliation can use one temporal input. If omitted, capture the current UTC date once at function entry |

**Behavior**:

1. Acquire `FOR UPDATE` on the CVE as the first persistent read, then load and
   lock its associated Ticket, if any. A CVE without an associated Ticket uses
   `not_applicable`.
2. Resolve `default_cvss_version`: if the parameter is `None`, read
   from `settings_service.get_default_cvss_version(db)`. Call
   `cvss.resolve_severity_score()` with the complete assessment set to obtain
   the committed-current resolution.
3. Persist its unified label, or `NULL` for absent, to `CVE.severity`, and
   report the true old and new values when they differ. The caller owns the
   context-specific direct `severity_changed` event in the same transaction.
4. Call `cvss.resolve_eligibility_score()` with the resolved
   `default_cvss_version` to obtain the score and `suse`/`fallback` source.
5. Derive the propagation disposition from the current Ticket status and the
   owning workflow's documented caller category. A default-version workflow
   follows its separately documented target scope.
6. Flush and return the severity resolution, eligibility resolution, whether
   severity changed, propagation disposition, and `evaluation_date`. This
   specification defines the handoff value but not its package-owned consumer.

**TicketAuditEvent**: none directly. A caller that receives changed old/new
severity creates the required system-attributed `severity_changed` in the same
transaction. `associate_cve()` substitutes its manual-to-derived handover
values and emits exactly one such event. Product eligibility events belong to
the package mutation that applies the handoff.

**Idempotency**: safe to call multiple times. With unchanged assessments and
default version, severity and its audit are a no-op and the same pure handoff is
returned.

---

## Manual-Zone Exit Operations

These operations transition tickets out of the manual zone (Ignored or
Duplicated) back into the gate zone.

### `reopen_from_ignored()`

Reopens a ticket from Ignored status.

**Parameters**:

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `db` | `AsyncSession` | Yes | Database session |
| `ticket_id` | `UUID` | Yes | Ticket to reopen |
| `acting_user_id` | `UUID \| None` | No | Who is performing the action |

**Preconditions**:

- Ticket must exist
- Ticket must be in `Ignored` status

**Behavior**:

1. Acquire `FOR UPDATE` on the Ticket row
2. Verify current status is Ignored
3. Call `auto_assign_actor(ticket, acting_user_id, db, force=True)`:
   - `acting_user_id` is `None` (system): ticket retains current
     assignee; `reconcile_ticket_status` handles inactive assignees in
     the final step
   - `acting_user_id` is VA: becomes new assignee
   - `acting_user_id` is non-VA: ticket retains current assignee;
     `reconcile_ticket_status` handles inactive assignees in the final
     step
4. Call `_reenter_gate_zone()`:
   - Saves `original_status = Ignored`
   - Sets `status = Analysis` (floor of the gate zone)
   - Calls `reconcile_ticket_status(previous_status=Ignored)`
   - Produces `status_change` event with
     `old_value = Ignored, new_value = Analysis` (or `Analyzed`/`Resolved`
     if gate conditions are already satisfied)

**TicketAuditEvent**: `status_change` (via `reconcile_ticket_status`) +
optionally `assignment` (via `auto_assign_actor`)

---

### `revert_duplicate()`

Reverts a ticket from Duplicated status.

**Parameters**:

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `db` | `AsyncSession` | Yes | Database session |
| `ticket_id` | `UUID` | Yes | Ticket to revert |
| `acting_user_id` | `UUID \| None` | No | User performing the revert. Currently no system caller exists; this signature enables future system-initiated revert scenarios |

**Preconditions**:

- Ticket must exist
- Ticket must be in `Duplicated` status

**Behavior**:

1. Acquire `FOR UPDATE` on the Ticket row
2. Verify current status is Duplicated
3. Clear `duplicate_of_id` (set to NULL)
4. Call `auto_assign_actor(ticket, acting_user_id, db, force=True)`:
   assigns the acting user if they hold the `vulnerability_analyst`
   role; otherwise the ticket retains its current assignee
5. Create `TicketAuditEvent` (`duplicate_removed`)
6. Call `_reenter_gate_zone()`:
   - Saves `original_status = Duplicated`
   - Sets `status = Analysis` (floor of the gate zone)
   - Calls `reconcile_ticket_status(previous_status=Duplicated)`
   - Outcome: Analysis, Analyzed, or Resolved based on current gate
     conditions (independent of assignee presence)

Produces two `TicketAuditEvent` records in the same transaction:
`duplicate_removed` (user action) followed by `status_change` with
`old_value = Duplicated, new_value = (evaluated target)`.

**TicketAuditEvent**: `duplicate_removed` + `status_change`

The revert is non-retroactive: if other tickets were previously
repointed away from this ticket (via `duplicate_target_changed`
events), they are not affected by this revert — they remain
pointing to their current target.

## Utility Functions

## Auto-Assignment Rule

When a user with the `vulnerability_analyst` role performs any modifying
operation on a ticket with `assignee_id = NULL`, the ticket is
automatically assigned to the acting user. A `TicketAuditEvent` with
`event_type = assignment` is created atomically in the same transaction
as the modifying operation. If the acting user does not hold the
`vulnerability_analyst` role (e.g., a `restricted_analyst`),
auto-assignment is skipped — the ticket remains unassigned.

After the assignment, if the ticket was in `New` status,
`auto_assign_actor()` explicitly sets `status = Analysis` and creates a
`status_change` audit event (`New → Analysis`, `user_id = NULL`) before
returning to the caller. The caller then calls `reconcile_ticket_status`,
which evaluates from `Analysis` upward and may promote to `Analyzed` or
`Resolved` if gate conditions are already satisfied.

For operations that call `auto_assign_actor` and then immediately set
an explicit status (e.g., `ignore_ticket` → `Ignored`,
`mark_as_duplicate` → `Duplicated`): `auto_assign_actor` sets `Analysis`,
the caller then sets the explicit status. The audit trail records two
`status_change` events — `New → Analysis` and `Analysis → Ignored` (or
`Duplicated`). This is correct and intentional: the VA claimed the ticket
before choosing to act on it explicitly.

This rule is enforced via the shared helper `auto_assign_actor()`
(see below), which is called by all modules that modify tickets under
a `FOR UPDATE` lock (`ticket_mutations`, `package_service`,
`ticket_service`).

This rule does not apply to system operations (`acting_user_id = None`)
or to users without the `vulnerability_analyst` role.
It also does not apply when a `package_service` invocation creates only
system-derived `TicketPackageMaintainer` associations. The package service does
not call this helper for that association-only mutation; it calls the helper
normally when the same invocation also changes package-tree state.

### `auto_assign_actor()`

A public helper function that implements the auto-assignment check. Mutation
modules call it under the Ticket `FOR UPDATE` lock when their owning operation
requires auto-assignment. The association-only maintainership exception above
does not call it.

**Signature**:

```python
async def auto_assign_actor(
    ticket: Ticket,
    acting_user_id: UUID | None,
    db: AsyncSession,
    force: bool = False,
) -> bool:
    """Assign ticket to acting user if user holds VA role.

    When force=False (default): assigns only if ticket is currently
    unassigned. Used by all gate-relevant mutations as step 2.

    When force=True: assigns regardless of current assignee. Used by
    manual-zone exit functions (reopen_from_ignored, revert_duplicate)
    to take ownership. External callers (`package_service`,
    `ticket_service`, API handlers, background tasks) MUST NOT pass
    `force=True` — doing so is a bug.

    Returns True if assignment was applied (audit event created),
    False otherwise.

    Precondition: caller MUST hold FOR UPDATE on the ticket row.
    """
```

**Behavior**:

1. If `acting_user_id is None` → return False (system action)
2. If not `force` and `ticket.assignee_id is not None` → return False
   (already assigned)
3. Load the acting user's roles. If not VA → return False
4. If `ticket.assignee_id == acting_user_id` → return False (assignment
   unchanged, no audit event)
5. Set `ticket.assignee_id = acting_user_id`
6. Create `TicketAuditEvent` with `event_type = assignment`
7. If `ticket.status == New`: set `ticket.status = Analysis`, create
   `TicketAuditEvent` with `event_type = status_change`,
   `user_id = NULL`, `old_value = "New"`, `new_value = "Analysis"`
8. Return True

> **Caller responsibility**: this function performs assignment and, if
> the ticket is in `New` status, promotes it to `Analysis` and creates a
> `status_change` audit event (`user_id = NULL`). It does not call
> `reconcile_ticket_status()`. Callers MUST call
> `reconcile_ticket_status()` after completing all mutations to ensure
> inactive assignee sanitization and correct gate evaluation.

## Related Operations

Non-gate ticket lifecycle operations (assignment, CVE association,
mark-as-duplicate, set-confidentiality, access grant
management) live in `ticket_service` —
see [ticket-service.md](ticket-service.md) for the full service contract.

These operations use the same `FOR UPDATE` pattern documented in
[Concurrency Control](#concurrency-control) and create their own
`TicketAuditEvent` records. Some call `reconcile_ticket_status()` due
to indirect gate effects (severity source change, promotion evaluation
after assignment, status reconciliation after restore).

## Contract

Every service-layer operation that modifies data relevant to ticket
status gates MUST go through the appropriate centralized module:

- **Package/track/product mutations**: `package_service`
  (`TicketPackageTrack` status, delivery status, standalone
  `TicketPackageProduct` eligibility overrides, soft-delete/restore, record
  creation, additive maintainership association)
- **CVSS and severity mutations**: `ticket_mutations`
  (`CVECVSSAssessment` records, manual severity)
- **Ticket status evaluation**: `ticket_mutations` (the shared
  service-internal primitive is called after an effective gate-relevant
  mutation; delivery-status mutation is explicitly not gate-relevant)

Direct modification of gate-relevant records outside the owning module is a
bug. In particular, `ticket_mutations` owns CVSS assessments and CVE severity,
while `package_service` owns Product eligibility. CVSS functions return the
deterministic Eligibility Score result and propagation disposition required for
composition; this handoff does not permit direct package writes in
`ticket_mutations`.

Non-gate ticket lifecycle operations live in `ticket_service` — see
`docs/features/tickets/ticket-service.md`. Some of these operations
compose `recalculate_cvss_chain()`, package-owned propagation, and
`reconcile_ticket_status` due to indirect gate effects. CVE association uses
this composition because it changes the severity source; assignment calls
`reconcile_ticket_status` directly for promotion evaluation. The
per-function documentation in `ticket-service.md` specifies exactly
which operations call `reconcile_ticket_status` and why.

## Architectural Test Requirement

A parametrized integration test MUST be implemented to verify that the
`ticket_mutations` module produces the correct ticket status after every
type of ticket-centric mutation (CVSS assessment operations, manual
severity, manual-zone exits). The test must cover:

- **Forward transitions**: CVSS and severity changes causing ticket
  advancement
- **Backward transitions**: CVSS deletion breaking gate conditions
- **No-op cases**: unchanged assessment requests and mutations whose resolved
  severity stays unchanged
- **Edge cases**: ticket without CVE (no SUSE CVSS gate), manual
  severity on CVE-less ticket
- **CVSS status matrix**: manual and trusted-external callers across a
  ticketless CVE and every Ticket status, including external persistence with
  `deferred_until_reactivation` package propagation
- **CVE severity ownership**: every effective assessment create, update, and
  delete updates ticketless and inactive-state `CVE.severity`
- **Serialized outcomes**: canonical-vector no-op, create/update and
  delete/not-found races, concurrent upsert/upsert, upsert/delete, and
  association/CVSS mutation using independent database sessions; each result,
  HTTP/metric classification, audit payload, and handoff reflects the committed
  winner after `CVE` then `Ticket` locking
- **Authority and audit**: reserved SUSE variants, caller/actor mismatch,
  external-delete rejection, every-status direct events when a Ticket exists,
  ticketless no-event behavior, system-derived severity attribution, event
  ordering, and rollback atomicity
- **Manual-zone exits**: `reopen_from_ignored` and `revert_duplicate`
  producing correct status transitions

Package-centric mutation tests are specified in
`docs/features/packages/package-service.md` (Architectural Test
Requirement).

## Service Exceptions

All exceptions in this module inherit from `TicketMutationsError`.
API endpoint handlers catch `TicketMutationsError` subclasses and map
them to the corresponding HTTP status code and error code per
`api-spec.md`.

| Exception | HTTP | Code | Raised when |
|-----------|------|------|-------------|
| `TicketNotFoundError` † | 404 | `TICKET_NOT_FOUND` | Ticket ID does not exist |
| `TicketNotMutableError` † | 409 | `TICKET_NOT_MUTABLE` | Ticket is in manual zone (Ignored or Duplicated) |
| `CVSSAssessmentNotFoundError` | 404 | `CVSS_ASSESSMENT_NOT_FOUND` | No SUSE assessment exists for the accepted `(cve_id, cvss_version)` after the CVE itself was resolved |
| `InvalidCVSSVectorError` | 422 | `CVSS_INVALID_VECTOR` | CVSS vector string is malformed or invalid |
| `InvalidTransitionError` † | 409 | `TICKET_INVALID_TRANSITION` | Requested status transition is not allowed |
| `SeverityDerivedError` † | 409 | `TICKET_SEVERITY_DERIVED` | Cannot manually set severity when it is auto-derived |

† Shared exception — inherits from `ServiceError`, not from
`TicketMutationsError`. Handlers must catch it explicitly.

Caller-category/provider mismatches, external delete attempts, and a missing
CVE UUID supplied directly by an internal caller raise `ValueError`. These are
internal contract violations and do not introduce API error codes. API routes
resolve CVE accessibility before invoking this service.

Package-specific exceptions (`TrackNotFoundError`, `ProductNotFoundError`,
`PackageNotFoundError`) are defined in `package_service` — see
`docs/features/packages/package-service.md`.

## Cross-references

- `docs/features/packages/package-service.md` — package-centric
  mutations, orchestration, and query operations (imports
  `reconcile_ticket_status()`, `auto_assign_actor()`, and
  `ensure_ticket_operable()`)
- `docs/features/tickets/tickets.md` — ticket lifecycle, gate
  conditions, API endpoints
- `docs/features/tickets/ticket-audit-log.md` — event type contract
- `docs/features/tickets/cvss-scoring.md` — CVSS resolution cascade,
  severity calculation
- `docs/features/packages/package-model.md` — track/Product concepts,
  status propagation, exclusion, and derived actionability
- `docs/features/packages/product-lifecycle-transitions.md` — AIMAAS
  threshold changes triggering eligibility mutations
- `docs/features/identity/user-service.md` — `deactivate_user` bulk
  unassignment (complementary to inactive assignee sanitization)
- `docs/conventions.md` — Transaction and Locking (generic pessimistic
  locking pattern)
- `docs/features/tickets/ticket-service.md` — non-gate ticket lifecycle
  operations, ticket reactivation hooks (imports
  `reconcile_ticket_status()`, `recalculate_cvss_chain()`,
  `auto_assign_actor()`, `ensure_ticket_operable()`)
- `docs/features/platform/system-settings.md` — default CVSS version
  change triggering batch `recalculate_cvss_chain()` via Celery task
- `docs/features/platform/fetcher-infrastructure.md` — `catch_up()`
  per-ticket catch-up method contract
- `docs/api-spec.md` — general API conventions
