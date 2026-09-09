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

### Relationship with other modules

| Module | Relationship |
|--------|-------------|
| `services/cvss.py` | `ticket_mutations` delegates CVSS resolution and severity calculation to pure functions in `cvss.py`. The resolution cascade logic is never reimplemented inside `ticket_mutations` |
| `services/package_service.py` | Handles all package-centric mutations (track status, delivery status, product eligibility, soft-delete/restore, record creation) and package queries. `package_service` imports `reconcile_ticket_status()`, `auto_assign_actor()`, and `ensure_ticket_operable()` from `ticket_mutations`. The dependency is unidirectional: `package_service` -> `ticket_mutations` |
| `services/ticket_service.py` | Handles non-gate operations (assignment, CVE association, mark-as-duplicate, set-confidentiality, access grants). See [ticket-service.md](ticket-service.md) for the full contract. These operations use the same FOR UPDATE pattern and import `ensure_ticket_operable()` from `ticket_mutations` |

## State Machine Zones

The ticket state machine has two zones that determine which operations
are valid:

### Gate zone (Analysis, Analyzed, Resolved)

Status is determined automatically by `reconcile_ticket_status` based on
gate conditions. The `ticket_mutations` module operates exclusively on
tickets in this zone (with the exception of manual-zone exit functions).

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
Synchronous CVSS recalculation remains in the transaction; the function
registers the package-tree and fetcher recovery workflow for post-commit
execution. No action is needed by the calling function or endpoint handler.

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
- May call `recalculate_cvss_chain()` when an inactive → active
  transition is detected (producing `severity_changed` and
  `product_eligibility_changed` audit events if derived values change)
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
     `new_status ≠ effective_previous`:
      1. If `ticket.cve_id IS NOT NULL`: call
          `recalculate_cvss_chain(ticket_id, evaluation_date=evaluation_date)`
          (reads `default_cvss_version` internally; if the setting is absent,
          the exception propagates — this indicates a deployment error and
          the transaction rolls back).
         If `ticket.cve_id IS NULL`: skip (tickets without a CVE derive
         severity from `severity_manual`, not from CVSS assessments —
         there is nothing to recalculate)
      2. Register one post-commit reactivation workflow. Its package-domain
         phase first re-resolves every persisted package marker, including
         soft-deleted markers, through `package_service`; after those
         per-package transactions finish, it enqueues `catch_up()` for every
         registered fetcher via `get_catch_up_fetchers()`. Registration does
         not introduce a `ticket_mutations` → `package_service` import: the
         post-commit workflow owner performs that orchestration. Registration
         proceeds regardless of whether step 4.1 was skipped. The workflow and
         failure isolation contract are defined in `package-service.md`
         (Package-tree reactivation workflow) and `package-model.md`
         (Reactivation and Convergence)
   - **Note**: step 4 is independent of step 3. In the
     `_reenter_gate_zone()` case, the caller has already set the status
     before invoking reconcile; step 3 sees no change but step 4
     correctly detects the inactive-state exit via `previous_status`.
     Post-commit workflow registration is unconditional after
     `recalculate_cvss_chain()` returns — it does not re-check ticket
     status
   - **Registration deduplication**: recursive reconciliation within the same
     caller-owned transaction registers at most one reactivation workflow for
     the Ticket. Duplicate workflows across separate transactions remain safe
     because package resolution and all catch-ups are idempotent.
   - **Recursion termination**: `recalculate_cvss_chain()` calls
      `reconcile_ticket_status()` at its step 7. This inner call may
      re-trigger step 4 at most once: when the outer call set the ticket
      to Resolved (gates satisfied with pre-inactivity data) and the
      recalculation invalidates a gate, the inner call regresses the
      ticket to Analysis with `effective_previous` = Resolved — which is
      in the trigger set. The second `recalculate_cvss_chain()` call is
      idempotent (same inputs within the same transaction), producing no
      mutations. The innermost `reconcile_ticket_status()` sees an active
      status (Analysis or Analyzed) as `effective_previous`, which is not
      in the trigger set. Maximum recursion depth: 2 reconcile calls
      (outer → inner → innermost no-op). No infinite recursion risk —
      termination is guaranteed by idempotency of
      `recalculate_cvss_chain()`
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
`ticket_service`) — acquires `FOR UPDATE` on the ticket as its first
operation before calling `reconcile_ticket_status()`.

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

**Consumers**:

| Module | Functions that call `ensure_ticket_operable` |
|--------|----------------------------------------------|
| `ticket_mutations` | `upsert_cvss_assessment`\*, `delete_cvss_assessment`\*, `set_severity_manual` |
| `ticket_service` | `associate_cve`, `assign_ticket`, `ignore_ticket`, `mark_as_duplicate`, `set_confidentiality`, `grant_access`, `revoke_access` |
| `package_service` | Gate-relevant mutations call the guard; `set_track_delivery_status` also calls it for operability but remains outside assignment, audit, and Ticket reconciliation |

\* CVSS functions call `ensure_ticket_operable` **conditionally** — only
when the CVE has an associated ticket. Ticketless CVEs skip this check
(see `upsert_cvss_assessment()` below).

## Gate-Relevant Mutation Operations

Each ticket-mutation function below follows the same pattern unless its own
contract places semantic no-op or operation-specific guards before assignment:

1. Acquire `FOR UPDATE` on the parent Ticket row
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
computation. See Key Principle 6 ("Always derived from vector") in
[cvss-scoring.md](cvss-scoring.md#key-principles) for the system-wide
ingestion rule that governs how scores and versions are handled.

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
| `acting_user_id` | `UUID \| None` | No | Who is performing the action |

**Preconditions**:

- CVE must exist for `cve_id` — the FK constraint on
  `CVECVSSAssessment.cve_id` requires a valid CVE. API endpoints resolve
  and validate the CVE path parameter before calling this function;
  `cve_service.upsert_cve()` creates the CVE before calling this function.
  The function does not check CVE existence explicitly — an invalid
  `cve_id` produces an `IntegrityError` from the database.
- Vector must be parseable — raises `InvalidCVSSVectorError`

**Persistence mechanism**: SQL `INSERT ... ON CONFLICT DO UPDATE` on the
unique constraint `(cve_id, provider_name, cvss_version)`. This
guarantees atomicity at the database level — concurrent upserts for the
same natural key are serialized by PostgreSQL. This is consistent with
the `ON CONFLICT DO UPDATE` strategy documented in `cve-service.md`
(Child Table Deduplication) for all child tables with stable unique
constraints.

**Return type**: `tuple[CVECVSSAssessment, AssessmentUpsertAction]` —
where `AssessmentUpsertAction` is a three-valued enum:

| Value | Meaning | Metric |
|-------|---------|--------|
| `CREATED` | New record inserted | `record_created()` |
| `UPDATED` | Existing record modified (vector changed) | `record_updated()` |
| `UNCHANGED` | Existing record identical (no-op) | — (no metric) |

`AssessmentUpsertAction` is a separate type from
`cve_service.UpsertAction` despite having the same members. The
semantics differ: `cve_service.UpsertAction.unchanged` means "no global
CVE fields contributed" (child data may still have been upserted),
whereas `AssessmentUpsertAction.UNCHANGED` means "the assessment vector
is identical, no mutation occurred at all." Distinct types prevent
accidental conflation in code that handles both return values.

**Behavior**:

1. Parse the vector string with the `cvss` library. Derive version,
   score, and severity. If parsing fails, raise `InvalidCVSSVectorError`
2. `SELECT` existing `CVECVSSAssessment` for `(cve_id, provider,
   derived_version)`. Capture the existing record (if any) for old-value
   determination and no-op detection
3. **No-op short-circuit**: if an existing record was found and
   `existing.vector_string == incoming_vector_string`, return
   `(existing, UNCHANGED)` immediately — no database write, no lock
   acquisition, no recalculation chain, no audit event. This prevents
   unnecessary lock contention and recalculation overhead during bulk
   fetcher re-syncs where most CVSS data has not changed. Note: the
   short-circuit bypasses `auto_assign_actor()` because no mutation
   occurred — this is correct and consistent with the principle that
   side effects are triggered by state changes, not by intent to change
4. Look up the ticket associated with the CVE (if any)
5. If a ticket exists:
   a. Acquire `FOR UPDATE` on the Ticket row
   b. Call `ensure_ticket_operable(ticket)` — if the ticket is in a
      non-mutable status, the function raises `TicketNotMutableError`.
      No assessment write has occurred at this point, so no rollback of
      assessment data is needed
6. Execute `INSERT ... ON CONFLICT DO UPDATE` with the parsed
   vector_string, computed score, and derived severity. Determine action:
   - **No existing record** (step 2 returned nothing): `CREATED`
   - **Existing record with different vector**: `UPDATED`
7. If a ticket exists:
   a. Call `auto_assign_actor(ticket, acting_user_id, db)`
   b. Create `TicketAuditEvent` (`cvss_assessment_changed`). The
      `old_value` is derived from the `SELECT` in step 2: `NULL` if the
      record was created, `"provider vX.Y old_score"` if updated
   c. Call `recalculate_cvss_chain(ticket_id,
      acting_user_id=acting_user_id)` — reads `default_cvss_version`
      internally, recalculates severity and product eligibility, creates
      derived audit events (`severity_changed`,
      `product_eligibility_changed`) when values change, and calls
      `reconcile_ticket_status()` internally (post-transition catch-up,
      if triggered, is handled by reconcile step 4)
8. If no ticket exists (ticketless CVE): skip steps 5 and 7 — the CVSS
   assessment is stored but no ticket side effects are triggered
9. Return `(assessment, action)`

**Audit event values**:

| Action | `old_value` | `new_value` |
|--------|-------------|-------------|
| `CREATED` | `NULL` | `"provider vX.Y score"` |
| `UPDATED` | `"provider vX.Y old_score"` | `"provider vX.Y new_score"` |
| `UNCHANGED` | — (no audit event created) | — |

**TicketAuditEvent**: `cvss_assessment_changed` (only when the CVE has
an associated ticket and the action is `CREATED` or `UPDATED`)

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
| `acting_user_id` | `UUID \| None` | No | Who is performing the action |

**Preconditions**:

- Assessment must exist for `(cve_id, provider, cvss_version)` — raises
  `CVSSAssessmentNotFoundError` (HTTP 404,
  `error_code: "CVSS_ASSESSMENT_NOT_FOUND"`)

**Behavior**:

1. Look up the assessment by `(cve_id, provider, cvss_version)`
2. Look up the ticket associated with the assessment's CVE (if any)
3. If a ticket exists:
   a. Acquire `FOR UPDATE` on the Ticket row
   b. Call `ensure_ticket_operable(ticket)`
4. Delete the assessment record
5. If a ticket exists:
   a. Call `auto_assign_actor(ticket, acting_user_id, db)`
   b. Create `TicketAuditEvent` (`cvss_assessment_changed`,
      `old_value = "provider vX.Y score"`, `new_value = NULL`)
   c. Call `recalculate_cvss_chain(ticket_id,
      acting_user_id=acting_user_id)` — reads `default_cvss_version`
      internally, recalculates severity and product eligibility, creates
      derived audit events when values change, and calls
      `reconcile_ticket_status()` internally
6. If no ticket exists: skip audit event and chain

**TicketAuditEvent**: `cvss_assessment_changed` (only when the CVE has
an associated ticket)

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

Recalculates severity and product eligibility for a ticket based on
current CVSS assessments and the active default CVSS version. This
function does NOT create, update, or delete any `CVECVSSAssessment`
record — it only recalculates derived data.

**Callers**: `upsert_cvss_assessment()`, `delete_cvss_assessment()`,
`associate_cve()` (ticket-service, with `suppress_severity_event=True`),
`reconcile_ticket_status()` step 4 (post-transition catch-up), and the
batch recalculation Celery task triggered by a default CVSS version
change (see `docs/features/platform/system-settings.md`).

**Parameters**:

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `db` | `AsyncSession` | Yes | Database session |
| `ticket_id` | `UUID` | Yes | Ticket to recalculate |
| `default_cvss_version` | `str \| None` | No | The CVSS version to use for severity resolution and eligibility evaluation. If `None` (default), the function reads the current version from `settings_service.get_default_cvss_version(db)`. The batch recalculation task provides this explicitly (passed as a task argument from the triggering endpoint) to ensure all tickets in a batch use the same version. Other callers should typically omit this parameter |
| `acting_user_id` | `UUID \| None` | No | Who triggered the recalculation (typically `None` for system-initiated batch operations) |
| `suppress_severity_event` | `bool` | No | Default `False`. When `True`, suppresses emission of the `severity_changed` audit event. Used exclusively by `associate_cve()`, which owns the severity handover event and needs to use the ticket's previous `severity_manual` (not `CVE.severity`) as `old_value`. All other callers MUST NOT set this to `True` |
| `evaluation_date` | `date \| None` | No | UTC date used for every lifecycle predicate in this function, including the Reactive Support check in step 5 and final status reconciliation. If omitted, capture the current UTC date once at function entry |

**Behavior**:

1. Acquire `FOR UPDATE` on the Ticket row
2. Resolve `default_cvss_version`: if the parameter is `None`, read
   from `settings_service.get_default_cvss_version(db)`. Call
   `cvss.resolve_severity_score()` with the resolved version to
   determine the new resolved score
3. If `resolve_severity_score()` returned a score, map it to a severity
   label via `cvss.calculate_severity()` (score 0.0 maps to `None`).
   If `resolve_severity_score()` returned `None` (absent), the new
   severity is `NULL` (unresolved).
   If severity changed, update `CVE.severity`
4. Call `cvss.resolve_eligibility_score()` with the resolved
   `default_cvss_version` to determine the eligibility score
5. Re-evaluate `eligible` for each `TicketPackageProduct` linked to the
   ticket (including soft-deleted products — see `package-model.md` Design Decision 8) using the eligibility score:
   - Products with `is_eligible_override = true` are not modified
    - Products in Reactive Support remain `eligible = false` regardless
6. Create `TicketAuditEvent` records for each change:
    - `severity_changed` if severity changed AND
      `suppress_severity_event` is `False`
    - `product_eligibility_changed` for each Product whose eligibility changed,
      with the standard event-time Product subject detail and `reason = "cvss"`
7. Call `reconcile_ticket_status(evaluation_date=evaluation_date)` so the
   complete recalculation chain uses one temporal input

**TicketAuditEvent**: `severity_changed` (if severity changed and
`suppress_severity_event` is `False`) +
`product_eligibility_changed` (for each affected product)

**Idempotency**: safe to call multiple times — if nothing has changed
since the last call, no mutations or audit events are produced.

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

Direct modification of gate-relevant records outside the owning module is a bug,
with one architectural exception:

### Exception: CVSS Recalculation Chain Eligibility Mutations

The architectural dependency is strictly unidirectional: `package_service` depends
on `ticket_mutations`, but `ticket_mutations` does NOT depend on `package_service`
(to prevent circular dependencies).

Consequently, when a CVSS mutation triggers the Recalculation Chain, the resulting
automatic, deterministic product eligibility updates are performed inline directly
within `ticket_mutations`. These updates are not standalone product mutations but rather
system-wide consequences of the CVSS score change. The chain specification in
`docs/features/tickets/cvss-scoring.md` guarantees that all required side effects —
the generation of `product_eligibility_changed` audit events and the call to
`reconcile_ticket_status()` — are executed atomically in the same transaction.

All standalone product eligibility mutations (such as manual overrides by a VA,
automated resets, and product lifecycle phase transitions) remain the exclusive
responsibility of `package_service`.

The platform-wide recalculation after an Admin changes
`default_cvss_version` remains part of the CVSS exception above: its batch task
calls `recalculate_cvss_chain()` once per active Ticket in independent
transactions. Product threshold and Reactive Support changes instead use the
standalone automatic `package_service` operation defined in
`docs/features/packages/package-service.md`; they do not call the global CVSS
batch and never create manual overrides.

Non-gate ticket lifecycle operations live in `ticket_service` — see
`docs/features/tickets/ticket-service.md`. Some of these operations
call `reconcile_ticket_status` (directly or via
`recalculate_cvss_chain()`) due to indirect gate effects: CVE
association calls `recalculate_cvss_chain()` (which calls reconcile
internally) because it changes the severity source; assignment calls
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
- **No-op cases**: mutations that do not affect gate conditions
- **Edge cases**: ticket without CVE (no SUSE CVSS gate), manual
  severity on CVE-less ticket
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
| `CVSSAssessmentNotFoundError` | 404 | `CVSS_ASSESSMENT_NOT_FOUND` | No assessment exists for the given natural key `(cve_id, provider, cvss_version)` |
| `InvalidCVSSVectorError` | 422 | `CVSS_INVALID_VECTOR` | CVSS vector string is malformed or invalid |
| `InvalidTransitionError` † | 409 | `TICKET_INVALID_TRANSITION` | Requested status transition is not allowed |
| `SeverityDerivedError` † | 409 | `TICKET_SEVERITY_DERIVED` | Cannot manually set severity when it is auto-derived |

† Shared exception — inherits from `ServiceError`, not from
`TicketMutationsError`. Handlers must catch it explicitly.

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
