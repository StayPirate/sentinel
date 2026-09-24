# Ticket Mutations Service

## Purpose

Centralize ticket-centric primitives that modify or evaluate data relevant to
ticket status gates — CVSS assessment management, manual severity, and status
reconciliation — in a single service module (`ticket_mutations`).
This module also provides the shared `reconcile_ticket_status()` function
and the `auto_assign_actor()` helper, which are called by both this
module and `package_service`, and the `refresh_priority_auto()` primitive that
maintains the informational automatic Ticket priority defined in
[ticket-priority.md](ticket-priority.md).

Package-centric mutations (track status, delivery status, product eligibility,
soft-deletion/restore, record creation, and additive maintainer association) are
handled by `package_service` (`docs/features/packages/package-service.md`).
The sole exception is the atomic CVSS chain: its mutation functions maintain
CVE-owned assessment and severity state and may update system-managed Product
eligibility inline before one final Ticket reconciliation. The formula remains
owned by `package-model.md`; the exception neither imports `package_service`
nor permits overrides or any other package mutation.

Consumer-facing manual-zone exits are Ticket lifecycle compositions owned by
`ticket_service`. They retain the Ticket lock while calling the package-owned
synchronous eligibility boundary and then this module's
`reconcile_ticket_status()` primitive exactly once. Neither lower service
imports `ticket_service`.

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
decision. This enables higher-level services to compose these primitives with
other service boundaries in one transaction when needed.

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

Capability is checked by the API before its first service resource lookup. For
consumer-facing operations, capability does not replace Ticket visibility. The
service operation performs authoritative accessibility revalidation after its
required roots are locked, using the one canonical predicate in
`docs/features/identity/rbac.md` (Scope and Confidential Ticket Visibility),
and before status/operability guards, assessment lookup, no-op classification,
assignment, writes, audit, Product propagation, reconciliation, or post-commit
registration. The caller-category/context representation and query mechanism
are implementation choices.

Manual severity is a Ticket-path operation, so missing or inaccessible returns
`404 TICKET_NOT_FOUND`. Manual SUSE CVSS operations are CVE-path operations, so
missing or inaccessible returns `404 CVE_NOT_FOUND`, including when access is
denied by the associated locked-current Ticket. Every accessibility denial has
zero side effects. CVEs without an associated Ticket remain accessible under
the CVE contract.

Trusted external ingestion, default-version recalculation, and other specified
system operations do not acquire an HTTP user's scope and do not apply consumer
visibility filtering. Caller authority is explicit at the owning boundary and
is not inferred solely from `acting_user_id`.

The single-assessment mutation requires
`CVSSMutationCaller.MANUAL_SUSE`, identifying an authorized consumer operation
on the internal SUSE assessment. All trusted external ingestion, including a
single external assessment, uses the dedicated system-only
`upsert_external_cvss_batch()` boundary. Caller authority is never inferred from
whether `acting_user_id` is `NULL`.

### Relationship with other modules

| Module | Relationship |
|--------|-------------|
| `services/cvss.py` | `ticket_mutations` delegates CVSS resolution and severity calculation to pure functions in `cvss.py`. The resolution cascade logic is never reimplemented inside `ticket_mutations` |
| `services/ticket_priority.py` | `refresh_priority_auto()` delegates exploitation classification and priority resolution to the pure functions defined in [ticket-priority.md](ticket-priority.md); the decision table is never reimplemented inside `ticket_mutations` |
| `services/package_service.py` | Handles ordinary package-centric mutations (track status, delivery status, standalone eligibility overrides, Product-originated recalculation, synchronous manual-zone-exit convergence, soft-delete/restore, record creation) and package queries. `package_service` imports `reconcile_ticket_status()`, `auto_assign_actor()`, and `ensure_ticket_operable()` from `ticket_mutations`; `ticket_mutations` does not import `package_service`. The atomic CVSS chain is the sole exception allowed to update system-managed Product eligibility inline, using the package-model-owned pure evaluator without copying the formula |
| `services/ticket_service.py` | Handles Ticket lifecycle operations and cross-domain Ticket compositions, including manual-zone exits. It may import both `package_service` and the primitives in this module; neither lower service imports `ticket_service`. See [ticket-service.md](ticket-service.md) for the full contract |

## State Machine Zones

The ticket state machine has two zones that determine which operations
are valid:

### Gate zone (Analysis, Analyzed, Resolved)

Status is determined automatically by `reconcile_ticket_status` based on gate
conditions. Consumer-facing `ticket_mutations` operations act on Tickets in
this zone, with the documented manual-zone exit exceptions. Trusted external
CVSS ingestion is CVE-owned maintenance and follows the separate status matrix
below.

`New` is the initial pre-gate state, not part of the gate zone. A Ticket in
`New` has not yet been admitted to automatic gate evaluation; assignment
presence does not define the status. The `New → Analysis` transition is an
explicit one-way event triggered by an assignment action, not a gate evaluation.
`reconcile_ticket_status` skips tickets in `New` status entirely — the
floor of the gate zone is `Analysis`.

### Manual zone (Ignored, Duplicated)

Status is set by explicit user actions or specific system events.
`reconcile_ticket_status` never operates on tickets in the manual zone.
Gate-relevant mutations are blocked at the service layer by
`ensure_ticket_operable()` (raises `TicketNotMutableError` → 409
`TICKET_NOT_MUTABLE`).

Confidentiality, explicit access-grant, and manual reference mutations are not
gate-relevant. Their owning `ticket_service` or `reference_service` contracts
explicitly permit them in the manual zone without assignment, reconciliation,
status change, or manual-zone exit. Manual references are supplementary
editorial metadata rather than Ticket workflow or package-gate state.

### Manual-zone exit composition

Manual-zone exit is an explicit composition owned by `ticket_service`; see
[ticket-service.md](ticket-service.md#_complete_manual_zone_exit) for its
authoritative common finalization. Each public exit workflow prepares the
`Analysis` floor, then the private helper converges Product eligibility and
calls this module's `reconcile_ticket_status()` exactly once as its final
database mutation, with the original manual-zone status as `previous_status`
and the same UTC `evaluation_date`. The primitive records the real transition
and registers one transaction-local Ticket convergence effect for every
successful manual-zone exit, including when the final evaluated status is
`Resolved`.

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
  current assignee is inactive or no longer holds any
  `vulnerability_analyst` origin (assignment-eligibility sanitation)
- May register one transaction-local Ticket convergence effect after any
  manual-zone exit or a `Resolved` gate regression, whose consumption
  publishes the package-tree and fetcher catch-up workflow

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
3. If the determined status is `Analysis` or `Analyzed`, perform Assignment
   Eligibility Sanitization before any final status audit event. Its system
   `assignment` event therefore precedes the final `status_change`. A
   `Resolved` result retains the assignee and creates no sanitation event.
4. If the determined status differs from the current status, or if
   `previous_status` is provided and differs from the determined status:
   - Update `ticket.status`
   - Create `TicketAuditEvent` with `event_type = status_change`
   - `old_value` is taken from `previous_status` if provided; otherwise
     from the ticket's current status field
5. **Post-transition Ticket convergence registration**:
   - Resolve `effective_previous`: use `previous_status` parameter if
      provided (manual-zone exits finalized by
      `ticket_service._complete_manual_zone_exit()`), otherwise
     capture the ticket's status before gate evaluation as a local
     variable at the start of the function (regression cases)
    - Resolve `new_status`: the status determined by step 2 (regardless of
      whether step 4 produced a change — see note below)
   - If `effective_previous ∈ {Ignored, Duplicated}`, register one
     transaction-local Ticket convergence effect for every successful exit,
     whether `new_status` is `Analysis`, `Analyzed`, or `Resolved`.
   - If `effective_previous = Resolved` and `new_status ∈ {Analysis,
     Analyzed}`, register the same effect. A no-change `Resolved` evaluation
     does not register it.
   - For `Ignored` or `Duplicated`, the owning manual-zone exit MUST already
     have synchronously converged automatic Product eligibility before this
     final gate evaluation. A `Resolved` regression instead follows an
     ordinary gate-zone mutation whose eligibility inputs are already current.
     The post-commit package-domain phase re-resolves every persisted
     package marker, including soft-deleted markers, through
     `package_service`; after those per-package transactions finish, it
     attempts to enqueue `catch_up()` for every registered fetcher via
     `get_catch_up_fetchers()`. Registration does not introduce a
     `ticket_mutations` → `package_service` import: the Ticket convergence
     workflow owner performs that orchestration. The workflow and failure
     isolation contract are defined in `package-service.md`
     (`run_ticket_convergence()` workflow) and `package-model.md` (Ticket
     Convergence).
   - The automatic API mutation path treats only a broker operational initial-
     publication failure as best effort: it retains the committed mutation's
     success response, emits exactly one sanitized Ticket-scoped ERROR, and
     never returns `CELERY_UNAVAILABLE`. Other publication exceptions propagate
     unchanged without reclassifying committed work. Recovery uses the complete
     explicit rerun endpoint. See the registration lifecycle below and
     `ticket-service.md` (Ticket Convergence) for the publisher boundary and
     publication policies.
   - **Note**: step 5 is independent of step 4. In the
      `ticket_service._complete_manual_zone_exit()` case, the public workflow
      has already set the status
     before invoking reconcile; step 4 sees no change but step 5
     correctly detects the manual-zone exit via `previous_status`.
     Registration follows the preserved source status;
     it does not re-check Ticket status after registration.
   - **Registration deduplication**: recursive reconciliation within the same
     caller-owned transaction registers at most one Ticket convergence effect
     for the Ticket (see the registration lifecycle below). Duplicate
     workflows across separate transactions remain safe because package
     resolution and all catch-ups are idempotent.
   - `reconcile_ticket_status()` never acquires or re-acquires a CVE lock and
     never starts another eligibility chain. CVSS assessment mutations already
     maintain `CVE.severity`; package-domain manual-zone exit owns the special
     synchronous eligibility convergence.
     Keeping this Ticket-locked primitive free of CVE acquisition prevents a
     `Ticket` then `CVE` inversion against the global CVSS lock order.
   - **Cost in the common case**: zero. When no manual-zone exit or `Resolved`
     regression occurs (the overwhelmingly common path), step 5 is a small
     status comparison
6. The function operates within the same database transaction as the
   triggering operation (atomicity guarantee)

Every query performed by one invocation, including aggregate and existence
checks, uses the same resolved `evaluation_date`. The function never persists
the lifecycle phase or actionability result.

### Assignment Eligibility Sanitization

As behavior step 3, after determining the ticket's natural status via gate
evaluation and before any final status audit event, if the resulting status is
`Analysis` or `Analyzed` and `assignee_id` is non-NULL, read the assignee's
current `User.active` value and whether any current `UserRole` origin grants
`vulnerability_analyst`. This is a fresh PostgreSQL observation made while the
caller already holds the Ticket lock; it does not acquire a User row lock or
read audit history.

1. If the User is inactive, choose exact reason `inactive assignee`.
2. Otherwise, if no VA origin exists, choose exact reason
   `vulnerability_analyst role removed`.
3. Select the reason using the canonical precedence in
   `ticket-audit-log.md`. If neither condition is true, preserve the assignee
   and create no event.
4. For an ineligible assignee, set `assignee_id = NULL` and create exactly one
   system `assignment` event with `old_value = username`, `new_value = NULL`,
   exact `comment = "Unassigned from {username}: {reason}"`, and
   `detail = NULL`.
5. Emit a warning-level log identifying only User and Ticket UUIDs plus the
   closed reason, indicating that the identity-owned lifecycle batch should
   ordinarily have handled the clear.

If the resulting status is `Resolved`, no assignee check is performed. This
includes a manual-zone exit that evaluates directly to `Resolved`: an inactive
or non-VA assignee is retained. `reconcile_ticket_status()` is not invoked for
a Ticket that remains `Ignored` or `Duplicated`.

This mechanism complements the identity-owned deactivation and final-role-loss
batches by enforcing current eligibility when a preserved inactive-status
assignment later returns to `Analysis` or `Analyzed`, and by sanitizing
anomalous current data. It is not the primary serialization mechanism for a
concurrent assignment race. Unassignment does not change the ticket's status.

> **Invariant**: ticket status reflects work state, not staffing state.
> A ticket in `Analysis`, `Analyzed`, or `Resolved` status may have
> `assignee_id = NULL` (an orphaned ticket awaiting reassignment).
> See the Architectural Invariant in
> `docs/features/tickets/tickets.md`.

### `previous_status` parameter

The `previous_status` parameter exists to handle manual-zone exit
operations correctly. The public `ticket_service` workflow sets
`status = Analysis` before `_complete_manual_zone_exit()` calls
`reconcile_ticket_status`; if the function then promotes
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

### Transaction-Local Ticket Convergence Registration

Step 5 declares one future publication effect in the caller-owned transaction.
Its lifecycle is:

1. **Registration**: append one immutable semantic effect to a registry
   attached to the caller-owned session and transaction. The effect carries
   only the Ticket's internal UUID — the primitive identity the publication
   boundary needs. Registration performs no database query, no network, Redis,
   or Celery I/O, allocates no task ID, creates no `TicketAuditEvent`, and
   publishes nothing.
2. **Deduplication and order**: at most one effect exists per Ticket in one
   transaction, and a repeated `reconcile_ticket_status()` invocation for the
   same Ticket does not add a second one. Effects for different Tickets are
   consumed in first-registration order. The registry is bound to the
   transaction and not merely to the session object, even when it is attached
   to a reusable `AsyncSession`: a new transaction inherits no pending effect
   from an earlier committed, rolled-back, or failed transaction, whether or
   not that transaction's owner drained it.
3. **Discard**: rollback, a definitely failed commit, and pre-commit
   cancellation discard the transaction's effects without publication. A commit
   exception with an ambiguous database outcome also performs no publication
   and terminates the owner workflow; it is never treated as a committed unit
   eligible for a later attempt from that session.
4. **Detach and consume**: after the caller's commit succeeds, the transaction
   owner atomically detaches the complete effect sequence before the first
   publication attempt. A detached effect is consumed exactly once even when
   its attempt fails, so a reused session cannot replay it.
5. **Interruption gap**: a process interruption between commit and the first
   attempt can lose that publication. The gap is accepted; recovery is the
   explicit complete rerun in
   `tickets.md` ([Rerun Ticket Convergence](tickets.md#rerun-ticket-convergence)).
   No outbox, persisted dispatch record, Celery result backend, Redis key,
   audit event, or progress resource is introduced.

Publication uses the detached primitive values only and performs no database
read. The database-free publisher boundary, the `submitted` and
`acceptance_unconfirmed` vocabulary, the automatic and explicit publication
policies, and the allowed logs are defined in `ticket-service.md` (Ticket
Convergence). The required registration and consumption tests are defined in
`docs/features/platform/testing-strategy.md` (Ticket Convergence Publication
Handoff).

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

An operation that can create or change `assignee_id` is the cross-domain
exception to Ticket-first acquisition. Before any CVE or Ticket lock, it
acquires `FOR SHARE` on the prospective assignee User and retains that lock
through the assignment decision and Ticket mutation. It then follows the
ordinary CVE-then-Ticket or Ticket-only order. `auto_assign_actor()` receives
that stabilized User and performs no User query after the Ticket lock. System
paths and paths that cannot assign acquire no User lock.

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

- `ticket_service.ignore_new_for_rejected_cve` — owns its explicit all-status
  system matrix and must treat non-`New` states as no-ops
- `ticket_service.reopen_from_ignored` — must operate on Ignored tickets; skips
  mutability guard
- `ticket_service.revert_duplicate` — must operate on Duplicated tickets; skips
  mutability guard
- `ticket_service.set_confidentiality` — visibility-only mutation valid in
  every Ticket status
- `ticket_service.grant_access` and `ticket_service.revoke_access` — explicit
  visibility mutations valid in every Ticket status
- `reference_service.create_reference`, `reference_service.update_reference`,
  and `reference_service.delete_reference` — supplementary editorial metadata
  mutations valid in every Ticket status
- `ticket_service.dispatch_ticket_convergence` — validates its own eligible
  status set and never produces `TICKET_NOT_MUTABLE`
- `cve_service` on-demand refetch preparation — dispatch-only operation valid
  for an accessible CVE in every associated Ticket status
- Trusted external CVSS ingestion — maintains source-owned CVE assessment and
  severity state in every Ticket status and follows the propagation
  disposition defined by the CVSS status matrix

**Consumers**:

| Module | Functions that call `ensure_ticket_operable` |
|--------|----------------------------------------------|
| `ticket_mutations` | Manual-SUSE `upsert_cvss_assessment`, `delete_cvss_assessment`, `set_severity_manual` |
| `ticket_service` | `associate_cve`, `assign_ticket`, `ignore_ticket`, `mark_as_duplicate`, `set_priority_override` |
| `package_service` | Gate-relevant mutations call the guard; `set_track_delivery_status` also calls it for operability but remains outside assignment, audit, and Ticket reconciliation |

Trusted external ingestion does not call this guard. It may maintain
CVE-owned assessment and severity state in every Ticket status but must obey
the propagation disposition returned by the mutation.

## Gate-Relevant Mutation Operations

Each ticket-mutation function below follows the same pattern unless its own
contract places semantic no-op or operation-specific guards before assignment:

1. For a user-attributed operation capable of assignment, acquire `FOR SHARE`
   on the acting User; then acquire `FOR UPDATE` on the owning CVE/Ticket roots
2. For a consumer operation, revalidate accessibility from the locked-current
   required roots
3. Call `ensure_ticket_operable(ticket)`
4. Call `auto_assign_actor()`
5. Validate additional preconditions
6. Apply the mutation
7. Create `TicketAuditEvent`
8. Call `reconcile_ticket_status()`
9. Return the updated record

Manual SUSE CVSS mutation is such an operation-specific ordering: caller and
provider authority, manual-zone mutability, and serialized effective-action
classification precede `auto_assign_actor()`. Only an effective manual SUSE
create, update, or delete may assign. Trusted external ingestion and
default-version recalculation are system actions and never assign.

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

When a consumer mutation endpoint declares `TicketDetail`, its owning workflow
follows the assembly, accessibility-reuse, evaluation-date, and rollback
contract in `ticket-service.md` (`get_ticket_detail()`). Gate-relevant functions
accept the workflow's date and pass it to reconciliation; a function that does
not otherwise use the date leaves it unchanged for final assembly.

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
the transaction's first database operation. For a manual CVSS assessment
mutation, the first persistent root is the acting User under `FOR SHARE`, then
the owning CVE under `FOR UPDATE`, followed by the associated Ticket under `FOR
UPDATE` when one exists. Trusted external ingestion has no assignment-capable
actor and retains CVE then optional Ticket. Every operation follows the
cross-domain root order in `docs/conventions.md`.

### CVSS Mutation Authority and Result

The reserved provider comparison is `provider.strip().casefold() == "suse"`.
Every equivalent case or surrounding-whitespace form is reserved. The only
stored internal provider value is the canonical string `SUSE`.

| Caller category | Provider authority | Delete authority | Actor |
|---|---|---|---|
| `MANUAL_SUSE` | May create or update only the reserved SUSE assessment; the stored provider is canonicalized to `SUSE` | May delete only `SUSE` | `acting_user_id` is required and identifies the authorized user |

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
| `eligibility_resolution` | The committed-current Eligibility Score Resolution result: score plus `suse` or `fallback`, used by the package-model-owned evaluator |
| `propagation` | `immediate`, `deferred_until_reactivation`, `not_applicable`, or `none`, as defined below |
| `evaluation_date` | The single UTC date used by lifecycle evaluation, eligibility, actionability, reconciliation, result projection, and any response containing package-tree state |
| Product summary | Examined, override-skipped, and changed occurrence counts for applied immediate propagation; all zero otherwise |
| Ticket summary | Whether auto-assignment occurred and whether one final reconciliation ran |

The result is valid inside the caller-owned transaction. It is not evidence of
durability until that transaction commits. Callers use `action` for HTTP
classification: `created` maps to 201 and `updated` or `unchanged` maps to 200.
A fetcher may map `created` or `updated` to its corresponding effect metric only
after the caller-owned transaction commits; `unchanged` has no effect metric,
and terminal success is recorded independently by the owning fetcher workflow.
Delete maps `deleted` to 204 and `not_found` to the existing 404
`CVSS_ASSESSMENT_NOT_FOUND` response. No caller may classify an outcome from an
unlocked pre-read.

Propagation dispositions describe the completed Ticket-scoped outcome:

- `immediate`: the current locked workflow MUST apply automatic Product
  eligibility and any required final Ticket reconciliation before returning.
- `deferred_until_reactivation`: an external mutation associated with an
  `Ignored` or `Duplicated` Ticket is retained for package-owned propagation
  after the explicit manual-zone exit.
- `not_applicable`: the CVE has no associated Ticket, so there is no Product
  eligibility or Ticket state to propagate.
- `none`: the serialized outcome is `unchanged` or `not_found`, so there is no
  effective mutation to propagate.

The disposition is part of every successful result and is actionable only for
`created`, `updated`, or `deleted`. `unchanged` and `not_found` return the
current resolution values with `propagation = none`.

An authority rejection, manual-zone rejection, unchanged result, not-found
result, waiting concurrent no-op, deferred Product outcome, or caller rollback
creates no assignment, Product eligibility event, Product mutation, or final
Ticket reconciliation. Direct assessment and derived-severity records and the
automatic priority refresh remain immediate for effective deferred assessment
mutations. Any settings, database, eligibility, audit, flush, or reconciliation
failure propagates and rolls back the complete caller-owned chain: assessment,
`CVE.severity`, assignment, Product eligibility, automatic priority, Ticket
status, and every audit event.

### CVSS Status Matrix

| Associated Ticket status | Manual SUSE upsert/delete | Trusted external batch | Effective Ticket-scoped outcome |
|---|---|---|---|
| No Ticket | Allowed | Not reachable: ingestion creates or loads the unique Ticket before invoking the batch | Manual result is `not_applicable`; CVE-owned state only |
| `New` | Allowed; effective mutation may auto-assign the VA | Allowed; never assigns | `immediate`; an unassigned `New` remains outside gate reconciliation unless manual auto-assignment first moves it to `Analysis` |
| `Analysis` | Allowed; effective mutation may auto-assign the VA | Allowed; never assigns | `immediate` eligibility and at most one final reconciliation |
| `Analyzed` | Allowed; effective mutation may auto-assign the VA | Allowed; never assigns | `immediate` eligibility and at most one final reconciliation |
| `Resolved` | Allowed; effective mutation may auto-assign the VA | Allowed; never assigns | `immediate` eligibility and at most one final reconciliation; ordinary regression to `Analyzed` or `Analysis` is allowed |
| `Ignored` | Reject with `TicketNotMutableError`; no result | Allowed; never assigns | External CVE-owned state and direct audit only; Product/gate effects wait for explicit exit |
| `Duplicated` | Reject with `TicketNotMutableError`; no result | Allowed; never assigns | External CVE-owned state and direct audit only; Product/gate effects wait for explicit exit |

External delete is rejected for every row of the matrix. An effective
assessment mutation always recomputes and persists `CVE.severity`, including
for a ticketless CVE and a CVE associated with an inactive Ticket. Automatic
eligibility includes every Product occurrence regardless of exclusion,
actionability, or affectedness and skips only manual overrides. Immediate
propagation performs a final reconciliation only when a gate input changed or
manual assignment moved `New` into `Analysis`: Product eligibility changed,
unified severity changed, or the existence of any canonical SUSE assessment
across accepted versions changed between absent and present.
It still performs at most one such reconciliation after every direct and
Product audit record. An effective non-SUSE update that changes none of those
gate inputs does not reconcile.

Default-version recalculation uses the same state rows but is always a system
operation. It targets every persisted CVE: ticketless CVEs receive severity
only; `New` receives severity plus automatic eligibility but remains outside
gate reconciliation; `Analysis`, `Analyzed`, and `Resolved` receive severity
plus automatic eligibility and at most one reconciliation; `Ignored` and
`Duplicated` receive severity and a direct `severity_changed` event when that
value changes, but no eligibility, assignment, status, manual-zone exit, or
final reconciliation effect. Every associated Ticket, in every status, also
receives the automatic priority refresh defined in
[ticket-priority.md](ticket-priority.md).

### `upsert_cvss_assessment()`

Creates or updates the manual SUSE `CVECVSSAssessment` record for a CVE. The function
accepts a `cve_id` (not a `ticket_id`) and handles both CVEs with and
without an associated ticket. If an assessment for the same
`(cve_id, provider, version)` already exists, it is updated; otherwise a
new one is created. External-provider assessments never use this boundary.

**Parameters**:

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `db` | `AsyncSession` | Yes | Database session |
| `cve_id` | `UUID` | Yes | CVE that receives the assessment |
| `provider` | `str` | Yes | Assessment provider; must resolve to canonical `"SUSE"` |
| `vector_string` | `str` | Yes | CVSS vector string (version, score, and severity derived from it) |
| `caller` | `CVSSMutationCaller` | Yes | Must be `MANUAL_SUSE`; authority is not inferred from actor presence |
| `acting_user_id` | `UUID` | Yes | Authorized acting user |
| `default_cvss_version` | `str \| None` | No | Version used for severity and eligibility resolution. If `None`, read it once from `settings_service.get_default_cvss_version(db)` after root locking |
| `evaluation_date` | `date \| None` | No | UTC date for the complete immediate Product/reconciliation chain. If omitted, capture once at function entry |

**Preconditions**:

- Vector must be parseable — raises `InvalidCVSSVectorError`
- CVE must exist for `cve_id`; locked-current absence returns `CVE_NOT_FOUND`
- Caller category, actor, and provider must satisfy the authority table

**Return type**: `CVSSAssessmentMutationResult`, as defined above.

**Behavior**:

1. Validate caller/provider authority and parse the vector using only input
   data. Derive the exact version, canonical vector, decimal score, and
   version-specific assessment severity. Parsing failure raises
   `InvalidCVSSVectorError` before database access.
2. Acquire `FOR SHARE` on the acting User and stabilize current active/VA
   eligibility, then load the CVE with `FOR UPDATE`. If the User is no longer
   eligible, the effective CVSS mutation continues but its assignment step is
   skipped. If the CVE does not exist, return the CVE-path `CVE_NOT_FOUND`
   outcome.
3. Load the Ticket associated with that locked CVE, if any, with `FOR UPDATE`.
   This makes concurrent association compose in `CVE` then `Ticket` order.
4. Revalidate CVE accessibility from the locked CVE and its
   locked-current associated Ticket before reading assessment state. Denial is
   the CVE-path `CVE_NOT_FOUND` outcome.
5. Apply the status matrix and reject a locked manual-zone Ticket before any
   write.
6. Resolve `default_cvss_version`: if the parameter is `None`, read it once from
   `settings_service.get_default_cvss_version(db)`. Use this one value for both
   severity and eligibility resolution in this invocation.
7. Load the existing assessment for the canonical natural key under the CVE
   lock. Compare its persisted canonical vector with the incoming canonical
   vector, not with raw input text.
8. Classify and apply `created`, `updated`, or `unchanged` from that serialized
   state. `unchanged` resolves and returns the current severity and eligibility
   values without assignment, audit, severity write, package propagation,
   Ticket reconciliation, or metric.
9. For an effective create/update, persist the canonical vector and all parsed
   fields. Re-resolve the complete committed-current assessment set and always
   persist the resulting unified value to `CVE.severity`, including when its
   value is unchanged.
10. For an effective mutation with an associated Ticket, call
    `auto_assign_actor()` after the serialized action is known. If assignment
    moves `New` to `Analysis`, its
   `assignment` and system `status_change` records precede the CVSS records.
11. If a Ticket exists, create `cvss_assessment_changed`. If unified severity
    changed, create `severity_changed` next. Both are direct consequences and
    are created in every Ticket status; they are not deferred with Product
    propagation.
12. Resolve the Eligibility Score result. For `immediate`, reload every Product
    occurrence and its current threshold, lifecycle inputs, override marker,
    and eligibility under the held roots. Apply the canonical pure evaluator,
    skip overrides, and update changed booleans only. Create one system-
    attributed `product_eligibility_changed` event per change with
    `reason = cvss`, ordered by `TicketPackageProduct.id`. Then, for an
    effective mutation with an associated Ticket and whatever the propagation
    disposition, call `refresh_priority_auto()`; an optional system
    `priority_changed` follows any Product events. Priority is not a gate input
    and does not by itself trigger step 13.
13. If the Ticket is now in the gate zone and this effective chain changed a
    gate input or moved `New` into `Analysis`, call
    `reconcile_ticket_status()` exactly once with the same `evaluation_date`.
    Deferred, ticketless, and still-unassigned `New` outcomes do not reconcile.
14. Flush and return `CVSSAssessmentMutationResult`. Perform no network,
    Redis, Celery, or other post-commit effect while either root lock is held.

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
manual SUSE user. A changed derived severity adds `severity_changed` with
`user_id = NULL`. A changed effective priority adds system `priority_changed`
after the Product events and before the optional final gate `status_change`.

---

### `upsert_external_cvss_batch()`

System-only Category A boundary for one canonical CVE ingestion payload. It is
the only boundary through which `cve_service.upsert_cve()` applies one or more
trusted external assessments. API handlers, fetchers, tasks, and other services
do not call it directly; `cve_service` is the orchestrator.

```python
async def upsert_external_cvss_batch(
    db: AsyncSession,
    *,
    cve_id: UUID,
    assessments: Sequence[ParsedExternalCVSSAssessment],
    evaluation_date: date,
) -> ExternalCVSSBatchResult:
```

`ParsedExternalCVSSAssessment` carries the non-reserved canonical provider and
the immutable stable parsed result from `cvss.validate_cvss_vector()`. It is an
internal semantic type, not a Pydantic API schema or persisted entity. The
caller has already skipped individually invalid candidates and rejected
contradictory same-key candidates before writes under `cve-service.md`.

`ExternalCVSSBatchResult` is transaction-local and contains the per-candidate
`created`, `updated`, or `unchanged` actions in canonical order, final severity
and eligibility resolutions, propagation disposition, Product counts split into
examined, override-skipped, and changed occurrences, whether severity changed,
whether one final reconciliation ran, and the supplied `evaluation_date`. Any
effective assessment action contributes an effective CVSS child change to
`UpsertResult.action`; skipped candidates do not.

**Guards**:

- `evaluation_date` is required; this boundary never captures a replacement.
- Every provider must be non-empty, no longer than 100 characters, and not
  equivalent to reserved `SUSE` after outer trim and Unicode case-folding.
- Every item must contain a complete canonical parsed result for an accepted
  version, and the sequence must contain at most one canonical item for each
  `(provider, version)` key.
- A missing `evaluation_date`, missing CVE UUID, malformed parsed-result type,
  empty or over-length provider, reserved provider, or duplicate canonical key
  raises `ValueError`. These are internal contract failures, not API outcomes.

All guards use input only and complete before persistent writes. An empty
sequence is valid and returns an unchanged batch without reading settings,
writing severity, propagating eligibility, reconciling, or creating audit.

**Behavior**:

1. Sort candidates by version `4.0`, `3.1`, `3.0`, `2.0`, then canonical
   provider ascending by Unicode code point. The order is identical to the
   bounded CVSS list's version/provider order in `cvss-scoring.md`; it is not the
   multi-factor Severity Resolution Cascade. Database collation and input order
   never control mutation or event order.
2. As the first persistent read, obtain the CVE with `FOR UPDATE`, then obtain
   its unique associated Ticket with `FOR UPDATE` when one exists. When called
   by `upsert_cve()`, both are same-transaction locks already held; reacquisition
   is a no-op and does not change the global CVE-then-Ticket order.
3. Read `default_cvss_version` exactly once through
   `settings_service.get_default_cvss_version(db)`. The same value governs the
   final severity and eligibility resolutions.
4. For each candidate in canonical order, compare the canonical vector with the
   serialized current natural-key row. Create, update, or classify unchanged.
   Persist every effective candidate's complete vector-derived unit. Do not
   resolve severity, propagate Product eligibility, or reconcile between
   candidates.
5. When a Ticket exists, create one system-attributed
   `cvss_assessment_changed` event for each effective candidate, in the same
   canonical order. An unchanged candidate creates no event.
6. After all candidate writes, resolve the complete final assessment set once.
   If at least one candidate was created or updated, persist the resulting
   `CVE.severity` once. If the unified value changed and a Ticket exists, append
   at most one system-attributed `severity_changed`. An all-unchanged batch
   performs no severity write.
7. Resolve eligibility once from that same complete set and default version.
   Apply the status matrix to the post-assessment locked-current Ticket. For
   `New`, `Analysis`, `Analyzed`, and `Resolved`, evaluate every system-managed
   Product once, skip overrides, update effective differences, and append
   `product_eligibility_changed` in ascending `TicketPackageProduct.id` order.
   For `Ignored` and `Duplicated`, defer Product and gate effects. A ticketless
   CVE has no Ticket-scoped propagation. When at least one candidate was
   created or updated and a Ticket exists, then call `refresh_priority_auto()`
   in every Ticket status, including `Ignored` and `Duplicated`; the refresh is
   not deferred.
8. For a gate-zone Ticket, call `reconcile_ticket_status()` at most once, after
   every assessment, severity, Product, and priority event, and only when final
   gate input changed. An unassigned `New` remains outside gate reconciliation. Use the
   supplied `evaluation_date` throughout.
9. Flush and return the complete batch result. Do not commit, roll back, assign,
   exit a manual zone, perform network I/O, or publish a post-commit effect.

The batch is atomic. Settings, database, audit, eligibility, flush,
reconciliation, cancellation, and programming failures propagate unchanged and
roll back every assessment in the batch plus the caller's complete per-CVE
transaction. No per-assessment savepoint converts an unexpected failure into a
skip. Re-invocation with equal canonical candidates returns only unchanged
actions and performs no severity/Product/status write or event.

**Audit order**: for a Ticket, zero or more canonical
`cvss_assessment_changed`, at most one `severity_changed`, zero or more Product
events in occurrence-ID order, at most one system `priority_changed`, optional
assignment-eligibility sanitation, and at most one final gate `status_change`.
A ticketless batch creates no Ticket event. An empty or all-unchanged batch does
not refresh priority; `cve_service.upsert_cve()` performs its own refresh after
the batch.

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
| `evaluation_date` | `date \| None` | No | UTC date for the complete immediate Product/reconciliation chain. If omitted, capture once at function entry |

**Preconditions**:

- Caller must have manual SUSE authority and provider must resolve to canonical
  `SUSE`

**Return type**: `CVSSAssessmentMutationResult`, as defined above. The
`not_found` action maps to `CVSSAssessmentNotFoundError` at the API boundary.

**Behavior**:

1. Validate caller/provider authority and the accepted version using only input
   data. External caller categories and external providers raise `ValueError`;
   they cannot use this deletion boundary.
2. Acquire `FOR SHARE` on the acting User and stabilize current active/VA
   eligibility; then load the CVE with `FOR UPDATE` and its associated Ticket,
   if any, with `FOR UPDATE`. An ineligible User does not block an otherwise
   effective delete but makes its assignment step a skip. A missing CVE
   produces the consumer CVE-path `CVE_NOT_FOUND` outcome.
3. Revalidate consumer CVE accessibility from the locked CVE and its
   locked-current associated Ticket. Denial produces `CVE_NOT_FOUND` before
   status, assessment existence, no-op, assignment, or mutation decisions.
4. Apply the status matrix. Reject manual-zone Tickets before any write.
5. Resolve `default_cvss_version`: if the parameter is `None`, read it once from
   `settings_service.get_default_cvss_version(db)`. Use this one value for both
   severity and eligibility resolution in this invocation.
6. Load the canonical SUSE assessment under the CVE lock. If absent, resolve
   and return the current severity and eligibility values with `not_found`, but
   perform no write, audit event, package propagation, or metric.
7. Snapshot the canonical audit value and delete the assessment. Re-resolve the
   complete remaining assessment set and always persist the resulting unified
   value, including `NULL`, to `CVE.severity`.
8. If a Ticket exists, call `auto_assign_actor()` for the effective manual
   mutation. Its optional assignment and `New → Analysis` events precede the
   direct delete events.
9. Create `cvss_assessment_changed` with the snapshot as `old_value` and `NULL`
   as `new_value`. If unified severity changed, create system-attributed
   `severity_changed` next.
10. Resolve the Eligibility Score result and derive propagation from the status
    matrix. For `immediate`, apply the same locked-current automatic Product
    procedure, event ordering, and override skip as upsert step 12. Then, when a
    Ticket exists and whatever the propagation disposition, call
    `refresh_priority_auto()`.
11. Perform at most one final reconciliation under the same trigger and
    `evaluation_date` rule as upsert step 13, then flush and return `deleted`.
    Perform no network, Redis, Celery, or other post-commit effect under locks.

**TicketAuditEvent**: optional assignment and `New → Analysis`, then
`cvss_assessment_changed` for `deleted`, optional `severity_changed`, Product
eligibility events in occurrence-ID order, optional system `priority_changed`,
and optional final gate `status_change`. Direct CVSS records use
`detail = NULL`. `not_found`, rejection, and rollback leave no event or other
side effect.

---

### `set_severity_manual()`

Sets or clears the `severity_manual` field on a ticket.

**Parameters**:

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `db` | `AsyncSession` | Yes | Database session |
| `ticket_id` | `UUID` | Yes | Ticket to modify |
| `severity` | `Severity \| None` | Yes | New severity value (`Critical`, `High`, `Medium`, `Low`, or `None` for CVSS score 0.0 / informational), or Python `None` to clear the value (sets `severity_manual` to SQL `NULL` = unresolved) |
| `acting_user_id` | `UUID` | Yes | Authorized acting user performing the action |
| `evaluation_date` | `date \| None` | No | UTC date shared by reconciliation and any TicketDetail response; capture once at entry when omitted |

**Preconditions**:

- Ticket must be operable (`ensure_ticket_operable`)
- Ticket must have `cve_id IS NULL` — raises `SeverityDerivedError`
  if the ticket has an associated CVE (severity is derived from CVSS
   scores and cannot be set manually)

**Behavior**:

1. Acquire `FOR SHARE` on the acting User, then `FOR UPDATE` on the Ticket row
2. Revalidate consumer accessibility from the locked-current Ticket. Missing or
   inaccessible produces `TICKET_NOT_FOUND` before operability, derived-severity,
   or no-op decisions
3. Call `ensure_ticket_operable(ticket)`
4. Validate preconditions
5. If severity unchanged, return (no-op)
6. Call `auto_assign_actor(ticket, acting_user, db)` with the User stabilized by
   step 1
7. Update `ticket.severity_manual`
8. Create `TicketAuditEvent` (`severity_changed`, `user_id = acting_user_id`),
   then call `refresh_priority_auto()`; a changed effective priority adds a
   system `priority_changed`
9. Call `reconcile_ticket_status()` with the supplied or once-captured
   `evaluation_date`
10. Return updated ticket

**Gate relevance**: setting `severity_manual` affects the ticket's
resolved severity, which is gate-relevant (Analyzed gate #3 requires
severity). This operation is only valid when `cve_id IS NULL` — when a
CVE is associated, severity is derived from CVSS scores via the
resolution cascade and `severity_manual` is not applicable.

**TicketAuditEvent**: `severity_changed`, then optional system
`priority_changed`, before any final gate `status_change`

**Idempotency**: no-op if severity is unchanged.

---

### `recalculate_cvss_chain()`

Recalculates CVE-owned severity from current assessments and, according to its
typed invocation mode and locked Ticket state, applies the narrow automatic
Product eligibility exception. It does not create, update, or delete a
`CVECVSSAssessment` and never changes an override.

**Callers**: `associate_cve()` and the batch recalculation Celery task triggered
by the manual recalculation endpoint (see
`docs/features/platform/default-cvss-version-operations.md`). This contract
defines no Ticket convergence caller.

**Parameters**:

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `db` | `AsyncSession` | Yes | Database session |
| `cve_id` | `UUID` | Yes | CVE whose assessment set and associated Ticket, if any, are recalculated |
| `mode` | association or default-version semantic mode | Yes | Selects the caller-owned composition and its state-specific side effects; the concrete enum/type is an implementation choice |
| `association_previous_severity` | `Severity \| None` | Conditional | Required in association mode, where it carries the Ticket's pre-association manual severity, including `NULL`; omitted in default-version mode |
| `default_cvss_version` | `str \| None` | No | The CVSS version to use for severity resolution and eligibility evaluation. If `None` (default), the function reads the current version from `settings_service.get_default_cvss_version(db)`. The batch recalculation task provides this explicitly (passed as a task argument from the triggering endpoint) to ensure all CVEs in a batch use the same version. Other callers should typically omit this parameter |
| `evaluation_date` | `date \| None` | No | UTC date used by Product propagation and Ticket reconciliation as one temporal input. If omitted, capture once at function entry |

**Behavior**:

1. Acquire `FOR UPDATE` on the CVE as the first persistent read, then load and
   lock its associated Ticket, if any. A CVE without an associated Ticket uses
   `not_applicable`. In default-version mode, a lock lookup that returns no CVE
   row is the `missing` result defined under Runner-facing classification
   below; association mode retains its existing precondition that
   `associate_cve()` has already resolved and locked the CVE. This function
   does not call `ensure_ticket_operable()`:
   association mode has already passed that caller-owned guard, while default-
   version mode must maintain CVE-owned severity for every Ticket status and
   applies only the state-specific Product/gate effects below. Association mode
   likewise relies on `associate_cve()` having completed locked-current consumer
   accessibility under the same caller-owned User-then-CVE-then-Ticket
   transaction; this function performs no independent caller-scope evaluation.
   Default-version
   mode is a system operation and has no consumer scope.
2. Resolve `default_cvss_version`: if the parameter is `None`, read
   from `settings_service.get_default_cvss_version(db)`. Call
   `cvss.resolve_severity_score()` with the complete assessment set to obtain
   the committed-current resolution.
3. Capture the old `CVE.severity`, then persist the resolved unified label, or
   `NULL` for absent. When a Ticket exists and the applicable old and new
   effective severity differ, create the system-attributed `severity_changed`
   event before any Product event. Association mode compares
   `association_previous_severity` with the new CVE severity so the event
   records the manual-to-derived handover; default-version mode compares the
   old and new CVE severity. A ticketless CVE creates no Ticket event.
4. Call `cvss.resolve_eligibility_score()` with the resolved
   `default_cvss_version` to obtain the score and `suse`/`fallback` source.
5. Apply the selected mode:
   - **association**: use the newly associated Ticket and current persisted
     inputs to recalculate every automatic Product occurrence. Do not assign;
     `associate_cve()` already performed its one assignment step. Create Product
     events in occurrence-ID order after the handover event. Return the result
     so the association owner performs its one final reconciliation.
   - **default version**: apply the default-version state matrix to the supplied
     CVE. The owning `recalculate_cvss_derived_state` operation invokes this
     mode once for every persisted CVE. A ticketless CVE receives severity
      only. `New` receives automatic eligibility but no gate reconciliation.
      `Analysis`, `Analyzed`, and `Resolved` receive automatic eligibility and,
     when a gate input changed, this function performs exactly one final
     reconciliation after all severity and Product events. A `Resolved`
     regression registers the normal transaction-local Ticket convergence
     effect for the package-tree and fetcher catch-up. `Ignored` and
     `Duplicated` receive only CVE severity and its
     direct event when changed. No state assigns or exits the manual zone.
6. For an applicable Product phase, reload current Product thresholds,
   lifecycle dates, overrides, and booleans under the roots; use the shared pure
   evaluator; create `reason = cvss` events in ascending occurrence-ID order;
   and never alter overrides. Use the one `evaluation_date` throughout. When a
   Ticket exists, in both modes and every Ticket status, then call
   `refresh_priority_auto()` after the severity and Product steps and before
   the default-version mode's optional final reconciliation; association mode
   thereby refreshes priority from the newly associated CVE before
   `associate_cve()` reconciles.
7. Flush and return severity resolution, eligibility resolution, changed and
   skipped Product counts, whether severity changed, propagation, whether one
   reconciliation ran, `evaluation_date`, and the runner-facing classification
   below.

**Runner-facing classification**: the returned result classifies the unit
transaction-locally as exactly one of:

- `changed` — the unit contains at least one durable semantic mutation or its
  required audit event: a changed `CVE.severity`, an automatic Product
  eligibility change, a changed `Ticket.priority_auto` (including one masked by
  an override and therefore without an event), assignment-eligibility
  sanitation, a Ticket status change, or an audit event required by one of those
  effects. A reconciliation
  call that changes nothing does not by itself make a unit `changed`.
- `unchanged` — the unit succeeded already converged and contains no mutation
  and no audit event.
- `missing` — default-version mode found no CVE row after the lock lookup. A
  `missing` result creates no audit event, no Product mutation, no
  reconciliation, and no per-unit error; the all-CVE runner reports it as
  `skipped`. Association mode keeps its own precondition and never uses
  `missing` as a normal consumer outcome.

The classification describes the unit transaction; the transaction owner applies
it to the committed unit. The concrete result type is an implementation choice;
the three-way classification and its meaning are not.

**TicketAuditEvent**: this function creates the required system-attributed
`severity_changed` event when effective severity changes. Association mode uses
the caller-supplied pre-association manual value so exactly one event records the
manual-to-derived handover. The function then creates one system-attributed
`product_eligibility_changed` event per changed automatic occurrence when its
mode applies Product propagation, followed by an optional system
`priority_changed` when the effective priority changes. Default-version
reconciliation may append one final `status_change`; association leaves that
final event to its caller.

**Idempotency**: safe to call multiple times. With unchanged assessments and
default version, severity, Product values, and audit are no-ops and the same
current result is returned.

### Read-Only Impact Projection

The default-CVSS impact preview in
`docs/features/platform/default-cvss-version-operations.md` projects the
semantic outcomes of default-version mode without invoking any mutation
function in this module. It does not call `recalculate_cvss_chain()`, does not
acquire a mutation lock, and does not participate in the runner's execution.

- It projects the same outcomes as the default-version recalculation
  paragraph of the CVSS Status Matrix, substituting projected values for
  persistence and adding no effect of its own.
- It creates no audit event, no assignment, no Product mutation, no final
  `reconcile_ticket_status()` invocation, no manual-zone exit, and no
  post-commit effect.
- It does not project Ticket priority; no preview count reflects a priority
  change.
- A currently `Resolved` Ticket whose projected gate result is `Analyzed` or
  `Analysis` contributes one regression count. Promotions, demotions of
  `Analysis` or `Analyzed` Tickets, and no-change evaluations are not separate
  preview categories, and the preview returns no Ticket-scoped detail.
- Projected Product eligibility uses the current persisted inputs and the
  shared package-model evaluator. A projected boolean is never persisted, and
  an occurrence with `is_eligible_override = true` is reported as a skip
  without changing either field.

## Utility Functions

### `refresh_priority_auto()`

Recomputes `Ticket.priority_auto` from the locked-current resolved severity and
exploitation evidence, persists a changed value, and creates a system
`priority_changed` event only when the effective priority changes. It requires
the caller's Ticket lock and, for a CVE-associated Ticket, the preceding CVE
lock; it acquires no lock, performs no accessibility or operability check, and
never assigns or reconciles. The complete contract and every caller position
are owned by [ticket-priority.md](ticket-priority.md#refresh_priority_auto);
this is a cross-reference overview. Callers are the CVSS chains and
`set_severity_manual()` in this module, `ticket_service.create_ticket()` for
manual creation, and `cve_service.upsert_cve()`.

## Auto-Assignment Rule

When an active user with the `vulnerability_analyst` role performs any modifying
operation on a ticket with `assignee_id = NULL`, the ticket is
automatically assigned to the acting user. A `TicketAuditEvent` with
`event_type = assignment` is created atomically in the same transaction
as the modifying operation. If the acting user is inactive or does not hold the
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

This rule does not apply to system operations (`acting_user is None`),
inactive users, or users without the `vulnerability_analyst` role.
Manual reference create, update, and delete also do not call this helper: they
change supplementary editorial metadata without assignment, gate
reconciliation, status change, or manual-zone exit.
It also does not apply when a `package_service` invocation creates only
system-derived `TicketPackageMaintainer` associations. The package service does
not call this helper for that association-only mutation; it calls the helper
normally when the same invocation also changes package-tree state.

### `auto_assign_actor()`

A public helper function that implements the auto-assignment check. Mutation
modules pass the prospective User they locked `FOR SHARE` before the Ticket and
call the helper under the Ticket `FOR UPDATE` lock when their owning operation
requires auto-assignment. The association-only maintainership exception above
does not call it.

**Signature**:

```python
async def auto_assign_actor(
    ticket: Ticket,
    acting_user: User | None,
    db: AsyncSession,
    force: bool = False,
) -> bool:
    """Assign ticket to acting user if user is active and holds the VA role.

    When force=False (default): assigns only if ticket is currently
    unassigned. Used by all gate-relevant mutations as step 2.

    When force=True: assigns regardless of current assignee. Used only by
    ticket_service manual-zone exit functions (reopen_from_ignored,
    revert_duplicate) to take ownership. Other ticket_service functions,
    package_service, API handlers, and background tasks MUST NOT pass
    force=True — doing so is a bug.

    Returns True if assignment was applied (audit event created),
    False otherwise.

    Preconditions: caller MUST hold FOR SHARE on a non-None acting_user before
    FOR UPDATE on the ticket row, must have resolved that locked User's current
    VA-origin membership before the Ticket lock, and must still hold both locks.
    """
```

**Behavior**:

1. If `acting_user is None` → return False (system action)
2. If not `force` and `ticket.assignee_id is not None` → return False
   (already assigned)
3. Use the caller's locked-current active value and VA-origin membership. If
   the locked User is inactive or has no current VA role origin, return False.
   A pre-lock in-memory role collection is not authoritative; the caller loads
   or refreshes membership while holding the User lock and before acquiring the
   Ticket lock. The helper performs no User query or lock while holding the
   Ticket lock
4. If `ticket.assignee_id == acting_user.id` → return False (assignment
   unchanged, no audit event)
5. Set `ticket.assignee_id = acting_user.id`
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
> assignment-eligibility sanitation and correct gate evaluation.

## Related Operations

Ticket lifecycle operations and cross-domain compositions (assignment, CVE
association, manual-zone entry and exit, confidentiality, and access-grant
management) live in `ticket_service` —
see [ticket-service.md](ticket-service.md) for the full service contract.

These operations use the same `FOR UPDATE` pattern documented in
[Concurrency Control](#concurrency-control) and create their own
`TicketAuditEvent` records. Some call `reconcile_ticket_status()` due
to indirect gate effects (severity source change, promotion evaluation
after assignment, status reconciliation after restore).

## Contract

Every service-layer operation that modifies data relevant to Ticket status
gates MUST go through the appropriate centralized module:

- **Package/track/product mutations**: `package_service`
  (`TicketPackageTrack` status, delivery status, standalone
  `TicketPackageProduct` eligibility overrides, soft-delete/restore, record
  creation, additive maintainership association)
- **CVSS and severity mutations**: `ticket_mutations`
  (`CVECVSSAssessment` records, manual severity, and the narrow atomic write of
  system-managed Product eligibility required by a CVSS/default-version chain)
- **Ticket status evaluation**: `ticket_mutations` (the shared
  service-internal primitive is called after an effective gate-relevant
  mutation; delivery-status mutation is explicitly not gate-relevant)
- **Automatic Ticket priority**: `ticket_mutations.refresh_priority_auto()` is
  the only writer of `Ticket.priority_auto`; `ticket_service` owns the manual
  `priority_override`. Priority is not gate-relevant (see
  [ticket-priority.md](ticket-priority.md))

Direct modification of gate-relevant records outside the owning module is a
bug. `package_service` owns every standalone, creation, threshold, lifecycle,
override, and manual-zone-exit eligibility mutation. The sole exception lets
`ticket_mutations` update only automatic Product eligibility inline while it
owns the `CVE` then `Ticket` locks for the atomic CVSS chain. It reuses the one
package-model evaluator, does not import `package_service`, and may not mutate
affectedness, delivery, release, exclusion, hierarchy, or override state.

Ticket lifecycle operations and cross-domain Ticket compositions live in
`ticket_service` — see `docs/features/tickets/ticket-service.md`. Some of these
operations compose package or CVSS boundaries with `reconcile_ticket_status`
due to indirect gate effects. CVE association uses this composition because it
changes the severity source; manual-zone exits compose package-owned
eligibility convergence before their final gate evaluation; assignment calls
`reconcile_ticket_status` directly for promotion evaluation. The
per-function documentation in `ticket-service.md` specifies exactly
which operations call `reconcile_ticket_status` and why.

## Architectural Test Requirement

A parametrized integration test MUST be implemented to verify that the
`ticket_mutations` module produces the correct ticket status after every
ticket-centric primitive it owns (CVSS assessment operations, manual severity,
and status reconciliation). The test must cover:

- **Forward transitions**: CVSS and severity changes causing ticket
  advancement
- **Backward transitions**: CVSS deletion breaking gate conditions
- **No-op cases**: serialized `unchanged` and `not_found` assessment outcomes.
  Effective mutations whose resolved severity stays unchanged separately prove
  that SUSE-presence, eligibility, and reconciliation consequences still apply
- **Edge cases**: ticket without CVE (no SUSE CVSS gate), manual
  severity on CVE-less ticket
- **CVSS status matrix**: manual SUSE operations for a ticketless CVE and every
  Ticket status, plus the trusted-external batch for every associated-Ticket
  status. External persistence uses `deferred_until_reactivation` package
  propagation only for `Ignored` and `Duplicated`; both mutation boundaries are
  immediate on `Resolved`. Verify manual rejection in the manual zone and no
  Product or reconciliation effect for unchanged, not-found, rejected,
  deferred, empty-batch, or rolled-back outcomes
- **Eligibility formula and boundaries**: override-first precedence,
  Reactive Support for automatic records only, NULL threshold as `0.0`, NULL
  lifecycle as no lifecycle override, SUSE/default-version score or 10.0
  fallback including CVE-less Tickets, and proof that EOL, exclusion,
  affectedness, delivery, and severity-cascade winners are not inputs
- **Manual SUSE assignment**: an effective manual create, update, or delete
  assigns an unassigned Ticket only when the actor is active and holds the VA
  role, after
  no-op/not-found classification; `New` produces assignment then system
  `New → Analysis`; the external batch and default-version recalculation never
  assign
- **CVE severity ownership**: every effective assessment create, update, and
  delete updates ticketless and inactive-state `CVE.severity`
- **Serialized outcomes**: canonical-vector no-op, create/update and
  delete/not-found races, concurrent upsert/upsert, upsert/delete, and
  association/CVSS mutation using independent database sessions; each result,
  HTTP/metric classification, audit payload, and propagation result reflects
  the committed winner after `CVE` then `Ticket` locking
- **Authority and audit**: reserved SUSE variants, caller/actor mismatch,
  external-delete rejection, every-status direct events when a Ticket exists,
  ticketless no-event behavior, system-derived severity attribution, event
  ordering, Product event ordering by `TicketPackageProduct.id`, exact
  `reason = cvss`/`reactivation`, override and state skips, metadata-only
  override clear with equal boolean old/new values, and rollback atomicity
- **Complete atomic chain**: one UTC `evaluation_date` across lifecycle,
  eligibility, actionability, reconciliation, result, and package-tree
  response; at most one final reconciliation after all Product events; and
  rollback of assessment, severity, assignment, Product values, Ticket status,
  and every event for settings, database, audit, flush, or reconciliation error
- **Composed workflows**: CVE association consumes pre-existing assessments,
  updates automatic Products without a second assignment, and reconciles once;
  default-version processing visits every persisted CVE, applies Product/gate
  effects to `New`, `Analysis`, `Analyzed`, and `Resolved`, permits ordinary
  `Resolved` regression, and never exits `Ignored` or `Duplicated`; the
  `reconcile_ticket_status()` primitive supports the ticket-service-owned
  manual-zone exit after package convergence without acquiring a CVE lock
- **SUSE gate independence**: each accepted SUSE version alone satisfies the
  gate; external-only assessments do not; first-SUSE and last-SUSE changes may
  trigger reconciliation, while another SUSE addition or removal leaves the
  completeness predicate unchanged; default-version eligibility and the full
  severity cascade remain independent
- **Independent-session races**: CVSS/CVSS, CVSS/override,
  CVSS/reactivation, and default-version/CVSS races recompute from
  winner-current assessments, setting, threshold, lifecycle, override,
  Product, and Ticket state and never duplicate assignment, Product events, or
  final reconciliation
- **Locked-current consumer accessibility**: for manual severity and manual SUSE
  CVSS upsert/delete, race preliminary delegated access with confidentiality, explicit
  grant, and last included-package maintainership changes. Verify
  accessibility is revalidated only after the required Ticket or CVE-then-Ticket
  roots are locked; Ticket paths return `TICKET_NOT_FOUND`, CVE paths return
  `CVE_NOT_FOUND`; and denial leaves assessment, severity, assignment, Product,
  Ticket status, audit, reconciliation, and post-commit state unchanged. Trusted
  external ingestion and system recalculation remain unscoped
- **Automatic priority**: every CVSS chain, the external batch, and manual
  severity refresh `priority_auto` in the documented position; priority changes
  alone never trigger reconciliation, assignment, or a status change; deferred
  manual-zone batches still refresh priority; and default-version units whose
  only mutation is `priority_auto` classify `changed`. The complete matrix is in
  [ticket-priority.md](ticket-priority.md#testing-requirements)

Package-centric mutation tests are specified in
`docs/features/packages/package-service.md` (Architectural Test
Requirement). Complete manual-zone exit composition tests are specified in
`docs/features/tickets/ticket-service.md` (Architectural Test Requirement).

## Service Exceptions

All exceptions in this module inherit from `TicketMutationsError`.
API endpoint handlers catch `TicketMutationsError` subclasses and map
them to the corresponding HTTP status code and error code per
`api-spec.md`.

| Exception | HTTP | Code | Raised when |
|-----------|------|------|-------------|
| `TicketNotFoundError` † | 404 | `TICKET_NOT_FOUND` | Consumer Ticket locator is malformed, does not exist, or identifies an inaccessible Ticket; an internal UUID lookup may also be absent |
| `TicketNotMutableError` † | 409 | `TICKET_NOT_MUTABLE` | Ticket is in manual zone (Ignored or Duplicated) |
| `CVSSAssessmentNotFoundError` | 404 | `CVSS_ASSESSMENT_NOT_FOUND` | No SUSE assessment exists for the accepted `(cve_id, cvss_version)` after the CVE itself was resolved |
| `InvalidCVSSVectorError` | 422 | `CVSS_INVALID_VECTOR` | CVSS vector string is malformed or invalid |
| `InvalidTransitionError` † | 409 | `TICKET_INVALID_TRANSITION` | Requested status transition is not allowed |
| `SeverityDerivedError` † | 409 | `TICKET_SEVERITY_DERIVED` | Cannot manually set severity when it is auto-derived |

† Shared exception — inherits from `ServiceError`, not from
`TicketMutationsError`. Handlers must catch it explicitly.

Caller-category/provider mismatches and external delete attempts raise
`ValueError`. These are
internal contract violations and do not introduce API error codes. Consumer
CVE routes may perform delegated preliminary accessibility before invoking this
service and map a locked-current authoritative accessibility denial to the scoped
`404 CVE_NOT_FOUND` response without requiring a particular internal exception
or result type.

When a CVSS boundary must read the current default version,
`RequiredSystemSettingMissingError` from `settings_service` propagates
unchanged, rolls back the caller-owned transaction, and is exposed only through
the global non-sensitive `500 INTERNAL_ERROR` response.

Package-specific exceptions (`TrackNotFoundError`, `ProductNotFoundError`,
`PackageNotFoundError`) are defined in `package_service` — see
`docs/features/packages/package-service.md`.

The system-only external batch raises `ValueError` for missing
`evaluation_date`, missing CVE, malformed parsed-result type, empty or
over-length provider, reserved provider, or duplicate canonical key.
`RequiredSystemSettingMissingError` and unexpected
database, transaction, audit, eligibility, flush, reconciliation, cancellation,
and programming exceptions propagate unchanged. `cve_service` does not convert
them into per-candidate skips; its caller rolls back the complete per-CVE
transaction. Individual candidate skips occur only before this boundary.

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
- `docs/features/identity/user-service.md` — deactivation and final-role-loss
  bulk unassignment (complementary to assignment-eligibility sanitation)
- `docs/conventions.md` — Transaction and Locking (generic pessimistic
  locking pattern)
- `docs/features/tickets/ticket-service.md` — Ticket lifecycle operations,
  manual-zone exit composition, and Ticket convergence hooks (imports
  `reconcile_ticket_status()`, `recalculate_cvss_chain()`,
  `auto_assign_actor()`, `ensure_ticket_operable()`)
- `docs/features/platform/system-settings.md` — default CVSS version setting
  declaration, persistence, and mutation
- `docs/features/platform/default-cvss-version-operations.md` — default-version
  preview and all-CVE runner invoking `recalculate_cvss_chain()`
- `docs/features/platform/fetcher-infrastructure.md` — `catch_up()`
  per-ticket catch-up method contract
- `docs/features/identity/rbac.md` — canonical Ticket visibility predicate and
  capability/visibility orthogonality
- `docs/features/tickets/ticket-priority.md` — Ticket priority resolution,
  `refresh_priority_auto()`, and refresh points
- `docs/api-spec.md` — general API conventions and scoped accessibility
