# Package Service

## Purpose

Centralize all package-centric operations — mutations on `TicketPackage`,
`TicketPackageMaintainer`, `TicketPackageTrack`, and `TicketPackageProduct`
records, orchestration with external systems (SMELT), and package query
functions — in a single service module (`package_service`). This
ensures that:

- `ticket_mutations.reconcile_ticket_status()` is always called after
  gate-relevant package changes
- Manual exclusion markers and derived actionability are evaluated consistently
- Record creation logic (initial status, eligibility) is centralized
- The complete package lifecycle (orchestration + mutation + query) is
  owned by a single module

Without this centralization, package-centric logic would be scattered
across `ticket_mutations` (mutations), `package-model.md` endpoint
handlers (orchestration), and ad-hoc query code, leading to
inconsistency and missed re-evaluations.

## Architecture

### Module location

`backend/app/services/package_service.py`

### Async pattern

The service is implemented as async functions. The API (FastAPI) is the
primary consumer and calls the service directly with `await`. Synchronous
process entry points establish one async workflow boundary and await service
calls within it; they do not create a new event loop for each mutation.

| Entry point               | Invocation pattern                                             |
|---------------------------|----------------------------------------------------------------|
| API endpoint              | `await package_service.set_track_status(session, ...)`         |
| Celery track-release workflow | `await package_service.set_track_status(session, ...)` inside its one async workflow |
| IBS RabbitMQ consumer workflow | `await package_service.set_track_status(session, ...)` inside its one async workflow |

### Transaction ownership

The module does NOT commit or roll back. All operations execute within
the caller's database session. Commit responsibility belongs to the
caller.

This matches the `ticket_mutations` and `user_service` pattern — the
module applies mutations and creates audit events, but the transaction
boundary is the caller's decision. This enables callers to compose
multiple operations within a single transaction when needed (e.g.,
`add_package_to_ticket` creates a complete package-tree delta atomically).

### Acting user convention

User-facing mutation operations accept an `acting_user_id: UUID | None`
parameter where both user and system callers are supported:

- `UUID` — action performed by an authenticated VA (enables
  auto-assignment on unassigned tickets)
- `None` — system action (release detection, product lifecycle
  transitions). Auto-assignment does not apply

**API handler rule**: API endpoint handlers MUST always pass the UUID of
the authenticated user as `acting_user_id`. Passing `None` from an API
handler is a bug — it would silently bypass auto-assignment. `None` is
reserved exclusively for system entry points.

`set_product_eligibility()` is narrower: it is a user-attributed override
boundary and requires a non-null actor. Product- and CVSS-originated automatic
eligibility recalculation use their dedicated system boundaries instead.

### Relationship with other modules

| Module | Relationship |
|--------|-------------|
| `services/ticket_mutations.py` | `package_service` imports `reconcile_ticket_status()`, `auto_assign_actor()`, and `ensure_ticket_operable()` from `ticket_mutations`. The code dependency remains unidirectional: `package_service` depends on `ticket_mutations`, but `ticket_mutations` does NOT import `package_service`. `reconcile_ticket_status()` performs transactional CVSS recalculation and registers the package-service-owned reactivation workflow for execution by the post-commit workflow owner; the caller does not invoke package catch-up directly |
| `services/cvss.py` | `package_service` delegates eligibility calculation to `resolve_eligibility_score()` in `cvss.py` (SUSE-only, 2-step cascade — see Eligibility Score Resolution in `docs/features/tickets/cvss-scoring.md`) |
| `core/filters.py` | `search_packages()` receives a `confidentiality_filter` (a SQLAlchemy `ColumnElement`) built by the endpoint handler via `confidential_ticket_filter()`. The service function is unaware of access rules |

### Module invariant: I/O-then-Lock pattern

`package_service` contains both orchestration functions that perform
external I/O (e.g., `add_package_to_ticket` queries SMELT) and mutation
functions that acquire `FOR UPDATE` locks (e.g., `add_package_records`).
The following invariant MUST be maintained:

> Functions that perform external I/O MUST NOT acquire `FOR UPDATE`
> locks themselves. External I/O happens in orchestration functions,
> which delegate record mutations to lock-acquiring functions. The lock
> is acquired only after all external data has been fetched.

This is an application of the I/O-then-Lock corollary defined in
`docs/conventions.md` (Transaction Hygiene Rules). Violation of this
invariant would block concurrent mutations on the same ticket for the
duration of an external HTTP call.

## Auto-Assignment Rule

When a VA performs any modifying operation on a ticket with
`assignee_id = NULL`, the ticket is automatically assigned to the
acting VA. This is enforced via the shared helper
`ticket_mutations.auto_assign_actor()`.

The narrow exception is a package-resolution invocation whose only database
change is creation of system-derived `TicketPackageMaintainer` associations.
That invocation does not call `auto_assign_actor()` because maintainership is
authorization/work-routing metadata rather than a VA package-tree decision. If
the same invocation also creates any package-tree record, the normal
auto-assignment rule applies.

**Module-level rule**: auto-assignment is always applied by the function
that acquires the `FOR UPDATE` lock, never by orchestration wrappers.
For example, `add_package_to_ticket` does NOT apply auto-assignment — it
delegates to `add_package_records()`, which calls `auto_assign_actor` after
acquiring the lock only when package-tree state changes.

A function determines its semantic result from state reloaded under the Ticket
lock before calling `auto_assign_actor()`. A true no-op never assigns the actor,
creates an audit event, reconciles the Ticket, or registers a post-commit
effect. Intent to request a mutation is not itself a modifying operation.

See `docs/features/tickets/ticket-mutations.md` for the helper's
signature and behavior.

## Package Mutation Operations

### Semantic locators and locked ownership validation

Every direct mutation of an existing package-tree occurrence receives enough
semantic identity to name its expected Ticket/package/track path. At minimum:

- a package mutation receives `ticket_id` and `package_id`;
- a track mutation receives `ticket_id`, `package_id`, and `track_id`; and
- a Product-occurrence mutation receives `ticket_id`, `package_id`, `track_id`,
  and `ticket_package_product_id`.

The concrete parameter grouping is an implementation choice; no locator class,
dataclass, or private lookup helper is required. The public service contract is
that the function locks the declared Ticket as its first state-dependent
database operation, then reloads and validates the complete nested chain under
that lock before deciding a mutation, no-op, audit value, or return value. A
missing identifier or an identifier that belongs to another declared parent is
reported through the existing package-, track-, or Product-not-found exception
for the targeted level. It never mutates the occurrence found under the other
path and never reveals that such an occurrence exists.

Direct set/update and package-record-creation boundaries communicate semantic
outcomes that distinguish effective changes from true no-ops.
`set_track_status()` additionally communicates `rejected` for a prohibited
system target. Exclusion and restoration use the existing error-based
idempotency contracts in their own sections and do not acquire a new no-op
result here. Concrete result representations remain implementation choices.
Returned records and audit values reflect state reloaded under the lock,
including a concurrent winner's committed state; they are not assembled from
pre-lock snapshots.

Each user-facing function below follows the same pattern unless its section
states a narrower no-op or system-derived-metadata exception. System-only
operations such as `set_track_delivery_status()`, `set_product_released_at()`, and
`recalculate_product_eligibility_for_ticket()` omit auto-assignment as stated
in their sections. `add_package_records()` also omits assignment and
reconciliation when maintainership associations are its only mutation.
Exclusion and restoration operations are user-attributed only. Their shared
contract below requires a non-null `acting_user_id` and places the direct-marker
guard before auto-assignment.

### `set_track_status()`

Sets the affectedness status of a `TicketPackageTrack` record.

**Parameters**:

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `db` | `AsyncSession` | Yes | Database session |
| `ticket_id` | `UUID` | Yes | Declared parent Ticket to lock |
| `package_id` | `UUID` | Yes | Declared parent TicketPackage |
| `track_id` | `UUID` | Yes | TicketPackageTrack to modify |
| `status` | `PackageStatus` | Yes | New status value |
| `acting_user_id` | `UUID \| None` | No | Who is performing the action |
| `force` | `bool` | No | Caller-verified admin marker (default `False`) — required for a user-attributed `FIXED` request |

**Preconditions**:

- Parent ticket must be operable (`ensure_ticket_operable`)
- Package and track must exist under the declared Ticket/package path
- Status must be a valid `PackageStatus` value
- User-attributed callers use `force=True` only after verifying
  `admin_ticket_ops` for a `FIXED` target. They use `force=False` only after
  verifying `manage_packages` for a non-`FIXED` target

**Behavior**:

1. Acquire `FOR UPDATE` on `ticket_id` as the first state-dependent database
   operation.
2. Call `ensure_ticket_operable(ticket)`.
3. Reload the declared package/track chain under the lock. A missing or
   mismatched level raises its existing not-found exception.
4. Apply caller authority to the requested target:
   - a user-attributed `FIXED` request requires `force=True`;
   - a user-attributed non-`FIXED` request requires `force=False`; and
   - a system request accepts only `FIXED`.
5. For a prohibited user-attributed target/marker combination, raise
   `TrackFixedStatusRestrictedError` without side effects. For a prohibited
   system non-`FIXED` target, emit one sanitized warning and return `rejected`
   without mutation, assignment, audit, reconciliation, or post-commit effect.
6. If the locked status equals the target, return `no_op` before
   auto-assignment and every other side effect.
7. If a system `FIXED` request observes `NOT_AFFECTED`, `FIXED`, or `WONT_FIX`,
   return the protected `no_op` outcome. The release workflow may still accept
   its separately owned checkpoint after successful examination.
8. For an effective user-attributed change, call `auto_assign_actor()`; system
   changes never assign.
9. Update `TicketPackageTrack.status`, create one `track_status_changed` event
   with the locked old value and requested new value, and call
   `reconcile_ticket_status()`.
10. Flush and return `changed` with the updated track.

**TicketAuditEvent**: `track_status_changed`

**Idempotency**: unchanged authorized requests and protected automatic
final-state outcomes are true no-ops with no assignment, audit,
reconciliation, or post-commit effect. A repeated prohibited automatic target
remains `rejected` and repeats only its sanitized warning.

**FIXED restriction**: `FIXED` is restricted — only system callers
(`acting_user_id = None`) or user-attributed callers with `force=True` can set
it (step 5). The service does NOT query the RBAC system — it trusts the caller
to have verified the `admin_ticket_ops` capability before passing `force=True`.
CLI commands MUST verify `admin_ticket_ops` before passing `force=True`.
Passing `force=True` without capability verification is a bug.

System callers leave `force` at its default. The marker is not evaluated when
`acting_user_id` is `None`.

**Automatic authority**: system callers (`acting_user_id = None`) can request
only `FIXED` and can change only `ANALYSIS` or `AFFECTED`. A `FIXED` request
against any final state is a protected no-op rather than a workflow failure.
A different automatic target is rejected and causes the calling workflow unit
to fail: the caller consumes `rejected` and applies its own documented per-item
failure handling. This enforces the invariant from
`package-model.md`
([Automatic Transitions](package-model.md#automatic-transitions)) that
final-status records are not changed by automatic transitions. User-attributed
callers can transition from any state to any non-`FIXED` target after
`manage_packages` verification, or to `FIXED` from any state after
`admin_ticket_ops` verification.

**Exceptions**: declared-path lookup raises `TicketNotFoundError`,
`PackageNotFoundError`, or `TrackNotFoundError`; operability and authorization
errors propagate as documented in the Service Exceptions table. Database,
audit, and reconciliation failures propagate and roll back the caller-owned
transaction. A prohibited system target is the documented `rejected` result,
not an escaping service exception.

**Track-release composition**: IBS track release detection performs external
I/O before opening the per-track transaction, then calls this function with
`status=FIXED` and `acting_user_id=None`. Its workflow owner advances the
track's `TrackReleaseCheckpoint` in the same caller-owned transaction as any
effective status mutation, this function's audit event, and Ticket
reconciliation. This function remains the sole owner of affectedness mutation
and `track_status_changed`; the detector does not duplicate the audit event.
Checkpoint-only outcomes create no Ticket audit event and do not update
`TicketPackageTrack.updated_at`.

---

### `set_track_delivery_status()`

Sets the delivery status of a `TicketPackageTrack` record as a system-attributed
mutation. This is the single package-owned delivery mutation boundary used by
the authoritative reconciliation in `ibs-submission-tracking.md`; it performs
no external I/O.

**Parameters**:

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `db` | `AsyncSession` | Yes | Database session |
| `ticket_id` | `UUID` | Yes | Declared parent Ticket to lock |
| `package_id` | `UUID` | Yes | Declared parent TicketPackage |
| `track_id` | `UUID` | Yes | TicketPackageTrack to modify |
| `delivery_status` | `DeliveryStatus` | Yes | New delivery status value |
| `acting_user_id` | `None` | No | System-attribution marker; always `None` |

**Preconditions**:

- Parent ticket must be operable (`ensure_ticket_operable`)
- Package and track must exist under the declared Ticket/package path
- The transition `current_delivery_status → new_delivery_status` must be
  unchanged or one of `PENDING → IN_PROGRESS`, `IN_PROGRESS → RELEASED`, or
  `IN_PROGRESS → PENDING` under the evidence and stale-negative rules in
  `docs/features/packages/package-model.md`. Any change out of `RELEASED` is
  illegal. A caller whose complete observation proves `RELEASED` from `PENDING`
  applies the two approved forward transitions in one transaction.

**Behavior**:

1. Acquire `FOR UPDATE` on the declared Ticket row as the first state-dependent
   database operation. If the caller's current
   transaction already holds that lock, acquiring it again is compatible and
   does not establish a nested transaction.
2. Call `ensure_ticket_operable(ticket)`
3. Reload and validate the complete declared package/track chain
4. If delivery_status is unchanged, return `no_op`
5. Validate transition: verify that `current_delivery_status →
   new_delivery_status` is a legal transition per the delivery status
   state machine defined in `package-model.md`. If the transition is
   illegal, raise
   `InvalidDeliveryStatusTransition` without modifying the record.
6. Update `TicketPackageTrack.delivery_status`
7. Flush and return `changed` with the updated track

The operation never calls `auto_assign_actor()` or
`reconcile_ticket_status()`. Delivery is an independently derived system fact,
not a VA mutation or a Ticket gate input. It does not generate a
`TicketAuditEvent`; request/action provenance is retained by IBS submission
tracking, while the Ticket timeline records the independent
`track_status_changed` and `product_released` milestones.

The function participates in the caller-owned transaction and never commits or
rolls back. The shared IBS reconciler may upsert request, action, and
action-track evidence before calling it while holding the same Ticket lock; all
of those writes and the delivery change commit or roll back atomically.

**TicketAuditEvent**: none.

**Idempotency**: no-op if delivery_status is unchanged.

**Concurrent outcome**: after waiting for the Ticket lock, the function uses the
winner's committed delivery value. It returns `no_op` if that value already
equals the target, otherwise validates the transition from that value. It never
reports a stale pre-lock old value.

**Exceptions**: declared-path lookup raises `TicketNotFoundError`,
`PackageNotFoundError`, or `TrackNotFoundError`; operability, illegal-transition,
database, and flush failures propagate. The caller owns rollback.

**System attribution**: every caller passes `acting_user_id = None`. The
function is not exposed as a user-facing mutation, and a delivery change has no
user attribution because it creates no audit event.

---

### `set_product_released_at()`

Sets the `released_at` timestamp on a `TicketPackageProduct` record when
product release detection confirms the fix in the product's update
repository.

**Parameters**:

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `db` | `AsyncSession` | Yes | Database session |
| `ticket_id` | `UUID` | Yes | Declared parent Ticket to lock |
| `package_id` | `UUID` | Yes | Declared parent TicketPackage |
| `track_id` | `UUID` | Yes | Declared parent TicketPackageTrack |
| `ticket_package_product_id` | `UUID` | Yes | TicketPackageProduct to modify |
| `released_at` | `datetime` | Yes | Advisory issued date (UTC) |
| `advisory_id` | `str` | Yes | Advisory identifier (e.g., `SUSE-SU-2025:1234-1`) |

**Preconditions**:

- Parent ticket must be operable (`ensure_ticket_operable`) — release
  detection does NOT apply to non-operable tickets (Ignored or
  Duplicated)
- The declared package, track, and Product occurrence must form one path under
  `ticket_id`; otherwise raise the not-found exception for the missing or
  mismatched level
- No precondition on track or product `deleted_at` — release detection
  applies to soft-deleted child records (factual observation that keeps
  them current with reality)

**Behavior**:

1. Acquire `FOR UPDATE` on the declared Ticket row as the first state-dependent
   database operation
2. Call `ensure_ticket_operable(ticket)`
3. Reload and validate the complete package/track/Product path (no `deleted_at`
   filter — soft-deleted products are included)
4. If `released_at` is already set, return `no_op` (release confirmation
   is irreversible; see below)
5. Set `TicketPackageProduct.released_at` to the provided value
6. Create `TicketAuditEvent` (`product_released`, `user_id = NULL`)
   with `new_value` equal to the `released_at` timestamp in UTC ISO 8601
   format and with the event-time Product subject plus `advisory_id` in
   `detail`, as defined in `ticket-audit-log.md`
7. Call `reconcile_ticket_status()`
8. Flush and return `changed` with the updated product

**TicketAuditEvent**: `product_released`

**Idempotency**: no-op if `released_at` is already set (step 4).

**Irreversibility**: once set, `released_at` cannot be cleared or modified.
The value records a stable security advisory-issued time that passed the
complete validation contract at observation time. A later advisory retraction,
correction, disappearance, repository failure, or no-match does not reverse or
replace that accepted factual observation. Soft-deletion remains an independent
manual exclusion decision and is not a release-correction mechanism.

**Callers**: IBS product release detection tasks only
(`acting_user_id` is always `None`; auto-assignment does not apply).

**Product-release composition**: the detector completes repository I/O,
integrity validation, parsing, matching, and timestamp selection before this
function acquires the Ticket lock. Each `TicketPackageProduct` occurrence uses
one caller-owned transaction. If concurrent work already set `released_at`, the
later call is an idempotent no-op and does not replace the value, reconcile the
Ticket, or create another event. Only an effective NULL-to-timestamp change
creates `product_released` and invokes Ticket reconciliation.

**Exceptions**: declared-path lookup raises `TicketNotFoundError`,
`PackageNotFoundError`, `TrackNotFoundError`, or `ProductNotFoundError`;
operability, database, audit, and reconciliation failures propagate and roll
back the caller-owned transaction.

---

### `set_product_eligibility()`

Sets or resets the eligibility override of a `TicketPackageProduct` record.

**Parameters**:

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `db` | `AsyncSession` | Yes | Database session |
| `ticket_id` | `UUID` | Yes | Declared parent Ticket to lock |
| `package_id` | `UUID` | Yes | Declared parent TicketPackage |
| `track_id` | `UUID` | Yes | Declared parent TicketPackageTrack |
| `ticket_package_product_id` | `UUID` | Yes | TicketPackageProduct to modify |
| `eligible` | `bool \| None` | Yes | New eligibility value (`true`/`false` for override, `None` to reset to automatic calculation) |
| `acting_user_id` | `UUID` | Yes | Acting user attributed to the override or reset |

**Preconditions**:

- Parent ticket must be operable (`ensure_ticket_operable`)
- The declared package, track, and Product occurrence must form one path under
  the declared Ticket
- `acting_user_id` must be non-null; automatic recalculation uses the dedicated
  system boundaries

**Behavior**:

If `eligible` is `bool` (override):

1. Acquire `FOR UPDATE` on the declared Ticket row as the first state-dependent
   database operation
2. Call `ensure_ticket_operable(ticket)`
3. Reload and validate the complete declared path
4. If `TicketPackageProduct.eligible == eligible` AND
   `is_eligible_override == true`, return `no_op` before assignment
5. Call `auto_assign_actor()`
6. Update `TicketPackageProduct.eligible` to the given value
7. Set `TicketPackageProduct.is_eligible_override = true`
8. Create `TicketAuditEvent` (`product_eligibility_changed`) with the standard
   Product subject, `reason = "va_override"`, and `override_action = "set"`
   when the previous value was system-managed or `override_action = "changed"`
   when an existing override changed value
9. Call `reconcile_ticket_status()`
10. Flush and return `changed` with the updated product

If `eligible` is `None` (reset to automatic):

1. Acquire `FOR UPDATE` on the declared Ticket row as the first state-dependent
   database operation
2. Call `ensure_ticket_operable(ticket)`
3. Reload and validate the complete declared path
4. If `is_eligible_override == false`, return `no_op` before assignment
5. Call `auto_assign_actor()`
6. Set `TicketPackageProduct.is_eligible_override = false`
7. Recalculate eligibility using all automatic rules in
   `docs/features/packages/package-model.md` (Axis 2: Eligibility), including
   the Reactive Support rule and the threshold comparison based on
   `cvss.resolve_eligibility_score()`.
8. Update `TicketPackageProduct.eligible` to the calculated value
9. Create `TicketAuditEvent` (`product_eligibility_changed`) with the standard
   Product subject, `reason = "va_override"`, and
   `override_action = "cleared"`
10. Call `reconcile_ticket_status()`
11. Flush and return `changed` with the updated product

> **Note**: Eligibility recalculation delegates to
> `cvss.resolve_eligibility_score()` (SUSE assessment of the default
> version only; fallback to 10.0 if no SUSE assessment exists). Since this
> requires only single-row database reads (CVE assessments + product
> threshold), it is acceptable inside the `FOR UPDATE` lock.

**TicketAuditEvent**: `product_eligibility_changed`

**Idempotency**:

- Override (`eligible` is `bool`): no-op if `eligible` matches current value AND `is_eligible_override` is already `true`
- Reset (`eligible` is `None`): no-op if `is_eligible_override` is already `false` (the current `eligible` value is already system-managed)

Every no-op above occurs before auto-assignment and therefore produces no
assignment, eligibility event, Ticket reconciliation, or post-commit effect.
After a concurrent winner commits, the waiting caller determines override
action and audit old/new values from the reloaded locked state.

**Exceptions**: a null actor is a caller contract violation; declared-path
lookup raises `TicketNotFoundError`, `PackageNotFoundError`,
`TrackNotFoundError`, or `ProductNotFoundError`. Operability, eligibility
resolution, database, audit, and reconciliation failures propagate and roll
back the caller-owned transaction.

---

### `recalculate_product_eligibility_for_ticket()`

Recalculates system-managed eligibility for one catalog Product within one
operable Ticket. This is the mutation boundary used after an AIMAAS threshold
change or a Reactive Support lifecycle change. It is separate from
`set_product_eligibility()`, whose boolean path creates a VA override, and
from `ticket_mutations.recalculate_cvss_chain()`, which owns CVSS assessment
changes and the platform-wide `default_cvss_version` batch.

**Parameters**:

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `db` | `AsyncSession` | Yes | Caller-owned database session |
| `ticket_id` | `UUID` | Yes | Ticket whose matching package Products are recalculated |
| `catalog_product_id` | `UUID` | Yes | Internal catalog `Product.id`, not a `TicketPackageProduct.id` |
| `reason` | `Literal["threshold", "reactive_ltss", "reactivation"]` | Yes | System trigger recorded in each audit event |
| `evaluation_date` | `date \| None` | No | UTC date used for lifecycle rules and final actionability reconciliation. If omitted, capture once at function entry |

**Preconditions and guards**:

- The Ticket and catalog Product must exist.
- Tickets in `New`, `Analysis`, `Analyzed`, or `Resolved` are processed. A
  Ticket that entered `Ignored` or `Duplicated` after candidate selection
  returns a manual-zone skip result rather than raising
  `TicketNotMutableError`. Including `Resolved` lets threshold and lifecycle
  corrections invalidate resolution.
- The calling task validates `reason` before invoking this typed service
  boundary; callers pass only `threshold`, `reactive_ltss`, or `reactivation`.

**Behavior**:

1. Acquire `FOR UPDATE` on the Ticket row as the first database operation.
2. If the locked Ticket is `Ignored` or `Duplicated`, return a manual-zone skip
   result with zero changed records, without assignment, audit events, or
   reconciliation.
3. Call `ensure_ticket_operable(ticket)`, then load the catalog Product and
   its current threshold and lifecycle inputs.
4. Select every `TicketPackageProduct` in the Ticket that references the
   catalog Product. Include records that are directly or effectively
   soft-deleted and records under every track status. Skip records with
   `is_eligible_override = true`.
5. Resolve one `evaluation_date`, then resolve the Ticket's current eligibility score using the current persisted
   `default_cvss_version`, then apply the complete eligibility rules in
   `package-model.md` to every selected record. The task payload never
   supplies a threshold, lifecycle phase, score, or expected result.
6. For each record whose computed value differs, update `eligible` without
   changing `is_eligible_override` and create one
   `product_eligibility_changed` event in the same transaction. Set
   `user_id = NULL`, `comment = NULL`, preserve the true old and new boolean
   values, and populate the standard Product subject and `reason` detail keys
   defined in `ticket-audit-log.md`.
7. If at least one record changed, call `reconcile_ticket_status()` exactly
   once after all updates and audit events, using that `evaluation_date` for
   all actionability checks. If no value changed, return a no-op result without
   reconciliation or audit creation.
8. Flush and return the number of examined, override-skipped, and changed
records plus whether the Ticket was skipped in the manual zone. Do not commit or
   roll back; the caller owns the transaction.

This system operation never calls `auto_assign_actor()` and never creates or
clears a manual override.

**TicketAuditEvent**: one `product_eligibility_changed` event per changed
`TicketPackageProduct`; none for unchanged or override-skipped records.

**Idempotency**: deterministic and idempotent. Re-invocation reads current
persisted inputs and produces no mutation, audit event, or reconciliation once
all automatic records already hold the computed value. Delayed or
out-of-order invocations therefore converge to current state rather than
replaying a historical threshold or lifecycle result.

**Exceptions**: `TicketNotFoundError` or `ProductNotFoundError` when a required
root does not exist; shared settings, database, eligibility-resolution,
audit-validation, and reconciliation exceptions propagate unchanged. Any
exception rolls back the caller's whole Ticket transaction, including its
eligibility updates and audit events.

---

### `reconcile_lifecycle_actionability_for_ticket()`

Reconciles one gate-zone Ticket after Product lifecycle data or the UTC date
may have changed derived actionability. It does not persist a lifecycle phase
or actionability value.

```python
async def reconcile_lifecycle_actionability_for_ticket(
    db: AsyncSession,
    ticket_id: UUID,
    evaluation_date: date,
) -> LifecycleReconciliationResult:
```

**Preconditions and guards**:

- The Ticket must exist.
- `evaluation_date` is the UTC calendar date chosen by the caller for its
  complete lifecycle evaluation run.
- `New`, `Ignored`, and `Duplicated` return a skipped result. This is a
  defensive race guard; normal candidate selection includes only
  `Analysis`, `Analyzed`, and `Resolved`.

**Behavior**:

1. Acquire `FOR UPDATE` on the Ticket as the first database operation. Raise
   `TicketNotFoundError` if it does not exist.
2. If status is `New`, `Ignored`, or `Duplicated`, return a skipped result with
   no mutation, audit event, assignment, or task dispatch.
3. Call `reconcile_ticket_status()` exactly once, passing `evaluation_date` so
   all lifecycle and actionability predicates use the same temporal input.
4. Flush and return the old and current Ticket statuses and whether a status
   change occurred. Do not commit or roll back; the caller owns the
   transaction.

The delegated reconciliation creates the ordinary `status_change` event if
the Ticket changes status and performs the established inactive-to-active
catch-up if a `Resolved` Ticket regresses. This function creates no separate
audit event because actionability itself is not persisted. It never calls
`auto_assign_actor()` and never modifies exclusion markers, eligibility,
affectedness, or delivery state.

**Idempotency**: deterministic and idempotent for the supplied
`evaluation_date` and current persisted data. A repeated call after status has
converged produces no mutation or audit event.

**Exceptions**: `TicketNotFoundError` when the Ticket does not exist; database,
audit, reconciliation, and catch-up dispatch exceptions propagate according to
the delegated contracts.

---

### `add_package_records()`

Creates `TicketPackage`, `TicketPackageTrack`, and
`TicketPackageProduct` records for a package being added to a ticket.
Called by `add_package_to_ticket` after SMELT resolution completes.

**Parameters**:

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `db` | `AsyncSession` | Yes | Database session |
| `ticket_id` | `UUID` | Yes | Target ticket |
| `package_name` | `str` | Yes | Source package name |
| `tracks` | `list[ResolvedTrackData]` | Yes | Fully validated and locally resolved track/Product data; semantic shape defined below |
| `maintainer_emails` | `set[str]` | Yes | Fully validated, lowercase, globally deduplicated individual emails from the maintainership response; empty on a valid no-maintainer result or non-blocking maintainership failure |
| `acting_user_id` | `UUID \| None` | No | Who is performing the action |
| `audit_comment` | `str \| None` | No | System-generated context for `package_added`; `NULL` for user actions |
| `active_ticket_only` | `bool` | No | When true, skip without mutation if the locked Ticket is not active; used by Product catalog backfill |
| `allow_excluded_reresolution` | `bool` | No | Semantic caller context. `False` for the public add endpoint and internal callers whose candidate selection excludes existing soft-deleted packages; `True` for Ticket reactivation, which intentionally re-resolves persisted excluded package markers without restoring them. The concrete parameter name or grouping is an implementation choice |

`ResolvedTrackData` names the semantic input boundary; it does not require a
particular dataclass, `TypedDict`, Pydantic model, or other concrete in-memory
representation. Each item contains:

| Field | Type | Contract |
|-------|------|----------|
| `reference` | `str` | Unique SMELT codestream name, already validated against the persisted track-reference constraints |
| `workflow_type` | `WorkflowType` | Already mapped from the supported authoritative `codestream.maintenance_process_type` value |
| `catalog_product_ids` | non-empty collection of `UUID` | Distinct internal IDs of existing local Products resolved by exact CPE under this codestream |

Before calling `add_package_records()`, the caller has completed all external
I/O, JSend and response validation, unsupported-process filtering,
channel/compose deduplication, exact CPE lookup, workflow mapping, and
deduplication of `catalog_product_ids` within each track. It has also converted
the independently validated maintainership response to `maintainer_emails` as
specified in `package-maintainership.md`. Consequently this
function
does not parse SMELT data, infer a workflow, accept unknown Products, or decide
whether a codestream is supported. The concrete collection and record types
remain implementation choices as long as they preserve this contract.

**Preconditions**:

- When `active_ticket_only` is false, the parent Ticket must be operable
  (`ensure_ticket_operable`).
- When `active_ticket_only` is true, only an active parent Ticket is eligible;
  an inactive locked Ticket returns a no-op before the operability guard.

**Behavior**:

1. Acquire `FOR UPDATE` on the Ticket row
2. If `active_ticket_only` is true and the locked Ticket status is not `New`,
   `Analysis`, or `Analyzed`, return a no-op result before assignment,
   reconciliation, or audit creation.
3. Call `ensure_ticket_operable(ticket)`
4. Validate preconditions, identify the existing package occurrence or prepare
   its creation, and determine which package, track, Product, and maintainer
   records are missing under the lock. Query exact matching Users with `active
   = true`; unmatched and inactive users do not create associations.
5. If an existing package occurrence has `deleted_at IS NOT NULL` and
   `allow_excluded_reresolution` is false, raise
   `PackageAlreadyExcludedError` before creating a record, association, audit
   event, assignment, reconciliation, or result. This guard precedes every
   no-op or maintainer-only outcome.
6. If no record or association is missing, return a no-op result before
   auto-assignment, reconciliation, or audit creation.
7. Call `auto_assign_actor()` only if at least one package-tree record is
   missing. Maintainer-only mutation does not assign the actor.
8. Create or skip `TicketPackage` (idempotent — skip if exists)
9. For each track in `tracks`:
   - Create or skip `TicketPackageTrack` (idempotent — skip if exists,
     including soft-deleted records)
   - If newly created, initial status: `ANALYSIS`, delivery_status:
     `PENDING`. An existing track retains both values unchanged.
   - For each product under the track:
     - Create or skip `TicketPackageProduct` (idempotent — skip if
       exists, including soft-deleted records)
      - Calculate initial eligibility (see Record Creation Logic below)

> **Note**: Eligibility calculation inside the `FOR UPDATE` lock is
> acceptable here. `CVECVSSAssessment` records are loaded once for the
> entire product batch (same CVE for all products in the ticket —
> typically fewer than 20 records). The `cvss_threshold` per product is a
> single-row lookup from the Product table. The `cvss.py` functions
> (`resolve_eligibility_score`) are pure and do not perform database
> access on their own. Therefore total I/O volume inside the lock remains
> within "fast reads (single-row lookups)" permitted by Transaction
> Hygiene Rules, even when creating dozens of products in a single
> `add_package_records()` call.

10. For each missing active-user match, create one
   `TicketPackageMaintainer` and one system-attributed
   `package_maintainer_added` event with the exact payload in
   `ticket-audit-log.md`.
11. If a package-tree record was created, create one `TicketAuditEvent`
    (`package_added`) using `audit_comment` and call
    `reconcile_ticket_status()`. Maintainer-only mutation performs neither.
12. Flush and return the existing package-tree result. Maintainer additions do
    not alter public counts or add a public result field. Internally, the
    result distinguishes `package_tree_changed`, `package_tree_no_op`,
    `maintainer_only`, and `active_ticket_only_skipped`, while preserving the
    public creation/skip counts and new-track signal. The concrete result type
    is an implementation choice.

**TicketAuditEvent**: `package_added` when package-tree state changes; one
`package_maintainer_added` per new association.

**Idempotency**: if a `TicketPackageTrack` or `TicketPackageProduct`
record already exists for the given combination (including soft-deleted
records), it is skipped without modification. Existing maintainer associations
are likewise retained and skipped. Only missing records are created. This
ensures re-running `add_package_to_ticket` after a partial failure does not
produce duplicates. A package-tree no-op may still add missing maintainers; it
does not auto-assign or reconcile the Ticket.

**Concurrent outcomes**: same-Ticket invocations serialize on the Ticket lock.
The first transaction creates the missing rows; a waiting invocation reloads
the winner's state and truthfully reports skips, a package-tree no-op,
maintainer-only mutation, or active-Ticket skip as applicable. Database unique
constraints remain the final protection against duplicates. Only rows and
associations actually created by an invocation contribute its audit events,
assignment, reconciliation, counts, and post-commit new-IBS-track signal.

**Exceptions**: `TicketNotFoundError`, `TicketNotMutableError`, and
`PackageAlreadyExcludedError` under the public-add guard, plus database
constraint/flush failures, audit validation/flush failures, and delegated
eligibility failures, propagate to the caller and roll back the complete
caller-owned transaction. Unmatched/inactive Users and duplicate maintainer
associations are normal skip outcomes, not exceptions.

---

### Exclusion and restoration operations

The six direct-marker operations share one complete Category A contract:

| Function | Target path after `ticket_id` | Required direct marker | Mutation | Event |
|---|---|---|---|---|
| `soft_delete_ticket_package()` | `package_id` | NULL | set to current UTC timestamp | `package_excluded` |
| `soft_delete_ticket_package_track()` | `package_id`, `track_id` | NULL | set to current UTC timestamp | `track_excluded` |
| `soft_delete_ticket_package_product()` | `package_id`, `track_id`, `ticket_package_product_id` | NULL | set to current UTC timestamp | `product_excluded` |
| `restore_ticket_package()` | `package_id` | non-NULL | clear to NULL | `package_restored` |
| `restore_ticket_package_track()` | `package_id`, `track_id` | non-NULL | clear to NULL | `track_restored` |
| `restore_ticket_package_product()` | `package_id`, `track_id`, `ticket_package_product_id` | non-NULL | clear to NULL | `product_restored` |

Each function receives `db: AsyncSession`, the UUID path shown above,
`acting_user_id: UUID`, and an optional `evaluation_date: date`. The date is
the UTC date for actionability, Ticket reconciliation, result projection, and
the eventual mutation response. If omitted, the function captures it once at
entry and returns enough semantic context for the caller to reuse it; the
concrete result representation is an implementation choice.

**Shared guards and behavior**:

1. Validate `acting_user_id` before any database operation. `None` raises
   `ValueError`; exclusion and restoration have no system caller.
2. Resolve one `evaluation_date`, then acquire `FOR UPDATE` on the declared
   Ticket as the first database operation.
3. Call `ensure_ticket_operable(ticket)`.
4. Reload and validate the complete declared package-tree path under the lock.
5. Inspect only the target's locked direct marker. An exclusion of a non-NULL
   marker raises `PackageAlreadyExcludedError`; a restore of a NULL marker
   raises `PackageNotExcludedError`. The guard runs before assignment or any
   durable side effect.
6. Call `auto_assign_actor()` only after the direct-marker guard succeeds.
7. Change only the target marker as shown in the table. Ancestor and descendant
   markers, affectedness, eligibility, delivery, release facts, and lifecycle
   data remain unchanged.
8. Create exactly one direct event from the table and call
   `reconcile_ticket_status()` exactly once with the same `evaluation_date`.
9. Flush and return the target's locked-current state with `actionable` and
   `non_actionable_reason` projected using that date. Assignment and Ticket
   status changes may create their independently owned events.

No ancestor exclusion, descendant state, EOL phase, child-existence condition,
or availability of an actionable descendant is a guard. An exclusion can
therefore create an independent direct marker beneath an excluded ancestor or
on an already non-actionable target. A restore can succeed while the target
remains non-actionable through an ancestor, EOL, or its descendant set.

**Audit payloads** use the locked occurrence and the exact field contract in
`ticket-audit-log.md`:

| Level | Exclusion `old_value` / `new_value` | Restore `old_value` / `new_value` | `detail` |
|---|---|---|---|
| Package | package name / NULL | NULL / package name | NULL |
| Track | track reference / NULL | NULL / track reference | `track`, `package` |
| Product | Product display name / NULL | NULL / Product display name | event-time `track`, `package`, `product_name`, `product_cpe` |

Every event has `user_id = acting_user_id` and `comment = NULL`. A rejected
repeat call, path or operability failure, EOL-only transition, derived parent
actionability change, or rolled-back transaction creates no exclusion or
restoration event. Audit, reconciliation, database, constraint, and flush
failures propagate unchanged and roll back the complete caller-owned
transaction, including marker, assignment, and every audit or status effect.

**Re-invocation and concurrency**: a successful same-direction re-invocation
fails on the direct-marker guard without assignment, audit, reconciliation, or
post-commit effect. Same-Ticket calls serialize on the Ticket lock:

- exclude/exclude has one success followed by
  `PackageAlreadyExcludedError`;
- restore/restore has one success followed by `PackageNotExcludedError`;
- exclude/restore has no global priority: each caller applies its guard to the
  committed-current state observed after acquiring the lock; and
- ancestor/descendant calls may both succeed because each changes an
  independent direct marker.

Each successful result represents the valid locked state during its serialized
turn. A later concurrent transaction may naturally change effective
actionability after that transaction commits.

## Orchestration Operations

### `add_package_to_ticket()`

Orchestrates the full package addition flow: queries SMELT for track and
product resolution, then delegates record creation to
`add_package_records()`. This function performs external I/O and MUST NOT
acquire `FOR UPDATE` locks itself (I/O-then-Lock invariant).

See `docs/features/packages/package-model.md` (Adding Packages to a
Ticket) for the full behavioral specification, triggers, and SMELT query
details.

**Signature** (conceptual):

```python
async def add_package_to_ticket(
    db: AsyncSession,
    ticket_id: UUID,
    package_name: str,
    acting_user_id: UUID | None = None,
    audit_comment: str | None = None,
    active_ticket_only: bool = False,
    allow_excluded_reresolution: bool = False,
) -> AddPackageResult:
```

**Behavior**:

1. Query the SMELT v2 package-scoped maintained endpoint defined in
   `package-model.md` to resolve all currently maintained tracks and products
   for the given package name (external I/O — no lock held). Do not use the
   separate paginated maintained sweep operation. Parse the response body
   regardless of HTTP status and validate the JSON/JSend envelope, HTTP/status
   pairing, and every applicable codestream and supported-target field before a
   database lookup.
2. If connection, timeout, proxy, or remote-protocol failure remains after the
   shared transport retries, or the response cannot be parsed as JSON or has
   no recognized JSend `status` value, raise `SmeltUnavailableError`
   corresponding to `503 SMELT_UNAVAILABLE`. The only recognized `status`
   values are `success` and `error` (see `package-model.md`, SMELT Query for
   Package Resolution); JSend `fail` and any other value are unrecognized. No
   records are created.
3. Verify that a complete Product catalog snapshot exists; if none exists,
   raise `ProductCatalogNotReadyError` before interpreting the response
   outcome further or matching CPEs. Readiness failure takes precedence over both
   package-not-found and targets-unresolved outcomes. Error precedence is
   defined in `product-catalog.md` (Catalog Readiness and Freshness).
4. If SMELT returns a package-not-found response (HTTP 404 with a valid
   `status = "error"` envelope, or HTTP 200 with `status = "success"` and an
   empty `data` array), raise `PackageNotFoundInSmeltError` corresponding to
   `422 PACKAGE_NOT_FOUND_IN_SMELT`. Any other HTTP status and JSend `status`
   combination — including a non-200 response and HTTP 200 with
   `status = "error"` — raises `SmeltUnavailableError`. No records are
   created.
5. Filter known unsupported codestreams, map `workflow_type` from the
   authoritative `codestream.maintenance_process_type`, and apply the
   synthetic same-CPE channel/compose deduplication rule as specified in
   `package-model.md` (SMELT Query for Package Resolution). Match the
   remaining product CPEs directly against local `Product.cpe` before the
   Ticket lock is acquired. Build the validated `ResolvedTrackData` input
   defined by `add_package_records()`. If resolution is partial, emit the
   required structured warnings before mutation. If no Product CPE resolves to
   a local Product across supported codestreams, raise
   `PackageTargetsUnresolvedError`. No records are created.
6. After target resolution succeeds, call the SMELT package maintainership
   endpoint with no codestream filter. Parse and validate the complete response,
   then collect only non-null direct-user and group-member emails, lowercase
   them, and deduplicate globally. Any transport, HTTP/envelope, JSON, or schema
   failure (including a maintainership 404 after package targets succeeded) is
   non-blocking: emit the sanitized warning defined in
   `package-maintainership.md`, use an empty email set, and continue. A valid
   empty/no-email response also supplies an empty set without warning.
7. Delegate all record creation and maintainer association to
   `add_package_records()` — this is where
   the `FOR UPDATE` lock is acquired.
8. If step 7 created at least one track whose persisted `workflow_type` is
   `ibs`, register one best-effort post-commit invocation of the existing
   generic `run_catch_up("sync_ibs_requests", ticket_id)` mechanism. A
   package-only, Product-only, Git-track-only, maintainer-only, fully no-op, or
   `active_ticket_only` skip registers no effect. It never executes before the
   database commit succeeds, and no dedicated submission discovery or
   correlation task is introduced.
9. Return an `AddPackageResult` with creation/skip counts and the identities
   plus persisted workflow types of newly created tracks, or an equivalent
   semantic signal that lets the workflow owner determine whether step 8
   applies. The result does not prescribe a concrete dataclass or collection
   type.

`audit_comment` is internal system context for `package_added`. API callers
always pass `NULL`. Product catalog backfill passes
`Product catalog backfill`. Other automatic callers pass the contextual
comment defined by their owning workflow.

`active_ticket_only` is false for normal API and automatic callers. Product
catalog backfill sets it to true so a Ticket that became inactive after
batch selection is skipped under the Ticket row lock.

`allow_excluded_reresolution` is false for the public endpoint, CVE ingestion,
and Product catalog backfill. The latter two already omit existing soft-deleted
packages during their owning candidate-selection contracts. Ticket reactivation
sets it to true because it intentionally enumerates every persisted package
marker, including directly excluded ones. Its concrete name or grouping with
other internal caller context is an implementation choice.

The public API invocation also declares public-add semantics. After external
target and maintainership I/O, the locked mutation boundary rejects an existing
directly excluded package occurrence with `PackageAlreadyExcludedError` rather
than restoring or completing it. Ticket reactivation uses re-resolution
semantics and may complete missing descendants or maintainers beneath an
excluded package without clearing any marker. CVE ingestion and Product catalog
backfill do not select existing soft-deleted package markers. The concrete
caller-context parameter is an implementation choice; the API handler does not
perform the package lookup.

**Idempotency**: every invocation repeats the maintained-package validation
request. It requests maintainership only after package-target resolution
succeeds. Package-tree rows and maintainership associations are
insert-if-missing. With unchanged valid source data and complete included local
state, no database mutation, audit event, assignment, reconciliation, or
post-commit effect occurs. A later valid response or newly active matching User
may make a repeated invocation add maintainer associations while package-tree
counts remain unchanged. Under public semantics, a directly excluded package
instead raises `PackageAlreadyExcludedError`; fetched maintainer data is not
persisted because the locked guard precedes every mutation.

The returned semantic state is the delegated locked result. A
`package_tree_changed` result may register the post-commit IBS catch-up only
when its newly created track signal includes an IBS track;
`package_tree_no_op`, `maintainer_only`, and `active_ticket_only_skipped` never
register it.

**Escaping exceptions**: package-target, Product-catalog, and SMELT availability
exceptions from steps 1-5 escape according to the Service Exceptions table.
`PackageAlreadyExcludedError`, database, audit, and delegated service
exceptions from step 7 propagate and roll back the caller-owned transaction.
Maintainership-only transport,
HTTP/envelope, JSON, and schema errors from step 6 are caught and converted to
the documented warning plus empty set; they never escape this function.

**Public error precedence**: authentication, capability, and Ticket
accessibility are API prerequisites before this function. The orchestration
then follows the canonical sequence in `package-model.md` (Adding Packages to a
Ticket).

**Error handling**:

- **Steps 1–5 (package-target validation gate)**: blocking. If any of these
  steps fails,
  the function raises without side effects (no database writes occur). The
  endpoint handler translates service-layer exceptions to the corresponding
  HTTP error codes defined in `package-model.md`.
- **Step 6 (maintainership acquisition)**: non-blocking for its own failures.
  It can only reduce new maintainer additions to zero; it never changes
  package-target errors or removes an association.
- **Step 7 (record creation)**: transactional. Record creation occurs
  under the `FOR UPDATE` lock acquired by `add_package_records()`. If any
  failure occurs during this step, the transaction is rolled back and no
  records are persisted.
- **Step 8 (post-commit effect)**: best-effort. The API transaction
  dependency or other workflow owner executes these effects only after its
  caller-owned transaction commits. Failures do not roll back the created
  records.
  If generic catch-up publication fails (for example, Redis is unavailable),
  log a sanitized warning and continue. The complete daily
  `sync_ibs_requests` fetcher is the permanent recovery owner for the new IBS
  track while sufficient upstream evidence remains available. See
  `ibs-submission-tracking.md`.

**Auto-assignment**: applied by `add_package_records()` only after it confirms
that at least one package-tree record is missing. Maintainer associations alone
do not auto-assign. `add_package_to_ticket()` does not apply it.

### Package-tree reactivation workflow

This workflow is the package-domain first phase after an inactive Ticket enters
an active status. Its conceptual input is `ticket_id: UUID`; it returns no
domain value. It is idempotent and creates audit events only through effective
delegated `add_package_to_ticket()` mutations. It is an orchestration boundary,
not a caller-owned composable service function: the workflow owner opens and
completes one independent transaction per package while the delegated
`package_service` functions retain their module-wide no-commit contract.

After the status-transition transaction commits, the workflow:

1. Reads every persisted package name for the Ticket, including soft-deleted
   `TicketPackage` records.
2. Calls `add_package_to_ticket()` once per distinct package name with system
   attribution and reactivation audit context. It processes and commits each
   package independently. Existing package, track, Product, and exclusion state
   is preserved; missing descendants and additive maintainer associations may
   be created. A soft-deleted package's association remains ineffective until
   the package is restored.
3. Logs each failed package with the sanitized cause, `ticket_id`, package
   name, and `celery_task_id`, then continues. A failed package does not roll
   back successful siblings.
4. After every package has been attempted, dispatches the registered
   per-ticket fetcher catch-ups. Catch-up therefore observes every package-tree
   addition that committed successfully. Existing records remain eligible for
   catch-up even when another package failed re-resolution.

If the Ticket does not exist or has no persisted package marker, package-tree
resolution is a no-op and catch-up dispatch still proceeds. Errors propagated
by an individual `add_package_to_ticket()` invocation are isolated only when
they are package-specific resolution or validation failures; step 3 logs them
and processing continues. An infrastructure failure that prevents reliable
enumeration, completion of a package transaction, or catch-up dispatch escapes
to the workflow wrapper. The wrapper retries the complete idempotent workflow
according to the shared `run_catch_up` classification and limits: three retries
with 5, 10, and 20 second backoff for retryable failures, and immediate terminal
failure for non-retryable failures.

Each dispatched catch-up then uses its own shared `run_catch_up` retry policy;
its failure does not propagate back to the already-completed package-tree
wrapper. A terminal wrapper or individual catch-up failure emits a structured
ERROR log identifying `ticket_id`, the failed workflow phase or fetcher,
sanitized cause, and `celery_task_id`. Either terminal outcome requires an
operator-triggered rerun of the same complete workflow for `ticket_id`; it does
not resume from partial progress because successful package units and catch-ups
are idempotent. The concrete operator interface MUST be defined before this
workflow is implemented; no durable progress table or periodic full-tree
reconciliation is introduced. The workflow performs no audit logging of its
own and does not restore any soft-deleted record.

The post-commit registration and task/callback composition mechanism is an
implementation choice. The behavioral ordering and per-package transaction
isolation are required. See `package-model.md` (IBS Workflow Applicability and
Convergence) and `fetcher-infrastructure.md` (Per-Ticket Catch-Up).

## Query Operations

### `get_ticket_packages()`

Returns the complete package tree for a ticket, including soft-deleted
records (with `deleted_at` visible on each level).

```python
async def get_ticket_packages(
    db: AsyncSession,
    ticket_id: UUID,
    evaluation_date: date,
) -> list[PackageDetail]:
```

**Behavior**:

1. Query all `TicketPackage` records for the ticket (including
   soft-deleted)
2. For each package, load all tracks and products (including
   soft-deleted), with `deleted_at` visible
3. Compute `delivery_relevant`, `actionable`, and
   `non_actionable_reason` for every level using the supplied UTC
   `evaluation_date` and the canonical predicates from `package-model.md`
4. Do not load or project maintainer identities.
5. Return assembled `PackageDetail[]`, sorted alphabetically by
   `package_name`

**No locking needed** — this is a read-only operation.
**No filtering** — the caller (endpoint handler) is responsible for
access control via `require_accessible_ticket` before invoking this
function.

This function is called by both `GET /api/v1/tickets/{ticket_id}/packages`
and `GET /api/v1/tickets/{ticket_id}` (to populate the `packages` field
in `TicketDetail`).

### `search_packages()`

Searches packages across all tickets with filtering, pagination, and
confidentiality enforcement.

```python
async def search_packages(
    db: AsyncSession,
    confidentiality_filter: ColumnElement,  # from confidential_ticket_filter()
    evaluation_date: date,
    search: str | None = None,
    name: str | None = None,
    ticket_status: list[TicketStatus] | None = None,
    sort_by: Literal["package_name", "created_at"] = "created_at",
    sort_order: Literal["asc", "desc"] = "desc",
    page: int = 1,
    per_page: int = 20,
) -> PaginatedResult[PackageListItem]:
```

**Behavior**:

1. Build base query joining `TicketPackage` -> `Ticket`
2. Exclude non-actionable packages using the canonical SQL actionability
   predicate and the supplied UTC `evaluation_date`
3. Apply `confidentiality_filter` (pre-built by the endpoint handler
   via `confidential_ticket_filter()` — see
   `docs/features/tickets/tickets.md`, Confidentiality Filtering)
4. Apply `ticket_status` filter (if provided; invalid values silently
   ignored)
5. Apply `search` (ILIKE `%term%` substring match on `package_name`) or
   `name` (exact match)
6. Apply sorting (`sort_by`/`sort_order`; deterministic tiebreaker per
   `docs/api-spec.md`, Deterministic Pagination Ordering)
7. Execute paginated query
8. Compute `track_summary` via SQL aggregation (`COUNT(*) FILTER (WHERE
   status = ...)`) in the same query — NOT as Python post-processing —
   to avoid N+1 query patterns. Count only actionable tracks using the same
   `evaluation_date` as step 2
9. Return paginated `PackageListItem[]`

**No locking needed** — this is a read-only operation.

## Exclusion and Actionability Invariant

Every package-tree `deleted_at` mutation in this module is a direct authorized-user action
on the selected package, track, or Product. No helper propagates exclusion to
ancestors or descendants, and no system caller may invoke an exclusion or
restore operation with a null actor.

The module derives actionability through the shared SQL expressions specified
in `package-model.md`. A track with no actionable Products and a package with
no actionable tracks remain structurally present and retain their direct
markers unchanged. This invariant keeps manual intent independent from EOL and
other derived participation rules.

## Record Creation Logic

When `package_service` creates a new `TicketPackageTrack` record, the
initial status is always `ANALYSIS` and `delivery_status` is `PENDING`.

When it creates a new `TicketPackageProduct` record, eligibility is
calculated at creation time. See `docs/features/packages/package-model.md`
([Axis 2: Eligibility](package-model.md#axis-2-eligibility-per-product-only))
for the computation rules. Products do not have their own status — they
inherit affectedness implicitly from the parent track.

This logic is internal to `package_service` — callers (including
`add_package_to_ticket`) do not specify initial values.

## Concurrency Control

The generic pessimistic locking pattern and transaction hygiene rules
are defined in `docs/conventions.md` (Transaction and Locking). This
section documents package-specific refinements only.

All mutation functions in this module acquire `FOR UPDATE` on the parent
Ticket row as the first operation. This serializes concurrent package
mutations on the same ticket at the database level. The lock is released
automatically when the transaction commits or rolls back.

The I/O-then-Lock invariant (see Architecture section) is an additional
constraint specific to this module: orchestration functions that perform
external I/O MUST NOT acquire `FOR UPDATE` locks.

Track release reconciliation additionally validates the per-track checkpoint
predecessor under this Ticket lock. Polling, catch-up, RabbitMQ processing, and
retries must serialize or conditionally advance the checkpoint so a stale
worker cannot overwrite a newer accepted source state.

Product release detection likewise serializes concurrent first writes under
the Ticket lock. Once one transaction sets a Product occurrence's
`released_at`, every concurrent or repeated caller observes an irreversible
no-op and cannot replace the selected advisory time.

Exclusion, restoration, public addition, and internal re-resolution on the same
Ticket use the same serialization boundary. In addition to the direct-marker
outcomes defined above:

- a public add that acquires the lock after an exclusion commits observes the
  direct package marker and raises `PackageAlreadyExcludedError` before any
  local mutation;
- a public add that acquires the lock after a restore commits no longer has that
  guard and proceeds to its locked no-op, maintainer-only, or package-tree
  mutation outcome; and
- internal re-resolution proceeds beneath a concurrently committed exclusion,
  may add missing descendants or maintainers, and never clears any marker.

Each caller returns state valid for its own serialized turn. The contract does
not promise that a later transaction cannot change that state after commit.

## Service Exceptions

Module-owned exceptions raised by `package_service` inherit from
`PackageServiceError`. Shared service exceptions, `ValueError` caller-contract
violations, and delegated database, audit, or reconciliation exceptions do not
necessarily inherit from it. API endpoint handlers catch each documented
API-facing module-owned or shared exception and map it per `api-spec.md`.

### API-facing exceptions

Caught by endpoint handlers and mapped to HTTP responses:

| Exception | HTTP | Code | Raised when |
|-----------|------|------|-------------|
| `TicketNotFoundError` † | 404 | `TICKET_NOT_FOUND` | `FOR UPDATE` returns no row |
| `TicketNotMutableError` † | 409 | `TICKET_NOT_MUTABLE` | Ticket is in manual zone (defense in depth — API layer catches first) |
| `TrackNotFoundError` | 404 | `RESOURCE_NOT_FOUND` | Track ID does not exist under the declared Ticket/package path |
| `ProductNotFoundError` | 404 | `RESOURCE_NOT_FOUND` | Product occurrence ID does not exist under the declared Ticket/package/track path |
| `PackageNotFoundError` | 404 | `RESOURCE_NOT_FOUND` | Package ID does not exist under the declared Ticket path |
| `PackageAlreadyExcludedError` | 409 | `PACKAGE_ALREADY_EXCLUDED` | Soft-delete targets an already excluded record, or public package addition targets a directly excluded package occurrence |
| `PackageNotExcludedError` | 422 | `PACKAGE_NOT_EXCLUDED` | Restore on record with `deleted_at IS NULL` |
| `SmeltUnavailableError` | 503 | `SMELT_UNAVAILABLE` | SMELT transport fails after shared retries or SMELT does not produce a valid expected response |
| `ProductCatalogNotReadyError` | 503 | `PRODUCT_CATALOG_NOT_READY` | No complete SMELT Product catalog snapshot has committed |
| `PackageNotFoundInSmeltError` | 422 | `PACKAGE_NOT_FOUND_IN_SMELT` | SMELT returns zero tracks |
| `PackageTargetsUnresolvedError` | 422 | `PACKAGE_TARGETS_UNRESOLVED` | SMELT returns tracks but no target resolves through the current Product catalog snapshot |
| `TrackFixedStatusRestrictedError` | 403 | `AUTH_INSUFFICIENT_PERMISSION` | User-attributed caller uses the admin force marker inconsistently with the requested affectedness target |

† Shared exception — inherits from `ServiceError`, not from
`PackageServiceError`. Handlers must catch it explicitly.

### System-internal exceptions

Handled by system callers directly (not mapped to HTTP responses):

| Exception | Raised when | Handling |
|-----------|-------------|----------|
| `InvalidDeliveryStatusTransition` | Requested delivery transition is not one of the approved transitions or attempts to leave `RELEASED` | The shared IBS reconciler rolls back the track scope, records the sanitized local failure, and continues with independent scopes |

## Excluded and Non-Actionable Records

This section distinguishes Ticket operability, manual exclusion, and lifecycle
actionability, which have different semantics:

### Ticket-level operability

Non-operable tickets (Ignored or Duplicated) MUST NOT
receive any package mutations. `ensure_ticket_operable(ticket)` enforces
this for all mutation functions in this module (including
`set_product_released_at`). Automated callers (release detection
fetchers, IBS RabbitMQ consumer) scope their queries to active tickets
at query time (a stricter subset — excludes Resolved in addition to
non-operable statuses); the guard fires only in race conditions.
Required caller behavior: catch `TicketNotMutableError`, log a
WARNING, and continue processing the next item.

### Package-tree exclusion and actionability

Directly or effectively manually excluded package-tree records and EOL Products
continue to receive updates within each owning process's Ticket-status scope.
Local eligibility and lifecycle reconciliation may operate on all operable
Tickets. External IBS release and delivery monitoring operates only on active
Tickets; a Resolved Ticket is reconciled if it returns to an active status.
Exclusion and actionability control participation in decision-making, not
whether factual state can be updated within the applicable scope.

Mutation functions (`set_track_status`, `set_track_delivery_status`,
`set_product_eligibility`, `set_product_released_at`) do NOT require
child-record `deleted_at IS NULL` as a precondition. This ensures that
manually excluded and EOL records remain current with reality, enabling accurate
re-evaluation if a marker is restored or lifecycle data changes.

Restore functions require only that the targeted record is directly
excluded. A restore under an excluded ancestor, or a restore that leaves the
record lifecycle-non-actionable, is valid because it removes one independent
manual exclusion decision.

## Architectural Test Requirement

A parametrized integration test MUST be implemented to verify that the
`package_service` mutation functions correctly trigger
`reconcile_ticket_status` and produce the expected ticket status
transitions. The test must cover:

- **Forward transitions**: package mutations causing ticket advancement
  (e.g., setting all tracks to final status triggers Analyzed -> Resolved;
  or an AFFECTED track becoming resolution-complete because all its
  products become ineligible also triggers Analyzed -> Resolved)
- **Backward transitions**: package mutations breaking gate conditions
  (e.g., restoring a soft-deleted track with non-final status)
- **Independent exclusion scopes**: excluding or restoring one level does not
  modify ancestor or descendant markers; actionability and reason precedence
  are recalculated correctly. Cover all eight package/track/Product direct-marker
  combinations, each combination with and without EOL, exclusion beneath an
  excluded ancestor, parents with no actionable descendants, ancestor restore
  with directly excluded descendants, and deterministic reason precedence
- **Auto-assignment**: mutations on unassigned tickets trigger assignment
  to the acting VA; every direct-mutation no-op occurs before assignment,
  audit, Ticket reconciliation, and post-commit effects
- **Nested ownership validation**: every package, track, and Product occurrence
  mutation validates the complete declared path under the Ticket lock; test a
  correct path, each missing level, and each child-belongs-to-another-parent
  mismatch, all without mutating or revealing the other occurrence
- **Affectedness authority matrix**: cover every source state with
  `manage_packages` non-`FIXED`, `admin_ticket_ops` `FIXED`, system `FIXED`,
  protected final-state no-op, and rejected system non-`FIXED` outcomes; verify
  alternative capability authorization before accessibility
- **Concurrent direct mutations**: independent sessions serialize on the
  Ticket lock, return results from winner-current state, and preserve truthful
  audit old/new values without duplicate assignment or reconciliation. Cover
  exclude/exclude, restore/restore, exclude/restore, independent
  ancestor/descendant marker changes, public add racing with exclusion or
  restore, and internal re-resolution racing with exclusion
- **Automatic Product eligibility recalculation**: verify manual-override
  records are skipped; an `Ignored` or `Duplicated` Ticket is skipped without
  mutation, audit, or reconciliation; `Resolved` is processed; a fully
  converged Ticket is a no-op; and multiple changed
  `TicketPackageProduct` records produce one event per record followed by one
  Ticket reconciliation
- **Derived actionability**: verify Python/SQL lifecycle parity, all reason
  precedence cases, parent actionability, EOL entry/exit, and one shared UTC
  evaluation date across mutation, reconciliation, result projection, response
  rows, and aggregate counts, including a workflow that crosses midnight UTC;
  a pure EOL entry/exit
  creates no package-tree exclusion/restoration audit event, while an actual
  Ticket status change still creates the ordinary `status_change` event
- **Public Product identity**: package-tree Product responses expose
  `TicketPackageProduct.id` as `id`, the related Product CPE as `product_cpe`,
  and no internal catalog `Product.id`; Product mutation paths resolve
  `ticket_package_product_id` as the package-tree occurrence
- **Human-readable Product audit subjects**: every Product event persists the
  event-time Product name and CPE with package and track context; release
  events preserve the actual `released_at`, and VA eligibility events
  distinguish override set, change, and clear actions
- **Exclusion/restore actor and rollback**: a null actor raises `ValueError`
  before every database operation; successful direct-marker changes create
  exactly one event with the acting user and exact old/new/detail payload;
  repeated-call losers and EOL-only changes create none; audit,
  reconciliation, and flush failures roll back marker, assignment, event, and
  status effects; rejected repeats leave no durable side effect
- **Maintainership acquisition**: every package-resolution invocation attempts
  the maintainership request after target validation and before locking;
  transport/HTTP/envelope/schema failures continue with an empty set and a
  PII-free warning; direct users and group members deduplicate by lowercase
  email; only current active exact-email User matches are associated; a
  package-tree no-op, including Product catalog backfill, can add associations;
  concurrent calls serialize; sequential unchanged re-invocation creates no
  duplicate row or event; every new association has one atomic system event;
  association-only mutation does not assign or reconcile, leaves public result
  fields/counts unchanged, and later omission/failure never removes rows;
  maintainer visibility does not grant any capability-protected mutation
- **Track release composition**: verify IBS I/O completes before the Ticket
  lock; an effective automatic `FIXED` transition, its one service-owned audit
  event, Ticket reconciliation, and checkpoint advancement commit atomically;
  any local failure rolls them all back; checkpoint-only outcomes create no
  event and do not touch the track timestamp; final-status and repeated
  outcomes are no-ops; final-state races permit checkpoint advancement;
  rejected system targets fail the workflow unit and retain the checkpoint;
  independent sessions verify concurrent checkpoint anti-regression
- **Product release composition**: verify repository I/O and complete metadata
  validation occur before the Ticket lock; an effective release timestamp, its
  one service-owned event, and Ticket reconciliation commit atomically; local
  failure rolls back all three; and concurrent or repeated calls preserve the
  first committed timestamp without another event or reconciliation
- **Delivery mutation composition**: verify every approved transition, an
  unchanged no-op, rejection of direct `PENDING → RELEASED` and every change
  out of `RELEASED`, two-step atomic advancement from `PENDING` to `RELEASED`,
  compatibility when the caller already holds the Ticket lock, caller-owned
  rollback, and the absence of assignment, Ticket reconciliation, and audit
  events
- **Package creation concurrency and result truth**: verify one locked winner,
  truthful created/skipped counts, and distinct package-tree change,
  package-tree no-op, maintainer-only, and skipped-inactive outcomes; only an
  effective package-tree change assigns and reconciles
- **Dimension independence**: affectedness, eligibility, track delivery, and
  Product release observations do not mutate or suppress one another; the
  Ticket gate ignores `delivery_status`, while independently computed results
  may commit atomically without becoming mutual inputs
- **Package-add request catch-up**: verify one post-commit generic
  `run_catch_up("sync_ibs_requests", ticket_id)` publication when at least one
  IBS track is created, no publication for every documented non-triggering
  outcome, no publication before commit, and best-effort failure without
  rollback; no dedicated submission task is used

## Cross-references

- `docs/features/tickets/ticket-mutations.md` — `reconcile_ticket_status()`,
  `auto_assign_actor()`, `ensure_ticket_operable()`, ticket-centric mutations
- `docs/features/tickets/tickets.md` — ticket lifecycle, gate
  conditions, confidentiality filtering (`confidential_ticket_filter()`)
- `docs/features/tickets/ticket-audit-log.md` — event type contract
- `docs/features/packages/product-catalog.md` — current repository mappings
  and Product catalog backfill
- `docs/features/tickets/cvss-scoring.md` — CVSS resolution cascade,
  eligibility threshold comparison
- `docs/features/packages/package-model.md` — track/Product concepts,
  exclusion and actionability model, API endpoints
- `docs/features/packages/product-lifecycle-transitions.md` — AIMAAS
  threshold changes triggering eligibility mutations
- `docs/features/packages/ibs-track-release-detection.md` — IBS
  track-level release detection
- `docs/features/packages/ibs-product-release-detection.md` — IBS
  product-level release detection
- `docs/features/packages/ibs-submission-tracking.md` — SR/RR tracking,
  delivery pipeline
- `docs/features/integrations/ibs-rabbitmq-integration.md` — real-time
  IBS event consumption
- `docs/features/packages/package-maintainership.md` — SMELT maintainership
  acquisition, additive associations, privacy, and visibility
- `docs/conventions.md` — Transaction and Locking (pessimistic locking,
  I/O-then-Lock corollary)
- `docs/api-spec.md` — general API conventions
