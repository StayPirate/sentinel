# Ticket Service

## Purpose

Centralize non-gate ticket lifecycle operations — creation, CVE
association, assignment, manual-zone entries, and confidentiality
management — in a single service module
(`ticket_service`). This ensures that:

- `FOR UPDATE` locking is consistently applied on the Ticket row
- `TicketAuditEvent` records are always created atomically
- `reconcile_ticket_status()` is called when operations have side effects
  on gate conditions (severity changes, status reconciliation)
- `auto_assign_actor()` is applied uniformly for unassigned tickets
- `ensure_ticket_operable()` enforces mutability regardless of entry
  point
- Business rules (idempotency) are enforced regardless of entry point

Gate-relevant mutations (CVSS assessments, manual severity,
manual-zone exits) are handled by `ticket_mutations`
(`docs/features/tickets/ticket-mutations.md`). Package-centric mutations
are handled by `package_service`
(`docs/features/packages/package-service.md`).

Read-only operations (listing tickets, retrieving ticket details,
searching) are not centralized in this service because they carry no
business logic, side effects, or audit trail requirements. They are
implemented directly in API endpoint handlers (see
`docs/features/tickets/tickets.md`).

## Architecture

### Module location

`backend/app/services/ticket_service.py`

### Async pattern

The service is implemented as async functions. The API (FastAPI) is the
primary consumer and calls the service directly with `await`. Synchronous
process entry points establish one async workflow boundary and await service
calls within it; they do not create a new event loop for each mutation. See
`docs/conventions.md` (Sync-to-Async Bridging).

| Entry point            | Invocation pattern                                          |
|------------------------|-------------------------------------------------------------|
| API endpoint           | `await ticket_service.assign_ticket(session, ...)`          |
| cve_service (async)    | `await ticket_service.create_ticket(session, ...)`          |

### Transaction ownership

The module does NOT commit or roll back. All operations execute within
the caller's database session. Commit responsibility belongs to the
caller.

This matches the `ticket_mutations`, `package_service`, and
`user_service` pattern — the module applies mutations and creates audit
events, but the transaction boundary is the caller's decision.

### Acting user convention

All mutation operations accept an `acting_user_id: UUID | None`
parameter:

- `UUID` — action performed by an authenticated user. Enables
  auto-assignment on unassigned tickets if the user holds the
  `vulnerability_analyst` role
- `None` — system action (CVE ingestion or another specified automatic
  creation source). Auto-
  assignment does not apply

**API handler rule**: API endpoint handlers MUST always pass the UUID of
the authenticated user as `acting_user_id`. Passing `None` from an API
handler is a bug — it would silently bypass auto-assignment. `None` is
reserved exclusively for system entry points.

**Exception**: `grant_access` and `revoke_access` accept
`acting_user_id: UUID` (non-optional) because these operations are
inherently user-initiated — there is no system scenario for granting or
revoking explicit access.

### Relationship with other modules

| Module | Relationship |
|--------|-------------|
| `services/ticket_mutations.py` | `ticket_service` imports `reconcile_ticket_status()`, `recalculate_cvss_chain()`, `auto_assign_actor()`, and `ensure_ticket_operable()` from `ticket_mutations`. The dependency is unidirectional: `ticket_service` → `ticket_mutations`. Neither module imports from the other in the reverse direction |
| `services/package_service.py` | No direct dependency. Both modules independently depend on `ticket_mutations` for status evaluation |
| `services/cvss.py` | No direct dependency. CVSS resolution is delegated through `ticket_mutations.recalculate_cvss_chain()` where this service requires it |

## Scope Boundary

The following ticket mutation endpoints route to `ticket_mutations`,
not `ticket_service`, because they are gate-relevant or manual-zone
exit operations:

| Endpoint | Function | Reason |
|----------|----------|--------|
| `PATCH .../severity` | `set_severity_manual()` | Gate-relevant (severity affects Analyzed gate #3) |
| `POST .../reopen` | `reopen_from_ignored()` | Manual-zone exit (re-enters gate zone via `_reenter_gate_zone()`) |
| `POST .../revert-duplicate` | `revert_duplicate()` | Manual-zone exit (re-enters gate zone via `_reenter_gate_zone()`) |

See [ticket-mutations.md](ticket-mutations.md) for these operations'
contracts.

### Operability guard

Operations that modify the Ticket row (all mutation functions except
`create_ticket`) call `ensure_ticket_operable(ticket)` from
`ticket_mutations` after acquiring `FOR UPDATE`. This checks:

1. **Mutability guard**: status ∈ {Ignored, Duplicated} →
   `TicketNotMutableError`

Explicit opt-outs (functions that do NOT call `ensure_ticket_operable`):

- `ignore_ticket` — calls `ensure_ticket_operable` (which catches
  Ignored/Duplicated), then applies its own status check (New/Analysis
  required). See ordering constraint below

**Ordering constraint for `ignore_ticket`**:
`ensure_ticket_operable` executes first. For Ignored/Duplicated tickets
it raises `TicketNotMutableError` before the function's own status check
fires. For other non-valid statuses (Analyzed, Resolved), the function's
own check raises `InvalidTransitionError`. This ordering is contractual.

### Concurrency control

All mutation operations that modify only the Ticket root follow the
pessimistic locking pattern defined in `docs/conventions.md`
(Transaction and Locking) and extended by `ticket-mutations.md`
(Concurrency Control). Every such operation acquires `FOR UPDATE` on the
Ticket row as its first database operation.

`associate_cve()` participates in both CVE-owned and Ticket-owned state and
therefore uses the global root order: lock the CVE first, then the Ticket. This
is the only existing-row exception in this module to the Ticket-first rule.

Creating a CVE-less Ticket performs only an INSERT and needs no existing-root
lock. When `create_ticket()` associates a CVE, it resolves and locks that CVE
before inserting the Ticket. The Ticket uniqueness constraint remains the
final defense against concurrent INSERTs for the same CVE.

## Ticket Lifecycle Operations

### create_ticket

Creates a new ticket. Optionally associates a CVE and sets initial
status based on the creating user's role.

```python
async def create_ticket(
    db: AsyncSession,
    *,
    acting_user_id: UUID | None,
    cve_id: str | None = None,
    severity_manual: Severity | None = None,
    is_confidential: bool = False,
    source: TicketCreationSource,
) -> Ticket:
```

`TicketCreationSource` is a service-layer-only Python enum (not a
database column — it is never persisted). Values: `manual` and
`cve_ingestion`. It determines the audit event comment (e.g., "Ticket created
manually" or "CVE ingested from NVD"). Defined in
`backend/app/services/ticket_service.py`.

**Preconditions**:

- If `cve_id` is provided: CVE Resolution Behavior applies (on-demand
  fetch if unknown, conflict check if already associated with another
  ticket)
- If `is_confidential` is True: the acting user must hold
  `manage_confidentiality` capability (enforced at the API layer)
- If both `cve_id` and `severity_manual` are provided: the service
  raises `SeverityDerivedError`. When a CVE is associated, severity is
  derived exclusively from CVSS assessments — manual severity is not
  applicable. UI implementations should disable the severity field when
  a CVE is provided at creation time

**Behavioral steps**:

1. If `cve_id` is provided, resolve CVE via CVE Resolution Behavior and retain
   `FOR UPDATE` on the CVE before reading association state or inserting the
   Ticket. A newly inserted CVE is already owned by the transaction. If no CVE
   is provided, no row lock is required
2. INSERT new Ticket row with initial fields (all unspecified columns
   use database defaults: `duplicate_of_id = NULL`,
   `updated_at = now(UTC)`, etc.)
3. Determine initial status:
   - If `acting_user_id` is not None AND user holds VA role:
     `status = Analysis`, `assignee_id = acting_user_id`
   - Otherwise: `status = New`
4. Create `TicketAuditEvent` (`ticket_created`, comment from `source`). This is
   always the first event in the Ticket's history, before every optional
   severity, assignment, or CVE-association event below
5. If `severity_manual` provided: create `TicketAuditEvent`
   (`severity_changed`, `old_value = NULL`, `new_value = <severity>`)
6. If assigned (step 3): create `TicketAuditEvent` (`assignment`)
7. If CVE associated: create `TicketAuditEvent` (`cve_associated`)
8. Return the created Ticket

**Concurrency — CVE uniqueness**: If the INSERT raises an
`IntegrityError` due to the UNIQUE constraint on `Ticket.cve_id` (race
between concurrent creation for the same CVE), the service catches the
exception and raises `TicketCVEConflictError`. The API handler maps this
to `409 TICKET_CVE_CONFLICT`.

**Locking**: none for CVE-less creation. CVE-associated creation locks the CVE
before the Ticket INSERT. This serializes association state with concurrent
CVSS mutations; the new Ticket row itself has no pre-existing row to lock.

**reconcile_ticket_status**: Not called — initial status is determined by
fixed rules, and the ticket cannot have packages at creation time.

**Audit events**: Up to 4 (`ticket_created`, `severity_changed`,
`assignment`, `cve_associated`).

### associate_cve

Associates a CVE with a ticket that does not yet have one.

```python
async def associate_cve(
    db: AsyncSession,
    *,
    ticket_id: UUID,
    cve_id: str,
    acting_user_id: UUID,
) -> Ticket:
```

**Preconditions**:

- Ticket must be operable (`ensure_ticket_operable`)
- Ticket must have `cve_id IS NULL` (else `TicketCVEAlreadySetError`)
- CVE Resolution Behavior applies (on-demand fetch, conflict check)

**Behavioral steps**:

1. Resolve or create the local CVE through CVE Resolution Behavior without
   holding a Ticket lock. For an existing CVE, the resolution query acquires
   `FOR UPDATE` as its first persistent read; a newly inserted CVE becomes the
   transaction's locked root. No external I/O occurs in this transaction.
2. Retain the CVE `FOR UPDATE` lock established by step 1.
3. Acquire `FOR UPDATE` on the Ticket row.
4. Call `ensure_ticket_operable(ticket)`.
5. Verify `ticket.cve_id IS NULL` (else `TicketCVEAlreadySetError`) and, under
   the CVE lock, verify that no other Ticket is associated with the CVE (else
   `TicketCVEConflictError`).
6. `auto_assign_actor(ticket, acting_user_id)`.
7. Capture `previous_severity = ticket.severity_manual` (may be `NULL`).
8. Set `ticket.cve_id` and clear `ticket.severity_manual = NULL` (same
    UPDATE — maintains `chk_ticket_severity_manual_cve_exclusive`)
9. Create `TicketAuditEvent` (`cve_associated`,
    `user_id = acting_user_id`).
10. Call `recalculate_cvss_chain(cve.id)`. The same-transaction re-locks
    preserve the CVE-then-Ticket order and observe all assessment mutations
    committed before this operation acquired the CVE lock.
11. Determine `new_severity` from the committed-current CVE severity (possibly
    `NULL`). If `previous_severity != new_severity`, create
    `TicketAuditEvent` (`severity_changed`, `user_id = NULL`,
    `old_value = previous_severity`, `new_value = new_severity`,
    `detail = NULL`). This event captures the handover from manual to
    CVSS-derived severity; Sentinel derived it, so the associating user is not
    its actor.
12. Return the immediate eligibility handoff to the owning composition. This
    specification does not define its package-domain consumer. Call
    `reconcile_ticket_status()` for the association's currently defined Ticket
    effects; gate #3 (severity set) and gate #4 (SUSE CVSS provided) may now
    fail, causing regression to Analysis.
13. Return updated Ticket.

**Locking**: `FOR UPDATE` on CVE, then `FOR UPDATE` on Ticket. CVE Resolution
Behavior involves only local database operations and may insert a minimal CVE
before that row can be locked. No synchronous external HTTP call or
Redis/Celery operation occurs while either lock is held. Re-locking either row
inside `recalculate_cvss_chain()` is a same-transaction no-op. Task dispatch via
`trigger_on_demand_fetch()` is the endpoint handler's responsibility and MUST
occur after `db.commit()`, outside the locked transaction.

This order serializes correctly with CVSS mutation. If the CVSS mutation locks
the CVE first, association waits and then consumes its committed severity. If
association locks first, the CVSS mutation waits, then observes the associated
Ticket and applies its direct-audit and propagation contract. Neither path can
use a pre-lock assessment or association snapshot.

**recalculate_cvss_chain**: YES. Associating a CVE changes the Ticket's
severity source. The function confirms the CVE-owned severity from the complete
locked assessment set and returns the separate Eligibility Score result. The
result is available to the package-owned boundary; this specification does not
define that boundary's consumption.
If the CVE has no assessments, severity resolves to `null` (gate #3 fails) and
eligibility uses the 10.0 conservative fallback.

`associate_cve` owns the manual-to-derived handover event because it retains
the previous `severity_manual` value. The delegated calculation reports any
CVE severity change but emits no event directly; association emits exactly one
handover event when the source transition changes the effective value.

**Note on pre-existing CVSS assessments**: If the CVE being associated
already has `CVECVSSAssessment` records (e.g., from a prior NVD sync), these
assessments are immediately available to the CVSS resolution cascade.
`recalculate_cvss_chain()` uses them to confirm severity and produce the
package-domain eligibility handoff without requiring a fresh NVD fetch.

**Audit events**: `cve_associated` (always). `severity_changed` (if
`previous_severity != new_severity` — captures the manual→derived
handover; emitted by `associate_cve` with `user_id = NULL`, not attributed to
the associating user). `cve_associated` retains `user_id = acting_user_id`.
Possibly `assignment` and `status_change` (from auto-assign), and possibly
`status_change` from reconciliation. This contract does not create a Product
eligibility event.

### assign_ticket

Assigns or reassigns a ticket to a user.

```python
async def assign_ticket(
    db: AsyncSession,
    *,
    ticket_id: UUID,
    assignee_id: UUID,
    acting_user_id: UUID | None,
) -> Ticket:
```

**Preconditions**:

- Ticket must be operable (`ensure_ticket_operable`)
- Target user must be active (else `AssigneeInactiveError`) and hold
  the `vulnerability_analyst` role (else `AssigneeNotVAError`)

**Behavioral steps**:

1. Acquire `FOR UPDATE` on the Ticket row
2. Call `ensure_ticket_operable(ticket)`
3. Validate target user (active — else `AssigneeInactiveError`;
    holds VA role — else `AssigneeNotVAError`)
4. **Idempotency check**: if `ticket.assignee_id == assignee_id`, return
    ticket unchanged (no audit event, no status evaluation)
5. Set `ticket.assignee_id = assignee_id`
6. Create `TicketAuditEvent` (`assignment`)
7. If `ticket.status == New`: set `ticket.status = Analysis`, create
    `TicketAuditEvent` (`status_change`, `user_id = NULL`,
    `old_value = "New"`, `new_value = "Analysis"`) — this is the explicit
    `New → Analysis` transition (see Architectural Invariant in
    `tickets.md`); the `status_change` event is created here, not by
    `reconcile_ticket_status`
8. Call `reconcile_ticket_status(ticket)` — evaluates further promotion
    from `Analysis` upward; may produce a second `status_change` event
    if `Analyzed` or `Resolved` gate conditions are already satisfied
9. Return updated Ticket

**Locking**: FOR UPDATE on Ticket row.

**reconcile_ticket_status**: YES — evaluates whether the ticket's
existing data satisfies gates above `Analysis` (Analyzed or Resolved).
While `ticket-mutations.md` classifies assignment as "not gate-relevant"
in the sense that it does not modify CVSS/severity/package data, the
explicit `New → Analysis` transition in step 7 means the ticket is now
in the gate zone and `reconcile_ticket_status` can promote it further
if conditions are met.

**Audit events**: `assignment` (only if assignee actually changes).
Possibly `status_change` (explicit `New → Analysis` in step 7 and/or
further promotion from `reconcile_ticket_status`).

**auto_assign_actor**: Not called — this operation performs an explicit
assignment to a specified user, which supersedes implicit
auto-assignment of the acting user.

### ignore_ticket

Transitions a ticket to Ignored status (manual-zone entry).

```python
async def ignore_ticket(
    db: AsyncSession,
    *,
    ticket_id: UUID,
    acting_user_id: UUID | None,
) -> Ticket:
```

**Preconditions**:

- Ticket must be operable (`ensure_ticket_operable`) — catches
  Ignored and Duplicated tickets before the status check
- Ticket must be in New or Analysis status (only valid source states;
  else `InvalidTransitionError`)

**Behavioral steps**:

1. Acquire `FOR UPDATE` on the Ticket row
2. Call `ensure_ticket_operable(ticket)` — rejects Ignored or Duplicated
   (`TicketNotMutableError`) tickets
3. Verify status is New or Analysis (else `InvalidTransitionError` —
   this catches Analyzed and Resolved, which pass `ensure_ticket_operable`
   but are not valid source states for ignore)
4. `auto_assign_actor(ticket, acting_user_id)`
5. Set `ticket.status = Ignored`
6. Create `TicketAuditEvent` (`status_change`)
7. Return updated Ticket

**Locking**: FOR UPDATE on Ticket row.

**reconcile_ticket_status**: NOT called — this is a direct transition
into the manual zone. `reconcile_ticket_status` never operates on
Ignored tickets.

**Audit events**: `status_change`. Possibly `assignment` (from
auto-assign).

### mark_as_duplicate

Marks a ticket as a duplicate of another non-Duplicated ticket. If
other tickets currently point to the source, they are atomically
repointed to the target within the same transaction.

```python
async def mark_as_duplicate(
    db: AsyncSession,
    *,
    ticket_id: UUID,
    duplicate_of_id: UUID,
    acting_user_id: UUID | None,
) -> Ticket:
```

**Preconditions**:

- Source ticket must exist (else `TicketNotFoundError`)
- Target ticket must exist (else `TicketNotFoundError`)
- Target ticket must be accessible to the acting user (API-layer scope
  check; confidential target without access → 404)
- Source ticket must be operable (`ensure_ticket_operable`)
- Target must not be in Duplicated status (else
  `DuplicateTargetIsDuplicatedError`)
- Source must not equal target (else `SelfDuplicateError`)

**Behavioral steps**:

1. **Phase 1 — lock and validate roots**:
   a. Determine lock order: `first = min(source_id, target_id)`,
      `second = max(source_id, target_id)`
   b. `SELECT ... WHERE id = first FOR UPDATE` — lock first root
   c. Validate the first root immediately (operable if source,
      non-Duplicated if target)
   d. `SELECT ... WHERE id = second FOR UPDATE` — lock second root
   e. Validate the second root immediately
   f. Validate source != target (else `SelfDuplicateError`)
2. **Phase 2 — lock dependents**:
   `SELECT ... WHERE duplicate_of_id = source_id ORDER BY id FOR UPDATE NOWAIT`
   On SQLSTATE `55P03`: rollback and raise
   `DuplicateConcurrentModificationError`
3. **Mutations** (only reached if all locks acquired):
   a. `auto_assign_actor(source, acting_user_id)`
   b. Set `source.status = Duplicated`,
      `source.duplicate_of_id = target_id`
   c. Create `TicketAuditEvent` (`status_change`,
      old_value = source's current status after auto_assign,
      new_value = `Duplicated`, user_id = acting_user_id)
   d. Create `TicketAuditEvent` (`duplicate_set`,
      old_value = NULL, new_value = target's `SNTL-{n}`,
      user_id = acting_user_id)
   e. For each dependent ticket:
      - Set `dependent.duplicate_of_id = target_id`
      - Create `TicketAuditEvent` (`duplicate_target_changed`,
        old_value = source's `SNTL-{n}`,
        new_value = target's `SNTL-{n}`,
        user_id = NULL,
        detail = `{"triggered_by_ticket": "SNTL-{n}"}` where the
        value is the source ticket's identifier)
      - Dependents are repointed as a system action (`user_id = NULL`);
        no confidentiality access check is applied to dependent tickets
4. Return updated source ticket

**Post-operation**: no post-commit work. Everything is atomic.

**Locking**: source + target (blocking, ordered) + dependents (NOWAIT,
ordered). All within a single transaction.

**Constraint**: `mark_as_duplicate` MUST execute in a transaction
holding no pre-existing Ticket row locks. This ensures Phase 1 is
always the first lock acquisition on Ticket rows in the transaction,
preventing ordering inversions with locks acquired by prior operations
in the same session.

**reconcile_ticket_status**: NOT called — direct transition into
manual zone.

**Audit events**:
- `status_change` (on source — records the `{current} → Duplicated`
  transition)
- `duplicate_set` (on source — records the link creation)
- One `duplicate_target_changed` per dependent (system action)
- Plus any events produced by `auto_assign_actor` (e.g.,
  `status_change` for `New → Analysis`, `assignment`) — see
  `ticket-mutations.md`

**Atomicity guarantee**: if any step fails (validation, NOWAIT
conflict, or database error), the entire transaction rolls back. No
mutations or audit events persist.

## Ticket Reactivation

When a ticket transitions from an inactive status (Resolved, Ignored, or
Duplicated) back to an active status, the system registers the asynchronous
package-tree then per-ticket fetcher catch-up. It first
   re-resolves every persisted package marker through SMELT, including
   soft-deleted markers without restoring them, then catches up on external
   data against the resulting tree (e.g., Red Hat CVSS updates — the
   `sync_redhat_cves` fetcher scopes to active tickets and skips inactive
   ones). See `docs/features/packages/package-model.md` (Reactivation and
   Convergence) and
   [fetcher-infrastructure.md](../platform/fetcher-infrastructure.md)
   ("Per-Ticket Catch-Up: `catch_up()` Method") for the method contract.

The workflow is registered internally by `reconcile_ticket_status()` (step 4)
when it detects an inactive-state exit and runs after commit. CVSS assessment
mutations maintain `CVE.severity` in every status. A setting-only default-version
change remains subject to the inactive-CVE convergence limitation in
`system-settings.md`; this reactivation path does not acquire a CVE lock while
holding the Ticket lock. The package-owned reactivation workflow resolves
current eligibility from persisted inputs. No action is needed by endpoint
handlers or callers. This applies to all three
inactive → active paths:

- `reopen_from_ignored()` — Ignored → active (via
  [ticket-mutations.md](ticket-mutations.md), `_reenter_gate_zone()`)
- `revert_duplicate()` — Duplicated → active (via
  [ticket-mutations.md](ticket-mutations.md), `_reenter_gate_zone()`)
- Gate-driven regression — Resolved → active (automatic, via any
  mutation that unsatisfies a gate)

### Convergence behavior

The ticket may transition rapidly as async tasks complete. For example,
if a release was detected while the ticket was inactive, the IBS
catch-up may set tracks to FIXED and products to released, causing the
ticket to reach Resolved shortly after reactivation. This is expected
behavior — the system converges to the accurate state.

### Cross-references

- [cvss-scoring.md](cvss-scoring.md) — CVSS resolution cascade,
  recalculation trigger rationale
- [ticket-mutations.md](ticket-mutations.md) —
  `reconcile_ticket_status()` step 4, `recalculate_cvss_chain()`
  contract, `_reenter_gate_zone()` helper
- [fetcher-infrastructure.md](../platform/fetcher-infrastructure.md) —
  `catch_up()` method contract

## Confidentiality Management

### set_confidentiality

Toggles the `is_confidential` flag on a ticket.

```python
async def set_confidentiality(
    db: AsyncSession,
    *,
    ticket_id: UUID,
    is_confidential: bool,
    acting_user_id: UUID | None,
) -> Ticket:
```

**Preconditions**:

- Ticket must be operable (`ensure_ticket_operable`)
- Requires `manage_confidentiality` capability (enforced at API layer)

**Behavioral steps**:

1. Acquire `FOR UPDATE` on the Ticket row
2. Call `ensure_ticket_operable(ticket)`
3. **Idempotency check**: if `ticket.is_confidential == is_confidential`,
    return ticket unchanged (no audit event)
4. Set `ticket.is_confidential = is_confidential`
5. Create `TicketAuditEvent` (`confidentiality_changed`)
6. Return updated Ticket

**Note on access grants**: When setting `is_confidential = false`,
existing `TicketAccessGrant` records are NOT deleted immediately. They
become inert (the confidentiality filter no longer restricts access).
Stale grants are cleaned up by a periodic task (weekly, 14-day delay).
See `tickets.md` (Stale Access Grant Cleanup) for details.

**Locking**: FOR UPDATE on Ticket row.

**reconcile_ticket_status**: NOT called — confidentiality is not
gate-relevant.

**Audit events**: `confidentiality_changed` (only if value actually
changes).

### grant_access

Grants explicit access to a user on a confidential ticket.

```python
async def grant_access(
    db: AsyncSession,
    *,
    ticket_id: UUID,
    target_user_id: UUID,
    acting_user_id: UUID,
) -> TicketAccessGrant:
```

**Preconditions**:

- Ticket must be operable (`ensure_ticket_operable`)
- Ticket must be confidential (`is_confidential = true`; else
  `TicketNotConfidentialError`)
- Target user must exist (else `UserNotFoundError`)
- Target user must be active (else `InactiveUserError`). Note: this
  check does not apply to `revoke_access` — revoking a grant from an
  inactive user is a legitimate cleanup operation
- Requires `manage_confidentiality` capability (enforced at API layer)

**Behavioral steps**:

1. Acquire `FOR UPDATE` on the Ticket row
2. Call `ensure_ticket_operable(ticket)`
3. Verify ticket is confidential (else `TicketNotConfidentialError`)
4. Verify target user is active (else `InactiveUserError`)
5. **Idempotency check**: if grant already exists for this user, return
    existing grant unchanged (no audit event)
6. INSERT `TicketAccessGrant` record (`ticket_id`, `user_id`,
    `granted_by = acting_user_id`, `granted_at = now(UTC)`)
7. Create `TicketAuditEvent` (`access_grant_added`)
8. Return the created grant

**Concurrency**: If two concurrent requests attempt to grant access to
the same user, the UNIQUE constraint on `TicketAccessGrant`
(`ticket_id`, `user_id`) prevents duplicates. The service catches the
resulting `IntegrityError` and treats it as an idempotent success
(returns the existing grant, no audit event).

**Locking**: FOR UPDATE on Ticket row (provides immutability guard
consistency with other mutation functions).

**reconcile_ticket_status**: NOT called — access grants are not
gate-relevant.

**Audit events**: `access_grant_added` (only if grant is new).

### revoke_access

Revokes explicit access from a user on a confidential ticket.

```python
async def revoke_access(
    db: AsyncSession,
    *,
    ticket_id: UUID,
    target_user_id: UUID,
    acting_user_id: UUID,
) -> None:
```

**Preconditions**:

- Ticket must be operable (`ensure_ticket_operable`)
- Ticket must be confidential (`is_confidential = true`; else
  `TicketNotConfidentialError`)
- Target user must exist (else `UserNotFoundError`)
- Requires `manage_confidentiality` capability (enforced at API layer)

**Behavioral steps**:

1. Acquire `FOR UPDATE` on the Ticket row
2. Call `ensure_ticket_operable(ticket)`
3. Verify ticket is confidential (else `TicketNotConfidentialError`)
4. **Idempotency check**: if grant does not exist for this user, return
    without side effects (no audit event)
5. Delete `TicketAccessGrant` record
6. Create `TicketAuditEvent` (`access_grant_removed`)
7. Return

**Locking**: FOR UPDATE on Ticket row (provides immutability guard
consistency with other mutation functions).

**reconcile_ticket_status**: NOT called.

**Audit events**: `access_grant_removed` (only if grant existed).

### list_access_grants

Lists all users with explicit access grants for a confidential ticket.

```python
async def list_access_grants(
    db: AsyncSession,
    *,
    ticket_id: UUID,
) -> list[TicketAccessGrant]:
```

**Preconditions**:

- Ticket must be confidential (`is_confidential = true`; else
  `TicketNotConfidentialError`)
- Requires `manage_confidentiality` capability (enforced at API layer)

**Behavioral steps**:

1. Verify ticket is confidential (else `TicketNotConfidentialError`)
2. Query `TicketAccessGrant` records for the ticket, ordered by
   `granted_at` ascending
3. Return list

**Locking**: None (read-only).

**reconcile_ticket_status**: NOT called.

**Audit events**: None (read-only).

## Service Exceptions

All exceptions in this module inherit from `TicketServiceError`.
API endpoint handlers catch `TicketServiceError` subclasses and map them
to the corresponding HTTP status code and error code per `api-spec.md`.

| Exception | HTTP | Code | Raised when |
|-----------|------|------|-------------|
| `TicketNotFoundError` † | 404 | `TICKET_NOT_FOUND` | Ticket ID does not exist |
| `TicketNotMutableError` † | 409 | `TICKET_NOT_MUTABLE` | Ticket is in manual zone (Ignored or Duplicated) |
| `InvalidTransitionError` † | 409 | `TICKET_INVALID_TRANSITION` | Requested status transition is not allowed |
| `TicketCVEAlreadySetError` | 400 | `TICKET_CVE_ALREADY_SET` | Ticket already has a CVE associated |
| `TicketCVEConflictError` | 409 | `TICKET_CVE_CONFLICT` | CVE is already associated with another ticket |
| `AssigneeNotVAError` | 400 | `TICKET_ASSIGNEE_NOT_VA` | Target user lacks the vulnerability_analyst role |
| `AssigneeInactiveError` | 409 | `TICKET_ASSIGNEE_INACTIVE` | Target user is inactive (for assignment) |
| `InactiveUserError` † | 409 | `USER_INACTIVE` | Target user is inactive (for access grant) |
| `SelfDuplicateError` | 400 | `TICKET_SELF_DUPLICATE` | Ticket cannot be marked as duplicate of itself |
| `DuplicateTargetIsDuplicatedError` | 409 | `TICKET_DUPLICATE_TARGET_DUPLICATED` | Target ticket is already in Duplicated status |
| `DuplicateConcurrentModificationError` | 409 | `TICKET_DUPLICATE_CONCURRENT_MODIFICATION` | NOWAIT lock on a dependent failed (concurrent operation on the duplicate group) |
| `SeverityDerivedError` † | 409 | `TICKET_SEVERITY_DERIVED` | Cannot manually set severity when it is auto-derived |
| `TicketNotConfidentialError` | 409 | `TICKET_NOT_CONFIDENTIAL` | Operation requires a confidential ticket |
| `UserNotFoundError` † | 404 | `USER_NOT_FOUND` | Referenced user does not exist |
| `CVEIdFormatError` † | 422 | `CVE_INVALID_FORMAT` | CVE-ID passed to `ensure_cve_exists()` does not match `^CVE-[0-9]{4}-[0-9]{4,}$` (defense-in-depth; fires only if caller omits pre-validation) |

† Shared exception — inherits from `ServiceError` (or `CVEServiceError`
for `CVEIdFormatError`), not from `TicketServiceError`. Handlers must
catch it explicitly.

## Dependency Summary

```
ticket_mutations (infrastructure)
    ├── reconcile_ticket_status()
    ├── recalculate_cvss_chain()
    ├── auto_assign_actor()
    └── ensure_ticket_operable()
         ▲                ▲
         │                │
  ticket_service    package_service
  (non-gate ops)    (package ops)
```

| ticket_service function | ensure_ticket_operable | reconcile_ticket_status | recalculate_cvss_chain | auto_assign_actor |
|------------------------|:----------------------:|:----------------------:|:---------------------:|:---------------------:|
| create_ticket          | —                      | —                      | —                     | —                     |
| associate_cve          | ✓                      | ✓                      | ✓                     | ✓                     |
| assign_ticket          | ✓                      | ✓                      | —                     | —                     |
| ignore_ticket          | ✓                      | —                      | —                     | ✓                     |
| mark_as_duplicate      | ✓                      | —                      | —                     | ✓                     |
| set_confidentiality    | ✓                      | —                      | —                     | —                     |
| grant_access           | ✓                      | —                      | —                     | —                     |
| revoke_access          | ✓                      | —                      | —                     | —                     |
| list_access_grants     | —                      | —                      | —                     | —                     |

## Architectural Test Requirement

The following integration tests MUST be implemented to verify correct
behavior of `ticket_service` operations:

1. **CVE association causes status regression**: create a ticket without
   CVE, set `severity_manual`, add a package with tracks in final
   status to reach Analyzed. Associate a CVE → verify ticket regresses
   to Analysis (gate #3 and #4 fail)

2. **Assignment promotes New → Analysis explicitly**: create a ticket in
   New status. Assign a VA → verify ticket promotes to Analysis and a
   `status_change` event with `old_value = "New"`, `new_value = "Analysis"`,
   `user_id = NULL` is created (not by `reconcile_ticket_status` but by
   the explicit step in `assign_ticket` before calling reconcile)

3. **Assignment idempotency**: assign a ticket to user X, then assign
   again to user X → verify no audit event is created on the second call

7. **`New → Analysis` promotion coverage** (parametrized): every code
   path that sets `assignee_id` on a `New` ticket MUST produce a
   `status_change` event with `old_value = "New"` and
   `new_value = "Analysis"`. Paths to cover: `assign_ticket()` (explicit
   assignment) and `auto_assign_actor()` (triggered via any mutation
   function on an unassigned ticket, e.g., `set_severity_manual`,
   `set_track_status`, `add_package_to_ticket`). This test guards against
   future code paths that set `assignee_id` without performing the
   `New → Analysis` transition.

4. **Mark-as-duplicate with dependents (atomic repoint)**: mark ticket B as
   duplicate of C, where tickets A1 and A2 currently point to B. Verify:
   (a) A1 and A2 are atomically repointed to C, (b)
   `duplicate_target_changed` events are created for A1 and A2, (c)
   `duplicate_set` and `status_change` events are created for B

5. **Concurrent modification conflict**: hold a lock on a dependent
   ticket (simulating a concurrent revert). Call `mark_as_duplicate`
   on the dependent's target. Verify: (a) the operation raises
   `DuplicateConcurrentModificationError`, (b) the transaction is
   rolled back (no mutations, no audit events persist), (c) retrying
   after the lock is released succeeds normally

6. **CVE uniqueness race condition**: simulate concurrent `create_ticket`
   calls for the same CVE → verify one succeeds and the other raises
   `TicketCVEConflictError`

7. **grant_access concurrent requests**: simulate concurrent
   `grant_access` calls for the same user/ticket → verify one creates
   the grant and the other returns idempotent success

8. **CVE association and assessment race**: use independent sessions to race
   `associate_cve()` with a CVSS assessment mutation. Verify CVE-then-Ticket
   lock serialization, committed-current severity and eligibility handoff,
   acting-user `cve_associated` followed by system `severity_changed` when the
   handover changes value, and no stale or duplicate event from the loser

## Cross-references

- `docs/features/tickets/ticket-mutations.md` — gate-relevant mutations,
  `reconcile_ticket_status` contract, `ensure_ticket_operable` contract
- `docs/features/tickets/tickets.md` — ticket lifecycle, status gates,
  API endpoint definitions
- `docs/features/tickets/ticket-audit-log.md` — audit event types and
  contract
- `docs/features/tickets/tickets.md` — CVE Resolution Behavior (section
  "CVE Resolution Behavior")
- `docs/features/tickets/cve-service.md` — On-Demand Fetch: fetch_single_cve
- `docs/features/identity/rbac.md` — capability definitions
  (`triage_ticket`, `manage_confidentiality`,
  `create_ticket`)
- `docs/conventions.md` — Transaction and Locking pattern
- `docs/api-spec.md` — general API conventions, error code categories
