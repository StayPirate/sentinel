# Ticket Service

## Purpose

Centralize Ticket lifecycle operations and cross-domain Ticket compositions —
creation, CVE association, assignment, manual-zone entry and exit, and
confidentiality management — in a single service module
(`ticket_service`). This ensures that:

- `FOR UPDATE` locking is consistently applied on the Ticket row
- every `TicketAuditEvent` required by the owning domain contract is created
  atomically, while explicit no-event boundaries remain intentional
- `reconcile_ticket_status()` is called when operations have side effects
  on gate conditions (severity changes, status reconciliation)
- `auto_assign_actor()` is applied uniformly for unassigned tickets
- `ensure_ticket_operable()` enforces mutability regardless of entry
  point
- Business rules (idempotency) are enforced regardless of entry point

Gate primitives and CVSS/severity mutations are handled by
`ticket_mutations` (`docs/features/tickets/ticket-mutations.md`).
Package-centric mutations are handled by `package_service`
(`docs/features/packages/package-service.md`). This service may compose both
lower services while it owns one Ticket lifecycle workflow; neither lower
service imports `ticket_service`.

Read-only Ticket operations (listing, detail, and search) require a
service-capable boundary because they contain model-aware visibility and
business query construction. They need not live in `ticket_service`, but they
MUST NOT be implemented as business ORM queries in API handlers or Core. API
handlers remain thin and delegate these reads to the applicable service-owned
query boundary (see `docs/features/tickets/tickets.md`). Each consumer-facing
read constrains the rows, assembled detail, and pagination count it returns by
the canonical visibility predicate in the same database operation or equivalent
single database view; a preliminary accessibility decision alone is not
sufficient.

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

All operations accept the caller's database session and do not commit or roll
back. Commit responsibility belongs to the caller. Functions that require an
external post-commit effect register it with the caller-owned transaction;
the API transaction dependency commits and releases locks before executing the
effect.

This matches the `ticket_mutations`, `package_service`, and `user_service`
pattern: service functions apply mutations, create audit events, or register
post-commit work while the caller owns transaction completion.

### Acting user convention

Mutation operations accept an `acting_user_id: UUID | None` parameter when the
owning contract supports both direct and system callers:

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

`assign_ticket()`, `ignore_ticket()`, `mark_as_duplicate()`,
`revert_duplicate()`, `set_confidentiality()`, and direct access-grant
operations require a non-null authorized acting user. Their API handlers must
not use system attribution. `create_ticket()` and `reopen_from_ignored()` retain
their documented system callers.

### Caller category and Ticket accessibility

Consumer-facing service operations consume the one canonical Ticket visibility
predicate from `docs/features/identity/rbac.md` (Scope and Confidential Ticket
Visibility) without defining another semantic variant. Anonymous reads use the
canonical anonymous behavior and therefore do not query grants or
maintainership. Services own every model-aware query or operation needed to
apply the predicate; Core and API handlers do not construct business ORM
queries. The concrete caller-context representation, helper shape, and SQL
formulation are implementation choices.

API capability checks complete before the first service resource lookup. For a
consumer-facing mutation, an API accessibility decision may reject early but is
not authoritative after a lock wait. Once the operation acquires every required
root lock in its documented order, it MUST revalidate accessibility from the
locked-current Ticket state before operability, nested-resource ownership,
status guards, no-op classification, assignment, writes, audit,
reconciliation, or post-commit-effect registration. An inaccessible or missing
Ticket on a Ticket resource path produces `404 TICKET_NOT_FOUND` with no local
write, audit event, reconciliation, or registered post-commit effect. This
ordering does not alter any function's existing lock order.

A trusted internal or system call does not acquire an HTTP caller's scope and
does not apply consumer visibility filtering. Service boundaries distinguish
that caller category from consumer-facing use proportionately; they do not
infer it merely from an optional actor field or require a particular public
helper or context type.

If an approved consumer workflow performs external I/O before its Ticket lock,
its preliminary service-delegated accessibility check permits that phase. A
documented external failure that occurs before the lock retains its existing
precedence; the workflow does not perform another database lookup solely to
replace it with a not-found response. After successful external I/O, locked-current
accessibility is authoritative at the mutation boundary. A concurrent loss of
visibility there denies the mutation with zero local side effects.

Authorization uses the locked pre-mutation state. If an authorized mutation's
own effect removes the caller's final visibility path, the mutation still
commits and returns its ordinary success response. Later requests evaluate the
committed post-state.

### Relationship with other modules

| Module | Relationship |
|--------|-------------|
| `services/ticket_mutations.py` | `ticket_service` imports `reconcile_ticket_status()`, `recalculate_cvss_chain()`, `auto_assign_actor()`, and `ensure_ticket_operable()` from `ticket_mutations`. The dependency is unidirectional: `ticket_service` → `ticket_mutations`. Neither module imports from the other in the reverse direction |
| `services/package_service.py` | `ticket_service` invokes the package-owned synchronous eligibility boundary during manual-zone exits while retaining the Ticket lock. `package_service` does not import `ticket_service`; both modules depend on `ticket_mutations` for status evaluation |
| `services/cvss.py` | No direct dependency. CVSS resolution is delegated through `ticket_mutations.recalculate_cvss_chain()` where this service requires it |

## Scope Boundary

The following gate primitive endpoint routes directly to
`ticket_mutations`, while manual-zone exit endpoints route to this service as
cross-domain Ticket lifecycle compositions:

| Endpoint | Function | Reason |
|----------|----------|--------|
| `PATCH .../severity` | `ticket_mutations.set_severity_manual()` | Gate-relevant severity primitive |
| `POST .../reopen` | `ticket_service.reopen_from_ignored()` | Manual-zone exit composition |
| `POST .../revert-duplicate` | `ticket_service.revert_duplicate()` | Manual-zone exit composition |
| `POST .../rerun-reactivation` | `ticket_service.dispatch_ticket_convergence()` | Complete asynchronous recovery dispatch |

See [ticket-mutations.md](ticket-mutations.md) for the severity and shared gate
primitives. The complete manual-zone exit contracts are defined below.

### Operability guard

Operations that modify the Ticket row (all mutation functions except
`create_ticket`) call `ensure_ticket_operable(ticket)` from
`ticket_mutations` after acquiring `FOR UPDATE`. This checks:

1. **Mutability guard**: status ∈ {Ignored, Duplicated} →
   `TicketNotMutableError`

Explicit opt-outs (functions that do NOT call `ensure_ticket_operable`):

- `reopen_from_ignored` and `revert_duplicate` — validate their exact manual-
  zone source state instead because they are its dedicated exits

`ignore_ticket` calls `ensure_ticket_operable` (which catches
Ignored/Duplicated), then applies its own status check (New/Analysis required).
See ordering constraint below.

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
    ingestion_source: CVESourceType | None = None,
) -> Ticket:
```

`TicketCreationSource` is a service-layer-only Python enum (not a database
column) with values `manual` and `cve_ingestion`. `ingestion_source` is required
exactly when `source = cve_ingestion` and forbidden for `manual`; mismatches
raise `ValueError` before database access. The source identifier maps to the
canonical labels in `cve-service.md`, producing exactly
`Ticket created manually` or `CVE ingested from {source}`. The concrete private
mapping location is an implementation choice.

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
4. Create `TicketAuditEvent` (`ticket_created`) with the exact canonical
   comment selected from `source` and `ingestion_source`. This is
   always the first event in the Ticket's history, before every optional
   severity, assignment, or CVE-association event below
5. If assigned (step 3): create `TicketAuditEvent` (`assignment`)
6. If `severity_manual` provided: create `TicketAuditEvent`
   (`severity_changed`, `old_value = NULL`, `new_value = <severity>`)
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

**Audit events**: Up to 4, in this order: `ticket_created`, optional
`assignment`, optional `severity_changed`, and optional `cve_associated`.
Every event except `ticket_created` uses `comment = NULL`.

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
4. For a consumer call, revalidate Ticket accessibility from the locked-current
   Ticket. Capability has already been checked before CVE or Ticket lookup. An
   inaccessible Ticket returns `TICKET_NOT_FOUND` even though this workflow
   locked the CVE first.
5. Call `ensure_ticket_operable(ticket)`.
6. Verify `ticket.cve_id IS NULL` (else `TicketCVEAlreadySetError`) and, under
   the CVE lock, verify that no other Ticket is associated with the CVE (else
   `TicketCVEConflictError`).
7. `auto_assign_actor(ticket, acting_user_id)`.
8. Capture `previous_severity = ticket.severity_manual` (may be `NULL`).
9. Set `ticket.cve_id` and clear `ticket.severity_manual = NULL` (same
    UPDATE — maintains `chk_ticket_severity_manual_cve_exclusive`)
10. Create `TicketAuditEvent` (`cve_associated`,
    `user_id = acting_user_id`).
11. Call `recalculate_cvss_chain()` in association mode with `cve.id` and
    `association_previous_severity = previous_severity`. The same-transaction
    re-locks preserve the CVE-then-Ticket order and observe all assessment
    mutations committed before this operation acquired the CVE lock. The chain
    confirms CVE-owned severity, creates the optional manual-to-derived
    `severity_changed` handover, then recalculates every system-managed Product
    through the narrow exception. Changed-Product events are system-attributed,
    use `reason = cvss`, and are ordered by `TicketPackageProduct.id` after the
    handover event.
12. Call `reconcile_ticket_status()` exactly once after the handover and all
    Product events, using the same UTC `evaluation_date`. Gate #3 (severity set)
    and gate #4 (at least one canonical SUSE assessment in any accepted
    version) may now fail, causing regression to Analysis. Do not auto-assign a
    second time.
13. Return the updated Ticket.

**Locking**: `FOR UPDATE` on CVE, then `FOR UPDATE` on Ticket. CVE Resolution
Behavior involves only local database operations and may insert a minimal CVE
before that row can be locked. No synchronous external HTTP call or
Redis/Celery operation occurs while either lock is held. Re-locking either row
inside `recalculate_cvss_chain()` is a same-transaction no-op. The API workflow
registers `trigger_on_demand_fetch()` as a post-commit effect; the shared
transaction dependency executes it only after commit and lock release.

This order serializes correctly with CVSS mutation. If the CVSS mutation locks
the CVE first, association waits and then consumes its committed severity. If
association locks first, the CVSS mutation waits, then observes the associated
Ticket and applies its direct-audit and propagation contract. Neither path can
use a pre-lock assessment or association snapshot.

**recalculate_cvss_chain**: YES, in association mode. Associating a CVE changes
the Ticket's severity source. The function confirms CVE-owned severity from the
complete locked assessment set and applies automatic Product eligibility
inline through the package-model-owned evaluator.
If the CVE has no assessments, severity resolves to `null` (gate #3 fails) and
eligibility uses the 10.0 conservative fallback.

A `TicketCVEConflictError` continues to expose the documented
`existing_ticket_id` even when that conflicting Ticket is otherwise
inaccessible. Ticket and CVE identifiers are not confidential Ticket content;
this does not authorize following the identifier to protected data.

`associate_cve` captures and passes the previous `severity_manual` value; the
delegated calculation creates exactly one handover event when the source
transition changes the effective value.

**Note on pre-existing CVSS assessments**: If the CVE being associated
already has `CVECVSSAssessment` records (e.g., from a prior NVD sync), these
assessments are immediately available to the CVSS resolution cascade.
`recalculate_cvss_chain()` uses them to confirm severity and update automatic
Product eligibility without requiring a fresh NVD fetch.

**Audit events**: `cve_associated` (always). `severity_changed` (if
`previous_severity != new_severity` — captures the manual→derived
handover; emitted by `recalculate_cvss_chain()` from the previous value supplied
by `associate_cve`, with `user_id = NULL`, not attributed to the associating
user). `cve_associated` retains `user_id = acting_user_id`.
Possibly `assignment` and `status_change` (from auto-assign), and possibly
`status_change` from reconciliation. It creates one Product eligibility event
per changed automatic occurrence, followed by at most one gate-derived
`status_change`. Optional assignment and its `New → Analysis` event precede
`cve_associated`; Product events follow the handover event.

Any settings, database, eligibility, audit, flush, or reconciliation error
escapes and rolls back association, manual-severity clearing, assignment,
Product values, Ticket status, and every event together.

### assign_ticket

Assigns or reassigns a ticket to a user.

```python
async def assign_ticket(
    db: AsyncSession,
    *,
    ticket_id: UUID,
    assignee_id: UUID,
    acting_user_id: UUID,
) -> Ticket:
```

**Preconditions**:

- Ticket must be operable (`ensure_ticket_operable`)
- Target user must be active (else `AssigneeInactiveError`) and hold
  the `vulnerability_analyst` role (else `AssigneeNotVAError`)

**Behavioral steps**:

1. Acquire `FOR UPDATE` on the Ticket row
2. Revalidate consumer accessibility from the locked-current Ticket; denial
   returns `TICKET_NOT_FOUND` before target-user or operability errors
3. Call `ensure_ticket_operable(ticket)`
4. Validate target user (active — else `AssigneeInactiveError`;
    holds VA role — else `AssigneeNotVAError`)
5. **Idempotency check**: if `ticket.assignee_id == assignee_id`, return
    ticket unchanged (no audit event, no status evaluation)
6. Set `ticket.assignee_id = assignee_id`
7. Create `TicketAuditEvent` (`assignment`)
8. If `ticket.status == New`: set `ticket.status = Analysis`, create
    `TicketAuditEvent` (`status_change`, `user_id = NULL`,
    `old_value = "New"`, `new_value = "Analysis"`) — this is the explicit
    `New → Analysis` transition (see Architectural Invariant in
    `tickets.md`); the `status_change` event is created here, not by
    `reconcile_ticket_status`
9. Call `reconcile_ticket_status(ticket)` — evaluates further promotion
    from `Analysis` upward; may produce a second `status_change` event
    if `Analyzed` or `Resolved` gate conditions are already satisfied
10. Return updated Ticket

**Locking**: FOR UPDATE on Ticket row.

**reconcile_ticket_status**: YES — evaluates whether the ticket's
existing data satisfies gates above `Analysis` (Analyzed or Resolved).
While `ticket-mutations.md` classifies assignment as "not gate-relevant"
in the sense that it does not modify CVSS/severity/package data, the
explicit `New → Analysis` transition in step 8 means the ticket is now
in the gate zone and `reconcile_ticket_status` can promote it further
if conditions are met.

**Audit events**: `assignment` (only if assignee actually changes).
Possibly `status_change` (explicit `New → Analysis` in step 8 and/or
further promotion from `reconcile_ticket_status`). Assignment promotion and
ordinary gate events use `comment = NULL`.

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
    acting_user_id: UUID,
) -> Ticket:
```

**Preconditions**:

- Ticket must be operable (`ensure_ticket_operable`) — catches
  Ignored and Duplicated tickets before the status check
- Ticket must be in New or Analysis status (only valid source states;
  else `InvalidTransitionError`)

**Behavioral steps**:

1. Acquire `FOR UPDATE` on the Ticket row
2. Revalidate consumer accessibility from the locked-current Ticket; denial
   returns `TICKET_NOT_FOUND` before status or operability errors
3. Call `ensure_ticket_operable(ticket)` — rejects Ignored or Duplicated
   (`TicketNotMutableError`) tickets
4. Verify status is New or Analysis (else `InvalidTransitionError` —
   this catches Analyzed and Resolved, which pass `ensure_ticket_operable`
   but are not valid source states for ignore)
5. `auto_assign_actor(ticket, acting_user_id)`
6. Set `ticket.status = Ignored`
7. Create `TicketAuditEvent` (`status_change`)
8. Return updated Ticket

**Locking**: FOR UPDATE on Ticket row.

**reconcile_ticket_status**: NOT called — this is a direct transition
into the manual zone. `reconcile_ticket_status` never operates on
Ignored tickets.

**Audit events**: `status_change`. Possibly `assignment` (from
auto-assign). Both use `comment = NULL`.

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
    acting_user_id: UUID,
) -> Ticket:
```

**Preconditions**:

- Source ticket must exist and be accessible to the acting user from its
  locked-current state (else `TicketNotFoundError`)
- Target ticket must exist and be accessible to the acting user from its
  locked-current state (else `TicketNotFoundError`). An initially inaccessible
  target cannot be selected
- Source ticket must be operable (`ensure_ticket_operable`)
- Target must not be in Duplicated status (else
  `DuplicateTargetIsDuplicatedError`)
- Source must not equal target (else `SelfDuplicateError`)

**Behavioral steps**:

1. **Phase 1 — lock and validate roots**:
   a. Determine lock order: `first = min(source_id, target_id)`,
       `second = max(source_id, target_id)`
   b. `SELECT ... WHERE id = first FOR UPDATE` — lock first root
   c. `SELECT ... WHERE id = second FOR UPDATE` — lock second root
   d. Revalidate accessibility for both locked-current roots
   e. Validate both role-specific guards (operable for the source,
      non-Duplicated for the target)
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

The source and target visibility decisions are both made from the locked-current
rows and both must pass before Phase 2 or any mutation. Missing and inaccessible
roots produce the same `TICKET_NOT_FOUND` outcome. Dependents remain a trusted
system consequence of the authorized source mutation and are not independently
visibility-checked. After a link is established, `duplicate_of` may continue to
expose the stored target `SNTL-{n}` identifier if that target later becomes
inaccessible; following that identifier then returns `TICKET_NOT_FOUND`.

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

Dependent `duplicate_target_changed` events follow the UUID order of the
locked dependent rows from Phase 2. All normal status and duplicate comments
are `NULL`.

**Atomicity guarantee**: if any step fails (validation, NOWAIT
conflict, or database error), the entire transaction rolls back. No
mutations or audit events persist.

## Manual-Zone Exit Operations

These Ticket lifecycle workflows compose the package-owned synchronous
eligibility boundary with the gate primitives in `ticket_mutations`. The
composition remains in this higher-level service so `ticket_mutations` never
imports `package_service` and the CVSS chain remains its sole inline Product-
eligibility ownership exception.

### `_complete_manual_zone_exit()`

Only `reopen_from_ignored()` and `revert_duplicate()` call this helper, after
they acquire the Ticket lock, validate and preserve the exact source status,
and prepare the Ticket at the `Analysis` floor. Entry points and lower services
never call it directly.

Its semantic inputs are the caller-owned session, the locked Ticket already at
`Analysis`, the preserved `original_status`, and one UTC `evaluation_date`.
For `original_status = Duplicated`, `duplicate_of_id` must already be `NULL`.

**Behavioral steps**:

1. Invoke the package-owned synchronous manual-zone-exit eligibility boundary
   with the already locked Ticket and `evaluation_date`. The boundary reloads
   current persisted assessment, setting, threshold, lifecycle, override, and
   Product inputs; it neither reacquires the Ticket lock nor assigns or
   reconciles.
2. Call `ticket_mutations.reconcile_ticket_status()` exactly once with
   `previous_status=original_status` and the same `evaluation_date`.
3. Ensure the reconciliation result has registered one post-commit Ticket
   convergence workflow for this successful manual-zone exit, including when
   the evaluated result is `Resolved`.

Changed automatic Product events use the system actor,
`reason = reactivation`, and ascending `TicketPackageProduct.id` order. Any
inactive-assignee sanitation event follows those Product events; the final
`status_change` remains last. The helper performs no CVE write or CVE lock,
external I/O, Redis command, task publication, commit, or rollback. Any
settings, database, eligibility, audit, flush, or reconciliation error escapes
and rolls back the complete caller-owned transaction.

### `reopen_from_ignored()`

Reopens a Ticket from `Ignored` through the shared manual-zone exit
composition.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `db` | `AsyncSession` | Yes | Caller-owned database session |
| `ticket_id` | `UUID` | Yes | Ticket to reopen |
| `acting_user_id` | `UUID \| None` | No | Acting user, or `NULL` for the documented system reopen |

**Preconditions**: the Ticket exists and its locked-current status is
`Ignored`; otherwise raise `TicketNotFoundError` or
`InvalidTransitionError`, respectively.

**Behavioral steps**:

1. Acquire `FOR UPDATE` on the Ticket as the first database operation and
   for a consumer call revalidate locked-current accessibility before validating
   `Ignored`. The documented trusted system reopen does not acquire user scope.
   The caller identifies that trusted invocation explicitly through the
   implementation-chosen service boundary; `acting_user_id = NULL` by itself
   never grants system authority.
2. Preserve `original_status = Ignored` and resolve one UTC `evaluation_date`.
3. Call `ticket_mutations.auto_assign_actor(..., force=True)`. A VA actor
   becomes the assignee; a non-VA actor or system caller leaves the current
   assignee unchanged. Final reconciliation sanitizes an inactive assignee only
   when the final status is `Analysis` or `Analyzed`; a final `Resolved` result
   retains it.
4. Set `status = Analysis`, then call `_complete_manual_zone_exit()` with the
   preserved source status and date and return the resulting Ticket. Its final
   status is `Analysis`, `Analyzed`, or `Resolved` from current gate inputs.

**Audit events**: optional actor assignment, zero or more system-attributed
`product_eligibility_changed` events, optional inactive-assignee sanitation
`assignment`, then one system-attributed
`status_change` from `Ignored` to the final evaluated status. All comments are
`NULL` except a sanitation assignment's canonical unassignment comment.

**Locking and transaction**: the function retains its Ticket `FOR UPDATE` lock
through assignment, package convergence, audit, and final reconciliation. It
flushes but does not commit or roll back. Any escaping error rolls back all of
these effects in the caller-owned transaction.

**Return and idempotency**: returns the updated Ticket after flush. A request
whose locked-current status is no longer `Ignored` is rejected rather than
silently replayed; after a successful exit, retry requires a new state decision.

### `revert_duplicate()`

Reverts a Ticket from `Duplicated` through the shared manual-zone exit
composition. Repointing performed when it was marked duplicate remains
non-retroactive; other Tickets keep their current targets.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `db` | `AsyncSession` | Yes | Caller-owned database session |
| `ticket_id` | `UUID` | Yes | Ticket to revert |
| `acting_user_id` | `UUID` | Yes | Authorized acting user |

**Preconditions**: the Ticket exists and its locked-current status is
`Duplicated`; otherwise raise `TicketNotFoundError` or
`InvalidTransitionError`, respectively.

**Behavioral steps**:

1. Acquire `FOR UPDATE` on the Ticket as the first database operation and
   revalidate locked-current consumer accessibility before validating
   `Duplicated`.
2. Preserve `original_status = Duplicated`, capture the current duplicate
   target's `SNTL-{n}` identifier as `original_target_identifier`, and resolve
   one UTC `evaluation_date`.
3. Call `ticket_mutations.auto_assign_actor(..., force=True)`. A VA actor
   becomes the assignee; otherwise the current assignee is retained.
4. Clear `duplicate_of_id` and set `status = Analysis` consecutively before
   any operation that may flush. Both values are therefore written together,
   preserving
   `chk_ticket_duplicate_status_coherence`.
5. Create the acting-user `duplicate_removed` event with
   `old_value = original_target_identifier` and `new_value = NULL`.
6. Call `_complete_manual_zone_exit()` with the preserved source status and
   date and return the resulting Ticket. Its final
   status is `Analysis`, `Analyzed`, or `Resolved` from current gate inputs.

**Audit events**: optional actor assignment, `duplicate_removed`, zero or more
system-attributed `product_eligibility_changed` events, optional
inactive-assignee sanitation `assignment`, then one
system-attributed `status_change` from `Duplicated` to the final evaluated
status. All comments are `NULL` except a sanitation assignment's canonical
unassignment comment. Every event and mutation is atomic in the caller-owned
transaction.

**Locking and transaction**: the function retains its Ticket `FOR UPDATE` lock
through assignment, duplicate-link removal, audit, package convergence, and
final reconciliation. It flushes but does not commit or roll back. Any escaping
error rolls back the duplicate-link clear and every other effect.

**Return and idempotency**: returns the updated Ticket after flush. A request
whose locked-current status is no longer `Duplicated` is rejected rather than
silently replayed; a successful revert never repoints other Tickets.

## Ticket Convergence

Every successful `Ignored` or `Duplicated` exit registers the asynchronous
package-tree and per-ticket fetcher catch-up, even if its immediate gate result
is `Resolved`. An ordinary `Resolved` regression registers the same workflow.
An explicit `Ignored` or `Duplicated` exit first
converges existing system-managed Product eligibility synchronously from current
PostgreSQL inputs before its final gate result. A `Resolved` regression is
instead produced by an ordinary gate-zone mutation that has already maintained
current eligibility. The post-commit workflow
   re-resolves every persisted package marker through SMELT, including
   soft-deleted markers without restoring them, then catches up on external
   data against the resulting tree (e.g., Red Hat CVSS updates — the
   `sync_redhat_cves` fetcher scopes to active tickets and skips inactive
   ones). See `docs/features/packages/package-model.md` (Ticket Convergence)
   and
   [fetcher-infrastructure.md](../platform/fetcher-infrastructure.md)
   ("Per-Ticket Catch-Up: `catch_up()` Method") for the method contract.

The workflow is registered internally by `reconcile_ticket_status()` from the
preserved manual-zone source status or a `Resolved` regression and runs after
commit. CVSS assessment and
default-version workflows already maintain `CVE.severity` in every status; this
convergence path neither recalculates severity nor acquires a CVE lock while
holding the Ticket lock. The package-owned synchronous boundary used by manual-
zone exits resolves current eligibility from persisted inputs with
`reason = reactivation`. No action is needed by endpoint handlers or other
callers. Registration applies to:

- `reopen_from_ignored()` — Ignored → any gate-zone result via this service's private
  `_complete_manual_zone_exit()` finalization
- `revert_duplicate()` — Duplicated → any gate-zone result via the same composition
- Gate-driven regression — Resolved → active (automatic, via any
  mutation that unsatisfies a gate)

Publication registered by these automatic mutation paths is best-effort. If
the post-commit callback cannot publish the root convergence task, it logs one
sanitized structured ERROR with `ticket_id` and the request or task correlation
already bound to that execution context, then returns normally. The committed
Ticket/package mutation and its normal success response are retained; the
failure does not become `CELERY_UNAVAILABLE`. Recovery is a complete explicit
rerun through `POST /api/v1/tickets/{ticket_id}/rerun-reactivation`.

This differs intentionally from that explicit rerun endpoint: dispatch is the
requested operation there, so its initial publication failure returns 503 and
no Ticket mutation has been committed. Neither path adds a requesting-user log
field; API request correlation uses the existing `request_id` contract.

### Convergence behavior

The Ticket's first final gate result after a manual-zone exit, and the mutation
that regresses a `Resolved` Ticket, already reflects current automatic
eligibility. The Ticket may still transition as asynchronous external
catch-up completes. For example,
if a release was detected while the ticket was inactive, the IBS
catch-up may set tracks to FIXED and products to released, causing the
ticket to reach Resolved shortly after convergence begins. This is expected
behavior — the system converges to the accurate state.

### `dispatch_ticket_convergence()`

Service boundary used by
`POST /api/v1/tickets/{ticket_id}/rerun-reactivation`. It validates current
state under the caller-owned transaction and registers publication as a
post-commit effect, so no broker I/O occurs while the Ticket lock is held.

```python
async def dispatch_ticket_convergence(
    db: AsyncSession,
    *,
    ticket_id: UUID,
) -> str:
```

Consumer invocations additionally supply the request-resolved caller information
needed by the canonical visibility predicate through the module-level
implementation-chosen boundary. The displayed signature does not prescribe that
boundary's concrete parameter or context shape.

**Preconditions and guards**:

- The API has already authenticated the caller and verified either
  `triage_ticket` or `manage_fetchers` before service resource lookup. If a thin
  API boundary also performed preliminary Ticket accessibility, that decision
  is not authoritative after a lock wait.
- The Ticket must still exist and its locked-current status must be `Analysis`,
  `Analyzed`, or `Resolved`. Absence raises `TicketNotFoundError`; `New`,
  `Ignored`, or `Duplicated` raises `InvalidTransitionError`.
- The function does not call `ensure_ticket_operable()`.

**Behavior**:

1. Load the Ticket by canonical UUID with `FOR UPDATE` as the first database
   operation, revalidate consumer accessibility, and only then evaluate status
   eligibility from locked-current state. Missing or inaccessible returns
   `TICKET_NOT_FOUND` and registers no callback.
2. Allocate the transient Celery task ID without performing broker I/O.
3. Register one post-commit callback that publishes the root Ticket
   convergence task with the canonical `ticket_id` and allocated task ID.
   No Ticket field or audit event is changed.
4. Return the allocated root task ID. The caller maps it to
   `TicketConvergenceDispatchResponse` and HTTP 202.

The caller-owned transaction commits and releases the lock before the callback
publishes. If initial publication raises, the callback raises
`TicketConvergenceDispatchError`; the function-scoped API transaction boundary
maps it to 503 before transmitting the response. No compensation row exists
because this workflow deliberately has no durable run resource. A broker
acknowledgement may be ambiguous, so the task may still execute despite the 503
response. Re-invocation is intentionally accepted and registers another
complete workflow. Concurrent calls serialize only the locked status check;
they do not coalesce publication. The function creates no `TicketAuditEvent`.

The function propagates `TicketNotFoundError`, `InvalidTransitionError`,
`TicketConvergenceDispatchError`, and database exceptions. It does not expose
package-specific or catch-up exceptions synchronously because those occur in
the dispatched workflow.

### Cross-references

- [cvss-scoring.md](cvss-scoring.md) — CVSS resolution cascade,
  recalculation trigger rationale
- [ticket-mutations.md](ticket-mutations.md) —
  `reconcile_ticket_status()` step 5, `recalculate_cvss_chain()`
  contract, assignment and operability primitives
- [package-service.md](../packages/package-service.md) — synchronous manual-
  zone-exit eligibility boundary and complete Ticket convergence workflow
- [fetcher-infrastructure.md](../platform/fetcher-infrastructure.md) —
  `catch_up()` method contract
- [tickets.md](tickets.md#rerun-ticket-convergence) — operator rerun API,
  authorization order, response, and errors

## Confidentiality Management

### set_confidentiality

Toggles the `is_confidential` flag on a ticket.

```python
async def set_confidentiality(
    db: AsyncSession,
    *,
    ticket_id: UUID,
    is_confidential: bool,
    acting_user_id: UUID,
) -> Ticket:
```

**Preconditions**:

- Ticket must be operable (`ensure_ticket_operable`)
- Requires `manage_confidentiality` capability (enforced at API layer)

**Behavioral steps**:

1. Acquire `FOR UPDATE` on the Ticket row
2. Revalidate consumer accessibility from the locked-current Ticket; denial
   returns `TICKET_NOT_FOUND` before operability or no-op classification
3. Call `ensure_ticket_operable(ticket)`
4. **Idempotency check**: if `ticket.is_confidential == is_confidential`,
    return ticket unchanged (no audit event)
5. Set `ticket.is_confidential = is_confidential`
6. Create `TicketAuditEvent` (`confidentiality_changed`)
7. Return updated Ticket

**Note on access grants**: When setting `is_confidential = false`,
existing `TicketAccessGrant` records are NOT deleted immediately. They
become inert (the confidentiality filter no longer restricts access).
Stale grants are cleaned up by a periodic task (weekly, 14-day delay).
See `tickets.md` (Stale Access Grant Cleanup) for details.

That periodic cleanup is a separate housekeeping boundary. It locks qualifying
Tickets in UUID order, revalidates their non-confidential age condition,
deletes current grants idempotently, and creates no
`access_grant_removed` event.

**Locking**: FOR UPDATE on Ticket row.

**reconcile_ticket_status**: NOT called — confidentiality is not
gate-relevant.

**Audit events**: `confidentiality_changed` (only if value actually
changes), with `comment = NULL`.

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
2. Revalidate consumer accessibility from the locked-current Ticket; denial
   returns `TICKET_NOT_FOUND` before confidentiality, target-user, or no-op
   decisions
3. Call `ensure_ticket_operable(ticket)`
4. Verify ticket is confidential (else `TicketNotConfidentialError`)
5. Verify target user is active (else `InactiveUserError`)
6. **Idempotency check**: if grant already exists for this user, return
    existing grant unchanged (no audit event)
7. INSERT `TicketAccessGrant` record (`ticket_id`, `user_id`,
    `granted_by = acting_user_id`, `granted_at = now(UTC)`)
8. Create `TicketAuditEvent` (`access_grant_added`)
9. Return the created grant

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
2. Revalidate consumer accessibility from the locked-current Ticket; denial
   returns `TICKET_NOT_FOUND` before confidentiality, target-user, or no-op
   decisions
3. Call `ensure_ticket_operable(ticket)`
4. Verify ticket is confidential (else `TicketNotConfidentialError`)
5. **Idempotency check**: if grant does not exist for this user, return
    without side effects (no audit event)
6. Delete `TicketAccessGrant` record
7. Create `TicketAuditEvent` (`access_grant_removed`)
8. Return

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

Consumer use also supplies the caller information required to evaluate the
canonical visibility predicate. Its concrete parameter or context shape is an
implementation choice.

**Preconditions**:

- Ticket must be confidential (`is_confidential = true`; else
  `TicketNotConfidentialError`)
- Requires `manage_confidentiality` capability (enforced at API layer)

**Behavioral steps**:

1. Select the parent Ticket and its grants through the canonical accessibility
   predicate in one database operation or equivalent single database view. A
   missing or inaccessible Ticket raises `TicketNotFoundError`; it never returns
   an empty list for that case.
2. Verify ticket is confidential (else `TicketNotConfidentialError`)
3. Return `TicketAccessGrant` records for the ticket, ordered by
   `granted_at` ascending

**Locking**: None (read-only).

**reconcile_ticket_status**: NOT called.

**Audit events**: None (read-only).

## Service Exceptions

All exceptions in this module inherit from `TicketServiceError`.
API endpoint handlers catch `TicketServiceError` subclasses and map them
to the corresponding HTTP status code and error code per `api-spec.md`.

| Exception | HTTP | Code | Raised when |
|-----------|------|------|-------------|
| `TicketNotFoundError` † | 404 | `TICKET_NOT_FOUND` | Ticket ID does not exist or is inaccessible on a consumer Ticket path |
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
| `TicketConvergenceDispatchError` | 503 | `CELERY_UNAVAILABLE` | Initial publication of the root Ticket convergence task failed |
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
  (Ticket flows)    (package ops)
         │                ▲
         └────────────────┘
          manual-zone exit
```

| ticket_service function | ensure_ticket_operable | reconcile_ticket_status | recalculate_cvss_chain | auto_assign_actor | package convergence |
|------------------------|:----------------------:|:----------------------:|:---------------------:|:---------------------:|:-------------------:|
| create_ticket          | —                      | —                      | —                     | —                     | —                   |
| associate_cve          | ✓                      | ✓                      | ✓                     | ✓                     | —                   |
| assign_ticket          | ✓                      | ✓                      | —                     | —                     | —                   |
| ignore_ticket          | ✓                      | —                      | —                     | ✓                     | —                   |
| mark_as_duplicate      | ✓                      | —                      | —                     | ✓                     | —                   |
| reopen_from_ignored    | —                      | ✓                      | —                     | ✓                     | ✓                   |
| revert_duplicate       | —                      | ✓                      | —                     | ✓                     | ✓                   |
| dispatch_ticket_convergence | —                  | —                      | —                     | —                     | —                   |
| set_confidentiality    | ✓                      | —                      | —                     | —                     | —                   |
| grant_access           | ✓                      | —                      | —                     | —                     | —                   |
| revoke_access          | ✓                      | —                      | —                     | —                     | —                   |
| list_access_grants     | —                      | —                      | —                     | —                     | —                   |

## Architectural Test Requirement

The following integration tests MUST be implemented to verify correct
behavior of `ticket_service` operations:

1. **CVE association causes status regression**: create a ticket without
   CVE, set `severity_manual`, and add a package with tracks in final status to
   reach Analyzed. Associate a CVE whose assessment set is empty, then verify
   the ticket regresses to Analysis because gates #3 and #4 fail

2. **Assignment promotes New → Analysis explicitly**: create a ticket in
   New status. Assign a VA → verify ticket promotes to Analysis and a
   `status_change` event with `old_value = "New"`, `new_value = "Analysis"`,
   `user_id = NULL` is created (not by `reconcile_ticket_status` but by
   the explicit step in `assign_ticket` before calling reconcile)

3. **Assignment idempotency**: assign a ticket to user X, then assign
   again to user X → verify no audit event is created on the second call

4. **`New → Analysis` promotion coverage** (parametrized): every code
   path that sets `assignee_id` on a `New` ticket MUST produce a
   `status_change` event with `old_value = "New"` and
   `new_value = "Analysis"`. Paths to cover: `assign_ticket()` (explicit
   assignment) and `auto_assign_actor()` (triggered via any mutation
   function on an unassigned ticket, e.g., `set_severity_manual`,
   `set_track_status`, `add_package_to_ticket`). This test guards against
   future code paths that set `assignee_id` without performing the
   `New → Analysis` transition.

5. **Mark-as-duplicate with dependents (atomic repoint)**: mark ticket B as
   duplicate of C, where tickets A1 and A2 currently point to B. Verify:
   (a) A1 and A2 are atomically repointed to C, (b)
   `duplicate_target_changed` events are created for A1 and A2 in their locked
   UUID order, (c)
   `duplicate_set` and `status_change` events are created for B

6. **Concurrent modification conflict**: hold a lock on a dependent
   ticket (simulating a concurrent revert). Call `mark_as_duplicate`
   on the dependent's target. Verify: (a) the operation raises
   `DuplicateConcurrentModificationError`, (b) the transaction is
   rolled back (no mutations, no audit events persist), (c) retrying
   after the lock is released succeeds normally

7. **CVE uniqueness race condition**: simulate concurrent `create_ticket`
   calls for the same CVE → verify one succeeds and the other raises
   `TicketCVEConflictError`

8. **grant_access concurrent requests**: simulate concurrent
   `grant_access` calls for the same user/ticket → verify one creates
   the grant and the other returns idempotent success

9. **CVE association and assessment race**: use independent sessions to race
   `associate_cve()` with a CVSS assessment mutation. Verify CVE-then-Ticket
   lock serialization, committed-current severity and applied eligibility,
   acting-user `cve_associated` followed by system `severity_changed` when the
   handover changes value, Product events in occurrence-ID order, one shared
   evaluation date, one final reconciliation, and no stale or duplicate event
   or second assignment from the loser
10. **Manual-zone exit composition**: for both `reopen_from_ignored()` and
   `revert_duplicate()`, verify this service owns the Ticket lock and direct
   lifecycle/audit mutations, invokes the package-owned synchronous boundary
   with the same `evaluation_date`, and then invokes
   `reconcile_ticket_status()` exactly once. Cover VA, non-VA, and documented
   system assignment behavior; current-input eligibility convergence and
   override skips; Product-event ID ordering before final status; exact-source-
   state rejection; complete rollback on package or reconciliation failure;
   and a race with CVSS mutation that never acquires Ticket then CVE or creates
   duplicate events. For revert, force an autoflush-capable role lookup and
   prove `duplicate_of_id = NULL` and the `Analysis` floor are flushed together
   without violating `chk_ticket_duplicate_status_coherence`; assert that the
   `duplicate_removed` event uses the pre-clear target's `SNTL-{n}` identifier
   as `old_value` and `NULL` as `new_value`
11. **Manual-zone convergence registration**: both exit workflows register one
    post-commit Ticket convergence workflow for final `Analysis`, `Analyzed`,
    and `Resolved`; inactive assignees are cleared only for final `Analysis` or
    `Analyzed` and retained for final `Resolved`; automatic publication failure
    is logged and swallowed after commit, preserving the mutation's success
    response and requiring the complete operator rerun
12. **Operator convergence dispatch**: verify locked-current acceptance for
    `Analysis`, `Analyzed`, and `Resolved`; rejection of `New`, `Ignored`, and
    `Duplicated` with `InvalidTransitionError`; commit and lock release before
    publication; canonical Ticket UUID and root task UUID return; repeated and
    concurrent publication without conflict; broker failure mapping; ambiguous
    acknowledgement tolerance; and no Ticket mutation or audit event
13. **Canonical comments and creation order**: manual and every canonical CVE
    source create the exact `ticket_created.comment`; creation keeps
    `ticket_created`, optional assignment, optional manual severity, and
    optional CVE association order. Normal status transitions use NULL comments,
    while rejection uses exactly `CVE rejected`
14. **Confidentiality and grants**: direct changes assert exact acting-user
    events and no-op absence; stale-grant cleanup covers deterministic Ticket
    selection, locked revalidation, idempotent/concurrent cleanup, rollback, and
    zero `access_grant_removed` events
15. **Locked-current accessibility**: for every consumer mutation above, use
    independent sessions to change confidentiality, the caller's grant, or the
    last included-package maintainership path between preliminary delegated access and
    root-lock acquisition. Verify the locked-current decision wins, denial maps
    to `TICKET_NOT_FOUND`, and denial leaves zero assignment, write, audit,
    reconciliation, or post-commit registration. Cover CVE-then-Ticket
    association, both ordered duplicate roots, manual-zone exits, convergence
    dispatch, confidentiality, and grants. Separately verify that an authorized
    mutation which itself removes the caller's last visibility path returns its
    normal success response and only later requests are denied
16. **Accessible reads**: grant listing selects through the accessible parent
    in the same database operation or view, returns an ordinary empty list only
    for an accessible Ticket with no grants, and cannot return rows selected
    after visibility is lost

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
  (`triage_ticket`, `manage_confidentiality`, `create_ticket`) and the canonical
  Ticket visibility predicate
- `docs/conventions.md` — Transaction and Locking pattern
- `docs/api-spec.md` — general API conventions, error code categories
