# Ticket Service

## Purpose

Centralize Ticket reads, lifecycle operations, and cross-domain Ticket
compositions — listing, detail assembly, creation, CVE association, assignment,
priority override, manual-zone entry and exit, and confidentiality management,
including the Coordinated Release Date — in a single
service module
(`ticket_service`). This ensures that:

- `FOR UPDATE` locking is consistently applied on the Ticket row
- every `TicketAuditEvent` required by the owning domain contract is created
  atomically, while explicit no-event boundaries remain intentional
- `reconcile_ticket_status()` is called when operations have side effects
  on gate conditions (severity changes, status reconciliation)
- `auto_assign_actor()` is applied uniformly for unassigned tickets
- `ensure_ticket_operable()` enforces mutability except for the explicit
  lifecycle, dispatch, visibility-only, and embargo-metadata opt-outs
  documented below
- Business rules (idempotency) are enforced regardless of entry point

Gate primitives and CVSS/severity mutations are handled by
`ticket_mutations` (`docs/features/tickets/ticket-mutations.md`).
Package-centric mutations are handled by `package_service`
(`docs/features/packages/package-service.md`). This service may compose both
lower services while it owns one Ticket lifecycle workflow; neither lower
service imports `ticket_service`.

Read-only Ticket listing, search, SNTL resolution, and detail assembly live in
`ticket_service`. They MUST NOT be implemented as business ORM queries in API
handlers or Core. This module composes package-owned query/projection behavior
without duplicating package policy. Each consumer-facing read constrains the
rows, assembled detail, and pagination count it returns by the canonical
visibility predicate in the same database operation or equivalent single
database view; a preliminary accessibility decision alone is not sufficient.

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
external post-commit effect register it with the caller-owned transaction; the
API transaction dependency commits and releases locks before executing the
effect.

This matches the `ticket_mutations`, `package_service`, and `user_service`
pattern: service functions apply mutations, create audit events, or register
post-commit work while the caller owns transaction completion.

`dispatch_ticket_convergence()` is the deliberate exception: publication is its
requested operation and its failure must remain observable, so it is a
service-owned orchestration boundary that opens and completes its own short
session (`docs/conventions.md`, Caller-Owned Service Transactions —
orchestration boundary). It does not accept a caller-supplied session. The
automatic convergence effects registered by `reconcile_ticket_status()` keep
using the caller-owned transaction; the API drain consumes them in the
dependency's post-commit phase, after the commit and the release of the row
locks.

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
`revert_duplicate()`, `set_confidentiality()`,
`set_coordinated_release_date()`, and direct access-grant operations require a
non-null authorized acting user. Their API handlers must
not use system attribution. `create_ticket()` and `reopen_from_ignored()` retain
their documented system callers. `ignore_new_for_rejected_cve()` is exclusively
system-only and has no actor parameter.

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
| `services/ticket_mutations.py` | `ticket_service` imports `reconcile_ticket_status()`, `recalculate_cvss_chain()`, `auto_assign_actor()`, `ensure_ticket_operable()`, and `refresh_priority_auto()` from `ticket_mutations`. The dependency is unidirectional: `ticket_service` → `ticket_mutations`. Neither module imports from the other in the reverse direction |
| `services/package_service.py` | `ticket_service` invokes package-owned projection behavior for Ticket detail and the synchronous eligibility boundary during manual-zone exits. `package_service` does not import `ticket_service`; both modules depend on `ticket_mutations` for status evaluation |
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

Ordinary operations that modify the Ticket row call
`ensure_ticket_operable(ticket)` from `ticket_mutations` after acquiring
`FOR UPDATE`. This checks:

1. **Mutability guard**: status ∈ {Ignored, Duplicated} →
   `TicketNotMutableError`

Explicit opt-outs (functions that do NOT call `ensure_ticket_operable`):

- `ignore_new_for_rejected_cve` — validates exactly `New` as the automatic
  rejection source state and leaves every other status unchanged
- `reopen_from_ignored` and `revert_duplicate` — validate their exact manual-
  zone source state instead because they are its dedicated exits
- `set_confidentiality`, `grant_access`, and `revoke_access` — visibility-only
  operations valid in every Ticket status; they neither assign, reconcile, nor
  exit the manual zone
- `set_coordinated_release_date` — embargo-metadata operation valid in every
  Ticket status while the Ticket is confidential; it neither assigns,
  reconciles, nor exits the manual zone
- `dispatch_ticket_convergence` — validates its own eligible status set

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
Ticket row as its first root operation unless it can assign a User.

Every user-attributed path that can create or change an assignment first
acquires `FOR SHARE` on the prospective assignee User and validates eligibility
from that locked row. It then acquires any CVE and Ticket roots in the global
`User -> CVE -> Ticket` order. The User lock is retained until transaction
completion and conflicts with deactivation or a potentially final VA-origin
removal. System-only paths that do not assign acquire no User lock.

For operations whose existing error precedence requires Ticket accessibility or
operability before a missing or ineligible assignment target is reported, User
resolution may preserve an absent result and locking may occur first, but the
error is raised only after the Ticket checks. This stabilizes target state
without changing the public error order.

`associate_cve()` participates in User assignment eligibility plus CVE-owned
and Ticket-owned state and therefore uses the global root order: acting User,
CVE, then Ticket. A system CVE workflow that cannot assign omits the User root
and retains CVE then Ticket. The User-then-Ticket access-grant exception is
defined next.

Access-grant operations that identify a target user participate in User and
Ticket state without mutating the User. They use the global `User` then `Ticket`
root order so target activity and username remain stable against concurrent
deactivation, reactivation, or rename. Target resolution may discover absence
before the Ticket lock, but the operation defers `UserNotFoundError` until after
locked-current Ticket accessibility succeeds. Missing or inaccessible Tickets
therefore still produce `TICKET_NOT_FOUND` without disclosing the target-user
result. Each direct grant/revoke invocation begins while its caller-owned
transaction holds no Ticket row lock; composing a Ticket-first operation before
one of these functions would invert the global order.

The matching semantics remain owned by `user_service`: valid UUID input selects
`User.id`, all other input selects the exact stored username, and no match is an
absent result. The grant workflow uses that user-domain boundary in a
lock-aware, deferred-error form so it can retain the matched User lock or the
absence result while it performs the Ticket check. It does not duplicate
identifier parsing/matching in `ticket_service` and does not call the ordinary
read-only `resolve_user_identifier()` in a way that would raise before Ticket
accessibility. The concrete private helper, optional parameter, or equivalent
service result used to provide this behavior is an implementation choice, not a
new consumer operation.

Creating a CVE-less Ticket performs only a User eligibility lock, when it has a
manual actor, followed by the INSERT. When `create_ticket()` associates a CVE,
it locks the manual actor User before resolving and locking that CVE, then
inserts the Ticket. A system creation has no User root. The Ticket uniqueness
constraint remains the final defense against concurrent INSERTs for the same
CVE.

## Ticket Query Operations

These Category B operations are read-only and use the caller's `AsyncSession`.
They create no audit event, acquire no mutation lock, and never commit or roll
back. They return service-layer semantic projections rather than Pydantic
schemas; concrete dataclasses, typed mappings, query helpers, and SQL statement
shapes are implementation choices. Database exceptions propagate unchanged.

All consumer calls receive the request-resolved caller information described
under Caller category and Ticket accessibility. The exact parameter that
carries it is intentionally omitted from the conceptual signatures below.

### Ticket locator resolution

Consumer-facing Ticket locators follow `docs/api-spec.md` (Ticket Identifier
Resolution). A service-owned resolution operation accepts `db: AsyncSession`, a
`ticket_id: str` containing canonical `SNTL-{n}`, and caller information. It
parses the grammar and positive PostgreSQL `INTEGER` bound, selects
`Ticket.sequence_id = n`, and applies the canonical visibility predicate.

Malformed input, an external Ticket UUID, a missing sequence, and an
inaccessible Ticket all produce `TicketNotFoundError`. A successful result
contains the internal `Ticket.id` UUID and enough selected Ticket state for its
caller; it never makes that UUID a consumer response field. A mutation may use
the resolved UUID as its internal service locator, but its owning mutation
service still performs the documented locked-current accessibility check. The
preliminary resolution does not authorize later unconstrained work.

For a single protected read, the owning query may integrate syntax,
sequence-resolution, visibility, and response selection rather than calling a
standalone resolver. The observable result and layer ownership are identical.

### `list_tickets()`

Conceptual semantic inputs are:

| Input | Type | Default | Meaning |
|---|---|---|---|
| `db` | `AsyncSession` | required | Caller-owned session |
| `search` | `str \| None` | `None` | Ticket multi-field search |
| `status` | supplied-state plus collection of valid `TicketStatus` | omitted | Repeatable OR filter, preserving omitted versus supplied-but-empty after validation |
| `assignee` | `str \| None` | `None` | User UUID, exact username, or literal `none` |
| `severity` | supplied-state plus collection of valid resolved-severity filters | omitted | Repeatable OR filter including `none` and `unresolved`, preserving omitted versus supplied-but-empty after validation |
| `priority` | supplied-state plus collection of valid effective-priority filters | omitted | Repeatable OR filter over `p1`–`p4` and `unresolved`, preserving omitted versus supplied-but-empty after validation |
| `overdue` | supplied-state plus collection of valid milestone phases | omitted | Repeatable OR filter over `triage`, `submission`, `um`, and `qa`, preserving omitted versus supplied-but-empty after validation |
| `maintainer` | `str \| None` | `None` | User UUID or exact username |
| `sort_by` | `created_at`, `updated_at`, `severity`, `priority`, `status`, `ticket_id`, `triage_due_at`, `submission_due_at`, `um_due_at`, `qa_due_at`, or `release_due_at` | `created_at` | Primary sort |
| `sort_order` | `asc` or `desc` | `desc` | Sort direction |
| `page` | positive integer | `1` | One-indexed page |
| `per_page` | integer 1–100 | `20` | Page size |

The result contains a collection of Ticket summary projections plus `total`,
`page`, and `per_page`. Its behavior is:

1. Capture one UTC evaluation instant and derive the response's
   `evaluation_date` from it
   ([ticket-deadlines.md](ticket-deadlines.md#evaluation-instant)). Build one
   candidate set of Tickets satisfying the canonical visibility predicate.
   Anonymous calls evaluate no grant or maintainership branch.
2. Normalize `search` by trimming outer whitespace once. An empty result means
   no search filter. Percent, underscore, and backslash remain literal input;
   they do not become SQL pattern syntax. Apply the field-specific OR matching
   rules in `tickets.md` only to directly included package occurrences and
   current CVE/external-identifier state.
3. Apply simultaneously supplied client filters with AND semantics. Values
   inside one repeatable status, severity, priority, or overdue filter use OR
   semantics.
   The API
   passes whether the filter was supplied together with its valid members in an
   implementation-chosen typed form, so an all-invalid supplied filter yields
   an empty page while omission applies no filter. Handle literal
   `assignee=none` before User resolution. An unknown optional assignee or
   maintainer identifier yields an empty page rather than
   `UserNotFoundError`; maintainer matching uses an included
   `TicketPackage.deleted_at IS NULL` occurrence.
4. Resolve severity exactly once per Ticket using the canonical Ticket severity
   cascade. Severity filtering, semantic sorting, and projection all use that
   same value, including the distinction between resolved `None` and SQL NULL.
   Likewise derive the effective priority once per Ticket as
   `COALESCE(priority_override, priority_auto)`; priority filtering (`unresolved`
   matching SQL NULL), sorting, and projection all use that value. Derive the
   five Ticket-level due dates from that resolved severity, the status, and
   `created_at` through the service-owned SQL expressions in
   [ticket-deadlines.md](ticket-deadlines.md#read-ownership-and-query-integration);
   due-date sorting and projection use those values, and the `overdue` filter
   applies the Ticket-level rules there with the one evaluation instant, using
   existence semantics over tracks and Products.
5. Collapse all one-to-many joins to one logical Ticket. Package, maintainer,
   and external-identifier fan-out must not duplicate rows or inflate `total`.
6. Project `package_names` from directly included package occurrences only,
   deduplicate exact persisted strings, and sort them in ascending Unicode
   code-point order. Database or deployment collation is not the API order.
7. Apply the requested primary order and an internal `Ticket.id` UUID
   tie-breaker in the same direction. `ticket_id` sorting uses numeric
   `sequence_id`; status, severity, and priority use the semantic ranks and
   nullable rules in `docs/api-spec.md`; due dates use timestamp order with
   `NULL` last.
8. Compute `total` after visibility and every filter but before page slicing,
   then return the requested page. A page beyond the last is an empty
   collection with the correct total.

Rows, total, resolved users and severity, sorting, and pagination derive from
one coherent PostgreSQL observation. A concurrent commit may be observed
entirely before or entirely after that view, never as a count/page mismatch
assembled from incompatible views.

### `get_ticket_detail()`

The consumer operation accepts `db: AsyncSession`, a public `ticket_id: str`,
and caller information. It captures one UTC evaluation instant exactly once at
entry for milestone comparisons
([ticket-deadlines.md](ticket-deadlines.md#evaluation-instant)) and uses that
instant's UTC calendar date as the response's `evaluation_date`; as a
read-only request it accepts no separately selected date. Mutation workflows
that return `TicketDetail` instead supply their existing workflow date and the
internal UUID of the locked post-mutation Ticket; only this mutation-assembly
mode receives a workflow date, and it captures its instant at projection
entry. The concrete overload/helper arrangement is an implementation choice;
no Pydantic type enters the Service layer.

The result is the semantic projection represented by `TicketDetail` in
`tickets.md`. The operation:

1. Resolves a public locator through the SNTL-only contract and selects the root
   through the canonical visibility predicate. Missing, malformed, UUID, and
   inaccessible locators raise `TicketNotFoundError`.
2. Projects the root fields (including `coordinated_release_at`), resolved
   severity, effective, automatic, and override priority, the five Ticket-level
   due dates from
   [ticket-deadlines.md](ticket-deadlines.md#due-dates), complete current
   assignee reference, and expanded current
   CVE fields, including the KEV, EPSS, SSVC, and grouped CWE evidence and their
   ordering defined by `CVEDetail` in `tickets.md`. CVSS assessments are not
   inline; they remain in their dedicated sub-resource.
3. Orders CVE external identifiers by ascending Unicode code point of source,
   then identifier, with `CVEExternalIdentifier.id` as the final tie-breaker.
4. If `duplicate_of_id` is non-null, selects only the target's immutable
   `sequence_id` to produce `duplicate_of_ticket_id`. It does not follow a
   duplicate chain, expose target content, or apply a second protected-content
   lookup. This is the bounded identifier-only disclosure contract.
5. Composes the package-owned complete tree projection with the same
   `evaluation_date` and the same evaluation instant, which projects the per-track due
   dates, `milestones`, and `current_phase`. Package names, track references, and Product CPEs use
   ascending Unicode code-point order with the corresponding occurrence UUID
   as final tie-breaker. Maintainer identities are not loaded or projected.

The root accessibility decision and every PostgreSQL-backed component use one
coherent observation point. A concurrent mutation may yield an entirely
pre-change detail, an entirely post-change detail, or the applicable not-found
outcome, but never a mixed response. The implementation may use one statement,
a transaction snapshot, or another equivalent mechanism; this specification
does not prescribe it.

Every mutation endpoint declaring `TicketDetail` delegates its final response
assembly to this same contract inside the caller-owned transaction after its
mutation has produced the post-state. A mutation that already needs an
`evaluation_date` for eligibility, actionability, or reconciliation supplies
that date. Every other such mutation captures one UTC date at workflow entry
solely for its complete final projection. Serializers do not recapture it.

Assembly consumes the transaction-owned new Ticket for creation, or the
mutation's locked Ticket and successful locked-pre-state authorization for an
existing root, rather than applying a second post-mutation visibility decision.
Therefore a mutation that removes the actor's final visibility path still
returns its ordinary post-mutation detail, while the next request is denied. If
assembly fails, the exception escapes and the caller rolls back the mutation
and its audit events.

## Ticket Lifecycle Operations

### create_ticket

Creates a new ticket. Optionally associates a CVE and sets initial status from
the creating User's locked-current active VA eligibility.

```python
async def create_ticket(
    db: AsyncSession,
    *,
    acting_user_id: UUID | None,
    cve_id: str | None = None,
    severity_manual: Severity | None = None,
    is_confidential: bool = False,
    coordinated_release_at: datetime | None = None,
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
- `coordinated_release_at` is a timezone-aware UTC instant and is permitted
  only with `is_confidential = True` and `source = manual`. The API rejects a
  non-null value without confidential creation through schema validation; a
  service caller that violates either condition receives `ValueError` before
  database access, like the `ingestion_source` mismatch above
- If both `cve_id` and `severity_manual` are provided: the service
  raises `SeverityDerivedError`. When a CVE is associated, severity is
  derived exclusively from CVSS assessments — manual severity is not
  applicable. UI implementations should disable the severity field when
  a CVE is provided at creation time

**Behavioral steps**:

1. For manual creation, acquire `FOR SHARE` on the acting User and determine
   active VA eligibility from the locked row. An inactive or non-VA creator is
   not assigned; creation continues under the existing non-assignment branch.
   A system creation skips this step
2. If `cve_id` is provided, resolve CVE via CVE Resolution Behavior and retain
   `FOR UPDATE` on the CVE before reading association state or inserting the
   Ticket. A newly inserted CVE is already owned by the transaction. If no CVE
   is provided, no row lock is required
3. INSERT new Ticket row with initial fields, including
   `coordinated_release_at` when supplied (all unspecified columns
   use database defaults: `duplicate_of_id = NULL`,
   `updated_at = now(UTC)`, etc.)
4. Determine initial status:
   - If the locked acting User is active and holds the VA role:
     `status = Analysis`, `assignee_id = acting_user_id`
   - Otherwise: `status = New`
5. Create `TicketAuditEvent` (`ticket_created`) with the exact canonical
   comment selected from `source` and `ingestion_source`. This is
   always the first event in the Ticket's history, before every optional
   severity, CRD, assignment, or CVE-association event below
6. If assigned (step 4): create `TicketAuditEvent` (`assignment`)
7. If `severity_manual` provided: create `TicketAuditEvent`
   (`severity_changed`, `old_value = NULL`, `new_value = <severity>`)
8. If `coordinated_release_at` provided: create `TicketAuditEvent`
   (`coordinated_release_changed`, creating user, `old_value = NULL`,
   `new_value` = the stored instant in UTC ISO 8601 format)
9. If CVE associated: create `TicketAuditEvent` (`cve_associated`)
10. For `source = manual`, call `ticket_mutations.refresh_priority_auto()` for
   the new Ticket under the held locks. A resulting `priority_changed` (system,
   `NULL -> Px`) follows every creation event above. For
   `source = cve_ingestion`, do not refresh: the calling `upsert_cve()` owns the
   single refresh after its CVSS batch (see
   [ticket-priority.md](ticket-priority.md#refresh-points))
11. For manual create-with-CVE, use the locked-current CVE and new Ticket to
   prepare an all-source freshness refresh through `cve_service`. Validate
   registry capability and enabled state and register publication only after all
   creation and audit work succeeds. This applies to both a newly created
   placeholder and an existing CVE
12. Return the created Ticket

For a manual creation whose locked-current CVE is already `REJECTED`, these
same steps remain authoritative: initial status still comes only from step 4,
and the function does not call `ignore_new_for_rejected_cve()` or create the
automatic `CVE rejected` status event. The authorized user may invoke the
ordinary manual ignore operation separately.

**Concurrency — CVE uniqueness**: If the INSERT raises an
`IntegrityError` due to the UNIQUE constraint on `Ticket.cve_id` (race
between concurrent creation for the same CVE), the service catches the
exception and raises `TicketCVEConflictError`. The API handler maps this
to `409 TICKET_CVE_CONFLICT`.

**Locking**: manual creation locks User `FOR SHARE`; CVE-associated creation
then locks the CVE before the Ticket INSERT. System creation omits the User
lock. This serializes assignment eligibility and association state; the new
Ticket row itself has no pre-existing row to lock.

**reconcile_ticket_status**: Not called — initial status is determined by
fixed rules, and the ticket cannot have packages at creation time.

**Post-commit freshness**: after successful caller commit and lock release, the
registered database-free effect publishes the refresh. Publication failure is
best-effort for this mutation: log it and preserve the ordinary `201` response
and committed audit events. An expected no-eligible-source preparation outcome
is likewise logged and suppressed, so no publication is registered and the
Ticket still commits. Unexpected database, bootstrap-invariant, registration,
or transaction errors escape and roll back normally. Periodic sync or manual
refetch recovers the accepted crash gap; there is no durable dispatch row.

**Audit events**: Up to 6, in this order: `ticket_created`, optional
`assignment`, optional `severity_changed`, optional
`coordinated_release_changed`, optional `cve_associated`, and, for manual
creation only, optional system `priority_changed`. Every event except
`ticket_created` uses `comment = NULL`.

### associate_cve

Associates a CVE with a ticket that does not yet have one.

```python
async def associate_cve(
    db: AsyncSession,
    *,
    ticket_id: UUID,
    cve_id: str,
    acting_user_id: UUID,
    evaluation_date: date | None = None,
) -> Ticket:
```

For an API workflow returning `TicketDetail`, the caller captures one UTC date
and supplies it here and to final detail assembly. Another internal caller may
omit it; the function then captures one date at entry for its complete chain.

**Preconditions**:

- Ticket must be operable (`ensure_ticket_operable`)
- Ticket must have `cve_id IS NULL` (else `TicketCVEAlreadySetError`)
- CVE Resolution Behavior applies (on-demand fetch, conflict check)

**Behavioral steps**:

1. Acquire `FOR SHARE` on the acting User and stabilize current active/VA
   eligibility. If ineligible, the association continues but auto-assignment is
   skipped
2. Resolve or create the local CVE through CVE Resolution Behavior without
   holding a Ticket lock. For an existing CVE, the resolution query acquires
   `FOR UPDATE` as its first persistent read; a newly inserted CVE becomes the
   transaction's locked root. No external I/O occurs in this transaction.
3. Retain the CVE `FOR UPDATE` lock established by step 2.
4. Acquire `FOR UPDATE` on the Ticket row.
5. For a consumer call, revalidate Ticket accessibility from the locked-current
   Ticket. Capability has already been checked before CVE or Ticket lookup. An
   inaccessible Ticket returns `TICKET_NOT_FOUND` even though this workflow
   locked the CVE first.
6. Call `ensure_ticket_operable(ticket)`.
7. Verify `ticket.cve_id IS NULL` (else `TicketCVEAlreadySetError`) and, under
   the CVE lock, verify that no other Ticket is associated with the CVE (else
   `TicketCVEConflictError`).
8. `auto_assign_actor(ticket, acting_user)` using the stabilized User.
9. Capture `previous_severity = ticket.severity_manual` (may be `NULL`).
10. Set `ticket.cve_id` and clear `ticket.severity_manual = NULL` (same
    UPDATE — maintains `chk_ticket_severity_manual_cve_exclusive`)
11. Create `TicketAuditEvent` (`cve_associated`,
    `user_id = acting_user_id`).
12. Resolve `evaluation_date` from the supplied value or capture it once, then
    call `recalculate_cvss_chain()` in association mode with `cve.id`,
    `association_previous_severity = previous_severity`, and that date. The
    same-transaction re-locks preserve the already-established
    User-then-CVE-then-Ticket order and observe all assessment
    mutations committed before this operation acquired the CVE lock. The chain
    confirms CVE-owned severity, creates the optional manual-to-derived
    `severity_changed` handover, then recalculates every system-managed Product
    through the narrow exception. Changed-Product events are system-attributed,
    use `reason = cvss`, and are ordered by `TicketPackageProduct.id` after the
    handover event. The chain then refreshes the automatic priority from the
    associated CVE's severity and exploitation evidence, creating an optional
    system `priority_changed` after the Product events.
13. Call `reconcile_ticket_status()` exactly once after the handover and all
    Product events, using the same UTC `evaluation_date`. Gate #3 (severity set)
    and gate #4 (at least one canonical SUSE assessment in any accepted
    version) may now fail, causing regression to Analysis. Do not auto-assign a
    second time.
14. Prepare and register an all-source CVE freshness refresh through
    `cve_service`, regardless of whether the CVE was newly created or already
    populated. Complete registry and enabled-state validation before
    registration.
15. Return the updated Ticket.

If the locked CVE was already `REJECTED` before this deliberate manual
association, the function still performs only the ordinary association,
severity-source handover, Product, and gate sequence above. It does not invoke
`ignore_new_for_rejected_cve()` or create an automatic `CVE rejected` event; the
authorized user may ignore the Ticket through the ordinary manual operation.

**Locking**: `FOR SHARE` on acting User, `FOR UPDATE` on CVE, then `FOR
UPDATE` on Ticket. CVE Resolution
Behavior involves only local database operations and may insert a minimal CVE
before that row can be locked. No synchronous external HTTP call or
Redis/Celery operation occurs while either lock is held. Re-locking either row
inside `recalculate_cvss_chain()` is a same-transaction no-op. The service
registers database-free publication as a post-commit effect; the shared
transaction dependency executes it only after commit and lock release.

This order serializes correctly with CVSS mutation. Manual CVSS mutation first
locks its own acting User and then the CVE; system CVSS mutation starts with the
CVE. If either mutation locks the CVE first, association waits and then consumes
its committed severity. If association locks first, the CVSS mutation waits,
then observes the associated Ticket and applies its direct-audit and propagation
contract. Neither path can use a pre-lock assessment or association snapshot.

**recalculate_cvss_chain**: YES, in association mode. Associating a CVE changes
the Ticket's severity source. The function confirms CVE-owned severity from the
complete locked assessment set and applies automatic Product eligibility
inline through the package-model-owned evaluator.
If the CVE has no assessments, severity resolves to `null` (gate #3 fails) and
eligibility uses the 10.0 conservative fallback.

A `TicketCVEConflictError` continues to expose the documented
`existing_ticket_id` as the conflicting Ticket's `SNTL-{n}` identity even when
that Ticket is otherwise inaccessible. Ticket and CVE identifiers are not
confidential Ticket content; this does not authorize following the identifier
to protected data.

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
per changed automatic occurrence and an optional system `priority_changed`,
followed by at most one gate-derived `status_change`. Optional assignment and
its `New → Analysis` event precede `cve_associated`; Product events follow the
handover event, and `priority_changed` follows the Product events.

Any settings, database, eligibility, audit, flush, or reconciliation error
escapes and rolls back association, manual-severity clearing, assignment,
Product values, automatic priority, Ticket status, and every event together.

An expected no-eligible-source freshness outcome is logged and suppressed: it
registers no publication but does not roll back the association. Unexpected
database, bootstrap-invariant, registration, or transaction errors still escape
and roll back normally. After successful commit, Redis or broker publication
failure is best-effort and preserves the ordinary `200` response. Periodic sync
or manual refetch recovers the accepted commit-to-publication crash gap without
durable dispatch state.

### assign_ticket

Assigns or reassigns a ticket to a user.

```python
async def assign_ticket(
    db: AsyncSession,
    *,
    ticket_id: UUID,
    assignee_id: UUID,
    acting_user_id: UUID,
    evaluation_date: date | None = None,
) -> Ticket:
```

For an API workflow returning `TicketDetail`, the caller supplies the same UTC
date to this function and final detail assembly. Other callers may omit it; the
function captures one date at entry if reconciliation becomes applicable.

**Preconditions**:

- Ticket must be operable (`ensure_ticket_operable`)
- Target user must be active (else `AssigneeInactiveError`) and hold
  the `vulnerability_analyst` role (else `AssigneeNotVAError`)

**Behavioral steps**:

1. Resolve the target User through the user-domain boundary and acquire `FOR
   SHARE` on a match before the Ticket lock. Preserve absence for deferred
   reporting
2. Acquire `FOR UPDATE` on the Ticket row
3. Revalidate consumer accessibility from the locked-current Ticket; denial
   returns `TICKET_NOT_FOUND` before target-user or operability errors
4. Call `ensure_ticket_operable(ticket)`
5. If the target was absent, raise `UserNotFoundError`. Validate the locked
   target user (active — else `AssigneeInactiveError`;
   holds VA role — else `AssigneeNotVAError`)
6. **Idempotency check**: if `ticket.assignee_id == assignee_id`, return
    ticket unchanged (no audit event, no status evaluation)
7. Set `ticket.assignee_id = assignee_id`
8. Create `TicketAuditEvent` (`assignment`)
9. If `ticket.status == New`: set `ticket.status = Analysis`, create
    `TicketAuditEvent` (`status_change`, `user_id = NULL`,
    `old_value = "New"`, `new_value = "Analysis"`) — this is the explicit
    `New → Analysis` transition (see Architectural Invariant in
    `tickets.md`); the `status_change` event is created here, not by
    `reconcile_ticket_status`
10. Call `reconcile_ticket_status(ticket, evaluation_date=evaluation_date)` —
    using the supplied date or the one captured at entry, evaluates further promotion
    from `Analysis` upward; may produce a second `status_change` event
    if `Analyzed` or `Resolved` gate conditions are already satisfied
11. Return updated Ticket

**Locking**: `FOR SHARE` on target User, then `FOR UPDATE` on Ticket. Target
absence is reported only after locked-current Ticket accessibility and
operability, preserving their existing precedence.

**reconcile_ticket_status**: YES — evaluates whether the ticket's
existing data satisfies gates above `Analysis` (Analyzed or Resolved).
While `ticket-mutations.md` classifies assignment as "not gate-relevant"
in the sense that it does not modify CVSS/severity/package data, the
explicit `New → Analysis` transition in step 9 means the ticket is now
in the gate zone and `reconcile_ticket_status` can promote it further
if conditions are met.

**Audit events**: `assignment` (only if assignee actually changes).
Possibly `status_change` (explicit `New → Analysis` in step 9 and/or
further promotion from `reconcile_ticket_status`). Assignment promotion and
ordinary gate events use `comment = NULL`.

**auto_assign_actor**: Not called — this operation performs an explicit
assignment to a specified user, which supersedes implicit
auto-assignment of the acting user.

### set_priority_override

Sets, changes, or clears `Ticket.priority_override`. The complete Category A
contract is owned by
[ticket-priority.md](ticket-priority.md#set_priority_override); this is a
cross-reference overview.

- **Locking**: `FOR SHARE` on the acting User, then `FOR UPDATE` on the Ticket.
- **Guards**: locked-current accessibility (`TicketNotFoundError`), then
  `ensure_ticket_operable()` (`TicketNotMutableError`); an unchanged override is
  a no-op before assignment.
- **Effects**: `auto_assign_actor()`, the override write, one acting-user
  `priority_changed` with `override_action` `set`, `changed`, or `cleared`, then
  exactly one `reconcile_ticket_status()`. `priority_auto` is not modified.
- **Audit order**: optional `assignment` and system `New → Analysis`,
  `priority_changed`, then at most one final gate-derived `status_change`.

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

1. Acquire `FOR SHARE` on the acting User and stabilize current assignment
   eligibility
2. Acquire `FOR UPDATE` on the Ticket row
3. Revalidate consumer accessibility from the locked-current Ticket; denial
   returns `TICKET_NOT_FOUND` before status or operability errors
4. Call `ensure_ticket_operable(ticket)` — rejects Ignored or Duplicated
   (`TicketNotMutableError`) tickets
5. Verify status is New or Analysis (else `InvalidTransitionError` —
   this catches Analyzed and Resolved, which pass `ensure_ticket_operable`
   but are not valid source states for ignore)
6. `auto_assign_actor(ticket, acting_user)` using the stabilized User; an
   inactive or non-VA actor is not assigned
7. Set `ticket.status = Ignored`
8. Create `TicketAuditEvent` (`status_change`)
9. Return updated Ticket

**Locking**: `FOR SHARE` on acting User, then `FOR UPDATE` on Ticket.

**reconcile_ticket_status**: NOT called — this is a direct transition
into the manual zone. `reconcile_ticket_status` never operates on
Ignored tickets.

**Audit events**: `status_change`. Possibly `assignment` (from
auto-assign). Both use `comment = NULL`.

### `ignore_new_for_rejected_cve()`

Trusted system-only lifecycle boundary for the automatic consequence of a
rejected associated CVE. Only `cve_service.upsert_cve()` may call it, while the
caller owns the CVE lock and already holds the unique associated Ticket lock.
It is not an API, task, CLI, or general-purpose ignore operation.

```python
async def ignore_new_for_rejected_cve(
    db: AsyncSession,
    *,
    cve_id: UUID,
    ticket: Ticket,
) -> Ticket:
```

`cve_id` is the internal UUID of the already locked CVE root; `ticket` is its
already locked unique associated Ticket.

**Preconditions and authority**:

- The caller explicitly uses the trusted internal boundary; actor absence alone
  never grants authority.
- The caller holds the associated CVE root lock and the supplied Ticket
  `FOR UPDATE` lock in that order.
- Authority and lock ownership are trusted caller preconditions, not conditions
  rediscovered through session introspection. The function verifies
  `ticket.cve_id == cve_id`; an association violation raises `ValueError` before
  a Ticket mutation.

**Behavior**:

1. Read the supplied locked-current Ticket status without reacquiring either
   root or querying audit history.
2. If status is `New`, set it to `Ignored` and create exactly one
   system-attributed `status_change` with `old_value = "New"`,
   `new_value = "Ignored"`, `comment = "CVE rejected"`, and `detail = NULL`.
3. For `Ignored`, `Analysis`, `Analyzed`, `Resolved`, or `Duplicated`, return the
   Ticket unchanged with no event. Do not call `ensure_ticket_operable()`,
   assign, reconcile, register convergence, or change any other field.
4. Flush an effective transition and return the Ticket. Do not commit, roll
   back, or perform external, Redis, or Celery I/O.

The boundary is idempotent from current state: after one effective transition,
re-invocation observes `Ignored` and is a no-op. Database, audit, flush,
cancellation, and programming exceptions propagate unchanged and roll back the
caller's complete per-CVE transaction.

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

1. Acquire `FOR SHARE` on the acting User and stabilize current assignment
   eligibility.
2. **Phase 1 — lock and validate roots**:
   a. Determine lock order: `first = min(source_id, target_id)`,
       `second = max(source_id, target_id)`
   b. `SELECT ... WHERE id = first FOR UPDATE` — lock first root
   c. `SELECT ... WHERE id = second FOR UPDATE` — lock second root
   d. Revalidate accessibility for both locked-current roots
   e. Validate both role-specific guards (operable for the source,
      non-Duplicated for the target)
   f. Validate source != target (else `SelfDuplicateError`)
3. **Phase 2 — lock dependents**:
   `SELECT ... WHERE duplicate_of_id = source_id ORDER BY id FOR UPDATE NOWAIT`
   On SQLSTATE `55P03`: rollback and raise
   `DuplicateConcurrentModificationError`
4. **Mutations** (only reached if all locks acquired):
   a. `auto_assign_actor(source, acting_user)` using the stabilized User; an
      inactive or non-VA actor is not assigned
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
5. Return updated source ticket

The source and target visibility decisions are both made from the locked-current
rows and both must pass before Phase 2 or any mutation. Missing and inaccessible
roots produce the same `TICKET_NOT_FOUND` outcome. Dependents remain a trusted
system consequence of the authorized source mutation and are not independently
visibility-checked. After a link is established, `duplicate_of_ticket_id` may
continue to expose the stored target `SNTL-{n}` identifier if that target later
becomes inaccessible; following that identifier then returns
`TICKET_NOT_FOUND`.

**Post-operation**: no post-commit work. Everything is atomic.

**Locking**: acting User `FOR SHARE`, source + target (blocking, ordered), then
dependents (NOWAIT, ordered). All within a single transaction.

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
3. Ensure the reconciliation result has registered one transaction-local
   Ticket convergence effect for this successful manual-zone exit, including
   when the evaluated result is `Resolved`.

Changed automatic Product events use the system actor,
`reason = reactivation`, and ascending `TicketPackageProduct.id` order. Any
assignment-eligibility sanitation event follows those Product events; the final
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
| `evaluation_date` | `date \| None` | No | UTC date shared by synchronous eligibility, reconciliation, and any TicketDetail response; capture once at entry when omitted |

**Preconditions**: the Ticket exists and its locked-current status is
`Ignored`; otherwise raise `TicketNotFoundError` or
`InvalidTransitionError`, respectively.

**Behavioral steps**:

1. For a non-null actor, acquire `FOR SHARE` on the acting User and stabilize
   current assignment eligibility; a system caller has no User root. Then
   acquire `FOR UPDATE` on the Ticket and
   for a consumer call revalidate locked-current accessibility before validating
   `Ignored`. The documented trusted system reopen does not acquire user scope.
   The caller identifies that trusted invocation explicitly through the
   implementation-chosen service boundary; `acting_user_id = NULL` by itself
   never grants system authority.
2. Preserve `original_status = Ignored` and resolve `evaluation_date` from the
   supplied value or capture it once.
3. Call `ticket_mutations.auto_assign_actor(..., force=True)` with the
   stabilized User. An active VA actor becomes the assignee; an inactive or
   non-VA actor or system caller leaves the current assignee unchanged. Final
   reconciliation sanitizes an inactive or non-VA assignee only when the final
   status is `Analysis` or `Analyzed`; a final `Resolved` result retains it.
4. Set `status = Analysis`, then call `_complete_manual_zone_exit()` with the
   preserved source status and date and return the resulting Ticket. Its final
   status is `Analysis`, `Analyzed`, or `Resolved` from current gate inputs.

**Audit events**: optional actor assignment, zero or more system-attributed
`product_eligibility_changed` events, optional assignment-eligibility sanitation
`assignment`, then one system-attributed
`status_change` from `Ignored` to the final evaluated status. All comments are
`NULL` except a sanitation assignment's canonical unassignment comment.

**Locking and transaction**: a consumer invocation retains its acting User `FOR
SHARE` and Ticket `FOR UPDATE` locks through assignment, package convergence,
audit, and final reconciliation. A system invocation retains only the existing
CVE/Ticket roots. It
flushes but does not commit or roll back. Any escaping error rolls back all of
these effects in the caller-owned transaction.

**CVE-ingestion composition**: before invoking this function, the trusted
`cve_service` caller verifies under its existing CVE-then-Ticket locks that the
Ticket remains the unique association of the locked CVE and that its status is
`Ignored`. It then calls the existing system form with `ticket_id` and the
caller-supplied `evaluation_date`. Step 1 reselects the same Ticket `FOR UPDATE`;
that same-transaction re-lock is a no-op and does not invert the already-held
CVE-then-Ticket order. The remaining behavior, audit, convergence registration,
and exception contracts are identical. If locked-current status is not
`Ignored`, `cve_service` does not invoke this boundary; a direct invalid
invocation retains the ordinary `InvalidTransitionError`. System authority is
selected through the existing implementation-chosen service boundary, not by
`acting_user_id = NULL` alone.

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
| `evaluation_date` | `date \| None` | No | UTC date shared by synchronous eligibility, reconciliation, and any TicketDetail response; capture once at entry when omitted |

**Preconditions**: the Ticket exists and its locked-current status is
`Duplicated`; otherwise raise `TicketNotFoundError` or
`InvalidTransitionError`, respectively.

**Behavioral steps**:

1. Acquire `FOR SHARE` on the acting User and stabilize current assignment
   eligibility, then acquire `FOR UPDATE` on the Ticket and
   revalidate locked-current consumer accessibility before validating
   `Duplicated`.
2. Preserve `original_status = Duplicated`, capture the current duplicate
   target's `SNTL-{n}` identifier as `original_target_identifier`, and resolve
   `evaluation_date` from the supplied value or capture it once.
3. Call `ticket_mutations.auto_assign_actor(..., force=True)` with the
   stabilized User. An active VA actor becomes the assignee; otherwise the
   current assignee is retained.
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
assignment-eligibility sanitation `assignment`, then one
system-attributed `status_change` from `Duplicated` to the final evaluated
status. All comments are `NULL` except a sanitation assignment's canonical
unassignment comment. Every event and mutation is atomic in the caller-owned
transaction.

**Locking and transaction**: the function retains its acting User `FOR SHARE`
and Ticket `FOR UPDATE` locks through assignment, duplicate-link removal, audit,
package convergence, and
final reconciliation. It flushes but does not commit or roll back. Any escaping
error rolls back the duplicate-link clear and every other effect.

**Return and idempotency**: returns the updated Ticket after flush. A request
whose locked-current status is no longer `Duplicated` is rejected rather than
silently replayed; a successful revert never repoints other Tickets.

## Ticket Convergence

Every successful `Ignored` or `Duplicated` exit registers one transaction-local
Ticket convergence effect, even if its immediate gate result is `Resolved`. An
ordinary `Resolved` regression registers the same effect.
An explicit `Ignored` or `Duplicated` exit first
converges existing system-managed Product eligibility synchronously from current
PostgreSQL inputs before its final gate result. A `Resolved` regression is
instead produced by an ordinary gate-zone mutation that has already maintained
current eligibility. The Ticket convergence workflow
   re-resolves every persisted package marker through SMELT, including
   soft-deleted markers without restoring them, then catches up on external
   data against the resulting tree (e.g., Red Hat CVSS updates — the
   `sync_redhat_cves` fetcher scopes to active tickets and skips inactive
   ones). See `docs/features/packages/package-model.md` (Ticket Convergence)
   and
   [fetcher-infrastructure.md](../platform/fetcher-infrastructure.md)
   ("Per-Ticket Catch-Up: `catch_up()` Method") for the method contract.

The effect is registered internally by `reconcile_ticket_status()` from the
preserved manual-zone source status or a `Resolved` regression. Its initial
publication attempt runs after commit. CVSS assessment and
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

Publication registered by these automatic mutation paths follows the
publication policies below. The committed Ticket/package mutation and its
normal success response are retained on a broker operational publication
failure, and recovery is a complete explicit rerun through
`POST /api/v1/tickets/{ticket_id}/rerun-reactivation`.

This differs intentionally from that explicit rerun endpoint: dispatch is the
requested operation there, so a broker operational initial-publication failure
returns 503 and no Ticket mutation has been committed. Other publication
exceptions propagate unchanged. Neither path adds a requesting-user log field;
API request correlation uses the existing `request_id` contract.

### Publication vocabulary

These terms are normative for every specification that describes Ticket
convergence publication:

| Term | Meaning |
|------|---------|
| **registration** | the transaction-local declaration of one future Ticket convergence publication effect, created by `reconcile_ticket_status()` step 5 |
| **initial publication attempt** | the synchronous broker call that submits the root Ticket convergence task |
| **submitted** | the initial publication attempt returned without raising; it proves neither worker start nor workflow outcome |
| **acceptance_unconfirmed** | the initial publication attempt raised a broker operational error; it is not proof that the broker rejected the task |
| **root workflow outcome** | the later execution, retry, and terminal outcome of `run_ticket_convergence()` |
| **catch-up publication/outcome** | the later per-fetcher publication and its execution |
| **explicit complete rerun** | `POST /api/v1/tickets/{ticket_id}/rerun-reactivation` |

### Initial publication boundary and database-free publisher

The publication boundary submits exactly one root Ticket convergence task per
registered effect:

```python
async def publish_ticket_convergence(
    *,
    ticket_id: UUID,
    task_id: str,
) -> None:
```

The publisher is a Ticket-convergence-specific, database-free boundary, not a
generic post-commit effect framework. Its concrete module placement and Celery
client injection mechanism are implementation choices, but every module that
consumes detached effects (`ticket_mutations`, `ticket_service`,
`package_service`, and the CVE/fetcher infrastructure) MUST be able to reach it
and substitute the broker-publication call in tests without violating the
documented module dependency directions.

- The boundary receives only detached primitive data: the canonical internal
  Ticket UUID and the allocated task ID. It opens no database session, performs
  no query, and accepts no ORM instance. Its only external I/O is the configured
  Celery broker publication call; it performs no HTTP or other network I/O and
  accesses no Redis key of its own.
- It returns `None` when the publication call returns without raising. That
  event is `submitted`. The library-normalized broker operational error
  `kombu.exceptions.OperationalError` (the same class as
  `celery.exceptions.OperationalError`) propagates unchanged and means
  `acceptance_unconfirmed`. Classification uses the exception class only and
  never the exception text.
- The synchronous call includes Celery's own configured publication retry
  policy. The boundary adds no retry of its own.
- The draining owner allocates the transient root task ID in memory immediately
  before each attempt. Registration never allocates one and no task ID is
  persisted.
- Every other exception propagates unchanged and is never converted into
  `acceptance_unconfirmed`: `asyncio.CancelledError`, worker cancellation and
  shutdown signals (`WorkerShutdown`, `WorkerTerminate`, `SystemExit`,
  `KeyboardInterrupt`), `SoftTimeLimitExceeded`, `TimeLimitExceeded`,
  `Terminated`, `MemoryError`, serialization and content errors
  (`SerializationError`, `EncodeError`, `SerializerNotInstalled`,
  `ContentDisallowed`), `QueueNotFound`, `ImproperlyConfigured`,
  `SecurityError`, and any unexpected programming or contract error.
- The boundary never waits for worker start or workflow execution and never
  reads a Celery task result; the deployment has no Celery result backend. It
  emits no log and selects no owner policy.
- No database transaction or row lock may be open when the boundary is
  invoked.

### Publication policies

Every automatic transaction owner uses one policy. This includes API mutations,
CVE/fetcher finalization, the all-CVE recalculation runner, per-Ticket lifecycle
and Product/threshold workflows, lifecycle catch-up, and the per-package units
of `run_ticket_convergence()`. The owner commits and releases its row locks,
atomically detaches the complete sequence, and attempts each effect once in
registered order before beginning its next unit or dependent post-commit
handoff. An owner may close or reuse its session according to its owning
contract because the publisher performs no database work.

The automatic adapter calls the database-free publisher. A normal return leaves
the committed unit and its existing outcome accounting unchanged. A
`kombu.exceptions.OperationalError` also leaves them unchanged, emits exactly
one Ticket-owned sanitized `ticket_convergence_publication_failed` ERROR, and is
absorbed so later effects and owner work continue. Automatic paths never return
`CELERY_UNAVAILABLE`, expose a publication result to their owner, add a
publication-failure counter, or change an aggregate outcome because of this
broker operational failure. Recovery is the explicit complete rerun. A complete
all-CVE recalculation is not guaranteed to republish an already-converged unit.

Every other exception propagates unchanged from the automatic adapter. Because
the database commit has already succeeded, it MUST bypass any pre-commit or
transaction-failure handler: it cannot roll back or reclassify the committed
unit, overwrite a committed source status, call a second terminal metric helper,
or emit the broker-operational publication-failure event. The automatic API path then
follows the unchanged generic post-commit callback contract; task and fetcher
owners follow their existing whole-workflow failure or retry contracts. The
owning specification defines session closure and subsequent work after that
propagation.

**Explicit operator rerun.** This path does not use the best-effort automatic
drain: publication is the requested operation. `dispatch_ticket_convergence()`
opens a short-lived session, locks and validates the Ticket, allocates the
transient task ID, commits and closes the session, and only then performs the
initial publication attempt with no lock held. `submitted` returns the task ID
for the existing `202` response. `acceptance_unconfirmed` emits exactly one
sanitized request-owned ERROR and raises `TicketConvergenceDispatchError`,
which the endpoint maps to `503 CELERY_UNAVAILABLE` before the response is
transmitted. No Ticket mutation, audit event, compensation row, durable run, or
progress resource is created, and duplicate work remains accepted.

### Publication failure logging

For one broker operational initial-publication failure, exactly one owner-selected
feature log is emitted. The publisher boundary and the API transaction
dependency's generic post-commit callback loop never log that failure
themselves.

- All automatic owners share one Ticket-owned event:
  `ticket_convergence_publication_failed` at ERROR, with `ticket_id` (the
  internal Ticket UUID), the closed sanitized `cause` category
  `broker_operational_error`, and the request or task correlation already bound
  to the execution context.
- The explicit operator rerun owns its request failure event
  `ticket_convergence_dispatch_failed` at ERROR, with `ticket_id`, the same
  closed `cause` category, and the bound `request_id`.

The two feature-owned events above contain no `exc_info`, raw exception text, a
traceback, broker URLs, hosts, ports, credentials, payloads, Ticket content, or
external data. This restriction does not redefine the unchanged generic
post-commit callback log for an unexpected non-operational exception. Log
format, levels, and correlation remain owned by
`docs/features/platform/logging.md`.

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

Service-owned orchestration boundary used by
`POST /api/v1/tickets/{ticket_id}/rerun-reactivation`. Publication is the
requested operation, so the function owns one short transaction and performs
the initial publication attempt manually after that transaction has committed
and closed.

```python
async def dispatch_ticket_convergence(
    *,
    ticket_id: UUID,
    session_factory: async_sessionmaker[AsyncSession],
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
- The Ticket must still exist, be accessible, and its locked-current status must
  be `Analysis`, `Analyzed`, or `Resolved`. Absence or inaccessible visibility
  raises `TicketNotFoundError`; `New`, `Ignored`, or `Duplicated` raises
  `InvalidTransitionError`.
- The function does not call `ensure_ticket_operable()`.

**Behavior**:

1. Open a short-lived session from `session_factory`. Load the Ticket by
   canonical UUID with `FOR UPDATE` as the first database operation, revalidate
   consumer accessibility, and only then evaluate status eligibility from
   locked-current state. A missing or inaccessible Ticket and an ineligible
   status raise before publication and register no effect or callback.
2. Allocate the transient Celery root task ID without performing broker I/O.
3. Commit and close the session, releasing the Ticket lock.
4. Perform the initial publication attempt through the database-free publisher
   defined in "Initial publication boundary and database-free publisher" above,
   with the canonical Ticket UUID and the allocated task ID and with no lock
   held. On `submitted`, return the allocated task ID. On
   `acceptance_unconfirmed`, emit exactly one sanitized request-owned ERROR (see
   "Publication failure logging") and raise `TicketConvergenceDispatchError`
   with the fixed message `"Ticket convergence could not be dispatched to the
   task broker"`. The endpoint uses that same fixed text as the 503 `detail` and
    never exposes the caught exception text.

A database exception or ambiguous outcome from step 3 closes the session,
discards the transient task ID, performs no publication attempt, and propagates
through the ordinary database-error path. Because this preparation transaction
does not mutate Ticket state, it requires no compensation; a later explicit
rerun starts a new locked validation and allocates a new task ID.

The preparation transaction performs no I/O while the Ticket lock is held, and
the publication attempt acquires no lock. The endpoint maps the returned task
ID to `TicketConvergenceDispatchResponse`
and HTTP 202, and `TicketConvergenceDispatchError` to
`503 CELERY_UNAVAILABLE` before the response is transmitted.

The function registers no post-commit callback and never depends on an
exception raised during the API transaction dependency's teardown or callback
loop. It creates no `TicketAuditEvent`, no durable run or progress resource, and
no compensation row. A broker acknowledgement may be ambiguous, so the task may
still execute despite the 503 response. Re-invocation is intentionally accepted
and publishes another complete workflow. Concurrent calls serialize only the
locked status check; they do not coalesce publication.

The function propagates `TicketNotFoundError`, `InvalidTransitionError`,
`TicketConvergenceDispatchError`, database exceptions, and every
non-operational publication exception. It does not expose package-specific or
catch-up exceptions synchronously because those occur in the dispatched
workflow.

### Cross-references

- [cvss-scoring.md](cvss-scoring.md) — CVSS resolution cascade
- [default-cvss-version-operations.md](../platform/default-cvss-version-operations.md)
  — all-CVE runner consumption of the automatic publication policy
- [ticket-mutations.md](ticket-mutations.md) —
  `reconcile_ticket_status()` step 5, `recalculate_cvss_chain()`
  contract, assignment and operability primitives
- [package-service.md](../packages/package-service.md) — synchronous manual-
  zone-exit eligibility boundary and complete Ticket convergence workflow
- [fetcher-infrastructure.md](../platform/fetcher-infrastructure.md) —
  `catch_up()` method contract
- [cve-fetcher-infrastructure.md](../platform/cve-fetcher-infrastructure.md) —
  per-CVE finalization drain (`commit_and_dispatch()`)
- [testing-strategy.md](../platform/testing-strategy.md) — Ticket Convergence
  Publication Handoff test matrix
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

- Requires `manage_confidentiality` capability (enforced at API layer)

**Behavioral steps**:

1. Acquire `FOR UPDATE` on the Ticket row
2. Revalidate consumer accessibility from the locked-current Ticket; denial
   returns `TICKET_NOT_FOUND` before no-op classification
3. **Idempotency check**: if `ticket.is_confidential == is_confidential`,
    return ticket unchanged (no audit event)
4. Preserve the locked current flag as the event's `old_value`, then set
   `ticket.is_confidential = is_confidential`.
5. For an effective `true` to `false` transition, delete every
   `TicketAccessGrant` belonging to the Ticket in the same transaction. These
   automatic deletions create no `access_grant_removed` events. For
   `false` to `true`, create no grant and perform no external lookup.
6. Create exactly one `TicketAuditEvent` (`confidentiality_changed`) with the
   preserved and requested boolean strings.
7. Flush the flag, grant deletions, and event, then return the locked-current
   updated Ticket.

`Ticket.coordinated_release_at` is never modified by this operation. After an
effective `true` to `false` transition, a retained CRD stays read-only until
the Ticket becomes confidential again (see `set_coordinated_release_date`).

`TicketPackageMaintainer` rows are not grants and are never modified by this
operation. When confidentiality becomes true, existing associations qualify
through the canonical visibility predicate while their package is included and
the caller can authenticate. The transition performs no SMELT request or
maintainership acquisition.

**Locking**: FOR UPDATE on Ticket row.

**Concurrency and result**: concurrent confidentiality, grant, and revoke
operations serialize on this Ticket lock. Each caller classifies its result
from the state observed after waiting. A same-value waiter is a no-op. Opposing
effective toggles each create one event in serialization order. If
declassification wins before a grant or revoke, that waiter observes a
non-confidential Ticket and is rejected by its normal guard. If grant or revoke
wins first, its effective event precedes `confidentiality_changed`; a subsequent
declassification deletes every then-current grant. No caller returns a stale
pre-lock Ticket or grant result.

**Transaction and rollback**: the function calls neither commit nor rollback.
Any grant-deletion, audit, database, or flush failure escapes and causes the
caller-owned transaction to roll back the flag, every deletion, and the event
together. A caller rollback after return has the same complete effect.

**reconcile_ticket_status**: NOT called — confidentiality is not
gate-relevant.

**auto_assign_actor**: Not called. Confidentiality changes visibility only.

**Audit events**: `confidentiality_changed` only when the flag actually
changes, with `comment = NULL`. Automatic grant deletion creates no additional
event.

### set_coordinated_release_date

Sets, changes, or clears `Ticket.coordinated_release_at` on a confidential
Ticket. Semantics are owned by
[tickets.md](tickets.md#coordinated-release-date).

```python
async def set_coordinated_release_date(
    db: AsyncSession,
    *,
    ticket_id: UUID,
    coordinated_release_at: datetime | None,
    acting_user_id: UUID,
) -> Ticket:
```

`coordinated_release_at` is a timezone-aware instant, already normalized to UTC
by the API boundary; `None` clears the CRD. `acting_user_id` is the authorized
user; no system caller exists. The API requires `manage_confidentiality` before
calling.

**Behavioral steps**:

1. Acquire `FOR UPDATE` on the Ticket row. No User lock is acquired because
   the operation never assigns.
2. Revalidate consumer accessibility from the locked-current Ticket. Missing or
   inaccessible raises `TicketNotFoundError` before every other decision.
3. Verify the locked-current Ticket is confidential; otherwise raise
   `TicketNotConfidentialError`. This function does not call
   `ensure_ticket_operable()`; it is valid in every Ticket status, including
   `Ignored` and `Duplicated`.
4. **Idempotency check**: if the requested instant equals the stored value
   (both `NULL`, or the same UTC instant), return the Ticket unchanged with no
   write or event.
5. Preserve the stored value, persist the requested value, and create one
   `coordinated_release_changed` event attributed to `acting_user_id` whose
   `old_value` and `new_value` are the preserved and requested instants in UTC
   ISO 8601 format, or `NULL` for an absent side.
6. Flush the column and event, then return the locked-current updated Ticket.

**Concurrency**: the operation serializes with `set_confidentiality()`, access
grants, and every other Ticket mutation on the Ticket lock and classifies its
result from the state observed after waiting. If declassification wins, the
waiter is rejected with `TicketNotConfidentialError`; if the CRD change wins, a
later declassification retains the new value. Two concurrent CRD changes each
create one event in serialization order with true locked old values; a waiter
that observes its requested value is a no-op.

**reconcile_ticket_status**: NOT called — the CRD is not gate-relevant.

**auto_assign_actor**: Not called. The CRD is embargo metadata, not Ticket
work.

**Transaction and exceptions**: the function flushes but neither commits nor
rolls back. It propagates `TicketNotFoundError`, `TicketNotConfidentialError`,
and database, audit, and flush failures. Any failure or caller rollback leaves
neither the new value nor the event. The API returns the `TicketDetail`
projection of the post-mutation Ticket under
[`get_ticket_detail()`](#get_ticket_detail).

**Audit events**: `coordinated_release_changed` only when the stored value
actually changes.

### grant_access

Grants explicit access to a user on a confidential ticket.

```python
async def grant_access(
    db: AsyncSession,
    *,
    ticket_id: UUID,
    target_user: str,
    acting_user_id: UUID,
) -> AccessGrantMutationResult:
```

`target_user` accepts a UUID or exact username under `docs/api-spec.md` (User
Identifier Resolution). `AccessGrantMutationResult` is a transaction-local
typed result with `grant: TicketAccessGrant` and `action`, whose value is
exactly `created` or `already_exists`. The API maps `created` to 201 and
`already_exists` to 200; callers never infer this status from an unlocked
pre-read.

**Preconditions**:

- Ticket must be confidential (`is_confidential = true`; else
  `TicketNotConfidentialError`)
- Target user must exist (else `UserNotFoundError`)
- Creation for a target without an existing grant requires that target to be
  active (else `InactiveUserError`). This check does not apply to an existing
  idempotent grant result or to `revoke_access` — revoking a grant from an
  inactive user is a legitimate cleanup operation
- Requires `manage_confidentiality` capability (enforced at API layer)

**Behavioral steps**:

1. Resolve the target identifier and acquire `FOR NO KEY UPDATE` on the matching
   User as the first persistent root operation. Preserve absence without raising
   it yet. A matched row remains locked through the operation, stabilizing its
   ID, username, and active state without unnecessarily conflicting with
   foreign-key `FOR KEY SHARE` validation.
2. Acquire `FOR UPDATE` on the Ticket row.
3. Revalidate consumer accessibility from the locked-current Ticket. Missing or
   inaccessible returns `TICKET_NOT_FOUND` before confidentiality,
   target-user, activity, or no-op decisions.
4. Verify the Ticket is confidential (else `TicketNotConfidentialError`). This
   function does not call `ensure_ticket_operable()`. This guard precedes the
   deferred target-user result, so an accessible non-confidential Ticket returns
   `TICKET_NOT_CONFIDENTIAL` regardless of whether the target exists.
5. If the target was absent, raise `UserNotFoundError`. This result is reachable
   only for an accessible confidential Ticket.
6. Load the grant for the stabilized target under the Ticket lock. If it
   already exists, return `already_exists` with the original `granted_by` and
   `granted_at`.
   Do not validate `User.active`, rewrite provenance, or create an event.
7. For an absent grant, verify the locked target User is active (else
   `InactiveUserError`).
8. INSERT `TicketAccessGrant` record (`ticket_id`, `user_id`,
    `granted_by = acting_user_id`, `granted_at = now(UTC)`)
9. Create `TicketAuditEvent` (`access_grant_added`) whose `new_value` is the
   stabilized current target username.
10. Flush the grant and event, then return `created` with the new grant.

**Concurrency**: the User-then-Ticket locks serialize target lifecycle/rename
with the grant decision and serialize all grant/confidentiality operations for
one Ticket. Concurrent identical grants produce one `created` result and one
event; each waiter returns the winner-current row as `already_exists`, including
when a later deactivation made its current target projection inactive. The
UNIQUE constraint on `(ticket_id, user_id)` remains a database backstop, but the
contract does not permit continuing in a PostgreSQL transaction aborted by a
unique violation. Any conflict-safe mechanism that preserves the caller-owned
transaction and winner's original provenance is valid.

If deactivation wins the User lock, an absent grant is rejected with
`InactiveUserError`; an existing grant still returns `already_exists`. If grant
creation wins, it commits one grant/event and later deactivation retains the
grant. If reactivation wins, new creation may proceed; if an absent-grant call
observes the inactive User first, it is rejected and a later reactivation does
not retroactively change that result. A concurrent rename either commits first
and supplies the stabilized new username or waits until after this operation;
audit content never mixes target identities.

**Locking**: `FOR NO KEY UPDATE` on target User, then `FOR UPDATE` on Ticket.
Target absence is deferred until after Ticket accessibility as described above.
The function requires no pre-existing Ticket lock in the caller-owned
transaction.

**reconcile_ticket_status**: NOT called — access grants are not
gate-relevant.

**auto_assign_actor**: Not called. A grant is not a Ticket work mutation.

**Audit events**: `access_grant_added` (only if grant is new).

**Transaction and exceptions**: the function flushes but neither commits nor
rolls back. It propagates the documented service exceptions plus database,
audit, and flush failures. Any failure or caller rollback leaves no grant or
event.

### revoke_access

Revokes explicit access from a user on a confidential ticket.

```python
async def revoke_access(
    db: AsyncSession,
    *,
    ticket_id: UUID,
    target_user: str,
    acting_user_id: UUID,
) -> None:
```

**Preconditions**:

- Ticket must be confidential (`is_confidential = true`; else
  `TicketNotConfidentialError`)
- Target user must exist (else `UserNotFoundError`)
- Requires `manage_confidentiality` capability (enforced at API layer)

**Behavioral steps**:

1. Resolve and lock the target User as `grant_access()` does, preserving absence
   until the Ticket accessibility decision. Activity is not a revoke guard.
2. Acquire `FOR UPDATE` on the Ticket row.
3. Revalidate locked-current Ticket accessibility. Missing or inaccessible
   returns `TICKET_NOT_FOUND` before confidentiality, target-user, or no-op
   decisions.
4. Verify the Ticket is confidential (else `TicketNotConfidentialError`). This
   function does not call `ensure_ticket_operable()`. This guard precedes the
   deferred target-user result, so an accessible non-confidential Ticket returns
   `TICKET_NOT_CONFIDENTIAL` regardless of whether the target exists.
5. If the target was absent, raise `UserNotFoundError`. This result is reachable
   only for an accessible confidential Ticket.
6. **Idempotency check**: if grant does not exist for this user, return without
   side effects (no audit event)
7. Delete `TicketAccessGrant` record
8. Create `TicketAuditEvent` (`access_grant_removed`) whose `old_value` is the
   stabilized current target username
9. Flush the deletion and event, then return

**Locking**: `FOR NO KEY UPDATE` on target User, then `FOR UPDATE` on Ticket. The
function requires no pre-existing Ticket lock in the caller-owned transaction.

**Concurrency**: grant/revoke and revoke/revoke serialize on the Ticket after
the target User. The result follows commit order: grant then revoke leaves no
grant and creates add then remove events; no-op revoke then grant leaves the new
grant and only the add event; two revokes create at most one remove event.
Concurrent rename follows the same stabilized-username rule as grant. The
confidentiality race follows `set_confidentiality()`'s winner-current contract.

**Transaction and exceptions**: the function flushes but neither commits nor
rolls back. It propagates the documented service exceptions plus database,
audit, and flush failures. Failure or caller rollback restores the grant and
removes the event together.

**reconcile_ticket_status**: NOT called.

**auto_assign_actor**: Not called. Revocation changes visibility only.

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
   `granted_at` ascending and `user_id` ascending

The response projection resolves both target and grantor through complete
current `UserSummary` objects. Inactive users remain present with
`active = false`; neither inactivity nor reactivation mutates the grant.

**Locking**: None (read-only).

**reconcile_ticket_status**: NOT called.

**Audit events**: None (read-only).

## Service Exceptions

All exceptions in this module inherit from `TicketServiceError`.
API endpoint handlers catch `TicketServiceError` subclasses and map them
to the corresponding HTTP status code and error code per `api-spec.md`.

| Exception | HTTP | Code | Raised when |
|-----------|------|------|-------------|
| `TicketNotFoundError` † | 404 | `TICKET_NOT_FOUND` | Consumer Ticket locator is malformed, does not exist, or identifies an inaccessible Ticket; internal callers may also use it for an absent UUID |
| `TicketNotMutableError` † | 409 | `TICKET_NOT_MUTABLE` | Ticket is in manual zone (Ignored or Duplicated) |
| `InvalidTransitionError` † | 409 | `TICKET_INVALID_TRANSITION` | Requested status transition is not allowed |
| `TicketCVEAlreadySetError` | 400 | `TICKET_CVE_ALREADY_SET` | Ticket already has a CVE associated |
| `TicketCVEConflictError` | 409 | `TICKET_CVE_CONFLICT` | CVE is already associated with another ticket |
| `AssigneeNotVAError` | 400 | `TICKET_ASSIGNEE_NOT_VA` | Target user lacks the vulnerability_analyst role |
| `AssigneeInactiveError` | 409 | `TICKET_ASSIGNEE_INACTIVE` | Target user is inactive (for assignment) |
| `InactiveUserError` † | 409 | `USER_INACTIVE` | A new access grant is requested for an inactive target that has no existing grant |
| `SelfDuplicateError` | 400 | `TICKET_SELF_DUPLICATE` | Ticket cannot be marked as duplicate of itself |
| `DuplicateTargetIsDuplicatedError` | 409 | `TICKET_DUPLICATE_TARGET_DUPLICATED` | Target ticket is already in Duplicated status |
| `DuplicateConcurrentModificationError` | 409 | `TICKET_DUPLICATE_CONCURRENT_MODIFICATION` | NOWAIT lock on a dependent failed (concurrent operation on the duplicate group) |
| `SeverityDerivedError` † | 409 | `TICKET_SEVERITY_DERIVED` | Cannot manually set severity when it is auto-derived |
| `TicketNotConfidentialError` | 409 | `TICKET_NOT_CONFIDENTIAL` | Operation requires a confidential ticket |
| `TicketConvergenceDispatchError` | 503 | `CELERY_UNAVAILABLE` | Initial publication raised the broker operational error; the exception uses fixed sanitized detail and never contains the broker exception text |
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
    ├── refresh_priority_auto()
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
| set_priority_override  | ✓                      | ✓                      | —                     | ✓                     | —                   |
| ignore_ticket          | ✓                      | —                      | —                     | ✓                     | —                   |
| ignore_new_for_rejected_cve | —                  | —                      | —                     | —                     | —                   |
| mark_as_duplicate      | ✓                      | —                      | —                     | ✓                     | —                   |
| reopen_from_ignored    | —                      | ✓                      | —                     | ✓                     | ✓                   |
| revert_duplicate       | —                      | ✓                      | —                     | ✓                     | ✓                   |
| dispatch_ticket_convergence | —                  | —                      | —                     | —                     | —                   |
| set_confidentiality    | —                      | —                      | —                     | —                     | —                   |
| set_coordinated_release_date | —                | —                      | —                     | —                     | —                   |
| grant_access           | —                      | —                      | —                     | —                     | —                   |
| revoke_access          | —                      | —                      | —                     | —                     | —                   |
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
   `associate_cve()` with a CVSS assessment mutation. Verify
   User-then-CVE-then-Ticket locking for manual paths, CVE-then-Ticket locking
   for system paths, committed-current severity and applied eligibility,
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
     transaction-local Ticket convergence effect for final `Analysis`,
     `Analyzed`, and `Resolved`; registration is deduplicated per Ticket in one
     transaction in first-registration order; rollback, a definitely failed or
     ambiguous commit, and pre-commit cancellation produce no publication; an
     automatic broker operational publication failure is absorbed after commit
     with exactly one sanitized log, preserving the mutation's success response
     and requiring the complete operator rerun;
     inactive or non-VA assignees are cleared only for final `Analysis` or
     `Analyzed` and retained for final `Resolved`
12. **Operator convergence dispatch**: verify locked-current acceptance for
     `Analysis`, `Analyzed`, and `Resolved`; rejection of `New`, `Ignored`, and
     `Duplicated` with `InvalidTransitionError`; commit, session close, and lock
     release before the publication attempt; canonical Ticket UUID and root
     task UUID return; no post-commit callback registration; repeated and
     concurrent publication without conflict; `acceptance_unconfirmed` mapping
     to `TicketConvergenceDispatchError` before response transmission; ambiguous
     acknowledgement tolerance; and no Ticket mutation or audit event
13. **Canonical comments and creation order**: manual and every canonical CVE
    source create the exact `ticket_created.comment`; creation keeps
    `ticket_created`, optional assignment, optional manual severity, optional
    Coordinated Release Date, optional CVE association, and optional
    manual-creation `priority_changed` order. Normal status transitions use NULL comments,
    while rejection uses exactly `CVE rejected`
14. **Confidentiality and grants**: direct changes assert exact acting-user
    events and no-op absence; `true` to `false` atomically deletes every grant
    with only `confidentiality_changed`, complete rollback on deletion/audit/
    flush failure, retained maintainer associations, and no manual-grant
    recreation on `false` to `true`. Grant responses distinguish `created` from
    `already_exists`, preserve original provenance, project inactive users, and
    order lists by grant time then target UUID. Declassification leaves
    `coordinated_release_at` unchanged and creates no
    `coordinated_release_changed` event
15. **Locked-current accessibility**: for every consumer mutation above, use
    independent sessions to change confidentiality, the caller's grant, or the
    last included-package maintainership path between preliminary delegated access and
    root-lock acquisition. Verify the locked-current decision wins, denial maps
    to `TICKET_NOT_FOUND`, and denial leaves zero assignment, write, audit,
    reconciliation, or post-commit registration. Cover
    User-then-CVE-then-Ticket association, both ordered duplicate roots,
    manual-zone exits, convergence
    dispatch, confidentiality, the Coordinated Release Date, and grants.
    Separately verify that an authorized
    mutation which itself removes the caller's last visibility path returns its
    normal success response and only later requests are denied
16. **Accessible reads**: grant listing selects through the accessible parent
    in the same database operation or view, returns an ordinary empty list only
    for an accessible Ticket with no grants, and cannot return rows selected
    after visibility is lost
17. **System CVE rejection boundary**: call only with CVE-then-Ticket locks and
    cover `New -> Ignored` with exact system event/comment, every other status as
    a no-op, re-invocation, rejected-orphan creation order, association/lock
    preconditions, runtime association violation, no audit-history query, and
    complete rollback on audit or flush failure
18. **CVE republication composition**: under an already-held CVE-then-Ticket
    lock pair, verify the association and `Ignored` status before invoking the
    existing system `reopen_from_ignored()` form. Assert its Ticket reselect is a
    same-transaction re-lock, the caller's `evaluation_date` is preserved,
    Product and gate convergence use the current ingestion batch's assessment
    state, and an association/status mismatch causes no lifecycle call
19. **Priority composition**: manual creation refreshes the automatic priority
    after every creation event while ingestion creation does not; association
    refreshes it inside the chain after Product events and before the one final
    reconciliation; and `set_priority_override()` satisfies the override tests
    in [ticket-priority.md](ticket-priority.md#testing-requirements)
20. **Coordinated Release Date**: `set_coordinated_release_date()` sets,
    changes, and clears the value with one exact acting-user
    `coordinated_release_changed` event (UTC ISO 8601 old/new values, `NULL`
    for the absent side, `comment` and `detail` `NULL`); an unchanged request,
    including an equal instant supplied with a different offset, is a no-op
    with no event; a non-confidential Ticket, including one declassified with a
    retained CRD, raises `TicketNotConfidentialError` with no effect; the
    operation succeeds in every Ticket status including `Ignored` and
    `Duplicated` without assignment, reconciliation, or status change; past
    instants are accepted; independent-session races with declassification and
    with another CRD change serialize as specified; and audit or flush failure
    rolls back value and event together. Manual creation with a CRD records the
    event after optional `severity_changed` and before optional
    `cve_associated`; creation with a CRD without confidential creation, or
    through the ingestion source, raises `ValueError` before database access

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
- `docs/features/tickets/ticket-priority.md` — priority override and automatic
  refresh contracts
- `docs/features/tickets/ticket-deadlines.md` — due dates, milestones, overdue
  filter, and evaluation instant
- `docs/api-spec.md` — general API conventions, error code categories
