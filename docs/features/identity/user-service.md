# User Lifecycle Service

## Purpose

Centralize all user lifecycle operations (creation, modification,
deactivation, reactivation, role management) in a single service module
to ensure consistent enforcement of business rules and side effects
regardless of the entry point (API, CLI, external sync, or future
integrations).

Without this centralization, each entry point would need to independently
implement side effects (ticket unassignment, API key revocation,
TicketAuditEvent creation) and business rules (self-removal guard,
self-deactivation guard), leading to inconsistency and bugs.

This module also owns user lookups and list/detail queries needed by API
consumers. Keeping these reads at the existing user-domain service boundary
preserves thin API handlers without introducing a separate query abstraction.
Read functions do not create audit events. A CLI command may reuse these
functions; no entry point may mutate `User` or `UserRole` directly.

## Architecture

### Module location

`backend/app/services/user_service.py`

### Async pattern

The service is implemented as async functions. The API (FastAPI) is the
primary consumer and calls the service directly with `await`. A synchronous
CLI or Celery entry point wraps its complete async workflow — session
acquisition, service composition, transaction completion, and post-commit
effects — in exactly one `asyncio.run()` call.

| Entry point | Invocation pattern |
|---|---|
| API endpoint | Await services inside the API transaction dependency |
| Celery task (sync) | `asyncio.run(complete_task_workflow(...))` |
| CLI command | `asyncio.run(complete_cli_workflow(...))` |

### Transaction Ownership

Every function that accepts an `AsyncSession` follows
`docs/conventions.md` (Caller-Owned Service Transactions): it flushes when
required and never commits or rolls back. The API transaction dependency or
complete CLI/task workflow commits exactly once after all delegated database
mutations succeed and rolls back when an exception escapes. A read-only or
Redis-only workflow such as `unlock_user()` performs no empty database commit.

Functions that invalidate sessions return the identifiers and other values
needed for Redis cleanup. The workflow owner performs that cleanup only after
its database commit succeeds. Audit records use the same session and therefore
commit or roll back atomically with the lifecycle mutation.

### Acting user convention

All operations accept an `acting_user_id: UUID | None` parameter:

- `UUID` — action performed by an authenticated user. Enables
  self-operation guards (self-deactivation, self-role-removal)
- `None` — system action (external sync, CLI, fetcher). Self-operation
  guards do not apply

This distinction allows the service to enforce invariants for interactive
users while preserving the ability of system processes to perform any
operation.

**API handler rule**: API endpoint handlers MUST always pass the UUID of
the authenticated user (obtained via `Depends()`) as `acting_user_id`.
Passing `None` from an API handler is a bug — it would silently bypass
all self-operation guards. `None` is reserved exclusively for system
entry points (external sync, Celery tasks, CLI commands).

## External User Data Ownership

For external users (`external_id IS NOT NULL`), all identity fields
(`username`, `email`, `full_name`, `manager_id`,
`synced_at`) are managed exclusively by the external sync process. No
human caller — whether via API or CLI — may modify these fields. The only
legitimate consumer of `update_user()` for external users is the sync process
itself (`acting_user_id = None`).

Fields managed by dedicated operations have their own ownership rules:

- `active` — managed by `deactivate_user()` / `reactivate_user()`. For
  external users, this field is managed exclusively by external sync — manual
  deactivation/reactivation by admins is blocked (see External Active Status
  Ownership below)
- Roles — managed by `update_roles()` for per-user assignment,
    `sync_role_mapping()` and `delete_role_mapping_roles()` for
    external group mapping operations. Available to admins for manual roles
    (`group_name = '_manual'`)
- `password_hash` — managed by `reset_password()`, which independently
  blocks external users via `ExternalUserPasswordError`

Conversely, for local users (`external_id IS NULL`), the
external-provider-specific fields (`manager_id`, `synced_at`) are not
applicable and must not be set — they have no source of truth outside of
the external identity provider.

### External Active Status Ownership

For external users, the external identity provider is the sole source of
truth for the `active` field. Manual deactivation or reactivation by
admins (via API, CLI, or UI) is not permitted — these operations are
reserved for the external sync process.

**Rationale**: if an admin could manually deactivate an external user, the
next sync cycle would reactivate them (because the provider still reports
the user as active). This creates a confusing loop where
irreversible side effects (API key revocation, session invalidation,
ticket unassignment) are triggered by the deactivation but never restored
by the automatic reactivation. Blocking manual deactivation eliminates
this inconsistency entirely.

**Enforcement**: `deactivate_user()` and `reactivate_user()` check
`user.external_id IS NOT NULL AND acting_user_id IS NOT NULL` and raise
`ExternalUserStatusReadOnlyError` when both conditions are true. Since external
sync always passes `acting_user_id = None`, its calls are unaffected.
CLI commands add an additional pre-call guard for defense in depth
(CLI also uses `acting_user_id = None`).

**Evaluation point differs by function**: the two functions check this
condition at different points relative to their idempotency (no-op) check,
and this difference is intentional, not an inconsistency:

- `reactivate_user()` evaluates the guard unconditionally, before the
  already-active check — a human caller reactivating an external user is
  rejected with `ExternalUserStatusReadOnlyError` regardless of the user's
  current `active` value (see `reactivate_user()` below).
- `deactivate_user()` evaluates the already-inactive no-op check first, and
  the guard only for a currently-active user — a human caller deactivating
  an already-inactive external user gets the same no-op response as for a
  local user (see `deactivate_user()` below). This ordering keeps
  `deactivate_user()` consistent with `GET .../deactivation-impact`
  (`docs/features/identity/user-management.md`), whose preview must not be
  stricter than the action it previews: both must treat an already-inactive
  external user as a no-op, not a rejection.

**If an external user must be blocked from Sentinel**: deactivate the
user at the external identity provider. The next external sync cycle will propagate
the change to Sentinel with all associated side effects.

### Immutability Constraints

Once set, `external_id` cannot be modified by any operation in this
service. This field is the stable identity anchor that links a Sentinel user
to an external provider object. All external sync operations match by
`external_id` — if it were changed, the user would lose its external
association and historical audit trail.

## Inactive User Management Principle

### Operational metadata exclusions

Three high-frequency operational fields are narrow exceptions to lifecycle
mutation ownership and identity audit events:

| Field | Exclusive write boundary |
|---|---|
| `User.last_login_at` | Authentication session-creation workflow |
| `ApiKey.last_used_at` | `api_key_service.update_last_used_at()` |
| `User.synced_at` | External provisioning synchronization workflow through `update_user()` |

These boundaries may update only the named metadata field without a lifecycle
audit event. They do not authorize direct modification of any other user or
API-key field. See `identity-audit-log.md` (Operational Metadata Exclusions).

### Deactivation and management

Deactivation blocks login and revokes active sessions/keys, but does not
prevent administrative modifications to the account. All management
operations (`update_user`, `reset_password`, `update_roles`) remain
available on inactive users via both CLI and API. This allows admins to
prepare accounts before reactivation (e.g., assign appropriate roles, set
a new password).

## User Deletion

User deletion is not supported. Deactivation is the terminal state of the
user lifecycle. This is intentional: User records are referenced by
`TicketAuditEvent` (audit trail), `Ticket` (historical assignments), `ApiKey`
(revocation records), `Session`, `UserRole`, and `User` itself
(`manager_id`, self-referencing). Deleting a user would orphan these
records or require complex chain/anonymization logic.

If a future requirement arises (e.g., GDPR right-to-erasure), it will be
addressed as a separate feature with its own specification covering data
anonymization, orphan handling, and audit trail preservation.

## Operations

Every database function below accepts `session: AsyncSession` as its first
parameter even where the parameter tables focus on domain inputs.

Unless a function states otherwise, read functions propagate database errors
and create no audit events. Mutating functions propagate the service
exceptions below plus database/flush errors, participate in the caller-owned
transaction, and create no effect on a rejected invocation. An idempotent
no-op creates no audit event.

### Read Operations

#### `resolve_user_identifier(session, identifier)`

Accepts `session: AsyncSession` and `identifier: str`. If `identifier` parses
as a UUID, look up `User.id`; otherwise look up the exact stored username.
Return the matching User row without loading response-specific relationships.
Raise `UserNotFoundError` when no row matches. Profile-shaped functions load
their own relationships explicitly. The function is read-only and
deterministic for a fixed database snapshot.

#### `list_users(session, filters, pagination, sorting)`

Accepts the typed filters, pagination values, and sorting selection defined by
`user-management.md` (List Users). Return `UserPage(items: list[User], total:
int)` with deterministic secondary ordering by `User.id`. When sorting by
`full_name`, rows with `NULL` sort last per `api-spec.md` (Nullable Sort
Field Ordering). The function applies every documented filter and loads
the role and manager data required by the response; API handlers perform
no ORM query or filtering themselves.

#### `get_user(session, identifier)`

Resolves the UUID or username through `resolve_user_identifier()` and returns
the complete profile data defined by `user-management.md` (Get User), including
roles and manager. Unknown users raise `UserNotFoundError`.

#### `get_user_roles(session, user_id)`

Accepts `session: AsyncSession` and `user_id: UUID`. Return the distinct
set of `Role` values held by the user across all origins (direct + group
mappings). Unknown or role-less `user_id` yields an empty list (does not
raise `UserNotFoundError`). Ordering is not guaranteed by the service —
response formatters apply the deterministic ordering rule from `rbac.md`
(Deterministic ordering).

#### `get_deactivation_impact(session, user_id)`

Accepts `session: AsyncSession` and `user_id: UUID`. Return
`DeactivationImpact(sessions_count: int, tickets_count: int,
is_last_active_admin: bool)` using one database snapshot. Counts include active
sessions and active-status tickets currently assigned to the user. The admin
flag is true only when the target is active, holds an effective Admin role, and
no other active user holds Admin. Unknown users raise `UserNotFoundError`.
This read is a point-in-time preview, creates no audit event, and acquires no
mutation lock; deactivation re-evaluates actual state when it runs. API-key
counting remains owned by `api_key_service.count_non_revoked_keys()`.
This ticket-dependent read belongs only to the deactivation workflow; the
general user query boundary contains identifier resolution, list, and detail
reads.

### Mutation Result Types

- `DeactivationResult` contains the updated `user` and
  `invalidated_session_ids: list[UUID]` required for the post-commit cache
  purge.
- `PasswordResetResult` contains the updated `user`,
  `invalidated_session_ids: list[UUID]`, and normalized `username` required for
  post-commit session-cache and lockout-counter cleanup.

When `create_user()`, `update_user()`, `update_roles()`, `reactivate_user()`,
or `deactivate_user()` returns a User for API profile serialization, the
returned object has roles and manager loaded. Callers do not execute follow-up
ORM queries to construct the Get User response shape.

### Password handling

The `password` and `new_password` parameters accepted by `create_user()`
and `reset_password()` MUST NOT be logged, included in error messages, or
exposed in stack traces. Implementations must treat these fields as opaque
secrets that exist only for the duration of hashing.

### Private Helpers

These are internal functions not exposed to callers. They encapsulate
shared logic used by multiple public operations.

#### `_unassign_active_tickets(db, user_id, reason)`

Performs bulk Ticket unassignment for a user. `reason` is one of the exact
closed values `user deactivated`, `vulnerability_analyst role removed`,
`vulnerability_analyst role removed by external sync`, or
`vulnerability_analyst role removed after role mapping deletion`. The separate
reconciliation sanitation value `inactive assignee` is not passed to this
identity-owned helper. No guard on roles or active status applies here.
The caller has already locked the User root; this helper therefore preserves
the global `User` then ordered `Ticket` lock order.

**Behavior**:

1. Query candidate Ticket IDs where `assignee_id = user_id` and status is active
   (New, Analysis, or Analyzed — see
   `docs/features/tickets/tickets.md` § Status Categories), ordered by Ticket
   UUID ascending. `New` tickets should never have an assignee under the current
   invariant (see Architectural Invariant in `tickets.md`). They remain in the
   defensive query scope so an assignment-path bug is corrected with the
   regular unassignment batch.
2. For each candidate (iterated individually, not as a bulk update): acquire
   `SELECT ... FOR UPDATE` on the Ticket row, then revalidate locked-current
   `assignee_id = user_id` and active status. A row that no longer matches is a
   no-op. This preserves the User-then-Ticket lock order and prevents stale
   audit values or duplicate events.
3. Set `assignee_id = NULL` only after successful revalidation.
4. Create a `TicketAuditEvent` with `event_type = assignment`:
   - `user_id = NULL` (system action)
   - `old_value` = user's username
   - `new_value` = `NULL`
   - `comment` = `"Unassigned from {username}: {reason}"`
   - `detail = NULL`

Events follow the same ascending Ticket UUID order. A waiting or repeated call
that observes no matching assignment creates no event. Audit validation,
insertion, flush, or database failure escapes and rolls back the complete
caller-owned identity workflow.

Unassignment does **not** change ticket status — the ticket remains in
its current gate-zone status (Analysis or Analyzed) and is visible in
the unassigned ticket queue (`?assignee=none`). See the Architectural
Invariant in `tickets.md`.

Tickets in inactive statuses (Resolved, Ignored, Duplicated) are not
touched — they no longer need an active assignee. Ticket
history preserves the previous assignment via the TicketAuditEvent record.
No attempt is made to reassign to the manager or any other user.

#### `_unassign_tickets_on_va_role_loss(db, user_id, reason)`

Conditionally unassigns tickets when a user may have lost the
`vulnerability_analyst` role entirely. Serializes concurrent checks via
row-level locking.

**Behavior**:

1. Acquire a row-level lock on the User record:
   `SELECT ... FROM user WHERE id = user_id FOR UPDATE`. This serializes
   concurrent VA role loss checks for the same user (see Concurrency
   Considerations)
2. Query: does at least one `UserRole` record exist with
   `user_id = user_id` and `role = vulnerability_analyst` (any
   `group_name`)?
3. If yes → no-op, return. The user still holds the VA role from at
   least one origin
4. If no → call `_unassign_active_tickets(db, user_id, reason)`

**Design rationale**: the guard in step 2 ensures that removing one
source of the VA role (e.g., manual) does not trigger unassignment when
another source (e.g., externally-derived) still exists. The `FOR UPDATE` lock
in step 1 prevents a race condition where two concurrent transactions
(each removing one VA role source) both see the other source as still
present and skip unassignment — leaving the user with no VA role but
tickets still assigned.

**Lock contention**: when called from `sync_role_mapping()` or
`delete_role_mapping_roles()` for multiple users within a single
transaction, each call acquires a separate `FOR UPDATE` lock on its
target user. All locks are held until the transaction commits. If a lock
cannot be acquired (blocked by a concurrent transaction on the same
user), the calling transaction waits. If PostgreSQL's `lock_timeout` or
`statement_timeout` fires, the resulting exception propagates to the
caller and rolls back the entire transaction — this is the intended
behavior (atomicity). Callers operating on bounded user sets (role
mappings are expected to have <100 members) accept this cost.
Large-scale operations (external sync) process each mapping independently
via per-service-call transactions, limiting the blast radius.

### `create_user()`

Creates a new User record with optional initial roles.

**Parameters**:

| Parameter        | Type                        | Required | Description                          |
|------------------|-----------------------------|----------|--------------------------------------|
| `username`       | `str`                       | Yes      | Unique username                      |
| `email`          | `str`                       | Yes      | Unique email address                 |
| `full_name`      | `str \| None`               | No       | Display name                         |
| `active`         | `bool`                      | No       | Default: `True`                      |
| `external_id` | `UUID \| None`            | No       | External provider stable UUID (immutable). NULL for local users |
| `manager_id`     | `UUID \| None`              | No       | FK to user.id of the direct line manager |
| `password`       | `str \| None`               | No       | Plain-text password (hashed before storage). Required for local users, must be NULL for external users |
| `roles`          | `list[tuple[Role, str]]`    | No       | List of (role, group_name) pairs    |
| `acting_user_id` | `UUID \| None`              | No       | Who is performing the action         |

**Behavior**:

1. Normalize `username` (trim whitespace, lowercase) and validate format
   per `docs/conventions.md` (Username Format). If invalid, raise
   `UsernameFormatError`
2. Normalize `email` by trimming leading and trailing whitespace and converting
   the entire string — local part and domain alike — to lowercase (see
   `docs/data-model.md`, `User.email`: stored as lowercase). Validate the
   format of this fully-lowercased value with the `email-validator` library
   (`validate_email(value, check_deliverability=False)` — the deliverability
   check is disabled so validation never performs a DNS lookup or other
   network I/O). If the format is invalid, raise `EmailFormatError` before
   any other step executes. All uniqueness checks and persisted values use
   this fully-lowercased value — not `email-validator`'s own `.normalized`
   result, which lowercases only the domain and preserves local-part case
   per RFC convention; `email-validator` is used here for format validation
   only

   **Defense in depth, not a single guarantee**: API request schemas and CLI
   commands also validate email format at the boundary, using the same
   `email-validator` library, as an earlier and better-UX check (see
   `docs/features/identity/user-management.md`). That boundary check does
   not replace the guarantee above: `create_user()` is also the entry point
   for external provisioning, which has no Pydantic or Click boundary in
   front of it — the service itself is the only validation point every
   caller is guaranteed to cross.

3. Validate password/`external_id` mutual exclusivity: if
   `external_id` is provided and `password` is also provided, raise
   `ExternalUserPasswordError`. If `external_id` is NULL and `password` is not
   provided, raise `PasswordValidationError`
4. If `external_id` is NULL and `manager_id` is provided (not `None`), raise
   `ExternalUserFieldReadOnlyError`. `manager_id` is external-provider-specific
   and has no source of truth for local users (see External User Data
   Ownership above); this mirrors the same guard `update_user()` applies to
   an existing local user
5. Validate uniqueness of `username` and normalized `email` across all users
   (including inactive). If `external_id` is provided, also validate
   its uniqueness — if already associated with another user, raise
   `UserConflictError`. If violated, raise `UserConflictError`
6. If `password` is provided, validate length per the password policy in
   `docs/features/identity/local-authentication.md` § Password Validation
   (16–128 characters). If invalid, raise `PasswordValidationError`
7. If `password` is provided, hash it with bcrypt (see
   `docs/features/identity/local-authentication.md` for hashing parameters)
8. Create User record with provided fields,
   `password_hash` set to the hash (or NULL if no password), and
   `synced_at = now()` if `external_id` is set
9. For each role in `roles`, create UserRole with specified `group_name`
   and `assigned_by = acting_user_id`. If the list contains duplicate
   entries (same role + same `group_name`), deduplicate silently — only
   one UserRole record is created per unique `(role, group_name)` pair.
   This is consistent with the idempotency behavior of `update_roles()`.
   For each UserRole created, also create an `IdentityAuditEvent` with
   `event_type = role_added` via `IdentityAuditLog.log_event()` —
   `user_id` = `acting_user_id`, `target_user_id` = created user,
   `new_value` = role name. For `_manual` roles, `detail = NULL`. For an
   externally-derived role, `detail = {"source": "external_sync",
   "mapping": group_name}`; both keys are required. This preserves the
   external source and role-mapping decision for every initial assignment.
10. Create `user_created` via `IdentityAuditLog.log_event()`. A local API or
    CLI creation uses `detail = NULL`; external synchronization uses
    `detail = {"source": "external_sync"}`
11. Flush the user, roles, and all audit events, then return the created User

**Concurrency**: no root row exists to lock. Pre-checks provide useful errors,
but the database UNIQUE constraints on normalized username, normalized email,
and external ID are authoritative. If concurrent creations race, one may
succeed; each loser translates the constraint violation to `UserConflictError`.
The loser's caller rolls back, so it persists no user, role, or audit event.

**Re-invocation**: not idempotent. Repeating a successful creation with the
same normalized username or email raises `UserConflictError` and creates no
additional records.

**TicketAuditEvent**: none (user creation does not affect tickets)

**IdentityAuditEvent**: `user_created` — `user_id` = acting API user or NULL
for CLI/external synchronization,
`target_user_id` = created user, `new_value` = username. Additionally,
   one `role_added` event per initial role assigned (see step 8). All events
created via `IdentityAuditLog.log_event()` in the same transaction.

### `update_user()`

Updates mutable user identity fields. This operation does NOT cover role
changes or active status changes — those have dedicated operations with
their own business rules.

**Parameters**:

| Parameter        | Type                        | Required | Description                          |
|------------------|-----------------------------|----------|--------------------------------------|
| `user_id`        | `UUID`                      | Yes      | User to update                       |
| `acting_user_id` | `UUID \| None`              | No       | Who is performing the action         |
| `username`       | `str \| None`               | No       | New username (updated by external sync when username changes at provider) |
| `email`          | `str \| _Missing`             | No       | New non-null email (normalized; uniqueness validated) |
| `full_name`      | `str \| None \| _Missing`     | No       | New display name; NULL clears it     |
| `manager_id`     | `UUID \| None \| _Missing`    | No       | New manager (FK to user.id); NULL clears it |
| `synced_at`      | `datetime \| None \| _Missing` | No       | Operational sync timestamp           |

**Behavior**:

1. Acquire a `FOR UPDATE` lock on the User row by ID. If not found, raise
   `UserNotFoundError`. The locked row is the authoritative source for guards,
   old audit values, and no-op detection
2. If `user.external_id IS NOT NULL` and `acting_user_id` is not None:
   raise `ExternalUserFieldReadOnlyError`. Identity fields of external users are
   managed exclusively by external sync (see External User Data Ownership
   above). The entire `update_user()` operation is blocked for human
   callers on external users — there is no identity field that an admin
   should modify manually.
3. If `user.external_id IS NULL` and `manager_id` or
   `synced_at` is provided (not `_MISSING`): raise
   `ExternalUserFieldReadOnlyError`. These fields are external-provider-specific and have
   no source of truth for local users.
4. **Username validation** (if `username` is provided): normalize and
   validate the format per the rules in `docs/conventions.md` (section
   "Username Format"). If invalid, raise `UsernameFormatError`. Verify
   uniqueness in the database (excluding the current user, including
   inactive users). If violated, raise `UserConflictError`. For external
   users, this step is reached only by the sync process (human callers
   are already blocked at step 2). External synchronization adds
   `detail = {"source": "external_sync"}` to `username_changed`; a future
   authenticated/manual caller uses `detail = NULL`
5. If `email` is provided, reject `None`; normalize it the same way as
   `create_user()` (trim whitespace, lowercase the entire string, validate
   format with `email-validator` — `check_deliverability=False` — raising
   `EmailFormatError` on invalid format, and using the fully-lowercased
   value rather than `email-validator`'s own `.normalized` result). Then
   validate uniqueness using the normalized value, excluding the current
   user and including inactive users. If violated, raise `UserConflictError`
6. Apply provided field updates. Optional parameters use a `_MISSING`
   sentinel as default to distinguish three states:
   - `_MISSING` (default): field is not modified
    - `None`: a nullable field is explicitly cleared to NULL in the database
   - Any other value: field is updated to the new value

    `email` is non-nullable and therefore does not permit this state. This is
    necessary because nullable fields (`full_name`,
    `manager_id`) may need to be explicitly cleared — e.g.,
   when external sync discovers that a provider attribute has been removed. The
   pattern follows Python's standard sentinel convention
   (`dataclasses.MISSING`).

    If all optional parameters are `_MISSING`, this is a no-op: no UPDATE
   is issued. The User record returned is the one loaded in step 1.
7. For each changed field, create an `IdentityAuditEvent` via
   `IdentityAuditLog.log_event()`: `username_changed`, `email_changed`,
   `full_name_changed`, or `manager_changed` with `old_value` and
   `new_value`. For an external user updated by synchronization, email and full
   name events include `detail = {"source": "external_sync"}`; manual local
   updates use `detail = NULL`. One event per changed field, all in the same
   transaction.
8. Return updated User

**Concurrency**: mutations for one user serialize on its row lock. A second
caller evaluates guards and old/new audit values only after the first caller
commits or rolls back. Locks are not acquired on unrelated users. Normalized
email UNIQUE constraints remain authoritative for concurrent updates of two
different users; a loser receives `UserConflictError` and rolls back its
mutation and audit events.

**Re-invocation**: conditionally idempotent. Fields whose normalized requested
value already equals stored state are no-ops and create no audit event; only
effective field changes are persisted and audited.

**TicketAuditEvent**: none

**IdentityAuditEvent**: one per changed field (`username_changed`,
`email_changed`, `full_name_changed`, `manager_changed`). See
`docs/features/identity/identity-audit-log.md` for the event type
contract.

### `update_roles()`

Adds or removes roles for a user.

**Parameters**:

| Parameter      | Type                        | Required | Description                          |
|----------------|-----------------------------|----------|--------------------------------------|
| `user_id`      | `UUID`                      | Yes      | User to update                       |
| `add`          | `list[tuple[Role, str]]`    | No       | Roles to add as (role, group_name)  |
| `remove`       | `list[tuple[Role, str]]`    | No       | Roles to remove as (role, group_name) |
| `acting_user_id` | `UUID \| None`            | No       | Who is performing the action         |

**Business rules**:

1. **Self-removal guard**: if `acting_user_id` is not None AND
   `acting_user_id == user_id` AND `Admin` is in the effective `remove`
   list (after input resolution), reject the operation with
   `SelfRoleRemovalError`. This prevents any authenticated user from
   removing their own Admin role, regardless of the entry point. System
   actions (`acting_user_id = None`) are exempt.
   For the implications of this guard on the "zero admins" scenario and
   the CLI recovery procedure, see `docs/features/identity/user-management.md`,
   Business Rule 2
2. **Externally-derived role protection**: when `acting_user_id` is set (user
   action), cannot remove roles with `group_name != '_manual'`. Raise
   `ExternalDerivedRoleError`. System actions are exempt (external sync must be
   able to remove externally-derived roles when group membership changes)
3. **Idempotency**: adding a role already present for the same
   (user_id, role, group_name) combination is a no-op. Removing a role
   not present is a no-op

A concurrent duplicate addition that reaches the UNIQUE constraint is treated
as the same idempotent no-op rather than an operation failure. No duplicate
role or audit event is created.

**Behavior**:

1. Look up user by ID. If not found, raise `UserNotFoundError`
2. Resolve inputs (set-based): deduplicate entries within each list
   (treat as sets — each unique `(role, group_name)` tuple appears at
   most once). Then cancel entries that appear in both lists:
   `effective_add = add − remove`, `effective_remove = remove − add`.
   If both effective lists are empty after resolution, this is a no-op:
   return the user unchanged
3. Validate business rules (self-removal guard, externally-derived protection)
   against the resolved effective lists
4. For each entry in `effective_add`, create UserRole if not already
   present, with `assigned_by = acting_user_id`
5. For each entry in `effective_remove`, delete matching UserRole record
6. VA role loss check: if `vulnerability_analyst` appears in
   `effective_remove`, call
   `_unassign_tickets_on_va_role_loss(db, user_id,
   "vulnerability_analyst role removed")`.
   **Ordering invariant**: this step MUST execute after step 5's
   deletion, because `_unassign_tickets_on_va_role_loss()` checks for
   *remaining* VA roles — if the role being removed has not yet been
   deleted, the check would always find it and never trigger
   unassignment
7. For each role added, create `IdentityAuditEvent` with `event_type =
   role_added`; for each role removed, `event_type = role_removed`. All
   events created via `IdentityAuditLog.log_event()` in the same
   transaction.
8. Return updated User with current roles

**TicketAuditEvent**: if removing the `vulnerability_analyst` role causes
the user to lose it entirely (no remaining `UserRole` records for that
role from any origin), one `assignment` event per unassigned active
ticket. See `_unassign_tickets_on_va_role_loss()`. Otherwise, none.

**IdentityAuditEvent**: `role_added` / `role_removed` per effective
change. See `docs/features/identity/identity-audit-log.md`.

### `sync_role_mapping()`

Synchronizes `UserRole` records for a specific role mapping against the
current set of group members. Creates missing records for users in
the group and removes records for users no longer in the group.

This function centralizes all bulk role operations triggered by external
group membership. It is called by the external sync process and by the
Create Role Mapping endpoint when a new mapping is created (see
`identity-provisioning.md`). During the local-only phase, this function
has no callers.

**Parameters**:

| Parameter                 | Type            | Required | Description                          |
|---------------------------|-----------------|----------|--------------------------------------|
| `role`                    | `Role`          | Yes      | The role to sync                     |
| `group_name`             | `str`           | Yes      | The external group name that tags these roles |
| `current_member_user_ids` | `set[UUID]`     | Yes      | User IDs currently in the group   |
| `acting_user_id`          | `UUID \| None`  | No       | Who is performing the action         |

**Behavior**:

1. Query all existing `UserRole` records where `role` and `group_name`
   match the provided values. Collect their `user_id` values as
   `existing_user_ids`
2. Compute:
   - `to_add = current_member_user_ids - existing_user_ids`
   - `to_remove = existing_user_ids - current_member_user_ids`
3. **Self-admin guard**: if `acting_user_id` is not None, `role` is
   `Admin`, and `acting_user_id` is in `to_remove`: check whether the
   acting user has any other `UserRole` granting `Admin` (from a
   different `group_name` or from `_manual`). If not, reject with
   `SelfRoleRemovalError`
4. For each user in `to_add`, create `UserRole(user_id, role,
   group_name)` with `assigned_by = NULL` (externally-derived roles are
   system-assigned regardless of the initiator)
5. Delete all `UserRole` records where `user_id` is in `to_remove`,
   `role` matches, and `group_name` matches
6. VA role loss check: if `role` is `vulnerability_analyst` and
   `to_remove` is non-empty, call
   `_unassign_tickets_on_va_role_loss(db, user_id,
   "vulnerability_analyst role removed by external sync")` for each user in
   `to_remove`, processed in ascending User UUID order. A consistent order
   avoids deadlocks between concurrent bulk role operations
7. For each user in `to_add`, create `IdentityAuditEvent` with
   `event_type = role_added`; for each user in `to_remove`, create
   `role_removed`. Each event uses `user_id = acting_user_id`, identifies the
   affected user, and stores the role in `new_value` (add) or `old_value`
   (remove). Because these roles derive from an external mapping, every event
   includes `detail = {"source": "external_sync", "mapping": group_name}`
   whether the mapping was applied by external synchronization or an
   authenticated administrator. All events use
   `IdentityAuditLog.log_event()`.
8. Return `(added_count, removed_count)`

**Idempotency**: calling this function twice with the same
`current_member_user_ids` produces the same result — the second call
finds nothing to add or remove. The UNIQUE constraint on
`(user_id, role, group_name)` prevents duplicate records.
Concurrent duplicate additions have the same no-op outcome and create no
duplicate audit event.

**TicketAuditEvent**: if `role` is `vulnerability_analyst` and removing
it causes any user to lose the role entirely (no remaining `UserRole`
records from any origin), one `assignment` event per unassigned active
ticket per affected user. See `_unassign_tickets_on_va_role_loss()`.
Otherwise, none.

**IdentityAuditEvent**: `role_added` / `role_removed` per effective change,
with `user_id = acting_user_id` and mapping detail. See
`docs/features/identity/identity-audit-log.md`.

### `delete_role_mapping_roles()`

Removes all `UserRole` records associated with a specific role mapping.
Used when a role mapping is deleted via
`DELETE /api/v1/admin/role-mappings/{id}`.

**Parameters**:

| Parameter        | Type            | Required | Description                          |
|------------------|-----------------|----------|--------------------------------------|
| `role`           | `Role`          | Yes      | The role to remove                   |
| `group_name`    | `str`           | Yes      | The external group name that tags these roles |
| `acting_user_id` | `UUID \| None`  | No       | Who is performing the action         |

**Behavior**:

1. Query all `UserRole` records where `role` and `group_name` match.
   Collect their `user_id` values as `affected_user_ids`
2. **Self-admin guard**: if `acting_user_id` is not None, `role` is
   `Admin`, and `acting_user_id` is in `affected_user_ids`: check
   whether the acting user has any other `UserRole` granting `Admin`
   (from a different `group_name` or from `_manual`). If not, reject
   the entire operation with `SelfRoleRemovalError`: "Cannot delete
   this role mapping because it is the sole source of your admin role.
   Assign admin via another mapping or manually before retrying."
   No `UserRole` records are removed — the operation is atomic
3. Delete all matching `UserRole` records
4. VA role loss check: if `role` is `vulnerability_analyst`, call
   `_unassign_tickets_on_va_role_loss(db, user_id,
   "vulnerability_analyst role removed after role mapping deletion")` for each user
   in `affected_user_ids`, processed in ascending User UUID order. A consistent
   order avoids deadlocks between concurrent bulk role operations
5. For each removed `UserRole`, create `IdentityAuditEvent` with
   `event_type = role_removed`, `user_id = acting_user_id`,
   `target_user_id` = affected user, `old_value` = role name, and
   `detail = {"source": "external_sync", "mapping": group_name}` via
   `IdentityAuditLog.log_event()`
6. Return `affected_users_count`

**TicketAuditEvent**: if `role` is `vulnerability_analyst` and removing
it causes any user to lose the role entirely (no remaining `UserRole`
records from any origin), one `assignment` event per unassigned active
ticket per affected user. See `_unassign_tickets_on_va_role_loss()`.
Otherwise, none.

**IdentityAuditEvent**: `role_removed` per affected user. See
`docs/features/identity/identity-audit-log.md`.

### `deactivate_user()`

Deactivates a user account and triggers all associated side effects.

**Parameters**:

| Parameter      | Type                        | Required | Description                          |
|----------------|-----------------------------|----------|--------------------------------------|
| `user_id`      | `UUID`                      | Yes      | User to deactivate                   |
| `acting_user_id` | `UUID \| None`            | No       | Who is performing the action         |
| `reason`       | `str`                       | Yes      | Identity-lifecycle context stored in `user_deactivated.detail`; not copied into Ticket audit comments |

**Preconditions**:

- User must be currently active. If already inactive, this is a no-op
  (returns the user unchanged)
- **External status guard**: if `user.external_id IS NOT NULL` AND
  `acting_user_id IS NOT NULL`, reject with
  `ExternalUserStatusReadOnlyError`. Active status of external users is managed
  exclusively by external sync (see External Active Status Ownership above)
- **Self-deactivation guard**: if `acting_user_id` is not None AND
  `acting_user_id == user_id`, reject with `SelfDeactivationError`

As the first database operation, acquire a `FOR NO KEY UPDATE` lock on the
target User row. If no row exists, raise `UserNotFoundError`. First check
whether the user is already inactive; if so, return
`DeactivationResult(user, [])` without any mutation or audit event.
Only an active user is then evaluated against the external-status and
self-deactivation guards, in that order. `FOR NO KEY UPDATE` serializes
deactivation with API key creation and bulk revocation while remaining
compatible with the `FOR KEY SHARE` locks those operations trigger during
foreign-key validation (see `api-key-service.md`).

**Side effects — Database phase** (executed atomically in a single
database transaction, in this specific order):

1. Revoke all API keys belonging to this user via
   `api_key_service.revoke_all_user_keys(session, user_id,
   acting_user_id=acting_user_id)`. Keys are not deleted — preserves audit
   trail and attributes every revocation to the same API actor, or NULL for
   CLI/external-sync workflows.
   See `docs/features/identity/api-key-service.md`.
2. Invalidate all active sessions for this user (DB only) via
   `session_service.invalidate_user_sessions(db, user_id,
   reason="deactivation")`. This sets
   `Session.is_active = false` in the database and returns the list of
   invalidated `session_id`s (used by the post-commit phase). See
   `docs/features/identity/authentication.md` (Session invalidation) for the
   session service contract.
3. Set `User.active = false`
4. Unassign active tickets: call
   `_unassign_active_tickets(db, user_id, "user deactivated")`. The caller's
   `reason` remains identity-lifecycle context only. This clears `assignee_id` on all
   active tickets and creates `TicketAuditEvent` records — all within the
   same transaction. Ticket status is
   not changed (see Architectural Invariant in `tickets.md`). See
   Private Helpers for the full contract.

After the database steps, create `user_deactivated`, flush every mutation and
audit record, and return. The event uses `user_id = acting_user_id`,
`target_user_id = user_id`, `old_value = "active"`, and
`new_value = "inactive"`. Its `detail` always contains the supplied `reason`;
external synchronization also includes `source = "external_sync"`
before returning
`DeactivationResult(user, invalidated_session_ids)`. The service does not
commit.

**Workflow-owned post-commit phase** (best-effort, after the caller commits and
the pessimistic row lock is released):

5. Purge session cache via
   `session_service.purge_session_cache(invalidated_session_ids)`. The helper
   owns the Redis-error and warning-suppression contract. The database is the
   authoritative source for session validity; auth middleware verifies
   against the database on cache miss. See
   `docs/features/identity/authentication.md` (Session invalidation).

The API, CLI, external synchronization, or task workflow invokes step 5 from
the returned result. `deactivate_user()` itself performs no Redis I/O.

**Ordering rationale**: API keys and sessions are revoked BEFORE the
user is marked as inactive (steps 1-2 before step 3). Under the
single-transaction model, all database steps commit atomically — an
interruption before commit rolls back everything. The ordering is
significant for retry safety: if the transaction succeeds but the
process crashes before the post-commit phase, the admin can verify that
the user is already inactive and re-invoke the cache purge
independently. The Redis cache purge (step 5) is post-commit per
`docs/conventions.md` (Transaction Hygiene Rules) — it cannot be rolled
back by a transaction failure and must not extend the pessimistic row lock
hold time.

**IdentityAuditEvent**: `user_deactivated` — `user_id` follows the Actor
Contract, `target_user_id` = deactivated user, and `detail` includes reason and
external source when applicable. API key revocations produce individual
`api_key_revoked` events via `api_key_service`. See
`docs/features/identity/identity-audit-log.md`.

**TicketAuditEvent**: yes — one `assignment` event per unassigned ticket (see
`docs/features/tickets/ticket-audit-log.md` for the event type contract)

### `reactivate_user()`

Reactivates a previously deactivated user account.

**Parameters**:

| Parameter      | Type                        | Required | Description                          |
|----------------|-----------------------------|----------|--------------------------------------|
| `user_id`      | `UUID`                      | Yes      | User to reactivate                   |
| `acting_user_id` | `UUID \| None`            | No       | Who is performing the action         |

**Preconditions**:

- **External status guard**: if `user.external_id IS NOT NULL` AND
  `acting_user_id IS NOT NULL`, reject with
  `ExternalUserStatusReadOnlyError`, regardless of the user's current
  `active` value. Active status of external users is managed exclusively
  by external sync (see External Active Status Ownership above); a human
  caller can never reactivate an external user, not even as a no-op. This
  guard is evaluated first, before the idempotency check below, so it is
  never bypassed by an already-active external user
- User must be currently inactive. If already active — and the guard
  above did not already reject the call — this is a no-op (returns the
  user unchanged)

**Behavior**:

1. Acquire a `FOR UPDATE` lock on the User row by ID. If it does not exist,
   raise `UserNotFoundError`
2. Evaluate the preconditions against the locked row, in the order listed
   above: the external-status guard first (unconditional on `active` for a
   human caller), then the already-active no-op check
3. Set `User.active = true`
4. Create `IdentityAuditEvent` with `event_type = user_reactivated`
   via `IdentityAuditLog.log_event()`. External synchronization uses
   `detail = {"source": "external_sync"}`; authenticated API and manual CLI
   calls use `detail = NULL`
5. Flush and return the updated User

**Concurrency**: concurrent calls serialize on the User row. The first caller
that observes an inactive user creates the mutation and event; later callers
observe the committed active state and return as no-ops. Reactivation also
serializes with password reset, field updates, role operations that lock the
same root, and deactivation.

**Re-invocation**: idempotent for local users. Once active, another call
returns the unchanged user and creates no audit event. For an external
user, every human-caller invocation raises `ExternalUserStatusReadOnlyError`
regardless of the current `active` value — there is no no-op path for a
human caller on an external user.

**Explicitly NOT restored**:

- Previously unassigned tickets are NOT returned to the user
- Revoked API keys are NOT restored (user must create new ones manually)
- Role assignments are unchanged (roles are not affected by
  deactivation/reactivation)

**TicketAuditEvent**: none (reactivation is not a ticket mutation)

**IdentityAuditEvent**: `user_reactivated`. See
`docs/features/identity/identity-audit-log.md`.

### `reset_password()`

Resets the password for a local user and invalidates all active sessions.

**Parameters**:

| Parameter       | Type             | Required | Description                          |
|-----------------|------------------|----------|--------------------------------------|
| `user_id`       | `UUID`           | Yes      | User whose password is being reset   |
| `new_password`  | `str`            | Yes      | New plain-text password (validated and hashed internally) |
| `acting_user_id`| `UUID \| None`   | No       | Who is performing the action (admin or system) |

**Preconditions**:

- User must exist. If not found, raise `UserNotFoundError`
- User must be a local user (`external_id IS NULL`). If
  `external_id` is set, raise `ExternalUserPasswordError`: "Cannot set
  password for external user. External users authenticate via SSO."

**Behavior — Database phase** (single transaction):

1. Validate password length (16–128 characters). If invalid, raise
   `PasswordValidationError`
2. Hash the password with bcrypt (see
   `docs/features/identity/local-authentication.md` for hashing parameters).
   Validation and hashing use only the input and occur before acquiring a row
   lock
3. As the first database operation, acquire a `FOR UPDATE` lock on the target
   User. If missing, raise `UserNotFoundError`; if external, raise
   `ExternalUserPasswordError`
4. Update `User.password_hash` with the new hash
5. Invalidate all active sessions (DB only) via
   `session_service.invalidate_user_sessions(db, user_id,
   reason="password_reset")` — returns
   `invalidated_session_ids`. This forces re-login with the new
   password.
6. Create `IdentityAuditEvent` with `event_type = password_reset` via
   `IdentityAuditLog.log_event()` — `user_id` = `acting_user_id`
   (authenticated API user or NULL for CLI/system), `target_user_id` = target
   user. Created in the same
   transaction as the password hash update.
7. Flush and return `PasswordResetResult(user, invalidated_session_ids,
   username)`. `username` is the stored normalized username needed for
   post-commit lockout cleanup

**Workflow-owned post-commit phase** (best-effort, after the caller commits):

8. Purge session cache via
   `session_service.purge_session_cache(invalidated_session_ids)`. The helper
   owns the Redis-error and warning-suppression contract.
9. Clear the login lockout counter: delete the Redis key
   `login_attempts:{username}` if it exists. If Redis is unreachable,
   log WARNING and proceed — the counter will expire naturally via TTL.
   This ensures that a locked-out user regains access immediately after
    a password reset (or within the TTL window if Redis is unavailable).

`reset_password()` performs only the database phase and returns the data for
steps 8-9; it does not commit or execute Redis I/O. The API, CLI, or task
workflow owns the commit and invokes both post-commit effects.

**Concurrency**: resets for one user serialize on the User row. Each successful
caller writes the hash computed for that invocation and creates one audit
event; the last committed reset determines the accepted password. Concurrent
deactivation cannot interleave its database mutations with a reset because it
uses the same root lock. No bcrypt work or Redis I/O occurs while the lock is
held.

**Re-invocation**: not idempotent. Each successful invocation hashes and stores
the supplied password anew, invalidates sessions present at that invocation,
and creates one `password_reset` event.

**TicketAuditEvent**: none (password reset does not affect tickets)

**IdentityAuditEvent**: `password_reset` — `user_id` = authenticated API actor
or NULL for CLI/system, `target_user_id` = target user. See
`docs/features/identity/identity-audit-log.md` for the event type
contract.

### `unlock_user(session, user_id, acting_user_id)`

Clears the login lockout counter for a user, restoring their ability to
attempt local authentication.

**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `session` | `AsyncSession` | Caller-supplied session used for the user lookup |
| `user_id` | `UUID` | Target user to unlock |
| `acting_user_id` | `UUID \| None` | Who is performing the action (admin or system) |

**Behavior:**

1. Load user by `user_id`. If not found, raise `UserNotFoundError`.
2. Delete the Redis key `login_attempts:{username}` (where `username`
   is the user's current username). If Redis is unreachable, log WARNING
   and proceed — the counter will expire naturally via TTL.
3. Log an INFO message with `user_id` (UUID) — no username or other
   personal identifiers (per `docs/features/platform/logging.md`).

**Idempotency:** if the user is not currently locked out (Redis key
does not exist or counter is zero), the operation completes successfully
with no error. This is a no-op, not a failure.

**Exceptions:**

| Exception | Condition |
|-----------|-----------|
| `UserNotFoundError` | `user_id` does not match any user |

**Notes:**
- No `TicketAuditEvent` is created (not a ticket operation).
- No `IdentityAuditEvent` is created. Lockout is a transient
  Redis-only state, not a persistent identity mutation. Application
  logging (INFO level) provides sufficient operational visibility.
- No session invalidation (unlocking does not indicate compromise).
- The password reset workflow continues to clear the lockout counter as a
  post-commit side effect (step 9), but `unlock_user()`
  provides an independent path that does not force a password change.
- `acting_user_id` is accepted for lifecycle-call signature uniformity and has
  no persisted effect because unlock creates no audit event.
- The user lookup is read-only and acquires no row lock. Redis executes only
  after that query; there is no database mutation or commit to coordinate.

## Transactionality

All database operations follow the caller-owned contract in
`docs/conventions.md`. Service functions flush when required and never commit
or roll back. The API dependency or complete CLI/task workflow commits once
after every database mutation and audit event succeeds; an exception rolls the
whole workflow back. Read-only and Redis-only workflows do not issue an empty
commit. This ensures that a user is never left in a partially mutated state.

Redis operations returned by database-mutating functions such as
`deactivate_user()` and `reset_password()` (session cache purge and login
lockout counter deletion) are NOT part of the PostgreSQL transaction boundary.
The workflow owner executes them post-commit using values returned by the
service, and they are best-effort: if the process crashes between commit
and Redis cleanup, or if Redis is unreachable, the affected cache
entries expire naturally via TTL. The database is always the
authoritative source — Redis is a performance optimization, not a
correctness requirement.

This two-phase pattern (see `docs/conventions.md`, Transaction Hygiene
Rules) ensures that:

1. A user is never left in a partially-deactivated database state
2. The pessimistic row lock is held for the minimum necessary duration
   (database operations only)
3. Redis failures or latency cannot extend lock hold time or block
   concurrent mutations on the same entity

Operations that conditionally produce side effects (`update_roles`,
`sync_role_mapping`, `delete_role_mapping_roles`) MUST also execute within
a single database transaction when removing the `vulnerability_analyst`
role, ensuring atomicity between role removal, ticket unassignment, and
TicketAuditEvent creation. When no VA role is being removed, these
operations perform a single logical write and atomicity is less critical.

`create_user`, `update_user`, and `reactivate_user` use the same contract:
their identity audit events are mandatory side effects and therefore must be
atomic with their lifecycle writes.

For deactivation, the caller-provided identity reason and the canonical Ticket
unassignment reason are deliberately independent. Every required identity and
Ticket event is flushed in the same transaction; failure of either audit trail
rolls back user lifecycle, roles, API keys, sessions, Ticket assignments, and
all events in that workflow.

## Concurrency Considerations

### Concurrent deactivation from multiple entry points

If two entry points call `deactivate_user()` for the same user
concurrently (e.g., external sync and admin API), the `active` precondition
check and write MUST use row-level locking (`SELECT ... FOR NO KEY UPDATE`) to
prevent duplicate side effects. The first caller acquires the lock,
performs the deactivation, and commits. The second caller acquires the
lock, finds `active = false`, and returns as a no-op.

### Role modification during deactivation

`update_roles()` does not check whether the target user is active. Adding
roles to an inactive user is permitted — it has no immediate effect but
prepares the user for reactivation. This is intentional: an admin may
want to adjust a user's roles before reactivating them.

### Concurrent role modification from multiple entry points

`update_roles()` does not require row-level locking for the role
INSERT/DELETE operations themselves. Each role is an independent tuple
`(user_id, role, group_name)` managed via atomic INSERT/DELETE
operations. Concurrency safety for role records is guaranteed by:

1. **UNIQUE constraint** `(user_id, role, group_name)` — prevents
   duplicate records regardless of timing
2. **Disjoint key spaces** — manual actions use `group_name = '_manual'`
   while external sync uses the actual group name. These never operate on
   the same row
3. **Idempotency** — adding a role already present is a no-op; removing
   a role not present is a no-op. Two concurrent identical operations
   produce the same final state as one

**Exception — VA role removal**: when `vulnerability_analyst` is being
removed, `_unassign_tickets_on_va_role_loss()` introduces a
read-modify-write pattern (check remaining VA roles → conditionally
unassign tickets). This is serialized by a `SELECT ... FOR UPDATE` lock
on the `User` row inside the helper. Without this lock, two concurrent
transactions removing the last two VA role sources (e.g., admin removing
manual role + external sync removing externally-derived role) could each see the
other source as still present and skip unassignment, leaving the user
with no VA role but tickets still assigned.

### Concurrent role removal and deactivation

If `update_roles()` removes the VA role and `deactivate_user()` runs
concurrently for the same user, both may attempt ticket unassignment.
Conflicting pessimistic row locks on the User row in both operations serialize
them (`FOR UPDATE` in the role helper conflicts with `FOR NO KEY UPDATE` in
deactivation). The first to commit performs the unassignment; the second finds
no assigned tickets (or finds the user already inactive) and is a no-op. No
duplicate TicketAuditEvents are created.

Independent-session tests cover the User-then-ascending-Ticket lock order,
locked-current predicate revalidation, and one system `assignment` event per
effective unassignment. They assert the exact four identity-owned reason values,
`detail = NULL`, no event for an already-cleared or no-longer-active candidate,
and complete rollback of identity and Ticket changes after an audit failure.

### Assignment concurrent with deactivation or role loss

Ticket assignment locks the Ticket root while deactivation and VA-role loss
lock the User root before scanning assigned tickets. An assignment that
validated the user before deactivation and commits only after the unassignment
scan may therefore leave an inactive or non-VA user assigned to an active
ticket. This bounded residual race is accepted until the ticket and identity
locking contracts are reconciled together; changing either lock order
in isolation could introduce a User↔Ticket deadlock. Operators repair the state
through ordinary ticket reassignment. No periodic reconciliation mechanism is
introduced solely for this race.

### Redis operations and lock scope

Redis cache cleanup (session liveness purge, login lockout counter
deletion) executes after the transaction commits and the pessimistic row
lock is released. This ensures that Redis latency or unreachability
cannot extend the lock hold time or block concurrent mutations. See
`docs/conventions.md` (Transaction Hygiene Rules) for the general rule
and `docs/features/identity/authentication.md` (Session invalidation)
for the two-phase session service contract.

## Service Exceptions

All exceptions in this module inherit from `UserServiceError`.
API endpoint handlers catch `UserServiceError` subclasses and map them
to the corresponding HTTP status code and error code per `api-spec.md`.

| Exception | HTTP | Code | Raised when |
|-----------|------|------|-------------|
| `UserNotFoundError` † | 404 | `USER_NOT_FOUND` | User identifier does not resolve to any user |
| `UserConflictError` | 409 | `USER_ALREADY_EXISTS` | Username, email, or external ID already in use |
| `SelfRoleRemovalError` | 409 | `USER_SELF_ROLE_REMOVAL` | Admin attempting to remove their own admin role |
| `SelfDeactivationError` | 409 | `USER_SELF_DEACTIVATION` | Admin attempting to deactivate themselves |
| `ExternalUserStatusReadOnlyError` | 409 | `USER_EXTERNAL_STATUS_READONLY` | Cannot manually activate/deactivate an external user |
| `ExternalDerivedRoleError` | 409 | `USER_EXTERNAL_ROLE_PROTECTED` | Cannot manually modify externally-derived roles |
| `ExternalUserFieldReadOnlyError` | 409 | `USER_EXTERNAL_FIELD_READONLY` | Cannot modify synced fields on an external user |
| `ExternalUserPasswordError` | 409 | `USER_EXTERNAL_PASSWORD_FORBIDDEN` | Cannot set password for an external user |
| `PasswordValidationError` † | 422 | `USER_PASSWORD_POLICY_VIOLATION` | Password does not meet policy requirements |

† Shared exception — inherits from `ServiceError`, not from
`UserServiceError`. Handlers must catch it explicitly. `PasswordValidationError`
is defined in `app/core/passwords.py` (Core layer, imported by
`user_service` and any other module that validates a candidate password) —
see `docs/conventions.md` (Service Exception Conventions, Shared
exceptions).

`UserConflictError` carries a `conflict_field` attribute
(`"username"`, `"email"`, or `"external_id"`) identifying which uniqueness
constraint was violated. The attribute never carries the conflicting value
itself — only the field name — so a caller can produce a more specific
message (e.g., distinguishing a duplicate username from a duplicate email in
`create_user()`, per `docs/features/identity/user-management.md`) without
re-deriving which constraint fired and without exposing the submitted
value, which would otherwise enable username or email enumeration through
the response.

### System-internal exceptions

| Exception | Raised when | Handling |
|-----------|-------------|----------|
| `UsernameFormatError` | Username does not match format rules | CLI: stderr message + exit 1; External sync: logged as warning, user skipped |
| `EmailFormatError` | Email does not pass `email-validator` format validation | CLI: stderr message + exit 1; External sync: logged as warning, user skipped |

These are not listed in the API-facing table above because the API request
schemas for `create_user()`/`update_user()` callers (Pydantic) already reject
a malformed username or email with the global 422 `VALIDATION_ERROR`
response before the service is reached — see
`docs/features/identity/user-management.md`. `UsernameFormatError` and
`EmailFormatError` are reachable in practice only through CLI and external
synchronization, which have no such boundary in front of the service.

## Relationship to Other Specifications

| Spec | Relationship |
|---|---|
| `docs/features/identity/api-key-service.md` | Centralized API key database service. `deactivate_user` calls `api_key_service.revoke_all_user_keys()` as step 1 of the deactivation side effects |
| `docs/features/identity/api-key-management.md` | API key lifecycle and retention contract |
| `docs/features/identity/authentication.md` | Defines the session model and `session_service`. `deactivate_user` calls `session_service.invalidate_user_sessions()`. `reset_password` calls the same. |
| `docs/features/identity/identity-provisioning.md` | External sync process calls `create_user`, `update_user`, `sync_role_mapping`, `deactivate_user`, `reactivate_user`. Role mapping CRUD endpoints call `sync_role_mapping` and `delete_role_mapping_roles` |
| `docs/features/identity/rbac.md` | Admin API endpoints delegate to `update_roles`, `deactivate_user`, `reactivate_user` |
| `docs/features/identity/user-management.md` | CLI commands delegate to `create_user`, `update_user`, `update_roles`, `deactivate_user`, `reactivate_user` |
| `docs/features/identity/local-authentication.md` | Defines password management. `create_user` accepts an optional password. CLI `set-password` and admin endpoint delegate to `reset_password` |
| `docs/features/tickets/ticket-audit-log.md` | `deactivate_user` creates TicketAuditEvents per the `assignment` event type contract |
| `docs/features/identity/identity-audit-log.md` | All identity mutations create IdentityAuditEvents per the event type contract |
| `docs/features/platform/audit-trail-infrastructure.md` | BaseAuditLog, AuditEventMixin, naming conventions |
| `docs/data-model.md` | User and UserRole table definitions |
