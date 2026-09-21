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
- Roles — `update_roles()` owns manual per-user assignments only
    (`group_name = '_manual'`). External role origins are managed exclusively
    by `sync_role_mapping()` and `delete_role_mapping_roles()`. Manual
    operations never insert, delete, or mutate an external-origin row, while
    external origins still participate in effective-role evaluation (see
    `docs/features/identity/rbac.md`, Role Origins and Coexistence)
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

**Enforcement**: `deactivate_user()`, `get_deactivation_impact()`, and
`reactivate_user()` check
`user.external_id IS NOT NULL AND acting_user_id IS NOT NULL` and raise
`ExternalUserStatusReadOnlyError` when both conditions are true. Since external
sync always passes `acting_user_id = None`, its calls are unaffected.
CLI commands enforce their own manual-surface guard because their
`acting_user_id = None` call is indistinguishable from external
synchronization at this boundary; see
`docs/features/identity/user-management.md` (`manage-user deactivate`).

**Evaluation point differs by function**: the functions check this
condition at different points relative to their idempotency (no-op) check,
and this difference is intentional, not an inconsistency:

- `reactivate_user()` evaluates the guard unconditionally, before the
  already-active check — a human caller reactivating an external user is
  rejected with `ExternalUserStatusReadOnlyError` regardless of the user's
  current `active` value (see `reactivate_user()` below).
- `deactivate_user()` and `get_deactivation_impact()` evaluate the
  already-inactive no-op check first, and the guard only for a
  currently-active user — a human caller deactivating or previewing an
  already-inactive external user gets the same no-op response as for a
  local user (see `deactivate_user()` and `get_deactivation_impact()`
  below). This ordering keeps `deactivate_user()` consistent with
  `GET .../deactivation-impact`
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

Deactivation does not delete or modify `TicketAccessGrant` or
`TicketPackageMaintainer` rows. Those retained visibility relationships are
unusable while the User cannot authenticate and become usable again after
reactivation if they still satisfy their ordinary Ticket-side conditions. A
separate successful Ticket declassification may delete explicit grants while
the User is inactive; reactivation does not recreate them.

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

This function is the ordinary required-result read boundary. Cross-domain
mutations that must make the User an ordered locking root, defer absence until a
protected parent-resource check, or both still use this service's exact UUID-or-
username matching semantics through a user-domain boundary. That lock-aware
boundary may return a matched locked User or an absent result without raising
immediately, as required by the owning mutation contract. Its private helper,
optional parameter, or equivalent result shape is an implementation choice; it
does not create a second identifier-resolution policy or permit another service
to duplicate the matching rules.

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

#### `get_deactivation_impact(session, user_id, acting_user_id)`

Accepts `session: AsyncSession`, `user_id: UUID`, and
`acting_user_id: UUID | None` — the authenticated administrator for API
callers, `None` for CLI and other system callers. This function is the
complete preview boundary for administrator deactivation: the API and CLI
surfaces call it and perform no API-key, Session, Ticket, or UserRole query
of their own.

**Result**: `DeactivationImpact(already_inactive: bool,
is_last_active_admin: bool, api_keys_count: int, sessions_count: int,
tickets_count: int)`.

| Field | Type | Meaning |
|---|---|---|
| `already_inactive` | `bool` | `true` when the target is already inactive; all other fields are then zeroed |
| `is_last_active_admin` | `bool` | `true` when the active target holds an effective Admin role (any origin) and no other active user holds Admin |
| `api_keys_count` | `int` | Non-revoked API keys that deactivation would revoke, including expired keys |
| `sessions_count` | `int` | Active Sessions that deactivation would invalidate |
| `tickets_count` | `int` | Active-status Tickets currently assigned to the target that deactivation would unassign |

**Guard and no-op ordering** — the same target-state ordering used by
`deactivate_user()`:

1. Unknown target — `UserNotFoundError`.
2. Already-inactive target — return
   `DeactivationImpact(already_inactive=true, is_last_active_admin=false,
   api_keys_count=0, sessions_count=0, tickets_count=0)` without evaluating
   the guards below and without accessing the resources counted above. This
   applies equally to local and external targets: an already-inactive
   external user is a successful zero-impact preview, not a rejection.
3. Active external target (`external_id IS NOT NULL`) with a non-NULL
   `acting_user_id` — `ExternalUserStatusReadOnlyError`. With
   `acting_user_id = None` this service guard is inapplicable, mirroring
   `deactivate_user()`: actor-NULL callers are CLI/system surfaces, and the
   CLI applies its own equivalent target guard before prompting (see
   `docs/features/identity/user-management.md`, `manage-user deactivate`,
   and External Active Status Ownership above). External synchronization
   deactivates through `deactivate_user()` under the same actor-NULL
   contract.
4. Active self-target (`acting_user_id = user_id`) — `SelfDeactivationError`.
   `acting_user_id = None` (CLI and other system callers) makes this guard
   inapplicable.
5. Active eligible target — compute the observations.

**Query ownership**: the API-key count is delegated to
`api_key_service.count_non_revoked_keys()`. The Session, Ticket, and
effective-Admin observations belong to this service boundary; no API handler
or CLI command reconstructs them. The preview counts no explicit
`TicketAccessGrant` or `TicketPackageMaintainer` row: deactivation retains
both, so neither is a mutation whose cardinality belongs in the impact
response.

**Advisory consistency**: the four observed values are independent
point-in-time observations produced by this read workflow. They are not
promised to share one PostgreSQL transaction snapshot or to be mutually
atomic, and successive queries may observe concurrent changes. The read
acquires no lock and creates no reservation, preview token, progress state,
or durable record. It does not constrain the later `deactivate_user()`
invocation, which independently revalidates locked-current state and affects
every in-scope resource present when it executes. A preview is therefore
advisory: it reports what a deactivation would affect if it ran at
observation time, not a guarantee of the effects the operator will later
commit.

**Side effects and audit**: none. The preview creates no audit event, no
database mutation, and no Redis operation.

**Re-invocation**: read-only and repeatable. Every invocation returns
observations of the state it observes; nothing is cached or remembered
between invocations.

**Exceptions**: `UserNotFoundError`, `ExternalUserStatusReadOnlyError`, and
`SelfDeactivationError` per the ordering above; database errors and
exceptions propagated by `api_key_service.count_non_revoked_keys()`
propagate unchanged.

This ticket-dependent read belongs only to the deactivation workflow; the
general user query boundary contains identifier resolution, list, and detail
reads.

### Mutation Result Types

- `DeactivationResult` contains the updated `user`, `deactivated: bool`, and
  `invalidated_session_ids: list[UUID]`. `deactivated` is `true` only when
  the invocation performed the effective `active → inactive` transition and
  `false` for an already-inactive or concurrent-loser no-op;
  `invalidated_session_ids` is empty on a no-op and otherwise carries the
  identifiers required for the post-commit cache purge. The flag is a
  service result field only — the HTTP payload returns the current profile
  and does not expose it.
- `PasswordResetResult` contains the updated `user`,
  `invalidated_session_ids: list[UUID]`, and normalized `username` required for
  post-commit session-cache and lockout-counter cleanup.
- `RoleUpdateResult` contains the updated `user` and the effective manual
  changes: `added_roles: list[Role]` and `removed_roles: list[Role]`. Both
  lists describe effective `_manual` `UserRole` insertions and deletions
  from one `update_roles()` invocation — not the difference of aggregated
  effective roles across all origins.
- `UserUpdateResult` contains the updated `user` and `changed_fields`: the
  deterministic sequence of field names effectively changed by one
  `update_user()` invocation relative to the locked-current row. The closed
  value set, in fixed order, is `username`, `email`, `full_name`,
  `manager_id`, `synced_at`. An empty sequence is a no-op: no field was
  persisted and no audit event was created.
- `ReactivationResult` contains the updated `user` and `reactivated: bool`,
  which is `true` only when this invocation performed the
  `inactive → active` transition and `false` when the target was already
  active.

The User returned by a profile-mutating operation — directly by
`create_user()`, or as the result's `user` for `update_user()`,
`reactivate_user()`, `deactivate_user()`, and `update_roles()` — has roles
and manager loaded for API profile serialization. Callers do not execute
follow-up ORM queries to construct the Get User response shape. API and
external synchronization callers serialize the result's `user`; they do not
infer the outcome from a read taken before the mutation.

### Password handling

The `password` and `new_password` parameters accepted by `create_user()`
and `reset_password()` MUST NOT be logged, included in error messages, or
exposed in stack traces. Implementations must treat these fields as opaque
secrets that exist only for the duration of hashing.

### Private Helpers

These are internal functions not exposed to callers. They encapsulate
shared logic used by multiple public operations.

#### `_unassign_active_tickets(db, user, reason) -> None`

This Category A helper accepts `db: AsyncSession`, the target `user: User`, and
`reason: Literal["user deactivated", "vulnerability_analyst role removed",
"vulnerability_analyst role removed by external sync",
"vulnerability_analyst role removed after role mapping deletion"]`. The
reconciliation-only `inactive assignee` reason is not accepted. The caller must
already hold `FOR NO KEY UPDATE` on `user`. The locked User's `id` and username
are the authoritative target and audit snapshot. No role or active-status guard
applies inside this helper. A valid invocation returns `None`.

**Behavior**:

1. Select every Ticket ID whose current `assignee_id` equals `user.id`, without
   filtering by status, order the IDs by Ticket UUID ascending, and acquire
   `FOR UPDATE` in that order. Including all statuses prevents an inactive-
   status candidate from escaping the lock protocol by concurrently returning
   to an active status. An anomalously assigned `New` Ticket is also in scope.
2. For each candidate, revalidate the locked-current assignee and status.
3. If `assignee_id != user.id`, or if status is `Resolved`, `Ignored`, or
   `Duplicated`, preserve the Ticket and create no event. If status is `New`,
   `Analysis`, or `Analyzed` and the assignee still matches, set only
   `assignee_id = NULL`.
4. For each effective clear, create exactly one `TicketAuditEvent` with
   `event_type = assignment`, `user_id = NULL`, `old_value` equal to the locked
   User's username, `new_value = NULL`, exact
   `comment = "Unassigned from {username}: {reason}"`, and `detail = NULL`.
   Events follow ascending Ticket UUID order.
5. Flush the clears and events without changing Ticket status, invoking gate
   reconciliation, assigning a replacement User, committing, or rolling back.

The helper is conditionally idempotent. A repeated or waiting invocation that
observes an already-cleared assignment, a reassigned Ticket, or an inactive
status creates no event. `Resolved`, `Ignored`, and `Duplicated` preserve their
assignee because they do not currently require an eligible active-work owner;
a later return to `Analysis` or `Analyzed` is covered by reconciliation
sanitation. An effective clear leaves `New`, `Analysis`, or `Analyzed`
unchanged and makes the Ticket visible in the unassigned queue.

An invalid internal `reason` raises `ValueError` before any Ticket mutation.
Database, lock-timeout, cancellation, audit-validation/insertion, and flush
exceptions propagate unchanged. Any escaping exception or caller rollback
rolls back every clear and event in the complete caller-owned identity
workflow.

#### `_unassign_tickets_on_va_role_loss(db, user, reason) -> None`

This Category A helper accepts `db: AsyncSession`, a `user: User` already locked
`FOR NO KEY UPDATE` by the caller, and
`reason: Literal["vulnerability_analyst role removed",
"vulnerability_analyst role removed by external sync",
"vulnerability_analyst role removed after role mapping deletion"]`. The caller
invokes it only after applying the intended `UserRole` deletions in the same
transaction. It returns `None` and does not acquire or upgrade the User lock.

1. Query whether any transaction-visible `UserRole` remains for `user.id` and
   `vulnerability_analyst`, across every `group_name` origin.
2. If at least one origin remains, return without changing a Ticket or creating
   an event.
3. If none remains, delegate to `_unassign_active_tickets(db, user, reason)`.

Removing only one of multiple origins is therefore an idempotent no-op for
Ticket state. Re-invocation after effective final loss delegates safely and
finds no active assignment to clear. An invalid reason raises `ValueError`
before Ticket mutation. Database, lock-timeout, cancellation, delegated audit,
and flush exceptions propagate unchanged and roll back the caller-owned role,
Ticket, and audit transaction.

For a multi-User role-origin batch, the orchestrator first locks every affected
User `FOR NO KEY UPDATE` in ascending UUID order, applies and revalidates the
role changes, selects the unfiltered union of Tickets assigned to Users with
effective final loss, and locks that union in ascending Ticket UUID order. It
then applies `_unassign_active_tickets()`'s locked-current status, assignment,
audit, and no-op rules over that union in the same Ticket order. The internal
batch/helper composition is an implementation choice; it may not reacquire
locks in an order that changes this guarantee. It must not alternate one User
and that User's Tickets before locking the next User. Deferred mapping workflows
must also satisfy the activation gate in `identity-provisioning.md` before using
this composition.

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

    A provided field is effectively changed only when its requested value
    differs from the locked-current value. `_MISSING` is never a change, and
    the comparison uses the normalized requested value for `username` and
    `email`. If no provided field differs, this is a no-op: no UPDATE is
    issued, no audit event is created, `changed_fields` is empty, and the
    result's `user` is the locked row loaded in step 1.
7. For each changed field other than `synced_at`, create an
   `IdentityAuditEvent` via `IdentityAuditLog.log_event()`:
   `username_changed`, `email_changed`, `full_name_changed`, or
   `manager_changed` with `old_value` and `new_value`. `synced_at` is
   operational metadata and never produces an audit event (see Operational
   metadata exclusions above). For an external user updated by
   synchronization, email and full name events include
   `detail = {"source": "external_sync"}`; manual local updates use
   `detail = NULL`. One event per changed field, all in the same transaction.
8. Flush and return `UserUpdateResult(user, changed_fields)`. The
   `changed_fields` sequence lists every effective change in the fixed order
   `username`, `email`, `full_name`, `manager_id`, `synced_at`, and `user`
   is the current User with profile, roles, and manager loaded for API
   serialization — updated when fields changed, otherwise the locked row
   from step 1

**Concurrency**: mutations for one user serialize on its row lock. A second
caller evaluates guards, old/new audit values, and `changed_fields`
classification only after the first caller commits or rolls back, so a
waiting caller observes the committed values and its result describes only
its own effective changes. Locks are not acquired on unrelated users.
Normalized email UNIQUE constraints remain authoritative for concurrent
updates of two different users; a loser receives `UserConflictError` and
rolls back its mutation and audit events.

**Re-invocation**: conditionally idempotent. Fields whose normalized requested
value already equals stored state are no-ops and create no audit event; only
effective field changes are persisted and audited, and `changed_fields`
reports exactly those effective changes. A fully no-op re-invocation returns
an empty `changed_fields`.

**TicketAuditEvent**: none

**IdentityAuditEvent**: one per changed field other than `synced_at`
(`username_changed`, `email_changed`, `full_name_changed`,
`manager_changed`). See
`docs/features/identity/identity-audit-log.md` for the event type
contract.

### `update_roles()`

Adds or removes manual (`group_name = '_manual'`) role assignments for a
user. The operation never inserts, deletes, or mutates a row with any other
`group_name`: external role origins are owned by `sync_role_mapping()` and
`delete_role_mapping_roles()` and remain unchanged. External origins still
participate in effective-role evaluation, the self-Admin guard, and final VA
origin loss.

Callers pass role values rather than `(role, group_name)` pairs; the
`_manual` origin is implicit.

**Parameters**:

| Parameter      | Type                        | Required | Description                          |
|----------------|-----------------------------|----------|--------------------------------------|
| `user_id`      | `UUID`                      | Yes      | User whose manual roles change       |
| `add`          | `list[Role] \| None`        | No       | Manual roles to add; default `None`, equivalent to an empty collection |
| `remove`       | `list[Role] \| None`        | No       | Manual roles to remove; default `None`, equivalent to an empty collection |
| `acting_user_id` | `UUID \| None`            | No       | Who is performing the action         |

**Business rules**:

1. **Manual ownership**: every insertion creates a `UserRole` row with
   `group_name = '_manual'` and `assigned_by = acting_user_id`; every
   deletion removes only the matching `_manual` row. A role held through an
   external origin is neither removed nor modified. Adding a manual role
   while an external origin already grants the same role creates a separate
   `_manual` row, and removing that manual row leaves the external origin
   effective (see `docs/features/identity/rbac.md`, Role Origins and
   Coexistence)
2. **Self-removal guard (effective final origin)**: if `acting_user_id` is
   not None AND `acting_user_id == user_id`, the operation is rejected with
   `SelfRoleRemovalError` only when it would effectively delete the acting
   user's `_manual` Admin row and no other Admin origin remains in the
   locked-current origin set. Removing a missing manual Admin row is an
   idempotent no-op and is permitted; deleting the manual Admin row is
   permitted when another Admin origin — a row with a different
   `group_name` — remains. The rejection happens before any `UserRole`
   write, audit event, or Ticket mutation, so it has no partial effect.
   System actions (`acting_user_id = None`, including CLI) are exempt. For
   the implications of this guard on the "zero admins" scenario and the CLI
   recovery procedure, see `docs/features/identity/user-management.md`,
   Business Rule 2
3. **Idempotency**: adding a role whose `_manual` row is already present is
   a no-op; removing a role without a `_manual` row is a no-op. A request
   whose normalized effective change sets are both empty is a no-op
4. **Set semantics within one request**: the caller-supplied lists are
   treated as sets. Entries repeated within one list are deduplicated, and
   roles present in both `add` and `remove` are cancelled before any
   persistent access. The service resolves these permissively for every
   caller and never rejects a request because of duplicate or overlapping
   input. The API layer applies a stricter request validation before calling
   this service (see `docs/features/identity/user-management.md`, Set User
   Roles)

**Behavior**:

1. Resolve inputs in memory, before the first persistent read: treat an
   omitted or `None` `add`/`remove` as an empty collection, treat `add` and
   `remove` as sets of Role values, deduplicate each list, and cancel the
   intersection — `resolved_add = add − remove`,
   `resolved_remove = remove − add`. If both resolved sets are empty, verify
   the User exists and load the profile, manager, and role assignments
   required for serialization, then return
   `RoleUpdateResult(user, [], [])`. No row lock is needed because no state
   is classified or mutated. A missing User raises `UserNotFoundError` and
   creates no audit event
2. As the first persistent access of a non-empty request, acquire
   `FOR NO KEY UPDATE` on the target User by ID. If not found, raise
   `UserNotFoundError`. The lock serializes every manual role mutation for
   one User — not only Admin and `vulnerability_analyst` changes — and keeps
   classification, the self-Admin guard, result lists, and audit events
   deterministic
3. Classify under the lock against the locked-current `UserRole` rows:
   - effective insertions: each role in `resolved_add` without a current
     `_manual` row for the User;
   - effective deletions: each role in `resolved_remove` with a current
     `_manual` row for the User.

   Rows with `group_name != '_manual'` are never candidates for change. They
   are observed only to evaluate effective role membership, effective
   self-Admin status, and final VA-origin loss
4. Apply the self-removal guard against the classified effective deletions
   (Business Rule 2). A rejection raises before any mutation, audit event, or
   Ticket change
5. Insert the effective insertions in ascending role wire-format order,
   each as a `UserRole` row with `group_name = '_manual'` and
   `assigned_by = acting_user_id`
6. Delete the matching `_manual` rows for the effective deletions in
   ascending role wire-format order
7. If `vulnerability_analyst` is among the effective deletions, call
   `_unassign_tickets_on_va_role_loss(db, user,
   "vulnerability_analyst role removed")`.
   **Ordering invariant**: this step MUST execute after step 6's deletion,
   because `_unassign_tickets_on_va_role_loss()` checks for *remaining* VA
   origins — if the deleted row were still visible, the check would always
   find it and never trigger unassignment. A manual deletion whose role
   remains effective through an external origin changes no Ticket
8. Create Identity audit events for every effective `_manual` insertion and
   deletion via `IdentityAuditLog.log_event()`, in this order:
   - one `role_added` per effective insertion, in ascending wire-format
     order: `user_id = acting_user_id`, `target_user_id = user_id`,
     `old_value = NULL`, `new_value` = role, `detail = NULL`;
   - then one `role_removed` per effective deletion, in ascending
     wire-format order: `user_id = acting_user_id`,
     `target_user_id = user_id`, `old_value` = role, `new_value = NULL`,
     `detail = NULL`.

   No event is created for a cancelled input, an already-present `_manual`
   row, a missing `_manual` row, or a concurrent loser that observes the
   requested state
9. Flush every `UserRole` mutation and Identity event.
   `_unassign_tickets_on_va_role_loss()` flushes its own Ticket clears and
   TicketAuditEvents in the same caller-owned transaction
10. Return `RoleUpdateResult(user, added_roles, removed_roles)`:
    - `user` is the updated User with profile, manager, and role assignments
      loaded for API serialization;
    - `added_roles` contains exactly the `_manual` rows inserted by this
      invocation, ordered by wire-format role value;
    - `removed_roles` contains exactly the `_manual` rows deleted by this
      invocation, ordered by wire-format role value.

    Both lists report effective `_manual` row changes, not the difference of
    aggregated effective roles across all origins. A manual addition is
    therefore reported even when the role was already effective through an
    external origin, and a manual removal is reported even when the role
    remains effective through an external origin

**Concurrency**: every non-empty manual mutation acquires the User
`FOR NO KEY UPDATE` before classifying its effect, so concurrent manual role
mutations for one User serialize deterministically:

- duplicate additions: the first transaction inserts one row and one
  `role_added`; the second observes the committed `_manual` row as an
  idempotent no-op and creates no row or event;
- duplicate removals: the first transaction deletes one row and one
  `role_removed`; the second observes a missing `_manual` row and is a no-op;
- a concurrent add and remove of the same role: lock order decides the final
  state, and each transaction classifies its own effective effect from
  locked-current state; a loser that observes the requested state is a no-op;
- requests touching different roles of the same User serialize on the same
  User lock, so both effects and their event order are deterministic;
- the UNIQUE constraint on `(user_id, role, group_name)` remains the
  database integrity backstop; it is not a user-visible no-op path. Every
  documented manual writer locks the User before classifying, so a duplicate
  add whose transaction waits on the lock observes the committed `_manual`
  row and is an idempotent no-op before reaching the INSERT. A violation
  that still reaches the constraint indicates a writer that did not honor
  this contract or a database anomaly; the database error propagates and the
  complete caller-owned transaction rolls back instead of being converted
  into a no-op.

**Re-invocation**: conditionally idempotent. Repeating a successful
invocation observes the already-reached state and returns a
`RoleUpdateResult` with empty `added_roles` and `removed_roles`; it creates
no `UserRole` row, no Identity event, and no Ticket mutation. Re-invoking
after an effective final VA-origin loss delegates safely and finds no active
assignment to clear.

**Exceptions**: `UserNotFoundError` (unknown target User),
`SelfRoleRemovalError` (effective final Admin origin loss), database and
lock-timeout errors, cancellation, `IdentityAuditLog` validation or insertion
failures, and flush failures propagate to the caller unchanged. Database
constraint violations — including a violation of the UNIQUE backstop —
propagate as database errors; the complete caller-owned transaction rolls
back, including `UserRole` rows, Identity events, Ticket clears, and Ticket
events.

**TicketAuditEvent**: if the effective deletions remove the user's final
`vulnerability_analyst` origin — no remaining `UserRole` row for that role
from any `group_name` — one `assignment` event per unassigned active ticket,
with reason `vulnerability_analyst role removed`. Removing one of multiple VA
origins, or a manual row whose role remains effective through an external
origin, creates none. See `_unassign_tickets_on_va_role_loss()` and
`docs/features/tickets/ticket-audit-log.md`.

**IdentityAuditEvent**: one `role_added` per effective `_manual` insertion
and one `role_removed` per effective `_manual` deletion, in the order and
with the fields defined in step 8. See
`docs/features/identity/identity-audit-log.md`.

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
   `to_remove` is non-empty, apply
   `_unassign_tickets_on_va_role_loss()` with reason
   `vulnerability_analyst role removed by external sync` to every User whose
   removal is effective. The complete affected-set stabilization, lock, and
   same-mapping concurrency contract is deferred to
   `identity-provisioning.md`; this function must not be activated until that
   contract guarantees the helper's locked-User precondition for every
   mutated User
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
`(user_id, role, group_name)` prevents duplicate records and remains the
database integrity backstop. Concurrent duplicate additions must resolve to
the same no-op outcome through the affected-set stabilization and locking
that this function's deferred activation contract requires (see
`identity-provisioning.md`) and create no duplicate audit event.

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
4. VA role loss check: if `role` is `vulnerability_analyst`, apply
   `_unassign_tickets_on_va_role_loss()` with reason
   `vulnerability_analyst role removed after role mapping deletion` to every
   User whose removal is effective. The complete affected-set stabilization,
   lock, and CRUD/sync concurrency contract is deferred to
   `identity-provisioning.md`; this function must not be activated until that
   contract guarantees the helper's locked-User precondition for every
   mutated User
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

**Guard and no-op ordering** — the same target-state ordering used by
`get_deactivation_impact()`:

1. Unknown target — `UserNotFoundError`.
2. Already-inactive target — successful no-op: no mutation and no audit
   event. Return
   `DeactivationResult(user, deactivated=false, invalidated_session_ids=[])`
   without evaluating the guards below and without revoking keys,
   invalidating Sessions, or unassigning Tickets. This applies equally to
   local and external targets (see External Active Status Ownership above).
3. Active external target (`external_id IS NOT NULL`) with a non-NULL
   `acting_user_id` — `ExternalUserStatusReadOnlyError`. Active status of
   external users is managed exclusively by external sync.
4. Active self-target with `acting_user_id = user_id` —
   `SelfDeactivationError`.
5. Active eligible target — the side-effect sequence below.

As the first database operation, acquire a `FOR NO KEY UPDATE` lock on the
target User row and revalidate existence, active status, and every guard
against the locked-current row. An API or CLI pre-read is never
authoritative: guards, audit values, and no-op classification all derive
from the locked state. `FOR NO KEY UPDATE` serializes deactivation with API
key creation and bulk revocation while remaining compatible with the
`FOR KEY SHARE` locks those operations trigger during foreign-key
validation (see `api-key-service.md`).

**Side effects — Database phase** (executed atomically in a single
database transaction, in this specific order):

1. Revoke every non-revoked API key belonging to this user, including
   expired keys, via `api_key_service.revoke_all_user_keys(session,
   user_id, acting_user_id=acting_user_id)`. Keys are not deleted — the
   revocation preserves the audit trail and is attributed to the same
   actor (or NULL for CLI/external-sync workflows). The delegated service
   creates exactly one `api_key_revoked` Identity event per effective
   revocation in its documented deterministic order; an already-revoked
   key creates none. See `docs/features/identity/api-key-service.md`.
2. Invalidate all active Sessions for this user (DB only) via
   `session_service.invalidate_user_sessions(db, user_id,
   reason="deactivation")`, which returns the invalidated `session_id`s
   used by the post-commit phase. Session invalidation creates no Identity
   audit event. See `docs/features/identity/authentication.md` (Session
   invalidation).
3. Set `User.active = false`.
4. Unassign active tickets via
   `_unassign_active_tickets(db, user, "user deactivated")`. The
   caller-supplied `reason` is identity-lifecycle context only and is never
   copied into Ticket audit comments. The helper locks candidate Tickets in
   ascending UUID order, clears only locked-current `New`, `Analysis`, and
   `Analyzed` assignments, and creates exactly one `assignment`
   TicketAuditEvent per effective clear. Ticket status is never changed
   (see Architectural Invariant in `tickets.md`). See Private Helpers for
   the full contract; a preserved or already-cleared candidate creates no
   event.
5. Create `user_deactivated` after every delegated mutation above. The
   event uses `user_id = acting_user_id`, `target_user_id = user_id`,
   `old_value = "active"`, and `new_value = "inactive"`. Its `detail`
   always contains the supplied `reason`; it also contains
   `source = "external_sync"` exactly when `acting_user_id` is `None` and
   the target is external (derived, never passed as a parameter — see
   Audit attribution below).
6. Flush every mutation and audit record and return
   `DeactivationResult(user, deactivated=true, invalidated_session_ids)`.
   `user` has roles and manager loaded for API serialization.

The composite insertion order is the API-key revocation events, then the
Ticket `assignment` events, then the single identity `user_deactivated`
event; all of them flush together and commit or roll back with the
mutations. The delegated services own their own event payloads — this
section does not restate them.

The database phase performs no `TicketAccessGrant` or
`TicketPackageMaintainer` mutation. Existing relationships remain persisted;
the inactive User cannot authenticate to exercise them. Deactivation creates
no `access_grant_added` or `access_grant_removed` event and no grant or
maintainer event of any kind. Retained rows remain subject to their ordinary
Ticket-side contracts.

The service does not commit; the workflow owner commits exactly once after
step 6.

**Rollback**: any failure or interruption before the workflow commit —
API-key mutation or audit failure, Session invalidation failure,
`User.active` write failure, Ticket lock/clear/audit failure,
`user_deactivated` insertion failure, lock timeout, database error, or
flush error — rolls back the complete workflow. No partial key revocation,
Session invalidation, assignment clear, or audit event survives a rollback.

**Workflow-owned post-commit phase** (best-effort, after the caller commits and
the pessimistic row lock is released):

7. Purge the session cache via
   `session_service.purge_session_cache(invalidated_session_ids)`. The helper
   attempts every returned `session_id` and owns the Redis-error and
   warning-suppression contract. See
   `docs/features/identity/authentication.md` (Session invalidation).

The API, CLI, external synchronization, or task workflow invokes step 7 from
the returned result. `deactivate_user()` itself performs no Redis I/O, and no
Redis operation executes while the User lock is held. A `RedisError` from the
purge cannot reclassify or roll back the committed deactivation; the API and
CLI still report their committed success. Cache entries not deleted expire
naturally within their existing TTL. The workflow does not persist the
invalidated identifiers, retry the purge in a task, or expose an independent
purge invocation: once the transient result is lost, recovery is exclusively
TTL-based plus the authoritative database check (see
`docs/features/identity/authentication.md`, Session liveness check).

**Ordering rationale**: the order of steps 1-4 is fixed and deterministic:
API keys and Sessions are revoked BEFORE the user is marked inactive
(steps 1-2 before step 3), and Ticket unassignment follows it (step 4).
Under the single-transaction model, all database steps commit atomically — an
interruption before commit rolls back everything, and no caller can observe
an intermediate step. The fixed order makes the composed contract, the
composite audit sequence, and the concurrency tests deterministic. The Redis
cache purge (step 7) is post-commit per `docs/conventions.md` (Transaction
Hygiene Rules) — it cannot be rolled back by a transaction failure and must
not extend the pessimistic row lock hold time.

**Re-invocation**: conditionally idempotent. A repeated invocation after a
successful deactivation observes the committed inactive state and returns a
`deactivated = false` no-op with an empty `invalidated_session_ids`, creating
no mutation and no audit event. A concurrent loser behaves identically.

**Concurrency**:

- **deactivation / deactivation**: both callers serialize on the User lock.
  Exactly one observes the active state, performs the transition, and returns
  `deactivated = true`; the other observes the committed inactive state and
  returns `deactivated = false` with no duplicate side effect or event.
- **deactivation / API-key creation**: both lock the User (`FOR NO KEY
  UPDATE`). If deactivation commits first, key creation observes the inactive
  owner and is rejected with `InactiveUserError`; if creation commits first,
  the new key exists and deactivation revokes it in step 1. Whichever caller
  acquires the lock second observes the first caller's committed state.
- **deactivation / session creation**: successful local and SSO session
  creation revalidates the locked-current active status under the same User
  lock (see `docs/features/identity/authentication.md`, Session creation). If
  session creation commits first, deactivation observes and invalidates the
  new Session in step 2; if deactivation commits first, login observes the
  inactive User and creates no Session.
- **deactivation / manual role mutation**: both serialize on the User lock.
  The first to commit performs any Ticket unassignment; the second finds no
  assigned tickets or an already-inactive User and creates no duplicate
  `assignment` event (see Concurrent role removal and deactivation).
- **deactivation / Ticket assignment**: inherited unchanged from the stable
  assignment-eligibility contract (see Assignment concurrent with
  deactivation or active manual role loss).
- **deactivation / access-grant creation**: inherited unchanged; deactivation
  retains every grant row (see Access grant concurrent with user lifecycle or
  rename).

**IdentityAuditEvent**: `user_deactivated` — `user_id` follows the Actor
Contract, `target_user_id` = deactivated user, and `detail` includes reason and
external source when applicable. API key revocations produce individual
`api_key_revoked` events via `api_key_service`. See
`docs/features/identity/identity-audit-log.md`.

**TicketAuditEvent**: yes — one `assignment` event per effectively
unassigned ticket (see
`docs/features/tickets/ticket-audit-log.md` for the event type contract). No
grant event is created because no grant row is changed.

#### Audit attribution

No invocation-source parameter is added. Attribution derives from the
actor and the locked target:

- actor UUID — authenticated API operation; `user_deactivated.detail`
  carries the `reason` and no `source` key. An active external target is
  rejected before mutation, so this combination cannot describe external
  sync.
- actor `None` and local target — CLI or other system action;
  `user_deactivated.detail` carries the `reason` and no `source` key.
- actor `None` and external target — external synchronization;
  `user_deactivated.detail` carries the `reason` and
  `source = "external_sync"`.

The caller-provided `reason` is lifecycle context, not a source
discriminator. It never changes the derived `source` key.

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
  above did not already reject the call — this is a no-op: no mutation and
  no audit event are created, and the result is
  `ReactivationResult(user, false)`

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
5. Flush and return `ReactivationResult(user, true)`; `user` is the updated
   User with profile, roles, and manager loaded for API serialization

**Concurrency**: concurrent calls serialize on the User row. The first caller
that observes an inactive user creates the mutation and event and returns
`reactivated = true`; later callers observe the committed active state and
return `ReactivationResult(user, false)` as no-ops. Reactivation also
serializes with password reset, field updates, role operations that lock the
same root, and deactivation.

**Re-invocation**: idempotent for local users. Once active, another call
returns `ReactivationResult(user, false)` and creates no audit event. For an
external user, every human-caller invocation raises
`ExternalUserStatusReadOnlyError` regardless of the current `active` value —
there is no no-op path for a human caller on an external user.

**Explicitly NOT restored**:

- Previously unassigned tickets are NOT returned to the user
- Revoked API keys are NOT restored (user must create new ones manually)
- Role assignments are unchanged (roles are not affected by
  deactivation/reactivation)

Retained `TicketAccessGrant` and `TicketPackageMaintainer` rows are not
restored because they were never removed. They become usable through ordinary
authentication and Ticket visibility on later requests. Explicit grants
deleted by a confidentiality `true` to `false` transition while the User was
inactive remain deleted and are not recreated.

**TicketAuditEvent**: none (reactivation is not a ticket mutation and does not
change grants)

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

`update_roles()` always executes within the caller-owned transaction. Every
effective `_manual` `UserRole` insertion or deletion, its Identity event, and
— when the final `vulnerability_analyst` origin is lost — the derived Ticket
unassignment and TicketAuditEvents commit or roll back as one unit. A
validation, insertion, or flush failure in either audit trail rolls back the
complete role and Ticket workflow. `sync_role_mapping()` and
`delete_role_mapping_roles()` keep the same all-or-nothing requirement when
removing the `vulnerability_analyst` role and additionally inherit the
activation gate in `identity-provisioning.md`.

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
concurrently (e.g., external sync and admin API), the guard classification
and write MUST use row-level locking (`SELECT ... FOR NO KEY UPDATE`) to
prevent duplicate side effects. The first caller acquires the lock,
performs the deactivation, and commits with `deactivated = true`. The second
caller acquires the lock, finds `active = false`, and returns
`deactivated = false` as a no-op with an empty
`invalidated_session_ids`, no mutation, and no audit event.

### Role modification during deactivation

`update_roles()` does not check whether the target user is active. Adding
roles to an inactive user is permitted — it has no immediate effect but
prepares the user for reactivation. This is intentional: an admin may
want to adjust a user's roles before reactivating them.

### Concurrent role modification from multiple entry points

Every non-empty `update_roles()` request acquires `FOR NO KEY UPDATE` on the
User before reading or changing `UserRole` rows. The lock covers every manual
role, not only `vulnerability_analyst`, so classification, the self-Admin
guard, result lists, and audit order stay deterministic for concurrent
requests on the same User. Manual mutations never touch a row whose
`group_name != '_manual'`; external origins remain protected by:

1. **Disjoint key spaces** — manual actions use `group_name = '_manual'`
   while external sync uses the actual group name. These never operate on
   the same row
2. **Idempotency** — adding a `_manual` role already present is a no-op;
   removing a `_manual` role not present is a no-op. Two concurrent identical
   operations produce the same final state as one
3. **UNIQUE constraint** `(user_id, role, group_name)` — the database
   integrity backstop, not an expected concurrency path. Every documented
   manual writer locks the User before classifying, so duplicates resolve as
   locked-current no-ops; a violation that still reaches the constraint
   propagates as a database error and rolls back the complete caller-owned
   transaction

The User lock is additionally authoritative for effective VA eligibility and
for effective Admin status in active manual role mutation. It serializes
manual origin changes with assignment and deactivation, so final VA-origin
loss and the self-Admin guard are evaluated from the locked-current origin
set. Deferred external-origin mutations are governed by the activation gate
in `identity-provisioning.md`.

### Concurrent role removal and deactivation

If `update_roles()` removes the VA role and `deactivate_user()` runs
concurrently for the same user, both may attempt ticket unassignment.
Conflicting pessimistic row locks on the User row in both operations serialize
them (both use `FOR NO KEY UPDATE`). The first to commit performs the
unassignment; the second finds
no assigned tickets (or finds the user already inactive) and is a no-op. No
duplicate TicketAuditEvents are created.

Independent-session tests for active manual role mutation and deactivation
cover the User-then-ascending-Ticket lock order,
locked-current predicate revalidation, and one system `assignment` event per
effective unassignment. They assert the exact four identity-owned reason values,
`detail = NULL`, no event for an already-cleared or no-longer-active candidate,
and complete rollback of identity and Ticket changes after an audit failure.

### Session creation concurrent with deactivation

Successful local and SSO Session creation revalidates the locked-current
`User.active` value under the same `FOR NO KEY UPDATE` User root lock before
creating the Session and updating `last_login_at` (see
`docs/features/identity/authentication.md`, Session creation). Deactivation
uses the conflicting `FOR NO KEY UPDATE` lock, so the two operations have one
serialization point:

- if Session creation commits first, the new Session exists and a later
  deactivation invalidates it together with every other active Session;
- if deactivation commits first, the login workflow observes the committed
  inactive User under the lock, creates no Session, and returns its
  provider-specific authentication failure (`AUTH_INVALID_CREDENTIALS` for
  local login, `AUTH_SSO_USER_INACTIVE` for SSO — see the provider specs).

No Session can commit for an inactive User, and password hashing or external
IdP/network I/O never executes while the User lock is held.

### Assignment concurrent with deactivation or active manual role loss

Every assignment-capable path acquires `FOR SHARE` on its prospective assignee
User before any CVE or Ticket root and validates eligibility from that locked
state. Deactivation and active manual VA role-origin mutation use conflicting
`FOR NO KEY UPDATE` on the same User. The outcomes are therefore stable:

- if assignment obtains the User lock first, the lifecycle transaction waits;
  after assignment commits, it observes and clears that assignment when the
  Ticket is in `New`, `Analysis`, or `Analyzed`;
- if deactivation or effective final VA-role loss obtains the User lock first,
  assignment waits and then observes the committed ineligible User. Explicit
  assignment raises its existing inactive or non-VA exception. Manual creation,
  auto-assignment, and embedded/forced assignment skip assignment and continue
  with their ordinary non-assignment behavior; and
- rejected, skipped, stale, losing, repeated, and rolled-back outcomes create no
  assignment event.

No committed active-status Ticket can retain an assignee made ineligible by one
of these serialized lifecycle changes. Reconciliation sanitation remains a
defensive current-state invariant check for Tickets that return from an inactive
status or for anomalous data; it is not the primary repair for this race. No
periodic task, recovery state, or audit-derived repair is introduced.

### Access grant concurrent with user lifecycle or rename

Access-grant creation and revocation use the global User-then-Ticket root order
defined in `docs/conventions.md`. `ticket-service.md` owns their deferred-error
and target-resolution refinements. They lock the target User before the Ticket, so
deactivation, reactivation, and username changes for that target cannot
interleave with target activity validation, grant classification, or the event
username snapshot.

For grant creation, if deactivation commits first, a missing grant is rejected
with `USER_INACTIVE`; an already-existing grant remains an idempotent result and
is retained. If creation commits first, it creates one grant and one
`access_grant_added`, and later deactivation retains that row. If reactivation
commits first, an absent grant may be created; if the grant operation observes
the inactive User first, it is rejected and later reactivation does not alter
that completed result. Rename/grant and rename/revoke outcomes use either the
committed old username or committed new username consistently according to
lock order, never a mixed identity snapshot.

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
| `SelfRoleRemovalError` | 409 | `USER_SELF_ROLE_REMOVAL` | Effective removal of the acting user's final Admin origin (manual or mapping-derived) |
| `SelfDeactivationError` | 409 | `USER_SELF_DEACTIVATION` | Admin attempting to deactivate themselves |
| `ExternalUserStatusReadOnlyError` | 409 | `USER_EXTERNAL_STATUS_READONLY` | Cannot manually activate/deactivate an external user |
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
