# API Key Service

## Purpose

Centralize every API key database operation in one async service module:
creation, single and bulk revocation, listing, retrieval, ownership checks,
and the operational `last_used_at` touch. API, CLI, authentication, and user
lifecycle callers remain thin and perform no direct API key queries or
writes.

The management behavior exposed to consumers is authoritative in
`docs/features/identity/api-key-management.md`; this specification owns the
service contract that realizes it.

## Architecture

### Module Location and Invocation

The module is `backend/app/services/api_key_service.py`. Every public
function is async and receives an `AsyncSession`. API and other services
await functions directly. A synchronous CLI command wraps its complete async
workflow in exactly one `asyncio.run()` call as defined by
`docs/features/platform/cli-infrastructure.md`.

### Actor and Owner Restrictions

`create_key()` is self-service and derives both actor and owner from its
required `user_id`; it accepts no separate actor. Revocation functions accept
`acting_user_id: UUID | None`:

- a UUID identifies the authenticated self-service or administrator actor;
- `None` identifies a CLI or automated system action.

Where supported, `owner_user_id: UUID | None` is an ownership restriction,
not an actor. A UUID requires the key to belong to that user. `None` permits
the caller to address any key and is used only by administrator, CLI, and
system workflows whose authorization is established outside this service.

### Transaction Ownership

The caller owns the transaction. Service functions flush when required so
constraints, generated identifiers, returned state, and audit events are
available before return. They never commit. Any exception leaves commit or
rollback to the caller. Therefore an API key mutation and its
`IdentityAuditEvent` either commit together or roll back together.

The service translates a normalized-name uniqueness violation into
`ApiKeyNameConflictError` while preserving a transaction state the caller can
roll back normally. The implementation may choose any SQLAlchemy/PostgreSQL
mechanism that provides that observable contract; it must not commit or
silently discard unrelated caller work.

### Status and Query Defaults

All functions use the status derivation in `api-key-management.md`:
`revoked`, otherwise `expired`, otherwise `active`. A function that evaluates
status captures one UTC `now` value for the invocation unless the caller
provides one explicitly for deterministic composition or testing.

Read functions create no audit events. Unless stated otherwise, they
propagate database exceptions and the service exceptions documented below.

## Result Types

Every `ApiKey` returned for API serialization includes the nullable revoker
`User` record needed to render `revoked_by` as the standard User Reference
Object in `api-spec.md`. A NULL `revoked_by` foreign key has no revoker record.

`ApiKeyPage` contains:

| Field | Type | Meaning |
|---|---|---|
| `items` | `list[ApiKey]` | Page rows in requested order |
| `total` | `int` | Matching rows before pagination |
| `page` | `int` | Requested page |
| `per_page` | `int` | Requested page size |

`ApiKeyWithOwner` contains an `ApiKey` plus the owner `User` record needed to
render the standard `owner` User Reference Object.
`ApiKeyWithOwnerPage` has the same pagination fields as `ApiKeyPage`, with
`items: list[ApiKeyWithOwner]`.

`ApiKeyCliList` contains `items: list[ApiKey]` and
`evaluated_at: datetime`. The CLI uses `evaluated_at` as the single status
snapshot for every displayed row.

Pagination and sort arguments reaching this module have already passed API
schema validation. The service still handles every documented enum value and
does not silently substitute a different filter or sort.

## Operations

### `create_key()`

```python
async def create_key(
    session: AsyncSession,
    user_id: UUID,
    name: str,
    expires_at: datetime | None,
) -> CreatedApiKey
```

`CreatedApiKey` contains the persisted `ApiKey` and the plaintext key as a
separate transient string. The plaintext is never assigned to a model field.

**Guards:**

- Missing owner: `UserNotFoundError`.
- Inactive owner: `InactiveUserError`.
- Name violating the API Key Name Rule: `ApiKeyNameValidationError`.
- Existing non-revoked key with the same normalized name:
  `ApiKeyNameConflictError`.
- `expires_at <= now`: `ApiKeyInvalidExpiryError`.

**Behavior:**

1. Lock the owner `User` row with `SELECT ... FOR NO KEY UPDATE` as the
   first database operation. Validate existence and active status under that
   lock. This serializes creation with user deactivation and bulk revocation:
   whichever operation acquires the user lock second observes the first
   operation's committed state. A key cannot commit for an inactive user.
   `FOR NO KEY UPDATE` is sufficient because these operations never modify
   `User.id`; it remains compatible with the `FOR KEY SHARE` locks PostgreSQL
   acquires when validating foreign keys that reference `User.id`.
2. Trim and lowercase `name`, then validate length and `[a-z0-9._-]` format
   exactly as specified by the API Key Name Rule.
3. Validate `expires_at` against the operation's UTC `now` snapshot. There is
   no maximum expiration.
4. Check for a non-revoked key with the normalized name. This provides an
   early semantic error but is not the concurrency guarantee.
5. Generate `stl_ak_` plus 32 cryptographically random alphanumeric
   characters, compute its lowercase hexadecimal SHA-256 digest, and create
   the row with the normalized name, first 12 characters as `prefix`, and
   the requested expiration.
6. Flush the insert. The partial unique index is the authoritative
   database-level integrity backstop: it protects the invariant against
   direct SQL, future code paths that bypass the owner lock, or a missed
   pre-check. Under the owner lock, the pre-check in step 4 provides the
   normal conflict result for conforming service calls — two conforming
   `create_key()` invocations cannot concurrently reach the insert. Any
   violation is translated to `ApiKeyNameConflictError`.
7. Count keys for this owner whose derived status is `active`, using the same
   `now` snapshot. If the count exceeds 20, emit the safe anomaly WARNING
   defined in `api-key-management.md`.
8. Create and flush one `api_key_created` event through
   `IdentityAuditLog.log_event()`: actor = owner, target = owner,
   `new_value` = normalized name, `detail = {"key_id": "<uuid>"}`.
9. Return the row and plaintext key.

**Re-invocation:** not idempotent in general: a different available name
creates another key. Re-invocation while the same normalized name remains
non-revoked raises `ApiKeyNameConflictError`. Concurrent same-name calls
serialize on the owner lock; the loser observes the winner's committed insert
and raises `ApiKeyNameConflictError`.

**Exceptions:** service exceptions listed below and underlying database or
audit-service exceptions not translated above.

### `revoke_key()`

```python
async def revoke_key(
    session: AsyncSession,
    key_id: UUID,
    acting_user_id: UUID | None,
    owner_user_id: UUID | None = None,
) -> ApiKeyWithOwner
```

**Guard:** if no key matches `key_id` and the optional owner restriction,
raise `ApiKeyNotFoundError`. A key belonging to another owner is deliberately
indistinguishable from a missing key.

**Behavior:**

1. Select the key by `key_id` and, when non-NULL, `owner_user_id`, using
   `SELECT ... FOR UPDATE`. This is the function's first database operation.
2. If no row matches, raise `ApiKeyNotFoundError`.
3. If `revoked_at` is already non-NULL, return the unchanged row. Do not
   change `revoked_by` and do not create an audit event.
4. Set `revoked_at` to the operation's UTC `now` snapshot and `revoked_by` to
   `acting_user_id`.
5. Create one `api_key_revoked` event: actor = `acting_user_id`, target = key
   owner, `old_value` = normalized key name, and
   `detail = {"key_id": "<uuid>"}`.
6. Flush the mutation and audit event, then return the key with its owner and
   nullable revoker records loaded for API serialization. The same enriched
   result is returned for the idempotent no-op path.

**Re-invocation and concurrency:** idempotent. The row lock serializes
single, administrator, CLI, and bulk revocation of the same key. Exactly the
first transaction that observes `revoked_at IS NULL` mutates the key and
creates one event. Later or concurrent calls return the committed revoked
state with no additional event.

**Exceptions:** `ApiKeyNotFoundError` and underlying database or audit-service
exceptions.

### `revoke_all_user_keys()`

```python
async def revoke_all_user_keys(
    session: AsyncSession,
    user_id: UUID,
    acting_user_id: UUID | None,
) -> int
```

Revokes every non-revoked key for one user, including expired keys. This is a
user-deactivation side effect; it does not use the derived `active` status as
its scope.

**Guard:** missing user raises `UserNotFoundError`.

**Behavior:**

1. Select the user with `FOR NO KEY UPDATE` as this function's first
   database operation. `user_service.deactivate_user()` already holds a
   conflicting lock in the same transaction, so reacquisition is immediate.
   A missing user raises `UserNotFoundError`.
2. Select all keys for the user with `revoked_at IS NULL` using
   `FOR UPDATE`, in deterministic `id` order. The user lock already
   serializes concurrent bulk operations for the same owner; the
   deterministic key ordering serializes each row with `revoke_key()`.
3. For each selected key, set one shared `revoked_at` snapshot and
   `revoked_by = acting_user_id`.
4. For each selected key, create one `api_key_revoked` event with actor,
   target, and old value as above and
   `detail = {"key_id": "<uuid>", "reason": "user_deactivated"}`.
5. Flush all mutations and events and return the number of keys changed.

**Re-invocation and concurrency:** idempotent. No matching rows returns zero
and creates no event. Concurrent single or bulk revocations still produce one
mutation and event per key because all paths lock the same key row before
checking `revoked_at`. Concurrent single and bulk revocations complete without
deadlock: the user lock uses `FOR NO KEY UPDATE`, which is compatible with the
`FOR KEY SHARE` locks PostgreSQL acquires when `revoke_key()` flushes
foreign-key-backed mutations and audit events.

**Exceptions:** `UserNotFoundError` and underlying database or audit-service
exceptions.

### `get_key_by_hash()`

```python
async def get_key_by_hash(
    session: AsyncSession,
    key_hash: str,
) -> ApiKey | None
```

Returns the key whose stored digest exactly matches `key_hash`, or `None` when
no key matches. This read is used only by the authentication boundary after it
computes the digest of a presented credential. It does not lock, mutate, or
create an audit event. Database exceptions propagate. Lifecycle validation
remains in `authentication.md`; callers must not use this read as a substitute
for `revoke_key()`.

### `list_user_keys()`

```python
async def list_user_keys(
    session: AsyncSession,
    user_id: UUID,
    status: ApiKeyStatus | None,
    page: int,
    per_page: int,
    sort_by: ApiKeySortField,
    sort_order: SortOrder,
    now: datetime | None = None,
) -> ApiKeyPage
```

Validates that the user exists, then returns only that user's matching keys.
Missing user raises `UserNotFoundError`. Status filtering, sorting,
`last_used_at` NULL-last behavior, and pagination follow
`api-key-management.md` and `api-spec.md`. An out-of-range page returns empty
`items` with the correct `total`. No row lock or audit event is created.

### `list_all_keys()`

```python
async def list_all_keys(
    session: AsyncSession,
    owner: str | None,
    status: ApiKeyStatus | None,
    page: int,
    per_page: int,
    sort_by: ApiKeySortField,
    sort_order: SortOrder,
    now: datetime | None = None,
) -> ApiKeyWithOwnerPage
```

Returns matching keys across all owners with owner records. `owner` accepts
a user UUID or case-sensitive exact username under the shared User Identifier
Resolution contract. An unknown owner returns an empty page with `total=0`;
it is not an error. Other filtering, sorting, NULL placement, and pagination
match `list_user_keys()`. No row lock or audit event is created.

### `count_non_revoked_keys()`

```python
async def count_non_revoked_keys(
    session: AsyncSession,
    user_id: UUID,
) -> int
```

Returns the number of keys owned by `user_id` whose `revoked_at` is NULL,
including expired keys. The caller has already resolved the user; an unknown
UUID therefore returns zero rather than raising `UserNotFoundError`.
`user_service.get_deactivation_impact()` is the consumer; the administrator
deactivation API and the `manage-user deactivate` CLI obtain the count
through that service boundary and never call this function or query `ApiKey`
directly. This read does not lock, mutate, or create an audit event.
Database exceptions propagate.

### `list_user_keys_for_cli()`

```python
async def list_user_keys_for_cli(
    session: AsyncSession,
    username: str,
    now: datetime | None = None,
) -> ApiKeyCliList
```

Trims and lowercases the username, resolves the user, and returns all their
keys ordered by `id DESC`. `id` is a UUIDv7 value, so this is equivalent to
`created_at DESC` with a deterministic tiebreak, in a single column. Unknown
user raises `UserNotFoundError`. The result's `evaluated_at` is the
function's shared status snapshot; the caller must not capture a different
time per row. This operator-only query is intentionally unpaginated. It
creates no audit event.

### `update_last_used_at()`

```python
async def update_last_used_at(
    session: AsyncSession,
    key_id: UUID,
    used_at: datetime,
) -> bool
```

Persists operational authentication metadata after successful credential
validation. The authentication boundary maintains a per-instance cache of
the last successful write time per key. If less than 60 seconds have elapsed,
it does not call this function.

When called, update the matching row only when its current `last_used_at` is
NULL or earlier than `used_at`; flush and return `True` if changed. A missing
row or a timestamp that would not advance the value returns `False`. This
function does not lock the row, does not modify lifecycle fields, and creates
no `IdentityAuditEvent`. Concurrent updates may race, but the conditional
update guarantees `last_used_at` never moves backward. Database exceptions
propagate.

**Re-invocation:** conditionally idempotent; the same or older `used_at`
produces no additional write.

The authentication boundary owns a transaction dedicated to this operational
touch. It commits after a successful update and records a debounce success
only after that commit. On failure it rolls back, does not advance the
in-memory debounce timestamp, and continues authentication with the otherwise
valid credential; `last_used_at` is best-effort metadata.

## Service Exceptions

All module-specific exceptions inherit from `ApiKeyServiceError`, which
inherits from `ServiceError`. API handlers map each exception explicitly.
Shared exceptions marked † inherit directly from `ServiceError`.

| Exception | HTTP | Code | Raised when |
|---|---|---|---|
| `UserNotFoundError` † | 404 | `USER_NOT_FOUND` | Required owner user does not exist |
| `InactiveUserError` † | 409 | `USER_INACTIVE` | Key creation owner is inactive |
| `ApiKeyNotFoundError` | 404 | `AUTH_API_KEY_NOT_FOUND` | Key does not exist or fails an owner restriction |
| `ApiKeyNameConflictError` | 409 | `AUTH_API_KEY_NAME_CONFLICT` | Non-revoked key already uses the normalized name for this owner |
| `ApiKeyNameValidationError` | 422 | `AUTH_API_KEY_NAME_INVALID` | Normalized name violates the API Key Name Rule |
| `ApiKeyInvalidExpiryError` | 400 | `AUTH_API_KEY_INVALID_EXPIRY` | Expiration is not strictly later than creation time |

## Cross-references

- `docs/api-spec.md` — API pagination, sorting, filtering, and errors
- `docs/data-model.md` — `ApiKey` schema and partial unique index
- `docs/features/identity/api-key-management.md` — lifecycle, status, API,
  CLI, logging, and retention behavior
- `docs/features/identity/authentication.md` — API key credential validation
- `docs/features/identity/identity-audit-log.md` — audit event payloads and
  operational metadata exclusions
- `docs/features/identity/user-service.md` — deactivation caller and user lock
- `docs/features/platform/audit-trail-infrastructure.md` — audit atomicity and
  idempotent no-ops
- `docs/features/platform/cli-infrastructure.md` — CLI async and transaction
  workflow
