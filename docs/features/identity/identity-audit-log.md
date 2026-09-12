# Identity Audit Log

## Purpose

Provide a persistent, queryable audit trail for all identity-related
operations in Sentinel: user lifecycle, role assignments, API key
management, and role mapping administration.

This audit trail replaces the INFO-level application logging currently
specified for these operations. Application-level logging MAY be retained
alongside the database audit trail for operational monitoring, but the
database record is the authoritative historical audit source. Current user,
role, and API-key state remains authoritative in the owning operational tables
per `docs/features/platform/audit-trail-infrastructure.md` (Operational State
Authority).

## Data Model

### IdentityAuditEvent Table

Inherits `id`, `created_at`, and `user_id` from `AuditEventMixin`.

| Column | Type | Constraints | Description |
|---|---|---|---|
| id | UUID | Inherited from AuditEventMixin | Internal identifier |
| event_type | VARCHAR(50) | NOT NULL | See IdentityAuditEventType |
| user_id | UUID | Inherited from AuditEventMixin | Authenticated Sentinel user who performed the action. NULL when no authenticated Sentinel actor exists, including CLI, task/system, and external-sync workflows |
| target_user_id | UUID | FK(user.id), nullable | The user affected by the action. NULL for role mapping events (which affect configuration, not a specific user) |
| old_value | TEXT | nullable | Previous state (human-readable) |
| new_value | TEXT | nullable | New state (human-readable) |
| detail | JSONB | nullable | Additional structured context when old_value/new_value are insufficient |
| created_at | TIMESTAMPTZ | Inherited from AuditEventMixin | When the event occurred |

**Notes**:

- `id`, `created_at`, and `user_id` are inherited from `AuditEventMixin`
- `target_user_id` distinguishes "who acted" from "who was affected". For
  example, when an admin resets another user's password: `user_id` = admin,
  `target_user_id` = target user
- For role mapping events, `target_user_id` is NULL because the action
  affects a configuration rule, not a specific user. The `detail` JSONB
  captures the mapping details and affected user count
- `detail` JSONB is used for structured data that does not fit the
  old_value/new_value pattern (e.g., role mapping metadata, affected
  user counts)
- `old_value` and `new_value` must not exceed 512 Unicode code points. This limit
  is derived from the constraints of the source columns: username max 64
  characters, email max 255 characters, role names and status strings are
  shorter still. After validating the original field combination, the service
  preserves exactly the first 512 code points of an over-limit value, without
  normalization or an ellipsis. `None` remains `None`

### Actor Contract

Actor nullability records whether the operation was authenticated as a
Sentinel user; it does not attempt to identify an operating-system user behind
a CLI invocation.

| Invocation source | `user_id` |
|---|---|
| Authenticated API operation | Authenticated user's UUID; API handlers MUST NOT pass NULL |
| Self-service API key creation | Key owner's UUID |
| CLI workflow | NULL |
| Celery task or other system automation | NULL |
| External provisioning synchronization | NULL |

When actor NULL could describe either a manual CLI workflow or external
synchronization, event-specific `detail.source` identifies external sync.
Manual CLI lifecycle events leave that source detail absent.

### IdentityAuditEventType Enum

| Value | Trigger | `user_id` | `target_user_id` | `old_value` | `new_value` | `detail` |
|---|---|---|---|---|---|---|
| `user_created` | User account created (authenticated API, CLI, or external sync) | Per Actor Contract | Created user | `NULL` | Username | External sync only: `{"source": "external_sync"}`; otherwise `NULL` |
| `user_deactivated` | Authenticated API, CLI, or external sync deactivation | Per Actor Contract | Deactivated user | `active` | `inactive` | Reason; external sync also identifies its source |
| `user_reactivated` | Authenticated API, CLI, or external sync reactivation | Per Actor Contract | Reactivated user | `inactive` | `active` | External sync only: `{"source": "external_sync"}`; otherwise `NULL` |
| `password_reset` | Authenticated administrator or CLI resets a local user's password | Per Actor Contract | Target user | `NULL` | `NULL` | `NULL` |
| `role_added` | Direct or group-derived role assignment | Per Actor Contract | Target user | `NULL` | Role name (e.g., `admin`) | For a group-derived role: `{"source": "external_sync", "mapping": "SecurityTeam"}` |
| `role_removed` | Direct or group-derived role removal | Per Actor Contract | Target user | Role name (e.g., `admin`) | `NULL` | For a group-derived role: `{"source": "external_sync", "mapping": "SecurityTeam"}` |
| `role_mapping_created` | Admin creates group-to-role mapping | Admin | `NULL` | `NULL` | `"{group_name} -> {role}"` | `{"group_name": "...", "role": "...", "affected_users": N}` |
| `role_mapping_deleted` | Admin deletes group-to-role mapping | Admin | `NULL` | `"{group_name} -> {role}"` | `NULL` | `{"group_name": "...", "role": "...", "affected_users": N}` |
| `username_changed` | Username updated by an authorized lifecycle caller | Per Actor Contract | Renamed user | Old username | New username | External sync only: `{"source": "external_sync"}`; otherwise `NULL` |
| `api_key_created` | User creates own API key | Key owner | Key owner | `NULL` | Normalized key name | `{"key_id": "uuid"}` |
| `api_key_revoked` | User, admin, or system revokes API key | Acting user or `NULL` (system) | Key owner | Key name/label | `NULL` | `{"key_id": "uuid", "reason": "user_deactivated"}` (reason only for bulk revocation during deactivation) |
| `email_changed` | Email address updated (authenticated API, CLI, or external sync) | Per Actor Contract | Target user | Old email | New email | External sync only: `{"source": "external_sync"}`; otherwise `NULL` |
| `full_name_changed` | Full name updated (authenticated API, CLI, or external sync) | Per Actor Contract | Target user | Old full name (or `NULL`) | New full name (or `NULL`) | External sync only: `{"source": "external_sync"}`; otherwise `NULL` |
| `manager_changed` | Direct manager updated (external sync) | `NULL` (system) | Target user | Old manager username (or `NULL`) | New manager username (or `NULL`) | `NULL` |

### detail JSONB Schema Contract

The `detail` column carries structured context for event types where
`old_value`/`new_value` are insufficient. Every event type that
populates `detail` MUST have its schema defined in the table below.
Event types not listed here MUST set `detail` to `NULL`.

| Event Type | Required Keys | Optional Keys | Example |
|---|---|---|---|
| `user_created` | — | `source` (literal `"external_sync"`) | `{"source": "external_sync"}` |
| `user_deactivated` | `reason` (string) | `source` (literal `"external_sync"`) | `{"reason": "external_sync_missing", "source": "external_sync"}` |
| `user_reactivated` | — | `source` (literal `"external_sync"`) | `{"source": "external_sync"}` |
| `role_added` | — | `source` (literal `"external_sync"`), `mapping` (string) | `{"source": "external_sync", "mapping": "SecurityTeam"}` |
| `role_removed` | — | `source` (literal `"external_sync"`), `mapping` (string) | `{"source": "external_sync", "mapping": "SecurityTeam"}` |
| `role_mapping_created` | `group_name` (string), `role` (string), `affected_users` (int) | — | `{"group_name": "SecurityTeam", "role": "admin", "affected_users": 5}` |
| `role_mapping_deleted` | `group_name` (string), `role` (string), `affected_users` (int) | — | `{"group_name": "SecurityTeam", "role": "admin", "affected_users": 3}` |
| `api_key_created` | `key_id` (UUID string) | — | `{"key_id": "550e8400-e29b-41d4-a716-446655440000"}` |
| `api_key_revoked` | `key_id` (UUID string) | `reason` (string) | `{"key_id": "550e8400-e29b-41d4-a716-446655440000", "reason": "user_deactivated"}` |
| `email_changed` | — | `source` (literal `"external_sync"`) | `{"source": "external_sync"}` |
| `full_name_changed` | — | `source` (literal `"external_sync"`) | `{"source": "external_sync"}` |
| `username_changed` | — | `source` (literal `"external_sync"`) | `{"source": "external_sync"}` |

**Notes**:

- `role_added` and `role_removed`: `detail` is `NULL` for a direct manual role
  assignment by API or CLI. Group-derived assignments always include both
  keys, whether the mapping is applied by external synchronization or by an
  authenticated role-mapping create/delete operation. `source` equals
  `"external_sync"` to identify the external origin of the role, while
  `mapping` identifies the external group/role mapping that caused it.
  As a validation rule, `source` and `mapping` are required together: either
  both are present or `detail` is `NULL`.
- `user_created`: manual API and CLI creation uses `detail = NULL`; external
  synchronization requires `{"source": "external_sync"}`
- `user_deactivated`, `user_reactivated`, `email_changed`,
  `full_name_changed`, and `username_changed`: an external-sync mutation requires
  `source = "external_sync"`; authenticated API and manual CLI mutations omit
  the key. `user_deactivated.reason` remains required for every source
- `user_deactivated.detail.reason` is identity-lifecycle context and is
  independent of Ticket unassignment comments. A derived Ticket unassignment
  always uses the canonical Ticket reason `user deactivated`, regardless of
  whether the identity event describes an API, CLI, or external-sync cause.
- `api_key_revoked`: the `reason` key is present only for bulk
  revocations triggered by user deactivation. For individual manual
  revocations, `detail` contains only `key_id`
- The top-level `detail` value MUST be a JSON object. `affected_users` is a
  non-negative integer (a boolean is not an integer for this contract), and
  every `key_id` is a canonical UUID string
- The service layer MUST validate that `detail` contains only keys
  defined in this contract for the given event type — undocumented keys
  are rejected
- When a new `IdentityAuditEventType` is added that uses the `detail`
  column, this table MUST be extended with the corresponding schema
  definition before the implementation proceeds

### `IdentityAuditLog.log_event()`

```python
class IdentityAuditLog(BaseAuditLog):
    name = "identity"
    description = "User lifecycle, roles, API keys, and role mappings"
    model_class = IdentityAuditEvent

    @classmethod
    async def log_event(
        cls,
        session: AsyncSession,
        *,
        event_type: IdentityAuditEventType,
        user_id: UUID | None,
        target_user_id: UUID | None,
        old_value: str | None = None,
        new_value: str | None = None,
        detail: Mapping[str, str | int] | None = None,
    ) -> None:
        ...
```

The method accepts only an `IdentityAuditEventType` member and the exact typed
fields above. It validates the event-specific required/NULL field combination
from the IdentityAuditEventType table and the `detail` schema. It enforces
event types that are intrinsically system-only (`manager_changed`) and
intrinsically administrator-only
(`role_mapping_created` and `role_mapping_deleted`). For events whose actor is
listed as "Per Actor Contract", invocation-source attribution is a caller
obligation because `log_event()` receives no invocation-source parameter. A
contract violation — including a raw/unknown event type, missing or
unexpected field, wrong detail value type, unknown key, invalid UUID string,
oversized payload, or JSON encoding failure — raises `ValueError`. Database and
flush exceptions propagate unchanged. Callers MUST NOT catch an audit failure
and continue the business mutation.

Validation and persistence occur in this deterministic order:

1. Validate `event_type`, actor/target requirements, and the original
   `old_value`/`new_value`/`detail` combination. Unknown detail keys and schema
   mismatches fail here, before truncation or size measurement.
2. Truncate non-NULL `old_value` and `new_value` to their first 512 Unicode
   code points, with no Unicode normalization and no ellipsis.
3. If `detail` is non-NULL, serialize it solely for size measurement as compact
   deterministic JSON with `ensure_ascii=False`, sorted keys, separators `,`
   and `:` without spaces, and no non-finite numbers. Encode the complete JSON
   representation as UTF-8, including braces, keys, quotes, and escaping.
4. Accept a serialized size of at most 4096 bytes. More than 4096 bytes raises
   `ValueError`; no event is inserted.
5. Create exactly one `IdentityAuditEvent` and flush it before returning.

An empty `detail` mapping is invalid. Callers represent the absence of
structured context with `detail = NULL`.

The method returns `None` and never commits or rolls back. Each successful
invocation creates a new event and is not idempotent; callers invoke it only
for an effective mutation. It uses the mutation's caller-owned transaction, so
an audit validation or insert failure rolls back the mutation and event
together.

## API

### List Identity Audit Events

```
GET /api/v1/admin/identity/audit-log
```

Returns a paginated list of identity audit events, ordered by
`created_at` descending. Sorting is fixed — client-controlled
`sort_by` / `sort_order` parameters are not supported (audit trail
entries are always displayed in reverse chronological order).

**Query parameters**:

| Parameter | Type | Default | Description |
|---|---|---|---|
| `page` | int | 1 | Page number (1-indexed) |
| `per_page` | int | 20 | Items per page (max 100) |
| `event_type` | string (repeatable) | -- | Filter by event type. Multiple values use OR semantics (e.g., `?event_type=role_added&event_type=user_deactivated`). See `docs/api-spec.md` (Enum Filter Validation) for handling of invalid values |
| `actor` | string | -- | Filter by actor: user UUID, username, or `system` for automated events |
| `target_user` | string | -- | Filter by target user (UUID or username) |
| `from_date` | string | -- | ISO 8601 date/datetime. Include events from this date onwards (inclusive) |
| `to_date` | string | -- | ISO 8601 date/datetime. Include events up to this date (inclusive) |

**`Capability: manage_users`**

For non-admin users, a self-scoped
endpoint is available at `GET /api/v1/users/me/audit-log` (see below).

**Response** (200 OK):

```json
{
  "data": [
    {
      "id": "uuid",
      "event_type": "role_added",
      "old_value": null,
      "new_value": "admin",
      "detail": {"source": "external_sync", "mapping": "SecurityTeam"},
      "created_at": "2026-05-13T10:30:00Z",
      "actor": null,
      "target_user": {
        "id": "uuid",
        "username": "jdoe",
        "full_name": "John Doe",
        "active": true
      }
    }
  ],
  "meta": {
    "total": 156,
    "page": 1,
    "per_page": 20
  }
}
```

### List My Identity Audit Events

```
GET /api/v1/users/me/audit-log
```

Returns a paginated list of identity audit events where the
authenticated user is the target (`target_user_id = current_user.id`).
The target filter is implicit and not exposed as a query parameter.
Events with `target_user_id IS NULL` (role mapping configuration
events) are excluded.

Sorting is fixed at `created_at` descending — client-controlled
`sort_by` / `sort_order` parameters are not supported.

**Query parameters**:

| Parameter | Type | Default | Description |
|---|---|---|---|
| `page` | int | 1 | Page number (1-indexed) |
| `per_page` | int | 20 | Items per page (max 100) |
| `event_type` | string (repeatable) | -- | Filter by event type. Multiple values use OR semantics (e.g., `?event_type=role_added&event_type=user_deactivated`). See `docs/api-spec.md` (Enum Filter Validation) for handling of invalid values |
| `from_date` | string | -- | ISO 8601 date/datetime. Include events from this date onwards (inclusive) |
| `to_date` | string | -- | ISO 8601 date/datetime. Include events up to this date (inclusive) |

The `actor` and `target_user` filters are not available on this
endpoint. The target is always the authenticated user; the actor is
anonymized in the response (see below).

**`Access: Authenticated`**

**Response** (200 OK):

```json
{
  "data": [
    {
      "id": "uuid",
      "event_type": "role_added",
      "old_value": null,
      "new_value": "admin",
      "detail": {"source": "external_sync", "mapping": "SecurityTeam"},
      "created_at": "2026-05-13T10:30:00Z",
      "actor": "system"
    }
  ],
  "meta": {
    "total": 42,
    "page": 1,
    "per_page": 20
  }
}
```

**Actor anonymization**: the `actor` field is returned as a string
(not an object) to prevent non-admin users from identifying which
specific administrator performed an action. The mapping is:

| DB condition | `actor` value |
|---|---|
| `user_id IS NULL` | `"system"` |
| `user_id = target_user_id` | `"self"` |
| `user_id IS NOT NULL AND user_id ≠ target_user_id` | `"admin"` |

This gives users visibility into whether an event was triggered by
themselves, by an administrator, or by an automated system process,
without exposing the administrator's identity.

**`detail` field transparency**: the `detail` JSONB field is returned
unredacted in the self-service response. This includes external group names in
`detail.mapping` for external sync events (e.g.,
`{"source": "external_sync", "mapping": "SecurityTeam"}`). External group names
are considered non-sensitive organizational metadata — they are
meaningful only within the external provider's administrative context and do not
constitute personal data or security-critical information.

## Service Contract

Every service function that modifies identity-related data (user
lifecycle, roles, API keys, role mappings) MUST create an
`IdentityAuditEvent` via `IdentityAuditLog.log_event()` in the same
database transaction as the mutation.

**Operational metadata exclusions**: `User.last_login_at`,
`ApiKey.last_used_at`, and `User.synced_at` are high-frequency operational
metadata, not identity lifecycle mutations. Their owning authentication or
provisioning boundaries may update them without an `IdentityAuditEvent`.
This is a narrow exception: changing any API key lifecycle field (`name`,
`expires_at`, `revoked_at`, or `revoked_by`) remains an audited mutation and
must go through `api_key_service`. In particular,
`api_key_service.update_last_used_at()` is the only unaudited API key write.

**API key audit events**: the `api_key_service` is the centralized
location for all API key mutations. Audit events are created inside the
service functions, not in the calling endpoints:

- `create_key()` → creates 1 `api_key_created` event; key creation is
  self-service, so actor and target are the owner
- `revoke_key()` → creates 1 `api_key_revoked` event
- `revoke_all_user_keys()` → creates N `api_key_revoked` events (one per
  revoked key). Each event includes `{"reason": "user_deactivated"}` in
  the `detail` JSONB field to distinguish bulk revocation during
  deactivation from individual manual revocations

Session invalidation during deactivation does NOT produce audit events
(sessions are excluded from the audit trail scope).

**Field-change events**: the `user_service.update_user()` function
produces one audit event per changed field. If a single `update_user()`
call modifies both `email` and `full_name`, two events are created
(`email_changed` + `full_name_changed`) in the same transaction.

**External sync coverage**: the `user_created` event type applies to ALL user
creation regardless of source (manual admin creation AND external sync). On
initial external sync this may produce hundreds of `user_created` events —
this is intentional to maintain a complete, coherent history for every
user. Field-change events (`email_changed`, `full_name_changed`,
`manager_changed`, `username_changed`) are likewise produced by external sync
when the corresponding fields change at the external identity provider.

**Future fields**: if a new mutable field is added to the User table in
the future, a corresponding `{field}_changed` event type MUST be added
to `IdentityAuditEventType`. This is expected to be rare.

## Data Retention

Indefinite. IdentityAuditEvent records are never automatically deleted.

## Testing Requirements

Tests for any identity-mutating service MUST verify:

1. An `IdentityAuditEvent` record is created after the operation
2. The `event_type` matches the expected value
3. `user_id` and `target_user_id` are correctly populated
4. `old_value`, `new_value`, and `detail` are correctly populated
5. The event is created in the same transaction (rollback = no event)

Tests for `IdentityAuditLog.log_event()` itself MUST cover every documented
validation rejection, truncation at 512 Unicode code points, and acceptance at
4096 UTF-8 bytes with rejection above that boundary.

Self-service endpoint tests MUST verify all three actor-anonymization branches,
that `actor` is always a string rather than a User object, and that events with
`target_user_id IS NULL` are excluded.

## Cross-references

- `docs/features/platform/audit-trail-infrastructure.md` — BaseAuditLog,
  AuditEventMixin, naming conventions
- `docs/conventions.md` — Audit Trail
- `docs/api-spec.md` — global API conventions
- `docs/features/identity/user-service.md` — service operations that
  produce identity audit events
- `docs/features/identity/user-management.md` — admin password reset
  and audit trail summary references
- `docs/features/identity/identity-provisioning.md` — External sync operations that
  produce identity audit events
- `docs/features/identity/api-key-service.md` — centralized API key
  lifecycle service; produces `api_key_created` and `api_key_revoked`
  events
- `docs/features/identity/api-key-management.md` — API key lifecycle and
  management surfaces
- `docs/features/identity/rbac.md` — Endpoint Permission Map (add new
  endpoint)
