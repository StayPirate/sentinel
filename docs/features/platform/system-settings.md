# System Settings

## Purpose

System-wide configuration and administrative operations for the Sentinel
platform. The System Settings page provides settings that affect platform behavior
across all users and tickets.

## Access Control

All administration endpoints and UI pages require the `manage_settings`
capability.

## Service Module

System-setting persistence, bootstrap, reads, and audit logging are implemented
in `backend/app/services/settings.py`. Setting mutation and recalculation
publication are specified here and in
`docs/features/platform/default-cvss-version-operations.md`.

## Settings

### Default CVSS Version

Selects the preferred version in the cross-version Severity Resolution Cascade
and the exact canonical SUSE version used for Eligibility Score Resolution. It
does not exclude other accepted versions from severity and does not control the
version-independent SUSE-assessment presence gate.

| Property        | Value                            |
|-----------------|----------------------------------|
| Setting key     | `default_cvss_version`           |
| Type            | String                           |
| Allowed values  | `"3.1"`, `"4.0"`                 |
| Initial value   | `"3.1"`                          |
| Changed by      | Admin only                       |

**Impact of changing the default version**:

When the Admin changes the default CVSS version, the PATCH endpoint composes
the setting mutation with the complete-run admission, ownership, and
publication contract in
`docs/features/platform/default-cvss-version-operations.md`
(Complete-Run Coordination). This section owns only the invariants needed at
that coordination boundary; the Settings mutation service owns its final
signature, transaction composition, concurrent changed/no-op classification,
and result type.

For a request that the complete Settings mutation contract classifies as a
value change, the required coordination sequence is:

1. **Validate** the new value against allowed values (`"3.1"`, `"4.0"`)
2. **Acquire the execution fence**: acquire the feature-specific
   PostgreSQL session-level advisory fence with non-blocking semantics.
   Only a definitive lock-not-acquired result means the fence is held:
   nothing is committed, no lease is acquired, no task is published, and
   the request returns 409 `CVSS_RECALC_ALREADY_IN_PROGRESS`. A database
   or session error during acquisition propagates as a server error and is
   never reported as `409`. A runner holds this fence for its complete
   mutating workflow, so a PATCH cannot overtake it even when the Redis
   lease is absent.
3. **Acquire the admission lease** while holding the fence: preallocate
   the run's Celery task ID and acquire the Redis lease
   `cvss_recalc_active` with `SET ... NX EX 900`, as defined by the
   coordination contract. A held lease releases the fence and returns 409
   `CVSS_RECALC_ALREADY_IN_PROGRESS`. A `RedisError` or uncertain
   acquisition releases the fence and returns 503 `REDIS_UNAVAILABLE`.
   Nothing is committed in either case.
4. **Commit** the new setting value and a `SettingAuditEvent` atomically while
   the fence is held. No Redis or broker I/O occurs inside that transaction or
   while a setting row lock is held. When commit is definitely unsuccessful,
   roll back and close the transaction owner before Redis cleanup. When commit
   completion is uncertain, invalidate or close the transaction connection
   before Redis cleanup; the persisted outcome remains unknown, but no setting
   row lock may survive. Then attempt owner-safe lease removal while the fence
   remains held, release the fence, and propagate the original transaction
   failure through the normal server error mapping. This coordination contract
   does not select a separate dispatch-session mechanism or override the shared
   API transaction conventions; the complete Settings mutation contract must
   define that composition before implementation.
5. **Release the fence and confirm release** before any broker call. If explicit
   unlock fails or is uncertain, invoke no publisher, invalidate or close the
   dedicated connection, attempt owner-safe lease removal, emit the applicable
   cleanup event, and propagate the original server error. Connection closure
   remains the automatic lock-release backstop. A definitive `false` return
   from `pg_advisory_unlock` also means release was not confirmed; it is treated
   as an internal fence-release failure and follows this same global `500
   INTERNAL_ERROR` path.
6. **Enqueue** the batch recalculation Celery task
   (`recalculate_cvss_derived_state`) with the new version as an explicit
   argument and the preallocated task ID, then classify the publication
   outcome under the coordination contract: `submitted` reports a
   scheduled task; an `acceptance_unconfirmed` broker operational error
   retains the lease and must not report that no task can exist; a
   non-operational publisher exception propagates unchanged and also retains
   the lease conservatively.
7. Return the PATCH outcome: a `submitted` publication returns 200 OK
   with the committed setting and a scheduled task; an
   `acceptance_unconfirmed` publication returns 503
   `CELERY_UNAVAILABLE` with the setting change and its audit event
   committed and the admission lease retained (see Error responses). A
   pre-publisher setting, transaction, or fence error and any non-operational
   publisher exception propagate through their ordinary error mapping.

**Commit-first rationale**: the `SettingAuditEvent` is always the first
durable record. No ticket mutation can occur without the setting change
being audited. This prevents phantom mutations (ticket audit events
without a recorded cause).

The PATCH outcome follows the coordination contract. A `submitted` publication
returns 200 OK reporting a scheduled task; a no-op change returns 200 OK
reporting that this request published no new task. An `acceptance_unconfirmed`
publication returns
`503 CELERY_UNAVAILABLE`; the setting change and its `SettingAuditEvent` remain
committed and the admission lease is retained. The response never reports
`recalculation_scheduled = false` as evidence that no earlier admitted or
acceptance-unconfirmed run can exist, and it never releases the retained lease.
The no-op path reads no Redis coordination state merely to strengthen that
boolean. Its locked-current classification and concurrent relationship to the
changed path belong to the complete Settings mutation contract rather than to
this coordination sequence.

The runner, manual recalculation endpoint, impact-preview service and endpoint,
observability, restart and recovery behavior, absence of persistent run state,
and complete-run coordination are authoritative in
`docs/features/platform/default-cvss-version-operations.md`. The PATCH endpoint
only composes the setting mutation with an immediate publication attempt; it
does not redefine those operation contracts.

## Bootstrap

The `default_cvss_version` setting (declared above with Initial value
`"3.1"`) MUST exist at runtime before any process reads it. The system
guarantees existence via two complementary mechanisms:

1. **Alembic data migration** (primary — runs before any process starts):

   ```sql
   INSERT INTO system_setting (key, value)
   VALUES ('default_cvss_version', '3.1')
   ON CONFLICT (key) DO NOTHING;
   ```

2. **FastAPI lifespan bootstrap** (defense-in-depth, self-healing):

   ```sql
   INSERT INTO system_setting (key, value)
   VALUES ('default_cvss_version', '3.1')
   ON CONFLICT (key) DO NOTHING;
   ```

Properties:

- **Idempotent**: if the setting already exists (e.g., Admin changed it
  to `"4.0"`), the INSERT is a no-op
- **Self-healing**: if the row is accidentally deleted, the next
  application restart restores the default
- **Multi-replica safe**: `ON CONFLICT DO NOTHING` handles concurrent
  startup of multiple API server instances without race conditions
- **Process-order independent after migration**: the Alembic migration
  guarantees the setting exists before any process (API server, Celery
  worker, RabbitMQ consumer) starts. The FastAPI lifespan bootstrap also
  restores a row deleted after migration before that API instance serves
  requests; non-API processes continue to rely on the migration guarantee

Neither initialization mechanism creates a `SettingAuditEvent`. They establish
or restore required baseline data idempotently; they are not administrative
setting mutations and have no human actor.

### Bootstrap Service

```python
async def bootstrap_system_settings(session: AsyncSession) -> None:
    ...
```

`session` is the caller-owned asynchronous database session. The function:

1. Inserts `default_cvss_version = "3.1"` with `ON CONFLICT (key) DO
   NOTHING`.
2. Flushes the insert before returning so database errors surface at this
   boundary. It never commits; the caller owns the transaction.
3. Returns `None` whether it inserted the row or found an existing row.

The operation is idempotent. Repeated calls preserve the existing value,
including an administrator-selected value of `"4.0"`. Concurrent calls are
safe: at most one inserts the row and every successful caller observes a
completed insert or conflict before returning. It creates no audit event.

Database availability, missing-table/schema, constraint, and flush failures
propagate to the caller. The function does not catch them, retry them, or
return partial success.

### Setting Read Service

```python
async def get_default_cvss_version(session: AsyncSession) -> str:
    ...
```

The function reads the `default_cvss_version` row from `system_setting` and
returns its stored value. If the row is absent, it raises
`RequiredSystemSettingMissingError`; it never substitutes a hardcoded or
environment-derived value. Database availability and schema errors propagate
unchanged. The function performs no writes and creates no audit event.

### Service Exceptions

All exceptions defined by the settings service inherit from
`SettingsServiceError`, which inherits from the shared `ServiceError` root.

System-internal exceptions:

| Exception | Raised when | Handling |
|---|---|---|
| `RequiredSystemSettingMissingError` | The required `default_cvss_version` row is absent | Propagates to the caller; API handlers do not catch it, so the framework returns the global `500 INTERNAL_ERROR` response |

The public response uses the standard non-sensitive `INTERNAL_ERROR` detail;
it does not disclose whether migration, bootstrap, or data corruption caused
the missing row. Because `500 INTERNAL_ERROR` is a global response, endpoint
error tables do not repeat it.

### FastAPI Lifespan Ordering and Failure

Database migration is an external deployment prerequisite and never runs in
the application lifespan. During API startup, after application configuration
is validated and before request serving begins, the lifespan opens a database
transaction, invokes `bootstrap_system_settings()` with that transaction's
session, and commits. Only a successful commit allows startup to complete.

If database connection, schema access, bootstrap, flush, or commit fails, the
transaction rolls back and the exception escapes the lifespan. FastAPI startup
therefore fails and the API process MUST NOT begin serving requests. Startup
does not continue in a degraded mode and does not use a fallback setting.

## API Endpoints

All endpoints in this section require the `manage_settings` capability.

### Get System Settings

```
GET /api/v1/admin/settings
```

**Request body**: none.

**Query parameters**: none. The endpoint is not paginated.

**Behavior**: call `get_default_cvss_version()` with the request session and
return the persisted value. A missing required row propagates
`RequiredSystemSettingMissingError` and is exposed through the standard `500
INTERNAL_ERROR` response; no fallback value is returned.

Response:

```json
{
  "data": {
    "default_cvss_version": "3.1"
  }
}
```

**`Capability: manage_settings`**

### Update System Settings

```
PATCH /api/v1/admin/settings
```

Request body:

```json
{
  "default_cvss_version": "4.0"
}
```

Validates the value against allowed values. On a value change, composes the
setting mutation with complete-run admission, lease acquisition, commit, and
publication as described in "Impact of changing the default version" above.
Changing the setting neither requires nor consumes a prior impact preview; see
`docs/features/platform/default-cvss-version-operations.md`.

**Note on PATCH with side effects**: this endpoint uses PATCH because
semantically it is a configuration field update — the setting changes
value. Admission, the setting-and-audit commit, confirmed fence release, and the
initial publication attempt complete during the request. Only task execution is
asynchronous: the response does not wait for a worker to start or complete the
recalculation. This is a documented deviation from the
`POST /resource/{id}/verb` convention for operations with side effects.

**Error responses**:

| Status | Code | Condition |
|--------|------|-----------|
| 409 | `CVSS_RECALC_ALREADY_IN_PROGRESS` | The execution fence or the admission lease is already held, so the setting change is blocked; nothing is committed |
| 503 | `REDIS_UNAVAILABLE` | Redis rejected or could not complete lease acquisition; nothing is committed |
| 503 | `CELERY_UNAVAILABLE` | The publisher raised `kombu.exceptions.OperationalError`, so broker acceptance is unconfirmed; the setting change and audit event remain committed and the admission lease is retained |

A setting, transaction, commit, or fence-release failure before publisher
invocation propagates its ordinary error after owner-safe cleanup is attempted;
it is not `CELERY_UNAVAILABLE` and is not a successful PATCH outcome. An
unconfirmed acceptance returns `503 CELERY_UNAVAILABLE` with the fixed
sanitized detail `"Recalculation task publication could not be confirmed"` and
is retryable only after the task is delivered or the retained lease expires by
its TTL. A publisher exception that is not a broker operational error also
retains the lease and propagates as a server error; the endpoint must not
release the retained lease on that path. A no-op change observes only the
persisted setting value and reads no coordination state; when a lease is
retained, the no-op response must not imply that no run can exist.

Response (200 OK): the settings object in the standard
`{"data": ...}` envelope. The `recalculation_scheduled` boolean field
is present in the current response shape:

```json
{
  "data": {
    "default_cvss_version": "4.0",
    "recalculation_scheduled": true
  }
}
```

While the current response retains this boolean, it is `true` only when the
value changed and this request's publication returned `submitted`. Under the
current response contract it is `false` for a no-op change, where this request
published no new task. It does not assert that no earlier admitted or
acceptance-unconfirmed run can exist, and the no-op path performs no Redis query
to make such a claim. An unconfirmed publication instead uses the `503
CELERY_UNAVAILABLE` response above. No run-status endpoint or additional
response field is introduced. The admin recovery surface remains
`POST /api/v1/admin/settings/default-cvss-version/recalculate`.

This coordination change retains the existing boolean response shape. The
complete Settings mutation contract may preserve it or replace it with a more
explicit outcome, but any replacement must preserve the non-assertion above.

**`Capability: manage_settings`**

## Data Model

System settings are stored in a key-value configuration table. See
`docs/data-model.md` for the schema.

## Setting Audit Log

Every administrative modification to a system setting MUST produce a
`SettingAuditEvent` record in the same database transaction as the
setting update. Alembic seeding and lifespan bootstrap are initialization,
not administrative modifications, and create no event.

### SettingAuditEvent Table

See `docs/data-model.md` for the full table definition. Key columns:

| Column | Type | Description |
|---|---|---|
| event_type | VARCHAR(50) | `SettingAuditEventType` — currently only `setting_changed` |
| setting_key | VARCHAR(100) | Which setting was changed (e.g., `default_cvss_version`) |
| user_id | UUID | Admin who changed the setting (always present — no system-initiated changes) |
| old_value | TEXT | Previous value |
| new_value | TEXT | New value |

### SettingAuditLog Service

```python
class SettingAuditLog(BaseAuditLog):
    name = "setting"
    description = "System setting modifications"
    model_class = SettingAuditEvent

    @classmethod
    async def log_event(
        cls,
        session: AsyncSession,
        *,
        event_type: SettingAuditEventType,
        setting_key: str,
        user_id: UUID | None,
        old_value: str | None,
        new_value: str,
    ) -> None:
        ...
```

The method accepts only a `SettingAuditEventType` member; the currently valid
member is `SETTING_CHANGED` (`"setting_changed"`). It validates the enum at
the service boundary because this classification enum has no database CHECK
constraint. It also requires a non-null `user_id`; a missing human actor raises
`ValueError`. The database foreign key validates `setting_key`, and NOT NULL
constraints validate required persisted fields.

After validation, the method creates exactly one event and flushes it before
returning. It never commits. Each invocation creates a new event and is
therefore not idempotent; callers MUST invoke it only when a setting value
actually changes. `ValueError` and all database/flush exceptions propagate to
the caller.

Setting mutations use a caller-owned transaction and pass the same
`AsyncSession` to the setting update and `log_event()`. If audit validation or
insertion fails, the exception remains part of the mutation transaction and
the caller rolls back both changes. The caller MUST NOT commit the setting
update independently or catch an audit failure and continue.

### List Settings Audit Events

```
GET /api/v1/admin/settings/audit-log
```

**Request body**: none.

Returns a paginated list of setting changes, ordered by `created_at`
descending, with deterministic secondary ordering as defined by
`docs/api-spec.md` (Deterministic Pagination Ordering). Sorting is fixed —
client-controlled `sort_by` / `sort_order` parameters are not supported
(audit trail entries are always displayed in reverse chronological order).

**Query parameters**:

| Parameter | Type | Default | Description |
|---|---|---|---|
| `page` | int | 1 | Page number (1-indexed) |
| `per_page` | int | 20 | Items per page (max 100) |
| `event_type` | string (repeatable) | -- | Filter by event type (currently only `setting_changed`). Multiple values use OR semantics (e.g., `?event_type=setting_changed`). See `docs/api-spec.md` (Enum Filter Validation) for handling of invalid values |
| `setting_key` | string | -- | Filter by setting key |
| `actor` | string | -- | Filter by actor: user UUID or username. `system` is accepted but will return no results (all setting changes are user-initiated) |
| `from_date` | string | -- | ISO 8601 date/datetime. Include events from this date onwards (inclusive) |
| `to_date` | string | -- | ISO 8601 date/datetime. Include events up to this date (inclusive) |

Different filter types combine with AND. Repeated `event_type` values combine
with OR after invalid enum values are removed according to `docs/api-spec.md`.
`setting_key` is an exact match; an unknown key returns an empty page. Actor
resolution uses `BaseAuditLog.filter_by_actor()`: unknown UUIDs/usernames and
the literal `system` return an empty page rather than 404.

Pagination uses the global bounds without clamping, `meta.total` counts the
filtered result set, and a page beyond the final page returns an empty `data`
array with the requested page metadata. Date parsing and normalization follow
`docs/api-spec.md` (Date Range Interpretation): malformed values produce the
global `422 VALIDATION_ERROR`, while an inverted normalized range produces the
shared `400 DATE_RANGE_INVERTED` response. Undeclared query parameters,
including `sort_by` and `sort_order`, follow the global undeclared-query
semantics and are ignored.

**`Capability: manage_settings`**

**Response** (200 OK):

```json
{
  "data": [
    {
      "id": "uuid",
      "event_type": "setting_changed",
      "setting_key": "default_cvss_version",
      "old_value": "3.1",
      "new_value": "4.0",
      "created_at": "2026-05-13T14:00:00Z",
      "actor": {
        "id": "uuid",
        "username": "asmith",
        "full_name": "Alice Smith",
        "active": true
      }
    }
  ],
  "meta": {
    "total": 3,
    "page": 1,
    "per_page": 20
  }
}
```

`created_at` is serialized in UTC with a `Z` suffix. Because setting audit
events require a human actor and user rows cannot be hard-deleted, `actor` is
always the complete current user reference object shown above and is never
`null`.

### Data Retention

Indefinite. SettingAuditEvent records are never automatically deleted.

## Cross-references

- `docs/features/platform/audit-trail-infrastructure.md` — BaseAuditLog,
  AuditEventMixin
- `docs/api-spec.md` — global API conventions (envelope format, error codes,
  pagination, shared 422 responses)
- `docs/features/identity/rbac.md` — Endpoint Permission Map
- `docs/features/platform/default-cvss-version-operations.md` — impact preview,
  manual recalculation, all-CVE runner, observability, and recovery
- `docs/features/tickets/cvss-scoring.md` — setting consumers and pure severity
  and eligibility resolutions
- `docs/conventions.md` — caller-owned transactions and Redis conventions
