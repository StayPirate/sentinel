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
in `backend/app/services/settings.py`. The setting mutation contract
(`update_default_cvss_version()` and its PATCH endpoint) is specified in this
document but not yet implemented. The impact preview, all-CVE recalculation
runner, manual admission, and publication contracts are specified in
`docs/features/platform/default-cvss-version-operations.md` and are not yet
implemented.

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

Changing the setting does not itself recalculate already-derived state: later
single-CVE workflows read the persisted value when they run, while existing
CVE, Product-eligibility, and gate-driven Ticket state converges only when the
manual all-CVE recalculation run executes. A successful
`PATCH /api/v1/admin/settings` commits the new value and exactly one
`SettingAuditEvent`; the runner, admission coordination, publication, recovery,
and absence of persistent run state are authoritative in
`docs/features/platform/default-cvss-version-operations.md`.

The intended administrative sequence is advisory and non-atomic:

1. The administrator may call
   `GET /api/v1/admin/settings/default-cvss-version/impact` to preview the
   expected impact of the proposed value before confirming the change.
2. `PATCH /api/v1/admin/settings` commits the setting change and its audit
   event.
3. `POST /api/v1/admin/settings/default-cvss-version/recalculate` admits and
   publishes the recalculation run for the currently persisted value.

The preview is optional and non-binding; the PATCH neither requires nor
consumes it. The POST reads the persisted setting under its execution fence, so
a change committed between the PATCH and the POST is the version the POST
submits; no client-supplied version is accepted. A run admitted before a later
setting change is superseded when its delivery observes a persisted value
different from its own `target_version`; it then terminates `stale` before any
derived-state mutation, as defined in
`docs/features/platform/default-cvss-version-operations.md` (Input Validation
and Stale Delivery).

**Exclusion from an active recalculation**: an effective setting change is
rejected with `409 CVSS_RECALC_ALREADY_IN_PROGRESS` while a recalculation
execution fence is held. The PATCH requests the same stable, feature-specific
PostgreSQL advisory-lock identifier used by the runner's session-level fence,
in transaction-level, non-blocking form, so the transaction-level form
conflicts with the session-level fence across every connection and process
using the same PostgreSQL database, including multiple Celery workers, and it
releases automatically with the PATCH transaction. The fence identifier and
its session-level lifecycle are owned by
`docs/features/platform/default-cvss-version-operations.md` (Execution Fence).

A request whose value already equals the locked-current persisted value is a
no-op: it performs no fence check, no setting update, and no audit event, and
it succeeds even while a recalculation runner is active. The PATCH performs no
Redis operation, acquires no lease, publishes no task, registers no
post-commit callback, and reports no scheduling or convergence state.

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

### Setting Mutation Service

```python
async def update_default_cvss_version(
    session: AsyncSession,
    *,
    new_version: Literal["3.1", "4.0"],
    acting_user_id: UUID,
) -> str:
    ...
```

`session` is the caller-owned asynchronous database session. `new_version` is
the requested value; `acting_user_id` is the authenticated administrator who
requested the change and always attributes the resulting audit event. The
function returns the persisted setting value after the call: the new value when
it changed the row, or the locked-current value when the request was a no-op.

**Inputs and guards**:

1. The requested value is restricted to the closed set `"3.1"` and `"4.0"`.
   The API request schema rejects any other value with the global `422
   VALIDATION_ERROR` before the service is invoked. Because the type annotation
   is not runtime enforcement, the service also validates its input before any
   database access and raises `ValueError` for an out-of-set value; that path
   is unreachable through the API.
2. The function loads the required `default_cvss_version` row with a `FOR
   UPDATE` row lock as its first database operation. An absent row raises
   `RequiredSystemSettingMissingError`.
3. An effective change additionally requires the recalculation execution fence
   described below. A definitive lock-not-acquired result raises
   `CVSSRecalculationAlreadyInProgressError`; a database or session error
   during the attempt propagates as a server error and is never reported as
   `409`.

**Behavior**:

1. Acquire the `FOR UPDATE` row lock on the required setting row.
2. If the locked-current value equals `new_version`, return that value. A
   no-op performs no advisory-lock request, no setting update, and no audit
   event.
3. Otherwise request the stable, feature-specific advisory lock in
   transaction-level, non-blocking form (`pg_try_advisory_xact_lock`
   semantics), using the same identifier as the recalculation execution fence
   owned by `docs/features/platform/default-cvss-version-operations.md`
   (Execution Fence). A definitive lock-not-acquired result raises
   `CVSSRecalculationAlreadyInProgressError`; the caller's transaction rolls
   back, so no setting change and no audit event persist.
4. Update the setting row to `new_version`.
5. Create exactly one `SettingAuditEvent` through `SettingAuditLog.log_event()`
   in the same transaction, with `event_type = setting_changed`,
   `setting_key = default_cvss_version`, `user_id = acting_user_id`,
   `old_value` equal to the locked-current value, and `new_value` equal to
   `new_version`.
6. Flush so the setting update and the audit insert reach the database before
   returning. The function never commits and never rolls back.

**Transaction and side effects**: the setting update and its audit event are
the function's only durable effects; they commit or roll back atomically with
the caller's transaction. The function performs no Redis command, acquires no
lease, invokes no publisher, registers no post-commit callback, and creates no
other row. The transaction-level advisory lock is released by that
transaction's commit or rollback and by no other mechanism. The PATCH endpoint
uses the shared `DatabaseSession` dependency, which commits exactly once after
the handler succeeds and rolls back exactly once when an exception escapes.

**Concurrent requests**: concurrent requests serialize on the setting row
lock, and each request classifies against the value it observes while holding
that lock, never against an observation made before acquiring it. The outcome
depends on the persisted value before the race and on the order in which the
requests acquire the row lock:

- two requests carrying the same value, when that value differs from the
  persisted value: exactly one effective change and exactly one
  `SettingAuditEvent`, whichever request acquires the lock first — the first
  commits the change, and the second observes the committed value as
  locked-current and is a no-op;
- two requests carrying the same value, when that value already equals the
  persisted value: two no-ops, with no setting update, no advisory-lock
  request, and no `SettingAuditEvent`;
- two requests carrying different values, when the request for the persisted
  value acquires the row lock first: a no-op followed by one effective change
  and one `SettingAuditEvent` whose `old_value` is the persisted value;
- two requests carrying different values, when the request for the other value
  acquires the row lock first: two serialized effective changes and two
  `SettingAuditEvent`s; the second event's `old_value` equals the value
  committed by the first request, so audit history is always consistent with
  the committed row state.

An effective change concurrent with a recalculation run holding the
session-level fence cannot acquire the transaction-level lock and is rejected
with `CVSSRecalculationAlreadyInProgressError`; a no-op request takes no
advisory lock and is unaffected by an active run.

**Re-invocation**: the function is idempotent at the value level. Repeating the
same request after a successful change, or repeating a no-op request, returns
the persisted value and creates no additional audit event. Each effective
change creates exactly one new event.

**Exceptions propagated**: `ValueError` for an out-of-set value,
`RequiredSystemSettingMissingError`, `CVSSRecalculationAlreadyInProgressError`,
and database, flush, or other session errors propagate to the caller unchanged.

### Service Exceptions

All exceptions defined by the settings service inherit from
`SettingsServiceError`, which inherits from the shared `ServiceError` root.
Not every exception that crosses the service boundary belongs to this
hierarchy: `ValueError`, database and session errors, `MemoryError`,
`SoftTimeLimitExceeded`, control signals, and programming errors are not
settings-owned, are never mapped to a settings-specific HTTP status or error
code, and propagate unchanged. The preview and manual-admission operations
define the remaining API-facing exceptions of this hierarchy in
`docs/features/platform/default-cvss-version-operations.md`. API endpoint
handlers catch each documented API-facing exception and map it to the HTTP
status and error code stated in its owning specification and
`docs/api-spec.md`.

API-facing exceptions (this specification):

| Exception | HTTP | Code | Raised when |
|---|---|---|---|
| `CVSSRecalculationAlreadyInProgressError` | 409 | `CVSS_RECALC_ALREADY_IN_PROGRESS` | An effective setting change is rejected because the recalculation execution fence is held; nothing is committed |

`CVSSRecalculationAlreadyInProgressError` is also raised by the manual
recalculation admission when the execution fence or the admission lease is
already held, as defined in
`docs/features/platform/default-cvss-version-operations.md` (Complete-Run
Coordination).

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

The request schema accepts exactly `"3.1"` or `"4.0"`; any other value is
rejected by schema validation with the global `422 VALIDATION_ERROR` response
before the service is invoked.

**Behavior**: call `update_default_cvss_version()` with the request session,
the submitted value, and the authenticated administrator's UUID. The service
atomically updates the setting and creates exactly one `SettingAuditEvent` in
the same transaction, or classifies the request as a no-op. A `200 OK`
response reports the persisted value in the standard `{"data": ...}` envelope:
the new value for an effective change, or the locked-current value for a no-op.
The response contains no scheduling, change, or run-status flag.

The endpoint performs no Redis operation, acquires no lease, publishes no
task, and registers no post-commit callback. Changing the setting does not
itself recalculate derived state; the separate manual recalculation endpoint
is the only surface that admits and publishes the all-CVE run, as described in
`docs/features/platform/default-cvss-version-operations.md`. The PATCH is the
setting-mutation step of the intended preview→PATCH→POST sequence; it neither
requires nor consumes a prior impact preview.

Response (200 OK):

```json
{
  "data": {
    "default_cvss_version": "4.0"
  }
}
```

**Error responses**:

| Status | Code | Condition |
|--------|------|-----------|
| 409 | `CVSS_RECALC_ALREADY_IN_PROGRESS` | An effective setting change is blocked because the recalculation execution fence is held; nothing is committed |

A no-op request reads only the persisted setting row, takes no coordination
check, and returns `200 OK` even while a recalculation runner is active.

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
